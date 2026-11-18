//! Task package composition: alias validation, package-scoped task naming,
//! and the incremental accumulator that avoids re-resolving shared imports.

use super::{
    BTreeMap, Diagnostic, DiagnosticCategory, HashMap, HashSet, IndexMap, ModuleLoader, Path,
    TaskAction, TaskCapabilityRequest, TaskDefinition, TaskEdgeOrigin, TaskPackage,
    TaskPackageIdentity,
};

#[derive(Default)]
pub(super) struct TaskAccumulator {
    pub(super) tasks: IndexMap<String, TaskDefinition>,
    references: TaskReferenceIndex,
    #[cfg(test)]
    pub(super) composed_references: usize,
    #[cfg(test)]
    pub(super) composition_events: Vec<(String, String)>,
}

impl TaskAccumulator {
    fn contains_key(&self, name: &str) -> bool {
        self.tasks.contains_key(name)
    }

    fn get(&self, name: &str) -> Option<&TaskDefinition> {
        self.tasks.get(name)
    }

    pub(super) fn insert(&mut self, name: &str, task: TaskDefinition) {
        let Self {
            tasks, references, ..
        } = self;
        references.remove(name);
        tasks.insert(name.to_owned(), task);
        references.record(name, tasks.get(name));
    }

    fn references(&self, alias: &str) -> Vec<String> {
        self.references.for_alias(alias)
    }
}

#[derive(Default)]
struct TaskReferenceIndex {
    ranks: HashMap<String, usize>,
    aliases: HashMap<String, String>,
    by_alias: HashMap<String, BTreeMap<usize, String>>,
    next_rank: usize,
}

impl TaskReferenceIndex {
    fn remove(&mut self, name: &str) {
        let Some(rank) = self.ranks.get(name).copied() else {
            return;
        };
        let Some(alias) = self.aliases.remove(name) else {
            return;
        };
        let remove_alias = self.by_alias.get_mut(&alias).is_some_and(|references| {
            references.remove(&rank);
            references.is_empty()
        });
        if remove_alias {
            self.by_alias.remove(&alias);
        }
    }

    fn record(&mut self, name: &str, task: Option<&TaskDefinition>) {
        let rank = self.rank(name);
        let alias = task
            .and_then(|task| task.action.as_ref())
            .and_then(|action| package_reference_alias(action.uses.as_deref()));
        if let Some(alias) = alias {
            self.aliases.insert(name.to_owned(), alias.to_owned());
            self.by_alias
                .entry(alias.to_owned())
                .or_default()
                .insert(rank, name.to_owned());
        }
    }

    fn rank(&mut self, name: &str) -> usize {
        if let Some(rank) = self.ranks.get(name) {
            return *rank;
        }
        let rank = self.next_rank;
        self.next_rank += 1;
        self.ranks.insert(name.to_owned(), rank);
        rank
    }

    fn for_alias(&self, alias: &str) -> Vec<String> {
        self.by_alias
            .get(alias)
            .map(|references| references.values().cloned().collect())
            .unwrap_or_default()
    }
}

pub(super) fn apply_task_packages(
    loader: &mut ModuleLoader,
    source: &Path,
    packages: &IndexMap<String, TaskPackage>,
    tasks: &mut TaskAccumulator,
) -> Result<(), Diagnostic> {
    for (alias, package) in packages {
        validate_task_package_alias(alias)?;
        let loaded_package = loader.load_task_package_with_identity(source, package)?;
        let package_identity = loaded_package.identity;
        let package_project = loaded_package.project;
        let mut package_tasks = package_project.tasks;
        let all_package_task_names = package_tasks.keys().cloned().collect::<HashSet<_>>();
        let mut exported = package_tasks.shift_remove(&package.task).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO625",
                format!(
                    "task package {alias} does not export selected task: {}",
                    package.task
                ),
            )
        })?;
        let package_task_names = package_tasks.keys().cloned().collect::<HashSet<_>>();
        exported = remap_package_task(alias, &package.task, exported, &all_package_task_names);
        tag_package_task(&mut exported, &package_identity);
        exported.hidden = false;
        for (name, task) in package_tasks {
            let generated_name = package_task_name(alias, &name);
            if tasks.contains_key(&generated_name) {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO626",
                    format!("task package task collides with an existing task: {generated_name}"),
                ));
            }
            let mut task = remap_package_task(alias, &name, task, &package_task_names);
            tag_package_task(&mut task, &package_identity);
            task.hidden = true;
            tasks.insert(&generated_name, task);
        }
        for name in tasks.references(alias) {
            #[cfg(test)]
            {
                tasks.composed_references += 1;
                tasks
                    .composition_events
                    .push((alias.to_owned(), name.clone()));
            }
            let caller = tasks.get(&name).cloned().ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::Internal,
                    "NEO701",
                    format!("task package reference disappeared during composition: {name}"),
                )
            })?;
            tasks.insert(&name, merge_package_task(exported.clone(), caller));
        }
    }
    Ok(())
}

fn validate_task_package_alias(alias: &str) -> Result<(), Diagnostic> {
    let valid = !alias.is_empty()
        && alias
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
        && alias.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        });
    if valid {
        Ok(())
    } else {
        Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO621",
            format!("invalid task package alias: {alias}"),
        ))
    }
}

fn package_reference_alias(uses: Option<&str>) -> Option<&str> {
    let value = uses?;
    value
        .strip_prefix("package:")
        .or_else(|| value.strip_prefix('@'))
        .filter(|alias| !alias.is_empty())
}

fn package_task_name(alias: &str, name: &str) -> String {
    format!("package-{alias}:{name}")
}

fn tag_package_task(task: &mut TaskDefinition, identity: &TaskPackageIdentity) {
    task.package = Some(identity.clone());
    task.capability_requests = task
        .action
        .as_ref()
        .into_iter()
        .flat_map(|action| &action.capabilities)
        .map(|capability| TaskCapabilityRequest {
            capability: capability.clone(),
            origin: TaskEdgeOrigin::Package,
        })
        .collect();
    task.dependency_origins.needs = vec![TaskEdgeOrigin::Package; task.needs.len()];
    task.dependency_origins.before = vec![TaskEdgeOrigin::Package; task.hooks.before.len()];
    task.dependency_origins.after = vec![TaskEdgeOrigin::Package; task.hooks.after.len()];
}

fn remap_package_task(
    alias: &str,
    name: &str,
    mut task: TaskDefinition,
    package_tasks: &HashSet<String>,
) -> TaskDefinition {
    let remap = |dependency: String| {
        if package_tasks.contains(&dependency) {
            package_task_name(alias, &dependency)
        } else {
            dependency
        }
    };
    task.needs = task.needs.into_iter().map(remap).collect();
    task.parallel_needs = task.parallel_needs.into_iter().map(remap).collect();
    task.wait = task
        .wait
        .into_iter()
        .map(|name| if name == "all" { name } else { remap(name) })
        .collect();
    task.hooks.before = task.hooks.before.into_iter().map(remap).collect();
    task.hooks.after = task.hooks.after.into_iter().map(remap).collect();
    task.extends = task.extends.map(remap);
    task.id = task.id.map(|id| format!("package-{alias}:{id}"));
    task.slug = task.slug.map(|slug| format!("{alias}-{slug}"));
    task.name = task.name.map(|label| format!("{alias}: {label}"));
    let _ = name;
    task
}

fn edge_origins(count: usize, origins: &[TaskEdgeOrigin]) -> Vec<TaskEdgeOrigin> {
    if origins.len() == count {
        origins.to_vec()
    } else {
        vec![TaskEdgeOrigin::Caller; count]
    }
}

fn merge_package_task(mut package: TaskDefinition, caller: TaskDefinition) -> TaskDefinition {
    package.background = caller.background.or(package.background);
    package.parallel_needs.extend(caller.parallel_needs);
    package.wait.extend(caller.wait);
    package.execution_grant_required |= caller.execution_grant_required;
    package.id = caller.id.or(package.id);
    package.name = caller.name.or(package.name);
    package.slug = caller.slug.or(package.slug);
    package.description = caller.description.or(package.description);
    package.help = caller.help.or(package.help);
    package.template = caller.template || package.template;
    package.dependency_origins.needs.extend(edge_origins(
        caller.needs.len(),
        &caller.dependency_origins.needs,
    ));
    package.dependency_origins.before.extend(edge_origins(
        caller.hooks.before.len(),
        &caller.dependency_origins.before,
    ));
    package.dependency_origins.after.extend(edge_origins(
        caller.hooks.after.len(),
        &caller.dependency_origins.after,
    ));
    package.needs.extend(caller.needs);
    package.hooks.before.extend(caller.hooks.before);
    package.hooks.after.extend(caller.hooks.after);
    package.parameters.retain(|parameter| {
        !caller
            .parameters
            .iter()
            .any(|replacement| replacement.name == parameter.name)
    });
    package.parameters.extend(caller.parameters);
    package.outputs.extend(caller.outputs);
    package.if_condition = caller.if_condition.or(package.if_condition);
    package.force = caller.force.or(package.force);
    let mut caller_requests = caller.capability_requests;
    if caller_requests.is_empty()
        && let Some(action) = caller.action.as_ref()
    {
        caller_requests = action
            .capabilities
            .iter()
            .map(|capability| TaskCapabilityRequest {
                capability: capability.clone(),
                origin: TaskEdgeOrigin::Caller,
            })
            .collect();
    }
    package.capability_requests.extend(caller_requests);
    package.action = match (package.action, caller.action) {
        (Some(package), Some(caller)) => Some(merge_package_action(package, caller)),
        (Some(package), None) => Some(package),
        (None, _) => None,
    };
    package
}

fn merge_package_action(mut package: TaskAction, caller: TaskAction) -> TaskAction {
    let caller_overrides_values = caller.with.contains_key("values");
    package.with.extend(caller.with);
    if caller_overrides_values {
        package.values_document = caller.values_document;
        package.values_from_package = caller.values_from_package;
    }
    package.env.extend(caller.env);
    package.dotenv.extend(caller.dotenv);
    package.capabilities.extend(caller.capabilities);
    package.capabilities.sort();
    package.capabilities.dedup();
    if !caller.args.is_empty() {
        package.args = caller.args;
    }
    if !caller.files.is_empty() {
        package.files = caller.files;
        package.files_document = caller.files_document;
        package.files_from_package = caller.files_from_package;
    }
    if caller.cwd.is_some() {
        package.cwd = caller.cwd;
        package.cwd_document = caller.cwd_document;
        package.cwd_from_package = caller.cwd_from_package;
    }
    package
}
