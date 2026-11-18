//! Read-only configuration loading and inspection assembly.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use indexmap::IndexMap;
use neoenv_config::{
    DotenvImport, EnvironmentEntry, PathOperation, PathOperationKind, TaskDirectories, TaskPackage,
    sources::{ConfigMergePlan, ConfigSource},
};
use neoenv_core::tools::ToolDeclaration;
use neoenv_core::{
    Diagnostic, DiagnosticCategory, InspectionDocument, InspectionEnvironmentEntry,
    InspectionPathOperation, InspectionSource, InspectionTask, InspectionTaskOutput,
    ValidationDocument,
    tasks::{
        TaskAction, TaskCapabilityRequest, TaskDefinition, TaskDotenvImport, TaskEdgeOrigin,
        TaskOutputVisibility, TaskPackageIdentity, resolve_inheritance, task_dependency_edges,
        valid_environment_key,
    },
};
use neoenv_policy::should_redact_environment;
use neotales_dotenv::parse as parse_dotenv;

use crate::{
    budget::{ResourceBudget, read_text_file},
    discovery::{
        DiscoveredProject, discover_from_environment, resolve_workspace_alias_with_profile,
        select_sources,
    },
    modules::ModuleLoader,
    paths::{UserDirectory, user_directory},
    trust::Contributor,
    vault::REFERENCE_PREFIX,
};

mod task_packages;
#[cfg(test)]
mod tests;

use task_packages::{TaskAccumulator, apply_task_packages};

const CONFIGURATION_FILENAMES: [&str; 4] = ["neoenv.yaml", "neoenv.yml", "neoenv.toml", ".neoenv"];

/// The resolved read-only configuration state for one project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProject {
    pub project: DiscoveredProject,
    pub sources: Vec<ConfigSource>,
    /// Declared vaults, in source order. A declaration only: loading a project
    /// never opens a provider, a keyring, or an identity file.
    pub vaults: IndexMap<String, neoenv_config::VaultDeclaration>,
    pub environment: IndexMap<String, EnvironmentEntry>,
    pub path: Vec<PathOperation>,
    pub tools: Vec<ToolDeclaration>,
    pub context: Option<String>,
    /// Which file `context` came from, when a file supplied it.
    ///
    /// `None` means either no source declared one, or `--context` won -- and those are
    /// different situations that a reader would want told apart, so the command that
    /// prints this says which.
    pub context_source: Option<PathBuf>,
    pub task_dirs: TaskDirectories,
    /// The project's tasks, with `extends:` resolved.
    ///
    /// **Private, and that is the point.** Every reader has to go through
    /// [`ResolvedProject::tasks`], which re-raises the resolution failure, so a
    /// reader cannot quietly read an empty map for a project whose tasks simply
    /// failed to resolve -- which would report "this project has no tasks" and be
    /// indistinguishable from a project that has none.
    ///
    /// Empty when `task_error` is set. Never empty *and* unresolved by accident:
    /// the two are the same field read two ways, and the accessor is the only way
    /// to read it.
    tasks: IndexMap<String, TaskDefinition>,
    /// Why task inheritance could not be resolved, when it could not be.
    ///
    /// **Recorded rather than returned, so that its blast radius is a decision
    /// rather than a side effect of where `resolve_inheritance` happens to be
    /// called.** It was called once, here, while the project was being loaded,
    /// which turned a project-wide check into a precondition of every operation:
    /// one task with a dangling `extends:` made `nenv config` and `nenv context`
    /// refuse, and neither of them reads a task. See #259.
    ///
    /// A missing `extends:` base *should* be an error -- a silently ignored base
    /// is a wrong answer rather than an absence. It should be an error of the task
    /// that has the dangling base, reported by the commands that can see tasks.
    pub task_error: Option<Diagnostic>,
    /// The project's jobs, as written.
    ///
    /// **Not resolved here**: `extends:` and `cron` are refused at read time;
    /// reachable `needs` and `wait` graphs are lowered when a job runs (also in
    /// dry-run). What is here is exactly what the file
    /// says, so `nenv job list` can report a project whose jobs would not lower
    /// rather than hiding them -- a refusal that hides the jobs is the same
    /// absence-for-a-failure this repository keeps finding.
    pub jobs: IndexMap<String, neoenv_core::tasks::JobDefinition>,
    /// Deferred inventory sources, never read by general project resolution.
    inventories: crate::inventory_files::InventorySources,
    /// The project's declared deployment workflows, in declaration order.
    pub deployments: IndexMap<String, neoenv_core::tasks::DeploymentDefinition>,
    /// The tasks **as written**, with `extends:` not resolved.
    ///
    /// Public, and the counterpart to the private [`Self::tasks`]. Two commands
    /// need only the *keys* -- `context list` harvests context names out of
    /// `build:dev`-style task keys, and the shortcut dispatcher asks "is this name
    /// a task" before it runs anything -- and neither answer depends on a base
    /// task existing. Resolving inheritance to learn a task's *name* would make
    /// both of them fail for a reason they cannot observe and cannot explain.
    ///
    /// A `TaskDefinition` here is the declaration, so `extends` is still `Some`
    /// and `action` may be absent. It is not a resolved task and must not be run.
    pub declared_tasks: IndexMap<String, TaskDefinition>,
    /// Task keys whose effective declaration came from a trusted cached remote module.
    pub remote_tasks: HashSet<String>,
    /// Every document whose bytes contributed to this graph, identified from
    /// the exact bytes that were parsed. The execution gate checks the root
    /// first, then this list; it never reopens a path to recompute an identity.
    ///
    /// Documents are configuration, modules, and task packages. Dotenv files
    /// and render templates are inputs to an effect, not configuration that
    /// selects one, and are not identities in this list.
    pub contributors: Vec<Contributor>,
    /// Every context name the project declares, in source order and
    /// deduplicated.
    ///
    /// Two sources, because both are the project saying "this context exists":
    /// the project's own `context:` setting, and the `contexts:` list on a
    /// `dotenv:` import (the reference's own scoping key). The first is what
    /// makes `context: dev` with no `:dev` task variant coherent rather than a
    /// rejection -- the project named the context, so it is one.
    ///
    /// The dotenv source is collected from *every* entry, including one whose
    /// `os` filter excluded it on this machine: the set answers "which context
    /// names does this project use", which is about what was written, not about
    /// what happened to load here. A `prod`-scoped dotenv is often the only thing
    /// that tells `--context releae` is a typo.
    pub declared_contexts: Vec<String>,
}

impl ResolvedProject {
    /// Resolves inventory-only files and inline layers into a fresh ordered
    /// snapshot. Call once per inventory/SSH operation, not for unrelated commands.
    /// Captures no credentials and grants no network capabilities.
    ///
    /// # Errors
    /// Strictly rejects invalid user or declared inventory entries when consumed.
    pub fn inventories(&self) -> Result<IndexMap<String, neoenv_config::Inventory>, Diagnostic> {
        self.inventories.resolve()
    }

    /// The project's tasks, or why they could not be produced.
    ///
    /// **Every reader goes through here, and the four answers are the point.**
    ///
    /// A command that resolves tasks -- `run`, `plan`, `help`, `list`, `complete`,
    /// `inspect` -- calls this and propagates the error, so a dangling `extends:`
    /// is reported by the commands that can see it. A command that does not resolve
    /// tasks -- `config`, `context` -- does not call this, because task inheritance
    /// is not one of its inputs and refusing to name a project's context because an
    /// unrelated task names a base that does not exist is not an answer.
    ///
    /// # Errors
    ///
    /// Returns the recorded diagnostic when task inheritance could not be resolved.
    ///
    /// **The error is cloned out rather than borrowed.** A caller that wants to
    /// *report* rather than refuse reads [`Self::task_error`] directly and pays
    /// nothing; the callers that propagate use `?`, and eight of them should not
    /// each have to spell `.map_err(Clone::clone)`. The clone happens only on the
    /// path that is already failing.
    pub fn tasks(&self) -> Result<&IndexMap<String, TaskDefinition>, Diagnostic> {
        match &self.task_error {
            Some(error) => Err(error.clone()),
            None => Ok(&self.tasks),
        }
    }

    /// The tasks to *report*: the resolved ones, or the declared ones when
    /// inheritance did not resolve.
    ///
    /// For a command that describes the project rather than refusing it. Never
    /// returns an empty map for a project that declares tasks, because an empty
    /// listing reads as "this project has no tasks" and the project has some --
    /// they just could not be resolved, which is a different fact with a different
    /// remedy. The companion is [`Self::task_error`], and a caller that uses this
    /// must report that too.
    #[must_use]
    pub fn listed_tasks(&self) -> &IndexMap<String, TaskDefinition> {
        if self.task_error.is_some() {
            &self.declared_tasks
        } else {
            &self.tasks
        }
    }

    /// The resolved form of the named tasks and whatever they inherit from.
    ///
    /// **The per-task answer, and the reason `run` can work on a project that
    /// [`Self::task_error`] says it cannot fully resolve.** Only the chains
    /// reachable from `names` are visited, so a dangling `extends:` in a task the
    /// caller did not name is invisible -- and the error that *is* returned is
    /// about a task the caller named or a base it actually inherits from.
    ///
    /// A caller asking for a task this project does not declare gets an empty map
    /// rather than an error, because "there is no such task" is the dispatcher's
    /// question to answer with its own vocabulary (`task shortcut ... was not
    /// found`), not this function's.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing base or a cycle reachable from `names`.
    pub fn tasks_for(
        &self,
        names: &[String],
        context: &str,
    ) -> Result<IndexMap<String, TaskDefinition>, Diagnostic> {
        match &self.task_error {
            // The whole map resolved, so the closure walk needs no fixpoint: every
            // definition in it is already final, and one pass is exact.
            //
            // **The walk still has to happen.** The first version took a shortcut
            // here and returned only the requested names, on the reasoning that the
            // caller has a resolved map to hand. It does not -- the caller has
            // *these* tasks and nothing else, and `run_tasks` plans from what it is
            // given. So `nenv run check` on a clean project failed with "depends on
            // missing task package-imported:prepare", for a task that was present
            // and resolved. Six integration tests caught it; the reasoning did not.
            None => Ok(dependency_closure(&self.tasks, names, context)),
            Some(_) => self.tasks_for_partial(names, context),
        }
    }

    /// The closure half of [`Self::tasks_for`]: resolve inheritance, then follow
    /// whatever `needs` and hooks the *resolved* definitions turned out to have,
    /// and repeat until the set stops growing.
    ///
    /// **The fixpoint is not optional.** Inheritance and dependency closure feed
    /// each other: `release` may declare no `needs` of its own and inherit
    /// `needs: [lint]` from the base it extends, and that base is only visible
    /// *after* resolution. Resolving once and then walking the resolved map would
    /// produce a plan missing `lint`, and the run would fail with a missing
    /// dependency in a task whose declaration is perfectly valid -- an error that
    /// names a task the user never mentioned, which is the same mistake this whole
    /// function exists to remove.
    ///
    /// The two name resolvers are the core's own, not copies. A second
    /// implementation of "which key does this `needs:` or hook suffix mean" is how
    /// a planner and a runner end up including different tasks for one command.
    fn tasks_for_partial(
        &self,
        names: &[String],
        context: &str,
    ) -> Result<IndexMap<String, TaskDefinition>, Diagnostic> {
        // Context-resolved, for the same reason as `dependency_closure` above.
        let mut wanted: Vec<String> = names
            .iter()
            .map(|name| {
                neoenv_core::tasks::resolve_task_name(&self.declared_tasks, name, context)
                    .unwrap_or_else(|_| (*name).clone())
            })
            .collect();
        for _ in 0..=self.declared_tasks.len() {
            let resolved =
                neoenv_core::tasks::resolve_inheritance_for(&self.declared_tasks, &wanted)
                    .map_err(|error| {
                        Diagnostic::new(DiagnosticCategory::Validation, "NEO320", error.to_string())
                    })?;
            let mut grew = false;
            // A clone, because the loop reads `wanted` while growing it. The set is
            // bounded by the task count, so the copy is bounded too.
            let snapshot = wanted.clone();
            for name in &snapshot {
                let Some(task) = resolved.get(name) else {
                    continue;
                };
                // Against the **declared** map, not `resolved`. `resolved` holds only
                // the set so far, so a dependency outside it is invisible here -- the
                // closure stops growing, the loop returns, and the run then fails with
                // "depends on missing task" for a task that exists and whose
                // declaration is valid. Name resolution only needs the full set of
                // *keys* to answer "which key does this name mean".
                for dependency in task
                    .needs
                    .iter()
                    .chain(task.wait.iter().filter(|name| name.as_str() != "all"))
                {
                    // An unresolvable `needs:` is left to `plan_task`, which words the
                    // error in the vocabulary of the command that hit it. Guessing
                    // here would report a core-level failure for something the
                    // planner handles better.
                    if let Ok(selected) = neoenv_core::tasks::resolve_task_name(
                        &self.declared_tasks,
                        dependency,
                        context,
                    ) && !wanted.contains(&selected)
                    {
                        wanted.push(selected);
                        grew = true;
                    }
                }
                for hook in task.hooks.before.iter().chain(task.hooks.after.iter()) {
                    if let Some(selected) = neoenv_core::tasks::resolve_hook_name(
                        &self.declared_tasks,
                        name,
                        hook,
                        context,
                    ) && !wanted.contains(&selected)
                    {
                        wanted.push(selected);
                        grew = true;
                    }
                }
            }
            if !grew {
                return Ok(resolved);
            }
        }
        Err(Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO520",
            format!(
                "resolving {} did not settle after {} passes over {} declared task(s); \
                 the dependency graph is not acyclic",
                wanted.join(", "),
                self.declared_tasks.len() + 1,
                self.declared_tasks.len()
            ),
        ))
    }

    /// The task-resolution failure, if there is one, without the decision of
    /// whether it is fatal.
    ///
    /// For a command that reports the project *and* its problems, which is a third
    /// answer distinct from both "refuse" and "ignore": the tasks that did resolve,
    /// plus the reason the rest did not.
    #[must_use]
    pub fn task_error(&self) -> Option<&Diagnostic> {
        self.task_error.as_ref()
    }

    /// Returns a versioned, default-redacted inspection document.
    #[must_use]
    pub fn inspection_document(&self) -> InspectionDocument {
        InspectionDocument {
            schema_version: InspectionDocument::SCHEMA_VERSION,
            format_version: neoenv_config::FORMAT_VERSION,
            sources: inspection_sources(&self.sources),
            environment: self
                .environment
                .values()
                .map(|entry| {
                    // A declared secret always redacts, whatever the key is
                    // called. A Go file can mark `PORT` secret and the name
                    // heuristic alone would print it. The heuristic still covers
                    // a native file, which has no secret form of its own.
                    let redacted = entry.secret || should_redact_environment(&entry.key);
                    InspectionEnvironmentEntry {
                        key: entry.key.clone(),
                        value: if redacted {
                            "[redacted]".into()
                        } else {
                            entry.value.clone()
                        },
                        redacted,
                        source: entry.source.clone(),
                    }
                })
                .collect(),
            path: self
                .path
                .iter()
                .map(|operation| InspectionPathOperation {
                    operation: match operation.kind {
                        PathOperationKind::Prepend => "prepend",
                        PathOperationKind::Append => "append",
                    }
                    .into(),
                    value: operation.value.clone(),
                    source: operation.source.clone(),
                })
                .collect(),
            // **The declared tasks when inheritance did not resolve, and the resolved
            // ones when it did.** This reads `self.tasks` -- the private field -- from
            // inside the defining crate, so the compiler could not force a decision
            // here the way it did at the twenty-one external readers. Left alone it
            // would emit an *empty* `tasks` array for a project that plainly has
            // tasks, and an empty array is indistinguishable from a project with
            // none. The CLI prints the resolution failure to stderr and exits
            // non-zero, so the document and the status together are unambiguous.
            //
            // The document *shape* is unchanged: `inspection-v2.schema.json` is a
            // published contract and an `unresolved` key would change what every
            // consumer of `inspect --format json` sees. The failure is reported
            // beside the document, not inside it.
            tasks: self
                .listed_tasks()
                .iter()
                .map(|(key, task)| {
                    let (dependencies, before_hooks, after_hooks) = task_dependency_edges(task);
                    InspectionTask {
                        key: key.clone(),
                        id: task.id.clone().unwrap_or_else(|| key.clone()),
                        name: task.name.clone().unwrap_or_else(|| key.clone()),
                        slug: task.slug.clone().unwrap_or_else(|| {
                            key.chars()
                                .filter(char::is_ascii_alphanumeric)
                                .map(|character| character.to_ascii_lowercase())
                                .collect()
                        }),
                        description: task.description.clone(),
                        outputs: task
                            .outputs
                            .iter()
                            .map(|(name, output)| InspectionTaskOutput {
                                name: name.clone(),
                                description: output.description.clone(),
                                visibility: match output.visibility {
                                    TaskOutputVisibility::Public => "public",
                                    TaskOutputVisibility::Private => "private",
                                }
                                .into(),
                            })
                            .collect(),
                        package: task.package.clone(),
                        dependencies,
                        before_hooks,
                        after_hooks,
                    }
                })
                .collect(),
        }
    }

    /// Returns a versioned success document for validation automation.
    #[must_use]
    pub fn validation_document(&self) -> ValidationDocument {
        ValidationDocument {
            schema_version: ValidationDocument::SCHEMA_VERSION,
            valid: true,
            sources: inspection_sources(&self.sources),
        }
    }
}

/// Discovers and reads the active configuration without running project code.
///
/// # Errors
///
/// Returns diagnostics for missing projects, source I/O, or invalid source
/// documents. Missing user and conventional private files are ignored.
/// Loads the active project in an explicitly selected configuration profile.
///
/// `ConfigProfile::Native` is the strict v1 schema. `Go` is the opt-in
/// compatibility profile and is threaded all the way down, including into
/// imported modules, so a Go file and its imports are read consistently.
///
/// # Errors
///
/// Returns diagnostics for missing projects, source I/O, or invalid source
/// documents.
/// `context_override` is the command line's `--context`, if any.
///
/// It has to arrive *here* rather than being applied afterwards: a `dotenv:`
/// entry's `contexts:` filter is evaluated while the sources are merged, and
/// filtering it against the document's own `context:` alone meant
/// `nenv task run build --context prod` resolved `prod` for task selection and
/// the empty string for the filter -- so a `contexts: [prod]` dotenv was not
/// loaded and an unfiltered one was loaded regardless of the flag.
pub fn load_active_project_with_profile(
    start: &Path,
    explicit_path: Option<&Path>,
    profile: neoenv_config::ConfigProfile,
    context_override: Option<&str>,
) -> Result<ResolvedProject, Diagnostic> {
    let project = discover_from_environment(start, explicit_path)?.ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::NotFound,
            "NEO401",
            "no nenv configuration found",
        )
    })?;
    let user_config = user_config_path();
    let private_overlay = conventional_private_overlay(&project.project_root);
    let plan = select_sources(&project, user_config.as_deref(), private_overlay.as_deref())?;
    resolve_sources(project, &plan, profile, context_override)
}

/// Loads the active project in the strict v1 schema.
///
/// # Errors
///
/// Returns the same diagnostics as [`load_active_project_with_profile`].
pub fn load_active_project(
    start: &Path,
    explicit_path: Option<&Path>,
) -> Result<ResolvedProject, Diagnostic> {
    load_active_project_with_profile(
        start,
        explicit_path,
        neoenv_config::ConfigProfile::process_profile(),
        None,
    )
}

/// Loads an explicit local workspace alias when present, otherwise uses normal
/// project discovery. Alias lookup is local-only and limited to declared members.
///
/// # Errors
///
/// Returns discovery, workspace-alias, source-composition, or configuration
/// diagnostics.
pub fn load_project_or_workspace_alias(
    start: &Path,
    explicit_path: Option<&Path>,
) -> Result<ResolvedProject, Diagnostic> {
    load_project_or_workspace_alias_with_profile(
        start,
        explicit_path,
        neoenv_config::ConfigProfile::process_profile(),
        None,
    )
}

/// The profile-aware form of [`load_project_or_workspace_alias`].
///
/// # Errors
///
/// Returns discovery, workspace-alias, source-composition, or configuration
/// diagnostics.
pub fn load_project_or_workspace_alias_with_profile(
    start: &Path,
    explicit_path: Option<&Path>,
    profile: neoenv_config::ConfigProfile,
    context_override: Option<&str>,
) -> Result<ResolvedProject, Diagnostic> {
    if let Some(path) = explicit_path.filter(|path| !path.is_file())
        && let Some(project) =
            resolve_workspace_alias_with_profile(start, &path.to_string_lossy(), profile)?
    {
        let private_overlay = conventional_private_overlay(&project.project_root);
        let plan = select_sources(
            &project,
            user_config_path().as_deref(),
            private_overlay.as_deref(),
        )?;
        return resolve_sources(project, &plan, profile, context_override);
    }
    load_active_project_with_profile(start, explicit_path, profile, context_override)
}

/// Everything a configuration source contributes to, accumulated across sources.
///
/// A struct rather than a list of `&mut` out-parameters: with eight of them the
/// call sites could not be read, and a new field meant threading another through
/// both of them in the right position. The fields stay separate inside, so the
/// merge order in `apply_project` is unchanged and still visible in one place.
#[derive(Default)]
struct SourceAccumulator {
    environment: IndexMap<String, EnvironmentEntry>,
    /// Declared vaults, in source order. Later sources win by name, like every
    /// other keyed section. A declaration never opens anything.
    vaults: IndexMap<String, neoenv_config::VaultDeclaration>,
    tools: Vec<ToolDeclaration>,
    /// The last document's own `context:`, which is the *lowest* of the three
    /// precedence sources.
    ///
    /// Kept separate from `context_override` because a document must not be able
    /// to overwrite `--context`: the task resolver uses
    /// `select_context(cli, env, project.context)`, and if the dotenv filter saw
    /// a different winner the two would resolve different worlds for one command.
    context: Option<String>,
    /// The file the winning `context:` came from.
    ///
    /// **Recorded because the fourth layer made the existing answer wrong.** `config
    /// list` reported the *project* file for `context` unconditionally, which was correct
    /// while the project file was the only thing that could set it. With a
    /// higher-precedence overrides file it becomes a misreport -- a confidently wrong
    /// provenance, which is worse than an absent one.
    context_source: Option<PathBuf>,
    /// The command line's or the environment's `--context`, if either was given.
    context_override: Option<String>,
    task_dirs: TaskDirectories,
    tasks: TaskAccumulator,
    /// Jobs, in source order and deduplicated by key like every other section.
    jobs: IndexMap<String, neoenv_core::tasks::JobDefinition>,
    /// Inventories, in source order. Later sources win, as for every other keyed
    /// section -- a workspace member that declares an inventory overrides it, and
    /// that is a decision a file can make.
    inventories: crate::inventory_files::InventorySources,
    /// Deployments, in source order, on the same terms as inventories.
    deployments: IndexMap<String, neoenv_core::tasks::DeploymentDefinition>,
    path: Vec<PathOperation>,
    declared_contexts: Vec<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered merge is easier to audit than eight extracted steps"
)]
fn resolve_sources(
    project: DiscoveredProject,
    plan: &ConfigMergePlan,
    profile: neoenv_config::ConfigProfile,
    context_override: Option<&str>,
) -> Result<ResolvedProject, Diagnostic> {
    let mut accumulated = SourceAccumulator {
        // Trimmed, because the reference trims (`runner.go`: `strings.TrimSpace`):
        // an untrimmed `context: "prod "` matched no `contexts: [prod]`, and an
        // all-blank context skipped every unfiltered dotenv.
        context_override: context_override
            .map(str::trim)
            .filter(|context| !context.is_empty())
            .map(str::to_owned),
        ..SourceAccumulator::default()
    };
    let mut remote_tasks = HashSet::new();
    accumulated.inventories = crate::inventory_files::InventorySources::for_process();
    let mut sources = Vec::new();
    let mut module_loader = ModuleLoader::with_profile(&project.project_root, profile)?;
    for source in plan.sources() {
        let mut documents = module_loader.load_local_modules(source.path())?;
        let (parsed_source, parsed) = documents.pop().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO701",
                format!(
                    "configuration source produced no document: {}",
                    source.path().display()
                ),
            )
        })?;
        let module_sources = documents
            .iter()
            .map(|(module_source, _)| module_source.clone())
            .collect::<Vec<_>>();
        for (module_source, module) in documents {
            // **A remote module may not declare a vault.** A declaration is a
            // local file path, an identity, or a keyring account: the authority
            // to read one is a trust decision, not something a downloaded module
            // grants itself. This check is before `apply_project`, so a remote
            // module cannot add a vault and cannot replace a local one by
            // declaring the same name.
            refuse_remote_vault_declarations(&module_source, &module)?;
            let remote_task_names = if module_source.is_remote_module() {
                module.tasks.keys().cloned().collect()
            } else {
                Vec::new()
            };
            let task_packages = module.task_packages.clone();
            let package_source = PathBuf::from(&module.source.path);
            apply_project(&mut accumulated, module)?;
            apply_task_packages(
                &mut module_loader,
                &package_source,
                &task_packages,
                &mut accumulated.tasks,
            )?;
            // The module source is retained between its importer and its dependents.
            // This preserves the path that supplied every winning declaration.
            // It is intentionally inserted before the importing source below.
            //
            // Modules may recur through separate source layers, where later layers
            // still correctly override earlier declarations.
            //
            // `sources` is assembled separately to keep its precedence ordering.
            for task in remote_task_names {
                remote_tasks.insert(task);
            }
        }
        refuse_remote_vault_declarations(&parsed_source, &parsed)?;
        let parsed_task_names = parsed.tasks.keys().cloned().collect::<Vec<_>>();
        let task_packages = parsed.task_packages.clone();
        let parsed_source = PathBuf::from(&parsed.source.path);
        apply_project(&mut accumulated, parsed)?;
        apply_task_packages(
            &mut module_loader,
            &parsed_source,
            &task_packages,
            &mut accumulated.tasks,
        )?;
        for task in parsed_task_names {
            remote_tasks.remove(&task);
        }
        sources.extend(module_sources);
        sources.push(source.clone());
    }
    let contributors = module_loader.take_contributors();
    // Recorded, not returned. See `ResolvedProject::task_error` for why, and for
    // what the four commands each do with it once it is recorded.
    let declared_tasks = accumulated.tasks.tasks.clone();
    let (tasks, task_error) = match resolve_inheritance(&accumulated.tasks.tasks) {
        Ok(resolved) => (resolved, None),
        Err(error) => (
            IndexMap::new(),
            Some(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO320",
                error.to_string(),
            )),
        ),
    };
    Ok(ResolvedProject {
        project,
        sources,
        vaults: accumulated.vaults,
        environment: accumulated.environment,
        path: accumulated.path,
        tools: accumulated.tools,
        context: accumulated
            .context_override
            .clone()
            .or_else(|| accumulated.context.clone()),
        // `None` when `--context` won, which is the right answer: a value from the
        // command line came from no file, and naming one would be a lie.
        context_source: if accumulated.context_override.is_some() {
            None
        } else {
            accumulated.context_source.clone()
        },
        task_dirs: accumulated.task_dirs,
        tasks,
        task_error,
        declared_tasks,
        jobs: accumulated.jobs,
        inventories: accumulated.inventories,
        deployments: accumulated.deployments,
        remote_tasks,
        contributors,
        declared_contexts: accumulated.declared_contexts,
    })
}

/// The transitive closure of `names` over `needs` and hooks, in a **complete** map.
///
/// Complete is the load-bearing word. `resolved` here has every definition
/// resolved and every key present, so resolving a name against it is exact and one
/// pass reaches the fixpoint. The partial case -- a map that is still growing --
/// is [`ResolvedProject::tasks_for_partial`], which has to iterate because
/// resolving inheritance can reveal dependencies that were not in the set.
///
/// An unresolvable `needs:` is left to `plan_task`, which words the error in the
/// vocabulary of the command that hit it.
fn dependency_closure(
    resolved: &IndexMap<String, TaskDefinition>,
    names: &[String],
    context: &str,
) -> IndexMap<String, TaskDefinition> {
    // **Seeded with the context-resolved name, not the literal one.**
    // `plan_task` resolves its root the same way (`resolve_task_name`), so seeding
    // with `build` when the run is `nenv task plan build --context prod` hands the
    // planner a map that does not contain `build:prod` and it silently plans the
    // base instead. Three integration tests caught that.
    //
    // A name that resolves to nothing is kept verbatim, so the caller still gets
    // `plan_task`'s own "no such task" error rather than an empty map.
    let mut wanted: Vec<String> = names
        .iter()
        .map(|name| {
            neoenv_core::tasks::resolve_task_name(resolved, name, context)
                .unwrap_or_else(|_| (*name).clone())
        })
        .filter(|name| resolved.contains_key(name))
        .collect();
    for _ in 0..=resolved.len() {
        let mut grew = false;
        let snapshot = wanted.clone();
        for name in &snapshot {
            let Some(task) = resolved.get(name) else {
                continue;
            };
            for dependency in task
                .needs
                .iter()
                .chain(task.wait.iter().filter(|name| name.as_str() != "all"))
            {
                if let Ok(selected) =
                    neoenv_core::tasks::resolve_task_name(resolved, dependency, context)
                    && !wanted.contains(&selected)
                {
                    wanted.push(selected);
                    grew = true;
                }
            }
            for hook in task.hooks.before.iter().chain(task.hooks.after.iter()) {
                if let Some(selected) =
                    neoenv_core::tasks::resolve_hook_name(resolved, name, hook, context)
                    && !wanted.contains(&selected)
                {
                    wanted.push(selected);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    resolved
        .iter()
        .filter(|(name, _)| wanted.contains(name))
        .map(|(name, task)| (name.clone(), task.clone()))
        .collect()
}

/// Refuses vault declarations from a remote module.
///
/// A vault declaration can name a local path, an age identity, or a keyring
/// account. Letting a remote module contribute one would let whoever controls the
/// module choose a credential source, and a later source could replace a local
/// declaration wholesale. Neither is a capability the module was granted.
fn refuse_remote_vault_declarations(
    source: &ConfigSource,
    project: &neoenv_config::Project,
) -> Result<(), Diagnostic> {
    // **Origin, not a path shape.** A tarball is extracted under a cache
    // directory that does not look like the commits cache, and a local project
    // may contain a directory that does. The loader records the import form on
    // the `ConfigSource`, and nested local imports inside remote content inherit
    // it.
    if project.vaults.is_empty() || !source.is_remote_module() {
        return Ok(());
    }
    Err(Diagnostic::new(
        DiagnosticCategory::Trust,
        "NEO343",
        "a remote module declares vaults; a vault declaration must come from a local \
         configuration source and is not granted by module content",
    ))
}

/// Merges one parsed document into the accumulated result.
///
/// Takes the accumulator rather than eight `&mut` out-parameters: the call sites
/// were unreadable, and every new field meant threading another through both of
/// them in the right position. The merge order below is unchanged, and is still
/// visible in one place -- the order is load-bearing, because a later source may
/// replace a value but may not declassify a secret, and because a document's own
/// `context:` has to be in effect before its `dotenv:` list is filtered.
fn apply_project(
    accumulated: &mut SourceAccumulator,
    parsed: neoenv_config::Project,
) -> Result<(), Diagnostic> {
    let SourceAccumulator {
        environment,
        vaults,
        tools,
        context,
        context_source,
        context_override,
        task_dirs,
        tasks,
        path,
        declared_contexts,
        jobs,
        inventories,
        deployments,
    } = accumulated;
    // Before the dotenv list, which is filtered by context: the reference
    // resolves the context first (`jobDotenvPaths` takes the resolved name), and
    // a file that sets `config.context` and then scopes a dotenv to it would
    // otherwise filter against whatever the *previous* source established.
    if let Some(declared) = &parsed.context {
        // Trimmed for the same reason as the override above.
        let declared = declared.trim();
        *context = (!declared.is_empty()).then(|| declared.to_owned());
        // **Every source sets this, not only the last.** The point is to know which
        // file the *winner* came from, and a later source that declares no `context:`
        // leaves the earlier one winning -- so the field is left alone in that case,
        // which happens by not touching it.
        *context_source = (!declared.is_empty()).then(|| PathBuf::from(&parsed.source.path));
        // The project's own `context:` is a declaration, and without this a
        // project that sets `context: dev` and has no `:dev` task variant is told
        // its own configured context is one it does not use. That is not a
        // hypothetical: the existing
        // `task_commands_resolve_context_render_help_and_never_execute_actions`
        // test is exactly that project.
        if !declared.is_empty()
            && !declared.contains('*')
            && !declared_contexts.iter().any(|known| known == declared)
        {
            declared_contexts.push(declared.to_owned());
        }
    }
    let os = std::env::consts::OS;
    // Every context either section declares is a context the project *uses*, so a
    // `--context` typo has something to be wrong against.
    //
    // Collected from both sections, and collected *before* either is filtered: the
    // set answers "what did this project write", not "what happened to load
    // here", so an entry excluded by its own `os` filter on this machine still
    // counts.
    //
    // These were two near-identical loops thirty lines apart -- one over `dotenv`
    // and one over `path`, and they had already drifted (`contains` against
    // `iter().any`) -- and the duplication is why the `path` half was missing for
    // a whole review round. That is how a project whose only contextual
    // declaration sat on a PATH entry looked context-free and accepted a typo
    // silently.
    for contexts in parsed
        .dotenv
        .iter()
        .map(|entry| &entry.filter.contexts)
        .chain(parsed.path.iter().map(|entry| &entry.filter.contexts))
    {
        for declared in contexts {
            // Trimmed, like both of the two places a context enters this function
            // (`:310` and `:434`). Untrimmed, `contexts: ['prod ']` made the context
            // *unusable* -- the filter compares exactly, so no entry matched -- and
            // *untypable* at the same time, because `validate_context` was then told
            // the project uses a context literally named `"prod "`.
            let declared = declared.trim();
            if !declared.is_empty()
                && !declared.contains('*')
                && !declared_contexts.iter().any(|known| known == declared)
            {
                declared_contexts.push(declared.to_owned());
            }
        }
    }
    for dotenv in parsed.dotenv {
        let effective = context_override.as_deref().or(context.as_deref());
        if !dotenv.filter.matches(os, effective.unwrap_or_default()) {
            continue;
        }
        apply_dotenv(environment, &dotenv)?;
    }
    for entry in parsed.environment {
        let value = interpolate(&entry.value, environment, &entry.source)?;
        // A later source may legitimately *replace* a value, but it must not be
        // able to declassify one an earlier source marked secret: a private
        // overlay that re-declares a key plainly would otherwise print a value
        // the project declared secret. Failing safe matches the rule the Go
        // compatibility profile applies within a single document.
        let already_secret = environment
            .get(&entry.key)
            .is_some_and(|existing| existing.secret);
        environment.insert(
            entry.key.clone(),
            EnvironmentEntry {
                value,
                secret: already_secret || entry.secret,
                ..entry
            },
        );
    }
    for mut operation in parsed.path {
        // The *effective* context, the same one the dotenv loop above uses. This
        // read the document's own value instead, so
        // `nenv run build --context prod` loaded a `contexts: [prod]` dotenv and
        // dropped a `contexts: [prod]` PATH entry -- one command, two worlds, and
        // the identical bug the dotenv loop was just fixed for.
        let effective = context_override.as_deref().or(context.as_deref());
        if !operation.filter.matches(os, effective.unwrap_or_default()) {
            continue;
        }
        operation.value = source_relative_path(&operation.value, &operation.source, environment)?;
        path.retain(|existing| existing.value != operation.value);
        path.push(operation);
    }
    tools.extend(parsed.tools);
    // A vault declaration is keyed by name, so a later source replaces an earlier
    // one whole rather than merging provider fields. Merging two providers field
    // by field would make a private overlay able to keep an identity from one
    // declaration and a path from another, which is a vault nobody wrote.
    for (name, vault) in parsed.vaults {
        vaults.insert(name, vault);
    }
    task_dirs.local.extend(parsed.task_dirs.local);
    task_dirs.global.extend(parsed.task_dirs.global);
    // Later sources win, the same as every other keyed section, and insertion
    // order is source order so `job list` is stable across a workspace.
    for (name, job) in parsed.jobs {
        jobs.insert(name, job);
    }
    inventories.push(
        PathBuf::from(&parsed.source.path),
        parsed.inventory_files,
        parsed.inventories,
    );
    for (name, deployment) in parsed.deployments {
        deployments.insert(name, deployment);
    }
    for (name, task) in parsed.tasks {
        tasks.insert(&name, task);
    }
    Ok(())
}

fn apply_dotenv(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    dotenv: &DotenvImport,
) -> Result<IndexMap<String, String>, Diagnostic> {
    apply_dotenv_values(environment, &dotenv.path, dotenv.required, &dotenv.source)
}

/// Applies one task dotenv document and returns the keys it assigned.
///
/// The assignment keys, not a before/after value comparison, are what tell the
/// resolver which values this task owns. An assignment equal to an inherited
/// value is still an assignment and must still be resolved if it is a reference.
pub(crate) fn apply_task_dotenv(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    dotenv: &TaskDotenvImport,
) -> Result<IndexMap<String, String>, Diagnostic> {
    apply_dotenv_values(environment, &dotenv.path, dotenv.required, &dotenv.source)
}

/// Imports a dotenv file named on the command line into `environment`.
///
/// The path is resolved against the caller's working directory and is required
/// to exist, because unlike a declared import the caller typed it explicitly.
/// There is deliberately no containment check here: containment exists to stop
/// a remote module from reading outside the project, and this is a path the user
/// named, exactly like a program handed to `exec`.
///
/// Values are interpolated against the environment as it stands, so a later
/// `-E` can reference an earlier one.
///
/// # Errors
///
/// Returns a validation diagnostic for a missing file, a malformed document, or
/// an invalid environment key, and a runtime diagnostic for an unreadable file.
pub fn apply_cli_dotenv(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    path: &Path,
) -> Result<(), Diagnostic> {
    apply_cli_dotenv_with_assignments(environment, path).map(|_| ())
}

/// Applies a CLI dotenv file and returns the keys it assigned.
///
/// See [`apply_cli_dotenv`] for the path and error rules. The assignment map is
/// the caller's ownership record: a command-line `-E` assignment is supplied even
/// when its text happens to equal the caller's inherited value.
///
/// # Errors
///
/// Returns the same diagnostics as [`apply_cli_dotenv`].
pub fn apply_cli_dotenv_with_assignments(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    path: &Path,
) -> Result<IndexMap<String, String>, Diagnostic> {
    let display = path.display().to_string();
    let input = read_text_file(path, &ResourceBudget::default()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO701",
                format!("required dotenv file was not found: {display}"),
            )
        } else {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO702",
                format!("failed to read dotenv file {display}: {error}"),
            )
            .with_cause(error)
        }
    })?;
    insert_dotenv_assignments(environment, path, &input)
}

/// Reads, validates, and merges one dotenv document at a resolved path.
///
/// Returns the keys the document assigned, in source order.
fn insert_dotenv_assignments(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    path: &Path,
    input: &str,
) -> Result<IndexMap<String, String>, Diagnostic> {
    let document = parse_dotenv(input);
    let mut assignments = IndexMap::new();
    if let Some((message, span)) = document.first_invalid() {
        return Err(
            Diagnostic::new(DiagnosticCategory::Validation, "NEO703", message).at(
                neoenv_core::SourceSpan::new(path.display().to_string(), span.line, span.column),
            ),
        );
    }
    for assignment in document.assignments() {
        let source =
            neoenv_core::SourceSpan::new(path.display().to_string(), assignment.span.line, 1);
        if !valid_environment_key(&assignment.key) {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO105",
                format!("invalid environment key: {}", assignment.key),
            )
            .at(source));
        }
        let value = interpolate(&assignment.value, environment, &source)?;
        // A dotenv document has no secret form of its own, so this entry is never
        // secret by declaration. It must still not *un-declare* one: a later
        // source's `dotenv:` setting a key an earlier source marked secret would
        // otherwise print it. Failing safe matches every other merge here.
        let already_secret = environment
            .get(&assignment.key)
            .is_some_and(|entry| entry.secret);
        assignments.insert(assignment.key.clone(), value.clone());
        environment.insert(
            assignment.key.clone(),
            EnvironmentEntry {
                key: assignment.key.clone(),
                value,
                source,
                secret: already_secret,
            },
        );
    }
    Ok(assignments)
}

fn apply_dotenv_values(
    environment: &mut IndexMap<String, EnvironmentEntry>,
    dotenv_path: &str,
    required: bool,
    declaration_source: &neoenv_core::SourceSpan,
) -> Result<IndexMap<String, String>, Diagnostic> {
    let source = Path::new(&declaration_source.path);
    let path = source
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(dotenv_path);
    let input = match read_text_file(&path, &ResourceBudget::default()) {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(IndexMap::new());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO701",
                format!("required dotenv file was not found: {}", path.display()),
            )
            .at(declaration_source.clone()));
        }
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO702",
                format!("failed to read dotenv file {}: {error}", path.display()),
            )
            .at(declaration_source.clone()));
        }
    };
    insert_dotenv_assignments(environment, &path, &input)
}

fn interpolate(
    value: &str,
    environment: &IndexMap<String, EnvironmentEntry>,
    source: &neoenv_core::SourceSpan,
) -> Result<String, Diagnostic> {
    if value.contains("$(") || value.contains('`') {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO111",
            "command substitution is not supported in environment declarations",
        )
        .at(source.clone()));
    }
    // **A secret reference keeps its `${NAME}` until use.** Configuration loading
    // does not know the final CLI context: a project value may be overridden with
    // `-e WHICH=token`, and expanding `${WHICH}` here would turn the reference
    // into `nsv://vault/` before the resolver ever saw it. Values that are not
    // references keep the existing eager interpolation.
    if value.trim_start().starts_with(REFERENCE_PREFIX) {
        return Ok(value.to_owned());
    }
    Ok(neotales_env::interpolate_with(value, |name| {
        environment.get(name).map(|entry| entry.value.as_str())
    }))
}

fn source_relative_path(
    value: &str,
    source: &neoenv_core::SourceSpan,
    environment: &IndexMap<String, EnvironmentEntry>,
) -> Result<String, Diagnostic> {
    let value = interpolate(value, environment, source)?;
    let path = Path::new(&value);
    if path.is_absolute() {
        return Ok(value);
    }
    Ok(Path::new(&source.path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(path)
        .display()
        .to_string())
}

fn inspection_sources(sources: &[ConfigSource]) -> Vec<InspectionSource> {
    sources
        .iter()
        .map(|source| InspectionSource {
            path: source.path().display().to_string(),
            kind: source.kind_name().into(),
        })
        .collect()
}

fn user_config_path() -> Option<PathBuf> {
    let config_root = user_directory(UserDirectory::Config)?;
    let candidate = config_root.join("neoenv/neoenv.yaml");
    candidate.is_file().then_some(candidate)
}

fn conventional_private_overlay(project_root: &Path) -> Option<PathBuf> {
    let directory = project_root.join("neoenv/private");
    CONFIGURATION_FILENAMES
        .iter()
        .map(|name| directory.join(name))
        .find(|candidate| candidate.is_file())
}
