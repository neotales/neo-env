//! Pure task planning: context selection, inheritance, dependency edges,
//! input binding, and validation. No filesystem, network, or process effects.

use super::help::{resolve_task_name, visit};
use super::predicate::validate_predicate;
use super::runners::{is_script_runner, is_template_runner, is_wsl_runner, parse_uv_runner};
use super::{
    BTreeMap, DEFAULT_CONTEXT, HashMap, HashSet, IndexMap, JobDefinition, PlannedTask, SourceSpan,
    TaskAction, TaskCapabilityRequest, TaskDefinition, TaskDependencyEdge, TaskDotenvImport,
    TaskEdgeOrigin, TaskError, TaskInputBinding, TaskInputError, TaskInputValues, TaskOutcome,
    TaskParameter, TaskParameterDefault, TaskParameterType, TaskPlan,
};

#[must_use]
pub fn select_context(
    cli_context: Option<&str>,
    environment_context: Option<&str>,
    project_context: Option<&str>,
) -> String {
    // Trimmed, and blank treated as unset, the way the resolution side does it.
    // They have to agree: an untrimmed `--context " prod "` gave the dotenv filter
    // `prod` and this `prod` with a space, so the flag loaded prod's dotenv and was
    // then rejected as an unknown context. And `--context ""` on a project with
    // `context: prod` loaded prod's dotenv while running the *default* task.
    //
    // `let`-chain shaped, which the release gate's toolchain rejects.
    let chosen = cli_context
        .map(str::trim)
        .filter(|context| !context.is_empty())
        .or_else(|| {
            environment_context
                .map(str::trim)
                .filter(|context| !context.is_empty())
        })
        .or_else(|| {
            project_context
                .map(str::trim)
                .filter(|context| !context.is_empty())
        });
    chosen.unwrap_or(DEFAULT_CONTEXT).to_owned()
}

/// Resolves `extends:` for the named tasks and whatever they inherit from, and
/// nothing else.
///
/// **This exists because resolving the whole map is the wrong granularity for
/// "run this task".** A project with one task whose `extends:` names a base that
/// does not exist used to make *every* task unrunnable, including a
/// self-contained task three lines above it in the same file -- so `nenv run
/// build` reported a problem with a task the user did not ask about and cannot
/// see. `resolve_inheritance` over the whole map is still what `validate` and the
/// project-wide reports want; this is what a single task wants.
///
/// Only the reachable chains are visited, so a broken task elsewhere in the file is
/// invisible here. That is the point, and it is the safe direction: the error
/// returned is one about a task the caller named or a base it actually inherits
/// from, never about a bystander.
///
/// # Errors
///
/// Returns an error for a missing base or an inheritance cycle reachable from
/// `names`. A cycle *is* still reported, because a cyclic chain the caller asked
/// for cannot be resolved into anything.
pub fn resolve_inheritance_for(
    tasks: &IndexMap<String, TaskDefinition>,
    names: &[String],
) -> Result<IndexMap<String, TaskDefinition>, TaskError> {
    let mut resolved = HashMap::new();
    let mut resolving = Vec::new();
    let mut result = IndexMap::with_capacity(names.len());
    for name in names {
        if !tasks.contains_key(name) {
            continue;
        }
        result.insert(
            name.clone(),
            resolve_one(name, tasks, &mut resolved, &mut resolving)?,
        );
    }
    Ok(result)
}

/// Resolves inherited task definitions while preserving declaration order.
///
/// **The whole-map resolution**, which is what `validate` and the project-wide
/// reports want. A single task wants [`resolve_inheritance_for`], whose whole
/// reason to exist is that this one turns one dangling base into a project-wide
/// failure.
///
/// # Errors
///
/// Returns an error for missing bases, inheritance cycles, missing actions, or
/// invalid parameter definitions.
pub fn resolve_inheritance(
    tasks: &IndexMap<String, TaskDefinition>,
) -> Result<IndexMap<String, TaskDefinition>, TaskError> {
    let mut resolved = HashMap::new();
    let mut resolving = Vec::new();
    let mut result = IndexMap::with_capacity(tasks.len());
    for name in tasks.keys() {
        result.insert(
            name.clone(),
            resolve_one(name, tasks, &mut resolved, &mut resolving)?,
        );
    }
    for (name, task) in &result {
        validate_task(name, task)?;
    }
    validate_identities(&result)?;
    Ok(result)
}

/// Renders metadata for the context-selected task without evaluating it.
///
/// # Errors
///
/// Returns an error when no matching task exists for the requested context.
/// Returns dependency and hook edges paired with their declaration origins.
#[must_use]
pub fn task_dependency_edges(
    task: &TaskDefinition,
) -> (
    Vec<TaskDependencyEdge>,
    Vec<TaskDependencyEdge>,
    Vec<TaskDependencyEdge>,
) {
    let edges = |names: &[String], origins: &[TaskEdgeOrigin]| {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| TaskDependencyEdge {
                name: name.clone(),
                origin: origins.get(index).copied().unwrap_or_default(),
            })
            .collect()
    };
    (
        edges(&task.needs, &task.dependency_origins.needs),
        edges(&task.hooks.before, &task.dependency_origins.before),
        edges(&task.hooks.after, &task.dependency_origins.after),
    )
}

/// Binds a root task's declared command-line inputs. Options are parsed only
/// before `--`; every token after that separator is passed literally to the
/// selected runner.
///
/// # Errors
///
/// Returns a task-selection or input diagnostic when an option, positional
/// value, required parameter, or typed value is invalid.
pub fn bind_task_inputs(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
    arguments: &[String],
) -> Result<TaskInputBinding, TaskInputError> {
    let task_name =
        resolve_task_name(tasks, requested_name, context).map_err(TaskInputError::Task)?;
    let task = &tasks[&task_name];
    let mut values = TaskInputValues::new();
    let positional = task
        .parameters
        .iter()
        .filter_map(|parameter| parameter.position.map(|position| (position, parameter)))
        .collect::<BTreeMap<_, _>>();
    let has_positional_contract = !positional.is_empty();
    let mut positional_index = 0;
    let mut passthrough = Vec::new();
    let mut after_separator = false;
    let mut index = 0;

    while index < arguments.len() {
        let argument = &arguments[index];
        if after_separator {
            passthrough.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            after_separator = true;
            index += 1;
            continue;
        }
        if let Some(option) = argument.strip_prefix("--") {
            let (option, inline_value) = option
                .split_once('=')
                .map_or((option, None), |(name, value)| (name, Some(value)));
            bind_long_option(
                option,
                inline_value,
                argument,
                task,
                &task_name,
                arguments,
                &mut index,
                &mut values,
            )?;
            continue;
        }
        if let Some(option) = argument.strip_prefix('-') {
            bind_short_option(
                option,
                argument,
                task,
                &task_name,
                arguments,
                &mut index,
                &mut values,
            )?;
            continue;
        }

        if let Some(parameter) = positional.get(&positional_index) {
            insert_input_value(&mut values, &task_name, parameter, argument.clone())?;
            if !parameter.repeatable {
                positional_index += 1;
            }
        } else if has_positional_contract {
            return Err(TaskInputError::UnexpectedPositional {
                task: task_name,
                value: argument.clone(),
            });
        } else {
            passthrough.push(argument.clone());
        }
        index += 1;
    }

    for parameter in &task.parameters {
        let static_value = task
            .action
            .as_ref()
            .and_then(|action| action.with.get(&parameter.name));
        if parameter.required
            && !values.contains_key(&parameter.name)
            && static_value.is_none()
            && parameter.default.is_none()
        {
            return Err(TaskInputError::MissingRequired {
                task: task_name.clone(),
                parameter: parameter.name.clone(),
            });
        }
    }
    Ok(TaskInputBinding {
        values,
        passthrough,
    })
}

#[allow(clippy::too_many_arguments)]
fn bind_long_option(
    option: &str,
    inline_value: Option<&str>,
    argument: &str,
    task: &TaskDefinition,
    task_name: &str,
    arguments: &[String],
    index: &mut usize,
    values: &mut TaskInputValues,
) -> Result<(), TaskInputError> {
    if let Some(name) = option.strip_prefix("no-") {
        let parameter = task.parameters.iter().find(|parameter| {
            parameter.long.as_deref() == Some(name)
                && parameter.parameter_type == TaskParameterType::Boolean
        });
        let parameter = parameter.ok_or_else(|| TaskInputError::UnknownOption {
            task: task_name.to_owned(),
            option: format!("--{option}"),
        })?;
        if inline_value.is_some() {
            return Err(TaskInputError::InvalidValue {
                task: task_name.to_owned(),
                parameter: parameter.name.clone(),
                value: argument.to_owned(),
            });
        }
        insert_input_value(values, task_name, parameter, "false".into())?;
        *index += 1;
        return Ok(());
    }
    let parameter = task
        .parameters
        .iter()
        .find(|parameter| parameter.long.as_deref() == Some(option))
        .ok_or_else(|| TaskInputError::UnknownOption {
            task: task_name.to_owned(),
            option: format!("--{option}"),
        })?;
    let value = option_value(
        arguments,
        index,
        inline_value,
        parameter,
        task_name,
        &format!("--{option}"),
    )?;
    insert_input_value(values, task_name, parameter, value)?;
    *index += 1;
    Ok(())
}

fn bind_short_option(
    option: &str,
    argument: &str,
    task: &TaskDefinition,
    task_name: &str,
    arguments: &[String],
    index: &mut usize,
    values: &mut TaskInputValues,
) -> Result<(), TaskInputError> {
    if option.is_empty() {
        return Err(TaskInputError::UnexpectedPositional {
            task: task_name.to_owned(),
            value: argument.to_owned(),
        });
    }
    if option.chars().count() != 1 {
        return Err(TaskInputError::UnknownOption {
            task: task_name.to_owned(),
            option: argument.to_owned(),
        });
    }
    let Some(short) = option.chars().next() else {
        return Err(TaskInputError::UnknownOption {
            task: task_name.to_owned(),
            option: argument.to_owned(),
        });
    };
    let parameter = task
        .parameters
        .iter()
        .find(|parameter| parameter.short == Some(short))
        .ok_or_else(|| TaskInputError::UnknownOption {
            task: task_name.to_owned(),
            option: argument.to_owned(),
        })?;
    let value = option_value(arguments, index, None, parameter, task_name, argument)?;
    insert_input_value(values, task_name, parameter, value)?;
    *index += 1;
    Ok(())
}

fn option_value(
    arguments: &[String],
    index: &mut usize,
    inline_value: Option<&str>,
    parameter: &TaskParameter,
    task: &str,
    option: &str,
) -> Result<String, TaskInputError> {
    if let Some(value) = inline_value {
        return Ok(value.to_owned());
    }
    if parameter.parameter_type == TaskParameterType::Boolean {
        return Ok("true".into());
    }
    let value = arguments
        .get(*index + 1)
        .filter(|value| *value != "--")
        .ok_or_else(|| TaskInputError::MissingOptionValue {
            task: task.to_owned(),
            option: option.to_owned(),
        })?;
    *index += 1;
    Ok(value.clone())
}

fn insert_input_value(
    values: &mut TaskInputValues,
    task: &str,
    parameter: &TaskParameter,
    value: String,
) -> Result<(), TaskInputError> {
    let value = normalize_input_value(parameter, value.clone()).ok_or_else(|| {
        TaskInputError::InvalidValue {
            task: task.to_owned(),
            parameter: parameter.name.clone(),
            value,
        }
    })?;
    let entry = values.entry(parameter.name.clone()).or_default();
    if !parameter.repeatable && !entry.is_empty() {
        return Err(TaskInputError::DuplicateOption {
            task: task.to_owned(),
            parameter: parameter.name.clone(),
        });
    }
    entry.push(value);
    Ok(())
}

/// Returns a canonical string representation for a typed task input.
#[must_use]
pub fn normalize_input_value(parameter: &TaskParameter, value: String) -> Option<String> {
    match parameter.parameter_type {
        TaskParameterType::String => Some(value),
        TaskParameterType::Boolean => value.parse::<bool>().ok().map(|value| value.to_string()),
        TaskParameterType::Integer => value.parse::<i64>().ok().map(|value| value.to_string()),
    }
}

/// Produces a dependency-first execution plan without running task actions.
///
/// # Errors
///
/// Returns an error for missing tasks or dependencies, or a dependency cycle.
pub fn plan_task(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
) -> Result<TaskPlan, TaskError> {
    let root = resolve_task_name(tasks, requested_name, context)?;
    let mut planned = HashSet::new();
    let mut visiting = Vec::new();
    let mut task_names = Vec::new();
    visit(
        &root,
        tasks,
        context,
        &mut planned,
        &mut visiting,
        &mut task_names,
    )?;
    for name in &task_names {
        let task = &tasks[name];
        if task.wait.iter().any(|name| name == "all") && task.wait.len() != 1 {
            return Err(TaskError::InvalidAction {
                task: name.clone(),
                message: "`wait: all` cannot be combined with named waits".into(),
            });
        }
        if task
            .parallel_needs
            .iter()
            .any(|parallel| !task.needs.contains(parallel))
        {
            return Err(TaskError::InvalidAction {
                task: name.clone(),
                message: "parallel dependencies must also be in needs".into(),
            });
        }
    }
    Ok(TaskPlan {
        context: context.to_owned(),
        tasks: task_names
            .into_iter()
            .map(|name| {
                let task = &tasks[&name];
                let (dependencies, before_hooks, after_hooks) = task_dependency_edges(task);
                PlannedTask {
                    name,
                    background: task.background == Some(true),
                    wait: task.wait.clone(),
                    parallel_dependencies: task.parallel_needs.clone(),
                    outcome: TaskOutcome::Planned,
                    package: task.package.clone(),
                    dependencies,
                    before_hooks,
                    after_hooks,
                }
            })
            .collect(),
    })
}

fn resolve_one(
    name: &str,
    tasks: &IndexMap<String, TaskDefinition>,
    resolved: &mut HashMap<String, TaskDefinition>,
    resolving: &mut Vec<String>,
) -> Result<TaskDefinition, TaskError> {
    if let Some(task) = resolved.get(name) {
        return Ok(task.clone());
    }
    if let Some(position) = resolving.iter().position(|item| item == name) {
        let mut trace = resolving[position..].to_vec();
        trace.push(name.to_owned());
        return Err(TaskError::InheritanceCycle { trace });
    }
    let task = &tasks[name];
    resolving.push(name.to_owned());
    let mut resolved_task = if let Some(base) = &task.extends {
        if !tasks.contains_key(base) {
            return Err(TaskError::MissingBase {
                task: name.to_owned(),
                base: base.clone(),
            });
        }
        merge_task(resolve_one(base, tasks, resolved, resolving)?, task.clone())
    } else {
        task.clone()
    };
    resolving.pop();
    resolved_task.extends = None;
    // Identity belongs to this declaration, never to its template/base.
    resolved_task.id = task.id.clone().or_else(|| Some(name.to_owned()));
    resolved_task.name = task.name.clone().or_else(|| Some(name.to_owned()));
    resolved_task.slug = task.slug.clone().or_else(|| Some(slugify(name)));
    resolved.insert(name.to_owned(), resolved_task.clone());
    Ok(resolved_task)
}

fn merge_task(mut base: TaskDefinition, child: TaskDefinition) -> TaskDefinition {
    base.execution_grant_required |= child.execution_grant_required;
    base.background = child.background.or(base.background);
    if !child.wait.is_empty() {
        base.wait = child.wait;
    }
    let child_declares_capabilities = child
        .action
        .as_ref()
        .is_some_and(|action| !action.capabilities.is_empty());
    let child_capability_requests = if child_declares_capabilities {
        if child.capability_requests.is_empty() {
            child
                .action
                .as_ref()
                .into_iter()
                .flat_map(|action| &action.capabilities)
                .map(|capability| TaskCapabilityRequest {
                    capability: capability.clone(),
                    origin: TaskEdgeOrigin::Caller,
                })
                .collect()
        } else {
            child.capability_requests
        }
    } else {
        Vec::new()
    };
    base.name = child.name.or(base.name);
    base.description = child.description.or(base.description);
    base.help = child.help.or(base.help);
    base.package = child.package.or(base.package);
    if child
        .action
        .as_ref()
        .and_then(|action| action.uses.as_deref())
        .is_some_and(|runner| runner != "composite")
    {
        base.composite_steps.clear();
    }
    if !child.composite_steps.is_empty() {
        base.composite_steps = child.composite_steps;
    }
    base.action = match (base.action, child.action) {
        (Some(base), Some(child)) => Some(merge_action(base, child)),
        (base, child) => child.or(base),
    };
    if !child.needs.is_empty() {
        base.parallel_needs = child.parallel_needs;
        base.needs = child.needs;
        base.dependency_origins.needs = edge_origins(&base.needs, &child.dependency_origins.needs);
    }
    if !child.hooks.before.is_empty() {
        base.hooks.before = child.hooks.before;
        base.dependency_origins.before =
            edge_origins(&base.hooks.before, &child.dependency_origins.before);
    }
    if !child.hooks.after.is_empty() {
        base.hooks.after = child.hooks.after;
        base.dependency_origins.after =
            edge_origins(&base.hooks.after, &child.dependency_origins.after);
    }
    if child_declares_capabilities {
        base.capability_requests = child_capability_requests;
    }
    base.template = child.template;
    base.outputs.extend(child.outputs);
    base.if_condition = child.if_condition.or(base.if_condition);
    base.force = child.force.or(base.force);
    merge_parameters(&mut base.parameters, child.parameters);
    base
}

fn edge_origins(names: &[String], origins: &[TaskEdgeOrigin]) -> Vec<TaskEdgeOrigin> {
    names
        .iter()
        .enumerate()
        .map(|(index, _)| origins.get(index).copied().unwrap_or_default())
        .collect()
}

fn validate_identities(tasks: &IndexMap<String, TaskDefinition>) -> Result<(), TaskError> {
    let mut ids = BTreeMap::<String, Vec<String>>::new();
    let mut slugs = BTreeMap::<String, Vec<String>>::new();
    for (key, task) in tasks {
        let id = task
            .id
            .as_deref()
            .ok_or_else(|| TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "id".into(),
            })?;
        let name = task
            .name
            .as_deref()
            .ok_or_else(|| TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "name".into(),
            })?;
        let slug = task
            .slug
            .as_deref()
            .ok_or_else(|| TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "slug".into(),
            })?;
        if !valid_id(id) {
            return Err(TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "id".into(),
            });
        }
        if name.trim().is_empty() {
            return Err(TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "name".into(),
            });
        }
        if !valid_slug(slug) {
            return Err(TaskError::InvalidTaskIdentity {
                task: key.clone(),
                field: "slug".into(),
            });
        }
        ids.entry(id.to_owned()).or_default().push(key.clone());
        slugs.entry(slug.to_owned()).or_default().push(key.clone());
    }
    for (field, values) in [("id", ids), ("slug", slugs)] {
        if let Some((value, tasks)) = values.into_iter().find(|(_, tasks)| tasks.len() > 1) {
            return Err(TaskError::DuplicateTaskIdentity {
                field: field.into(),
                value,
                tasks,
            });
        }
    }
    Ok(())
}

pub(super) fn task_identity(key: &str, task: &TaskDefinition) -> (String, String, String) {
    (
        task.id.clone().unwrap_or_else(|| key.to_owned()),
        task.name.clone().unwrap_or_else(|| key.to_owned()),
        task.slug.clone().unwrap_or_else(|| slugify(key)),
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/')
        })
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut hyphen = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            hyphen = false;
        } else if !slug.is_empty() && !hyphen {
            slug.push('-');
            hyphen = true;
        }
    }
    slug.trim_end_matches('-').to_owned()
}

fn merge_action(mut base: TaskAction, child: TaskAction) -> TaskAction {
    base.uses = child.uses.or(base.uses);
    base.run = child.run.or(base.run);
    if child.source.is_some() {
        base.source = child.source;
        base.source_document = child.source_document;
        base.source_from_package = child.source_from_package;
    }
    if child.destination.is_some() {
        base.destination = child.destination;
        base.destination_document = child.destination_document;
        base.destination_from_package = child.destination_from_package;
    }
    if !child.args.is_empty() {
        base.args = child.args;
    }
    if !child.files.is_empty() {
        base.files = child.files;
        base.files_document = child.files_document;
        base.files_from_package = child.files_from_package;
    }
    if child.cwd.is_some() {
        base.cwd = child.cwd;
        base.cwd_document = child.cwd_document;
        base.cwd_from_package = child.cwd_from_package;
    }
    base.env.extend(child.env);
    if !child.dotenv.is_empty() {
        base.dotenv = child.dotenv;
    }
    let child_overrides_values = child.with.contains_key("values");
    base.with.extend(child.with);
    if child_overrides_values {
        base.values_document = child.values_document;
        base.values_from_package = child.values_from_package;
    }
    if !child.capabilities.is_empty() {
        base.capabilities = child.capabilities;
    }
    base
}

fn merge_parameters(base: &mut Vec<TaskParameter>, child: Vec<TaskParameter>) {
    let positions: HashMap<_, _> = base
        .iter()
        .enumerate()
        .map(|(index, parameter)| (parameter.name.clone(), index))
        .collect();
    for parameter in child {
        if let Some(position) = positions.get(&parameter.name) {
            base[*position] = parameter;
        } else {
            base.push(parameter);
        }
    }
}

fn validate_task(name: &str, task: &TaskDefinition) -> Result<(), TaskError> {
    if !task.outputs.is_empty()
        && task
            .action
            .as_ref()
            .is_some_and(|action| action.uses.as_deref() == Some("ssh"))
    {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "SSH tasks do not support local output handoff files".into(),
        });
    }
    if !task.template && task.action.is_none() && task.wait.is_empty() && task.job.is_none() {
        return Err(TaskError::MissingAction {
            task: name.to_owned(),
        });
    }
    if !task.template && task.action.is_some() {
        validate_task_action(
            name,
            task.action
                .as_ref()
                .ok_or_else(|| TaskError::MissingAction {
                    task: name.to_owned(),
                })?,
        )?;
    }
    for output in task.outputs.keys() {
        if !valid_environment_key(output) {
            return Err(TaskError::InvalidOutput {
                task: name.to_owned(),
                output: output.clone(),
            });
        }
    }
    for (field, predicate) in [("if", &task.if_condition), ("force", &task.force)] {
        if let Some(predicate) = predicate {
            validate_predicate(predicate).map_err(|message| TaskError::InvalidPredicate {
                task: name.to_owned(),
                field: field.to_owned(),
                message,
            })?;
        }
    }
    validate_parameters(name, &task.parameters)?;
    validate_positional_parameters(name, &task.parameters)?;
    Ok(())
}

fn validate_task_action(name: &str, action: &TaskAction) -> Result<(), TaskError> {
    let uses = action
        .uses
        .as_deref()
        .ok_or_else(|| TaskError::InvalidAction {
            task: name.to_owned(),
            message: "must specify a runner".to_owned(),
        })?;
    if is_wsl_runner(uses) {
        validate_wsl_action(name, action)?;
    } else {
        validate_script_runner_action(name, uses, action)?;
    }
    if uses == "ssh"
        && (!action.args.is_empty()
            || action.cwd.is_some()
            || action.source.is_some()
            || action.destination.is_some()
            || action
                .with
                .keys()
                .any(|key| !matches!(key.as_str(), "inventory" | "targets" | "timeout"))
            || ["inventory", "targets"]
                .iter()
                .any(|key| action.with.get(*key).is_none_or(String::is_empty)))
    {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "SSH requires with.inventory and with.targets; only with.timeout, env and dotenv are additionally supported, not local args/cwd/source/destination".into(),
        });
    }
    if uses == "render" {
        if action.source.as_deref().is_none_or(str::is_empty)
            || action.destination.as_deref().is_none_or(str::is_empty)
        {
            return Err(TaskError::InvalidAction {
                task: name.to_owned(),
                message: "render actions must specify non-empty source and destination values"
                    .to_owned(),
            });
        }
        if action.run.is_some()
            || !action.args.is_empty()
            || action.cwd.is_some()
            || !action.env.is_empty()
            || !action.dotenv.is_empty()
            || !action.capabilities.is_empty()
        {
            return Err(TaskError::InvalidAction {
                task: name.to_owned(),
                message: "render actions may only use source, destination, and with inputs"
                    .to_owned(),
            });
        }
    }
    for (key, value) in &action.env {
        if !valid_environment_key(key) {
            return Err(TaskError::InvalidEnvironmentKey {
                task: name.to_owned(),
                key: key.clone(),
            });
        }
        if value.contains("$(") || value.contains('`') {
            return Err(TaskError::CommandSubstitution {
                task: name.to_owned(),
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn validate_wsl_action(name: &str, action: &TaskAction) -> Result<(), TaskError> {
    if action.run.as_deref().is_none_or(str::is_empty) {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "wsl requires a non-empty run value".to_owned(),
        });
    }
    if action.source.is_some() || action.destination.is_some() || !action.files.is_empty() {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "wsl reads run only; source, destination, and with.files are not supported"
                .to_owned(),
        });
    }
    for (key, value) in &action.with {
        match key.as_str() {
            "distribution" => {
                if value.trim().is_empty() || value.contains('\0') {
                    return Err(TaskError::InvalidAction {
                        task: name.to_owned(),
                        message: "wsl with.distribution must be a non-empty name".to_owned(),
                    });
                }
            }
            "mount-root" => {
                if value.trim().is_empty()
                    || !value.trim().starts_with('/')
                    || value.contains('\\')
                    || value.contains('\0')
                    || value
                        .split('/')
                        .any(|component| matches!(component, "." | ".."))
                {
                    return Err(TaskError::InvalidAction {
                        task: name.to_owned(),
                        message: "wsl with.mount-root must be an absolute Linux directory                                   without `.` or `..`"
                            .to_owned(),
                    });
                }
            }
            "timeout" => {}
            other => {
                return Err(TaskError::InvalidAction {
                    task: name.to_owned(),
                    message: format!(
                        "unknown wsl with key {other:?}; supported keys are distribution, \
                         mount-root, and timeout"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_template_action(name: &str, action: &TaskAction) -> Result<(), TaskError> {
    if action.files.is_empty() {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "tmpl requires at least one `with.files` mapping".to_owned(),
        });
    }
    if action.run.is_some()
        || action.source.is_some()
        || action.destination.is_some()
        || !action.args.is_empty()
        || action.cwd.is_some()
        || !action.capabilities.is_empty()
    {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "tmpl actions may only use with.files, with.values, with.disable-env, \
                      with.disable-gotmpl, env, and dotenv; run/source/destination/args/cwd/\
                      capabilities are not read"
                .to_owned(),
        });
    }
    for (key, value) in &action.with {
        match key.as_str() {
            "values" => {
                if value.trim().is_empty() {
                    return Err(TaskError::InvalidAction {
                        task: name.to_owned(),
                        message: "tmpl with.values must be a non-empty path".to_owned(),
                    });
                }
            }
            "disable-env" | "disable-gotmpl" => {
                if !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "true" | "false" | "1" | "0"
                ) {
                    return Err(TaskError::InvalidAction {
                        task: name.to_owned(),
                        message: format!("tmpl with.{key} must be a boolean"),
                    });
                }
            }
            other => {
                return Err(TaskError::InvalidAction {
                    task: name.to_owned(),
                    message: format!(
                        "unknown tmpl with key {other:?}; supported keys are files, values, \
                         disable-env, and disable-gotmpl"
                    ),
                });
            }
        }
    }
    for spec in &action.files {
        let source = spec
            .split_once(':')
            .map_or(spec.as_str(), |(source, _)| source)
            .trim();
        if source.is_empty() {
            return Err(TaskError::InvalidAction {
                task: name.to_owned(),
                message: format!(
                    "tmpl file mapping {spec:?} has an empty source; write \
                     `source` or `source:destination`"
                ),
            });
        }
    }
    Ok(())
}

fn validate_script_runner_action(
    name: &str,
    uses: &str,
    action: &TaskAction,
) -> Result<(), TaskError> {
    if is_template_runner(uses) {
        return validate_template_action(name, action);
    }
    if !action.files.is_empty() {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: format!("with.files is only read by tmpl; {uses} does not read it"),
        });
    }
    let uv = parse_uv_runner(uses).map_err(|message| TaskError::InvalidAction {
        task: name.to_owned(),
        message,
    })?;
    let script_runner = is_script_runner(uses);
    let inline = action.run.as_deref().is_some_and(|run| !run.is_empty());
    let file = action
        .source
        .as_deref()
        .is_some_and(|source| !source.is_empty());
    if script_runner || uv.is_some() {
        // Explicit inline-vs-file. An empty `run:` beside a `source:` is the one
        // spelling that would otherwise "work" while saying two different things.
        if inline == file {
            return Err(TaskError::InvalidAction {
                task: name.to_owned(),
                message: if inline {
                    "must specify exactly one of run (inline script) or source (script file), \
                     not both"
                        .to_owned()
                } else {
                    "must specify run (inline script) or source (script file)".to_owned()
                },
            });
        }
    } else if uses != "render" && uses != "composite" && !inline {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: "must specify a non-empty run value".to_owned(),
        });
    }
    if !script_runner && uv.is_none() && uses != "render" && action.source.is_some() {
        return Err(TaskError::InvalidAction {
            task: name.to_owned(),
            message: format!(
                "source is only supported by the render runner and named script runners; \
                 {uses} reads its script from run"
            ),
        });
    }
    Ok(())
}

fn validate_parameters(name: &str, parameters: &[TaskParameter]) -> Result<(), TaskError> {
    let mut names = HashSet::new();
    let mut positions = HashSet::new();
    let mut longs = HashSet::new();
    let mut shorts = HashSet::new();
    for parameter in parameters {
        validate_parameter(
            name,
            parameter,
            &mut names,
            &mut positions,
            &mut longs,
            &mut shorts,
        )?;
    }
    Ok(())
}

fn validate_parameter<'a>(
    name: &str,
    parameter: &'a TaskParameter,
    names: &mut HashSet<&'a str>,
    positions: &mut HashSet<usize>,
    longs: &mut HashSet<&'a str>,
    shorts: &mut HashSet<char>,
) -> Result<(), TaskError> {
    if !names.insert(&parameter.name) {
        return Err(TaskError::DuplicateParameter {
            task: name.to_owned(),
            parameter: parameter.name.clone(),
        });
    }
    if !valid_environment_key(&parameter.name) {
        return Err(TaskError::InvalidParameter {
            task: name.to_owned(),
            parameter: parameter.name.clone(),
            message: "name must be a valid environment key".into(),
        });
    }
    if let Some(position) = parameter.position {
        if parameter.long.is_some() || parameter.short.is_some() {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: "cannot combine positional and option bindings".into(),
            });
        }
        if !positions.insert(position) {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: format!("positional index {position} is already used"),
            });
        }
    }
    if let Some(long) = &parameter.long
        && (!valid_long_option(long) || !longs.insert(long) || is_reserved_task_option(long))
    {
        return Err(TaskError::InvalidParameter {
            task: name.to_owned(),
            parameter: parameter.name.clone(),
            message: format!("long option --{long} is invalid, duplicate, or reserved"),
        });
    }
    if let Some(short) = parameter.short {
        if !short.is_ascii_alphanumeric() || !shorts.insert(short) {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: format!("short option -{short} is invalid or duplicate"),
            });
        }
        if is_reserved_task_short(short) {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: format!("short option -{short} is reserved for nenv"),
            });
        }
    }
    if !valid_parameter_default(parameter) {
        return Err(TaskError::InvalidParameterDefault {
            task: name.to_owned(),
            parameter: parameter.name.clone(),
        });
    }
    Ok(())
}

fn valid_parameter_default(parameter: &TaskParameter) -> bool {
    matches!(
        (&parameter.parameter_type, &parameter.default),
        (_, None)
            | (
                TaskParameterType::String,
                Some(TaskParameterDefault::String(_))
            )
            | (
                TaskParameterType::Boolean,
                Some(TaskParameterDefault::Boolean(_))
            )
            | (
                TaskParameterType::Integer,
                Some(TaskParameterDefault::Integer(_))
            )
    )
}

fn validate_positional_parameters(
    name: &str,
    parameters: &[TaskParameter],
) -> Result<(), TaskError> {
    let positional = parameters
        .iter()
        .filter_map(|parameter| parameter.position.map(|position| (position, parameter)))
        .collect::<BTreeMap<_, _>>();
    for (expected, (position, parameter)) in positional.iter().enumerate() {
        if *position != expected {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: "positional indexes must start at zero and be contiguous".into(),
            });
        }
        if parameter.repeatable && expected + 1 != positional.len() {
            return Err(TaskError::InvalidParameter {
                task: name.to_owned(),
                parameter: parameter.name.clone(),
                message: "a repeatable positional input must be last".into(),
            });
        }
    }
    Ok(())
}

fn valid_long_option(option: &str) -> bool {
    !option.is_empty()
        && !option.starts_with('-')
        && !option.ends_with('-')
        && option.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Options the CLI claims for itself after a task name.
///
/// `run` and `task run` keep recognizing their own options after the task name,
/// so a task that binds one of these would have its input silently swallowed.
/// Rejecting the declaration is the fix: the same rule that already covers
/// `dry-run` and `capability-policy`.
fn is_reserved_task_option(option: &str) -> bool {
    matches!(
        option,
        "help"
            | "format"
            | "context"
            | "dry-run"
            | "capability-policy"
            | "project"
            | "dotenv"
            | "env"
            | "version"
    )
}

/// Short options the CLI claims after a task name.
///
/// Reserved for the same reason the long names are: a task binding one would
/// have its input silently swallowed. `h` is here because `requested_help_command`
/// claims `--help` at any position before `--`, and `c` is deliberately absent
/// because `--context` has no short form, so `-c` already belongs to the task.
fn is_reserved_task_short(short: char) -> bool {
    matches!(short, 'h' | 'p' | 'E' | 'e')
}

/// Reports whether `key` is a portable environment variable name.
///
/// This is the single definition. Configuration `env:` entries, dotenv imports,
/// task handoff documents, and CLI `--env KEY=VALUE` all validate through it, so
/// one rule produces one diagnostic everywhere.
#[must_use]
pub fn valid_environment_key(key: &str) -> bool {
    let mut characters = key.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Lowers one job's steps into tasks, chained so they run in declaration order.
///
/// ## Why a chain and not a new executor
///
/// A job is a sequence, and the existing executor is a dependency-first walk. **A
/// linear `needs` chain is exactly a sequence**, so the steps become ordinary tasks
/// where step *n* depends on step *n-1*, and the planner produces them in order
/// without a second step scheduler. Background steps make those edges launch
/// ordering; explicit waits add completion barriers.
///
/// That gets the two properties a job actually needs for free, because they are
/// properties of the task executor rather than of a job executor:
///
/// - **the environment accumulates across steps**, because one plan shares one
///   environment (`scheduler.rs`, `apply_handoff` per node), and
/// - **a failing step stops the ones after it**, because the plan marks everything
///   downstream blocked.
///
/// It is also what the reference does, in effect: `taskFromJobStep`
/// (`neofile/runner.go:667-698`) desugars every step into a `Task` and runs it
/// through the ordinary task executor.
///
/// ## The key, and why it is not the step's name
///
/// `{job}:{position}`. The reference lets a step's `id` or `name` become the task's
/// name, which means a step can collide with a real task or with another step, and
/// the collision is silent -- the later declaration wins. Here the key is always
/// derived, the declared name goes to the task's *display* name, and two steps
/// cannot collide with anything. A deliberate divergence in the safe direction.
///
/// ## A repeated task is refused, not collapsed
///
/// `steps: [build, test, build]` cannot be expressed in a chain: the second `build`
/// is already in the closure and the planner would run it once. The reference runs
/// it twice. Neither is obviously right, but a **silent collapse** is the failure
/// this repository keeps finding, so it is refused by name.
///
/// # Errors
///
/// Returns an error for an empty list, a missing task reference, repeated task
/// references or ambiguous/missing wait identities. A wait-only step is a barrier.
/// Job-level dependencies are handled by [`lower_jobs`], not this step lowering.
pub fn lower_job(
    job_key: &str,
    job: &JobDefinition,
    tasks: &IndexMap<String, TaskDefinition>,
) -> Result<LoweredJob, TaskError> {
    if job.steps.is_empty() {
        // Not `expect`. The reader refuses a job with no steps, so this is
        // unreachable through the CLI -- and a public function that panics on
        // unreachable input is one where the panic is the only documentation of the
        // invariant, and it is documentation nobody reads.
        return Err(TaskError::JobStepEmpty {
            job: job_key.to_owned(),
        });
    }
    let mut lowered = IndexMap::new();
    let mut previous: Option<String> = None;
    let mut referenced: Vec<String> = Vec::new();
    let aliases = job_step_aliases(job_key, job)?;

    for (index, step) in job.steps.iter().enumerate() {
        let key = format!("{job_key}:{}", index + 1);
        let mut definition = match &step.task {
            Some(reference) => {
                let source = tasks
                    .get(reference)
                    .ok_or_else(|| TaskError::JobStepTaskMissing {
                        job: job_key.to_owned(),
                        step: index + 1,
                        task: reference.clone(),
                    })?;
                if referenced.iter().any(|seen| seen == reference) {
                    return Err(TaskError::JobStepRepeated {
                        job: job_key.to_owned(),
                        task: reference.clone(),
                    });
                }
                referenced.push(reference.clone());
                source.clone()
            }
            None => TaskDefinition {
                action: step.run.as_ref().map(|_| TaskAction {
                    uses: Some(step.uses.clone().unwrap_or_else(|| "exec".to_owned())),
                    run: step.run.clone(),
                    args: step.args.clone(),
                    cwd: step.cwd.clone().or_else(|| job.cwd.clone()),
                    env: merged_env(&job.env, &step.env),
                    ..TaskAction::default()
                }),
                ..TaskDefinition::default()
            },
        };
        // A referenced task keeps its own body; the step supplies the job's defaults
        // and its own overrides on top, exactly as `taskFromJobStep` does.
        apply_step_defaults(&mut definition, job, step);
        definition.id = Some(key.clone());
        definition.name = step
            .name
            .clone()
            .or_else(|| step.id.clone())
            .or(Some(key.clone()));
        definition.slug = Some(key.clone());
        definition.background = step.background.or(definition.background);
        if !step.wait.is_empty() {
            definition.wait = step
                .wait
                .iter()
                .map(|name| {
                    if name == "all" {
                        return Ok(name.clone());
                    }
                    aliases
                        .get(name)
                        .cloned()
                        .ok_or_else(|| TaskError::InvalidAction {
                            task: key.clone(),
                            message: format!("wait names no step: {name}"),
                        })
                })
                .collect::<Result<_, _>>()?;
        }
        if let Some(condition) = &step.if_condition {
            definition.if_condition = Some(condition.clone());
        }
        if let Some(force) = &step.force {
            definition.force = Some(force.clone());
        }
        if let Some(previous) = &previous {
            definition.needs.insert(0, previous.clone());
            definition
                .dependency_origins
                .needs
                .insert(0, super::TaskEdgeOrigin::Caller);
        }
        previous = Some(key.clone());
        lowered.insert(key, definition);
    }
    Ok(LoweredJob {
        // The chain is non-empty: the guard above refuses an empty step list, so
        // `previous` is set by the end of the loop.
        root: previous.ok_or_else(|| TaskError::JobStepEmpty {
            job: job_key.to_owned(),
        })?,
        tasks: lowered,
        references: referenced,
    })
}

fn job_step_aliases(
    job_key: &str,
    job: &JobDefinition,
) -> Result<IndexMap<String, String>, TaskError> {
    let mut aliases = IndexMap::new();
    let mut references = HashSet::new();
    for (index, step) in job.steps.iter().enumerate() {
        if let Some(reference) = &step.task
            && !references.insert(reference)
        {
            return Err(TaskError::JobStepRepeated {
                job: job_key.to_owned(),
                task: reference.clone(),
            });
        }
        for alias in step.id.iter().chain(step.task.iter()) {
            let key = format!("{job_key}:{}", index + 1);
            if aliases
                .insert(alias.clone(), key.clone())
                .is_some_and(|previous| previous != key)
            {
                return Err(TaskError::InvalidAction {
                    task: job_key.to_owned(),
                    message: "job step wait identities must be unique".into(),
                });
            }
        }
    }
    Ok(aliases)
}

fn apply_step_defaults(
    definition: &mut TaskDefinition,
    job: &JobDefinition,
    step: &super::StepDefinition,
) {
    if let Some(action) = definition.action.as_mut() {
        if let Some(timeout) = &step.timeout {
            action.with.insert("timeout".into(), timeout.clone());
        }
        if !job.env.is_empty() || !step.env.is_empty() {
            action.env = merged_env(&job.env, &step.env);
        }
        if let Some(cwd) = step.cwd.clone().or_else(|| job.cwd.clone()) {
            action.cwd = Some(cwd);
        }
        if !job.dotenv.is_empty() {
            action.dotenv = job
                .dotenv
                .iter()
                .map(|path| TaskDotenvImport {
                    path: path.clone(),
                    required: true,
                    source: SourceSpan::new(String::new(), 0, 0),
                })
                .collect();
        }
    }
}

/// Lowers reachable job dependencies into owned step containers.
///
/// Job `needs` and `wait` names never resolve against task names. Cycles and
/// missing jobs fail before execution. Each job publishes handoffs only after
/// successful completion; the requested job is joined even if background.
///
/// # Errors
///
/// Returns a planning error for an invalid reachable job or step graph.
pub fn lower_jobs(
    jobs: &IndexMap<String, JobDefinition>,
    requested: &str,
    tasks: &IndexMap<String, TaskDefinition>,
    context: &str,
) -> Result<LoweredJob, TaskError> {
    let mut containers = IndexMap::new();
    let mut references = Vec::new();
    let declarations = jobs
        .iter()
        .map(|(name, job)| {
            (
                name.clone(),
                TaskDefinition {
                    needs: job.needs.clone(),
                    wait: job.wait.clone(),
                    ..TaskDefinition::default()
                },
            )
        })
        .collect();
    let reachable = plan_task(&declarations, requested, DEFAULT_CONTEXT)?;
    for planned in reachable.tasks {
        let name = &planned.name;
        let job = &jobs[name];
        let mut lowered = lower_job(name, job, tasks)?;
        references.extend(lowered.references.clone());
        let mut steps = tasks.clone();
        for (key, task) in lowered.tasks.drain(..) {
            if steps.insert(key, task).is_some() {
                return Err(TaskError::InvalidAction {
                    task: name.clone(),
                    message: "job step key collides with a task".into(),
                });
            }
        }
        // The job condition gates its first step and is inherited by the chain.
        // The container itself gates before launching any step.
        containers.insert(
            name.clone(),
            TaskDefinition {
                needs: job.needs.clone(),
                // Jobs are DAG nodes: independent needs launch concurrently,
                // and the job itself joins all of its required predecessors.
                parallel_needs: job.needs.clone(),
                background: Some(true),
                wait: job.wait.clone(),
                if_condition: job.if_condition.clone(),
                job: Some(Box::new(super::TaskSequence {
                    tasks: steps,
                    root: lowered.root,
                    context: context.to_owned(),
                    timeout: job.timeout.clone(),
                    kind: super::TaskSequenceKind::Job,
                })),
                ..TaskDefinition::default()
            },
        );
    }
    // Planning validates names and cycles without executing any job.
    plan_task(&containers, requested, DEFAULT_CONTEXT)?;
    Ok(LoweredJob {
        root: requested.to_owned(),
        tasks: containers,
        references,
    })
}

/// The job's `env`, then the step's, with the step winning.
fn merged_env(
    job: &indexmap::IndexMap<String, String>,
    step: &indexmap::IndexMap<String, String>,
) -> indexmap::IndexMap<String, String> {
    let mut merged = job.clone();
    for (key, value) in step {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

/// A job lowered into tasks: the map, and the key of the step that starts it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredJob {
    /// The key of the first step, which is what the plan is requested from.
    pub root: String,
    /// The lowered steps, chained in declaration order.
    pub tasks: IndexMap<String, TaskDefinition>,
    /// The tasks the steps refer to, in first-use order.
    ///
    /// Needed by the caller so it can resolve those tasks from the project's *resolved*
    /// map. A step that runs `build` must run the merged `build` -- a `build` that
    /// `extends` a template -- and the lowering only ever sees declarations.
    pub references: Vec<String>,
}

impl LoweredJob {
    /// The tasks this job's steps refer to.
    #[must_use]
    pub fn task_references(&self) -> &[String] {
        &self.references
    }
}
