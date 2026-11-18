//! Task help rendering. Produces display text only and never evaluates a
//! task or touches the filesystem.

use super::planning::task_identity;
use super::{
    HashSet, IndexMap, TaskAction, TaskDefinition, TaskDependencyEdge, TaskError, TaskHelp,
    TaskOutput, TaskParameter, TaskParameterDefault, TaskParameterType, Write,
    task_dependency_edges,
};

/// Renders metadata for the context-selected task without evaluating it.
///
/// # Errors
///
/// Returns an error when no matching task exists for the requested context.
pub fn task_help(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
) -> Result<TaskHelp, TaskError> {
    let name = resolve_task_name(tasks, requested_name, context)?;
    let task = &tasks[&name];
    let (id, display_name, slug) = task_identity(&name, task);
    let (dependencies, before_hooks, after_hooks) = task_dependency_edges(task);
    Ok(TaskHelp {
        background: task.background == Some(true),
        wait: task.wait.clone(),
        parallel_dependencies: task.parallel_needs.clone(),
        id,
        name: display_name,
        slug,
        description: task.description.clone(),
        help: task.help.clone(),
        action: task_help_action(task),
        parameters: task.parameters.clone(),
        dependencies: task.needs.clone(),
        dependency_edges: dependencies,
        before_hooks,
        after_hooks,
        outputs: task.outputs.clone(),
        package: task.package.clone(),
    })
}

fn task_help_action(task: &TaskDefinition) -> Option<TaskAction> {
    let mut action = task.action.clone()?;
    if task.package.is_some() {
        for value in action.env.values_mut() {
            *value = "[redacted]".into();
        }
    }
    Some(action)
}

impl TaskHelp {
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut output = render_task_help_header(self);
        render_task_help_inputs(&mut output, &self.parameters);
        render_task_help_dependencies(
            &mut output,
            &self.dependency_edges,
            &self.before_hooks,
            &self.after_hooks,
        );
        render_task_help_outputs(&mut output, &self.outputs);
        if self.background || !self.wait.is_empty() || !self.parallel_dependencies.is_empty() {
            writeln!(
                output,
                "Background: {}\nWait: {}\nParallel dependencies: {}",
                self.background,
                self.wait.join(", "),
                self.parallel_dependencies.join(", ")
            )
            .expect("writing to String cannot fail");
        }
        output
    }
}

fn render_task_help_header(help: &TaskHelp) -> String {
    let positional = help
        .parameters
        .iter()
        .filter(|parameter| parameter.position.is_some())
        .map(|parameter| {
            if parameter.required {
                format!(" <{}>", parameter.name)
            } else {
                format!(" [{}]", parameter.name)
            }
        })
        .collect::<String>();
    let options = help
        .parameters
        .iter()
        .any(|parameter| parameter.long.is_some() || parameter.short.is_some());
    let option_suffix = if options { " [options]" } else { "" };
    let mut output = format!(
        "Usage:\n  nenv {slug}{positional}{option_suffix} [-- <arguments>...]\n  nenv run {slug}{positional}{option_suffix} [-- <arguments>...]\n  nenv task run {slug}{positional}{option_suffix} [-- <arguments>...]\n\n",
        slug = help.slug,
    );
    if let Some(description) = &help.description {
        writeln!(output, "{description}").expect("writing to String cannot fail");
    }
    if let Some(text) = &help.help {
        writeln!(output, "\n{text}").expect("writing to String cannot fail");
    }
    writeln!(
        output,
        "\nTask: {}\nId: {}\nSlug: {}",
        help.name, help.id, help.slug
    )
    .expect("writing to String cannot fail");
    if let Some(package) = &help.package {
        writeln!(
            output,
            "\nPackage:\n  Path: {}\n  SHA-256: {}\n  Export: {}",
            package.path, package.sha256, package.export
        )
        .expect("writing to String cannot fail");
    }
    if let Some(action) = &help.action {
        write_option(&mut output, "Uses", action.uses.as_deref());
        write_option(&mut output, "Run", action.run.as_deref());
    } else {
        write_option(&mut output, "Uses", None);
        write_option(&mut output, "Run", None);
    }
    output
}

fn render_task_help_inputs(output: &mut String, parameters: &[TaskParameter]) {
    output.push_str("Inputs:\n");
    if parameters.is_empty() {
        output.push_str("  none\n");
    }
    for parameter in parameters {
        let required = if parameter.required {
            "required"
        } else {
            "optional"
        };
        let default = parameter
            .default
            .as_ref()
            .map_or_else(|| "none".to_owned(), format_default);
        let description = parameter.description.as_deref().unwrap_or("none");
        let binding = parameter_binding(parameter);
        writeln!(
            output,
            "  {binding:<24} {:?}, {required}, default: {default}: {description}",
            parameter.parameter_type
        )
        .expect("writing to String cannot fail");
    }
}

fn render_task_help_dependencies(
    output: &mut String,
    dependencies: &[TaskDependencyEdge],
    before_hooks: &[TaskDependencyEdge],
    after_hooks: &[TaskDependencyEdge],
) {
    output.push_str("Dependencies:\n");
    if dependencies.is_empty() {
        output.push_str("  none\n");
    }
    for dependency in dependencies {
        writeln!(output, "  {} ({})", dependency.name, dependency.origin)
            .expect("writing to String cannot fail");
    }
    for (label, hooks) in [("Before hooks", before_hooks), ("After hooks", after_hooks)] {
        if hooks.is_empty() {
            continue;
        }
        writeln!(output, "{label}:").expect("writing to String cannot fail");
        for hook in hooks {
            writeln!(output, "  {} ({})", hook.name, hook.origin)
                .expect("writing to String cannot fail");
        }
    }
}

fn render_task_help_outputs(output: &mut String, outputs: &IndexMap<String, TaskOutput>) {
    output.push_str("Outputs:\n");
    if outputs.is_empty() {
        output.push_str("  none\n");
    }
    for (name, declaration) in outputs {
        writeln!(
            output,
            "  {name} ({:?}): {}",
            declaration.visibility,
            declaration.description.as_deref().unwrap_or("none")
        )
        .expect("writing to String cannot fail");
    }
}

/// Resolves a `needs:` entry to the task key it names, in the running context.
///
/// Public for the same reason as [`resolve_hook_name`]: the runtime computes the
/// same closure when it resolves inheritance for one requested task, and two
/// implementations of this rule would disagree about which tasks a run includes.
///
/// # Errors
///
/// Returns [`TaskError`] when `requested` names no task this project declares in
/// `context` -- which is a *different* answer from "it names a task that is not
/// the one you meant", and the caller words it.
pub fn resolve_task_name(
    tasks: &IndexMap<String, TaskDefinition>,
    requested: &str,
    context: &str,
) -> Result<String, TaskError> {
    let selected = if requested.contains(':') {
        tasks.contains_key(requested).then(|| requested.to_owned())
    } else {
        let contextual = format!("{requested}:{context}");
        tasks
            .contains_key(&contextual)
            .then_some(contextual)
            .or_else(|| tasks.contains_key(requested).then(|| requested.to_owned()))
    };
    selected
        .or_else(|| {
            tasks.iter().find_map(|(key, task)| {
                (task.id.as_deref() == Some(requested) || task.slug.as_deref() == Some(requested))
                    .then(|| key.clone())
            })
        })
        .ok_or_else(|| TaskError::MissingTask {
            task: requested.to_owned(),
            context: context.to_owned(),
        })
}

fn write_option(output: &mut String, label: &str, value: Option<&str>) {
    writeln!(output, "{label}: {}", value.unwrap_or("none"))
        .expect("writing to String cannot fail");
}
fn format_default(default: &TaskParameterDefault) -> String {
    match default {
        TaskParameterDefault::String(value) => format!("{value:?}"),
        TaskParameterDefault::Boolean(value) => value.to_string(),
        TaskParameterDefault::Integer(value) => value.to_string(),
    }
}

fn parameter_binding(parameter: &TaskParameter) -> String {
    if let Some(position) = parameter.position {
        return if parameter.repeatable {
            format!("<{}...> (position {position})", parameter.name)
        } else {
            format!("<{}> (position {position})", parameter.name)
        };
    }
    let mut flags = Vec::new();
    if let Some(short) = parameter.short {
        flags.push(format!("-{short}"));
    }
    if let Some(long) = &parameter.long {
        flags.push(format!("--{long}"));
        if parameter.parameter_type != TaskParameterType::Boolean {
            flags.push(format!("<{}>", parameter.name));
        }
    }
    if parameter.repeatable {
        flags.push("repeatable".into());
    }
    if flags.is_empty() {
        format!("{} (static)", parameter.name)
    } else {
        flags.join(" ")
    }
}

pub(super) fn visit(
    name: &str,
    tasks: &IndexMap<String, TaskDefinition>,
    context: &str,
    planned: &mut HashSet<String>,
    visiting: &mut Vec<String>,
    result: &mut Vec<String>,
) -> Result<(), TaskError> {
    if planned.contains(name) {
        return Ok(());
    }
    if let Some(position) = visiting.iter().position(|item| item == name) {
        let mut trace = visiting[position..].to_vec();
        trace.push(name.to_owned());
        return Err(TaskError::DependencyCycle { trace });
    }
    visiting.push(name.to_owned());
    for dependency in tasks[name].needs.iter().chain(
        tasks[name]
            .wait
            .iter()
            .filter(|name| name.as_str() != "all"),
    ) {
        let selected = resolve_task_name(tasks, dependency, context).map_err(|_| {
            TaskError::MissingDependency {
                task: name.to_owned(),
                dependency: dependency.clone(),
            }
        })?;
        visit(&selected, tasks, context, planned, visiting, result)?;
    }
    for hook in &tasks[name].hooks.before {
        if let Some(selected) = resolve_hook_name(tasks, name, hook, context) {
            visit(&selected, tasks, context, planned, visiting, result)?;
        }
    }
    visiting.pop();
    planned.insert(name.to_owned());
    result.push(name.to_owned());
    for hook in &tasks[name].hooks.after {
        if let Some(selected) = resolve_hook_name(tasks, name, hook, context) {
            visit(&selected, tasks, context, planned, visiting, result)?;
        }
    }
    Ok(())
}

/// Resolves a hook suffix to the task key it names, in the running context.
///
/// Public because the runtime has to compute the same closure when it resolves
/// inheritance for a single requested task, and a second implementation of this
/// rule is how two callers end up disagreeing about which tasks a run includes.
#[must_use]
pub fn resolve_hook_name(
    tasks: &IndexMap<String, TaskDefinition>,
    task: &str,
    suffix: &str,
    context: &str,
) -> Option<String> {
    let suffix = suffix.trim();
    if suffix.is_empty() {
        return None;
    }
    let context_suffix = format!(":{context}");
    let owner = task.strip_suffix(&context_suffix).unwrap_or(task);
    let hook = format!("{owner}:{suffix}");
    let contextual = format!("{hook}:{context}");
    tasks
        .contains_key(&contextual)
        .then_some(contextual)
        .or_else(|| tasks.contains_key(&hook).then_some(hook))
}
