//! Process-boundary effects for tasks: fallback runner resolution, literal
//! argv execution without a shell, and render/copy destination handling.

use super::*;
use crate::vault::REFERENCE_PREFIX;

#[derive(Debug)]
pub(super) struct ResolvedFallbackRunner {
    pub(super) path: PathBuf,
    pub(super) directory: PathBuf,
    pub(super) global: bool,
}

pub(super) fn resolve_fallback_runner(
    runner: &str,
    project_root: &Path,
    directories: TaskRunnerDirectories<'_>,
) -> Result<ResolvedFallbackRunner, String> {
    let mut components = Path::new(runner).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err("fallback runner must be a bare file name".to_owned());
    }
    let root = project_root.canonicalize().map_err(|error| {
        format!(
            "failed to resolve project root {}: {error}",
            project_root.display()
        )
    })?;
    for (configured, global) in directories
        .local
        .iter()
        .map(|path| (path, false))
        .chain(directories.global.iter().map(|path| (path, true)))
    {
        let configured = Path::new(configured);
        if global && !configured.is_absolute() {
            return Err("global task directory must be absolute".to_owned());
        }
        let directory = if global {
            configured.to_owned()
        } else {
            root.join(configured)
        };
        let directory = directory.canonicalize().map_err(|error| {
            format!(
                "failed to resolve task directory {}: {error}",
                directory.display()
            )
        })?;
        if !directory.is_dir() {
            return Err(format!(
                "task directory is not a directory: {}",
                directory.display()
            ));
        }
        if !global && !directory.starts_with(&root) {
            return Err("local task directory escapes the project root".to_owned());
        }
        let candidate = directory.join(runner);
        let path = match candidate.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "failed to resolve fallback runner {}: {error}",
                    candidate.display()
                ));
            }
        };
        if !path.starts_with(&directory) || !path.is_file() {
            return Err(format!(
                "fallback runner escapes its task directory: {}",
                candidate.display()
            ));
        }
        return Ok(ResolvedFallbackRunner {
            path,
            directory,
            global,
        });
    }
    Err(format!("unsupported local task runner: {runner}"))
}

/// Renders a source-contained template using only declared `with` inputs.
pub(super) fn render_task_file(task: &TaskDefinition, project_root: &Path) -> Result<(), String> {
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "render action has no action".to_owned())?;
    let source = resolve_existing_declared_file(
        project_root,
        task,
        action
            .source
            .as_deref()
            .ok_or("render action has no source")?,
        action.source_document.as_ref(),
        action.source_from_package,
        "render source",
    )?;
    let destination = resolve_render_destination(
        project_root,
        task,
        action
            .destination
            .as_deref()
            .ok_or("render action has no destination")?,
        action.destination_document.as_ref(),
        action.destination_from_package,
    )?;
    let input = read_text_file(&source, &ResourceBudget::default())
        .map_err(|error| format!("failed to read render source {}: {error}", source.display()))?;
    let inputs = action
        .with
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    let values = BTreeMap::from([("inputs".into(), Value::Map(inputs))]);
    let rendered = Template::parse(&input)
        .and_then(|template| template.render_typed(&values))
        .map_err(|error| format!("failed to render {}: {error}", source.display()))?;
    write_rendered_text(&destination, &rendered)
}

/// Writes rendered text atomically beside the destination.
pub(super) fn write_rendered_text(destination: &Path, rendered: &str) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "render destination has no parent directory".to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "failed to create temporary render output in {}: {error}",
            parent.display()
        )
    })?;
    temporary
        .write_all(rendered.as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| {
            format!(
                "failed to write render destination {}: {error}",
                destination.display()
            )
        })?;
    temporary.persist(destination).map_err(|error| {
        format!(
            "failed to atomically replace render destination {}: {}",
            destination.display(),
            error.error
        )
    })?;
    Ok(())
}

#[cfg(test)]
pub(super) fn render_file(action: &TaskAction, project_root: &Path) -> Result<(), String> {
    render_task_file(
        &TaskDefinition {
            action: Some(action.clone()),
            ..TaskDefinition::default()
        },
        project_root,
    )
}

pub(super) fn resolve_existing_declared_file(
    project_root: &Path,
    task: &TaskDefinition,
    declared: &str,
    document: Option<&neoenv_core::SourceSpan>,
    from_package: bool,
    label: &str,
) -> Result<PathBuf, String> {
    let (root, candidate) =
        resolve_declared_path(project_root, task, declared, document, from_package, label)?;
    let resolved = candidate.canonicalize().map_err(|error| {
        format!(
            "failed to resolve {label} {}: {error}",
            Path::new(declared).display()
        )
    })?;
    if !resolved.starts_with(&root) {
        return if from_package {
            Err(format!("{label} escapes the package root"))
        } else {
            Err(format!("{label} escapes the project root"))
        };
    }
    if !resolved.is_file() {
        return Err(format!("{label} is not a file: {}", resolved.display()));
    }
    Ok(resolved)
}

pub(super) fn resolve_render_destination(
    project_root: &Path,
    task: &TaskDefinition,
    declared: &str,
    document: Option<&neoenv_core::SourceSpan>,
    from_package: bool,
) -> Result<PathBuf, String> {
    let (root, candidate) = resolve_declared_path(
        project_root,
        task,
        declared,
        document,
        from_package,
        "render destination",
    )?;
    let parent = candidate
        .parent()
        .ok_or_else(|| "render destination has no parent directory".to_owned())?
        .canonicalize()
        .map_err(|error| format!("failed to resolve render destination parent: {error}"))?;
    if !parent.starts_with(&root) {
        return if from_package {
            Err("render destination escapes the package root".to_owned())
        } else {
            Err("render destination escapes the project root".to_owned())
        };
    }
    let name = candidate
        .file_name()
        .ok_or_else(|| "render destination must name a file".to_owned())?;
    let destination = parent.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("render destination must not be a symlink".to_owned());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect render destination {}: {error}",
                destination.display()
            ));
        }
    }
    Ok(destination)
}

pub(super) fn resolve_declared_path(
    project_root: &Path,
    task: &TaskDefinition,
    declared: &str,
    document: Option<&neoenv_core::SourceSpan>,
    from_package: bool,
    label: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let project_root = project_root.canonicalize().map_err(|error| {
        format!(
            "failed to resolve project root {}: {error}",
            project_root.display()
        )
    })?;
    let declared_path = Path::new(declared);
    let root = if from_package {
        task.package
            .as_ref()
            .ok_or_else(|| format!("{label} has no package identity"))?
            .root
            .canonicalize()
            .map_err(|error| format!("failed to resolve package root: {error}"))?
    } else {
        if !is_project_relative(declared_path) {
            return Err(format!(
                "{label} must be relative to its declaring document without traversal"
            ));
        }
        project_root.clone()
    };
    let base = match document {
        Some(document) => Path::new(&document.path)
            .canonicalize()
            .map_err(|error| format!("failed to resolve {label} declaring document: {error}"))?
            .parent()
            .map(Path::to_owned)
            .ok_or_else(|| format!("{label} declaring document has no parent"))?,
        None if from_package => {
            return Err(format!("{label} has no package declaring document"));
        }
        None => project_root.clone(),
    };
    if !base.starts_with(&root) {
        return Err(format!("{label} declaring document escapes its root"));
    }
    let candidate = if declared_path.is_absolute() {
        if !from_package {
            return Err(format!(
                "{label} must be relative to its declaring document"
            ));
        }
        declared_path.to_owned()
    } else {
        if declared_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(format!("{label} must not contain parent traversal"));
        }
        base.join(declared_path)
    };
    Ok((root, candidate))
}

pub(super) fn is_project_relative(path: &Path) -> bool {
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

pub(super) fn render_portable(
    run: &str,
    environment: &BTreeMap<String, String>,
) -> Result<String, String> {
    let values = BTreeMap::from([
        (
            "env".into(),
            Value::Map(
                environment
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                    .collect(),
            ),
        ),
        ("os".into(), Value::String(std::env::consts::OS.into())),
        ("arch".into(), Value::String(std::env::consts::ARCH.into())),
    ]);
    let run = interpolate_portable_environment(run, environment);
    Template::parse(&run)
        .and_then(|template| template.render_typed(&values))
        .map_err(|error| format!("failed to render portable task: {error}"))
}

/// Expands only braced environment references before Go-template rendering.
///
/// `$NAME` remains literal for portable commands so a task cannot accidentally
/// acquire shell-like expansion semantics. `${NAME}` is `nenv`'s explicit
/// configuration interpolation form and must be resolved before the template
/// parser sees its braces.
pub(super) fn interpolate_portable_environment(
    run: &str,
    environment: &BTreeMap<String, String>,
) -> String {
    let mut output = String::new();
    let mut characters = run.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '$' || characters.peek() != Some(&'{') {
            output.push(character);
            continue;
        }
        characters.next();
        let mut name = String::new();
        let mut closed = false;
        for character in characters.by_ref() {
            if character == '}' {
                closed = true;
                break;
            }
            name.push(character);
        }
        if closed {
            output.push_str(environment.get(&name).map_or("", String::as_str));
        } else {
            output.push_str("${");
            output.push_str(&name);
        }
    }
    output
}

pub(super) fn format_process_error(error: ProcessError) -> String {
    match error {
        ProcessError::Cancelled => "task cancelled".into(),
        ProcessError::TimedOut => "task timed out".into(),
        ProcessError::Cleanup { primary, cleanup } => format!(
            "{}; cleanup failed: {cleanup}; descendants may remain",
            format_process_error(*primary)
        ),
        ProcessError::Start(error) => format!("failed to start task: {error}"),
        error => error.to_string(),
    }
}

pub(super) fn select_dependency(
    tasks: &IndexMap<String, TaskDefinition>,
    dependency: &str,
    context: &str,
) -> String {
    if let Ok(name) = neoenv_core::tasks::resolve_task_name(tasks, dependency, context) {
        return name;
    }
    if dependency.contains(':') {
        dependency.to_owned()
    } else {
        let contextual = format!("{dependency}:{context}");
        if tasks.contains_key(&contextual) {
            contextual
        } else {
            dependency.to_owned()
        }
    }
}

pub(super) fn resolve_cwd(project_root: &Path, task: &TaskDefinition) -> Result<PathBuf, String> {
    let Some(action) = task.action.as_ref() else {
        return Err("task has no action".to_owned());
    };
    let Some(declared) = action.cwd.as_deref() else {
        return project_root.canonicalize().map_err(|error| {
            format!(
                "failed to resolve project root {}: {error}",
                project_root.display()
            )
        });
    };
    let (root, candidate) = resolve_declared_path(
        project_root,
        task,
        declared,
        action.cwd_document.as_ref(),
        action.cwd_from_package,
        "task working directory",
    )?;
    let cwd = candidate.canonicalize().map_err(|error| {
        format!(
            "task working directory does not exist: {} ({error})",
            candidate.display()
        )
    })?;
    if !cwd.starts_with(&root) {
        return Err("task working directory escapes its declaring root".to_owned());
    }
    if !cwd.is_dir() {
        return Err(format!(
            "task working directory is not a directory: {}",
            cwd.display()
        ));
    }
    Ok(cwd)
}

pub(super) fn default_value(value: &TaskParameterDefault) -> String {
    match value {
        TaskParameterDefault::String(value) => value.clone(),
        TaskParameterDefault::Boolean(value) => value.to_string(),
        TaskParameterDefault::Integer(value) => value.to_string(),
    }
}

/// Builds the environment one task action sees.
///
/// Order, lowest to highest: the caller's environment, this task's declared
/// `dotenv` files, this task's declared `env`, then `overrides`.
///
/// `overrides` is the command-line `--env` map. It is applied here rather than
/// to the incoming `environment` so it is genuinely last: a task's own `env:`
/// cannot silently beat an explicit `-e` on the command line, and `-e PATH=...`
/// still wins over the tool directories `apply_path_operations` prepended.
pub(super) fn apply_task_environment(
    environment: &BTreeMap<String, String>,
    declared_environment: &IndexMap<String, String>,
    action: &TaskAction,
    overrides: Option<&BTreeMap<String, String>>,
    vaults: Option<&crate::vault::VaultSet>,
) -> Result<BTreeMap<String, String>, String> {
    let mut dotenv_environment = IndexMap::new();
    for (key, value) in environment {
        dotenv_environment.insert(
            key.clone(),
            EnvironmentEntry {
                key: key.clone(),
                value: value.clone(),
                source: neoenv_core::SourceSpan::new("process environment".into(), 1, 1),
                // Inherited from whatever produced the value; a synthesized
                // process-environment view never invents a secret.
                secret: false,
            },
        );
    }
    let mut task_dotenv_assignments = IndexMap::new();
    for dotenv in &action.dotenv {
        let assignments = apply_task_dotenv(&mut dotenv_environment, dotenv).map_err(|error| {
            let source = error
                .source
                .map(|source| format!("{}:{}: ", source.path, source.line))
                .unwrap_or_default();
            format!("{source}{}", error.message)
        })?;
        task_dotenv_assignments.extend(assignments);
    }
    // The interpolation scope is what this run owns: the project declarations,
    // the task's dotenv assignments (by key, not by a value comparison), its own
    // `env:`, and the CLI overrides. The inherited environment is in `resolved`
    // so the child gets it and an explicitly named inherited input can be
    // interpolated, but it is outside the scope: an inherited value is never
    // scanned or resolved merely because it exists.
    let mut scope: std::collections::BTreeSet<String> =
        declared_environment.keys().cloned().collect();
    scope.extend(task_dotenv_assignments.keys().cloned());
    let mut resolved = dotenv_environment
        .into_iter()
        .map(|(key, value)| (key, value.value))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in &action.env {
        let value = interpolate_environment(value, &resolved)?;
        scope.insert(key.clone());
        resolved.insert(key.clone(), value);
    }
    if let Some(overrides) = overrides {
        for (key, value) in overrides {
            scope.insert(key.clone());
            resolved.insert(key.clone(), value.clone());
        }
    }
    // Settle every override first, then resolve the values that remain
    // effective. A project value replaced by a task value or by `-e` is never
    // fetched. The context is the final effective environment, so a reference
    // may explicitly read an inherited input; the scope is what keeps an
    // unrelated inherited value from being scanned.
    if let Some(vaults) = vaults {
        let context = resolved.clone();
        vaults
            .resolve_environment(&mut resolved, &scope, &context)
            .map_err(|error| error.to_string())?;
    }
    Ok(resolved)
}

pub(super) fn interpolate_environment(
    value: &str,
    environment: &BTreeMap<String, String>,
) -> Result<String, String> {
    if value.contains("$(") || value.contains('`') {
        return Err("command substitution is not supported in task environments".to_owned());
    }
    // A task `env:` value that is a reference keeps its `${NAME}` until the
    // resolver runs against the final task/CLI scope.
    if value.trim_start().starts_with(REFERENCE_PREFIX) {
        return Ok(value.to_owned());
    }
    Ok(neotales_env::interpolate_with(value, |name| {
        environment.get(name).map(String::as_str)
    }))
}

pub(super) fn parse_timeout(value: &str) -> Result<Duration, String> {
    let (amount, unit) = ["ms", "s", "m", "h"]
        .into_iter()
        .find_map(|unit| value.strip_suffix(unit).map(|amount| (amount, unit)))
        .ok_or_else(|| format!("invalid positive timeout {value:?}"))?;
    let amount = amount
        .parse::<u64>()
        .map_err(|_| format!("invalid positive timeout {value:?}"))?;
    if amount == 0 {
        return Err(format!("invalid positive timeout {value:?}"));
    }
    let seconds = match unit {
        "ms" => return Ok(Duration::from_millis(amount)),
        "s" => Some(amount),
        "m" => amount.checked_mul(60),
        "h" => amount.checked_mul(3_600),
        _ => None,
    }
    .ok_or_else(|| format!("invalid positive timeout {value:?}"))?;
    Ok(Duration::from_secs(seconds))
}
