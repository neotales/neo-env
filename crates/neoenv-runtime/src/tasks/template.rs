//! The `tmpl` runner: local file-to-file rendering with the project template
//! engine.
//!
//! The Go reference's `with` is a map of `any`: `with.files` is a list of
//! `source` or `source:destination` strings, `with.values` names a YAML mapping,
//! and `disable-env`/`disable-gotmpl` switch the two render stages off. Neoenv
//! keeps the same local-only behavior: no shell, no command substitution, no
//! URL source, and no network fetch. Paths are resolved through the same
//! contained-path rules as the `render` runner, including package-relative
//! sources.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use neoenv_core::tasks::{TaskAction, TaskDefinition};
use neotales_gotmpl::{MissingValueBehavior, RenderOptions, Template, Value};
use serde_yaml::Value as YamlValue;

use crate::budget::{ResourceBudget, read_text_file};

use super::TaskRunOptions;
use super::process::{resolve_declared_path, resolve_existing_declared_file};

/// Renders every `with.files` mapping for one `tmpl` task.
///
/// # Errors
///
/// Returns a message for a malformed mapping, a missing/escaping source or
/// values file, an escaping destination, invalid YAML, a template parse/render
/// failure, a resource limit, or cancellation.
pub(super) fn render_template_task(
    task: &TaskDefinition,
    project_root: &Path,
    environment: &BTreeMap<String, String>,
    options: &TaskRunOptions<'_>,
) -> Result<(), String> {
    let is_cancelled = || options.cancellation.is_cancelled();
    render_template_task_with(
        task,
        project_root,
        environment,
        &is_cancelled,
        &|_| false,
        &|_| false,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_template_task_with(
    task: &TaskDefinition,
    project_root: &Path,
    environment: &BTreeMap<String, String>,
    is_cancelled: &dyn Fn() -> bool,
    fail_at: &dyn Fn(usize) -> bool,
    restore_fails_at: &dyn Fn(usize) -> bool,
) -> Result<(), String> {
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "task has no action".to_owned())?;
    validate_runtime_action(action)?;
    let use_env = !bool_setting(action, "disable-env")?;
    let use_template = !bool_setting(action, "disable-gotmpl")?;
    let values = load_values(task, project_root, action)?;
    // Phase one: check cancellation, then resolve, read, render, and stage every
    // mapping. Nothing is published until every source and value is valid.
    let mut staged = Vec::with_capacity(action.files.len());
    for spec in &action.files {
        if is_cancelled() {
            return Err("task cancelled".to_owned());
        }
        staged.push(render_one(
            task,
            project_root,
            action,
            spec,
            environment,
            &values,
            use_env,
            use_template,
            is_cancelled,
        )?);
    }
    // Phase two: cancellation after staging and immediately before each commit.
    if is_cancelled() {
        return Err("task cancelled".to_owned());
    }
    commit_all(staged, is_cancelled, fail_at, restore_fails_at)
}

#[allow(clippy::too_many_arguments)]
fn render_one(
    task: &TaskDefinition,
    project_root: &Path,
    action: &TaskAction,
    spec: &str,
    environment: &BTreeMap<String, String>,
    values: &BTreeMap<String, Value>,
    use_env: bool,
    use_template: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<StagedOutput, String> {
    let (source, destination) = split_spec(spec);
    let source = source.trim();
    if source.is_empty() {
        return Err(format!(
            "tmpl file mapping {spec:?} has an empty source; write `source` or              `source:destination`"
        ));
    }
    let destination = match destination.trim() {
        "" => infer_destination(source),
        destination => destination.to_owned(),
    };
    let source_path = resolve_existing_declared_file(
        project_root,
        task,
        source,
        action.files_document.as_ref(),
        action.files_from_package,
        "tmpl source",
    )?;
    let destination_path = plan_destination(project_root, task, action, &destination)?;
    let mut content =
        read_text_file(&source_path, &ResourceBudget::default()).map_err(|error| {
            format!(
                "failed to read tmpl source {}: {error}",
                source_path.display()
            )
        })?;
    if use_env {
        // `$(...)` and backticks are deliberately not evaluated. They remain
        // literal text, which is the reference's behavior with command
        // substitution disabled and keeps this a renderer rather than a shell.
        content = interpolate_outside_actions(&content, environment);
    }
    if use_template {
        let template = Template::parse(&content).map_err(|error| {
            format!(
                "failed to parse tmpl source {}: {error}",
                source_path.display()
            )
        })?;
        let render_options = RenderOptions {
            missing_value: MissingValueBehavior::Null,
            is_cancelled: Some(is_cancelled),
            ..RenderOptions::default()
        };
        let data = template_data(environment, values);
        content = template
            .render_typed_with_options(&data, render_options)
            .map_err(|error| match error {
                neotales_gotmpl::Error::Cancelled => "task cancelled".to_owned(),
                error => format!(
                    "failed to render tmpl source {}: {error}",
                    source_path.display()
                ),
            })?;
    }
    destination_path.stage(&content)
}

fn validate_runtime_action(action: &TaskAction) -> Result<(), String> {
    if action.files.is_empty() {
        return Err("tmpl requires at least one `with.files` mapping".to_owned());
    }
    if action.run.is_some()
        || action.source.is_some()
        || action.destination.is_some()
        || !action.args.is_empty()
        || action.cwd.is_some()
        || !action.capabilities.is_empty()
    {
        return Err(
            "tmpl actions may only use with.files, with.values, with.disable-env, \
             with.disable-gotmpl, env, and dotenv"
                .to_owned(),
        );
    }
    for key in action.with.keys() {
        if !matches!(key.as_str(), "values" | "disable-env" | "disable-gotmpl") {
            return Err(format!(
                "unknown tmpl with key {key:?}; supported keys are files, values, \
                 disable-env, and disable-gotmpl"
            ));
        }
    }
    Ok(())
}

fn load_values(
    task: &TaskDefinition,
    project_root: &Path,
    action: &TaskAction,
) -> Result<BTreeMap<String, Value>, String> {
    let Some(declared) = action.with.get("values") else {
        return Ok(BTreeMap::new());
    };
    let path = resolve_existing_declared_file(
        project_root,
        task,
        declared.trim(),
        action.values_document.as_ref(),
        action.values_from_package,
        "tmpl values",
    )?;
    let input = read_text_file(&path, &ResourceBudget::default())
        .map_err(|error| format!("failed to read tmpl values {}: {error}", path.display()))?;
    if input.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let yaml: YamlValue = serde_yaml::from_str(&input)
        .map_err(|error| format!("failed to parse tmpl values {}: {error}", path.display()))?;
    let YamlValue::Mapping(mapping) = yaml else {
        return Err(format!(
            "tmpl values {} must be a YAML mapping at the top level",
            path.display()
        ));
    };
    let mut values = BTreeMap::new();
    for (key, value) in mapping {
        let YamlValue::String(key) = key else {
            return Err("tmpl values keys must be strings".to_owned());
        };
        values.insert(key, yaml_to_value(value)?);
    }
    Ok(values)
}

fn yaml_to_value(value: YamlValue) -> Result<Value, String> {
    match value {
        YamlValue::Null => Ok(Value::Null),
        YamlValue::Bool(value) => Ok(Value::Bool(value)),
        YamlValue::Number(value) => {
            if value.is_f64() {
                let float = value.as_f64().ok_or_else(|| {
                    "tmpl values contains a number that cannot be read".to_owned()
                })?;
                if !float.is_finite() {
                    return Err("tmpl values contains a non-finite number".to_owned());
                }
                Ok(Value::Float(float))
            } else if let Some(integer) = value.as_i64() {
                exact_integer(integer)
            } else if let Some(unsigned) = value.as_u64() {
                exact_unsigned(unsigned)
            } else {
                Err("tmpl values contains a number that cannot be represented".to_owned())
            }
        }
        YamlValue::String(value) => Ok(Value::String(value)),
        YamlValue::Sequence(sequence) => sequence
            .into_iter()
            .map(yaml_to_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        YamlValue::Mapping(mapping) => {
            let mut values = BTreeMap::new();
            for (key, value) in mapping {
                let YamlValue::String(key) = key else {
                    return Err("tmpl values keys must be strings".to_owned());
                };
                values.insert(key, yaml_to_value(value)?);
            }
            Ok(Value::Map(values))
        }
        YamlValue::Tagged(tagged) => yaml_to_value(tagged.value),
    }
}

/// Expands `${NAME}`/`$NAME` outside Go-template actions only.
///
/// The reference expands the whole source before parsing, which turns a template
/// variable such as `{{ $item }}` into an empty environment lookup. A template
/// action is code, not text, so this scanner copies `{{ ... }}` verbatim and
/// interpolates only the text between actions. Quoted strings inside an action
/// are skipped so a `}}` in a literal does not end the action early.
fn interpolate_outside_actions(content: &str, environment: &BTreeMap<String, String>) -> String {
    let mut output = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("{{") {
        let (before, action) = rest.split_at(start);
        output.push_str(&interpolate_env(before, environment));
        let body = &action[2..];
        if let Some(end) = find_action_end(body) {
            output.push_str(&action[..2 + end + 2]);
            rest = &action[2 + end + 2..];
        } else {
            output.push_str(action);
            return output;
        }
    }
    output.push_str(&interpolate_env(rest, environment));
    output
}

fn interpolate_env(text: &str, environment: &BTreeMap<String, String>) -> String {
    neotales_env::interpolate_with(text, |name| environment.get(name).map(String::as_str))
}

/// Returns the byte offset of the `}}` that closes an action body.
fn find_action_end(body: &str) -> Option<usize> {
    // A comment can contain `}}` as text; the reference's closing sequence is
    // `*/}}`, so find that before the quote scanner.
    if body.trim_start_matches('-').trim_start().starts_with("/*")
        && let Some(close) = body.find("*/}}")
    {
        return Some(close + 2);
    }
    let bytes = body.as_bytes();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' && delimiter != b'`' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' | b'\'' | b'`' => {
                quote = Some(byte);
                index += 1;
            }
            b'}' if bytes[index + 1] == b'}' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// The largest integer magnitude an IEEE-754 double represents exactly.
const MAX_EXACT_INTEGER: u64 = 1_u64 << 53;

fn exact_integer(integer: i64) -> Result<Value, String> {
    if integer.unsigned_abs() > MAX_EXACT_INTEGER {
        return Err(format!(
            "tmpl values integer {integer} cannot be represented exactly; \
             use a string or a value within ±{MAX_EXACT_INTEGER}"
        ));
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(Value::Number(integer as f64))
}

fn exact_unsigned(unsigned: u64) -> Result<Value, String> {
    if unsigned > MAX_EXACT_INTEGER {
        return Err(format!(
            "tmpl values integer {unsigned} cannot be represented exactly; \
             use a string or a value within ±{MAX_EXACT_INTEGER}"
        ));
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(Value::Number(unsigned as f64))
}

fn template_data(
    environment: &BTreeMap<String, String>,
    values: &BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    let env = Value::Map(
        environment
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    );
    let data = Value::Map(values.clone());
    let os = Value::String(go_os().to_owned());
    let arch = Value::String(go_arch().to_owned());
    BTreeMap::from([
        ("Env".to_owned(), env.clone()),
        ("env".to_owned(), env),
        ("Data".to_owned(), data.clone()),
        ("data".to_owned(), data),
        ("OS".to_owned(), os.clone()),
        ("os".to_owned(), os),
        ("Arch".to_owned(), arch.clone()),
        ("arch".to_owned(), arch),
    ])
}

/// The reference compares `.OS` to Go's `runtime.GOOS`, where macOS is
/// `darwin`; `std::env::consts::OS` says `macos`.
fn go_os() -> &'static str {
    if std::env::consts::OS == "macos" {
        "darwin"
    } else {
        std::env::consts::OS
    }
}

/// Go's `runtime.GOARCH` names, not Rust's architecture constants.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        other => other,
    }
}

fn bool_setting(action: &TaskAction, key: &str) -> Result<bool, String> {
    let Some(value) = action.with.get(key) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("tmpl with.{key} must be a boolean")),
    }
}

fn split_spec(spec: &str) -> (&str, &str) {
    let spec = spec.trim();
    let Some(index) = spec.find(':') else {
        return (spec, "");
    };
    if index == 0 {
        return (spec, "");
    }
    // Match the reference's Windows-volume guard: `C:\x` is a path, not a
    // source/destination split at the drive colon.
    #[cfg(windows)]
    if index == 1
        && spec.as_bytes()[0].is_ascii_alphabetic()
        && spec.as_bytes().get(1) == Some(&b':')
    {
        return (spec, "");
    }
    (&spec[..index], &spec[index + 1..])
}

fn infer_destination(source: &str) -> String {
    let source = source.trim();
    for extension in [".tmpl", ".tpl", ".gotmpl"] {
        if let Some(stem) = source.strip_suffix(extension) {
            return stem.to_owned();
        }
    }
    format!("{source}.out")
}

fn plan_destination(
    project_root: &Path,
    task: &TaskDefinition,
    action: &TaskAction,
    declared: &str,
) -> Result<PlannedDestination, String> {
    let (root, candidate) = resolve_declared_path(
        project_root,
        task,
        declared,
        action.files_document.as_ref(),
        action.files_from_package,
        "tmpl destination",
    )?;
    let name = candidate
        .file_name()
        .ok_or_else(|| "tmpl destination must name a file".to_owned())?;
    let parent = candidate
        .parent()
        .ok_or_else(|| "tmpl destination has no parent directory".to_owned())?;
    // Walk the existing prefix lexically. A symlinked destination directory is
    // refused even when its target is inside the root, so the later
    // `create_dir_all` can never follow a link out of the tree.
    let relative = parent
        .strip_prefix(&root)
        .map_err(|_| "tmpl destination escapes its declaring root".to_owned())?;
    let mut current = root.clone();
    let mut staging_parent = root.clone();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("tmpl destination must not traverse a symlink".to_owned());
            }
            Ok(metadata) if metadata.file_type().is_dir() => {
                staging_parent.clone_from(&current);
            }
            Ok(_) => return Err("tmpl destination has a non-directory ancestor".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!("failed to inspect tmpl destination: {error}"));
            }
        }
    }
    Ok(PlannedDestination {
        path: parent.join(name),
        root,
        staging_parent,
    })
}

struct PlannedDestination {
    path: PathBuf,
    root: PathBuf,
    staging_parent: PathBuf,
}

impl PlannedDestination {
    /// Stages rendered bytes in the nearest existing ancestor. Nothing is
    /// published here; the temp file is dropped on any later failure.
    fn stage(self, content: &str) -> Result<StagedOutput, String> {
        // Stage beside the nearest existing ancestor, never in a directory that
        // does not exist yet. A later source failure therefore leaves no output
        // and no destination directory behind.
        let mut temporary =
            tempfile::NamedTempFile::new_in(&self.staging_parent).map_err(|error| {
                format!(
                    "failed to create tmpl staging file in {}: {error}",
                    self.staging_parent.display()
                )
            })?;
        temporary
            .write_all(content.as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| {
                format!(
                    "failed to write tmpl staging file for {}: {error}",
                    self.path.display()
                )
            })?;
        Ok(StagedOutput {
            temporary,
            destination: self.path,
            root: self.root,
        })
    }
}

struct StagedOutput {
    temporary: tempfile::NamedTempFile,
    destination: PathBuf,
    root: PathBuf,
}

impl StagedOutput {
    fn prepare_destination(self) -> Result<(tempfile::NamedTempFile, PathBuf), String> {
        let parent = self
            .destination
            .parent()
            .ok_or_else(|| "tmpl destination has no parent directory".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create tmpl destination directory: {error}"))?;
        let parent = parent
            .canonicalize()
            .map_err(|error| format!("failed to resolve tmpl destination directory: {error}"))?;
        if !parent.starts_with(&self.root) {
            return Err("tmpl destination escapes its declaring root".to_owned());
        }
        let name = self
            .destination
            .file_name()
            .ok_or_else(|| "tmpl destination must name a file".to_owned())?;
        let destination = parent.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("tmpl destination must not be a symlink".to_owned());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("failed to inspect tmpl destination: {error}"));
            }
        }
        Ok((self.temporary, destination))
    }
}

static BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Publishes every staged output, rolling back the ones already published if a
/// later one cannot be committed.
fn commit_all(
    staged: Vec<StagedOutput>,
    is_cancelled: &dyn Fn() -> bool,
    fail_at: &dyn Fn(usize) -> bool,
    restore_fails_at: &dyn Fn(usize) -> bool,
) -> Result<(), String> {
    let mut published: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for (index, output) in staged.into_iter().enumerate() {
        if is_cancelled() {
            return Err(failure("task cancelled", &published, restore_fails_at));
        }
        if fail_at(index) {
            return Err(failure(
                format!("tmpl commit failed at mapping {index}"),
                &published,
                restore_fails_at,
            ));
        }
        let (temporary, destination) = match output.prepare_destination() {
            Ok(prepared) => prepared,
            Err(error) => return Err(failure(error, &published, restore_fails_at)),
        };
        // Preparation creates the destination directory; a cancel between here
        // and the backup/persist must not publish this mapping or leave earlier
        // ones behind.
        if is_cancelled() {
            return Err(failure("task cancelled", &published, restore_fails_at));
        }
        let backup = match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(failure(
                    "tmpl destination must not be a symlink".to_owned(),
                    &published,
                    restore_fails_at,
                ));
            }
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(failure(
                    "tmpl destination is not a regular file".to_owned(),
                    &published,
                    restore_fails_at,
                ));
            }
            Ok(_) => match backup_path(&destination) {
                Ok(path) => Some(path),
                Err(error) => {
                    return Err(failure(error, &published, restore_fails_at));
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(failure(
                    format!("failed to inspect tmpl destination: {error}"),
                    &published,
                    restore_fails_at,
                ));
            }
        };
        if let Some(backup) = &backup
            && let Err(error) = fs::rename(&destination, backup)
        {
            return Err(failure(
                format!("failed to preserve tmpl destination: {error}"),
                &published,
                restore_fails_at,
            ));
        }
        // Include this destination before the persist, so a cancel or failure
        // restores the backup that was just moved aside.
        published.push((destination.clone(), backup));
        if is_cancelled() {
            return Err(failure("task cancelled", &published, restore_fails_at));
        }
        if let Err(error) = temporary.persist(&destination) {
            return Err(failure(
                format!(
                    "failed to publish tmpl destination {}: {}",
                    destination.display(),
                    error.error
                ),
                &published,
                restore_fails_at,
            ));
        }
    }
    let mut cleanup_failures = Vec::new();
    for (_, backup) in published {
        if let Some(backup) = backup
            && let Err(error) = fs::remove_file(&backup)
        {
            cleanup_failures.push(format!("remove {}: {error}", backup.display()));
        }
    }
    if cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "tmpl outputs committed but backup cleanup failed: {}",
            cleanup_failures.join("; ")
        ))
    }
}

fn failure(
    original: impl Into<String>,
    published: &[(PathBuf, Option<PathBuf>)],
    restore_fails_at: &dyn Fn(usize) -> bool,
) -> String {
    let original = original.into();
    match rollback(published, restore_fails_at) {
        Ok(()) => original,
        Err(rollback) => format!("{original}; rollback failed: {rollback}"),
    }
}

fn rollback(
    published: &[(PathBuf, Option<PathBuf>)],
    restore_fails_at: &dyn Fn(usize) -> bool,
) -> Result<(), String> {
    let mut failures = Vec::new();
    for (index, (destination, backup)) in published.iter().enumerate().rev() {
        if let Err(error) = fs::remove_file(destination)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            failures.push(format!("remove {}: {error}", destination.display()));
        }
        if let Some(backup) = backup {
            if restore_fails_at(index) {
                failures.push(format!(
                    "restore {} from backup {} failed (injected)",
                    destination.display(),
                    backup.display()
                ));
                continue;
            }
            if let Err(error) = fs::rename(backup, destination) {
                failures.push(format!(
                    "restore {} from backup {}: {error}",
                    destination.display(),
                    backup.display()
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn backup_path(destination: &Path) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "tmpl destination has no parent directory".to_owned())?;
    for _ in 0..1_000 {
        let sequence = BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "{}-{}-{sequence}",
            neoenv_core::names::TMPL_BACKUP_PREFIX,
            std::process::id()
        ));
        if fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    Err("failed to allocate a tmpl backup path".to_owned())
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap, fs};

    use indexmap::IndexMap;
    use neoenv_core::tasks::{TaskAction, TaskDefinition};
    use tempfile::TempDir;

    use super::render_template_task_with;

    fn task(files: &[&str], disable_gotmpl: bool) -> TaskDefinition {
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("tmpl".into()),
                files: files.iter().map(|file| (*file).to_owned()).collect(),
                with: if disable_gotmpl {
                    IndexMap::from([("disable-gotmpl".to_owned(), "true".to_owned())])
                } else {
                    IndexMap::new()
                },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        }
    }

    #[test]
    fn cancellation_before_a_later_mapping_does_not_read_it() {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("one.tmpl"), "one\n").unwrap();
        fs::write(project.path().join("two.tmpl"), "two\n").unwrap();
        let task = task(&["one.tmpl:one.out", "two.tmpl:two.out"], true);
        let calls = Cell::new(0);
        let cancelled = || {
            let next = calls.get() + 1;
            calls.set(next);
            next > 1
        };
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &cancelled,
            &|_| false,
            &|_| false,
        )
        .unwrap_err();
        assert_eq!(error, "task cancelled");
        assert!(!project.path().join("one.out").exists());
        assert!(!project.path().join("two.out").exists());
    }

    #[test]
    fn cancellation_after_preparation_writes_nothing() {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("one.tmpl"), "one\n").unwrap();
        let task = task(&["one.tmpl:one.out"], true);
        let calls = Cell::new(0);
        let cancelled = || {
            let next = calls.get() + 1;
            calls.set(next);
            // one before the mapping, one after staging, one commit-loop check,
            // then this check immediately after destination preparation
            next >= 4
        };
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &cancelled,
            &|_| false,
            &|_| false,
        )
        .unwrap_err();
        assert_eq!(error, "task cancelled");
        assert!(!project.path().join("one.out").exists());
    }

    #[test]
    fn cancellation_before_a_later_commit_rolls_back_the_first() {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("one.tmpl"), "one\n").unwrap();
        fs::write(project.path().join("two.tmpl"), "two\n").unwrap();
        let task = task(&["one.tmpl:one.out", "two.tmpl:two.out"], true);
        let calls = Cell::new(0);
        let cancelled = || {
            let next = calls.get() + 1;
            calls.set(next);
            // two pre-mapping checks, one post-staging check, then for each
            // commit: loop check, after preparation, after backup. Cancel at the
            // final mapping's after-backup check.
            next >= 9
        };
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &cancelled,
            &|_| false,
            &|_| false,
        )
        .unwrap_err();
        assert_eq!(error, "task cancelled");
        assert!(
            !project.path().join("one.out").exists(),
            "the first commit must be rolled back"
        );
        assert!(!project.path().join("two.out").exists());
    }

    #[test]
    fn cancellation_after_moving_a_backup_restores_it() {
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("one.tmpl"),
            "one
",
        )
        .unwrap();
        fs::write(
            project.path().join("one.out"),
            "old one
",
        )
        .unwrap();
        let task = task(&["one.tmpl:one.out"], true);
        let calls = Cell::new(0);
        let cancelled = || {
            let next = calls.get() + 1;
            calls.set(next);
            // four checks through preparation, then the after-backup check
            next >= 5
        };
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &cancelled,
            &|_| false,
            &|_| false,
        )
        .unwrap_err();
        assert_eq!(error, "task cancelled");
        assert_eq!(
            fs::read_to_string(project.path().join("one.out")).unwrap(),
            "old one
",
            "the moved backup must be restored on cancellation"
        );
    }

    #[test]
    fn a_directory_destination_is_rejected_and_left_untouched() {
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("one.tmpl"),
            "one
",
        )
        .unwrap();
        fs::write(
            project.path().join("two.tmpl"),
            "two
",
        )
        .unwrap();
        fs::write(
            project.path().join("one.out"),
            "old one
",
        )
        .unwrap();
        fs::create_dir(project.path().join("two.out")).unwrap();
        fs::write(
            project.path().join("two.out/keep"),
            "keep
",
        )
        .unwrap();
        let task = task(&["one.tmpl:one.out", "two.tmpl:two.out"], true);
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &|| false,
            &|_| false,
            &|_| false,
        )
        .unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        assert_eq!(
            fs::read_to_string(project.path().join("one.out")).unwrap(),
            "old one
"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("two.out/keep")).unwrap(),
            "keep
"
        );
    }

    #[test]
    fn a_failed_restore_is_reported_separately_from_the_original_error() {
        let project = TempDir::new().unwrap();
        fs::write(
            project.path().join("one.tmpl"),
            "one
",
        )
        .unwrap();
        fs::write(
            project.path().join("two.tmpl"),
            "two
",
        )
        .unwrap();
        fs::write(
            project.path().join("one.out"),
            "old one
",
        )
        .unwrap();
        let task = task(&["one.tmpl:one.out", "two.tmpl:two.out"], true);
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &|| false,
            &|index| index == 1,
            &|index| index == 0,
        )
        .unwrap_err();
        assert!(error.contains("mapping 1"), "{error}");
        assert!(error.contains("rollback failed"), "{error}");
        assert!(error.contains("restore"), "{error}");
        let backup = fs::read_dir(project.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(neoenv_core::names::TMPL_BACKUP_PREFIX))
            })
            .expect("the failed restore must leave the backup in place");
        assert!(
            error.contains(&backup.display().to_string()),
            "the error must name the surviving backup {}: {error}",
            backup.display()
        );
        assert!(!project.path().join("one.out").exists());
    }

    #[test]
    fn a_mid_list_commit_failure_rolls_back_earlier_outputs() {
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("one.tmpl"), "one\n").unwrap();
        fs::write(project.path().join("two.tmpl"), "two\n").unwrap();
        fs::write(project.path().join("one.out"), "old one\n").unwrap();
        let task = task(&["one.tmpl:one.out", "two.tmpl:two.out"], true);
        let error = render_template_task_with(
            &task,
            project.path(),
            &BTreeMap::new(),
            &|| false,
            &|index| index == 1,
            &|_| false,
        )
        .unwrap_err();
        assert!(error.contains("mapping 1"), "{error}");
        assert_eq!(
            fs::read_to_string(project.path().join("one.out")).unwrap(),
            "old one\n",
            "the first output must be restored from its backup"
        );
        assert!(!project.path().join("two.out").exists());
    }
}
