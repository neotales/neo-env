//! Normalization from loosely typed structured documents into the strict
//! task model, with every rejection reported against a source span.

use super::spans::StructuredSpans;
use super::structured::{
    DotenvList, StructuredParameter, StructuredPredicate, StructuredTask, StructuredWithValue,
};
use super::{
    Diagnostic, DiagnosticCategory, IndexMap, SourceSpan, TaskAction, TaskDefinition,
    TaskDotenvImport, TaskHooks, TaskParameter, reject_command_substitution,
};

#[allow(clippy::too_many_lines)] // Keeps a structured task declaration normalized in one place.
pub(super) fn normalize_task(
    task: StructuredTask,
    name: &str,
    source_path: &str,
    spans: &mut StructuredSpans,
) -> Result<TaskDefinition, Diagnostic> {
    match task {
        StructuredTask::Scalar(run) => Ok(TaskDefinition {
            action: Some(TaskAction {
                uses: Some("exec".to_owned()),
                run: Some(run),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        }),
        StructuredTask::Map(task) => {
            reject_runner_selectors(
                task.embed.as_ref(),
                task.image.as_ref(),
                &task.hosts,
                name,
                source_path,
            )?;
            let task = *task;
            let (with, files) = split_task_with(task.with, name, source_path)?;
            let has_dotenv = !matches!(&task.dotenv, DotenvList::Empty);
            let action = if task.uses.is_some()
                || task.run.is_some()
                || task.source.is_some()
                || task.destination.is_some()
                || !files.is_empty()
                || has_dotenv
            {
                let dotenv = task
                    .dotenv
                    .into_vec()
                    .into_iter()
                    .map(|dotenv| {
                        // The filter is dropped, and correctly so: a task's
                        // `dotenv:` is a plain list of paths in the reference
                        // (`task.go`: `DotEnv []string`), so a task-level entry
                        // has nothing to scope. The project-level list does.
                        let (path, required, _filter) = dotenv.into_parts();
                        let source = spans.next_task_dotenv(name, source_path);
                        reject_command_substitution(&path, source_path, source.line)?;
                        Ok(TaskDotenvImport {
                            path,
                            required,
                            source,
                        })
                    })
                    .collect::<Result<Vec<_>, Diagnostic>>()?;
                Some(TaskAction {
                    uses: Some(task.uses.unwrap_or_else(|| "exec".to_owned())),
                    run: task.run,
                    source: task.source,
                    destination: task.destination,
                    args: task.args.into_vec(),
                    files,
                    cwd: task.cwd,
                    env: task.env,
                    dotenv,
                    with: apply_task_timeout(with, task.timeout, name, source_path)?,
                    capabilities: task.capabilities.into_vec(),
                    source_document: Some(SourceSpan::new(source_path.to_owned(), 1, 1)),
                    destination_document: Some(SourceSpan::new(source_path.to_owned(), 1, 1)),
                    cwd_document: Some(SourceSpan::new(source_path.to_owned(), 1, 1)),
                    files_document: Some(SourceSpan::new(source_path.to_owned(), 1, 1)),
                    values_document: Some(SourceSpan::new(source_path.to_owned(), 1, 1)),
                    source_from_package: false,
                    destination_from_package: false,
                    cwd_from_package: false,
                    files_from_package: false,
                    values_from_package: false,
                })
            } else {
                None
            };
            let parameters = task
                .inputs
                .into_iter()
                .map(|(name, parameter)| match parameter {
                    StructuredParameter::Type(parameter_type) => TaskParameter {
                        name,
                        parameter_type,
                        required: false,
                        default: None,
                        description: None,
                        position: None,
                        long: None,
                        short: None,
                        repeatable: false,
                    },
                    StructuredParameter::Map(parameter) => TaskParameter {
                        name,
                        parameter_type: parameter.parameter_type,
                        required: parameter.required,
                        default: parameter.default,
                        description: parameter.description,
                        position: parameter.position,
                        long: parameter.long,
                        short: parameter.short,
                        repeatable: parameter.repeatable,
                    },
                })
                .collect();
            let parallel_needs = task.needs.parallel_ids();
            Ok(TaskDefinition {
                background: task.background,
                wait: super::structured::normalize_wait(task.wait, task.wait_all)?,
                parallel_needs,
                id: task.id,
                name: task.name,
                slug: task.slug,
                description: task.description,
                help: task.help,
                action,
                needs: task.needs.into_vec().map_err(|error| {
                    Diagnostic::new(
                        DiagnosticCategory::Validation,
                        error.code.clone(),
                        error.message.clone(),
                    )
                    .at(SourceSpan::new(source_path.to_owned(), 1, 1))
                })?,
                hooks: hooks_of(task.hooks, name, source_path)?,
                extends: task.extends,
                template: task.template,
                parameters,
                outputs: task
                    .outputs
                    .into_iter()
                    .map(|(name, output)| (name, output.into_output()))
                    .collect(),
                if_condition: task.if_condition.map(StructuredPredicate::into_string),
                force: task.force.map(StructuredPredicate::into_string),
                hidden: false,
                package: None,
                dependency_origins: neoenv_core::tasks::TaskDependencyOrigins::default(),
                capability_requests: Vec::new(),
                job: None,
                execution_grant_required: false,
            })
        }
    }
}

/// Refuses a task field that selects a Go runner this model does not have.
///
/// `embed`, `image`, and `hosts` choose a container or a remote host. There is
/// no Rust equivalent, and silently ignoring one would run the task *locally*
/// when the file said otherwise -- the worst possible outcome, because the run
/// would appear to succeed. Naming it is the only safe answer.
///
/// # Errors
///
/// Returns NEO139 naming the field.
fn reject_runner_selectors(
    embed: Option<&String>,
    image: Option<&String>,
    hosts: &super::structured::StringList,
    name: &str,
    source_path: &str,
) -> Result<(), Diagnostic> {
    for (present, key) in [
        (embed.is_some(), "embed"),
        (image.is_some(), "image"),
        (
            !matches!(hosts, super::structured::StringList::Empty),
            "hosts",
        ),
    ] {
        if present {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO139",
                format!(
                    "task {name} sets `{key}`, which selects a Go runner this model does \
                     not have; run it with the Go nenv, or move the command to `uses:`"
                ),
            )
            .at(SourceSpan::new(source_path.to_owned(), 1, 1)));
        }
    }
    Ok(())
}

/// Resolves a task's `hooks`, reporting a bad scalar against the declaration.
///
/// # Errors
///
/// Returns a diagnostic when a `hooks:` scalar is neither a recognized boolean
/// spelling nor `1`.
fn hooks_of(
    hooks: super::structured::HooksSection,
    name: &str,
    source_path: &str,
) -> Result<TaskHooks, Diagnostic> {
    let hooks = hooks.into_parts().map_err(|message| {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO137",
            format!("task {name}: {message}"),
        )
        .at(SourceSpan::new(source_path.to_owned(), 1, 1))
    })?;
    Ok(TaskHooks {
        before: hooks.before.into_vec(),
        after: hooks.after.into_vec(),
    })
}

/// Folds the Go top-level `timeout` into `with`, which is where the run-time
/// reads it.
///
/// A document that sets both spellings is a diagnostic rather than a silent
/// winner: `with.timeout` is the native spelling and `timeout:` is the Go one,
/// and a file carrying both has said two different things about how long a task
/// may run. Reporting the conflict is the only answer that does not pick one on
/// the user's behalf and then enforce it.
///
/// # Errors
///
/// Returns NEO136 when both spellings are present and disagree.
/// Splits the loosely typed `with:` map into scalar strings and the `tmpl`
/// runner's file list.
///
/// The reference's `with` is a map of `any`, so `disable-gotmpl: true` and
/// `files: [a:b]` are ordinary spellings. Neoenv's runtime settings are strings,
/// so scalars are normalized here and the one list-valued key is extracted. A
/// list on any other key is refused with the key named, rather than becoming an
/// unknown YAML type or an inert value.
fn split_task_with(
    with: IndexMap<String, StructuredWithValue>,
    name: &str,
    source_path: &str,
) -> Result<(IndexMap<String, String>, Vec<String>), Diagnostic> {
    let mut scalars = IndexMap::new();
    let mut files = Vec::new();
    for (key, value) in with {
        match (key.as_str(), value) {
            ("files", StructuredWithValue::List(values)) => {
                if values.is_empty() {
                    return Err(tmpl_diagnostic(
                        name,
                        source_path,
                        "task `with.files` must be a non-empty list of \
                         `source` or `source:destination` strings",
                    ));
                }
                files = values;
            }
            ("files", _) => {
                return Err(tmpl_diagnostic(
                    name,
                    source_path,
                    "task `with.files` must be a list of `source` or \
                     `source:destination` strings, not a scalar",
                ));
            }
            (_, StructuredWithValue::List(_)) => {
                return Err(tmpl_diagnostic(
                    name,
                    source_path,
                    format!("task `with.{key}` must be a scalar; only `with.files` is a list"),
                ));
            }
            (_, StructuredWithValue::String(value)) => {
                scalars.insert(key, value);
            }
            (_, StructuredWithValue::Bool(value)) => {
                scalars.insert(key, value.to_string());
            }
            (_, StructuredWithValue::Integer(value)) => {
                scalars.insert(key, value.to_string());
            }
            (_, StructuredWithValue::Float(value)) => {
                scalars.insert(key, value.to_string());
            }
        }
    }
    Ok((scalars, files))
}

fn tmpl_diagnostic(name: &str, source_path: &str, message: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Validation,
        "NEO151",
        format!("task {name}: {message}"),
    )
    .at(SourceSpan::new(source_path.to_owned(), 1, 1))
}

fn apply_task_timeout(
    mut with: IndexMap<String, String>,
    timeout: Option<String>,
    name: &str,
    source_path: &str,
) -> Result<IndexMap<String, String>, Diagnostic> {
    let Some(timeout) = timeout else {
        return Ok(with);
    };
    if let Some(existing) = with.get("timeout") {
        if *existing == timeout {
            return Ok(with);
        }
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO136",
            format!(
                "task {name} sets both `timeout: {timeout}` and `with.timeout: {existing}`; \
                 remove one so the limit is unambiguous"
            ),
        )
        // The declaring document, not a span cursor: the per-task dotenv queue
        // is already drained at this point, so borrowing one put the diagnostic
        // at line 1 of the file and never at the conflict.
        .at(SourceSpan::new(source_path.to_owned(), 1, 1)));
    }
    with.insert("timeout".to_owned(), timeout);
    Ok(with)
}
