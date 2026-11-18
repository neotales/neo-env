//! Human and JSON rendering for inspection, package identity, errors, and
//! help, plus the shared project loader used by the command dispatchers.

use super::{
    Diagnostic, DiagnosticCategory, ExitCategory, OutputFormat, Path, cli, command_tree,
    load_project_or_workspace_alias_with_profile,
};

/// Loads a project in the strict v1 schema.
///
/// # Errors
///
/// Returns discovery, workspace-alias, or configuration diagnostics.
pub(super) fn load_project(
    path: Option<&str>,
) -> Result<neoenv_runtime::resolved_config::ResolvedProject, Diagnostic> {
    load_project_with_profile(path, neoenv_config::ConfigProfile::process_profile(), None)
}

/// Loads a project in an explicitly selected configuration profile.
///
/// # Errors
///
/// Returns discovery, workspace-alias, or configuration diagnostics.
/// `context` is the command line's `--context`, threaded in so a `dotenv:`
/// entry's `contexts:` filter is evaluated against the same context the task
/// resolver uses. It is not applied here: the filter runs while the sources are
/// merged, which is before this returns.
pub(super) fn load_project_with_profile(
    path: Option<&str>,
    profile: neoenv_config::ConfigProfile,
    context: Option<&str>,
) -> Result<neoenv_runtime::resolved_config::ResolvedProject, Diagnostic> {
    let start = std::env::current_dir().map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Runtime, "NEO502", error.to_string())
    })?;
    load_project_or_workspace_alias_with_profile(&start, path.map(Path::new), profile, context)
}

/// Refuses a config-directed effect unless the root and every contributing
/// document match an explicit trust record.
///
/// This is called after a project has been read, never before it: reading a
/// project is how `nenv trust status` tells a user what to approve. The gate
/// compares identities computed from the bytes that were parsed, so nothing is
/// re-read between the check and the effect.
pub(super) fn require_execution_trust(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
) -> Result<(), Diagnostic> {
    neoenv_runtime::trust::require_execution(
        &project.project.configuration_path,
        &project.contributors,
    )
    .map_err(|error| error.to_diagnostic())
}

/// Loads a project and refuses it unless its execution graph is trusted.
pub(super) fn load_trusted_project_with_profile(
    path: Option<&str>,
    profile: neoenv_config::ConfigProfile,
    context: Option<&str>,
) -> Result<neoenv_runtime::resolved_config::ResolvedProject, Diagnostic> {
    let project = load_project_with_profile(path, profile, context)?;
    require_execution_trust(&project)?;
    Ok(project)
}

pub(super) fn print_json(value: &(impl serde::Serialize + ?Sized)) -> Result<(), Diagnostic> {
    let output = serde_json::to_string_pretty(value).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO503", error.to_string())
    })?;
    println!("{output}");
    Ok(())
}

pub(crate) fn print_package_identity(package: Option<&neoenv_core::tasks::TaskPackageIdentity>) {
    if let Some(package) = package {
        println!(
            "  package: path={} sha256={} export={}",
            package.path, package.sha256, package.export
        );
    }
}

pub(super) fn print_inspection_text(document: &neoenv_core::InspectionDocument) {
    println!("format_version: {}", document.format_version);
    for source in &document.sources {
        println!("source: {} ({})", source.path, source.kind);
    }
    for entry in &document.environment {
        println!(
            "{}={} ({}, {}:{})",
            entry.key, entry.value, entry.source.path, entry.source.line, entry.source.column
        );
    }
    for operation in &document.path {
        println!(
            "PATH {}={} ({}, {}:{})",
            operation.operation,
            operation.value,
            operation.source.path,
            operation.source.line,
            operation.source.column
        );
    }
    for task in &document.tasks {
        println!(
            "task: {} (id: {}, name: {}, slug: {})",
            task.key, task.id, task.name, task.slug
        );
        print_package_identity(task.package.as_ref());
        for edge in task
            .dependencies
            .iter()
            .chain(&task.before_hooks)
            .chain(&task.after_hooks)
        {
            println!(
                "task dependency: {}.{} ({})",
                task.key, edge.name, edge.origin
            );
        }
        for output in &task.outputs {
            println!(
                "task output: {}.{} ({})",
                task.key, output.name, output.visibility
            );
        }
    }
}

pub(super) fn print_error(format: OutputFormat, error: &Diagnostic) {
    match format {
        OutputFormat::Text => {
            eprintln!("nenv: {error}");
            if error.exit_category() == ExitCategory::Usage {
                eprintln!("Run 'nenv --help' for usage.");
            }
        }
        OutputFormat::Json => {
            match serde_json::to_string(&neoenv_core::DiagnosticDocument::from_diagnostic(error)) {
                Ok(output) => eprintln!("{output}"),
                Err(_) => eprintln!("nenv: {error}"),
            }
        }
    }
}

pub(super) fn print_help(command: &'static command_tree::CommandSpec) {
    println!("{}", cli::help_text_for(command));
}
