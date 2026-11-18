//! Transactional project/global tool lifecycle operations.
//!
//! The command layer deliberately keeps lifecycle planning in one place.  A
//! plan is a local, serializable value; only the publish step is allowed to
//! change a lock/config file or remove a previously published version.

mod global;
mod project;
mod version;

use global::{pin_global, purge_global, remove_global, unpin_global, update_global};
use project::{pin_project, purge_project, remove_project, unpin_project, update_project};

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use neoenv_core::{
    Diagnostic, DiagnosticCategory,
    tools::{LockedTool, Platform, ToolDeclaration, ToolLockfile, ToolProvider},
};
use neoenv_installer::tools::{
    cleanup_stale_temporaries_in, install_key, install_locked_tools_in, installed_versions_in,
    remove_installed_version_in,
};
use neoenv_runtime::{
    budget::{ResourceBudget, read_file_bytes, read_text_file},
    resolved_config::ResolvedProject,
    state_file,
};

use super::{
    GlobalScope, GlobalToolInstallation, GlobalToolRequest, OutputFormat, ToolScope,
    cleanup_new_global_installations, global_install_cancellation, global_install_cancelled,
    global_tool_and_version, global_tool_config_path, global_tool_data_root,
    install_global_tools_transaction, load_project, lockfile_path, parse_global_tool_request,
    print_json, read_global_tool_document, read_lockfile, record_global_tools, remove_global_path,
    split_global_key_version, state_file_diagnostic, write_locked_state,
};

const REPORT_SCHEMA_VERSION: u32 = 1;
const PROJECT_UPDATE_SOURCE_PREFIX: &str = "project-update:";
// The marker name is written by `global_install` when it publishes a global
// install and read back here to decide ownership. It must stay one constant:
// two spellings would silently stop recognizing on-disk ownership.
pub(super) const GLOBAL_OWNERSHIP_MARKER: &str = neoenv_core::names::GLOBAL_OWNERSHIP_MARKER;

type GlobalPurgeCandidate = (String, String, PathBuf, Option<PathBuf>);

#[derive(Clone, Debug, serde::Serialize)]
struct LifecycleChange {
    tool: String,
    action: String,
    from_version: Option<String>,
    to_version: Option<String>,
    path: Option<String>,
    reason: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct LifecycleReport {
    schema_version: u32,
    scope: String,
    command: String,
    dry_run: bool,
    changes: Vec<LifecycleChange>,
}

impl LifecycleReport {
    fn new(scope: ToolScope, command: &str, dry_run: bool) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            scope: scope_name(scope).into(),
            command: command.into(),
            dry_run,
            changes: Vec::new(),
        }
    }

    fn change(
        &mut self,
        tool: impl Into<String>,
        action: &str,
        from_version: Option<String>,
        to_version: Option<String>,
        path: Option<PathBuf>,
        reason: Option<&str>,
    ) {
        self.changes.push(LifecycleChange {
            tool: tool.into(),
            action: action.into(),
            from_version,
            to_version,
            path: path.map(|path| path.display().to_string()),
            reason: reason.map(str::to_owned),
        });
    }
}

fn print_report(report: &LifecycleReport, format: OutputFormat) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Json => print_json(report),
        OutputFormat::Text => {
            println!("scope: {}", report.scope);
            println!("command: {}", report.command);
            println!("dry_run: {}", report.dry_run);
            for change in &report.changes {
                println!(
                    "change: tool={} action={} from={} to={} path={} reason={}",
                    change.tool,
                    change.action,
                    optional_text(change.from_version.as_deref()),
                    optional_text(change.to_version.as_deref()),
                    optional_text(change.path.as_deref()),
                    optional_text(change.reason.as_deref()),
                );
            }
            Ok(())
        }
    }
}

fn optional_text(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn scope_name(scope: ToolScope) -> &'static str {
    match scope {
        ToolScope::Project => "project",
        ToolScope::User => "user",
        ToolScope::Global => "global",
    }
}

fn usage(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Usage, "NEO001", message)
}

fn validation(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO103", message)
}

fn not_found(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::NotFound, "NEO521", message)
}

fn runtime(path: &Path, error: &std::io::Error) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO522",
        format!("failed to access {}: {error}", path.display()),
    )
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
}

fn project_receipt_matches(root: &Path, digest: &str) -> bool {
    let path = root.join(neoenv_core::names::INSTALL_RECEIPT);
    regular_file(&path)
        && read_file_bytes(&path, &ResourceBudget::default()).is_ok_and(|contents| {
            String::from_utf8(contents).is_ok_and(|value| value.trim() == digest)
        })
}

fn artifact_matches_digest(path: &Path, digest: &str) -> bool {
    let Ok(bytes) = read_file_bytes(path, &ResourceBudget::default()) else {
        return false;
    };
    format!("{:x}", Sha256::digest(&bytes)) == digest
}

fn project_artifact_owned(path: &Path, digest: &str) -> bool {
    regular_file(path) && artifact_matches_digest(path, digest)
}

fn owned_read_dir(path: &Path) -> Result<Option<fs::ReadDir>, Diagnostic> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            fs::read_dir(path)
                .map(Some)
                .map_err(|error| runtime(path, &error))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(runtime(path, &error)),
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}

fn validate_version(value: &str) -> Result<(), Diagnostic> {
    if safe_component(value) {
        Ok(())
    } else {
        Err(validation(format!("invalid tool version `{value}`")))
    }
}

fn split_requested_tool(value: &str) -> Result<(String, Option<String>), Diagnostic> {
    let (tool, version) = split_global_key_version(value)?;
    if tool.is_empty() {
        return Err(validation("tool name cannot be empty"));
    }
    if let Some(version) = version {
        validate_version(version)?;
    }
    Ok((tool.to_owned(), version.map(str::to_owned)))
}

/// Resolves the lifecycle root from a project the caller has already checked.
///
/// A lifecycle command that executes must not load configuration a second
/// time: the trust decision was made over the returned snapshot's bytes, so
/// that snapshot is what the operation consumes.
fn project_for_lifecycle(
    project: Option<&ResolvedProject>,
) -> Result<(PathBuf, PathBuf, ToolLockfile), Diagnostic> {
    let root = match project {
        Some(project) => project.project.project_root.clone(),
        None => load_project(None)?.project.project_root,
    };
    let neoenv = root.join(neoenv_core::names::PROJECT_DIRECTORY);
    match fs::symlink_metadata(&neoenv) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(validation(
                "project .neoenv tree is not a regular directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime(&neoenv, &error)),
    }
    let path = lockfile_path(&root);
    let lockfile = read_lockfile(&path)?;
    Ok((root, path, lockfile))
}

fn project_declaration<'a>(
    declarations: &'a [ToolDeclaration],
    id: &str,
) -> Result<&'a ToolDeclaration, Diagnostic> {
    declarations
        .iter()
        .find(|declaration| declaration.id == id)
        .ok_or_else(|| not_found(format!("project tool is not declared: {id}")))
}

fn project_lock_tool<'a>(
    lockfile: &'a ToolLockfile,
    id: &str,
) -> Result<&'a LockedTool, Diagnostic> {
    lockfile
        .tools
        .iter()
        .find(|tool| tool.id == id)
        .ok_or_else(|| not_found(format!("project tool is not locked: {id}")))
}

fn project_pins<'a>(lockfile: &'a ToolLockfile, id: &str) -> &'a [String] {
    lockfile.pins.get(id).map_or(&[], Vec::as_slice)
}

fn project_install_root(root: &Path, tool: &LockedTool) -> Result<PathBuf, Diagnostic> {
    Ok(root
        .join(neoenv_core::names::PROJECT_TOOL_DIRECTORY)
        .join(install_key(tool)?))
}

fn project_installed_version(
    root: &Path,
    lockfile: &ToolLockfile,
    id: &str,
    version: &str,
) -> Result<Option<(PathBuf, String)>, Diagnostic> {
    let storage = neoenv_installer::tools::ToolStorage::project(root);
    if let Some(tool) = lockfile
        .tools
        .iter()
        .find(|tool| tool.id == id && tool.resolved_version == version && tool.resolver == "cargo")
    {
        let path = storage.install_directory().join(install_key(tool)?);
        let versions = installed_versions_in(&storage)?;
        return Ok(versions
            .into_iter()
            .find(|entry| entry.path == path)
            .map(|entry| (entry.path, entry.sha256)));
    }
    let versions = installed_versions_in(&storage)?;
    if let Some(entry) = versions
        .into_iter()
        .find(|entry| entry.id == id && entry.resolved_version == version)
    {
        return Ok(Some((entry.path, entry.sha256)));
    }
    // Roots created by the original installer predate the metadata marker.  A
    // current lock entry is still proof that this exact digest is nenv-owned.
    if let Some(tool) = lockfile
        .tools
        .iter()
        .find(|tool| tool.id == id && tool.resolved_version == version)
    {
        let path = storage.install_directory().join(&tool.sha256);
        let owned = fs::symlink_metadata(&path).is_ok_and(|metadata| {
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink()
        });
        if owned && project_receipt_matches(&path, &tool.sha256) {
            return Ok(Some((path, tool.sha256.clone())));
        }
    }
    Ok(None)
}

fn project_remove_owned_root(
    storage: &neoenv_installer::tools::ToolStorage,
    path: &Path,
    sha256: &str,
) -> Result<bool, Diagnostic> {
    let Some(storage_key) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    if path.parent() != Some(storage.install_directory())
        || !neoenv_core::tools::is_sha256(storage_key)
    {
        return Ok(false);
    }
    if remove_installed_version_in(storage, storage_key)? {
        return Ok(true);
    }
    if storage_key != sha256 {
        return Ok(false);
    }
    let expected = storage.install_directory().join(storage_key);
    if path != expected || !neoenv_core::tools::is_sha256(sha256) {
        return Ok(false);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            metadata
        }
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(runtime(path, &error)),
    };
    let _ = metadata;
    if !project_receipt_matches(path, sha256) {
        return Ok(false);
    }
    fs::remove_dir_all(path).map_err(|error| runtime(path, &error))?;
    Ok(true)
}

fn cleanup_project_update_temporary(
    storage: &neoenv_installer::tools::ToolStorage,
    roots: &[(String, String)],
    artifacts: &[String],
) {
    for (_, sha256) in roots {
        let _ = remove_installed_version_in(storage, sha256);
    }
    for sha256 in artifacts {
        let path = storage.artifact_directory().join(sha256);
        if neoenv_core::tools::is_sha256(sha256)
            && path.starts_with(storage.artifact_directory())
            && project_artifact_owned(&path, sha256)
        {
            let _ = super::remove_global_path(&path);
        }
    }
}

fn write_project_lock(path: &Path, lockfile: &ToolLockfile) -> Result<(), Diagnostic> {
    lockfile
        .validate()
        .map_err(|error| validation(error.to_string()))?;
    let output = toml::to_string_pretty(lockfile).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
    })?;
    state_file::write_atomic(path, output.as_bytes())
        .map_err(|error| state_file_diagnostic(path, error))
}

pub(crate) fn run(
    scope: ToolScope,
    project: Option<&ResolvedProject>,
    command: &super::ToolCommand,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match command {
        super::ToolCommand::Remove { .. }
        | super::ToolCommand::Update { .. }
        | super::ToolCommand::Pin { .. }
        | super::ToolCommand::Unpin { .. }
        | super::ToolCommand::Purge { .. }
            if scope == ToolScope::Global && !dry_run =>
        {
            Err(crate::global_install::system_mutation_disabled_diagnostic())
        }
        super::ToolCommand::Remove { .. } => match scope {
            ToolScope::Project => remove_project(project, tools, dry_run, format),
            ToolScope::User => remove_global(tools, dry_run, format, GlobalScope::User),
            ToolScope::Global => remove_global(tools, dry_run, format, GlobalScope::System),
        },
        super::ToolCommand::Update { .. } => match scope {
            ToolScope::Project => update_project(project, tools, dry_run, format),
            ToolScope::User => update_global(tools, dry_run, format, GlobalScope::User),
            ToolScope::Global => update_global(tools, dry_run, format, GlobalScope::System),
        },
        super::ToolCommand::Pin { .. } => match scope {
            ToolScope::Project => pin_project(project, tools, dry_run, format),
            ToolScope::User => pin_global(tools, dry_run, format, GlobalScope::User),
            ToolScope::Global => pin_global(tools, dry_run, format, GlobalScope::System),
        },
        super::ToolCommand::Unpin { .. } => match scope {
            ToolScope::Project => unpin_project(project, tools, dry_run, format),
            ToolScope::User => unpin_global(tools, dry_run, format, GlobalScope::User),
            ToolScope::Global => unpin_global(tools, dry_run, format, GlobalScope::System),
        },
        super::ToolCommand::Purge { .. } => match scope {
            ToolScope::Project => purge_project(project, tools, dry_run, format),
            ToolScope::User => purge_global(tools, dry_run, format, GlobalScope::User),
            ToolScope::Global => purge_global(tools, dry_run, format, GlobalScope::System),
        },
        _ => Err(usage("unsupported lifecycle command")),
    }
}
