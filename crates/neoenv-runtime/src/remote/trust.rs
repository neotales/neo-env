//! Repository allowlisting and fetch policy.
//!
//! This file owns `trust.toml`. It answers one question: **may `nenv` fetch from
//! this canonical repository?** It never answers whether content may execute.
//! Execution approval lives in [`crate::trust`] and is keyed on exact file
//! identity. Adding a repository here authorizes a fetch, not a run.

use super::model::{parse_trust_repository, trust_repository_identity};
use super::{
    Path, PathBuf, RemoteError, ResourceBudget, UserDirectory, fs, read_text_file, state_file,
    user_directory,
};
use crate::state_file::StateFileError;

/// Returns the user-scoped remote trust policy location.
///
/// # Errors
///
/// Returns an error when no user configuration directory can be determined.
pub fn trust_path() -> Result<PathBuf, RemoteError> {
    let root = user_config_root()?;
    Ok(root.join(neoenv_core::names::TRUST_FILE))
}

fn user_config_root() -> Result<PathBuf, RemoteError> {
    user_directory(UserDirectory::Config)
        .ok_or_else(|| RemoteError::Io("cannot determine user configuration directory".into()))
}

/// Reads canonical repository identities from the user allow-list.
///
/// # Errors
///
/// Returns an error for unreadable or malformed policy files.
pub fn trusted_repositories() -> Result<Vec<String>, RemoteError> {
    let path = trust_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let input = read_text_file(&path, &ResourceBudget::default())
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    parse_trusted_repositories(&input, &path)
}

pub(super) fn parse_trusted_repositories(
    input: &str,
    path: &Path,
) -> Result<Vec<String>, RemoteError> {
    let document: toml::Value = toml::from_str(input).map_err(|error| {
        RemoteError::parser_source(format!("invalid trust policy {}", path.display()), error)
    })?;
    let table = document.as_table().ok_or_else(|| {
        RemoteError::Io(format!(
            "invalid trust policy {}: expected a TOML table",
            path.display()
        ))
    })?;
    for key in table.keys() {
        if key != "remote" {
            return Err(RemoteError::Io(format!(
                "invalid trust policy {}: unknown key `{key}`",
                path.display()
            )));
        }
    }
    let values = document
        .get("remote")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("allow"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            RemoteError::Io(format!(
                "invalid trust policy {}: expected remote.allow array",
                path.display()
            ))
        })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| RemoteError::Io("remote.allow entries must be strings".into()))
                .and_then(parse_trust_repository)
        })
        .collect()
}

/// Adds a canonical repository identity to the user allow-list.
///
/// # Errors
///
/// Returns an error for invalid repositories or policy I/O failures.
pub fn trust_repository(value: &str) -> Result<String, RemoteError> {
    let repository = trust_repository_identity(value)?;
    let path = trust_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid trust policy path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let state = state_file::lock(&path).map_err(remote_state_error)?;
    let mut repositories = match state.read_to_string() {
        Ok(input) => parse_trusted_repositories(&input, &path)?,
        Err(error) if error.is_not_found() => Vec::new(),
        Err(error) => return Err(remote_state_error(error)),
    };
    if !repositories.contains(&repository) {
        repositories.push(repository.clone());
        write_trusted_repositories(&state, &mut repositories)?;
    }
    Ok(repository)
}

/// Removes one canonical repository from the user allow-list.
///
/// The read, removal, and replacement are performed while holding the same
/// coordination lock used by [`trust_repository`]. A missing entry is reported
/// as a stable not-found error rather than silently creating a policy file.
///
/// # Errors
///
/// Returns [`RemoteError::TrustNotFound`] when the repository is not present,
/// or a validation, policy, or filesystem error for malformed or inaccessible
/// trust state.
pub fn untrust_repository(value: &str) -> Result<String, RemoteError> {
    let repository = trust_repository_identity(value)?;
    let path = trust_path()?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RemoteError::TrustNotFound(repository));
        }
        Err(error) => return Err(RemoteError::io_source("remote filesystem operation", error)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid trust policy path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let state = state_file::lock(&path).map_err(remote_state_error)?;
    let mut repositories = match state.read_to_string() {
        Ok(input) => parse_trusted_repositories(&input, &path)?,
        Err(error) if error.is_not_found() => Vec::new(),
        Err(error) => return Err(remote_state_error(error)),
    };
    let before = repositories.len();
    repositories.retain(|entry| entry != &repository);
    if repositories.len() == before {
        return Err(RemoteError::TrustNotFound(repository));
    }
    write_trusted_repositories(&state, &mut repositories)?;
    Ok(repository)
}

fn write_trusted_repositories(
    state: &crate::state_file::LockedStateFile,
    repositories: &mut [String],
) -> Result<(), RemoteError> {
    repositories.sort();
    let entries = repositories
        .iter()
        .map(|repository| format!("  {repository:?}"))
        .collect::<Vec<_>>()
        .join(",\n");
    state
        .write(format!("[remote]\nallow = [\n{entries}\n]\n").as_bytes())
        .map_err(remote_state_error)
}

pub(super) fn remote_state_error(error: StateFileError) -> RemoteError {
    RemoteError::state_file_source("remote state operation", error)
}
