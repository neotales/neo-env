//! User-owned persisted capability policy loading.

use std::{
    env, fmt, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use neoenv_policy::CapabilityGrants;

use crate::{
    budget::{ResourceBudget, read_text_file},
    paths::{UserDirectory, user_directory},
};

/// Errors loading the external capability policy.
#[derive(Clone, Debug)]
pub enum CapabilityPolicyError {
    Location,
    Read {
        path: PathBuf,
        message: String,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    ReadSource {
        path: PathBuf,
        source: Arc<io::Error>,
    },
    ParseSource {
        path: PathBuf,
        source: Arc<toml::de::Error>,
    },
}

impl fmt::Display for CapabilityPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Location => formatter.write_str("cannot determine user configuration directory"),
            Self::Read { path, message } => write!(
                formatter,
                "cannot read capability policy {}: {message}",
                path.display()
            ),
            Self::Parse { path, message } => write!(
                formatter,
                "invalid capability policy {}: {message}",
                path.display()
            ),
            Self::ReadSource { path, .. } => write!(
                formatter,
                "cannot read capability policy {}",
                path.display()
            ),
            Self::ParseSource { path, .. } => {
                write!(formatter, "invalid capability policy {}", path.display())
            }
        }
    }
}

impl PartialEq for CapabilityPolicyError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
            && std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for CapabilityPolicyError {}

impl std::error::Error for CapabilityPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadSource { source, .. } => Some(source.as_ref()),
            Self::ParseSource { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Returns the default user-owned persisted capability policy location.
///
/// The `NEOENV_CAPABILITY_POLICY` environment variable overrides this location
/// for non-interactive or test execution.
///
/// # Errors
///
/// Returns an error when no supported user configuration location is available.
pub fn capability_policy_path() -> Result<PathBuf, CapabilityPolicyError> {
    if let Some(path) = env::var_os("NEOENV_CAPABILITY_POLICY") {
        return Ok(PathBuf::from(path));
    }
    let root = user_directory(UserDirectory::Config).ok_or(CapabilityPolicyError::Location)?;
    Ok(root.join(neoenv_core::names::CAPABILITIES_FILE))
}

/// Loads grants from a user-owned policy file. A missing policy is an empty,
/// default-deny grant set rather than an implicit approval.
///
/// Capability documents are intentionally read-only in the current runtime.
/// Any future capability-file mutation must use [`crate::state_file`] rather
/// than a direct write.
///
/// # Errors
///
/// Returns an error when an existing policy cannot be read or parsed.
pub fn load_capability_grants(path: &Path) -> Result<CapabilityGrants, CapabilityPolicyError> {
    let document = match read_text_file(path, &ResourceBudget::default()) {
        Ok(document) => document,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CapabilityGrants::default());
        }
        Err(error) => {
            return Err(CapabilityPolicyError::ReadSource {
                path: path.to_owned(),
                source: Arc::new(error),
            });
        }
    };
    CapabilityGrants::from_toml(&document).map_err(|error| CapabilityPolicyError::ParseSource {
        path: path.to_owned(),
        source: Arc::new(error),
    })
}

#[cfg(test)]
mod tests {
    use super::load_capability_grants;

    #[test]
    fn missing_policy_is_default_deny() {
        let directory = tempfile::TempDir::new().unwrap();
        let grants = load_capability_grants(&directory.path().join("missing.toml")).unwrap();

        assert!(!grants.authorizes(
            neoenv_policy::Capability::Execute,
            "project:example/task:build"
        ));
    }
}
