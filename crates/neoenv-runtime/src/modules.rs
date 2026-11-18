//! Local module loading with canonical containment and deterministic postorder composition.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use flate2::read::GzDecoder;
use neoenv_config::{
    Format, ModuleImport, Project, TaskPackage, parse_project_with_profile, sources::ConfigSource,
};
use neoenv_core::{
    Diagnostic, DiagnosticCategory, SourceSpan,
    tasks::{TaskDefinition, TaskDotenvImport, TaskPackageIdentity},
};
use sha2::{Digest, Sha256};

use crate::budget::{ExtractionBudget, ResourceBudget, read_text_file};
use crate::paths::{UserDirectory, user_directory};
use crate::remote::{RemoteError, RemoteModule};
use crate::transport::HttpPolicy;

mod loader;
mod tarball;
#[cfg(test)]
mod tests;

pub(crate) use loader::ModuleLoader;
pub use loader::{load_local_modules, load_task_package};
pub use tarball::fetch_tarball_module;
pub(crate) use tarball::{TarballModule, cached_tarball_details};

#[cfg(test)]
use loader::discover_named_module_in;
#[cfg(test)]
use tarball::extract_tarball;

fn module_document(path: &Path) -> Result<PathBuf, Diagnostic> {
    if path.is_file() {
        return fs::canonicalize(path).map_err(|error| io_error(path, &error));
    }
    [
        "neoenv.module.yaml",
        "neoenv.module.yml",
        "neoenv.yaml",
        "neoenv.yml",
        "neoenv.toml",
    ]
    .iter()
    .map(|name| path.join(name))
    .find(|candidate| candidate.is_file())
    .ok_or_else(|| {
        validation(
            "NEO615",
            format!("module configuration was not found: {}", path.display()),
        )
    })
    .and_then(|candidate| fs::canonicalize(candidate).map_err(|error| io_error(path, &error)))
}

fn is_remote(value: &str) -> bool {
    crate::remote::is_remote(value) || value.contains("://") || value.starts_with("git@")
}

fn remote_error(error: &RemoteError) -> Diagnostic {
    let category = match error {
        RemoteError::Untrusted(_) => DiagnosticCategory::Trust,
        RemoteError::TrustNotFound(_) => DiagnosticCategory::NotFound,
        RemoteError::Cancelled => DiagnosticCategory::Runtime,
        _ => DiagnosticCategory::Validation,
    };
    Diagnostic::new(category, "NEO616", error.to_string()).with_cause(error.clone())
}

fn io_error(path: &Path, error: &std::io::Error) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO615",
        format!("failed to read local module {}: {error}", path.display()),
    )
    .with_cause(io::Error::new(error.kind(), error.to_string()))
}

fn imported_neoenv_error(path: &Path) -> Diagnostic {
    validation(
        "NEO611",
        format!("local modules must be YAML or TOML: {}", path.display()),
    )
}

fn validation(code: &str, message: String) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, code, message)
}
