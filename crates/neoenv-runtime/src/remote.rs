//! Pinned GitHub module references, user trust policy, and immutable cache access.

use std::{
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use crate::{
    budget::{BudgetReader, ResourceBudget, ResourceLimit, read_text_file},
    paths::{UserDirectory, user_directory},
    state_file::{self, StateFileError},
    tasks::TaskCancellation,
    transport::{GitPolicy, HttpError, TimeoutPolicyError, redact_url_secrets},
};
mod client;
mod model;
#[cfg(test)]
mod tests;
mod trust;

pub(crate) use client::{CachedModule, cached_module_details, cached_module_details_unchecked};
pub use client::{
    cached_module, clear_module_cache, ensure_trusted, fetch_module, fetch_module_with_cancellation,
};
pub use model::{GitFailure, RemoteError, RemoteModule, RemoteReference, is_local_git, is_remote};
pub use trust::{trust_path, trust_repository, trusted_repositories, untrust_repository};

/// Compatibility re-exports. The execution-trust manifest is owned by
/// [`crate::trust`]; these names stay here because existing call sites reached
/// for them through `neoenv_runtime::remote`.
pub use crate::trust::{ProjectTrust, project_trust_path, project_trust_status, trust_project};

#[cfg(test)]
use client::*;
#[cfg(test)]
use trust::*;
