//! The execution-trust store: which exact configuration bytes may direct an
//! effect.
//!
//! # What is trusted
//!
//! A trust record names one **identity**, never a location alone:
//!
//! - a local file is its canonical absolute path plus the BLAKE3 digest of the
//!   exact bytes that were parsed;
//! - a remote file is its canonical repository identity, the resolved immutable
//!   commit, the normalized repository-relative path, and the BLAKE3 digest of
//!   the exact bytes.
//!
//! A cache path, a URL on its own, a revision on its own, or a digest on its
//! own is not an identity. The store is `projects.toml` under the user's
//! configuration directory; repository allowlisting lives beside it in
//! `trust.toml` and authorizes *fetching*, never execution.
//!
//! # BLAKE3, and why not SHA-256
//!
//! New execution-trust identities and remote-file trust checksums are BLAKE3.
//! It is a fast cryptographic hash and the store verifies every contributing
//! file on every effect. Publisher-supplied artifact checksums — tool installs,
//! archives, and upstream release manifests — remain SHA-256 because the
//! publisher supplied that digest and converting it would mean comparing against
//! a number nobody published. Local project records written before this module
//! existed carry a `sha256` field and are still honored (and still checked with
//! SHA-256); approving the file again replaces that record with a BLAKE3 one.
//!
//! # What a digest does not mean
//!
//! A checksum is not authentication. A BLAKE3 digest proves only that the bytes
//! are the bytes that were approved. It says nothing about who wrote them, and
//! it is not a signature. Trust here is a local decision about content, not
//! proof of authorship.

use std::{
    collections::HashSet,
    fmt, fs, io,
    path::{Component, Path, PathBuf},
};

use neoenv_core::{Diagnostic, DiagnosticCategory};
use serde::Serialize;

use crate::{
    budget::{ResourceBudget, read_file_bytes},
    paths::{UserDirectory, user_directory},
    state_file::{self, LockedStateFile, StateFileError},
};

/// The trust-store format this build reads and writes.
pub const TRUST_FORMAT_VERSION: u32 = 2;

/// One hash algorithm that can appear in a trust record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    /// Used by every identity this module creates.
    Blake3,
    /// Accepted only for records written by an earlier build.
    Sha256,
}

impl DigestAlgorithm {
    /// The name written to the store and printed to a user.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
        }
    }
}

/// A hash of exact file bytes, with the algorithm that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    pub hex: String,
}

impl ContentDigest {
    /// Hashes bytes with BLAKE3. Every new trust identity uses this.
    #[must_use]
    pub fn blake3(bytes: &[u8]) -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3,
            hex: blake3::hash(bytes).to_hex().to_string(),
        }
    }

    /// Hashes bytes with SHA-256. Used only to verify a legacy record.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            algorithm: DigestAlgorithm::Sha256,
            hex: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    /// Recomputes this digest's algorithm over `bytes`.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        match self.algorithm {
            DigestAlgorithm::Blake3 => self.hex == Self::blake3(bytes).hex,
            DigestAlgorithm::Sha256 => self.hex == Self::sha256(bytes).hex,
        }
    }

    fn valid_hex(&self) -> bool {
        self.hex.len() == 64 && self.hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm.name(), self.hex)
    }
}

/// The identity of one contributing local file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalTrustIdentity {
    /// Canonical absolute path.
    pub path: String,
    pub digest: ContentDigest,
}

/// The identity of one contributing remote file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RemoteTrustIdentity {
    /// Canonical repository identity, for example `github.com/owner/repo`.
    pub repository: String,
    /// The resolved immutable commit, never a tag or branch.
    pub commit: String,
    /// Normalized repository-relative path with `/` separators.
    pub path: String,
    pub digest: ContentDigest,
}

/// Either kind of execution-trust identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TrustIdentity {
    Local(LocalTrustIdentity),
    Remote(RemoteTrustIdentity),
}

impl TrustIdentity {
    /// The digest that must match the bytes about to be executed or rendered.
    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        match self {
            Self::Local(identity) => &identity.digest,
            Self::Remote(identity) => &identity.digest,
        }
    }

    /// A stable key used to deduplicate contributors and match records.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Local(identity) => format!("local\n{}", identity.path),
            Self::Remote(identity) => format!(
                "remote\n{}\n{}\n{}",
                identity.repository, identity.commit, identity.path
            ),
        }
    }
}

impl fmt::Display for TrustIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(identity) => {
                write!(formatter, "{} ({})", identity.path, identity.digest)
            }
            Self::Remote(identity) => write!(
                formatter,
                "{}@{}//{} ({})",
                identity.repository, identity.commit, identity.path, identity.digest
            ),
        }
    }
}

/// One file that contributed to the selected configuration graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Contributor {
    pub identity: TrustIdentity,
    /// SHA-256 of the same bytes, retained only so a record written by an
    /// earlier build can still be verified without reopening the file. New
    /// records never use it.
    #[serde(skip)]
    pub legacy_sha256: Option<String>,
}

impl Contributor {
    /// Records a local document from the exact bytes that were parsed.
    ///
    /// A path that is not valid UTF-8 is refused: the store compares path
    /// strings, and a lossy replacement could make two distinct files share one
    /// approval.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be represented without loss.
    pub fn local(path: &Path, input: &str) -> Result<Self, TrustError> {
        let path = path.to_str().ok_or_else(|| TrustError::Store {
            path: path.to_owned(),
            message: "path is not valid UTF-8 and cannot be stored without loss".into(),
        })?;
        Ok(Self {
            identity: TrustIdentity::Local(LocalTrustIdentity {
                path: path.to_owned(),
                digest: ContentDigest::blake3(input.as_bytes()),
            }),
            legacy_sha256: Some(ContentDigest::sha256(input.as_bytes()).hex),
        })
    }

    /// Records a remote document from the exact bytes that were parsed.
    #[must_use]
    pub fn remote(repository: &str, commit: &str, relative_path: &str, input: &str) -> Self {
        Self {
            identity: TrustIdentity::Remote(RemoteTrustIdentity {
                repository: repository.to_owned(),
                commit: commit.to_owned(),
                path: relative_path.to_owned(),
                digest: ContentDigest::blake3(input.as_bytes()),
            }),
            legacy_sha256: None,
        }
    }
}

/// The parsed trust store.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    path: PathBuf,
    projects: Vec<LocalTrustIdentity>,
    remotes: Vec<RemoteTrustIdentity>,
}

impl TrustStore {
    /// The file these records were read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Local records, sorted by path.
    #[must_use]
    pub fn projects(&self) -> &[LocalTrustIdentity] {
        &self.projects
    }

    /// Remote records, sorted by repository, commit, then path.
    #[must_use]
    pub fn remotes(&self) -> &[RemoteTrustIdentity] {
        &self.remotes
    }

    fn local_record(&self, path: &str) -> Option<&LocalTrustIdentity> {
        self.projects
            .iter()
            .find(|record| same_path(&record.path, path))
    }

    fn remote_record(
        &self,
        repository: &str,
        commit: &str,
        path: &str,
    ) -> Option<&RemoteTrustIdentity> {
        self.remotes.iter().find(|record| {
            record.repository == repository && record.commit == commit && record.path == path
        })
    }
}

/// A trust decision that could not be made, or was made and refused.
#[derive(Debug)]
pub enum TrustError {
    /// The identity has no record at all.
    NotTrusted { identity: String },
    /// The identity's record names different bytes or coordinates.
    IdentityChanged {
        identity: String,
        expected: String,
        observed: String,
        remedy: String,
    },
    /// A requested record does not exist.
    NotFound { identity: String },
    /// The trust store is malformed or carries an unknown key.
    Store { path: PathBuf, message: String },
    /// The remote cache could not be read or verified.
    Remote { message: String },
    /// The file or store could not be read.
    Io { path: PathBuf, source: io::Error },
}

impl TrustError {
    /// Maps the failure to the diagnostic category the CLI reports.
    #[must_use]
    pub fn category(&self) -> DiagnosticCategory {
        match self {
            Self::NotTrusted { .. } | Self::IdentityChanged { .. } => DiagnosticCategory::Trust,
            Self::NotFound { .. } => DiagnosticCategory::NotFound,
            Self::Store { .. } | Self::Remote { .. } => DiagnosticCategory::Validation,
            Self::Io { .. } => DiagnosticCategory::Runtime,
        }
    }

    /// The stable diagnostic code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotTrusted { .. } | Self::IdentityChanged { .. } => "NEO344",
            Self::NotFound { .. } => "NEO345",
            Self::Store { .. } => "NEO346",
            Self::Remote { .. } => "NEO348",
            Self::Io { .. } => "NEO347",
        }
    }

    /// Converts the failure into a diagnostic with the same message.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic::new(self.category(), self.code(), self.to_string()).with_cause(self.clone())
    }
}

impl Clone for TrustError {
    fn clone(&self) -> Self {
        match self {
            Self::NotTrusted { identity } => Self::NotTrusted {
                identity: identity.clone(),
            },
            Self::IdentityChanged {
                identity,
                expected,
                observed,
                remedy,
            } => Self::IdentityChanged {
                identity: identity.clone(),
                expected: expected.clone(),
                observed: observed.clone(),
                remedy: remedy.clone(),
            },
            Self::NotFound { identity } => Self::NotFound {
                identity: identity.clone(),
            },
            Self::Store { path, message } => Self::Store {
                path: path.clone(),
                message: message.clone(),
            },
            Self::Remote { message } => Self::Remote {
                message: message.clone(),
            },
            Self::Io { path, source } => Self::Io {
                path: path.clone(),
                source: io::Error::new(source.kind(), source.to_string()),
            },
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTrusted { identity } => write!(
                formatter,
                "configuration is not trusted: {identity}; approve it explicitly with `nenv trust add <path>`"
            ),
            Self::IdentityChanged {
                identity,
                expected,
                observed,
                remedy,
            } => write!(
                formatter,
                "trust record for {identity} does not match: expected {expected}, observed {observed}; \
                 nothing was executed; {remedy}"
            ),
            Self::NotFound { identity } => {
                write!(formatter, "no trust record exists for {identity}")
            }
            Self::Store { path, message } => {
                write!(
                    formatter,
                    "malformed trust store {}: {message}",
                    path.display()
                )
            }
            Self::Remote { message } => write!(formatter, "remote trust identity: {message}"),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "failed to read trust state {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for TrustError {}

impl From<StateFileError> for TrustError {
    fn from(error: StateFileError) -> Self {
        let path = error.path().to_owned();
        if error.is_not_found() {
            return Self::Io {
                path,
                source: io::Error::new(io::ErrorKind::NotFound, error.to_string()),
            };
        }
        match error.io_error() {
            Some(source) => Self::Io {
                path,
                source: io::Error::new(source.kind(), error.to_string()),
            },
            None => Self::Store {
                path,
                message: error.to_string(),
            },
        }
    }
}

/// Returns the local trust-manifest location (`projects.toml`).
///
/// # Errors
///
/// Returns an error when no user configuration directory can be determined.
pub fn project_trust_path() -> Result<PathBuf, TrustError> {
    let root = user_directory(UserDirectory::Config).ok_or_else(|| TrustError::Io {
        path: PathBuf::from("."),
        source: io::Error::new(
            io::ErrorKind::NotFound,
            "cannot determine user configuration directory",
        ),
    })?;
    Ok(root.join(neoenv_core::names::PROJECTS_FILE))
}

/// Reads the trust store at the default location.
///
/// # Errors
///
/// Returns an error when the store is unreadable or malformed. A missing store
/// is an empty store: nothing is trusted, which is the safe answer.
pub fn read_trust_store() -> Result<TrustStore, TrustError> {
    read_store_at(&project_trust_path()?)
}

/// Reads the trust store at an explicit path.
///
/// # Errors
///
/// Returns an error when the store is unreadable or malformed.
pub fn read_store_at(path: &Path) -> Result<TrustStore, TrustError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(TrustError::Store {
                path: path.to_owned(),
                message: "trust store must be a regular file, not a symlink".into(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(TrustStore {
                path: path.to_owned(),
                ..TrustStore::default()
            });
        }
        Err(error) => {
            return Err(TrustError::Io {
                path: path.to_owned(),
                source: error,
            });
        }
    }
    let input =
        read_file_bytes(path, &ResourceBudget::default()).map_err(|source| TrustError::Io {
            path: path.to_owned(),
            source,
        })?;
    let input = String::from_utf8(input).map_err(|error| TrustError::Store {
        path: path.to_owned(),
        message: format!("trust store is not UTF-8: {error}"),
    })?;
    parse_store(&input, path)
}

/// Computes the identity of a local file from its exact bytes.
///
/// # Errors
///
/// Returns an error when the path cannot be canonicalized or read.
pub fn local_identity(path: &Path) -> Result<LocalTrustIdentity, TrustError> {
    let path = fs::canonicalize(path).map_err(|source| TrustError::Io {
        path: path.to_owned(),
        source,
    })?;
    let bytes =
        read_file_bytes(&path, &ResourceBudget::default()).map_err(|source| TrustError::Io {
            path: path.clone(),
            source,
        })?;
    let display = path.to_str().ok_or_else(|| TrustError::Store {
        path: path.clone(),
        message: "path is not valid UTF-8 and cannot be stored without loss".into(),
    })?;
    // A generated record is validated before it is used or written, so a
    // writer cannot publish a record the next read refuses.
    validate_local_path(display).map_err(|message| TrustError::Store {
        path: path.clone(),
        message,
    })?;
    Ok(LocalTrustIdentity {
        path: display.to_owned(),
        digest: ContentDigest::blake3(&bytes),
    })
}

/// Approves one local file's current bytes.
///
/// The read, update, and replacement happen under the same coordination lock,
/// and the replacement is atomic.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the store cannot be
/// updated. An existing record for the same canonical path is replaced.
pub fn approve_local(path: &Path) -> Result<LocalTrustIdentity, TrustError> {
    approve_local_in(&project_trust_path()?, path)
}

/// [`approve_local`] against an explicit store path.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the store cannot be
/// updated.
pub fn approve_local_in(store_path: &Path, path: &Path) -> Result<LocalTrustIdentity, TrustError> {
    let identity = local_identity(path)?;
    let parent = store_path.parent().ok_or_else(|| TrustError::Store {
        path: store_path.to_owned(),
        message: "trust store has no parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(|source| TrustError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let state = state_file::lock(store_path)?;
    let mut store = read_store_from_state(&state)?;
    store
        .projects
        .retain(|record| !same_path(&record.path, &identity.path));
    store.projects.push(identity.clone());
    write_store(&state, &mut store)?;
    Ok(identity)
}

/// Approves several local files under one lock and one atomic replacement.
///
/// Missing or unreadable files are skipped: a tree walk sees transient paths,
/// and approval of the files that exist is the useful outcome. A caller that
/// needs to know one specific file was approved uses [`approve_local_in`].
///
/// # Errors
///
/// Returns an error when the store cannot be read or written.
pub fn approve_locals_in(store_path: &Path, paths: &[PathBuf]) -> Result<(), TrustError> {
    let mut identities = Vec::with_capacity(paths.len());
    for path in paths {
        if let Ok(identity) = local_identity(path) {
            identities.push(identity);
        }
    }
    if identities.is_empty() {
        return Ok(());
    }
    let parent = store_path.parent().ok_or_else(|| TrustError::Store {
        path: store_path.to_owned(),
        message: "trust store has no parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(|source| TrustError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let state = state_file::lock(store_path)?;
    let mut store = read_store_from_state(&state)?;
    for identity in identities {
        store
            .projects
            .retain(|record| !same_path(&record.path, &identity.path));
        store.projects.push(identity);
    }
    write_store(&state, &mut store)
}

/// Revokes one local file's approval.
///
/// # Errors
///
/// Returns [`TrustError::NotFound`] when no record exists for the path, or a
/// store error when the state cannot be updated.
pub fn revoke_local(path: &Path) -> Result<LocalTrustIdentity, TrustError> {
    revoke_local_in(&project_trust_path()?, path)
}

/// [`revoke_local`] against an explicit store path.
///
/// # Errors
///
/// Returns [`TrustError::NotFound`] when no record exists for the path, or a
/// store error when the state cannot be updated.
pub fn revoke_local_in(store_path: &Path, path: &Path) -> Result<LocalTrustIdentity, TrustError> {
    let identity = local_identity(path)?;
    let parent = store_path.parent().ok_or_else(|| TrustError::Store {
        path: store_path.to_owned(),
        message: "trust store has no parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(|source| TrustError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let state = state_file::lock(store_path)?;
    let mut store = read_store_from_state(&state)?;
    let before = store.projects.len();
    store
        .projects
        .retain(|record| !same_path(&record.path, &identity.path));
    if store.projects.len() == before {
        return Err(TrustError::NotFound {
            identity: identity.path,
        });
    }
    write_store(&state, &mut store)?;
    Ok(identity)
}

/// Reports whether a local file's current bytes match an approval.
///
/// # Errors
///
/// Returns an error when the file or store cannot be read.
pub fn local_status(path: &Path) -> Result<(LocalTrustIdentity, bool), TrustError> {
    local_status_in(&project_trust_path()?, path)
}

/// [`local_status`] against an explicit store path.
///
/// # Errors
///
/// Returns an error when the file or store cannot be read.
pub fn local_status_in(
    store_path: &Path,
    path: &Path,
) -> Result<(LocalTrustIdentity, bool), TrustError> {
    let identity = local_identity(path)?;
    let store = read_store_at(store_path)?;
    let trusted = store.local_record(&identity.path).is_some_and(|record| {
        read_file_bytes(Path::new(&identity.path), &ResourceBudget::default())
            .is_ok_and(|bytes| record.digest.matches(&bytes))
    });
    Ok((identity, trusted))
}

/// Approves exact remote bytes for one repository, commit, and relative path.
///
/// The caller supplies bytes that were read from the controlled cache; this
/// function never fetches.
///
/// # Errors
///
/// Returns an error when the store cannot be updated.
pub fn approve_remote(
    repository: &str,
    commit: &str,
    relative_path: &str,
    bytes: &[u8],
) -> Result<RemoteTrustIdentity, TrustError> {
    approve_remote_in(
        &project_trust_path()?,
        repository,
        commit,
        relative_path,
        bytes,
    )
}

/// [`approve_remote`] against an explicit store path.
///
/// # Errors
///
/// Returns an error when the store cannot be updated.
pub fn approve_remote_in(
    store_path: &Path,
    repository: &str,
    commit: &str,
    relative_path: &str,
    bytes: &[u8],
) -> Result<RemoteTrustIdentity, TrustError> {
    validate_remote_fields(repository, commit, relative_path).map_err(|message| {
        TrustError::Store {
            path: store_path.to_owned(),
            message: format!("remote record: {message}"),
        }
    })?;
    let identity = RemoteTrustIdentity {
        repository: repository.to_owned(),
        commit: commit.to_owned(),
        path: relative_path.to_owned(),
        digest: ContentDigest::blake3(bytes),
    };
    let parent = store_path.parent().ok_or_else(|| TrustError::Store {
        path: store_path.to_owned(),
        message: "trust store has no parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(|source| TrustError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let state = state_file::lock(store_path)?;
    let mut store = read_store_from_state(&state)?;
    store.remotes.retain(|record| {
        !(record.repository == identity.repository
            && record.commit == identity.commit
            && record.path == identity.path)
    });
    store.remotes.push(identity.clone());
    write_store(&state, &mut store)?;
    Ok(identity)
}

/// Revokes one remote file approval.
///
/// # Errors
///
/// Returns [`TrustError::NotFound`] when the record is absent.
pub fn revoke_remote(
    repository: &str,
    commit: &str,
    relative_path: &str,
) -> Result<RemoteTrustIdentity, TrustError> {
    revoke_remote_in(&project_trust_path()?, repository, commit, relative_path)
}

/// [`revoke_remote`] against an explicit store path.
///
/// # Errors
///
/// Returns [`TrustError::NotFound`] when the record is absent.
pub fn revoke_remote_in(
    store_path: &Path,
    repository: &str,
    commit: &str,
    relative_path: &str,
) -> Result<RemoteTrustIdentity, TrustError> {
    let parent = store_path.parent().ok_or_else(|| TrustError::Store {
        path: store_path.to_owned(),
        message: "trust store has no parent directory".into(),
    })?;
    fs::create_dir_all(parent).map_err(|source| TrustError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let state = state_file::lock(store_path)?;
    let mut store = read_store_from_state(&state)?;
    let Some(position) = store.remotes.iter().position(|record| {
        record.repository == repository && record.commit == commit && record.path == relative_path
    }) else {
        return Err(TrustError::NotFound {
            identity: format!("{repository}@{commit}//{relative_path}"),
        });
    };
    let removed = store.remotes.remove(position);
    write_store(&state, &mut store)?;
    Ok(removed)
}

/// Reports whether the store contains a matching remote record.
///
/// # Errors
///
/// Returns an error when the store cannot be read.
pub fn remote_status(
    repository: &str,
    commit: &str,
    relative_path: &str,
) -> Result<(RemoteTrustIdentity, bool), TrustError> {
    remote_status_in(&project_trust_path()?, repository, commit, relative_path)
}

/// [`remote_status`] against an explicit store path.
///
/// # Errors
///
/// Returns an error when the store cannot be read.
pub fn remote_status_in(
    store_path: &Path,
    repository: &str,
    commit: &str,
    relative_path: &str,
) -> Result<(RemoteTrustIdentity, bool), TrustError> {
    let store = read_store_at(store_path)?;
    let identity = store
        .remote_record(repository, commit, relative_path)
        .cloned()
        .unwrap_or_else(|| RemoteTrustIdentity {
            repository: repository.to_owned(),
            commit: commit.to_owned(),
            path: relative_path.to_owned(),
            digest: ContentDigest::blake3(b""),
        });
    let trusted = store
        .remote_record(repository, commit, relative_path)
        .is_some();
    Ok((identity, trusted))
}

/// Refuses an effect unless `identity` matches a record exactly.
///
/// # Errors
///
/// Returns [`TrustError::NotTrusted`] when there is no record and
/// [`TrustError::IdentityChanged`] when the record names other bytes or
/// coordinates. The error names both identities.
pub fn require_identity(store: &TrustStore, identity: &TrustIdentity) -> Result<(), TrustError> {
    match identity {
        TrustIdentity::Local(observed) => match store.local_record(&observed.path) {
            None => Err(TrustError::NotTrusted {
                identity: observed.path.clone(),
            }),
            Some(record) if record.digest == observed.digest => Ok(()),
            Some(record) => Err(TrustError::IdentityChanged {
                identity: observed.path.clone(),
                expected: record.digest.to_string(),
                observed: observed.digest.to_string(),
                remedy: format!(
                    "run `nenv trust add {}` to approve the new content",
                    observed.path
                ),
            }),
        },
        TrustIdentity::Remote(observed) => {
            match store.remote_record(&observed.repository, &observed.commit, &observed.path) {
                None => Err(TrustError::NotTrusted {
                    identity: format!(
                        "{}@{}//{}",
                        observed.repository, observed.commit, observed.path
                    ),
                }),
                Some(record) if record.digest == observed.digest => Ok(()),
                Some(record) => Err(TrustError::IdentityChanged {
                    identity: format!(
                        "{}@{}//{}",
                        observed.repository, observed.commit, observed.path
                    ),
                    expected: record.digest.to_string(),
                    observed: observed.digest.to_string(),
                    remedy: "re-approve the cached file after checking the change".into(),
                }),
            }
        }
    }
}

/// Refuses a config-directed effect unless the root and every contributor are
/// trusted.
///
/// The root is checked first so the diagnostic names the file the user has to
/// approve before any dependency is considered. Nothing here reopens a
/// contributor: the digest was computed from the bytes that were parsed.
///
/// # Errors
///
/// Returns the first trust failure in root-then-graph order.
pub fn require_execution(root: &Path, contributors: &[Contributor]) -> Result<(), TrustError> {
    require_execution_in(&project_trust_path()?, root, contributors)
}

/// [`require_execution`] against an explicit store path.
///
/// # Errors
///
/// Returns the first trust failure in root-then-graph order.
pub fn require_execution_in(
    store_path: &Path,
    root: &Path,
    contributors: &[Contributor],
) -> Result<(), TrustError> {
    let store = read_store_at(store_path)?;
    let root = fs::canonicalize(root).map_err(|source| TrustError::Io {
        path: root.to_owned(),
        source,
    })?;
    let root_path = root.to_str().ok_or_else(|| TrustError::Store {
        path: root.clone(),
        message: "path is not valid UTF-8 and cannot be stored without loss".into(),
    })?;
    let root_contributor = contributors.iter().find(|contributor| {
        matches!(
            &contributor.identity,
            TrustIdentity::Local(identity) if same_path(&identity.path, root_path)
        )
    });
    if let Some(contributor) = root_contributor {
        require_contributor(&store, contributor)?;
    } else {
        let identity = local_identity(&root)?;
        require_identity(&store, &TrustIdentity::Local(identity))?;
    }
    for contributor in contributors {
        require_contributor(&store, contributor)?;
    }
    Ok(())
}

/// Verifies one contributor, accepting a legacy SHA-256 record for a local
/// file because the SHA-256 was computed from the same parsed bytes.
fn require_contributor(store: &TrustStore, contributor: &Contributor) -> Result<(), TrustError> {
    let TrustIdentity::Local(observed) = &contributor.identity else {
        return require_identity(store, &contributor.identity);
    };
    match store.local_record(&observed.path) {
        None => Err(TrustError::NotTrusted {
            identity: observed.path.clone(),
        }),
        Some(record) if record.digest == observed.digest => Ok(()),
        Some(record)
            if record.digest.algorithm == DigestAlgorithm::Sha256
                && contributor
                    .legacy_sha256
                    .as_ref()
                    .is_some_and(|sha256| sha256 == &record.digest.hex) =>
        {
            Ok(())
        }
        Some(record) => Err(TrustError::IdentityChanged {
            identity: observed.path.clone(),
            expected: record.digest.to_string(),
            observed: observed.digest.to_string(),
            remedy: format!(
                "run `nenv trust add {}` to approve the new content",
                observed.path
            ),
        }),
    }
}

fn read_store_from_state(state: &LockedStateFile) -> Result<TrustStore, TrustError> {
    match state.read_to_string() {
        Ok(input) => parse_store(&input, state.path()),
        Err(error) if error.is_not_found() => Ok(TrustStore {
            path: state.path().to_owned(),
            ..TrustStore::default()
        }),
        Err(error) => Err(error.into()),
    }
}

fn write_store(state: &LockedStateFile, store: &mut TrustStore) -> Result<(), TrustError> {
    store
        .projects
        .sort_by(|left, right| left.path.cmp(&right.path));
    store.remotes.sort_by(|left, right| {
        (&left.repository, &left.commit, &left.path).cmp(&(
            &right.repository,
            &right.commit,
            &right.path,
        ))
    });
    // Serialized with the TOML library, not Rust's debug formatting: a filename
    // containing a control byte has to become a legal TOML escape (`\u0001`),
    // and debug formatting emits a bare byte that the next read refuses.
    let mut root = toml::map::Map::new();
    root.insert(
        "format_version".into(),
        toml::Value::Integer(i64::from(TRUST_FORMAT_VERSION)),
    );
    let projects = store
        .projects
        .iter()
        .map(|record| {
            let mut table = toml::map::Map::new();
            table.insert("path".into(), toml::Value::String(record.path.clone()));
            table.insert(
                record.digest.algorithm.name().into(),
                toml::Value::String(record.digest.hex.clone()),
            );
            toml::Value::Table(table)
        })
        .collect::<Vec<_>>();
    root.insert("projects".into(), toml::Value::Array(projects));
    let remotes = store
        .remotes
        .iter()
        .map(|record| {
            let mut table = toml::map::Map::new();
            table.insert(
                "repository".into(),
                toml::Value::String(record.repository.clone()),
            );
            table.insert("commit".into(), toml::Value::String(record.commit.clone()));
            table.insert("path".into(), toml::Value::String(record.path.clone()));
            table.insert(
                record.digest.algorithm.name().into(),
                toml::Value::String(record.digest.hex.clone()),
            );
            toml::Value::Table(table)
        })
        .collect::<Vec<_>>();
    root.insert("remote".into(), toml::Value::Array(remotes));

    let output =
        toml::to_string_pretty(&toml::Value::Table(root)).map_err(|error| TrustError::Store {
            path: state.path().to_owned(),
            message: format!("cannot serialize trust store: {error}"),
        })?;
    // The complete document is validated before it replaces the old one. A
    // writer must never publish a store its own reader refuses.
    parse_store(&output, state.path())?;
    state.write(output.as_bytes()).map_err(TrustError::from)
}

fn parse_store(input: &str, path: &Path) -> Result<TrustStore, TrustError> {
    let store_error = |message: String| TrustError::Store {
        path: path.to_owned(),
        message,
    };
    let document: toml::Value =
        toml::from_str(input).map_err(|error| store_error(error.to_string()))?;
    let table = document
        .as_table()
        .ok_or_else(|| store_error("expected a TOML table".into()))?;
    for key in table.keys() {
        if !matches!(key.as_str(), "format_version" | "projects" | "remote") {
            return Err(store_error(format!("unknown key `{key}`")));
        }
    }
    let version = table
        .get("format_version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| store_error("expected integer `format_version`".into()))?;
    if version < 1 || u32::try_from(version).map_or(true, |version| version > TRUST_FORMAT_VERSION)
    {
        return Err(store_error(format!(
            "unsupported format_version {version}; this build writes {TRUST_FORMAT_VERSION}"
        )));
    }
    let mut store = TrustStore {
        path: path.to_owned(),
        ..TrustStore::default()
    };
    if let Some(projects) = table.get("projects") {
        store.projects = parse_projects(projects, path)?;
    }
    if let Some(remotes) = table.get("remote") {
        store.remotes = parse_remotes(remotes, path)?;
    }
    Ok(store)
}

fn parse_projects(value: &toml::Value, path: &Path) -> Result<Vec<LocalTrustIdentity>, TrustError> {
    let store_error = |message: String| TrustError::Store {
        path: path.to_owned(),
        message,
    };
    let projects = value
        .as_array()
        .ok_or_else(|| store_error("`projects` must be an array of tables".into()))?;
    let mut seen = HashSet::with_capacity(projects.len());
    let mut parsed = Vec::with_capacity(projects.len());
    for value in projects {
        let table = value
            .as_table()
            .ok_or_else(|| store_error("each `projects` entry must be a table".into()))?;
        let path = required_string(table, "path").map_err(&store_error)?;
        validate_local_path(&path)
            .map_err(|message| store_error(format!("project record path `{path}`: {message}")))?;
        if !seen.insert(path_key(&path)) {
            return Err(store_error(format!("duplicate project record: {path}")));
        }
        let digest = required_digest(table, &store_error)?;
        parsed.push(LocalTrustIdentity { path, digest });
    }
    Ok(parsed)
}

fn parse_remotes(value: &toml::Value, path: &Path) -> Result<Vec<RemoteTrustIdentity>, TrustError> {
    let store_error = |message: String| TrustError::Store {
        path: path.to_owned(),
        message,
    };
    let remotes = value
        .as_array()
        .ok_or_else(|| store_error("`remote` must be an array of tables".into()))?;
    let mut seen = HashSet::with_capacity(remotes.len());
    let mut parsed = Vec::with_capacity(remotes.len());
    for value in remotes {
        let table = value
            .as_table()
            .ok_or_else(|| store_error("each `remote` entry must be a table".into()))?;
        for key in table.keys() {
            if !matches!(key.as_str(), "repository" | "commit" | "path" | "blake3") {
                return Err(store_error(format!("unknown remote key `{key}`")));
            }
        }
        let repository = required_string(table, "repository").map_err(&store_error)?;
        let commit = required_string(table, "commit").map_err(&store_error)?;
        let relative = required_string(table, "path").map_err(&store_error)?;
        validate_remote_fields(&repository, &commit, &relative)
            .map_err(|message| store_error(format!("remote record: {message}")))?;
        if !seen.insert(remote_key(&repository, &commit, &relative)) {
            return Err(store_error(format!(
                "duplicate remote record: {repository}@{commit}//{relative}"
            )));
        }
        let digest = match table.get("blake3") {
            Some(value) => ContentDigest {
                algorithm: DigestAlgorithm::Blake3,
                hex: value
                    .as_str()
                    .ok_or_else(|| store_error("`blake3` must be a string".into()))?
                    .to_owned(),
            },
            None => {
                return Err(store_error(
                    "remote records require a `blake3` digest; SHA-256 is only accepted for legacy local project records"
                        .into(),
                ));
            }
        };
        if !digest.valid_hex() {
            return Err(store_error(
                "remote `blake3` must be 64 hexadecimal characters".into(),
            ));
        }
        parsed.push(RemoteTrustIdentity {
            repository,
            commit,
            path: relative,
            digest,
        });
    }
    Ok(parsed)
}

fn required_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<String, String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("expected string `{key}`"))
}

fn required_digest(
    table: &toml::map::Map<String, toml::Value>,
    store_error: &impl Fn(String) -> TrustError,
) -> Result<ContentDigest, TrustError> {
    for key in table.keys() {
        if !matches!(key.as_str(), "path" | "blake3" | "sha256") {
            return Err(store_error(format!("unknown project key `{key}`")));
        }
    }
    match (table.get("blake3"), table.get("sha256")) {
        (Some(_), Some(_)) => Err(store_error(
            "a project record must carry exactly one digest".into(),
        )),
        (Some(value), None) => {
            let digest = ContentDigest {
                algorithm: DigestAlgorithm::Blake3,
                hex: value
                    .as_str()
                    .ok_or_else(|| store_error("`blake3` must be a string".into()))?
                    .to_owned(),
            };
            if !digest.valid_hex() {
                return Err(store_error(
                    "`blake3` must be 64 hexadecimal characters".into(),
                ));
            }
            Ok(digest)
        }
        (None, Some(value)) => {
            let digest = ContentDigest {
                algorithm: DigestAlgorithm::Sha256,
                hex: value
                    .as_str()
                    .ok_or_else(|| store_error("`sha256` must be a string".into()))?
                    .to_owned(),
            };
            if !digest.valid_hex() {
                return Err(store_error(
                    "`sha256` must be 64 hexadecimal characters".into(),
                ));
            }
            Ok(digest)
        }
        (None, None) => Err(store_error(
            "a project record requires `blake3` (or a legacy `sha256`)".into(),
        )),
    }
}

/// A local record must name one canonical absolute file.
///
/// The store is hand-editable, so a relative path, a `.`/`..` segment, or an
/// empty separator is refused rather than silently never matching an identity.
/// **`Path::components()` is not enough**: it normalizes away interior dot
/// segments, so `/tmp/./neoenv.yaml` would be accepted. The raw spelling is
/// checked instead. Whitespace is a legal filename character and is kept, which
/// is what makes a generated record round-trip through this parser.
fn validate_local_path(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("path must be non-empty".into());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }
    for (index, part) in value
        .split(|character| character == '/' || (cfg!(windows) && character == '\\'))
        .enumerate()
    {
        if part.is_empty() {
            let allowed_prefix =
                index == 0 || (cfg!(windows) && index == 1 && value.starts_with("\\\\"));
            if !allowed_prefix {
                return Err("path must use its normalized spelling".into());
            }
        } else if matches!(part, "." | "..") {
            return Err("path may not contain `.` or `..` segments".into());
        }
    }
    let mut names_a_file = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {}
            Component::Normal(_) => names_a_file = true,
            Component::CurDir | Component::ParentDir => {
                return Err("path must be canonical and may not contain `.` or `..`".into());
            }
        }
    }
    if !names_a_file {
        return Err("path must name a file".into());
    }
    Ok(())
}

/// A remote record must carry both coordinates and a normalized relative path.
fn validate_remote_fields(
    repository: &str,
    commit: &str,
    relative_path: &str,
) -> Result<(), String> {
    validate_remote_repository(repository)?;
    if (commit.len() != 40 && commit.len() != 64)
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("commit must be 40 or 64 lowercase hexadecimal characters, never a tag".into());
    }
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || relative_path.chars().any(char::is_control)
    {
        return Err(
            "path must be a normalized repository-relative path with `/` separators".into(),
        );
    }
    Ok(())
}

/// A local git identity is `file://` followed by an absolute filesystem path.
///
/// The path is lexical: no `.`/`..` segments, no query or fragment, no
/// backslash. No filesystem access happens here, so validating an identity
/// cannot follow a link.
fn validate_local_repository_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains(['?', '#', '\\']) {
        return Err("local repository must be an absolute path with no query or fragment".into());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("local repository must be an absolute path".into());
    }
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir => {
                return Err("local repository path must not contain `.` or `..` segments".into());
            }
        }
    }
    Ok(())
}

/// A Git repository identity is `github.com/<owner>/<name>`, lowercase.
///
/// A bare `r` or `/` is not an identity: it has no host, owner, and name to
/// compare. Tarball imports have a URL identity instead and are validated by
/// [`validate_tarball_url`], because their URL may legitimately carry a query.
fn validate_remote_repository(value: &str) -> Result<(), String> {
    if value.starts_with("https://") {
        return validate_tarball_url(value);
    }
    if let Some(path) = value.strip_prefix("file://") {
        return validate_local_repository_path(path);
    }
    if value != value.trim() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("repository must not contain whitespace or control characters".into());
    }
    let mut parts = value.split('/');
    let (Some(host), Some(owner), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(
            "repository must be a canonical host/owner/name identity, not a URL or bare name"
                .into(),
        );
    };
    if host != "github.com"
        || !canonical_repository_segment(owner)
        || !canonical_repository_segment(name)
    {
        return Err("repository must be a canonical github.com/owner/name identity".into());
    }
    Ok(())
}

fn canonical_repository_segment(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value == value.to_ascii_lowercase()
        && !value.contains(['@', ':', '\\', '?', '#'])
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

/// A pinned archive URL. A query is part of the address the publisher signed;
/// credentials (`@`) and fragments are not, and the digest is separate.
fn validate_tarball_url(value: &str) -> Result<(), String> {
    if value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("tarball repository must be a valid HTTPS URL".into());
    }
    // WHATWG parsing repairs `https:///example.test/archive` into a URL with
    // host `example.test`. The original spelling has an empty authority, and
    // this is the only place that can still see it.
    let Some(rest) = value.strip_prefix("https://") else {
        return Err("tarball repository must be a valid HTTPS URL".into());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err("tarball repository must include an authority".into());
    }
    // `https://@example.test/archive` parses with an empty username and no
    // password, so the parsed URL cannot tell it from an ordinary host. The
    // original authority can, and `modules/tarball.rs` refuses any `@`.
    if authority.contains('@') {
        return Err("tarball repository must not carry credentials".into());
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| "tarball repository must be a valid HTTPS URL".to_string())?;
    if parsed.scheme() != "https" || parsed.host_str().is_none_or(str::is_empty) {
        return Err("tarball repository must be an HTTPS URL with an authority".into());
    }
    // A root path is legitimate: a server may serve its archive at `/`.
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("tarball repository must not carry credentials or a fragment".into());
    }
    Ok(())
}

fn path_key(value: &str) -> String {
    if cfg!(windows) {
        value.to_ascii_lowercase()
    } else {
        value.to_owned()
    }
}

fn remote_key(repository: &str, commit: &str, relative_path: &str) -> String {
    format!("{repository}\n{commit}\n{relative_path}")
}

fn same_path(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// Approves one file from the verified remote cache.
///
/// The spec is a remote source with a file subpath, for example
/// `github:owner/repo@<commit>//module.yaml`. The cache is read without a fetch
/// and without requiring repository allowlisting: approval is a local action on
/// bytes already present, and allowlisting authorizes fetches only.
///
/// # Errors
///
/// Returns an error when the spec, cache, or store cannot be read or verified.
pub fn approve_cached_remote(
    project_root: &Path,
    spec: &str,
) -> Result<RemoteTrustIdentity, TrustError> {
    approve_cached_remote_in(&project_trust_path()?, project_root, spec)
}

/// [`approve_cached_remote`] against an explicit store path.
///
/// # Errors
///
/// Returns an error when the spec, cache, or store cannot be read or verified.
pub fn approve_cached_remote_in(
    store_path: &Path,
    project_root: &Path,
    spec: &str,
) -> Result<RemoteTrustIdentity, TrustError> {
    let (repository, commit, relative_path, bytes) = cached_remote_file(project_root, spec)?;
    approve_remote_in(store_path, &repository, &commit, &relative_path, &bytes)
}

/// Revokes one file identity from the verified remote cache.
///
/// # Errors
///
/// Returns [`TrustError::NotFound`] when the record is absent, or an error when
/// the spec or cache cannot be read.
pub fn revoke_cached_remote(
    project_root: &Path,
    spec: &str,
) -> Result<RemoteTrustIdentity, TrustError> {
    let (repository, commit, relative_path, _) = cached_remote_file(project_root, spec)?;
    revoke_remote(&repository, &commit, &relative_path)
}

fn cached_remote_file(
    project_root: &Path,
    spec: &str,
) -> Result<(String, String, String, Vec<u8>), TrustError> {
    if let Some(tarball) =
        crate::modules::TarballModule::parse(spec).map_err(|error| TrustError::Remote {
            message: error.to_string(),
        })?
    {
        let cached =
            crate::modules::cached_tarball_details(project_root, &tarball).map_err(|error| {
                TrustError::Remote {
                    message: error.to_string(),
                }
            })?;
        if !cached.path.is_file() {
            return Err(TrustError::Remote {
                message: format!(
                    "remote trust requires a file path, not a directory: {}",
                    cached.path.display()
                ),
            });
        }
        let relative_path = repository_relative(&cached.source_root, &cached.path)?;
        let bytes =
            read_file_bytes(&cached.path, &ResourceBudget::default()).map_err(|source| {
                TrustError::Io {
                    path: cached.path.clone(),
                    source,
                }
            })?;
        return Ok((cached.url, cached.digest, relative_path, bytes));
    }
    let module = crate::remote::RemoteModule::parse(spec).map_err(|error| TrustError::Remote {
        message: error.to_string(),
    })?;
    let cached =
        crate::remote::cached_module_details_unchecked(project_root, &module).map_err(|error| {
            TrustError::Remote {
                message: error.to_string(),
            }
        })?;
    if !cached.path.is_file() {
        return Err(TrustError::Remote {
            message: format!(
                "remote trust requires a file path, not a directory: {}",
                cached.path.display()
            ),
        });
    }
    let relative_path = repository_relative(&cached.source_root, &cached.path)?;
    let bytes = read_file_bytes(&cached.path, &ResourceBudget::default()).map_err(|source| {
        TrustError::Io {
            path: cached.path.clone(),
            source,
        }
    })?;
    Ok((module.repository, cached.commit, relative_path, bytes))
}

fn repository_relative(root: &Path, path: &Path) -> Result<String, TrustError> {
    let relative = path.strip_prefix(root).map_err(|_| TrustError::Remote {
        message: format!(
            "remote document escapes its extraction root: {}",
            path.display()
        ),
    })?;
    let mut normalized = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(TrustError::Remote {
                message: format!("remote document path is not normalized: {}", path.display()),
            });
        };
        let part = part.to_str().ok_or_else(|| TrustError::Store {
            path: path.to_owned(),
            message: "remote document path is not valid UTF-8".into(),
        })?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    if normalized.is_empty() {
        return Err(TrustError::Remote {
            message: format!(
                "remote document path names the extraction root: {}",
                path.display()
            ),
        });
    }
    Ok(normalized)
}

/// The compatibility shape used by `nenv trust` before remote identities
/// existed. It names the same bytes as [`LocalTrustIdentity`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectTrust {
    pub path: String,
    pub blake3: String,
}

/// Approves a project configuration file and returns its identity.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the store updated.
pub fn trust_project(path: &Path) -> Result<ProjectTrust, TrustError> {
    let identity = approve_local(path)?;
    Ok(ProjectTrust {
        path: identity.path,
        blake3: identity.digest.hex,
    })
}

/// Reports a project file's current identity and whether it is approved.
///
/// # Errors
///
/// Returns an error when the file or store cannot be read.
pub fn project_trust_status(path: &Path) -> Result<(ProjectTrust, bool), TrustError> {
    let (identity, trusted) = local_status(path)?;
    Ok((
        ProjectTrust {
            path: identity.path,
            blake3: identity.digest.hex,
        },
        trusted,
    ))
}

/// Reports whether one contributor is covered by the store.
///
/// A legacy SHA-256 record is accepted for a local contributor because the
/// contributor retained the SHA-256 of the same parsed bytes.
#[must_use]
pub fn contributor_is_trusted(store: &TrustStore, contributor: &Contributor) -> bool {
    match &contributor.identity {
        TrustIdentity::Local(observed) => {
            store.local_record(&observed.path).is_some_and(|record| {
                record.digest == observed.digest
                    || (record.digest.algorithm == DigestAlgorithm::Sha256
                        && contributor
                            .legacy_sha256
                            .as_ref()
                            .is_some_and(|sha256| sha256 == &record.digest.hex))
            })
        }
        TrustIdentity::Remote(observed) => store
            .remote_record(&observed.repository, &observed.commit, &observed.path)
            .is_some_and(|record| record.digest == observed.digest),
    }
}

/// Rejects a duplicate contributor while preserving first-seen order.
#[must_use]
pub fn deduplicate(contributors: Vec<Contributor>) -> Vec<Contributor> {
    let mut seen = HashSet::new();
    contributors
        .into_iter()
        .filter(|contributor| seen.insert(contributor.identity.key()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{
        ContentDigest, Contributor, DigestAlgorithm, TrustError, TrustIdentity,
        approve_cached_remote_in, approve_local_in, approve_remote_in, local_status_in,
        read_store_at, require_execution_in, require_identity, revoke_local_in, revoke_remote_in,
    };

    fn store_path(root: &TempDir) -> std::path::PathBuf {
        root.path().join("projects.toml")
    }

    fn write(root: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        path
    }

    /// The contract's first rule for this store: new identities are BLAKE3.
    #[test]
    fn a_new_local_record_is_blake3_and_names_the_exact_bytes() {
        let root = TempDir::new().unwrap();
        let path = write(&root, "neoenv.yaml", "format_version: 1\n");
        let identity = approve_local_in(&store_path(&root), &path).unwrap();
        assert_eq!(identity.digest.algorithm, DigestAlgorithm::Blake3);
        assert_eq!(
            identity.digest.hex,
            blake3::hash(b"format_version: 1\n").to_hex().to_string()
        );

        let written = fs::read_to_string(store_path(&root)).unwrap();
        assert!(written.contains("blake3 ="), "{written}");
        assert!(!written.contains("sha256 ="), "{written}");
        assert!(written.contains(&identity.path));
    }

    /// A store written by an earlier build carries `sha256` and must keep
    /// working. A matching legacy record still authorizes, and a changed file
    /// still fails closed.
    #[test]
    fn a_legacy_sha256_project_record_still_verifies() {
        let root = TempDir::new().unwrap();
        let path = write(&root, "neoenv.yaml", "legacy\n");
        let legacy = ContentDigest::sha256(b"legacy\n");
        fs::write(
            store_path(&root),
            format!(
                "format_version = 1\n\n[[projects]]\npath = {:?}\nsha256 = {:?}\n",
                path.canonicalize().unwrap().display().to_string(),
                legacy.hex
            ),
        )
        .unwrap();

        let (identity, trusted) = local_status_in(&store_path(&root), &path).unwrap();
        assert!(trusted);
        assert_eq!(identity.digest.algorithm, DigestAlgorithm::Blake3);
        let store = read_store_at(&store_path(&root)).unwrap();
        assert_eq!(store.projects()[0].digest, legacy);
        // The execution gate accepts a legacy record because it decoded the
        // same parsed bytes and retained their SHA-256.
        require_execution_in(
            &store_path(&root),
            &path,
            &[Contributor::local(&path.canonicalize().unwrap(), "legacy\n").unwrap()],
        )
        .unwrap();

        fs::write(&path, "changed\n").unwrap();
        let (_, trusted) = local_status_in(&store_path(&root), &path).unwrap();
        assert!(!trusted);
    }

    /// Changing one file invalidates that approval only.
    #[test]
    fn a_content_change_invalidates_only_the_affected_file() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let first = write(&root, "one.yaml", "one\n");
        let second = write(&root, "two.yaml", "two\n");
        approve_local_in(&store, &first).unwrap();
        approve_local_in(&store, &second).unwrap();

        fs::write(&first, "one changed\n").unwrap();
        assert!(!local_status_in(&store, &first).unwrap().1);
        assert!(local_status_in(&store, &second).unwrap().1);
    }

    /// A path change is a new identity. The old record remains but cannot
    /// authorize the new path, and a revoke of the new path is not found.
    #[test]
    fn a_path_change_is_not_covered_by_the_old_approval() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let original = write(&root, "module.yaml", "module\n");
        approve_local_in(&store, &original).unwrap();
        let moved = root.path().join("nested/module.yaml");
        fs::create_dir_all(moved.parent().unwrap()).unwrap();
        fs::rename(&original, &moved).unwrap();

        assert!(!local_status_in(&store, &moved).unwrap().1);
        assert!(matches!(
            revoke_local_in(&store, &moved),
            Err(TrustError::NotFound { .. })
        ));
    }

    #[test]
    fn explicit_revoke_removes_the_record() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let path = write(&root, "neoenv.yaml", "config\n");
        approve_local_in(&store, &path).unwrap();
        assert!(local_status_in(&store, &path).unwrap().1);
        revoke_local_in(&store, &path).unwrap();
        assert!(!local_status_in(&store, &path).unwrap().1);
        assert!(matches!(
            revoke_local_in(&store, &path),
            Err(TrustError::NotFound { .. })
        ));
    }

    /// The root is reported before any dependency.
    #[test]
    fn the_root_is_checked_before_the_graph() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let config = write(&root, "neoenv.yaml", "config\n");
        let module = write(&root, "module.yaml", "module\n");
        let contributors = vec![
            Contributor::local(&config.canonicalize().unwrap(), "config\n").unwrap(),
            Contributor::local(&module.canonicalize().unwrap(), "module\n").unwrap(),
        ];
        let error = require_execution_in(&store, &config, &contributors).unwrap_err();
        assert!(matches!(error, TrustError::NotTrusted { .. }));
        assert!(error.to_string().contains("neoenv.yaml"), "{error}");
        assert!(!error.to_string().contains("module.yaml"), "{error}");
    }

    /// A dependency whose bytes changed does not execute, and the error names
    /// expected and observed identity.
    #[test]
    fn a_changed_dependency_reports_expected_and_observed_identity() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let config = write(&root, "neoenv.yaml", "config\n");
        let module = write(&root, "module.yaml", "module\n");
        approve_local_in(&store, &config).unwrap();
        approve_local_in(&store, &module).unwrap();
        fs::write(&module, "module changed\n").unwrap();

        let contributors = vec![
            Contributor::local(&config.canonicalize().unwrap(), "config\n").unwrap(),
            Contributor::local(&module.canonicalize().unwrap(), "module changed\n").unwrap(),
        ];
        let error = require_execution_in(&store, &config, &contributors).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("expected blake3:"), "{message}");
        assert!(message.contains("observed blake3:"), "{message}");
        assert!(message.contains("module.yaml"), "{message}");
        assert_eq!(error.code(), "NEO344");
    }

    /// Commit and subpath are part of a remote identity, so changing either
    /// leaves the old approval behind.
    #[test]
    fn a_remote_commit_or_subpath_change_invalidates_the_approval() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let commit = "0123456789abcdef0123456789abcdef01234567";
        approve_remote_in(
            &store,
            "github.com/octo/repo",
            commit,
            "module.yaml",
            b"body",
        )
        .unwrap();
        let approved = read_store_at(&store).unwrap();
        require_identity(
            &approved,
            &TrustIdentity::Remote(super::RemoteTrustIdentity {
                repository: "github.com/octo/repo".into(),
                commit: commit.into(),
                path: "module.yaml".into(),
                digest: ContentDigest::blake3(b"body"),
            }),
        )
        .unwrap();

        let other_commit = "fedcba9876543210fedcba9876543210fedcba98";
        let changed_commit = TrustIdentity::Remote(super::RemoteTrustIdentity {
            repository: "github.com/octo/repo".into(),
            commit: other_commit.into(),
            path: "module.yaml".into(),
            digest: ContentDigest::blake3(b"body"),
        });
        assert!(require_identity(&approved, &changed_commit).is_err());

        let changed_path = TrustIdentity::Remote(super::RemoteTrustIdentity {
            repository: "github.com/octo/repo".into(),
            commit: commit.into(),
            path: "nested/module.yaml".into(),
            digest: ContentDigest::blake3(b"body"),
        });
        assert!(require_identity(&approved, &changed_path).is_err());

        revoke_remote_in(&store, "github.com/octo/repo", commit, "module.yaml").unwrap();
        assert!(matches!(
            revoke_remote_in(&store, "github.com/octo/repo", commit, "module.yaml"),
            Err(TrustError::NotFound { .. })
        ));
    }

    #[test]
    fn a_changed_remote_digest_reports_expected_and_observed() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let commit = "0123456789abcdef0123456789abcdef01234567";
        approve_remote_in(
            &store,
            "github.com/octo/repo",
            commit,
            "module.yaml",
            b"approved",
        )
        .unwrap();
        let store = read_store_at(&store).unwrap();
        let error = require_identity(
            &store,
            &TrustIdentity::Remote(super::RemoteTrustIdentity {
                repository: "github.com/octo/repo".into(),
                commit: commit.into(),
                path: "module.yaml".into(),
                digest: ContentDigest::blake3(b"changed"),
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("expected blake3:"), "{message}");
        assert!(message.contains("observed blake3:"), "{message}");
        assert!(message.contains("module.yaml"), "{message}");
    }

    #[test]
    fn malformed_trust_state_fails_closed() {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        let project = |path: &str| {
            format!("format_version = 2\n\n[[projects]]\npath = {path:?}\nblake3 = {DIGEST:?}\n")
        };
        let duplicate_project = format!(
            "format_version = 2\n\n[[projects]]\npath = \"/tmp/a.yaml\"\nblake3 = {DIGEST:?}\n\n[[projects]]\npath = \"/tmp/a.yaml\"\nblake3 = {DIGEST:?}\n"
        );
        let remote = |repository: &str, commit: &str, path: &str| {
            format!(
                "format_version = 2\n\n[[remote]]\nrepository = {repository:?}\ncommit = {commit:?}\npath = {path:?}\nblake3 = {DIGEST:?}\n"
            )
        };
        let duplicate_remote = format!(
            "{}\n[[remote]]\nrepository = \"github.com/octo/repo\"\ncommit = {COMMIT:?}\npath = \"module.yaml\"\nblake3 = {DIGEST:?}\n",
            remote("github.com/octo/repo", COMMIT, "module.yaml")
        );
        let cases =
            vec![
            "format_version = 2\nunknown = true\n".to_owned(),
            "format_version = 2\n\n[[projects]]\npath = \"a\"\nblake3 = \"00\"\nsha256 = \"00\"\n"
                .to_owned(),
            "format_version = 99\n".to_owned(),
            String::new(),
            project(""),
            project("relative/neoenv.yaml"),
            project("/tmp/../tmp/neoenv.yaml"),
            project("/tmp/./neoenv.yaml"),
            project("/tmp//neoenv.yaml"),
            duplicate_project,
            remote("", COMMIT, "module.yaml"),
            remote("github.com/octo/repo", "", "module.yaml"),
            remote("github.com/octo/repo", "tag:v1", "module.yaml"),
            remote("github.com/octo/repo", COMMIT, ""),
            remote("github.com/octo/repo", COMMIT, "/module.yaml"),
            remote("https:///module.tar.gz", COMMIT, "module.yaml"),
            remote("https:///example.test/archive", COMMIT, "module.yaml"),
            remote("https://@example.test/archive", COMMIT, "module.yaml"),
            remote("https://user@example.test/module.tar.gz", COMMIT, "module.yaml"),
            remote("github.com/octo/repo", COMMIT, "../module.yaml"),
            remote("github.com/octo/repo", COMMIT, "nested//module.yaml"),
            duplicate_remote,
        ];
        for body in cases {
            fs::write(&store, &body).unwrap();
            assert!(
                read_store_at(&store).is_err(),
                "store should be refused: {body:?}"
            );
        }
    }

    #[test]
    fn approving_a_malformed_remote_identity_is_refused() {
        let root = TempDir::new().unwrap();
        let store = store_path(&root);
        for (repository, commit, path) in [
            (
                "",
                "0123456789abcdef0123456789abcdef01234567",
                "module.yaml",
            ),
            ("github.com/octo/repo", "", "module.yaml"),
            ("github.com/octo/repo", "main", "module.yaml"),
            (
                "github.com/octo/repo",
                "0123456789abcdef0123456789abcdef01234567",
                "",
            ),
            (
                "github.com/octo/repo",
                "0123456789abcdef0123456789abcdef01234567",
                "../x",
            ),
        ] {
            assert!(
                approve_remote_in(&store, repository, commit, path, b"bytes").is_err(),
                "identity should be refused: {repository:?} {commit:?} {path:?}"
            );
        }
        assert!(!store.exists());
    }

    #[test]
    fn a_valid_filename_with_a_trailing_space_round_trips() {
        let root = TempDir::new().unwrap();
        let store = root.path().join("store/projects.toml");
        let path = root.path().join("neoenv.yaml ");
        fs::write(&path, "config\n").unwrap();

        let identity = approve_local_in(&store, &path).unwrap();
        assert!(identity.path.ends_with("neoenv.yaml "), "{}", identity.path);
        let written = read_store_at(&store).unwrap();
        assert_eq!(written.projects().len(), 1);
        assert!(local_status_in(&store, &path).unwrap().1);
    }

    #[test]
    fn a_control_character_filename_round_trips() {
        let root = TempDir::new().unwrap();
        let store = root.path().join("store/projects.toml");
        let path = root.path().join("neoenv-\u{1}.yaml");
        fs::write(&path, "config\n").unwrap();

        let identity = approve_local_in(&store, &path).unwrap();
        assert!(identity.path.contains('\u{1}'), "{}", identity.path);
        let written = fs::read_to_string(&store).unwrap();
        assert!(
            written.contains("\\u0001"),
            "a control byte must be a legal TOML escape: {written}"
        );
        let parsed = read_store_at(&store).unwrap();
        assert_eq!(parsed.projects().len(), 1);
        assert!(local_status_in(&store, &path).unwrap().1);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_refused_instead_of_collapsed() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = TempDir::new().unwrap();
        let store = root.path().join("store/projects.toml");
        let path = root
            .path()
            .join(std::ffi::OsStr::from_bytes(b"neoenv-\xff.yaml"));
        fs::write(&path, "config\n").unwrap();

        let error = approve_local_in(&store, &path).unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"), "{error}");
        assert!(!store.exists());
        assert!(Contributor::local(&path, "config\n").is_err());
    }

    #[test]
    fn a_root_path_tarball_url_can_be_approved() {
        let project = TempDir::new().unwrap();
        let store_root = TempDir::new().unwrap();
        let store = store_root.path().join("projects.toml");
        let digest = "cd".repeat(32);
        // A server may serve the archive at `/`; the tarball import accepts it.
        let url = "https://example.test/";
        let cache = project
            .path()
            .join(neoenv_core::names::MODULE_TARBALLS)
            .join(&digest);
        fs::create_dir_all(cache.join("source")).unwrap();
        fs::write(
            cache.join("source/neoenv.module.yaml"),
            "env:\n  MODULE_VALUE: root-tarball\n",
        )
        .unwrap();
        fs::write(
            cache.join("metadata.toml"),
            format!("url = {url:?}\nsha256 = {digest:?}\n"),
        )
        .unwrap();

        let identity =
            approve_cached_remote_in(&store, project.path(), &format!("{url}#sha256={digest}"))
                .unwrap();
        assert_eq!(identity.repository, url);
        assert_eq!(identity.commit, digest);
        assert_eq!(identity.path, "neoenv.module.yaml");

        let written = read_store_at(&store).unwrap();
        require_identity(&written, &TrustIdentity::Remote(identity)).unwrap();
    }

    #[test]
    fn a_query_bearing_tarball_url_can_be_approved() {
        let project = TempDir::new().unwrap();
        let store_root = TempDir::new().unwrap();
        let store = store_root.path().join("projects.toml");
        let digest = "ab".repeat(32);
        let url = "https://example.test/module.tar.gz?token=signed&version=1";
        let cache = project
            .path()
            .join(neoenv_core::names::MODULE_TARBALLS)
            .join(&digest);
        fs::create_dir_all(cache.join("source")).unwrap();
        fs::write(
            cache.join("source/neoenv.module.yaml"),
            "env:\n  MODULE_VALUE: tarball\n",
        )
        .unwrap();
        fs::write(
            cache.join("metadata.toml"),
            format!("url = {url:?}\nsha256 = {digest:?}\n"),
        )
        .unwrap();

        let identity =
            approve_cached_remote_in(&store, project.path(), &format!("{url}#sha256={digest}"))
                .unwrap();
        assert_eq!(identity.repository, url);
        assert_eq!(identity.commit, digest);
        assert_eq!(identity.path, "neoenv.module.yaml");

        let written = read_store_at(&store).unwrap();
        require_identity(&written, &TrustIdentity::Remote(identity)).unwrap();
    }

    #[test]
    fn a_missing_store_is_an_empty_store_not_an_error() {
        let root = TempDir::new().unwrap();
        let store = read_store_at(&root.path().join("missing.toml")).unwrap();
        assert!(store.projects().is_empty());
        assert!(store.remotes().is_empty());
    }

    #[test]
    fn duplicate_contributors_are_recorded_once() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("neoenv.yaml");
        fs::write(&path, "config\n").unwrap();
        let contributor = Contributor::local(&path, "config\n").unwrap();
        let deduplicated = super::deduplicate(vec![contributor.clone(), contributor]);
        assert_eq!(deduplicated.len(), 1);
    }
}
