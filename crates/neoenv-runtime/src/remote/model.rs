//! Remote module identity, typed remote errors, and project trust records.

use super::{
    Arc, Digest, ExitStatus, HttpError, Sha256, StateFileError, TimeoutPolicyError, fmt, io,
    redact_url_secrets,
};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteModule {
    pub repository: String,
    pub reference: RemoteReference,
    pub subpath: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteReference {
    Commit(String),
    Tag(String),
}

/// A completed Git child that failed, retained without ever rendering its
/// stderr into a user-facing diagnostic.
///
/// The status and captured stderr are part of the typed source chain.  The
/// display implementation intentionally contains only the operation and exit
/// code because Git diagnostics can echo credential-bearing URLs or tokens.
#[derive(Debug)]
pub struct GitFailure {
    pub operation: String,
    pub status: ExitStatus,
    pub stderr: String,
    pub source: Option<Arc<io::Error>>,
}

impl fmt::Display for GitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status.code() {
            Some(code) => write!(
                formatter,
                "Git {} failed with exit status {code}",
                self.operation
            ),
            None => write!(formatter, "Git {} was terminated", self.operation),
        }
    }
}

impl std::error::Error for GitFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Errors produced by the remote Git/cache effect boundary.
///
/// The legacy string variants remain for validation and compatibility paths
/// that do not have an operational source.  Failures crossing an effect use
/// the typed `*Source`/`GitProcess` variants so callers can inspect the source
/// chain before mapping the error to a CLI diagnostic.
#[derive(Clone, Debug)]
pub enum RemoteError {
    InvalidSource,
    MissingImmutableReference,
    MutableReference,
    /// A local repository reference named a tag rather than a commit. A tag is
    /// a mutable name, so it cannot be an execution identity.
    LocalMutableReference,
    /// A fetch was requested for a non-local source. This build has no network
    /// transport; only `file://` and absolute-path repositories are fetchable.
    NonLocalFetch(String),
    InvalidSubpath,
    InvalidPolicy(String),
    PolicySource {
        message: String,
        source: Arc<TimeoutPolicyError>,
    },
    Cancelled,
    Untrusted(String),
    TrustNotFound(String),
    NotFetched(String),
    CacheMismatch(String),
    Io(String),
    IoSource {
        operation: String,
        source: Arc<io::Error>,
    },
    Http {
        operation: String,
        source: HttpError,
    },
    Archive {
        operation: String,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    Parser {
        operation: String,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    StateFile {
        operation: String,
        source: Arc<StateFileError>,
    },
    Diagnostic {
        operation: String,
        source: Arc<neoenv_core::Diagnostic>,
    },
    Git(String),
    GitProcess(Arc<GitFailure>),
}

impl RemoteError {
    pub(crate) fn io_source(operation: impl Into<String>, source: io::Error) -> Self {
        Self::IoSource {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn http_source(operation: impl Into<String>, source: HttpError) -> Self {
        Self::Http {
            operation: operation.into(),
            source,
        }
    }

    pub(crate) fn archive_source<E>(operation: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Archive {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn parser_source<E>(operation: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Parser {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn policy_source(source: TimeoutPolicyError) -> Self {
        Self::PolicySource {
            message: source.to_string(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn state_file_source(operation: impl Into<String>, source: StateFileError) -> Self {
        Self::StateFile {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn diagnostic_source(
        operation: impl Into<String>,
        source: neoenv_core::Diagnostic,
    ) -> Self {
        Self::Diagnostic {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }

    pub(crate) fn git_process(failure: GitFailure) -> Self {
        Self::GitProcess(Arc::new(failure))
    }

    /// Returns the retained Git status and stderr, when this is a Git child
    /// failure.
    #[must_use]
    pub fn git_failure(&self) -> Option<&GitFailure> {
        match self {
            Self::GitProcess(failure) => Some(failure),
            _ => None,
        }
    }

    /// Returns the retained HTTP error, when this failure crossed the HTTP
    /// adapter.
    #[must_use]
    pub fn http_error(&self) -> Option<&HttpError> {
        match self {
            Self::Http { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Returns the retained I/O error, when this failure crossed an I/O
    /// adapter directly.
    #[must_use]
    pub fn io_error(&self) -> Option<&io::Error> {
        match self {
            Self::IoSource { source, .. } => Some(source),
            Self::GitProcess(failure) => failure.source.as_deref(),
            _ => None,
        }
    }
}

impl PartialEq for RemoteError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
            && std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for RemoteError {}

impl fmt::Display for RemoteError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource => {
                output.write_str("remote modules must use GitHub HTTPS or github: syntax")
            }
            Self::MissingImmutableReference => {
                output.write_str("remote module requires a pinned commit or exact tag")
            }
            Self::MutableReference => output.write_str(
                "remote module reference must be a full commit or tag:<name>, not a branch or HEAD",
            ),
            Self::LocalMutableReference => output.write_str(
                "local git reference must be a full commit; a branch or tag is not immutable",
            ),
            Self::NonLocalFetch(source) => write!(
                output,
                "non-local fetch is not enabled; this build fetches only file:// or path git repositories: {source}"
            ),
            Self::InvalidPolicy(message) | Self::PolicySource { message, .. } => {
                output.write_str(message)
            }
            Self::Cancelled => output.write_str("remote module operation cancelled"),
            Self::InvalidSubpath => {
                output.write_str("remote module subpath must be non-empty and traversal-free")
            }
            Self::Untrusted(repository) => {
                write!(output, "remote repository is not trusted: {repository}")
            }
            Self::TrustNotFound(repository) => write!(
                output,
                "remote repository is not in the trust allow-list: {repository}"
            ),
            Self::NotFetched(source) => write!(
                output,
                "remote module is not fetched: {}",
                redact_url_secrets(source)
            ),
            Self::CacheMismatch(source) => write!(
                output,
                "remote cache does not match immutable reference: {}",
                redact_url_secrets(source)
            ),
            Self::Io(error) | Self::Git(error) => output.write_str(error),
            Self::IoSource { operation, .. } => {
                write!(output, "{operation}: filesystem operation failed")
            }
            Self::Http { operation, source } => write!(output, "{operation}: {source}"),
            Self::Archive { operation, .. } => {
                write!(output, "{operation}: archive could not be read")
            }
            Self::Parser { operation, .. } => {
                write!(output, "{operation}: parser rejected input")
            }
            Self::StateFile { operation, .. } => {
                write!(output, "{operation}: state file operation failed")
            }
            Self::Diagnostic { operation, .. } => {
                write!(output, "{operation}: configuration could not be read")
            }
            Self::GitProcess(failure) => fmt::Display::fmt(failure, output),
        }
    }
}

impl std::error::Error for RemoteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PolicySource { source, .. } => Some(source.as_ref()),
            Self::IoSource { source, .. } => Some(source.as_ref()),
            Self::Http { source, .. } => Some(source),
            Self::Archive { source, .. } | Self::Parser { source, .. } => Some(source.as_ref()),
            Self::StateFile { source, .. } => Some(source.as_ref()),
            Self::Diagnostic { source, .. } => Some(source.as_ref()),
            Self::GitProcess(failure) => Some(failure.as_ref()),
            Self::InvalidSource
            | Self::MissingImmutableReference
            | Self::MutableReference
            | Self::LocalMutableReference
            | Self::NonLocalFetch(_)
            | Self::InvalidSubpath
            | Self::InvalidPolicy(_)
            | Self::Cancelled
            | Self::Untrusted(_)
            | Self::TrustNotFound(_)
            | Self::NotFetched(_)
            | Self::CacheMismatch(_)
            | Self::Io(_)
            | Self::Git(_) => None,
        }
    }
}

impl RemoteModule {
    /// Parses one canonical, pinned GitHub or local git module source.
    ///
    /// # Errors
    ///
    /// Returns an error for non-GitHub, mutable, malformed, or traversal-containing sources.
    pub fn parse(value: &str) -> Result<Self, RemoteError> {
        let value = value.trim();
        if is_local_git(value) {
            return Self::parse_local(value);
        }
        let source = if let Some(source) = value.strip_prefix("github:") {
            source
        } else if let Some(https) = value.strip_prefix("https://") {
            let Some((host, source)) = https.split_once('/') else {
                return Err(RemoteError::InvalidSource);
            };
            if !host.eq_ignore_ascii_case("github.com") {
                return Err(RemoteError::InvalidSource);
            }
            source
        } else {
            return Err(RemoteError::InvalidSource);
        };
        if source.contains(['?', '#', '\\']) || value.contains('@') && value.contains("github.com@")
        {
            return Err(RemoteError::InvalidSource);
        }
        let (source, subpath) = match source.split_once("//") {
            Some((source, subpath)) => (source, Some(normalize_subpath(subpath)?)),
            None => (source, None),
        };
        let (repository, reference) = source
            .rsplit_once('@')
            .ok_or(RemoteError::MissingImmutableReference)?;
        let repository = repository.trim_end_matches(".git");
        let mut parts = repository.split('/');
        let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(RemoteError::InvalidSource);
        };
        if !valid_segment(owner) || !valid_segment(name) {
            return Err(RemoteError::InvalidSource);
        }
        Ok(Self {
            repository: format!(
                "github.com/{}/{}",
                owner.to_ascii_lowercase(),
                name.to_ascii_lowercase()
            ),
            reference: parse_reference(reference)?,
            subpath,
        })
    }

    /// Parses a local git source: `<absolute path>` or `file://<absolute path>`,
    /// followed by `@<full commit>` and an optional `//<subpath>`.
    ///
    /// A local reference must name a commit. A branch or tag is a mutable name,
    /// so it is refused rather than resolved.
    fn parse_local(value: &str) -> Result<Self, RemoteError> {
        let raw = value.strip_prefix("file://").unwrap_or(value);
        let (path, revision) = raw
            .rsplit_once('@')
            .ok_or(RemoteError::MissingImmutableReference)?;
        let (reference, subpath) = match revision.split_once("//") {
            Some((reference, subpath)) => (reference, Some(normalize_subpath(subpath)?)),
            None => (revision, None),
        };
        let repository = local_repository_identity(path)?;
        let reference = match parse_reference(reference)? {
            RemoteReference::Commit(commit) => RemoteReference::Commit(commit),
            RemoteReference::Tag(_) => return Err(RemoteError::LocalMutableReference),
        };
        Ok(Self {
            repository,
            reference,
            subpath,
        })
    }

    /// Whether this source is a local filesystem repository.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.repository.starts_with("file://")
    }

    /// The filesystem path behind a local repository identity.
    #[must_use]
    pub fn local_path(&self) -> Option<&str> {
        self.repository.strip_prefix("file://")
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        let reference = match &self.reference {
            RemoteReference::Commit(commit) => format!("commit:{commit}"),
            RemoteReference::Tag(tag) => format!("tag:{tag}"),
        };
        match &self.subpath {
            Some(subpath) => format!("{}@{}//{}", self.repository, reference, subpath),
            None => format!("{}@{}", self.repository, reference),
        }
    }

    #[must_use]
    pub fn cache_key(&self) -> String {
        let reference = match &self.reference {
            RemoteReference::Commit(commit) => format!("commit:{commit}"),
            RemoteReference::Tag(tag) => format!("tag:{tag}"),
        };
        format!(
            "{:x}",
            Sha256::digest(format!("{}@{}", self.repository, reference))
        )
    }

    #[must_use]
    pub fn git_url(&self) -> String {
        if let Some(path) = self.local_path() {
            return path.to_owned();
        }
        format!("https://{}.git", self.repository)
    }
}

/// Whether a value names a local git repository rather than a GitHub one.
///
/// `file://` is always a local form. A bare filesystem path is only treated as
/// a git source when it is absolute and carries an `@<revision>`, so an absolute
/// local task-package path without a revision is still refused as a path rather
/// than silently reinterpreted.
#[must_use]
pub fn is_local_git(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("file://") || (Path::new(value).is_absolute() && value.contains('@'))
}

/// Normalizes an absolute filesystem path to a `file://` repository identity.
///
/// The spelling is lexical: `.` segments are dropped, repeated separators are
/// collapsed, and `..` is refused rather than folded. No filesystem access
/// happens here, so parsing a reference cannot follow a link.
fn local_repository_identity(value: &str) -> Result<String, RemoteError> {
    crate::local_repository::normalize(value.trim()).ok_or(RemoteError::InvalidSource)
}

#[must_use]
pub fn is_remote(value: &str) -> bool {
    value.trim_start().starts_with("github:")
        || value.trim_start().starts_with("https://github.com/")
}
pub(super) fn parse_trust_repository(value: &str) -> Result<String, RemoteError> {
    if let Some(repository) = value.strip_prefix("github.com/") {
        canonical_repository(&format!("github:{repository}"))
    } else {
        canonical_repository(value)
    }
}

pub(super) fn trust_repository_identity(value: &str) -> Result<String, RemoteError> {
    canonical_repository(value)
        .or_else(|_| RemoteModule::parse(value).map(|module| module.repository))
}

pub(super) fn canonical_repository(value: &str) -> Result<String, RemoteError> {
    #[cfg(windows)]
    if (value.starts_with("file://") || Path::new(value).is_absolute()) && value != value.trim() {
        return Err(RemoteError::InvalidSource);
    }
    let value = value.trim();
    if let Some(path) = value.strip_prefix("file://") {
        if path.contains('@') {
            return RemoteModule::parse(value).map(|module| module.repository);
        }
        return local_repository_identity(path);
    }
    if Path::new(value).is_absolute() {
        if value.contains('@') {
            return RemoteModule::parse(value).map(|module| module.repository);
        }
        return local_repository_identity(value);
    }
    let source = if let Some(source) = value.strip_prefix("github:") {
        source
    } else if let Some(https) = value.strip_prefix("https://") {
        let Some((host, source)) = https.split_once('/') else {
            return Err(RemoteError::InvalidSource);
        };
        if !host.eq_ignore_ascii_case("github.com") {
            return Err(RemoteError::InvalidSource);
        }
        source
    } else {
        value
    }
    .trim_end_matches(".git");
    if source.contains(['@', '?', '#', '\\']) {
        return Err(RemoteError::InvalidSource);
    }
    let mut parts = source.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(RemoteError::InvalidSource);
    };
    if !valid_segment(owner) || !valid_segment(name) {
        return Err(RemoteError::InvalidSource);
    }
    Ok(format!(
        "github.com/{}/{}",
        owner.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    ))
}

pub(super) fn parse_reference(value: &str) -> Result<RemoteReference, RemoteError> {
    if (value.len() == 40 || value.len() == 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Ok(RemoteReference::Commit(value.to_ascii_lowercase()));
    }
    if let Some(tag) = value.strip_prefix("tag:")
        && !tag.is_empty()
        && !tag.contains([' ', '~', '^', ':', '\\'])
        && !tag.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Ok(RemoteReference::Tag(tag.to_owned()));
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "head" | "main" | "master"
    ) || !value.is_empty()
    {
        Err(RemoteError::MutableReference)
    } else {
        Err(RemoteError::MissingImmutableReference)
    }
}

pub(super) fn valid_segment(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "." | "..") && !value.contains(['@', ':', '\\'])
}
pub(super) fn normalize_subpath(value: &str) -> Result<String, RemoteError> {
    let value = value.trim_matches('/');
    if value.is_empty() || value.split('/').any(|part| matches!(part, "" | "." | "..")) {
        Err(RemoteError::InvalidSubpath)
    } else {
        Ok(value.to_owned())
    }
}
