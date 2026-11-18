//! Remote fetch and cache population. Git and archive work runs under a
//! transport seam so tests can substitute a local origin, and every child
//! process is bounded and reaped with its tree.

use super::trust::remote_state_error;
use super::{
    Arc, AtomicBool, BudgetReader, Command, Digest, Duration, ExitStatus, GitFailure, GitPolicy,
    Instant, Ordering, Path, PathBuf, Read, RemoteError, RemoteModule, RemoteReference,
    ResourceBudget, ResourceLimit, Sha256, Stdio, TaskCancellation, fs, read_text_file,
    redact_url_secrets, state_file, thread, trusted_repositories,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GitFileProtocol {
    Deny,
    Allow,
}

/// Internal seam between the immutable remote source and the Git process.
///
/// The application implementation always uses [`GitHubGitTransport`]. Tests
/// can provide a transport for one canonical repository without adding a
/// user-facing URL override to the runtime.
pub(super) trait GitTransport {
    fn fetch_url(&self, module: &RemoteModule) -> String;

    fn file_protocol(&self) -> GitFileProtocol {
        GitFileProtocol::Deny
    }
}

#[cfg(test)]
pub(super) struct GitHubGitTransport;

#[cfg(test)]
impl GitTransport for GitHubGitTransport {
    fn fetch_url(&self, module: &RemoteModule) -> String {
        module.git_url()
    }
}

/// Transport for an explicitly allow-listed local repository.
///
/// Only a `file://` identity reaches it, and [`ensure_trusted`] has already
/// required the repository allow-list. The URL is a filesystem path, so no
/// network, credential, or SSH transport is reachable.
pub(super) struct LocalGitTransport {
    pub(super) url: String,
}

impl GitTransport for LocalGitTransport {
    fn fetch_url(&self, _module: &RemoteModule) -> String {
        self.url.clone()
    }

    fn file_protocol(&self) -> GitFileProtocol {
        GitFileProtocol::Allow
    }
}
/// Verifies that a module's canonical repository is explicitly trusted.
///
/// # Errors
///
/// Returns an error when the user allow-list does not contain the repository.
pub fn ensure_trusted(module: &RemoteModule) -> Result<(), RemoteError> {
    if trusted_repositories()?.contains(&module.repository) {
        Ok(())
    } else {
        Err(RemoteError::Untrusted(module.repository.clone()))
    }
}

/// Returns an already-fetched immutable module directory without doing network I/O.
///
/// # Errors
///
/// Returns an error for untrusted, missing, tampered, or escaping cache entries.
pub fn cached_module(project_root: &Path, module: &RemoteModule) -> Result<PathBuf, RemoteError> {
    cached_module_with_cancellation(project_root, module, None)
}

#[derive(Clone, Debug)]
pub(crate) struct CachedModule {
    pub path: PathBuf,
    pub commit: String,
    pub source_root: PathBuf,
}

pub(super) fn cached_module_with_cancellation(
    project_root: &Path,
    module: &RemoteModule,
    cancellation: Option<&TaskCancellation>,
) -> Result<PathBuf, RemoteError> {
    cached_module_details_with_cancellation(project_root, module, cancellation)
        .map(|cached| cached.path)
}

/// Returns an already-fetched module together with the immutable commit and the
/// canonical extraction root those bytes came from.
pub(crate) fn cached_module_details(
    project_root: &Path,
    module: &RemoteModule,
) -> Result<CachedModule, RemoteError> {
    cached_module_details_with_cancellation(project_root, module, None)
}

/// Cache verification without the repository allowlist.
///
/// Approving a cached file is a local read that performs no fetch, so it must
/// not require fetch policy. The cache is still verified structurally.
pub(crate) fn cached_module_details_unchecked(
    project_root: &Path,
    module: &RemoteModule,
) -> Result<CachedModule, RemoteError> {
    let commit = match &module.reference {
        RemoteReference::Commit(commit) => commit.clone(),
        RemoteReference::Tag(_) => tag_binding_commit(project_root, module)?,
    };
    cached_module_for_commit_details(project_root, module, &commit, None)
}

pub(super) fn cached_module_details_with_cancellation(
    project_root: &Path,
    module: &RemoteModule,
    cancellation: Option<&TaskCancellation>,
) -> Result<CachedModule, RemoteError> {
    ensure_trusted(module)?;
    let commit = match &module.reference {
        RemoteReference::Commit(commit) => commit.clone(),
        RemoteReference::Tag(_) => tag_binding_commit(project_root, module)?,
    };
    cached_module_for_commit_details(project_root, module, &commit, cancellation)
}

#[cfg(test)]
pub(super) fn cached_module_for_commit(
    project_root: &Path,
    module: &RemoteModule,
    resolved_commit: &str,
) -> Result<PathBuf, RemoteError> {
    cached_module_for_commit_with_cancellation(project_root, module, resolved_commit, None)
}

pub(super) fn cached_module_for_commit_with_cancellation(
    project_root: &Path,
    module: &RemoteModule,
    resolved_commit: &str,
    cancellation: Option<&TaskCancellation>,
) -> Result<PathBuf, RemoteError> {
    cached_module_for_commit_details(project_root, module, resolved_commit, cancellation)
        .map(|cached| cached.path)
}

pub(super) fn cached_module_for_commit_details(
    project_root: &Path,
    module: &RemoteModule,
    resolved_commit: &str,
    cancellation: Option<&TaskCancellation>,
) -> Result<CachedModule, RemoteError> {
    let root = commit_cache_path(project_root, module, resolved_commit);
    let metadata_path = root.join("metadata.toml");
    if fs::symlink_metadata(&metadata_path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.file_type().is_file())
    {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    let metadata =
        read_text_file(&metadata_path, &ResourceBudget::default()).map_err(|error| match error
            .kind()
        {
            std::io::ErrorKind::NotFound => RemoteError::NotFetched(module.canonical()),
            std::io::ErrorKind::InvalidData => RemoteError::CacheMismatch(module.canonical()),
            _ => RemoteError::io_source("remote filesystem operation", error),
        })?;
    let expected = metadata_for(&module.repository, resolved_commit);
    if metadata != expected {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    let root_metadata = fs::symlink_metadata(&root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RemoteError::NotFetched(module.canonical())
        } else {
            RemoteError::io_source("remote filesystem operation", error)
        }
    })?;
    if !root_metadata.file_type().is_dir() {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    let source = root.join("source");
    let source_metadata = fs::symlink_metadata(&source)
        .map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
    if !source_metadata.file_type().is_dir() {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    let canonical_cache_root =
        fs::canonicalize(&root).map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
    let canonical_root =
        fs::canonicalize(&source).map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
    if canonical_root == canonical_cache_root || !canonical_root.starts_with(&canonical_cache_root)
    {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    let commit = revision_with_cancellation(&source, cancellation)?;
    if resolved_commit != commit {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    ensure_clean_worktree(&source, &commit, module, cancellation)?;
    let path = module
        .subpath
        .as_ref()
        .map_or_else(|| source.clone(), |subpath| source.join(subpath));
    refuse_symlinked_subpath(&canonical_root, &path, module)?;
    let canonical_path =
        fs::canonicalize(&path).map_err(|_| RemoteError::NotFetched(module.canonical()))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    Ok(CachedModule {
        path: canonical_path,
        commit,
        source_root: canonical_root,
    })
}

/// Rejects a selected remote path that is, or traverses, a symbolic link.
///
/// Canonicalization alone would accept a link that points back inside the
/// checkout. Trust identities are repository-relative paths, and a link means
/// the path a record names is not the path the bytes came from.
fn refuse_symlinked_subpath(
    source_root: &Path,
    selected: &Path,
    module: &RemoteModule,
) -> Result<(), RemoteError> {
    let relative = selected
        .strip_prefix(source_root)
        .map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
    if relative.as_os_str().is_empty() {
        return Ok(());
    }
    let mut current = source_root.to_owned();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
        if metadata.file_type().is_symlink() {
            return Err(RemoteError::CacheMismatch(module.canonical()));
        }
    }
    Ok(())
}

/// Explicitly fetches a trusted module, or verifies an existing immutable cache on update.
///
/// # Errors
///
/// Returns an error for trust, cache, filesystem, or Git transport failures.
pub fn fetch_module(
    project_root: &Path,
    module: &RemoteModule,
    update: bool,
) -> Result<PathBuf, RemoteError> {
    fetch_module_with_cancellation(project_root, module, update, None)
}

/// Explicitly fetches a trusted module while observing an optional cancellation flag.
///
/// # Errors
///
/// Returns trust, policy, cancellation, cache, filesystem, or Git transport failures.
pub fn fetch_module_with_cancellation(
    project_root: &Path,
    module: &RemoteModule,
    update: bool,
    cancellation: Option<&TaskCancellation>,
) -> Result<PathBuf, RemoteError> {
    let Some(path) = module.local_path() else {
        // No network transport is enabled in this build. Refusing here keeps
        // `nenv remote fetch` unable to reach GitHub, an SSH remote, or any
        // other scheme, and it happens before a Git child is spawned.
        return Err(RemoteError::NonLocalFetch(module.canonical()));
    };
    if !crate::local_repository::validate_identity(&module.repository) {
        return Err(RemoteError::InvalidSource);
    }
    #[cfg(windows)]
    let path = path.replace('/', "\\");
    #[cfg(not(windows))]
    let path = path.to_owned();
    let transport = LocalGitTransport { url: path };
    fetch_module_with_transport(project_root, module, update, cancellation, &transport)
}

pub(super) fn fetch_module_with_transport<T: GitTransport + ?Sized>(
    project_root: &Path,
    module: &RemoteModule,
    update: bool,
    cancellation: Option<&TaskCancellation>,
    transport: &T,
) -> Result<PathBuf, RemoteError> {
    ensure_trusted(module)?;
    if matches!(&module.reference, RemoteReference::Tag(_)) {
        return fetch_tag_module(project_root, module, cancellation, transport);
    }
    let RemoteReference::Commit(commit) = &module.reference else {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    };
    let destination = commit_cache_path(project_root, module, commit);
    if destination.exists() {
        if !update {
            return cached_module_with_cancellation(project_root, module, cancellation);
        }
        return verify_immutable_remote(module, &destination, cancellation, transport)
            .and_then(|()| cached_module_with_cancellation(project_root, module, cancellation));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid module cache path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let temporary = tempfile::Builder::new()
        .prefix("neoenv-module-")
        .tempdir_in(parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let source = temporary.path().join("source");
    let commit = git_fetch(module, &source, cancellation, transport)?;
    fs::write(
        temporary.path().join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    // Keep the TempDir guard until after rename. On a failed publication its
    // Drop implementation removes the staged directory; on success the old
    // path is already gone and cleanup is harmless.
    fs::rename(temporary.path(), &destination)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    cached_module_with_cancellation(project_root, module, cancellation)
}

/// Removes the immutable cache entry addressed by one canonical remote source.
///
/// This performs no transport I/O and does not require trust because it cannot
/// read or execute remote content.
///
/// # Errors
///
/// Returns an error when cached provenance is malformed or cache removal fails.
pub fn clear_module_cache(project_root: &Path, module: &RemoteModule) -> Result<bool, RemoteError> {
    let binding_state = if matches!(&module.reference, RemoteReference::Tag(_)) {
        let binding = tag_binding_path(project_root, module);
        let binding_parent = binding
            .parent()
            .ok_or_else(|| RemoteError::Io("invalid module cache path".into()))?;
        fs::create_dir_all(binding_parent)
            .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
        Some(state_file::lock(&binding).map_err(remote_state_error)?)
    } else {
        None
    };
    let commit = match &module.reference {
        RemoteReference::Commit(commit) => Some(commit.clone()),
        RemoteReference::Tag(_) => {
            let state = binding_state
                .as_ref()
                .ok_or_else(|| RemoteError::Io("missing module binding lock".into()))?;
            match state.read_to_string() {
                Ok(metadata) => Some(parse_tag_binding(module, &metadata)?),
                Err(error) if error.is_not_found() => None,
                Err(error) => return Err(remote_state_error(error)),
            }
        }
    };
    let mut removed = false;
    if let Some(commit) = commit {
        let path = commit_cache_path(project_root, module, &commit);
        if path.exists() {
            fs::remove_dir_all(path)
                .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
            removed = true;
        }
    }
    if let Some(state) = binding_state {
        let binding = state.path().to_owned();
        match fs::symlink_metadata(&binding) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(&binding).map_err(|error| {
                    RemoteError::io_source("remote filesystem operation", error)
                })?;
                removed = true;
            }
            Ok(_) => {
                return Err(RemoteError::Io(format!(
                    "refusing to remove unsafe module binding {}",
                    binding.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(RemoteError::io_source("remote filesystem operation", error)),
        }
    }
    Ok(removed)
}

/// Resolves an exact tag during an explicit fetch before reading or publishing cache data.
pub(super) fn fetch_tag_module<T: GitTransport + ?Sized>(
    project_root: &Path,
    module: &RemoteModule,
    cancellation: Option<&TaskCancellation>,
    transport: &T,
) -> Result<PathBuf, RemoteError> {
    let root = modules_root(project_root);
    fs::create_dir_all(&root)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let temporary = tempfile::Builder::new()
        .prefix("neoenv-module-")
        .tempdir_in(&root)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let source = temporary.path().join("source");
    let commit = git_fetch(module, &source, cancellation, transport)?;
    let binding = tag_binding_path(project_root, module);
    let binding_parent = binding
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid module cache path".into()))?;
    fs::create_dir_all(binding_parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    let binding_state = state_file::lock(&binding).map_err(remote_state_error)?;
    match binding_state.read_to_string() {
        Ok(metadata) => {
            if parse_tag_binding(module, &metadata)? != commit {
                return Err(RemoteError::CacheMismatch(module.canonical()));
            }
            return cached_module_for_commit_with_cancellation(
                project_root,
                module,
                &commit,
                cancellation,
            );
        }
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(remote_state_error(error)),
    }

    let destination = commit_cache_path(project_root, module, &commit);
    let parent = destination
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid module cache path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    if destination.exists() {
        cached_module_for_commit_with_cancellation(project_root, module, &commit, cancellation)?;
    } else {
        fs::write(
            temporary.path().join("metadata.toml"),
            metadata_for(&module.repository, &commit),
        )
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
        // Retain the temporary-directory guard through publication so a
        // failed rename cannot strand staged content in the cache parent.
        fs::rename(temporary.path(), &destination)
            .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    }
    binding_state
        .write(tag_metadata_for(module, &commit).as_bytes())
        .map_err(remote_state_error)?;
    cached_module_for_commit_with_cancellation(project_root, module, &commit, cancellation)
}

pub(super) fn verify_immutable_remote<T: GitTransport + ?Sized>(
    module: &RemoteModule,
    destination: &Path,
    cancellation: Option<&TaskCancellation>,
    transport: &T,
) -> Result<(), RemoteError> {
    let temporary = tempfile::tempdir()
        .map_err(|error| RemoteError::io_source("remote filesystem operation", error))?;
    git_fetch(module, temporary.path(), cancellation, transport)?;
    let cached = revision_with_cancellation(destination.join("source"), cancellation)?;
    let fetched = revision_with_cancellation(temporary.path(), cancellation)?;
    if cached == fetched {
        Ok(())
    } else {
        Err(RemoteError::CacheMismatch(module.canonical()))
    }
}

pub(super) fn git_fetch<T: GitTransport + ?Sized>(
    module: &RemoteModule,
    destination: &Path,
    cancellation: Option<&TaskCancellation>,
    transport: &T,
) -> Result<String, RemoteError> {
    run_git(
        &[
            "init",
            destination
                .to_str()
                .ok_or_else(|| RemoteError::Io("non-UTF-8 cache path".into()))?,
        ],
        cancellation,
    )?;
    let reference = match &module.reference {
        RemoteReference::Commit(commit) => commit.clone(),
        RemoteReference::Tag(tag) => format!("refs/tags/{tag}"),
    };
    let url = transport.fetch_url(module);
    run_git_in_with_transport(
        destination,
        &["fetch", "--depth=1", "--no-tags", &url, &reference],
        cancellation,
        transport.file_protocol(),
    )?;
    // Peeling ensures annotated tags are bound to their target commit, not tag objects.
    let resolved = revision_ref(destination, "FETCH_HEAD^{commit}", cancellation)?;
    if matches!(&module.reference, RemoteReference::Commit(commit) if commit != &resolved) {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    run_git_in(
        destination,
        &["checkout", "--detach", "--force", &resolved],
        cancellation,
    )?;
    Ok(resolved)
}

#[cfg(test)]
pub(super) fn revision(path: impl AsRef<Path>) -> Result<String, RemoteError> {
    revision_with_cancellation(path, None)
}

pub(super) fn revision_with_cancellation(
    path: impl AsRef<Path>,
    cancellation: Option<&TaskCancellation>,
) -> Result<String, RemoteError> {
    revision_ref(path, "HEAD", cancellation)
}

/// The largest pinned-tree listing this verifier will read.
const MODULE_TREE_BYTES: u64 = 64 * 1024 * 1024;
/// The most working-tree entries a cache entry may contain.
const MODULE_TREE_ENTRIES: usize = 100_000;

/// Verifies the checkout's bytes and file types directly against the pinned
/// commit tree.
///
/// **No Git command that reads the working tree is used.** `git status`,
/// `git diff`, and `git diff-index` consult the checkout's own index (where
/// `assume-unchanged` and `skip-worktree` live) and apply clean filters
/// declared by `.gitattributes` with drivers from `.git/config`. A substituted
/// script could therefore compare equal to the committed bytes, and a
/// checkout-controlled filter would run *before* trust was decided.
///
/// Instead, `git ls-tree` reads only the immutable commit objects, and every
/// listed blob is compared with the file on disk by recomputing the Git blob
/// object id from the raw bytes: no filters, no index, no external helper.
/// Symlinks are compared by their link target, gitlinks (submodules) are
/// refused because their contents cannot be established, and any untracked or
/// ignored file fails closed. On platforms with an executable bit, `100644` and
/// `100755` are distinguished: flipping a cached file's executable state is a
/// different tree. A cache entry must contain exactly the committed tree,
/// because a command a package runs may name any file in it.
pub(super) fn ensure_clean_worktree(
    path: &Path,
    commit: &str,
    module: &RemoteModule,
    cancellation: Option<&TaskCancellation>,
) -> Result<(), RemoteError> {
    let entries = pinned_tree_entries(path, commit, module, cancellation)?;
    let actual = worktree_leaves(path, module)?;
    let mut expected = std::collections::HashSet::with_capacity(entries.len());
    for entry in &entries {
        verify_tree_entry(path, entry, &actual, module)?;
        expected.insert(entry.path.as_path());
    }
    if actual.keys().any(|leaf| !expected.contains(leaf.as_path())) {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    Ok(())
}

struct PinnedTreeEntry {
    mode: String,
    oid: String,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorktreeLeaf {
    File,
    Symlink,
}

fn pinned_tree_entries(
    path: &Path,
    commit: &str,
    module: &RemoteModule,
    cancellation: Option<&TaskCancellation>,
) -> Result<Vec<PinnedTreeEntry>, RemoteError> {
    let mut command = Command::new("git");
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("--no-replace-objects")
        .args(git_options())
        .arg("-C")
        .arg(path)
        .args(["ls-tree", "-r", "-z", "--full-tree", commit]);
    let policy = GitPolicy::from_environment().map_err(RemoteError::policy_source)?;
    let budget = ResourceBudget {
        git_stdout_bytes: MODULE_TREE_BYTES,
        ..ResourceBudget::default()
    };
    let output =
        run_git_output_with_policy_and_budget(&mut command, policy.timeout, cancellation, budget)?;
    if !output.status.success() {
        return Err(git_failure(
            "read pinned module tree",
            output.status,
            &output.stderr,
        ));
    }
    let mut entries = Vec::new();
    for record in output.stdout.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let entry = parse_tree_entry(record)
            .ok_or_else(|| RemoteError::CacheMismatch(module.canonical()))?;
        entries.push(entry);
        if entries.len() > MODULE_TREE_ENTRIES {
            return Err(RemoteError::CacheMismatch(module.canonical()));
        }
    }
    Ok(entries)
}

/// Parses one `ls-tree -z` record: `<mode> <type> <oid>\t<path>`.
fn parse_tree_entry(record: &[u8]) -> Option<PinnedTreeEntry> {
    let tab = record.iter().position(|byte| *byte == b'\t')?;
    let (metadata, raw_path) = record.split_at(tab);
    let raw_path = raw_path.get(1..)?;
    let mut fields = metadata.split(|byte| *byte == b' ');
    let mode = std::str::from_utf8(fields.next()?).ok()?;
    let kind = fields.next()?;
    let oid = std::str::from_utf8(fields.next()?).ok()?;
    if fields.next().is_some() || kind != b"blob" as &[u8] {
        return None;
    }
    if !matches!(mode, "100644" | "100755" | "120000") {
        return None;
    }
    if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(PinnedTreeEntry {
        mode: mode.to_owned(),
        oid: oid.to_ascii_lowercase(),
        path: tree_relative_path(raw_path)?,
    })
}

/// Converts a normalized Git path to a platform path, refusing anything that
/// could name the repository root or traverse outside it.
fn tree_relative_path(raw: &[u8]) -> Option<PathBuf> {
    if raw.is_empty() || raw.first() == Some(&b'/') {
        return None;
    }
    let mut path = PathBuf::new();
    for component in raw.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return None;
        }
        path.push(tree_path_component(component)?);
    }
    Some(path)
}

#[cfg(unix)]
// The fallible shape is the Windows variant's: Unix path bytes are always
// representable, and callers keep one signature for every platform.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn tree_path_component(bytes: &[u8]) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt as _;
    Some(std::ffi::OsString::from_vec(bytes.to_vec()))
}

#[cfg(not(unix))]
fn tree_path_component(bytes: &[u8]) -> Option<std::ffi::OsString> {
    std::str::from_utf8(bytes)
        .ok()
        .map(std::ffi::OsString::from)
}

/// Every non-directory entry in the checkout, excluding the repository's own
/// `.git` directory. Directories are not recorded: Git does not track them.
fn worktree_leaves(
    root: &Path,
    module: &RemoteModule,
) -> Result<std::collections::HashMap<PathBuf, WorktreeLeaf>, RemoteError> {
    let mut leaves = std::collections::HashMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| RemoteError::io_source("read cached module directory", error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| RemoteError::io_source("read cached module entry", error))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RemoteError::CacheMismatch(module.canonical()))?;
            if relative == Path::new(".git") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                RemoteError::io_source("read cached module entry metadata", error)
            })?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_symlink() {
                leaves.insert(relative.to_owned(), WorktreeLeaf::Symlink);
            } else if file_type.is_file() {
                leaves.insert(relative.to_owned(), WorktreeLeaf::File);
            } else {
                // A socket, FIFO, or device node is not part of any commit.
                return Err(RemoteError::CacheMismatch(module.canonical()));
            }
            if leaves.len() > MODULE_TREE_ENTRIES {
                return Err(RemoteError::CacheMismatch(module.canonical()));
            }
        }
    }
    Ok(leaves)
}

fn verify_tree_entry(
    root: &Path,
    entry: &PinnedTreeEntry,
    actual: &std::collections::HashMap<PathBuf, WorktreeLeaf>,
    module: &RemoteModule,
) -> Result<(), RemoteError> {
    let mismatch = || RemoteError::CacheMismatch(module.canonical());
    let actual_kind = actual.get(&entry.path).copied();
    if entry.mode == "120000" {
        if actual_kind != Some(WorktreeLeaf::Symlink) {
            return Err(mismatch());
        }
        let target = fs::read_link(root.join(&entry.path))
            .map_err(|error| RemoteError::io_source("read cached module symlink", error))?;
        return verify_blob_bytes(&link_target_bytes(&target)?, &entry.oid, module);
    }
    if actual_kind != Some(WorktreeLeaf::File) {
        return Err(mismatch());
    }
    let path = root.join(&entry.path);
    if !executable_matches(&path, &entry.mode)? {
        return Err(mismatch());
    }
    verify_blob_file(&path, &entry.oid, module)
}

/// Whether the on-disk executable bit agrees with the tree mode.
///
/// Git records `100644` or `100755` for a regular file, and the owner
/// executable bit is part of what a package runs: a cached script changed from
/// non-executable to executable (or back) is not the approved tree. Git itself
/// compares only the owner execute bit, so a `0755` file changed to `0655` is
/// a different tree even though other execute bits are still set. Platforms
/// without an executable bit cannot disagree.
#[cfg(unix)]
fn executable_matches(path: &Path, mode: &str) -> Result<bool, RemoteError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RemoteError::io_source("read cached module entry metadata", error))?;
    if !metadata.file_type().is_file() {
        return Ok(false);
    }
    let executable = metadata.permissions().mode() & 0o100 != 0;
    Ok(executable == (mode == "100755"))
}

#[cfg(not(unix))]
fn executable_matches(_path: &Path, _mode: &str) -> Result<bool, RemoteError> {
    Ok(true)
}

fn verify_blob_file(path: &Path, oid: &str, module: &RemoteModule) -> Result<(), RemoteError> {
    let metadata = fs::metadata(path)
        .map_err(|error| RemoteError::io_source("read cached module file metadata", error))?;
    let mut hasher = BlobHasher::new(oid.len(), metadata.len())
        .ok_or_else(|| RemoteError::CacheMismatch(module.canonical()))?;
    let mut file = fs::File::open(path)
        .map_err(|error| RemoteError::io_source("read cached module file", error))?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| RemoteError::io_source("read cached module file", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hasher.hex() == oid {
        Ok(())
    } else {
        Err(RemoteError::CacheMismatch(module.canonical()))
    }
}

fn verify_blob_bytes(bytes: &[u8], oid: &str, module: &RemoteModule) -> Result<(), RemoteError> {
    let mut hasher = BlobHasher::new(oid.len(), bytes.len() as u64)
        .ok_or_else(|| RemoteError::CacheMismatch(module.canonical()))?;
    hasher.update(bytes);
    if hasher.hex() == oid {
        Ok(())
    } else {
        Err(RemoteError::CacheMismatch(module.canonical()))
    }
}

/// Git's blob object id for raw bytes, with the repository's hash algorithm.
enum BlobHasher {
    Sha1(sha1::Sha1),
    Sha256(Sha256),
}

impl BlobHasher {
    fn new(oid_length: usize, size: u64) -> Option<Self> {
        let header = format!("blob {size}\0");
        let mut hasher = match oid_length {
            40 => Self::Sha1(sha1::Sha1::new()),
            64 => Self::Sha256(Sha256::new()),
            _ => return None,
        };
        hasher.update(header.as_bytes());
        Some(hasher)
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hasher) => Digest::update(hasher, bytes),
            Self::Sha256(hasher) => Digest::update(hasher, bytes),
        }
    }

    fn hex(self) -> String {
        match self {
            Self::Sha1(hasher) => format!("{:x}", Digest::finalize(hasher)),
            Self::Sha256(hasher) => format!("{:x}", Digest::finalize(hasher)),
        }
    }
}

#[cfg(unix)]
// The fallible shape is the Windows variant's: Unix link targets are bytes.
#[cfg_attr(unix, allow(clippy::unnecessary_wraps))]
fn link_target_bytes(target: &Path) -> Result<Vec<u8>, RemoteError> {
    use std::os::unix::ffi::OsStrExt as _;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn link_target_bytes(target: &Path) -> Result<Vec<u8>, RemoteError> {
    target
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| RemoteError::Io("cached module symlink target is not UTF-8".into()))
}

pub(super) fn revision_ref(
    path: impl AsRef<Path>,
    reference: &str,
    cancellation: Option<&TaskCancellation>,
) -> Result<String, RemoteError> {
    let mut command = Command::new("git");
    command
        .args(git_options())
        .arg("-C")
        .arg(path.as_ref())
        .args(["rev-parse", reference]);
    let output = run_git_output(&mut command, cancellation)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_ascii_lowercase())
    } else {
        Err(git_failure(
            "resolve fetched module revision",
            output.status,
            &output.stderr,
        ))
    }
}

pub(super) fn modules_root(project_root: &Path) -> PathBuf {
    project_root.join(".neoenv/modules")
}

pub(super) fn commit_cache_path(
    project_root: &Path,
    module: &RemoteModule,
    commit: &str,
) -> PathBuf {
    modules_root(project_root)
        .join("commits")
        .join(format!("{:x}", Sha256::digest(&module.repository)))
        .join(commit)
}

pub(super) fn tag_binding_path(project_root: &Path, module: &RemoteModule) -> PathBuf {
    modules_root(project_root)
        .join("tags")
        .join(format!("{}.toml", module.cache_key()))
}

pub(super) fn tag_binding_commit(
    project_root: &Path,
    module: &RemoteModule,
) -> Result<String, RemoteError> {
    let path = tag_binding_path(project_root, module);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(RemoteError::CacheMismatch(module.canonical()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RemoteError::NotFetched(module.canonical()));
        }
        Err(error) => return Err(RemoteError::io_source("remote filesystem operation", error)),
    }
    let metadata =
        read_text_file(&path, &ResourceBudget::default()).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => RemoteError::NotFetched(module.canonical()),
            std::io::ErrorKind::InvalidData => RemoteError::CacheMismatch(module.canonical()),
            _ => RemoteError::io_source("remote filesystem operation", error),
        })?;
    parse_tag_binding(module, &metadata)
}

pub(super) fn parse_tag_binding(
    module: &RemoteModule,
    metadata: &str,
) -> Result<String, RemoteError> {
    let expected_prefix = format!("canonical = {:?}\ncommit = ", module.canonical());
    let Some(commit) = metadata.strip_prefix(&expected_prefix) else {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    };
    let commit = commit.trim().trim_matches('"');
    if (commit.len() != 40 && commit.len() != 64)
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(RemoteError::CacheMismatch(module.canonical()));
    }
    Ok(commit.to_ascii_lowercase())
}

pub(super) fn metadata_for(repository: &str, commit: &str) -> String {
    format!("repository = {repository:?}\ncommit = {commit:?}\n")
}

pub(super) fn tag_metadata_for(module: &RemoteModule, commit: &str) -> String {
    format!(
        "canonical = {:?}\ncommit = {:?}\n",
        module.canonical(),
        commit
    )
}

pub(super) fn run_git(
    arguments: &[&str],
    cancellation: Option<&TaskCancellation>,
) -> Result<(), RemoteError> {
    run_git_command(
        Command::new("git").args(git_options()).args(arguments),
        cancellation,
    )
}

pub(super) fn run_git_in(
    path: &Path,
    arguments: &[&str],
    cancellation: Option<&TaskCancellation>,
) -> Result<(), RemoteError> {
    run_git_command(
        Command::new("git")
            .args(git_options())
            .arg("-C")
            .arg(path)
            .args(arguments),
        cancellation,
    )
}

pub(super) fn run_git_in_with_transport(
    path: &Path,
    arguments: &[&str],
    cancellation: Option<&TaskCancellation>,
    file_protocol: GitFileProtocol,
) -> Result<(), RemoteError> {
    run_git_command(
        Command::new("git")
            .args(git_options_for_file_protocol(file_protocol))
            .arg("-C")
            .arg(path)
            .args(arguments),
        cancellation,
    )
}

pub(super) fn git_failure(operation: &str, status: ExitStatus, stderr: &[u8]) -> RemoteError {
    RemoteError::git_process(GitFailure {
        operation: operation.to_owned(),
        status,
        stderr: redact_url_secrets(&String::from_utf8_lossy(stderr)),
        source: None,
    })
}

pub(super) fn run_git_command(
    command: &mut Command,
    cancellation: Option<&TaskCancellation>,
) -> Result<(), RemoteError> {
    let output = run_git_output(command, cancellation)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(git_failure("fetch", output.status, &output.stderr))
    }
}

pub(super) fn run_git_output(
    command: &mut Command,
    cancellation: Option<&TaskCancellation>,
) -> Result<std::process::Output, RemoteError> {
    if cancellation.is_some_and(TaskCancellation::is_cancelled) {
        return Err(RemoteError::Cancelled);
    }
    let policy = GitPolicy::from_environment().map_err(RemoteError::policy_source)?;
    run_git_output_with_policy_and_budget(
        command,
        policy.timeout,
        cancellation,
        ResourceBudget::default(),
    )
}

#[cfg(test)]
pub(super) fn run_git_output_with_policy(
    command: &mut Command,
    timeout: Duration,
    cancellation: Option<&TaskCancellation>,
) -> Result<std::process::Output, RemoteError> {
    run_git_output_with_policy_and_budget(command, timeout, cancellation, ResourceBudget::default())
}

pub(super) fn run_git_output_with_policy_and_budget(
    command: &mut Command,
    timeout: Duration,
    cancellation: Option<&TaskCancellation>,
    budget: ResourceBudget,
) -> Result<std::process::Output, RemoteError> {
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        // Inherited `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*` pairs can introduce
        // `url.*.insteadOf` rewrites: a local path would then be fetched from
        // HTTPS or SSH. Drop that channel entirely, along with the legacy
        // `GIT_CONFIG_PARAMETERS` form, and disable non-file protocols below.
        .env("GIT_CONFIG_COUNT", "0")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env("GIT_TERMINAL_PROMPT", "0")
        // A `refs/replace/*` entry in the cache could otherwise substitute the
        // tree an object id names. Every object read in this process must see
        // the real object graph, not the checkout's replacement graph.
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    contain_git_process_tree(command);
    let mut child = command
        .spawn()
        .map_err(|error| RemoteError::io_source("start Git process", error))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = stop_git_process_tree(&mut child);
        return Err(RemoteError::Io("Git stdout pipe was not configured".into()));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = stop_git_process_tree(&mut child);
        return Err(RemoteError::Io("Git stderr pipe was not configured".into()));
    };
    let pipe_failed = Arc::new(AtomicBool::new(false));
    let stdout_failed = Arc::clone(&pipe_failed);
    let stderr_failed = Arc::clone(&pipe_failed);
    let stdout_reader = thread::spawn(move || {
        read_git_pipe(
            stdout,
            budget.git_stdout_bytes,
            ResourceLimit::GitStdout,
            &stdout_failed,
        )
    });
    let stderr_reader = thread::spawn(move || {
        read_git_pipe(
            stderr,
            budget.git_stderr_bytes,
            ResourceLimit::GitStderr,
            &stderr_failed,
        )
    });

    let completion = wait_for_git_output(&mut child, timeout, cancellation, &pipe_failed);
    let stdout = join_git_pipe(stdout_reader, "stdout");
    let stderr = join_git_pipe(stderr_reader, "stderr");
    let stdout = stdout?;
    let stderr = stderr?;
    match completion {
        Ok(status) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        Err(StopError::Cancelled { stop_error }) => {
            if let Some(error) = stop_error {
                return Err(RemoteError::Git(format!(
                    "failed to stop git process tree: {error}"
                )));
            }
            Err(RemoteError::Cancelled)
        }
        Err(StopError::TimedOut {
            stop_error,
            timeout,
        }) => {
            if let Some(error) = stop_error {
                return Err(RemoteError::Git(format!(
                    "failed to stop git process tree: {error}"
                )));
            }
            let context = format!("git command timed out after {} seconds", timeout.as_secs());
            Err(RemoteError::Git(context))
        }
        Err(StopError::PipeFailure) => {
            Err(RemoteError::Git("Git output pipe reader failed".to_owned()))
        }
        Err(StopError::Wait(error)) => Err(RemoteError::Git(error)),
    }
}

pub(super) fn read_git_pipe(
    mut pipe: impl Read,
    limit: u64,
    resource: ResourceLimit,
    failed: &AtomicBool,
) -> Result<Vec<u8>, RemoteError> {
    let mut reader = BudgetReader::new(&mut pipe, resource, limit);
    let mut output = Vec::with_capacity(limit.min(8192) as usize);
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(error) => {
                failed.store(true, Ordering::Release);
                return Err(RemoteError::io_source(
                    format!("read Git {} (limit {limit})", resource.name()),
                    error,
                ));
            }
        }
    }
}

pub(super) fn join_git_pipe(
    reader: thread::JoinHandle<Result<Vec<u8>, RemoteError>>,
    stream: &str,
) -> Result<Vec<u8>, RemoteError> {
    reader
        .join()
        .map_err(|_| RemoteError::Io(format!("Git {stream} reader panicked")))?
}

pub(super) enum StopError {
    Cancelled {
        stop_error: Option<String>,
    },
    TimedOut {
        stop_error: Option<String>,
        timeout: Duration,
    },
    PipeFailure,
    Wait(String),
}

pub(super) fn wait_for_git_output(
    child: &mut std::process::Child,
    timeout: Duration,
    cancellation: Option<&TaskCancellation>,
    pipe_failed: &AtomicBool,
) -> Result<std::process::ExitStatus, StopError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if pipe_failed.load(Ordering::Acquire) => {
                let _ = stop_git_process_tree(child);
                return Err(StopError::PipeFailure);
            }
            Ok(None) if cancellation.is_some_and(TaskCancellation::is_cancelled) => {
                let stop_error = stop_git_process_tree(child);
                return Err(StopError::Cancelled { stop_error });
            }
            Ok(None) if started.elapsed() >= timeout => {
                let stop_error = stop_git_process_tree(child);
                return Err(StopError::TimedOut {
                    stop_error,
                    timeout,
                });
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let stop_error = stop_git_process_tree(child);
                let message = if let Some(stop_error) = stop_error {
                    format!("failed to wait for git: {error}; cleanup failed: {stop_error}")
                } else {
                    format!("failed to wait for git: {error}")
                };
                return Err(StopError::Wait(message));
            }
        }
    }
}

pub(super) fn stop_git_process_tree(child: &mut std::process::Child) -> Option<String> {
    let stop_error = kill_git_process_tree(child).err();
    let reap_error = child
        .wait()
        .err()
        .map(|error| format!("failed to reap git process tree: {error}"));
    stop_error.or(reap_error)
}

#[cfg(unix)]
pub(super) fn contain_git_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
pub(super) fn contain_git_process_tree(_command: &mut Command) {}

#[cfg(unix)]
pub(super) fn kill_git_process_tree(child: &mut std::process::Child) -> Result<(), String> {
    use nix::{
        errno::Errno,
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    let process_group =
        i32::try_from(child.id()).map_err(|_| "process ID is out of range".to_owned())?;
    match kill(Pid::from_raw(-process_group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => {
            let _ = child.kill();
            Err(error.to_string())
        }
    }
}

#[cfg(windows)]
pub(super) fn kill_git_process_tree(child: &mut std::process::Child) -> Result<(), String> {
    let process_id = child.id().to_string();
    let status = Command::new("taskkill")
        .arg("/PID")
        .arg(&process_id)
        .arg("/T")
        .arg("/F")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            let _ = child.kill();
            error.to_string()
        })?;
    if !status.success()
        && child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_none()
    {
        let _ = child.kill();
        return Err("taskkill did not stop the process tree".into());
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
pub(super) fn kill_git_process_tree(child: &mut std::process::Child) -> Result<(), String> {
    child.kill().map_err(|error| error.to_string())
}

#[cfg(test)]
pub(super) const GIT_STDERR_LIMIT_BYTES: usize = 8 * 1024;

#[cfg(test)]
pub(super) fn format_git_failure(context: &str, stderr: &[u8]) -> String {
    let redacted = redact_url_secrets(String::from_utf8_lossy(stderr).trim());
    if redacted.is_empty() {
        return context.into();
    }
    let mut end = redacted.len().min(GIT_STDERR_LIMIT_BYTES);
    while !redacted.is_char_boundary(end) {
        end -= 1;
    }
    if end == redacted.len() {
        format!("{context}: {redacted}")
    } else {
        format!("{context}: {}… [truncated]", &redacted[..end])
    }
}

pub(super) fn git_options() -> [&'static str; 14] {
    git_options_for_file_protocol(GitFileProtocol::Deny)
}

/// Git options for every child process.
///
/// Protocol policy is explicit: `protocol.allow=never` denies every scheme and
/// the per-protocol entries name the ones this build could otherwise reach.
/// Only a local fetch flips `file` to `always`; HTTPS, SSH, `git://`, and
/// `ext::` stay denied for every fetch, so a rewritten URL cannot reach a
/// network or run an external transport helper.
pub(super) fn git_options_for_file_protocol(file_protocol: GitFileProtocol) -> [&'static str; 14] {
    [
        "-c",
        "protocol.allow=never",
        "-c",
        match file_protocol {
            GitFileProtocol::Deny => "protocol.file.allow=never",
            GitFileProtocol::Allow => "protocol.file.allow=always",
        },
        "-c",
        "protocol.https.allow=never",
        "-c",
        "protocol.ssh.allow=never",
        "-c",
        "protocol.git.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
    ]
}
