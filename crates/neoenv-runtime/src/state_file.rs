//! Locked, durable, and replace-safe writes for `nenv` state files.
//!
//! Every mutable `nenv` state file goes through this module.  A state write is
//! prepared in an unpredictable file in the destination directory, synced, and
//! then published with replacement semantics.  A coordination lock is
//! deliberately separate from the state file: replacing the state inode must
//! not release a lock held by another writer.

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use fs4::FileExt;
use tempfile::Builder as TempFileBuilder;

use crate::budget::{ResourceBudget, read_file_bytes, read_text_file};

/// An I/O or path-safety failure while accessing a state file.
#[derive(Debug)]
pub enum StateFileError {
    /// The destination has no usable parent directory.
    Parent { path: PathBuf },
    /// The destination or its lock path could not be inspected.
    Inspect { path: PathBuf, source: io::Error },
    /// The destination (or its coordination file) is not a regular file.
    UnsafePath { path: PathBuf, detail: &'static str },
    /// The cross-process writer lock could not be opened or acquired.
    Lock { path: PathBuf, source: io::Error },
    /// The same-directory temporary file could not be created.
    CreateTemporary { path: PathBuf, source: io::Error },
    /// The temporary file could not be written, permissioned, or synced.
    WriteTemporary { path: PathBuf, source: io::Error },
    /// The prepared file could not be published at the destination.
    Publish { path: PathBuf, source: io::Error },
    /// The existing state file could not be read.
    Read { path: PathBuf, source: io::Error },
}

impl StateFileError {
    /// Returns the state path associated with this error.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Parent { path }
            | Self::Inspect { path, .. }
            | Self::UnsafePath { path, .. }
            | Self::Lock { path, .. }
            | Self::CreateTemporary { path, .. }
            | Self::WriteTemporary { path, .. }
            | Self::Publish { path, .. }
            | Self::Read { path, .. } => path,
        }
    }

    /// Returns the underlying I/O error, when this failure has one.
    #[must_use]
    pub fn io_error(&self) -> Option<&io::Error> {
        match self {
            Self::Inspect { source, .. }
            | Self::Lock { source, .. }
            | Self::CreateTemporary { source, .. }
            | Self::WriteTemporary { source, .. }
            | Self::Publish { source, .. }
            | Self::Read { source, .. } => Some(source),
            Self::Parent { .. } | Self::UnsafePath { .. } => None,
        }
    }

    /// Returns whether the state file did not exist.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        self.io_error()
            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
    }
}

impl fmt::Display for StateFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent { path } => {
                write!(
                    formatter,
                    "cannot determine parent directory for {}",
                    path.display()
                )
            }
            Self::Inspect { path, source } => {
                write!(formatter, "cannot inspect {}: {source}", path.display())
            }
            Self::UnsafePath { path, detail } => {
                write!(
                    formatter,
                    "refusing to replace unsafe state path {}: {detail}",
                    path.display()
                )
            }
            Self::Lock { path, source } => {
                write!(
                    formatter,
                    "failed to lock state file {}: {source}",
                    path.display()
                )
            }
            Self::CreateTemporary { path, source } => write!(
                formatter,
                "failed to create temporary state file for {}: {source}",
                path.display()
            ),
            Self::WriteTemporary { path, source } => write!(
                formatter,
                "failed to write temporary state file for {}: {source}",
                path.display()
            ),
            Self::Publish { path, source } => {
                write!(
                    formatter,
                    "failed to publish state file {}: {source}",
                    path.display()
                )
            }
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "failed to read state file {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for StateFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io_error()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// A state file whose cross-process lock is held by this value.
///
/// The lock is advisory on Unix and a Windows file lock.  `fs4` releases it
/// when the file handle is dropped, including when a process exits, so a
/// crashed writer cannot leave a permanently locked state file behind.
pub struct LockedStateFile {
    path: PathBuf,
    parent: PathBuf,
    _lock: File,
}

impl LockedStateFile {
    /// Returns the destination path protected by this lock.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the current state while retaining the writer lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination is unsafe, missing, or unreadable.
    pub fn read(&self) -> Result<Vec<u8>, StateFileError> {
        self.validate_destination()?;
        read_file_bytes(&self.path, &ResourceBudget::default()).map_err(|source| {
            StateFileError::Read {
                path: self.path.clone(),
                source,
            }
        })
    }

    /// Reads the current state as UTF-8 while retaining the writer lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination is unsafe, missing, or not UTF-8.
    pub fn read_to_string(&self) -> Result<String, StateFileError> {
        self.validate_destination()?;
        read_text_file(&self.path, &ResourceBudget::default()).map_err(|source| {
            StateFileError::Read {
                path: self.path.clone(),
                source,
            }
        })
    }

    /// Atomically replaces the destination while retaining the writer lock.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the previous destination if any
    /// preparation or publication step fails.
    pub fn write(&self, contents: &[u8]) -> Result<(), StateFileError> {
        let limits = ResourceBudget::default();
        if u64::try_from(contents.len()).unwrap_or(u64::MAX) > limits.metadata_bytes {
            return Err(StateFileError::WriteTemporary {
                path: self.path.clone(),
                source: io::Error::other(crate::budget::ResourceLimitError::new(
                    crate::budget::ResourceLimit::Metadata,
                    limits.metadata_bytes,
                )),
            });
        }
        self.write_contents(contents, PublishFault::None)
    }

    fn validate_destination(&self) -> Result<Option<Permissions>, StateFileError> {
        validate_regular_destination(&self.path)
    }

    fn write_contents(&self, contents: &[u8], fault: PublishFault) -> Result<(), StateFileError> {
        let original_permissions = self.validate_destination()?;
        // `tempfile` uses create_new when opening this file and obtains a
        // cryptographically unpredictable name from the platform CSPRNG.  The
        // file is in the destination directory, so publication never crosses a
        // filesystem boundary.
        let mut temporary = TempFileBuilder::new()
            .prefix(neoenv_core::names::STATE_TEMPORARY_PREFIX)
            .suffix(".tmp")
            .tempfile_in(&self.parent)
            .map_err(|source| StateFileError::CreateTemporary {
                path: self.path.clone(),
                source,
            })?;

        if let Some(permissions) = original_permissions.as_ref() {
            temporary
                .as_file()
                .set_permissions(permissions.clone())
                .map_err(|source| StateFileError::WriteTemporary {
                    path: self.path.clone(),
                    source,
                })?;
        }

        temporary
            .write_all(contents)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|source| StateFileError::WriteTemporary {
                path: self.path.clone(),
                source,
            })?;

        // Recheck immediately before publication.  This closes the ordinary
        // check/use window for a destination replaced by another process; the
        // atomic publish itself still never follows a destination symlink.
        let current_permissions = self.validate_destination()?;
        if let Some(permissions) = current_permissions
            .as_ref()
            .or(original_permissions.as_ref())
        {
            temporary
                .as_file()
                .set_permissions(permissions.clone())
                .map_err(|source| StateFileError::WriteTemporary {
                    path: self.path.clone(),
                    source,
                })?;
            temporary
                .as_file()
                .sync_all()
                .map_err(|source| StateFileError::WriteTemporary {
                    path: self.path.clone(),
                    source,
                })?;
        }

        if fault == PublishFault::BeforePublish {
            return Err(StateFileError::Publish {
                path: self.path.clone(),
                source: io::Error::other("injected publish fault"),
            });
        }
        #[cfg(test)]
        exit_injected_publish();

        temporary.persist(&self.path).map_err(|error| {
            // Dropping `error.file` here removes the prepared file.  The old
            // destination has not been touched when replacement fails.
            StateFileError::Publish {
                path: self.path.clone(),
                source: error.error,
            }
        })?;
        sync_parent(&self.parent);
        Ok(())
    }
}

/// Acquires the cross-process lock for one state path.
///
/// The parent directory must already exist.  The fixed-name coordination file
/// lives beside the state file, so all writers using the same destination share
/// one lock even when their temporary directories differ.  The lock file is
/// retained after unlock: removing it would let a waiter acquire a new inode
/// while another writer still owns the old one.
///
/// # Errors
///
/// Returns an error when the path is unsafe, the lock cannot be opened, or
/// the destination is a symlink or non-regular file.
pub fn lock(path: &Path) -> Result<LockedStateFile, StateFileError> {
    let parent = parent_directory(path)?;
    let lock_path = coordination_lock_path(path)?;
    validate_lock_path(&lock_path)?;

    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|source| StateFileError::Lock {
            path: lock_path.clone(),
            source,
        })?;
    FileExt::lock(&lock_file).map_err(|source| StateFileError::Lock {
        path: lock_path.clone(),
        source,
    })?;

    let state = LockedStateFile {
        path: path.to_owned(),
        parent,
        _lock: lock_file,
    };
    state.validate_destination()?;
    Ok(state)
}

/// Writes one complete state document using the shared lock and atomic publish
/// implementation.
///
/// Callers that perform a read/modify/write operation must hold the guard from
/// [`lock`] while both reading and calling [`LockedStateFile::write`]. This is
/// the contract for future capability-document writers as well as the current
/// configuration and trust writers.
///
/// # Errors
///
/// Returns a [`StateFileError`] without replacing the previous destination on
/// any preparation or publication failure.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), StateFileError> {
    let state = lock(path)?;
    state.write(contents)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishFault {
    None,
    BeforePublish,
}

fn parent_directory(path: &Path) -> Result<PathBuf, StateFileError> {
    let parent = path.parent().ok_or_else(|| StateFileError::Parent {
        path: path.to_owned(),
    })?;
    if parent.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(parent.to_owned())
    }
}

fn coordination_lock_path(path: &Path) -> Result<PathBuf, StateFileError> {
    let parent = parent_directory(path)?;
    let file_name = path.file_name().ok_or_else(|| StateFileError::Parent {
        path: path.to_owned(),
    })?;
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(".neoenv-state.lock");
    Ok(parent.join(name))
}

fn validate_lock_path(path: &Path) -> Result<(), StateFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(StateFileError::UnsafePath {
                path: path.to_owned(),
                detail: "lock path is not a regular file",
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StateFileError::Inspect {
            path: path.to_owned(),
            source,
        }),
    }
}

fn validate_regular_destination(path: &Path) -> Result<Option<Permissions>, StateFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(StateFileError::UnsafePath {
                path: path.to_owned(),
                detail: "destination is not a regular file",
            })
        }
        Ok(metadata) => Ok(Some(metadata.permissions())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StateFileError::Inspect {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) {
    // Directory fsync is not available on every Unix filesystem.  The state
    // file itself is always synced; a best-effort directory sync upgrades the
    // common case without making otherwise valid writes fail on such a FS.
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) {}

#[cfg(test)]
fn exit_injected_publish() {
    if std::env::var_os("NEOENV_TEST_EXIT_DURING_STATE_PUBLISH").is_some() {
        std::process::exit(86);
    }
}

#[cfg(test)]
fn write_atomic_with_fault(
    path: &Path,
    contents: &[u8],
    fault: PublishFault,
) -> Result<(), StateFileError> {
    let state = lock(path)?;
    state.write_contents(contents, fault)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        process::Command,
        sync::{Arc, Barrier},
        thread,
    };

    use neoenv_policy::{Capability, CapabilityGrants};

    use super::{
        PublishFault, StateFileError, coordination_lock_path, lock, write_atomic,
        write_atomic_with_fault,
    };
    use crate::policy::load_capability_grants;

    #[test]
    fn replaces_regular_state_and_leaves_no_prepared_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::write(&path, "old\n").unwrap();

        let lock_path = coordination_lock_path(&path).unwrap();
        write_atomic(&path, b"new\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
        assert!(lock_path.is_file());
        assert!(
            !fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoenv-state-"))
        );
    }

    #[test]
    fn coordination_lock_is_beside_state_and_survives_publish() {
        let current_directory = std::env::current_dir().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("neoenv-state-lock-test-")
            .tempdir_in(&current_directory)
            .unwrap();
        let path = directory.path().join("state.toml");
        let lock_path = coordination_lock_path(&path).unwrap();

        // The lock lands **beside the state file**, which is the whole property. The
        // fixture is created with `tempdir_in(&current_directory)` rather than
        // `tempdir()` precisely so that is true, and the `assert_eq!` below proves it
        // -- and proves it *better* than the assertion that used to follow it, since
        // that one would still have passed if `coordination_lock_path` had been changed
        // to use `env::temp_dir()`.
        //
        // A second assertion used to follow, that the path was not under
        // `std::env::temp_dir()` -- and its truth value is a function of the ambient
        // environment rather than of the code. Measured:
        //
        //   TMPDIR=/tmp,          cwd=/home/atticus/...  -> assertion holds
        //   TMPDIR=/home/atticus, cwd=/home/atticus/...  -> assertion fails
        //   TMPDIR=/tmp,          cwd=/tmp                -> assertion fails
        //
        // So the trigger is not "the repo is under `$TMPDIR`" but **`TMPDIR` is any
        // ancestor of the checkout**, which is a wider blast radius than it looks: set
        // `TMPDIR` to the checkout's own parent and it fails with the repo exactly
        // where it is today. It is not a Linux/macOS/Windows axis, so the cross-platform
        // gate never saw it, and this project's own workflow uses `/tmp` worktrees.
        //
        // **The general shape: a test assertion that reads ambient process state.**
        // For any of them, ask "would this still hold if the repo were cloned into
        // `/tmp`, with `TMPDIR` pointing at something else?" -- CI does both.
        assert_eq!(lock_path.parent(), path.parent());
        write_atomic(&path, b"published\n").unwrap();
        assert!(lock_path.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_coordination_path() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        let lock_path = coordination_lock_path(&path).unwrap();
        let target = directory.path().join("outside.lock");
        fs::write(&target, "keep\n").unwrap();
        symlink(&target, &lock_path).unwrap();

        let error = write_atomic(&path, b"replace\n").unwrap_err();

        assert!(matches!(error, StateFileError::UnsafePath { .. }));
        assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_destination_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("outside.toml");
        let path = directory.path().join("state.toml");
        fs::write(&target, "keep\n").unwrap();
        symlink(&target, &path).unwrap();

        let error = write_atomic(&path, b"replace\n").unwrap_err();

        assert!(matches!(error, StateFileError::UnsafePath { .. }));
        assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
    }

    #[test]
    fn refuses_non_regular_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::create_dir(&path).unwrap();

        let error = write_atomic(&path, b"replace\n").unwrap_err();

        assert!(matches!(error, StateFileError::UnsafePath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        write_atomic(&path, b"new\n").unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn process_exit_during_publish_child() {
        let Some(path) = std::env::var_os("NEOENV_TEST_EXIT_DURING_STATE_PUBLISH_PATH") else {
            return;
        };
        let _ = write_atomic(Path::new(&path), b"new contents\n");
        panic!("the injected publish exit did not fire");
    }

    #[test]
    fn process_exit_during_publish_preserves_previous_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::write(&path, "old valid contents\n").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state_file::tests::process_exit_during_publish_child",
            ])
            .env("NEOENV_TEST_EXIT_DURING_STATE_PUBLISH", "1")
            .env("NEOENV_TEST_EXIT_DURING_STATE_PUBLISH_PATH", &path)
            .status()
            .unwrap();

        assert!(!status.success());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old valid contents\n");
        write_atomic(&path, b"after restart\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "after restart\n");
    }

    #[cfg(unix)]
    #[test]
    fn injected_publish_fault_preserves_permissions_and_previous_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::write(&path, "old valid contents\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        let error = write_atomic_with_fault(&path, b"new contents\n", PublishFault::BeforePublish)
            .unwrap_err();

        assert!(matches!(error, StateFileError::Publish { .. }));
        assert_eq!(fs::read_to_string(&path).unwrap(), "old valid contents\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn injected_publish_fault_preserves_the_previous_valid_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.toml");
        fs::write(&path, "old valid contents\n").unwrap();

        let error = write_atomic_with_fault(&path, b"new contents\n", PublishFault::BeforePublish)
            .unwrap_err();

        assert!(matches!(error, StateFileError::Publish { .. }));
        assert_eq!(fs::read_to_string(&path).unwrap(), "old valid contents\n");
    }

    #[test]
    fn twenty_concurrent_writers_serialize_without_losing_updates() {
        const WRITERS: usize = 20;

        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().join("state.toml"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut workers = Vec::with_capacity(WRITERS);
        for index in 0..WRITERS {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let state = lock(&path).unwrap();
                let mut contents = match state.read_to_string() {
                    Ok(contents) => contents,
                    Err(error) if error.is_not_found() => String::new(),
                    Err(error) => panic!("read failed: {error}"),
                };
                contents.push_str("writer-");
                contents.push_str(&index.to_string());
                contents.push('\n');
                state.write(contents.as_bytes()).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let contents = fs::read_to_string(path.as_ref()).unwrap();
        assert_eq!(contents.lines().count(), WRITERS);
        for index in 0..WRITERS {
            assert!(contents.contains(&format!("writer-{index}")));
        }
    }

    #[test]
    fn capability_documents_remain_read_only_inputs_but_future_writers_use_this_contract() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capabilities.toml");
        let grants = CapabilityGrants::default();
        let document = grants.to_toml().unwrap();

        write_atomic(&path, document.as_bytes()).unwrap();

        let loaded = load_capability_grants(&path).unwrap();
        assert!(!loaded.authorizes(Capability::Execute, "project:example"));
    }
}
