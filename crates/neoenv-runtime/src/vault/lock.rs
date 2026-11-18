//! Cooperative cross-process locking for vault mutations.
//!
//! **This is a lock among cooperating `neoenv` processes, not an atomic
//! guarantee against other applications.** The user explicitly accepts that
//! limitation for `ensure` and `set`.
//!
//! Every mutation takes a fixed global lock first, then a resource lock named by
//! a hash of the canonical resource identity. The global lock is what makes
//! nested bootstrap safe: two processes cannot hold resource locks in opposite
//! orders because only one of them can hold the global lock. Nested calls on the
//! same thread reuse the already-held lock.
//!
//! Lock files contain no secret: the resource identity is hashed, and the lock
//! root is under nenv's state directory.

use std::{
    cell::Cell,
    fs::File,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
    thread,
    time::Duration,
};

use fs4::FileExt;
use neoenv_core::DiagnosticCategory;
use sha2::{Digest, Sha256};

use super::VaultError;

const LOCK_ATTEMPTS: usize = 3_000;

/// The default nenv-owned lock root.
#[cfg(not(test))]
pub(super) fn default_lock_root() -> Option<PathBuf> {
    crate::paths::neoenv_directory(crate::paths::UserDirectory::State)
        .map(|root| root.join("locks").join("vault"))
}

/// Unit tests must not create lock files in the user's real state directory.
#[cfg(test)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the test and production signatures differ only because tests always have a temp root"
)]
pub(super) fn default_lock_root() -> Option<PathBuf> {
    Some(
        std::env::temp_dir()
            .join("neoenv-vault-locks")
            .join(std::process::id().to_string()),
    )
}
const LOCK_RETRY: Duration = Duration::from_millis(10);

static PROCESS_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

thread_local! {
    static LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

struct DepthGuard;

impl DepthGuard {
    fn enter() -> Self {
        LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Runs `operation` while holding the cooperative vault mutation locks.
///
/// `resource` is the canonical resource identity. It is hashed, never written
/// into a filename. `lock_root` is created if absent.
pub(super) fn with_mutation_lock<T>(
    lock_root: &Path,
    resource: &[u8],
    operation: impl FnOnce() -> Result<T, VaultError>,
) -> Result<T, VaultError> {
    if LOCK_DEPTH.with(Cell::get) > 0 {
        // Reentrant on one thread: the global cross-process lock is already held,
        // so a nested KeePass/age/OS bootstrap cannot deadlock against itself.
        return operation();
    }

    let process = PROCESS_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let mut guard = None;
    for attempt in 0..LOCK_ATTEMPTS {
        match process.try_lock() {
            Ok(acquired) => {
                guard = Some(acquired);
                break;
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(lock_error("process lock was poisoned"));
            }
            Err(std::sync::TryLockError::WouldBlock) if attempt + 1 < LOCK_ATTEMPTS => {
                thread::sleep(LOCK_RETRY);
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }
    let _process_guard = guard.ok_or_else(|| lock_error("timed out waiting for the vault lock"))?;
    let _depth = DepthGuard::enter();

    let lock_dir = prepare_lock_root(lock_root)?;
    let global = open_lock(&lock_dir, "global.lock")?;
    acquire(&global)?;

    let digest = hash_resource(resource);
    let resource_file = open_lock(&lock_dir, &format!("{digest}.lock"))?;
    acquire(&resource_file)?;

    operation()
}

#[cfg(unix)]
fn prepare_lock_root(root: &Path) -> Result<File, VaultError> {
    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::{Mode, fstat, mkdirat},
    };

    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| lock_error("cannot resolve vault lock directory"))?
            .join(root)
    };
    let mut current = File::from(
        open(
            "/",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| lock_error("cannot open vault lock directory root"))?,
    );
    let uid = nix::unistd::Uid::effective().as_raw();
    let component_count = absolute
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    let mut seen = 0usize;
    for component in absolute.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        seen += 1;
        let name = name
            .to_str()
            .ok_or_else(|| lock_error("invalid vault lock directory"))?;
        let fd = match openat(
            &current,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => {
                match mkdirat(&current, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(nix::errno::Errno::EEXIST) => {
                        // Another process may have created this exact component
                        // after our ENOENT. Re-open it relative to the pinned
                        // parent with NOFOLLOW, then validate ownership and
                        // permissions below; never accept EEXIST by itself.
                    }
                    Err(_) => return Err(lock_error("cannot create vault lock directory")),
                }
                openat(
                    &current,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| lock_error("cannot safely open vault lock directory"))?
            }
            Err(_) => return Err(lock_error("cannot safely open vault lock directory")),
        };
        let metadata = fstat(&fd).map_err(|_| lock_error("cannot inspect vault lock directory"))?;
        let is_final = seen == component_count;
        if metadata.st_uid != uid && metadata.st_uid != 0 {
            return Err(lock_error("vault lock path has an untrusted owner"));
        }
        if is_final {
            if metadata.st_uid != uid || metadata.st_mode & 0o077 != 0 {
                return Err(lock_error(
                    "vault lock directory must be owned by the current user and private",
                ));
            }
        } else if metadata.st_mode & 0o022 != 0
            && !(metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0)
        {
            return Err(lock_error("vault lock path traverses a writable directory"));
        }
        current = File::from(fd);
    }
    Ok(current)
}

#[cfg(not(unix))]
fn prepare_lock_root(_root: &Path) -> Result<File, VaultError> {
    Err(lock_error(
        "safe vault locks are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn open_lock(directory: &File, name: &str) -> Result<File, VaultError> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::{Mode, fstat},
    };
    let fd = openat(
        directory,
        name,
        OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| lock_error("cannot safely open vault lock file"))?;
    let metadata = fstat(&fd).map_err(|_| lock_error("cannot inspect vault lock file"))?;
    if metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG
        || metadata.st_uid != nix::unistd::Uid::effective().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(lock_error(
            "vault lock file must be owned by the current user and private",
        ));
    }
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_lock(_directory: &File, _name: &str) -> Result<File, VaultError> {
    Err(lock_error(
        "safe vault locks are unsupported on this platform",
    ))
}

fn acquire(file: &File) -> Result<(), VaultError> {
    for attempt in 0..LOCK_ATTEMPTS {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(fs4::TryLockError::WouldBlock) => {
                if attempt + 1 < LOCK_ATTEMPTS {
                    thread::sleep(LOCK_RETRY);
                }
            }
            Err(fs4::TryLockError::Error(_)) => {
                return Err(lock_error("cannot acquire vault lock"));
            }
        }
    }
    Err(lock_error("timed out waiting for the vault lock"))
}

fn hash_resource(resource: &[u8]) -> String {
    format!("{:x}", Sha256::digest(resource))
}

fn lock_error(message: &'static str) -> VaultError {
    VaultError::new("NEO712", DiagnosticCategory::Runtime, message)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::with_mutation_lock;

    #[test]
    fn lock_files_are_hashed_and_named_by_resource_identity() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("locks");
        with_mutation_lock(&root, b"service-secret\0account-secret", || Ok(())).expect("lock");
        let names: Vec<String> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name == "global.lock"));
        assert!(names.iter().all(|name| !name.contains("service-secret")));
        assert!(names.iter().all(|name| !name.contains("account-secret")));
        assert!(
            names
                .iter()
                .filter(|name| name.as_str() != "global.lock")
                .all(|name| name.len() == 64 + ".lock".len()
                    && std::path::Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext == "lock"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_permissive_lock_root() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("locks");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(with_mutation_lock(&root, b"resource", || Ok(())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_lock_file_without_opening_its_target() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("locks");
        fs::create_dir(&root).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, root.join("global.lock")).unwrap();
        assert!(with_mutation_lock(&root, b"resource", || Ok(())).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_in_the_lock_root_path() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(with_mutation_lock(&link.join("locks"), b"resource", || Ok(())).is_err());
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
    }
}
