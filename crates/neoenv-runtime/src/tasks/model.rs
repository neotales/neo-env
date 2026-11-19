//! Task run options, environment, cancellation, and the run report types
//! returned to callers.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskRunReport {
    pub context: String,
    pub tasks: Vec<TaskRunResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskRunResult {
    pub name: String,
    pub outcome: TaskOutcome,
    pub exit_code: Option<i32>,
    pub message: Option<String>,
    pub package: Option<TaskPackageIdentity>,
    pub dependencies: Vec<neoenv_core::tasks::TaskDependencyEdge>,
    pub before_hooks: Vec<neoenv_core::tasks::TaskDependencyEdge>,
    pub after_hooks: Vec<neoenv_core::tasks::TaskDependencyEdge>,
}

#[derive(Clone, Debug)]
pub enum TaskRunError {
    Planning(String),
    /// A planning/parser failure with its original typed source retained.
    PlanningSource {
        message: String,
        source: Arc<TaskError>,
    },
    /// A filesystem failure encountered while preparing a task run.
    IoSource {
        operation: String,
        source: Arc<io::Error>,
    },
    InvalidCapability {
        task: String,
        capability: String,
        package: Option<Box<TaskPackageIdentity>>,
    },
    CapabilityDenied {
        task: String,
        capability: Capability,
        subject: String,
        package: Option<Box<TaskPackageIdentity>>,
        policy_source: Option<PathBuf>,
    },
}

/// Resolved environment inputs for one isolated task run.
#[derive(Clone, Copy)]
pub struct TaskEnvironment<'a> {
    pub values: &'a IndexMap<String, String>,
    pub path_operations: &'a [PathOperation],
    /// Values applied *after* `path_operations` and tool activation.
    ///
    /// This is where a command-line `--env KEY=VALUE` belongs. `values` is the
    /// base that declared `PATH` prepending then modifies, so an override placed
    /// there could not win against it; putting overrides here makes
    /// `--env PATH=...` the last word, which is the usual reason to type it.
    pub overrides: Option<&'a IndexMap<String, String>>,
}

/// A handle callers can use to stop a running task graph.
#[derive(Clone, Default)]
pub struct TaskCancellation {
    flag: Arc<AtomicBool>,
    parents: Vec<Arc<AtomicBool>>,
    deadline: Option<std::time::Instant>,
}

impl TaskCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a cancellation handle backed by a process-wide signal flag.
    ///
    /// This lets an application install one Ctrl-C handler while sharing the
    /// same signal between task execution and another supervised operation.
    #[must_use]
    pub fn from_shared(flag: Arc<AtomicBool>) -> Self {
        Self {
            flag,
            parents: Vec::new(),
            deadline: None,
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
            || self.parents.iter().any(|flag| flag.load(Ordering::Acquire))
            || self.timed_out()
    }

    pub(super) fn child(&self) -> Self {
        let mut parents = self.parents.clone();
        parents.push(self.flag.clone());
        Self {
            flag: Arc::default(),
            parents,
            deadline: self.deadline,
        }
    }

    pub(super) fn with_timeout(&self, timeout: Option<Duration>) -> Result<Self, String> {
        let mut child = self.child();
        if let Some(timeout) = timeout {
            let deadline = std::time::Instant::now()
                .checked_add(timeout)
                .ok_or("job timeout is out of range")?;
            child.deadline = Some(
                child
                    .deadline
                    .map_or(deadline, |parent| parent.min(deadline)),
            );
        }
        Ok(child)
    }

    pub(super) fn timed_out(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

/// An explicit host cooperation contract, not a
/// kernel-enforced capability. A host violating it can invalidate child
/// identity before a supervisor has sent its pidfd. On Windows, the current
/// executable must have a trusted matching-version `neoenv-windows-launcher.exe`
/// in its resolved install directory. The directory is a trust boundary, not a
/// signature check. Overlapped pipes use cancellable writes; synchronous pipes
/// and synchronous disk files use job-owned forwarding processes. Character
/// output uses synchronous calls of at most 4 KiB, with cancellation checked
/// between calls. Event signalling waits for an admitted call to return, and
/// the gate prevents any new call after signalling. A call in progress cannot
/// be bounded or interrupted; cleanup reports failure if signalling or writer
/// joining misses its deadline.
#[derive(Clone, Copy)]
pub struct CooperativeOwnedBackend<'a> {
    executable: &'a Path,
}

impl<'a> CooperativeOwnedBackend<'a> {
    /// Opt in to owned supervisors under an exclusive child-wait policy.
    ///
    /// The host must establish a waitable `SIGCHLD` disposition and guarantee
    /// that no other thread or library reaps children created by this runtime,
    /// including with `waitpid(-1)`, until ownership has been discharged. This
    /// must remain true across startup failures. The executable must be the
    /// current executable and implement nenv's private supervisor modes. On
    /// Windows, see the helper and output-destination restrictions on the type.
    #[must_use]
    pub const fn with_exclusive_child_waits(executable: &'a Path) -> Self {
        Self { executable }
    }

    pub(super) const fn executable(self) -> &'a Path {
        self.executable
    }
}

/// Filesystem identity recorded at enumeration and checked again before use.
///
/// On Unix this is the device and inode of the directory or executable. It
/// detects a root or binary **replaced by rename/recreate**, which a path string
/// cannot. It does not detect content modified in place through the same inode,
/// and it is not a content-integrity guarantee. `None` is returned on platforms
/// where this code has no stable identity source; the execute grant remains the
/// authority there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallIdentity {
    pub device: u64,
    pub inode: u64,
}

impl InstallIdentity {
    /// Reads the identity of `path` without following a final symlink.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = std::fs::symlink_metadata(path).ok()?;
            Some(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }
}

/// A runtime installation the application selected for this run.
///
/// The runtime layer cannot enumerate the data directory itself: that would link
/// it back to the installer crate, which already depends on this one. The
/// application builds this list from the installer's structural evidence, which
/// checks that the receipt and executable exist and stay inside the install
/// root. **The version is a directory label, and the receipt digest is only
/// shape-checked.** There is no signature binding the digest to the binary or
/// proving the binary is that version. The external `execute` grant is the
/// authorization.
///
/// The identity fields detect a **replaced object** (a directory or executable
/// renamed away and recreated). They do not detect content written in place
/// through the same inode, and they provide no content-integrity guarantee.
/// They also do not remove the race between the recheck and `spawn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRuntime {
    pub id: String,
    /// The install directory's version label. It is not independently proven.
    pub version: String,
    /// The install root the receipt and binary must stay under.
    pub root: PathBuf,
    pub bin_dir: PathBuf,
    /// The exact executable path selected by enumeration.
    pub binary: PathBuf,
    /// The exact receipt whose contents must still match `digest`.
    pub receipt: PathBuf,
    /// The trimmed receipt digest read during enumeration.
    pub digest: String,
    /// Identity of the install root at enumeration, when the platform provides one.
    pub root_identity: Option<InstallIdentity>,
    /// Identity of the executable at enumeration, when the platform provides one.
    pub binary_identity: Option<InstallIdentity>,
}

/// Controls execution behavior for a task graph.
#[derive(Clone, Copy)]
pub struct TaskRunOptions<'a> {
    /// Route SSH and attached Docker output to stderr, keeping stdout
    /// available for a final JSON document.
    pub ssh_output_to_stderr: bool,
    /// Additional declared-secret values to scrub from remote console output.
    pub ssh_secret_values: &'a [&'a str],
    /// Resolved inventory snapshot for SSH actions; absent means SSH is refused.
    pub inventories: Option<&'a IndexMap<String, neoenv_config::Inventory>>,
    pub dry_run: bool,
    pub cancellation: &'a TaskCancellation,
    /// External grants only. Task declarations can request but never grant capabilities.
    pub capability_grants: Option<&'a CapabilityGrants>,
    /// Persisted policy provenance for trust diagnostics.
    pub capability_policy_source: Option<&'a Path>,
    /// Tasks loaded from a remote cache need an explicit execution grant even
    /// when their declaration does not request additional capabilities.
    pub remote_tasks: Option<&'a HashSet<String>>,
    /// Explicit local and global directories eligible for unknown runner lookup.
    pub task_directories: TaskRunnerDirectories<'a>,
    /// Receipt-backed runtimes available to versioned runners such as
    /// `uses: uv@0.8.0`. Empty means no managed runtime is selected, which
    /// refuses a versioned request rather than falling back to `PATH`.
    pub managed_runtimes: &'a [ManagedRuntime],
    /// Bound values supplied to the root task through its task-local CLI.
    pub input_values: Option<&'a TaskInputValues>,
    /// Declared vaults for lazy secret resolution.
    ///
    /// `None` means this run has no vault context, and an `nsv://` value is left
    /// as written. That is deliberate for library callers and tests that never
    /// asked for secrets, and for a dry run: a plan is not a consumption point
    /// and must not open a vault for a project value or a predicate. The CLI
    /// supplies a set for a real run, even an empty one.
    pub vaults: Option<&'a crate::vault::VaultSet>,
    /// Explicit host cooperation for private modes in the *current executable*.
    ///
    /// On Linux the path must resolve to the same executable inode as the
    /// caller; the runtime actually launches `/proc/self/exe`. That executable
    /// must implement nenv's private versioned supervisor and anchor modes.
    /// An arbitrary supervisor path is rejected. `None` leaves owned background
    /// execution unavailable. See [`CooperativeOwnedBackend`] for the host's
    /// required exclusive child-wait policy.
    pub owned_backend: Option<CooperativeOwnedBackend<'a>>,
}

/// Directory scopes for unknown runner fallback. Empty lists disable fallback.
#[derive(Clone, Copy, Default)]
pub struct TaskRunnerDirectories<'a> {
    pub local: &'a [String],
    pub global: &'a [String],
}

impl TaskRunError {
    pub(super) fn planning_source(message: String, source: TaskError) -> Self {
        Self::PlanningSource {
            message,
            source: Arc::new(source),
        }
    }

    pub(super) fn io_source(operation: impl Into<String>, source: io::Error) -> Self {
        Self::IoSource {
            operation: operation.into(),
            source: Arc::new(source),
        }
    }
}

impl fmt::Display for TaskRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planning(message) | Self::PlanningSource { message, .. } => {
                formatter.write_str(message)
            }
            Self::IoSource { operation, .. } => {
                write!(formatter, "{operation}: task filesystem operation failed")
            }
            Self::InvalidCapability {
                task,
                capability,
                package,
            } => {
                write!(formatter, "task {task}")?;
                write_package_identity(formatter, package.as_deref())?;
                write!(formatter, " requests unsupported capability: {capability}")
            }
            Self::CapabilityDenied {
                task,
                capability,
                subject,
                package,
                policy_source,
            } => {
                write!(formatter, "task {task}")?;
                write_package_identity(formatter, package.as_deref())?;
                write!(
                    formatter,
                    " requested capability {} is not granted to {subject}",
                    capability.name()
                )?;
                if let Some(path) = policy_source {
                    write!(formatter, " by external policy {}", path.display())?;
                }
                Ok(())
            }
        }
    }
}

fn write_package_identity(
    formatter: &mut fmt::Formatter<'_>,
    package: Option<&TaskPackageIdentity>,
) -> fmt::Result {
    if let Some(package) = package {
        write!(
            formatter,
            " from package {} (sha256: {}, export: {})",
            package.path, package.sha256, package.export
        )?;
    }
    Ok(())
}

impl PartialEq for TaskRunError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
            && std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for TaskRunError {}

impl std::error::Error for TaskRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PlanningSource { source, .. } => Some(source.as_ref()),
            Self::IoSource { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
