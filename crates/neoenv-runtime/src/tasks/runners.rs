//! Named script runners and the exact-version `uv` runner.
//!
//! The command shapes are fixed here rather than guessed from the script text.
//! `run:` is inline, `source:` is a file, and both are documented in
//! `docs/task-runners.md`. Interpreter arguments and task/CLI arguments are
//! appended in one order for every runner in a family, so a fake interpreter can
//! assert the whole argv and a user can reason about `$1`/`process.argv` without
//! reading this module.
//!
//! No named runner installs anything or reaches the network. `uv` is selected
//! only from the receipt-backed managed-runtime list the application supplied;
//! an absent exact version is an error, never a `PATH` fallback.

use std::{fs, io::Write as _, process::ExitStatus};

use neoenv_core::tasks::is_script_runner;

use super::process::resolve_existing_declared_file;
use super::{
    BTreeMap, Duration, ExecutionOptions, InstallIdentity, ManagedRuntime, Path, PathBuf,
    TaskAction, TaskDefinition, TaskRunOptions, execute_argv,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptRunner {
    Bash,
    Sh,
    Pwsh,
    Powershell,
    Node,
    Bun,
    Deno,
    Python,
    Nu,
    Fish,
    Go,
    Dotnet,
}

impl ScriptRunner {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "bash" => Some(Self::Bash),
            "sh" => Some(Self::Sh),
            "pwsh" => Some(Self::Pwsh),
            "powershell" => Some(Self::Powershell),
            "node" => Some(Self::Node),
            "bun" => Some(Self::Bun),
            "deno" => Some(Self::Deno),
            "python" => Some(Self::Python),
            "nu" => Some(Self::Nu),
            "fish" => Some(Self::Fish),
            "go" => Some(Self::Go),
            "dotnet" => Some(Self::Dotnet),
            _ => None,
        }
    }

    fn program(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Sh => "sh",
            Self::Pwsh => "pwsh",
            Self::Powershell => "powershell",
            Self::Node => "node",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::Python => "python",
            Self::Nu => "nu",
            Self::Fish => "fish",
            Self::Go => "go",
            Self::Dotnet => "dotnet",
        }
    }
}

/// The exact executable candidates for a runner, in precedence order.
///
/// Python is the only one with two names today. On Unix, `python3` is tried
/// before `python` because a host can have a `python` that is not Python 3; the
/// choice is still a PATH lookup, not an install.
fn program_candidates(runner: ScriptRunner) -> &'static [&'static str] {
    match runner {
        ScriptRunner::Python if cfg!(windows) => &["python"],
        ScriptRunner::Python => &["python3", "python"],
        ScriptRunner::Bash => &["bash"],
        ScriptRunner::Sh => &["sh"],
        ScriptRunner::Pwsh => &["pwsh"],
        ScriptRunner::Powershell => &["powershell"],
        ScriptRunner::Node => &["node"],
        ScriptRunner::Bun => &["bun"],
        ScriptRunner::Deno => &["deno"],
        ScriptRunner::Nu => &["nu"],
        ScriptRunner::Fish => &["fish"],
        ScriptRunner::Go => &["go"],
        ScriptRunner::Dotnet => &["dotnet"],
    }
}

/// Runs a named script runner.
///
/// # Errors
///
/// Returns a message for a script/file contract violation, an interpreter that
/// is not on the task's `PATH`, a Windows POSIX-shell refusal, or a process
/// launch/cancellation/timeout failure.
#[allow(
    clippy::too_many_arguments,
    reason = "the runner seam names every independent input explicitly, matching execute_task"
)]
pub(super) fn execute_script(
    name: &str,
    task: &TaskDefinition,
    project_root: &Path,
    task_environment: &BTreeMap<String, String>,
    cwd: &Path,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExitStatus, String> {
    execute_script_on(
        name,
        task,
        project_root,
        task_environment,
        cwd,
        passthrough,
        options,
        timeout,
        cfg!(windows),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_script_on(
    name: &str,
    task: &TaskDefinition,
    project_root: &Path,
    task_environment: &BTreeMap<String, String>,
    cwd: &Path,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
    windows: bool,
) -> Result<ExitStatus, String> {
    debug_assert!(is_script_runner(name));
    let runner = ScriptRunner::from_name(name)
        .ok_or_else(|| format!("unsupported script runner: {name}"))?;
    if let Some(message) = windows_refusal(runner, windows) {
        return Err(message);
    }
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "task has no action".to_owned())?;
    let mut _temporary = None;
    let source = match (runner, script_source(task, project_root)?) {
        (ScriptRunner::Go, ScriptSource::Inline(script)) => {
            let staged = stage_inline_source(&script, ".go")?;
            let path = staged.path().to_path_buf();
            _temporary = Some(staged);
            ScriptSource::File(path)
        }
        (ScriptRunner::Dotnet, ScriptSource::Inline(script)) => {
            let staged = stage_inline_source(&script, ".cs")?;
            let path = staged.path().to_path_buf();
            _temporary = Some(staged);
            ScriptSource::File(path)
        }
        (_, source) => source,
    };
    if runner == ScriptRunner::Go {
        let ScriptSource::File(source_path) = &source else {
            return Err("go source was not staged".to_owned());
        };
        return execute_go(
            source_path,
            action,
            cwd,
            task_environment,
            passthrough,
            options,
            timeout,
        );
    }
    let spec = command_for(runner, &source, action, !passthrough.is_empty())?;
    let program = program_candidates(runner)
        .iter()
        .find_map(|candidate| resolve_executable(candidate, task_environment))
        .ok_or_else(|| {
            format!(
                "task runner executable was not found on PATH: {}",
                program_candidates(runner).join(" or ")
            )
        })?;
    let is_cancelled = || options.cancellation.is_cancelled();
    execute_argv(
        &program.to_string_lossy(),
        &spec.arguments,
        &ExecutionOptions {
            working_directory: cwd,
            environment: task_environment,
            passthrough,
            is_cancelled: &is_cancelled,
            timeout,
        },
    )
    .map_err(super::process::format_process_error)
}

/// Re-checks the structural evidence a managed `uv` install must still carry.
///
/// This is not a trust check. The receipt is not a signature, the digest is not
/// bound to the executable, and the version is only the directory label. This
/// proves the same paths are still a complete, self-consistent shape and, on
/// Unix, that the root and executable are the same filesystem objects seen at
/// enumeration. Object identity detects a renamed-away-and-recreated path; it
/// does not detect content modified in place through the same inode and gives no
/// content-integrity guarantee. There is still a race between this check and
/// spawning; the caller's `execute` grant is the authority, not this function.
///
/// # Errors
///
/// Returns a message when the root is missing or a symlink, the version label
/// no longer matches the root directory name, the receipt is missing or
/// changed, the executable path is not the enumerated one, is a symlink, is not
/// executable, resolves outside the root, or no longer has its enumerated
/// identity.
pub(super) fn recheck_uv_install(runtime: &ManagedRuntime) -> Result<(), String> {
    let incomplete = || {
        format!(
            "managed uv@{} failed installation verification; reinstall it",
            runtime.version
        )
    };
    let root = fs::symlink_metadata(&runtime.root).map_err(|_| incomplete())?;
    if !root.file_type().is_dir() {
        return Err(incomplete());
    }
    if runtime.root.file_name().and_then(|name| name.to_str()) != Some(runtime.version.as_str()) {
        return Err(incomplete());
    }
    if runtime.receipt.parent() != Some(runtime.root.as_path()) {
        return Err(incomplete());
    }
    let receipt = fs::symlink_metadata(&runtime.receipt).map_err(|_| incomplete())?;
    if !receipt.file_type().is_file() {
        return Err(incomplete());
    }
    let digest = fs::read_to_string(&runtime.receipt).map_err(|_| incomplete())?;
    let digest = digest.trim();
    if digest != runtime.digest || !uv_receipt_digest_is_well_formed(digest) {
        return Err(incomplete());
    }
    let bin_dir = fs::symlink_metadata(&runtime.bin_dir).map_err(|_| incomplete())?;
    if !bin_dir.file_type().is_dir() {
        return Err(incomplete());
    }
    let expected_binary = runtime
        .bin_dir
        .join(if cfg!(windows) { "uv.exe" } else { "uv" });
    if runtime.binary != expected_binary || !is_usable_file(&runtime.binary) {
        return Err(incomplete());
    }
    let canonical_root = runtime.root.canonicalize().map_err(|_| incomplete())?;
    if !runtime
        .receipt
        .canonicalize()
        .map_err(|_| incomplete())?
        .starts_with(&canonical_root)
        || !runtime
            .bin_dir
            .canonicalize()
            .map_err(|_| incomplete())?
            .starts_with(&canonical_root)
        || !runtime
            .binary
            .canonicalize()
            .map_err(|_| incomplete())?
            .starts_with(&canonical_root)
    {
        return Err(incomplete());
    }
    #[cfg(unix)]
    {
        // A path string is not an identity: a directory or executable can be
        // replaced at the same path. The identity narrows that window. It does
        // not remove the race between this check and `spawn`.
        if runtime.root_identity.is_none()
            || runtime.root_identity != InstallIdentity::of(&runtime.root)
            || runtime.binary_identity.is_none()
            || runtime.binary_identity != InstallIdentity::of(&runtime.binary)
        {
            return Err(incomplete());
        }
    }
    Ok(())
}

fn uv_receipt_digest_is_well_formed(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The diagnostic for a requested managed version that was not supplied.
pub(super) fn uv_version_error(version: &str, managed: &[ManagedRuntime]) -> String {
    let installed = managed
        .iter()
        .filter(|runtime| runtime.id == "uv")
        .map(|runtime| runtime.version.as_str())
        .collect::<Vec<_>>();
    if installed.is_empty() {
        format!(
            "task runner uv@{version} is not installed; no managed uv runtime is available, \
             and a PATH uv is not used"
        )
    } else {
        format!(
            "task runner uv@{version} is not installed; managed uv versions are {}",
            installed.join(", ")
        )
    }
}

/// Runs `uses: uv@<exact-version>`.
///
/// The executable is the managed runtime whose version equals the request
/// exactly. There is no PATH lookup and no install: a missing version lists the
/// managed versions that *are* installed and refuses.
///
/// # Errors
///
/// Returns a message for a missing or incomplete managed runtime, a script/file
/// contract violation, or a process launch/cancellation/timeout failure.
#[allow(
    clippy::too_many_arguments,
    reason = "the runner seam names every independent input explicitly, matching execute_task"
)]
pub(super) fn execute_uv(
    version: &str,
    task: &TaskDefinition,
    project_root: &Path,
    task_environment: &BTreeMap<String, String>,
    cwd: &Path,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExitStatus, String> {
    let managed = options
        .managed_runtimes
        .iter()
        .find(|runtime| runtime.id == "uv" && runtime.version == version)
        .ok_or_else(|| uv_version_error(version, options.managed_runtimes))?;
    recheck_uv_install(managed)?;
    let binary = &managed.binary;

    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "task has no action".to_owned())?;
    let source = script_source(task, project_root)?;
    let mut arguments = vec![
        "run".to_owned(),
        "--no-project".to_owned(),
        "--no-sync".to_owned(),
        "--offline".to_owned(),
        "--no-python-downloads".to_owned(),
        "python".to_owned(),
    ];
    match &source {
        ScriptSource::Inline(script) => {
            arguments.push("-c".to_owned());
            arguments.push(script.clone());
        }
        ScriptSource::File(path) => arguments.push(path.display().to_string()),
    }
    arguments.extend(action.args.iter().cloned());
    let is_cancelled = || options.cancellation.is_cancelled();
    execute_argv(
        &binary.to_string_lossy(),
        &arguments,
        &ExecutionOptions {
            working_directory: cwd,
            environment: task_environment,
            passthrough,
            is_cancelled: &is_cancelled,
            timeout,
        },
    )
    .map_err(super::process::format_process_error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScriptSource {
    Inline(String),
    File(PathBuf),
}

fn script_source(task: &TaskDefinition, project_root: &Path) -> Result<ScriptSource, String> {
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "task has no action".to_owned())?;
    let inline = action.run.as_deref().filter(|run| !run.is_empty());
    let file = action.source.as_deref().filter(|source| !source.is_empty());
    match (inline, file) {
        (Some(run), None) => Ok(ScriptSource::Inline(run.to_owned())),
        (None, Some(source)) => resolve_existing_declared_file(
            project_root,
            task,
            source,
            action.source_document.as_ref(),
            action.source_from_package,
            "script source",
        )
        .map(ScriptSource::File),
        (Some(_), Some(_)) => Err(
            "script runners accept exactly one of run (inline script) or source (script file)"
                .to_owned(),
        ),
        (None, None) => {
            Err("script runners require run (inline script) or source (script file)".to_owned())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandSpec {
    arguments: Vec<String>,
}

/// Runs a script through the explicit Windows Subsystem for Linux bridge.
///
/// `uses: wsl` is never an alias for `bash`. The Windows `wsl.exe` process is
/// started with an optional distribution and a translated working directory,
/// then `sh -lc <run>` inside the distribution.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_wsl(
    run: &str,
    action: &TaskAction,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExitStatus, String> {
    execute_wsl_on(
        run,
        action,
        cwd,
        environment,
        passthrough,
        options,
        timeout,
        cfg!(windows),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_wsl_on(
    run: &str,
    action: &TaskAction,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
    windows: bool,
) -> Result<ExitStatus, String> {
    if !windows {
        return Err(
            "uses: wsl is a Windows-only runner; on this host use portable, argv, shell,              or a script runner"
                .to_owned(),
        );
    }
    for key in action.with.keys() {
        if !matches!(key.as_str(), "distribution" | "mount-root" | "timeout") {
            return Err(format!(
                "unknown wsl with key {key:?}; supported keys are distribution, \
                 mount-root, and timeout"
            ));
        }
    }
    let program = resolve_exact_executable("wsl.exe", environment)
        .ok_or_else(|| "task runner executable was not found on PATH: wsl.exe".to_owned())?;
    let spec = wsl_command(action, cwd, run)?;
    let is_cancelled = || options.cancellation.is_cancelled();
    execute_argv(
        &program.to_string_lossy(),
        &spec.arguments,
        &ExecutionOptions {
            working_directory: cwd,
            environment,
            passthrough,
            is_cancelled: &is_cancelled,
            timeout,
        },
    )
    .map_err(super::process::format_process_error)
}

fn wsl_command(action: &TaskAction, cwd: &Path, run: &str) -> Result<CommandSpec, String> {
    let mut arguments = Vec::new();
    if let Some(distribution) = action.with.get("distribution") {
        let distribution = distribution.trim();
        if distribution.is_empty() || distribution.contains('\0') {
            return Err("wsl with.distribution must be a non-empty name".to_owned());
        }
        arguments.extend(["--distribution".to_owned(), distribution.to_owned()]);
    }
    arguments.extend([
        "--cd".to_owned(),
        wsl_path(cwd, action.with.get("mount-root").map(String::as_str))?,
        "--exec".to_owned(),
        "sh".to_owned(),
        "-lc".to_owned(),
        run.to_owned(),
        // `-c` makes this `$0`; declared args begin at `$1`.
        "neoenv-task".to_owned(),
    ]);
    arguments.extend(action.args.iter().cloned());
    Ok(CommandSpec { arguments })
}

/// Translates a Windows drive path under an explicitly configured WSL mount
/// root.
///
/// There is no safe default root: a distribution can use a custom automount
/// root or disable automount, and querying it needs a live WSL. The caller must
/// set `with.mount-root`.
fn wsl_path(path: &Path, mount_root: Option<&str>) -> Result<String, String> {
    let text = path.to_string_lossy();
    let text = text
        .strip_prefix(r"\\?\UNC\")
        .map_or_else(|| text.strip_prefix(r"\\?\").unwrap_or(&text), |_| &text)
        .to_owned();
    if text.starts_with(r"\\") || text.starts_with("UNC\\") {
        return Err("wsl working directory is a UNC path and cannot be translated".to_owned());
    }
    if text.starts_with('/') {
        return Ok(text.replace('\\', "/"));
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let root = match mount_root {
            Some(root) => normalize_mount_root(root)?,
            None => {
                return Err(format!(
                    "wsl cannot translate the Windows working directory {} without an \
                     explicit with.mount-root; set it to the selected distribution's \
                     automount root (for example /mnt)",
                    path.display()
                ));
            }
        };
        let rest = &text[2..];
        if !rest.is_empty() && !rest.starts_with('\\') && !rest.starts_with('/') {
            return Err(format!(
                "wsl working directory must be an absolute drive path: {}",
                path.display()
            ));
        }
        let drive = char::from(bytes[0]).to_ascii_lowercase();
        let translated = format!("{root}/{drive}{}", rest.replace('\\', "/"));
        return Ok(translated);
    }
    Err(format!(
        "wsl working directory must be an absolute drive path: {}",
        path.display()
    ))
}

fn normalize_mount_root(root: &str) -> Result<String, String> {
    let root = root.trim();
    if root.is_empty()
        || !root.starts_with('/')
        || root.contains('\\')
        || root.contains('\0')
        || root
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(
            "wsl with.mount-root must be an absolute Linux directory without `.` or `..`"
                .to_owned(),
        );
    }
    Ok(root.trim_end_matches('/').to_owned())
}

/// Builds one Go source file and runs the resulting binary with the task's
/// arguments unchanged.
///
/// `go run` treats consecutive arguments ending in `.go` as additional source
/// files, so `go run main.go first.go` compiles two files instead of passing
/// `first.go` to the program. Building first avoids that parser entirely.
#[allow(clippy::too_many_arguments)]
fn execute_go(
    source: &Path,
    action: &TaskAction,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExitStatus, String> {
    execute_go_with(
        source,
        action,
        cwd,
        environment,
        passthrough,
        options,
        timeout,
        &|| {},
    )
}

/// The test seam is the callback after a successful build. Production passes a
/// no-op; tests use it to cancel or exhaust the deadline between phases.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_go_with(
    source: &Path,
    action: &TaskAction,
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
    before_run: &dyn Fn(),
) -> Result<ExitStatus, String> {
    let go = program_candidates(ScriptRunner::Go)
        .iter()
        .find_map(|candidate| resolve_executable(candidate, environment))
        .ok_or_else(|| "task runner executable was not found on PATH: go".to_owned())?;
    let build = tempfile::TempDir::new()
        .map_err(|error| format!("failed to create Go build directory: {error}"))?;
    let binary = build.path().join(if cfg!(windows) {
        "program.exe"
    } else {
        "program"
    });
    let started = std::time::Instant::now();
    let is_cancelled = || options.cancellation.is_cancelled();
    let build_status = execute_argv(
        &go.to_string_lossy(),
        &[
            "build".to_owned(),
            "-o".to_owned(),
            binary.display().to_string(),
            source.display().to_string(),
        ],
        &ExecutionOptions {
            working_directory: cwd,
            environment,
            passthrough: &[],
            is_cancelled: &is_cancelled,
            timeout,
        },
    )
    .map_err(super::process::format_process_error)?;
    if !build_status.success() {
        return Err(format!(
            "go build failed with exit code {}",
            build_status.code().unwrap_or(1)
        ));
    }
    before_run();
    if options.cancellation.is_cancelled() {
        return Err("task cancelled".to_owned());
    }
    let remaining = timeout.map(|limit| limit.saturating_sub(started.elapsed()));
    if remaining.is_some_and(|remaining| remaining.is_zero()) {
        return Err("task timed out".to_owned());
    }
    execute_argv(
        &binary.to_string_lossy(),
        &action.args,
        &ExecutionOptions {
            working_directory: cwd,
            environment,
            passthrough,
            is_cancelled: &is_cancelled,
            timeout: remaining,
        },
    )
    .map_err(super::process::format_process_error)
}

fn command_for(
    runner: ScriptRunner,
    source: &ScriptSource,
    action: &TaskAction,
    has_passthrough: bool,
) -> Result<CommandSpec, String> {
    let mut arguments = Vec::new();
    let mut separator = false;
    match source {
        ScriptSource::Inline(script) => match runner {
            ScriptRunner::Bash => {
                arguments.extend([
                    "--noprofile".to_owned(),
                    "--norc".to_owned(),
                    "-eo".to_owned(),
                    "pipefail".to_owned(),
                    "-c".to_owned(),
                    script.clone(),
                    // `-c` makes the next argument `$0`; giving it a name keeps
                    // declared args at `$1...` instead of shifting them.
                    "neoenv-task".to_owned(),
                ]);
            }
            ScriptRunner::Sh => {
                arguments.extend([
                    "-e".to_owned(),
                    "-c".to_owned(),
                    script.clone(),
                    "neoenv-task".to_owned(),
                ]);
            }
            ScriptRunner::Pwsh | ScriptRunner::Powershell => {
                arguments.extend([
                    "-NoLogo".to_owned(),
                    "-NoProfile".to_owned(),
                    "-ExecutionPolicy".to_owned(),
                    "Bypass".to_owned(),
                    "-Command".to_owned(),
                    script.clone(),
                ]);
            }
            ScriptRunner::Node | ScriptRunner::Bun => {
                // Without `--`, an option-like task argument is parsed by Node
                // or Bun itself: `node -e script --version` prints the Node
                // version and never runs the script. The separator makes every
                // task argument a script argument.
                arguments.extend(["-e".to_owned(), script.clone(), "--".to_owned()]);
            }
            ScriptRunner::Deno => {
                arguments.extend(["eval".to_owned(), script.clone()]);
            }
            ScriptRunner::Python | ScriptRunner::Nu | ScriptRunner::Fish => {
                arguments.extend(["-c".to_owned(), script.clone()]);
            }
            ScriptRunner::Go | ScriptRunner::Dotnet => {
                return Err(format!(
                    "inline {} source must be staged to a file before command construction",
                    runner.program()
                ));
            }
        },
        ScriptSource::File(path) => {
            let path = path.display().to_string();
            match runner {
                ScriptRunner::Sh => arguments.extend(["-e".to_owned(), path]),
                ScriptRunner::Pwsh | ScriptRunner::Powershell => {
                    arguments.extend([
                        "-NoLogo".to_owned(),
                        "-NoProfile".to_owned(),
                        "-ExecutionPolicy".to_owned(),
                        "Bypass".to_owned(),
                        "-File".to_owned(),
                        path,
                    ]);
                }
                ScriptRunner::Deno => {
                    // Cast's deno file mode grants all permissions. That is a
                    // wide grant, so it is stated in the runner documentation
                    // rather than discovered from a failing script.
                    arguments.extend(["run".to_owned(), "-A".to_owned(), path]);
                }
                ScriptRunner::Go => {
                    return Err("go source is built by execute_go".to_owned());
                }
                ScriptRunner::Dotnet => {
                    let extension = Path::new(&path)
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .unwrap_or("");
                    match extension {
                        "dll" | "exe" => arguments.push(path),
                        "cs" | "csx" | "" => {
                            arguments.extend(["run".to_owned(), "--file".to_owned(), path]);
                            separator = true;
                        }
                        _ => {
                            arguments.extend(["run".to_owned(), "--project".to_owned(), path]);
                            separator = true;
                        }
                    }
                }
                ScriptRunner::Bash
                | ScriptRunner::Node
                | ScriptRunner::Bun
                | ScriptRunner::Python
                | ScriptRunner::Nu
                | ScriptRunner::Fish => arguments.push(path),
            }
        }
    }
    if separator && (!action.args.is_empty() || has_passthrough) {
        arguments.push("--".to_owned());
    }
    arguments.extend(action.args.iter().cloned());
    Ok(CommandSpec { arguments })
}

fn stage_inline_source(script: &str, extension: &str) -> Result<tempfile::NamedTempFile, String> {
    let mut staged = tempfile::Builder::new()
        .prefix("neoenv-task-")
        .suffix(extension)
        .tempfile()
        .map_err(|error| format!("failed to create temporary {extension} source: {error}"))?;
    staged
        .write_all(script.as_bytes())
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| format!("failed to write temporary {extension} source: {error}"))?;
    Ok(staged)
}

fn windows_refusal(runner: ScriptRunner, windows: bool) -> Option<String> {
    if !windows {
        return None;
    }
    match runner {
        ScriptRunner::Bash | ScriptRunner::Sh | ScriptRunner::Fish => Some(format!(
            "task runner {} is refused on Windows because a native Git Bash/non-WSL \
             executable cannot be identified safely from PATH; `bash.exe` there may be \
             the WSL launcher. Use `uses: wsl` for WSL explicitly, pwsh/powershell, or \
             a fallback runner that names an explicit native executable",
            runner.program()
        )),
        _ => None,
    }
}

/// Resolves `program` against the child's own `PATH`, mirroring how the process
/// executor resolves a bare name.
fn resolve_executable(program: &str, environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    let path = environment.iter().find_map(|(key, value)| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case("PATH").then_some(value)
        } else {
            (key == "PATH").then_some(value)
        }
    })?;
    for directory in std::env::split_paths(path) {
        for candidate in executable_candidates(program, environment) {
            let candidate = directory.join(&candidate);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolves one exact executable name, without `PATHEXT`.
///
/// Windows `wsl.exe` must not be found through a bare `wsl` lookup: PATHEXT can
/// prefer `wsl.com`/`wsl.cmd`, or omit `.EXE`. Finding this file does not
/// authenticate it; it is only a PATH location.
fn resolve_exact_executable(
    program: &str,
    environment: &BTreeMap<String, String>,
) -> Option<PathBuf> {
    let path = environment.iter().find_map(|(key, value)| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case("PATH").then_some(value)
        } else {
            (key == "PATH").then_some(value)
        }
    })?;
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        if is_usable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Whether `path` is an executable for normal `PATH` lookup.
///
/// Unlike [`is_usable_file`], this follows a symlink. `PATH` is full of symlinks
/// (`python3`, package-manager shims), and refusing them would make the named
/// runners unusable. The strict no-symlink rule applies to the managed `uv`
/// executable, which is an object identity and not a lookup.
fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn executable_candidates(program: &str, environment: &BTreeMap<String, String>) -> Vec<String> {
    if !cfg!(windows) || Path::new(program).extension().is_some() {
        return vec![program.to_owned()];
    }
    let mut candidates = vec![program.to_owned()];
    let extensions = environment
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case("PATHEXT").then_some(value));
    let extensions = extensions.map_or_else(
        || {
            vec![
                ".COM".to_owned(),
                ".EXE".to_owned(),
                ".BAT".to_owned(),
                ".CMD".to_owned(),
            ]
        },
        |value| {
            value
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_owned)
                .collect()
        },
    );
    candidates.extend(
        extensions
            .into_iter()
            .map(|extension| format!("{program}{extension}")),
    );
    candidates
}

/// Whether `path` is a real executable file, never a symlink.
///
/// `symlink_metadata` is deliberate: `metadata` follows a symlink and would
/// accept a link pointing at a real executable. A symlink is not the object the
/// enumeration recorded, even when its target stays inside the install root.
fn is_usable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{TaskCancellation, TaskRunnerDirectories};
    use indexmap::IndexMap;

    #[test]
    fn posix_shells_are_refused_on_windows() {
        for runner in [ScriptRunner::Bash, ScriptRunner::Sh, ScriptRunner::Fish] {
            assert!(windows_refusal(runner, true).is_some());
            assert!(windows_refusal(runner, false).is_none());
        }
        for runner in [
            ScriptRunner::Pwsh,
            ScriptRunner::Powershell,
            ScriptRunner::Node,
            ScriptRunner::Bun,
            ScriptRunner::Deno,
            ScriptRunner::Python,
            ScriptRunner::Nu,
        ] {
            assert!(windows_refusal(runner, true).is_none());
        }
    }

    /// `PATH` is full of symlinks; lookup must follow one. The strict check is
    /// only for the managed `uv` object, where the link itself is not the
    /// enumerated binary.
    #[cfg(unix)]
    #[test]
    fn path_lookup_follows_a_symlink_while_managed_binary_check_refuses_it() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::TempDir::new().unwrap();
        let real = directory.path().join("node-real");
        fs::write(&real, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        let link = directory.path().join("node");
        symlink(&real, &link).unwrap();
        let environment =
            BTreeMap::from([("PATH".to_owned(), directory.path().display().to_string())]);
        assert!(resolve_executable("node", &environment).is_some());
        assert!(!is_usable_file(&link));
    }

    fn options(cancellation: &TaskCancellation) -> TaskRunOptions<'_> {
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        }
    }

    /// A `bash.exe` on PATH could be the WSL launcher. Windows bash/sh are
    /// refused before PATH resolution, so the shim is never selected.
    #[cfg(unix)]
    #[test]
    fn windows_bash_and_sh_never_resolve_a_bash_exe_shim() {
        use std::os::unix::fs::PermissionsExt as _;

        for runner in ["bash", "sh"] {
            let project = tempfile::TempDir::new().unwrap();
            let fake = tempfile::TempDir::new().unwrap();
            let marker = project.path().join("wsl-shim-ran");
            let shim = fake.path().join("bash.exe");
            fs::write(&shim, format!("#!/bin/sh\n: > {}\n", marker.display())).unwrap();
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
            let environment =
                BTreeMap::from([("PATH".to_owned(), fake.path().display().to_string())]);
            let cancellation = TaskCancellation::new();
            let task = TaskDefinition {
                action: Some(TaskAction {
                    uses: Some(runner.into()),
                    run: Some("true".into()),
                    ..TaskAction::default()
                }),
                ..TaskDefinition::default()
            };
            let error = execute_script_on(
                runner,
                &task,
                project.path(),
                &environment,
                project.path(),
                &[],
                &options(&cancellation),
                None,
                true,
            )
            .unwrap_err();
            assert!(error.contains("uses: wsl"), "{runner}: {error}");
            assert!(!marker.exists(), "{runner}: the PATH shim must not run");
        }
    }

    #[test]
    fn wsl_command_has_distribution_cd_and_shell_arguments() {
        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            with: IndexMap::from([
                ("distribution".to_owned(), "Ubuntu-22.04".to_owned()),
                ("mount-root".to_owned(), "/mnt".to_owned()),
            ]),
            args: vec!["declared".into()],
            ..TaskAction::default()
        };
        let spec = wsl_command(&action, Path::new(r"C:\work\project"), "echo hi").unwrap();
        assert_eq!(
            spec.arguments,
            [
                "--distribution",
                "Ubuntu-22.04",
                "--cd",
                "/mnt/c/work/project",
                "--exec",
                "sh",
                "-lc",
                "echo hi",
                "neoenv-task",
                "declared",
            ]
        );

        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            with: IndexMap::from([("mount-root".to_owned(), "/custom/root".to_owned())]),
            ..TaskAction::default()
        };
        let spec = wsl_command(&action, Path::new(r"C:\work\project"), "echo hi").unwrap();
        assert_eq!(spec.arguments[..2], ["--cd", "/custom/root/c/work/project"]);
    }

    #[test]
    fn wsl_refuses_drive_translation_without_an_explicit_mount_root() {
        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            ..TaskAction::default()
        };
        let error = wsl_command(&action, Path::new(r"C:\work\project"), "echo hi").unwrap_err();
        assert!(error.contains("with.mount-root"), "{error}");
    }

    #[test]
    fn wsl_rejects_unc_working_directories() {
        assert!(wsl_path(Path::new(r"\\server\share\project"), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn wsl_exact_lookup_prefers_wsl_exe_over_other_pathext_names() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::TempDir::new().unwrap();
        let fake = tempfile::TempDir::new().unwrap();
        let output = project.path().join("argv");
        for name in ["wsl.exe", "wsl.cmd", "wsl.com", "wsl"] {
            let marker = project.path().join(format!("{name}.ran"));
            let script = if name == "wsl.exe" {
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RESULT\"\n".to_owned()
            } else {
                format!("#!/bin/sh\n: > {}\n", marker.display())
            };
            let path = fake.path().join(name);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let environment = BTreeMap::from([
            ("PATH".to_owned(), fake.path().display().to_string()),
            ("PATHEXT".to_owned(), ".CMD;.COM".to_owned()),
            ("RESULT".to_owned(), output.display().to_string()),
        ]);
        let cancellation = TaskCancellation::new();
        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("true".into()),
            with: IndexMap::from([("mount-root".to_owned(), "/mnt".to_owned())]),
            ..TaskAction::default()
        };
        let status = execute_wsl_on(
            "true",
            &action,
            project.path(),
            &environment,
            &[],
            &options(&cancellation),
            None,
            true,
        )
        .unwrap();
        assert!(status.success());
        for name in ["wsl.cmd", "wsl.com", "wsl"] {
            assert!(
                !project.path().join(format!("{name}.ran")).exists(),
                "{name} ran"
            );
        }
        assert!(output.exists(), "wsl.exe must be the executable that ran");
    }

    #[cfg(unix)]
    #[test]
    fn wsl_execution_passes_distribution_and_translated_cd() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::TempDir::new().unwrap();
        let fake = tempfile::TempDir::new().unwrap();
        let output = project.path().join("argv");
        let wsl = fake.path().join("wsl.exe");
        fs::write(&wsl, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RESULT\"\n").unwrap();
        fs::set_permissions(&wsl, fs::Permissions::from_mode(0o755)).unwrap();
        let environment = BTreeMap::from([
            ("PATH".to_owned(), fake.path().display().to_string()),
            ("RESULT".to_owned(), output.display().to_string()),
        ]);
        let cancellation = TaskCancellation::new();
        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            with: IndexMap::from([
                ("distribution".to_owned(), "Ubuntu-22.04".to_owned()),
                ("mount-root".to_owned(), "/mnt".to_owned()),
            ]),
            args: vec!["declared".into()],
            ..TaskAction::default()
        };
        let status = execute_wsl_on(
            "echo hi",
            &action,
            project.path(),
            &environment,
            &["passed".into()],
            &options(&cancellation),
            None,
            true,
        )
        .unwrap();
        assert!(status.success());
        let recorded = fs::read_to_string(&output).unwrap();
        assert_eq!(
            recorded.lines().collect::<Vec<_>>(),
            [
                "--distribution",
                "Ubuntu-22.04",
                "--cd",
                &project.path().display().to_string(),
                "--exec",
                "sh",
                "-lc",
                "echo hi",
                "neoenv-task",
                "declared",
                "passed",
            ]
        );
    }

    #[test]
    fn wsl_is_refused_off_windows() {
        let project = tempfile::TempDir::new().unwrap();
        let cancellation = TaskCancellation::new();
        let action = TaskAction {
            uses: Some("wsl".into()),
            run: Some("true".into()),
            ..TaskAction::default()
        };
        let error = execute_wsl_on(
            "true",
            &action,
            project.path(),
            &BTreeMap::new(),
            &[],
            &options(&cancellation),
            None,
            false,
        )
        .unwrap_err();
        assert!(error.contains("Windows-only"), "{error}");
    }

    #[test]
    fn inline_shells_pin_dollar_zero_and_append_declared_args() {
        let action = TaskAction {
            args: vec!["one".into(), "two".into()],
            ..TaskAction::default()
        };
        let spec = command_for(
            ScriptRunner::Bash,
            &ScriptSource::Inline("echo hi".into()),
            &action,
            false,
        )
        .unwrap();
        assert_eq!(
            spec.arguments,
            [
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                "echo hi",
                "neoenv-task",
                "one",
                "two",
            ]
        );

        let spec = command_for(
            ScriptRunner::Sh,
            &ScriptSource::Inline("echo hi".into()),
            &action,
            false,
        )
        .unwrap();
        assert_eq!(
            spec.arguments,
            ["-e", "-c", "echo hi", "neoenv-task", "one", "two"]
        );
    }

    #[test]
    fn inline_interpreters_do_not_invent_a_script_name() {
        let action = TaskAction::default();
        for (runner, prefix) in [
            (ScriptRunner::Node, vec!["-e", "x", "--"]),
            (ScriptRunner::Bun, vec!["-e", "x", "--"]),
            (ScriptRunner::Deno, vec!["eval", "x"]),
            (ScriptRunner::Python, vec!["-c", "x"]),
            (ScriptRunner::Nu, vec!["-c", "x"]),
            (ScriptRunner::Fish, vec!["-c", "x"]),
            (
                ScriptRunner::Pwsh,
                vec![
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "x",
                ],
            ),
        ] {
            let spec =
                command_for(runner, &ScriptSource::Inline("x".into()), &action, false).unwrap();
            assert_eq!(spec.arguments, prefix, "{runner:?}");
        }
    }
}
