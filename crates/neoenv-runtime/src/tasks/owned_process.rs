//! CLI-owned supervisor client. Library callers must opt in by supplying the
//! executable path; no global switch or process-wide signal mutation occurs.

use neotales_process::{CommandChain, Error, ExecutionOptions};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{net::UnixStream, process::ExitStatusExt},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const REQUEST: &[u8] = b"NEOENV-OWNED/1\n";
const MAX_RESPONSE_LINE: usize = 128;
// Concurrent debug builds can hash several large executables at once; this
// absolute startup bound is independent of the supervisor's per-I/O bound.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
const ANCESTRY_UNAVAILABLE: &str =
    "cannot inspect terminal lease ancestry; refusing contested foreground execution";

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static SIGNAL_FAULT: std::cell::Cell<Option<rustix::io::Errno>> = const { std::cell::Cell::new(None) };
    static WAIT_FAULT: std::cell::Cell<Option<rustix::io::Errno>> = const { std::cell::Cell::new(None) };
    static SIGNAL_PERSISTENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TRICKLE_SUPERVISOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXIT_SUPERVISOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TRICKLE_PIDFD: std::cell::RefCell<Option<std::os::fd::OwnedFd>> = const { std::cell::RefCell::new(None) };
    static TRICKLE_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REQUEST_WRITE_PROGRESS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static WITHHOLD_PIDFD_MARKER: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    static WITHHOLD_CHILD_PIDFD: std::cell::RefCell<Option<std::os::fd::OwnedFd>> = const { std::cell::RefCell::new(None) };
}

#[derive(Serialize)]
struct Run<'a> {
    version: &'static str,
    binary_sha256: String,
    program: &'a str,
    arguments: &'a [String],
    cwd: String,
    environment: &'a BTreeMap<String, String>,
    timeout_ms: Option<u64>,
    pipelines: Vec<Vec<Stage>>,
    operators: Vec<String>,
    foreground: bool,
}

#[derive(Serialize)]
struct Stage {
    program: String,
    arguments: Vec<String>,
}

/// Whether an explicit CLI-owned backend is available on this platform.
pub(super) const fn supported(backend: Option<&Path>) -> bool {
    cfg!(target_os = "linux") && backend.is_some()
}

/// Explains why the owned background backend is unavailable on this target.
pub(super) const fn unavailable_reason() -> &'static str {
    "exclusive child ownership is not implemented on this platform"
}

pub(super) fn execute_chain(
    chain: &CommandChain,
    options: &ExecutionOptions<'_>,
    backend: &Path,
    foreground: bool,
) -> Result<ExitStatus, Error> {
    let Some(first) = chain
        .programs
        .first()
        .and_then(|pipeline| pipeline.commands.first())
    else {
        return Err(Error::EmptyCommand);
    };
    let pipelines = chain
        .programs
        .iter()
        .map(|pipeline| {
            pipeline
                .commands
                .iter()
                .map(|command| Stage {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                })
                .collect::<Vec<_>>()
        })
        .map(|mut pipeline| {
            if let Some(last) = pipeline.last_mut() {
                last.arguments.extend_from_slice(options.passthrough);
            }
            pipeline
        })
        .collect::<Vec<_>>();
    let operators = chain
        .operators
        .iter()
        .map(|operator| match operator {
            neotales_process::ChainOperator::And => "&&",
            neotales_process::ChainOperator::Or => "||",
            neotales_process::ChainOperator::Sequence => ";",
        })
        .map(str::to_owned)
        .collect();
    execute_request(
        &first.program,
        &[],
        pipelines,
        operators,
        options,
        backend,
        foreground,
    )
}

pub(super) fn execute_argv(
    program: &str,
    arguments: &[String],
    options: &ExecutionOptions<'_>,
    backend: &Path,
    foreground: bool,
) -> Result<ExitStatus, Error> {
    let mut arguments = arguments.to_vec();
    arguments.extend_from_slice(options.passthrough);
    execute_request(
        program,
        &arguments,
        Vec::new(),
        Vec::new(),
        options,
        backend,
        foreground,
    )
}

#[allow(clippy::too_many_lines)]
fn execute_request(
    program: &str,
    arguments: &[String],
    pipelines: Vec<Vec<Stage>>,
    operators: Vec<String>,
    options: &ExecutionOptions<'_>,
    backend: &Path,
    foreground: bool,
) -> Result<ExitStatus, Error> {
    if (options.is_cancelled)() {
        return Err(Error::Cancelled);
    }
    verify_current_executable(backend)?;
    // Hash before launching: the helper's bounded request-read deadline must
    // not run while this process hashes a large debug binary.
    let binary = std::fs::read("/proc/self/exe").map_err(start_error)?;
    let binary_sha256 = digest_hex(&binary);
    // Startup has a separate absolute deadline and remains cancellable.
    // The action budget begins only once the supervisor has spawned a child.
    let started = Instant::now();
    let startup_options = ExecutionOptions {
        working_directory: options.working_directory,
        environment: options.environment,
        passthrough: options.passthrough,
        is_cancelled: options.is_cancelled,
        timeout: Some(STARTUP_TIMEOUT),
    };
    let startup = &startup_options;
    check_execution(started, startup.timeout, startup.is_cancelled)?;
    // Hold the advisory lease before a supervisor can inspect or change the
    // foreground process group.
    let _foreground_lease = if foreground {
        acquire_foreground_lease(startup.is_cancelled, startup.timeout, started)?
    } else {
        None
    };
    let (mut parent, child_socket) = UnixStream::pair().map_err(start_error)?;
    parent
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(start_error)?;
    parent
        .set_write_timeout(Some(poll_timeout(
            started,
            startup.timeout,
            startup.is_cancelled,
            Duration::from_secs(3),
        )?))
        .map_err(start_error)?;
    let (stdin, control) = duplicate_startup_sockets(&parent, &child_socket, UnixStream::try_clone)
        .map_err(start_error)?;
    if !cfg!(target_os = "linux") {
        return Err(Error::Internal(
            "managed supervisor unavailable on this platform",
        ));
    }
    let mode = "--neoenv-owned-supervisor-pidfd-v1";
    let mut command = Command::new("/proc/self/exe");
    command.arg(mode);
    #[cfg(all(test, target_os = "linux"))]
    if TRICKLE_SUPERVISOR.with(std::cell::Cell::get) || EXIT_SUPERVISOR.with(std::cell::Cell::get) {
        command = Command::new("/usr/bin/python3");
        command
            .args([
                "-c",
                include_str!("../../tests/support/trickle_supervisor.py"),
            ])
            .arg(env!("CARGO_PKG_VERSION"));
        if EXIT_SUPERVISOR.with(std::cell::Cell::get) {
            command.arg("exit");
        }
    }
    #[cfg(all(test, target_os = "linux"))]
    WITHHOLD_PIDFD_MARKER.with(|marker| {
        if let Some(path) = marker.borrow().as_ref() {
            command = Command::new("/usr/bin/python3");
            command
                .args([
                    "-c",
                    include_str!("../../tests/support/trickle_supervisor.py"),
                    env!("CARGO_PKG_VERSION"),
                    "withhold",
                ])
                .arg(path);
        }
    });
    let spawned = command
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(stdin)))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(start_error)?;
    // `Command` retains its configured stdin descriptor after `spawn`. The
    // host must close that copy of the peer endpoint, or helper exit cannot
    // produce EOF on the control socket.
    drop(command);
    // Install the reap guard immediately after spawn, before any handshake or
    // fallible protocol setup.
    let mut child = ChildGuard {
        child: Some(spawned),
        control: Some(control),
        #[cfg(target_os = "linux")]
        pidfd: None,
        #[cfg(target_os = "linux")]
        pidfd_received: false,
    };
    #[cfg(all(test, target_os = "linux"))]
    if WITHHOLD_PIDFD_MARKER.with(|marker| marker.borrow().is_some()) {
        let pid = rustix::process::Pid::from_child(child.child.as_ref().unwrap());
        let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
        WITHHOLD_CHILD_PIDFD.with(|slot| *slot.borrow_mut() = Some(fd));
    }
    drop(child_socket);
    let mut execution_started = started;
    let mut launching = true;
    let result = (|| {
        write_request(&mut parent, REQUEST, started, startup)?;
        #[cfg(target_os = "linux")]
        {
            child.pidfd = Some(receive_pidfd_poll(&parent, started, startup)?);
            child.pidfd_received = true;
            check_execution(started, startup.timeout, startup.is_cancelled)?;
            #[cfg(all(test, target_os = "linux"))]
            if TRICKLE_SUPERVISOR.with(std::cell::Cell::get)
                || EXIT_SUPERVISOR.with(std::cell::Cell::get)
            {
                TRICKLE_PIDFD.with(|slot| {
                    *slot.borrow_mut() = Some(child.pidfd.as_ref().unwrap().try_clone().unwrap());
                });
            }
            parent
                .set_read_timeout(Some(Duration::from_millis(50)))
                .map_err(start_error)?;
        }
        let banner = read_protocol_line(
            &mut parent,
            started,
            startup,
            Some(Instant::now() + Duration::from_secs(3)),
        )?;
        let expected = format!("NEOENV-OWNED/1 {}\n", env!("CARGO_PKG_VERSION"));
        if banner != expected.as_bytes() {
            return Err(Error::Internal("owned supervisor identity mismatch"));
        }
        let request = Run {
            version: env!("CARGO_PKG_VERSION"),
            binary_sha256,
            program,
            arguments,
            cwd: options.working_directory.display().to_string(),
            environment: options.environment,
            timeout_ms: options
                .timeout
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
            pipelines,
            operators,
            foreground,
        };
        let bytes = serde_json::to_vec(&request)
            .map_err(|_| Error::Internal("failed to encode supervisor request"))?;
        let size = u32::try_from(bytes.len())
            .map_err(|_| Error::Internal("supervisor request too large"))?;
        write_request(&mut parent, &size.to_be_bytes(), started, startup)?;
        write_request(&mut parent, &bytes, started, startup)?;
        if foreground {
            send_stdin(&parent, started, startup)?;
        }
        let acknowledgement = read_response(&mut parent, started, startup)?;
        if acknowledgement != b"STARTED\n" {
            return Err(Error::Internal("invalid supervisor start acknowledgement"));
        }
        execution_started = Instant::now();
        launching = false;
        let response = read_response(&mut parent, execution_started, options)?;
        parse_supervisor_response(&response)
    })();
    let result = match result {
        Err(Error::TimedOut) if launching => Err(Error::Internal("supervisor startup timed out")),
        other => other,
    };
    finish_request(
        result,
        &parent,
        &mut child,
        execution_started,
        options.timeout,
    )
}

fn parse_supervisor_response(response: &[u8]) -> Result<ExitStatus, Error> {
    let line = std::str::from_utf8(response)
        .map_err(|_| Error::Internal("invalid supervisor response"))?;
    if line == "TIMEOUT\n" {
        return Err(Error::TimedOut);
    }
    if line == "CANCELLED\n" {
        return Err(Error::Cancelled);
    }
    let raw = line
        .strip_prefix("EXIT ")
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or(Error::Internal("invalid supervisor result"))?;
    Ok(ExitStatus::from_raw(raw))
}

fn finish_request(
    result: Result<ExitStatus, Error>,
    parent: &UnixStream,
    child: &mut ChildGuard,
    started: Instant,
    timeout: Option<Duration>,
) -> Result<ExitStatus, Error> {
    match result {
        Err(primary) => {
            let _ = parent.shutdown(std::net::Shutdown::Both);
            Err(append_cleanup(primary, child.cleanup_with_retries()))
        }
        Ok(status) => {
            child.reap(started, timeout)?;
            Ok(status)
        }
    }
}

fn append_cleanup(primary: Error, cleanup: Result<(), Error>) -> Error {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => Error::Cleanup {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
    }
}

fn check_execution(
    started: Instant,
    timeout: Option<Duration>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), Error> {
    if cancelled() {
        return Err(Error::Cancelled);
    }
    if timeout.is_some_and(|limit| started.elapsed() >= limit) {
        return Err(Error::TimedOut);
    }
    Ok(())
}

fn poll_timeout(
    started: Instant,
    timeout: Option<Duration>,
    cancelled: &dyn Fn() -> bool,
    maximum: Duration,
) -> Result<Duration, Error> {
    check_execution(started, timeout, cancelled)?;
    Ok(timeout
        .map_or(maximum, |limit| {
            limit.saturating_sub(started.elapsed()).min(maximum)
        })
        .max(Duration::from_millis(1)))
}

fn operation_error(
    error: std::io::Error,
    started: Instant,
    options: &ExecutionOptions<'_>,
) -> Error {
    check_execution(started, options.timeout, options.is_cancelled)
        .err()
        .unwrap_or_else(|| start_error(error))
}

fn write_request(
    socket: &mut UnixStream,
    bytes: &[u8],
    started: Instant,
    options: &ExecutionOptions<'_>,
) -> Result<(), Error> {
    let mut written = 0;
    let mut idle_deadline = Instant::now() + Duration::from_secs(3);
    while written < bytes.len() {
        let mut timeout = poll_timeout(
            started,
            options.timeout,
            options.is_cancelled,
            Duration::from_millis(50),
        )?;
        let idle_remaining = idle_deadline.saturating_duration_since(Instant::now());
        if idle_remaining.is_zero() {
            return Err(Error::Internal("supervisor request write timed out"));
        }
        timeout = timeout.min(idle_remaining).max(Duration::from_millis(1));
        socket
            .set_write_timeout(Some(timeout))
            .map_err(start_error)?;
        let end = written.saturating_add(16 * 1024).min(bytes.len());
        match socket.write(&bytes[written..end]) {
            Ok(0) => return Err(Error::Internal("supervisor closed during request")),
            Ok(count) => {
                #[cfg(all(test, target_os = "linux"))]
                if bytes.len() >= 512_000 {
                    REQUEST_WRITE_PROGRESS.with(|calls| calls.set(calls.get() + 1));
                }
                written += count;
                idle_deadline = Instant::now() + Duration::from_secs(3);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(operation_error(error, started, options)),
        }
    }
    check_execution(started, options.timeout, options.is_cancelled)
}

fn read_response(
    socket: &mut UnixStream,
    started: Instant,
    options: &ExecutionOptions<'_>,
) -> Result<Vec<u8>, Error> {
    read_protocol_line(socket, started, options, None)
}

fn read_protocol_line(
    socket: &mut UnixStream,
    started: Instant,
    options: &ExecutionOptions<'_>,
    startup_deadline: Option<Instant>,
) -> Result<Vec<u8>, Error> {
    let mut response = Vec::new();
    let mut chunk = [0; MAX_RESPONSE_LINE];
    loop {
        let mut timeout = poll_timeout(
            started,
            options.timeout,
            options.is_cancelled,
            Duration::from_millis(50),
        )?;
        if let Some(deadline) = startup_deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Internal("supervisor startup timed out"));
            }
            timeout = timeout.min(remaining).max(Duration::from_millis(1));
        }
        socket
            .set_read_timeout(Some(timeout))
            .map_err(start_error)?;
        let remaining = MAX_RESPONSE_LINE
            .checked_sub(response.len())
            .filter(|remaining| *remaining > 0)
            .ok_or(Error::Internal("invalid supervisor response"))?;
        // Read one byte at a time: STARTED and the final result can be
        // delivered together for a short-lived child.
        match socket.read(&mut chunk[..remaining.min(1)]) {
            Ok(0) => return Err(Error::Internal("supervisor closed without a result")),
            Ok(count) => {
                check_execution(started, options.timeout, options.is_cancelled)?;
                if startup_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(Error::Internal("supervisor startup timed out"));
                }
                #[cfg(all(test, target_os = "linux"))]
                if startup_deadline.is_none() && TRICKLE_SUPERVISOR.with(std::cell::Cell::get) {
                    TRICKLE_BYTES.with(|bytes| bytes.set(bytes.get() + count));
                }
                response.extend_from_slice(&chunk[..count]);
                if let Some(index) = response.iter().position(|byte| *byte == b'\n') {
                    if index + 1 != response.len() {
                        return Err(Error::Internal("invalid supervisor response"));
                    }
                    return Ok(response);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(operation_error(error, started, options)),
        }
    }
}

fn digest_hex(input: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input);
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        output.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        output.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    output
}

fn duplicate_startup_sockets(
    parent: &UnixStream,
    child: &UnixStream,
    mut duplicate: impl FnMut(&UnixStream) -> std::io::Result<UnixStream>,
) -> std::io::Result<(UnixStream, UnixStream)> {
    // Both potentially failing duplications happen before any child exists.
    Ok((duplicate(child)?, duplicate(parent)?))
}

#[cfg(target_os = "linux")]
fn acquire_foreground_lease(
    cancelled: &dyn Fn() -> bool,
    timeout: Option<Duration>,
    started: Instant,
) -> Result<Option<std::fs::File>, Error> {
    use nix::{
        errno::Errno,
        fcntl::{FcntlArg, fcntl},
        libc,
    };
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(tty) => tty,
        Err(error) if matches!(error.raw_os_error(), Some(6 | 19 | 2)) => return Ok(None),
        Err(error) => return Err(start_error(error)),
    };
    // /dev/tty is one shared inode. Linux exposes the controlling device's
    // encoded dev_t as field 7 of /proc/self/stat. Use that as an OFD lock
    // offset so threads and processes on the same device contend, while
    // different terminals use independent bytes.
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(start_error)?;
    let tail = stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(Error::Internal("failed to identify terminal"))?;
    let device: i32 = tail
        .split_whitespace()
        .nth(4)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(Error::Internal("failed to identify terminal"))?;
    let device = u32::from_ne_bytes(device.to_ne_bytes());
    let lock = libc::flock {
        l_type: libc::F_WRLCK
            .try_into()
            .map_err(|_| Error::Internal("invalid terminal lock type"))?,
        l_whence: libc::SEEK_SET
            .try_into()
            .map_err(|_| Error::Internal("invalid terminal lock origin"))?,
        l_start: i64::from(device),
        l_len: 1,
        l_pid: 0,
    };
    loop {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            return Err(Error::TimedOut);
        }
        match fcntl(&tty, FcntlArg::F_OFD_SETLK(&lock)) {
            Ok(_) => return Ok(Some(tty)),
            Err(Errno::EAGAIN | Errno::EACCES) => {
                if has_terminal_lease_ancestor(&tty, device)? {
                    return Err(Error::Internal(
                        "nested foreground nenv cannot acquire its ancestor's terminal lease",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(Error::Internal("failed to acquire terminal lease")),
        }
    }
}

#[cfg(target_os = "linux")]
fn has_terminal_lease_ancestor(tty: &std::fs::File, device: u32) -> Result<bool, Error> {
    has_terminal_lease_ancestor_at(tty, device, Path::new("/proc"), std::process::id())
}

#[cfg(target_os = "linux")]
fn has_terminal_lease_ancestor_at(
    tty: &std::fs::File,
    device: u32,
    proc_root: &Path,
    self_pid: u32,
) -> Result<bool, Error> {
    use std::os::unix::fs::MetadataExt;
    let tty_metadata = tty.metadata().map_err(ancestry_error)?;
    let mut pid = self_pid;
    let mut session = None;
    for _ in 0..128 {
        let proc_dir = proc_root.join(pid.to_string());
        let stat = std::fs::read_to_string(proc_dir.join("stat")).map_err(ancestry_error)?;
        let tail = stat
            .rsplit_once(')')
            .map(|(_, tail)| tail)
            .ok_or(Error::Internal(ANCESTRY_UNAVAILABLE))?;
        let fields: Vec<_> = tail.split_whitespace().collect();
        let parent = fields
            .get(1)
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(Error::Internal(ANCESTRY_UNAVAILABLE))?;
        let current_session = fields
            .get(3)
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(Error::Internal(ANCESTRY_UNAVAILABLE))?;
        if session.is_some_and(|expected| expected != current_session) {
            return Ok(false);
        }
        session = Some(current_session);
        if pid != self_pid {
            let fds = std::fs::read_dir(proc_dir.join("fd")).map_err(ancestry_error)?;
            for entry in fds {
                let entry = entry.map_err(ancestry_error)?;
                let metadata = match std::fs::metadata(entry.path()) {
                    Ok(metadata) => metadata,
                    Err(error) => return Err(ancestry_error(error)),
                };
                if metadata.dev() != tty_metadata.dev() || metadata.ino() != tty_metadata.ino() {
                    continue;
                }
                let info = match std::fs::read_to_string(
                    proc_dir.join("fdinfo").join(entry.file_name()),
                ) {
                    Ok(info) => info,
                    Err(error) => return Err(ancestry_error(error)),
                };
                if info
                    .lines()
                    .filter_map(|line| line.strip_prefix("lock:"))
                    .any(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        fields.get(1) == Some(&"OFDLCK")
                            && fields.get(6).and_then(|value| value.parse::<u64>().ok())
                                == Some(u64::from(device))
                            && fields.get(7).and_then(|value| value.parse::<u64>().ok())
                                == Some(u64::from(device))
                    })
                {
                    return Ok(true);
                }
            }
        }
        if parent == 0 || parent == pid {
            return Ok(false);
        }
        pid = parent;
    }
    Err(Error::Internal(
        "terminal ancestry exceeds inspection limit",
    ))
}

#[cfg(target_os = "linux")]
fn ancestry_error(_error: std::io::Error) -> Error {
    Error::Internal(ANCESTRY_UNAVAILABLE)
}

#[cfg(not(target_os = "linux"))]
fn acquire_foreground_lease(
    _cancelled: &dyn Fn() -> bool,
    _timeout: Option<Duration>,
    _started: Instant,
) -> Result<Option<std::fs::File>, Error> {
    Err(Error::Internal(
        "managed supervisor unavailable on this platform",
    ))
}

fn verify_current_executable(backend: &Path) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let current = std::env::current_exe().map_err(start_error)?;
    let current = std::fs::metadata(current).map_err(start_error)?;
    let backend = std::fs::metadata(backend).map_err(start_error)?;
    if current.dev() != backend.dev() || current.ino() != backend.ino() {
        return Err(Error::Internal(
            "owned supervisor must be the current CLI executable",
        ));
    }
    Ok(())
}

fn send_stdin(
    socket: &UnixStream,
    started: Instant,
    options: &ExecutionOptions<'_>,
) -> Result<(), Error> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd};
    let stdin = std::io::stdin();
    let fds = [stdin.as_fd()];
    let idle_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut timeout = poll_timeout(
            started,
            options.timeout,
            options.is_cancelled,
            Duration::from_millis(50),
        )?;
        let idle_remaining = idle_deadline.saturating_duration_since(Instant::now());
        if idle_remaining.is_zero() {
            return Err(Error::Internal("stdin descriptor send timed out"));
        }
        timeout = timeout.min(idle_remaining).max(Duration::from_millis(1));
        socket
            .set_write_timeout(Some(timeout))
            .map_err(start_error)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(Error::Internal(
                "stdin descriptor control buffer unavailable",
            ));
        }
        match sendmsg(
            socket,
            &[IoSlice::new(b"I")],
            &mut ancillary,
            SendFlags::empty(),
        ) {
            Ok(1) => return check_execution(started, options.timeout, options.is_cancelled),
            Ok(_) => return Err(Error::Internal("invalid stdin descriptor send")),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
            Err(error) => return Err(operation_error(error.into(), started, options)),
        }
    }
}

#[cfg(target_os = "linux")]
fn receive_pidfd(socket: &UnixStream) -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    use std::{io::IoSliceMut, mem::MaybeUninit};
    let mut data = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let result = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut data)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if result.bytes != 1 || data != *b"P" {
        return Err(std::io::Error::other("invalid supervisor identity message"));
    }
    ancillary
        .drain()
        .find_map(|message| match message {
            RecvAncillaryMessage::ScmRights(mut rights) => rights.next(),
            _ => None,
        })
        .ok_or_else(|| std::io::Error::other("missing supervisor pidfd"))
}

#[cfg(target_os = "linux")]
fn receive_pidfd_poll(
    socket: &UnixStream,
    started: Instant,
    options: &ExecutionOptions<'_>,
) -> Result<std::os::fd::OwnedFd, Error> {
    receive_pidfd_until(
        socket,
        started,
        options,
        Instant::now() + Duration::from_secs(3),
    )
}

#[cfg(target_os = "linux")]
fn receive_pidfd_until(
    socket: &UnixStream,
    started: Instant,
    options: &ExecutionOptions<'_>,
    startup_deadline: Instant,
) -> Result<std::os::fd::OwnedFd, Error> {
    loop {
        let mut timeout = poll_timeout(
            started,
            options.timeout,
            options.is_cancelled,
            Duration::from_millis(50),
        )?;
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Internal("supervisor pidfd startup timed out"));
        }
        timeout = timeout.min(remaining).max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(timeout))
            .map_err(start_error)?;
        match receive_pidfd(socket) {
            // The caller installs the received descriptor in its guard before
            // checking cancellation again, so identity is never discarded.
            Ok(fd) => return Ok(fd),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(operation_error(error, started, options)),
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
    control: Option<UnixStream>,
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "linux")]
    pidfd_received: bool,
}

impl ChildGuard {
    fn reap(&mut self, started: Instant, timeout: Option<Duration>) -> Result<(), Error> {
        let maximum = Instant::now() + Duration::from_secs(3);
        let deadline = timeout
            .and_then(|limit| started.checked_add(limit))
            .map_or(maximum, |deadline| deadline.min(maximum));
        match self.wait_pidfd_until(deadline) {
            Ok(true) => {
                self.control.take();
                self.child.take();
                Ok(())
            }
            Ok(false) => {
                let primary = if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                    Error::TimedOut
                } else {
                    Error::Internal("supervisor did not exit after reporting its result")
                };
                Err(append_cleanup(primary, self.cleanup_with_retries()))
            }
            Err(primary) => Err(append_cleanup(primary, self.cleanup_with_retries())),
        }
    }

    fn cleanup_with_retries(&mut self) -> Result<(), Error> {
        match self.cancel_and_reap() {
            Ok(()) => Ok(()),
            Err(first) if self.child.is_none() => Err(first),
            Err(first) => match self.cancel_and_reap() {
                Ok(()) => Ok(()),
                Err(last) => Err(append_cleanup(first, Err(last))),
            },
        }
    }

    fn cancel_and_reap(&mut self) -> Result<(), Error> {
        if let Some(control) = self.control.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
        #[cfg(target_os = "linux")]
        if self.pidfd_received {
            if self.pidfd.is_none() {
                self.child.take();
                return Ok(());
            }
            self.signal_pidfd(rustix::process::Signal::CONT)?;
            if self.wait_pidfd_until(Instant::now() + Duration::from_secs(2))? {
                self.child.take();
                return Ok(());
            }
            self.signal_pidfd(rustix::process::Signal::KILL)?;
            if !self.wait_pidfd_until(Instant::now() + Duration::from_secs(3))? {
                return Err(Error::Internal(
                    "supervisor did not exit after forced termination",
                ));
            }
            self.child.take();
            return Err(Error::Internal(
                "supervisor required forced termination; descendants may remain",
            ));
        }
        // Before pidfd transfer this is safe only under the explicit host
        // contract: SIGCHLD is waitable and no other waiter reaps our child.
        if let Some(child) = self.child.as_mut() {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match child.kill() {
                    Ok(()) => break,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) if child.try_wait().map_err(start_error)?.is_some() => {
                        self.child.take();
                        return Ok(());
                    }
                    Err(_) => {
                        return Err(Error::Internal("failed to terminate starting supervisor"));
                    }
                }
            }
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.child.take();
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(error) => return Err(start_error(error)),
                }
                if Instant::now() >= deadline {
                    return Err(Error::Internal("starting supervisor did not exit"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn signal_pidfd(&self, signal: rustix::process::Signal) -> Result<(), Error> {
        use std::os::fd::AsFd;
        let fd = self
            .pidfd
            .as_ref()
            .ok_or(Error::Internal("supervisor identity unavailable"))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            #[cfg(test)]
            let injected = if SIGNAL_PERSISTENT.with(std::cell::Cell::get) {
                Some(rustix::io::Errno::IO)
            } else {
                SIGNAL_FAULT.with(std::cell::Cell::take)
            };
            #[cfg(not(test))]
            let injected: Option<rustix::io::Errno> = None;
            let result = injected.map_or_else(
                || rustix::process::pidfd_send_signal(fd.as_fd(), signal),
                Err,
            );
            match result {
                Ok(()) | Err(rustix::io::Errno::SRCH) => return Ok(()),
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN)
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(Error::Internal("failed to signal owned supervisor")),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_pidfd_with(
        &mut self,
        deadline: Instant,
        mut wait: impl FnMut(&std::os::fd::OwnedFd) -> Result<bool, rustix::io::Errno>,
    ) -> Result<bool, Error> {
        loop {
            let fd = self
                .pidfd
                .as_ref()
                .ok_or(Error::Internal("supervisor identity unavailable"))?;
            match wait(fd) {
                Ok(true) => {
                    self.pidfd.take();
                    return Ok(true);
                }
                Ok(false) => return Ok(false),
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {
                    if Instant::now() >= deadline {
                        return Ok(false);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(rustix::io::Errno::CHILD) => {
                    return Err(Error::Internal("supervisor was reaped externally"));
                }
                Err(_) => return Err(Error::Internal("failed to wait for supervisor pidfd")),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_pidfd_until(&mut self, deadline: Instant) -> Result<bool, Error> {
        use std::os::fd::AsFd;
        loop {
            if self.poll_pidfd_with(deadline, |fd| {
                #[cfg(test)]
                if let Some(error) = WAIT_FAULT.with(std::cell::Cell::take) {
                    return Err(error);
                }
                rustix::process::waitid(
                    rustix::process::WaitId::PidFd(fd.as_fd()),
                    rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
                )
                .map(|status| status.is_some())
            })? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_pidfd_until(&mut self, _deadline: Instant) -> Result<bool, Error> {
        Err(Error::Internal(
            "managed supervisor unavailable on this platform",
        ))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        for _ in 0..2 {
            if self.child.is_none() {
                return;
            }
            if self.cancel_and_reap().is_ok() {
                return;
            }
        }
    }
}

fn start_error(error: std::io::Error) -> Error {
    // Do not echo OS errors that can include task paths or other input.
    drop(error);
    Error::Internal("owned supervisor I/O failed")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        ANCESTRY_UNAVAILABLE, ChildGuard, EXIT_SUPERVISOR, REQUEST_WRITE_PROGRESS, SIGNAL_FAULT,
        SIGNAL_PERSISTENT, TRICKLE_BYTES, TRICKLE_PIDFD, TRICKLE_SUPERVISOR, WAIT_FAULT,
        WITHHOLD_CHILD_PIDFD, WITHHOLD_PIDFD_MARKER, append_cleanup, duplicate_startup_sockets,
        execute_request, finish_request, has_terminal_lease_ancestor_at, parse_supervisor_response,
        read_response, receive_pidfd, receive_pidfd_until, send_stdin, write_request,
    };
    use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions, pidfd_open, waitid};
    use std::{
        io::{self, Read, Write},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
    };

    fn guard_for_helper(script: &str) -> (ChildGuard, UnixStream, Pid) {
        let (parent, helper) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let stdout = helper.try_clone().unwrap();
        let child = Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::from(OwnedFd::from(helper)))
            .stdout(Stdio::from(OwnedFd::from(stdout)))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = Pid::from_child(&child);
        (
            ChildGuard {
                child: Some(child),
                control: Some(parent.try_clone().unwrap()),
                pidfd: None,
                pidfd_received: false,
            },
            parent,
            pid,
        )
    }

    fn assert_reaped(pid: Pid) {
        assert_eq!(
            waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG
            )
            .unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    fn clone_failures_happen_before_spawn() {
        let (parent, child) = UnixStream::pair().unwrap();
        for failed_call in 1..=2 {
            let mut calls = 0;
            let result = duplicate_startup_sockets(&parent, &child, |stream| {
                calls += 1;
                if calls == failed_call {
                    Err(io::Error::other("injected clone failure"))
                } else {
                    stream.try_clone()
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, failed_call);
        }
    }

    #[test]
    fn inaccessible_ancestor_fails_closed_with_named_diagnostic() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join("101");
        let ancestor = root.path().join("102");
        std::fs::create_dir(&current).unwrap();
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::write(current.join("stat"), "101 (self) S 102 101 101").unwrap();
        std::fs::write(ancestor.join("stat"), "102 (ancestor) S 1 101 101").unwrap();
        let fds = ancestor.join("fd");
        std::fs::create_dir(&fds).unwrap();
        std::fs::set_permissions(&fds, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A privileged test runner may bypass mode bits. A missing proc entry
        // still exercises the same fail-closed inaccessible-ancestry path.
        let bypasses_mode_bits = std::fs::read_dir(&fds).is_ok();
        if bypasses_mode_bits {
            std::fs::remove_dir(&fds).unwrap();
        }
        let tty = tempfile::tempfile().unwrap();
        let error = has_terminal_lease_ancestor_at(&tty, 1, root.path(), 101).unwrap_err();
        if !bypasses_mode_bits {
            std::fs::set_permissions(&fds, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(error.to_string().contains(ANCESTRY_UNAVAILABLE), "{error}");
    }

    #[test]
    fn primary_failure_keeps_cleanup_diagnostic() {
        for (primary, expected) in [
            (neotales_process::Error::Cancelled, "execution cancelled"),
            (neotales_process::Error::TimedOut, "execution timed out"),
            (
                neotales_process::Error::Internal("bad protocol"),
                "bad protocol",
            ),
        ] {
            let error = append_cleanup(
                primary,
                Err(neotales_process::Error::Internal(
                    "injected cleanup failure",
                )),
            );
            let text = error.to_string();
            assert!(text.starts_with(expected), "{text}");
            assert!(
                text.contains("cleanup failed: injected cleanup failure"),
                "{text}"
            );
            assert!(text.contains("descendants may remain"), "{text}");
        }
    }

    fn slow_request_stops(cancel_instead_of_timeout: bool) {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let peer_stopped = Arc::clone(&stopped);
        let reader = std::thread::spawn(move || {
            let mut buffer = [0; 8192];
            let mut received = 0;
            while !peer_stopped.load(Ordering::Acquire) {
                match peer.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => received += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("slow peer read: {error}"),
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            received
        });
        let environment = std::collections::BTreeMap::new();
        let started = std::time::Instant::now();
        let cancelled = || {
            cancel_instead_of_timeout && started.elapsed() >= std::time::Duration::from_millis(600)
        };
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: (!cancel_instead_of_timeout).then_some(std::time::Duration::from_millis(600)),
        };
        REQUEST_WRITE_PROGRESS.with(|calls| calls.set(0));
        let result = write_request(&mut client, &vec![b'x'; 1_000_000], started, &options);
        let progress = REQUEST_WRITE_PROGRESS.with(std::cell::Cell::get);
        let elapsed = started.elapsed();
        stopped.store(true, Ordering::Release);
        client.shutdown(std::net::Shutdown::Both).unwrap();
        let received = reader.join().unwrap();
        if cancel_instead_of_timeout {
            assert!(
                matches!(result, Err(neotales_process::Error::Cancelled)),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(neotales_process::Error::TimedOut)),
                "{result:?}"
            );
        }
        assert!(
            progress >= 2,
            "peer did not produce repeated write progress: {progress}"
        );
        assert!(
            received > 0 && received < 1_000_000,
            "received {received} bytes"
        );
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn slow_request_writer_observes_absolute_deadline() {
        slow_request_stops(false);
    }

    #[test]
    fn slow_request_writer_observes_cancellation() {
        slow_request_stops(true);
    }

    #[test]
    fn blocked_stdin_descriptor_send_observes_cancellation() {
        let (mut client, _peer) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        loop {
            match client.write(&[b'x'; 8192]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill socket: {error}"),
            }
        }
        client.set_nonblocking(false).unwrap();
        let environment = std::collections::BTreeMap::new();
        let started = std::time::Instant::now();
        let cancelled = || started.elapsed() >= std::time::Duration::from_millis(200);
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: None,
        };
        let result = send_stdin(&client, started, &options);
        assert!(
            matches!(result, Err(neotales_process::Error::Cancelled)),
            "{result:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn host_deadline_expires_while_partial_response_is_stalled() {
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"EXIT ").unwrap();
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_millis(100)),
        };
        let started = std::time::Instant::now();
        let result = read_response(&mut client, started, &options);
        assert!(matches!(result, Err(neotales_process::Error::TimedOut)));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn response_limit_and_utf8_validation_are_preserved() {
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&[b'x'; 129]).unwrap();
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_secs(1)),
        };
        let error = read_response(&mut client, std::time::Instant::now(), &options).unwrap_err();
        assert!(error.to_string().contains("invalid supervisor response"));
        assert!(parse_supervisor_response(b"EXIT \xff\n").is_err());
        assert!(parse_supervisor_response(b"not-a-result\n").is_err());
    }

    #[test]
    fn trickling_helper_is_timed_out_and_reaped() {
        let script = "exec /usr/bin/python3 -c 'import sys,time; [(sys.stdout.write(\"x\"),sys.stdout.flush(),time.sleep(.01)) for _ in range(200)]'";
        let (mut guard, mut socket, pid) = guard_for_helper(script);
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_millis(200)),
        };
        let started = std::time::Instant::now();
        let result = read_response(&mut socket, started, &options);
        let result = match result {
            Ok(_) => panic!("trickling helper unexpectedly finished"),
            Err(error) => Err(error),
        };
        let result = finish_request(result, &socket, &mut guard, started, options.timeout);
        assert!(matches!(result, Err(neotales_process::Error::TimedOut)));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_reaped(pid);
    }

    #[test]
    fn complete_client_times_out_and_reaps_trickling_supervisor() {
        use std::os::fd::AsFd;
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_secs(1)),
        };
        let executable = std::env::current_exe().unwrap();
        TRICKLE_BYTES.with(|bytes| bytes.set(0));
        TRICKLE_SUPERVISOR.with(|flag| flag.set(true));
        let started = std::time::Instant::now();
        let result = execute_request(
            "ignored",
            &[],
            Vec::new(),
            Vec::new(),
            &options,
            &executable,
            false,
        );
        TRICKLE_SUPERVISOR.with(|flag| flag.set(false));
        let bytes = TRICKLE_BYTES.with(std::cell::Cell::get);
        assert!(
            matches!(result, Err(neotales_process::Error::TimedOut)),
            "{result:?}"
        );
        assert!(bytes >= 3, "helper did not actually trickle: {bytes} bytes");
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        let pidfd = TRICKLE_PIDFD
            .with(|slot| slot.borrow_mut().take())
            .expect("helper reached protocol");
        assert_eq!(
            waitid(
                WaitId::PidFd(pidfd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG
            )
            .unwrap_err(),
            rustix::io::Errno::CHILD,
            "trickling supervisor must already be reaped"
        );
    }

    #[test]
    fn complete_client_observes_eof_when_supervisor_exits_after_request() {
        use std::os::fd::AsFd;
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_secs(3)),
        };
        let executable = std::env::current_exe().unwrap();
        EXIT_SUPERVISOR.with(|flag| flag.set(true));
        let started = std::time::Instant::now();
        let result = execute_request(
            "ignored",
            &[],
            Vec::new(),
            Vec::new(),
            &options,
            &executable,
            false,
        );
        EXIT_SUPERVISOR.with(|flag| flag.set(false));
        assert!(
            matches!(
                result,
                Err(neotales_process::Error::Internal(
                    "supervisor closed without a result"
                ))
            ),
            "{result:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        let pidfd = TRICKLE_PIDFD
            .with(|slot| slot.borrow_mut().take())
            .expect("helper reached protocol");
        assert_eq!(
            waitid(
                WaitId::PidFd(pidfd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG
            )
            .unwrap_err(),
            rustix::io::Errno::CHILD,
        );
    }

    #[test]
    fn cancellation_interrupts_withheld_pidfd_and_reaps_helper() {
        use std::os::fd::AsFd;
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("request-received");
        WITHHOLD_PIDFD_MARKER.with(|slot| *slot.borrow_mut() = Some(marker.clone()));
        let cancellation_seen = std::cell::Cell::new(None);
        let cancelled = || {
            if marker.exists() {
                if cancellation_seen.get().is_none() {
                    cancellation_seen.set(Some(std::time::Instant::now()));
                }
                true
            } else {
                false
            }
        };
        let environment = std::collections::BTreeMap::new();
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: None,
        };
        let executable = std::env::current_exe().unwrap();
        let result = execute_request(
            "ignored",
            &[],
            Vec::new(),
            Vec::new(),
            &options,
            &executable,
            false,
        );
        WITHHOLD_PIDFD_MARKER.with(|slot| slot.borrow_mut().take());
        assert!(
            matches!(result, Err(neotales_process::Error::Cancelled)),
            "{result:?}"
        );
        let seen = cancellation_seen
            .get()
            .expect("helper received the request");
        assert!(
            seen.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            seen.elapsed()
        );
        let pidfd = WITHHOLD_CHILD_PIDFD
            .with(|slot| slot.borrow_mut().take())
            .expect("helper started");
        assert_eq!(
            waitid(
                WaitId::PidFd(pidfd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG
            )
            .unwrap_err(),
            rustix::io::Errno::CHILD,
            "withholding supervisor must already be reaped"
        );
    }

    #[test]
    fn trickling_helper_observes_cancellation_and_is_reaped() {
        let script = "exec /usr/bin/python3 -c 'import sys,time; [(sys.stdout.write(\"x\"),sys.stdout.flush(),time.sleep(.01)) for _ in range(200)]'";
        let (mut guard, mut socket, pid) = guard_for_helper(script);
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        let environment = std::collections::BTreeMap::new();
        let started = std::time::Instant::now();
        let cancelled = || started.elapsed() >= std::time::Duration::from_millis(200);
        let options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: None,
        };
        let result = match read_response(&mut socket, started, &options) {
            Ok(_) => panic!("trickling helper unexpectedly finished"),
            Err(error) => Err(error),
        };
        let result = finish_request(result, &socket, &mut guard, started, None);
        assert!(matches!(result, Err(neotales_process::Error::Cancelled)));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_reaped(pid);
    }

    #[test]
    fn persistent_failure_is_reported_without_library_stderr() {
        const FLAG: &str = "NEOENV_TEST_PERSISTENT_CLEANUP";
        if std::env::var_os(FLAG).is_some() {
            use std::os::fd::AsFd;
            let (mut guard, _parent, _pid) = guard_for_helper("read line");
            let pid = Pid::from_child(guard.child.as_ref().unwrap());
            guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
            guard.pidfd_received = true;
            let cleanup_fd = guard.pidfd.as_ref().unwrap().try_clone().unwrap();
            SIGNAL_PERSISTENT.with(|fault| fault.set(true));
            let error = append_cleanup(
                neotales_process::Error::TimedOut,
                guard.cleanup_with_retries(),
            );
            let text = error.to_string();
            assert!(text.starts_with("execution timed out"), "{text}");
            assert!(text.contains("cleanup failed"), "{text}");
            assert!(text.contains("descendants may remain"), "{text}");
            drop(guard);
            SIGNAL_PERSISTENT.with(|fault| fault.set(false));
            match rustix::process::pidfd_send_signal(
                cleanup_fd.as_fd(),
                rustix::process::Signal::KILL,
            ) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => panic!("test cleanup: {error}"),
            }
            waitid(WaitId::PidFd(cleanup_fd.as_fd()), WaitIdOptions::EXITED)
                .unwrap()
                .unwrap();
            println!("PERSISTENT_CLEANUP_REPORTED");
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tasks::owned_process::tests::persistent_failure_is_reported_without_library_stderr",
                "--nocapture",
            ])
            .env(FLAG, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("PERSISTENT_CLEANUP_REPORTED"));
    }

    #[test]
    fn helper_exit_and_failed_write_before_pidfd_are_reaped() {
        let (mut guard, mut parent, pid) = guard_for_helper("exit 0");
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .unwrap();
        assert!(parent.write_all(b"request").is_err());
        guard.cancel_and_reap().unwrap();
        assert_reaped(pid);
    }

    #[test]
    fn missing_pidfd_before_handoff_closes_control_and_reaps() {
        let (mut guard, parent, pid) = guard_for_helper("printf P; cat >/dev/null");
        assert!(receive_pidfd(&parent).is_err());
        guard.cancel_and_reap().unwrap();
        assert_reaped(pid);
    }

    #[test]
    fn withheld_pidfd_honors_action_and_startup_deadlines() {
        let (client, _peer) = UnixStream::pair().unwrap();
        let environment = std::collections::BTreeMap::new();
        let started = std::time::Instant::now();
        let mut options = neotales_process::ExecutionOptions {
            working_directory: std::path::Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: Some(std::time::Duration::from_millis(150)),
        };
        let result = receive_pidfd_until(
            &client,
            started,
            &options,
            started + std::time::Duration::from_secs(3),
        );
        assert!(
            matches!(result, Err(neotales_process::Error::TimedOut)),
            "{result:?}"
        );
        let started = std::time::Instant::now();
        options.timeout = None;
        let result = receive_pidfd_until(
            &client,
            started,
            &options,
            started + std::time::Duration::from_millis(150),
        );
        assert!(
            matches!(
                result,
                Err(neotales_process::Error::Internal(
                    "supervisor pidfd startup timed out"
                ))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn stopped_helper_before_pidfd_is_killed_and_reaped() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::STOPPED | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .unwrap();
        let started = std::time::Instant::now();
        guard.cancel_and_reap().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert_reaped(pid);
    }

    #[test]
    fn transient_signal_and_wait_errors_retry_during_cancel() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        SIGNAL_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::INTR)));
        WAIT_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::AGAIN)));
        guard.cancel_and_reap().unwrap();
        assert_reaped(pid);
    }

    #[test]
    fn failed_cancel_retains_pidfd_for_drop_retry() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        SIGNAL_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::IO)));
        assert!(guard.cancel_and_reap().is_err());
        assert!(guard.pidfd.is_some());
        assert!(guard.child.is_some());
        drop(guard);
        assert_reaped(pid);
    }

    #[test]
    fn drop_retries_cleanup_after_injected_signal_failure() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        SIGNAL_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::IO)));
        drop(guard);
        assert_reaped(pid);
    }

    #[test]
    fn failed_cancel_wait_retains_pidfd_for_drop_retry() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        WAIT_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::IO)));
        assert!(guard.cancel_and_reap().is_err());
        assert!(guard.pidfd.is_some());
        drop(guard);
        assert_reaped(pid);
    }

    #[test]
    fn drop_retries_cleanup_after_injected_wait_failure() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        WAIT_FAULT.with(|fault| fault.set(Some(rustix::io::Errno::IO)));
        drop(guard);
        assert_reaped(pid);
    }

    #[test]
    fn stopped_helper_after_pidfd_is_continued_and_reaped() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::STOPPED | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .unwrap();
        let started = std::time::Instant::now();
        guard.cancel_and_reap().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert_reaped(pid);
    }

    #[test]
    fn unresponsive_helper_is_killed_by_pidfd_with_a_clear_failure() {
        let (mut guard, _parent, pid) = guard_for_helper("exec /bin/sleep 30");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::STOPPED | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .unwrap();
        let started = std::time::Instant::now();
        let error = guard.cancel_and_reap().unwrap_err();
        assert!(error.to_string().contains("forced termination"));
        assert!(started.elapsed() < std::time::Duration::from_secs(6));
        assert_reaped(pid);
    }

    #[test]
    fn interrupted_pidfd_wait_retries_and_retains_identity() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        let mut calls = 0;
        let ready = guard
            .poll_pidfd_with(
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                |_| {
                    calls += 1;
                    if calls == 1 {
                        Err(rustix::io::Errno::INTR)
                    } else {
                        Ok(false)
                    }
                },
            )
            .unwrap();
        assert!(!ready);
        assert_eq!(calls, 2);
        assert!(guard.pidfd.is_some());
        guard.cancel_and_reap().unwrap();
        assert_reaped(pid);
    }

    #[test]
    fn non_child_wait_error_is_not_reported_as_foreign_reap() {
        let (mut guard, _parent, pid) = guard_for_helper("read line");
        guard.pidfd = Some(pidfd_open(pid, PidfdFlags::empty()).unwrap());
        guard.pidfd_received = true;
        let error = guard
            .poll_pidfd_with(
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                |_| Err(rustix::io::Errno::IO),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to wait for supervisor pidfd")
        );
        assert!(guard.pidfd.is_some());
        guard.cancel_and_reap().unwrap();
        assert_reaped(pid);
    }

    #[test]
    fn foreign_reap_is_reported_by_client_without_touching_another_child() {
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let pidfd = pidfd_open(Pid::from_child(&child), PidfdFlags::empty()).unwrap();
        assert!(child.wait().unwrap().success());
        let mut unrelated = Command::new("/bin/sleep")
            .arg("5")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildGuard {
            child: Some(child),
            control: None,
            pidfd: Some(pidfd),
            pidfd_received: true,
        };
        assert!(guard.reap(std::time::Instant::now(), None).is_err());
        drop(guard);
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }
}

#[cfg(test)]
mod capability_tests {
    #[test]
    fn unavailable_backend_explains_atomic_containment_requirement() {
        let reason = super::unavailable_reason();
        assert!(!reason.is_empty());
    }

    #[test]
    fn owned_backend_capability_is_linux_only() {
        assert_eq!(
            super::supported(Some(std::path::Path::new("/backend"))),
            cfg!(target_os = "linux")
        );
        assert!(!super::supported(None));
    }

    #[test]
    fn foreign_executable_is_not_an_owned_backend() {
        assert!(super::verify_current_executable(std::path::Path::new("/bin/true")).is_err());
        assert!(super::verify_current_executable(&std::env::current_exe().unwrap()).is_ok());
    }
}
