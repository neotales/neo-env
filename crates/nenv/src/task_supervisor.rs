//! Private, single-command supervisor. Not yet connected to the runtime.
//!
//! Only this exec'd process changes its SIGCHLD disposition. No other thread in
//! it waits for children; its waitable leader reserves the numeric group ID
//! until the group has been signalled. The control socket is never passed to
//! the command. Losing the control peer kills the owned group.
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            net::UnixStream,
            process::{CommandExt, ExitStatusExt},
        },
    },
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use rustix::process::{Pid as ChildPid, WaitId, WaitIdOptions, waitid};
use serde::Deserialize;

pub(crate) const MODE: &str = "--neoenv-owned-supervisor-v1";
pub(crate) const ANCHOR_MODE: &str = "--neoenv-terminal-anchor-v1";
#[cfg(target_os = "linux")]
pub(crate) const MANAGED_MODE: &str = "--neoenv-owned-supervisor-pidfd-v1";
const REQUEST: &[u8] = b"NEOENV-OWNED/1\n";
const IO_DEADLINE: Duration = Duration::from_secs(2);
const MAX_REQUEST: usize = 1024 * 1024;

/// A process-group leader for an exclusively owned terminal supervisor.
///
/// The supervisor starts this mode using its own executable, not a task's
/// search path. The pipe is the lifetime: closing it causes the anchor to exit.
pub(crate) fn run_anchor() -> i32 {
    let result = (|| -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(b"NEOENV-TERMINAL-ANCHOR/1\n")?;
        stdout.flush()?;
        io::copy(&mut io::stdin().lock(), &mut io::sink())?;
        Ok(())
    })();
    i32::from(result.is_err())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    version: String,
    binary_sha256: String,
    program: String,
    arguments: Vec<String>,
    cwd: String,
    environment: BTreeMap<String, String>,
    timeout_ms: Option<u64>,
    #[serde(default)]
    pipelines: Vec<Vec<Stage>>,
    #[serde(default)]
    operators: Vec<String>,
    #[serde(default)]
    foreground: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    program: String,
    arguments: Vec<String>,
}

pub(crate) fn run(managed: bool) -> i32 {
    match serve(managed) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[allow(clippy::too_many_lines)]
fn serve(managed: bool) -> io::Result<()> {
    let socket_fd = io::stdin().as_fd().try_clone_to_owned()?;
    let mut socket = UnixStream::from(socket_fd);
    socket.set_read_timeout(Some(IO_DEADLINE))?;
    socket.set_write_timeout(Some(IO_DEADLINE))?;
    let mut request = [0; REQUEST.len()];
    socket.read_exact(&mut request)?;
    if request != REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol version",
        ));
    }

    // signal-hook installs an actual handler with SA_RESTART | SA_SIGINFO,
    // replacing inherited SIG_IGN and SA_NOCLDWAIT rather than changing the
    // embedding process. The signal can remain blocked: waitid does not need
    // delivery. This helper starts no threads or children before registration.
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGCHLD, flag)?;
    #[cfg(target_os = "linux")]
    if managed {
        send_self_pidfd(&socket)?;
    }
    #[cfg(not(target_os = "linux"))]
    if managed {
        return Err(io::Error::other("managed supervisor unsupported"));
    }
    socket.write_all(format!("NEOENV-OWNED/1 {}\n", env!("CARGO_PKG_VERSION")).as_bytes())?;
    let mut size = [0; 4];
    socket.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_REQUEST {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request size"));
    }
    let mut bytes = vec![0; size];
    socket.read_exact(&mut bytes)?;
    let request: Run = serde_json::from_slice(&bytes)?;
    let binary = std::fs::read(std::env::current_exe()?)?;
    let binary_sha256 = digest_hex(&binary);
    if request.version != env!("CARGO_PKG_VERSION")
        || request.binary_sha256 != binary_sha256
        || (request.pipelines.is_empty() && request.program.is_empty())
        || (!request.pipelines.is_empty()
            && (request.pipelines.iter().any(Vec::is_empty)
                || request
                    .pipelines
                    .iter()
                    .flatten()
                    .any(|stage| stage.program.is_empty())
                || request.operators.len() + 1 != request.pipelines.len()
                || request
                    .operators
                    .iter()
                    .any(|operator| !matches!(operator.as_str(), "&&" | "||" | ";"))))
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "binary version"));
    }
    // Darwin cannot safely distinguish an unsignalable live process group
    // from a zombie-only group when killpg returns EPERM. This private legacy
    // mode must not launch anything until it can guarantee owned cleanup.
    #[cfg(target_os = "macos")]
    if !managed {
        socket.write_all(b"ERROR\n")?;
        return Err(io::Error::other("legacy supervisor unsupported on macOS"));
    }
    let foreground_stdin = if request.foreground {
        let stdin = receive_stdin(&socket)?;
        Some(stdin)
    } else {
        None
    };
    socket.set_nonblocking(true)?;
    // EOF or unexpected control data before launch is a refusal, too.
    if control_closed(&socket)? {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "control closed"));
    }
    if !request.pipelines.is_empty() {
        let mut started = None;
        let mut last_status = None;
        for (index, pipeline) in request.pipelines.iter().enumerate() {
            let run = if index == 0 {
                true
            } else {
                match request.operators[index - 1].as_str() {
                    "&&" => last_status.is_some_and(|status: ExitStatus| status.success()),
                    "||" => last_status.is_some_and(|status: ExitStatus| !status.success()),
                    ";" => true,
                    _ => false,
                }
            };
            if run {
                let outcome = if let Some(stdin) = &foreground_stdin {
                    run_foreground(pipeline, &request, &socket, &mut started, stdin)?
                } else {
                    run_pipeline(pipeline, &request, &socket, &mut started)?
                };
                match outcome {
                    PipelineResult::Status(status) => last_status = Some(status),
                    PipelineResult::Timeout => {
                        socket.set_nonblocking(false)?;
                        return socket.write_all(b"TIMEOUT\n");
                    }
                    PipelineResult::Cancelled => {
                        socket.set_nonblocking(false)?;
                        return socket.write_all(b"CANCELLED\n");
                    }
                    PipelineResult::ControlClosed => return Ok(()),
                }
            }
        }
        socket.set_nonblocking(false)?;
        let status = last_status.unwrap_or_else(|| ExitStatus::from_raw(0));
        return socket.write_all(format!("EXIT {}\n", status.into_raw()).as_bytes());
    }
    if let Some(stdin) = &foreground_stdin {
        let stage = Stage {
            program: request.program.clone(),
            arguments: request.arguments.clone(),
        };
        let outcome = run_foreground(&[stage], &request, &socket, &mut None, stdin)?;
        socket.set_nonblocking(false)?;
        return match outcome {
            PipelineResult::Status(status) => {
                socket.write_all(format!("EXIT {}\n", status.into_raw()).as_bytes())
            }
            PipelineResult::Timeout => socket.write_all(b"TIMEOUT\n"),
            PipelineResult::Cancelled => socket.write_all(b"CANCELLED\n"),
            PipelineResult::ControlClosed => Ok(()),
        };
    }
    let child = Command::new(&request.program)
        .args(&request.arguments)
        .current_dir(&request.cwd)
        .env_clear()
        .envs(&request.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn();
    let Ok(child) = child else {
        return socket.write_all(b"ERROR\n");
    };
    let mut child = OwnedChild(Some(child));
    let mut started = None;
    announce_started(&socket, &mut started)?;
    let started = started.expect("child start recorded");
    let outcome = loop {
        let process = child.0.as_ref().expect("owned child");
        let observed = waitid(
            WaitId::Pid(ChildPid::from_child(process)),
            WaitIdOptions::EXITED
                | WaitIdOptions::STOPPED
                | WaitIdOptions::NOHANG
                | WaitIdOptions::NOWAIT,
        )
        .map_err(io::Error::from)?;
        if let Some(status) = observed {
            if status.stopped() {
                child.stop()?;
                break "CANCELLED\n".to_owned();
            }
            if status.exited() || status.killed() || status.dumped() {
                let status = child.stop()?;
                break format!("EXIT {}\n", status.into_raw());
            }
        }
        if control_closed(&socket)? {
            child.stop()?;
            return Ok(());
        }
        if request
            .timeout_ms
            .is_some_and(|ms| started.elapsed() >= Duration::from_millis(ms))
        {
            child.stop()?;
            break "TIMEOUT\n".to_owned();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    socket.set_nonblocking(false)?;
    socket.write_all(outcome.as_bytes())
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

enum PipelineResult {
    Status(ExitStatus),
    Timeout,
    Cancelled,
    ControlClosed,
}

// Announce only the first child of a command chain; subsequent pipelines share
// the same action deadline. The owned-child guards are installed before I/O.
fn announce_started(mut socket: &UnixStream, started: &mut Option<Instant>) -> io::Result<()> {
    if started.is_none() {
        *started = Some(Instant::now());
        socket.write_all(b"STARTED\n")?;
    }
    Ok(())
}

fn receive_stdin(socket: &UnixStream) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    use std::{io::IoSliceMut, mem::MaybeUninit};
    let mut data = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    // Linux applies close-on-exec atomically while receiving descriptors. On
    // other Unix targets this private helper is still single-threaded and does
    // not spawn children before this receive, so fcntl below cannot race an
    // exec in this process.
    #[cfg(target_os = "linux")]
    let flags = RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = RecvFlags::empty();
    let result = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut data)],
        &mut ancillary,
        flags,
    )?;
    if result.bytes != 1 || data != *b"I" {
        return Err(io::Error::other("invalid stdin descriptor message"));
    }
    let fd = ancillary
        .drain()
        .find_map(|message| match message {
            RecvAncillaryMessage::ScmRights(mut rights) => rights.next(),
            _ => None,
        })
        .ok_or_else(|| io::Error::other("missing stdin descriptor"))?;
    let flags = rustix::io::fcntl_getfd(&fd)?;
    rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}

#[cfg(target_os = "linux")]
struct TerminalGuard {
    fd: std::os::fd::OwnedFd,
    previous: Pid,
}

#[cfg(target_os = "linux")]
fn terminal_set_group(fd: &impl AsFd, group: Pid) -> nix::Result<()> {
    use nix::sys::signal::{SigSet, SigmaskHow, pthread_sigmask};
    let mut set = SigSet::empty();
    set.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut previous))?;
    let result = nix::unistd::tcsetpgrp(fd, group);
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
    result.and(restored)
}

#[cfg(target_os = "linux")]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal_set_group(&self.fd, self.previous);
    }
}

#[cfg(target_os = "linux")]
struct ForegroundGroup {
    anchor: Option<Child>,
    stages: Vec<Child>,
    terminal: Option<TerminalGuard>,
}

#[cfg(target_os = "linux")]
impl ForegroundGroup {
    fn finish_success(&mut self) -> io::Result<Vec<ExitStatus>> {
        let statuses = self
            .stages
            .iter_mut()
            .map(Child::wait)
            .collect::<io::Result<Vec<_>>>()?;
        let anchor = self.anchor.as_mut().expect("owned anchor");
        match anchor.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(error),
        }
        anchor.wait()?;
        self.anchor.take();
        if let Some(terminal) = self.terminal.take() {
            terminal_set_group(&terminal.fd, terminal.previous).map_err(io::Error::from)?;
        }
        Ok(statuses)
    }

    fn finish(&mut self) -> io::Result<Vec<ExitStatus>> {
        let Some(anchor) = self.anchor.as_mut() else {
            return Ok(Vec::new());
        };
        let id = i32::try_from(anchor.id()).map_err(|_| io::Error::other("anchor pid"))?;
        match kill(Pid::from_raw(-id), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
        let statuses = self
            .stages
            .iter_mut()
            .map(Child::wait)
            .collect::<io::Result<Vec<_>>>()?;
        anchor.wait()?;
        self.anchor.take();
        if let Some(terminal) = self.terminal.take() {
            terminal_set_group(&terminal.fd, terminal.previous).map_err(io::Error::from)?;
        }
        Ok(statuses)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ForegroundGroup {
    fn drop(&mut self) {
        if self.anchor.is_some() {
            let _ = self.finish();
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn run_foreground(
    stages: &[Stage],
    request: &Run,
    socket: &UnixStream,
    started: &mut Option<Instant>,
    stdin: &std::os::fd::OwnedFd,
) -> io::Result<PipelineResult> {
    // /proc/self/exe refers to this already-verified supervisor image even if
    // the on-disk executable name is replaced after startup.
    let anchor = Command::new("/proc/self/exe")
        .arg(ANCHOR_MODE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let mut group = ForegroundGroup {
        anchor: Some(anchor),
        stages: Vec::new(),
        terminal: None,
    };
    let anchor = group.anchor.as_mut().expect("anchor");
    let mut banner = [0; b"NEOENV-TERMINAL-ANCHOR/1\n".len()];
    anchor
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("anchor stdout"))?
        .read_exact(&mut banner)?;
    if &banner != b"NEOENV-TERMINAL-ANCHOR/1\n" {
        return Err(io::Error::other("anchor identity"));
    }
    let id = i32::try_from(anchor.id()).map_err(|_| io::Error::other("anchor pid"))?;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    match tty {
        Ok(tty) => {
            let fd: std::os::fd::OwnedFd = tty.into();
            let previous = nix::unistd::tcgetpgrp(&fd)?;
            if previous != nix::unistd::getpgrp() {
                return Err(io::Error::other("caller does not own foreground terminal"));
            }
            terminal_set_group(&fd, Pid::from_raw(id))?;
            group.terminal = Some(TerminalGuard { fd, previous });
        }
        Err(error) if error.raw_os_error() == Some(Errno::ENXIO as i32) => {}
        Err(error) => return Err(error),
    }
    let mut previous_stdout = None;
    for (index, stage) in stages.iter().enumerate() {
        let input = match previous_stdout.take() {
            Some(stdout) => Stdio::from(stdout),
            None => Stdio::from(stdin.try_clone()?),
        };
        let mut child = Command::new(&stage.program)
            .args(&stage.arguments)
            .current_dir(&request.cwd)
            .env_clear()
            .envs(&request.environment)
            .stdin(input)
            .stdout(if index + 1 < stages.len() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stderr(Stdio::inherit())
            .process_group(id)
            .spawn()?;
        previous_stdout = child.stdout.take();
        group.stages.push(child);
        announce_started(socket, started)?;
    }
    loop {
        if control_closed(socket)? {
            group.finish()?;
            return Ok(PipelineResult::ControlClosed);
        }
        if request.timeout_ms.is_some_and(|ms| {
            started.expect("child start recorded").elapsed() >= Duration::from_millis(ms)
        }) {
            group.finish()?;
            return Ok(PipelineResult::Timeout);
        }
        let mut completed = 0;
        for child in &group.stages {
            let status = waitid(
                WaitId::Pid(ChildPid::from_child(child)),
                WaitIdOptions::EXITED
                    | WaitIdOptions::STOPPED
                    | WaitIdOptions::NOHANG
                    | WaitIdOptions::NOWAIT,
            )?;
            if let Some(status) = status {
                if status.stopped() || status.terminating_signal() == Some(Signal::SIGINT as i32) {
                    group.finish()?;
                    return Ok(PipelineResult::Cancelled);
                }
                if status.exited() || status.killed() || status.dumped() {
                    completed += 1;
                }
            }
        }
        if completed == group.stages.len() {
            let statuses = group.finish_success()?;
            return Ok(PipelineResult::Status(
                *statuses
                    .last()
                    .ok_or_else(|| io::Error::other("empty pipeline"))?,
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(target_os = "linux"))]
fn run_foreground(
    _stages: &[Stage],
    _request: &Run,
    _socket: &UnixStream,
    _started: &mut Option<Instant>,
    _stdin: &std::os::fd::OwnedFd,
) -> io::Result<PipelineResult> {
    Err(io::Error::other(
        "owned foreground execution is unavailable on this platform",
    ))
}

fn run_pipeline(
    stages: &[Stage],
    request: &Run,
    socket: &UnixStream,
    started: &mut Option<Instant>,
) -> io::Result<PipelineResult> {
    let mut children: Vec<OwnedChild> = Vec::with_capacity(stages.len());
    let mut previous_stdout = None;
    for (index, stage) in stages.iter().enumerate() {
        let mut command = Command::new(&stage.program);
        command
            .args(&stage.arguments)
            .current_dir(&request.cwd)
            .env_clear()
            .envs(&request.environment)
            .stdin(previous_stdout.take().map_or(Stdio::null(), Stdio::from))
            .stdout(if index + 1 < stages.len() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stderr(Stdio::inherit())
            .process_group(0);
        let Ok(mut child) = command.spawn() else {
            for child in &mut children {
                let _ = child.stop();
            }
            return Err(io::Error::other("pipeline stage failed to start"));
        };
        previous_stdout = child.stdout.take();
        children.push(OwnedChild(Some(child)));
        announce_started(socket, started)?;
    }

    let mut statuses: Vec<Option<ExitStatus>> = vec![None; children.len()];
    loop {
        if control_closed(socket)? {
            for child in &mut children {
                let _ = child.stop();
            }
            return Ok(PipelineResult::ControlClosed);
        }
        if request.timeout_ms.is_some_and(|ms| {
            started.expect("child start recorded").elapsed() >= Duration::from_millis(ms)
        }) {
            for child in &mut children {
                let _ = child.stop();
            }
            return Ok(PipelineResult::Timeout);
        }
        for index in 0..children.len() {
            if statuses[index].is_some() {
                continue;
            }
            let child = children[index].0.as_ref().expect("live pipeline child");
            let observed = waitid(
                WaitId::Pid(ChildPid::from_child(child)),
                WaitIdOptions::EXITED
                    | WaitIdOptions::STOPPED
                    | WaitIdOptions::NOHANG
                    | WaitIdOptions::NOWAIT,
            )
            .map_err(io::Error::from)?;
            if let Some(status) = observed {
                if status.stopped() {
                    for child in &mut children {
                        let _ = child.stop();
                    }
                    return Ok(PipelineResult::Cancelled);
                }
                if status.exited() || status.killed() || status.dumped() {
                    statuses[index] = Some(children[index].stop()?);
                }
            }
        }
        if statuses.iter().all(Option::is_some) {
            let last = statuses.len() - 1;
            return Ok(PipelineResult::Status(
                statuses[last].take().expect("last stage status"),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn send_self_pidfd(socket: &UnixStream) -> io::Result<()> {
    use rustix::{
        net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg},
        process::{PidfdFlags, getpid, pidfd_open},
    };
    use std::{io::IoSlice, mem::MaybeUninit};
    let pidfd = pidfd_open(getpid(), PidfdFlags::empty())?;
    let fds = [pidfd.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(io::Error::other("pidfd control buffer"));
    }
    if sendmsg(
        socket,
        &[IoSlice::new(b"P")],
        &mut control,
        SendFlags::empty(),
    )? != 1
    {
        return Err(io::Error::other("pidfd send"));
    }
    Ok(())
}

fn control_closed(mut socket: &UnixStream) -> io::Result<bool> {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(_) => Ok(true), // EOF or any control byte cancels.
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn stop(&mut self) -> io::Result<std::process::ExitStatus> {
        let child = self.0.as_mut().expect("owned child");
        let id = i32::try_from(child.id()).map_err(|_| io::Error::other("child id"))?;
        // This process is the exclusive parent, and has never waited on the
        // child. The group's leader remains waitable even after exit.
        match kill(Pid::from_raw(-id), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
        let status = child.wait()?;
        self.0.take();
        Ok(status)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The runtime background_tasks harness includes this module without
    // registering its #[test] functions, leaving this helper unused there.
    #[allow(dead_code)]
    fn bounded_status(command: &mut Command, timeout: Duration) -> Option<ExitStatus> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    #[test]
    fn supervisor_probe_timeout_is_bounded() {
        let start = Instant::now();
        assert!(
            bounded_status(
                Command::new("sh").args(["-c", "exec sleep 30"]),
                Duration::from_millis(100)
            )
            .is_none()
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[allow(dead_code)] // The runtime background_tasks harness includes this module without registering its tests.
    fn errno_code(error: io::Error, base: i32) -> i32 {
        base + match error.raw_os_error() {
            Some(code) if code == Errno::EPERM as i32 => 1,
            Some(code) if code == Errno::ESRCH as i32 => 2,
            Some(code) if code == Errno::ECHILD as i32 => 3,
            _ => 4,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn waitable_child_and_group_cleanup_work_on_host() {
        const FLAG: &str = "NEOENV_SUPERVISOR_WAITID_PROBE";
        if std::env::var_os(FLAG).is_none() {
            // Only this direct probe child is terminated on deadline. Its
            // short-lived "exit 7" child is never signalled by numeric PID here.
            let status = bounded_status(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "task_supervisor::tests::waitable_child_and_group_cleanup_work_on_host",
                    ])
                    .env(FLAG, "1"),
                Duration::from_secs(10),
            );
            assert!(
                status.is_some_and(|status| status.success()),
                "supervisor primitive probe status: {status:?}; 21=handler, 22=spawn, 23=waitid, 25=deadline, 26=status; 31-34=signal, 41-44=wait, 51-54=wait after ESRCH (1=EPERM, 2=ESRCH, 3=ECHILD, 4=other)"
            );
            return;
        }
        let flag = Arc::new(AtomicBool::new(false));
        if signal_hook::flag::register(signal_hook::consts::SIGCHLD, flag).is_err() {
            std::process::exit(21);
        }
        let Ok(process) = Command::new("sh")
            .args(["-c", "exit 7"])
            .process_group(0)
            .spawn()
        else {
            std::process::exit(22);
        };
        let mut owned = OwnedChild(Some(process));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let observed = match waitid(
                WaitId::Pid(ChildPid::from_child(owned.0.as_ref().unwrap())),
                WaitIdOptions::EXITED
                    | WaitIdOptions::STOPPED
                    | WaitIdOptions::NOHANG
                    | WaitIdOptions::NOWAIT,
            ) {
                Ok(observed) => observed,
                Err(_) => std::process::exit(23),
            };
            if let Some(status) = observed
                && (status.exited() || status.killed() || status.dumped())
            {
                // The leader is still an unreaped child, so its PID cannot
                // have been reused when signalling its process group.
                let mut child = owned.0.take().unwrap();
                let id = i32::try_from(child.id()).unwrap();
                let signal = kill(Pid::from_raw(-id), Signal::SIGKILL);
                let wait_base = if matches!(signal, Err(Errno::ESRCH)) {
                    50
                } else {
                    40
                };
                let status = child.wait().map_err(|error| errno_code(error, wait_base));
                if let Err(error) = signal
                    && error != Errno::ESRCH
                {
                    let code = errno_code(io::Error::from(error), 30);
                    std::process::exit(code);
                }
                let status = status.unwrap_or_else(|code| std::process::exit(code));
                if status.into_raw() != 1792 {
                    std::process::exit(26)
                }
                break;
            }
            if Instant::now() >= deadline {
                std::process::exit(25)
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // This is evidence about Darwin, not an alternate cleanup policy. The
    // helper is independently timed out and only its direct child is killed.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_waitable_group_signal_diagnostic() {
        // Unlike the production guard, this guard never signals a group.
        // Every failure path still owns and reaps its direct child.
        struct ProbeChild(Option<Child>);

        impl Drop for ProbeChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        const FLAG: &str = "NEOENV_DARWIN_GROUP_DIAGNOSTIC";
        if std::env::var_os(FLAG).is_none() {
            let helper = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "task_supervisor::tests::darwin_waitable_group_signal_diagnostic",
                    "--nocapture",
                ])
                .env(FLAG, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut helper = ProbeChild(Some(helper));
            // Read at most 4 KiB per stream; closing a full pipe also keeps
            // a malfunctioning helper from producing unbounded CI logs.
            let capture = |stream: Box<dyn Read + Send>| {
                std::thread::spawn(move || {
                    let mut bytes = Vec::new();
                    let _ = stream.take(4096).read_to_end(&mut bytes);
                    bytes
                })
            };
            let stdout = capture(Box::new(helper.0.as_mut().unwrap().stdout.take().unwrap()));
            let stderr = capture(Box::new(helper.0.as_mut().unwrap().stderr.take().unwrap()));
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = helper.0.as_mut().unwrap().try_wait().unwrap() {
                    helper.0.take();
                    eprintln!("{}", String::from_utf8_lossy(&stdout.join().unwrap()));
                    eprintln!("{}", String::from_utf8_lossy(&stderr.join().unwrap()));
                    assert!(
                        status.success(),
                        "Darwin diagnostic helper failed: {status}"
                    );
                    return;
                }
                if Instant::now() >= deadline {
                    // Never signal a potentially recycled group or descendant PID.
                    drop(helper);
                    eprintln!("{}", String::from_utf8_lossy(&stdout.join().unwrap()));
                    eprintln!("{}", String::from_utf8_lossy(&stderr.join().unwrap()));
                    panic!("Darwin diagnostic helper timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        for with_descendant in [false, true] {
            let (mut ready, writer) = UnixStream::pair().unwrap();
            ready
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let script = if with_descendant {
                // The descendant signals readiness itself, then expires even if
                // the helper is killed or the group signal fails. No ps output
                // or unbounded input is captured.
                "(printf R; exec sleep 8) & exit 7"
            } else {
                "exit 7"
            };
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap();
            let mut child = ProbeChild(Some(child));
            if with_descendant {
                let mut byte = [0];
                ready
                    .read_exact(&mut byte)
                    .expect("descendant readiness timed out");
                assert_eq!(byte, *b"R");
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let observed = loop {
                let status = waitid(
                    WaitId::Pid(ChildPid::from_child(child.0.as_ref().unwrap())),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                )
                .unwrap();
                if let Some(status) = status {
                    break status;
                }
                assert!(Instant::now() < deadline, "leader did not exit");
                std::thread::sleep(Duration::from_millis(10));
            };
            // The waitable, unreaped leader reserves this group identity. This
            // one signal is the subject of the probe, not a cleanup retry.
            let group = i32::try_from(child.0.as_ref().unwrap().id()).unwrap();
            let signal = kill(Pid::from_raw(-group), Signal::SIGKILL);
            eprintln!(
                "Darwin group diagnostic: descendant_ready={with_descendant} leader_exited={} signal={signal:?}",
                observed.exited()
            );
            // After the observation, only reap our direct child. On failure a
            // descendant expires naturally; never retry using an unpinned PID.
            child.0.as_mut().unwrap().wait().unwrap();
            child.0.take();
            if !with_descendant {
                assert_eq!(
                    signal,
                    Err(Errno::EPERM),
                    "Darwin zombie-only group signal behavior changed"
                );
            }
        }
    }
}
