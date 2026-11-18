//! Windows job-backed owned execution. Native Windows validation is pending.

use neotales_process::{CommandChain, Error, ExecutionOptions};
use std::{
    io::{self, Read},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(super) const fn supported(backend: Option<&Path>) -> bool {
    backend.is_some()
}

pub(super) const fn unavailable_reason() -> &'static str {
    "Windows owned execution requires a configured helper"
}

pub(super) fn execute_chain(
    chain: &CommandChain,
    options: &ExecutionOptions<'_>,
    backend: &Path,
    foreground: bool,
) -> Result<ExitStatus, Error> {
    if chain.programs.len() != 1
        || !chain.operators.is_empty()
        || chain.programs[0].commands.len() != 1
    {
        return Err(Error::Internal(
            "Windows owned pipelines and command chains are not implemented",
        ));
    }
    let command = &chain.programs[0].commands[0];
    execute_argv(
        &command.program,
        &command.arguments,
        options,
        backend,
        foreground,
    )
}

fn resolve(program: &str, options: &ExecutionOptions<'_>) -> Result<PathBuf, Error> {
    let path = Path::new(program);
    let extensions: &[&str] = if path.extension().is_some() {
        &[""]
    } else {
        &[".exe", ".com"]
    };
    let candidates: Vec<PathBuf> = if path.is_absolute() || path.components().count() > 1 {
        vec![if path.is_absolute() {
            path.to_path_buf()
        } else {
            options.working_directory.join(path)
        }]
    } else {
        options
            .environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
            .map(|(_, value)| {
                std::env::split_paths(value)
                    .map(|p| {
                        if p.is_absolute() {
                            p
                        } else {
                            options.working_directory.join(p)
                        }
                    })
                    .map(|p| p.join(path))
                    .collect()
            })
            .unwrap_or_default()
    };
    for candidate in candidates {
        for extension in extensions {
            let candidate = if extension.is_empty() {
                candidate.clone()
            } else {
                let mut name = candidate.as_os_str().to_os_string();
                name.push(extension);
                PathBuf::from(name)
            };
            if !candidate
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("exe") || s.eq_ignore_ascii_case("com"))
            {
                continue;
            }
            if candidate.is_file() {
                return std::fs::canonicalize(candidate).map_err(Error::Start);
            }
        }
    }
    Err(Error::Start(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "owned executable not found in child PATH or unsupported file type",
    )))
}

pub(super) fn execute_argv(
    program: &str,
    arguments: &[String],
    options: &ExecutionOptions<'_>,
    backend: &Path,
    foreground: bool,
) -> Result<ExitStatus, Error> {
    if (options.is_cancelled)() {
        return Err(Error::Cancelled);
    }
    let current = std::env::current_exe().map_err(Error::Start)?;
    if std::fs::canonicalize(backend).map_err(Error::Start)?
        != std::fs::canonicalize(&current).map_err(Error::Start)?
    {
        return Err(Error::Internal(
            "owned backend must be the current executable",
        ));
    }
    let executable = resolve(program, options)?;
    let cwd = std::fs::canonicalize(options.working_directory).map_err(Error::Start)?;
    let started = Instant::now();
    let args: Vec<_> = arguments
        .iter()
        .chain(options.passthrough)
        .cloned()
        .collect();
    if foreground {
        return Err(Error::Internal(
            "Windows owned foreground execution is not implemented",
        ));
    }
    // Keep a non-write/non-delete-shared open handle until every helper has
    // exited. This prevents replacement between validation and process start.
    let (helper, _locked_helper) = lock_helper(&current).map_err(Error::Start)?;
    let cancellation = neoenv_windows_job::OutputCancellation::new().map_err(Error::Start)?;
    let stdout = match neoenv_windows_job::OutputWriter::stdout(cancellation.clone()) {
        Ok(writer) => Destination::Overlapped(writer),
        Err(_) => Destination::Forward(
            neoenv_windows_job::ForwardDestination::stdout().map_err(Error::Start)?,
        ),
    };
    let stderr = match neoenv_windows_job::OutputWriter::stderr(cancellation.clone()) {
        Ok(writer) => Destination::Overlapped(writer),
        Err(_) => Destination::Forward(
            neoenv_windows_job::ForwardDestination::stderr().map_err(Error::Start)?,
        ),
    };
    let mut execution = OutputExecution {
        children: Vec::new(),
        writers: Vec::new(),
        cancellation,
        forwarding: Vec::new(),
        first_failure: Arc::new(Mutex::new(None)),
    };
    let result = (|| {
        let cancelled =
            || (options.is_cancelled)() || options.timeout.is_some_and(|t| started.elapsed() >= t);
        let (out_read, out_write) = neoenv_windows_job::anonymous_pipe().map_err(Error::Start)?;
        let (err_read, err_write) = neoenv_windows_job::anonymous_pipe().map_err(Error::Start)?;
        execution
            .proxy(&helper, out_read, stdout, "stdout", &cancelled)
            .map_err(Error::Start)?;
        execution
            .proxy(&helper, err_read, stderr, "stderr", &cancelled)
            .map_err(Error::Start)?;
        let listener = neoenv_windows_job::ControlListener::new().map_err(Error::Start)?;
        let launcher = launch_helper(&helper, &listener, "").map_err(Error::Start)?;
        execution.children.push(launcher);
        let launcher = execution.children.last().expect("just pushed launcher");
        let mut control = listener
            .authenticate(launcher, Duration::from_secs(10), &cancelled)
            .map_err(Error::Start)?;
        let request = neoenv_windows_job::LauncherRequest {
            executable,
            arguments: args,
            environment: options.environment.clone(),
            directory: cwd,
        };
        let body = serde_json::to_vec(&request).map_err(|e| Error::Start(io::Error::other(e)))?;
        use neoenv_windows_job::protocol::Kind;
        control
            .send(Kind::Request, &body, Duration::from_secs(10), &cancelled)
            .map_err(Error::Start)?;
        control
            .send_pipe(&out_write, Duration::from_secs(10), &cancelled)
            .map_err(Error::Start)?;
        control
            .send_pipe(&err_write, Duration::from_secs(10), &cancelled)
            .map_err(Error::Start)?;
        drop((out_write, err_write));
        let cancelled_or_output_failed = || {
            cancelled()
                || execution.cancellation.is_cancelled()
                || execution.forward_error().is_some()
        };
        let response = control.receive_until_cancelled(&cancelled_or_output_failed);
        drop(control);
        let (kind, body) = match response {
            Ok(response) => response,
            Err(error) => {
                if let Some(output) = execution.take_first_failure() {
                    return Err(Error::Io(output));
                }
                if let Some(output) = execution.forward_error() {
                    return Err(Error::Io(output));
                }
                if (options.is_cancelled)() {
                    return Err(Error::Cancelled);
                }
                if options.timeout.is_some_and(|t| started.elapsed() >= t) {
                    return Err(Error::TimedOut);
                }
                return Err(Error::Io(error));
            }
        };
        if kind != Kind::Result {
            return Err(Error::Io(io::Error::other("invalid launcher response")));
        }
        let response: neoenv_windows_job::LauncherResponse =
            serde_json::from_slice(&body).map_err(|e| Error::Io(io::Error::other(e)))?;
        if let Err(error) = execution.join_writers(&cancelled) {
            if let Some(output) = execution.take_first_failure() {
                return Err(Error::Io(output));
            }
            if (options.is_cancelled)() {
                return Err(Error::Cancelled);
            }
            if options.timeout.is_some_and(|t| started.elapsed() >= t) {
                return Err(Error::TimedOut);
            }
            return Err(Error::Io(error));
        }
        if let Err(error) = execution.wait_forwarding(&cancelled) {
            if (options.is_cancelled)() {
                return Err(Error::Cancelled);
            }
            if options.timeout.is_some_and(|t| started.elapsed() >= t) {
                return Err(Error::TimedOut);
            }
            return Err(Error::Io(error));
        }
        interpret_launcher_response(response)
    })();
    match (result, execution.cleanup()) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(Error::Cleanup {
            primary: Box::new(Error::Internal("task completed but Windows cleanup failed")),
            cleanup: Box::new(Error::Io(cleanup)),
        }),
        (Err(primary), Err(cleanup)) => Err(Error::Cleanup {
            primary: Box::new(primary),
            cleanup: Box::new(Error::Io(cleanup)),
        }),
    }
}

// Preserve the launcher's non-sensitive stage and Win32 code through the
// runtime's process-error formatter; a plain StartFailed has no such data.
fn interpret_launcher_response(
    response: neoenv_windows_job::LauncherResponse,
) -> Result<ExitStatus, Error> {
    match response {
        neoenv_windows_job::LauncherResponse::Exit(code) => Ok(ExitStatus::from_raw(code)),
        neoenv_windows_job::LauncherResponse::StartFailedDetailed { stage, code } => {
            Err(Error::Io(io::Error::other(format!(
                "Windows launcher start failed at {stage:?} (Win32 code {code:?})"
            ))))
        }
        neoenv_windows_job::LauncherResponse::StartFailed => Err(Error::Io(io::Error::other(
            "Windows launcher rejected task startup",
        ))),
        neoenv_windows_job::LauncherResponse::ExecutionFailed => Err(Error::Io(io::Error::other(
            "Windows launcher lost host connection or failed to monitor the task",
        ))),
        neoenv_windows_job::LauncherResponse::CleanupFailed => Err(Error::Io(io::Error::other(
            "Windows launcher could not verify task cleanup",
        ))),
        neoenv_windows_job::LauncherResponse::MonitorFailed { phase, code } => {
            Err(Error::Io(io::Error::other(format!(
                "Windows launcher monitor failed at {phase:?} (Win32 code {code:?})"
            ))))
        }
        neoenv_windows_job::LauncherResponse::CleanupFailedDetailed { code, timed_out } => {
            Err(Error::Io(io::Error::other(format!(
                "Windows launcher cleanup failed (Win32 code {code:?}, timed out: {timed_out})"
            ))))
        }
    }
}

fn lock_helper(executable: &Path) -> io::Result<(PathBuf, std::fs::File)> {
    let executable = std::fs::canonicalize(executable)?;
    let directory = executable
        .parent()
        .ok_or_else(|| io::Error::other("executable has no install directory"))?;
    let path = directory.join("neoenv-windows-launcher.exe");
    // FILE_FLAG_OPEN_REPARSE_POINT opens the link itself; a post-open file
    // attribute check rejects any reparse point, including symlinks/junctions.
    // FILE_SHARE_READ only prevents writes and deletion while this guard lives.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Windows launcher helper unavailable or locked: {}: {e}",
                    path.display()
                ),
            )
        })?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows launcher helper must not be a reparse point",
        ));
    }
    let resolved = std::fs::canonicalize(&path)?;
    if resolved.parent() != Some(directory) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows launcher helper is outside the resolved install directory",
        ));
    }
    Ok((resolved, file))
}

fn launch_helper(
    helper: &Path,
    listener: &neoenv_windows_job::ControlListener,
    mode: &str,
) -> io::Result<neoenv_windows_job::Child> {
    let identity = neoenv_windows_job::HostIdentity::current()?;
    let mut args = Vec::new();
    if !mode.is_empty() {
        args.push(mode.into());
    }
    args.extend([
        listener.name().into(),
        identity.pid.to_string(),
        identity.creation_time.to_string(),
    ]);
    let environment = std::collections::BTreeMap::new();
    neoenv_windows_job::Child::spawn_isolated_launcher(&neoenv_windows_job::Spawn {
        executable: helper,
        arguments: &args,
        environment: &environment,
        directory: helper
            .parent()
            .ok_or_else(|| io::Error::other("helper has no directory"))?,
        inherit_stdin: false,
    })
}

// Publish the original failure before signalling the peer. Otherwise the peer's
// cancellation error can win the race and hide the error that caused it.
fn record_writer_failure(
    first: &Mutex<Option<io::Error>>,
    cancel: &neoenv_windows_job::OutputCancellation,
    stream: &str,
    error: &io::Error,
) {
    let mut first = first
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if first.is_none() && !cancel.is_cancelled() {
        *first = Some(io::Error::new(
            error.kind(),
            format!("{stream} output writer failed: {error}"),
        ));
        cancel.request_cancel();
        // Release the failure mutex before signalling: a console call may hold
        // the admission gate indefinitely, but the original error must remain readable.
        drop(first);
        let _ = cancel.cancel();
    }
}

enum Destination {
    Overlapped(neoenv_windows_job::OutputWriter),
    Forward(neoenv_windows_job::ForwardDestination),
}
struct OutputExecution {
    children: Vec<neoenv_windows_job::Child>,
    writers: Vec<JoinHandle<io::Result<()>>>,
    cancellation: neoenv_windows_job::OutputCancellation,
    forwarding: Vec<usize>,
    first_failure: Arc<Mutex<Option<io::Error>>>,
}
impl OutputExecution {
    fn proxy(
        &mut self,
        helper: &Path,
        source: neoenv_windows_job::PipeReader,
        writer: Destination,
        stream: &'static str,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        let listener = neoenv_windows_job::ControlListener::new()?;
        let mode = match &writer {
            Destination::Overlapped(_) => "--proxy",
            Destination::Forward(_) => "--forward-proxy",
        };
        let child = launch_helper(helper, &listener, mode)?;
        self.children.push(child);
        let child = self.children.last().expect("just pushed proxy");
        let mut control = listener.authenticate(child, Duration::from_secs(10), cancelled)?;
        if let Destination::Forward(destination) = writer {
            control.send_pipe_reader(&source, Duration::from_secs(10), cancelled)?;
            control.send_forward_destination(&destination, Duration::from_secs(10), cancelled)?;
            drop((source, destination, control));
            self.forwarding.push(self.children.len() - 1);
            return Ok(());
        }
        let Destination::Overlapped(writer) = writer else {
            unreachable!()
        };
        let (mut output, destination) = neoenv_windows_job::anonymous_pipe()?;
        control.send_pipe_reader(&source, Duration::from_secs(10), cancelled)?;
        control.send_pipe(&destination, Duration::from_secs(10), cancelled)?;
        drop((source, destination, control));
        let cancel = self.cancellation.clone();
        let first_failure = Arc::clone(&self.first_failure);
        self.writers.push(std::thread::spawn(move || {
            let result = (|| {
                let mut buffer = [0; 8192];
                loop {
                    let n = output.read(&mut buffer)?;
                    if n == 0 {
                        return Ok(());
                    }
                    writer.write_all(&buffer[..n])?;
                }
            })();
            if let Err(error) = &result {
                record_writer_failure(&first_failure, &cancel, stream, error);
            }
            result
        }));
        Ok(())
    }
    fn take_first_failure(&self) -> Option<io::Error> {
        self.first_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
    fn forward_error(&self) -> Option<io::Error> {
        for &index in &self.forwarding {
            match self.children[index].try_wait() {
                Ok(Some(0)) | Ok(None) => {}
                Ok(Some(code)) => {
                    return Some(io::Error::other(format!(
                        "output forwarding process failed with exit code {code}"
                    )));
                }
                Err(error) => {
                    return Some(io::Error::other(format!(
                        "output forwarding process wait failed: {error}"
                    )));
                }
            }
        }
        None
    }
    fn wait_forwarding(&self, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        loop {
            if let Some(error) = self.forward_error() {
                return Err(error);
            }
            if self
                .forwarding
                .iter()
                .all(|&i| matches!(self.children[i].try_wait(), Ok(Some(0))))
            {
                return Ok(());
            }
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "output forwarding cancelled",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn join_writers(&mut self, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        while self.writers.iter().any(|w| !w.is_finished()) {
            if let Some(error) = self.forward_error() {
                return Err(error);
            }
            if cancelled() || self.cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "output drain cancelled or output writer failed",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut failures = Vec::new();
        for writer in self.writers.drain(..) {
            match writer.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("output writer failed: {error}")),
                Err(_) => failures.push("output writer panicked".into()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}
impl OutputExecution {
    fn cleanup(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        // Mark cancellation before attempting the gate, but never let a
        // blocked console call prevent job termination on this thread.
        self.cancellation.request_cancel();
        let cancellation = self.cancellation.clone();
        let (signal_tx, signal_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = signal_tx.send(cancellation.cancel());
        });
        for child in &self.children {
            if let Err(error) = child.terminate() {
                failures.push(format!("Windows job termination failed: {error}"));
            }
        }
        self.children.clear();
        let deadline = Instant::now() + Duration::from_secs(5);
        match signal_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("output cancellation signal failed: {error}")),
            Err(_) => failures.push(
                "output cancellation event could not be signalled before cleanup deadline".into(),
            ),
        }
        while self.writers.iter().any(|w| !w.is_finished()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        for writer in self.writers.drain(..) {
            if writer.is_finished() {
                match writer.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                    Ok(Err(error)) => failures.push(format!("output writer failed: {error}")),
                    Err(_) => failures.push("output writer panicked".into()),
                }
            } else {
                failures.push("output writer did not join before cleanup deadline".into());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Windows owned cleanup failed: {}",
                failures.join("; ")
            )))
        }
    }
}
impl Drop for OutputExecution {
    fn drop(&mut self) {
        if !self.children.is_empty() || !self.writers.is_empty() {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_error_preserves_launcher_stage_and_os_code() {
        let result = interpret_launcher_response(
            neoenv_windows_job::LauncherResponse::StartFailedDetailed {
                stage: neoenv_windows_job::LauncherStage::BuildEnvironment,
                code: Some(87),
            },
        );
        let message = super::super::process::format_process_error(result.unwrap_err());
        assert!(message.contains("BuildEnvironment"), "{message}");
        assert!(message.contains("87"), "{message}");
    }

    #[test]
    fn first_writer_failure_is_not_replaced_by_peer_interruption() {
        let cancellation = neoenv_windows_job::OutputCancellation::new().unwrap();
        let failure = Mutex::new(None);
        record_writer_failure(
            &failure,
            &cancellation,
            "stderr",
            &io::Error::new(io::ErrorKind::Interrupted, "original device failure"),
        );
        assert!(cancellation.is_cancelled());
        record_writer_failure(
            &failure,
            &cancellation,
            "stdout",
            &io::Error::new(io::ErrorKind::Interrupted, "output cancelled"),
        );
        let error = failure.lock().unwrap().take().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(
            error
                .to_string()
                .contains("stderr output writer failed: original device failure")
        );
        assert!(!error.to_string().contains("output cancelled"));
    }

    #[test]
    fn locked_helper_cannot_be_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let exe = directory.path().join("nenv.exe");
        let helper = directory.path().join("neoenv-windows-launcher.exe");
        std::fs::write(&exe, b"host").unwrap();
        std::fs::write(&helper, b"helper").unwrap();
        let (_path, guard) = lock_helper(&exe).unwrap();
        assert!(std::fs::rename(&helper, directory.path().join("replaced.exe")).is_err());
        assert!(std::fs::write(&helper, b"replacement").is_err());
        drop(guard);
        std::fs::rename(&helper, directory.path().join("replaced.exe")).unwrap();
    }

    #[test]
    fn slow_successful_output_drain_has_no_three_second_limit() {
        let cancellation = neoenv_windows_job::OutputCancellation::new().unwrap();
        let mut execution = OutputExecution {
            children: Vec::new(),
            forwarding: Vec::new(),
            first_failure: Arc::new(Mutex::new(None)),
            cancellation,
            writers: vec![std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(3200));
                Ok(())
            })],
        };
        execution.join_writers(&|| false).unwrap();
    }

    #[test]
    fn cleanup_reports_writer_completion_timeout() {
        let cancellation = neoenv_windows_job::OutputCancellation::new().unwrap();
        let mut execution = OutputExecution {
            children: Vec::new(),
            forwarding: Vec::new(),
            first_failure: Arc::new(Mutex::new(None)),
            cancellation,
            writers: vec![std::thread::spawn(|| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "output cancellation completion deadline exceeded",
                ))
            })],
        };
        let error = execution.cleanup().unwrap_err().to_string();
        assert!(
            error.contains("output cancellation completion deadline exceeded"),
            "{error}"
        );
    }

    #[test]
    fn multi_stage_chain_is_rejected_without_launch() {
        let chain = neotales_process::parse("first | second").unwrap();
        let environment = std::collections::BTreeMap::new();
        let options = ExecutionOptions {
            working_directory: Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| false,
            timeout: None,
        };
        let result = execute_chain(&chain, &options, Path::new("unused"), false);
        assert!(matches!(result, Err(Error::Internal(_))));
    }

    #[test]
    fn cancellation_before_start_does_not_resolve_or_spawn() {
        let environment = std::collections::BTreeMap::new();
        let options = ExecutionOptions {
            working_directory: Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &|| true,
            timeout: None,
        };
        assert!(matches!(
            execute_argv("unused", &[], &options, Path::new("unused"), false),
            Err(Error::Cancelled)
        ));
    }
}
