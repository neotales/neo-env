//! Single-command private launcher, used by the experimental Windows backend.

use super::{
    Child, ControlClient, HostIdentity, LauncherStage, Spawn, SpawnCleanupFailure, StagedFailure,
};
use crate::protocol::Kind;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, path::PathBuf, time::Duration};

/// Single executable request; its environment may contain secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherRequest {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub directory: PathBuf,
    pub environment: BTreeMap<String, String>,
}

/// Stable launcher result without task arguments, environment or OS paths.
#[derive(Debug, Serialize, Deserialize)]
pub enum LauncherResponse {
    Exit(u32),
    StartFailed,
    /// Safe operation and optional Win32 error; never includes task data.
    StartFailedDetailed {
        stage: LauncherStage,
        code: Option<i32>,
    },
    ExecutionFailed,
    /// The monitor lost the host or could not wait for the worker.
    MonitorFailed {
        phase: MonitorPhase,
        code: Option<i32>,
    },
    CleanupFailed,
    /// Job cleanup failed; paths and process arguments are never included.
    CleanupFailedDetailed {
        code: Option<i32>,
        timed_out: bool,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MonitorPhase {
    HostConnection,
    ProcessWait,
}

fn cleanup_failure(error: io::Error) -> LauncherResponse {
    LauncherResponse::CleanupFailedDetailed {
        code: error.raw_os_error(),
        timed_out: error.kind() == io::ErrorKind::TimedOut,
    }
}

fn start_when_connected<T>(
    check: impl FnOnce() -> io::Result<bool>,
    spawn: impl FnOnce() -> io::Result<T>,
) -> io::Result<io::Result<T>> {
    if !check()? {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "launcher host disconnected before startup",
        ));
    }
    Ok(spawn())
}

fn supervise(
    mut connected: impl FnMut() -> io::Result<bool>,
    mut wait: impl FnMut() -> io::Result<Option<u32>>,
    mut terminate: impl FnMut() -> io::Result<()>,
) -> LauncherResponse {
    loop {
        let host_failure = match connected() {
            Ok(true) => None,
            Ok(false) => Some(None),
            Err(error) => Some(error.raw_os_error()),
        };
        if let Some(code) = host_failure {
            return match terminate() {
                Ok(()) => LauncherResponse::MonitorFailed {
                    phase: MonitorPhase::HostConnection,
                    code,
                },
                Err(error) => cleanup_failure(error),
            };
        }
        match wait() {
            Ok(Some(code)) => {
                return match terminate() {
                    Ok(()) => LauncherResponse::Exit(code),
                    Err(error) => cleanup_failure(error),
                };
            }
            Ok(None) => {}
            Err(error) => {
                let code = error.raw_os_error();
                return match terminate() {
                    Ok(()) => LauncherResponse::MonitorFailed {
                        phase: MonitorPhase::ProcessWait,
                        code,
                    },
                    Err(error) => cleanup_failure(error),
                };
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn classify_start_error(error: &io::Error) -> LauncherResponse {
    if error
        .get_ref()
        .is_some_and(|e| e.is::<SpawnCleanupFailure>())
    {
        LauncherResponse::CleanupFailed
    } else if let Some(failure) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<StagedFailure>())
    {
        LauncherResponse::StartFailedDetailed {
            stage: failure.stage,
            code: failure.code,
        }
    } else {
        LauncherResponse::StartFailed
    }
}

/// Called only by the private launcher's main, before application threads.
#[allow(dead_code)] // The private binary compiles this module separately.
pub(crate) fn run_launcher(name: &str, host: HostIdentity) -> io::Result<()> {
    let mut control = ControlClient::connect(name, host, Duration::from_secs(10), &|| false)?;
    let (kind, bytes) = control.receive(Duration::from_secs(10), &|| false)?;
    if kind != Kind::Request {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid launcher request",
        ));
    }
    let request: LauncherRequest = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid launcher request"))?;
    if !request.directory.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher directory must be absolute",
        ));
    }
    let stdout = control.receive_pipe(Duration::from_secs(10), &|| false)?;
    let stderr = control.receive_pipe(Duration::from_secs(10), &|| false)?;
    // A disconnect can still race this final check and process creation.
    let spec = Spawn {
        executable: &request.executable,
        arguments: &request.arguments,
        environment: &request.environment,
        directory: &request.directory,
        inherit_stdin: false,
    };
    let started = start_when_connected(
        || control.host_running(),
        || {
            Child::spawn_with_outputs(
                &spec,
                Some((&stdout, &stderr)),
                Some(&|| control.host_running()),
            )
        },
    )?;
    drop(stdout);
    drop(stderr);
    let response = match started {
        Err(error) => classify_start_error(&error),
        Ok(child) => supervise(
            || control.host_running(),
            || child.try_wait(),
            || child.terminate(),
        ),
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|_| io::Error::other("launcher response encoding failed"))?;
    control.send(Kind::Result, &bytes, Duration::from_secs(3), &|| false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn startup_diagnostic_contains_stage_and_code_without_task_data() {
        let error = super::super::at_stage(
            LauncherStage::CreateProcess,
            io::Error::from_raw_os_error(5),
        );
        let response = classify_start_error(&error);
        assert!(matches!(
            response,
            LauncherResponse::StartFailedDetailed {
                stage: LauncherStage::CreateProcess,
                code: Some(5)
            }
        ));
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("CreateProcess"));
        assert!(!encoded.contains("secret"));
    }

    #[test]
    fn disconnected_before_start_does_not_spawn() {
        let spawned = Cell::new(false);
        let result = start_when_connected(
            || Ok(false),
            || {
                spawned.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!spawned.get());
    }

    #[test]
    fn monitor_failures_explicitly_terminate_and_report_cleanup() {
        for fail_host in [true, false] {
            for fail_cleanup in [true, false] {
                let calls = Cell::new(0);
                let result = supervise(
                    || {
                        if fail_host {
                            Err(io::Error::other("injected"))
                        } else {
                            Ok(true)
                        }
                    },
                    || Err(io::Error::other("injected")),
                    || {
                        calls.set(calls.get() + 1);
                        if fail_cleanup {
                            Err(io::Error::other("injected"))
                        } else {
                            Ok(())
                        }
                    },
                );
                assert_eq!(calls.get(), 1);
                if fail_cleanup {
                    assert!(matches!(
                        result,
                        LauncherResponse::CleanupFailedDetailed { .. }
                    ));
                } else {
                    assert!(matches!(result, LauncherResponse::MonitorFailed { .. }));
                }
            }
        }
    }

    #[test]
    fn startup_cleanup_failure_is_distinct_from_start_failure() {
        assert!(matches!(
            classify_start_error(&io::Error::other(SpawnCleanupFailure)),
            LauncherResponse::CleanupFailed
        ));
        assert!(matches!(
            classify_start_error(&io::Error::other("injected")),
            LauncherResponse::StartFailed
        ));
    }
}
