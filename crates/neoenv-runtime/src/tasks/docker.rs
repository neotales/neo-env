//! Docker's daemon outlives its CLI. A lost create reply is not proof that
//! create was cancelled; report the recovery identity, never "cleaned up".
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use super::{TaskAction, TaskRunOptions};

const LABEL: &str = "org.neoenv.task-owner";
const PHASE_LIMIT: Duration = Duration::from_secs(10);
const DEFAULT_LIMIT: Duration = Duration::from_secs(3600);

enum Phase {
    Exited(ExitStatus, String),
    Interrupted,
    Failed,
}

enum Output {
    Capture,
    Inherit,
    Stderr,
}

// Output is staged in a private file rather than a pipe, so a full pipe cannot
// deadlock cancellation. Diagnostic text from Docker is not copied into errors.
fn cli(
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    limit: Duration,
    cancelled: &dyn Fn() -> bool,
    destination: Output,
) -> Phase {
    if cancelled() || limit.is_zero() {
        return Phase::Interrupted;
    }
    let mut output = match tempfile::tempfile() {
        Ok(file) => file,
        Err(_) => return Phase::Failed,
    };
    let capture = matches!(destination, Output::Capture);
    let stdout = match destination {
        Output::Capture => match output.try_clone() {
            Ok(file) => Stdio::from(file),
            Err(_) => return Phase::Failed,
        },
        Output::Inherit => Stdio::inherit(),
        Output::Stderr => Stdio::from(std::io::stderr()),
    };
    let mut child = match Command::new("docker")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Phase::Failed,
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if capture
                    && (output.seek(SeekFrom::Start(0)).is_err()
                        || output.take(4097).read_to_string(&mut text).is_err()
                        || text.len() > 4096)
                {
                    return Phase::Failed;
                }
                return Phase::Exited(status, text);
            }
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Phase::Failed;
            }
        }
        if cancelled() || started.elapsed() >= limit {
            // This bounds our wait, not daemon execution. All callers must
            // treat an interrupted mutating operation as an unknown outcome.
            let _ = child.kill();
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Phase::Interrupted;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn recovery(name: &str, marker: &str, detail: &str) -> String {
    format!(
        "docker {detail}; daemon outcome/cleanup unknown; recovery name={name} \
         label {LABEL}={marker}. Inspect the same daemon and remove only a matching owned container"
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    image: &str,
    action: &TaskAction,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    passthrough: &[String],
    options: &TaskRunOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExitStatus, String> {
    if image.is_empty() || image.starts_with('-') || image.contains('\0') {
        return Err("docker run must name a non-empty image, not an option".into());
    }
    if action.with.keys().any(|key| key != "timeout")
        || action.destination.is_some()
        || action.cwd.is_some()
    {
        return Err("docker supports only with.timeout, run (image), and args".into());
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "docker identity generation failed")?;
    let marker: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = format!("neoenv-{marker}");
    let start = Instant::now();
    let limit = timeout.unwrap_or(DEFAULT_LIMIT);
    let cancelled = || options.cancellation.is_cancelled();
    if cancelled() || limit.is_zero() {
        return Err("task cancelled".into());
    }
    let mut create = vec![
        "create".into(),
        "--name".into(),
        name.clone(),
        "--label".into(),
        format!("{LABEL}={marker}"),
        image.into(),
    ];
    create.extend(action.args.iter().cloned());
    create.extend_from_slice(passthrough);
    let id = match cli(&create, cwd, env, limit, &cancelled, Output::Capture) {
        Phase::Exited(status, text) if status.success() => {
            let id = text.trim().to_owned();
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(recovery(&name, &marker, "create returned an invalid id"));
            }
            id
        }
        _ => return Err(recovery(&name, &marker, "create was not confirmed")),
    };
    // Inspect by immutable ID; never delete by name after inspection, because
    // another actor could replace a name between inspect and remove.
    let inspect = vec![
        "inspect".into(),
        "--format".into(),
        format!("{{{{index .Config.Labels \"{LABEL}\"}}}}"),
        id.clone(),
    ];
    let matches = || match cli(&inspect, cwd, env, PHASE_LIMIT, &|| false, Output::Capture) {
        Phase::Exited(status, text) => status.success() && text.trim() == marker,
        _ => false,
    };
    if !matches() {
        return Err(recovery(&name, &marker, "ownership could not be confirmed"));
    }
    let remaining = limit.saturating_sub(start.elapsed());
    let result = cli(
        &["start".into(), "--attach".into(), id.clone()],
        cwd,
        env,
        remaining,
        &cancelled,
        if options.ssh_output_to_stderr {
            Output::Stderr
        } else {
            Output::Inherit
        },
    );
    // Revalidate even after start: never remove an object without its marker.
    if !matches() {
        return Err(recovery(
            &name,
            &marker,
            "cleanup ownership could not be confirmed",
        ));
    }
    let remove = vec!["rm".into(), "--force".into(), id];
    if !matches!(
        cli(&remove, cwd, env, PHASE_LIMIT, &|| false, Output::Capture),
        Phase::Exited(status, _) if status.success()
    ) {
        return Err(recovery(&name, &marker, "cleanup was not confirmed"));
    }
    match result {
        Phase::Exited(status, _) => Ok(status),
        Phase::Interrupted if cancelled() => Err("task cancelled".into()),
        Phase::Interrupted => Err("task timed out".into()),
        Phase::Failed => Err("docker start failed; cleanup confirmed".into()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::tasks::{TaskCancellation, TaskRunnerDirectories};
    use std::{fs, os::unix::fs::PermissionsExt};

    // This fake separates the create reply from a late daemon-side effect.
    // It never invokes a real Docker daemon.
    const FAKE: &str = r#"#!/usr/bin/python3
import os, sys, time, subprocess
from pathlib import Path
root = Path(os.environ["FAKE_ROOT"])
mode = os.environ["FAKE_MODE"]
args = sys.argv[1:]
op = args[0]
if op == "late":
    time.sleep(.25)
    (root / "late").write_text("created")
    sys.exit(0)
with (root / "calls").open("a") as f:
    f.write(op + "\n")
if op == "create":
    (root / "label").write_text(args[args.index("--label") + 1].split("=", 1)[1])
    (root / "name").write_text(args[args.index("--name") + 1])
    if mode == "late":
        subprocess.Popen([sys.executable, __file__, "late"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        (root / "accepted").write_text("yes")
        time.sleep(2)
    print("a" * 64)
elif op == "inspect":
    print("wrong" if mode == "wrong" else (root / "label").read_text())
elif op == "start":
    if mode in ("timeout", "cancel"):
        time.sleep(2)
elif op == "rm":
    if mode == "cleanup":
        sys.exit(1)
"#;

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

    fn run(mode: &str, timeout: Duration) -> (tempfile::TempDir, Result<ExitStatus, String>) {
        let dir = tempfile::tempdir().unwrap();
        let docker = dir.path().join("docker");
        fs::write(&docker, FAKE).unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        let env = BTreeMap::from([
            ("PATH".into(), dir.path().display().to_string()),
            ("FAKE_ROOT".into(), dir.path().display().to_string()),
            ("FAKE_MODE".into(), mode.into()),
        ]);
        let cancellation = TaskCancellation::new();
        if mode == "cancel" || mode == "late" {
            let signal = cancellation.clone();
            let calls = dir.path().join("calls");
            let accepted = dir.path().join("accepted");
            let late = mode == "late";
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline
                    && !(if late {
                        accepted.exists()
                    } else {
                        fs::read_to_string(&calls)
                            .is_ok_and(|text| text.lines().any(|line| line == "start"))
                    })
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                signal.cancel();
            });
        }
        let action = TaskAction::default();
        let result = execute(
            "example:1",
            &action,
            dir.path(),
            &env,
            &[],
            &options(&cancellation),
            Some(timeout),
        );
        (dir, result)
    }

    fn calls(dir: &tempfile::TempDir) -> Vec<String> {
        fs::read_to_string(dir.path().join("calls"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn normal_create_run_and_confirmed_cleanup() {
        let (dir, result) = run("normal", Duration::from_secs(3));
        assert!(result.unwrap().success());
        assert_eq!(calls(&dir), ["create", "inspect", "start", "inspect", "rm"]);
    }

    #[test]
    fn interrupted_create_reports_recovery_identity_even_if_creation_is_late() {
        let (dir, result) = run("late", Duration::from_secs(3));
        let error = result.unwrap_err();
        assert!(error.contains("outcome/cleanup unknown"), "{error}");
        assert!(error.contains(&fs::read_to_string(dir.path().join("name")).unwrap()));
        assert!(error.contains(&fs::read_to_string(dir.path().join("label")).unwrap()));
        std::thread::sleep(Duration::from_millis(400));
        assert!(dir.path().join("late").exists());
        assert_eq!(calls(&dir), ["create"]);
    }

    #[test]
    fn mismatched_marker_is_never_removed() {
        let (dir, result) = run("wrong", Duration::from_secs(3));
        assert!(
            result
                .unwrap_err()
                .contains("ownership could not be confirmed")
        );
        assert_eq!(calls(&dir), ["create", "inspect"]);
    }

    #[test]
    fn cleanup_failure_is_unknown_not_success() {
        let (dir, result) = run("cleanup", Duration::from_secs(3));
        assert!(result.unwrap_err().contains("cleanup unknown"));
        assert_eq!(calls(&dir), ["create", "inspect", "start", "inspect", "rm"]);
    }

    #[test]
    fn timed_out_start_still_cleans_up() {
        let (dir, result) = run("timeout", Duration::from_millis(400));
        assert_eq!(result.unwrap_err(), "task timed out");
        assert_eq!(calls(&dir), ["create", "inspect", "start", "inspect", "rm"]);
    }

    #[test]
    fn cancelled_start_still_cleans_up() {
        let (dir, result) = run("cancel", Duration::from_secs(3));
        assert_eq!(result.unwrap_err(), "task cancelled");
        assert_eq!(calls(&dir), ["create", "inspect", "start", "inspect", "rm"]);
    }

    /// This explicitly selected live lane never skips on missing prerequisites.
    /// Its wrapper records only the generated name and label; deletion remains
    /// exclusively the runner's marker-checked operation.
    #[test]
    #[ignore = "requires local Docker daemon and preloaded alpine:3.21"]
    fn docker_live_daemon() {
        let path = std::env::var_os("PATH").expect("PATH must locate the Docker CLI");
        let real = std::env::split_paths(&path)
            .map(|directory| directory.join("docker"))
            .find(|candidate| candidate.is_file())
            .expect("selected live Docker test requires a Docker CLI")
            .canonicalize()
            .expect("Docker CLI path must resolve");
        let dir = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("docker");
        fs::write(
            &wrapper,
            "#!/bin/sh\nif [ \"$1\" = create ]; then printf '%s' \"$3\" > \"$LIVE_DIR/name\"; printf '%s' \"$5\" > \"$LIVE_DIR/label\"; fi\nexec \"$REAL_DOCKER\" \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let env = BTreeMap::from([
            ("PATH".into(), dir.path().display().to_string()),
            ("REAL_DOCKER".into(), real.display().to_string()),
            ("LIVE_DIR".into(), dir.path().display().to_string()),
            ("DOCKER_CONFIG".into(), config.path().display().to_string()),
            ("DOCKER_HOST".into(), "unix:///var/run/docker.sock".into()),
        ]);
        let available = || {
            matches!(
                cli(
                    &["info".into(), "--format".into(), "{{.ID}}".into()],
                    dir.path(),
                    &env,
                    PHASE_LIMIT,
                    &|| false,
                    Output::Capture,
                ),
                Phase::Exited(status, _) if status.success()
            )
        };
        assert!(
            available(),
            "selected live test requires an available local Docker daemon"
        );
        let cancellation = TaskCancellation::new();
        let action = TaskAction {
            args: vec!["echo".into(), "neoenv-live-test".into()],
            ..TaskAction::default()
        };
        let result = execute(
            "alpine:3.21",
            &action,
            dir.path(),
            &env,
            &[],
            &options(&cancellation),
            Some(Duration::from_secs(30)),
        )
        .unwrap_or_else(|error| panic!("live Docker execution failed: {error}"));
        assert!(result.success(), "live container failed: {result}");
        assert!(
            available(),
            "daemon disappeared before cleanup verification"
        );
        let name = fs::read_to_string(dir.path().join("name")).unwrap();
        let label = fs::read_to_string(dir.path().join("label")).unwrap();
        assert!(name.starts_with("neoenv-"));
        assert!(label.starts_with(&format!("{LABEL}=")));
        for (filter, check_label) in [
            (format!("label={label}"), true),
            (format!("name={name}"), false),
        ] {
            let filters = vec![
                "ps".into(),
                "--all".into(),
                "--filter".into(),
                filter,
                "--format".into(),
                "{{.Names}}".into(),
            ];
            match cli(
                &filters,
                dir.path(),
                &env,
                PHASE_LIMIT,
                &|| false,
                Output::Capture,
            ) {
                Phase::Exited(status, names) => {
                    assert!(status.success(), "could not verify cleanup");
                    assert!(
                        if check_label {
                            names.trim().is_empty()
                        } else {
                            !names.lines().any(|found| found == name)
                        },
                        "owned container remains: {name} {label}: {names}"
                    );
                }
                _ => panic!("cleanup verification timed out or failed for {name} {label}"),
            }
        }
    }
}
