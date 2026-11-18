//! Periodic process-lifecycle coverage for the compiled `nenv` binary.
//!
//! This target deliberately uses real task deadlines and is excluded from
//! normal `cargo test` runs. The cases are separate so one failure cannot hide
//! hook, force, timeout, or help regressions. The package's unit-test target
//! supplies the supervised worker-panic cases; this target supplies the
//! black-box Ctrl-C descendant case in the same opt-in package suite.

use std::{
    fs,
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::process::Stdio;

use tempfile::TempDir;

fn command(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nenv"))
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("nenv process should start")
}

fn shell_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn write_configuration(directory: &TempDir, contents: &str) {
    fs::write(directory.path().join("neoenv.yaml"), contents)
        .expect("periodic configuration should be writable");
}

#[test]
fn periodic_task_help_is_side_effect_free() {
    let directory = TempDir::new().unwrap();
    let marker = directory.path().join("must-not-run");
    write_configuration(
        &directory,
        &format!(
            "tasks:\n  build:\n    description: Build the periodic integration fixture.\n    help: Help must not execute this action.\n    uses: shell\n    run: 'touch {}'\n",
            shell_path(&marker)
        ),
    );

    let output = command(directory.path(), &["task", "help", "build"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Build the periodic integration fixture."));
    assert!(stdout.contains("Help must not execute this action."));
    assert!(!marker.exists());
}

#[test]
fn periodic_hooks_run_in_order() {
    let directory = TempDir::new().unwrap();
    let before = directory.path().join("before-ran");
    let build = directory.path().join("build-ran");
    let after = directory.path().join("after-ran");
    write_configuration(
        &directory,
        &format!(
            "tasks:\n  build:\n    uses: shell\n    run: 'sleep 1; touch {}'\n    hooks:\n      before: before\n      after: after\n  build:before:\n    uses: shell\n    run: 'touch {}'\n  build:after:\n    uses: shell\n    run: 'touch {}'\n",
            shell_path(&build),
            shell_path(&before),
            shell_path(&after),
        ),
    );

    let output = command(directory.path(), &["task", "run", "build"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "build:before Succeeded\nbuild Succeeded\nbuild:after Succeeded\n"
    );
    assert!(before.exists());
    assert!(build.exists());
    assert!(after.exists());
}

#[test]
fn periodic_force_recovers_after_a_failed_dependency() {
    let directory = TempDir::new().unwrap();
    let recovery = directory.path().join("recovery-ran");
    write_configuration(
        &directory,
        &format!(
            "tasks:\n  prepare:\n    uses: argv\n    run: 'false'\n  recover:\n    needs: prepare\n    force: outcome.prepare == failed\n    uses: shell\n    run: 'sleep 1; touch {}'\n",
            shell_path(&recovery)
        ),
    );

    let output = command(directory.path(), &["task", "run", "recover"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "prepare Failed\nrecover Succeeded\n"
    );
    assert!(recovery.exists());
}

#[test]
fn periodic_timeout_terminates_descendants() {
    let directory = TempDir::new().unwrap();
    let timeout_child = directory.path().join("timeout-child-survived");
    write_configuration(
        &directory,
        &format!(
            "tasks:\n  timeout:\n    uses: shell\n    run: '(sleep 3; touch {}) & wait'\n    with:\n      timeout: 1s\n",
            shell_path(&timeout_child)
        ),
    );

    let output = command(directory.path(), &["task", "run", "timeout"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "timeout TimedOut\n"
    );
    thread::sleep(Duration::from_secs(3));
    assert!(
        !timeout_child.exists(),
        "the timed-out task's descendant was not terminated"
    );
}

#[cfg(unix)]
#[test]
fn periodic_interrupt_terminates_descendants() {
    let directory = TempDir::new().unwrap();
    let ready = directory.path().join("interrupt-child-ready");
    let survived = directory.path().join("interrupt-child-survived");
    write_configuration(
        &directory,
        &format!(
            "tasks:\n  interrupt:\n    uses: shell\n    run: '(touch {}; sleep 3; touch {}) & wait'\n",
            shell_path(&ready),
            shell_path(&survived),
        ),
    );

    let task = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .current_dir(directory.path())
        .args(["task", "run", "interrupt"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("nenv process should start");
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "the interrupt descendant did not start");
    assert!(
        Command::new("kill")
            .args(["-INT", &task.id().to_string()])
            .status()
            .expect("kill should be available on Unix test hosts")
            .success()
    );
    let output = task
        .wait_with_output()
        .expect("nenv process should return after Ctrl-C");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "interrupt Cancelled\n"
    );
    thread::sleep(Duration::from_secs(3));
    assert!(
        !survived.exists(),
        "the Ctrl-C task descendant was not terminated"
    );
}
