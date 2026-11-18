//! Real controlling-terminal checks, not pipe-based stdin approximations.
#![cfg(target_os = "linux")]

use std::{fs, process::Command};

fn probe(mode: &str) {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("terminal_probe.py"),
        include_str!("support/terminal_probe.py"),
    )
    .unwrap();
    let output = Command::new("python3")
        .args(["terminal_probe.py", mode, env!("CARGO_BIN_EXE_nenv")])
        .current_dir(root.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.path().join("home"))
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .env("NEOENV_STATE_HOME", root.path().join("state"))
        .env("NEOENV_CACHE_HOME", root.path().join("cache"))
        .output()
        .expect("python3 is required for the Unix pseudo-terminal lane");
    assert!(
        output.status.success(),
        "mode {mode}: stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inherited_terminal_stdin_works_and_is_restored_between_actions_and_pipeline_stages() {
    probe("stdin");
}

#[test]
fn redirected_stdin_keeps_its_value_and_terminal_job_control() {
    probe("redirected");
}

#[test]
fn parallel_foreground_work_serializes_terminal_handoff() {
    probe("parallel");
}

#[test]
fn independent_cli_processes_serialize_terminal_handoff() {
    probe("parallel_process");
}

#[test]
fn independent_terminals_do_not_block_each_other() {
    probe("distinct_terminals");
}

#[test]
fn nested_foreground_invocation_fails_promptly_without_deadlock() {
    probe("nested");
}

#[test]
fn nested_copied_binary_cannot_bypass_terminal_lease_detection() {
    probe("nested_copy");
}

#[test]
fn terminal_ctrl_c_cancels_the_foreground_pipeline_and_background_siblings() {
    probe("interrupt");
}

#[test]
fn terminal_ctrl_c_with_inherited_ignored_sigchld() {
    probe("interrupt_ignored");
}

#[test]
fn terminal_ctrl_z_cancels_stopped_work_and_restores_the_terminal_for_explicit_recovery() {
    probe("suspend");
}

#[test]
fn foreground_pipeline_never_runs_a_path_supplied_anchor() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("terminal_path_probe.py"),
        include_str!("support/terminal_path_probe.py"),
    )
    .unwrap();
    let output = Command::new("python3")
        .args(["terminal_path_probe.py", env!("CARGO_BIN_EXE_nenv")])
        .current_dir(root.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
