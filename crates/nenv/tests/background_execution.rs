//! CLI contracts for structured task/job concurrency. No network or global
//! configuration is used; every fixture has its own home and state directories.
#![cfg(unix)]

use std::{
    fs,
    os::unix::process::CommandExt,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const CHECK_A: &str = "test -f x-finished && touch a-finished";
const CHECK_B: &str = "test -f y-finished && touch b-finished";
const CHECK_ROOT: &str = "test -f a-finished && test -f b-finished && touch root-finished";

/// Bound a child without relying on GNU timeout or inherited output pipes.
/// The unreaped child reserves the process-group ID until cleanup completes.
fn bounded_output(command: &mut Command, limit: Duration) -> Option<Output> {
    let output_dir = tempfile::tempdir().unwrap();
    let stdout_path = output_dir.path().join("stdout");
    let stderr_path = output_dir.path().join("stderr");
    let mut child = command
        .process_group(0)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .unwrap();
    let group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(Output {
                status,
                stdout: fs::read(stdout_path).unwrap(),
                stderr: fs::read(stderr_path).unwrap(),
            });
        }
        if Instant::now() >= deadline {
            // Give nenv a chance to cancel and reap its own supervisor groups.
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGINT);
            // Leave the leader unreaped throughout the grace period, reserving
            // its group ID even if it exits before a child that ignores SIGINT.
            std::thread::sleep(Duration::from_secs(5));
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            child.wait().unwrap();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn project(yaml: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("neoenv.yaml"), yaml).unwrap();
    root
}

mod support;

/// Approves the fixture's current bytes before a run.
///
/// Execution requires an approved record for the exact bytes the run will read.
/// Every case here writes its configuration first and then runs, so approving at
/// the call site keeps the record current without changing what the case
/// asserts.
fn approve(root: &std::path::Path) {
    support::approve_tree(&root.join("config"), root);
}

fn run(root: &tempfile::TempDir, args: &[&str]) -> Output {
    approve(root.path());
    let temp_dir = fs::canonicalize(root.path()).unwrap().join("tmp");
    fs::create_dir_all(&temp_dir).unwrap();
    Command::new(env!("CARGO_BIN_EXE_nenv"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.path().join("home"))
        .env("TMPDIR", &temp_dir)
        .env("TMP", &temp_dir)
        .env("TEMP", &temp_dir)
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .env("NEOENV_STATE_HOME", root.path().join("state"))
        .env("NEOENV_CACHE_HOME", root.path().join("cache"))
        .current_dir(root.path())
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

// The markers prove overlap and ordering; the generous finite polling and job
// budgets are deadlock guards, not performance assertions. Each supervised
// step authenticates the executable before it can create a marker, which is
// slow for large debug binaries on a busy host. Timeout behavior itself is
// covered by the dedicated deadline tests below.
#[test]
#[cfg(target_os = "linux")]
fn job_steps_overlap_until_an_id_wait_and_keep_default_step_order() {
    let root = project(
        r#"
jobs:
  build:
    steps:
      - id: compiler
        background: true
        uses: shell
        timeout: 120s
        run: |
          for n in $(seq 1 1200); do
            if test -f release; then echo COMPILED=yes > "$NEOENV_ENV"; exit 0; fi
            sleep 0.05
          done
          exit 91
      - uses: shell
        run: 'test -z "$COMPILED" && touch release'
      - wait: [compiler]
      - uses: shell
        run: 'test "$COMPILED" = yes && touch finished'
"#,
    );
    let stdout = success(&run(&root, &["job", "run", "build"]));
    for position in 1..=4 {
        assert!(
            stdout.contains(&format!("build:{position} Succeeded")),
            "{stdout}"
        );
    }
    assert!(root.path().join("finished").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn background_jobs_overlap_as_whole_sequences_and_publish_only_on_join() {
    let root = project(
        r#"
jobs:
  worker:
    timeout: 120s
    steps:
      - uses: shell
        run: touch started
      - uses: shell
        run: |
          for n in $(seq 1 1200); do
            if test -f release; then echo JOB_VALUE=joined > "$NEOENV_ENV"; exit 0; fi
            sleep 0.05
          done
          exit 91
  release:
    steps:
      - uses: shell
        run: |
          test -z "$JOB_VALUE" || exit 93
          for n in $(seq 1 1200); do test -f started && touch release && exit 0; sleep 0.05; done
          exit 92
  finish:
    needs: [worker, release]
    wait: [worker]
    steps:
      - uses: shell
        run: 'test "$JOB_VALUE" = joined && touch finished'
"#,
    );
    let stdout = success(&run(&root, &["job", "run", "finish"]));
    assert!(
        stdout.contains("worker Succeeded") && stdout.contains("finish Succeeded"),
        "{stdout}"
    );
    assert!(root.path().join("finished").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn independent_job_dependencies_overlap_by_default_and_join_before_the_dependent_job() {
    let root = project(
        r"
jobs:
  left:
    timeout: 120s
    steps:
      - uses: shell
        run: |
          touch left
          for n in $(seq 1 1200); do test -f right && exit 0; sleep 0.05; done
          exit 91
  right:
    timeout: 120s
    steps:
      - uses: shell
        run: |
          touch right
          for n in $(seq 1 1200); do test -f left && exit 0; sleep 0.05; done
          exit 92
  finish:
    needs: [left, right]
    steps:
      - uses: shell
        run: 'test -f left && test -f right && touch finished'
",
    );
    success(&run(&root, &["job", "run", "finish"]));
    assert!(root.path().join("finished").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn independent_job_branches_launch_before_joining_nested_dependencies() {
    let root = project(&format!(
        r"
jobs:
  x:
    steps:
      - uses: shell
        run: 'touch x-started; for n in $(seq 1 1200); do if test -f y-started; then touch x-finished; exit 0; fi; sleep 0.05; done; exit 91'
  y:
    steps:
      - uses: shell
        run: 'touch y-started; for n in $(seq 1 1200); do if test -f x-started; then touch y-finished; exit 0; fi; sleep 0.05; done; exit 92'
  a:
    needs: [x]
    steps: [{{uses: shell, run: '{CHECK_A}'}}]
  b:
    needs: [y]
    steps: [{{uses: shell, run: '{CHECK_B}'}}]
  root:
    needs: [a, b]
    steps: [{{uses: shell, run: '{CHECK_ROOT}'}}]
",
    ));
    approve(root.path());
    let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    command
        .args(["job", "run", "root"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.path().join("home"))
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .env("NEOENV_STATE_HOME", root.path().join("state"))
        .env("NEOENV_CACHE_HOME", root.path().join("cache"))
        .current_dir(root.path());
    let output = bounded_output(&mut command, Duration::from_secs(180))
        .expect("cross-branch job graph timed out");
    success(&output);
    assert!(root.path().join("root-finished").exists());
}

#[test]
fn cross_branch_checks_reject_premature_execution() {
    let root = tempfile::tempdir().unwrap();
    for (check, marker) in [
        (CHECK_A, "a-finished"),
        (CHECK_B, "b-finished"),
        (CHECK_ROOT, "root-finished"),
    ] {
        let status = Command::new("/bin/sh")
            .args(["-c", check])
            .current_dir(root.path())
            .status()
            .unwrap();
        assert!(!status.success(), "premature check succeeded: {check}");
        assert!(!root.path().join(marker).exists(), "{marker} was created");
    }
    for present in ["a-finished", "b-finished"] {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(present), "").unwrap();
        let status = Command::new("/bin/sh")
            .args(["-c", CHECK_ROOT])
            .current_dir(directory.path())
            .status()
            .unwrap();
        assert!(!status.success(), "root succeeded with only {present}");
        assert!(!directory.path().join("root-finished").exists());
    }
    let directory = tempfile::tempdir().unwrap();
    for marker in ["a-finished", "b-finished"] {
        fs::write(directory.path().join(marker), "").unwrap();
    }
    let status = Command::new("/bin/sh")
        .args(["-c", CHECK_ROOT])
        .current_dir(directory.path())
        .status()
        .unwrap();
    assert!(status.success(), "root failed with both prerequisites");
    assert!(directory.path().join("root-finished").exists());
}

#[test]
fn bounded_output_terminates_and_reaps_a_timed_out_child() {
    let root = tempfile::tempdir().unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .current_dir(root.path())
        .args(["-c", "trap '' INT; sleep 30 & echo $! > child.pid; wait"]);
    let started = Instant::now();
    assert!(bounded_output(&mut command, Duration::from_secs(1)).is_none());
    assert!(started.elapsed() < Duration::from_secs(12));
    let pid = fs::read_to_string(root.path().join("child.pid")).unwrap();
    let status = Command::new("ps")
        .args(["-o", "stat=", "-p", pid.trim()])
        .output()
        .unwrap();
    let state = String::from_utf8_lossy(&status.stdout);
    assert!(
        !status.status.success() || state.trim().is_empty() || state.trim().starts_with('Z'),
        "process-group child survived timeout: {pid} {state}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn independent_job_handoffs_merge_in_plan_order_even_when_completed_out_of_order() {
    let root = project(
        r#"
jobs:
  slow:
    steps: [{uses: shell, run: 'sleep 1; echo VALUE=slow > "$NEOENV_ENV"'}]
  fast:
    steps: [{uses: shell, run: 'echo VALUE=fast > "$NEOENV_ENV"'}]
  finish:
    needs: [slow, fast]
    steps: [{uses: shell, run: 'test "$VALUE" = fast'}]
"#,
    );
    success(&run(&root, &["job", "run", "finish"]));
}

#[test]
fn job_background_is_rejected_instead_of_ignored() {
    let root = project("jobs: {build: {background: true, steps: [{run: 'true'}]}}");
    let output = run(&root, &["job", "run", "build"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("sets `background`"),
        "{output:?}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn background_exec_pipeline_preserves_pipe_and_chain_semantics() {
    let root = project(
        r"
tasks:
  pipeline:
    background: true
    run: 'yes x | head -c 262144 | wc -c && printf chained'
  finish:
    wait: [pipeline]
    run: 'true'
",
    );
    let stdout = success(&run(&root, &["run", "finish"]));
    assert!(stdout.contains("262144"), "{stdout}");
    assert!(stdout.contains("chained"), "{stdout}");
}

#[test]
#[cfg(target_os = "linux")]
fn background_pipeline_kills_exited_stage_descendants_before_pipe_eof() {
    let root = project(
        r"
tasks:
  pipeline:
    background: true
    run: 'sh -c ''(sleep 1; touch escaped) & exit 0'' | cat'
  finish:
    wait: [pipeline]
    run: 'true'
",
    );
    success(&run(&root, &["run", "finish"]));
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert!(!root.path().join("escaped").exists());
}

#[test]
fn default_exec_matches_portable_parser_and_keeps_args_literal() {
    let root = project(
        r"
tasks:
  default:
    run: 'printf %s hi | tr a-z A-Z'
  portable:
    uses: portable
    run: 'printf %s hi | tr a-z A-Z'
  appended:
    uses: exec
    run: printf
    args: ['%s', 'literal value']
",
    );
    for task in ["default", "portable", "appended"] {
        let output = run(&root, &["run", task]);
        let stdout = success(&output);
        if task == "appended" {
            assert!(stdout.contains("literal value"), "{stdout}");
        } else {
            assert!(stdout.contains("HI"), "{stdout}");
        }
    }
}

#[test]
fn passthrough_reaches_every_executed_pipeline_in_a_chain() {
    let root = project(
        r"
tasks:
  foreground:
    run: 'printf %s A; printf %s B && false || printf %s C'
    args: [VALUE]
",
    );
    let stdout = success(&run(&root, &["run", "foreground"]));
    assert!(stdout.contains("AVALUEBVALUECVALUE"), "{stdout}");
}

#[test]
#[cfg(target_os = "linux")]
fn background_passthrough_reaches_executed_pipeline_in_a_chain() {
    let root = project(
        r"
tasks:
  background:
    background: true
    run: 'printf %s A; printf %s B && false || printf %s C'
    args: [VALUE]
  finish:
    wait: [background]
    run: 'true'
",
    );
    let stdout = success(&run(&root, &["run", "finish"]));
    assert!(stdout.contains("AVALUEBVALUECVALUE"), "{stdout}");
}

#[test]
fn foreground_success_preserves_detached_descendants_and_pipe_eof() {
    let root = project(
        r#"
tasks:
  detached:
    uses: shell
    run: '(sleep 0.2; touch survived) >/dev/null 2>&1 &'
  pipe:
    run: "sh -c '(sleep 0.2; printf late) & exit 0' | cat"
"#,
    );
    success(&run(&root, &["run", "detached"]));
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(root.path().join("survived").exists());
    let stdout = success(&run(&root, &["run", "pipe"]));
    assert!(stdout.contains("late"), "{stdout}");
}

#[test]
#[cfg(target_os = "linux")]
fn foreground_timeout_stops_descendant_holding_pipeline_open() {
    // The job deadline includes supervisor authentication before the shell
    // starts. Leave startup headroom and separately require the ready marker;
    // the escaped marker remains scheduled beyond the deadline.
    let root = project(
        r#"
jobs:
  build:
    timeout: 15s
    steps:
      - uses: shell
        run: "sh -c '(touch descendant-ready; sleep 20; touch escaped) & exit 0' | cat"
"#,
    );
    let output = run(&root, &["job", "run", "build"]);
    assert!(!output.status.success());
    assert!(
        root.path().join("descendant-ready").exists(),
        "descendant did not signal readiness: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("build:1 TimedOut") || stdout.contains("build TimedOut"),
        "{stdout}"
    );
    std::thread::sleep(std::time::Duration::from_millis(20300));
    assert!(!root.path().join("escaped").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn host_timeout_resumes_stopped_supervisor_and_cleans_task() {
    let root = project(
        r"
tasks:
  stalled:
    uses: shell
    with: {timeout: 3s}
    run: 'echo $$ > stage.pid; echo $PPID > supervisor.pid; kill -STOP $PPID; echo stopped > stop.sent; (sleep 4; touch escaped) & sleep 30'
",
    );
    fs::write(
        root.path().join("stopped_supervisor_probe.py"),
        include_str!("support/stopped_supervisor_probe.py"),
    )
    .unwrap();
    approve(root.path());
    let output = Command::new("python3")
        .args(["stopped_supervisor_probe.py", env!("CARGO_BIN_EXE_nenv")])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.path().join("home"))
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .env("NEOENV_STATE_HOME", root.path().join("state"))
        .env("NEOENV_CACHE_HOME", root.path().join("cache"))
        .current_dir(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn job_execution_repairs_inherited_ignored_sigchld() {
    let root = project("jobs: {build: {steps: [{uses: shell, run: 'echo job-ok'}]}}");
    approve(root.path());
    let output = Command::new("python3")
        .args([
            "-c",
            "import os,signal,sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); os.execv(sys.argv[1], [sys.argv[1], 'job', 'run', 'build'])",
            env!("CARGO_BIN_EXE_nenv"),
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.path().join("home"))
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .env("NEOENV_STATE_HOME", root.path().join("state"))
        .env("NEOENV_CACHE_HOME", root.path().join("cache"))
        .current_dir(root.path())
        .output()
        .unwrap();
    assert!(success(&output).contains("job-ok"));
}

#[test]
fn exec_template_if_else_matches_portable_and_argv_keeps_template_literal() {
    let root = project(
        r"
tasks:
  default:
    env: {FEATURE: enabled}
    run: '{{ if .env.FEATURE }}printf enabled{{ else }}printf disabled{{ end }}'
  portable:
    uses: portable
    env: {FEATURE: enabled}
    run: '{{ if .env.FEATURE }}printf enabled{{ else }}printf disabled{{ end }}'
  disabled:
    uses: argv
    run: printf
    args: ['{{ if .env.FEATURE }}enabled{{ else }}disabled{{ end }}']
",
    );
    for task in ["default", "portable"] {
        assert!(
            success(&run(&root, &["run", task])).contains("enabled"),
            "exec/portable template did not select the true branch"
        );
    }
    assert!(
        success(&run(&root, &["run", "disabled"]))
            .contains("{{ if .env.FEATURE }}enabled{{ else }}disabled{{ end }}"),
        "argv must not render templates"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn background_exec_template_uses_the_same_rendering() {
    let root = project(
        r"
tasks:
  background:
    background: true
    env: {FEATURE: enabled}
    run: '{{ if .env.FEATURE }}printf background-enabled{{ else }}printf background-disabled{{ end }}'
  finish:
    wait: [background]
    run: 'true'
",
    );
    assert!(
        success(&run(&root, &["run", "finish"])).contains("background-enabled"),
        "background exec must use the same template rendering"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn execution_reports_platform_unavailability_without_running_the_task() {
    let root = project("tasks: {unsupported: {background: true, run: 'touch should-not-run'}}");
    let output = run(&root, &["run", "unsupported"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("exclusive child ownership is not implemented on this platform"),
        "{output:?}"
    );
    assert!(!root.path().join("should-not-run").exists());
}

#[test]
#[cfg(target_os = "macos")]
fn background_job_steps_report_platform_unavailability_without_running() {
    let root = project(
        "jobs: {unsupported: {steps: [{uses: shell, background: true, run: 'touch should-not-run'}]}}",
    );
    let output = run(&root, &["job", "run", "unsupported"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("exclusive child ownership is not implemented on this platform"),
        "{output:?}"
    );
    assert!(!root.path().join("should-not-run").exists());
}

#[test]
#[cfg(target_os = "macos")]
fn foreground_jobs_remain_supported_without_graph_controls() {
    let root = project("jobs: {foreground: {steps: [{uses: shell, run: 'touch foreground-ran'}]}}");
    let output = run(&root, &["job", "run", "foreground"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        root.path().join("foreground-ran").exists(),
        "foreground job step was not run: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("foreground:1 Succeeded"),
        "{output:?}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn jobs_have_an_overall_deadline_and_do_not_run_later_steps_after_it() {
    let root = project(
        r"
jobs:
  slow:
    timeout: 150ms
    steps:
      - uses: shell
        run: sleep 30
      - uses: shell
        run: touch wrong
  finish:
    wait: [slow]
    steps:
      - uses: shell
        run: touch wrong
",
    );
    let output = run(&root, &["job", "run", "finish"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("slow TimedOut") && stdout.contains("finish Blocked"),
        "{stdout}"
    );
    assert!(!root.path().join("wrong").exists());
}

#[test]
fn job_graph_dry_run_plans_nested_steps_without_launching_any() {
    let root = project(
        r"
jobs:
  worker:
    steps: [{uses: shell, run: touch wrong}]
  finish:
    needs: [worker]
    wait-all: true
    steps: [{uses: shell, run: touch wrong}]
",
    );
    let stdout = success(&run(&root, &["job", "run", "--dry-run", "finish"]));
    assert!(
        stdout.contains("worker Planned") && stdout.contains("finish Planned"),
        "{stdout}"
    );
    assert!(!root.path().join("wrong").exists());
}

#[test]
fn job_dependency_and_wait_names_are_not_task_names_and_cycles_are_refused() {
    for yaml in [
        "tasks: {missing: 'true'}\njobs:\n  finish:\n    wait: [missing]\n    steps: ['missing']\n",
        "jobs:\n  finish: {needs: [other], steps: [{run: 'true'}]}\n  other: {wait: [finish], steps: [{run: 'true'}]}\n",
        "jobs:\n  finish:\n    steps:\n      - {id: one, wait: [two]}\n      - {id: two, run: 'true'}\n",
    ] {
        let root = project(yaml);
        let output = run(&root, &["job", "run", "finish"]);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert!(!root.path().join("wrong").exists());
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn unreachable_broken_jobs_do_not_poison_a_requested_job_graph() {
    let root = project(
        r"
jobs:
  invalid: [no-such-task]
  dependency: [{run: 'touch dependency-ran'}]
  finish:
    needs: [dependency]
    steps: [{run: 'touch finish-ran'}]
",
    );
    let output = run(&root, &["job", "run", "finish"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("dependency-ran").exists(), "{output:?}");
    assert!(root.path().join("finish-ran").exists(), "{output:?}");
}

#[test]
#[cfg(target_os = "macos")]
fn job_graphs_require_owned_background_execution_on_macos() {
    let root = project(
        r"
jobs:
  invalid: [no-such-task]
  dependency: [{run: 'touch dependency-ran'}]
  finish:
    needs: [dependency]
    steps: [{run: 'touch finish-ran'}]
",
    );
    let output = run(&root, &["job", "run", "finish"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("exclusive child ownership is not implemented on this platform"),
        "{output:?}"
    );
    assert!(!root.path().join("dependency-ran").exists());
    assert!(!root.path().join("finish-ran").exists());
}

#[test]
fn job_task_references_preserve_inheritance_and_original_dependencies() {
    let root = project(
        r"
tasks:
  template:
    template: true
    needs: [prepare]
    uses: shell
    run: test -f prepared
  prepare: {uses: shell, run: touch prepared}
  build: {extends: template}
jobs:
  finish: [build]
",
    );
    success(&run(&root, &["job", "run", "finish"]));
    assert!(root.path().join("prepared").exists());
}

#[test]
fn authorization_is_checked_before_any_background_launch_even_in_dry_runs() {
    let root = project(
        r"
tasks:
  background:
    background: true
    uses: shell
    run: touch wrong
  privileged:
    uses: shell
    run: touch wrong
    capabilities: [execute]
  finish:
    needs: [background, privileged]
    wait-all: true
",
    );
    for args in [vec!["run", "finish"], vec!["run", "finish", "--dry-run"]] {
        let output = run(&root, &args);
        assert_eq!(output.status.code(), Some(5), "{output:?}");
        assert!(!root.path().join("wrong").exists());
    }
}

#[test]
fn nested_job_authorization_is_also_checked_before_launch() {
    let root = project(
        r"
tasks:
  privileged:
    uses: shell
    run: touch wrong
    capabilities: [execute]
jobs:
  background:
    steps: [{uses: shell, run: touch wrong}]
  finish:
    needs: [background]
    steps: [privileged]
",
    );
    for dry in [false, true] {
        let mut args = vec!["job", "run"];
        if dry {
            args.push("--dry-run");
        }
        args.push("finish");
        let output = run(&root, &args);
        assert_eq!(output.status.code(), Some(5), "{output:?}");
        assert!(!root.path().join("wrong").exists());
    }
}

#[test]
fn task_wait_validation_and_plan_metadata_are_actionable() {
    let root = project(
        r"
tasks:
  worker: {background: true, uses: portable, run: 'true'}
  finish: {wait: [worker]}
",
    );
    let output = run(&root, &["task", "plan", "finish", "--format", "json"]);
    let json: serde_json::Value = serde_json::from_str(&success(&output)).unwrap();
    assert_eq!(json["tasks"][0]["background"], true);
    assert_eq!(json["tasks"][1]["wait"][0], "worker");

    for yaml in [
        "tasks: {finish: {wait: [missing]}}",
        "tasks: {finish: {wait: [other]}, other: {wait: [finish]}}",
        "tasks: {finish: {wait: [missing], wait-all: true}}",
        "tasks: {worker: 'true', finish: {needs: {worker: {parallel: true}}, uses: portable, run: 'true'}}",
    ] {
        let root = project(yaml);
        let output = run(&root, &["run", "finish", "--dry-run"]);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
    }
}
