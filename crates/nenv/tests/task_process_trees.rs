//! What happens to a task's children when the run ends — measured, not assumed.
//!
//! ## Why this file exists
//!
//! A gap ticket (#267) was filed from a grep that said the task runner had no process
//! containment. The grep was scoped to `lib/neoenv-runtime/src/tasks/process.rs`,
//! which **does not spawn anything** — it parses timeouts. The spawning and the
//! containment are in `neotales-process`, two crates away, and both are there:
//!
//! ```text
//! rust-libraries/os/process/src/lib.rs:542:    command.process_group(0);
//! rust-libraries/os/process/src/lib.rs:559:    match kill(Pid::from_raw(-process_group), Signal::SIGKILL)
//! rust-libraries/os/process/src/lib.rs:573:    let status = Command::new("taskkill")
//! ```
//!
//! So the ticket asserted a defect that does not exist, and this file is what
//! established that — by **running** it rather than reading it. A grep over the wrong
//! crate is the same class of error as a grep for the wrong word: a real symbol nearby
//! and nothing about the thing asked about.
//!
//! ## What the measurement found
//!
//! | the run ends because | the task's backgrounded grandchild |
//! |---|---|
//! | the task's own timeout | **gone** — the group kill takes it |
//! | the task finished normally | **alive** — deliberate, and correct |
//! | `nenv run` was cancelled (SIGTERM) | **alive** — **this is the defect** |
//!
//! The second row is right and must stay right: a task that backgrounds a watcher and
//! exits zero means it, and reaping it would break that. The third row is not
//! defensible — a user who interrupts a run believes the work stopped.
//!
//! ## And the cancellation row, which was asserted twice and was wrong twice
//!
//! A gap ticket claimed `nenv run` left the task's children running on cancellation,
//! on the strength of this:
//!
//! ```text
//! $ nenv run quick &
//! $ kill -INT <nenv>
//! nenv: gone (default handler -- it died immediately)
//! grandchild: ALIVE
//! ```
//!
//! **The fixture was `sh -c 'sleep 300 & echo $!; exit 0'` — a task that exits
//! immediately.** So `nenv` had already finished when the signal was sent ("No such
//! process"), and the `sleep 300` found afterwards belonged to a *completed* run. The
//! surviving child was real; the attribution was invented. The same conclusion was then
//! reached a second time from a stale binary.
//!
//! Measured properly, every path contains:
//!
//! | path | the task's grandchild after SIGINT |
//! |---|---|
//! | one task, `portable` | gone |
//! | one task, `shell` | gone |
//! | one task, `argv` | gone |
//! | a dependency chain | gone |
//! | two tasks in parallel | **both** gone |
//! | a job's step | gone |
//!
//! The mechanism is `neotales-process`'s `wait_for_children`, which already checks
//! `is_cancelled()` and calls the same `stop_process_tree` group kill the timeout uses,
//! and `nenv` already installs the handler through `task_cancellation()` ->
//! `ctrl_c_signal()`. **Both halves existed; the ticket described a gap between two
//! things that were already joined.**
//!
//! So these are the assertions. A defect claimed here twice, from setups that did not
//! exercise the path, is the cheapest thing in the repository to defend against a test
//! that does exercise it.

#![cfg(unix)]

use std::{
    fs,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use tempfile::tempdir;

/// A task that backgrounds a grandchild and then waits, so the grandchild is alive
/// when the run is cut short.
///
/// `sleep 300 &` then `echo $!` then `sleep 300`: the echo is what makes the pid
/// observable, and the second sleep is what keeps the task running so something has to
/// end it. A task that finished on its own would prove nothing.
const SPAWNER: &str = "\
format_version: 1
tasks:
  spawner:
    uses: portable
    run: \"sh -c 'sleep 120 & echo $!; sleep 120'\"
    with:
      timeout: 2s
";

/// A task that backgrounds a grandchild and exits zero, deliberately.
///
/// **The grandchild's output is redirected away from the pipe, and that is not a
/// detail.** `Command::output()` reads to EOF, and a backgrounded child *inherits*
/// nenv's stdout pipe -- so a grandchild that keeps the pipe open holds the reader
/// until it exits. The first version of this test took 300 seconds and then reported
/// the grandchild reaped, which is the test measuring its own harness: by the time
/// `output()` returned, the `sleep` had finished on its own and there was nothing left
/// to find.
///
/// A test whose failure is really a hang in the measurement is worse than no test,
/// because the number it reports is a confident wrong answer rather than a slow one.
const SURVIVOR: &str = "\
format_version: 1
tasks:
  survivor:
    uses: portable
    run: \"sh -c 'sleep 120 >/dev/null 2>&1 & echo $!; exit 0'\"
";

mod support;

fn project(body: &str) -> tempfile::TempDir {
    let directory = tempdir().expect("a temporary directory");
    fs::write(directory.path().join("neoenv.yaml"), body).expect("the fixture writes");
    directory
}

fn run(directory: &Path, arguments: &[&str]) -> std::process::Output {
    support::TestCommand::new()
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("the binary runs")
}

/// Whether a pid is still a live process this user can signal.
///
/// `kill -0` is the test, and its failure modes matter: a pid we do not own, and a
/// pid that has been reaped and **recycled**, both answer "gone" for different
/// reasons. The window here is a couple of seconds on a freshly allocated pid, so a
/// recycle is not a realistic explanation, and a wrong answer in the direction of
/// "gone" is the safe one for a test whose job is to catch a survivor.
fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        // `kill -0` on a dead pid exits 1 **and writes to stderr**. That is the
        // expected answer here, and a suite that prints errors it means to have is
        // the "an absence must be distinguishable from a failure" rule run
        // backwards: a reader scanning the output cannot tell a probe from a break.
        .stderr(std::process::Stdio::null())
        .status()
        // `is_ok_and` rather than `map(..).unwrap_or(..)`: the `Result` is the thing
        // being asked about, and a `kill` that could not be run is not a live process.
        .is_ok_and(|status| status.success())
}

/// The pid the task printed, read from its output.
///
/// Parsed rather than pattern-matched loosely, because a line that merely *contains*
/// digits is not a pid, and a test that accepts any number would pass on the elapsed
/// time or the exit code.
fn spawned_pid(output: &std::process::Output) -> u32 {
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.trim().parse::<u32>().ok())
        .unwrap_or_else(|| {
            panic!(
                "the task printed no pid:\nstdout: {text}\nstderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

/// **A timed-out task's children die with it.** This is the half that already works,
/// pinned so it cannot regress while the other half is fixed.
#[test]
fn a_timeout_contains_the_task_process_tree() {
    let directory = project(SPAWNER);
    let output = run(directory.path(), &["run", "spawner"]);

    assert_eq!(
        output.status.code(),
        Some(6),
        "a timeout must not exit 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("TimedOut"),
        "the outcome must say it timed out rather than only that it failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let pid = spawned_pid(&output);

    // The kill and the exit are separate events, so poll rather than assert once: a
    // single check races the signal handler and would fail intermittently, and a test
    // that fails intermittently is a test people learn to re-run.
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(
        !alive(pid),
        "the grandchild {pid} survived the timeout. The task reported TimedOut and \
         the work went on, which is the failure this asserts against: a timeout that \
         stops only the immediate child leaves descendants holding ports and CPU."
    );
}

/// **A task that finishes normally keeps its backgrounded child.** Deliberate, and the
/// counterpart to the test above.
///
/// A task that starts a watcher and exits zero means it. Reaping the group on a
/// successful exit would break that, so this is the row that says the containment is
/// scoped rather than blanket — and it is why the fix for the cancellation case cannot
/// simply be "always kill the group".
#[test]
fn a_successful_run_keeps_what_the_task_deliberately_left_running() {
    let directory = project(SURVIVOR);
    let output = run(directory.path(), &["run", "survivor"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pid = spawned_pid(&output);
    assert!(
        alive(pid),
        "the grandchild {pid} was reaped after a successful run. A task that \
         backgrounds a watcher and exits zero means it, and this row is what stops a \
         fix for the cancellation case from becoming a blanket group kill."
    );

    // Leave the machine as we found it. A test that leaks a sleeping process is a test
    // that makes the next one slower and the suite's process report wrong.
    let _ = Command::new("kill")
        .args([pid.to_string().as_str()])
        .stderr(std::process::Stdio::null())
        .status();
}
/// Every runner and every chain shape, with a grandchild to find.
///
/// **One test, six fixtures, because the claim is uniform and a uniform claim proved
/// once is the claim that was wrong the first time.** A gap ticket asserted a defect
/// here twice — once from a fixture whose task exited immediately, so the signal went
/// to a process already gone, and once from a stale binary. Both times the surviving
/// child was real and the *attribution* was invented.
///
/// Output goes to a **file**, not a pipe. A pipe would need a reader thread (a blocking
/// `read` on the child's stdout hangs until the grandchild exits, which is the bug the
/// first version of this file had) and a file is pollable without either. The grandchild
/// redirects its own output, so the file's writer set closes when the task's direct
/// child exits and the size stops growing.
#[test]
fn cancellation_contains_the_tree_on_every_path() {
    /// `uses:` is varied deliberately. `portable` goes through `execute_chain`, and
    /// `shell` and `argv` are separate paths; a claim covering only the one that was
    /// measured is the claim that was wrong the first time.
    const LONGRUNNING: &str = "sh -c 'sleep 120 >/dev/null 2>&1 & echo $!; sleep 120'";
    let escaped = LONGRUNNING.replace('\\', "\\\\").replace('"', "\\\"");

    let cases: [(&str, String, &[&str]); 6] = [
        (
            "one task, portable",
            format!(
                "format_version: 1\ntasks:\n  a:\n    uses: portable\n    run: \"{escaped}\"\n"
            ),
            &["run", "a"],
        ),
        (
            "one task, shell",
            format!("format_version: 1\ntasks:\n  a:\n    uses: shell\n    run: \"{escaped}\"\n"),
            &["run", "a"],
        ),
        (
            "one task, argv",
            String::from(
                "format_version: 1\ntasks:\n  a:\n    uses: argv\n    run: sh\n    args: [-c, 'sleep 120 >/dev/null 2>&1 & echo $!; sleep 120']\n",
            ),
            &["run", "a"],
        ),
        (
            "a dependency chain",
            format!(
                "format_version: 1\ntasks:\n  a:\n    uses: portable\n    run: \"{escaped}\"\n  b:\n    uses: portable\n    needs: [a]\n    run: echo done\n"
            ),
            &["run", "b"],
        ),
        (
            "two tasks in parallel",
            format!(
                "format_version: 1\ntasks:\n  a:\n    uses: portable\n    run: \"{escaped}\"\n  b:\n    uses: portable\n    run: \"{escaped}\"\n  both:\n    uses: portable\n    needs: [a, b]\n    run: echo done\n"
            ),
            &["run", "both"],
        ),
        (
            "a job's step",
            format!(
                "format_version: 1\ntasks:\n  step1:\n    uses: portable\n    run: \"{escaped}\"\njobs:\n  j:\n    steps:\n      - task: step1\n"
            ),
            &["job", "run", "j"],
        ),
    ];

    for (name, body, arguments) in cases {
        let directory = project(&body);
        let log = directory.path().join("run.log");
        let file = fs::File::create(&log).expect("the log file is created");
        let mut child = support::TestCommand::new()
            .args(arguments)
            .current_dir(directory.path())
            .stdout(file.try_clone().expect("the log is duplicable"))
            .stderr(file)
            .spawn()
            .unwrap_or_else(|error| panic!("{name}: the binary runs: {error}"));

        // **Wait for the task to print its grandchild's pid** rather than sleeping a
        // fixed time. A fixed sleep is exactly how the first attempt signalled a
        // process that had already exited and called the result a leak.
        let pids = wait_for_pids(&log, Duration::from_secs(20));
        assert!(
            !pids.is_empty(),
            "{name}: the task printed no pid; log:\n{}",
            read(&log)
        );

        // SIGINT, not SIGTERM: this is the key the user presses.
        let _ = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            // A run that finished between the pid arriving and the signal is a
            // *pass* for every assertion after this except the exit code, and
            // `kill` saying so on stderr would be noise shaped like a failure.
            .stderr(std::process::Stdio::null())
            .status();
        let status = child.wait().expect("the run finishes");

        let log_text = read(&log);
        assert!(
            !status.success(),
            "{name}: a cancelled run must not exit 0, or Ctrl-C reads as success. \
             status: {status:?}\nlog: {log_text}"
        );
        assert!(
            log_text.contains("Cancelled") || log_text.contains("cancelled"),
            "{name}: the run must say it was cancelled. A reader who pressed Ctrl-C and \
             got no reason has to assume the tool crashed: {log_text}"
        );

        for pid in pids {
            let deadline = Instant::now() + Duration::from_secs(10);
            while alive(pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                !alive(pid),
                "{name}: grandchild {pid} survived SIGINT. The run reported Cancelled \
                 and the work went on, which is a user who interrupted a run and is \
                 still paying for it."
            );
        }
    }
}

/// Every pid the run has printed so far, polled until there is at least one.
fn wait_for_pids(log: &Path, within: Duration) -> Vec<u32> {
    let deadline = Instant::now() + within;
    loop {
        let pids: Vec<u32> = read(log)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .filter(|pid| *pid > 1)
            .collect();
        if !pids.is_empty() || Instant::now() >= deadline {
            return pids;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}
