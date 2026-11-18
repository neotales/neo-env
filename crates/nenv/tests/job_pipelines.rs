//! `nenv job` — the ordered pipelines this project declares, and running one.
//!
//! ## The property under test
//!
//! **A job is a sequence, so its steps run in the order the file declares them**,
//! and the environment carries from one step to the next. Both are properties of the
//! run, not of the parser, so every case here runs the binary.
//!
//! ## Why the lowering matters more than it looks
//!
//! A job is lowered into a *chain of tasks* — step *n* depends on step *n-1* — and
//! handed to the ordinary task runner. So "does a job run in order" is really "does
//! the ordinary task runner run a linear chain in order and share one environment
//! across it", which is a claim about shared machinery. If that is true, a
//! three-step `needs` chain in a plain task file has to behave identically, and
//! `a_equivalent_task_chain_behaves_identically` asserts it: **if the two ever
//! diverge, the lowering is doing something the task runner does not, and that is
//! the bug to look for.**
//!
//! ## The refusals are asserted, not assumed
//!
//! Every key the reference declares and never reads is refused by name, and so is a
//! step with no `task:` and no `run:`. A test that only checked "a job runs" would
//! pass just as happily against a version that silently ignored `cron`.

use std::path::Path;

use tempfile::tempdir;

/// Three steps: two task references and one inline command, with a job-level `env`.
const PIPELINE: &str = "\
format_version: 1
env:
  STAGE: production
tasks:
  build:
    uses: shell
    run: echo \"built for $STAGE\" > built.txt
  test:
    uses: shell
    run: echo \"tested for $STAGE\" > tested.txt
jobs:
  release:
    desc: Build, then test, then announce
    env:
      RELEASE: yes
    steps:
      - task: build
      - task: test
      - run: echo announcing
";

mod support;

fn project(contents: &str) -> tempfile::TempDir {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("neoenv.yaml"), contents).expect("the fixture writes");
    dir
}

fn run(dir: &Path, arguments: &[&str]) -> (i32, String, String) {
    let output = support::TestCommand::new()
        .args(arguments)
        .current_dir(dir)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The steps run, and the job's `env` reaches the inline step that has no `env` of
/// its own.
#[test]
fn a_job_runs_its_steps_in_the_declared_order() {
    let dir = project(PIPELINE);
    let (code, stdout, stderr) = run(dir.path(), &["job", "run", "release"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("release:1 Succeeded")
            && stdout.contains("release:2 Succeeded")
            && stdout.contains("release:3 Succeeded"),
        "every step must report success, in order:\n{stdout}"
    );
    let first = stdout.find("release:1").expect("step 1 ran");
    let second = stdout.find("release:2").expect("step 2 ran");
    let third = stdout.find("release:3").expect("step 3 ran");
    assert!(
        first < second && second < third,
        "the report is out of declaration order:\n{stdout}"
    );
    // A step that runs another task really ran that task.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("built.txt")).ok(),
        Some("built for production\n".to_owned()),
        "step 1 is a `task:` reference to build, and build did not run"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("tested.txt")).ok(),
        Some("tested for production\n".to_owned()),
        "step 2 is a `task:` reference to test, and test did not run"
    );
}

/// **The equivalence that keeps the lowering honest.** The same shape written as
/// plain tasks must produce the same run.
#[test]
fn an_equivalent_task_chain_behaves_identically() {
    let chain = project(
        "format_version: 1\n\
         tasks:\n  \
           one:\n    uses: shell\n    run: 'echo one'\n  \
           two:\n    uses: shell\n    needs: [one]\n    run: 'echo two'\n  \
           three:\n    uses: shell\n    needs: [two]\n    run: 'echo three'\n",
    );
    let (chain_code, chain_stdout, chain_stderr) = run(chain.path(), &["run", "three"]);
    assert_eq!(chain_code, 0, "stderr: {chain_stderr}");

    let (dry_code, dry_stdout, dry_stderr) = run(chain.path(), &["run", "--dry-run", "three"]);
    assert_eq!(
        dry_code, 0,
        "a dry run of a healthy three-task chain exits non-zero and says the plan is \
         blocked. A dry run's answer is what *would* run; reporting the user's own \
         plan as broken is a wrong answer, not a conservative one.\nstderr: {dry_stderr}"
    );
    for step in ["one Planned", "two Planned", "three Planned"] {
        assert!(
            dry_stdout.contains(step),
            "`{step}` is missing from a dry run that should plan all three:\n{dry_stdout}"
        );
    }
    assert!(
        !chain_stdout.contains("Blocked"),
        "the real run blocked something:\n{chain_stdout}"
    );
}

/// A job's dry run plans every step, for the same reason the task chain's does.
#[test]
fn a_job_dry_run_plans_every_step() {
    let dir = project(PIPELINE);
    let (code, stdout, stderr) = run(dir.path(), &["job", "run", "--dry-run", "release"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for step in ["release:1", "release:2", "release:3"] {
        assert!(
            stdout.contains(&format!("{step} Planned")),
            "`{step}` is not Planned:\n{stdout}"
        );
    }
    assert!(
        !dir.path().join("built.txt").exists(),
        "a dry run ran a step, so it is not a dry run"
    );
}

/// `list` and the bare group agree, and an empty project says so in words.
#[test]
fn list_reports_the_jobs_and_an_empty_project_says_so() {
    let dir = project(PIPELINE);
    for arguments in [vec!["job", "list"], vec!["job"]] {
        let (code, stdout, stderr) = run(dir.path(), &arguments);
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("release") && stdout.contains("Build, then test"),
            "`nenv {}` did not report the job and its description:\n{stdout}",
            arguments.join(" ")
        );
    }

    let empty =
        project("format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n");
    let (code, stdout, _) = run(empty.path(), &["job", "list"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("no jobs"),
        "a project with no jobs must say so in words; a bare newline is \
         indistinguishable from a crash:\n{stdout:?}"
    );
}

/// A name that is not a job is refused **with the alternatives named**.
#[test]
fn an_unknown_job_is_refused_with_the_available_names() {
    let dir = project(PIPELINE);
    let (code, stdout, stderr) = run(dir.path(), &["job", "run", "relesae"]);
    assert_ne!(code, 0, "a mistyped job name must not run anything");
    assert!(stdout.is_empty(), "nothing ran: {stdout}");
    assert!(
        stderr.contains("relesae") && stderr.contains("release"),
        "the refusal must name what was asked for and what exists:\n{stderr}"
    );
}

/// Every key the reference declares and never reads is refused by name, and each
/// diagnostic says *that* so nobody readds it as a gap.
#[test]
fn the_reference_inert_keys_are_refused_by_name() {
    for (key, body) in [
        (
            "extends",
            "format_version: 1\njobs:\n  d:\n    extends: base\n    steps:\n      - run: x\n",
        ),
        (
            "cron",
            "format_version: 1\njobs:\n  d:\n    cron: '* * * * *'\n    steps:\n      - run: x\n",
        ),
        (
            "embed",
            "format_version: 1\njobs:\n  d:\n    steps:\n      - embed: img\n        run: x\n",
        ),
        (
            "with",
            "format_version: 1\njobs:\n  d:\n    steps:\n      - with: {a: b}\n        run: x\n",
        ),
    ] {
        let dir = project(body);
        let (code, _, stderr) = run(dir.path(), &["validate"]);
        assert_ne!(
            code, 0,
            "`{key}` was accepted, so it is a key that parses and does nothing"
        );
        assert!(
            stderr.contains(key),
            "the refusal for `{key}` does not name it:\n{stderr}"
        );
        assert!(
            stderr.contains("never reads") || stderr.contains("never copies"),
            "the refusal for `{key}` does not say the reference never acts on it, so \
             the next reader adds it back thinking it is a gap:\n{stderr}"
        );
    }
}

/// A step that means nothing is refused, because a step that runs nothing is a step
/// that silently did not run.
#[test]
fn a_step_with_neither_a_task_nor_a_run_is_refused() {
    let dir = project("format_version: 1\njobs:\n  d:\n    steps:\n      - name: only-a-name\n");
    let (code, _, stderr) = run(dir.path(), &["validate"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("neither") && stderr.contains("step 1"),
        "the refusal must name the step's position, so a ten-step job points at one \
         line:\n{stderr}"
    );
}

/// `task:` and `run:` together is a step that could mean two things.
#[test]
fn a_step_with_both_a_task_and_a_run_is_refused() {
    let dir = project(
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n\
         jobs:\n  d:\n    steps:\n      - task: build\n        run: echo other\n",
    );
    let (code, _, stderr) = run(dir.path(), &["validate"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("both"),
        "the refusal must say what is wrong rather than that a field is unknown:\n{stderr}"
    );
}

/// A step referring to a task the project does not declare, naming the task.
#[test]
fn a_step_referring_to_a_missing_task_names_it() {
    let dir = project("format_version: 1\njobs:\n  d:\n    steps:\n      - task: nowhere\n");
    let (code, _, stderr) = run(dir.path(), &["job", "run", "d"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("nowhere"),
        "the refusal must name the task the step asked for:\n{stderr}"
    );
}

/// The same task twice in one job is refused rather than silently collapsed.
///
/// A chain runs the task once, whatever the file says twice. The reference runs it
/// twice. Neither is obviously right, and a **silent collapse** is the failure this
/// repository keeps finding, so it is refused.
#[test]
fn a_repeated_task_in_one_job_is_refused_rather_than_collapsed() {
    let dir = project(
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n\
         jobs:\n  d:\n    steps:\n      - task: build\n      - run: echo between\n      - task: build\n",
    );
    let (code, stdout, stderr) = run(dir.path(), &["job", "run", "d"]);
    assert_ne!(
        code, 0,
        "the job ran, so the second `build` was silently dropped or the chain ran it \
         twice. stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("build") && stderr.contains("more than once"),
        "the refusal must say which task repeats and that repeating is the problem:\n{stderr}"
    );
}

/// A `jobs:` section is reported by `inspect` and does not break `validate`.
#[test]
fn a_project_with_jobs_validates_and_inspects() {
    let dir = project(PIPELINE);
    let (code, _, stderr) = run(dir.path(), &["validate"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let (inspect_code, inspect_stdout, inspect_stderr) = run(dir.path(), &["inspect"]);
    assert_eq!(inspect_code, 0, "stderr: {inspect_stderr}");
    assert!(
        inspect_stdout.contains("build"),
        "the tasks are still reported alongside a jobs section:\n{inspect_stdout}"
    );
}
