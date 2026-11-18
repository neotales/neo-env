//! Which commands survive a task whose `extends:` names a base that does not exist.
//!
//! ## Why this is one test file rather than a unit test
//!
//! **The bug was never in a function.** `resolve_inheritance` was correct and
//! `ResolvedProject` was correct; what was wrong was that one of them was called
//! from a place that made a project-wide check a precondition of every operation.
//! A unit test on either would have passed throughout.
//!
//! So every case here runs the binary. The property under test is *which command
//! calls what*, and that is only observable from outside the process.
//!
//! ## The four answers
//!
//! | command | answer | why |
//! |---------|--------|-----|
//! | `config`, `context` | succeed | task inheritance is not one of their inputs |
//! | `task list` | list what was declared, exit non-zero | a refusal that hides the tasks is indistinguishable from a project with none |
//! | `inspect` | report the project, exit non-zero | same, and the shape is a published contract so the failure goes beside it |
//! | `validate` | refuse | naming project-wide problems is its job |
//! | `run <good>` | succeed | a dangling base in a task you did not ask about is not your problem |
//! | `run <the broken one>` | refuse, naming *its* base | the error must be about the task you ran |
//!
//! Two of these are the ones a naive fix gets wrong in opposite directions: making
//! everything permissive (a run of the broken task then reports the wrong thing) and
//! making everything strict (which is the bug).
//!
//! ## The inheritance/dependency fixpoint
//!
//! `release` declares no `needs` of its own and inherits `needs: [lint]` from the
//! base it extends. Resolving inheritance once and then walking the *resolved*
//! definitions is not enough — the dependency is only visible after resolution — so
//! the closure has to iterate. A test that runs `release` and checks the output
//! contains `lint` is the only thing that catches a fixpoint that stopped after one
//! pass, and that regression is silent: the run would fail with "depends on missing
//! task lint" for a task that exists.

use std::path::Path;

use tempfile::tempdir;

/// A project whose only fault is one dangling `extends:`.
///
/// `release` deliberately inherits its `needs` from the base it extends, so this
/// fixture exercises the fixpoint as well as the scoping.
const FIXTURE: &str = "\
format_version: 1
tasks:
  lint:
    uses: portable
    run: echo LINTED
  build:
    uses: portable
    needs: [lint]
    run: echo BUILT
  # Declares no needs of its own; inherits `needs: [lint]` from `build`.
  release:
    extends: build
    run: echo RELEASED
  broken:
    extends: nowhere
    run: echo THIS-MUST-NEVER-RUN
";

mod support;

fn project() -> tempfile::TempDir {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("neoenv.yaml"), FIXTURE).expect("the fixture writes");
    dir
}

/// Runs `nenv` in `dir` and returns `(exit code, stdout, stderr)`.
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

/// A command that does not read tasks must not be taken down by one that cannot
/// resolve.
#[test]
fn commands_that_do_not_read_tasks_succeed() {
    let dir = project();
    for command in [vec!["config"], vec!["context"], vec!["context", "list"]] {
        let (code, stdout, stderr) = run(dir.path(), &command);
        assert_eq!(
            code,
            0,
            "`nenv {}` must not fail because an unrelated task names a base that does \
             not exist. Task inheritance is not one of its inputs.\nstderr: {stderr}",
            command.join(" ")
        );
        assert!(
            !stderr.contains("extends"),
            "`nenv {}` mentioned inheritance on stderr: {stderr}",
            command.join(" ")
        );
        let _ = stdout;
    }
}

/// `task list` must list the tasks and still fail, because a list that quietly
/// drops a task the user declared is the absence standing in for a failure.
#[test]
fn task_list_reports_the_tasks_and_still_fails() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["task", "list"]);
    assert_ne!(
        code, 0,
        "an exit status of 0 would report a clean project. stderr: {stderr}"
    );
    for expected in ["build", "release", "broken", "lint"] {
        assert!(
            stdout.lines().any(|line| line.trim() == expected),
            "the declared task `{expected}` is missing from the listing, so a reader \
             cannot tell it was dropped from that it does not exist.\nstdout:\n{stdout}"
        );
    }
    assert!(
        stderr.contains("nowhere"),
        "the reason inheritance did not resolve has to be on stderr, or a non-zero \
         status says only that something failed.\nstderr: {stderr}"
    );
}

/// The JSON form has to be machine-readable in the same way, and `unresolved` is
/// present only when something is wrong so a consumer can branch on the key.
#[test]
fn task_list_json_carries_the_failure_and_only_when_there_is_one() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["task", "list", "--format", "json"]);
    assert_ne!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("the listing is JSON on stdout");
    let names: Vec<&str> = value["tasks"]
        .as_array()
        .expect("tasks is an array")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    assert!(
        names.contains(&"release") && names.contains(&"broken"),
        "the declared tasks are listed, got {names:?}"
    );
    assert!(
        value["unresolved"].is_string(),
        "`unresolved` is absent on a project with a real fault, so a consumer has \
         nothing to branch on: {value}"
    );

    // And on a project with no fault, the key is absent rather than null -- a key
    // that is always present is a second thing every consumer has to check.
    let clean = tempdir().expect("a temporary directory");
    std::fs::write(
        clean.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the clean fixture writes");
    let (clean_code, clean_stdout, clean_stderr) =
        run(clean.path(), &["task", "list", "--format", "json"]);
    assert_eq!(clean_code, 0, "stderr: {clean_stderr}");
    let clean_value: serde_json::Value =
        serde_json::from_str(&clean_stdout).expect("the clean listing is JSON");
    assert!(
        clean_value.get("unresolved").is_none(),
        "`unresolved` is present on a project that is fine, so its presence means \
         nothing: {clean_value}"
    );
}

/// `inspect` reports the project *and* the fault, and does not change its document
/// shape to do it: `inspection-v2.schema.json` is a published contract.
#[test]
fn inspect_reports_the_project_and_fails_without_changing_its_shape() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["inspect"]);
    assert_ne!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("release") && stdout.contains("broken"),
        "a project with tasks must not inspect as though it had none.\nstdout:\n{stdout}"
    );
    assert!(stderr.contains("nowhere"), "stderr: {stderr}");

    let (json_code, json_stdout, json_stderr) = run(dir.path(), &["inspect", "--format", "json"]);
    assert_ne!(json_code, 0, "stderr: {json_stderr}");
    let value: serde_json::Value =
        serde_json::from_str(&json_stdout).expect("inspect emits JSON on stdout");
    let tasks = value["tasks"].as_array().expect("tasks is an array");
    assert_eq!(
        tasks.len(),
        4,
        "every declared task is reported, got {}",
        value["tasks"]
    );
    // The schema keys are exactly the published ones. A new key here would change
    // what every consumer of `inspect --format json` sees.
    for key in value.as_object().expect("an object").keys() {
        assert!(
            [
                "schema_version",
                "format_version",
                "sources",
                "environment",
                "path",
                "tasks"
            ]
            .contains(&key.as_str()),
            "inspect gained the key `{key}`, which is a change to a published contract"
        );
    }
}

/// `validate` is the one command that must refuse, and refusing before it prints
/// "valid" is the only honest ordering.
#[test]
fn validate_refuses_and_never_prints_valid() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["validate"]);
    assert_ne!(code, 0, "a project with a dangling base is not valid");
    assert!(
        !stdout.contains("valid:"),
        "`validate` printed a success line and then failed: {stdout}"
    );
    assert!(stderr.contains("nowhere"), "stderr: {stderr}");

    // And a clean project still validates, so the refusal is not unconditional.
    let clean = tempdir().expect("a temporary directory");
    std::fs::write(
        clean.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the clean fixture writes");
    let (clean_code, clean_stdout, clean_stderr) = run(clean.path(), &["validate"]);
    assert_eq!(clean_code, 0, "stderr: {clean_stderr}");
    assert!(
        clean_stdout.contains("valid:"),
        "a clean project must still validate: {clean_stdout}"
    );
}

/// The other half: a run must work. Refusing here is the original bug, and a fix
/// that made every command permissive would be caught by the next test rather than
/// by this one.
#[test]
fn a_task_that_does_not_extend_anything_runs_on_this_project() {
    let dir = project();
    for task in ["build", "release"] {
        let (code, stdout, stderr) = run(dir.path(), &["run", task]);
        assert_eq!(
            code, 0,
            "`nenv run {task}` must work on a project whose only fault is an \
             unrelated dangling base.\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains("THIS-MUST-NEVER-RUN"),
            "`nenv run {task}` ran the broken task: {stdout}"
        );
    }
}

/// The fixpoint. `release` declares no `needs` and inherits `needs: [lint]`, so the
/// dependency is only visible *after* inheritance resolves. One pass would plan
/// `release` alone and fail with a missing dependency in a task that exists.
#[test]
fn an_inherited_dependency_is_planned_and_run() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["run", "release"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("LINTED"),
        "`release` inherits `needs: [lint]`, so lint must run first. The \
         inheritance/dependency closure takes more than one pass and this is what \
         catches a version that takes one.\nstdout:\n{stdout}"
    );
    let lint_first = stdout
        .find("LINTED")
        .is_some_and(|lint| stdout.find("RELEASED").is_some_and(|rel| lint < rel));
    assert!(
        lint_first,
        "the inherited dependency must run before its dependent"
    );

    let (plan_code, plan_stdout, plan_stderr) = run(dir.path(), &["task", "plan", "release"]);
    assert_eq!(plan_code, 0, "stderr: {plan_stderr}");
    assert!(
        plan_stdout.contains("lint"),
        "the plan omits the inherited dependency:\n{plan_stdout}"
    );
}

/// And the refusal that remains must be about the task that was run, naming its own
/// base -- not about a bystander.
#[test]
fn running_the_broken_task_refuses_and_names_its_own_base() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["run", "broken"]);
    assert_ne!(code, 0, "a dangling base must not run");
    assert!(
        !stdout.contains("THIS-MUST-NEVER-RUN"),
        "the broken task ran anyway: {stdout}"
    );
    assert!(
        stderr.contains("broken") && stderr.contains("nowhere"),
        "the refusal has to name the task that was run and the base it names, or it \
         is a message about something the reader cannot see.\nstderr: {stderr}"
    );
    for bystander in ["build", "release", "lint"] {
        assert!(
            !stderr.contains(bystander),
            "the refusal blames `{bystander}`, which the reader did not run:\n{stderr}"
        );
    }
}

/// A cycle is still reported when the caller asked for the cyclic task, because a
/// chain that cannot resolve into anything is not "partially fine".
#[test]
fn a_cycle_in_the_requested_chain_is_reported() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  a:\n    extends: b\n    run: echo A\n  b:\n    extends: a\n    \
         run: echo B\n  fine:\n    uses: portable\n    run: echo FINE\n",
    )
    .expect("the fixture writes");
    let (code, _, stderr) = run(dir.path(), &["run", "a"]);
    assert_ne!(code, 0, "a cycle must not resolve");
    assert!(!stderr.is_empty(), "the cycle has to be explained");

    // The unrelated task is still runnable, which is the scoping this whole file
    // is about.
    let (fine_code, fine_stdout, fine_stderr) = run(dir.path(), &["run", "fine"]);
    assert_eq!(
        fine_code, 0,
        "a cycle in `a`/`b` must not stop an unrelated task.\nstderr: {fine_stderr}"
    );
    assert!(fine_stdout.contains("FINE"), "stdout: {fine_stdout}");
}
