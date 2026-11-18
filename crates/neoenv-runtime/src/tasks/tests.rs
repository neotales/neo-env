//! Task execution tests for environment expansion, shell-free dispatch,
//! short-circuiting, force predicates, and hook failure handling.

use std::{
    collections::{BTreeMap, HashSet},
    error::Error as _,
};

use super::{
    InstallIdentity, ManagedRuntime, TaskCancellation, TaskEnvironment, TaskOutcome, TaskRunError,
    TaskRunOptions, TaskRunReport, TaskRunnerDirectories, interpolate_portable_environment,
    run_tasks, run_tasks_with_cancellation,
};
use indexmap::{IndexMap, indexmap};
use neoenv_core::tasks::{TaskAction, TaskDefinition, TaskError, TaskHooks};
use neoenv_policy::CapabilityGrants;
use std::{fs, path::Path};

#[test]
fn portable_environment_expands_only_explicit_braced_references() {
    let environment =
        std::collections::BTreeMap::from([("GREETING".into(), "Hello from nenv".into())]);
    assert_eq!(
        interpolate_portable_environment("echo ${GREETING} $GREETING", &environment),
        "echo Hello from nenv $GREETING"
    );
}

#[test]
fn portable_task_renders_and_executes_literal_argv_without_a_shell() {
    let tasks = indexmap! {
        "portable".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("portable".into()),
                // A shell would expand the double-quoted value and fail this comparison.
                run: Some("test \"$HOME\" = '$HOME' && test {{ .env.HOME }} = /not-literal".into()),
                env: indexmap! { "HOME".into() => "/not-literal".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let report = run_tasks(
        &tasks,
        "portable",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        false,
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
}

#[test]
fn portable_chain_short_circuits_and_sequences_without_a_shell() {
    let tasks = indexmap! {
        "portable".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("portable".into()),
                run: Some("false && false || printf x | grep x; true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let report = run_tasks(
        &tasks,
        "portable",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        false,
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
}

#[test]
fn force_predicate_can_run_a_recovery_task_after_a_failed_dependency() {
    let tasks = indexmap! {
        "prepare".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("argv".into()), run: Some("false".into()), ..TaskAction::default() }),
            ..TaskDefinition::default()
        },
        "cleanup".into() => TaskDefinition {
            needs: vec!["prepare".into()],
            force: Some("outcome.prepare == failed".into()),
            action: Some(TaskAction { uses: Some("argv".into()), run: Some("true".into()), ..TaskAction::default() }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let report = run_tasks(
        &tasks,
        "cleanup",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        false,
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert_eq!(report.tasks[1].outcome, TaskOutcome::Succeeded);
}

#[test]
fn failed_before_hook_blocks_its_task_and_after_hook() {
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("argv".into()), run: Some("true".into()), ..TaskAction::default() }),
            hooks: TaskHooks { before: vec!["before".into()], after: vec!["after".into()] },
            ..TaskDefinition::default()
        },
        "build:before".into() => TaskDefinition { action: Some(TaskAction { uses: Some("argv".into()), run: Some("false".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "build:after".into() => TaskDefinition { action: Some(TaskAction { uses: Some("argv".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    let values = IndexMap::new();
    let report = run_tasks(
        &tasks,
        "build",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        false,
    )
    .unwrap();
    assert_eq!(
        report
            .tasks
            .iter()
            .map(|task| (&task.name, task.outcome))
            .collect::<Vec<_>>(),
        [
            (&"build:before".to_owned(), TaskOutcome::Failed),
            (&"build".to_owned(), TaskOutcome::Blocked),
            (&"build:after".to_owned(), TaskOutcome::Blocked),
        ]
    );
}

#[test]
fn planning_parser_source_is_reachable_from_task_error() {
    let tasks = indexmap! {
        "broken".into() => TaskDefinition {
            needs: vec!["missing".into()],
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let error = run_tasks(
        &tasks,
        "broken",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        true,
    )
    .unwrap_err();

    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<TaskError>())
            .is_some()
    );
}

#[test]
fn cancellation_prevents_hook_graph_execution() {
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("argv".into()), run: Some("false".into()), ..TaskAction::default() }),
            hooks: TaskHooks { before: vec!["before".into()], after: vec!["after".into()] },
            ..TaskDefinition::default()
        },
        "build:before".into() => TaskDefinition { action: Some(TaskAction { uses: Some("argv".into()), run: Some("false".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "build:after".into() => TaskDefinition { action: Some(TaskAction { uses: Some("argv".into()), run: Some("false".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();
    cancellation.cancel();
    let report = run_tasks_with_cancellation(
        &tasks,
        "build",
        "default",
        Path::new("."),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap();
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Cancelled)
    );
}

#[test]
fn requested_capabilities_are_default_denied_before_dry_run() {
    let project = tempfile::TempDir::new().unwrap();
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            id: Some("build-v1".into()),
            action: Some(TaskAction {
                uses: Some("portable".into()),
                run: Some("true".into()),
                capabilities: vec!["execute".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();

    let error = run_tasks_with_cancellation(
        &tasks,
        "build",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: true,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: Some(Path::new("policy.toml")),
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        super::TaskRunError::CapabilityDenied { ref subject, .. }
            if subject.ends_with("/task:build-v1")
    ));
    assert!(error.to_string().contains("policy.toml"));
}

#[test]
fn remote_tasks_require_an_explicit_execute_grant() {
    let project = tempfile::TempDir::new().unwrap();
    let tasks = indexmap! {
        "remote".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("portable".into()),
                run: Some("true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();
    let remote_tasks = HashSet::from(["remote".to_owned()]);

    let error = run_tasks_with_cancellation(
        &tasks,
        "remote",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: true,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: Some(&remote_tasks),
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        super::TaskRunError::CapabilityDenied { .. }
    ));
    assert!(error.to_string().contains("capability execute"));
}

#[test]
fn external_grant_authorizes_only_the_matching_stable_subject() {
    let project = tempfile::TempDir::new().unwrap();
    let subject = format!(
        "project:{}/task:build-v1",
        project.path().canonicalize().unwrap().display()
    );
    let grants = CapabilityGrants::from_toml(&format!(
        "[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"
    ))
    .unwrap();
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            id: Some("build-v1".into()),
            action: Some(TaskAction {
                uses: Some("portable".into()),
                run: Some("true".into()),
                capabilities: vec!["execute".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();

    let report = run_tasks_with_cancellation(
        &tasks,
        "build",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: true,
            cancellation: &cancellation,
            capability_grants: Some(&grants),
            capability_policy_source: Some(Path::new("policy.toml")),
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap();

    assert_eq!(report.tasks[0].outcome, TaskOutcome::Planned);
}

#[cfg(unix)]
#[test]
fn unknown_runner_uses_only_a_configured_local_file_with_literal_argv() {
    use std::os::unix::fs::PermissionsExt;

    let project = tempfile::TempDir::new().unwrap();
    let runners = project.path().join("runners");
    fs::create_dir(&runners).unwrap();
    let runner = runners.join("capture");
    fs::write(&runner, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RESULT\"\n").unwrap();
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
    let output = project.path().join("argv");
    let tasks = indexmap! {
        "capture".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("capture".into()),
                run: Some("$(not-a-command); literal value".into()),
                args: vec!["declared arg".into()],
                env: indexmap! { "RESULT".into() => output.display().to_string() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();

    let report = run_tasks_with_cancellation(
        &tasks,
        "capture",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &["passed through".into()],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories {
                local: &["runners".into()],
                global: &[],
            },
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap();

    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        "$(not-a-command); literal value\ndeclared arg\npassed through\n"
    );
}

#[test]
fn global_fallback_runner_requires_an_exact_external_execute_grant() {
    let project = tempfile::TempDir::new().unwrap();
    let global = tempfile::TempDir::new().unwrap();
    fs::write(global.path().join("runner"), "not executed during dry run").unwrap();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("runner".into()),
                run: Some("literal".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();
    let subject = format!(
        "global-task-dir:{}/runner:runner",
        global.path().canonicalize().unwrap().display()
    );
    let directories = vec![global.path().display().to_string()];
    let denied = run_tasks_with_cancellation(
        &tasks,
        "task",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: true,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: Some(Path::new("policy.toml")),
            remote_tasks: None,
            task_directories: TaskRunnerDirectories {
                local: &[],
                global: &directories,
            },
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap_err();
    assert!(matches!(
        denied,
        super::TaskRunError::CapabilityDenied { .. }
    ));
    let grants = CapabilityGrants::from_toml(&format!(
        "[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"
    ))
    .unwrap();

    let report = run_tasks_with_cancellation(
        &tasks,
        "task",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: true,
            cancellation: &cancellation,
            capability_grants: Some(&grants),
            capability_policy_source: Some(Path::new("policy.toml")),
            remote_tasks: None,
            task_directories: TaskRunnerDirectories {
                local: &[],
                global: &directories,
            },
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap();

    assert_eq!(report.tasks[0].outcome, TaskOutcome::Planned);
}

#[test]
fn fallback_rejects_ambient_paths_and_local_directory_escapes() {
    let project = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    assert!(
        super::resolve_fallback_runner(
            "runner",
            project.path(),
            TaskRunnerDirectories {
                local: &[],
                global: &[]
            },
        )
        .unwrap_err()
        .contains("unsupported local task runner")
    );
    assert!(
        super::resolve_fallback_runner(
            "runner",
            project.path(),
            TaskRunnerDirectories {
                local: &[outside.path().display().to_string()],
                global: &[]
            },
        )
        .unwrap_err()
        .contains("escapes the project root")
    );
    assert!(
        super::resolve_fallback_runner(
            "../runner",
            project.path(),
            TaskRunnerDirectories {
                local: &[],
                global: &[]
            },
        )
        .unwrap_err()
        .contains("bare file name")
    );
}

#[test]
fn handoff_documents_are_parsed_without_filesystem_effects() {
    let outputs = indexmap! {
        "PUBLIC".into() => neoenv_core::tasks::TaskOutput {
            description: None,
            visibility: neoenv_core::tasks::TaskOutputVisibility::Public,
        },
        "PRIVATE".into() => neoenv_core::tasks::TaskOutput {
            description: None,
            visibility: neoenv_core::tasks::TaskOutputVisibility::Private,
        },
    };
    let values = super::HandoffDocuments {
        environment: Some("MODE=test\nEMPTY=\n"),
        path: Some("bin\ntools\n"),
        outputs: Some("PUBLIC=visible\nPRIVATE=secret\n"),
    }
    .parse(&outputs)
    .unwrap();

    assert_eq!(
        values,
        super::HandoffValues {
            environment: vec![
                ("MODE".into(), "test".into()),
                ("EMPTY".into(), String::new())
            ],
            path: vec!["bin".into(), "tools".into()],
            outputs: vec![("PUBLIC".into(), "visible".into())],
        }
    );
}

#[test]
fn private_outputs_do_not_cross_the_task_handoff_boundary() {
    let directory = tempfile::TempDir::new().unwrap();
    let handoff = super::Handoff::new(directory.path());
    std::fs::write(&handoff.outputs, "PUBLIC=value\nPRIVATE=secret\n").unwrap();
    let outputs = indexmap! {
        "PUBLIC".into() => neoenv_core::tasks::TaskOutput { description: None, visibility: neoenv_core::tasks::TaskOutputVisibility::Public },
        "PRIVATE".into() => neoenv_core::tasks::TaskOutput { description: None, visibility: neoenv_core::tasks::TaskOutputVisibility::Private },
    };
    let values = handoff.read(&outputs).unwrap();
    assert_eq!(values.outputs, vec![("PUBLIC".into(), "value".into())]);
}

#[test]
fn render_task_uses_only_declared_inputs_and_replaces_the_destination() {
    let project = tempfile::TempDir::new().unwrap();
    fs::create_dir_all(project.path().join("templates")).unwrap();
    fs::create_dir_all(project.path().join("generated")).unwrap();
    fs::write(
        project.path().join("templates/app.conf.tmpl"),
        "name={{ .inputs.name }}\n",
    )
    .unwrap();
    fs::write(project.path().join("generated/app.conf"), "old\n").unwrap();
    let tasks = indexmap! {
        "render".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("render".into()),
                source: Some("templates/app.conf.tmpl".into()),
                destination: Some("generated/app.conf".into()),
                with: indexmap! { "name".into() => "neoenv".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let report = run_tasks(
        &tasks,
        "render",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        false,
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert_eq!(
        fs::read_to_string(project.path().join("generated/app.conf")).unwrap(),
        "name=neoenv\n"
    );
}

#[test]
fn render_task_rejects_host_state_and_project_escapes() {
    let project = tempfile::TempDir::new().unwrap();
    fs::create_dir(project.path().join("generated")).unwrap();
    fs::write(project.path().join("template"), "{{ .env.HOME }}").unwrap();
    let action = TaskAction {
        uses: Some("render".into()),
        source: Some("template".into()),
        destination: Some("generated/output".into()),
        ..TaskAction::default()
    };
    assert!(
        super::render_file(&action, project.path())
            .unwrap_err()
            .contains("missing template value: .env")
    );
    let escaped_source = TaskAction {
        source: Some("../template".into()),
        ..action.clone()
    };
    assert!(
        super::render_file(&escaped_source, project.path())
            .unwrap_err()
            .contains("without traversal")
    );
    let escaped_destination = TaskAction {
        destination: Some("../output".into()),
        ..action
    };
    assert!(
        super::render_file(&escaped_destination, project.path())
            .unwrap_err()
            .contains("without traversal")
    );
}

#[cfg(unix)]
#[test]
fn render_task_rejects_symlink_escapes() {
    use std::os::unix::fs::symlink;

    let project = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    fs::create_dir(project.path().join("generated")).unwrap();
    fs::write(outside.path().join("template"), "outside").unwrap();
    symlink(
        outside.path().join("template"),
        project.path().join("template"),
    )
    .unwrap();
    let action = TaskAction {
        uses: Some("render".into()),
        source: Some("template".into()),
        destination: Some("generated/output".into()),
        ..TaskAction::default()
    };
    assert!(
        super::render_file(&action, project.path())
            .unwrap_err()
            .contains("escapes the project root")
    );
    fs::remove_file(project.path().join("template")).unwrap();
    fs::write(project.path().join("template"), "inside").unwrap();
    symlink(outside.path(), project.path().join("linked")).unwrap();
    let escaped_destination = TaskAction {
        destination: Some("linked/output".into()),
        ..action
    };
    assert!(
        super::render_file(&escaped_destination, project.path())
            .unwrap_err()
            .contains("escapes the project root")
    );
}

/// A name followed by a separator must keep that separator, at every boundary the
/// unbraced form can end at.
///
/// **This test exists because the behaviour was wrong and nothing here noticed.**
/// `neotales-env` read an unbraced name with `Iterator::take_while`, which consumes
/// and discards the first character that fails its predicate. The predicate was
/// right -- a shell name stops at `/` -- but the terminator went into the iterator
/// instead of back into the output, so `$HOME/bin` expanded to `/home/devbin` and
/// `$PATH:/opt` to `/usr/bin/opt`. Neither failed loudly. A task declaring
/// `PATH: "$PATH:/opt"` got a `PATH` that had lost its colon and still looked like
/// a `PATH`, and the tool that could not be found said nothing about the colon.
///
/// The characters below are the ones a value can contain and a name cannot, plus a
/// two-byte character to say the delimiter is found on a character boundary rather
/// than a byte. A shell name is ASCII, so a multi-byte character is a terminator
/// too, and slicing mid-character would panic.
#[test]
fn a_name_followed_by_any_other_character_keeps_that_character() {
    let environment = BTreeMap::from([
        ("HOME".to_owned(), "/home/dev".to_owned()),
        ("PATH".to_owned(), "/usr/bin".to_owned()),
    ]);
    for (value, expected) in [
        ("$HOME/bin", "/home/dev/bin"),
        ("$PATH:/opt", "/usr/bin:/opt"),
        ("$HOME-dev", "/home/dev-dev"),
        ("$HOME.dev", "/home/dev.dev"),
        ("$HOME dev", "/home/dev dev"),
        ("$HOME=", "/home/dev="),
        ("$HOME\nnext", "/home/dev\nnext"),
        ("$HOME\u{e9}", "/home/dev\u{e9}"),
        // The braced form was right before the fix, by the accident that the
        // character `take_while` ate there was the `}` it wanted gone. Pinning it
        // means the fix cannot be reintroduced as a change to the braced form.
        ("${HOME}/bin", "/home/dev/bin"),
    ] {
        assert_eq!(
            super::process::interpolate_environment(value, &environment).unwrap(),
            expected,
            "interpolating {value:?}"
        );
    }
}

/// A `PATH` built by interpolation has to be a usable `PATH`.
///
/// **The separator test above proves a character survives; this proves the assembled
/// value is one a shell can parse.** Those are different claims and the first one
/// passed while the value was still wrong: `/usr/bin/opt` is a single entry, so the
/// directory `/opt` was never on the path, and the only symptom was a binary that
/// could not be found. A test that asserts characters is not a test that asserts
/// correctness.
#[test]
fn an_interpolated_path_is_a_path_shell_can_split() {
    let environment = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
    let value = super::process::interpolate_environment("$PATH:/opt/bin", &environment).unwrap();
    assert_eq!(
        value.split(':').collect::<Vec<_>>(),
        vec!["/usr/bin", "/bin", "/opt/bin"],
        "every entry must survive as its own entry"
    );
}

/// `len` and `index` count and address **bytes**, not characters.
///
/// A task's `run:` is a user-authored template, so `{{ len .env.MESSAGE }}` is
/// something a person can write, and a value they wrote is not necessarily ASCII.
/// Go's `len` on a string is its length in bytes and `index` yields a byte, and
/// `neotales-gotmpl` measured both against Go 1.27.1 rather than reading it.
///
/// **This test is here because the count was wrong and the result still looked
/// like a result.** `len` returned a character count, so `{{ len "café" }}` was
/// `4` where every other Go template in existence says `5`. Nothing failed — a
/// wrong number is the right shape of a number — and the fix was three commits that
/// had to be reconciled against the .NET reference. A value with a non-ASCII
/// character in it is exactly the input a byte-oriented tool gets wrong, and it is
/// the input nobody writes a unit test for until it has already shipped.
#[test]
fn len_and_index_count_bytes_rather_than_characters() {
    let environment = BTreeMap::from([("MESSAGE".to_owned(), "café".to_owned())]);
    for (template, expected) in [
        ("{{ len .env.MESSAGE }}", "5"),
        ("{{ len \"café\" }}", "5"),
        ("{{ len \"a😀b\" }}", "6"),
        ("{{ len \"\" }}", "0"),
    ] {
        let rendered =
            super::process::render_portable(template, &environment).expect("the template parses");
        assert_eq!(rendered, expected, "rendering {template:?}");
    }
}

/// `index` on a string yields the **byte** at a position, and a position in the
/// middle of a multi-byte character is not an error.
///
/// That last part is a deliberate contract rather than an oversight, and this test
/// exists to say so, because it reads like a bug. Go returns the continuation byte
/// and the .NET reference indexes the encoded array, and `neotales-gotmpl` matches
/// both — so `{{ index "a😀b" 1 }}` is a number, not an error. The alternative
/// would be a template engine inventing a stricter rule than either target has,
/// which trades a documented divergence for an undocumented one.
///
/// The bytes are asserted rather than the characters, because that is the whole
/// claim: `😀` is three bytes, so the string is `a`(97) `😀`(240,159,144) `b`(98)
/// and the sequence of values says which one the engine returned.
#[test]
fn index_on_a_string_returns_the_byte_at_a_position() {
    let environment = BTreeMap::from([("MESSAGE".to_owned(), "a😀b".to_owned())]);
    let rendered = super::process::render_portable(
        "{{ index .env.MESSAGE 0 }}|{{ index .env.MESSAGE 1 }}|{{ index .env.MESSAGE 2 }}|\
         {{ index .env.MESSAGE 3 }}|{{ index .env.MESSAGE 4 }}",
        &environment,
    )
    .expect("every offset below the byte length is addressable");
    assert_eq!(
        rendered, "97|240|159|152|128",
        "a three-byte character is three addressable positions"
    );
}

/// A position outside the bytes, or one that is not a whole number, is an error.
///
/// **The second half is the half that bites.** A fractional or negative index used
/// to be accepted and quietly truncated, so `{{ index .l 1.5 }}` returned the
/// element at 1 and reported nothing. A task whose command line depends on a
/// computed index would then run against the wrong element with a template that
/// looked fine. Go and the .NET reference both refuse all three cases — negative,
/// fractional, and non-numeric — and a wrong element is worse than a refused one.
#[test]
fn an_index_that_is_not_a_whole_number_in_range_is_refused() {
    let environment = BTreeMap::from([("MESSAGE".to_owned(), "abc".to_owned())]);
    for template in [
        "{{ index .env.MESSAGE 1.5 }}",
        "{{ index .env.MESSAGE -1 }}",
        "{{ index .env.MESSAGE 99 }}",
        "{{ index .env.MESSAGE \"a\" }}",
    ] {
        assert!(
            super::process::render_portable(template, &environment).is_err(),
            "{template:?} must be refused rather than resolved to something"
        );
    }
}

#[test]
fn tmpl_cancellation_before_commit_writes_nothing() {
    let project = tempfile::TempDir::new().unwrap();
    fs::write(project.path().join("input.tmpl"), "value\n").unwrap();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("tmpl".into()),
                files: vec!["input.tmpl".into()],
                // No Go template stage, so the only cancellation point left is
                // the one immediately before the output commit.
                with: indexmap! { "disable-gotmpl".into() => "true".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();
    cancellation.cancel();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Cancelled);
    assert!(!project.path().join("input").exists());
}

#[cfg(unix)]
fn write_fake_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::write(path, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RESULT\"\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn write_fake_go(fake: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let path = fake.join("go");
    fs::write(
        &path,
        "#!/bin/sh\n         if [ \"$1\" = \"build\" ]; then\n           out=\"$3\"\n           printf '%s\\n' \"$@\" > \"$BUILD_RESULT\"\n           printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$@\" > \"$RUN_RESULT\"\\n' > \"$out\"\n           /bin/chmod +x \"$out\"\n           exit 0\n         fi\n         exit 42\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn run_named_task(
    tasks: &IndexMap<String, TaskDefinition>,
    project_root: &Path,
    values: &IndexMap<String, String>,
    passthrough: &[String],
    cancellation: &TaskCancellation,
    task_directories: TaskRunnerDirectories<'_>,
    managed_runtimes: &[ManagedRuntime],
) -> Result<TaskRunReport, TaskRunError> {
    run_named_task_with_grants(
        tasks,
        project_root,
        values,
        passthrough,
        cancellation,
        task_directories,
        managed_runtimes,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_named_task_with_grants(
    tasks: &IndexMap<String, TaskDefinition>,
    project_root: &Path,
    values: &IndexMap<String, String>,
    passthrough: &[String],
    cancellation: &TaskCancellation,
    task_directories: TaskRunnerDirectories<'_>,
    managed_runtimes: &[ManagedRuntime],
    grants: Option<&CapabilityGrants>,
) -> Result<TaskRunReport, TaskRunError> {
    run_tasks_with_cancellation(
        tasks,
        "task",
        "default",
        project_root,
        TaskEnvironment {
            values,
            path_operations: &[],
            overrides: None,
        },
        passthrough,
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation,
            capability_grants: grants,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories,
            managed_runtimes,
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
}

/// A managed uv install with a well-formed receipt and a usable binary. The
/// receipt is self-attesting, so tests that execute it must also grant execute.
#[cfg(unix)]
fn managed_uv_at(root: &Path, version: &str, digest: &str) -> ManagedRuntime {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let binary = bin_dir.join("uv");
    write_fake_executable(&binary);
    let receipt = root.join("receipt");
    fs::write(&receipt, digest).unwrap();
    ManagedRuntime {
        id: "uv".into(),
        version: version.into(),
        root: root.to_path_buf(),
        bin_dir,
        binary: binary.clone(),
        receipt,
        digest: digest.into(),
        root_identity: InstallIdentity::of(root),
        binary_identity: InstallIdentity::of(&binary),
    }
}

#[cfg(unix)]
fn managed_uv(version: &str, digest: &str) -> (tempfile::TempDir, ManagedRuntime) {
    let root = tempfile::TempDir::new().unwrap();
    let version_root = root.path().join("uv").join(version);
    fs::create_dir_all(&version_root).unwrap();
    let runtime = managed_uv_at(&version_root, version, digest);
    (root, runtime)
}

fn execute_grant(project_root: &Path, task: &str) -> CapabilityGrants {
    let root = project_root.canonicalize().unwrap();
    let subject = format!("project:{}/task:{task}", root.display());
    CapabilityGrants::from_toml(&format!(
        "[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"
    ))
    .unwrap()
}

/// Asserts one named runner's inline argv through a fake interpreter that
/// records the whole command rather than a string the runner printed about
/// itself.
#[cfg(unix)]
fn assert_inline_shape(uses: &str, executable: &str, expected: &[&str]) {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    let output = project.path().join("argv");
    write_fake_executable(&fake.path().join(executable));
    let values = IndexMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        ("RESULT".to_owned(), output.display().to_string()),
    ]);
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some(uses.into()),
                run: Some("inline-script".into()),
                args: vec!["declared".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &["--passed".into()],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded, "{uses}");
    let recorded = fs::read_to_string(&output).unwrap();
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        expected,
        "{uses} argv"
    );
}

#[cfg(unix)]
#[test]
fn shell_runners_have_explicit_inline_argument_shapes() {
    assert_inline_shape(
        "bash",
        "bash",
        &[
            "--noprofile",
            "--norc",
            "-eo",
            "pipefail",
            "-c",
            "inline-script",
            "neoenv-task",
            "declared",
            "--passed",
        ],
    );
    assert_inline_shape(
        "sh",
        "sh",
        &[
            "-e",
            "-c",
            "inline-script",
            "neoenv-task",
            "declared",
            "--passed",
        ],
    );
    assert_inline_shape(
        "fish",
        "fish",
        &["-c", "inline-script", "declared", "--passed"],
    );
}

#[cfg(unix)]
#[test]
fn language_runners_have_explicit_inline_argument_shapes() {
    assert_inline_shape(
        "pwsh",
        "pwsh",
        &[
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "inline-script",
            "declared",
            "--passed",
        ],
    );
    assert_inline_shape(
        "powershell",
        "powershell",
        &[
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "inline-script",
            "declared",
            "--passed",
        ],
    );
    assert_inline_shape(
        "node",
        "node",
        &["-e", "inline-script", "--", "declared", "--passed"],
    );
    assert_inline_shape(
        "bun",
        "bun",
        &["-e", "inline-script", "--", "declared", "--passed"],
    );
    assert_inline_shape(
        "deno",
        "deno",
        &["eval", "inline-script", "declared", "--passed"],
    );
    assert_inline_shape(
        "python",
        "python3",
        &["-c", "inline-script", "declared", "--passed"],
    );
    assert_inline_shape("nu", "nu", &["-c", "inline-script", "declared", "--passed"]);
}

/// File mode is `source:` and the engine appends declared and CLI arguments
/// after the path. Nothing guesses file mode from a one-line `run:`.
#[cfg(unix)]
#[test]
fn named_script_runner_file_mode_passes_the_resolved_source_path() {
    for (uses, executable, prefix) in [
        ("bash", "bash", vec![]),
        ("sh", "sh", vec!["-e"]),
        ("node", "node", vec![]),
        ("python", "python3", vec![]),
        ("deno", "deno", vec!["run", "-A"]),
    ] {
        let project = tempfile::TempDir::new().unwrap();
        let fake = tempfile::TempDir::new().unwrap();
        let output = project.path().join("argv");
        write_fake_executable(&fake.path().join(executable));
        let script = project.path().join("script.src");
        fs::write(&script, "ignored by the fake interpreter").unwrap();
        let expected_script = script.canonicalize().unwrap();
        let values = IndexMap::from([
            ("PATH".to_owned(), fake.path().display().to_string()),
            ("RESULT".to_owned(), output.display().to_string()),
        ]);
        let tasks = indexmap! {
            "task".into() => TaskDefinition {
                action: Some(TaskAction {
                    uses: Some((*uses).into()),
                    source: Some("script.src".into()),
                    args: vec!["declared".into()],
                    ..TaskAction::default()
                }),
                ..TaskDefinition::default()
            },
        };
        let cancellation = TaskCancellation::new();
        let report = run_named_task(
            &tasks,
            project.path(),
            &values,
            &["--passed".into()],
            &cancellation,
            TaskRunnerDirectories::default(),
            &[],
        )
        .unwrap();
        assert_eq!(
            report.tasks[0].outcome,
            TaskOutcome::Succeeded,
            "{uses}: {:?}",
            report.tasks[0].message
        );
        let recorded = fs::read_to_string(&output).unwrap();
        let expected: Vec<String> = prefix
            .iter()
            .map(|value| (*value).to_owned())
            .chain([expected_script.display().to_string()])
            .chain(["declared".to_owned(), "--passed".to_owned()])
            .collect();
        assert_eq!(
            recorded.lines().collect::<Vec<_>>(),
            expected.iter().map(String::as_str).collect::<Vec<_>>(),
            "{uses} file argv"
        );
    }
}

/// File mode goes through the same containment check as `render`: a script
/// outside the declaring root is refused, not executed.
#[cfg(unix)]
#[test]
fn named_runner_source_must_stay_inside_the_project() {
    let project = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    fs::write(outside.path().join("outside.sh"), "echo outside\n").unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_executable(&fake.path().join("bash"));
    let values = IndexMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        (
            "RESULT".to_owned(),
            project.path().join("argv").display().to_string(),
        ),
    ]);
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("bash".into()),
                source: Some("../outside.sh".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert!(
        report.tasks[0]
            .message
            .as_deref()
            .is_some_and(|message| message.contains("traversal")),
        "{:?}",
        report.tasks[0].message
    );
}

#[cfg(unix)]
#[test]
fn go_runner_builds_then_runs_and_keeps_go_suffix_arguments() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_go(fake.path());
    let source = project.path().join("main.go");
    fs::write(&source, "package main\n").unwrap();
    let build_result = project.path().join("build-argv");
    let run_result = project.path().join("run-argv");
    let values = IndexMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        (
            "BUILD_RESULT".to_owned(),
            build_result.display().to_string(),
        ),
        ("RUN_RESULT".to_owned(), run_result.display().to_string()),
    ]);
    let cancellation = TaskCancellation::new();

    let file_task = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                source: Some("main.go".into()),
                args: vec!["first.go".into(), "--declared".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let report = run_named_task(
        &file_task,
        project.path(),
        &values,
        &["--passed".into()],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    let build: Vec<String> = fs::read_to_string(&build_result)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(build[0], "build");
    assert_eq!(build[1], "-o");
    assert_eq!(
        build[3],
        source.canonicalize().unwrap().display().to_string()
    );
    assert!(
        !Path::new(&build[2]).exists(),
        "the built binary must be removed"
    );
    assert_eq!(
        fs::read_to_string(&run_result)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        ["first.go", "--declared", "--passed"],
        "go build plus direct execution must not steal .go arguments"
    );
}

#[cfg(unix)]
#[test]
fn go_runner_stages_inline_source_and_keeps_go_suffix_arguments() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_go(fake.path());
    let cancellation = TaskCancellation::new();
    let inline_task = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                run: Some("package main\nfunc main() {}\n".into()),
                args: vec!["first.go".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let mut sources = Vec::new();
    for index in 0..2 {
        let build_result = project.path().join(format!("inline-build-{index}"));
        let run_result = project.path().join(format!("inline-run-{index}"));
        let values = IndexMap::from([
            ("PATH".to_owned(), fake.path().display().to_string()),
            (
                "BUILD_RESULT".to_owned(),
                build_result.display().to_string(),
            ),
            ("RUN_RESULT".to_owned(), run_result.display().to_string()),
        ]);
        let report = run_named_task(
            &inline_task,
            project.path(),
            &values,
            &[],
            &cancellation,
            TaskRunnerDirectories::default(),
            &[],
        )
        .unwrap();
        assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
        let build: Vec<String> = fs::read_to_string(build_result)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(build[0], "build");
        assert_eq!(
            Path::new(&build[3]).extension(),
            Some(std::ffi::OsStr::new("go")),
            "{build:?}"
        );
        assert!(
            !Path::new(&build[3]).exists(),
            "the staged source must be removed"
        );
        assert!(
            !Path::new(&build[2]).exists(),
            "the built binary must be removed"
        );
        assert_eq!(
            fs::read_to_string(run_result)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            ["first.go"],
            "an argument ending in .go must reach the program unchanged"
        );
        sources.push(build[3].clone());
    }
    assert_ne!(
        sources[0], sources[1],
        "each inline source gets a fresh name"
    );
}

#[cfg(unix)]
#[test]
fn dotnet_runner_selects_file_project_and_binary_modes() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    let output = project.path().join("argv");
    write_fake_executable(&fake.path().join("dotnet"));
    let cases = [
        ("script.cs", vec!["run", "--file"]),
        ("script.csx", vec!["run", "--file"]),
        ("tool", vec!["run", "--file"]),
        ("app.csproj", vec!["run", "--project"]),
        ("app.fsproj", vec!["run", "--project"]),
        ("app.vbproj", vec!["run", "--project"]),
        ("app.dll", vec![]),
        ("app.exe", vec![]),
    ];
    let cancellation = TaskCancellation::new();
    for (name, prefix) in cases {
        let path = project.path().join(name);
        fs::write(&path, "not a real program").unwrap();
        let values = IndexMap::from([
            ("PATH".to_owned(), fake.path().display().to_string()),
            ("RESULT".to_owned(), output.display().to_string()),
        ]);
        let tasks = indexmap! {
            "task".into() => TaskDefinition {
                action: Some(TaskAction {
                    uses: Some("dotnet".into()),
                    source: Some(name.into()),
                    args: vec!["--declared".into()],
                    ..TaskAction::default()
                }),
                ..TaskDefinition::default()
            },
        };
        let report = run_named_task(
            &tasks,
            project.path(),
            &values,
            &["--passed".into()],
            &cancellation,
            TaskRunnerDirectories::default(),
            &[],
        )
        .unwrap();
        assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded, "{name}");
        let recorded = fs::read_to_string(&output).unwrap();
        let arguments: Vec<&str> = recorded.lines().collect();
        let canonical = path.canonicalize().unwrap().display().to_string();
        let mut expected = prefix;
        expected.push(&canonical);
        if !matches!(name, "app.dll" | "app.exe") {
            expected.push("--");
        }
        expected.extend(["--declared", "--passed"]);
        assert_eq!(arguments, expected, "{name}");
    }
}

#[cfg(unix)]
#[test]
fn dotnet_runner_handles_passthrough_and_inline_source() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    let output = project.path().join("argv");
    write_fake_executable(&fake.path().join("dotnet"));
    fs::write(project.path().join("script.cs"), "not a real program").unwrap();
    let cancellation = TaskCancellation::new();
    let values = IndexMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        ("RESULT".to_owned(), output.display().to_string()),
    ]);
    let passthrough_only = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("dotnet".into()),
                source: Some("script.cs".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let report = run_named_task(
        &passthrough_only,
        project.path(),
        &values,
        &["--passed".into()],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    let recorded = fs::read_to_string(&output).unwrap();
    let arguments: Vec<&str> = recorded.lines().collect();
    assert_eq!(
        arguments,
        [
            "run",
            "--file",
            &project
                .path()
                .join("script.cs")
                .canonicalize()
                .unwrap()
                .display()
                .to_string(),
            "--",
            "--passed",
        ]
    );

    let inline = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("dotnet".into()),
                run: Some("Console.WriteLine(\"hi\");".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let report = run_named_task(
        &inline,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    let recorded = fs::read_to_string(&output).unwrap();
    let arguments: Vec<&str> = recorded.lines().collect();
    assert_eq!(&arguments[..2], ["run", "--file"]);
    assert_eq!(
        Path::new(arguments[2]).extension(),
        Some(std::ffi::OsStr::new("cs")),
        "{arguments:?}"
    );
    assert!(
        !Path::new(arguments[2]).exists(),
        "the staged file must be removed"
    );
}

#[cfg(unix)]
#[test]
fn go_runner_does_not_start_the_binary_when_cancelled_after_build() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_go(fake.path());
    let source = project.path().join("main.go");
    fs::write(&source, "package main\n").unwrap();
    let run_result = project.path().join("run-marker");
    let environment = BTreeMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        (
            "BUILD_RESULT".to_owned(),
            project.path().join("build-argv").display().to_string(),
        ),
        ("RUN_RESULT".to_owned(), run_result.display().to_string()),
    ]);
    let cancellation = TaskCancellation::new();
    let options = TaskRunOptions {
        ssh_output_to_stderr: false,
        ssh_secret_values: &[],
        inventories: None,
        dry_run: false,
        cancellation: &cancellation,
        capability_grants: None,
        capability_policy_source: None,
        remote_tasks: None,
        task_directories: TaskRunnerDirectories::default(),
        managed_runtimes: &[],
        input_values: None,
        vaults: None,
        owned_backend: None,
    };
    let action = TaskAction {
        uses: Some("go".into()),
        source: Some("main.go".into()),
        ..TaskAction::default()
    };
    let error = super::runners::execute_go_with(
        &source,
        &action,
        project.path(),
        &environment,
        &[],
        &options,
        None,
        &|| cancellation.cancel(),
    )
    .unwrap_err();
    assert_eq!(error, "task cancelled");
    assert!(!run_result.exists(), "the built binary must not start");
}

#[cfg(unix)]
#[test]
fn go_runner_does_not_start_the_binary_when_the_deadline_is_exhausted_after_build() {
    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_go(fake.path());
    let source = project.path().join("main.go");
    fs::write(&source, "package main\n").unwrap();
    let run_result = project.path().join("run-marker");
    let environment = BTreeMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        (
            "BUILD_RESULT".to_owned(),
            project.path().join("build-argv").display().to_string(),
        ),
        ("RUN_RESULT".to_owned(), run_result.display().to_string()),
    ]);
    let cancellation = TaskCancellation::new();
    let options = TaskRunOptions {
        ssh_output_to_stderr: false,
        ssh_secret_values: &[],
        inventories: None,
        dry_run: false,
        cancellation: &cancellation,
        capability_grants: None,
        capability_policy_source: None,
        remote_tasks: None,
        task_directories: TaskRunnerDirectories::default(),
        managed_runtimes: &[],
        input_values: None,
        vaults: None,
        owned_backend: None,
    };
    let action = TaskAction {
        uses: Some("go".into()),
        source: Some("main.go".into()),
        ..TaskAction::default()
    };
    let callback_ran = std::cell::Cell::new(false);
    // The build budget is deliberately generous so the fake build cannot consume
    // it; the callback then burns past the remaining deadline. If the build
    // itself timed out, the callback assertion below would fail.
    let error = super::runners::execute_go_with(
        &source,
        &action,
        project.path(),
        &environment,
        &[],
        &options,
        Some(std::time::Duration::from_secs(1)),
        &|| {
            callback_ran.set(true);
            std::thread::sleep(std::time::Duration::from_millis(1_100));
        },
    )
    .unwrap_err();
    assert_eq!(error, "task timed out");
    assert!(
        callback_ran.get(),
        "the post-build callback must have run before the deadline gate"
    );
    assert!(!run_result.exists(), "the built binary must not start");
}

#[cfg(unix)]
#[test]
fn go_runner_refuses_source_escape_and_a_missing_interpreter() {
    let project = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    fs::write(outside.path().join("outside.go"), "package main\n").unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    write_fake_executable(&fake.path().join("go"));
    let cancellation = TaskCancellation::new();
    let escaping = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                source: Some("../outside.go".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::from([
        ("PATH".to_owned(), fake.path().display().to_string()),
        (
            "RESULT".to_owned(),
            project.path().join("argv").display().to_string(),
        ),
    ]);
    let report = run_named_task(
        &escaping,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);

    let missing = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                run: Some("package main\n".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let empty_path = IndexMap::from([("PATH".to_owned(), String::new())]);
    let report = run_named_task(
        &missing,
        project.path(),
        &empty_path,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert!(
        report.tasks[0]
            .message
            .as_deref()
            .is_some_and(|message| message.contains("not found on PATH: go")),
        "{:?}",
        report.tasks[0].message
    );
}

#[cfg(unix)]
#[test]
fn go_runner_observes_cancellation_and_timeout() {
    use std::os::unix::fs::PermissionsExt as _;

    let project = tempfile::TempDir::new().unwrap();
    fs::write(project.path().join("main.go"), "package main\n").unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    let go = fake.path().join("go");
    fs::write(&go, "#!/bin/sh\n/bin/sleep 5\n").unwrap();
    fs::set_permissions(&go, fs::Permissions::from_mode(0o755)).unwrap();
    let values = IndexMap::from([("PATH".to_owned(), fake.path().display().to_string())]);
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                source: Some("main.go".into()),
                with: indexmap! { "timeout".into() => "50ms".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::TimedOut);

    let cancellation = TaskCancellation::new();
    cancellation.cancel();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("go".into()),
                source: Some("main.go".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Cancelled);
}

/// A configured fallback named `bash` is shadowed by the built-in runner. That
/// is the compatibility boundary documented in `docs/task-runners.md`; silently
/// preferring the file would give an existing project a different interpreter.
#[cfg(unix)]
#[test]
fn a_builtin_runner_name_shadows_a_same_named_fallback() {
    let project = tempfile::TempDir::new().unwrap();
    let runners = project.path().join("runners");
    fs::create_dir(&runners).unwrap();
    let marker = project.path().join("fallback-ran");
    let fallback = runners.join("bash");
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(
            &fallback,
            format!("#!/bin/sh\ntouch {}\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&fallback, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let values = IndexMap::from([(
        "PATH".to_owned(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
    )]);
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("bash".into()),
                run: Some("true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories {
            local: &["runners".into()],
            global: &[],
        },
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert!(
        !marker.exists(),
        "a configured fallback named bash must not replace the built-in runner"
    );
}

/// `uv@<version>` selects the managed runtime by exact version. A `uv` on PATH
/// is not a candidate, even when it would run successfully.
#[cfg(unix)]
#[test]
fn uv_runner_uses_the_exact_managed_version_and_never_path_uv() {
    let project = tempfile::TempDir::new().unwrap();
    let path_uv = tempfile::TempDir::new().unwrap();
    let output = project.path().join("argv");
    let path_marker = project.path().join("path-uv-ran");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let script = path_uv.path().join("uv");
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch {}\n", path_marker.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let values = IndexMap::from([
        ("PATH".to_owned(), path_uv.path().display().to_string()),
        ("RESULT".to_owned(), output.display().to_string()),
    ]);
    let digest = "a".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    let runtimes = vec![managed];
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                args: vec!["declared".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let grants = execute_grant(project.path(), "task");
    let report = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &["--passed".into()],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert!(
        !path_marker.exists(),
        "PATH uv must never be used for a versioned request"
    );
    assert_eq!(
        fs::read_to_string(&output)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [
            "run",
            "--no-project",
            "--no-sync",
            "--offline",
            "--no-python-downloads",
            "python",
            "-c",
            "inline-script",
            "declared",
            "--passed",
        ]
    );
}

/// A well-formed receipt is self-attesting, not authoritative. A forged
/// receipt with a plausible digest is not trusted merely because it is
/// well-formed: executing it needs an execute grant even when the task declares
/// no capability.
#[cfg(unix)]
#[test]
fn uv_runner_does_not_trust_a_forged_receipt_without_an_execute_grant() {
    let project = tempfile::TempDir::new().unwrap();
    let digest = "c".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let error = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
    )
    .unwrap_err();
    assert!(
        matches!(error, TaskRunError::CapabilityDenied { .. }),
        "{error:?}"
    );
}

/// A path is not an identity: a root directory replaced at the same path after
/// enumeration must be refused even when the replacement has the same layout,
/// receipt text and executable contents. This is the root-replacement case.
#[cfg(unix)]
#[test]
fn uv_runner_refuses_a_root_replaced_after_enumeration() {
    let project = tempfile::TempDir::new().unwrap();
    let parent = tempfile::TempDir::new().unwrap();
    let digest = "1".repeat(64);
    let root = parent.path().join("uv").join("0.8.0");
    fs::create_dir_all(&root).unwrap();
    let managed = managed_uv_at(&root, "0.8.0", &digest);
    let old = parent.path().join("uv").join("0.8.0-old");
    fs::rename(&root, &old).unwrap();
    fs::create_dir_all(&root).unwrap();
    let _replacement = managed_uv_at(&root, "0.8.0", &digest);

    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
    assert!(
        old.exists(),
        "the original root must be held through the assertion so its inode cannot be reused"
    );
    assert!(
        root.exists(),
        "the replacement root must still be the one checked"
    );
}

/// The original executable is renamed aside (and held) before a replacement is
/// created, so an inode cannot be reused by the allocator and make the identity
/// check pass by accident. The replacement must still be refused.
#[cfg(unix)]
#[test]
fn uv_runner_refuses_a_binary_replaced_after_enumeration() {
    let project = tempfile::TempDir::new().unwrap();
    let digest = "2".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    let original = managed.bin_dir.join("uv-original");
    fs::rename(&managed.binary, &original).unwrap();
    write_fake_executable(&managed.binary);
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
    assert!(
        original.exists(),
        "the original executable must be held through the assertion"
    );
}

/// A symlink is refused even when its target is inside the install root. This is
/// the Linux equivalent of the Windows-gated test below and proves the check is
/// about the file object, not path containment.
#[cfg(unix)]
#[test]
fn uv_runner_refuses_an_internal_binary_symlink() {
    use std::os::unix::fs::symlink;

    let project = tempfile::TempDir::new().unwrap();
    let digest = "3".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    let target = managed.bin_dir.join("uv-real");
    fs::rename(&managed.binary, &target).unwrap();
    symlink(&target, &managed.binary).unwrap();
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
    assert!(target.exists(), "the internal symlink target must be held");
}

/// Windows-gated internal-root symlink test. Creating a symlink on Windows may
/// require Developer Mode or an elevated token; if the OS refuses the link, the
/// test reports that visibly rather than passing silently. It has not been run
/// natively here.
#[cfg(windows)]
#[test]
fn uv_runner_refuses_an_internal_binary_symlink_on_windows() {
    let project = tempfile::TempDir::new().unwrap();
    let parent = tempfile::TempDir::new().unwrap();
    let root = parent.path().join("uv").join("0.8.0");
    fs::create_dir_all(&root).unwrap();
    let target = root.join("uv-real.exe");
    fs::write(&target, "not executed").unwrap();
    let binary = root.join("uv.exe");
    if let Err(error) = std::os::windows::fs::symlink_file(&target, &binary) {
        eprintln!(
            "SKIPPED: could not create an internal Windows symlink ({error}); \
             native symlink behaviour is unverified"
        );
        return;
    }
    let digest = "4".repeat(64);
    let receipt = root.join("receipt");
    fs::write(&receipt, &digest).unwrap();
    let managed = ManagedRuntime {
        id: "uv".into(),
        version: "0.8.0".into(),
        root: root.clone(),
        bin_dir: root.clone(),
        binary: binary.clone(),
        receipt,
        digest,
        root_identity: InstallIdentity::of(&root),
        binary_identity: InstallIdentity::of(&binary),
    };
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
    assert!(target.exists(), "the internal symlink target must be held");
}

/// The receipt is re-checked at use. A file replaced after enumeration no
/// longer matches the digest the list carries and fails closed before spawn.
#[cfg(unix)]
#[test]
fn uv_runner_refuses_a_receipt_changed_after_enumeration() {
    let project = tempfile::TempDir::new().unwrap();
    let digest = "d".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    fs::write(&managed.receipt, "e".repeat(64)).unwrap();
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
}

/// A receipt with no executable is incomplete, even if the digest looks right.
#[cfg(unix)]
#[test]
fn uv_runner_refuses_an_incomplete_managed_install() {
    let project = tempfile::TempDir::new().unwrap();
    let digest = "f".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    fs::remove_file(managed.bin_dir.join("uv")).unwrap();
    let runtimes = vec![managed];
    let values = IndexMap::new();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let grants = execute_grant(project.path(), "task");
    let cancellation = TaskCancellation::new();
    let error = run_named_task_with_grants(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
        Some(&grants),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed installation verification"),
        "{error}"
    );
}

/// A declared capability is still enforced for a managed versioned runner. The
/// exact version being present does not grant what the task itself asked for.
#[cfg(unix)]
#[test]
fn uv_runner_still_obeys_task_capability_requests() {
    let project = tempfile::TempDir::new().unwrap();
    let digest = "a".repeat(64);
    let (_managed_root, managed) = managed_uv("0.8.0", &digest);
    let values = IndexMap::new();
    let runtimes = vec![managed];
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("inline-script".into()),
                capabilities: vec!["execute".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    let error = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &runtimes,
    )
    .unwrap_err();
    assert!(
        matches!(error, TaskRunError::CapabilityDenied { .. }),
        "{error:?}"
    );
}

/// A missing exact version reports the versions that are installed and refuses.
/// An `execute` grant for the caller does not make it fall back to PATH.
#[cfg(unix)]
#[test]
fn uv_runner_missing_exact_version_does_not_fall_back_even_with_a_grant() {
    let project = tempfile::TempDir::new().unwrap();
    let path_uv = tempfile::TempDir::new().unwrap();
    let path_marker = project.path().join("path-uv-ran");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let script = path_uv.path().join("uv");
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch {}\n", path_marker.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let values = IndexMap::from([("PATH".to_owned(), path_uv.path().display().to_string())]);
    let digest = "b".repeat(64);
    let (_managed_root, installed) = managed_uv("0.7.0", &digest);
    let runtimes = vec![installed];
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv@0.8.0".into()),
                run: Some("true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let root = project.path().canonicalize().unwrap();
    let subject = format!("project:{}/task:task", root.display());
    let grants = CapabilityGrants::from_toml(&format!(
        "[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"
    ))
    .unwrap();
    let cancellation = TaskCancellation::new();
    let error = run_tasks_with_cancellation(
        &tasks,
        "task",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: Some(&grants),
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &runtimes,
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap_err();
    let TaskRunError::Planning(message) = error else {
        panic!("missing managed version must be a planning error: {error:?}");
    };
    assert!(message.contains("uv@0.8.0"), "{message}");
    assert!(message.contains("0.7.0"), "{message}");
    assert!(!path_marker.exists(), "PATH uv must not run");
}

#[test]
fn uv_runner_without_a_version_is_refused() {
    let project = tempfile::TempDir::new().unwrap();
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("uv".into()),
                run: Some("true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let values = IndexMap::new();
    let cancellation = TaskCancellation::new();
    let error = run_tasks_with_cancellation(
        &tasks,
        "task",
        "default",
        project.path(),
        TaskEnvironment {
            values: &values,
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            managed_runtimes: &[],
            input_values: None,
            vaults: None,
            owned_backend: None,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("exact version"), "{error}");
}

/// Cancellation reaches named runners through the same process executor as
/// every other local action.
#[cfg(unix)]
#[test]
fn named_runner_observes_cooperative_cancellation() {
    use std::os::unix::fs::PermissionsExt as _;

    let project = tempfile::TempDir::new().unwrap();
    let fake = tempfile::TempDir::new().unwrap();
    let script = fake.path().join("bash");
    fs::write(&script, "#!/bin/sh\n/bin/sleep 5\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let values = IndexMap::from([("PATH".to_owned(), fake.path().display().to_string())]);
    let tasks = indexmap! {
        "task".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("bash".into()),
                run: Some("true".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let cancellation = TaskCancellation::new();
    cancellation.cancel();
    let report = run_named_task(
        &tasks,
        project.path(),
        &values,
        &[],
        &cancellation,
        TaskRunnerDirectories::default(),
        &[],
    )
    .unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Cancelled);
}
