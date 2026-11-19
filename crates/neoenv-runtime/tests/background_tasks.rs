//! Public parser-to-runner tests. Each run owns its directory and cancellation;
//! synchronization uses files, not shared ports or timing-only overlap claims.
#![cfg(unix)]

use std::{
    fmt::Write as _,
    fs,
    path::Path,
    time::{Duration, Instant},
};

use indexmap::IndexMap;
use neoenv_core::tasks::{
    CompositeStep, TaskAction, TaskCapabilityRequest, TaskDefinition, TaskEdgeOrigin, TaskOutcome,
    TaskPackageIdentity, TaskSequence, TaskSequenceKind, resolve_inheritance,
};
use neoenv_policy::CapabilityGrants;
use neoenv_runtime::tasks::{
    CooperativeOwnedBackend, TaskCancellation, TaskEnvironment, TaskRunError, TaskRunOptions,
    TaskRunReport, TaskRunnerDirectories, run_tasks_with_cancellation,
};

#[path = "../../nenv/src/task_supervisor.rs"]
mod task_supervisor;

// This executable is both the integration-test host and the owned supervisor.
// It never performs an indiscriminate child wait, satisfying the opt-in policy.
// Tests run serially so each panic is attributed before the next scenario.
#[allow(clippy::too_many_lines)] // The explicit registry keeps every scenario discoverable.
pub(super) fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(task_supervisor::MODE) => std::process::exit(task_supervisor::run(false)),
        #[cfg(target_os = "linux")]
        Some(task_supervisor::MANAGED_MODE) => std::process::exit(task_supervisor::run(true)),
        Some(task_supervisor::ANCHOR_MODE) => std::process::exit(task_supervisor::run_anchor()),
        _ => {}
    }
    let tests: &[(&str, fn())] = &[
        (
            "unavailable_backend_refuses_execution_but_dry_run_only_plans",
            unavailable_backend_refuses_execution_but_dry_run_only_plans,
        ),
        (
            "composite_steps_run_in_order_and_stop_after_failure",
            composite_steps_run_in_order_and_stop_after_failure,
        ),
        (
            "composite_only_dependencies_remain_sequential",
            composite_only_dependencies_remain_sequential,
        ),
        (
            "composite_caller_and_package_grants_keep_distinct_subjects",
            composite_caller_and_package_grants_keep_distinct_subjects,
        ),
        (
            "nested_job_composite_capability_denial_preflights_before_effects",
            nested_job_composite_capability_denial_preflights_before_effects,
        ),
        (
            "invalid_composite_timeout_preflights_before_dependency_effects",
            invalid_composite_timeout_preflights_before_dependency_effects,
        ),
        (
            "composite_dry_run_does_not_spawn_steps",
            composite_dry_run_does_not_spawn_steps,
        ),
        (
            "composite_timeout_stops_the_sequence",
            composite_timeout_stops_the_sequence,
        ),
        (
            "composite_cancellation_stops_the_sequence",
            composite_cancellation_stops_the_sequence,
        ),
        (
            "background_launch_overlaps_then_named_wait_publishes_outputs_and_environment",
            background_launch_overlaps_then_named_wait_publishes_outputs_and_environment,
        ),
        (
            "parallel_dependencies_really_overlap_and_are_joined_before_the_owner",
            parallel_dependencies_really_overlap_and_are_joined_before_the_owner,
        ),
        (
            "wait_all_is_a_barrier_and_successful_handoffs_merge_in_launch_order",
            wait_all_is_a_barrier_and_successful_handoffs_merge_in_launch_order,
        ),
        (
            "implicit_final_join_reports_background_failure_and_discards_its_handoff",
            implicit_final_join_reports_background_failure_and_discards_its_handoff,
        ),
        (
            "a_joined_failure_blocks_normal_work_but_allows_explicit_force_recovery",
            a_joined_failure_blocks_normal_work_but_allows_explicit_force_recovery,
        ),
        (
            "timeout_cleans_up_the_background_process_tree",
            timeout_cleans_up_the_background_process_tree,
        ),
        (
            "successful_background_leaders_cannot_leave_detached_descendants",
            successful_background_leaders_cannot_leave_detached_descendants,
        ),
        (
            "caller_cancellation_joins_every_worker_and_its_descendants",
            caller_cancellation_joins_every_worker_and_its_descendants,
        ),
        (
            "partial_pipeline_start_failure_also_cleans_up_prior_background_groups",
            partial_pipeline_start_failure_also_cleans_up_prior_background_groups,
        ),
        (
            "dry_run_spawns_nothing_and_does_not_claim_execution_success",
            dry_run_spawns_nothing_and_does_not_claim_execution_success,
        ),
        (
            "graph_budget_is_checked_before_effects_in_both_execution_and_dry_run",
            graph_budget_is_checked_before_effects_in_both_execution_and_dry_run,
        ),
        (
            "unreachable_parallel_requests_do_not_change_default_ordering",
            unreachable_parallel_requests_do_not_change_default_ordering,
        ),
        (
            "skipped_wait_targets_are_not_inferred_to_have_succeeded",
            skipped_wait_targets_are_not_inferred_to_have_succeeded,
        ),
        (
            "pending_background_work_has_a_running_outcome_and_is_not_inferred_successful",
            pending_background_work_has_a_running_outcome_and_is_not_inferred_successful,
        ),
        (
            "scheduler_preparation_errors_cancel_and_join_already_started_background_workers",
            scheduler_preparation_errors_cancel_and_join_already_started_background_workers,
        ),
        (
            "background_job_timeout_and_caller_cancellation_stop_nested_process_trees",
            background_job_timeout_and_caller_cancellation_stop_nested_process_trees,
        ),
        (
            "job_lowering_keeps_remote_execution_trust_on_referenced_bodies",
            job_lowering_keeps_remote_execution_trust_on_referenced_bodies,
        ),
        (
            "an_exited_owned_pipeline_leader_cannot_keep_a_downstream_reader_waiting_for_eof",
            an_exited_owned_pipeline_leader_cannot_keep_a_downstream_reader_waiting_for_eof,
        ),
    ];
    let mut filter = None;
    let mut exact = false;
    let mut list = false;
    let mut arguments = args.iter();
    while let Some(arg) = arguments.next() {
        match arg.as_str() {
            "--exact" => exact = true,
            "--list" => list = true,
            "--nocapture" => {}
            "--test-threads" => {
                assert!(
                    arguments.next().is_some(),
                    "--test-threads requires a value"
                );
            }
            value if value.starts_with("--test-threads=") => {}
            value if value.starts_with('-') => panic!("unsupported test option: {value}"),
            value => {
                assert!(
                    filter.replace(value).is_none(),
                    "only one test filter is supported"
                );
            }
        }
    }
    let mut run = 0;
    let mut failed = 0;
    for &(name, test) in tests {
        if filter.is_some_and(|filter| {
            if exact {
                name != filter
            } else {
                !name.contains(filter)
            }
        }) {
            continue;
        }
        if list {
            println!("{name}: test");
            continue;
        }
        run += 1;
        print!("test {name} ... ");
        if std::panic::catch_unwind(test).is_ok() {
            println!("ok");
        } else {
            println!("FAILED");
            failed += 1;
        }
    }
    if !list {
        println!(
            "test result: {}. {} passed; {failed} failed; {} filtered out",
            if failed == 0 { "ok" } else { "FAILED" },
            run - failed,
            tests.len() - run
        );
    }
    if failed != 0 {
        std::process::exit(1);
    }
}

fn composite_steps_run_in_order_and_stop_after_failure() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("order");
    let marker = marker.display().to_string();
    let definitions = tasks(
        root.path(),
        &format!(
            "tasks:\n  finish:\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'printf first >> {marker}'\n      - uses: shell\n        run: 'exit 7'\n      - uses: shell\n        run: 'printf third >> {marker}'\n"
        ),
    );
    let cancellation = TaskCancellation::default();
    let report = execute(root.path(), &definitions, &cancellation, false);
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert_eq!(
        fs::read_to_string(root.path().join("order")).unwrap(),
        "first"
    );
}

fn composite_only_dependencies_remain_sequential() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("order");
    let definitions = tasks(
        root.path(),
        &format!(
            "tasks:\n  prepare:\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'printf first >> {}'\n  finish:\n    needs: prepare\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'printf second >> {}'\n",
            marker.display(),
            marker.display(),
        ),
    );
    let cancellation = TaskCancellation::default();
    let report = execute(root.path(), &definitions, &cancellation, false);
    assert_eq!(report.tasks.len(), 2);
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Succeeded),
        "{:?}",
        report.tasks
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "firstsecond");
}

fn composite_caller_and_package_grants_keep_distinct_subjects() {
    let root = tempfile::tempdir().unwrap();
    let caller_subject = format!(
        "project:{}/task:release-v2",
        root.path().canonicalize().unwrap().display()
    );
    let caller_grants = CapabilityGrants::from_toml(&format!(
        "[[grants]]\nsubject = {caller_subject:?}\ncapability = 'execute'\n"
    ))
    .unwrap();
    let package_grants = CapabilityGrants::from_toml(
        "[[grants]]\nsubject = 'package:composite-digest'\ncapability = 'execute'\n",
    )
    .unwrap();
    let mut task = TaskDefinition {
        id: Some("release-v2".into()),
        action: Some(TaskAction {
            uses: Some("composite".into()),
            ..TaskAction::default()
        }),
        composite_steps: vec![CompositeStep {
            uses: "shell".into(),
            run: "touch caller-granted".into(),
            source_document: None,
        }],
        execution_grant_required: true,
        ..TaskDefinition::default()
    };
    let mut task_map = IndexMap::new();
    task_map.insert("finish".into(), task.clone());
    let cancellation = TaskCancellation::default();
    let caller_report =
        execute_with_grants(root.path(), &task_map, &cancellation, &caller_grants).unwrap();
    assert_eq!(caller_report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert!(root.path().join("caller-granted").exists());

    task.composite_steps[0].run = "touch caller-wrong-subject".into();
    task_map.insert("finish".into(), task.clone());
    let denied =
        execute_with_grants(root.path(), &task_map, &cancellation, &package_grants).unwrap_err();
    assert!(denied.to_string().contains("is not granted"));
    assert!(!root.path().join("caller-wrong-subject").exists());

    task.composite_steps[0].run = "touch package-granted".into();
    task.execution_grant_required = false;
    task.package = Some(TaskPackageIdentity {
        path: "package.yaml".into(),
        sha256: "composite-digest".into(),
        export: "default".into(),
        root: root.path().to_path_buf(),
        external: false,
    });
    task.capability_requests = vec![TaskCapabilityRequest {
        capability: "execute".into(),
        origin: TaskEdgeOrigin::Package,
    }];
    task_map.insert("finish".into(), task.clone());
    let package_report =
        execute_with_grants(root.path(), &task_map, &cancellation, &package_grants).unwrap();
    assert_eq!(package_report.tasks[0].outcome, TaskOutcome::Succeeded);
    assert!(root.path().join("package-granted").exists());

    task.composite_steps[0].run = "touch cross-subject".into();
    task_map.insert("finish".into(), task);
    let denied =
        execute_with_grants(root.path(), &task_map, &cancellation, &caller_grants).unwrap_err();
    assert!(denied.to_string().contains("is not granted"));
    assert!(!root.path().join("cross-subject").exists());
}

fn nested_job_composite_capability_denial_preflights_before_effects() {
    let root = tempfile::tempdir().unwrap();
    let before = root.path().join("before-denial");
    let after = root.path().join("after-denial");
    let mut tasks = IndexMap::new();
    tasks.insert(
        "prepare".into(),
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("shell".into()),
                run: Some(format!("touch {}", before.display())),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    tasks.insert(
        "release".into(),
        TaskDefinition {
            id: Some("release".into()),
            needs: vec!["prepare".into()],
            action: Some(TaskAction {
                uses: Some("composite".into()),
                ..TaskAction::default()
            }),
            composite_steps: vec![CompositeStep {
                uses: "shell".into(),
                run: format!("touch {}", after.display()),
                source_document: None,
            }],
            package: Some(TaskPackageIdentity {
                path: "nested-package.yaml".into(),
                sha256: "nested-composite-digest".into(),
                export: "default".into(),
                root: root.path().to_path_buf(),
                external: true,
            }),
            ..TaskDefinition::default()
        },
    );
    let sequence = TaskSequence {
        tasks,
        root: "release".into(),
        context: "default".into(),
        timeout: None,
        kind: TaskSequenceKind::Job,
    };
    let mut graph = IndexMap::new();
    graph.insert(
        "finish".into(),
        TaskDefinition {
            job: Some(Box::new(sequence)),
            ..TaskDefinition::default()
        },
    );
    let error = execute_with_grants(
        root.path(),
        &graph,
        &TaskCancellation::default(),
        &CapabilityGrants::default(),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("composite-step-0"), "{message}");
    assert!(
        message.contains("package:nested-composite-digest"),
        "{message}"
    );
    assert!(message.contains("is not granted"), "{message}");
    assert!(!before.exists());
    assert!(!after.exists());
}

fn invalid_composite_timeout_preflights_before_dependency_effects() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("before-invalid-timeout");
    let mut tasks = IndexMap::new();
    tasks.insert(
        "prepare".into(),
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("shell".into()),
                run: Some(format!("touch {}", marker.display())),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    tasks.insert(
        "finish".into(),
        TaskDefinition {
            needs: vec!["prepare".into()],
            action: Some(TaskAction {
                uses: Some("composite".into()),
                with: indexmap::indexmap! {"timeout".into() => "not-a-duration".into()},
                ..TaskAction::default()
            }),
            composite_steps: vec![CompositeStep {
                uses: "shell".into(),
                run: "true".into(),
                source_document: None,
            }],
            ..TaskDefinition::default()
        },
    );
    let error = execute_with_grants(
        root.path(),
        &tasks,
        &TaskCancellation::default(),
        &CapabilityGrants::default(),
    )
    .unwrap_err();
    assert!(!error.to_string().is_empty());
    assert!(!marker.exists());
}

fn composite_dry_run_does_not_spawn_steps() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("ran");
    let definitions = tasks(
        root.path(),
        &format!(
            "tasks:\n  finish:\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'touch {}'\n",
            marker.display()
        ),
    );
    let cancellation = TaskCancellation::default();
    let _report = execute(root.path(), &definitions, &cancellation, true);
    assert!(!marker.exists());
}

fn composite_timeout_stops_the_sequence() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("after-timeout");
    let definitions = tasks(
        root.path(),
        &format!(
            "tasks:\n  finish:\n    uses: composite\n    timeout: 100ms\n    steps:\n      - uses: shell\n        run: 'sleep 2'\n      - uses: shell\n        run: 'touch {}'\n",
            marker.display()
        ),
    );
    let cancellation = TaskCancellation::default();
    let report = execute(root.path(), &definitions, &cancellation, false);
    assert_eq!(report.tasks[0].outcome, TaskOutcome::TimedOut);
    assert!(!marker.exists());
}

fn composite_cancellation_stops_the_sequence() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("after-cancel");
    let definitions = tasks(
        root.path(),
        &format!(
            "tasks:\n  finish:\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'sleep 2'\n      - uses: shell\n        run: 'touch {}'\n",
            marker.display()
        ),
    );
    let cancellation = TaskCancellation::default();
    let cancel = cancellation.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
    });
    let report = execute(root.path(), &definitions, &cancellation, false);
    canceller.join().unwrap();
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Cancelled);
    assert!(!marker.exists());
}

fn owned_backend() -> CooperativeOwnedBackend<'static> {
    static EXECUTABLE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let executable =
        EXECUTABLE.get_or_init(|| std::env::current_exe().expect("current test executable"));
    CooperativeOwnedBackend::with_exclusive_child_waits(executable)
}

fn tasks(root: &Path, yaml: &str) -> IndexMap<String, TaskDefinition> {
    let path = root.join("neoenv.yaml");
    fs::write(&path, yaml).unwrap();
    resolve_inheritance(&neoenv_config::parse_project(&path, yaml).unwrap().tasks).unwrap()
}

fn execute(
    root: &Path,
    tasks: &IndexMap<String, TaskDefinition>,
    cancellation: &TaskCancellation,
    dry_run: bool,
) -> TaskRunReport {
    let values = ["RESULT", "BAD", "MERGED", "NEOENV_OUTPUT_VALUE"]
        .into_iter()
        .map(|key| (key.to_owned(), String::new()))
        .collect();
    run_tasks_with_cancellation(
        tasks,
        "finish",
        "default",
        root,
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
            managed_runtimes: &[],
            vaults: None,
            dry_run,
            cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            input_values: None,
            owned_backend: Some(owned_backend()),
        },
    )
    .unwrap()
}

fn execute_with_grants(
    root: &Path,
    tasks: &IndexMap<String, TaskDefinition>,
    cancellation: &TaskCancellation,
    grants: &CapabilityGrants,
) -> Result<TaskRunReport, TaskRunError> {
    let values = IndexMap::new();
    run_tasks_with_cancellation(
        tasks,
        "finish",
        "default",
        root,
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
            managed_runtimes: &[],
            vaults: None,
            dry_run: false,
            cancellation,
            capability_grants: Some(grants),
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            input_values: None,
            owned_backend: Some(owned_backend()),
        },
    )
}

fn outcomes(report: &TaskRunReport) -> Vec<(&str, TaskOutcome)> {
    report
        .tasks
        .iter()
        .map(|task| (task.name.as_str(), task.outcome))
        .collect()
}

fn unavailable_backend_refuses_execution_but_dry_run_only_plans() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
format_version: 1
tasks:
  first:
    uses: shell
    run: touch started
  worker:
    background: true
    uses: shell
    run: touch worker
  finish:
    needs: [first, worker]
    uses: shell
    run: touch finish
",
    );
    let values = IndexMap::default();
    let cancellation = TaskCancellation::default();
    for dry_run in [false, true] {
        let result = run_tasks_with_cancellation(
            &definitions,
            "finish",
            "default",
            root.path(),
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
                managed_runtimes: &[],
                vaults: None,
                dry_run,
                cancellation: &cancellation,
                capability_grants: None,
                capability_policy_source: None,
                remote_tasks: None,
                task_directories: TaskRunnerDirectories::default(),
                input_values: None,
                owned_backend: None,
            },
        );
        if dry_run {
            let report = result.unwrap();
            assert!(
                report
                    .tasks
                    .iter()
                    .all(|task| task.outcome == TaskOutcome::Planned)
            );
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("exclusive child ownership")
            );
        }
        for marker in ["started", "worker", "finish"] {
            assert!(!root.path().join(marker).exists());
        }
    }
}

fn background_launch_overlaps_then_named_wait_publishes_outputs_and_environment() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
format_version: 1
tasks:
  producer:
    background: true
    uses: shell
    timeout: 3s
    outputs: {VALUE: published}
    run: |
      for n in $(seq 1 200); do
        if test -f release; then
          echo RESULT=ready > "$NEOENV_ENV"
          echo VALUE=joined > "$NEOENV_OUTPUTS"
          exit 0
        fi
        sleep 0.01
      done
      exit 91
  release:
    needs: [producer]
    uses: shell
    run: 'test -z "$RESULT" && touch release'
  finish:
    needs: [release]
    wait: [producer]
    if: outputs.VALUE == joined
    uses: shell
    run: 'test "$RESULT" = ready && test "$NEOENV_OUTPUT_VALUE" = joined'
"#,
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert_eq!(
        outcomes(&report),
        [
            ("producer", TaskOutcome::Succeeded),
            ("release", TaskOutcome::Succeeded),
            ("finish", TaskOutcome::Succeeded),
        ]
    );
}

fn parallel_dependencies_really_overlap_and_are_joined_before_the_owner() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  one:
    uses: shell
    timeout: 3s
    run: |
      touch one
      for n in $(seq 1 200); do test -f two && exit 0; sleep 0.01; done
      exit 91
  two:
    uses: shell
    timeout: 3s
    run: |
      touch two
      for n in $(seq 1 200); do test -f one && exit 0; sleep 0.01; done
      exit 92
  finish:
    needs: [{id: one, parallel: true}, {id: two, parallel: true}]
    uses: shell
    run: 'test -f one && test -f two'
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Succeeded),
        "{report:?}"
    );
}

fn wait_all_is_a_barrier_and_successful_handoffs_merge_in_launch_order() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
tasks:
  one:
    background: true
    uses: shell
    timeout: 3s
    run: 'sleep 0.1; echo MERGED=first > "$NEOENV_ENV"'
  two:
    background: true
    uses: shell
    run: 'echo MERGED=second > "$NEOENV_ENV"'
  barrier:
    needs: [one, two]
    wait-all: true
  finish:
    needs: [barrier]
    uses: shell
    run: 'test "$MERGED" = second'
"#,
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Succeeded),
        "{report:?}"
    );
}

fn implicit_final_join_reports_background_failure_and_discards_its_handoff() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
tasks:
  fail:
    background: true
    uses: shell
    timeout: 3s
    run: |
      for n in $(seq 1 200); do
        if test -f foreground; then echo BAD=leaked > "$NEOENV_ENV"; exit 17; fi
        sleep 0.01
      done
      exit 91
  finish:
    needs: [fail]
    uses: shell
    timeout: 3s
    run: 'touch foreground; sleep 30'
"#,
    );
    let started = Instant::now();
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert_eq!(report.tasks[0].exit_code, Some(17));
    assert_eq!(report.tasks[1].outcome, TaskOutcome::Cancelled);
}

fn a_joined_failure_blocks_normal_work_but_allows_explicit_force_recovery() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
tasks:
  fail:
    background: true
    uses: shell
    run: 'echo BAD=leaked > "$NEOENV_ENV"; exit 12'
  blocked:
    wait: [fail]
    uses: shell
    run: touch wrong
  finish:
    needs: [blocked]
    force: outcome.fail == failed
    uses: shell
    run: 'test -z "$BAD" && touch recovered'
"#,
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert_eq!(
        outcomes(&report),
        [
            ("fail", TaskOutcome::Failed),
            ("blocked", TaskOutcome::Blocked),
            ("finish", TaskOutcome::Succeeded),
        ]
    );
    assert!(!root.path().join("wrong").exists());
    assert!(root.path().join("recovered").exists());
}

fn process_running(pid: i32) -> bool {
    let output = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&output.stdout);
    output.status.success() && !status.trim().is_empty() && !status.trim().starts_with('Z')
}

fn assert_child_stopped(root: &Path) {
    let pid: i32 = fs::read_to_string(root.join("child.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let running = process_running(pid);
    // Even a failing test must not leave its fixture behind.
    if running {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    assert!(!running, "the owned descendant survived");
}

fn timeout_cleans_up_the_background_process_tree() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  tree:
    background: true
    uses: shell
    timeout: 2s
    run: 'sleep 30 & echo $! > child.pid; wait'
  finish:
    wait: [tree]
    uses: shell
    run: touch wrong
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert_eq!(report.tasks[0].outcome, TaskOutcome::TimedOut);
    assert_eq!(report.tasks[1].outcome, TaskOutcome::Blocked);
    assert_child_stopped(root.path());
    assert!(!root.path().join("wrong").exists());
}

fn successful_background_leaders_cannot_leave_detached_descendants() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  tree:
    background: true
    uses: shell
    run: 'sleep 30 & echo $! > child.pid; exit 0'
  finish:
    wait-all: true
    needs: [tree]
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Succeeded),
        "{report:?}"
    );
    assert_child_stopped(root.path());
}

fn caller_cancellation_joins_every_worker_and_its_descendants() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  tree:
    background: true
    uses: shell
    timeout: 5s
    run: 'sleep 30 & echo $! > child.pid; wait'
  second:
    background: true
    uses: shell
    timeout: 5s
    run: 'touch second; sleep 30'
  finish:
    needs: [tree, second]
    wait: all
",
    );
    let cancellation = TaskCancellation::new();
    let report = std::thread::scope(|scope| {
        let handle = scope.spawn(|| execute(root.path(), &definitions, &cancellation, false));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !(root.path().join("child.pid").exists() && root.path().join("second").exists())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        cancellation.cancel();
        handle.join().unwrap()
    });
    assert!(
        root.path().join("second").exists(),
        "both workers must have launched"
    );
    assert_eq!(
        outcomes(&report),
        [
            ("tree", TaskOutcome::Cancelled),
            ("second", TaskOutcome::Cancelled),
            ("finish", TaskOutcome::Cancelled),
        ]
    );
    assert_child_stopped(root.path());
}

fn partial_pipeline_start_failure_also_cleans_up_prior_background_groups() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
tasks:
  pipeline:
    background: true
    uses: portable
    run: "sleep 30 | neoenv-fixture-program-that-does-not-exist"
  finish:
    needs: [pipeline]
    wait-all: true
"#,
    );
    let started = Instant::now();
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Failed);
    assert_eq!(report.tasks[1].outcome, TaskOutcome::Blocked);
}

fn dry_run_spawns_nothing_and_does_not_claim_execution_success() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  tree: {background: true, uses: shell, run: 'touch wrong; sleep 30'}
  finish: {wait: [tree]}
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), true);
    assert_eq!(
        outcomes(&report),
        [
            ("tree", TaskOutcome::Planned),
            ("finish", TaskOutcome::Planned)
        ]
    );
    assert!(!root.path().join("wrong").exists());
}

fn graph_budget_is_checked_before_effects_in_both_execution_and_dry_run() {
    let root = tempfile::tempdir().unwrap();
    let mut yaml = String::from("tasks:\n");
    for index in 0..33 {
        writeln!(
            yaml,
            "  worker{index}: {{background: true, uses: shell, run: touch wrong}}"
        )
        .unwrap();
    }
    yaml.push_str("  finish:\n    wait: [");
    yaml.push_str(
        &(0..33)
            .map(|index| format!("worker{index}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    yaml.push_str("]\n");
    let definitions = tasks(root.path(), &yaml);
    for dry_run in [false, true] {
        let cancellation = TaskCancellation::new();
        let error = run_tasks_with_cancellation(
            &definitions,
            "finish",
            "default",
            root.path(),
            TaskEnvironment {
                values: &IndexMap::new(),
                path_operations: &[],
                overrides: None,
            },
            &[],
            TaskRunOptions {
                ssh_output_to_stderr: false,
                ssh_secret_values: &[],
                inventories: None,
                managed_runtimes: &[],
                vaults: None,
                dry_run,
                cancellation: &cancellation,
                capability_grants: None,
                capability_policy_source: None,
                remote_tasks: None,
                task_directories: TaskRunnerDirectories::default(),
                input_values: None,
                owned_backend: Some(owned_backend()),
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("at most 32 background tasks"),
            "{error}"
        );
        assert!(!root.path().join("wrong").exists());
    }
}

fn unreachable_parallel_requests_do_not_change_default_ordering() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  one:
    uses: shell
    run: 'sleep 0.05; touch one'
  unrelated:
    needs: [{id: one, parallel: true}]
    uses: portable
    run: 'true'
  finish:
    needs: [one]
    uses: shell
    run: test -f one
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert_eq!(
        outcomes(&report),
        [
            ("one", TaskOutcome::Succeeded),
            ("finish", TaskOutcome::Succeeded)
        ]
    );
}

fn skipped_wait_targets_are_not_inferred_to_have_succeeded() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  skipped: {background: true, if: 'false', uses: shell, run: touch wrong}
  finish: {wait: [skipped], uses: shell, run: touch wrong}
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert_eq!(
        outcomes(&report),
        [
            ("skipped", TaskOutcome::Skipped),
            ("finish", TaskOutcome::Blocked)
        ]
    );
    assert!(!root.path().join("wrong").exists());
}

fn pending_background_work_has_a_running_outcome_and_is_not_inferred_successful() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r"
tasks:
  worker:
    background: true
    uses: shell
    timeout: 3s
    run: |
      for n in $(seq 1 200); do test -f release && exit 0; sleep 0.01; done
      exit 91
  observe:
    needs: [worker]
    if: outcome.worker == running && !success
    uses: shell
    run: touch release
  finish:
    needs: [observe]
    wait: [worker]
    if: success
    uses: portable
    run: 'true'
",
    );
    let report = execute(root.path(), &definitions, &TaskCancellation::new(), false);
    assert!(
        report
            .tasks
            .iter()
            .all(|task| task.outcome == TaskOutcome::Succeeded),
        "{report:?}"
    );
}

fn scheduler_preparation_errors_cancel_and_join_already_started_background_workers() {
    let root = tempfile::tempdir().unwrap();
    let mut definitions = tasks(
        root.path(),
        r"
tasks:
  tree:
    background: true
    uses: shell
    timeout: 5s
    run: 'sleep 30 & echo $! > child.pid; wait'
  ready:
    needs: [tree]
    uses: shell
    timeout: 3s
    run: |
      for n in $(seq 1 200); do test -f child.pid && exit 0; sleep 0.01; done
      exit 91
  finish:
    needs: [ready]
    uses: portable
    run: 'true'
",
    );
    // Public runtime callers may provide an invalid predicate after normalization.
    // This reaches the scheduler's early error path with a live owned child.
    definitions.get_mut("finish").unwrap().force = Some("not valid predicate syntax".into());
    let cancellation = TaskCancellation::new();
    let error = run_tasks_with_cancellation(
        &definitions,
        "finish",
        "default",
        root.path(),
        TaskEnvironment {
            values: &IndexMap::new(),
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            managed_runtimes: &[],
            vaults: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            input_values: None,
            owned_backend: Some(owned_backend()),
        },
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("invalid force predicate"),
        "{error}"
    );
    assert_child_stopped(root.path());
}

fn background_job_timeout_and_caller_cancellation_stop_nested_process_trees() {
    for cancel in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let timeout = if cancel { "10s" } else { "2s" };
        let yaml = format!(
            r"
jobs:
  worker:
    timeout: {timeout}
    steps:
      - uses: shell
        run: 'sleep 30 & echo $! > child.pid; wait'
  finish:
    needs: [worker]
    wait: [worker]
    steps: [{{uses: shell, run: touch wrong}}]
"
        );
        let path = root.path().join("neoenv.yaml");
        fs::write(&path, &yaml).unwrap();
        let project = neoenv_config::parse_project(&path, &yaml).unwrap();
        let lowered =
            neoenv_core::tasks::lower_jobs(&project.jobs, "finish", &project.tasks, "default")
                .unwrap();
        let cancellation = TaskCancellation::new();
        let report = std::thread::scope(|scope| {
            let handle = scope.spawn(|| execute(root.path(), &lowered.tasks, &cancellation, false));
            if cancel {
                let deadline = Instant::now() + Duration::from_secs(3);
                while !root.path().join("child.pid").exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                cancellation.cancel();
            }
            handle.join().unwrap()
        });
        assert_eq!(
            report.tasks[0].outcome,
            if cancel {
                TaskOutcome::Cancelled
            } else {
                TaskOutcome::TimedOut
            }
        );
        assert_eq!(
            report.tasks[1].outcome,
            if cancel {
                TaskOutcome::Cancelled
            } else {
                TaskOutcome::Blocked
            }
        );
        assert_child_stopped(root.path());
        assert!(!root.path().join("wrong").exists());
    }
}

fn job_lowering_keeps_remote_execution_trust_on_referenced_bodies() {
    let root = tempfile::tempdir().unwrap();
    let yaml = "tasks:\n  remote: {uses: shell, run: touch wrong}\njobs:\n  finish:\n    steps: [remote]\n";
    let path = root.path().join("neoenv.yaml");
    fs::write(&path, yaml).unwrap();
    let mut project = neoenv_config::parse_project(&path, yaml).unwrap();
    project
        .tasks
        .get_mut("remote")
        .unwrap()
        .execution_grant_required = true;
    let lowered =
        neoenv_core::tasks::lower_jobs(&project.jobs, "finish", &project.tasks, "default").unwrap();
    let cancellation = TaskCancellation::new();
    let error = run_tasks_with_cancellation(
        &lowered.tasks,
        "finish",
        "default",
        root.path(),
        TaskEnvironment {
            values: &IndexMap::new(),
            path_operations: &[],
            overrides: None,
        },
        &[],
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            managed_runtimes: &[],
            vaults: None,
            dry_run: false,
            cancellation: &cancellation,
            capability_grants: None,
            capability_policy_source: None,
            remote_tasks: None,
            task_directories: TaskRunnerDirectories::default(),
            input_values: None,
            owned_backend: Some(owned_backend()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        neoenv_runtime::tasks::TaskRunError::CapabilityDenied { .. }
    ));
    assert!(!root.path().join("wrong").exists());
}

fn an_exited_owned_pipeline_leader_cannot_keep_a_downstream_reader_waiting_for_eof() {
    let root = tempfile::tempdir().unwrap();
    let definitions = tasks(
        root.path(),
        r#"
tasks:
  pipeline:
    background: true
    uses: portable
    timeout: 120s
    run: "sh -c 'head -c 262144 /dev/zero; wait_ack() { for n in $(seq 1 1200); do test -f watchdog.ready && return 0; sleep 0.05; done; echo expired > watchdog.expired; return 1; }; (wait_ack && exec sleep 100) & echo $! > child.pid; wait_ack || exit 91' | sh -c 'cat > received'"
  finish:
    wait: [pipeline]
"#,
    );
    let cancellation = TaskCancellation::new();
    let (report, watchdog_ok) = std::thread::scope(|scope| {
        let (finished, completion) = std::sync::mpsc::channel();
        let cancellation = &cancellation;
        let marker = root.path().join("child.pid");
        let acknowledgement = root.path().join("watchdog.ready");
        let watchdog = scope.spawn(move || {
            // Bound startup separately: the watchdog for pipe EOF must start
            // only after the stage has actually launched its descendant.
            let deadline = Instant::now() + Duration::from_secs(60);
            while !marker.exists() {
                if completion.recv_timeout(Duration::from_millis(50)).is_ok() {
                    return false;
                }
                if Instant::now() >= deadline {
                    cancellation.cancel();
                    return false;
                }
            }
            // The stage cannot successfully exit and the descendant's 100s
            // sleep cannot start before this acknowledgement. Expiry writes a
            // failure marker, even if pipeline status hides the stage failure.
            let ready_at = Instant::now();
            let deadline = ready_at + Duration::from_secs(3);
            if fs::write(acknowledgement, "").is_err() {
                cancellation.cancel();
                return false;
            }
            // A regression must fail as Cancelled instead of waiting for the
            // 100s child. This is a separate post-readiness deadline.
            match completion.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(completed_at) if (ready_at..=deadline).contains(&completed_at) => true,
                _ => {
                    cancellation.cancel();
                    false
                }
            }
        });
        let report = execute(root.path(), &definitions, cancellation, false);
        let _ = finished.send(Instant::now());
        (report, watchdog.join().unwrap())
    });
    assert_child_stopped(root.path());
    assert!(
        !root.path().join("watchdog.expired").exists(),
        "fixture readiness wait expired"
    );
    assert!(
        watchdog_ok,
        "pipeline did not complete within the EOF deadline"
    );
    assert_eq!(
        outcomes(&report),
        [
            ("pipeline", TaskOutcome::Succeeded),
            ("finish", TaskOutcome::Succeeded),
        ]
    );
    let received = fs::read(root.path().join("received")).unwrap();
    assert_eq!(
        received.len(),
        262_144,
        "cleanup must not discard buffered pipeline data"
    );
    assert!(received.iter().all(|byte| *byte == 0));
}
