//! Task scheduling: capability enforcement, predicate gating, hook
//! ordering, dependency sequencing, and force-based recovery.

use std::collections::{HashMap, HashSet};

use super::handoff::{Handoff, HandoffValues, apply_handoff};
use super::process::{
    apply_task_environment, default_value, format_process_error, parse_timeout, render_portable,
    render_task_file, resolve_cwd, resolve_fallback_runner, select_dependency,
};
use super::{
    BTreeMap, Capability, ExecutionOptions, IndexMap, Path, PathOperation, PathOperationKind,
    PredicateContext, TaskAction, TaskCancellation, TaskDefinition, TaskEdgeOrigin,
    TaskEnvironment, TaskInputValues, TaskOutcome, TaskRunError, TaskRunOptions, TaskRunReport,
    TaskRunResult, TaskRunnerDirectories, TempDir, evaluate_predicate_with_context, execute_argv,
    execute_chain, normalize_input_value, parse, plan_task, task_dependency_edges,
};
use crate::vault::REFERENCE_PREFIX;
use neoenv_core::tasks::{
    is_builtin_runner, is_script_runner, is_template_runner, parse_uv_runner,
};

/// Executes a dependency graph. Portable actions are rendered and parsed
/// into literal argv; shell actions receive `run` as one explicit `sh -c` argument.
///
/// # Errors
///
/// Returns an error if the requested task graph cannot be planned.
pub fn run_tasks(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
    project_root: &Path,
    project_environment: TaskEnvironment<'_>,
    passthrough: &[String],
    dry_run: bool,
) -> Result<TaskRunReport, TaskRunError> {
    let cancellation = TaskCancellation::new();
    run_tasks_with_cancellation(
        tasks,
        requested_name,
        context,
        project_root,
        project_environment,
        passthrough,
        TaskRunOptions {
            ssh_output_to_stderr: false,
            ssh_secret_values: &[],
            inventories: None,
            dry_run,
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
}

/// Executes a dependency-first graph with opt-in owned background workers.
///
/// Missing/false background mode preserves sequential dispatch. Named waits and
/// parallel dependency joins publish successful handoffs before predicates;
/// remaining workers are joined at graph end. Reports stay in plan order and
/// never contain running outcomes. Caller cancellation and observed failures
/// stop active workers; explicit force recovery can run after their joins.
/// Background groups own their descendants even after a successful leader.
/// Foreground descendant compatibility is unchanged.
///
/// Child wait ownership must be exclusive: embedding processes must not
/// automatically reap SIGCHLD children or externally wait on runtime-owned PIDs.
/// This process-wide precondition is not enforced; unconditional safety in such
/// embedding environments remains a review blocker.
///
/// # Errors
///
/// Returns an error for invalid graphs, denied capabilities, excessive overlap
/// or unavailable platform containment, before spawning. Preparation errors can
/// also return after partial effects, but all owned workers are cancelled/joined.
#[allow(clippy::too_many_lines)]
pub fn run_tasks_with_cancellation(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
    project_root: &Path,
    project_environment: TaskEnvironment<'_>,
    passthrough: &[String],
    options: TaskRunOptions<'_>,
) -> Result<TaskRunReport, TaskRunError> {
    run_graph(
        tasks,
        requested_name,
        context,
        project_root,
        project_environment,
        passthrough,
        None,
        ExecutionScope {
            options,
            owned: false,
        },
    )
    .map(|(report, _)| report)
}

#[allow(clippy::too_many_lines)]
fn run_graph(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
    project_root: &Path,
    project_environment: TaskEnvironment<'_>,
    passthrough: &[String],
    caller_subject_override: Option<&str>,
    scope: ExecutionScope<'_>,
) -> Result<(TaskRunReport, HandoffValues), TaskRunError> {
    let ExecutionScope {
        options,
        owned: owned_scope,
    } = scope;
    let lowered_tasks = lower_composite_tasks(tasks, requested_name, context)?;
    let tasks = &lowered_tasks;
    let plan = plan_task(tasks, requested_name, context)
        .map_err(|error| TaskRunError::planning_source(error.to_string(), error))?;
    let declared_environment = project_environment.values;
    // A dry run never resolves a secret, including for predicates. A plan is not
    // a consumption point; it reports what would run without opening a vault.
    let vaults = (!options.dry_run).then_some(options.vaults).flatten();
    let mut environment: BTreeMap<_, _> = std::env::vars().collect();
    environment.extend(project_environment.values.clone());
    apply_path_operations(&mut environment, project_environment.path_operations);
    add_windows_git_utilities(&mut environment);
    let initial_environment = environment.clone();
    // `--env` overrides are applied last, inside `apply_task_environment`, so a
    // task's own `dotenv`/`env` cannot beat an explicit command-line value. The
    // engine works in `BTreeMap`s, so flatten the caller's ordered map once here.
    let predicate_overrides: Option<BTreeMap<String, String>> =
        project_environment.overrides.map(|overrides| {
            overrides
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        });
    validate_capabilities(
        tasks,
        &plan.tasks,
        project_root,
        options,
        &environment,
        declared_environment,
        predicate_overrides.as_ref(),
        caller_subject_override,
    )?;
    // Reject oversized overlap before any effects. Blocking a launch when all
    // slots are occupied can deadlock a worker waiting for a later action.
    let parallel: std::collections::HashSet<String> = plan
        .tasks
        .iter()
        .flat_map(|task| &tasks[&task.name].parallel_needs)
        .map(|name| select_dependency(tasks, name, context))
        .collect();
    if overlap_count(
        tasks,
        &plan,
        context,
        options
            .owned_backend
            .map(super::model::CooperativeOwnedBackend::executable),
        options.dry_run,
    )? > MAX_BACKGROUND_TASKS
    {
        return Err(TaskRunError::Planning(format!(
            "a plan may launch at most {MAX_BACKGROUND_TASKS} background tasks"
        )));
    }
    let mut results = Vec::with_capacity(plan.tasks.len());
    let mut indexes = TaskExecutionIndex::default();
    // Planning order is dependency-first and may place after-hooks after the
    // requested task. The requested invocation remains the task that receives
    // passthrough arguments and input values; never infer it from plan order.
    let root = neoenv_core::tasks::resolve_task_name(tasks, requested_name, context)
        .map_err(|error| TaskRunError::planning_source(error.to_string(), error))?;
    let mut downstream_blocked = false;
    let mut conditional_tasks: HashSet<String> = HashSet::new();
    // An after hook of a conditional task is conditional too even though the
    // parent is planned first and the hook carries no edge back to it. Resolve
    // owners with the planner's hook rule once, up front.
    let mut after_hook_owners: HashMap<String, Vec<String>> = HashMap::new();
    for (name, task) in tasks {
        for hook in &task.hooks.after {
            if let Some(selected) =
                neoenv_core::tasks::resolve_hook_name(tasks, name, hook, context)
            {
                after_hook_owners
                    .entry(selected)
                    .or_default()
                    .push(name.clone());
            }
        }
    }
    // Only explicitly typed Job containers form a DAG. Composite sequences are
    // ordered task chains and must not activate the all-job scheduling policy.
    let jobs = plan.tasks.iter().all(|planned| {
        tasks[&planned.name]
            .job
            .as_ref()
            .is_some_and(|sequence| sequence.kind == neoenv_core::tasks::TaskSequenceKind::Job)
    });
    let report_order: BTreeMap<_, _> = plan
        .tasks
        .iter()
        .enumerate()
        .map(|(index, task)| (task.name.clone(), index))
        .collect();
    if jobs {
        indexes.job_handoffs = Some(JobHandoffs {
            base: environment.clone(),
            order: report_order.clone(),
            completed: BTreeMap::new(),
        });
    }

    let root = root.as_str();
    std::thread::scope(|scope| -> Result<(), TaskRunError> {
        let mut workers = Vec::new();
        let mut group = options.cancellation.child();
        let mut pending = plan.tasks;
        while !pending.is_empty() {
            if jobs && group.is_cancelled() {
                join_workers(
                    &mut workers,
                    None,
                    &mut results,
                    &mut indexes,
                    &mut environment,
                    &mut downstream_blocked,
                );
                group = options.cancellation.child();
            }
            let position = if jobs && !options.dry_run {
                pending.iter().position(|planned| {
                    let task = &tasks[&planned.name];
                    let unfinished = |name: &str| {
                        let selected = select_dependency(tasks, name, context);
                        pending.iter().any(|item| item.name == selected)
                            || workers
                                .iter()
                                .any(|worker: &BackgroundWorker<'_>| worker.name == selected)
                    };
                    !task.needs.iter().any(|name| unfinished(name))
                        && !task.wait.iter().any(|name| {
                            if name == "all" {
                                !workers.is_empty()
                            } else {
                                unfinished(name)
                            }
                        })
                })
            } else {
                Some(0)
            };
            let Some(position) = position else {
                // Do not join the first launched worker blindly: it may depend
                // on a later worker that must finish to unlock another job.
                if let Some(worker) = workers.iter().find(|worker| {
                    worker
                        .handle
                        .as_ref()
                        .is_some_and(std::thread::ScopedJoinHandle::is_finished)
                }) {
                    let names = std::collections::HashSet::from([worker.name.clone()]);
                    join_workers(
                        &mut workers,
                        Some(&names),
                        &mut results,
                        &mut indexes,
                        &mut environment,
                        &mut downstream_blocked,
                    );
                } else if workers.is_empty() {
                    return Err(TaskRunError::Planning(
                        "job graph has no runnable node".into(),
                    ));
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                continue;
            };
            let planned = pending.remove(position);
            let task = &tasks[&planned.name];
            if group.is_cancelled() {
                join_workers(
                    &mut workers,
                    None,
                    &mut results,
                    &mut indexes,
                    &mut environment,
                    &mut downstream_blocked,
                );
                group = options.cancellation.child();
            }
            let waits = if task.wait.iter().any(|name| name == "all") {
                None
            } else {
                Some(
                    task.wait
                        .iter()
                        .chain(&task.parallel_needs)
                        .chain(task.needs.iter().filter(|name| {
                            let name = select_dependency(tasks, name, context);
                            parallel.contains(&name) && tasks[&name].background != Some(true)
                        }))
                        .map(|name| select_dependency(tasks, name, context))
                        .collect::<std::collections::HashSet<_>>(),
                )
            };
            join_workers(
                &mut workers,
                waits.as_ref(),
                &mut results,
                &mut indexes,
                &mut environment,
                &mut downstream_blocked,
            );
            if group.is_cancelled() {
                join_workers(
                    &mut workers,
                    None,
                    &mut results,
                    &mut indexes,
                    &mut environment,
                    &mut downstream_blocked,
                );
                group = options.cancellation.child();
            }
            if options.cancellation.is_cancelled() {
                indexes.record_result(
                    &mut results,
                    result(
                        task,
                        &planned.name,
                        TaskOutcome::Cancelled,
                        None,
                        Some("task run cancelled"),
                    ),
                );
                continue;
            }
            // **Unknown results propagate.** A conditional predecessor has no real
            // success or failure, so a dependent cannot be decided either. Mark the
            // dependent conditional rather than letting `Planned` stand in for a
            // success that might not happen.
            if options.dry_run {
                let owner_is_conditional =
                    after_hook_owners.get(&planned.name).is_some_and(|owners| {
                        owners.iter().any(|owner| conditional_tasks.contains(owner))
                    });
                if owner_is_conditional {
                    conditional_tasks.insert(planned.name.clone());
                    indexes.record_result(
                        &mut results,
                        result(
                            task,
                            &planned.name,
                            TaskOutcome::Conditional,
                            None,
                            Some("outcome depends on a conditional parent task"),
                        ),
                    );
                    continue;
                }
                // **Use the planner's own selection rules.** An edge stores the
                // declared name (`build`), while the planned key may be the
                // context-selected `build:dev`. A hook similarly resolves by owner
                // and context. Comparing the declared spelling to planned keys
                // silently lost conditional state for exactly those cases.
                let dependency_is_conditional = planned.dependencies.iter().any(|edge| {
                    neoenv_core::tasks::resolve_task_name(tasks, &edge.name, context)
                        .is_ok_and(|selected| conditional_tasks.contains(&selected))
                }) || planned.before_hooks.iter().any(|edge| {
                    neoenv_core::tasks::resolve_hook_name(tasks, &planned.name, &edge.name, context)
                        .is_some_and(|selected| conditional_tasks.contains(&selected))
                }) || planned.after_hooks.iter().any(|edge| {
                    neoenv_core::tasks::resolve_hook_name(tasks, &planned.name, &edge.name, context)
                        .is_some_and(|selected| conditional_tasks.contains(&selected))
                });
                if dependency_is_conditional {
                    conditional_tasks.insert(planned.name.clone());
                    indexes.record_result(
                        &mut results,
                        result(
                            task,
                            &planned.name,
                            TaskOutcome::Conditional,
                            None,
                            Some("outcome depends on a conditional parent task"),
                        ),
                    );
                    continue;
                }
            }
            let predicate_inputs = predicate_inputs(
                task,
                (planned.name == root)
                    .then_some(options.input_values)
                    .flatten(),
            );
            // `args:` is this task's own declared arguments; the passthrough is
            // appended for the requested task only. Per task, because each task
            // declares its own.
            let task_args = task
                .action
                .as_ref()
                .map(|action| action.args.clone())
                .unwrap_or_default();
            let mut combined_args = task_args.clone();
            if planned.name == root {
                combined_args.extend_from_slice(passthrough);
            }
            let predicate_context = PredicateContext {
                environment: &environment,
                context,
                inputs: &predicate_inputs,
                outcomes: &indexes.outcomes,
                outputs: &indexes.outputs,
                overrides: predicate_overrides.as_ref(),
                // The task's own `args:` followed by the command-line passthrough,
                // which is the list the reference builds: a Go file written as
                // `if: args.0 == deploy` gates on the task's declared first
                // argument, not on whatever the user happened to type. Only the
                // requested task gets the passthrough, so a `needs` task's
                // predicate cannot see arguments meant for its dependent.
                args: if planned.name == root {
                    &combined_args
                } else {
                    &task_args
                },
            };
            if options.dry_run
                && predicates_are_conditional(
                    task,
                    &environment,
                    declared_environment,
                    predicate_overrides.as_ref(),
                    &conditional_tasks,
                )?
            {
                conditional_tasks.insert(planned.name.clone());
                indexes.record_result(
                    &mut results,
                    result(
                        task,
                        &planned.name,
                        TaskOutcome::Conditional,
                        None,
                        Some("outcome depends on an unresolved secret reference"),
                    ),
                );
                continue;
            }
            let forced = should_force(task, predicate_context, vaults, declared_environment)?;
            if !forced && downstream_blocked {
                indexes.record_result(
                    &mut results,
                    result(
                        task,
                        &planned.name,
                        TaskOutcome::Blocked,
                        None,
                        Some("a preceding task did not succeed"),
                    ),
                );
                continue;
            }
            if !forced
                && task
                    .needs
                    .iter()
                    .chain(task.wait.iter().filter(|name| name.as_str() != "all"))
                    .any(|dependency| indexes.dependency_failed(tasks, dependency, context))
            {
                indexes.record_result(
                    &mut results,
                    result(
                        task,
                        &planned.name,
                        TaskOutcome::Blocked,
                        None,
                        Some("a dependency did not succeed"),
                    ),
                );
                continue;
            }
            match should_run(
                task,
                predicate_context,
                forced,
                vaults,
                declared_environment,
            ) {
                Ok(false) => {
                    indexes.record_result(
                        &mut results,
                        result(
                            task,
                            &planned.name,
                            TaskOutcome::Skipped,
                            None,
                            Some("task predicate evaluated to false"),
                        ),
                    );
                    continue;
                }
                Ok(true) => {}
                Err(message) => {
                    downstream_blocked = true;
                    group.cancel();
                    indexes.record_result(
                        &mut results,
                        result(
                            task,
                            &planned.name,
                            TaskOutcome::Failed,
                            None,
                            Some(&message),
                        ),
                    );
                    continue;
                }
            }
            if options.dry_run {
                indexes.record_result(
                    &mut results,
                    result(task, &planned.name, TaskOutcome::Planned, None, None),
                );
                continue;
            }
            let task_passthrough = if planned.name == root {
                passthrough
            } else {
                &[]
            };
            if task.background == Some(true) || parallel.contains(&planned.name) {
                let position = results.len();
                // Planned is an internal placeholder, replaced by the joined result.
                results.push(result(
                    task,
                    &planned.name,
                    TaskOutcome::Planned,
                    None,
                    None,
                ));
                let environment = environment.clone();
                let cancellation = group.clone();
                let cleanup = cancellation.clone();
                let name = planned.name.clone();
                let overrides = predicate_overrides.as_ref();
                let handle = std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        let _panic_cleanup = CancelOnPanic(cancellation.clone());
                        let execution = execute_task(
                            &name,
                            task,
                            project_root,
                            &environment,
                            declared_environment,
                            task_passthrough,
                            ExecutionScope {
                                options: TaskRunOptions {
                                    cancellation: &cancellation,
                                    ..options
                                },
                                owned: true,
                            },
                            (name == root).then_some(options.input_values).flatten(),
                            overrides,
                        );
                        if !execution
                            .as_ref()
                            .is_ok_and(|(outcome, _, _)| !is_failure(*outcome))
                        {
                            cancellation.cancel();
                        }
                        execution_result(task, &name, execution)
                    })
                    .map_err(|error| TaskRunError::io_source("start background worker", error))?;
                indexes
                    .outcomes
                    .insert(planned.name.clone(), TaskOutcome::Running);
                workers.push(BackgroundWorker {
                    name: planned.name,
                    position,
                    handle: Some(handle),
                    cancellation: cleanup,
                });
                continue;
            }
            let execution = execute_task(
                &planned.name,
                task,
                project_root,
                &environment,
                declared_environment,
                task_passthrough,
                ExecutionScope {
                    options: TaskRunOptions {
                        cancellation: &group,
                        ..options
                    },
                    owned: owned_scope,
                },
                (planned.name == root)
                    .then_some(options.input_values)
                    .flatten(),
                predicate_overrides.as_ref(),
            );
            let run_result = match execution {
                Ok((TaskOutcome::Succeeded, code, handoff)) => {
                    indexes.record_outputs(&handoff.outputs);
                    apply_handoff(&mut environment, handoff);
                    result(task, &planned.name, TaskOutcome::Succeeded, code, None)
                }
                Ok((outcome, code, _)) => result(task, &planned.name, outcome, code, None),
                Err(message) => result(
                    task,
                    &planned.name,
                    failure_message_outcome(&message),
                    None,
                    Some(&message),
                ),
            };
            downstream_blocked |= matches!(
                run_result.outcome,
                TaskOutcome::Failed
                    | TaskOutcome::TimedOut
                    | TaskOutcome::Cancelled
                    | TaskOutcome::Blocked
            );
            if is_failure(run_result.outcome) {
                group.cancel();
            }
            indexes.record_result(&mut results, run_result);
        }
        join_workers(
            &mut workers,
            None,
            &mut results,
            &mut indexes,
            &mut environment,
            &mut downstream_blocked,
        );
        Ok(())
    })?;
    if jobs {
        results.sort_by_key(|result| report_order[&result.name]);
    }
    let handoff = HandoffValues {
        environment: environment
            .into_iter()
            .filter(|(key, value)| initial_environment.get(key) != Some(value))
            .collect(),
        outputs: indexes.outputs.into_iter().collect(),
        path: Vec::new(),
    };
    Ok((
        TaskRunReport {
            context: context.to_owned(),
            tasks: results,
        },
        handoff,
    ))
}

/// Lowers only reachable composites, including those in reachable job graphs,
/// before capability preflight, retaining the resolved task identity.
fn lower_composite_tasks(
    tasks: &IndexMap<String, TaskDefinition>,
    requested_name: &str,
    context: &str,
) -> Result<IndexMap<String, TaskDefinition>, TaskRunError> {
    let plan = plan_task(tasks, requested_name, context)
        .map_err(|error| TaskRunError::planning_source(error.to_string(), error))?;
    let mut lowered = tasks.clone();
    for planned in plan.tasks {
        let name = &planned.name;
        let task = lowered.get_mut(name).expect("planned task exists");
        if let Some(job) = task.job.as_mut() {
            job.tasks = lower_composite_tasks(&job.tasks, &job.root, &job.context)?;
        }
        let is_composite = task
            .action
            .as_ref()
            .and_then(|action| action.uses.as_deref())
            == Some("composite");
        let composite_timeout = if is_composite {
            Some(validate_composite_task(name, task)?)
        } else {
            None
        };
        if !is_composite && !task.composite_steps.is_empty() {
            return Err(TaskRunError::Planning(format!(
                "task {name} has composite steps but does not use `composite`"
            )));
        }
        if let Some(sequence) = task
            .job
            .as_ref()
            .filter(|sequence| sequence.kind == neoenv_core::tasks::TaskSequenceKind::Composite)
        {
            if !matches_lowered_composite(task, sequence, context)
                || sequence.timeout != composite_timeout.flatten()
            {
                return Err(TaskRunError::Planning(format!(
                    "task {name} has an invalid composite sequence"
                )));
            }
            continue;
        }
        if !is_composite {
            continue;
        }
        if task.job.is_some() {
            return Err(TaskRunError::Planning(format!(
                "task {name} cannot combine composite steps with a job sequence"
            )));
        }
        let mut steps = IndexMap::new();
        let mut previous = None;
        for (index, step) in task.composite_steps.iter().enumerate() {
            let step_name = format!("composite-step-{index}");
            let mut synthetic = TaskDefinition {
                name: Some(format!("{name} step {}", index + 1)),
                action: Some(TaskAction {
                    uses: Some(step.uses.clone()),
                    run: Some(step.run.clone()),
                    source_document: step.source_document.clone(),
                    ..TaskAction::default()
                }),
                package: task.package.clone(),
                execution_grant_required: task.execution_grant_required,
                ..TaskDefinition::default()
            };
            if let Some(previous_name) = previous {
                synthetic.needs.push(previous_name);
                synthetic
                    .dependency_origins
                    .needs
                    .push(if task.package.is_some() {
                        TaskEdgeOrigin::Package
                    } else {
                        TaskEdgeOrigin::Caller
                    });
            }
            previous = Some(step_name.clone());
            steps.insert(step_name, synthetic);
        }
        let root = previous
            .ok_or_else(|| TaskRunError::Planning(format!("composite task {name} has no steps")))?;
        task.job = Some(Box::new(neoenv_core::tasks::TaskSequence {
            tasks: steps,
            root,
            context: context.to_owned(),
            timeout: composite_timeout.flatten(),
            kind: neoenv_core::tasks::TaskSequenceKind::Composite,
        }));
    }
    Ok(lowered)
}

/// Checks that an already-lowered composite is exactly its declared sequential shell chain.
fn matches_lowered_composite(
    task: &TaskDefinition,
    sequence: &neoenv_core::tasks::TaskSequence,
    context: &str,
) -> bool {
    if sequence.tasks.len() != task.composite_steps.len() || sequence.context != context {
        return false;
    }
    let mut previous: Option<String> = None;
    for (index, ((key, child), declared)) in
        sequence.tasks.iter().zip(&task.composite_steps).enumerate()
    {
        if key != &format!("composite-step-{index}")
            || child.job.is_some()
            || !child.composite_steps.is_empty()
            || child.package != task.package
            || child.execution_grant_required != task.execution_grant_required
            || child.needs != previous.iter().cloned().collect::<Vec<_>>()
            || !child.parallel_needs.is_empty()
            || child.background.is_some()
            || !child.wait.is_empty()
            || !child.hooks.before.is_empty()
            || !child.hooks.after.is_empty()
            || !child.capability_requests.is_empty()
            || !child.parameters.is_empty()
            || !child.outputs.is_empty()
            || child.if_condition.is_some()
            || child.force.is_some()
        {
            return false;
        }
        let Some(action) = child.action.as_ref() else {
            return false;
        };
        if action.uses.as_deref() != Some(declared.uses.as_str())
            || action.run.as_deref() != Some(declared.run.as_str())
            || action.source_document != declared.source_document
            || action.source.is_some()
            || action.destination.is_some()
            || !action.args.is_empty()
            || !action.files.is_empty()
            || action.cwd.is_some()
            || !action.env.is_empty()
            || !action.dotenv.is_empty()
            || !action.with.is_empty()
            || !action.capabilities.is_empty()
        {
            return false;
        }
        previous = Some(key.clone());
    }
    let expected_origin = if task.package.is_some() {
        TaskEdgeOrigin::Package
    } else {
        TaskEdgeOrigin::Caller
    };
    if sequence.tasks.values().any(|step| {
        let expected_count = usize::from(!step.needs.is_empty());
        step.dependency_origins.needs.len() != expected_count
            || step
                .dependency_origins
                .needs
                .iter()
                .any(|origin| *origin != expected_origin)
    }) {
        return false;
    }
    previous.as_deref() == Some(sequence.root.as_str())
}

/// Validates a composite task independently of its representation and parses
/// its whole-sequence deadline before any graph effects can begin.
fn validate_composite_task(
    name: &str,
    task: &TaskDefinition,
) -> Result<Option<String>, TaskRunError> {
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| TaskRunError::Planning(format!("composite task {name} has no action")))?;
    if action.run.is_some()
        || action.source.is_some()
        || action.destination.is_some()
        || !action.args.is_empty()
        || !action.files.is_empty()
        || action.cwd.is_some()
        || !action.env.is_empty()
        || !action.dotenv.is_empty()
        || action.with.keys().any(|key| key != "timeout")
    {
        return Err(TaskRunError::Planning(format!(
            "composite task {name} contains unsupported action fields"
        )));
    }
    if task.composite_steps.is_empty() {
        return Err(TaskRunError::Planning(format!(
            "composite task {name} has no steps"
        )));
    }
    if task
        .composite_steps
        .iter()
        .any(|step| step.uses != "shell" || step.run.trim().is_empty())
    {
        return Err(TaskRunError::Planning(format!(
            "composite task {name} requires non-empty shell steps"
        )));
    }
    let timeout = action.with.get("timeout").cloned();
    if let Some(value) = timeout.as_deref() {
        parse_timeout(value).map_err(TaskRunError::Planning)?;
    }
    Ok(timeout)
}

/// A graph's explicit overlap budget. Larger graphs fail before any action runs.
pub const MAX_BACKGROUND_TASKS: usize = 32;

fn overlap_count(
    tasks: &IndexMap<String, TaskDefinition>,
    plan: &neoenv_core::tasks::TaskPlan,
    context: &str,
    backend: Option<&Path>,
    dry_run: bool,
) -> Result<usize, TaskRunError> {
    let parallel = plan
        .tasks
        .iter()
        .flat_map(|task| &tasks[&task.name].parallel_needs)
        .map(|name| select_dependency(tasks, name, context))
        .collect::<std::collections::HashSet<_>>();
    let mut count = 0usize;
    for planned in &plan.tasks {
        let task = &tasks[&planned.name];
        if task.background == Some(true) || parallel.contains(&planned.name) {
            if !dry_run && !super::owned_process::supported(backend) {
                return Err(TaskRunError::Planning(format!(
                    "owned background execution is unavailable: {}",
                    super::owned_process::unavailable_reason()
                )));
            }
            count = count.saturating_add(1);
        }
        if let Some(job) = &task.job {
            job.timeout
                .as_deref()
                .map(parse_timeout)
                .transpose()
                .map_err(TaskRunError::Planning)?;
            let nested = plan_task(&job.tasks, &job.root, &job.context)
                .map_err(|error| TaskRunError::planning_source(error.to_string(), error))?;
            count = count.saturating_add(overlap_count(
                &job.tasks,
                &nested,
                &job.context,
                backend,
                dry_run,
            )?);
        }
    }
    Ok(count)
}

type Execution = Result<(TaskOutcome, Option<i32>, HandoffValues), String>;

#[derive(Clone, Copy)]
struct ExecutionScope<'a> {
    options: TaskRunOptions<'a>,
    owned: bool,
}

struct BackgroundWorker<'scope> {
    name: String,
    position: usize,
    handle: Option<std::thread::ScopedJoinHandle<'scope, (TaskRunResult, HandoffValues)>>,
    cancellation: TaskCancellation,
}

struct CancelOnPanic(TaskCancellation);

impl Drop for CancelOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.cancel();
        }
    }
}

impl Drop for BackgroundWorker<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.cancellation.cancel();
            let _ = handle.join();
        }
    }
}

fn is_failure(outcome: TaskOutcome) -> bool {
    matches!(
        outcome,
        TaskOutcome::Failed | TaskOutcome::TimedOut | TaskOutcome::Cancelled | TaskOutcome::Blocked
    )
}

fn execution_result(
    task: &TaskDefinition,
    name: &str,
    execution: Execution,
) -> (TaskRunResult, HandoffValues) {
    match execution {
        Ok((outcome, code, handoff)) => (
            result(task, name, outcome, code, None),
            if outcome == TaskOutcome::Succeeded {
                handoff
            } else {
                HandoffValues::default()
            },
        ),
        Err(message) => (
            result(
                task,
                name,
                failure_message_outcome(&message),
                None,
                Some(&message),
            ),
            HandoffValues::default(),
        ),
    }
}

fn failure_message_outcome(message: &str) -> TaskOutcome {
    if message.starts_with("task cancelled; cleanup failed:") {
        TaskOutcome::Cancelled
    } else if message.starts_with("task timed out; cleanup failed:") {
        TaskOutcome::TimedOut
    } else {
        TaskOutcome::Failed
    }
}

#[cfg(test)]
mod cleanup_diagnostics_tests {
    use super::{TaskOutcome, failure_message_outcome, format_process_error};
    use neotales_process::Error;

    #[test]
    fn primary_outcome_and_cleanup_warning_are_preserved() {
        for (primary, outcome) in [
            (Error::Cancelled, TaskOutcome::Cancelled),
            (Error::TimedOut, TaskOutcome::TimedOut),
            (Error::Internal("bad protocol"), TaskOutcome::Failed),
        ] {
            let message = format_process_error(Error::Cleanup {
                primary: Box::new(primary),
                cleanup: Box::new(Error::Internal("injected cleanup error")),
            });
            assert_eq!(failure_message_outcome(&message), outcome, "{message}");
            assert!(message.contains("injected cleanup error"), "{message}");
            assert!(message.contains("descendants may remain"), "{message}");
        }
    }
}

fn join_workers(
    workers: &mut Vec<BackgroundWorker<'_>>,
    names: Option<&std::collections::HashSet<String>>,
    results: &mut [TaskRunResult],
    indexes: &mut TaskExecutionIndex,
    environment: &mut BTreeMap<String, String>,
    blocked: &mut bool,
) {
    let mut index = 0;
    while index < workers.len() {
        if names.is_some_and(|names| !names.contains(&workers[index].name)) {
            index += 1;
            continue;
        }
        let mut worker = workers.remove(index);
        let (run_result, handoff) = if let Some(Ok(value)) = worker
            .handle
            .take()
            .map(std::thread::ScopedJoinHandle::join)
        {
            value
        } else {
            let mut failed = results[worker.position].clone();
            failed.outcome = TaskOutcome::Failed;
            failed.message = Some("background worker panicked".into());
            (failed, HandoffValues::default())
        };
        *blocked |= is_failure(run_result.outcome);
        indexes
            .outcomes
            .insert(worker.name.clone(), run_result.outcome);
        if run_result.outcome == TaskOutcome::Succeeded {
            if let Some(jobs) = &mut indexes.job_handoffs {
                jobs.completed.insert(jobs.order[&worker.name], handoff);
                *environment = jobs.base.clone();
                indexes.outputs.clear();
                for value in jobs.completed.values() {
                    for (key, value) in &value.outputs {
                        indexes.outputs.insert(key.clone(), value.clone());
                    }
                    apply_handoff(environment, value.clone());
                }
            } else {
                indexes.record_outputs(&handoff.outputs);
                apply_handoff(environment, handoff);
            }
        }
        results[worker.position] = run_result;
    }
}

#[derive(Default)]
struct TaskExecutionIndex {
    outcomes: BTreeMap<String, TaskOutcome>,
    outputs: BTreeMap<String, String>,
    job_handoffs: Option<JobHandoffs>,
}

struct JobHandoffs {
    base: BTreeMap<String, String>,
    order: BTreeMap<String, usize>,
    completed: BTreeMap<usize, HandoffValues>,
}

impl TaskExecutionIndex {
    fn record_result(&mut self, results: &mut Vec<TaskRunResult>, result: TaskRunResult) {
        self.outcomes.insert(result.name.clone(), result.outcome);
        results.push(result);
    }

    fn record_outputs(&mut self, outputs: &[(String, String)]) {
        for (key, value) in outputs {
            self.outputs.insert(key.clone(), value.clone());
        }
    }

    fn dependency_failed(
        &self,
        tasks: &IndexMap<String, TaskDefinition>,
        dependency: &str,
        context: &str,
    ) -> bool {
        let Ok(dependency) = neoenv_core::tasks::resolve_task_name(tasks, dependency, context)
        else {
            return false;
        };
        // **`Planned` is not a failure.** In a dry run every task is recorded as
        // `Planned`, so "anything that is not `Succeeded` has failed" marks every
        // dependent `Blocked` -- and `nenv run --dry-run` on a two-task plan reported
        // the second task blocked, printed "a dependency did not succeed", and exited
        // non-zero. A dry run's whole answer is "this is what would run", and it was
        // reporting the user's own plan as broken.
        //
        // Found by `nenv job run --dry-run` on a three-step job, and confirmed to
        // predate jobs: the same output comes from a plain three-task `needs` chain.
        //
        // `Skipped` still blocks, deliberately and unchanged: a dependency whose
        // predicate said no did not do the thing the dependent was counting on. That
        // is a separate question from this one and changing it would be a behaviour
        // change nobody asked for.
        self.outcomes.get(&dependency).is_some_and(|outcome| {
            !matches!(
                outcome,
                TaskOutcome::Succeeded
                    | TaskOutcome::Planned
                    | TaskOutcome::Conditional
                    | TaskOutcome::Running
            )
        })
    }
}

// Capability checks intentionally bind caller and package subjects together.
#[allow(clippy::too_many_lines)]
fn validate_capabilities(
    tasks: &IndexMap<String, TaskDefinition>,
    planned: &[neoenv_core::tasks::PlannedTask],
    project_root: &Path,
    options: TaskRunOptions<'_>,
    environment: &BTreeMap<String, String>,
    declared_environment: &IndexMap<String, String>,
    overrides: Option<&BTreeMap<String, String>>,
    caller_subject_override: Option<&str>,
) -> Result<(), TaskRunError> {
    let root = project_root.canonicalize().map_err(|error| {
        TaskRunError::io_source(
            format!("resolve project root {}", project_root.display()),
            error,
        )
    })?;
    let grants = options.capability_grants.cloned().unwrap_or_default();
    for (position, planned_task) in planned.iter().enumerate() {
        let task = &tasks[&planned_task.name];
        if let Some(job) = &task.job {
            let nested = plan_task(&job.tasks, &job.root, &job.context)
                .map_err(|error| TaskRunError::planning_source(error.to_string(), error))?;
            let nested_subject = (job.kind == neoenv_core::tasks::TaskSequenceKind::Composite)
                .then(|| caller_policy_subject(task, &planned_task.name, &root));
            validate_capabilities(
                &job.tasks,
                &nested.tasks,
                project_root,
                options,
                environment,
                declared_environment,
                overrides,
                nested_subject.as_deref(),
            )?;
        }
        let caller_subject = caller_subject_override
            .map(str::to_owned)
            .unwrap_or_else(|| caller_policy_subject(task, &planned_task.name, &root));
        let mut requests = task.capability_requests.clone();
        if requests.is_empty()
            && let Some(action) = task.action.as_ref()
        {
            requests = action
                .capabilities
                .iter()
                .map(|capability| neoenv_core::tasks::TaskCapabilityRequest {
                    capability: capability.clone(),
                    origin: if task.package.is_some() {
                        TaskEdgeOrigin::Package
                    } else {
                        TaskEdgeOrigin::Caller
                    },
                })
                .collect();
        }
        if task
            .package
            .as_ref()
            .is_some_and(|package| package.external)
            && !requests.iter().any(|request| {
                request.capability == "execute" && request.origin == TaskEdgeOrigin::Package
            })
        {
            requests.push(neoenv_core::tasks::TaskCapabilityRequest {
                capability: "execute".into(),
                origin: TaskEdgeOrigin::Package,
            });
        }
        if (task.execution_grant_required
            || options
                .remote_tasks
                .is_some_and(|remote_tasks| remote_tasks.contains(&planned_task.name)))
            && !requests
                .iter()
                .any(|request| request.capability == "execute")
        {
            requests.push(neoenv_core::tasks::TaskCapabilityRequest {
                capability: "execute".into(),
                origin: TaskEdgeOrigin::Caller,
            });
        }
        if task
            .action
            .as_ref()
            .is_some_and(|action| action.uses.as_deref() == Some("ssh"))
        {
            if !requests.iter().any(|request| {
                request.capability == "execute" && request.origin == TaskEdgeOrigin::Caller
            }) {
                requests.push(neoenv_core::tasks::TaskCapabilityRequest {
                    capability: "execute".into(),
                    origin: TaskEdgeOrigin::Caller,
                });
            }
            if position > 0
                && super::ssh_runner::uses_home_identity(task, options)
                    .map_err(TaskRunError::Planning)?
            {
                return Err(TaskRunError::Planning(
                    "dynamic SSH identity after a preceding task is unsupported".into(),
                ));
            }
            // Use the same task-local environment transformation as execution,
            // but do not resolve vaults while merely planning authorization.
            let effective = super::process::apply_task_environment(
                environment,
                declared_environment,
                task.action.as_ref().expect("validated SSH action"),
                overrides,
                None,
            )
            .map_err(TaskRunError::Planning)?;
            super::ssh_runner::authorize(task, options, &effective, &root)
                .map_err(TaskRunError::Planning)?;
        }
        // `with.files` is only meaningful to the template file renderer. The
        // declaration normalizer extracts it before the action reaches here, so a
        // non-tmpl task carrying it would otherwise ignore a key the user wrote.
        if let Some(action) = task.action.as_ref()
            && !action.files.is_empty()
            && !is_template_runner(action.uses.as_deref().unwrap_or(""))
        {
            return Err(TaskRunError::Planning(format!(
                "task {} declares with.files but uses {}; with.files is only read by tmpl",
                planned_task.name,
                action.uses.as_deref().unwrap_or("no runner")
            )));
        }
        // A managed `uv@<version>` is selected by exact version from the
        // verified-runtime list, and running it requires an external execute
        // grant. The install receipt is self-attesting, not signed, so the
        // grant is the authority that the task may launch that runtime. Syntax
        // and version selection are checked first so a typo names the typo
        // rather than the missing grant.
        if let Some(runner) = task
            .action
            .as_ref()
            .and_then(|action| action.uses.as_deref())
            && (runner == "uv" || runner.starts_with("uv@"))
        {
            let request = parse_uv_runner(runner).map_err(TaskRunError::Planning)?;
            let request = request.ok_or_else(|| {
                TaskRunError::Planning("uv runner requires an exact version".to_owned())
            })?;
            let managed = options
                .managed_runtimes
                .iter()
                .find(|runtime| runtime.id == "uv" && runtime.version == request.version)
                .ok_or_else(|| {
                    TaskRunError::Planning(super::runners::uv_version_error(
                        request.version,
                        options.managed_runtimes,
                    ))
                })?;
            super::runners::recheck_uv_install(managed).map_err(TaskRunError::Planning)?;
            if !requests.iter().any(|request| {
                request.capability == "execute" && request.origin == TaskEdgeOrigin::Caller
            }) {
                requests.push(neoenv_core::tasks::TaskCapabilityRequest {
                    capability: "execute".into(),
                    origin: TaskEdgeOrigin::Caller,
                });
            }
        }
        for request in &requests {
            let capability = Capability::parse(&request.capability).ok_or_else(|| {
                TaskRunError::InvalidCapability {
                    task: planned_task.name.clone(),
                    capability: request.capability.clone(),
                    package: task.package.clone().map(Box::new),
                }
            })?;
            let subject = match request.origin {
                TaskEdgeOrigin::Caller => caller_subject.clone(),
                TaskEdgeOrigin::Package => task
                    .package
                    .as_ref()
                    .ok_or_else(|| {
                        TaskRunError::Planning(format!(
                            "package-origin capability has no package identity: {}",
                            planned_task.name
                        ))
                    })?
                    .policy_subject(),
            };
            if !grants.authorizes(capability, &subject) {
                return Err(TaskRunError::CapabilityDenied {
                    task: planned_task.name.clone(),
                    capability,
                    subject,
                    package: task.package.clone().map(Box::new),
                    policy_source: options.capability_policy_source.map(Path::to_owned),
                });
            }
        }
        if let Some(runner) = task
            .action
            .as_ref()
            .and_then(|action| action.uses.as_deref())
            && runner != "exec"
            && runner != "composite"
            && !is_builtin_runner(runner)
        {
            let resolved = resolve_fallback_runner(runner, project_root, options.task_directories)
                .map_err(TaskRunError::Planning)?;
            if resolved.global {
                let subject = format!(
                    "global-task-dir:{}/runner:{}",
                    resolved.directory.display(),
                    runner
                );
                if !grants.authorizes(Capability::Execute, &subject) {
                    return Err(TaskRunError::CapabilityDenied {
                        task: planned_task.name.clone(),
                        capability: Capability::Execute,
                        subject,
                        package: task.package.clone().map(Box::new),
                        policy_source: options.capability_policy_source.map(Path::to_owned),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Uses the same resolved identity as ordinary task capability checks.
fn caller_policy_subject(task: &TaskDefinition, original_key: &str, root: &Path) -> String {
    let identity = task.id.as_deref().unwrap_or(original_key);
    format!("project:{}/task:{identity}", root.display())
}

fn predicate_inputs(task: &TaskDefinition, supplied: Option<&TaskInputValues>) -> TaskInputValues {
    let mut inputs = TaskInputValues::default();
    for parameter in &task.parameters {
        let values = supplied
            .and_then(|values| values.get(&parameter.name).cloned())
            .or_else(|| {
                task.action
                    .as_ref()
                    .and_then(|action| action.with.get(&parameter.name))
                    .map(|value| vec![value.clone()])
            })
            .or_else(|| {
                parameter
                    .default
                    .as_ref()
                    .map(default_value)
                    .map(|value| vec![value])
            });
        if let Some(values) = values {
            inputs.insert(parameter.name.clone(), values);
        }
    }
    inputs
}

/// Whether a dry run cannot decide a predicate without resolving secrets.
///
/// The environment is built exactly as the predicate would see it, but with no
/// vault set, so values stay as written. Only environment dependencies that are
/// still `nsv://` references make the outcome conditional. No vault is opened and
/// no dotenv value is resolved.
fn predicates_are_conditional(
    task: &TaskDefinition,
    environment: &BTreeMap<String, String>,
    declared_environment: &IndexMap<String, String>,
    overrides: Option<&BTreeMap<String, String>>,
    conditional_tasks: &HashSet<String>,
) -> Result<bool, TaskRunError> {
    if task.force.is_none() && task.if_condition.is_none() {
        return Ok(false);
    }
    let predicate_environment = match task.action.as_ref() {
        Some(action) => {
            apply_task_environment(environment, declared_environment, action, overrides, None)
                .map_err(TaskRunError::Planning)?
        }
        None => environment.clone(),
    };
    let predicates = [task.force.as_deref(), task.if_condition.as_deref()];
    for predicate in predicates.into_iter().flatten() {
        let environment_dependencies =
            neoenv_core::tasks::predicate_environment_dependencies(predicate)
                .map_err(TaskRunError::Planning)?;
        for dependency in environment_dependencies {
            if predicate_environment
                .get(&dependency)
                .is_some_and(|value| value.contains(REFERENCE_PREFIX))
            {
                return Ok(true);
            }
        }
        let outcome_dependencies = neoenv_core::tasks::predicate_outcome_dependencies(predicate)
            .map_err(TaskRunError::Planning)?;
        if outcome_dependencies
            .iter()
            .any(|dependency| conditional_tasks.contains(dependency))
        {
            return Ok(true);
        }
        if !conditional_tasks.is_empty()
            && neoenv_core::tasks::predicate_reads_uncertain_aggregate(predicate)
                .map_err(TaskRunError::Planning)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn should_force(
    task: &TaskDefinition,
    predicate_context: PredicateContext<'_>,
    vaults: Option<&crate::vault::VaultSet>,
    declared_environment: &IndexMap<String, String>,
) -> Result<bool, TaskRunError> {
    let Some(predicate) = task.force.as_deref() else {
        return Ok(false);
    };
    let predicate_environment = task
        .action
        .as_ref()
        .map_or_else(
            || Ok(predicate_context.environment.clone()),
            |action| {
                apply_task_environment(
                    predicate_context.environment,
                    declared_environment,
                    action,
                    predicate_context.overrides,
                    vaults,
                )
            },
        )
        .map_err(TaskRunError::Planning)?;
    let context = PredicateContext {
        environment: &predicate_environment,
        ..predicate_context
    };
    evaluate_predicate_with_context(predicate, context)
        .map_err(|error| TaskRunError::Planning(format!("invalid force predicate: {error}")))
}

fn should_run(
    task: &TaskDefinition,
    predicate_context: PredicateContext<'_>,
    forced: bool,
    vaults: Option<&crate::vault::VaultSet>,
    declared_environment: &IndexMap<String, String>,
) -> Result<bool, String> {
    if forced {
        return Ok(true);
    }
    let Some(predicate) = task.if_condition.as_deref() else {
        return Ok(true);
    };
    let predicate_environment = task.action.as_ref().map_or_else(
        || Ok(predicate_context.environment.clone()),
        |action| {
            apply_task_environment(
                predicate_context.environment,
                declared_environment,
                action,
                predicate_context.overrides,
                vaults,
            )
        },
    )?;
    let predicate_context = PredicateContext {
        environment: &predicate_environment,
        ..predicate_context
    };
    evaluate_predicate_with_context(predicate, predicate_context)
        .map_err(|error| format!("invalid if predicate: {error}"))
}

fn apply_path_operations(environment: &mut BTreeMap<String, String>, operations: &[PathOperation]) {
    let prepends = operations
        .iter()
        .filter(|operation| operation.kind == PathOperationKind::Prepend)
        .map(|operation| operation.value.clone())
        .collect::<Vec<_>>();
    let appends = operations
        .iter()
        .filter(|operation| operation.kind == PathOperationKind::Append)
        .map(|operation| operation.value.clone())
        .collect::<Vec<_>>();
    let existing = path_value(environment).map(str::to_owned);
    let value = neotales_env::path_prepend(
        existing.as_deref(),
        &prepends,
        neotales_env::Platform::host(),
    );
    let value = neotales_env::path_append(Some(&value), &appends, neotales_env::Platform::host());
    if !prepends.is_empty() || !appends.is_empty() {
        set_path_value(environment, value);
    }
}

fn path_value(environment: &BTreeMap<String, String>) -> Option<&str> {
    #[cfg(windows)]
    {
        environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
            .map(|(_, value)| value.as_str())
    }
    #[cfg(not(windows))]
    {
        environment.get("PATH").map(String::as_str)
    }
}

fn set_path_value(environment: &mut BTreeMap<String, String>, value: String) {
    #[cfg(windows)]
    environment.retain(|key, _| !key.eq_ignore_ascii_case("PATH"));
    environment.insert("PATH".to_owned(), value);
}

/// Makes Git for Windows' POSIX utilities available to portable tasks.
///
/// Git for Windows provides `echo`, `env`, and other standard utilities under
/// `usr\\bin`. The directory is appended so an explicitly configured tool or
/// an existing user PATH entry continues to take precedence.
#[cfg(windows)]
fn add_windows_git_utilities(environment: &mut BTreeMap<String, String>) {
    let directories = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(std::path::PathBuf::from)
        .map(|directory| directory.join("Git").join("usr").join("bin"))
        .filter(|directory| directory.is_dir())
        .map(|directory| directory.display().to_string())
        .collect::<Vec<_>>();
    if directories.is_empty() {
        return;
    }

    let existing = path_value(environment).map(str::to_owned);
    let path = neotales_env::path_append(
        existing.as_deref(),
        &directories,
        neotales_env::Platform::host(),
    );
    set_path_value(environment, path);
}

#[cfg(not(windows))]
fn add_windows_git_utilities(_environment: &mut BTreeMap<String, String>) {}

fn result(
    task: &TaskDefinition,
    name: &str,
    outcome: TaskOutcome,
    exit_code: Option<i32>,
    message: Option<&str>,
) -> TaskRunResult {
    let (dependencies, before_hooks, after_hooks) = task_dependency_edges(task);
    TaskRunResult {
        name: name.to_owned(),
        outcome,
        exit_code,
        message: message.map(str::to_owned),
        package: task.package.clone(),
        dependencies,
        before_hooks,
        after_hooks,
    }
}

#[cfg(test)]
mod composite_lowering_tests {
    use super::*;
    use neoenv_core::tasks::CompositeStep;

    fn run_with_grants(
        root: &Path,
        tasks: &IndexMap<String, TaskDefinition>,
        grants: &neoenv_policy::CapabilityGrants,
    ) -> Result<TaskRunReport, TaskRunError> {
        let values = IndexMap::new();
        let cancellation = TaskCancellation::default();
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
                cancellation: &cancellation,
                capability_grants: Some(grants),
                capability_policy_source: None,
                remote_tasks: None,
                task_directories: TaskRunnerDirectories::default(),
                input_values: None,
                owned_backend: None,
            },
        )
    }

    fn lowered_valid(_root: &Path) -> IndexMap<String, TaskDefinition> {
        let mut tasks = IndexMap::new();
        tasks.insert(
            "finish".into(),
            TaskDefinition {
                action: Some(TaskAction {
                    uses: Some("composite".into()),
                    with: IndexMap::from([("timeout".into(), "1s".into())]),
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
        lower_composite_tasks(&tasks, "finish", "default").unwrap()
    }

    #[test]
    fn rejects_invalid_direct_composite_models_before_planning() {
        for (runner, run, uses_composite) in [
            ("portable", "true", true),
            ("composite", "", true),
            ("shell", "", true),
            ("shell", "true", false),
        ] {
            let mut tasks = IndexMap::new();
            let mut task = TaskDefinition {
                action: Some(TaskAction {
                    uses: Some(if uses_composite {
                        "composite".into()
                    } else {
                        "shell".into()
                    }),
                    ..TaskAction::default()
                }),
                ..TaskDefinition::default()
            };
            task.composite_steps = vec![CompositeStep {
                uses: runner.into(),
                run: run.into(),
                source_document: None,
            }];
            tasks.insert("check".into(), task);
            assert!(
                lower_composite_tasks(&tasks, "check", "default").is_err(),
                "accepted invalid direct composite model: {runner} {run} / {uses_composite}"
            );
        }
    }

    #[test]
    fn rejects_adversarial_public_composite_sequences() {
        let root = tempfile::tempdir().unwrap();

        let mut with_path_field = lowered_valid(root.path());
        with_path_field["finish"].action.as_mut().unwrap().cwd = Some("ignored".into());
        assert!(lower_composite_tasks(&with_path_field, "finish", "default").is_err());

        let mut changed_timeout = lowered_valid(root.path());
        changed_timeout["finish"].job.as_mut().unwrap().timeout = Some("2s".into());
        assert!(lower_composite_tasks(&changed_timeout, "finish", "default").is_err());
    }

    #[test]
    fn forged_synthetic_child_id_cannot_override_parent_subject() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("must-not-run");
        let forged_subject = format!(
            "project:{}/task:other",
            root.path().canonicalize().unwrap().display()
        );
        let grants = neoenv_policy::CapabilityGrants::from_toml(&format!(
            "[[grants]]\nsubject = {forged_subject:?}\ncapability = 'execute'\n"
        ))
        .unwrap();
        let mut tasks = lowered_valid(root.path());
        tasks["finish"].execution_grant_required = true;
        let command = format!("touch {}", marker.display());
        tasks["finish"].composite_steps[0].run = command.clone();
        let child = tasks["finish"]
            .job
            .as_mut()
            .unwrap()
            .tasks
            .get_mut("composite-step-0")
            .unwrap();
        child.id = Some("other".into());
        child.execution_grant_required = true;
        child.action.as_mut().unwrap().run = Some(command);

        let error = run_with_grants(root.path(), &tasks, &grants).unwrap_err();
        assert!(error.to_string().contains("project:"));
        assert!(error.to_string().contains("/task:finish"));
        assert!(!error.to_string().contains("/task:other"));
        assert!(!marker.exists());
    }

    #[test]
    fn composite_steps_use_explicit_parent_identity_for_both_preflights() {
        let root = tempfile::tempdir().unwrap();
        let subject = format!(
            "project:{}/task:stable-id",
            root.path().canonicalize().unwrap().display()
        );
        let grants = neoenv_policy::CapabilityGrants::from_toml(&format!(
            "[[grants]]\nsubject = {subject:?}\ncapability = 'execute'\n"
        ))
        .unwrap();
        let mut tasks = lowered_valid(root.path());
        let parent = tasks.get_mut("finish").unwrap();
        parent.id = Some("stable-id".into());
        parent.execution_grant_required = true;
        parent
            .job
            .as_mut()
            .unwrap()
            .tasks
            .get_mut("composite-step-0")
            .unwrap()
            .execution_grant_required = true;

        let report = run_with_grants(root.path(), &tasks, &grants).unwrap();
        assert_eq!(report.tasks.last().unwrap().outcome, TaskOutcome::Succeeded);
    }

    #[test]
    fn unreachable_invalid_composite_does_not_block_requested_task() {
        let root = tempfile::tempdir().unwrap();
        let mut tasks = lowered_valid(root.path());
        let mut invalid = tasks["finish"].clone();
        invalid.job = None;
        invalid.composite_steps.clear();
        tasks.insert("unrelated".into(), invalid);

        let report = run_with_grants(root.path(), &tasks, &Default::default()).unwrap();
        assert_eq!(report.tasks.last().unwrap().outcome, TaskOutcome::Succeeded);
    }

    #[test]
    fn unreachable_invalid_composite_inside_reachable_job_does_not_block() {
        let root = tempfile::tempdir().unwrap();
        let mut nested = lowered_valid(root.path());
        let mut invalid = nested["finish"].clone();
        invalid.job = None;
        invalid.composite_steps.clear();
        nested.insert("unrelated".into(), invalid);
        let tasks = IndexMap::from([(
            "finish".into(),
            TaskDefinition {
                job: Some(Box::new(neoenv_core::tasks::TaskSequence {
                    tasks: nested,
                    root: "finish".into(),
                    context: "default".into(),
                    timeout: None,
                    kind: neoenv_core::tasks::TaskSequenceKind::Job,
                })),
                ..TaskDefinition::default()
            },
        )]);

        let report = run_with_grants(root.path(), &tasks, &Default::default()).unwrap();
        assert_eq!(report.tasks.last().unwrap().outcome, TaskOutcome::Succeeded);
    }
}

fn required_run(action: &TaskAction) -> Result<&str, String> {
    action
        .run
        .as_deref()
        .filter(|run| !run.is_empty())
        .ok_or_else(|| "task action has no run value".to_owned())
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "the execution seam names every independent input explicitly"
)]
fn execute_task(
    task_name: &str,
    task: &TaskDefinition,
    project_root: &Path,
    environment: &BTreeMap<String, String>,
    declared_environment: &IndexMap<String, String>,
    passthrough: &[String],
    scope: ExecutionScope<'_>,
    // Narrowed to the root task by the caller, because a dependency must not
    // consume the values supplied on the command line.
    input_values: Option<&TaskInputValues>,
    overrides: Option<&BTreeMap<String, String>>,
) -> Result<(TaskOutcome, Option<i32>, HandoffValues), String> {
    let options = &scope.options;
    let owned_background = scope.owned;
    if let Some(job) = &task.job {
        if job.kind == neoenv_core::tasks::TaskSequenceKind::Composite
            && job
                .tasks
                .values()
                .any(|step| step.job.is_some() || !step.composite_steps.is_empty())
        {
            return Err("nested composite steps are unsupported".into());
        }
        let timeout = job.timeout.as_deref().map(parse_timeout).transpose()?;
        let cancellation = options.cancellation.with_timeout(timeout)?;
        let values = environment
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let overrides = overrides.map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        });
        let caller_subject = if job.kind == neoenv_core::tasks::TaskSequenceKind::Composite {
            let root = project_root
                .canonicalize()
                .map_err(|_| "resolve project root for composite authorization".to_owned())?;
            Some(caller_policy_subject(task, task_name, &root))
        } else {
            None
        };
        let (report, handoff) = run_graph(
            &job.tasks,
            &job.root,
            &job.context,
            project_root,
            TaskEnvironment {
                values: &values,
                path_operations: &[],
                overrides: overrides.as_ref(),
            },
            &[],
            caller_subject.as_deref(),
            ExecutionScope {
                options: TaskRunOptions {
                    input_values: None,
                    cancellation: &cancellation,
                    ..*options
                },
                owned: owned_background,
            },
        )
        .map_err(|error| error.to_string())?;
        // A nested job must not discard a Docker recovery identity when it
        // collapses its child report into a single outcome.
        let recovery_messages: Vec<_> = report
            .tasks
            .iter()
            .filter_map(|task| task.message.as_deref())
            .filter(|message| message.contains("daemon outcome/cleanup unknown"))
            .collect();
        if !recovery_messages.is_empty() {
            return Err(recovery_messages.join("; "));
        }
        let outcome = if !options.cancellation.is_cancelled() && cancellation.timed_out() {
            TaskOutcome::TimedOut
        } else {
            report
                .tasks
                .iter()
                .map(|task| task.outcome)
                .find(|outcome| matches!(outcome, TaskOutcome::Failed | TaskOutcome::TimedOut))
                .or_else(|| {
                    report
                        .tasks
                        .iter()
                        .map(|task| task.outcome)
                        .find(|outcome| is_failure(*outcome))
                })
                .unwrap_or(TaskOutcome::Succeeded)
        };
        return Ok((
            outcome,
            (outcome == TaskOutcome::Succeeded).then_some(0),
            handoff,
        ));
    }
    if task.action.is_none() && !task.wait.is_empty() {
        return Ok((TaskOutcome::Succeeded, Some(0), HandoffValues::default()));
    }
    let action = task
        .action
        .as_ref()
        .ok_or_else(|| "task has no action".to_owned())?;
    if action.uses.as_deref() == Some("render") {
        render_task_file(task, project_root)?;
        return Ok((TaskOutcome::Succeeded, Some(0), HandoffValues::default()));
    }
    if action.uses.as_deref().is_some_and(is_template_runner) {
        let task_environment = apply_task_environment(
            environment,
            declared_environment,
            action,
            overrides,
            options.vaults,
        )?;
        return match super::template::render_template_task(
            task,
            project_root,
            &task_environment,
            options,
        ) {
            Ok(()) => Ok((TaskOutcome::Succeeded, Some(0), HandoffValues::default())),
            Err(message) if message == "task cancelled" => {
                Ok((TaskOutcome::Cancelled, None, HandoffValues::default()))
            }
            Err(message) => Err(message),
        };
    }
    let handoff_directory = TempDir::new().map_err(|error| error.to_string())?;
    let handoff = Handoff::new(handoff_directory.path());
    let cwd = resolve_cwd(project_root, task)?;
    let mut task_environment = apply_task_environment(
        environment,
        declared_environment,
        action,
        overrides,
        options.vaults,
    )?;
    task_environment.insert(
        "NEOENV_ENV".into(),
        handoff.environment.display().to_string(),
    );
    task_environment.insert("NEOENV_PATH".into(), handoff.path.display().to_string());
    task_environment.insert(
        "NEOENV_OUTPUTS".into(),
        handoff.outputs.display().to_string(),
    );
    for parameter in &task.parameters {
        let values = input_values
            .and_then(|values| values.get(&parameter.name).cloned())
            .or_else(|| {
                action
                    .with
                    .get(&parameter.name)
                    .cloned()
                    .map(|value| vec![value])
            })
            .or_else(|| {
                parameter
                    .default
                    .as_ref()
                    .map(default_value)
                    .map(|value| vec![value])
            });
        if parameter.required && values.is_none() {
            return Err(format!(
                "required task input is not set: {}",
                parameter.name
            ));
        }
        if let Some(values) = values {
            let mut normalized = Vec::with_capacity(values.len());
            for value in values {
                let value = normalize_input_value(parameter, value)
                    .ok_or_else(|| format!("task input {} has an invalid value", parameter.name))?;
                normalized.push(value);
            }
            let value = if parameter.repeatable {
                serde_json::to_string(&normalized).map_err(|error| {
                    format!("failed to encode task input {}: {error}", parameter.name)
                })?
            } else {
                normalized
                    .into_iter()
                    .next()
                    .ok_or_else(|| format!("task input {} has no value", parameter.name))?
            };
            task_environment.insert(format!("NEOENV_INPUT_{}", parameter.name), value);
        }
    }
    if action.uses.as_deref() == Some("ssh") {
        if !passthrough.is_empty() {
            return Err("SSH tasks do not accept passthrough arguments".into());
        }
        let status =
            match super::ssh_runner::execute(task, &task_environment, options, project_root) {
                Ok(status) => status,
                Err(message) if message == "task cancelled" => {
                    return Ok((TaskOutcome::Cancelled, None, HandoffValues::default()));
                }
                Err(message) if message == "task timed out" => {
                    return Ok((TaskOutcome::TimedOut, None, HandoffValues::default()));
                }
                Err(message) => return Err(message),
            };
        return Ok((
            if status == 0 {
                TaskOutcome::Succeeded
            } else {
                TaskOutcome::Failed
            },
            i32::try_from(status).ok(),
            HandoffValues::default(),
        ));
    }
    let timeout = action
        .with
        .get("timeout")
        .map(|value| parse_timeout(value))
        .transpose()?;
    // Background work must never fall back to the historical adapter. On
    // Unix, use the owned foreground adapter only where it is implemented;
    // Windows deliberately retains its existing foreground adapter.
    let use_owned = owned_background
        || (cfg!(not(windows))
            && super::owned_process::supported(
                scope
                    .options
                    .owned_backend
                    .map(|backend| backend.executable()),
            ));
    let execution = match action.uses.as_deref() {
        Some("exec" | "portable") => render_portable(required_run(action)?, &task_environment)
            .and_then(|rendered| {
                parse(&rendered)
                    .map_err(|error| error.to_string())
                    .and_then(|chain| {
                        let is_cancelled = || options.cancellation.is_cancelled();
                        let mut portable_args = action.args.clone();
                        portable_args.extend_from_slice(passthrough);
                        let execution = ExecutionOptions {
                            working_directory: &cwd,
                            environment: &task_environment,
                            passthrough: &portable_args,
                            is_cancelled: &is_cancelled,
                            timeout,
                        };
                        if use_owned {
                            scope.options.owned_backend.map_or_else(
                                || Err("owned background execution is unavailable".into()),
                                |backend| {
                                    super::owned_process::execute_chain(
                                        &chain,
                                        &execution,
                                        backend.executable(),
                                        !owned_background,
                                    )
                                    .map_err(format_process_error)
                                },
                            )
                        } else {
                            execute_chain(&chain, &execution).map_err(format_process_error)
                        }
                    })
            }),
        Some("argv") => {
            let run = required_run(action)?;
            let is_cancelled = || options.cancellation.is_cancelled();
            let execution = ExecutionOptions {
                working_directory: &cwd,
                environment: &task_environment,
                passthrough,
                is_cancelled: &is_cancelled,
                timeout,
            };
            if use_owned {
                scope.options.owned_backend.map_or_else(
                    || Err("owned background execution is unavailable".into()),
                    |backend| {
                        super::owned_process::execute_argv(
                            run,
                            &action.args,
                            &execution,
                            backend.executable(),
                            !owned_background,
                        )
                        .map_err(format_process_error)
                    },
                )
            } else {
                execute_argv(run, &action.args, &execution).map_err(format_process_error)
            }
        }
        Some("shell") => {
            let mut arguments = vec![
                "-c".into(),
                required_run(action)?.to_owned(),
                "neoenv-task".into(),
            ];
            arguments.extend(action.args.iter().cloned());
            let is_cancelled = || options.cancellation.is_cancelled();
            let execution = ExecutionOptions {
                working_directory: &cwd,
                environment: &task_environment,
                passthrough,
                is_cancelled: &is_cancelled,
                timeout,
            };
            if use_owned {
                scope.options.owned_backend.map_or_else(
                    || Err("owned background execution is unavailable".into()),
                    |backend| {
                        super::owned_process::execute_argv(
                            "sh",
                            &arguments,
                            &execution,
                            backend.executable(),
                            !owned_background,
                        )
                        .map_err(format_process_error)
                    },
                )
            } else {
                execute_argv("sh", &arguments, &execution).map_err(format_process_error)
            }
        }
        Some("docker") => {
            if owned_background {
                Err("docker tasks do not support owned background execution".to_owned())
            } else {
                super::docker::execute(
                    required_run(action)?,
                    action,
                    &cwd,
                    &task_environment,
                    passthrough,
                    options,
                    timeout,
                )
            }
        }
        Some("wsl") => super::runners::execute_wsl(
            required_run(action)?,
            action,
            &cwd,
            &task_environment,
            passthrough,
            options,
            timeout,
        ),
        Some(runner) if is_script_runner(runner) => super::runners::execute_script(
            runner,
            task,
            project_root,
            &task_environment,
            &cwd,
            passthrough,
            options,
            timeout,
        ),
        Some(runner) if runner == "uv" || runner.starts_with("uv@") => {
            match parse_uv_runner(runner) {
                Ok(Some(request)) => super::runners::execute_uv(
                    request.version,
                    task,
                    project_root,
                    &task_environment,
                    &cwd,
                    passthrough,
                    options,
                    timeout,
                ),
                Ok(None) => Err("uv runner requires an exact version".to_owned()),
                Err(message) => Err(message),
            }
        }
        Some(runner) => {
            let runner = resolve_fallback_runner(runner, project_root, options.task_directories)?;
            let mut arguments = vec![required_run(action)?.to_owned()];
            arguments.extend(action.args.iter().cloned());
            let is_cancelled = || options.cancellation.is_cancelled();
            let program = runner.path.display().to_string();
            let execution = ExecutionOptions {
                working_directory: &cwd,
                environment: &task_environment,
                passthrough,
                is_cancelled: &is_cancelled,
                timeout,
            };
            if use_owned {
                scope.options.owned_backend.map_or_else(
                    || Err("owned background execution is unavailable".into()),
                    |backend| {
                        super::owned_process::execute_argv(
                            &program,
                            &arguments,
                            &execution,
                            backend.executable(),
                            !owned_background,
                        )
                        .map_err(format_process_error)
                    },
                )
            } else {
                execute_argv(&program, &arguments, &execution).map_err(format_process_error)
            }
        }
        None => {
            Err("task runner must be explicitly selected as portable, argv, or shell".to_owned())
        }
    };
    let status = match execution {
        Ok(status) => status,
        Err(message) if message == "task cancelled" => {
            return Ok((TaskOutcome::Cancelled, None, HandoffValues::default()));
        }
        Err(message) if message == "task timed out" => {
            return Ok((TaskOutcome::TimedOut, None, HandoffValues::default()));
        }
        Err(message) => return Err(message),
    };
    Ok((
        if status.success() {
            TaskOutcome::Succeeded
        } else {
            TaskOutcome::Failed
        },
        status.code(),
        handoff.read(&task.outputs)?,
    ))
}
