//! `nenv job` — the project's ordered pipelines, and running one.
//!
//! ## Why this is a command and not a filtered `task list`
//!
//! A job is a **sequence of steps** and a task is a **node in a dependency graph**.
//! The reference says so at `neofile/job.go:5` — *"Job is an experimental pipeline
//! definition made of ordered steps"* — and keeps them in separate namespaces:
//! `resolveJob` takes a `*JobMap`, `resolveTask` takes a `*TaskMap`, and neither is
//! ever handed the other's type. The decision, with citations, is in
//! `docs/decision-records/a-job-is-a-sequence-of-steps.md`.
//!
//! So `job list` lists jobs, not tasks, and a job is a thing a user names.
//!
//! ## How a job runs without a job executor
//!
//! **A job's steps are lowered into a chain of tasks**, step *n* depending on step
//! *n-1*, and handed to the ordinary task runner. A linear `needs` chain *is* a
//! sequence, so this needs no new execution path, and it inherits the two properties
//! a sequence needs for free:
//!
//! - the environment accumulates across steps, because one plan shares one
//!   environment, and
//! - a failing step stops the ones after it, because the plan marks downstream work
//!   blocked.
//!
//! The reference does the same thing in effect: `taskFromJobStep`
//! (`neofile/runner.go:667-698`) desugars each step into a `Task` and runs it through
//! the normal task executor.
//!
//! ## What this command refuses, and why that is the design
//!
//! A job's keys are ported **with their behaviour or refused by name**:
//!
//! | key | here |
//! |-----|------|
//! | `steps` | run, in order |
//! | `env`, `cwd`, `dotenv` | applied to every step, a step's own winning |
//! | `if` | gates the whole job, before the first step |
//! | `description`, `help` | shown by `job list` |
//! | `extends`, `cron` | **refused at read time** — inert in the reference |
//! | `needs`, `wait`, `background` | owned job containers, sharing the task scheduler |
//! | `timeout` | whole-job deadline, propagated through its steps and joins |
//!
//! Sequential jobs retain their per-step reports. Jobs using graph controls
//! report one final result per job; their steps execute in an owned nested scope.

use neoenv_core::tasks::JobDefinition;

use crate::{
    Diagnostic, DiagnosticCategory, RunOverrides,
    cli::{JobCommand, OutputFormat},
    output::{load_project_with_profile, print_json},
    task_dispatch::{PlanRun, project_environment, run_plan},
};

/// The one entry point, so the tree, the parser and the manifest have a single thing
/// to agree about.
pub(super) fn dispatch_job(
    command: &JobCommand,
    path: Option<&str>,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
    context_override: Option<&str>,
) -> Result<(), Diagnostic> {
    let project = load_project_with_profile(path, profile, context_override)?;
    match command {
        JobCommand::Group { .. } | JobCommand::List { .. } => print_list(&project.jobs, format),
        JobCommand::Run { job, dry_run, .. } => {
            if !*dry_run {
                crate::output::require_execution_trust(&project)?;
            }
            run_one(&project, job, *dry_run, format, context_override)
        }
        JobCommand::Help { job, .. } => print_help(&project.jobs, job, format),
    }
}

fn print_list(
    jobs: &indexmap::IndexMap<String, JobDefinition>,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Json => print_json(&serde_json::json!(
            jobs.iter()
                .map(|(key, job)| serde_json::json!({
                    "key": key,
                    "name": job.name,
                    "description": job.description,
                    "steps": job.steps.len(),
                }))
                .collect::<Vec<_>>()
        )),
        OutputFormat::Text => {
            if jobs.is_empty() {
                // A real answer, in words. A bare newline is indistinguishable from a
                // crash or a truncated pipe.
                println!("this project declares no jobs");
                return Ok(());
            }
            for (key, job) in jobs {
                match job.description.as_deref() {
                    Some(description) => println!("{key}\t{description}"),
                    // The step count, because for a job it is the most useful thing
                    // after the name -- a sequence's length is its whole shape.
                    None => println!("{key}\t{} step(s)", job.steps.len()),
                }
            }
            Ok(())
        }
    }
}

fn print_help(
    jobs: &indexmap::IndexMap<String, JobDefinition>,
    job: &str,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let Some(definition) = jobs.get(job) else {
        return Err(unknown_job(jobs, job));
    };
    match format {
        OutputFormat::Json => print_json(&serde_json::json!({
            "key": job,
            "name": definition.name,
            "description": definition.description,
            "help": definition.help,
            "background": definition.background.unwrap_or(false),
            "wait": definition.wait,
            "needs": definition.needs,
            "parallel_dependencies": definition.parallel_needs,
            "timeout": definition.timeout,
            "steps": definition.steps.iter().enumerate().map(|(index, step)| serde_json::json!({
                "position": index + 1,
                "id": step.id,
                "name": step.name,
                "task": step.task,
                "run": step.run,
                "uses": step.uses,
                "cwd": step.cwd,
                "background": step.background,
                "wait": step.wait,
                "timeout": step.timeout,
            })).collect::<Vec<_>>(),
        })),
        OutputFormat::Text => {
            println!(
                "{}",
                definition.help.as_deref().unwrap_or_else(|| {
                    definition
                        .description
                        .as_deref()
                        .unwrap_or("(no help for this job)")
                })
            );
            if format == OutputFormat::Text && definition.help.is_none() {
                // The step list is the help for a sequence: a job's meaning *is* its
                // order, so a description alone answers a different question.
                for (index, step) in definition.steps.iter().enumerate() {
                    let what = step
                        .task
                        .clone()
                        .or_else(|| step.run.clone())
                        .unwrap_or_else(|| "(nothing)".to_owned());
                    println!("  {}. {what}", index + 1);
                }
            }
            Ok(())
        }
    }
}

/// A refusal that names the alternatives, for the same reason `config get` and
/// `context` do: "no such job" on its own makes the user run `job list` and read all
/// of it to discover they typoed a name.
fn unknown_job(jobs: &indexmap::IndexMap<String, JobDefinition>, job: &str) -> Diagnostic {
    let available = if jobs.is_empty() {
        "none".to_owned()
    } else {
        jobs.keys().cloned().collect::<Vec<_>>().join(", ")
    };
    Diagnostic::new(
        DiagnosticCategory::NotFound,
        "NEO340",
        format!("job {job:?} is not declared by this project. Available: {available}"),
    )
}

fn run_one(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    job: &str,
    dry_run: bool,
    format: OutputFormat,
    context_override: Option<&str>,
) -> Result<(), Diagnostic> {
    let Some(definition) = project.jobs.get(job) else {
        return Err(unknown_job(&project.jobs, job));
    };
    let context =
        neoenv_core::tasks::select_context(context_override, None, project.context.as_deref());
    let graph = !definition.needs.is_empty()
        || !definition.wait.is_empty()
        || definition.background == Some(true)
        || definition.timeout.is_some();

    // The job's `if` gates the whole thing, before the first step and before any
    // lowering. The reference evaluates `shouldRunJob` once per job for the same
    // reason (`runner.go:421`).
    let predicate_environment: std::collections::BTreeMap<String, String> =
        project_environment(project).into_iter().collect();
    if !graph
        && let Some(condition) = &definition.if_condition
        && !neoenv_core::tasks::evaluate_predicate_with_context(
            condition,
            neoenv_core::tasks::PredicateContext {
                environment: &predicate_environment,
                context: &context,
                ..neoenv_core::tasks::PredicateContext::empty(&predicate_environment)
            },
        )
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO342",
                format!("job {job:?} has an invalid `if`: {error}"),
            )
        })?
    {
        println!("{job} Skipped");
        return Ok(());
    }

    // A step that runs another task needs that task's *resolved* definition, so the
    // closure is taken for every task the job could reach. Refusing on a dangling
    // `extends:` outside the job is #259's answer and not repeated here.
    let lower = |tasks: &indexmap::IndexMap<String, neoenv_core::tasks::TaskDefinition>| {
        if graph {
            neoenv_core::tasks::lower_jobs(&project.jobs, job, tasks, &context)
        } else {
            neoenv_core::tasks::lower_job(job, definition, tasks)
        }
    };
    let lowered = lower(&project.declared_tasks).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Validation, "NEO341", error.to_string())
    })?;
    // The referenced tasks come from the project's resolved map so a step that runs
    // `build` runs the *merged* `build`, not its declaration.
    let mut tasks = project
        .tasks_for(lowered.task_references(), &context)
        .map_err(|error| error.clone())?;
    for (name, task) in &mut tasks {
        task.execution_grant_required |= project.remote_tasks.contains(name);
    }
    // Lower from resolved bodies, not declarations: inheritance and trust must
    // follow a task when a step gives it a synthetic identity.
    let lowered = lower(&tasks).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Validation, "NEO341", error.to_string())
    })?;
    if graph {
        tasks.clear();
    }
    for (key, definition) in &lowered.tasks {
        if tasks.insert(key.clone(), definition.clone()).is_some() {
            return Err(Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO520",
                format!("lowering job {job:?} produced the key {key:?} twice"),
            ));
        }
    }

    let mut environment = project_environment(project);
    // Job identifiers belong to the graph namespace, not the selected task
    // context. The lowered job bodies retain `context` for their task steps.
    let graph_context = if graph {
        neoenv_core::tasks::DEFAULT_CONTEXT
    } else {
        &context
    };
    run_plan(
        project,
        &mut environment,
        &RunOverrides::default(),
        &[],
        &PlanRun {
            tasks: &tasks,
            root: &lowered.root,
            context: graph_context,
            dry_run,
            capability_policy: None,
            format,
        },
    )
}
