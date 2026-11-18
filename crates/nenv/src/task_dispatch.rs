//! Task command dispatch, from planning and capability policy through
//! execution, output rendering, and task diagnostic mapping.

use super::output::print_package_identity;
use super::run_overrides::{apply_dotenv_overrides, project_path};
use super::{
    Diagnostic, DiagnosticCategory, OutputFormat, RunOverrides, TaskCommand, TaskEnvironment,
    TaskInputError, TaskRunOptions, TaskRunnerDirectories, bind_task_inputs, ctrl_c_signal,
    global_tool_data_directory, load_project_with_profile, plan_task, print_json, select_context,
    task_help, validate_context,
};
use neoenv_core::tasks::TaskDefinition;
use neoenv_installer::tools::runtime_install_evidence;
use neoenv_runtime::tasks::ManagedRuntime;

/// Establish a waitable SIGCHLD disposition in the CLI process before it
/// creates task children. This is deliberately CLI-local; the runtime library
/// never changes process-wide signal policy for an embedding application.
#[cfg(unix)]
fn establish_cli_child_policy() -> Result<(), Diagnostic> {
    use std::sync::{Arc, OnceLock, atomic::AtomicBool};
    static CHILD_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    if CHILD_FLAG.get().is_none() {
        let flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGCHLD, Arc::clone(&flag)).map_err(
            |error| {
                Diagnostic::new(
                    DiagnosticCategory::Runtime,
                    "NEO522",
                    format!("failed to establish child wait policy: {error}"),
                )
            },
        )?;
        let _ = CHILD_FLAG.set(flag);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn dispatch_task(
    command: &TaskCommand,
    format: OutputFormat,
    cli_context: Option<&str>,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let path = match command {
        TaskCommand::List { path }
        | TaskCommand::Help { path, .. }
        | TaskCommand::Plan { path, .. }
        | TaskCommand::Run { path, .. } => path.as_deref(),
        TaskCommand::Complete { .. } => None,
    };
    // `run` is the only task command that declares the run-local options, so it
    // is the only one whose `--project` applies.
    let overrides = match command {
        TaskCommand::Run { overrides, .. } => overrides,
        _ => &RunOverrides::default(),
    };
    // Read *before* the project is loaded, and passed in, because a `dotenv:`
    // entry's `contexts:` filter is evaluated while the sources are merged. The
    // command line wins over the environment here for the same reason it does in
    // `select_context` below: one command must not resolve two different worlds.
    let environment_context = std::env::var("NEOENV_CONTEXT").ok();
    let requested_context = cli_context.or(environment_context.as_deref());
    let project =
        load_project_with_profile(project_path(path, overrides), profile, requested_context)?;
    let context = select_context(
        cli_context,
        environment_context.as_deref(),
        project.context.as_deref(),
    );
    // Before the command runs, so `run`, `task run`, `task help`, and `task plan`
    // all reject a mistyped context the same way. The context can come from the
    // command line, from `NEOENV_CONTEXT`, or from the project's own `context:`
    // setting, so a typo in a configuration file is caught here too.
    validate_context(
        &project.declared_tasks,
        &project.declared_contexts,
        &context,
    )
    .map_err(|error| task_error(&error))?;
    match command {
        // **The third answer, and it is the one this bug needed.** `list` neither
        // refuses nor ignores: a project with a dangling `extends:` still has tasks
        // worth naming, and a refusal that hides them is indistinguishable from a
        // project with none. So the declared tasks are listed, the reason
        // inheritance did not resolve is printed to stderr, and the exit status is
        // non-zero.
        //
        // The status is the load-bearing part. Without it, a script reading stdout
        // sees a short list and cannot tell "this project declares three tasks" from
        // "three tasks failed to resolve" -- which is the absence standing in for a
        // failure to produce, and is what the empty `tasks` map would have looked
        // like if this field were public. #259.
        TaskCommand::List { .. } => {
            let unresolved = project.task_error().cloned();
            let listed: Vec<&str> = project
                .declared_tasks
                .iter()
                .filter(|(_, task)| !task.hidden)
                .map(|(name, _)| name.as_str())
                .collect();
            match format {
                OutputFormat::Text => {
                    for name in &listed {
                        println!("{name}");
                    }
                }
                OutputFormat::Json => {
                    // Built as a map rather than through `json!` with an `Option`,
                    // because `json!` serialises `None` as an explicit `null` and the
                    // key is then *always* there. A key that is present on a clean
                    // project means its presence carries no information, and every
                    // consumer has to test the value instead of the key. Absent is
                    // the unambiguous shape, and the first version of this emitted
                    // `null` -- caught by a test that asserted what the comment here
                    // claimed.
                    let mut document = serde_json::Map::new();
                    document.insert("context".to_owned(), serde_json::json!(context));
                    document.insert("tasks".to_owned(), serde_json::json!(listed));
                    if let Some(error) = unresolved.as_ref() {
                        document.insert(
                            "unresolved".to_owned(),
                            serde_json::json!(error.to_string()),
                        );
                    }
                    print_json(&serde_json::Value::Object(document))?;
                }
            }
            if let Some(error) = unresolved {
                eprintln!("nenv: {error}");
                eprintln!(
                    "nenv: the tasks above are as declared; their `extends:` did not resolve."
                );
                std::process::exit(error.exit_category().code());
            }
        }
        TaskCommand::Help { task, .. } => {
            // `tasks_for`, not `tasks()`: help is about the task you named, and a
            // dangling `extends:` in a task three lines away is not your problem.
            let wanted = vec![task.clone()];
            let help = task_help(&project.tasks_for(&wanted, &context)?, task, &context)
                .map_err(|error| task_error(&error))?;
            match format {
                OutputFormat::Text => print!("{}", help.render_text()),
                OutputFormat::Json => print_json(&help)?,
            }
        }
        TaskCommand::Plan { task, .. } => {
            let wanted = vec![task.clone()];
            let plan = plan_task(&project.tasks_for(&wanted, &context)?, task, &context)
                .map_err(|error| task_error(&error))?;
            match format {
                OutputFormat::Text => {
                    for task in &plan.tasks {
                        println!("{} {:?}", task.name, task.outcome);
                        print_package_identity(task.package.as_ref());
                    }
                }
                OutputFormat::Json => print_json(&plan)?,
            }
        }
        TaskCommand::Complete { task } => {
            let candidates = match task {
                // Names only, so `declared_tasks`: completing a task name does not
                // need that task's `extends:` to resolve, and a shell completion
                // that returns nothing because an unrelated task is broken is a
                // completion that silently stops working. #259.
                None => project
                    .declared_tasks
                    .iter()
                    .filter(|(_, task)| !task.hidden)
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>(),
                Some(task) => task_help(
                    &project.tasks_for(std::slice::from_ref(task), &context)?,
                    task,
                    &context,
                )
                .map(|help| {
                    help.parameters
                        .iter()
                        .flat_map(|parameter| {
                            let mut values = Vec::new();
                            if let Some(long) = &parameter.long {
                                values.push(format!("--{long}"));
                                if parameter.parameter_type
                                    == neoenv_core::tasks::TaskParameterType::Boolean
                                {
                                    values.push(format!("--no-{long}"));
                                }
                            }
                            if let Some(short) = parameter.short {
                                values.push(format!("-{short}"));
                            }
                            values
                        })
                        .chain(std::iter::once("--".into()))
                        .collect::<Vec<_>>()
                })
                .map_err(|error| task_error(&error))?,
            };
            match format {
                OutputFormat::Text => {
                    for candidate in candidates {
                        println!("{candidate}");
                    }
                }
                OutputFormat::Json => print_json(&serde_json::json!({ "candidates": candidates }))?,
            }
        }
        TaskCommand::Run {
            task,
            dry_run,
            capability_policy,
            passthrough,
            overrides,
            ..
        } => {
            // A dry run reports a plan and takes no effect, so it is readable
            // before approval; every real run needs the root and the selected
            // graph trusted first.
            if !*dry_run {
                super::output::require_execution_trust(&project)?;
            }
            // The closure is bound to a name because `PlanRun` borrows it and the
            // temporary would not outlive the call.
            let planned = project.tasks_for(std::slice::from_ref(task), &context)?;
            let mut environment = project_environment(&project);
            run_plan(
                &project,
                &mut environment,
                overrides,
                passthrough,
                &PlanRun {
                    tasks: &planned,
                    root: task,
                    context: &context,
                    dry_run: *dry_run,
                    capability_policy: capability_policy.as_deref(),
                    format,
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn task_cancellation() -> Result<neoenv_runtime::tasks::TaskCancellation, Diagnostic> {
    let signal = ctrl_c_signal().map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO330",
            format!("failed to install task cancellation handler: {error}"),
        )
    })?;
    Ok(neoenv_runtime::tasks::TaskCancellation::from_shared(signal))
}

pub(super) fn task_error(error: &neoenv_core::tasks::TaskError) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO321", error.to_string())
}

pub(super) fn task_input_error(error: &TaskInputError) -> Diagnostic {
    let category = match error {
        TaskInputError::Task(_) => DiagnosticCategory::Validation,
        _ => DiagnosticCategory::Usage,
    };
    Diagnostic::new(category, "NEO322", error.to_string())
}

pub(super) fn task_run_error(error: &neoenv_runtime::tasks::TaskRunError) -> Diagnostic {
    match error {
        neoenv_runtime::tasks::TaskRunError::CapabilityDenied { policy_source, .. } => {
            let diagnostic =
                Diagnostic::new(DiagnosticCategory::Trust, "NEO331", error.to_string())
                    .with_cause(error.clone());
            policy_source.as_ref().map_or(diagnostic.clone(), |path| {
                diagnostic.at(neoenv_core::SourceSpan::new(
                    path.display().to_string(),
                    1,
                    1,
                ))
            })
        }
        neoenv_runtime::tasks::TaskRunError::InvalidCapability { .. }
        | neoenv_runtime::tasks::TaskRunError::Planning(_)
        | neoenv_runtime::tasks::TaskRunError::PlanningSource { .. }
        | neoenv_runtime::tasks::TaskRunError::IoSource { .. } => {
            Diagnostic::new(DiagnosticCategory::Validation, "NEO330", error.to_string())
                .with_cause(error.clone())
        }
    }
}

pub(super) fn capability_policy_error(
    error: &neoenv_runtime::policy::CapabilityPolicyError,
) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Trust, "NEO331", error.to_string())
        .with_cause(error.clone())
}

/// The project's environment as plain `KEY=VALUE` strings.
///
/// A named function because two commands need it and it is four lines that look
/// like they could be written two ways. The `secret` flag is deliberately **not**
/// consulted: a redacted value is a rendering decision made by `inspect`, and
/// dropping a declared secret from the environment a task actually runs with would
/// be a different and much worse decision.
pub(super) fn project_environment(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
) -> indexmap::IndexMap<String, String> {
    project
        .environment
        .iter()
        .map(|(key, entry)| (key.clone(), entry.value.clone()))
        .collect()
}

/// What to run, for the one place that runs a plan.
///
/// An options struct rather than seven parameters, because `task run` and `job run`
/// both need it and a positional list this long is a list someone reorders wrong.
/// It lives in one place so the two commands cannot build different options -- the
/// alternative is two copies of a capability-policy path and a cancellation token,
/// which is how a dry run starts behaving differently depending on which command
/// asked for it.
pub(super) struct PlanRun<'a> {
    /// The tasks the plan is planned from. A closure of the requested task, not the
    /// whole map: a dangling `extends:` in a task outside the plan stays outside it.
    pub tasks: &'a indexmap::IndexMap<String, TaskDefinition>,
    /// The key the plan starts from.
    pub root: &'a str,
    pub context: &'a str,
    pub dry_run: bool,
    /// `None` means the user's policy file, which is the default rather than a
    /// different policy.
    pub capability_policy: Option<&'a str>,
    pub format: OutputFormat,
}

/// The managed installs a versioned runner may select, by directory label.
///
/// `runtime_install_evidence` requires a real receipt with a well-formed digest
/// and a contained executable, not merely a receipt file. The version is the
/// directory label and the digest is only shape-checked; there is no
/// provenance signature. An unreadable data directory contributes nothing, so a
/// non-uv project is unaffected and a `uv@<version>` request fails closed. The
/// receipt is self-attesting, so execution additionally needs an execute grant;
/// the runtime's capability pass enforces that.
fn selected_managed_runtimes() -> Vec<ManagedRuntime> {
    global_tool_data_directory(crate::GlobalScope::User)
        .map(|root| runtime_install_evidence(&root))
        .unwrap_or_default()
        .into_iter()
        .map(|runtime| ManagedRuntime {
            id: runtime.id,
            version: runtime.version,
            root: runtime.root,
            bin_dir: runtime.bin_dir,
            binary: runtime.binary,
            receipt: runtime.receipt,
            digest: runtime.digest,
            root_identity: runtime.root_identity,
            binary_identity: runtime.binary_identity,
        })
        .collect()
}

/// Runs one plan and prints its report, then fails if anything did not succeed.
///
/// Shared by `task run` and `job run` so the options, the capability grants, the
/// cancellation token and the reporting are built once. `environment` is taken
/// mutably because `-E` dotenv overrides are applied here, after the project's own
/// environment and before PATH activation -- the same order for both commands.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_plan(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    environment: &mut indexmap::IndexMap<String, String>,
    overrides: &RunOverrides,
    passthrough: &[String],
    run: &PlanRun<'_>,
) -> Result<(), Diagnostic> {
    #[cfg(unix)]
    establish_cli_child_policy()?;
    let bound_inputs = bind_task_inputs(run.tasks, run.root, run.context, passthrough)
        .map_err(|error| task_input_error(&error))?;
    // The declaration set is cheap and touches no vault. Resolution is deferred
    // to `apply_task_environment`, which builds the final task environment and
    // knows which values are effective after task `env:`, task `dotenv:`, and
    // `-e`. Resolving here would fetch a project value that a later override
    // replaces, which is both unnecessary and a failure when the replaced vault
    // is unavailable.
    let vaults = neoenv_runtime::vault::VaultSet::from_project(project);
    // `-E` applies below PATH/tool activation so a dotenv file cannot undo a
    // prepended tool directory; `-e` is handed to the runtime so it lands after
    // activation and wins.
    let _dotenv_assignments = apply_dotenv_overrides(environment, &overrides.dotenv)?;
    let env_overrides: indexmap::IndexMap<String, String> = overrides.env.iter().cloned().collect();
    let cancellation = task_cancellation()?;
    let managed_runtimes = selected_managed_runtimes();
    let policy_path = run
        .capability_policy
        .map_or_else(neoenv_runtime::policy::capability_policy_path, |path| {
            Ok(std::path::PathBuf::from(path))
        })
        .map_err(|error| capability_policy_error(&error))?;
    let grants = neoenv_runtime::policy::load_capability_grants(&policy_path)
        .map_err(|error| capability_policy_error(&error))?;
    let ssh_secret_values = project
        .environment
        .values()
        .filter(|entry| entry.secret)
        .map(|entry| entry.value.as_str())
        .collect::<Vec<_>>();
    let inventories = if plan_task(run.tasks, run.root, run.context)
        .map_err(|error| task_error(&error))?
        .tasks
        .iter()
        .any(|planned| {
            run.tasks
                .get(&planned.name)
                .and_then(|task| task.action.as_ref())
                .is_some_and(|action| action.uses.as_deref() == Some("ssh"))
        }) {
        Some(project.inventories()?)
    } else {
        None
    };
    #[cfg(any(target_os = "linux", windows))]
    let owned_backend = std::env::current_exe().ok();
    #[cfg(not(any(target_os = "linux", windows)))]
    let owned_backend: Option<std::path::PathBuf> = None;
    let report = neoenv_runtime::tasks::run_tasks_with_cancellation(
        run.tasks,
        run.root,
        run.context,
        &project.project.project_root,
        TaskEnvironment {
            values: environment,
            path_operations: &project.path,
            overrides: (!env_overrides.is_empty()).then_some(&env_overrides),
        },
        &bound_inputs.passthrough,
        TaskRunOptions {
            ssh_output_to_stderr: run.format == OutputFormat::Json,
            ssh_secret_values: &ssh_secret_values,
            inventories: inventories.as_ref(),
            dry_run: run.dry_run,
            cancellation: &cancellation,
            capability_grants: Some(&grants),
            capability_policy_source: Some(&policy_path),
            remote_tasks: Some(&project.remote_tasks),
            task_directories: TaskRunnerDirectories {
                local: &project.task_dirs.local,
                global: &project.task_dirs.global,
            },
            managed_runtimes: &managed_runtimes,
            input_values: Some(&bound_inputs.values),
            // A dry run never resolves a secret, not even for a predicate. The
            // plan reports what would run without opening a vault.
            vaults: (!run.dry_run).then_some(&vaults),
            owned_backend: owned_backend
                .as_deref()
                .map(neoenv_runtime::tasks::CooperativeOwnedBackend::with_exclusive_child_waits),
        },
    )
    .map_err(|error| task_run_error(&error))?;
    match run.format {
        OutputFormat::Text => {
            for task in &report.tasks {
                println!("{} {:?}", task.name, task.outcome);
                print_package_identity(task.package.as_ref());
                if let Some(message) = &task.message {
                    eprintln!("nenv: {message}");
                }
            }
        }
        OutputFormat::Json => print_json(&report)?,
    }
    if report.tasks.iter().any(|task| {
        task.outcome != neoenv_core::tasks::TaskOutcome::Succeeded
            && task.outcome != neoenv_core::tasks::TaskOutcome::Planned
            && task.outcome != neoenv_core::tasks::TaskOutcome::Conditional
            && task.outcome != neoenv_core::tasks::TaskOutcome::Skipped
    }) {
        return Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO330",
            "one or more tasks did not succeed",
        ));
    }
    Ok(())
}
