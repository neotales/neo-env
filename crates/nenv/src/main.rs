mod cli;
mod command_tree;
mod completion;
mod config_commands;
mod context_commands;
mod global_install;
mod inventory_commands;
mod job_commands;
mod output;
mod project_commands;
mod run_overrides;
mod runtime_commands;
mod secret_commands;
mod ship_commands;
mod task_dispatch;
#[cfg(unix)]
mod task_supervisor;
mod tool_dispatch;
mod tool_lifecycle;
mod workspace_commands;

// The two lists below are the crate-root view of `global_install`. `app_tests`
// reaches these `pub(super)` items through `super::`, so dropping one breaks the
// test build rather than failing at the definition site. The supervisor
// internals are test-only and listed separately so the release build does not
// carry an unused-import warning.
#[cfg(test)]
use global_install::{
    GlobalInstallEvent, GlobalProviderEnvironment, catch_global_install_panic,
    parse_global_tool_request_with_environment, record_global_tools_at, supervise_global_installs,
};
use global_install::{
    GlobalScope, GlobalToolInstallation, GlobalToolRequest, cleanup_new_global_installations,
    command_spec, ctrl_c_signal, global_install_cancellation, global_install_cancelled,
    global_tool_and_version, global_tool_config_path, global_tool_data_directory,
    global_tool_data_root, global_tool_storage, install_global_tools,
    install_global_tools_transaction, parse_global_tool_request, parse_global_use,
    print_global_use_preview, read_global_tool_document, record_global_tools, remove_global_path,
    safe_global_lock_name, split_global_key_version, state_file_diagnostic, use_command_spec,
    write_locked_state,
};
use output::{
    load_project, load_project_with_profile, print_error, print_help, print_inspection_text,
    print_json,
};
use project_commands::{dispatch_remote, dispatch_trust, initialize_project};
use run_overrides::{apply_dotenv_overrides, apply_env_overrides, project_path};
use task_dispatch::dispatch_task;
use tool_dispatch::dispatch_tool;
use workspace_commands::dispatch_workspace;

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use cli::{
    Command, ContextCommand, Invocation, JobCommand, OutputFormat, RemoteCommand, RunOverrides,
    RuntimeCommand, SelfCommand, ShipCommand, TaskCommand, ToolCommand, ToolScope, TrustCommand,
    WorkspaceCommand, parse,
};
use command_tree::{CommandAction, CommandSpec, OptionId, ROOT};
use neoenv_core::tasks::{
    TaskInputError, bind_task_inputs, plan_task, select_context, task_help, validate_context,
};
use neoenv_core::tools::{
    DotnetToolDeclaration, GithubReleaseDeclaration, NpmDeclaration, Platform, RubyGemsDeclaration,
    ToolDeclaration, ToolProvider, plan_tools,
};
use neoenv_core::{Diagnostic, DiagnosticCategory, ExitCategory, SourceSpan};
use neoenv_installer::{
    activation::{activation_diff, activation_diff_with, inherited_environment, invalid_key},
    tools::{
        BunRuntimeProgress, DenoRuntimeProgress, DotnetSdkProgress, GoSdkProgress,
        JavaRuntimeProgress, NodeRuntimeProgress, OdinRuntimeProgress, PythonRuntimeProgress,
        RustRuntimeProgress, ToolStorage, UvRuntimeProgress, ZigRuntimeProgress,
        bun_binary_directory, cleanup_stale_temporaries_in, cleanup_unreferenced,
        install_bun_runtime_with_progress, install_deno_runtime_with_progress,
        install_dotnet_sdk_with_progress, install_go_sdk_with_progress,
        install_java_runtime_with_progress, install_locked_tools, install_locked_tools_in,
        install_node_runtime_with_progress, install_odin_runtime_with_progress,
        install_python_runtime_with_progress, install_rust_runtime_with_progress,
        install_uv_runtime_with_progress, install_zig_runtime_with_progress, installed_runtimes,
        java_home_directory, lockfile_path, read_lockfile, resolve_bun_runtime,
        resolve_deno_runtime, resolve_dotnet_sdk, resolve_go_sdk, resolve_java_runtime,
        resolve_node_runtime, resolve_odin_runtime, resolve_python_runtime, resolve_rust_runtime,
        resolve_tools, resolve_uv_runtime, resolve_zig_runtime, tool_states, tool_states_in,
        verify_lockfile, which_installed, which_installed_in, write_lockfile,
    },
};
use neoenv_runtime::remote::{
    RemoteModule, clear_module_cache, fetch_module_with_cancellation, trust_path, trust_project,
    trust_repository, trusted_repositories, untrust_repository,
};
use neoenv_runtime::{
    budget::{ResourceBudget, read_text_file},
    paths::{UserDirectory, system_directory},
    resolved_config::load_project_or_workspace_alias_with_profile,
    state_file::{self, LockedStateFile, StateFileError},
    tasks::{TaskEnvironment, TaskRunOptions, TaskRunnerDirectories},
};

fn main() {
    #[cfg(unix)]
    if std::env::args_os()
        .skip(1)
        .eq([task_supervisor::ANCHOR_MODE])
    {
        std::process::exit(task_supervisor::run_anchor());
    }
    #[cfg(unix)]
    if std::env::args_os().skip(1).eq([task_supervisor::MODE]) {
        std::process::exit(task_supervisor::run(false));
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .skip(1)
        .eq([task_supervisor::MANAGED_MODE])
    {
        std::process::exit(task_supervisor::run(true));
    }
    match parse(std::env::args().skip(1)) {
        Ok(invocation) => {
            // Recorded once, here, so every loader in the process reads the
            // profile the user asked for. Threading it through each call site
            // instead is how a *missed* site becomes a command that accepts
            // `--profile` and quietly ignores it.
            neoenv_config::ConfigProfile::set_process_profile(invocation.profile);
            if let Err(error) = dispatch(&invocation) {
                print_error(invocation.format, &error);
                std::process::exit(error.exit_category().code());
            }
        }
        Err(error) => {
            print_error(OutputFormat::Text, &error);
            std::process::exit(error.exit_category().code());
        }
    }
}

// The dispatch is one arm per `Command`, and the length is the vocabulary's size
// rather than this function's complexity. A table of closures would lose the
// exhaustiveness that makes a new command a compile error here, which is the
// property the whole match exists for.
#[allow(clippy::too_many_lines)]
/// The project path a `job` subcommand was given, whichever verb it was.
///
/// A named function because the four verbs each carry one and the match is repeated
/// at the call site otherwise -- and a second copy of that match is a second place
/// for a new verb to be forgotten.
/// The project path a `ship` subcommand was given, whichever verb it was.
fn ship_path(command: &ShipCommand) -> Option<&str> {
    match command {
        ShipCommand::Group { path }
        | ShipCommand::List { path }
        | ShipCommand::Lifecycle { path, .. }
        | ShipCommand::Other { path, .. } => path.as_deref(),
    }
}

fn job_path(command: &JobCommand) -> Option<&str> {
    match command {
        JobCommand::Group { path }
        | JobCommand::List { path }
        | JobCommand::Help { path, .. }
        | JobCommand::Run { path, .. } => path.as_deref(),
    }
}

// The dispatch is one arm per `Command`, and the length is the vocabulary's size
// rather than this function's complexity. A table of closures would lose the
// exhaustiveness that makes a new command a compile error here, which is the
// property the whole match exists for.
#[allow(clippy::too_many_lines)]
fn dispatch(invocation: &Invocation) -> Result<(), Diagnostic> {
    match &invocation.command {
        Command::Help { command } => {
            print_help(command);
            Ok(())
        }
        Command::HelpError {
            command,
            diagnostic,
        } => {
            if invocation.format == OutputFormat::Text {
                print_help(command);
            }
            Err(diagnostic.clone())
        }
        Command::Version => {
            println!("nenv {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Shortcut {
            name,
            arguments,
            builtin,
        } => dispatch_shortcut(name, arguments, builtin, invocation),
        Command::TaskShortcut { task, arguments } => {
            dispatch_task_shortcut(task, arguments, invocation)
        }
        Command::Self_ { command } => dispatch_self(command, invocation.format),
        Command::Validate { path } => dispatch_validate(path.as_deref(), invocation),
        Command::Inspect { path } => dispatch_inspect(path.as_deref(), invocation),
        Command::Exec { command, overrides } => {
            let spec = command_spec(CommandAction::Exec)?;
            if invocation.format == OutputFormat::Json && !spec.output.json {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "exec only supports text output because it streams the command's output",
                ));
            }
            execute_project_command(command, overrides, invocation.profile)
        }
        Command::Task { command } => dispatch_task(
            command,
            invocation.format,
            invocation.context.as_deref(),
            invocation.profile,
        ),
        Command::Tool { command } => dispatch_tool(command, invocation.format),
        Command::Shell { shell, path } => {
            let spec = command_spec(CommandAction::ShellActivate)?;
            if invocation.format == OutputFormat::Json && !spec.output.json {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "shell activation only supports text output",
                ));
            }
            let shell = neotales_env::Shell::parse(shell).ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    format!("unsupported shell: {shell}"),
                )
            })?;
            let mut project = load_project_with_profile(path.as_deref(), invocation.profile, None)?;
            crate::output::require_execution_trust(&project)?;
            // Shell activation is a consumption point: every project `env:` value
            // is rendered into the user's shell here, so this is where a lazy
            // `nsv://` reference becomes a value. `inspect` and `validate` never
            // call this.
            let vaults = neoenv_runtime::vault::VaultSet::from_project(&project);
            let inherited: BTreeMap<String, String> = inherited_environment().into_iter().collect();
            vaults
                .resolve_project_environment(&mut project, &inherited)
                .map_err(|error| error.to_diagnostic())?;
            println!(
                "{}",
                invalid_key(
                    activation_diff(&project),
                    &project.project.configuration_path
                )?
                .render(shell)
            );
            Ok(())
        }
        Command::Trust { command } => {
            dispatch_trust(command, invocation.format, invocation.profile)
        }
        Command::Workspace { command } => dispatch_workspace_command(command, invocation),
        Command::Context { command } => dispatch_context_command(command, invocation),
        Command::Ship { command } => ship_commands::dispatch_ship(
            command,
            ship_path(command),
            invocation.format,
            invocation.context.as_deref(),
            invocation.profile,
        ),
        Command::Inventory { command } => inventory_commands::dispatch_inventory(
            command,
            invocation.format,
            invocation.context.as_deref(),
            invocation.profile,
        ),
        Command::Job { command } => job_commands::dispatch_job(
            command,
            job_path(command),
            invocation.format,
            invocation.profile,
            invocation.context.as_deref(),
        ),
        Command::Config { command } => {
            config_commands::dispatch_config(command, invocation.format, invocation.profile)
        }
        Command::Runtime { command } => dispatch_runtime_command(command, invocation),
        Command::Secret { command } => {
            secret_commands::dispatch_secret(command, invocation.format, invocation.profile)
        }
        Command::Remote { command } => dispatch_remote(command, invocation.format),
        Command::Completion { shell } => {
            let spec = command_spec(CommandAction::Completion)?;
            if invocation.format == OutputFormat::Json && !spec.output.json {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "completion only supports text output",
                ));
            }
            print!("{}", completion::generate(shell)?);
            Ok(())
        }
    }
}

fn dispatch_task_shortcut(
    task: &str,
    arguments: &[String],
    invocation: &Invocation,
) -> Result<(), Diagnostic> {
    let command = TaskCommand::Run {
        task: task.into(),
        path: None,
        dry_run: false,
        capability_policy: None,
        passthrough: arguments.to_vec(),
        overrides: RunOverrides::default(),
    };
    dispatch_task(
        &command,
        invocation.format,
        invocation.context.as_deref(),
        invocation.profile,
    )
    .map_err(|error| {
        if error.exit_category() == ExitCategory::NotFound {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO401",
                format!(
                    "task shortcut `{task}` could not be run because no nenv configuration was found; run `nenv init`, or use `nenv --help` to see built-in commands"
                ),
            )
        } else if error.message.starts_with(&format!("task {task} was not found")) {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO321",
                format!(
                    "task shortcut `{task}` was not found; run `nenv task list` to see available tasks, or `nenv --help` for built-in commands"
                ),
            )
        } else {
            error
        }
    })
}

/// `validate` is the read-only check a Go document is migrated with, so it takes
/// the invocation rather than a format and a profile it would be handed anyway.
fn dispatch_validate(path: Option<&str>, invocation: &Invocation) -> Result<(), Diagnostic> {
    let project = load_project_with_profile(path, invocation.profile, None)?;
    // **The one command that refuses**, of the four answers. Naming project-wide
    // problems is what `validate` is for, so a dangling `extends:` -- which makes
    // every task in the project unresolvable -- is a finding, and refusing before
    // printing "valid" is the only honest ordering. Every other command has a
    // narrower job and must not be taken down by this. #259.
    if let Some(error) = project.task_error() {
        return Err(error.clone());
    }
    match invocation.format {
        OutputFormat::Text => {
            println!("valid: {}", project.project.configuration_path.display());
        }
        OutputFormat::Json => print_json(&project.validation_document())?,
    }
    Ok(())
}

fn dispatch_inspect(path: Option<&str>, invocation: &Invocation) -> Result<(), Diagnostic> {
    let project = load_project_with_profile(path, invocation.profile, None)?;
    let unresolved = project.task_error().cloned();
    // The document lists the *declared* tasks when inheritance did not resolve, so
    // `tasks` is never empty for a project that has some. The failure goes to stderr
    // and the exit status is non-zero, so the document and the status together are
    // unambiguous: a document with tasks and a zero status means they resolved.
    //
    // stderr rather than into the document because `inspection-v2.schema.json` is a
    // published contract -- an `unresolved` key would change what every consumer of
    // `inspect --format json` sees, to fix a problem that a stderr line and an exit
    // code already fix. #259.
    let document = project.inspection_document();
    match invocation.format {
        OutputFormat::Text => print_inspection_text(&document),
        OutputFormat::Json => print_json(&document)?,
    }
    if let Some(error) = unresolved {
        eprintln!("nenv: {error}");
        eprintln!("nenv: the tasks above are as declared; their `extends:` did not resolve.");
        return Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Validation,
            "NEO320",
            format!(
                "{} task(s) could not be resolved; see above",
                document.tasks.len()
            ),
        ));
    }
    Ok(())
}

/// `workspace` reads the workspace document, so it takes the whole invocation
/// rather than a format and a profile it would otherwise have to be handed.
/// Answers "which context would a task run under", and "what contexts exist".
///
/// A thin wrapper over the implementation, taking the whole `Invocation`, so the
/// five things a context needs -- the project path, the `--context` override, the
/// dotenv overrides, the output format, and the config profile -- are gathered in
/// one place instead of five call sites. A query command that read its inputs from
/// a slightly different set than its neighbours is a query command whose answer
/// can differ from the thing it is reporting on.
fn dispatch_context_command(
    command: &ContextCommand,
    invocation: &Invocation,
) -> Result<(), Diagnostic> {
    context_commands::dispatch_context(
        command,
        invocation.context.as_deref(),
        invocation.format,
        invocation.profile,
    )
}

fn dispatch_workspace_command(
    command: &WorkspaceCommand,
    invocation: &Invocation,
) -> Result<(), Diagnostic> {
    dispatch_workspace(command, invocation.format, invocation.profile)
}

fn dispatch_runtime_command(
    command: &RuntimeCommand,
    invocation: &Invocation,
) -> Result<(), Diagnostic> {
    runtime_commands::dispatch_runtime(command, invocation.format)
}

fn execute_project_command(
    command: &[String],
    overrides: &RunOverrides,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let project = load_project_with_profile(project_path(None, overrides), profile, None)?;
    crate::output::require_execution_trust(&project)?;
    let environment = activated_project_environment(&project, &overrides.dotenv, &overrides.env)?;
    let program = resolve_exec_program(&project, &command[0])?;
    let status = ProcessCommand::new(&program)
        .args(&command[1..])
        .current_dir(process_working_directory(&project.project.project_root))
        .env_clear()
        .envs(environment)
        .status()
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                format!("failed to start {}: {error}", program.display()),
            )
        })?;
    if status.success() {
        return Ok(());
    }
    Err(Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO522",
        format!("command {} exited with {status}", program.display()),
    ))
}

fn resolve_exec_program(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    requested: &str,
) -> Result<PathBuf, Diagnostic> {
    // Explicit paths are intentional user selections, not PATH fallback.
    if requested.contains(['/', '\\']) {
        return Ok(PathBuf::from(requested));
    }
    for candidate in executable_candidates(requested) {
        if let Some(path) = tool_dispatch::resolve_project_tool_for_exec(project, &candidate)? {
            return Ok(path);
        }
        if let Some(path) =
            tool_dispatch::globally_selected_native_executable(&candidate, GlobalScope::User)?
        {
            return Ok(path);
        }
        if let Some(path) =
            tool_dispatch::globally_selected_native_executable(&candidate, GlobalScope::System)?
        {
            return Ok(path);
        }
    }
    Ok(PathBuf::from(requested))
}

#[cfg(windows)]
fn executable_candidates(requested: &str) -> Vec<String> {
    let mut candidates = vec![requested.to_owned()];
    if Path::new(requested).extension().is_none() {
        candidates.extend([".exe", ".cmd", ".bat"].map(|suffix| format!("{requested}{suffix}")));
    }
    candidates
}

#[cfg(windows)]
fn process_working_directory(project_root: &Path) -> PathBuf {
    project_root
        .display()
        .to_string()
        .strip_prefix(r"\\?\")
        .map_or_else(|| project_root.to_owned(), PathBuf::from)
}

#[cfg(not(windows))]
fn process_working_directory(project_root: &Path) -> PathBuf {
    project_root.to_owned()
}

#[cfg(not(windows))]
fn executable_candidates(requested: &str) -> Vec<String> {
    vec![requested.to_owned()]
}

/// Builds the child environment for `exec`.
///
/// `-E` is applied *after* the activation diff so its `${NAME}` references
/// resolve against the resolved project environment, the same base a declared
/// dotenv import gets. `-e` is applied after that, so `-e PATH=...` is the last
/// word on both `run` and `exec`.
///
/// One deliberate divergence from `run`: `run` applies `-E` before the declared
/// `PATH` operations, so a dotenv file cannot undo a prepended tool directory,
/// while here it can. Applying `-E` after the diff is what makes project
/// interpolation work, and `-e PATH=...` remains the way to override `PATH`
/// either way.
///
/// `NEOENV_PROJECT` and `NEOENV_ROOT` are inserted before the overrides here, so
/// `-e` can replace them. The task engine inserts its own `NEOENV_ENV`,
/// `NEOENV_PATH`, and `NEOENV_OUTPUTS` after the overrides, so those three are
/// not overridable on either command.
fn activated_project_environment(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    dotenv: &[String],
    env: &[(String, String)],
) -> Result<indexmap::IndexMap<String, String>, Diagnostic> {
    // Resolution is deliberately *after* activation and after `-E`/`-e`. A
    // project value that a command-line override replaces is never fetched, and
    // a reference interpolates against the final effective values rather than
    // the process environment.
    let vaults = neoenv_runtime::vault::VaultSet::from_project(project);
    let mut inherited = inherited_environment();
    normalize_windows_path_key(&mut inherited);
    // **Runtimes reach the shell here, and nowhere else did before.** An installed Go,
    // Node, Python, uv, Deno, Zig, Rust or .NET lands in nenv's global data directory
    // and is contributed to `PATH` along with the variables it needs (`GOROOT`,
    // `DOTNET_ROOT`, `RUSTUP_HOME`/`CARGO_HOME`). Without this the runtime is installed
    // and not runnable, and nothing in the tree said so.
    //
    // **A data directory that cannot be resolved or read contributes nothing** rather than
    // failing. Not finding installed runtimes is the normal state of a machine that has
    // not run `nenv global install`, and turning that into a diagnostic would make
    // every task fail on such a machine — which is strictly worse than the behaviour this
    // replaces, where runtimes were never contributed at all.
    // System runtimes first, then per-user runtimes: `runtime_diff` writes in
    // order and the last write wins, so a user's runtime overrides the system one.
    let mut runtimes = installed_runtimes(&global_tool_data_directory(GlobalScope::System)?);
    runtimes.extend(installed_runtimes(&global_tool_data_directory(
        GlobalScope::User,
    )?));
    let mut environment = invalid_key(
        activation_diff_with(project, &runtimes),
        &project.project.configuration_path,
    )?
    .apply(&inherited);
    environment.insert(
        "NEOENV_PROJECT".into(),
        project.project.configuration_path.display().to_string(),
    );
    environment.insert(
        "NEOENV_ROOT".into(),
        project.project.project_root.display().to_string(),
    );
    add_windows_git_utilities_to_exec_environment(&mut environment);
    let dotenv_assignments = apply_dotenv_overrides(&mut environment, dotenv)?;
    apply_env_overrides(&mut environment, env);
    // **Ownership is explicit.** The scope is the project's declared keys plus
    // the keys the command line actually supplied, even when a supplied value is
    // byte-for-byte equal to the inherited one. The context is the whole final
    // effective environment, so an explicitly named inherited input such as
    // `${HOME}` works and project/CLI precedence is already settled. An unrelated
    // inherited value containing `nsv://` is outside the scope and is not scanned.
    let mut scope: std::collections::BTreeSet<String> =
        project.environment.keys().cloned().collect();
    scope.extend(dotenv_assignments.keys().cloned());
    scope.extend(env.iter().map(|(key, _)| key.clone()));
    let context: BTreeMap<String, String> = environment
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    vaults
        .resolve_ordered_environment(&mut environment, &scope, &context)
        .map_err(|error| error.to_diagnostic())?;
    Ok(environment)
}

#[cfg(windows)]
fn normalize_windows_path_key(environment: &mut indexmap::IndexMap<String, String>) {
    let existing = environment
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map(|(key, value)| (key.clone(), value.clone()));
    if let Some((key, value)) = existing {
        environment.shift_remove(&key);
        environment.retain(|key, _| !key.eq_ignore_ascii_case("PATH"));
        environment.insert("PATH".into(), value);
    }
}

#[cfg(not(windows))]
fn normalize_windows_path_key(_environment: &mut indexmap::IndexMap<String, String>) {}

#[cfg(windows)]
fn add_windows_git_utilities_to_exec_environment(
    environment: &mut indexmap::IndexMap<String, String>,
) {
    let directories = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .map(|directory| directory.join("Git").join("usr").join("bin"))
        .filter(|directory| directory.is_dir())
        .map(|directory| directory.display().to_string())
        .collect::<Vec<_>>();
    if directories.is_empty() {
        return;
    }
    let existing = environment.get("PATH").map(String::as_str);
    environment.insert(
        "PATH".into(),
        neotales_env::path_append(existing, &directories, neotales_env::Platform::host()),
    );
}

#[cfg(not(windows))]
fn add_windows_git_utilities_to_exec_environment(
    _environment: &mut indexmap::IndexMap<String, String>,
) {
}

fn dispatch_shortcut(
    name: &str,
    arguments: &[String],
    builtin: &SelfCommand,
    invocation: &Invocation,
) -> Result<(), Diagnostic> {
    match load_project_with_profile(None, invocation.profile, None) {
        Ok(project) if project.declared_tasks.contains_key(name) => dispatch_task(
            &TaskCommand::Run {
                task: name.into(),
                path: None,
                dry_run: false,
                capability_policy: None,
                passthrough: arguments.to_vec(),
                overrides: RunOverrides::default(),
            },
            invocation.format,
            invocation.context.as_deref(),
            invocation.profile,
        ),
        Ok(_)
        | Err(Diagnostic {
            category: DiagnosticCategory::NotFound,
            ..
        }) => {
            if matches!(builtin, SelfCommand::Init) && !arguments.is_empty() {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    format!("unexpected argument for init: {}", arguments[0]),
                ));
            }
            let builtin = match builtin {
                SelfCommand::Init => SelfCommand::Init,
                SelfCommand::Use { .. } => SelfCommand::Use {
                    arguments: arguments.to_vec(),
                },
            };
            dispatch_self(&builtin, invocation.format)
        }
        Err(error) => Err(error),
    }
}

fn dispatch_self(command: &SelfCommand, format: OutputFormat) -> Result<(), Diagnostic> {
    match command {
        SelfCommand::Init => initialize_project(format),
        SelfCommand::Use { arguments } => run_native_use(arguments, format),
    }
}

fn run_native_use(arguments: &[String], format: OutputFormat) -> Result<(), Diagnostic> {
    let use_command = use_command_spec()?;
    if format == OutputFormat::Json && !use_command.output.json {
        return Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "use only supports text output",
        ));
    }

    let request = parse_global_use(arguments)?;
    if request.dry_run {
        print_global_use_preview(&request.tools, request.scope)?;
        return Ok(());
    }
    install_global_tools(&request.tools, request.scope)
}

#[cfg(test)]
mod app_tests;
