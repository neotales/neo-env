//! `nenv context` — the effective context, and every context the project names.
//!
//! ## Why this command exists
//!
//! The context a task runs under is chosen by a four-step precedence chain, and
//! three of the four steps are invisible. A project that sets `context: prod`, a
//! shell that exports `NEOENV_CONTEXT=staging`, and a command line that says
//! `--context releae` all resolve to *something*, and until now there was no way to
//! ask what. The symptom is a task that runs under the wrong context with nothing
//! to say so.
//!
//! This is the smallest of the six reference commands with no counterpart, and the
//! one with the most data already behind it: `select_context` is the same function
//! the task dispatcher calls, so `context current` and a task's context cannot
//! disagree — which is the whole point of asking here rather than reading a config
//! file and reasoning about it.
//!
//! ## The contract, taken from the reference
//!
//! `context` with no subcommand is `context current`, matching the reference. The
//! error text names every source that could set a context, because a user who typed
//! nothing and got nothing needs to know what to type rather than that it failed.
//!
//! `context list` records **where each name came from** — "Task context",
//! "Dotenv context", "Current context" — rather than printing bare names. That
//! origin is the useful half: two names can be spelled the same way and mean
//! different things, and a list without origins cannot tell a typo from a name
//! that only one source uses.

use neoenv_core::tasks::{select_context, validate_context};
use neoenv_runtime::resolved_config::ResolvedProject;

use crate::{
    Diagnostic,
    cli::{ContextCommand, OutputFormat},
    output::{load_project_with_profile, print_json},
};

/// A context the project names, and where the name came from.
///
/// The origin is not decoration. A context that appears only because a dotenv entry
/// mentions it is exactly the one a user is about to mistype, and a list that shows
/// the name without its origin gives them nothing to check it against.
struct NamedContext {
    name: String,
    origin: &'static str,
}

pub(super) fn dispatch_context(
    command: &ContextCommand,
    cli_context: Option<&str>,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    // The environment is read once, here, rather than in each branch: a command
    // that resolved a context from the command line in one branch and from the
    // environment in another is a command whose two subcommands disagree.
    let environment_context = std::env::var("NEOENV_CONTEXT").ok();
    let requested = cli_context.or(environment_context.as_deref());

    let path = match command {
        ContextCommand::Group { path }
        | ContextCommand::Current { path }
        | ContextCommand::List { path } => path.as_deref(),
    };
    let project = load_project_with_profile(path, profile, requested)?;
    let current = select_context(
        cli_context,
        environment_context.as_deref(),
        project.context.as_deref(),
    );

    // **`nenv context --context releae` must not answer `releae`.** A command whose
    // whole purpose is "which context applies" is the one place a mistyped context
    // has to be caught: every other command either runs under it or fails, and this
    // one would print it back and look like it worked. `validate_context` is the same
    // check the task dispatcher runs, so the two cannot disagree, and the
    // alternatives come from the same set, so a refusal here lists what was meant.
    //
    // Skipped for `list`, which is the command a user runs *because* they do not
    // know which contexts exist. Refusing that would be circular.
    if !matches!(command, ContextCommand::List { .. }) {
        validate_context(
            &project.declared_tasks,
            &project.declared_contexts,
            &current,
        )
        .map_err(|error| crate::task_dispatch::task_error(&error))?;
    }

    match command {
        ContextCommand::Current { .. } | ContextCommand::Group { .. } => match format {
            OutputFormat::Json => print_json(&serde_json::json!({ "context": current })),
            OutputFormat::Text => {
                println!("{current}");
                Ok(())
            }
        },
        ContextCommand::List { .. } => {
            let contexts = declared_contexts(&project);
            match format {
                OutputFormat::Json => {
                    print_json(&serde_json::json!(contexts
                    .iter()
                    .map(|item| serde_json::json!({ "name": item.name, "origin": item.origin }))
                    .collect::<Vec<_>>()))
                }
                OutputFormat::Text => {
                    if contexts.is_empty() {
                        // An empty list is a real answer and prints as one. It is
                        // not a failure and not a header with nothing under it.
                        println!("no contexts are declared by this project");
                        return Ok(());
                    }
                    for item in &contexts {
                        println!("{}\t{}", item.name, item.origin);
                    }
                    Ok(())
                }
            }
        }
    }
}

/// Every context name the project writes, in first-seen order, with its origin.
///
/// Deduplicated by name, keeping the first origin: `declared_contexts` is already
/// deduplicated and ordered upstream, and a name that appears twice in this output
/// is a name the reader has to look up twice.
fn declared_contexts(project: &ResolvedProject) -> Vec<NamedContext> {
    let mut out: Vec<NamedContext> = Vec::new();
    let mut push = |name: &str, origin: &'static str| {
        let trimmed = name.trim();
        // `*` is a filter meaning "every context", not a context anyone can select.
        if trimmed.is_empty() || trimmed == "*" {
            return;
        }
        if out.iter().any(|item| item.name == trimmed) {
            return;
        }
        out.push(NamedContext {
            name: trimmed.to_owned(),
            origin,
        });
    };

    // The project's own `context:` is first, because it is the one that is in
    // effect, and a reader scanning a list wants to see that before the rest.
    if let Some(current) = project.context.as_deref() {
        push(current, "current context");
    }

    // Task keys carry their context after the colon, and that is where most of them
    // come from. `declared_contexts` does **not** include them -- it is collected from
    // `context:` and from the `contexts:` filter on env and dotenv entries, which is
    // the right set for "which context names does this project use" but the wrong one
    // for a list a reader is checking a typo against. A project whose only `dev` is
    // `build:dev` would otherwise report that it has no `dev`.
    // `declared_tasks`, not `tasks()`. A context name harvested out of a task key
    // does not depend on that task's `extends:` resolving, and refusing to list the
    // contexts because an unrelated task names a base that does not exist is not an
    // answer to the question -- it is a different question's failure. #259.
    for key in project.declared_tasks.keys() {
        if let Some((_, context)) = key.split_once(':') {
            push(context, "task variant");
        }
    }
    for name in &project.declared_contexts {
        push(name, "declared by context:, or by an env or dotenv entry");
    }
    out
}

#[cfg(test)]
#[path = "context_commands_tests.rs"]
mod tests;
