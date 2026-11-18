//! Argument parsing driven entirely by the shared command tree. The parser
//! holds no command semantics of its own; every accepted spelling, option,
//! and arity rule comes from `command_tree`.

use super::{
    Command, CommandAction, CommandOption, CommandSpec, ConfigCommand, ContextCommand, Diagnostic,
    DiagnosticCategory, InventoryCommand, Invocation, JobCommand, OptionId, OutputFormat, Path,
    ROOT, RemoteCommand, RunOverrides, RuntimeCommand, SecretCommand, SelfCommand, ShipCommand,
    TaskCommand, ToolCommand, ToolScope, TrustCommand, WorkspaceCommand,
};

/// The task `nenv run` selects when no task name is given.
const DEFAULT_TASK: &str = "default";

pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Invocation, Diagnostic> {
    debug_assert!(ROOT.accepts_help());
    let raw_arguments: Vec<_> = arguments.into_iter().collect();
    let (command_arguments, format, context, profile) = parse_global_options(&raw_arguments)?;
    if let Some((command, diagnostic)) = unknown_child_help_request(&command_arguments) {
        return Ok(Invocation {
            command: Command::HelpError {
                command,
                diagnostic,
            },
            format,
            context,
            profile,
        });
    }
    if let Some(command) = task_help_request(&command_arguments) {
        return Ok(Invocation {
            command: Command::Task { command },
            format,
            context,
            profile,
        });
    }
    if let Some(command) = requested_help_command(&raw_arguments) {
        return Ok(Invocation {
            command: Command::Help { command },
            format,
            context,
            profile,
        });
    }

    let mut arguments = command_arguments.into_iter().peekable();
    let command = match arguments.next().as_deref() {
        None => Command::Help { command: &ROOT },
        Some(token) if option_matches(&ROOT, OptionId::Help, token) => {
            Command::Help { command: &ROOT }
        }
        Some(token) if option_matches(&ROOT, OptionId::Version, token) => Command::Version,
        Some(token) => match ROOT.child(token) {
            Some(command) => parse_command(command, &mut arguments)?,
            None => Command::TaskShortcut {
                task: token.to_owned(),
                arguments: arguments.collect(),
            },
        },
    };
    // `--context` selects a task context, so it applies to anything that runs a
    // task: `run`, `task run`, and a task shortcut. `exec` is excluded: it
    // resolves an executable, never a task, so there is no context to select and
    // accepting the flag would silently discard it.
    if context.is_some()
        && !matches!(
            &command,
            Command::Task { .. }
                | Command::Shortcut { .. }
                | Command::TaskShortcut { .. }
                // `nenv context --context dev` is asking "which context would apply
                // if I asked for dev". The flag is the question, not a setting this
                // command would discard. Refusing it makes the one command that
                // reports contexts unable to report on a *specific* one, and the
                // only workaround left is the environment variable, which nobody
                // finds.
                | Command::Context { .. }
                // `ship` resolves a deployment *by context* -- the reference's
                // `ShipMap.Resolve` keys on `name:context` and the refusal it prints
                // names the context. A flag it could not honour would be worse here
                // than almost anywhere, because the whole selection is
                // context-based, and the reference's own `ship` help lists
                // `-c, --context`.
                | Command::Ship { .. }
                // Likewise `ssh` and `scp`: a host can be selected by `@tag`, and a
                // project may scope a tag to a context. The reference lists
                // `-c, --context` on both.
                | Command::Inventory { .. }
        )
    {
        return Err(usage(
            "--context is only valid for run, task, task shortcut, context, ship, and \
             host commands",
        ));
    }
    Ok(Invocation {
        command,
        format,
        context,
        profile,
    })
}

// Command dispatch is exhaustive over typed tree actions: the match has no
// wildcard arm, so adding a `CommandAction` variant is a compile error here
// rather than a command that silently parses to nothing. Several tree nodes
// intentionally share one action, so an action is not a one-to-one node name.
//
// The `too_many_lines` allow is not laziness about the length: this is an exhaustive
// dispatch over the action vocabulary, and every arm is a call to a per-command
// parser. Compressing it to fit a line count would mean a table of closures, which
// hides the exhaustiveness that is the whole reason the match has no wildcard.
#[allow(clippy::too_many_lines)]
fn parse_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    match command.action {
        CommandAction::Root => Ok(Command::Help { command }),
        CommandAction::Help => Ok(help_command(command, arguments)),
        CommandAction::InitShortcut => Ok(Command::Shortcut {
            name: command.name.to_owned(),
            arguments: arguments.collect(),
            builtin: SelfCommand::Init,
        }),
        CommandAction::UseShortcut => Ok(Command::Shortcut {
            name: command.name.to_owned(),
            arguments: arguments.collect(),
            builtin: SelfCommand::Use {
                arguments: Vec::new(),
            },
        }),
        CommandAction::SelfGroup => Ok(Command::Self_ {
            command: parse_self(command, arguments)?,
        }),
        CommandAction::SelfInit => {
            reject_remaining(command_label(command), arguments)?;
            Ok(Command::Self_ {
                command: SelfCommand::Init,
            })
        }
        CommandAction::SelfUse => Ok(Command::Self_ {
            command: SelfCommand::Use {
                arguments: arguments.collect(),
            },
        }),
        CommandAction::Validate => Ok(Command::Validate {
            path: optional_path(command.name, arguments)?,
        }),
        CommandAction::Inspect => Ok(Command::Inspect {
            path: optional_path(command.name, arguments)?,
        }),
        CommandAction::Exec => {
            let (command, overrides) = parse_exec(command, arguments)?;
            Ok(Command::Exec { command, overrides })
        }
        CommandAction::TaskGroup => Ok(Command::Task {
            command: parse_task(command, arguments)?,
        }),
        CommandAction::RunShortcut | CommandAction::TaskRun => Ok(Command::Task {
            command: parse_task_run(command, arguments)?,
        }),
        CommandAction::ToolGroup => Ok(Command::Tool {
            command: parse_tool(command, arguments)?,
        }),
        CommandAction::TrustGroup => Ok(Command::Trust {
            command: parse_trust(command, arguments)?,
        }),
        CommandAction::WorkspaceGroup => Ok(Command::Workspace {
            command: parse_workspace(command, arguments)?,
        }),
        CommandAction::ShipGroup
        | CommandAction::ShipList
        | CommandAction::ShipDeploy
        | CommandAction::ShipRollback
        | CommandAction::ShipDestroy => ship_command(command, arguments),
        CommandAction::InventoryGroup
        | CommandAction::InventoryList
        | CommandAction::Ssh
        | CommandAction::Scp => inventory_command(command, arguments),
        CommandAction::JobGroup
        | CommandAction::JobList
        | CommandAction::JobHelp
        | CommandAction::JobRun => job_command(command, arguments),
        CommandAction::ConfigGroup
        | CommandAction::ConfigList
        | CommandAction::ConfigGet
        | CommandAction::ConfigSet
        | CommandAction::ConfigUnset => config_command(command, arguments),
        CommandAction::ContextGroup
        | CommandAction::ContextCurrent
        | CommandAction::ContextList => context_command(command, arguments),
        CommandAction::RuntimeGroup => Ok(Command::Runtime {
            command: parse_runtime(command, arguments)?,
        }),
        CommandAction::SecretGroup => Ok(Command::Secret {
            command: parse_secret(command, arguments)?,
        }),
        CommandAction::RemoteGroup => Ok(Command::Remote {
            command: parse_remote(command, arguments)?,
        }),
        CommandAction::ShellGroup => parse_shell(command, arguments),
        CommandAction::ShellActivate => Err(usage("shell activate must follow shell")),
        CommandAction::Completion => completion_command(command, arguments),
        CommandAction::TaskList
        | CommandAction::TaskHelp
        | CommandAction::TaskPlan
        | CommandAction::TaskComplete
        | CommandAction::ToolPlan
        | CommandAction::ToolLock
        | CommandAction::ToolVerify
        | CommandAction::ToolInstall
        | CommandAction::ToolList
        | CommandAction::ToolWhich
        | CommandAction::ToolWhere
        | CommandAction::ToolUse
        | CommandAction::ToolRemove
        | CommandAction::ToolUpdate
        | CommandAction::ToolPin
        | CommandAction::ToolUnpin
        | CommandAction::ToolPurge
        | CommandAction::ToolCleanup
        | CommandAction::TrustStatus
        | CommandAction::TrustAdd
        | CommandAction::TrustRemove
        | CommandAction::TrustRevoke
        | CommandAction::WorkspaceList
        | CommandAction::RuntimeList
        | CommandAction::RuntimeWhere
        | CommandAction::SecretGet
        | CommandAction::SecretSet
        | CommandAction::RemoteInspect
        | CommandAction::RemoteFetch
        | CommandAction::RemoteInstall
        | CommandAction::RemoteUpdate
        | CommandAction::RemoteClear => Err(command_requires_parent(command)),
    }
}

fn parse_shell(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    let child = next_tree_child(command, arguments, "action")?;
    if child.action != CommandAction::ShellActivate {
        return Err(usage(format!(
            "unknown {} action: {}",
            command.name, child.name
        )));
    }
    let label = command_label(child);
    let shell = next_argument(label, "shell", arguments)?;
    let path = arguments.next();
    reject_remaining(label, arguments)?;
    Ok(Command::Shell { shell, path })
}

fn command_requires_parent(command: &CommandSpec) -> Diagnostic {
    usage(format!(
        "{} must be reached through its parent",
        command.name
    ))
}

fn command_label(command: &CommandSpec) -> &str {
    command.usage.strip_prefix("nenv ").unwrap_or(command.usage)
}

fn option_token_matches(option: Option<&CommandOption>, token: &str) -> bool {
    option.is_some_and(|option| {
        (!option.short.is_empty() && option.short == token)
            || (!option.long.is_empty() && option.long == token)
    })
}

fn option_matches(command: &CommandSpec, id: OptionId, token: &str) -> bool {
    option_token_matches(command.option(id), token)
}

/// The child a group names, or `None` when the group was named alone.
///
/// **Separate from `next_tree_child` because "named alone" is a real answer for some
/// groups and a usage error for others.** `nenv context` with nothing after it means
/// "the current context"; `nenv tool` with nothing after it means the subcommand was
/// forgotten, and defaulting that would silently do something nobody asked for. The
/// caller decides which, so this only reports the fact.
///
/// An argument starting with `-` is an option rather than a subcommand, so
/// `nenv context --format json` is `current` with a format and not a subcommand
/// named `--format`.
/// What the next token is, from a group's point of view.
///
/// `Absent` and `Unrecognised` are the two the old `Option` collapsed, and **the
/// collapse is the bug**: a caller that treats both as "no subcommand" cannot tell
/// `nenv config` from `nenv config bogus`, and answers the second with the first.
enum NextChild {
    /// No token, or a flag or `--`. A path may follow.
    Absent,
    /// A recognised child. Its token has been consumed.
    ///
    /// **The typed spelling is carried as well as the node**, and that is not
    /// redundancy. `parent.child("up")` returns the node named `deploy`, because `up`
    /// is an alias, and a caller that reports `child.name` has silently rewritten the
    /// user's verb. `ship up` must say `up` -- a plan that renames the command does not
    /// match the reader's scrollback. The alias belongs in the tree and the *typed*
    /// token belongs in the report, and a shared helper is the only place both are
    /// available at once.
    Child {
        node: &'static CommandSpec,
        typed: String,
    },
    /// A word that is not a child of this group. **Not** consumed, so the caller can
    /// name it.
    Unrecognised(String),
}

/// The next child of `parent`, consuming its token.
///
/// **Three cases, not two, and the third is the one that was missing.** `None` covered
/// both "there is no child here" and "that word is not a child", and the four callers
/// that follow a `None` with `optional_path(..)` therefore read an invented subcommand
/// as a *path*:
///
/// ```text
/// $ nenv config bogus ; echo $?
/// context      dev      /path/to/neoenv.yaml
/// env.STAGE    dev      /path/to/neoenv.yaml:3:3
/// 0
/// ```
///
/// **Exit 0, and a complete, plausible listing** — the answer to a question nobody
/// asked. A user who mistypes a subcommand is told the project is fine, which is worse
/// than a refusal that names the wrong thing: this is not a wrong classification, it is
/// a *success* that hides one.
///
/// `nenv context bogus` printed `dev`, `nenv job bogus` printed "this project declares
/// no jobs", `nenv inventory bogus` printed the equivalent. Four commands, one shared
/// cause, and it survived because each parser was written separately — the same "two
/// copies of one convention" that the `ship` fix repeated.
///
/// So it is one function now, and `ship` uses it too rather than keeping the
/// hand-written peek it needed for the same reason.
fn peek_tree_child(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> NextChild {
    let Some(token) = arguments.peek() else {
        return NextChild::Absent;
    };
    if token == "--" || token.starts_with('-') || looks_like_a_path(token) {
        return NextChild::Absent;
    }
    // **Peeked, then consumed only on a match.** Taking the token first and asking
    // afterwards loses it, and a lost token is a word the rest of the parser cannot
    // refuse — which is how `ship deploye` printed the deployment list.
    match parent.child(token) {
        Some(node) => {
            let typed = token.clone();
            arguments.next();
            NextChild::Child { node, typed }
        }
        None => NextChild::Unrecognised(token.clone()),
    }
}

/// Whether a bare word after a group is a **path** rather than a subcommand.
///
/// **The rule has to exist, and the first version of the refusal did not have it.**
/// `optional_path` accepted whatever came next, so before the refusal a path and an
/// invented subcommand were the same token — and refusing the second necessarily
/// refuses the first. `nenv config ./elsewhere` stopped working, which the test for
/// the *fix* caught and the original bug report never would have.
///
/// Three ways to say "this is a path", in one function so the rule is in one place:
///
/// - it contains a separator (`elsewhere`, `./elsewhere`, `a/b`), which is what a
///   shell and a copy-paste both produce;
/// - it starts with `.` or `~`;
/// - **or it names something that exists**, which is what keeps the relative-directory
///   case (`nenv config proj`, with `proj/` in the working directory) working.
///
/// The third is a filesystem read in a parser, and that is deliberate: `optional_path`
/// is about to stat the token anyway, and a rule that refuses a path the user can see
/// is worse than one extra `exists()` call.
fn looks_like_a_path(token: &str) -> bool {
    token.contains('/')
        || token.starts_with('.')
        || token.starts_with('~')
        || Path::new(token).exists()
}

/// The public subcommand names of a group, for a refusal.
///
/// **In the message**, because a refusal that says only "unknown" sends the reader off
/// to find the list themselves, which is the thing they were about to do anyway.
fn subcommand_names(parent: &CommandSpec) -> String {
    let names: Vec<&str> = parent
        .children
        .iter()
        .filter(|child| child.is_public())
        .map(|child| child.name)
        .collect();
    if names.is_empty() {
        "it takes none".to_owned()
    } else {
        format!("it takes {}", names.join(", "))
    }
}

/// A group that took a word which is not one of its subcommands.
///
/// One function, so all the groups refuse identically. A reader who mistypes
/// `config set` is told `set` is not a subcommand and what is, rather than being told
/// their *value* was unexpected.
fn unknown_subcommand(parent: &CommandSpec, word: &str) -> Diagnostic {
    usage(format!(
        "unknown {} subcommand: {word}; {}",
        parent.name,
        subcommand_names(parent)
    ))
}

fn next_tree_child(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    noun: &str,
) -> Result<&'static CommandSpec, Diagnostic> {
    let token = arguments
        .next()
        .ok_or_else(|| usage(format!("missing {noun} for {}", parent.name)))?;
    parent
        .child(&token)
        .ok_or_else(|| usage(format!("unknown {} {noun}: {token}", parent.name)))
}

/// Detect only malformed *child* help requests. An arbitrary top-level word
/// remains a task shortcut, so asking for its help must not require loading a
/// project or turn a possible task name into an unknown command.
fn unknown_child_help_request(arguments: &[String]) -> Option<(&'static CommandSpec, Diagnostic)> {
    let has_help = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| option_matches(&ROOT, OptionId::Help, argument));
    if !has_help {
        return None;
    }
    let tokens = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| !option_matches(&ROOT, OptionId::Help, argument))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let [parent, child, ..] = tokens.as_slice() else {
        return None;
    };
    let parent = ROOT.child(parent)?;
    // Derived from the tree rather than a hand-maintained list, so a new public
    // group cannot be forgotten here. A group is a public node with children;
    // a hidden group such as `shell` is not a user-facing spelling to correct.
    let is_public_group = parent.is_public() && !parent.children.is_empty();
    if !is_public_group || parent.child(child).is_some() {
        return None;
    }
    let suggestions = suggestions(child, parent.children.iter().map(|command| command.name));
    let suggestion = if suggestions.is_empty() {
        String::new()
    } else {
        format!("; did you mean {}?", format_suggestions(&suggestions))
    };
    Some((
        parent,
        usage(format!(
            "unknown {} subcommand: {child}{suggestion}",
            parent.name
        )),
    ))
}

fn suggestions<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let maximum = input.chars().count().clamp(1, 3);
    let mut matches = candidates
        .into_iter()
        .filter_map(|candidate| {
            let distance = edit_distance(input, candidate);
            (distance <= maximum).then_some((distance, candidate))
        })
        .collect::<Vec<_>>();
    matches.sort_unstable();
    matches
        .into_iter()
        .take(3)
        .map(|(_, candidate)| candidate)
        .collect()
}

fn format_suggestions(suggestions: &[&str]) -> String {
    suggestions
        .iter()
        .map(|suggestion| format!("`{suggestion}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    for (left_index, left_character) in left.chars().enumerate() {
        let mut current = Vec::with_capacity(right.len() + 1);
        current.push(left_index + 1);
        for (right_index, right_character) in right.iter().enumerate() {
            current.push(
                (previous[right_index + 1] + 1)
                    .min(current[right_index] + 1)
                    .min(previous[right_index] + usize::from(left_character != *right_character)),
            );
        }
        previous = current;
    }
    previous[right.len()]
}

fn parse_self(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<SelfCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "command")?;
    match child.action {
        CommandAction::SelfInit => {
            reject_remaining(child.usage, arguments)?;
            Ok(SelfCommand::Init)
        }
        CommandAction::SelfUse => Ok(SelfCommand::Use {
            arguments: arguments.collect(),
        }),
        _ => Err(usage(format!(
            "unknown {} command: {}",
            parent.name, child.name
        ))),
    }
}

fn parse_exec(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(Vec<String>, RunOverrides), Diagnostic> {
    // nenv options are only recognised before the program name, so a flag the
    // program itself takes is never eaten. `--` ends nenv parsing explicitly.
    let mut overrides = RunOverrides::default();
    let mut values = Vec::new();
    let mut after_separator = false;
    while let Some(argument) = arguments.next() {
        if after_separator {
            values.push(argument);
        } else if argument == "--" {
            after_separator = true;
        } else if values.is_empty() {
            match parse_run_override(command, &argument, arguments, &mut overrides)? {
                OverrideOutcome::Consumed => {}
                OverrideOutcome::Passthrough => values.push(argument),
            }
        } else {
            values.push(argument);
        }
    }
    if values.is_empty() {
        return Err(usage(
            "exec requires a command; use `nenv exec -- <command> [<arguments>...]`",
        ));
    }
    Ok((values, overrides))
}

/// Whether a token was an override this call consumed, or a literal argument.
enum OverrideOutcome {
    Consumed,
    Passthrough,
}

/// Consumes one `-p`/`-E`/`-e` option and its value.
///
/// `arguments` is only advanced for an option this function recognizes, so a
/// token that is not one leaves the stream untouched.
fn parse_run_override(
    command: &'static CommandSpec,
    argument: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    overrides: &mut RunOverrides,
) -> Result<OverrideOutcome, Diagnostic> {
    let label = command.name;
    let id = if option_matches(command, OptionId::Project, argument) {
        OptionId::Project
    } else if option_matches(command, OptionId::Dotenv, argument) {
        OptionId::Dotenv
    } else if option_matches(command, OptionId::Env, argument) {
        OptionId::Env
    } else {
        return Ok(OverrideOutcome::Passthrough);
    };
    let spelling = option_spelling(command, id);
    let value = arguments
        .next()
        .ok_or_else(|| usage(format!("missing value for {spelling}")))?;
    // A leading-dash value is almost always a forgotten argument, and silently
    // treating `-x` as a project path or a dotenv path is worse than saying so.
    // A path that genuinely begins with `-` is written `./-name`, which is the
    // usual shell idiom; a lone `-` is left alone because it means stdin.
    if is_option_like(&value) {
        return Err(usage(format!(
            "{spelling} does not accept the option {value}"
        )));
    }
    match id {
        OptionId::Project => {
            if overrides.project.is_some() {
                return Err(usage("duplicate --project option"));
            }
            overrides.project = Some(value);
        }
        OptionId::Dotenv => overrides.dotenv.push(value),
        OptionId::Env => overrides.env.push(split_environment_assignment(&value)?),
        // `id` is one of the three matched above, so this arm is unreachable
        // today. It is a runtime guard, not a compile-time one: adding a fourth
        // option to this function's match would fall here silently.
        _ => return Err(usage(format!("unhandled option {spelling} on {label}"))),
    }
    Ok(OverrideOutcome::Consumed)
}

/// Whether a value token looks like an option rather than a value.
///
/// A lone `-` is the conventional stand-in for stdin, so it is never one. Every
/// other leading-dash token is rejected as a value, whether or not this command
/// happens to declare it: a forgotten `-x` should not become a project path, and
/// rejecting unknown ones too keeps the rule explainable in one sentence.
fn is_option_like(value: &str) -> bool {
    value.len() > 1 && value.starts_with('-')
}

fn option_spelling(command: &'static CommandSpec, id: OptionId) -> &'static str {
    command
        .options
        .iter()
        .find(|option| option.id() == id)
        .map_or("option", |option| option.long)
}

/// Splits `KEY=VALUE`, keeping `=`, spaces, Unicode, and a leading `-` in the
/// value literal. Only the key is validated here so an invalid key produces the
/// same diagnostic as the dotenv path.
fn split_environment_assignment(value: &str) -> Result<(String, String), Diagnostic> {
    let Some((key, value)) = value.split_once('=') else {
        // The token is not echoed: it may carry a value the caller did not
        // intend to print to stderr or a JSON diagnostic.
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO105",
            "environment assignment must be KEY=VALUE",
        ));
    };
    if !neoenv_core::tasks::valid_environment_key(key) {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO105",
            format!("invalid environment key: {key}"),
        ));
    }
    Ok((key.to_owned(), value.to_owned()))
}

fn parse_global_options(
    raw_arguments: &[String],
) -> Result<
    (
        Vec<String>,
        OutputFormat,
        Option<String>,
        neoenv_config::ConfigProfile,
    ),
    Diagnostic,
> {
    let mut command_arguments = Vec::new();
    let mut format = OutputFormat::Text;
    let mut format_seen = false;
    let mut context = None;
    let mut profile = neoenv_config::ConfigProfile::Native;
    let mut index = 0;
    // `exec` streams a child process, and `--context` is an ordinary program flag
    // for anything that takes it. nenv stops claiming it at the program name so
    // the child keeps the flag. `--format` keeps applying throughout, because
    // `exec` is text-only and there is nothing to disambiguate.
    let mut exec_command = false;
    let mut exec_program: Option<usize> = None;

    while index < raw_arguments.len() {
        if raw_arguments[index] == "--" {
            command_arguments.extend_from_slice(&raw_arguments[index..]);
            break;
        }

        if option_matches(&ROOT, OptionId::Format, &raw_arguments[index]) {
            if format_seen {
                return Err(usage("duplicate --format option"));
            }
            let value = raw_arguments
                .get(index + 1)
                .ok_or_else(|| usage("missing value for --format"))?;
            format = match value.as_str() {
                "text" => OutputFormat::Text,
                "json" => OutputFormat::Json,
                _ => return Err(usage(format!("invalid --format value: {value}"))),
            };
            format_seen = true;
            index += 2;
        } else if exec_program.is_none()
            && option_matches(&ROOT, OptionId::Profile, &raw_arguments[index])
        {
            let value = raw_arguments
                .get(index + 1)
                .ok_or_else(|| usage("missing value for --profile"))?;
            profile = neoenv_config::ConfigProfile::from_name(value)
                .ok_or_else(|| usage(format!("invalid --profile value: {value}")))?;
            index += 2;
        } else if exec_program.is_none()
            && option_matches(&ROOT, OptionId::Context, &raw_arguments[index])
        {
            if context.is_some() {
                return Err(usage("duplicate --context option"));
            }
            context = Some(
                raw_arguments
                    .get(index + 1)
                    .cloned()
                    .ok_or_else(|| usage("missing value for --context"))?,
            );
            index += 2;
        } else {
            let token = &raw_arguments[index];
            if command_arguments.is_empty() {
                exec_command = ROOT
                    .child(token)
                    .is_some_and(|command| matches!(command.action, CommandAction::Exec));
            } else if exec_command && exec_program.is_none() {
                exec_program = Some(command_arguments.len());
            }
            command_arguments.push(token.clone());
            index += 1;
        }
    }

    Ok((command_arguments, format, context, profile))
}

fn requested_help_command(arguments: &[String]) -> Option<&'static CommandSpec> {
    let mut tokens = Vec::new();
    let mut help_requested = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        if option_matches(&ROOT, OptionId::Help, argument) {
            help_requested = true;
        } else if ROOT.options.iter().any(|option| {
            matches!(
                option.value,
                crate::command_tree::OptionValue::Required { .. }
            ) && option.long == *argument
        }) {
            index += 1;
        } else {
            tokens.push(argument.clone());
        }
        index += 1;
    }
    if !help_requested {
        return None;
    }
    if tokens.len() > 1
        && tokens.first().is_some_and(|token| {
            ROOT.child(token)
                .is_some_and(|command| command.action == CommandAction::Help)
        })
    {
        tokens.remove(0);
    }
    Some(resolve_help_command(&tokens))
}

fn resolve_help_command(tokens: &[String]) -> &'static CommandSpec {
    let mut command = &ROOT;
    for token in tokens {
        let Some(child) = command.child(token) else {
            break;
        };
        command = child;
    }
    command
}

fn parse_runtime(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<RuntimeCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "subcommand")?;
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::RuntimeList => {
            if let Some(extra) = arguments.next() {
                return Err(usage(format!(
                    "{command_label} takes no arguments, got {extra:?}"
                )));
            }
            Ok(RuntimeCommand::List)
        }
        CommandAction::RuntimeWhere => Ok(RuntimeCommand::Where {
            runtime: required_argument(child.name, "runtime", arguments)?,
        }),
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn parse_secret(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<SecretCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "subcommand")?;
    let label = format!("{} {}", parent.name, child.name);
    let reference = next_argument(&label, "reference", arguments)?;
    let path = arguments.next();
    reject_remaining(&label, arguments)?;
    match child.action {
        CommandAction::SecretGet => Ok(SecretCommand::Get { path, reference }),
        CommandAction::SecretSet => Ok(SecretCommand::Set { path, reference }),
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

/// The `Command` wrapper for a parsed `context` subcommand.
///
/// **Separate from `parse_command` because that function matches every
/// `CommandAction` exhaustively, and adding an arm to it crosses clippy's line
/// limit.** Extracting the body is better than compressing the formatting or
/// raising the limit: the dispatch table stays one entry per action, which is what
/// makes it readable, and the limit stays a signal rather than something this file
/// carries an exception for.
/// The `Command` for `nenv completion <shell>`.
///
/// Extracted for the same reason as `context_command`: `parse_command` matches every
/// `CommandAction` exhaustively, so each arm it gains has to be paid for by one it
/// gives up. Moving a wrapper into a named function is better than compressing it
/// onto one line, because the name says what the arm does and the limit stays a
/// signal.
/// The `Command` for `nenv help [command]`.
///
/// Extracted for the same reason as `completion_command` and `context_command`:
/// `parse_command` matches every `CommandAction` exhaustively, so each arm it gains
/// has to be paid for by one it gives up. Three of its arms are now one-liners calling
/// named functions, which is both shorter than the function was and clearer than the
/// bodies were inline -- the table now reads as a list of commands rather than a list
/// of constructions.
/// Returns a `Command` rather than a `Result` because it cannot fail, and a
/// signature that says otherwise is a promise this function does not keep.
/// The `Command` for a parsed `ship` invocation.
///
/// A recognised verb becomes [`ShipCommand::Lifecycle`]; anything else becomes
/// [`ShipCommand::Other`] and is refused downstream with the reference's own wording,
/// because the reference validates the verb against a fixed set rather than reading it
/// as a deployment name.
fn ship_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Ship {
        command: parse_ship(command, arguments)?,
    })
}

fn parse_ship(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<ShipCommand, Diagnostic> {
    // **Peeked, not consumed, and the peek is the shared one.** This parser had its
    // own version because `next_tree_child_if_present` takes the token *before* it
    // knows whether the token names a child, so `ship deploye` came back as "no
    // subcommand" with `deploye` already eaten -- and the command then printed the
    // deployment list, which is a plausible-looking answer to a question nobody asked.
    //
    // The same footgun ate `@prod` on `ssh @prod`. And it turned out to be the *same*
    // footgun in four more parsers, where it did not fail loudly at all -- so the
    // bespoke peek is gone and `peek_tree_child` is the one place this is decided.
    //
    // `ship` keeps one thing the other groups do not: an unrecognised verb becomes a
    // value rather than an "unknown subcommand". The reference validates the verb
    // against a fixed set rather than reading it as a deployment name, and `ship prod`
    // is a plausible typo for `ship deploy prod` -- so the downstream refusal reads
    // "ship prod is not implemented yet", which names the verb, where "unknown ship
    // subcommand" would name a rule the reader does not know exists.
    let (token, child) = match peek_tree_child(parent, arguments) {
        NextChild::Absent => {
            return Ok(ShipCommand::Group {
                path: optional_path(parent.name, arguments)?,
            });
        }
        NextChild::Child { node, typed } => (typed, node),
        NextChild::Unrecognised(word) => {
            return Ok(ShipCommand::Other {
                path: None,
                verb: word,
            });
        }
    };

    let label = format!("{} {}", parent.name, token);
    match child.action {
        CommandAction::ShipList => Ok(ShipCommand::List {
            path: optional_path(&label, arguments)?,
        }),
        CommandAction::ShipDeploy | CommandAction::ShipRollback | CommandAction::ShipDestroy => {
            let mut plan_only = false;
            let mut deployment: Option<String> = None;
            let mut after_separator = false;
            for token in arguments.by_ref() {
                if after_separator {
                    deployment = Some(token);
                } else if token == "--" {
                    after_separator = true;
                } else if option_matches(child, OptionId::DryRun, token.as_str())
                    || token == "--dry-run"
                {
                    // `--dry-run` is the reference's alias for `--plan`, accepted
                    // without being declared: a `CommandOption` holds one long
                    // spelling, and the tree contract rightly refuses two options
                    // sharing an `OptionId`. See `SHIP_PLAN_OPTION`.
                    plan_only = true;
                } else if token.starts_with('-') && token != "-" {
                    return Err(usage(format!("unknown option for {label}: {token}")));
                } else {
                    deployment = Some(token);
                }
            }
            Ok(ShipCommand::Lifecycle {
                path: None,
                // **The token the user typed**, not the node's canonical name. `ship
                // up` reports `up` and not `deploy`, as the reference does -- a
                // refusal that renamed the verb would not match the user's scrollback.
                // Getting this needs the typed spelling held before the alias resolves,
                // which is the other reason the lookup above peeks.
                verb: token,
                deployment,
                plan_only,
            })
        }
        _ => Ok(ShipCommand::Other {
            path: None,
            verb: child.name.to_owned(),
        }),
    }
}

/// The `Command` for a parsed `inventory`, `ssh` or `scp` invocation.
///
/// One function for all three, because they share the shape: an inventory, a list of
/// targets, and a plan flag. Three parsers would let `scp` grow a field `ssh` does not
/// have with nothing comparing them.
fn inventory_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Inventory {
        command: parse_inventory(command, arguments)?,
    })
}

/// The inventory a command resolves against when `--inventory` is absent.
///
/// A constant rather than a default argument, so the default is visible at every use
/// site instead of in one signature somebody reads once.
const DEFAULT_INVENTORY: &str = "default";

fn parse_inventory(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<InventoryCommand, Diagnostic> {
    // `ssh` and `scp` are **leaves**: their first positional is a target, not a
    // subcommand. So they must not go through `next_tree_child_if_present`, which
    // *consumes* the token before checking it -- it ate `@prod` and then reported
    // "unexpected argument for ssh", which is a diagnostic about the parser rather
    // than about the command.
    if matches!(parent.action, CommandAction::Ssh | CommandAction::Scp) {
        return parse_host_command(parent, arguments);
    }

    // `nenv inventory` with nothing after it is `list`, matching every other group
    // in this tree. The reference has no `inventory` command at all, so there is
    // nothing to match; the convention is this tree's.
    // **A word that is not a subcommand is refused by name**, not read as a
    // path. See `peek_tree_child`: the old `Option` could not tell the two apart,
    // and `nenv config bogus` exited 0 with a complete listing.
    let child = match peek_tree_child(parent, arguments) {
        NextChild::Absent => {
            return Ok(InventoryCommand::Group {
                path: optional_path(parent.name, arguments)?,
            });
        }
        NextChild::Child { node: child, .. } => child,
        NextChild::Unrecognised(word) => {
            return Err(unknown_subcommand(parent, &word));
        }
    };
    if child.action != CommandAction::InventoryList {
        return Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        )));
    }
    Ok(InventoryCommand::List {
        path: optional_path(&format!("{} {}", parent.name, child.name), arguments)?,
    })
}

/// The `ssh` and `scp` bodies, which differ only in where their positionals split.
///
/// Named `parse_host_command` rather than `parse_remote` because `parse_remote` is
/// already the `remote` command's parser -- and two functions with the same name and
/// different return types in one file is a lookup that goes wrong exactly once.
fn parse_host_command(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<InventoryCommand, Diagnostic> {
    let child = parent;
    let label = parent.name.to_owned();
    let is_scp = child.action == CommandAction::Scp;

    // Options and positionals are interleaved and their order is not fixed, so this
    // drains the iterator and sorts them out afterwards. A loop that stopped at the
    // first positional would make `ssh --plan web1` work and `ssh web1 --plan` not,
    // which is a rule nobody can guess.
    let mut inventory: Option<String> = None;
    let mut plan_only = false;
    let mut pull = false;
    let mut positional: Vec<String> = Vec::new();
    let mut after_separator = false;
    let mut script_parts = Vec::new();
    while let Some(token) = arguments.next() {
        if after_separator {
            if is_scp {
                positional.push(token);
            } else {
                script_parts.push(token);
            }
            continue;
        }
        if token == "--" {
            after_separator = true;
        } else if option_matches(child, OptionId::Inventory, token.as_str()) {
            inventory = Some(
                arguments
                    .next()
                    .ok_or_else(|| usage("--inventory needs a value"))?,
            );
        } else if option_matches(child, OptionId::DryRun, token.as_str()) || token == "--dry-run" {
            // `--dry-run` is the reference's alias for `--plan` (`cli.go:2468`) and is
            // accepted without being declared, because a `CommandOption` holds one
            // long spelling and the tree contract rightly refuses two options sharing
            // an `OptionId`. See `REMOTE_OPTIONS` for the reasoning.
            plan_only = true;
        } else if option_matches(child, OptionId::Pull, token.as_str()) {
            pull = true;
        } else if token.starts_with('-') && token != "-" {
            return Err(usage(format!("unknown option for {label}: {token}")));
        } else {
            positional.push(token);
        }
    }
    let inventory = inventory.unwrap_or_else(|| DEFAULT_INVENTORY.to_owned());

    // `scp <source> <destination> <target>...`: the two paths come first and
    // everything after them is a target, as in the reference's usage line at
    // `cli.go:3380`. The arity is checked before anything is consumed so the message
    // can say what is missing rather than which argument it ran out of.
    if is_scp {
        if positional.len() < 3 {
            return Err(usage(
                "scp needs a source, a destination, and at least one inventory host \
                 or @tag",
            ));
        }
        let mut positional = positional.into_iter();
        return Ok(InventoryCommand::Scp {
            path: None,
            inventory,
            source: positional
                .next()
                .expect("the arity check above guaranteed a source"),
            destination: positional
                .next()
                .expect("the arity check above guaranteed a destination"),
            targets: positional.collect(),
            pull,
            plan_only,
        });
    }
    if positional.is_empty() {
        return Err(usage("ssh needs at least one inventory host or @tag"));
    }
    Ok(InventoryCommand::Ssh {
        path: None,
        inventory,
        targets: positional,
        script: (!script_parts.is_empty()).then(|| script_parts.join(" ")),
        plan_only,
    })
}

/// The `Command` for a parsed `job` subcommand.
///
/// Extracted for the same reason as `config_command` and `context_command`:
/// `parse_command` matches every `CommandAction` exhaustively, so each arm it gains
/// has to be paid for by one it gives up.
fn job_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Job {
        command: parse_job(command, arguments)?,
    })
}

fn parse_job(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<JobCommand, Diagnostic> {
    // **A word that is not a subcommand is refused by name**, not read as a
    // path. See `peek_tree_child`: the old `Option` could not tell the two apart,
    // and `nenv config bogus` exited 0 with a complete listing.
    let child = match peek_tree_child(parent, arguments) {
        NextChild::Absent => {
            return Ok(JobCommand::Group {
                path: optional_path(parent.name, arguments)?,
            });
        }
        NextChild::Child { node: child, .. } => child,
        NextChild::Unrecognised(word) => {
            return Err(unknown_subcommand(parent, &word));
        }
    };
    let label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::JobList => Ok(JobCommand::List {
            path: optional_path(&label, arguments)?,
        }),
        CommandAction::JobHelp => Ok(JobCommand::Help {
            // The job first and the path optional, so `job help deploy ./p` and
            // `job help ./p deploy` are the same request.
            job: required_argument(&label, "job", arguments)?,
            path: optional_path(&label, arguments)?,
        }),
        CommandAction::JobRun => {
            // `--dry-run` is read here rather than through a channel from the
            // invocation, because `parse_command` receives no parsed options and the
            // task parser reads its own the same way. Two parsers each reading their
            // own options is the existing convention; inventing a third path for one
            // command would be the surprising choice.
            let mut dry_run = false;
            while arguments
                .peek()
                .is_some_and(|token| option_matches(child, OptionId::DryRun, token.as_str()))
            {
                arguments.next();
                dry_run = true;
            }
            Ok(JobCommand::Run {
                job: required_argument(&label, "job", arguments)?,
                path: optional_path(&label, arguments)?,
                dry_run,
            })
        }
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

/// The `Command` for a parsed `config` subcommand.
///
/// Extracted for the same reason as `completion_command` and `context_command`:
/// `parse_command` matches every `CommandAction` exhaustively, so each arm it gains
/// has to be paid for by one it gives up.
fn config_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Config {
        command: parse_config(command, arguments)?,
    })
}

/// Parses the `config` group and its two verbs.
///
/// `nenv config` with nothing after it is `list`, matching the reference: someone
/// who types the group name wants the keys, not a usage message.
fn parse_config(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<ConfigCommand, Diagnostic> {
    // **A word that is not a subcommand is refused by name**, not read as a
    // path. See `peek_tree_child`: the old `Option` could not tell the two apart,
    // and `nenv config bogus` exited 0 with a complete listing.
    let child = match peek_tree_child(parent, arguments) {
        NextChild::Absent => {
            return Ok(ConfigCommand::Group {
                path: optional_path(parent.name, arguments)?,
            });
        }
        NextChild::Child { node: child, .. } => child,
        NextChild::Unrecognised(word) => {
            return Err(unknown_subcommand(parent, &word));
        }
    };
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::ConfigList => Ok(ConfigCommand::List {
            path: optional_path(&command_label, arguments)?,
        }),
        // **The key comes first and the path is optional** -- which is what
        // `nenv config get --help` documents, and which the parser did not do.
        // `required_argument` rejects whatever is left before the path can be read, so
        // `config get <key> <path>` was refused with "unexpected argument for config
        // get". The help text, this comment and the parser all disagreed, and the only
        // one a user ever meets is the parser.
        //
        // **The reversed order is not accepted, and this comment used to say it was.**
        // `config get ./p env.STAGE` would need a rule for telling a key from a path,
        // and the obvious one -- "whichever names a file that exists" -- guesses wrong
        // for a key that happens to be a filename, and for a path that does not exist yet.
        // A guess about which argument is which is a worse failure than a documented
        // order, so the order is fixed and `key_then_optional_path` says so when the key
        // is a path.
        CommandAction::ConfigGet => {
            let (key, path) = key_then_optional_path(&command_label, arguments)?;
            Ok(ConfigCommand::Get { key, path })
        }
        CommandAction::ConfigSet => {
            let (key, value, path) = key_value_then_optional_path(&command_label, arguments)?;
            Ok(ConfigCommand::Set { key, value, path })
        }
        CommandAction::ConfigUnset => {
            // `key_then_optional_path` rather than a new reader: the shape is the same as
            // `config get`, and a second function for two arguments is a second place to
            // get the "which argument is the key" diagnostic wrong.
            let (key, path) = key_then_optional_path(&command_label, arguments)?;
            Ok(ConfigCommand::Unset { key, path })
        }
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn help_command(
    _command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Command {
    // The spec is not read: `nenv help` is about the *tokens*, and which node was
    // matched is already implied by reaching here. The parameter exists so this has
    // the same shape as the other extracted arms and can be called from the table
    // without a special case.
    let tokens = arguments.by_ref().collect::<Vec<_>>();
    Command::Help {
        command: resolve_help_command(&tokens),
    }
}

fn completion_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Completion {
        shell: required_argument(command.name, "shell", arguments)?,
    })
}

fn context_command(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Command, Diagnostic> {
    Ok(Command::Context {
        command: parse_context(command, arguments)?,
    })
}

/// Parses the `context` group and its two children.
///
/// **The children's actions are listed in `parse_command` as well as here.** That
/// looks redundant and is not: `parse_command` matches every `CommandAction` with no
/// wildcard arm, on purpose, so a new action that nobody handled is a compile error
/// rather than a command that parses to nothing. Listing them there keeps that
/// property; listing them again here is what makes them reachable.
///
/// `nenv context` with nothing after it is `current`, not a usage error.
///
/// The reference behaves the same way and it is the useful behaviour: someone who
/// types the group name wants the answer, not a list of what they could have typed.
/// `ContextCommand::Group` stays a distinct variant rather than being collapsed to
/// `Current` here, so the help text and the parser cannot disagree about which
/// spelling means what.
fn parse_context(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<ContextCommand, Diagnostic> {
    // **A word that is not a subcommand is refused by name**, not read as a
    // path. See `peek_tree_child`: the old `Option` could not tell the two apart,
    // and `nenv config bogus` exited 0 with a complete listing.
    let child = match peek_tree_child(parent, arguments) {
        NextChild::Absent => {
            return Ok(ContextCommand::Group {
                path: optional_path(parent.name, arguments)?,
            });
        }
        NextChild::Child { node: child, .. } => child,
        NextChild::Unrecognised(word) => {
            return Err(unknown_subcommand(parent, &word));
        }
    };
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::ContextCurrent => Ok(ContextCommand::Current {
            path: optional_path(&command_label, arguments)?,
        }),
        CommandAction::ContextList => Ok(ContextCommand::List {
            path: optional_path(&command_label, arguments)?,
        }),
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn parse_workspace(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<WorkspaceCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "subcommand")?;
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::WorkspaceList => Ok(WorkspaceCommand::List {
            path: optional_path(&command_label, arguments)?,
        }),
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn parse_trust(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<TrustCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "subcommand")?;
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::TrustStatus => {
            if arguments.peek().is_none() {
                Ok(TrustCommand::Status)
            } else {
                let path = project_argument(&command_label, child, arguments)?;
                Ok(TrustCommand::ProjectStatus { path })
            }
        }
        CommandAction::TrustAdd => {
            let value = next_argument(&command_label, "path or repository", arguments)?;
            let (value, remote_requested, project_requested) =
                if option_matches(child, OptionId::Remote, &value) {
                    (
                        next_argument(&command_label, "remote identity", arguments)?,
                        true,
                        false,
                    )
                } else if option_matches(child, OptionId::Project, &value) {
                    (
                        next_argument(&command_label, "project path", arguments)?,
                        false,
                        true,
                    )
                } else {
                    (value, false, false)
                };
            reject_remaining(&command_label, arguments)?;
            if remote_requested {
                Ok(TrustCommand::AddRemote { spec: value })
            } else if project_requested
                || (looks_like_project_path(&value) && !looks_like_remote_repository(&value))
            {
                Ok(TrustCommand::AddProject { path: value })
            } else {
                Ok(TrustCommand::AddRepository { repository: value })
            }
        }
        CommandAction::TrustRemove => {
            let repository = next_argument(&command_label, "repository", arguments)?;
            let (repository, remote_requested) =
                if option_matches(child, OptionId::Remote, &repository) {
                    (
                        next_argument(&command_label, "remote identity", arguments)?,
                        true,
                    )
                } else {
                    (repository, false)
                };
            reject_remaining(&command_label, arguments)?;
            if remote_requested {
                Ok(TrustCommand::RemoveRemote { spec: repository })
            } else {
                Ok(TrustCommand::RemoveRepository { repository })
            }
        }
        CommandAction::TrustRevoke => {
            let path = next_argument(&command_label, "path", arguments)?;
            reject_remaining(&command_label, arguments)?;
            Ok(TrustCommand::RevokeProject { path })
        }
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn project_argument(
    command: &str,
    spec: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<String, Diagnostic> {
    let value = next_argument(command, "project path", arguments)?;
    let value = if option_matches(spec, OptionId::Project, &value) {
        next_argument(command, "project path", arguments)?
    } else {
        value
    };
    reject_remaining(command, arguments)?;
    Ok(value)
}

fn next_argument(
    command: &str,
    name: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<String, Diagnostic> {
    arguments
        .next()
        .ok_or_else(|| usage(format!("missing {name} for {command}")))
}

fn looks_like_project_path(value: &str) -> bool {
    value.contains(['/', '\\'])
        || Path::new(value)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("toml")
                    || extension.eq_ignore_ascii_case("yaml")
                    || extension.eq_ignore_ascii_case("yml")
            })
}

fn looks_like_remote_repository(value: &str) -> bool {
    value.trim_start().starts_with("github:")
        || value.trim_start().starts_with("https://github.com/")
        || value.trim_start().starts_with("file://")
}

fn parse_remote(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<RemoteCommand, Diagnostic> {
    let subcommand = arguments
        .next()
        .ok_or_else(|| usage(format!("missing subcommand for {}", parent.name)))?;
    let source = arguments
        .next()
        .ok_or_else(|| usage(format!("missing source for {} {subcommand}", parent.name)))?;
    let child = parent
        .child(&subcommand)
        .ok_or_else(|| usage(format!("unknown {} subcommand: {subcommand}", parent.name)))?;
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::RemoteInspect => {
            reject_remaining(&command_label, arguments)?;
            Ok(RemoteCommand::Inspect { source })
        }
        CommandAction::RemoteFetch => Ok(RemoteCommand::Fetch {
            source,
            path: optional_path(&command_label, arguments)?,
        }),
        CommandAction::RemoteInstall => Ok(RemoteCommand::Install {
            source,
            path: optional_path(&command_label, arguments)?,
        }),
        CommandAction::RemoteUpdate => Ok(RemoteCommand::Update {
            source,
            path: optional_path(&command_label, arguments)?,
        }),
        CommandAction::RemoteClear => Ok(RemoteCommand::Clear {
            source,
            path: optional_path(&command_label, arguments)?,
        }),
        _ => Err(usage(format!(
            "unknown {} subcommand: {subcommand}",
            parent.name
        ))),
    }
}

fn parse_task(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<TaskCommand, Diagnostic> {
    let child = next_tree_child(parent, arguments, "subcommand")?;
    let command_label = format!("{} {}", parent.name, child.name);
    match child.action {
        CommandAction::TaskList => Ok(TaskCommand::List {
            path: optional_path(&command_label, arguments)?,
        }),
        CommandAction::TaskHelp => {
            let (task, path) = task_and_optional_path(&command_label, arguments)?;
            Ok(TaskCommand::Help { task, path })
        }
        CommandAction::TaskPlan => {
            let (task, path) = task_and_optional_path(&command_label, arguments)?;
            Ok(TaskCommand::Plan { task, path })
        }
        CommandAction::TaskRun => parse_task_run(child, arguments),
        CommandAction::TaskComplete => {
            let task = arguments.next();
            reject_remaining(&command_label, arguments)?;
            Ok(TaskCommand::Complete { task })
        }
        _ => Err(usage(format!(
            "unknown {} subcommand: {}",
            parent.name, child.name
        ))),
    }
}

fn parse_task_run(
    command: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<TaskCommand, Diagnostic> {
    // Options are recognized before the task name as well as after it, so a bare
    // `run` can select `default` with no task token in between.
    let mut overrides = RunOverrides::default();
    let mut task: Option<String> = None;
    let mut path = None;
    let mut dry_run = false;
    let mut capability_policy = None;
    let mut passthrough = Vec::new();
    let mut after_separator = false;
    while let Some(argument) = arguments.next() {
        if after_separator {
            passthrough.push(argument);
        } else if argument == "--" {
            after_separator = true;
            passthrough.push(argument);
        } else if let OverrideOutcome::Consumed =
            parse_run_override(command, &argument, arguments, &mut overrides)?
        {
        } else if option_matches(command, OptionId::DryRun, &argument) {
            if dry_run {
                return Err(usage("duplicate --dry-run option"));
            }
            dry_run = true;
        } else if option_matches(command, OptionId::CapabilityPolicy, &argument) {
            if capability_policy.is_some() {
                return Err(usage("duplicate --capability-policy option"));
            }
            capability_policy = Some(
                arguments
                    .next()
                    .ok_or_else(|| usage("missing value for --capability-policy"))?,
            );
        } else if task.is_none() {
            task = Some(argument);
        } else if path.is_none() && looks_like_task_configuration_path(&argument) {
            path = Some(argument);
        } else {
            passthrough.push(argument);
        }
    }
    let Some(task) = task else {
        return Ok(TaskCommand::Run {
            task: DEFAULT_TASK.to_owned(),
            path,
            dry_run,
            capability_policy,
            passthrough,
            overrides,
        });
    };
    Ok(TaskCommand::Run {
        task,
        path,
        dry_run,
        capability_policy,
        passthrough,
        overrides,
    })
}

fn looks_like_task_configuration_path(value: &str) -> bool {
    Path::new(value)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name == neoenv_core::names::PROJECT_DIRECTORY)
        || Path::new(value)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("toml")
                    || extension.eq_ignore_ascii_case("yaml")
                    || extension.eq_ignore_ascii_case("yml")
            })
}

fn task_help_request(arguments: &[String]) -> Option<TaskCommand> {
    let has_help = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| option_matches(&ROOT, OptionId::Help, argument));
    if !has_help {
        return None;
    }
    let tokens = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| !option_matches(&ROOT, OptionId::Help, argument))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let root = ROOT.child(tokens.first().copied().unwrap_or(""));
    if let Some(command) = root {
        if matches!(
            command.action,
            CommandAction::RunShortcut | CommandAction::TaskRun
        ) {
            return match tokens.as_slice() {
                [_, name] => Some(TaskCommand::Help {
                    task: (*name).to_owned(),
                    path: None,
                }),
                [_, name, path] if looks_like_task_configuration_path(path) => {
                    Some(TaskCommand::Help {
                        task: (*name).to_owned(),
                        path: Some((*path).to_owned()),
                    })
                }
                _ => None,
            };
        }
        if command.action == CommandAction::TaskGroup
            && tokens.len() >= 3
            && let Some(child) = command.child(tokens[1])
            && matches!(
                child.action,
                CommandAction::TaskRun | CommandAction::TaskHelp
            )
        {
            return match tokens.as_slice() {
                [_, _, name] => Some(TaskCommand::Help {
                    task: (*name).to_owned(),
                    path: None,
                }),
                [_, _, name, path] if looks_like_task_configuration_path(path) => {
                    Some(TaskCommand::Help {
                        task: (*name).to_owned(),
                        path: Some((*path).to_owned()),
                    })
                }
                _ => None,
            };
        }
        return None;
    }
    match tokens.as_slice() {
        [task] => Some(TaskCommand::Help {
            task: (*task).to_owned(),
            path: None,
        }),
        _ => None,
    }
}

fn task_and_optional_path(
    command: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(String, Option<String>), Diagnostic> {
    let task = arguments
        .next()
        .ok_or_else(|| usage(format!("missing task for {command}")))?;
    let path = arguments.next();
    reject_remaining(command, arguments)?;
    Ok((task, path))
}

struct ToolArguments {
    subcommand: String,
    child: &'static CommandSpec,
    locked: bool,
    positional: Vec<String>,
}

fn parse_tool_arguments(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<ToolArguments, Diagnostic> {
    let subcommand = arguments
        .next()
        .ok_or_else(|| usage(format!("missing subcommand for {}", parent.name)))?;
    let child = parent
        .child(&subcommand)
        .ok_or_else(|| usage(format!("unknown {} subcommand: {subcommand}", parent.name)))?;
    let locked_option = child.option(OptionId::Locked);
    let mut locked = false;
    let mut positional = Vec::new();
    for value in arguments {
        if option_token_matches(locked_option, &value) {
            if locked {
                return Err(usage("duplicate --locked option"));
            }
            locked = true;
        } else {
            positional.push(value);
        }
    }
    Ok(ToolArguments {
        subcommand,
        child,
        locked,
        positional,
    })
}

fn scope_values(
    values: Vec<String>,
    spec: &'static CommandSpec,
    command: &str,
) -> Result<(Option<ToolScope>, Vec<String>), Diagnostic> {
    let mut scope = None;
    let mut rest = Vec::new();
    for value in values {
        if option_matches(spec, OptionId::User, &value) {
            if scope.replace(ToolScope::User).is_some() {
                return Err(usage(format!(
                    "duplicate or conflicting scope for tool {command}"
                )));
            }
        } else if option_matches(spec, OptionId::Global, &value) {
            if scope.replace(ToolScope::Global).is_some() {
                return Err(usage(format!(
                    "duplicate or conflicting scope for tool {command}"
                )));
            }
        } else {
            rest.push(value);
        }
    }
    Ok((scope, rest))
}

#[allow(clippy::too_many_lines)] // One dispatch over every tool subcommand.
fn parse_tool(
    parent: &'static CommandSpec,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<ToolCommand, Diagnostic> {
    let ToolArguments {
        subcommand,
        child,
        locked,
        positional,
    } = parse_tool_arguments(parent, arguments)?;
    let child_name = child.name;
    match child.action {
        CommandAction::ToolPlan => Ok(ToolCommand::Plan {
            path: one_optional_path(child.name, &positional)?,
            locked,
        }),
        CommandAction::ToolLock => Ok(ToolCommand::Lock {
            path: one_optional_path(child.name, &positional)?,
            locked,
        }),
        CommandAction::ToolVerify if !locked => Ok(ToolCommand::Verify {
            path: one_optional_path(child.name, &positional)?,
        }),
        CommandAction::ToolInstall if locked => Ok(ToolCommand::Install {
            path: one_optional_path(child.name, &positional)?,
        }),
        CommandAction::ToolList if !locked => {
            let (scope, positional) = scope_values(positional, child, child.name)?;
            let path = one_optional_path(child.name, &positional)?;
            if scope.is_some() && path.is_some() {
                return Err(usage(
                    "tool list does not accept a project path together with --user or --global",
                ));
            }
            Ok(ToolCommand::List { path, scope })
        }
        CommandAction::ToolWhich | CommandAction::ToolWhere if !locked => {
            let (scope, positional) = scope_values(positional, child, child.name)?;
            let mut positional = positional.into_iter();
            let executable = positional.next().ok_or_else(|| {
                usage(format!(
                    "missing executable for {} {child_name}",
                    parent.name
                ))
            })?;
            let path = positional.next();
            if positional.next().is_some() {
                return Err(usage(format!(
                    "unexpected argument for {} {child_name}",
                    parent.name
                )));
            }
            if scope.is_some() && path.is_some() {
                return Err(usage(format!(
                    "tool {child_name} does not accept a project path together with --user or --global"
                )));
            }
            if child.action == CommandAction::ToolWhere {
                Ok(ToolCommand::Where {
                    executable,
                    path,
                    scope,
                })
            } else {
                Ok(ToolCommand::Which {
                    executable,
                    path,
                    scope,
                })
            }
        }
        CommandAction::ToolUse if !locked => parse_tool_use(positional, child),
        CommandAction::ToolRemove
        | CommandAction::ToolUpdate
        | CommandAction::ToolPin
        | CommandAction::ToolUnpin
        | CommandAction::ToolPurge
            if !locked =>
        {
            parse_lifecycle(positional, child)
        }
        CommandAction::ToolCleanup if !locked => {
            let (scope, positional) = scope_values(positional, child, child.name)?;
            let mut dry_run = false;
            let mut paths = Vec::new();
            for value in positional {
                if option_matches(child, OptionId::DryRun, &value) {
                    if dry_run {
                        return Err(usage("duplicate --dry-run option"));
                    }
                    dry_run = true;
                } else {
                    paths.push(value);
                }
            }
            let path = one_optional_path("cleanup", &paths)?;
            if scope.is_some() && path.is_some() {
                return Err(usage(
                    "tool cleanup does not accept a project path together with --user or --global",
                ));
            }
            Ok(ToolCommand::Cleanup {
                path,
                dry_run,
                scope,
            })
        }
        CommandAction::ToolVerify => {
            Err(usage("--locked is only valid for tool plan or tool lock"))
        }
        CommandAction::ToolInstall => Err(usage("tool install requires --locked")),
        CommandAction::ToolList
        | CommandAction::ToolWhich
        | CommandAction::ToolWhere
        | CommandAction::ToolUse
        | CommandAction::ToolRemove
        | CommandAction::ToolUpdate
        | CommandAction::ToolPin
        | CommandAction::ToolUnpin
        | CommandAction::ToolPurge
        | CommandAction::ToolCleanup => Err(usage("--locked is not valid for this tool command")),
        _ => Err(usage(format!(
            "unknown {} subcommand: {subcommand}",
            parent.name
        ))),
    }
}

fn has_explicit_version(value: &str) -> bool {
    let separator = value
        .find(':')
        .and_then(|colon| value.rfind('@').filter(|at| *at > colon + 1));
    separator.is_some()
        || value
            .rfind('@')
            .is_some_and(|at| at > 0 && !value.contains(':'))
}

fn parse_lifecycle(
    values: Vec<String>,
    spec: &'static CommandSpec,
) -> Result<ToolCommand, Diagnostic> {
    let action = spec.action;
    let command = spec.name;
    let mut project = false;
    let mut user = false;
    let mut global = false;
    let mut dry_run = false;
    let mut tools = Vec::new();
    for value in values {
        if option_matches(spec, OptionId::Project, &value) {
            if project {
                return Err(usage("duplicate --project option"));
            }
            project = true;
        } else if option_matches(spec, OptionId::User, &value) {
            if user {
                return Err(usage("duplicate --user option"));
            }
            user = true;
        } else if option_matches(spec, OptionId::Global, &value) {
            if global {
                return Err(usage("duplicate --global option"));
            }
            global = true;
        } else if option_matches(spec, OptionId::DryRun, &value) {
            if dry_run {
                return Err(usage("duplicate --dry-run option"));
            }
            dry_run = true;
        } else if value.starts_with('-') {
            return Err(usage(format!("unknown option for tool {command}: {value}")));
        } else {
            tools.push(value);
        }
    }
    if usize::from(project) + usize::from(user) + usize::from(global) != 1 {
        return Err(usage(format!(
            "tool {command} requires exactly one of --project, --user, or --global"
        )));
    }
    if tools.is_empty() && action != CommandAction::ToolPurge {
        return Err(usage(format!(
            "tool {command} requires one or more tool names"
        )));
    }
    if action == CommandAction::ToolPurge && tools.iter().any(|tool| has_explicit_version(tool)) {
        return Err(usage("tool purge accepts tool names, not versions"));
    }
    let scope = if project {
        ToolScope::Project
    } else if user {
        ToolScope::User
    } else {
        ToolScope::Global
    };
    Ok(match action {
        CommandAction::ToolRemove => ToolCommand::Remove {
            scope,
            tools,
            dry_run,
        },
        CommandAction::ToolUpdate => ToolCommand::Update {
            scope,
            tools,
            dry_run,
        },
        CommandAction::ToolPin => ToolCommand::Pin {
            scope,
            tools,
            dry_run,
        },
        CommandAction::ToolUnpin => ToolCommand::Unpin {
            scope,
            tools,
            dry_run,
        },
        CommandAction::ToolPurge => ToolCommand::Purge {
            scope,
            tools,
            dry_run,
        },
        _ => return Err(usage(format!("unknown lifecycle command: {command}"))),
    })
}

fn parse_tool_use(
    values: Vec<String>,
    command: &'static CommandSpec,
) -> Result<ToolCommand, Diagnostic> {
    // Scope flags belong to this command only before `--`. Everything after
    // the separator is the child program's argument and must not be read as a
    // nenv scope flag; `tool use foo -- -g` runs `foo` with `-g`.
    let before_separator = values.iter().take_while(|value| value.as_str() != "--");
    if before_separator.clone().any(|value| {
        option_matches(command, OptionId::User, value)
            || option_matches(command, OptionId::Global, value)
    }) {
        return Ok(ToolCommand::GlobalUse { arguments: values });
    }
    let mut values = values.into_iter();
    let executable = values
        .next()
        .ok_or_else(|| usage("missing executable for tool use"))?;
    let mut path = None;
    let mut arguments = Vec::new();
    let mut after_separator = false;
    for value in values {
        if after_separator {
            arguments.push(value);
        } else if value == "--" {
            after_separator = true;
        } else if path.is_none() {
            path = Some(value);
        } else {
            return Err(usage("tool use arguments must follow --"));
        }
    }
    Ok(ToolCommand::Use {
        executable,
        path,
        arguments,
    })
}

fn one_optional_path(command: &str, values: &[String]) -> Result<Option<String>, Diagnostic> {
    match values {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        _ => Err(usage(format!("unexpected argument for tool {command}"))),
    }
}

fn optional_path(
    command: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<Option<String>, Diagnostic> {
    let path = arguments.next();
    reject_remaining(command, arguments)?;
    Ok(path)
}

/// A required argument followed by an optional one, read **without rejecting in between**.
///
/// `required_argument` calls `reject_remaining`, which is right when nothing follows and
/// wrong the moment something does: the leftover is consumed as an error before the
/// caller can look at it. That is what made `config get <key> <path>` impossible, and it
/// is the reason this exists rather than a call to `required_argument` followed by
/// `optional_path` -- the composition that reads correctly and does not work.
fn key_then_optional_path(
    command: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(String, Option<String>), Diagnostic> {
    let key = arguments
        .next()
        .ok_or_else(|| usage(format!("missing key for {command}")))?;
    let path = arguments.next();
    // **A key that is a path is the mistake worth naming.** Without this the reversed
    // order fails as "explicit project configuration does not exist", which sends the
    // reader looking for a missing project file rather than at their own argument order.
    if path.is_some() && std::path::Path::new(&key).is_file() {
        return Err(usage(format!(
            "{key:?} is a file, so it is the project path, not the key. \
             The order is `{command} <key> [path]`."
        )));
    }
    reject_remaining(command, arguments)?;
    Ok((key, path))
}

/// A required key, a required value, and an optional path, read without rejecting between.
///
/// Same reason as [`key_then_optional_path`]: `required_argument` rejects what is left, so
/// composing two of them could never accept a third argument. Three in a row is the case
/// where the composition is most tempting and most wrong, so it gets its own function
/// rather than a third call.
fn key_value_then_optional_path(
    command: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(String, String, Option<String>), Diagnostic> {
    let key = arguments
        .next()
        .ok_or_else(|| usage(format!("missing key for {command}")))?;
    let value = arguments
        .next()
        .ok_or_else(|| usage(format!("missing value for {command}")))?;
    let path = arguments.next();
    if path.is_some() && std::path::Path::new(&key).is_file() {
        return Err(usage(format!(
            "{key:?} is a file, so it is the project path, not the key. \
             The order is `{command} <key> <value> [path]`."
        )));
    }
    reject_remaining(command, arguments)?;
    Ok((key, value, path))
}

fn required_argument(
    command: &str,
    name: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<String, Diagnostic> {
    let argument = arguments
        .next()
        .ok_or_else(|| usage(format!("missing {name} for {command}")))?;
    reject_remaining(command, arguments)?;
    Ok(argument)
}

fn reject_remaining(
    command: &str,
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(), Diagnostic> {
    if let Some(argument) = arguments.next() {
        Err(usage(format!(
            "unexpected argument for {command}: {argument}"
        )))
    } else {
        Ok(())
    }
}

fn usage(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Usage, "NEO001", message)
}
