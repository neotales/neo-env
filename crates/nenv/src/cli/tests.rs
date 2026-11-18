//! Parser tests plus the tree/contract drift guard. `validate_tree` fails
//! when a command node gains a child or option that has no parser case.

use std::collections::BTreeSet;

use super::{
    Command, Invocation, OutputFormat, RemoteCommand, RunOverrides, RuntimeCommand, SelfCommand,
    TaskCommand, ToolCommand, ToolScope, TrustCommand, help_text_for, parse,
};
use crate::command_tree::{CommandAction, CommandSpec, CommandVisibility, OptionId, ROOT};
use neoenv_core::ExitCategory;

const PARSER_DRIFT: CommandSpec = CommandSpec {
    name: "parser-drift",
    aliases: &[],
    visibility: CommandVisibility::Public,
    description: "A node without unique parser wiring.",
    usage: "nenv parser-drift",
    arguments: &[],
    options: ROOT.options,
    output: ROOT.output,
    action: CommandAction::Inspect,
    children: &[],
};
const DRIFTED_ROOT: CommandSpec = CommandSpec {
    children: &[ROOT, PARSER_DRIFT],
    ..ROOT
};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[derive(Clone)]
struct VisibleEntry {
    path: Vec<&'static str>,
    command: &'static CommandSpec,
}

fn visible_entries(command: &'static CommandSpec, parents: &[&'static str]) -> Vec<VisibleEntry> {
    if !command.is_public() {
        return Vec::new();
    }
    let mut path = parents.to_vec();
    if command.action != CommandAction::Root {
        path.push(command.name);
    }
    let mut entries = vec![VisibleEntry { path, command }];
    for child in command.children {
        let child_parents = if command.action == CommandAction::Root {
            Vec::new()
        } else {
            let mut child_parents = parents.to_vec();
            child_parents.push(command.name);
            child_parents
        };
        entries.extend(visible_entries(child, &child_parents));
    }
    entries
}

fn same_node(left: &CommandSpec, right: &CommandSpec) -> bool {
    left.action == right.action && left.usage == right.usage
}

fn validate_tree(command: &CommandSpec) -> Result<(), String> {
    fn visit(command: &CommandSpec, actions: &mut BTreeSet<CommandAction>) -> Result<(), String> {
        if command.name.is_empty() || command.description.is_empty() || command.usage.is_empty() {
            return Err(format!("incomplete command node {}", command.name));
        }
        if !command.accepts_help() {
            return Err(format!("{} does not accept both help flags", command.name));
        }
        let mut option_ids = BTreeSet::new();
        for option in command.options {
            if option.id() == OptionId::Unspecified {
                return Err(format!("{} has an untyped option", command.name));
            }
            if !option_ids.insert(option.id()) {
                return Err(format!("{} repeats a typed option", command.name));
            }
        }
        let is_group = matches!(
            command.action,
            CommandAction::SelfGroup
                | CommandAction::TaskGroup
                | CommandAction::ToolGroup
                | CommandAction::TrustGroup
                | CommandAction::WorkspaceGroup
                | CommandAction::RemoteGroup
                | CommandAction::ShellGroup
                // A group node declares no `--format` of its own; its children do, and
                // the leaf arm below checks each of those. Adding `runtime` here is the
                // whole contract for the new group, and forgetting it is not silent: the
                // leaf arm then treats the group as a command, finds JSON output with no
                // format option, and fails with "runtime has an output/format contract
                // drift". That is the guard doing the job it was written for, on the
                // first run of the thing it was written to police.
                | CommandAction::RuntimeGroup
                // Same shape as `runtime`, and the same reason: `context` is a group
                // whose children carry the `--format` option, not the group itself.
                | CommandAction::ContextGroup
                // A group declares no `--format` of its own; its children do.
                | CommandAction::ConfigGroup
                | CommandAction::JobGroup
                | CommandAction::InventoryGroup
                | CommandAction::ShipGroup
        );
        if !is_group && command.output.json != command.option(OptionId::Format).is_some() {
            return Err(format!(
                "{} has an output/format contract drift",
                command.name
            ));
        }
        if !actions.insert(command.action) {
            return Err(format!(
                "{} reuses parser action {:?}",
                command.name, command.action
            ));
        }
        let sibling_names = command
            .children
            .iter()
            .flat_map(CommandSpec::command_names)
            .collect::<BTreeSet<_>>();
        if sibling_names.len()
            != command
                .children
                .iter()
                .map(|child| 1 + child.aliases.len())
                .sum::<usize>()
        {
            return Err(format!("{} has a duplicate name or alias", command.name));
        }
        for child in command.children {
            visit(child, actions)?;
        }
        Ok(())
    }

    visit(command, &mut BTreeSet::new())
}

#[test]
#[allow(clippy::too_many_lines)]
fn parses_read_only_commands() {
    assert_eq!(
        parse(arguments(&["inspect", "neoenv.toml", "--format", "json"])),
        Ok(Invocation {
            command: Command::Inspect {
                path: Some("neoenv.toml".into()),
            },
            format: OutputFormat::Json,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "plan", "--locked", "neoenv.toml"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Plan {
                    path: Some("neoenv.toml".into()),
                    locked: true
                }
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["trust", "status"])),
        Ok(Invocation {
            command: Command::Trust {
                command: TrustCommand::Status
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["trust", "add", ".\\neoenv.toml"])),
        Ok(Invocation {
            command: Command::Trust {
                command: TrustCommand::AddProject {
                    path: ".\\neoenv.toml".into(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["trust", "add", "github:octo/repo@tag:v1"])),
        Ok(Invocation {
            command: Command::Trust {
                command: TrustCommand::AddRepository {
                    repository: "github:octo/repo@tag:v1".into(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["trust", "remove", "github:octo/repo"])),
        Ok(Invocation {
            command: Command::Trust {
                command: TrustCommand::RemoveRepository {
                    repository: "github:octo/repo".into(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["init"])),
        Ok(Invocation {
            command: Command::Shortcut {
                name: "init".into(),
                arguments: Vec::new(),
                builtin: SelfCommand::Init,
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["remote", "inspect", "github:octo/repo@tag:v1"])),
        Ok(Invocation {
            command: Command::Remote {
                command: RemoteCommand::Inspect {
                    source: "github:octo/repo@tag:v1".into()
                }
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["remote", "install", "github:octo/repo@tag:v1"])),
        Ok(Invocation {
            command: Command::Remote {
                command: RemoteCommand::Install {
                    source: "github:octo/repo@tag:v1".into(),
                    path: None,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&[
            "task",
            "plan",
            "build",
            "neoenv.yaml",
            "--context",
            "prod"
        ])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Plan {
                    task: "build".into(),
                    path: Some("neoenv.yaml".into())
                }
            },
            format: OutputFormat::Text,
            context: Some("prod".into()),
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn reports_usage_errors() {
    let error = parse(arguments(&["completion"])).unwrap_err();
    assert_eq!(error.exit_category(), ExitCategory::Usage);
    assert_eq!(error.code, "NEO001");
}

#[test]
fn provides_focused_help_from_the_command_tree() {
    let invocation = parse(arguments(&["task", "run", "--help"])).unwrap();
    let command = match invocation.command {
        Command::Help { command } => command,
        command => panic!("expected command help, got {command:?}"),
    };
    let task_run = ROOT.child("task").unwrap().child("run").unwrap();
    assert_eq!(command.action, task_run.action);
    assert_eq!(command.usage, task_run.usage);
    assert!(help_text_for(command).contains(command.description));

    let root = help_text_for(&ROOT);
    assert!(root.contains("Usage:\n  nenv [command] [options]"));
    assert!(root.contains("  init"));
    assert!(root.contains("Create an nenv configuration"));
    assert!(root.contains("  task       Plan, describe, and run project tasks."));
    assert!(!root.contains("completion"));
    assert!(!root.contains("shell"));
    assert!(root.ends_with("Configuration format version: 1"));

    let task = ROOT.child("task").unwrap();
    let task_help = help_text_for(task);
    assert!(task_help.contains("Usage:\n  nenv task <command> [options]"));
    assert!(task_help.contains("  run        Run a task after capability-policy checks."));
    assert!(!task_help.contains("  tool"));
}

#[test]
fn command_tree_contract_covers_help_aliases_and_parser_wiring() {
    validate_tree(&ROOT).expect("the production command tree is fully wired");
    let entries = visible_entries(&ROOT, &[]);
    assert!(entries.len() > 1);
    for entry in entries {
        let mut canonical = entry.path.clone();
        let canonical_target = if entry.command.action == CommandAction::Root {
            &ROOT
        } else {
            canonical.push("--help");
            let invocation = parse(arguments(&canonical)).unwrap();
            match invocation.command {
                Command::Help { command } => command,
                command => panic!("expected help for {canonical:?}, got {command:?}"),
            }
        };
        let rendered = help_text_for(entry.command);
        assert!(
            rendered.contains(entry.command.description),
            "help omits declared description for {}",
            entry.command.usage
        );
        for flag in ["-h", "--help"] {
            let mut values = entry.path.clone();
            values.push(flag);
            let target = match parse(arguments(&values)).unwrap().command {
                Command::Help { command } => command,
                command => panic!("expected help for {values:?}, got {command:?}"),
            };
            assert!(
                same_node(target, entry.command),
                "{} resolved to {:?} {} instead of {:?} {}",
                values.join(" "),
                target.action,
                target.usage,
                entry.command.action,
                entry.command.usage
            );
        }
        for alias in entry.command.aliases {
            let mut values = entry.path.clone();
            let Some(last) = values.last_mut() else {
                continue;
            };
            *last = alias;
            values.push("--help");
            let target = match parse(arguments(&values)).unwrap().command {
                Command::Help { command } => command,
                command => panic!("expected help for alias {values:?}, got {command:?}"),
            };
            assert!(same_node(target, entry.command));
            assert!(same_node(canonical_target, entry.command));
        }
    }
}

#[test]
fn root_help_hides_internal_commands_that_remain_invocable() {
    let root_help = help_text_for(&ROOT);
    for hidden in ROOT
        .children
        .iter()
        .filter(|command| command.visibility == CommandVisibility::Hidden)
    {
        assert!(!root_help.contains(hidden.name));
    }
    assert!(matches!(
        parse(arguments(&["completion", "bash"])),
        Ok(Invocation {
            command: Command::Completion { .. },
            profile: neoenv_config::ConfigProfile::Native,
            ..
        })
    ));
    assert!(matches!(
        parse(arguments(&["shell", "activate", "bash"])),
        Ok(Invocation {
            command: Command::Shell { .. },
            profile: neoenv_config::ConfigProfile::Native,
            ..
        })
    ));
    assert!(matches!(
        parse(arguments(&["task", "complete"])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Complete { .. }
            },
            profile: neoenv_config::ConfigProfile::Native,
            ..
        })
    ));
}

#[test]
fn adding_a_node_without_unique_parser_wiring_is_rejected() {
    let error = validate_tree(&DRIFTED_ROOT).expect_err("duplicate parser wiring must fail");
    assert!(error.contains("reuses parser action"));
}

#[test]
fn unknown_child_with_help_returns_parent_help_and_a_focused_diagnostic() {
    let invocation = parse(arguments(&["task", "use", "-h"])).expect("parse succeeds");
    assert_eq!(invocation.format, OutputFormat::Text);
    match invocation.command {
        Command::HelpError {
            command,
            diagnostic,
        } => {
            assert!(same_node(command, ROOT.child("task").unwrap()));
            assert!(diagnostic.message.contains("unknown task subcommand: use"));
            assert!(diagnostic.message.contains("did you mean"));
        }
        command => panic!("expected focused help error, got {command:?}"),
    }
}

/// Every public group must reject an unknown child with the same focused
/// diagnostic. The set of groups is derived from the tree, so adding one cannot
/// silently fall out of this behaviour.
#[test]
fn every_public_group_rejects_an_unknown_child_with_help() {
    fn visit(command: &'static CommandSpec) {
        if !command.is_public() || command.children.is_empty() {
            return;
        }
        let invocation = [command.name, "definitely-not-a-subcommand", "-h"];
        match parse(arguments(&invocation))
            .expect("parse succeeds")
            .command
        {
            Command::HelpError { diagnostic, .. } => {
                assert!(
                    diagnostic
                        .message
                        .contains(&format!("unknown {} subcommand", command.name)),
                    "{}: {}",
                    command.name,
                    diagnostic.message
                );
                assert_eq!(
                    diagnostic.category,
                    super::DiagnosticCategory::Usage,
                    "{} must stay a usage error",
                    command.name
                );
            }
            other => panic!(
                "expected focused help error for {}, got {other:?}",
                command.name
            ),
        }
        for child in command.children {
            visit(child);
        }
    }
    for child in ROOT.children {
        visit(child);
    }
}

#[test]
fn does_not_treat_passthrough_help_as_a_cli_help_request() {
    assert_eq!(
        parse(arguments(&["task", "run", "build", "--", "--help"])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Run {
                    task: "build".into(),
                    path: None,
                    dry_run: false,
                    capability_policy: None,
                    passthrough: vec!["--".into(), "--help".into()],
                    overrides: RunOverrides::default(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_task_run_options_and_passthrough() {
    assert_eq!(
        parse(arguments(&[
            "task",
            "run",
            "build",
            "config.yaml",
            "--dry-run",
            "--",
            "--flag",
            "value"
        ])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Run {
                    task: "build".into(),
                    path: Some("config.yaml".into()),
                    dry_run: true,
                    capability_policy: None,
                    passthrough: vec!["--".into(), "--flag".into(), "value".into()],
                    overrides: RunOverrides::default(),
                }
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn preserves_path_like_task_positionals_unless_they_name_configuration() {
    assert_eq!(
        parse(arguments(&["run", "build", "apps/frontend"])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Run {
                    task: "build".into(),
                    path: None,
                    dry_run: false,
                    capability_policy: None,
                    passthrough: vec!["apps/frontend".into()],
                    overrides: RunOverrides::default(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_legacy_task_run_aliases_and_direct_task_names() {
    for alias in ["run", "r"] {
        assert_eq!(
            parse(arguments(&[alias, "build"])),
            Ok(Invocation {
                command: Command::Task {
                    command: TaskCommand::Run {
                        task: "build".into(),
                        path: None,
                        dry_run: false,
                        capability_policy: None,
                        passthrough: Vec::new(),
                        overrides: RunOverrides::default(),
                    },
                },
                format: OutputFormat::Text,
                context: None,
                profile: neoenv_config::ConfigProfile::Native,
            })
        );
    }
    assert_eq!(
        parse(arguments(&["build", "--", "--release"])),
        Ok(Invocation {
            command: Command::TaskShortcut {
                task: "build".into(),
                arguments: vec!["--".into(), "--release".into()],
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_task_capability_policy_injection() {
    assert_eq!(
        parse(arguments(&[
            "task",
            "run",
            "build",
            "--capability-policy",
            "policy.toml"
        ])),
        Ok(Invocation {
            command: Command::Task {
                command: TaskCommand::Run {
                    task: "build".into(),
                    path: None,
                    dry_run: false,
                    capability_policy: Some("policy.toml".into()),
                    passthrough: Vec::new(),
                    overrides: RunOverrides::default(),
                }
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_shell_activation() {
    assert_eq!(
        parse(arguments(&["shell", "activate", "bash", "neoenv.yaml"])),
        Ok(Invocation {
            command: Command::Shell {
                shell: "bash".into(),
                path: Some("neoenv.yaml".into())
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn scope_and_project_path_cannot_be_supplied_together() {
    for args in [
        vec!["tool", "list", "--user", "project.yaml"],
        vec!["tool", "which", "--global", "demo", "project.yaml"],
        vec!["tool", "where", "--user", "demo", "project.yaml"],
        vec!["tool", "cleanup", "--global", "project.yaml", "--dry-run"],
    ] {
        let error = parse(arguments(&args)).expect_err("scope + project path");
        assert!(
            error.message.contains("does not accept a project path"),
            "{args:?}: {error}"
        );
    }
}

#[test]
fn parses_controlled_tool_lifecycle_commands() {
    assert_eq!(
        parse(arguments(&["tool", "where", "demo", "project.yaml"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Where {
                    executable: "demo".into(),
                    path: Some("project.yaml".into()),
                    scope: None,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&[
            "tool",
            "use",
            "demo",
            "project.yaml",
            "--",
            "--flag"
        ])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Use {
                    executable: "demo".into(),
                    path: Some("project.yaml".into()),
                    arguments: vec!["--flag".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_task_overridable_shortcuts_and_self_builtins() {
    assert_eq!(
        parse(arguments(&["use", "-g", "dotnet"])),
        Ok(Invocation {
            command: Command::Shortcut {
                name: "use".into(),
                arguments: vec!["-g".into(), "dotnet".into()],
                builtin: SelfCommand::Use {
                    arguments: Vec::new(),
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["self", "use", "-g", "dotnet"])),
        Ok(Invocation {
            command: Command::Self_ {
                command: SelfCommand::Use {
                    arguments: vec!["-g".into(), "dotnet".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "use", "-g", "dotnet"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::GlobalUse {
                    arguments: vec!["-g".into(), "dotnet".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_global_tool_removal_without_accepting_project_paths() {
    assert_eq!(
        parse(arguments(&["tool", "remove", "--global", "node", "zig"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Remove {
                    scope: ToolScope::Global,
                    tools: vec!["node".into(), "zig".into()],
                    dry_run: false,
                }
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert!(parse(arguments(&["tool", "remove", "node"])).is_err());
}

#[test]
fn tool_use_scope_flags_stop_at_the_separator() {
    assert_eq!(
        parse(arguments(&["tool", "use", "demo", "--", "-g"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Use {
                    executable: "demo".into(),
                    path: None,
                    arguments: vec!["-g".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "use", "demo", "--", "-u"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Use {
                    executable: "demo".into(),
                    path: None,
                    arguments: vec!["-u".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "use", "-g", "demo", "--", "-u"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::GlobalUse {
                    arguments: vec!["-g".into(), "demo".into(), "--".into(), "-u".into()],
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn short_g_is_the_system_scope_alias() {
    assert_eq!(
        parse(arguments(&["tool", "pin", "-g", "node"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Pin {
                    scope: ToolScope::Global,
                    tools: vec!["node".into()],
                    dry_run: false,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_global_tool_pin_unpin_and_purge() {
    assert_eq!(
        parse(arguments(&["tool", "pin", "--user", "node@22.0.0"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Pin {
                    scope: ToolScope::User,
                    tools: vec!["node@22.0.0".into()],
                    dry_run: false,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "unpin", "--user", "node"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Unpin {
                    scope: ToolScope::User,
                    tools: vec!["node".into()],
                    dry_run: false,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert_eq!(
        parse(arguments(&["tool", "purge", "--user"])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Purge {
                    scope: ToolScope::User,
                    tools: Vec::new(),
                    dry_run: false,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
}

#[test]
fn parses_explicit_project_lifecycle_scope_and_dry_run() {
    assert_eq!(
        parse(arguments(&[
            "tool",
            "update",
            "--project",
            "--dry-run",
            "demo"
        ])),
        Ok(Invocation {
            command: Command::Tool {
                command: ToolCommand::Update {
                    scope: ToolScope::Project,
                    tools: vec!["demo".into()],
                    dry_run: true,
                },
            },
            format: OutputFormat::Text,
            context: None,
            profile: neoenv_config::ConfigProfile::Native,
        })
    );
    assert!(parse(arguments(&["tool", "purge", "--project", "--global"])).is_err());
    assert!(parse(arguments(&["tool", "purge", "--global", "npm:@scope/demo"])).is_ok());
    assert!(
        parse(arguments(&[
            "tool",
            "purge",
            "--global",
            "npm:@scope/demo@2.0.0"
        ]))
        .is_err()
    );
}

/// **The `runtime` group parses to the two read-only verbs, and refuses anything else.**
///
/// A user who installed a runtime had no way to ask what was installed: the only route
/// was `nenv tool global-use <name>`, which is an install, not a query. `list` and
/// `where` are the two answers that need no network, and they are the two the installed
/// state can actually support — so they are the two that exist.
///
/// The rejection rows matter as much as the acceptance rows. A verb that parses and then
/// does the wrong thing is worse than one that refuses, and `runtime list go` must not
/// silently become `list` with a stray argument.
#[test]
fn the_runtime_group_parses_only_its_read_only_verbs() {
    // Reduce the whole invocation to the runtime command, so each row asserts the
    // verb rather than the surrounding envelope that eight other rows already cover.
    let verb = |tokens: &[&str]| match parse(arguments(tokens)) {
        Ok(Invocation {
            command: Command::Runtime { command },
            ..
        }) => Ok(command),
        Ok(other) => panic!("expected a runtime command, got {other:?}"),
        Err(error) => Err(error),
    };

    assert_eq!(verb(&["runtime", "list"]), Ok(RuntimeCommand::List));
    assert_eq!(
        verb(&["runtime", "ls"]),
        Ok(RuntimeCommand::List),
        "the `ls` alias must work, or muscle memory sends the user to an error"
    );
    assert_eq!(
        verb(&["runtime", "where", "go"]),
        Ok(RuntimeCommand::Where {
            runtime: "go".into()
        })
    );
    // **A stray argument is refused, not ignored.** Without this row, `runtime list go`
    // would report every runtime and the user would believe it had filtered.
    assert!(
        parse(arguments(&["runtime", "list", "go"])).is_err(),
        "`runtime list` must refuse an argument rather than ignore it"
    );
    // `where` needs a name; without one there is nothing to answer about.
    assert!(
        parse(arguments(&["runtime", "where"])).is_err(),
        "`runtime where` must require a runtime name"
    );
    // **The verbs that need a version index are refused rather than faked.** `update` and
    // `upgrade` require resolving a latest version, which is the fetch half of
    // `RuntimeLayout` and does not exist yet. A partial answer would be worse than the
    // error, because the user cannot tell a refusal from a result.
    for unimplemented in ["update", "upgrade", "install", "remove"] {
        assert!(
            parse(arguments(&["runtime", unimplemented])).is_err(),
            "`runtime {unimplemented}` is not implemented and must be a named refusal"
        );
    }
}
