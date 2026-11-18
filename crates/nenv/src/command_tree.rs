#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandVisibility {
    Public,
    Hidden,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CommandAction {
    Root,
    Help,
    InitShortcut,
    UseShortcut,
    SelfGroup,
    SelfInit,
    SelfUse,
    Validate,
    Inspect,
    Exec,
    TaskGroup,
    RunShortcut,
    TaskList,
    TaskHelp,
    TaskPlan,
    TaskRun,
    TaskComplete,
    ToolGroup,
    ToolPlan,
    ToolLock,
    ToolVerify,
    ToolInstall,
    ToolList,
    ToolWhich,
    ToolWhere,
    ToolUse,
    ToolRemove,
    ToolUpdate,
    ToolPin,
    ToolUnpin,
    ToolPurge,
    ToolCleanup,
    TrustGroup,
    TrustStatus,
    TrustAdd,
    TrustRemove,
    TrustRevoke,
    WorkspaceGroup,
    WorkspaceList,
    ConfigGroup,
    ConfigList,
    ConfigGet,
    ConfigSet,
    ConfigUnset,
    JobGroup,
    JobList,
    JobHelp,
    JobRun,
    InventoryGroup,
    InventoryList,
    Ssh,
    Scp,
    ShipGroup,
    ShipList,
    ShipDeploy,
    ShipRollback,
    ShipDestroy,
    ContextGroup,
    ContextCurrent,
    ContextList,
    /// Native runtimes this project can install, and the ones that are installed.
    ///
    /// A first-class group rather than more `tool global-use` spellings: a runtime and
    /// a tool are different things with different lifecycles, and until this existed the
    /// only way to ask what was installed was to know that runtimes were files in a
    /// directory nothing read back.
    RuntimeGroup,
    RuntimeList,
    RuntimeWhere,
    SecretGroup,
    SecretGet,
    SecretSet,
    RemoteGroup,
    RemoteInspect,
    RemoteFetch,
    RemoteInstall,
    RemoteUpdate,
    RemoteClear,
    ShellGroup,
    ShellActivate,
    Completion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArgumentCardinality {
    Required,
    Optional,
    OneOrMore,
    ZeroOrMore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandArgument {
    pub name: &'static str,
    pub description: &'static str,
    pub cardinality: ArgumentCardinality,
    pub choices: &'static [&'static str],
}

impl CommandArgument {
    pub const fn required(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            cardinality: ArgumentCardinality::Required,
            choices: &[],
        }
    }

    pub const fn optional(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            cardinality: ArgumentCardinality::Optional,
            choices: &[],
        }
    }

    pub const fn one_or_more(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            cardinality: ArgumentCardinality::OneOrMore,
            choices: &[],
        }
    }

    pub const fn zero_or_more(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            cardinality: ArgumentCardinality::ZeroOrMore,
            choices: &[],
        }
    }

    pub const fn required_choices(
        name: &'static str,
        description: &'static str,
        choices: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            description,
            cardinality: ArgumentCardinality::Required,
            choices,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum OptionId {
    Help,
    Version,
    Format,
    Context,
    User,
    Global,
    DryRun,
    Locked,
    Project,
    /// `--remote` on `trust add` and `trust remove`: the target is a cached
    /// remote file identity rather than a local path.
    Remote,
    CapabilityPolicy,
    /// `-E/--dotenv` and `-e/--env` on `run` and `exec`. Both are repeatable
    /// and take a value; the tree records the spelling only and the parser is
    /// what accumulates occurrences, so `OptionValue` stays `Copy`.
    Dotenv,
    Env,
    /// Selects the configuration dialect a document is read as. Opt-in only:
    /// `native` is the strict v1 schema and remains the default.
    Profile,
    /// Which declared host list `ssh`/`scp` resolve against. A value, and the
    /// reason the inventory is a parameter rather than a convention.
    Inventory,
    /// The direction of an `scp` copy: remote to local rather than local to remote.
    Pull,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionValue {
    None,
    Required {
        name: &'static str,
        choices: &'static [&'static str],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandOption {
    pub short: &'static str,
    pub long: &'static str,
    pub value: OptionValue,
    pub description: &'static str,
}

impl CommandOption {
    pub const fn flag(short: &'static str, long: &'static str, description: &'static str) -> Self {
        Self {
            short,
            long,
            value: OptionValue::None,
            description,
        }
    }

    pub const fn value(
        short: &'static str,
        long: &'static str,
        name: &'static str,
        choices: &'static [&'static str],
        description: &'static str,
    ) -> Self {
        Self {
            short,
            long,
            value: OptionValue::Required { name, choices },
            description,
        }
    }

    pub fn id(&self) -> OptionId {
        match self.long {
            "--help" => OptionId::Help,
            "--version" => OptionId::Version,
            "--format" => OptionId::Format,
            "--context" => OptionId::Context,
            "--user" | "-u" => OptionId::User,
            "-g" | "--global" => OptionId::Global,
            // `--plan` is the reference's spelling and `--dry-run` its alias
            // (`cli.go:2468`); the same id for both says so in one place instead of
            // the parser carrying a string comparison.
            "--dry-run" | "--plan" => OptionId::DryRun,
            "--locked" => OptionId::Locked,
            "--project" => OptionId::Project,
            "--remote" => OptionId::Remote,
            "--capability-policy" => OptionId::CapabilityPolicy,
            "--dotenv" => OptionId::Dotenv,
            "--env" => OptionId::Env,
            "--profile" => OptionId::Profile,
            "--inventory" => OptionId::Inventory,
            "--pull" => OptionId::Pull,
            _ => OptionId::Unspecified,
        }
    }

    pub fn display(&self) -> String {
        let mut spelling = String::new();
        if !self.short.is_empty() {
            spelling.push_str(self.short);
            if !self.long.is_empty() {
                spelling.push_str(", ");
            }
        }
        spelling.push_str(self.long);
        if let OptionValue::Required { name, .. } = self.value {
            spelling.push(' ');
            spelling.push('<');
            spelling.push_str(name);
            spelling.push('>');
        }
        spelling
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputSupport {
    pub text: bool,
    pub json: bool,
}

impl OutputSupport {
    pub const TEXT: Self = Self {
        text: true,
        json: false,
    };

    pub const TEXT_AND_JSON: Self = Self {
        text: true,
        json: true,
    };
}

pub(crate) const COMPLETION_SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell", "nushell"];

const HELP_OPTION: CommandOption = CommandOption::flag("-h", "--help", "Show this help.");
const ROOT_HELP_OPTION: CommandOption =
    CommandOption::flag("-h", "--help", "Show help for a command.");
const FORMAT_OPTION: CommandOption = CommandOption::value(
    "",
    "--format",
    "text|json",
    &["text", "json"],
    "Select output format.",
);
// Deliberately long-form only. `run` accepts its own options *after* the task
// name, so a `-c` short form would be stolen from any task that binds `-c` as an
// input: the `task_inputs_bind_positions_options_repetition_and_help_for_every_
// entry_point` case passes `-c 2` as a task input. `-c` is also an ordinary
// program flag for `exec` (`sh -c`, `git -c`). `--context` keeps working
// everywhere, and `parse_global_options` stops claiming it once `exec` reaches
// the program name.
const PROFILE_OPTION: CommandOption = CommandOption::value(
    "",
    "--profile",
    "native|go",
    &["native", "go"],
    "Read a Go nenv document through the compatibility profile. Applies to the \
     commands that read a configuration document; the rest ignore it, as they do \
     `--context`.",
);
const CONTEXT_OPTION: CommandOption =
    CommandOption::value("", "--context", "name", &[], "Select a task context.");
// `--project` also exists on the tool lifecycle commands, where it is a boolean
// scope flag rather than a value. `option_matches` is per-command, so there is
// no runtime collision, but both spellings resolve to `OptionId::Project` and
// the difference is the `value` here.
const RUN_PROJECT_OPTION: CommandOption = CommandOption::value(
    "-p",
    "--project",
    "path",
    &[],
    "Select the project configuration or workspace alias.",
);
const RUN_DOTENV_OPTION: CommandOption = CommandOption::value(
    "-E",
    "--dotenv",
    "path",
    &[],
    "Import a dotenv file for this run. Repeatable, applied in order.",
);
const RUN_ENV_OPTION: CommandOption = CommandOption::value(
    "-e",
    "--env",
    "KEY=VALUE",
    &[],
    "Set one environment variable for this run. Repeatable, applied in order.",
);
const RUN_OVERRIDE_OPTIONS: &[CommandOption] = &[
    RUN_PROJECT_OPTION,
    RUN_DOTENV_OPTION,
    RUN_ENV_OPTION,
    HELP_OPTION,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub visibility: CommandVisibility,
    pub description: &'static str,
    pub usage: &'static str,
    pub arguments: &'static [CommandArgument],
    pub options: &'static [CommandOption],
    pub output: OutputSupport,
    pub action: CommandAction,
    pub children: &'static [CommandSpec],
}

/// The single command-specification boundary consumed by parsers and renderers.
///
/// Parsing and presentation may depend on this tree, but they do not own
/// or mutate the command declarations themselves.
impl CommandSpec {
    pub fn matches(&self, candidate: &str) -> bool {
        self.name == candidate || self.aliases.contains(&candidate)
    }

    /// Finds the node that owns `action`, searching this node's subtree.
    ///
    /// `ROOT` is the only entry point into the tree; there is no parallel
    /// catalog, so a lookup can never disagree with the declared structure.
    pub fn find(&'static self, action: CommandAction) -> Option<&'static Self> {
        if self.action == action {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.find(action))
    }

    pub fn child(&self, candidate: &str) -> Option<&'static Self> {
        self.children
            .iter()
            .find(|command| command.matches(candidate))
    }

    pub fn is_public(&self) -> bool {
        self.visibility == CommandVisibility::Public
    }

    pub fn option(&self, id: OptionId) -> Option<&'static CommandOption> {
        self.options.iter().find(|option| option.id() == id)
    }

    pub fn accepts_option(&self, id: OptionId, token: &str) -> bool {
        self.option(id).is_some_and(|option| {
            (!option.short.is_empty() && option.short == token)
                || (!option.long.is_empty() && option.long == token)
        })
    }

    pub fn accepts_help(&self) -> bool {
        self.options
            .iter()
            .any(|option| option.short == "-h" && option.long == "--help")
    }

    pub fn command_names(&self) -> Vec<&'static str> {
        std::iter::once(self.name)
            .chain(self.aliases.iter().copied())
            .collect()
    }
}

const SELF_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "init",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Create a project configuration without task override.",
        usage: "nenv self init",
        arguments: &[],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::SelfInit,
        children: &[],
    },
    CommandSpec {
        name: "use",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Select and install a native or provider-backed nenv tool without task override.",
        usage: "nenv self use [options] (--user|--global) <runtime|gh:owner/repo|provider:package>[@<version>]",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Runtime or provider-backed tool, optionally followed by a version.",
        )],
        options: &[
            CommandOption::flag(
                "-u",
                "--user",
                "Install for this user: configuration under NEOENV_CONFIG_HOME/XDG_CONFIG_HOME and binaries under NEOENV_DATA_HOME/XDG_DATA_HOME.",
            ),
            CommandOption::flag(
                "-g",
                "--global",
                "Install system-wide: configuration under NEOENV_GLOBAL_CONFIG_DIR or /etc/neoenv, binaries under NEOENV_GLOBAL_INSTALL_DIR or /usr/local/neoenv.",
            ),
            CommandOption::flag(
                "",
                "--dry-run",
                "Show the ordered install plan without downloading or changing configuration.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT,
        action: CommandAction::SelfUse,
        children: &[],
    },
];

const TASK_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "List available tasks.",
        usage: "nenv task list [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[CONTEXT_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskList,
        children: &[],
    },
    CommandSpec {
        name: "help",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show a task's resolved documentation.",
        usage: "nenv task help <task> [path]",
        arguments: &[
            CommandArgument::required("task", "Task name."),
            CommandArgument::optional("path", "Project configuration path."),
        ],
        options: &[CONTEXT_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskHelp,
        children: &[],
    },
    CommandSpec {
        name: "plan",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show the task execution plan without running it.",
        usage: "nenv task plan <task> [path]",
        arguments: &[
            CommandArgument::required("task", "Task name."),
            CommandArgument::optional("path", "Project configuration path."),
        ],
        options: &[CONTEXT_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskPlan,
        children: &[],
    },
    CommandSpec {
        name: "run",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Run a task after capability-policy checks.",
        usage: "nenv task run [<task>] [path] [options] [-- <arguments>...]",
        arguments: &[
            CommandArgument::optional("task", "Task name. Defaults to `default`."),
            CommandArgument::optional("path", "Project configuration path."),
            CommandArgument::zero_or_more("arguments", "Literal arguments passed after --."),
        ],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag("", "--dry-run", "Plan without executing actions."),
            CommandOption::value(
                "",
                "--capability-policy",
                "path",
                &[],
                "Use a specific capability policy file.",
            ),
            RUN_PROJECT_OPTION,
            RUN_DOTENV_OPTION,
            RUN_ENV_OPTION,
            CONTEXT_OPTION,
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskRun,
        children: &[],
    },
    CommandSpec {
        name: "complete",
        aliases: &[],
        visibility: CommandVisibility::Hidden,
        description: "Print task names for shell completion.",
        usage: "nenv task complete [task]",
        arguments: &[CommandArgument::optional(
            "task",
            "Task whose input options should be completed.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskComplete,
        children: &[],
    },
];

const TOOL_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "plan",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Resolve declared tools without installing.",
        usage: "nenv tool plan [path] [--locked]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag(
                "",
                "--locked",
                "Verify the existing lockfile instead of resolving.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolPlan,
        children: &[],
    },
    CommandSpec {
        name: "lock",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Write or verify the project lockfile.",
        usage: "nenv tool lock [path] [--locked]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag(
                "",
                "--locked",
                "Verify the existing lockfile instead of writing.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolLock,
        children: &[],
    },
    CommandSpec {
        name: "verify",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Verify the current lockfile.",
        usage: "nenv tool verify [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolVerify,
        children: &[],
    },
    CommandSpec {
        name: "install",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Install tools from the lockfile.",
        usage: "nenv tool install --locked [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag(
                "",
                "--locked",
                "Required: install only from the existing lockfile.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolInstall,
        children: &[],
    },
    CommandSpec {
        name: "list",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show installed-state for locked tools, or a global scope.",
        usage: "nenv tool list [path] [--user|--global]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[
            FORMAT_OPTION,
            PROFILE_OPTION,
            CommandOption::flag("-u", "--user", "Inspect this user's global tools."),
            CommandOption::flag("-g", "--global", "Inspect the system-wide global tools."),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolList,
        children: &[],
    },
    CommandSpec {
        name: "which",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print an installed executable path.",
        usage: "nenv tool which <executable> [path] [--user|--global]",
        arguments: &[
            CommandArgument::required("executable", "Installed executable name."),
            CommandArgument::optional("path", "Project configuration path."),
        ],
        options: &[
            FORMAT_OPTION,
            PROFILE_OPTION,
            CommandOption::flag("-u", "--user", "Resolve only this user's global tools."),
            CommandOption::flag(
                "-g",
                "--global",
                "Resolve only the system-wide global tools.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolWhich,
        children: &[],
    },
    CommandSpec {
        name: "where",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Alias for `tool which`.",
        usage: "nenv tool where <executable> [path] [--user|--global]",
        arguments: &[
            CommandArgument::required("executable", "Installed executable name."),
            CommandArgument::optional("path", "Project configuration path."),
        ],
        options: &[
            FORMAT_OPTION,
            PROFILE_OPTION,
            CommandOption::flag("-u", "--user", "Resolve only this user's global tools."),
            CommandOption::flag(
                "-g",
                "--global",
                "Resolve only the system-wide global tools.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolWhere,
        children: &[],
    },
    CommandSpec {
        name: "use",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Run a declared executable or install a global native/provider tool.",
        usage: "nenv tool use <executable> [path] [-- <arguments>...]\nnenv tool use (--user|--global) [--dry-run] <runtime|gh:owner/repo|provider:package>[@<version>]...",
        arguments: &[
            CommandArgument::required("executable", "Declared or global tool name."),
            CommandArgument::optional("path", "Project configuration path."),
            CommandArgument::zero_or_more(
                "arguments",
                "Literal executable arguments passed after --.",
            ),
        ],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag(
                "-u",
                "--user",
                "Install for this user beneath NEOENV_CONFIG_HOME/NEOENV_DATA_HOME.",
            ),
            CommandOption::flag(
                "-g",
                "--global",
                "Install system-wide beneath the system configuration and install roots.",
            ),
            CommandOption::flag(
                "",
                "--dry-run",
                "Show the ordered global install plan without downloading tools.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT,
        action: CommandAction::ToolUse,
        children: &[],
    },
    CommandSpec {
        name: "remove",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Remove a selected tool version or a whole tool.",
        usage: "nenv tool remove (--project|--user|--global) [--dry-run] <tool>[@<version>]...",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Tool name, optionally followed by a version.",
        )],
        options: LIFECYCLE_OPTIONS,
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolRemove,
        children: &[],
    },
    CommandSpec {
        name: "update",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Resolve and install an allowed newer tool version.",
        usage: "nenv tool update (--project|--user|--global) [--dry-run] <tool>[@<version>]...",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Tool name, optionally followed by a version.",
        )],
        options: LIFECYCLE_OPTIONS,
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolUpdate,
        children: &[],
    },
    CommandSpec {
        name: "pin",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Keep an installed tool version during purge.",
        usage: "nenv tool pin (--project|--user|--global) [--dry-run] <tool>[@<version>]...",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Tool name, optionally followed by a version.",
        )],
        options: LIFECYCLE_OPTIONS,
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolPin,
        children: &[],
    },
    CommandSpec {
        name: "unpin",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Allow a pinned tool version to be purged.",
        usage: "nenv tool unpin (--project|--user|--global) [--dry-run] <tool>[@<version>]...",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Tool name, optionally followed by a version.",
        )],
        options: LIFECYCLE_OPTIONS,
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolUnpin,
        children: &[],
    },
    CommandSpec {
        name: "purge",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Remove unreferenced nenv-owned tool versions.",
        usage: "nenv tool purge (--project|--user|--global) [--dry-run] [<tool>...]",
        arguments: &[CommandArgument::zero_or_more(
            "tool",
            "Optional tool name without a version.",
        )],
        options: LIFECYCLE_OPTIONS,
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolPurge,
        children: &[],
    },
    CommandSpec {
        name: "cleanup",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Remove unreferenced installed tools.",
        usage: "nenv tool cleanup [path] [--user|--global] [--dry-run]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag("-u", "--user", "Clean this user's global install."),
            CommandOption::flag("-g", "--global", "Clean the system-wide global install."),
            CommandOption::flag("", "--dry-run", "Report entries without removing them."),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolCleanup,
        children: &[],
    },
];

const TRUST_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "status",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show trust status for the current project.",
        usage: "nenv trust status\nnenv trust status --project <path>",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path when project status is requested.",
        )],
        options: &[
            CommandOption::flag(
                "",
                "--project",
                "Show trust status for an explicit project configuration.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TrustStatus,
        children: &[],
    },
    CommandSpec {
        name: "add",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Trust a project configuration or remote repository.",
        usage: "nenv trust add [--project] <path>\nnenv trust add <github:owner/repository>\nnenv trust add <file:///absolute/path>\nnenv trust add --remote <repository>@<commit>//<path>",
        arguments: &[CommandArgument::required(
            "target",
            "Project configuration path, remote repository, or cached remote file identity.",
        )],
        options: &[
            CommandOption::flag(
                "",
                "--project",
                "Treat the input as a project configuration path.",
            ),
            CommandOption::flag(
                "",
                "--remote",
                "Approve one cached remote file identity and display its digest.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TrustAdd,
        children: &[],
    },
    CommandSpec {
        name: "remove",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Remove a remote repository from the allow-list, or revoke a cached remote file.",
        usage: "nenv trust remove <github:owner/repository>\nnenv trust remove --remote <repository>@<commit>//<path>",
        arguments: &[CommandArgument::required(
            "repository",
            "Remote repository, or cached remote file identity with --remote.",
        )],
        options: &[
            CommandOption::flag(
                "",
                "--remote",
                "Revoke one cached remote file identity rather than a repository.",
            ),
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TrustRemove,
        children: &[],
    },
    CommandSpec {
        name: "revoke",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Revoke a local file's execution-trust record.",
        usage: "nenv trust revoke <path>",
        arguments: &[CommandArgument::required(
            "path",
            "Local configuration, module, or package file to revoke.",
        )],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TrustRevoke,
        children: &[],
    },
];

const SECRET_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "get",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print a secret from an OS credential-store reference.",
        usage: "nenv secret get <reference> [path]",
        arguments: &[
            CommandArgument::required("reference", "nsv:// reference to read."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::SecretGet,
        children: &[],
    },
    CommandSpec {
        name: "set",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Read a new value from standard input and store it in an OS credential store.",
        usage: "nenv secret set <reference> [path]",
        arguments: &[
            CommandArgument::required("reference", "nsv:// reference to write."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::SecretSet,
        children: &[],
    },
];

const RUNTIME_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        aliases: &["ls"],
        visibility: CommandVisibility::Public,
        description: "List the runtimes installed in nenv's global data directory.",
        usage: "nenv runtime list",
        arguments: &[],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RuntimeList,
        children: &[],
    },
    CommandSpec {
        name: "where",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print the directories a runtime contributes to the shell.",
        usage: "nenv runtime where <runtime>",
        arguments: &[CommandArgument::required(
            "runtime",
            "Runtime name, such as go, node or python.",
        )],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RuntimeWhere,
        children: &[],
    },
];

/// `--plan`, shared by the three lifecycle verbs so the three cannot drift on the
/// spelling of the flag.
///
/// **`--dry-run` is accepted as an alias and not declared**, for the same reason as
/// `ssh`'s: a `CommandOption` holds one long spelling, and the tree contract rightly
/// refuses two options sharing an `OptionId`.
const SHIP_PLAN_OPTION: CommandOption = CommandOption::flag(
    "",
    "--plan",
    "Print what would happen, without acting. `--dry-run` is accepted as an alias.",
);

const SHIP_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        aliases: &["ls"],
        visibility: CommandVisibility::Public,
        description: "List the deployment workflows this project declares.",
        usage: "nenv ship list [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project directory or configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ShipList,
        children: &[],
    },
    // The five lifecycle verbs, each its own node with its own action, because a tree
    // node is what the help and the manifest enumerate. `up` and `down` are aliases of
    // `deploy` and `destroy` rather than separate nodes: the reference's
    // `isShipLifecycle` treats them as the same verbs, and a second node would put
    // them in the help twice.
    CommandSpec {
        name: "deploy",
        aliases: &["up"],
        visibility: CommandVisibility::Public,
        description: "Resolve a deployment, then refuse: deployment is not implemented yet.",
        usage: "nenv ship deploy [name] [flags]",
        arguments: &[CommandArgument::optional(
            "name",
            "The deployment to act on. Defaults to the one this context selects.",
        )],
        options: &[SHIP_PLAN_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ShipDeploy,
        children: &[],
    },
    CommandSpec {
        name: "rollback",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Resolve a deployment, then refuse: rollback is not implemented yet.",
        usage: "nenv ship rollback [name] [flags]",
        arguments: &[CommandArgument::optional(
            "name",
            "The deployment to act on. Defaults to the one this context selects.",
        )],
        options: &[SHIP_PLAN_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ShipRollback,
        children: &[],
    },
    CommandSpec {
        name: "destroy",
        aliases: &["down"],
        visibility: CommandVisibility::Public,
        description: "Resolve a deployment, then refuse: destroy is not implemented yet.",
        usage: "nenv ship destroy [name] [flags]",
        arguments: &[CommandArgument::optional(
            "name",
            "The deployment to act on. Defaults to the one this context selects.",
        )],
        options: &[SHIP_PLAN_OPTION, FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ShipDestroy,
        children: &[],
    },
];

const INVENTORY_CHILDREN: &[CommandSpec] = &[CommandSpec {
    name: "list",
    aliases: &["ls"],
    visibility: CommandVisibility::Public,
    description: "List the declared host lists, and which hosts a grant authorises.",
    usage: "nenv inventory list [path]",
    arguments: &[CommandArgument::optional(
        "path",
        "Project directory or configuration path.",
    )],
    options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
    output: OutputSupport::TEXT_AND_JSON,
    action: CommandAction::InventoryList,
    children: &[],
}];

/// `--plan` and the shared formatting flags.
///
/// A const slice rather than a function, because a `&[CommandOption]` in a `const` is
/// the only way two command specs can share a flag list without one of them owning
/// it.
///
/// **Only `--plan` is declared, and `--dry-run` is still accepted.** The reference
/// accepts both (`cli.go:2468`) and prints both in its help. A `CommandOption` has
/// one `long` and one `short`, so two spellings of one flag is either two options --
/// which the tree contract correctly refuses, because two options with one
/// `OptionId` means a parser that cannot tell them apart -- or one option and an
/// undeclared alias. The alias is the lesser cost: the help names the flag and its
/// alias in one description, and `nenv ssh --dry-run` still works.
const REMOTE_OPTIONS: &[CommandOption] = &[
    CommandOption::flag(
        "",
        "--plan",
        "Print what would happen, without connecting. `--dry-run` is accepted as an alias.",
    ),
    FORMAT_OPTION,
    PROFILE_OPTION,
    HELP_OPTION,
];

/// The inventory flag, shared so the two remote commands spell it identically.
const INVENTORY_OPTION: CommandOption = CommandOption::value(
    "-i",
    "--inventory",
    "name",
    &[],
    "Which declared host list to resolve against. Defaults to `default`.",
);

/// `nenv ssh` — a **top-level** command, as in the reference.
///
/// It resolves inventory targets, prints a plan on request, and then refuses: the
/// reference does exactly the same, at `cli.go:2298`, with the same words. See
/// `apps/nenv/src/inventory_commands.rs` for why the refusal is the deliverable
/// rather than a stub.
const SSH_SPEC: CommandSpec = CommandSpec {
    name: "ssh",
    aliases: &[],
    visibility: CommandVisibility::Public,
    description: "Execute a remote script after -- on explicitly authorized, pinned inventory hosts.",
    usage: "nenv ssh <host-or-tag>... [flags] [-- <remote-script>]",
    arguments: &[CommandArgument::one_or_more(
        "target",
        "An inventory host name, or @tag for every host carrying it.",
    )],
    options: &[
        INVENTORY_OPTION,
        REMOTE_OPTIONS[0],
        REMOTE_OPTIONS[1],
        REMOTE_OPTIONS[2],
        REMOTE_OPTIONS[3],
    ],
    output: OutputSupport::TEXT_AND_JSON,
    action: CommandAction::Ssh,
    children: &[],
};

/// `nenv scp`, and likewise top-level. The two paths come first and everything after
/// them is a target, as in the reference's usage line at `cli.go:3380`.
const SCP_SPEC: CommandSpec = CommandSpec {
    name: "scp",
    aliases: &[],
    visibility: CommandVisibility::Public,
    description: "Copy one file to or from explicitly authorized, pinned inventory hosts.",
    usage: "nenv scp <source> <destination> <host-or-tag>... [flags]",
    arguments: &[
        CommandArgument::required("source", "The file or directory to copy."),
        CommandArgument::required("destination", "Where it goes."),
        CommandArgument::one_or_more(
            "target",
            "An inventory host name, or @tag for every host carrying it.",
        ),
    ],
    options: &[
        INVENTORY_OPTION,
        CommandOption::flag(
            "",
            "--pull",
            "The direction is remote to local, rather than local to remote.",
        ),
        REMOTE_OPTIONS[0],
        REMOTE_OPTIONS[1],
        REMOTE_OPTIONS[2],
        REMOTE_OPTIONS[3],
    ],
    output: OutputSupport::TEXT_AND_JSON,
    action: CommandAction::Scp,
    children: &[],
};

const JOB_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        aliases: &["ls"],
        visibility: CommandVisibility::Public,
        description: "List the ordered pipelines this project declares.",
        usage: "nenv job list [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project directory or configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::JobList,
        children: &[],
    },
    CommandSpec {
        name: "help",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print a job's help, and the steps it runs in order.",
        usage: "nenv job help <job> [path]",
        arguments: &[
            CommandArgument::required("job", "The job to describe."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::JobHelp,
        children: &[],
    },
    CommandSpec {
        name: "run",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Run a job's steps, in the order the job declares them.",
        usage: "nenv job run <job> [path]",
        arguments: &[
            CommandArgument::required("job", "The job to run."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[
            FORMAT_OPTION,
            PROFILE_OPTION,
            CommandOption::flag(
                "",
                "--dry-run",
                "Print the steps and their order without running any of them.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::JobRun,
        children: &[],
    },
];

const CONFIG_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        aliases: &["ls"],
        visibility: CommandVisibility::Public,
        description: "List the configuration keys this project declares.",
        usage: "nenv config list [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project directory or configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ConfigList,
        children: &[],
    },
    CommandSpec {
        name: "get",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print the value of one declared configuration key.",
        usage: "nenv config get <key> [path]",
        arguments: &[
            CommandArgument::required("key", "The configuration key to read."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ConfigGet,
        children: &[],
    },
    CommandSpec {
        name: "set",
        aliases: &[],
        visibility: CommandVisibility::Public,
        // **"Correct a declared key", not "set a key".** "Set" suggests it will create
        // one, and the distinction *is* the behaviour: a key the project does not declare
        // is refused with the alternatives named, so a typo cannot become a key nobody
        // asked for.
        description: "Correct one declared configuration key, in the machine-owned overrides file.",
        usage: "nenv config set <key> <value> [path]",
        arguments: &[
            CommandArgument::required("key", "The configuration key to correct."),
            CommandArgument::required("value", "The value it should have."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        // **No `FORMAT_OPTION`.** There is no value to format: the answer is which file
        // was written, and offering `--json` for a confirmation implies structured output
        // worth consuming when the useful part is a path a human is going to open.
        options: &[PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::ConfigSet,
        children: &[],
    },
    CommandSpec {
        name: "unset",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Remove a correction from the machine-owned overrides file.",
        usage: "nenv config unset <key> [path]",
        arguments: &[
            CommandArgument::required("key", "The configuration key to stop correcting."),
            CommandArgument::optional("path", "Project directory or configuration path."),
        ],
        options: &[PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::ConfigUnset,
        children: &[],
    },
];

const CONTEXT_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "current",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Print the context a task would run under, and where it came from.",
        usage: "nenv context current [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project directory or configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ContextCurrent,
        children: &[],
    },
    CommandSpec {
        name: "list",
        aliases: &["ls"],
        visibility: CommandVisibility::Public,
        description: "List every context this project names, with what declares it.",
        usage: "nenv context list [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project directory or configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ContextList,
        children: &[],
    },
];

const WORKSPACE_CHILDREN: &[CommandSpec] = &[CommandSpec {
    name: "list",
    aliases: &["ls"],
    visibility: CommandVisibility::Public,
    description: "List the members and aliases a workspace declares.",
    usage: "nenv workspace list [path]",
    arguments: &[CommandArgument::optional(
        "path",
        "Workspace root directory or project configuration path.",
    )],
    options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
    output: OutputSupport::TEXT_AND_JSON,
    action: CommandAction::WorkspaceList,
    children: &[],
}];

const REMOTE_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "inspect",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Inspect a remote module reference.",
        usage: "nenv remote inspect <source>",
        arguments: &[CommandArgument::required(
            "source",
            "Remote module reference.",
        )],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteInspect,
        children: &[],
    },
    CommandSpec {
        name: "fetch",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Fetch a trusted local git module.",
        usage: "nenv remote fetch <source> [path]",
        arguments: &[
            CommandArgument::required("source", "Remote module reference."),
            CommandArgument::optional("path", "Module output path."),
        ],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteFetch,
        children: &[],
    },
    CommandSpec {
        name: "install",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Fetch and install a trusted local git module.",
        usage: "nenv remote install <source> [path]",
        arguments: &[
            CommandArgument::required("source", "Remote module reference."),
            CommandArgument::optional("path", "Module output path."),
        ],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteInstall,
        children: &[],
    },
    CommandSpec {
        name: "update",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Refresh a cached local git module.",
        usage: "nenv remote update <source> [path]",
        arguments: &[
            CommandArgument::required("source", "Remote module reference."),
            CommandArgument::optional("path", "Module output path."),
        ],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteUpdate,
        children: &[],
    },
    CommandSpec {
        name: "clear",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Clear a cached remote module.",
        usage: "nenv remote clear <source> [path]",
        arguments: &[
            CommandArgument::required("source", "Remote module reference."),
            CommandArgument::optional("path", "Module output path."),
        ],
        options: &[FORMAT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteClear,
        children: &[],
    },
];

const SHELL_CHILDREN: &[CommandSpec] = &[CommandSpec {
    name: "activate",
    aliases: &[],
    visibility: CommandVisibility::Hidden,
    description: "Print shell activation code.",
    usage: "nenv shell activate <shell> [path]",
    arguments: &[
        CommandArgument::required_choices(
            "shell",
            "Shell to render activation code for.",
            COMPLETION_SHELLS,
        ),
        CommandArgument::optional("path", "Project configuration path."),
    ],
    options: &[PROFILE_OPTION, HELP_OPTION],
    output: OutputSupport::TEXT,
    action: CommandAction::ShellActivate,
    children: &[],
}];

const ROOT_CHILDREN: &[CommandSpec] = &[
    CommandSpec {
        name: "init",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Create an nenv configuration in the current directory.",
        usage: "nenv init",
        arguments: &[],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::InitShortcut,
        children: &[],
    },
    CommandSpec {
        name: "use",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Select and install a native or provider-backed nenv tool; tasks may override it.",
        usage: "nenv use (--user|--global) [--dry-run] <runtime|gh:owner/repo|provider:package>[@<version>]...",
        arguments: &[CommandArgument::one_or_more(
            "tool",
            "Runtime or provider-backed tool, optionally followed by a version.",
        )],
        options: &[
            CommandOption::flag(
                "-u",
                "--user",
                "Install for this user: configuration under NEOENV_CONFIG_HOME/XDG_CONFIG_HOME and binaries under NEOENV_DATA_HOME/XDG_DATA_HOME.",
            ),
            CommandOption::flag(
                "-g",
                "--global",
                "Install system-wide: configuration under NEOENV_GLOBAL_CONFIG_DIR or /etc/neoenv, binaries under NEOENV_GLOBAL_INSTALL_DIR or /usr/local/neoenv.",
            ),
            CommandOption::flag(
                "",
                "--dry-run",
                "Show the ordered install plan without downloading or changing configuration.",
            ),
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT,
        action: CommandAction::UseShortcut,
        children: &[],
    },
    CommandSpec {
        name: "self",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Run built-ins that task shortcuts cannot override.",
        usage: "nenv self <command>",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::SelfGroup,
        children: SELF_CHILDREN,
    },
    CommandSpec {
        name: "validate",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Validate a project configuration.",
        usage: "nenv validate [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::Validate,
        children: &[],
    },
    CommandSpec {
        name: "inspect",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show the resolved project configuration.",
        usage: "nenv inspect [path]",
        arguments: &[CommandArgument::optional(
            "path",
            "Project configuration path.",
        )],
        options: &[FORMAT_OPTION, PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::Inspect,
        children: &[],
    },
    CommandSpec {
        name: "exec",
        aliases: &["x"],
        visibility: CommandVisibility::Public,
        description: "Run a command in the resolved project environment.",
        usage: "nenv exec [-p <path>] [-E <path>] [-e KEY=VALUE] [--] <command> [<arguments>...]",
        arguments: &[CommandArgument::one_or_more(
            "command",
            "Executable and its arguments.",
        )],
        options: RUN_OVERRIDE_OPTIONS,
        output: OutputSupport::TEXT,
        action: CommandAction::Exec,
        children: &[],
    },
    CommandSpec {
        name: "task",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Plan, describe, and run project tasks.",
        usage: "nenv task <command> [options]",
        arguments: &[],
        options: &[CONTEXT_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TaskGroup,
        children: TASK_CHILDREN,
    },
    CommandSpec {
        name: "run",
        aliases: &["r"],
        visibility: CommandVisibility::Public,
        description: "Run a project task.",
        usage: "nenv run [<task>] [path] [options] [-- <arguments>...]",
        arguments: &[
            CommandArgument::optional("task", "Task name. Defaults to `default`."),
            CommandArgument::optional("path", "Project configuration path."),
            CommandArgument::zero_or_more("arguments", "Literal arguments passed after --."),
        ],
        options: &[
            PROFILE_OPTION,
            CommandOption::flag("", "--dry-run", "Plan without executing actions."),
            CommandOption::value(
                "",
                "--capability-policy",
                "path",
                &[],
                "Use a specific capability policy file.",
            ),
            RUN_PROJECT_OPTION,
            RUN_DOTENV_OPTION,
            RUN_ENV_OPTION,
            CONTEXT_OPTION,
            FORMAT_OPTION,
            HELP_OPTION,
        ],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RunShortcut,
        children: &[],
    },
    CommandSpec {
        name: "tool",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Plan, install, and inspect declared project tools.",
        usage: "nenv tool <command> [options]",
        arguments: &[],
        options: &[PROFILE_OPTION, HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ToolGroup,
        children: TOOL_CHILDREN,
    },
    CommandSpec {
        name: "trust",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Inspect, grant, or remove remote-module trust.",
        usage: "nenv trust <command>",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::TrustGroup,
        children: TRUST_CHILDREN,
    },
    CommandSpec {
        name: "workspace",
        aliases: &["ws"],
        visibility: CommandVisibility::Public,
        description: "Inspect the members and aliases a workspace declares.",
        usage: "nenv workspace <command>",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::WorkspaceGroup,
        children: WORKSPACE_CHILDREN,
    },
    CommandSpec {
        name: "inventory",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Report the declared host lists, and what a grant authorises.",
        usage: "nenv inventory [list] [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::InventoryGroup,
        children: INVENTORY_CHILDREN,
    },
    // `ssh` and `scp` are top-level, as in the reference's root help
    // (`cli/metadata.go:49`). Their specs are consts so `inventory` can name the
    // same nodes in its help without a second copy that could drift.
    SSH_SPEC,
    SCP_SPEC,
    CommandSpec {
        name: "ship",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Report the declared deployment workflows, and refuse to act on one.",
        usage: "nenv ship [list|deploy [name]|rollback [name]|destroy [name]] [flags]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ShipGroup,
        children: SHIP_CHILDREN,
    },
    CommandSpec {
        name: "job",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Report the ordered pipelines this project declares, and run one.",
        usage: "nenv job [list|help <job>|run <job>] [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::JobGroup,
        children: JOB_CHILDREN,
    },
    CommandSpec {
        name: "config",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Report the configuration keys a project declares, and their values.",
        usage: "nenv config [list|get <key>] [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ConfigGroup,
        children: CONFIG_CHILDREN,
    },
    CommandSpec {
        name: "context",
        aliases: &["ctx"],
        visibility: CommandVisibility::Public,
        description: "Report the context a task would run under, and every context declared.",
        usage: "nenv context [current|list] [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::ContextGroup,
        children: CONTEXT_CHILDREN,
    },
    CommandSpec {
        name: "secret",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Read or write an OS credential-store secret reference.",
        usage: "nenv secret <get|set> <reference> [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::SecretGroup,
        children: SECRET_CHILDREN,
    },
    CommandSpec {
        name: "runtime",
        aliases: &["runtimes"],
        visibility: CommandVisibility::Public,
        description: "Inspect the language runtimes installed in nenv's global data directory.",
        usage: "nenv runtime <command>",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RuntimeGroup,
        children: RUNTIME_CHILDREN,
    },
    CommandSpec {
        name: "remote",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Inspect and manage cached remote modules.",
        usage: "nenv remote <command> <source> [path]",
        arguments: &[],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT_AND_JSON,
        action: CommandAction::RemoteGroup,
        children: REMOTE_CHILDREN,
    },
    CommandSpec {
        name: "shell",
        aliases: &[],
        visibility: CommandVisibility::Hidden,
        description: "Print shell activation code.",
        usage: "nenv shell <command>",
        arguments: &[],
        options: &[HELP_OPTION],
        children: SHELL_CHILDREN,
        output: OutputSupport::TEXT,
        action: CommandAction::ShellGroup,
    },
    CommandSpec {
        name: "completion",
        aliases: &[],
        visibility: CommandVisibility::Hidden,
        description: "Print a shell completion script.",
        usage: "nenv completion <bash|zsh|fish|powershell|nushell>",
        arguments: &[CommandArgument::required_choices(
            "shell",
            "Shell to generate completion for.",
            COMPLETION_SHELLS,
        )],
        options: &[HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::Completion,
        children: &[],
    },
    CommandSpec {
        name: "help",
        aliases: &[],
        visibility: CommandVisibility::Public,
        description: "Show help for a command.",
        usage: "nenv help [command] [arguments]...",
        arguments: &[CommandArgument::zero_or_more(
            "command",
            "Command path to describe.",
        )],
        options: &[ROOT_HELP_OPTION],
        output: OutputSupport::TEXT,
        action: CommandAction::Help,
        children: &[],
    },
];

const ROOT_OPTIONS: &[CommandOption] = &[
    ROOT_HELP_OPTION,
    CommandOption::flag("-V", "--version", "Show the nenv version."),
    FORMAT_OPTION,
    CONTEXT_OPTION,
    PROFILE_OPTION,
];

const LIFECYCLE_OPTIONS: &[CommandOption] = &[
    CommandOption::flag(
        "",
        "--project",
        "Operate on the current project lockfile and .neoenv tree.",
    ),
    CommandOption::flag(
        "-u",
        "--user",
        "Operate on this user's nenv configuration and data.",
    ),
    CommandOption::flag(
        "-g",
        "--global",
        "Operate on the system-wide nenv configuration and data.",
    ),
    CommandOption::flag("", "--dry-run", "Report the plan without changing files."),
    FORMAT_OPTION,
    HELP_OPTION,
];

/// The complete `nenv` command surface. Parsing, help, and shell completion all
/// start at this node; adding a command here cannot create an unvalidated leaf.
pub(crate) static ROOT: CommandSpec = CommandSpec {
    name: "nenv",
    aliases: &[],
    visibility: CommandVisibility::Public,
    description: "Create reproducible, project-scoped developer environments.",
    usage: "nenv [command] [options]",
    arguments: &[],
    options: ROOT_OPTIONS,
    output: OutputSupport::TEXT_AND_JSON,
    action: CommandAction::Root,
    children: ROOT_CHILDREN,
};

/// Proves the tree is the complete typed command boundary: every action is
/// unique, and every action is reachable from `ROOT` by `find`.
#[cfg(test)]
mod boundary_tests {
    use std::collections::BTreeSet;

    use super::{CommandAction, CommandSpec, ROOT};

    fn assert_unique_actions(command: &'static CommandSpec, actions: &mut BTreeSet<CommandAction>) {
        assert!(
            actions.insert(command.action),
            "duplicate action for {}",
            command.name
        );
        assert_eq!(
            ROOT.find(command.action).map(|command| command.name),
            Some(command.name)
        );
        for child in command.children {
            assert_unique_actions(child, actions);
        }
    }

    #[test]
    fn the_tree_is_the_complete_typed_command_boundary() {
        let mut actions = BTreeSet::new();
        assert_unique_actions(&ROOT, &mut actions);
        assert!(actions.contains(&CommandAction::Root));
        assert!(actions.contains(&CommandAction::TaskRun));
        assert!(actions.contains(&CommandAction::ToolInstall));
        assert!(actions.contains(&CommandAction::RemoteInstall));
    }
}
