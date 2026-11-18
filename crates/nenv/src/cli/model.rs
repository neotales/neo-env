//! The parsed command surface: the typed enums produced from the command
//! tree plus the output format selector.

use super::{CommandSpec, Diagnostic};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Project selection and run-local environment overrides for `run` and `exec`.
///
/// The two lists keep command-line order because a later `-E` must win over an
/// earlier one for the same key. They stay separate from
/// `ResolvedProject::environment` on purpose: a CLI override has no declaring
/// source, so it must not acquire a fabricated source span or start appearing
/// in `nenv inspect` output.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunOverrides {
    pub project: Option<String>,
    pub dotenv: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Help {
        command: &'static CommandSpec,
    },
    /// A malformed child command whose parent help is still useful. Keeping
    /// this in the invocation lets `--format json` retain a machine-readable
    /// diagnostic instead of falling back to text root help.
    HelpError {
        command: &'static CommandSpec,
        diagnostic: Diagnostic,
    },
    Version,
    /// A task-overridable command which falls back to the named built-in.
    Shortcut {
        name: String,
        arguments: Vec<String>,
        builtin: SelfCommand,
    },
    /// A legacy direct task invocation without a built-in fallback.
    TaskShortcut {
        task: String,
        arguments: Vec<String>,
    },
    /// Built-ins which must remain available when a task shadows a shortcut.
    Self_ {
        command: SelfCommand,
    },
    Validate {
        path: Option<String>,
    },
    Inspect {
        path: Option<String>,
    },
    Exec {
        command: Vec<String>,
        overrides: RunOverrides,
    },
    Task {
        command: TaskCommand,
    },
    Tool {
        command: ToolCommand,
    },
    Shell {
        shell: String,
        path: Option<String>,
    },
    Completion {
        shell: String,
    },
    Trust {
        command: TrustCommand,
    },
    Workspace {
        command: WorkspaceCommand,
    },
    /// The project's ordered pipelines, and running one.
    Job {
        command: JobCommand,
    },
    /// The commands that name hosts: `inventory`, `ssh`, `scp`.
    Inventory {
        command: InventoryCommand,
    },
    /// The project's deployment workflows.
    Ship {
        command: ShipCommand,
    },
    /// The declared configuration keys, and the value one resolved to.
    ///
    /// `Group` is `nenv config` with no subcommand and means `list`, matching the
    /// reference. Kept distinct rather than collapsed so the parser and the help text
    /// cannot disagree about which spelling means what.
    Config {
        command: ConfigCommand,
    },
    /// The context a task would run under, and every context the project names.
    ///
    /// Its own variant rather than a `ContextCommand` folded into `TaskCommand`,
    /// because asking *which* context applies is a different question from asking
    /// *what a task does* -- it is answerable without naming a task, which is
    /// exactly what a user does not know when they ask it.
    Context {
        command: ContextCommand,
    },
    /// Native runtimes installed in the global data directory.
    ///
    /// Separate from `ToolCommand` because a runtime and a tool have different
    /// lifecycles: a tool is declared, locked and resolved per project, while a runtime
    /// is installed once globally and then *reaches the shell* rather than being invoked
    /// through `nenv`. Modelling them as one made both awkward.
    Runtime {
        command: RuntimeCommand,
    },
    /// Read or write an OS credential-store secret reference.
    Secret {
        command: SecretCommand,
    },
    Remote {
        command: RemoteCommand,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelfCommand {
    Init,
    Use { arguments: Vec<String> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustCommand {
    Status,
    ProjectStatus { path: String },
    AddRepository { repository: String },
    RemoveRepository { repository: String },
    AddProject { path: String },
    RevokeProject { path: String },
    AddRemote { spec: String },
    RemoveRemote { spec: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceCommand {
    List { path: Option<String> },
}

/// `nenv context` — the effective context, or every context the project names.
///
/// **`Group` is `context` with no subcommand, and it means `Current`.** That is the
/// reference's behaviour and it is the useful one: a user who types `nenv context`
/// wants the answer, not a usage message. The distinction is kept as a variant
/// rather than collapsed in the parser so the help text and the parser cannot
/// disagree about which spelling means what.
/// `nenv ship` — the project's deployment workflows.
///
/// Three variants rather than one per verb, because the verb is a *value* the
/// reference validates against a fixed set (`isShipLifecycle`, `cli.go:2713`) and
/// spelling five enum variants would let the tree and that set drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShipCommand {
    Group {
        path: Option<String>,
    },
    List {
        path: Option<String>,
    },
    /// A recognised lifecycle verb: `deploy`, `up`, `rollback`, `destroy`, `down`.
    Lifecycle {
        path: Option<String>,
        verb: String,
        /// `None` selects the deployment this context resolves to.
        deployment: Option<String>,
        plan_only: bool,
    },
    /// Anything else, refused with the reference's words.
    Other {
        path: Option<String>,
        verb: String,
    },
}

/// `ssh`, `scp` and `inventory`: the commands that name hosts.
///
/// One enum for all three rather than three, because they share the whole shape --
/// an inventory, a list of targets, a plan flag -- and three enums would let `scp`
/// grow a field `ssh` does not have and nothing would notice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InventoryCommand {
    Group {
        path: Option<String>,
    },
    List {
        path: Option<String>,
    },
    Ssh {
        path: Option<String>,
        inventory: String,
        targets: Vec<String>,
        /// Exact remote script after `--`; never interpreted locally.
        script: Option<String>,
        plan_only: bool,
    },
    Scp {
        path: Option<String>,
        inventory: String,
        targets: Vec<String>,
        source: String,
        destination: String,
        pull: bool,
        plan_only: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobCommand {
    /// `nenv job` with nothing after it, which means `list`.
    Group {
        path: Option<String>,
    },
    List {
        path: Option<String>,
    },
    /// The job's own help or description, as `nenv job run <job> --help` prints it.
    Help {
        path: Option<String>,
        job: String,
    },
    Run {
        path: Option<String>,
        job: String,
        dry_run: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigCommand {
    Group {
        path: Option<String>,
    },
    List {
        path: Option<String>,
    },
    Get {
        path: Option<String>,
        key: String,
    },
    /// Correct one declared key, in the machine-owned overrides file.
    ///
    /// **It corrects and does not invent.** A key the project does not declare is
    /// refused with the alternatives named, because a typo that silently creates a key is
    /// the shape of defect this repository has shipped eleven of -- a file asking for one
    /// thing and getting another, with nothing saying so.
    Set {
        path: Option<String>,
        key: String,
        value: String,
    },
    /// Removes a correction from the same file `set` writes.
    ///
    /// Its own variant rather than `set` with an empty value, because **an empty value is
    /// a value**: a project can legitimately set a key to nothing, and `set context ""`
    /// must not mean "forget what I said about the context".
    Unset {
        path: Option<String>,
        key: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContextCommand {
    /// `nenv context` with nothing after it. Means current, not a usage error.
    Group {
        path: Option<String>,
    },
    Current {
        path: Option<String>,
    },
    List {
        path: Option<String>,
    },
}

/// A read-only query against the installed runtimes.
///
/// **Only the two verbs that need no network are here.** `update` and `upgrade` require
/// resolving a latest version, which means the fetch half of `RuntimeLayout` — and a verb
/// that cannot answer correctly is worse than an absent one, because a user who types
/// `nenv runtime upgrade` and gets "unknown subcommand" learns the truth, while one who
/// gets a partial answer learns something false. `install` already exists as
/// `nenv tool global-use <runtime>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretCommand {
    Get {
        path: Option<String>,
        reference: String,
    },
    Set {
        path: Option<String>,
        reference: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCommand {
    /// Every runtime with a complete, receipt-verified install.
    List,
    /// The directories one runtime contributes: its `PATH` entry and its variables.
    Where { runtime: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteCommand {
    Inspect {
        source: String,
    },
    Fetch {
        source: String,
        path: Option<String>,
    },
    Install {
        source: String,
        path: Option<String>,
    },
    Update {
        source: String,
        path: Option<String>,
    },
    Clear {
        source: String,
        path: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolScope {
    Project,
    /// This user's configuration and data roots.
    User,
    /// The machine-wide configuration and install roots.
    Global,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolCommand {
    Plan {
        path: Option<String>,
        locked: bool,
    },
    Lock {
        path: Option<String>,
        locked: bool,
    },
    Verify {
        path: Option<String>,
    },
    Install {
        path: Option<String>,
    },
    List {
        path: Option<String>,
        scope: Option<ToolScope>,
    },
    Which {
        executable: String,
        path: Option<String>,
        scope: Option<ToolScope>,
    },
    Where {
        executable: String,
        path: Option<String>,
        scope: Option<ToolScope>,
    },
    Use {
        executable: String,
        path: Option<String>,
        arguments: Vec<String>,
    },
    GlobalUse {
        arguments: Vec<String>,
    },
    Remove {
        scope: ToolScope,
        tools: Vec<String>,
        dry_run: bool,
    },
    Update {
        scope: ToolScope,
        tools: Vec<String>,
        dry_run: bool,
    },
    Pin {
        scope: ToolScope,
        tools: Vec<String>,
        dry_run: bool,
    },
    Unpin {
        scope: ToolScope,
        tools: Vec<String>,
        dry_run: bool,
    },
    Purge {
        scope: ToolScope,
        tools: Vec<String>,
        dry_run: bool,
    },
    Cleanup {
        path: Option<String>,
        dry_run: bool,
        scope: Option<ToolScope>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCommand {
    List {
        path: Option<String>,
    },
    Help {
        task: String,
        path: Option<String>,
    },
    Plan {
        task: String,
        path: Option<String>,
    },
    /// Hidden completion candidate endpoint. It reads configuration but never
    /// evaluates a task action.
    Complete {
        task: Option<String>,
    },
    Run {
        task: String,
        path: Option<String>,
        dry_run: bool,
        capability_policy: Option<String>,
        passthrough: Vec<String>,
        overrides: RunOverrides,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub command: Command,
    pub format: OutputFormat,
    pub context: Option<String>,
    /// Configuration dialect selected with `--profile`. Defaults to the strict
    /// v1 schema; `go` opts into the Go compatibility profile.
    pub profile: neoenv_config::ConfigProfile,
}
