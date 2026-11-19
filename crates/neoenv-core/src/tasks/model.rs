//! Pure task declarations, package identity, and dependency graph types.

use super::{BTreeMap, Deserialize, IndexMap, PathBuf, Serialize, SourceSpan, fmt};

pub const DEFAULT_CONTEXT: &str = "default";

/// Stable identity of the package document that supplied a task action.
///
/// The package alias is deliberately absent. `path` and `sha256` identify the
/// exact document snapshot, while `export` records the selected package entry
/// point. Runtime-only containment and trust classification are excluded from
/// the serialized contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskPackageIdentity {
    pub path: String,
    pub sha256: String,
    pub export: String,
    #[serde(skip)]
    pub root: PathBuf,
    #[serde(skip)]
    pub external: bool,
}

impl TaskPackageIdentity {
    /// Returns the capability-policy subject for this package snapshot.
    #[must_use]
    pub fn policy_subject(&self) -> String {
        format!("package:{}", self.sha256)
    }
}

/// Origin of one task dependency or hook edge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskEdgeOrigin {
    #[default]
    Caller,
    Package,
}

impl fmt::Display for TaskEdgeOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller => formatter.write_str("caller"),
            Self::Package => formatter.write_str("package"),
        }
    }
}

/// A dependency or hook edge together with the document side that declared it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskDependencyEdge {
    pub name: String,
    pub origin: TaskEdgeOrigin,
}

/// Per-edge origins retained in declaration order. A vector is used instead
/// of a name-keyed map so duplicate edges from both sides remain auditable.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskDependencyOrigins {
    pub needs: Vec<TaskEdgeOrigin>,
    pub before: Vec<TaskEdgeOrigin>,
    pub after: Vec<TaskEdgeOrigin>,
}

/// A capability request retained with the side that declared it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCapabilityRequest {
    pub capability: String,
    pub origin: TaskEdgeOrigin,
}

/// Values available to the deliberately closed task predicate language.
///
/// These values are supplied by the task engine; predicate evaluation never
/// starts a process, renders a template, or expands a shell expression.
#[derive(Clone, Copy, Debug)]
pub struct PredicateContext<'a> {
    pub environment: &'a BTreeMap<String, String>,
    pub context: &'a str,
    pub inputs: &'a TaskInputValues,
    pub outcomes: &'a BTreeMap<String, TaskOutcome>,
    pub outputs: &'a BTreeMap<String, String>,
    /// Command-line `--env KEY=VALUE` values, applied after a task's own `dotenv`
    /// and `env` so a predicate sees the same effective environment the task will
    /// actually run with.
    pub overrides: Option<&'a BTreeMap<String, String>>,
    /// The task's positional passthrough arguments, for the `args` and `args.N`
    /// references. Empty when the task was not given any.
    pub args: &'a [String],
}

impl<'a> PredicateContext<'a> {
    #[must_use]
    pub fn empty(environment: &'a BTreeMap<String, String>) -> Self {
        static INPUTS: std::sync::OnceLock<TaskInputValues> = std::sync::OnceLock::new();
        static OUTCOMES: std::sync::OnceLock<BTreeMap<String, TaskOutcome>> =
            std::sync::OnceLock::new();
        static OUTPUTS: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
        static ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        Self {
            environment,
            context: DEFAULT_CONTEXT,
            inputs: INPUTS.get_or_init(TaskInputValues::default),
            outcomes: OUTCOMES.get_or_init(BTreeMap::new),
            outputs: OUTPUTS.get_or_init(BTreeMap::new),
            overrides: None,
            args: ARGS.get_or_init(Vec::new),
        }
    }

    /// Whether everything the context knows about has succeeded, for the
    /// `success` reference.
    ///
    /// # Divergence from the Go reference, deliberate
    ///
    /// The reference hardcodes `Success: true` at both of its call sites, so
    /// `success` there is a constant: `force: success` runs a recovery task
    /// unconditionally and `if: success` always passes. This computes the
    /// answer the name promises instead.
    ///
    /// The constant is treated as vestigial rather than as a specification. A
    /// predicate named `success` that ignores whether anything succeeded would
    /// be worse than either spelling out the divergence: it would read as a
    /// working recovery condition while firing every time, which is the failure
    /// a user cannot diagnose from the output. The inverse error -- silently
    /// matching a reference constant -- at least cannot mislead anyone, because
    /// it does not appear to work.
    ///
    /// `Planned`, `Succeeded`, `Skipped`, and `Blocked` are not failures;
    /// `Failed`, `TimedOut`, and `Cancelled` are. `Conditional` is deliberately
    /// not counted as success: its real result is unknown, and a dry run must
    /// report the predicate as conditional rather than let this answer a
    /// question it cannot know. `Running` is not yet known successful either.
    /// An empty context is successful, matching the reference's zero value.
    #[must_use]
    pub fn success(&self) -> bool {
        self.outcomes.values().all(|outcome| {
            matches!(
                outcome,
                TaskOutcome::Planned
                    | TaskOutcome::Succeeded
                    | TaskOutcome::Skipped
                    | TaskOutcome::Blocked
            )
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TaskDefinition {
    /// Stable identity. Missing values are derived from the declaration key.
    pub id: Option<String>,
    /// Human-readable label. Missing values are derived from the declaration key.
    pub name: Option<String>,
    /// Canonical lookup label. Missing values are deterministically derived from the key.
    pub slug: Option<String>,
    pub description: Option<String>,
    pub help: Option<String>,
    pub action: Option<TaskAction>,
    /// Ordered inline actions for an explicitly composite task.
    #[serde(skip)]
    pub composite_steps: Vec<CompositeStep>,
    pub needs: Vec<String>,
    /// `Some(true)` overlaps following tasks until joined; absence inherits.
    pub background: Option<bool>,
    /// Dependencies launched concurrently and joined before this action.
    pub parallel_needs: Vec<String>,
    /// Completion barriers. The sole name `all` joins previously launched work.
    pub wait: Vec<String>,
    pub hooks: TaskHooks,
    pub extends: Option<String>,
    pub template: bool,
    pub parameters: Vec<TaskParameter>,
    pub outputs: IndexMap<String, TaskOutput>,
    pub if_condition: Option<String>,
    pub force: Option<String>,
    /// Package implementation tasks are addressable for dependency planning,
    /// but omitted from user-facing task listings and completion candidates.
    #[serde(skip)]
    pub hidden: bool,
    /// Snapshot identity when the effective action came from a task package.
    #[serde(skip)]
    pub package: Option<TaskPackageIdentity>,
    /// Origin for every declared `needs`, `before`, and `after` edge.
    #[serde(skip)]
    pub dependency_origins: TaskDependencyOrigins,
    /// Capability requests paired with their caller/package declaration origin.
    #[serde(skip)]
    pub capability_requests: Vec<TaskCapabilityRequest>,
    /// Internal job container. Not accepted as a user task field.
    #[serde(skip)]
    pub job: Option<Box<TaskSequence>>,
    /// Execution trust follows remote task bodies through job lowering.
    #[serde(skip)]
    pub execution_grant_required: bool,
}

/// One inline action in a composite task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompositeStep {
    /// Explicitly selected action runner.
    pub uses: String,
    /// Command passed to the selected runner.
    pub run: String,
    /// Source document for diagnostics and package provenance.
    pub source_document: Option<SourceSpan>,
}

/// An owned, isolated step graph used when a job itself overlaps other jobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSequence {
    /// Complete step graph, including referenced task dependencies.
    pub tasks: IndexMap<String, TaskDefinition>,
    /// The step from which to plan the sequence.
    pub root: String,
    /// Task context selected for dependencies and step predicates.
    pub context: String,
    /// Optional whole-job deadline, in the same positive units as task timeout.
    pub timeout: Option<String>,
    /// Distinguishes an ordered composite from a job DAG at runtime.
    pub kind: TaskSequenceKind,
}

/// Execution semantics for an owned task sequence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TaskSequenceKind {
    /// A normal job, whose all-container graph can use DAG scheduling.
    #[default]
    Job,
    /// A sequential sequence lowered from inline composite actions.
    Composite,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskOutputVisibility {
    #[default]
    Public,
    Private,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TaskOutput {
    pub description: Option<String>,
    pub visibility: TaskOutputVisibility,
}

/// Sibling task suffixes run immediately before or after a task.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TaskHooks {
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent declaration-origin bit for a different \
              runner field; collapsing them would make the provenance ambiguous"
)]
pub struct TaskAction {
    pub uses: Option<String>,
    /// Inline script text for a script runner, or the command for `portable`,
    /// `argv`, and `shell`.
    pub run: Option<String>,
    /// File input for a runner, relative to its declaring document until
    /// package composition canonicalizes it.
    ///
    /// `render` reads it as a template. The named script runners (`bash`, `sh`,
    /// `pwsh`, `powershell`, `node`, `bun`, `deno`, `python`, `nu`, `fish`,
    /// `go`, `dotnet`) and `uv@<version>` read it as a script file. A script
    /// runner sets exactly one of `run` (inline) and `source` (file), so the
    /// choice is explicit rather than inferred from a file extension.
    pub source: Option<String>,
    /// Output file for the `render` runner, relative to its declaring document
    /// until package composition canonicalizes it.
    pub destination: Option<String>,
    pub args: Vec<String>,
    /// File mappings for the `tmpl` runner: `source` or
    /// `source:destination`, resolved relative to the declaring document.
    pub files: Vec<String>,
    /// Declaring document for `files`, kept separate from `source_document` so a
    /// caller override does not inherit the package's file provenance.
    #[serde(skip)]
    pub files_document: Option<SourceSpan>,
    /// Whether `files` was declared inside a package.
    #[serde(skip)]
    pub files_from_package: bool,
    /// Declaring document for `with.values`, kept separate from the package's
    /// file provenance.
    #[serde(skip)]
    pub values_document: Option<SourceSpan>,
    /// Whether `with.values` was declared inside a package.
    #[serde(skip)]
    pub values_from_package: bool,
    pub cwd: Option<String>,
    pub env: IndexMap<String, String>,
    /// Dotenv declarations are retained with their source for relative resolution.
    pub dotenv: Vec<TaskDotenvImport>,
    pub with: IndexMap<String, String>,
    pub capabilities: Vec<String>,
    /// Declaring document for a relative render source.
    #[serde(skip)]
    pub source_document: Option<SourceSpan>,
    /// Declaring document for a relative render destination.
    #[serde(skip)]
    pub destination_document: Option<SourceSpan>,
    /// Declaring document for a relative working directory.
    #[serde(skip)]
    pub cwd_document: Option<SourceSpan>,
    /// Whether `source` was canonicalized and contained as package-relative.
    #[serde(skip)]
    pub source_from_package: bool,
    /// Whether `destination` was canonicalized and contained as package-relative.
    #[serde(skip)]
    pub destination_from_package: bool,
    /// Whether `cwd` was canonicalized and contained as package-relative.
    #[serde(skip)]
    pub cwd_from_package: bool,
}

/// A dotenv file imported only for the task action that declares it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskDotenvImport {
    pub path: String,
    pub required: bool,
    pub source: SourceSpan,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskParameterType {
    String,
    Boolean,
    Integer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TaskParameterDefault {
    String(String),
    Boolean(bool),
    Integer(i64),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub parameter_type: TaskParameterType,
    pub required: bool,
    pub default: Option<TaskParameterDefault>,
    pub description: Option<String>,
    /// Zero-based positional index accepted by the task command line.
    pub position: Option<usize>,
    /// Long option name, without its leading `--`.
    pub long: Option<String>,
    /// Single-character short option name, without its leading `-`.
    pub short: Option<char>,
    /// Whether the parameter can appear more than once.
    pub repeatable: bool,
}

/// Command-line values bound to the root task. Repeated values retain their
/// declaration order.
pub type TaskInputValues = IndexMap<String, Vec<String>>;

/// Result of binding task-local options and positional values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskInputBinding {
    pub values: TaskInputValues,
    /// Literal arguments after `--`, or unbound positional arguments when the
    /// task declares no positional input contract.
    pub passthrough: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskInputError {
    Task(TaskError),
    UnknownOption {
        task: String,
        option: String,
    },
    MissingOptionValue {
        task: String,
        option: String,
    },
    DuplicateOption {
        task: String,
        parameter: String,
    },
    InvalidValue {
        task: String,
        parameter: String,
        value: String,
    },
    MissingRequired {
        task: String,
        parameter: String,
    },
    UnexpectedPositional {
        task: String,
        value: String,
    },
}

impl fmt::Display for TaskInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Task(error) => error.fmt(formatter),
            Self::UnknownOption { task, option } => {
                write!(formatter, "task {task} does not define option {option}")
            }
            Self::MissingOptionValue { task, option } => {
                write!(formatter, "task {task} option {option} requires a value")
            }
            Self::DuplicateOption { task, parameter } => {
                write!(
                    formatter,
                    "task {task} input {parameter} was provided more than once"
                )
            }
            Self::InvalidValue {
                task,
                parameter,
                value,
            } => write!(
                formatter,
                "task {task} input {parameter} has an invalid value {value:?}"
            ),
            Self::MissingRequired { task, parameter } => {
                write!(formatter, "task {task} requires input {parameter}")
            }
            Self::UnexpectedPositional { task, value } => {
                write!(
                    formatter,
                    "task {task} does not accept positional input {value:?}"
                )
            }
        }
    }
}

impl std::error::Error for TaskInputError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    Planned,
    /// A dry run could not decide this outcome without resolving a secret. It
    /// is neither a predicted success nor a predicted skip, and it propagates to
    /// dependents that cannot be decided either.
    Conditional,
    /// Launched but not joined. Used by predicates, never a final run result.
    Running,
    Succeeded,
    Failed,
    Skipped,
    Blocked,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedTask {
    pub name: String,
    /// Declared overlap mode. Per-edge parallel launch is listed on its owner.
    pub background: bool,
    /// Completion barriers evaluated before the action.
    pub wait: Vec<String>,
    /// Dependencies launched concurrently and joined before this action.
    pub parallel_dependencies: Vec<String>,
    pub outcome: TaskOutcome,
    pub package: Option<TaskPackageIdentity>,
    pub dependencies: Vec<TaskDependencyEdge>,
    pub before_hooks: Vec<TaskDependencyEdge>,
    pub after_hooks: Vec<TaskDependencyEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskPlan {
    pub context: String,
    pub tasks: Vec<PlannedTask>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskHelp {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub help: Option<String>,
    /// Declared overlap mode, false unless explicitly enabled.
    pub background: bool,
    /// Named completion barriers, or the sole entry `all`.
    pub wait: Vec<String>,
    /// Dependencies launched concurrently and joined before this action.
    pub parallel_dependencies: Vec<String>,
    pub action: Option<TaskAction>,
    pub parameters: Vec<TaskParameter>,
    pub dependencies: Vec<String>,
    pub dependency_edges: Vec<TaskDependencyEdge>,
    pub before_hooks: Vec<TaskDependencyEdge>,
    pub after_hooks: Vec<TaskDependencyEdge>,
    pub outputs: IndexMap<String, TaskOutput>,
    pub package: Option<TaskPackageIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskError {
    MissingAction {
        task: String,
    },
    InvalidAction {
        task: String,
        message: String,
    },
    InvalidEnvironmentKey {
        task: String,
        key: String,
    },
    CommandSubstitution {
        task: String,
        key: String,
    },
    InvalidOutput {
        task: String,
        output: String,
    },
    InvalidTaskIdentity {
        task: String,
        field: String,
    },
    DuplicateTaskIdentity {
        field: String,
        value: String,
        tasks: Vec<String>,
    },
    DuplicateParameter {
        task: String,
        parameter: String,
    },
    InvalidParameterDefault {
        task: String,
        parameter: String,
    },
    InvalidParameter {
        task: String,
        parameter: String,
        message: String,
    },
    InvalidPredicate {
        task: String,
        field: String,
        message: String,
    },
    /// A job uses a key this model does not honour yet.
    ///
    /// Retained for callers reporting unsupported extensions. Job dependency
    /// graphs are now implemented by owned step containers.
    UnsupportedJobKey {
        job: String,
        key: &'static str,
    },
    /// A job declares no steps.
    JobStepEmpty {
        job: String,
    },
    /// A step's `task:` names a task the project does not declare.
    JobStepTaskMissing {
        job: String,
        step: usize,
        task: String,
    },
    /// The same task appears in one job's steps twice.
    ///
    /// A chain collapses the second occurrence into the first, so the reference's
    /// "run it twice" is not reproduced. A silent collapse is the failure this
    /// repository keeps finding, so it is refused.
    JobStepRepeated {
        job: String,
        task: String,
    },
    MissingBase {
        task: String,
        base: String,
    },
    InheritanceCycle {
        trace: Vec<String>,
    },
    MissingTask {
        task: String,
        context: String,
    },
    /// A context that no task key and no entry names, in a project that does use
    /// contexts.
    ///
    /// Distinct from `MissingTask`: the task exists, and running it in the
    /// default context would have "succeeded" while doing the wrong thing.
    UnknownContext {
        context: String,
        known: Vec<String>,
    },
    MissingDependency {
        task: String,
        dependency: String,
    },
    DependencyCycle {
        trace: Vec<String>,
    },
}

impl fmt::Display for TaskError {
    // One arm per variant, and the variants are the error vocabulary. Splitting
    // this to satisfy a line count would put an arm per helper, which is a worse
    // shape to read than one match that says what every error reads as.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAction { task } => write!(formatter, "task {task} must specify an action"),
            Self::InvalidAction { task, message } => write!(formatter, "task {task} {message}"),
            Self::InvalidEnvironmentKey { task, key } => {
                write!(formatter, "task {task} has invalid environment key: {key}")
            }
            Self::CommandSubstitution { task, key } => write!(
                formatter,
                "task {task} environment {key} uses unsupported command substitution"
            ),
            Self::InvalidOutput { task, output } => {
                write!(formatter, "task {task} has invalid output name: {output}")
            }
            Self::InvalidTaskIdentity { task, field } => {
                write!(formatter, "task {task} has an invalid {field}")
            }
            Self::DuplicateTaskIdentity {
                field,
                value,
                tasks,
            } => write!(
                formatter,
                "task {field} {value:?} is used by multiple tasks: {}",
                tasks.join(", ")
            ),
            Self::DuplicateParameter { task, parameter } => write!(
                formatter,
                "task {task} declares parameter {parameter} more than once"
            ),
            Self::InvalidParameterDefault { task, parameter } => write!(
                formatter,
                "task {task} parameter {parameter} has an incompatible default"
            ),
            Self::InvalidParameter {
                task,
                parameter,
                message,
            } => write!(formatter, "task {task} parameter {parameter} {message}"),
            Self::InvalidPredicate {
                task,
                field,
                message,
            } => write!(
                formatter,
                "task {task} has invalid {field} predicate: {message}"
            ),
            Self::UnsupportedJobKey { job, key } => {
                write!(
                    formatter,
                    "job {job} sets `{key}`, which is a two-level graph this model does \
                     not build yet: a job that needs another job, whose steps are \
                     themselves a chain, has no linear representation"
                )
            }
            Self::JobStepEmpty { job } => {
                write!(
                    formatter,
                    "job {job} declares no steps, so there is nothing to lower"
                )
            }
            Self::JobStepTaskMissing { job, step, task } => {
                write!(
                    formatter,
                    "job {job} step {step} runs task {task:?}, which this project does \
                     not declare"
                )
            }
            Self::JobStepRepeated { job, task } => {
                write!(
                    formatter,
                    "job {job} runs task {task:?} more than once. A job's steps are a \
                     chain, so a repeated task would run once and silently; the \
                     reference runs it twice. Neither is right, and a silent collapse \
                     is worse than a refusal, so split the job or use `run:` steps"
                )
            }
            Self::MissingBase { task, base } => {
                write!(formatter, "task {task} extends missing task {base}")
            }
            Self::InheritanceCycle { trace } => {
                write!(formatter, "task inheritance cycle: {}", trace.join(" -> "))
            }
            Self::MissingTask { task, context } => {
                write!(formatter, "task {task} was not found for context {context}")
            }
            Self::UnknownContext { context, known } => {
                let available = if known.is_empty() {
                    "<none>".to_owned()
                } else {
                    known.join(", ")
                };
                write!(
                    formatter,
                    "context {context:?} is not used by this project; it uses: {available}. \
                     A mistyped context would otherwise run the default-context task and \
                     report success."
                )
            }
            Self::MissingDependency { task, dependency } => write!(
                formatter,
                "task {task} depends on missing task {dependency}"
            ),
            Self::DependencyCycle { trace } => {
                write!(formatter, "task dependency cycle: {}", trace.join(" -> "))
            }
        }
    }
}

impl std::error::Error for TaskError {}

/// A named sequence of steps, run in order.
///
/// ## Why this is not a task
///
/// A [`TaskDefinition`] is a node in a dependency graph: `needs` are edges, and the
/// executor walks them dependency-first. A job is an **ordered list**, and the order
/// is the whole meaning -- `steps: [migrate, seed, serve]` is a different thing from
/// three tasks that happen to be independent.
///
/// The reference agrees, and says so at `neofile/job.go:5`: *"Job is an
/// experimental pipeline definition made of ordered steps."* `JobMap` and `TaskMap`
/// are separate types and neither is ever handed to the other's resolver. The
/// decision, with the citations, is in
/// `docs/decision-records/a-job-is-a-sequence-of-steps.md`.
///
/// ## Why there is no `extends` and no `cron`
///
/// Both exist in the reference and **both are inert there**: `Job.Extends` is written
/// at `neofile/job.go:90` and read nowhere, and `Job.Cron` is written at
/// `neofile/job.go:91-93` and read nowhere -- not even wired to the separate
/// `On.Schedule.Crons` structure.
///
/// Accepting them here would add two keys that parse and do nothing, which is #31
/// and the reason this model exists. They are **refused by name** in
/// `neoenv-config`, and the diagnostic says why. A key is ported with its behaviour
/// or refused; never on the strength of the reference having a field for it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JobDefinition {
    /// Optional deadline for the entire job, including joins and steps.
    pub timeout: Option<String>,
    /// Stable identity. Missing values are derived from the declaration key.
    pub id: Option<String>,
    /// Human-readable label. Missing values are derived from the declaration key.
    pub name: Option<String>,
    pub description: Option<String>,
    pub help: Option<String>,
    /// Jobs this one runs after. Resolved against `jobs:`, never against `tasks:` --
    /// the reference keeps the two namespaces apart, and a cross-namespace `needs`
    /// would be a resolution rule nobody can find.
    pub needs: Vec<String>,
    /// Overlap following jobs when reached as a dependency.
    pub background: Option<bool>,
    /// Job dependencies launched concurrently, then joined before the steps.
    pub parallel_needs: Vec<String>,
    /// Job completion barriers; `all` joins previously launched jobs.
    pub wait: Vec<String>,
    /// The steps, in the order they run.
    pub steps: Vec<StepDefinition>,
    /// Applied to every step, with the step's own `env` winning.
    pub env: indexmap::IndexMap<String, String>,
    /// Loaded for every step.
    pub dotenv: Vec<String>,
    /// Evaluated once, before the first step. A false job is skipped whole.
    pub if_condition: Option<String>,
    /// The default working directory for every step. A step's own `cwd` wins.
    pub cwd: Option<String>,
}

/// One step of a job: either a command, or a reference to another task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StepDefinition {
    /// Optional per-step deadline, overriding a referenced task's deadline.
    pub timeout: Option<String>,
    /// Optional display identity. **Never the key** -- the key is derived from the
    /// job and the step's position, so two steps cannot collide with each other or
    /// with a real task. See `lower_job` for why that is a divergence from the
    /// reference and a good one.
    pub id: Option<String>,
    pub name: Option<String>,
    /// The task this step runs, by key. Mutually exclusive with `run`.
    ///
    /// A bare scalar step is this form, matching the reference: *"A scalar step name
    /// is treated as a task reference"* (`neofile/steps.go:8`).
    pub task: Option<String>,
    /// The command this step runs, when it is not a task reference.
    pub run: Option<String>,
    /// The runner for `run`. Defaults to direct `exec`, as a task's does.
    pub uses: Option<String>,
    /// Literal arguments for a direct `exec` runner.
    pub args: Vec<String>,
    /// Applied after the job's `env`, so the step wins.
    pub env: indexmap::IndexMap<String, String>,
    /// Overrides the job's `cwd`.
    pub cwd: Option<String>,
    /// Evaluated before this step. Distinct from the job's `if`, which gates all of
    /// them at once.
    pub if_condition: Option<String>,
    /// Forces the step to run when its `if` is false.
    pub force: Option<String>,
    /// Overlap following steps until an explicit or final completion barrier.
    pub background: Option<bool>,
    /// Step IDs or referenced task names to join; `all` joins preceding work.
    pub wait: Vec<String>,
}

/// A named deployment workflow.
///
/// ## How one is selected, and it is not by a `contexts:` filter
///
/// `ShipMap.Resolve` (`neofile/ship_map.go:118-127`) is a **key convention**:
///
/// ```text
/// Resolve("", "")         -> "default"
/// Resolve("web", "prod")  -> "web:prod" if that key exists, else "web"
/// Resolve("web", "")      -> "web"
/// ```
///
/// So a project writes `web` and `web:prod` as two entries and `--context prod`
/// picks the second. **There is no ambiguity case**, because it is a key lookup
/// rather than a search over candidates -- which is simpler than a filter, and worth
/// having.
///
/// ## Why there is no `contexts:` here
///
/// `ShipDeployment.Contexts` exists in the reference and is read in exactly two
/// places, `cli/complete.go:337` and `:352` -- **shell completion**. It plays no part
/// in resolution. Since this repository has no deployment completion, a `contexts:`
/// key here would parse and do nothing, so `deny_unknown_fields` refuses it by name.
/// A key is ported with its behaviour or refused.
///
/// ## Why this is so much smaller than the reference's
///
/// The reference's `neofile.ShipDeployment` has fourteen fields. Its `ship` path
/// reads **four** of them — `Name`, `Type`, `Desc`, `Contexts` — and refuses to
/// execute at `cli.go:817` before touching any of the rest. The other ten are parsed
/// and never read, the same as `Job.Extends` and `Job.Cron` were.
///
/// So they are **refused here by name** rather than accepted and ignored. A key that
/// parses and does nothing is the failure this repository has shipped eleven of, and
/// accepting ten of them to be a superset would be building a worse version of the
/// defect. A key is ported with its behaviour or refused; a key the reference does not
/// act on has no behaviour to port.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeploymentDefinition {
    /// Stable identity. Missing values are derived from the declaration key.
    pub id: Option<String>,
    /// Human-readable label. Missing values are derived from the declaration key.
    pub name: Option<String>,
    /// What kind of deployment this is, reported by `ship list` and by `--plan`.
    ///
    /// Free-form on purpose: the reference treats an absent one as the literal
    /// `"unspecified"` (`cli.go:802-804`) rather than refusing, so there is no
    /// vocabulary to enforce and inventing one would refuse a config the reference
    /// accepts.
    pub deployment_type: Option<String>,
    pub description: Option<String>,
    pub help: Option<String>,
}

/// The type `ship` reports when a deployment declares none.
///
/// A free function rather than an associated const, because `impl` blocks cannot
/// carry constants and a `const` in the type would make every reader import the type
/// just to name a word.
pub const UNSPECIFIED_DEPLOYMENT_TYPE: &str = "unspecified";

impl DeploymentDefinition {
    /// The type to report, defaulting to `"unspecified"` as the reference does.
    #[must_use]
    pub fn reported_type(&self) -> &str {
        self.deployment_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(UNSPECIFIED_DEPLOYMENT_TYPE)
    }

    /// The display name, or the key when none is declared.
    #[must_use]
    pub fn label<'a>(&'a self, key: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(key)
    }
}
