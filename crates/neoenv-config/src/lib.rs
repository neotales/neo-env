//! Syntax parsing and normalization for `nenv` configuration documents.

use std::{collections::VecDeque, fmt, path::Path};

use indexmap::IndexMap;
use neoenv_core::{
    Diagnostic, DiagnosticCategory, SourceSpan,
    tasks::{
        DeploymentDefinition, JobDefinition, TaskAction, TaskDefinition, TaskDotenvImport,
        TaskHooks, TaskOutput, TaskOutputVisibility, TaskParameter, TaskParameterDefault,
        TaskParameterType,
    },
    tools::{PlatformOverride, PlatformSelector, ToolDeclaration, ToolProvider},
};
use serde::{Deserialize, Serialize};

/// The first public configuration format version.
pub const FORMAT_VERSION: u32 = 1;

pub mod sources;

/// Supported on-disk configuration syntaxes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Neoenv,
    Toml,
    Yaml,
}

impl Format {
    /// Determines a syntax from a recognized file name or extension.
    ///
    /// # Errors
    ///
    /// Returns a validation diagnostic when the path has no recognized format.
    pub fn from_path(path: &Path) -> Result<Self, Diagnostic> {
        match path.file_name().and_then(|name| name.to_str()) {
            Some(name) if name == neoenv_core::names::PROJECT_DIRECTORY => Ok(Self::Neoenv),
            _ => match path.extension().and_then(|extension| extension.to_str()) {
                Some("toml") => Ok(Self::Toml),
                Some("yaml" | "yml") => Ok(Self::Yaml),
                _ => Err(Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO101",
                    format!("unrecognized nenv configuration format: {}", path.display()),
                )),
            },
        }
    }
}

/// A normalized, ordered environment assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentEntry {
    pub key: String,
    pub value: String,
    pub source: SourceSpan,
    /// Declared secret, from a Go `KEY:VALUE` entry or an explicit `secret`
    /// flag. A secret is redacted from inspection and never rendered in a
    /// diagnostic, independently of whether its *name* looks sensitive.
    ///
    /// This is separate from `neoenv_policy::should_redact_environment`, which
    /// is a name heuristic. A Go file can mark any key secret, including one
    /// named `PORT`, and that has to hold.
    pub secret: bool,
}

/// A dotenv file imported while applying its declaring configuration source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotenvImport {
    pub path: String,
    pub required: bool,
    /// The OS and context this import is scoped to. Absent, the entry always
    /// applies.
    pub filter: EntryFilter,
    pub source: SourceSpan,
}

/// The OS and context an environment-affecting entry is scoped to.
///
/// One type for both `dotenv:` and `paths:`, because the predicate is the same
/// and two copies of a filter rule will drift -- and a filter that quietly stops
/// filtering is a silent behavior change, not a compile error.
///
/// The predicate is the reference's (`neofile/dotenv.go`'s `HasContext` and
/// `runner.go`'s `jobDotenvPaths`):
///
/// - the OS matches when it is absent, `*`, or equal to the running one;
/// - with no `contexts`, the entry applies only in the default context;
/// - otherwise it applies when any listed context is `*` or equal to the
///   active one.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntryFilter {
    /// The operating system this entry is scoped to. Absent, `*`, or equal to
    /// the running one all match.
    #[serde(default)]
    pub os: Option<String>,
    /// The contexts this entry is scoped to. Absent, it applies only in the
    /// default context.
    #[serde(default)]
    pub contexts: Vec<String>,
}

impl EntryFilter {
    /// A filter that never narrows anything, for the many construction sites
    /// that have no scoping to express.
    #[must_use]
    pub fn always() -> Self {
        Self::default()
    }

    /// Whether the entry applies on `os` in `context`.
    ///
    /// `os` is the *running* platform, which is not the same string a file writes
    /// or that the reference compares against: `std::env::consts::OS` is `macos`,
    /// `runtime.GOOS` is `darwin`, and `paths.go` accepts `mac`, `macos`,
    /// `darwin`, and `osx`. Compared literally, `paths: [{darwin:
    /// /opt/homebrew/bin}]` -- the exact line a user would write -- matched
    /// nothing on macOS, and `os: darwin` matched nothing either. So a declared
    /// name is matched against the running platform's *aliases* rather than
    /// against the name itself, which is also what the release-asset matcher does.
    ///
    /// A `*` still matches every platform, and a name that is an alias of nothing
    /// the running platform goes by matches nothing -- the safe direction.
    ///
    /// **The declared names are trimmed here**, in the predicate, rather than in
    /// each of the three readers that build an `EntryFilter`. The comparison is
    /// exact, so an untrimmed `os: " darwin "` or a `contexts: ['prod ']` entry
    /// matches nothing at all -- silently, on every platform. Trimming one reader
    /// left the other two unfixed, which is how the `paths:` reader could be right
    /// and the `dotenv:` reader wrong in the same commit.
    ///
    /// **This is a deliberate divergence from the reference, in the accepting
    /// direction.** `neofile/paths.go:96` stores `valueNode.Value` verbatim and
    /// `runner.go:706` compares it to `runtime.GOOS` with no trim, so the Go
    /// reference ignores a padded value where this honors it. Recorded as a
    /// divergence rather than as parity: a reference bug is not a specification.
    #[must_use]
    pub fn matches(&self, os: &str, context: &str) -> bool {
        let os_matches = self.os.as_deref().is_none_or(|declared| {
            let declared = declared.trim();
            declared.is_empty()
                || declared == "*"
                || neoenv_core::tools::platform_os_aliases(os).contains(&declared)
        });
        if !os_matches {
            return false;
        }
        // **Presence, not content, decides the default-context rule.** A `contexts`
        // key that is absent applies in the default context; a key that is present
        // applies only where one of its entries names the running context. An
        // earlier version dropped blank *entries* and then asked the resulting list
        // whether it was empty, which made the two questions the same question --
        // and picked the wrong answer for the case that produces blanks on its own.
        // `contexts: ["${CTX}"]` with `CTX` unset, or a padded `['prod ']`, became
        // an empty list, which means the default context, which means a `dotenv:`
        // entry scoped to production *loaded its production secrets in the default
        // context*. Before that it loaded nowhere. Widening a filter that names a
        // context this run does not have is the one failure mode worth spending a
        // line on here: the alternative -- dropping the key -- silently *grants* the
        // scope the user was withholding.
        //
        // So a present key with no usable entry matches nothing. That is not
        // symmetric with a blank `os`, and the asymmetry is deliberate rather than
        // an oversight: `os` is an `Option`, so `Some("")` is a value and `None` is
        // no value, and a blank one reads as "no OS filter". `contexts` is a list,
        // so a blank member is a *name*, and a name that exists nowhere names
        // nothing. Earlier this doc claimed both halves shared one reading of
        // blank; they did not, and the one shape that was shared was the dangerous
        // one.
        if self.contexts.is_empty() {
            return context.is_empty() || context == "*" || context == "default";
        }
        self.contexts
            .iter()
            .map(|declared| declared.trim())
            .filter(|declared| !declared.is_empty())
            .any(|declared| declared == "*" || declared == context)
    }
}

/// A typed, ordered operation on `PATH`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathOperation {
    pub kind: PathOperationKind,
    pub value: String,
    /// The OS and context this entry is scoped to. Absent, it always applies.
    pub filter: EntryFilter,
    pub source: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathOperationKind {
    Prepend,
    Append,
}

/// The currently implemented configuration contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Project {
    pub format_version: u32,
    pub source: SourceSpan,
    /// Declared secret providers, in declaration order.
    ///
    /// **A declaration, not a resolution.** Loading a project never opens a
    /// vault, a keyring, or an identity file. A value that names a vault is
    /// resolved where it is consumed; see `docs/vaults.md`.
    pub vaults: IndexMap<String, VaultDeclaration>,
    pub environment: Vec<EnvironmentEntry>,
    pub dotenv: Vec<DotenvImport>,
    pub path: Vec<PathOperation>,
    pub tools: Vec<ToolDeclaration>,
    pub context: Option<String>,
    /// Explicit directories used to resolve otherwise unsupported task runners.
    pub task_dirs: TaskDirectories,
    /// Named, structured local task packages. These are intentionally distinct
    /// from executable fallback runner directories.
    pub task_packages: IndexMap<String, TaskPackage>,
    pub tasks: IndexMap<String, TaskDefinition>,
    /// Ordered pipelines. A namespace of its own, deliberately not reachable from
    /// `tasks` -- a job is a sequence and a task is a node, and resolving one
    /// through the other's map would make the two indistinguishable.
    pub jobs: IndexMap<String, JobDefinition>,
    /// Named lists of hosts this project may open connections to.
    ///
    /// **A declaration, not a grant.** What makes a host reachable is a
    /// `connect` capability grant naming `inventory:{name}/host:{host}`, and the two
    /// are separate on purpose: declaring a host and authorising nenv to reach it are
    /// different decisions by different people, and a config that did both would let
    /// anyone who can edit a file grant themselves a network capability.
    pub inventories: IndexMap<String, Inventory>,
    /// Inventory-only documents, relative to this document and loaded before inline entries.
    pub inventory_files: Vec<String>,
    /// Named deployment workflows, as the reference's `ship:` section.
    ///
    /// Refused by `ship`'s verbs rather than executed, because the reference does not
    /// execute them either -- see
    /// `docs/decision-records/inventory-hosts-are-a-subject.md` and #257.
    pub deployments: IndexMap<String, DeploymentDefinition>,
    pub imports: Vec<ModuleImport>,
    /// Explicit local workspace members and aliases. Discovery never scans for members.
    pub workspace: Workspace,
}

/// A declared source of secret values.
///
/// The declaration is configuration data: it records which provider to use and
/// which provider-specific settings were written. It does not hold a resolved
/// secret and it does not prove the provider can be opened.
///
/// `Debug` is redacted. A provider declaration can contain a master password or
/// ciphertext, and a `Project` is printed by test failures and by code that
/// formats a load error.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultDeclaration {
    /// The name a `nsv://` reference uses in its first segment.
    pub name: String,
    /// The provider and its provider-specific settings.
    pub provider: VaultProvider,
    /// Where the declaration was written.
    pub source: SourceSpan,
}

impl fmt::Debug for VaultDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultDeclaration")
            .field("name", &self.name)
            .field("provider", &self.provider.name())
            .field("source", &self.source)
            .finish()
    }
}

impl VaultDeclaration {
    /// The provider name the configuration wrote.
    #[must_use]
    pub const fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

/// The provider-specific half of a [`VaultDeclaration`].
#[derive(Clone, Eq, PartialEq)]
pub enum VaultProvider {
    /// An age identity plus encrypted bootstrap values.
    Age(AgeVault),
    /// A `KeePass` KDBX document opened with a master password.
    Keepass(KeepassVault),
    /// The operating-system credential store.
    Os(OsVault),
}

impl VaultProvider {
    /// The stable provider name used on disk and in diagnostics.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Age(_) => "age",
            Self::Keepass(_) => "keepass",
            Self::Os(_) => "os",
        }
    }
}

impl fmt::Debug for VaultProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Age(vault) => formatter.debug_tuple("Age").field(vault).finish(),
            Self::Keepass(vault) => formatter.debug_tuple("Keepass").field(vault).finish(),
            Self::Os(vault) => formatter.debug_tuple("Os").field(vault).finish(),
        }
    }
}

/// An `age` vault's settings.
#[derive(Clone, Eq, PartialEq)]
pub struct AgeVault {
    /// An identity file path, an inline `AGE-SECRET-KEY-...`, or an `nsv://`
    /// reference. Absent means the machine identity under the user config
    /// directory.
    ///
    /// Redacted by `Debug`: a path is usually harmless but an inline identity
    /// is not, and one representation must not leak because the other is safe.
    pub identity: Option<String>,
    /// Encrypted bootstrap values, keyed by the path a reference uses.
    pub values: IndexMap<String, String>,
}

impl fmt::Debug for AgeVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgeVault")
            .field("identity", &self.identity.as_ref().map(|_| "[redacted]"))
            .field(
                "values",
                &format_args!("{} encrypted value(s)", self.values.len()),
            )
            .finish()
    }
}

/// A `keepass` vault's settings.
#[derive(Clone, Eq, PartialEq)]
pub struct KeepassVault {
    /// The KDBX path, as written. Resolved against the declaring file.
    pub path: String,
    /// The master password: a literal, an interpolated value, or an `nsv://`
    /// reference.
    ///
    /// Redacted by `Debug`. Every error path must also keep it out of its
    /// message.
    pub secret: String,
}

impl fmt::Debug for KeepassVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeepassVault")
            .field("path", &self.path)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// An operating-system credential store vault's settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsVault {
    /// The keyring service name. Defaults to [`DEFAULT_OS_SERVICE`].
    pub service: String,
}

/// The default keyring service when an `os` vault omits `service`.
pub const DEFAULT_OS_SERVICE: &str = "neoenv";

/// A local-only workspace declaration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Workspace {
    pub members: Vec<String>,
    pub aliases: IndexMap<String, String>,
}

/// A module source and the optional task view it contributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleImport {
    pub from: String,
    pub namespace: Option<String>,
    pub tasks: Vec<String>,
}

/// Explicit task-runner search directories. Empty lists disable fallback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskDirectories {
    pub local: Vec<String>,
    pub global: Vec<String>,
}

/// A task package selected by a stable project-local alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskPackage {
    /// A project-relative source or a bare package name resolved from the
    /// project/user `nenv` task-package roots.
    pub from: String,
    /// The package task exported to callers. Defaults to `default`.
    pub task: String,
}

/// Which configuration dialect a document is read as.
///
/// `Native` is the strict v1 schema and is the only one that can appear in a
/// project's own resolution. `Go` is an opt-in read-only compatibility profile
/// for a Go `nenv` file; it normalizes Go input into the same v1 model so the
/// rest of the system cannot tell the difference, and it is never written back.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConfigProfile {
    #[default]
    Native,
    Go,
}

/// The profile for this process, chosen once by argument parsing.
///
/// A process-wide setting rather than a parameter because the profile is a
/// property of the invocation, not of any one call: `validate`, `inspect`,
/// `run`, `exec`, `task *`, `workspace *`, and every `tool` subcommand all read
/// a configuration document, and threading a parameter through that many entry
/// points is how a *missed* site becomes a command that silently ignores the
/// option. The first write wins, so a library cannot be reconfigured mid-run.
static PROCESS_PROFILE: std::sync::OnceLock<ConfigProfile> = std::sync::OnceLock::new();

impl ConfigProfile {
    /// Records the profile for this process. Later calls are ignored.
    pub fn set_process_profile(profile: Self) {
        let _ = PROCESS_PROFILE.set(profile);
    }

    /// The profile for this process, defaulting to the strict v1 schema.
    #[must_use]
    pub fn process_profile() -> Self {
        PROCESS_PROFILE.get().copied().unwrap_or_default()
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "native" | "v1" => Some(Self::Native),
            "go" | "neofile" => Some(Self::Go),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Go => "go",
        }
    }
}

/// Parses a format-versioned configuration document without performing I/O.
///
/// # Errors
///
/// Returns a validation diagnostic for unsupported formats, malformed syntax,
/// unsupported format versions, or invalid environment keys.
pub fn parse_project(path: &Path, input: &str) -> Result<Project, Diagnostic> {
    parse_project_with_profile(path, input, Format::from_path(path)?, ConfigProfile::Native)
}

/// Parses an inventory-only YAML/TOML document. Rejects every other top-level
/// key, including empty declarations, rather than silently discarding content.
///
/// # Errors
/// Returns a redacted validation diagnostic for non-inventory content or syntax.
pub fn parse_inventory_file(
    path: &Path,
    input: &str,
) -> Result<IndexMap<String, Inventory>, Diagnostic> {
    let invalid = || {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO444",
            "inventory file must be YAML/TOML containing only format_version and inventories",
        )
    };
    let keys: Vec<String> = match Format::from_path(path).map_err(|_| invalid())? {
        Format::Yaml => {
            let value: serde_yaml::Value = serde_yaml::from_str(input).map_err(|_| invalid())?;
            value
                .as_mapping()
                .ok_or_else(invalid)?
                .keys()
                .map(|key| key.as_str().map(str::to_owned).ok_or_else(invalid))
                .collect::<Result<_, _>>()?
        }
        Format::Toml => {
            let value: toml::Value = toml::from_str(input).map_err(|_| invalid())?;
            value
                .as_table()
                .ok_or_else(invalid)?
                .keys()
                .cloned()
                .collect()
        }
        Format::Neoenv => return Err(invalid()),
    };
    if keys
        .iter()
        .any(|key| !matches!(key.as_str(), "format_version" | "inventories" | "inventory"))
        || !keys
            .iter()
            .any(|key| matches!(key.as_str(), "inventories" | "inventory"))
    {
        return Err(invalid());
    }
    parse_project(path, input)
        .map(|project| project.inventories)
        .map_err(|_| invalid())
}

/// Parses a configuration document using an explicitly selected format.
///
/// This supports callers that expose a format override without changing the
/// source path used in diagnostics and provenance.
///
/// # Errors
///
/// Returns a validation diagnostic for malformed syntax, unsupported format
/// versions, duplicate keys, or invalid environment keys.
pub fn parse_project_with_format(
    path: &Path,
    input: &str,
    format: Format,
) -> Result<Project, Diagnostic> {
    parse_project_with_profile(path, input, format, ConfigProfile::Native)
}

/// Parses a configuration document in an explicitly selected profile.
///
/// The profile selects a whole *parse path*, never a relaxation of the strict
/// one: `Native` still rejects every unknown field. That is what lets a Go file
/// be read without a native file becoming any easier to get wrong.
///
/// # Errors
///
/// Returns a validation diagnostic for malformed syntax, unsupported format
/// versions, duplicate keys, invalid environment keys, or a Go construct that
/// the Go reference itself does not execute.
pub fn parse_project_with_profile(
    path: &Path,
    input: &str,
    format: Format,
    profile: ConfigProfile,
) -> Result<Project, Diagnostic> {
    match profile {
        ConfigProfile::Native => match format {
            Format::Neoenv => parse_neoenv(path, input),
            Format::Toml => parse_toml(path, input),
            Format::Yaml => parse_yaml(path, input),
        },
        ConfigProfile::Go => match format {
            // The line-oriented `.neoenv` syntax has no Go equivalent; a Go
            // document is always YAML or TOML.
            Format::Neoenv => Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO131",
                "the go compatibility profile requires a YAML or TOML document",
            )
            .at(document_span(path, input))),
            format => compat::parse_go(path, input, format),
        },
    }
}

/// Parses a format-versioned environment document without performing I/O.
///
/// This compatibility alias will be removed when the broader project model is
/// introduced; new callers should use [`parse_project`].
///
/// # Errors
///
/// Returns the same diagnostic as [`parse_project`].
pub fn parse_environment_document(path: &Path, input: &str) -> Result<Project, Diagnostic> {
    parse_project(path, input)
}

mod compat;
#[cfg(test)]
mod compat_tests;
mod neoenv;
mod normalize;
mod spans;
mod structured;
#[cfg(test)]
mod tests;
mod use_block;

use neoenv::parse_neoenv;
use structured::{parse_toml, parse_yaml};

fn default_format_version() -> u32 {
    FORMAT_VERSION
}
fn required_dotenv() -> bool {
    true
}
fn reject_command_substitution(value: &str, path: &str, line: u32) -> Result<(), Diagnostic> {
    if value.contains("$(") || value.contains('`') {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO111",
            "command substitution is not supported in environment declarations",
        )
        .at(SourceSpan::new(path.to_owned(), line, 1)));
    }
    Ok(())
}

fn document_error(path: &Path, input: &str, code: &str, message: String) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, code, message).at(document_span(path, input))
}

fn document_span(path: &Path, input: &str) -> SourceSpan {
    let line_count = u32::try_from(input.lines().count())
        .unwrap_or(u32::MAX)
        .max(1);
    SourceSpan::new(path.display().to_string(), line_count, 1)
}

/// A named list of hosts.
///
/// ## Why the host list is a declaration and not a grant
///
/// Because the authorisation is a **capability grant keyed by host**, so adding a
/// host to this list does not authorise anything -- it makes the host *eligible*,
/// and the run is refused until a grant names it. That direction is the safe one and
/// it is safe by construction: the grant set is the thing that has to be edited
/// deliberately, and the file most people edit is not it.
///
/// A project that declared hosts and treated the declaration as permission would let
/// anybody who can write `neoenv.yaml` grant themselves a network capability. The
/// whole point of the existing `ProjectTrust { path, sha256 }` mechanism is the
/// opposite property, and the two together are what "the config said so" is not a
/// trust decision means.
/// A named list of hosts, and the defaults they inherit.
///
/// ## Why this is richer than a list of names
///
/// Because the reference's is, and the part that matters is **tags**. A target is
/// either a host name or `@tag` (`projects/inventory.go:62`,
/// `strings.TrimPrefix(target, "@")`), and a tag matching several hosts is the whole
/// reason to have an inventory rather than a list: `nenv ssh @prod` is the thing a
/// user wants to type. A `Vec<String>` would be parity in name and not in use.
///
/// Host **declaration order** is kept as well as the map, because resolution walks
/// hosts in the order the file wrote them and a map's order is not that. Two runs
/// over one file have to produce the same plan, and a plan you cannot diff is a plan
/// you cannot review.
///
/// ## Why a host here authorises nothing
///
/// The authorisation is a `connect` capability grant naming
/// `inventory:{inventory}/host:{host}`, and the two are separate on purpose:
/// declaring a host and authorising nenv to reach it are different decisions, and a
/// config that did both would let anybody who can edit a file grant themselves a
/// network capability. See
/// `docs/decision-records/inventory-hosts-are-a-subject.md`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Inventory {
    /// The hosts, keyed by name, in whatever order the reader gave them.
    pub hosts: IndexMap<String, InventoryHost>,
    /// The names in declaration order. `IndexMap` preserves insertion order, and this
    /// is a second copy of it so a reader that re-sorts the map cannot quietly change
    /// the order a plan is printed in.
    pub order: Vec<String>,
    /// Applied to every host that does not set its own.
    pub defaults: InventoryDefaults,
}

/// One host: where to reach it, and what it is called in a tag.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InventoryHost {
    /// The address to connect to, when it differs from the host's name.
    ///
    /// `None` means "the name is the address", which is the common case and the one
    /// that makes `inventories: {prod: [web1, web2]}` read the way it looks.
    pub address: Option<String>,
    /// The tags this host answers to. A target of `@prod` matches a host with `prod`
    /// among its tags.
    pub tags: Vec<String>,
    /// Explicit SSH login; otherwise the inventory default is required.
    pub user: Option<String>,
    /// Explicit SSH port; otherwise the inventory default or 22.
    pub port: Option<u16>,
    /// Required base64 SSH-format Ed25519 public host-key blob, never TOFU.
    pub host_key: Option<String>,
    /// Name of an environment value resolved only when connecting.
    /// When `identity_file` is configured this is the key passphrase; otherwise
    /// it is used as a login password only with `password_auth: true`.
    pub password_env: Option<String>,
    /// Optional private identity path; overrides the inventory default.
    /// Relative paths are resolved against the project root. `~` uses the
    /// effective HOME (USERPROFILE on Windows); `~user` is unsupported.
    pub identity_file: Option<String>,
    /// Opts into password login when no identity file is configured.
    /// Without this flag, the default authentication method is the SSH agent.
    pub password_auth: bool,
}

/// What every host inherits unless it says otherwise.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InventoryDefaults {
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Private identity path inherited by hosts that do not specify one.
    /// Relative paths are resolved against the project root. `~` uses the
    /// effective HOME (USERPROFILE on Windows); `~user` is unsupported.
    pub identity_file: Option<String>,
}

impl Inventory {
    /// Whether `host` is one this inventory names.
    ///
    /// Case-insensitive, because a host name is a DNS name and DNS is
    /// case-insensitive: `Web1` and `web1` are the same machine, and treating them as
    /// different hosts would let `web1` be granted and `Web1` be used.
    #[must_use]
    pub fn has_host(&self, host: &str) -> bool {
        self.hosts
            .keys()
            .any(|name| name.eq_ignore_ascii_case(host))
    }

    /// The names in declaration order, or the map's order when `order` is empty.
    ///
    /// The fallback is for a project built by hand rather than read from a file --
    /// a test, or a caller constructing an `Inventory` directly. Empty `order` with a
    /// populated `hosts` cannot come from the reader, which always fills both.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        if self.order.is_empty() {
            self.hosts.keys().map(String::as_str).collect()
        } else {
            self.order.iter().map(String::as_str).collect()
        }
    }

    /// The address to reach `name` on: its own, or its name.
    #[must_use]
    pub fn address_of(&self, name: &str) -> String {
        self.hosts
            .get(name)
            .and_then(|host| host.address.clone())
            .unwrap_or_else(|| name.to_owned())
    }
}
