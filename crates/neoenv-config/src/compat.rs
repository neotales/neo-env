//! Opt-in Go `nenv` compatibility profile.
//!
//! This is a *separate read path*, not a relaxation of the strict v1 one. A
//! native document still rejects every unknown field. A Go document is read
//! here, assembled into the same [`StructuredProject`] the native reader
//! produces, and handed to the same normalizer — so every rule, span,
//! diagnostic, and invariant that applies to a native file applies unchanged,
//! and nothing downstream can tell which dialect produced a `Project`.
//!
//! ## Scope
//!
//! Supported: `config.context` and `config.defaults.context`, both `env:`
//! forms (the v1 mapping and the Go sequence, including the Go secret flag),
//! and every section whose *shape* is already shared — `tools`, `tasks`,
//! `task_dirs`, `task_packages`, `imports`, `workspace`, `context`, and the
//! bare-string `dotenv:`/`path:` forms. Reading the shared sections is what
//! makes a half-migrated file inspectable instead of all-or-nothing.
//!
//! Not yet supported, and rejected *by name* rather than ignored: Go `use:`
//! tool entries, OS- and context-filtered `dotenv` entries, per-entry `PATH`
//! filtering, and the `inventories`, `ship`, `config.modules`, and
//! `config.external` constructs — the last three because the Go reference does
//! not execute them either, or because they change what resolves. Silently
//! ignoring any of these would produce a run that looked successful while
//! dropping the user's tools, which is the one failure mode a compatibility
//! layer must never have.

use std::{collections::BTreeMap, path::Path};

use neoenv_core::{Diagnostic, DiagnosticCategory};

use super::neoenv::validate_key;
use super::spans::{StructuredSpans, structured_spans};
use super::structured::{
    DotenvList, ModuleImportList, StructuredDeployment, StructuredDotenv,
    StructuredDotenvDeclaration, StructuredInventory, StructuredJob, StructuredPathOperation,
    StructuredProject, StructuredTask, StructuredTaskDirectories, StructuredTaskPackage,
    StructuredTool, StructuredTools, StructuredWorkspace, structured_project,
};
use super::{
    Deserialize, EnvironmentEntry, Format, IndexMap, Project, default_format_version,
    document_error, reject_command_substitution, required_dotenv,
};

/// A Go `env:` entry. A `KEY:VALUE` scalar and an explicit `secret: true`
/// mapping are secrets; `KEY=VALUE` is a plain value.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoEnvItem {
    Scalar(String),
    /// A separate struct because `deny_unknown_fields` cannot be attached to an
    /// enum variant. It matters here: without it, a misspelled `secrets: true`
    /// would be dropped and the value would print in clear.
    Mapping(GoEnvMapping),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoEnvMapping {
    name: String,
    value: String,
    #[serde(default)]
    secret: bool,
}

/// The Go `env:` section: the v1 mapping, or the Go ordered sequence.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoEnvSection {
    /// The native v1 form, which the shared normalizer already validates.
    Mapping(IndexMap<String, String>),
    /// The Go mapping form whose *value* is a mapping, as in
    /// `FOO: {value: bar, secret: true}` (`env.go`). The v1 mapping cannot hold
    /// it, so it is a third shape rather than an alias.
    Detailed(IndexMap<String, GoDetailedEnvValue>),
    /// The Go ordered form. Order is significant, so this stays a `Vec`.
    Sequence(Vec<GoEnvItem>),
}

/// One Go `dotenv:` entry. A bare string and a native declaration are both
/// shared shapes; `os`/`contexts` are the Go-only filter.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoDotEnvMapping {
    Native(StructuredDotenv),
    /// An unknown key makes the mapping match neither variant, so it is rejected
    /// rather than dropped. The known Go-only keys get the named diagnostic below.
    Go(GoDotEnvFilter),
}

/// A `dotenv:` entry carrying a Go-only platform or context filter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoDotEnvFilter {
    path: String,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    contexts: Vec<String>,
}

/// One Go `paths:` entry: the native `{prepend, append}` shape, or the Go
/// shape. `append: false` is the default in both dialects, so it is accepted
/// rather than treated as a Go-only key.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoPathMapping {
    Native(StructuredPathOperation),
    // Boxed because the nine OS shorthand fields make this variant several times
    // the size of `Native`, and every conversion of one moves it.
    Go(Box<GoPathFilter>),
}

/// A `path:` entry carrying a Go-only platform filter or an append shorthand.
///
/// No `deny_unknown_fields`: it is incompatible with the `flatten` below, and
/// the inventory walk in `validate_key_inventory` is what rejects an unknown
/// key — with a better message, because it names the key.
#[derive(Deserialize)]
struct GoPathFilter {
    /// The reference accepts `path` and `value` for the same thing
    /// (`paths.go`, the `case "value", "path"` arm). Both are read here, because
    /// an unread one does not fail -- it becomes an *empty* path entry, which
    /// is the one outcome worse than a diagnostic.
    #[serde(default)]
    path: Option<String>,
    #[serde(default, alias = "value")]
    value: Option<String>,
    #[serde(default)]
    os: Option<String>,
    // The reference's OS shorthands (`paths.go`), each of which also carries the
    // path. Read because the key inventory is what *rejects* an unrecognized
    // key, and a shorthand the inventory does not list would be named as unknown
    // by a file that is perfectly valid.
    #[serde(default)]
    windows: Option<String>,
    #[serde(default)]
    win: Option<String>,
    #[serde(default)]
    win32: Option<String>,
    #[serde(default)]
    linux: Option<String>,
    #[serde(default)]
    unix: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    macos: Option<String>,
    #[serde(default)]
    darwin: Option<String>,
    #[serde(default)]
    osx: Option<String>,
    #[serde(default)]
    append: bool,
}

impl GoPathFilter {
    /// The path and OS the entry declares, or `None` if it names no path.
    ///
    /// One walk, and both values come from the *same* key. Two independent
    /// fixed-ordering chains let one entry take its path from one key and its OS
    /// from another: `paths: [{darwin: /opt/homebrew/bin, linux: /usr/bin}]` took
    /// the path from `darwin` and the OS from `linux`, so a macOS directory was
    /// added on Linux. The reference's `paths.go` switch is document-order
    /// last-wins, which has the same property for the reason that matters here --
    /// `Path` and `OS` are always set together, in one arm.
    ///
    /// A shorthand *is* a path: the reference's arm is `case "linux", "unix":
    /// ep.OS = "linux"; ep.Path = valueNode.Value`, so `paths: [{linux: /bin}]`
    /// names `/bin` and scopes it to Linux.
    ///
    /// The order below is fixed rather than document order, because a struct with
    /// named fields has lost the document order by the time this runs. The first
    /// key that names a path wins, which is the opposite of the reference's
    /// last-wins; a Go file with two path keys in one entry is malformed either
    /// way, and agreeing with itself matters more than agreeing with a case that
    /// cannot be written deliberately.
    fn resolved(&self) -> Option<(String, Option<String>)> {
        // `(path, os)` per key, generic keys first because `path`/`value` are the
        // unambiguous spellings and a shorthand alongside one of them is a typo.
        // Eleven rows, not twelve. There is no "and an explicit `os` on its own"
        // row: a bare `os:` with no path names no directory, and the caller
        // refuses that by name.
        let candidates: [(Option<&String>, Option<&str>); 11] = [
            (self.path.as_ref(), None),
            (self.value.as_ref(), None),
            (self.windows.as_ref(), Some("windows")),
            (self.win.as_ref(), Some("windows")),
            (self.win32.as_ref(), Some("windows")),
            (self.linux.as_ref(), Some("linux")),
            (self.unix.as_ref(), Some("linux")),
            (self.mac.as_ref(), Some("darwin")),
            (self.macos.as_ref(), Some("darwin")),
            (self.darwin.as_ref(), Some("darwin")),
            (self.osx.as_ref(), Some("darwin")),
        ];
        for (path, os) in candidates {
            if let Some(path) = path.filter(|path| !path.trim().is_empty()) {
                // Not trimmed here: `EntryFilter::matches` trims, because the
                // comparison is exact and there are three readers that build an
                // `EntryFilter`. Trimming one of them left the other two wrong in
                // the same commit.
                let os = os.map(str::to_owned).or_else(|| self.os.clone());
                return Some((path.clone(), os));
            }
        }
        None
    }
}

impl From<GoPathMapping> for StructuredPathOperation {
    /// Only called for an entry that names a path; [`select_path`] refuses the
    /// others by name first.
    ///
    /// A `From` impl cannot express "no path" without either a panic or a
    /// default, and the caller's check runs *after* the conversion -- so a
    /// `paths: [{darwin: ""}]` reached the default and produced the empty PATH
    /// entry the reader is written to forbid, which resolves to the *project
    /// root* on PATH. Resolving first makes the empty case unrepresentable here.
    fn from(mapping: GoPathMapping) -> Self {
        match mapping {
            GoPathMapping::Native(operation) => operation,
            GoPathMapping::Go(declared) => {
                let (path, os) = declared
                    .resolved()
                    .expect("select_path refuses an entry that names no path");
                let filter = super::EntryFilter {
                    os,
                    contexts: Vec::new(),
                };
                if declared.append {
                    return Self {
                        prepend: None,
                        append: Some(path),
                        filter,
                    };
                }
                Self {
                    prepend: Some(path),
                    append: None,
                    filter,
                }
            }
        }
    }
}

/// The value of a Go `env:` mapping entry, as in
/// `FOO: {value: bar, secret: true}`.
///
/// A separate shape from [`GoEnvMapping`] because here the *outer* key is the
/// variable name, so an inner `name` is optional -- and if both are present they
/// must agree, or the file has given the same variable two names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoDetailedEnvValue {
    value: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    secret: bool,
}

impl GoDetailedEnvValue {
    fn declared_name(&self) -> Option<&String> {
        self.name.as_ref()
    }
}

#[derive(Deserialize, Default)]
struct GoDefaults {
    context: Option<String>,
    /// Inert here for the same reason the top-level `config.shell` is: the Rust
    /// shell is fixed per command, not per project. Declared so a valid Go file
    /// is not rejected for using it. Never read is the intended state.
    #[serde(default)]
    #[allow(dead_code)]
    shell: Option<String>,
}

/// Go's `config:` section.
///
/// `shell`, `env.substitution`, `root`, `include`, `exclude`, `aliases`, and
/// `merge` are accepted and inert here; `modules` and `external` are rejected
/// because they change what resolves. Being explicit about which is which is
/// what lets a Go file be read without guessing.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct GoConfigSection {
    context: Option<String>,
    #[serde(default)]
    defaults: Option<GoDefaults>,
    /// Rejected: a mutable module list changes what an import resolves to.
    #[serde(default)]
    modules: Option<serde::de::IgnoredAny>,
    /// Rejected: an external root makes discovery walk outside the project.
    #[serde(default)]
    external: Option<String>,
    /// Accepted, and deliberately not acted on. See [`InertGoConfig`] for why
    /// each key is inert; the field is never read, which is the point.
    #[serde(flatten)]
    #[allow(dead_code)]
    inert: InertGoConfig,
}

/// Go `config:` keys this profile accepts but does not act on.
///
/// They are declared so a valid Go file is not rejected for using them, and read
/// never so they cannot be acted on by accident. Each has a reason:
///
/// - `shell`: the Rust shell is fixed per command, not per project.
/// - `env.substitution`: every Rust value is already a plain string.
/// - `root`: workspace-root declaration is a discovery concern, and the Rust
///   discoverer has its own precedence.
/// - `include`/`exclude`/`aliases`/`merge`: workspace file filtering. The Rust
///   workspace takes declared members and declared aliases only.
///
/// [`allow(dead_code)`] is the honest annotation here: the fields exist to be
/// *accepted and ignored*, so "never read" is the intended state, not a gap.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct InertGoConfig {
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    env: Option<GoEnvSubstitution>,
    #[serde(default)]
    root: Option<bool>,
    #[serde(default)]
    include: Option<Vec<String>>,
    #[serde(default)]
    exclude: Option<Vec<String>>,
    #[serde(default)]
    aliases: Option<IndexMap<String, String>>,
    #[serde(default)]
    merge: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct GoEnvSubstitution {
    #[serde(default)]
    substitution: Option<bool>,
}

/// The Go document.
///
/// `deny_unknown_fields` is the load-bearing attribute: an unrecognized
/// top-level key is a named error, never a silent drop. Every Go-only section
/// is declared even where this profile cannot act on it, precisely so it can
/// be named in a diagnostic instead of vanishing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoDocument {
    /// Go files predate `format_version`; it is implied.
    #[serde(default = "default_format_version")]
    format_version: u32,
    #[serde(default)]
    config: Option<GoConfigSection>,
    /// Both dialects, so `environment` stays an accepted alias.
    #[serde(default, alias = "environment")]
    env: Option<GoEnvSection>,
    #[serde(default)]
    dotenv: Option<GoDotEnvList>,
    /// The Go `PATH` section is spelled `paths:`; `path:` is the Rust-native
    /// one. Both are accepted so a half-migrated file still reads.
    #[serde(default, rename = "paths", alias = "path")]
    path: Option<GoPathList>,
    #[serde(default)]
    tools: Vec<StructuredTool>,
    /// Native context selection, when the file has not migrated to `config:`.
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    task_dirs: StructuredTaskDirectories,
    #[serde(default, alias = "packages")]
    task_packages: IndexMap<String, StructuredTaskPackage>,
    #[serde(default)]
    tasks: IndexMap<String, StructuredTask>,
    /// Ordered pipelines. `default` because a Go document without a `jobs:` section
    /// is the common case, and without it every such file fails to deserialize --
    /// which surfaces as "the Go document is not valid YAML", a message about the
    /// wrong thing entirely. That phrasing is worth remembering: it is what a serde
    /// shape error looks like from the outside, and it cost an hour once already.
    #[serde(default)]
    jobs: IndexMap<String, StructuredJob>,
    #[serde(default, alias = "modules")]
    imports: ModuleImportList,
    #[serde(default)]
    workspace: StructuredWorkspace,
    /// The Go `use:` tool block. Read by `use_block::normalize_use`.
    #[serde(default, rename = "use")]
    use_block: Option<indexmap::IndexMap<String, serde_yaml::Value>>,
    /// Declared by Go, and **not executed by Go either** -- the reference resolves
    /// inventory targets and then says "SSH execution is not implemented yet"
    /// (`cli/cli.go:2298`). Carried through the normalizer as a real value now, so a
    /// Go file naming hosts is read rather than refused, and the hosts still authorise
    /// nothing without a `connect` capability grant.
    #[serde(default)]
    inventories: IndexMap<String, StructuredInventory>,
    /// Carried through the normalizer as a real value. It was refused here on the
    /// grounds that the Go reference does not execute `ship` either -- true, and the
    /// wrong reason for the same reason `inventories` was: the reader had nowhere to
    /// put the deployments.
    /// Carried through the normalizer as a real value, and -- like `inventories` --
    /// not because the Go reference executes it, which it does not, but because the
    /// reader now has somewhere to put it.
    #[serde(default, rename = "ship")]
    ship: IndexMap<String, StructuredDeployment>,
}

/// A Go `dotenv:` list, which admits bare strings alongside declarations.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoDotEnvList {
    Single(String),
    List(Vec<GoDotEnvEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GoDotEnvEntry {
    Path(String),
    Mapping(GoDotEnvMapping),
}

/// A Go `path:` list, which admits bare strings alongside declarations.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoPathList {
    Single(String),
    List(Vec<GoPathEntry>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GoPathEntry {
    Value(String),
    Mapping(GoPathMapping),
}

/// The Go key inventory, validated before serde runs.
///
/// serde reports an unknown key inside an untagged variant as "data did not
/// match any variant", which names neither the key nor the field it wanted.
/// Checking the inventory here produces a diagnostic that names the offending
/// key, where it was, and the keys that *are* valid -- and it means that
/// property does not depend on how any particular serde version words its own
/// message. `an_unknown_key_is_named_at_every_level` is the test that holds it.
/// The Go top-level keys, from `neofile.go`'s own switch.
///
/// Two of these are *not* the Rust spelling and must not be treated as one:
/// `paths` is the Go `PATH` section and the reference rejects `path` at the top
/// level, and `description` is the Go spelling of the Rust `context`-adjacent
/// task metadata. The Rust-native keys are listed alongside because a file that
/// has been half-migrated legitimately carries both, and rejecting one would
/// refuse a file the user is in the middle of converting.
const TOP_LEVEL_KEYS: &[&str] = &[
    // Go.
    "id",
    "name",
    "version",
    "description",
    "desc",
    "subcmds",
    "subcommands",
    "on",
    "config",
    "import",
    "env",
    "dotenv",
    "paths",
    "meta",
    "tasks",
    "jobs",
    "ship",
    "deployments",
    "use",
    // `inventories` is accepted and read. It was refused for a long time with a
    // message noting the Go reference does not execute it either -- true, and the
    // wrong reason to refuse a port: the reader had nowhere to put the hosts. It has
    // an `Inventory` now, and the hosts authorise nothing without a `connect` grant.
    "inventory",
    "inventories",
    "trusted_sources",
    "trustedSources",
    "trusted-sources",
    // Rust-native, for a half-migrated file.
    "format_version",
    "environment",
    "path",
    "tools",
    "context",
    "task_dirs",
    "packages",
    "task_packages",
    "imports",
    "modules",
    "workspace",
];

/// Go project metadata the reference reads and this model has no field for.
const GO_PROJECT_METADATA: &[&str] = &[
    "id",
    "name",
    "version",
    "description",
    "desc",
    "subcmds",
    "subcommands",
    "on",
    "meta",
    // `jobs` was here and is not any more. It is a key the reference reads and this
    // model had no field for, so a Go file with a pipeline was refused with NEO132
    // naming it. The model has `JobDefinition` now, so the key is carried through the
    // same normalizer as a native one -- which is the point: a refusal is only the
    // right answer while there is nowhere to put the thing.
    "inventory",
    "trusted_sources",
    "trustedSources",
    "trusted-sources",
];

const CONFIG_KEYS: &[&str] = &[
    "context", "defaults", "shell", "env", "root", "include", "exclude", "aliases", "merge",
    "modules", "external",
];

const DEFAULTS_KEYS: &[&str] = &["context", "shell"];

/// A `dotenv:` entry is a bare string, or a mapping with these keys.
///
/// `os` and `contexts` are the reference's own keys on its own `DotEnv`, and
/// `runner.go` applies both. They used to be listed and then refused by
/// `go_only_keys`, on the grounds that the model had nowhere to put them; it has
/// a place now.
const DOTENV_ENTRY_KEYS: &[&str] = &["path", "required", "os", "contexts"];

/// A `paths:` entry, from `paths.go`'s own switch.
///
/// The OS shorthands (`windows`/`win`/`win32`, `linux`/`unix`,
/// `mac`/`macos`/`darwin`/`osx`) each mean "this path, on that platform" and are
/// *honored*: the reference parses them and then never reads them, because
/// `runner.go` does not consume `nf.Paths` at all. A Go file that says
/// `paths: [{darwin: /opt/homebrew/bin}]` plainly means it, and honoring the key
/// is strictly closer to the author's intent than adding the directory on every
/// platform. That is a deliberate divergence from the reference and it is the
/// only one in this block.
///
/// `prepend` and `append` are native keys, listed so a half-migrated file still
/// reads. **Everything the reference accepts is accepted**, so a `paths` entry
/// has no key this profile cannot act on. The inventory is still what rejects,
/// and it gives a better diagnostic than a `deny_unknown_fields` failure inside an
/// untagged variant, which degrades to "data did not match any variant" and names
/// neither the key nor the field.
const PATH_ENTRY_KEYS: &[&str] = &[
    "value", "path", "os", "append", "prepend", //
    "windows", "win", "win32", "linux", "unix", "mac", "macos", "darwin", "osx",
];

/// An `env:` sequence entry is a scalar, or a mapping with these keys.
const ENV_ENTRY_KEYS: &[&str] = &["name", "value", "secret"];

/// A `needs:` sequence entry, from `need.go`'s own switch.
const NEED_ENTRY_KEYS: &[&str] = &["id", "parallel"];

/// A Go `use:` entry, from `use_map.go`'s own `UseEntry`.
const USE_ENTRY_KEYS: &[&str] = &[
    "version",
    "asset",
    "url",
    "checksum",
    "binpath",
    "bindir",
    "bins",
    "grep",
    "rename",
    "rn",
    "prerelease",
    "pre",
];

/// A per-platform `use:` override, from `use_map.go`'s own `OSArchConfig`.
///
/// No `version`: the reference's per-platform struct has none either, so
/// accepting one would imply support that does not exist.
const USE_PLATFORM_KEYS: &[&str] = &[
    "asset", "url", "checksum", "binpath", "bindir", "bins", "grep", "rename", "rn",
];

/// A section to check, named by the path a diagnostic should report.
struct KeyCheck {
    /// Dotted location, empty for the document itself.
    location: &'static str,
    /// The keys allowed directly under it.
    allowed: &'static [&'static str],
    /// Whether the value must be a sequence whose *entries* are checked.
    entries: bool,
    /// Whether the section is a mapping whose *values* are the checked mappings.
    detailed: bool,
}

const CHECKS: &[KeyCheck] = &[
    KeyCheck {
        location: "",
        allowed: TOP_LEVEL_KEYS,
        entries: false,
        detailed: false,
    },
    KeyCheck {
        location: "config",
        allowed: CONFIG_KEYS,
        entries: false,
        detailed: false,
    },
    KeyCheck {
        location: "config.defaults",
        allowed: DEFAULTS_KEYS,
        entries: false,
        detailed: false,
    },
    KeyCheck {
        location: "dotenv",
        allowed: DOTENV_ENTRY_KEYS,
        entries: true,
        detailed: false,
    },
    // Both spellings: `paths` is the Go section and `path` is the native one,
    // and a half-migrated file may carry either.
    KeyCheck {
        location: "paths",
        allowed: PATH_ENTRY_KEYS,
        entries: true,
        detailed: false,
    },
    KeyCheck {
        location: "path",
        allowed: PATH_ENTRY_KEYS,
        entries: true,
        detailed: false,
    },
    KeyCheck {
        location: "env",
        allowed: ENV_ENTRY_KEYS,
        entries: true,
        detailed: false,
    },
    // `env:` as a mapping of name to a *detailed* value. The outer keys are the
    // variable names, which are not in any fixed list, so only the inner keys
    // are checked.
    KeyCheck {
        location: "env",
        allowed: ENV_ENTRY_KEYS,
        entries: false,
        detailed: true,
    },
];

/// Rejects a key the Go reader does not know, by name, before serde runs.
///
/// # Errors
///
/// Returns NEO130 naming the key, or the underlying document syntax error.
fn validate_key_inventory(path: &Path, input: &str, format: Format) -> Result<(), Diagnostic> {
    let document: serde_yaml::Value = match format {
        Format::Yaml => {
            serde_yaml::from_str(input).map_err(|error| yaml_syntax_error(path, &error))?
        }
        Format::Toml => {
            let value: toml::Value =
                toml::from_str(input).map_err(|error| toml_syntax_error(path, error))?;
            as_yaml(&value)
        }
        Format::Neoenv => unreachable!("the line-oriented format is rejected by the caller"),
    };
    reject_go_project_metadata(path, input, &document)?;
    check_task_needs(path, input, &document)?;
    check_use_entries(path, input, &document)?;
    for check in CHECKS {
        check_section(path, input, &document, check)?;
    }
    Ok(())
}

/// Refuses Go project metadata the reference reads and this model cannot hold.
///
/// Reported here rather than left to the native reader, whose "unknown field"
/// message lists the *v1* keys -- so it names the right key and then suggests
/// the user had misspelled one of a set that never included it.
///
/// # Errors
///
/// Returns NEO132 naming the first metadata key present.
fn reject_go_project_metadata(
    path: &Path,
    input: &str,
    document: &serde_yaml::Value,
) -> Result<(), Diagnostic> {
    let serde_yaml::Value::Mapping(mapping) = document else {
        return Ok(());
    };
    for key in GO_PROJECT_METADATA {
        if !mapping.contains_key(serde_yaml::Value::String((*key).to_owned())) {
            continue;
        }
        return Err(document_error(
            path,
            input,
            "NEO132",
            format!(
                "this Go project sets `{key}`, which is project metadata with no Rust \
                 equivalent; remove it to migrate, or keep the file for the Go nenv"
            ),
        ));
    }
    Ok(())
}

fn check_section(
    path: &Path,
    input: &str,
    document: &serde_yaml::Value,
    check: &KeyCheck,
) -> Result<(), Diagnostic> {
    let mut current = document;
    for segment in check
        .location
        .split('.')
        .filter(|segment| !segment.is_empty())
    {
        let serde_yaml::Value::Mapping(mapping) = current else {
            return Ok(());
        };
        let Some(value) = mapping.get(serde_yaml::Value::String(segment.to_owned())) else {
            return Ok(());
        };
        current = value;
    }
    let candidates: Vec<&serde_yaml::Value> = match (check.entries, check.detailed, current) {
        (true, _, serde_yaml::Value::Sequence(entries)) => entries.iter().collect(),
        (_, true, serde_yaml::Value::Mapping(mapping)) => mapping.values().collect(),
        (false, _, serde_yaml::Value::Mapping(_)) => vec![current],
        // A section in a shape the reader does not expect is serde's business,
        // not this walk's; a wrong shape is still a diagnostic, just not a
        // better one.
        _ => return Ok(()),
    };
    for candidate in candidates {
        check_mapping(path, input, check.location, candidate, check.allowed)?;
    }
    Ok(())
}

fn check_mapping(
    path: &Path,
    input: &str,
    location: &str,
    value: &serde_yaml::Value,
    allowed: &[&str],
) -> Result<(), Diagnostic> {
    let owned: Vec<String> = allowed.iter().map(|key| (*key).to_owned()).collect();
    check_owned_mapping(path, input, location, value, &owned)
}

/// The same check over an owned key set.
///
/// Owned because one caller builds its set per `use:` entry: the platform keys
/// that entry actually declares have to be accepted by their literal names, and
/// a fixed table cannot know them. Leaking those names to get a `&[&str]` would
/// trade a leak for a convenience, which is not a trade worth making.
fn check_owned_mapping(
    path: &Path,
    input: &str,
    location: &str,
    value: &serde_yaml::Value,
    allowed: &[String],
) -> Result<(), Diagnostic> {
    let serde_yaml::Value::Mapping(mapping) = value else {
        return Ok(());
    };
    for key in mapping.keys() {
        let serde_yaml::Value::String(key) = key else {
            continue;
        };
        if allowed.iter().any(|allowed| allowed == key) {
            continue;
        }
        return Err(unknown_key_owned(path, input, location, key, allowed));
    }
    Ok(())
}

/// The keys one `use:` entry may carry: its own, plus the platform keys it
/// declares.
///
/// Listed per entry so the diagnostic names the platform key the user actually
/// wrote, which is what tells them it was misspelled.
fn use_entry_allowed_keys(entry: &serde_yaml::Value) -> Vec<String> {
    let mut allowed: Vec<String> = USE_ENTRY_KEYS.iter().map(|key| (*key).to_owned()).collect();
    if let serde_yaml::Value::Mapping(fields) = entry {
        for name in fields.keys() {
            let Some(name) = name.as_str() else { continue };
            if !crate::use_block::is_platform_key(name) || allowed.iter().any(|key| key == name) {
                continue;
            }
            allowed.push(name.to_owned());
        }
    }
    allowed
}

/// Checks every task's `needs` entries.
///
/// A per-need option the reader does not know has to be *named*, and the
/// `deny_unknown_fields` that would catch it sits inside an untagged enum, where
/// it degrades to "data did not match any variant" -- naming neither the option
/// nor the field. Walking it here keeps the diagnostic useful.
fn check_task_needs(
    path: &Path,
    input: &str,
    document: &serde_yaml::Value,
) -> Result<(), Diagnostic> {
    let serde_yaml::Value::Mapping(tasks) = document else {
        return Ok(());
    };
    let Some(serde_yaml::Value::Mapping(declarations)) =
        tasks.get(serde_yaml::Value::String("tasks".to_owned()))
    else {
        return Ok(());
    };
    for (_, task) in declarations {
        let serde_yaml::Value::Mapping(fields) = task else {
            continue;
        };
        let Some(serde_yaml::Value::Sequence(entries)) =
            fields.get(serde_yaml::Value::String("needs".to_owned()))
        else {
            continue;
        };
        for entry in entries {
            check_mapping(path, input, "needs", entry, NEED_ENTRY_KEYS)?;
        }
    }
    Ok(())
}

/// Checks every `use:` entry and its per-platform overrides.
///
/// A `use:` entry is read with `deny_unknown_fields`, which inside an untagged
/// enum degrades to "data did not match any variant" -- naming neither the key
/// nor the entry. A `use:` key that is read and dropped changes *which artifact
/// gets installed*, so it has to be named here instead.
fn check_use_entries(
    path: &Path,
    input: &str,
    document: &serde_yaml::Value,
) -> Result<(), Diagnostic> {
    let serde_yaml::Value::Mapping(root) = document else {
        return Ok(());
    };
    let Some(serde_yaml::Value::Mapping(entries)) =
        root.get(serde_yaml::Value::String("use".to_owned()))
    else {
        return Ok(());
    };
    for (key, entry) in entries {
        let key_name = key.as_str().unwrap_or("<key>");
        // The scalar form is a bare version, with no keys to check.
        if !matches!(entry, serde_yaml::Value::Mapping(_)) {
            continue;
        }
        // Tolerated here and checked with its own list below, because a
        // platform key is a *valid* entry key that this pass does not descend
        // into.
        let allowed = use_entry_allowed_keys(entry);
        check_owned_mapping(path, input, "use", entry, &allowed)?;
        let serde_yaml::Value::Mapping(fields) = entry else {
            continue;
        };
        for (name, value) in fields {
            let Some(platform) = name.as_str() else {
                continue;
            };
            if !crate::use_block::is_platform_key(platform) {
                continue;
            }
            let location = format!("use.{key_name}.{platform}");
            check_mapping(path, input, &location, value, USE_PLATFORM_KEYS)?;
        }
    }
    Ok(())
}

fn unknown_key_owned(
    path: &Path,
    input: &str,
    location: &str,
    key: &str,
    allowed: &[String],
) -> Diagnostic {
    let where_ = if location.is_empty() {
        "the document".to_owned()
    } else {
        format!("`{location}`")
    };
    document_error(
        path,
        input,
        "NEO130",
        format!(
            "unknown key `{key}` in {where_}, expected one of {}",
            allowed.join(", ")
        ),
    )
}

/// Re-expresses a parsed TOML value in the shape the walk above uses.
///
/// `toml::Value` and `serde_yaml::Value` agree on map, sequence, and string, and
/// TOML has no tagged unions, so this is a structural walk rather than a
/// conversion with cases to get wrong. A datetime becomes its RFC 3339 text,
/// which is what the TOML serializer would have written anyway.
fn as_yaml(value: &toml::Value) -> serde_yaml::Value {
    match value {
        toml::Value::Table(table) => serde_yaml::Value::Mapping(
            table
                .iter()
                .map(|(key, value)| (serde_yaml::Value::String(key.clone()), as_yaml(value)))
                .collect(),
        ),
        toml::Value::Array(items) => {
            serde_yaml::Value::Sequence(items.iter().map(as_yaml).collect())
        }
        toml::Value::String(text) => serde_yaml::Value::String(text.clone()),
        toml::Value::Integer(number) => {
            serde_yaml::Value::Number(serde_yaml::Number::from(*number))
        }
        toml::Value::Float(number) => serde_yaml::Value::Number(serde_yaml::Number::from(*number)),
        toml::Value::Boolean(value) => serde_yaml::Value::Bool(*value),
        toml::Value::Datetime(value) => serde_yaml::Value::String(value.to_string()),
    }
}

/// Parses a Go `nenv` document into the v1 model.
pub(super) fn parse_go(path: &Path, input: &str, format: Format) -> Result<Project, Diagnostic> {
    validate_key_inventory(path, input, format)?;
    let document: GoDocument = match format {
        Format::Yaml => {
            serde_yaml::from_str(input).map_err(|error| yaml_syntax_error(path, &error))?
        }
        Format::Toml => toml::from_str(input).map_err(|error| toml_syntax_error(path, error))?,
        // The caller rejects the line-oriented format before reaching here.
        Format::Neoenv => unreachable!("the line-oriented format is rejected by the caller"),
    };
    assemble(path, input, format, document)
}

fn assemble(
    path: &Path,
    input: &str,
    format: Format,
    document: GoDocument,
) -> Result<Project, Diagnostic> {
    reject_unsupported(path, input, &document)?;
    // Resolved before any field is moved out of `document`, because the context
    // choice reads both `config:` and the native `context:`.
    let context = select_go_context(path, input, &document)?;
    // The span scanner is a whole-document line walk, so it runs once here and
    // both the shared normalizer and the Go-specific path reuse the result.
    let spans = structured_spans(input, format);
    // Split once, up front: the mapping goes to the shared normalizer and the
    // sequence is normalized separately, because a document carries at most one
    // and the two forms have different shapes.
    let (mapping, detailed, sequence) = match document.env {
        None => (IndexMap::new(), IndexMap::new(), None),
        Some(GoEnvSection::Mapping(mapping)) => (mapping, IndexMap::new(), None),
        Some(GoEnvSection::Detailed(detailed)) => (IndexMap::new(), detailed, None),
        Some(GoEnvSection::Sequence(sequence)) => {
            (IndexMap::new(), IndexMap::new(), Some(sequence))
        }
    };
    let native = StructuredProject {
        format_version: document.format_version,
        vaults: IndexMap::new(),
        env: mapping,
        dotenv: select_dotenv(document.dotenv),
        path: select_path(path, input, document.path)?,
        tools: {
            let mut tools = document.tools;
            if let Some(entries) = &document.use_block {
                tools.extend(crate::use_block::normalize_use(
                    path, input, format, entries,
                )?);
            }
            StructuredTools::List(tools)
        },
        context,
        task_dirs: document.task_dirs,
        task_packages: document.task_packages,
        tasks: document.tasks,
        // The Go document's `jobs:` is carried through the same normalizer as a
        // native one, so a Go file with a pipeline is read by the same code and
        // gets the same refusals. It was previously in `GO_PROJECT_METADATA` and
        // refused outright; that refusal is removed in `reject_go_project_metadata`
        // below, because the model now has somewhere to put it.
        jobs: document.jobs,
        inventories: document.inventories,
        inventory_files: Vec::new(),
        deployments: document.ship,
        imports: document.imports,
        workspace: document.workspace,
    };
    // Every shared section goes through the ordinary normalizer, so v1
    // validation, spans, and diagnostics are identical to a native read.
    let mut project = structured_project(path, input, native, spans.clone())?;
    // The Go sequence form carries an order and a secret flag that the v1
    // `IndexMap<String, String>` cannot express, so it is applied after.
    if !detailed.is_empty() {
        project.environment = select_detailed(path, input, &spans, detailed)?;
    } else if let Some(entries) = select_sequence(path, input, spans, sequence)? {
        project.environment = entries;
    }
    Ok(project)
}

/// Rejects every Go section this profile cannot faithfully execute.
///
/// **The list is empty, and that is a change.** `inventories` and `ship` were both
/// refused here on the grounds that the Go reference does not execute them either --
/// true, and the wrong reason. Refusing a construct because the *reference* is
/// incomplete is a strange standard to hold a port to; the question worth asking is
/// whether the reader can represent it faithfully, and both can now. They are carried
/// through the normalizer, and the keys their models cannot honour are refused by
/// `deny_unknown_fields` where the reader is.
fn reject_unsupported(path: &Path, input: &str, document: &GoDocument) -> Result<(), Diagnostic> {
    let Some(config) = &document.config else {
        return Ok(());
    };
    for (present, name, remedy) in [
        (
            config.modules.is_some(),
            "`config.modules`",
            "declare the module under `imports:` instead",
        ),
        (
            config.external.is_some(),
            "`config.external`",
            "pass `--project` explicitly instead",
        ),
    ] {
        if present {
            return Err(document_error(
                path,
                input,
                "NEO132",
                format!(
                    "this Go {name} changes what resolves, so the compatibility profile \
                     refuses it rather than guessing; {remedy}"
                ),
            ));
        }
    }
    Ok(())
}

/// Go context selection: `config.context`, then `config.defaults.context`, then
/// the native top-level `context:`. That is the order the reference applies.
fn select_go_context(
    path: &Path,
    input: &str,
    document: &GoDocument,
) -> Result<Option<String>, Diagnostic> {
    let Some(config) = &document.config else {
        return Ok(document.context.clone());
    };
    let candidates = [
        ("config.context", config.context.clone()),
        (
            "config.defaults.context",
            config
                .defaults
                .as_ref()
                .and_then(|defaults| defaults.context.clone()),
        ),
    ];
    for (name, value) in candidates {
        let Some(value) = value else { continue };
        // A file that sets both is ambiguous, and silently preferring one would
        // hide a real disagreement between the two spellings. Written as a
        // nested `if` rather than a let-chain: the release gate builds with a
        // toolchain that does not accept `let` in that position.
        if let Some(conflict) = &document.context
            && *conflict != value
        {
            return Err(document_error(
                path,
                input,
                "NEO135",
                format!(
                    "this Go file sets both `context: {conflict}` and `{name}: {value}`; \
                         the Go reference applies {name}, so remove the other to migrate \
                         cleanly"
                ),
            ));
        }
        return Ok(Some(value));
    }
    Ok(document.context.clone())
}

/// The v1 mapping form needs no special handling. The Go sequence form becomes
/// ordered entries with their secret flags intact.
fn select_sequence(
    path: &Path,
    input: &str,
    spans: StructuredSpans,
    items: Option<Vec<GoEnvItem>>,
) -> Result<Option<Vec<EnvironmentEntry>>, Diagnostic> {
    let Some(items) = items else {
        return Ok(None);
    };
    let source_path = path.display().to_string();
    let mut spans = spans;
    let mut entries: Vec<EnvironmentEntry> = Vec::with_capacity(items.len());
    // A key-to-position index, so a repeated key is last-wins without a linear
    // rescan. The native mapping form gets that from `IndexMap` for free; a
    // `Vec` preserves order and does not, so a 1 MiB Go file full of short
    // entries would otherwise cost O(n^2) string comparisons against the same
    // 1 MiB budget the native path pays.
    let mut positions: BTreeMap<String, usize> = BTreeMap::new();
    for item in items {
        let (key, value, secret) = match item {
            GoEnvItem::Scalar(text) => split_go_env(&text, path, input)?,
            GoEnvItem::Mapping(GoEnvMapping {
                name,
                value,
                secret,
            }) => (name, value, secret),
        };
        let source = spans.next_env(&source_path);
        validate_key(&key, &source_path, source.line)?;
        // The native mapping form always runs this, so the Go form has to as
        // well; otherwise a command substitution is only caught later, during
        // interpolation, and the parse-time guarantee is gone. The span is
        // taken first so the diagnostic points at the entry, not at line 1.
        reject_command_substitution(&value, &source_path, source.line)?;
        // The sequence is ordered and a repeated key is last-wins, which is the
        // rule the Go reference applies and the rule the v1 mapping already used.
        // The secret flag is the one exception, and it fails safe: a later plain
        // re-declaration can narrow to secret but never widen back to plain, so
        // reordering a file cannot declassify a value.
        if let Some(&index) = positions.get(&key) {
            let existing = &mut entries[index];
            existing.value = value;
            existing.source = source;
            existing.secret |= secret;
        } else {
            positions.insert(key.clone(), entries.len());
            entries.push(EnvironmentEntry {
                key,
                value,
                source,
                secret,
            });
        }
    }
    Ok(Some(entries))
}

/// The Go mapping form whose value is a mapping, flattened into entries.
///
/// A separate shape from the sequence because the *order* guarantee differs: a
/// mapping is unordered, and a duplicate key here is a serde error rather than
/// last-wins. Reporting it is better than silently keeping the first.
///
/// # Errors
///
/// Returns a diagnostic for an invalid key or a duplicate.
fn select_detailed(
    path: &Path,
    _input: &str,
    spans: &StructuredSpans,
    detailed: IndexMap<String, GoDetailedEnvValue>,
) -> Result<Vec<EnvironmentEntry>, Diagnostic> {
    let source_path = path.display().to_string();
    let mut cursor = spans.clone();
    let mut entries = Vec::with_capacity(detailed.len());
    for (key, mapping) in detailed {
        // Taken first so the validation below reports the entry's own line
        // rather than line 1 of the file.
        let source = cursor.next_env(&source_path);
        // Nested rather than a let-chain: the release gate builds with a
        // toolchain that does not accept `let` in that position.
        if let Some(declared) = mapping.declared_name()
            && *declared != key
        {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO139",
                format!(
                    "this Go env entry is keyed `{key}` but its `name` says `{declared}`; \
                         a variable cannot have two names"
                ),
            )
            .at(source));
        }
        validate_key(&key, &source_path, source.line)?;
        reject_command_substitution(&mapping.value, &source_path, source.line)?;
        entries.push(EnvironmentEntry {
            key,
            value: mapping.value,
            source,
            secret: mapping.secret,
        });
    }
    Ok(entries)
}

/// Normalizes a Go `dotenv:` list.
///
/// Every key the reference's `DotEnv` accepts is either the native `required` or
/// carried in the entry's filter, so nothing here is refused by name any more.
/// The parameters that used to name a refused key are gone with it.
fn select_dotenv(dotenv: Option<GoDotEnvList>) -> DotenvList {
    let entries = match dotenv {
        None => return DotenvList::Empty,
        Some(GoDotEnvList::Single(path)) => {
            return DotenvList::List(vec![StructuredDotenv::Path(path)]);
        }
        Some(GoDotEnvList::List(entries)) => entries,
    };
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry {
            GoDotEnvEntry::Path(path) => normalized.push(StructuredDotenv::Path(path)),
            GoDotEnvEntry::Mapping(mapping) => {
                normalized.push(match mapping {
                    GoDotEnvMapping::Native(native) => native,
                    // `required` is deliberately absent from the Go shape: it
                    // is a *native* key, so a mapping carrying it matches
                    // `Native` above and never reaches here. The reference's
                    // `DotEnv` has no such key, and the profile must not accept
                    // a document the reference rejects.
                    GoDotEnvMapping::Go(GoDotEnvFilter { path, os, contexts }) => {
                        StructuredDotenv::Declaration(StructuredDotenvDeclaration {
                            path,
                            required: required_dotenv(),
                            filter: super::EntryFilter { os, contexts },
                        })
                    }
                });
            }
        }
    }
    DotenvList::List(normalized)
}

fn select_path(
    path: &Path,
    input: &str,
    entries: Option<GoPathList>,
) -> Result<Vec<StructuredPathOperation>, Diagnostic> {
    let entries = match entries {
        None => return Ok(Vec::new()),
        Some(GoPathList::Single(value)) => {
            if value.trim().is_empty() {
                return Err(unnamed_path_entry(path, input, "an empty string"));
            }
            return Ok(vec![StructuredPathOperation {
                prepend: Some(value),
                append: None,
                filter: super::EntryFilter::always(),
            }]);
        }
        Some(GoPathList::List(entries)) => entries,
    };
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry {
            GoPathEntry::Value(value) => {
                if value.trim().is_empty() {
                    return Err(unnamed_path_entry(path, input, "an empty string"));
                }
                normalized.push(StructuredPathOperation {
                    prepend: Some(value),
                    append: None,
                    // A bare string names a path and no scope, which is the same
                    // as a filter that matches everything.
                    filter: super::EntryFilter::always(),
                });
            }
            GoPathEntry::Mapping(mapping) => {
                // Resolved *before* the conversion, because the conversion has no
                // way to represent "no path" and a default would produce the empty
                // PATH entry this function exists to refuse.
                if matches!(mapping, GoPathMapping::Go(ref declared) if declared.resolved().is_none())
                {
                    return Err(unnamed_path_entry(path, input, "missing a `path`"));
                }
                let operation: StructuredPathOperation = mapping.into();
                // An operation carrying a value in *neither* field names no
                // directory. "Absent or blank" rather than "blank" matters: the
                // defaulting branch leaves the other field `None`, and `None` is
                // not a blank string.
                let carries = |value: &Option<String>| {
                    value
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                };
                if !carries(&operation.prepend) && !carries(&operation.append) {
                    return Err(unnamed_path_entry(path, input, "missing a `path`"));
                }
                normalized.push(operation);
            }
        }
    }
    Ok(normalized)
}

/// A Go `paths:` entry that names no directory to add.
///
/// Named rather than defaulted: an empty `PATH` element is the current working
/// directory on POSIX, so a defaulted entry is not a no-op -- it silently
/// changes what every later relative lookup resolves to, and it does so
/// *after* the tool directories, where it is invisible.
fn unnamed_path_entry(path: &Path, input: &str, what: &str) -> Diagnostic {
    document_error(
        path,
        input,
        "NEO132",
        format!(
            "this Go `paths` entry is {what}, so it adds the current directory to PATH; \
             give it a `path`, or remove it"
        ),
    )
}

/// Splits a Go sequence `env` scalar.
///
/// `KEY=VALUE` is a plain value. `KEY:VALUE` is a *secret* in the reference, and
/// the distinction is load-bearing: a colon entry must never print. `=` wins
/// over `:` so a value that legitimately contains a colon — a URL, a time, a
/// `host:port` — splits at the `=` and keeps its colon intact.
fn split_go_env(
    text: &str,
    path: &Path,
    input: &str,
) -> Result<(String, String, bool), Diagnostic> {
    if let Some((key, value)) = text.split_once('=') {
        return Ok((key.to_owned(), value.to_owned(), false));
    }
    if let Some((key, value)) = text.split_once(':') {
        return Ok((key.to_owned(), value.to_owned(), true));
    }
    Err(document_error(
        path,
        input,
        "NEO134",
        "a Go env sequence entry must be KEY=VALUE or KEY:VALUE".to_owned(),
    ))
}

/// A document syntax or type error, reported at the position the parser gave.
///
/// The parser's own message is deliberately *not* used as the diagnostic text:
/// serde and `toml` both quote the offending value, and in this profile a value
/// can be a declared secret. The position is strictly more useful anyway, and it
/// keeps the text form of the diagnostic free of configuration contents.
fn syntax_error(
    path: &Path,
    dialect: &str,
    position: Option<(usize, usize)>,
    detail: Option<String>,
) -> Diagnostic {
    let (line, column) = position.map_or((1, 1), |(line, column)| {
        (
            u32::try_from(line).unwrap_or(u32::MAX).max(1),
            u32::try_from(column).unwrap_or(u32::MAX).max(1),
        )
    });
    let message = match detail {
        Some(detail) => detail,
        None => format!("the Go document is not valid {dialect}"),
    };
    Diagnostic::new(DiagnosticCategory::Validation, "NEO130", message).at(
        neoenv_core::SourceSpan::new(path.display().to_string(), line, column),
    )
}

fn yaml_syntax_error(path: &Path, error: &serde_yaml::Error) -> Diagnostic {
    let message = safe_parser_message(error);
    syntax_error(
        path,
        "YAML",
        error
            .location()
            .map(|location| (location.line(), location.column())),
        message,
    )
}

/// The parser message, but only when it is known not to quote a value.
///
/// `deny_unknown_fields` violations name a *key* and a list of expected keys,
/// which is exactly the diagnostic a user needs and cannot leak a secret. Every
/// other serde message may quote the offending value, so it is dropped.
/// Strips a leading serde key path from a parser message, if there is one.
///
/// **Only a path that looks like a key path is stripped.** serde writes
/// `ship.web: invalid type: ...` for a nested field, and the key is what a reader
/// needs; but a message can also begin with a *value*, as in
/// `invalid value: string "hunter2"`, and cutting at the first `": "` in that one
/// would move the quoted value to the front and make the remainder look like a
/// diagnostic worth printing.
///
/// So the leading segment must match a plain identifier path -- letters, digits, `_`,
/// `.` and `-` -- which a quoted value containing spaces or punctuation cannot. A key
/// that is itself an unusual string is then not stripped, and its message is dropped
/// rather than printed, which is the safe direction.
fn strip_key_path(message: &str) -> &str {
    let mut rest = message;
    // At most two segments: `field:` or `field.subfield:`. A third is not a shape
    // serde reports this way, and an unbounded loop over arbitrary `": "` would be.
    for _ in 0..2 {
        let Some(cut) = rest.find(": ") else {
            return rest;
        };
        let (segment, tail) = rest.split_at(cut);
        if segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return rest;
        }
        rest = &tail[2..];
    }
    rest
}

fn safe_parser_message(error: &serde_yaml::Error) -> Option<String> {
    /// The container shapes whose serde message names a type and no value.
    ///
    /// A free `const` rather than one inside the function: Rust items exist from the
    /// start of their scope, so a `const` declared after the first `return` reads as
    /// though it were conditional -- and clippy is right to say so.
    const CONTAINER_SHAPES: [&str; 4] = [
        "invalid type: sequence, ",
        "invalid type: map, ",
        "invalid type: struct ",
        "invalid type: newtype struct ",
    ];
    let message = error.to_string();
    if message.starts_with("unknown field") {
        // A `deny_unknown_fields` violation names a *key* and the keys that were
        // expected. No value, so it is always safe and always the diagnostic a user
        // needs.
        return Some(message);
    }
    // **A section given the wrong *shape* used to be reported as invalid syntax.**
    //
    //     $ printf 'ship:\n  - a\n' > neoenv.yaml
    //     $ nenv --profile go validate
    //     nenv: neoenv.yaml:2:3: the Go document is not valid YAML
    //
    // The document is valid YAML. One section is a sequence where a mapping belongs.
    // The message names the wrong layer, and the reader is sent to re-check syntax
    // that was already correct.
    //
    // The fix cannot be "surface every `invalid type`", because that prefix is not
    // value-free. Measured, not assumed:
    //
    //     format_version: not-a-number
    //       -> invalid type: string "not-a-number", expected u32     # the VALUE
    //     ship: [a]
    //       -> invalid type: sequence, expected a map                 # only the type
    //
    // **serde quotes a scalar and names a container.** That is the distinction, and it
    // is exact: `string`, `integer`, `boolean`, `floating point` and a bare enum name
    // all carry the value; `map`, `sequence` and a struct name never do. In this
    // profile a value can be a declared secret, so only the container shapes are
    // surfaced.
    //
    // The first attempt allowed the whole prefix and was reverted within the minute:
    // it printed `not-a-number` for a scalar, which is precisely the leak this
    // function exists to prevent. The rule is now the narrower one, and
    // `a_container_shape_error_is_named_and_a_scalar_value_is_not` pins both
    // directions.
    //
    // **The key comes first**, which is what made the obvious prefix rule miss:
    //
    //     ship: invalid type: sequence, expected a map at line 2 column 3
    //
    // so the text starts with `ship: `, not with `invalid type:`. The key path is
    // stripped first -- and only when it looks like a key path, `[A-Za-z0-9_.-]+: `,
    // so a message whose *first* element is a quoted scalar can never be mistaken for
    // one with a key in front. `env.DB_PASSWORD.value` is stripped; `"hunter2":` is
    // not, because it does not match.
    let body = strip_key_path(&message);
    // `KEY_PATH` is a *marker* for "does the message begin with a key path", checked
    // by a helper rather than inlined, so the pattern and the use cannot drift.
    CONTAINER_SHAPES
        .iter()
        .any(|prefix| body.starts_with(prefix))
        .then_some(message)
}

/// `toml` exposes no line/column, so the span stays at the document. The
/// diagnostic still names the dialect, and the cause keeps the detail without
/// putting configuration contents into printed text.
fn toml_syntax_error(path: &Path, error: toml::de::Error) -> Diagnostic {
    // The cause is `#[serde(skip)]` and never rendered at the CLI boundary, so a
    // library caller still gets the detail while printed text stays free of
    // configuration contents.
    syntax_error(path, "TOML", None, None).with_cause(error)
}
