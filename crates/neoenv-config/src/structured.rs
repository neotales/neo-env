//! Deserialization shapes for the YAML and TOML document formats. These
//! mirror the on-disk syntax and are normalized into the public model.

use neoenv_core::SourceSpan;
use neoenv_core::tasks::{DeploymentDefinition, JobDefinition, StepDefinition};

use super::neoenv::validate_key;
use super::normalize::normalize_task;
use super::spans::{StructuredSpans, structured_spans};
use super::{
    AgeVault, Deserialize, Diagnostic, DiagnosticCategory, DotenvImport, EnvironmentEntry,
    FORMAT_VERSION, Format, IndexMap, Inventory, InventoryDefaults, InventoryHost, KeepassVault,
    ModuleImport, OsVault, Path, PathOperation, PathOperationKind, PlatformOverride,
    PlatformSelector, Project, TaskDirectories, TaskOutput, TaskOutputVisibility, TaskPackage,
    TaskParameterDefault, TaskParameterType, ToolDeclaration, ToolProvider, VaultDeclaration,
    VaultProvider, Workspace, default_format_version, document_error, document_span,
    reject_command_substitution, required_dotenv,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredProject {
    #[serde(default = "default_format_version")]
    pub(super) format_version: u32,
    /// Declared secret providers. A declaration only; see `VaultDeclaration`.
    #[serde(default)]
    pub(super) vaults: IndexMap<String, StructuredVault>,
    #[serde(default, alias = "environment")]
    pub(super) env: IndexMap<String, String>,
    #[serde(default)]
    pub(super) dotenv: DotenvList,
    #[serde(default)]
    pub(super) path: Vec<StructuredPathOperation>,
    #[serde(default)]
    pub(super) tools: StructuredTools,
    pub(super) context: Option<String>,
    #[serde(default)]
    pub(super) task_dirs: StructuredTaskDirectories,
    #[serde(default, alias = "packages")]
    pub(super) task_packages: IndexMap<String, StructuredTaskPackage>,
    #[serde(default)]
    pub(super) tasks: IndexMap<String, StructuredTask>,
    /// Ordered pipelines. A separate namespace from `tasks`, as in the reference:
    /// `resolveJob` and `resolveTask` never see each other's map.
    #[serde(default)]
    pub(super) jobs: IndexMap<String, StructuredJob>,
    /// Named host lists. A declaration only -- see `Inventory` for why a host here
    /// authorises nothing.
    #[serde(default, alias = "inventory")]
    pub(super) inventories: IndexMap<String, StructuredInventory>,
    #[serde(default)]
    pub(super) inventory_files: Vec<String>,
    /// Deployment workflows, as the reference's `ship:` section.
    #[serde(default)]
    pub(super) deployments: IndexMap<String, StructuredDeployment>,
    /// `import` is the Go spelling; `modules` is a legacy alias.
    #[serde(default, alias = "modules", alias = "import")]
    pub(super) imports: ModuleImportList,
    #[serde(default)]
    pub(super) workspace: StructuredWorkspace,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredWorkspace {
    #[serde(default)]
    pub(super) members: StringList,
    #[serde(default)]
    pub(super) aliases: IndexMap<String, String>,
}

/// One `vaults:` entry, before provider-specific validation.
///
/// One struct rather than a tagged enum so a field from the wrong provider is
/// refused by *name* with a message that says which provider it belongs to. An
/// untagged enum reports only "did not match any variant", which is exactly the
/// diagnostic that sends a reader nowhere.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredVault {
    /// The vault driver name. `driver` is the configuration key; `provider` is
    /// deliberately not accepted as an alias, because an alias would make two
    /// spellings mean one thing and a removed key silently keep working.
    pub(super) driver: String,
    pub(super) identity: Option<String>,
    #[serde(default)]
    pub(super) values: IndexMap<String, String>,
    pub(super) path: Option<String>,
    pub(super) secret: Option<String>,
    pub(super) service: Option<String>,
}

impl StructuredVault {
    fn into_declaration(
        self,
        name: String,
        source_path: &str,
    ) -> Result<VaultDeclaration, Diagnostic> {
        let driver_name = self.driver.clone();
        let provider = match driver_name.as_str() {
            "age" => VaultProvider::Age(self.age_provider(&name, source_path)?),
            "keepass" => VaultProvider::Keepass(self.keepass_provider(&name, source_path)?),
            "os" => {
                for (present, key, owner) in [
                    (self.identity.is_some(), "identity", "age"),
                    (!self.values.is_empty(), "values", "age"),
                    (self.path.is_some(), "path", "keepass"),
                    (self.secret.is_some(), "secret", "keepass"),
                ] {
                    if present {
                        return Err(vault_error(
                            "NEO148",
                            format!(
                                "vault {name} is an `os` vault and sets `{key}`, which \
                                 belongs to the `{owner}` driver"
                            ),
                            source_at(source_path),
                        ));
                    }
                }
                let service = self
                    .service
                    .unwrap_or_else(|| super::DEFAULT_OS_SERVICE.to_owned());
                if service.trim().is_empty() {
                    return Err(vault_error(
                        "NEO148",
                        format!("vault {name} is an `os` vault and requires a non-empty service"),
                        source_at(source_path),
                    ));
                }
                VaultProvider::Os(OsVault {
                    service: service.trim().to_owned(),
                })
            }
            other => {
                return Err(vault_error(
                    "NEO147",
                    format!(
                        "vault {name} uses unknown driver {other:?}; this build implements \
                         `age`, `keepass`, and `os`"
                    ),
                    source_at(source_path),
                ));
            }
        };
        Ok(VaultDeclaration {
            name,
            provider,
            source: source_at(source_path),
        })
    }

    fn age_provider(self, name: &str, source_path: &str) -> Result<AgeVault, Diagnostic> {
        for (present, key, owner) in [
            (self.path.is_some(), "path", "keepass"),
            (self.secret.is_some(), "secret", "keepass"),
            (self.service.is_some(), "service", "os"),
        ] {
            if present {
                return Err(vault_error(
                    "NEO148",
                    format!(
                        "vault {name} is an `age` vault and sets `{key}`, which belongs to the \
                         `{owner}` driver; a key that parses and does nothing is not accepted"
                    ),
                    source_at(source_path),
                ));
            }
        }
        for (key, value) in &self.values {
            if key.trim().is_empty() {
                return Err(vault_error(
                    "NEO150",
                    format!("vault {name} has an empty age value name"),
                    source_at(source_path),
                ));
            }
            if value.is_empty() {
                return Err(vault_error(
                    "NEO150",
                    format!("vault {name} has an empty age value for {key:?}"),
                    source_at(source_path),
                ));
            }
        }
        Ok(AgeVault {
            identity: self.identity,
            values: self.values,
        })
    }

    fn keepass_provider(self, name: &str, source_path: &str) -> Result<KeepassVault, Diagnostic> {
        for (present, key, owner) in [
            (self.identity.is_some(), "identity", "age"),
            (!self.values.is_empty(), "values", "age"),
            (self.service.is_some(), "service", "os"),
        ] {
            if present {
                return Err(vault_error(
                    "NEO148",
                    format!(
                        "vault {name} is a `keepass` vault and sets `{key}`, which belongs to \
                         the `{owner}` driver; a key that parses and does nothing is not \
                         accepted"
                    ),
                    source_at(source_path),
                ));
            }
        }
        let path = self.path.unwrap_or_default();
        if path.trim().is_empty() {
            return Err(vault_error(
                "NEO148",
                format!("vault {name} is a `keepass` vault and requires `path`"),
                source_at(source_path),
            ));
        }
        let secret = self.secret.unwrap_or_default();
        if secret.is_empty() {
            return Err(vault_error(
                "NEO148",
                format!(
                    "vault {name} is a `keepass` vault and requires `secret`, either a literal \
                     password or an nsv:// reference"
                ),
                source_at(source_path),
            ));
        }
        Ok(KeepassVault { path, secret })
    }
}

fn source_at(source_path: &str) -> SourceSpan {
    SourceSpan::new(source_path.to_owned(), 1, 1)
}

fn vault_error(code: &str, message: String, source: SourceSpan) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, code, message).at(source)
}

fn is_vault_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        })
}

fn normalize_vaults(
    vaults: IndexMap<String, StructuredVault>,
    source_path: &str,
) -> Result<IndexMap<String, VaultDeclaration>, Diagnostic> {
    let mut normalized = IndexMap::new();
    for (name, vault) in vaults {
        if !is_vault_name(&name) {
            return Err(vault_error(
                "NEO146",
                format!(
                    "vault name {name:?} is not a lowercase identifier; a name starts with a \
                     lowercase letter or digit and continues with lowercase letters, digits, \
                     `-` or `_`"
                ),
                SourceSpan::new(source_path.to_owned(), 1, 1),
            ));
        }
        let declaration = vault.into_declaration(name, source_path)?;
        normalized.insert(declaration.name.clone(), declaration);
    }
    Ok(normalized)
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(super) enum ModuleImportList {
    #[default]
    Empty,
    Scalar(String),
    List(Vec<StructuredModuleImport>),
}

impl ModuleImportList {
    pub(super) fn into_vec(self) -> Vec<ModuleImport> {
        match self {
            Self::Empty => Vec::new(),
            Self::Scalar(from) => vec![ModuleImport {
                from,
                namespace: None,
                tasks: Vec::new(),
            }],
            Self::List(imports) => imports
                .into_iter()
                .map(StructuredModuleImport::into_import)
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredModuleImport {
    Scalar(String),
    Map(StructuredModuleImportMap),
}

impl StructuredModuleImport {
    pub(super) fn into_import(self) -> ModuleImport {
        match self {
            Self::Scalar(from) => ModuleImport {
                from,
                namespace: None,
                tasks: Vec::new(),
            },
            Self::Map(import) => ModuleImport {
                from: import.from,
                namespace: import.namespace.or(import.ns),
                tasks: import.tasks.into_vec(),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredModuleImportMap {
    pub(super) from: String,
    pub(super) namespace: Option<String>,
    pub(super) ns: Option<String>,
    #[serde(default)]
    pub(super) tasks: StringList,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredTaskDirectories {
    #[serde(default)]
    pub(super) local: StringList,
    #[serde(default)]
    pub(super) global: StringList,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredTaskPackage {
    Scalar(String),
    Map(StructuredTaskPackageMap),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredTaskPackageMap {
    pub(super) from: String,
    #[serde(default = "default_package_task")]
    pub(super) task: String,
}

pub(super) fn default_package_task() -> String {
    "default".into()
}

impl StructuredTaskPackage {
    pub(super) fn into_package(self) -> TaskPackage {
        match self {
            Self::Scalar(from) => TaskPackage {
                from,
                task: default_package_task(),
            },
            Self::Map(package) => TaskPackage {
                from: package.from,
                task: package.task,
            },
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(super) enum DotenvList {
    #[default]
    Empty,
    Scalar(String),
    List(Vec<StructuredDotenv>),
}

impl DotenvList {
    pub(super) fn into_vec(self) -> Vec<StructuredDotenv> {
        match self {
            Self::Empty => Vec::new(),
            Self::Scalar(path) => vec![StructuredDotenv::Path(path)],
            Self::List(values) => values,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredDotenv {
    Path(String),
    Declaration(StructuredDotenvDeclaration),
}

impl StructuredDotenv {
    /// The path, whether it is required, and the scope it is filtered to.
    pub(super) fn into_parts(self) -> (String, bool, super::EntryFilter) {
        match self {
            // A bare string carries no filter, which is the same as one that
            // matches everything.
            Self::Path(path) => (path, true, super::EntryFilter::always()),
            Self::Declaration(declaration) => {
                (declaration.path, declaration.required, declaration.filter)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredDotenvDeclaration {
    pub(super) path: String,
    #[serde(default = "required_dotenv")]
    pub(super) required: bool,
    /// The OS and context this import is scoped to.
    ///
    /// Nested rather than flattened. `deny_unknown_fields` and `flatten` are
    /// incompatible, and flattening would mean an unrecognized key on a
    /// `dotenv:` entry is *dropped* rather than named -- the silent-drop shape
    /// this profile exists to prevent, and one this file has already been bitten
    /// by twice. The Go dialect's flat `os:`/`contexts:` are the reference's own
    /// keys, and the compatibility reader maps them onto this same struct.
    ///
    /// A native file writes `filter: {os: ..., contexts: [...]}`.
    #[serde(default)]
    pub(super) filter: super::EntryFilter,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredPathOperation {
    pub(super) prepend: Option<String>,
    pub(super) append: Option<String>,
    /// The OS and context this entry is scoped to. Nested for the same reason
    /// as the `dotenv` filter above, and the same native spelling.
    ///
    /// Honoring a `paths` OS filter is a deliberate divergence: the reference
    /// *parses* one and then never reads it, because `runner.go` does not consume
    /// `nf.Paths` at all. A Go file that says `paths: [{darwin:
    /// /opt/homebrew/bin}]` plainly means it, and adding the directory on every
    /// platform is not a reading of that line anyone intended.
    #[serde(default)]
    pub(super) filter: super::EntryFilter,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredTask {
    Scalar(String),
    Map(Box<StructuredTaskMap>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredTaskMap {
    pub(super) background: Option<bool>,
    #[serde(default)]
    pub(super) wait: StringList,
    #[serde(default, rename = "wait-all", alias = "wait_all")]
    pub(super) wait_all: bool,
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    pub(super) slug: Option<String>,
    #[serde(alias = "desc")]
    pub(super) description: Option<String>,
    pub(super) help: Option<String>,
    #[serde(alias = "use")]
    pub(super) uses: Option<String>,
    pub(super) run: Option<String>,
    pub(super) source: Option<String>,
    pub(super) destination: Option<String>,
    #[serde(default)]
    pub(super) args: StringList,
    pub(super) cwd: Option<String>,
    #[serde(default)]
    pub(super) env: IndexMap<String, String>,
    /// `envfile` and `env-file` are the Go spellings of `dotenv`.
    #[serde(default, alias = "envfile", alias = "env-file")]
    pub(super) dotenv: DotenvList,
    #[serde(default)]
    pub(super) with: IndexMap<String, StructuredWithValue>,
    #[serde(default)]
    pub(super) capabilities: StringList,
    /// `deps` and `dependencies` are the Go spellings. The reference accepts
    /// both and they mean the same list, so they are aliases rather than a
    /// second field that could disagree with it.
    #[serde(default, alias = "deps", alias = "dependencies")]
    pub(super) needs: NeedsSection,
    #[serde(default)]
    pub(super) hooks: HooksSection,
    pub(super) extends: Option<String>,
    #[serde(default)]
    pub(super) template: bool,
    #[serde(default, alias = "params", alias = "input")]
    pub(super) inputs: IndexMap<String, StructuredParameter>,
    #[serde(default)]
    pub(super) outputs: IndexMap<String, StructuredOutput>,
    /// `predicate` is the Go spelling of `if`.
    #[serde(rename = "if", alias = "predicate")]
    pub(super) if_condition: Option<StructuredPredicate>,
    pub(super) force: Option<StructuredPredicate>,
    /// Select a Go runner. The Rust model has no equivalent, so these are
    /// declared to be *named* in a diagnostic rather than surfacing as an
    /// unknown field -- the second is technically accurate and tells the user
    /// nothing about what to do instead.
    // Declared, never read: rejection happens in `normalize_task` from the
    // presence of a value, and "never read" is the intended state for a field
    // whose whole purpose is to be recognized and refused.
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) embed: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) image: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) hosts: StringList,
    /// The Go top-level `timeout`, which behaves exactly like `with.timeout`.
    /// It is hoisted into `with` during normalization so there is one field to
    /// read at run time, and a document that sets both is a diagnostic rather
    /// than a silent winner.
    #[serde(default)]
    pub(super) timeout: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredOutput {
    Description(String),
    Declaration(StructuredOutputDeclaration),
}

impl StructuredOutput {
    pub(super) fn into_output(self) -> TaskOutput {
        match self {
            Self::Description(description) => TaskOutput {
                description: Some(description),
                visibility: TaskOutputVisibility::Public,
            },
            Self::Declaration(declaration) => TaskOutput {
                description: declaration.description,
                visibility: declaration.visibility,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredOutputDeclaration {
    #[serde(default, alias = "desc")]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) visibility: TaskOutputVisibility,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredTaskHooks {
    #[serde(default)]
    pub(super) before: StringList,
    #[serde(default)]
    pub(super) after: StringList,
}

/// One entry of a Go `needs` sequence.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum Need {
    /// `- build`
    Id(String),
    /// `- id: build`
    ///   `parallel: true`
    Mapping(NeedMapping),
}

/// Strict per-need options. Unlike the reference's inert flag, `parallel`
/// requests concurrent launch followed by a completion join at the owner.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NeedMapping {
    pub(super) id: String,
    /// Launch concurrently, then join before the dependent's action.
    #[serde(default)]
    parallel: bool,
}

/// A task's `needs`.
///
/// The reference's shape is a *sequence* whose entries are either a bare name
/// or a mapping carrying `id` and `parallel`. The mapping-of-names form this
/// type also accepts is an extension, not the reference's: it is kept because a
/// half-migrated file may use it and rejecting it would refuse a file the user
/// is in the middle of converting, but it is documented as an extension so
/// nobody mistakes it for parity.
///
/// Order is preserved in every form, because needs become graph edges and a
/// reordering changes the run order. A sequence is already ordered; `IndexMap`
/// does it for the extension.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum NeedsSection {
    /// The v1 list of names.
    List(StringList),
    /// The reference's sequence of scalars and per-need mappings.
    Entries(Vec<Need>),
    /// An extension: a mapping of name to options.
    Ordered(IndexMap<String, serde_yaml::Value>),
}

impl NeedsSection {
    pub(super) fn parallel_ids(&self) -> Vec<String> {
        match self {
            Self::Entries(entries) => entries
                .iter()
                .filter_map(|entry| match entry {
                    Need::Mapping(mapping) if mapping.parallel => Some(mapping.id.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
    /// # Errors
    ///
    /// Returns NEO141 when a per-need mapping was written without its sequence
    /// wrapper, which would otherwise produce edges named after the option keys.
    pub(super) fn into_vec(self) -> Result<Vec<String>, Diagnostic> {
        Ok(match self {
            Self::List(list) => list.into_vec(),
            Self::Entries(entries) => entries
                .into_iter()
                .map(|entry| match entry {
                    Need::Id(id) => id,
                    Need::Mapping(mapping) => mapping.id,
                })
                .collect(),
            Self::Ordered(ordered) => {
                // `{id: build, parallel: true}` is a per-need mapping that lost
                // its sequence wrapper. Accepting it would produce edges named
                // after the *option keys*, which is not a typo the user can see.
                if ordered.contains_key("id") {
                    return Err(Diagnostic::new(
                        DiagnosticCategory::Validation,
                        "NEO141",
                        "a `needs` entry of {id: ..., parallel: ...} must be written as a \
                         one-element sequence: `needs: [{id: ..., parallel: ...}]`",
                    ));
                }
                if ordered.values().any(|options| {
                    options.as_mapping().is_some_and(|mapping| {
                        mapping.contains_key(serde_yaml::Value::String("parallel".into()))
                    })
                }) {
                    return Err(Diagnostic::new(
                        DiagnosticCategory::Validation,
                        "NEO147",
                        "parallel options in name-keyed needs mappings are not implemented; use `needs: [{id: name, parallel: true}]`",
                    ));
                }
                ordered.into_keys().collect()
            }
        })
    }
}

impl Default for NeedsSection {
    fn default() -> Self {
        Self::List(StringList::Empty)
    }
}

pub(super) fn normalize_wait(wait: StringList, wait_all: bool) -> Result<Vec<String>, Diagnostic> {
    let wait = wait.into_vec();
    if wait_all {
        if !wait.is_empty() && wait != ["all"] {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO146",
                "wait-all cannot be combined with named waits",
            ));
        }
        return Ok(vec!["all".into()]);
    }
    if wait.iter().any(|name| name == "all") && wait.len() != 1 {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO146",
            "wait: all cannot be combined with named waits",
        ));
    }
    Ok(wait)
}

/// A task's `hooks`, as the v1 mapping or the Go scalar shorthand.
///
/// `hooks: true` means "depend on tasks named `before` and `after`" — the
/// literal names, because hooks are edges and an edge names a task. That is
/// what the reference does, so translating it to anything else would invent a
/// behavior a Go file does not have.
// `Shorthand` is tried first and this ordering is load-bearing. `untagged`
// commits to the first variant that matches, and `StructuredTaskHooks` has two
// optional fields, so it happily deserializes the boolean `true` into an empty
// mapping. Putting the boolean first is safe the other way round: a mapping is
// not a bool, so it falls through to `Mapping`.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum HooksSection {
    // The boolean and the string and the integer are all one concept, and the
    // reference accepts `true`, `"true"`, `"yes"`, and `1`. `Shorthand` is
    // tried before `Mapping` because `StructuredTaskHooks` has two optional
    // fields and would otherwise match the scalar as an empty mapping.
    Shorthand(GoHooksShorthand),
    Mapping(StructuredTaskHooks),
}

/// A `hooks:` scalar, in every spelling the reference accepts.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum GoHooksShorthand {
    Flag(bool),
    Word(String),
    Count(u64),
}

impl GoHooksShorthand {
    /// The reference compares case-insensitively against `true`/`yes` and
    /// against the literal `1`; anything else is an error there, so it is one
    /// here too rather than a default.
    fn enabled(self) -> Result<bool, String> {
        match self {
            Self::Flag(flag) => Ok(flag),
            // The reference compares the *literal* against "1" and "0", so any
            // other integer is an error there. Accepting `2` as false would be
            // inventing a reading: a typo would silently produce no edges.
            Self::Count(0) => Ok(false),
            Self::Count(1) => Ok(true),
            Self::Count(count) => Err(format!(
                "expected 'true' or 'false' for hooks scalar, got {count}"
            )),
            Self::Word(word) => match word.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" => Ok(true),
                "false" | "no" => Ok(false),
                other => Err(format!(
                    "expected 'true' or 'false' for hooks scalar, got {other:?}"
                )),
            },
        }
    }
}

impl Default for HooksSection {
    fn default() -> Self {
        Self::Mapping(StructuredTaskHooks::default())
    }
}

impl HooksSection {
    /// # Errors
    ///
    /// Returns a diagnostic when a `hooks:` scalar is neither a recognized
    /// boolean spelling nor `1`.
    pub(super) fn into_parts(self) -> Result<StructuredTaskHooks, String> {
        Ok(match self {
            Self::Mapping(hooks) => hooks,
            Self::Shorthand(shorthand) => {
                if shorthand.enabled()? {
                    StructuredTaskHooks {
                        before: StringList::Scalar("before".into()),
                        after: StringList::Scalar("after".into()),
                    }
                } else {
                    StructuredTaskHooks {
                        before: StringList::Empty,
                        after: StringList::Empty,
                    }
                }
            }
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(super) enum StringList {
    #[default]
    Empty,
    Scalar(String),
    List(Vec<String>),
}

impl StringList {
    pub(super) fn into_vec(self) -> Vec<String> {
        match self {
            Self::Empty => Vec::new(),
            Self::Scalar(value) => vec![value],
            Self::List(values) => values,
        }
    }
}

/// A `with:` value.
///
/// Most runners take scalar settings, but the reference's `tmpl` runner takes
/// `with.files` as a string list. Keeping the loosely typed shapes here lets the
/// document parse and lets normalization reject a list on every other key
/// instead of failing as an unknown YAML type with no key name.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredWithValue {
    String(String),
    Bool(bool),
    Integer(i64),
    Float(f64),
    List(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredParameter {
    Type(TaskParameterType),
    Map(StructuredParameterMap),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredParameterMap {
    #[serde(rename = "type")]
    pub(super) parameter_type: TaskParameterType,
    #[serde(default)]
    pub(super) required: bool,
    pub(super) default: Option<TaskParameterDefault>,
    pub(super) description: Option<String>,
    pub(super) position: Option<usize>,
    pub(super) long: Option<String>,
    pub(super) short: Option<char>,
    #[serde(default)]
    pub(super) repeatable: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredPredicate {
    String(String),
    Boolean(bool),
}

impl StructuredPredicate {
    pub(super) fn into_string(self) -> String {
        match self {
            Self::String(value) => value,
            Self::Boolean(value) => value.to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredTool {
    pub(super) id: String,
    #[serde(deserialize_with = "deserialize_version_scalar")]
    pub(super) version: String,
    pub(super) provider: Option<String>,
    pub(super) url: Option<String>,
    pub(super) sha256: Option<String>,
    pub(super) github_release: Option<StructuredGithubRelease>,
    pub(super) gitlab_release: Option<StructuredGitlabRelease>,
    pub(super) aqua: Option<StructuredAqua>,
    pub(super) npm: Option<StructuredNpm>,
    pub(super) dotnet_tool: Option<StructuredDotnetTool>,
    pub(super) go_module: Option<StructuredGoModule>,
    pub(super) ruby_gems: Option<StructuredRubyGems>,
    pub(super) cargo: Option<StructuredCargo>,
    #[serde(default)]
    pub(super) binaries: Vec<String>,
    /// A path to the binary inside the installed tree. Go: `binpath`.
    #[serde(default, alias = "binpath")]
    pub(super) binpath: Option<String>,
    /// The directory inside an archive to take binaries from. Go: `bindir`.
    #[serde(default, alias = "bindir")]
    pub(super) bindir: Option<String>,
    #[serde(default)]
    pub(super) platforms: Vec<StructuredPlatform>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredCargo {
    #[serde(deserialize_with = "deserialize_cargo_crate")]
    pub(super) crate_name: String,
    #[serde(deserialize_with = "deserialize_cargo_version")]
    pub(super) version: String,
    #[serde(deserialize_with = "deserialize_cargo_registry")]
    pub(super) registry: String,
    #[serde(deserialize_with = "deserialize_cargo_checksum")]
    pub(super) checksum: String,
    #[serde(deserialize_with = "deserialize_cargo_toolchain")]
    pub(super) toolchain: String,
    pub(super) scripts: StructuredCargoScripts,
    pub(super) build: StructuredCargoBuild,
    pub(super) network: StructuredCargoNetwork,
}

fn deserialize_cargo_crate<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = String::deserialize(deserializer)?;
    if !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(name)
    } else {
        Err(serde::de::Error::custom(
            "Cargo crate_name must be a valid package name",
        ))
    }
}
fn deserialize_cargo_registry<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if neoenv_core::tools::is_canonical_https_url(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Cargo registry must be a canonical HTTPS URL",
        ))
    }
}
fn deserialize_cargo_checksum<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if neoenv_core::tools::is_sha256(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Cargo checksum must be 64 lowercase hex characters",
        ))
    }
}
fn deserialize_cargo_toolchain<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if neoenv_core::tools::is_cargo_toolchain_pin(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Cargo toolchain must be pinned to an exact version",
        ))
    }
}

fn deserialize_cargo_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if neoenv_core::tools::is_exact_manager_version(&version) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(
            "Cargo version must be an exact semantic version such as 1.2.3",
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StructuredCargoScripts {
    Deny,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StructuredCargoBuild {
    Isolated,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum StructuredCargoNetwork {
    Deny,
}

/// Accepts a version written as a string, an integer, or a float.
///
/// YAML authors write `version: 1.27` without quotes, and the Go profile has
/// always accepted a numeric scalar there. Deserializing directly into `String`
/// used to coerce it; routing through [`serde_yaml::Value`] does not, so the
/// coercion is explicit here and applies to both `tools:` shapes.
fn deserialize_version_scalar<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match value {
        serde_yaml::Value::String(version) => Ok(version),
        serde_yaml::Value::Number(number) => Ok(number.to_string()),
        serde_yaml::Value::Bool(version) => Ok(version.to_string()),
        other => Err(serde::de::Error::custom(format!(
            "a tool version must be a string or number, not {}",
            yaml_kind(&other)
        ))),
    }
}

/// The two accepted `tools:` shapes.
///
/// A sequence of full declarations is the native form. A mapping is the short
/// form: ordinary keys name a tool and carry its version, and the reserved
/// `aliases` key maps a short name to a backend-qualified id.
///
/// The mapping is deliberately narrow. A value is a version scalar, and an
/// alias target must be `gh:owner/repo`; anything else is refused by name
/// rather than carried and ignored. The full declaration form remains
/// available under the sequence spelling.
pub(super) enum StructuredTools {
    List(Vec<StructuredTool>),
    Map(StructuredToolMap),
}

impl<'de> Deserialize<'de> for StructuredTools {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::Sequence(items) => {
                serde_yaml::from_value(serde_yaml::Value::Sequence(items))
                    .map(Self::List)
                    .map_err(serde::de::Error::custom)
            }
            serde_yaml::Value::Mapping(map) => {
                serde_yaml::from_value(serde_yaml::Value::Mapping(map))
                    .map(Self::Map)
                    .map_err(serde::de::Error::custom)
            }
            other => Err(serde::de::Error::custom(format!(
                "`tools:` must be a sequence of declarations or a mapping, not {}",
                yaml_kind(&other)
            ))),
        }
    }
}

impl Default for StructuredTools {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredToolMapEntry {
    #[serde(deserialize_with = "deserialize_version_scalar")]
    version: String,
    #[serde(default)]
    binaries: Vec<String>,
    #[serde(default)]
    asset: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    grep: Option<String>,
    #[serde(default, alias = "pre")]
    prerelease: bool,
    #[serde(default, alias = "rn")]
    rename: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct StructuredToolMap {
    #[serde(default)]
    pub(super) aliases: IndexMap<String, String>,
    #[serde(flatten)]
    pub(super) entries: IndexMap<String, serde_yaml::Value>,
}

impl StructuredTools {
    /// Expands the short mapping form into full declarations.
    ///
    /// Every unqualified key must have an alias, every alias must name a tool
    /// that is declared, and every alias target must be a GitHub repository.
    /// Each of those refusals prevents a field from being accepted and then
    /// silently doing nothing.
    pub(super) fn into_tools(self) -> Result<Vec<StructuredTool>, Diagnostic> {
        match self {
            Self::List(tools) => Ok(tools),
            Self::Map(map) => expand_tool_map(map),
        }
    }
}

#[allow(clippy::too_many_lines)] // One table-like expansion of the short mapping form.
fn expand_tool_map(map: StructuredToolMap) -> Result<Vec<StructuredTool>, Diagnostic> {
    let StructuredToolMap { aliases, entries } = map;
    for (name, target) in &aliases {
        if !entries.contains_key(name) {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO132",
                format!(
                    "tool alias `{name}` has no declaration under `tools:`; add `{name}: <version>` or remove the alias"
                ),
            ));
        }
        if !target.starts_with("gh:") {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO132",
                format!(
                    "tool alias `{name}` targets `{target}`; this form supports only `gh:owner/repo` targets. Use the sequence form for a provider declaration that needs more fields"
                ),
            ));
        }
    }
    let mut tools = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        // The short name is the executable name. It is not derived from the
        // repository: `rg` points at `BurntSushi/ripgrep`, and guessing
        // `ripgrep` would install a binary nobody asked for. A detailed value
        // can override `binaries` when the executable has another name.
        let (version, binaries, asset, checksum, grep, prerelease, rename) = match value {
            serde_yaml::Value::String(version) => {
                (version, vec![name.clone()], None, None, None, false, None)
            }
            serde_yaml::Value::Number(number) => (
                number.to_string(),
                vec![name.clone()],
                None,
                None,
                None,
                false,
                None,
            ),
            serde_yaml::Value::Mapping(_) => {
                let entry = serde_yaml::from_value::<StructuredToolMapEntry>(value).map_err(
                    |error| {
                        Diagnostic::new(
                            DiagnosticCategory::Validation,
                            "NEO132",
                            format!(
                                "tool `{name}` in the short `tools:` mapping is not readable: {error}"
                            ),
                        )
                    },
                )?;
                let binaries = if entry.binaries.is_empty() {
                    vec![name.clone()]
                } else {
                    entry.binaries
                };
                (
                    entry.version,
                    binaries,
                    entry.asset,
                    entry.checksum,
                    entry.grep,
                    entry.prerelease,
                    entry.rename,
                )
            }
            other => {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO132",
                    format!(
                        "tool `{name}` in the short `tools:` mapping must have a version scalar or a mapping, not {}",
                        yaml_kind(&other)
                    ),
                ));
            }
        };
        let target = aliases.get(&name).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO132",
                format!(
                    "tool `{name}` in the short `tools:` mapping has no backend alias; add `aliases: {{ {name}: gh:owner/repo }}` or use the sequence form"
                ),
            )
        })?;
        let repository = target.strip_prefix("gh:").unwrap_or_default();
        let (owner, repo) = repository.split_once('/').ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO132",
                format!("tool alias `{name}` targets `{target}`, which is not `gh:owner/repo`"),
            )
        })?;
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO132",
                format!("tool alias `{name}` targets `{target}`, which is not `gh:owner/repo`"),
            ));
        }
        tools.push(StructuredTool {
            id: name.clone(),
            version,
            provider: Some("github-release".to_owned()),
            url: None,
            sha256: checksum,
            github_release: Some(StructuredGithubRelease {
                repository: repository.to_owned(),
                asset,
                checksum_asset: None,
                grep,
                prerelease,
                rename,
            }),
            gitlab_release: None,
            aqua: None,
            npm: None,
            dotnet_tool: None,
            go_module: None,
            ruby_gems: None,
            cargo: None,
            binaries,
            binpath: None,
            bindir: None,
            platforms: Vec::new(),
        });
    }
    Ok(tools)
}

fn yaml_kind(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "a boolean",
        serde_yaml::Value::Number(_) => "a number",
        serde_yaml::Value::String(_) => "a string",
        serde_yaml::Value::Sequence(_) => "a sequence",
        serde_yaml::Value::Mapping(_) => "a mapping",
        serde_yaml::Value::Tagged(_) => "a tagged value",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredGithubRelease {
    pub(super) repository: String,
    /// Optional: an absent asset means "select by platform".
    #[serde(default)]
    pub(super) asset: Option<String>,
    pub(super) checksum_asset: Option<String>,
    /// A regular expression for selecting a release artifact.
    #[serde(default, alias = "grep")]
    pub(super) grep: Option<String>,
    /// Allow a pre-release when resolving `latest`.
    #[serde(default)]
    pub(super) prerelease: bool,
    /// The destination name from a Go `rename`/`rn` key.
    #[serde(default)]
    pub(super) rename: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredAqua {
    pub(super) endpoint: String,
    pub(super) registry_revision: String,
    pub(super) package: String,
    pub(super) manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredNpm {
    pub(super) endpoint: String,
    pub(super) package: String,
    pub(super) manager: Option<StructuredNpmManager>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredNpmManager {
    pub(super) name: StructuredNpmManagerName,
    #[serde(deserialize_with = "deserialize_manager_version")]
    pub(super) version: String,
    #[serde(default, deserialize_with = "deserialize_optional_manager_digest")]
    pub(super) archive_sha256: Option<String>,
}

fn deserialize_optional_manager_digest<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let digest = Option::<String>::deserialize(deserializer)?;
    if digest.as_deref().is_none_or(neoenv_core::tools::is_sha256) {
        Ok(digest)
    } else {
        Err(serde::de::Error::custom(
            "manager archive_sha256 must be 64 lowercase hex characters",
        ))
    }
}

fn deserialize_manager_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if neoenv_core::tools::is_exact_manager_version(&version) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(
            "manager version must be an exact semantic version such as 1.2.3",
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum StructuredNpmManagerName {
    Bun,
    Pnpm,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredDotnetTool {
    pub(super) source: String,
    pub(super) endpoint: String,
    pub(super) package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredGoModule {
    pub(super) source: String,
    pub(super) endpoint: String,
    pub(super) module: String,
    pub(super) go_sum: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredRubyGems {
    pub(super) endpoint: String,
    pub(super) gem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredPlatform {
    pub(super) os: Option<String>,
    pub(super) arch: Option<String>,
    pub(super) url: Option<String>,
    pub(super) sha256: Option<String>,
    pub(super) binaries: Option<Vec<String>>,
    #[serde(default, alias = "binpath")]
    pub(super) binpath: Option<String>,
    #[serde(default, alias = "bindir")]
    pub(super) bindir: Option<String>,
    /// A per-platform asset template. Absent means "select by platform".
    #[serde(default, alias = "asset")]
    pub(super) asset: Option<String>,
    /// A per-platform regular expression over release artifacts.
    #[serde(default, alias = "grep")]
    pub(super) grep: Option<String>,
    /// A per-platform `rename`/`rn` destination name.
    #[serde(default, alias = "rn")]
    pub(super) rename: Option<String>,
}

/// A GitLab release declaration, keyed by namespace and project.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredGitlabRelease {
    pub(super) namespace: String,
    pub(super) project: String,
    #[serde(default = "default_gitlab_host")]
    pub(super) host: String,
    /// An asset name template. Required, because a release with no asset
    /// selector has nothing to resolve against.
    pub(super) asset: String,
    /// A regular expression for selecting a release artifact.
    #[serde(default, alias = "grep")]
    pub(super) grep: Option<String>,
}

fn default_gitlab_host() -> String {
    "gitlab.com".to_owned()
}

pub(super) fn parse_toml(path: &Path, input: &str) -> Result<Project, Diagnostic> {
    let project: StructuredProject = toml::from_str(input).map_err(|error| {
        document_error(path, input, "NEO102", error.to_string()).with_cause(error)
    })?;
    structured_project(path, input, project, structured_spans(input, Format::Toml))
}

pub(super) fn parse_yaml(path: &Path, input: &str) -> Result<Project, Diagnostic> {
    let project: StructuredProject = serde_yaml::from_str(input).map_err(|error| {
        document_error(path, input, "NEO102", error.to_string()).with_cause(error)
    })?;
    structured_project(path, input, project, structured_spans(input, Format::Yaml))
}

pub(super) fn structured_project(
    path: &Path,
    input: &str,
    project: StructuredProject,
    mut spans: StructuredSpans,
) -> Result<Project, Diagnostic> {
    if project.format_version != FORMAT_VERSION {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO103",
            format!(
                "unsupported configuration format version: {}",
                project.format_version
            ),
        )
        .at(document_span(path, input)));
    }

    let source_path = path.display().to_string();
    let vaults = normalize_vaults(project.vaults, &source_path)?;
    let (environment, dotenv, path_operations) = normalize_environment_extensions(
        project.env,
        project.dotenv,
        project.path,
        &source_path,
        &mut spans,
    )?;
    let tools = project
        .tools
        .into_tools()?
        .into_iter()
        .map(|tool| {
            if tool.provider.as_deref() == Some("cargo") && tool.binaries.is_empty() {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO514",
                    format!(
                        "Cargo tool `{}` must declare at least one executable in `binaries` for deterministic lookup",
                        tool.id
                    ),
                ));
            }
            Ok(normalize_tool(tool, &source_path, &mut spans))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tasks = project
        .tasks
        .into_iter()
        .map(|(name, task)| {
            normalize_task(task, &name, &source_path, &mut spans).map(|task| (name, task))
        })
        .collect::<Result<_, _>>()?;
    Ok(Project {
        format_version: FORMAT_VERSION,
        source: document_span(path, input),
        vaults,
        environment,
        dotenv,
        path: path_operations,
        tools,
        context: project.context,
        task_dirs: TaskDirectories {
            local: project.task_dirs.local.into_vec(),
            global: project.task_dirs.global.into_vec(),
        },
        task_packages: project
            .task_packages
            .into_iter()
            .map(|(name, package)| (name, package.into_package()))
            .collect(),
        tasks,
        deployments: project
            .deployments
            .into_iter()
            .map(|(name, deployment)| (name, deployment.into_deployment()))
            .collect(),
        inventory_files: project.inventory_files,
        inventories: project
            .inventories
            .into_iter()
            .map(|(name, inventory)| (name, inventory.into_inventory()))
            .collect(),
        jobs: project
            .jobs
            .into_iter()
            .map(|(name, job)| normalize_job(job, &name, &source_path).map(|job| (name, job)))
            .collect::<Result<_, _>>()?,
        imports: project.imports.into_vec(),
        workspace: Workspace {
            members: project.workspace.members.into_vec(),
            aliases: project.workspace.aliases,
        },
    })
}

fn normalize_tool(
    tool: StructuredTool,
    source_path: &str,
    spans: &mut StructuredSpans,
) -> ToolDeclaration {
    ToolDeclaration {
        declaration_source: spans.next_tool(source_path),
        id: tool.id,
        version: tool.version,
        provider: ToolProvider::from_name(tool.provider.as_deref()),
        url: tool.url,
        sha256: tool.sha256,
        github_release: tool.github_release.map(|github| {
            neoenv_core::tools::GithubReleaseDeclaration {
                repository: github.repository,
                asset: github.asset,
                checksum_asset: github.checksum_asset,
                grep: github.grep,
                prerelease: github.prerelease,
                rename: github.rename,
            }
        }),
        gitlab_release: tool.gitlab_release.map(|gitlab| {
            neoenv_core::tools::GitlabReleaseDeclaration {
                host: gitlab.host,
                namespace: gitlab.namespace,
                project: gitlab.project,
                asset: gitlab.asset,
                grep: gitlab.grep,
            }
        }),
        aqua: tool.aqua.map(|aqua| neoenv_core::tools::AquaDeclaration {
            endpoint: aqua.endpoint,
            registry_revision: aqua.registry_revision,
            package: aqua.package,
            manifest_sha256: aqua.manifest_sha256,
        }),
        npm: tool.npm.map(|npm| neoenv_core::tools::NpmDeclaration {
            endpoint: npm.endpoint,
            package: npm.package,
            manager: npm.manager.map(|manager| neoenv_core::tools::NpmManager {
                name: match manager.name {
                    StructuredNpmManagerName::Bun => neoenv_core::tools::NpmManagerName::Bun,
                    StructuredNpmManagerName::Pnpm => neoenv_core::tools::NpmManagerName::Pnpm,
                },
                version: manager.version,
                archive_sha256: manager.archive_sha256,
            }),
        }),
        dotnet_tool: tool
            .dotnet_tool
            .map(|dotnet| neoenv_core::tools::DotnetToolDeclaration {
                source: dotnet.source,
                endpoint: dotnet.endpoint,
                package: dotnet.package,
            }),
        go_module: tool
            .go_module
            .map(|go| neoenv_core::tools::GoModuleDeclaration {
                source: go.source,
                endpoint: go.endpoint,
                module: go.module,
                go_sum: go.go_sum,
            }),
        ruby_gems: tool
            .ruby_gems
            .map(|ruby| neoenv_core::tools::RubyGemsDeclaration {
                endpoint: ruby.endpoint,
                gem: ruby.gem,
            }),
        cargo: normalize_cargo(tool.cargo),
        binaries: tool.binaries,
        binpath: tool.binpath,
        bindir: tool.bindir,
        platforms: tool
            .platforms
            .into_iter()
            .map(|platform| PlatformOverride {
                platform: PlatformSelector {
                    os: platform.os,
                    arch: platform.arch,
                },
                url: platform.url,
                sha256: platform.sha256,
                binaries: platform.binaries,
                binpath: platform.binpath,
                bindir: platform.bindir,
                asset: platform.asset,
                grep: platform.grep,
                rename: platform.rename,
            })
            .collect(),
    }
}

fn normalize_cargo(cargo: Option<StructuredCargo>) -> Option<neoenv_core::tools::CargoDeclaration> {
    cargo.map(|cargo| neoenv_core::tools::CargoDeclaration {
        crate_name: cargo.crate_name,
        version: cargo.version,
        registry: cargo.registry,
        checksum: cargo.checksum,
        toolchain: cargo.toolchain,
        scripts: match cargo.scripts {
            StructuredCargoScripts::Deny => neoenv_core::tools::CargoScriptPolicy::Deny,
        },
        build: match cargo.build {
            StructuredCargoBuild::Isolated => neoenv_core::tools::CargoBuildPolicy::Isolated,
        },
        network: match cargo.network {
            StructuredCargoNetwork::Deny => neoenv_core::tools::CargoNetworkPolicy::Deny,
        },
    })
}

pub(super) type EnvironmentExtensions =
    (Vec<EnvironmentEntry>, Vec<DotenvImport>, Vec<PathOperation>);

pub(super) fn normalize_environment_extensions(
    env: IndexMap<String, String>,
    dotenv: DotenvList,
    path: Vec<StructuredPathOperation>,
    source_path: &str,
    spans: &mut StructuredSpans,
) -> Result<EnvironmentExtensions, Diagnostic> {
    let mut environment = Vec::with_capacity(env.len());
    for (key, value) in env {
        let source = spans.next_env(source_path);
        validate_key(&key, source_path, source.line)?;
        reject_command_substitution(&value, source_path, source.line)?;
        environment.push(EnvironmentEntry {
            key,
            value,
            source,
            // The v1 mapping form has no secret flag; redaction is by name. Only
            // the Go compatibility profile can mark a value secret.
            secret: false,
        });
    }
    let dotenv = dotenv
        .into_vec()
        .into_iter()
        .map(|dotenv| {
            let (path, required, filter) = dotenv.into_parts();
            let source = spans.next_dotenv(source_path);
            reject_command_substitution(&path, source_path, source.line)?;
            Ok(DotenvImport {
                path,
                required,
                filter,
                source,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    let path_operations = path
        .into_iter()
        .map(|operation| {
            let source = spans.next_path(source_path);
            match (operation.prepend, operation.append) {
                (Some(value), None) => Ok((PathOperationKind::Prepend, value)),
                (None, Some(value)) => Ok((PathOperationKind::Append, value)),
                _ => Err(Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO110",
                    "a PATH operation must declare exactly one of prepend or append",
                )
                .at(source.clone())),
            }
            .and_then(|(kind, value)| {
                reject_command_substitution(&value, source_path, source.line)?;
                Ok(PathOperation {
                    kind,
                    value,
                    filter: operation.filter,
                    source,
                })
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    Ok((environment, dotenv, path_operations))
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredJob {
    /// A bare `steps:` list, so `jobs: {deploy: [build, test]}` is valid.
    Steps(StructuredStepList),
    Map(Box<StructuredJobMap>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredJobMap {
    pub(super) timeout: Option<String>,
    pub(super) background: Option<bool>,
    #[serde(default)]
    pub(super) wait: StringList,
    #[serde(default, rename = "wait-all", alias = "wait_all")]
    pub(super) wait_all: bool,
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    #[serde(alias = "desc")]
    pub(super) description: Option<String>,
    pub(super) help: Option<String>,
    /// `deps` and `dependencies` are the Go spellings, as on a task.
    #[serde(default, alias = "deps", alias = "dependencies")]
    pub(super) needs: NeedsSection,
    #[serde(default)]
    pub(super) steps: StructuredStepList,
    #[serde(default)]
    pub(super) env: IndexMap<String, String>,
    /// `envfile` and `env-file` are the Go spellings of `dotenv`, as on a task.
    #[serde(default, alias = "envfile", alias = "env-file")]
    pub(super) dotenv: DotenvList,
    /// The default working directory for every step.
    pub(super) cwd: Option<String>,
    /// `predicate` is the Go spelling of `if`.
    #[serde(rename = "if", alias = "predicate")]
    pub(super) if_condition: Option<StructuredPredicate>,
    /// Declared, never read, and **refused** by `normalize_job`.
    ///
    /// The reference has both of these fields and honours neither: `Job.Extends` is
    /// written at `neofile/job.go:90` and read nowhere, and `Job.Cron` is written at
    /// `neofile/job.go:91-93` and read nowhere. Accepting them would add two keys that
    /// parse and do nothing, which is the failure this repository has shipped before.
    /// See `docs/decision-records/a-job-is-a-sequence-of-steps.md`.
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) extends: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) cron: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredStepList {
    #[default]
    Empty,
    /// `steps: [build, test]` -- a bare scalar is a task reference, matching
    /// `neofile/steps.go:8`.
    Bare(Vec<String>),
    Detailed(Vec<StructuredStep>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredStep {
    pub(super) timeout: Option<String>,
    pub(super) background: Option<bool>,
    #[serde(default)]
    pub(super) wait: StringList,
    #[serde(default, rename = "wait-all", alias = "wait_all")]
    pub(super) wait_all: bool,
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    /// The task this step runs. The alternative to `run`.
    #[serde(alias = "task", alias = "uses_task")]
    pub(super) task: Option<String>,
    pub(super) uses: Option<String>,
    pub(super) run: Option<String>,
    #[serde(default)]
    pub(super) args: Vec<String>,
    #[serde(default)]
    pub(super) env: IndexMap<String, String>,
    pub(super) cwd: Option<String>,
    #[serde(rename = "if", alias = "predicate")]
    pub(super) if_condition: Option<StructuredPredicate>,
    pub(super) force: Option<String>,
    /// Declared, never read, and **refused**: the reference's `taskFromJobStep`
    /// (`runner.go:680-696`) copies neither `Embed` nor `With` into the task it
    /// builds, so a step's `embed:` and `with:` parse in the reference and do
    /// nothing there either.
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) embed: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) with: IndexMap<String, String>,
}

/// Normalizes one `jobs:` entry.
///
/// **The refusals are the point of this function.** `extends` and `cron` exist in
/// the reference and are inert there, so they are refused here by name rather than
/// accepted and ignored -- and a step's `embed` and `with` likewise, because
/// `taskFromJobStep` copies neither. A key is ported with its behaviour or refused;
/// never on the strength of the reference having a field for it. The citations are in
/// `docs/decision-records/a-job-is-a-sequence-of-steps.md`.
fn normalize_job(
    job: StructuredJob,
    name: &str,
    source_path: &str,
) -> Result<JobDefinition, Diagnostic> {
    let at = || SourceSpan::new(source_path.to_owned(), 1, 1);
    // `label`, not `name`: the second slot is the job's declared display name and
    // `name` is already the declaration key every message in here uses.
    let (
        id,
        label,
        description,
        help,
        needs,
        steps,
        env,
        dotenv,
        cwd,
        if_condition,
        background,
        wait,
        parallel_needs,
        timeout,
    ) = match job {
        StructuredJob::Steps(steps) => (
            None,
            None,
            None,
            None,
            Vec::new(),
            steps,
            IndexMap::new(),
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            None,
        ),
        StructuredJob::Map(job) => {
            let job = *job;
            let parallel_needs = job.needs.parallel_ids();
            for (present, key) in [
                (job.extends.is_some(), "extends"),
                (job.cron.is_some(), "cron"),
                (job.background.is_some(), "background"),
            ] {
                if present {
                    return Err(Diagnostic::new(
                        DiagnosticCategory::Validation,
                        "NEO141",
                        format!(
                            "job {name} sets `{key}`, which the reference parses and never \
                             reads; there is no behaviour to port, and a key that does \
                             nothing is worse than a key that is refused"
                        ),
                    )
                    .at(at()));
                }
            }
            (
                job.id,
                job.name,
                job.description,
                job.help,
                job.needs.into_vec()?,
                job.steps,
                job.env,
                normalize_job_dotenv(job.dotenv, source_path),
                job.cwd,
                job.if_condition.map(StructuredPredicate::into_string),
                job.background,
                normalize_wait(job.wait, job.wait_all)?,
                parallel_needs,
                job.timeout,
            )
        }
    };

    let steps = normalize_steps(steps, name, source_path)?;
    validate_job_steps(&steps, name, source_path)?;

    Ok(JobDefinition {
        timeout,
        id,
        name: label,
        description,
        help,
        needs,
        steps,
        env,
        dotenv,
        if_condition,
        cwd,
        background,
        wait,
        parallel_needs,
    })
}

fn validate_job_steps(
    steps: &[StepDefinition],
    name: &str,
    source_path: &str,
) -> Result<(), Diagnostic> {
    let at = || SourceSpan::new(source_path.to_owned(), 1, 1);
    if steps.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO142",
            format!("job {name} declares no steps, so there is nothing for it to run"),
        )
        .at(at()));
    }
    for (index, step) in steps.iter().enumerate() {
        if step.task.is_none()
            && step.run.as_deref().is_none_or(str::is_empty)
            && step.wait.is_empty()
        {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO143",
                format!(
                    "job {name} step {} has neither a `task:` to run nor a `run:` command",
                    index + 1
                ),
            )
            .at(at()));
        }
        if step.task.is_some() && step.run.is_some() {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO144",
                format!(
                    "job {name} step {} sets both `task:` and `run:`; a step is one or the \
                     other, and guessing which was meant is how a run does something \
                     nobody wrote",
                    index + 1
                ),
            )
            .at(at()));
        }
    }

    Ok(())
}

fn normalize_steps(
    steps: StructuredStepList,
    job: &str,
    source_path: &str,
) -> Result<Vec<StepDefinition>, Diagnostic> {
    let at = || SourceSpan::new(source_path.to_owned(), 1, 1);
    Ok(match steps {
        StructuredStepList::Empty => Vec::new(),
        // A bare scalar is a task reference: *"A scalar step name is treated as a task
        // reference"*, `neofile/steps.go:8`.
        StructuredStepList::Bare(names) => names
            .into_iter()
            .map(|task| StepDefinition {
                task: Some(task),
                ..StepDefinition::default()
            })
            .collect(),
        StructuredStepList::Detailed(steps) => steps
            .into_iter()
            .map(|step| {
                for (present, key) in [
                    (step.embed.is_some(), "embed"),
                    (!step.with.is_empty(), "with"),
                ] {
                    if present {
                        return Err(Diagnostic::new(
                            DiagnosticCategory::Validation,
                            "NEO145",
                            format!(
                                "job {job} has a step with `{key}`, which the reference \
                                 parses and never copies into the task it builds; there \
                                 is no behaviour to port"
                            ),
                        )
                        .at(at()));
                    }
                }
                Ok(StepDefinition {
                    timeout: step.timeout,
                    background: step.background,
                    wait: normalize_wait(step.wait, step.wait_all)?,
                    id: step.id,
                    name: step.name,
                    task: step.task,
                    run: step.run,
                    uses: step.uses,
                    args: step.args,
                    env: step.env,
                    cwd: step.cwd,
                    if_condition: step.if_condition.map(StructuredPredicate::into_string),
                    force: step.force,
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

/// A job's `dotenv:` becomes the same import shape a task's does.
///
/// **Not `DotenvImport`.** That type carries a `SourceSpan` and an `EntryFilter`
/// from the document reader's span machinery, and a job's dotenv list is a plain
/// list of paths that the lowering hands to each synthetic step. Using the task's
/// own type keeps the lowering free of a second dotenv reader, and a job whose
/// dotenv is missing is a failing step rather than a failing project -- which is
/// the correct blast radius, and the same asymmetry #259 records for `task_packages`.
fn normalize_job_dotenv(list: DotenvList, _source_path: &str) -> Vec<String> {
    list.into_vec()
        .into_iter()
        .map(|entry| entry.into_parts().0)
        .collect()
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredInventory {
    /// `inventories: {prod: [web1, web2]}` -- a bare list of host names, which is
    /// the shape most inventories want and the one where each host's address is its
    /// own name.
    Hosts(Vec<String>),
    Map(Box<StructuredInventoryMap>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredInventoryMap {
    #[serde(default)]
    pub(super) hosts: IndexMap<String, StructuredInventoryHost>,
    #[serde(default)]
    pub(super) defaults: StructuredInventoryDefaults,
}

/// One host entry. A bare string is an address, so both `hosts: {web1: web1}` and
/// `hosts: {web1: 10.0.0.1}` are accepted.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StructuredInventoryHost {
    Bare(String),
    Map(Box<StructuredInventoryHostMap>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredInventoryHostMap {
    /// Where to connect, when it is not the host's own name.
    pub(super) address: Option<String>,
    /// The tags this host answers to; `ssh @prod` selects every host with `prod`.
    #[serde(default)]
    pub(super) tags: StringList,
    pub(super) user: Option<String>,
    pub(super) port: Option<u16>,
    pub(super) host_key: Option<String>,
    pub(super) password_env: Option<String>,
    pub(super) identity_file: Option<String>,
    #[serde(default)]
    pub(super) password_auth: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredInventoryDefaults {
    pub(super) user: Option<String>,
    pub(super) port: Option<u16>,
    pub(super) identity_file: Option<String>,
}

impl StructuredInventory {
    fn into_inventory(self) -> Inventory {
        match self {
            Self::Hosts(names) => {
                let hosts: IndexMap<String, InventoryHost> = names
                    .into_iter()
                    .map(|name| (name, InventoryHost::default()))
                    .collect();
                Inventory {
                    order: hosts.keys().cloned().collect(),
                    hosts,
                    defaults: InventoryDefaults::default(),
                }
            }
            Self::Map(map) => {
                let mut hosts = IndexMap::new();
                for (name, host) in map.hosts {
                    let mut host = match host {
                        StructuredInventoryHost::Bare(address) => InventoryHost {
                            address: Some(address),
                            ..InventoryHost::default()
                        },
                        StructuredInventoryHost::Map(host) => InventoryHost {
                            address: host.address,
                            tags: host.tags.into_vec(),
                            user: host.user,
                            port: host.port,
                            host_key: host.host_key,
                            password_env: host.password_env,
                            identity_file: host.identity_file,
                            password_auth: host.password_auth,
                        },
                    };
                    host.address = host.address.filter(|value| value != &name);
                    hosts.insert(name, host);
                }
                Inventory {
                    order: hosts.keys().cloned().collect(),
                    hosts,
                    defaults: InventoryDefaults {
                        user: map.defaults.user,
                        port: map.defaults.port,
                        identity_file: map.defaults.identity_file,
                    },
                }
            }
        }
    }
}

/// One `ship:` entry.
///
/// **`deny_unknown_fields`, and the reference's other ten keys are *not* declared.**
/// The reference's `ShipDeployment` has fourteen fields and its `ship` path reads four
/// of them, refusing to execute at `cli.go:817` before touching the rest. Declaring
/// `env`, `dotenv`, `before`, `after`, `compose`, `cwd` and `timeout` here would accept
/// ten keys that parse and do nothing -- the same defect as #31, imported on purpose.
/// They are absent here, so `deny_unknown_fields` refuses each by name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredDeployment {
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    /// `type` is the reference's spelling of the deployment kind. Not a Rust keyword
    /// issue, but worth noting: the field is `deployment_type` in the model and `type`
    /// on disk.
    #[serde(rename = "type")]
    pub(super) deployment_type: Option<String>,
    #[serde(alias = "desc")]
    pub(super) description: Option<String>,
    pub(super) help: Option<String>,
    // `contexts` is deliberately NOT declared. The reference reads
    // `ShipDeployment.Contexts` in exactly two places -- `cli/complete.go:337` and
    // `:352`, both shell completion -- and never in `ShipMap.Resolve`, which selects a
    // deployment by the key convention `name:context` instead. So `contexts` here
    // would parse and do nothing, and `deny_unknown_fields` refuses it by name.
}

impl StructuredDeployment {
    fn into_deployment(self) -> DeploymentDefinition {
        DeploymentDefinition {
            id: self.id,
            name: self.name,
            deployment_type: self.deployment_type,
            description: self.description,
            help: self.help,
        }
    }
}
