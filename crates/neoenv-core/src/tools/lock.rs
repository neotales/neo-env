//! The tool lockfile document and its validation, including provenance
//! and identity checks that must hold before any artifact is installed.

use super::planning::{
    canonicalize_url, is_go_sum, is_npm_integrity, is_registry_revision, is_safe_binary_name,
    is_sha512_integrity, is_valid_go_module, is_valid_nuget_package,
};
use super::{
    ArtifactVerification, BTreeMap, Deserialize, HashSet, PlannedTool, Platform, Serialize,
    SourceSpan, TOOL_LOCK_SCHEMA_VERSION, ToolPlan, ToolProvenance, fmt, is_sha256,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLockfile {
    pub schema_version: u32,
    pub tools: Vec<LockedTool>,
    /// Exact project lifecycle constraints.  The selected `tools` table is
    /// the active lock; this side table records versions that must survive
    /// cleanup even after a later update changes the active entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pins: BTreeMap<String, Vec<String>>,
    /// Optional reproducible package-manager resolution graph. Older lockfiles
    /// omit this field and remain valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager_lock: Option<ManagerLock>,
    /// Optional source-build evidence. Absent in historical lockfiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_build: Option<CargoBuildLock>,
}

impl ToolLockfile {
    pub fn from_plan(plan: &ToolPlan) -> Self {
        Self {
            schema_version: TOOL_LOCK_SCHEMA_VERSION,
            tools: plan.tools.iter().map(LockedTool::from).collect(),
            pins: BTreeMap::new(),
            manager_lock: None,
            cargo_build: plan
                .tools
                .iter()
                .find(|tool| tool.provenance.provider == "cargo")
                .map(|tool| CargoBuildLock {
                    tool_id: tool.id.clone(),
                    crate_name: tool.provenance.package.clone().unwrap_or_default(),
                    version: tool.resolved_version.clone(),
                    registry: tool
                        .provenance
                        .registry_endpoint
                        .clone()
                        .unwrap_or_default(),
                    checksum: tool.sha256.clone(),
                    toolchain: tool.cargo_toolchain.clone().unwrap_or_default(),
                    scripts: super::CargoScriptPolicy::Deny,
                    build: super::CargoBuildPolicy::Isolated,
                    network: super::CargoNetworkPolicy::Deny,
                }),
        }
    }

    /// # Errors
    ///
    /// Returns an error when schema, identity, URL, provenance, binary, or
    /// digest invariants are not satisfied.
    pub fn validate(&self) -> Result<(), ToolLockError> {
        if self.schema_version != TOOL_LOCK_SCHEMA_VERSION {
            return Err(ToolLockError::UnsupportedSchemaVersion {
                schema_version: self.schema_version,
            });
        }
        validate_lock_pins(&self.pins)?;
        if let Some(manager_lock) = &self.manager_lock {
            manager_lock.validate()?;
        }
        if self.cargo_build.as_ref().is_some_and(|build| {
            !valid_cargo_name(&build.crate_name)
                || build.tool_id.is_empty()
                || !super::is_exact_manager_version(&build.version)
                || !super::is_canonical_https_url(&build.registry)
                || !is_sha256(&build.checksum)
                || !valid_toolchain_pin(&build.toolchain)
        }) {
            return Err(ToolLockError::InvalidCargoBuild);
        }
        let mut ids = HashSet::with_capacity(self.tools.len());
        for tool in &self.tools {
            validate_locked_tool(tool, &mut ids)?;
        }
        if let Some(build) = &self.cargo_build {
            let matches: Vec<_> = self
                .tools
                .iter()
                .filter(|tool| tool.id == build.tool_id)
                .collect();
            if self
                .tools
                .iter()
                .filter(|tool| tool.resolver == "cargo")
                .count()
                != 1
                || matches.len() != 1
                || matches[0].resolver != "cargo"
                || matches[0].provenance.provider != "cargo"
                || matches[0].resolved_version != build.version
                || matches[0].provenance.package.as_deref() != Some(build.crate_name.as_str())
                || matches[0].provenance.registry_endpoint.as_deref()
                    != Some(build.registry.as_str())
                || matches[0].sha256 != build.checksum
                || matches[0].verification.sha256 != build.checksum
                || matches[0].binaries.is_empty()
                || matches[0].cargo_toolchain.as_deref() != Some(build.toolchain.as_str())
            {
                return Err(ToolLockError::InvalidCargoBuild);
            }
        } else if self.tools.iter().any(|tool| tool.resolver == "cargo") {
            return Err(ToolLockError::InvalidCargoBuild);
        }
        Ok(())
    }
}

fn valid_cargo_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_toolchain_pin(value: &str) -> bool {
    value.len() <= 256 && super::is_cargo_toolchain_pin(value)
}

/// Immutable inputs and explicit sandbox policy for a Cargo source build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoBuildLock {
    /// Exact tool declaration ID this source-build evidence belongs to.
    pub tool_id: String,
    /// Exact registry package name.
    pub crate_name: String,
    /// Exact crate release version.
    pub version: String,
    /// Canonical HTTPS URL of the registry index.
    pub registry: String,
    /// Registry-provided SHA-256 of the exact `.crate` source archive.
    pub checksum: String,
    /// Exact Rust toolchain version, optionally with a safe target triple.
    pub toolchain: String,
    /// Lifecycle-script permission; currently only `Deny` is valid.
    pub scripts: super::CargoScriptPolicy,
    /// Build isolation requirement; currently only `Isolated` is valid.
    pub build: super::CargoBuildPolicy,
    /// Build network access; currently only `Deny` is valid.
    pub network: super::CargoNetworkPolicy,
}

/// Versioned record of an npm-compatible package manager's complete resolution.
///
/// `schema_version` evolves independently from the enclosing tool lock schema.
/// Consumers that download `tarball_url` must independently enforce their
/// network/host policy (including redirects and resolved addresses); URL
/// canonicalization in this domain validator is not an SSRF defense.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerLock {
    /// Independent version for evolution of this nested graph format.
    pub schema_version: u32,
    pub manager: String,
    pub manager_version: String,
    /// SHA-256 of the exact manager executable selected for this install.
    pub manager_sha256: String,
    pub runtime_version: String,
    /// Archive provenance for replayable managed runtimes. Older manager graphs
    /// may omit it, but cannot be used for verified managed replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_archive: Option<ManagerRuntimeArchive>,
    pub manifest_sha256: String,
    pub lockfile_sha256: String,
    pub script_policy: ScriptPolicy,
    pub packages: Vec<ManagerPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerRuntimeArchive {
    pub url: String,
    pub sha256: String,
}

/// Explicit policy for lifecycle scripts in managed package installs.
///
/// `Disabled` is the only implemented contract: a package-manager installer
/// must configure the manager to skip lifecycle scripts, not merely record
/// this value. Any future policy requires a schema/API change and an explicit
/// validated allowlist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptPolicy {
    Disabled,
}

/// An immutable package node in the manager's dependency graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    /// Edges use package IDs; cycles are allowed, so consumers must bound traversal.
    pub dependencies: Vec<String>,
    /// Canonical HTTP(S) URL. Network consumers still must enforce host policy.
    pub tarball_url: String,
    pub integrity: String,
    pub sha256: String,
}

impl ManagerLock {
    /// Check graph identity, digest, URL, and bounded-size invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ToolLockError::InvalidManagerLock`] if any graph invariant fails.
    pub fn validate(&self) -> Result<(), ToolLockError> {
        const MAX_PACKAGES: usize = 100_000;
        const MAX_EDGES: usize = 1_000_000;
        const MAX_TEXT_BYTES: usize = 16_384;
        const MAX_INTEGRITY_BYTES: usize = 256;
        const MAX_DEPS_PER_PACKAGE: usize = 100_000;
        if self.schema_version != 1
            || self.manager.is_empty()
            || self.manager.len() > 128
            || self.manager_version.is_empty()
            || self.manager_version.len() > MAX_TEXT_BYTES
            || !is_sha256(&self.manager_sha256)
            || self.runtime_version.is_empty()
            || self.runtime_version.len() > MAX_TEXT_BYTES
            || self.runtime_archive.as_ref().is_some_and(|archive| {
                archive.url.len() > MAX_TEXT_BYTES
                    || canonicalize_url(&archive.url).as_deref() != Ok(archive.url.as_str())
                    || !is_sha256(&archive.sha256)
            })
            || !is_sha256(&self.manifest_sha256)
            || !is_sha256(&self.lockfile_sha256)
            || self.packages.len() > MAX_PACKAGES
        {
            return Err(ToolLockError::InvalidManagerLock);
        }
        let mut ids = HashSet::with_capacity(self.packages.len());
        let mut edges = 0usize;
        for package in &self.packages {
            if package.id.is_empty()
                || package.name.is_empty()
                || package.version.is_empty()
                || package.id.len() > MAX_TEXT_BYTES
                || package.name.len() > MAX_TEXT_BYTES
                || package.version.len() > MAX_TEXT_BYTES
                || package.tarball_url.len() > MAX_TEXT_BYTES
                || package.integrity.len() > MAX_INTEGRITY_BYTES
                || package.dependencies.len() > MAX_DEPS_PER_PACKAGE
                || !ids.insert(package.id.as_str())
                || canonicalize_url(&package.tarball_url).as_deref()
                    != Ok(package.tarball_url.as_str())
                || !is_npm_integrity(&package.integrity)
                || !is_sha256(&package.sha256)
            {
                return Err(ToolLockError::InvalidManagerLock);
            }
            edges = edges.saturating_add(package.dependencies.len());
            if edges > MAX_EDGES {
                return Err(ToolLockError::InvalidManagerLock);
            }
        }
        for package in &self.packages {
            let mut dependencies = HashSet::new();
            if package
                .dependencies
                .iter()
                .any(|dep| !ids.contains(dep.as_str()) || !dependencies.insert(dep.as_str()))
            {
                return Err(ToolLockError::InvalidManagerLock);
            }
        }
        // This is a dependency graph, not a topological install plan. npm
        // packages may legitimately depend on one another through cycles;
        // consumers must handle cycles without unbounded recursive traversal.
        Ok(())
    }
}

fn validate_lock_pins(pins: &BTreeMap<String, Vec<String>>) -> Result<(), ToolLockError> {
    for (id, versions) in pins {
        if id.is_empty()
            || versions.is_empty()
            || versions.iter().any(|version| {
                version.is_empty()
                    || version.contains(['/', '\\'])
                    || version.chars().any(char::is_control)
            })
        {
            return Err(ToolLockError::InvalidTool { id: id.clone() });
        }
        let mut unique = HashSet::with_capacity(versions.len());
        if versions.iter().any(|version| !unique.insert(version)) {
            return Err(ToolLockError::InvalidTool { id: id.clone() });
        }
    }
    Ok(())
}

fn validate_locked_tool<'a>(
    tool: &'a LockedTool,
    ids: &mut HashSet<&'a str>,
) -> Result<(), ToolLockError> {
    if !ids.insert(tool.id.as_str()) {
        return Err(ToolLockError::DuplicateToolId {
            id: tool.id.clone(),
        });
    }
    if !is_sha256(&tool.sha256) {
        return Err(ToolLockError::InvalidSha256 {
            id: tool.id.clone(),
            sha256: tool.sha256.clone(),
        });
    }
    if (tool.resolver == "cargo" && tool.binaries.is_empty())
        || (tool.resolver != "cargo" && tool.cargo_toolchain.is_some())
        || tool.verification.sha256 != tool.sha256
        || tool.provenance.provider != tool.resolver
        || tool.provenance.provider.is_empty()
        || tool.provenance.immutable_id.is_empty()
        || tool
            .verification
            .signature
            .as_ref()
            .is_some_and(|signature| signature.scheme.is_empty() || signature.identity.is_empty())
    {
        return Err(ToolLockError::InvalidTool {
            id: tool.id.clone(),
        });
    }
    validate_tool_provenance(tool)?;
    validate_tool_identity(tool)
}

fn validate_tool_provenance(tool: &LockedTool) -> Result<(), ToolLockError> {
    let provenance = &tool.provenance;
    let github = matches!(
        provenance.provider.as_str(),
        "github-release" | "gitlab-release"
    );
    let aqua = provenance.provider == "aqua";
    let npm = provenance.provider == "npm";
    let dotnet_tool = provenance.provider == "dotnet-tool";
    let go_module = provenance.provider == "go-module";
    let ruby_gems = provenance.provider == "ruby-gems";
    let cargo = provenance.provider == "cargo";
    let cargo_evidence = cargo
        && provenance
            .registry_endpoint
            .as_deref()
            .is_some_and(super::is_canonical_https_url)
        && provenance
            .package
            .as_ref()
            .is_some_and(|package| valid_cargo_name(package));
    let aqua_evidence = provenance.registry_endpoint.is_some()
        && provenance
            .registry_revision
            .as_deref()
            .is_some_and(is_registry_revision)
        && provenance.manifest_sha256.as_deref().is_some_and(is_sha256)
        && provenance
            .package
            .as_ref()
            .is_some_and(|package| !package.is_empty());
    let npm_evidence = npm && has_npm_evidence(provenance);
    let dotnet_tool_evidence = dotnet_tool && has_dotnet_tool_evidence(provenance);
    let go_module_evidence = go_module && has_go_module_evidence(provenance);
    let ruby_gems_evidence = ruby_gems && has_ruby_gems_evidence(provenance);
    let invalid = github
        != (provenance.repository.is_some()
            && provenance.release_id.is_some()
            && provenance.asset_id.is_some())
        || aqua != aqua_evidence
        || npm != npm_evidence
        || dotnet_tool != dotnet_tool_evidence
        || go_module != go_module_evidence
        || ruby_gems != ruby_gems_evidence
        || cargo != cargo_evidence
        || (!aqua
            && !npm
            && !dotnet_tool
            && !go_module
            && !ruby_gems
            && !cargo
            && (provenance.registry_endpoint.is_some()
                || provenance.registry_revision.is_some()
                || provenance.manifest_sha256.is_some()
                || provenance.package.is_some()))
        || (!npm
            && !dotnet_tool
            && !go_module
            && !ruby_gems
            && !cargo
            && provenance.registry_integrity.is_some())
        || (!github
            && !aqua
            && !npm
            && !dotnet_tool
            && !go_module
            && !ruby_gems
            && !cargo
            && (provenance.repository.is_some()
                || provenance.release_id.is_some()
                || provenance.asset_id.is_some()
                || provenance.immutable_id != tool.url));
    if invalid {
        return Err(ToolLockError::InvalidTool {
            id: tool.id.clone(),
        });
    }
    Ok(())
}

fn validate_tool_identity(tool: &LockedTool) -> Result<(), ToolLockError> {
    if canonicalize_url(&tool.url).as_deref() != Ok(tool.url.as_str())
        || tool.id.is_empty()
        || tool.resolved_version.is_empty()
        || tool.binaries.is_empty()
        || tool
            .binaries
            .iter()
            .any(|binary| !is_safe_binary_name(binary))
        || tool.declaration_source.path.is_empty()
        || tool.declaration_source.line == 0
    {
        return Err(ToolLockError::InvalidTool {
            id: tool.id.clone(),
        });
    }
    Ok(())
}

fn has_npm_evidence(provenance: &ToolProvenance) -> bool {
    provenance.registry_endpoint.is_some()
        && provenance
            .package
            .as_ref()
            .is_some_and(|package| !package.is_empty())
        && provenance
            .registry_integrity
            .as_ref()
            .is_some_and(|integrity| !integrity.is_empty())
}

fn has_dotnet_tool_evidence(provenance: &ToolProvenance) -> bool {
    provenance.registry_endpoint.is_some()
        && provenance
            .package
            .as_ref()
            .is_some_and(|package| is_valid_nuget_package(package))
        && provenance
            .registry_integrity
            .as_deref()
            .is_some_and(is_sha512_integrity)
        && provenance.immutable_id.starts_with("nuget:")
}

pub(super) fn has_go_module_evidence(provenance: &ToolProvenance) -> bool {
    provenance.registry_endpoint.is_some()
        && provenance
            .package
            .as_ref()
            .is_some_and(|module| is_valid_go_module(module))
        && provenance
            .registry_integrity
            .as_deref()
            .is_some_and(is_go_sum)
        && provenance.immutable_id.starts_with("go:")
}

fn has_ruby_gems_evidence(provenance: &ToolProvenance) -> bool {
    provenance.registry_endpoint.is_some()
        && provenance
            .package
            .as_ref()
            .is_some_and(|gem| is_valid_ruby_gem(gem))
        && provenance
            .registry_integrity
            .as_deref()
            .is_some_and(is_sha256)
        && provenance.immutable_id.starts_with("rubygems:")
}

fn is_valid_ruby_gem(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedTool {
    pub id: String,
    pub resolved_version: String,
    pub url: String,
    pub platform: Platform,
    pub sha256: String,
    pub provenance: ToolProvenance,
    pub verification: ArtifactVerification,
    pub binaries: Vec<String>,
    pub declaration_source: SourceSpan,
    pub resolver: String,
    /// Exact Rust toolchain identity for Cargo-backed entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_toolchain: Option<String>,
}

impl From<&PlannedTool> for LockedTool {
    fn from(tool: &PlannedTool) -> Self {
        Self {
            id: tool.id.clone(),
            resolved_version: tool.resolved_version.clone(),
            url: tool.url.clone(),
            platform: tool.platform.clone(),
            sha256: tool.sha256.clone(),
            provenance: tool.provenance.clone(),
            verification: tool.verification.clone(),
            binaries: tool.binaries.clone(),
            declaration_source: tool.declaration_source.clone(),
            resolver: tool.provenance.provider.clone(),
            cargo_toolchain: tool.cargo_toolchain.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolLockError {
    UnsupportedSchemaVersion { schema_version: u32 },
    DuplicateToolId { id: String },
    InvalidSha256 { id: String, sha256: String },
    InvalidTool { id: String },
    InvalidManagerLock,
    InvalidCargoBuild,
}

impl fmt::Display for ToolLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { schema_version } => write!(
                formatter,
                "unsupported tool lock schema version {schema_version}"
            ),
            Self::DuplicateToolId { id } => write!(formatter, "duplicate locked tool ID {id}"),
            Self::InvalidSha256 { id, sha256 } => {
                write!(formatter, "locked tool {id} has invalid SHA-256 {sha256}")
            }
            Self::InvalidTool { id } => {
                write!(formatter, "locked tool {id} is incomplete or invalid")
            }
            Self::InvalidManagerLock => formatter.write_str("manager lock graph is invalid"),
            Self::InvalidCargoBuild => formatter.write_str("Cargo build provenance is invalid"),
        }
    }
}

impl std::error::Error for ToolLockError {}

/// # Errors
///
/// Returns an error when a validated lock differs from the complete planned
/// declaration, including order and provenance.
pub fn verify_tool_plan(
    plan: &ToolPlan,
    lockfile: &ToolLockfile,
) -> Result<(), ToolVerificationError> {
    lockfile
        .validate()
        .map_err(ToolVerificationError::InvalidLock)?;
    if plan.tools.len() != lockfile.tools.len() {
        return Err(ToolVerificationError::DeclarationMismatch);
    }
    for (planned, locked) in plan.tools.iter().zip(&lockfile.tools) {
        if planned.id != locked.id
            || planned.resolved_version != locked.resolved_version
            || planned.binaries != locked.binaries
            || planned.cargo_toolchain != locked.cargo_toolchain
            || planned.declaration_source != locked.declaration_source
        {
            return Err(ToolVerificationError::DeclarationMismatch);
        }
        if planned.url != locked.url {
            return Err(ToolVerificationError::SourceMismatch {
                id: planned.id.clone(),
            });
        }
        if planned.platform != locked.platform {
            return Err(ToolVerificationError::PlatformMismatch {
                id: planned.id.clone(),
            });
        }
        if planned.sha256 != locked.sha256 {
            return Err(ToolVerificationError::ChecksumMismatch {
                id: planned.id.clone(),
            });
        }
        if planned.provenance != locked.provenance || planned.verification != locked.verification {
            return Err(ToolVerificationError::ProvenanceMismatch {
                id: planned.id.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ToolVerificationError {
    InvalidLock(ToolLockError),
    DeclarationMismatch,
    SourceMismatch { id: String },
    PlatformMismatch { id: String },
    ChecksumMismatch { id: String },
    ProvenanceMismatch { id: String },
}

impl fmt::Display for ToolVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLock(error) => error.fmt(formatter),
            Self::DeclarationMismatch => formatter.write_str("tool declarations differ from lock"),
            Self::SourceMismatch { id } => write!(formatter, "tool {id} source differs from lock"),
            Self::PlatformMismatch { id } => {
                write!(formatter, "tool {id} platform differs from lock")
            }
            Self::ChecksumMismatch { id } => {
                write!(formatter, "tool {id} SHA-256 differs from lock")
            }
            Self::ProvenanceMismatch { id } => {
                write!(formatter, "tool {id} provider provenance differs from lock")
            }
        }
    }
}

impl std::error::Error for ToolVerificationError {}

#[cfg(test)]
mod manager_lock_tests {
    use super::*;
    use crate::tools::STANDARD;
    use base64::Engine;

    fn fixture() -> ManagerLock {
        ManagerLock {
            schema_version: 1,
            manager: "pnpm".into(),
            manager_version: "9.0.0".into(),
            manager_sha256: "e".repeat(64),
            runtime_version: "bun 1.2.0".into(),
            runtime_archive: None,
            manifest_sha256: "a".repeat(64),
            lockfile_sha256: "b".repeat(64),
            script_policy: ScriptPolicy::Disabled,
            packages: vec![ManagerPackage {
                id: "pkg@1.0.0".into(),
                name: "pkg".into(),
                version: "1.0.0".into(),
                dependencies: vec![],
                tarball_url: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".into(),
                integrity: format!("sha512-{}", STANDARD.encode([7_u8; 64])),
                sha256: "c".repeat(64),
            }],
        }
    }

    #[test]
    fn manager_graph_serializes_round_trip_and_validates() {
        let graph = fixture();
        graph.validate().unwrap();
        let encoded = serde_json::to_string(&graph).unwrap();
        assert_eq!(
            serde_json::from_str::<ManagerLock>(&encoded).unwrap(),
            graph
        );
    }

    #[test]
    fn runtime_archive_provenance_round_trips_and_is_validated() {
        let mut graph = fixture();
        graph.runtime_archive = Some(ManagerRuntimeArchive {
            url: "https://example.test/bun.zip".into(),
            sha256: "d".repeat(64),
        });
        let encoded = serde_json::to_string(&graph).unwrap();
        let decoded: ManagerLock = serde_json::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, graph);
        graph.runtime_archive.as_mut().unwrap().url = "file:///tmp/bun.zip".into();
        assert_eq!(graph.validate(), Err(ToolLockError::InvalidManagerLock));
        graph.runtime_archive.as_mut().unwrap().url = "https://example.test/bun.zip".into();
        graph.runtime_archive.as_mut().unwrap().sha256 = "bad".into();
        assert_eq!(graph.validate(), Err(ToolLockError::InvalidManagerLock));
    }

    #[test]
    fn manager_sha256_schema_matches_runtime_lowercase_validation() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/schemas/manager-lock-v1.schema.json"
        ))
        .unwrap();
        let pattern = schema["$defs"]["sha256"]["pattern"].as_str().unwrap();
        let regex = regex::Regex::new(pattern).unwrap();
        for value in [
            "a".repeat(64),
            "0123456789abcdef".repeat(4),
            "A".repeat(64),
            "f".repeat(63),
            "g".repeat(64),
        ] {
            assert_eq!(regex.is_match(&value), is_sha256(&value), "{value}");
        }
    }

    #[test]
    fn legacy_tool_lock_without_nested_graph_remains_compatible() {
        let mut value =
            serde_json::to_value(ToolLockfile::from_plan(&ToolPlan::default())).unwrap();
        value.as_object_mut().unwrap().remove("manager_lock");
        let decoded: ToolLockfile = serde_json::from_value(value).unwrap();
        assert!(decoded.manager_lock.is_none());
        decoded.validate().unwrap();
    }

    #[test]
    fn manager_graph_rejects_duplicate_nodes_and_dangling_edges() {
        let mut graph = fixture();
        let mut duplicate_id = graph.packages[0].clone();
        duplicate_id.version = "2.0.0".into();
        graph.packages.push(duplicate_id);
        // These are structurally deserializable (and permitted by JSON Schema),
        // but violate the graph-wide unique-ID semantic invariant.
        let syntactic = serde_json::to_value(&graph).unwrap();
        let decoded: ManagerLock = serde_json::from_value(syntactic).unwrap();
        assert_eq!(decoded.validate(), Err(ToolLockError::InvalidManagerLock));

        let mut graph = fixture();
        graph.packages[0].dependencies.push("missing@1.0.0".into());
        let syntactic = serde_json::to_value(&graph).unwrap();
        let decoded: ManagerLock = serde_json::from_value(syntactic).unwrap();
        assert_eq!(decoded.validate(), Err(ToolLockError::InvalidManagerLock));
    }

    #[test]
    fn manager_graph_requires_well_formed_supported_sri_and_accepts_cycles() {
        let mut graph = fixture();
        graph.packages.push(ManagerPackage {
            id: "other@1.0.0".into(),
            name: "other".into(),
            version: "1.0.0".into(),
            dependencies: vec!["pkg@1.0.0".into()],
            tarball_url: "https://registry.npmjs.org/other/-/other-1.0.0.tgz".into(),
            integrity: format!("sha512-{}", STANDARD.encode([8_u8; 64])),
            sha256: "d".repeat(64),
        });
        graph.packages[0].dependencies.push("other@1.0.0".into());
        graph.packages[0].integrity = format!(
            "sha1-unsupported sha256-{} sha512-{}",
            STANDARD.encode([3_u8; 32]),
            STANDARD.encode([7_u8; 64])
        );
        graph.validate().unwrap();

        graph.packages[0].integrity = "sha1-unsupported".into();
        assert_eq!(graph.validate(), Err(ToolLockError::InvalidManagerLock));
        graph.packages[0].integrity = "sha512-not-base64!".into();
        assert_eq!(graph.validate(), Err(ToolLockError::InvalidManagerLock));
    }
}
