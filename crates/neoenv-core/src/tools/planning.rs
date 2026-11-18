//! Pure provider planning: declarations resolved to exact artifacts and
//! checksums with no network or filesystem access.

use super::{
    AquaRegistryManifest, ArtifactVerification, Engine, GithubReleaseAsset, GithubReleaseMetadata,
    HashSet, NpmRegistryPackage, PlannedTool, Platform, PlatformOverride, PlatformSelector,
    ProviderAuthPolicy, RubyGemsRegistryPackage, STANDARD, ToolDeclaration, ToolPlan,
    ToolPlanError, ToolProvenance, ToolProvider, Url, platform_arch_aliases, platform_os_aliases,
};
use regex::Regex;
use sha2::{Digest, Sha256};

/// Plans an exact Cargo registry archive using its registry-provided checksum.
///
/// This only creates immutable artifact provenance. It does not execute Cargo
/// or download the archive.
///
/// # Errors
///
/// Returns an error for an unsupported policy, invalid crate identity, mutable
/// version, non-canonical registry, unsafe binary list, or invalid checksum.
pub fn plan_cargo_crate(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<PlannedTool, ToolPlanError> {
    let cargo = declaration
        .cargo
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidCargo {
            id: declaration.id.clone(),
        })?;
    if declaration.provider != ToolProvider::Cargo
        || !is_valid_cargo_crate_name(&cargo.crate_name)
        || !is_exact_manager_version(&cargo.version)
        || declaration.version != cargo.version
        || declaration.url.is_some()
        || declaration.sha256.is_some()
        || !declaration.platforms.is_empty()
        || declaration.binaries.is_empty()
        || declaration
            .binaries
            .iter()
            .any(|binary| !is_safe_binary_name(binary))
        || cargo.scripts != super::CargoScriptPolicy::Deny
        || cargo.build != super::CargoBuildPolicy::Isolated
        || cargo.network != super::CargoNetworkPolicy::Deny
        || !is_sha256(&cargo.checksum)
    {
        return Err(ToolPlanError::InvalidCargo {
            id: declaration.id.clone(),
        });
    }
    let registry =
        canonical_http_url(&cargo.registry).map_err(|_| ToolPlanError::InvalidCargo {
            id: declaration.id.clone(),
        })?;
    if registry != cargo.registry || registry != "https://index.crates.io/" {
        return Err(ToolPlanError::InvalidCargo {
            id: declaration.id.clone(),
        });
    }
    let toolchain = cargo_toolchain_for_platform(&cargo.toolchain, platform).ok_or_else(|| {
        ToolPlanError::InvalidCargo {
            id: declaration.id.clone(),
        }
    })?;
    let crate_name = &cargo.crate_name;
    let version = &cargo.version;
    let url = format!("https://static.crates.io/crates/{crate_name}/{crate_name}-{version}.crate");
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: version.clone(),
        url: url.clone(),
        platform: platform.clone(),
        sha256: cargo.checksum.clone(),
        provenance: ToolProvenance {
            provider: "cargo".into(),
            immutable_id: url,
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(registry),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(crate_name.clone()),
            registry_integrity: None,
            declaration_sha256: None,
            authentication: ProviderAuthPolicy::Prohibited,
        },
        verification: ArtifactVerification {
            sha256: cargo.checksum.clone(),
            signature: None,
        },
        binaries: declaration.binaries.clone(),
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: Some(toolchain),
    })
}

/// Resolves a Cargo toolchain pin to an exact version/target for this platform.
///
/// A target-qualified pin is retained unchanged. Bare versions are rejected:
/// `Platform` does not identify libc ABI (notably GNU versus musl), so planning
/// cannot safely infer a Rust target from it.
#[must_use]
pub fn cargo_toolchain_for_platform(pin: &str, platform: &Platform) -> Option<String> {
    if !is_cargo_toolchain_pin(pin) {
        return None;
    }
    let _ = platform;
    pin.contains('-').then(|| pin.to_owned())
}

fn is_valid_cargo_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && name.bytes().any(|byte| byte.is_ascii_alphanumeric())
}

/// Plans one exact Go module ZIP after `go mod download` verified its declared
/// `go.sum` checksum. Building module source is deliberately outside planning.
///
/// # Errors
///
/// Returns an error for a mutable version, invalid proxy/source policy, checksum
/// evidence, unsafe binary declaration, or artifact digest.
pub fn plan_go_module(
    declaration: &ToolDeclaration,
    platform: &Platform,
    sha256: String,
    verified_go_sum: &str,
) -> Result<PlannedTool, ToolPlanError> {
    let go = declaration
        .go_module
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
    if declaration.provider != ToolProvider::GoModule
        || go.source != "go-proxy"
        || !is_exact_go_version(&declaration.version)
        || !is_valid_go_module(&go.module)
        || !is_go_sum(&go.go_sum)
        || go.go_sum != verified_go_sum
        || declaration.url.is_some()
        || declaration.sha256.is_some()
        || !declaration.platforms.is_empty()
        || declaration.binaries.is_empty()
        || declaration
            .binaries
            .iter()
            .any(|binary| !is_safe_binary_name(binary))
    {
        return Err(ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        });
    }
    if !is_sha256(&sha256) {
        return Err(ToolPlanError::InvalidSha256 {
            id: declaration.id.clone(),
            sha256,
        });
    }
    let endpoint =
        canonical_http_url(&go.endpoint).map_err(|_| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
    let url = format!(
        "{}/{}/@v/{}.zip",
        endpoint.trim_end_matches('/'),
        go_proxy_escape(&go.module),
        declaration.version
    );
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url,
        platform: platform.clone(),
        sha256: sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id: format!("go:{}@{}/sum:{}", go.module, declaration.version, go.go_sum),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(endpoint),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(go.module.clone()),
            registry_integrity: Some(go.go_sum.clone()),
            declaration_sha256: None,
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256,
            signature: None,
        },
        binaries: declaration.binaries.clone(),
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

/// Plans one exact .NET tool package after `NuGet`'s SHA-512 sidecar and package
/// bytes have been verified. Package URLs are derived from the declared v3
/// flat-container source; metadata cannot redirect the selected artifact.
///
/// # Errors
///
/// Returns an error for an invalid source policy, package identity, version,
/// digest, binary declaration, or endpoint.
pub fn plan_dotnet_tool(
    declaration: &ToolDeclaration,
    platform: &Platform,
    sha256: String,
    integrity: String,
) -> Result<PlannedTool, ToolPlanError> {
    let dotnet =
        declaration
            .dotnet_tool
            .as_ref()
            .ok_or_else(|| ToolPlanError::InvalidDotnetTool {
                id: declaration.id.clone(),
            })?;
    if declaration.provider != ToolProvider::DotnetTool
        || dotnet.source != "nuget-v3"
        || !is_exact_dotnet_version(&declaration.version)
        || !is_valid_nuget_package(&dotnet.package)
        || declaration.url.is_some()
        || declaration.sha256.is_some()
        || !declaration.platforms.is_empty()
        || declaration.binaries.is_empty()
        || declaration
            .binaries
            .iter()
            .any(|binary| !is_safe_binary_name(binary))
    {
        return Err(ToolPlanError::InvalidDotnetTool {
            id: declaration.id.clone(),
        });
    }
    if !is_sha256(&sha256) {
        return Err(ToolPlanError::InvalidSha256 {
            id: declaration.id.clone(),
            sha256,
        });
    }
    if !is_sha512_integrity(&integrity) {
        return Err(ToolPlanError::InvalidDotnetIntegrity {
            id: declaration.id.clone(),
        });
    }
    let endpoint =
        canonical_http_url(&dotnet.endpoint).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url,
        })?;
    let package = dotnet.package.to_ascii_lowercase();
    let version = declaration.version.to_ascii_lowercase();
    let url = format!(
        "{}/{package}/{version}/{package}.{version}.nupkg",
        endpoint.trim_end_matches('/')
    );
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url: url.clone(),
        platform: platform.clone(),
        sha256: sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id: format!("nuget:{package}/version:{version}/sha512:{integrity}"),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(endpoint),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(dotnet.package.clone()),
            registry_integrity: Some(integrity),
            declaration_sha256: None,
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256,
            signature: None,
        },
        binaries: declaration.binaries.clone(),
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

impl PartialEq for ToolPlanError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
            && std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for ToolPlanError {}

impl std::error::Error for ToolPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProviderSource { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// # Errors
///
/// Returns an error for duplicate IDs, ambiguous or missing platform assets, or
/// non-URL/non-SHA-256 declarations.
pub fn plan_tools(
    declarations: &[ToolDeclaration],
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let mut ids = HashSet::with_capacity(declarations.len());
    let mut tools = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        if !ids.insert(declaration.id.as_str()) {
            return Err(ToolPlanError::DuplicateToolId {
                id: declaration.id.clone(),
            });
        }
        if !matches!(declaration.provider, ToolProvider::ExplicitUrl) {
            return Err(ToolPlanError::UnsupportedProvider {
                id: declaration.id.clone(),
                provider: declaration.provider.name().into(),
            });
        }
        // Here, not only in the release planners: the same three keys are readable
        // on a native declaration, and without this a native file setting
        // `binpath` installed the archive-root binary while reporting success.
        reject_binary_layout(declaration)?;
        let selected = select_platform_override(declaration, platform)?;
        let url = selected
            .and_then(|value| value.url.clone())
            .or_else(|| declaration.url.clone())
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            })?;
        let sha256 = selected
            .and_then(|value| value.sha256.clone())
            .or_else(|| declaration.sha256.clone())
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            })?;
        let binaries = selected
            .and_then(|value| value.binaries.clone())
            .unwrap_or_else(|| declaration.binaries.clone());
        let url = canonicalize_url(&url).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url: url.clone(),
        })?;
        if !is_sha256(&sha256) {
            return Err(ToolPlanError::InvalidSha256 {
                id: declaration.id.clone(),
                sha256,
            });
        }
        if binaries.is_empty() || binaries.iter().any(String::is_empty) {
            return Err(ToolPlanError::EmptyBinaries {
                id: declaration.id.clone(),
            });
        }
        tools.push(PlannedTool {
            id: declaration.id.clone(),
            resolved_version: declaration.version.clone(),
            url: url.clone(),
            platform: platform.clone(),
            sha256: sha256.clone(),
            provenance: ToolProvenance {
                provider: declaration.provider.name().into(),
                immutable_id: url.clone(),
                repository: None,
                release_id: None,
                asset_id: None,
                registry_endpoint: None,
                registry_revision: None,
                manifest_sha256: None,
                package: None,
                registry_integrity: None,
                declaration_sha256: None,
                authentication: declaration.provider.authentication_policy(),
            },
            verification: ArtifactVerification {
                sha256: sha256.clone(),
                signature: None,
            },
            binaries,
            declaration_source: declaration.declaration_source.clone(),
            cargo_toolchain: None,
        });
    }
    Ok(ToolPlan { tools })
}

/// Plans one npm tarball after its registry metadata and SRI digest have been verified.
///
/// # Errors
///
/// Returns an error when package metadata, bin paths, URLs, or the derived
/// artifact SHA-256 do not satisfy the npm provider contract.
pub fn plan_npm_registry(
    declaration: &ToolDeclaration,
    platform: &Platform,
    package: &NpmRegistryPackage,
    sha256: String,
) -> Result<PlannedTool, ToolPlanError> {
    let npm = declaration
        .npm
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        })?;
    if let Some(manager) = &npm.manager {
        if !is_exact_manager_version(&manager.version) {
            return Err(ToolPlanError::InvalidNpmManagerVersion {
                id: declaration.id.clone(),
                version: manager.version.clone(),
            });
        }
        let name = match manager.name {
            super::NpmManagerName::Bun => "bun",
            super::NpmManagerName::Pnpm => "pnpm",
        };
        return Err(ToolPlanError::UnsupportedProvider {
            id: declaration.id.clone(),
            provider: format!(
                "{name}@{} manager installation is not implemented; refusing direct-tarball fallback",
                manager.version
            ),
        });
    }
    if declaration.provider != ToolProvider::Npm
        || !is_exact_npm_version(&declaration.version)
        || package.package != npm.package
        || package.version != declaration.version
        || package.binaries.is_empty()
        || package
            .binaries
            .iter()
            .any(|bin| !is_safe_binary_name(&bin.name) || !is_safe_npm_bin_path(&bin.path))
    {
        return Err(ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        });
    }
    if !is_sha256(&sha256) {
        return Err(ToolPlanError::InvalidSha256 {
            id: declaration.id.clone(),
            sha256,
        });
    }
    let endpoint =
        canonical_http_url(&npm.endpoint).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url,
        })?;
    let url =
        canonical_http_url(&package.tarball).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url,
        })?;
    if package.integrity.is_empty() {
        return Err(ToolPlanError::InvalidNpmIntegrity {
            id: declaration.id.clone(),
        });
    }
    let binaries: Vec<String> = package
        .binaries
        .iter()
        .map(|bin| bin.name.clone())
        .collect();
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url: url.clone(),
        platform: platform.clone(),
        sha256: sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id: format!(
                "npm:{}/version:{}/integrity:{}",
                npm.package, package.version, package.integrity
            ),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(endpoint),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(npm.package.clone()),
            registry_integrity: Some(package.integrity.clone()),
            declaration_sha256: None,
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256,
            signature: None,
        },
        binaries,
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

/// Plans a `RubyGems` archive after the registry's mandatory archive SHA-256 was
/// checked against the downloaded bytes.
///
/// # Errors
///
/// Returns an error for invalid declaration, registry, package identity, or
/// archive digest facts.
pub fn plan_ruby_gems(
    declaration: &ToolDeclaration,
    platform: &Platform,
    package: &RubyGemsRegistryPackage,
) -> Result<PlannedTool, ToolPlanError> {
    let ruby = declaration
        .ruby_gems
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        })?;
    if declaration.provider != ToolProvider::RubyGems
        || !is_exact_dotnet_version(&declaration.version)
        || package.gem != ruby.gem
        || package.version != declaration.version
        || package.platform != "ruby"
        || declaration.url.is_some()
        || declaration.sha256.is_some()
        || !declaration.platforms.is_empty()
        || declaration.binaries.is_empty()
        || declaration
            .binaries
            .iter()
            .any(|binary| !is_safe_binary_name(binary))
        || !is_sha256(&package.sha256)
    {
        return Err(ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        });
    }
    let endpoint =
        canonical_http_url(&ruby.endpoint).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url,
        })?;
    let url = format!(
        "{}/gems/{}-{}.gem",
        endpoint.trim_end_matches('/'),
        ruby.gem,
        declaration.version
    );
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url,
        platform: platform.clone(),
        sha256: package.sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id: format!(
                "rubygems:{}/version:{}/sha256:{}",
                ruby.gem, package.version, package.sha256
            ),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(endpoint),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(ruby.gem.clone()),
            registry_integrity: Some(package.sha256.clone()),
            declaration_sha256: None,
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256: package.sha256.clone(),
            signature: None,
        },
        binaries: declaration.binaries.clone(),
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

/// Resolves verified Aqua registry metadata into a locked artifact without I/O.
///
/// # Errors
///
/// Returns an error for mutable registry inputs, an invalid manifest, ambiguous
/// platform assets, or an absent/invalid artifact checksum.
pub fn plan_aqua_registry(
    declaration: &ToolDeclaration,
    platform: &Platform,
    manifest: &AquaRegistryManifest,
) -> Result<PlannedTool, ToolPlanError> {
    let aqua = declaration
        .aqua
        .as_ref()
        .ok_or_else(|| ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        })?;
    if declaration.provider != ToolProvider::Aqua
        || !is_registry_revision(&aqua.registry_revision)
        || !is_sha256(&aqua.manifest_sha256)
        || aqua.package.is_empty()
        || manifest.package != aqua.package
    {
        return Err(ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        });
    }
    let assets: Vec<_> = manifest
        .assets
        .iter()
        .filter(|asset| asset.version == declaration.version && asset.platform == *platform)
        .collect();
    let asset = match assets.as_slice() {
        [asset] => *asset,
        [] => {
            return Err(ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            });
        }
        _ => {
            return Err(ToolPlanError::AmbiguousAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            });
        }
    };
    if !is_sha256(&asset.sha256) {
        return Err(ToolPlanError::InvalidSha256 {
            id: declaration.id.clone(),
            sha256: asset.sha256.clone(),
        });
    }
    if declaration.binaries.is_empty() || declaration.binaries.iter().any(String::is_empty) {
        return Err(ToolPlanError::EmptyBinaries {
            id: declaration.id.clone(),
        });
    }
    let endpoint =
        canonical_http_url(&aqua.endpoint).map_err(|url| ToolPlanError::UnsupportedUrl {
            id: declaration.id.clone(),
            url,
        })?;
    let url = canonical_http_url(&asset.url).map_err(|url| ToolPlanError::UnsupportedUrl {
        id: declaration.id.clone(),
        url,
    })?;
    let immutable_id = format!(
        "registry:{}/manifest:{}/package:{}/version:{}/platform:{}/{}",
        aqua.registry_revision,
        aqua.manifest_sha256,
        aqua.package,
        declaration.version,
        platform.os,
        platform.arch
    );
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url,
        platform: platform.clone(),
        sha256: asset.sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id,
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some(endpoint),
            registry_revision: Some(aqua.registry_revision.clone()),
            manifest_sha256: Some(aqua.manifest_sha256.clone()),
            package: Some(aqua.package.clone()),
            registry_integrity: None,
            declaration_sha256: None,
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256: asset.sha256.clone(),
            signature: None,
        },
        binaries: declaration.binaries.clone(),
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

/// Resolves GitHub API metadata into a locked artifact without performing I/O.
///
/// # Errors
///
/// Returns an error when the release tag, selected asset, checksum, URL, or
/// binaries do not satisfy the declaration.
/// Refuses a declaration whose binary layout this model cannot honor.
///
/// `binpath` and `bindir` name a location inside the artifact, and the
/// extractors place a tool's whole binary list at the archive root. Refusing
/// here rather than carrying the key silently means a Go file that uses one
/// fails with a message that says what to do instead, rather than installing
/// successfully and putting the wrong thing on `PATH`.
///
/// # Errors
///
/// Returns `ToolPlanError::UnsupportedBinaryLayout` naming the key.
pub fn reject_binary_layout(declaration: &ToolDeclaration) -> Result<(), ToolPlanError> {
    let refuse = |present: bool, key: &str| {
        present.then(|| ToolPlanError::UnsupportedBinaryLayout {
            id: declaration.id.clone(),
            key: key.to_owned(),
        })
    };
    if let Some(error) = refuse(declaration.binpath.is_some(), "binpath")
        .or_else(|| refuse(declaration.bindir.is_some(), "bindir"))
    {
        return Err(error);
    }
    // Per-platform too. An earlier version checked only the declaration's own
    // keys, so `linux-amd64: {binpath: "dist/cli"}` was read into the override
    // and then read by nothing: the plan succeeded, the archive-root binary was
    // installed, and no diagnostic fired. That is the exact outcome the refusal
    // exists to prevent, reached one level down.
    for override_ in &declaration.platforms {
        if let Some(error) = refuse(override_.binpath.is_some(), "binpath")
            .or_else(|| refuse(override_.bindir.is_some(), "bindir"))
        {
            return Err(error);
        }
    }
    Ok(())
}

/// Whether a release asset name is an archive whose internal paths are
/// preserved by the extractors.
///
/// Kept here rather than in the installer so planning and installation agree
/// before any bytes are fetched. It is deliberately a suffix test on the
/// publisher's name, not a content sniff.
pub fn is_archive_asset_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz", ".tbz2", ".tar.zst", ".zip",
        ".tar",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

/// Selects the release asset for a declaration on `platform`.
///
/// Shared by the planner and the installer's provider so the two cannot drift:
/// they used to carry separate copies of this rule, and a divergence would mean
/// `tool plan` naming one artifact and `tool install` fetching another.
///
/// With a declared selector, every matching asset is considered. More than one
/// match is refused rather than choosing based on provider response order.
///
/// # Errors
///
/// Returns `ToolPlanError::InvalidGrepPattern` when a `grep` pattern does not
/// compile, `ToolPlanError::AmbiguousAsset` when multiple assets match, and
/// `ToolPlanError::AssetSelection` when nothing matches.
pub fn select_github_asset<'a>(
    assets: &'a [GithubReleaseAsset],
    declaration_asset: Option<&str>,
    grep: Option<&str>,
    platform: &Platform,
    id: &str,
) -> Result<&'a GithubReleaseAsset, ToolPlanError> {
    let pattern = grep
        .map(|pattern| {
            Regex::new(pattern).map_err(|error| ToolPlanError::InvalidGrepPattern {
                id: id.to_owned(),
                pattern: pattern.to_owned(),
                reason: error.to_string(),
            })
        })
        .transpose()?;
    // `grep` selects from artifacts, never from a checksum sidecar. A pattern
    // alone is an explicit selector, so it does not also require the platform
    // predicate: the file named the artifact class the user wants.
    let matches = |name: &str| {
        pattern.as_ref().is_none_or(|pattern| {
            pattern.is_match(name) && (grep.is_none() || is_release_artifact(name))
        })
    };
    let matches_asset = |asset: &&GithubReleaseAsset| {
        let name = asset.name.as_str();
        if !matches(name) {
            return false;
        }
        match declaration_asset {
            // A template, when the name carries placeholders. A native declaration
            // writes `tool-{os}-{arch}.tar.gz` and expects the platform's own names
            // substituted.
            //
            // A pattern that is *both* a template and a glob keeps its wildcards:
            // `cli-*-{arch}*.zip` has placeholders, and taking the template arm alone
            // substituted them into `cli-*-x86_64*.zip` and then compared for exact
            // equality, which cannot succeed -- a `MissingAsset` whose message did
            // not echo the pattern the user wrote.
            Some(template) if template.contains("{os}") || template.contains("{arch}") => {
                asset_names_for(template, platform).iter().any(|candidate| {
                    if candidate.contains('*') || candidate.contains('?') {
                        glob_matches(candidate, name)
                    } else {
                        candidate == name
                    }
                })
            }
            // A glob, when it does not. The reference's `asset` is a glob
            // (`selectAssetByGlob`, `release.go:246`) and `cli-*-linux.tar.gz` is a
            // perfectly ordinary Go declaration; matching it exactly failed closed
            // with `MissingAsset` and a list of assets that look like they match.
            Some(pattern) if pattern.contains('*') || pattern.contains('?') => {
                glob_matches(pattern, name)
            }
            // Neither: an exact name, which is what a native declaration with a
            // literal asset has always meant.
            Some(name) => name == asset.name,
            // Only an artifact is eligible, and the *whole* platform predicate is this
            // function's, shared with the installer's `github_asset_matches_host`. The
            // two branches used to carry one filter each and they disagreed three ways:
            // `tool plan` named a checksum sidecar while `tool install --global` named
            // the archive, `mac` was missing from the installer's alias list, and the
            // architecture lists treated `arm` and `x86` differently. Sharing only the
            // artifact half left the same defect in the other two quarters.
            None => is_release_artifact(name) && asset_matches_platform(name, platform),
        }
    };
    let selected: Vec<_> = assets.iter().filter(matches_asset).collect();
    match selected.as_slice() {
        [asset] => return Ok(*asset),
        [] => {}
        _ if declaration_asset.is_some() || grep.is_some() => {
            return Err(ToolPlanError::AmbiguousAsset {
                id: id.to_owned(),
                platform: platform.clone(),
            });
        }
        _ => return Ok(selected[0]),
    }
    // **`AssetSelection`, not `MissingAsset`, when nothing matched a *pattern* or
    // the platform default.** `MissingAsset` renders as "tool X has no asset for
    // os/arch" and stops there, and this function is the *only* diagnostic a
    // project-pinned `gh:` key and `tool plan` ever produce. So a release that
    // publishes `tool_linux_x86.tar.gz` and `tool_linux_x86_64.tar.gz` on a 32-bit
    // host said only "has no asset for linux/x86" -- no list, and no hint that the
    // refusal is deliberate.
    //
    // It is deliberate: plain `x86` is a substring of `x86_64`, so matching it would
    // let a 32-bit host accept a 64-bit archive. The user deserves to see the
    // candidates and the way out, and `AssetSelection` already renders both -- it is
    // the type the global path has always used for this.
    let mut names: Vec<String> = assets.iter().map(|asset| asset.name.clone()).collect();
    names.sort();
    names.dedup();
    // **The advice depends on whether the user already declared `asset:`, and each
    // case says what to do.** A single message for both said "declare `asset:` with
    // the one to install" to someone who had just written
    // `asset: demo_linux_amd64.zip` -- an instruction that contradicts itself and,
    // worse, never named the value they wrote. The reference keeps the same
    // distinction (`tools/release.go` emits a separate message for a pattern miss
    // from the platform miss), and so does this.
    //
    // The declared value is echoed with `{declared:?}`, not `{declared}`. `AssetSelection`
    // renders `reason` verbatim, and `asset:` is read from a checked-in project file
    // with no charset or length validation, so a raw echo lets a committed config
    // carry newlines and ANSI escapes into a teammate's terminal. The neighbouring
    // `InvalidGrepPattern` arm already uses `{pattern:?}` for the same reason.
    //
    // The platform is *not* repeated: `AssetSelection`'s `Display` already prints
    // `cannot select a GitHub asset for {os}/{arch}:`.
    let reason = match (grep, declaration_asset.filter(|name| !name.is_empty())) {
        (Some(pattern), _) => format!(
            "no release asset matched the `grep` pattern {pattern:?}; correct it, or remove it \
             to select by platform"
        ),
        (None, Some(declared)) => format!(
            "no release asset matched the declared `asset: {declared:?}`; correct it, or \
             remove it to select by platform"
        ),
        (None, None) => {
            "no release asset matched this platform; declare `asset:` with the one to install"
                .to_owned()
        }
    };
    Err(ToolPlanError::AssetSelection {
        id: id.to_owned(),
        platform: platform.clone(),
        reason,
        assets: names,
    })
}

/// The kinds of file a release publishes *beside* its artifact, by the extension
/// that names them.
///
/// **A list of sidecar kinds, not a list of substrings, and not a test for
/// "has an extension".** Both of the earlier attempts at this rule failed, and
/// they failed in opposite directions at once:
///
/// - Substring-anywhere (`sbom`, `sha256`, `checksum`) missed the two SBOM
///   extensions `GoReleaser` actually emits -- `foo_linux_amd64.spdx.json` and
///   `.cdx.json`, neither of which contains `sbom` -- while matching a tool
///   genuinely called `sbomctl` anywhere in its name.
/// - "Reject anything whose last segment looks like an extension" fixed the miss
///   and broke the *artifact* instead: `foo-linux-amd64-1.0.0` ends in `0`, which
///   is extension-shaped, so a versioned binary name was refused. That argument
///   only works when a dash or underscore follows the version, which is not a
///   property anyone controls.
///
/// So the rule is narrow in the direction that matters: a sidecar is recognized by
/// its *last extension* naming a kind of file that is not the artifact. An
/// unrecognized extension is the artifact -- a release publishing `tool.deb`,
/// `tool.pyz`, or `tool.dat` resolves, which none of the earlier versions did.
///
/// The reference has no such filter at all: `selectAssetByPlatform`
/// (`tools/release.go:262`) takes the first name that matches, sidecar or not. So
/// this is a **deliberate divergence in the safe direction**, named as one rather
/// than presented as parity -- the reference will hand a user a `.sha256` file, and
/// this will hand them a diagnostic listing what it could use instead.
pub const SIDECAR_EXTENSIONS: &[&str] = &[
    // Digests.
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    // The SHA-3 family. Present because `DIGEST_ALGORITHMS` carries it and the
    // cross-table test is right that a name must not be a sidecar by one rule and
    // the artifact by the other: `foo.sha3` is a real convention and without this
    // the extension rule called it the artifact.
    "sha3",
    "sha3-256",
    "sha3-512",
    "md5",
    "blake2",
    "blake3",
    "digest",
    // Signatures and attestations.
    "sig",
    "asc",
    "minisig",
    // The GnuPG spellings. `gpg` and `gpgasc` are the two extensions
    // `goreleaser`'s `signs.artifacts` and Debian's `debsign` emit for a detached
    // signature, and they are the *same kind of file* as `asc` and `sig`, which are
    // both listed. Their absence was the same regression class as `sum`: the whole
    // family was present except for the two spellings a Linux packager actually
    // uses, so `foo_1.2.3_linux_amd64.tar.gz.gpg` -- a detached signature that
    // matches linux and amd64 in its prefix -- was installable as the program.
    "gpg",
    "gpgasc",
    "p7s",
    "pem",
    "cer",
    "crt",
    "cert",
    // `checksum` as a bare last extension. `foo_linux_amd64.checksums` was
    // classified as the artifact while `foo_linux_amd64.checksums.txt` was not --
    // the same manifest under two spellings, two answers, which is the defect shape
    // this file keeps producing. `checksums.txt` is already caught by `txt`; the
    // extensionless spelling was the half that was missing.
    "checksum",
    "checksums",
    // A single-segment SBOM. See the note above: `anchore/syft` publishes
    // `syft_<version>_<os>_<arch>.sbom` for every platform of every release, and
    // that name satisfies the platform predicate on its prefix. In the release
    // current when this row was added, `syft_1.52.0_darwin_arm64.sbom` is listed
    // *before* `syft_1.52.0_darwin_arm64.tar.gz`, so with the entry missing
    // first-match selection installed the SBOM on every platform.
    "sbom",
    // **A binary patch.** `denoland/deno` publishes
    // `deno-x86_64-unknown-linux-gnu.from-2.9.6.bsdiff` -- a *delta* between two
    // releases, not the program -- and it is listed ahead of the `.zip` in upload
    // order, so first-match selection installed the patch and reported success.
    // Found by the same scan that found `sbom`, and the same defect: a sidecar
    // whose name carries the platform.
    "bsdiff",
    // **A provenance proof.** `FiloSottile/age` publishes
    // `age-v1.3.2-linux-amd64.tar.gz.proof` for every platform -- nine of them.
    // Not currently exploitable, because age uploads the archive first, but
    // `select_github_asset` is first-match with *no ordering guarantee*, so
    // reordering those two assets is all it takes. `.proof` is a suffix, not a
    // format with a second extension, so no other entry covers it.
    "proof",
    // **An electron-updater channel manifest.** `logseq/logseq` publishes
    // `latest-linux-arm64.yml`, `latest-x64-mac.yml`, and six siblings, and lists
    // them **first** -- ahead of every program in the release. `is_release_artifact`
    // said `yml` was the artifact, the name carries `linux`/`arm64` in its prefix, so
    // the whole platform predicate passed and `gh:logseq/logseq` installed an updater
    // manifest as the program and reported success.
    //
    // mise does not classify `.yml` as a checksum either, so this is a *shared* gap
    // rather than a parity loss -- which makes it more urgent, not less, because
    // nothing upstream will catch it. `yaml` is the same family and does not happen
    // to carry a platform token today.
    //
    // A YAML sidecar in general: `.goreleaser.yaml` is a config, not a digest, and
    // this list is a list of sidecar *kinds*, not of digests.
    "yml",
    "yaml",
    // **A `b2` digest and an IPFS CID.** `watchexec/watchexec` publishes `B3SUMS`
    // plus 160 per-file `*.b3` digests; `ipfs/kubo` publishes 46 `*.cid`. Both
    // classify every one as the artifact today. Not exploitable *yet* -- the archive
    // is listed first in both releases -- and that is exactly the "one reordering
    // away" argument that added `proof`.
    "b3",
    "cid",
    // **A per-file digest in the `shasum` spelling.** `minio/mc` publishes 54
    // `*.shasum` files, one per platform, each carrying linux/darwin and
    // amd64/arm64 in its prefix. A test row asserted the opposite -- that
    // `tool_linux_amd64.shasum` is the artifact -- on the reasoning that `shasum` is
    // a coreutils *program* and so its name is not a manifest. Both are true and they
    // are different claims: `shasum` alone is a program, and `foo_linux_amd64.shasum`
    // is a digest. The row was testing the first with a name for the second.
    "shasum",
    // **The extensionless plural, `shasums`, is NOT here** — `sha` in
    // `DIGEST_ALGORITHMS` plus the `<algorithm>sums` shape already catch it, and a
    // first attempt at this entry was removed because mutating it out left every
    // test green. It is the only digest in `containers/podman`'s release (nine
    // assets, and this one), and both halves used to call it a program, so the
    // install was refused with `shasums` *listed as available* in the same message
    // that said it was not there.
    //
    // What was missing was the *algorithm*, not the extension: `shasum` was only in
    // this table as a dotted form, and the shape rule needs an algorithm token.
    // mise's `CHECKSUM_PATTERNS` carries `(?i)^SHASUMS` as a prefix match, so that
    // was a **parity loss**, not a shared gap -- which is worth distinguishing from
    // `.yml`, where mise also has nothing. The row in the test table carries the
    // name either way, which is what a table row should do: name the *behavior*,
    // not the table that implements it.
    // **A BLAKE2b and a SHA3-512 digest**, uppercase with an underscore.
    // `saltstack/salt` publishes `salt-<v>-onedir-linux-<arch>.tar.xz.BLAKE2B` and
    // the same name in `.SHA3_512`, for every platform of every release -- six real
    // names. `SHA512` was already covered and these two were not, so a release that
    // uploaded the digest before the archive would install the digest.
    "blake2b",
    "sha3_512",
    // `sha3_256` is **not** published in that spelling by anything in the corpus, and
    // removing it fails no test. It stays because the burden of proof in *this*
    // table runs one way: a missing sidecar kind installs the wrong file, an extra
    // one costs a string. What it does not get is to be free -- hence the row in
    // the test table below, so the entry is a decision rather than a leftover.
    "sha3_256",
    // **An electron-updater chunk-hash manifest.** `logseq/logseq` publishes
    // `Logseq-darwin-arm64-2.0.1.dmg.blockmap`, and in the release current when this
    // row was added that name is asset **10** against the real `.dmg` at **12** -- so
    // first-match selection installed a blockmap and reported success, in the *same
    // release* whose `.yml` the previous commit fixed.
    //
    // It was originally added to the installer's `is_signature_kind` instead, which is
    // the *digest* classifier. The wrong-install direction is the one that had to be
    // closed, and only the artifact table closes it. Recorded because putting a
    // sidecar kind in the wrong one of two adjacent tables is invisible to every
    // test that does not simulate first-match selection.
    "blockmap",
    "pub",
    "sigstore",
    "attestation",
    // **`sbom` is here because a real release publishes the single-segment form,
    // and an earlier version of this file deleted it on bad evidence.**
    //
    // It was deleted because mutation-testing its removal failed no test. That
    // inference was circular: *a member with no test row is exactly what "no
    // failing test" measures.* The correct reading of that mutation was "the table
    // is missing a row for `foo_linux_amd64.sbom`", not "the entry is dead". The
    // review checked `anchore/syft` against the live API and found
    // `syft_1.52.0_linux_amd64.sbom`, `syft_1.52.0_darwin_arm64.sbom`, and one per
    // platform for **every** release. Those names carry `linux`/`darwin` and
    // `amd64`/`arm64` in their prefix, so they satisfy the whole platform
    // predicate: with the entry deleted, `gh:anchore/syft` on macOS resolved the
    // SBOM as the program and reported success. Reverted, and the row below now
    // carries a real asset name rather than an invented one.
    //
    // **`intoto`, `spdx`, `cdx`, and `cyclonedx` are NOT here**, and the evidence
    // is a scan of specific releases rather than a mutation: the latest
    // `goreleaser/goreleaser`, `sigstore/cosign`, `aquasecurity/trivy`, and
    // `sigstore/fulcio` release assets end in `.apk .deb .gz .json .pub .rpm .txt
    // .exe .yaml .zip .zst` and contain no single-segment `.spdx`, `.cdx`,
    // `.cyclonedx`, or `.intoto`. Those formats ride on a second extension
    // (`foo_linux_amd64.spdx.json` ends in `json`, `foo.intoto.jsonl` in `jsonl`),
    // so the second extension is the discriminator and the format name is a
    // red herring. Re-run the scan before re-adding one of the four.
    //
    // The general rule, and note the **asymmetry** that the `sbom` episode makes
    // worth stating: *list a segment only if some real release publishes a sidecar
    // whose last segment is that word.* Keeping an entry no release needs costs
    // nothing; removing one a release does need installs the wrong file silently.
    // So the burden of proof is on removal, and a mutation is not proof.
    //
    // Manifests. `json` covers `foo_linux_amd64.spdx.json`; the SBOM's licence
    // sibling needs `csv`, because `GoReleaser`'s `licenses` type emits
    // `{{ .ArtifactName }}.licenses.csv` next to the archive and the prefix carries
    // the platform.
    "json",
    "jsonl",
    "txt",
    "text",
    "csv",
    "sha",
];

/// Extensions that make a name a *program or a package*, whatever else it contains.
///
/// **Consulted by the installer's digest classifier, and by nothing in this file --
/// deliberately, and a mutation is what established it.** A name ending in
/// `.tar.gz`, `.deb`, or `.zip` is the program, and no amount of an algorithm or a
/// `checksum` token in the prefix makes it a manifest.
///
/// It took three attempts at the installer's classifier to arrive here, because
/// each attempt tried to settle the question from the *name*:
///
/// - `blake3_linux_x86_64.tar.gz`, `md5_linux_amd64.tar.gz`, and
///   `checksum_linux_amd64.tar.gz` are all real program archives whose names
///   contain a digest word, and a token test called every one of them a digest. The
///   caller's exactly-one rule then refused the install while offering another
///   platform's archive as a checksum candidate.
///
/// The fix is structural rather than another name to avoid, and it is *asymmetric on
/// purpose*: a packaging extension missing from this list would let a program be
/// called a digest, which is a refusal the user can act on, while a manifest with a
/// packaging extension does not occur. So the list is deliberately generous and the
/// cost of a wrong entry is the cheap direction.
///
/// The planner's `is_release_artifact` does **not** use this list, and adding the
/// guard there was tried and removed: it was dead, because no member of
/// `SIDECAR_EXTENSIONS` is a packaging extension and no packaging name ends in
/// `sum`/`sums`. Two rules over the same names need not need the same guard, and
/// carrying an unexercised one for symmetry is how dead code survives a rewrite.
pub const PROGRAM_EXTENSIONS: &[&str] = &[
    "gz", "tgz", "bz2", "xz", "zst", "zip", "7z", "rar", "tar", "deb", "rpm", "apk", "msi", "pkg",
    "dmg", "exe", "msix", "appimage", "jar", "war", "whl", "gem", "egg", "pyz", "crate", "nupkg",
    "so", "dylib", "dll", "a", "lib", "bin", "run", "sh",
];

/// Whether a release asset is a *package* — a distribution format that cannot
/// become a runnable binary through this project's extractors — rather than the
/// program itself.
///
/// **This is the largest wrong-install class in the project, and it was invisible
/// because every test agreed with it.** `cli/cli` v2.101.0 lists
/// `gh_2.101.0_linux_amd64.deb` at asset **4** and the real
/// `gh_2.101.0_linux_amd64.tar.gz` at asset **6**. First-match selection took the
/// `.deb`; `ArtifactPlan` matched no archive suffix and fell through to
/// `RawBinary`; `extract_raw_binary` copied the `ar` blob to `bin/gh`, marked it
/// executable, and the install **reported success**. The user got a working
/// install of a file that cannot execute. Across 100 repositories this produced
/// **1,120** asset names no extractor can open, and 84 (release, platform)
/// selections that picked a package over a real archive — `anchore/syft`,
/// `aquasecurity/trivy`, `caddyserver/caddy`, `containers/podman`, `gohugoio/hugo`,
/// `neovim/neovim`, `ollama/ollama`, `rclone/rclone`, `sharkdp/bat`, and others.
///
/// Three test rows **pinned the behavior**, under a comment claiming the opposite
/// ("an unrecognized extension is the artifact, which is what makes a release of
/// `tool_1.2.3_linux_amd64.deb` resolve"). So the rule was load-bearing in the
/// wrong direction, and the burden of proof that usually protects a table's members
/// does not apply here: **removing a needed sidecar entry installs the wrong file;
/// removing a needed package entry refuses a release — loud, and the diagnostic
/// lists every candidate.** The asymmetry runs the other way for this list.
///
/// **Any dot-segment, not just the last**, matching mise's
/// `is_non_executable_asset` (`jdx/mise` `src/backend/asset_matcher.rs:705`), which
/// tests `asset.split('.').any(...)`. That is why mise refuses
/// `goreleaser_…_x86_64.pkg.tar.zst` and a last-extension-only rule would accept it:
/// the last segment there is `zst`, and the `pkg` in the middle is the package.
///
/// **Applied to automatic selection only, which is the whole point.** mise gates it
/// at `am.rs:348`, inside the scorer, with the comment "Keep them out of automatic
/// selection while still allowing an explicit `asset_pattern` or URL to select one
/// for custom installation logic." A user who writes `asset: foo.deb` gets it — the
/// explicit arms of `select_github_asset` never consult this.
///
/// **The undecodable compression formats belong here too, and were missing.** This
/// list exists to give the user a *good* diagnostic, and the install-time
/// `UNOPENABLE_EXTENSIONS` gives a worse one: it fires *after* selection, so
/// `gh:fastfetch-cli/fastfetch` on windows selected `fastfetch-windows-amd64.7z`
/// and the user never learned that `fastfetch-windows-amd64.zip` was in the same
/// release, one line later. With them here, selection skips the `.7z` and takes the
/// `.zip`; and where the release ships *only* the undecodable one —
/// `gh:restic/restic` publishes `.bz2` for every platform and no `.tar.gz` at all —
/// the refusal arrives with the whole candidate list instead of a dead end.
///
/// **`appimage` was here and has been removed, because the evidence for it was
/// false.** An `AppImage` is a directly-runnable ELF, so installing one as a raw
/// binary *works*: at the parent commit `gh:neovim/neovim` and `gh:logseq/logseq`
/// both selected an `AppImage` and the result ran. mise has no `appimage` member for
/// the same reason. Refusing it was a parity loss that also made a tool shipping
/// only an `AppImage` uninstallable, and the paragraph above justified it with
/// "witnessed wrong installs" -- which this corpus contradicts.
///
/// **`tar.zst` is not a *package*.** `zst` is a compression suffix and appears
/// here only as one of the undecodable formats below. An earlier version listed it
/// as a third "addition" in a paragraph while a code comment twelve lines down said
/// the opposite, so the document and the code each said something different about
/// the same entry; there is now one sentence about it.
///
/// **The three groups below are three different reasons, and the group a name lands
/// in decides the *advice* the user gets** — see `ArtifactPlan`'s refusal message,
/// which reads `UNDECODABLE_EXTENSIONS` to pick between "no decoder exists" and
/// "this is a package". A name in the wrong group gets a message that cannot be
/// acted on, which is the project's own definition of a half-written diagnostic.
const NON_EXECUTABLE_EXTENSIONS: &[&str] = &[
    // mise's `is_non_executable_asset`, verbatim and in mise's order, so the two
    // can be diffed: `apk appx appxbundle deb dmg mpkg msi msix msixbundle pkg rpm`.
    "apk",
    "appx",
    "appxbundle",
    "deb",
    "dmg",
    "mpkg",
    "msi",
    "msix",
    "msixbundle",
    "pkg",
    "rpm",
    // Ours, absent from mise, and each a witnessed wrong install:
    // `goreleaser_2.18.2_linux_amd64.flatpak` and
    // `Logseq-win-x64-0.10.15-full.nupkg` were both selected at the parent commit
    // and neither is an executable.
    "flatpak",
    "nupkg",
    // **`appimage` was here, was removed, and is back -- and the reason it went is
    // worth keeping, because the removal was justified by a claim that was false.**
    //
    // The argument for removing it was that "an AppImage is a directly-runnable
    // ELF, so installing one as a raw binary *works*", supported by "at the parent
    // commit `gh:neovim/neovim` and `gh:logseq/logseq` both selected an `AppImage`
    // and the result ran". Neither half survived checking. Those two releases
    // selected `nvim-linux-x86_64.tar.gz` and `Logseq-linux-x64-0.10.15.zip` at the
    // parent; the AppImage is the *new* selection, in 7 of the 11 changed winners.
    // And "the result ran" was never observed -- there is no test and no recorded run.
    //
    // What is true, and is why it belongs here: **an AppImage needs FUSE at run
    // time.** On a host or in a container without `libfuse2` the install still
    // reports success and the first run fails -- the same shape as the bug this
    // table exists to prevent, one layer up. That is the loud direction, and
    // membership parity with mise (which has no `appimage` member) is not *outcome*
    // parity: this project is first-match over release order where mise scores.
    "appimage",
    // Openable, but not a program. A wheel, a gem and a jar are a zip and a tar, so
    // they are kept out of *automatic selection* and `ArtifactPlan` refuses them as
    // unopenable -- because its layout arms key on literal suffixes and **nothing
    // sniffs content**, so a `.whl` would otherwise fall through to a raw binary.
    "whl",
    "gem",
    "jar",
    // A compression format with no decoder here, **including the bzip2
    // shorthands**. `bz2` alone left `tbz`/`tbz2` accepted while `bz2` was refused,
    // and `aristocratos/btop` publishes `btop-*.tbz` and *nothing else* -- so the
    // same bytes took two paths depending on their spelling, and the one that got
    // through installed a compressed blob as an executable and reported success.
    //
    // `gz`, `xz`, `tgz` and `zip` are deliberately absent: those are the ones this
    // project can read, and a last-segment-only test would miss a package marker in
    // the middle.
    "zst",
    "bz2",
    "tbz",
    "tbz2",
    "7z",
    "rar",
    "z",
    "lz",
    "lzma",
    "br",
    "sz",
    // `ar`, because a `.deb` *is* an `ar` archive. It was in the installer's table
    // and not here, which meant a `.ar` asset was selected and then refused with the
    // worse post-selection diagnostic -- the precise argument for moving nine
    // compression formats into this table in the first place.
    "ar",
];

/// Whether any dot-segment of a lowercased asset name names a distribution format.
#[must_use]
pub fn is_package_not_program(file: &str) -> bool {
    file.split('.')
        .any(|segment| NON_EXECUTABLE_EXTENSIONS.contains(&segment))
}

/// Whether a release asset is the *artifact* rather than a sidecar published
/// beside it.
///
/// A sidecar is named with the platform as often as the artifact is: `GoReleaser`
/// emits `foo-linux-amd64.tar.gz`, `foo-linux-amd64.tar.gz.sha256`,
/// `foo-linux-amd64.tar.gz.sig`, and `foo_linux_amd64.spdx.json` for the same build,
/// and all four match the platform. Selecting the wrong one installs a checksum file
/// as though it were a program, so the filter earns its place.
#[must_use]
pub fn is_release_artifact(name: &str) -> bool {
    // Split on both separators: a Windows release publishes
    // `downloads\tool.exe` with a backslash, and stripping only `/` left the
    // whole path in play, so the *last* extension read was `downloads\tool`.
    let file = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    // **A package is not a program.** See [`is_package_not_program`]. This is the
    // one filter here that is about *what the file is* rather than *what it is
    // called*, and it is the largest wrong-install class in the project: a `.deb`
    // is an `ar` archive, and the raw-binary path copies it to `bin/<name>`, marks
    // it executable, writes a receipt and publishes a launcher -- so the install
    // *succeeds* and the first run fails with `Exec format error`.
    if is_package_not_program(&file) {
        return false;
    }
    // **No `PROGRAM_EXTENSIONS` guard here, and the mutation is why.** Replacing the
    // guard with a no-op left every test in the workspace green. It is dead in
    // *this* function: a name whose last extension is `.tar.gz`, `.deb`, or `.zip`
    // cannot be a sidecar by either rule below, because no member of
    // `SIDECAR_EXTENSIONS` is a packaging extension and no such name ends in
    // `sum`/`sums`. The guard is load-bearing in the *installer's* classifier --
    // removing it there fails immediately -- because that function also accepts a
    // bare `checksum` token, and `checksum_linux_amd64.tar.gz` matches it.
    //
    // Two rules over the same names do not need the same guard, and the difference
    // is only visible by mutation. The list is shared; the guard is not, and
    // carrying an unexercised one "for symmetry" is how dead code survives a
    // rewrite.
    //
    // A `<name>.<kind>` whose `kind` names a sidecar kind. Checked on the *last*
    // extension only: `foo.tar.gz.sha256` ends in `sha256` and
    // `foo_linux_amd64.spdx.json` ends in `json`, so one segment covers both the
    // appended-digest and the two-extension SBOM shapes.
    let sidecar_extension = file
        .rsplit_once('.')
        .is_some_and(|(_, kind)| SIDECAR_EXTENSIONS.contains(&kind));
    if sidecar_extension {
        return false;
    }
    // A `checksum`/`checksums` *part*, with no extension to carry it. `mikefarah/yq`
    // publishes `checksums`, `checksums-bsd`, and `checksums_hashes_order` beside
    // the archive, and none of them has an extension, so the rule above cannot see
    // them and each was the artifact -- a release the global path then found two
    // digests in and refused.
    //
    // **The last part, not any part.** `mikefarah/yq` also publishes
    // `checksums.bundle` and `checksums-bsd.bundle`, where `bundle` is last; those
    // stay the artifact, and the installer's classifier deliberately uses the same
    // last-part rule so the two halves of one provider agree. Matching `bundle`
    // here would make both classify it a digest and the ambiguity would remain.
    let last_part = file.rsplit(['-', '_', '.']).next().unwrap_or(&file);
    if last_part == "checksum" || last_part == "checksums" {
        return false;
    }
    !is_digest_sidecar_name(&file)
}

/// Whether a name is a digest sidecar: a trailing `-`/`_`/`.`-delimited token that
/// is an algorithm name followed by `sums` or `sum`.
///
/// Both suffixes, because they are the same convention in two spellings and the
/// extension rule catches neither on its own -- `foo_linux_amd64.sha256sums` and
/// `foo_linux_amd64.sha256sum` are each a *single* extension, `sha256sums` and
/// `sha256sum`, neither of which is a bare `sums` or `sum`. `sum` is also the
/// per-architecture spelling of what `SHA256SUMS` is for the whole tree, and its
/// absence was a regression: a release of exactly `foo_linux_amd64.tar.gz` plus
/// `foo_linux_amd64.sha256sum` used to resolve and then yielded two platform
/// candidates on the global path.
///
/// **Shape, not a list of whole names, because the spellings vary and a list of
/// names would miss them.** `SHA256SUMS` (Git), `sha256sums` (AUR and Homebrew), and
/// `checksum.name_template`'s `foo_linux_amd64_SHA256SUMS` differ in case *and* in
/// prefix -- and the last one matches linux and `x86_64` in its prefix, so treating
/// it as an artifact selects the manifest, which is the exact bug this rule exists
/// to close. Requiring the whole name to be uppercase is what made the lowercase
/// spellings artifacts; requiring it to be separator-free is what made every
/// templated spelling one. The *algorithm* is still a list, though --
/// [`is_digest_algorithm`] explains why "any non-empty prefix" is not the
/// alternative, and the two directions it fails in are both covered by rows.
///
/// This owns the whole `*sums`/`*sum` family, so `SIDECAR_EXTENSIONS` deliberately
/// does **not** list `sums` or `sum`: they were there and no test row failed
/// without them, which is how a dead entry survives four rewrites of this file. A
/// name like `tool.sums` is caught here, by the empty-`head` branch.
fn is_digest_sidecar_name(file: &str) -> bool {
    // A bare coreutils checksum program is a program, whatever shape rule reaches it.
    // See [`COREOUTSUM_DIGEST_PROGRAMS`]: this is the one case no shape rule can
    // decide, because `md5sum` and `SHA256SUMS` are identical once lowercased.
    if COREOUTSUM_DIGEST_PROGRAMS.contains(&file) {
        return false;
    }
    // **Two different splits, because there are two different shapes.**
    //
    // `rsplit` always yields at least one segment, so the `unwrap_or` cannot fire.
    let token = file.rsplit(['-', '_', '.']).next().unwrap_or(file);
    // Shape one: the last `-`/`_`/`.`-delimited token is *exactly* `sum` or `sums`.
    // GoReleaser's `checksum.name_template: "{{ .ArtifactName }}_sums"` emits
    // `foo_linux_amd64_sums`. An earlier version read the empty head this leaves as
    // "no algorithm named, so this is a tool called `...-sums`" and installed the
    // manifest as the program. The one name that must survive is the *whole* name
    // being the suffix, because `sum` is a real program and a release of a single
    // `sum` binary is not a manifest.
    if token == "sum" || token == "sums" {
        return file != token;
    }
    // Shape two: the name *ends* in `sum`/`sums` with an algorithm somewhere
    // before it. Strip the suffix from the whole name first, then look for the
    // algorithm among the head's `-`/`_`/`.`-delimited parts, **rightmost first**.
    //
    // **...but not when the whole name *is* the marker.** Shape one has always had
    // that guard -- `sum` is a real program -- and shape two did not, so bare
    // `md5sum`, `sha1sum`, and `sha256sum` were manifests. All three are coreutils
    // programs, and a release of exactly one of them is a program. Two test rows
    // asserted the opposite. The asymmetry was invisible because the miss fails
    // closed (the archive-root lookup finds nothing either) and the refusal looks
    // identical to every other "no platform binary matched" -- which is the general
    // shape of this bug class: **a wrong classification that fails closed still
    // hides itself behind a diagnostic the user has no reason to doubt.**
    //
    // Two earlier readings of this were both wrong, and the failure mode was the
    // same each time -- the manifest was installed as the program:
    //
    // - **Strip the suffix from the last `_`/`.`-delimited component only.** That
    //   works for `foo_linux_amd64.sha256sums` and fails for
    //   `ripgrep-15.2.0-x86_64-unknown-linux-musl-sha256sums`, whose last component
    //   is `64-unknown-linux-musl-sha256sums` and whose head comes out as
    //   `64-unknown-linux-musl-sha256`. Every `-<version>-<os>-<arch>` name has that
    //   shape, so it was the *common* case that broke. The `.` still matters: those
    //   two dotted names are each a *single* extension, so the extension rule above
    //   cannot see them either.
    // - **Scan every `_`/`.`-delimited component.** That does not help, because all
    //   the dash-delimited parts are fused into that last component.
    //
    // So the algorithm search is a second scan *inside* the head, over all three
    // separators. This is not the "any non-empty prefix" rule that was removed two
    // commits ago -- the algorithm half is still a list, so `cksum`, `b2sum`, and
    // `shasum` are all still artifacts. Only the *reach* of the list changed.
    //
    // `-` is in the inner split for the same reason it was excluded from the outer
    // one, and the two are not in conflict: `sha3-256sums` strips to `sha3-256`,
    // whose rightmost part is `256` and whose next is `sha3`, and either is checked.
    //
    // The scan is rightmost-first so the *nearest* algorithm to the suffix wins.
    // **That ordering is not exercised**, and a mutation swapping it for
    // leftmost-first passes every test: no name in a 1039-asset corpus of 60 real
    // releases carries two algorithm-shaped parts. It is the right order on the
    // reasoning that the nearest one to the suffix is the one the manifest is
    // about, and it is recorded as a choice rather than a verified property.
    ["sums", "sum"].iter().any(|suffix| {
        file.strip_suffix(suffix)
            .is_some_and(|head| head.split(['-', '_', '.']).rev().any(is_digest_algorithm))
    })
}

/// The `<algorithm>sum` programs GNU coreutils installs, plus the other checksum
/// utilities that share the shape.
///
/// **A list, and this is the one place a list is right.** `md5sum` and `SHA256SUMS`
/// are structurally identical after lowercasing -- an algorithm name, the literal
/// `sum` or `sums`, and nothing else -- and no positional, extension, or
/// shape-based rule can separate them. A release of exactly `md5sum` is a program;
/// a release of exactly `SHA256SUMS` is a manifest. The discriminator is membership
/// in a *closed* set: coreutils ships a fixed, enumerable family of checksum
/// binaries, so this is a fact about known binaries rather than a guess about
/// a convention.
///
/// `b2sum` is here because **GNU coreutils 9.0 added it**, as a legacy
/// interface to `cksum`. An earlier version of this comment said it "ships in its
/// own distribution", which was false and was the stated reason for including it.
/// Every other member is an original coreutils checksum binary except the last two.
///
/// `b3sum` and `blake3sum` are here for the opposite reason: they are the BLAKE3
/// reference implementation's binaries, and they were added to `DIGEST_ALGORITHMS`
/// for `B3SUMS` -- which made *them* read as manifests. A set has to be checked
/// against the programs it protects when the *other* list gains a member.
///
/// The plural `SHA256SUMS` is deliberately absent, which is the whole point: the
/// manifest convention is plural and every coreutils program is singular. A
/// test row asserted the opposite for `md5sum` and `sha1sum` and was wrong.
///
/// The miss fails closed -- a release of only `md5sum` is refused with "no platform
/// binary or archive matched" -- so the cost of getting this wrong is a diagnostic,
/// not a wrong install. That is why it sat unfixed for a commit and still had to be
/// written down: **a wrong classification that fails closed hides behind a
/// diagnostic the user has no reason to doubt.**
const COREOUTSUM_DIGEST_PROGRAMS: &[&str] = &[
    "sum",
    "cksum",
    "b2sum",
    "shasum",
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "b3sum",
    "blake3sum",
];

/// Whether `head` -- what remains of a `...<algorithm>sums` token once the suffix
/// is stripped -- names a digest algorithm.
///
/// **A list of algorithm names, not "any non-empty prefix".** The prefix-only rule
/// was correct for every name it was written against and wrong for every name it
/// was not: `foo_linux_amd64-cksum`, `tool-linux-amd64.md5sum`, and `b2sum` are
/// all words that end in `sum`, and a *digest* of the wrong thing is still not the
/// program. The over-match had teeth, because a release of
/// `tool_linux_amd64.tar.gz` plus `tool_linux_amd64-cksum` then had *no* platform
/// artifact at all and failed with "no platform binary or archive matched" -- a
/// working release stopped installing because a sidecar was misfiled.
///
/// **`head` can never contain a dot, an underscore, or a dash**, because the caller
/// splits the name on all three before calling. An earlier version of this doc
/// credited the resolution of the dotted `GoReleaser` spelling
/// `foo_linux_amd64.sha256sums` to a `rsplit('.')` inside this function, and that
/// line was dead. It was then kept "in case a future reader needs it" and given a
/// no-op disjunct as well; mutation-testing the whole body down to
/// `DIGEST_ALGORITHMS.contains(&head)` passed every test, so both were dead and
/// both are gone. **Dead code kept on the theory that a future caller might want it
/// is dead code a future caller will not find**, because the next reader cannot tell
/// it apart from the load-bearing lines beside it.
///
/// This list is **not** a subset of [`SIDECAR_EXTENSIONS`], and the difference is
/// load-bearing. `sum`, `cksum`, and `b2sum` are in this list and absent from that
/// one, because they name *programs* the first list must not treat as sidecars
/// (see [`COREOUTSUM_DIGEST_PROGRAMS`]) rather than sidecar extensions.
///
/// An earlier version of this paragraph claimed the subset property and said it
/// was asserted by test. **Both halves were false**: three of twelve members fail
/// it under the most generous reading, and no such test exists — the only
/// cross-table test covers [`DIGEST_ALGORITHMS`], which *is* a subset. A doc that
/// names a test which does not check the named property is worse than a doc that
/// says nothing, because it makes a reader stop looking.
///
/// **No counts are written here either**, deliberately: every revision of that
/// sentence that carried one went stale within a commit, twice, because the number
/// moves whenever either table does.
/// the ones that appear glued to `sum`/`sums` without a separator, which is a
/// smaller and more conventional set than the extensions a release appends after a
/// dot.
///
/// **A member missing from here is a miss, and a miss here does *not* fail safe.**
/// An earlier version of this doc claimed it did, on the grounds that "the sidecar
/// is offered as the artifact and the refusal that follows names every candidate".
/// There is no refusal on the planner path: `select_github_asset` is
/// `assets.iter().find(..)`, first match wins, and `plan_github_release` has no
/// ambiguity check at all. Only `select_global_github_asset` refuses. A digest name
/// this list misses is **installed as the program** whenever the release lists it
/// before the archive -- which is what `checksum.name_template` ordering does.
///
/// **What still gets missed.** One kind, and it is a decision rather than a gap:
///
/// - **An algorithm this list does not name.** `b2sums` classifies as the artifact.
///   `b2` is excluded deliberately (see [`DIGEST_ALGORITHMS`]), so that is a choice.
///   It is the *only* remaining miss class, and it was verified to be the only one by
///   running a 1039-name corpus of real release assets from 60 projects through both
///   classifiers.
///
/// A second class used to be listed here and was **fixed**, not merely described:
/// shape two used to read the suffix off the last `_`/`.`-delimited component, so
/// `ripgrep-15.2.0-x86_64-unknown-linux-musl-sha256sums` yielded the head
/// `64-unknown-linux-musl-sha256`, matched no algorithm, and installed the manifest
/// as the program. An earlier revision of this doc kept that paragraph *and* named
/// the pre-commit implementation as the fix -- which is the code that had the bug.
/// A doc that describes a fixed bug and prescribes the reverted fix is worse than
/// no doc, because the next reader of this function will reintroduce it. **When a
/// fix lands, the paragraph describing the bug is the thing most likely to be left
/// behind, and it is the paragraph that will be believed.**
fn is_digest_algorithm(head: &str) -> bool {
    DIGEST_ALGORITHMS.contains(&head)
}

/// The algorithm names a digest-manifest name glues to `sum` or `sums`.
///
/// Every member is also a member of [`SIDECAR_EXTENSIONS`], so no name is
/// classified as a sidecar here and as the artifact there. That overlap is the
/// point: it is checked by a test that removes each member of *this* list and
/// requires a row to fail, because the two tables reading the same name
/// differently is the defect this file has now produced twice.
///
/// `sha3` and `sha3-256`/`sha3-512` were added because the previous version's own
/// doc named `sha3sum` as a shape it could not see, and shipped without fixing it.
/// The installer's digest classifier shares this list precisely so that the two
/// cannot drift on which algorithms exist.
///
/// **`b2` and `cksum` are deliberately absent**, and the reason is the caller's
/// exactly-one rule rather than any doubt that they are digests: `b2sum` is a real
/// coreutils-family name, and treating it as a release convention is a guess about
/// which spelling a project picked. A guess that is wrong here costs a *refusal* on
/// a good release, which is the cheaper of the two errors.
pub const DIGEST_ALGORITHMS: &[&str] = &[
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha3", "sha3-256", "sha3-512", "md5",
    "blake2", "blake3",
    // The short `b3` spelling. `b2` is excluded below on the reasoning that no
    // release uses that spelling, and `b3` is here because `watchexec/watchexec`
    // *does*: it publishes `B3SUMS` plus 160 per-file `*.b3` digests. The exclusion
    // was never "b2 is not a digest algorithm" -- it was "no release has told us
    // this spelling exists", and a single publisher is enough to tell us.
    "b3",
    // **`sha`, for `shasums`.** The algorithm a project nominally writes there is
    // SHA-1, but `shasums` is a *convention* rather than a claim about the hash, and
    // `containers/podman` publishes an extensionless `shasums` as the only digest in
    // its release. mise carries `(?i)^SHASUMS` as a prefix match, so this closes a
    // parity gap rather than opening a guess: without it that release is refused
    // with the file listed as available.
    //
    // `sha1` is already a member, so this is a *spelling* of it, and `sha` is also an
    // extension in its own right -- which is how `foo_linux_amd64.sha` was already
    // classified.
    "sha",
];

/// Whether a release asset's name carries this platform's OS and architecture.
///
/// The rule is the reference's: lowercase the name, require it to contain one of
/// the platform's OS aliases *and* one of its architecture aliases. First match
/// wins, and the caller supplies the assets in release order, so the choice is
/// deterministic.
///
/// It is a heuristic by construction -- two assets can both match -- so an
/// ambiguous result is the caller's to report rather than something to paper
/// over here.
/// Exported because the installer's provider answers the same question before a
/// plan exists, and a second copy of the *platform* half is exactly how the two
/// paths came to disagree about `mac`.
#[must_use]
pub fn asset_matches_platform(name: &str, platform: &Platform) -> bool {
    let name = name.to_ascii_lowercase();
    matches_alias(&name, &platform_os_aliases(&platform.os))
        && matches_arch_alias(&name, &platform_arch_aliases(&platform.arch))
}

/// The architecture families this project recognises, written with the keys
/// [`platform_arch_aliases`] is keyed by.
///
/// A list rather than a map because it is also the **probe order** for
/// [`named_architecture`], and the order is part of the contract: a name naming two
/// families is ambiguous, and reporting the first is how an ambiguity would become a
/// silent wrong answer rather than a refusal.
const ARCHITECTURE_FAMILIES: &[&str] = &["x86_64", "arm64", "386", "arm"];

/// The pointer width, in bits, that a family implies.
fn family_width(family: &str) -> Option<u8> {
    match family {
        "x86_64" | "arm64" => Some(64),
        "386" | "arm" => Some(32),
        _ => None,
    }
}

/// The family that `arch` belongs to, or `None` when it belongs to none this project
/// knows.
///
/// An empty architecture and an unrecognised one both land here, and both mean
/// *unknown* rather than *32-bit* -- which is the distinction that matters below,
/// because an unknown host width must not be treated as a narrow one.
fn family_of(arch: &str) -> Option<&'static str> {
    let wanted = platform_arch_aliases(arch);
    if wanted.is_empty() {
        return None;
    }
    ARCHITECTURE_FAMILIES.iter().copied().find(|family| {
        let members = platform_arch_aliases(family);
        wanted.iter().any(|alias| members.contains(alias))
    })
}

/// The architecture family that `name` names, if it names **exactly one**.
///
/// `None` covers two different situations and the difference matters: a name that
/// names no architecture (the ordinary case for an explicit `url:`) and a name that
/// names two (`tool-amd64-arm64.tar.gz`, which no publisher ships). The second is
/// not "no answer" so much as "not this function's to adjudicate", and callers that
/// treat both as unconstrained are choosing not to guess rather than being told the
/// name is clean.
#[must_use]
pub fn named_architecture(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    let mut hits = ARCHITECTURE_FAMILIES
        .iter()
        .copied()
        .filter(|family| matches_arch_alias(&name, &platform_arch_aliases(family)));
    match (hits.next(), hits.next()) {
        (Some(only), None) => Some(only),
        // No family matched. Before concluding the name states no architecture, ask
        // whether it states a *widened* one -- see `widened_family`, which is the whole
        // reason this function cannot be a literal-alias search.
        (None, _) => widened_family(&name),
        // Two families matched. Unanswerable, and reporting the first would turn an
        // ambiguity into a silent wrong answer.
        (Some(_), Some(_)) => None,
    }
}

/// The bare roots that a following qualifier can widen, and the family each widens
/// *to*.
///
/// One pair, and the shape is not arbitrary: `arm` is a family root that says nothing
/// about width, and `arm64` is the width-qualified name for the same processor family.
/// `386` has no such partner -- `x86_64` is a different stem, not a widening of `386`
/// -- which is why the 32-bit x86 family is fixed by *exclusion* instead and needs no
/// entry here.
const WIDENABLE_ROOTS: &[(&str, &str)] = &[("arm", "arm64")];

/// The family a name is *widened* to, when it spells a 32-bit root plus a wider
/// qualifier rather than the 64-bit family's own aliases.
///
/// This exists because `arm-64` and `armv8` contain neither `arm64` nor `aarch64` --
/// the two aliases the `arm64` family is written with -- so a literal search finds no
/// family at all and reports the name as architecture-free. It is the same spelling
/// that defeated the first version of the width guard, and it is why a name can state a
/// width without containing the family that owns it.
///
/// The predicate is the mirror image of the guard in [`contains_architecture`]: that
/// one *refuses* a widened occurrence, this one *reports* it. Sharing the qualifier
/// list is what keeps the two from disagreeing, which is why neither re-derives it --
/// two copies of this predicate is how `arm-64` ends up refused by the planner and
/// reported as architecture-free by the installer.
fn widened_family(name: &str) -> Option<&'static str> {
    for (root, family) in WIDENABLE_ROOTS {
        for start in occurrences(name, root) {
            if names_a_wider_qualifier(&name[start + root.len()..]) {
                return Some(family);
            }
        }
    }
    None
}

/// Whether the text following a bare family root names a width wider than 32-bit,
/// either adjacent to it or through one separator.
///
/// The single definition of that test. [`contains_architecture`] and
/// [`widened_family`] are its only two callers, and they must agree, because they read
/// the same rule in opposite directions.
fn names_a_wider_qualifier(rest: &str) -> bool {
    /// The width of the token starting at the front of `text`, if it is wider than 32.
    fn leading_is_wider(text: &str) -> bool {
        let token: String = text
            .chars()
            .take_while(|character| !"-_.".contains(*character))
            .collect();
        arm_qualifier_width(&token).is_some_and(|width| width > 32)
    }
    if leading_is_wider(rest) {
        return true;
    }
    rest.strip_prefix(['-', '_', '.'])
        .is_some_and(leading_is_wider)
}

/// Whether `name` names an architecture **wider** than `host`'s, and which family.
///
/// # Why wider and not merely different
///
/// This is the check the install path was missing, and its direction is the whole
/// design. A `386` or 32-bit `arm` artifact on a 64-bit host *runs* -- under multilib,
/// or because `aarch64` executes `arm` -- so refusing it would break an install that
/// works, including one the user asked for explicitly with `asset:`. A 64-bit
/// artifact on a 32-bit host **cannot run at all**: it installs, is marked
/// executable, a receipt is written, a launcher is published, and the first
/// invocation fails with `Exec format error`.
///
/// That is the same asymmetry the 32-bit `x86` and `arm` fixes were about, and it is
/// why the answer is `Option`: a name that names no architecture, a host whose
/// architecture is unknown, and a name naming two families all yield `None`, and in
/// every one of those cases the install proceeds as it did before.
#[must_use]
pub fn names_a_wider_architecture(name: &str, host: &Platform) -> Option<&'static str> {
    let named = named_architecture(name)?;
    let named_width = family_width(named)?;
    let host_width = family_width(family_of(&host.arch)?)?;
    (named_width > host_width).then_some(named)
}

/// Whether `template`, with this platform substituted, produces `name`.
///
/// The architecture is the awkward half. This model's `Platform` carries Rust's
/// spelling (`x86_64`) where the reference carries Go's (`amd64`), and release
/// assets are named with either. Substituting only the model's own spelling made
/// `asset: "tool-{arch}.tar.gz"` fail against a release publishing
/// `tool-amd64.tar.gz` -- a previously-guaranteed `MissingAsset` that the
/// platform fallback then papered over by selecting something else entirely.
/// So every alias is tried.
///
/// Which one wins is decided by the *asset list's* order, not by alias
/// precedence: this is called once per asset, so a release listing
/// `tool-osx.tar.gz` before `tool-darwin.tar.gz` on a darwin platform matches the
/// first. That is the reference's own first-match behavior and it is documented
/// on `select_github_asset`; it is not a deliberate preference for the platform's
/// own spelling over an alias.
/// Every name a template can stand for on this platform: the cross product of
/// the OS and architecture aliases.
///
/// The platform's own spelling is included in both lists, so a release that names
/// assets the way this model does and one that names them the way the reference
/// does both resolve.
fn asset_names_for(template: &str, platform: &Platform) -> Vec<String> {
    let os: Vec<String> = platform_os_aliases(&platform.os)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let arch: Vec<String> = platform_arch_aliases(&platform.arch)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut names = Vec::with_capacity(os.len() * arch.len());
    for os_name in &os {
        for arch_name in &arch {
            names.push(
                template
                    .replace("{os}", os_name)
                    .replace("{arch}", arch_name),
            );
        }
    }
    names
}

/// Matches an asset name against a glob supporting `*` and `?`.
///
/// Anchored at both ends, which is what `filepath.Match` -- which the reference
/// uses -- does, and what makes `cli-*-linux.tar.gz` mean what it looks like.
/// Iterative rather than recursive: a pathological pattern like 40 `*`s would
/// otherwise be exponential, and an asset name is attacker-adjacent data in the
/// sense that it decides what gets downloaded.
pub(super) fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0usize, 0usize);
    // After a `*`, remember where to resume if the rest fails to match.
    let (mut star, mut resume) = (usize::MAX, 0usize);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = p;
            resume = n;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            resume += 1;
            n = resume;
        } else {
            return false;
        }
    }
    // Every remaining pattern character must be a `*`. A full match leaves
    // `p == pattern.len()`, and an empty range satisfies this -- the earlier
    // `p < pattern.len() &&` guard made a *complete* match return false.
    pattern[p..].iter().all(|&at| at == '*')
}

/// Whether a name carries an OS alias as a whole word.
///
/// A plain substring test is not good enough for the OS, and the reason is
/// embarrassing enough to be worth writing down: the reference's Windows aliases
/// are `["windows", "win"]`, and **`darwin` contains `win`**. Substring matching
/// therefore lets a Windows host select `tool-darwin-amd64.tar.gz` -- a macOS
/// binary -- and install it while reporting success. A test that asserted the
/// reference's behavior faithfully would have locked that in.
///
/// So an occurrence has to be bounded: preceded by a non-alphanumeric character
/// or the start of the name, and followed by a non-alphanumeric character or the
/// end. `tool-win.zip`, `x86_64-windows`, and `my-linux-thing` all match; the
/// `win` inside `darwin` does not, because an `r` precedes it.
fn matches_alias(name: &str, aliases: &[&str]) -> bool {
    aliases.iter().any(|alias| {
        // An empty alias matches at every position, including past the end, and a
        // non-ASCII one makes `start + 1` a non-boundary slice. Neither is
        // reachable from `Platform::host()`, and both are a panic rather than a
        // wrong answer if a caller ever passes one.
        if alias.is_empty() || !alias.is_ascii() {
            return false;
        }
        let mut from = 0;
        while let Some(at) = name[from..].find(alias) {
            let start = from + at;
            let end = start + alias.len();
            let bounded_before = name[..start]
                .chars()
                .next_back()
                .is_none_or(|before| !before.is_ascii_alphanumeric());
            let bounded_after = name[end..]
                .chars()
                .next()
                .is_none_or(|after| !after.is_ascii_alphanumeric());
            if bounded_before && bounded_after {
                return true;
            }
            // Resume past this occurrence's start so the search advances.
            from = start + 1;
        }
        false
    })
}

/// Whether a name carries an architecture alias.
///
/// **A substring test with two width rules, and both were measured before either was
/// written down.** A 32-bit ARM host used to match every `arm64` asset in a release —
/// 112 releases across 39 repositories, each installing a 64-bit binary, reporting
/// success and failing at first run with `Exec format error`.
///
/// A *token* test is the obvious fix and is wrong: it breaks `arm64v8` (3 corpus
/// names) and `jq-linux64` (1), because those spell the architecture glued to a
/// qualifier and `arm64` is not a token inside them. So the substring test stays.
///
/// The width is then read off the characters that follow:
///
/// 1. **An immediately adjacent digit** is a width. `arm`+`64` is `arm64`; `arm`+`6`
///    is `arm6`. This is also why `arm5`/`arm6`/`arm7` must be listed separately —
///    the `arm` alias is rejected on exactly the names they exist to match.
/// 2. **A width or ABI qualifier that is *wider* than 32-bit, through one separator**,
///    but **only for a bare family root**. `arm-64` and `arm_v8` name a 64-bit
///    architecture; `arm-v6` and `arm-v7` are 32-bit and must keep matching, which is
///    why the qualifier set is `64`/`v8`/`v9` and not "anything that looks like a
///    width". Applying rule 2 to a *width-qualified* alias is what would break
///    `arm64-0.10.15` and `386_1.16.1`, where the digits after the separator are a
///    **version**.
///
/// Measured over the 6,178-name corpus, against a plain substring test:
///
/// | family | names that stop matching | names that start matching |
/// |---|---|---|
/// | `x86_64` | 0 | 0 |
/// | `arm64` | 0 | 0 |
/// | 386 | 0 | 0 |
/// | `arm32` | 12 | 0 |
///
/// **Zero regression in the three families that were already correct, and 12 real
/// wrong-installs closed** — every one a `…-linux-arm-64…` name from
/// `localsend/localsend`, the last of which a first-match selector was still
/// installing on a 32-bit host after the first version of this fix.
fn matches_arch_alias(name: &str, aliases: &[&str]) -> bool {
    aliases
        .iter()
        // An empty alias is contained in every name, so the guard is not
        // defensive tidiness: without it a blank architecture matches everything
        // and the OS half alone decides.
        .filter(|alias| !alias.is_empty())
        .any(|alias| contains_architecture(name, alias))
}

/// The pointer width an ARM version qualifier names, in bits, or `None` when the
/// qualifier names no version at all.
///
/// **This replaces a three-string allow-list**, and the reason is a bug the list could
/// not express. The list was `["64", "v8", "v9"]`, matched with `starts_with`, so `v8l`
/// matched `v8` and `armv8l` was classified 64-bit. It is not: `armv8l` is the glibc
/// triple for **32-bit** `aarch64` -- the `l` is the long ABI on `aarch32`, and
/// Debian's 32-bit `ARMv8` port is `armhf`, so a 32-bit host was refused a
/// correct install, which
/// is the expensive direction.
///
/// A list also cannot be *extended* safely: `WIDER_THAN_32_BIT_ARM` mixed a digit-only
/// encoding (`64`) with two v-prefixed ones (`v8`, `v9`), so the digit-only spellings
/// of 8 and 9 were missing and `arm-8` matched a 32-bit host. Every addition was
/// another chance to leave a hole rather than a rule.
///
/// Reading the number instead makes the set closed and self-completing: the qualifier
/// grammar is `arm [sep] [v] N [abi]*`, and N decides the width.
///
/// **`armv8l` is an exception and is called out as one.** By the number alone `v8` is
/// 64-bit, so a rule that "derived" the right answer for `armv8l` would be wrong about
/// `armv9l` -- which is 64-bit and has no `aarch32` long-ABI meaning. Deriving it is
/// not possible from the token, so it is encoded, documented, and asserted both ways.
fn arm_qualifier_width(qualifier: &str) -> Option<u8> {
    let after_v = qualifier.strip_prefix('v').unwrap_or(qualifier);
    let digits = after_v
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    // The ABI letters that trail the number do not change the width -- except on v8,
    // where a trailing `l` selects AArch32 rather than AArch64.
    let trailing_abi = &after_v[digits.len()..];
    if digits == "8" && trailing_abi.starts_with('l') {
        return Some(32);
    }
    match digits.as_str() {
        // ARMv8-A and ARMv9-A are 64-bit, and `arm64`/`arm-64` say so directly.
        "8" | "9" | "64" => Some(64),
        // ARMv5/v6/v7 and an explicit 32 are 32-bit. `rclone` ships
        // `linux-arm-v6` and `linux-arm-v7`, so treating these as wider refused 30
        // real 32-bit names while fixing none.
        "5" | "6" | "7" | "32" => Some(32),
        _ => None,
    }
}

/// Whether `name` contains `alias` somewhere that is not part of a wider
/// architecture.
///
/// The occurrence has to *start* somewhere, so the scan advances past each match
/// rather than stopping at the first: `arm` heads `arm64` in `tool_linux_arm64.tar.gz`
/// and must be rejected there, and the same `arm` is a good match in
/// `tool_linux_arm.tar.gz`.
fn contains_architecture(name: &str, alias: &str) -> bool {
    for start in occurrences(name, alias) {
        let rest = &name[start + alias.len()..];
        // `rest` is a valid slice at `name.len()` too, and indexing it rather than
        // `name[end]` keeps this from ever computing an out-of-range byte offset.
        //
        // **One rule, not two.** This used to be an unconditional "the next character
        // is a digit, therefore wider" *plus* the qualifier test below. The digit rule
        // is the same test with the separator omitted, and having it separately is what
        // made `arm32` a false refusal: `3` is a digit, so `arm32` was rejected without
        // ever asking what the number *was*. `arm32` is 32-bit -- Android's name for
        // armv7 -- and a 32-bit host was refused a correct install.
        //
        // `names_a_wider_qualifier` already reads the number, so asking it for the
        // adjacent case too is what makes the set closed: `arm64` and `arm32` now take
        // the same path and are told apart by the digits, not by the presence of digits.
        if is_bare_family_root(alias) && names_a_wider_qualifier(rest) {
            continue;
        }
        return true;
    }
    false
}

/// Whether `alias` names a whole family rather than a specific width, and so is the
/// one spelling where a *following* qualifier can widen it.
///
/// `arm64`, `armv7` and `386` already say which width they mean, so a token after
/// them is part of something else — a version, most often. `arm` says nothing, so
/// `arm-64` is `arm` widened.
fn is_bare_family_root(alias: &str) -> bool {
    alias == "arm"
}

/// Every position at which `alias` occurs in `name`, in order.
///
/// The cursor has to live in the closure, not in the loop body: a `from` declared
/// inside the body is re-initialised on every call, so the iterator would return the
/// *first* occurrence forever and the scan would never reach a later one. That was
/// the first version of this function, and it silently reduced the width check to
/// "does the name start with the alias" — which passes for `tool_linux_arm64.tar.gz`
/// only because the alias happens to head it.
fn occurrences<'a>(name: &'a str, alias: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        let found = name[from..].find(alias)? + from;
        from = found + 1;
        Some(found)
    })
}

/// Plans one GitHub release tool against the release's real asset list.
///
/// # Errors
///
/// Returns a `ToolPlanError` when the provider does not match, the version is
/// not the release tag, no asset matches, a `grep:` pattern cannot be honored,
/// the binaries are empty, or the artifact URL is not usable.
#[allow(clippy::too_many_lines)] // The release overlay and rename checks stay together.
pub fn plan_github_release(
    declaration: &ToolDeclaration,
    platform: &Platform,
    release: &GithubReleaseMetadata,
    checksum: Option<String>,
) -> Result<PlannedTool, ToolPlanError> {
    let github =
        declaration
            .github_release
            .as_ref()
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            })?;
    reject_binary_layout(declaration)?;
    if declaration.provider != ToolProvider::GithubRelease || release.tag != declaration.version {
        return Err(ToolPlanError::MissingAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        });
    }
    // Field by field, the way the reference's `MergeWithDefaults` overlays: a
    // platform value wins only where it is present. The all-or-nothing version
    // let an override that set only `grep` also clear the declaration's `asset`.
    let override_ = select_platform_override(declaration, platform)?;
    let asset_template = override_
        .and_then(|override_| override_.asset.as_deref())
        .or(github.asset.as_deref());
    let grep = override_
        .and_then(|override_| override_.grep.as_deref())
        .or(github.grep.as_deref());
    let rename = override_
        .and_then(|override_| override_.rename.as_deref())
        .or(github.rename.as_deref());
    // No direct-URL branch. A `url:` on a release entry means "fetch this exact
    // file" in the reference, which this model already expresses as the
    // `explicit-url` provider, so the compatibility reader maps it there rather
    // than the planner growing a second way to get a URL.
    //
    // An earlier version did add one here, and it produced a plan the lock
    // refused: `provider: "github-release"` with no `asset_id`, against an
    // invariant requiring all three of repository, release id, and asset id. The
    // plan looked right, `tool plan` printed it, and `tool install` then failed
    // before downloading anything. Loosening the invariant was the other option
    // and the wrong one -- it is what makes a lock entry auditable, and the
    // equivalent rule for the other five providers would then disagree with it.
    let asset = select_github_asset(
        &release.assets,
        asset_template,
        grep,
        platform,
        &declaration.id,
    )?;
    if rename.is_some() && is_archive_asset_name(&asset.name) {
        return Err(ToolPlanError::RenameOnArchive {
            id: declaration.id.clone(),
            asset: asset.name.clone(),
        });
    }
    let url = canonicalize_url(&asset.url).map_err(|url| ToolPlanError::UnsupportedUrl {
        id: declaration.id.clone(),
        url,
    })?;
    let sha256 =
        declaration
            .sha256
            .clone()
            .or(checksum)
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            })?;
    if !is_sha256(&sha256) {
        return Err(ToolPlanError::InvalidSha256 {
            id: declaration.id.clone(),
            sha256,
        });
    }
    // A per-platform `bins` replaces the declaration's own, the way `url` and
    // `sha256` already do. Reading the declaration's list unconditionally dropped
    // `linux-amd64: {bins: [helper]}` -- the same shape as the per-platform
    // `asset` case two lines up, which *was* honored.
    let binaries = match select_platform_override(declaration, platform)? {
        Some(override_) => override_
            .binaries
            .clone()
            .unwrap_or_else(|| declaration.binaries.clone()),
        None => declaration.binaries.clone(),
    };
    if binaries.is_empty() || binaries.iter().any(String::is_empty) {
        return Err(ToolPlanError::EmptyBinaries {
            id: declaration.id.clone(),
        });
    }
    // A name that is not a single component, refused here rather than at
    // lock-write time. `tool plan` printing a tool the installer will reject is the
    // worst of the two outcomes, because the user can see it and believe it.
    if let Some(unsafe_name) = binaries.iter().find(|name| !is_safe_binary_name(name)) {
        return Err(ToolPlanError::UnsafeBinaryName {
            id: declaration.id.clone(),
            name: unsafe_name.clone(),
        });
    }
    Ok(PlannedTool {
        id: declaration.id.clone(),
        resolved_version: declaration.version.clone(),
        url,
        platform: platform.clone(),
        sha256: sha256.clone(),
        provenance: ToolProvenance {
            provider: declaration.provider.name().into(),
            immutable_id: format!("release:{}/asset:{}", release.id, asset.id),
            repository: Some(github.repository.clone()),
            release_id: Some(release.id),
            asset_id: Some(asset.id),
            registry_endpoint: None,
            registry_revision: None,
            manifest_sha256: None,
            package: None,
            registry_integrity: None,
            declaration_sha256: Some(github_declaration_fingerprint(declaration, github)),
            authentication: declaration.provider.authentication_policy(),
        },
        verification: ArtifactVerification {
            sha256,
            signature: None,
        },
        binaries,
        declaration_source: declaration.declaration_source.clone(),
        cargo_toolchain: None,
    })
}

/// Computes a stable fingerprint of the declaration fields that govern the
/// GitHub artifact and install result.
#[must_use]
pub fn github_declaration_fingerprint(
    declaration: &ToolDeclaration,
    github: &super::GithubReleaseDeclaration,
) -> String {
    let canonical = format!(
        "github-v1\0{}\0{:?}\0{:?}\0{:?}\0{}\0{:?}\0{:?}\0{:?}\0{:?}\0{:?}\0{:?}",
        github.repository,
        github.asset,
        github.checksum_asset,
        github.grep,
        github.prerelease,
        github.rename,
        declaration.sha256,
        declaration.binaries,
        declaration
            .platforms
            .iter()
            .map(|entry| (
                &entry.platform.os,
                &entry.platform.arch,
                &entry.url,
                &entry.sha256,
                &entry.binaries,
                &entry.binpath,
                &entry.bindir,
                &entry.asset,
                &entry.grep,
                &entry.rename,
            ))
            .collect::<Vec<_>>(),
        declaration.binpath,
        declaration.bindir,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

/// The one platform override in force for `platform`, or `None`.
///
/// The tiers are resolved one at a time -- an exact OS-and-architecture match,
/// then an OS-only match, then a bare default -- because an exact match *beats* an
/// OS-only one rather than competing with it. Two matches **within** a tier are
/// ambiguous, and that is an error rather than a pick: two matching overrides mean
/// the file does not say which artifact this platform gets, and choosing would
/// install something the user did not name.
///
/// Exported because the installer's provider has to answer the same question
/// before a plan exists, and a second copy of this precedence is how the two
/// drifted apart once already: the installer read the declaration's own asset
/// while the planner read the override's, and `tool plan` named one artifact
/// while `tool install` fetched another.
///
/// # Errors
///
/// Returns `ToolPlanError::AmbiguousPlatformOverride` when two overrides in the
/// same tier match, which means the file does not say which one this platform
/// gets.
pub fn select_platform_override<'a>(
    declaration: &'a ToolDeclaration,
    platform: &Platform,
) -> Result<Option<&'a PlatformOverride>, ToolPlanError> {
    for selector in [
        OverrideSelector::Exact,
        OverrideSelector::OsOnly,
        OverrideSelector::Default,
    ] {
        let matches: Vec<_> = declaration
            .platforms
            .iter()
            .filter(|asset| selector.matches(&asset.platform, platform))
            .collect();
        match matches.as_slice() {
            [] => {}
            [asset] => return Ok(Some(asset)),
            _ => {
                return Err(ToolPlanError::AmbiguousPlatformOverride {
                    id: declaration.id.clone(),
                    platform: platform.clone(),
                });
            }
        }
    }
    Ok(None)
}

#[derive(Clone, Copy)]
enum OverrideSelector {
    Exact,
    OsOnly,
    Default,
}

impl OverrideSelector {
    fn matches(self, candidate: &PlatformSelector, target: &Platform) -> bool {
        match self {
            Self::Exact => {
                candidate.os.as_deref() == Some(&target.os)
                    && candidate.arch.as_deref() == Some(&target.arch)
            }
            Self::OsOnly => candidate.os.as_deref() == Some(&target.os) && candidate.arch.is_none(),
            Self::Default => candidate.os.is_none() && candidate.arch.is_none(),
        }
    }
}

#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// # Errors
///
/// Returns an error when the value is not a credential-free, fragment-free
/// absolute HTTP(S) URL.
pub fn canonical_http_url(value: &str) -> Result<String, String> {
    let mut url = Url::parse(value).map_err(|_| "invalid HTTP(S) URL".to_owned())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid HTTP(S) URL".to_owned());
    }
    url.set_fragment(None);
    Ok(url.into())
}

/// Returns true only for an already-canonical HTTPS URL.
#[must_use]
pub fn is_canonical_https_url(value: &str) -> bool {
    value.starts_with("https://") && canonical_http_url(value).as_deref() == Ok(value)
}

/// Checks an exact supported Rust toolchain pin, optionally suffixed by a target triple.
///
/// Accepted forms are `MAJOR.MINOR.PATCH` and
/// `MAJOR.MINOR.PATCH-ARCH-VENDOR-OS[-ABI]`. The target form is limited to
/// known Rust target components, with exactly three or four fields.
/// Floating channels, prereleases, build metadata, paths, unknown components,
/// and extra fields are rejected.
#[must_use]
pub fn is_cargo_toolchain_pin(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let (version, target) = value
        .split_once('-')
        .map_or((value, None), |(v, t)| (v, Some(t)));
    let components: Vec<_> = version.split('.').collect();
    let version_ok = components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (*component == "0" || !component.starts_with('0'))
        });
    version_ok && target.is_none_or(is_supported_rust_target)
}

/// Rust target identities supported by Cargo build declarations.
///
/// This exact-tuple registry prevents individually plausible architecture,
/// vendor, OS, and ABI tokens from being combined into nonexistent targets.
fn is_supported_rust_target(target: &str) -> bool {
    const TARGETS: &[&str] = &[
        "aarch64-apple-darwin",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "aarch64-apple-tvos",
        "aarch64-apple-visionos",
        "aarch64-apple-watchos",
        "aarch64-unknown-fuchsia",
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu_ilp32",
        "aarch64-unknown-linux-musl",
        "aarch64-unknown-linux-ohos",
        "aarch64-unknown-netbsd",
        "aarch64-unknown-none",
        "aarch64-unknown-openbsd",
        "aarch64-unknown-redox",
        "aarch64-unknown-uefi",
        "aarch64-unknown-windows-gnu",
        "aarch64-unknown-windows-gnullvm",
        "aarch64-uwp-windows-msvc",
        "arm-unknown-linux-gnueabi",
        "arm-unknown-linux-gnueabihf",
        "armv7-unknown-linux-gnueabihf",
        "armv7-unknown-linux-musleabihf",
        "i686-apple-darwin",
        "i686-pc-windows-gnu",
        "i686-pc-windows-msvc",
        "i686-unknown-linux-gnu",
        "i686-unknown-linux-musl",
        "i686-unknown-netbsd",
        "i686-unknown-openbsd",
        "loongarch64-unknown-linux-gnu",
        "loongarch64-unknown-linux-musl",
        "powerpc-unknown-linux-gnu",
        "powerpc64-unknown-linux-gnu",
        "powerpc64le-unknown-linux-gnu",
        "powerpc64le-unknown-linux-musl",
        "riscv32imac-unknown-none-elf",
        "riscv32imac-unknown-xous-elf",
        "riscv32imafc-unknown-linux-gnu",
        "riscv64gc-unknown-linux-gnu",
        "riscv64gc-unknown-linux-musl",
        "riscv64gc-unknown-none-elf",
        "s390x-unknown-linux-gnu",
        "s390x-unknown-linux-musl",
        "wasm32-unknown-emscripten",
        "wasm32-unknown-unknown",
        "wasm32-wasip1",
        "wasm32-wasip1-threads",
        "wasm32-wasip2",
        "wasm64-unknown-unknown",
        "x86_64-apple-darwin",
        "x86_64-apple-ios",
        "x86_64-apple-ios-macabi",
        "x86_64-apple-tvos",
        "x86_64-apple-watchos-sim",
        "x86_64-pc-solaris",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-gnullvm",
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-dragonfly",
        "x86_64-unknown-freebsd",
        "x86_64-unknown-fuchsia",
        "x86_64-unknown-haiku",
        "x86_64-unknown-hermit",
        "x86_64-unknown-illumos",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnux32",
        "x86_64-unknown-linux-musl",
        "x86_64-unknown-linux-ohos",
        "x86_64-unknown-netbsd",
        "x86_64-unknown-openbsd",
        "x86_64-unknown-redox",
        "x86_64-unknown-uefi",
        "x86_64-unknown-windows-gnu",
        "x86_64-unknown-windows-gnullvm",
        "x86_64-uwp-windows-msvc",
    ];
    TARGETS.contains(&target)
}

pub(super) fn canonicalize_url(value: &str) -> Result<String, String> {
    canonical_http_url(value)
}

#[must_use]
pub fn is_registry_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_exact_npm_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Validates one exact semantic version for a selected npm-compatible manager.
///
/// Unlike npm selectors, this accepts exact prereleases and build metadata;
/// it rejects ranges, tags, paths, whitespace, and non-canonical numeric
/// components without rewriting the supplied string.
#[must_use]
pub fn is_exact_manager_version(value: &str) -> bool {
    fn identifiers(value: &str, numeric_no_leading_zero: bool) -> bool {
        !value.is_empty()
            && value.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && (!numeric_no_leading_zero
                        || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                        || identifier == "0"
                        || !identifier.starts_with('0'))
            })
    }
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(version, metadata)| {
            (version, Some(metadata))
        });
    if build.is_some_and(|metadata| !identifiers(metadata, false)) {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(version, pre)| (version, Some(pre)));
    if prerelease.is_some_and(|pre| !identifiers(pre, true)) {
        return false;
    }
    let mut components = core.split('.');
    let valid_core = (0..3).all(|_| {
        components.next().is_some_and(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
        })
    }) && components.next().is_none();
    valid_core && value.is_ascii()
}

fn is_exact_dotnet_version(value: &str) -> bool {
    let (core, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(core, pre)| (core, Some(pre)));
    is_exact_npm_version(core)
        && prerelease.is_none_or(|pre| {
            !pre.is_empty()
                && pre
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        })
}

fn is_exact_go_version(value: &str) -> bool {
    value.starts_with('v')
        && value.len() > 1
        && !value.contains([' ', '\t', '\n', '/', '@'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

pub(super) fn is_valid_go_module(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains(['\\', '?', '#', '@'])
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
}

pub(super) fn is_go_sum(value: &str) -> bool {
    value.strip_prefix("h1:").is_some_and(|encoded| {
        STANDARD
            .decode(encoded)
            .is_ok_and(|digest| digest.len() == 32)
    })
}

fn go_proxy_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_ascii_uppercase() {
                ['!', character.to_ascii_lowercase()]
            } else {
                ['\0', character]
            }
        })
        .filter(|character| *character != '\0')
        .collect()
}

pub(super) fn is_valid_nuget_package(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub(super) fn is_sha512_integrity(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha512-") else {
        return false;
    };
    STANDARD
        .decode(encoded)
        .is_ok_and(|digest| digest.len() == 64)
}

/// Whether an npm SRI string contains a supported, correctly sized digest.
///
/// The installer accepts any valid sha256 or sha512 token in whitespace
/// separated SRI, matching npm provider verification behavior. Malformed and
/// unsupported alternatives are ignored when another supported token exists;
/// at least one supported, correctly sized digest is required by lock
/// validation.
pub(super) fn is_npm_integrity(value: &str) -> bool {
    value.split_whitespace().any(|entry| {
        let Some((algorithm, encoded)) = entry.split_once('-') else {
            return false;
        };
        let Ok(digest) = STANDARD.decode(encoded) else {
            return false;
        };
        match algorithm {
            "sha256" => digest.len() == 32,
            "sha512" => digest.len() == 64,
            _ => false,
        }
    })
}

pub(super) fn is_safe_binary_name(value: &str) -> bool {
    !value.is_empty() && PathLike::new(value).is_normal_name()
}

fn is_safe_npm_bin_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !value.starts_with('/')
        && !value.contains('\\')
}

pub(super) struct PathLike<'a>(&'a str);
impl PathLike<'_> {
    pub(super) fn new(value: &str) -> PathLike<'_> {
        PathLike(value)
    }
    pub(super) fn is_normal_name(&self) -> bool {
        !self.0.contains(['/', '\\']) && self.0 != "." && self.0 != ".."
    }
}
