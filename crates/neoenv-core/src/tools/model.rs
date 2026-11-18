//! Pure tool declarations, provider identity, and provenance types.

use super::{Arc, Deserialize, Serialize, SourceSpan, fmt};

pub const TOOL_LOCK_SCHEMA_VERSION: u32 = 6;

/// Authentication requirements declared by a provider implementation.
/// Credentials are never configuration or lockfile data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderAuthPolicy {
    Prohibited,
    Optional,
    Required,
}

/// A provider normalized from a tool declaration.
/// Extension providers are parseable but deliberately have no resolver yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ToolProvider {
    ExplicitUrl,
    GithubRelease,
    /// A GitLab release, from a Go `gl:namespace/project` key.
    ///
    /// Distinct from `GithubRelease` rather than an `Extension`, because the
    /// declaration is fully modeled -- see [`GitlabReleaseDeclaration`] -- and
    /// only the *resolver* is missing. A provider invented at resolve time would
    /// lose the project path the file already stated.
    GitlabRelease,
    Aqua,
    Npm,
    DotnetTool,
    GoModule,
    RubyGems,
    Cargo,
    Extension(String),
}

impl ToolProvider {
    #[must_use]
    pub fn from_name(name: Option<&str>) -> Self {
        match name.unwrap_or("explicit-url") {
            "explicit-url" => Self::ExplicitUrl,
            "github-release" => Self::GithubRelease,
            "gitlab-release" => Self::GitlabRelease,
            "aqua" => Self::Aqua,
            "npm" => Self::Npm,
            "dotnet-tool" => Self::DotnetTool,
            "go-module" => Self::GoModule,
            "ruby-gems" => Self::RubyGems,
            "cargo" => Self::Cargo,
            name => Self::Extension(name.into()),
        }
    }

    #[must_use]
    pub const fn authentication_policy(&self) -> ProviderAuthPolicy {
        match self {
            // A private GitLab project needs a token to read its releases, so
            // the policy matches GitHub rather than the public-registry default.
            Self::GithubRelease | Self::GitlabRelease => ProviderAuthPolicy::Optional,
            Self::ExplicitUrl
            | Self::Aqua
            | Self::Npm
            | Self::DotnetTool
            | Self::GoModule
            | Self::RubyGems
            | Self::Cargo
            | Self::Extension(_) => ProviderAuthPolicy::Prohibited,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::ExplicitUrl => "explicit-url",
            Self::GithubRelease => "github-release",
            Self::GitlabRelease => "gitlab-release",
            Self::Aqua => "aqua",
            Self::Npm => "npm",
            Self::DotnetTool => "dotnet-tool",
            Self::GoModule => "go-module",
            Self::RubyGems => "ruby-gems",
            Self::Cargo => "cargo",
            Self::Extension(name) => name,
        }
    }
}

/// Immutable provider facts recorded in a lock entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProvenance {
    pub provider: String,
    pub immutable_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_integrity: Option<String>,
    /// Digest of the provider declaration inputs that selected this artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_sha256: Option<String>,
    pub authentication: ProviderAuthPolicy,
}

/// Optional signature evidence. Providers must still resolve a SHA-256 digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureVerification {
    pub scheme: String,
    pub identity: String,
}

/// The byte-verification contract for a locked artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVerification {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
}

impl Platform {
    #[must_use]
    pub fn host() -> Self {
        Self::new(std::env::consts::OS, std::env::consts::ARCH)
    }

    #[must_use]
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSelector {
    pub os: Option<String>,
    pub arch: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformOverride {
    pub platform: PlatformSelector,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub binaries: Option<Vec<String>>,
    pub binpath: Option<String>,
    pub bindir: Option<String>,
    /// A per-platform asset template, from the Go `asset` key. Absent means
    /// "select by platform", the same as the declaration's own absent asset.
    pub asset: Option<String>,
    /// A per-platform regular expression, from the Go `grep` key. It selects
    /// among release artifacts; an invalid expression is
    /// `ToolPlanError::InvalidGrepPattern`.
    pub grep: Option<String>,
    /// The per-platform `rename`/`rn` destination name.
    pub rename: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubReleaseDeclaration {
    pub repository: String,
    /// An asset name template, with `{os}` and `{arch}` substituted and then
    /// matched exactly.
    ///
    /// Optional: when absent, the release's assets are scanned for one whose
    /// name carries this platform's OS and architecture. That is what lets a
    /// `gh:owner/repo` entry with nothing but a version resolve, and it is a
    /// capability a native declaration can now use too.
    pub asset: Option<String>,
    pub checksum_asset: Option<String>,
    /// A regular expression for selecting a release artifact, from the Go
    /// `grep` key or the native `grep` field.
    pub grep: Option<String>,
    /// Allow a pre-release when resolving `latest`.
    ///
    /// The flag changes which release metadata is fetched; it does not turn a
    /// pinned version into a floating one. A locked install records the exact
    /// tag that was chosen.
    pub prerelease: bool,
    /// The destination binary name from a Go `rename`/`rn` key.
    ///
    /// A raw single-binary artifact can be written under this name. An archive
    /// cannot yet be rewritten, so planning refuses this for an archive rather
    /// than reporting an install that used a different file name.
    pub rename: Option<String>,
}

/// A GitLab release, from a Go `gl:` key.
///
/// `namespace` and `project` are the two halves of `gl:namespace/project`. `host`
/// is the registry host, defaulting to `gitlab.com`; the reference carries no
/// per-entry host either, so a self-managed GitLab is not expressible there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitlabReleaseDeclaration {
    pub host: String,
    pub namespace: String,
    pub project: String,
    /// An asset name template, substituted and matched exactly, the way
    /// [`GithubReleaseDeclaration::asset`] is.
    pub asset: String,
    /// A regular expression for selecting the asset, from the Go `grep` key.
    ///
    /// GitLab resolution has no provider in this build, so this field is
    /// carried and the provider is refused by name before asset selection.
    pub grep: Option<String>,
}

/// The immutable Aqua registry input used to resolve a package manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AquaDeclaration {
    pub endpoint: String,
    pub registry_revision: String,
    pub package: String,
    pub manifest_sha256: String,
}

/// Public npm registry input. Versions are exact; ranges and tags are rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmDeclaration {
    pub endpoint: String,
    pub package: String,
    /// Optional package manager selection. Selected managers are currently
    /// parsed and retained, but execution is refused until manager installs are wired.
    pub manager: Option<NpmManager>,
}

/// An explicitly selected JavaScript package manager and exact release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmManager {
    pub name: NpmManagerName,
    pub version: String,
    /// Explicit user trust in the exact Bun release archive, for offline bootstrap.
    pub archive_sha256: Option<String>,
}

/// Supported explicit npm-compatible manager identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NpmManagerName {
    Bun,
    Pnpm,
}

/// A public `NuGet` v3 flat-container source. The source kind is explicit so a
/// future authenticated or script-based source cannot be selected implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetToolDeclaration {
    pub source: String,
    pub endpoint: String,
    pub package: String,
}

/// An exact Go module fetched only from an explicit module proxy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoModuleDeclaration {
    pub source: String,
    pub endpoint: String,
    pub module: String,
    pub go_sum: String,
}

/// An exact Ruby gem fetched from an explicit, unauthenticated registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RubyGemsDeclaration {
    pub endpoint: String,
    pub gem: String,
}

/// Explicit Cargo source-build declaration. All policy choices are required;
/// this declaration is modeled now, while execution remains deliberately disabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoDeclaration {
    pub crate_name: String,
    pub version: String,
    pub registry: String,
    pub checksum: String,
    pub toolchain: String,
    pub scripts: CargoScriptPolicy,
    pub build: CargoBuildPolicy,
    pub network: CargoNetworkPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoScriptPolicy {
    Deny,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoBuildPolicy {
    Isolated,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoNetworkPolicy {
    Deny,
}

/// Registry facts for one exact `RubyGems` package version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RubyGemsRegistryPackage {
    pub gem: String,
    pub version: String,
    pub platform: String,
    pub sha256: String,
}

/// npm package metadata for one exact version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmRegistryPackage {
    pub package: String,
    pub version: String,
    pub tarball: String,
    pub integrity: String,
    pub binaries: Vec<NpmBinary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmBinary {
    pub name: String,
    pub path: String,
}

/// A verified package manifest returned by an Aqua registry endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AquaRegistryManifest {
    pub package: String,
    pub assets: Vec<AquaRegistryAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AquaRegistryAsset {
    pub version: String,
    pub platform: Platform,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubReleaseAsset {
    pub id: u64,
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubReleaseMetadata {
    pub id: u64,
    pub tag: String,
    pub assets: Vec<GithubReleaseAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDeclaration {
    pub id: String,
    pub version: String,
    pub provider: ToolProvider,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub github_release: Option<GithubReleaseDeclaration>,
    pub gitlab_release: Option<GitlabReleaseDeclaration>,
    pub aqua: Option<AquaDeclaration>,
    pub npm: Option<NpmDeclaration>,
    pub dotnet_tool: Option<DotnetToolDeclaration>,
    pub go_module: Option<GoModuleDeclaration>,
    pub ruby_gems: Option<RubyGemsDeclaration>,
    pub cargo: Option<CargoDeclaration>,
    pub binaries: Vec<String>,
    /// A path to the binary inside the installed tree, from the Go `binpath` key.
    pub binpath: Option<String>,
    /// The directory inside an archive to take binaries from, from the Go
    /// `bindir` key.
    pub bindir: Option<String>,
    pub platforms: Vec<PlatformOverride>,
    pub declaration_source: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlannedTool {
    pub id: String,
    pub resolved_version: String,
    pub url: String,
    pub platform: Platform,
    pub sha256: String,
    pub provenance: ToolProvenance,
    pub verification: ArtifactVerification,
    pub binaries: Vec<String>,
    pub declaration_source: SourceSpan,
    /// Exact managed Rust toolchain pin for Cargo-backed tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_toolchain: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ToolPlan {
    pub tools: Vec<PlannedTool>,
}

#[derive(Clone, Debug)]
pub enum ToolPlanError {
    DuplicateToolId {
        id: String,
    },
    AmbiguousPlatformOverride {
        id: String,
        platform: Platform,
    },
    MissingAsset {
        id: String,
        platform: Platform,
    },
    UnsupportedUrl {
        id: String,
        url: String,
    },
    UnsupportedProvider {
        id: String,
        provider: String,
    },
    InvalidSha256 {
        id: String,
        sha256: String,
    },
    EmptyBinaries {
        id: String,
    },
    UnpinnedRegistry {
        id: String,
    },
    AmbiguousAsset {
        id: String,
        platform: Platform,
    },
    AssetSelection {
        id: String,
        platform: Platform,
        reason: String,
        assets: Vec<String>,
    },
    InvalidNpmPackage {
        id: String,
    },
    InvalidNpmManagerVersion {
        id: String,
        version: String,
    },
    InvalidNpmIntegrity {
        id: String,
    },
    InvalidDotnetTool {
        id: String,
    },
    InvalidDotnetIntegrity {
        id: String,
    },
    InvalidGoModule {
        id: String,
    },
    InvalidGoChecksum {
        id: String,
    },
    InvalidRubyGem {
        id: String,
    },
    InvalidCargo {
        id: String,
    },
    ResourceLimit {
        id: String,
        message: String,
    },
    /// A provider adapter failed after planning had started. The original
    /// typed source is retained for library callers while `fallback` keeps the
    /// stable domain-facing message and variant this boundary has always
    /// produced.
    ProviderSource {
        fallback: Box<ToolPlanError>,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    /// A binary name that is not a single normal path component.
    ///
    /// Checked at *plan* time rather than at lock-write time, because a name like
    /// `../../evil` otherwise survived `tool plan` -- which printed a tool the
    /// user could see and believe -- and failed only at install with a lock
    /// diagnostic that does not mention the key it came from.
    UnsafeBinaryName {
        id: String,
        name: String,
    },
    /// An npm package's bin path, which may be nested but must stay inside the
    /// package.
    UnsafeBinary {
        id: String,
    },
    /// A Go `grep:` asset pattern that is not a valid regular expression.
    ///
    /// The pattern is applied only to release artifacts, and a pattern that
    /// does not compile is refused by name rather than ignored. Falling back to
    /// platform selection would install a *different artifact than the file
    /// named*, which is the worst available outcome -- it looks like a
    /// successful install.
    InvalidGrepPattern {
        id: String,
        pattern: String,
        reason: String,
    },
    /// A `rename` on an archive, which this build cannot honor safely.
    ///
    /// The extractor preserves archive paths and has no original-to-destination
    /// mapping. Installing the original name and reporting success would be a
    /// false success, so this is refused before any bytes are published.
    RenameOnArchive {
        id: String,
        asset: String,
    },
    /// A Go `binpath:` or `bindir:`, which this model carries but cannot honor.
    ///
    /// Reported rather than carried silently. Both name a location *inside* the
    /// extracted artifact -- a path to one binary, or a directory to take
    /// binaries from -- and the extractors here place a tool's whole binary list
    /// at the archive root with no per-binary selection. Carrying the key on the
    /// declaration and then dropping it before install would be exactly the
    /// silent-drop failure this profile exists to prevent: the install would
    /// succeed and put the wrong thing on `PATH`.
    UnsupportedBinaryLayout {
        id: String,
        key: String,
    },
}

// One arm per error, each saying what went wrong *and* what to do about it. The
// routing that keeps a message from becoming a half-written diagnostic is exactly
// what does not fit on one screen per arm.
#[allow(clippy::too_many_lines)]
impl fmt::Display for ToolPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateToolId { id } => write!(formatter, "duplicate tool ID {id}"),
            Self::AmbiguousPlatformOverride { id, platform } => write!(
                formatter,
                "tool {id} has ambiguous platform assets for {}/{}",
                platform.os, platform.arch
            ),
            Self::MissingAsset { id, platform } => write!(
                formatter,
                "tool {id} has no asset for {}/{}",
                platform.os, platform.arch
            ),
            Self::UnsupportedUrl { id, url } => {
                write!(formatter, "tool {id} has unsupported URL {url}")
            }
            Self::UnsupportedProvider { id, provider } => {
                write!(
                    formatter,
                    "tool {id} provider {provider} is not implemented"
                )
            }
            Self::InvalidSha256 { id, sha256 } => {
                write!(formatter, "tool {id} has invalid SHA-256 {sha256}")
            }
            Self::EmptyBinaries { id } => write!(formatter, "tool {id} has no binaries"),
            Self::UnpinnedRegistry { id } => {
                write!(formatter, "tool {id} has an unpinned Aqua registry")
            }
            Self::AmbiguousAsset { id, platform } => write!(
                formatter,
                "tool {id} has ambiguous registry assets for {}/{}",
                platform.os, platform.arch
            ),
            Self::AssetSelection {
                id,
                platform,
                reason,
                assets,
            } => {
                // **Asset names are escaped, and this is the *remote* arm of a
                // terminal-escape hole whose config arm was closed first.** These
                // names come from a GitHub release, so a hostile or compromised
                // release -- a weaker trust boundary than the user's own checked-in
                // config -- could carry newlines and ANSI escapes into a terminal.
                //
                // `id`, `platform.os`, `platform.arch` and `reason` still
                // interpolate raw, and it is worth being precise about *why* that is
                // not a hole, because a previous version of this comment gave the
                // wrong reason and "all four are config-sourced" is itself false:
                //
                // - `platform.os` and `platform.arch` are **host**-derived
                //   (`Platform::host()` reads `std::env::consts`) and threaded
                //   unchanged from the CLI into `select_github_asset`. No config key
                //   can set them, so they are the *strongest* boundary of the four.
                // - `id` is config-sourced: a checked-in `neoenv.yaml`. Weaker than
                //   the network, stronger than nothing.
                // - `reason` is a constant, except that the `AssetSelection` reason
                //   interpolates the declared `asset:` value -- and that one is
                //   already escaped at construction, with `{declared:?}`.
                //
                // So the values that reach a terminal unescaped are host- and
                // config-derived, and the untrusted source is the only one escaped.
                // An earlier version claimed escaping here was "the last place a
                // value reached a diagnostic unescaped", which was false in the same
                // `write!` two lines below.
                let available = if assets.is_empty() {
                    "<none>".to_owned()
                } else {
                    assets
                        .iter()
                        .map(|name| format!("{name:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                write!(
                    formatter,
                    "tool {id} cannot select a GitHub asset for {}/{}: {reason}; available assets: {available}",
                    platform.os, platform.arch
                )
            }
            Self::InvalidGrepPattern {
                id,
                pattern,
                reason,
            } => {
                write!(
                    formatter,
                    "tool {id} selects its asset with grep pattern {pattern:?}, which is not \
                     a valid regular expression: {reason}"
                )
            }
            Self::RenameOnArchive { id, asset } => {
                write!(
                    formatter,
                    "tool {id} requests `rename` for the archive {asset:?}; archived binaries                      are not rewritten by this build. Use the archive's own name, or an                      explicit `asset` that is a raw single-binary download."
                )
            }
            Self::UnsupportedBinaryLayout { id, key } => {
                write!(
                    formatter,
                    "tool {id} sets `{key}`, which names a location inside the downloaded \
                     artifact. This model places a tool's binaries at the archive root and \
                     has no per-binary selection, so honoring it would need the extractors \
                     to change. Use `bins:` to name the executables instead."
                )
            }
            Self::InvalidNpmPackage { id } => {
                write!(formatter, "tool {id} has invalid npm package metadata")
            }
            Self::InvalidNpmManagerVersion { id, version } => write!(
                formatter,
                "tool {id} selects an invalid npm manager version {version:?}; use one exact semantic version such as 1.2.3"
            ),
            Self::InvalidNpmIntegrity { id } => {
                write!(formatter, "tool {id} has invalid npm integrity")
            }
            Self::InvalidDotnetTool { id } => {
                write!(formatter, "tool {id} has invalid .NET tool metadata")
            }
            Self::InvalidDotnetIntegrity { id } => {
                write!(formatter, "tool {id} has invalid NuGet SHA-512")
            }
            Self::InvalidGoModule { id } => {
                write!(formatter, "tool {id} has invalid Go module metadata")
            }
            Self::InvalidGoChecksum { id } => {
                write!(formatter, "tool {id} has invalid Go checksum evidence")
            }
            Self::InvalidRubyGem { id } => {
                write!(formatter, "tool {id} has invalid RubyGems metadata")
            }
            Self::InvalidCargo { id } => {
                write!(
                    formatter,
                    "tool {id} has invalid Cargo metadata or build policy; specify the exact managed Rust toolchain with an explicit target triple (including GNU or musl ABI on Linux)"
                )
            }
            Self::ResourceLimit { id, message } => {
                write!(formatter, "tool {id}: {message}")
            }
            // The provider source never leaks into the message; the retained
            // fallback renders exactly the message this boundary always did.
            Self::ProviderSource { fallback, .. } => fmt::Display::fmt(fallback, formatter),
            Self::UnsafeBinaryName { id, name } => write!(
                formatter,
                "tool {id} names the binary `{name}`, which is not a single file name: a \
                 binary cannot contain a path separator, or be `.` or `..`. The installer \
                 writes `<root>/bin/<name>`, so anything else would write outside it."
            ),
            Self::UnsafeBinary { id } => write!(formatter, "tool {id} has an unsafe npm bin path"),
        }
    }
}

/// The names an OS goes by, in a release asset name or a `dotenv:`/`paths:`
/// `os:` key.
///
/// **Two vocabularies, one table, and it is deliberately the union.** The two
/// callers disagree about which spellings exist: `paths.go:86` accepts four and
/// `release.go:277` accepts three, so neither list is right for both. Choosing
/// the intersection would make `os: mac` silently match nothing, which is the
/// exact bug this table was created to fix; choosing the union widens the
/// *release-asset* matcher by one name (`mac`, so `tool-mac.tar.gz` is a name it
/// will synthesize), which is the safe direction -- a wider match can pick the
/// right file, a narrower one cannot. Two tables would drift, and drift here is
/// a platform that stops matching silently.
///
/// The aliases exist because the two vocabularies disagree: this model's
/// `Platform` and the reference both spell macOS differently from the file a
/// user writes (`std::env::consts::OS` is `macos`, `runtime.GOOS` is `darwin`,
/// and `paths.go` accepts `mac`, `macos`, `darwin`, and `osx`). Without them a
/// `paths: [{darwin: /opt/homebrew/bin}]` -- the exact line a user would write --
/// silently matched nothing on macOS, and `os: darwin` did the same.
///
/// An unrecognized OS matches **only its own name**. That is the reference's rule
/// (`return []string{goos}`) and it is the safe direction: widening an
/// unrecognized name can only ever select an artifact built for a different OS.
/// An earlier version listed every known alias here, which made the most common
/// host -- linux, which is not a named case -- accept a darwin asset and install
/// it while reporting success.
#[must_use]
pub fn platform_os_aliases(os: &str) -> Vec<&str> {
    match os {
        // `mac` is here because `paths.go` accepts it and both this file's doc
        // comment and the commit that added the table name it. It was missing,
        // which meant `dotenv: [{path: .env.mac, os: mac}]` -- a spelling the
        // reference accepts -- matched nothing on macOS.
        "darwin" | "macos" => vec!["darwin", "macos", "osx", "mac"],
        "windows" => vec!["windows", "win"],
        // An empty name is an *unknown* platform, not a name contained in
        // everything. Returning `vec![""]` here would make the substring test
        // below true for every asset, and a blank `Platform` would then select
        // whichever asset the release happened to list first.
        "" => Vec::new(),
        other => vec![other],
    }
}

/// The names a platform's architecture goes by in a release asset.
///
/// Same rule as [`platform_os_aliases`]: an unrecognized architecture matches
/// only itself, so a `s390x` host never accepts an `amd64` asset.
///
/// The spellings differ from the reference's because this model's `Platform`
/// carries Rust's names (`x86_64`), where the reference carries Go's (`amd64`).
///
/// **`i386` and `i686` are this project's own spellings, not the reference's.**
/// `platformArchNames` in `neobeard/neoenv` (`tools/release.go`) has cases only for
/// `amd64` and `arm64`; everything else returns `[]string{goarch}`, so a 386 host
/// there matches the literal `386` and nothing else. An earlier version of this
/// file's comment claimed the reference "had" the `i386`/`i686` spellings and that
/// removing them was a regression against it. The *removal* was a real regression
/// against this project's own earlier list; the *justification* was invented, and
/// describing a project-specific choice as parity is how it gets deleted by the
/// next person who reads the reference.
#[must_use]
pub fn platform_arch_aliases(arch: &str) -> Vec<&str> {
    match arch {
        "x86_64" | "amd64" => vec!["x86_64", "amd64", "x64"],
        "arm64" | "aarch64" => vec!["arm64", "aarch64"],
        // The 32-bit x86 family, and **`x86` is deliberately absent.**
        //
        // `matches_arch_alias` is a substring test, and `x86` is a substring of
        // `x86_64` -- so listing `x86` here made a 32-bit host match
        // `tool_linux_x86_64.tar.gz` and install a 64-bit build while reporting
        // success. That is this project's defining failure mode: a silent wrong
        // artifact. The reference cannot hit it, because `platformArchNames` has
        // cases only for `amd64` and `arm64` and otherwise returns `[]string{goarch}`
        // -- for a 386 host that is `["386"]`, and `x86_64` does not contain `386`.
        //
        // So the 32-bit family is the three spellings that are *not* substrings of
        // `x86_64` or `amd64`. A release naming the architecture plain `x86` is
        // **refused**, with every candidate listed, rather than matched
        // ambiguously. That is the safe direction and it costs a real
        // convenience: a 32-bit user whose release says `x86` gets a diagnostic
        // naming a one-line `asset:` fix instead of a silently wrong install.
        //
        // `386` is a *key* as well as a value, because a lock or a
        // `PlatformOverride` written by the Go toolchain carries that spelling and
        // it must resolve to the same family, not the narrower `vec!["386"]`.
        "386" | "x86" | "i386" | "i686" => vec!["386", "i386", "i686"],
        // The 32-bit ARM family. **`arm` is deliberately INCLUDED**, unlike `x86`
        // above, and the reason is worth stating because it looks inconsistent.
        //
        // Both are prefixes of a wider spelling — `x86` of `x86_64`, `arm` of
        // `arm64` — and both used to cause the same silent wrong install. The two are
        // fixed differently because the cost is different: excluding `x86` from the
        // 386 family refuses a release that says plain `x86`, and no corpus name
        // does, so it is free. Excluding `arm` would *not* be free — 309 corpus names
        // spell a 32-bit ARM architecture plain `arm` or `arm_1`, so a 32-bit user
        // would be refused an install that works today.
        //
        // So `arm` stays in the list and the *width* is checked at match time instead:
        // see `contains_architecture`, where an alias running straight into digits is
        // part of a wider architecture. That fixes 1,118 arm64-or-wider names at zero
        // observable cost, where the exclusion would have cost 25 real ones.
        //
        // `arm5`, `arm6` and `arm7` are GoReleaser's spellings for armv5/6/7 and are
        // measured, not guessed: without them `duplicati`'s `-linux-arm7-cli.zip` and
        // `nats-server`'s `-linux-arm6` stop matching, which is 25 observable losses.
        //
        // Only `arm` is a *key*, because only `arm` is a spelling a host reports:
        // Rust's `std::env::consts::ARCH` and the Go toolchain's `GOARCH` both say
        // `arm` on 32-bit ARM, and a `PlatformOverride` is matched by exact string
        // against the host's own architecture, so `linux-arm6:` can never select. The
        // other eleven are **values only** -- tokens to look for in an asset name --
        // and that is where they are load-bearing and measured.
        //
        // An earlier version listed all twelve as keys, and a mutation that dropped
        // `arm6` and `armv7l` from the key list passed every test, because no test
        // and no host can reach them. A member no input can reach is dead, and the fix
        // is to delete it rather than invent a test that constructs a `Platform` no
        // machine would ever report.
        // **One member, and the width parse is what makes that sufficient.**
        //
        // This was `arm`, `arm5`, `arm6`, `arm7` — and then twelve, and then eight. The
        // specific reason it is one now: `arm_qualifier_width` reads the *number* after
        // the root, so a single `arm` alias distinguishes `arm64` and `arm-64` and
        // `armv8` and `arm8` (all wider, rejected) from `armv5`, `armv6`, `armv7`,
        // `arm32`, `armv8l`, `armhf`, `armel` and the GoReleaser `arm5`/`arm6`/`arm7`
        // (all 32-bit, matched). Listing the 32-bit spellings was only ever compensating
        // for a rule that asked "is the next character a digit" instead of "what number
        // is it".
        //
        // **`arm6` had to go, and keeping it was an active bug rather than a redundancy.**
        // `arm64` contains the four characters `arm6`, so the `arm6` alias matched it --
        // and because the width guard applies only to a *bare* family root, a non-bare
        // alias got no width check at all. So a 32-bit host matched `arm64` through
        // `arm6`. Removing the separate adjacent-digit rule exposed it; the fix is not
        // to put that rule back but to delete the aliases it was propping up.
        //
        // This is the "no 32-bit family member may be shadowed" property paying for
        // itself: `arm6` and `arm7` were never shadowed by `arm` under the old digit
        // test, so nothing flagged them, and they were not redundant in the old code
        // either. They became redundant the moment the width parse landed.
        //
        "arm" => vec!["arm"],
        // As above: an empty architecture is unknown, not a substring of all.
        "" => Vec::new(),
        other => vec![other],
    }
}
