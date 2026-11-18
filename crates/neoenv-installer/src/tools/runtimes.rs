//! Native language runtime installers. Each runtime owns its asset
//! resolution, progress reporting, and installation strategy.

use super::archive::{extract_gzip_tar, extract_xz_tar, extract_zip, has_suffix};
use super::http::{get_json, get_text};
use super::{
    Command, Deserialize, Diagnostic, Digest, Path, PathBuf, Platform, Read, ResourceBudget,
    Sha256, Sha512, Write, canonical_http_url, fs, http_error, http_policy, receipt_matches,
    runtime_error, runtime_io, temporary_path, url_encode, usable_file,
};
use neoenv_runtime::tasks::InstallIdentity;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// An immutable .NET SDK archive selected from Microsoft's release metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetSdkAsset {
    pub version: String,
    pub url: String,
    pub sha512: String,
}

/// A meaningful point in the installation of a .NET SDK archive.
///
/// Callers can render these updates without needing to know about archive
/// layout or the temporary paths used to make the installation atomic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DotnetSdkProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

/// An immutable Go SDK archive selected from Go's signed release manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoSdkAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

/// A meaningful point in a Go SDK installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoSdkProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

/// An immutable Node.js archive and checksum published by nodejs.org.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

/// Progress emitted while installing a Node.js runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZigRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenoRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenoRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UvRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UvRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdinRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdinRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZigRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

/// An immutable Eclipse Temurin JDK archive selected from Adoptium's release
/// metadata.
///
/// `version` is Adoptium's release-archive directory name (`jdk-21.0.13+9`),
/// not the semver string. The archive is published under
/// `<install-root>/<version>/`, so the layout can locate `bin/java` without
/// parsing a semver string that does not match the directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavaRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

/// An immutable Bun release archive selected from the project's release feed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BunRuntimeAsset {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

/// Retained verified release archive within a newly installed Bun runtime.
pub const BUN_RUNTIME_ARCHIVE: &str = ".neoenv-bun-archive.zip";
/// Release metadata retained alongside the verified archive.
pub const BUN_RUNTIME_PROVENANCE: &str = ".neoenv-bun-asset.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BunRuntimeProgress {
    Downloading { received: u64, total: Option<u64> },
    Extracting,
}

#[derive(Deserialize)]
pub(super) struct ZigIndexAsset {
    tarball: String,
    shasum: String,
}

#[derive(Deserialize)]
pub(super) struct ZigIndexRelease {
    version: String,
    #[serde(flatten)]
    fields: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct NodeRelease {
    version: String,
    lts: serde_json::Value,
}

#[derive(Deserialize)]
pub(super) struct DenoVersions {
    cli: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct UvRelease {
    tag_name: String,
}

#[derive(Deserialize)]
pub(super) struct RustChannelManifest {
    pkg: RustChannelPackages,
}

#[derive(Deserialize)]
pub(super) struct RustChannelPackages {
    rust: RustChannelPackage,
}

#[derive(Deserialize)]
pub(super) struct RustChannelPackage {
    version: String,
}

#[derive(Deserialize)]
pub(super) struct OdinRelease {
    tag_name: String,
    assets: Vec<OdinReleaseAsset>,
}

#[derive(Deserialize)]
pub(super) struct OdinReleaseAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PythonRelease {
    assets: Vec<OdinReleaseAsset>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdoptiumAvailableReleases {
    pub(super) most_recent_lts: u32,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdoptiumRelease {
    pub(super) release_name: String,
    pub(super) version_data: AdoptiumVersion,
    pub(super) binaries: Vec<AdoptiumBinary>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdoptiumVersion {
    pub(super) semver: String,
    pub(super) major: u32,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdoptiumBinary {
    pub(super) architecture: String,
    pub(super) image_type: String,
    pub(super) jvm_impl: String,
    pub(super) os: String,
    pub(super) package: AdoptiumPackage,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdoptiumPackage {
    pub(super) checksum: String,
    pub(super) link: String,
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct BunRelease {
    tag_name: String,
    assets: Vec<OdinReleaseAsset>,
}

#[derive(Deserialize)]
pub(super) struct GoRelease {
    version: String,
    stable: bool,
    files: Vec<GoReleaseFile>,
}

#[derive(Deserialize)]
pub(super) struct GoReleaseFile {
    filename: String,
    os: String,
    arch: String,
    kind: String,
    sha256: String,
}

#[derive(Deserialize)]
pub(super) struct DotnetReleasesIndex {
    #[serde(rename = "releases-index")]
    channels: Vec<DotnetChannel>,
}

#[derive(Deserialize)]
pub(super) struct DotnetChannel {
    #[serde(rename = "channel-version")]
    version: String,
    #[serde(rename = "latest-sdk")]
    latest_sdk: String,
    #[serde(rename = "releases.json")]
    releases_url: String,
    #[serde(rename = "support-phase")]
    support_phase: String,
}

#[derive(Deserialize)]
pub(super) struct DotnetReleaseDocument {
    releases: Vec<DotnetRelease>,
}

#[derive(Deserialize)]
pub(super) struct DotnetRelease {
    sdk: Option<DotnetSdk>,
}

#[derive(Deserialize)]
pub(super) struct DotnetSdk {
    version: String,
    files: Vec<DotnetSdkFile>,
}

#[derive(Deserialize)]
pub(super) struct DotnetSdkFile {
    rid: String,
    url: String,
    hash: String,
}

/// Resolves a supported .NET SDK version to one immutable, host-specific
/// archive. A bare or `latest` request selects the newest stable supported SDK.
///
/// # Errors
///
/// Returns a runtime diagnostic when Microsoft's metadata cannot provide a
/// release archive and SHA-512 digest for the current host.
pub fn resolve_dotnet_sdk(
    version: &str,
    platform: &Platform,
) -> Result<DotnetSdkAsset, Diagnostic> {
    const INDEX: &str =
        "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json";
    let index: DotnetReleasesIndex = get_json(INDEX)?;
    let requested = version.trim();
    let channel = select_dotnet_channel(&index.channels, requested, platform)?;
    let version = if requested.is_empty() || requested == "latest" {
        channel.latest_sdk.as_str()
    } else {
        requested
    };
    let document: DotnetReleaseDocument = get_json(&channel.releases_url)?;
    let sdk = document
        .releases
        .into_iter()
        .filter_map(|release| release.sdk)
        .find(|sdk| sdk.version == version)
        .ok_or_else(|| {
            runtime_error(format!(
                ".NET SDK {version} is not published for channel {}",
                channel.version
            ))
        })?;
    let rid = dotnet_rid(platform)?;
    let file = sdk
        .files
        .into_iter()
        .find(|file| {
            let url = file.url.to_ascii_lowercase();
            file.rid == rid && (has_suffix(&url, ".zip") || has_suffix(&url, ".tar.gz"))
        })
        .ok_or_else(|| {
            runtime_error(format!(".NET SDK {} has no archive for {rid}", sdk.version))
        })?;
    if canonical_http_url(&file.url).is_err()
        || file.hash.len() != 128
        || !file.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(runtime_error(
            ".NET release metadata contains an invalid SDK archive",
        ));
    }
    Ok(DotnetSdkAsset {
        version: sdk.version,
        url: file.url,
        sha512: file.hash.to_ascii_lowercase(),
    })
}

/// Resolves a Go SDK version to one host-specific archive with the checksum
/// published by go.dev. A bare or `latest` request selects the newest stable
/// release in that manifest.
///
/// # Errors
///
/// Returns a runtime diagnostic if the release manifest cannot provide an
/// archive and SHA-256 checksum for this host.
pub fn resolve_go_sdk(version: &str, platform: &Platform) -> Result<GoSdkAsset, Diagnostic> {
    const INDEX: &str = "https://go.dev/dl/?mode=json";
    let releases: Vec<GoRelease> = get_json(INDEX).map_err(|error| {
        runtime_error(format!(
            "failed to fetch Go release metadata: {}",
            error.message
        ))
    })?;
    let requested = version.trim().trim_start_matches("go");
    let release = if requested.is_empty() || requested == "latest" {
        releases.into_iter().find(|release| release.stable)
    } else {
        releases
            .into_iter()
            .find(|release| release.version.trim_start_matches("go") == requested)
    }
    .ok_or_else(|| runtime_error(format!("Go SDK {version} is not published")))?;
    let archive_os = match platform.os.as_str() {
        "macos" => "darwin",
        value => value,
    };
    let archive_arch = match platform.arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        value => value,
    };
    let extension = if archive_os == "windows" {
        ".zip"
    } else {
        ".tar.gz"
    };
    let file = release
        .files
        .into_iter()
        .find(|file| {
            file.kind == "archive"
                && file.os == archive_os
                && file.arch == archive_arch
                && has_suffix(&file.filename, extension)
        })
        .ok_or_else(|| {
            runtime_error(format!(
                "Go SDK {} has no archive for {}/{}",
                release.version, platform.os, platform.arch
            ))
        })?;
    if file.sha256.len() != 64 || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(runtime_error(
            "Go release metadata contains an invalid SDK archive",
        ));
    }
    Ok(GoSdkAsset {
        version: release.version.trim_start_matches("go").into(),
        // `go.dev/dl/<archive>` redirects to this Google-owned download
        // endpoint. The installer deliberately disables redirects to prevent
        // a locked provider request from silently changing origin.
        url: format!("https://dl.google.com/go/{}", file.filename),
        sha256: file.sha256.to_ascii_lowercase(),
    })
}

/// Resolves an exact Node.js release and verifies its archive name against the
/// publisher's SHA-256 manifest before any archive bytes are downloaded.
///
/// # Errors
///
/// Returns a runtime diagnostic when the publisher metadata is unavailable or
/// has no valid archive/checksum pair for the requested host.
pub fn resolve_node_runtime(
    version: &str,
    platform: &Platform,
) -> Result<NodeRuntimeAsset, Diagnostic> {
    let releases: Vec<NodeRelease> = get_json("https://nodejs.org/dist/index.json")?;
    let requested = version.trim();
    let release = releases
        .into_iter()
        .find(|release| match requested {
            "" | "latest" => true,
            "lts" => !release.lts.is_null() && release.lts != serde_json::Value::Bool(false),
            requested => {
                release.version.trim_start_matches('v') == requested.trim_start_matches('v')
            }
        })
        .ok_or_else(|| runtime_error(format!("Node.js {version} is not published")))?;
    let (os, arch, extension) = match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => ("linux", "x64", "tar.xz"),
        ("linux", "aarch64") => ("linux", "arm64", "tar.xz"),
        ("macos" | "darwin", "x86_64") => ("darwin", "x64", "tar.gz"),
        ("macos" | "darwin", "aarch64") => ("darwin", "arm64", "tar.gz"),
        ("windows", "x86_64") => ("win", "x64", "zip"),
        ("windows", "aarch64") => ("win", "arm64", "zip"),
        _ => {
            return Err(runtime_error(format!(
                "Node.js does not support {}/{}",
                platform.os, platform.arch
            )));
        }
    };
    let filename = format!("node-{}-{os}-{arch}.{extension}", release.version);
    let sums_url = format!("https://nodejs.org/dist/{}/SHASUMS256.txt", release.version);
    let sums = get_text(&sums_url)?;
    let sha256 = sums
        .lines()
        .find_map(|line| {
            let (digest, name) = line.split_once("  ")?;
            (name.trim_start_matches('*') == filename).then_some(digest)
        })
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            runtime_error(format!(
                "Node.js checksum manifest has no valid digest for {filename}"
            ))
        })?;
    Ok(NodeRuntimeAsset {
        version: release.version.trim_start_matches('v').into(),
        url: format!("https://nodejs.org/dist/{}/{}", release.version, filename),
        sha256: sha256.into(),
    })
}

/// Resolves a Zig release from its official checksum-bearing index.
///
/// # Errors
///
/// Returns a runtime diagnostic if no exact host archive and SHA-256 is published.
pub fn resolve_zig_runtime(
    version: &str,
    platform: &Platform,
) -> Result<ZigRuntimeAsset, Diagnostic> {
    let releases: std::collections::HashMap<String, serde_json::Value> =
        get_json("https://ziglang.org/download/index.json")?;
    let mut releases = releases
        .into_values()
        .filter_map(|value| serde_json::from_value::<ZigIndexRelease>(value).ok());
    let requested = version.trim();
    let release = if requested.is_empty() || requested == "latest" {
        releases
            .filter(|release| !release.version.contains('-'))
            // Semver precedence, not byte order: byte order reports `0.9.0` as newer
            // than `0.13.0`, so `latest` for Zig used to resolve to a release from
            // two years before the newest one. Zig versions are `major.minor.patch`
            // with no pre-release, which is exactly the shape byte order gets wrong.
            .max_by(|left, right| {
                neoenv_core::version::compare_versions(&left.version, &right.version)
            })
    } else {
        releases.find(|release| release.version == requested)
    }
    .ok_or_else(|| runtime_error(format!("Zig {version} is not published")))?;
    let key = match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => "x86_64-linux",
        ("linux", "aarch64") => "aarch64-linux",
        ("macos" | "darwin", "x86_64") => "x86_64-macos",
        ("macos" | "darwin", "aarch64") => "aarch64-macos",
        ("windows", "x86_64") => "x86_64-windows",
        ("windows", "aarch64") => "aarch64-windows",
        _ => {
            return Err(runtime_error(format!(
                "Zig does not support {}/{}",
                platform.os, platform.arch
            )));
        }
    };
    let asset = release
        .fields
        .get(key)
        .and_then(|value| serde_json::from_value::<ZigIndexAsset>(value.clone()).ok())
        .ok_or_else(|| {
            runtime_error(format!("Zig {} has no archive for {key}", release.version))
        })?;
    if canonical_http_url(&asset.tarball).is_err()
        || asset.shasum.len() != 64
        || !asset.shasum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(runtime_error(
            "Zig release metadata contains an invalid archive",
        ));
    }
    Ok(ZigRuntimeAsset {
        version: release.version,
        url: asset.tarball.clone(),
        sha256: asset.shasum.to_ascii_lowercase(),
    })
}

/// Resolves a Deno CLI release from Deno's official version and checksum feeds.
///
/// # Errors
///
/// Returns a runtime diagnostic if Deno does not publish an archive for this host.
pub fn resolve_deno_runtime(
    version: &str,
    platform: &Platform,
) -> Result<DenoRuntimeAsset, Diagnostic> {
    let releases: DenoVersions = get_json("https://deno.com/versions.json")?;
    let requested = version.trim().trim_start_matches('v');
    let version = releases
        .cli
        .into_iter()
        .find(|release| {
            requested.is_empty()
                || requested == "latest"
                || release.trim_start_matches('v') == requested
        })
        .ok_or_else(|| runtime_error(format!("Deno {version} is not published")))?
        .trim_start_matches('v')
        .to_owned();
    let target = rust_target_triple(platform).ok_or_else(|| {
        runtime_error(format!(
            "Deno does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let url = format!("https://dl.deno.land/release/v{version}/deno-{target}.zip");
    let checksum = get_text(&format!("{url}.sha256sum"))?;
    let sha256 = checksum
        .split_whitespace()
        .find(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| runtime_error("Deno checksum manifest contains no valid digest"))?;
    Ok(DenoRuntimeAsset {
        version,
        url,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// Resolves the latest or requested uv release from its official release feed.
///
/// # Errors
///
/// Returns a runtime diagnostic if uv publishes no checksum-verified archive for this host.
pub fn resolve_uv_runtime(
    version: &str,
    platform: &Platform,
) -> Result<UvRuntimeAsset, Diagnostic> {
    let requested = version.trim().trim_start_matches('v');
    let version = if requested.is_empty() || requested == "latest" {
        get_json::<UvRelease>("https://api.github.com/repos/astral-sh/uv/releases/latest")?
            .tag_name
            .trim_start_matches('v')
            .to_owned()
    } else {
        requested.to_owned()
    };
    let (target, extension) = uv_target(platform).ok_or_else(|| {
        runtime_error(format!(
            "uv does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let url = format!(
        "https://releases.astral.sh/github/uv/releases/download/{version}/uv-{target}.{extension}"
    );
    let checksum = get_text(&format!("{url}.sha256"))?;
    let sha256 = checksum
        .split_whitespace()
        .find(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| runtime_error("uv checksum manifest contains no valid digest"))?;
    Ok(UvRuntimeAsset {
        version,
        url,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// Resolves an official checksum-verified rustup bootstrapper and Rust toolchain version.
///
/// # Errors
///
/// Returns a runtime diagnostic if rustup is unavailable for this host.
pub fn resolve_rust_runtime(
    version: &str,
    platform: &Platform,
) -> Result<RustRuntimeAsset, Diagnostic> {
    let requested = version.trim();
    let version = if requested.is_empty() || requested == "latest" || requested == "stable" {
        let manifest: RustChannelManifest =
            get_json("https://static.rust-lang.org/dist/channel-rust-stable.toml")?;
        manifest
            .pkg
            .rust
            .version
            .split_whitespace()
            .next()
            .ok_or_else(|| runtime_error("Rust stable manifest has no version"))?
            .to_owned()
    } else {
        requested.trim_start_matches('v').to_owned()
    };
    let target = rust_target_triple(platform).ok_or_else(|| {
        runtime_error(format!(
            "Rust does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let executable = if platform.os == "windows" { ".exe" } else { "" };
    let url = format!("https://static.rust-lang.org/rustup/dist/{target}/rustup-init{executable}");
    let checksum = get_text(&format!("{url}.sha256"))?;
    let sha256 = checksum
        .split_whitespace()
        .find(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| runtime_error("rustup checksum manifest contains no valid digest"))?;
    Ok(RustRuntimeAsset {
        version,
        url,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// Resolves a checksum-verified official Odin compiler release for this host.
///
/// # Errors
///
/// Returns a runtime diagnostic when Odin has no release asset with a SHA-256 digest.
pub fn resolve_odin_runtime(
    version: &str,
    platform: &Platform,
) -> Result<OdinRuntimeAsset, Diagnostic> {
    let requested = version.trim();
    let endpoint = if requested.is_empty() || requested == "latest" {
        "https://api.github.com/repos/odin-lang/Odin/releases/latest".to_owned()
    } else {
        format!(
            "https://api.github.com/repos/odin-lang/Odin/releases/tags/{}",
            url_encode(requested)
        )
    };
    let release: OdinRelease = get_json(&endpoint)?;
    let tag = release.tag_name.trim_start_matches('v');
    let (os, arch, extension) = match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => ("linux", "amd64", "tar.gz"),
        ("linux", "aarch64") => ("linux", "arm64", "tar.gz"),
        ("macos" | "darwin", "x86_64") => ("macos", "amd64", "tar.gz"),
        ("macos" | "darwin", "aarch64") => ("macos", "arm64", "tar.gz"),
        ("windows", "x86_64") => ("windows", "amd64", "zip"),
        _ => {
            return Err(runtime_error(format!(
                "Odin does not support {}/{}",
                platform.os, platform.arch
            )));
        }
    };
    let filename = format!("odin-{os}-{arch}-{tag}.{extension}");
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == filename)
        .ok_or_else(|| runtime_error(format!("Odin {tag} has no asset {filename}")))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| runtime_error(format!("Odin {tag} asset has no valid SHA-256 digest")))?;
    Ok(OdinRuntimeAsset {
        version: tag.into(),
        url: asset.browser_download_url,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// Resolves a checksum-verified `CPython` standalone archive from Astral.
///
/// # Errors
///
/// Returns a runtime diagnostic when no stable host archive is published.
pub fn resolve_python_runtime(
    version: &str,
    platform: &Platform,
) -> Result<PythonRuntimeAsset, Diagnostic> {
    let release: PythonRelease =
        get_json("https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest")?;
    let target = rust_target_triple(platform).ok_or_else(|| {
        runtime_error(format!(
            "Python does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let requested = version.trim().trim_start_matches('v');
    let suffix = format!("-{target}-install_only.tar.gz");
    let asset = release
        .assets
        .into_iter()
        .filter(|asset| asset.name.starts_with("cpython-") && asset.name.ends_with(&suffix))
        .filter(|asset| !asset.name.contains("rc") && !asset.name.contains("beta"))
        .filter(|asset| {
            requested.is_empty()
                || requested == "latest"
                || asset.name.starts_with(&format!("cpython-{requested}+"))
        })
        .max_by_key(|asset| python_asset_version(&asset.name))
        .ok_or_else(|| {
            runtime_error(format!(
                "Python {version} has no standalone archive for {target}"
            ))
        })?;
    let resolved = asset
        .name
        .strip_prefix("cpython-")
        .and_then(|name| name.split_once('+'))
        .map(|(version, _)| version.to_owned())
        .ok_or_else(|| runtime_error("Python release asset has an invalid name"))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| runtime_error("Python release asset has no valid SHA-256 digest"))?;
    Ok(PythonRuntimeAsset {
        version: resolved,
        url: asset.browser_download_url,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// A Temurin JDK home for a host, given the install root and release dir.
///
/// The install root is the version directory (`.../java/<version>`), so this
/// function returns `<root>/<version>` on Linux and Windows. A macOS JDK is a
/// bundle: its home is `<root>/<version>/Contents/Home`. Keeping this in one
/// function is what makes the installer, the runtime layout, shell activation
/// and `tool which` agree on where `java` lives.
#[must_use]
pub fn java_home_directory(root: &Path, version: &str) -> PathBuf {
    java_home_directory_for(root, version, std::env::consts::OS)
}

/// As [`java_home_directory`], with the operating system named explicitly.
///
/// `os` uses Rust's `std::env::consts::OS` spelling (`linux`, `macos`,
/// `windows`). The explicit form is what a fixture test can call for a host it
/// is not running on.
#[must_use]
pub fn java_home_directory_for(root: &Path, version: &str, os: &str) -> PathBuf {
    let release = root.join(version);
    if os == "macos" {
        release.join("Contents").join("Home")
    } else {
        release
    }
}

/// The executable path inside a Temurin JDK for one host.
pub(super) fn java_executable_path(
    root: &Path,
    version: &str,
    os: &str,
    executable: &str,
) -> PathBuf {
    let name = if os == "windows" {
        format!("{executable}.exe")
    } else {
        executable.to_owned()
    };
    java_home_directory_for(root, version, os)
        .join("bin")
        .join(name)
}

/// The Bun archive directory and asset name for a host.
///
/// Bun publishes both `baseline` and `musl` variants beside the ordinary
/// archive. This project selects neither implicitly: baseline is a different
/// CPU baseline, and its Linux build is deliberately glibc-only, so `musl` is
/// not a drop-in. A host without an exact entry is refused.
pub(super) fn bun_target(platform: &Platform) -> Option<(&'static str, &'static str)> {
    match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => Some(("bun-linux-x64", "bun-linux-x64.zip")),
        ("linux", "aarch64") => Some(("bun-linux-aarch64", "bun-linux-aarch64.zip")),
        ("macos" | "darwin", "x86_64") => Some(("bun-darwin-x64", "bun-darwin-x64.zip")),
        ("macos" | "darwin", "aarch64") => Some(("bun-darwin-aarch64", "bun-darwin-aarch64.zip")),
        ("windows", "x86_64") => Some(("bun-windows-x64", "bun-windows-x64.zip")),
        ("windows", "aarch64") => Some(("bun-windows-aarch64", "bun-windows-aarch64.zip")),
        _ => None,
    }
}

/// Parses a whole Bun release version, with an optional `v`/`bun-v` prefix.
///
/// Only the stable `major.minor`/`major.minor.patch` form is accepted. Bun's
/// canary tags are not a supported release channel here, and a partial match
/// such as `1.4.4-typo` must be refused before a URL is built rather than
/// becoming a request for a different tag. The same validator is used on the
/// metadata tag and on a caller-supplied asset version, so neither can become a
/// path component or URL segment without matching the whole grammar.
pub(super) fn parse_bun_version(value: &str) -> Result<String, Diagnostic> {
    if value.trim() != value {
        return Err(runtime_error(format!(
            "`{value}` is not a supported Bun release version; surrounding whitespace is not part of a version"
        )));
    }
    let normalized = value
        .strip_prefix("bun-v")
        .or_else(|| value.strip_prefix('v'))
        .unwrap_or(value);
    let parts = normalized.split('.').collect::<Vec<_>>();
    if parts.len() < 2
        || parts.len() > 4
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || !safe_bun_component(normalized)
    {
        return Err(runtime_error(format!(
            "`{value}` is not a supported Bun release version; use a stable version such as 1.4.4"
        )));
    }
    Ok(normalized.to_owned())
}

/// Whether a Bun version is one ordinary, cross-platform-safe path component.
///
/// The grammar already keeps separators out; this repeats the Windows-specific
/// checks because a version from remote metadata becomes an install directory.
pub(super) fn safe_bun_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.trim() == value
        && !value.ends_with('.')
        && !value.ends_with(' ')
        && !value.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        && !value.chars().any(char::is_control)
}

/// Parses a `SHASUMS256.txt` body for one archive name.
pub(super) fn bun_checksum(body: &str, asset: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let (digest, name) = line.split_once("  ")?;
        (name.trim_start_matches('*') == asset
            && digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| digest.to_ascii_lowercase())
    })
}

/// Resolves a checksum-verified Bun release archive.
///
/// # Errors
///
/// Returns a runtime diagnostic when the host is unsupported, the release feed
/// is unavailable, or the publisher's checksum manifest has no entry for the
/// selected archive.
pub fn resolve_bun_runtime(
    version: &str,
    platform: &Platform,
) -> Result<BunRuntimeAsset, Diagnostic> {
    const RELEASES: &str = "https://api.github.com/repos/oven-sh/bun/releases";
    let (_archive_dir, asset_name) = bun_target(platform).ok_or_else(|| {
        runtime_error(format!(
            "Bun does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let requested = version.trim();
    let exact_request = !(requested.is_empty() || requested == "latest");
    let requested = if exact_request {
        Some(parse_bun_version(requested)?)
    } else {
        None
    };
    let endpoint = match &requested {
        Some(version) => format!("{RELEASES}/tags/bun-v{version}"),
        None => format!("{RELEASES}/latest"),
    };
    let release: BunRelease = get_json(&endpoint)?;
    let release_version = parse_bun_version(&release.tag_name)?;
    if let Some(requested) = &requested
        && requested != &release_version
    {
        return Err(runtime_error(format!(
            "Bun metadata returned {release_version}, which does not match the requested {requested}"
        )));
    }
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| {
            runtime_error(format!(
                "Bun {release_version} has no archive {asset_name} for {}/{}",
                platform.os, platform.arch
            ))
        })?;
    let sums_url = format!(
        "https://github.com/oven-sh/bun/releases/download/bun-v{release_version}/SHASUMS256.txt"
    );
    let sums = get_text(&sums_url)?;
    let sha256 = bun_checksum(&sums, &asset.name).ok_or_else(|| {
        runtime_error(format!(
            "Bun checksum manifest has no valid digest for {}",
            asset.name
        ))
    })?;
    Ok(BunRuntimeAsset {
        version: release_version,
        url: asset.browser_download_url.clone(),
        sha256,
    })
}

/// The Adoptium operating-system and architecture spelling for a host.
///
/// Split out of [`resolve_java_runtime`] so the refusal is testable without a
/// network call. A host this table does not name gets no archive rather than a
/// nearby one: Adoptium's `x64` is not an `x86_64` alias this code may guess at.
pub(super) fn java_target(platform: &Platform) -> Option<(&'static str, &'static str)> {
    match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => Some(("linux", "x64")),
        ("linux", "aarch64") => Some(("linux", "aarch64")),
        ("macos" | "darwin", "x86_64") => Some(("mac", "x64")),
        ("macos" | "darwin", "aarch64") => Some(("mac", "aarch64")),
        ("windows", "x86_64") => Some(("windows", "x64")),
        ("windows", "aarch64") => Some(("windows", "aarch64")),
        _ => None,
    }
}

/// A Java version request, parsed before any network request is made.
///
/// The distinction matters because an exact-looking malformed string must not
/// be sent upstream and then explained as "not published". `21-typo` is a
/// usage error in this code, not a claim about Adoptium's catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JavaRequest {
    Latest,
    Feature(u32),
    Exact { feature: u32 },
}

/// Parses a complete Java request.
///
/// Accepted forms are `latest`/empty, a bare feature version (`21`), and the
/// exact spellings Adoptium publishes: dotted numeric releases with an optional
/// `+build` suffix (`21.0.13+9`, `21.0.13+9.0.LTS`, `21.0.12.1+1`) or the Java 8
/// form (`8u462-b08`). An optional `jdk-` or `jdk` prefix is accepted. The whole
/// string must match; nothing is truncated at the first non-digit.
pub(super) fn parse_java_request(version: &str) -> Result<JavaRequest, Diagnostic> {
    let requested = version.trim();
    if requested.is_empty() || requested == "latest" {
        return Ok(JavaRequest::Latest);
    }
    let normalized = requested
        .strip_prefix("jdk-")
        .or_else(|| requested.strip_prefix("jdk"))
        .unwrap_or(requested);
    if normalized.is_empty() {
        return Err(runtime_error(format!(
            "Java version `{version}` is missing after the `jdk-` prefix"
        )));
    }
    if normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        let feature = normalized.parse::<u32>().map_err(|_| {
            runtime_error(format!("Java feature version `{version}` is not a number"))
        })?;
        return Ok(JavaRequest::Feature(feature));
    }
    let feature = exact_java_version(normalized).ok_or_else(|| {
        runtime_error(format!(
            "Java version `{version}` is not `latest`, a feature version such as `21`, or an exact release such as `21.0.13+9`"
        ))
    })?;
    Ok(JavaRequest::Exact { feature })
}

/// Returns the feature version of a fully valid exact Java release string.
fn exact_java_version(value: &str) -> Option<u32> {
    let (core, build) = value
        .split_once('+')
        .map_or((value, None), |(core, build)| (core, Some(build)));
    if let Some(build) = build
        && (build.is_empty()
            || build
                .split('.')
                .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric())))
    {
        return None;
    }
    if let Some((head, rest)) = core.split_once('u') {
        if head.is_empty() || !head.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let (update, revision) = rest
            .split_once('-')
            .map_or((rest, None), |(update, revision)| (update, Some(revision)));
        if update.is_empty() || !update.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if let Some(revision) = revision {
            let number = revision.strip_prefix('b')?;
            if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
        }
        return head.parse::<u32>().ok();
    }
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() < 2
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    parts.first()?.parse::<u32>().ok()
}

/// Resolves an Eclipse Temurin JDK from Adoptium's release metadata.
///
/// `version` accepts `latest` (the most recent LTS), a feature version (`21`),
/// or an exact Adoptium release (`21.0.13+9`, `jdk-21.0.13+9`, or the semver
/// `21.0.13+9.0.LTS`). Exact versions are matched against the most recent GA
/// releases of that feature line, because Adoptium's version endpoint takes a
/// Maven range rather than a bare version and a range that silently widens is
/// the wrong shape for a locked install.
///
/// # Errors
///
/// Returns a runtime diagnostic when the host is unsupported, the metadata is
/// unavailable, or no checksum-verified JDK archive matches the request.
pub fn resolve_java_runtime(
    version: &str,
    platform: &Platform,
) -> Result<JavaRuntimeAsset, Diagnostic> {
    const INFO: &str = "https://api.adoptium.net/v3/info/available_releases";
    const RELEASES: &str = "https://api.adoptium.net/v3/assets/feature_releases";
    let (os, arch) = java_target(platform).ok_or_else(|| {
        runtime_error(format!(
            "Java does not support {}/{}",
            platform.os, platform.arch
        ))
    })?;
    let requested = version.trim();
    let (feature, exact) = match parse_java_request(version)? {
        JavaRequest::Latest => {
            let info: AdoptiumAvailableReleases = get_json(INFO).map_err(|error| {
                runtime_error(format!(
                    "failed to fetch Adoptium release metadata: {}",
                    error.message
                ))
            })?;
            (info.most_recent_lts, false)
        }
        JavaRequest::Feature(feature) => (feature, false),
        JavaRequest::Exact { feature } => (feature, true),
    };
    let url = java_releases_url(RELEASES, feature, os, arch, exact);
    let releases: Vec<AdoptiumRelease> = get_json(&url)?;
    let release = select_java_release(&releases, requested, exact, feature)?;
    if !safe_java_component(&release.release_name) {
        return Err(runtime_error(
            "Adoptium release metadata contains an unsafe release directory name",
        ));
    }
    let binary = select_java_binary(release, os, arch)?;
    if binary.package.checksum.len() != 64
        || !binary
            .package
            .checksum
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(runtime_error(
            "Adoptium release metadata contains an invalid JDK archive checksum",
        ));
    }
    if canonical_http_url(&binary.package.link).is_err() {
        return Err(runtime_error(
            "Adoptium release metadata contains an invalid JDK archive URL",
        ));
    }
    Ok(JavaRuntimeAsset {
        version: release.release_name.clone(),
        url: binary.package.link.clone(),
        sha256: binary.package.checksum.to_ascii_lowercase(),
    })
}

/// The Adoptium query for one feature line and host.
///
/// The parameters are part of the contract with a remote service, which makes
/// them worth asserting literally: a misspelled `jvm_impl` or a missing
/// `vendor` still returns a JSON array, so the failure would look like "Java is
/// not published" rather than "the query is wrong".
pub(super) fn java_releases_url(
    base: &str,
    feature: u32,
    os: &str,
    arch: &str,
    exact: bool,
) -> String {
    let page_size = if exact { 20 } else { 1 };
    format!(
        "{base}/{feature}/ga?architecture={arch}&image_type=jdk&jvm_impl=hotspot&os={os}&page=0&page_size={page_size}&sort_order=DESC&vendor=eclipse"
    )
}

/// The directory holding `bun` inside a published Bun install root.
#[must_use]
pub fn bun_binary_directory(root: &Path) -> PathBuf {
    let directory =
        bun_target(&Platform::host()).map_or("bun-linux-x64", |(directory, _)| directory);
    root.join(directory)
}

/// Downloads, SHA-256-verifies, and atomically publishes Bun.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification,
/// extraction, or binary-discovery failure.
pub fn install_bun_runtime_with_progress<F>(
    root: &Path,
    asset: &BunRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(BunRuntimeProgress),
{
    if parse_bun_version(&asset.version).is_err() {
        return Err(runtime_error(format!(
            "invalid Bun version `{}`: it is not one supported stable release component",
            asset.version
        )));
    }
    let binary = bun_binary_directory(root).join(bun_binary_name());
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime_io(root, &error)),
        Ok(metadata) => {
            if metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && usable_file(&binary)
                && receipt_matches(&root.join(BunRuntime.receipt()), &asset.sha256)
            {
                if bun_retained_evidence_matches(root, asset) {
                    return Ok(binary);
                }
                return Err(runtime_error(format!(
                    "Bun installation at {} lacks matching retained archive and provenance; remove it and explicitly reinstall to restore verified evidence",
                    root.display()
                )));
            }
            return Err(runtime_error(format!(
                "Bun installation at {} does not match the resolved archive checksum; remove it before reinstalling",
                root.display()
            )));
        }
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Bun install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "bun-download")?;
    let temporary = temporary_path(parent, "bun-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(BunRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(BunRuntimeProgress::Extracting);
        extract_zip(&archive, &temporary)?;
        let binary = bun_binary_directory(&temporary).join(bun_binary_name());
        if !usable_file(&binary) {
            return Err(runtime_error(
                "Bun archive did not provide the bun executable",
            ));
        }
        retain_bun_archive(&archive, &temporary, &asset.sha256)?;
        let provenance = serde_json::to_vec(asset)
            .map_err(|error| runtime_error(format!("cannot serialize Bun provenance: {error}")))?;
        fs::write(temporary.join(BUN_RUNTIME_PROVENANCE), provenance)
            .map_err(|error| runtime_io(&temporary, &error))?;
        fs::write(temporary.join(BunRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(bun_binary_directory(root).join(bun_binary_name())),
            Err(_error) => {
                let published = bun_binary_directory(root).join(bun_binary_name());
                if usable_file(&published)
                    && receipt_matches(&root.join(BunRuntime.receipt()), &asset.sha256)
                    && bun_retained_evidence_matches(root, asset)
                {
                    let _ = fs::remove_dir_all(&temporary);
                    Ok(published)
                } else {
                    let _ = fs::remove_dir_all(&temporary);
                    Err(runtime_error(format!(
                        "Bun installation at {} could not be published and the existing tree does not match the resolved archive checksum",
                        root.display()
                    )))
                }
            }
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn bun_retained_evidence_matches(root: &Path, asset: &BunRuntimeAsset) -> bool {
    let provenance = root.join(BUN_RUNTIME_PROVENANCE);
    let archive = root.join(BUN_RUNTIME_ARCHIVE);
    let Ok(bytes) = super::install::read_regular_nofollow_bounded(&provenance, 2 * 1024 * 1024)
    else {
        return false;
    };
    serde_json::from_slice::<BunRuntimeAsset>(&bytes).is_ok_and(|found| &found == asset)
        && super::install::hash_file(&archive).is_ok_and(|digest| digest == asset.sha256)
}

pub(super) fn retain_bun_archive(
    archive: &Path,
    install_staging: &Path,
    sha256: &str,
) -> Result<(), Diagnostic> {
    if !super::verify_file(archive, sha256)? {
        return Err(runtime_error("downloaded Bun archive SHA-256 mismatch"));
    }
    let retained = install_staging.join(BUN_RUNTIME_ARCHIVE);
    fs::rename(archive, &retained).map_err(|error| runtime_io(&retained, &error))
}

/// Whether a Java release name is one ordinary, cross-platform-safe path
/// component.
///
/// The value becomes a directory below the data root, so this is deliberately
/// stricter than "no slash". It refuses the Windows spellings that are legal in
/// a Rust `Path` but not one ordinary file name: drive prefixes, alternate data
/// stream separators, UNC prefixes (both are caught by rejecting `:` and `\\`),
/// reserved device names, and names ending in a dot or space. It also rejects
/// wildcard and redirection characters so a name that is safe on one host is
/// not silently unsafe on another.
pub(super) fn safe_java_component(value: &str) -> bool {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.trim() != value
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || value.chars().any(char::is_control)
    {
        return false;
    }
    // Windows reserves these device names with or without an extension, so the
    // stem before the first dot is what matters.
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Selects the release Adoptium metadata offers for a Java request.
pub(super) fn select_java_release<'a>(
    releases: &'a [AdoptiumRelease],
    requested: &str,
    exact: bool,
    feature: u32,
) -> Result<&'a AdoptiumRelease, Diagnostic> {
    if exact {
        let normalized = requested.trim_start_matches("jdk-");
        releases
            .iter()
            .find(|release| {
                release.version_data.major == feature
                    && (release.release_name == requested
                        || release.release_name.trim_start_matches("jdk-") == normalized
                        || release.version_data.semver == normalized
                        || release.version_data.semver == requested)
            })
            .ok_or_else(|| {
                runtime_error(format!(
                    "Java {requested} is not among the most recent GA releases of feature {feature}; request `java@{feature}` for the current release"
                ))
            })
    } else {
        releases.first().ok_or_else(|| {
            runtime_error(format!("Java feature release {feature} has no GA archive"))
        })
    }
}

/// Selects the one Temurin JDK package for an Adoptium OS and architecture.
pub(super) fn select_java_binary<'a>(
    release: &'a AdoptiumRelease,
    os: &str,
    arch: &str,
) -> Result<&'a AdoptiumBinary, Diagnostic> {
    let extension = if os == "windows" { "zip" } else { "tar.gz" };
    release
        .binaries
        .iter()
        .find(|binary| {
            binary.os == os
                && binary.architecture == arch
                && binary.image_type == "jdk"
                && binary.jvm_impl == "hotspot"
                && has_suffix(&binary.package.name, extension)
        })
        .ok_or_else(|| {
            runtime_error(format!(
                "Java {} has no JDK archive for {os}/{arch}",
                release.release_name
            ))
        })
}

/// Downloads, SHA-256-verifies, and atomically publishes an Eclipse Temurin
/// JDK.
///
/// The archive's top-level `jdk-*` directory is preserved beneath the install
/// root, and the asset's `version` is that directory's name. `JAVA_HOME` is
/// therefore `<install-root>/<version>`, which is what the layout reports.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification,
/// extraction, or binary-discovery failure.
/// Returns a matching, already-published Java install, or refuses a conflict.
///
/// A directory that already exists is accepted only when both the executable
/// and the receipt naming the expected checksum are present. An install with a
/// missing or different receipt is a conflict, not a cache hit: accepting it
/// would report success for bytes nobody verified, and overwriting it would
/// destroy an installation another process or user owns.
///
/// # Errors
///
/// Returns a runtime diagnostic when `root` exists but is not a regular
/// directory, or when its executable and receipt do not prove the expected
/// archive was installed.
pub(super) fn java_existing_install(
    root: &Path,
    version: &str,
    expected_sha256: &str,
) -> Result<Option<PathBuf>, Diagnostic> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(runtime_io(root, &error)),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(runtime_error(format!(
            "Java installation path {} is not a regular directory",
            root.display()
        )));
    }
    let binary = java_executable_path(root, version, std::env::consts::OS, "java");
    if usable_file(&binary) && receipt_matches(&root.join(JavaRuntime.receipt()), expected_sha256) {
        return Ok(Some(binary));
    }
    Err(runtime_error(format!(
        "Java installation at {} does not match the resolved archive checksum; remove it before reinstalling",
        root.display()
    )))
}

/// Downloads, SHA-256-verifies, and atomically publishes an Eclipse Temurin
/// JDK.
///
/// The archive's top-level `jdk-*` directory is preserved beneath the install
/// root, and the asset's `version` is that directory's name. `JAVA_HOME` is
/// `<install-root>/<version>` on Linux and Windows, and
/// `<install-root>/<version>/Contents/Home` for a macOS bundle.
///
/// The installer validates `asset.version` before using it as a path component,
/// and refuses an existing installation whose receipt does not match the
/// resolved archive. That applies to the pre-download check and to the rename
/// collision path, so a race cannot turn an unverified directory into a
/// successful install.
///
/// # Errors
///
/// Returns without publishing a partial install on an invalid version, a
/// receipt conflict, transfer or verification failure, extraction failure, or
/// binary-discovery failure.
pub fn install_java_runtime_with_progress<F>(
    root: &Path,
    asset: &JavaRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(JavaRuntimeProgress),
{
    if !safe_java_component(&asset.version) {
        return Err(runtime_error(format!(
            "invalid Java version `{}`: it is not one ordinary safe path component",
            asset.version
        )));
    }
    if let Some(existing) = java_existing_install(root, &asset.version, &asset.sha256)? {
        return Ok(existing);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Java install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "java-download")?;
    let temporary = temporary_path(parent, "java-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(JavaRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(JavaRuntimeProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        let extracted =
            java_executable_path(&temporary, &asset.version, std::env::consts::OS, "java");
        if !usable_file(&extracted) {
            return Err(runtime_error(format!(
                "Java archive did not provide {}/bin/{}",
                asset.version,
                java_binary_name()
            )));
        }
        fs::write(temporary.join(JavaRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(java_executable_path(
                root,
                &asset.version,
                std::env::consts::OS,
                "java",
            )),
            Err(error) => {
                // A concurrent installer may have published the same version
                // while this one was extracting. Accept it only when its
                // receipt proves the same verified bytes; otherwise report the
                // conflict rather than the less useful rename error.
                let _ = fs::remove_dir_all(&temporary);
                match java_existing_install(root, &asset.version, &asset.sha256) {
                    Ok(Some(existing)) => Ok(existing),
                    Ok(None) => Err(runtime_io(root, &error)),
                    Err(conflict) => Err(conflict),
                }
            }
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, SHA-256-verifies, and atomically installs a Go SDK below the
/// caller-provided `nenv` directory.
///
/// # Errors
///
/// Returns without publishing a partial install when download, verification,
/// extraction, or binary discovery fails.
pub fn install_go_sdk_with_progress<F>(
    root: &Path,
    asset: &GoSdkAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(GoSdkProgress),
{
    let binary = root.join("go").join("bin").join(go_binary_name());
    if usable_file(&binary) && receipt_matches(&root.join(GoRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Go install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "go-download")?;
    let temporary = temporary_path(parent, "go-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(GoSdkProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(GoSdkProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        let binary = temporary.join("go").join("bin").join(go_binary_name());
        if !usable_file(&binary) {
            return Err(runtime_error("Go SDK archive did not provide go"));
        }
        fs::write(temporary.join(GoRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(root.join("go").join("bin").join(go_binary_name())),
            Err(_) if usable_file(&root.join("go").join("bin").join(go_binary_name())) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(root.join("go").join("bin").join(go_binary_name()))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, checksum-verifies, and atomically publishes a Node.js runtime.
///
/// # Errors
///
/// Returns without publishing a partial install if download, verification,
/// extraction, or binary discovery fails.
pub fn install_node_runtime_with_progress<F>(
    root: &Path,
    asset: &NodeRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(NodeRuntimeProgress),
{
    let binary = node_binary(root, &asset.version);
    if usable_file(&binary) && receipt_matches(&root.join(NodeRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Node.js install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "node-download")?;
    let temporary = temporary_path(parent, "node-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(NodeRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(NodeRuntimeProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else if has_suffix(&asset.url, ".tar.xz") {
            extract_xz_tar(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        let binary = node_binary(&temporary, &asset.version);
        if !usable_file(&binary) {
            return Err(runtime_error("Node.js archive did not provide node"));
        }
        fs::write(temporary.join(NodeRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(node_binary(root, &asset.version)),
            Err(_) if usable_file(&node_binary(root, &asset.version)) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(node_binary(root, &asset.version))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, verifies, and atomically publishes a Zig runtime.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification, or extraction failure.
pub fn install_zig_runtime_with_progress<F>(
    root: &Path,
    asset: &ZigRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(ZigRuntimeProgress),
{
    let binary = zig_binary(root, &asset.version);
    if usable_file(&binary) && receipt_matches(&root.join(ZigRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Zig install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "zig-download")?;
    let temporary = temporary_path(parent, "zig-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(ZigRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(ZigRuntimeProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_xz_tar(&archive, &temporary)?;
        }
        if !usable_file(&zig_binary(&temporary, &asset.version)) {
            return Err(runtime_error("Zig archive did not provide zig"));
        }
        fs::write(temporary.join(ZigRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(zig_binary(root, &asset.version)),
            Err(_) if usable_file(&zig_binary(root, &asset.version)) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(zig_binary(root, &asset.version))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, verifies, and atomically publishes a Deno runtime.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification, or extraction failure.
pub fn install_deno_runtime_with_progress<F>(
    root: &Path,
    asset: &DenoRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(DenoRuntimeProgress),
{
    let binary = root.join(deno_binary_name());
    if usable_file(&binary) && receipt_matches(&root.join(DenoRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Deno install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "deno-download")?;
    let temporary = temporary_path(parent, "deno-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(DenoRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(DenoRuntimeProgress::Extracting);
        extract_zip(&archive, &temporary)?;
        if !usable_file(&temporary.join(deno_binary_name())) {
            return Err(runtime_error("Deno archive did not provide deno"));
        }
        fs::write(temporary.join(DenoRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(root.join(deno_binary_name())),
            Err(_) if usable_file(&root.join(deno_binary_name())) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(root.join(deno_binary_name()))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, verifies, and atomically publishes a uv runtime.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification, or extraction failure.
pub fn install_uv_runtime_with_progress<F>(
    root: &Path,
    asset: &UvRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(UvRuntimeProgress),
{
    let binary = uv_binary(root);
    if usable_file(&binary) && receipt_matches(&root.join(UvRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("uv install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "uv-download")?;
    let temporary = temporary_path(parent, "uv-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(UvRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(UvRuntimeProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        if !usable_file(&uv_binary(&temporary)) {
            return Err(runtime_error("uv archive did not provide uv"));
        }
        fs::write(temporary.join(UvRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(uv_binary(root)),
            Err(_) if usable_file(&uv_binary(root)) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(uv_binary(root))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Installs a Rust toolchain with a verified rustup bootstrapper in nenv-owned state.
///
/// # Errors
///
/// Returns without publishing a partial install if bootstrap download or toolchain install fails.
pub fn install_rust_runtime_with_progress<F>(
    root: &Path,
    asset: &RustRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(RustRuntimeProgress),
{
    let binary = rust_toolchain_binary(root, &asset.version, "rustc");
    if usable_file(&binary) && receipt_matches(&root.join(RustRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Rust install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let bootstrap_directory = temporary_path(parent, "rustup-bootstrap")?;
    let bootstrap = bootstrap_directory.join(if cfg!(windows) {
        "rustup-init.exe"
    } else {
        "rustup-init"
    });
    let temporary = temporary_path(parent, "rust-install")?;
    let result = (|| {
        fs::create_dir(&bootstrap_directory)
            .map_err(|error| runtime_io(&bootstrap_directory, &error))?;
        download_sha256_archive(&asset.url, &bootstrap, &asset.sha256, |received, total| {
            progress(RustRuntimeProgress::Downloading { received, total });
        })?;
        #[cfg(unix)]
        fs::set_permissions(&bootstrap, PermissionsExt::from_mode(0o700))
            .map_err(|error| runtime_io(&bootstrap, &error))?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(RustRuntimeProgress::Extracting);
        let status = Command::new(&bootstrap)
            .args([
                "-y",
                "--no-modify-path",
                "--profile",
                "minimal",
                "--default-toolchain",
            ])
            .arg(&asset.version)
            .env("RUSTUP_HOME", temporary.join("rustup"))
            .env("CARGO_HOME", temporary.join("cargo"))
            .status()
            .map_err(|error| runtime_error(format!("failed to start rustup-init: {error}")))?;
        if !status.success() {
            return Err(runtime_error(format!("rustup-init exited with {status}")));
        }
        if !usable_file(&rust_toolchain_binary(&temporary, &asset.version, "rustc")) {
            return Err(runtime_error("rustup did not provide rustc"));
        }
        fs::write(temporary.join(RustRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(rust_toolchain_binary(root, &asset.version, "rustc")),
            Err(_) if usable_file(&rust_toolchain_binary(root, &asset.version, "rustc")) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(rust_toolchain_binary(root, &asset.version, "rustc"))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_dir_all(&bootstrap_directory);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, verifies, and atomically publishes Odin with its support directories intact.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification, or extraction failure.
pub fn install_odin_runtime_with_progress<F>(
    root: &Path,
    asset: &OdinRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(OdinRuntimeProgress),
{
    let binary = odin_binary(root);
    if usable_file(&binary) && receipt_matches(&root.join(OdinRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Odin install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "odin-download")?;
    let temporary = temporary_path(parent, "odin-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(OdinRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(OdinRuntimeProgress::Extracting);
        if has_suffix(&asset.url, ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        if !usable_file(&odin_binary(&temporary)) {
            return Err(runtime_error("Odin archive did not provide odin"));
        }
        fs::write(temporary.join(OdinRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(odin_binary(root)),
            Err(_) if usable_file(&odin_binary(root)) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(odin_binary(root))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, verifies, and atomically publishes a standalone Python runtime.
///
/// # Errors
///
/// Returns without publishing a partial install on transfer, verification, or extraction failure.
pub fn install_python_runtime_with_progress<F>(
    root: &Path,
    asset: &PythonRuntimeAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(PythonRuntimeProgress),
{
    let binary = python_binary(root);
    if usable_file(&binary) && receipt_matches(&root.join(PythonRuntime.receipt()), &asset.sha256) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("Python install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "python-download")?;
    let temporary = temporary_path(parent, "python-install")?;
    let result = (|| {
        download_sha256_archive(&asset.url, &archive, &asset.sha256, |received, total| {
            progress(PythonRuntimeProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(PythonRuntimeProgress::Extracting);
        extract_gzip_tar(&archive, &temporary)?;
        if !usable_file(&python_binary(&temporary)) {
            return Err(runtime_error("Python archive did not provide python"));
        }
        fs::write(temporary.join(PythonRuntime.receipt()), &asset.sha256)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(python_binary(root)),
            Err(_) if usable_file(&python_binary(root)) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(python_binary(root))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Downloads, SHA-512-verifies, and atomically installs a resolved .NET SDK
/// under the caller-supplied nenv-owned directory.
///
/// # Errors
///
/// Returns a runtime diagnostic without publishing a partial installation when
/// the transfer, digest verification, archive extraction, or binary check fails.
pub fn install_dotnet_sdk(root: &Path, asset: &DotnetSdkAsset) -> Result<PathBuf, Diagnostic> {
    install_dotnet_sdk_with_progress(root, asset, |_| {})
}

/// Downloads, verifies, and atomically installs a resolved .NET SDK while
/// reporting transfer and extraction progress.
///
/// # Errors
///
/// Returns the same errors as [`install_dotnet_sdk`]. Progress callbacks are
/// invoked only for work performed during this call; an already-installed SDK
/// returns immediately.
pub fn install_dotnet_sdk_with_progress<F>(
    root: &Path,
    asset: &DotnetSdkAsset,
    mut progress: F,
) -> Result<PathBuf, Diagnostic>
where
    F: FnMut(DotnetSdkProgress),
{
    let binary = root.join(dotnet_binary_name());
    if usable_file(&binary) && receipt_matches(&root.join(DotnetRuntime.receipt()), &asset.sha512) {
        return Ok(binary);
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error(".NET install root has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let archive = temporary_path(parent, "dotnet-download")?;
    let temporary = temporary_path(parent, "dotnet-install")?;
    let result = (|| {
        download_dotnet_sdk(&asset.url, &archive, &asset.sha512, |received, total| {
            progress(DotnetSdkProgress::Downloading { received, total });
        })?;
        fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
        progress(DotnetSdkProgress::Extracting);
        if has_suffix(&asset.url.to_ascii_lowercase(), ".zip") {
            extract_zip(&archive, &temporary)?;
        } else {
            extract_gzip_tar(&archive, &temporary)?;
        }
        let binary = temporary.join(dotnet_binary_name());
        if !usable_file(&binary) {
            return Err(runtime_error(".NET SDK archive did not provide dotnet"));
        }
        fs::write(temporary.join(DotnetRuntime.receipt()), &asset.sha512)
            .map_err(|error| runtime_io(&temporary, &error))?;
        match fs::rename(&temporary, root) {
            Ok(()) => Ok(root.join(dotnet_binary_name())),
            Err(_) if usable_file(&root.join(dotnet_binary_name())) => {
                let _ = fs::remove_dir_all(&temporary);
                Ok(root.join(dotnet_binary_name()))
            }
            Err(error) => Err(runtime_io(root, &error)),
        }
    })();
    let _ = fs::remove_file(&archive);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

pub(super) fn select_dotnet_channel<'a>(
    channels: &'a [DotnetChannel],
    requested: &str,
    platform: &Platform,
) -> Result<&'a DotnetChannel, Diagnostic> {
    let requested_channel = requested
        .split_once('.')
        .and_then(|(major, minor)| major.parse::<u32>().ok().zip(minor.parse::<u32>().ok()))
        .map(|(major, minor)| format!("{major}.{minor}"));
    if let Some(channel) = requested_channel {
        return channels
            .iter()
            .find(|candidate| candidate.version == channel)
            .ok_or_else(|| {
                runtime_error(format!(".NET SDK {requested} has no supported channel"))
            });
    }
    channels
        .iter()
        .filter(|channel| {
            !channel.latest_sdk.contains('-')
                && matches!(channel.support_phase.as_str(), "active" | "maintenance")
        })
        .max_by_key(|channel| dotnet_channel_key(&channel.version))
        .ok_or_else(|| {
            runtime_error(format!(
                "no stable .NET SDK is available for {}/{}",
                platform.os, platform.arch
            ))
        })
}

pub(super) fn dotnet_channel_key(version: &str) -> (u32, u32) {
    let mut parts = version
        .split('.')
        .filter_map(|part| part.parse::<u32>().ok());
    (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    )
}

pub(super) fn dotnet_rid(platform: &Platform) -> Result<&'static str, Diagnostic> {
    match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => Ok("linux-x64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos" | "darwin", "x86_64") => Ok("osx-x64"),
        ("macos" | "darwin", "aarch64") => Ok("osx-arm64"),
        ("windows", "x86_64") => Ok("win-x64"),
        ("windows", "aarch64") => Ok("win-arm64"),
        _ => Err(runtime_error(format!(
            ".NET SDK does not support {}/{}",
            platform.os, platform.arch
        ))),
    }
}

pub(super) fn dotnet_binary_name() -> &'static str {
    if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    }
}

pub(super) fn go_binary_name() -> &'static str {
    if cfg!(windows) { "go.exe" } else { "go" }
}

/// The Rust target triple for the machine this code is running on.
///
/// **Six places computed this independently** and two of them were byte-identical
/// copies containing a dead `cfg!(windows)` branch -- `uv_binary` and
/// `rust_toolchain_binary` both returned early on Windows and then branched on
/// `cfg!(windows)` again inside the triple, so the `*-pc-windows-msvc` strings in
/// `uv_binary` were unreachable. Clippy cannot see it, because `cfg!` is a bool
/// expression rather than a statement, so the compiler never learns the branch is
/// dead.
///
/// That duplication is not cosmetic. The **resolver** builds a download URL from one
/// copy of a triple and the **binary path helper** looks for the extracted file using
/// another, with nothing tying them together. When they disagree the install does not
/// report a path bug -- it reports `uv archive did not provide uv`, which sends the
/// reader to the archive instead of to the code. A single definition makes that
/// divergence impossible rather than merely unlikely.
///
/// `node_binary` and `zig_binary` deliberately do **not** use this: they take a
/// `version` because their archive layouts embed it, and they are a different naming
/// scheme (node's `v<version>-<platform>-<arch>`, zig's `<arch>-<os>-<version>`)
/// rather than a Rust triple. Forcing them through this would be the duplication
/// coming back wearing a different hat.
/// **A runtime this project installed: where it lives and what it needs to be
/// usable.**
///
/// Produced by [`installed_runtimes`] and consumed by the shell-activation diff, so it
/// carries exactly what a caller needs to put a runtime on `PATH` and to set the
/// variables the runtime reads at launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRuntime {
    /// The runtime's own name — `go`, `node`, `python` — as the user spells it.
    pub id: String,
    /// The resolved version, which is also the directory name under the data root.
    pub version: String,
    /// The install root; the receipt and the runtime's own tree live beneath it.
    pub root: PathBuf,
    /// The directory to prepend to `PATH`.
    pub bin_dir: PathBuf,
    /// Variables this runtime needs, in the order they must be applied.
    pub environment: Vec<(String, String)>,
}

/// **A runtime asset resolved for a concrete version and platform: what to download and
/// what to check it against.**
///
/// The eleven per-runtime `*RuntimeAsset` structs were field-for-field identical —
/// `{version, url, sha256}` — except that .NET carries a `sha512`. Rather than collapse
/// those eleven types now, this is the shape they all reduce to, so the trait can speak one
/// type while every existing resolver keeps returning its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRuntime {
    /// The resolved version, never the literal string `latest`.
    pub version: String,
    pub url: String,
    /// The expected digest, lowercase hex. Read it through
    /// [`RuntimeLayout::digest_algorithm`]; the two are separate because .NET is
    /// SHA-512 and conflating them would be a verification bug waiting to happen.
    pub digest: String,
}

/// **One runtime's layout: what it calls itself, how a complete install is recognised,
/// and what it needs to be usable.**
///
/// The eleven runtimes shipped here each answered these three questions in their own
/// installer function, in a shape no other runtime could reuse: eleven receipt filenames,
/// eleven binary-path helpers, and — for the four that need it — hand-written `export` lines
/// in a generated launcher string. That is why adding one was twelve tickets' worth of
/// work rather than a table row, and it is why `RuntimeSpec` is being introduced from the
/// *install* end rather than the *fetch* end: the layout is what a caller has to know
/// about, and today nothing states it.
///
/// **This is deliberately narrower than the trait in #514.** It does not carry
/// `latest()`, `asset()` or `Channel`, because none of those has a consumer yet and an
/// unused trait method is an interface that can be wrong without anything noticing. They
/// arrive when the fetch side is unified, and by then the eleven implementors below are the
/// test corpus for them.
pub trait RuntimeLayout: Send + Sync {
    /// The runtime's name, and the directory it installs beneath.
    fn id(&self) -> &'static str;

    /// The file whose presence marks a **complete** install published by the
    /// installer. It is a marker, not a signature.
    ///
    /// Enumeration reads nothing else. A directory without this file is not reported,
    /// which is what stops a half-extracted or foreign directory from putting a broken
    /// runtime on `PATH` — the same rule the tool installer already applies to its
    /// storage directory.
    fn receipt(&self) -> &'static str;

    /// The directory holding this runtime's executables, given its install root.
    ///
    /// Not derivable from the id: `go` is `go/bin`, `python` is `python/bin`, `node` and
    /// `zig` embed the version in the directory name, and `uv` puts the executable at the
    /// top level. That is five shapes, and guessing one is how a runtime ends up installed
    /// and unreachable.
    fn bin_dir(&self, root: &Path, version: &str) -> PathBuf;

    /// Variables this runtime needs in order to run, in application order.
    ///
    /// This older signature is retained for layout implementations and callers
    /// that only need the install root. Runtimes whose home depends on the
    /// installed version override [`RuntimeLayout::environment_for`] instead.
    fn environment(&self, _root: &Path) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Variables this runtime needs in order to run, with the installed version
    /// available.
    ///
    /// The default delegates to [`RuntimeLayout::environment`], so an existing
    /// implementation keeps working unchanged. Java overrides this because its
    /// home is `<install-root>/<release-directory>` on Unix and Windows, and
    /// `<install-root>/<release-directory>/Contents/Home` in a macOS bundle.
    fn environment_for(&self, root: &Path, _version: &str) -> Vec<(String, String)> {
        self.environment(root)
    }

    /// The digest [`RuntimeLayout::resolve`] produces, as an algorithm name.
    ///
    /// **Separate from the digest rather than encoded in it.** Ten of the eleven are
    /// SHA-256 and .NET is SHA-512, and a 64-character field that is sometimes a SHA-512
    /// is a verification bug waiting to happen. The algorithm travels with the value.
    fn digest_algorithm(&self) -> &'static str {
        "sha256"
    }

    /// Resolve `requested` for `platform` to a concrete asset.
    ///
    /// `requested` is a version, or `latest` (or empty) for the newest the publisher
    /// offers. **Every one of the eleven resolvers already has exactly this signature** —
    /// `fn(version: &str, platform: &Platform) -> Result<XRuntimeAsset, Diagnostic>` — so
    /// this method is a uniform seam over tested code rather than a rewrite. What it buys
    /// is that "which runtimes can be upgraded, and to what" becomes answerable without a
    /// caller naming a resolver per runtime.
    ///
    /// An implementor must **refuse a platform it has no artifact for**, naming what it
    /// does have. It must never substitute a nearby version or architecture: that is the
    /// silent wrong install this project exists to prevent, and a runtime that downloads
    /// the wrong build is worse than one that declines.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic naming the runtime, the version and the platform when the
    /// publisher has no artifact for that combination, or when the release index cannot
    /// be read. The diagnostic is the whole answer here — there is no partial result and
    /// no fallback path, so a caller cannot mistake a refusal for a resolution.
    fn resolve(&self, requested: &str, platform: &Platform) -> Result<ResolvedRuntime, Diagnostic>;
}

/// The eleven runtimes this project installs today, in one place.
///
/// A list rather than eleven `match` arms at each call site, because the call sites are
/// exactly where they have drifted: the receipts were eleven string literals spread through
/// eleven installer functions, and nothing could check that the one written was the one
/// enumeration looked for.
pub const RUNTIME_LAYOUTS: &[&dyn RuntimeLayout] = &[
    &GoRuntime,
    &NodeRuntime,
    &DotnetRuntime,
    &ZigRuntime,
    &DenoRuntime,
    &UvRuntime,
    &RustRuntime,
    &OdinRuntime,
    &PythonRuntime,
    &JavaRuntime,
    &BunRuntime,
];

/// Declares one runtime's row in [`RUNTIME_LAYOUTS`].
///
/// The arms are positional: `id` and `receipt`, then exactly one of `resolve` or
/// `resolve_sha512`, then `bin_dir`, then the optional `env`.
///
/// **The two resolve arms are distinct rather than one arm with a digest parameter**
/// because the eight SHA-256 assets name their field `sha256` and only .NET names it
/// `sha512`, and a single arm taking the field name as an argument cannot be checked
/// against the algorithm it claims. Choosing the arm *is* the claim: `resolve_sha512`
/// emits `digest_algorithm() == "sha512"` and reads `asset.sha512`, so the algorithm and
/// the field cannot disagree.
macro_rules! runtime_layout {
    (
        $(#[$meta:meta])*
        $name:ident, $id:literal, $receipt:expr
        $(, resolve = $resolve:path)?
        $(, resolve_sha512 = $resolve512:path)?
        , bin_dir = |$root:ident, $version:ident| $body:expr
        $(, env = |$r2:ident| $envbody:expr)?
        $(, env_for = |$r3:ident, $ev:ident| $envbody_for:expr)?
        $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl RuntimeLayout for $name {
            fn id(&self) -> &'static str {
                $id
            }

            fn receipt(&self) -> &'static str {
                $receipt
            }

            $(
                fn resolve(
                    &self,
                    requested: &str,
                    platform: &Platform,
                ) -> Result<ResolvedRuntime, Diagnostic> {
                    let asset = $resolve(requested, platform)?;
                    Ok(ResolvedRuntime {
                        version: asset.version,
                        url: asset.url,
                        digest: asset.sha256,
                    })
                }
            )?

            $(
                fn digest_algorithm(&self) -> &'static str {
                    "sha512"
                }

                fn resolve(
                    &self,
                    requested: &str,
                    platform: &Platform,
                ) -> Result<ResolvedRuntime, Diagnostic> {
                    let asset = $resolve512(requested, platform)?;
                    Ok(ResolvedRuntime {
                        version: asset.version,
                        url: asset.url,
                        digest: asset.sha512,
                    })
                }
            )?

            fn bin_dir(&self, $root: &Path, $version: &str) -> PathBuf {
                let ($root, $version) = ($root, $version);
                $body
            }

            $(
                fn environment(&self, $r2: &Path) -> Vec<(String, String)> {
                    let $r2 = $r2;
                    $envbody
                }
            )?

            $(
                fn environment_for(&self, $r3: &Path, $ev: &str) -> Vec<(String, String)> {
                    let $r3 = $r3;
                    $envbody_for
                }
            )?
        }
    };
}

runtime_layout!(
    /// Go. The SDK tarball nests everything under `go/`, so the executables are one
    /// level below the root rather than at it.
    GoRuntime,
    "go",
    neoenv_core::names::GO_SDK_RECEIPT,
    resolve = resolve_go_sdk,
    bin_dir = |root, _version| root.join("go").join("bin"),
    env = |root| vec![
        ("GOROOT".to_owned(), root.display().to_string()),
        (
            "GOPATH".to_owned(),
            root.join("gopath").display().to_string(),
        ),
    ],
);

runtime_layout!(
    /// Node.js. The archive's top directory embeds the version, so the bin directory
    /// cannot be computed without it. Windows puts `node.exe` at that directory's root;
    /// other platforms put `node` under `bin/`.
    NodeRuntime,
    "node",
    neoenv_core::names::NODE_RUNTIME_RECEIPT,
    resolve = resolve_node_runtime,
    bin_dir = |root, version| {
        let archive_dir = root.join(node_archive_dir(version));
        if cfg!(windows) {
            archive_dir
        } else {
            archive_dir.join("bin")
        }
    },
);

runtime_layout!(
    /// The .NET SDK. `dotnet` itself sits at the root, and it needs `DOTNET_ROOT` set
    /// because the host resolves its own installation relative to the executable unless
    /// it is told where it is.
    DotnetRuntime,
    "dotnet",
    neoenv_core::names::DOTNET_SDK_RECEIPT,
    resolve_sha512 = resolve_dotnet_sdk,
    bin_dir = |root, _version| root.to_path_buf(),
    env = |root| vec![("DOTNET_ROOT".to_owned(), root.display().to_string())],
);

runtime_layout!(
    /// Zig. Like Node, the directory name carries the version and the OS/arch.
    ZigRuntime,
    "zig",
    neoenv_core::names::ZIG_RUNTIME_RECEIPT,
    resolve = resolve_zig_runtime,
    bin_dir = |root, version| root.join(zig_archive_dir(version)),
);

runtime_layout!(
    /// Deno. A single executable at the top level.
    DenoRuntime,
    "deno",
    neoenv_core::names::DENO_RUNTIME_RECEIPT,
    resolve = resolve_deno_runtime,
    bin_dir = |root, _version| root.to_path_buf(),
);

runtime_layout!(
    /// uv. The Unix tarballs nest the executable under a target-named directory and the
    /// Windows zip puts it at the top level, so the shape is host-dependent.
    UvRuntime,
    "uv",
    neoenv_core::names::UV_RUNTIME_RECEIPT,
    resolve = resolve_uv_runtime,
    bin_dir = |root, _version| {
        if cfg!(windows) {
            root.to_path_buf()
        } else {
            root.join(format!("uv-{}", host_target()))
        }
    },
);

runtime_layout!(
    /// A Rust toolchain managed by `rustup`, with `nenv`'s own `RUSTUP_HOME` and
    /// `CARGO_HOME` so it cannot pick up — or be picked up by — a user's own rustup.
    ///
    /// `RUSTUP_HOME` is what makes the isolation work, and it is the reason this runtime
    /// sets environment at all: without it `rustup` resolves against `$HOME/.rustup`
    /// and a `rust-toolchain.toml` in the project would select a toolchain the user
    /// installed rather than the one `nenv` installed.
    RustRuntime,
    "rust",
    neoenv_core::names::RUST_RUNTIME_RECEIPT,
    resolve = resolve_rust_runtime,
    bin_dir = |root, version| {
        root.join("rustup")
            .join("toolchains")
            .join(format!("{version}-{}", host_target()))
            .join("bin")
    },
    env = |root| {
        vec![
            (
                "RUSTUP_HOME".to_owned(),
                root.join("rustup").display().to_string(),
            ),
            (
                "CARGO_HOME".to_owned(),
                root.join("cargo").display().to_string(),
            ),
        ]
    },
);

runtime_layout!(
    /// Odin. Its archive nests the executable under `dist/` or a versioned directory, so
    /// the location is probed rather than computed.
    OdinRuntime,
    "odin",
    neoenv_core::names::ODIN_RUNTIME_RECEIPT,
    resolve = resolve_odin_runtime,
    bin_dir = |root, _version| odin_binary(root)
        .parent()
        .map_or_else(|| root.to_path_buf(), Path::to_path_buf),
);

runtime_layout!(
    /// A `CPython` standalone build, which nests under `python/`.
    PythonRuntime,
    "python",
    neoenv_core::names::PYTHON_RUNTIME_RECEIPT,
    resolve = resolve_python_runtime,
    bin_dir = |root, _version| {
        if cfg!(windows) {
            root.join("python")
        } else {
            root.join("python").join("bin")
        }
    },
);

runtime_layout!(
    /// Bun. The zip nests the executable in a platform-named directory, so the
    /// bin directory is a function of the host rather than the version.
    BunRuntime,
    "bun",
    neoenv_core::names::BUN_RUNTIME_RECEIPT,
    resolve = resolve_bun_runtime,
    bin_dir = |root, _version| bun_binary_directory(root),
);

runtime_layout!(
    /// Eclipse Temurin. The archive unpacks to a `jdk-*` directory whose name is
    /// Adoptium's release name, and the asset version is that directory name.
    /// `JAVA_HOME` names that release directory beneath the install root, which
    /// avoids reconstructing a directory from a semver string that differs from
    /// it (`21.0.13+9.0.LTS` versus `jdk-21.0.13+9`).
    JavaRuntime,
    "java",
    neoenv_core::names::JAVA_RUNTIME_RECEIPT,
    resolve = resolve_java_runtime,
    bin_dir = |root, version| java_home_directory(root, version).join("bin"),
    env_for = |root, version| {
        vec![(
            "JAVA_HOME".to_owned(),
            java_home_directory(root, version).display().to_string(),
        )]
    },
);

/// Every runtime under `data_root` that carries a **complete install receipt.
///
/// Enumeration is deliberately read-only and evidence-based: a runtime is reported only
/// when its receipt is present, so a half-extracted directory, a version that failed
/// verification, or a directory a user put there by hand are all invisible to the shell.
/// **The receipt is self-attesting.** This is the shell-activation enumeration, not a
/// provenance check; a process launch uses [`runtime_install_evidence`] and an external
/// execute grant instead.
///
/// Versions are reported newest-last within a runtime, so a caller that prepends in
/// iteration order ends up with the **oldest** first and the newest last — which is the
/// wrong precedence for a `PATH` prepend. Callers that want the newest to win iterate
/// this in reverse, as `activation_diff` already does for tools.
#[must_use]
pub fn installed_runtimes(data_root: &Path) -> Vec<InstalledRuntime> {
    let mut found = Vec::new();
    for layout in RUNTIME_LAYOUTS {
        let runtime_root = data_root.join(layout.id());
        let Ok(entries) = fs::read_dir(&runtime_root) else {
            continue;
        };
        // `read_dir` order is unspecified, so collect and sort rather than depend on it.
        let mut versions: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        // **Oldest first, by version precedence — and that is the whole contract here.**
        // `activation::runtime_diff` prepends each runtime's `PATH` entry and sets each of
        // its variables, so the *last* write wins, so this function's order decides which
        // installed version reaches the shell. `versions.sort()` sorted bytes, which put
        // `1.10.0` before `1.9.0`: oldest-first became untrue at exactly the digit-width
        // boundary, the newest version stopped being last, and a user with Go 1.9 and
        // Go 1.10 installed silently got 1.9 on their `PATH`.
        versions.sort_by(|left, right| neoenv_core::version::compare_versions(left, right));
        for version in versions {
            let root = runtime_root.join(&version);
            if !root.join(layout.receipt()).is_file() {
                continue;
            }
            found.push(InstalledRuntime {
                id: layout.id().to_owned(),
                version: version.clone(),
                bin_dir: layout.bin_dir(&root, &version),
                environment: layout.environment_for(&root, &version),
                root,
            });
        }
    }
    found
}

/// Structural evidence for one runtime install, used by a versioned runner.
///
/// **This is not provenance and not a version proof.** `version` is the
/// install directory's label. `digest` is the receipt text and is only checked
/// for shape; it is not bound to the executable, and the executable is not
/// proven to be that version. There is no signature or external manifest to
/// compare against. A runner therefore additionally requires an external
/// `execute` grant; see `docs/task-runners.md`.
///
/// The executable path and the filesystem identities are retained so a runner
/// can notice a root or binary replaced between enumeration and execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInstallEvidence {
    pub id: String,
    /// Directory label. Not independently proven to match the binary.
    pub version: String,
    /// The install root the receipt and binary must stay under.
    pub root: PathBuf,
    /// The directory to prepend to `PATH`.
    pub bin_dir: PathBuf,
    /// The exact executable path selected by enumeration.
    pub binary: PathBuf,
    /// The exact receipt file whose contents were read.
    pub receipt: PathBuf,
    /// The trimmed receipt text, retained for a second structural check at use.
    pub digest: String,
    /// Identity of the install root at enumeration, when the platform has one.
    pub root_identity: Option<InstallIdentity>,
    /// Identity of the executable at enumeration, when the platform has one.
    pub binary_identity: Option<InstallIdentity>,
}

/// Enumerates runtimes with structurally complete receipt and executable files.
///
/// Unlike [`installed_runtimes`], this does **not** treat the presence of a
/// receipt file as sufficient. It requires:
///
/// - a real version directory, not a symlink;
/// - a real receipt file, not a symlink, containing lowercase hex of the
///   layout's digest length;
/// - a real `bin_dir` inside the install root; and
/// - a usable executable there, with `uv` additionally requiring the exact
///   `uv` binary the layout names.
///
/// These are structural checks only. The version label and the receipt digest
/// are not authenticated, and the digest is not a hash of the executable. This
/// is the enumeration a versioned task runner uses; it is deliberately separate
/// from [`installed_runtimes`] so shell activation keeps its existing contract.
#[must_use]
pub fn runtime_install_evidence(data_root: &Path) -> Vec<RuntimeInstallEvidence> {
    let mut found = Vec::new();
    for layout in RUNTIME_LAYOUTS {
        let runtime_root = data_root.join(layout.id());
        let Ok(entries) = fs::read_dir(&runtime_root) else {
            continue;
        };
        let mut versions: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        versions.sort_by(|left, right| neoenv_core::version::compare_versions(left, right));
        for version in versions {
            let root = runtime_root.join(&version);
            if let Some(runtime) = runtime_install_evidence_for(*layout, &root, &version) {
                found.push(runtime);
            }
        }
    }
    found
}

fn runtime_install_evidence_for(
    layout: &dyn RuntimeLayout,
    root: &Path,
    version: &str,
) -> Option<RuntimeInstallEvidence> {
    // `symlink_metadata` on the version directory rejects a symlinked install
    // without following it to somewhere else.
    let root_metadata = fs::symlink_metadata(root).ok()?;
    if !root_metadata.file_type().is_dir() {
        return None;
    }
    let receipt = root.join(layout.receipt());
    let receipt_metadata = fs::symlink_metadata(&receipt).ok()?;
    if !receipt_metadata.file_type().is_file() {
        return None;
    }
    let digest = fs::read_to_string(&receipt).ok()?.trim().to_owned();
    if !receipt_digest_is_well_formed(&digest, layout.digest_algorithm()) {
        return None;
    }
    let bin_dir = layout.bin_dir(root, version);
    let bin_metadata = fs::symlink_metadata(&bin_dir).ok()?;
    if !bin_metadata.file_type().is_dir() {
        return None;
    }
    let canonical_root = root.canonicalize().ok()?;
    if !bin_dir.canonicalize().ok()?.starts_with(&canonical_root) {
        return None;
    }
    let binary = if layout.id() == "uv" {
        uv_binary(root)
    } else {
        let entries = fs::read_dir(&bin_dir).ok()?;
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| usable_file(path))?
    };
    if !usable_file(&binary) || !binary.canonicalize().ok()?.starts_with(&canonical_root) {
        return None;
    }
    Some(RuntimeInstallEvidence {
        id: layout.id().to_owned(),
        version: version.to_owned(),
        root: root.to_owned(),
        bin_dir,
        binary: binary.clone(),
        receipt,
        digest,
        root_identity: InstallIdentity::of(root),
        binary_identity: InstallIdentity::of(&binary),
    })
}

fn receipt_digest_is_well_formed(digest: &str, algorithm: &str) -> bool {
    let length = match algorithm {
        "sha512" => 128,
        _ => 64,
    };
    digest.len() == length
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The archive suffix for a uv asset: a zip on Windows, a gzip tarball elsewhere.
pub(super) fn uv_extension(os: &str) -> &'static str {
    if os == "windows" { "zip" } else { "tar.gz" }
}

/// The uv download target and archive suffix for a platform, or `None` when uv
/// publishes nothing for it.
///
/// **Split out of `resolve_uv_runtime` so a test can reach it.** The resolver does
/// network I/O -- it resolves `latest`, then fetches `<url>.sha256` -- so the matrix was
/// only reachable by calling it, which made it untestable. An untestable matrix is a
/// matrix that silently drifts from the extraction path in [`uv_binary`], which computes
/// the same triple from [`host_target`]. It is a pure function of the platform and should
/// have been one from the start, and
/// `the_uv_resolver_and_the_extraction_path_agree_on_every_published_platform` is the
/// test that now holds the two together.
///
/// Refuses rather than approximating. uv ships no 32-bit ARM artifact, so a 32-bit ARM
/// host gets a named error rather than a 64-bit binary.
pub(super) fn uv_target(platform: &Platform) -> Option<(&'static str, &'static str)> {
    rust_target_triple(platform).map(|target| (target, uv_extension(&platform.os)))
}

/// The Rust target triple for a platform, or `None` when this project does not
/// recognise it.
///
/// **This replaces four byte-identical copies of the same six-line `match`.**
/// `resolve_deno_runtime`, `resolve_rust_runtime`, `resolve_python_runtime` and
/// `resolve_uv_runtime` each carried their own, and `uv_binary` and
/// `rust_toolchain_binary` carried two more written with `cfg!` — one of which had an
/// unreachable Windows arm. Six computations of one table, with nothing keeping them
/// equal.
///
/// The reason it matters is not tidiness. Each copy is the only thing standing between a
/// platform and a wrong-architecture download, and a copy that goes stale produces one of
/// the two failures this project exists to prevent:
///
/// - One that **disagrees** with the path the install later looks in reports
///   "archive did not provide &lt;tool&gt;", which blames the upstream publisher for a bug
///   in this file.
/// - One that **gains** a platform hands a host a build that does not exist for it, or an
///   existing build for the wrong one.
///
/// `None` means "not recognised" and every caller turns it into a named error. No caller
/// may substitute a nearby triple: that is the silent wrong install.
///
/// `node_binary` and `zig_binary` are deliberately not routed through this. Their archive
/// layouts embed the version and use a different naming scheme (`v<version>-<platform>-
/// <arch>`, `<arch>-<os>-<version>`), so they are not instances of this table and folding
/// them in would be the duplication returning in a new shape.
pub(super) fn rust_target_triple(platform: &Platform) -> Option<&'static str> {
    Some(match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos" | "darwin", "x86_64") => "x86_64-apple-darwin",
        ("macos" | "darwin", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

pub(super) fn host_target() -> &'static str {
    // One table, and this is a lookup in it rather than a second copy. The
    // fallback is unreachable on any platform Rust builds for -- the four
    // `cfg!` branches it used to spell out covered exactly the platforms the
    // table accepts -- and it is the *x86_64* one, because a host this code runs
    // on that the table does not recognise is a host whose triple we genuinely do
    // not know, and naming the common case beats panicking inside a path helper.
    rust_target_triple(&Platform::host()).unwrap_or("x86_64-unknown-linux-gnu")
}

pub(super) fn deno_binary_name() -> &'static str {
    if cfg!(windows) { "deno.exe" } else { "deno" }
}

pub(super) fn java_binary_name() -> &'static str {
    if cfg!(windows) { "java.exe" } else { "java" }
}

pub(super) fn bun_binary_name() -> &'static str {
    if cfg!(windows) { "bun.exe" } else { "bun" }
}

pub(super) fn uv_binary(root: &Path) -> PathBuf {
    // The Windows zip puts the executable at the root; the Unix tarballs nest it under
    // their target directory. Two layouts, so the early return is real -- but the
    // triple below it used to be computed a second time, with an unreachable Windows
    // arm, which is what `host_target` now exists to prevent.
    if cfg!(windows) {
        return root.join("uv.exe");
    }
    root.join(format!("uv-{}", host_target())).join("uv")
}

pub(super) fn rust_toolchain_binary(root: &Path, version: &str, name: &str) -> PathBuf {
    let extension = if cfg!(windows) { ".exe" } else { "" };
    root.join("rustup")
        .join("toolchains")
        .join(format!("{version}-{}", host_target()))
        .join("bin")
        .join(format!("{name}{extension}"))
}

pub(super) fn odin_binary(root: &Path) -> PathBuf {
    let binary = if cfg!(windows) { "odin.exe" } else { "odin" };
    let direct = root.join(binary);
    if direct.is_file() {
        direct
    } else if root.join("dist").join(binary).is_file() {
        root.join("dist").join(binary)
    } else {
        root.join("odin").join(binary)
    }
}

pub(super) fn python_binary(root: &Path) -> PathBuf {
    if cfg!(windows) {
        root.join("python").join("python.exe")
    } else {
        root.join("python").join("bin").join("python3")
    }
}

pub(super) fn python_asset_version(name: &str) -> (u32, u32, u32) {
    name.strip_prefix("cpython-")
        .and_then(|value| value.split_once('+').map(|(version, _)| version))
        .map(|version| {
            let mut parts = version.split('.').filter_map(|part| part.parse().ok());
            (
                parts.next().unwrap_or_default(),
                parts.next().unwrap_or_default(),
                parts.next().unwrap_or_default(),
            )
        })
        .unwrap_or_default()
}

/// The OS and architecture pair Node.js names its archive directories with.
///
/// **Extracted so [`NodeRuntime::bin_dir`] and [`node_binary`] cannot disagree.** They
/// describe the same directory from two directions — one puts it on `PATH`, the other
/// looks for the executable in it — and a disagreement is invisible until a user finds
/// that `node` is installed and not runnable. That is the `uv_binary` defect this file
/// already had once, in the same shape.
pub(super) const fn node_archive_target() -> (&'static str, &'static str) {
    let platform = if cfg!(windows) {
        "win"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    (platform, arch)
}

/// The directory Node.js's archive unpacks into, relative to the install root.
pub(super) fn node_archive_dir(version: &str) -> String {
    let (platform, arch) = node_archive_target();
    format!("node-v{version}-{platform}-{arch}")
}

pub(super) fn node_binary(root: &Path, version: &str) -> PathBuf {
    let name = node_archive_dir(version);
    if cfg!(windows) {
        root.join(name).join("node.exe")
    } else {
        root.join(name).join("bin").join("node")
    }
}

/// The OS and architecture pair Zig names its archive directories with.
///
/// Single-sourced with [`ZigRuntime::bin_dir`] for the same reason as
/// [`node_archive_target`].
pub(super) const fn zig_archive_target() -> (&'static str, &'static str) {
    let os = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    (arch, os)
}

/// The directory Zig's archive unpacks into, relative to the install root.
pub(super) fn zig_archive_dir(version: &str) -> String {
    let (arch, os) = zig_archive_target();
    format!("zig-{arch}-{os}-{version}")
}

pub(super) fn zig_binary(root: &Path, version: &str) -> PathBuf {
    let binary = if cfg!(windows) { "zig.exe" } else { "zig" };
    root.join(zig_archive_dir(version)).join(binary)
}

pub(super) fn download_dotnet_sdk(
    url: &str,
    destination: &Path,
    expected_sha512: &str,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to download .NET SDK"))?;
    policy
        .validate_artifact_length(url, &response, ResourceBudget::default().artifact_bytes)
        .map_err(|error| http_error(error, "failed to download .NET SDK"))?;
    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let mut input =
        policy.streaming_reader_limited(url, response, ResourceBudget::default().artifact_bytes);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| runtime_io(destination, &error))?;
    let mut digest = Sha512::new();
    let mut buffer = vec![0_u8; 32 * 1024];
    let mut received = 0_u64;
    let mut reported = 0_u64;
    progress(received, total);
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| runtime_io(destination, &error))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        // `count` is a buffer length and therefore fits in `u64` on every
        // supported target.
        received += count as u64;
        output
            .write_all(&buffer[..count])
            .map_err(|error| runtime_io(destination, &error))?;
        if received - reported >= 1024 * 1024 || total == Some(received) {
            progress(received, total);
            reported = received;
        }
    }
    output
        .sync_all()
        .map_err(|error| runtime_io(destination, &error))?;
    if format!("{:x}", digest.finalize()) != expected_sha512 {
        return Err(runtime_error(".NET SDK SHA-512 verification failed"));
    }
    Ok(())
}

pub(super) fn download_sha256_archive(
    url: &str,
    destination: &Path,
    expected_sha256: &str,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        // Runtime artifacts are pinned to a publisher SHA-256 before extraction.
        // Follow the short-lived GitHub asset redirect used by verified releases.
        .get_with_redirects(url, 5)
        .map_err(|error| http_error(error, "failed to download runtime archive"))?;
    policy
        .validate_artifact_length(url, &response, ResourceBudget::default().artifact_bytes)
        .map_err(|error| http_error(error, "failed to download runtime archive"))?;
    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let mut input =
        policy.streaming_reader_limited(url, response, ResourceBudget::default().artifact_bytes);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| runtime_io(destination, &error))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 32 * 1024];
    let mut received = 0_u64;
    let mut reported = 0_u64;
    progress(received, total);
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| runtime_io(destination, &error))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        received += count as u64;
        output
            .write_all(&buffer[..count])
            .map_err(|error| runtime_io(destination, &error))?;
        if received - reported >= 1024 * 1024 || total == Some(received) {
            progress(received, total);
            reported = received;
        }
    }
    output
        .sync_all()
        .map_err(|error| runtime_io(destination, &error))?;
    if format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err(runtime_error("runtime archive SHA-256 verification failed"));
    }
    Ok(())
}
