//! Archive-format artifact extraction. Each layout is selected by a typed
//! `ArtifactPlan`, and every entry is containment- and budget-checked before
//! it is written.

use super::providers::npm_bins_from_package_json;
// `make_executable` is imported under `cfg(unix)` because all four of its call sites in
// this file are, and an unconditional import of a `cfg(unix)` item is the `E0432` this
// file once had. The other half of that fix over-corrected: it made the *function*
// unconditional, with a no-op body for non-unix, so the function compiled everywhere and
// was then never called -- two warnings on every Windows target, which
// `cargo check --target <windows>` with `-D warnings` reports and a native build cannot.
#[cfg(unix)]
use super::make_executable;
use super::{
    BudgetReader, Component, Diagnostic, ExtractionBudget, LockedTool, Path, Read, ResourceBudget,
    ResourceLimit, ResourceLimitError, Write, fs, runtime_error, runtime_error_with_cause,
    runtime_io, usable_file,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ArtifactLayout {
    NpmPackage,
    DotnetToolPackage,
    RubyGem,
    GzipTar,
    XzTar,
    Tar,
    Zip,
    RawBinary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArtifactPlan {
    pub(super) layout: ArtifactLayout,
}

impl ArtifactPlan {
    pub(super) fn from_locked_tool(tool: &LockedTool) -> Result<Self, Diagnostic> {
        // One lowercase, read by every arm below. This used to call
        // `to_ascii_lowercase` once per `has_suffix`, which is six allocations of
        // the whole URL to classify one artifact.
        let url = tool.url.to_ascii_lowercase();
        // **The layout arms read the *path*, not the URL.** `canonical_http_url`
        // rejects credentials and fragments but keeps the query, and a presigned
        // download carries one routinely, so `…/tool.tar.gz?token=abc` matched no
        // suffix arm and fell through to `RawBinary` — the same silent wrong install
        // the package guard exists to prevent, now for the *decodable* formats. The
        // previous commit fixed this for `container_url_refused` and left it open for
        // the five arms below, which is what made the fix half-applied.
        let name = path_name(&url);
        let layout = match tool.resolver.as_str() {
            "npm" => ArtifactLayout::NpmPackage,
            "dotnet-tool" => ArtifactLayout::DotnetToolPackage,
            "ruby-gems" => ArtifactLayout::RubyGem,
            _ if has_suffix(name, ".tar.gz") || has_suffix(name, ".tgz") => ArtifactLayout::GzipTar,
            _ if has_suffix(name, ".tar.xz") => ArtifactLayout::XzTar,
            _ if has_suffix(name, ".tar") => ArtifactLayout::Tar,
            _ if has_suffix(name, ".zip") => ArtifactLayout::Zip,
            // **A raw binary is only a raw binary when nothing says otherwise.**
            //
            // The catch-all used to be `tool.binaries.len() == 1`, which made *every*
            // packaging format a raw binary: a `.deb` is an `ar` archive, and
            // `extract_raw_binary` copies the blob to `bin/<name>`, marks it
            // executable, writes a receipt and publishes a launcher -- so the
            // install **succeeded** and the first run failed with
            // `Exec format error`. `cli/cli` shipped exactly that: the `.deb` at
            // asset 4, the real `.tar.gz` at asset 6, and first-match selection took
            // the `.deb`.
            //
            // `container_url_refused` reads `UNOPENABLE_EXTENSIONS`, which is *not*
            // `PROGRAM_EXTENSIONS`: the first version of this guard read that one and
            // so refused every `.tar.gz` the extractor exists to unpack, because `gz`
            // is a member of it. The list is "cannot be opened" -- packages, the
            // compression formats with no decoder here, and `ar`.
            //
            // `is_release_artifact` refuses the same names at *selection* time, where
            // the user still gets the whole candidate list; this is the backstop for
            // anything that reaches the installer anyway, notably through an explicit
            // `asset:` or `url:`, which the selection rule deliberately honors.
            _ if tool.binaries.len() == 1 && !container_url_refused(&url) => {
                ArtifactLayout::RawBinary
            }
            // **The advice has to match the reason, and there are three reasons.**
            //
            // The arm is reached whenever the suffix arms miss, which is *also* what
            // happens when a declaration names two binaries for a plain archive — so a
            // two-way branch left the residual case telling a user with a perfectly
            // good `.tar.gz` that "a distribution package cannot be installed as a
            // tool". Nothing in that sentence was true for those inputs.
            //
            // And one sentence for all of `UNOPENABLE_EXTENSIONS` was a dead end for
            // 12 of them: for `zst`/`bz2`/`7z`/`rar` and the rest there is no decoder
            // here, so no `asset:` can ever succeed and telling the user to declare one
            // sends them in a circle. 21 of 933 real selections hit the wrong
            // sentence, and `gh:restic/restic` has no alternative asset at all on
            // linux — it ships `.bz2` for every platform and no `.tar.gz`.
            _ if has_no_decoder(&url) => {
                return Err(runtime_error(format!(
                    "cannot extract unrecognized artifact type: {}. This project has no \
                     decoder for that compression format, so no `asset:` can make it \
                     installable; the formats it can unpack are .tar.gz, .tgz, .tar.xz, \
                     .tar and .zip",
                    tool.url
                )));
            }
            _ if container_url_refused(&url) => {
                return Err(runtime_error(format!(
                    "cannot extract unrecognized artifact type: {}. A distribution \
                     package cannot be installed as a tool, and a package's contents are \
                     not a binary; declare `asset:` with an archive from this release if \
                     it ships one",
                    tool.url
                )));
            }
            _ if tool.binaries.len() > 1 => {
                return Err(runtime_error(format!(
                    "cannot extract unrecognized artifact type: {}. This artifact is an \
                     archive, and {} binaries were declared for it; a single archive \
                     entry can only be one binary, so declare one with `bins: [name]`",
                    tool.url,
                    tool.binaries.len()
                )));
            }
            _ => {
                return Err(runtime_error(format!(
                    "cannot extract unrecognized artifact type: {}. It has no recognized \
                     archive extension and this release is not installable as a tool; \
                     declare `asset:` with the name of a file this project can unpack",
                    tool.url
                )));
            }
        };
        Ok(Self { layout })
    }
}

// Runtime-specific archive layouts are explicit at this boundary.
//
// The extraction budget is established before the layout is selected, so an
// artifact that is both unrecognized and over budget still reports the budget
// diagnostic. Selecting the layout first would swap that for a format error.
pub(super) fn extract_artifact(
    artifact: &Path,
    destination: &Path,
    tool: &LockedTool,
) -> Result<(), Diagnostic> {
    let mut budget = extraction_budget(artifact)?;
    let plan = ArtifactPlan::from_locked_tool(tool)?;
    match plan.layout {
        ArtifactLayout::NpmPackage => extract_npm_tarball(artifact, destination, tool, &mut budget),
        ArtifactLayout::DotnetToolPackage => {
            extract_dotnet_tool_package(artifact, destination, tool, &mut budget)
        }
        ArtifactLayout::RubyGem => extract_ruby_gem(artifact, destination, tool, &mut budget),
        ArtifactLayout::GzipTar => extract_tar_with_budget(
            flate2::read::GzDecoder::new(
                fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
            ),
            destination,
            &mut budget,
        ),
        ArtifactLayout::XzTar => extract_tar_with_budget(
            xz2::read::XzDecoder::new(
                fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
            ),
            destination,
            &mut budget,
        ),
        ArtifactLayout::Tar => extract_tar_with_budget(
            fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
            destination,
            &mut budget,
        ),
        ArtifactLayout::Zip => extract_zip_with_budget(artifact, destination, &mut budget),
        ArtifactLayout::RawBinary => extract_raw_binary(artifact, destination, tool),
    }
}

pub(super) fn extract_raw_binary(
    artifact: &Path,
    destination: &Path,
    tool: &LockedTool,
) -> Result<(), Diagnostic> {
    let [binary] = tool.binaries.as_slice() else {
        return Err(runtime_error("raw artifacts require exactly one binary"));
    };
    fs::create_dir(destination.join("bin")).map_err(|error| runtime_io(destination, &error))?;
    fs::copy(artifact, destination.join("bin").join(binary))
        .map_err(|error| runtime_io(destination, &error))?;
    #[cfg(unix)]
    {
        make_executable(&destination.join("bin").join(binary))
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

/// `RubyGems` archives are unpacked directly into an isolated `GEM_HOME`. Ruby and
/// `gem install` are never started, so hooks and extension build scripts cannot run.
#[allow(clippy::too_many_lines)]
pub(super) fn extract_ruby_gem(
    artifact: &Path,
    destination: &Path,
    tool: &LockedTool,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let gem = tool
        .provenance
        .package
        .as_deref()
        .ok_or_else(|| runtime_error("RubyGems lock entry has no gem provenance"))?;
    let expected = tool
        .provenance
        .registry_integrity
        .as_deref()
        .ok_or_else(|| runtime_error("RubyGems lock entry has no archive SHA-256 provenance"))?;
    if expected != tool.sha256 {
        return Err(runtime_error(
            "RubyGems archive SHA-256 provenance differs from lock",
        ));
    }
    let home = destination.join("gem-home");
    let payload = home
        .join("gems")
        .join(format!("{gem}-{}", tool.resolved_version));
    fs::create_dir_all(&payload).map_err(|error| runtime_io(&payload, &error))?;
    let mut outer =
        tar::Archive::new(fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?);
    let mut found_data = false;
    for entry in outer
        .entries()
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?
    {
        let mut entry =
            entry.map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let entry_path = entry
            .path()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let declared_size = entry
            .header()
            .size()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        budget
            .begin_entry(entry_path.as_ref(), Some(declared_size))
            .map_err(budget_error)?;
        let path = safe_archive_path_with_budget(entry_path.as_ref(), budget)?;
        let kind = entry.header().entry_type();
        if !kind.is_dir() && !kind.is_file() {
            return Err(runtime_error(
                "RubyGems archive contains a link or unsupported entry",
            ));
        }
        if path == Path::new("data.tar.gz") {
            if !kind.is_file() {
                return Err(runtime_error("RubyGems data.tar.gz is not a regular file"));
            }
            found_data = true;
            let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&mut entry));
            for nested in archive
                .entries()
                .map_err(|error| runtime_error_with_cause(error.to_string(), error))?
            {
                let mut nested =
                    nested.map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
                let nested_path = nested
                    .path()
                    .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
                let nested_size = nested
                    .header()
                    .size()
                    .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
                budget
                    .begin_entry(nested_path.as_ref(), Some(nested_size))
                    .map_err(budget_error)?;
                let path = safe_archive_path_with_budget(nested_path.as_ref(), budget)?;
                if path.starts_with("ext")
                    || path.file_name().is_some_and(|name| name == "extconf.rb")
                {
                    return Err(runtime_error(
                        "RubyGems native extensions are denied by default",
                    ));
                }
                let nested_kind = nested.header().entry_type();
                if nested_kind.is_dir() {
                    fs::create_dir_all(payload.join(path))
                        .map_err(|error| runtime_io(&payload.join(path), &error))?;
                } else if nested_kind.is_file() {
                    let target = payload.join(path);
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
                    }
                    let mut output =
                        fs::File::create(&target).map_err(|error| runtime_io(&target, &error))?;
                    copy_budgeted(&mut nested, &mut output, budget)?;
                } else {
                    return Err(runtime_error(
                        "RubyGems archive contains a link or unsupported entry",
                    ));
                }
            }
        }
    }
    if !found_data {
        return Err(runtime_error("RubyGems archive has no data.tar.gz"));
    }
    let bin = destination.join("bin");
    fs::create_dir(&bin).map_err(|error| runtime_io(&bin, &error))?;
    for binary in &tool.binaries {
        let source = payload.join("bin").join(binary);
        if !usable_file(&source) {
            return Err(runtime_error(
                "Ruby gem does not provide every declared binary",
            ));
        }
        let launcher = bin.join(binary);
        fs::write(&launcher, format!("#!/bin/sh\nroot=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd)\nexport GEM_HOME=\"$root/gem-home\"\nexport GEM_PATH=\"$GEM_HOME\"\nexec \"$GEM_HOME/gems/{gem}-{}/bin/{binary}\" \"$@\"\n", tool.resolved_version))
            .map_err(|error| runtime_io(&launcher, &error))?;
        #[cfg(unix)]
        make_executable(&launcher)?;
    }
    Ok(())
}

/// `NuGet` .NET tool packages are ZIPs with a tool-settings manifest and managed
/// entrypoint below `tools/<tfm>/any`. We extract their payload directly and
/// expose only declared commands through small launchers; `NuGet` scripts and the
/// global `dotnet tool install` machinery are never invoked.
#[allow(clippy::too_many_lines)]
pub(super) fn extract_dotnet_tool_package(
    artifact: &Path,
    destination: &Path,
    tool: &LockedTool,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let file = fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
    if u64::try_from(archive.len()).unwrap_or(u64::MAX) > budget.limits().archive_entries {
        return Err(budget_error(ResourceLimitError::new(
            ResourceLimit::ArchiveEntries,
            budget.limits().archive_entries,
        )));
    }
    let mut manifest = None;
    let mut scanned_entries = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        check_archive_scan_count(budget, &mut scanned_entries)?;
        let entry_path = Path::new(entry.name());
        budget
            .check_entry(entry_path, Some(entry.size()))
            .map_err(budget_error)?;
        let _ = safe_archive_path_with_budget(entry_path, budget)?;
        if entry
            .name()
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("DotnetToolSettings.xml"))
        {
            manifest = Some(read_archive_metadata(&mut entry, budget)?);
            break;
        }
    }
    let mut commands = dotnet_tool_commands(
        &manifest.ok_or_else(|| runtime_error("NuGet package has no DotnetToolSettings.xml"))?,
    )?;
    for binary in &tool.binaries {
        let entrypoint = commands
            .get(binary)
            .ok_or_else(|| runtime_error("NuGet tool command differs from lock"))?;
        if !Path::new(entrypoint)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
            || !is_safe_dotnet_entrypoint(entrypoint)
        {
            return Err(runtime_error("NuGet tool has an unsafe managed entrypoint"));
        }
        let entries: Vec<_> = (0..archive.len())
            .filter_map(|index| {
                let entry = archive.by_index(index).ok()?;
                entry
                    .name()
                    .ends_with(entrypoint)
                    .then_some(entry.name().to_owned())
            })
            .collect();
        let [entry] = entries.as_slice() else {
            return Err(runtime_error(
                "NuGet tool entrypoint is absent or ambiguous",
            ));
        };
        let Some(entry) = entry.strip_prefix("tools/") else {
            return Err(runtime_error(
                "NuGet tool entrypoint is outside tools layout",
            ));
        };
        commands.insert(binary.clone(), entry.to_owned());
    }
    let payload = destination.join("payload");
    fs::create_dir(&payload).map_err(|error| runtime_io(&payload, &error))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let entry_path = Path::new(entry.name());
        budget
            .begin_entry(entry_path, Some(entry.size()))
            .map_err(budget_error)?;
        let path = safe_archive_path_with_budget(entry_path, budget)?;
        if entry
            .unix_mode()
            .is_some_and(|mode| matches!(mode & 0o170_000, 0o120_000 | 0o060_000 | 0o020_000))
        {
            return Err(runtime_error(
                "NuGet package contains a link or unsupported entry",
            ));
        }
        if entry.is_dir() {
            continue;
        }
        let target = payload.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
        }
        let mut output = fs::File::create(&target).map_err(|error| runtime_io(&target, &error))?;
        copy_budgeted(&mut entry, &mut output, budget)?;
    }
    let bin = destination.join("bin");
    fs::create_dir(&bin).map_err(|error| runtime_io(&bin, &error))?;
    for binary in &tool.binaries {
        let entrypoint = commands.get(binary).ok_or_else(|| {
            runtime_error("NuGet tool command differs from lock after validation")
        })?;
        let target = bin.join(binary);
        fs::write(&target, format!("#!/bin/sh\nexec dotnet \"$(dirname \"$0\")/../payload/tools/{entrypoint}\" \"$@\"\n"))
            .map_err(|error| runtime_io(&target, &error))?;
        #[cfg(unix)]
        make_executable(&target)?;
    }
    Ok(())
}

pub(super) fn dotnet_tool_commands(
    input: &str,
) -> Result<std::collections::BTreeMap<String, String>, Diagnostic> {
    let mut commands = std::collections::BTreeMap::new();
    for command in input.match_indices("<Command") {
        let rest = &input[command.0..];
        if !rest
            .as_bytes()
            .get("<Command".len())
            .is_some_and(u8::is_ascii_whitespace)
        {
            continue;
        }
        let end = rest
            .find('>')
            .ok_or_else(|| runtime_error("invalid DotnetToolSettings.xml"))?;
        let tag = &rest[..end];
        let name = xml_attribute(tag, "Name")
            .ok_or_else(|| runtime_error("invalid DotnetToolSettings.xml"))?;
        let entrypoint = xml_attribute(tag, "EntryPoint")
            .ok_or_else(|| runtime_error("invalid DotnetToolSettings.xml"))?;
        if commands
            .insert(name.to_owned(), entrypoint.to_owned())
            .is_some()
        {
            return Err(runtime_error("duplicate NuGet tool command"));
        }
    }
    (!commands.is_empty())
        .then_some(commands)
        .ok_or_else(|| runtime_error("NuGet package has no tool commands"))
}

pub(super) fn xml_attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let (_, value) = tag.split_once(&format!("{name}=\""))?;
    value.split_once('"').map(|(value, _)| value)
}

pub(super) fn is_safe_dotnet_entrypoint(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// npm tarballs contain a `package/` root. Only declared bin files are exposed;
/// package scripts and all package-manager hooks are intentionally ignored.
#[allow(clippy::too_many_lines)]
pub(super) fn extract_npm_tarball(
    artifact: &Path,
    destination: &Path,
    tool: &LockedTool,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
    ));
    fs::create_dir_all(destination).map_err(|error| runtime_io(destination, &error))?;
    let bin = destination.join("bin");
    fs::create_dir(&bin).map_err(|error| runtime_io(&bin, &error))?;
    let package = tool
        .provenance
        .package
        .as_deref()
        .ok_or_else(|| runtime_error("npm lock entry has no package provenance"))?;
    let metadata = tool
        .provenance
        .registry_integrity
        .as_deref()
        .ok_or_else(|| runtime_error("npm lock entry has no integrity provenance"))?;
    if package.is_empty() || metadata.is_empty() {
        return Err(runtime_error("npm lock entry is incomplete"));
    }
    let mut wanted = std::collections::BTreeMap::new();
    // npm metadata is re-read from the archived package.json only to map locked names to paths.
    let mut package_json = None;
    let mut scanned_entries = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?
    {
        let mut entry =
            entry.map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        check_archive_scan_count(budget, &mut scanned_entries)?;
        let entry_path = entry
            .path()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let declared_size = entry
            .header()
            .size()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        budget
            .check_entry(entry_path.as_ref(), Some(declared_size))
            .map_err(budget_error)?;
        let _ = safe_archive_path_with_budget(entry_path.as_ref(), budget)?;
        if !entry.header().entry_type().is_dir() && !entry.header().entry_type().is_file() {
            return Err(runtime_error(
                "npm archive contains a link or unsupported entry",
            ));
        }
        if entry_path == Path::new("package/package.json") {
            package_json = Some(read_archive_metadata(&mut entry, budget)?);
            break;
        }
    }
    let value: serde_json::Value = serde_json::from_str(
        &package_json.ok_or_else(|| runtime_error("npm tarball has no package.json"))?,
    )
    .map_err(|_| runtime_error("npm tarball has invalid package.json"))?;
    let bins = npm_bins_from_package_json(package, &value)
        .ok_or_else(|| runtime_error("npm tarball has no declared bin"))?;
    for bin_entry in bins {
        if tool.binaries.iter().any(|name| name == &bin_entry.name) {
            wanted.insert(format!("package/{}", bin_entry.path), bin_entry.name);
        }
    }
    if wanted.len() != tool.binaries.len() {
        return Err(runtime_error(
            "npm tarball bin declarations differ from lock",
        ));
    }
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
    ));
    for entry in archive
        .entries()
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?
    {
        let mut entry =
            entry.map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let path = entry
            .path()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let declared_size = entry
            .header()
            .size()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        budget
            .begin_entry(path.as_ref(), Some(declared_size))
            .map_err(budget_error)?;
        let safe_path = safe_archive_path_with_budget(path.as_ref(), budget)?;
        let kind = entry.header().entry_type();
        if !kind.is_dir() && !kind.is_file() {
            return Err(runtime_error(
                "npm archive contains a link or unsupported entry",
            ));
        }
        let Some(name) = wanted.get(safe_path.to_string_lossy().as_ref()) else {
            continue;
        };
        if !kind.is_file() {
            return Err(runtime_error("npm bin is not a regular file"));
        }
        let target = bin.join(name);
        let mut output = fs::File::create(&target).map_err(|error| runtime_io(&target, &error))?;
        copy_budgeted(&mut entry, &mut output, budget)?;
        #[cfg(unix)]
        make_executable(&target)?;
    }
    Ok(())
}

pub(super) fn has_suffix(value: &str, suffix: &str) -> bool {
    value.as_bytes().ends_with(suffix.as_bytes())
}

/// Whether a URL names something **the extractor cannot open**, and so must not be
/// treated as a raw binary.
///
/// **Not [`neoenv_core::tools::PROGRAM_EXTENSIONS`].** That table is "this is not a
/// program", which mixes two things: distribution *packages* and *compression
/// suffixes*. Reading it here refused `gh_2.101.0_linux_amd64.tar.gz` -- because
/// `gz` is a member -- and the very archives this extractor exists to unpack. A
/// predicate that answers a different question than the one asked is worse than no
/// predicate, and this one was caught only because the test that drove the explicit
/// `asset:` path also carried a `.tar.gz` control.
///
/// The question here is narrower: **can `ArtifactPlan` open it?** The extractor
/// reads `.tar.gz`, `.tgz`, `.tar.xz`, `.tar`, and `.zip`, plus an extensionless raw
/// binary. So the list is the packaging formats, the compression formats with no
/// decoder here, and `ar` -- because a `.deb` *is* an `ar` archive, and that is the
/// file `extract_raw_binary` was copying to `bin/` and marking executable.
///
/// `whl`, `gem`, `jar` and `nupkg` are deliberately **absent**: they are openable
/// (`extract_zip_with_budget` extracts every entry, with no layout requirement), so
/// calling them unopenable is false. They are still kept out of *automatic*
/// selection, where the advice is a different sentence -- see
/// [`neoenv_core::tools::NON_EXECUTABLE_EXTENSIONS`].
const UNOPENABLE_EXTENSIONS: &[&str] = &[
    // A distribution package.
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
    "flatpak",
    "appimage",
    "ar",
    // **Openable, and that is exactly why they are here.** A wheel, a gem, a jar
    // and a nupkg are a zip or a tar, so an earlier version of this comment claimed
    // they were "deliberately absent" on the grounds that the extractor unpacks them.
    // It does -- through the `Zip` arm -- but *nothing sniffs content*: the layout
    // arms key on the literal suffixes `.tar.gz .tgz .tar.xz .tar .zip`, and a
    // `.whl` matches none of them. So removing these four turned a loud refusal
    // into a raw-binary install, which is the worst direction this project has. The
    // claim was true about the formats and false about the code path.
    "whl",
    "gem",
    "jar",
    "nupkg",
    // A compression format with no decoder here, **including the bzip2
    // shorthands**. `gz`, `xz`, `tgz` and `zip` are deliberately absent -- those
    // are the ones this extractor can read.
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
];

/// The predicate `ArtifactPlan` consults. `pub(crate)` so the cross-table test can
/// assert that the *selection* rule and this one agree: something skipped at
/// selection and accepted at extraction is the wrong-install direction, and nothing
/// else catches it.
///
/// **It lowercases its own input.** It and `has_no_decoder` are correct only on a
/// lowercased URL, and the sole caller complies -- but a contract that holds only
/// because the caller happens to comply is one `refactor` from a silent wrong
/// install, and *no test could fail on it*: every row in the suite is a lowercase
/// literal, so `container_url_refused("…/TOOL.DEB")` returning `false` was
/// invisible. An uppercase extension is a real spelling -- this file's own
/// `is_release_artifact` has a comment about a Windows release publishing
/// `downloads\tool.exe`, and a case-insensitive filesystem can deliver any case --
/// so the normalization belongs here, not in a `debug_assert` that vanishes in
/// release builds.
///
/// **The path only.** `canonical_http_url` rejects credentials and fragments but
/// *keeps the query* -- a presigned download URL carries one routinely -- and
/// `plan_tools` writes the canonicalized URL straight into the lock. So
/// `gh_2.101.0_linux_amd64.deb?token=abc` arrived here as one last segment whose
/// dot-segments were `gh_2`, `101`, `0_linux_amd64` and `deb?token=abc`, none of
/// which matched, and the package was installed as an executable again.
pub(crate) fn container_url_refused(url: &str) -> bool {
    path_name(&url.to_ascii_lowercase())
        .split('.')
        .any(unopenable_extension_is)
}

/// Whether one dot-segment is in [`UNOPENABLE_EXTENSIONS`].
///
/// **Read by [`container_url_refused`] itself**, so it is one predicate with one
/// name rather than the same `contains` written twice, and so the cross-table test
/// can assert membership **on the list this rule actually reads**. An earlier
/// version of that test asserted the same members against `PROGRAM_EXTENSIONS`,
/// which this rule does not read -- so those lines would have passed with the rule
/// deleted. A mutator that hits the neighbouring constant and a test that reads only
/// one of them agree perfectly, and together they look like coverage.
pub(crate) fn unopenable_extension_is(segment: &str) -> bool {
    UNOPENABLE_EXTENSIONS.contains(&segment)
}

/// Whether the refusal is "no decoder for this compression format" rather than
/// "this is a package". The two need different advice, and giving both the same
/// sentence was a dead end for a third of the list.
fn has_no_decoder(url: &str) -> bool {
    path_name(url).split('.').any(has_decoder_advice)
}

/// Whether one dot-segment is a compression format with no decoder here, which is
/// the half of the refusal that needs *different advice* rather than a different
/// verdict. Exposed so the cross-table test can assert both halves agree.
pub(crate) fn has_decoder_advice(segment: &str) -> bool {
    UNDECODABLE_EXTENSIONS.contains(&segment)
}

/// The whole decoder-advice list, so the cross-table test can assert the subset
/// property *by reading it* rather than by restating its members.
///
/// A hardcoded member list in that assertion is worse than none: it held while
/// `tbz` and `tbz2` were in one list and not the other, which is exactly the state
/// that let a `.tbz` asset be selected and then installed as a raw binary. The
/// property is "every name with decoder advice also has a verdict", and only a loop
/// over the real list can fail when a member is added to the wrong one.
///
/// `#[cfg(test)]` because nothing in the library reads it -- `has_no_decoder` and
/// `unopenable_extension_is` are the production entries to the same two constants.
/// Without the attribute this is a `dead_code` warning in the library build, and the
/// two ways to silence that are worse: calling it from production code purely so it
/// looks used, or dropping the accessor and going back to a hardcoded member list.
#[cfg(test)]
pub(crate) fn undecodable_extensions() -> &'static [&'static str] {
    UNDECODABLE_EXTENSIONS
}

/// The compression formats with no decoder here, split out from
/// [`UNOPENABLE_EXTENSIONS`] so the *message* can be right even though the
/// *refusal* is the same for both reasons.
const UNDECODABLE_EXTENSIONS: &[&str] = &[
    "zst", "bz2", "7z", "rar", "z", "lz", "lzma", "br", "sz",
    // **The bzip2 shorthands.** `bz2` was listed and `tbz`/`tbz2` were not, so the
    // two tables disagreed about the same bytes -- and in the silent direction.
    // `aristocratos/btop` v1.4.5 and v1.4.6 publish `btop-*.tbz` and nothing else
    // (11 assets, all `.tbz`), first-match selected it, no layout arm matched, and
    // `extract_raw_binary` copied a bzip2 blob to `bin/btop`, marked it executable,
    // wrote a receipt and published a launcher. The install reported success.
    //
    // mise's `ExtractionFormat` *does* cover these, so it installs btop correctly
    // where this refuses it. The right end state is a decoder, not a refusal: the
    // refusal is the loud direction and is what ships now.
    "tbz", "tbz2",
];

/// The path of a URL, with any query and fragment removed.
///
/// **The `rsplit('/')` step cannot be observed by any input today, and that is a
/// property of the split set rather than of the URLs.** Segments are taken with
/// `split('.')`, and `/` is *not* a separator there, so a directory named `pkg`
/// yields the segment `/pkg/v1/tool-1` and never a bare `pkg` — meaning the
/// `rsplit` changes no verdict and a mutation removing it passes every test. It is
/// kept because it is the guarantee that a mirror path like
/// `…/pkg/v1/tool.tar.gz` can never contribute a segment, and that guarantee is
/// load-bearing the moment anyone widens the split set to include `/`.
///
/// A test row claiming to cover it would be theatre: no input distinguishes the two
/// forms, so any row would be satisfied by both. The mirror-path rows in
/// `the_containment_list_is_verified_against_the_packaging_list` do assert the
/// *behaviour* — that such a URL is installable — and they are what would fail if
/// the split set were widened; they simply cannot fail on the removal.
fn path_name(url: &str) -> &str {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let path = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    path.rsplit('/').next().unwrap_or(path)
}

pub(super) fn extraction_budget(artifact: &Path) -> Result<ExtractionBudget, Diagnostic> {
    let compressed_size = fs::metadata(artifact)
        .map(|metadata| metadata.len())
        .map_err(|error| runtime_io(artifact, &error))?;
    let limits = ResourceBudget::default();
    if compressed_size > limits.artifact_bytes {
        return Err(budget_error(ResourceLimitError::new(
            ResourceLimit::Artifact,
            limits.artifact_bytes,
        )));
    }
    Ok(ExtractionBudget::new(limits, Some(compressed_size)))
}

pub(super) fn extraction_reader_budget() -> ExtractionBudget {
    ExtractionBudget::new(ResourceBudget::default(), None)
}

pub(super) fn budget_error(error: neoenv_runtime::budget::ResourceLimitError) -> Diagnostic {
    runtime_error_with_cause(error.to_string(), error)
}

pub(super) fn check_archive_scan_count(
    budget: &ExtractionBudget,
    seen: &mut u64,
) -> Result<(), Diagnostic> {
    *seen = seen.saturating_add(1);
    if *seen > budget.limits().archive_entries {
        return Err(budget_error(ResourceLimitError::new(
            ResourceLimit::ArchiveEntries,
            budget.limits().archive_entries,
        )));
    }
    Ok(())
}

pub(super) fn copy_budgeted(
    input: &mut impl Read,
    output: &mut impl Write,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        if count == 0 {
            return Ok(());
        }
        budget.account_entry_bytes(count).map_err(budget_error)?;
        output
            .write_all(&buffer[..count])
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
    }
}

pub(super) fn read_archive_metadata(
    input: &mut impl Read,
    budget: &ExtractionBudget,
) -> Result<String, Diagnostic> {
    let mut reader = BudgetReader::new(
        input,
        ResourceLimit::ArchiveMetadata,
        budget.limits().http_body_bytes,
    );
    let mut bytes = Vec::with_capacity(budget.limits().metadata_bytes.min(8192) as usize);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes).map_err(|_| runtime_error("archive metadata is not UTF-8"))
}

pub(super) fn extract_gzip_tar(artifact: &Path, destination: &Path) -> Result<(), Diagnostic> {
    let mut budget = extraction_budget(artifact)?;
    extract_tar_with_budget(
        flate2::read::GzDecoder::new(
            fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
        ),
        destination,
        &mut budget,
    )
}

pub(super) fn extract_xz_tar(artifact: &Path, destination: &Path) -> Result<(), Diagnostic> {
    let mut budget = extraction_budget(artifact)?;
    extract_tar_with_budget(
        xz2::read::XzDecoder::new(
            fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?,
        ),
        destination,
        &mut budget,
    )
}

pub(super) fn extract_tar_with_budget(
    reader: impl Read,
    destination: &Path,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let mut archive = tar::Archive::new(reader);
    for entry in archive
        .entries()
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?
    {
        let mut entry =
            entry.map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let entry_path = entry
            .path()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let declared_size = entry
            .header()
            .size()
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        budget
            .begin_entry(entry_path.as_ref(), Some(declared_size))
            .map_err(budget_error)?;
        let path = safe_archive_path_with_budget(entry_path.as_ref(), budget)?;
        let target = destination.join(path);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&target).map_err(|error| runtime_io(&target, &error))?;
        } else if kind.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
            }
            let mut output =
                fs::File::create(&target).map_err(|error| runtime_io(&target, &error))?;
            copy_budgeted(&mut entry, &mut output, budget)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(entry.header().mode().unwrap_or(0o644)),
                )
                .map_err(|error| runtime_io(&target, &error))?;
            }
        } else {
            return Err(runtime_error(
                "archive contains a link or unsupported entry",
            ));
        }
    }
    Ok(())
}

pub(super) fn extract_zip(artifact: &Path, destination: &Path) -> Result<(), Diagnostic> {
    let mut budget = extraction_budget(artifact)?;
    extract_zip_with_budget(artifact, destination, &mut budget)
}

pub(super) fn extract_zip_with_budget(
    artifact: &Path,
    destination: &Path,
    budget: &mut ExtractionBudget,
) -> Result<(), Diagnostic> {
    let file = fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
    if u64::try_from(archive.len()).unwrap_or(u64::MAX) > budget.limits().archive_entries {
        return Err(budget_error(ResourceLimitError::new(
            ResourceLimit::ArchiveEntries,
            budget.limits().archive_entries,
        )));
    }
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        let entry_path = Path::new(entry.name());
        let declared_size = entry.size();
        budget
            .begin_entry(entry_path, Some(declared_size))
            .map_err(budget_error)?;
        let path = safe_archive_path_with_budget(entry_path, budget)?;
        let target = destination.join(path);
        if entry
            .unix_mode()
            .is_some_and(|mode| matches!(mode & 0o170_000, 0o120_000 | 0o060_000 | 0o020_000))
        {
            return Err(runtime_error(
                "archive contains a link or unsupported entry",
            ));
        }
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|error| runtime_io(&target, &error))?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
            }
            let mut output =
                fs::File::create(&target).map_err(|error| runtime_io(&target, &error))?;
            copy_budgeted(&mut entry, &mut output, budget)?;
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                    .map_err(|error| runtime_io(&target, &error))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn safe_archive_path(path: &Path) -> Result<&Path, Diagnostic> {
    let budget = extraction_reader_budget();
    safe_archive_path_with_budget(path, &budget)
}

pub(super) fn safe_archive_path_with_budget<'a>(
    path: &'a Path,
    budget: &ExtractionBudget,
) -> Result<&'a Path, Diagnostic> {
    budget.check_path(path).map_err(budget_error)?;
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(runtime_error(format!(
            "archive contains unsafe path {}",
            path.display()
        )));
    }
    Ok(path)
}
