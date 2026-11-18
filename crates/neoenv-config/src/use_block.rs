//! The Go `use:` block, normalized into the Rust tool model.
//!
//! A Go `nenv` file declares its tools under `use:`, keyed by a string that
//! carries the *kind* of tool as well as its name: a bare runtime (`node`), a
//! GitHub release (`gh:owner/repo`), a GitLab release (`gl:owner/repo`), or a
//! package manager (`npm:left-pad`). The key is the dispatch, and the value is
//! either a bare version string or a mapping.
//!
//! Every accepted form is turned into the same [`StructuredTool`] the native
//! reader produces, so the rest of normalization, validation, and diagnostics is
//! identical whether the file was written in either dialect. Nothing here
//! decides anything at resolve time: a key whose provider this model cannot
//! resolve is carried with a provider that says so, and reports by name when it
//! is planned.
//!
//! [`StructuredTool`]: super::structured::StructuredTool

use std::path::Path;

use neoenv_core::Diagnostic;

use super::structured::{StructuredGithubRelease, StructuredGitlabRelease, StructuredTool};
use super::{Format, document_error};

/// The GitLab host a `gl:` key resolves against when the file names none.
const DEFAULT_GITLAB_HOST: &str = "gitlab.com";

/// The prefix that marks a package-manager key, as in `npm:left-pad`.
const PACKAGE_MANAGER: &str = "package-manager";

/// The prefix that marks a bare language runtime, which this model has no
/// installer for. Named at resolve time rather than mapped onto a provider that
/// would try to fetch an empty URL.
const RUNTIME: &str = "runtime";

/// How a `use:` key is classified, as the reference classifies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToolKeyKind {
    /// A bare runtime name such as `node`.
    Runtime,
    /// `gh:owner/repo`
    Github,
    /// `gl:owner/repo`
    Gitlab,
    /// `manager:package`, such as `npm:left-pad`.
    Package,
    /// A `gh:` or `gl:` key with no `/`.
    ///
    /// Its own kind so it is *refused*. Classifying it as a runtime would give
    /// it a provider, and a malformed key would then resolve as a tool named
    /// `gh:cli` rather than being reported.
    MalformedRelease,
}

fn classify(key: &str) -> ToolKeyKind {
    for (prefix, well_formed) in [("gh:", ToolKeyKind::Github), ("gl:", ToolKeyKind::Gitlab)] {
        if let Some(rest) = key.strip_prefix(prefix) {
            let halves = rest.split_once('/');
            let usable = halves.is_some_and(|(left, right)| !left.is_empty() && !right.is_empty());
            return if usable {
                well_formed
            } else {
                ToolKeyKind::MalformedRelease
            };
        }
    }
    if key.contains(':') {
        return ToolKeyKind::Package;
    }
    ToolKeyKind::Runtime
}

/// The keys a Go `use:` entry accepts.
///
/// A separate struct from the native `StructuredTool` because the *keys* differ:
/// Go spells them `binpath`, `bindir`, `bins`, `grep`, and `rename`, and
/// `version` is optional in the mapping form only because a bare string carries
/// it instead.
///
/// No `deny_unknown_fields`: it cannot be combined with the `flatten` below, and
/// serde silently lets the flattened map win, so a legitimate per-platform
/// override stops matching. Unknown keys are rejected by the inventory walk in
/// `validate_key_inventory` instead, which names the key, its location, and the
/// keys that *are* valid -- a better diagnostic than this attribute could give.
#[derive(Default, serde::Deserialize)]
struct UseEntry {
    version: Option<String>,
    asset: Option<String>,
    url: Option<String>,
    checksum: Option<String>,
    binpath: Option<String>,
    bindir: Option<String>,
    bins: Option<Vec<String>>,
    grep: Option<String>,
    #[serde(alias = "rn")]
    rename: Option<String>,
    #[serde(default, alias = "pre")]
    prerelease: bool,
    /// Per-platform overrides, keyed `linux`, `darwin-arm64`, `windows-amd64`.
    #[serde(flatten)]
    platforms: std::collections::BTreeMap<String, PlatformEntry>,
}

/// A per-platform `use:` override.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformEntry {
    // No `version`: the reference's `OSArchConfig` has none either, so a
    // per-platform version is not a thing this profile should appear to accept.
    asset: Option<String>,
    url: Option<String>,
    checksum: Option<String>,
    binpath: Option<String>,
    bindir: Option<String>,
    bins: Option<Vec<String>>,
    grep: Option<String>,
    #[serde(alias = "rn")]
    rename: Option<String>,
}

/// The platform-key prefixes the Go `use:` block recognizes, each with its
/// trailing dash.
///
/// The dash is load-bearing: the reference's `isPlatformKey` tests
/// `strings.HasPrefix(key, "windows-")`, so a bare `windows:` is *not* a
/// platform spec there. Matching the bare name turned it into an arch-less
/// override that [`super::structured::PlatformOverride`] selection then applied
/// to every machine of that OS -- a block the reference ignores entirely.
///
/// The list lives here and `compat.rs` borrows it, because two byte-identical
/// copies of a table that decides what counts as a platform key will drift, and
/// the drift would be silent.
pub(super) const PLATFORM_PREFIXES: [&str; 9] = [
    "linux-",
    "darwin-",
    "windows-",
    "freebsd-",
    "openbsd-",
    "netbsd-",
    "dragonfly-",
    "solaris-",
    "plan9-",
];

/// Whether a `use:` entry's key is a per-platform override.
pub(super) fn is_platform_key(key: &str) -> bool {
    PLATFORM_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

/// Normalizes a whole `use:` block into tools, in document order.
///
/// # Errors
///
/// Returns NEO132 for a key that cannot be classified, and NEO135 for an entry
/// that does not carry a version.
pub(super) fn normalize_use(
    path: &Path,
    input: &str,
    format: Format,
    entries: &indexmap::IndexMap<String, serde_yaml::Value>,
) -> Result<Vec<StructuredTool>, Diagnostic> {
    let _ = format;
    let mut tools = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        tools.push(normalize_entry(path, input, key, value)?);
    }
    Ok(tools)
}

/// The provider, and any release declaration, a `use:` key resolves to.
///
/// Split out of [`normalize_entry`] so the key classification reads on its own:
/// which provider a key selects is a decision about the *key*, and the rest of
/// the entry is about its values.
///
/// # Errors
///
/// Returns NEO132 for a `gh:`/`gl:` key that is missing a half.
fn classify_provider(
    path: &Path,
    input: &str,
    key: &str,
    entry: &UseEntry,
    asset: Option<&str>,
) -> Result<
    (
        String,
        Option<StructuredGithubRelease>,
        Option<StructuredGitlabRelease>,
    ),
    Diagnostic,
> {
    Ok(match classify(key) {
        ToolKeyKind::Github => {
            let rest = key.strip_prefix("gh:").unwrap_or_default();
            let Some((owner, repo)) = rest
                .split_once('/')
                .filter(|(left, right)| !left.is_empty() && !right.is_empty())
            else {
                return Err(document_error(
                    path,
                    input,
                    "NEO132",
                    format!("this Go `use:` key `{key}` is not `gh:owner/repo`"),
                ));
            };
            (
                "github-release".to_owned(),
                Some(StructuredGithubRelease {
                    repository: format!("{owner}/{repo}"),
                    asset: asset.map(str::to_owned),
                    checksum_asset: None,
                    grep: entry.grep.as_deref().map(trimmed).filter(|g| !g.is_empty()),
                    prerelease: entry.prerelease,
                    rename: entry
                        .rename
                        .as_deref()
                        .map(trimmed)
                        .filter(|rename| !rename.is_empty()),
                }),
                None,
            )
        }
        ToolKeyKind::Gitlab => {
            let rest = key.strip_prefix("gl:").unwrap_or_default();
            let Some((namespace, project)) = rest
                .split_once('/')
                .filter(|(left, right)| !left.is_empty() && !right.is_empty())
            else {
                return Err(document_error(
                    path,
                    input,
                    "NEO132",
                    format!("this Go `use:` key `{key}` is not `gl:namespace/project`"),
                ));
            };
            (
                "gitlab-release".to_owned(),
                None,
                Some(StructuredGitlabRelease {
                    host: DEFAULT_GITLAB_HOST.to_owned(),
                    namespace: namespace.to_owned(),
                    project: project.to_owned(),
                    // A GitLab release has no asset template to substitute, so
                    // the name the file gives is the name; an absent one is
                    // caught at resolve time, which reports the provider.
                    asset: asset.map(str::to_owned).unwrap_or_default(),
                    grep: entry.grep.as_deref().map(trimmed).filter(|g| !g.is_empty()),
                }),
            )
        }
        ToolKeyKind::Package => {
            let manager = key.split(':').next().unwrap_or_default();
            (format!("{PACKAGE_MANAGER}:{manager}"), None, None)
        }
        ToolKeyKind::Runtime => (format!("{RUNTIME}:{key}"), None, None),
        ToolKeyKind::MalformedRelease => {
            let (prefix, expected) = if key.starts_with("gl:") {
                ("gl:", "gl:namespace/project")
            } else {
                ("gh:", "gh:owner/repo")
            };
            return Err(document_error(
                path,
                input,
                "NEO132",
                format!(
                    "this Go `use:` key `{key}` starts with `{prefix}` but is not \
                     `{expected}`; both halves are required"
                ),
            ));
        }
    })
}

/// Reads a `use:` value into its entry shape and the version it declares.
///
/// # Errors
///
/// Returns NEO130 when the value is neither a version nor a mapping, and NEO135
/// when the version is absent or empty.
fn read_entry(
    path: &Path,
    input: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<(UseEntry, String), Diagnostic> {
    // Dispatched on the value's own kind rather than through an untagged enum.
    // `UseEntry` flattens its platform overrides, and `flatten` inside an untagged
    // variant does not behave: a legitimate `darwin-arm64:` override failed to
    // match and degraded to "data did not match any variant". Choosing the shape
    // here keeps the flatten on a plain struct, where it works.
    let entry = match value {
        // Any scalar is the version, the way the reference takes a `ScalarNode`
        // (`use_map.go`). Restricting this to strings refused `node: 20` and
        // `node: true`, which the reference accepts -- a divergence that reads
        // as strictness but is not.
        serde_yaml::Value::String(version) => UseEntry {
            version: Some(version.clone()),
            ..UseEntry::default()
        },
        serde_yaml::Value::Number(version) => UseEntry {
            version: Some(version.to_string()),
            ..UseEntry::default()
        },
        serde_yaml::Value::Bool(version) => UseEntry {
            version: Some(version.to_string()),
            ..UseEntry::default()
        },
        serde_yaml::Value::Mapping(_) => {
            serde_yaml::from_value::<UseEntry>(value.clone()).map_err(|error| {
                // The value is echoed nowhere: a `use:` entry can carry a URL
                // with credentials in it, and a type error would quote it.
                document_error(
                    path,
                    input,
                    "NEO130",
                    format!("this Go `use:` entry for `{key}` is not readable: {error}"),
                )
            })?
        }
        other => {
            return Err(document_error(
                path,
                input,
                "NEO130",
                format!(
                    "this Go `use:` entry for `{key}` is a {}, not a version or a mapping",
                    yaml_kind(other)
                ),
            ));
        }
    };
    let Some(version) = entry.version.as_deref().map(trimmed) else {
        return Err(document_error(
            path,
            input,
            "NEO135",
            format!(
                "this Go `use:` entry for `{key}` has no version; a mapping form must set \\
                 `version`"
            ),
        ));
    };
    if version.is_empty() {
        return Err(document_error(
            path,
            input,
            "NEO135",
            format!("this Go `use:` entry for `{key}` has an empty version"),
        ));
    }
    Ok((entry, version))
}

/// The derived facts [`refuse_unusable_combinations`] needs about one entry.
///
/// A struct rather than five more parameters: the call had reached eight, and
/// four of the five are properties of the same entry rather than independent
/// inputs.
struct EntryFacts<'a> {
    key: &'a str,
    /// Whether the key names a release (`gh:` or `gl:`), which is what decides
    /// whether the release-specific refusals apply at all.
    release_key: bool,
    platforms: &'a [super::structured::StructuredPlatform],
    asset: Option<&'a String>,
    grep: Option<&'a String>,
    has_url: bool,
}

/// The binaries one `use:` entry installs, and the refusal when the file gives two
/// names for the same thing.
///
/// `rename` is the installed *name*. The declaration carries it separately as
/// well as lowering it into `binaries[0]`, because planning must distinguish
/// "install the archive's own file under its own name" from "write this raw
/// download under a different name". A raw single-binary artifact is written
/// under the requested name; an archive is refused by the planner until the
/// extractor can carry an original-to-destination mapping, so a successful
/// install never silently uses a different name than the file asked for. When
/// `bins` is also given, which of the two wins depends on whether the artifact
/// is an archive or a plain binary, so it is refused rather than guessed.
///
/// With neither, the name is the repository's repo half: the reference sets
/// `plan.Name` to it (`tools/install.go:86,97`) and `install_binary.go` falls back
/// to it. A key that names no repository -- a bare runtime, a package manager --
/// keeps an empty list, which planning reports; inventing a name would install a
/// binary under a name nobody asked for.
///
/// # Errors
///
/// Returns NEO136 when the entry names binaries with both `bins` and `rename`.
fn resolve_binaries(
    path: &Path,
    input: &str,
    key: &str,
    entry: &UseEntry,
) -> Result<Vec<String>, Diagnostic> {
    let bins = entry
        .bins
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|bin| trimmed(bin))
        .filter(|bin| !bin.is_empty())
        .collect::<Vec<_>>();
    let rename = entry
        .rename
        .as_deref()
        .map(trimmed)
        .filter(|rename| !rename.is_empty());
    if rename.is_some() && !bins.is_empty() {
        return Err(document_error(
            path,
            input,
            "NEO136",
            format!(
                "this Go `use:` entry for `{key}` sets both `bins` and `rename`. They mean \
                 different things -- `bins` says which files to take from the artifact, \
                 `rename` says what to call the installed one -- and this profile has a \
                 single binary-name list that is both, so it cannot honor the pair. Keep one, \
                 or set `bins: [b]` to install as `b`."
            ),
        ));
    }
    let default_name = default_binary_name(key);
    Ok(match (&rename, bins.is_empty(), default_name) {
        (Some(rename), _, _) => vec![rename.clone()],
        (None, false, _) => bins,
        (None, true, Some(name)) => vec![name],
        (None, true, None) => Vec::new(),
    })
}

/// Refuses a `use:` entry whose keys cannot all be honored together.
///
/// Split out of [`normalize_entry`] because it is a table of cases rather than a
/// decision, and folding it in pushed the function past a size at which the
/// order of the remaining steps stopped being readable.
///
/// # Errors
///
/// Returns NEO132 naming the combination and what to do about it.
fn refuse_unusable_combinations(
    path: &Path,
    input: &str,
    facts: &EntryFacts<'_>,
) -> Result<(), Diagnostic> {
    let EntryFacts {
        key,
        release_key,
        platforms,
        asset,
        grep,
        has_url,
    } = facts;
    // Refused on its own, before the `direct` mapping is even considered.
    //
    // It is the same defect the top-level case was, one level down: read into the
    // override, and read by nothing. A release plan cannot honor an override's
    // URL -- a URL cannot satisfy the lock's provenance invariant, which is why
    // the top-level form maps to the `explicit-url` provider instead. And unlike
    // the top-level form this is *not* mappable: an entry may legitimately carry
    // both `asset:` and a per-platform `url:` ("the release's asset, except here
    // use this file"), and refusing the whole entry for that would reject a
    // declaration the reference honors.
    //
    // So it is named on its own, and an entry with a per-platform URL is not also
    // checked for a redundant top-level one below.
    if *release_key
        && platforms
            .iter()
            .any(|platform| platform.url.as_deref().is_some_and(|url| !url.is_empty()))
    {
        return Err(document_error(
            path,
            input,
            "NEO132",
            format!(
                "this Go `use:` entry for `{key}` sets a per-platform `url`, which a release \
                 plan cannot honor: a URL names no release asset, so the lock cannot record where \
                 the download came from. Put the `url` at the top level, where it selects the \
                 `explicit-url` provider."
            ),
        ));
    }
    // `asset:` and `grep:` select *from the release's assets*, and a direct
    // download has none. Reading them and dropping them would silently change
    // which file is fetched, so they are named -- but only when there *is* a
    // direct download, because without one the two are the ordinary way to say
    // which asset to fetch.
    if *has_url {
        for (present, name) in [(asset.is_some(), "asset"), (grep.is_some(), "grep")] {
            if present {
                return Err(document_error(
                    path,
                    input,
                    "NEO132",
                    format!(
                        "this Go `use:` entry for `{key}` sets both `url` and `{name}`; a `url` \
                         is fetched directly, so `{name}` has no release asset to select from. \
                         Give one or the other."
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn normalize_entry(
    path: &Path,
    input: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<StructuredTool, Diagnostic> {
    // Trimmed and refused when blank, the way the reference reads it
    // (`key := strings.TrimSpace(keyNode.Value); if key == ""`). Without the
    // trim a leading space defeated `strip_prefix`, so `" gh:cli/cli"`
    // classified as a *package manager* -- a GitHub release read as npm. Without
    // the blank check an empty key produced a tool with an empty id.
    let key = key.trim();
    if key.is_empty() {
        return Err(document_error(
            path,
            input,
            "NEO132",
            "this Go `use:` key is empty, so it names no tool".to_owned(),
        ));
    }
    let (entry, version) = read_entry(path, input, key, value)?;

    // A per-platform `url:` is honored by the *override*, the way `url` is
    // everywhere else in this model -- a platform override's URL wins over the
    // declaration's. Read here rather than refused so the key reaches the model,
    // and so the refusal below can name it when the override is a release key's,
    // where no reader would pick it up.
    let platforms = normalize_platforms(path, input, key, &entry.platforms)?;
    let asset = entry
        .asset
        .as_deref()
        .map(trimmed)
        .filter(|a| !a.is_empty());
    let url = entry.url.as_deref().map(trimmed).filter(|u| !u.is_empty());
    let checksum = entry
        .checksum
        .as_deref()
        .map(trimmed)
        .filter(|c| !c.is_empty());

    // A `url:` on a release key means "fetch this exact file": the reference's
    // `DirectReleaseAsset` short-circuits asset selection with it. The
    // `explicit-url` provider is this model's version of that -- a named URL
    // verified against a declared digest -- so the key maps there rather than
    // into the release planners, whose provenance a URL cannot satisfy.
    //
    // Only for a key that *is* a release key, and only when the URL is at the top
    // level. A per-platform `url:` is a different question -- see below.
    let release_key = matches!(classify(key), ToolKeyKind::Github | ToolKeyKind::Gitlab);
    let direct = url.clone().filter(|_| release_key);
    refuse_unusable_combinations(
        path,
        input,
        &EntryFacts {
            key,
            release_key,
            platforms: &platforms,
            asset: asset.as_ref(),
            grep: entry
                .grep
                .as_deref()
                .map(trimmed)
                .filter(|grep| !grep.is_empty())
                .as_ref(),
            has_url: url.is_some(),
        },
    )?;
    // The `asset`/`grep` refusal lives in `refuse_unusable_combinations`, gated on
    // a `url` being present, so it does not have to be repeated here.
    let (provider, github_release, gitlab_release) = if direct.is_some() {
        ("explicit-url".to_owned(), None, None)
    } else {
        classify_provider(path, input, key, &entry, asset.as_deref())?
    };
    let binaries = resolve_binaries(path, input, key, &entry)?;

    Ok(StructuredTool {
        id: key.to_owned(),
        version,
        provider: Some(provider),
        url,
        sha256: checksum,
        github_release,
        gitlab_release,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries,
        binpath: entry
            .binpath
            .as_deref()
            .map(trimmed)
            .filter(|b| !b.is_empty()),
        bindir: entry
            .bindir
            .as_deref()
            .map(trimmed)
            .filter(|b| !b.is_empty()),
        platforms,
    })
}

fn normalize_platforms(
    path: &Path,
    input: &str,
    key: &str,
    platforms: &std::collections::BTreeMap<String, PlatformEntry>,
) -> Result<Vec<super::structured::StructuredPlatform>, Diagnostic> {
    let mut normalized = Vec::with_capacity(platforms.len());
    for (name, entry) in platforms {
        if !is_platform_key(name) {
            // Belt and braces. `check_use_entries` runs before this and names an
            // unrecognized key with its location, so in practice the earlier
            // check answers first and this does not fire. Kept because the two
            // lists are maintained separately and a future edit to either could
            // open a gap -- but the comment it replaces claimed the flatten
            // "only ever holds platform keys", which is not a property anything
            // here enforces.
            return Err(document_error(
                path,
                input,
                "NEO132",
                format!("this Go `use:` entry for `{key}` has unrecognized key `{name}`"),
            ));
        }
        let (os, arch) = name.split_once('-').unwrap_or((name.as_str(), ""));
        // One list, trimmed and blank-filtered, used by both the refusal below and
        // the `binaries` fold further down. They used to compute "has bins"
        // differently -- the check asked whether *any element* was non-blank while
        // the fold asked whether the *vec* was non-empty and never trimmed -- so
        // `bins: ["  "], rename: cli` passed the check, folded to `["  "]`, and
        // dropped the rename. The installer then writes `<root>/bin/␠␠`. The
        // reference drops the blank and installs `cli`
        // (`install_binary.go:17`).
        let binaries: Vec<String> = entry
            .bins
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|bin| trimmed(bin))
            .filter(|bin| !bin.is_empty())
            .collect();
        let renamed = entry
            .rename
            .as_deref()
            .map(trimmed)
            .filter(|rename| !rename.is_empty());
        let rename_for_platform = renamed.clone();
        if !binaries.is_empty() && renamed.is_some() {
            // The reason, which an earlier version of this message got wrong. The
            // reference does not *choose* between the two keys: `Bins` says which
            // files to take out of the artifact and `Rename` says what to call the
            // installed one (`install_binary.go:14-31` and `:72`), so
            // `bins: [a] + rename: b` is a document it honors, installing `a` as
            // `b`. This model has a single `binaries` list that is both the
            // selector and the installed name -- the installer writes
            // `<root>/bin/<binary>` from it -- so it cannot represent the pair, and
            // picking either one silently drops the other.
            return Err(document_error(
                path,
                input,
                "NEO136",
                format!(
                    "this Go `use:` entry for `{key}` sets both `bins` and `rename` under \
                     `{name}`. They mean different things -- `bins` says which files to take from \
                     the artifact, `rename` says what to call the installed one -- and this profile \
                     has a single binary-name list that is both, so it cannot honor the pair. \
                     Keep one, or set `bins: [b]` to install as `b`."
                ),
            ));
        }
        normalized.push(super::structured::StructuredPlatform {
            os: Some(os.to_owned()),
            arch: (!arch.is_empty()).then(|| arch.to_owned()),
            url: entry.url.as_deref().map(trimmed).filter(|u| !u.is_empty()),
            sha256: entry
                .checksum
                .as_deref()
                .map(trimmed)
                .filter(|c| !c.is_empty()),
            // The same trimmed list the refusal above used, so a blank-only
            // `bins` is absent rather than present-and-empty. A per-platform
            // `rename` becomes that override's single binary, for the same reason
            // the top-level one does: the installer writes `<root>/bin/<binary>`
            // from the binary list and nothing else, so a separate field would be
            // read and then dropped. The reference honors a per-platform rename
            // (`MergeWithDefaults`).
            binaries: (!binaries.is_empty())
                .then_some(binaries)
                .or_else(|| renamed.map(|name| vec![name])),
            binpath: entry
                .binpath
                .as_deref()
                .map(trimmed)
                .filter(|b| !b.is_empty()),
            bindir: entry
                .bindir
                .as_deref()
                .map(trimmed)
                .filter(|b| !b.is_empty()),
            asset: entry
                .asset
                .as_deref()
                .map(trimmed)
                .filter(|a| !a.is_empty()),
            grep: entry.grep.as_deref().map(trimmed).filter(|g| !g.is_empty()),
            rename: rename_for_platform,
        });
    }
    Ok(normalized)
}

/// The binary name a key implies when it names none: the repository's repo half
/// for a `gh:`/`gl:` key, and nothing for the other kinds.
///
/// A bare runtime and a package manager both take their name from a *registry*
/// the file did not give here, so guessing one would install a binary under an
/// invented name. Those keep an empty list, which planning reports as
/// `EmptyBinaries` -- a diagnostic naming the problem, rather than a wrong name
/// that looks like a success.
fn default_binary_name(key: &str) -> Option<String> {
    for prefix in ["gh:", "gl:"] {
        // Nested rather than a let chain: the release gate builds with a
        // toolchain that does not accept `let` in that position.
        if let Some(rest) = key.strip_prefix(prefix)
            && let Some((_, repo)) = rest.split_once('/')
        {
            // One component only. `gh:owner/repo/v2` parses as far as the
            // first slash, leaving `repo/v2` -- which the installer's
            // binary-name check rejects at lock-write time, long after
            // `tool plan` reported a tool it could not install.
            if !repo.is_empty() && !repo.contains('/') {
                return Some(repo.to_owned());
            }
        }
    }
    None
}

/// How a `use:` value's YAML kind reads in a diagnostic.
fn yaml_kind(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Null => "null",
        _ => "value",
    }
}

fn trimmed(value: &str) -> String {
    value.trim().to_owned()
}
