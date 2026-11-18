//! Tool model, planning, and lockfile validation tests.

use super::*;

const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn declaration(id: &str) -> ToolDeclaration {
    ToolDeclaration {
        id: id.into(),
        version: "1.0.0".into(),
        provider: ToolProvider::ExplicitUrl,
        url: Some("https://example.test/tool.tar.gz".into()),
        sha256: Some(SHA256.into()),
        github_release: None,
        gitlab_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec![id.into()],
        binpath: None,
        bindir: None,
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 3, 1),
    }
}

#[test]
fn cargo_build_provenance_validates_policy_inputs_and_legacy_locks() {
    let plan = plan_tools(&[declaration("tool")], &Platform::new("linux", "x86_64")).unwrap();
    let mut lock = ToolLockfile::from_plan(&plan);
    let entry = &mut lock.tools[0];
    entry.resolver = "cargo".into();
    entry.provenance.provider = "cargo".into();
    entry.provenance.package = Some("tool".into());
    entry.provenance.registry_endpoint = Some("https://index.crates.io/".into());
    entry.cargo_toolchain = Some("1.85.0".into());
    let provenance = CargoBuildLock {
        tool_id: "tool".into(),
        crate_name: "tool".into(),
        version: "1.0.0".into(),
        registry: "https://index.crates.io/".into(),
        checksum: SHA256.into(),
        toolchain: "1.85.0".into(),
        scripts: CargoScriptPolicy::Deny,
        build: CargoBuildPolicy::Isolated,
        network: CargoNetworkPolicy::Deny,
    };
    lock.cargo_build = Some(provenance);
    lock.validate().unwrap();
    lock.cargo_build.as_mut().unwrap().tool_id = "other".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().tool_id = "tool".into();
    lock.cargo_build.as_mut().unwrap().version = "^1.0".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().version = "1.0.0".into();
    lock.cargo_build.as_mut().unwrap().registry = "http://index.crates.io/".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().registry = "https://index.crates.io/".into();
    lock.cargo_build.as_mut().unwrap().checksum = "f".repeat(64);
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().checksum = SHA256.into();
    lock.cargo_build.as_mut().unwrap().toolchain = "1.86.0".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().toolchain = "1.85.0".into();
    lock.cargo_build.as_mut().unwrap().toolchain = "1.85.0-../../evil".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build.as_mut().unwrap().toolchain =
        "1.85.0-x86_64-unknown-linux-gnu-extra-extra".into();
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));
    lock.cargo_build = None;
    assert_eq!(lock.validate(), Err(ToolLockError::InvalidCargoBuild));

    let mut legacy = serde_json::to_value(ToolLockfile::from_plan(&plan)).unwrap();
    legacy.as_object_mut().unwrap().remove("cargo_build");
    let decoded: ToolLockfile = serde_json::from_value(legacy).unwrap();
    assert!(decoded.cargo_build.is_none());
    decoded.validate().unwrap();
}

#[test]
fn cargo_toolchain_pin_accepts_only_full_exact_version_and_safe_optional_target() {
    for accepted in [
        "1.85.0",
        "1.85.0-x86_64-unknown-linux-gnu",
        "1.85.0-aarch64-apple-darwin",
        "1.85.0-x86_64-pc-windows-msvc",
        "1.85.0-wasm32-unknown-unknown",
    ] {
        assert!(is_cargo_toolchain_pin(accepted), "{accepted}");
    }
    for rejected in [
        "stable",
        "1.85",
        "1.85.0-rc.1",
        "1.85.0+metadata",
        "1.85.0-x86_64-unknown",
        "1.85.0-x86_64-../../escape",
        "1.85.0-x86_64-unknown-linux-gnu/extra",
        "1.85.0-x86_64-unknown-linux-gnu-extra-extra",
        "1.85.0-wasm32-apple-windows-msvc",
        "1.85.0-x86_64-apple-windows-msvc",
        "1.85.0-madeup-unknown-linux-gnu",
        "1.85.0-x86_64-madeup-linux-gnu",
        "1.85.0-x86_64-unknown-linux-madeup",
        &format!("1.85.0-{}", "x".repeat(257)),
    ] {
        assert!(!is_cargo_toolchain_pin(rejected), "{rejected}");
    }
}

#[test]
fn cargo_planner_requires_explicit_target_qualified_toolchain_pin() {
    let mut tool = declaration("ripgrep");
    tool.version = "14.1.1".into();
    tool.provider = ToolProvider::Cargo;
    tool.url = None;
    tool.sha256 = None;
    tool.cargo = Some(CargoDeclaration {
        crate_name: "ripgrep".into(),
        version: "14.1.1".into(),
        registry: "https://index.crates.io/".into(),
        checksum: SHA256.into(),
        toolchain: "1.85.0-x86_64-unknown-linux-gnu".into(),
        scripts: CargoScriptPolicy::Deny,
        build: CargoBuildPolicy::Isolated,
        network: CargoNetworkPolicy::Deny,
    });
    let plan = plan_cargo_crate(&tool, &Platform::new("linux", "x86_64")).unwrap();
    assert_eq!(
        plan.cargo_toolchain.as_deref(),
        Some("1.85.0-x86_64-unknown-linux-gnu")
    );
    assert!(cargo_toolchain_for_platform("1.85.0", &Platform::new("linux", "x86_64")).is_none());
    assert_eq!(
        cargo_toolchain_for_platform(
            "1.85.0-x86_64-unknown-linux-musl",
            &Platform::new("linux", "x86_64")
        )
        .as_deref(),
        Some("1.85.0-x86_64-unknown-linux-musl")
    );
}

#[test]
fn npm_planner_refuses_programmatic_manager_selection_and_checks_its_exact_version() {
    let platform = Platform::new("linux", "x86_64");
    let package = NpmRegistryPackage {
        package: "demo".into(),
        version: "1.2.3".into(),
        tarball: "https://registry.npmjs.org/demo/-/demo-1.2.3.tgz".into(),
        integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".into(),
        binaries: vec![NpmBinary {
            name: "demo".into(),
            path: "bin/demo.js".into(),
        }],
    };
    let mut tool = declaration("demo");
    tool.provider = ToolProvider::Npm;
    tool.version = "1.2.3".into();
    tool.url = None;
    tool.sha256 = None;
    tool.npm = Some(NpmDeclaration {
        endpoint: "https://registry.npmjs.org".into(),
        package: "demo".into(),
        manager: Some(NpmManager {
            name: NpmManagerName::Bun,
            version: "1.4.4-rc.1".into(),
            archive_sha256: None,
        }),
    });

    let error = plan_npm_registry(&tool, &platform, &package, SHA256.into()).unwrap_err();
    assert!(error.to_string().contains("bun@1.4.4-rc.1"));
    assert!(
        error
            .to_string()
            .contains("refusing direct-tarball fallback")
    );

    tool.npm.as_mut().unwrap().manager.as_mut().unwrap().version = "^1.4.4".into();
    assert!(matches!(
        plan_npm_registry(&tool, &platform, &package, SHA256.into()),
        Err(ToolPlanError::InvalidNpmManagerVersion { .. })
    ));

    tool.npm.as_mut().unwrap().manager = None;
    assert!(plan_npm_registry(&tool, &platform, &package, SHA256.into()).is_ok());
}

#[test]
fn plans_in_declaration_order_with_exact_os_and_default_precedence() {
    let mut first = declaration("first");
    first.platforms = vec![
        PlatformOverride {
            platform: PlatformSelector {
                os: None,
                arch: None,
            },
            url: Some("https://example.test/default".into()),
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        },
        PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: None,
            },
            url: Some("https://example.test/linux".into()),
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        },
        PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: Some("x86_64".into()),
            },
            url: Some("https://example.test/exact".into()),
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        },
    ];
    let plan = plan_tools(
        &[first, declaration("second")],
        &Platform::new("linux", "x86_64"),
    )
    .unwrap();
    assert_eq!(
        plan.tools
            .iter()
            .map(|tool| tool.id.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(plan.tools[0].url, "https://example.test/exact");
}

#[test]
fn rejects_ambiguous_missing_and_non_strict_assets() {
    let mut ambiguous = declaration("tool");
    ambiguous.platforms = vec![
        PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: None,
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        },
        PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: None,
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        },
    ];
    assert!(matches!(
        plan_tools(&[ambiguous], &Platform::new("linux", "x86_64")),
        Err(ToolPlanError::AmbiguousPlatformOverride { .. })
    ));
    let mut invalid = declaration("invalid");
    invalid.sha256 = Some("sha256:bad".into());
    assert!(matches!(
        plan_tools(&[invalid], &Platform::new("linux", "x86_64")),
        Err(ToolPlanError::InvalidSha256 { .. })
    ));
}

#[test]
fn canonicalizes_http_urls_and_rejects_sensitive_url_components() {
    let mut tool = declaration("tool");
    tool.url = Some("HTTPS://Example.Test:443/download".into());
    let plan = plan_tools(&[tool], &Platform::new("linux", "x86_64")).unwrap();
    assert_eq!(plan.tools[0].url, "https://example.test/download");

    for url in [
        "https://user:secret@example.test/tool",
        "https://example.test/tool#fragment",
        "ftp://example.test/tool",
    ] {
        let mut tool = declaration("tool");
        tool.url = Some(url.into());
        let error = plan_tools(&[tool], &Platform::new("linux", "x86_64")).unwrap_err();
        assert!(matches!(error, ToolPlanError::UnsupportedUrl { .. }));
        assert!(!error.to_string().contains("secret"));
    }
}

/// **An internationalized host is normalized to punycode, and the answer is pinned
/// rather than assumed.**
///
/// This exists because of a *data* downgrade nobody had recorded. `yoke-derive 0.8.3`
/// does not compile on the toolchain the release gate pins, so `idna_adapter` was
/// pinned `1.2.1 → 1.2.0`, and that is not only a `yoke` change: `1.2.0` requires the
/// `icu_*` 1.x line where `1.2.1` requires 2.x, so the lock moved **ICU4X 2.1.x →
/// 1.5.x** — the UTS46 normalization and IDNA property tables, on the path every
/// `Url::parse` goes through.
///
/// The first commit described the pin purely as a compile fix and never mentioned
/// ICU4X. Before this test, **no test anywhere in `rust/` exercised IDN**, so
/// whichever table was in the lock was unverified in both directions.
///
/// The rows are the two halves that could differ between table generations: a host
/// that must be *converted*, and one that must be *left alone*. A bare `ü` test would
/// pass or fail with the table version but would not catch a change that broke
/// ASCII hosts, which is the far more likely regression.
#[test]
fn an_idn_host_is_normalized_to_punycode() {
    for (input, expected) in [
        // The canonical example: `münchen` → `xn--mnchen-3ya`.
        ("https://münchen.example.test/tool", "xn--mnchen-3ya"),
        ("https://bücher.example.test/tool", "xn--bcher-kva"),
        // A CJK host, whose normalization is a different table lookup again.
        ("https://例え.example.test/tool", "xn--r8jz45g"),
    ] {
        let mut tool = declaration("tool");
        tool.url = Some(input.into());
        let plan = plan_tools(&[tool], &Platform::new("linux", "x86_64"))
            .unwrap_or_else(|error| panic!("{input} failed to plan: {error}"));
        assert!(
            plan.tools[0].url.contains(expected),
            "{input} must normalize to {expected}, got {}",
            plan.tools[0].url
        );
        assert!(
            !plan.tools[0].url.contains('ü') && !plan.tools[0].url.contains('例'),
            "a non-ASCII host must not survive into the lock, where it would be \
             re-parsed by whatever reads it next: {}",
            plan.tools[0].url
        );
    }

    // **And the control that matters more: an ASCII host is untouched.** A table
    // downgrade that broke ordinary hostnames would be a far worse regression than one
    // that mishandled IDN, and this row is what would catch it.
    for host in [
        "example.test",
        "a-b.example.test",
        "xn--mnchen-3ya.example.test",
    ] {
        let mut tool = declaration("tool");
        tool.url = Some(format!("https://{host}/tool"));
        let plan = plan_tools(&[tool], &Platform::new("linux", "x86_64")).unwrap();
        assert_eq!(
            plan.tools[0].url,
            format!("https://{host}/tool"),
            "an ASCII host must round-trip unchanged"
        );
    }
}

#[test]
fn provider_source_renders_its_retained_fallback_verbatim() {
    for fallback in [
        ToolPlanError::MissingAsset {
            id: "demo".into(),
            platform: Platform::new("linux", "x86_64"),
        },
        ToolPlanError::InvalidGoChecksum { id: "demo".into() },
        ToolPlanError::ResourceLimit {
            id: "demo".into(),
            message: "resource budget exceeded".into(),
        },
    ] {
        let expected = fallback.to_string();
        let error = ToolPlanError::ProviderSource {
            fallback: Box::new(fallback),
            source: Arc::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
        };
        assert_eq!(error.to_string(), expected);
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .is_some()
        );
    }
}

#[test]
fn locks_and_verifies_all_resolved_declaration_fields() {
    let plan = plan_tools(&[declaration("tool")], &Platform::new("linux", "x86_64")).unwrap();
    let mut lock = ToolLockfile::from_plan(&plan);
    assert!(verify_tool_plan(&plan, &lock).is_ok());
    lock.tools[0].sha256 = "f".repeat(64);
    lock.tools[0].verification.sha256 = lock.tools[0].sha256.clone();
    assert!(matches!(
        verify_tool_plan(&plan, &lock),
        Err(ToolVerificationError::ChecksumMismatch { .. })
    ));
}

#[test]
fn parses_extension_provider_names_but_does_not_resolve_them() {
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::from_name(Some("github-release"));

    assert_eq!(tool.provider.name(), "github-release");
    assert_eq!(
        tool.provider.authentication_policy(),
        ProviderAuthPolicy::Optional
    );
    assert!(matches!(
        plan_tools(&[tool], &Platform::new("linux", "x86_64")),
        Err(ToolPlanError::UnsupportedProvider { .. })
    ));
}

#[test]
fn rejects_lock_entries_with_inconsistent_provider_evidence() {
    let plan = plan_tools(&[declaration("tool")], &Platform::new("linux", "x86_64")).unwrap();
    let mut lock = ToolLockfile::from_plan(&plan);
    lock.tools[0].provenance.immutable_id = "https://example.test/other".into();

    assert!(matches!(
        lock.validate(),
        Err(ToolLockError::InvalidTool { .. })
    ));
}

#[test]
fn plans_github_release_with_numeric_identity_and_checksum() {
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::GithubRelease;
    tool.url = None;
    tool.github_release = Some(GithubReleaseDeclaration {
        grep: None,
        repository: "owner/tool".into(),
        asset: Some("tool-{os}-{arch}.tar.gz".into()),
        checksum_asset: Some("checksums.txt".into()),
        prerelease: false,
        rename: None,
    });
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &GithubReleaseMetadata {
            id: 42,
            tag: "1.0.0".into(),
            assets: vec![GithubReleaseAsset {
                id: 7,
                name: "tool-linux-x86_64.tar.gz".into(),
                url: "https://example.test/tool.tar.gz".into(),
            }],
        },
        None,
    )
    .unwrap();
    assert_eq!(planned.provenance.repository.as_deref(), Some("owner/tool"));
    assert_eq!(planned.provenance.release_id, Some(42));
    assert_eq!(planned.provenance.asset_id, Some(7));
    assert_ne!(planned.provenance.immutable_id, planned.url);
}

/// Builds a release with several assets, so a selection has something to choose
/// between. The ids are the asset indices, which is how the tests below name the
/// one they expect.
fn release_with(assets: &[(&str, &str)]) -> GithubReleaseMetadata {
    GithubReleaseMetadata {
        id: 1,
        tag: "1.0.0".into(),
        assets: assets
            .iter()
            .enumerate()
            .map(|(index, (name, url))| GithubReleaseAsset {
                id: index as u64 + 1,
                name: (*name).into(),
                url: (*url).into(),
            })
            .collect(),
    }
}

fn github_tool(asset: Option<&str>) -> ToolDeclaration {
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::GithubRelease;
    tool.url = None;
    tool.github_release = Some(GithubReleaseDeclaration {
        repository: "owner/tool".into(),
        asset: asset.map(str::to_owned),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    tool
}

#[test]
fn selects_a_platform_asset_when_the_declaration_names_none() {
    // The case that makes a bare `gh:owner/repo` entry resolvable. Nothing in the
    // file names an artifact, so the release's own asset list is the only
    // evidence there is.
    let release = release_with(&[
        ("tool-darwin-arm64.tar.gz", "https://example.test/darwin"),
        ("tool-linux-x86_64.tar.gz", "https://example.test/linux"),
    ]);
    let planned = plan_github_release(
        &github_tool(None),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.provenance.asset_id, Some(2), "the linux asset");
    assert_eq!(planned.url.as_str(), "https://example.test/linux");
}

#[test]
fn a_declared_asset_wins_over_one_that_merely_matches_the_platform() {
    // The negative half of the rule above. If the declared name were ignored, or
    // if platform selection ran first, this would plan the linux asset even
    // though the file named a different one.
    let release = release_with(&[
        ("tool-linux-x86_64.tar.gz", "https://example.test/platform"),
        ("tool-glibc.tar.gz", "https://example.test/declared"),
    ]);
    let planned = plan_github_release(
        &github_tool(Some("tool-glibc.tar.gz")),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/declared");
}

#[test]
fn a_declared_asset_template_is_substituted_before_matching() {
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/one")]);
    let planned = plan_github_release(
        &github_tool(Some("tool-{os}-{arch}.tar.gz")),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/one");
}

#[test]
fn grep_selects_a_release_artifact_and_an_invalid_pattern_is_refused() {
    let release = release_with(&[
        ("tool-linux-x86_64.tar.gz", "https://example.test/linux"),
        ("tool-linux-x86_64-sha256sums", "https://example.test/sums"),
    ]);
    let mut tool = github_tool(None);
    tool.github_release.as_mut().expect("a declaration").grep = Some("^tool-.*\\.tar\\.gz$".into());
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("a valid grep must select");
    assert_eq!(planned.url.as_str(), "https://example.test/linux");

    let named = release_with(&[
        (
            "age-keygen_linux_amd64.tar.gz",
            "https://example.test/age-keygen",
        ),
        ("age_linux_amd64.tar.gz", "https://example.test/age"),
    ]);
    tool.github_release.as_mut().expect("a declaration").grep = Some("age-keygen".into());
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &named,
        Some(SHA256.into()),
    )
    .expect("the named filter must select the age-keygen artifact");
    assert_eq!(planned.url.as_str(), "https://example.test/age-keygen");

    tool.github_release.as_mut().expect("a declaration").grep = Some("[".into());
    let error = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect_err("an invalid regex must be refused");
    assert!(
        matches!(error, ToolPlanError::InvalidGrepPattern { .. }),
        "{error}"
    );
    assert!(error.to_string().contains('['), "{error}");
}

#[test]
fn a_per_platform_rename_is_also_refused_for_an_archive() {
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/archive")]);
    let mut tool = github_tool(Some("tool-linux-x86_64.tar.gz"));
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
        },
        url: None,
        sha256: None,
        binaries: None,
        binpath: None,
        bindir: None,
        asset: None,
        grep: None,
        rename: Some("agek".into()),
    }];
    let error = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect_err("a per-platform archive rename must be refused");
    assert!(
        matches!(error, ToolPlanError::RenameOnArchive { .. }),
        "{error}"
    );
}

#[test]
fn rename_is_refused_for_an_archive_but_allowed_for_a_raw_asset() {
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/archive")]);
    let mut tool = github_tool(Some("tool-linux-x86_64.tar.gz"));
    tool.github_release.as_mut().expect("a declaration").rename = Some("agek".into());
    let error = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect_err("an archive rename must not report success");
    assert!(
        matches!(error, ToolPlanError::RenameOnArchive { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("rename"), "{error}");

    let raw = release_with(&[("age-keygen", "https://example.test/raw")]);
    let mut tool = github_tool(Some("age-keygen"));
    tool.github_release.as_mut().expect("a declaration").rename = Some("agek".into());
    plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &raw,
        Some(SHA256.into()),
    )
    .expect("a raw asset can be written under the requested name");
}

#[test]
fn refuses_a_binary_layout_the_extractors_cannot_honor() {
    // `binpath` and `bindir` name a location inside the artifact, and the
    // extractors place the whole binary list at the archive root. Carrying them
    // and dropping them before install would put the wrong thing on PATH.
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/linux")]);
    let cases: &[(&str, LayoutSetter)] = &[("binpath", set_binpath), ("bindir", set_bindir)];
    for (expected, set) in cases {
        let mut tool = github_tool(None);
        set(&mut tool, Some("bin".into()));
        let error = plan_github_release(
            &tool,
            &Platform::new("linux", "x86_64"),
            &release,
            Some(SHA256.into()),
        )
        .expect_err("a binary layout must not resolve");
        match &error {
            ToolPlanError::UnsupportedBinaryLayout { key, .. } => assert_eq!(key, expected),
            other => panic!("expected an unsupported binary layout, got {other}"),
        }
        // The message has to say what to use instead, not just that it failed.
        assert!(error.to_string().contains("bins:"), "{error}");
    }
}

#[test]
fn a_per_platform_asset_overrides_the_declaration_asset() {
    // The reference overlays platform values field by field (`MergeWithDefaults`),
    // and an override that declares an asset replaces the one the file set.
    let release = release_with(&[
        ("tool-default.tar.gz", "https://example.test/default"),
        ("tool-darwin.tar.gz", "https://example.test/darwin"),
    ]);
    let mut tool = github_tool(Some("tool-default.tar.gz"));
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("darwin".into()),
            arch: None,
        },
        url: None,
        sha256: None,
        binaries: None,
        binpath: None,
        bindir: None,
        asset: Some("tool-darwin.tar.gz".into()),
        grep: None,
        rename: None,
    }];
    let planned = plan_github_release(
        &tool,
        &Platform::new("darwin", "arm64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/darwin");
    // And the declaration's own asset still applies on a platform with no
    // override, which is the half that a "replace wholesale" reading would lose.
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("the declaration's own asset applies off the overridden platform");
    assert_eq!(planned.url.as_str(), "https://example.test/default");
}

/// A platform override that matches but declares no asset must leave the
/// declaration's own asset in place.
///
/// This is the property that separates the reference's field-by-field overlay
/// (`MergeWithDefaults`, where only a non-empty platform value wins) from a
/// wholesale replace. Under a replace, *any* matching override would drop the
/// declaration's asset and the entry would stop resolving wherever the override
/// happened not to name one — which is most of them.
#[test]
fn a_matching_override_without_an_asset_keeps_the_declarations_asset() {
    let release = release_with(&[
        ("tool-darwin.tar.gz", "https://example.test/darwin"),
        ("tool-default.tar.gz", "https://example.test/default"),
    ]);
    let mut tool = github_tool(Some("tool-default.tar.gz"));
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("darwin".into()),
            arch: None,
        },
        // A `url` here would be the *right* answer -- a direct download wins over
        // every asset selector -- so this override deliberately sets only a
        // checksum, which is not an asset selector at all.
        url: None,
        sha256: Some(SHA256.into()),
        binaries: None,
        binpath: None,
        bindir: None,
        asset: None,
        grep: None,
        rename: None,
    }];
    let planned = plan_github_release(
        &tool,
        &Platform::new("darwin", "arm64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("an override with no asset must not clear the declaration's");
    assert_eq!(planned.url.as_str(), "https://example.test/default");
}

#[test]
fn a_per_platform_grep_selects_the_override_artifact() {
    let release = release_with(&[
        ("tool-linux-x86_64.tar.gz", "https://example.test/linux"),
        (
            "tool-linux-x86_64-debug.tar.gz",
            "https://example.test/debug",
        ),
    ]);
    let mut tool = github_tool(None);
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: None,
        },
        url: None,
        sha256: None,
        binaries: None,
        binpath: None,
        bindir: None,
        asset: None,
        grep: Some("debug\\.tar\\.gz$".into()),
        rename: None,
    }];
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("a per-platform grep must select");
    assert_eq!(planned.url.as_str(), "https://example.test/debug");
}

/// A foreign OS must never match. This is the regression guard for a bug that
/// shipped once: the alias table for an unrecognized OS listed *every* alias, so
/// the most common host -- linux, which is not a named case -- accepted a darwin
/// asset and installed it while reporting success. Widening an unrecognized name
/// can only ever select an artifact for a different platform.
#[test]
fn a_foreign_operating_system_never_matches() {
    let release = release_with(&[
        ("tool-darwin-amd64.tar.gz", "https://example.test/darwin"),
        ("tool-windows-amd64.zip", "https://example.test/windows"),
        ("tool-linux-amd64.tar.gz", "https://example.test/linux"),
    ]);
    for (os, expected) in [
        ("linux", "https://example.test/linux"),
        ("darwin", "https://example.test/darwin"),
        ("windows", "https://example.test/windows"),
    ] {
        let planned = plan_github_release(
            &github_tool(None),
            &Platform::new(os, "x86_64"),
            &release,
            Some(SHA256.into()),
        )
        .unwrap_or_else(|error| panic!("{os} failed to plan: {error}"));
        assert_eq!(planned.url.as_str(), expected, "on {os}");
    }
}

#[test]
fn a_foreign_architecture_never_matches() {
    let release = release_with(&[
        ("tool-linux-amd64.tar.gz", "https://example.test/amd64"),
        ("tool-linux-arm64.tar.gz", "https://example.test/arm64"),
    ]);
    for (arch, expected) in [
        ("x86_64", "https://example.test/amd64"),
        ("arm64", "https://example.test/arm64"),
    ] {
        let planned = plan_github_release(
            &github_tool(None),
            &Platform::new("linux", arch),
            &release,
            Some(SHA256.into()),
        )
        .unwrap_or_else(|error| panic!("{arch} failed to plan: {error}"));
        assert_eq!(planned.url.as_str(), expected, "on {arch}");
    }
}

/// **A 32-bit ARM host must not accept an `arm64` asset, and must still accept a
/// 32-bit one.** `arm` is a prefix of `arm64`, so a substring match made every
/// `arm64` release asset eligible on a 32-bit host — 112 releases across 39
/// repositories, each installing a 64-bit binary, reporting success, and failing at
/// first run.
///
/// Both halves matter, and the second is why the fix is not "drop `arm` from the
/// family": 309 corpus names spell a 32-bit ARM architecture plain `arm` or `arm_1`,
/// so excluding it would refuse installs that work today. The width is checked at
/// match time instead — an alias running straight into digits is a wider
/// architecture.
///
/// Every name below is a real release asset, not a synthetic one.
#[test]
// A table of real release asset names, one per architecture spelling, with the
// expected verdict for a 32-bit host and for an arm64 host. Every row is a name a
// real publisher ships -- that is what makes the table evidence rather than a
// restatement of the rule.
#[allow(clippy::too_many_lines)]
fn a_32_bit_arm_host_takes_32_bit_assets_and_never_an_arm64_one() {
    let platform = Platform::new("linux", "arm");
    let release = release_with(&[
        (
            "gh_2.101.0_linux_arm64.tar.gz",
            "https://example.test/arm64",
        ),
        (
            "gh_2.101.0_linux_armv6.tar.gz",
            "https://example.test/armv6",
        ),
        (
            "gh_2.101.0_linux_armv5.tar.gz",
            "https://example.test/armv5",
        ),
    ]);
    // The arm64 asset is listed FIRST, so this is first-match: without the width
    // guard the 32-bit host takes it and the test passes for the wrong reason.
    let planned = plan_github_release(&github_tool(None), &platform, &release, Some(SHA256.into()))
        .unwrap_or_else(|error| panic!("32-bit arm failed to plan: {error}"));
    assert_eq!(
        planned.url.as_str(),
        "https://example.test/armv6",
        "a 32-bit host must not take the arm64 asset that is listed first"
    );

    // And with ONLY arm64 published, the answer is a loud refusal naming the
    // candidates — which is what mise's `has_arch_mismatch` produces, and what the
    // 32-bit `x86` family has done since `x86` was excluded.
    let arm64_only = release_with(&[("gh_2.101.0_linux_arm64.tar.gz", "https://example.test/64")]);
    let error = plan_github_release(
        &github_tool(None),
        &platform,
        &arm64_only,
        Some(SHA256.into()),
    )
    .expect_err("a 32-bit host must refuse an arm64-only release");
    let message = error.to_string();
    assert!(
        message.contains("arm64"),
        "the refusal must list the candidate so the user can see what was skipped, \
         got: {message}"
    );

    // **The 32-bit spellings that must keep matching.** Every name here was taken
    // from the 6,178-name release corpus, and an earlier version of this table claimed
    // "every name below is a real release asset" while inventing at least nine of them
    // -- `gh_2.101.0_linux_arm.tar.gz`, `gh_2.101.0_linux_armv5.tar.gz`,
    // `nats-server-v2.14.7-linux-arm5.tar.gz`, `fzf-0.74.4-android_arm64v8.tar.gz` and
    // others no publisher ships. That is the worst shape a test can have here: the
    // table's evidentiary value is that real publishers produce these spellings, and a
    // reader cannot tell a fix for a real one from a fix for an invented one.
    //
    // The OS travels with each name because `asset_matches_platform` requires *both*
    // halves, and a `freebsd` name does not match a `linux` host for reasons that have
    // nothing to do with architecture.
    for (name, os) in [
        ("alertmanager-0.33.1.linux-armv5.tar.gz", "linux"),
        ("alertmanager-0.33.1.linux-armv6.tar.gz", "linux"),
        ("alertmanager-0.33.1.linux-armv7.tar.gz", "linux"),
        ("alertmanager-0.33.1.freebsd-armv6.tar.gz", "freebsd"),
        ("traefik_v3.7.13_linux_armv7.tar.gz", "linux"),
        ("goreleaser_Linux_armv7.tar.gz", "linux"),
        ("btop-armv7l-linux-musleabihf.tbz", "linux"),
        ("jq-linux-armhf", "linux"),
        ("jq-linux-armel", "linux"),
        ("hugo_0.164.0_linux-arm.tar.gz", "linux"),
        ("coredns_1.14.5_linux_arm.tgz", "linux"),
        // The separator spellings, which are what the first version of the width guard
        // got wrong: `v5`/`v6`/`v7` are 32-bit and must keep matching, while `64` and
        // `v8` are 64-bit and must not. `rclone` ships all four.
        ("rclone-v1.74.4-linux-arm-v6.zip", "linux"),
        ("rclone-v1.74.4-linux-arm-v7.zip", "linux"),
        // GoReleaser's short spellings, which the width guard *cannot* cover because a
        // digit follows `arm` -- so they must be listed.
        //
        // `arm7` decides 40 corpus names and `arm7-cli.zip` is selectable. **`arm6`
        // decides 12 and none of them carry an OS token** -- `nats-server`'s assets
        // spell the architecture and nothing else -- so today `arm6` changes no
        // first-match selection. It is kept because it is a real GoReleaser spelling
        // beside a real `arm7`, a missing member here is a wrong install, and a
        // superfluous one costs a string. That asymmetry is the table's standing rule,
        // stated at the definition rather than re-argued per member.
        ("nats-server-v2.14.7-linux-arm6.sbom.spdx.json", "linux"),
        (
            "duplicati-2.4.0.100_canary_2026-09-04-linux-arm7-cli.zip",
            "linux",
        ),
    ] {
        assert!(
            asset_matches_platform(name, &Platform::new(os, "arm")),
            "{name} is a 32-bit ARM asset and must still match a 32-bit host"
        );
    }

    // **The bug, in every spelling it takes on a 32-bit host.** The `arm-64` rows are
    // why the width rule reads a *following* qualifier and not only an adjacent digit:
    // a first version fixed `arm64` and let `arm-64` through, and a first-match
    // selector then still installed a 64-bit binary from `localsend/localsend`.
    //
    // `arm64-<version>` is the case that constrains the rule the other way: those
    // digits are a *version*, which is why the qualifier test applies only to a bare
    // family root and never to `arm64` or `386`.
    for (name, os) in [
        ("gh_2.101.0_linux_arm64.tar.gz", "linux"),
        ("fzf-0.74.4-linux_arm64.tar.gz", "linux"),
        ("gh_2.101.0_windows_arm64.zip", "windows"),
        ("Logseq-linux-arm64-0.10.15.zip", "linux"),
        ("Logseq-darwin-arm64-2.0.1.zip", "darwin"),
        ("LocalSend-1.18.0-android-arm64v8.apk", "android"),
        // The separator and ABI spellings, real names from `localsend/localsend`.
        ("LocalSend-1.18.0-linux-arm-64.tar.gz", "linux"),
        ("LocalSend-1.18.2-windows-arm-64.exe", "windows"),
    ] {
        assert!(
            !asset_matches_platform(name, &Platform::new(os, "arm")),
            "{name} is 64-bit and must not match a 32-bit host"
        );
    }

    // **And the control that makes this a width test rather than a token test.**
    // `arm64v8` and `arm64-<version>` are real spellings, `arm64` is not a whole token
    // inside the first, and all of them must still match the host they are built for.
    for (name, os) in [
        ("fzf-0.74.4-android_arm64v8.tar.gz", "android"),
        ("LocalSend-1.18.0-android-arm64v8.apk", "android"),
        ("Logseq-darwin-arm64-2.0.1.zip", "darwin"),
        ("gh_2.101.0_macOS_arm64.zip", "macos"),
    ] {
        assert!(
            asset_matches_platform(name, &Platform::new(os, "arm64")),
            "{name} is an arm64 asset and must match an arm64 host"
        );
    }
}

/// **Naming an architecture in a release asset is a separate question from matching
/// one, and the install path needs the first without the second.**
///
/// `asset_matches_platform` answers "does this asset suit this platform", which is
/// what *selecting* an asset needs. The installer needs "does this asset name an
/// architecture at all, and is it one this host can run" — a question about a URL it
/// has already been handed and cannot re-select. That gap is why a lock written
/// before the 32-bit ARM width guard existed kept installing a 64-bit binary: the
/// lock's `platform` field is copied from the *host* on every planning path, explicit
/// `asset:` included, so it records which machine planned the lock and nothing about
/// the artifact.
///
/// Every name below is from the 6,178-name corpus.
#[test]
fn a_name_states_its_architecture_and_only_a_wider_one_is_a_problem() {
    // The two questions, on the same names, answering differently.
    for (name, family) in [
        ("gh_2.101.0_linux_arm64.tar.gz", "arm64"),
        ("ripgrep-15.2.0-aarch64-apple-darwin.tar.gz", "arm64"),
        ("gh_2.101.0_linux_amd64.tar.gz", "x86_64"),
        ("ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz", "x86_64"),
        ("jq-linux64", "x86_64"),
        ("jq-linux-armhf", "arm"),
        ("coredns_1.14.5_linux_arm.tgz", "arm"),
        ("alertmanager-0.33.1.linux-armv7.tar.gz", "arm"),
        ("rclone-v1.74.4-linux-arm-v6.zip", "arm"),
        ("alertmanager-0.33.1.linux-armv5.tar.gz", "arm"),
    ] {
        assert_eq!(named_architecture(name), Some(family), "{name}");
    }

    // **A name that states no architecture** — the ordinary case for an explicit
    // `url:`, and the case a naive "the second field must be an arch" check breaks.
    for name in [
        "tool",
        "tool.tar.gz",
        "my-company-internal-binary",
        "tool-linux.tar.gz",
        "1.2.3",
    ] {
        assert_eq!(named_architecture(name), None, "{name} states no arch");
    }

    // **And a name that states two**, which is unanswerable rather than clean. A
    // function that returned the first hit here would turn an ambiguity into a
    // silent wrong answer; returning `None` means callers decline to guess.
    assert_eq!(named_architecture("tool-amd64-arm64.tar.gz"), None);

    // **The direction is the whole design.** A wider artifact cannot run; a narrower
    // one can, so it is not refused. Every host/artifact pair below is checked in both
    // directions, because an assertion that only ever runs one way proves nothing
    // about the other.
    for (artifact, host_arch, refused) in [
        // The bug: a 64-bit ARM artifact for a 32-bit ARM host.
        ("gh_2.101.0_linux_arm64.tar.gz", "arm", true),
        ("LocalSend-1.18.0-linux-arm-64.tar.gz", "arm", true),
        ("LocalSend-1.18.0-android-arm64v8.apk", "arm", true),
        // A 64-bit x86 artifact for a 32-bit x86 host -- the *first* family to need
        // this, so the rule has to cover it too.
        ("gh_2.101.0_linux_amd64.tar.gz", "386", true),
        ("jq-linux64", "i686", true),
        // The direction that must NOT be refused: these run.
        ("jq-linux-armhf", "arm64", false),
        ("alertmanager-0.33.1.linux-armv5.tar.gz", "aarch64", false),
        ("jq-linux64", "x86_64", false),
        ("gh_2.101.0_linux_arm64.tar.gz", "aarch64", false),
        // Same width, different family: not refused, because the arch half is a
        // width check and not a "same family" check. A 32-bit x86 host is not
        // offered a 32-bit ARM artifact by any real release, so the row is a
        // boundary statement rather than a scenario.
        ("jq-linux-armhf", "x86_64", false),
    ] {
        let host = Platform::new("linux", host_arch);
        assert_eq!(
            names_a_wider_architecture(artifact, &host).is_some(),
            refused,
            "{artifact} on a {host_arch} host"
        );
    }

    // **An unknown host architecture declines rather than guessing.** Treating an
    // unknown width as 32-bit would make every unknown host refuse every 64-bit
    // artifact, which is the loud failure in the safe direction -- but it would be
    // *wrong*, and a machine reporting something this project has not seen is not a
    // machine to be loud at.
    for host_arch in ["", "riscv64", "s390x", "mips64"] {
        let host = Platform::new("linux", host_arch);
        assert_eq!(
            names_a_wider_architecture("gh_2.101.0_linux_amd64.tar.gz", &host),
            None,
            "an unknown host architecture must not adjudicate"
        );
    }
}

/// **Two invariants for the architecture families, and the second is the one that
/// matters.**
///
/// An earlier version of this test claimed the table "polices itself" and did not. It
/// checked only *redundancy* — that a shorter alias already matches a longer one — and
/// adding `arm64v8` to the 32-bit family passed the whole suite with the original bug
/// fully restored. The companion assertion claimed "no member of a 32-bit family may
/// be a prefix of a 64-bit spelling" while testing two exact strings, `arm64` and
/// `aarch64`, so `arm64v8`, `arm-64` and `aarch` all sailed through.
///
/// It also misdirected: adding the legitimate `armv8` failed with *"`armv8` is already
/// matched by `arm` … remove it"*, and neither half was true. `arm` does not match
/// `armv8` (the width guard rejects it), and removing it is not the fix — it names a
/// 64-bit architecture. So the invariant silently doubled as a 64-bit-exclusion check
/// without saying so.
#[test]
fn the_architecture_families_are_minimal_and_narrow() {
    //
    // **`armv8l` was in this list and it is wrong.** It is the glibc triple for
    // *32-bit* AArch64 — the `l` is the long ABI on AArch32, and Debian's 32-bit ARMv8
    // port is `armhf`. The matcher reports it 64-bit because `contains_architecture`
    // prefix-matches `rest.starts_with("v8")`, so `v8l` matches `v8`. The test was green
    // *because the bug was real*: a constant named `SIXTY_FOUR_BIT_SPELLINGS` asserted
    // that a 32-bit spelling must not match, and the refusal is the expensive direction
    // in `planning.rs` — a correct 32-bit install refused.
    //
    // It appears in 0 of 6,178 corpus names, so no corpus sweep reaches it and nothing
    // else in the suite noticed. It is left out here and asserted **32-bit** below, so
    // the next reader is told which way it goes and why rather than finding it in a
    // list whose name is the claim.
    const SIXTY_FOUR_BIT_SPELLINGS: &[&str] = &[
        "arm64", "aarch64", "arm64v8", "armv8", "arm_64", "arm-64", "arm.v8", "aarch",
    ];

    // And the 32-bit spellings that sit one character away from them, which is where
    // this goes wrong. Every one of these must still match a 32-bit host.
    const THIRTY_TWO_BIT_SPELLINGS: &[&str] = &[
        "armv8l", "arm32", "arm-32", "armv7l", "armv6l", "armv5tel", "armhf", "armel",
    ];

    // **Minimality: no member is shadowed by a shorter one in its own family.** An
    // alias a shorter alias already matches can never decide a match, so it costs a
    // string and changes no verdict. Eight members were exactly that — `armv5`,
    // `armv6`, `armv7`, `armv5tel`, `armv6l`, `armv7l`, `armhf`, `armel` — and removing
    // all eight changed 0 of 6,178 corpus names.
    for arch in ["arm", "x86_64", "amd64", "arm64", "aarch64"] {
        let family = platform_arch_aliases(arch);
        for member in &family {
            for other in &family {
                if other == member {
                    continue;
                }
                // `other` is shorter, is a prefix of `member`, and the width guard does
                // not reject it there — the same rule the matcher uses.
                let follows = member.as_bytes().get(other.len()).copied();
                let shadowed =
                    member.starts_with(other) && !follows.is_some_and(|byte| byte.is_ascii_digit());
                assert!(
                    !shadowed,
                    "{member:?} is already matched by the shorter alias {other:?} in the \
                     {arch} family, so it can never decide a match; remove it"
                );
            }
        }
    }

    // **Narrowness: no 32-bit family matches a 64-bit spelling, however it is
    // written.** This is the one that catches the original bug.
    //
    // It is asserted through the *matcher* rather than by comparing strings, because a
    // string-prefix test is not the same question and gives a false alarm: `arm64`
    // literally begins with the characters `arm6`, so a prefix assertion fails on
    // `arm6` -- a member that is perfectly correct, because the width guard rejects it
    // there. An earlier version of this test made exactly that mistake, and the
    // failure it produced named the wrong remedy.
    // **And the converse, which is the half that was missing.** A list of what must be
    // refused is only half the property: a rule that refuses everything passes it. These
    // are the spellings one character away from the refused set, and a 32-bit host must
    // accept every one.
    for spelling in THIRTY_TWO_BIT_SPELLINGS {
        for (template, os) in [
            ("tool-1.2.3-{os}-{arch}.tar.gz", "linux"),
            ("tool-1.2.3_{os}_{arch}.zip", "darwin"),
        ] {
            let name = template.replace("{os}", os).replace("{arch}", spelling);
            assert!(
                asset_matches_platform(&name, &Platform::new(os, "arm")),
                "{spelling} is a 32-bit ARM spelling (as {name}) and must match a 32-bit \
                 host; refusing it is the expensive direction"
            );
        }
    }

    for spelling in SIXTY_FOUR_BIT_SPELLINGS {
        for (template, os) in [
            ("tool-1.2.3-{os}-{arch}.tar.gz", "linux"),
            ("tool-1.2.3_{os}_{arch}.zip", "darwin"),
        ] {
            let name = template.replace("{os}", os).replace("{arch}", spelling);
            assert!(
                !asset_matches_platform(&name, &Platform::new(os, "arm")),
                "the 32-bit ARM family must not match the 64-bit spelling {spelling:?} \
                 (as {name})"
            );
        }
    }
    // The same property for the 32-bit x86 family, which was the *first* family to
    // need it — so the rule is stated once and both families get it.
    for spelling in ["x86_64", "amd64", "x64"] {
        let name = format!("tool-1.2.3-linux-{spelling}.tar.gz");
        assert!(
            !asset_matches_platform(&name, &Platform::new("linux", "386")),
            "the 386 family must not match {spelling:?} (as {name})"
        );
    }
}

/// `darwin` contains `win`, and `win` is one of the reference's Windows aliases.
///
/// Reproduced faithfully, this lets a Windows host select and install
/// `tool-darwin-amd64.tar.gz` -- a macOS binary -- and report success. The OS
/// check therefore requires a bounded occurrence. The architecture check is a
/// substring test too, for a different reason that the earlier version of this
/// comment got wrong: it is not the interior separator (`x86_64-unknown-linux-musl`
/// is two whole tokens), it is the *glued* spellings like `arm64v8` and
/// `jq-linux64`. It carries one extra guard — an alias running straight into digits
/// is a wider architecture — which is what stops `arm` matching `arm64`.
#[test]
fn a_windows_host_does_not_select_the_windows_alias_inside_darwin() {
    let release = release_with(&[
        ("tool-darwin-amd64.tar.gz", "https://example.test/darwin"),
        ("tool-windows-amd64.zip", "https://example.test/windows"),
    ]);
    let planned = plan_github_release(
        &github_tool(None),
        &Platform::new("windows", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/windows");
}

/// The bounded-occurrence rule must still accept the spellings that are not a
/// whole token, since rejecting them would reintroduce the opposite failure --
/// an asset that should match not matching, and the user getting a diagnostic
/// listing assets that look right.
#[test]
fn a_bounded_occurrence_still_matches_the_spellings_that_are_not_whole_tokens() {
    for (os, arch, name) in [
        (
            "linux",
            "x86_64",
            "ripgrep-14.0.0-x86_64-unknown-linux-musl.tar.gz",
        ),
        ("darwin", "arm64", "tool_aarch64-apple-darwin.tar.gz"),
        ("windows", "x86_64", "tool-win-x64.zip"),
        ("linux", "x86_64", "my-linux-x86_64-thing.tar.gz"),
    ] {
        assert!(
            super::planning::asset_matches_platform(name, &Platform::new(os, arch)),
            "{name} should match {os}/{arch}"
        );
    }
}

#[test]
fn an_unrecognized_platform_matches_nothing_rather_than_everything() {
    // The safe direction for a name the model does not know: no match, so the
    // user gets a diagnostic listing the available assets. The unsafe direction
    // is a guess, and a guess here installs the wrong binary.
    let release = release_with(&[("tool-linux-amd64.tar.gz", "https://example.test/linux")]);
    let error = plan_github_release(
        &github_tool(None),
        &Platform::new("plan9", "riscv64"),
        &release,
        Some(SHA256.into()),
    )
    .expect_err("an unknown platform must not resolve to something");
    assert!(
        matches!(error, ToolPlanError::AssetSelection { .. }),
        "{error}"
    );
    // **And the refusal has to be actionable**, which is the whole reason this is
    // `AssetSelection` rather than `MissingAsset`. `select_github_asset` is the only
    // diagnostic a project-pinned `gh:` key and `tool plan` ever produce, and
    // `MissingAsset` renders as "tool X has no asset for os/arch" and stops. A
    // 32-bit host against a release publishing `tool_linux_x86.tar.gz` and
    // `tool_linux_x86_64.tar.gz` therefore learned nothing: not which assets exist,
    // and not that the refusal is deliberate because `x86` is a substring of
    // `x86_64`.
    let message = error.to_string();
    assert!(
        message.contains("declare `asset:`"),
        "the refusal must name the way out, got: {message}"
    );
    assert!(
        message.contains("tool-linux-amd64.tar.gz"),
        "and it must list what the release actually publishes, got: {message}"
    );
}

/// **A user who already declared `asset:` must not be told to declare it.** The two
/// cases were one message, so someone who had just written
/// `asset: demo_linux_amd64.zip` was told to "declare `asset:` with the one to
/// install" -- self-contradicting, and their own value appeared nowhere.
///
/// This is the one behavior the commit adding the split introduced, and it had **no
/// test**: collapsing both arms back together passed every test in both crates,
/// because the assertions elsewhere match `AssetSelection { .. }` and discard
/// `reason`. A fix with no row is a fix that can be reverted silently.
///
/// Three things are asserted, because all three are the point:
///
/// - the declared value is echoed, so the user can see what was read;
/// - the instruction does **not** tell them to declare it;
/// - the message still says what to do.
#[test]
fn a_declared_asset_miss_echoes_the_declaration_instead_of_asking_for_one() {
    let release = release_with(&[
        ("demo_linux_amd64.tar.gz", "https://example.test/a"),
        ("demo-darwin-arm64.zip", "https://example.test/b"),
    ]);
    let error = select_github_asset(
        &release.assets,
        Some("demo_linux_amd64.zip"),
        None,
        &Platform::new("linux", "x86_64"),
        "gh:acme/demo",
    )
    .expect_err("a declared name that is not published must not resolve");
    let message = error.to_string();
    assert!(
        message.contains("demo_linux_amd64.zip"),
        "the message must echo what the user wrote, got: {message}"
    );
    assert!(
        !message.contains("declare `asset:`"),
        "telling someone who already declared `asset:` to declare it is the defect, \
         got: {message}"
    );
    assert!(
        message.contains("correct it") || message.contains("remove it"),
        "and it must still say what to do, got: {message}"
    );
    // The value is echoed with `{:?}`, so a committed config cannot carry newlines or
    // ANSI escapes into a teammate's terminal through this diagnostic.
    let release = release_with(&[("demo_linux_amd64.tar.gz", "https://example.test/a")]);
    let injected = select_github_asset(
        &release.assets,
        Some("demo\u{1b}[31m\u{7}x\u{1b}[0m.zip"),
        None,
        &Platform::new("linux", "x86_64"),
        "gh:acme/demo",
    )
    .expect_err("an unterminated escape is not a published asset");
    let text = injected.to_string();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\n'),
        "a declared value must be echoed quoted, not raw, so it cannot rewrite the \
         terminal: {text:?}"
    );

    // **And the *remote* arm of the same hole**, which is the larger of the two: the
    // asset names in the candidate list come from a GitHub release, so a hostile or
    // compromised release is a weaker trust boundary than the user's own config. The
    // config arm was closed first and this one was left open, with `join` on raw
    // names, until a review pointed at it.
    let hostile = release_with(&[
        (
            "demo\u{1b}[31m\u{7}x\u{1b}[0m.tar.gz",
            "https://example.test/a",
        ),
        ("demo\nfake-asset.tar.gz", "https://example.test/b"),
    ]);
    let error = select_github_asset(
        &hostile.assets,
        Some("absent.tar.gz"),
        None,
        &Platform::new("linux", "x86_64"),
        "gh:acme/demo",
    )
    .expect_err("a name with an escape is not a published asset");
    let text = error.to_string();
    assert!(
        !text.contains('\u{1b}'),
        "a release asset name must be escaped, or a hostile release can rewrite a \
         terminal: {text:?}"
    );
    // The name itself *is* shown -- the user needs to see what the release actually
    // published -- so the assertion is on a raw newline rather than on the substring.
    // A name containing one is rendered `"demo\nfake-asset.tar.gz"`, which is a name,
    // not a second line.
    assert!(
        !text.contains('\n'),
        "a newline in a release asset name must not be able to forge a second line: \
         {text:?}"
    );
    assert!(
        text.contains("fake-asset"),
        "and the user must still be able to read what the release published: {text:?}"
    );
}

/// The reference's `asset` is a glob, and `cli-*-linux.tar.gz` is an ordinary Go
/// declaration. Matching it exactly failed closed with `MissingAsset` and a list
/// of assets that visibly matched.
#[test]
fn a_glob_asset_pattern_matches_the_release() {
    let release = release_with(&[
        ("tool-darwin-amd64.tar.gz", "https://example.test/darwin"),
        ("cli-1.0.0-linux.tar.gz", "https://example.test/linux"),
    ]);
    let planned = plan_github_release(
        &github_tool(Some("cli-*-linux.tar.gz")),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/linux");
}

#[test]
fn github_glob_and_grep_asset_selection_rejects_reordered_ambiguity() {
    for selector in [(Some("cli-*-linux.zip"), None)] {
        let forward = release_with(&[
            ("cli-1.0.0-linux.zip", "https://example.test/one"),
            ("cli-2.0.0-linux.zip", "https://example.test/two"),
        ]);
        let reverse = release_with(&[
            ("cli-2.0.0-linux.zip", "https://example.test/two"),
            ("cli-1.0.0-linux.zip", "https://example.test/one"),
        ]);
        for release in [&forward, &reverse] {
            let mut declaration = github_tool(selector.0);
            declaration.github_release.as_mut().unwrap().grep = selector.1.map(str::to_owned);
            let result = plan_github_release(
                &declaration,
                &Platform::new("linux", "x86_64"),
                release,
                Some(SHA256.into()),
            );
            assert!(
                matches!(result, Err(ToolPlanError::AmbiguousAsset { .. })),
                "selector {selector:?} did not reject ambiguity: {result:?}"
            );
        }
    }
    for reverse in [false, true] {
        let release = if reverse {
            release_with(&[
                ("cli-2.0.0-linux-x86_64.tar.gz", "https://example.test/two"),
                ("cli-1.0.0-linux-x86_64.tar.gz", "https://example.test/one"),
            ])
        } else {
            release_with(&[
                ("cli-1.0.0-linux-x86_64.tar.gz", "https://example.test/one"),
                ("cli-2.0.0-linux-x86_64.tar.gz", "https://example.test/two"),
            ])
        };
        assert!(matches!(
            select_github_asset(
                &release.assets,
                None,
                Some("^cli-.*\\.tar\\.gz$"),
                &Platform::new("linux", "x86_64"),
                "tool"
            ),
            Err(ToolPlanError::AmbiguousAsset { .. })
        ));
    }
    let exact = release_with(&[
        ("cli-1.0.0-linux.zip", "https://example.test/one"),
        ("cli-2.0.0-linux.zip", "https://example.test/two"),
    ]);
    assert!(
        plan_github_release(
            &github_tool(Some("cli-2.0.0-linux.zip")),
            &Platform::new("linux", "x86_64"),
            &exact,
            Some(SHA256.into())
        )
        .is_ok(),
        "an exact asset declaration disambiguates a multi-match release"
    );
}

/// The platform fallback must not select a checksum sidecar as the artifact.
///
/// A sidecar is named with the platform as often as the artifact is: `GoReleaser`
/// publishes `foo-linux-amd64.tar.gz` *and* `foo-linux-amd64.tar.gz.sha256`, and
/// both contain the platform's OS and architecture, so a platform match that
/// ignores this picks the checksum file.
/// The installer's global branch filtered sidecars and the shared selector did
/// not, so `tool plan` named the sidecar and `tool install --global` named the
/// archive. The rule now lives in the selector both branches go through.
#[test]
fn a_platform_match_does_not_select_a_checksum_sidecar() {
    let release = release_with(&[
        (
            "tool-linux-x86_64.tar.gz.sha256",
            "https://example.test/sidecar",
        ),
        (
            "tool-linux-x86_64.tar.gz.sig",
            "https://example.test/signature",
        ),
        (
            "tool-linux-x86_64-checksums.txt",
            "https://example.test/checksums",
        ),
        ("tool-linux-x86_64.tar.gz", "https://example.test/artifact"),
    ]);
    let planned = plan_github_release(
        &github_tool(None),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(
        planned.url.as_str(),
        "https://example.test/artifact",
        "a sidecar is not the artifact"
    );
    // And a declared asset still wins, sidecar or not: an explicit name is the
    // user's decision, and this rule must not override it.
    let planned = plan_github_release(
        &github_tool(Some("tool-linux-x86_64.tar.gz.sha256")),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/sidecar");
}

/// A glob is anchored at both ends, like `filepath.Match` -- which the reference
/// uses. An unanchored match would select `evil-cli-1.0.0-linux.tar.gz.bak` for
/// the pattern `cli-*`, and that decides what gets downloaded.
#[test]
fn a_glob_asset_pattern_is_anchored_at_both_ends() {
    for (pattern, expected) in [
        ("cli-*-linux.tar.gz", true),
        ("*-linux.tar.gz", true),
        ("cli-*", true),
        ("cli", false),
        ("*cli", false),
        ("evil-cli-1.0.0.tar.gz", false),
    ] {
        assert_eq!(
            super::planning::glob_matches(pattern, "cli-1.0.0-linux.tar.gz"),
            expected,
            "pattern {pattern}"
        );
    }
    // `?` is one character, not one or more.
    assert!(super::planning::glob_matches(
        "cli-?.0.0-linux.tar.gz",
        "cli-1.0.0-linux.tar.gz"
    ));
    assert!(!super::planning::glob_matches(
        "cli-?.0.0-linux.tar.gz",
        "cli-12.0.0-linux.tar.gz"
    ));
}

/// The architecture placeholder substitutes both spellings, because this
/// model's `Platform` says `x86_64` where the reference says `amd64` and release
/// assets are named with either. Substituting only the model's own spelling made
/// `asset: "tool-{arch}.tar.gz"` fail against a release publishing
/// `tool-amd64.tar.gz` -- and the platform fallback then papered over the failure
/// by selecting a *different* artifact.
#[test]
fn the_arch_placeholder_substitutes_every_spelling_of_this_architecture() {
    for (os, arch, asset_name) in [
        ("linux", "x86_64", "tool-linux-amd64.tar.gz"),
        ("linux", "x86_64", "tool-linux-x86_64.tar.gz"),
        ("linux", "x86_64", "tool-linux-x64.tar.gz"),
        ("linux", "arm64", "tool-linux-arm64.tar.gz"),
        ("linux", "arm64", "tool-linux-aarch64.tar.gz"),
        // And the OS half, which the earlier version of this test bound to a
        // constant and so claimed a dimension it did not have.
        ("darwin", "x86_64", "tool-macos-amd64.tar.gz"),
        ("darwin", "x86_64", "tool-darwin-amd64.tar.gz"),
        ("darwin", "x86_64", "tool-osx-amd64.tar.gz"),
        ("windows", "x86_64", "tool-windows-amd64.tar.gz"),
    ] {
        let release = release_with(&[(asset_name, "https://example.test/hit")]);
        let planned = plan_github_release(
            &github_tool(Some("tool-{os}-{arch}.tar.gz")),
            &Platform::new(os, arch),
            &release,
            Some(SHA256.into()),
        )
        .unwrap_or_else(|error| panic!("{os}/{arch} vs {asset_name}: {error}"));
        assert_eq!(planned.url.as_str(), "https://example.test/hit");
    }
}

/// A pattern that is *both* a template and a glob keeps its wildcards.
///
/// `cli-*-{arch}*.zip` has placeholders, so it took the template arm, had them
/// substituted into `cli-*-x86_64*.zip`, and was then compared for exact
/// equality -- which cannot succeed. The result was a `MissingAsset` whose
/// message did not echo the pattern the user wrote.
#[test]
fn a_pattern_that_is_both_a_template_and_a_glob_keeps_its_wildcards() {
    let release = release_with(&[("cli-2.0.0-x86_64-linux.zip", "https://example.test/hit")]);
    let planned = plan_github_release(
        &github_tool(Some("cli-*-{arch}-*.zip")),
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(planned.url.as_str(), "https://example.test/hit");
}

/// An empty or non-ASCII platform name must match nothing, and must not panic.
///
/// Both were a panic rather than a wrong answer: an empty alias makes
/// `find("")` return `Some(0)` on every resume, and a non-ASCII one makes
/// `start + 1` a non-boundary slice. Neither is reachable from
/// `Platform::host()`, but a caller passing one would have taken the process
/// down inside a `validate` over a file the user is editing.
#[test]
fn an_unusable_platform_name_matches_nothing_rather_than_panicking() {
    // The empty asset name is in the list too, since an empty alias matches it
    // at every position.
    for (os, arch) in [("", "x86_64"), ("x86_64", ""), ("élan", "x86_64"), ("", "")] {
        for name in ["", "tool-linux-x86_64.tar.gz", "tool-élan.tar.gz"] {
            assert!(
                !super::planning::asset_matches_platform(name, &Platform::new(os, arch)),
                "{os:?}/{arch:?} matched {name:?}"
            );
        }
    }
}

/// A binary name that is not a single file name is refused at *plan* time.
///
/// The planner checked only emptiness, so `rename: "../../evil"` produced a plan,
/// `tool plan` printed a tool the user could see and believe, and the failure
/// arrived at lock-write time as a diagnostic that never mentions the key it came
/// from. The installer writes `<root>/bin/<name>`, so anything with a separator
/// writes outside that.
#[test]
fn a_binary_name_that_is_not_one_file_name_is_refused() {
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/linux")]);
    for name in ["../../evil", "a/b", "..", ".", "a\\b", "/abs"] {
        let mut tool = github_tool(None);
        tool.binaries = vec![name.into()];
        let error = plan_github_release(
            &tool,
            &Platform::new("linux", "x86_64"),
            &release,
            Some(SHA256.into()),
        )
        .expect_err(&format!("{name:?} was accepted"));
        match &error {
            ToolPlanError::UnsafeBinaryName { name: reported, .. } => {
                assert_eq!(reported, name);
            }
            other => panic!("{name:?}: expected an unsafe-name refusal, got {other}"),
        }
        // The message has to name the offending value, or the user cannot find it.
        assert!(error.to_string().contains(name), "{error}");
    }
    // And a plain name is still fine, or the check would be refusing everything.
    let mut tool = github_tool(None);
    tool.binaries = vec!["tool".into()];
    plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("a plain binary name must plan");
}

#[test]
fn a_per_platform_binary_layout_is_refused_like_the_declarations_own() {
    // The refusal only checked the declaration's own keys, so a per-platform
    // `binpath` was read into the override and then read by nothing: the plan
    // succeeded, the archive-root binary was installed, and no diagnostic fired.
    let release = release_with(&[("tool-linux-x86_64.tar.gz", "https://example.test/linux")]);
    let cases: &[(&str, OverrideSetter)] = &[
        ("binpath", set_override_binpath),
        ("bindir", set_override_bindir),
    ];
    for (expected, set) in cases {
        let mut tool = github_tool(None);
        set(&mut tool);
        let error = plan_github_release(
            &tool,
            &Platform::new("linux", "x86_64"),
            &release,
            Some(SHA256.into()),
        )
        .expect_err("a per-platform binary layout must not resolve");
        match &error {
            ToolPlanError::UnsupportedBinaryLayout { key, .. } => assert_eq!(key, expected),
            other => panic!("expected an unsupported binary layout, got {other}"),
        }
        assert!(error.to_string().contains("bins:"), "{error}");
    }
}

#[test]
fn a_per_platform_bins_replaces_the_declarations_own() {
    // `plan_github_release` read `declaration.binaries` unconditionally, so
    // `linux-amd64: {bins: [helper]}` was dropped -- the same shape as the
    // per-platform `asset` case, which *was* honored.
    // Both platforms, so the second half can assert something about binaries
    // rather than a missing asset.
    let release = release_with(&[
        ("tool-linux-x86_64.tar.gz", "https://example.test/linux"),
        ("tool-darwin-arm64.tar.gz", "https://example.test/darwin"),
    ]);
    let mut tool = github_tool(None);
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: None,
        },
        url: None,
        sha256: None,
        binaries: Some(vec!["helper".into(), "tool".into()]),
        binpath: None,
        bindir: None,
        asset: None,
        grep: None,
        rename: None,
    }];
    let planned = plan_github_release(
        &tool,
        &Platform::new("linux", "x86_64"),
        &release,
        Some(SHA256.into()),
    )
    .unwrap();
    assert_eq!(
        planned.binaries,
        vec!["helper".to_owned(), "tool".to_owned()]
    );
    // And the declaration's own list still applies off the overridden platform.
    // Without this the override could be read as a *replacement* for the whole
    // declaration rather than for the binary list, and every other platform
    // would lose its binaries.
    let planned = plan_github_release(
        &tool,
        &Platform::new("darwin", "arm64"),
        &release,
        Some(SHA256.into()),
    )
    .expect("a platform with no override plans from the declaration");
    assert_eq!(planned.binaries, vec!["tool".to_owned()]);
}

/// A `url:` on a release key must produce a plan the *lock* accepts.
///
/// This is the regression guard for a plan that was built, printed by `tool
/// plan`, and then rejected by `write_lockfile` before any download: the direct-URL
/// branch set `asset_id: None` while keeping `provider: "github-release"`, and the
/// lock's provenance invariant requires all three of repository, release id, and
/// asset id for that provider.
///
/// The planner's own tests could not catch it -- they call the planner directly,
/// so they never see the lock. This one writes a lockfile.
#[test]
fn a_github_plan_always_satisfies_the_locks_provenance_invariant() {
    let release = release_with(&[(
        "tool-linux-x86_64.tar.gz",
        "https://example.test/from-release",
    )]);
    for (label, asset, url) in [
        // A declared asset, as a plain release entry.
        ("declared asset", Some("tool-linux-x86_64.tar.gz"), None),
        // No declared asset: the platform fallback.
        ("platform selection", None, None),
        // A `url:` present. The reference short-circuits asset selection with it,
        // and this model expresses that by mapping the entry to the
        // `explicit-url` provider in the compatibility reader -- so a
        // `github-release` declaration that *also* carries a `url` must still
        // plan, and plan from the release.
        (
            "a url on a release declaration",
            None,
            Some("https://example.test/declared.tar.gz"),
        ),
    ] {
        let mut tool = github_tool(asset);
        tool.url = url.map(str::to_owned);
        let plan = plan_github_release(
            &tool,
            &Platform::new("linux", "x86_64"),
            &release,
            Some(SHA256.into()),
        )
        .unwrap_or_else(|error| panic!("{label} failed to plan: {error}"));
        // The invariant, stated as the lock states it.
        let provenance = &plan.provenance;
        assert_eq!(
            provenance.provider, "github-release",
            "{label}: the provider changed"
        );
        assert!(
            provenance.repository.is_some()
                && provenance.release_id.is_some()
                && provenance.asset_id.is_some(),
            "{label}: a github-release lock entry must name the release and the              asset, and this one has {repository:?}/{release_id:?}/{asset_id:?}",
            repository = provenance.repository,
            release_id = provenance.release_id,
            asset_id = provenance.asset_id
        );
        // And the lock actually accepts it, rather than the invariant merely
        // appearing to hold.
        let lock = ToolLockfile::from_plan(&ToolPlan { tools: vec![plan] });
        lock.validate()
            .unwrap_or_else(|error| panic!("{label}: the lock refused it: {error}"));
    }
}

/// The refusal has to run before the provider dispatch, not inside two planners.
///
/// `aqua` and the four registry providers each planned `declaration.binaries`
/// and installed it at the archive root, so a native `provider: aqua` with
/// `binpath: dist/cli` installed the wrong binary and reported success. Checking
/// inside `plan_github_release` and `plan_tools` covered two of eight providers.
#[test]
fn a_binary_layout_is_refused_for_every_provider() {
    // The loop is over providers because the *call site* is: `reject_binary_layout`
    // itself never dispatches on `provider`, so this checks that the refusal is
    // reached from every provider's path. A test of the function alone would pass
    // with the call site deleted -- which is what happened, for six of eight.
    for provider in [
        ToolProvider::Aqua,
        ToolProvider::Npm,
        ToolProvider::DotnetTool,
        ToolProvider::GoModule,
        ToolProvider::RubyGems,
        ToolProvider::ExplicitUrl,
        ToolProvider::GithubRelease,
        ToolProvider::Extension("something".into()),
    ] {
        // `name()` because `ToolProvider` has no `Display`, and a test that
        // cannot say which provider it is looking at cannot be read when it fails.
        // Taken from the loop value, not from the default declaration -- which
        // would have labelled every iteration the same thing.
        let label = provider.name().to_owned();
        let mut tool = declaration("tool");
        tool.provider = provider;
        tool.url = Some("https://example.test/tool.tar.gz".into());
        tool.binpath = Some("dist/tool".into());
        let error = reject_binary_layout(&tool).expect_err("every provider must refuse a binpath");
        match &error {
            ToolPlanError::UnsupportedBinaryLayout { key, .. } => {
                assert_eq!(key, "binpath", "{label}");
            }
            other => panic!("{label}: expected a binary-layout refusal, got {other}"),
        }
        // Per-platform, on every provider too.
        let mut scoped = tool.clone();
        scoped.binpath = None;
        scoped.platforms = vec![PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: None,
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: Some("dist/tool".into()),
            bindir: None,
            asset: None,
            grep: None,
            rename: None,
        }];
        assert!(
            reject_binary_layout(&scoped).is_err(),
            "{label}: a per-platform binpath must be refused too"
        );
    }
}

#[test]
fn a_native_declaration_with_a_binary_layout_is_refused() {
    // `plan_tools` is the path the native `explicit-url` provider goes through,
    // and it never called the refusal -- so a native file setting `binpath`
    // installed the archive-root binary and reported success. A silent drop
    // outside the Go dialect, introduced by making the keys readable.
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::ExplicitUrl;
    tool.binpath = Some("dist/tool".into());
    let error = plan_tools(&[tool], &Platform::new("linux", "x86_64"))
        .expect_err("a native binary layout must not resolve");
    match error {
        ToolPlanError::UnsupportedBinaryLayout { key, .. } => assert_eq!(key, "binpath"),
        other => panic!("expected an unsupported binary layout, got {other}"),
    }
}

#[test]
fn plans_aqua_asset_only_from_a_pinned_manifest() {
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::Aqua;
    tool.url = None;
    tool.sha256 = None;
    tool.aqua = Some(AquaDeclaration {
        endpoint: "http://127.0.0.1:8080".into(),
        registry_revision: "a".repeat(40),
        package: "owner/tool".into(),
        manifest_sha256: SHA256.into(),
    });
    let planned = plan_aqua_registry(
        &tool,
        &Platform::new("linux", "x86_64"),
        &AquaRegistryManifest {
            package: "owner/tool".into(),
            assets: vec![AquaRegistryAsset {
                version: "1.0.0".into(),
                platform: Platform::new("linux", "x86_64"),
                url: "https://example.test/tool.tar.gz".into(),
                sha256: SHA256.into(),
            }],
        },
    )
    .unwrap();
    assert_eq!(
        planned.provenance.registry_revision.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(planned.provenance.package.as_deref(), Some("owner/tool"));
}

#[test]
fn rejects_ambiguous_aqua_assets() {
    let mut tool = declaration("tool");
    tool.provider = ToolProvider::Aqua;
    tool.aqua = Some(AquaDeclaration {
        endpoint: "https://registry.example.test".into(),
        registry_revision: "a".repeat(40),
        package: "owner/tool".into(),
        manifest_sha256: SHA256.into(),
    });
    let asset = AquaRegistryAsset {
        version: "1.0.0".into(),
        platform: Platform::new("linux", "x86_64"),
        url: "https://example.test/tool.tar.gz".into(),
        sha256: SHA256.into(),
    };
    assert!(matches!(
        plan_aqua_registry(
            &tool,
            &Platform::new("linux", "x86_64"),
            &AquaRegistryManifest {
                package: "owner/tool".into(),
                assets: vec![asset.clone(), asset]
            },
        ),
        Err(ToolPlanError::AmbiguousAsset { .. })
    ));
}

#[test]
fn plans_dotnet_tool_with_immutable_nuget_identity() {
    let mut tool = declaration("dotnetsay");
    tool.provider = ToolProvider::DotnetTool;
    tool.url = None;
    tool.sha256 = None;
    tool.dotnet_tool = Some(DotnetToolDeclaration {
        source: "nuget-v3".into(),
        endpoint: "http://127.0.0.1:8080/v3-flatcontainer".into(),
        package: "DotNetSay".into(),
    });
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode([0_u8; 64])
    );
    let planned = plan_dotnet_tool(
        &tool,
        &Platform::new("linux", "x86_64"),
        SHA256.into(),
        integrity,
    )
    .unwrap();
    assert_eq!(
        planned.url,
        "http://127.0.0.1:8080/v3-flatcontainer/dotnetsay/1.0.0/dotnetsay.1.0.0.nupkg"
    );
    assert!(
        planned
            .provenance
            .immutable_id
            .starts_with("nuget:dotnetsay/version:1.0.0/sha512:")
    );
}

#[test]
fn plans_go_module_only_with_exact_checksum_evidence() {
    let go_sum = format!("h1:{}", STANDARD.encode([0_u8; 32]));
    let mut tool = declaration("demo");
    tool.provider = ToolProvider::GoModule;
    tool.version = "v1.0.0".into();
    tool.url = None;
    tool.sha256 = None;
    tool.go_module = Some(GoModuleDeclaration {
        source: "go-proxy".into(),
        endpoint: "http://127.0.0.1:8080".into(),
        module: "example.test/tools/demo".into(),
        go_sum: go_sum.clone(),
    });
    let planned = plan_go_module(
        &tool,
        &Platform::new("linux", "x86_64"),
        SHA256.into(),
        &go_sum,
    )
    .unwrap();
    assert_eq!(
        planned.url,
        "http://127.0.0.1:8080/example.test/tools/demo/@v/v1.0.0.zip"
    );
    assert!(has_go_module_evidence(&planned.provenance));
    assert_eq!(
        canonicalize_url(&planned.url).as_deref(),
        Ok(planned.url.as_str())
    );
    ToolLockfile::from_plan(&ToolPlan {
        tools: vec![planned],
    })
    .validate()
    .unwrap();

    tool.version = "latest".into();
    assert!(matches!(
        plan_go_module(
            &tool,
            &Platform::new("linux", "x86_64"),
            SHA256.into(),
            &go_sum,
        ),
        Err(ToolPlanError::InvalidGoModule { .. })
    ));
}

#[test]
fn plans_ruby_gem_with_mandatory_archive_sha256() {
    let mut tool = declaration("demo");
    tool.version = "1.2.3".into();
    tool.provider = ToolProvider::RubyGems;
    tool.url = None;
    tool.sha256 = None;
    tool.ruby_gems = Some(RubyGemsDeclaration {
        endpoint: "https://registry.example.test".into(),
        gem: "demo".into(),
    });
    let planned = plan_ruby_gems(
        &tool,
        &Platform::new("linux", "x86_64"),
        &RubyGemsRegistryPackage {
            gem: "demo".into(),
            version: "1.2.3".into(),
            platform: "ruby".into(),
            sha256: SHA256.into(),
        },
    )
    .unwrap();
    assert_eq!(planned.sha256, SHA256);
    assert_eq!(
        planned.provenance.registry_integrity.as_deref(),
        Some(SHA256)
    );
}

/// A setter for one of the two binary-layout keys, so the refusal test can
/// cover both with one body instead of two copies of it.
type LayoutSetter = fn(&mut ToolDeclaration, Option<String>);

fn set_binpath(tool: &mut ToolDeclaration, value: Option<String>) {
    tool.binpath = value;
}

fn set_bindir(tool: &mut ToolDeclaration, value: Option<String>) {
    tool.bindir = value;
}

/// Sets a per-platform binary-layout key, so the refusal test covers both keys
/// with one body instead of two copies of it.
type OverrideSetter = fn(&mut ToolDeclaration);

fn set_override_binpath(tool: &mut ToolDeclaration) {
    tool.platforms = vec![PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: None,
        },
        url: None,
        sha256: None,
        binaries: None,
        binpath: Some("dist/cli".into()),
        bindir: None,
        asset: None,
        grep: None,
        rename: None,
    }];
}

fn set_override_bindir(tool: &mut ToolDeclaration) {
    set_override_binpath(tool);
    let override_ = &mut tool.platforms[0];
    override_.binpath = None;
    override_.bindir = Some("dist".into());
}

/// The artifact test, over the whole set rather than the two names that failed.
///
/// Two earlier shapes of this rule each failed in *one* direction, and the two
/// failures together are what forced the current one:
///
/// - substring-anywhere missed `spdx`/`cdx`, so `foo_linux_amd64.spdx.json` was
///   selected as the artifact, while matching `sbomctl-linux-amd64` anywhere;
/// - "no extension-shaped tail" caught the SBOMs and rejected
///   `foo-linux-amd64-1.0.0`, which ends in a one-character segment.
///
/// So the table below is deliberately long in both directions, and every row is a
/// name that actually occurs rather than a shape invented for the test.
#[test]
// A table of real asset names, not logic. Splitting it would put a name and its
// expectation in different functions, which is the one thing this table exists to
// make easy to compare.
#[allow(clippy::too_many_lines)]
fn an_artifact_is_recognized_by_its_last_extension_naming_a_sidecar_kind() {
    for (name, is_artifact) in [
        // Artifacts, including the version-in-the-name forms the previous rule
        // refused. The version is *last* in these, which is the case the
        // "extension-shaped tail" argument got wrong.
        ("tool-linux-amd64", true),
        ("tool-linux-x86_64.tar.gz", true),
        ("tool-linux-amd64.tgz", true),
        ("tool-windows-x86_64.zip", true),
        ("tool-linux-amd64-1.0.0", true),
        ("tool_linux_amd64_1.0.0", true),
        ("tool-linux-amd64-v1.0", true),
        ("tool-1.2.3-linux-amd64", true),
        // Suffixes the previous commit's table carried but this one does not need
        // to: an unrecognized extension is the artifact, which is what makes a
        // release of `tool_1.2.3_linux_amd64.tar.zst` resolve.
        ("tool-linux-amd64.pyz", true),
        ("node-v20.11.0-linux-x64.tar.xz", true),
        ("tool-linux-amd64.dat", true),
        // **...except a distribution package, which was the exception this
        // paragraph was written to justify and it was the wrong way round.**
        //
        // Three rows here read `("…_linux_amd64.deb", true)` under the comment above,
        // and they pinned a live wrong install. `cli/cli` v2.101.0 lists
        // `gh_2.101.0_linux_amd64.deb` at asset 4 and the real
        // `gh_2.101.0_linux_amd64.tar.gz` at asset 6; first-match took the `.deb`,
        // `ArtifactPlan` fell through to `RawBinary`, and `extract_raw_binary`
        // copied the `ar` blob to `bin/gh`, marked it executable, wrote a receipt
        // and published a launcher. **The install reported success** and the first
        // run failed with `Exec format error`. Across 100 repositories: 1,120
        // names no extractor can open, and 84 selections that took a package over a
        // real archive.
        //
        // The paragraph's own reasoning is the tell: "an unrecognized extension is
        // the artifact" is right for `.dat` and `.pyz`, which no tool ships as
        // anything but a program, and wrong for a *package*, which is not an
        // unrecognized thing at all -- it is a very well known thing that is not a
        // program. See `is_package_not_program`.
        ("tool_1.2.3_linux_amd64.deb", false),
        ("tool_1.2.3_linux_amd64.rpm", false),
        ("gh_2.101.0_linux_amd64.deb", false),
        ("grafana_enterprise-11.6.0_linux_amd64.rpm", false),
        ("trivy_0.58.1_Linux-64bit.deb", false),
        ("logseq-desktop-arm64.dmg", false),
        ("podman-installer-windows-amd64.msi", false),
        // Any dot-segment, not just the last, so a package name wrapped in a
        // compression suffix is still caught. mise's test is the same, which is why
        // it refuses `goreleaser_…_x86_64.pkg.tar.zst` and a last-extension rule
        // would not.
        ("goreleaser_2.18.2_linux_amd64.pkg.tar.zst", false),
        ("tool-linux-amd64.flatpak", false),
        ("tool.1.2.3.nupkg", false),
        // Openable but not a program: kept out of automatic selection, *not* refused
        // as unopenable, because a wheel and a gem are a zip and a tar.
        ("tool-1.2.3-py3-none-manylinux_2_17_x86_64.whl", false),
        ("tool-1.2.3.gem", false),
        ("tool-1.2.3.jar", false),
        // **The compression formats with no decoder here**, which the previous
        // version of this table left to the installer's worse diagnostic. Selection
        // is the right place for them: `gh:fastfetch-cli/fastfetch` shipped
        // `fastfetch-windows-amd64.7z` and `fastfetch-windows-amd64.zip` in the
        // same release, and first-match took the `.7z`, so the user never learned
        // the `.zip` was sitting right there.
        ("fastfetch-windows-amd64.7z", false),
        ("restic_0.19.1_linux_amd64.bz2", false),
        ("ollama-linux-amd64.tar.zst", false),
        ("tool.7z", false),
        ("tool.br", false),
        // **An AppImage is refused, and it was briefly not.** The removal argued
        // that an AppImage is a directly-runnable ELF and so installs correctly,
        // citing `gh:neovim/neovim` and `gh:logseq/logseq` selecting one "at the
        // parent commit" with "the result ran". Both halves were false: those
        // releases selected `nvim-linux-x86_64.tar.gz` and
        // `Logseq-linux-x64-0.10.15.zip` at the parent, so the AppImage was the
        // *new* winner, and no run was ever recorded. The real reason is that an
        // AppImage **needs FUSE at run time**, so on a host without `libfuse2` the
        // install reports success and the first run fails -- the same shape as the
        // bug this table prevents, one layer up.
        ("tool-linux-amd64.AppImage", false),
        ("nvim-linux-x86_64.appimage", false),
        // ...and the archive beside it, which is what those two releases actually
        // published first.
        ("nvim-linux-x86_64.tar.gz", true),
        // **The bzip2 shorthands.** `bz2` was listed and these were not, so the same
        // bytes took two paths depending on spelling, and `aristocratos/btop`
        // publishes `btop-*.tbz` and nothing else.
        ("btop-x86_64-linux-musl.tbz", false),
        ("btop-aarch64-unknown-linux-musl.tbz2", false),
        // ...and a name carrying a package marker is still a package when the
        // program is the archive, so the program half is untouched.
        ("tool_1.2.3_linux_amd64.tar.gz", true),
        ("tool_1.2.3_linux_amd64.tar.xz", true),
        ("tool_1.2.3_linux_amd64.zip", true),
        // **`.tar.zst` is refused for the *compression* reason, not the packaging
        // one**, and the two reasons give different advice. An earlier version of
        // this paragraph listed `tar.zst` as a third "addition" to the package list
        // while a code comment twelve lines away said `zst` is "not a package", so
        // the document and the code each said something different about the same
        // entry. The row cannot tell the two reasons apart — only the message can —
        // so what it pins is the verdict, and the reason split is asserted in the
        // installer's test, where both halves of the advice live.
        ("tool_1.2.3_linux_amd64.tar.zst", false),
        // A program that merely *contains* a listed substring, which the any-segment
        // test could have caught and does not: `appimage` needs a whole segment.
        ("myappimager-linux-amd64", true),
        ("debian-linux-amd64", true),
        ("apkbuilder-linux-amd64", true),
        ("pkgdownloader-linux-amd64", true),
        // A tool whose *name* contains a sidecar marker is still the tool.
        ("sbomctl-linux-amd64", true),
        ("sha256sum-linux-amd64.tar.gz", true),
        ("sums-linux-amd64", true),
        // Sidecars, by the two extensions `GoReleaser` emits for an SBOM.
        ("foo_linux_amd64.spdx.json", false),
        ("foo_linux_amd64.cdx.json", false),
        ("foo_linux_amd64.sbom.json", false),
        // Digests, appended and standalone.
        ("tool-linux-x86_64.tar.gz.sha256", false),
        ("tool-linux-x86_64.tar.gz.sha512", false),
        ("tool-linux-x86_64-checksums.txt", false),
        ("provenance.json", false),
        ("foo-linux-amd64.jsonl", false),
        // Signatures and attestations.
        ("tool-linux-x86_64.tar.gz.sig", false),
        ("tool-linux-x86_64.tar.gz.asc", false),
        ("tool-linux-x86_64.tar.gz.minisig", false),
        ("foo.intoto.jsonl", false),
        // The digest-manifest family, in all three spellings that occur. The
        // templated ones matter most: `foo_linux_amd64_SHA256SUMS` matches linux
        // and x86_64 in its *prefix*, so treating it as an artifact selects the
        // manifest -- the exact bug this rule exists to close.
        ("SHA256SUMS", false),
        ("sha256sums", false),
        ("Sha256Sums", false),
        ("foo_SHA256SUMS", false),
        ("foo_linux_amd64_SHA256SUMS", false),
        ("foo-1.2.3_SHA256SUMS", false),
        // The dotted spelling of the digest-manifest family. The last token of
        // `foo_linux_amd64.sha256sums` is `amd64.sha256sums`, whose algorithm
        // contains a dot -- and an alphanumerics-only bound on it made the manifest
        // classify as the artifact, match linux and amd64 in its prefix, and get
        // installed as the program. The underscore spelling was already caught, so
        // the two differed on a single character.
        ("foo_linux_amd64.sha256sums", false),
        ("amd64.sha256sums", false),
        // A bare `sums`/`sum` as the whole trailing token is GoReleaser's
        // `checksum.name_template: "{{ .ArtifactName }}_sums"` output, so it is a
        // manifest. An earlier version read an empty head as "no algorithm named,
        // so this is a tool called `...-sums`" and installed the manifest as the
        // program. The one name that must survive is the *whole name* being the
        // suffix, because `sum` is a real program in its own right.
        ("tool-linux-amd64-sums", false),
        ("foo_linux_amd64_sums", false),
        ("sum", true),
        ("sums", true),
        ("sums-linux-amd64", true),
        // A word that merely *ends* in `sum` is not a manifest. The rule used to
        // accept any non-empty head, so all four of these were filed as digests --
        // and a release of `tool_linux_amd64.tar.gz` plus one of them then had no
        // platform artifact at all and failed with "no platform binary or archive
        // matched". A digest of the wrong thing is still not the program.
        ("tool_linux_amd64-cksum", true),
        ("tool_linux_amd64.b2sum", true),
        // And the coreutils spellings, which *are* the convention.
        ("foo_linux_amd64.md5sum", false),
        ("foo_linux_amd64.sha1sum", false),
        // **...but a bare marker is a program.** `md5sum`, `sha1sum`, and
        // `sha256sum` are coreutils, and two rows asserted the opposite. The miss
        // fails closed and so hid behind a diagnostic the user has no reason to
        // doubt -- which is the general shape: a wrong classification that fails
        // closed is still a wrong classification.
        ("md5sum", true),
        ("sha1sum", true),
        ("sha256sum", true),
        ("blake3", true),
        // ...and so is a bare algorithm, which is a plausible project name and is
        // not a manifest. The installer reached the opposite answer, so the two
        // halves disagreed on a name both could be asked about.
        ("sha256", true),
        ("cksum", true),
        // **Every remaining member of `COREOUTSUM_DIGEST_PROGRAMS` has a row here,
        // in the crate that owns the list.** An earlier version put six of them in
        // the *installer's* test file, which exercises a function that never reads
        // the table -- so they passed and proved nothing. The list is the one place
        // here that needs a closed membership test rather than a shape, and the cost
        // of that is a row per member, which is a good trade: a member with no row is
        // how `sums` sat in the list contradicting the doc three lines above it.
        ("sum", true),
        ("b2sum", true),
        ("shasum", true),
        ("sha224sum", true),
        ("sha384sum", true),
        ("sha512sum", true),
        ("b3sum", true),
        ("blake3sum", true),
        // The SHA-3 family, and the dashed spellings. `sha3sum` was named in the
        // previous version's own doc as a shape it could not see, and shipped
        // without being fixed; `sha3-256sums` additionally required the suffix split
        // to stop treating `-` as a separator, or the algorithm token arrived as
        // `256`.
        ("foo_linux_amd64.sha3sums", false),
        ("foo_linux_amd64.sha3-256sums", false),
        ("foo_linux_amd64.sha3-512sum", false),
        ("sha3-256sums", false),
        // The extensionless `checksum` spellings, which were the other half of a
        // pair: `foo_linux_amd64.checksums.txt` was a sidecar and
        // `foo_linux_amd64.checksums` was the artifact.
        ("foo_linux_amd64.checksums", false),
        ("foo_linux_amd64.checksum", false),
        // The architecture in front of the algorithm, which is the GoReleaser
        // spelling. It resolves because the *suffix* split stops at `_` and `.`, so
        // the head arrives whole; a `-` in the split would reduce it to `sha512sum`.
        ("x86_64.sha512sum", false),
        ("amd64.sha256sums", false),
        // A manifest glued onto a **multi-component version string**, which is the
        // shape every `-<version>-<os>-<arch>` project name has. This row exists
        // because an earlier version of the rule scanned only the *last* `_`/`.`-
        // delimited component, so the head arrived as
        // `64-unknown-linux-musl-sha256`, matched no algorithm, and the manifest
        // was installed as the program. The installer's classifier called the same
        // name a digest, so two halves of one provider disagreed out loud on a name
        // ripgrep actually publishes.
        ("ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz", true),
        ("ripgrep-15.2.0-x86_64-unknown-linux-musl-sha256sums", false),
        ("ripgrep-15.2.0-x86_64-unknown-linux-musl.sha256sums", false),
        // **A real single-segment SBOM, from a real release.** `anchore/syft`
        // publishes `syft_<version>_<os>_<arch>.sbom` for every platform of every
        // release, and the name carries `linux`/`darwin` and `amd64`/`arm64` in its
        // prefix, so it satisfies the whole platform predicate. `sbom` was deleted
        // from `SIDECAR_EXTENSIONS` one commit ago because removing it failed no
        // test -- which is circular, because a member with no row is exactly what
        // "no failing test" measures. This row is the missing half of that
        // argument, and it is a real asset name rather than an invented one.
        ("syft_1.52.0_linux_amd64.sbom", false),
        ("syft_1.52.0_darwin_arm64.sbom", false),
        ("syft_1.52.0_linux_amd64.tar.gz", true),
        // **A binary patch.** `denoland/deno` publishes
        // `deno-x86_64-unknown-linux-gnu.from-2.9.6.bsdiff` -- a *delta* between two
        // releases, not the program -- and it is listed **ahead of the `.zip`** in
        // upload order, so first-match selection installed the patch and reported
        // success, on every platform, today. Found by the same 1039-name corpus
        // scan that found `sbom`.
        ("deno-x86_64-unknown-linux-gnu.from-2.9.6.bsdiff", false),
        ("deno-x86_64-unknown-linux-gnu.zip", true),
        // **A provenance proof.** `FiloSottile/age` publishes
        // `age-v1.3.2-linux-amd64.tar.gz.proof` for every platform -- nine of them.
        // Not currently exploitable, because age uploads the archive first, but
        // `select_github_asset` is first-match with no ordering guarantee.
        ("age-v1.3.2-linux-amd64.tar.gz.proof", false),
        ("age-v1.3.2-linux-amd64.tar.gz", true),
        // **A per-file digest in the `shasum` spelling.** `minio/mc` publishes 54 of
        // these, one per platform, each carrying linux/darwin and amd64/arm64 in its
        // prefix. A row here asserted the *opposite*, on the reasoning that `shasum`
        // is a coreutils program and so its name cannot be a manifest. Both claims
        // are true and they are different claims: `shasum` alone is a program, and
        // `foo_linux_amd64.shasum` is a digest. The row was testing the first with a
        // name for the second. Both are now asserted.
        ("tool_linux_amd64.shasum", false),
        ("shasum", true),
        // **An electron-updater channel manifest, listed first in the release.**
        // `logseq/logseq` publishes six of these and none of them is a program; the
        // planner picked one and reported success. mise does not classify `.yml` as a
        // checksum either, so nothing upstream catches this.
        ("latest-linux-arm64.yml", false),
        ("latest-x64-mac.yml", false),
        ("latest.yml", false),
        // **A `b2` digest and an IPFS CID.** `watchexec/watchexec` publishes `B3SUMS`
        // plus 160 `*.b3` files; `ipfs/kubo` publishes 46 `*.cid`.
        ("foo_linux_amd64.b3", false),
        ("B3SUMS", false),
        ("foo_linux_amd64.cid", false),
        // A general YAML sidecar, which is not a digest at all -- this list is a list
        // of sidecar *kinds*.
        ("foo_linux_amd64.goreleaser.yaml", false),
        // **An electron-updater chunk-hash manifest, in the same release as the
        // `.yml` above.** `logseq/logseq` 2.0.1 lists
        // `Logseq-darwin-arm64-2.0.1.dmg.blockmap` as asset **10** and the real
        // `.dmg` as **12**, so first-match selection installed the blockmap and
        // reported success. It had been added to the *installer's* signature list
        // instead, which is the digest classifier -- putting a sidecar kind in the
        // wrong one of two adjacent tables is invisible to every test that does not
        // simulate first-match over a real release's ordering.
        ("Logseq-darwin-arm64-2.0.1.dmg.blockmap", false),
        // The `.dmg` beside it is **also not the program** -- a disk image cannot
        // become a binary -- so it is covered by the package rule rather than the
        // sidecar one. That is the second half of this release: with both rows
        // wrong in the same way, `gh:logseq/logseq` on darwin/arm64 had no correct
        // candidate at all.
        ("Logseq-darwin-arm64-2.0.1.dmg", false),
        // **The only digest in `containers/podman`'s release.** Nine assets, and this
        // extensionless one. Both halves called it a program, so the install was
        // refused with `shasums` listed as available in the message that said it was
        // not there. mise's `CHECKSUM_PATTERNS` carries `(?i)^SHASUMS`, so this was a
        // parity loss rather than a shared gap.
        ("shasums", false),
        ("shasum", true),
        // **A BLAKE2b and a SHA3-512 digest, uppercase with an underscore.**
        // `saltstack/salt` publishes both for every platform of every release --
        // six real names -- and `SHA512` was already covered while these were not.
        ("salt-3008.1-2-onedir-linux-arm64.tar.xz.BLAKE2B", false),
        ("salt-3008.1-2-onedir-linux-arm64.tar.xz.SHA3_512", false),
        ("salt-3008.1-2-onedir-linux-x86_64.tar.xz.SHA512", false),
        ("salt-3008.1-2-onedir-linux-x86_64.tar.xz", true),
        // `sha3_256` has **no publisher in the corpus** and removing it fails
        // nothing, so this row exists to make the entry a *decision* rather than a
        // leftover: it is kept because a missing sidecar kind installs the wrong file
        // and an extra one costs a string, and the row is what stops that asymmetry
        // from quietly becoming "anything may be added here without asking".
        ("foo_linux_amd64.SHA3_256", false),
        // **The BLAKE3 reference implementation's binaries.** Adding `b3` to the
        // algorithm list for `B3SUMS` made *these* read as manifests, because the
        // `<algorithm>sum` shape matches. A set has to be checked against the
        // programs it protects when the other list gains a member.
        ("b3sum", true),
        ("blake3sum", true),
        // **`mikefarah/yq`'s extensionless manifests**, found by the same scan. Only
        // `checksums` is recognized, because the rule is that the *last* part is the
        // word: `checksums-bsd` and `checksums_hashes_order` end in a name part, and
        // `checksums.bundle` ends in `bundle`.
        //
        // That is a deliberate under-match, and the arithmetic is the point. All five
        // are digests in fact, and matching all five left `tool install --global`
        // refusing a perfectly good release with "multiple checksum assets were
        // found" -- the global path requires exactly one and the release offers five.
        // One recognized candidate resolves it. The installer's classifier draws the
        // same line, so the two halves agree on all five.
        ("checksums", false),
        ("checksums-bsd", true),
        ("checksums_hashes_order", true),
        ("checksums.bundle", true),
        ("checksums-bsd.bundle", true),
        // And the `*sum` singular, which only the singular arm of two rules can
        // catch. `astral-sh/uv` publishes exactly this name. Both this rule and the
        // installer's dropped their singular spelling to a dead entry once, and a
        // mutation removing it passed every test in both crates.
        ("sha256.sum", false),
        ("foo_linux_amd64.sum", false),
        // The families the extension list was missing, all of which a project
        // publishes beside the archive. `csv` is `GoReleaser`'s `licenses` output
        // and `cert` is a cosign certificate. The `*sum` spellings are *not*
        // extension entries at all -- they are a single extension, and
        // `is_digest_sidecar_name` owns that family, which is why `sums`/`sum` are
        // absent from `SIDECAR_EXTENSIONS` and asserted absent by a test.
        ("tool_1.2.3_linux_amd64.licenses.csv", false),
        ("tool_linux_amd64.sha256sum", false),
        ("tool_linux_amd64.sha512sum", false),
        ("tool-linux-amd64.tar.gz.cert", false),
        ("tool.sigstore", false),
        // The GnuPG spellings, which are the same kind of file as the `sig` and
        // `asc` above and were missing for the same reason: the family was there
        // except for the two extensions a Linux packager actually emits.
        ("tool-linux-amd64.tar.gz.gpg", false),
        ("tool-linux-amd64.tar.gz.gpgasc", false),
        // The rest of the list, which had no row at all: removing any one of these
        // failed nothing before this test.
        ("tool-linux-amd64.pem", false),
        ("tool-linux-amd64.cer", false),
        ("tool-linux-amd64.crt", false),
        ("tool-linux-amd64.pub", false),
        ("tool-linux-amd64.p7s", false),
        ("tool-linux-amd64.attestation", false),
        ("tool-linux-amd64.md5", false),
        ("tool-linux-amd64.blake2", false),
        ("tool-linux-amd64.blake3", false),
        ("tool-linux-amd64.digest", false),
        ("tool-linux-amd64.sha", false),
        ("tool-linux-amd64.text", false),
        // `sums` is *not* in `SIDECAR_EXTENSIONS` -- `is_digest_sidecar_name` owns
        // the whole family. It was in the table, and no row failed without it,
        // which is how a dead entry survives four rewrites of this file.
        ("tool-linux-amd64.sums", false),
        // A path is stripped before the extension is read. Both separators, because
        // a Windows release publishes `downloads\tool.exe`; stripping only `/` left
        // the whole path in play, so the last extension read was `downloads\tool`.
        ("downloads/tool-linux-amd64.tar.gz", true),
        ("downloads/SHA256SUMS", false),
        ("downloads\\tool.exe", true),
        ("downloads\\SHA256SUMS", false),
        ("downloads\\foo_linux_amd64.tar.gz.sha256", false),
    ] {
        assert_eq!(
            super::planning::is_release_artifact(name),
            is_artifact,
            "{name}"
        );
    }
}

/// Every member of `DIGEST_ALGORITHMS` is load-bearing, and the overlap with
/// `SIDECAR_EXTENSIONS` is deliberate.
///
/// Two classifiers reading one name two ways is the defect this file has now
/// produced twice, so the tables are checked against each other rather than left
/// to review: an algorithm listed here but absent there would classify
/// `foo.sha256` as a sidecar in one rule and the artifact in the other.
#[test]
fn the_digest_algorithm_list_and_the_sidecar_extension_list_agree() {
    use super::planning::{DIGEST_ALGORITHMS, SIDECAR_EXTENSIONS};

    // **The contents, as literals, not as "everything in the list is in the
    // other list".** An earlier version of this test iterated `DIGEST_ALGORITHMS`
    // and asserted each member was also a sidecar extension -- which is a
    // tautology over the *wrong* direction: removing a member removed the only
    // row that mentioned it, and dropping `blake3` passed. A test that reads its
    // expectations out of the thing under test cannot fail about the thing under
    // test, so the expected set is written out here.
    assert_eq!(
        DIGEST_ALGORITHMS,
        &[
            "sha1", "sha224", "sha256", "sha384", "sha512", "sha3", "sha3-256", "sha3-512", "md5",
            "blake2", "blake3", "b3", "sha",
        ],
        "the digest-algorithm set changed; add a row for the new name above so the \
         addition is a decision, and check whether the coreutils spelling it \
         generalizes is a digest *file* convention in releases"
    );

    // Now the cross-table property, which is genuinely about two lists: no name is
    // a sidecar by one rule and the artifact by the other.
    for algorithm in DIGEST_ALGORITHMS {
        assert!(
            SIDECAR_EXTENSIONS.contains(algorithm),
            "{algorithm} is a digest algorithm here but not a sidecar extension, so \
             `foo.{algorithm}` is a sidecar by one rule and the artifact by the other"
        );
        // And each one is load-bearing *in the rule*, with a name of its own.
        // The `-` variant is the point: an algorithm containing a dash is only
        // reachable because the suffix split excludes `-`. Before that, `sha3-256`
        // and `sha3-512` were list members no input could reach -- dead entries by
        // the same definition this file applies to `sums` and `sum`, which are no
        // longer in `SIDECAR_EXTENSIONS` at all, and to `intoto`, `spdx`, `cdx`, and
        // `cyclonedx`, which are absent for the *different* reason recorded at the
        // table. **`sbom` is in the table**: it was removed on the circular
        // "no test failed" evidence and the removal installed syft's SBOM as the
        // program.
        for spelling in [
            format!("tool_linux_amd64.{algorithm}sums"),
            format!("tool_linux_amd64.{algorithm}sum"),
            format!("tool_linux_amd64_{algorithm}sums"),
        ] {
            assert!(
                !super::planning::is_release_artifact(&spelling),
                "{spelling} is a manifest, but the algorithm is not recognized"
            );
        }
    }

    // The reverse direction is not required -- a sidecar extension need not be a
    // digest algorithm -- but the two that look like they should be are named
    // explicitly so that adding one back is a decision. They were in the table
    // once and no row failed without them, which is how a dead entry survives.
    for extension in ["sums", "sum"] {
        assert!(
            !SIDECAR_EXTENSIONS.contains(&extension),
            "{extension} is handled by `is_digest_sidecar_name`; a second copy in the \
             extension table is the dead entry this rule replaced"
        );
    }
}

/// **Every member of the packaging table is exercised, and each row states where its
/// evidence comes from** — which is not the same thing for all of them, and a table
/// that hides the difference is how a guess gets promoted to a decision.
///
/// The table splits three ways, and only one of the three is backed by this
/// project's own corpus:
///
/// - **mise's list, carried verbatim.** `apk appx appxbundle deb dmg mpkg msi msix
///   msixbundle pkg rpm` is `is_non_executable_asset` from `jdx/mise`
///   `src/backend/asset_matcher.rs:705`, member for member. The authority is the
///   reference, not a corpus observation — which is a legitimate reason to keep a
///   member and *not* a reason to describe it as "witnessed".
/// - **Worse than the copy, absent from mise, witnessed here.** `flatpak` and
///   `nupkg`: `goreleaser_2.18.2_linux_amd64.flatpak` and
///   `Logseq-win-x64-0.10.15-full.nupkg` were both selected at the parent commit and
///   neither is an executable.
/// - **No publisher in the corpus at all.** `z`, `lz`, `lzma`, `sz` — and `rar`,
///   which is a real and common release format that simply did not appear in 286
///   releases. **Kept anyway, because this table's burden of proof runs toward
///   keeping**: a missing member is a silent wrong install, while an extra member
///   costs a string and a refusal that lists every candidate.
///
/// Members of this table had no row, and removing one left the suite green, which is
/// the measurement — not proof it is unneeded. `sha3_256` in the sidecar table is
/// the same case, and the two are now decided the same way. No count is written
/// here: a number in a sentence about which members are covered goes stale the
/// moment a member is added, which is the same mistake as the table-size sentence
/// two commits ago.
#[test]
fn every_packaging_member_has_a_row_and_a_stated_source_of_evidence() {
    // mise's list, verbatim. The authority is the reference, and a test that says so
    // is what stops a later reader describing them as corpus observations.
    for extension in [
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
    ] {
        assert!(
            is_package_not_program(&format!("tool_1.2.3_linux_amd64.{extension}")),
            "{extension} is in mise's `is_non_executable_asset` and must be kept out of \
             automatic selection"
        );
    }
    // Watched here, absent from mise.
    for name in [
        "goreleaser_2.18.2_linux_amd64.flatpak",
        "Logseq-win-x64-0.10.15-full.nupkg",
    ] {
        assert!(
            !is_release_artifact(name),
            "{name} is a witnessed wrong install"
        );
    }
    // No publisher in the corpus. Kept, and the reason is recorded above rather than
    // left to look like an oversight.
    for extension in ["zst", "bz2", "7z", "rar", "z", "lz", "lzma", "br", "sz"] {
        assert!(
            !is_release_artifact(&format!("tool_1.2.3_linux_amd64.{extension}")),
            "{extension} has no decoder here, so selecting it as the program would \
             install a compressed blob as an executable"
        );
    }
    // Openable, and still refused. A wheel and a gem really are a zip and a tar, so
    // "cannot be opened" is a false description of the *format* -- but the layout
    // arms key on literal suffixes and nothing sniffs content, so a `.whl` matches
    // none of them and falls through to `RawBinary`. The two claims are different
    // and both get tested: the format is openable, and the artifact is not
    // installable. An earlier version of this comment said they were "not refused as
    // unopenable", which described the bug.
    for extension in ["whl", "gem", "jar"] {
        assert!(
            !is_release_artifact(&format!("tool-1.2.3-py3-none-manylinux.{extension}")),
            "{extension} is not a program, so it must not be auto-selected"
        );
    }
    // **`ar`, because a `.deb` *is* an `ar` archive.** It was in the installer's
    // table and missing here, which meant a `.ar` asset was *selected* and then
    // refused with the worse post-selection diagnostic -- the precise argument this
    // table exists for, applied to the one member left behind. No publisher in the
    // corpus ships a bare `.ar`, so this row is about the two tables agreeing rather
    // than about an observed wrong install.
    assert!(
        !is_release_artifact("tool_1.2.3_linux_amd64.ar"),
        "a `.ar` cannot become a runnable tool, so it must not be auto-selected"
    );
    // **And the ones that must keep resolving**, which is the half a test built only
    // from refusals would miss. `appimage` is deliberately *absent* from this half:
    // it was moved here and then moved back, and the table's own comment records
    // why -- the "it works, the corpus shows it" argument did not survive checking,
    // and the real reason (FUSE at run time) points the other way.
    for name in [
        "gh_2.101.0_linux_amd64.tar.gz",
        "gh_2.101.0_linux_amd64.tar.xz",
        "gh_2.101.0_linux_amd64.zip",
        "gh_2.101.0_linux_amd64.tar",
    ] {
        assert!(
            is_release_artifact(name),
            "{name} is the program and must still be selectable"
        );
    }
    // Substring coincidences: a program whose *name* contains a listed token is not
    // a package, because the test is on whole dot-segments. This is the difference
    // between mise's shape and a substring search, and a substring search would
    // refuse all four of these.
    for name in [
        "myappimager-linux-amd64",
        "debian-linux-amd64",
        "apkbuilder-linux-amd64",
        "pkgdownloader-linux-amd64",
        "sbomctl-linux-amd64",
        "sha256sum-linux-amd64.tar.gz",
    ] {
        assert!(
            is_release_artifact(name),
            "{name} is the program, not a package"
        );
    }
}
