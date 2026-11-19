//! Configuration parsing tests, including bounded malformed-document
//! fuzzing and cross-format normalization equivalence.

use std::{error::Error as _, panic::AssertUnwindSafe, path::Path};

use super::{
    ConfigProfile, FORMAT_VERSION, Format, parse_environment_document, parse_project,
    parse_project_with_format, parse_project_with_profile,
};

#[test]
fn parser_source_is_retained_on_a_diagnostic() {
    let error = parse_project(Path::new("neoenv.toml"), "[format_version").unwrap_err();
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<toml::de::Error>())
            .is_some()
    );
}

#[test]
fn exposes_the_initial_format_version() {
    assert_eq!(FORMAT_VERSION, 1);
}

#[test]
fn parses_typed_cargo_build_declarations_from_yaml_and_toml() {
    let yaml = r"
format_version: 1
tools:
  - id: ripgrep
    version: 14.1.1
    provider: cargo
    binaries: [rg]
    cargo:
      crate_name: ripgrep
      version: 14.1.1
      registry: https://index.crates.io/
      checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      toolchain: 1.85.0-x86_64-unknown-linux-gnu
      scripts: deny
      build: isolated
      network: deny
";
    let toml = r#"
format_version = 1
[[tools]]
id = "ripgrep"
version = "14.1.1"
provider = "cargo"
binaries = ["rg"]
[tools.cargo]
crate_name = "ripgrep"
version = "14.1.1"
registry = "https://index.crates.io/"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
toolchain = "1.85.0-x86_64-unknown-linux-gnu"
scripts = "deny"
build = "isolated"
network = "deny"
"#;
    for (file, source) in [("neoenv.yaml", yaml), ("neoenv.toml", toml)] {
        let project = parse_project(Path::new(file), source).unwrap();
        let cargo = project.tools[0].cargo.as_ref().unwrap();
        assert_eq!(cargo.crate_name, "ripgrep");
        assert_eq!(cargo.version, "14.1.1");
        assert_eq!(cargo.toolchain, "1.85.0-x86_64-unknown-linux-gnu");
    }
}

#[test]
fn cargo_declaration_rejects_non_exact_versions_and_open_policy() {
    let base = r"
format_version: 1
tools:
  - id: ripgrep
    version: 14.1.1
    provider: cargo
    binaries: [rg]
    cargo:
      crate_name: ripgrep
      version: VERSION
      registry: https://index.crates.io/
      checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      toolchain: 1.85.0
      scripts: deny
      build: isolated
      network: deny
";
    assert!(parse_project(Path::new("neoenv.yaml"), &base.replace("VERSION", "^14.1")).is_err());
    assert!(
        parse_project(
            Path::new("neoenv.yaml"),
            &base.replace("scripts: deny", "scripts: allow")
        )
        .is_err()
    );
    assert!(
        parse_project(
            Path::new("neoenv.yaml"),
            &base.replace("https://index.crates.io/", "http://index.crates.io/")
        )
        .is_err()
    );
    assert!(
        parse_project(
            Path::new("neoenv.yaml"),
            &base.replace(
                "toolchain: 1.85.0",
                "toolchain: 1.85.0-x86_64-unknown-linux-gnu-extra-extra"
            )
        )
        .is_err()
    );
    assert!(
        parse_project(
            Path::new("neoenv.yaml"),
            &base.replace("binaries: [rg]\n", "")
        )
        .is_err()
    );
}

#[test]
fn parser_never_panics_on_bounded_malformed_documents() {
    // Deterministic mutation corpus. This keeps the safety check available on
    // every platform without requiring a networked fuzzing toolchain.
    let seeds = [
        "format_version: 1\ntasks:\n  build:\n    run: 'true'\n",
        "[tasks.build]\nrun = 'true'\n",
        "MESSAGE=value\n",
        "{ broken: [toml",
    ];
    for seed in seeds {
        for mutation in 0..128_u32 {
            let mut input = seed.as_bytes().to_vec();
            let mut state = mutation.wrapping_mul(0x9e37_79b9).wrapping_add(1);
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                if state.trailing_zeros() >= 3 {
                    *byte ^= state.to_le_bytes()[0];
                }
            }
            let input = String::from_utf8_lossy(&input);
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = parse_project(Path::new("neoenv.yaml"), &input);
                let _ = parse_project(Path::new("neoenv.toml"), &input);
                let _ = parse_project(Path::new(".neoenv"), &input);
            }));
            assert!(result.is_ok(), "parser panicked for mutation {mutation}");
        }
    }
}

#[test]
fn normalizes_each_fixture_format_to_the_same_environment() {
    let expected = vec![("APP_NAME", "neoenv"), ("LOG_LEVEL", "debug")];
    for (path, input) in [
        (
            "environment.yaml",
            include_str!("../../../fixtures/config/v1/environment.yaml"),
        ),
        (
            "environment.toml",
            include_str!("../../../fixtures/config/v1/environment.toml"),
        ),
        (
            ".neoenv",
            include_str!("../../../fixtures/config/v1/.neoenv"),
        ),
    ] {
        let project = parse_environment_document(Path::new(path), input).unwrap();
        let actual: Vec<_> = project
            .environment
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn normalizes_unicode_blank_values_and_continuations() {
    let yaml =
        "env:\n  MESSAGE: hello world\n  EMPTY: ''\n  UNICODE: snowman ☃\n  CONTINUED: onetwo\n";
    let toml =
        "[env]\nMESSAGE = 'hello world'\nEMPTY = ''\nUNICODE = 'snowman ☃'\nCONTINUED = 'onetwo'\n";
    let compact = "MESSAGE=hello world\nEMPTY=\nUNICODE=snowman ☃\nCONTINUED=one\\\ntwo\n";
    let expected = vec![
        ("MESSAGE", "hello world"),
        ("EMPTY", ""),
        ("UNICODE", "snowman ☃"),
        ("CONTINUED", "onetwo"),
    ];

    for (path, input) in [
        ("neoenv.yaml", yaml),
        ("neoenv.toml", toml),
        (".neoenv", compact),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        let environment: Vec<_> = project
            .environment
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();
        assert_eq!(environment, expected);
    }
}

#[test]
fn rejects_duplicate_keys_and_invalid_compact_escapes_with_locations() {
    let duplicate = parse_project(Path::new(".neoenv"), "PORT=3000\nPORT=3001\n").unwrap_err();
    let escape = parse_project(Path::new(".neoenv"), "MESSAGE=\"\\q\"\n").unwrap_err();

    assert_eq!(duplicate.code, "NEO106");
    assert_eq!(duplicate.source.unwrap().line, 2);
    assert_eq!(escape.code, "NEO109");
    assert_eq!(escape.source.unwrap().line, 1);
}

#[test]
fn rejects_unknown_structured_fields_with_a_source_location() {
    let error = parse_project(Path::new("neoenv.yaml"), "unexpected: true\n").unwrap_err();

    assert_eq!(error.code, "NEO102");
    assert_eq!(error.source.unwrap().path, "neoenv.yaml");
}

#[test]
fn accepts_an_explicit_format_without_a_matching_path_extension() {
    let project =
        parse_project_with_format(Path::new("stdin"), "NAME=neoenv\n", Format::Neoenv).unwrap();

    assert_eq!(project.environment[0].value, "neoenv");
}

#[test]
fn parses_compact_quoted_values_and_continuations() {
    let project = parse_project(
        Path::new(".neoenv"),
        include_str!("../../../fixtures/config/v1/compact-syntax.neoenv"),
    )
    .unwrap();

    let environment: Vec<_> = project
        .environment
        .iter()
        .map(|entry| (entry.key.as_str(), entry.value.as_str()))
        .collect();
    assert_eq!(
        environment,
        vec![
            ("MESSAGE", "hello\nworld"),
            ("CONTINUED", "onetwo"),
            ("LITERAL", "not an escape: \\n"),
        ]
    );
}

#[test]
fn reports_a_location_for_an_unterminated_continuation() {
    let error = parse_project(Path::new(".neoenv"), "NAME=neoenv\\\n").unwrap_err();

    assert_eq!(error.code, "NEO108");
    assert_eq!(error.source.unwrap().line, 1);
}

#[test]
fn normalizes_ordered_url_tools_from_yaml_and_toml_only() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let yaml = format!(
        "tools:\n  - id: first\n    version: 1.0.0\n    url: https://example.test/first\n    sha256: {digest}\n    binaries: [first]\n"
    );
    let toml = format!(
        "[[tools]]\nid = 'first'\nversion = '1.0.0'\nurl = 'https://example.test/first'\nsha256 = '{digest}'\nbinaries = ['first']\n"
    );
    for (path, input) in [("neoenv.yaml", yaml), ("neoenv.toml", toml)] {
        let project = parse_project(Path::new(path), &input).unwrap();
        assert_eq!(project.tools.len(), 1);
        assert_eq!(project.tools[0].id, "first");
        assert_eq!(project.tools[0].declaration_source.path, path);
    }
    assert!(parse_project(Path::new(".neoenv"), "tools: []\n").is_err());
}

#[test]
fn parses_provider_extension_names_without_selecting_a_resolver() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        include_str!("../../../fixtures/config/v1/provider-extension.yaml"),
    )
    .unwrap();

    assert_eq!(project.tools[0].provider.name(), "github-release");
}

#[test]
fn parses_typed_github_release_declaration() {
    let project = parse_project(
            Path::new("neoenv.yaml"),
            "format_version: 1\ntools:\n  - id: demo\n    version: v1.2.3\n    provider: github-release\n    github_release:\n      repository: owner/demo\n      asset: demo-{os}-{arch}.tar.gz\n      checksum_asset: checksums.txt\n    binaries: [demo]\n",
        )
        .unwrap();
    let github = project.tools[0].github_release.as_ref().unwrap();
    assert_eq!(github.repository, "owner/demo");
    assert_eq!(github.asset.as_deref(), Some("demo-{os}-{arch}.tar.gz"));
}

#[test]
fn expands_tool_map_aliases_and_numeric_versions() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "tools:\n  aliases:\n    dust: gh:bootandy/dust\n  dust: 1.27\n",
    )
    .unwrap();
    let tool = &project.tools[0];
    assert_eq!(tool.id, "dust");
    assert_eq!(tool.version, "1.27");
    assert_eq!(tool.provider.name(), "github-release");
    assert_eq!(
        tool.github_release.as_ref().unwrap().repository,
        "bootandy/dust"
    );
    assert_eq!(tool.binaries, vec!["dust".to_owned()]);
}

#[test]
fn tool_map_uses_the_short_name_as_the_binary_not_the_repository() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "tools:\n  aliases:\n    rg: gh:BurntSushi/ripgrep\n  rg: 14.1.0\n",
    )
    .unwrap();
    let tool = &project.tools[0];
    assert_eq!(tool.id, "rg");
    assert_eq!(
        tool.github_release.as_ref().unwrap().repository,
        "BurntSushi/ripgrep"
    );
    assert_eq!(tool.binaries, vec!["rg".to_owned()]);
}

#[test]
fn tool_map_allows_an_explicit_binary_name() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "tools:\n  aliases:\n    ripgrep: gh:BurntSushi/ripgrep\n  ripgrep:\n    version: 14.1.0\n    binaries: [rg]\n",
    )
    .unwrap();
    let tool = &project.tools[0];
    assert_eq!(tool.id, "ripgrep");
    assert_eq!(tool.binaries, vec!["rg".to_owned()]);
}

#[test]
fn expands_tool_map_aliases_from_toml_too() {
    let project = parse_project(
        Path::new("neoenv.toml"),
        "[tools]\ndust = \"1.27\"\n[tools.aliases]\ndust = \"gh:bootandy/dust\"\n",
    )
    .unwrap();
    let tool = &project.tools[0];
    assert_eq!(tool.id, "dust");
    assert_eq!(tool.version, "1.27");
    assert_eq!(
        tool.github_release.as_ref().unwrap().repository,
        "bootandy/dust"
    );
}

#[test]
fn tool_map_refuses_aliases_and_declarations_that_do_not_pair() {
    for input in [
        "tools:\n  aliases:\n    dust: gh:bootandy/dust\n",
        "tools:\n  dust: 1.27\n",
        "tools:\n  aliases:\n    dust: npm:dust\n  dust: 1.27\n",
        "tools:\n  aliases:\n    dust: gh:bootandy/dust\n  dust:\n    unknown: 1.27\n",
    ] {
        let error = parse_project(Path::new("neoenv.yaml"), input).expect_err("expected a refusal");
        assert_eq!(error.code, "NEO132", "{input}: {error}");
    }
}

#[test]
fn parses_typed_aqua_declaration() {
    let project = parse_project(
            Path::new("neoenv.yaml"),
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: aqua\n    aqua:\n      endpoint: http://127.0.0.1:8080\n      registry_revision: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      package: owner/demo\n      manifest_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n    binaries: [demo]\n",
        )
        .unwrap();
    let aqua = project.tools[0].aqua.as_ref().unwrap();
    assert_eq!(aqua.package, "owner/demo");
    assert_eq!(aqua.registry_revision, "a".repeat(40));
}

#[test]
fn npm_manager_selection_is_typed_in_yaml_and_toml() {
    let yaml = r#"format_version: 1
tools:
  - id: demo
    version: 1.2.3
    provider: npm
    npm:
      endpoint: https://registry.npmjs.org
      package: demo
      manager: { name: bun, version: "1.4.4-rc.1" }
"#;
    let toml = r#"format_version = 1

[[tools]]
id = "demo"
version = "1.2.3"
provider = "npm"
[tools.npm]
endpoint = "https://registry.npmjs.org"
package = "demo"
[tools.npm.manager]
name = "pnpm"
version = "10.0.0+build.7"
"#;
    for (path, input, expected_name, expected_version) in [
        ("neoenv.yaml", yaml, "bun", "1.4.4-rc.1"),
        ("neoenv.toml", toml, "pnpm", "10.0.0+build.7"),
    ] {
        let parsed = parse_project(Path::new(path), input).unwrap();
        let manager = parsed.tools[0]
            .npm
            .as_ref()
            .unwrap()
            .manager
            .as_ref()
            .unwrap();
        assert_eq!(
            manager.name,
            if expected_name == "bun" {
                neoenv_core::tools::NpmManagerName::Bun
            } else {
                neoenv_core::tools::NpmManagerName::Pnpm
            }
        );
        assert_eq!(manager.version, expected_version);
    }
}

#[test]
fn npm_manager_archive_pin_requires_lowercase_sha256() {
    let input = |pin: &str| {
        format!(
            "format_version: 1\ntools:\n  - id: demo\n    version: '1.2.3'\n    provider: npm\n    npm: {{ endpoint: https://registry.npmjs.org, package: demo, manager: {{ name: bun, version: '1.4.4', archive_sha256: '{pin}' }} }}\n"
        )
    };
    let digest = "ab".repeat(32);
    let parsed = parse_project(Path::new("neoenv.yaml"), &input(&digest)).unwrap();
    assert_eq!(
        parsed.tools[0]
            .npm
            .as_ref()
            .unwrap()
            .manager
            .as_ref()
            .unwrap()
            .archive_sha256
            .as_deref(),
        Some(digest.as_str())
    );
    for bad in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
        assert!(parse_project(Path::new("neoenv.yaml"), &input(&bad)).is_err());
    }
}

#[test]
fn npm_manager_selector_rejects_unknown_names_and_non_string_versions() {
    for (path, input) in [
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: yarn, version: '1.0.0' } }\n",
        ),
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: bun, version: 1.4 } }\n",
        ),
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: bun, version: '1.2' } }\n",
        ),
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: bun, version: '^1.2.3' } }\n",
        ),
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: bun, version: '../bun' } }\n",
        ),
        (
            "neoenv.yaml",
            "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo, manager: { name: bun, version: '' } }\n",
        ),
        (
            "neoenv.toml",
            "format_version = 1\n[[tools]]\nid = 'demo'\nversion = '1.2.3'\nprovider = 'npm'\n[tools.npm]\nendpoint = 'https://registry.npmjs.org'\npackage = 'demo'\n[tools.npm.manager]\nname = 'yarn'\nversion = '1.0.0'\n",
        ),
        (
            "neoenv.toml",
            "format_version = 1\n[[tools]]\nid = 'demo'\nversion = '1.2.3'\nprovider = 'npm'\n[tools.npm]\nendpoint = 'https://registry.npmjs.org'\npackage = 'demo'\n[tools.npm.manager]\nname = 'bun'\nversion = 1.4\n",
        ),
        (
            "neoenv.toml",
            "format_version = 1\n[[tools]]\nid = 'demo'\nversion = '1.2.3'\nprovider = 'npm'\n[tools.npm]\nendpoint = 'https://registry.npmjs.org'\npackage = 'demo'\n[tools.npm.manager]\nname = 'bun'\nversion = '>=1.2.3'\n",
        ),
        (
            "neoenv.toml",
            "format_version = 1\n[[tools]]\nid = 'demo'\nversion = '1.2.3'\nprovider = 'npm'\n[tools.npm]\nendpoint = 'https://registry.npmjs.org'\npackage = 'demo'\n[tools.npm.manager]\nname = 'bun'\nversion = '../bun'\n",
        ),
        (
            "neoenv.toml",
            "format_version = 1\n[[tools]]\nid = 'demo'\nversion = '1.2.3'\nprovider = 'npm'\n[tools.npm]\nendpoint = 'https://registry.npmjs.org'\npackage = 'demo'\n[tools.npm.manager]\nname = 'bun'\nversion = ''\n",
        ),
    ] {
        assert!(
            parse_project(Path::new(path), input).is_err(),
            "{path}: {input}"
        );
    }
}

#[test]
fn npm_manager_omission_preserves_legacy_declaration() {
    let parsed = parse_project(
        Path::new("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: demo\n    version: 1.2.3\n    provider: npm\n    npm: { endpoint: https://registry.npmjs.org, package: demo }\n",
    )
    .unwrap();
    assert_eq!(parsed.tools[0].npm.as_ref().unwrap().manager, None);
}

#[test]
fn normalizes_scalar_and_map_tasks_from_yaml_and_toml_only() {
    for (path, input) in [
        (
            "tasks.yaml",
            include_str!("../../../fixtures/config/v1/tasks.yaml"),
        ),
        (
            "tasks.toml",
            include_str!("../../../fixtures/config/v1/tasks.toml"),
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        assert_eq!(project.context.as_deref(), Some("staging"));
        assert_eq!(
            project.tasks["lint"]
                .action
                .as_ref()
                .unwrap()
                .run
                .as_deref(),
            Some("cargo clippy")
        );
        assert_eq!(
            project.tasks["lint"]
                .action
                .as_ref()
                .unwrap()
                .uses
                .as_deref(),
            Some("exec")
        );
        assert!(
            project.tasks["lint"]
                .action
                .as_ref()
                .unwrap()
                .args
                .is_empty()
        );
        assert_eq!(project.tasks["test"].needs, ["build"]);
        assert_eq!(project.tasks["test"].parameters[0].name, "suite");
        assert_eq!(
            project.tasks["test"]
                .action
                .as_ref()
                .unwrap()
                .uses
                .as_deref(),
            Some("exec")
        );
        assert_eq!(
            project.tasks["build"]
                .action
                .as_ref()
                .unwrap()
                .uses
                .as_deref(),
            Some("shell")
        );
    }
    assert!(parse_project(Path::new(".neoenv"), "tasks: build\n").is_err());
}

#[test]
fn scalar_tasks_default_to_exec_without_splitting_the_run_field() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "tasks:\n  greet: 'printf hello world'\n",
    )
    .unwrap();
    let action = project.tasks["greet"].action.as_ref().unwrap();
    assert_eq!(action.uses.as_deref(), Some("exec"));
    assert_eq!(action.run.as_deref(), Some("printf hello world"));
    assert!(action.args.is_empty());
}

#[test]
fn parses_explicit_scoped_task_directories() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "task_dirs:\n  local: runners\n  global: [/opt/neoenv/runners]\n",
    )
    .unwrap();

    assert_eq!(project.task_dirs.local, ["runners"]);
    assert_eq!(project.task_dirs.global, ["/opt/neoenv/runners"]);
}

#[test]
fn normalizes_named_structured_task_packages() {
    for (path, input) in [
        (
            Path::new("neoenv.yaml"),
            "task_packages:\n  lint: lint-package\n  release:\n    from: tasks/release.toml\n    task: publish\n",
        ),
        (
            Path::new("neoenv.toml"),
            "[task_packages]\nlint = 'lint-package'\n[task_packages.release]\nfrom = 'tasks/release.toml'\ntask = 'publish'\n",
        ),
    ] {
        let project = parse_project(path, input).unwrap();
        assert_eq!(project.task_packages["lint"].from, "lint-package");
        assert_eq!(project.task_packages["lint"].task, "default");
        assert_eq!(project.task_packages["release"].from, "tasks/release.toml");
        assert_eq!(project.task_packages["release"].task, "publish");
    }
}

#[test]
fn normalizes_task_predicates_from_yaml_and_toml() {
    for (path, input) in [
        (
            "task-predicates.yaml",
            include_str!("../../../fixtures/config/v1/task-predicates.yaml"),
        ),
        (
            "task-predicates.toml",
            include_str!("../../../fixtures/config/v1/task-predicates.toml"),
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        assert_eq!(
            project.tasks["base"].if_condition.as_deref(),
            Some("env.ENABLED")
        );
        assert_eq!(project.tasks["base"].force.as_deref(), Some("false"));
        assert_eq!(
            project.tasks["forced"].if_condition.as_deref(),
            Some("false")
        );
        assert_eq!(project.tasks["forced"].force.as_deref(), Some("true"));
    }
}

#[test]
fn normalizes_task_identity_and_output_visibility() {
    let project = parse_project(
            Path::new("tasks.yaml"),
            "tasks:\n  build:\n    id: build-v2\n    name: Build application\n    slug: build-app\n    uses: portable\n    run: 'true'\n    outputs:\n      ARTIFACT:\n        description: Archive path\n        visibility: private\n      URL: Published URL\n",
        )
        .unwrap();
    let task = &project.tasks["build"];
    assert_eq!(task.id.as_deref(), Some("build-v2"));
    assert_eq!(task.name.as_deref(), Some("Build application"));
    assert_eq!(task.slug.as_deref(), Some("build-app"));
    assert_eq!(
        task.outputs["ARTIFACT"].visibility,
        neoenv_core::tasks::TaskOutputVisibility::Private
    );
    assert_eq!(
        task.outputs["URL"].description.as_deref(),
        Some("Published URL")
    );
}

#[test]
fn accepts_legacy_task_description_and_runner_aliases() {
    for (path, input) in [
        (
            "tasks.yaml",
            "tasks:\n  build:\n    desc: Build the project.\n    help: Run this before publishing.\n    use: portable\n    run: 'true'\n",
        ),
        (
            "tasks.toml",
            "[tasks.build]\ndesc = 'Build the project.'\nhelp = 'Run this before publishing.'\nuse = 'portable'\nrun = 'true'\n",
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        let task = &project.tasks["build"];
        assert_eq!(task.description.as_deref(), Some("Build the project."));
        assert_eq!(task.help.as_deref(), Some("Run this before publishing."));
        assert_eq!(
            task.action
                .as_ref()
                .and_then(|action| action.uses.as_deref()),
            Some("portable")
        );
    }
}

#[test]
fn parses_structured_module_import_task_views() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "imports:\n  - from: common\n    ns: tools\n    tasks: [build, test]\n",
    )
    .unwrap();

    assert_eq!(project.imports[0].from, "common");
    assert_eq!(project.imports[0].namespace.as_deref(), Some("tools"));
    assert_eq!(project.imports[0].tasks, ["build", "test"]);
}

#[test]
fn parses_explicit_local_workspace_members_and_aliases() {
    let project = parse_project(
        Path::new("neoenv.yaml"),
        "workspace:\n  members: [apps/frontend]\n  aliases: { web: apps/frontend }\n",
    )
    .unwrap();

    assert_eq!(project.workspace.members, ["apps/frontend"]);
    assert_eq!(project.workspace.aliases["web"], "apps/frontend");
}

#[test]
fn normalizes_render_task_source_destination_and_inputs() {
    let project = parse_project(
            Path::new("tasks.yaml"),
            "tasks:\n  render:\n    uses: render\n    source: templates/app.conf.tmpl\n    destination: generated/app.conf\n    with:\n      name: neoenv\n",
        )
        .unwrap();
    let action = project.tasks["render"].action.as_ref().unwrap();
    assert_eq!(action.source.as_deref(), Some("templates/app.conf.tmpl"));
    assert_eq!(action.destination.as_deref(), Some("generated/app.conf"));
    assert_eq!(action.with["name"], "neoenv");
}

#[test]
fn normalizes_tmpl_file_mappings_and_scalar_with_values() {
    for (path, input) in [
        (
            "tmpl.yaml",
            "tasks:\n  render:\n    uses: tmpl\n    with:\n      files:\n        - app.yml.gotmpl:out/app.yml\n      values: values.yaml\n      disable-gotmpl: true\n",
        ),
        (
            "tmpl.toml",
            "[tasks.render]\nuses = 'tmpl'\n[tasks.render.with]\nfiles = ['app.yml.gotmpl:out/app.yml']\nvalues = 'values.yaml'\n'disable-gotmpl' = true\n",
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        let action = project.tasks["render"].action.as_ref().unwrap();
        assert_eq!(action.files, ["app.yml.gotmpl:out/app.yml"]);
        assert_eq!(action.with["values"], "values.yaml");
        assert_eq!(action.with["disable-gotmpl"], "true");
        assert!(!action.with.contains_key("files"));
    }

    let invalid = parse_project(
        Path::new("bad.yaml"),
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      other: [a, b]\n",
    );
    assert!(invalid.is_err(), "only with.files may be a list");
}

#[test]
fn normalizes_task_input_cli_bindings_from_yaml_and_toml() {
    for (path, input) in [
        (
            "inputs.yaml",
            "tasks:\n  build:\n    uses: portable\n    run: 'true'\n    inputs:\n      target: { type: string, position: 0, required: true }\n      release: { type: boolean, long: release, short: r, default: false }\n      tag: { type: string, long: tag, repeatable: true }\n",
        ),
        (
            "inputs.toml",
            "[tasks.build]\nuses = 'portable'\nrun = 'true'\n[tasks.build.inputs.target]\ntype = 'string'\nposition = 0\nrequired = true\n[tasks.build.inputs.release]\ntype = 'boolean'\nlong = 'release'\nshort = 'r'\ndefault = false\n[tasks.build.inputs.tag]\ntype = 'string'\nlong = 'tag'\nrepeatable = true\n",
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        let parameters = &project.tasks["build"].parameters;
        assert_eq!(parameters[0].position, Some(0));
        assert_eq!(parameters[1].long.as_deref(), Some("release"));
        assert_eq!(parameters[1].short, Some('r'));
        assert!(parameters[2].repeatable);
    }
}

#[test]
fn normalizes_scalar_and_list_task_hooks() {
    for (path, input) in [
        (
            "hooks.yaml",
            "tasks:\n  build:\n    uses: portable\n    run: 'true'\n    hooks:\n      before: prepare\n      after: [cleanup, report]\n",
        ),
        (
            "hooks.toml",
            "[tasks.build]\nuses = 'portable'\nrun = 'true'\n[tasks.build.hooks]\nbefore = 'prepare'\nafter = ['cleanup', 'report']\n",
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        assert_eq!(project.tasks["build"].hooks.before, ["prepare"]);
        assert_eq!(project.tasks["build"].hooks.after, ["cleanup", "report"]);
    }
}

#[test]
fn parses_typed_dotenv_and_ordered_path_operations_from_structured_formats() {
    for (path, input) in [
        (
            "environment-extensions.yaml",
            include_str!("../../../fixtures/config/v1/environment-extensions.yaml"),
        ),
        (
            "environment-extensions.toml",
            include_str!("../../../fixtures/config/v1/environment-extensions.toml"),
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        assert_eq!(project.dotenv[0].path, "environment-extensions.env");
        assert!(project.dotenv[0].required);
        assert_eq!(project.path.len(), 2);
        assert_eq!(project.path[0].kind, super::PathOperationKind::Prepend);
        assert_eq!(project.path[1].kind, super::PathOperationKind::Append);
    }
    assert!(parse_project(Path::new(".neoenv"), "dotenv: local.env\n").is_err());
    assert!(parse_project(Path::new(".neoenv"), "PATH: [{ prepend: bin }]\n").is_err());
}

#[test]
fn parses_task_dotenv_from_yaml_and_toml_and_rejects_substitution() {
    for (path, input) in [
        (
            "tasks.yaml",
            "tasks:\n  base:\n    template: true\n    dotenv: [{ path: base.env, required: false }]\n  build:\n    extends: base\n    uses: shell\n    run: 'true'\n",
        ),
        (
            "tasks.toml",
            "[tasks.base]\ntemplate = true\ndotenv = [{ path = 'base.env', required = false }]\n[tasks.build]\nextends = 'base'\nuses = 'shell'\nrun = 'true'\n",
        ),
    ] {
        let project = parse_project(Path::new(path), input).unwrap();
        let resolved = neoenv_core::tasks::resolve_inheritance(&project.tasks).unwrap();
        let dotenv = &resolved["build"].action.as_ref().unwrap().dotenv;
        assert_eq!(dotenv[0].path, "base.env");
        assert!(!dotenv[0].required);
        assert_eq!(dotenv[0].source.path, path);
    }
    let error = parse_project(
        Path::new("tasks.yaml"),
        "tasks:\n  build:\n    uses: shell\n    run: 'true'\n    dotenv: '$(whoami)'\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "NEO111");
}

#[test]
fn tracks_yaml_declaration_spans_without_matching_nested_keys() {
    let project = parse_project(
            Path::new("neoenv.yaml"),
            "tasks:\n  build:\n    dotenv: task.env\n    env:\n      id: shadow\n      prepend: shadow\n      dotenv: shadow\ndotenv:\n  - path: project.env\npath:\n  - prepend: bin\n  - append: tools/bin\nenv:\n  DOTENV: project\ntools:\n  - id: demo\n    version: 1\n",
        )
        .unwrap();

    assert_eq!(
        project.tasks["build"].action.as_ref().unwrap().dotenv[0]
            .source
            .line,
        3
    );
    assert_eq!(project.dotenv[0].source.line, 9);
    assert_eq!(project.path[0].source.line, 11);
    assert_eq!(project.path[1].source.line, 12);
    assert_eq!(project.environment[0].source.line, 14);
    assert_eq!(project.tools[0].declaration_source.line, 16);
}

#[test]
fn tracks_toml_declaration_spans_for_repeated_task_and_path_keys() {
    let project = parse_project(
            Path::new("neoenv.toml"),
            "[tasks.first]\ndotenv = 'first.env'\n[tasks.second]\ndotenv = 'second.env'\n[tasks.second.env]\nid = 'shadow'\nprepend = 'shadow'\n[[path]]\nprepend = 'bin'\n[[path]]\nappend = 'tools/bin'\n[[tools]]\nid = 'demo'\nversion = '1'\n",
        )
        .unwrap();

    assert_eq!(
        project.tasks["first"].action.as_ref().unwrap().dotenv[0]
            .source
            .line,
        2
    );
    assert_eq!(
        project.tasks["second"].action.as_ref().unwrap().dotenv[0]
            .source
            .line,
        4
    );
    assert_eq!(project.path[0].source.line, 9);
    assert_eq!(project.path[1].source.line, 11);
    assert_eq!(project.tools[0].declaration_source.line, 12);
}

#[test]
fn rejects_command_substitution_in_every_environment_format() {
    for (path, input) in [
        ("neoenv.yaml", "env:\n  VALUE: '$(whoami)'\n"),
        ("neoenv.toml", "[env]\nVALUE = '`whoami`'\n"),
        (".neoenv", "VALUE=$(whoami)\n"),
    ] {
        let error = parse_project(Path::new(path), input).unwrap_err();
        assert_eq!(error.code, "NEO111");
    }
}

#[test]
fn composite_tasks_parse_only_strict_inline_shell_steps() {
    let valid = parse_project(
        Path::new("neoenv.yaml"),
        "tasks:\n  composite:\n    uses: composite\n    steps:\n      - uses: shell\n        run: 'echo first'\n      - uses: shell\n        run: 'echo second'\n",
    )
    .unwrap();
    let task = &valid.tasks["composite"];
    assert_eq!(task.composite_steps.len(), 2);
    assert_eq!(task.composite_steps[0].uses, "shell");
    assert_eq!(task.composite_steps[1].run, "echo second");

    for invalid in [
        "tasks:\n  composite:\n    uses: composite\n    steps: []\n",
        "tasks:\n  composite:\n    uses: composite\n    steps:\n      - task: other\n",
        "tasks:\n  composite:\n    uses: composite\n    steps:\n      - uses: composite\n        run: nested\n",
        "tasks:\n  composite:\n    uses: composite\n    steps:\n      - uses: shell\n        run: ok\n        cwd: nested\n",
        "tasks:\n  composite:\n    uses: composite\n    steps:\n      - uses: shell\n        run: '  '\n",
    ] {
        assert!(
            parse_project(Path::new("neoenv.yaml"), invalid).is_err(),
            "accepted unsupported composite form: {invalid}"
        );
    }
}

/// The Go task-field spellings added for #499, mapped onto the Rust model
/// without weakening the capability model or the process-tree containment.
mod go_task_fields {
    use super::{ConfigProfile, Format, parse_project, parse_project_with_profile};
    use neoenv_core::tasks::TaskDefinition;

    /// A `show` task declaring `body`, always with a runner.
    ///
    /// `with:` lives on the action, so a task with no `uses` has nothing for a
    /// `timeout` to attach to. Supplying the runner here keeps each test to the
    /// one field it is about, and matches what a real file that sets a timeout
    /// looks like anyway.
    fn task(body: &str) -> TaskDefinition {
        let document = format!("{FORMAT_VERSION_DOC}\n{}", indent(body));
        let project = parse_project(
            std::path::Path::new("neoenv.yaml"),
            &format!(
                "{FORMAT_VERSION_DOC}\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n{}",
                indent(body)
            ),
        )
        .unwrap_or_else(|error| panic!("expected acceptance: {error}\n{document}"));
        project
            .tasks
            .get("show")
            .cloned()
            .unwrap_or_else(|| panic!("no `show` task in {document}"))
    }

    const FORMAT_VERSION_DOC: &str = "format_version: 1";

    fn indent(body: &str) -> String {
        use std::fmt::Write as _;
        let mut indented = String::new();
        for line in body.lines() {
            let _ = writeln!(indented, "    {line}");
        }
        indented
    }

    fn with(body: &str, key: &str) -> Option<String> {
        task(body)
            .action
            .as_ref()
            .and_then(|action| action.with.get(key).cloned())
    }

    #[test]
    fn a_top_level_timeout_behaves_like_with_timeout() {
        // The ticket's requirement: identical, including the kill of the whole
        // process tree, which is enforced at run time from this one field.
        assert_eq!(with("timeout: 30s\n", "timeout").as_deref(), Some("30s"));
        assert_eq!(
            with("with:\n  timeout: 30s\n", "timeout").as_deref(),
            Some("30s")
        );
    }

    #[test]
    fn the_two_timeout_spellings_must_not_disagree() {
        // A file carrying both has said two things about how long a task may
        // run. Picking one on the user's behalf and then enforcing it is the
        // one outcome nobody wants.
        // Two disagreements, because a duration can disagree in more than one
        // direction and a rule that only catches one of them is not a rule.
        for (top, with) in [("30s", "60s"), ("0s", "1s"), ("1s", "1m")] {
            let body = format!("timeout: {top}\nwith:\n  timeout: {with}\n");
            let error = parse_project(
                std::path::Path::new("neoenv.yaml"),
                &format!("{FORMAT_VERSION_DOC}\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n{}", indent(&body)),
            )
            .expect_err("a disagreement must be a diagnostic");
            let message = format!("{error}");
            assert!(message.contains(top) && message.contains(with), "{message}");
            assert_eq!(error.code, "NEO136", "{message}");
        }
    }

    #[test]
    fn agreeing_timeout_spellings_are_not_a_conflict() {
        let resolved = task("timeout: 30s\nwith:\n  timeout: 30s\n");
        assert_eq!(
            resolved
                .action
                .as_ref()
                .and_then(|action| action.with.get("timeout"))
                .map(String::as_str),
            Some("30s")
        );
    }

    #[test]
    fn deps_and_dependencies_are_the_same_list_as_needs() {
        for body in ["needs: [a]\n", "deps: [a]\n", "dependencies: [a]\n"] {
            assert_eq!(task(body).needs, vec!["a".to_owned()], "{body}");
        }
    }

    #[test]
    fn a_mapping_needs_preserves_document_order() {
        // Needs become graph edges, so order is run order. A `BTreeMap` here
        // would silently reorder, which is the bug this guards.
        assert_eq!(
            task("needs:\n  zzz: null\n  mmm: null\n  aaa: null\n").needs,
            vec!["zzz".to_owned(), "mmm".to_owned(), "aaa".to_owned()]
        );
    }

    #[test]
    fn a_mapping_needs_ignores_per_entry_options() {
        // The reference reads per-need options; the Rust model has no field for
        // them, so they are read and dropped rather than rejected -- rejecting
        // would refuse a valid Go file, and keeping them would be inventing
        // behavior with nowhere to put it.
        assert_eq!(
            task("needs:\n  a:\n    condition: always\n").needs,
            vec!["a".to_owned()]
        );
    }

    #[test]
    fn predicate_is_the_go_spelling_of_if() {
        let resolved = task("predicate: os == linux\n");
        assert_eq!(resolved.if_condition.as_deref(), Some("os == linux"));
        let native = task("if: os == linux\n");
        assert_eq!(
            resolved.if_condition, native.if_condition,
            "both spellings must produce the same predicate"
        );
    }

    #[test]
    fn envfile_is_the_go_spelling_of_dotenv() {
        let resolved = task("envfile: .env\n");
        let action = resolved.action.as_ref().expect("an action");
        assert_eq!(
            action.dotenv.len(),
            1,
            "envfile must become a dotenv import"
        );
        assert_eq!(action.dotenv[0].path, ".env");
        let native = task("dotenv: .env\n");
        assert_eq!(
            action.dotenv[0].path,
            native.action.as_ref().unwrap().dotenv[0].path
        );
    }

    #[test]
    fn needs_accepts_every_shape_the_reference_declares() {
        // `need.go`: a sequence whose entries are a bare name or a mapping with
        // `id` and `parallel`. The mapping-of-names form is an extension and is
        // documented as one.
        for body in [
            "needs: [zzz, aaa]\n",
            "needs:\n  - zzz\n  - aaa\n",
            "needs:\n  - id: zzz\n    parallel: false\n  - id: aaa\n",
            "needs:\n  zzz: null\n  aaa: null\n",
        ] {
            assert_eq!(
                task(body).needs,
                vec!["zzz".to_owned(), "aaa".to_owned()],
                "{body}"
            );
        }
    }

    #[test]
    fn a_needs_sequence_preserves_document_order() {
        assert_eq!(
            task("needs:\n  - id: zzz\n  - id: mmm\n  - id: aaa\n").needs,
            vec!["zzz".to_owned(), "mmm".to_owned(), "aaa".to_owned()]
        );
    }

    #[test]
    fn the_parallel_need_option_preserves_an_explicit_launch_request() {
        assert_eq!(
            task("needs:\n  - id: zzz\n    parallel: true\n").needs,
            vec!["zzz".to_owned()]
        );
        assert_eq!(
            task("needs:\n  - id: zzz\n    parallel: true\n").parallel_needs,
            vec!["zzz".to_owned()]
        );
    }

    #[test]
    fn hooks_accepts_every_scalar_spelling_the_reference_accepts() {
        // `task.go` compares case-insensitively against `true`/`yes` and
        // against the literal `1`.
        for body in [
            "hooks: true\n",
            "hooks: 'true'\n",
            "hooks: 'yes'\n",
            "hooks: 1\n",
        ] {
            let resolved = task(body);
            assert_eq!(resolved.hooks.before, vec!["before".to_owned()], "{body}");
            assert_eq!(resolved.hooks.after, vec!["after".to_owned()], "{body}");
        }
        for body in [
            "hooks: false\n",
            "hooks: 'false'\n",
            "hooks: 'no'\n",
            "hooks: 0\n",
        ] {
            let resolved = task(body);
            assert!(resolved.hooks.before.is_empty(), "{body}");
            assert!(resolved.hooks.after.is_empty(), "{body}");
        }
    }

    #[test]
    fn an_unrecognized_hooks_scalar_is_a_diagnostic() {
        // The reference errors here rather than defaulting, so defaulting would
        // be inventing a behavior: a typo would silently produce no edges.
        for body in ["hooks: maybe\n", "hooks: 2\n"] {
            let error = parse_project(
                std::path::Path::new("neoenv.yaml"),
                &format!(
                    "{FORMAT_VERSION_DOC}\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n{}",
                    indent(body)
                ),
            )
            .expect_err("an unrecognized hooks scalar must be a diagnostic");
            assert_eq!(error.code, "NEO137", "{error}");
        }
    }

    #[test]
    fn a_go_runner_selector_is_refused_rather_than_ignored() {
        // `embed`, `image`, and `hosts` select a container or a remote host.
        // Ignoring one would run the task *locally* when the file said
        // otherwise, which is the worst outcome available: the run would appear
        // to succeed.
        for key in ["embed: alpine", "image: node:20", "hosts: [web]"] {
            let error = parse_project(
                std::path::Path::new("neoenv.yaml"),
                &format!(
                    "{FORMAT_VERSION_DOC}\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n    {key}\n"
                ),
            )
            .expect_err("a runner selector must be refused");
            let message = format!("{error}");
            assert_eq!(error.code, "NEO139", "{message}");
            assert!(
                message.contains(key.split(':').next().unwrap()),
                "{message}"
            );
        }
    }

    #[test]
    fn the_go_task_key_aliases_all_reach_the_same_field() {
        for (body, expected) in [
            ("dotenv: .env\n", ".env"),
            ("envfile: .env\n", ".env"),
            ("env-file: .env\n", ".env"),
        ] {
            let action = task(body).action.expect("an action");
            assert_eq!(action.dotenv[0].path, expected, "{body}");
        }
    }

    #[test]
    fn hooks_true_becomes_before_and_after_edges() {
        // In the reference `true` means "depend on tasks named `before` and
        // `after`" -- literal names, because a hook is an edge. Translating it
        // to anything else would invent a behavior a Go file does not have.
        let resolved = task("hooks: true\n");
        assert_eq!(resolved.hooks.before, vec!["before".to_owned()]);
        assert_eq!(resolved.hooks.after, vec!["after".to_owned()]);
    }

    #[test]
    fn hooks_false_adds_no_edges() {
        let resolved = task("hooks: false\n");
        assert!(resolved.hooks.before.is_empty());
        assert!(resolved.hooks.after.is_empty());
    }

    #[test]
    fn a_hooks_mapping_is_unchanged_by_the_shorthand() {
        // The shorthand is only possible because `StructuredTaskHooks` has two
        // optional fields, so the untagged order matters: the boolean has to be
        // tried first or `hooks: true` deserializes into an empty mapping.
        let resolved = task("hooks:\n  before: pre\n  after: [post]\n");
        assert_eq!(resolved.hooks.before, vec!["pre".to_owned()]);
        assert_eq!(resolved.hooks.after, vec!["post".to_owned()]);
    }

    #[test]
    fn an_omitted_hooks_block_is_empty() {
        let resolved = task("");
        assert!(resolved.hooks.before.is_empty());
        assert!(resolved.hooks.after.is_empty());
    }

    #[test]
    fn the_mappings_hold_in_the_go_compatibility_profile_too() {
        // The profile reads the same task shapes, so a Go file gets the same
        // normalization rather than a second, divergent path.
        let project = parse_project_with_profile(
            std::path::Path::new("neoenv.yaml"),
            "config:\n  context: production\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n    timeout: 30s\n    deps: [a]\n    hooks: true\n    predicate: os == linux\n  a:\n    uses: portable\n    run: 'true'\n",
            Format::Yaml,
            ConfigProfile::Go,
        )
        .unwrap();
        let show = project.tasks.get("show").unwrap();
        assert_eq!(show.needs, vec!["a".to_owned()]);
        assert_eq!(show.hooks.before, vec!["before".to_owned()]);
        assert_eq!(show.if_condition.as_deref(), Some("os == linux"));
        assert_eq!(
            show.action
                .as_ref()
                .and_then(|action| action.with.get("timeout"))
                .map(String::as_str),
            Some("30s")
        );
        assert_eq!(project.context.as_deref(), Some("production"));
    }
}

mod vault_declarations {
    use std::path::Path;

    use super::super::{VaultProvider, parse_project};

    fn vaults(input: &str) -> Result<super::super::Project, super::super::Diagnostic> {
        parse_project(Path::new("neoenv.yaml"), input)
    }

    #[test]
    fn age_and_keepass_are_normalized_with_their_provider_settings() {
        let project = vaults(
            "vaults:\n  machine:\n    driver: age\n    identity: ~/.config/neoenv/age/identity.txt\n    values:\n      work-vault: ciphertext\n  work:\n    driver: keepass\n    path: ./.neoenv/secrets.kdbx\n    secret: nsv://machine/work-vault\n",
        )
        .unwrap();
        let machine = project.vaults.get("machine").unwrap();
        assert_eq!(machine.provider_name(), "age");
        match &machine.provider {
            VaultProvider::Age(age) => {
                assert_eq!(
                    age.identity.as_deref(),
                    Some("~/.config/neoenv/age/identity.txt")
                );
                assert_eq!(
                    age.values.get("work-vault").map(String::as_str),
                    Some("ciphertext")
                );
            }
            VaultProvider::Keepass(_) | VaultProvider::Os(_) => {
                panic!("expected an age vault")
            }
        }
        let work = project.vaults.get("work").unwrap();
        assert_eq!(work.provider_name(), "keepass");
        match &work.provider {
            VaultProvider::Keepass(keepass) => {
                assert_eq!(keepass.path, "./.neoenv/secrets.kdbx");
                assert_eq!(keepass.secret, "nsv://machine/work-vault");
            }
            VaultProvider::Age(_) | VaultProvider::Os(_) => {
                panic!("expected a keepass vault")
            }
        }
    }

    #[test]
    fn toml_accepts_the_same_declarations() {
        let project = parse_project(
            Path::new("neoenv.toml"),
            "[vaults.machine]\ndriver = \"age\"\nidentity = \"identity.txt\"\n\n[vaults.work]\ndriver = \"keepass\"\npath = \"secrets.kdbx\"\nsecret = \"nsv://machine/keepass\"\n",
        )
        .unwrap();
        assert_eq!(project.vaults.len(), 2);
    }

    #[test]
    fn the_os_provider_defaults_and_explicit_service_are_accepted() {
        let project =
            vaults("vaults:\n  login:\n    driver: os\n  work:\n    driver: os\n    service: com.example.app\n")
                .unwrap();
        match &project.vaults["login"].provider {
            VaultProvider::Os(os) => assert_eq!(os.service, "neoenv"),
            VaultProvider::Age(_) | VaultProvider::Keepass(_) => panic!("expected an os vault"),
        }
        match &project.vaults["work"].provider {
            VaultProvider::Os(os) => assert_eq!(os.service, "com.example.app"),
            VaultProvider::Age(_) | VaultProvider::Keepass(_) => panic!("expected an os vault"),
        }
    }

    #[test]
    fn an_os_vault_refuses_fields_from_other_providers() {
        let error =
            vaults("vaults:\n  login:\n    driver: os\n    path: secrets.kdbx\n").unwrap_err();
        assert_eq!(error.code, "NEO148");
        assert!(error.message.contains("path"));
    }

    #[test]
    fn provider_and_kind_are_not_aliases_for_driver() {
        for key in ["provider", "kind"] {
            let error = vaults(&format!("vaults:\n  work:\n    {key}: age\n")).unwrap_err();
            assert_eq!(error.code, "NEO102");
            assert!(error.message.contains("unknown field"), "{}", error.message);
        }
    }

    #[test]
    fn an_unknown_provider_names_the_supported_set() {
        let error = vaults("vaults:\n  login:\n    driver: vault\n").unwrap_err();
        assert_eq!(error.code, "NEO147");
        assert!(error.message.contains("age"));
        assert!(error.message.contains("keepass"));
    }

    #[test]
    fn service_is_refused_on_a_non_os_driver_by_name() {
        for driver in ["age", "keepass"] {
            let error = if driver == "keepass" {
                vaults("vaults:\n  work:\n    driver: keepass\n    path: secrets.kdbx\n    secret: x\n    service: nope\n")
            } else {
                vaults("vaults:\n  work:\n    driver: age\n    service: nope\n")
            }
            .unwrap_err();
            assert_eq!(error.code, "NEO148");
            assert!(error.message.contains("service"), "{}", error.message);
        }
    }

    #[test]
    fn a_keepass_declaration_requires_a_path_and_a_secret() {
        let missing_path =
            vaults("vaults:\n  work:\n    driver: keepass\n    secret: password\n").unwrap_err();
        assert_eq!(missing_path.code, "NEO148");
        assert!(missing_path.message.contains("path"));
        let missing_secret =
            vaults("vaults:\n  work:\n    driver: keepass\n    path: secrets.kdbx\n").unwrap_err();
        assert_eq!(missing_secret.code, "NEO148");
        assert!(missing_secret.message.contains("secret"));
    }

    #[test]
    fn a_field_from_the_wrong_provider_is_refused_by_name() {
        let error =
            vaults("vaults:\n  work:\n    driver: keepass\n    path: secrets.kdbx\n    secret: x\n    identity: nope\n")
                .unwrap_err();
        assert_eq!(error.code, "NEO148");
        assert!(error.message.contains("identity"));
        assert!(error.message.contains("age"));
    }

    #[test]
    fn a_vault_name_must_be_a_lowercase_identifier() {
        let error = vaults("vaults:\n  Work:\n    driver: age\n").unwrap_err();
        assert_eq!(error.code, "NEO146");
        assert!(error.message.contains("Work"));
    }

    #[test]
    fn the_line_oriented_syntax_has_no_vault_form_and_produces_an_empty_map() {
        let project = parse_project(Path::new(".neoenv"), "NAME=neoenv\n").unwrap();
        assert!(project.vaults.is_empty());
    }

    #[test]
    fn debug_redacts_age_values_and_a_keepass_secret() {
        let project = vaults(
            "vaults:\n  machine:\n    driver: age\n    identity: AGE-SECRET-KEY-SENTINEL\n    values:\n      work: CIPHERTEXT-SENTINEL\n  work:\n    driver: keepass\n    path: secrets.kdbx\n    secret: PASSWORD-SENTINEL\n",
        )
        .unwrap();
        let debug = format!("{project:?}");
        assert!(!debug.contains("SENTINEL"));
    }
}
