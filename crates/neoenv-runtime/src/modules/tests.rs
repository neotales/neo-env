//! Module loader tests for composition order, containment, task package
//! identity, and cache reuse.

use super::{ModuleLoader, load_local_modules, load_task_package};
use neoenv_config::TaskPackage;
use std::{error::Error as _, fs, io, panic::AssertUnwindSafe};

use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn cached_direct(root: &std::path::Path, name: &str, input: &[u8]) -> (String, std::path::PathBuf) {
    let digest = format!("{:x}", Sha256::digest(input));
    let cache = root
        .join(neoenv_core::names::PROJECT_MODULE_CACHE)
        .join("files")
        .join(&digest);
    fs::create_dir_all(cache.parent().unwrap()).unwrap();
    fs::write(&cache, input).unwrap();
    (
        format!("https://example.test/{name}#sha256={digest}&type=file"),
        cache,
    )
}

#[test]
fn direct_file_module_and_task_package_load_verified_bytes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    let (module, _) = cached_direct(temp.path(), "module.toml", b"[env]\nANSWER = 'yes'\n");
    fs::write(&root, format!("imports: [\"{module}\"]\n")).unwrap();
    let modules = load_local_modules(temp.path(), &root).unwrap();
    assert_eq!(modules[0].1.environment[0].value, "yes");
    assert!(modules[0].0.is_remote_module());
    let (package, cache) = cached_direct(temp.path(), "task.yaml", b"tasks:\n  lint: 'true'\n");
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::process_profile())
            .unwrap();
    let loaded = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: package.clone(),
                task: "lint".into(),
            },
        )
        .unwrap();
    assert!(loaded.project.tasks.contains_key("lint"));
    assert!(loaded.identity.external);
    assert!(loader.take_contributors().iter().any(|item| matches!(&item.identity, crate::trust::TrustIdentity::Remote(remote) if remote.repository == "https://example.test/task.yaml")));
    fs::write(cache, b"tampered").unwrap();
    assert!(
        loader
            .load_task_package_with_identity(
                &root,
                &TaskPackage {
                    from: package,
                    task: "lint".into()
                }
            )
            .is_err()
    );
}

#[test]
fn direct_file_nested_imports_are_refused() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    let (module, _) = cached_direct(temp.path(), "module.yaml", b"imports: [../outside.yaml]\n");
    fs::write(&root, format!("imports: [\"{module}\"]\n")).unwrap();
    assert_eq!(
        load_local_modules(temp.path(), &root).unwrap_err().code,
        "NEO632"
    );
}

#[test]
fn direct_file_rejects_path_bearing_declarations_for_modules_and_packages() {
    let cases = [
        "imports: [../outside.yaml]\n",
        "task_packages:\n  nested: ./other.yaml\n",
        "dotenv: .env\n",
        "inventory_files: [other.yaml]\n",
        "inventories:\n  lab:\n    defaults:\n      identity_file: fixture-key\n    hosts: {}\n",
        "vaults:\n  work:\n    driver: keepass\n    path: secret.kdbx\n    secret: nsv://machine/work\n",
        "task_dirs:\n  local: runners\n",
        "workspace:\n  members: [other]\n",
        "path:\n  - prepend: bin\n",
        "tools:\n  - id: demo\n    version: 1\n",
        "tasks:\n  lint:\n    uses: shell\n    run: 'true'\n    cwd: ../outside\n",
        "tasks:\n  lint:\n    uses: shell\n    run: 'true'\n    dotenv: other.env\n",
        "tasks:\n  lint:\n    uses: render\n    source: ../outside\n    destination: out\n",
        "tasks:\n  lint:\n    uses: tmpl\n    with:\n      files: [other:out]\n",
        "tasks:\n  lint:\n    uses: tmpl\n    with:\n      values: other.yaml\n",
        "jobs:\n  example:\n    cwd: other\n    steps: [lint]\n",
    ];
    for body in cases {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("neoenv.yaml");
        let (spec, _) = cached_direct(temp.path(), "module.yaml", body.as_bytes());
        fs::write(&root, format!("imports: [\"{spec}\"]\n")).unwrap();
        let error = load_local_modules(temp.path(), &root).unwrap_err();
        assert_eq!(error.code, "NEO632", "{body}: {error:?}");
        let error = load_task_package(
            temp.path(),
            &root,
            &TaskPackage {
                from: spec,
                task: "lint".into(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "NEO632", "{body}: {error:?}");
    }
}

#[test]
fn loads_nested_modules_before_importers_and_preserves_paths() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("modules")).unwrap();
    fs::write(
        temp.path().join("modules/base.yaml"),
        "env:\n  VALUE: base\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("modules/feature.yaml"),
        "imports: [base.yaml]\nenv:\n  VALUE: feature\n",
    )
    .unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(
        &root,
        "imports: [modules/feature.yaml]\nenv:\n  VALUE: project\n",
    )
    .unwrap();
    let modules = load_local_modules(temp.path(), &root).unwrap();
    assert_eq!(
        modules
            .iter()
            .map(|(_, project)| project.environment[0].value.as_str())
            .collect::<Vec<_>>(),
        ["base", "feature", "project"]
    );
}

#[test]
fn rejects_traversal_and_cycles() {
    // The escaping document must sit beside the project root, so both live in
    // one container. Using a shared parent directory here would let parallel
    // tests race on the same outside file.
    let container = TempDir::new().unwrap();
    let temp = container.path().join("project");
    fs::create_dir_all(&temp).unwrap();
    let outside = container.path().join("outside.yaml");
    fs::write(&outside, "env: {}\n").unwrap();
    let root = temp.join("neoenv.yaml");
    fs::write(&root, "imports: [../outside.yaml]\n").unwrap();
    assert_eq!(load_local_modules(&temp, &root).unwrap_err().code, "NEO614");
    fs::write(temp.join("one.yaml"), "imports: [two.yaml]\n").unwrap();
    fs::write(temp.join("two.yaml"), "imports: [one.yaml]\n").unwrap();
    fs::write(&root, "imports: [one.yaml]\n").unwrap();
    assert_eq!(load_local_modules(&temp, &root).unwrap_err().code, "NEO610");
}

#[test]
fn imported_neoenv_documents_keep_the_format_diagnostic_before_parsing() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("module")).unwrap();
    let imported = temp.path().join("module/.neoenv");
    fs::write(&imported, "tasks: [\n").unwrap();
    let imported = imported.canonicalize().unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "imports: [module/.neoenv]\n").unwrap();
    let error = load_local_modules(temp.path(), &root).unwrap_err();
    assert_eq!(error.code, "NEO611");
    assert_eq!(
        error.message,
        format!("local modules must be YAML or TOML: {}", imported.display())
    );
}

#[test]
fn selects_and_namespaces_module_tasks_without_running_them() {
    let temp = TempDir::new().unwrap();
    fs::write(
            temp.path().join("module.yaml"),
            "tasks:\n  build:\n    run: touch should-not-run\n  test:\n    needs: build\n    run: touch should-not-run\n",
        )
        .unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(
        &root,
        "imports:\n  - from: module.yaml\n    namespace: tools\n    tasks: [build, test]\n",
    )
    .unwrap();

    let modules = load_local_modules(temp.path(), &root).unwrap();
    let module = &modules[0].1;
    assert!(module.tasks.contains_key("tools:build"));
    assert_eq!(module.tasks["tools:test"].needs, ["tools:build"]);
    assert!(!temp.path().join("should-not-run").exists());
}

#[test]
fn task_package_module_cache_parses_shared_imports_once_and_preserves_snapshots() {
    let temp = TempDir::new().unwrap();
    let package_directory = temp.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    fs::write(
        package_directory.join("shared.yaml"),
        "tasks:\n  prepare: 'true'\n",
    )
    .unwrap();
    let package_contents = "imports: [shared.yaml]\ntasks:\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n";
    fs::write(package_directory.join("first.yaml"), package_contents).unwrap();
    fs::write(package_directory.join("second.yaml"), package_contents).unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let first = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/first.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();
    let second = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/second.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();
    assert_eq!(loader.parsed_document_count(), 3);

    let mut first_baseline =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let first_expected = first_baseline
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/first.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();
    let mut second_baseline =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let second_expected = second_baseline
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/second.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();

    assert_eq!(first.project.tasks, first_expected.project.tasks);
    assert_eq!(second.project.tasks, second_expected.project.tasks);
    assert_eq!(first.identity, first_expected.identity);
    assert_eq!(second.identity, second_expected.identity);
    assert_eq!(
        first.identity.sha256,
        format!(
            "{:x}",
            Sha256::digest(fs::read(package_directory.join("first.yaml")).unwrap())
        )
    );
    assert_eq!(
        second.identity.sha256,
        format!(
            "{:x}",
            Sha256::digest(fs::read(package_directory.join("second.yaml")).unwrap())
        )
    );
}

#[test]
fn module_cache_keeps_import_selectors_and_namespaces_independent() {
    let temp = TempDir::new().unwrap();
    let package_directory = temp.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    fs::write(
        package_directory.join("shared.yaml"),
        "tasks:\n  a: 'true'\n  b: 'true'\n",
    )
    .unwrap();
    for (name, namespace) in [("first", "first"), ("second", "second")] {
        fs::write(
                package_directory.join(format!("{name}.yaml")),
                format!(
                    "imports:\n  - from: shared.yaml\n    namespace: {namespace}\n    tasks: [{}]\ntasks:\n  default:\n    uses: portable\n    run: 'true'\n",
                    if name == "first" { "a" } else { "b" }
                ),
            )
            .unwrap();
    }
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let first = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/first.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();
    let second = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "neoenv/tasks/second.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap();
    assert_eq!(loader.parsed_document_count(), 3);
    assert!(first.project.tasks.contains_key("first:a"));
    assert!(!first.project.tasks.contains_key("second:b"));
    assert!(second.project.tasks.contains_key("second:b"));
    assert!(!second.project.tasks.contains_key("first:a"));
}

#[test]
fn module_loader_reuses_each_selected_document_across_source_graph_loads() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("shared.yaml"), "env:\n  VALUE: shared\n").unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "imports: [shared.yaml]\nenv:\n  VALUE: root\n").unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let first = loader.load_local_modules(&root).unwrap();
    let second = loader.load_local_modules(&root).unwrap();
    assert_eq!(loader.parsed_document_count(), 2);
    assert_eq!(first, second);
}

// Keeps all four stable graph diagnostics together.
#[test]
#[allow(clippy::too_many_lines)]
fn task_package_graph_diagnostics_keep_their_existing_containment_and_limits() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    let cycle_directory = temp.path().join("cycle");
    fs::create_dir_all(&cycle_directory).unwrap();
    fs::write(
        cycle_directory.join("package.yaml"),
        "imports: [other.yaml]\n",
    )
    .unwrap();
    fs::write(
        cycle_directory.join("other.yaml"),
        "imports: [package.yaml]\n",
    )
    .unwrap();
    let cycle_package = cycle_directory.join("package.yaml").canonicalize().unwrap();
    let cycle_other = cycle_directory.join("other.yaml").canonicalize().unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let error = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "cycle/package.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "NEO610");
    assert_eq!(
        error.message,
        format!(
            "local module import cycle: {} -> {} -> {}",
            cycle_package.display(),
            cycle_other.display(),
            cycle_package.display()
        )
    );

    let deep_directory = temp.path().join("deep");
    fs::create_dir_all(&deep_directory).unwrap();
    for index in 0..18 {
        let import = if index + 1 < 18 {
            format!("imports: [m{}.yaml]\n", index + 1)
        } else {
            String::new()
        };
        fs::write(
            deep_directory.join(format!("m{index}.yaml")),
            format!("{import}env: {{}}\n"),
        )
        .unwrap();
    }
    fs::write(deep_directory.join("package.yaml"), "imports: [m0.yaml]\n").unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let error = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "deep/package.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "NEO627");
    assert_eq!(
        error.message,
        "module import depth limit exceeded: maximum depth is 16"
    );

    let many_directory = temp.path().join("many");
    fs::create_dir_all(&many_directory).unwrap();
    let names = (0..128)
        .map(|index| format!("m{index}.yaml"))
        .collect::<Vec<_>>();
    for name in &names {
        fs::write(many_directory.join(name), "env: {}\n").unwrap();
    }
    fs::write(
        many_directory.join("package.yaml"),
        format!("imports: [{}]\n", names.join(", ")),
    )
    .unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let error = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "many/package.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "NEO628");
    assert_eq!(
        error.message,
        "module document count limit exceeded: maximum documents is 128"
    );

    let contained_directory = temp.path().join("contained");
    fs::create_dir_all(&contained_directory).unwrap();
    fs::write(temp.path().join("outside.yaml"), "env: {}\n").unwrap();
    fs::write(
        contained_directory.join("package.yaml"),
        "imports: [../outside.yaml]\n",
    )
    .unwrap();
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    let error = loader
        .load_task_package_with_identity(
            &root,
            &TaskPackage {
                from: "contained/package.yaml".into(),
                task: "default".into(),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "NEO614");
    assert_eq!(
        error.message,
        "local module import escapes project root: ../outside.yaml"
    );
}

#[test]
fn loads_digest_pinned_tarball_only_from_a_hermetic_cache() {
    let temp = TempDir::new().unwrap();
    let digest = "a".repeat(64);
    let source = temp
        .path()
        .join(".neoenv/modules/tarballs")
        .join(&digest)
        .join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("neoenv.module.yaml"),
        "env:\n  TARBALL: cached\n",
    )
    .unwrap();
    fs::write(
        source.parent().unwrap().join("metadata.toml"),
        format!("url = \"https://example.test/module.tar.gz\"\nsha256 = {digest:?}\n"),
    )
    .unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(
        &root,
        format!("imports: [\"https://example.test/module.tar.gz#sha256={digest}\"]\n"),
    )
    .unwrap();

    let modules = load_local_modules(temp.path(), &root).unwrap();
    assert_eq!(modules[0].1.environment[0].value, "cached");
}

#[test]
fn discovers_named_modules_from_the_user_cache_without_network_access() {
    let temp = TempDir::new().unwrap();
    let user_cache = temp.path().join("user/modules");
    fs::create_dir_all(&user_cache).unwrap();
    fs::write(user_cache.join("shared.yaml"), "env:\n  CACHE: user\n").unwrap();

    let module = super::discover_named_module_in(temp.path(), "shared", Some(&user_cache)).unwrap();
    assert_eq!(fs::read_to_string(module).unwrap(), "env:\n  CACHE: user\n");
}

#[test]
fn task_package_nested_subfolder_path_selects_the_named_task() {
    let temp = TempDir::new().unwrap();
    let directory = temp.path().join("tasks/lint");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("base.yaml"), "tasks:\n  prepare: 'true'\n").unwrap();
    fs::write(
        directory.join("task.yaml"),
        "imports: [base.yaml]\ntasks:\n  lint:\n    needs: prepare\n    uses: portable\n    run: 'true'\n  other: 'true'\n",
    )
    .unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    let package = load_task_package(
        temp.path(),
        &root,
        &TaskPackage {
            from: "./tasks/lint/task.yaml".into(),
            task: "lint".into(),
        },
    )
    .unwrap();

    // The selected export is one named task; its imports are confined to the
    // same subfolder and composed before it.
    assert!(package.tasks.contains_key("lint"));
    assert!(package.tasks.contains_key("other"));
    assert!(package.tasks.contains_key("prepare"));
    assert_eq!(package.tasks["lint"].needs, ["prepare"]);
}

#[test]
fn nested_task_package_paths_cannot_escape_the_project() {
    let container = TempDir::new().unwrap();
    let project = container.path().join("project");
    fs::create_dir_all(project.join("tasks/lint")).unwrap();
    let outside = container.path().join("outside.yaml");
    fs::write(&outside, "tasks:\n  escaped: 'true'\n").unwrap();
    let root = project.join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    for reference in [
        "./tasks/../../outside.yaml",
        "./tasks/lint/../../../outside.yaml",
    ] {
        let error = load_task_package(
            &project,
            &root,
            &TaskPackage {
                from: reference.into(),
                task: "escaped".into(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "NEO623", "{reference}");
        assert!(
            error.message.contains("escapes project root"),
            "{reference}: {}",
            error.message
        );
    }
}

#[test]
fn unpinned_remote_task_package_references_are_refused_before_any_cache_read() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();
    let commit = "0123456789abcdef0123456789abcdef01234567";

    for (reference, expected) in [
        (
            "github:octo/repo@main//tasks/lint/task.yaml".to_owned(),
            "not a branch or HEAD",
        ),
        (
            "github:octo/repo//tasks/lint/task.yaml".to_owned(),
            "requires a pinned commit or exact tag",
        ),
        (
            format!("github:octo/repo@{commit}//../secret.yaml"),
            "subpath must be non-empty and traversal-free",
        ),
    ] {
        let reference = reference.as_str();
        let error = load_task_package(
            temp.path(),
            &root,
            &TaskPackage {
                from: reference.into(),
                task: "lint".into(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "NEO622", "{reference}");
        assert!(
            error.message.contains(expected),
            "{reference}: {}",
            error.message
        );
    }
}

#[cfg(unix)]
#[test]
fn a_nested_task_package_directory_symlink_cannot_escape_the_project() {
    use std::os::unix::fs::symlink;

    let container = TempDir::new().unwrap();
    let project = container.path().join("project");
    fs::create_dir_all(project.join("tasks")).unwrap();
    let outside = container.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("task.yaml"), "tasks:\n  escaped: 'true'\n").unwrap();
    symlink(&outside, project.join("tasks/lint")).unwrap();
    let root = project.join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    let error = load_task_package(
        &project,
        &root,
        &TaskPackage {
            from: "./tasks/lint/task.yaml".into(),
            task: "escaped".into(),
        },
    )
    .unwrap_err();

    assert_eq!(error.code, "NEO623");
    // The link is refused on the original path, before canonicalization can
    // make the outside directory look like the selected package root.
    assert!(error.message.contains("symbolic link"), "{}", error.message);
}

#[cfg(unix)]
#[test]
fn a_same_directory_symlinked_task_package_path_is_refused() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let directory = temp.path().join("pkg");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("task.yaml"),
        "tasks:\n  default:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    symlink("task.yaml", directory.join("link.yaml")).unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, "format_version: 1\n").unwrap();

    let error = load_task_package(
        temp.path(),
        &root,
        &TaskPackage {
            from: "pkg/link.yaml".into(),
            task: "default".into(),
        },
    )
    .unwrap_err();

    assert_eq!(error.code, "NEO623");
    assert!(error.message.contains("symbolic link"), "{}", error.message);
}

#[cfg(unix)]
#[test]
fn a_parent_component_is_walked_where_it_actually_resolves() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let module_directory = project.join("a");
    fs::create_dir_all(&module_directory).unwrap();
    fs::create_dir_all(project.join("real")).unwrap();
    fs::write(
        project.join("real/task.yaml"),
        "tasks:\n  default:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    // The link is beside `a`, not inside it. A walk that floors at the
    // declaring directory would inspect `a/link`, miss this link, and accept
    // the target.
    symlink("real", project.join("link")).unwrap();
    let importing = module_directory.join("module.yaml");
    fs::write(&importing, "format_version: 1\n").unwrap();

    let error = load_task_package(
        project,
        &importing,
        &TaskPackage {
            from: "../link/task.yaml".into(),
            task: "default".into(),
        },
    )
    .unwrap_err();

    assert_eq!(error.code, "NEO623");
    assert!(error.message.contains("symbolic link"), "{}", error.message);
}

#[test]
fn task_packages_are_contained_and_compose_imported_task_definitions() {
    // Both the project and the escaping document share one container so the
    // `..` reference stays valid without writing into the shared parent.
    let container = TempDir::new().unwrap();
    let temp = container.path().join("project");
    fs::create_dir_all(&temp).unwrap();
    let root = temp.join("neoenv.yaml");
    let tasks = temp.join("neoenv/tasks");
    fs::create_dir_all(&tasks).unwrap();
    fs::write(tasks.join("base.yaml"), "tasks:\n  prepare: 'true'\n").unwrap();
    fs::write(
            tasks.join("lint.yaml"),
            "imports: [base.yaml]\ntasks:\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
        )
        .unwrap();
    fs::write(&root, "format_version: 1\n").unwrap();
    let package = load_task_package(
        &temp,
        &root,
        &TaskPackage {
            from: "lint".into(),
            task: "default".into(),
        },
    )
    .unwrap();
    assert!(package.tasks.contains_key("prepare"));
    assert_eq!(package.tasks["default"].needs, ["prepare"]);

    let outside = container.path().join("outside-task.yaml");
    fs::write(&outside, "tasks:\n  default: 'true'\n").unwrap();
    let error = load_task_package(
        &temp,
        &root,
        &TaskPackage {
            from: "../outside-task.yaml".into(),
            task: "default".into(),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "NEO623");
}

#[cfg(unix)]
#[test]
fn path_style_task_package_dotenv_symlinks_cannot_escape_the_document_directory() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let root = project.join("neoenv.yaml");
    let package_directory = project.join("pkg");
    fs::create_dir_all(&package_directory).unwrap();
    fs::write(&root, "format_version: 1\n").unwrap();
    fs::write(
        package_directory.join("tool.yaml"),
        "tasks:\n  default:\n    uses: shell\n    run: 'true'\n    dotenv: tool.env\n",
    )
    .unwrap();
    let outside = project.join("outside.env");
    fs::write(&outside, "PACKAGE_SECRET=must-not-be-read\n").unwrap();
    symlink(&outside, package_directory.join("tool.env")).unwrap();

    let error = load_task_package(
        project,
        &root,
        &TaskPackage {
            from: "pkg/tool.yaml".into(),
            task: "default".into(),
        },
    )
    .unwrap_err();

    assert_eq!(error.code, "NEO629");
    assert!(
        error
            .message
            .contains("task dotenv path escapes its package root")
    );
    assert!(!error.message.contains("must-not-be-read"));
}

#[cfg(unix)]
#[test]
fn task_package_symlinks_cannot_escape_the_project_package_root() {
    use std::os::unix::fs::symlink;

    let container = TempDir::new().unwrap();
    let temp = container.path().join("project");
    fs::create_dir_all(&temp).unwrap();
    let root = temp.join("neoenv.yaml");
    let tasks = temp.join("neoenv/tasks");
    fs::create_dir_all(&tasks).unwrap();
    let outside = container.path().join("outside-task.yaml");
    fs::write(&outside, "tasks:\n  default: 'true'\n").unwrap();
    symlink(&outside, tasks.join("lint.yaml")).unwrap();
    fs::write(&root, "format_version: 1\n").unwrap();
    let error = load_task_package(
        &temp,
        &root,
        &TaskPackage {
            from: "lint".into(),
            task: "default".into(),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "NEO623");
}

#[test]
fn rejects_tarball_links_before_they_can_escape_the_cache() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("unsafe.tar.gz");
    let output = fs::File::create(&archive).unwrap();
    let encoder = GzEncoder::new(output, Compression::default());
    let mut tarball = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("module.yaml").unwrap();
    header.set_link_name("../../outside.yaml").unwrap();
    header.set_size(0);
    header.set_cksum();
    tarball.append(&header, io::empty()).unwrap();
    tarball.into_inner().unwrap().finish().unwrap();

    assert!(matches!(
        super::extract_tarball(&archive, &temp.path().join("source")),
        Err(super::RemoteError::CacheMismatch(_))
    ));
}

#[test]
fn module_import_depth_has_a_stable_budget_diagnostic() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    for index in 0..18 {
        let path = temp.path().join(format!("m{index}.yaml"));
        let import = if index + 1 < 18 {
            format!("imports: [m{}.yaml]\n", index + 1)
        } else {
            String::new()
        };
        fs::write(&path, format!("{import}env: {{}}\n")).unwrap();
    }
    fs::write(&root, "imports: [m0.yaml]\n").unwrap();
    let error = load_local_modules(temp.path(), &root).unwrap_err();
    assert_eq!(error.code, "NEO627");
    assert!(error.message.contains("module import depth limit exceeded"));
    assert!(error.message.contains("16"));
}

#[test]
fn module_document_graph_has_a_stable_budget_diagnostic() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    let names = (0..128)
        .map(|index| format!("m{index}.yaml"))
        .collect::<Vec<_>>();
    for name in &names {
        fs::write(temp.path().join(name), "env: {}\n").unwrap();
    }
    fs::write(&root, format!("imports: [{}]\n", names.join(", "))).unwrap();
    let error = load_local_modules(temp.path(), &root).unwrap_err();
    assert_eq!(error.code, "NEO628");
    assert!(
        error
            .message
            .contains("module document count limit exceeded")
    );
    assert!(error.message.contains("128"));
}

#[test]
fn oversized_local_module_metadata_is_rejected_with_its_limit() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    fs::write(&root, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let error = load_local_modules(temp.path(), &root).unwrap_err();
    assert!(error.message.contains("local metadata limit 1048576"));
}

#[test]
fn truncated_archive_retains_the_parser_source() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("truncated.tar.gz");
    fs::write(&archive, b"not a gzip archive").unwrap();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        super::extract_tarball(&archive, &temp.path().join("source"))
    }));
    let error = result
        .expect("truncated archive must not panic")
        .unwrap_err();

    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some()
    );
}

#[test]
fn archive_loader_never_panics_on_bounded_malformed_inputs() {
    let temp = TempDir::new().unwrap();
    for case in 0..256_u32 {
        let mut state = case.wrapping_mul(0x9e37_79b9).wrapping_add(7);
        let length = (state as usize % 384) + 1;
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state.to_le_bytes()[0];
        }
        let archive = temp.path().join(format!("case-{case}.tar.gz"));
        fs::write(&archive, bytes).unwrap();
        let destination = temp.path().join(format!("source-{case}"));
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            super::extract_tarball(&archive, &destination)
        }));
        assert!(result.is_ok(), "archive loader panicked for case {case}");
        assert!(
            result.unwrap().is_err(),
            "malformed case {case} was accepted"
        );
    }
}
