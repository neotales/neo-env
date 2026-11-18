//! Resolved configuration tests for package composition order, source
//! precedence, inspection redaction, and dotenv quoting.

use std::{
    fs,
    path::{Path, PathBuf},
};

use indexmap::IndexMap;
use neoenv_config::TaskPackage;
use neoenv_core::tasks::{TaskAction, TaskDefinition};
use tempfile::TempDir;

use super::{TaskAccumulator, apply_task_packages, conventional_private_overlay, resolve_sources};
use crate::discovery::{discover, select_sources};
use crate::modules::ModuleLoader;

fn write(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
}

#[test]
fn package_composition_is_incremental_and_preserves_package_order() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    let package_directory = temp.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    write(&root, "format_version: 1\n");
    for name in ["first", "second"] {
        write(
            &package_directory.join(format!("{name}.yaml")),
            "tasks:\n  default:\n    uses: portable\n    run: 'true'\n",
        );
    }
    let package = |name: &str| TaskPackage {
        from: format!("neoenv/tasks/{name}.yaml"),
        task: "default".into(),
    };
    let mut packages = IndexMap::new();
    packages.insert("first".into(), package("first"));
    packages.insert("second".into(), package("second"));

    let mut tasks = TaskAccumulator::default();
    tasks.insert(
        "first-caller",
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("package:first".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    tasks.insert(
        "second-caller",
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("package:second".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    apply_task_packages(&mut loader, &root, &packages, &mut tasks).unwrap();
    assert_eq!(
        tasks.composition_events,
        [
            ("first".into(), "first-caller".into()),
            ("second".into(), "second-caller".into())
        ]
    );

    let mut reversed_packages = IndexMap::new();
    reversed_packages.insert("second".into(), package("second"));
    reversed_packages.insert("first".into(), package("first"));
    let mut reversed_tasks = TaskAccumulator::default();
    reversed_tasks.insert(
        "first-caller",
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("package:first".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    reversed_tasks.insert(
        "second-caller",
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("package:second".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    apply_task_packages(&mut loader, &root, &reversed_packages, &mut reversed_tasks).unwrap();
    assert_eq!(
        reversed_tasks.composition_events,
        [
            ("second".into(), "second-caller".into()),
            ("first".into(), "first-caller".into())
        ]
    );

    let mut unreferenced = TaskAccumulator::default();
    unreferenced.insert(
        "ordinary",
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("portable".into()),
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    );
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    apply_task_packages(&mut loader, &root, &packages, &mut unreferenced).unwrap();
    assert_eq!(unreferenced.composed_references, 0);
    assert!(unreferenced.composition_events.is_empty());
}

#[test]
fn a_caller_override_replaces_package_file_and_values_provenance() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("neoenv.yaml");
    let package_directory = temp.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    write(&root, "format_version: 1\n");
    write(
        &package_directory.join("default.yaml"),
        "tasks:\n  default:\n    uses: tmpl\n    with:\n      files:\n        - package.tmpl:package.out\n      values: package-values.yaml\n",
    );
    let package = TaskPackage {
        from: "neoenv/tasks/default.yaml".into(),
        task: "default".into(),
    };
    let mut packages = IndexMap::new();
    packages.insert("pack".into(), package);

    let caller_document = neoenv_core::SourceSpan::new("caller.yaml".into(), 1, 1);
    let caller = |files: Vec<String>, values: bool| {
        let has_files = !files.is_empty();
        TaskDefinition {
            action: Some(TaskAction {
                uses: Some("package:pack".into()),
                files,
                files_document: has_files.then(|| caller_document.clone()),
                values_document: values.then(|| caller_document.clone()),
                with: if values {
                    IndexMap::from([("values".to_owned(), "caller-values.yaml".to_owned())])
                } else {
                    IndexMap::new()
                },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        }
    };
    let mut tasks = TaskAccumulator::default();
    tasks.insert(
        "override",
        caller(vec!["caller.tmpl:caller.out".into()], true),
    );
    tasks.insert("plain", caller(Vec::new(), false));
    let mut loader =
        ModuleLoader::with_profile(temp.path(), neoenv_config::ConfigProfile::Native).unwrap();
    apply_task_packages(&mut loader, &root, &packages, &mut tasks).unwrap();

    let overridden = tasks
        .tasks
        .get("override")
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert!(!overridden.files_from_package);
    assert_eq!(
        overridden
            .files_document
            .as_ref()
            .map(|span| span.path.as_str()),
        Some("caller.yaml")
    );
    assert!(!overridden.values_from_package);
    assert_eq!(
        overridden
            .values_document
            .as_ref()
            .map(|span| span.path.as_str()),
        Some("caller.yaml")
    );

    let inherited = tasks.tasks.get("plain").unwrap().action.as_ref().unwrap();
    assert!(inherited.files_from_package);
    assert!(
        inherited
            .files_document
            .as_ref()
            .is_some_and(|span| span.path.ends_with("neoenv/tasks/default.yaml"))
    );
    assert!(inherited.values_from_package);
    assert!(
        inherited
            .values_document
            .as_ref()
            .is_some_and(|span| span.path.ends_with("neoenv/tasks/default.yaml"))
    );
}

#[test]
fn later_sources_override_values_and_inspection_redacts_secrets() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let private = root.join("neoenv/private");
    let user = temp.path().join("user.yaml");
    fs::create_dir_all(&private).unwrap();
    write(
        &root.join("neoenv.yaml"),
        "env:\n  PORT: '3000'\n  API_TOKEN: project-token\n",
    );
    write(&private.join("neoenv.yaml"), "env:\n  PORT: '4000'\n");
    write(&user, "env:\n  PORT: '2000'\n  REGION: west\n");
    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(
        &project,
        Some(&user),
        conventional_private_overlay(&root).as_deref(),
    )
    .unwrap();

    let resolved =
        resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();
    let document = resolved.inspection_document();
    let token = document
        .environment
        .iter()
        .find(|entry| entry.key == "API_TOKEN")
        .unwrap();

    assert_eq!(resolved.environment["PORT"].value, "4000");
    assert_eq!(document.sources.len(), 3);
    assert_eq!(token.value, "[redacted]");
    assert!(token.redacted);
}

/// A declared secret must survive *every* later source, however it re-declares
/// the key. There are three ways a later source can set a value — a plain `env`
/// entry, a `dotenv` file, and a `with:` override — and each one originally had
/// a path that wrote `secret: false` unconditionally, which is enough to print
/// a value the project declared secret.
#[test]
fn a_later_source_cannot_declassify_a_declared_secret() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let private = root.join("neoenv/private");
    let user = temp.path().join("user.yaml");
    fs::create_dir_all(&private).unwrap();
    // The secret arrives through the Go profile, where `KEY:VALUE` is a declared
    // secret. The private overlay then sets the same key plainly, and the user
    // file sets it again.
    write(
        &root.join("neoenv.yaml"),
        "env:\n  - name: API_TOKEN\n    value: project-token\n    secret: true\n  - PORT=3000\n",
    );
    write(
        &private.join("neoenv.yaml"),
        "env:\n  API_TOKEN: private-plain\n",
    );
    write(&user, "env:\n  API_TOKEN: user-plain\n");

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(
        &project,
        Some(&user),
        conventional_private_overlay(&root).as_deref(),
    )
    .unwrap();
    let resolved = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Go, None).unwrap();
    let document = resolved.inspection_document();
    let token = document
        .environment
        .iter()
        .find(|entry| entry.key == "API_TOKEN")
        .expect("the key survives the merge");

    // The *value* is the later one: last-wins is what a user expects, and the
    // fix is about redaction, not about refusing the override.
    assert_eq!(token.value, "[redacted]");
    assert!(token.redacted, "a later source declassified the value");
    let rendered = format!("{document:?}");
    assert!(
        !rendered.contains("user-plain") && !rendered.contains("private-plain"),
        "a secret value reached the inspection document: {rendered}"
    );
}

/// The same property through `dotenv`, which is the path a review found writing
/// `secret: false` into the same map that backs the inspection document.
#[test]
fn a_later_dotenv_cannot_declassify_a_declared_secret() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let private = root.join("neoenv/private");
    fs::create_dir_all(&private).unwrap();
    write(
        &root.join("neoenv.yaml"),
        "env:\n  - name: API_TOKEN\n    value: project-token\n    secret: true\n",
    );
    write(&private.join(".env"), "API_TOKEN=from-private-dotenv\n");
    write(&private.join("neoenv.yaml"), "dotenv: .env\n");

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(
        &project,
        None,
        conventional_private_overlay(&root).as_deref(),
    )
    .unwrap();
    let resolved = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Go, None).unwrap();
    let document = resolved.inspection_document();
    let token = document
        .environment
        .iter()
        .find(|entry| entry.key == "API_TOKEN")
        .expect("the key survives the merge");
    assert!(
        token.redacted && token.value == "[redacted]",
        "a dotenv source declassified the value: {token:?}"
    );
    let rendered = format!("{document:?}");
    assert!(
        !rendered.contains("from-private-dotenv"),
        "the dotenv value reached the inspection document: {rendered}"
    );
}

#[test]
fn dotenv_imports_preserve_quote_semantics_before_interpolation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    write(&root.join("neoenv.yaml"), "dotenv: .env\n");
    write(
        &root.join(".env"),
        "export NAME='Neo Env'\nMESSAGE=\"hello ${NAME}\"\nMULTILINE=`one\ntwo`\n",
    );
    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();

    let resolved =
        resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();

    assert_eq!(resolved.environment["NAME"].value, "Neo Env");
    assert_eq!(resolved.environment["MESSAGE"].value, "hello Neo Env");
    assert_eq!(resolved.environment["MULTILINE"].value, "one\ntwo");
}

/// A `dotenv:` or `paths:` filter must gate the *effect*, not just survive the
/// parse.
///
/// Every other test for this feature could pass with the filter carried into the
/// model and then ignored at resolution, which is the silent-drop shape this
/// codebase keeps finding. These go through `resolve_sources` and assert on the
/// environment and the PATH that come out the other side.
#[test]
fn a_dotenv_context_filter_gates_which_file_is_loaded() {
    for (yaml, context, expected) in [
        // No `contexts`: the default context only. A named context must not load
        // it, or a dev run inherits prod credentials.
        (
            "dotenv:\n  - path: .env.shared\n",
            None,
            Some("shared-value"),
        ),
        ("dotenv:\n  - path: .env.shared\n", Some("prod"), None),
        // Scoped to prod, and prod is the active context.
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("prod"),
            Some("prod-value"),
        ),
        // Scoped to prod, dev is active. Not loaded.
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("dev"),
            None,
        ),
        // A wildcard context applies wherever it is asked for.
        (
            "dotenv:\n  - path: .env.all\n    filter:\n      contexts: ['*']\n",
            Some("staging"),
            Some("all-value"),
        ),
        // **A `contexts` key that is present but names nothing loads nothing** --
        // in *any* context, including the default one. This is the row the previous
        // version of the code got backwards, and the reason is the one this whole
        // profile exists to prevent: dropping blank entries made the key
        // indistinguishable from an absent one, so `contexts: ['']` and
        // `contexts: ['prod ']` both became "the default context", and a
        // production-scoped `.env.prod` **loaded its production secrets in the
        // default context**. Before the blank-drop it loaded nowhere, which is the
        // safe direction: a filter naming a context this run does not have grants
        // nothing, and says so.
        //
        // The three spellings are the ways a user reaches it by hand. There is no
        // interpolation in this layer, so `${CTX}` is simply a name nothing can
        // select -- an earlier version of the config-crate test described it as an
        // unexpanded environment variable, which described a mechanism that does
        // not exist.
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: ['']\n",
            None,
            None,
        ),
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: ['${CTX}']\n",
            None,
            None,
        ),
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: ['prod ']\n",
            None,
            None,
        ),
        // And the padded row is *also* a miss in the other direction: `prod ` is
        // not a context anyone can type, because `validate_context` sees the
        // trimmed name. Loading `.env.prod` here would mean a typo silently
        // succeeded. It must load nothing under the default context too.
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: ['prod ']\n",
            Some("staging"),
            None,
        ),
        // The control for the padded case: the *trimmed* name does select, and the
        // trimmed spelling loads. Without this row the four above would also pass
        // if the filter were simply broken.
        (
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [' prod']\n",
            Some("prod"),
            Some("prod-value"),
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        write(&root.join(".env.shared"), "FROM_SHARED=shared-value\n");
        write(&root.join(".env.prod"), "FROM_PROD=prod-value\n");
        write(&root.join(".env.all"), "FROM_ALL=all-value\n");
        let config = if let Some(context) = context {
            format!("format_version: 1\ncontext: {context}\n{yaml}")
        } else {
            format!("format_version: 1\n{yaml}")
        };
        write(&root.join("neoenv.yaml"), &config);

        let project = discover(&root, None, None).unwrap().unwrap();
        let plan = select_sources(&project, None, None).unwrap();
        let resolved =
            resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();

        let loaded: Vec<&str> = ["FROM_SHARED", "FROM_PROD", "FROM_ALL"]
            .into_iter()
            .filter(|key| resolved.environment.contains_key(*key))
            .collect();
        match expected {
            Some(key) => assert_eq!(
                loaded.len(),
                1,
                "context {context:?} should load exactly {key}, loaded {loaded:?}"
            ),
            None => assert!(loaded.is_empty(), "context {context:?} loaded {loaded:?}"),
        }
    }
}

/// A `config.context` in the *same* document has to be known before that
/// document's `dotenv:` list is filtered.
///
/// The filter used to run first, so a file that set `config.context: prod` and
/// then scoped a dotenv to `prod` filtered against whatever the *previous* source
/// had established -- loading nothing, or loading the wrong file, with no
/// diagnostic.
#[test]
fn a_documents_own_context_applies_to_its_own_dotenv_filter() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    write(&root.join(".env.prod"), "FROM_PROD=prod-value\n");
    write(
        &root.join("neoenv.yaml"),
        "format_version: 1\ncontext: prod\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
    );

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let resolved =
        resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();

    assert_eq!(
        resolved
            .environment
            .get("FROM_PROD")
            .map(|entry| entry.value.as_str()),
        Some("prod-value"),
        "the document's own context must scope its own dotenv"
    );
}

/// A `paths:` OS filter must gate the directory, on the running platform.
#[test]
fn a_paths_os_filter_gates_the_directory_on_this_platform() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    let mine = root.join("mine");
    let theirs = root.join("theirs");
    fs::create_dir_all(&mine).unwrap();
    fs::create_dir_all(&theirs).unwrap();
    // One entry for this platform and one for a different one, plus a `*`.
    write(
        &root.join("neoenv.yaml"),
        &format!(
            "format_version: 1\npath:\n  - prepend: {mine}\n  - prepend: {theirs}\n    filter:\n      os: definitely-not-this-os\n  - prepend: {mine}/wild\n    filter:\n      os: '*'\n",
            mine = mine.display(),
            theirs = theirs.display(),
        ),
    );

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let resolved =
        resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();

    let values: Vec<&str> = resolved
        .path
        .iter()
        .map(|entry| entry.value.as_str())
        .collect();
    assert!(
        values.contains(&mine.to_str().unwrap()),
        "the unfiltered entry must apply: {values:?}"
    );
    assert!(
        values.contains(&format!("{}/wild", mine.display()).as_str()),
        "a `*` os must apply: {values:?}"
    );
    assert!(
        !values.contains(&theirs.to_str().unwrap()),
        "another platform's entry must not apply: {values:?}"
    );
}

/// The dotenv filter must see the same context the task resolver used, from
/// every source and at the documented precedence.
///
/// It used to see only the *document's* own `context:`. So
/// `nenv run build --context prod` selected the `prod` task while the filter saw
/// the empty string: a `contexts: [prod]` dotenv was not loaded, and an
/// *unfiltered* one was loaded regardless of the flag. The task that ran and the
/// environment it ran in came from two different worlds.
#[test]
fn the_dotenv_filter_sees_the_requested_context_from_every_source() {
    for (label, yaml, context_override, expected) in [
        (
            "no context anywhere",
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            None,
            false,
        ),
        (
            "the command line asks for it",
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("prod"),
            true,
        ),
        (
            "the command line asks for the default context",
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("default"),
            false,
        ),
        (
            "the document declares it",
            "context: prod\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            None,
            true,
        ),
        (
            "the document declares a different one",
            "context: dev\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            None,
            false,
        ),
        (
            "the command line beats the document, in both directions",
            "context: prod\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("default"),
            false,
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        write(&root.join(".env.prod"), "FROM_PROD=prod-value\n");
        write(
            &root.join("neoenv.yaml"),
            &format!(
                "format_version: 1\n{yaml}tasks:\n  build:\n    uses: portable\n    run: 'true'\n"
            ),
        );
        let project = discover(&root, None, None).unwrap().unwrap();
        let plan = select_sources(&project, None, None).unwrap();
        let resolved = resolve_sources(
            project,
            &plan,
            neoenv_config::ConfigProfile::Native,
            context_override,
        )
        .unwrap();
        assert_eq!(
            resolved.environment.contains_key("FROM_PROD"),
            expected,
            "{label}: the wrong dotenv loaded"
        );
    }
}

/// A context is trimmed, the way the reference trims it.
///
/// Untrimmed, `context: "prod "` matched no `contexts: [prod]`, and a context of
/// `"  "` was neither empty nor equal to `default`, so it skipped every
/// *unfiltered* dotenv — a whitespace-only value silently removed the project's
/// whole dotenv configuration.
#[test]
fn a_context_is_trimmed_and_a_blank_one_is_treated_as_unset() {
    // (label, yaml, command-line override, the key that must load)
    for (label, yaml, override_value, expected) in [
        (
            "whitespace on the document's own value",
            "context: 'prod '\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            None,
            "FROM_PROD",
        ),
        (
            "whitespace on the command line's value",
            "dotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some(" prod "),
            "FROM_PROD",
        ),
        (
            "a blank command line is unset, so the document's value applies",
            "context: prod\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\n",
            Some("   "),
            "FROM_PROD",
        ),
        (
            "a whitespace-only document value is unset, so an unfiltered dotenv loads",
            "context: '  '\ndotenv:\n  - path: .env.plain\n",
            None,
            "FROM_PLAIN",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        write(&root.join(".env.prod"), "FROM_PROD=prod-value\n");
        write(&root.join(".env.plain"), "FROM_PLAIN=plain-value\n");
        write(
            &root.join("neoenv.yaml"),
            &format!(
                "format_version: 1\n{yaml}tasks:\n  build:\n    uses: portable\n    run: 'true'\n"
            ),
        );
        let project = discover(&root, None, None).unwrap().unwrap();
        let plan = select_sources(&project, None, None).unwrap();
        let resolved = resolve_sources(
            project,
            &plan,
            neoenv_config::ConfigProfile::Native,
            override_value,
        )
        .unwrap();
        assert!(
            resolved.environment.contains_key(expected),
            "{label}: {expected} did not load, and neither did anything else ({:?})",
            resolved.environment.keys().collect::<Vec<_>>()
        );
    }
}

/// The `paths:` filter must see the same context the dotenv filter does.
///
/// It read the *document's* own value while the dotenv loop, one loop above, read
/// the effective one. So `nenv run build --context prod` loaded a
/// `contexts: [prod]` dotenv and dropped a `contexts: [prod]` PATH entry -- one
/// command, two worlds, and the identical bug the dotenv loop was fixed for in the
/// previous commit.
#[test]
fn a_paths_context_filter_sees_the_requested_context() {
    for (label, yaml, context_override, expected) in [
        (
            "no context anywhere",
            "path:\n  - prepend: mine\n    filter:\n      contexts: [prod]\n",
            None,
            false,
        ),
        (
            "the command line asks for it",
            "path:\n  - prepend: mine\n    filter:\n      contexts: [prod]\n",
            Some("prod"),
            true,
        ),
        (
            "the command line asks for the default context",
            "path:\n  - prepend: mine\n    filter:\n      contexts: [prod]\n",
            Some("default"),
            false,
        ),
        (
            "the document declares it",
            "context: prod\npath:\n  - prepend: mine\n    filter:\n      contexts: [prod]\n",
            None,
            true,
        ),
        (
            "the command line beats the document",
            "context: prod\npath:\n  - prepend: mine\n    filter:\n      contexts: [prod]\n",
            Some("default"),
            false,
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        write(
            &root.join("neoenv.yaml"),
            &format!(
                "format_version: 1\n{yaml}tasks:\n  build:\n    uses: portable\n    run: 'true'\n"
            ),
        );
        let project = discover(&root, None, None).unwrap().unwrap();
        let plan = select_sources(&project, None, None).unwrap();
        let resolved = resolve_sources(
            project,
            &plan,
            neoenv_config::ConfigProfile::Native,
            context_override,
        )
        .unwrap();
        // The *entries*, not just the count: a count assertion passes just as
        // happily when the wrong entry survives. The value is made absolute
        // against the project root on the way through, so the assertion is on the
        // tail -- which is still enough to catch a different directory winning.
        let values: Vec<&str> = resolved
            .path
            .iter()
            .map(|entry| entry.value.as_str())
            .collect();
        if expected {
            assert_eq!(
                values.len(),
                1,
                "{label}: expected exactly one entry, got {values:?}"
            );
        } else {
            assert!(values.is_empty(), "{label}: the filter kept {values:?}");
        }
        for value in &values {
            assert!(
                value.ends_with("mine"),
                "{label}: an entry survived that is not the one declared: {value}"
            );
        }
    }
}

/// A context a `paths:` entry declares is one the project *uses*.
///
/// `declared_contexts` was collected from dotenv filters only, so a project whose
/// only contextual declaration was on a PATH entry looked like it used no
/// contexts -- and `--context <typo>` was accepted silently, which is the #503
/// failure reopened through the other section.
#[test]
fn a_context_declared_only_by_a_paths_entry_counts_as_known() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    write(
        &root.join("neoenv.yaml"),
        "format_version: 1\npath:\n  - prepend: mine\n    filter:\n      contexts: [staging]\ntasks:\n  build:\n    uses: portable\n    run: 'true'\n",
    );
    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let resolved =
        resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None).unwrap();
    assert_eq!(
        resolved.declared_contexts,
        vec!["staging".to_owned()],
        "a PATH entry's contexts are declarations too"
    );
}

/// A padded context is recorded trimmed.
///
/// Untrimmed, `contexts: ['prod ']` made the context *unusable* -- the filter
/// compares exactly, so no entry ever matched -- and *untypable* at the same time,
/// because `validate_context` was then told the project uses a context literally
/// named `"prod "`. Both entry points that set a context already trimmed; the
/// collection loop this commit rewrote did not, so the asymmetry ended up inside
/// the one function that had just been made consistent.
#[test]
fn a_padded_declared_context_is_recorded_trimmed() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    write(
        &root.join("neoenv.yaml"),
        "format_version: 1\npath:\n  - prepend: mine\n    filter:\n      contexts: ['staging ']\n  - prepend: theirs\n    filter:\n      contexts: [' prod']\ntasks:\n  build:\n    uses: portable\n    run: 'true'\n",
    );
    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let resolved = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None)
        .expect("a padded context is a context");
    assert_eq!(
        resolved.declared_contexts,
        vec!["staging".to_owned(), "prod".to_owned()],
        "a padded context is recorded trimmed, so it is both loadable and typable"
    );
}

fn seed_tarball(root: &Path, digest: &str, files: &[(&str, &str)]) -> String {
    let url = "https://example.invalid/module.tar.gz";
    let cache = root.join(".neoenv/modules/tarballs").join(digest);
    let source = cache.join("source");
    fs::create_dir_all(&source).unwrap();
    write(
        &cache.join("metadata.toml"),
        &format!("url = {url:?}\nsha256 = {digest:?}\n"),
    );
    for (path, contents) in files {
        let destination = source.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        write(&destination, contents);
    }
    format!("{url}#sha256={digest}")
}

#[test]
fn a_tarball_module_cannot_declare_a_vault_or_replace_a_local_one() {
    let temp = TempDir::new().unwrap();
    let digest = "a".repeat(64);
    let import = seed_tarball(
        temp.path(),
        &digest,
        &[(
            "neoenv.yaml",
            "vaults:\n  work:\n    driver: keepass\n    path: remote.kdbx\n    secret: remote\n",
        )],
    );
    let root = temp.path().join("neoenv.yaml");
    write(
        &root,
        &format!("format_version: 1\nvaults:\n  work:\n    driver: age\nimports:\n  - {import}\n"),
    );

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let error = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None)
        .expect_err("a tarball vault declaration must be refused");
    assert_eq!(error.code, "NEO343");
}

#[test]
fn a_local_import_inside_a_tarball_stays_remote() {
    let temp = TempDir::new().unwrap();
    let digest = "b".repeat(64);
    let import = seed_tarball(
        temp.path(),
        &digest,
        &[
            ("neoenv.yaml", "imports:\n  - nested/neoenv.yaml\n"),
            ("nested/neoenv.yaml", "vaults:\n  work:\n    driver: age\n"),
        ],
    );
    let root = temp.path().join("neoenv.yaml");
    write(
        &root,
        &format!("format_version: 1\nimports:\n  - {import}\n"),
    );

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let error = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None)
        .expect_err("a local import inside remote content is still remote");
    assert_eq!(error.code, "NEO343");
}

#[test]
fn a_local_directory_that_looks_like_the_remote_cache_is_still_local() {
    let temp = TempDir::new().unwrap();
    let lookalike = temp.path().join(".neoenv/modules/commits/abc");
    fs::create_dir_all(&lookalike).unwrap();
    write(
        &lookalike.join("neoenv.yaml"),
        "vaults:\n  work:\n    driver: age\n",
    );
    let root = temp.path().join("neoenv.yaml");
    write(
        &root,
        "format_version: 1\nimports:\n  - .neoenv/modules/commits/abc/neoenv.yaml\n",
    );

    let project = discover(&root, None, None).unwrap().unwrap();
    let plan = select_sources(&project, None, None).unwrap();
    let resolved = resolve_sources(project, &plan, neoenv_config::ConfigProfile::Native, None)
        .expect("a local lookalike is local");
    assert_eq!(resolved.vaults["work"].provider_name(), "age");
}

#[test]
fn the_guard_refuses_a_remote_replacement_without_mutating_the_local_declaration() {
    use super::{SourceAccumulator, apply_project, refuse_remote_vault_declarations};

    let local = neoenv_config::parse_project(
        Path::new("/project/neoenv.yaml"),
        "vaults:\n  work:\n    driver: age\n",
    )
    .unwrap();
    let remote = neoenv_config::parse_project(
        Path::new("/project/.neoenv/modules/commits/abc/neoenv.yaml"),
        "vaults:\n  work:\n    driver: keepass\n    path: remote.kdbx\n    secret: remote\n",
    )
    .unwrap();
    let mut accumulated = SourceAccumulator::default();
    apply_project(&mut accumulated, local).unwrap();
    assert_eq!(
        accumulated.vaults["work"].source.path,
        "/project/neoenv.yaml"
    );

    let error = refuse_remote_vault_declarations(
        &neoenv_config::sources::ConfigSource::remote_module(PathBuf::from(
            "/project/.neoenv/modules/commits/abc/neoenv.yaml",
        )),
        &remote,
    )
    .unwrap_err();
    assert_eq!(error.code, "NEO343");
    // The local declaration is still the local one: the refusal happens before
    // the merge, so a remote module cannot replace it by declaring the same name.
    assert_eq!(accumulated.vaults.len(), 1);
    assert_eq!(accumulated.vaults["work"].provider_name(), "age");
    assert_eq!(
        accumulated.vaults["work"].source.path,
        "/project/neoenv.yaml"
    );
}
