//! `uses: tmpl` at the command boundary, driven by the fixtures the Go
//! reference's test corpus describes.
//!
//! The fixtures live in `fixtures/tmpl`; each test copies the ones it needs into
//! a temporary project so path containment and destination creation run against
//! a real project root.

use std::{fs, path::Path};

use tempfile::TempDir;

mod support;

fn fixtures() -> std::path::PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/nenv`; the shared fixture tree is two
    // levels up at `fixtures`.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tmpl")
}

fn copy_fixture(project: &Path, name: &str) {
    fs::copy(fixtures().join(name), project.join(name)).unwrap();
}

fn project(body: &str) -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("neoenv.yaml"), body).unwrap();
    directory
}

fn run_in(directory: &Path, arguments: &[&str]) -> std::process::Output {
    // The builder owns `NEOENV_CONFIG_HOME` so it can approve the fixture it is
    // pointed at. Everything else that could let a developer's own configuration
    // decide the assertion is removed.
    let mut command = support::TestCommand::new();
    for variable in [
        "NEOENV_PROJECT",
        "NEOENV_CONTEXT",
        "NEOENV_DATA_HOME",
        "NEOENV_CACHE_HOME",
        "NEOENV_STATE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
    ] {
        command.env_remove(variable);
    }
    command
        .current_dir(directory)
        .args(arguments)
        .output()
        .unwrap()
}

fn go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

#[test]
fn tmpl_renders_declared_mappings_values_env_and_go_os_arch() {
    let directory = project(
        "env:\n  SERVICE: api\ntasks:\n  render:\n    uses: tmpl\n    with:\n      files:\n        - app.yml.gotmpl:out/app.yml\n      values: values.yaml\n",
    );
    copy_fixture(directory.path(), "app.yml.gotmpl");
    copy_fixture(directory.path(), "values.yaml");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(output.status.success(), "{output:?}");
    let rendered = fs::read_to_string(directory.path().join("out/app.yml")).unwrap();
    assert_eq!(
        rendered,
        format!(
            "service: api\nreplicas: 3\nname: neo\nos: {}\narch: {}\n",
            go_os(),
            go_arch()
        )
    );
}

#[test]
fn tmpl_infers_the_destination_and_can_disable_go_template() {
    let directory = project(
        "tasks:\n  infer:\n    uses: tmpl\n    with:\n      files: [config.txt.tmpl]\n  plain:\n    uses: tmpl\n    with:\n      files: [disabled.txt.tmpl]\n      disable-gotmpl: true\n    env:\n      NAME: neo\n",
    );
    copy_fixture(directory.path(), "config.txt.tmpl");
    copy_fixture(directory.path(), "disabled.txt.tmpl");
    let output = run_in(directory.path(), &["run", "infer"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("config.txt")).unwrap(),
        format!("arch={}\n", go_arch())
    );

    let output = run_in(directory.path(), &["run", "plain"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("disabled.txt")).unwrap(),
        "hello neo {{ .Name }}\n"
    );
}

#[test]
fn tmpl_can_disable_env_expansion() {
    let directory = project(
        "tasks:\n  plain:\n    uses: tmpl\n    with:\n      files: [env.txt.tmpl]\n      disable-env: true\n    env:\n      NAME: neo\n",
    );
    copy_fixture(directory.path(), "env.txt.tmpl");
    let output = run_in(directory.path(), &["run", "plain"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("env.txt")).unwrap(),
        "name: ${NAME}\n"
    );
}

/// Command substitution is not a command here. It remains literal text, as in
/// the reference with command substitution disabled.
#[test]
fn tmpl_leaves_command_substitution_literal() {
    let directory = project(
        "env:\n  NAME: neo\ntasks:\n  inert:\n    uses: tmpl\n    with:\n      files: [inert.tmpl]\n",
    );
    copy_fixture(directory.path(), "inert.tmpl");
    let output = run_in(directory.path(), &["run", "inert"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("inert")).unwrap(),
        "literal $(not-a-command) `not-a-command` neo\n"
    );
}

/// A Go-template variable must survive env interpolation. The reference expands
/// the whole source before parsing, which would turn `{{ $item }}` into an empty
/// lookup; this checks the action is left intact while `${SERVICE}` outside it
/// still expands.
#[test]
fn tmpl_keeps_template_variables_out_of_env_interpolation() {
    let directory = project(
        "env:\n  SERVICE: api\ntasks:\n  render:\n    uses: tmpl\n    with:\n      files: [variable.tmpl]\n      values: values.yaml\n",
    );
    copy_fixture(directory.path(), "variable.tmpl");
    copy_fixture(directory.path(), "values.yaml");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("variable")).unwrap(),
        "name=neo service=api\n"
    );
}

#[test]
fn tmpl_rejects_a_large_integer_rather_than_rounding_it() {
    let directory = project(
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files: [config.txt.tmpl]\n      values: large-int.yaml\n",
    );
    copy_fixture(directory.path(), "config.txt.tmpl");
    copy_fixture(directory.path(), "large-int.yaml");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot be represented exactly"),
        "{stderr:?}"
    );
    assert!(!directory.path().join("config.txt").exists());
}

/// Every source is read and rendered before the first output is committed, so a
/// later missing file leaves no earlier file behind.
#[test]
fn tmpl_missing_later_source_writes_no_earlier_output() {
    let directory = project(
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files:\n        - config.txt.tmpl:early/out.txt\n        - missing.tmpl:late.txt\n",
    );
    copy_fixture(directory.path(), "config.txt.tmpl");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(!directory.path().join("early").exists());
    assert!(!directory.path().join("late.txt").exists());
}

#[test]
fn tmpl_requires_with_files() {
    let directory = project("tasks:\n  render:\n    uses: tmpl\n");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("with.files") || stderr.contains("tmpl"),
        "{stderr:?}"
    );
}

#[test]
fn tmpl_rejects_unknown_with_keys() {
    let directory =
        project("tasks:\n  render:\n    uses: tmpl\n    with:\n      file: [app.yml.gotmpl]\n");
    let output = run_in(directory.path(), &["validate"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("with.files"), "{stderr:?}");
}

#[test]
fn tmpl_rejects_source_destination_and_values_escapes() {
    let parent = TempDir::new().unwrap();
    let project = parent.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::write(parent.path().join("outside.tmpl"), "outside\n").unwrap();
    fs::write(parent.path().join("values.yaml"), "name: outside\n").unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "tasks:\n  source-escape:\n    uses: tmpl\n    with:\n      files: [../outside.tmpl]\n  dest-escape:\n    uses: tmpl\n    with:\n      files: [app.yml.gotmpl:../escaped.txt]\n  values-escape:\n    uses: tmpl\n    with:\n      files: [app.yml.gotmpl]\n      values: ../values.yaml\n",
    )
    .unwrap();
    copy_fixture(&project, "app.yml.gotmpl");

    for task in ["source-escape", "dest-escape", "values-escape"] {
        let output = run_in(&project, &["run", task]);
        assert!(!output.status.success(), "{task}: {output:?}");
    }
    assert!(
        !parent.path().join("escaped.txt").exists(),
        "an escaping destination must not be written"
    );
}

#[test]
fn tmpl_reports_a_missing_source_instead_of_creating_output() {
    let directory = project(
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files: [missing.tmpl:out.txt]\n",
    );
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(!directory.path().join("out.txt").exists());
}

#[test]
fn tmpl_reports_a_missing_values_file() {
    let directory = project(
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files: [app.yml.gotmpl]\n      values: missing.yaml\n",
    );
    copy_fixture(directory.path(), "app.yml.gotmpl");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
}

#[test]
fn templ_is_not_an_alias_because_the_reference_does_not_accept_it() {
    let directory =
        project("tasks:\n  render:\n    uses: templ\n    with:\n      files: [app.yml.gotmpl]\n");
    copy_fixture(directory.path(), "app.yml.gotmpl");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("with.files is only read by tmpl")
            || stderr.contains("unsupported local task runner: templ"),
        "{stderr:?}"
    );
}

#[test]
fn tmpl_url_spelling_is_accepted_without_fetching_anything() {
    let directory = project(
        "tasks:\n  render:\n    uses: tmpl://not-a-url\n    with:\n      files: [config.txt.tmpl]\n",
    );
    copy_fixture(directory.path(), "config.txt.tmpl");
    let output = run_in(directory.path(), &["run", "render"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("config.txt")).unwrap(),
        format!("arch={}\n", go_arch())
    );
}

/// A later destination that is a symlink fails before anything is published, so
/// an earlier valid mapping leaves no output behind.
#[cfg(unix)]
#[test]
fn tmpl_second_destination_symlink_writes_no_earlier_output() {
    use std::os::unix::fs::symlink;

    let parent = TempDir::new().unwrap();
    let project = parent.path().join("project");
    let outside = parent.path().join("outside");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, project.join("link")).unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files:\n        - config.txt.tmpl:first.txt\n        - config.txt.tmpl:link/second.txt\n",
    )
    .unwrap();
    copy_fixture(&project, "config.txt.tmpl");
    let output = run_in(&project, &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(!project.join("first.txt").exists());
    assert!(!outside.join("second.txt").exists());
}

/// A destination directory symlink is refused even when the target exists,
/// rather than creating the output through the link.
#[cfg(unix)]
#[test]
fn tmpl_refuses_a_symlinked_destination_directory() {
    use std::os::unix::fs::symlink;

    let parent = TempDir::new().unwrap();
    let project = parent.path().join("project");
    let outside = parent.path().join("outside");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, project.join("link")).unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "tasks:\n  render:\n    uses: tmpl\n    with:\n      files: [config.txt.tmpl:link/out.txt]\n",
    )
    .unwrap();
    copy_fixture(&project, "config.txt.tmpl");
    let output = run_in(&project, &["run", "render"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        !outside.join("out.txt").exists(),
        "nothing may be written through a destination symlink"
    );
}
