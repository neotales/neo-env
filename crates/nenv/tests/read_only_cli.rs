use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
};

#[cfg(unix)]
use std::{process::Stdio, time::Duration};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

mod support;

use std::sync::OnceLock;

/// One isolated config home for this test binary. Trust records are keyed by
/// canonical path, so every fixture can share it without crossing approvals.
fn config_home() -> &'static std::path::Path {
    static HOME: OnceLock<TempDir> = OnceLock::new();
    HOME.get_or_init(|| TempDir::new().unwrap()).path()
}

fn write_project(content: &str) -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("neoenv.yaml");
    fs::write(&path, content).unwrap();
    support::approve_tree(config_home(), directory.path());
    (directory, path)
}

fn shell_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn command() -> support::TestCommand {
    support::TestCommand::new()
}

#[test]
fn completion_scripts_are_static_and_do_not_require_a_project() {
    let directory = TempDir::new().unwrap();
    for shell in ["bash", "zsh", "fish", "powershell", "nushell"] {
        let output = command()
            .current_dir(directory.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .arg("completion")
            .arg(shell)
            .output()
            .unwrap();

        assert!(output.status.success(), "{shell}: {output:?}");
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(script.contains("task"));
        assert!(script.contains("format"));
        assert!(script.contains("locked"));
        assert!(script.contains("task complete"));
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn completion_rejects_unsupported_shells() {
    let output = command().arg("completion").arg("sh").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unsupported completion shell")
    );
}

#[test]
fn init_creates_a_toml_project_configuration_without_overwriting() {
    let directory = TempDir::new().unwrap();
    let first = command()
        .current_dir(directory.path())
        .arg("init")
        .output()
        .unwrap();

    assert!(first.status.success(), "{first:?}");
    let path = directory.path().join("neoenv.toml");
    assert_eq!(fs::read_to_string(&path).unwrap(), "format_version = 1\n");

    let second = command()
        .current_dir(directory.path())
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(3));
    assert!(
        String::from_utf8(second.stderr)
            .unwrap()
            .contains("nenv configuration already exists")
    );
    assert_eq!(fs::read_to_string(path).unwrap(), "format_version = 1\n");
}

#[test]
fn tool_which_without_a_lockfile_is_a_clean_not_found_result() {
    let (directory, project) = write_project("format_version: 1\n");
    let configuration_home = directory.path().join("configuration");
    let output = command()
        .current_dir(directory.path())
        .env("NEOENV_CONFIG_HOME", configuration_home)
        .env_remove("MISE_GLOBAL_CONFIG_FILE")
        .args(["tool", "which", "dotnet", project.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("installed executable not found: dotnet"));
    assert!(!error.contains("failed to read tool lockfile"));
}

#[test]
fn global_use_uses_system_scope_without_mise() {
    let (directory, _) = write_project("format_version: 1\n");
    let configuration_home = directory.path().join("configuration");
    let data_home = directory.path().join("data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    let output = command()
        .current_dir(directory.path())
        .env("NEOENV_CONFIG_HOME", &configuration_home)
        .env("NEOENV_DATA_HOME", &data_home)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .env_remove("MISE_GLOBAL_CONFIG_FILE")
        .env_remove("MISE_DATA_DIR")
        .args([
            "use",
            "--global",
            "--dry-run",
            "dotnet@10.0.401",
            "dotnet@9.0.308",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap().replace('\\', "/");
    assert!(
        text.contains(
            &system_install
                .join("tools")
                .display()
                .to_string()
                .replace('\\', "/")
        )
    );
    assert!(!text.contains(&data_home.display().to_string().replace('\\', "/")));
    assert!(!text.to_ascii_lowercase().contains("mise"));
    assert!(text.find("dotnet@10.0.401").unwrap() < text.find("dotnet@9.0.308").unwrap());
}

#[test]
fn tool_which_resolves_a_native_global_tool_without_a_project() {
    let directory = TempDir::new().unwrap();
    let configuration_home = directory.path().join("configuration");
    let data_home = directory.path().join("data");
    fs::create_dir_all(configuration_home.join("neoenv")).unwrap();
    fs::write(
        configuration_home.join("neoenv/neoenv.toml"),
        "format_version = 1\n[global.tools]\ndotnet = \"10.0.401\"\n",
    )
    .unwrap();
    let binary = if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    };
    let executable = data_home.join("neoenv/tools/dotnet/10.0.401").join(binary);
    fs::create_dir_all(executable.parent().unwrap()).unwrap();
    fs::write(&executable, "fixture").unwrap();

    let output = command()
        .current_dir(directory.path())
        .env("NEOENV_CONFIG_HOME", &configuration_home)
        .env("NEOENV_DATA_HOME", &data_home)
        .args(["tool", "which", "dotnet"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .replace('\\', "/")
            .ends_with(&format!("data/neoenv/tools/dotnet/10.0.401/{binary}\n"))
    );
}

#[test]
fn help_is_hierarchical_and_unknown_children_show_parent_help() {
    let root = command().arg("--help").output().unwrap();
    assert!(root.status.success(), "{root:?}");
    let root = String::from_utf8(root.stdout).unwrap();
    assert!(root.contains("Usage:\n  nenv [command] [options]"));
    assert!(root.contains("  task       Plan, describe, and run project tasks."));
    assert!(!root.contains("completion"));

    let task = command().args(["task", "use", "-h"]).output().unwrap();
    assert_eq!(task.status.code(), Some(2), "{task:?}");
    let task_help = String::from_utf8(task.stdout).unwrap();
    assert!(task_help.contains("nenv task\n"));
    assert!(task_help.contains("  run        Run a task after capability-policy checks."));
    assert!(!task_help.contains("nenv [command] [options]"));
    let diagnostic = String::from_utf8(task.stderr).unwrap();
    assert!(diagnostic.contains("unknown task subcommand: use"));
    assert!(diagnostic.contains("did you mean"));

    let run = command().args(["task", "run", "--help"]).output().unwrap();
    assert!(run.status.success(), "{run:?}");
    let run = String::from_utf8(run.stdout).unwrap();
    assert!(run.contains("nenv task run\n"));
    assert!(run.contains("--capability-policy <path>"));
}

#[test]
fn run_and_r_are_task_run_aliases_for_toml_projects() {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join("neoenv.toml"),
        "format_version = 1\n\n[tasks.build]\nuses = \"portable\"\nrun = \"whoami\"\n",
    )
    .unwrap();

    for arguments in [
        ["task", "run", "build"].as_slice(),
        ["run", "build"].as_slice(),
        ["r", "build"].as_slice(),
        ["build"].as_slice(),
    ] {
        let output = command()
            .current_dir(directory.path())
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("build Succeeded")
        );
    }
}

#[cfg(unix)]
#[test]
fn task_shortcuts_override_builtins_while_self_remains_available() {
    let directory = TempDir::new().unwrap();
    let marker = directory.path().join("task-init-ran");
    let configuration = directory.path().join("neoenv.yaml");
    fs::write(
        &configuration,
        format!(
            "tasks:\n  init:\n    id: init\n    uses: shell\n    run: touch {}\n    capabilities: [execute]\n",
            shell_path(&marker),
        ),
    )
    .unwrap();
    let policy = directory.path().join("capabilities.toml");
    let subject = format!(
        "project:{}/task:init",
        directory.path().canonicalize().unwrap().display(),
    );
    fs::write(
        &policy,
        format!("[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"),
    )
    .unwrap();

    let shortcut = command()
        .current_dir(directory.path())
        .env("NEOENV_CAPABILITY_POLICY", &policy)
        .arg("init")
        .output()
        .unwrap();
    assert!(shortcut.status.success(), "{shortcut:?}");
    assert!(marker.exists());

    let builtin = command()
        .current_dir(directory.path())
        .arg("self")
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(builtin.status.code(), Some(3));
    assert!(
        String::from_utf8(builtin.stderr)
            .unwrap()
            .contains("nenv configuration already exists")
    );
}

#[test]
fn checked_in_read_only_json_schemas_are_valid_json() {
    for (schema, version) in [
        (
            include_str!("../../../docs/schemas/inspection-v1.schema.json"),
            1,
        ),
        (
            include_str!("../../../docs/schemas/inspection-v2.schema.json"),
            2,
        ),
        (
            include_str!("../../../docs/schemas/validation-v1.schema.json"),
            1,
        ),
        (
            include_str!("../../../docs/schemas/workspace-list-v1.schema.json"),
            1,
        ),
        (
            include_str!("../../../docs/schemas/diagnostic-v1.schema.json"),
            1,
        ),
    ] {
        let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["properties"]["schema_version"]["const"], version);
    }
}

#[test]
fn json_diagnostics_use_a_versioned_envelope() {
    let output = command()
        .arg("inspect")
        .arg("missing-neoenv.yaml")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let document: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["diagnostic"]["category"], "not_found");
    assert_eq!(document["diagnostic"]["code"], "NEO201");
}

#[test]
fn the_workspace_list_document_matches_its_checked_in_schema() {
    let directory = write_workspace_fixture();
    let output = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/workspace-list-v1.schema.json"
    ))
    .unwrap();

    // The schema pins the top-level shape, so an added or renamed field fails
    // here rather than silently changing an advertised stable document.
    assert_eq!(
        document["schema_version"],
        schema["properties"]["schema_version"]["const"]
    );
    let members = &schema["properties"]["members"]["items"];
    let mut required = members["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect::<Vec<_>>();
    required.sort_unstable();
    for member in document["members"].as_array().unwrap() {
        let object = member.as_object().unwrap();
        let mut emitted = object.keys().map(String::as_str).collect::<Vec<_>>();
        emitted.sort_unstable();
        assert_eq!(emitted, required, "member fields drifted from the schema");
    }
}

#[test]
fn output_contract_keeps_text_json_and_diagnostics_on_their_own_streams() {
    let (directory, path) =
        write_project("tasks:\n  check:\n    uses: portable\n    run: 'true'\n");

    let text = command()
        .env("NO_COLOR", "1")
        .arg("task")
        .arg("list")
        .arg(&path)
        .output()
        .unwrap();
    assert!(text.status.success(), "{text:?}");
    assert_eq!(text.stdout, b"check\n");
    assert!(text.stderr.is_empty());
    assert!(
        !text.stdout.contains(&0x1b),
        "text output must not contain ANSI"
    );

    let json = command()
        .arg("task")
        .arg("list")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(json.status.success(), "{json:?}");
    assert!(json.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["tasks"], serde_json::json!(["check"]));

    let failure = command()
        .arg("inspect")
        .arg(directory.path().join("missing.toml"))
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert_eq!(failure.status.code(), Some(4));
    assert!(failure.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&failure.stderr).unwrap();
    assert_eq!(diagnostic["schema_version"], 1);
    assert_eq!(diagnostic["diagnostic"]["category"], "not_found");
}

#[test]
fn hidden_task_completion_endpoint_is_machine_safe_when_json_is_requested() {
    let (directory, _) = write_project("tasks:\n  check:\n    uses: portable\n    run: 'true'\n");
    let output = command()
        .current_dir(directory.path())
        .arg("task")
        .arg("complete")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["candidates"], serde_json::json!(["check"]));
}

fn serve_once(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });
    format!("http://{address}/tool")
}

#[test]
fn validate_accepts_an_explicit_project_file() {
    let (_directory, path) = write_project("env:\n  NAME: neoenv\n");

    let output = command().arg("validate").arg(&path).output().unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("valid: ")
    );
}

#[test]
fn validate_rejects_incomplete_or_unsafe_map_task_actions() {
    for content in [
        "tasks:\n  check:\n    uses: shell\n",
        "tasks:\n  check:\n    uses: shell\n    run: echo\n    env:\n      BAD-KEY: value\n",
        "tasks:\n  check:\n    uses: shell\n    run: echo\n    env:\n      VALUE: '$(whoami)'\n",
    ] {
        let (_directory, path) = write_project(content);
        let output = command().arg("validate").arg(path).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
    }
}

#[test]
fn validate_accepts_deferred_runner_contracts_for_fail_closed_runtime_resolution() {
    for runner in ["language", "docker", "project"] {
        let (_directory, path) = write_project(&format!(
            "tasks:\n  check:\n    uses: {runner}\n    run: entry\n"
        ));
        let output = command().arg("validate").arg(path).output().unwrap();
        assert!(output.status.success(), "{runner}: {output:?}");
    }
}

#[test]
fn task_capability_denial_is_a_trust_error_with_policy_provenance() {
    let (directory, path) = write_project(
        "tasks:\n  build:\n    uses: portable\n    run: 'true'\n    capabilities: [execute]\n",
    );
    let policy = directory.path().join("capabilities.toml");

    let output = command()
        .arg("task")
        .arg("run")
        .arg("build")
        .arg(&path)
        .arg("--capability-policy")
        .arg(&policy)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&format!("{}:1:1", policy.display())));
    assert!(stderr.contains("requested capability execute is not granted"));
}

#[test]
fn task_environment_interpolates_and_handoffs_require_declared_outputs() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("neoenv.yaml");
    fs::write(&path, format!(
        "env:\n  BASE: project\ntasks:\n  produce:\n    uses: shell\n    run: 'printf \"artifact=result\\n\" > \"$NEOENV_OUTPUTS\"'\n    outputs:\n      artifact: result\n  consume:\n    uses: shell\n    run: 'test \"$MESSAGE\" = project-task && test \"$NEOENV_OUTPUT_artifact\" = result && touch {}'\n    env:\n      MESSAGE: ${{BASE}}-task\n    needs: produce\n",
        shell_path(&directory.path().join("handoff-marker")),
    )).unwrap();
    let output = command()
        .arg("task")
        .arg("run")
        .arg("consume")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(directory.path().join("handoff-marker").exists());

    fs::write(
        &path,
        "tasks:\n  produce:\n    uses: shell\n    run: 'printf \"unexpected=value\\n\" > \"$NEOENV_OUTPUTS\"'\n",
    )
    .unwrap();
    let output = command()
        .arg("task")
        .arg("run")
        .arg("produce")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("task output was not declared")
    );
}

#[test]
fn dotenv_rejects_invalid_environment_keys_with_the_dotenv_location() {
    let (directory, path) = write_project("dotenv: local.env\n");
    let dotenv = directory.path().join("local.env");
    fs::write(&dotenv, "BAD-KEY=value\n").unwrap();

    let output = command().arg("validate").arg(&path).output().unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid environment key: BAD-KEY"));
    assert!(stderr.contains(&dotenv.display().to_string()) || stderr.contains("local.env"));
}

#[test]
fn untrusted_remote_imports_use_the_trust_exit_category() {
    let (directory, path) = write_project("imports: [github:octo/repo@tag:v1.2.3]\n");
    let config = TempDir::new().unwrap();

    let output = command()
        .env("XDG_CONFIG_HOME", config.path())
        .arg("inspect")
        .arg(&path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(5));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("remote repository is not trusted")
    );
    drop(directory);
}

#[test]
#[allow(clippy::too_many_lines)]
fn trusted_cached_remote_modules_compose_without_network_access() {
    let (directory, path) = write_project(
        "imports: \"github:octo/repo@tag:v1.2.3//module.yaml\"\nenv:\n  PROJECT: local\n",
    );
    let parsed = neoenv_config::parse_project(&path, &fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        parsed.imports[0].from,
        "github:octo/repo@tag:v1.2.3//module.yaml"
    );
    let config = TempDir::new().unwrap();
    let policy = config.path().join("neoenv");
    fs::create_dir(&policy).unwrap();
    fs::write(
        policy.join("trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();

    let repository = "github.com/octo/repo";
    let source = directory.path().join("remote-source");
    fs::create_dir(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    let marker = directory.path().join("remote-task-ran");
    fs::write(
        source.join("module.yaml"),
        format!(
            "env:\n  MODULE: remote\ntasks:\n  remote:\n    uses: shell\n    run: 'touch {}'\n",
            marker.display()
        ),
    )
    .unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let repository_key = format!("{:x}", Sha256::digest(repository));
    let cache = directory
        .path()
        .join(".neoenv/modules/commits")
        .join(repository_key)
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();
    let tag_key = format!("{:x}", Sha256::digest("github.com/octo/repo@tag:v1.2.3"));
    let tags = directory.path().join(".neoenv/modules/tags");
    fs::create_dir_all(&tags).unwrap();
    fs::write(
        tags.join(format!("{tag_key}.toml")),
        format!(
            "canonical = \"github.com/octo/repo@tag:v1.2.3//module.yaml\"\ncommit = {commit:?}\n"
        ),
    )
    .unwrap();

    let output = command()
        .env("XDG_CONFIG_HOME", config.path())
        .arg("inspect")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["environment"][0]["key"], "MODULE");
    assert_eq!(document["environment"][0]["value"], "remote");
    assert!(
        document["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["path"].as_str().unwrap().ends_with("module.yaml"))
    );

    let denied = command()
        .env("XDG_CONFIG_HOME", config.path())
        .arg("task")
        .arg("run")
        .arg("remote")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(5));
    assert!(!marker.exists());

    let subject = format!(
        "project:{}/task:remote",
        directory.path().canonicalize().unwrap().display()
    );
    fs::write(
        policy.join("capabilities.toml"),
        format!("[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"),
    )
    .unwrap();
    let allowed = command()
        .env("XDG_CONFIG_HOME", config.path())
        .arg("task")
        .arg("run")
        .arg("remote")
        .arg(&path)
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{allowed:?}");
    assert_eq!(
        String::from_utf8(allowed.stdout).unwrap(),
        "remote Planned\n"
    );
    assert!(!marker.exists());
}

#[test]
fn inspect_discovers_a_project_and_redacts_default_sensitive_values() {
    let (directory, _) = write_project("env:\n  NAME: neoenv\n  API_TOKEN: do-not-print\n");

    let output = command()
        .current_dir(directory.path())
        .env_remove("NEOENV_PROJECT")
        .env_remove("XDG_CONFIG_HOME")
        .arg("inspect")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema_version"], 2);
    assert_eq!(document["environment"][1]["value"], "[redacted]");
    assert_eq!(document["environment"][1]["redacted"], true);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("do-not-print")
    );
}

#[test]
fn inspect_reports_not_found_for_a_directory_without_configuration() {
    let directory = TempDir::new().unwrap();

    let output = command()
        .current_dir(directory.path())
        .env_remove("NEOENV_PROJECT")
        .arg("inspect")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no nenv configuration found")
    );
}

#[test]
fn compact_neoenv_projects_validate_and_inspect_without_module_loading() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join(".neoenv");
    fs::write(&path, "APP_NAME=neoenv\n").unwrap();

    let validate = command().arg("validate").arg(&path).output().unwrap();
    let inspect = command()
        .arg("inspect")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(validate.status.success());
    assert!(inspect.status.success());
    let document: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(document["environment"][0]["key"], "APP_NAME");
    assert_eq!(document["environment"][0]["value"], "neoenv");
}

#[test]
fn environment_extensions_interpolate_import_dotenv_and_apply_to_tasks_and_shells() {
    let (directory, path) = write_project(
        "dotenv: local.env\npath:\n  - prepend: bin\n  - append: tools/bin\nenv:\n  BASE: project\n  MESSAGE: ${BASE}-message\ntasks:\n  check:\n    uses: shell\n    run: 'test \"$FROM_DOTENV\" = loaded && test \"$MESSAGE\" = project-message'\n",
    );
    fs::write(directory.path().join("local.env"), "FROM_DOTENV=loaded\n").unwrap();

    let inspect = command()
        .arg("inspect")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let document: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(
        document["environment"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key"] == "MESSAGE")
            .unwrap()["value"],
        "project-message"
    );
    assert_eq!(document["path"][0]["operation"], "prepend");
    assert!(std::path::Path::new(document["path"][0]["value"].as_str().unwrap()).ends_with("bin"));
    assert!(
        std::path::Path::new(document["path"][1]["value"].as_str().unwrap()).ends_with("tools/bin")
    );

    let task = command()
        .current_dir(directory.path())
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&path)
        .output()
        .unwrap();
    assert!(task.status.success());
    let shell = command()
        .arg("shell")
        .arg("activate")
        .arg("bash")
        .arg(&path)
        .output()
        .unwrap();
    assert!(shell.status.success());
    assert!(String::from_utf8(shell.stdout).unwrap().contains("PATH"));
}

#[test]
fn dotenv_diagnostics_distinguish_required_and_optional_files_and_layers_interpolate_in_order() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config/neoenv");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("neoenv.yaml"), "env:\n  BASE: user\n").unwrap();
    let project = directory.path().join("neoenv.yaml");
    fs::write(&project, "env:\n  MESSAGE: ${BASE}-project\n").unwrap();
    let inspect = command()
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .arg("inspect")
        .arg(&project)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let document: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(
        document["environment"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key"] == "MESSAGE")
            .unwrap()["value"],
        "user-project"
    );

    fs::write(&project, "dotenv: missing.env\n").unwrap();
    let required = command().arg("validate").arg(&project).output().unwrap();
    assert_eq!(required.status.code(), Some(3));
    assert!(
        String::from_utf8(required.stderr)
            .unwrap()
            .contains("required dotenv file")
    );
    fs::write(
        &project,
        "dotenv: [{ path: missing.env, required: false }]\n",
    )
    .unwrap();
    assert!(
        command()
            .arg("validate")
            .arg(&project)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn task_dotenv_is_source_relative_optional_or_required_and_precedes_task_env() {
    let directory = TempDir::new().unwrap();
    let task_directory = directory.path().join("task");
    fs::create_dir_all(&task_directory).unwrap();
    let project = task_directory.join("neoenv.yaml");
    fs::write(
        &project,
        "env:\n  VALUE: project\ntasks:\n  check:\n    uses: shell\n    run: 'test \"$FROM_TASK\" = dotenv && test \"$VALUE\" = dotenv-task'\n    dotenv: task.env\n    env:\n      VALUE: ${FROM_TASK}-task\n",
    )
    .unwrap();
    fs::write(
        task_directory.join("task.env"),
        "FROM_TASK=dotenv\nVALUE=dotenv\n",
    )
    .unwrap();

    assert!(
        command()
            .arg("task")
            .arg("run")
            .arg("check")
            .arg(&project)
            .status()
            .unwrap()
            .success()
    );

    fs::remove_file(task_directory.join("task.env")).unwrap();
    let required = command()
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&project)
        .output()
        .unwrap();
    assert!(!required.status.success());
    assert!(
        String::from_utf8(required.stderr)
            .unwrap()
            .contains("required dotenv file")
    );

    fs::write(
        &project,
        "tasks:\n  check:\n    uses: shell\n    run: 'true'\n    dotenv: [{ path: missing.env, required: false }]\n",
    )
    .unwrap();
    assert!(
        command()
            .arg("task")
            .arg("run")
            .arg("check")
            .arg(&project)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn user_module_and_project_sources_apply_in_documented_order() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config/neoenv");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("neoenv.yaml"), "env:\n  BASE: user\n").unwrap();
    fs::write(
        directory.path().join("module.yaml"),
        "env:\n  VALUE: ${BASE}-module\n",
    )
    .unwrap();
    let project = directory.path().join("neoenv.yaml");
    fs::write(
        &project,
        "imports: [module.yaml]\nenv:\n  VALUE: ${VALUE}-project\n",
    )
    .unwrap();

    let output = command()
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .arg("inspect")
        .arg(&project)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let value = document["environment"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "VALUE")
        .unwrap();
    assert_eq!(value["value"], "user-module-project");
    let reported_path = std::path::Path::new(value["source"]["path"].as_str().unwrap());
    assert_eq!(
        reported_path.canonicalize().unwrap(),
        project.canonicalize().unwrap()
    );
}

#[test]
fn command_substitution_is_rejected_by_the_compiled_binary() {
    let (_directory, path) = write_project("env:\n  VALUE: '$(whoami)'\n");
    let output = command().arg("validate").arg(path).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("command substitution")
    );
}

#[test]
fn shell_activation_renders_escaped_composed_environment() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/modules/local/neoenv.yaml");
    let output = command()
        .arg("shell")
        .arg("activate")
        .arg("bash")
        .arg(&fixture)
        .output()
        .unwrap();

    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(output.contains("export MODULE_VALUE='project'"));
    assert!(output.contains("export SHELL_VALUE='a'\"'\"'not-executed'"));
}

#[test]
fn inspect_composes_local_modules_in_order_and_reports_provenance() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/modules/local/neoenv.yaml");
    let output = command()
        .arg("inspect")
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["environment"][0]["value"], "project");
    assert_eq!(document["sources"][0]["kind"], "module");
    assert_eq!(document["sources"][1]["kind"], "module");
    assert_eq!(document["sources"][2]["kind"], "project");
}

#[test]
fn remote_modules_fail_closed_without_fetching_or_executing() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("remote-module-must-not-run");
    let pinned = "0123456789abcdef0123456789abcdef01234567";
    let isolated_config = directory.path().join("config");
    for import in [
        format!("github:octo/example@{pinned}//modules"),
        "github:octo/example@main//modules".into(),
        format!("github:octo/example@{pinned}//../modules"),
    ] {
        fs::write(
            &path,
            format!(
                "imports: [{import:?}]\ntasks:\n  run:\n    run: touch {}\n",
                marker.display()
            ),
        )
        .unwrap();
        let output = command()
            .env("XDG_CONFIG_HOME", &isolated_config)
            .arg("inspect")
            .arg(&path)
            .output()
            .unwrap();
        let expected = if import.contains("@main") || import.contains("../") {
            Some(3)
        } else {
            Some(5)
        };
        assert_eq!(output.status.code(), expected);
        assert!(String::from_utf8(output.stderr).unwrap().contains("remote"));
        assert!(!marker.exists());
        assert!(!directory.path().join(".neoenv/modules").exists());
    }
}

#[test]
fn remote_inspect_accepts_exact_tags_without_fetching() {
    let directory = TempDir::new().unwrap();
    let source = "github:octo/example@tag:v1.2.3//modules";

    let output = command()
        .current_dir(directory.path())
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .arg("remote")
        .arg("inspect")
        .arg(source)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("github.com/octo/example@tag:v1.2.3//modules")
    );
    assert!(!directory.path().join(".neoenv/modules").exists());
}

#[test]
fn task_commands_resolve_context_render_help_and_never_execute_actions() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("task-action-must-not-run");
    fs::write(&path, format!(
        "context: dev\ntasks:\n  base:\n    template: true\n    inputs:\n      release: boolean\n  build:\n    extends: base\n    uses: shell\n    run: touch {}\n    help: Build safely.\n  build:prod:\n    extends: build\n    run: touch {}-prod\n  test:\n    uses: shell\n    run: touch {}-test\n    needs: build\n",
        marker.display(), marker.display(), marker.display()
    )).unwrap();

    let list = command()
        .arg("task")
        .arg("list")
        .arg(&path)
        .output()
        .unwrap();
    assert!(list.status.success());
    assert_eq!(
        String::from_utf8(list.stdout).unwrap(),
        "base\nbuild\nbuild:prod\ntest\n"
    );

    let help = command()
        .arg("task")
        .arg("help")
        .arg("build")
        .arg(&path)
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("Task: build"));
    assert!(help.contains("Build safely."));
    assert!(help.contains("release (static)"));
    assert!(help.contains("Boolean"));

    let plan = command()
        .arg("task")
        .arg("plan")
        .arg("test")
        .arg(&path)
        .env("NEOENV_CONTEXT", "dev")
        .arg("--context")
        .arg("prod")
        .output()
        .unwrap();
    assert!(plan.status.success());
    assert_eq!(
        String::from_utf8(plan.stdout).unwrap(),
        "build:prod Planned\ntest Planned\n"
    );
    assert!(!marker.exists());
    assert!(
        !marker
            .with_file_name("task-action-must-not-run-prod")
            .exists()
    );
    assert!(
        !marker
            .with_file_name("task-action-must-not-run-test")
            .exists()
    );

    let environment_plan = command()
        .arg("task")
        .arg("plan")
        .arg("build")
        .arg(&path)
        .env("NEOENV_CONTEXT", "prod")
        .output()
        .unwrap();
    assert!(environment_plan.status.success());
    assert_eq!(
        String::from_utf8(environment_plan.stdout).unwrap(),
        "build:prod Planned\n"
    );
}

#[test]
fn task_routes_explicit_workspace_aliases_to_declared_members_with_member_context() {
    let directory = TempDir::new().unwrap();
    let member = directory.path().join("apps/frontend");
    fs::create_dir_all(&member).unwrap();
    fs::write(
        directory.path().join("neoenv.yaml"),
        "workspace:\n  members: [apps/frontend]\n  aliases:\n    web: apps/frontend\n    frontend: web\n",
    )
    .unwrap();
    fs::write(
        member.join("neoenv.yaml"),
        "context: prod\ntasks:\n  build:\n    uses: portable\n    run: 'true'\n  build:prod:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();

    let output = command()
        .current_dir(directory.path())
        .env_remove("NEOENV_PROJECT")
        .env_remove("XDG_CONFIG_HOME")
        .arg("task")
        .arg("plan")
        .arg("build")
        .arg("frontend")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "build:prod Planned\n"
    );
    assert!(!directory.path().join(".neoenv/modules").exists());
}

#[test]
fn task_plan_reports_dependency_cycles_without_execution() {
    let (_directory, path) = write_project(
        "tasks:\n  first:\n    uses: shell\n    run: 'false'\n    needs: second\n  second:\n    uses: shell\n    run: 'false'\n    needs: first\n",
    );
    let output = command()
        .arg("task")
        .arg("plan")
        .arg("first")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("first -> second -> first")
    );
}

#[test]
fn task_run_passes_literal_arguments_to_an_explicit_argv_runner() {
    let (directory, path) = write_project(
        "tasks:\n  check:\n    uses: argv\n    run: sh\n    args: [-c, 'test \"$0\" = \"--flag\" && test \"$1\" = \"value\"']\n",
    );

    let output = command()
        .current_dir(directory.path())
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&path)
        .arg("--")
        .arg("--flag")
        .arg("value")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "check Succeeded\n"
    );
}

#[test]
fn task_inputs_bind_positions_options_repetition_and_help_for_every_entry_point() {
    for (filename, content) in [
        (
            "neoenv.yaml",
            "tasks:\n  build:\n    uses: argv\n    run: sh\n    args:\n      - -c\n      - 'test \"$NEOENV_INPUT_target\" = \"héllo world\" && test \"$NEOENV_INPUT_release\" = true && test \"$NEOENV_INPUT_count\" = 2 && test \"$NEOENV_INPUT_tag\" = \"[\\\"one\\\",\\\"two\\\"]\" && test \"$0\" = --literal'\n    with: { target: fallback }\n    inputs:\n      target: { type: string, position: 0, required: true }\n      release: { type: boolean, long: release, short: r, default: false }\n      count: { type: integer, long: count, short: c }\n      tag: { type: string, long: tag, repeatable: true }\n",
        ),
        (
            "neoenv.toml",
            "[tasks.build]\nuses = 'argv'\nrun = 'sh'\nargs = ['-c', 'test \"$NEOENV_INPUT_target\" = \"héllo world\" && test \"$NEOENV_INPUT_release\" = true && test \"$NEOENV_INPUT_count\" = 2 && test \"$NEOENV_INPUT_tag\" = \"[\\\"one\\\",\\\"two\\\"]\" && test \"$0\" = --literal']\n[tasks.build.with]\ntarget = 'fallback'\n[tasks.build.inputs.target]\ntype = 'string'\nposition = 0\nrequired = true\n[tasks.build.inputs.release]\ntype = 'boolean'\nlong = 'release'\nshort = 'r'\ndefault = false\n[tasks.build.inputs.count]\ntype = 'integer'\nlong = 'count'\nshort = 'c'\n[tasks.build.inputs.tag]\ntype = 'string'\nlong = 'tag'\nrepeatable = true\n",
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(filename);
        fs::write(&path, content).unwrap();
        for entry in [
            vec![
                "build",
                "héllo world",
                "-r",
                "--count",
                "02",
                "--tag=one",
                "--tag",
                "two",
                "--",
                "--literal",
            ],
            vec![
                "run",
                "build",
                "héllo world",
                "--release",
                "-c",
                "2",
                "--tag",
                "one",
                "--tag",
                "two",
                "--",
                "--literal",
            ],
            vec![
                "r",
                "build",
                "héllo world",
                "-r",
                "--count=2",
                "--tag",
                "one",
                "--tag=two",
                "--",
                "--literal",
            ],
            vec![
                "task",
                "run",
                "build",
                "héllo world",
                "--release",
                "--count",
                "2",
                "--tag=one",
                "--tag",
                "two",
                "--",
                "--literal",
            ],
        ] {
            let output = command()
                .current_dir(directory.path())
                .args(&entry)
                .output()
                .unwrap();
            assert!(output.status.success(), "{filename} {entry:?}: {output:?}");
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                "build Succeeded\n"
            );
        }
        for entry in [
            vec!["build", "-h"],
            vec!["run", "build", "-h"],
            vec!["r", "build", "-h"],
            vec!["task", "run", "build", "-h"],
        ] {
            let output = command()
                .current_dir(directory.path())
                .args(&entry)
                .output()
                .unwrap();
            assert!(output.status.success(), "{filename} {entry:?}: {output:?}");
            let help = String::from_utf8(output.stdout).unwrap();
            assert!(help.contains("Usage:"));
            assert!(help.contains("--release"));
            assert!(help.contains("<target>"));
        }
    }
}

#[test]
fn task_input_diagnostics_reject_unknown_duplicate_missing_and_mistyped_values() {
    let (directory, path) = write_project(
        "tasks:\n  build:\n    uses: portable\n    run: 'true'\n    inputs:\n      target: { type: string, position: 0, required: true }\n      count: { type: integer, long: count }\n      release: { type: boolean, long: release }\n",
    );
    for (arguments, expected) in [
        (
            vec!["build", "--unknown"],
            "does not define option --unknown",
        ),
        (
            vec!["build", "target", "--count", "one"],
            "input count has an invalid value",
        ),
        (
            vec!["build", "target", "--release", "--release"],
            "input release was provided more than once",
        ),
        (vec!["build"], "requires input target"),
    ] {
        let output = command()
            .current_dir(directory.path())
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{arguments:?}: {output:?}"
        );
    }
    assert!(path.exists());
}

#[test]
fn task_completion_candidates_read_configuration_without_executing_actions() {
    let (directory, path) = write_project(
        "tasks:\n  build:\n    uses: shell\n    run: 'touch should-not-run'\n    inputs:\n      release: { type: boolean, long: release, short: r }\n      count: { type: integer, long: count }\n",
    );
    let tasks = command()
        .current_dir(directory.path())
        .args(["task", "complete"])
        .output()
        .unwrap();
    assert!(tasks.status.success(), "{tasks:?}");
    assert_eq!(String::from_utf8(tasks.stdout).unwrap(), "build\n");
    let options = command()
        .current_dir(directory.path())
        .args(["task", "complete", "build"])
        .output()
        .unwrap();
    assert!(options.status.success(), "{options:?}");
    assert_eq!(
        String::from_utf8(options.stdout).unwrap(),
        "--release\n--no-release\n-r\n--count\n--\n"
    );
    assert!(!directory.path().join("should-not-run").exists());
    assert!(path.exists());
}

#[test]
fn scalar_tasks_use_the_portable_runner_in_yaml_and_toml() {
    for (filename, content) in [
        (
            "neoenv.yaml",
            "tasks:\n  check: 'test -f {marker} && touch {marker}-ran'\n",
        ),
        (
            "neoenv.toml",
            "[tasks]\ncheck = 'test -f {marker} && touch {marker}-ran'\n",
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(filename);
        let marker = directory.path().join("scalar-marker");
        fs::write(&marker, "").unwrap();
        fs::write(&path, content.replace("{marker}", &shell_path(&marker))).unwrap();

        let help = command()
            .arg("task")
            .arg("help")
            .arg("check")
            .arg(&path)
            .output()
            .unwrap();
        let plan = command()
            .arg("task")
            .arg("plan")
            .arg("check")
            .arg(&path)
            .output()
            .unwrap();

        assert!(help.status.success(), "{filename}: {help:?}");
        assert!(
            String::from_utf8(help.stdout)
                .unwrap()
                .contains("Uses: exec")
        );
        assert!(plan.status.success(), "{filename}: {plan:?}");
        assert!(!marker.with_file_name("scalar-marker-ran").exists());

        let run = command()
            .arg("task")
            .arg("run")
            .arg("check")
            .arg(&path)
            .output()
            .unwrap();

        assert!(run.status.success(), "{filename}: {run:?}");
        assert_eq!(String::from_utf8(run.stdout).unwrap(), "check Succeeded\n");
        assert!(marker.with_file_name("scalar-marker-ran").exists());
    }
}

#[test]
fn task_predicate_fixture_reports_skip_and_force_outcomes() {
    let (directory, path) = write_project(include_str!(
        "../../../fixtures/config/v1/task-predicates.yaml"
    ));

    let skip = command()
        .current_dir(directory.path())
        .arg("task")
        .arg("run")
        .arg("skip")
        .arg(&path)
        .output()
        .unwrap();
    assert!(skip.status.success());
    assert_eq!(String::from_utf8(skip.stdout).unwrap(), "skip Skipped\n");

    let forced = command()
        .current_dir(directory.path())
        .arg("task")
        .arg("run")
        .arg("forced")
        .arg(&path)
        .output()
        .unwrap();
    assert!(forced.status.success());
    assert_eq!(
        String::from_utf8(forced.stdout).unwrap(),
        "forced Succeeded\n"
    );
}

#[test]
fn task_predicates_use_context_inputs_prior_outcomes_and_public_outputs() {
    for (filename, contents) in [
        (
            "neoenv.yaml",
            "tasks:\n  produce:\n    uses: shell\n    run: 'printf \"ARTIFACT=dist/app.zip\\n\" > \"$NEOENV_OUTPUTS\"'\n    outputs:\n      ARTIFACT: published archive\n  consume:\n    needs: produce\n    uses: argv\n    run: 'true'\n    if: context == release && input.target == win-x64 && outcome.produce == succeeded && output.ARTIFACT == dist/app.zip\n    inputs:\n      target: { type: string, position: 0, required: true }\n  prepare:\n    uses: argv\n    run: 'false'\n  cleanup:\n    needs: prepare\n    uses: argv\n    run: 'true'\n    force: outcome.prepare == failed\n",
        ),
        (
            "neoenv.toml",
            "[tasks.produce]\nuses = 'shell'\nrun = 'printf \"ARTIFACT=dist/app.zip\\n\" > \"$NEOENV_OUTPUTS\"'\n[tasks.produce.outputs.ARTIFACT]\ndescription = 'published archive'\n[tasks.consume]\nneeds = ['produce']\nuses = 'argv'\nrun = 'true'\nif = 'context == release && input.target == win-x64 && outcome.produce == succeeded && output.ARTIFACT == dist/app.zip'\n[tasks.consume.inputs.target]\ntype = 'string'\nposition = 0\nrequired = true\n[tasks.prepare]\nuses = 'argv'\nrun = 'false'\n[tasks.cleanup]\nneeds = ['prepare']\nuses = 'argv'\nrun = 'true'\nforce = 'outcome.prepare == failed'\n",
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(filename);
        fs::write(&path, contents).unwrap();
        let consume = command()
            .current_dir(directory.path())
            .args(["--context", "release", "task", "run", "consume"])
            .arg(&path)
            .arg("win-x64")
            .output()
            .unwrap();
        assert!(consume.status.success(), "{filename}: {consume:?}");
        assert_eq!(
            String::from_utf8(consume.stdout).unwrap(),
            "produce Succeeded\nconsume Succeeded\n"
        );

        let cleanup = command()
            .current_dir(directory.path())
            .args(["task", "run", "cleanup"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!cleanup.status.success(), "{filename}: {cleanup:?}");
        assert_eq!(
            String::from_utf8(cleanup.stdout).unwrap(),
            "prepare Failed\ncleanup Succeeded\n"
        );
    }
}

#[test]
fn nested_yaml_and_toml_modules_execute_with_source_relative_dotenv_outputs_and_inputs() {
    let directory = TempDir::new().unwrap();
    let root = directory.path().join("neoenv.yaml");
    let nested = directory.path().join("tasks/nested.yaml");
    let leaf = directory.path().join("tasks/leaf.toml");
    let dotenv = directory.path().join("tasks/module.env");
    let marker = directory.path().join("module-task-ran");
    fs::create_dir_all(nested.parent().unwrap()).unwrap();
    fs::write(&dotenv, "MODULE_VALUE=from-dotenv\n").unwrap();
    fs::write(&root, "imports: [tasks/nested.yaml]\n").unwrap();
    fs::write(
        &nested,
        format!(
            "imports: [leaf.toml]\ntasks:\n  consume:\n    needs: produce\n    uses: shell\n    dotenv: module.env\n    run: 'test \"$MODULE_VALUE\" = from-dotenv && test \"$NEOENV_OUTPUT_ARTIFACT\" = module.zip && test \"$NEOENV_INPUT_target\" = xplat && touch {}'\n    inputs:\n      target: {{ type: string, position: 0, required: true }}\n",
            shell_path(&marker)
        ),
    )
    .unwrap();
    fs::write(&leaf, "[tasks.produce]\nuses = 'shell'\nrun = 'printf \"ARTIFACT=module.zip\\n\" > \"$NEOENV_OUTPUTS\"'\n[tasks.produce.outputs.ARTIFACT]\ndescription = 'module archive'\n").unwrap();

    let help = command()
        .current_dir(directory.path())
        .args(["task", "help", "consume"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(help.status.success(), "{help:?}");
    assert!(String::from_utf8(help.stdout).unwrap().contains("<target>"));

    let run = command()
        .current_dir(directory.path())
        .args(["task", "run", "consume"])
        .arg(&root)
        .arg("xplat")
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    assert_eq!(
        String::from_utf8(run.stdout).unwrap(),
        "produce Succeeded\nconsume Succeeded\n"
    );
    assert!(marker.exists());
}

#[test]
fn remote_clear_only_removes_the_addressed_neoenv_cache_entry() {
    let (directory, path) = write_project("format_version: 1\n");
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let source = format!("github:octo/repo@{commit}//module.yaml");
    let repository_key = format!("{:x}", Sha256::digest("github.com/octo/repo"));
    let cache = directory
        .path()
        .join(".neoenv/modules/commits")
        .join(repository_key)
        .join(commit);
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        "repository = 'github.com/octo/repo'\n",
    )
    .unwrap();
    let foreign = directory.path().join(".neoenv/modules/foreign/retain");
    fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    fs::write(&foreign, "retain").unwrap();

    let output = command()
        .current_dir(directory.path())
        .args(["remote", "clear", &source])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("cleared:")
    );
    assert!(!cache.exists());
    assert_eq!(fs::read_to_string(foreign).unwrap(), "retain");
}

#[test]
// Covers the complete package identity and execution contract together.
#[allow(clippy::too_many_lines)]
fn structured_task_packages_are_not_fallback_runners_and_preserve_task_contracts() {
    for (root_name, root_contents, package_name) in [
        (
            "neoenv.yaml",
            "task_packages:\n  lint: lint\ntasks:\n  check:\n    uses: package:lint\n",
            "lint.yaml",
        ),
        (
            "neoenv.toml",
            "[task_packages]\nlint = 'lint'\n[tasks.check]\nuses = 'package:lint'\n",
            "lint.toml",
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join(root_name);
        let package_root = directory.path().join("neoenv/tasks");
        let marker = directory.path().join("package-task-ran");
        fs::create_dir_all(&package_root).unwrap();
        fs::write(&root, root_contents).unwrap();
        fs::write(
            package_root.join("package.env"),
            "PACKAGE_VALUE=from-package\n",
        )
        .unwrap();
        let package_contents = if package_name.ends_with("yaml") {
            format!(
                "tasks:\n  prepare:\n    uses: argv\n    run: 'true'\n  default:\n    needs: prepare\n    uses: shell\n    dotenv: package.env\n    env:\n      UNRELATED_TOKEN: do-not-print\n    run: 'test \"$PACKAGE_VALUE\" = from-package && test \"$NEOENV_INPUT_target\" = xplat && touch {} && printf \"ARTIFACT=lint.txt\\n\" > \"$NEOENV_OUTPUTS\"'\n    inputs:\n      target: {{ type: string, position: 0, required: true }}\n    outputs:\n      ARTIFACT: lint artifact\n",
                shell_path(&marker)
            )
        } else {
            format!(
                "[tasks.prepare]\nuses = 'argv'\nrun = 'true'\n[tasks.default]\nneeds = ['prepare']\nuses = 'shell'\ndotenv = 'package.env'\nrun = 'test \"$PACKAGE_VALUE\" = from-package && test \"$NEOENV_INPUT_target\" = xplat && touch {} && printf \"ARTIFACT=lint.txt\\n\" > \"$NEOENV_OUTPUTS\"'\n[tasks.default.env]\nUNRELATED_TOKEN = 'do-not-print'\n[tasks.default.inputs.target]\ntype = 'string'\nposition = 0\nrequired = true\n[tasks.default.outputs.ARTIFACT]\ndescription = 'lint artifact'\n",
                shell_path(&marker)
            )
        };
        let package_document = package_root.join(package_name);
        fs::write(&package_document, package_contents).unwrap();
        let package_document = package_document.canonicalize().unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(&package_document).unwrap()));
        let identity_line = format!(
            "  package: path={} sha256={digest} export=default",
            package_document.display()
        );

        let help = command()
            .current_dir(directory.path())
            .args(["task", "help", "check"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(help.status.success(), "{root_name}: {help:?}");
        let help_text = String::from_utf8(help.stdout).unwrap();
        assert!(help_text.contains("<target>"));
        assert!(help_text.contains("ARTIFACT"));
        assert!(help_text.contains(&format!("Path: {}", package_document.display())));
        assert!(help_text.contains(&format!("SHA-256: {digest}")));
        assert!(help_text.contains("Export: default"));
        assert!(help_text.contains("prepare (package)"));

        let help_json = command()
            .current_dir(directory.path())
            .args(["task", "help", "check"])
            .arg(&root)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(help_json.status.success(), "{root_name}: {help_json:?}");
        let help_json_text = String::from_utf8(help_json.stdout).unwrap();
        assert!(!help_json_text.contains("do-not-print"));
        let help_json: serde_json::Value = serde_json::from_str(&help_json_text).unwrap();
        assert_eq!(
            help_json["package"]["path"],
            package_document.display().to_string()
        );
        assert_eq!(help_json["package"]["sha256"], digest);
        assert_eq!(help_json["package"]["export"], "default");
        assert_eq!(help_json["action"]["env"]["UNRELATED_TOKEN"], "[redacted]");

        let run = command()
            .current_dir(directory.path())
            .args(["task", "run", "check"])
            .arg(&root)
            .arg("xplat")
            .output()
            .unwrap();
        assert!(run.status.success(), "{root_name}: {run:?}");
        assert_eq!(
            String::from_utf8(run.stdout).unwrap(),
            format!(
                "package-lint:prepare Succeeded\n{identity_line}\ncheck Succeeded\n{identity_line}\n"
            )
        );
        assert!(marker.exists());

        let plan = command()
            .current_dir(directory.path())
            .args(["task", "plan", "check"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(plan.status.success(), "{root_name}: {plan:?}");
        let plan_text = String::from_utf8(plan.stdout).unwrap();
        assert_eq!(plan_text.matches(&identity_line).count(), 2, "{plan_text}");

        let inspection = command()
            .current_dir(directory.path())
            .arg("inspect")
            .arg(&root)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(inspection.status.success(), "{root_name}: {inspection:?}");
        let inspection: serde_json::Value = serde_json::from_slice(&inspection.stdout).unwrap();
        let package_tasks = inspection["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|task| task["package"].is_object())
            .collect::<Vec<_>>();
        assert_eq!(package_tasks.len(), 2);
        assert!(package_tasks.iter().all(|task| {
            task["package"]["path"] == package_document.display().to_string()
                && task["package"]["sha256"] == digest
                && task["package"]["export"] == "default"
        }));
        let exported = package_tasks
            .iter()
            .find(|task| task["key"] == "check")
            .unwrap();
        assert_eq!(exported["outputs"][0]["name"], "ARTIFACT");
        assert_eq!(exported["dependencies"][0]["origin"], "package");

        let listed = command()
            .current_dir(directory.path())
            .args(["task", "list"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(listed.status.success(), "{root_name}: {listed:?}");
        assert_eq!(String::from_utf8(listed.stdout).unwrap(), "check\n");

        let completed = command()
            .current_dir(directory.path())
            .args(["task", "complete"])
            .output()
            .unwrap();
        assert!(completed.status.success(), "{root_name}: {completed:?}");
        assert_eq!(String::from_utf8(completed.stdout).unwrap(), "check\n");

        let implementation_help = command()
            .current_dir(directory.path())
            .args(["task", "help", "package-lint:prepare"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            implementation_help.status.success(),
            "{root_name}: {implementation_help:?}"
        );
        assert!(
            String::from_utf8_lossy(&implementation_help.stdout).contains("package-lint:prepare")
        );
    }
}

#[test]
fn project_local_packages_keep_the_caller_subject_for_caller_declared_capabilities() {
    let (directory, root) = write_project(
        "task_packages:\n  local: local\ntasks:\n  check:\n    uses: package:local\n    capabilities: [execute]\n",
    );
    let package = directory.path().join("neoenv/tasks/local.yaml");
    fs::create_dir_all(package.parent().unwrap()).unwrap();
    fs::write(
        &package,
        "tasks:\n  default:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    let package = package.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&package).unwrap()));
    let policy = directory.path().join("capabilities.toml");
    let caller = format!(
        "project:{}/task:check",
        directory.path().canonicalize().unwrap().display()
    );

    fs::write(
        &policy,
        format!("[[grants]]\nsubject = \"package:{digest}\"\ncapability = 'execute'\n"),
    )
    .unwrap();
    let package_only = command()
        .args(["task", "run", "check"])
        .arg(&root)
        .arg("--capability-policy")
        .arg(&policy)
        .output()
        .unwrap();
    assert_eq!(package_only.status.code(), Some(5));

    fs::write(
        &policy,
        format!("[[grants]]\nsubject = {caller:?}\ncapability = 'execute'\n"),
    )
    .unwrap();
    let allowed = command()
        .args(["task", "run", "check"])
        .arg(&root)
        .arg("--capability-policy")
        .arg(&policy)
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{allowed:?}");
}

#[test]
// Exercises grant, revoke, replacement, and dual-subject denial as one lifecycle.
#[allow(clippy::too_many_lines)]
fn user_data_task_packages_support_at_aliases_and_propagate_capabilities() {
    let directory = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let config = TempDir::new().unwrap();
    let root = directory.path().join("neoenv.yaml");
    fs::write(
        &root,
        "task_packages:\n  audit: audit\ntasks:\n  check:\n    uses: '@audit'\n    capabilities: [execute]\n",
    )
    .unwrap();
    let package_directory = data.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    fs::write(
        package_directory.join("audit.env"),
        "PACKAGE_PATH_VALUE=loaded-from-package\n",
    )
    .unwrap();
    let package_document = package_directory.join("audit.yaml");
    fs::write(
        &package_document,
        "tasks:\n  default:\n    uses: shell\n    run: 'test \"$PACKAGE_PATH_VALUE\" = loaded-from-package'\n    dotenv: audit.env\n    env:\n      UNRELATED_TOKEN: package-secret-value\n    capabilities: [execute]\n",
    )
    .unwrap();
    let package_document = package_document.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&package_document).unwrap()));

    let denied = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(5));
    let denied_text = String::from_utf8(denied.stderr).unwrap();
    assert!(denied_text.contains("execute"));
    assert!(denied_text.contains(&package_document.display().to_string()));
    assert!(denied_text.contains(&digest));
    assert!(denied_text.contains("export: default"));
    assert!(denied_text.contains(&format!("package:{digest}")));
    assert!(!denied_text.contains("package-secret-value"));

    let policy_directory = config.path().join("neoenv");
    fs::create_dir_all(&policy_directory).unwrap();
    let policy = policy_directory.join("capabilities.toml");
    let caller_subject = format!(
        "project:{}/task:check",
        directory.path().canonicalize().unwrap().display()
    );
    fs::write(
        &policy,
        format!("[[grants]]\nsubject = {caller_subject:?}\ncapability = 'execute'\n"),
    )
    .unwrap();
    let caller_only = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(caller_only.status.code(), Some(5));

    fs::write(
        &policy,
        format!("[[grants]]\nsubject = \"package:{digest}\"\ncapability = 'execute'\n"),
    )
    .unwrap();
    let package_only = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(package_only.status.code(), Some(5));

    fs::write(
        &policy,
        format!(
            "[[grants]]\nsubject = {caller_subject:?}\ncapability = 'execute'\n[[grants]]\nsubject = \"package:{digest}\"\ncapability = 'execute'\n"
        ),
    )
    .unwrap();
    let allowed = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{allowed:?}");
    let identity_line = format!(
        "  package: path={} sha256={digest} export=default",
        package_document.display()
    );
    assert_eq!(
        String::from_utf8(allowed.stdout).unwrap(),
        format!("check Succeeded\n{identity_line}\n")
    );

    fs::write(&policy, "").unwrap();
    let revoked = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(revoked.status.code(), Some(5));

    let mut changed = fs::read(&package_document).unwrap();
    changed.extend_from_slice(b"# changed package bytes\n");
    fs::write(&package_document, &changed).unwrap();
    let changed_digest = format!("{:x}", Sha256::digest(&changed));
    assert_ne!(changed_digest, digest);
    fs::write(
        &policy,
        format!(
            "[[grants]]\nsubject = {caller_subject:?}\ncapability = 'execute'\n[[grants]]\nsubject = \"package:{digest}\"\ncapability = 'execute'\n"
        ),
    )
    .unwrap();
    let modified_denied = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(modified_denied.status.code(), Some(5));
    let modified_stderr = String::from_utf8(modified_denied.stderr).unwrap();
    assert!(modified_stderr.contains(&changed_digest));
    assert!(!modified_stderr.contains(&format!("not granted to package:{digest}")));

    let help = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .args(["task", "help", "check"])
        .arg(&root)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(help.status.success(), "{help:?}");
    let help_text = String::from_utf8(help.stdout).unwrap();
    assert!(!help_text.contains("package-secret-value"));
    let help: serde_json::Value = serde_json::from_str(&help_text).unwrap();
    assert_eq!(help["package"]["sha256"], changed_digest);

    fs::write(
        &policy,
        format!(
            "[[grants]]\nsubject = {caller_subject:?}\ncapability = 'execute'\n[[grants]]\nsubject = \"package:{changed_digest}\"\ncapability = 'execute'\n"
        ),
    )
    .unwrap();
    let changed_allowed = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(changed_allowed.status.success(), "{changed_allowed:?}");
}

#[test]
fn user_data_toml_packages_use_the_digest_execute_subject() {
    let directory = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let config = TempDir::new().unwrap();
    let root = directory.path().join("neoenv.toml");
    fs::write(
        &root,
        "[task_packages]\naudit = 'audit'\n[tasks.check]\nuses = '@audit'\n",
    )
    .unwrap();
    let package_directory = data.path().join("neoenv/tasks");
    fs::create_dir_all(&package_directory).unwrap();
    fs::write(
        package_directory.join("audit.env"),
        "FROM_TOML_PACKAGE=loaded\n",
    )
    .unwrap();
    let package = package_directory.join("audit.toml");
    fs::write(
        &package,
        "[tasks.default]\nuses = 'shell'\nrun = 'test \"$FROM_TOML_PACKAGE\" = loaded'\ndotenv = 'audit.env'\n",
    )
    .unwrap();
    let package = package.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&package).unwrap()));

    let denied = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(5));
    let stderr = String::from_utf8(denied.stderr).unwrap();
    assert!(stderr.contains(&package.display().to_string()));
    assert!(stderr.contains(&format!("package:{digest}")));

    let policy_directory = config.path().join("neoenv");
    fs::create_dir_all(&policy_directory).unwrap();
    fs::write(
        policy_directory.join("capabilities.toml"),
        format!("[[grants]]\nsubject = \"package:{digest}\"\ncapability = 'execute'\n"),
    )
    .unwrap();
    let allowed = command()
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data.path())
        .env("NEOENV_CONFIG_HOME", config.path())
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{allowed:?}");
    assert!(
        String::from_utf8(allowed.stdout)
            .unwrap()
            .contains(digest.as_str())
    );
}

#[test]
fn imported_yaml_and_toml_packages_keep_paths_and_identity_with_the_selected_document() {
    for (root_name, root_contents, extension) in [
        (
            "neoenv.yaml",
            "task_packages:\n  imported: imported\ntasks:\n  check:\n    uses: package:imported\n",
            "yaml",
        ),
        (
            "neoenv.toml",
            "[task_packages]\nimported = 'imported'\n[tasks.check]\nuses = 'package:imported'\n",
            "toml",
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let root = directory.path().join(root_name);
        let package_directory = directory.path().join("neoenv/tasks");
        fs::create_dir_all(package_directory.join("generated")).unwrap();
        fs::write(&root, root_contents).unwrap();
        fs::write(
            package_directory.join("package.env"),
            "PACKAGE_VALUE=package\n",
        )
        .unwrap();
        fs::write(
            package_directory.join("imported.env"),
            "STEP_VALUE=imported\n",
        )
        .unwrap();
        fs::write(
            package_directory.join("template.tmpl"),
            "rendered={{ .inputs.name }}\n",
        )
        .unwrap();
        let (steps, package) = if extension == "yaml" {
            (
                "tasks:\n  prepare:\n    uses: shell\n    run: 'test \"$STEP_VALUE\" = imported'\n    dotenv: imported.env\n    env:\n      STEP_TOKEN: step-secret\n  render:\n    uses: render\n    source: template.tmpl\n    destination: generated/rendered.txt\n    with: { name: packaged }\n",
                "imports: [steps.yaml]\ntasks:\n  default:\n    needs: [prepare, render]\n    uses: shell\n    dotenv: package.env\n    cwd: '.'\n    run: 'test \"$PACKAGE_VALUE\" = package && printf \"ARTIFACT=package.txt\\n\" > \"$NEOENV_OUTPUTS\"'\n    outputs:\n      ARTIFACT: package artifact\n",
            )
        } else {
            (
                "[tasks.prepare]\nuses = 'shell'\nrun = 'test \"$STEP_VALUE\" = imported'\ndotenv = 'imported.env'\n[tasks.prepare.env]\nSTEP_TOKEN = 'step-secret'\n[tasks.render]\nuses = 'render'\nsource = 'template.tmpl'\ndestination = 'generated/rendered.txt'\n[tasks.render.with]\nname = 'packaged'\n",
                "imports = ['steps.toml']\n[tasks.default]\nneeds = ['prepare', 'render']\nuses = 'shell'\ndotenv = 'package.env'\ncwd = '.'\nrun = 'test \"$PACKAGE_VALUE\" = package && printf \"ARTIFACT=package.txt\\n\" > \"$NEOENV_OUTPUTS\"'\n[tasks.default.outputs.ARTIFACT]\ndescription = 'package artifact'\n",
            )
        };
        let steps_path = package_directory.join(format!("steps.{extension}"));
        fs::write(&steps_path, steps).unwrap();
        let package_path = package_directory.join(format!("imported.{extension}"));
        fs::write(&package_path, package).unwrap();
        let package_path = package_path.canonicalize().unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(&package_path).unwrap()));

        let run = command()
            .current_dir(directory.path())
            .args(["task", "run", "check"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(run.status.success(), "{root_name}: {run:?}");
        let run_text = String::from_utf8(run.stdout).unwrap();
        assert_eq!(run_text.matches(&digest).count(), 3, "{run_text}");
        assert!(run_text.contains(&package_path.display().to_string()));
        assert!(run_text.contains("export=default"));
        assert_eq!(
            fs::read_to_string(package_directory.join("generated/rendered.txt")).unwrap(),
            "rendered=packaged\n"
        );

        let report: serde_json::Value = serde_json::from_slice(
            &command()
                .current_dir(directory.path())
                .args(["task", "run", "check"])
                .arg(&root)
                .args(["--format", "json", "--dry-run"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            report["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|task| task["package"]["sha256"] == digest)
        );
        assert!(report["tasks"].as_array().unwrap().iter().all(|task| {
            task["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .all(|edge| edge["origin"] == "package")
        }));
    }
}

#[test]
fn package_merged_tasks_retain_caller_and_package_edges_in_order() {
    let (directory, root) = write_project(
        "task_packages:\n  shared: shared\ntasks:\n  caller-step: 'true'\n  check:\n    uses: package:shared\n    needs: [caller-step, package-shared:prepare]\n",
    );
    let package = directory.path().join("neoenv/tasks/shared.yaml");
    fs::create_dir_all(package.parent().unwrap()).unwrap();
    fs::write(
        &package,
        "tasks:\n  prepare: 'true'\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();

    let help = command()
        .args(["task", "help", "check"])
        .arg(&root)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(help.status.success(), "{help:?}");
    let help: serde_json::Value = serde_json::from_slice(&help.stdout).unwrap();
    assert_eq!(
        help["dependency_edges"][0]["name"],
        "package-shared:prepare"
    );
    assert_eq!(help["dependency_edges"][0]["origin"], "package");
    assert_eq!(help["dependency_edges"][1]["name"], "caller-step");
    assert_eq!(help["dependency_edges"][1]["origin"], "caller");
    assert_eq!(
        help["dependency_edges"][2]["name"],
        "package-shared:prepare"
    );
    assert_eq!(help["dependency_edges"][2]["origin"], "caller");

    let run = command()
        .args(["task", "run", "check", "--format", "json"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    let run: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    let check = run["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["name"] == "check")
        .unwrap();
    assert_eq!(check["dependencies"][0]["origin"], "package");
    assert_eq!(check["dependencies"][1]["origin"], "caller");
    assert_eq!(check["dependencies"][2]["origin"], "caller");
}

#[test]
fn invalid_package_capabilities_include_identity_without_package_environment_values() {
    let (directory, root) = write_project(
        "task_packages:\n  invalid: invalid\ntasks:\n  check:\n    uses: package:invalid\n",
    );
    let package = directory.path().join("neoenv/tasks/invalid.yaml");
    fs::create_dir_all(package.parent().unwrap()).unwrap();
    fs::write(
        &package,
        "tasks:\n  default:\n    uses: portable\n    run: 'true'\n    env:\n      UNRELATED_TOKEN: never-print-this\n    capabilities: [run-anything]\n",
    )
    .unwrap();
    let package = package.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&package).unwrap()));

    let output = command()
        .args(["task", "run", "check"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&package.display().to_string()));
    assert!(stderr.contains(&digest));
    assert!(stderr.contains("export: default"));
    assert!(stderr.contains("run-anything"));
    assert!(!stderr.contains("never-print-this"));
}

#[test]
fn task_package_declared_paths_are_contained_after_canonicalization() {
    let (directory, root) = write_project(
        "task_packages:\n  paths: paths\ntasks:\n  check:\n    uses: package:paths\n",
    );
    let package_directory = directory.path().join("neoenv/tasks");
    fs::create_dir_all(package_directory.join("generated")).unwrap();
    fs::write(directory.path().join("outside.env"), "VALUE=outside\n").unwrap();
    fs::write(directory.path().join("outside.tmpl"), "outside\n").unwrap();
    let package = package_directory.join("paths.yaml");
    for declaration in [
        "    uses: shell\n    run: 'true'\n    dotenv: ../outside.env",
        "    uses: render\n    source: ../outside.tmpl\n    destination: generated/output",
        "    uses: shell\n    run: 'true'\n    cwd: ..",
        "    uses: render\n    source: outside.tmpl\n    destination: ../escaped",
    ] {
        fs::write(&package, format!("tasks:\n  default:\n{declaration}\n")).unwrap();
        fs::write(package_directory.join("outside.tmpl"), "inside\n").unwrap();
        let output = command().arg("validate").arg(&root).output().unwrap();
        assert_eq!(output.status.code(), Some(3), "{declaration}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("package root") || stderr.contains("declaring package document"),
            "{declaration}: {stderr}"
        );
        assert!(!stderr.contains("VALUE=outside"), "{declaration}: {stderr}");
    }
}

#[test]
fn task_package_aliases_share_document_identity_and_generated_names_still_collide() {
    let directory = TempDir::new().unwrap();
    let root = directory.path().join("neoenv.yaml");
    let package = directory.path().join("neoenv/tasks/shared.yaml");
    fs::create_dir_all(package.parent().unwrap()).unwrap();
    fs::write(
        &root,
        "task_packages:\n  first: shared\n  second: shared\ntasks:\n  one:\n    uses: package:first\n  two:\n    uses: package:second\n",
    )
    .unwrap();
    fs::write(
        &package,
        "tasks:\n  prepare: 'true'\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    let package = package.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&package).unwrap()));

    for task in ["one", "two"] {
        let help = command()
            .args(["task", "help", task])
            .arg(&root)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(help.status.success(), "{task}: {help:?}");
        let document: serde_json::Value = serde_json::from_slice(&help.stdout).unwrap();
        assert_eq!(document["package"]["path"], package.display().to_string());
        assert_eq!(document["package"]["sha256"], digest);
        assert_eq!(document["package"]["export"], "default");
        assert_eq!(document["dependency_edges"][0]["origin"], "package");
    }

    let (collision_directory, collision_root) = write_project(
        "imports: [modules/first.yaml]\ntask_packages:\n  first: packages/other.yaml\n",
    );
    let modules = collision_directory.path().join("modules");
    let packages = collision_directory.path().join("packages");
    fs::create_dir_all(&modules).unwrap();
    fs::create_dir_all(&packages).unwrap();
    fs::write(
        modules.join("first.yaml"),
        "task_packages:\n  first: other.yaml\ntasks:\n  from-module:\n    uses: package:first\n",
    )
    .unwrap();
    fs::write(
        modules.join("other.yaml"),
        "tasks:\n  prepare: 'true'\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    fs::write(
        packages.join("other.yaml"),
        "tasks:\n  prepare: 'true'\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    let collision = command()
        .arg("validate")
        .arg(&collision_root)
        .output()
        .unwrap();
    assert_eq!(collision.status.code(), Some(3));
    assert!(
        String::from_utf8(collision.stderr)
            .unwrap()
            .contains("task package task collides")
    );
}

#[test]
fn task_package_missing_and_generated_task_collisions_are_diagnostic() {
    let (directory, root) = write_project(
        "task_packages:\n  missing: no-such-package\ntasks:\n  check:\n    uses: package:missing\n",
    );
    let missing = command().arg("validate").arg(&root).output().unwrap();
    assert_eq!(missing.status.code(), Some(3));
    assert!(
        String::from_utf8(missing.stderr)
            .unwrap()
            .contains("task package was not found")
    );
    fs::write(
        &root,
        "task_packages:\n  remote: 'https://example.test/package.yaml'\ntasks:\n  check:\n    uses: package:remote\n",
    )
    .unwrap();
    let remote = command().arg("validate").arg(&root).output().unwrap();
    assert_eq!(remote.status.code(), Some(3));
    assert!(
        String::from_utf8(remote.stderr)
            .unwrap()
            .contains("remote modules must use GitHub HTTPS or github: syntax")
    );

    let package_root = directory.path().join("neoenv/tasks");
    fs::create_dir_all(&package_root).unwrap();
    fs::write(
        package_root.join("lint.yaml"),
        "tasks:\n  prepare: 'true'\n  default:\n    needs: prepare\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    fs::write(
        &root,
        "task_packages:\n  lint: lint\ntasks:\n  package-lint:prepare: 'true'\n  check:\n    uses: package:lint\n",
    )
    .unwrap();
    let collision = command().arg("validate").arg(&root).output().unwrap();
    assert_eq!(collision.status.code(), Some(3));
    assert!(
        String::from_utf8(collision.stderr)
            .unwrap()
            .contains("task package task collides")
    );
}

#[test]
fn task_run_dry_run_does_not_start_the_action() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("must-not-run");
    fs::write(
        &path,
        format!(
            "tasks:\n  check:\n    uses: shell\n    run: touch {}\n",
            marker.display()
        ),
    )
    .unwrap();

    let output = command()
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&path)
        .arg("--dry-run")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "check Planned\n");
    assert!(!marker.exists());
}

#[test]
fn task_run_blocks_dependents_after_a_failed_dependency() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("must-not-run");
    fs::write(
        &path,
        format!("tasks:\n  fail:\n    uses: shell\n    run: 'exit 1'\n  root:\n    uses: shell\n    run: touch {}\n    needs: fail\n", marker.display()),
    )
    .unwrap();

    let output = command()
        .arg("task")
        .arg("run")
        .arg("root")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "fail Failed\nroot Blocked\n"
    );
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn task_hooks_run_in_order_and_propagate_failures() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("hook-order");
    fs::write(
        &path,
        format!(
            "context: prod\ntasks:\n  build:\n    uses: shell\n    run: 'printf build >> {marker}'\n    hooks:\n      before: before\n      after: after\n  build:before:\n    uses: shell\n    run: 'printf fallback-before >> {marker}'\n  build:before:prod:\n    uses: shell\n    run: 'printf before >> {marker}'\n  build:after:\n    uses: shell\n    run: 'printf after >> {marker}'\n",
            marker = marker.display()
        ),
    )
    .unwrap();

    let output = command()
        .arg("task")
        .arg("run")
        .arg("build")
        .arg(&path)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "beforebuildafter");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "build:before:prod Succeeded\nbuild Succeeded\nbuild:after Succeeded\n"
    );

    fs::write(
        &path,
        format!(
            "tasks:\n  build:\n    uses: shell\n    run: 'touch {marker}'\n    hooks:\n      before: before\n      after: after\n  build:before:\n    uses: shell\n    run: 'exit 1'\n  build:after:\n    uses: shell\n    run: 'touch {marker}-after'\n",
            marker = marker.display()
        ),
    )
    .unwrap();
    fs::remove_file(&marker).unwrap();
    let output = command()
        .arg("task")
        .arg("run")
        .arg("build")
        .arg(&path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "build:before Failed\nbuild Blocked\nbuild:after Blocked\n"
    );
    assert!(!marker.exists());
    assert!(!marker.with_file_name("hook-order-after").exists());
}

#[cfg(unix)]
#[test]
fn task_timeout_terminates_shell_descendants() {
    let (directory, path) = write_project("");
    let ready = directory.path().join("descendant-ready");
    let marker = directory.path().join("descendant-survived");
    fs::write(
        &path,
        format!(
            "tasks:\n  check:\n    uses: shell\n    run: '(touch {ready}; sleep 1; touch {marker}) & wait'\n    with:\n      timeout: 500ms\n",
            ready = ready.display(),
            marker = marker.display(),
        ),
    )
    .unwrap();

    let output = command()
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "check TimedOut\n"
    );
    assert!(
        ready.exists(),
        "the descendant did not start before the timeout"
    );
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        !marker.exists(),
        "the timed-out descendant was not terminated"
    );
}

#[cfg(unix)]
#[test]
fn task_interrupt_cancels_shell_descendants() {
    let (directory, path) = write_project("");
    let ready = directory.path().join("cancel-descendant-ready");
    let marker = directory.path().join("cancel-descendant-survived");
    fs::write(
        &path,
        format!(
            "tasks:\n  check:\n    uses: shell\n    run: '(touch {ready}; sleep 1; touch {marker}) & wait'\n",
            ready = ready.display(),
            marker = marker.display(),
        ),
    )
    .unwrap();

    let mut task = command()
        .arg("task")
        .arg("run")
        .arg("check")
        .arg(&path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if ready.exists() {
            break;
        }
        if let Some(status) = task.try_wait().unwrap() {
            panic!("task exited before descendant readiness: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "the descendant did not start");
    assert!(
        Command::new("kill")
            .args(["-INT", &task.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = task.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "check Cancelled\n"
    );
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        !marker.exists(),
        "the cancelled descendant was not terminated"
    );
}

#[test]
fn task_handoffs_are_run_local_and_do_not_change_the_test_process() {
    let (directory, path) = write_project("");
    let marker = directory.path().join("handoff-result");
    fs::write(
        &path,
        format!("tasks:\n  produce:\n    uses: shell\n    run: 'printf \"HANDOFF_VALUE=available\\n\" > \"$NEOENV_ENV\"; printf \"artifact=result\\n\" > \"$NEOENV_OUTPUTS\"'\n    outputs:\n      artifact: result\n  consume:\n    uses: shell\n    run: 'test \"$HANDOFF_VALUE\" = available && test \"$NEOENV_OUTPUT_artifact\" = result && touch {}'\n    needs: produce\n", shell_path(&marker)),
    )
    .unwrap();
    let before = std::env::var("HANDOFF_VALUE").ok();

    let output = command()
        .arg("task")
        .arg("run")
        .arg("consume")
        .arg(&path)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(marker.exists());
    assert_eq!(std::env::var("HANDOFF_VALUE").ok(), before);
}

#[test]
fn tool_plan_lock_and_verify_are_deterministic_and_do_not_install_artifacts() {
    let (directory, path) = write_project(
        "tools:\n  - id: first\n    version: 1.0.0\n    url: https://example.test/first\n    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n    binaries: [first]\n  - id: second\n    version: 2.0.0\n    url: https://example.test/second\n    sha256: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\n    binaries: [second]\n",
    );
    let planned = command()
        .arg("tool")
        .arg("plan")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(planned.status.success());
    let document: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(document["tools"][0]["id"], "first");
    assert_eq!(document["tools"][1]["id"], "second");

    let locked = command()
        .arg("tool")
        .arg("lock")
        .arg(&path)
        .output()
        .unwrap();
    assert!(locked.status.success());
    let lockfile = directory.path().join("neoenv.lock");
    assert!(lockfile.is_file());
    let verified = command()
        .arg("tool")
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(!directory.path().join("tools").exists());
}

#[test]
fn tool_verify_detects_a_digest_mismatch() {
    let (directory, path) = write_project(
        "tools:\n  - id: tool\n    version: 1.0.0\n    url: https://example.test/tool\n    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n    binaries: [tool]\n",
    );
    assert!(
        command()
            .arg("tool")
            .arg("lock")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let lockfile = directory.path().join("neoenv.lock");
    let lock = fs::read_to_string(&lockfile).unwrap().replace(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    fs::write(lockfile, lock).unwrap();
    let output = command()
        .arg("tool")
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("SHA-256 differs")
    );
}

#[test]
fn tool_install_locked_verifies_and_reports_actual_installs() {
    let artifact = b"#!/bin/sh\necho neoenv\n".to_vec();
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let url = serve_once(artifact);
    let (directory, path) = write_project(&format!(
        "tools:\n  - id: demo\n    version: 1.0.0\n    url: {url}\n    sha256: {digest}\n    binaries: [demo]\n"
    ));
    assert!(
        command()
            .arg("tool")
            .arg("lock")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );

    let install = command()
        .arg("tool")
        .arg("install")
        .arg("--locked")
        .arg(&path)
        .output()
        .unwrap();
    assert!(install.status.success());
    assert!(
        String::from_utf8(install.stdout)
            .unwrap()
            .starts_with("demo 1.0.0 ")
    );

    let listed = command()
        .arg("tool")
        .arg("list")
        .arg(&path)
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed = String::from_utf8(listed.stdout).unwrap();
    assert!(listed.starts_with("demo 1.0.0 "));

    let which = command()
        .arg("tool")
        .arg("which")
        .arg("demo")
        .arg(&path)
        .output()
        .unwrap();
    assert!(which.status.success());
    let installed_path = String::from_utf8(which.stdout).unwrap();
    assert!(installed_path.contains(".neoenv"));
    assert!(installed_path.contains("tools"));

    let reinstall = command()
        .arg("tool")
        .arg("install")
        .arg("--locked")
        .arg(&path)
        .output()
        .unwrap();
    assert!(reinstall.status.success());
    assert!(
        String::from_utf8(reinstall.stdout)
            .unwrap()
            .starts_with("demo 1.0.0 ")
    );
    assert!(directory.path().join(".neoenv/tools").is_dir());

    let activation = command()
        .arg("shell")
        .arg("activate")
        .arg("bash")
        .arg(&path)
        .output()
        .unwrap();
    assert!(activation.status.success());
    let activation = String::from_utf8(activation.stdout).unwrap();
    assert!(activation.contains(".neoenv"));
    assert!(activation.contains("tools"));
}

#[test]
fn exec_and_x_apply_dotenv_environment_and_installed_tool_paths() {
    let (artifact, binary) = if cfg!(windows) {
        (
            b"@echo off\r\n<nul set /p =%PROJECT_VALUE%^|%FROM_DOTENV%\r\nexit /b 0\r\n".to_vec(),
            "demo.cmd",
        )
    } else {
        (
            b"#!/bin/sh\nprintf '%s|%s' \"$PROJECT_VALUE\" \"$FROM_DOTENV\"\n".to_vec(),
            "demo",
        )
    };
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let url = serve_once(artifact);
    let (directory, path) = write_project(&format!(
        "dotenv: local.env\nenv:\n  PROJECT_VALUE: configured\ntools:\n  - id: demo\n    version: 1.0.0\n    url: {url}\n    sha256: {digest}\n    binaries: [{binary}]\n"
    ));
    fs::write(directory.path().join("local.env"), "FROM_DOTENV=loaded\n").unwrap();
    assert!(
        command()
            .arg("tool")
            .arg("lock")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        command()
            .arg("tool")
            .arg("install")
            .arg("--locked")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    for invocation in [&["exec", "--", "demo"][..], &["x", "demo"][..]] {
        let output = command()
            .current_dir(directory.path())
            .args(invocation)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "configured|loaded"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn tool_lifecycle_reports_provider_state_uses_only_declared_binaries_and_cleans_orphans() {
    let (artifact, binary) = if cfg!(windows) {
        (
            b"@echo off\r\n> \"%~2\" <nul set /p \"=%~1\"\r\nexit /b 0\r\n".to_vec(),
            "demo.cmd",
        )
    } else {
        (b"#!/bin/sh\nprintf '%s' \"$1\" > \"$2\"\n".to_vec(), "demo")
    };
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let url = serve_once(artifact);
    let (directory, path) = write_project(&format!(
        "tools:\n  - id: demo\n    version: 1.0.0\n    url: {url}\n    sha256: {digest}\n    binaries: [{binary}]\n"
    ));
    assert!(
        command()
            .arg("tool")
            .arg("lock")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );

    let missing = command()
        .arg("tool")
        .arg("list")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert!(missing.status.success());
    let missing: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing[0]["provider"], "explicit-url");
    assert_eq!(missing[0]["installed"], false);

    assert!(
        command()
            .arg("tool")
            .arg("install")
            .arg("--locked")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let marker = directory.path().join("used");
    let used = command()
        .arg("tool")
        .arg("use")
        .arg(binary)
        .arg(&path)
        .arg("--")
        .arg("value")
        .arg(&marker)
        .output()
        .unwrap();
    assert!(used.status.success(), "{used:?}");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "value");

    let where_output = command()
        .arg("tool")
        .arg("where")
        .arg(binary)
        .arg(&path)
        .output()
        .unwrap();
    assert!(where_output.status.success());
    let tool_directory = if cfg!(windows) {
        ".neoenv\\tools"
    } else {
        ".neoenv/tools"
    };
    assert!(
        String::from_utf8(where_output.stdout)
            .unwrap()
            .contains(tool_directory)
    );
    let unsafe_where = command()
        .arg("tool")
        .arg("where")
        .arg(format!("bin/{binary}"))
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(unsafe_where.status.code(), Some(2));

    let stale = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let stale_artifact = directory.path().join(".neoenv/artifacts").join(stale);
    let stale_install = directory.path().join(".neoenv/tools").join(stale);
    fs::write(&stale_artifact, "stale").unwrap();
    fs::create_dir(&stale_install).unwrap();
    let preview = command()
        .arg("tool")
        .arg("cleanup")
        .arg("--dry-run")
        .arg(&path)
        .output()
        .unwrap();
    assert!(preview.status.success());
    assert!(stale_artifact.exists());
    assert!(stale_install.exists());
    let cleanup = command()
        .arg("tool")
        .arg("cleanup")
        .arg(&path)
        .output()
        .unwrap();
    assert!(cleanup.status.success(), "{cleanup:?}");
    assert!(!stale_artifact.exists());
    assert!(!stale_install.exists());
    assert!(
        directory
            .path()
            .join(".neoenv/artifacts")
            .join(&digest)
            .is_file()
    );
}

#[test]
fn tool_install_does_not_publish_a_checksum_mismatch() {
    let url = serve_once(b"untrusted bytes".to_vec());
    let (directory, path) = write_project(&format!(
        "tools:\n  - id: broken\n    version: 1.0.0\n    url: {url}\n    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n    binaries: [broken]\n"
    ));
    assert!(
        command()
            .arg("tool")
            .arg("lock")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );

    let output = command()
        .arg("tool")
        .arg("install")
        .arg("--locked")
        .arg(&path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("SHA-256 mismatch")
    );
    assert!(!directory.path().join(".neoenv/tools").exists());
    assert!(
        !directory
            .path()
            .join(".neoenv/artifacts")
            .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .exists()
    );
}

/// Declares a workspace with two aliased members and one nameless member, so
/// every listing ordering is exercised.
fn write_workspace_fixture() -> TempDir {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    for member in ["packages/api", "packages/web", "tools/standalone"] {
        fs::create_dir_all(root.join(member)).unwrap();
        fs::write(
            root.join(member).join("neoenv.yaml"),
            "format_version: 1\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n",
        )
        .unwrap();
    }
    fs::write(
        root.join("neoenv.yaml"),
        "format_version: 1\nworkspace:\n  members:\n    - packages/api\n    - packages/web\n    - tools/standalone\n  aliases:\n    web: packages/web\n    api: packages/api\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    directory
}

#[test]
fn workspace_list_reports_every_declared_member_in_a_stable_order() {
    let directory = write_workspace_fixture();
    let output = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // Aliases sort by name, then members without an alias sort by declared path.
    // The command reports canonical roots, which differ from the `TempDir`
    // spelling wherever the system temp directory is itself a symlink.
    let canonical = fs::canonicalize(directory.path()).unwrap();
    let expected = format!(
        "api\t{}\t{}\nweb\t{}\t{}\n\t{}\t{}\n",
        canonical.join("packages").join("api").display(),
        std::path::Path::new("packages").join("api").display(),
        canonical.join("packages").join("web").display(),
        std::path::Path::new("packages").join("web").display(),
        canonical.join("tools").join("standalone").display(),
        std::path::Path::new("tools").join("standalone").display(),
    );
    assert_eq!(stdout, expected);

    // Repeating the call must not reorder anything.
    let repeated = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(repeated.stdout, output.stdout);
}

#[test]
fn workspace_list_text_and_json_carry_the_same_rows() {
    let directory = write_workspace_fixture();
    let text = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();
    let json = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert_eq!(json.status.code(), Some(0), "{json:?}");
    assert!(json.stderr.is_empty(), "{json:?}");
    let document: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(document["schema_version"], 1);

    // Assert the whole document rather than rendering the text back out of it,
    // so a wrong or dropped JSON field cannot validate itself.
    let canonical = fs::canonicalize(directory.path()).unwrap();
    assert_eq!(
        document["members"],
        serde_json::json!([
            {
                "alias": "api",
                "member": "packages/api",
                "path": canonical.join("packages").join("api"),
                "relative_path": std::path::Path::new("packages").join("api"),
            },
            {
                "alias": "web",
                "member": "packages/web",
                "path": canonical.join("packages").join("web"),
                "relative_path": std::path::Path::new("packages").join("web"),
            },
            {
                "alias": "",
                "member": "tools/standalone",
                "path": canonical.join("tools").join("standalone"),
                "relative_path": std::path::Path::new("tools").join("standalone"),
            },
        ])
    );

    // The text form carries the same rows, minus the declared spelling.
    assert_eq!(
        String::from_utf8(text.stdout).unwrap(),
        format!(
            "api\t{}\t{}\nweb\t{}\t{}\n\t{}\t{}\n",
            canonical.join("packages").join("api").display(),
            std::path::Path::new("packages").join("api").display(),
            canonical.join("packages").join("web").display(),
            std::path::Path::new("packages").join("web").display(),
            canonical.join("tools").join("standalone").display(),
            std::path::Path::new("tools").join("standalone").display(),
        )
    );
}

#[test]
fn workspace_list_never_scans_for_undeclared_members() {
    let (directory, _path) = write_project("format_version: 1\n");
    // A sibling directory that looks like a member but is never declared.
    fs::create_dir_all(directory.path().join("packages/undeclared")).unwrap();
    fs::write(
        directory.path().join("packages/undeclared/neoenv.yaml"),
        "format_version: 1\n",
    )
    .unwrap();

    let output = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");

    let json = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(document["members"], serde_json::json!([]));
}

#[test]
fn workspace_list_finds_the_declaring_ancestor_from_a_member() {
    let directory = write_workspace_fixture();
    let output = command()
        .current_dir(directory.path().join("packages/api"))
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 3);
}

#[test]
fn workspace_list_accepts_an_explicit_root_but_does_not_walk_above_it() {
    let directory = write_workspace_fixture();

    for selection in [
        directory.path().to_path_buf(),
        directory.path().join("neoenv.yaml"),
    ] {
        let output = command()
            .current_dir(std::env::temp_dir())
            .arg("workspace")
            .arg("list")
            .arg(&selection)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{selection:?}: {output:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 3);
    }

    // A member declares a project but not a workspace, and an explicit path must
    // not silently resolve to the workspace above it.
    let member = directory.path().join("packages/api");
    let output = command()
        .arg("workspace")
        .arg("list")
        .arg(&member)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no nenv workspace")
    );
}

#[test]
fn workspace_aliases_still_select_a_member_for_task_commands() {
    let directory = write_workspace_fixture();
    for alias in ["api", "web"] {
        let output = command()
            .current_dir(directory.path())
            .arg("task")
            .arg("list")
            .arg(alias)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{alias}: {output:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "check");
    }
}

#[test]
fn workspace_list_keeps_the_existing_workspace_validation_diagnostics() {
    let cases = [
        (
            "duplicate workspace member",
            "format_version: 1\nworkspace:\n  members:\n    - a\n    - a\n",
            vec!["a"],
        ),
        (
            "workspace alias cycle",
            "format_version: 1\nworkspace:\n  members:\n    - a\n  aliases:\n    x: y\n    y: x\n",
            vec!["a"],
        ),
        (
            "workspace alias target is not declared",
            "format_version: 1\nworkspace:\n  members:\n    - a\n  aliases:\n    x: nope\n",
            vec!["a"],
        ),
        (
            "workspace member escapes the workspace root",
            "format_version: 1\nworkspace:\n  members:\n    - ../outside\n",
            Vec::<&str>::new(),
        ),
    ];
    for (expected, configuration, members) in cases {
        // The workspace root is a subdirectory so a `..` member can reach a
        // sibling that still lives inside this test's own container. Nothing
        // here reaches a shared parent or needs a symlink, so the escape case
        // behaves the same on every platform.
        let container = TempDir::new().unwrap();
        let directory = container.path().join("workspace");
        fs::create_dir_all(&directory).unwrap();
        let sibling = container.path().join("sibling");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("neoenv.yaml"), "format_version: 1\n").unwrap();
        for member in members {
            let path = directory.join(member);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("neoenv.yaml"), "format_version: 1\n").unwrap();
        }
        let configuration = configuration.replace("../outside", "../sibling");
        fs::write(directory.join("neoenv.yaml"), configuration).unwrap();

        let output = command()
            .current_dir(&directory)
            .arg("workspace")
            .arg("list")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{expected}: {output:?}");
        assert!(output.stdout.is_empty(), "{expected}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{expected}: {output:?}"
        );
    }
}

#[test]
fn workspace_group_reports_usage_and_rejects_unknown_subcommands() {
    let directory = write_workspace_fixture();
    for arguments in [
        vec!["workspace"],
        vec!["workspace", "bogus"],
        vec!["ws", "bogus"],
    ] {
        let output = command()
            .current_dir(directory.path())
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
    } // Both the group and the `ws` alias accept help.
    for arguments in [vec!["workspace", "--help"], vec!["ws", "--help"]] {
        let output = command()
            .current_dir(directory.path())
            .args(&arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert!(String::from_utf8(output.stdout).unwrap().contains("list"));
    }
}

/// A duplicate key inside a map-shaped section is not a duplicate struct field,
/// so the deserializer keeps the last value instead of rejecting the document.
/// This matches duplicate task names, which behave the same way, and is pinned
/// here so the shadowed member is still reported rather than silently dropped.
#[test]
fn a_duplicate_alias_key_keeps_the_last_value_and_still_lists_the_shadowed_member() {
    let directory = TempDir::new().unwrap();
    for member in ["a", "b"] {
        let path = directory.path().join(member);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("neoenv.yaml"), "format_version: 1\n").unwrap();
    }
    fs::write(
        directory.path().join("neoenv.yaml"),
        "format_version: 1\nworkspace:\n  members:\n    - a\n    - b\n  aliases:\n    x: a\n    x: b\n",
    )
    .unwrap();

    let output = command()
        .current_dir(directory.path())
        .arg("workspace")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    // The command reports canonical member roots, which differ from the
    // `TempDir` spelling wherever the system temp directory is a symlink.
    let canonical = fs::canonicalize(directory.path()).unwrap();
    // `x` resolves to the last declared value, and the shadowed member is still
    // listed with an empty alias.
    assert!(stdout.starts_with(&format!("x\t{}\tb\n", canonical.join("b").display())));
    assert!(stdout.ends_with(&format!("\t{}\ta\n", canonical.join("a").display())));
}

/// A project whose `default` task exists, so a bare `run` has something to
/// select, plus a `show` task that prints resolved environment values.
fn write_override_project() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join("neoenv.yaml"),
        "format_version: 1\nenv:\n  FROM_PROJECT: project-value\ntasks:\n  default:\n    uses: portable\n    run: 'printf default-ran'\n  show:\n    uses: portable\n    run: 'echo \"PROJECT=${FROM_PROJECT} EXTRA=${EXTRA} DOTENV=${DOTENV_ONLY} DOTENV_TWO=${DOTENV_TWO}\"'\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("extra.env"),
        "DOTENV_ONLY=from-dotenv\nDOTENV_TWO=from-dotenv-two\n",
    )
    .unwrap();
    directory
}

fn run_in(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    support::approve_tree(config_home(), directory);
    command()
        .current_dir(directory)
        .args(arguments)
        // These tests assert on resolved output, so an inherited project or
        // context would change the result without changing the arguments.
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap()
}

#[test]
fn a_bare_run_selects_the_default_task_and_an_explicit_name_still_wins() {
    let directory = write_override_project();

    let bare = run_in(directory.path(), &["run"]);
    assert_eq!(bare.status.code(), Some(0), "{bare:?}");
    assert!(String::from_utf8_lossy(&bare.stdout).contains("default-ran"));

    let named = run_in(directory.path(), &["run", "show"]);
    assert_eq!(named.status.code(), Some(0), "{named:?}");
    assert!(String::from_utf8_lossy(&named.stdout).contains("PROJECT=project-value"));
}

#[test]
fn env_overrides_apply_on_either_side_of_the_task_name() {
    let directory = write_override_project();
    for arguments in [
        &["run", "show", "-e", "EXTRA=hello"][..],
        &["run", "-e", "EXTRA=hello", "show"][..],
        &["task", "run", "show", "--env", "EXTRA=hello"][..],
    ] {
        let output = run_in(directory.path(), arguments);
        assert_eq!(output.status.code(), Some(0), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("EXTRA=hello"),
            "{arguments:?}: {output:?}"
        );
    }
}

#[test]
fn env_values_are_literal_and_the_last_repeated_key_wins() {
    let directory = write_override_project();
    for value in ["  späce -dash  ", "a=b=c", "trailing ", "0100"] {
        let output = run_in(
            directory.path(),
            &["run", "show", "-e", &format!("EXTRA={value}")],
        );
        assert_eq!(output.status.code(), Some(0), "{value:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("EXTRA={value}")),
            "{value:?}: {output:?}"
        );
    }
    let repeated = run_in(
        directory.path(),
        &["run", "show", "-e", "EXTRA=one", "-e", "EXTRA=two"],
    );
    assert!(
        String::from_utf8_lossy(&repeated.stdout).contains("EXTRA=two"),
        "{repeated:?}"
    );
    assert!(!String::from_utf8_lossy(&repeated.stdout).contains("EXTRA=one"));
}

#[test]
fn dotenv_overrides_are_repeatable_ordered_and_beat_by_env() {
    let directory = write_override_project();
    fs::write(
        directory.path().join("second.env"),
        "DOTENV_TWO=from-second\n",
    )
    .unwrap();

    let output = run_in(
        directory.path(),
        &["run", "show", "-E", "extra.env", "-E", "second.env"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The task prints `DOTENV=${DOTENV_ONLY}`, so the value appears under the
    // `DOTENV` label.
    assert!(stdout.contains("DOTENV=from-dotenv"), "{stdout}");
    // A later `-E` wins for the same key.
    assert!(stdout.contains("DOTENV_TWO=from-second"), "{stdout}");

    // `-e` is applied after `-E`, so an explicit assignment wins.
    let overridden = run_in(
        directory.path(),
        &[
            "run",
            "show",
            "-E",
            "extra.env",
            "-e",
            "DOTENV_ONLY=from-flag",
        ],
    );
    assert!(
        String::from_utf8_lossy(&overridden.stdout).contains("DOTENV=from-flag"),
        "{overridden:?}"
    );
}

#[test]
fn exec_applies_the_same_project_selection_and_overrides() {
    let directory = write_override_project();
    let output = run_in(
        directory.path(),
        &[
            "exec",
            "-e",
            "CHILD_ONLY=set",
            "-E",
            "extra.env",
            "sh",
            "-c",
            "printf %s \"$CHILD_ONLY:$DOTENV_ONLY:$FROM_PROJECT\"",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "set:from-dotenv:project-value"
    );
}

#[test]
fn exec_leaves_the_programs_own_flags_alone() {
    let directory = write_override_project();
    // `sh -c` must reach the child, not be claimed as an nenv option.
    let output = run_in(directory.path(), &["exec", "sh", "-c", "printf %s \"$0\""]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    #[cfg(unix)]
    assert_eq!(stdout, "sh");
    #[cfg(windows)]
    assert!(stdout.contains("bash") || stdout.contains("sh"), "{stdout}");

    // `--` also ends nenv parsing for exec.
    let separated = run_in(directory.path(), &["exec", "--", "sh", "-c", "printf ok"]);
    assert_eq!(separated.status.code(), Some(0), "{separated:?}");
    assert_eq!(String::from_utf8(separated.stdout).unwrap(), "ok");
}

#[test]
fn arguments_after_the_task_name_or_separator_belong_to_the_task() {
    let directory = write_override_project();
    // `-e` after the task name is still nenv's on `run`, which is the
    // established grammar; the separator is what hands arguments to the task.
    let output = run_in(
        directory.path(),
        &["run", "show", "--", "-e", "EXTRA=passthrough"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `-e` after `--` was not claimed by nenv, so `EXTRA` stayed unset.
    assert!(stdout.contains("EXTRA= DOTENV="), "{stdout}");
    assert!(stdout.contains(" -e EXTRA=passthrough"), "{stdout}");

    #[cfg(unix)]
    {
        // The literal pair really did reach the task, proven by a task that prints
        // both the interpolated value and its arguments using POSIX spelling.
        let echoing = TempDir::new().unwrap();
        fs::write(
            echoing.path().join("neoenv.yaml"),
            "format_version: 1\ntasks:\n  show:\n    uses: portable\n    run: 'echo \"extra=[${EXTRA}]\"'\n",
        )
        .unwrap();
        let output = run_in(
            echoing.path(),
            &["run", "show", "--", "-e", "EXTRA=passthrough"],
        );
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // `${EXTRA}` interpolates to nothing, and that is the proof: the `-e` after
        // `--` reached the task as a literal argument and never set the variable.
        assert!(stdout.contains("extra=[] -e EXTRA=passthrough"), "{stdout}");
    }
}

#[test]
fn project_selection_works_for_run_and_exec_including_workspace_aliases() {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let member = "packages/api";
    fs::create_dir_all(root.join(member)).unwrap();
    fs::write(
        root.join(member).join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  check:\n    uses: portable\n    run: 'printf member-ran'\n",
    )
    .unwrap();
    fs::write(
        root.join("neoenv.yaml"),
        "format_version: 1\nworkspace:\n  members:\n    - packages/api\n  aliases:\n    api: packages/api\ntasks:\n  check:\n    uses: portable\n    run: 'printf root-ran'\n",
    )
    .unwrap();

    for arguments in [
        ["run", "--project", "api", "check"],
        ["run", "-p", "api", "check"],
        ["run", "check", "-p", "api"],
    ] {
        let output = run_in(root, &arguments);
        assert_eq!(output.status.code(), Some(0), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("member-ran"),
            "{arguments:?}: {output:?}"
        );
    }

    // A path to the configuration file works as well as an alias.
    let by_path = run_in(root, &["run", "-p", "packages/api/neoenv.yaml", "check"]);
    assert!(
        String::from_utf8_lossy(&by_path.stdout).contains("member-ran"),
        "{by_path:?}"
    );
}

#[test]
fn invalid_overrides_fail_with_stable_diagnostics() {
    let directory = write_override_project();
    let cases: [(&[&str], i32, &str); 6] = [
        (
            &["run", "show", "-e", "BAD-KEY=1"],
            3,
            "invalid environment key",
        ),
        (&["run", "show", "-e", "NOEQUALS"], 3, "must be KEY=VALUE"),
        (
            &["run", "-E", "does-not-exist.env", "show"],
            3,
            "required dotenv file was not found",
        ),
        (&["run", "-p"], 2, "missing value for --project"),
        (
            &["run", "-p", "a", "-p", "b", "show"],
            2,
            "duplicate --project",
        ),
        (&["run", "--project", "nope", "show"], 4, "does not exist"),
    ];
    for (arguments, code, expected) in cases {
        let output = run_in(directory.path(), arguments);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{arguments:?}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{arguments:?}: {output:?}"
        );
    }
}

#[test]
fn run_local_overrides_never_reach_the_project_or_the_caller() {
    let directory = write_override_project();

    // The caller's own environment is untouched: the child sees the override,
    // and nenv's own process never had it.
    let child = run_in(
        directory.path(),
        &[
            "exec",
            "-e",
            "ONLY_IN_CHILD=1",
            "sh",
            "-c",
            "printf %s \"$ONLY_IN_CHILD\"",
        ],
    );
    assert_eq!(String::from_utf8(child.stdout).unwrap(), "1");

    // `inspect` reports only declared configuration, so a CLI value never
    // acquires a fabricated source span or starts appearing in JSON output.
    let inspected = command()
        .current_dir(directory.path())
        .arg("inspect")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(0), "{inspected:?}");
    let document: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    let keys = document["environment"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["key"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(keys.contains(&"FROM_PROJECT"), "{keys:?}");
    assert!(!keys.contains(&"ONLY_IN_CHILD"), "{keys:?}");
    assert!(!keys.contains(&"EXTRA"), "{keys:?}");
}

#[test]
fn context_precedence_is_explicit_then_environment_then_project_then_default() {
    let directory = write_override_project();
    // The project declares no context, so an unknown explicit context falls back
    // to `default` rather than failing. This pins the documented precedence and
    // the existing fallback, which this ticket deliberately did not change.
    let output = command()
        .current_dir(directory.path())
        .arg("run")
        .arg("show")
        .arg("--context")
        .arg("not-a-declared-context")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let selected = run_in(directory.path(), &["run", "show", "--context", "default"]);
    assert_eq!(selected.status.code(), Some(0), "{selected:?}");

    // `--context` is still rejected for commands that select no task context.
    let rejected = run_in(directory.path(), &["validate", "--context", "default"]);
    assert_eq!(rejected.status.code(), Some(2), "{rejected:?}");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("--context"),
        "{rejected:?}"
    );
}

/// A project whose task declares its own `dotenv` and `env`, so the interaction
/// between a task's declared values and the command-line overrides is
/// observable.
fn write_declaring_project() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join("neoenv.yaml"),
        "format_version: 1\nenv:\n  FROM_PROJECT: project-value\ntasks:\n  show:\n    uses: portable\n    env:\n      SHARED: from-task-env\n      TASK_ONLY: task-only\n    run: 'printf \"SHARED=${SHARED} TASK_ONLY=${TASK_ONLY} FROM_PROJECT=${FROM_PROJECT} REF=${REF}\"'\n",
    )
    .unwrap();
    directory
}

#[test]
fn command_line_env_is_the_last_word_over_a_tasks_own_env() {
    let directory = write_declaring_project();

    // Unset: the task's declared value is used and its own key is visible.
    let plain = run_in(directory.path(), &["run", "show"]);
    assert_eq!(plain.status.code(), Some(0), "{plain:?}");
    let stdout = String::from_utf8_lossy(&plain.stdout);
    assert!(stdout.contains("SHARED=from-task-env"), "{stdout}");
    assert!(stdout.contains("TASK_ONLY=task-only"), "{stdout}");

    // Set: `-e` beats the task's own `env:`, which is the whole point of
    // applying overrides last.
    let overridden = run_in(directory.path(), &["run", "show", "-e", "SHARED=from-flag"]);
    assert_eq!(overridden.status.code(), Some(0), "{overridden:?}");
    let stdout = String::from_utf8_lossy(&overridden.stdout);
    assert!(stdout.contains("SHARED=from-flag"), "{stdout}");
    assert!(!stdout.contains("SHARED=from-task-env"), "{stdout}");
}

#[test]
fn a_dotenv_file_interpolates_against_the_project_environment() {
    let directory = write_declaring_project();
    fs::write(
        directory.path().join("ref.env"),
        "REF=prefix-${FROM_PROJECT}\n",
    )
    .unwrap();

    // The reference must resolve to the declared project value, not an empty
    // string, which is what an unseeded interpolation base would produce.
    let output = run_in(directory.path(), &["run", "show", "-E", "ref.env"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("REF=prefix-project-value"), "{stdout}");

    // The same on exec, where the base is the inherited environment.
    let exec = run_in(
        directory.path(),
        &["exec", "-E", "ref.env", "sh", "-c", "printf %s \"$REF\""],
    );
    assert_eq!(exec.status.code(), Some(0), "{exec:?}");
    assert_eq!(
        String::from_utf8(exec.stdout).unwrap(),
        "prefix-project-value"
    );
}

#[test]
fn a_task_may_not_bind_an_option_the_cli_claims() {
    let directory = TempDir::new().unwrap();
    // Every option `run` claims after the task name is reserved, so a task that
    // binds one fails at validation instead of silently losing its input. `-c` is
    // deliberately not reserved: `--context` has no short form, so `-c` belongs
    // to the task.
    let reserved: [(&str, &str); 8] = [
        ("long", "        long: env\n"),
        ("long", "        long: project\n"),
        ("long", "        long: dotenv\n"),
        ("short", "        short: e\n"),
        ("short", "        short: E\n"),
        ("short", "        short: p\n"),
        ("short", "        short: h\n"),
        ("free", "        short: c\n"),
    ];
    for (name, declaration) in reserved {
        fs::write(
            directory.path().join("neoenv.yaml"),
            format!(
                "format_version: 1\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n    inputs:\n      value:\n        type: string\n{declaration}"
            ),
        )
        .unwrap();
        let output = run_in(directory.path(), &["validate"]);
        if name == "free" {
            // `-c` stays available to a task.
            assert_eq!(output.status.code(), Some(0), "{declaration}: {output:?}");
            continue;
        }
        assert_eq!(output.status.code(), Some(3), "{declaration}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reserved"),
            "{declaration}: {output:?}"
        );
    }
}

#[test]
fn an_option_is_rejected_where_a_value_is_required() {
    let directory = write_override_project();
    // `--dry-run` here is a forgotten argument, not a project path.
    for arguments in [
        &["run", "-p", "--dry-run", "show"][..],
        &["run", "-E", "--dry-run", "show"][..],
        &["run", "-e", "--dry-run", "show"][..],
    ] {
        let output = run_in(directory.path(), arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("does not accept the option"),
            "{arguments:?}: {output:?}"
        );
    }
}

#[test]
fn a_malformed_env_token_is_never_echoed() {
    let directory = write_override_project();
    // A token with no `=` carries the whole payload, so echoing it back would
    // print a value the caller never meant to expose on stderr or in JSON.
    // Naming an invalid *key* is different and stays: a key is not a secret and
    // the diagnostic is useless without it.
    for (arguments, fragment) in [
        (
            ["run", "show", "-e", "SUPERSECRETNOEQUALS"],
            "SUPERSECRETNOEQUALS",
        ),
        (
            ["run", "show", "-e", "BAD-KEY=SUPERSECRETVALUE"],
            "SUPERSECRETVALUE",
        ),
    ] {
        let output = run_in(directory.path(), &arguments);
        assert_eq!(output.status.code(), Some(3), "{arguments:?}: {output:?}");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !combined.contains(fragment),
            "{arguments:?} leaked {fragment}: {combined}"
        );
    }
}

#[test]
fn context_is_rejected_for_exec_rather_than_silently_discarded() {
    let directory = write_override_project();
    // `exec` resolves an executable, never a task, so there is no context to
    // select. Accepting the flag and ignoring it would be worse than this.
    let output = run_in(
        directory.path(),
        &["exec", "--context", "default", "sh", "-c", "printf ok"],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--context"),
        "{output:?}"
    );
}

/// The Go-Neofile compatibility profile, exercised through the compiled binary.
///
/// The library tests cover the normalization rules; these cover the parts only
/// the binary can show: that `--profile` is a global option, that it reaches
/// every command that reads a configuration document, and that a declared secret
/// does not reach any output stream.
mod go_compat_profile {
    use super::{TempDir, command, fs};

    fn project(body: &str) -> (TempDir, std::path::PathBuf) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("neoenv.yaml");
        fs::write(&path, body).unwrap();
        // `run_in` points `XDG_CONFIG_HOME` here, and the runtime requires the
        // directory to exist.
        fs::create_dir_all(directory.path().join("xdg-config-home")).unwrap();
        (directory, path)
    }

    /// Runs the binary with a controlled configuration environment.
    ///
    /// The user configuration is the one variable that can change a result
    /// without changing the arguments: `user_config_path` reads
    /// `$XDG_CONFIG_HOME/neoenv/neoenv.yaml`, falling back to
    /// `$HOME/.config/neoenv/neoenv.yaml`, and a developer's real file would
    /// otherwise be merged into every result here.
    ///
    /// It is *redirected* rather than stripped. Removing `HOME` looks like the
    /// stronger fix and is not: the runtime needs a user configuration
    /// directory to exist and fails with "cannot determine user configuration
    /// directory" when it cannot find one, so stripping it turns a controlled
    /// result into an unrelated failure. Pointing `XDG_CONFIG_HOME` at an empty
    /// directory inside the test's own temp tree controls the contents and
    /// leaves the environment valid.
    /// Runs the binary with a controlled configuration environment.
    ///
    /// The user configuration is the one variable that can change a result
    /// without changing the arguments: `user_config_path` reads
    /// `$XDG_CONFIG_HOME/neoenv/neoenv.yaml`, and a developer's real file would
    /// otherwise be merged into every result here.
    ///
    /// It is *redirected*, which is the house convention in this file, rather
    /// than stripped. Removing `HOME` looks like the stronger fix and is not:
    /// the runtime needs a user configuration directory to exist and fails with
    /// "cannot determine user configuration directory" when it cannot find one,
    /// so stripping it turns a controlled result into an unrelated failure.
    /// Pointing `XDG_CONFIG_HOME` at an empty directory controls the contents
    /// and leaves the environment valid.
    ///
    /// `NEOENV_CAPABILITY_POLICY` is removed because a policy file changes
    /// which capabilities a task is granted.
    fn run_in(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
        let mut command = command();
        command.current_dir(directory);
        for variable in [
            "NEOENV_PROJECT",
            "NEOENV_CONTEXT",
            "NEOENV_CAPABILITY_POLICY",
            "NEOENV_CONFIG_HOME",
        ] {
            command.env_remove(variable);
        }
        command
            .env("XDG_CONFIG_HOME", directory.join("xdg-config-home"))
            .args(arguments)
            .output()
            .unwrap()
    }

    #[test]
    fn a_go_document_is_rejected_without_the_profile_and_read_with_it() {
        let (directory, _) = project("config:\n  context: production\nenv:\n  - PORT=8080\n");
        let strict = run_in(directory.path(), &["inspect"]);
        assert_ne!(
            strict.status.code(),
            Some(0),
            "the strict v1 schema must still reject a Go `config:` section"
        );
        assert!(String::from_utf8_lossy(&strict.stderr).contains("unknown field `config`"));

        // Accepted before the command as well as after it: it is a global option.
        for arguments in [
            vec!["--profile", "go", "inspect"],
            vec!["inspect", "--profile", "go"],
        ] {
            let output = run_in(directory.path(), &arguments);
            assert_eq!(output.status.code(), Some(0), "{arguments:?}: {output:?}");
        }
    }

    #[test]
    fn a_declared_secret_is_redacted_and_a_plain_value_is_not() {
        let (directory, _) = project("env:\n  - PORT=8080\n  - DATABASE_URL:postgres://host/db\n");
        let output = run_in(directory.path(), &["--profile", "go", "inspect"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("PORT=8080"), "{text}");
        assert!(text.contains("[redacted]"), "{text}");
        assert!(
            !text.contains("postgres://"),
            "a `KEY:VALUE` entry is a declared secret and must not print: {text}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("postgres://"),
            "the secret reached stderr: {:?}",
            output.stderr
        );
    }

    #[test]
    fn a_secret_marked_by_name_still_redacts_under_the_go_profile() {
        // The name heuristic keeps working, so a half-migrated file is no less
        // safe than a native one.
        let (directory, _) = project("env:\n  - API_TOKEN=plain-looking\n");
        let output = run_in(directory.path(), &["--profile", "go", "inspect"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("[redacted]"), "{text}");
        assert!(!text.contains("plain-looking"), "{text}");
    }

    #[test]
    fn an_untranslatable_go_section_is_named_rather_than_dropped() {
        // `use:` is no longer here: it is read, not refused. The sections a Go
        // reference does not execute are, and `use:` is not one of them.
        // **One case left, and it is a loop over one element.** That is
        // deliberate: `use:`, `inventories:` and `ship:` were all in this table and
        // all left, and three single-case tests would have been three places to
        // re-derive why each one left. The comments below are the record of that.
        //
        // Each was refused on the grounds that the Go reference does not execute it
        // either. True, and the wrong reason for all three: the reader had nowhere
        // to put the construct. `use:` has a `use_block` reader, `inventories:` has
        // an `Inventory`, and `ship:` has a `DeploymentDefinition` -- and a
        // declared host authorises nothing without a `connect` grant, so the trust
        // decision is unchanged. **A refusal is only right while there is nowhere to
        // put the thing.**
        // `inventories:` was here and is not any more. Refusing it because
        // the Go reference does not execute it either was true and was the
        // wrong reason: the reader had nowhere to put the hosts. It has an
        // `Inventory` now, and a declared host authorises nothing without a
        // `connect` grant, so the trust decision is unchanged.
        // `ship` is not here any more. It was refused on the grounds that the Go
        // reference does not execute it either -- true, and the wrong reason for
        // the same reason `inventories` left: the reader had nowhere to put the
        // deployments, and it has somewhere now. A Go `ship:` section is carried
        // through the normalizer.
        let (body, expected) = ("config:\n  external: /elsewhere\n", "config.external");
        let (directory, _) = project(body);
        let output = run_in(directory.path(), &["--profile", "go", "inspect"]);
        assert_eq!(output.status.code(), Some(3), "{body}: {output:?}");
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(expected), "{body} produced: {message}");
    }

    #[test]
    fn the_json_inspection_document_reports_the_normalized_model() {
        // The migration is verifiable: the same document read natively and
        // through the Go profile produces the same normalized model.
        let (go_directory, _go_path) = project("env:\n  - PORT=8080\n");
        let (native_directory, _) = project("format_version: 1\nenv:\n  PORT: \"8080\"\n");
        let go = run_in(
            go_directory.path(),
            &["--profile", "go", "inspect", "--format", "json"],
        );
        let native = run_in(native_directory.path(), &["inspect", "--format", "json"]);
        assert_eq!(go.status.code(), Some(0), "{go:?}");
        assert_eq!(native.status.code(), Some(0), "{native:?}");

        let read = |output: &std::process::Output| {
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("a JSON inspection document");
            let environment = value["environment"]
                .as_array()
                .expect("an environment array");
            environment
                .iter()
                .map(|entry| {
                    (
                        entry["key"].as_str().unwrap_or_default().to_owned(),
                        entry["value"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(read(&go), read(&native));
        assert_eq!(read(&go), vec![("PORT".to_owned(), "8080".to_owned())]);
    }

    #[test]
    fn an_invalid_profile_value_is_a_usage_error() {
        let (directory, _) = project("format_version: 1\n");
        let output = run_in(directory.path(), &["--profile", "nope", "inspect"]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid --profile value"));
    }

    #[test]
    fn a_missing_profile_value_is_a_usage_error() {
        let (directory, _) = project("format_version: 1\n");
        let output = run_in(directory.path(), &["--profile"]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("missing value for --profile"));
    }

    #[test]
    fn the_profile_is_documented_only_where_it_is_honored() {
        // Claiming an option on a command that ignores it is the #497
        // option-claim class, so the two lists are checked from both sides.
        //
        // A project is present because `task <subcommand> --help` resolves the
        // project before rendering help, so an empty directory would exit 4
        // instead of printing anything. That is pre-existing behavior, not
        // something this profile introduced.
        let directory = TempDir::new().unwrap();
        fs::write(
            directory.path().join("neoenv.yaml"),
            "format_version: 1\ntasks:\n  show:\n    uses: portable\n    run: 'true'\n",
        )
        .unwrap();
        // Each entry is a full argument list, not a joined command string:
        // `Command::args` does not word-split, so `"task list"` would arrive as
        // one argument and parse as a task named `task list`.
        for honors in [
            &["validate"][..],
            &["inspect"][..],
            &["run"][..],
            &["task", "list"][..],
            &["task", "run"][..],
            &["task", "plan"][..],
            &["task", "help"][..],
            &["task", "complete"][..],
            &["workspace", "list"][..],
        ] {
            let mut arguments = honors.to_vec();
            arguments.push("--help");
            let output = run_in(directory.path(), &arguments);
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                text.contains("--profile"),
                "{honors:?} does not document it: status={:?} out={:?} err={:?}",
                output.status.code(),
                output.stdout,
                output.stderr
            );
        }
        for ignores in [
            &["remote", "list"][..],
            &["trust", "list"][..],
            &["self", "init"][..],
        ] {
            let mut arguments = ignores.to_vec();
            arguments.push("--help");
            let output = run_in(directory.path(), &arguments);
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                !text.contains("--profile"),
                "{ignores:?} documents an option it does not honor: {text}"
            );
        }
    }
}

/// The Go task-field spellings from #499, exercised through the compiled binary.
///
/// The library tests cover normalization; the two here that matter are the ones
/// only a real process can answer: that a top-level `timeout` still kills the
/// whole process tree, and that a mapping `needs` actually drives run order.
///
/// Gated because the fixtures shell out to `sh`, `echo`, and `exit`. Every other
/// POSIX test in this file carries the same gate; without it the whole module
/// fails to compile on Windows, which this host cannot check.
#[cfg(unix)]
mod go_task_fields {
    use super::{TempDir, command, fs};

    fn project(body: &str) -> TempDir {
        let directory = TempDir::new().unwrap();
        fs::write(
            directory.path().join("neoenv.yaml"),
            format!("format_version: 1\n{body}"),
        )
        .unwrap();
        // Inside this test's own temp tree, not a fixed name in the shared temp
        // root: two tests running at once would otherwise collide.
        fs::create_dir_all(directory.path().join("xdg-config-home")).unwrap();
        directory
    }

    /// Redirects rather than strips the user configuration directory; see the
    /// note on `go_compat_profile::run_in` for why stripping `HOME` is wrong.
    fn run_in(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
        let mut command = command();
        command.current_dir(directory);
        for variable in [
            "NEOENV_PROJECT",
            "NEOENV_CONTEXT",
            "NEOENV_CAPABILITY_POLICY",
            "NEOENV_CONFIG_HOME",
        ] {
            command.env_remove(variable);
        }
        command
            .env("XDG_CONFIG_HOME", directory.join("xdg-config-home"))
            .args(arguments)
            .output()
            .unwrap()
    }

    /// Only the tasks a run actually executed, in the order it executed them.
    ///
    /// The report lists every task with an outcome, so filtering on the lines
    /// the runner echoes is what distinguishes "ran" from "was planned".
    fn executed(output: &std::process::Output, names: &[&str]) -> Vec<String> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| names.contains(line))
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn a_top_level_timeout_kills_the_whole_process_tree() {
        // The ticket's requirement is that the Go spelling behaves *exactly*
        // like `with.timeout`, and what `with.timeout` guarantees is that a
        // nested grandchild dies too. The portable runner already wraps the
        // command in a shell, so naming an inner `sh` gives three levels --
        // runner, shell, inner shell, sleep -- and a kill that only reaches the
        // direct child leaves the sleep alive holding the pipe open, which is
        // what the elapsed bound catches.
        for field in ["timeout: 1s", "with:\n      timeout: 1s"] {
            let directory = project(&format!(
                "tasks:\n  runaway:\n    uses: portable\n    run: 'sh -c \"sleep 45\"'\n    {field}\n"
            ));
            let started = std::time::Instant::now();
            let output = run_in(directory.path(), &["run", "runaway"]);
            let elapsed = started.elapsed();
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("TimedOut"), "{field}: {text}");
            assert!(
                elapsed < std::time::Duration::from_secs(20),
                "{field} took {elapsed:?}; the tree was not killed"
            );
        }
    }

    #[test]
    fn a_top_level_timeout_is_rejected_when_it_cannot_be_parsed() {
        let directory =
            project("tasks:\n  a:\n    uses: portable\n    run: 'true'\n    timeout: soon\n");
        let output = run_in(directory.path(), &["run", "a"]);
        assert_ne!(output.status.code(), Some(0), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("timeout"),
            "{output:?}"
        );
    }

    #[test]
    fn a_mapping_needs_drives_the_run_in_document_order() {
        // Needs become graph edges, so order is run order. Every Go spelling has
        // to reach the same place, or a migrated file silently reorders.
        // The first two are the reference's shapes: a sequence of mappings with
        // per-need options, and a sequence of bare names. The third is the
        // mapping-of-names extension, kept so a half-migrated file still reads.
        for field in [
            "needs:\n      - id: zzz\n        parallel: false\n      - id: aaa",
            "needs:\n      - zzz\n      - aaa",
            "deps: [zzz, aaa]",
            "dependencies: [zzz, aaa]",
            "needs:\n      zzz: null\n      aaa: null",
        ] {
            let directory = project(&format!(
                "tasks:\n  all:\n    uses: portable\n    run: 'echo all'\n    {field}\n  zzz:\n    uses: portable\n    run: 'echo zzz'\n  aaa:\n    uses: portable\n    run: 'echo aaa'\n"
            ));
            let output = run_in(directory.path(), &["run", "all"]);
            assert_eq!(output.status.code(), Some(0), "{field}: {output:?}");
            assert_eq!(
                executed(&output, &["zzz", "aaa", "all"]),
                vec!["zzz".to_owned(), "aaa".to_owned(), "all".to_owned()],
                "{field} did not run in document order"
            );
        }
    }

    #[test]
    fn a_failed_dependency_still_stops_the_dependent() {
        // Failure propagation has to survive the mapping form, not just the
        // list form: an edge that is created but does not propagate would let
        // `all` run after `zzz` failed.
        let directory = project(
            "tasks:\n  all:\n    uses: portable\n    run: 'echo all'\n    needs:\n      zzz: null\n  zzz:\n    uses: portable\n    run: 'exit 3'\n",
        );
        let output = run_in(directory.path(), &["run", "all"]);
        assert_ne!(output.status.code(), Some(0), "{output:?}");
        assert!(
            !executed(&output, &["all"]).contains(&"all".to_owned()),
            "the dependent ran after its dependency failed: {output:?}"
        );
    }

    #[test]
    fn a_needs_edge_to_a_missing_task_is_a_diagnostic() {
        let directory = project(
            "tasks:\n  all:\n    uses: portable\n    run: 'echo all'\n    deps: [absent]\n",
        );
        let output = run_in(directory.path(), &["run", "all"]);
        assert_ne!(output.status.code(), Some(0), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("absent"),
            "a missing edge must be named: {output:?}"
        );
    }

    #[test]
    fn the_predicate_and_envfile_spellings_are_accepted_end_to_end() {
        let directory = project(
            "tasks:\n  show:\n    uses: portable\n    run: 'echo show'\n    predicate: os == linux\n    envfile: .env\n",
        );
        fs::write(directory.path().join(".env"), "SHOW=1\n").unwrap();
        let output = run_in(directory.path(), &["run", "show"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        #[cfg(target_os = "linux")]
        assert!(executed(&output, &["show"]).contains(&"show".to_owned()));
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!executed(&output, &["show"]).contains(&"show".to_owned()));
            assert!(String::from_utf8_lossy(&output.stdout).contains("show Skipped"));
        }
    }

    #[test]
    fn a_hooks_shorthand_parses_and_reports_its_edges() {
        // #505: the edges are parsed and displayed but the scheduler does not
        // consume them yet, so the run order is *not* asserted here. Asserting
        // it would encode a bug as an expectation. What is asserted is that the
        // spelling is accepted and that the two edges are visible, which is
        // what makes #505 observable.
        let directory = project(
            "tasks:\n  a:\n    uses: portable\n    run: 'echo a'\n    hooks: true\n  before:\n    uses: portable\n    run: 'echo before'\n  after:\n    uses: portable\n    run: 'echo after'\n",
        );
        let output = run_in(directory.path(), &["validate"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let help = run_in(directory.path(), &["task", "help", "a"]);
        let text = String::from_utf8_lossy(&help.stdout);
        assert!(text.contains("before"), "{text}");
        assert!(text.contains("after"), "{text}");
    }
}

/// A mistyped context must be rejected, not resolved to the default-context task.
///
/// The reference does this the other way: `runner.go` looks up `name:context` and
/// falls back to `name`, so a typo runs the wrong thing and reports success. The
/// black-box property is that the *command* refuses, for every task subcommand
/// and every source of the context -- a test of `validate_context` alone would
/// not see whether the wiring is there.
mod unknown_context {
    use super::{TempDir, command, fs};

    fn project(body: &str) -> TempDir {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("neoenv.yaml"), body).unwrap();
        // The `prod` dotenv the fixtures below scope. Written into the test's own
        // temp tree, never into a shared root.
        fs::write(directory.path().join(".env.prod"), "FROM_PROD=prod-value\n").unwrap();
        directory
    }

    // `uses: shell` and an echoed variable, because the point of the positive
    // half is *which file loaded*: a portable task's `run` is a literal string
    // that never expands `$FROM_PROD`, so it would have proved nothing.
    const CONTEXTS: &str = "format_version: 1\ndotenv:\n  - path: .env.prod\n    filter:\n      contexts: [prod]\ntasks:\n  build:\n    uses: shell\n    run: 'echo task=build FROM_PROD=[$FROM_PROD]'\n  build:prod:\n    uses: shell\n    run: 'echo task=build:prod FROM_PROD=[$FROM_PROD]'\n";

    /// Every task subcommand, because the context is resolved before dispatch and
    /// all of them share that step. `task help` and `task plan` in particular are
    /// read-only, so a guard that only sat on `run` would look complete.
    #[test]
    fn every_task_command_rejects_a_context_the_project_does_not_use() {
        let directory = project(CONTEXTS);
        for arguments in [
            vec!["run", "build", "--context", "releae"],
            vec!["task", "run", "build", "--context", "releae"],
            vec!["task", "help", "build", "--context", "releae"],
            vec!["task", "plan", "build", "--context", "releae"],
        ] {
            let output = command()
                .current_dir(directory.path())
                .env_remove("NEOENV_PROJECT")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("NEOENV_CONTEXT")
                .args(&arguments)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success(),
                "{arguments:?} accepted a context it does not use"
            );
            // The message has to name what *is* available, or there is nothing to
            // correct toward.
            assert!(stderr.contains("it uses: prod"), "{arguments:?}: {stderr}");
        }
    }

    /// The environment is a second source of the context, and a typo there is as
    /// invisible as one on the command line.
    #[test]
    fn a_typo_from_the_environment_is_rejected_too() {
        let directory = project(CONTEXTS);
        let output = command()
            .current_dir(directory.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .env("NEOENV_CONTEXT", "releae")
            .args(["run", "build"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("it uses: prod"), "{stderr}");
    }

    /// A context the *project itself* configures is a declaration, even when no
    /// task has a variant for it.
    ///
    /// This is not a nicety. A project that sets `context: dev` and has only
    /// `build:prod` is perfectly coherent -- `dev` is a label, and the tasks run
    /// in the default context. Rejecting it would break every invocation, and the
    /// narrower rule is the whole reason this feature is safe to ship.
    #[test]
    fn a_context_the_project_configures_is_known_even_with_no_task_variant() {
        let directory = project(
            "format_version: 1\ncontext: dev\ntasks:\n  build:\n    uses: portable\n    run: 'echo default-build'\n  build:prod:\n    uses: portable\n    run: 'echo prod-build'\n",
        );
        let output = command()
            .current_dir(directory.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("NEOENV_CONTEXT")
            .args(["run", "build"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "a project-configured context must be accepted: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("default-build"));
        // And it is listed as available when some *other* name is asked for, which
        // is what makes the diagnostic actionable.
        let rejected = command()
            .current_dir(directory.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("NEOENV_CONTEXT")
            .args(["run", "build", "--context", "releae"])
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(stderr.contains("it uses: dev, prod"), "{stderr}");
    }

    /// The false positive that would make the feature unusable. Three shapes have
    /// to keep working: a known context, a task with no contextual variant, and a
    /// project that uses no contexts at all.
    #[test]
    fn a_valid_context_still_runs_and_a_project_without_contexts_is_untouched() {
        let directory = project(CONTEXTS);
        for (context, task) in [("prod", "build:prod"), ("default", "build")] {
            let output = command()
                .current_dir(directory.path())
                .env_remove("NEOENV_PROJECT")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("NEOENV_CONTEXT")
                .args(["run", "build", "--context", context])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "--context {context} was rejected: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains(&format!("task={task}")), "{stdout}");
            // The dotenv's `contexts:` filter has to see the same context the task
            // resolver used. It did not: the filter ran against the document's own
            // `context:` alone, so `--context prod` selected the `prod` *task*
            // while the filter saw the empty string -- the prod dotenv was not
            // loaded, and an unfiltered one was loaded regardless of the flag.
            assert_eq!(
                stdout.contains("FROM_PROD=[prod-value]"),
                context == "prod",
                "--context {context} loaded the wrong dotenv: {stdout}"
            );
        }
        // `NEOENV_CONTEXT` is the same input by another route and has to reach the
        // filter too. It was read *after* the project was loaded, so it reached
        // task selection and nothing else.
        for (label, context_env, argument) in [
            ("environment", "prod", None),
            ("environment loses to the flag", "prod", Some("default")),
        ] {
            let mut command = command();
            command
                .current_dir(directory.path())
                .env_remove("NEOENV_PROJECT")
                .env_remove("XDG_CONFIG_HOME")
                .env("NEOENV_CONTEXT", context_env)
                .args(["run", "build"]);
            if let Some(argument) = argument {
                command.args(["--context", argument]);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{label}: command failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.contains("FROM_PROD=[prod-value]"),
                argument.is_none(),
                "{label}: the wrong dotenv loaded: {stdout}"
            );
        }
        // A task with no `:prod` variant falls back, which is the reference's
        // behavior and the reason the fallback exists at all.
        let no_variant = project(
            "format_version: 1\ntasks:\n  deploy:\n    uses: portable\n    run: 'echo deployed'\n  build:prod:\n    uses: portable\n    run: 'echo built'\n",
        );
        let output = command()
            .current_dir(no_variant.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("NEOENV_CONTEXT")
            .args(["run", "deploy", "--context", "prod"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "a task with no variant must still run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // And a project with no contexts at all accepts anything, because there is
        // no set for the name to be wrong against.
        let bare = project(
            "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: 'echo ok'\n",
        );
        let output = command()
            .current_dir(bare.path())
            .env_remove("NEOENV_PROJECT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("NEOENV_CONTEXT")
            .args(["run", "build", "--context", "anything"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "a project with no contexts must accept any: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
