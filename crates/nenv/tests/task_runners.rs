//! Named task runners at the command boundary.
//!
//! These exercise the compiled binary with real `/bin/bash` and `/bin/sh`, so
//! they cover configuration parsing, plan validation, environment assembly, and
//! the process boundary together. The runtime unit tests use fake interpreters
//! to assert every argv shape without depending on what is installed.

use std::{fs, process::Command};

use tempfile::TempDir;

mod support;

fn command() -> support::TestCommand {
    support::TestCommand::new()
}

fn isolated(command: &mut support::TestCommand) {
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
}

fn run_in(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    let mut command = command();
    isolated(&mut command);
    command
        .current_dir(directory)
        .args(arguments)
        .output()
        .unwrap()
}

fn project(body: &str) -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("neoenv.yaml"), body).unwrap();
    directory
}

/// The on-disk `uv` path for the Linux targets the managed-runtime CLI tests
/// cover. Windows and macOS are deliberately not claimed here.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn managed_uv_binary(version_root: &std::path::Path) -> std::path::PathBuf {
    let target = if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    version_root.join(format!("uv-{target}")).join("uv")
}

#[cfg(unix)]
#[test]
fn bash_runner_executes_inline_script_with_args_after_dollar_zero() {
    let directory = project(
        "tasks:\n  check:\n    uses: bash\n    run: 'printf \"%s|%s|%s|%s\\n\" \"$0\" \"$1\" \"$2\" \"$3\"'\n    args: [one, two]\n",
    );
    let output = run_in(directory.path(), &["run", "check", "--", "three"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("neoenv-task|one|two|three"),
        "inline bash must keep declared args at $1: {stdout:?}"
    );
}

#[cfg(unix)]
#[test]
fn bash_runner_executes_a_source_file_with_its_path_as_dollar_zero() {
    let directory =
        project("tasks:\n  check:\n    uses: bash\n    source: script.sh\n    args: [one]\n");
    let script = directory.path().join("script.sh");
    fs::write(&script, "printf 'file:%s|%s\\n' \"$0\" \"$1\"\n").unwrap();
    let output = run_in(directory.path(), &["run", "check"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!(
            "file:{}|one",
            script.canonicalize().unwrap().display()
        )),
        "file mode must pass the resolved path: {stdout:?}"
    );
}

#[cfg(unix)]
#[test]
fn sh_runner_is_the_posix_shell_with_explicit_errexit() {
    let directory = project(
        "tasks:\n  check:\n    uses: sh\n    run: 'printf \"sh:%s|%s\\n\" \"$0\" \"$1\"'\n    args: [one]\n",
    );
    let output = run_in(directory.path(), &["run", "check"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("sh:neoenv-task|one"), "{stdout:?}");
}

#[test]
fn a_script_runner_with_both_run_and_source_is_refused_by_validate() {
    let directory = project(
        "tasks:\n  check:\n    uses: bash\n    run: 'echo inline'\n    source: script.sh\n",
    );
    let output = run_in(directory.path(), &["validate"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("exactly one of run") && stderr.contains("source"),
        "the diagnostic must name both sides: {stderr:?}"
    );
}

/// The legacy `use:` spelling works for a versioned runner too. This is the
/// spelling the request used, and the config parser has accepted `use:` as an
/// alias of `uses:` since before named runners existed.
#[test]
fn legacy_use_alias_selects_a_versioned_uv_runner() {
    let directory = project("tasks:\n  check:\n    use: 'uv@0.8.0'\n    run: 'print(1)'\n");
    let output = run_in(directory.path(), &["validate"]);
    assert!(output.status.success(), "{output:?}");

    let directory = project("tasks:\n  check:\n    use: uv\n    run: 'print(1)'\n");
    let output = run_in(directory.path(), &["validate"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("exact version"), "{stderr:?}");
}

#[test]
fn uv_without_an_exact_version_is_refused_by_validate() {
    for uses in ["uv", "uv@latest", "uv@^0.8"] {
        let directory = project(&format!(
            "tasks:\n  check:\n    uses: '{uses}'\n    run: 'print(1)'\n"
        ));
        let output = run_in(directory.path(), &["validate"]);
        assert!(!output.status.success(), "{uses}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("exact version"),
            "{uses} must name the requirement: {stderr:?}"
        );
    }
}

/// End-to-end proof that a missing managed version is not satisfied by a `uv`
/// on the task's PATH. The fake would leave a marker if anything executed it.
#[cfg(unix)]
#[test]
fn uv_runner_without_the_managed_version_does_not_execute_path_uv() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = project("tasks:\n  check:\n    uses: uv@0.8.0\n    run: 'print(1)'\n");
    let fake_path = TempDir::new().unwrap();
    let marker = directory.path().join("path-uv-ran");
    let fake_uv = fake_path.path().join("uv");
    fs::write(&fake_uv, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
    fs::set_permissions(&fake_uv, fs::Permissions::from_mode(0o755)).unwrap();
    let data_home = TempDir::new().unwrap();

    let mut command = command();
    isolated(&mut command);
    let output = command
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data_home.path())
        .env("PATH", fake_path.path())
        .args(["run", "check"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("uv@0.8.0") && stderr.contains("not installed"),
        "the refusal must name the exact version: {stderr:?}"
    );
    assert!(
        !marker.exists(),
        "a PATH uv must not be used when the managed version is missing"
    );
}

/// Whether an interpreter can be executed at all in this test environment.
/// A missing interpreter is reported as a visible skip by the tests that need a
/// real runtime, never silently treated as a pass.
fn available(program: &str) -> bool {
    available_with(program, &["--version"])
}

fn available_with(program: &str, arguments: &[&str]) -> bool {
    // Run the probe from a neutral directory. A mise shim invoked from this
    // repository's source tree refuses an untrusted `mise.toml`, while the same
    // shim under a task's temporary project directory works. The probe must see
    // what the task will see.
    let directory = TempDir::new().unwrap();
    Command::new(program)
        .args(arguments)
        .current_dir(directory.path())
        .output()
        .is_ok_and(|output| output.status.success())
}

/// `dotnet run --file` is an SDK capability, not merely a host capability.
/// Probe the run command's help so an older SDK skips instead of failing.
fn dotnet_run_file_supported() -> bool {
    let directory = TempDir::new().unwrap();
    let Ok(output) = Command::new("dotnet")
        .args(["run", "--help"])
        .current_dir(directory.path())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    help.contains("--file")
}

/// **The Node blocker.** `node -e script --version` prints Node's version and
/// never runs the script; the engine must put `--` before every task argument.
/// This asserts the script ran and that declared and CLI option-like arguments
/// arrived as script arguments.
#[test]
fn real_node_inline_runner_keeps_option_like_task_arguments_for_the_script() {
    if !available("node") {
        eprintln!("SKIPPED: node is not on PATH, so the real Node argument test did not run");
        return;
    }
    let directory = project(
        "tasks:\n  check:\n    uses: node\n    run: 'console.log(\"node-script-ran:\" + JSON.stringify(process.argv.slice(1)))'\n    args: [--declared-option, declared]\n",
    );
    let output = run_in(
        directory.path(),
        &["run", "check", "--", "--passed-option", "passed"],
    );
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(
            "node-script-ran:[\"--declared-option\",\"declared\",\"--passed-option\",\"passed\"]"
        ),
        "the script itself must run and receive every task argument: {stdout:?}"
    );
}

/// Bun's argument parser has the same option-like-argument hazard as Node's,
/// established here against the real binary rather than inferred from Node.
#[test]
fn real_bun_inline_runner_keeps_option_like_task_arguments_for_the_script() {
    if !available("bun") {
        eprintln!("SKIPPED: bun is not on PATH, so real Bun argument behaviour is unverified here");
        return;
    }
    let directory = project(
        "tasks:\n  check:\n    uses: bun\n    run: 'console.log(\"bun-script-ran:\" + JSON.stringify(process.argv.slice(1)))'\n    args: [--declared-option, declared]\n",
    );
    let output = run_in(
        directory.path(),
        &["run", "check", "--", "--passed-option", "passed"],
    );
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(
            "bun-script-ran:[\"--declared-option\",\"declared\",\"--passed-option\",\"passed\"]"
        ),
        "the script itself must run and receive every task argument: {stdout:?}"
    );
}

/// The real enumeration path must not turn an invalid receipt into a runnable
/// managed uv, and must not fall back to a PATH uv when it does not.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn an_invalid_managed_uv_receipt_fails_closed_without_path_fallback() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = project("tasks:\n  check:\n    uses: uv@0.8.0\n    run: 'print(1)'\n");
    let data_home = TempDir::new().unwrap();
    // `neoenv_directory(Data)` appends `neoenv` to NEOENV_DATA_HOME, and the
    // runtime data root is its `tools` child. The old path omitted `neoenv`,
    // so this test was not exercising the file the app reads.
    let version_root = data_home
        .path()
        .join("neoenv")
        .join("tools")
        .join("uv")
        .join("0.8.0");
    fs::create_dir_all(&version_root).unwrap();
    let binary = managed_uv_binary(&version_root);
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(version_root.join(".neoenv-uv-sha256"), "not-a-digest").unwrap();

    let fake_path = TempDir::new().unwrap();
    let marker = directory.path().join("path-uv-ran");
    let fake_uv = fake_path.path().join("uv");
    // Redirection, not `touch`: PATH is only the fake directory, so an external
    // command would itself fail to resolve.
    fs::write(&fake_uv, format!("#!/bin/sh\n: > {}\n", marker.display())).unwrap();
    fs::set_permissions(&fake_uv, fs::Permissions::from_mode(0o755)).unwrap();

    let mut command = command();
    isolated(&mut command);
    let output = command
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data_home.path())
        .env("PATH", fake_path.path())
        .args(["run", "check"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("uv@0.8.0") && stderr.contains("not installed"),
        "{stderr:?}"
    );
    assert!(
        !marker.exists(),
        "a PATH uv must not be used when the managed receipt is invalid"
    );
}

/// Positive control for the invalid-receipt test: the same data-home path and
/// a well-formed receipt are accepted by the real enumeration, the managed
/// binary runs, and the PATH decoy does not.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn a_structurally_complete_managed_uv_runs_with_a_grant_and_ignores_path_uv() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = project("tasks:\n  check:\n    uses: uv@0.8.0\n    run: 'print(1)'\n");
    let data_home = TempDir::new().unwrap();
    let version_root = data_home
        .path()
        .join("neoenv")
        .join("tools")
        .join("uv")
        .join("0.8.0");
    fs::create_dir_all(&version_root).unwrap();
    let binary = managed_uv_binary(&version_root);
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    let managed_marker = directory.path().join("managed-uv-ran");
    fs::write(
        &binary,
        format!("#!/bin/sh\n: > {}\n", managed_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(version_root.join(".neoenv-uv-sha256"), "a".repeat(64)).unwrap();

    let fake_path = TempDir::new().unwrap();
    let path_marker = directory.path().join("path-uv-ran");
    let fake_uv = fake_path.path().join("uv");
    fs::write(
        &fake_uv,
        format!("#!/bin/sh\n: > {}\n", path_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_uv, fs::Permissions::from_mode(0o755)).unwrap();

    let root = directory.path().canonicalize().unwrap();
    let subject = format!("project:{}/task:check", root.display());
    let policy = directory.path().join("policy.toml");
    fs::write(
        &policy,
        format!("[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"),
    )
    .unwrap();

    let mut command = command();
    isolated(&mut command);
    let output = command
        .current_dir(directory.path())
        .env("NEOENV_DATA_HOME", data_home.path())
        .env("PATH", fake_path.path())
        .args(["run", "check", "--capability-policy"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        managed_marker.exists(),
        "the managed binary must be the one that ran"
    );
    assert!(
        !path_marker.exists(),
        "a PATH uv must not be used when a managed version is selected"
    );
}

/// Real Go is exercised only when `go version` succeeds in this environment.
#[test]
fn real_go_inline_runner_runs_when_go_is_installed() {
    if !available_with("go", &["version"]) {
        eprintln!("SKIPPED: go is not installed/usable, so the real Go runner did not run");
        return;
    }
    let directory = project(
        "tasks:\n  check:\n    uses: go\n    args: [first.go]\n    run: |\n      package main\n      import (\"fmt\"; \"os\")\n      func main() { fmt.Printf(\"go-ran:%s\", os.Args[1]) }\n",
    );
    let output = run_in(directory.path(), &["run", "check"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("go-ran:first.go"),
        "a .go program argument must reach the program unchanged: {output:?}"
    );
}

/// Real .NET is exercised only when `dotnet --version` succeeds in this
/// environment. `dotnet run --file` also needs an SDK that supports it.
#[test]
fn real_dotnet_inline_runner_runs_when_dotnet_is_installed() {
    if !available_with("dotnet", &["--version"]) || !dotnet_run_file_supported() {
        eprintln!(
            "SKIPPED: dotnet or an SDK with `run --file` is not available, so the real .NET runner did not run"
        );
        return;
    }
    let directory = project(
        "tasks:\n  check:\n    uses: dotnet\n    run: 'System.Console.Write(\"dotnet-ran\");'\n",
    );
    let output = run_in(directory.path(), &["run", "check"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dotnet-ran"), "{output:?}");
}
