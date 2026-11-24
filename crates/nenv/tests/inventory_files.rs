//! Real CLI inventory composition and strict file boundaries; loopback only.
use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::{Child, Output},
    thread,
    time::{Duration, Instant},
};

mod support;

fn run(root: &Path, args: &[&str]) -> Output {
    command(root, args).output().expect("CLI")
}

fn command(root: &Path, args: &[&str]) -> support::TestCommand {
    let mut command = support::TestCommand::new();
    command
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("HOME", root)
        .env("NEOENV_CONFIG_HOME", root.join("config"))
        .env("NEOENV_DATA_HOME", root.join("data"))
        .env("NEOENV_CACHE_HOME", root.join("cache"))
        .env("NEOENV_STATE_HOME", root.join("state"));
    command
}

fn inventory(host: &str) -> String {
    format!("format_version: 1\ninventories:\n  lab:\n    hosts:\n      {host}: 127.0.0.1\n")
}

fn names(output: &Output) -> Vec<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    value[0]["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|host| host["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn user_files_are_sorted_then_declared_files_then_inline_replace_whole_inventories() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let auto = root.join("config/neoenv/inventories");
    fs::create_dir_all(&auto).unwrap();
    fs::write(auto.join("20-last.yaml"), inventory("auto-last")).unwrap();
    fs::write(auto.join("10-first.yaml"), inventory("auto-first")).unwrap();
    fs::write(root.join(".neoenv"), "MODE=local\n").unwrap();
    assert_eq!(
        names(&run(root, &["inventory", "--format", "json"])),
        ["auto-last"]
    );
    fs::write(root.join("first.yaml"), inventory("declared-first")).unwrap();
    fs::write(root.join("second.yaml"), inventory("declared-last")).unwrap();
    fs::write(
        root.join(".neoenv"),
        "MODE=local\ninventory first.yaml\ninventory \"second.yaml\"\n",
    )
    .unwrap();
    assert_eq!(
        names(&run(root, &["inventory", "--format", "json"])),
        ["declared-last"]
    );
    fs::write(
        root.join("neoenv.yaml"),
        format!(
            "inventory_files: [first.yaml, second.yaml]\n{}",
            inventory("inline"),
        ),
    )
    .unwrap();
    assert_eq!(
        names(&run(root, &["inventory", "--format", "json"])),
        ["inline"]
    );
    fs::remove_file(root.join("neoenv.yaml")).unwrap();
    fs::write(
        root.join("neoenv.toml"),
        "inventory_files = ['first.yaml', 'second.yaml']\n",
    )
    .unwrap();
    assert_eq!(
        names(&run(root, &["inventory", "--format", "json"])),
        ["declared-last"]
    );
}

#[test]
fn unknown_keys_unsupported_entries_missing_files_and_non_inventory_sections_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join(".neoenv"), "inventory hosts.yaml\n").unwrap();
    assert!(!run(root, &["inventory"]).status.success());
    for body in [
        "inventories: {}\nenv: {}\n",
        "inventories: {}\ntasks: {}\n",
        "inventories: {}\ninventory_files: []\n",
        "inventories:\n  lab:\n    hosts:\n      one:\n        misspelled_port: 22\n",
    ] {
        fs::write(root.join("hosts.yaml"), body).unwrap();
        let output = run(root, &["inventory"]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("inventory file must be YAML/TOML")
        );
    }
    fs::write(root.join("hosts.yaml"), inventory("one")).unwrap();
    fs::write(root.join(".neoenv"), "inventory ../hosts.yaml\n").unwrap();
    assert!(!run(root, &["inventory"]).status.success());
    fs::write(root.join(".neoenv"), "").unwrap();
    let auto = root.join("config/neoenv/inventories");
    fs::create_dir_all(&auto).unwrap();
    fs::write(auto.join("unsupported.txt"), inventory("one")).unwrap();
    assert!(!run(root, &["inventory"]).status.success());
}

#[test]
fn validate_refuses_ssh_fields_the_runner_cannot_honor() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    for field in [
        "    args: [ignored]\n",
        "    cwd: ignored\n",
        "    source: ignored\n",
        "    destination: ignored\n",
        "    outputs: {IGNORED: {}}\n",
        "    with: {inventory: lab, targets: first, ignored: value}\n",
    ] {
        let with = if field.contains("with:") {
            ""
        } else {
            "    with: {inventory: lab, targets: first}\n"
        };
        let document = format!("tasks:\n  sample:\n    uses: ssh\n    run: 'true'\n{with}{field}");
        fs::write(root.join("neoenv.yaml"), &document).unwrap();
        assert!(
            !run(root, &["validate"]).status.success(),
            "unused SSH field was accepted"
        );
    }
    fs::write(
        root.join("neoenv.yaml"),
        "inventories:\n  lab:\n    defaults:\n      identity_file: fixture-key\n    hosts: {}\n",
    )
    .unwrap();
    assert!(run(root, &["validate"]).status.success());
}

#[cfg(unix)]
#[test]
fn inventory_symlink_escape_and_local_scp_link_are_refused_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("hosts.yaml"), inventory("one")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("hosts.yaml"),
        dir.path().join("hosts.yaml"),
    )
    .unwrap();
    fs::write(dir.path().join(".neoenv"), "inventory hosts.yaml\n").unwrap();
    assert!(!run(dir.path(), &["inventory"]).status.success());
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
    assert!(neoenv_runtime::ssh::local_file(dir.path(), "escape/file", true).is_err());
    fs::write(outside.path().join("file"), b"untouched").unwrap();
    std::os::unix::fs::symlink(outside.path().join("file"), dir.path().join("link")).unwrap();
    assert!(neoenv_runtime::ssh::local_file(dir.path(), "link", true).is_err());
    assert!(neoenv_runtime::ssh::local_file(dir.path(), "link", false).is_err());
    assert_eq!(fs::read(outside.path().join("file")).unwrap(), b"untouched");
}

#[test]
fn invalid_external_inventory_is_lazy_for_local_commands_but_strict_for_consumers() {
    let local_run = portable_command(env!("CARGO_BIN_EXE_nenv"), &["--version"]);
    for source in [
        "user-malformed",
        "user-unsupported",
        "declared-malformed",
        "declared-missing",
    ] {
        let directory = tempfile::tempdir().unwrap();
        // Task capability subjects are built from the canonical project root,
        // as the scheduler does. A raw temp path can differ once resolved
        // (macOS `/var` -> `/private/var`, Windows 8.3 name -> long name), so a
        // non-canonical fixture would grant execute to a subject the runner
        // never asks about.
        let root = directory.path().canonicalize().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let inline = format!(
            "inventories:\n  lab:\n    defaults: {{user: fixture, port: {port}}}\n    hosts:\n      first:\n        address: 127.0.0.1\n        host_key: {}\n",
            "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
        );
        let mut document = format!(
            "{inline}tasks:\n  local:\n    uses: portable\n    run: {local_run}\n  remote:\n    uses: ssh\n    with: {{inventory: lab, targets: first}}\n    run: {local_run}\n  wrapper:\n    deps: [remote]\n    uses: portable\n    run: {local_run}\n"
        );
        let policy = root.join("config/neoenv");
        fs::create_dir_all(&policy).unwrap();
        match source {
            "user-malformed" | "user-unsupported" => {
                let auto = root.join("config/neoenv/inventories");
                fs::create_dir_all(&auto).unwrap();
                let file = if source == "user-malformed" {
                    "bad.yaml"
                } else {
                    "bad.txt"
                };
                fs::write(auto.join(file), "inventories: [invalid]\n").unwrap();
            }
            _ => {
                document.push_str("inventory_files: [bad.yaml]\n");
                if source == "declared-malformed" {
                    fs::write(root.join("bad.yaml"), "inventories: [invalid]\n").unwrap();
                }
            }
        }
        fs::write(root.join("neoenv.yaml"), &document).unwrap();
        let project = neoenv_config::parse_project(
            &root.join("neoenv.yaml"),
            &fs::read_to_string(root.join("neoenv.yaml")).unwrap(),
        )
        .unwrap();
        let endpoint = neoenv_runtime::ssh::endpoint_subject_with_context(
            &project.inventories["lab"],
            "first",
            &std::collections::BTreeMap::new(),
            &root,
        )
        .unwrap();
        let remote_subject = format!("project:{}/task:remote", root.display());
        let wrapper_subject = format!("project:{}/task:wrapper", root.display());
        fs::write(
            policy.join("capabilities.toml"),
            format!(
                "[[grants]]\nsubject = \"inventory:lab/host:first\"\ncapability = \"connect\"\n\
                 [[grants]]\nsubject = {endpoint:?}\ncapability = \"connect\"\n\
                 [[grants]]\nsubject = {remote_subject:?}\ncapability = \"execute\"\n\
                 [[grants]]\nsubject = {wrapper_subject:?}\ncapability = \"execute\"\n"
            ),
        )
        .unwrap();
        for args in [
            vec!["validate"],
            vec!["inspect"],
            vec!["task", "list"],
            vec!["task", "plan", "local"],
            vec!["run", "local"],
        ] {
            let output = run(&root, &args);
            assert!(
                output.status.success(),
                "{source} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if args[0] == "run" {
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("nenv "),
                    "{source} {args:?} did not execute the fixture binary: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
        }
        for args in [
            vec!["inventory"],
            vec!["ssh", "-i", "lab", "first", "--", "true"],
            vec!["scp", "-i", "lab", "local.txt", "remote.txt", "first"],
            vec!["run", "remote"],
            vec!["run", "wrapper"],
        ] {
            let output = run(&root, &args);
            assert!(
                !output.status.success(),
                "{source} {args:?} accepted invalid inventory"
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("nenv "),
                "{source} {args:?} reached the task action: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_no_connection(&listener, source, &args);
            let message = String::from_utf8_lossy(&output.stderr);
            assert!(
                message.contains("inventory"),
                "{source} {args:?}: {message}"
            );
            assert!(
                !message.contains("connect grant"),
                "inventory was not validated before authorization"
            );
        }
        if source == "user-malformed" || source == "user-unsupported" {
            fs::remove_dir_all(root.join("config/neoenv/inventories")).unwrap();
        } else {
            fs::remove_file(root.join("bad.yaml")).ok();
            document = document.replace("inventory_files: [bad.yaml]\n", "");
            fs::write(root.join("neoenv.yaml"), document).unwrap();
        }
        let mut child = command(&root, &["run", "remote"])
            .spawn()
            .expect("start positive SSH control");
        assert_connection(&listener, source, &mut child);
    }
}

fn assert_no_connection(listener: &TcpListener, source: &str, args: &[&str]) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("{source} {args:?}: listener failed: {error}"),
        Ok((stream, _)) => {
            drop(stream);
            panic!("{source} {args:?} attempted an SSH connection");
        }
    }
}

fn assert_connection(listener: &TcpListener, source: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                drop(stream);
                while Instant::now() < deadline {
                    if child.try_wait().expect("check SSH control child").is_some() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                terminate_child(child);
                panic!("{source}: positive SSH control did not exit after listener close");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                terminate_child(child);
                panic!("{source}: listener failed: {error}");
            }
        }
        if Instant::now() >= deadline {
            terminate_child(child);
            panic!("{source}: positive SSH control did not reach the listener before deadline");
        }
        if child.try_wait().expect("check SSH control child").is_some() {
            panic!("{source}: SSH control exited before connecting");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Serializes a portable command for YAML without relying on a shell or PATH lookup.
fn portable_command(program: &str, args: &[&str]) -> String {
    let command = std::iter::once(program)
        .chain(args.iter().copied())
        .map(|part| format!("{part:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    serde_yaml::to_string(&command)
        .expect("command serializes")
        .trim()
        .to_owned()
}

#[test]
fn portable_command_yaml_preserves_spaces_and_backslashes() {
    let program = r"C:\fixture path\nenv.exe";
    let serialized = portable_command(program, &["--version"]);
    let yaml = format!("run: {serialized}\n");
    let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let run = value["run"].as_str().unwrap();
    let parsed = neotales_process::parse(run).unwrap();
    assert_eq!(parsed.programs.len(), 1);
    assert_eq!(parsed.programs[0].commands.len(), 1);
    assert_eq!(parsed.programs[0].commands[0].program, program);
    assert_eq!(parsed.programs[0].commands[0].arguments, ["--version"]);
}
