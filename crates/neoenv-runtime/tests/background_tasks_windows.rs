//! End-to-end Windows pair executed in a subprocess with overlapped stdout.
//!
//! The file is compiled two ways: as a module of `background_tasks_main` under
//! `cfg(windows)`, and as its own test target because Cargo auto-discovers every
//! `.rs` file in `tests/`. The crate-level `cfg` keeps the second form empty off
//! Windows, which is the same guard `background_tasks.rs` uses.
#![cfg(windows)]

use neoenv_core::tasks::{TaskOutcome, resolve_inheritance};
use neoenv_runtime::tasks::{
    CooperativeOwnedBackend, TaskCancellation, TaskEnvironment, TaskRunOptions,
    TaskRunnerDirectories, run_tasks_with_cancellation,
};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("worker") => worker(&args[2], &args[3], &args[4]),
        Some("host") => host(Path::new(&args[2]), args[3] == "cancel"),
        Some("finish") => {}
        _ => {
            run_case(false);
            run_case(true);
        }
    }
}
fn worker(name: &str, peer: &str, mode: &str) {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(format!("\x1b[31m{name}\0\x1b[0m").as_bytes())
        .unwrap();
    stdout.flush().unwrap();
    drop(stdout);
    fs::write(name, b"started").unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while !Path::new(peer).exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(Path::new(peer).exists(), "parallel peer did not start");
    if mode == "cancel" {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
fn host(root: &Path, cancel: bool) {
    let executable = std::env::current_exe().unwrap();
    let path = executable.to_string_lossy().replace('\\', "/");
    let mode = if cancel { "cancel" } else { "complete" };
    let yaml = format!(
        r#"tasks:
  one:
    uses: argv
    run: "{path}"
    args: [worker, one, two, {mode}]
  two:
    uses: argv
    run: "{path}"
    args: [worker, two, one, {mode}]
  finish:
    needs: [{{id: one, parallel: true}}, {{id: two, parallel: true}}]
    uses: argv
    run: "{path}"
    args: [finish]
"#
    );
    let parsed = neoenv_config::parse_project(&root.join("neoenv.yaml"), &yaml).unwrap();
    let tasks = resolve_inheritance(&parsed.tasks).unwrap();
    let values = indexmap::IndexMap::new();
    let cancellation = TaskCancellation::new();
    let started = Instant::now();
    let report = std::thread::scope(|scope| {
        if cancel {
            let handle = cancellation.clone();
            scope.spawn(move || {
                let until = Instant::now() + Duration::from_secs(20);
                while !(root.join("one").exists() && root.join("two").exists())
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                handle.cancel();
            });
        }
        run_tasks_with_cancellation(
            &tasks,
            "finish",
            "default",
            root,
            TaskEnvironment {
                values: &values,
                path_operations: &[],
                overrides: None,
            },
            &[],
            TaskRunOptions {
                ssh_output_to_stderr: false,
                ssh_secret_values: &[],
                inventories: None,
                dry_run: false,
                cancellation: &cancellation,
                capability_grants: None,
                capability_policy_source: None,
                remote_tasks: None,
                task_directories: TaskRunnerDirectories::default(),
                managed_runtimes: &[],
                input_values: None,
                vaults: None,
                owned_backend: Some(CooperativeOwnedBackend::with_exclusive_child_waits(
                    &executable,
                )),
            },
        )
        .unwrap()
    });
    assert!(
        root.join("one").exists() && root.join("two").exists(),
        "both pair members must start: {report:?}"
    );
    for name in ["one", "two"] {
        let entry = report
            .tasks
            .iter()
            .find(|entry| entry.name == name)
            .expect("pair result");
        assert_eq!(
            entry.outcome,
            if cancel {
                TaskOutcome::Cancelled
            } else {
                TaskOutcome::Succeeded
            },
            "{entry:?}"
        );
    }
    if cancel {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "pair cleanup exceeded deadline"
        );
    }
}
fn run_case(cancel: bool) {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap();
    let helper = dir.join("neoenv-windows-launcher.exe");
    let helper = if helper.is_file() {
        helper
    } else {
        dir.parent().unwrap().join("neoenv-windows-launcher.exe")
    };
    assert!(
        helper.is_file(),
        "build neoenv-windows-launcher.exe before running this test"
    );
    let root = tempfile::tempdir().unwrap();
    let host_exe = root.path().join("background-host.exe");
    fs::copy(exe, &host_exe).unwrap();
    fs::copy(helper, root.path().join("neoenv-windows-launcher.exe")).unwrap();
    let (mut reader, writer) = neoenv_windows_job::overlapped_output_pipe().unwrap();
    let stderr = writer.try_clone().unwrap();
    let mut child = Command::new(host_exe)
        .arg("host")
        .arg(root.path())
        .arg(if cancel { "cancel" } else { "complete" })
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    let output = std::thread::spawn(move || {
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();
        data
    });
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("runtime host exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let data = output.join().unwrap();
    assert!(
        status.success(),
        "host failed: {}",
        String::from_utf8_lossy(&data)
    );
    for name in ["one", "two"] {
        let expected = format!("\x1b[31m{name}\0\x1b[0m");
        assert!(
            data.windows(expected.len())
                .any(|window| window == expected.as_bytes()),
            "missing bytes for {name}: {data:?}"
        );
    }
}
