#![cfg(windows)]

use neoenv_windows_job::{
    Child, ControlListener, HostIdentity, LauncherRequest, LauncherResponse, Spawn,
    VerifiedControl, anonymous_pipe, protocol::Kind,
};
use std::{collections::BTreeMap, io::Read, time::Duration};

#[test]
fn worker() {
    use std::io::Write as _;
    if std::env::var_os("NEOENV_SENTINEL_DRIVER").is_some() {
        sentinel_driver();
        return;
    }
    if let (Some(name), Some(value)) = (
        std::env::var_os("NEOENV_SENTINEL_NAME"),
        std::env::var_os("NEOENV_SENTINEL_VALUE"),
    ) {
        use std::os::windows::{
            ffi::OsStrExt,
            io::{FromRawHandle, OwnedHandle},
        };
        use windows_sys::Win32::{
            Foundation::{CompareObjectHandles, GetHandleInformation},
            System::Threading::{EVENT_MODIFY_STATE, OpenEventW},
        };
        let wide: Vec<u16> = name.encode_wide().chain([0]).collect();
        let value: usize = value.to_str().unwrap().parse().unwrap();
        // Check the candidate before opening the named event: OpenEventW may
        // itself allocate the same numeric handle in an otherwise empty slot.
        let mut flags = 0;
        let candidate_exists = unsafe { GetHandleInformation(value as _, &mut flags) } != 0;
        // SAFETY: the named event is created by this test's parent driver;
        // OpenEventW returns a new owned handle or null.
        let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
        assert!(!event.is_null(), "could not open sentinel event");
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        use std::os::windows::io::AsRawHandle;
        // The candidate handle value can be reused for another object. Compare
        // object identity rather than treating any valid numeric handle as a leak.
        if candidate_exists {
            assert_eq!(
                unsafe { CompareObjectHandles(event.as_raw_handle(), value as _) },
                0,
                "unrelated inheritable sentinel reached worker"
            );
        }
    }
    if std::env::var_os("NEOENV_LAUNCHER_TEST_WORKER").is_some() {
        std::io::stdout().write_all(b"\x1b[31mout\x1b[0m").unwrap();
        std::io::stderr().write_all(b"\x1b[32merr\x1b[0m").unwrap();
    }
}

// Cargo embeds a host build path that may not exist on the guest. Staged
// artifacts place the helper alongside this test executable.
fn helper_executable() -> std::path::PathBuf {
    let sibling = std::env::current_exe()
        .unwrap()
        .with_file_name("neoenv-windows-launcher.exe");
    if sibling.is_file() {
        return std::fs::canonicalize(sibling).unwrap();
    }
    std::fs::canonicalize(env!("CARGO_BIN_EXE_neoenv-windows-launcher"))
        .expect("launcher missing beside test executable and at Cargo build path")
}

fn launcher(listener: &ControlListener) -> Child {
    launch_mode(listener, false)
}

fn launch_mode(listener: &ControlListener, proxy: bool) -> Child {
    let identity = HostIdentity::current().unwrap();
    let executable = helper_executable();
    let directory = std::env::temp_dir();
    let environment = BTreeMap::new();
    let mut args = Vec::new();
    if proxy {
        args.push("--proxy".into());
    }
    args.extend([
        listener.name().into(),
        identity.pid.to_string(),
        identity.creation_time.to_string(),
    ]);
    Child::spawn_isolated_launcher(&Spawn {
        executable: &executable,
        arguments: &args,
        environment: &environment,
        directory: &directory,
        inherit_stdin: false,
    })
    .unwrap()
}

#[test]
fn relative_helper_is_resolved_before_launch() {
    let name = format!("neoenv-relative-helper-{}", std::process::id());
    let relative_dir = std::path::PathBuf::from(name);
    std::fs::create_dir(&relative_dir).unwrap();
    let relative_helper = relative_dir.join("neoenv-windows-launcher.exe");
    std::fs::copy(helper_executable(), &relative_helper).unwrap();
    assert!(!relative_helper.is_absolute());
    let listener = ControlListener::new().unwrap();
    let identity = HostIdentity::current().unwrap();
    let args = vec![
        "--proxy".into(),
        listener.name().into(),
        identity.pid.to_string(),
        identity.creation_time.to_string(),
    ];
    let child = Child::spawn_isolated_launcher(&Spawn {
        executable: &relative_helper,
        arguments: &args,
        environment: &BTreeMap::new(),
        directory: &std::env::temp_dir(),
        inherit_stdin: false,
    })
    .unwrap();
    let control = listener
        .authenticate(&child, Duration::from_secs(10), &|| false)
        .unwrap();
    drop(control);
    child.terminate().unwrap();
    drop(child);
    std::fs::remove_dir_all(relative_dir).unwrap();
}

#[test]
fn isolated_proxy_preserves_bytes_and_eof() {
    use std::io::Write as _;
    let listener = ControlListener::new().unwrap();
    let proxy = launch_mode(&listener, true);
    let mut control = listener
        .authenticate(&proxy, Duration::from_secs(10), &|| false)
        .unwrap();
    let (source_reader, mut source_writer) = anonymous_pipe().unwrap();
    let (mut sink_reader, sink_writer) = anonymous_pipe().unwrap();
    control
        .send_pipe_reader(&source_reader, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_pipe(&sink_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    drop((source_reader, sink_writer));
    let bytes = b"\x1b[31mproxy\0bytes\x1b[0m";
    source_writer.write_all(bytes).unwrap();
    drop(source_writer);
    let (kind, result) = control.receive(Duration::from_secs(5), &|| false).unwrap();
    assert_eq!(kind, Kind::Result);
    assert_eq!(result, b"ok");
    drop(control);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut result = Vec::new();
        let value = sink_reader.read_to_end(&mut result).map(|_| result);
        let _ = tx.send(value);
    });
    let result = rx.recv_timeout(Duration::from_secs(3));
    if result.is_err() {
        let _ = proxy.terminate();
    }
    assert_eq!(
        result
            .expect("proxy EOF timed out; termination attempted")
            .unwrap(),
        bytes
    );
}

#[test]
fn terminating_proxy_unblocks_backpressured_source() {
    use std::io::Write as _;
    let listener = ControlListener::new().unwrap();
    let proxy = launch_mode(&listener, true);
    let mut control = listener
        .authenticate(&proxy, Duration::from_secs(10), &|| false)
        .unwrap();
    let (source_reader, mut source_writer) = anonymous_pipe().unwrap();
    let (sink_reader, sink_writer) = anonymous_pipe().unwrap();
    control
        .send_pipe_reader(&source_reader, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_pipe(&sink_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    drop((source_reader, sink_writer));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = source_writer.write_all(&vec![b'x'; 2_000_000]);
        let _ = tx.send(result);
    });
    // With the sink undrained, the finite pipe buffers must apply backpressure.
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    let started = std::time::Instant::now();
    proxy.terminate().unwrap();
    assert!(started.elapsed() < Duration::from_secs(4));
    let result = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("source writer remained blocked");
    assert!(
        result.is_err(),
        "source unexpectedly completed after proxy termination"
    );
    drop((sink_reader, control));
}

// Run this fixture in its own process: the deliberately inheritable sentinel
// must never be created in the multithreaded integration-test host.
fn sentinel_driver() {
    use std::os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation},
        System::Threading::CreateEventW,
    };
    let name = format!(r"Local\neoenv-inherit-sentinel-{}", std::process::id());
    let wide: Vec<u16> = std::ffi::OsStr::new(&name)
        .encode_wide()
        .chain([0])
        .collect();
    // SAFETY: the name is NUL terminated and CreateEventW returns ownership.
    let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
    assert!(!raw.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    // This sentinel is intentionally inheritable in this disposable driver.
    assert_ne!(
        unsafe {
            SetHandleInformation(
                event.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        },
        0
    );
    let listener = ControlListener::new().unwrap();
    let launcher = launcher(&listener);
    let mut control = listener
        .authenticate(&launcher, Duration::from_secs(10), &|| false)
        .unwrap();
    let mut req = request(std::env::current_exe().unwrap());
    req.environment.insert("NEOENV_SENTINEL_NAME".into(), name);
    req.environment.insert(
        "NEOENV_SENTINEL_VALUE".into(),
        (event.as_raw_handle() as usize).to_string(),
    );
    send(&mut control, &req);
    let (mut stdout, stdout_writer) = anonymous_pipe().unwrap();
    let (mut stderr, stderr_writer) = anonymous_pipe().unwrap();
    control
        .send_pipe(&stdout_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_pipe(&stderr_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    drop((stdout_writer, stderr_writer));
    let (_, body) = control.receive(Duration::from_secs(10), &|| false).unwrap();
    let response: LauncherResponse = serde_json::from_slice(&body).unwrap();
    assert!(
        matches!(response, LauncherResponse::Exit(0)),
        "sentinel worker failed: {response:?}"
    );
    drop(control);
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out).unwrap();
    stderr.read_to_end(&mut err).unwrap();
    assert!(out.windows(12).any(|b| b == b"\x1b[31mout\x1b[0m"));
    assert!(err.windows(12).any(|b| b == b"\x1b[32merr\x1b[0m"));
}

#[test]
fn unrelated_inheritable_handle_does_not_reach_worker() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "worker", "--nocapture"])
        .env_clear()
        .env("NEOENV_SENTINEL_DRIVER", "1")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated inheritable-handle fixture failed"
    );
}

fn request(executable: std::path::PathBuf) -> LauncherRequest {
    LauncherRequest {
        executable,
        arguments: vec!["--exact".into(), "worker".into(), "--nocapture".into()],
        directory: std::env::temp_dir(),
        environment: BTreeMap::from([("NEOENV_LAUNCHER_TEST_WORKER".into(), "1".into())]),
    }
}

fn send(control: &mut VerifiedControl<'_>, request: &LauncherRequest) {
    control
        .send(
            Kind::Request,
            &serde_json::to_vec(request).unwrap(),
            Duration::from_secs(5),
            &|| false,
        )
        .unwrap();
}

#[test]
fn actual_dedicated_binary_runs_command_and_preserves_ansi() {
    let listener = ControlListener::new().unwrap();
    let launcher = launcher(&listener);
    let mut control = listener
        .authenticate(&launcher, Duration::from_secs(10), &|| false)
        .unwrap();
    // Match runtime inputs: canonical Windows paths and inherited drive
    // current-directory pseudo-variables, unlike a one-key synthetic env.
    let mut request = request(std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap());
    request.directory = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    request.environment.insert("=C:".into(), r"C:\".into());
    send(&mut control, &request);
    let (mut out_reader, out_writer) = anonymous_pipe().unwrap();
    let (mut err_reader, err_writer) = anonymous_pipe().unwrap();
    control
        .send_pipe(&out_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_pipe(&err_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    drop((out_writer, err_writer));
    let (kind, body) = control.receive(Duration::from_secs(10), &|| false).unwrap();
    assert_eq!(kind, Kind::Result);
    let response = serde_json::from_slice::<LauncherResponse>(&body).unwrap();
    assert!(
        matches!(response, LauncherResponse::Exit(0)),
        "launcher response: {response:?}"
    );
    drop(control);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = out_reader
            .read_to_end(&mut out)
            .and_then(|_| err_reader.read_to_end(&mut err))
            .map(|_| (out, err));
        let _ = tx.send(result);
    });
    let result = rx.recv_timeout(Duration::from_secs(5));
    if result.is_err() {
        let _ = launcher.terminate();
    }
    let (out, err) = result
        .expect("output EOF timed out; cleanup attempted")
        .unwrap();
    assert!(out.windows(12).any(|bytes| bytes == b"\x1b[31mout\x1b[0m"));
    assert!(err.windows(12).any(|bytes| bytes == b"\x1b[32merr\x1b[0m"));
}

#[test]
fn actual_dedicated_binary_reports_start_failure() {
    let listener = ControlListener::new().unwrap();
    let launcher = launcher(&listener);
    let mut control = listener
        .authenticate(&launcher, Duration::from_secs(10), &|| false)
        .unwrap();
    send(
        &mut control,
        &request(std::env::temp_dir().join("neoenv-missing-worker.exe")),
    );
    let (_out_reader, out_writer) = anonymous_pipe().unwrap();
    let (_err_reader, err_writer) = anonymous_pipe().unwrap();
    control
        .send_pipe(&out_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_pipe(&err_writer, Duration::from_secs(5), &|| false)
        .unwrap();
    let (_, body) = control.receive(Duration::from_secs(10), &|| false).unwrap();
    assert!(matches!(
        serde_json::from_slice::<LauncherResponse>(&body).unwrap(),
        LauncherResponse::StartFailed | LauncherResponse::StartFailedDetailed { .. }
    ));
}

#[test]
fn two_isolated_launchers_run_concurrently() {
    let first_listener = ControlListener::new().unwrap();
    let second_listener = ControlListener::new().unwrap();
    let first = launcher(&first_listener);
    let second = launcher(&second_listener);
    let mut first_control = first_listener
        .authenticate(&first, Duration::from_secs(10), &|| false)
        .unwrap();
    let mut second_control = second_listener
        .authenticate(&second, Duration::from_secs(10), &|| false)
        .unwrap();
    let (mut out1, out1_write) = anonymous_pipe().unwrap();
    let (mut err1, err1_write) = anonymous_pipe().unwrap();
    let (mut out2, out2_write) = anonymous_pipe().unwrap();
    let (mut err2, err2_write) = anonymous_pipe().unwrap();
    let req = request(std::env::current_exe().unwrap());
    send(&mut first_control, &req);
    send(&mut second_control, &req);
    for (control, out, err) in [
        (&mut first_control, &out1_write, &err1_write),
        (&mut second_control, &out2_write, &err2_write),
    ] {
        control
            .send_pipe(out, Duration::from_secs(5), &|| false)
            .unwrap();
        control
            .send_pipe(err, Duration::from_secs(5), &|| false)
            .unwrap();
    }
    drop((out1_write, err1_write, out2_write, err2_write));
    for control in [&mut first_control, &mut second_control] {
        let (kind, bytes) = control.receive(Duration::from_secs(10), &|| false).unwrap();
        assert_eq!(kind, Kind::Result);
        let response = serde_json::from_slice::<LauncherResponse>(&bytes).unwrap();
        assert!(
            matches!(response, LauncherResponse::Exit(0)),
            "launcher response: {response:?}"
        );
    }
    for reader in [&mut out1, &mut err1, &mut out2, &mut err2] {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(bytes.contains(&0x1b));
    }
}

#[test]
fn isolated_forwarder_writes_synchronous_pipe_and_cancels_when_blocked() {
    use neoenv_windows_job::ForwardDestination;
    use std::{io::Write as _, os::windows::io::AsHandle};
    for blocked in [false, true] {
        let listener = ControlListener::new().unwrap();
        let identity = HostIdentity::current().unwrap();
        let executable = helper_executable();
        let args = vec![
            "--forward-proxy".into(),
            listener.name().into(),
            identity.pid.to_string(),
            identity.creation_time.to_string(),
        ];
        let environment = BTreeMap::new();
        let helper = Child::spawn_isolated_launcher(&Spawn {
            executable: &executable,
            arguments: &args,
            environment: &environment,
            directory: &std::env::temp_dir(),
            inherit_stdin: false,
        })
        .unwrap();
        let mut control = listener
            .authenticate(&helper, Duration::from_secs(10), &|| false)
            .unwrap();
        let (source, mut input) = anonymous_pipe().unwrap();
        let (mut reader, writer) = std::io::pipe().unwrap();
        let destination = ForwardDestination::from_handle(writer.as_handle()).unwrap();
        control
            .send_pipe_reader(&source, Duration::from_secs(5), &|| false)
            .unwrap();
        control
            .send_forward_destination(&destination, Duration::from_secs(5), &|| false)
            .unwrap();
        drop((control, source, destination, writer));
        if blocked {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(input.write_all(&vec![1; 2_000_000]));
            });
            assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
            let start = std::time::Instant::now();
            helper.terminate().unwrap();
            assert!(start.elapsed() < Duration::from_secs(4));
            assert!(rx.recv_timeout(Duration::from_secs(4)).unwrap().is_err());
        } else {
            let bytes = b"\x1b[31msync\0pipe\x1b[0m";
            input.write_all(bytes).unwrap();
            drop(input);
            let mut data = Vec::new();
            reader.read_to_end(&mut data).unwrap();
            assert_eq!(data, bytes);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(code) = helper.try_wait().unwrap() {
                    assert_eq!(code, 0);
                    break;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[test]
fn isolated_forwarder_preserves_disk_file_bytes() {
    use neoenv_windows_job::ForwardDestination;
    use std::{
        io::{Seek as _, Write as _},
        os::windows::io::AsHandle,
    };
    let listener = ControlListener::new().unwrap();
    let identity = HostIdentity::current().unwrap();
    let args = vec![
        "--forward-proxy".into(),
        listener.name().into(),
        identity.pid.to_string(),
        identity.creation_time.to_string(),
    ];
    let helper = Child::spawn_isolated_launcher(&Spawn {
        executable: &helper_executable(),
        arguments: &args,
        environment: &BTreeMap::new(),
        directory: &std::env::temp_dir(),
        inherit_stdin: false,
    })
    .unwrap();
    let mut control = listener
        .authenticate(&helper, Duration::from_secs(10), &|| false)
        .unwrap();
    let (source, mut input) = anonymous_pipe().unwrap();
    let file_path = std::env::temp_dir().join(format!(
        "neoenv-forward-{}-{}.tmp",
        std::process::id(),
        identity.creation_time
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();
    let destination = ForwardDestination::from_handle(file.as_handle()).unwrap();
    control
        .send_pipe_reader(&source, Duration::from_secs(5), &|| false)
        .unwrap();
    control
        .send_forward_destination(&destination, Duration::from_secs(5), &|| false)
        .unwrap();
    drop((control, source, destination));
    let expected = b"\x1b[31mfile\0bytes\x1b[0m";
    input.write_all(expected).unwrap();
    drop(input);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(code) = helper.try_wait().unwrap() {
            assert_eq!(code, 0);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "file forwarding deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    file.rewind().unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
    drop(file);
    std::fs::remove_file(file_path).unwrap();
}
