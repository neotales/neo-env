#![cfg(unix)]

use sha2::Digest;
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
    time::Duration,
};

fn launch() -> (std::process::Child, UnixStream) {
    let _ = binary_digest();
    let (parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .arg("--neoenv-owned-supervisor-v1")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    (child, parent)
}

fn binary_digest() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| {
        format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(env!("CARGO_BIN_EXE_nenv")).unwrap())
        )
    })
}

#[test]
fn terminal_anchor_announces_version_and_exits_when_its_pipe_closes() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .arg("--neoenv-terminal-anchor-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "NEOENV-TERMINAL-ANCHOR/1\n");
    assert!(child.try_wait().unwrap().is_none());
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}

fn send(
    socket: &mut UnixStream,
    program: &str,
    arguments: &[&str],
    cwd: &str,
    timeout_ms: Option<u64>,
) {
    socket.write_all(b"NEOENV-OWNED/1\n").unwrap();
    let mut response = String::new();
    BufReader::new(socket.try_clone().unwrap())
        .read_line(&mut response)
        .unwrap();
    assert_eq!(
        response,
        format!("NEOENV-OWNED/1 {}\n", env!("CARGO_PKG_VERSION"))
    );
    let request = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "binary_sha256": binary_digest(),
        "program": program,
        "arguments": arguments,
        "cwd": cwd,
        "environment": {"PATH": "/usr/bin:/bin"},
        "timeout_ms": timeout_ms,
    });
    let bytes = serde_json::to_vec(&request).unwrap();
    socket
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    socket.write_all(&bytes).unwrap();
}

#[cfg(not(target_os = "macos"))]
#[test]
fn versioned_socket_executes_single_owned_command() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "sh",
        &["-c", "printf yes > marker"],
        root.path().to_str().unwrap(),
        None,
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "STARTED\nEXIT 0\n");
    assert!(child.wait().unwrap().success());
    assert_eq!(
        std::fs::read_to_string(root.path().join("marker")).unwrap(),
        "yes"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn legacy_execution_is_refused_before_any_side_effect() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "sh",
        &["-c", "printf yes > marker"],
        root.path().to_str().unwrap(),
        None,
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "ERROR\n");
    assert!(!child.wait().unwrap().success());
    assert!(!root.path().join("marker").exists());
}

#[test]
fn incompatible_version_and_control_eof_are_refused() {
    let (mut child, mut socket) = launch();
    socket.write_all(b"NEOENV-OWNED/2\n").unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    assert!(response.is_empty());
    assert!(!child.wait().unwrap().success());

    let (mut child, socket) = launch();
    drop(socket);
    assert!(!child.wait().unwrap().success());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn timeout_kills_descendants_before_returning() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "sh",
        &["-c", "(sleep 1; touch escaped) & wait"],
        root.path().to_str().unwrap(),
        Some(100),
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "STARTED\nTIMEOUT\n");
    assert!(child.wait().unwrap().success());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!root.path().join("escaped").exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn eof_kills_a_started_command_and_its_descendants() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "sh",
        &["-c", "touch started; (sleep 1; touch escaped) & wait"],
        root.path().to_str().unwrap(),
        None,
    );
    let mut acknowledgement = String::new();
    BufReader::new(socket.try_clone().unwrap())
        .read_line(&mut acknowledgement)
        .unwrap();
    assert_eq!(acknowledgement, "STARTED\n");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !root.path().join("started").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(socket);
    assert!(child.wait().unwrap().success());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!root.path().join("escaped").exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn exited_leader_does_not_leave_its_background_descendant() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "sh",
        &["-c", "(sleep 1; touch escaped) & exit 0"],
        root.path().to_str().unwrap(),
        None,
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "STARTED\nEXIT 0\n");
    assert!(child.wait().unwrap().success());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!root.path().join("escaped").exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn inherited_ignored_sigchld_does_not_autoreap_owned_child() {
    let _ = binary_digest();
    let (mut socket, child_socket) = UnixStream::pair().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let mut child = Command::new("python3")
        .args(["-c", "import os,signal,sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); os.execv(sys.argv[1], [sys.argv[1], '--neoenv-owned-supervisor-v1'])", env!("CARGO_BIN_EXE_nenv")])
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().unwrap();
    let root = tempfile::tempdir().unwrap();
    send(
        &mut socket,
        "sh",
        &["-c", "exit 7"],
        root.path().to_str().unwrap(),
        None,
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "STARTED\nEXIT 1792\n");
    assert!(child.wait().unwrap().success());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn broad_foreign_waiter_cannot_reap_supervisor_owned_command() {
    let root = tempfile::tempdir().unwrap();
    let script = r"
import array, json, os, socket, subprocess, sys, threading, time
a, b = socket.socketpair()
p = subprocess.Popen([sys.argv[1], '--neoenv-owned-supervisor-v1'], stdin=b,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
b.close()
def reap():
    while True:
        try: os.waitpid(-1, os.WNOHANG)
        except ChildProcessError: pass
        time.sleep(.001)
threading.Thread(target=reap, daemon=True).start()
a.settimeout(4)
a.sendall(b'NEOENV-OWNED/1\n')
line = b''
while not line.endswith(b'\n'): line += a.recv(1)
assert line == ('NEOENV-OWNED/1 ' + sys.argv[2] + '\n').encode(), line
import hashlib
request = json.dumps({'version':sys.argv[2], 'binary_sha256':hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest(), 'program':'sh', 'arguments':['-c','exit 7'],
                      'cwd':sys.argv[3], 'environment':{'PATH':'/usr/bin:/bin'},
                      'timeout_ms':None, 'foreground':sys.argv[4] == 'foreground'}).encode()
a.sendall(len(request).to_bytes(4, 'big') + request)
if sys.argv[4] == 'foreground':
    with open('/dev/null', 'rb') as stdin:
        a.sendmsg([b'I'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [stdin.fileno()]))])
response = b''
while response.count(b'\n') < 2:
    chunk = a.recv(64)
    assert chunk, response
    response += chunk
assert response == b'STARTED\nEXIT 1792\n', response
";
    for mode in ["background", "foreground"] {
        let output = Command::new("python3")
            .args([
                "-c",
                script,
                env!("CARGO_BIN_EXE_nenv"),
                env!("CARGO_PKG_VERSION"),
                root.path().to_str().unwrap(),
                mode,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn startup_failure_is_reported_without_signalling_unrelated_child() {
    let root = tempfile::tempdir().unwrap();
    let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
    let (mut child, mut socket) = launch();
    send(
        &mut socket,
        "/no-such-neoenv-executable",
        &[],
        root.path().to_str().unwrap(),
        None,
    );
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response, "ERROR\n");
    assert!(child.wait().unwrap().success());
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[cfg(target_os = "linux")]
fn managed_helper() -> (std::process::Child, UnixStream, OwnedFd) {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
    use std::{io::IoSliceMut, mem::MaybeUninit};

    let (mut socket, child_socket) = UnixStream::pair().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .arg("--neoenv-owned-supervisor-pidfd-v1")
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    socket.write_all(b"NEOENV-OWNED/1\n").unwrap();
    let mut data = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let result = recvmsg(
        &socket,
        &mut [IoSliceMut::new(&mut data)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .unwrap();
    assert_eq!(result.bytes, 1);
    assert_eq!(&data, b"P");
    let pidfd = ancillary
        .drain()
        .find_map(|msg| match msg {
            RecvAncillaryMessage::ScmRights(mut rights) => rights.next(),
            _ => None,
        })
        .expect("self pidfd");
    (child, socket, pidfd)
}

#[cfg(target_os = "linux")]
#[test]
fn helper_delivers_self_pidfd_for_identity_safe_reaping() {
    use rustix::process::{WaitId, WaitIdOptions, waitid};
    use std::os::fd::AsFd;
    let (_child, socket, pidfd) = managed_helper();
    drop(socket);
    let result = waitid(WaitId::PidFd(pidfd.as_fd()), WaitIdOptions::EXITED)
        .unwrap()
        .unwrap();
    assert!(result.exited());
    assert!(result.exit_status().is_none_or(|code| code != 0));
}

#[cfg(target_os = "linux")]
#[test]
fn pidfd_wait_reports_foreign_reap_instead_of_reaping_another_child() {
    use rustix::{
        io::Errno,
        process::{WaitId, WaitIdOptions, waitid},
    };
    use std::os::fd::AsFd;
    let (mut child, socket, pidfd) = managed_helper();
    drop(socket);
    // Simulate the host's unrelated waiter by consuming this test fixture.
    assert!(!child.wait().unwrap().success());
    let mut unrelated = Command::new("sleep").arg("5").spawn().unwrap();
    assert_eq!(
        waitid(WaitId::PidFd(pidfd.as_fd()), WaitIdOptions::EXITED).unwrap_err(),
        Errno::CHILD
    );
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[test]
fn silent_peer_times_out_and_piped_stdin_is_rejected() {
    let (mut child, _socket) = launch();
    assert!(!child.wait().unwrap().success());

    let status = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .arg("--neoenv-owned-supervisor-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}
