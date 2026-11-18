#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::{Condvar, Mutex};

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

mod support;

fn command() -> support::TestCommand {
    support::TestCommand::new()
}

fn project_command(root: &Path) -> support::TestCommand {
    let mut command = command();
    command.current_dir(root);
    command
        .env_remove("MISE_GLOBAL_CONFIG_FILE")
        .env_remove("MISE_DATA_DIR");
    command
}

/// Global commands read global state, not project configuration, and several
/// tests snapshot that state. They deliberately use a plain `Command`: an
/// approval write would be a write the "no writes" assertions are meant to see.
fn global_command(root: &Path, config_home: &Path, data_home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    command
        .current_dir(root)
        .env("NEOENV_CONFIG_HOME", config_home)
        .env("NEOENV_DATA_HOME", data_home)
        .env_remove("MISE_GLOBAL_CONFIG_FILE")
        .env_remove("MISE_DATA_DIR");
    command
}

fn config_path(config_home: &Path) -> PathBuf {
    config_home.join("neoenv/neoenv.toml")
}

fn write_project(directory: &Path, version: &str) -> PathBuf {
    let path = directory.join("neoenv.yaml");
    let asset = format!("demo-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let contents = format!(
        "format_version: 1\ntools:\n  - id: gh:owner/repo\n    version: {version}\n    provider: github-release\n    github_release:\n      repository: owner/repo\n      asset: {asset}\n      checksum_asset: checksums.txt\n    binaries: [repo]\n"
    );
    fs::write(&path, contents).unwrap();
    path
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(directory: &Path, root: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                visit(&path, root, files);
            } else {
                files.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut files = Vec::new();
    visit(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn assert_json_text_agree(text: &[u8], json: &[u8]) {
    let document: serde_json::Value = serde_json::from_slice(json).unwrap();
    assert_eq!(document["schema_version"], 1);
    let rendered = String::from_utf8(text.to_vec()).unwrap();
    assert!(rendered.contains(&format!("scope: {}", document["scope"].as_str().unwrap())));
    assert!(rendered.contains(&format!(
        "command: {}",
        document["command"].as_str().unwrap()
    )));
    assert!(rendered.contains(&format!("dry_run: {}", document["dry_run"])));
    if let Some(changes) = document["changes"].as_array() {
        for change in changes {
            assert!(rendered.contains(change["action"].as_str().unwrap()));
            assert!(rendered.contains(change["tool"].as_str().unwrap()));
        }
    }
}

struct ReleaseFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    gate: Arc<ArtifactGate>,
    thread: Option<thread::JoinHandle<()>>,
}

// The gated process fixtures below require non-reaping waitid and a safely
// owned process group. They are selected only on Linux/macOS; unrelated Unix
// lifecycle tests, including truncated transfers, keep their broader gates.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum GateState {
    #[default]
    Open,
    Armed,
    Paused,
    Released,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct ArtifactGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ArtifactGate {
    fn arm(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(*state == GateState::Open);
        *state = GateState::Armed;
    }

    fn wait_until_paused(&self, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                *state != GateState::Paused && *state != GateState::Released
            })
            .unwrap();
        *state == GateState::Paused
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        *state = GateState::Released;
        self.changed.notify_all();
    }

    fn pause_response(&self, stream: &mut std::net::TcpStream, body: &[u8]) -> bool {
        let mut state = self.state.lock().unwrap();
        if *state != GateState::Armed {
            return false;
        }
        let partial = body.len().saturating_div(2).max(1).min(body.len());
        if stream.write_all(&body[..partial]).is_err() || stream.flush().is_err() {
            return true;
        }
        *state = GateState::Paused;
        self.changed.notify_all();
        while *state == GateState::Paused {
            state = self.changed.wait(state).unwrap();
        }
        let _ = stream.write_all(&body[partial..]);
        true
    }
}

impl ReleaseFixture {
    fn start(versions: &[&str], latest: &str) -> Self {
        Self::start_with_options(versions, latest, Duration::ZERO, false)
    }

    fn start_with_options(
        versions: &[&str],
        latest: &str,
        delay: Duration,
        corrupt_new: bool,
    ) -> Self {
        Self::start_with_options_and_transfer_failure(versions, latest, delay, corrupt_new, false)
    }

    #[cfg(unix)]
    fn start_with_truncated_latest(versions: &[&str], latest: &str) -> Self {
        Self::start_with_options_and_transfer_failure(versions, latest, Duration::ZERO, false, true)
    }

    #[allow(clippy::too_many_lines)]
    fn start_with_options_and_transfer_failure(
        versions: &[&str],
        latest: &str,
        delay: Duration,
        corrupt_new: bool,
        truncate_new: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let gate = Arc::new(ArtifactGate::default());
        let versions = versions
            .iter()
            .map(|version| (*version).to_owned())
            .collect::<Vec<_>>();
        let latest = latest.to_owned();
        let server_stop = Arc::clone(&stop);
        let server_requests = Arc::clone(&requests);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let server_gate = Arc::clone(&gate);
        let thread = thread::spawn(move || {
            let asset = format!("demo-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        server_requests.fetch_add(1, Ordering::Relaxed);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut request = [0_u8; 8192];
                        let size = stream.read(&mut request).unwrap_or(0);
                        let request = String::from_utf8_lossy(&request[..size]);
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_owned();
                        let version = if path == "/repos/owner/repo/releases/latest" {
                            Some(latest.clone())
                        } else if let Some(version) =
                            path.strip_prefix("/repos/owner/repo/releases/tags/")
                        {
                            Some(version.to_owned())
                        } else if let Some(version) = path.strip_prefix("/artifact/") {
                            Some(version.to_owned())
                        } else {
                            path.strip_prefix("/checksums/").map(str::to_owned)
                        };
                        let known = version
                            .as_ref()
                            .is_some_and(|version| versions.iter().any(|known| known == version));
                        let truncate_artifact = truncate_new
                            && path.starts_with("/artifact/")
                            && version.as_ref().is_some_and(|version| version == &latest);
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        let latest_artifact = path.starts_with("/artifact/")
                            && version.as_ref().is_some_and(|version| version == &latest);
                        let (status, body) = if let Some(version) = version {
                            if !known {
                                ("404 Not Found", b"missing".to_vec())
                            } else if path.starts_with("/artifact/") {
                                if !delay.is_zero() {
                                    thread::sleep(delay);
                                }
                                let body = if corrupt_new && version == latest {
                                    b"corrupt artifact".to_vec()
                                } else {
                                    format!("#!/bin/sh\nprintf '{version}'\n").into_bytes()
                                };
                                ("200 OK", body)
                            } else if path.starts_with("/checksums/") {
                                let body = if corrupt_new && version == latest {
                                    format!("{}  {asset}\n", "0".repeat(64))
                                } else {
                                    let body = format!("#!/bin/sh\nprintf '{version}'\n");
                                    format!("{:x}  {asset}\n", Sha256::digest(body.as_bytes()))
                                };
                                ("200 OK", body.into_bytes())
                            } else {
                                let body = format!(
                                    "{{\"id\":42,\"tag_name\":\"{version}\",\"assets\":[{{\"id\":7,\"name\":\"{asset}\",\"browser_download_url\":\"http://{address}/artifact/{version}\"}},{{\"id\":8,\"name\":\"checksums.txt\",\"browser_download_url\":\"http://{address}/checksums/{version}\"}}]}}"
                                );
                                ("200 OK", body.into_bytes())
                            }
                        } else {
                            ("404 Not Found", b"missing".to_vec())
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        if truncate_artifact {
                            let partial = body.len().saturating_div(2).max(1).min(body.len());
                            let _ = stream.write_all(body.get(..partial).unwrap_or(&body));
                            let _ = stream.flush();
                            drop(stream);
                            continue;
                        }
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        if latest_artifact && server_gate.pause_response(&mut stream, &body) {
                            continue;
                        }
                        let _ = stream.write_all(&body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            stop,
            requests,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            gate,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn stop(mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.gate.release();
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for ReleaseFixture {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.gate.release();
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// This guard is the sole waiter for a fixture leader. It observes exit without
// reaping, signals the owned process group while its ID cannot be recycled,
// then reaps the leader and joins the capped pipe readers. A descendant that
// deliberately escapes the fixture's process group is not covered.
struct OwnedChild {
    child: Option<std::process::Child>,
    stop_capture: Arc<AtomicBool>,
    stdout: Option<CaptureReader>,
    stderr: Option<CaptureReader>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_CAPTURE: usize = 16 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct CaptureState {
    bytes: Vec<u8>,
    seen: u64,
    truncated: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct CaptureReader {
    state: Arc<Mutex<CaptureState>>,
    thread: Option<thread::JoinHandle<std::io::Result<()>>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl CaptureReader {
    fn start<R: Read + std::os::fd::AsFd + Send + 'static>(
        mut reader: R,
        stop: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = OFlag::from_bits_truncate(fcntl(&reader, FcntlArg::F_GETFL)?);
        fcntl(&reader, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        let state = Arc::new(Mutex::new(CaptureState::default()));
        let worker_state = Arc::clone(&state);
        let thread = thread::Builder::new().spawn(move || {
            let mut buffer = [0_u8; 4096];
            let mut after_stop = 0_usize;
            loop {
                let stopping = stop.load(Ordering::Acquire);
                // A writer outside the owned group cannot keep capture alive.
                if stopping && after_stop >= 64 * 1024 {
                    break;
                }
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if stopping {
                            after_stop += count;
                        }
                        let mut capture = worker_state.lock().unwrap();
                        capture.seen = capture.seen.saturating_add(count as u64);
                        let keep = count.min(MAX_CAPTURE.saturating_sub(capture.bytes.len()));
                        capture.bytes.extend_from_slice(&buffer[..keep]);
                        capture.truncated |= keep < count;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        if stopping {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopping {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })?;
        Ok(Self {
            state,
            thread: Some(thread),
        })
    }

    fn finish(mut self) -> std::io::Result<Vec<u8>> {
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| std::io::Error::other("capture thread panicked"))??;
        let state = self.state.lock().unwrap();
        let mut bytes = state.bytes.clone();
        if state.truncated {
            bytes.extend_from_slice(b"\n[output truncated]\n");
        }
        Ok(bytes)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
trait Spawnable {
    fn builder(&mut self) -> &mut Command;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Spawnable for Command {
    fn builder(&mut self) -> &mut Command {
        self
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Spawnable for support::TestCommand {
    fn builder(&mut self) -> &mut Command {
        self.inner_mut()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OwnedChild {
    fn spawn(command: &mut impl Spawnable) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let child = command
            .builder()
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut owned = Self {
            child: Some(child),
            stop_capture: Arc::new(AtomicBool::new(false)),
            stdout: None,
            stderr: None,
        };
        let stdout = owned.child.as_mut().unwrap().stdout.take().unwrap();
        let stderr = owned.child.as_mut().unwrap().stderr.take().unwrap();
        owned.stdout = Some(CaptureReader::start(
            stdout,
            Arc::clone(&owned.stop_capture),
        )?);
        owned.stderr = Some(CaptureReader::start(
            stderr,
            Arc::clone(&owned.stop_capture),
        )?);
        Ok(owned)
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn exited_without_reaping(&self) -> std::io::Result<bool> {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        let raw =
            i32::try_from(self.id()).map_err(|_| std::io::Error::other("invalid child pid"))?;
        let pid = Pid::from_raw(raw).ok_or_else(|| std::io::Error::other("invalid child pid"))?;
        loop {
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Ok(status) => return Ok(status.is_some()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn wait_until_exit(&self, timeout: Duration) -> std::io::Result<bool> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.exited_without_reaping()? {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        use nix::errno::Errno;
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        if self.child.is_some() {
            // waitid(WNOWAIT) confirms the leader is still our unreaped child.
            // This guard is its sole waiter, so its PID cannot be recycled
            // before killpg, even if it exited.
            let exited = self.exited_without_reaping()?;
            let pid =
                i32::try_from(self.id()).map_err(|_| std::io::Error::other("invalid child pid"))?;
            match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
                Ok(()) => {}
                Err(Errno::ESRCH) if exited => {}
                Err(error) => {
                    // The group vanished while its leader was live, or could
                    // not be signalled. Reap our still-owned leader, but do
                    // not claim that escaped descendants were cleaned up.
                    let child = self.child.as_mut().unwrap();
                    let _ = child.kill();
                    let _ = child.wait();
                    self.child.take();
                    return Err(std::io::Error::other(format!(
                        "owned process group cleanup failed: {error}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn output(mut self) -> std::io::Result<std::process::Output> {
        self.terminate()?;
        let status = self.child.as_mut().unwrap().wait()?;
        self.child.take();
        self.stop_capture.store(true, Ordering::Release);
        let stdout = self.stdout.take().unwrap().finish()?;
        let stderr = self.stderr.take().unwrap().finish()?;
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }

    fn finish(self, timeout: Duration) -> Result<std::process::Output, String> {
        let timed_out = !self
            .wait_until_exit(timeout)
            .map_err(|error| error.to_string())?;
        let output = self.output().map_err(|error| error.to_string())?;
        if timed_out {
            return Err(format!(
                "subprocess timed out after {timeout:?}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(output)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            // If ownership verification fails, do not signal a potentially
            // recycled process group. Capture still stops without waiting for
            // unrelated pipe writers.
            if self.terminate().is_ok()
                && let Some(child) = self.child.as_mut()
            {
                let _ = child.wait();
            }
            self.child.take();
        }
        self.stop_capture.store(true, Ordering::Release);
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.finish();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.finish();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ExecWorker {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ExecWorker {
    fn stop_and_join(&mut self) -> thread::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.handle.take().unwrap().join()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for ExecWorker {
    fn drop(&mut self) {
        if self.handle.is_some() {
            let _ = self.stop_and_join();
        }
    }
}

fn install_project_version(root: &Path, fixture: &ReleaseFixture, version: &str) {
    let path = write_project(root, version);
    assert!(
        project_command(root)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["tool", "lock", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        project_command(root)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["tool", "install", "--locked", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let _ = fixture;
}

#[test]
fn project_dry_runs_cover_all_lifecycle_commands_without_writes() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let before = snapshot(directory.path());
    let update = project_command(directory.path())
        .args([
            "--format",
            "json",
            "tool",
            "update",
            "--project",
            "--dry-run",
            "gh:owner/repo",
        ])
        .output()
        .unwrap();
    assert!(update.status.success(), "{update:?}");
    assert_eq!(snapshot(directory.path()), before);
    let update_text = project_command(directory.path())
        .args(["tool", "update", "--project", "--dry-run", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(update_text.status.success());
    assert_json_text_agree(&update_text.stdout, &update.stdout);

    let pin = project_command(directory.path())
        .args(["tool", "pin", "--project", "--dry-run", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(pin.status.success(), "{pin:?}");
    assert_eq!(snapshot(directory.path()), before);
    assert!(
        project_command(directory.path())
            .args(["tool", "pin", "--project", "gh:owner/repo"])
            .status()
            .unwrap()
            .success()
    );
    let after_pin = snapshot(directory.path());
    let unpin = project_command(directory.path())
        .args(["tool", "unpin", "--project", "--dry-run", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(unpin.status.success(), "{unpin:?}");
    assert_eq!(snapshot(directory.path()), after_pin);
    let remove = project_command(directory.path())
        .args(["tool", "remove", "--project", "--dry-run", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(remove.status.success(), "{remove:?}");
    assert_eq!(snapshot(directory.path()), after_pin);
    let purge = project_command(directory.path())
        .args(["tool", "purge", "--project", "--dry-run"])
        .output()
        .unwrap();
    assert!(purge.status.success(), "{purge:?}");
    assert_eq!(snapshot(directory.path()), after_pin);
    fixture.stop();
}

#[test]
fn cargo_declaration_refuses_stale_explicit_url_lock_before_install_effects() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: ripgrep\n    version: 14.1.1\n    provider: cargo\n    binaries: [new-rg]\n    cargo:\n      crate_name: ripgrep\n      version: 14.1.1\n      registry: https://index.crates.io/\n      checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      toolchain: 1.85.0-x86_64-unknown-linux-gnu\n      scripts: deny\n      build: isolated\n      network: deny\n",
    )
    .unwrap();

    let url = "https://example.test/legacy-binary.tar.gz";
    let digest = "b".repeat(64);
    let lockfile = neoenv_core::tools::ToolLockfile {
        schema_version: neoenv_core::tools::TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![neoenv_core::tools::LockedTool {
            id: "ripgrep".into(),
            resolved_version: "14.1.1".into(),
            url: url.into(),
            platform: neoenv_core::tools::Platform::host(),
            sha256: digest.clone(),
            provenance: neoenv_core::tools::ToolProvenance {
                provider: "explicit-url".into(),
                immutable_id: url.into(),
                repository: None,
                release_id: None,
                asset_id: None,
                registry_endpoint: None,
                registry_revision: None,
                manifest_sha256: None,
                package: None,
                registry_integrity: None,
                declaration_sha256: None,
                authentication: neoenv_core::tools::ProviderAuthPolicy::Prohibited,
            },
            verification: neoenv_core::tools::ArtifactVerification {
                sha256: digest,
                signature: None,
            },
            binaries: vec!["rg".into()],
            declaration_source: neoenv_core::SourceSpan::new("neoenv.yaml".into(), 3, 1),
            resolver: "explicit-url".into(),
            cargo_toolchain: None,
        }],
        pins: std::collections::BTreeMap::new(),
        manager_lock: None,
        cargo_build: None,
    };
    fs::write(
        neoenv_installer::tools::lockfile_path(root.path()),
        toml::to_string_pretty(&lockfile).unwrap(),
    )
    .unwrap();
    for args in [
        vec!["tool", "which", "rg"],
        vec!["tool", "use", "rg"],
        vec!["exec", "--", "rg"],
    ] {
        let output = project_command(root.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "Cargo installation requires one fully associated declaration and lock entry"
            ),
            "stale same-ID alias escaped Cargo refusal"
        );
    }
    let output = project_command(root.path())
        .args(["tool", "install", "--locked", "neoenv.yaml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "Cargo installation requires one fully associated declaration and lock entry"
        )
    );
    assert!(
        !neoenv_installer::tools::project_storage(root.path())
            .install_directory()
            .exists()
    );
    assert!(
        !neoenv_installer::tools::project_storage(root.path())
            .artifact_directory()
            .exists()
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn cargo_declaration_blocks_which_use_and_exec_fallback_without_a_lock() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: ripgrep\n    version: 14.1.1\n    provider: cargo\n    binaries: [rg]\n    cargo:\n      crate_name: ripgrep\n      version: 14.1.1\n      registry: https://index.crates.io/\n      checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      toolchain: 1.85.0-x86_64-unknown-linux-gnu\n      scripts: deny\n      build: isolated\n      network: deny\n",
    )
    .unwrap();
    for args in [
        vec!["tool", "which", "rg"],
        vec!["tool", "use", "rg"],
        vec!["exec", "--", "rg"],
    ] {
        let output = project_command(root.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Cargo declaration has no matching lock")
        );
    }
    let unrelated = project_command(root.path())
        .args(["exec", "--", "git", "--version"])
        .output()
        .unwrap();
    assert!(
        unrelated.status.success(),
        "unrelated PATH executable was blocked: {}",
        String::from_utf8_lossy(&unrelated.stderr)
    );
    assert!(!root.path().join("neoenv.lock").exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn installed_cargo_tool_is_selected_by_project_which_use_and_exec() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().unwrap();
    let crate_name = "nenv-cargo-e2e";
    let version = "1.2.3";
    let main = b"fn main() { println!(\"cargo-e2e-ok\"); }\n";
    let manifest = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n[[bin]]\nname = \"cargo-e2e-bin\"\npath = \"src/main.rs\"\n"
    );
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, contents) in [
            (
                format!("{crate_name}-{version}/Cargo.toml"),
                manifest.as_bytes(),
            ),
            (
                format!("{crate_name}-{version}/src/main.rs"),
                main.as_slice(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, contents).unwrap();
        }
        let shared_binary = b"#!/bin/sh\necho shared-archive-tool\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(shared_binary.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "bin/shared-bin", shared_binary.as_slice())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
    }
    let checksum = format!("{:x}", Sha256::digest(&bytes));
    let compiler = Command::new("rustc").arg("-vV").output().unwrap();
    assert!(compiler.status.success());
    let verbose = String::from_utf8(compiler.stdout).unwrap();
    let compiler_version = verbose
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let target = verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();
    let toolchain = format!("{compiler_version}-{target}");
    let data = root.path().join("neoenv-data");
    let managed_data = data.join("neoenv");
    let managed_bin = managed_data
        .join("rust")
        .join(compiler_version)
        .join("rustup/toolchains")
        .join(&toolchain)
        .join("bin");
    fs::create_dir_all(&managed_bin).unwrap();
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    assert!(sysroot.status.success());
    let sysroot = Path::new(std::str::from_utf8(&sysroot.stdout).unwrap().trim());
    for name in ["cargo", "rustc"] {
        let path = managed_bin.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nexec \"{}\" \"$@\"\n",
                sysroot.join("bin").join(name).display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(
        managed_data
            .join("rust")
            .join(compiler_version)
            .join(neoenv_core::names::RUST_RUNTIME_RECEIPT),
        "local fixture",
    )
    .unwrap();
    fs::write(
        root.path().join("neoenv.yaml"),
        format!(
            "format_version: 1\ntools:\n  - id: cargo-e2e\n    version: {version}\n    provider: cargo\n    binaries: [cargo-e2e-bin]\n    cargo:\n      crate_name: {crate_name}\n      version: {version}\n      registry: https://index.crates.io/\n      checksum: {checksum}\n      toolchain: {toolchain}\n      scripts: deny\n      build: isolated\n      network: deny\n  - id: shared-other\n    version: {version}\n    provider: explicit-url\n    url: https://example.test/shared.tar.gz\n    sha256: {checksum}\n    binaries: [shared-bin]\n"
        ),
    )
    .unwrap();
    let lock = project_command(root.path())
        .env("NEOENV_DATA_HOME", &data)
        .args(["tool", "lock", "neoenv.yaml"])
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );

    let storage = neoenv_installer::tools::project_storage(root.path());
    fs::create_dir_all(storage.artifact_directory()).unwrap();
    fs::write(storage.artifact_directory().join(checksum), bytes).unwrap();
    let installed = project_command(root.path())
        .env("NEOENV_DATA_HOME", &data)
        .env("NEOENV_ALLOW_CARGO_BUILD", "1")
        .args(["tool", "install", "--locked", "neoenv.yaml"])
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );

    let selected = project_command(root.path())
        .args(["tool", "which", "cargo-e2e-bin"])
        .output()
        .unwrap();
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert!(String::from_utf8_lossy(&selected.stdout).contains("cargo-e2e-bin"));
    let used = project_command(root.path())
        .args(["tool", "use", "cargo-e2e-bin"])
        .output()
        .unwrap();
    assert!(
        used.status.success(),
        "{}",
        String::from_utf8_lossy(&used.stderr)
    );
    assert!(String::from_utf8_lossy(&used.stdout).contains("cargo-e2e-ok"));
    let executed = project_command(root.path())
        .args(["exec", "--", "cargo-e2e-bin"])
        .output()
        .unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert!(String::from_utf8_lossy(&executed.stdout).contains("cargo-e2e-ok"));
    let config_path = root.path().join("neoenv.yaml");
    let current_config = fs::read_to_string(&config_path).unwrap();
    assert!(current_config.contains("binaries: [cargo-e2e-bin]"));
    fs::write(
        &config_path,
        current_config.replace("binaries: [cargo-e2e-bin]", "binaries: [new-cargo-alias]"),
    )
    .unwrap();
    for args in [
        vec!["tool", "which", "cargo-e2e-bin"],
        vec!["tool", "use", "cargo-e2e-bin"],
        vec!["exec", "--", "cargo-e2e-bin"],
    ] {
        let stale = project_command(root.path()).args(args).output().unwrap();
        assert!(
            !stale.status.success(),
            "stale locked Cargo alias was selected"
        );
        assert!(
            String::from_utf8_lossy(&stale.stderr).contains("Cargo"),
            "{stale:?}"
        );
    }
    fs::write(&config_path, current_config).unwrap();

    let lock_path = neoenv_installer::tools::lockfile_path(root.path());
    let mut installed_lock = neoenv_installer::tools::read_lockfile(&lock_path).unwrap();
    assert_eq!(installed_lock.tools.len(), 2);
    let current_tool = installed_lock
        .tools
        .iter()
        .find(|tool| tool.resolver == "cargo")
        .unwrap()
        .clone();
    let shared_tool = installed_lock
        .tools
        .iter()
        .find(|tool| tool.id == "shared-other")
        .unwrap()
        .clone();
    let current_build = installed_lock.cargo_build.clone().unwrap();
    let current_key = neoenv_installer::tools::install_key(&current_tool).unwrap();
    let current_root = storage.install_directory().join(&current_key);
    let shared_root = storage
        .install_directory()
        .join(neoenv_installer::tools::install_key(&shared_tool).unwrap());
    assert!(shared_root.exists());
    let mut obsolete_tool = current_tool.clone();
    let (current_version, target) = current_build
        .toolchain
        .split_once('-')
        .expect("current Cargo toolchain has a target triple");
    let obsolete_version = if current_version == "0.0.0" {
        "0.0.1"
    } else {
        "0.0.0"
    };
    let obsolete_toolchain = format!("{obsolete_version}-{target}");
    assert!(
        neoenv_core::tools::is_cargo_toolchain_pin(&obsolete_toolchain),
        "obsolete Cargo fixture must use a supported exact toolchain pin"
    );
    assert_ne!(
        obsolete_toolchain, current_build.toolchain,
        "obsolete Cargo fixture must use a different version for the same target"
    );
    obsolete_tool.cargo_toolchain = Some(obsolete_toolchain.clone());
    let mut obsolete_build = current_build;
    obsolete_build.toolchain = obsolete_toolchain;
    let obsolete_key = neoenv_installer::tools::install_key(&obsolete_tool).unwrap();
    assert_ne!(
        obsolete_key, current_key,
        "obsolete Cargo toolchain fixture must not alias the current install"
    );
    let obsolete_root = storage.install_directory().join(&obsolete_key);
    fs::create_dir_all(obsolete_root.join("bin")).unwrap();
    fs::copy(
        current_root.join("bin/cargo-e2e-bin"),
        obsolete_root.join("bin/cargo-e2e-bin"),
    )
    .unwrap();
    let metadata_path = current_root.join(".neoenv-install.toml");
    let metadata = fs::read_to_string(metadata_path).unwrap();
    assert!(metadata.contains(&format!("storage_key = \"{current_key}\"")));
    fs::write(
        obsolete_root.join(".neoenv-install.toml"),
        metadata.replace(
            &format!("storage_key = \"{current_key}\""),
            &format!("storage_key = \"{obsolete_key}\""),
        ),
    )
    .unwrap();
    fs::write(
        obsolete_root.join(".neoenv-artifact-sha256"),
        &current_tool.sha256,
    )
    .unwrap();
    fs::write(
        obsolete_root.join(neoenv_installer::tools::CARGO_BUILD_RECEIPT),
        neoenv_installer::tools::cargo_install_identity(&obsolete_tool, &obsolete_build).unwrap(),
    )
    .unwrap();

    let purged = project_command(root.path())
        .args(["tool", "purge", "--project"])
        .output()
        .unwrap();
    assert!(
        purged.status.success(),
        "{}",
        String::from_utf8_lossy(&purged.stderr)
    );
    assert!(
        current_root.exists(),
        "purge removed the lock-selected build"
    );
    assert!(
        !obsolete_root.exists(),
        "purge retained an obsolete build merely because it shares the archive checksum"
    );
    assert!(
        storage
            .artifact_directory()
            .join(&current_tool.sha256)
            .exists(),
        "purging an obsolete install must retain the still-locked archive"
    );

    let removed = project_command(root.path())
        .args(["tool", "remove", "--project", "cargo-e2e"])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    installed_lock = neoenv_installer::tools::read_lockfile(&lock_path).unwrap();
    assert_eq!(installed_lock.tools.len(), 1);
    assert_eq!(installed_lock.tools[0].id, "shared-other");
    assert!(installed_lock.validate().is_ok());
    assert!(
        installed_lock.cargo_build.is_none(),
        "whole-tool removal must clear the associated Cargo build record"
    );
    assert!(!current_root.exists());
    assert!(
        shared_root.exists(),
        "removing the Cargo tool must preserve a different selected tool sharing its source archive"
    );
}

#[test]
fn global_dry_runs_cover_all_lifecycle_commands_without_writes() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["use", "--user", "gh:owner/repo@1.0.0"])
            .status()
            .unwrap()
            .success()
    );
    let config_snapshot = snapshot(&config_home);
    let data_snapshot = snapshot(&data_home);
    for arguments in [
        vec!["tool", "update", "--user", "--dry-run", "gh:owner/repo"],
        vec!["tool", "pin", "--user", "--dry-run", "gh:owner/repo"],
    ] {
        let output = global_command(directory.path(), &config_home, &data_home)
            .args(&arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8(output.stdout.clone())
                .unwrap()
                .contains("scope: user"),
            "{arguments:?}: {output:?}"
        );
        assert_eq!(snapshot(&config_home), config_snapshot);
        assert_eq!(snapshot(&data_home), data_snapshot);
    }
    let json = global_command(directory.path(), &config_home, &data_home)
        .args([
            "tool",
            "pin",
            "--user",
            "--dry-run",
            "--format",
            "json",
            "gh:owner/repo",
        ])
        .output()
        .unwrap();
    assert!(json.status.success(), "{json:?}");
    let document: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(document["scope"], "user");
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .args(["tool", "pin", "--user", "gh:owner/repo"])
            .status()
            .unwrap()
            .success()
    );
    let pinned_snapshot = snapshot(&config_home);
    let pinned_data_snapshot = snapshot(&data_home);
    for arguments in [
        vec!["tool", "unpin", "--user", "--dry-run", "gh:owner/repo"],
        vec!["tool", "remove", "--user", "--dry-run", "gh:owner/repo"],
        vec!["tool", "purge", "--user", "--dry-run"],
    ] {
        let output = global_command(directory.path(), &config_home, &data_home)
            .args(&arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert_eq!(snapshot(&config_home), pinned_snapshot);
        assert_eq!(snapshot(&data_home), pinned_data_snapshot);
    }
    fixture.stop();
}

#[test]
fn project_purge_preserves_foreign_digest_named_data() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0"], "1.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let foreign = directory.path().join(".neoenv/tools").join("f".repeat(64));
    fs::create_dir_all(&foreign).unwrap();
    fs::write(foreign.join("sentinel"), b"foreign").unwrap();
    let output = project_command(directory.path())
        .args(["tool", "purge", "--project"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(foreign.join("sentinel")).unwrap(), b"foreign");
    fixture.stop();
}

#[test]
fn project_update_pin_remove_and_purge_preserve_references() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let lock_path = directory.path().join("neoenv.lock");
    let old_lock = fs::read_to_string(&lock_path).unwrap();
    let update = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(update.status.success(), "{update:?}");
    let new_lock = fs::read_to_string(&lock_path).unwrap();
    assert!(new_lock.contains("2.0.0"));
    let old_digest = old_lock
        .split("sha256 = \"")
        .nth(1)
        .and_then(|value| value.split('"').next())
        .unwrap()
        .to_owned();
    let old_root = directory.path().join(".neoenv/tools").join(&old_digest);
    assert!(old_root.is_dir());
    let pin = project_command(directory.path())
        .args(["tool", "pin", "--project", "gh:owner/repo@1.0.0"])
        .status()
        .unwrap();
    assert!(pin.success());
    let pinned_update = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(pinned_update.status.success(), "{pinned_update:?}");
    assert!(fs::read_to_string(&lock_path).unwrap().contains("2.0.0"));
    let purge = project_command(directory.path())
        .args(["tool", "purge", "--project"])
        .status()
        .unwrap();
    assert!(purge.success());
    assert!(old_root.is_dir());
    let remove_old = project_command(directory.path())
        .args(["tool", "unpin", "--project", "gh:owner/repo@1.0.0"])
        .status()
        .unwrap();
    assert!(remove_old.success());
    let remove = project_command(directory.path())
        .args(["tool", "remove", "--project", "gh:owner/repo@1.0.0"])
        .status()
        .unwrap();
    assert!(remove.success());
    assert!(!old_root.exists());
    let remove_all = project_command(directory.path())
        .args(["tool", "remove", "--project", "gh:owner/repo"])
        .status()
        .unwrap();
    assert!(remove_all.success());
    assert!(
        !directory
            .path()
            .join(".neoenv/tools")
            .join(&old_digest)
            .exists()
    );
    fixture.stop();
}

#[test]
#[cfg(unix)]
fn failed_project_update_keeps_old_executable_and_has_no_partial_install() {
    let directory = TempDir::new().unwrap();
    let fixture =
        ReleaseFixture::start_with_options(&["1.0.0", "2.0.0"], "2.0.0", Duration::ZERO, true);
    install_project_version(directory.path(), &fixture, "1.0.0");
    let old_lock = fs::read_to_string(directory.path().join("neoenv.lock")).unwrap();
    let output = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(directory.path().join("neoenv.lock")).unwrap(),
        old_lock
    );
    let exec = project_command(directory.path())
        .args(["exec", "--", "repo"])
        .output()
        .unwrap();
    assert!(exec.status.success(), "{exec:?}");
    assert_eq!(String::from_utf8(exec.stdout).unwrap(), "1.0.0");
    let tools = directory.path().join(".neoenv/tools");
    assert!(
        tools
            .read_dir()
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp"))
    );
    fixture.stop();
}

#[test]
#[cfg(unix)]
fn failed_midstream_download_keeps_previous_install_and_removes_staging() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start_with_truncated_latest(&["1.0.0", "2.0.0"], "2.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let old_lock = fs::read_to_string(directory.path().join("neoenv.lock")).unwrap();
    let new_artifact = b"#!/bin/sh\nprintf '2.0.0'\n";
    let new_digest = format!("{:x}", Sha256::digest(new_artifact));

    let output = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(directory.path().join("neoenv.lock")).unwrap(),
        old_lock,
        "a failed transfer must not publish a new lock entry"
    );

    let executable = directory
        .path()
        .join(".neoenv/tools")
        .join(
            old_lock
                .split("sha256 = \"")
                .nth(1)
                .and_then(|value| value.split('"').next())
                .unwrap(),
        )
        .join("bin/repo");
    assert!(
        executable.is_file(),
        "the previously published version disappeared"
    );
    let output = project_command(directory.path())
        .args(["exec", "--", "repo"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "1.0.0");

    let artifacts = directory.path().join(".neoenv/artifacts");
    assert!(
        !artifacts.join(&new_digest).exists(),
        "the failed transfer published a partial artifact"
    );
    let install_root = directory.path().join(".neoenv/tools").join(&new_digest);
    assert!(
        !install_root.exists(),
        "the failed transfer left an empty or partial install root"
    );
    assert_no_empty_install_roots(&directory.path().join(".neoenv/tools"));
    assert_no_installer_temporary_content(directory.path());
    fixture.stop();
}

#[cfg(unix)]
fn assert_no_empty_install_roots(root: &Path) {
    for entry in fs::read_dir(root).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            assert!(
                fs::read_dir(entry.path()).unwrap().next().is_some(),
                "empty nenv install root remained: {}",
                entry.path().display()
            );
        }
    }
}

#[cfg(unix)]
fn assert_no_installer_temporary_content(root: &Path) {
    fn visit(path: &Path) {
        for entry in fs::read_dir(path).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !Path::new(&name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp")),
                "installer temporary file remained: {}",
                entry.path().display()
            );
            if entry.file_type().unwrap().is_dir() {
                visit(&entry.path());
            }
        }
    }
    visit(root);
}

#[test]
fn global_lifecycle_reports_the_system_scope() {
    let directory = support::secure_temp_dir();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(&system_config).unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ndemo = \"1.0.0\"\n",
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "purge", "--global", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("scope: global")
    );
}

#[test]
fn global_update_pin_and_scope_independence() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    let install = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["use", "--user", "gh:owner/repo@1.0.0"])
        .output()
        .unwrap();
    assert!(install.status.success(), "{install:?}");
    let update_preview = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args([
            "--format",
            "json",
            "tool",
            "update",
            "--user",
            "--dry-run",
            "gh:owner/repo",
        ])
        .output()
        .unwrap();
    assert!(update_preview.status.success(), "{update_preview:?}");
    let text_preview = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--user", "--dry-run", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(text_preview.status.success());
    assert_json_text_agree(&text_preview.stdout, &update_preview.stdout);
    let update = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--user", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(update.status.success(), "{update:?}");
    let pin = global_command(directory.path(), &config_home, &data_home)
        .args(["tool", "pin", "--user", "gh:owner/repo@1.0.0"])
        .status()
        .unwrap();
    assert!(pin.success());
    let purge = global_command(directory.path(), &config_home, &data_home)
        .args(["tool", "purge", "--user"])
        .status()
        .unwrap();
    assert!(purge.success());
    assert!(data_home.join("neoenv/tools").read_dir().is_ok());
    fixture.stop();
}

#[test]
fn pinned_global_update_keeps_the_selected_version_without_provider_io() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["use", "--user", "gh:owner/repo@1.0.0"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .args(["tool", "pin", "--user", "gh:owner/repo"])
            .status()
            .unwrap()
            .success()
    );
    let requests_before = fixture.request_count();
    let output = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--user", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fixture.request_count(), requests_before);
    let config = fs::read_to_string(config_path(&config_home)).unwrap();
    assert!(config.contains("1.0.0"));
    assert!(!config.contains("2.0.0"));
    fixture.stop();
}

#[test]
fn update_rejects_a_version_the_provider_does_not_offer_and_keeps_the_lock() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0"], "1.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let lock_path = directory.path().join("neoenv.lock");
    let before = fs::read_to_string(&lock_path).unwrap();
    let no_newer = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(no_newer.status.success(), "{no_newer:?}");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), before);
    let unavailable = project_command(directory.path())
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["tool", "update", "--project", "gh:owner/repo@2.0.0"])
        .output()
        .unwrap();
    assert!(!unavailable.status.success());
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), before);
    fixture.stop();
}

#[test]
fn global_remove_distinguishes_one_version_from_the_whole_tool() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["use", "--user", "gh:owner/repo@1.0.0"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["tool", "update", "--user", "gh:owner/repo"])
            .status()
            .unwrap()
            .success()
    );
    let remove_old = global_command(directory.path(), &config_home, &data_home)
        .args(["tool", "remove", "--user", "gh:owner/repo@1.0.0"])
        .output()
        .unwrap();
    assert!(remove_old.status.success(), "{remove_old:?}");
    let config = fs::read_to_string(config_path(&config_home)).unwrap();
    assert!(config.contains("2.0.0"));
    assert!(!config.contains("1.0.0"));
    let remove_all = global_command(directory.path(), &config_home, &data_home)
        .args(["tool", "remove", "--user", "gh:owner/repo"])
        .status()
        .unwrap();
    assert!(remove_all.success());
    let config = fs::read_to_string(config_path(&config_home)).unwrap();
    assert!(!config.contains("gh:owner/repo"));
    let artifacts = data_home.join("neoenv/artifacts");
    assert!(
        !artifacts.exists()
            || fs::read_dir(artifacts).is_ok_and(|mut entries| entries.next().is_none())
    );
    fixture.stop();
}

#[test]
fn global_and_project_purge_do_not_cross_data_roots() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0"], "1.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", fixture.url())
            .args(["use", "--user", "gh:owner/repo@1.0.0"])
            .status()
            .unwrap()
            .success()
    );
    let project_executable = directory.path().join(".neoenv/tools");
    let global_executable = data_home.join("neoenv/tools");
    assert!(
        project_command(directory.path())
            .args(["tool", "purge", "--project"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        global_command(directory.path(), &config_home, &data_home)
            .args(["tool", "purge", "--user"])
            .status()
            .unwrap()
            .success()
    );
    assert!(project_executable.is_dir());
    assert!(global_executable.is_dir());
    assert!(fs::read_dir(project_executable).unwrap().next().is_some());
    assert!(fs::read_dir(global_executable).unwrap().next().is_some());
    fixture.stop();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn noisy_runaway_capture_stays_bounded() {
    let mut command = Command::new("sh");
    command.args(["-c", "while :; do printf 0123456789abcdef; done"]);
    let child = OwnedChild::spawn(&mut command).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let capture = child.stdout.as_ref().unwrap().state.lock().unwrap();
        if capture.seen > (MAX_CAPTURE as u64) * 8 {
            assert_eq!(capture.bytes.len(), MAX_CAPTURE);
            assert!(capture.truncated);
            break;
        }
        drop(capture);
        assert!(
            std::time::Instant::now() < deadline,
            "noisy child did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let error = child.finish(Duration::from_millis(200)).unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(error.contains("[output truncated]"), "{error}");
}

#[cfg(target_os = "linux")]
fn fixture_process_is_running(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state != "Z" && state != "X")
}

#[cfg(target_os = "linux")]
fn exercise_exited_leader_cleanup(drop_guard: bool) {
    let directory = tempfile::tempdir().unwrap();
    let gate = directory.path().join("keep-running");
    let ready = directory.path().join("ready");
    fs::write(&gate, b"fixture").unwrap();
    let mut command = Command::new("sh");
    command.args([
        "-c",
        &format!(
            "(printf ready > '{}'; while [ -e '{}' ]; do printf x; sleep 0.05; done) & echo $! >&2; while [ ! -e '{}' ]; do :; done; exit 0",
            ready.display(), gate.display(), ready.display()
        ),
    ]);
    let child = OwnedChild::spawn(&mut command).unwrap();
    assert!(
        child.wait_until_exit(Duration::from_secs(5)).unwrap(),
        "fixture leader did not exit"
    );
    let pid_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pid = loop {
        let bytes = child
            .stderr
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .bytes
            .clone();
        if let Ok(text) = std::str::from_utf8(&bytes)
            && text.ends_with('\n')
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            break pid;
        }
        assert!(
            std::time::Instant::now() < pid_deadline,
            "writer PID not captured"
        );
        thread::sleep(Duration::from_millis(5));
    };
    assert!(
        fixture_process_is_running(pid),
        "writer must remain alive after its leader exits"
    );
    let capture = Arc::clone(&child.stdout.as_ref().unwrap().state);
    if drop_guard {
        drop(child);
    } else {
        let output = child.finish(Duration::from_secs(5)).unwrap();
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            pid.to_string()
        );
    }
    assert!(ready.exists(), "writer must start before leader exits");
    assert_eq!(Arc::strong_count(&capture), 1, "capture reader must stop");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while fixture_process_is_running(pid) && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let still_running = fixture_process_is_running(pid);
    // Clean up the old implementation's writer even if the assertion fails.
    fs::remove_file(&gate).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while fixture_process_is_running(pid) && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !fixture_process_is_running(pid),
        "fixture writer did not stop"
    );
    assert!(!still_running, "leader exit left a writer descendant alive");
}

#[cfg(target_os = "linux")]
#[test]
fn exited_leader_does_not_leave_writer_descendant() {
    exercise_exited_leader_cleanup(false);
    exercise_exited_leader_cleanup(true);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn already_reaped_leader_refuses_process_group_signal() {
    let mut command = Command::new("sh");
    command.args(["-c", "exit 0"]);
    let mut child = OwnedChild::spawn(&mut command).unwrap();
    assert!(child.child.as_mut().unwrap().wait().unwrap().success());
    let error = child
        .terminate()
        .expect_err("reaped leader must not authorize a group signal");
    assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::ECHILD as i32));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn hung_exec_worker_is_bounded_and_reaped() {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
    let mut command = Command::new("sh");
    command.args(["-c", "printf fixture-start; exec sleep 30"]);
    let child = OwnedChild::spawn(&mut command).unwrap();
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.stdout.as_ref().unwrap().state.lock().unwrap().bytes != b"fixture-start" {
        assert!(
            std::time::Instant::now() < ready_deadline,
            "hung fixture did not start"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let started = std::time::Instant::now();
    let error = child.finish(Duration::from_millis(200)).unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(error.contains("fixture-start"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(kill(pid, None), Err(Errno::ESRCH), "child must be reaped");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn captured_failure_output_is_bounded_without_pipe_deadlock() {
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "printf fixture-error >&2; i=0; while [ \"$i\" -lt 10000 ]; do printf 0123456789abcdef; printf fedcba9876543210 >&2; i=$((i+1)); done; exit 7",
    ]);
    let output = OwnedChild::spawn(&mut command)
        .unwrap()
        .finish(Duration::from_secs(10))
        .expect("large output must not block the child");
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.ends_with(b"[output truncated]\n"));
    assert!(output.stdout.len() < 17 * 1024);
    assert!(output.stderr.starts_with(b"fixture-error"));
    assert!(output.stderr.ends_with(b"[output truncated]\n"));
    assert!(output.stderr.len() < 17 * 1024);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exec_worker_guard_reaps_child_during_panic() {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 30"]);
        let child = OwnedChild::spawn(&mut command).unwrap();
        sender.send(child.id()).unwrap();
        let _ = child.finish(Duration::from_millis(200));
    });
    let started = std::time::Instant::now();
    let mut pid = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _worker = ExecWorker {
            stop,
            handle: Some(handle),
        };
        pid = Some(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
        panic!("fixture assertion failure");
    }));
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        kill(Pid::from_raw(i32::try_from(pid.unwrap()).unwrap()), None),
        Err(Errno::ESRCH),
        "worker child must be reaped during unwind"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn concurrent_exec_observes_old_or_new_but_never_a_missing_executable() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    fixture.gate.arm();
    let mut command = project_command(directory.path());
    command.env("NEOENV_GITHUB_API_URL", fixture.url()).args([
        "tool",
        "update",
        "--project",
        "gh:owner/repo",
    ]);
    let mut update = OwnedChild::spawn(&mut command).unwrap();
    if !fixture.gate.wait_until_paused(Duration::from_secs(30)) {
        let _ = update.terminate();
        let output = update.output().unwrap();
        panic!("new artifact was not requested; update output: {output:?}");
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let root = directory.path().to_owned();
    let handle = thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            let mut command = project_command(&root);
            command.args(["exec", "--", "repo"]);
            let output = OwnedChild::spawn(&mut command)
                .map_err(|error| error.to_string())
                .and_then(|child| child.finish(Duration::from_secs(10)));
            let failed = output.is_err();
            if sender.send(output).is_err() || failed {
                break;
            }
        }
    });
    let mut worker = ExecWorker {
        stop,
        handle: Some(handle),
    };
    let first = receiver
        .recv_timeout(Duration::from_secs(30))
        .unwrap()
        .unwrap_or_else(|error| panic!("exec worker failed: {error}"));
    assert!(
        first.status.success(),
        "executable missing before publish: {first:?}"
    );
    assert_eq!(first.stdout, b"1.0.0");
    fixture.gate.release();
    let update_output = update
        .finish(Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("update did not finish: {error}"));
    assert!(
        update_output.status.success(),
        "update failed: {update_output:?}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .expect("new executable was never observed");
        let output = receiver
            .recv_timeout(remaining)
            .unwrap()
            .unwrap_or_else(|error| panic!("exec worker failed: {error}"));
        assert!(
            output.status.success(),
            "executable disappeared during update: {output:?}"
        );
        assert!(output.stdout == b"1.0.0" || output.stdout == b"2.0.0");
        if output.stdout == b"2.0.0" {
            break;
        }
    }
    worker.stop_and_join().unwrap();
    for output in receiver.try_iter() {
        let output = output.unwrap_or_else(|error| panic!("exec worker failed: {error}"));
        assert!(
            output.status.success(),
            "executable disappeared during update: {output:?}"
        );
        assert!(output.stdout == b"1.0.0" || output.stdout == b"2.0.0");
    }
    fixture.stop();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn interrupted_global_update_does_not_change_selection() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = ReleaseFixture::start(&["1.0.0", "2.0.0"], "2.0.0");
    let install = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .args(["use", "--user", "gh:owner/repo@1.0.0"])
        .output()
        .unwrap();
    assert!(install.status.success(), "{install:?}");
    let original_config = fs::read(config_path(&config_home)).unwrap();
    fixture.gate.arm();
    let mut command = global_command(directory.path(), &config_home, &data_home);
    command
        .env("NEOENV_GITHUB_API_URL", fixture.url())
        .env("NEOENV_HTTP_READ_IDLE_TIMEOUT", "5")
        .env("NEOENV_HTTP_TOTAL_TIMEOUT", "5")
        .args(["tool", "update", "--user", "gh:owner/repo"]);
    let mut child = OwnedChild::spawn(&mut command).unwrap();
    if !fixture.gate.wait_until_paused(Duration::from_secs(30)) {
        let _ = child.terminate();
        let output = child.output().unwrap();
        panic!("new artifact was not requested; update output: {output:?}");
    }
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGINT,
    )
    .unwrap();
    // Keep the body stalled until the worker exits. Its configured read-idle
    // timeout bounds the wait; the diagnostic proves SIGINT was observed.
    let output = child
        .finish(Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("cancelled update did not finish: {error}"));
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cancelled"),
        "{output:?}"
    );
    fixture.gate.release();
    let config = fs::read(config_path(&config_home)).unwrap();
    assert_eq!(
        config, original_config,
        "interrupted update must preserve selection"
    );
    fixture.stop();
}

#[cfg(windows)]
#[test]
fn locked_install_file_is_a_runtime_diagnostic() {
    let directory = TempDir::new().unwrap();
    let fixture = ReleaseFixture::start(&["1.0.0"], "1.0.0");
    install_project_version(directory.path(), &fixture, "1.0.0");
    let lock = directory.path().join("neoenv.lock");
    let lock_document = fs::read_to_string(&lock).unwrap();
    let digest = lock_document
        .split("sha256 = \"")
        .nth(1)
        .and_then(|value| value.split('"').next())
        .unwrap();
    let executable = directory
        .path()
        .join(".neoenv/tools")
        .join(digest)
        .join("bin/repo");
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        options.share_mode(0);
    }
    let file = options.open(&executable).unwrap();
    let output = project_command(directory.path())
        .args([
            "--format",
            "json",
            "tool",
            "remove",
            "--project",
            "gh:owner/repo",
        ])
        .output()
        .unwrap();
    drop(file);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    let code = document["diagnostic"]["code"].as_str().unwrap();
    assert!(matches!(code, "NEO522" | "NEO520"), "{document}");
    fixture.stop();
}
