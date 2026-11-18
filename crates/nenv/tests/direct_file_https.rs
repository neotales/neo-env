//! Real HTTPS CLI lifecycle tests, with two separately built binaries.
//!
//! The ordinary release binary rejects our private fixture CA. A separate
//! binary is built from a temporary source copy with a test-only transport
//! injection that replaces roots but retains rustls verification. The shipped
//! transport has no test CA code or override; no CA is embedded in either.

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, ToSocketAddrs},
    path::PathBuf,
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[derive(Clone)]
enum Response {
    Body(Vec<u8>),
    Concurrent(Vec<u8>),
    Oversized,
    StreamedOversized,
    Redirect,
    Stall,
}

struct HttpsFixture {
    dir: TempDir,
    port: u16,
    ipv4_address: SocketAddr,
    loopback_addresses: Vec<SocketAddr>,
    ipv6_available: bool,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
    accepted_addresses: Arc<Mutex<Vec<SocketAddr>>>,
    tls_errors: Arc<Mutex<Vec<String>>>,
    server: Option<thread::JoinHandle<()>>,
    fixture_binary: PathBuf,
    release_binary: PathBuf,
}

struct Binaries {
    fixture: PathBuf,
    release: PathBuf,
    _fixture_source: TempDir,
    _target: TempDir,
}

fn bind_loopback_listeners() -> (Vec<TcpListener>, Vec<SocketAddr>, bool) {
    const PORT_ATTEMPTS: usize = 16;

    for _ in 0..PORT_ATTEMPTS {
        let ipv4 = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind IPv4 loopback fixture listener");
        let ipv4_address = ipv4.local_addr().unwrap();
        let ipv6_address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, ipv4_address.port(), 0, 0);

        let (mut listeners, mut addresses, ipv6_available) = match TcpListener::bind(ipv6_address) {
            Ok(ipv6) => (
                vec![ipv4, ipv6],
                vec![ipv4_address, ipv6_address.into()],
                true,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) if ipv6_is_unavailable(&error) => (vec![ipv4], vec![ipv4_address], false),
            Err(error) => panic!("bind IPv6 loopback fixture listener: {error}"),
        };

        for listener in &mut listeners {
            listener
                .set_nonblocking(true)
                .expect("set loopback fixture listener nonblocking");
        }
        addresses.sort();
        return (listeners, addresses, ipv6_available);
    }

    panic!("could not reserve one port for both loopback address families");
}

fn ipv6_is_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    ) || (cfg!(windows) && matches!(error.raw_os_error(), Some(10047 | 10049)))
}

fn localhost_addresses_match_fixture(
    resolved: &[SocketAddr],
    bound: &[SocketAddr],
    ipv6_available: bool,
) -> bool {
    !resolved.is_empty()
        && resolved.iter().all(|address| {
            address.ip().is_loopback()
                && (bound.contains(address) || (!ipv6_available && address.is_ipv6()))
        })
        && resolved.iter().any(|address| bound.contains(address))
}

/// Normalizes a temporary fixture file before applying LF-based test surgery.
fn replace_fixture_marker(contents: &str, marker: &str, replacement: &str) -> String {
    let contents = contents.replace("\r\n", "\n");
    assert_eq!(contents.matches(marker).count(), 1);
    contents.replacen(marker, replacement, 1)
}

/// Adds the fixture-only TLS dependency to the temporary lockfile copy.
fn add_fixture_lock_dependency(contents: &str) -> String {
    let lock = contents.replace("\r\n", "\n");
    let start = lock.find("name = \"neoenv-runtime\"\n").unwrap();
    let end = lock[start..]
        .find("\n[[package]]")
        .map_or(lock.len(), |offset| start + offset);
    let package = &lock[start..end];
    assert!(!package.contains("\n \"rustls\","));
    assert_eq!(package.matches("\n \"rustix\",").count(), 1);
    let package = package.replacen("\n \"rustix\",", "\n \"rustix\",\n \"rustls\",", 1);
    format!("{}{}{}", &lock[..start], package, &lock[end..])
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            fs::copy(entry.path(), target).unwrap();
        } else {
            panic!("unexpected special file in fixture source copy");
        }
    }
}

/// Separate target directory avoids recursively acquiring the test runner's
/// Cargo build lock. These binaries are not the distributable under test.
fn binaries() -> Binaries {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture_source = TempDir::new().unwrap();
    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "rustfmt.toml",
    ] {
        fs::copy(workspace.join(file), fixture_source.path().join(file)).unwrap();
    }
    copy_tree(
        &workspace.join("crates"),
        &fixture_source.path().join("crates"),
    );
    let manifest = fixture_source
        .path()
        .join("crates/neoenv-runtime/Cargo.toml");
    let contents = fs::read_to_string(&manifest).unwrap();
    let marker = "[dependencies]\n";
    fs::write(
        &manifest,
        replace_fixture_marker(
            &contents,
            marker,
            "[dependencies]\nrustls = { version = \"=0.23.46\", default-features = false, features = [\"ring\", \"std\", \"tls12\"] }\n",
        ),
    )
    .unwrap();
    // Modify only the temporary copy's lockfile to reflect the fixture-only
    // dependency; the real workspace lockfile is never written by tests.
    let lock_path = fixture_source.path().join("Cargo.lock");
    let lock = fs::read_to_string(&lock_path).unwrap();
    fs::write(&lock_path, add_fixture_lock_dependency(&lock)).unwrap();
    let transport = fixture_source
        .path()
        .join("crates/neoenv-runtime/src/transport.rs");
    let contents = fs::read_to_string(&transport).unwrap();
    let marker = "        let request = builder.build().get(url);";
    assert_eq!(contents.matches(marker).count(), 1);
    let injection = r#"
        let bytes = std::fs::read(std::env::var_os("NEOENV_TEST_TLS_CA_DER").expect("fixture CA path")).expect("read fixture CA");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(bytes)).expect("valid fixture CA");
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let request = builder.tls_config(Arc::new(config)).build().get(url);
"#;
    let contents = contents.replacen(marker, injection, 1);
    let marker = ".map_err(|error| HttpError::request(target, error))";
    let diagnostic = ".map_err(|error| { eprintln!(\"fixture transport error: {error:?}\"); HttpError::request(target, error) })";
    assert_eq!(contents.matches(marker).count(), 1);
    fs::write(&transport, contents.replacen(marker, diagnostic, 1)).unwrap();
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    fs::create_dir_all(&target_root).unwrap();
    let target_root = fs::canonicalize(target_root).unwrap();
    let target = tempfile::Builder::new()
        .prefix("direct-file-tls-fixture-")
        .tempdir_in(target_root)
        .unwrap();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let run = |source: &std::path::Path, args: &[&str]| {
        let output = Command::new(&cargo)
            .current_dir(source)
            .env("CARGO_TARGET_DIR", target.path())
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .env("CARGO_PROFILE_RELEASE_DEBUG", "0")
            .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0")
            .args(args)
            .output()
            .expect("build HTTPS test binary");
        assert!(output.status.success(), "fixture build: {output:?}");
    };
    run(
        fixture_source.path(),
        &["build", "--locked", "-p", "nenv", "--bin", "nenv"],
    );
    run(
        &workspace,
        &[
            "build",
            "--locked",
            "-p",
            "nenv",
            "--bin",
            "nenv",
            "--release",
            "--no-default-features",
        ],
    );
    Binaries {
        fixture: target
            .path()
            .join("debug")
            .join(format!("nenv{}", std::env::consts::EXE_SUFFIX)),
        release: target
            .path()
            .join("release")
            .join(format!("nenv{}", std::env::consts::EXE_SUFFIX)),
        _fixture_source: fixture_source,
        _target: target,
    }
}

impl HttpsFixture {
    fn new(response: Response, binaries: &Binaries) -> Self {
        let dir = TempDir::new().unwrap();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(dir.path().join("ca.der"), cert.der()).unwrap();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private.into())
            .unwrap();
        // Bind both loopback families to one port so a separately resolved
        // `localhost` connection cannot land on an unrelated service.
        let (listeners, loopback_addresses, ipv6_available) = bind_loopback_listeners();
        let ipv4_address = loopback_addresses
            .iter()
            .copied()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback listener is required");
        let port = ipv4_address.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        let accepts = Arc::new(AtomicUsize::new(0));
        let server_accepts = Arc::clone(&accepts);
        let accepted_addresses = Arc::new(Mutex::new(Vec::new()));
        let server_accepted_addresses = Arc::clone(&accepted_addresses);
        let tls_errors = Arc::new(Mutex::new(Vec::new()));
        let server_errors = Arc::clone(&tls_errors);
        let server = thread::spawn(move || {
            let mut clients = Vec::new();
            while !stopped.load(Ordering::Relaxed) {
                for listener in &listeners {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            server_accepts.fetch_add(1, Ordering::Relaxed);
                            server_accepted_addresses
                                .lock()
                                .unwrap()
                                .push(listener.local_addr().unwrap());
                            let tls = Arc::new(tls.clone());
                            let response = response.clone();
                            let requests = Arc::clone(&server_requests);
                            let errors = Arc::clone(&server_errors);
                            clients.push(thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                            let connection = rustls::ServerConnection::new(tls).unwrap();
                            let mut tls = rustls::StreamOwned::new(connection, stream);
                            let mut request = [0_u8; 4096];
                            if let Err(error) = tls.read(&mut request) {
                                errors.lock().unwrap().push(error.to_string());
                                return;
                            }
                            requests.fetch_add(1, Ordering::Relaxed);
                            match response {
                                Response::Body(body) => {
                                    let _ = write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                                    let _ = tls.write_all(&body);
                                    let _ = tls.flush();
                                }
                                Response::Concurrent(body) => {
                                    let deadline = Instant::now() + Duration::from_secs(5);
                                    while requests.load(Ordering::Relaxed) < 2 && Instant::now() < deadline {
                                        thread::sleep(Duration::from_millis(10));
                                    }
                                    let _ = write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                                    let _ = tls.write_all(&body);
                                    let _ = tls.flush();
                                }
                                Response::Oversized => {
                                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n");
                                    let _ = tls.flush();
                                }
                                Response::StreamedOversized => {
                                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n100001\r\n");
                                    let _ = tls.write_all(&vec![b'x'; 1_048_577]);
                                    let _ = tls.write_all(b"\r\n0\r\n\r\n");
                                    let _ = tls.flush();
                                }
                                Response::Redirect => {
                                    let _ = tls.write_all(b"HTTP/1.1 302 Found\r\nLocation: /escaped\r\nContent-Length: 0\r\n\r\n");
                                    let _ = tls.flush();
                                }
                                Response::Stall => {
                                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n");
                                    let _ = tls.flush();
                                    thread::sleep(Duration::from_secs(3));
                                }
                            }
                            }));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("HTTPS accept: {error}"),
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            for client in clients {
                client.join().unwrap();
            }
        });
        Self {
            dir,
            port,
            ipv4_address,
            loopback_addresses,
            ipv6_available,
            stop,
            requests,
            accepts,
            accepted_addresses,
            tls_errors,
            server: Some(server),
            fixture_binary: binaries.fixture.clone(),
            release_binary: binaries.release.clone(),
        }
    }

    fn spec(&self, digest: &str) -> String {
        format!(
            "https://localhost:{}/task.yaml#sha256={digest}&type=file",
            self.port
        )
    }

    fn command_with_binary(&self, project: &TempDir, binary: &std::path::Path) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(project.path())
            .env("NEOENV_CONFIG_HOME", self.dir.path().join("config"))
            .env("NEOENV_DATA_HOME", self.dir.path().join("data"))
            .env("NEOENV_TEST_TLS_CA_DER", self.dir.path().join("ca.der"))
            .env_remove("SSL_CERT_FILE")
            .env_remove("SSL_CERT_DIR")
            .env("NO_PROXY", "localhost,127.0.0.1")
            .env("NO_COLOR", "1")
            .env_remove("NEOENV_PROJECT")
            .env_remove("NEOENV_CONTEXT");
        command
    }

    fn command(&self, project: &TempDir) -> Command {
        self.command_with_binary(project, &self.fixture_binary)
    }

    fn run(&self, project: &TempDir, args: &[&str]) -> Output {
        self.command(project).args(args).output().unwrap()
    }

    fn assert_loopback_endpoint_families(&self) {
        assert!(self.ipv4_address.is_ipv4());
        assert!(self.loopback_addresses.contains(&self.ipv4_address));
        assert_eq!(
            self.loopback_addresses.iter().any(SocketAddr::is_ipv6),
            self.ipv6_available,
            "IPv6 listener availability must match the recorded fixture state"
        );
        assert!(
            self.loopback_addresses
                .iter()
                .all(|address| address.port() == self.port && address.ip().is_loopback()),
            "fixture listeners must be loopback-only and share one port: {:?}",
            self.loopback_addresses
        );

        let resolved = ("localhost", self.port)
            .to_socket_addrs()
            .unwrap()
            .collect::<Vec<_>>();
        assert!(!resolved.is_empty(), "localhost resolved to no endpoints");
        assert!(
            localhost_addresses_match_fixture(
                &resolved,
                &self.loopback_addresses,
                self.ipv6_available
            ),
            "localhost resolved outside the fixture's available loopback families: {resolved:?}"
        );

        for address in &self.loopback_addresses {
            let stream = std::net::TcpStream::connect_timeout(address, Duration::from_secs(2))
                .unwrap_or_else(|error| {
                    panic!("fixture endpoint {address} did not accept TCP: {error}")
                });
            drop(stream);
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let accepted = self.accepted_addresses.lock().unwrap().clone();
            if self
                .loopback_addresses
                .iter()
                .all(|address| accepted.contains(address))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not accept on every bound endpoint: {accepted:?}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_tls_alert(&self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let errors = self.tls_errors.lock().unwrap().clone();
            if errors.iter().any(|message| message.contains(expected)) {
                assert!(self.accepts.load(Ordering::Relaxed) > 0);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "expected TLS alert {expected}: {errors:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.take().unwrap().join().unwrap();
    }
}

fn https_fetch_then_approval_and_execution_for_module_and_package(binaries: &Binaries) {
    let body = b"tasks:\n  remote:\n    uses: shell\n    run: 'touch fetched-ran'\n";
    let digest = format!("{:x}", Sha256::digest(body));
    for package in [false, true] {
        let server = HttpsFixture::new(Response::Body(body.to_vec()), binaries);
        let project = TempDir::new().unwrap();
        let spec = server.spec(&digest);
        let config = if package {
            format!(
                "task_packages:\n  fetched:\n    from: '{spec}'\n    task: remote\ntasks:\n  check:\n    uses: package:fetched\n"
            )
        } else {
            format!("imports: ['{spec}']\n")
        };
        fs::write(project.path().join("neoenv.yaml"), config).unwrap();
        let fetch = server.run(&project, &["remote", "fetch", &spec]);
        assert!(
            fetch.status.success(),
            "fetch: {fetch:?}; accepts: {}; requests: {}; server TLS errors: {:?}",
            server.accepts.load(Ordering::Relaxed),
            server.requests.load(Ordering::Relaxed),
            server.tls_errors.lock().unwrap()
        );
        assert!(
            server
                .run(&project, &["trust", "add", "--project", "neoenv.yaml"])
                .status
                .success()
        );
        let task = if package { "check" } else { "remote" };
        let denied = server.run(&project, &["task", "run", task]);
        assert_eq!(denied.status.code(), Some(5), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains("not trusted"),
            "{denied:?}"
        );
        assert!(!project.path().join("fetched-ran").exists());
        let approve = server.run(&project, &["trust", "add", "--remote", &spec]);
        assert!(approve.status.success(), "approve: {approve:?}");
        let denied = server.run(&project, &["task", "run", task]);
        assert!(!denied.status.success(), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains("capability execute"),
            "{denied:?}"
        );
        assert!(!project.path().join("fetched-ran").exists());
        let subject = if package {
            format!("package:{digest}")
        } else {
            format!(
                "project:{}/task:remote",
                project.path().canonicalize().unwrap().display()
            )
        };
        let capabilities = server.dir.path().join("config/neoenv/capabilities.toml");
        fs::create_dir_all(capabilities.parent().unwrap()).unwrap();
        fs::write(
            capabilities,
            format!("[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"),
        )
        .unwrap();
        let run = server.run(&project, &["task", "run", task]);
        assert!(run.status.success(), "run: {run:?}");
        assert!(project.path().join("fetched-ran").exists());
    }
}

fn https_fetch_rejects_mismatch_oversize_stall_and_redirect_before_publish(binaries: &Binaries) {
    for response in [
        Response::Body(b"different bytes".to_vec()),
        Response::Oversized,
        Response::StreamedOversized,
        Response::Stall,
        Response::Redirect,
    ] {
        let server = HttpsFixture::new(response, binaries);
        let project = TempDir::new().unwrap();
        fs::write(project.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"expected bytes"));
        let spec = server.spec(&digest);
        let output = server
            .command(&project)
            .env("NEOENV_HTTP_READ_IDLE_TIMEOUT", "1")
            .env("NEOENV_HTTP_TOTAL_TIMEOUT", "2")
            .args(["remote", "fetch", &spec])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            1,
            "request was not served exactly once: {output:?}"
        );
        assert!(
            !project
                .path()
                .join(neoenv_core::names::PROJECT_MODULE_CACHE)
                .join("files")
                .join(digest)
                .exists()
        );
    }
}

fn https_fetch_rejects_untrusted_server_certificate(binaries: &Binaries) {
    let body = b"tasks:\n  remote: 'true'\n";
    let digest = format!("{:x}", Sha256::digest(body));
    let server = HttpsFixture::new(Response::Body(body.to_vec()), binaries);
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    let wrong_ca = server.dir.path().join("wrong-ca.der");
    // rcgen's default subject is identical for every generated certificate.
    // A different key with that same subject is an apparent issuer whose
    // signature fails, yielding DecryptError rather than UnknownCA.
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "unrelated fixture CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    fs::write(&wrong_ca, cert.der()).unwrap();
    let output = server
        .command(&project)
        .env("NEOENV_TEST_TLS_CA_DER", wrong_ca)
        .args(["remote", "fetch", &server.spec(&digest)])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 0, "{output:?}");
    server.assert_tls_alert("UnknownCA");
    assert!(
        !project
            .path()
            .join(neoenv_core::names::PROJECT_MODULE_CACHE)
            .join("files")
            .join(digest)
            .exists()
    );
}

fn release_binary_rejects_fixture_ca_even_when_test_variable_is_set(binaries: &Binaries) {
    let body = b"tasks:\n  remote: 'true'\n";
    let digest = format!("{:x}", Sha256::digest(body));
    let server = HttpsFixture::new(Response::Body(body.to_vec()), binaries);
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    let output = server
        .command_with_binary(&project, &server.release_binary)
        .args(["remote", "fetch", &server.spec(&digest)])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 0, "{output:?}");
    server.assert_tls_alert("UnknownCA");
}

fn production_tls_verifier_rejects_hostname_mismatch_with_fixture_anchor(binaries: &Binaries) {
    let body = b"tasks:\n  remote: 'true'\n";
    let digest = format!("{:x}", Sha256::digest(body));
    let server = HttpsFixture::new(Response::Body(body.to_vec()), binaries);
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    let positive = TempDir::new().unwrap();
    fs::write(positive.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    let output = server.run(&positive, &["remote", "fetch", &server.spec(&digest)]);
    assert!(
        output.status.success(),
        "hostname positive control: {output:?}"
    );
    // Check rustls's exact certificate error, rather than only a generic
    // handshake failure. This is an independent verifier-level assertion.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            fs::read(server.dir.path().join("ca.der")).unwrap(),
        ))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned()).unwrap();
    let connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let stream = std::net::TcpStream::connect(server.ipv4_address).unwrap();
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let result = tls
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .and_then(|()| tls.flush())
        .and_then(|()| tls.read(&mut [0_u8; 1]).map(|_| ()));
    let error = result.unwrap_err();
    let cause = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>());
    assert!(
        matches!(
            cause,
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. }
            ))
        ),
        "{error:?}"
    );
    // Wait for the independent verifier's server-side alert and discard it,
    // so only the subsequent CLI connection can satisfy the next assertion.
    server.assert_tls_alert("BadCertificate");
    server.tls_errors.lock().unwrap().clear();
    let accepts_before_cli = server.accepts.load(Ordering::Relaxed);
    // The certificate names localhost, not the loopback IP. The fixture build
    // injects the trusted root but uses the same rustls verifier as production.
    let spec = server.spec(&digest).replacen("localhost", "127.0.0.1", 1);
    let output = server
        .command(&project)
        .args(["remote", "fetch", &spec])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 1, "{output:?}");
    server.assert_tls_alert("BadCertificate");
    assert!(server.accepts.load(Ordering::Relaxed) > accepts_before_cli);
}

fn concurrent_https_fetches_publish_one_verified_cache_entry(binaries: &Binaries) {
    let body = b"tasks:\n  remote: 'true'\n";
    let digest = format!("{:x}", Sha256::digest(body));
    let server = HttpsFixture::new(Response::Concurrent(body.to_vec()), binaries);
    let project = TempDir::new().unwrap();
    fs::write(project.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    let spec = server.spec(&digest);
    let mut first = server
        .command(&project)
        .args(["remote", "fetch", &spec])
        .spawn()
        .unwrap();
    let mut second = server
        .command(&project)
        .args(["remote", "fetch", &spec])
        .spawn()
        .unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);
    let path: PathBuf = project
        .path()
        .join(neoenv_core::names::PROJECT_MODULE_CACHE)
        .join("files")
        .join(digest);
    assert_eq!(fs::read(path).unwrap(), body);
}

#[test]
fn fixture_marker_replacement_handles_lf_and_crlf_inputs() {
    let marker = "[dependencies]\n";
    let replacement = "[dependencies]\nrustls = { version = \"=0.23.46\" }\n";
    for (input, expected) in [
        (
            "[dependencies]\nserde = \"1\"\n",
            "[dependencies]\nrustls = { version = \"=0.23.46\" }\nserde = \"1\"\n",
        ),
        (
            "[dependencies]\r\nserde = \"1\"\r\n",
            "[dependencies]\nrustls = { version = \"=0.23.46\" }\nserde = \"1\"\n",
        ),
    ] {
        assert_eq!(replace_fixture_marker(input, marker, replacement), expected);
    }

    let lock = "name = \"neoenv-runtime\"\nversion = \"0.1.0\"\ndependencies = [\n \"rustix\",\n]\n\n[[package]]\n";
    for input in [lock.to_owned(), lock.replace('\n', "\r\n")] {
        let changed = add_fixture_lock_dependency(&input);
        assert!(changed.contains("\n \"rustix\",\n \"rustls\",\n"));
    }
}

#[test]
fn localhost_resolution_requires_a_bound_family_when_ipv6_is_unavailable() {
    let bound = [SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443))];
    let only_v6 = [SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        443,
        0,
        0,
    ))];

    assert!(
        !localhost_addresses_match_fixture(&only_v6, &bound, false),
        "an IPv6-only localhost result cannot match an IPv4-only fixture"
    );
    assert!(
        localhost_addresses_match_fixture(
            &[
                only_v6[0],
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
            ],
            &bound,
            false,
        ),
        "an unavailable IPv6 result may coexist with a usable bound IPv4 result"
    );
    assert!(
        !localhost_addresses_match_fixture(&only_v6, &bound, true),
        "an available but unbound IPv6 result must be rejected"
    );
}

#[test]
fn controlled_direct_file_https_lifecycle() {
    // Stack ownership removes both nested Cargo output and copied source on
    // success or panic, without touching any other run's target.
    let binaries = binaries();
    let endpoint_fixture = HttpsFixture::new(Response::Body(Vec::new()), &binaries);
    endpoint_fixture.assert_loopback_endpoint_families();
    https_fetch_then_approval_and_execution_for_module_and_package(&binaries);
    https_fetch_rejects_mismatch_oversize_stall_and_redirect_before_publish(&binaries);
    https_fetch_rejects_untrusted_server_certificate(&binaries);
    release_binary_rejects_fixture_ca_even_when_test_variable_is_set(&binaries);
    production_tls_verifier_rejects_hostname_mismatch_with_fixture_anchor(&binaries);
    concurrent_https_fetches_publish_one_verified_cache_entry(&binaries);
}
