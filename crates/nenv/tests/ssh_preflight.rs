//! CLI preflight against an owned fake transport. No SSH server or live secrets.
use std::{
    fmt::Write as _,
    fs,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

// RFC 8032 public verification key encoded as an SSH blob, not a private key.
const PIN: &str = "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

struct FakeTransport {
    port: u16,
    connections: Arc<AtomicUsize>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeTransport {
    fn new() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count.fetch_add(1, Ordering::SeqCst);
                        drop(stream); // Any regression fails quickly, not at a 30s deadline.
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.recv_timeout(Duration::from_millis(5)).is_ok() {
                            break;
                        }
                    }
                    Err(error) => panic!("owned fake transport: {error}"),
                }
            }
        });
        Self {
            port,
            connections,
            stop: Some(stop),
            worker: Some(worker),
        }
    }
}

impl Drop for FakeTransport {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = self.worker.take().unwrap().join();
    }
}

mod support;

#[test]
fn every_hosts_console_is_preflighted_before_direct_or_task_transport() {
    for invalid in [
        "password-length",
        "password-control",
        "alias-length",
        "additional-secret",
    ] {
        let transport = FakeTransport::new();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let later = if invalid == "alias-length" {
            "h".repeat(129)
        } else {
            "second".into()
        };
        let document = format!(
            "inventories:\n  lab:\n    defaults: {{user: fixture, port: {}}}\n    hosts:\n      first:\n        address: 127.0.0.1\n        host_key: {PIN}\n        password_env: FIRST_AUTH\n        password_auth: true\n        tags: [both]\n      {later}:\n        address: 127.0.0.1\n        host_key: {PIN}\n        password_env: SECOND_AUTH\n        password_auth: true\n        tags: [both]\ntasks:\n  remote:\n    uses: ssh\n    with: {{inventory: lab, targets: '@both'}}\n    run: 'touch must-not-execute'\n",
            transport.port,
        );
        fs::write(root.join("neoenv.yaml"), &document).unwrap();
        let parsed = neoenv_config::parse_project(&root.join("neoenv.yaml"), &document).unwrap();
        let inventory = &parsed.inventories["lab"];
        let mut policy = String::new();
        for host in ["first", later.as_str()] {
            for subject in [
                format!("inventory:lab/host:{host}"),
                neoenv_runtime::ssh::endpoint_subject_with_context(
                    inventory,
                    host,
                    &std::collections::BTreeMap::new(),
                    &root,
                )
                .unwrap(),
            ] {
                writeln!(
                    policy,
                    "[[grants]]\nsubject = {subject:?}\ncapability = 'connect'"
                )
                .unwrap();
            }
        }
        let task_subject = format!("project:{}/task:remote", root.display());
        writeln!(
            policy,
            "[[grants]]\nsubject = {task_subject:?}\ncapability = 'execute'"
        )
        .unwrap();
        fs::write(root.join("policy.toml"), policy).unwrap();
        let password = match invalid {
            "password-length" => "z".repeat(257),
            "password-control" => "fixture\nnot-a-live-password".into(),
            _ => "second-fixture".into(),
        };
        for args in [
            vec!["ssh", "-i", "lab", "@both", "--", "touch must-not-execute"],
            vec!["run", "remote"],
        ] {
            let output = support::TestCommand::new()
                .args(&args).current_dir(&root).env_clear()
                .env("HOME", &root)
                .env("NEOENV_CONFIG_HOME", root.join("config"))
                .env("NEOENV_DATA_HOME", root.join("data"))
                .env("NEOENV_CACHE_HOME", root.join("cache"))
                .env("NEOENV_STATE_HOME", root.join("state"))
                .env("NEOENV_CAPABILITY_POLICY", root.join("policy.toml"))
                // Names deliberately evade the name-based secret heuristic:
                // the second endpoint must add its own password to its policy.
                .env("FIRST_AUTH", "first-fixture")
                .env("SECOND_AUTH", &password)
                .env("EXTRA_SECRET", if invalid == "additional-secret" { "x".repeat(257) } else { String::new() })
                .output().unwrap();
            assert!(!output.status.success(), "{invalid} {args:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stdout.contains("redaction limits") || stderr.contains("redaction limits"),
                "not a console preflight failure: {invalid} {args:?}: {stdout} {stderr}"
            );
            assert!(!stdout.contains(&password) && !stderr.contains(&password));
            assert_eq!(
                transport.connections.load(Ordering::SeqCst),
                0,
                "connected before full preflight"
            );
        }
    }
}

#[test]
fn task_home_is_authorized_before_effects_and_dynamic_handoffs_are_refused() {
    let transport = FakeTransport::new();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let other_home = root.join("task-home");
    let document = format!(
        "inventories:\n  lab:\n    defaults: {{user: fixture, port: {}}}\n    hosts:\n      first:\n        address: 127.0.0.1\n        host_key: {PIN}\n        identity_file: ~/fixture-key\ntasks:\n  prep:\n    run: 'touch preceding-effect; printf \"HOME=/changed\\n\" >> \"$NEOENV_ENV\"'\n  remote-static:\n    uses: ssh\n    with: {{inventory: lab, targets: first}}\n    env:\n      HOME: {}\n    run: 'echo fixture'\n  remote-dynamic:\n    needs: [prep]\n    uses: ssh\n    with: {{inventory: lab, targets: first}}\n    env:\n      HOME: '${{HOME}}'\n    run: 'echo fixture'\n",
        transport.port,
        other_home.display()
    );
    fs::write(root.join("neoenv.yaml"), &document).unwrap();
    let parsed = neoenv_config::parse_project(&root.join("neoenv.yaml"), &document).unwrap();
    let env = std::collections::BTreeMap::from([("HOME".into(), other_home.display().to_string())]);
    let subject = neoenv_runtime::ssh::endpoint_subject_with_context(
        &parsed.inventories["lab"],
        "first",
        &env,
        &root,
    )
    .unwrap();
    let mut policy = String::new();
    for subject in ["inventory:lab/host:first".to_owned(), subject] {
        writeln!(
            policy,
            "[[grants]]\nsubject = {subject:?}\ncapability = 'connect'"
        )
        .unwrap();
    }
    for task in ["remote-static", "remote-dynamic"] {
        writeln!(
            policy,
            "[[grants]]\nsubject = {:?}\ncapability = 'execute'",
            format!("project:{}/task:{task}", root.display())
        )
        .unwrap();
    }
    fs::write(root.join("policy.toml"), policy).unwrap();
    let invoke = |task: &str| {
        support::TestCommand::new()
            .args(["run", task])
            .current_dir(&root)
            .env_clear()
            .env("HOME", &root)
            .env("NEOENV_CONFIG_HOME", root.join("config"))
            .env("NEOENV_DATA_HOME", root.join("data"))
            .env("NEOENV_CACHE_HOME", root.join("cache"))
            .env("NEOENV_STATE_HOME", root.join("state"))
            .env("NEOENV_CAPABILITY_POLICY", root.join("policy.toml"))
            .output()
            .unwrap()
    };
    let static_result = invoke("remote-static");
    assert!(!static_result.status.success());
    assert!(
        String::from_utf8_lossy(&static_result.stderr).contains("host-key verification"),
        "task-local grant must pass preflight: {}",
        String::from_utf8_lossy(&static_result.stderr)
    );
    let dynamic_result = invoke("remote-dynamic");
    assert!(!dynamic_result.status.success());
    assert!(
        String::from_utf8_lossy(&dynamic_result.stderr).contains("dynamic SSH identity"),
        "dynamic identity must be refused in preflight: {}",
        String::from_utf8_lossy(&dynamic_result.stderr)
    );
    assert!(!root.join("preceding-effect").exists());
}

#[test]
fn reserved_identity_grant_is_rejected_before_any_host_effect() {
    let transport = FakeTransport::new();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let document = format!(
        "inventories:\n  lab:\n    defaults: {{user: fixture, port: {}}}\n    hosts:\n      first:\n        address: 127.0.0.1\n        host_key: {PIN}\n        identity_file: ~/fixture-key\n      second:\n        address: 127.0.0.1\n        host_key: {PIN}\n        identity_file: ~/other-key\n",
        transport.port,
    );
    fs::write(root.join("neoenv.yaml"), document).unwrap();
    fs::write(
        root.join("policy.toml"),
        format!(
            "[[grants]]\nsubject = {:?}\ncapability = 'connect'\n",
            neoenv_policy::RESERVED_SSH_IDENTITY_SUBJECT
        ),
    )
    .unwrap();
    for host in ["first", "second"] {
        let output = support::TestCommand::new()
            .args(["ssh", "-i", "lab", host, "--", "echo fixture"])
            .current_dir(&root)
            .env_clear()
            .env("HOME", &root)
            .env("NEOENV_CONFIG_HOME", root.join("config"))
            .env("NEOENV_DATA_HOME", root.join("data"))
            .env("NEOENV_CACHE_HOME", root.join("cache"))
            .env("NEOENV_STATE_HOME", root.join("state"))
            .env("NEOENV_CAPABILITY_POLICY", root.join("policy.toml"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("invalid capability policy"),
            "reserved policy must fail closed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(transport.connections.load(Ordering::SeqCst), 0);
    }
}
