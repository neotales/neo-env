//! Explicit Docker lane: actual SSH/SCP through the CLI, two independent peers.
//! Never falls back to local sshd or reads host identities/credentials.
#![cfg(target_os = "linux")]

use neotales_age::{AgeFile, AgeKey, AgeRecipient};
use std::{
    fmt::Write as _,
    fs,
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant},
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
// The same OCI digest already pinned by rs/lib/ssh/e2e.
const IMAGE: &str = "lscr.io/linuxserver/openssh-server";
const TAG: &str = "latest@sha256:161e0b670b31d9539ca1718bc5943e981779331b4e1c9d32e8929d7652a1f22f";
const LITERAL: &str = "a'; touch injected.txt; printf 'literal\nline";

async fn peer(
    password: &str,
    network: &str,
    public_key: &str,
) -> Result<(ContainerAsync<GenericImage>, u16, String), Error> {
    let container = GenericImage::new(IMAGE, TAG)
        .with_exposed_port(2222.tcp())
        .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
        .with_env_var("USER_NAME", "fixture")
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("USER_PASSWORD", password)
        .with_env_var("PUBLIC_KEY", public_key)
        .with_env_var("SUDO_ACCESS", "false")
        .with_network(network)
        .with_mapped_port(0, 2222.tcp())
        .with_host_config_modifier(|config| {
            // Docker allocates unique ports; bind them only to loopback.
            config.publish_all_ports = Some(false);
            assert!(
                config
                    .port_bindings
                    .as_ref()
                    .is_some_and(|ports| ports.contains_key("2222/tcp")),
                "fixture needs an explicit loopback port binding"
            );
            for bindings in config
                .port_bindings
                .iter_mut()
                .flat_map(|ports| ports.values_mut())
                .flatten()
                .flatten()
            {
                bindings.host_ip = Some("127.0.0.1".into());
            }
        })
        .start()
        .await?;
    let port = container.get_host_port_ipv4(2222.tcp()).await?;
    let mut output = container
        .exec(ExecCommand::new([
            "cat",
            "/config/ssh_host_keys/ssh_host_ed25519_key.pub",
        ]))
        .await?;
    let public = String::from_utf8(output.stdout_to_vec().await?)?;
    let pin = public
        .split_whitespace()
        .nth(1)
        .ok_or("fixture public host key missing")?
        .to_owned();
    Ok((container, port, pin))
}

async fn fixture_identity(password: &str) -> Result<(String, String, String, String), Error> {
    let container = GenericImage::new(IMAGE, TAG)
        .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
        .with_env_var("USER_NAME", "fixture")
        .with_env_var("PASSWORD_ACCESS", "true")
        .with_env_var("USER_PASSWORD", password)
        .start()
        .await?;
    let mut generated = container
        .exec(ExecCommand::new([
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "fixture-passphrase",
            "-f",
            "/tmp/neoenv-fixture-key",
        ]))
        .await?;
    let _ = generated.exit_code().await?;
    let _ = generated.stdout_to_vec().await?;
    let mut private = container
        .exec(ExecCommand::new(["cat", "/tmp/neoenv-fixture-key"]))
        .await?;
    let mut public = container
        .exec(ExecCommand::new(["cat", "/tmp/neoenv-fixture-key.pub"]))
        .await?;
    let mut generated_agent_key = container
        .exec(ExecCommand::new([
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            "/tmp/neoenv-agent-key",
        ]))
        .await?;
    let agent_key_status = generated_agent_key.exit_code().await?;
    if agent_key_status.is_some_and(|code| code != 0) {
        return Err(format!(
            "fixture unencrypted key generation failed: {}",
            String::from_utf8_lossy(&generated_agent_key.stderr_to_vec().await?)
        )
        .into());
    }
    let _ = generated_agent_key.stdout_to_vec().await?;
    let mut agent_private = container
        .exec(ExecCommand::new(["cat", "/tmp/neoenv-agent-key"]))
        .await?;
    let mut agent_public = container
        .exec(ExecCommand::new(["cat", "/tmp/neoenv-agent-key.pub"]))
        .await?;
    Ok((
        String::from_utf8(private.stdout_to_vec().await?)?,
        String::from_utf8(public.stdout_to_vec().await?)?,
        String::from_utf8(agent_private.stdout_to_vec().await?)?,
        String::from_utf8(agent_public.stdout_to_vec().await?)?,
    ))
}

fn cli_command(root: &Path, password: &str, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    command
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("HOME", root)
        .env("NEOENV_CONFIG_HOME", root.join("config"))
        .env("NEOENV_DATA_HOME", root.join("data"))
        .env("NEOENV_CACHE_HOME", root.join("cache"))
        .env("NEOENV_STATE_HOME", root.join("state"))
        .env("NEOENV_CAPABILITY_POLICY", root.join("capabilities.toml"))
        .env("FIXTURE_PASSWORD", password)
        .env("FIXTURE_KEY_PASSPHRASE", "fixture-passphrase")
        .env("FIXTURE_MESSAGE", LITERAL);
    command
}

fn invoke(root: &Path, password: &str, args: &[&str]) -> Output {
    cli_command(root, password, args)
        .output()
        .expect("CLI starts")
}

fn invoke_with_agent(root: &Path, password: &str, socket: &Path, args: &[&str]) -> Output {
    let mut command = cli_command(root, password, args);
    command.env("SSH_AUTH_SOCK", socket);
    command.output().expect("CLI starts with fixture agent")
}

struct FixtureProcess(Option<std::process::Child>);
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn succeeds(root: &Path, password: &str, args: &[&str]) -> Output {
    let output = invoke(root, password, args);
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(password));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(password));
    output
}

fn policy(root: &Path, inventory: &neoenv_config::Inventory, names: &[&str], tasks: &[&str]) {
    let mut subjects = Vec::new();
    for name in names {
        subjects.push((
            neoenv_runtime::inventory::host_subject("lab", name),
            "connect",
        ));
        subjects.push((
            neoenv_runtime::ssh::endpoint_subject_with_context(
                inventory,
                name,
                &std::collections::BTreeMap::from([("HOME".into(), root.display().to_string())]),
                root,
            )
            .expect("fixture endpoint subject"),
            "connect",
        ));
    }
    for task in tasks {
        subjects.push((format!("project:{}/task:{task}", root.display()), "execute"));
    }
    let mut text = String::new();
    for (subject, capability) in subjects {
        writeln!(
            text,
            "[[grants]]\nsubject = {subject:?}\ncapability = {capability:?}"
        )
        .expect("fixture policy formats");
    }
    fs::write(root.join("capabilities.toml"), text).expect("fixture policy");
}

#[tokio::test(flavor = "multi_thread")]
// One owned two-host fixture keeps setup/teardown isolated across the whole
// observable workflow, including refusals that must not mutate either peer.
#[allow(clippy::too_many_lines)]
async fn actual_ssh_scp_templates_and_two_host_authorization() -> Result<(), Error> {
    if std::env::var("DOCKER_HOST").is_ok_and(|host| !host.starts_with("unix://")) {
        return Err("SSH fixture requires a local Unix-socket Docker daemon".into());
    }
    let mut entropy = [0; 24];
    getrandom::fill(&mut entropy).map_err(|_| "fixture entropy unavailable")?;
    let mut password = String::new();
    for byte in entropy {
        write!(password, "{byte:02x}").expect("fixture password formats");
    }
    let (private_key, public_key, agent_private_key, agent_public_key) =
        fixture_identity(&password).await?;
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let age_key = AgeKey::generate()?;
    let age_identity = root.join("fixture-age-identity.txt");
    fs::write(&age_identity, format!("{}\n", age_key.private_key))?;
    let age_recipient = AgeRecipient::from_public_key(&age_key.public_key)?;
    let encrypted_passphrase = AgeFile::encrypt_armored(b"fixture-passphrase", &[age_recipient])?;
    let mut encrypted_passphrase_yaml = String::new();
    for line in encrypted_passphrase.lines() {
        writeln!(encrypted_passphrase_yaml, "        {line}")?;
    }
    let identity_path = root.join("fixture-key");
    fs::write(&identity_path, private_key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))?;
    }
    let imported_by_openssh = Command::new("ssh-keygen")
        .args(["-y", "-P", "fixture-passphrase", "-f"])
        .arg(&identity_path)
        .output()?;
    if !imported_by_openssh.status.success() {
        return Err(format!(
            "encrypted fixture key failed independent OpenSSH validation: {}",
            String::from_utf8_lossy(&imported_by_openssh.stderr)
        )
        .into());
    }
    let agent_key_path = root.join("fixture-agent-key");
    fs::write(&agent_key_path, agent_private_key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&agent_key_path, fs::Permissions::from_mode(0o600))?;
    }
    let agent_socket = root.join("fixture-agent.sock");
    let agent = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&agent_socket)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut agent = FixtureProcess(Some(agent));
    let agent_deadline = Instant::now() + Duration::from_secs(5);
    while !agent_socket.exists() {
        if agent
            .0
            .as_mut()
            .expect("owned fixture agent")
            .try_wait()?
            .is_some()
        {
            return Err("isolated fixture ssh-agent exited before creating its socket".into());
        }
        if Instant::now() >= agent_deadline {
            return Err("isolated fixture ssh-agent socket was not created".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let rejected_key = root.join("fixture-rejected-key");
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&rejected_key)
        .env_clear()
        .output()?;
    if !generated.status.success() {
        return Err("fixture rejected key generation failed".into());
    }
    let added_rejected = Command::new("ssh-add")
        .arg(&rejected_key)
        .env_clear()
        .env("SSH_AUTH_SOCK", &agent_socket)
        .output()?;
    if !added_rejected.status.success() {
        return Err("could not load rejected fixture key".into());
    }
    let added = Command::new("ssh-add")
        .arg(&agent_key_path)
        .env_clear()
        .env("SSH_AUTH_SOCK", &agent_socket)
        .output()?;
    if !added.status.success() {
        return Err(format!(
            "could not load the fixture key into isolated ssh-agent: {}",
            String::from_utf8_lossy(&added.stderr)
        )
        .into());
    }
    let network = format!(
        "neoenv-ssh-{}",
        root.file_name()
            .ok_or("fixture name missing")?
            .to_string_lossy()
    );
    let public_keys = format!("{public_key}\n{agent_public_key}");
    let (first_peer, port1, pin1) = peer(&password, &network, &public_keys).await?;
    let (second_peer, port2, pin2) = peer(&password, &network, &public_keys).await?;
    assert_ne!(port1, port2);
    assert_ne!(pin1, pin2, "each container generates its own host key");
    let document = format!(
        r#"format_version: 1
inventories:
  lab:
    defaults:
      user: fixture
      port: {port1}
    hosts:
      first:
        address: 127.0.0.1
        host_key: {pin1}
        password_env: FIXTURE_PASSWORD
        password_auth: true
        tags: [both]
      second:
        address: 127.0.0.1
        port: {port2}
        user: fixture
        host_key: {pin2}
        password_env: FIXTURE_PASSWORD
        password_auth: true
        tags: [both]
tasks:
  templated:
    uses: ssh
    with:
      inventory: lab
      targets: "@both"
      timeout: 10s
    run: |
      printf '%s' '{{{{ .host.name }}}}:{{{{ "rendered" | upper }}}}' > rendered.txt
      printf '%s' {{{{ .shell.env.FIXTURE_MESSAGE }}}} > quoted.txt
      test ! -e injected.txt
  denied-task:
    uses: ssh
    with:
      inventory: lab
      targets: "@both"
    run: touch denied-task.txt
  deadline:
    uses: ssh
    with:
      inventory: lab
      targets: first
      timeout: 1s
    run: printf entered > timeout-start.txt; sleep 5
  bad-option:
    uses: ssh
    with:
      inventory: lab
      targets: first
      ignored: no
    run: touch should-not-exist
  identity-task:
    uses: ssh
    with:
      inventory: lab
      targets: first
      timeout: 10s
    env:
      FIXTURE_KEY_PASSPHRASE: nsv://fixture/key-passphrase
    run: printf fixture-passphrase; printf fixture-passphrase >&2; printf identity > identity.txt
  agent-task:
    uses: ssh
    with:
      inventory: lab
      targets: first
      timeout: 10s
    run: printf agent > agent.txt
"#
    );
    fs::write(root.join("neoenv.yaml"), &document)?;
    let parsed = neoenv_config::parse_project(&root.join("neoenv.yaml"), &document)?;
    let inventory = &parsed.inventories["lab"];
    // A later host's password is deliberately invisible to the name-based
    // secret heuristic. Its own endpoint policy must fail before first executes.
    let preflight_document = document.replace(
        "        password_env: FIXTURE_PASSWORD\n        password_auth: true\n        tags: [both]\ntasks:",
        "        password_env: SECOND_AUTH\n        password_auth: true\n        tags: [both]\ntasks:",
    );
    assert_ne!(preflight_document, document);
    let preflight_parsed =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &preflight_document)?;
    fs::write(root.join("neoenv.yaml"), &preflight_document)?;
    policy(
        &root,
        &preflight_parsed.inventories["lab"],
        &["first", "second"],
        &["denied-task"],
    );
    for args in [
        vec!["ssh", "-i", "lab", "@both", "--", "touch denied-task.txt"],
        vec!["run", "denied-task"],
    ] {
        let refused = cli_command(&root, &password, &args)
            .env("SECOND_AUTH", "x".repeat(257))
            .output()?;
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stdout).contains("redaction limits")
                || String::from_utf8_lossy(&refused.stderr).contains("redaction limits")
        );
        for peer in [&first_peer, &second_peer] {
            let mut result = peer
                .exec(ExecCommand::new([
                    "sh",
                    "-c",
                    "test ! -e /config/denied-task.txt && printf untouched",
                ]))
                .await?;
            assert_eq!(result.stdout_to_vec().await?, b"untouched");
        }
    }
    fs::write(root.join("neoenv.yaml"), &document)?;
    policy(
        &root,
        inventory,
        &["first", "second"],
        &["templated", "deadline", "bad-option"],
    );
    succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "@both",
            "--",
            "printf connected > marker.txt",
        ],
    );
    for name in ["first", "second"] {
        succeeds(
            &root,
            &password,
            &[
                "ssh",
                "-i",
                "lab",
                name,
                "--",
                "test \"$(cat marker.txt)\" = connected",
            ],
        );
    }
    let console = succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "@both",
            "--",
            "printf '\\033[31mhello\\n'; printf 'warning\\n' >&2; head -c 131072 /dev/zero | tr '\\000' x; printf tail",
        ],
    );
    let stdout = String::from_utf8_lossy(&console.stdout);
    let stderr = String::from_utf8_lossy(&console.stderr);
    assert!(stdout.contains("[first stdout] \x1b[31mhello"));
    assert!(stdout.contains("[second stdout] \x1b[31mhello"));
    assert!(stderr.contains("[first stderr] warning"));
    assert!(stderr.contains("[second stderr] warning"));
    assert!(stdout.len() > 262_144);
    let json = succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "--format",
            "json",
            "first",
            "--",
            "printf json-tail",
        ],
    );
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)?;
    assert_eq!(report["status"], "succeeded");
    assert!(String::from_utf8_lossy(&json.stderr).contains("[first stdout] json-tail"));
    let secret_script = format!("printf '%s' '{password}'; printf '%s' '{password}' >&2; exit 17");
    let failed = invoke(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", &secret_script],
    );
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains(&password));
    assert!(!String::from_utf8_lossy(&failed.stderr).contains(&password));
    let wrong_password = invoke(
        &root,
        "wrong-fixture-only",
        &["ssh", "-i", "lab", "first", "--", "true"],
    );
    assert!(!wrong_password.status.success());
    assert!(String::from_utf8_lossy(&wrong_password.stderr).contains("authentication failed"));
    assert!(
        !invoke(&root, &password, &["run", "denied-task"])
            .status
            .success()
    );
    succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "@both",
            "--",
            "test ! -e denied-task.txt",
        ],
    );
    fs::write(root.join("payload.txt"), b"actual SCP payload\0\n")?;
    succeeds(
        &root,
        &password,
        &["scp", "-i", "lab", "payload.txt", "copied.txt", "@both"],
    );
    for name in ["first", "second"] {
        succeeds(
            &root,
            &password,
            &[
                "scp",
                "-i",
                "lab",
                "--pull",
                "copied.txt",
                "received.txt",
                name,
            ],
        );
        assert_eq!(
            fs::read(root.join("received.txt"))?,
            b"actual SCP payload\0\n"
        );
    }
    succeeds(&root, &password, &["run", "templated"]);
    for name in ["first", "second"] {
        succeeds(
            &root,
            &password,
            &[
                "scp",
                "-i",
                "lab",
                "--pull",
                "rendered.txt",
                "rendered.txt",
                name,
            ],
        );
        assert_eq!(
            fs::read(root.join("rendered.txt"))?,
            format!("{name}:RENDERED").as_bytes()
        );
        succeeds(
            &root,
            &password,
            &[
                "scp",
                "-i",
                "lab",
                "--pull",
                "quoted.txt",
                "quoted.txt",
                name,
            ],
        );
        assert_eq!(fs::read(root.join("quoted.txt"))?, LITERAL.as_bytes());
    }
    let start = Instant::now();
    let timed_out = invoke(&root, &password, &["run", "deadline"]);
    assert!(!timed_out.status.success());
    assert!(String::from_utf8_lossy(&timed_out.stdout).contains("TimedOut"));
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "overall SSH deadline did not bound the operation"
    );
    succeeds(
        &root,
        &password,
        &[
            "scp",
            "-i",
            "lab",
            "--pull",
            "timeout-start.txt",
            "timeout-start.txt",
            "first",
        ],
    );
    assert_eq!(fs::read(root.join("timeout-start.txt"))?, b"entered");
    assert!(
        !invoke(&root, &password, &["run", "bad-option"])
            .status
            .success()
    );
    let environment =
        std::collections::BTreeMap::from([("FIXTURE_PASSWORD".into(), password.clone())]);
    let endpoint =
        neoenv_runtime::ssh::Endpoint::resolve_with_root(inventory, "first", &environment, &root)?;
    let cancellation = neoenv_runtime::tasks::TaskCancellation::new();
    let trigger = cancellation.clone();
    let worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        trigger.cancel();
    });
    let start = Instant::now();
    let cancelled = neoenv_runtime::ssh::execute_console(
        &endpoint,
        "printf entered > cancel-start.txt; printf cancel-tail; sleep 5",
        Duration::from_secs(10),
        neoenv_runtime::ssh::ConsoleOptions {
            alias: "cancel-fixture",
            stderr_only: false,
            secrets: &[],
            cancellation: Some(cancellation),
        },
    );
    worker
        .join()
        .map_err(|_| "fixture cancellation worker failed")?;
    assert!(cancelled.is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    succeeds(
        &root,
        &password,
        &[
            "scp",
            "-i",
            "lab",
            "--pull",
            "cancel-start.txt",
            "cancel-start.txt",
            "first",
        ],
    );
    assert_eq!(fs::read(root.join("cancel-start.txt"))?, b"entered");
    let signal_script = format!(
        "printf '%s' '{password}'; printf signal-tail; printf entered > signal-start.txt; sleep 5"
    );
    let process = cli_command(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", &signal_script],
    )
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()?;
    let mut process = FixtureProcess(Some(process));
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut marker = first_peer
            .exec(ExecCommand::new(["cat", "/config/signal-start.txt"]))
            .await?;
        if marker.stdout_to_vec().await? == b"entered" {
            break;
        }
        assert!(
            Instant::now() < ready_deadline,
            "owned SSH process did not reach its fixture script"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = process
        .0
        .as_ref()
        .expect("owned fixture process")
        .id()
        .to_string();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid])
            .status()?
            .success()
    );
    let cancel_deadline = Instant::now() + Duration::from_secs(3);
    while process
        .0
        .as_mut()
        .expect("owned fixture process")
        .try_wait()?
        .is_none()
    {
        assert!(
            Instant::now() < cancel_deadline,
            "owned SSH process did not cancel"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let cancelled = process
        .0
        .take()
        .expect("owned fixture process")
        .wait_with_output()?;
    assert!(!cancelled.status.success());
    let text = String::from_utf8_lossy(&cancelled.stdout);
    assert!(text.contains("[REDACTED]") && text.contains("signal-tail"));
    assert!(!text.contains(&password));
    assert!(!String::from_utf8_lossy(&cancelled.stderr).contains(&password));
    for bad in [
        "../escape",
        "a;touch-injected",
        "-option",
        "/absolute",
        "a\nb",
    ] {
        let output = invoke(
            &root,
            &password,
            &["scp", "-i", "lab", "--", "payload.txt", bad, "first"],
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("SCP remote path must contain safe relative components")
        );
    }
    assert!(
        !invoke(
            &root,
            &password,
            &["scp", "-i", "lab", "../outside", "valid.txt", "first"]
        )
        .status
        .success()
    );
    assert!(
        !invoke(
            &root,
            &password,
            &[
                "scp",
                "-i",
                "lab",
                "--pull",
                "copied.txt",
                "out.txt",
                "@both"
            ]
        )
        .status
        .success()
    );
    policy(&root, inventory, &["first"], &[]);
    assert!(
        !invoke(
            &root,
            &password,
            &["ssh", "-i", "lab", "@both", "--", "touch denied.txt"]
        )
        .status
        .success()
    );
    succeeds(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", "test ! -e denied.txt"],
    );

    // A changed endpoint cannot ride an old alias grant. With a new snapshot
    // grant but the wrong pin, handshake verification must still fail.
    let retargeted = document
        .replace(&format!("port: {port1}"), &format!("port: {port2}"))
        .replace(&pin1, &pin2);
    fs::write(root.join("neoenv.yaml"), &retargeted)?;
    let retarget = invoke(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", "touch retargeted.txt"],
    );
    assert!(!retarget.status.success());
    assert!(String::from_utf8_lossy(&retarget.stderr).contains("ssh-endpoint:"));
    fs::write(root.join("neoenv.yaml"), &document)?;
    policy(&root, inventory, &["first", "second"], &[]);
    succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "second",
            "--",
            "test ! -e retargeted.txt",
        ],
    );
    let wrong = document.replace(&pin1, &pin2);
    fs::write(root.join("neoenv.yaml"), &wrong)?;
    assert!(
        !invoke(
            &root,
            &password,
            &["ssh", "-i", "lab", "first", "--", "true"]
        )
        .status
        .success()
    );
    let parsed = neoenv_config::parse_project(&root.join("neoenv.yaml"), &wrong)?;
    policy(&root, &parsed.inventories["lab"], &["first"], &[]);
    let output = invoke(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", "true"],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("host-key verification"));
    let identity_document = document.replace(
        &format!(
            "      first:\n        address: 127.0.0.1\n        host_key: {pin1}\n        password_env: FIXTURE_PASSWORD\n        password_auth: true\n        tags: [both]"
        ),
        &format!(
            "      first:\n        address: 127.0.0.1\n        host_key: {pin1}\n        identity_file: fixture-key\n        password_env: FIXTURE_KEY_PASSPHRASE\n        tags: [both]"
        ),
    )
    .replace(
        "tasks:",
        &format!(
            "vaults:\n  fixture:\n    driver: age\n    identity: {}\n    values:\n      key-passphrase: |\n{encrypted_passphrase_yaml}tasks:",
            age_identity.display()
        ),
    );
    assert_ne!(identity_document, document);
    fs::write(root.join("neoenv.yaml"), &identity_document)?;
    let identity_project =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &identity_document)?;
    policy(
        &root,
        &identity_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let mut identity_command = cli_command(&root, &password, &["run", "identity-task"]);
    identity_command.env_remove("FIXTURE_KEY_PASSPHRASE");
    let identity_output = identity_command.output()?;
    assert!(
        identity_output.status.success(),
        "encrypted identity task failed: {}",
        String::from_utf8_lossy(&identity_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&identity_output.stdout).contains("[REDACTED]")
            || String::from_utf8_lossy(&identity_output.stderr).contains("[REDACTED]")
    );
    assert!(!String::from_utf8_lossy(&identity_output.stdout).contains("fixture-passphrase"));
    assert!(!String::from_utf8_lossy(&identity_output.stderr).contains("fixture-passphrase"));
    let nested = root.join("nested");
    fs::create_dir(&nested)?;
    let mut relative_command = cli_command(&root, &password, &["run", "identity-task"]);
    relative_command
        .current_dir(&nested)
        .env_remove("FIXTURE_KEY_PASSPHRASE");
    let relative_output = relative_command.output()?;
    assert!(
        relative_output.status.success(),
        "relative identity must use project root from a nested cwd: {}",
        String::from_utf8_lossy(&relative_output.stderr)
    );
    let home_document =
        identity_document.replace("identity_file: fixture-key", "identity_file: ~/fixture-key");
    fs::write(root.join("neoenv.yaml"), &home_document)?;
    let home_project = neoenv_config::parse_project(&root.join("neoenv.yaml"), &home_document)?;
    policy(
        &root,
        &home_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let listing = cli_command(&root, &password, &["inventory", "--format", "json"]).output()?;
    assert!(listing.status.success());
    let listing: serde_json::Value = serde_json::from_slice(&listing.stdout)?;
    let listed_subject = listing[0]["hosts"][0]["endpoint_subject"]
        .as_str()
        .ok_or("fixture inventory endpoint subject missing")?;
    let expected_subject = neoenv_runtime::ssh::endpoint_subject_with_context(
        &home_project.inventories["lab"],
        "first",
        &std::collections::BTreeMap::from([("HOME".into(), root.display().to_string())]),
        &root,
    )?;
    assert_eq!(listed_subject, expected_subject);
    let mut home_command = cli_command(&root, &password, &["run", "identity-task"]);
    home_command
        .current_dir(&nested)
        .env_remove("FIXTURE_KEY_PASSPHRASE");
    let home_output = home_command.output()?;
    assert!(
        home_output.status.success(),
        "fixture HOME expansion failed: {}",
        String::from_utf8_lossy(&home_output.stderr)
    );
    let mut home_direct = cli_command(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", "printf direct-home"],
    );
    home_direct.current_dir(&nested);
    let home_direct_output = home_direct.output()?;
    assert!(
        home_direct_output.status.success(),
        "direct SSH fixture HOME expansion failed: {}",
        String::from_utf8_lossy(&home_direct_output.stderr)
    );
    let other_home = root.join("other-home");
    fs::create_dir(&other_home)?;
    let mut denied_home = cli_command(
        &root,
        &password,
        &["ssh", "-i", "lab", "first", "--", "printf must-not-run"],
    );
    denied_home.env("HOME", &other_home);
    let denied_home_output = denied_home.output()?;
    assert!(!denied_home_output.status.success());
    assert!(
        String::from_utf8_lossy(&denied_home_output.stderr)
            .contains("endpoint requires connect grant"),
        "changed HOME must require a new endpoint grant: {}",
        String::from_utf8_lossy(&denied_home_output.stderr)
    );
    let task_override_document = home_document.replace(
        "    env:\n      FIXTURE_KEY_PASSPHRASE:",
        &format!(
            "    env:\n      HOME: {}\n      FIXTURE_KEY_PASSPHRASE:",
            other_home.display()
        ),
    );
    assert_ne!(task_override_document, home_document);
    fs::write(root.join("neoenv.yaml"), &task_override_document)?;
    let task_override = cli_command(&root, &password, &["run", "identity-task"]).output()?;
    assert!(!task_override.status.success());
    assert!(
        String::from_utf8_lossy(&task_override.stderr).contains("endpoint requires connect grant"),
        "task-local HOME change must be reauthorized: {}",
        String::from_utf8_lossy(&task_override.stderr)
    );
    fs::write(root.join("neoenv.yaml"), &identity_document)?;
    policy(
        &root,
        &identity_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let wrong_recipient = AgeRecipient::from_public_key(&age_key.public_key)?;
    let wrong_ciphertext =
        AgeFile::encrypt_armored(b"wrong-fixture-passphrase", &[wrong_recipient])?;
    let mut wrong_ciphertext_yaml = String::new();
    for line in wrong_ciphertext.lines() {
        writeln!(wrong_ciphertext_yaml, "        {line}")?;
    }
    let wrong_passphrase_document =
        identity_document.replace(&encrypted_passphrase_yaml, &wrong_ciphertext_yaml);
    assert_ne!(wrong_passphrase_document, identity_document);
    fs::write(root.join("neoenv.yaml"), &wrong_passphrase_document)?;
    let wrong_passphrase_project =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &wrong_passphrase_document)?;
    policy(
        &root,
        &wrong_passphrase_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let mut wrong_passphrase_command = cli_command(&root, &password, &["run", "identity-task"]);
    wrong_passphrase_command
        .env_remove("FIXTURE_KEY_PASSPHRASE")
        .env("SSH_AUTH_SOCK", &agent_socket);
    let wrong_passphrase = wrong_passphrase_command.output()?;
    assert!(!wrong_passphrase.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_passphrase.stderr)
            .contains("SSH identity file is invalid or unavailable"),
        "bad key passphrase must not fall back to the fixture agent: {}",
        String::from_utf8_lossy(&wrong_passphrase.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&wrong_passphrase.stderr).contains("wrong-fixture-passphrase")
    );
    fs::write(root.join("neoenv.yaml"), &identity_document)?;
    policy(
        &root,
        &identity_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "first",
            "--",
            "printf key-command > key-command.txt",
        ],
    );
    let mut identity_result = first_peer
        .exec(ExecCommand::new(["cat", "/config/identity.txt"]))
        .await?;
    assert_eq!(
        identity_result.stdout_to_vec().await?,
        b"identity",
        "encrypted fixture identity must authenticate"
    );
    let missing_identity_document =
        identity_document.replace("identity_file: fixture-key", "identity_file: missing-key");
    fs::write(root.join("neoenv.yaml"), &missing_identity_document)?;
    let missing_identity_project =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &missing_identity_document)?;
    policy(
        &root,
        &missing_identity_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let missing_identity =
        invoke_with_agent(&root, &password, &agent_socket, &["run", "identity-task"]);
    assert!(!missing_identity.status.success());
    assert!(
        String::from_utf8_lossy(&missing_identity.stderr)
            .contains("SSH identity file is invalid or unavailable"),
        "an explicit identity failure must not fall back to the fixture agent: {}",
        String::from_utf8_lossy(&missing_identity.stderr)
    );
    let unencrypted_document = identity_document.replace(
        "identity_file: fixture-key\n        password_env: FIXTURE_KEY_PASSPHRASE",
        "identity_file: fixture-agent-key",
    );
    fs::write(root.join("neoenv.yaml"), &unencrypted_document)?;
    let unencrypted_project =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &unencrypted_document)?;
    policy(
        &root,
        &unencrypted_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    succeeds(&root, &password, &["run", "identity-task"]);
    succeeds(
        &root,
        &password,
        &[
            "ssh",
            "-i",
            "lab",
            "first",
            "--",
            "printf unencrypted-command > unencrypted-command.txt",
        ],
    );
    fs::write(root.join("neoenv.yaml"), &identity_document)?;
    let encrypted_project =
        neoenv_config::parse_project(&root.join("neoenv.yaml"), &identity_document)?;
    policy(
        &root,
        &encrypted_project.inventories["lab"],
        &["first"],
        &["identity-task"],
    );
    let agent_document = document.replacen(
        "        password_env: FIXTURE_PASSWORD\n        password_auth: true\n        tags: [both]",
        "        password_env: FIXTURE_PASSWORD\n        tags: [both]",
        1,
    );
    fs::write(root.join("neoenv.yaml"), &agent_document)?;
    let agent_project = neoenv_config::parse_project(&root.join("neoenv.yaml"), &agent_document)?;
    policy(
        &root,
        &agent_project.inventories["lab"],
        &["first"],
        &["agent-task"],
    );
    let agent_output = invoke_with_agent(&root, &password, &agent_socket, &["run", "agent-task"]);
    assert!(
        agent_output.status.success(),
        "fixture agent task failed: {}",
        String::from_utf8_lossy(&agent_output.stderr)
    );
    let agent_command = invoke_with_agent(
        &root,
        &password,
        &agent_socket,
        &[
            "ssh",
            "-i",
            "lab",
            "first",
            "--",
            "printf agent-command > agent-command.txt",
        ],
    );
    assert!(
        agent_command.status.success(),
        "fixture agent command failed: {}",
        String::from_utf8_lossy(&agent_command.stderr)
    );
    let mut agent_result = first_peer
        .exec(ExecCommand::new(["cat", "/config/agent.txt"]))
        .await?;
    assert_eq!(agent_result.stdout_to_vec().await?, b"agent");
    let absent_agent_output = invoke_with_agent(
        &root,
        &password,
        &root.join("missing-agent.sock"),
        &["run", "agent-task"],
    );
    assert!(!absent_agent_output.status.success());
    assert!(
        String::from_utf8_lossy(&absent_agent_output.stderr).contains("SSH agent is unavailable"),
        "agent failure must not downgrade to password login"
    );
    first_peer.rm().await?;
    second_peer.rm().await?;
    // Handles remove exactly these containers on drop, including error/panic paths.
    Ok(())
}
