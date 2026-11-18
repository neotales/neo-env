//! Offline CLI regression tests for legacy and manager-selected npm locks.

use std::{collections::BTreeMap, fs, io::Write, process::Command};

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use neoenv_core::{
    SourceSpan,
    tools::{
        ArtifactVerification, LockedTool, ManagerLock, ManagerPackage, Platform,
        ProviderAuthPolicy, ScriptPolicy, TOOL_LOCK_SCHEMA_VERSION, ToolLockfile, ToolProvenance,
    },
};
use sha2::{Digest, Sha256, Sha512};
use tempfile::TempDir;

fn archive() -> Vec<u8> {
    archive_with_metadata(br#"{"name":"fixture","version":"1.0.0","bin":{"demo":"bin.js"}}"#)
}

fn archive_with_metadata(package_json: &[u8]) -> Vec<u8> {
    archive_with_extra(package_json, None)
}

fn archive_with_extra(package_json: &[u8], extra: Option<(&str, &[u8])>) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let mut entries = vec![
        ("package/package.json", package_json),
        ("package/bin.js", &b"#!/bin/sh\nexit 0\n"[..]),
    ];
    if let Some(extra) = extra {
        entries.push(extra);
    }
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }
    let mut encoder = tar.into_inner().unwrap();
    encoder.flush().unwrap();
    encoder.finish().unwrap()
}

fn fixture(managed: bool) -> (TempDir, String) {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools: []\n",
    )
    .unwrap();
    let bytes = archive();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&bytes)));
    let tool = LockedTool {
        id: "fixture".into(),
        resolved_version: "1.0.0".into(),
        url: "https://example.test/fixture.tgz".into(),
        platform: Platform::host(),
        sha256: digest.clone(),
        provenance: ToolProvenance {
            provider: "npm".into(),
            immutable_id: "fixture".into(),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some("https://example.test/".into()),
            registry_revision: None,
            manifest_sha256: None,
            package: Some("fixture".into()),
            registry_integrity: Some(integrity.clone()),
            declaration_sha256: None,
            authentication: ProviderAuthPolicy::Prohibited,
        },
        verification: ArtifactVerification {
            sha256: digest.clone(),
            signature: None,
        },
        binaries: vec!["demo".into()],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
        resolver: "npm".into(),
        cargo_toolchain: None,
    };
    let manager_lock = managed.then(|| ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.2.3".into(),
        manager_sha256: "a".repeat(64),
        runtime_version: "1.2.3".into(),
        runtime_archive: None,
        manifest_sha256: "b".repeat(64),
        lockfile_sha256: "c".repeat(64),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![ManagerPackage {
            id: "fixture@1.0.0".into(),
            name: "fixture".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            tarball_url: "https://example.test/fixture.tgz".into(),
            integrity,
            sha256: digest.clone(),
        }],
    });
    let lock = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![tool],
        pins: BTreeMap::new(),
        manager_lock,
        cargo_build: None,
    };
    lock.validate().unwrap();
    let lock_path = neoenv_installer::tools::lockfile_path(root.path());
    fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    fs::write(lock_path, toml::to_string_pretty(&lock).unwrap()).unwrap();
    let artifacts = root.path().join(".neoenv/artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    fs::write(artifacts.join(&digest), bytes).unwrap();
    (root, digest)
}

mod support;

/// Approves the fixture's current bytes before a run.
///
/// Execution requires an approved record for the exact bytes the run will read,
/// and several cases rewrite `neoenv.yaml` between runs. Approving immediately
/// before each run keeps the record current without changing what the case
/// asserts.
fn approve(root: &std::path::Path) {
    support::approve_tree(&root.join("config"), root);
}

fn install(root: &TempDir) -> std::process::Output {
    approve(root.path());
    Command::new(env!("CARGO_BIN_EXE_nenv"))
        .current_dir(root.path())
        .env_clear()
        .env("HOME", root.path())
        .env("NEOENV_CONFIG_HOME", root.path().join("config"))
        .env("NEOENV_DATA_HOME", root.path().join("data"))
        .args(["tool", "install", "--locked", "neoenv.yaml"])
        .output()
        .unwrap()
}

#[test]
fn legacy_npm_cli_installs_cached_tarball_offline() {
    let (root, digest) = fixture(false);
    let output = install(&root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(
            root.path()
                .join(".neoenv/tools")
                .join(digest)
                .join("bin/demo")
        )
        .unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
}

#[test]
fn declared_manager_cannot_install_a_legacy_lock_by_direct_extraction() {
    let (root, _) = fixture(false);
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm: { endpoint: https://example.test, package: fixture, manager: { name: bun, version: '1.4.4' } }\n",
    )
    .unwrap();
    let output = install(&root);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no matching manager lock"));
    assert!(!root.path().join(".neoenv/tools").exists());
}

#[cfg(unix)]
#[test]
fn declared_manager_blocks_legacy_and_matching_global_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let (root, digest) = fixture(false);
    assert!(install(&root).status.success());
    let run = |args: &[&str]| {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", std::env::temp_dir())
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["tool", "which", "demo"]).status.success());
    assert!(run(&["tool", "use", "demo"]).status.success());
    let global_config = root.path().join("config/neoenv");
    fs::create_dir_all(&global_config).unwrap();
    fs::write(
        global_config.join("neoenv.toml"),
        "[global.tools]\ndemo = '1.0.0'\nother = '1.0.0'\n",
    )
    .unwrap();
    for name in ["demo", "other"] {
        let path = root
            .path()
            .join("data/neoenv/tools")
            .join(name)
            .join("1.0.0");
        fs::create_dir_all(&path).unwrap();
        let binary = path.join(name);
        fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(binary, fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(run(&["tool", "which", "demo", "--user"]).status.success());
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm: { endpoint: https://example.test, package: fixture, manager: { name: bun, version: '1.4.4' } }\n",
    )
    .unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    assert!(!run(&["tool", "use", "demo"]).status.success());
    assert!(run(&["tool", "which", "other"]).status.success());
    assert!(run(&["tool", "use", "other"]).status.success());
    fs::remove_dir_all(root.path().join(".neoenv/tools").join(digest)).unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    assert!(!run(&["tool", "use", "demo"]).status.success());
    assert!(run(&["tool", "which", "demo", "--user"]).status.success());
}

#[cfg(unix)]
#[test]
fn exec_never_uses_legacy_or_path_for_an_unresolved_managed_package() {
    use std::os::unix::fs::PermissionsExt;
    let (root, _) = fixture(false);
    assert!(install(&root).status.success());
    let path_bin = root.path().join("malicious-path");
    fs::create_dir(&path_bin).unwrap();
    let marker = root.path().join("path-executed");
    let marker_text = marker.to_str().unwrap();
    assert!(
        marker_text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })
    );
    let binary = path_bin.join("demo");
    fs::write(
        &binary,
        format!("#!/bin/sh\nprintf yes > '{marker_text}'\n"),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let run = || {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", &path_bin)
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(["exec", "--", "demo"])
            .output()
            .unwrap()
    };
    assert!(
        run().status.success(),
        "legacy locked executable should work"
    );
    assert!(
        !marker.exists(),
        "legacy project executable should beat PATH"
    );
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm: { endpoint: https://example.test, package: fixture, manager: { name: bun, version: '1.4.4' } }\n",
    )
    .unwrap();
    assert!(!run().status.success());
    assert!(!marker.exists());
    let lock = root.path().join("neoenv.lock");
    fs::remove_file(&lock).unwrap();
    assert!(!run().status.success(), "missing lock must not fall back");
    assert!(!marker.exists());
    fs::create_dir(&lock).unwrap();
    assert!(
        !run().status.success(),
        "unreadable lock must not fall back"
    );
    assert!(!marker.exists());
    fs::remove_dir(&lock).unwrap();
    fs::write(&lock, "invalid [toml").unwrap();
    assert!(!run().status.success(), "corrupt lock must not fall back");
    assert!(!marker.exists());
    fs::remove_file(&lock).unwrap();
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm: { endpoint: https://example.test, package: fixture }\n",
    )
    .unwrap();
    assert!(
        run().status.success(),
        "unrelated PATH execution remains available"
    );
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    fs::write(&lock, "invalid [toml").unwrap();
    assert!(
        run().status.success(),
        "legacy npm project must retain PATH fallback for a corrupt lock"
    );
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();
    assert!(
        run().status.success(),
        "legacy npm project must retain PATH fallback for an unreadable lock"
    );
    assert!(marker.exists());
}

#[cfg(unix)]
#[test]
fn changed_registry_and_overlapping_alias_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let (root, _) = fixture(false);
    let lock_path = root.path().join("neoenv.lock");
    let mut lock = neoenv_installer::tools::read_lockfile(&lock_path).unwrap();
    let mut other = lock.tools[0].clone();
    other.id = "other".into();
    other.sha256 = "b".repeat(64);
    other.verification.sha256 = other.sha256.clone();
    other.provenance.package = Some("other".into());
    other.binaries = vec!["shared".into()];
    lock.tools.push(other.clone());
    lock.validate().unwrap();
    fs::write(&lock_path, toml::to_string_pretty(&lock).unwrap()).unwrap();
    let bin_dir = root
        .path()
        .join(".neoenv/tools")
        .join(&other.sha256)
        .join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("shared"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(bin_dir.join("shared"), fs::Permissions::from_mode(0o755)).unwrap();
    let global_config = root.path().join("config/neoenv");
    fs::create_dir_all(&global_config).unwrap();
    fs::write(
        global_config.join("neoenv.toml"),
        "[global.tools]\nshared = '1.0.0'\n",
    )
    .unwrap();
    let global = root.path().join("data/neoenv/tools/shared/1.0.0");
    fs::create_dir_all(&global).unwrap();
    fs::write(global.join("shared"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(global.join("shared"), fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", &global)
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["tool", "which", "shared"]).status.success());
    assert!(run(&["tool", "which", "shared", "--user"]).status.success());
    fs::write(
        root.path().join("neoenv.yaml"),
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm: { endpoint: https://changed.example.test, package: fixture, manager: { name: bun, version: '1.4.4' } }\n",
    ).unwrap();
    for args in [
        &["tool", "which", "shared"][..],
        &["tool", "use", "shared"][..],
        &["exec", "--", "shared"][..],
    ] {
        assert!(
            !run(args).status.success(),
            "ambiguous alias must fail: {args:?}"
        );
    }
}

#[test]
fn manager_selected_npm_cli_refuses_before_installation() {
    let (root, digest) = fixture(true);
    let output = install(&root);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one declared npm tool"));
    assert!(!root.path().join(".neoenv/tools").exists());
    assert!(root.path().join(".neoenv/artifacts").join(digest).is_file());
}

fn managed_runtime_fixture(
    root: &TempDir,
    binary: &std::path::Path,
    version: &str,
) -> (std::path::PathBuf, neoenv_installer::tools::BunRuntimeAsset) {
    let runtime_root = root.path().join("data/neoenv/tools/bun").join(version);
    let binary_dir = neoenv_installer::tools::bun_binary_directory(&runtime_root);
    fs::create_dir_all(&binary_dir).unwrap();
    let binary_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let managed_binary = binary_dir.join(binary_name);
    fs::copy(binary, &managed_binary).unwrap();
    let archive_path = runtime_root.join(neoenv_installer::tools::BUN_RUNTIME_ARCHIVE);
    let mut writer = zip::ZipWriter::new(fs::File::create(&archive_path).unwrap());
    let relative = managed_binary
        .strip_prefix(&runtime_root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    writer
        .start_file(relative, zip::write::SimpleFileOptions::default())
        .unwrap();
    std::io::copy(&mut fs::File::open(binary).unwrap(), &mut writer).unwrap();
    writer.finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&archive_path).unwrap()));
    fs::write(
        runtime_root.join(neoenv_core::names::BUN_RUNTIME_RECEIPT),
        &digest,
    )
    .unwrap();
    let asset = neoenv_installer::tools::BunRuntimeAsset {
        version: version.into(),
        url: "https://example.test/bun.zip".into(),
        sha256: digest,
    };
    fs::write(
        runtime_root.join(neoenv_installer::tools::BUN_RUNTIME_PROVENANCE),
        serde_json::to_vec(&asset).unwrap(),
    )
    .unwrap();
    (runtime_root, asset)
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum NpmFixture {
    Valid,
    Dependencies,
    Duplicate,
    Outside,
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
fn assert_fresh_bun_cli(
    binary: &std::path::Path,
    version: &str,
    fixture: NpmFixture,
    marker: Option<&std::path::Path>,
) {
    use std::{
        io::Read,
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    let root = TempDir::new().unwrap();
    let (_, asset) = managed_runtime_fixture(&root, binary, version);
    let metadata = &br#"{"name":"fixture","version":"1.0.0","bin":{"demo":"bin.js"}}"#[..];
    let (tarball, expected_error) = match fixture {
        NpmFixture::Valid => (archive(), None),
        NpmFixture::Dependencies => (
            archive_with_metadata(br#"{"name":"fixture","version":"1.0.0","bin":{"demo":"bin.js"},"dependencies":{"other":"1.0.0"}}"#),
            Some("dependency graph"),
        ),
        NpmFixture::Duplicate => (
            archive_with_extra(metadata, Some(("package/package.json", metadata))),
            Some("duplicate paths"),
        ),
        NpmFixture::Outside => (
            archive_with_extra(metadata, Some(("outside.js", b"unexpected"))),
            Some("outside package/"),
        ),
    };
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball)));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicUsize::new(0));
    let server = {
        let stop = Arc::clone(&stop);
        let count = Arc::clone(&count);
        let tarball = tarball.clone();
        let integrity = integrity.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut input = [0_u8; 4096];
                let len = stream.read(&mut input).unwrap();
                let request = String::from_utf8_lossy(&input[..len]);
                assert!(!request.to_ascii_lowercase().contains("authorization:"));
                let body = if request.starts_with("GET /fixture HTTP/1.1") {
                    format!(r#"{{"versions":{{"1.0.0":{{"name":"fixture","version":"1.0.0","bin":{{"demo":"bin.js"}},"dist":{{"tarball":"http://{address}/fixture.tgz","integrity":"{integrity}"}}}}}}}}"#).into_bytes()
                } else {
                    assert!(
                        request.starts_with("GET /fixture.tgz HTTP/1.1"),
                        "{request}"
                    );
                    tarball.clone()
                };
                count.fetch_add(1, Ordering::SeqCst);
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        })
    };
    fs::write(root.path().join("neoenv.yaml"), format!(
        "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm:\n      endpoint: http://{address}\n      package: fixture\n      manager: {{ name: bun, version: '{version}', archive_sha256: '{}' }}\n",
        asset.sha256
    )).unwrap();
    let run = |args: &[&str]| {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", std::env::temp_dir())
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(args)
            .output()
            .unwrap()
    };
    let locked = run(&["tool", "lock", "neoenv.yaml"]);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    if let Some(expected_error) = expected_error {
        assert!(!locked.status.success());
        assert!(
            String::from_utf8_lossy(&locked.stderr).contains(expected_error),
            "{}",
            String::from_utf8_lossy(&locked.stderr)
        );
        assert!(!root.path().join("neoenv.lock").exists());
        assert_eq!(
            fs::read_dir(root.path().join(".neoenv")).unwrap().count(),
            0
        );
        if let Some(marker) = marker {
            assert!(!marker.exists(), "unsafe fresh archive executed Bun");
        }
        // The same malformed bytes behind a previous legacy lock must also
        // leave that lock untouched and must not invoke Bun.
        let digest = format!("{:x}", Sha256::digest(&tarball));
        let previous = ToolLockfile {
            schema_version: TOOL_LOCK_SCHEMA_VERSION,
            tools: vec![LockedTool {
                id: "fixture".into(),
                resolved_version: "1.0.0".into(),
                url: format!("http://{address}/fixture.tgz"),
                platform: Platform::host(),
                sha256: digest.clone(),
                provenance: ToolProvenance {
                    provider: "npm".into(),
                    immutable_id: "fixture".into(),
                    repository: None,
                    release_id: None,
                    asset_id: None,
                    registry_endpoint: Some(format!("http://{address}/")),
                    registry_revision: None,
                    manifest_sha256: None,
                    package: Some("fixture".into()),
                    registry_integrity: Some(integrity.clone()),
                    declaration_sha256: None,
                    authentication: ProviderAuthPolicy::Prohibited,
                },
                verification: ArtifactVerification {
                    sha256: digest.clone(),
                    signature: None,
                },
                binaries: vec!["demo".into()],
                declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
                resolver: "npm".into(),
                cargo_toolchain: None,
            }],
            pins: BTreeMap::new(),
            manager_lock: None,
            cargo_build: None,
        };
        previous.validate().unwrap();
        let old_bytes = toml::to_string_pretty(&previous).unwrap();
        fs::write(root.path().join("neoenv.lock"), &old_bytes).unwrap();
        let artifacts = root.path().join(".neoenv/artifacts");
        fs::create_dir(&artifacts).unwrap();
        fs::write(artifacts.join(digest), &tarball).unwrap();
        let error = run(&["tool", "lock", "neoenv.yaml"]);
        assert!(!error.status.success());
        assert!(String::from_utf8_lossy(&error.stderr).contains(expected_error));
        assert_eq!(
            fs::read_to_string(root.path().join("neoenv.lock")).unwrap(),
            old_bytes
        );
        assert!(!root.path().join(".neoenv/bun-manager-inputs").exists());
        if let Some(marker) = marker {
            assert!(!marker.exists(), "unsafe existing archive executed Bun");
        }
        return;
    }
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    assert_eq!(count.load(Ordering::SeqCst), 3);
    let lock_path = root.path().join("neoenv.lock");
    let original_lock = fs::read(&lock_path).unwrap();
    let relocked = run(&["tool", "lock", "neoenv.yaml"]);
    assert!(
        relocked.status.success(),
        "{}",
        String::from_utf8_lossy(&relocked.stderr)
    );
    assert_eq!(fs::read(&lock_path).unwrap(), original_lock);
    let graph = neoenv_installer::tools::read_lockfile(&lock_path)
        .unwrap()
        .manager_lock
        .unwrap();
    let destination = root
        .path()
        .join(".neoenv/tools")
        .join(&graph.packages[0].sha256);
    let cache =
        neoenv_installer::tools::recover_bun_inputs(&root.path().join(".neoenv"), &graph).unwrap();
    let saved = fs::read(&cache.tarball).unwrap();
    fs::remove_file(&cache.tarball).unwrap();
    fs::write(&cache.tarball, b"tampered").unwrap();
    assert!(
        !run(&["tool", "install", "--locked", "neoenv.yaml"])
            .status
            .success()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read(&lock_path).unwrap(), original_lock);
    fs::remove_file(&cache.tarball).unwrap();
    fs::write(&cache.tarball, saved).unwrap();
    let archive_backup = cache.archive.with_extension("backup");
    fs::rename(&cache.archive, &archive_backup).unwrap();
    assert!(
        !run(&["tool", "install", "--locked", "neoenv.yaml"])
            .status
            .success()
    );
    assert!(!destination.exists());
    fs::rename(&archive_backup, &cache.archive).unwrap();
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("keep"), b"foreign").unwrap();
    assert!(
        !run(&["tool", "install", "--locked", "neoenv.yaml"])
            .status
            .success()
    );
    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"foreign");
    fs::remove_dir_all(&destination).unwrap();
    let installed = run(&["tool", "install", "--locked", "neoenv.yaml"]);
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    for args in [
        &["tool", "which", "demo"][..],
        &["tool", "use", "demo"][..],
        &["exec", "--", "demo"][..],
    ] {
        let output = run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "offline replay made registry requests"
    );
}

#[cfg(unix)]
#[test]
fn fresh_bun_cli_locks_and_installs_from_local_registry() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let binary = temp.path().join("fake-bun");
    fs::write(
        &binary,
        b"#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.4.4; exit 0; fi\n[ \"$1\" = install ] && [ \"$2\" = --offline ] && [ \"$3\" = --ignore-scripts ] && [ \"$4\" = --frozen-lockfile ] || exit 1\n/bin/mkdir -p node_modules/fixture || exit 2\nprintf '%s' '{\"name\":\"fixture\",\"version\":\"1.0.0\",\"bin\":{\"demo\":\"bin.js\"}}' > node_modules/fixture/package.json\nprintf '#!/bin/sh\\nexit 0\\n' > node_modules/fixture/bin.js\n",
    ).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    assert_fresh_bun_cli(&binary, "1.4.4", NpmFixture::Valid, None);
    assert_fresh_bun_cli(&binary, "1.4.4", NpmFixture::Dependencies, None);
}

#[cfg(unix)]
#[test]
fn fresh_bun_lock_rejects_duplicate_and_outside_paths_before_execution() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("bun-executed");
    let marker_text = marker.to_str().unwrap();
    assert!(
        marker_text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })
    );
    let binary = temp.path().join("fake-bun");
    fs::write(
        &binary,
        format!("#!/bin/sh\nprintf yes > '{marker_text}'\necho 1.4.4\n"),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    assert_fresh_bun_cli(&binary, "1.4.4", NpmFixture::Duplicate, Some(&marker));
    assert_fresh_bun_cli(&binary, "1.4.4", NpmFixture::Outside, Some(&marker));
}

#[cfg(unix)]
#[test]
#[ignore = "opt-in local real-Bun fixture; set NEOENV_TEST_REAL_BUN"]
fn fresh_bun_cli_real_binary_local_registry() {
    let binary = std::env::var_os("NEOENV_TEST_REAL_BUN").expect("set NEOENV_TEST_REAL_BUN");
    let binary = std::path::Path::new(&binary);
    let temp = TempDir::new().unwrap();
    let output = Command::new(binary)
        .arg("--version")
        .env_clear()
        .env("HOME", temp.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let version = String::from_utf8(output.stdout).unwrap();
    assert_fresh_bun_cli(binary, version.trim(), NpmFixture::Valid, None);
}

#[allow(clippy::too_many_lines)]
fn assert_bun_cli_relock(
    binary: &std::path::Path,
    version: &str,
    marker: Option<&std::path::Path>,
) {
    let (root, _) = fixture(false);
    let (runtime_root, asset) = managed_runtime_fixture(&root, binary, version);
    fs::write(
        root.path().join("neoenv.yaml"),
        format!(
            "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm:\n      endpoint: https://example.test\n      package: fixture\n      manager: {{ name: bun, version: '{version}' }}\n"
        ),
    ).unwrap();
    let run_lock = || {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(["tool", "lock", "neoenv.yaml"])
            .output()
            .unwrap()
    };
    let receipt = runtime_root.join(neoenv_core::names::BUN_RUNTIME_RECEIPT);
    let original_lock = fs::read(root.path().join("neoenv.lock")).unwrap();
    let unanchored = run_lock();
    assert!(!unanchored.status.success());
    assert!(String::from_utf8_lossy(&unanchored.stderr).contains("not a trust anchor"));
    assert_eq!(
        fs::read(root.path().join("neoenv.lock")).unwrap(),
        original_lock
    );
    if let Some(marker) = marker {
        assert!(
            !marker.exists(),
            "untrusted locally consistent runtime was executed"
        );
    }

    // This fixture represents a pre-authenticated manager lock. The runtime
    // archive itself is locally assembled and is not an official release.
    let mut existing =
        neoenv_installer::tools::read_lockfile(&root.path().join("neoenv.lock")).unwrap();
    let tool = &existing.tools[0];
    let integrity = tool.provenance.registry_integrity.clone().unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": "neoenv-locked-package-stage",
        "private": true,
        "dependencies": { "fixture": "file:./locked-package.tgz" }
    }))
    .unwrap();
    let bun_lock = serde_json::to_vec(&serde_json::json!({
        "lockfileVersion": 2,
        "configVersion": 1,
        "workspaces": { "": {
            "name": "neoenv-locked-package-stage",
            "dependencies": { "fixture": "file:./locked-package.tgz" }
        }},
        "packages": { "fixture": [
            "fixture@./locked-package.tgz", { "bin": { "demo": "bin.js" } }, integrity
        ]}
    }))
    .unwrap();
    existing.manager_lock = Some(ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: version.into(),
        manager_sha256: format!("{:x}", Sha256::digest(fs::read(binary).unwrap())),
        runtime_version: version.into(),
        runtime_archive: Some(neoenv_core::tools::ManagerRuntimeArchive {
            url: asset.url.clone(),
            sha256: asset.sha256.clone(),
        }),
        manifest_sha256: format!("{:x}", Sha256::digest(manifest)),
        lockfile_sha256: format!("{:x}", Sha256::digest(bun_lock)),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![ManagerPackage {
            id: "fixture@1.0.0".into(),
            name: "fixture".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            tarball_url: tool.url.clone(),
            integrity: tool.provenance.registry_integrity.clone().unwrap(),
            sha256: tool.sha256.clone(),
        }],
    });
    let lock_path = root.path().join("neoenv.lock");
    let correct = toml::to_string_pretty(&existing).unwrap();
    existing.manager_lock.as_mut().unwrap().manager_sha256 = "f".repeat(64);
    let mismatched = toml::to_string_pretty(&existing).unwrap();
    fs::write(&lock_path, &mismatched).unwrap();
    assert!(!run_lock().status.success());
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), mismatched);
    if let Some(marker) = marker {
        assert!(
            !marker.exists(),
            "manager hash mismatch executed the runtime"
        );
    }
    fs::write(&lock_path, &correct).unwrap();
    let mut different_asset = asset.clone();
    different_asset.url = "https://example.test/other.zip".into();
    let provenance = runtime_root.join(neoenv_installer::tools::BUN_RUNTIME_PROVENANCE);
    fs::write(&provenance, serde_json::to_vec(&different_asset).unwrap()).unwrap();
    assert!(!run_lock().status.success());
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), correct);
    if let Some(marker) = marker {
        assert!(!marker.exists(), "archive mismatch executed the runtime");
    }
    fs::write(&provenance, serde_json::to_vec(&asset).unwrap()).unwrap();
    fs::write(&receipt, "invalid").unwrap();
    assert!(!run_lock().status.success());
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), correct);
    fs::write(&receipt, &asset.sha256).unwrap();
    // Bootstrap the first manager graph from a user-pinned archive digest,
    // not from the self-reported runtime receipt.
    fs::write(&lock_path, &original_lock).unwrap();
    let config_with_pin = |digest: &str| {
        format!(
            "format_version: 1\ntools:\n  - id: fixture\n    version: '1.0.0'\n    provider: npm\n    npm:\n      endpoint: https://example.test\n      package: fixture\n      manager: {{ name: bun, version: '{version}', archive_sha256: '{digest}' }}\n"
        )
    };
    fs::write(
        root.path().join("neoenv.yaml"),
        config_with_pin(&"f".repeat(64)),
    )
    .unwrap();
    assert!(!run_lock().status.success());
    assert_eq!(fs::read(&lock_path).unwrap(), original_lock);
    if let Some(marker) = marker {
        assert!(!marker.exists(), "wrong user pin executed the runtime");
    }
    fs::write(
        root.path().join("neoenv.yaml"),
        config_with_pin(&asset.sha256),
    )
    .unwrap();
    let output = run_lock();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lock = neoenv_installer::tools::read_lockfile(&root.path().join("neoenv.lock")).unwrap();
    let graph = lock.manager_lock.unwrap();
    assert_eq!(graph.manager_version, version);
    assert_eq!(graph.packages[0].name, "fixture");
    assert!(
        neoenv_installer::tools::recover_bun_inputs(&root.path().join(".neoenv"), &graph).is_ok()
    );
    if let Some(marker) = marker {
        assert!(marker.exists(), "correct anchored runtime was not executed");
    }
    let latest = config_with_pin(&asset.sha256).replace("version: '1.0.0'", "version: 'latest'");
    fs::write(root.path().join("neoenv.yaml"), latest).unwrap();
    let relocked_latest = run_lock();
    assert!(
        relocked_latest.status.success(),
        "{}",
        String::from_utf8_lossy(&relocked_latest.stderr)
    );
    let run = |args: &[&str]| {
        approve(root.path());
        Command::new(env!("CARGO_BIN_EXE_nenv"))
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("NEOENV_CONFIG_HOME", root.path().join("config"))
            .env("NEOENV_DATA_HOME", root.path().join("data"))
            .args(args)
            .output()
            .unwrap()
    };
    let cached =
        neoenv_installer::tools::recover_bun_inputs(&root.path().join(".neoenv"), &graph).unwrap();
    let backup = cached.archive.with_extension("backup");
    fs::rename(&cached.archive, &backup).unwrap();
    assert!(
        !run(&["tool", "install", "--locked", "neoenv.yaml"])
            .status
            .success()
    );
    fs::rename(&backup, &cached.archive).unwrap();
    let destination = root
        .path()
        .join(".neoenv/tools")
        .join(&graph.packages[0].sha256);
    fs::create_dir_all(destination.join("bin")).unwrap();
    fs::write(destination.join("bin/demo"), b"legacy executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            destination.join("bin/demo"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    fs::write(destination.join("keep"), b"foreign").unwrap();
    assert!(
        !run(&["tool", "which", "demo"]).status.success(),
        "legacy direct extraction must not satisfy a manager lock"
    );
    assert!(
        !run(&["tool", "install", "--locked", "neoenv.yaml"])
            .status
            .success()
    );
    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"foreign");
    fs::remove_dir_all(&destination).unwrap();
    let installed = run(&["tool", "install", "--locked", "neoenv.yaml"]);
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let which = run(&["tool", "which", "demo"]);
    assert!(
        which.status.success(),
        "{}",
        String::from_utf8_lossy(&which.stderr)
    );
    let used = run(&["tool", "use", "demo"]);
    assert!(
        used.status.success(),
        "{}",
        String::from_utf8_lossy(&used.stderr)
    );
    let executed = run(&["exec", "--", "demo"]);
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    let current_config = fs::read_to_string(root.path().join("neoenv.yaml")).unwrap();
    let changed_manager = current_config.replace(
        &format!("version: '{version}', archive_sha256"),
        "version: '9.9.9', archive_sha256",
    );
    assert_ne!(changed_manager, current_config);
    fs::write(root.path().join("neoenv.yaml"), &changed_manager).unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    assert!(!run(&["tool", "use", "demo"]).status.success());
    assert!(!run(&["exec", "--", "demo"]).status.success());
    let changed_pin = current_config.replace(&asset.sha256, &"f".repeat(64));
    assert_ne!(changed_pin, current_config);
    fs::write(root.path().join("neoenv.yaml"), &changed_pin).unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    assert!(!run(&["tool", "use", "demo"]).status.success());
    fs::write(root.path().join("neoenv.yaml"), &current_config).unwrap();
    let ordinary_receipt = destination.join(".neoenv-artifact-sha256");
    let receipt_bytes = fs::read(&ordinary_receipt).unwrap();
    fs::remove_file(&ordinary_receipt).unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    assert!(!run(&["tool", "use", "demo"]).status.success());
    fs::write(&ordinary_receipt, "mismatched").unwrap();
    assert!(!run(&["tool", "which", "demo"]).status.success());
    fs::write(&ordinary_receipt, &receipt_bytes).unwrap();
    assert!(run(&["tool", "which", "demo"]).status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let bin = destination.join("bin");
        let moved_bin = destination.join("bin-real");
        fs::rename(&bin, &moved_bin).unwrap();
        symlink(&moved_bin, &bin).unwrap();
        assert!(!run(&["tool", "which", "demo"]).status.success());
        assert!(!run(&["tool", "use", "demo"]).status.success());
        fs::remove_file(&bin).unwrap();
        fs::rename(&moved_bin, &bin).unwrap();

        let moved_destination = destination.with_extension("real");
        fs::rename(&destination, &moved_destination).unwrap();
        symlink(&moved_destination, &destination).unwrap();
        assert!(!run(&["tool", "which", "demo"]).status.success());
        fs::remove_file(&destination).unwrap();
        fs::rename(&moved_destination, &destination).unwrap();

        let tools = root.path().join(".neoenv/tools");
        let moved_tools = root.path().join(".neoenv/tools-real");
        fs::rename(&tools, &moved_tools).unwrap();
        symlink(&moved_tools, &tools).unwrap();
        assert!(!run(&["tool", "which", "demo"]).status.success());
        fs::remove_file(&tools).unwrap();
        fs::rename(&moved_tools, &tools).unwrap();

        let storage = root.path().join(".neoenv");
        let moved_storage = root.path().join(".neoenv-real");
        fs::rename(&storage, &moved_storage).unwrap();
        symlink(&moved_storage, &storage).unwrap();
        assert!(!run(&["tool", "which", "demo"]).status.success());
        fs::remove_file(&storage).unwrap();
        fs::rename(&moved_storage, &storage).unwrap();
        assert!(run(&["tool", "which", "demo"]).status.success());
    }
}

#[cfg(unix)]
#[test]
fn bun_cli_refuses_unanchored_and_mismatched_managed_runtime() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("marker");
    let marker_text = marker.to_str().unwrap();
    assert!(
        marker_text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    );
    let binary = temp.path().join("fake-bun");
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf yes > '{marker_text}'; echo 1.4.4; exit 0; fi\n[ \"$1\" = install ] && [ \"$2\" = --offline ] && [ \"$3\" = --ignore-scripts ] && [ \"$4\" = --frozen-lockfile ] || exit 1\n/bin/mkdir -p node_modules/fixture || exit 2\nprintf '%s' '{{\"name\":\"fixture\",\"version\":\"1.0.0\",\"bin\":{{\"demo\":\"bin.js\"}}}}' > node_modules/fixture/package.json\nprintf '#!/bin/sh\\nexit 0\\n' > node_modules/fixture/bin.js\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    assert_bun_cli_relock(&binary, "1.4.4", Some(&marker));
}

#[test]
#[ignore = "opt-in offline real-Bun fixture; set NEOENV_TEST_REAL_BUN"]
fn bun_cli_relocks_cached_npm_resolution_offline() {
    let binary = std::env::var_os("NEOENV_TEST_REAL_BUN").expect("set NEOENV_TEST_REAL_BUN");
    let binary = std::path::Path::new(&binary);
    let temp = TempDir::new().unwrap();
    let version = Command::new(binary)
        .arg("--version")
        .env_clear()
        .env("HOME", temp.path())
        .output()
        .unwrap();
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).unwrap();
    assert_bun_cli_relock(binary, version.trim(), None);
}
