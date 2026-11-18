//! Installer tests covering archive safety, digest enforcement, and the
//! distinct project and global storage layouts.

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256, Sha512};
use std::{
    error::Error as _,
    fs,
    io::{self, Cursor, Read, Write},
    net::TcpListener,
    panic::AssertUnwindSafe,
    path::Path,
    thread,
};

use crate::activation::runtime_diff;
use indexmap::indexmap;
use neoenv_runtime::budget::{ExtractionBudget, ResourceBudget};

use super::install_bun_locked_package;
use super::runtimes::{
    AdoptiumBinary, AdoptiumPackage, AdoptiumRelease, AdoptiumVersion, BunRuntimeAsset,
    JavaRequest, JavaRuntimeAsset, RUNTIME_LAYOUTS, RuntimeLayout, bun_binary_directory,
    bun_checksum, bun_target, host_target, install_bun_runtime_with_progress,
    install_java_runtime_with_progress, installed_runtimes, java_executable_path,
    java_existing_install, java_home_directory, java_home_directory_for, java_releases_url,
    java_target, parse_bun_version, parse_java_request, runtime_install_evidence,
    rust_target_triple, safe_bun_component, safe_java_component, select_java_binary,
    select_java_release, uv_binary, uv_target,
};
use super::{
    ArtifactLayout, ArtifactPlan, ToolLockfile, ToolStorage, budget_error, copy_and_verify,
    download_sha256_archive, extract_dotnet_tool_package, extract_gzip_tar,
    extract_tar_with_budget, extract_zip, extract_zip_with_budget, extraction_budget, get_metadata,
    github_metadata_at, github_metadata_at_for, global_storage, install_locked_tools_in_on,
    lockfile_path, project_storage, publish_install, resolve_aqua_registry, resolve_dotnet_tool,
    resolve_npm_registry, resolve_ruby_gems, resolve_tools, safe_archive_path,
    select_global_github_asset, sha256, verify_lockfile, write_lockfile,
};
use neoenv_core::tools::{ManagerLock, ManagerPackage, ScriptPolicy};
use neoenv_core::{
    Diagnostic, SourceSpan,
    tools::{
        AquaDeclaration, ArtifactVerification, CargoBuildLock, CargoBuildPolicy,
        CargoNetworkPolicy, CargoScriptPolicy, DotnetToolDeclaration, GithubReleaseAsset,
        GithubReleaseDeclaration, GithubReleaseMetadata, LockedTool, NpmDeclaration, Platform,
        PlatformOverride, PlatformSelector, ProviderAuthPolicy, RubyGemsDeclaration,
        TOOL_LOCK_SCHEMA_VERSION, ToolDeclaration, ToolPlanError, ToolProvenance, ToolProvider,
        plan_tools,
    },
};
use std::collections::BTreeMap;
use tempfile::TempDir;

#[test]
fn bun_archive_and_output_byte_budgets_are_independent_at_the_boundary() {
    const LIMIT: u64 = 256 * 1024 * 1024;
    let mut archive_bytes = 0;
    let mut output_bytes = 0;
    super::install::account_bun_package_bytes(&mut archive_bytes, LIMIT - 1).unwrap();
    super::install::account_bun_package_bytes(&mut archive_bytes, 1).unwrap();
    super::install::account_bun_package_bytes(&mut output_bytes, LIMIT).unwrap();
    assert_eq!(archive_bytes, LIMIT);
    assert_eq!(output_bytes, LIMIT);
    assert!(super::install::account_bun_package_bytes(&mut archive_bytes, 1).is_err());
    assert!(super::install::account_bun_package_bytes(&mut output_bytes, 1).is_err());
    assert_eq!(archive_bytes, LIMIT);
    assert_eq!(output_bytes, LIMIT);
    let mut overflow = 1;
    assert!(super::install::account_bun_package_bytes(&mut overflow, u64::MAX).is_err());
}

#[cfg(unix)]
#[test]
fn bun_launcher_quotes_shell_metacharacters() {
    assert_eq!(
        super::install::quote_bun_launcher_arg("bin/it's$(unsafe).js"),
        "'bin/it'\\''s$(unsafe).js'"
    );
}

#[cfg(unix)]
#[test]
fn bun_input_fifo_is_rejected_without_blocking() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    const CHILD_FIFO: &str = "NEOENV_TEST_FIFO_PATH";
    if let Some(fifo) = std::env::var_os(CHILD_FIFO) {
        let fifo = Path::new(&fifo);
        assert!(super::install::read_regular_nofollow_bounded(fifo, 1024).is_err());
        assert!(super::install::hash_file(fifo).is_err());
        assert!(super::install::verify_file_sri(fifo, "sha256-invalid").is_err());
        return;
    }
    let temp = TempDir::new().unwrap();
    let fifo = temp.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tools::tests::bun_input_fifo_is_rejected_without_blocking",
        ])
        .env_clear()
        .env(CHILD_FIFO, &fifo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "FIFO child rejected inputs incorrectly");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO input blocked instead of being rejected");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn managed_bun_fixture(
    temp: &TempDir,
    source: &Path,
    version: &str,
) -> (std::path::PathBuf, std::path::PathBuf, BunRuntimeAsset) {
    let data = temp.path().join("managed");
    let root = data.join("bun").join(version);
    let binary_dir = bun_binary_directory(&root);
    fs::create_dir_all(&binary_dir).unwrap();
    let binary = binary_dir.join(super::runtimes::bun_binary_name());
    fs::copy(source, &binary).unwrap();
    let archive = temp.path().join("bun.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
    let relative = binary
        .strip_prefix(&root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    zip.start_file(relative, zip::write::SimpleFileOptions::default())
        .unwrap();
    io::copy(&mut fs::File::open(source).unwrap(), &mut zip).unwrap();
    zip.finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));
    fs::write(root.join(neoenv_core::names::BUN_RUNTIME_RECEIPT), &digest).unwrap();
    let asset = BunRuntimeAsset {
        version: version.into(),
        url: "https://example.test/bun.zip".into(),
        sha256: digest,
    };
    (data, archive, asset)
}

#[cfg(unix)]
#[test]
fn managed_bun_verifies_archive_receipt_version_and_executable() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("source");
    let script = b"#!/bin/sh\n[ \"$1\" = \"--version\" ] && echo 1.4.4\n";
    fs::write(&source, script).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let (data, archive, asset) = managed_bun_fixture(&temp, &source, "1.4.4");
    let scratch = temp.path().join("scratch");
    fs::create_dir(&scratch).unwrap();
    let verify =
        |asset: &BunRuntimeAsset| super::verify_managed_bun(&data, asset, &archive, None, &scratch);
    let verified = verify(&asset).unwrap();
    assert_eq!(
        verified.executable_sha256(),
        format!("{:x}", Sha256::digest(script))
    );
    assert_eq!(verified.archive_sha256(), asset.sha256);
    assert_eq!(verified.version(), "1.4.4");

    fs::write(verified.executable(), b"modified").unwrap();
    assert!(verify(&asset).is_err());
    fs::copy(&source, verified.executable()).unwrap();
    let receipt = data
        .join("bun/1.4.4")
        .join(neoenv_core::names::BUN_RUNTIME_RECEIPT);
    fs::write(&receipt, "wrong").unwrap();
    assert!(verify(&asset).is_err());
    fs::write(&receipt, &asset.sha256).unwrap();
    let mut wrong = asset.clone();
    wrong.sha256 = "f".repeat(64);
    fs::write(&receipt, &wrong.sha256).unwrap();
    assert!(verify(&wrong).is_err());
    fs::write(&receipt, &asset.sha256).unwrap();
    let saved_archive = fs::read(&archive).unwrap();
    fs::write(&archive, b"invalid archive").unwrap();
    assert!(verify(&asset).is_err());
    fs::write(&archive, saved_archive).unwrap();
    let mut bad_version = asset.clone();
    bad_version.version = "../1.4.4".into();
    assert!(verify(&bad_version).is_err());
    fs::remove_file(verified.executable()).unwrap();
    assert!(
        verify(&asset).is_err(),
        "missing managed Bun must not fall back"
    );
    symlink(&source, verified.executable()).unwrap();
    assert!(verify(&asset).is_err());
    let (other_data, other_archive, other_asset) = managed_bun_fixture(&temp, &source, "1.4.5");
    assert!(
        super::verify_managed_bun(&other_data, &other_asset, &other_archive, None, &scratch)
            .is_err()
    );
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn locked_bun_hash_is_checked_before_the_binary_executes() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("executed");
    let marker_text = marker.to_str().unwrap();
    assert!(
        marker_text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
        })
    );
    let source = temp.path().join("source");
    fs::write(
        &source,
        format!("#!/bin/sh\nprintf yes > '{marker_text}'\necho 1.4.4\n"),
    )
    .unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let (data, archive, asset) = managed_bun_fixture(&temp, &source, "1.4.4");
    let error =
        super::verify_managed_bun(&data, &asset, &archive, Some(&"f".repeat(64)), temp.path())
            .unwrap_err();
    assert!(error.message.contains("locked manager SHA-256"));
    assert!(!marker.exists());
    let digest = format!("{:x}", Sha256::digest(fs::read(&source).unwrap()));
    super::verify_managed_bun(&data, &asset, &archive, Some(&digest), temp.path()).unwrap();
    assert!(marker.exists());
}

#[test]
fn growing_input_never_writes_beyond_the_selected_limit() {
    let input = vec![1_u8; 2 * 1024 * 1024 + 1];
    let mut destination = Vec::new();
    let error = super::install::copy_bounded_input(
        &mut Cursor::new(input),
        &mut destination,
        2 * 1024 * 1024,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(destination.len(), 2 * 1024 * 1024);
}

#[test]
fn bun_runtime_archive_retention_checks_digest_and_moves_into_staging() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("download");
    let staging = temp.path().join("install");
    fs::create_dir(&staging).unwrap();
    fs::write(&source, b"archive fixture").unwrap();
    let digest = format!("{:x}", Sha256::digest(b"archive fixture"));
    assert!(super::runtimes::retain_bun_archive(&source, &staging, &"f".repeat(64)).is_err());
    assert!(source.exists());
    assert!(!staging.join(super::BUN_RUNTIME_ARCHIVE).exists());
    super::runtimes::retain_bun_archive(&source, &staging, &digest).unwrap();
    assert!(!source.exists());
    assert_eq!(
        fs::read(staging.join(super::BUN_RUNTIME_ARCHIVE)).unwrap(),
        b"archive fixture"
    );
}

#[test]
fn legacy_bun_runtime_requires_explicit_reinstall_for_missing_evidence() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("1.4.4");
    let bin = bun_binary_directory(&root);
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join(super::runtimes::bun_binary_name()), b"fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            bin.join(super::runtimes::bun_binary_name()),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let bytes = b"archive";
    let asset = BunRuntimeAsset {
        version: "1.4.4".into(),
        url: "https://example.test/bun.zip".into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    };
    fs::write(
        root.join(neoenv_core::names::BUN_RUNTIME_RECEIPT),
        &asset.sha256,
    )
    .unwrap();
    let error = install_bun_runtime_with_progress(&root, &asset, |_| {}).unwrap_err();
    assert!(error.message.contains("explicitly reinstall"));
    assert!(bin.is_dir());
    fs::write(root.join(super::BUN_RUNTIME_ARCHIVE), bytes).unwrap();
    fs::write(
        root.join(super::BUN_RUNTIME_PROVENANCE),
        serde_json::to_vec(&asset).unwrap(),
    )
    .unwrap();
    assert!(install_bun_runtime_with_progress(&root, &asset, |_| {}).is_ok());
    fs::write(root.join(super::BUN_RUNTIME_ARCHIVE), b"tampered").unwrap();
    let error = install_bun_runtime_with_progress(&root, &asset, |_| {}).unwrap_err();
    assert!(error.message.contains("explicitly reinstall"));
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn bun_input_cache_replays_offline_and_refuses_tampering_or_partial_publication() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("bun-source");
    fs::write(&source, b"#!/bin/sh\necho 1.4.4\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let (_, archive, asset) = managed_bun_fixture(&temp, &source, "1.4.4");
    let tarball = temp.path().join("demo.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let bytes = fs::read(&tarball).unwrap();
    let package = ManagerPackage {
        id: "demo@1.0.0".into(),
        name: "demo".into(),
        version: "1.0.0".into(),
        dependencies: vec![],
        tarball_url: "https://example.test/demo.tgz".into(),
        integrity: format!("sha512-{}", STANDARD.encode(Sha512::digest(&bytes))),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    let manifest = temp.path().join("manifest");
    let lockfile = temp.path().join("lockfile");
    let manifest_bytes = bun_install_manifest("demo");
    let lock_bytes = bun_lockfile_fixture(&package);
    fs::write(&manifest, &manifest_bytes).unwrap();
    fs::write(&lockfile, &lock_bytes).unwrap();
    let graph = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.4.4".into(),
        manager_sha256: format!("{:x}", Sha256::digest(fs::read(&source).unwrap())),
        runtime_version: "1.4.4".into(),
        runtime_archive: Some(neoenv_core::tools::ManagerRuntimeArchive {
            url: asset.url,
            sha256: asset.sha256,
        }),
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
        lockfile_sha256: format!("{:x}", Sha256::digest(&lock_bytes)),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![package],
    };
    let input = super::StoredBunInputs {
        archive,
        tarball,
        manifest,
        bun_lockfile: lockfile,
    };
    let storage = temp.path().join("cache");
    fs::create_dir(&storage).unwrap();
    let mut missing = input.clone();
    missing.tarball = temp.path().join("missing");
    assert!(super::persist_bun_inputs(&storage, &graph, &missing).is_err());
    let store = storage.join("bun-manager-inputs");
    assert_eq!(fs::read_dir(&store).unwrap().count(), 0);
    let oversized = temp.path().join("oversized");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(2 * 1024 * 1024 + 1)
        .unwrap();
    for manifest in [true, false] {
        let mut invalid = input.clone();
        if manifest {
            invalid.manifest = oversized.clone();
        } else {
            invalid.bun_lockfile = oversized.clone();
        }
        assert!(super::persist_bun_inputs(&storage, &graph, &invalid).is_err());
        assert_eq!(fs::read_dir(&store).unwrap().count(), 0);
    }
    let cached = super::persist_bun_inputs(&storage, &graph, &input).unwrap();
    assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
    for path in [
        &input.archive,
        &input.tarball,
        &input.manifest,
        &input.bun_lockfile,
    ] {
        fs::remove_file(path).unwrap();
    }
    let recovered = super::recover_bun_inputs(&storage, &graph).unwrap();
    assert_eq!(recovered.archive, cached.archive);
    assert_eq!(fs::read(&recovered.tarball).unwrap(), bytes);
    let destination = temp.path().join("unpublished");
    assert!(
        super::install_cached_bun_package(
            &storage,
            &temp.path().join("missing-runtime"),
            &graph,
            temp.path(),
            &destination,
        )
        .is_err()
    );
    assert!(!destination.exists());
    fs::remove_file(&cached.manifest).unwrap();
    fs::write(&cached.manifest, b"tampered").unwrap();
    assert!(super::recover_bun_inputs(&storage, &graph).is_err());
    assert!(super::persist_bun_inputs(&storage, &graph, &input).is_err());
    assert_eq!(fs::read(&cached.manifest).unwrap(), b"tampered");
    fs::remove_file(&cached.manifest).unwrap();
    assert!(super::recover_bun_inputs(&storage, &graph).is_err());
    symlink(&cached.tarball, &cached.manifest).unwrap();
    assert!(super::recover_bun_inputs(&storage, &graph).is_err());
    assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
}

fn bun_install_manifest(package: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": "neoenv-locked-package-stage",
        "private": true,
        "dependencies": { (package.to_owned()): "file:./locked-package.tgz" }
    }))
    .unwrap()
}

fn bun_lockfile_fixture(package: &ManagerPackage) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "lockfileVersion": 2,
        "configVersion": 1,
        "workspaces": {
            "": {
                "name": "neoenv-locked-package-stage",
                "dependencies": { (package.name.clone()): "file:./locked-package.tgz" }
            }
        },
        "packages": {
            (package.name.clone()): [
                format!("{}@./locked-package.tgz", package.name),
                { "bin": { "demo": "bin.js" } },
                package.integrity
            ]
        }
    }))
    .unwrap()
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn bun_installs_only_one_preverified_local_tarball_with_scripts_disabled() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temporary = TempDir::new().unwrap();
    let bun = temporary.path().join("bun-fixture");
    let script = b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 1.2.3; exit 0; fi\n[ \"$1\" = install ] && [ \"$2\" = --offline ] && [ \"$3\" = --ignore-scripts ] || exit 31\ntest -f locked-package.tgz || exit 32\nmkdir -p node_modules/demo\nprintf '%s' '{\"name\":\"demo\",\"version\":\"1.0.0\",\"bin\":{\"demo\":\"bin.js\"}}' > node_modules/demo/package.json\nprintf '#!/bin/sh\\nexit 0\\n' > node_modules/demo/bin.js\n";
    fs::write(&bun, script).unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let bun_link = temporary.path().join("bun-link");
    symlink(&bun, &bun_link).unwrap();
    let tarball = temporary.path().join("package.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let tarball_bytes = fs::read(&tarball).unwrap();
    let lock = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.2.3".into(),
        manager_sha256: format!("{:x}", Sha256::digest(script)),
        runtime_version: "1.2.3".into(),
        runtime_archive: None,
        manifest_sha256: "a".repeat(64),
        lockfile_sha256: "b".repeat(64),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![ManagerPackage {
            id: "demo@1.0.0".into(),
            name: "demo".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            tarball_url: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".into(),
            integrity: format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball_bytes))),
            sha256: format!("{:x}", Sha256::digest(&tarball_bytes)),
        }],
    };
    let manifest = temporary.path().join("manifest.json");
    let lockfile = temporary.path().join("manager-lock.json");
    fs::write(&manifest, bun_install_manifest("demo")).unwrap();
    fs::write(&lockfile, bun_lockfile_fixture(&lock.packages[0])).unwrap();
    let original_lockfile = fs::read(&lockfile).unwrap();
    let mut lock = lock;
    lock.manifest_sha256 = format!("{:x}", Sha256::digest(fs::read(&manifest).unwrap()));
    lock.lockfile_sha256 = format!("{:x}", Sha256::digest(fs::read(&lockfile).unwrap()));
    assert!(
        install_bun_locked_package(
            &bun_link,
            &lock,
            &tarball,
            &manifest,
            &lockfile,
            &temporary.path().join("symlink-manager")
        )
        .is_err()
    );
    let tarball_link = temporary.path().join("tarball-link");
    symlink(&tarball, &tarball_link).unwrap();
    assert!(
        install_bun_locked_package(
            &bun,
            &lock,
            &tarball_link,
            &manifest,
            &lockfile,
            &temporary.path().join("symlink-tarball")
        )
        .is_err()
    );

    let collision = temporary.path().join("collision");
    fs::create_dir(&collision).unwrap();
    fs::write(collision.join("marker"), "keep").unwrap();
    assert!(
        install_bun_locked_package(&bun, &lock, &tarball, &manifest, &lockfile, &collision)
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(collision.join("marker")).unwrap(),
        "keep"
    );

    let mut mismatched = lock.clone();
    mismatched.packages[0].version = "2.0.0".into();
    mismatched.packages[0].id = "demo@2.0.0".into();
    let mismatch_destination = temporary.path().join("metadata-mismatch");
    assert!(
        install_bun_locked_package(
            &bun,
            &mismatched,
            &tarball,
            &manifest,
            &lockfile,
            &mismatch_destination
        )
        .is_err()
    );
    assert!(!mismatch_destination.exists());

    let destination = temporary.path().join("published");
    assert_eq!(
        install_bun_locked_package(&bun, &lock, &tarball, &manifest, &lockfile, &destination)
            .unwrap(),
        destination
    );
    assert!(destination.join("node_modules/demo").is_dir());
    assert!(!destination.join("package.json").exists());
    assert!(!destination.join("locked-package.tgz").exists());

    fs::write(&manifest, b"tampered manifest").unwrap();
    let bad_inputs = temporary.path().join("bad-input-digests");
    assert!(
        install_bun_locked_package(&bun, &lock, &tarball, &manifest, &lockfile, &bad_inputs)
            .is_err()
    );
    assert!(!bad_inputs.exists());
    fs::write(&manifest, bun_install_manifest("demo")).unwrap();
    let mut changed_graph: serde_json::Value = serde_json::from_slice(&original_lockfile).unwrap();
    changed_graph["workspaces"][""]["dependencies"]["demo"] =
        serde_json::Value::String("demo@9.9.9".into());
    fs::write(&lockfile, serde_json::to_vec(&changed_graph).unwrap()).unwrap();
    let mut graph_lock = lock.clone();
    graph_lock.lockfile_sha256 = format!("{:x}", Sha256::digest(fs::read(&lockfile).unwrap()));
    let bad_graph = temporary.path().join("bad-lockfile-graph");
    assert!(
        install_bun_locked_package(
            &bun,
            &graph_lock,
            &tarball,
            &manifest,
            &lockfile,
            &bad_graph
        )
        .is_err()
    );
    assert!(!bad_graph.exists());
    let mut wrong_metadata: serde_json::Value = serde_json::from_slice(&original_lockfile).unwrap();
    wrong_metadata["packages"]["demo"][1]["version"] = serde_json::Value::String("9.9.9".into());
    fs::write(&lockfile, serde_json::to_vec(&wrong_metadata).unwrap()).unwrap();
    let mut wrong_version_lock = lock.clone();
    wrong_version_lock.lockfile_sha256 =
        format!("{:x}", Sha256::digest(fs::read(&lockfile).unwrap()));
    let wrong_version = temporary.path().join("wrong-lock-metadata-version");
    assert!(
        install_bun_locked_package(
            &bun,
            &wrong_version_lock,
            &tarball,
            &manifest,
            &lockfile,
            &wrong_version
        )
        .is_err()
    );
    let mut extra_metadata: serde_json::Value = serde_json::from_slice(&original_lockfile).unwrap();
    extra_metadata["packages"]["demo"][1]["unexpected"] = serde_json::Value::Bool(true);
    fs::write(&lockfile, serde_json::to_vec(&extra_metadata).unwrap()).unwrap();
    let mut extra_metadata_lock = lock.clone();
    extra_metadata_lock.lockfile_sha256 =
        format!("{:x}", Sha256::digest(fs::read(&lockfile).unwrap()));
    let extra_metadata_path = temporary.path().join("extra-lock-metadata");
    assert!(
        install_bun_locked_package(
            &bun,
            &extra_metadata_lock,
            &tarball,
            &manifest,
            &lockfile,
            &extra_metadata_path
        )
        .is_err()
    );
    fs::write(&lockfile, b"tampered lockfile").unwrap();
    let bad_lock_input = temporary.path().join("bad-lockfile-digest");
    assert!(
        install_bun_locked_package(&bun, &lock, &tarball, &manifest, &lockfile, &bad_lock_input)
            .is_err()
    );
    assert!(!bad_lock_input.exists());
    fs::write(&lockfile, original_lockfile).unwrap();

    let bad_destination = temporary.path().join("bad-manager");
    let mut bad_manager = lock.clone();
    bad_manager.manager_sha256 = "0".repeat(64);
    assert!(
        install_bun_locked_package(
            &bun,
            &bad_manager,
            &tarball,
            &manifest,
            &lockfile,
            &bad_destination
        )
        .is_err()
    );
    assert!(!bad_destination.exists());

    let failing_script =
        b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 1.2.3; exit 0; fi\nexit 1\n";
    fs::write(&bun, failing_script).unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let mut failing_lock = lock;
    failing_lock.manager_sha256 = format!("{:x}", Sha256::digest(failing_script));
    let failed_destination = temporary.path().join("failed-publish");
    assert!(
        install_bun_locked_package(
            &bun,
            &failing_lock,
            &tarball,
            &manifest,
            &lockfile,
            &failed_destination
        )
        .is_err()
    );
    assert!(!failed_destination.exists());
}

fn write_npm_tarball(path: &Path, name: &str, version: &str) {
    let manifest =
        format!(r#"{{"name":"{name}","version":"{version}","bin":{{"demo":"bin.js"}}}}"#);
    let file = fs::File::create(path).unwrap();
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            "package/package.json",
            Cursor::new(manifest.into_bytes()),
        )
        .unwrap();
    let mut bin_header = tar::Header::new_gnu();
    let binary = b"#!/bin/sh\nexit 0\n";
    bin_header.set_size(binary.len() as u64);
    bin_header.set_mode(0o755);
    bin_header.set_cksum();
    archive
        .append_data(&mut bin_header, "package/bin.js", Cursor::new(binary))
        .unwrap();
    archive.finish().unwrap();
}

#[cfg(unix)]
#[test]
fn bun_output_verification_rejects_missing_extra_tampered_and_symlink_entries() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().unwrap();
    let tarball = temporary.path().join("verified.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let archive_bytes = fs::read(&tarball).unwrap();
    let package = ManagerPackage {
        id: "demo@1.0.0".into(),
        name: "demo".into(),
        version: "1.0.0".into(),
        dependencies: vec![],
        tarball_url: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".into(),
        integrity: format!("sha512-{}", STANDARD.encode(Sha512::digest(&archive_bytes))),
        sha256: format!("{:x}", Sha256::digest(&archive_bytes)),
    };
    let installed = temporary.path().join("installed");
    fs::create_dir(&installed).unwrap();
    let valid = || {
        fs::write(
            installed.join("package.json"),
            br#"{"name":"demo","version":"1.0.0","bin":{"demo":"bin.js"}}"#,
        )
        .unwrap();
        fs::write(installed.join("bin.js"), b"#!/bin/sh\nexit 0\n").unwrap();
    };
    valid();
    assert!(super::install::verify_bun_installed_package(&installed, &tarball, &package).is_ok());
    fs::remove_file(installed.join("bin.js")).unwrap();
    assert!(super::install::verify_bun_installed_package(&installed, &tarball, &package).is_err());
    valid();
    fs::write(installed.join("extra"), b"extra").unwrap();
    assert!(super::install::verify_bun_installed_package(&installed, &tarball, &package).is_err());
    fs::remove_file(installed.join("extra")).unwrap();
    fs::write(installed.join("bin.js"), b"tampered").unwrap();
    assert!(super::install::verify_bun_installed_package(&installed, &tarball, &package).is_err());
    fs::remove_file(installed.join("bin.js")).unwrap();
    symlink(temporary.path().join("elsewhere"), installed.join("bin.js")).unwrap();
    assert!(super::install::verify_bun_installed_package(&installed, &tarball, &package).is_err());
    let real = temporary.path().join("real-dir");
    let link = temporary.path().join("directory-link");
    fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();
    assert!(super::install::require_real_directory(&link, "test root").is_err());
}

#[test]
fn bun_archive_decompression_budget_rejects_streams_over_limit() {
    let mut under = Cursor::new(vec![0; 9]).take(10);
    assert!(super::install::finish_bounded_decompressed_stream(&mut under, 9).is_ok());
    let mut over = Cursor::new(vec![0; 11]).take(10);
    assert!(super::install::finish_bounded_decompressed_stream(&mut over, 9).is_err());
}

#[cfg(unix)]
#[test]
fn bun_executes_only_staged_input_copies_when_source_paths_change() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new().unwrap();
    let bun = temporary.path().join("bun-source");
    let tarball = temporary.path().join("source.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let replacement = |path: &Path| path.to_string_lossy().replace('\'', "'\\''");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf replaced > '{}'; printf replaced > '{}'; echo 1.2.3; exit 0; fi\n[ \"$1\" = install ] && [ \"$2\" = --offline ] && [ \"$3\" = --ignore-scripts ] || exit 31\nmkdir -p node_modules/demo\nprintf '%s' '{{\"name\":\"demo\",\"version\":\"1.0.0\",\"bin\":{{\"demo\":\"bin.js\"}}}}' > node_modules/demo/package.json\nprintf '#!/bin/sh\\nexit 0\\n' > node_modules/demo/bin.js\n",
        replacement(&bun),
        replacement(&tarball)
    );
    fs::write(&bun, &script).unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let archive_bytes = fs::read(&tarball).unwrap();
    let digest = format!("{:x}", Sha256::digest(&archive_bytes));
    let lock = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.2.3".into(),
        manager_sha256: format!("{:x}", Sha256::digest(script.as_bytes())),
        runtime_version: "1.2.3".into(),
        runtime_archive: None,
        manifest_sha256: "a".repeat(64),
        lockfile_sha256: "b".repeat(64),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![ManagerPackage {
            id: "demo@1.0.0".into(),
            name: "demo".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            tarball_url: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".into(),
            integrity: format!("sha512-{}", STANDARD.encode(Sha512::digest(&archive_bytes))),
            sha256: digest,
        }],
    };
    let manifest = temporary.path().join("source-manifest.json");
    let lockfile = temporary.path().join("source-lock.json");
    fs::write(&manifest, bun_install_manifest("demo")).unwrap();
    fs::write(&lockfile, bun_lockfile_fixture(&lock.packages[0])).unwrap();
    let mut lock = lock;
    lock.manifest_sha256 = format!("{:x}", Sha256::digest(fs::read(&manifest).unwrap()));
    lock.lockfile_sha256 = format!("{:x}", Sha256::digest(fs::read(&lockfile).unwrap()));
    let destination = temporary.path().join("published");
    install_bun_locked_package(&bun, &lock, &tarball, &manifest, &lockfile, &destination).unwrap();
    assert!(destination.join("node_modules/demo").is_dir());
    assert_eq!(fs::read(&bun).unwrap(), b"replaced");
    assert_eq!(fs::read(&tarball).unwrap(), b"replaced");
}

#[test]
#[ignore = "opt-in local Bun integration; run with NEOENV_TEST_REAL_BUN=/path/to/bun"]
#[allow(clippy::too_many_lines)]
fn real_bun_offline_install_when_test_binary_is_supplied() {
    let bun = std::env::var_os("NEOENV_TEST_REAL_BUN")
        .expect("set NEOENV_TEST_REAL_BUN to run the opt-in real-Bun integration test");
    let bun = Path::new(&bun);
    let temporary = TempDir::new().unwrap();
    let tarball = temporary.path().join("demo.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let archive_bytes = fs::read(&tarball).unwrap();
    let version = std::process::Command::new(bun)
        .arg("--version")
        .env_clear()
        .env("HOME", temporary.path())
        .output()
        .unwrap();
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).unwrap().trim().to_owned();
    let (data, archive, asset) = managed_bun_fixture(&temporary, bun, &version);
    let scratch = temporary.path().join("verification");
    fs::create_dir(&scratch).unwrap();
    let verified = super::verify_managed_bun(&data, &asset, &archive, None, &scratch).unwrap();
    let lock = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: version.clone(),
        manager_sha256: verified.executable_sha256().to_owned(),
        runtime_version: version,
        runtime_archive: Some(neoenv_core::tools::ManagerRuntimeArchive {
            url: verified.archive_url().into(),
            sha256: verified.archive_sha256().into(),
        }),
        manifest_sha256: "a".repeat(64),
        lockfile_sha256: "b".repeat(64),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![ManagerPackage {
            id: "demo@1.0.0".into(),
            name: "demo".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            tarball_url: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".into(),
            integrity: format!("sha512-{}", STANDARD.encode(Sha512::digest(&archive_bytes))),
            sha256: format!("{:x}", Sha256::digest(&archive_bytes)),
        }],
    };
    let manifest = temporary.path().join("manifest.json");
    let lockfile = temporary.path().join("bun.lock");
    fs::write(&manifest, bun_install_manifest("demo")).unwrap();
    fs::copy(&manifest, temporary.path().join("package.json")).unwrap();
    fs::copy(&tarball, temporary.path().join("locked-package.tgz")).unwrap();
    let generated_lock = std::process::Command::new(verified.executable())
        .args([
            "install",
            "--lockfile-only",
            "--offline",
            "--ignore-scripts",
        ])
        .current_dir(temporary.path())
        .env_clear()
        .env("HOME", temporary.path())
        .env("TMPDIR", temporary.path())
        .output()
        .unwrap();
    assert!(
        generated_lock.status.success(),
        "Bun could not create offline lock fixture: {}",
        String::from_utf8_lossy(&generated_lock.stderr)
    );
    assert!(lockfile.is_file());
    let mut tool = package_tool("npm", "demo", &lock.packages[0].sha256);
    tool.url.clone_from(&lock.packages[0].tarball_url);
    tool.provenance.registry_endpoint =
        Some(super::canonical_http_url("https://registry.npmjs.org").unwrap());
    tool.provenance.registry_integrity = Some(lock.packages[0].integrity.clone());
    let planned = neoenv_core::tools::PlannedTool {
        id: tool.id,
        resolved_version: tool.resolved_version,
        url: tool.url,
        platform: tool.platform,
        sha256: tool.sha256,
        provenance: tool.provenance,
        verification: tool.verification,
        binaries: tool.binaries,
        declaration_source: tool.declaration_source,
        cargo_toolchain: None,
    };
    let declaration = ToolDeclaration {
        id: planned.id.clone(),
        version: planned.resolved_version.clone(),
        provider: ToolProvider::Npm,
        url: None,
        sha256: None,
        github_release: None,
        gitlab_release: None,
        aqua: None,
        npm: Some(NpmDeclaration {
            endpoint: "https://registry.npmjs.org".into(),
            package: "demo".into(),
            manager: Some(neoenv_core::tools::NpmManager {
                name: neoenv_core::tools::NpmManagerName::Bun,
                version: lock.manager_version.clone(),
                archive_sha256: None,
            }),
        }),
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["demo".into()],
        binpath: None,
        bindir: None,
        platforms: vec![],
        declaration_source: planned.declaration_source.clone(),
    };
    let prepared = super::prepare_bun_lock(&declaration, &planned, &verified, &tarball).unwrap();
    fs::write(&manifest, &prepared.manifest).unwrap();
    fs::write(&lockfile, &prepared.bun_lockfile).unwrap();
    let lock = prepared.graph;
    let cache = temporary.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let source = super::StoredBunInputs {
        archive,
        tarball,
        manifest,
        bun_lockfile: lockfile,
    };
    super::persist_bun_inputs(&cache, &lock, &source).unwrap();
    for path in [
        &source.archive,
        &source.tarball,
        &source.manifest,
        &source.bun_lockfile,
    ] {
        fs::remove_file(path).unwrap();
    }
    let cached = super::recover_bun_inputs(&cache, &lock).unwrap();
    assert!(cached.archive.is_file());
    let destination = temporary.path().join("published");
    super::install_cached_bun_package(&cache, &data, &lock, &scratch, &destination).unwrap();
    assert!(destination.join("node_modules/demo").is_dir());
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn lockfile_reader_enforces_byte_limit_including_file_growth() {
    let limit = ResourceBudget::default().metadata_bytes as usize;
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("neoenv.lock");
    fs::write(&path, vec![b' '; limit]).unwrap();
    let exact = super::read_lockfile(&path).unwrap_err();
    assert!(exact.message.contains("invalid tool lockfile"));

    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b" ").unwrap();
    let oversized = super::read_lockfile(&path).unwrap_err();
    assert!(oversized.message.contains("metadata"));

    fs::write(&path, [0xff]).unwrap();
    let invalid_utf8 = super::read_lockfile(&path).unwrap_err();
    assert!(invalid_utf8.message.contains("not UTF-8"));
}
#[test]
fn truncated_archive_retains_the_archive_parser_source() {
    let temporary = TempDir::new().unwrap();
    let mut budget = ExtractionBudget::new(ResourceBudget::default(), None);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        extract_tar_with_budget(
            Cursor::new(b"not a tar archive"),
            temporary.path(),
            &mut budget,
        )
    }));
    let error = result
        .expect("a truncated archive must not panic")
        .unwrap_err();

    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some()
    );
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn cargo_single_crate_backend_builds_with_the_exact_managed_toolchain_and_publishes_atomically() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    use neoenv_core::tools::{
        CargoBuildPolicy, CargoDeclaration, CargoNetworkPolicy, CargoScriptPolicy, plan_cargo_crate,
    };
    let temp = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let crate_name = "cargo-fixture";
    let version = "1.2.3";
    let mut archive_bytes = Vec::new();
    {
        let encoder =
            flate2::write::GzEncoder::new(&mut archive_bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let manifest = format!(
            "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n[[bin]]\nname = \"fixture-bin\"\npath = \"src/main.rs\"\n"
        );
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                format!("{crate_name}-{version}/Cargo.toml"),
                manifest.as_bytes(),
            )
            .unwrap();
        let source = b"fn main() { println!(\"fixture\"); }\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(source.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                format!("{crate_name}-{version}/src/main.rs"),
                source.as_slice(),
            )
            .unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }
    let artifact = temp.path().join("fixture.crate");
    fs::write(&artifact, &archive_bytes).unwrap();
    let checksum = format!("{:x}", Sha256::digest(&archive_bytes));
    let rustc = Command::new("rustc").arg("-vV").output().unwrap();
    assert!(rustc.status.success());
    let verbose = String::from_utf8(rustc.stdout).unwrap();
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
    let cargo = Command::new("cargo").arg("--version").output().unwrap();
    assert!(
        String::from_utf8_lossy(&cargo.stdout).starts_with(&format!("cargo {compiler_version}"))
    );
    let toolchain = format!("{compiler_version}-{target}");
    let managed_root = temp.path().join("neoenv");
    let managed_bin = managed_root
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
        managed_root
            .join("rust")
            .join(compiler_version)
            .join(neoenv_core::names::RUST_RUNTIME_RECEIPT),
        "fixture receipt",
    )
    .unwrap();

    let declaration = ToolDeclaration {
        id: "fixture".into(),
        version: version.into(),
        provider: ToolProvider::Cargo,
        url: None,
        sha256: None,
        github_release: None,
        gitlab_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: Some(CargoDeclaration {
            crate_name: crate_name.into(),
            version: version.into(),
            registry: "https://index.crates.io/".into(),
            checksum: checksum.clone(),
            toolchain: toolchain.clone(),
            scripts: CargoScriptPolicy::Deny,
            build: CargoBuildPolicy::Isolated,
            network: CargoNetworkPolicy::Deny,
        }),
        binaries: vec!["fixture-bin".into()],
        binpath: None,
        bindir: None,
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
    };
    let planned = plan_cargo_crate(&declaration, &Platform::host()).unwrap();
    let lock = ToolLockfile::from_plan(&neoenv_core::tools::ToolPlan {
        tools: vec![planned],
    });
    lock.validate().unwrap();
    let tool = &lock.tools[0];
    let manifest_with_dep: toml::Value = toml::from_str(&format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\n[[bin]]\nname = \"fixture-bin\"\n[dependencies]\nserde = \"1\"\n"
    ))
    .unwrap();
    assert!(
        super::install::validate_cargo_single_crate(
            &manifest_with_dep,
            temp.path(),
            lock.cargo_build.as_ref().unwrap(),
            &tool.binaries,
        )
        .is_err(),
        "dependency graph must be refused by the narrow backend"
    );
    let manifest_without_dep: toml::Value = toml::from_str(&format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\n[[bin]]\nname = \"fixture-bin\"\n"
    ))
    .unwrap();
    fs::write(temp.path().join("build.rs"), "fn main() {}").unwrap();
    assert!(
        super::install::validate_cargo_single_crate(
            &manifest_without_dep,
            temp.path(),
            lock.cargo_build.as_ref().unwrap(),
            &tool.binaries,
        )
        .is_err(),
        "build scripts are denied by the declared script policy"
    );
    fs::remove_file(temp.path().join("build.rs")).unwrap();
    let storage = ToolStorage::project(temp.path());
    let destination = super::install::install_root(&storage, tool).unwrap();
    assert_eq!(
        super::install::install_key(tool).unwrap(),
        super::install::cargo_install_identity(tool, lock.cargo_build.as_ref().unwrap()).unwrap(),
        "the directory key and receipt must hash exactly the same canonical identity"
    );
    fs::create_dir_all(storage.artifact_directory()).unwrap();
    let cached_bad_artifact = storage.artifact_directory().join(&tool.sha256);
    fs::write(&cached_bad_artifact, b"not the locked crate archive").unwrap();
    assert!(
        super::install::ensure_artifact(&storage, tool).is_err(),
        "a cache entry with the requested name must still pass checksum verification"
    );
    assert!(!cached_bad_artifact.exists());
    super::install::publish_cargo_install_at(
        &artifact,
        &destination,
        tool,
        lock.cargo_build.as_ref().unwrap(),
        &managed_root,
        true,
    )
    .unwrap();
    let installed = super::install::which_installed_in(&storage, &lock, "fixture-bin").unwrap();
    assert_eq!(installed, destination.join("bin/fixture-bin"));
    let mut changed_toolchain = lock.clone();
    changed_toolchain.tools[0].cargo_toolchain = Some("1.2.3-x86_64-pc-windows-msvc".into());
    changed_toolchain.cargo_build.as_mut().unwrap().toolchain =
        "1.2.3-x86_64-pc-windows-msvc".into();
    assert_ne!(
        super::install::install_root(&storage, &lock.tools[0]).unwrap(),
        super::install::install_root(&storage, &changed_toolchain.tools[0]).unwrap(),
        "Cargo installations from distinct toolchains need distinct storage keys"
    );
    assert!(
        super::install::which_installed_in(&storage, &changed_toolchain, "fixture-bin").is_none(),
        "archive SHA alone must not make a build from another toolchain reusable"
    );
    let mut moved_declaration = lock.clone();
    moved_declaration.tools[0].declaration_source.path = "modules/tools.yaml".into();
    assert_ne!(
        super::install::install_key(&lock.tools[0]).unwrap(),
        super::install::install_key(&moved_declaration.tools[0]).unwrap(),
        "declaration provenance is part of the shared install/receipt identity"
    );
    assert!(
        super::install::which_installed_in(&storage, &moved_declaration, "fixture-bin").is_none(),
        "a changed declaration source must not reuse the old receipt"
    );
    let installed_binary = destination.join("bin/fixture-bin");
    let missing_binary = destination.join("bin/fixture-bin.saved");
    fs::rename(&installed_binary, &missing_binary).unwrap();
    assert!(
        super::install::which_installed_in(&storage, &lock, "fixture-bin").is_none(),
        "a matching receipt must not select an installation with an incomplete binary set"
    );
    fs::rename(missing_binary, installed_binary).unwrap();
    let second_root = super::install::install_root(&storage, &changed_toolchain.tools[0]).unwrap();
    fs::create_dir_all(second_root.join("bin")).unwrap();
    fs::copy(
        destination.join("bin/fixture-bin"),
        second_root.join("bin/fixture-bin"),
    )
    .unwrap();
    super::install::write_install_metadata(&second_root, &changed_toolchain.tools[0]).unwrap();
    fs::write(
        second_root.join(super::INSTALL_RECEIPT),
        &changed_toolchain.tools[0].sha256,
    )
    .unwrap();
    fs::write(
        second_root.join(super::install::CARGO_BUILD_RECEIPT),
        super::install::cargo_install_identity(
            &changed_toolchain.tools[0],
            changed_toolchain.cargo_build.as_ref().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let versions = super::install::installed_versions_in(&storage).unwrap();
    assert_eq!(
        versions
            .iter()
            .filter(|version| version.sha256 == tool.sha256)
            .count(),
        2,
        "the same source archive must retain separate build identities"
    );
    let orphaned = super::install::cleanup_unreferenced_in(&storage, &lock, true).unwrap();
    assert!(
        orphaned.iter().any(|entry| entry.path == second_root),
        "cleanup must recognize the alternate build identity as an independent install"
    );
    let primary_key = super::install::install_key(&lock.tools[0]).unwrap();
    let alternate_key = super::install::install_key(&changed_toolchain.tools[0]).unwrap();
    assert!(super::install::remove_installed_version_in(&storage, &primary_key).unwrap());
    assert!(!destination.exists());
    assert!(
        second_root.exists(),
        "removing one build identity must preserve the other install and receipt"
    );
    assert!(
        second_root
            .join(super::install::CARGO_BUILD_RECEIPT)
            .is_file()
            && super::install::receipt_matches(
                &second_root.join(super::install::CARGO_BUILD_RECEIPT),
                &alternate_key,
            ),
        "the unselected build receipt must remain intact"
    );
    assert!(super::install::remove_installed_version_in(&storage, &alternate_key).unwrap());
    assert!(!second_root.exists());
    assert!(
        super::install::installed_versions_in(&storage)
            .unwrap()
            .is_empty()
    );

    let preserved = temp.path().join("pre-existing");
    fs::create_dir_all(&preserved).unwrap();
    fs::write(preserved.join("keep"), b"original").unwrap();
    let failure = super::install::publish_cargo_install_at(
        &artifact,
        &preserved,
        tool,
        lock.cargo_build.as_ref().unwrap(),
        &managed_root,
        true,
    );
    assert!(failure.is_err());
    assert_eq!(fs::read(preserved.join("keep")).unwrap(), b"original");

    let denied = super::install::publish_cargo_install_at(
        &artifact,
        &temp.path().join("denied"),
        tool,
        lock.cargo_build.as_ref().unwrap(),
        &managed_root,
        false,
    );
    assert!(denied.is_err());

    let fake_managed_root = temp.path().join("fake-neoenv");
    let fake_bin = fake_managed_root
        .join("rust")
        .join(compiler_version)
        .join("rustup/toolchains")
        .join(&toolchain)
        .join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_cargo = fake_bin.join("cargo");
    fs::write(
        &fake_cargo,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cargo {compiler_version}\"; exit 0; fi\nprintf '%s\\n' \"$*\" >> \"{}\"\nif [ \"$1\" = \"generate-lockfile\" ]; then while [ \"$#\" -gt 0 ]; do if [ \"$1\" = \"--manifest-path\" ]; then shift; manifest=\"$1\"; fi; shift; done; printf 'version = 4\\n' > \"$(dirname \"$manifest\")/Cargo.lock\"; exit 0; fi\nif [ \"$1\" = \"build\" ]; then while [ \"$#\" -gt 0 ]; do if [ \"$1\" = \"--target-dir\" ]; then shift; target=\"$1\"; fi; shift; done; mkdir -p \"$target/debug\"; printf '#!/bin/sh\\nexit 0\\n' > \"$target/debug/fixture-bin\"; chmod 755 \"$target/debug/fixture-bin\"; exit 0; fi\nexit 2\n",
            temp.path().join("fake-cargo-invocations").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_rustc = fake_bin.join("rustc");
    fs::write(
        &fake_rustc,
        format!(
            "#!/bin/sh\nexec \"{}\" \"$@\"\n",
            sysroot.join("bin/rustc").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_rustc, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        fake_managed_root
            .join("rust")
            .join(compiler_version)
            .join(neoenv_core::names::RUST_RUNTIME_RECEIPT),
        "fake fixture receipt",
    )
    .unwrap();
    let fake_destination = storage
        .install_directory()
        .join(format!("{}-fake", tool.sha256));
    super::install::publish_cargo_install_at(
        &artifact,
        &fake_destination,
        tool,
        lock.cargo_build.as_ref().unwrap(),
        &fake_managed_root,
        true,
    )
    .unwrap();
    let invocations = fs::read_to_string(temp.path().join("fake-cargo-invocations")).unwrap();
    assert!(invocations.contains("build --locked --offline --bins"));
    assert!(fake_destination.join("bin/fixture-bin").is_file());

    let marker = temp.path().join("wrapper-ran");
    let wrapper = temp.path().join("malicious-rustc-wrapper");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ntouch \"{}\"\nexec \"{}\" \"$@\"\n",
            marker.display(),
            sysroot.join("bin/rustc").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let runtime_config = managed_root.join(".cargo");
    fs::create_dir_all(&runtime_config).unwrap();
    fs::write(
        runtime_config.join("config.toml"),
        format!(
            "[build]\nrustc-wrapper = {:?}\n",
            wrapper.display().to_string()
        ),
    )
    .unwrap();
    let runtime_ancestor_install = temp.path().join("runtime-ancestor-config-install");
    assert!(
        super::install::publish_cargo_install_at(
            &artifact,
            &runtime_ancestor_install,
            tool,
            lock.cargo_build.as_ref().unwrap(),
            &managed_root,
            true,
        )
        .is_err(),
        "Cargo config above the temporary workspace must be rejected"
    );
    assert!(!marker.exists(), "runtime-data ancestor rustc-wrapper ran");
    fs::remove_dir_all(&runtime_config).unwrap();
    let wrapper_config = format!(
        "[build]\nrustc-wrapper = {:?}\n",
        wrapper.display().to_string()
    );
    let malicious_manifest = format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n[[bin]]\nname = \"fixture-bin\"\npath = \"src/main.rs\"\n"
    );
    let mut malicious_archive_bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(
            &mut malicious_archive_bytes,
            flate2::Compression::default(),
        );
        let mut archive = tar::Builder::new(encoder);
        for (path, contents) in [
            (
                format!("{crate_name}-{version}/Cargo.toml"),
                malicious_manifest.as_bytes(),
            ),
            (
                format!("{crate_name}-{version}/src/main.rs"),
                &b"fn main() { println!(\"fixture\"); }\n"[..],
            ),
            (".cargo/config.toml".to_owned(), wrapper_config.as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, contents).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }
    let malicious_archive = temp.path().join("malicious.crate");
    fs::write(&malicious_archive, malicious_archive_bytes).unwrap();
    assert!(
        super::install::publish_cargo_install_at(
            &malicious_archive,
            &temp.path().join("malicious-install"),
            tool,
            lock.cargo_build.as_ref().unwrap(),
            &managed_root,
            true,
        )
        .is_err()
    );
    assert!(
        !marker.exists(),
        "rustc-wrapper from extracted ancestor Cargo config must never execute"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // The adversarial source and manifest cases share one contract fixture.
fn cargo_build_refuses_external_binary_paths_and_compile_time_file_includes() {
    use neoenv_core::tools::{
        CargoBuildLock, CargoBuildPolicy, CargoNetworkPolicy, CargoScriptPolicy,
    };

    let crate_root = TempDir::new().unwrap();
    fs::create_dir_all(crate_root.path().join("src")).unwrap();
    fs::write(crate_root.path().join("src/main.rs"), "fn main() {}").unwrap();
    let build = CargoBuildLock {
        tool_id: "fixture".into(),
        crate_name: "fixture".into(),
        version: "1.0.0".into(),
        registry: "https://index.crates.io/".into(),
        checksum: "a".repeat(64),
        toolchain: "1.98.1-x86_64-unknown-linux-gnu".into(),
        scripts: CargoScriptPolicy::Deny,
        build: CargoBuildPolicy::Isolated,
        network: CargoNetworkPolicy::Deny,
    };
    let manifest = |path: &str| {
        toml::from_str::<toml::Value>(&format!(
            "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n[[bin]]\nname = \"fixture-bin\"\npath = {path:?}\n"
        ))
        .unwrap()
    };
    for outside_path in ["../outside.rs", "/host/secret.rs"] {
        assert!(
            super::install::validate_cargo_single_crate(
                &manifest(outside_path),
                crate_root.path(),
                &build,
                &["fixture-bin".into()],
            )
            .is_err(),
            "out-of-crate binary source path must be refused: {outside_path}"
        );
    }
    for library_path in ["../outside.rs", "/host/secret.rs"] {
        let library_manifest = toml::from_str::<toml::Value>(&format!(
            "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n[[bin]]\nname = \"fixture-bin\"\npath = \"src/main.rs\"\n[lib]\npath = {library_path:?}\n"
        ))
        .unwrap();
        assert!(
            super::install::validate_cargo_single_crate(
                &library_manifest,
                crate_root.path(),
                &build,
                &["fixture-bin".into()],
            )
            .is_err(),
            "library targets are refused by the narrow backend: {library_path}"
        );
    }

    let host_path = crate_root.path().join("host-file");
    fs::write(&host_path, "host file sentinel").unwrap();
    fs::write(
        crate_root.path().join("src/main.rs"),
        format!("const HOST: &[u8] = include_bytes!({host_path:?}); fn main() {{}}"),
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "compile-time include macros can read files outside the verified crate archive"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        "const HOST: &[u8] = include /* attacker comment */ ! (\"/host/secret\"); fn main() {}",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "comments may separate a Rust macro name from its exclamation mark"
    );
    fs::write(
        crate_root.path().join("src/main.txt"),
        "const HOST: &[u8] = include_bytes!(\"/host/secret\"); fn main() {}",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.txt"),
        )
        .is_err(),
        "Rust source with a non-Rust extension is still scanned when named as a binary target"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        r##"const RAW: &str = r#"// not a comment"#; include_bytes/**/!("/host/secret");"##,
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "raw strings make the simple comment scan uncertain, so the source is refused"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        r#"let _ = '"'; let _ = "/*"; let _ = include_bytes/**/!("/path/to/file");"#,
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "character literals are refused before their quotes can confuse comment scanning"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        "#[cfg_attr(all(), path = \"module.txt\")] mod module;",
    )
    .unwrap();
    fs::write(
        crate_root.path().join("src/module.txt"),
        "const HOST: &[u8] = include_bytes!(\"/path/to/file\");",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "conditional module paths are refused before they can select unscanned source"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        "macro_rules! hidden { ($m:ident) => { $m!(\"/path/to/file\") } } fn main() { let _ = hidden!(include_bytes); }",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "macro_rules definitions are refused rather than attempting to analyze expansion"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        "use std::include_bytes as read_file; fn main() { let _ = read_file!(\"/path/to/file\"); }",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "include_bytes identifiers are refused even when imported under an alias"
    );
    fs::write(
        crate_root.path().join("src/main.rs"),
        "#[external::attribute] fn main() {}",
    )
    .unwrap();
    assert!(
        super::install::reject_unconfined_cargo_sources(
            crate_root.path(),
            &manifest("src/main.rs"),
        )
        .is_err(),
        "procedural attribute macros are refused"
    );
}

#[test]
fn serializes_declaration_order_and_verifies_without_artifact_io() {
    let temporary = TempDir::new().unwrap();
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let declarations = ["first", "second"].map(|id| ToolDeclaration {
        id: id.into(),
        version: "1.0.0".into(),
        provider: neoenv_core::tools::ToolProvider::ExplicitUrl,
        url: Some(format!("https://example.test/{id}")),
        sha256: Some(digest.into()),
        github_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec![id.into()],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    });
    let plan = plan_tools(&declarations, &Platform::new("linux", "x86_64")).unwrap();
    let path = lockfile_path(temporary.path());
    write_lockfile(&path, &plan).unwrap();
    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.find("first").unwrap() < output.find("second").unwrap());
    assert!(verify_lockfile(&path, &plan).is_ok());
}

#[test]
fn project_and_global_storage_keep_distinct_layouts() {
    let temporary = TempDir::new().unwrap();
    let project = project_storage(temporary.path());
    let global = global_storage(temporary.path());
    assert_eq!(
        project.artifact_directory(),
        temporary.path().join(".neoenv/artifacts")
    );
    assert_eq!(
        project.install_directory(),
        temporary.path().join(".neoenv/tools")
    );
    assert_eq!(
        global.artifact_directory(),
        temporary.path().join("artifacts")
    );
    assert_eq!(global.install_directory(), temporary.path().join("tools"));
    assert!(!global.install_directory().ends_with(".neoenv/tools"));
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn manager_graph_is_bound_to_plan_selection_and_input_bytes_before_write() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new().unwrap();
    let path = lockfile_path(temp.path());
    let tarball = temp.path().join("fixture.tgz");
    write_npm_tarball(&tarball, "demo", "1.0.0");
    let bytes = fs::read(&tarball).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&bytes)));
    let package = ManagerPackage {
        id: "demo@1.0.0".into(),
        name: "demo".into(),
        version: "1.0.0".into(),
        dependencies: vec![],
        tarball_url: "https://example.test/fixture".into(),
        integrity: integrity.clone(),
        sha256: digest.clone(),
    };
    let manifest = temp.path().join("manifest.json");
    let bun_lock = temp.path().join("bun.lock");
    let bun = temp.path().join("bun");
    fs::write(&bun, b"#!/bin/sh\necho 1.2.3\n").unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let (data, archive, asset) = managed_bun_fixture(&temp, &bun, "1.2.3");
    let verified = super::verify_managed_bun(&data, &asset, &archive, None, temp.path()).unwrap();
    let manifest_bytes = bun_install_manifest("demo");
    let lock_bytes = bun_lockfile_fixture(&package);
    fs::write(&manifest, &manifest_bytes).unwrap();
    fs::write(&bun_lock, &lock_bytes).unwrap();
    let graph = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.2.3".into(),
        manager_sha256: verified.executable_sha256().to_owned(),
        runtime_version: "1.2.3".into(),
        runtime_archive: Some(neoenv_core::tools::ManagerRuntimeArchive {
            url: verified.archive_url().into(),
            sha256: verified.archive_sha256().into(),
        }),
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
        lockfile_sha256: format!("{:x}", Sha256::digest(&lock_bytes)),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![package],
    };
    let mut tool = package_tool("npm", "demo", &digest);
    tool.provenance.registry_integrity = Some(integrity);
    tool.provenance.registry_endpoint =
        Some(super::canonical_http_url("https://example.test").unwrap());
    let plan = neoenv_core::tools::ToolPlan {
        tools: vec![neoenv_core::tools::PlannedTool {
            id: tool.id.clone(),
            resolved_version: tool.resolved_version.clone(),
            url: tool.url.clone(),
            platform: tool.platform.clone(),
            sha256: tool.sha256.clone(),
            provenance: tool.provenance.clone(),
            verification: tool.verification.clone(),
            binaries: tool.binaries.clone(),
            declaration_source: tool.declaration_source.clone(),
            cargo_toolchain: None,
        }],
    };
    let declaration = ToolDeclaration {
        id: "fixture".into(),
        version: "1.0.0".into(),
        provider: ToolProvider::Npm,
        url: None,
        sha256: None,
        github_release: None,
        gitlab_release: None,
        aqua: None,
        npm: Some(NpmDeclaration {
            endpoint: "https://example.test".into(),
            package: "demo".into(),
            manager: Some(neoenv_core::tools::NpmManager {
                name: neoenv_core::tools::NpmManagerName::Bun,
                version: "1.2.3".into(),
                archive_sha256: None,
            }),
        }),
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["demo".into()],
        binpath: None,
        bindir: None,
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
    };
    let prepared =
        super::prepare_bun_lock(&declaration, &plan.tools[0], &verified, &tarball).unwrap();
    assert_eq!(prepared.graph, graph);
    assert_eq!(prepared.manifest, manifest_bytes);
    assert_eq!(prepared.bun_lockfile, lock_bytes);
    let collision = temp.path().join("existing-download");
    fs::write(&collision, b"do not replace").unwrap();
    assert!(super::stage_resolved_npm_tarball(&plan.tools[0], &collision).is_err());
    assert_eq!(fs::read(&collision).unwrap(), b"do not replace");
    let mut wrong_tool = plan.tools[0].clone();
    wrong_tool.sha256 = "f".repeat(64);
    assert!(super::prepare_bun_lock(&declaration, &wrong_tool, &verified, &tarball).is_err());
    let dependent_tarball = temp.path().join("dependent.tgz");
    let dependent_bytes = gzip_tar(&[
        (
            "package/package.json",
            br#"{"name":"demo","version":"1.0.0","bin":{"demo":"bin.js"},"dependencies":{"other":"1.0.0"}}"#,
        ),
        ("package/bin.js", b"#!/bin/sh\nexit 0\n"),
    ]);
    fs::write(&dependent_tarball, &dependent_bytes).unwrap();
    let mut dependent_tool = plan.tools[0].clone();
    dependent_tool.sha256 = format!("{:x}", Sha256::digest(&dependent_bytes));
    dependent_tool
        .verification
        .sha256
        .clone_from(&dependent_tool.sha256);
    dependent_tool.provenance.registry_integrity = Some(format!(
        "sha512-{}",
        STANDARD.encode(Sha512::digest(&dependent_bytes))
    ));
    let error =
        super::prepare_bun_lock(&declaration, &dependent_tool, &verified, &dependent_tarball)
            .err()
            .expect("dependency-bearing packages must be refused");
    assert!(error.message.contains("dependency graph"));
    let write = |graph: &ManagerLock, selection: &ToolDeclaration| {
        super::write_lockfile_with_manager(
            &path,
            &plan,
            &super::BunManagerLockInputs {
                declaration: selection,
                graph,
                managed_bun: &verified,
                tarball: &tarball,
                manifest: &manifest,
                bun_lockfile: &bun_lock,
            },
        )
    };
    let mut cases = Vec::new();
    let mut wrong = graph.clone();
    wrong.manager = "pnpm".into();
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.manager_sha256 = "f".repeat(64);
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.packages[0].name = "other".into();
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.packages[0].id = "other@1.0.0".into();
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.packages[0].version = "2.0.0".into();
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.packages[0].sha256 = "f".repeat(64);
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.packages[0].integrity = format!("sha512-{}", STANDARD.encode([0u8; 64]));
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.manifest_sha256 = "f".repeat(64);
    cases.push(wrong);
    let mut wrong = graph.clone();
    wrong.lockfile_sha256 = "f".repeat(64);
    cases.push(wrong);
    for wrong in cases {
        assert!(write(&wrong, &declaration).is_err());
        assert!(!path.exists());
    }
    let mut wrong_manager = declaration.clone();
    wrong_manager
        .npm
        .as_mut()
        .unwrap()
        .manager
        .as_mut()
        .unwrap()
        .version = "2.0.0".into();
    assert!(write(&graph, &wrong_manager).is_err());
    wrong_manager
        .npm
        .as_mut()
        .unwrap()
        .manager
        .as_mut()
        .unwrap()
        .name = neoenv_core::tools::NpmManagerName::Pnpm;
    assert!(write(&graph, &wrong_manager).is_err());
    let mut wrong_id = declaration.clone();
    wrong_id.id = "other".into();
    assert!(write(&graph, &wrong_id).is_err());
    fs::write(&bun_lock, b"{}").unwrap();
    let mut altered_graph = graph.clone();
    altered_graph.lockfile_sha256 = format!("{:x}", Sha256::digest(b"{}"));
    assert!(write(&altered_graph, &declaration).is_err());
    fs::write(&bun_lock, &lock_bytes).unwrap();
    assert!(!path.exists());
    write(&graph, &declaration).unwrap();
    assert_eq!(
        super::read_lockfile(&path).unwrap().manager_lock,
        Some(graph.clone())
    );
    let before = fs::read(&path).unwrap();
    fs::write(&manifest, b"changed").unwrap();
    assert!(write(&graph, &declaration).is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn legacy_relock_preserves_manager_locks_and_reports_invalid_existing_paths() {
    let temp = TempDir::new().unwrap();
    let path = lockfile_path(temp.path());
    let plan = neoenv_core::tools::ToolPlan::default();
    let graph = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: "1.2.3".into(),
        manager_sha256: "a".repeat(64),
        runtime_version: "1.2.3".into(),
        runtime_archive: None,
        manifest_sha256: "b".repeat(64),
        lockfile_sha256: "c".repeat(64),
        script_policy: ScriptPolicy::Disabled,
        packages: vec![],
    };
    let existing = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![],
        pins: BTreeMap::new(),
        manager_lock: Some(graph),
        cargo_build: None,
    };
    let original = toml::to_string_pretty(&existing).unwrap();
    fs::write(&path, &original).unwrap();
    let error = write_lockfile(&path, &plan).unwrap_err();
    assert!(error.message.contains("refusing to discard"));
    assert_eq!(fs::read_to_string(&path).unwrap(), original);

    let corrupted = b"not valid [toml";
    fs::write(&path, corrupted).unwrap();
    assert!(write_lockfile(&path, &plan).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupted);

    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("keep"), b"unchanged").unwrap();
    assert!(write_lockfile(&path, &plan).is_err());
    assert_eq!(fs::read(path.join("keep")).unwrap(), b"unchanged");
}

#[test]
fn legacy_relock_refuses_to_discard_cargo_build_provenance_before_writing() {
    let temp = TempDir::new().unwrap();
    let path = lockfile_path(temp.path());
    let existing = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![LockedTool {
            id: "ripgrep".into(),
            resolved_version: "14.1.1".into(),
            url: "https://static.crates.io/crates/ripgrep/ripgrep-14.1.1.crate".into(),
            platform: Platform::new("linux", "x86_64"),
            sha256: "a".repeat(64),
            provenance: ToolProvenance {
                provider: "cargo".into(),
                immutable_id: "https://static.crates.io/crates/ripgrep/ripgrep-14.1.1.crate".into(),
                repository: None,
                release_id: None,
                asset_id: None,
                registry_endpoint: Some("https://index.crates.io/".into()),
                registry_revision: None,
                manifest_sha256: None,
                package: Some("ripgrep".into()),
                registry_integrity: None,
                declaration_sha256: None,
                authentication: ProviderAuthPolicy::Prohibited,
            },
            verification: ArtifactVerification {
                sha256: "a".repeat(64),
                signature: None,
            },
            binaries: vec!["rg".into()],
            declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
            resolver: "cargo".into(),
            cargo_toolchain: Some("1.85.0".into()),
        }],
        pins: BTreeMap::new(),
        manager_lock: None,
        cargo_build: Some(CargoBuildLock {
            tool_id: "ripgrep".into(),
            crate_name: "ripgrep".into(),
            version: "14.1.1".into(),
            registry: "https://index.crates.io/".into(),
            checksum: "a".repeat(64),
            toolchain: "1.85.0".into(),
            scripts: CargoScriptPolicy::Deny,
            build: CargoBuildPolicy::Isolated,
            network: CargoNetworkPolicy::Deny,
        }),
    };
    existing.validate().unwrap();
    let original = toml::to_string_pretty(&existing).unwrap();
    fs::write(&path, &original).unwrap();

    let error = write_lockfile(&path, &neoenv_core::tools::ToolPlan::default()).unwrap_err();
    assert!(
        error
            .message
            .contains("refusing to discard the existing Cargo build provenance")
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn legacy_relock_does_not_treat_a_dangling_symlink_as_a_missing_lock() {
    use std::os::unix::fs::symlink;
    let temp = TempDir::new().unwrap();
    let path = lockfile_path(temp.path());
    let target = temp.path().join("missing");
    symlink(&target, &path).unwrap();
    assert!(write_lockfile(&path, &neoenv_core::tools::ToolPlan::default()).is_err());
    assert_eq!(fs::read_link(&path).unwrap(), target);
    assert!(!target.exists());
}

#[test]
fn legacy_relock_preserves_pins_and_creates_a_missing_lock() {
    let temp = TempDir::new().unwrap();
    let path = lockfile_path(temp.path());
    let plan = neoenv_core::tools::ToolPlan::default();
    write_lockfile(&path, &plan).unwrap();
    let mut existing = super::read_lockfile(&path).unwrap();
    existing.pins.insert("demo".into(), vec!["1.2.3".into()]);
    fs::write(&path, toml::to_string_pretty(&existing).unwrap()).unwrap();
    let rewritten = write_lockfile(&path, &plan).unwrap();
    assert_eq!(rewritten.pins, existing.pins);
    assert_eq!(super::read_lockfile(&path).unwrap().pins, existing.pins);
}

#[test]
fn rejects_digest_mismatches_without_publishing_bytes() {
    let mut output = Vec::new();
    let error = copy_and_verify(
        &mut Cursor::new(b"actual"),
        &mut output,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap_err();

    assert_eq!(error.code, "NEO520");
    assert!(error.message.contains("SHA-256 mismatch"));
}

#[test]
fn rejects_archive_paths_that_escape_the_install_root() {
    assert!(safe_archive_path(Path::new("../outside")).is_err());
    assert!(safe_archive_path(Path::new("/outside")).is_err());
    assert!(safe_archive_path(Path::new("./bin/tool")).is_ok());
    assert!(safe_archive_path(Path::new("bin/tool")).is_ok());
}

fn tar_fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, *contents).unwrap();
    }
    builder.into_inner().unwrap()
}

fn small_budget(overrides: fn(&mut ResourceBudget)) -> ExtractionBudget {
    let mut limits = ResourceBudget::default();
    overrides(&mut limits);
    ExtractionBudget::new(limits, Some(1))
}

fn package_tool(resolver: &str, package: &str, integrity: &str) -> LockedTool {
    LockedTool {
        id: "fixture".into(),
        resolved_version: "1.0.0".into(),
        url: "https://example.test/fixture".into(),
        platform: Platform::new("linux", "x86_64"),
        sha256: integrity.into(),
        provenance: ToolProvenance {
            provider: resolver.into(),
            immutable_id: "fixture".into(),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some("https://example.test".into()),
            registry_revision: None,
            manifest_sha256: None,
            package: Some(package.into()),
            registry_integrity: Some(integrity.into()),
            declaration_sha256: None,
            authentication: ProviderAuthPolicy::Prohibited,
        },
        verification: ArtifactVerification {
            sha256: integrity.into(),
            signature: None,
        },
        binaries: vec!["demo".into()],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
        resolver: resolver.into(),
        cargo_toolchain: None,
    }
}

#[test]
fn npm_manager_lock_does_not_fall_back_to_direct_archive_install() {
    let temp = TempDir::new().unwrap();
    let storage = project_storage(temp.path());
    let tool = package_tool("npm", "fixture", &"a".repeat(64));
    let host = tool.platform.clone();
    let lockfile = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![tool],
        pins: BTreeMap::new(),
        cargo_build: None,
        manager_lock: Some(ManagerLock {
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
                tarball_url: "https://example.test/fixture".into(),
                integrity: format!("sha512-{}", STANDARD.encode([0u8; 64])),
                sha256: "a".repeat(64),
            }],
        }),
    };
    lockfile.validate().unwrap();
    let error = install_locked_tools_in_on(&storage, &lockfile, &host).unwrap_err();
    assert!(
        error
            .message
            .contains("refusing direct archive installation")
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn cargo_selection_rejects_missing_cargo_declaration() {
    let mut tool = github_declaration(&GithubReleaseDeclaration {
        repository: "owner/tool".into(),
        asset: None,
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    tool.provider = ToolProvider::Cargo;
    let error = resolve_tools(&[tool], &Platform::new("linux", "x86_64")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid Cargo metadata or build policy")
    );
}

#[test]
fn locked_cargo_provenance_and_resolver_refuse_before_storage_effects() {
    let tool = LockedTool {
        id: "cargo-tool".into(),
        resolved_version: "1.2.3".into(),
        url: "https://example.test/source".into(),
        platform: Platform::new("linux", "x86_64"),
        sha256: "a".repeat(64),
        provenance: ToolProvenance {
            provider: "cargo".into(),
            immutable_id: "https://index.crates.io/".into(),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some("https://index.crates.io/".into()),
            registry_revision: None,
            manifest_sha256: None,
            package: Some("cargo-tool".into()),
            registry_integrity: None,
            declaration_sha256: None,
            authentication: ProviderAuthPolicy::Prohibited,
        },
        verification: ArtifactVerification {
            sha256: "a".repeat(64),
            signature: None,
        },
        binaries: vec!["cargo-tool".into()],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
        resolver: "cargo".into(),
        cargo_toolchain: Some("1.85.0-x86_64-unknown-linux-gnu".into()),
    };
    let build = CargoBuildLock {
        tool_id: "cargo-tool".into(),
        crate_name: "cargo-tool".into(),
        version: "1.2.3".into(),
        registry: "https://index.crates.io/".into(),
        checksum: "a".repeat(64),
        toolchain: "1.85.0-x86_64-unknown-linux-gnu".into(),
        scripts: CargoScriptPolicy::Deny,
        build: CargoBuildPolicy::Isolated,
        network: CargoNetworkPolicy::Deny,
    };

    let temp = TempDir::new().unwrap();
    let storage = ToolStorage::project(temp.path());
    let lockfile = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![tool.clone()],
        pins: BTreeMap::new(),
        manager_lock: Some(ManagerLock {
            schema_version: 1,
            manager: "bun".into(),
            manager_version: "1.4.4".into(),
            manager_sha256: "c".repeat(64),
            runtime_version: "1.4.4".into(),
            runtime_archive: None,
            manifest_sha256: "d".repeat(64),
            lockfile_sha256: "e".repeat(64),
            script_policy: ScriptPolicy::Disabled,
            packages: vec![],
        }),
        cargo_build: Some(build.clone()),
    };
    let error = install_locked_tools_in_on(&storage, &lockfile, &Platform::new("linux", "x86_64"))
        .unwrap_err();
    assert!(
        error
            .message
            .contains("Cargo source builds execute compiler inputs")
    );
    assert!(!storage.install_directory().exists());
    assert!(!storage.artifact_directory().exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    let runtime_root = temp.path().join("runtime-data");
    let bun_error =
        super::install_locked_bun_tool(temp.path(), &runtime_root, &[], &lockfile).unwrap_err();
    assert!(
        bun_error
            .message
            .contains("Cargo source builds execute compiler inputs")
    );
    assert!(!runtime_root.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn legacy_npm_lock_installs_from_cached_tarball() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("fixture.tgz");
    write_npm_tarball(&archive, "fixture", "1.0.0");
    let bytes = fs::read(&archive).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let mut tool = package_tool("npm", "fixture", &digest);
    tool.provenance.registry_integrity = Some(format!(
        "sha512-{}",
        STANDARD.encode(Sha512::digest(&bytes))
    ));
    let host = tool.platform.clone();
    let project = temp.path().join("project");
    let storage = project_storage(&project);
    fs::create_dir_all(storage.artifact_directory()).unwrap();
    fs::write(storage.artifact_directory().join(&digest), &bytes).unwrap();
    let lockfile = ToolLockfile {
        schema_version: TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![tool],
        pins: BTreeMap::new(),
        manager_lock: None,
        cargo_build: None,
    };
    let installed = install_locked_tools_in_on(&storage, &lockfile, &host).unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(
        fs::read(installed[0].bin_dir.join("demo")).unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
}

/// **A lock written before the 32-bit ARM width guard existed still installed a 64-bit
/// binary, and the install path is the only place that can now catch it.**
///
/// `LockedTool::platform` is copied from the *host* on every planning path -- explicit
/// `asset:` included -- so it records which machine wrote the lock and nothing about
/// which architecture the URL is. The pre-existing check
/// (`tool.platform != Platform::host()`) therefore passed a lock saying `linux/arm`
/// while pointing at `.../linux_arm64.tar.gz`, and the install completed: bytes
/// fetched, marked executable, receipt written, launcher published, failing only at
/// first run with `Exec format error`. Upgrading does not rewrite an existing lock and
/// nothing told the user to re-lock.
///
/// Every URL below is a real release asset from the 6,178-name corpus, and the hosts
/// are chosen to exercise **both** directions, because an assertion that only ever runs
/// one way is evidence for nothing about the other.
/// **Every runtime's bin directory is asserted, not just the one the enumerator test
/// happens to write a receipt for.**
///
/// A mutation that made `NodeRuntime::bin_dir` return the install root instead of
/// `node-v<version>-<platform>-<arch>/bin` passed the whole suite, because the only
/// enumerator row asserted `go` — the first entry in the table — and the other eight
/// layouts had no row at all. That is the "list member with no test row" defect wearing a
/// table-shaped hat, and it is the same shape as the `armv8l` case: a runtime installed
/// into a real directory and put on `PATH` somewhere else.
///
/// `bin_dir` is a pure function of the root and the version, so it is directly testable
/// without installing anything. **Every expectation below is a literal** — comparing a
/// layout against a helper that calls it proved nothing when a receipt name was checked
/// that way, and the same trap is open here.
#[test]
fn every_runtime_reports_the_bin_directory_its_archive_actually_unpacks_to() {
    use std::path::Path;

    let root = Path::new("/r");
    let version = "1.2.3";

    // (id, the bin directory relative to the install root, on this host)
    //
    // Host-dependent rows are marked, and the host-dependent ones are where the shapes
    // differ: the Windows zip and the Unix tarballs genuinely nest differently, so a test
    // running on one platform cannot assert the other. Those are asserted structurally
    // below instead of pretended to.
    let expected: &[(&str, &str)] = &[
        ("go", "go/bin"),
        (
            "python",
            if cfg!(windows) {
                "python"
            } else {
                "python/bin"
            },
        ),
        ("deno", ""),
        ("uv", if cfg!(windows) { "" } else { "uv-TARGET" }),
        ("dotnet", ""),
        ("rust", "rustup/toolchains/1.2.3-TARGET/bin"),
        ("odin", "PROBED"),
        ("zig", "zig-ARCH-OS-1.2.3"),
        ("node", "node-v1.2.3-PLATFORM-ARCH/bin"),
        (
            "java",
            if cfg!(target_os = "macos") {
                "1.2.3/Contents/Home/bin"
            } else {
                "1.2.3/bin"
            },
        ),
    ];

    for (id, relative) in expected {
        let layout = RUNTIME_LAYOUTS
            .iter()
            .find(|layout| layout.id() == *id)
            .unwrap_or_else(|| panic!("{id} is missing from the layout table"));
        let bin_dir = layout.bin_dir(root, version);
        let rendered = bin_dir
            .strip_prefix(root)
            .unwrap_or_else(|_| panic!("{id}: bin_dir {bin_dir:?} left its install root"))
            .to_string_lossy()
            .replace('\\', "/");

        // `TARGET`, `PLATFORM`/`ARCH` and `OS` stand for host-dependent spellings, so
        // the row asserts the *structure* and the fixed segments rather than a string
        // that would be false on the other platform.
        let structural = match *relative {
            "uv-TARGET" => {
                if cfg!(windows) {
                    rendered.is_empty()
                } else {
                    rendered.starts_with("uv-") && rendered.split('/').count() == 1
                }
            }
            "rustup/toolchains/1.2.3-TARGET/bin" => {
                let parts: Vec<&str> = rendered.split('/').collect();
                parts.len() == 4
                    && parts[0] == "rustup"
                    && parts[1] == "toolchains"
                    && parts[3] == "bin"
                    && parts[2].starts_with("1.2.3-")
            }
            // Odin probes for the executable rather than computing the path, so with no
            // install present it falls back to the root. The *probe* is the behaviour
            // under test and it needs a real tree; what is asserted here is that it never
            // leaves the install root.
            "PROBED" => bin_dir.starts_with(root),
            "zig-ARCH-OS-1.2.3" => {
                let parts: Vec<&str> = rendered.split('/').collect();
                parts.len() == 1 && parts[0].starts_with("zig-") && parts[0].ends_with(version)
            }
            "node-v1.2.3-PLATFORM-ARCH/bin" => {
                let parts: Vec<&str> = rendered.split('/').collect();
                let last = if cfg!(windows) { 1 } else { 2 };
                parts.len() == last
                    && parts[0].starts_with("node-v1.2.3-")
                    && (cfg!(windows) || parts[1] == "bin")
            }
            "BUN" => rendered.starts_with("bun-"),
            "" => rendered.is_empty(),
            fixed => rendered == fixed,
        };
        assert!(
            structural,
            "{id}: bin_dir is {rendered:?}, which is not the layout this row states \
             ({relative:?})"
        );
    }

    // **And the table is complete against the resolvers**, because a runtime with a
    // resolver and no layout is a runtime that installs and is then invisible: it never
    // reaches `PATH`, which is the failure this whole change exists to close.
    assert_eq!(
        RUNTIME_LAYOUTS.len(),
        11,
        "the layout table must cover all eleven installed runtimes; found {:?}",
        RUNTIME_LAYOUTS
            .iter()
            .map(|layout| layout.id())
            .collect::<Vec<_>>()
    );
}

/// Bun's archive names are platform-specific and exclude the baseline and musl
/// variants. A host without an exact entry is refused rather than given a
/// nearby CPU baseline.
#[test]
fn bun_targets_only_published_non_baseline_archives() {
    use neoenv_core::tools::Platform;

    let expect = |os: &str, arch: &str, want: Option<(&str, &str)>| {
        assert_eq!(bun_target(&Platform::new(os, arch)), want, "{os}/{arch}");
    };
    expect(
        "linux",
        "x86_64",
        Some(("bun-linux-x64", "bun-linux-x64.zip")),
    );
    expect(
        "linux",
        "aarch64",
        Some(("bun-linux-aarch64", "bun-linux-aarch64.zip")),
    );
    expect(
        "macos",
        "x86_64",
        Some(("bun-darwin-x64", "bun-darwin-x64.zip")),
    );
    expect(
        "macos",
        "aarch64",
        Some(("bun-darwin-aarch64", "bun-darwin-aarch64.zip")),
    );
    expect(
        "windows",
        "x86_64",
        Some(("bun-windows-x64", "bun-windows-x64.zip")),
    );
    expect(
        "windows",
        "aarch64",
        Some(("bun-windows-aarch64", "bun-windows-aarch64.zip")),
    );
    expect("linux", "i686", None);
    expect("linux", "armv7", None);
}

#[test]
fn bun_versions_are_parsed_as_a_whole_and_are_safe_components() {
    for (input, expected) in [
        ("1.4.4", "1.4.4"),
        ("v1.4.4", "1.4.4"),
        ("bun-v1.4.4", "1.4.4"),
        ("1.4", "1.4"),
    ] {
        assert_eq!(parse_bun_version(input).unwrap(), expected, "{input}");
    }
    for malformed in [
        "1",
        "1.4.4-typo",
        "1..4",
        "1.4.",
        "../1.4.4",
        "1.4.4/extra",
        "C:1.4.4",
        "1.4.4 ",
        " 1.4.4",
        "bun-v",
    ] {
        assert!(
            parse_bun_version(malformed).is_err(),
            "{malformed} must be refused before a URL or path"
        );
    }
    assert!(safe_bun_component("1.4.4"));
    assert!(!safe_bun_component("1.4."));
    assert!(!safe_bun_component("../1.4.4"));
    assert!(!safe_bun_component("C:1.4.4"));
}

#[test]
fn the_bun_installer_refuses_an_unsafe_or_unparsable_version_before_network() {
    let temp = TempDir::new().unwrap();
    for version in ["1.4.4-typo", "../1.4.4", "C:1.4.4"] {
        let asset = BunRuntimeAsset {
            version: version.to_owned(),
            url: "https://127.0.0.1:9/never-fetched".to_owned(),
            sha256: "a".repeat(64),
        };
        let error = install_bun_runtime_with_progress(&temp.path().join("bun"), &asset, |_| {})
            .expect_err("unsafe Bun version");
        assert!(
            error.message.contains("invalid Bun version"),
            "{version}: {}",
            error.message
        );
    }
}

#[test]
fn bun_checksums_name_the_exact_archive() {
    let sums = format!(
        "{}  bun-linux-x64.zip\n{}  bun-linux-x64-baseline.zip\n",
        "a".repeat(64),
        "b".repeat(64)
    );
    assert_eq!(
        bun_checksum(&sums, "bun-linux-x64.zip"),
        Some("a".repeat(64))
    );
    assert_eq!(
        bun_checksum(&sums, "bun-linux-x64-baseline.zip").as_deref(),
        Some(&*"b".repeat(64))
    );
    assert_eq!(bun_checksum(&sums, "bun-darwin-x64.zip"), None);
    assert_eq!(
        bun_checksum("not a digest  bun-linux-x64.zip\n", "bun-linux-x64.zip"),
        None
    );
}

#[test]
fn the_bun_layout_points_at_the_platform_directory() {
    use std::path::Path;

    let layout = RUNTIME_LAYOUTS
        .iter()
        .find(|layout| layout.id() == "bun")
        .expect("bun layout");
    let root = Path::new("/data/bun/1.4.4");
    let directory = bun_target(&neoenv_core::tools::Platform::host())
        .expect("Bun supports the test host")
        .0;
    assert_eq!(layout.receipt(), ".neoenv-bun-sha256");
    assert_eq!(layout.bin_dir(root, "1.4.4"), root.join(directory));
    assert_eq!(bun_binary_directory(root), root.join(directory));
}

/// Adoptium's architecture and OS spellings are not Rust's.
///
/// The table is asserted in both directions: every supported host maps to a
/// spelling Adoptium publishes, and a host this project does not build for is
/// refused rather than silently approximated. A wrong `x86_64` → `x64` mapping
/// is not a compile error and not a 404 for every request — it produces a URL
/// Adoptium rejects, which this code would then report as "not published".
#[test]
fn java_targets_only_the_platforms_adoptium_publishes() {
    use neoenv_core::tools::Platform;

    let expect = |os: &str, arch: &str, want: Option<(&str, &str)>| {
        assert_eq!(
            java_target(&Platform::new(os, arch)),
            want,
            "Java target for {os}/{arch}"
        );
    };

    expect("linux", "x86_64", Some(("linux", "x64")));
    expect("linux", "aarch64", Some(("linux", "aarch64")));
    expect("macos", "x86_64", Some(("mac", "x64")));
    expect("darwin", "aarch64", Some(("mac", "aarch64")));
    expect("windows", "x86_64", Some(("windows", "x64")));
    expect("windows", "aarch64", Some(("windows", "aarch64")));
    expect("linux", "i686", None);
    expect("linux", "armv7", None);
    expect("freebsd", "x86_64", None);
}

fn adoptium_release(release_name: &str, semver: &str, major: u32) -> AdoptiumRelease {
    let package = |os: &str, arch: &str, name: &str| AdoptiumBinary {
        architecture: arch.to_owned(),
        image_type: "jdk".to_owned(),
        jvm_impl: "hotspot".to_owned(),
        os: os.to_owned(),
        package: AdoptiumPackage {
            checksum: "a".repeat(64),
            link: format!("https://example.test/{name}"),
            name: name.to_owned(),
        },
    };
    AdoptiumRelease {
        release_name: release_name.to_owned(),
        version_data: AdoptiumVersion {
            semver: semver.to_owned(),
            major,
        },
        binaries: vec![
            package("linux", "x64", "OpenJDK-jdk_x64_linux_hotspot.tar.gz"),
            package(
                "linux",
                "aarch64",
                "OpenJDK-jdk_aarch64_linux_hotspot.tar.gz",
            ),
            package("mac", "x64", "OpenJDK-jdk_x64_mac_hotspot.tar.gz"),
            package("mac", "aarch64", "OpenJDK-jdk_aarch64_mac_hotspot.tar.gz"),
            package("windows", "x64", "OpenJDK-jdk_x64_windows_hotspot.zip"),
            package(
                "windows",
                "aarch64",
                "OpenJDK-jdk_aarch64_windows_hotspot.zip",
            ),
            package("linux", "x64", "OpenJDK-jdk_x64_linux_hotspot.tar.gz.json"),
        ],
    }
}

/// A feature request chooses the newest GA release Adoptium returns, and an
/// exact request matches either the archive name or the semver.
///
/// **Both spellings are accepted because both are what a user has.** Adoptium's
/// UI shows `21.0.13+9.0.LTS`; its download directory is `jdk-21.0.13+9`. A
/// resolver that accepted one and silently resolved the other would install a
/// version the user did not name, which is the failure this project treats as
/// worse than a refusal.
#[test]
fn java_release_selection_accepts_the_newest_or_one_exact_release() {
    let releases = vec![
        adoptium_release("jdk-21.0.14+7", "21.0.14+7.0.LTS", 21),
        adoptium_release("jdk-21.0.13+9", "21.0.13+9.0.LTS", 21),
    ];

    let newest = select_java_release(&releases, "21", false, 21).expect("newest");
    assert_eq!(newest.release_name, "jdk-21.0.14+7");

    for requested in ["21.0.13+9", "jdk-21.0.13+9", "21.0.13+9.0.LTS"] {
        let exact = select_java_release(&releases, requested, true, 21)
            .unwrap_or_else(|error| panic!("{requested}: {error}"));
        assert_eq!(exact.release_name, "jdk-21.0.13+9");
    }

    let error = select_java_release(&releases, "21.0.12+9", true, 21)
        .expect_err("a release that is not present must be refused");
    assert!(
        error.message.contains("21.0.12+9") && error.message.contains("java@21"),
        "the refusal must name the request and the actionable alternative: {}",
        error.message
    );

    let empty: Vec<AdoptiumRelease> = Vec::new();
    let error = select_java_release(&empty, "21", false, 21).expect_err("no release");
    assert!(error.message.contains("21"), "{}", error.message);
}

/// The selected package is the host's JDK archive, not a checksum sidecar or a
/// JRE. This is the exact `md5sum`-read-as-a-manifest failure the repository
/// records: a file that is adjacent, plausible, and not the artifact.
#[test]
fn java_binary_selection_requires_the_host_jdk_archive() {
    let release = adoptium_release("jdk-21.0.13+9", "21.0.13+9.0.LTS", 21);

    let linux = select_java_binary(&release, "linux", "x64").expect("linux x64");
    assert_eq!(
        linux.package.name, "OpenJDK-jdk_x64_linux_hotspot.tar.gz",
        "the JSON sidecar beside the archive must not be selected"
    );
    let windows = select_java_binary(&release, "windows", "aarch64").expect("windows");
    assert_eq!(
        windows.package.name,
        "OpenJDK-jdk_aarch64_windows_hotspot.zip"
    );
    let mac = select_java_binary(&release, "mac", "aarch64").expect("mac");
    assert_eq!(mac.package.name, "OpenJDK-jdk_aarch64_mac_hotspot.tar.gz");

    let error = select_java_binary(&release, "linux", "riscv64").expect_err("unsupported");
    assert!(error.message.contains("jdk-21.0.13+9"), "{}", error.message);
}

/// The Adoptium query names the JDK image, the JVM, the vendor and the host.
/// A query that omits one still answers with JSON, so the shape is asserted
/// literally rather than inferred from a successful parse.
#[test]
fn the_java_release_query_names_the_exact_archive_class() {
    assert_eq!(
        java_releases_url(
            "https://api.test/v3/assets/feature_releases",
            21,
            "linux",
            "x64",
            false
        ),
        "https://api.test/v3/assets/feature_releases/21/ga?architecture=x64&image_type=jdk&jvm_impl=hotspot&os=linux&page=0&page_size=1&sort_order=DESC&vendor=eclipse"
    );
    let exact = java_releases_url(
        "https://api.test/v3/assets/feature_releases",
        21,
        "mac",
        "aarch64",
        true,
    );
    assert!(exact.contains("page_size=20"), "{exact}");
    assert!(exact.contains("os=mac"), "{exact}");
}

/// A Java request is parsed as a whole string before any network request.
///
/// `21-typo` used to stop at `21`, look like a feature request, and only fail
/// after Adoptium was asked for a release. A malformed local string is a usage
/// error here, and this test can prove that without a network:
/// `parse_java_request` performs no I/O.
#[test]
fn java_requests_must_be_complete_and_well_formed() {
    let accepted = [
        ("", JavaRequest::Latest),
        ("latest", JavaRequest::Latest),
        ("21", JavaRequest::Feature(21)),
        ("jdk-21.0.13+9", JavaRequest::Exact { feature: 21 }),
        ("21.0.13+9.0.LTS", JavaRequest::Exact { feature: 21 }),
        ("21.0.12.1+1", JavaRequest::Exact { feature: 21 }),
        ("8u462-b08", JavaRequest::Exact { feature: 8 }),
        ("jdk8u462-b08", JavaRequest::Exact { feature: 8 }),
    ];
    for (version, expected) in accepted {
        assert_eq!(
            parse_java_request(version).unwrap_or_else(|error| panic!("{version}: {error}")),
            expected,
            "{version}"
        );
    }

    for malformed in [
        "21-typo",
        "21.0.13+9-typo",
        "21.0.13+",
        "21..13",
        "21.",
        "jdk-",
        "v21",
        "21.0.13+9.0.LTS!",
        "21.0.13+9_typo",
        "8u-b08",
        "8u462-typo",
    ] {
        assert!(
            parse_java_request(malformed).is_err(),
            "{malformed} must be refused before any network call"
        );
    }
}

/// A release name is one ordinary, cross-platform-safe path component.
///
/// Windows drive prefixes, UNC paths, alternate-data-stream colons, reserved
/// device names and trailing dots are refused even on Unix, because the same
/// value may later be used on a host where they are not ordinary names.
#[test]
fn java_release_names_are_strict_single_path_components() {
    for safe in [
        "jdk-21.0.13+9",
        "jdk8u462-b08",
        "21.0.13",
        "jdk-21.0.13+9.0.LTS",
        "jdk_21",
    ] {
        assert!(safe_java_component(safe), "{safe} should be accepted");
    }
    for unsafe_name in [
        "",
        ".",
        "..",
        "...",
        "../escape",
        "..\\escape",
        "/absolute",
        "C:",
        "C:escape",
        "C:\\escape",
        "\\\\server\\share",
        "\\\\?\\C:\\escape",
        "a:b",
        "a/b",
        "a\\b",
        "a*b",
        "a?b",
        "a\"b",
        "a<b",
        "a>b",
        "a|b",
        "a\0b",
        "a\nb",
        "trailing.",
        "trailing ",
        " leading",
        "CON",
        "con.txt",
        "LPT1.log",
        "NUL",
    ] {
        assert!(
            !safe_java_component(unsafe_name),
            "{unsafe_name:?} must be refused as one ordinary path component"
        );
    }
}

/// An existing install is a cache hit only when the receipt names the resolved
/// archive. A directory with a missing or mismatched receipt is a conflict.
#[test]
fn java_existing_install_requires_a_matching_receipt() {
    let temp = TempDir::new().unwrap();
    let sha = "a".repeat(64);
    let version = "jdk-21.0.13+9";

    let good = temp.path().join("good");
    write_java_install(&good, version, Some(&sha));
    assert_eq!(
        java_existing_install(&good, version, &sha).expect("matching install"),
        Some(java_executable_path(
            &good,
            version,
            std::env::consts::OS,
            "java"
        ))
    );

    let missing = temp.path().join("missing-receipt");
    write_java_install(&missing, version, None);
    let error = java_existing_install(&missing, version, &sha).expect_err("missing receipt");
    assert!(
        error
            .message
            .contains("does not match the resolved archive checksum"),
        "{}",
        error.message
    );

    let mismatched = temp.path().join("mismatched-receipt");
    write_java_install(&mismatched, version, Some(&"b".repeat(64)));
    assert!(
        java_existing_install(&mismatched, version, &sha).is_err(),
        "a different receipt must be a conflict"
    );

    let no_binary = temp.path().join("no-binary");
    write_java_install(&no_binary, version, Some(&sha));
    fs::remove_file(java_executable_path(
        &no_binary,
        version,
        std::env::consts::OS,
        "java",
    ))
    .unwrap();
    assert!(
        java_existing_install(&no_binary, version, &sha).is_err(),
        "a receipt without the executable is not a complete install"
    );

    let file = temp.path().join("not-a-directory");
    fs::write(&file, b"x").unwrap();
    assert!(java_existing_install(&file, version, &sha).is_err());

    #[cfg(unix)]
    {
        let target = temp.path().join("symlink-target");
        fs::create_dir_all(&target).unwrap();
        let link = temp.path().join("symlinked-root");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            java_existing_install(&link, version, &sha).is_err(),
            "a symlinked install root must be refused rather than followed"
        );
    }
}

fn write_java_install(root: &Path, version: &str, receipt: Option<&str>) {
    let binary = java_executable_path(root, version, std::env::consts::OS, "java");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    }
    if let Some(receipt) = receipt {
        fs::write(root.join(".neoenv-java-sha256"), receipt).unwrap();
    }
}

/// The installer validates a caller-supplied version before it uses it as a
/// path and before any network request. Some callers can construct
/// `JavaRuntimeAsset` directly, so this boundary cannot rely on the resolver.
#[test]
fn the_java_installer_refuses_an_unsafe_version_before_network() {
    let temp = TempDir::new().unwrap();
    for version in ["../escape", "C:\\escape", "\\\\server\\share", "a/b", "CON"] {
        let asset = JavaRuntimeAsset {
            version: version.to_owned(),
            url: "https://127.0.0.1:9/never-fetched".to_owned(),
            sha256: "a".repeat(64),
        };
        let error = install_java_runtime_with_progress(&temp.path().join("root"), &asset, |_| {})
            .expect_err("unsafe version");
        assert!(
            error.message.contains("invalid Java version"),
            "{version}: {}",
            error.message
        );
    }
}

/// The paths the installer, layout, activation and dispatch use agree for
/// Linux, Windows and a macOS bundle.
#[test]
fn java_home_and_executable_paths_match_each_archive_layout() {
    use std::path::Path;

    let root = Path::new("/data/java/jdk-21.0.13+9");
    let version = "jdk-21.0.13+9";
    assert_eq!(
        java_home_directory_for(root, version, "linux"),
        root.join(version)
    );
    assert_eq!(
        java_home_directory_for(root, version, "windows"),
        root.join(version)
    );
    assert_eq!(
        java_home_directory_for(root, version, "macos"),
        root.join(version).join("Contents").join("Home")
    );
    assert_eq!(
        java_executable_path(root, version, "macos", "java"),
        root.join(version)
            .join("Contents")
            .join("Home")
            .join("bin")
            .join("java")
    );
    assert_eq!(
        java_executable_path(root, version, "windows", "javac"),
        root.join(version).join("bin").join("javac.exe")
    );
    assert_eq!(
        java_home_directory(root, version),
        java_home_directory_for(root, version, std::env::consts::OS)
    );
}

/// Representative archives: each host's real top-level layout is extracted and
/// the executable is found where the shared path helper says it is.
#[test]
fn java_archive_fixtures_place_the_executable_where_the_layout_looks() {
    let temp = TempDir::new().unwrap();
    let version = "jdk-21.0.13+9";

    let linux_archive = temp.path().join("linux.tar.gz");
    fs::write(
        &linux_archive,
        gzip_tar(&[("jdk-21.0.13+9/bin/java", b"#!/bin/sh\n")]),
    )
    .unwrap();
    let linux_root = temp.path().join("linux-root");
    extract_gzip_tar(&linux_archive, &linux_root).unwrap();
    assert!(
        java_executable_path(&linux_root, version, "linux", "java").is_file(),
        "the Linux archive's jdk-*/bin layout must match the helper"
    );

    let mac_archive = temp.path().join("mac.tar.gz");
    fs::write(
        &mac_archive,
        gzip_tar(&[("jdk-21.0.13+9/Contents/Home/bin/java", b"#!/bin/sh\n")]),
    )
    .unwrap();
    let mac_root = temp.path().join("mac-root");
    extract_gzip_tar(&mac_archive, &mac_root).unwrap();
    assert!(
        java_executable_path(&mac_root, version, "macos", "java").is_file(),
        "the macOS bundle's Contents/Home layout must match the helper"
    );

    let windows_archive = temp.path().join("windows.zip");
    let file = fs::File::create(&windows_archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file(
            "jdk-21.0.13+9/bin/java.exe",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(b"MZ").unwrap();
    writer.finish().unwrap();
    let windows_root = temp.path().join("windows-root");
    extract_zip(&windows_archive, &windows_root).unwrap();
    assert!(
        java_executable_path(&windows_root, version, "windows", "java").is_file(),
        "the Windows archive's jdk-*/bin/java.exe layout must match the helper"
    );
}

/// The older root-only `environment` hook still works for an implementor that
/// does not know about versions. `environment_for` delegates to it by default.
#[test]
fn the_root_only_environment_hook_still_works() {
    struct RootOnly;

    impl super::runtimes::RuntimeLayout for RootOnly {
        fn id(&self) -> &'static str {
            "root-only"
        }

        fn receipt(&self) -> &'static str {
            ".receipt"
        }

        fn bin_dir(&self, root: &Path, _version: &str) -> std::path::PathBuf {
            root.to_path_buf()
        }

        fn environment(&self, root: &Path) -> Vec<(String, String)> {
            vec![("ROOT_ONLY".to_owned(), root.display().to_string())]
        }

        fn resolve(
            &self,
            _requested: &str,
            _platform: &neoenv_core::tools::Platform,
        ) -> Result<super::runtimes::ResolvedRuntime, neoenv_core::Diagnostic> {
            Err(neoenv_core::Diagnostic::new(
                neoenv_core::DiagnosticCategory::Internal,
                "TEST",
                "not used",
            ))
        }
    }

    let root = Path::new("/data/root-only/1.0.0");
    assert_eq!(
        RootOnly.environment_for(root, "1.0.0"),
        RootOnly.environment(root),
        "the version-aware hook must delegate to the root-only hook"
    );
}

/// The Java layout reports the same home as the installer and activation path.
#[test]
fn the_java_layout_uses_the_release_directory_and_sets_java_home() {
    use std::path::Path;

    let layout = RUNTIME_LAYOUTS
        .iter()
        .find(|layout| layout.id() == "java")
        .expect("java layout");
    let root = Path::new("/data/java/jdk-21.0.13+9");
    let version = "jdk-21.0.13+9";
    let home = java_home_directory(root, version);

    assert_eq!(layout.receipt(), ".neoenv-java-sha256");
    assert_eq!(layout.bin_dir(root, version), home.join("bin"));
    assert_eq!(
        layout.environment_for(root, version),
        vec![("JAVA_HOME".to_owned(), home.display().to_string())],
        "JAVA_HOME must name the directory that contains bin/, on every host"
    );
    assert_eq!(
        layout.environment(root),
        Vec::<(String, String)>::new(),
        "the old root-only hook keeps its default for existing implementors"
    );
}

/// **Enumeration reports a runtime only when its receipt proves the install completed,
/// and says where its executables and its variables are.**
///
/// Enumeration is what makes an installed runtime reachable from the shell, and it reads a
/// directory tree. The rule that keeps that safe is that **the receipt is the only
/// evidence**: a version directory that exists because an extraction was interrupted, or
/// because a checksum failed, or because a user made it by hand, is invisible — and an
/// invisible runtime is a good outcome, where a visible broken one would put a
/// non-existent `go` at the front of `PATH` for every task in the project.
///
/// The receipt names are what most invites drift, because each runtime's installer writes
/// its own string literal. The loop at the end asserts the receipts are unique across the
/// table and nenv-shaped, which is the only place the enumerator's names and the
/// installers' names can be compared at all.
#[test]
fn a_runtime_is_enumerated_only_when_its_receipt_is_present() {
    let root = tempfile::tempdir().expect("data root");
    let data = root.path();

    // Nothing installed: the normal state of a machine that has never run
    // `nenv global install`, and an empty list rather than an error.
    assert!(
        installed_runtimes(data).is_empty(),
        "an empty data directory must enumerate no runtimes"
    );

    // A version directory with **no receipt** — the interrupted or hand-made case.
    let unreceipted = data.join("go").join("1.22.0");
    std::fs::create_dir_all(&unreceipted).expect("create version directory");
    assert!(
        installed_runtimes(data).is_empty(),
        "a version directory with no receipt must not be reported: {:?}",
        installed_runtimes(data)
    );

    // A file where the executable goes is not a receipt either, and neither is a
    // directory with the right *name* in the wrong place.
    std::fs::write(unreceipted.join("go"), "not a receipt").expect("decoy file");
    assert!(
        installed_runtimes(data).is_empty(),
        "a plain file must not complete an install"
    );

    // With the receipt, it appears — carrying the layout the table claims.
    let receipt = data
        .join("go")
        .join("1.22.0")
        .join(RUNTIME_LAYOUTS[0].receipt());
    std::fs::write(&receipt, format!("{}\n", "a".repeat(64))).expect("write receipt");
    let found = installed_runtimes(data);
    assert_eq!(found.len(), 1, "{found:?}");
    let go = &found[0];
    assert_eq!(
        go.id, "go",
        "the first runtime in the table is the one written"
    );
    assert_eq!(go.version, "1.22.0");
    assert_eq!(
        go.bin_dir,
        data.join("go").join("1.22.0").join("go").join("bin"),
        "the reported bin directory must be the one the SDK tarball actually unpacks to"
    );
    let expected_root = data.join("go").join("1.22.0").display().to_string();
    assert_eq!(
        go.environment
            .iter()
            .find(|(key, _)| key == "GOROOT")
            .map(|(_, value)| value.as_str()),
        Some(expected_root.as_str()),
        "GOROOT must point at the install root, or the toolchain resolves against the \
         user's own"
    );

    // **Every receipt in the table is nenv-shaped and unique.** Two runtimes sharing a
    // receipt name would make enumeration unable to tell them apart, and a rename on one
    // side only would make a runtime permanently invisible with no error anywhere.
    for layout in RUNTIME_LAYOUTS {
        let receipt = layout.receipt();
        assert!(
            receipt.starts_with(".neoenv-")
                && (receipt.ends_with("-sha256") || receipt.ends_with("-sha512")),
            "{}: receipt {receipt:?} is not an nenv receipt name",
            layout.id()
        );
        assert_eq!(
            RUNTIME_LAYOUTS
                .iter()
                .filter(|other| other.receipt() == receipt)
                .count(),
            1,
            "{}: receipt {receipt:?} is shared with another runtime",
            layout.id()
        );
    }
}

#[test]
fn a_lock_whose_artifact_cannot_run_on_the_host_is_refused_before_any_download() {
    let root = tempfile::tempdir().expect("temp dir");
    let storage = ToolStorage::project(root.path());
    let digest = "b".repeat(64);

    // (url, host platform, must be refused)
    for (url, host, refused) in [
        // The bug, in every spelling that carries it.
        (
            "https://example.test/gh_2.101.0_linux_arm64.tar.gz",
            Platform::new("linux", "arm"),
            true,
        ),
        (
            "https://example.test/LocalSend-1.18.0-linux-arm-64.tar.gz",
            Platform::new("linux", "arm"),
            true,
        ),
        (
            "https://example.test/LocalSend-1.18.0-android-arm64v8.apk",
            Platform::new("linux", "arm"),
            true,
        ),
        // The *first* family to need this, so the rule has to cover it: a 64-bit x86
        // artifact for a 32-bit x86 host.
        (
            "https://example.test/gh_2.101.0_linux_amd64.tar.gz",
            Platform::new("linux", "386"),
            true,
        ),
        // **And the direction that must keep working.** A 32-bit artifact on a 64-bit
        // host runs, so refusing it would break an install that works -- including one
        // the user asked for explicitly with `asset:`.
        (
            "https://example.test/jq-linux-armhf",
            Platform::new("linux", "aarch64"),
            false,
        ),
        (
            "https://example.test/alertmanager-0.33.1.linux-armv5.tar.gz",
            Platform::new("linux", "aarch64"),
            false,
        ),
        (
            "https://example.test/jq-linux64",
            Platform::new("linux", "x86_64"),
            false,
        ),
        // A name that states no architecture at all -- the ordinary explicit `url:`
        // case, and what a "the second field must be an arch" check would break.
        (
            "https://example.test/my-company-internal-binary",
            Platform::new("linux", "arm"),
            false,
        ),
    ] {
        let mut tool = package_tool("github-release", "fixture", &digest);
        tool.url = url.into();
        tool.platform = host.clone();
        // A `github-release` lock's provenance is the *asset identity*, and
        // `validate_tool_provenance` requires all three of repository, release id and
        // asset id -- and forbids the registry fields a package-style provider carries.
        // That is what makes this fixture realistic rather than minimal: a lock this
        // project would actually have written, which is the only kind whose
        // architecture claim the check is about.
        tool.provenance.repository = Some("cli/cli".into());
        tool.provenance.release_id = Some(1);
        tool.provenance.asset_id = Some(1);
        tool.provenance.registry_endpoint = None;
        tool.provenance.package = None;
        tool.provenance.registry_integrity = None;
        let lockfile = ToolLockfile {
            schema_version: TOOL_LOCK_SCHEMA_VERSION,
            tools: vec![tool],
            pins: BTreeMap::new(),
            cargo_build: None,
            manager_lock: None,
        };

        let outcome = install_locked_tools_in_on(&storage, &lockfile, &host);
        let message = outcome.err().map(|error| error.to_string());
        let said_too_wide = message
            .as_deref()
            .is_some_and(|text| text.contains("this host cannot execute"));
        if refused {
            let message =
                message.unwrap_or_else(|| panic!("{url} on {} must be refused", host.arch));
            assert!(
                said_too_wide,
                "{url} on a {}/{} host must be refused as too wide, got: {message}",
                host.os, host.arch
            );
            // The message has to say what to do, not only what is wrong. This project
            // exists because a silent wrong install is worse than a refusal.
            assert!(
                message.contains("re-lock"),
                "the refusal must name the remedy, got: {message}"
            );
            assert!(
                !message.contains(&digest),
                "the refusal must not echo the digest, got: {message}"
            );
        } else {
            assert!(
                !said_too_wide,
                "{url} on a {}/{} host runs and must not be refused as too wide: {}",
                host.os,
                host.arch,
                message.unwrap_or_default()
            );
        }
    }
}

/// **The extraction path has the shape the archive actually has, and that is a
/// separate claim from the matrix's.**
///
/// A mutation that rewrote `uv_binary` to look for `root/uv/uv` instead of
/// `root/uv-<target>/uv` passed the whole suite, because the matrix test above checks
/// which *target string* is used and not where inside the extracted tree the executable
/// is expected. Nothing else covers it: the install tests do not extract a real uv
/// archive on the host architecture, and the diagnostic that fires when the path is
/// wrong is "uv archive did not provide uv", which reads like an upstream problem rather
/// than a path bug.
///
/// So the layout is asserted directly, and only for the branch this host takes -- the
/// Windows zip and the Unix tarballs genuinely nest differently, and a test cannot
/// observe the other branch from here.
#[test]
fn the_uv_extraction_path_matches_the_archive_layout() {
    let root = Path::new("/opt/uv");
    let binary = uv_binary(root);
    let name = binary
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the extraction path must name a file");
    if cfg!(windows) {
        // The Windows zip puts the executable at the archive root.
        assert_eq!(binary, root.join("uv.exe"), "windows zip layout");
    } else {
        // The Unix tarballs nest it under their target directory, and that directory is
        // named by the same triple the download URL is built from.
        assert_eq!(name, "uv", "the executable's own name");
        let parent = binary
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .expect("the executable must sit inside a named target directory");
        assert_eq!(
            parent,
            format!("uv-{}", host_target()),
            "the extraction path must nest under the same target the URL names"
        );
        assert_eq!(
            uv_target(&Platform::host()).map(|(target, _)| target),
            Some(host_target()),
            "on this host the matrix and the extraction path must name one target"
        );
    }
}

/// **The uv resolver and the uv extraction path must agree on every published
/// platform, and both are checked against literals rather than against each other.**
///
/// This is the test for a defect that had no test and no symptom anyone would have
/// recognised. `resolve_uv_runtime` built the download URL from one hand-written copy of
/// the target matrix, and `uv_binary` computed the path it looks for the extracted file
/// at from a *second*, separately written copy. Nothing tied them together.
///
/// When they disagree the failure is actively misleading: the install checks
/// `usable_file(&uv_binary(&temporary))` and reports **"uv archive did not provide uv"**,
/// which sends the reader to inspect the archive rather than to look at the path. The
/// message blames the upstream publisher for a bug in this file.
///
/// The two copies had already diverged: `uv_binary` returned early on Windows and then
/// branched on `cfg!(windows)` again inside the triple, so its `*-pc-windows-msvc` arm
/// was unreachable. Clippy cannot see that, because `cfg!` is a bool expression rather
/// than a statement.
///
/// **Every expectation below is a literal.** An earlier version of this test compared the
/// matrix's archive suffix against `uv_extension` -- which is the function the matrix
/// itself calls -- so that row could not fail however wrong the suffix became, and a
/// mutation setting the Windows suffix to `tar.gz` survived it. Comparing a function
/// against its own caller is not a check.
#[test]
fn the_uv_resolver_and_the_extraction_path_agree_on_every_published_platform() {
    // (os, arch, the target uv's release names, the archive it ships)
    for (os, arch, target, suffix) in [
        ("linux", "x86_64", "x86_64-unknown-linux-gnu", "tar.gz"),
        ("linux", "aarch64", "aarch64-unknown-linux-gnu", "tar.gz"),
        ("macos", "x86_64", "x86_64-apple-darwin", "tar.gz"),
        ("macos", "aarch64", "aarch64-apple-darwin", "tar.gz"),
        ("windows", "x86_64", "x86_64-pc-windows-msvc", "zip"),
        ("windows", "aarch64", "aarch64-pc-windows-msvc", "zip"),
    ] {
        let platform = Platform::new(os, arch);
        assert_eq!(
            uv_target(&platform),
            Some((target, suffix)),
            "{os}/{arch}: the download target and archive suffix uv publishes for"
        );
    }

    // **And the extraction path agrees with the matrix on this host.** `host_target` is
    // driven by `cfg!`, so on any given machine this row can only be checked against the
    // architecture it is running on -- which is why the table above carries literals for
    // the rest, and why the macOS arm64 runner is the one that exercises the aarch64 rows
    // of `host_target` itself. Read this row as "these two agree *here*", not as
    // coverage of every target.
    let host = Platform::host();
    let (from_matrix, _) =
        uv_target(&host).unwrap_or_else(|| panic!("uv does not publish for this host"));
    assert_eq!(
        from_matrix,
        host_target(),
        "the resolver's matrix and the extraction path compute different targets for the \
         host, so the install would look for a path the download never produces"
    );

    // **And a platform uv publishes nothing for refuses**, rather than being handed the
    // nearest available build. uv has no 32-bit ARM artifact at all, so the first two rows
    // are the 32-bit-ARM host case: a refusal, not a 64-bit binary. Approximating here is
    // the exact failure this project exists to prevent, and it is silent -- the install
    // succeeds and the binary fails at first run.
    for (os, arch) in [
        ("linux", "arm"),
        ("linux", "armv7l"),
        ("linux", "i686"),
        ("windows", "386"),
        ("freebsd", "x86_64"),
    ] {
        assert_eq!(
            uv_target(&Platform::new(os, arch)),
            None,
            "{os}/{arch} must refuse: uv publishes no such artifact, and approximating \
             would install a binary for the wrong architecture"
        );
        // **And the shared table refuses it too**, not just uv's wrapper. The other
        // three resolvers read the same table, so this is the row that holds *them* to
        // refusing as well -- one of them gaining a 32-bit arm would hand a 32-bit host
        // a 64-bit build, silently.
        assert_eq!(
            rust_target_triple(&Platform::new(os, arch)),
            None,
            "{os}/{arch} must not resolve to any triple: no runtime may approximate one"
        );
    }

    // **The table is the single definition, and this is the row that keeps it one.**
    // It replaces four byte-identical `match` blocks plus two `cfg!` copies; a mutation
    // that reintroduced a second copy in a resolver would not fail anything else, because
    // the resolvers do network I/O and cannot be called from a test.
    for (os, arch, target, _) in [
        ("linux", "x86_64", "x86_64-unknown-linux-gnu", "tar.gz"),
        ("linux", "aarch64", "aarch64-unknown-linux-gnu", "tar.gz"),
        ("macos", "x86_64", "x86_64-apple-darwin", "tar.gz"),
        ("macos", "aarch64", "aarch64-apple-darwin", "tar.gz"),
        ("windows", "x86_64", "x86_64-pc-windows-msvc", "zip"),
        ("windows", "aarch64", "aarch64-pc-windows-msvc", "zip"),
    ] {
        assert_eq!(
            rust_target_triple(&Platform::new(os, arch)),
            Some(target),
            "{os}/{arch}"
        );
    }

    // `macos` and `darwin` are the same platform under two names -- Rust calls it
    // `macos`, the Go toolchain and half the release asset names call it `darwin` --
    // and a resolver that accepted only one would refuse a perfectly good platform. The
    // aliases are part of the table, so they are part of what is asserted.
    for (os, arch) in [("macos", "x86_64"), ("macos", "aarch64")] {
        assert_eq!(
            rust_target_triple(&Platform::new("darwin", arch)),
            rust_target_triple(&Platform::new(os, arch)),
            "darwin and macos must resolve alike"
        );
    }
}

#[test]
fn artifact_plan_is_a_pure_typed_archive_boundary() {
    let mut tool = package_tool("explicit-url", "fixture", &"a".repeat(64));
    for (url, expected) in [
        ("https://example.test/tool.tar.gz", ArtifactLayout::GzipTar),
        ("https://example.test/tool.tgz", ArtifactLayout::GzipTar),
        ("https://example.test/tool.tar.xz", ArtifactLayout::XzTar),
        ("https://example.test/tool.tar", ArtifactLayout::Tar),
        ("https://example.test/tool.zip", ArtifactLayout::Zip),
        ("https://example.test/tool", ArtifactLayout::RawBinary),
    ] {
        tool.url = url.into();
        assert_eq!(
            ArtifactPlan::from_locked_tool(&tool).unwrap().layout,
            expected
        );
    }

    tool.resolver = "npm".into();
    assert_eq!(
        ArtifactPlan::from_locked_tool(&tool).unwrap().layout,
        ArtifactLayout::NpmPackage
    );
    tool.binaries.push("second".into());
    tool.resolver = "explicit-url".into();
    tool.url = "https://example.test/tool.unknown".into();
    assert_eq!(
        ArtifactPlan::from_locked_tool(&tool).unwrap_err().code,
        "NEO520"
    );
}

/// **A query string must not change which layout a URL dispatches to, and the
/// refusal must name the reason that actually applies.**
///
/// The rows below exist because two separate defects lived in this one function
/// and neither was visible from a test:
///
/// - The five layout arms tested `has_suffix` against the **whole lowercased URL**,
///   query included, while `container_url_refused` had already been taught to strip
///   it. So `…/tool.tar.gz?token=abc` dispatched to `RawBinary` — the same silent
///   wrong install the package guard exists to prevent, now for the *decodable*
///   formats. The previous commit fixed the predicate and left the arms, which is
///   what "half-applied" means.
/// - The refusal arm branched on the URL's format, but it is also reached when a
///   declaration simply names two binaries for a plain archive. Those users were
///   told "a distribution package cannot be installed as a tool", and nothing in
///   that sentence was true for them.
#[test]
fn a_queried_url_keeps_its_layout_and_the_refusal_names_the_real_reason() {
    let mut tool = package_tool("explicit-url", "fixture", &"a".repeat(64));

    // The query is kept by `canonical_http_url` and written into the lock verbatim,
    // so these are the shapes a presigned download actually produces.
    for (url, expected) in [
        (
            "https://example.test/tool.tar.gz?token=abc",
            ArtifactLayout::GzipTar,
        ),
        (
            "https://example.test/tool.tgz?sig=1&x=2",
            ArtifactLayout::GzipTar,
        ),
        (
            "https://example.test/tool.tar.xz?Expires=1",
            ArtifactLayout::XzTar,
        ),
        ("https://example.test/tool.tar#frag", ArtifactLayout::Tar),
        (
            "https://example.test/tool.zip?token=abc",
            ArtifactLayout::Zip,
        ),
        (
            "https://example.test/tool?download=1",
            ArtifactLayout::RawBinary,
        ),
    ] {
        tool.url = url.into();
        assert_eq!(
            ArtifactPlan::from_locked_tool(&tool).unwrap().layout,
            expected,
            "{url} must dispatch on its path, not on its query"
        );
    }

    // **Two binaries is a different problem from a package**, and it needs a
    // different sentence.
    //
    // Only the *unrecognized-extension* shape reaches that arm, and the distinction
    // matters: a `.tar.gz` declaring two binaries dispatches to `GzipTar` like any
    // other, because the suffix arms come first and are right to. One report of
    // this defect showed a `.tar.gz` producing the package message, which cannot
    // happen with that match order — so the rows below use the URLs that actually
    // reach the arm, and a `.tar.gz` is asserted to *succeed* here for that reason.
    tool.binaries = vec!["one".into(), "two".into()];
    tool.url = "https://example.test/tool_1.2.3-linux-amd64.tar.gz".into();
    assert_eq!(
        ArtifactPlan::from_locked_tool(&tool).unwrap().layout,
        ArtifactLayout::GzipTar,
        "an archive dispatches on its extension; the binary count is a later problem"
    );
    for url in [
        "https://example.test/tool.unknown",
        "https://example.test/tool",
        "https://example.test/tool?download=1",
    ] {
        tool.url = url.into();
        let message = ArtifactPlan::from_locked_tool(&tool)
            .expect_err("two binaries cannot come out of one unrecognized artifact")
            .to_string();
        assert!(
            message.contains("binaries were declared"),
            "{url} declares two binaries, so the refusal must say that -- got: {message}"
        );
        assert!(
            !message.contains("distribution package"),
            "nothing about {url} makes it a package, and telling a user it is sends \
             them looking for an `asset:` that would not help, got: {message}"
        );
        assert!(
            !message.contains("no decoder"),
            "and there is no compression format involved, got: {message}"
        );
    }

    // And the two reasons that genuinely *are* about the URL still get their own
    // sentences, so the arm above is not simply swallowing everything.
    tool.binaries = vec!["one".into()];
    for url in [
        "https://example.test/restic_0.19.1_linux_amd64.bz2",
        // **The bzip2 *shorthands*, which are the same bytes under different
        // spellings.** `bz2` was in both lists and these were in neither, so the two
        // tables disagreed about one format -- and in the silent direction, for a
        // release (`aristocratos/btop`) that publishes `.tbz` and nothing else.
        //
        // The advice half is what this loop pins. A name in the verdict list but not
        // the decoder list would be refused with "a distribution package cannot be
        // installed as a tool", which is false for a bzip2 blob and sends the user
        // looking for an `asset:` that cannot help. A mutation removing `tbz2` from
        // the advice list survives every other row in the suite.
        "https://example.test/btop-x86_64-linux-musl.tbz",
        "https://example.test/btop-aarch64-linux-musl.tbz2",
        "https://example.test/ollama-linux-amd64.tar.zst",
        "https://example.test/fastfetch-windows-amd64.7z",
    ] {
        tool.url = url.into();
        let message = ArtifactPlan::from_locked_tool(&tool)
            .expect_err("a compressed blob is not a program")
            .to_string();
        assert!(
            message.contains("no decoder"),
            "{url} is a compression format with no decoder here, so the refusal must \
             say that rather than blaming a package, got: {message}"
        );
        assert!(
            !message.contains("distribution package"),
            "and it is not a package, got: {message}"
        );
    }
    tool.url = "https://example.test/gh_2.101.0_linux_amd64.deb".into();
    let package = ArtifactPlan::from_locked_tool(&tool)
        .expect_err("a deb is not a program")
        .to_string();
    assert!(
        package.contains("distribution package") && !package.contains("no decoder"),
        "got: {package}"
    );
}

fn gzip_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let tar = tar_fixture(entries);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn tar_entry_flood_and_oversized_entry_report_their_budget_limits() {
    let temp = TempDir::new().unwrap();
    let flood = tar_fixture(&[("a", b""), ("b", b""), ("c", b"")]);
    let mut budget = small_budget(|limits| limits.archive_entries = 2);
    let error = extract_tar_with_budget(
        Cursor::new(flood),
        &temp.path().join("tar-flood"),
        &mut budget,
    )
    .unwrap_err();
    assert!(error.message.contains("archive entry count limit 2"));

    let oversized = tar_fixture(&[("large", b"1234")]);
    let mut budget = small_budget(|limits| limits.archive_entry_bytes = 3);
    let error = extract_tar_with_budget(
        Cursor::new(oversized),
        &temp.path().join("tar-large"),
        &mut budget,
    )
    .unwrap_err();
    assert!(error.message.contains("archive entry bytes limit 3"));
}

#[test]
fn npm_metadata_and_payload_are_bounded_while_streaming() {
    let temp = TempDir::new().unwrap();
    let package = gzip_tar(&[(
        "package/package.json",
        br#"{"name":"fixture","bin":"cli.js"}"#,
    )]);
    let archive = temp.path().join("package.tgz");
    fs::write(&archive, &package).unwrap();
    let tool = package_tool("npm", "fixture", "a".repeat(64).as_str());
    let mut metadata_budget = ExtractionBudget::new(
        ResourceBudget {
            http_body_bytes: 8,
            ..ResourceBudget::default()
        },
        Some(package.len() as u64),
    );
    let error = super::extract_npm_tarball(
        &archive,
        &temp.path().join("npm-meta"),
        &tool,
        &mut metadata_budget,
    )
    .unwrap_err();
    assert!(
        error.message.contains("buffered archive metadata limit 8"),
        "{}",
        error.message
    );

    let payload = gzip_tar(&[
        (
            "package/package.json",
            br#"{"name":"fixture","bin":"cli.js"}"#,
        ),
        ("package/cli.js", b"1234"),
    ]);
    let archive = temp.path().join("payload.tgz");
    fs::write(&archive, &payload).unwrap();
    let mut payload_budget = ExtractionBudget::new(
        ResourceBudget {
            archive_entry_bytes: 3,
            ..ResourceBudget::default()
        },
        Some(payload.len() as u64),
    );
    let error = super::extract_npm_tarball(
        &archive,
        &temp.path().join("npm-payload"),
        &tool,
        &mut payload_budget,
    )
    .unwrap_err();
    assert!(error.message.contains("archive entry bytes limit 3"));
}

#[test]
fn gem_payload_is_nested_streamed_and_bounded() {
    let temp = TempDir::new().unwrap();
    let data = gzip_tar(&[("bin/demo", b"1234")]);
    let outer = tar_fixture(&[("data.tar.gz", &data)]);
    let archive = temp.path().join("fixture.gem");
    fs::write(&archive, &outer).unwrap();
    let digest = format!("{:x}", Sha256::digest(&outer));
    let tool = package_tool("ruby-gems", "fixture", &digest);
    let mut budget = ExtractionBudget::new(
        ResourceBudget {
            archive_entry_bytes: 3,
            ..ResourceBudget::default()
        },
        Some(outer.len() as u64),
    );
    let error = super::extract_ruby_gem(&archive, &temp.path().join("gem-out"), &tool, &mut budget)
        .unwrap_err();
    assert!(error.message.contains("archive entry bytes limit 3"));
}

#[test]
fn nuget_metadata_is_bounded_before_payload_extraction() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("fixture.nupkg");
    let file = fs::File::create(&archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file(
            "tools/net8.0/any/DotnetToolSettings.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(b"1234").unwrap();
    writer.finish().unwrap();
    let tool = package_tool("dotnet-tool", "fixture", &"a".repeat(64));
    let mut budget = ExtractionBudget::new(
        ResourceBudget {
            http_body_bytes: 3,
            ..ResourceBudget::default()
        },
        Some(fs::metadata(&archive).unwrap().len()),
    );
    let error = super::extract_dotnet_tool_package(
        &archive,
        &temp.path().join("nuget-out"),
        &tool,
        &mut budget,
    )
    .unwrap_err();
    assert!(error.message.contains("buffered archive metadata limit 3"));
}

#[test]
fn failed_quota_extraction_preserves_a_published_install_and_removes_staging() {
    let temp = TempDir::new().unwrap();
    let artifact = temp.path().join("artifact.tar.gz");
    let payload = vec![b'x'; 100_000];
    fs::write(&artifact, gzip_tar(&[("payload", payload.as_slice())])).unwrap();
    let mut tool = package_tool("explicit", "fixture", &"a".repeat(64));
    tool.url = "https://example.test/artifact.tar.gz".into();
    let root = temp.path().join("published");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("sentinel"), b"keep").unwrap();
    let error = publish_install(&artifact, &root, &tool).unwrap_err();
    assert!(error.message.contains("archive expansion ratio limit 100"));
    assert_eq!(fs::read(root.join("sentinel")).unwrap(), b"keep");
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".install.")
    }));
}

#[test]
fn zip_entry_flood_reports_the_shared_entry_budget() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("flood.zip");
    let file = fs::File::create(&archive).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    for name in ["a", "b", "c"] {
        writer.start_file(name, options).unwrap();
        writer.write_all(b"").unwrap();
    }
    writer.finish().unwrap();
    let mut budget = small_budget(|limits| limits.archive_entries = 2);
    let error =
        extract_zip_with_budget(&archive, &temp.path().join("zip-out"), &mut budget).unwrap_err();
    assert!(error.message.contains("archive entry count limit 2"));
}

#[test]
fn archive_ratio_path_and_link_budgets_fail_with_stable_text() {
    let temp = TempDir::new().unwrap();
    let bomb = tar_fixture(&[("bomb", b"123")]);
    let mut ratio = small_budget(|limits| limits.expansion_ratio = 2);
    let error = extract_tar_with_budget(Cursor::new(bomb), &temp.path().join("ratio"), &mut ratio)
        .unwrap_err();
    assert!(error.message.contains("archive expansion ratio limit 2"));

    let long_path = "a".repeat(64);
    let long = tar_fixture(&[(&long_path, b"")]);
    let mut path_budget = small_budget(|limits| limits.archive_path_bytes = 8);
    let error = extract_tar_with_budget(
        Cursor::new(long),
        &temp.path().join("path"),
        &mut path_budget,
    )
    .unwrap_err();
    assert!(error.message.contains("archive path bytes limit 8"));

    let deep_path = (0..129)
        .map(|index| format!("d{index}"))
        .collect::<Vec<_>>()
        .join("/");
    let component_budget = small_budget(|limits| limits.archive_path_components = 128);
    let error = budget_error(
        component_budget
            .check_path(Path::new(&deep_path))
            .unwrap_err(),
    );
    assert!(error.message.contains("archive path components limit 128"));

    let link = {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o644);
        header.set_size(0);
        header.set_path("link").unwrap();
        header.set_link_name("../outside").unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
        builder.into_inner().unwrap()
    };
    let mut link_budget = ExtractionBudget::new(ResourceBudget::default(), None);
    let error = extract_tar_with_budget(
        Cursor::new(link),
        &temp.path().join("link"),
        &mut link_budget,
    )
    .unwrap_err();
    assert!(error.message.contains("link or unsupported entry"));
}

#[test]
fn resolves_release_metadata_from_a_local_http_fixture() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let size = stream.read(&mut request).unwrap();
        assert!(
            std::str::from_utf8(&request[..size])
                .unwrap()
                .starts_with("GET /repos/owner/demo/releases/tags/v1.2.3 HTTP/1.1")
        );
        let body = r#"{"id":42,"tag_name":"v1.2.3","assets":[{"id":7,"name":"demo-linux-x86_64.tar.gz","browser_download_url":"http://example.test/demo.tar.gz"}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let metadata =
        github_metadata_at(&format!("http://{address}"), "owner/demo", "v1.2.3").unwrap();
    server.join().unwrap();
    assert_eq!(metadata.id, 42);
    assert_eq!(metadata.assets[0].id, 7);
}

#[test]
fn gitlab_pinned_release_resolves_from_local_v4_fixture() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let size = stream.read(&mut request).unwrap();
        assert!(
            std::str::from_utf8(&request[..size])
                .unwrap()
                .starts_with("GET /projects/group%2Fdemo/releases/v1.2.3 HTTP/1.1")
        );
        let body = r#"{"tag_name":"v1.2.3","assets":{"links":[{"name":"demo-linux-x86_64.tar.gz","url":"https://example.test/demo.tar.gz"}]}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "group/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GitlabRelease;
    declaration.github_release = None;
    declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
        host: "gitlab.com".into(),
        namespace: "group".into(),
        project: "demo".into(),
        asset: "demo-{os}-{arch}.tar.gz".into(),
        grep: None,
    });
    declaration.version = "v1.2.3".into();
    declaration.sha256 = Some("a".repeat(64));
    let result = super::providers::resolve_gitlab_release_at(
        &declaration,
        &Platform::new("linux", "x86_64"),
        &format!("http://{address}"),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(result.tools[0].provenance.provider, "gitlab-release");
    assert_eq!(result.tools[0].resolved_version, "v1.2.3");
    assert_eq!(result.tools[0].url, "https://example.test/demo.tar.gz");
}

#[test]
fn gitlab_release_refuses_missing_digest_pin_before_network() {
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "group/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GitlabRelease;
    declaration.github_release = None;
    declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
        host: "gitlab.com".into(),
        namespace: "group".into(),
        project: "demo".into(),
        asset: "demo-{os}-{arch}.tar.gz".into(),
        grep: None,
    });
    declaration.version = "v1.2.3".into();
    assert!(matches!(
        super::providers::resolve_gitlab_release(&declaration, &Platform::new("linux", "x86_64")),
        Err(neoenv_core::tools::ToolPlanError::UnpinnedRegistry { .. })
    ));
}

#[test]
fn gitlab_fixture_refuses_duplicate_asset_names() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let size = stream.read(&mut request).unwrap();
        assert!(
            std::str::from_utf8(&request[..size])
                .unwrap()
                .starts_with("GET /projects/group%2Fdemo/releases/v1.2.3 HTTP/1.1")
        );
        let body = r#"{"tag_name":"v1.2.3","assets":{"links":[{"name":"demo-linux-x86_64.tar.gz","url":"https://example.test/a.tar.gz"},{"name":"demo-linux-x86_64.tar.gz","url":"https://example.test/b.tar.gz"}]}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "group/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GitlabRelease;
    declaration.github_release = None;
    declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
        host: "gitlab.com".into(),
        namespace: "group".into(),
        project: "demo".into(),
        asset: "demo-{os}-{arch}.tar.gz".into(),
        grep: None,
    });
    declaration.version = "v1.2.3".into();
    declaration.sha256 = Some("a".repeat(64));
    let error = super::providers::resolve_gitlab_release_at(
        &declaration,
        &Platform::new("linux", "x86_64"),
        &format!("http://{address}"),
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(matches!(
        error,
        neoenv_core::tools::ToolPlanError::AmbiguousAsset { .. }
    ));
}

#[test]
fn gitlab_release_refuses_reordered_glob_matches() {
    for reverse in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            let entries = if reverse {
                r#"{"name":"demo-linux-x86_64-b.tar.gz","url":"https://example.test/b"},{"name":"demo-linux-x86_64-a.tar.gz","url":"https://example.test/a"}"#
            } else {
                r#"{"name":"demo-linux-x86_64-a.tar.gz","url":"https://example.test/a"},{"name":"demo-linux-x86_64-b.tar.gz","url":"https://example.test/b"}"#
            };
            let body = format!(r#"{{"tag_name":"v1.2.3","assets":{{"links":[{entries}]}}}}"#);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let mut declaration = github_declaration(&GithubReleaseDeclaration {
            repository: "group/demo".into(),
            asset: Some("demo-linux-x86_64-*.tar.gz".into()),
            checksum_asset: None,
            grep: None,
            prerelease: false,
            rename: None,
        });
        declaration.provider = ToolProvider::GitlabRelease;
        declaration.github_release = None;
        declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
            host: "gitlab.com".into(),
            namespace: "group".into(),
            project: "demo".into(),
            asset: "demo-linux-x86_64-*.tar.gz".into(),
            grep: None,
        });
        declaration.version = "v1.2.3".into();
        declaration.sha256 = Some("a".repeat(64));
        let error = super::providers::resolve_gitlab_release_at(
            &declaration,
            &Platform::new("linux", "x86_64"),
            &format!("http://{address}"),
        )
        .unwrap_err();
        server.join().unwrap();
        assert!(matches!(
            error,
            neoenv_core::tools::ToolPlanError::AmbiguousAsset { .. }
        ));
    }
}

#[test]
fn github_fixture_checksum_mismatch_refuses_publication() {
    let bytes = b"not an archive";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let checksum_address = address;
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            let (body, content_type): (&[u8], &str) = if request.contains("/checksums.txt") {
                (b"0000000000000000000000000000000000000000000000000000000000000000 demo-linux-x86_64.tar.gz\n", "text/plain")
            } else {
                (bytes, "application/octet-stream")
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: Some("checksums.txt".into()),
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GithubRelease;
    declaration.github_release.as_mut().unwrap().checksum_asset = Some("checksums.txt".into());
    declaration.version = "v1.2.3".into();
    let metadata = GithubReleaseMetadata {
        id: 1,
        tag: "v1.2.3".into(),
        assets: vec![
            GithubReleaseAsset {
                id: 1,
                name: "demo-linux-x86_64.tar.gz".into(),
                url: format!("http://{address}/asset"),
            },
            GithubReleaseAsset {
                id: 2,
                name: "checksums.txt".into(),
                url: format!("http://{checksum_address}/checksums.txt"),
            },
        ],
    };
    let plan = super::providers::plan_resolved_github_release(
        &declaration,
        &Platform::new("linux", "x86_64"),
        &metadata,
        declaration.github_release.as_ref().unwrap(),
    )
    .unwrap();
    let lock = ToolLockfile::from_plan(&plan);
    let root = tempfile::tempdir().unwrap();
    let storage = ToolStorage::project(root.path());
    let error =
        install_locked_tools_in_on(&storage, &lock, &Platform::new("linux", "x86_64")).unwrap_err();
    server.join().unwrap();
    assert!(error.message.contains("SHA-256 mismatch"), "{error}");
    assert!(
        !storage
            .install_directory()
            .join(&lock.tools[0].sha256)
            .exists()
    );
}

#[test]
fn gitlab_fixture_checksum_mismatch_refuses_publication() {
    let bytes = b"not an archive";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            let release_body = format!(
                r#"{{"tag_name":"v1.2.3","assets":{{"links":[{{"name":"demo-linux-x86_64.tar.gz","url":"http://{address}/asset"}}]}}}}"#
            );
            let is_release = String::from_utf8_lossy(&request).contains("/releases/");
            let (body, content_type): (&[u8], &str) = if is_release {
                (release_body.as_bytes(), "application/json")
            } else {
                (bytes, "application/octet-stream")
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "group/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GitlabRelease;
    declaration.github_release = None;
    declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
        host: "gitlab.com".into(),
        namespace: "group".into(),
        project: "demo".into(),
        asset: "demo-{os}-{arch}.tar.gz".into(),
        grep: None,
    });
    declaration.version = "v1.2.3".into();
    declaration.sha256 = Some("0".repeat(64));
    let plan = super::providers::resolve_gitlab_release_at(
        &declaration,
        &Platform::new("linux", "x86_64"),
        &format!("http://{address}"),
    )
    .unwrap();
    let lock = ToolLockfile::from_plan(&plan);
    let root = tempfile::tempdir().unwrap();
    let storage = ToolStorage::project(root.path());
    let error =
        install_locked_tools_in_on(&storage, &lock, &Platform::new("linux", "x86_64")).unwrap_err();
    server.join().unwrap();
    assert!(error.message.contains("SHA-256 mismatch"), "{error}");
    assert!(!storage.install_directory().exists());
}

#[test]
fn gitlab_fixture_path_escape_refuses_before_publication() {
    let mut tar = tar_fixture(&[("inside", b"escape")]);
    tar[..100].fill(0);
    tar[..10].copy_from_slice(b"../outside");
    tar[148..156].fill(b' ');
    let checksum: u64 = tar[..512].iter().map(|byte| u64::from(*byte)).sum();
    let checksum_field = format!("{checksum:06o}\0 ");
    tar[148..156].copy_from_slice(checksum_field.as_bytes());
    let mut check_archive = tar::Archive::new(Cursor::new(&tar));
    assert_eq!(
        check_archive
            .entries()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .unwrap(),
        Path::new("../outside")
    );
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).unwrap();
    let archive = encoder.finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(&archive));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            let release = format!(
                r#"{{"tag_name":"v1.2.3","assets":{{"links":[{{"name":"demo-linux-x86_64.tar.gz","url":"http://{address}/demo-linux-x86_64.tar.gz"}}]}}}}"#
            );
            let body = if request.contains("/releases/") {
                release.as_bytes()
            } else {
                archive.as_slice()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "group/demo".into(),
        asset: Some("demo-{os}-{arch}.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::GitlabRelease;
    declaration.github_release = None;
    declaration.gitlab_release = Some(neoenv_core::tools::GitlabReleaseDeclaration {
        host: "gitlab.com".into(),
        namespace: "group".into(),
        project: "demo".into(),
        asset: "demo-{os}-{arch}.tar.gz".into(),
        grep: None,
    });
    declaration.version = "v1.2.3".into();
    declaration.sha256 = Some(digest);
    let plan = super::providers::resolve_gitlab_release_at(
        &declaration,
        &Platform::new("linux", "x86_64"),
        &format!("http://{address}"),
    )
    .unwrap();
    let lock = ToolLockfile::from_plan(&plan);
    let root = tempfile::tempdir().unwrap();
    let storage = ToolStorage::project(root.path());
    let error =
        install_locked_tools_in_on(&storage, &lock, &Platform::new("linux", "x86_64")).unwrap_err();
    server.join().unwrap();
    assert!(
        error.message.contains("archive contains unsafe path"),
        "{error}"
    );
    assert!(
        !storage
            .install_directory()
            .join(&lock.tools[0].sha256)
            .exists()
    );
}

#[test]
fn aqua_invalid_revision_is_refused_before_any_fixture_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut declaration = github_declaration(&GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: None,
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    });
    declaration.provider = ToolProvider::Aqua;
    declaration.url = None;
    declaration.sha256 = None;
    declaration.aqua = Some(neoenv_core::tools::AquaDeclaration {
        endpoint: format!("http://{address}"),
        registry_revision: "../../outside".into(),
        package: "owner/demo".into(),
        manifest_sha256: "a".repeat(64),
    });
    let error =
        super::providers::resolve_aqua_registry(&declaration, &Platform::new("linux", "x86_64"))
            .unwrap_err();
    assert!(matches!(
        error,
        neoenv_core::tools::ToolPlanError::UnpinnedRegistry { .. }
    ));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[test]
fn prerelease_latest_uses_the_release_list_and_skips_drafts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let size = stream.read(&mut request).unwrap();
        assert!(
            std::str::from_utf8(&request[..size])
                .unwrap()
                .starts_with("GET /repos/owner/demo/releases?per_page=20 HTTP/1.1"),
            "the pre-release path must not request /releases/latest"
        );
        let body = r#"[
            {"id":99,"tag_name":"v2.0.0-rc.1","draft":false,"prerelease":true,"assets":[]},
            {"id":42,"tag_name":"v1.0.0","draft":true,"prerelease":false,"assets":[]}
        ]"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let metadata =
        github_metadata_at_for(&format!("http://{address}"), "owner/demo", "latest", true).unwrap();
    server.join().unwrap();
    assert_eq!(metadata.id, 99);
    assert_eq!(metadata.tag, "v2.0.0-rc.1");
}

#[test]
fn github_global_asset_selection_reports_ambiguous_available_names() {
    let assets = [
        GithubReleaseAsset {
            id: 1,
            name: "demo-linux-amd64.tar.gz".into(),
            url: "https://example.test/demo-linux-amd64.tar.gz".into(),
        },
        GithubReleaseAsset {
            id: 2,
            name: "checksums.txt".into(),
            url: "https://example.test/checksums.txt".into(),
        },
        GithubReleaseAsset {
            id: 3,
            name: "demo-linux-x86_64.zip".into(),
            url: "https://example.test/demo-linux-x86_64.zip".into(),
        },
    ];
    let declaration = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: None,
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let error = select_global_github_asset(
        &assets,
        &declaration,
        &Platform::new("linux", "x86_64"),
        "gh:owner/demo",
    )
    .unwrap_err();
    let ToolPlanError::AssetSelection { reason, assets, .. } = error else {
        panic!("ambiguous GitHub assets must retain their available names");
    };
    assert!(reason.contains("multiple platform binaries or archives"));
    assert_eq!(
        assets,
        [
            "checksums.txt",
            "demo-linux-amd64.tar.gz",
            "demo-linux-x86_64.zip"
        ]
    );
}

#[test]
fn runtime_archive_download_allows_only_its_explicit_five_redirects() {
    let body = "verified runtime archive fixture";
    let digest = sha256(body);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_body = body.to_owned();
    let server = thread::spawn(move || {
        let (mut redirect, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = redirect.read(&mut request).unwrap();
        write!(
            redirect,
            "HTTP/1.1 302 Found\r\nLocation: http://{address}/asset\r\nContent-Length: 0\r\n\r\n"
        )
        .unwrap();
        drop(redirect);

        let (mut asset, _) = listener.accept().unwrap();
        let _ = asset.read(&mut request).unwrap();
        write!(
            asset,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{server_body}",
            server_body.len()
        )
        .unwrap();
    });
    let temporary = TempDir::new().unwrap();
    let destination = temporary.path().join("runtime.archive");

    download_sha256_archive(
        &format!("http://{address}/start"),
        &destination,
        &digest,
        |_, _| {},
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(fs::read_to_string(destination).unwrap(), body);
}

#[test]
fn http_diagnostics_redact_url_userinfo() {
    let error = get_metadata("http://alice:secret@127.0.0.1:1/private?token=value").unwrap_err();
    let diagnostic = error.to_string();
    assert!(!diagnostic.contains("alice"));
    assert!(!diagnostic.contains("secret"));
    assert!(!diagnostic.contains("token"));
    assert!(diagnostic.contains("http://127.0.0.1:1/private"));
}

#[test]
fn provider_http_source_survives_tool_planning() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).unwrap();
        let _ = stream.write_all(b"malformed response\r\n\r\n");
    });
    let tool = ToolDeclaration {
        id: "demo".into(),
        version: "1.0.0".into(),
        provider: ToolProvider::Aqua,
        url: None,
        sha256: None,
        github_release: None,
        aqua: Some(AquaDeclaration {
            endpoint: format!("http://{address}"),
            registry_revision: "a".repeat(40),
            package: "owner/demo".into(),
            manifest_sha256: "b".repeat(64),
        }),
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["demo".into()],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };

    let error = resolve_aqua_registry(&tool, &Platform::new("linux", "x86_64")).unwrap_err();
    server.join().unwrap();
    let diagnostic = error
        .source()
        .and_then(|source| source.downcast_ref::<Diagnostic>())
        .expect("provider diagnostic source");
    assert!(
        diagnostic
            .source()
            .and_then(|source| source.downcast_ref::<neoenv_runtime::transport::HttpError>())
            .is_some()
    );
}

#[test]
fn registry_credentials_never_enter_an_installer_diagnostic() {
    let error = get_metadata(
        "http://registry-user:registry-password@127.0.0.1:1/manifest?access_token=registry-token",
    )
    .unwrap_err();
    let diagnostic = error.to_string();
    for secret in [
        "registry-user",
        "registry-password",
        "registry-token",
        "access_token",
    ] {
        assert!(!diagnostic.contains(secret), "diagnostic leaked {secret}");
    }
}

#[test]
fn resolves_aqua_manifest_from_a_local_pinned_fixture() {
    let body = "package: owner/demo\nassets:\n  - version: 1.2.3\n    os: linux\n    arch: x86_64\n    url: http://artifacts.example.test/demo.tar.gz\n    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let size = stream.read(&mut request).unwrap();
        let request = std::str::from_utf8(&request[..size]).unwrap();
        assert!(request.starts_with(
            "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pkgs/owner/demo/registry.yaml HTTP/1.1"
        ));
        assert!(!request.contains("Authorization:"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let tool = ToolDeclaration {
        id: "demo".into(),
        version: "1.2.3".into(),
        provider: ToolProvider::Aqua,
        url: None,
        sha256: None,
        github_release: None,
        aqua: Some(AquaDeclaration {
            endpoint: format!("http://{address}"),
            registry_revision: "a".repeat(40),
            package: "owner/demo".into(),
            manifest_sha256: sha256(body),
        }),
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["demo".into()],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };
    let plan = resolve_aqua_registry(&tool, &Platform::new("linux", "x86_64")).unwrap();
    server.join().unwrap();
    assert_eq!(
        plan.tools[0].url,
        "http://artifacts.example.test/demo.tar.gz"
    );
    assert_eq!(
        plan.tools[0].provenance.package.as_deref(),
        Some("owner/demo")
    );
}

#[test]
fn resolves_npm_metadata_and_tarball_from_a_local_fixture() {
    let tarball = b"npm fixture tarball";
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(tarball)));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_integrity = integrity.clone();
    let server = thread::spawn(move || {
        for expected in ["GET /demo HTTP/1.1", "GET /demo-1.2.3.tgz HTTP/1.1"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..size]).unwrap();
            assert!(request.starts_with(expected));
            assert!(!request.contains("Authorization:"));
            let body = if expected.contains(".tgz") {
                tarball.to_vec()
            } else {
                format!(r#"{{"versions":{{"1.2.3":{{"name":"demo","version":"1.2.3","bin":"cli.js","dist":{{"tarball":"http://{address}/demo-1.2.3.tgz","integrity":"{server_integrity}"}}}}}}}}"#).into_bytes()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let mut tool = ToolDeclaration {
        id: "demo".into(),
        version: "1.2.3".into(),
        provider: ToolProvider::Npm,
        url: None,
        sha256: None,
        github_release: None,
        aqua: None,
        npm: Some(NpmDeclaration {
            endpoint: format!("http://{address}"),
            package: "demo".into(),
            manager: None,
        }),
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec![],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };
    tool.npm.as_mut().unwrap().manager = Some(neoenv_core::tools::NpmManager {
        name: neoenv_core::tools::NpmManagerName::Bun,
        version: "1.4.4".into(),
        archive_sha256: None,
    });
    let error = resolve_npm_registry(&tool, &Platform::new("linux", "x86_64"))
        .expect_err("selected manager must fail before registry access");
    assert!(error.to_string().contains("bun@1.4.4"));
    assert!(
        error
            .to_string()
            .contains("refusing direct-tarball fallback")
    );
    tool.npm.as_mut().unwrap().manager = None;
    let plan = resolve_npm_registry(&tool, &Platform::new("linux", "x86_64")).unwrap();
    server.join().unwrap();
    assert_eq!(plan.tools[0].binaries, ["demo"]);
    assert_eq!(
        plan.tools[0].provenance.registry_integrity.as_deref(),
        Some(integrity.as_str())
    );
    assert_eq!(
        plan.tools[0].sha256,
        format!("{:x}", Sha256::digest(tarball))
    );
}

#[test]
fn resolves_ruby_gem_from_a_local_fixture_with_archive_sha256() {
    let archive = b"hermetic gem fixture";
    let digest = format!("{:x}", Sha256::digest(archive));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_digest = digest.clone();
    let server = thread::spawn(move || {
        for expected in [
            "GET /api/v1/versions/demo.json HTTP/1.1",
            "GET /gems/demo-1.2.3.gem HTTP/1.1",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..size]).unwrap();
            assert!(request.starts_with(expected));
            assert!(!request.contains("Authorization:"));
            let body = if expected.contains("versions") {
                format!(r#"[{{"name":"demo","number":"1.2.3","platform":"ruby","sha":"{server_digest}"}}]"#).into_bytes()
            } else {
                archive.to_vec()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let tool = ToolDeclaration {
        id: "demo".into(),
        version: "1.2.3".into(),
        provider: ToolProvider::RubyGems,
        url: None,
        sha256: None,
        github_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: Some(RubyGemsDeclaration {
            endpoint: format!("http://{address}"),
            gem: "demo".into(),
        }),
        cargo: None,
        binaries: vec!["demo".into()],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };
    let plan = resolve_ruby_gems(&tool, &Platform::new("linux", "x86_64")).unwrap();
    server.join().unwrap();
    assert_eq!(plan.tools[0].sha256, digest);
    assert_eq!(plan.tools[0].provenance.package.as_deref(), Some("demo"));
}

#[test]
fn resolves_dotnet_tool_package_and_sha512_from_a_local_fixture() {
    let package = b"NuGet fixture package";
    let digest = STANDARD.encode(Sha512::digest(package));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_digest = digest.clone();
    let server = thread::spawn(move || {
        for expected in [
            "GET /v3-flatcontainer/dotnetsay/2.1.7/dotnetsay.2.1.7.nupkg.sha512 HTTP/1.1",
            "GET /v3-flatcontainer/dotnetsay/2.1.7/dotnetsay.2.1.7.nupkg HTTP/1.1",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..size]).unwrap();
            assert!(request.starts_with(expected));
            assert!(!request.contains("Authorization:"));
            let body = if expected.ends_with(".sha512 HTTP/1.1") {
                server_digest.as_bytes()
            } else {
                package
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    let tool = ToolDeclaration {
        id: "dotnetsay".into(),
        version: "2.1.7".into(),
        provider: ToolProvider::DotnetTool,
        url: None,
        sha256: None,
        github_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: Some(DotnetToolDeclaration {
            source: "nuget-v3".into(),
            endpoint: format!("http://{address}/v3-flatcontainer"),
            package: "DotNetSay".into(),
        }),
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["dotnetsay".into()],
        platforms: vec![],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };
    let plan = resolve_dotnet_tool(&tool, &Platform::new("linux", "x86_64")).unwrap();
    server.join().unwrap();
    assert_eq!(
        plan.tools[0].sha256,
        format!("{:x}", Sha256::digest(package))
    );
    assert_eq!(
        plan.tools[0].provenance.registry_integrity.as_deref(),
        Some(format!("sha512-{digest}").as_str())
    );
}

#[test]
fn extracts_only_validated_dotnet_tool_layout_and_writes_direct_launcher() {
    let temporary = TempDir::new().unwrap();
    let package = temporary.path().join("demo.nupkg");
    let file = std::fs::File::create(&package).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    archive
        .start_file("tools/net8.0/any/DotnetToolSettings.xml", options)
        .unwrap();
    archive
            .write_all(b"<DotNetCliTool><Commands><Command Name=\"demo\" EntryPoint=\"demo.dll\" /></Commands></DotNetCliTool>")
            .unwrap();
    archive
        .start_file("tools/net8.0/any/demo.dll", options)
        .unwrap();
    archive.write_all(b"managed assembly").unwrap();
    archive.finish().unwrap();
    let digest = "a".repeat(64);
    let tool = LockedTool {
        id: "demo".into(),
        resolved_version: "1.0.0".into(),
        url: "http://example.test/demo.nupkg".into(),
        platform: Platform::new("linux", "x86_64"),
        sha256: digest.clone(),
        provenance: ToolProvenance {
            provider: "dotnet-tool".into(),
            immutable_id: "nuget:demo/version:1.0.0/sha512:fixture".into(),
            repository: None,
            release_id: None,
            asset_id: None,
            registry_endpoint: Some("http://example.test/v3-flatcontainer".into()),
            registry_revision: None,
            manifest_sha256: None,
            package: Some("demo".into()),
            registry_integrity: Some("sha512-fixture".into()),
            declaration_sha256: None,
            authentication: ProviderAuthPolicy::Prohibited,
        },
        verification: ArtifactVerification {
            sha256: digest,
            signature: None,
        },
        binaries: vec!["demo".into()],
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
        resolver: "dotnet-tool".into(),
        cargo_toolchain: None,
    };
    let mut budget = extraction_budget(&package).unwrap();
    extract_dotnet_tool_package(&package, temporary.path(), &tool, &mut budget).unwrap();
    assert!(
        temporary
            .path()
            .join("payload/tools/net8.0/any/demo.dll")
            .is_file()
    );
    let launcher = std::fs::read_to_string(temporary.path().join("bin/demo")).unwrap();
    assert!(launcher.contains("dotnet"));
    assert!(launcher.contains("payload/tools/net8.0/any/demo.dll"));
}

/// A minimal `github-release` declaration, so the two tests below state only
/// what they are about. Built from the full field list rather than a
/// `..Default::default()`, because `ToolDeclaration` has no `Default` and a
/// partial one would be a second thing to keep in step.
fn github_declaration(github: &GithubReleaseDeclaration) -> ToolDeclaration {
    ToolDeclaration {
        id: "gh:owner/demo".into(),
        version: "1.0.0".into(),
        provider: ToolProvider::GithubRelease,
        url: None,
        sha256: None,
        github_release: Some(github.clone()),
        gitlab_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: vec!["demo".into()],
        binpath: None,
        bindir: None,
        platforms: Vec::new(),
        declaration_source: SourceSpan::new("neoenv.yaml".into(), 1, 1),
    }
}

/// The installer must choose the asset by the *same* rule the planner does,
/// including a per-platform override.
///
/// It used to select the asset itself from the declaration's keys only. A
/// `linux-x86_64: {asset: "custom.tar.gz"}` was honored by `tool plan` and
/// invisible here, so `tool plan` named one artifact and `tool install` fetched
/// another. Nothing reported it: both calls succeeded, on different files.
#[test]
fn the_installers_asset_choice_matches_the_planners_including_overrides() {
    let assets = [
        GithubReleaseAsset {
            id: 1,
            name: "demo-linux-amd64.tar.gz".into(),
            url: "https://example.test/from-platform.tar.gz".into(),
        },
        GithubReleaseAsset {
            id: 2,
            name: "custom.tar.gz".into(),
            url: "https://example.test/from-override.tar.gz".into(),
        },
    ];
    let github = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: None,
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let platform = Platform::new("linux", "x86_64");

    // With no override, both sides pick the platform match.
    let declaration = ToolDeclaration {
        platforms: Vec::new(),
        ..github_declaration(&github)
    };
    let chosen = super::providers::effective_asset(&declaration, &github, &platform).unwrap();
    assert_eq!(chosen, None, "no asset is declared at the top level");
    let selected = super::select_github_asset(
        &assets,
        chosen,
        super::providers::effective_grep(&declaration, &github, &platform).unwrap(),
        &platform,
        "gh:owner/demo",
    )
    .unwrap();
    assert_eq!(selected.id, 1, "the platform match");

    // With a per-platform override, the installer must see it too.
    let scoped = ToolDeclaration {
        platforms: vec![neoenv_core::tools::PlatformOverride {
            platform: neoenv_core::tools::PlatformSelector {
                os: Some("linux".into()),
                arch: Some("x86_64".into()),
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: Some("custom.tar.gz".into()),
            grep: None,
            rename: None,
        }],
        ..github_declaration(&github)
    };
    let chosen = super::providers::effective_asset(&scoped, &github, &platform).unwrap();
    assert_eq!(
        chosen,
        Some("custom.tar.gz"),
        "the override's asset must reach the installer"
    );
    let selected = super::select_github_asset(
        &assets,
        chosen,
        super::providers::effective_grep(&scoped, &github, &platform).unwrap(),
        &platform,
        "gh:owner/demo",
    )
    .unwrap();
    assert_eq!(
        selected.id, 2,
        "the override's asset, not the platform match"
    );
}

/// Two overrides that both match the platform mean the file does not say which
/// artifact this platform gets. Picking one would install something nobody
/// named, so it is an error.
#[test]
fn two_matching_overrides_are_refused_rather_than_one_being_picked() {
    let github = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let platform = Platform::new("linux", "x86_64");
    let override_at =
        |os: Option<&str>, arch: Option<&str>, asset: &str| neoenv_core::tools::PlatformOverride {
            platform: neoenv_core::tools::PlatformSelector {
                os: os.map(str::to_owned),
                arch: arch.map(str::to_owned),
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: Some(asset.into()),
            grep: None,
            rename: None,
        };
    // An exact match and an os-only match are not ambiguous: the exact one wins,
    // which is the planner's documented precedence.
    let scoped = ToolDeclaration {
        platforms: vec![
            override_at(Some("linux"), None, "by-os.tar.gz"),
            override_at(Some("linux"), Some("x86_64"), "exact.tar.gz"),
        ],
        ..github_declaration(&github)
    };
    assert_eq!(
        super::providers::effective_asset(&scoped, &github, &platform).unwrap(),
        Some("exact.tar.gz")
    );
    // An OS-only override applies when there is no exact one. Collecting every
    // tier together and counting them made an exact-plus-OS-only pair ambiguous,
    // and also meant an OS-only override on its own was found only by luck of
    // ordering.
    let os_only = ToolDeclaration {
        platforms: vec![override_at(Some("linux"), None, "by-os.tar.gz")],
        ..github_declaration(&github)
    };
    assert_eq!(
        super::providers::effective_asset(&os_only, &github, &platform).unwrap(),
        Some("by-os.tar.gz"),
        "an OS-only override applies when nothing matches the architecture"
    );
    // And an override for a different OS does not apply here, so the
    // declaration's own asset is the fallback.
    let other_os = ToolDeclaration {
        platforms: vec![override_at(Some("darwin"), None, "elsewhere.tar.gz")],
        ..github_declaration(&github)
    };
    assert_eq!(
        super::providers::effective_asset(&other_os, &github, &platform).unwrap(),
        Some("demo.tar.gz"),
        "another OS's override must not apply"
    );

    // Two that both match exactly is a file that names two artifacts.
    let ambiguous = ToolDeclaration {
        platforms: vec![
            override_at(Some("linux"), Some("x86_64"), "one.tar.gz"),
            override_at(Some("linux"), Some("x86_64"), "two.tar.gz"),
        ],
        ..github_declaration(&github)
    };
    let error = super::providers::effective_asset(&ambiguous, &github, &platform)
        .expect_err("two matching overrides must not be resolved by picking one");
    assert!(
        matches!(error, ToolPlanError::AmbiguousPlatformOverride { .. }),
        "{error}"
    );
}

/// The global path must not be judged by the *ordinary* path's rules.
///
/// `resolve_github_release` computed the override-aware asset selection
/// unconditionally, before the `if global_request`, and only the `else` used the
/// result. The global branch never consults a platform override at all, so
/// `tool install --global` failed with `MissingAsset` -- or
/// `AmbiguousPlatformOverride` -- on a declaration `tool plan` accepts. Both calls
/// succeeded on different inputs, and the error came from a value that was then
/// discarded.
///
/// Served from a loopback fixture, because the branch is only reachable after the
/// provider has resolved a tag, and the only other way to reach it is the public
/// network.
/// The global branch must not be judged by the *ordinary* branch's asset rule.
///
/// `resolve_github_release` computed the override-aware selection unconditionally,
/// before the `if global_request`, and only the `else` used the result. The global
/// branch never consults a platform override, so `tool install --global` failed
/// with `MissingAsset` -- or `AmbiguousPlatformOverride` -- on a declaration
/// `tool plan` accepts. Both calls succeeded on different inputs, and the error
/// came from a value that was then discarded.
///
/// Reached through [`plan_resolved_github_release`] rather than the fetching
/// wrapper, so no network and no process-wide environment variable is involved.
/// The branch is chosen by the declaration's *source path* (`global:`), which is
/// the real mechanism.
/// The two branches select assets by different rules, and the difference is
/// deliberate.
///
/// The *selection* step of the global branch reads the declaration's own keys
/// only. The ordinary branch reads the matching platform override, so `tool plan`
/// and `tool install` agree on what to fetch. An earlier version computed the
/// ordinary selection unconditionally, for both, so `tool install --global` failed
/// with `MissingAsset` on a declaration `tool plan` accepts -- and the error came
/// from a value that was then discarded.
///
/// Note what this does *not* claim: the global *plan* still applies an override's
/// `url`, `sha256`, and `binaries`, because it ends by handing the declaration to
/// the planner. Only the asset selection differs. A test that asserted the global
/// branch ignores overrides entirely would be wrong, and was.
#[test]
fn the_two_branches_select_the_asset_by_different_rules() {
    let platform = Platform::new("linux", "x86_64");
    let assets = vec![GithubReleaseAsset {
        id: 7,
        name: "demo-linux-x86_64.tar.gz".into(),
        url: "https://example.test/demo.tar.gz".into(),
    }];
    let github = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo-linux-x86_64.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    // An override naming an asset the release does not publish.
    let override_ = PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
        },
        url: None,
        sha256: None,
        binaries: None,
        binpath: None,
        bindir: None,
        asset: Some("does-not-exist.tar.gz".into()),
        grep: None,
        rename: None,
    };
    let declaration = ToolDeclaration {
        platforms: vec![override_],
        ..github_declaration(&github)
    };

    // The global selector reads the declaration's own keys, so it resolves.
    let global =
        super::providers::select_global_github_asset(&assets, &github, &platform, "gh:owner/demo")
            .expect("the global selector reads the declaration, not the override");
    assert_eq!(global.id, 7);

    // The ordinary selector honors the override, and reports the missing asset.
    let ordinary = super::providers::effective_asset(&declaration, &github, &platform)
        .expect("one matching override is not ambiguous");
    assert_eq!(ordinary, Some("does-not-exist.tar.gz"));
    let error = super::select_github_asset(
        &assets,
        ordinary,
        super::providers::effective_grep(&declaration, &github, &platform).unwrap(),
        &platform,
        "gh:owner/demo",
    )
    .expect_err("the ordinary selector honors the override");
    assert!(
        matches!(error, ToolPlanError::AssetSelection { .. }),
        "{error}"
    );

    // The declaration itself is otherwise well formed, so the global success is
    // not passing because the whole thing was invalid.
    assert_eq!(
        declaration
            .github_release
            .as_ref()
            .map(|g| g.repository.as_str()),
        Some("owner/demo")
    );
}

/// The global branch's plan must not re-select what its own selection ignored.
///
/// The global selection deliberately reads the *declaration's* asset, but the
/// planner at the end of the same function reads the *override's*. So a global
/// install whose override names an asset the release does not publish selected an
/// asset successfully and then failed at the planning step, re-selecting the
/// override's name. Clearing the override's `asset`/`grep` in the normalization is
/// what makes the two halves agree.
///
/// The override's `url`, `sha256`, and `binaries` are deliberately *not* cleared:
/// the planner applies those on both branches, and they are not asset selectors.
#[test]
fn a_global_plan_does_not_reselect_what_its_own_selection_ignored() {
    let platform = Platform::new("linux", "x86_64");
    let metadata = GithubReleaseMetadata {
        id: 42,
        tag: "v1.2.3".into(),
        assets: vec![GithubReleaseAsset {
            id: 7,
            name: "demo-linux-x86_64.tar.gz".into(),
            url: "https://example.test/demo.tar.gz".into(),
        }],
    };
    let github = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo-linux-x86_64.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    // One override naming an asset the release does not publish -- so a
    // re-selection would fail loudly rather than quietly picking something.
    //
    // Deliberately *one*. Two overrides matching the same platform are ambiguous
    // for `url` and `sha256` as well as for the asset, and the planner reports
    // that on both branches: the global branch does not get to skip it, because
    // the override still supplies values the plan needs. That is a malformed
    // declaration rather than a branch difference.
    // A `url` and a `binaries` list on the same override: the planner applies
    // those on *both* branches, so clearing them along with the asset selectors
    // would silently change what a global install downloads and what it links.
    // Asserted below, because the clearing loop and the fields it must not touch
    // are one edit apart.
    let missing = PlatformOverride {
        platform: PlatformSelector {
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
        },
        url: Some("https://example.test/override.tar.gz".into()),
        sha256: None,
        binaries: Some(vec!["demo".into(), "demo-helper".into()]),
        binpath: None,
        bindir: None,
        asset: Some("does-not-exist.tar.gz".into()),
        grep: None,
        rename: None,
    };
    let base = ToolDeclaration {
        version: "v1.2.3".into(),
        sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()),
        binaries: vec!["demo".into()],
        ..github_declaration(&github)
    };
    let global = ToolDeclaration {
        // `global:` is what selects the branch, exactly as in production.
        declaration_source: SourceSpan::new("global:demo".into(), 1, 1),
        platforms: vec![missing],
        ..base
    };
    let plan =
        super::providers::plan_resolved_github_release(&global, &platform, &metadata, &github)
            .expect("the global plan must not re-select what its own selection ignored");
    assert_eq!(plan.tools[0].url, "https://example.test/demo.tar.gz");
    // The binaries survive, because they are not an asset selector and the planner
    // applies them on both branches. The override's `url` does not apply here --
    // a direct URL is the top-level form's job, and a per-platform one on a release
    // entry is refused at parse time -- but the binaries are the planner's, and
    // clearing them would silently change what a global install links.
    assert_eq!(
        plan.tools[0].binaries,
        vec!["demo".to_owned(), "demo-helper".to_owned()],
        "the override's binaries must survive the global normalization"
    );
}

/// The ordinary branch's selection is reachable without a network fetch.
///
/// It used to be reachable only through `resolve_github_release`, which goes to
/// the network first, so the branch that `tool plan` and `tool install` must agree
/// on had no test of its own.
#[test]
fn the_ordinary_branch_honors_a_platform_override_without_a_network() {
    let platform = Platform::new("linux", "x86_64");
    let metadata = GithubReleaseMetadata {
        id: 42,
        tag: "v1.2.3".into(),
        assets: vec![
            GithubReleaseAsset {
                id: 7,
                name: "demo-linux-x86_64.tar.gz".into(),
                url: "https://example.test/from-release.tar.gz".into(),
            },
            GithubReleaseAsset {
                id: 8,
                name: "custom.tar.gz".into(),
                url: "https://example.test/from-override.tar.gz".into(),
            },
        ],
    };
    let github = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: None,
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let declaration = ToolDeclaration {
        // The tag has to match, or the planner reports a missing asset and the
        // override is never consulted.
        version: "v1.2.3".into(),
        sha256: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()),
        binaries: vec!["demo".into()],
        platforms: vec![PlatformOverride {
            platform: PlatformSelector {
                os: Some("linux".into()),
                arch: Some("x86_64".into()),
            },
            url: None,
            sha256: None,
            binaries: None,
            binpath: None,
            bindir: None,
            asset: Some("custom.tar.gz".into()),
            grep: None,
            rename: None,
        }],
        ..github_declaration(&github)
    };
    let plan =
        super::providers::plan_resolved_github_release(&declaration, &platform, &metadata, &github)
            .expect("the override's asset must be what gets planned");
    assert_eq!(
        plan.tools[0].url,
        "https://example.test/from-override.tar.gz"
    );
}

/// The two sidecar rules must stay *different*, and the checksum one must stay
/// narrow.
///
/// Its caller collects every asset the rule accepts and refuses when there is more
/// than one. Delegating it to the artifact rule's negation -- which is the
/// obvious de-duplication, and which this crate did for one commit -- made a
/// signature count as a digest candidate, so a `GoReleaser` release publishing
/// `checksums.txt` *and* `*.tar.gz.sig` (cosign is the default) had two
/// candidates for the same digest and every `tool install --global` of such a
/// tool failed with "multiple checksum assets were found".
///
/// No fixture in this file had a signature next to a checksum asset, which is why
/// 1125 tests passed with the regression in place.
#[test]
fn a_signature_beside_a_checksum_asset_does_not_make_the_digest_ambiguous() {
    let assets = [
        GithubReleaseAsset {
            id: 1,
            name: "demo-linux-x86_64.tar.gz".into(),
            url: "https://example.test/demo.tar.gz".into(),
        },
        GithubReleaseAsset {
            id: 2,
            name: "checksums.txt".into(),
            url: "https://example.test/checksums.txt".into(),
        },
        // The default cosign output, and the asset that caused the regression.
        GithubReleaseAsset {
            id: 3,
            name: "demo-linux-x86_64.tar.gz.sig".into(),
            url: "https://example.test/demo.tar.gz.sig".into(),
        },
    ];
    // The *caller*, not a copy of its filter. The previous version of this test
    // re-implemented `.filter(id != selected).filter(is_checksum_asset_name)`
    // inline, which is why the regression it names -- "multiple checksum assets
    // were found" -- is a caller behavior that the test would have passed straight
    // through.
    let declaration = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo-linux-x86_64.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let digest = super::providers::select_global_github_checksum_asset(
        &assets,
        &assets[0],
        &declaration,
        &Platform::new("linux", "x86_64"),
        "gh:owner/demo",
    )
    .expect("a signature beside a checksum asset must not make the digest ambiguous");
    assert_eq!(digest.name, "checksums.txt");
    // And the broad rule still calls it a sidecar for the *artifact* question,
    // which is where the broad rule is the right one. Asserted directly, and
    // against the shared rule rather than a local wrapper, so the next person to
    // re-introduce one has to explain why.
    assert!(!neoenv_core::tools::is_release_artifact(
        "demo-linux-x86_64.tar.gz.sig"
    ));
    assert!(neoenv_core::tools::is_release_artifact(
        "demo-linux-x86_64.tar.gz"
    ));
}

/// **Two real digest assets, neither declared.** `checksums.txt` *and*
/// `demo-linux-x86_64.tar.gz.sha256` are both digests, so the caller's
/// exactly-one rule refuses this release.
///
/// That refusal is the documented policy, not a bug -- there is no lock yet to
/// record a choice, and picking one of two digests silently is the outcome this
/// profile exists to prevent. The user's way out is a declared `checksum_asset:`,
/// and the row below shows the declared case resolving on both paths. This test
/// exists because an earlier version of the doc claimed the two paths "differ only
/// in what to do with more than one" -- which was false, and this pair is the
/// concrete case that made it false.
#[test]
fn two_undeclared_digest_assets_are_refused_and_the_declared_one_resolves() {
    let assets = [
        GithubReleaseAsset {
            id: 1,
            name: "demo-linux-x86_64.tar.gz".into(),
            url: "https://example.test/demo.tar.gz".into(),
        },
        GithubReleaseAsset {
            id: 2,
            name: "checksums.txt".into(),
            url: "https://example.test/checksums.txt".into(),
        },
        GithubReleaseAsset {
            id: 3,
            name: "demo-linux-x86_64.tar.gz.sha256".into(),
            url: "https://example.test/demo.tar.gz.sha256".into(),
        },
    ];
    let platform = Platform::new("linux", "x86_64");
    let base = GithubReleaseDeclaration {
        repository: "owner/demo".into(),
        asset: Some("demo-linux-x86_64.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    let refused = super::providers::select_global_github_checksum_asset(
        &assets,
        &assets[0],
        &base,
        &platform,
        "gh:owner/demo",
    )
    .expect_err("two undeclared digests must not be guessed between");
    let message = refused.to_string();
    assert!(
        message.contains("multiple checksum assets were found"),
        "the refusal must name the problem and list the candidates, got: {message}"
    );
    assert!(
        message.contains("checksums.txt") && message.contains("demo-linux-x86_64.tar.gz.sha256"),
        "and it must show the user both options, got: {message}"
    );
    // **And it must say what to do about it.** Listing the candidates without naming
    // the key leaves the user to guess between two spellings, which is the work the
    // refusal exists to avoid. `mikefarah/yq` publishes five checksum-shaped names,
    // so a release with more than one digest candidate is ordinary rather than
    // pathological, and the one-line fix is the only useful thing to print.
    assert!(
        message.contains("checksum_asset:"),
        "the refusal must name the one-line fix, got: {message}"
    );

    // The way out. The declared name is honored whatever else the release carries,
    // so a user who names the digest is never blocked by ambiguity.
    let declared = GithubReleaseDeclaration {
        checksum_asset: Some("checksums.txt".into()),
        ..base.clone()
    };
    let digest = super::providers::select_global_github_checksum_asset(
        &assets,
        &assets[0],
        &declared,
        &platform,
        "gh:owner/demo",
    )
    .expect("a declared checksum asset resolves regardless of what else is published");
    assert_eq!(digest.name, "checksums.txt");

    // And a declared name that is not published is a named failure, not a silent
    // fall-through to "find one for me" -- the same rule that makes a per-platform
    // `url:` refused instead of overridden.
    let absent = GithubReleaseDeclaration {
        checksum_asset: Some("sha512sums.txt".into()),
        ..base
    };
    let error = super::providers::select_global_github_checksum_asset(
        &assets,
        &assets[0],
        &absent,
        &platform,
        "gh:owner/demo",
    )
    .expect_err("a declared digest that is not published must not fall back");
    assert!(
        error
            .to_string()
            .contains("the configured checksum asset name was not found"),
        "got: {error}"
    );
}

/// **`mikefarah/yq`'s release, verbatim.** Five of its eight assets carry a
/// `checksum` part, and the global path requires *exactly one* digest candidate --
/// so before the last-part rule this release was refused with "multiple checksum
/// assets were found" and a list containing `yq_linux_amd64`, the program, beside
/// four other files.
///
/// The rule is that the *last* part must be the word, or a sidecar kind. That
/// recognizes `checksums` alone, which is the file the user wants, and leaves
/// `checksums-bsd`, `checksums_hashes_order`, `checksums.bundle`, and
/// `checksums-bsd.bundle` unrecognized. **The under-match is the fix**: one candidate
/// resolves, five do not, and the alternative -- matching all five -- refuses a
/// release that is not ambiguous at all.
///
/// This is the test that would have caught it, and it is written from the live asset
/// list rather than from an invented name, because every invented name in this file
/// carries a dot-extension and that is exactly what the bug needed.
#[test]
fn a_release_with_five_checksum_shaped_names_still_resolves() {
    // Distinct ids, because the digest selector excludes the *selected artifact* by
    // id. An earlier version of this test gave every asset `id: 1`, which filtered
    // the whole release out and reported "no checksum asset was found" -- a test that
    // looked like it was exercising the rule and was exercising nothing.
    let assets: Vec<GithubReleaseAsset> = [
        "checksums",
        "checksums-bsd",
        "checksums-bsd.bundle",
        "checksums.bundle",
        "checksums_hashes_order",
        "extract-checksum.sh",
        "yq_linux_amd64",
        "yq_linux_amd64.tar.gz",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, name)| GithubReleaseAsset {
        id: index as u64 + 1,
        name: name.into(),
        url: format!("https://example.test/{name}"),
    })
    .collect();
    let platform = Platform::new("linux", "x86_64");
    let declaration = GithubReleaseDeclaration {
        repository: "mikefarah/yq".into(),
        asset: Some("yq_linux_amd64.tar.gz".into()),
        checksum_asset: None,
        grep: None,
        prerelease: false,
        rename: None,
    };
    // The program is found, and it is the archive -- not `yq_linux_amd64`, which
    // carries no digest marker and is the bare binary.
    let artifact = super::providers::select_global_github_asset(
        &assets,
        &declaration,
        &platform,
        "gh:mikefarah/yq",
    )
    .expect("the declared archive must resolve");
    assert_eq!(artifact.name, "yq_linux_amd64.tar.gz");
    // And exactly one digest is found, so the install is not refused.
    let digest = super::providers::select_global_github_checksum_asset(
        &assets,
        artifact,
        &declaration,
        &platform,
        "gh:mikefarah/yq",
    )
    .expect("yq publishes one recognized digest and the install must not be refused");
    assert_eq!(digest.name, "checksums");
    // The program is never offered as a digest, which is the failure that started
    // this: a refusal whose candidate list contained the thing being installed.
    assert!(
        !assets
            .iter()
            .filter(|a| a.name != "yq_linux_amd64.tar.gz")
            .any(|a| super::providers::is_checksum_asset_name(&a.name) && a.name.contains("yq")),
        "no yq archive may be a digest candidate"
    );
}

/// The coreutils digest spellings, which the list did not have.
///
/// `md5sum`, `sha1sum`, `b2sum`, and `sha3sum` all name a digest file and none of
/// them contains `checksum`, `sha256`, or `sha512` -- so a release whose *only*
/// digest sibling was an `md5sum` file was refused with "no checksum asset was
/// found". A missing sidecar is a refusal on a release that published one, which
/// is the same defect shape as the `sum`/`sums` gap this series has now hit twice:
/// the family was present except for the spellings that actually occur.
///
/// The negative half is the reason this is a list and not the shared rule. A
/// release of the archive plus a `.sig` must stay unambiguous, and `is_release_
/// artifact`'s negation -- which the previous version of this function used and
/// which was reverted once already -- would call the signature a digest.
#[test]
fn a_coreutils_digest_name_is_a_digest_and_a_signature_is_not() {
    for name in [
        "demo-linux-x86_64.tar.gz.md5sum",
        "demo-linux-x86_64.sha1sum",
        "demo-linux-x86_64.sha256sums",
        "demo-linux-x86_64.tar.gz.blake3",
        "demo-linux-x86_64.sha256sum.txt",
        // GoReleaser's `checksum.name_template: "{{ .ArtifactName }}_sums"`, and
        // the dotted spelling of the same. **Both regressed** when this function
        // was narrowed from a substring to a trailing token: the shape
        // `ArtifactName` produces is `foo_1.0.0_linux_amd64_sums`, whose trailing
        // component is `amd64` after the `-` split, and the whole name carries no
        // algorithm anywhere. Core classifies both as sidecars, so a release
        // publishing one was refused with "no checksum asset was found" -- the
        // "too narrow" shape this function was rewritten to fix, reintroduced two
        // commits later. No installer row covered any `*sums` spelling, which is
        // why it shipped.
        "demo-linux-x86_64_sums",
        "demo-linux-x86_64.sums",
        // A manifest glued onto a multi-component version string, the shape every
        // `-<version>-<os>-<arch>` project name has. Core classifies this as a
        // sidecar; before its own fix it did not, and the two halves disagreed out
        // loud on a name ripgrep actually publishes.
        "ripgrep-15.2.0-x86_64-unknown-linux-musl.sha256sums",
        "ripgrep-15.2.0-x86_64-unknown-linux-musl-sha256sums",
        // **The leading form, which a positional guard broke.** `sha256sums.txt` is
        // published by `prometheus/prometheus`, `prometheus/node_exporter`,
        // `prometheus/alertmanager`, `prometheus/pushgateway`,
        // `prometheus/blackbox_exporter`, and `netdata/netdata`; `SHA256SUMS.txt` by
        // `logseq/logseq`; `sha256sum.txt` by `jqlang/jq`, `ollama/ollama`, and
        // `rancher/rancher`. A guard that skipped the *leading* part to protect
        // `md5sum_linux_amd64` made these stop matching, and the install was then
        // refused with the file named as missing **in the same message that listed
        // it as available**. mise spells the pattern `(?i)^sha256sums?\.txt$`, so
        // this was a parity loss as well as a regression.
        "sha256sums.txt",
        "SHA256SUMS.txt",
        "sha256sum.txt",
        "sha512sums.txt",
        "foo_linux_amd64_sha256sums.txt",
        // `B3SUMS` and the short `b3` spelling, which `watchexec/watchexec` publishes
        // 160 times over.
        "B3SUMS",
        "foo_linux_amd64.b3",
        // The `*sum` **singular**, which `astral-sh/uv` publishes verbatim. Both
        // this function and core carry a plural/singular pair, and mutating either
        // one down to `sums` alone passed every test in both crates -- the rule had
        // two spellings and only one was exercised.
        "sha256.sum",
        "foo_linux_amd64.sum",
        // `mikefarah/yq`'s manifests. `checksums` is a digest and the other four
        // names in that release are not, because the *last* part has to be the word
        // (or a sidecar kind). Core draws the same line, which is what leaves that
        // release with exactly one candidate instead of the five it used to offer --
        // and one candidate is what resolves it, since the global path requires
        // exactly one.
        "checksums",
        "checksums.txt",
        "foo-checksums",
        // A marker with a sidecar extension after it, which is the most common
        // spelling there is and which a last-part rule alone misses.
        "foo_linux_amd64.sha512",
        "foo_linux_amd64.sha256.txt",
    ] {
        assert!(
            super::providers::is_checksum_asset_name(name),
            "{name} carries a digest and must be found as one"
        );
        // And the planner agrees it is a sidecar, so the two halves of one
        // provider do not call the same file the artifact and the digest. The
        // asymmetry is deliberate: *everything this calls a digest, core calls a
        // sidecar.* The reverse is not required -- a signature is a sidecar to core
        // and no kind of digest here.
        assert!(
            !neoenv_core::tools::is_release_artifact(name),
            "{name} is a sidecar for the planner too, so the two halves of one \
             provider do not disagree about it"
        );
    }
    for name in [
        "demo-linux-x86_64.tar.gz.sig",
        "demo-linux-x86_64.tar.gz.gpg",
        "demo-linux-x86_64.spdx.json",
        "demo-linux-x86_64.tar.gz",
        // **`mikefarah/yq`'s four non-digests.** These carry a `checksum` part but
        // have a *name* part last, and both halves agree they are not digests --
        // which is what leaves that release with one candidate rather than five. A
        // rule that matched any `checksum` part made the global path refuse it with
        // the very message that now names the one-line fix.
        "checksums-bsd",
        "checksums_hashes_order",
        "checksums.bundle",
        "checksums-bsd.bundle",
        "extract-checksum.sh",
        // **A signature *of* a digest is not a digest.** `go-gitea/gitea` publishes
        // 729 names of this shape across its releases -- `*.sha256.asc` and
        // `*.sigstore.json` -- and a bare-algorithm-anywhere rule made every one a
        // digest candidate, which contradicts this file's own doc ("narrower in one
        // direction: a signature does not"). mise reaches the same place by
        // *penalizing* `.asc`/`.sig` rather than classifying them as checksums.
        "gitea-1.27.3-linux-amd64.sha256.asc",
        "gitea-1.27.3-linux-amd64.sha256.sigstore.json",
        "foo_linux_amd64.sha256.asc",
        "foo_linux_amd64.sha256.sig",
        "foo_linux_amd64.sha256.gpg",
        "foo_linux_amd64.sha256.gpgasc",
        "foo_linux_amd64.sha256.minisig",
        "foo_linux_amd64.sha256.p7s",
        "foo_linux_amd64.sha256.pem",
        "foo_linux_amd64.sha256.pub",
        "foo_linux_amd64.sha256.cert",
        "foo_linux_amd64.sha256.cer",
        "foo_linux_amd64.sha256.crt",
        "foo_linux_amd64.sha512.asc",
        "foo_linux_amd64.sha512.sigstore",
        // A bare marker as the *whole* name is a program, not a manifest. Core
        // decides this from a *list* (`COREOUTSUM_DIGEST_PROGRAMS`) because
        // `md5sum` and `SHA256SUMS` are identical once lowercased; these rows are
        // here because this function decides it by shape, and the two must agree.
        "md5sum",
        "sha1sum",
        "sha256sum",
        "cksum",
        "b2sum",
        "shasum",
        "sum",
        "sha224sum",
        "sha512sum",
        // The BLAKE3 reference implementation's binaries -- which **are** in core's
        // set, added by this commit because adding `b3` for `B3SUMS` made them read
        // as manifests -- and a bare algorithm, which is not.
        "b3sum",
        "blake3sum",
        "blake3",
    ] {
        assert!(
            !super::providers::is_checksum_asset_name(name),
            "{name} is not a digest, and counting it makes every cosign-signed \
             release ambiguous"
        );
    }
}

/// **A tool whose name contains a digest word is a tool, not a digest.**
///
/// This is the defect class three successive versions of `is_checksum_asset_name`
/// got wrong in one direction or the other, and the last version got it wrong
/// *twice* in the same commit that claimed to fix it. Each of these archives was
/// classified as a digest, and the caller's exactly-one rule then refused the
/// install while offering another platform's archive as a checksum candidate --
/// verified end to end through the real caller, not through this function.
///
/// The token-only fallback fixed `md5tool_linux_x86_64.tar.gz` and not these,
/// because a project whose name *is* an algorithm splits into a bare token.
///
/// What finally settles it is not a name at all: **a digest sidecar is never a
/// program or a package.** Every name here ends in `.tar.gz`, and every real
/// manifest ends in `sums`, `sum`, an algorithm name, or `.txt`.
/// **A distribution package is refused on every path, and an explicit `asset:`
/// still gets one.**
///
/// Two separate mechanisms, because either alone leaves the wrong-install
/// direction open:
///
/// - *Selection*: [`is_package_not_program`] keeps a package out of **automatic**
///   selection, so `gh:cli/cli` skips the `.deb` at asset 4 and takes the real
///   `.tar.gz` at asset 6. This is mise's shape — refuse automatically, honor an
///   explicit `asset_pattern`.
/// - *Containment*: `ArtifactPlan` refuses a URL that looks like a container, so a
///   package that reaches the installer anyway becomes a **loud** diagnostic instead
///   of an `ar` blob copied to `bin/gh`, marked executable, receipted and published.
///
/// The containment arm had no row, and removing it changed nothing — the first
/// attempt at a mutation run proved it. It is reachable through the *explicit*
/// `asset:` path, which does not consult the selection rule, and that is the case
/// this test drives.
#[test]
fn an_explicitly_declared_package_is_refused_loudly_rather_than_installed() {
    // The explicit arm honors what the user wrote -- including a name the automatic
    // rule would skip -- and hands it to the installer.
    // A one-asset release, built here rather than borrowed: neoenv-core's
    // `release_with` lives in that crate's test module and is not visible from here.
    let assets = vec![GithubReleaseAsset {
        id: 1,
        name: "gh_2.101.0_linux_amd64.deb".into(),
        url: "https://example.test/gh.deb".into(),
    }];
    let planned = super::select_github_asset(
        &assets,
        Some("gh_2.101.0_linux_amd64.deb"),
        None,
        &Platform::new("linux", "x86_64"),
        "gh:cli/cli",
    )
    .expect("an explicit `asset:` is honored, even a package");
    assert_eq!(planned.name, "gh_2.101.0_linux_amd64.deb");

    // And the installer then refuses it, by name, rather than copying the `ar` blob
    // to `bin/gh` and reporting success.
    let mut locked = package_tool("github-release", "cli/cli", &"a".repeat(64));
    locked.id = "gh:cli/cli".into();
    locked.resolved_version = "2.101.0".into();
    locked.url = planned.url.clone();
    locked.binaries = vec!["gh".into()];
    let error = ArtifactPlan::from_locked_tool(&locked)
        .expect_err("a package must not become a raw binary");
    let message = error.to_string();
    assert!(
        message.contains("unrecognized artifact type") && message.contains("gh.deb"),
        "the refusal must name the artifact it could not use, got: {message}"
    );
    assert!(
        message.contains("asset:"),
        "and it must say what to do instead, got: {message}"
    );
    assert!(
        message.contains("cannot be installed as a tool"),
        "a package's advice is that it is not a tool, got: {message}"
    );
    assert!(
        !message.contains("no decoder"),
        "and a package must not be told there is no decoder for it -- there is, it \
         is `ar`; the two reasons are different and conflating them is a message \
         that lies, got: {message}"
    );

    // **The other reason gets the other sentence, and this is the whole point of
    // splitting them.** For a compression format with no decoder here, "declare
    // `asset:` with an archive" is a dead end: no `asset:` can ever succeed. One
    // sentence for both reasons sent 21 of 933 real selections in a circle, and
    // `gh:restic/restic` has no alternative asset at all on linux -- it publishes
    // `.bz2` for every platform and no `.tar.gz`.
    let mut compressed = package_tool("github-release", "restic/restic", &"b".repeat(64));
    compressed.id = "gh:restic/restic".into();
    compressed.url = "https://example.test/restic_0.19.1_linux_amd64.bz2".into();
    compressed.binaries = vec!["restic".into()];
    let message = ArtifactPlan::from_locked_tool(&compressed)
        .expect_err("a bz2 blob is not a program")
        .to_string();
    assert!(
        message.contains("no decoder"),
        "a format with no decoder here must say so, got: {message}"
    );
    assert!(
        message.contains("no `asset:` can make it installable"),
        "and must not send the user looking for an alternative asset, because there \
         is none that would work, got: {message}"
    );
    assert!(
        message.contains(".tar.gz") && message.contains(".zip"),
        "and must name the formats it can unpack, so the user knows what a release \
         has to look like, got: {message}"
    );
}

/// **Every member of the two lists that mean "this is not a program" is exercised,
/// on the list each rule actually reads.**
///
/// This test exists because a mutation once removed `deb` and the suite stayed
/// green, and the reason it could not fail is the point: the assertions were
/// reading `PROGRAM_EXTENSIONS`, which the containment rule does **not** read.
/// `looks_like_a_container` -- the function an earlier version of this doc claimed
/// was the backstop, and which appears nowhere in the tree -- read that list
/// instead of `UNOPENABLE_EXTENSIONS`, so every assertion was satisfied by a
/// neighbouring constant whether or not the rule existed.
///
/// A mutator that hits the wrong one of two adjacent `&[&str]` constants and a test
/// that reads only one of them agree perfectly, and together they look like
/// coverage. So every membership check below goes through
/// `unopenable_extension_is` / `is_package_not_program`, which are the predicates
/// the rules themselves call, and a missing member turns a loud refusal back into a
/// quiet install -- the expensive direction.
#[test]
#[allow(clippy::too_many_lines)]
fn the_containment_list_is_verified_against_the_packaging_list() {
    // Every packaging extension the selection rule refuses is also one the
    // containment rule catches, so a package cannot be skipped at selection and
    // then accepted at extraction.
    for name in [
        "gh_2.101.0_linux_amd64.deb",
        "tool_1.2.3_linux_amd64.rpm",
        "tool_1.2.3_linux_amd64.apk",
        "tool_1.2.3_windows_amd64.msi",
        "tool_1.2.3_darwin_arm64.dmg",
        "tool_1.2.3_darwin_arm64.pkg",
    ] {
        assert!(
            neoenv_core::tools::is_package_not_program(name),
            "{name} is a package and must be kept out of automatic selection"
        );
        assert!(
            super::archive::container_url_refused(&format!("https://example.test/{name}")),
            "{name} must also be refused by the containment backstop, or it is \
             skipped at selection and accepted at extraction"
        );
    }
    // And the controls: a real archive is neither.
    for name in [
        "gh_2.101.0_linux_amd64.tar.gz",
        "gh_2.101.0_linux_amd64.tar.xz",
        "gh_2.101.0_linux_amd64.zip",
        "tool_1.2.3_linux_amd64.tar",
        // **No `.tar.zst` row, and there must not be one.** An earlier version of
        // this comment claimed "a `.tar.zst` is *not* a package -- the selection rule
        // accepts it" and used that to justify its absence from the control list.
        // Both halves are now false: the selection rule *refuses* `zst` along with
        // the other formats it has no decoder for, so this is a refusal on both
        // halves rather than a disagreement between them. The comment outlived the
        // row it described and then contradicted the code.
        "tool-linux-amd64",
    ] {
        assert!(
            !neoenv_core::tools::is_package_not_program(name),
            "{name} is not a package, so automatic selection must still consider it"
        );
        assert!(
            !super::archive::container_url_refused(&format!("https://example.test/{name}")),
            "{name} must reach the extractor"
        );
    }
    // `deb` is the member a mutation removed, named explicitly rather than only
    // reached through a row another member could satisfy -- **on both tables.** An
    // earlier version asserted it against `PROGRAM_EXTENSIONS`, which the
    // containment backstop does not read, so those five lines would have passed with
    // the backstop deleted. A mutator that hits the neighbouring constant and a
    // test that reads only one of them agree perfectly and together look like
    // coverage.
    assert!(neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&"deb"));
    assert!(neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&"rpm"));
    assert!(neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&"msi"));
    assert!(neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&"dmg"));
    assert!(neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&"pkg"));
    for member in [
        "deb",
        "rpm",
        "msi",
        "dmg",
        "pkg",
        "apk",
        "appx",
        "appxbundle",
        "mpkg",
        "msix",
        "msixbundle",
        "flatpak",
        "ar",
        "zst",
        "bz2",
        "7z",
        "rar",
        "z",
        "lz",
        "lzma",
        "br",
        "sz",
    ] {
        assert!(
            super::archive::unopenable_extension_is(member),
            "{member} must be refused by the containment rule, and it is read from \
             `UNOPENABLE_EXTENSIONS` -- not from `PROGRAM_EXTENSIONS`"
        );
    }
    // **Every member of the list the *advice* reads is also in the list the
    // *verdict* reads** -- and the loop reads the real list rather than restating
    // its members, which is the only form that can fail when a member is added to
    // the wrong one. A hardcoded member list here held while `tbz` and `tbz2` were
    // in one list and not the other, which is exactly the state that let
    // `aristocratos/btop`'s only asset be installed as a raw binary.
    for &member in super::archive::undecodable_extensions() {
        assert!(
            super::archive::has_decoder_advice(member),
            "{member} is in the decoder list, so it must have decoder advice"
        );
        assert!(
            super::archive::unopenable_extension_is(member),
            "{member} has decoder advice and must also have a verdict; a name in one \
             list and not the other is either a silent install or a message that lies"
        );
    }
    // **The four that are openable are still refused**, which is the whole point:
    // `extract_zip_with_budget` *would* unpack a wheel, but nothing sniffs content
    // and the layout arms key on literal suffixes, so a `.whl` matching none of them
    // falls through to `RawBinary`. An earlier version of this test asserted their
    // *absence* from the list, which is the opposite property and cannot detect the
    // regression: absence held, and a compressed blob was installed as an
    // executable. Assert the *verdict* instead, through the predicate a user hits.
    for member in [
        "whl", "gem", "jar", "nupkg", "appimage", "tbz", "tbz2", "ar",
    ] {
        assert!(
            super::archive::unopenable_extension_is(member),
            "{member} has no layout arm that can open it, so treating it as a raw \
             binary installs something that cannot run"
        );
        assert!(
            super::archive::container_url_refused(&format!(
                "https://example.test/tool_1.2.3.{member}"
            )),
            "{member} must be refused end-to-end, not merely present in a list"
        );
    }
    // ...and the archives those formats are *made of* still resolve. This is the
    // control that caught the first version of the rule, which read
    // `PROGRAM_EXTENSIONS` and so refused every `.tar.gz` in existence.
    for member in ["zip", "tar", "tar.gz", "tgz", "tar.xz"] {
        assert!(
            !super::archive::container_url_refused(&format!(
                "https://example.test/tool_1.2.3.{member}"
            )),
            "{member} is an archive this project unpacks"
        );
    }
    // **And the query string, which is how the whole rule was bypassed.**
    // `canonical_http_url` rejects credentials and fragments but keeps the query,
    // and `plan_tools` writes the canonicalized URL into the lock, so a presigned
    // `.deb` arrived with `deb?token=abc` as its last dot-segment and matched
    // nothing. Removing the `rsplit('/')` entirely also survived the suite, so no
    // row pinned that line at all.
    for url in [
        "https://example.test/gh_2.101.0_linux_amd64.deb",
        "https://example.test/gh_2.101.0_linux_amd64.deb?token=abc",
        "https://example.test/gh_2.101.0_linux_amd64.deb#frag",
        "https://example.test/gh_2.101.0_linux_amd64.deb?token=abc&x=1#frag",
        "https://example.test/dir.d/pkg/tool.7z?sig=1",
    ] {
        assert!(
            super::archive::container_url_refused(url),
            "{url} is not openable however it is spelled"
        );
    }
    for url in [
        "https://example.test/gh_2.101.0_linux_amd64.tar.gz",
        "https://example.test/gh_2.101.0_linux_amd64.tar.gz?token=abc",
        "https://example.test/tool",
        "https://example.test/tool?download=1",
    ] {
        assert!(
            !super::archive::container_url_refused(url),
            "{url} is installable however it is spelled"
        );
    }
    // **Case, which was an unenforced contract rather than a handled input.** Every
    // other row in this suite is a lowercase literal, so the predicate being
    // correct only on a lowercased URL was invisible: `.../TOOL.DEB` returned false
    // and no row could fail. It now normalizes internally, so case is a property
    // rather than a promise the caller has to keep.
    for url in [
        "https://example.test/TOOL_1.2.3.DEB",
        "https://example.test/Tool.Deb?token=abc",
        "https://example.test/TOOL_1.2.3.7Z",
    ] {
        assert!(
            super::archive::container_url_refused(url),
            "{url} is not openable whatever case it is written in"
        );
    }
    // **Any dot-segment, not just the last** -- the shape mise's own
    // `is_non_executable_asset` test has, and the reason it is in this rule rather
    // than the selection rule alone. A package marker in the middle of the name is
    // still a package; with a last-segment-only test the `.tar` below wins and the
    // `.pkg` inside it is installed as an executable.
    for url in [
        "https://example.test/dl/tool.pkg.tar",
        "https://example.test/dl/v1.2.3/tool.deb.tar",
        "https://example.test/dir.d/pkg/tool.7z?sig=1",
    ] {
        assert!(
            super::archive::container_url_refused(url),
            "{url} names a package in a non-final segment and must be refused"
        );
    }
    // **And the mirror case**, which is a *false* positive for the same rule: a
    // mirror path whose *directory* happens to be named after a packaging format,
    // with a real archive at the end. The last-segment step is what keeps this
    // installable, and removing it refused this too.
    for url in [
        "https://mirror.example.test/pkg/v1/tool-1.2.3-linux-amd64.tar.gz",
        "https://mirror.example.test/deb/tool-1.2.3-linux-amd64.zip",
        "https://mirror.example.test/msix/tool",
    ] {
        assert!(
            !super::archive::container_url_refused(url),
            "{url} has a packaging-named *directory* and an installable file; \
             testing the whole path would refuse it"
        );
    }
    // A compression format the extractor has no decoder for is refused the same
    // way, and the two the extractor *does* have decoders for are not. This is the
    // pair that caught the first version of the predicate, which read
    // `PROGRAM_EXTENSIONS` and so refused every `.tar.gz` in existence.
    for name in ["tool_1.2.3_linux_amd64.tar.zst", "tool.linux.tar.bz2"] {
        assert!(
            super::archive::container_url_refused(&format!("https://example.test/{name}")),
            "{name} cannot be opened, and installing it as a raw binary reports success"
        );
    }
}

#[test]
fn a_tool_named_after_a_hash_is_not_a_digest() {
    for name in [
        "blake3_linux_x86_64.tar.gz",
        "blake3_linux_arm64.tar.gz",
        "md5_linux_amd64.tar.gz",
        "sha256_linux_amd64.tar.gz",
        "tool_md5_linux_amd64.tar.gz",
        "tool-sha512-linux-amd64.tar.gz",
        "md5tool_linux_x86_64.tar.gz",
        "md5deep-4.4.0.tar.gz",
        "checksum_linux_amd64.tar.gz",
        "checksum-1.0-linux-amd64.tar.gz",
        // Real program names that happen to end in `sum`, which the shape rules
        // already excluded and which this pins.
        "sha1sum_linux_amd64.tar.gz",
        "sha3sum_linux_amd64.tar.gz",
        // **The same names with no extension at all**, which is the case the
        // `PROGRAM_EXTENSIONS` guard cannot help with -- it never runs. Every one of
        // these was classified as a digest, and a release shipping
        // `md5sum_linux_amd64`, `md5sum_linux_amd64.tar.gz`, and
        // `md5sum_checksums.txt` was refused with **the program itself** listed as a
        // checksum candidate. The rule that fixes it is positional rather than
        // lexical: a manifest marker is the *project* name when it leads, and a
        // marker when it follows something.
        "md5sum_linux_amd64",
        "sha1sum_linux_amd64",
        "sha256sum_linux_amd64",
        "sha512sum-linux-amd64",
        "blake3_linux_amd64",
        "sha512_linux_amd64",
        // **The coordinate guard has three families, and each needs a row** even
        // though no single vocabulary member does. An OS token last, an
        // architecture token last (the rows above), and a version token last.
        "md5sum-amd64-linux",
        "md5sum_1.2.3",
        "sha256sum-2.0",
        // And a project literally named `checksum`, extensionless.
        "checksum_linux_amd64",
    ] {
        assert!(
            !super::providers::is_checksum_asset_name(name),
            "{name} is an archive, and calling it a digest makes a good release \
             ambiguous"
        );
        // And the other half of the same fact: it *is* the artifact.
        assert!(
            neoenv_core::tools::is_release_artifact(name),
            "{name} is the program, and the planner must be able to select it"
        );
    }
}

/// What `github_asset_matches_host` classifies, on this platform.
///
/// **This is not an agreement test any more, and its name used to say it was.**
/// `github_asset_matches_host` had its own nine-entry suffix table *and* its own OS
/// and architecture alias lists, so the two halves of one provider disagreed three
/// ways at once: every suffix core knew and it did not was unreachable here, `mac`
/// was missing from its alias list, and the architecture lists treated `arm` and
/// `x86` differently. Sharing only the *artifact* half left the same defect in the
/// other two quarters.
///
/// Two earlier versions of this test were broken in ways that hid exactly that:
///
/// - It lived in `neoenv-core` and called the core function, so it could not have
///   reached the installer at all. It is here, next to the function that drifted.
/// - It then compared the installer against the two core functions the installer
///   delegates to -- `f(a) == (b(a) && c(a))`, a self-comparison that passes with
///   the function deleted -- and was commented as a list of *artifacts* while
///   carrying three sidecars, which agreed with their shared delegates and so
///   asserted nothing.
///
/// Every row below is a literal now. The property is "this is what the global path
/// decides", and each row is a name a release actually publishes.
#[test]
fn the_global_path_classifies_artifacts_and_sidecars() {
    let platform = Platform::new("linux", "x86_64");
    for name in [
        // Suffixes the installer's own list did not have, so they used to be
        // unreachable on this path while `tool plan` named them.
        "tool-linux-amd64.pyz",
        "nvim-linux-x86_64.tar.gz",
        // And a name that merely *contains* a package token as a substring, which
        // the any-segment test could have caught and does not.
        "myappimager-linux-amd64",
        "debian-linux-amd64",
        "apkbuilder-linux-amd64",
    ] {
        let asset = GithubReleaseAsset {
            id: 1,
            name: name.into(),
            url: "https://example.test/artifact".into(),
        };
        // The expected value is a literal, not the answer recomputed from the two
        // core functions the function under test delegates to. An earlier version
        // built it that way, which made the assertion `f(a) == (b(a) && c(a))` --
        // a self-comparison that would have passed even if both `f` and its two
        // delegates had been deleted. It also hid a misfiled row: this list was
        // commented as artifacts and carried three sidecars, which agreed with
        // their shared delegates and so asserted nothing.
        assert!(
            super::providers::github_asset_matches_host(&asset, &platform),
            "{name} is the artifact for this platform and must resolve on the \
             global path"
        );
    }
    // The other direction, which the self-comparison could not see. A release of
    // exactly `tool_1.2.3_linux_amd64.tar.gz` plus one of these used to resolve to
    // the sidecar, or -- when the sidecar was the only platform match -- to two
    // candidates and a refusal on a perfectly good release.
    //
    // **And the packaging formats, which were on the list above and were the
    // largest wrong-install class in the project.** `gh:cli/cli` on linux/x86_64
    // selects `gh_2.101.0_linux_amd64.deb` at asset 4 over the real
    // `gh_2.101.0_linux_amd64.tar.gz` at asset 6; the `.deb` is an `ar` archive, so
    // `extract_raw_binary` copied it to `bin/gh`, marked it executable, wrote a
    // receipt and published a launcher, and **the install reported success**. The
    // first run failed with `Exec format error`. See `is_package_not_program`.
    for name in [
        "tool_1.2.3_linux_amd64.sha256sum",
        "tool_1.2.3_linux_amd64.sig",
        "tool_1.2.3_linux_amd64.tar.gz.gpg",
        "tool_1.2.3_linux_amd64.spdx.json",
        "gh_2.101.0_linux_amd64.deb",
        "tool_1.2.3_linux_amd64.rpm",
        "tool_1.2.3_linux_amd64.apk",
        "tool_1.2.3_windows_amd64.msi",
        "tool_1.2.3_darwin_arm64.dmg",
        "tool_1.2.3_darwin_arm64.pkg",
        "tool_1.2.3_linux_amd64.flatpak",
        // **An AppImage, refused again after a brief removal.** The removal argued
        // it is "a directly-runnable ELF, so the raw-binary path installs it
        // correctly and the program runs", citing neovim/logseq selecting one at the
        // parent "with a working result". Both halves were false: those releases
        // selected `nvim-linux-x86_64.tar.gz` and `Logseq-linux-x64-0.10.15.zip` at
        // the parent, and no run was ever recorded. An AppImage **needs FUSE at run
        // time**, so without `libfuse2` the install reports success and the first run
        // fails -- the same shape as the bug this table prevents, one layer up.
        "tool_1.2.3_linux_amd64.AppImage",
        "nvim-linux-x86_64.appimage",
        // **The bzip2 shorthands**, which `bz2` alone left accepted while `bz2` was
        // refused -- the same bytes taking two paths depending on spelling, for a
        // release (`aristocratos/btop`) that publishes `.tbz` and nothing else.
        "btop-x86_64-linux-musl.tbz",
        "btop-aarch64-unknown-linux-musl.tbz2",
        // Any dot-segment, so a package marker in the middle still counts.
        "goreleaser_2.18.2_linux_amd64.pkg.tar.zst",
        // The compression formats with no decoder here. The previous version of
        // this list omitted them, so they reached the *installer's* worse diagnostic
        // — after selection, with no candidate list — rather than being skipped by
        // selection where the user learns the `.zip` is in the same release.
        "fastfetch-windows-amd64.7z",
        "restic_0.19.1_linux_amd64.bz2",
        "ollama-linux-amd64.tar.zst",
        "tool.7z",
        "tool.br",
    ] {
        let asset = GithubReleaseAsset {
            id: 1,
            name: name.into(),
            url: "https://example.test/sidecar".into(),
        };
        assert!(
            !super::providers::github_asset_matches_host(&asset, &platform),
            "{name} cannot become a runnable tool here, and selecting it as the \
             program is the bug"
        );
    }

    // The `mac` case, which the installer's alias list simply did not have: the
    // planner accepts it (the table documents `mac` as a spelling the reference
    // takes) and the global path used to refuse, so `tool plan` named the asset and
    // `tool install --global` errored with "no platform binary or archive matched".
    let darwin = Platform::new("darwin", "x86_64");
    for name in [
        "tool-mac-amd64.tar.gz",
        "tool-osx-amd64.tar.gz",
        "tool-darwin-amd64.tar.gz",
    ] {
        let asset = GithubReleaseAsset {
            id: 1,
            name: name.into(),
            url: "https://example.test/artifact".into(),
        };
        assert!(
            super::providers::github_asset_matches_host(&asset, &darwin),
            "{name} resolves under `tool plan` and must resolve here too"
        );
    }
    // And the architecture lists. `armhf` matching `arm` is core's deliberate
    // substring behavior (a token test would stop matching
    // `x86_64-unknown-linux-musl`) as well as the reference's `strings.Contains`,
    // and it is asserted here as a fact about the rule rather than as agreement
    // with another copy of it -- there is no longer another copy to agree with.
    //
    // The `x86` family, and the two rows that carry the reason it is shaped this
    // way. The first version of this test asserted `false` for
    // `tool_linux_i686.tar.gz` on `x86`, pinning a regression as the contract
    // (sharing the alias list had deleted `i386`/`i686`); the next version asserted
    // `true` for `tool_linux_x86.tar.gz` on `x86`, which is *also* wrong, because
    // `matches_arch_alias` is a substring test and `x86_64` contains `x86`. A
    // 32-bit host accepting a 64-bit archive while reporting success is this
    // project's defining failure mode.
    //
    // So the family is the three spellings that are not substrings of `x86_64` or
    // `amd64`, and a release naming the architecture plain `x86` is **refused**
    // rather than matched -- a loud diagnostic listing every candidate, in
    // exchange for never installing a 64-bit build on a 32-bit host. The reference
    // reaches the same place from the other side: it returns `[]string{goarch}`,
    // so a 386 host there matches only `386`.
    for (arch, name, expected) in [
        ("arm", "tool_linux_armhf.tar.gz", true),
        ("arm", "tool_linux_arm.tar.gz", true),
        ("arm", "tool_linux_amd64.tar.gz", false),
        // The 32-bit family, as a *host* spelling and as a release spelling.
        ("386", "tool_linux_i686.tar.gz", true),
        ("386", "tool_linux_i386.tar.gz", true),
        ("386", "tool_linux_386.tar.gz", true),
        ("i686", "tool_linux_386.tar.gz", true),
        ("x86", "tool_linux_386.tar.gz", true),
        ("x86", "tool_linux_i686.tar.gz", true),
        ("x86", "tool_linux_i386.tar.gz", true),
        // Plain `x86` as a release spelling: refused, and the whole point.
        ("x86", "tool_linux_x86.tar.gz", false),
        // And the 64-bit archive a 32-bit host must never accept, under every
        // spelling of it. These two rows are the ones the previous version omitted,
        // which is why the substring collision went unnoticed.
        ("x86", "tool_linux_x86_64.tar.gz", false),
        ("x86", "tool_linux_amd64.tar.gz", false),
        ("386", "tool_linux_x86_64.tar.gz", false),
        // 64-bit hosts are unaffected: `x86_64` must still match its own archive.
        // Note a plain-`x86` release does *not* match a 64-bit host either -- that
        // is a 32-bit artifact, and the alias lists are `["x86_64","amd64","x64"]`.
        ("x86_64", "tool_linux_x86_64.tar.gz", true),
        ("x86_64", "tool_linux_x86.tar.gz", false),
        ("amd64", "tool_linux_x86_64.tar.gz", true),
    ] {
        let platform = Platform::new("linux", arch);
        let asset = GithubReleaseAsset {
            id: 1,
            name: name.into(),
            url: "https://example.test/artifact".into(),
        };
        assert_eq!(
            super::providers::github_asset_matches_host(&asset, &platform),
            expected,
            "{name} on {arch}"
        );
    }
}

/// **The newest installed version must be the one the shell gets, across a digit-width
/// boundary.**
///
/// The bug this closes was silent and total. `installed_runtimes` promised oldest-first —
/// `activation::runtime_diff` prepends each `PATH` entry and sets each variable, so the
/// last write wins and the order decides which version reaches the shell — and it kept
/// that promise with `versions.sort()`, which sorts *bytes*. Byte order puts `1.10.0`
/// before `1.9.0`, so oldest-first stopped being true at exactly the boundary where a
/// version gains a digit, the newest version stopped being last, and a user with Go 1.9
/// and Go 1.10 installed silently got 1.9 on their `PATH`.
///
/// **The test goes through the real enumerator into the real activation diff on purpose.**
/// The existing activation tests hand-build `InstalledRuntime` values and pass them in
/// order, so they assert the diff honours the order it is given and say nothing about
/// whether the enumerator produces that order. A test that cannot reach the defect is not
/// a test of the defect, and the two halves being separately correct is exactly how this
/// survived: the diff's own comment argues at length about oldest-first while the
/// producer of that order sorted bytes.
#[test]
fn the_newest_installed_runtime_reaches_path_across_a_digit_width_boundary() {
    let root = tempfile::tempdir().expect("data root");
    let data = root.path();

    // Installed oldest-to-newest in *byte* order, so a byte sort and a precedence sort
    // are distinguishable by construction rather than by coincidence: `1.10.0` sorts
    // before `1.9.0` as text.
    for version in ["1.9.0", "1.10.0", "1.11.0"] {
        let directory = data.join("go").join(version);
        std::fs::create_dir_all(directory.join("go").join("bin")).expect("create runtime");
        std::fs::write(directory.join(".neoenv-go-sdk-sha256"), "receipt").expect("write receipt");
    }

    let enumerated = installed_runtimes(data);
    let versions: Vec<&str> = enumerated.iter().map(|it| it.version.as_str()).collect();
    assert_eq!(
        versions,
        vec!["1.9.0", "1.10.0", "1.11.0"],
        "the enumerator must report oldest first by version precedence, not byte order"
    );

    // And the consequence, which is the part a user experiences. `PATH` is read by
    // applying the diff over a starting environment, and the two bin directories are
    // located as substrings rather than by splitting on `:`, so this holds on Windows
    // too — the separator there is `;` and a `split(':')` assertion would quietly pass
    // on a one-element path.
    let before = indexmap! { "PATH".to_owned() => "/usr/bin".to_owned() };
    let applied = runtime_diff(&enumerated)
        .expect("the fixture contributes PATH and GOROOT, which are names")
        .apply(&before);
    let path = applied
        .get("PATH")
        .expect("PATH is always present after a prepend")
        .clone();
    let newest = data.join("go").join("1.11.0").join("go").join("bin");
    let oldest = data.join("go").join("1.9.0").join("go").join("bin");
    let newest_at = path.find(newest.to_string_lossy().as_ref());
    let oldest_at = path.find(oldest.to_string_lossy().as_ref());
    assert!(
        newest_at.is_some(),
        "the newest runtime must be on PATH: {path}"
    );
    assert!(
        oldest_at.is_some(),
        "every installed runtime must be on PATH: {path}"
    );
    assert!(
        newest_at < oldest_at,
        "the newest runtime must come FIRST on PATH, because a prepended earlier entry \
         would be found by the shell first. Got: {path}"
    );
}

fn write_uv_install(data: &Path, version: &str, receipt: &str, executable: bool) {
    let root = data.join("uv").join(version);
    let binary = uv_binary(&root);
    fs::create_dir_all(binary.parent().expect("uv binary parent")).expect("uv bin dir");
    fs::write(&binary, "#!/bin/sh\nexit 0\n").expect("uv binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(&binary, fs::Permissions::from_mode(mode)).expect("uv mode");
    }
    #[cfg(not(unix))]
    let _ = executable;
    fs::write(root.join(".neoenv-uv-sha256"), receipt).expect("uv receipt");
}

/// `runtime_install_evidence` is the enumeration a task runner uses. Receipt
/// presence alone is not evidence: the receipt must be a real file with a
/// well-formed digest of the layout's length, and the exact executable must be
/// a real, executable, contained file. These are structural checks only; the
/// digest is not bound to the executable and the version is a directory label.
#[test]
fn runtime_install_evidence_requires_a_complete_uv_install_and_rejects_invalid_receipts() {
    let valid = "a".repeat(64);
    let cases: &[(&str, &str, bool)] = &[
        ("valid", &valid, true),
        ("empty", "", true),
        ("malformed", "receipt", true),
        ("short", "abc", true),
        ("uppercase", &"A".repeat(64), true),
        ("missing executable", &valid, false),
    ];
    for (label, receipt, executable) in cases {
        let root = tempfile::tempdir().expect("data root");
        write_uv_install(root.path(), "0.8.0", receipt, *executable);
        let found = runtime_install_evidence(root.path());
        assert_eq!(
            found.len(),
            usize::from(*label == "valid"),
            "{label}: {found:?}"
        );
        if *label == "valid" {
            assert_eq!(found[0].id, "uv");
            assert_eq!(found[0].version, "0.8.0");
            assert_eq!(found[0].digest, valid);
            assert!(found[0].receipt.ends_with(".neoenv-uv-sha256"));
            assert!(
                found[0].bin_dir.join("uv").exists() || found[0].bin_dir.join("uv.exe").exists()
            );
        }
    }
}

/// A receipt with no executable at all must not be reported, and neither must a
/// runtime directory with no receipt.
#[test]
fn runtime_install_evidence_reports_no_install_when_the_receipt_or_binary_is_missing() {
    let root = tempfile::tempdir().expect("data root");
    let version_root = root.path().join("uv").join("0.8.0");
    fs::create_dir_all(&version_root).expect("version root");
    fs::write(version_root.join(".neoenv-uv-sha256"), "a".repeat(64)).expect("receipt");
    assert!(runtime_install_evidence(root.path()).is_empty());

    fs::remove_file(version_root.join(".neoenv-uv-sha256")).expect("remove receipt");
    let binary = uv_binary(&version_root);
    fs::create_dir_all(binary.parent().expect("bin parent")).expect("bin parent");
    fs::write(&binary, "binary").expect("binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("mode");
    }
    assert!(runtime_install_evidence(root.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn runtime_install_evidence_rejects_symlinked_receipts_binaries_and_version_directories() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let valid = "a".repeat(64);

    // Symlinked receipt.
    let root = tempfile::tempdir().expect("data root");
    write_uv_install(root.path(), "0.8.0", &valid, true);
    let version_root = root.path().join("uv").join("0.8.0");
    let receipt = version_root.join(".neoenv-uv-sha256");
    let outside = root.path().join("outside-receipt");
    fs::write(&outside, &valid).expect("outside receipt");
    fs::remove_file(&receipt).expect("remove receipt");
    symlink(&outside, &receipt).expect("symlink receipt");
    assert!(runtime_install_evidence(root.path()).is_empty());

    // Symlinked uv executable.
    let root = tempfile::tempdir().expect("data root");
    write_uv_install(root.path(), "0.8.0", &valid, true);
    let version_root = root.path().join("uv").join("0.8.0");
    let binary = uv_binary(&version_root);
    let outside_binary = root.path().join("outside-uv");
    fs::write(&outside_binary, "#!/bin/sh\nexit 0\n").expect("outside binary");
    fs::set_permissions(&outside_binary, fs::Permissions::from_mode(0o755)).expect("mode");
    fs::remove_file(&binary).expect("remove binary");
    symlink(&outside_binary, &binary).expect("symlink binary");
    assert!(runtime_install_evidence(root.path()).is_empty());

    // Symlinked version directory.
    let root = tempfile::tempdir().expect("data root");
    write_uv_install(root.path(), "0.8.0", &valid, true);
    let real_version = root.path().join("uv-real").join("0.8.0");
    fs::create_dir_all(real_version.parent().expect("parent")).expect("real parent");
    fs::rename(root.path().join("uv").join("0.8.0"), &real_version).expect("move version");
    fs::remove_dir(root.path().join("uv")).expect("remove uv dir");
    fs::create_dir(root.path().join("uv")).expect("recreate uv dir");
    symlink(&real_version, root.path().join("uv").join("0.8.0")).expect("symlink version");
    assert!(runtime_install_evidence(root.path()).is_empty());
}
