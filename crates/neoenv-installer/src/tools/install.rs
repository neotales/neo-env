//! Lockfile publication, installed-state tracking, and the transactional
//! install that stages bytes and publishes them atomically.

use super::archive::{
    budget_error, check_archive_scan_count, extract_artifact, extraction_reader_budget,
    read_archive_metadata,
};
use super::{
    Command, Deserialize, Diagnostic, DiagnosticCategory, HashSet, INSTALL_METADATA,
    INSTALL_RECEIPT, LockedTool, ManagerLock, Ordering, Path, PathBuf, Read, ResourceBudget,
    Serialize, Sha256, TEMP_SEQUENCE, ToolLockfile, ToolPlan, ToolStorage, copy_and_verify,
    diagnostic, file_error, fs, go_command, http_error, http_policy, io, lock_error,
    read_text_file, runtime_error, runtime_error_with_cause, runtime_io, state_file,
    temporary_path, usable_file, valid_binary_names, verification_error, verify_file,
    verify_tool_plan,
};
use base64::Engine;
use flate2::read::GzDecoder;
#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags, RenameFlags, open as open_nofollow, openat, renameat_with};
use sha2::Digest;
use tar::Archive;

const BUN_INPUT_METADATA_LIMIT: u64 = 2 * 1024 * 1024;
const BUN_INSTALL_GRAPH_RECEIPT: &str = ".neoenv-bun-graph-sha256";
pub const CARGO_BUILD_RECEIPT: &str = ".neoenv-cargo-build-sha256";

/// Evidence checked for one Bun binary under the neoenv-managed runtime root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManagedBun {
    executable: PathBuf,
    version: String,
    executable_sha256: String,
    archive_sha256: String,
    archive_url: String,
}

impl VerifiedManagedBun {
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    #[must_use]
    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    #[must_use]
    pub fn archive_url(&self) -> &str {
        &self.archive_url
    }
}

/// Load retained Bun evidence against a separately trusted existing lock.
///
/// The caller must authenticate the supplied anchor independently. Local
/// provenance and receipt files alone are not a trust anchor.
///
/// # Errors
///
/// Returns a diagnostic when the managed runtime or retained evidence is absent,
/// unsafe, malformed, or fails verification. No fallback or network is used.
pub fn verify_retained_managed_bun(
    data_root: &Path,
    version: &str,
    trusted_archive: &neoenv_core::tools::ManagerRuntimeArchive,
    trusted_executable_sha256: &str,
    scratch: &Path,
) -> Result<(VerifiedManagedBun, PathBuf), Diagnostic> {
    let (asset, archive) = retained_bun_asset(data_root, version)?;
    if asset.url != trusted_archive.url || asset.sha256 != trusted_archive.sha256 {
        return Err(runtime_error(
            "managed Bun provenance differs from trusted lock",
        ));
    }
    let bun = verify_managed_bun(
        data_root,
        &asset,
        &archive,
        Some(trusted_executable_sha256),
        scratch,
    )?;
    Ok((bun, archive))
}

/// Verify retained managed Bun against a user-supplied archive digest.
///
/// The digest authenticates the archive bytes, not the locally recorded URL.
/// The caller is responsible for obtaining that digest from a trusted source.
///
/// # Errors
///
/// Refuses missing or malformed evidence and digest mismatches before running Bun.
pub fn verify_pinned_retained_managed_bun(
    data_root: &Path,
    version: &str,
    archive_sha256: &str,
    scratch: &Path,
) -> Result<(VerifiedManagedBun, PathBuf), Diagnostic> {
    if !neoenv_core::tools::is_sha256(archive_sha256) {
        return Err(runtime_error("invalid pinned Bun archive SHA-256"));
    }
    let (asset, archive) = retained_bun_asset(data_root, version)?;
    if asset.sha256 != archive_sha256 {
        return Err(runtime_error(
            "managed Bun archive differs from user-pinned SHA-256",
        ));
    }
    let bun = verify_managed_bun(data_root, &asset, &archive, None, scratch)?;
    Ok((bun, archive))
}

fn retained_bun_asset(
    data_root: &Path,
    version: &str,
) -> Result<(super::BunRuntimeAsset, PathBuf), Diagnostic> {
    if super::runtimes::parse_bun_version(version)? != version {
        return Err(runtime_error("Bun manager version must be exact"));
    }
    let runtime_base = data_root.join("bun");
    let root = runtime_base.join(version);
    for path in [data_root, runtime_base.as_path(), root.as_path()] {
        require_real_directory(path, "managed Bun directory")?;
    }
    let provenance_path = root.join(super::BUN_RUNTIME_PROVENANCE);
    let bytes = read_regular_nofollow_bounded(&provenance_path, BUN_INPUT_METADATA_LIMIT)?;
    let asset: super::BunRuntimeAsset = serde_json::from_slice(&bytes)
        .map_err(|error| runtime_error_with_cause("invalid managed Bun provenance", error))?;
    if asset.version != version {
        return Err(runtime_error("managed Bun provenance version mismatch"));
    }
    let archive = root.join(super::BUN_RUNTIME_ARCHIVE);
    Ok((asset, archive))
}

/// The one-package Bun graph and canonical inputs produced without network access.
pub struct PreparedBunLock {
    pub graph: ManagerLock,
    pub manifest: Vec<u8>,
    pub bun_lockfile: Vec<u8>,
}

/// Build the supported dependency-free Bun lock inputs from a resolved npm plan.
///
/// The caller must supply an already authenticated npm plan, a managed Bun
/// verification result, and its locally cached npm tarball. No files are
/// written and no process or network is used.
///
/// # Errors
///
/// Rejects mismatched declarations, tarball integrity or identity, unsupported
/// dependency graphs, and package binaries that differ from the plan.
pub fn prepare_bun_lock(
    declaration: &neoenv_core::tools::ToolDeclaration,
    tool: &neoenv_core::tools::PlannedTool,
    bun: &VerifiedManagedBun,
    tarball: &Path,
) -> Result<PreparedBunLock, Diagnostic> {
    let (package, metadata) = inspect_resolved_bun_tarball(declaration, tool, tarball)?;
    let manager = declaration
        .npm
        .as_ref()
        .and_then(|npm| npm.manager.as_ref())
        .ok_or_else(|| runtime_error("Bun lock requires an explicit Bun manager"))?;
    if manager.version != bun.version
        || manager
            .archive_sha256
            .as_ref()
            .is_some_and(|pin| pin != &bun.archive_sha256)
    {
        return Err(runtime_error(
            "Bun lock inputs differ from the selected manager",
        ));
    }
    let bin = metadata
        .get("bin")
        .ok_or_else(|| runtime_error("npm package has no binaries"))?;
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": "neoenv-locked-package-stage",
        "private": true,
        "dependencies": { (package.name.clone()): "file:./locked-package.tgz" }
    }))
    .map_err(|error| runtime_error(error.to_string()))?;
    let bun_lockfile = serde_json::to_vec(&serde_json::json!({
        "lockfileVersion": 2,
        "configVersion": 1,
        "workspaces": { "": {
            "name": "neoenv-locked-package-stage",
            "dependencies": { (package.name.clone()): "file:./locked-package.tgz" }
        }},
        "packages": { (package.name.clone()): [
            format!("{}@./locked-package.tgz", package.name),
            { "bin": bin },
            package.integrity
        ]}
    }))
    .map_err(|error| runtime_error(error.to_string()))?;
    let graph = ManagerLock {
        schema_version: 1,
        manager: "bun".into(),
        manager_version: bun.version.clone(),
        manager_sha256: bun.executable_sha256.clone(),
        runtime_version: bun.version.clone(),
        runtime_archive: Some(neoenv_core::tools::ManagerRuntimeArchive {
            url: bun.archive_url.clone(),
            sha256: bun.archive_sha256.clone(),
        }),
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest)),
        lockfile_sha256: format!("{:x}", Sha256::digest(&bun_lockfile)),
        script_policy: neoenv_core::tools::ScriptPolicy::Disabled,
        packages: vec![package],
    };
    graph.validate().map_err(|error| lock_error(&error))?;
    Ok(PreparedBunLock {
        graph,
        manifest,
        bun_lockfile,
    })
}

/// Validate the complete npm tarball before any manager process is run.
///
/// # Errors
///
/// Rejects mismatched plans, hashes, unsafe archives, unsupported dependencies,
/// and binary names which differ from the plan.
pub fn validate_resolved_bun_tarball(
    declaration: &neoenv_core::tools::ToolDeclaration,
    tool: &neoenv_core::tools::PlannedTool,
    tarball: &Path,
) -> Result<(), Diagnostic> {
    inspect_resolved_bun_tarball(declaration, tool, tarball).map(|_| ())
}

fn inspect_resolved_bun_tarball(
    declaration: &neoenv_core::tools::ToolDeclaration,
    tool: &neoenv_core::tools::PlannedTool,
    tarball: &Path,
) -> Result<(super::ManagerPackage, serde_json::Value), Diagnostic> {
    let npm = declaration
        .npm
        .as_ref()
        .filter(|_| declaration.provider == neoenv_core::tools::ToolProvider::Npm)
        .ok_or_else(|| runtime_error("Bun lock requires an npm declaration"))?;
    let manager = npm
        .manager
        .as_ref()
        .filter(|manager| manager.name == neoenv_core::tools::NpmManagerName::Bun)
        .ok_or_else(|| runtime_error("Bun lock requires an explicit Bun manager"))?;
    if !neoenv_core::tools::is_exact_manager_version(&manager.version)
        || declaration.id != tool.id
        || (declaration.version != "latest" && declaration.version != tool.resolved_version)
        || tool.provenance.provider != "npm"
        || tool.provenance.package.as_deref() != Some(npm.package.as_str())
        || super::canonical_http_url(&npm.endpoint).ok().as_deref()
            != tool.provenance.registry_endpoint.as_deref()
        || tool.sha256 != tool.verification.sha256
        || !safe_package_name(&npm.package)
    {
        return Err(runtime_error(
            "Bun lock inputs differ from the selected declaration",
        ));
    }
    let integrity = tool
        .provenance
        .registry_integrity
        .as_ref()
        .ok_or_else(|| runtime_error("npm plan lacks registry integrity"))?;
    let package = super::ManagerPackage {
        id: format!("{}@{}", npm.package, tool.resolved_version),
        name: npm.package.clone(),
        version: tool.resolved_version.clone(),
        dependencies: vec![],
        tarball_url: tool.url.clone(),
        integrity: integrity.clone(),
        sha256: tool.sha256.clone(),
    };
    if hash_file(tarball)? != package.sha256 || !verify_file_sri(tarball, integrity)? {
        return Err(runtime_error("npm tarball differs from the resolved plan"));
    }
    let metadata = validate_npm_archive_metadata(tarball, &package)?;
    let bins = super::providers::npm_bins_from_package_json(&package.name, &metadata)
        .ok_or_else(|| runtime_error("npm package has no supported binaries"))?;
    let expected: HashSet<_> = tool.binaries.iter().collect();
    let actual: HashSet<_> = bins.iter().map(|bin| &bin.name).collect();
    if expected.len() != tool.binaries.len() || actual.len() != bins.len() || expected != actual {
        return Err(runtime_error(
            "npm package binaries differ from the resolved plan",
        ));
    }
    Ok((package, metadata))
}

/// Content-addressed, locally cached inputs for a single Bun manager graph.
#[derive(Clone, Debug)]
pub struct StoredBunInputs {
    pub archive: PathBuf,
    pub tarball: PathBuf,
    pub manifest: PathBuf,
    pub bun_lockfile: PathBuf,
}

fn bun_input_key(graph: &ManagerLock) -> Result<String, Diagnostic> {
    graph.validate().map_err(|error| lock_error(&error))?;
    if graph.manager != "bun"
        || graph.manager_version != graph.runtime_version
        || graph.runtime_archive.is_none()
        || graph.packages.len() != 1
        || !graph.packages[0].dependencies.is_empty()
    {
        return Err(runtime_error("unsupported or incomplete Bun cache graph"));
    }
    let encoded = serde_json::to_vec(graph).map_err(|error| runtime_error(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn bun_input_paths(root: &Path) -> StoredBunInputs {
    StoredBunInputs {
        archive: root.join("runtime.zip"),
        tarball: root.join("package.tgz"),
        manifest: root.join("manifest.json"),
        bun_lockfile: root.join("bun.lock"),
    }
}

fn copy_bun_inputs(
    source: &StoredBunInputs,
    destination: &StoredBunInputs,
) -> Result<(), Diagnostic> {
    for (input, output, limit) in [
        (
            &source.archive,
            &destination.archive,
            ResourceBudget::default().artifact_bytes,
        ),
        (
            &source.tarball,
            &destination.tarball,
            ResourceBudget::default().artifact_bytes,
        ),
        (
            &source.manifest,
            &destination.manifest,
            BUN_INPUT_METADATA_LIMIT,
        ),
        (
            &source.bun_lockfile,
            &destination.bun_lockfile,
            BUN_INPUT_METADATA_LIMIT,
        ),
    ] {
        copy_regular_file_nofollow(input, output, false, limit)?;
    }
    Ok(())
}

fn validate_staged_bun_inputs(
    graph: &ManagerLock,
    inputs: &StoredBunInputs,
) -> Result<(), Diagnostic> {
    let package = &graph.packages[0];
    let archive = graph
        .runtime_archive
        .as_ref()
        .ok_or_else(|| runtime_error("Bun cache lacks runtime archive provenance"))?;
    let manifest = read_regular_nofollow_bounded(&inputs.manifest, 2 * 1024 * 1024)?;
    let lockfile = read_regular_nofollow_bounded(&inputs.bun_lockfile, 2 * 1024 * 1024)?;
    if !verify_file(&inputs.archive, &archive.sha256)?
        || !verify_file(&inputs.tarball, &package.sha256)?
        || !verify_file_sri(&inputs.tarball, &package.integrity)?
        || format!("{:x}", Sha256::digest(&manifest)) != graph.manifest_sha256
        || format!("{:x}", Sha256::digest(&lockfile)) != graph.lockfile_sha256
    {
        return Err(runtime_error("cached Bun inputs differ from locked hashes"));
    }
    let expected = serde_json::to_vec(&serde_json::json!({
        "name": "neoenv-locked-package-stage",
        "private": true,
        "dependencies": { (package.name.clone()): "file:./locked-package.tgz" }
    }))
    .map_err(|error| runtime_error(error.to_string()))?;
    if manifest != expected {
        return Err(runtime_error("cached Bun manifest differs from graph"));
    }
    let metadata = validate_npm_archive_metadata(&inputs.tarball, package)?;
    validate_bun_lockfile(&inputs.bun_lockfile, package, &metadata)
}

/// Persist a complete graph's inputs as one atomic, content-addressed directory.
///
/// `storage_root` must be an existing trusted directory. Files are staged with
/// no-follow opens, bounded reads and synced contents; validation precedes
/// publication. Failed staging is removed. An existing entry is never replaced.
///
/// # Errors
///
/// Returns a diagnostic if any input is missing, unsafe, mismatched, or cannot
/// be safely published.
pub fn persist_bun_inputs(
    storage_root: &Path,
    graph: &ManagerLock,
    source: &StoredBunInputs,
) -> Result<StoredBunInputs, Diagnostic> {
    let key = bun_input_key(graph)?;
    require_real_directory(storage_root, "Bun storage root")?;
    let store = storage_root.join("bun-manager-inputs");
    match fs::create_dir(&store) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(runtime_io(&store, &error)),
    }
    require_real_directory(&store, "Bun input store")?;
    let destination = store.join(&key);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return recover_bun_inputs(storage_root, graph),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime_io(&destination, &error)),
    }
    let staging = create_private_staging(&store, "bun-inputs")?;
    let result = (|| {
        #[cfg(unix)]
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .map_err(|error| runtime_io(&staging, &error))?;
        let staged = bun_input_paths(&staging);
        copy_bun_inputs(source, &staged)?;
        validate_staged_bun_inputs(graph, &staged)?;
        #[cfg(unix)]
        fs::File::open(&staging)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| runtime_io(&staging, &error))?;
        publish_directory_noreplace(&staging, &destination)?;
        #[cfg(unix)]
        fs::File::open(&store)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| runtime_io(&store, &error))?;
        Ok(bun_input_paths(&destination))
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Resolve and verify cached inputs without consulting PATH or the network.
///
/// Returned paths must be staged and verified again by the consumer; this
/// function does not defend against another process with the same user ID.
///
/// # Errors
///
/// Returns a diagnostic if the graph, cache path, or any cached input is invalid.
pub fn recover_bun_inputs(
    storage_root: &Path,
    graph: &ManagerLock,
) -> Result<StoredBunInputs, Diagnostic> {
    let key = bun_input_key(graph)?;
    require_real_directory(storage_root, "Bun storage root")?;
    let store = storage_root.join("bun-manager-inputs");
    require_real_directory(&store, "Bun input store")?;
    let root = store.join(key);
    require_real_directory(&root, "Bun input entry")?;
    let source = bun_input_paths(&root);
    let staging = create_private_staging(&store, "bun-input-check")?;
    let result = (|| {
        #[cfg(unix)]
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .map_err(|error| runtime_io(&staging, &error))?;
        let staged = bun_input_paths(&staging);
        copy_bun_inputs(&source, &staged)?;
        validate_staged_bun_inputs(graph, &staged)?;
        Ok(source)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Verify a managed Bun installation against its retained release archive.
///
/// `asset` must come from a trusted release resolution or previously trusted
/// lock: checking its checksum and URL here does not authenticate that claim.
/// `data_root` is the trusted neoenv runtime data directory, and `scratch` is
/// an existing directory controlled by the caller. No PATH lookup is used.
/// Inputs are staged before hashing and version execution. A caller must
/// recheck the returned executable hash on a private copy before executing it.
/// For an existing lock, pass its manager SHA-256; a mismatch is refused before
/// executing Bun. `None` is only for deriving the identity of a new lock.
///
/// # Errors
///
/// Returns a diagnostic for invalid selection, missing or altered managed
/// installation, archive or receipt mismatch, or executable version mismatch.
#[allow(clippy::too_many_lines)]
pub fn verify_managed_bun(
    data_root: &Path,
    asset: &super::BunRuntimeAsset,
    archive: &Path,
    expected_executable_sha256: Option<&str>,
    scratch: &Path,
) -> Result<VerifiedManagedBun, Diagnostic> {
    let version = super::runtimes::parse_bun_version(&asset.version)?;
    if version != asset.version || super::runtimes::bun_target(&super::Platform::host()).is_none() {
        return Err(runtime_error(
            "unsupported exact managed Bun version or platform",
        ));
    }
    let archive_url = super::canonical_http_url(&asset.url)
        .map_err(|_| runtime_error("invalid managed Bun archive URL"))?;
    let runtime_base = data_root.join("bun");
    let root = runtime_base.join(&version);
    let binary_dir = super::runtimes::bun_binary_directory(&root);
    for dir in [
        data_root,
        runtime_base.as_path(),
        root.as_path(),
        binary_dir.as_path(),
        scratch,
    ] {
        require_real_directory(dir, "managed Bun directory")?;
    }
    if !receipt_matches(
        &root.join(neoenv_core::names::BUN_RUNTIME_RECEIPT),
        &asset.sha256,
    ) {
        return Err(runtime_error(
            "managed Bun receipt does not match archive checksum",
        ));
    }
    let executable = binary_dir.join(super::runtimes::bun_binary_name());
    let staging = create_private_staging(scratch, "bun-verification")?;
    let result = (|| {
        #[cfg(unix)]
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .map_err(|error| runtime_io(&staging, &error))?;
        let staged_archive = staging.join("archive.zip");
        let staged_binary = staging.join(super::runtimes::bun_binary_name());
        copy_regular_file_nofollow(
            archive,
            &staged_archive,
            false,
            ResourceBudget::default().artifact_bytes,
        )?;
        copy_regular_file_nofollow(
            &executable,
            &staged_binary,
            true,
            ResourceBudget::default().artifact_bytes,
        )?;
        if !verify_file(&staged_archive, &asset.sha256)? {
            return Err(runtime_error("managed Bun archive SHA-256 mismatch"));
        }
        let extracted = staging.join("extracted");
        fs::create_dir(&extracted).map_err(|error| runtime_io(&extracted, &error))?;
        super::archive::extract_zip(&staged_archive, &extracted)?;
        let archived_binary = super::runtimes::bun_binary_directory(&extracted)
            .join(super::runtimes::bun_binary_name());
        let executable_sha256 = hash_file(&staged_binary)?;
        if hash_file(&archived_binary)? != executable_sha256 {
            return Err(runtime_error(
                "managed Bun executable differs from verified archive",
            ));
        }
        if expected_executable_sha256.is_some_and(|expected| expected != executable_sha256) {
            return Err(runtime_error(
                "managed Bun executable differs from locked manager SHA-256",
            ));
        }
        let home = staging.join("home");
        let tmp = staging.join("tmp");
        fs::create_dir(&home).map_err(|error| runtime_io(&home, &error))?;
        fs::create_dir(&tmp).map_err(|error| runtime_io(&tmp, &error))?;
        let mut command = Command::new(&staged_binary);
        command
            .arg("--version")
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", &tmp)
            .env("TMP", &tmp)
            .env("TEMP", &tmp);
        #[cfg(windows)]
        for key in ["PATH", "SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command.output().map_err(|error| {
            runtime_error_with_cause("failed to query verified managed Bun", error)
        })?;
        if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != version {
            return Err(runtime_error("managed Bun executable version mismatch"));
        }
        Ok(VerifiedManagedBun {
            executable,
            version,
            executable_sha256,
            archive_sha256: asset.sha256.clone(),
            archive_url,
        })
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Recover and install one locked package with a verified managed Bun runtime.
///
/// This does not resolve, download, or search PATH. Archive provenance in the
/// graph must have been authenticated when the graph was created. All cached
/// inputs and the runtime binary are rechecked before the offline installer
/// stages and verifies them again.
///
/// # Errors
///
/// Returns a diagnostic for missing or changed cache/runtime inputs, an
/// unsupported graph, or an unsuccessful Bun install. The package destination
/// is not published until installation succeeds.
pub fn install_cached_bun_package(
    storage_root: &Path,
    runtime_data_root: &Path,
    graph: &ManagerLock,
    scratch: &Path,
    destination: &Path,
) -> Result<PathBuf, Diagnostic> {
    let inputs = recover_bun_inputs(storage_root, graph)?;
    let archive = graph
        .runtime_archive
        .as_ref()
        .ok_or_else(|| runtime_error("Bun lock lacks managed archive provenance"))?;
    let asset = super::BunRuntimeAsset {
        version: graph.runtime_version.clone(),
        url: archive.url.clone(),
        sha256: archive.sha256.clone(),
    };
    let bun = verify_managed_bun(
        runtime_data_root,
        &asset,
        &inputs.archive,
        Some(&graph.manager_sha256),
        scratch,
    )?;
    if bun.version != graph.manager_version || bun.executable_sha256 != graph.manager_sha256 {
        return Err(runtime_error(
            "verified managed Bun does not match the manager lock",
        ));
    }
    install_bun_locked_package(
        &bun.executable,
        graph,
        &inputs.tarball,
        &inputs.manifest,
        &inputs.bun_lockfile,
        destination,
    )
}

/// Download a previously resolved npm tarball into caller-owned staging.
///
/// The plan must be a valid npm tool plan. The downloaded bytes are checked
/// against its SHA-256; Bun lock preparation subsequently checks npm SRI and
/// package metadata. This function never publishes a tool or manager lock.
///
/// # Errors
///
/// Returns a diagnostic for an invalid plan, transfer failure, or digest
/// mismatch. Any partially downloaded destination is removed.
pub fn stage_resolved_npm_tarball(
    tool: &neoenv_core::tools::PlannedTool,
    destination: &Path,
) -> Result<(), Diagnostic> {
    let plan = ToolPlan {
        tools: vec![tool.clone()],
    };
    ToolLockfile::from_plan(&plan)
        .validate()
        .map_err(|error| lock_error(&error))?;
    if tool.provenance.provider != "npm" {
        return Err(runtime_error(
            "staged npm tarball requires a resolved npm plan",
        ));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| runtime_io(destination, &error))?;
    let result = (|| {
        let policy = http_policy()?;
        let response = policy
            .get(&tool.url)
            .map_err(|error| http_error(error, "failed to download locked npm tarball"))?;
        policy
            .validate_artifact_length(
                &tool.url,
                &response,
                ResourceBudget::default().artifact_bytes,
            )
            .map_err(|error| http_error(error, "failed to download locked npm tarball"))?;
        let mut reader = policy.streaming_reader_limited(
            &tool.url,
            response,
            ResourceBudget::default().artifact_bytes,
        );
        copy_and_verify(&mut reader, &mut output, &tool.sha256)?;
        output
            .sync_all()
            .map_err(|error| runtime_io(destination, &error))
    })();
    drop(output);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

/// Validate a declared Bun manager against its exact, supported tool lock.
///
/// # Errors
///
/// Returns a diagnostic for an unsupported or mismatched declaration or graph.
pub fn validate_bun_tool_lock(
    declaration: &neoenv_core::tools::ToolDeclaration,
    lockfile: &ToolLockfile,
) -> Result<(), Diagnostic> {
    bun_tool_association(declaration, lockfile).map(|_| ())
}

fn bun_tool_association<'a>(
    declaration: &neoenv_core::tools::ToolDeclaration,
    lockfile: &'a ToolLockfile,
) -> Result<(&'a LockedTool, &'a ManagerLock, &'a super::ManagerPackage), Diagnostic> {
    lockfile.validate().map_err(|error| lock_error(&error))?;
    let [tool] = lockfile.tools.as_slice() else {
        return Err(runtime_error(
            "Bun installation requires exactly one locked npm tool",
        ));
    };
    let graph = lockfile
        .manager_lock
        .as_ref()
        .ok_or_else(|| runtime_error("Bun installation requires a manager lock"))?;
    let npm = declaration
        .npm
        .as_ref()
        .filter(|_| declaration.provider == neoenv_core::tools::ToolProvider::Npm)
        .ok_or_else(|| runtime_error("Bun installation requires an npm declaration"))?;
    let manager = npm
        .manager
        .as_ref()
        .filter(|manager| manager.name == neoenv_core::tools::NpmManagerName::Bun)
        .ok_or_else(|| runtime_error("Bun installation requires an explicit Bun manager"))?;
    let archive = graph
        .runtime_archive
        .as_ref()
        .ok_or_else(|| runtime_error("Bun manager lock lacks archive provenance"))?;
    let [package] = graph.packages.as_slice() else {
        return Err(runtime_error(
            "Bun installation supports only one dependency-free package",
        ));
    };
    if !package.dependencies.is_empty()
        || declaration.id != tool.id
        || (declaration.version != "latest" && declaration.version != tool.resolved_version)
        || tool.platform != super::Platform::host()
        || tool.resolver != "npm"
        || tool.provenance.provider != "npm"
        || npm.package != package.name
        || tool.provenance.package.as_deref() != Some(package.name.as_str())
        || tool.resolved_version != package.version
        || package.id != format!("{}@{}", package.name, package.version)
        || tool.url != package.tarball_url
        || tool.sha256 != package.sha256
        || tool.verification.sha256 != package.sha256
        || tool.provenance.registry_integrity.as_deref() != Some(package.integrity.as_str())
        || super::canonical_http_url(&npm.endpoint).ok().as_deref()
            != tool.provenance.registry_endpoint.as_deref()
        || graph.manager != "bun"
        || !neoenv_core::tools::is_exact_manager_version(&manager.version)
        || graph.manager_version != manager.version
        || graph.runtime_version != manager.version
        || manager
            .archive_sha256
            .as_ref()
            .is_some_and(|pin| pin != &archive.sha256)
    {
        return Err(runtime_error(
            "Bun manager lock differs from the declaration or locked npm tool",
        ));
    }
    valid_binary_names(tool)?;
    Ok((tool, graph, package))
}

/// Install the supported single-package manager lock into project tool storage.
///
/// This is an offline, no-replace operation. It verifies declaration/lock
/// association and manager inputs before publishing a complete tree with the
/// ordinary tool receipt and an additional manager-graph receipt.
///
/// # Errors
///
/// Returns a diagnostic for unsupported declarations, mismatched lock or
/// runtime, unsafe binaries, an existing destination, or installation failure.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub fn install_locked_bun_tool(
    project_root: &Path,
    runtime_data_root: &Path,
    declarations: &[neoenv_core::tools::ToolDeclaration],
    lockfile: &ToolLockfile,
) -> Result<InstalledTool, Diagnostic> {
    use std::os::unix::fs::PermissionsExt;
    reject_unimplemented_cargo_install(declarations, lockfile)?;
    let [declaration] = declarations else {
        return Err(runtime_error(
            "Bun installation requires exactly one declared npm tool",
        ));
    };
    let (tool, graph, package) = bun_tool_association(declaration, lockfile)?;
    let storage = ToolStorage::project(project_root);
    let project_storage = project_root.join(neoenv_core::names::PROJECT_DIRECTORY);
    require_real_directory(&project_storage, "project tool storage")?;
    let root = install_root(&storage, tool)?;
    match fs::symlink_metadata(&root) {
        Ok(_) => {
            return Err(runtime_error(
                "Bun tool installation destination already exists; refusing replacement",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime_io(&root, &error)),
    }
    let staging = create_private_staging(&project_storage, "bun-tool")?;
    let result = (|| {
        let staged = staging.join("payload");
        install_cached_bun_package(
            &project_storage,
            runtime_data_root,
            graph,
            &staging,
            &staged,
        )?;
        let package_root = staged.join("node_modules").join(&package.name);
        let metadata_path = package_root.join("package.json");
        let metadata: serde_json::Value = serde_json::from_slice(&read_regular_nofollow_bounded(
            &metadata_path,
            BUN_INPUT_METADATA_LIMIT,
        )?)
        .map_err(|_| runtime_error("installed npm package metadata is invalid"))?;
        let bins = super::providers::npm_bins_from_package_json(&package.name, &metadata)
            .ok_or_else(|| runtime_error("installed npm package has no binaries"))?;
        let expected: HashSet<_> = tool.binaries.iter().collect();
        let actual: HashSet<_> = bins.iter().map(|bin| &bin.name).collect();
        if actual != expected || actual.len() != bins.len() {
            return Err(runtime_error(
                "installed npm binaries differ from locked names",
            ));
        }
        let bin_dir = staged.join("bin");
        fs::create_dir(&bin_dir).map_err(|error| runtime_io(&bin_dir, &error))?;
        for bin in bins {
            let path = Path::new(&bin.path);
            if bin.path.contains('\\')
                || bin.path.chars().any(char::is_control)
                || path
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
                || bin.path.is_empty()
            {
                return Err(runtime_error("npm package binary has an unsafe path"));
            }
            let target = package_root.join(path);
            let file =
                fs::symlink_metadata(&target).map_err(|error| runtime_io(&target, &error))?;
            if !file.file_type().is_file() {
                return Err(runtime_error("npm package binary is not a regular file"));
            }
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(file.permissions().mode() | 0o500),
            )
            .map_err(|error| runtime_io(&target, &error))?;
            let launcher = format!(
                "#!/bin/sh\nexec \"${{0%/*}}/../node_modules\"/{}/{} \"$@\"\n",
                quote_bun_launcher_arg(&package.name),
                quote_bun_launcher_arg(&bin.path),
            );
            let path = bin_dir.join(&bin.name);
            fs::write(&path, launcher).map_err(|error| runtime_io(&path, &error))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .map_err(|error| runtime_io(&path, &error))?;
        }
        fs::write(staged.join(INSTALL_RECEIPT), &tool.sha256)
            .map_err(|error| runtime_io(&staged, &error))?;
        fs::write(
            staged.join(BUN_INSTALL_GRAPH_RECEIPT),
            bun_input_key(graph)?,
        )
        .map_err(|error| runtime_io(&staged, &error))?;
        write_install_metadata(&staged, tool)?;
        fs::create_dir_all(storage.install_directory())
            .map_err(|error| runtime_io(storage.install_directory(), &error))?;
        require_real_directory(
            storage.install_directory(),
            "project tool install directory",
        )?;
        publish_directory_noreplace(&staged, &root)?;
        installed_tool(&storage, tool)
            .ok_or_else(|| runtime_error("published Bun tool is incomplete"))
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

#[cfg(unix)]
pub(super) fn quote_bun_launcher_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Unsupported on hosts where the launcher contract is not implemented.
///
/// # Errors
///
/// Always returns an unsupported-platform diagnostic.
#[cfg(not(unix))]
pub fn install_locked_bun_tool(
    _project_root: &Path,
    _runtime_data_root: &Path,
    _declarations: &[neoenv_core::tools::ToolDeclaration],
    _lockfile: &ToolLockfile,
) -> Result<InstalledTool, Diagnostic> {
    reject_unimplemented_cargo_install(_declarations, _lockfile)?;
    Err(runtime_error(
        "Bun tool installation is not supported on this host",
    ))
}

/// Install one dependency-free package from an already-resolved Bun manager lock.
///
/// The explicit executable must be the Bun selected by the caller (normally a
/// declared nenv-managed runtime). The tarball is treated as untrusted and is
/// verified against both locked digest forms before Bun sees it. This narrow
/// v1 contract rejects dependency graphs: complete transitive resolution is not
/// implemented yet.
///
/// Inputs are copied into a mode-0700 staging directory and only the staged
/// executable is hashed and run. This prevents path replacement between
/// verification and use, but does not defend against a hostile process running
/// as the same user or a compromised kernel. On non-Unix hosts no-follow is
/// implemented as a symlink check followed by open, so callers must protect
/// source paths from concurrent mutation. Publication uses an atomic
/// no-replace rename on supported Unix hosts; a destination collision fails
/// without replacing the existing tree, and staging is cleaned up.
/// `manifest` must contain the canonical synthetic manifest for the one locked
/// local tarball; it is staged unchanged as `package.json`. `lockfile` is staged
/// unchanged as `bun.lock` and is passed to Bun with `--frozen-lockfile`.
/// Their SHA-256 values must equal the corresponding lock fields. The supplied
/// lockfile is not asserted to have been produced by Bun: it is parsed as the
/// supported Bun v2 subset and its exact root dependency, package resolution,
/// and integrity are checked against `ManagerLock` before Bun consumes it.
///
/// # Errors
///
/// Returns a diagnostic for an unsupported graph, manager mismatch, digest
/// mismatch, Bun failure, or filesystem failure. The destination is published
/// only after Bun succeeds and produces the expected package directory.
#[allow(clippy::too_many_lines)]
pub fn install_bun_locked_package(
    bun_executable: &Path,
    lock: &ManagerLock,
    tarball: &Path,
    manifest: &Path,
    lockfile: &Path,
    destination: &Path,
) -> Result<PathBuf, Diagnostic> {
    lock.validate().map_err(|error| lock_error(&error))?;
    if lock.manager != "bun"
        || lock.script_policy != neoenv_core::tools::ScriptPolicy::Disabled
        || lock.packages.len() != 1
        || !lock.packages[0].dependencies.is_empty()
        || lock.runtime_version != lock.manager_version
    {
        return Err(runtime_error(
            "Bun manager install currently supports only one dependency-free package and matching manager/runtime versions",
        ));
    }
    let package = &lock.packages[0];
    if !safe_package_name(&package.name) {
        return Err(runtime_error(
            "locked npm package name is not a safe package path",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| runtime_error("invalid Bun package destination"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let staging = create_private_staging(parent, "bun-package")?;
    let result = (|| {
        #[cfg(unix)]
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .map_err(|error| runtime_io(&staging, &error))?;
        // Both inputs are copied with no-follow semantics on Unix into the
        // private staging directory. Hashing and execution use only these
        // staged copies, never the caller-controlled source paths.
        let staged_bun = staging.join(if cfg!(windows) { "bun.exe" } else { "bun" });
        let tarball_name = "locked-package.tgz";
        let staged_tarball = staging.join(tarball_name);
        let staged_manifest = staging.join("input-manifest.json");
        let staged_lockfile = staging.join("input-lockfile.json");
        copy_regular_file_nofollow(
            bun_executable,
            &staged_bun,
            true,
            ResourceBudget::default().artifact_bytes,
        )?;
        copy_regular_file_nofollow(
            tarball,
            &staged_tarball,
            false,
            ResourceBudget::default().artifact_bytes,
        )?;
        copy_regular_file_nofollow(manifest, &staged_manifest, false, BUN_INPUT_METADATA_LIMIT)?;
        copy_regular_file_nofollow(lockfile, &staged_lockfile, false, BUN_INPUT_METADATA_LIMIT)?;
        if hash_file(&staged_manifest)? != lock.manifest_sha256
            || hash_file(&staged_lockfile)? != lock.lockfile_sha256
        {
            return Err(runtime_error(
                "manifest or lockfile does not match its locked SHA-256",
            ));
        }
        if hash_file(&staged_bun)? != lock.manager_sha256 {
            return Err(runtime_error(
                "selected Bun executable does not match the locked SHA-256",
            ));
        }
        let home = staging.join("home");
        let temp = staging.join("tmp");
        fs::create_dir(&home).map_err(|error| runtime_io(&home, &error))?;
        fs::create_dir(&temp).map_err(|error| runtime_io(&temp, &error))?;
        let package_digest = hash_file(&staged_tarball)?;
        if package_digest != package.sha256 {
            return Err(runtime_error(
                "npm tarball does not match the locked SHA-256",
            ));
        }
        if !verify_file_sri(&staged_tarball, &package.integrity)? {
            return Err(runtime_error("npm tarball does not match locked integrity"));
        }
        let tarball_manifest = validate_npm_archive_metadata(&staged_tarball, package)?;
        let manifest = serde_json::json!({
            "name": "neoenv-locked-package-stage",
            "private": true,
            "dependencies": {
                (package.name.clone()): format!("file:./{tarball_name}")
            }
        });
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|error| runtime_error(error.to_string()))?;
        if fs::read(&staged_manifest).map_err(|error| runtime_io(&staged_manifest, &error))?
            != manifest_bytes
        {
            return Err(runtime_error(
                "verified manifest is not the canonical Bun install manifest for this lock",
            ));
        }
        validate_bun_lockfile(&staged_lockfile, package, &tarball_manifest)?;
        let mut version_command = Command::new(&staged_bun);
        version_command
            .arg("--version")
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", &temp)
            .env("TMP", &temp)
            .env("TEMP", &temp);
        #[cfg(windows)]
        for key in ["PATH", "SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                version_command.env(key, value);
            }
        }
        let version = version_command.output().map_err(|error| {
            runtime_error_with_cause("failed to query selected Bun version", error)
        })?;
        if !version.status.success()
            || String::from_utf8_lossy(&version.stdout).trim() != lock.manager_version
        {
            return Err(runtime_error(
                "selected Bun executable does not match the locked manager version",
            ));
        }
        fs::rename(&staged_manifest, staging.join("package.json"))
            .map_err(|error| runtime_io(&staging, &error))?;
        fs::rename(&staged_lockfile, staging.join("bun.lock"))
            .map_err(|error| runtime_io(&staging, &error))?;
        let mut command = Command::new(&staged_bun);
        command
            .args([
                "install",
                "--offline",
                "--ignore-scripts",
                "--frozen-lockfile",
            ])
            .current_dir(&staging)
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", &temp)
            .env("TMP", &temp)
            .env("TEMP", &temp);
        #[cfg(windows)]
        for key in ["PATH", "SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let output = command
            .output()
            .map_err(|error| runtime_error_with_cause("failed to run Bun install", error))?;
        if !output.status.success() {
            return Err(runtime_error(
                "Bun install failed for the verified local package tarball",
            ));
        }
        let node_modules = staging.join("node_modules");
        require_real_directory(&node_modules, "Bun node_modules root")?;
        let installed_package = node_modules.join(&package.name);
        require_real_directory(&installed_package, "Bun expected package directory")?;
        verify_bun_installed_package(&installed_package, &staged_tarball, package)?;
        fs::remove_dir_all(&home).map_err(|error| runtime_io(&home, &error))?;
        fs::remove_dir_all(&temp).map_err(|error| runtime_io(&temp, &error))?;
        fs::remove_file(&staged_tarball).map_err(|error| runtime_io(&staging, &error))?;
        fs::remove_file(&staged_bun).map_err(|error| runtime_io(&staging, &error))?;
        fs::remove_file(staging.join("package.json"))
            .map_err(|error| runtime_io(&staging, &error))?;
        fs::remove_file(staging.join("bun.lock")).map_err(|error| runtime_io(&staging, &error))?;
        publish_directory_noreplace(&staging, destination)?;
        Ok(destination.to_path_buf())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub(super) fn require_real_directory(path: &Path, label: &str) -> Result<(), Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| runtime_io(path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(runtime_error(format!("{label} is not a real directory")));
    }
    Ok(())
}

/// Accepts only Bun lockfile v2's narrow one-workspace, one-local-tarball shape.
/// Everything else is refused rather than treated as equivalent provenance.
fn validate_bun_lockfile(
    path: &Path,
    package: &super::ManagerPackage,
    tarball_manifest: &serde_json::Value,
) -> Result<(), Diagnostic> {
    let bytes = read_regular_nofollow_bounded(path, 2 * 1024 * 1024)?;
    let normalized = strip_json_trailing_commas(&bytes);
    let value: serde_json::Value = serde_json::from_slice(&normalized)
        .map_err(|_| runtime_error("Bun lockfile is invalid JSON"))?;
    let root = value
        .as_object()
        .ok_or_else(|| runtime_error("unsupported Bun lockfile shape"))?;
    if root.len() != 4
        || root
            .get("lockfileVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
        || root
            .get("configVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
    {
        return Err(runtime_error("unsupported Bun lockfile version or fields"));
    }
    let workspace = root
        .get("workspaces")
        .and_then(serde_json::Value::as_object)
        .and_then(|workspaces| {
            (workspaces.len() == 1)
                .then(|| workspaces.get(""))
                .flatten()
        })
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| runtime_error("Bun lockfile must contain exactly one root workspace"))?;
    if workspace.len() != 2 {
        return Err(runtime_error("unsupported Bun root workspace fields"));
    }
    let deps = workspace
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| runtime_error("Bun lockfile has no root dependencies"))?;
    if workspace.get("name").and_then(serde_json::Value::as_str)
        != Some("neoenv-locked-package-stage")
        || deps.len() != 1
        || deps.get(&package.name).and_then(serde_json::Value::as_str)
            != Some("file:./locked-package.tgz")
    {
        return Err(runtime_error(
            "Bun lockfile root dependency differs from the manager lock",
        ));
    }
    let packages = root
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| runtime_error("Bun lockfile has no package graph"))?;
    let entry = packages
        .get(&package.name)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| runtime_error("Bun lockfile package graph differs from manager lock"))?;
    let package_metadata = entry.get(1).and_then(serde_json::Value::as_object);
    // Bun 1.4.4's generated local-tarball entry contains only `bin` metadata
    // (observed in the required integration lane). Accept an optional version
    // only when it agrees with ManagerLock; no other metadata keys are defined
    // by this supported subset.
    let supported_metadata = package_metadata.is_some_and(|metadata| {
        metadata
            .keys()
            .all(|key| matches!(key.as_str(), "bin" | "version"))
            && metadata.get("bin") == tarball_manifest.get("bin")
            && metadata
                .get("version")
                .is_none_or(|version| version.as_str() == Some(package.version.as_str()))
    });
    if packages.len() != 1
        || entry.len() != 3
        || entry[0].as_str() != Some(format!("{}@./locked-package.tgz", package.name).as_str())
        || entry[2].as_str() != Some(package.integrity.as_str())
        || format!("{}@{}", package.name, package.version) != package.id
        || !supported_metadata
    {
        return Err(runtime_error(
            "Bun lockfile package identity, integrity, or dependency graph differs from manager lock",
        ));
    }
    Ok(())
}

fn strip_json_trailing_commas(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in input.iter().copied().enumerate() {
        if in_string {
            output.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
            output.push(byte);
        } else if byte == b',' {
            let next = input[index + 1..]
                .iter()
                .copied()
                .find(|next| !next.is_ascii_whitespace());
            if !matches!(next, Some(b'}' | b']')) {
                output.push(byte);
            }
        } else {
            output.push(byte);
        }
    }
    output
}

struct ScannedNpmArchive {
    manifest: serde_json::Value,
    expected: std::collections::BTreeMap<String, String>,
}

const NPM_ARCHIVE_MAX_ENTRIES: usize = 20_000;
const NPM_ARCHIVE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const NPM_ARCHIVE_MAX_DECOMPRESSED: u64 = 300 * 1024 * 1024;

pub(super) fn account_bun_package_bytes(total: &mut u64, bytes: u64) -> Result<(), Diagnostic> {
    let next = total
        .checked_add(bytes)
        .filter(|next| *next <= NPM_ARCHIVE_MAX_BYTES)
        .ok_or_else(|| runtime_error("npm package exceeds byte limit"))?;
    *total = next;
    Ok(())
}

/// One structural scan shared by locking, installation, and output checking.
#[allow(clippy::too_many_lines)]
fn scan_npm_archive(tarball: &Path) -> Result<ScannedNpmArchive, Diagnostic> {
    let mut expected = std::collections::BTreeMap::new();
    let file = open_regular_nofollow(tarball)?;
    let compressed = file
        .metadata()
        .map_err(|error| runtime_io(tarball, &error))?
        .len();
    if compressed > ResourceBudget::default().artifact_bytes {
        return Err(runtime_error("npm tarball exceeds artifact size limit"));
    }
    let mut archive = Archive::new(GzDecoder::new(file).take(NPM_ARCHIVE_MAX_DECOMPRESSED + 1));
    let mut total = 0u64;
    let mut entries = 0usize;
    let mut seen = HashSet::new();
    let mut archive_manifest = None;
    let mut budget =
        neoenv_runtime::budget::ExtractionBudget::new(ResourceBudget::default(), Some(compressed));
    let mut scanned = 0u64;
    for entry in archive
        .entries()
        .map_err(|e| runtime_error_with_cause("invalid npm tarball", e))?
    {
        let mut entry =
            entry.map_err(|e| runtime_error_with_cause("invalid npm tarball entry", e))?;
        let relative = entry
            .path()
            .map_err(|e| runtime_error_with_cause("invalid npm tarball path", e))?
            .into_owned();
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || relative.to_str().is_none_or(|path| path.contains('\\'))
        {
            return Err(runtime_error("unsafe path in verified npm archive"));
        }
        if relative.components().next() != Some(std::path::Component::Normal("package".as_ref())) {
            return Err(runtime_error(
                "verified npm archive contains a path outside package/",
            ));
        }
        entries += 1;
        if entries > NPM_ARCHIVE_MAX_ENTRIES {
            return Err(runtime_error("npm package exceeds entry limit"));
        }
        if !seen.insert(relative.clone()) {
            return Err(runtime_error(
                "verified npm archive contains duplicate paths",
            ));
        }
        check_archive_scan_count(&budget, &mut scanned)?;
        let size = entry
            .header()
            .size()
            .map_err(|e| runtime_error_with_cause("invalid npm archive size", e))?;
        budget
            .begin_entry(&relative, Some(size))
            .map_err(budget_error)?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(runtime_error(
                "verified npm archive contains a non-regular entry",
            ));
        }
        let name = relative
            .strip_prefix("package")
            .ok()
            .and_then(Path::to_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| runtime_error("invalid npm package entry path"))?
            .to_owned();
        if name == ".bun-tag" {
            return Err(runtime_error("npm package contains a reserved Bun marker"));
        }
        account_bun_package_bytes(&mut total, size)?;
        if name == "package.json" {
            if size > ResourceBudget::default().metadata_bytes {
                return Err(runtime_error("npm package metadata exceeds the size limit"));
            }
            let mut content = Vec::new();
            (&mut entry)
                .take(size + 1)
                .read_to_end(&mut content)
                .map_err(|e| runtime_error_with_cause("cannot read npm package entry", e))?;
            if content.len() as u64 != size {
                return Err(runtime_error(
                    "npm package entry size differs from its tar header",
                ));
            }
            budget
                .account_entry_bytes(content.len())
                .map_err(budget_error)?;
            archive_manifest = Some(
                serde_json::from_slice(&content)
                    .map_err(|_| runtime_error("npm package.json is invalid"))?,
            );
        } else {
            let mut digest = Sha256::new();
            let mut count = 0u64;
            let mut buffer = vec![0_u8; 32 * 1024];
            loop {
                let read = entry
                    .read(&mut buffer)
                    .map_err(|e| runtime_error_with_cause("cannot read npm package entry", e))?;
                if read == 0 {
                    break;
                }
                count = count.saturating_add(read as u64);
                if count > size {
                    return Err(runtime_error(
                        "npm package entry size differs from its tar header",
                    ));
                }
                budget.account_entry_bytes(read).map_err(budget_error)?;
                digest.update(&buffer[..read]);
            }
            if count != size {
                return Err(runtime_error(
                    "npm package entry size differs from its tar header",
                ));
            }
            expected.insert(name, format!("{:x}", digest.finalize()));
        }
    }
    let mut decompressed = archive.into_inner();
    finish_bounded_decompressed_stream(&mut decompressed, NPM_ARCHIVE_MAX_DECOMPRESSED)?;
    Ok(ScannedNpmArchive {
        manifest: archive_manifest
            .ok_or_else(|| runtime_error("npm tarball has no package/package.json"))?,
        expected,
    })
}

/// Check that Bun published exactly the package files supplied by the verified
/// tarball. This also rejects links and special files in Bun's output.
#[allow(clippy::too_many_lines)]
pub(super) fn verify_bun_installed_package(
    installed: &Path,
    tarball: &Path,
    package: &super::ManagerPackage,
) -> Result<(), Diagnostic> {
    require_real_directory(installed, "Bun package directory")?;
    let manifest = installed.join("package.json");
    let bytes = read_regular_nofollow_bounded(&manifest, 1024 * 1024)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| runtime_error("Bun installed package.json is invalid"))?;
    if value.get("name").and_then(serde_json::Value::as_str) != Some(package.name.as_str())
        || value.get("version").and_then(serde_json::Value::as_str)
            != Some(package.version.as_str())
    {
        return Err(runtime_error(
            "Bun installed package identity differs from the lock",
        ));
    }
    let scanned = scan_npm_archive(tarball)?;
    if scanned.manifest != value {
        return Err(runtime_error(
            "Bun installed package metadata differs from the verified tarball",
        ));
    }
    let expected = scanned.expected;
    // Archive and output are separate populations. Counting both together
    // makes an archive accepted at lock time fail solely because it was
    // materialized. Metadata and Bun's marker have their own small limits.
    let mut output_bytes = 0u64;
    let mut output_entries = 0usize;
    // Bun 1.4.4 writes the package's SRI string to `.bun-tag`; require the
    // exact locked integrity value rather than accepting arbitrary marker data.
    let mut actual = std::collections::BTreeMap::new();
    let mut stack = vec![(installed.to_path_buf(), PathBuf::new())];
    while let Some((directory, relative)) = stack.pop() {
        for item in fs::read_dir(&directory).map_err(|e| runtime_io(&directory, &e))? {
            let item = item.map_err(|e| runtime_io(&directory, &e))?;
            let file_type = item.file_type().map_err(|e| runtime_io(&item.path(), &e))?;
            let rel = relative.join(item.file_name());
            if file_type.is_dir() {
                stack.push((item.path(), rel));
            } else if file_type.is_file() {
                let path = item.path();
                let name = rel.to_string_lossy().replace('\\', "/");
                if name == ".bun-tag" {
                    let bytes = read_regular_nofollow_bounded(&path, 256)?;
                    if bytes != package.integrity.as_bytes() {
                        return Err(runtime_error(
                            "Bun package marker differs from locked package integrity",
                        ));
                    }
                    continue;
                }
                output_entries += 1;
                if output_entries > NPM_ARCHIVE_MAX_ENTRIES {
                    return Err(runtime_error("Bun output exceeds entry limit"));
                }
                // Bun rewrites package.json; it was independently checked
                // above with a 1 MiB cap rather than being counted twice.
                if name == "package.json" {
                    continue;
                }
                let remaining = NPM_ARCHIVE_MAX_BYTES - output_bytes;
                let bytes = read_regular_nofollow_bounded(&path, remaining)?;
                account_bun_package_bytes(&mut output_bytes, bytes.len() as u64)?;
                actual.insert(name, format!("{:x}", Sha256::digest(bytes)));
            } else {
                return Err(runtime_error(
                    "Bun output contains a symlink or special file",
                ));
            }
        }
    }
    if actual != expected {
        return Err(runtime_error(
            "Bun installed files differ from the verified npm tarball",
        ));
    }
    Ok(())
}

pub(super) fn finish_bounded_decompressed_stream<R: Read>(
    reader: &mut io::Take<R>,
    maximum: u64,
) -> Result<(), Diagnostic> {
    io::copy(reader, &mut io::sink())
        .map_err(|error| runtime_error_with_cause("cannot finish npm gzip stream", error))?;
    if maximum + 1 - reader.limit() > maximum {
        return Err(runtime_error(
            "npm tarball exceeds decompressed stream limit",
        ));
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> Result<fs::File, Diagnostic> {
    #[cfg(unix)]
    let file = {
        let fd = open_nofollow(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| runtime_error(format!("cannot safely open Bun output: {e}")))?;
        fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let file = {
        let metadata = fs::symlink_metadata(path).map_err(|e| runtime_io(path, &e))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(runtime_error("Bun output is not a regular file"));
        }
        fs::File::open(path).map_err(|e| runtime_io(path, &e))?
    };
    if !file.metadata().map_err(|e| runtime_io(path, &e))?.is_file() {
        return Err(runtime_error("Bun output is not a regular file"));
    }
    Ok(file)
}

pub(super) fn read_regular_nofollow_bounded(
    path: &Path,
    limit: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let file = open_regular_nofollow(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| runtime_io(path, &e))?;
    if bytes.len() as u64 > limit {
        return Err(runtime_error("Bun output file exceeds size limit"));
    }
    Ok(bytes)
}

fn create_private_staging(parent: &Path, label: &str) -> Result<PathBuf, Diagnostic> {
    for _ in 0..16 {
        let path = temporary_path(parent, label)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(runtime_io(&path, &error)),
        }
    }
    Err(runtime_error(
        "could not allocate a unique Bun package staging directory",
    ))
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Copies a regular source file without following a final symlink.
///
/// On Unix, no-follow opening is atomic. Other hosts first reject symlinks via
/// metadata and then open the file; callers must provide a source directory
/// protected from concurrent mutation on those hosts.
fn copy_regular_file_nofollow(
    source: &Path,
    destination: &Path,
    executable: bool,
    limit: u64,
) -> Result<(), Diagnostic> {
    #[cfg(unix)]
    let mut input = {
        let fd = open_nofollow(
            source,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| runtime_error(format!("cannot safely open selected input: {error}")))?;
        fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let mut input = {
        let metadata = fs::symlink_metadata(source).map_err(|error| runtime_io(source, &error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(runtime_error(
                "selected input must be a regular file, not a symlink",
            ));
        }
        fs::File::open(source).map_err(|error| runtime_io(source, &error))?
    };
    let metadata = input
        .metadata()
        .map_err(|error| runtime_io(source, &error))?;
    if !metadata.is_file() {
        return Err(runtime_error("selected input is not a regular file"));
    }
    if metadata.len() > limit {
        return Err(runtime_error("selected input exceeds its size limit"));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| runtime_io(destination, &error))?;
    copy_bounded_input(&mut input, &mut output, limit)
        .map_err(|error| runtime_io(destination, &error))?;
    output
        .sync_all()
        .map_err(|error| runtime_io(destination, &error))?;
    let mut permissions = metadata.permissions();
    if executable {
        #[cfg(unix)]
        permissions.set_mode((permissions.mode() & 0o555) | 0o500);
        #[cfg(not(unix))]
        permissions.set_readonly(false);
    } else {
        permissions.set_readonly(true);
    }
    fs::set_permissions(destination, permissions).map_err(|error| runtime_io(destination, &error))
}

pub(super) fn copy_bounded_input(
    input: &mut impl Read,
    output: &mut impl io::Write,
    limit: u64,
) -> io::Result<()> {
    io::copy(&mut (&mut *input).take(limit), output)?;
    let mut extra = [0_u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selected input exceeds its size limit",
        ));
    }
    Ok(())
}

fn publish_directory_noreplace(source: &Path, destination: &Path) -> Result<(), Diagnostic> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "redox"))]
    {
        renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
            .map_err(|error| runtime_error(format!("atomic no-replace publish failed: {error}")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "redox")))]
    {
        let _ = (source, destination);
        Err(runtime_error(
            "atomic no-replace directory publication is unsupported on this host",
        ))
    }
}

fn validate_npm_archive_metadata(
    tarball: &Path,
    package: &super::ManagerPackage,
) -> Result<serde_json::Value, Diagnostic> {
    let value = scan_npm_archive(tarball)?.manifest;
    if value.get("name").and_then(serde_json::Value::as_str) != Some(package.name.as_str())
        || value.get("version").and_then(serde_json::Value::as_str)
            != Some(package.version.as_str())
        || format!("{}@{}", package.name, package.version) != package.id
        || [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "devDependencies",
            "bundleDependencies",
            "bundledDependencies",
        ]
        .iter()
        .any(|field| {
            value.get(field).is_some_and(|value| {
                value
                    .as_object()
                    .is_none_or(|dependencies| !dependencies.is_empty())
            })
        })
    {
        return Err(runtime_error(
            "npm package metadata differs from the locked identity or dependency graph",
        ));
    }
    Ok(value)
}

fn safe_package_name(value: &str) -> bool {
    let mut components = value.split('/');
    let first = components.next().unwrap_or_default();
    let valid_component = |component: &str| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if let Some(scope) = first.strip_prefix('@') {
        valid_component(scope)
            && components.next().is_some_and(valid_component)
            && components.next().is_none()
    } else {
        valid_component(first) && components.next().is_none()
    }
}

pub(super) fn hash_file(path: &Path) -> Result<String, Diagnostic> {
    let file = open_regular_nofollow(path)?;
    let mut file = neoenv_runtime::budget::BudgetReader::new(
        file,
        neoenv_runtime::budget::ResourceLimit::Artifact,
        ResourceBudget::default().artifact_bytes,
    );
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| runtime_io(path, &error))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn verify_file_sri(path: &Path, integrity: &str) -> Result<bool, Diagnostic> {
    use super::Sha512;
    let file = open_regular_nofollow(path)?;
    let mut file = neoenv_runtime::budget::BudgetReader::new(
        file,
        neoenv_runtime::budget::ResourceLimit::Artifact,
        ResourceBudget::default().artifact_bytes,
    );
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| runtime_io(path, &error))?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        sha512.update(&buffer[..count]);
    }
    let sha256 = sha256.finalize();
    let sha512 = sha512.finalize();
    Ok(integrity.split_whitespace().any(|entry| {
        let Some((algorithm, encoded)) = entry.split_once('-') else {
            return false;
        };
        let Ok(expected) = super::STANDARD.decode(encoded) else {
            return false;
        };
        match algorithm {
            "sha256" => expected.as_slice() == sha256.as_slice(),
            "sha512" => expected.as_slice() == sha512.as_slice(),
            _ => false,
        }
    }))
}

/// # Errors
///
/// Returns an I/O or serialization diagnostic if the lock cannot be validated
/// or written.
pub fn write_lockfile(path: &Path, plan: &ToolPlan) -> Result<ToolLockfile, Diagnostic> {
    publish_tool_lockfile(path, plan, None)
}

/// The explicit declaration and local inputs associated with a Bun graph.
///
/// Paths must remain stable during validation. The inputs are not persisted
/// by this API and must be independently verified again before installation.
/// The manager evidence must be obtained from [`verify_managed_bun`], whose
/// release-asset trust requirements also apply here.
pub struct BunManagerLockInputs<'a> {
    pub declaration: &'a neoenv_core::tools::ToolDeclaration,
    pub graph: &'a ManagerLock,
    pub managed_bun: &'a VerifiedManagedBun,
    pub tarball: &'a Path,
    pub manifest: &'a Path,
    pub bun_lockfile: &'a Path,
}

/// Write a one-package Bun graph bound to its explicit selection and inputs.
///
/// # Errors
///
/// Refuses mismatched declarations, graph, tarball or inputs before writing.
/// Callers must separately persist the inputs and verify them at install time.
#[allow(clippy::too_many_lines)]
pub fn write_lockfile_with_manager(
    path: &Path,
    plan: &ToolPlan,
    inputs: &BunManagerLockInputs<'_>,
) -> Result<ToolLockfile, Diagnostic> {
    let graph = inputs.graph;
    graph.validate().map_err(|error| lock_error(&error))?;
    let npm = inputs
        .declaration
        .npm
        .as_ref()
        .filter(|_| inputs.declaration.provider == neoenv_core::tools::ToolProvider::Npm)
        .ok_or_else(|| runtime_error("manager graph requires an npm declaration"))?;
    let manager = npm
        .manager
        .as_ref()
        .ok_or_else(|| runtime_error("manager graph requires an explicit manager declaration"))?;
    if manager.name != neoenv_core::tools::NpmManagerName::Bun
        || !neoenv_core::tools::is_exact_manager_version(&manager.version)
        || graph.manager != "bun"
        || graph.manager_version != manager.version
        || graph.runtime_version != manager.version
        || inputs.managed_bun.version != manager.version
        || manager
            .archive_sha256
            .as_ref()
            .is_some_and(|pin| pin != &inputs.managed_bun.archive_sha256)
        || inputs.managed_bun.executable_sha256 != graph.manager_sha256
        || graph.runtime_archive.as_ref().is_none_or(|archive| {
            archive.url != inputs.managed_bun.archive_url
                || archive.sha256 != inputs.managed_bun.archive_sha256
        })
        || graph.packages.len() != 1
        || !graph.packages[0].dependencies.is_empty()
    {
        return Err(runtime_error(
            "unsupported or mismatched Bun manager selection or graph",
        ));
    }
    let package = &graph.packages[0];
    // The current lock schema has a single unlabelled manager graph. Until it
    // carries per-tool associations, accepting multiple npm tools would make
    // that association ambiguous when the lock is read back.
    if plan
        .tools
        .iter()
        .filter(|tool| tool.provenance.provider == "npm")
        .count()
        != 1
    {
        return Err(runtime_error(
            "Bun manager lock requires exactly one npm tool in the plan",
        ));
    }
    let mut selected = plan
        .tools
        .iter()
        .filter(|tool| tool.id == inputs.declaration.id);
    let tool = selected
        .next()
        .ok_or_else(|| runtime_error("manager graph has no selected tool in plan"))?;
    if selected.next().is_some()
        || tool.provenance.provider != "npm"
        || npm.package != package.name
        || super::canonical_http_url(&npm.endpoint).ok().as_deref()
            != tool.provenance.registry_endpoint.as_deref()
        || (inputs.declaration.version != "latest"
            && inputs.declaration.version != tool.resolved_version)
        || tool.provenance.package.as_deref() != Some(package.name.as_str())
        || tool.resolved_version != package.version
        || tool.url != package.tarball_url
        || tool.sha256 != package.sha256
        || tool.verification.sha256 != package.sha256
        || tool.provenance.registry_integrity.as_deref() != Some(package.integrity.as_str())
        || package.id != format!("{}@{}", package.name, package.version)
        || !safe_package_name(&package.name)
    {
        return Err(runtime_error(
            "manager graph differs from selected npm tool",
        ));
    }
    let manifest = read_regular_nofollow_bounded(inputs.manifest, 2 * 1024 * 1024)?;
    let bun_lock = read_regular_nofollow_bounded(inputs.bun_lockfile, 2 * 1024 * 1024)?;
    if !fs::symlink_metadata(&inputs.managed_bun.executable)
        .map_err(|error| runtime_io(&inputs.managed_bun.executable, &error))?
        .file_type()
        .is_file()
        || hash_file(&inputs.managed_bun.executable)? != graph.manager_sha256
        || format!("{:x}", Sha256::digest(&manifest)) != graph.manifest_sha256
        || format!("{:x}", Sha256::digest(&bun_lock)) != graph.lockfile_sha256
        || hash_file(inputs.tarball)? != package.sha256
        || !verify_file_sri(inputs.tarball, &package.integrity)?
    {
        return Err(runtime_error(
            "Bun manager inputs differ from their locked hashes",
        ));
    }
    let expected_manifest = serde_json::to_vec(&serde_json::json!({
        "name": "neoenv-locked-package-stage",
        "private": true,
        "dependencies": { (package.name.clone()): "file:./locked-package.tgz" }
    }))
    .map_err(|error| runtime_error(error.to_string()))?;
    if manifest != expected_manifest {
        return Err(runtime_error(
            "Bun manager manifest differs from selected package",
        ));
    }
    let metadata = validate_npm_archive_metadata(inputs.tarball, package)?;
    validate_bun_lockfile(inputs.bun_lockfile, package, &metadata)?;
    publish_tool_lockfile(path, plan, Some(graph.clone()))
}

fn publish_tool_lockfile(
    path: &Path,
    plan: &ToolPlan,
    manager_lock: Option<ManagerLock>,
) -> Result<ToolLockfile, Diagnostic> {
    let mut lockfile = ToolLockfile::from_plan(plan);
    lockfile.manager_lock = manager_lock;
    // Probe without following the final symlink, so a dangling lockfile link
    // cannot be mistaken for a new lock. Only absence permits creation.
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let existing = read_lockfile(path)?;
            if existing.manager_lock.is_some() && lockfile.manager_lock.is_none() {
                return Err(runtime_error(
                    "refusing to discard the existing package-manager lock; an explicit validated migration is required",
                ));
            }
            if existing.cargo_build.is_some() && lockfile.cargo_build.is_none() {
                return Err(runtime_error(
                    "refusing to discard the existing Cargo build provenance; an explicit validated migration is required",
                ));
            }
            lockfile.pins = existing.pins;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime_io(path, &error)),
    }
    lockfile.validate().map_err(|error| lock_error(&error))?;
    let output = toml::to_string_pretty(&lockfile)
        .map_err(|error| diagnostic("NEO512", error.to_string()))?;
    let parent = path.parent().ok_or_else(|| {
        diagnostic(
            "NEO512",
            format!("tool lockfile has no parent: {}", path.display()),
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    state_file::write_atomic(path, output.as_bytes()).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO520",
            format!("filesystem error at {}: {error}", path.display()),
        )
        .with_cause(error)
    })?;
    Ok(lockfile)
}

/// # Errors
///
/// Returns a not-found, parsing, or validation diagnostic when the lock cannot
/// be read or differs from the supplied plan.
pub fn verify_lockfile(path: &Path, plan: &ToolPlan) -> Result<ToolLockfile, Diagnostic> {
    let lockfile = read_lockfile(path)?;
    verify_tool_plan(plan, &lockfile).map_err(|error| verification_error(&error))?;
    Ok(lockfile)
}

/// Reads and validates a lockfile without resolving current declarations.
///
/// # Errors
///
/// Returns a diagnostic when the lockfile cannot be read, parsed, or validated.
pub fn read_lockfile(path: &Path) -> Result<ToolLockfile, Diagnostic> {
    // Preserve shared UTF-8 validation and metadata-budget diagnostics. The
    // lock-specific 32 MiB ceiling is a hard upper bound, while the shared
    // default (currently 1 MiB) is stricter and remains the effective cap.
    const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;
    let mut budget = ResourceBudget::default();
    budget.metadata_bytes = budget.metadata_bytes.min(MAX_LOCKFILE_BYTES);
    let input = read_text_file(path, &budget).map_err(|error| file_error(path, &error))?;
    let lockfile: ToolLockfile = toml::from_str(&input).map_err(|error| {
        diagnostic(
            "NEO513",
            format!("invalid tool lockfile {}: {error}", path.display()),
        )
    })?;
    lockfile.validate().map_err(|error| lock_error(&error))?;
    Ok(lockfile)
}

/// An installed lock entry. A tool is listed only when every declared binary is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledTool {
    pub id: String,
    pub resolved_version: String,
    pub bin_dir: PathBuf,
    pub url: String,
    pub sha256: String,
    pub resolver: String,
}

/// Local state for every lock entry. This is derived only from the lock and
/// project filesystem; inspection never resolves providers or contacts a network.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolState {
    pub id: String,
    pub resolved_version: String,
    pub provider: String,
    pub installed: bool,
    pub bin_dir: PathBuf,
    pub url: String,
    pub sha256: String,
    pub immutable_id: String,
}

/// A local cache entry selected for removal by cleanup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CleanupEntry {
    pub kind: String,
    pub path: PathBuf,
}

/// Metadata retained beside an atomically published installation.
///
/// The metadata makes lifecycle operations able to distinguish an older
/// nenv-owned version from a foreign directory that happens to use the
/// content-addressed storage layout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct InstallMetadata {
    id: String,
    resolved_version: String,
    sha256: String,
    #[serde(default)]
    storage_key: String,
}

/// One published, content-addressed installation known to `nenv`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledVersion {
    pub id: String,
    pub resolved_version: String,
    pub sha256: String,
    pub path: PathBuf,
}

/// Requires associated Cargo provenance and an explicit execution capability.
///
/// This preflight is intentionally pure and must run before any installer creates
/// storage, staging directories, or contacts an artifact source.
///
/// # Errors
///
/// Returns a validation diagnostic when Cargo declarations and lock evidence
/// are ambiguous, inconsistent, or lack the explicit build capability.
pub fn reject_unimplemented_cargo_install(
    declarations: &[neoenv_core::tools::ToolDeclaration],
    lockfile: &ToolLockfile,
) -> Result<(), Diagnostic> {
    validate_cargo_install_association(declarations, lockfile)?;
    let locked_cargo_count = lockfile
        .tools
        .iter()
        .filter(|tool| tool.resolver == "cargo")
        .count();
    if locked_cargo_count > 0 && std::env::var("NEOENV_ALLOW_CARGO_BUILD").as_deref() != Ok("1") {
        return Err(runtime_error(
            "Cargo source builds execute compiler inputs; set NEOENV_ALLOW_CARGO_BUILD=1 to grant this capability",
        ));
    }
    Ok(())
}

/// Validates Cargo declaration, lock entry, and build provenance association.
///
/// This pure validation is used by executable lookup; it does not require the
/// installation capability grant.
///
/// # Errors
///
/// Returns a diagnostic if the declaration and locked build evidence disagree.
pub fn validate_cargo_install_association(
    declarations: &[neoenv_core::tools::ToolDeclaration],
    lockfile: &ToolLockfile,
) -> Result<(), Diagnostic> {
    let declaration_cargo_count = declarations
        .iter()
        .filter(|tool| tool.provider == neoenv_core::tools::ToolProvider::Cargo)
        .count();
    let locked_cargo_count = lockfile
        .tools
        .iter()
        .filter(|tool| tool.resolver == "cargo")
        .count();
    let association_matches = if declarations.is_empty() {
        if locked_cargo_count == 0 {
            lockfile.cargo_build.is_none()
        } else {
            lockfile.cargo_build.as_ref().is_some_and(|build| {
                lockfile.tools.iter().any(|tool| {
                    tool.id == build.tool_id
                        && tool.resolver == "cargo"
                        && tool.resolved_version == build.version
                        && tool.sha256 == build.checksum
                        && tool.cargo_toolchain.as_deref() == Some(build.toolchain.as_str())
                        && tool.provenance.package.as_deref() == Some(build.crate_name.as_str())
                })
            })
        }
    } else {
        declarations
            .iter()
            .find(|declaration| declaration.provider == neoenv_core::tools::ToolProvider::Cargo)
            .zip(lockfile.cargo_build.as_ref())
            .and_then(|(declaration, build)| {
                let tool = lockfile
                    .tools
                    .iter()
                    .find(|entry| entry.id == build.tool_id)?;
                let cargo = declaration.cargo.as_ref()?;
                let expected_url = format!(
                    "https://static.crates.io/crates/{0}/{0}-{1}.crate",
                    cargo.crate_name, cargo.version
                );
                Some(
                    declaration.id == build.tool_id
                        && cargo.version == build.version
                        && cargo.crate_name == build.crate_name
                        && cargo.registry == build.registry
                        && cargo.checksum == build.checksum
                        && cargo.scripts == build.scripts
                        && cargo.build == build.build
                        && cargo.network == build.network
                        && declaration.version == tool.resolved_version
                        && declaration.binaries == tool.binaries
                        && expected_url == tool.url
                        && tool.sha256 == build.checksum
                        && tool.resolver == "cargo"
                        && tool.cargo_toolchain.as_deref() == Some(build.toolchain.as_str())
                        && neoenv_core::tools::cargo_toolchain_for_platform(
                            &cargo.toolchain,
                            &tool.platform,
                        )
                        .as_deref()
                            == Some(build.toolchain.as_str()),
                )
            })
            .unwrap_or(locked_cargo_count == 0 && declaration_cargo_count == 0)
    };
    if !association_matches
        || declaration_cargo_count > 1
        || locked_cargo_count > 1
        || (declaration_cargo_count > 0 && locked_cargo_count != 1)
        || (!declarations.is_empty() && (declaration_cargo_count > 0) != (locked_cargo_count > 0))
        || (locked_cargo_count > 0 && lockfile.cargo_build.is_none())
        || (!declarations.is_empty()
            && locked_cargo_count > 0
            && !declarations.iter().any(|declaration| {
                declaration.provider == neoenv_core::tools::ToolProvider::Cargo
                    && lockfile
                        .cargo_build
                        .as_ref()
                        .is_some_and(|build| declaration.id == build.tool_id)
            }))
    {
        return Err(runtime_error(
            "Cargo installation requires one fully associated declaration and lock entry",
        ));
    }
    Ok(())
}

/// Builds one dependency-free crate from its checksum-verified registry archive.
///
/// The source archive is extracted into private staging. Build scripts and all
/// dependency classes are rejected; Cargo runs with an empty `CARGO_HOME`,
/// `--offline`, and the exact Cargo/rustc binaries from the requested
/// neoenv-managed toolchain. This is not a general sandbox. The capability
/// grant is required because Cargo invokes compiler inputs; this supported
/// subset prevents build scripts and external crate code from running.
///
/// # Errors
///
/// Returns an error for a missing capability/toolchain, unsupported manifest,
/// compiler failure, missing declared binary, or publication failure.
#[cfg(unix)]
fn publish_cargo_install(
    artifact: &Path,
    root: &Path,
    tool: &LockedTool,
    build: &neoenv_core::tools::CargoBuildLock,
) -> Result<(), Diagnostic> {
    let runtime_data =
        neoenv_runtime::paths::neoenv_directory(neoenv_runtime::paths::UserDirectory::Data)
            .ok_or_else(|| runtime_error("cannot determine neoenv runtime data directory"))?;
    publish_cargo_install_at(
        artifact,
        root,
        tool,
        build,
        &runtime_data,
        std::env::var("NEOENV_ALLOW_CARGO_BUILD").as_deref() == Ok("1"),
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub(super) fn publish_cargo_install_at(
    artifact: &Path,
    root: &Path,
    tool: &LockedTool,
    build: &neoenv_core::tools::CargoBuildLock,
    runtime_data: &Path,
    capability_granted: bool,
) -> Result<(), Diagnostic> {
    use std::os::unix::fs::PermissionsExt;

    if !capability_granted {
        return Err(runtime_error(
            "Cargo source build requires NEOENV_ALLOW_CARGO_BUILD=1",
        ));
    }
    if build.tool_id != tool.id
        || build.version != tool.resolved_version
        || tool.provenance.package.as_deref() != Some(build.crate_name.as_str())
        || tool.sha256 != build.checksum
    {
        return Err(runtime_error(
            "Cargo build lock does not match the selected tool",
        ));
    }
    let Some((version, target)) = build.toolchain.split_once('-') else {
        return Err(runtime_error(
            "Cargo lock does not name an exact Rust target",
        ));
    };
    let runtime_root = runtime_data.join("rust").join(version);
    let rust_home = runtime_root.join("rustup");
    let toolchain_bin = rust_home
        .join("toolchains")
        .join(format!("{version}-{target}"))
        .join("bin");
    let cargo = toolchain_bin.join(if cfg!(windows) { "cargo.exe" } else { "cargo" });
    let rustc = toolchain_bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
    if !usable_file(&cargo) || !usable_file(&rustc) {
        return Err(runtime_error(
            "requested exact Cargo toolchain is not installed by neoenv; refusing PATH fallback",
        ));
    }
    if !runtime_root
        .join(neoenv_core::names::RUST_RUNTIME_RECEIPT)
        .is_file()
    {
        return Err(runtime_error(
            "requested Rust toolchain lacks a neoenv runtime receipt",
        ));
    }
    for (binary, expected) in [
        (&cargo, format!("cargo {version}")),
        (&rustc, format!("rustc {version}")),
    ] {
        let output = Command::new(binary)
            .arg("--version")
            .env_clear()
            .output()
            .map_err(|_| runtime_error("failed to verify the neoenv-managed Rust toolchain"))?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout).starts_with(&expected)
        {
            return Err(runtime_error(
                "installed Cargo toolchain version differs from the lock",
            ));
        }
    }
    let target_info = Command::new(&rustc)
        .args(["-vV"])
        .env_clear()
        .output()
        .map_err(|_| runtime_error("failed to inspect the neoenv-managed Rust target"))?;
    if !target_info.status.success()
        || !String::from_utf8_lossy(&target_info.stdout)
            .lines()
            .any(|line| line == format!("host: {target}"))
    {
        return Err(runtime_error("installed Rust target differs from the lock"));
    }
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("invalid Cargo install root"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let staging = temporary_path(parent, "cargo-build")?;
    fs::create_dir(&staging).map_err(|error| runtime_io(&staging, &error))?;
    let workspace = match tempfile::Builder::new()
        .prefix("neoenv-cargo-build-")
        .tempdir_in(runtime_data)
    {
        Ok(workspace) => workspace,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(runtime_error(format!(
                "cannot create private Cargo workspace: {error}"
            )));
        }
    };
    let result = (|| {
        let source = workspace.path().join("source");
        fs::create_dir(&source).map_err(|error| runtime_io(&source, &error))?;
        let archive = fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?;
        let mut budget = extraction_reader_budget();
        super::archive::extract_tar_with_budget(GzDecoder::new(archive), &source, &mut budget)?;
        let crate_root = source.join(format!("{}-{}", build.crate_name, build.version));
        reject_extracted_cargo_config(&crate_root, workspace.path())?;
        let manifest_path = crate_root.join("Cargo.toml");
        let manifest_bytes =
            fs::read(&manifest_path).map_err(|error| runtime_io(&manifest_path, &error))?;
        let manifest: toml::Value = toml::from_slice(&manifest_bytes)
            .map_err(|_| runtime_error("Cargo crate manifest is invalid TOML"))?;
        validate_cargo_single_crate(&manifest, &crate_root, build, &tool.binaries)?;
        reject_unconfined_cargo_sources(&crate_root, &manifest)?;
        // Make the staged package its own Cargo workspace so a user's
        // unrelated ancestor Cargo.toml cannot affect this offline build.
        let mut staged_manifest = manifest_bytes;
        staged_manifest.extend_from_slice(b"\n[workspace]\n");
        fs::write(&manifest_path, staged_manifest)
            .map_err(|error| runtime_io(&manifest_path, &error))?;
        let home = workspace.path().join("home");
        let cargo_home = workspace.path().join("cargo-home");
        fs::create_dir(&home).map_err(|error| runtime_io(&home, &error))?;
        fs::create_dir(&cargo_home).map_err(|error| runtime_io(&cargo_home, &error))?;
        let build_command = |command: &mut Command| {
            command
                .current_dir(&crate_root)
                .env_clear()
                .env("HOME", &home)
                .env("CARGO_HOME", &cargo_home)
                .env("RUSTUP_HOME", &rust_home)
                .env("RUSTC", &rustc)
                .env("CARGO_NET_OFFLINE", "true")
                .env("CARGO_INCREMENTAL", "0")
                .env("CARGO_TERM_COLOR", "never")
                // Cargo and rustc are invoked by absolute managed paths; PATH
                // remains available only for the host linker toolchain.
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        };
        let generated_lock = Command::new(&cargo);
        let mut generated_lock = generated_lock;
        build_command(&mut generated_lock);
        let output = generated_lock
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(&manifest_path)
            .output()
            .map_err(|_| runtime_error("failed to start the neoenv-managed Cargo binary"))?;
        if !output.status.success() {
            return Err(runtime_error(
                "Cargo could not create the dependency-free offline lock",
            ));
        }
        let mut cargo_build = Command::new(&cargo);
        build_command(&mut cargo_build);
        let output = cargo_build
            .args([
                "build",
                "--locked",
                "--offline",
                "--bins",
                "--manifest-path",
            ])
            .arg(&manifest_path)
            .arg("--target-dir")
            .arg(workspace.path().join("target"))
            .output()
            .map_err(|_| runtime_error("failed to start the neoenv-managed Cargo binary"))?;
        #[cfg(test)]
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        if !output.status.success() {
            return Err(runtime_error("Cargo source build failed"));
        }
        let bin = staging.join("payload/bin");
        fs::create_dir_all(&bin).map_err(|error| runtime_io(&bin, &error))?;
        for name in &tool.binaries {
            let executable = workspace.path().join("target/debug").join(name);
            if !usable_file(&executable) {
                return Err(runtime_error(
                    "Cargo crate did not produce every declared binary",
                ));
            }
            let published = bin.join(name);
            fs::copy(&executable, &published).map_err(|error| runtime_io(&published, &error))?;
            fs::set_permissions(&published, fs::Permissions::from_mode(0o755))
                .map_err(|error| runtime_io(&published, &error))?;
        }
        let payload = staging.join("payload");
        write_install_metadata(&payload, tool)?;
        fs::write(payload.join(INSTALL_RECEIPT), &tool.sha256)
            .map_err(|error| runtime_io(&payload, &error))?;
        let identity = cargo_install_identity(tool, build)?;
        fs::write(payload.join(CARGO_BUILD_RECEIPT), identity)
            .map_err(|error| runtime_io(&payload, &error))?;
        publish_directory_noreplace(&payload, root)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

fn reject_extracted_cargo_config(crate_root: &Path, workspace: &Path) -> Result<(), Diagnostic> {
    if !crate_root.starts_with(workspace) {
        return Err(runtime_error(
            "staged Cargo crate escaped its private workspace",
        ));
    }
    for ancestor in crate_root.ancestors() {
        let cargo_dir = ancestor.join(".cargo");
        let crate_local_config = ancestor == crate_root && fs::symlink_metadata(&cargo_dir).is_ok();
        let inherited_config = ["config.toml", "config"]
            .iter()
            .any(|name| fs::symlink_metadata(cargo_dir.join(name)).is_ok());
        if crate_local_config || inherited_config {
            return Err(runtime_error(
                "Cargo crate or extracted ancestor contains local Cargo configuration",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_cargo_install(
    _artifact: &Path,
    _root: &Path,
    _tool: &LockedTool,
    _build: &neoenv_core::tools::CargoBuildLock,
) -> Result<(), Diagnostic> {
    Err(runtime_error(
        "Cargo source builds are currently supported only on Unix hosts",
    ))
}

#[allow(clippy::too_many_lines)] // Manifest identity and source confinement are one validation boundary.
pub(super) fn validate_cargo_single_crate(
    manifest: &toml::Value,
    crate_root: &Path,
    build: &neoenv_core::tools::CargoBuildLock,
    requested_binaries: &[String],
) -> Result<(), Diagnostic> {
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| runtime_error("Cargo manifest has no package table"))?;
    if package.get("name").and_then(toml::Value::as_str) != Some(build.crate_name.as_str())
        || package.get("version").and_then(toml::Value::as_str) != Some(build.version.as_str())
        || package.contains_key("build")
        || package.contains_key("links")
        || manifest.get("workspace").is_some()
        || manifest.get("lib").is_some()
        || crate_root.join("src/lib.rs").exists()
        || crate_root.join("build.rs").exists()
        || manifest
            .get("lib")
            .and_then(toml::Value::as_table)
            .is_some_and(|lib| {
                lib.get("proc-macro")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false)
                    || lib
                        .get("crate-type")
                        .and_then(toml::Value::as_array)
                        .is_some_and(|kinds| {
                            kinds.iter().any(|kind| kind.as_str() == Some("proc-macro"))
                        })
            })
    {
        return Err(runtime_error(
            "Cargo crate must match its lock and may not use workspaces, links, or build scripts",
        ));
    }
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if manifest
            .get(key)
            .and_then(toml::Value::as_table)
            .is_some_and(|table| !table.is_empty())
        {
            return Err(runtime_error(
                "Cargo crate dependencies are not supported by this offline single-crate backend",
            ));
        }
    }
    if manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| !targets.is_empty())
    {
        return Err(runtime_error(
            "target-specific Cargo dependencies are not supported",
        ));
    }
    let targets = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| runtime_error("Cargo crate must declare explicit [[bin]] targets"))?;
    let declared: HashSet<_> = targets
        .iter()
        .filter_map(|target| target.get("name").and_then(toml::Value::as_str))
        .collect();
    if declared.len() != targets.len()
        || declared.len() != requested_binaries.len()
        || requested_binaries
            .iter()
            .any(|name| !declared.contains(name.as_str()))
    {
        return Err(runtime_error(
            "Cargo crate has an invalid or ambiguous binary target",
        ));
    }
    for target in targets {
        let target_name = target
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| runtime_error("Cargo crate has an invalid binary target"))?;
        let relative_path = target
            .get("path")
            .and_then(toml::Value::as_str)
            .map(Path::new)
            .map_or_else(
                || PathBuf::from("src/bin").join(format!("{target_name}.rs")),
                Path::to_path_buf,
            );
        if relative_path.is_absolute()
            || relative_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(runtime_error(
                "Cargo binary source path must remain inside the verified crate archive",
            ));
        }
        let target_path = crate_root.join(relative_path);
        let canonical_root = crate_root
            .canonicalize()
            .map_err(|error| runtime_io(crate_root, &error))?;
        let canonical_source = target_path.canonicalize().map_err(|_| {
            runtime_error("Cargo binary source is missing from the verified archive")
        })?;
        if !canonical_source.starts_with(&canonical_root) || !canonical_source.is_file() {
            return Err(runtime_error(
                "Cargo binary source path must remain inside the verified crate archive",
            ));
        }
    }
    Ok(())
}

pub(super) fn reject_unconfined_cargo_sources(
    crate_root: &Path,
    manifest: &toml::Value,
) -> Result<(), Diagnostic> {
    let explicit_targets = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|target| {
            let name = target.get("name").and_then(toml::Value::as_str)?;
            Some(
                target
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .map_or_else(
                        || PathBuf::from("src/bin").join(format!("{name}.rs")),
                        PathBuf::from,
                    ),
            )
        })
        .collect::<HashSet<_>>();
    let mut pending = vec![crate_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| runtime_io(&directory, &error))? {
            let entry = entry.map_err(|error| runtime_io(&directory, &error))?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| runtime_io(&path, &error))?;
            if metadata.file_type().is_symlink() {
                return Err(runtime_error(
                    "Cargo source tree contains a symlink and is not confined to the verified archive",
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && (path.extension().is_some_and(|extension| extension == "rs")
                    || path
                        .strip_prefix(crate_root)
                        .is_ok_and(|relative| explicit_targets.contains(relative)))
            {
                let source =
                    fs::read_to_string(&path).map_err(|error| runtime_io(&path, &error))?;
                if contains_raw_string_prefix(&source) {
                    return Err(runtime_error(
                        "Cargo sources with raw strings are refused because the source scan cannot safely distinguish their contents from comments",
                    ));
                }
                let without_comments = strip_rust_comments(&source).ok_or_else(|| {
                    runtime_error(
                        "Cargo sources with character literals or uncertain quoting are refused because the source scan cannot safely classify tokens",
                    )
                })?;
                let compact: String = without_comments
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                if ["include", "include_str", "include_bytes"]
                    .iter()
                    .any(|identifier| contains_rust_identifier(&without_comments, identifier))
                    || compact.contains("macro_rules!")
                    || compact.contains("#[path")
                    || (compact.contains("cfg_attr") && compact.contains("path="))
                    || contains_unapproved_attribute(&compact)
                {
                    return Err(runtime_error(
                        "Cargo sources using include macros, macro definitions, procedural attributes, or conditional module paths are refused because compilation is not filesystem-sandboxed",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn contains_rust_identifier(source: &str, identifier: &str) -> bool {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == identifier)
}

fn contains_raw_string_prefix(source: &str) -> bool {
    let bytes = source.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b'r' {
            return false;
        }
        let mut end = index + 1;
        while bytes.get(end) == Some(&b'#') {
            end += 1;
        }
        bytes.get(end) == Some(&b'"')
    })
}

fn contains_unapproved_attribute(source: &str) -> bool {
    const BUILTIN_ATTRIBUTES: &[&str] = &[
        "allow",
        "cfg",
        "deny",
        "deprecated",
        "doc",
        "expect",
        "forbid",
        "inline",
        "must_use",
        "no_mangle",
        "non_exhaustive",
        "repr",
        "track_caller",
        "warn",
    ];
    if source.contains("#![") {
        return true;
    }
    let mut remaining = source;
    while let Some(attribute_start) = remaining.find("#[") {
        remaining = &remaining[attribute_start + 2..];
        let end = remaining
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(remaining.len());
        let name = &remaining[..end];
        if !BUILTIN_ATTRIBUTES.contains(&name) {
            return true;
        }
        remaining = &remaining[end..];
    }
    false
}

fn strip_rust_comments(source: &str) -> Option<String> {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = characters.next() {
        if in_string {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
            output.push(character);
        } else if character == '\'' {
            // Lifetimes and character literals share punctuation in Rust. This
            // conservative scan refuses either rather than misclassifying a
            // quote and accidentally treating following code as a comment.
            return None;
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            for comment_character in characters.by_ref() {
                if comment_character == '\n' {
                    output.push('\n');
                    break;
                }
            }
            output.push(' ');
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            let mut depth = 1_u32;
            while depth > 0 {
                let Some(comment_character) = characters.next() else {
                    break;
                };
                if comment_character == '/' && characters.peek() == Some(&'*') {
                    characters.next();
                    depth = depth.saturating_add(1);
                } else if comment_character == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    depth -= 1;
                }
            }
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    Some(output)
}

/// Downloads, verifies, extracts, and atomically publishes every locked tool
/// in a project's historical storage layout.
///
/// # Errors
///
/// Returns a runtime diagnostic for invalid locked assets, download, checksum,
/// extraction, or filesystem failures.
pub fn install_locked_tools(
    project_root: &Path,
    lockfile: &ToolLockfile,
) -> Result<Vec<InstalledTool>, Diagnostic> {
    install_locked_tools_in(&ToolStorage::project(project_root), lockfile)
}

/// The storage-aware form of [`install_locked_tools`].
///
/// The installed-state check deliberately precedes artifact access.  This is
/// what makes a previously installed locked tool usable offline: a complete
/// receipt and binary set are sufficient, so no metadata or artifact request
/// is attempted merely to report an already-installed tool.
///
/// # Errors
///
/// Returns a diagnostic when the lock, artifact, extraction, or filesystem
/// operation cannot be completed.
pub fn install_locked_tools_in(
    storage: &ToolStorage,
    lockfile: &ToolLockfile,
) -> Result<Vec<InstalledTool>, Diagnostic> {
    install_locked_tools_in_on(storage, lockfile, &neoenv_core::tools::Platform::host())
}

/// [`install_locked_tools_in`] with the host platform supplied rather than read.
///
/// The split exists so the platform checks can be exercised for a host this machine is
/// not. Every one of them is a *32-bit-host* check -- a 64-bit artifact on a 32-bit
/// host is the only direction that cannot run -- so on any 64-bit machine the
/// `Platform::host()` form leaves the interesting branch unobservable, and a gate
/// running on `x86_64` and `aarch64` runners would never reach it. Reading the
/// environment in a thin wrapper and taking it as a parameter everywhere else keeps the
/// real code path and the test on the same code.
///
/// # Errors
///
/// Returns the same diagnostics as [`install_locked_tools_in`], with `host` standing
/// in for the machine's own platform.
pub fn install_locked_tools_in_on(
    storage: &ToolStorage,
    lockfile: &ToolLockfile,
    host: &neoenv_core::tools::Platform,
) -> Result<Vec<InstalledTool>, Diagnostic> {
    lockfile.validate().map_err(|error| lock_error(&error))?;
    reject_unimplemented_cargo_install(&[], lockfile)?;
    // Until the lifecycle can bind a verified managed Bun and its persisted
    // inputs to this lock, never reinterpret an npm package as a plain archive.
    // Preflight the whole set before changing any installed tools.
    if lockfile.manager_lock.is_some() && lockfile.tools.iter().any(|tool| tool.resolver == "npm") {
        return Err(runtime_error(
            "npm tool installation requires the managed Bun lock lifecycle, which is not yet available; refusing direct archive installation",
        ));
    }
    let mut installed = Vec::with_capacity(lockfile.tools.len());
    for tool in &lockfile.tools {
        if tool.platform != *host {
            return Err(runtime_error(format!(
                "locked tool {} targets {}/{} rather than this host",
                tool.id, tool.platform.os, tool.platform.arch
            )));
        }
        // **A lock is a claim about what was downloaded, and the check above takes that
        // claim at face value.** `LockedTool::platform` is copied from the *host* at
        // plan time on every path -- explicit `asset:` included -- so it records what
        // machine planned the lock and nothing about which architecture the URL
        // actually is. A lock written before the 32-bit ARM width guard existed
        // therefore says `linux/arm` while pointing at `.../linux_arm64.tar.gz`,
        // passes the check above, and installs a 64-bit binary: marked executable,
        // receipted, launcher published, failing only at first run with
        // `Exec format error`.
        //
        // Upgrading does not fix an already-written lock, and nothing told the user to
        // re-lock. This is the one place that can, because it is the last place before
        // the bytes are fetched.
        //
        // The direction is *wider*, not merely *different*: a 32-bit artifact on a
        // 64-bit host runs, so refusing it would break a working install -- including
        // one a user asked for explicitly. Only the direction that cannot run at all
        // is refused. See `names_a_wider_architecture`.
        let artifact_name = locked_artifact_name(&tool.url);
        if let Some(wider) = neoenv_core::tools::names_a_wider_architecture(artifact_name, host) {
            return Err(runtime_error(format!(
                "locked tool {} records {}/{} but its artifact {artifact_name:?} is a \
                 {wider} build, which this host cannot execute; re-lock it on this \
                 machine to pick an asset that matches",
                tool.id, tool.platform.os, tool.platform.arch
            )));
        }
        let root = install_root(storage, tool)?;
        if tool.resolver == "cargo"
            && root.exists()
            && !cargo_receipt_matches(storage, tool, lockfile)
        {
            return Err(runtime_error(
                "existing Cargo installation was built from different locked inputs; refusing stale reuse",
            ));
        }
        if let Some(description) = installed_tool(storage, tool) {
            if !root.join(INSTALL_METADATA).is_file() {
                write_install_metadata(&root, tool)?;
            }
            installed.push(description);
            continue;
        }
        let artifact = ensure_artifact(storage, tool)?;
        if tool.resolver == "cargo" {
            let build = lockfile
                .cargo_build
                .as_ref()
                .ok_or_else(|| runtime_error("Cargo lock entry lacks its build record"))?;
            publish_cargo_install(&artifact, &root, tool, build)?;
        } else if tool.resolver == "go-module" {
            publish_go_module_install(&artifact, &root, tool)?;
        } else {
            publish_install(&artifact, &root, tool)?;
        }
        let description = installed_tool(storage, tool).ok_or_else(|| {
            runtime_error(format!(
                "installed tool {} did not produce a complete binary set",
                tool.id
            ))
        })?;
        installed.push(description);
    }
    Ok(installed)
}

/// The file name a locked URL points at, or `""` when it has none.
///
/// Deliberately a **text** split rather than a URL parse. This is a second opinion on
/// a URL the planner already canonicalized through `Url::parse`, and it only ever
/// *narrows* what the installer will do: a name this cannot read is treated as naming
/// no architecture, which is the pre-existing behaviour. A parse that failed would be
/// strictly worse, because it would turn "cannot tell" into "refuse".
///
/// The one thing it must not do is decode nothing and thereby be *trivially*
/// bypassable in a way that looks like coverage. `Url::parse` normalizes
/// percent-encoded unreserved characters in the path, so a locked URL spells
/// `tool_arm64.tar.gz` even if the release advertised `%5F`; the check reads the
/// canonical form, which is the one that was downloaded.
fn locked_artifact_name(url: &str) -> &str {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let path = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    path.rsplit('/').next().unwrap_or(path)
}

/// Go module binaries require compilation of third-party source. This is denied
/// unless the caller explicitly grants it with `NEOENV_ALLOW_GO_MODULE_BUILD=1`.
pub(super) fn publish_go_module_install(
    artifact: &Path,
    root: &Path,
    tool: &LockedTool,
) -> Result<(), Diagnostic> {
    if std::env::var("NEOENV_ALLOW_GO_MODULE_BUILD").as_deref() != Ok("1") {
        return Err(runtime_error(
            "Go module installation requires NEOENV_ALLOW_GO_MODULE_BUILD=1",
        ));
    }
    let module = tool
        .provenance
        .package
        .as_deref()
        .ok_or_else(|| runtime_error("Go module lock entry has no module provenance"))?;
    let checksum = tool
        .provenance
        .registry_integrity
        .as_deref()
        .ok_or_else(|| runtime_error("Go module lock entry has no go.sum provenance"))?;
    if tool.provenance.registry_endpoint.is_none() {
        return Err(runtime_error(
            "Go module lock entry has no proxy provenance",
        ));
    }
    let parent = root.parent().ok_or_else(|| {
        runtime_error("invalid Go module installation root: missing parent directory")
    })?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let temporary = temporary_path(parent, "go-install")?;
    fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
    let result = (|| {
        let proxy = write_locked_go_proxy(&temporary, artifact, module, &tool.resolved_version)?;
        let endpoint = format!("file://{}", proxy.display());
        fs::write(
            temporary.join("go.mod"),
            format!(
                "module {}\n\ngo 1.18\n\nrequire {module} {}\n",
                neoenv_core::names::GO_INSTALL_MODULE,
                tool.resolved_version
            ),
        )
        .map_err(|error| runtime_io(&temporary, &error))?;
        fs::write(temporary.join("go.sum"), format!("{module} {checksum}\n"))
            .map_err(|error| runtime_io(&temporary, &error))?;
        let download = go_command(&temporary, &endpoint)
            .args([
                "mod",
                "download",
                &format!("{module}@{}", tool.resolved_version),
            ])
            .output()
            .map_err(|error| {
                runtime_error(format!("failed to start Go module download: {error}"))
            })?;
        if !download.status.success() {
            return Err(runtime_error("Go module checksum verification failed"));
        }
        let bin = temporary.join("bin");
        fs::create_dir(&bin).map_err(|error| runtime_io(&bin, &error))?;
        let install = go_command(&temporary, &endpoint)
            .env("GOBIN", &bin)
            .args(["install", &format!("{module}@{}", tool.resolved_version)])
            .output()
            .map_err(|error| runtime_error(format!("failed to start Go module build: {error}")))?;
        if !install.status.success() {
            return Err(runtime_error("Go module build failed"));
        }
        if !tool
            .binaries
            .iter()
            .all(|binary| usable_file(&bin.join(binary)))
        {
            return Err(runtime_error(
                "Go module does not provide every declared binary",
            ));
        }
        write_install_metadata(&temporary, tool)?;
        fs::write(temporary.join(INSTALL_RECEIPT), &tool.sha256)
            .map_err(|error| runtime_io(&temporary, &error))
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    fs::rename(&temporary, root).map_err(|error| runtime_io(root, &error))
}

/// Builds a local, exact proxy view from the already SHA-256-verified ZIP. Go
/// may read only these files while installing a locked module.
pub(super) fn write_locked_go_proxy(
    root: &Path,
    artifact: &Path,
    module: &str,
    version: &str,
) -> Result<PathBuf, Diagnostic> {
    let proxy = root.join("proxy");
    let version_directory = proxy.join(go_proxy_escape(module)).join("@v");
    fs::create_dir_all(&version_directory)
        .map_err(|error| runtime_io(&version_directory, &error))?;
    let zip = version_directory.join(format!("{version}.zip"));
    fs::copy(artifact, &zip).map_err(|error| runtime_io(&zip, &error))?;
    let file = fs::File::open(artifact).map_err(|error| runtime_io(artifact, &error))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
    let prefix = format!("{}@{version}/", go_proxy_escape(module));
    let mut go_mod = None;
    let metadata_budget = extraction_reader_budget();
    let mut scanned_entries = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        check_archive_scan_count(&metadata_budget, &mut scanned_entries)?;
        metadata_budget
            .check_entry(Path::new(entry.name()), Some(entry.size()))
            .map_err(budget_error)?;
        if entry.name() == format!("{prefix}go.mod") {
            go_mod = Some(read_archive_metadata(&mut entry, &metadata_budget)?.into_bytes());
            break;
        }
    }
    fs::write(
        version_directory.join(format!("{version}.mod")),
        go_mod.ok_or_else(|| runtime_error("Go module ZIP has no go.mod"))?,
    )
    .map_err(|error| runtime_io(&version_directory, &error))?;
    fs::write(
        version_directory.join(format!("{version}.info")),
        format!(r#"{{"Version":"{version}","Time":"1970-01-01T00:00:00Z"}}"#),
    )
    .map_err(|error| runtime_io(&version_directory, &error))?;
    Ok(proxy)
}

pub(super) fn go_proxy_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_ascii_uppercase() {
                ['!', character.to_ascii_lowercase()]
            } else {
                ['\0', character]
            }
        })
        .filter(|character| *character != '\0')
        .collect()
}

/// Returns installed tools in lockfile order, excluding missing or incomplete installs.
#[must_use]
pub fn installed_tools(project_root: &Path, lockfile: &ToolLockfile) -> Vec<InstalledTool> {
    installed_tools_in(&ToolStorage::project(project_root), lockfile)
}

/// Storage-aware form of [`installed_tools`].
#[must_use]
pub fn installed_tools_in(storage: &ToolStorage, lockfile: &ToolLockfile) -> Vec<InstalledTool> {
    lockfile
        .tools
        .iter()
        .filter_map(|tool| {
            manager_receipt_matches(storage, lockfile, tool)
                .then(|| installed_tool(storage, tool))
                .flatten()
        })
        .collect()
}

/// Reports every locked tool and whether its complete, receipt-verified install
/// is present. This deliberately does not repair, download, or resolve anything.
#[must_use]
pub fn tool_states(project_root: &Path, lockfile: &ToolLockfile) -> Vec<ToolState> {
    tool_states_in(&ToolStorage::project(project_root), lockfile)
}

/// Storage-aware form of [`tool_states`].
#[must_use]
pub fn tool_states_in(storage: &ToolStorage, lockfile: &ToolLockfile) -> Vec<ToolState> {
    lockfile
        .tools
        .iter()
        .map(|tool| ToolState {
            id: tool.id.clone(),
            resolved_version: tool.resolved_version.clone(),
            provider: tool.resolver.clone(),
            installed: manager_receipt_matches(storage, lockfile, tool)
                && installed_tool(storage, tool).is_some(),
            bin_dir: install_root(storage, tool)
                .unwrap_or_else(|_| storage.install_directory().join(&tool.sha256))
                .join("bin"),
            url: tool.url.clone(),
            sha256: tool.sha256.clone(),
            immutable_id: tool.provenance.immutable_id.clone(),
        })
        .collect()
}

/// Returns published content-addressed installations carrying `nenv` metadata.
///
/// This inspection is local-only and never resolves a provider.  Directories
/// without the metadata marker are deliberately ignored so a foreign entry in
/// the storage directory cannot be selected for lifecycle deletion.
///
/// # Errors
///
/// Returns a diagnostic when the storage directory cannot be inspected.
pub fn installed_versions_in(storage: &ToolStorage) -> Result<Vec<InstalledVersion>, Diagnostic> {
    let directory = storage.install_directory();
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Ok(_) => return Ok(Vec::new()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(runtime_io(directory, &error)),
    };
    let _ = metadata;
    let mut versions = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| runtime_io(directory, &error))? {
        let entry = entry.map_err(|error| runtime_io(directory, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !neoenv_core::tools::is_sha256(name) {
            continue;
        }
        let path = entry.path();
        let file_type = fs::symlink_metadata(&path)
            .map_err(|error| runtime_io(&path, &error))?
            .file_type();
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let metadata_path = path.join(INSTALL_METADATA);
        let Ok(metadata_file_type) =
            fs::symlink_metadata(&metadata_path).map(|metadata| metadata.file_type())
        else {
            continue;
        };
        if !metadata_file_type.is_file() || metadata_file_type.is_symlink() {
            continue;
        }
        let Ok(input) = read_text_file(&metadata_path, &ResourceBudget::default()) else {
            continue;
        };
        let Ok(metadata) = toml::from_str::<InstallMetadata>(&input) else {
            continue;
        };
        if (metadata.storage_key.is_empty() && metadata.sha256 != name)
            || (!metadata.storage_key.is_empty() && metadata.storage_key != name)
            || metadata.id.is_empty()
            || metadata.resolved_version.is_empty()
            || metadata.resolved_version.contains(['/', '\\'])
            || !receipt_matches(&path.join(INSTALL_RECEIPT), &metadata.sha256)
            || (!metadata.storage_key.is_empty()
                && metadata.storage_key != metadata.sha256
                && !receipt_matches(&path.join(CARGO_BUILD_RECEIPT), &metadata.storage_key))
        {
            continue;
        }
        versions.push(InstalledVersion {
            id: metadata.id,
            resolved_version: metadata.resolved_version,
            sha256: metadata.sha256,
            path,
        });
    }
    // **The version component is ordered by precedence, the others by bytes.** The id is a
    // name and byte order is right for it; the digest is hex and byte order is right for
    // it. The version is neither, and listing `1.9.0` above `1.10.0` is the kind of small
    // wrongness that makes a user stop believing a tool's output.
    //
    // No caller depends on this order — they all match on an exact id and version, or
    // collect into a set — so this is a presentation fix, and it is stated as one rather
    // than dressed up as a correctness fix.
    versions.sort_by(|left, right| {
        left.id.cmp(&right.id).then_with(|| {
            neoenv_core::version::compare_versions(&left.resolved_version, &right.resolved_version)
                .then_with(|| left.sha256.cmp(&right.sha256))
        })
    });
    Ok(versions)
}

/// Removes one metadata-bearing installation by its exact storage key.
///
/// Returns `Ok(false)` when the entry is absent or is not a `nenv`-owned
/// installation. Cargo storage keys identify a complete source/build identity,
/// not merely the archive checksum. The path is scoped to the selected storage
/// view and final-component symlinks are never followed.
///
/// # Errors
///
/// Returns a diagnostic when the storage entry cannot be inspected or removed.
pub fn remove_installed_version_in(
    storage: &ToolStorage,
    storage_key: &str,
) -> Result<bool, Diagnostic> {
    if !neoenv_core::tools::is_sha256(storage_key) {
        return Ok(false);
    }
    if !real_directory_chain(storage.install_directory()) {
        return Ok(false);
    }
    let path = storage.install_directory().join(storage_key);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            metadata
        }
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(runtime_io(&path, &error)),
    };
    let _ = metadata;
    let metadata_path = path.join(INSTALL_METADATA);
    let Ok(metadata_file_type) =
        fs::symlink_metadata(&metadata_path).map(|metadata| metadata.file_type())
    else {
        return Ok(false);
    };
    if !metadata_file_type.is_file() || metadata_file_type.is_symlink() {
        return Ok(false);
    }
    let Ok(input) = read_text_file(&metadata_path, &ResourceBudget::default()) else {
        return Ok(false);
    };
    let Ok(record) = toml::from_str::<InstallMetadata>(&input) else {
        return Ok(false);
    };
    let expected_key = path.file_name().unwrap_or_default().to_string_lossy();
    if (!record.storage_key.is_empty() && record.storage_key != expected_key)
        || (record.storage_key.is_empty() && record.sha256 != storage_key)
        || record.id.is_empty()
        || record.resolved_version.is_empty()
        || record.resolved_version.contains(['/', '\\'])
        || !receipt_matches(&path.join(INSTALL_RECEIPT), &record.sha256)
        || (!record.storage_key.is_empty()
            && record.storage_key != record.sha256
            && !receipt_matches(&path.join(CARGO_BUILD_RECEIPT), storage_key))
    {
        return Ok(false);
    }
    fs::remove_dir_all(&path).map_err(|error| runtime_io(&path, &error))?;
    Ok(true)
}

fn real_directory_chain(path: &Path) -> bool {
    path.ancestors().all(|ancestor| {
        fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink()
        })
    })
}

/// Removes only unreferenced, digest-addressed project cache entries. It never
/// follows links, removes non-digest names, changes locks, or accesses a network.
/// Entries are first renamed into a private quarantine, preventing a partial
/// selection from deleting a concurrently-created cache entry.
///
/// # Errors
///
/// Returns an error when the lock is invalid or the project cache cannot be
/// inspected, renamed into quarantine, or removed.
pub fn cleanup_unreferenced(
    project_root: &Path,
    lockfile: &ToolLockfile,
    dry_run: bool,
) -> Result<Vec<CleanupEntry>, Diagnostic> {
    cleanup_unreferenced_in(&ToolStorage::project(project_root), lockfile, dry_run)
}

/// Storage-aware form of [`cleanup_unreferenced`].
///
/// # Errors
///
/// Returns a diagnostic when the lock, cache entry, quarantine, or filesystem
/// operation cannot be completed.
pub fn cleanup_unreferenced_in(
    storage: &ToolStorage,
    lockfile: &ToolLockfile,
    dry_run: bool,
) -> Result<Vec<CleanupEntry>, Diagnostic> {
    lockfile.validate().map_err(|error| lock_error(&error))?;
    let retained_artifacts: HashSet<String> = lockfile
        .tools
        .iter()
        .map(|tool| tool.sha256.clone())
        .collect();
    let mut retained_installs: HashSet<String> = lockfile
        .tools
        .iter()
        .map(install_key)
        .collect::<Result<_, _>>()?;
    for (id, versions) in &lockfile.pins {
        for entry in installed_versions_in(storage)? {
            if entry.id == *id && versions.contains(&entry.resolved_version) {
                retained_installs.insert(install_key_from_path(&entry.path));
            }
        }
    }
    let mut entries = Vec::new();
    for (kind, directory, expects_directory) in [
        ("artifact", storage.artifact_directory().to_owned(), false),
        ("install", storage.install_directory().to_owned(), true),
    ] {
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_dir() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(runtime_io(&directory, &error)),
        };
        let _ = metadata;
        for entry in fs::read_dir(&directory).map_err(|error| runtime_io(&directory, &error))? {
            let entry = entry.map_err(|error| runtime_io(&directory, &error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !neoenv_core::tools::is_sha256(name)
                || if kind == "artifact" {
                    retained_artifacts.contains(name)
                } else {
                    retained_installs.contains(name)
                }
            {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| runtime_io(&entry.path(), &error))?;
            if (expects_directory && !metadata.file_type().is_dir())
                || (!expects_directory
                    && !metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink())
            {
                continue;
            }
            entries.push(CleanupEntry {
                kind: kind.into(),
                path: entry.path(),
            });
        }
    }
    if dry_run || entries.is_empty() {
        return Ok(entries);
    }
    let quarantine = storage.quarantine_directory().join(format!(
        ".cleanup.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&quarantine).map_err(|error| runtime_io(&quarantine, &error))?;
    for (index, entry) in entries.iter().enumerate() {
        let target = quarantine.join(index.to_string());
        fs::rename(&entry.path, &target).map_err(|error| runtime_io(&entry.path, &error))?;
    }
    fs::remove_dir_all(&quarantine).map_err(|error| runtime_io(&quarantine, &error))?;
    Ok(entries)
}

/// Resolves an installed executable using lockfile declaration order.
#[must_use]
pub fn which_installed(
    project_root: &Path,
    lockfile: &ToolLockfile,
    executable: &str,
) -> Option<PathBuf> {
    which_installed_in(&ToolStorage::project(project_root), lockfile, executable)
}

/// Storage-aware form of [`which_installed`].
#[must_use]
pub fn which_installed_in(
    storage: &ToolStorage,
    lockfile: &ToolLockfile,
    executable: &str,
) -> Option<PathBuf> {
    lockfile.tools.iter().find_map(|tool| {
        if !tool.binaries.iter().any(|binary| binary == executable) {
            return None;
        }
        if !manager_receipt_matches(storage, lockfile, tool) {
            return None;
        }
        let path = install_root(storage, tool)
            .ok()?
            .join("bin")
            .join(executable);
        usable_file(&path).then_some(path)
    })
}

fn manager_receipt_matches(
    storage: &ToolStorage,
    lockfile: &ToolLockfile,
    tool: &LockedTool,
) -> bool {
    if tool.resolver == "cargo" {
        return cargo_receipt_matches(storage, tool, lockfile)
            && installed_tool(storage, tool).is_some();
    }
    match &lockfile.manager_lock {
        Some(graph) if tool.resolver == "npm" => bun_input_key(graph)
            .is_ok_and(|digest| managed_bun_receipts_match(storage, tool, &digest)),
        _ => true,
    }
}

/// Open each manager-controlled directory without following its final
/// component and read receipts relative to the verified digest directory.
/// Returned executable paths may still be replaced by the same user after this
/// check; callers that execute them need an appropriate same-user trust boundary.
#[cfg(unix)]
fn managed_bun_receipts_match(
    storage: &ToolStorage,
    tool: &LockedTool,
    graph_digest: &str,
) -> bool {
    if !neoenv_core::tools::is_sha256(&tool.sha256) {
        return false;
    }
    let Some(parent) = storage.install_directory().parent() else {
        return false;
    };
    let Some(install_name) = storage.install_directory().file_name() else {
        return false;
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let Ok(parent_fd) = open_nofollow(parent, flags, Mode::empty()) else {
        return false;
    };
    let Ok(install_fd) = openat(&parent_fd, install_name, flags, Mode::empty()) else {
        return false;
    };
    let Ok(root_fd) = openat(&install_fd, tool.sha256.as_str(), flags, Mode::empty()) else {
        return false;
    };
    if openat(&root_fd, "bin", flags, Mode::empty()).is_err() {
        return false;
    }
    let matches_receipt = |name: &str, expected: &str| {
        let Ok(fd) = openat(
            &root_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) else {
            return false;
        };
        let file = fs::File::from(fd);
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return false;
        }
        let mut text = String::new();
        file.take(1025).read_to_string(&mut text).is_ok()
            && text.len() <= 1024
            && text.trim() == expected
    };
    matches_receipt(INSTALL_RECEIPT, &tool.sha256)
        && matches_receipt(BUN_INSTALL_GRAPH_RECEIPT, graph_digest)
}

/// Other platforms reject final-component symlinks but cannot atomically
/// exclude concurrent path replacement between validation and use.
#[cfg(not(unix))]
fn managed_bun_receipts_match(
    storage: &ToolStorage,
    tool: &LockedTool,
    graph_digest: &str,
) -> bool {
    let Some(parent) = storage.install_directory().parent() else {
        return false;
    };
    let Ok(root) = install_root(storage, tool) else {
        return false;
    };
    [
        parent,
        storage.install_directory(),
        root.as_path(),
        root.join("bin").as_path(),
    ]
    .iter()
    .all(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_dir()))
        && receipt_matches(&root.join(INSTALL_RECEIPT), &tool.sha256)
        && receipt_matches(&root.join(BUN_INSTALL_GRAPH_RECEIPT), graph_digest)
}

pub(super) fn receipt_matches(path: &Path, expected: &str) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    read_text_file(path, &ResourceBudget::default()).is_ok_and(|value| value.trim() == expected)
}

/// Computes the receipt digest binding a Cargo installation to its locked
/// source, declaration, binaries, policies, and toolchain identity.
///
/// # Errors
///
/// Returns a diagnostic when the identity cannot be serialized.
pub fn cargo_install_identity(
    tool: &LockedTool,
    build: &neoenv_core::tools::CargoBuildLock,
) -> Result<String, Diagnostic> {
    let bytes = serde_json::to_vec(&(tool, build))
        .map_err(|_| runtime_error("cannot encode Cargo build identity"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn cargo_receipt_matches(
    storage: &ToolStorage,
    tool: &LockedTool,
    lockfile: &ToolLockfile,
) -> bool {
    if tool.resolver != "cargo" {
        return true;
    }
    let Some(build) = lockfile.cargo_build.as_ref() else {
        return false;
    };
    if build.tool_id != tool.id || build.toolchain != tool.cargo_toolchain.as_deref().unwrap_or("")
    {
        return false;
    }
    let Ok(expected) = cargo_install_identity(tool, build) else {
        return false;
    };
    let Ok(root) = install_root(storage, tool) else {
        return false;
    };
    receipt_matches(&root.join(CARGO_BUILD_RECEIPT), &expected)
}

pub(super) fn installed_tool(storage: &ToolStorage, tool: &LockedTool) -> Option<InstalledTool> {
    valid_binary_names(tool).ok()?;
    let root = install_root(storage, tool).ok()?;
    if !receipt_matches(&root.join(INSTALL_RECEIPT), &tool.sha256) {
        return None;
    }
    let bin_dir = root.join("bin");
    tool.binaries
        .iter()
        .all(|binary| usable_file(&bin_dir.join(binary)))
        .then(|| installed_description(tool, bin_dir))
}

pub(super) fn installed_description(tool: &LockedTool, bin_dir: PathBuf) -> InstalledTool {
    InstalledTool {
        id: tool.id.clone(),
        resolved_version: tool.resolved_version.clone(),
        bin_dir,
        url: tool.url.clone(),
        sha256: tool.sha256.clone(),
        resolver: tool.resolver.clone(),
    }
}

pub(super) fn install_root(
    storage: &ToolStorage,
    tool: &LockedTool,
) -> Result<PathBuf, Diagnostic> {
    Ok(storage.install_directory().join(install_key(tool)?))
}

/// Returns the content-addressed storage key for a locked tool build.
///
/// Cargo uses the exact serialized identity hashed into its build receipt,
/// including declaration provenance and the fixed Cargo policy fields.
///
/// # Errors
///
/// Returns a diagnostic if a Cargo tool lacks the provenance needed to
/// reconstruct that canonical receipt identity.
pub fn install_key(tool: &LockedTool) -> Result<String, Diagnostic> {
    if tool.resolver == "cargo" {
        let build = canonical_cargo_build(tool)
            .ok_or_else(|| runtime_error("Cargo tool lacks a complete build identity"))?;
        cargo_install_identity(tool, &build)
    } else {
        Ok(tool.sha256.clone())
    }
}

fn canonical_cargo_build(tool: &LockedTool) -> Option<neoenv_core::tools::CargoBuildLock> {
    Some(neoenv_core::tools::CargoBuildLock {
        tool_id: tool.id.clone(),
        crate_name: tool.provenance.package.clone()?,
        version: tool.resolved_version.clone(),
        registry: tool.provenance.registry_endpoint.clone()?,
        checksum: tool.sha256.clone(),
        toolchain: tool.cargo_toolchain.clone()?,
        scripts: neoenv_core::tools::CargoScriptPolicy::Deny,
        build: neoenv_core::tools::CargoBuildPolicy::Isolated,
        network: neoenv_core::tools::CargoNetworkPolicy::Deny,
    })
}

fn install_key_from_path(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

pub(super) fn ensure_artifact(
    storage: &ToolStorage,
    tool: &LockedTool,
) -> Result<PathBuf, Diagnostic> {
    let directory = storage.artifact_directory().to_owned();
    fs::create_dir_all(&directory).map_err(|error| runtime_io(&directory, &error))?;
    let artifact = directory.join(&tool.sha256);
    match fs::symlink_metadata(&artifact) {
        Ok(metadata) if metadata.file_type().is_file() && verify_file(&artifact, &tool.sha256)? => {
            return Ok(artifact);
        }
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(&artifact).map_err(|error| runtime_io(&artifact, &error))?;
        }
        Ok(_) => {
            return Err(runtime_error(format!(
                "artifact cache path is not a file: {}",
                artifact.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(runtime_io(&artifact, &error)),
    }
    let temporary = temporary_path(&directory, "artifact")?;
    let result = download_and_verify(&tool.url, &temporary, &tool.sha256);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    match fs::rename(&temporary, &artifact) {
        Ok(()) => Ok(artifact),
        Err(_error) if artifact.is_file() && verify_file(&artifact, &tool.sha256)? => {
            let _ = fs::remove_file(&temporary);
            Ok(artifact)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(runtime_io(&artifact, &error))
        }
    }
}

pub(super) fn download_and_verify(
    url: &str,
    destination: &Path,
    digest: &str,
) -> Result<(), Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to download locked tool"))?;
    policy
        .validate_artifact_length(url, &response, ResourceBudget::default().artifact_bytes)
        .map_err(|error| http_error(error, "failed to download locked tool"))?;
    let mut reader =
        policy.streaming_reader_limited(url, response, ResourceBudget::default().artifact_bytes);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| runtime_io(destination, &error))?;
    copy_and_verify(&mut reader, &mut output, digest)?;
    output
        .sync_all()
        .map_err(|error| runtime_io(destination, &error))
}

pub(super) fn write_install_metadata(root: &Path, tool: &LockedTool) -> Result<(), Diagnostic> {
    let metadata = InstallMetadata {
        id: tool.id.clone(),
        resolved_version: tool.resolved_version.clone(),
        sha256: tool.sha256.clone(),
        storage_key: install_key(tool)?,
    };
    let contents = toml::to_string(&metadata).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
    })?;
    fs::write(root.join(INSTALL_METADATA), contents).map_err(|error| runtime_io(root, &error))
}

pub(super) fn publish_install(
    artifact: &Path,
    root: &Path,
    tool: &LockedTool,
) -> Result<(), Diagnostic> {
    valid_binary_names(tool)?;
    let parent = root
        .parent()
        .ok_or_else(|| runtime_error("invalid tool installation root: missing parent directory"))?;
    fs::create_dir_all(parent).map_err(|error| runtime_io(parent, &error))?;
    let temporary = temporary_path(parent, "install")?;
    fs::create_dir(&temporary).map_err(|error| runtime_io(&temporary, &error))?;
    let result = extract_artifact(artifact, &temporary, tool)
        .and_then(|()| {
            let bin = temporary.join("bin");
            if tool
                .binaries
                .iter()
                .all(|binary| usable_file(&bin.join(binary)))
            {
                Ok(())
            } else {
                Err(runtime_error(format!(
                    "artifact for {} does not provide every declared binary",
                    tool.id
                )))
            }
        })
        .and_then(|()| {
            write_install_metadata(&temporary, tool)?;
            fs::write(temporary.join(INSTALL_RECEIPT), &tool.sha256)
                .map_err(|error| runtime_io(&temporary, &error))
        });
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    match fs::rename(&temporary, root) {
        Ok(()) => Ok(()),
        Err(_error)
            if receipt_matches(&root.join(INSTALL_RECEIPT), &tool.sha256)
                && tool
                    .binaries
                    .iter()
                    .all(|binary| usable_file(&root.join("bin").join(binary))) =>
        {
            let _ = fs::remove_dir_all(&temporary);
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            Err(runtime_io(root, &error))
        }
    }
}
