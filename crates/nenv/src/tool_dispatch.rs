//! Tool command dispatch, including native executable resolution across
//! project and global selection, plus tool name validation and diagnostics.

use super::{
    Diagnostic, DiagnosticCategory, ExitCategory, GlobalScope, OutputFormat, Path, PathBuf,
    Platform, ProcessCommand, ResourceBudget, ToolCommand, ToolScope, bun_binary_directory,
    cleanup_unreferenced, fs, global_tool_config_path, global_tool_data_directory,
    global_tool_data_root, global_tool_storage, install_locked_tools, java_home_directory,
    load_project, lockfile_path, plan_tools, print_json, read_global_tool_document, read_lockfile,
    read_text_file, resolve_tools, run_native_use, safe_global_lock_name, tool_lifecycle,
    tool_states, verify_lockfile, which_installed, which_installed_in, write_lockfile,
};

#[allow(clippy::too_many_lines)]
pub(super) fn dispatch_tool(command: &ToolCommand, format: OutputFormat) -> Result<(), Diagnostic> {
    if let ToolCommand::GlobalUse { arguments } = command {
        return run_native_use(arguments, format);
    }
    match command {
        ToolCommand::Remove {
            scope,
            tools,
            dry_run,
        }
        | ToolCommand::Update {
            scope,
            tools,
            dry_run,
        }
        | ToolCommand::Pin {
            scope,
            tools,
            dry_run,
        }
        | ToolCommand::Unpin {
            scope,
            tools,
            dry_run,
        }
        | ToolCommand::Purge {
            scope,
            tools,
            dry_run,
        } => {
            // Global tool state is not project configuration, so there is no
            // config-directed effect to gate. A project-scoped lifecycle command
            // is, and the project must be trusted first. **The checked snapshot
            // is passed to the lifecycle rather than loaded again there**: a
            // second load would consume bytes the trust decision never saw.
            let checked = if !*dry_run && matches!(scope, ToolScope::Project) {
                Some(crate::output::load_trusted_project_with_profile(
                    None,
                    neoenv_config::ConfigProfile::process_profile(),
                    None,
                )?)
            } else {
                None
            };
            return tool_lifecycle::run(*scope, checked.as_ref(), command, tools, *dry_run, format);
        }
        _ => {}
    }
    if let ToolCommand::Install { path } = command {
        let project = crate::output::load_trusted_project_with_profile(
            path.as_deref(),
            neoenv_config::ConfigProfile::process_profile(),
            None,
        )?;
        let lock_path = lockfile_path(&project.project.project_root);
        let lockfile = read_lockfile(&lock_path)?;
        neoenv_installer::tools::reject_unimplemented_cargo_install(&project.tools, &lockfile)?;
        if lockfile.manager_lock.is_none()
            && project
                .tools
                .iter()
                .any(|tool| tool.npm.as_ref().is_some_and(|npm| npm.manager.is_some()))
        {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO514",
                "declared npm manager has no matching manager lock; refusing direct archive installation",
            ));
        }
        let installed = if lockfile.manager_lock.is_some() {
            let runtime_root = global_tool_data_directory(GlobalScope::User)?;
            vec![neoenv_installer::tools::install_locked_bun_tool(
                &project.project.project_root,
                &runtime_root,
                &project.tools,
                &lockfile,
            )?]
        } else {
            install_locked_tools(&project.project.project_root, &lockfile)?
        };
        return print_installed(&installed, format);
    }
    if let ToolCommand::List { path, scope } = command {
        if let Some(scope) = scope {
            return print_global_tool_states(*scope, format);
        }
        let project = load_project(path.as_deref())?;
        let lockfile = read_lockfile(&lockfile_path(&project.project.project_root))?;
        return print_tool_states(
            &tool_states(&project.project.project_root, &lockfile),
            format,
        );
    }
    if let ToolCommand::Which {
        executable,
        path,
        scope,
    }
    | ToolCommand::Where {
        executable,
        path,
        scope,
    } = command
    {
        validate_tool_name(executable)?;
        let resolved = if let Some(scope) = scope {
            let global_scope = match scope {
                ToolScope::User => GlobalScope::User,
                ToolScope::Global => GlobalScope::System,
                ToolScope::Project => {
                    return Err(Diagnostic::new(
                        DiagnosticCategory::Usage,
                        "NEO001",
                        "tool which/where accept --user or --global, not --project",
                    ));
                }
            };
            globally_selected_native_executable(executable, global_scope)?
        } else {
            let project = tool_project(path.as_deref())?;
            Some(resolve_tool_executable(project.as_ref(), executable)?)
        };
        let Some(path) = resolved else {
            return Err(Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO521",
                format!("installed executable not found: {executable}"),
            ));
        };
        match format {
            OutputFormat::Text => println!("{}", path.display()),
            OutputFormat::Json => {
                print_json(&serde_json::json!({ "executable": executable, "path": path }))?;
            }
        }
        return Ok(());
    }
    if let ToolCommand::Use {
        executable,
        path,
        arguments,
    } = command
    {
        validate_tool_name(executable)?;
        if format != OutputFormat::Text {
            return Err(Diagnostic::new(
                DiagnosticCategory::Usage,
                "NEO001",
                "tool use only supports text output",
            ));
        }
        let project = tool_project(path.as_deref())?;
        if let Some(project) = project.as_ref() {
            crate::output::require_execution_trust(project)?;
        }
        let executable = resolve_tool_executable(project.as_ref(), executable)?;
        let status = ProcessCommand::new(&executable)
            .args(arguments)
            .status()
            .map_err(|error| {
                Diagnostic::new(
                    DiagnosticCategory::Runtime,
                    "NEO522",
                    format!("failed to start {}: {error}", executable.display()),
                )
            })?;
        if !status.success() {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                format!("tool {} exited with {status}", executable.display()),
            ));
        }
        return Ok(());
    }
    if let ToolCommand::Cleanup {
        path,
        dry_run,
        scope,
    } = command
    {
        if let Some(scope) = scope {
            let global_scope = match scope {
                ToolScope::User => ToolScope::User,
                ToolScope::Global if *dry_run => ToolScope::Global,
                ToolScope::Global => {
                    return Err(crate::global_install::system_mutation_disabled_diagnostic());
                }
                ToolScope::Project => {
                    return Err(Diagnostic::new(
                        DiagnosticCategory::Usage,
                        "NEO001",
                        "tool cleanup accepts --user or --global here, not --project",
                    ));
                }
            };
            let purge = ToolCommand::Purge {
                scope: global_scope,
                tools: Vec::new(),
                dry_run: *dry_run,
            };
            return tool_lifecycle::run(global_scope, None, &purge, &[], *dry_run, format);
        }
        let project = load_project(path.as_deref())?;
        let lockfile = read_lockfile(&lockfile_path(&project.project.project_root))?;
        let entries = cleanup_unreferenced(&project.project.project_root, &lockfile, *dry_run)?;
        return print_cleanup(&entries, *dry_run, format);
    }
    let (path, locked, action) = match command {
        ToolCommand::Plan { path, locked } => (path.as_deref(), *locked, "plan"),
        ToolCommand::Lock { path, locked } => (path.as_deref(), *locked, "lock"),
        ToolCommand::Verify { path } => (path.as_deref(), true, "verify"),
        ToolCommand::Install { .. }
        | ToolCommand::List { .. }
        | ToolCommand::Which { .. }
        | ToolCommand::Where { .. }
        | ToolCommand::Use { .. }
        | ToolCommand::GlobalUse { .. }
        | ToolCommand::Remove { .. }
        | ToolCommand::Update { .. }
        | ToolCommand::Pin { .. }
        | ToolCommand::Unpin { .. }
        | ToolCommand::Purge { .. }
        | ToolCommand::Cleanup { .. } => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO701",
                "tool command was not dispatched before lockfile planning",
            ));
        }
    };
    let project = load_project(path)?;
    let lock_path = lockfile_path(&project.project.project_root);
    if locked || action == "verify" {
        if project.tools.iter().any(|tool| {
            matches!(
                tool.provider,
                neoenv_core::tools::ToolProvider::GithubRelease
                    | neoenv_core::tools::ToolProvider::Aqua
                    | neoenv_core::tools::ToolProvider::Npm
                    | neoenv_core::tools::ToolProvider::DotnetTool
                    | neoenv_core::tools::ToolProvider::GoModule
                    | neoenv_core::tools::ToolProvider::RubyGems
            )
        }) {
            read_lockfile(&lock_path)?;
            return match format {
                OutputFormat::Json => {
                    print_json(&serde_json::json!({ "valid": true, "lockfile": lock_path }))
                }
                OutputFormat::Text => {
                    println!("verified: {}", lock_path.display());
                    Ok(())
                }
            };
        }
        let plan = plan_tools(&project.tools, &Platform::host())
            .map_err(|error| tool_plan_error(&error))?;
        verify_lockfile(&lock_path, &plan)?;
        return match format {
            OutputFormat::Json => {
                print_json(&serde_json::json!({ "valid": true, "lockfile": lock_path }))
            }
            OutputFormat::Text => {
                println!("verified: {}", lock_path.display());
                Ok(())
            }
        };
    }
    if action == "lock"
        && project.tools.iter().any(|tool| {
            tool.npm
                .as_ref()
                .and_then(|npm| npm.manager.as_ref())
                .is_some_and(|manager| manager.name == neoenv_core::tools::NpmManagerName::Bun)
        })
    {
        let plan = lock_bun_tool(&project.tools, &project.project.project_root, &lock_path)?;
        return match format {
            OutputFormat::Json => print_json(&plan),
            OutputFormat::Text => {
                println!("locked: {}", lock_path.display());
                Ok(())
            }
        };
    }
    let plan = resolve_tools(&project.tools, &Platform::host())?;
    if action == "lock" && !locked {
        write_lockfile(&lock_path, &plan)?;
    }
    match format {
        OutputFormat::Json => print_json(&plan)?,
        OutputFormat::Text => match action {
            "plan" => {
                for tool in &plan.tools {
                    println!(
                        "{} {} {} {}",
                        tool.id, tool.resolved_version, tool.platform.os, tool.url
                    );
                }
            }
            "lock" => println!("locked: {}", lock_path.display()),
            _ => println!("verified: {}", lock_path.display()),
        },
    }
    Ok(())
}

/// Lock one npm package with an independently pinned managed Bun.
/// Existing manager locks remain immutable unless explicitly migrated.
#[allow(clippy::too_many_lines)]
fn lock_bun_tool(
    declarations: &[neoenv_core::tools::ToolDeclaration],
    project_root: &Path,
    lock_path: &Path,
) -> Result<neoenv_core::tools::ToolPlan, Diagnostic> {
    use neoenv_core::tools::{PlannedTool, ToolPlan};
    use neoenv_installer::tools::{
        BunManagerLockInputs, StoredBunInputs, persist_bun_inputs, prepare_bun_lock,
        recover_bun_inputs, stage_resolved_npm_tarball, validate_resolved_bun_tarball,
        verify_pinned_retained_managed_bun, verify_retained_managed_bun,
        write_lockfile_with_manager,
    };
    let fail = |message: &str| Diagnostic::new(DiagnosticCategory::Validation, "NEO514", message);
    let [declaration] = declarations else {
        return Err(fail(
            "Bun manager lock currently requires exactly one npm tool",
        ));
    };
    let manager = declaration
        .npm
        .as_ref()
        .and_then(|npm| npm.manager.as_ref())
        .ok_or_else(|| fail("Bun manager lock requires an explicit manager"))?;
    if manager.name != neoenv_core::tools::NpmManagerName::Bun {
        return Err(fail("only Bun manager locking is supported"));
    }
    let existing = match fs::symlink_metadata(lock_path) {
        Ok(_) => Some(read_lockfile(lock_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                format!("cannot inspect tool lock {}: {error}", lock_path.display()),
            ));
        }
    };
    let anchor = existing
        .as_ref()
        .and_then(|lock| lock.manager_lock.as_ref());
    if let Some(anchor) = anchor {
        let archive = anchor.runtime_archive.as_ref().ok_or_else(|| {
            fail("existing Bun manager lock lacks authenticated archive provenance; explicit migration is required")
        })?;
        if anchor.manager != "bun"
            || anchor.manager_version != manager.version
            || anchor.runtime_version != manager.version
            || manager
                .archive_sha256
                .as_ref()
                .is_some_and(|pin| pin != &archive.sha256)
        {
            return Err(fail(
                "existing manager selection differs; explicit migration is required",
            ));
        }
    } else if manager.archive_sha256.is_none() {
        return Err(fail(
            "offline Bun locking requires a previously authenticated manager lock or explicit archive_sha256; local runtime receipts are not a trust anchor",
        ));
    }
    let previous_plan = if let Some(existing) = &existing {
        let [locked] = existing.tools.as_slice() else {
            return Err(fail(
                "Bun locking requires one previously resolved npm lock entry",
            ));
        };
        if locked.id != declaration.id
            || locked.resolver != "npm"
            || locked.platform != Platform::host()
        {
            return Err(fail(
                "previous npm lock entry does not match the selected tool and platform",
            ));
        }
        Some(ToolPlan {
            tools: vec![PlannedTool {
                id: locked.id.clone(),
                resolved_version: locked.resolved_version.clone(),
                url: locked.url.clone(),
                platform: locked.platform.clone(),
                sha256: locked.sha256.clone(),
                provenance: locked.provenance.clone(),
                verification: locked.verification.clone(),
                binaries: locked.binaries.clone(),
                declaration_source: locked.declaration_source.clone(),
                cargo_toolchain: locked.cargo_toolchain.clone(),
            }],
        })
    } else {
        if !neoenv_core::tools::is_exact_manager_version(&declaration.version) {
            return Err(fail(
                "fresh Bun locking requires one exact npm package version",
            ));
        }
        None
    };
    let storage = project_root.join(neoenv_core::names::PROJECT_DIRECTORY);
    match fs::create_dir(&storage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                format!("cannot create project tool storage: {error}"),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&storage).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO520",
            format!("cannot inspect project tool storage: {error}"),
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(fail("project tool storage must be a real directory"));
    }
    let scratch = tempfile::Builder::new()
        .prefix("bun-lock-")
        .tempdir_in(&storage)
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                format!("cannot create Bun lock staging: {error}"),
            )
        })?;
    let (plan, tarball) = if let Some(plan) = previous_plan {
        let tarball = if let Some(anchor) = anchor {
            recover_bun_inputs(&storage, anchor)?.tarball
        } else {
            storage.join("artifacts").join(&plan.tools[0].sha256)
        };
        (plan, tarball)
    } else {
        // The manager is removed only from this in-memory resolver input.
        // Its output is never published as a legacy lock or directly installed.
        let mut resolution = declaration.clone();
        resolution
            .npm
            .as_mut()
            .expect("validated npm manager")
            .manager = None;
        let plan = resolve_tools(&[resolution], &Platform::host())?;
        let [tool] = plan.tools.as_slice() else {
            return Err(fail("npm resolver did not produce one package"));
        };
        let tarball = scratch.path().join("npm-package.tgz");
        stage_resolved_npm_tarball(tool, &tarball)?;
        (plan, tarball)
    };
    // Reject malformed or unsupported npm archives before invoking even
    // `bun --version`, and before writing any persistent manager inputs.
    validate_resolved_bun_tarball(declaration, &plan.tools[0], &tarball)?;
    let runtime_root = global_tool_data_directory(GlobalScope::User)?;
    let (bun, archive) = if let Some(anchor) = anchor {
        verify_retained_managed_bun(
            &runtime_root,
            &manager.version,
            anchor
                .runtime_archive
                .as_ref()
                .expect("validated archive anchor"),
            &anchor.manager_sha256,
            scratch.path(),
        )?
    } else {
        verify_pinned_retained_managed_bun(
            &runtime_root,
            &manager.version,
            manager
                .archive_sha256
                .as_deref()
                .expect("validated explicit digest"),
            scratch.path(),
        )?
    };
    let prepared = prepare_bun_lock(declaration, &plan.tools[0], &bun, &tarball)?;
    if anchor.is_some_and(|anchor| &prepared.graph != anchor) {
        return Err(fail(
            "resolved Bun graph differs from the existing lock; explicit migration is required",
        ));
    }
    let manifest = scratch.path().join("manifest.json");
    let bun_lockfile = scratch.path().join("bun.lock");
    fs::write(&manifest, &prepared.manifest)
        .and_then(|()| fs::write(&bun_lockfile, &prepared.bun_lockfile))
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                format!("cannot stage Bun inputs: {error}"),
            )
        })?;
    persist_bun_inputs(
        &storage,
        &prepared.graph,
        &StoredBunInputs {
            archive: archive.clone(),
            tarball: tarball.clone(),
            manifest: manifest.clone(),
            bun_lockfile: bun_lockfile.clone(),
        },
    )?;
    write_lockfile_with_manager(
        lock_path,
        &plan,
        &BunManagerLockInputs {
            declaration,
            graph: &prepared.graph,
            managed_bun: &bun,
            tarball: &tarball,
            manifest: &manifest,
            bun_lockfile: &bun_lockfile,
        },
    )?;
    Ok(plan)
}

pub(crate) fn validate_tool_name(name: &str) -> Result<(), Diagnostic> {
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "tool executable must be a declared binary name, not a path",
        ))
    } else {
        Ok(())
    }
}

fn tool_project(
    path: Option<&str>,
) -> Result<Option<neoenv_runtime::resolved_config::ResolvedProject>, Diagnostic> {
    match load_project(path) {
        Ok(project) => Ok(Some(project)),
        Err(error) if path.is_none() && error.exit_category() == ExitCategory::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn resolve_tool_executable(
    project: Option<&neoenv_runtime::resolved_config::ResolvedProject>,
    executable: &str,
) -> Result<PathBuf, Diagnostic> {
    if let Some(project) = project
        && let Some(path) = resolve_project_tool(project, executable)?
    {
        return Ok(path);
    }
    if let Some(path) = globally_selected_native_executable(executable, GlobalScope::User)? {
        return Ok(path);
    }
    if let Some(path) = globally_selected_native_executable(executable, GlobalScope::System)? {
        return Ok(path);
    }
    Err(Diagnostic::new(
        DiagnosticCategory::NotFound,
        "NEO521",
        format!(
            "installed executable not found: {executable}; run `nenv tool lock` and `nenv tool install --locked`, or `nenv use --global {executable}`"
        ),
    ))
}

/// Resolve a project-owned tool or refuse an ambiguous managed name. `None`
/// means the name is unrelated and the caller may apply its own fallback.
pub(super) fn resolve_project_tool(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    executable: &str,
) -> Result<Option<PathBuf>, Diagnostic> {
    resolve_project_tool_inner(project, executable, false)
}

/// `exec` historically falls back to PATH when a legacy project's lock
/// cannot be read. Keep that behavior only when no npm manager is declared.
pub(super) fn resolve_project_tool_for_exec(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    executable: &str,
) -> Result<Option<PathBuf>, Diagnostic> {
    resolve_project_tool_inner(project, executable, true)
}

#[allow(clippy::too_many_lines)] // Preserve legacy manager checks beside the Cargo fail-closed guard.
fn resolve_project_tool_inner(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    executable: &str,
    legacy_exec_fallback: bool,
) -> Result<Option<PathBuf>, Diagnostic> {
    let project_root = &project.project.project_root;
    let lock_path = lockfile_path(project_root);
    let allow_lock_error = legacy_exec_fallback
        && !project
            .tools
            .iter()
            .any(|tool| tool.npm.as_ref().is_some_and(|npm| npm.manager.is_some()));
    let lockfile = match fs::symlink_metadata(&lock_path) {
        Ok(_) => match read_lockfile(&lock_path) {
            Ok(lockfile) => Some(lockfile),
            Err(_) if allow_lock_error => None,
            Err(error) => return Err(error),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) if allow_lock_error => None,
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                format!("cannot inspect tool lock {}: {error}", lock_path.display()),
            ));
        }
    };
    // Crate names do not reliably predict executable names. Only explicit
    // declaration IDs and binary lists can attribute a requested name.
    let cargo_name_is_affected = project.tools.iter().any(|declaration| {
        declaration.provider == neoenv_core::tools::ToolProvider::Cargo
            && (declaration.binaries.is_empty()
                || declaration.id == executable
                || declaration
                    .binaries
                    .iter()
                    .any(|binary| binary == executable)
                || lockfile.as_ref().is_some_and(|lock| {
                    lock.tools.iter().any(|entry| {
                        entry.id == declaration.id
                            && entry.binaries.iter().any(|binary| binary == executable)
                    })
                }))
    });
    let cargo_lock_name_is_affected = lockfile.as_ref().is_some_and(|lock| {
        lock.tools.iter().any(|entry| {
            entry.resolver == "cargo"
                && (entry.id == executable
                    || entry.binaries.iter().any(|binary| binary == executable))
        }) || lock.cargo_build.as_ref().is_some_and(|build| {
            lock.tools
                .iter()
                .find(|entry| entry.id == build.tool_id)
                .is_some_and(|entry| {
                    entry.id == executable
                        || entry.binaries.iter().any(|binary| binary == executable)
                })
        })
    });
    if cargo_name_is_affected || cargo_lock_name_is_affected {
        let lock = lockfile.as_ref().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO514",
                "Cargo declaration has no matching lock; refusing fallback",
            )
        })?;
        neoenv_installer::tools::validate_cargo_install_association(&project.tools, lock)?;
        return which_installed(project_root, lock, executable)
            .map(Some)
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::NotFound,
                    "NEO521",
                    "Cargo executable is not installed for its current build identity; refusing fallback",
                )
            });
    }
    for declaration in &project.tools {
        let Some(npm) = declaration.npm.as_ref().filter(|npm| npm.manager.is_some()) else {
            continue;
        };
        let locked = lockfile
            .as_ref()
            .and_then(|lock| lock.tools.iter().find(|tool| tool.id == declaration.id));
        let named = declaration.binaries.iter().any(|name| name == executable)
            || declaration.id == executable
            || npm.package.rsplit('/').next() == Some(executable)
            || locked.is_some_and(|tool| tool.binaries.iter().any(|name| name == executable));
        // Without locked or declared binary names, npm metadata is the
        // only authority on aliases. Do not guess that an unknown global
        // executable is unrelated to the unresolved managed package.
        let reliable_names = locked.is_some_and(|tool| {
            tool.resolver == "npm"
                && tool.provenance.provider == "npm"
                && tool.provenance.package.as_deref() == Some(npm.package.as_str())
                && neoenv_core::tools::canonical_http_url(&npm.endpoint)
                    .ok()
                    .as_deref()
                    == tool.provenance.registry_endpoint.as_deref()
                && (declaration.version == "latest" || declaration.version == tool.resolved_version)
                && tool.platform == Platform::host()
                && tool.verification.sha256 == tool.sha256
                && declaration.url.is_none()
                && declaration.sha256.is_none()
                && declaration.binpath.is_none()
                && declaration.bindir.is_none()
                && declaration.platforms.is_empty()
                && (declaration.binaries.is_empty()
                    || (declaration.binaries.len() == tool.binaries.len()
                        && declaration
                            .binaries
                            .iter()
                            .all(|name| tool.binaries.contains(name))))
        });
        // A claim by another locked tool does not prove that this
        // unresolved manager cannot own the same executable alias.
        let unknown = !reliable_names;
        if !named && !unknown {
            continue;
        }
        let lock = lockfile.as_ref().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO514",
                "declared npm manager has no matching manager lock; refusing fallback",
            )
        })?;
        neoenv_installer::tools::validate_bun_tool_lock(declaration, lock)?;
        return which_installed(project_root, lock, executable).map(Some).ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::NotFound,
                    "NEO521",
                    "managed npm executable is not installed for its current lock; refusing fallback",
                )
            });
    }
    if let Some(lockfile) = lockfile.as_ref() {
        if let Some(path) = which_installed(project_root, lockfile, executable) {
            return Ok(Some(path));
        }
        if lockfile.manager_lock.is_some()
            && lockfile.tools.iter().any(|tool| {
                tool.resolver == "npm" && tool.binaries.iter().any(|binary| binary == executable)
            })
        {
            return Err(Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO521",
                "managed npm executable is not installed for its current lock; refusing fallback",
            ));
        }
    }
    Ok(None)
}

/// Finds an executable owned by a validated global provider record.
///
/// # Ownership policy
///
/// Every provider record in the scope is validated before this scope may fall
/// through. A record is bound to the lock entry with the same key, and present
/// version, digest, binary, immutable-id, resolver, and source fields must
/// match. Missing metadata is recovered from the verified lock entry; a stale
/// or mismatched field is an error, never a reason to try another scope.
///
/// An inaccessible or malformed lock is fail-closed even when its recorded
/// binaries do not name the requested executable. This project has no
/// integrity-bound ownership index (a self-hash of the same record is not one),
/// so it cannot prove that an unreadable record is unrelated. The tradeoff is
/// deliberate: an unrelated corrupt provider blocks lookup until repaired,
/// rather than risking selection from an unverified record.
///
/// Multiple records claiming the same executable are ambiguous and refused
/// irrespective of order or whether one of their locks is missing.
///
/// # Errors
///
/// Returns a runtime or not-found diagnostic for any unreadable or inconsistent
/// selected state. It does not silently skip a malformed record.
#[allow(clippy::too_many_lines)] // Every record is validated before a scope can fall through.
pub(super) fn globally_selected_provider_executable(
    document: &toml::Value,
    executable: &str,
    scope: GlobalScope,
) -> Result<Option<PathBuf>, Diagnostic> {
    let Some(global) = document.get("global").and_then(toml::Value::as_table) else {
        return Ok(None);
    };
    let Some(providers_value) = global.get("providers") else {
        return Ok(None);
    };
    let Some(providers) = providers_value.as_table() else {
        return Err(provider_state_error(
            "raw",
            "`global.providers` is not a table",
        ));
    };
    let data_root = global_tool_data_root(scope)?;
    let locks_root = data_root.join("locks");
    let storage = global_tool_storage(scope)?;
    let mut candidates = Vec::new();
    for (key, record) in providers {
        let Some(record) = record.as_table() else {
            return Err(provider_state_error(key, "provider record is not a table"));
        };
        let lock_path = provider_string_field(key, record, "lock_path")?.ok_or_else(|| {
            provider_state_error(
                key,
                "provider record has no `lock_path`; repair the record or reinstall the provider",
            )
        })?;
        let path = Path::new(lock_path);
        if !path.starts_with(&locks_root) || !safe_global_lock_name(path) {
            return Err(provider_state_error(
                key,
                "provider lock path is outside the nenv lock directory or has an unsafe name",
            ));
        }
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(provider_state_error(
                    key,
                    "provider lock path is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(provider_state_error(key, "provider lock file is missing"));
            }
            Err(error) => {
                return Err(provider_state_error(
                    key,
                    &format!("provider lock file cannot be inspected: {error}"),
                ));
            }
        }
        let lockfile = read_lockfile(path)?;
        let (entry, binaries) = bind_provider_record(key, record, &lockfile)?;
        if binaries.iter().any(|binary| binary == executable) {
            let cargo_build = lockfile
                .cargo_build
                .as_ref()
                .filter(|build| build.tool_id == entry.id)
                .cloned();
            candidates.push((key.clone(), entry, cargo_build));
        }
    }
    if candidates.len() > 1 {
        let keys = candidates
            .iter()
            .map(|(key, _, _)| key.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "multiple global provider records claim `{executable}` ({keys}); refusing to choose one by order"
            ),
        ));
    }
    let Some((key, entry, cargo_build)) = candidates.pop() else {
        return Ok(None);
    };
    if entry.resolver == "cargo" && cargo_build.is_none() {
        return Err(provider_state_error(
            &key,
            "Cargo provider lock has no associated build record",
        ));
    }
    let single = neoenv_core::tools::ToolLockfile {
        schema_version: neoenv_core::tools::TOOL_LOCK_SCHEMA_VERSION,
        tools: vec![entry],
        pins: std::collections::BTreeMap::new(),
        manager_lock: None,
        cargo_build,
    };
    let Some(result) = which_installed_in(&storage, &single, executable) else {
        return Err(Diagnostic::new(
            DiagnosticCategory::NotFound,
            "NEO521",
            format!(
                "selected global provider `{key}` lists `{executable}` but its installed executable is missing or unusable"
            ),
        ));
    };
    Ok(Some(result))
}

/// Binds a persisted provider record to the lock entry with the same key.
///
/// A missing `binaries`, version, or digest field is recovered from the verified
/// lock entry. A field that is present must match. An absent field is not a
/// reason to guess: the lock entry is the source of truth once it is bound by the
/// record key. This is the legacy-compatible direction for records written before
/// a field existed.
fn bind_provider_record(
    key: &str,
    record: &toml::map::Map<String, toml::Value>,
    lockfile: &neoenv_core::tools::ToolLockfile,
) -> Result<(neoenv_core::tools::LockedTool, Vec<String>), Diagnostic> {
    let entry = lockfile
        .tools
        .iter()
        .find(|entry| entry.id == key)
        .ok_or_else(|| {
            provider_state_error(
                key,
                "the lock file has no entry for this provider's recorded key",
            )
        })?;
    let binaries = match record.get("binaries") {
        Some(value) => {
            let values = value
                .as_array()
                .ok_or_else(|| provider_state_error(key, "provider `binaries` is not an array"))?;
            let recorded = values
                .iter()
                .map(toml::Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    provider_state_error(key, "provider `binaries` contains a non-string entry")
                })?;
            if recorded != entry.binaries {
                return Err(provider_record_mismatch(
                    key,
                    "binaries",
                    "the lock entry and the persisted provider record disagree",
                ));
            }
            entry.binaries.clone()
        }
        None => entry.binaries.clone(),
    };
    for field in ["version", "resolved_version"] {
        if let Some(version) = provider_string_field(key, record, field)?
            && version != entry.resolved_version
        {
            return Err(provider_record_mismatch(
                key,
                field,
                "the lock entry and the persisted provider record disagree",
            ));
        }
    }
    for field in ["sha256", "digest"] {
        if let Some(digest) = provider_string_field(key, record, field)?
            && digest != entry.sha256
        {
            return Err(provider_record_mismatch(
                key,
                field,
                "the lock entry and the persisted provider record disagree",
            ));
        }
    }
    if let Some(immutable) = provider_string_field(key, record, "immutable_id")?
        && immutable != entry.provenance.immutable_id
    {
        return Err(provider_record_mismatch(
            key,
            "immutable_id",
            "the lock entry and the persisted provider record disagree",
        ));
    }
    if let Some(resolver) = provider_string_field(key, record, "resolver")?
        && resolver != entry.resolver
    {
        return Err(provider_record_mismatch(
            key,
            "resolver",
            "the lock entry and the persisted provider record disagree",
        ));
    }
    if let Some(source) = provider_string_field(key, record, "source")?
        && source != entry.url
    {
        return Err(provider_record_mismatch(
            key,
            "source",
            "the lock entry and the persisted provider record disagree",
        ));
    }
    Ok((entry.clone(), binaries))
}

/// Reads an optional string field without conflating absence and a wrong type.
///
/// `record.get(field).and_then(as_str)` returns `None` for both; absence may be
/// recovered from the lock entry, but a present integer/array/bool must be
/// named and refused.
fn provider_string_field<'a>(
    key: &str,
    record: &'a toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<Option<&'a str>, Diagnostic> {
    match record.get(field) {
        None => Ok(None),
        Some(toml::Value::String(value)) => Ok(Some(value)),
        Some(value) => Err(provider_state_error(
            key,
            &format!(
                "provider field `{field}` must be a string, not {}",
                toml_kind(value)
            ),
        )),
    }
}

fn toml_kind(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "a string",
        toml::Value::Integer(_) => "an integer",
        toml::Value::Float(_) => "a float",
        toml::Value::Boolean(_) => "a boolean",
        toml::Value::Datetime(_) => "a datetime",
        toml::Value::Array(_) => "an array",
        toml::Value::Table(_) => "a table",
    }
}

fn provider_record_mismatch(key: &str, field: &str, detail: &str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO522",
        format!("selected global provider `{key}` has a mismatched `{field}`: {detail}"),
    )
}

fn provider_state_error(key: &str, detail: &str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO522",
        format!("selected global provider `{key}` is unreadable: {detail}"),
    )
}

/// An existing global configuration file, with only `NotFound` treated as absence.
///
/// `Path::is_file` collapses a directory, a dangling symlink, and a permission
/// error into the same `false`; that would silently turn a damaged user
/// configuration into "no tools installed" and let a caller try another scope.
/// This returns the path only for a regular, non-symlink file.
fn existing_global_config(scope: GlobalScope) -> Result<Option<PathBuf>, Diagnostic> {
    let path = global_tool_config_path(scope)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(Some(path))
        }
        Ok(_) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "global configuration {} is not a regular file (a directory, symlink, or special file is not accepted)",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to inspect global configuration {}: {error}",
                path.display()
            ),
        )),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn globally_selected_native_executable(
    executable: &str,
    scope: GlobalScope,
) -> Result<Option<PathBuf>, Diagnostic> {
    let Some(config_path) = existing_global_config(scope)? else {
        return Ok(None);
    };
    let input = read_text_file(&config_path, &ResourceBudget::default()).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!("failed to read {}: {error}", config_path.display()),
        )
    })?;
    let document = toml::from_str::<toml::Value>(&input).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO103",
            format!(
                "invalid nenv global configuration {}: {error}",
                config_path.display()
            ),
        )
    })?;
    if let Some(path) = globally_selected_provider_executable(&document, executable, scope)? {
        return Ok(Some(path));
    }
    let runtime = match executable {
        "golang" => "go",
        "python3" => "python",
        "cargo" | "rust" | "rustc" | "rustup" => "rust",
        // Every JDK tool lives in the same `bin` directory, so a request for
        // `javac` must select the `java` runtime and then look for `javac`
        // inside it. Falling through to the default arm would look for a
        // runtime literally named `javac`, which is never installed.
        "java" | "javaw" | "javac" | "javadoc" | "javap" | "jar" | "jshell" | "jlink"
        | "jpackage" | "keytool" | "jarsigner" | "jdeps" | "jcmd" | "jconsole" | "jdb" | "jps"
        | "jstat" | "jfr" => "java",
        name => name,
    };
    let Some(version) = document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("tools"))
        .and_then(toml::Value::as_table)
        .and_then(|tools| tools.get(runtime))
        .and_then(toml::Value::as_str)
    else {
        return Ok(None);
    };
    let binary = if runtime == "python" {
        if cfg!(windows) {
            "python.exe".into()
        } else {
            "python3".into()
        }
    } else if runtime == "rust" {
        let executable = if executable == "rust" {
            "rustc"
        } else {
            executable
        };
        if cfg!(windows) {
            format!("{executable}.exe")
        } else {
            executable.into()
        }
    } else if runtime == "java" {
        if cfg!(windows) {
            format!("{executable}.exe")
        } else {
            executable.into()
        }
    } else if cfg!(windows) {
        format!("{runtime}.exe")
    } else {
        runtime.into()
    };
    let root = global_tool_data_directory(scope)?
        .join(runtime)
        .join(version);
    let path = if runtime == "bun" {
        bun_binary_directory(&root).join(binary)
    } else if runtime == "go" {
        root.join("go").join("bin").join(binary)
    } else if runtime == "java" {
        // `root` already ends in the release version, so the shared helper
        // applies the macOS `Contents/Home` segment consistently with the
        // installer, layout, and `JAVA_HOME`.
        java_home_directory(&root, version).join("bin").join(binary)
    } else if runtime == "odin" {
        root.join("dist").join(binary)
    } else if runtime == "python" {
        if cfg!(windows) {
            root.join("python").join(binary)
        } else {
            root.join("python").join("bin").join(binary)
        }
    } else if runtime == "rust" {
        let target = if cfg!(windows) {
            if cfg!(target_arch = "aarch64") {
                "aarch64-pc-windows-msvc"
            } else {
                "x86_64-pc-windows-msvc"
            }
        } else if cfg!(target_os = "macos") {
            if cfg!(target_arch = "aarch64") {
                "aarch64-apple-darwin"
            } else {
                "x86_64-apple-darwin"
            }
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-unknown-linux-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        root.join("rustup")
            .join("toolchains")
            .join(format!("{version}-{target}"))
            .join("bin")
            .join(binary)
    } else if runtime == "node" {
        let platform = if cfg!(windows) {
            "win"
        } else if cfg!(target_os = "macos") {
            "darwin"
        } else {
            "linux"
        };
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };
        let directory = format!("node-v{version}-{platform}-{arch}");
        if cfg!(windows) {
            root.join(directory).join(binary)
        } else {
            root.join(directory).join("bin").join(binary)
        }
    } else if runtime == "zig" {
        let os = if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        };
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        root.join(format!("zig-{arch}-{os}-{version}")).join(binary)
    } else if runtime == "uv" {
        if cfg!(windows) {
            return Ok(root.join(&binary).is_file().then_some(root.join(binary)));
        }
        let target = if cfg!(windows) {
            if cfg!(target_arch = "aarch64") {
                "aarch64-pc-windows-msvc"
            } else {
                "x86_64-pc-windows-msvc"
            }
        } else if cfg!(target_os = "macos") {
            if cfg!(target_arch = "aarch64") {
                "aarch64-apple-darwin"
            } else {
                "x86_64-apple-darwin"
            }
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-unknown-linux-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        root.join(format!("uv-{target}")).join(binary)
    } else {
        root.join(binary)
    };
    Ok(path.is_file().then_some(path))
}

pub(super) fn tool_plan_error(error: &neoenv_core::tools::ToolPlanError) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO510", error.to_string())
        .with_cause(error.clone())
}

fn print_global_tool_states(scope: ToolScope, format: OutputFormat) -> Result<(), Diagnostic> {
    let scope = match scope {
        ToolScope::User => GlobalScope::User,
        ToolScope::Global => GlobalScope::System,
        ToolScope::Project => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Usage,
                "NEO001",
                "tool list accepts --user or --global here, not --project",
            ));
        }
    };
    let Some(path) = existing_global_config(scope)? else {
        return print_global_config_list(&[], scope, format);
    };
    let mut configured: Vec<(String, String)> = Vec::new();
    {
        let document = read_global_tool_document(&path)?;
        if let Some(tools) = document
            .get("global")
            .and_then(toml::Value::as_table)
            .and_then(|global| global.get("tools"))
            .and_then(toml::Value::as_table)
        {
            configured.extend(tools.iter().filter_map(|(id, version)| {
                version
                    .as_str()
                    .map(|version| (id.clone(), version.to_owned()))
            }));
        }
    }
    print_global_config_list(&configured, scope, format)
}

fn print_global_config_list(
    configured: &[(String, String)],
    scope: GlobalScope,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => {
            for (id, version) in configured {
                println!("configured\t{id}\t{version}");
            }
        }
        OutputFormat::Json => print_json(&serde_json::json!({
            "schema_version": 1,
            "contract": "global-tool-config",
            "scope": match scope { GlobalScope::User => "user", GlobalScope::System => "system" },
            "configured_tools": configured
                .iter()
                .map(|(id, version)| serde_json::json!({ "id": id, "configured_version": version }))
                .collect::<Vec<_>>(),
            "installed_state_included": false,
        }))?,
    }
    Ok(())
}

pub(super) fn print_installed(
    installed: &[neoenv_installer::tools::InstalledTool],
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => {
            for tool in installed {
                println!(
                    "{} {} {} {} {} {}",
                    tool.id,
                    tool.resolved_version,
                    tool.bin_dir.display(),
                    tool.url,
                    tool.sha256,
                    tool.resolver,
                );
            }
        }
        OutputFormat::Json => print_json(installed)?,
    }
    Ok(())
}

pub(super) fn print_tool_states(
    states: &[neoenv_installer::tools::ToolState],
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => {
            for tool in states {
                println!(
                    "{} {} {} {} {}",
                    tool.id,
                    tool.resolved_version,
                    tool.provider,
                    if tool.installed {
                        "installed"
                    } else {
                        "missing"
                    },
                    tool.bin_dir.display()
                );
            }
        }
        OutputFormat::Json => print_json(states)?,
    }
    Ok(())
}

pub(super) fn print_cleanup(
    entries: &[neoenv_installer::tools::CleanupEntry],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => {
            for entry in entries {
                println!(
                    "{} {} {}",
                    if dry_run { "would-remove" } else { "removed" },
                    entry.kind,
                    entry.path.display()
                );
            }
        }
        OutputFormat::Json => print_json(
            &serde_json::json!({ "dry_run": dry_run, "entries": entries, "images": "unsupported" }),
        )?,
    }
    Ok(())
}
