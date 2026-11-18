//! Project tool lifecycle: update, pin, and unpin over the project lockfile
//! and install root, including retention-aware purge candidate selection.

use super::version::compare_versions;
use super::{
    Diagnostic, HashSet, LifecycleReport, LockedTool, OutputFormat, PROJECT_UPDATE_SOURCE_PREFIX,
    Path, PathBuf, Platform, ResolvedProject, ToolLockfile, ToolProvider, ToolScope,
    artifact_matches_digest, cleanup_project_update_temporary, cleanup_stale_temporaries_in, fs,
    global_install_cancellation, install_locked_tools_in, installed_versions_in, load_project,
    not_found, owned_read_dir, print_report, project_artifact_owned, project_declaration,
    project_for_lifecycle, project_install_root, project_installed_version, project_lock_tool,
    project_pins, project_receipt_matches, project_remove_owned_root, regular_file, runtime,
    split_requested_tool, validate_version, validation, write_project_lock,
};

#[allow(clippy::too_many_lines)]
pub(super) fn update_project(
    project: Option<&ResolvedProject>,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (project_root, lock_path, old_lock) = project_for_lifecycle(project)?;
    // The declarations come from the checked snapshot when there is one. A
    // reload here would be a second read of a mutable path, and the update
    // would act on bytes the trust gate never approved.
    let declarations = match project {
        Some(project) => project.tools.clone(),
        None => load_project(None)?.tools,
    };
    let declarations = &declarations;
    let mut report = LifecycleReport::new(ToolScope::Project, "update", dry_run);
    let cancellation = global_install_cancellation()?;
    let mut requests = Vec::new();
    let mut new_lock = old_lock.clone();
    let mut seen = HashSet::new();

    for value in tools {
        let (id, requested_version) = split_requested_tool(value)?;
        if !seen.insert(id.clone()) {
            return Err(validation(format!("duplicate project tool `{id}`")));
        }
        let current = project_lock_tool(&old_lock, &id)?;
        let current_version = current.resolved_version.clone();
        let pinned = !project_pins(&old_lock, &id).is_empty();
        if requested_version.is_none() && pinned {
            report.change(
                id,
                "keep",
                Some(current_version.clone()),
                Some(current_version),
                Some(project_install_root(&project_root, current)?),
                Some("selected version is pinned"),
            );
            continue;
        }
        let declaration = project_declaration(declarations, &id)?;
        let mut next_declaration = declaration.clone();
        if let Some(version) = requested_version.as_deref() {
            validate_version(version)?;
            version.clone_into(&mut next_declaration.version);
        } else {
            if matches!(declaration.provider, ToolProvider::ExplicitUrl) {
                return Err(validation(format!(
                    "project tool `{id}` uses an explicit URL and does not publish newer versions"
                )));
            }
            if matches!(
                declaration.provider,
                ToolProvider::Aqua | ToolProvider::GoModule | ToolProvider::Extension(_)
            ) {
                return Err(validation(format!(
                    "project tool `{id}` provider does not expose an allowed update policy"
                )));
            }
            next_declaration.version = "latest".into();
            next_declaration.declaration_source.path = format!(
                "{PROJECT_UPDATE_SOURCE_PREFIX}{}",
                declaration.declaration_source.path
            );
        }
        let planned_version = requested_version.clone();
        if dry_run {
            report.change(
                id,
                "update",
                Some(current_version.clone()),
                planned_version.or_else(|| Some("latest".into())),
                Some(project_root.join(neoenv_core::names::PROJECT_TOOL_DIRECTORY)),
                Some("provider resolution deferred until publish"),
            );
            continue;
        }
        let plan = neoenv_installer::tools::resolve_tools(
            std::slice::from_ref(&next_declaration),
            &Platform::host(),
        )?;
        if cancellation.load(std::sync::atomic::Ordering::Acquire) {
            return Err(super::global_install_cancelled());
        }
        let planned = plan
            .tools
            .into_iter()
            .next()
            .ok_or_else(|| validation(format!("project tool `{id}` resolved no artifact")))?;
        let mut planned = planned;
        planned.declaration_source = declaration.declaration_source.clone();
        let next_version = planned.resolved_version.clone();
        if requested_version.is_none()
            && compare_versions(&next_version, &current_version) != std::cmp::Ordering::Greater
        {
            report.change(
                id,
                "keep",
                Some(current_version),
                Some(next_version),
                Some(project_install_root(&project_root, current)?),
                Some("no newer provider version is available"),
            );
            continue;
        }
        let replacement = LockedTool::from(&planned);
        if let Some(slot) = new_lock.tools.iter_mut().find(|tool| tool.id == id) {
            *slot = replacement.clone();
        } else {
            return Err(not_found(format!("project tool is not locked: {id}")));
        }
        report.change(
            id.clone(),
            "update",
            Some(current_version),
            Some(next_version),
            Some(project_install_root(&project_root, &replacement)?),
            None,
        );
        requests.push((id, planned));
    }

    if dry_run || requests.is_empty() {
        return print_report(&report, format);
    }

    let storage = neoenv_installer::tools::ToolStorage::project(&project_root);
    cleanup_stale_temporaries_in(&storage)?;
    let mut newly_published = Vec::new();
    let mut newly_cached_artifacts = Vec::new();
    for (id, planned) in &requests {
        let replacement = new_lock
            .tools
            .iter()
            .find(|tool| tool.id == *id)
            .ok_or_else(|| not_found(format!("project tool is not locked: {id}")))?;
        let key = neoenv_installer::tools::install_key(replacement)?;
        let root = storage.install_directory().join(&key);
        if !root.exists() {
            newly_published.push((id.clone(), key));
        }
        let artifact = storage.artifact_directory().join(&planned.sha256);
        if !artifact.exists() {
            newly_cached_artifacts.push(planned.sha256.clone());
        }
    }
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        return Err(super::global_install_cancelled());
    }
    if let Err(error) = install_locked_tools_in(&storage, &new_lock) {
        cleanup_project_update_temporary(&storage, &newly_published, &newly_cached_artifacts);
        return Err(error);
    }
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        cleanup_project_update_temporary(&storage, &newly_published, &newly_cached_artifacts);
        return Err(super::global_install_cancelled());
    }
    if let Err(error) = write_project_lock(&lock_path, &new_lock) {
        cleanup_project_update_temporary(&storage, &newly_published, &newly_cached_artifacts);
        return Err(error);
    }
    print_report(&report, format)
}

pub(super) fn pin_project(
    project: Option<&ResolvedProject>,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (root, lock_path, old_lock) = project_for_lifecycle(project)?;
    let mut report = LifecycleReport::new(ToolScope::Project, "pin", dry_run);
    let mut requested = Vec::new();
    for value in tools {
        let (id, requested_version) = split_requested_tool(value)?;
        let version = match requested_version {
            Some(version) => version,
            None => project_lock_tool(&old_lock, &id)?.resolved_version.clone(),
        };
        let (path, _) =
            project_installed_version(&root, &old_lock, &id, &version)?.ok_or_else(|| {
                not_found(format!("installed project tool not found: {id}@{version}"))
            })?;
        requested.push((id, version, path));
    }
    for (id, version, path) in &requested {
        report.change(
            id,
            "pin",
            Some(version.clone()),
            Some(version.clone()),
            Some(path.clone()),
            None,
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    let mut document = old_lock.clone();
    for (id, version, _) in requested {
        let versions = document.pins.entry(id).or_default();
        if !versions.contains(&version) {
            versions.push(version);
            versions.sort();
            versions.dedup();
        }
    }
    write_project_lock(&lock_path, &document)?;
    print_report(&report, format)
}

pub(super) fn unpin_project(
    project: Option<&ResolvedProject>,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (_, lock_path, old_lock) = project_for_lifecycle(project)?;
    let mut report = LifecycleReport::new(ToolScope::Project, "unpin", dry_run);
    let mut requested = Vec::new();
    for value in tools {
        let (id, requested_version) = split_requested_tool(value)?;
        if let Some(version) = requested_version {
            if !old_lock
                .pins
                .get(&id)
                .is_some_and(|versions| versions.contains(&version))
            {
                return Err(not_found(format!(
                    "project tool version is not pinned: {id}@{version}"
                )));
            }
            requested.push((id, Some(version)));
        } else {
            if !old_lock.pins.contains_key(&id) {
                return Err(not_found(format!("project tool is not pinned: {id}")));
            }
            requested.push((id, None));
        }
    }
    for (id, version) in &requested {
        report.change(
            id,
            "unpin",
            version.clone(),
            None,
            None,
            Some("version constraint removed"),
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    let mut document = old_lock.clone();
    for (id, version) in requested {
        if let Some(version) = version {
            if let Some(versions) = document.pins.get_mut(&id) {
                versions.retain(|value| value != &version);
                if versions.is_empty() {
                    document.pins.remove(&id);
                }
            }
        } else {
            document.pins.remove(&id);
        }
    }
    write_project_lock(&lock_path, &document)?;
    print_report(&report, format)
}

pub(super) fn project_retained_hashes(root: &Path, lockfile: &ToolLockfile) -> HashSet<String> {
    let mut retained = HashSet::new();
    for tool in &lockfile.tools {
        retained.insert(tool.sha256.clone());
    }
    for (id, versions) in &lockfile.pins {
        for version in versions {
            if let Ok(Some((_, sha256))) = project_installed_version(root, lockfile, id, version) {
                retained.insert(sha256);
            }
        }
    }
    retained
}

fn project_retained_install_keys(
    root: &Path,
    lockfile: &ToolLockfile,
) -> Result<HashSet<String>, Diagnostic> {
    let mut retained = lockfile
        .tools
        .iter()
        .map(neoenv_installer::tools::install_key)
        .collect::<Result<HashSet<_>, _>>()?;
    for (id, versions) in &lockfile.pins {
        for version in versions {
            if let Some((path, _)) = project_installed_version(root, lockfile, id, version)?
                && let Some(key) = path.file_name().and_then(|name| name.to_str())
            {
                retained.insert(key.to_owned());
            }
        }
    }
    Ok(retained)
}

pub(super) fn project_purge_candidates(
    root: &Path,
    lockfile: &ToolLockfile,
) -> Result<Vec<(String, String, PathBuf)>, Diagnostic> {
    let storage = neoenv_installer::tools::ToolStorage::project(root);
    let retained = project_retained_install_keys(root, lockfile)?;
    let mut candidates = Vec::new();
    for entry in installed_versions_in(&storage)? {
        let Some(storage_key) = entry.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !retained.contains(storage_key) {
            candidates.push((entry.id, entry.resolved_version, entry.path));
        }
    }
    // Also account for legacy digest-named roots which predate the metadata
    // marker.  Only exact SHA-256 directory names are considered; arbitrary
    // files and symlinks are left untouched.
    if let Some(entries) = owned_read_dir(storage.install_directory())? {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !neoenv_core::tools::is_sha256(name) || retained.contains(name) {
                continue;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            let owned = project_receipt_matches(&path, name);
            if owned && metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                let known = candidates
                    .iter()
                    .any(|(_, _, candidate)| candidate == &path);
                if !known {
                    candidates.push(("unknown".into(), name.to_owned(), path));
                }
            }
        }
    }
    candidates.sort_by(|left, right| left.2.cmp(&right.2));
    Ok(candidates)
}

pub(super) fn project_purge_artifacts(
    root: &Path,
    retained: &HashSet<String>,
) -> Result<Vec<PathBuf>, Diagnostic> {
    let storage = neoenv_installer::tools::ToolStorage::project(root);
    let mut result = Vec::new();
    let Some(entries) = owned_read_dir(storage.artifact_directory())? else {
        return Ok(result);
    };
    for entry in entries {
        let entry = entry.map_err(|error| runtime(storage.artifact_directory(), &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !neoenv_core::tools::is_sha256(name) || retained.contains(name) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_file()
            && regular_file(&path)
            && artifact_matches_digest(&path, name)
        {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}

pub(super) fn purge_project(
    project: Option<&ResolvedProject>,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (root, _, lockfile) = project_for_lifecycle(project)?;
    let mut report = LifecycleReport::new(ToolScope::Project, "purge", dry_run);
    let candidates = project_purge_candidates(&root, &lockfile)?;
    let requested: HashSet<String> = tools
        .iter()
        .map(|value| split_requested_tool(value).map(|(id, _)| id))
        .collect::<Result<_, _>>()?;
    for (id, version, path) in candidates {
        if !requested.is_empty() && !requested.contains(&id) {
            continue;
        }
        report.change(
            if id == "unknown" {
                path.display().to_string()
            } else {
                id
            },
            "purge",
            None,
            Some(version),
            Some(path),
            Some("unreferenced nenv-owned version"),
        );
    }
    let retained = project_retained_hashes(&root, &lockfile);
    let artifacts = if requested.is_empty() {
        project_purge_artifacts(&root, &retained)?
    } else {
        Vec::new()
    };
    for path in &artifacts {
        report.change(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
                .to_owned(),
            "purge",
            None,
            None,
            Some(path.clone()),
            Some("unreferenced nenv-owned artifact"),
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    let storage = neoenv_installer::tools::ToolStorage::project(&root);
    for (id, _, path) in project_purge_candidates(&root, &lockfile)? {
        if !requested.is_empty() && !requested.contains(&id) {
            continue;
        }
        if let Some(sha256) = path.file_name().and_then(|name| name.to_str())
            && neoenv_core::tools::is_sha256(sha256)
        {
            let _ = project_remove_owned_root(&storage, &path, sha256)?;
        }
    }
    for path in artifacts {
        if path.starts_with(storage.artifact_directory()) {
            super::remove_global_path(&path)?;
        }
    }
    print_report(&report, format)
}

#[allow(clippy::too_many_lines)]
pub(super) fn remove_project(
    project: Option<&ResolvedProject>,
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (root, lock_path, old_lock) = project_for_lifecycle(project)?;
    let storage = neoenv_installer::tools::ToolStorage::project(&root);
    let mut report = LifecycleReport::new(ToolScope::Project, "remove", dry_run);
    let mut version_requests = Vec::new();
    let mut whole_tools = Vec::new();
    for value in tools {
        let (id, version) = split_requested_tool(value)?;
        if let Some(version) = version {
            if compare_versions(
                &project_lock_tool(&old_lock, &id)?.resolved_version,
                &version,
            ) == std::cmp::Ordering::Equal
            {
                return Err(validation(format!(
                    "selected project tool version cannot be removed one version at a time: {id}@{version}"
                )));
            }
            if old_lock
                .pins
                .get(&id)
                .is_some_and(|versions| versions.contains(&version))
            {
                return Err(validation(format!(
                    "pinned project tool version cannot be removed: {id}@{version}"
                )));
            }
            let (path, sha256) = project_installed_version(&root, &old_lock, &id, &version)?
                .ok_or_else(|| {
                    not_found(format!("installed project tool not found: {id}@{version}"))
                })?;
            version_requests.push((id, version, path, sha256));
        } else {
            project_lock_tool(&old_lock, &id)?;
            whole_tools.push(id);
        }
    }
    for (id, version, path, _) in &version_requests {
        report.change(
            id,
            "remove",
            Some(version.clone()),
            None,
            Some(path.clone()),
            Some("one version only"),
        );
    }
    for id in &whole_tools {
        let paths = installed_versions_in(&storage)?
            .into_iter()
            .filter(|entry| entry.id == *id)
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        report.change(
            id,
            "remove",
            None,
            None,
            paths.first().cloned(),
            Some("whole tool"),
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    // Remove the active lock entry first.  A failed filesystem cleanup then
    // leaves only harmless unreferenced bytes, never a live lock pointing at a
    // deleted executable.
    let mut next_lock = old_lock.clone();
    next_lock
        .tools
        .retain(|tool| !whole_tools.contains(&tool.id));
    if next_lock
        .cargo_build
        .as_ref()
        .is_some_and(|build| whole_tools.contains(&build.tool_id))
    {
        next_lock.cargo_build = None;
    }
    for id in &whole_tools {
        next_lock.pins.remove(id);
    }
    if !whole_tools.is_empty() {
        write_project_lock(&lock_path, &next_lock)?;
    }
    let protected_hashes = project_retained_hashes(&root, &next_lock);
    let protected_installs = project_retained_install_keys(&root, &next_lock)?;
    let mut removed_digests = version_requests
        .iter()
        .map(|(_, _, _, sha256)| sha256.clone())
        .collect::<Vec<_>>();
    removed_digests.extend(
        old_lock
            .tools
            .iter()
            .filter(|tool| whole_tools.contains(&tool.id))
            .map(|tool| tool.sha256.clone()),
    );
    for (_, _, path, sha256) in version_requests {
        let storage_key = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if protected_installs.contains(storage_key) {
            continue;
        }
        if !project_remove_owned_root(&storage, &path, &sha256)? {
            return Err(runtime(
                &path,
                &std::io::Error::other("version is not nenv-owned"),
            ));
        }
    }
    for id in &whole_tools {
        for entry in installed_versions_in(&storage)? {
            let storage_key = entry
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if entry.id == *id && !protected_installs.contains(storage_key) {
                let _ = project_remove_owned_root(&storage, &entry.path, &entry.sha256)?;
            }
        }
        if let Some(tool) = old_lock.tools.iter().find(|tool| tool.id == *id) {
            let storage_key = neoenv_installer::tools::install_key(tool)?;
            let path = storage.install_directory().join(&storage_key);
            if !protected_installs.contains(&storage_key) && path.is_dir() {
                let _ = project_remove_owned_root(&storage, &path, &tool.sha256)?;
            }
        }
    }
    let installed = installed_versions_in(&storage)?;
    for sha256 in removed_digests {
        if protected_hashes.contains(&sha256)
            || next_lock.tools.iter().any(|tool| tool.sha256 == sha256)
            || installed.iter().any(|entry| entry.sha256 == sha256)
        {
            continue;
        }
        let artifact = storage.artifact_directory().join(&sha256);
        if artifact.starts_with(storage.artifact_directory())
            && project_artifact_owned(&artifact, &sha256)
        {
            super::remove_global_path(&artifact)?;
        }
    }
    print_report(&report, format)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use neoenv_core::tools::{Platform, plan_tools};
    use neoenv_installer::tools::{lockfile_path, write_lockfile};
    use tempfile::TempDir;

    use super::{OutputFormat, update_project};

    fn explicit_url_project() -> (TempDir, std::path::PathBuf) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("neoenv.yaml");
        fs::write(
            &path,
            "format_version: 1\n\
             tools:\n  \
               - id: demo\n    \
                 version: 1.0.0\n    \
                 url: https://example.test/artifact\n    \
                 sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n    \
                 binaries: [demo]\n",
        )
        .unwrap();
        (directory, path)
    }

    /// The lifecycle consumes the snapshot the trust gate approved.
    ///
    /// The file is rewritten after the snapshot is taken. If `update_project`
    /// reloaded it, the declaration would be gone and the command would fail
    /// with "not declared". It succeeds instead, and the same call with no
    /// snapshot fails, which proves the rewrite is real and the snapshot is
    /// what was consumed.
    #[test]
    fn update_consumes_the_checked_snapshot_instead_of_reloading() {
        let (_directory, path) = explicit_url_project();
        let checked = crate::output::load_project_with_profile(
            Some(&path.display().to_string()),
            neoenv_config::ConfigProfile::Native,
            None,
        )
        .unwrap();
        let plan = plan_tools(&checked.tools, &Platform::host()).unwrap();
        write_lockfile(&lockfile_path(&checked.project.project_root), &plan).unwrap();

        fs::write(&path, "format_version: 1\n").unwrap();

        update_project(
            Some(&checked),
            &["demo@2.0.0".into()],
            true,
            OutputFormat::Text,
        )
        .expect("the checked snapshot still declares demo");

        let error =
            update_project(None, &["demo@2.0.0".into()], true, OutputFormat::Text).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("not declared") || message.contains("no nenv configuration"),
            "a reload must not see the checked project: {message}"
        );
    }
}
