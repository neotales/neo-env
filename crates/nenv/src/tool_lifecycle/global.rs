//! Global tool lifecycle: update, pin, unpin, purge, and remove over the
//! global configuration and data roots, with per-install ownership proven
//! by a marker file rather than by path shape.

use super::version::compare_versions;
use super::{
    Diagnostic, DiagnosticCategory, GLOBAL_OWNERSHIP_MARKER, GlobalPurgeCandidate, GlobalScope,
    GlobalToolRequest, HashMap, HashSet, LifecycleReport, OutputFormat, Path, PathBuf,
    ResourceBudget, ToolLockfile, ToolScope, cleanup_new_global_installations, fs,
    global_install_cancellation, global_tool_and_version, global_tool_config_path,
    global_tool_data_root, install_global_tools_transaction, installed_versions_in, not_found,
    owned_read_dir, parse_global_tool_request, print_report, project_artifact_owned,
    read_global_tool_document, read_lockfile, read_text_file, record_global_tools, runtime,
    safe_component, split_global_key_version, state_file, state_file_diagnostic, usage,
    validate_version, validation, write_locked_state,
};

fn report_scope(scope: GlobalScope) -> ToolScope {
    match scope {
        GlobalScope::User => ToolScope::User,
        GlobalScope::System => ToolScope::Global,
    }
}

pub(super) fn validate_global_tool_document(document: &toml::Value) -> Result<(), Diagnostic> {
    let Some(global) = document.get("global") else {
        return Ok(());
    };
    let global = global
        .as_table()
        .ok_or_else(|| validation("global must be a TOML table"))?;
    if let Some(tools) = global.get("tools") {
        let tools = tools
            .as_table()
            .ok_or_else(|| validation("global.tools must be a TOML table"))?;
        for (tool, version) in tools {
            let version = version
                .as_str()
                .ok_or_else(|| validation(format!("global tool `{tool}` must select a version")))?;
            validate_version(version)?;
        }
    }
    if let Some(pins) = global.get("pins") {
        let pins = pins
            .as_table()
            .ok_or_else(|| validation("global.pins must be a TOML table"))?;
        for (tool, versions) in pins {
            let versions = versions
                .as_array()
                .ok_or_else(|| validation("global.pins entries must be TOML arrays"))?;
            if versions.is_empty() {
                return Err(validation(format!(
                    "global pin for `{tool}` must contain a version"
                )));
            }
            let mut seen = HashSet::new();
            for version in versions {
                let version = version.as_str().ok_or_else(|| {
                    validation(format!("global pin for `{tool}` must be a version string"))
                })?;
                validate_version(version)?;
                if !seen.insert(version) {
                    return Err(validation(format!(
                        "global pin for `{tool}` contains a duplicate version"
                    )));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn global_snapshot(scope: GlobalScope) -> Result<(PathBuf, toml::Value), Diagnostic> {
    let path = global_tool_config_path(scope)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(validation(
                "global tool configuration is not a regular file",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(not_found("no global tool configuration exists"));
        }
        Err(error) => return Err(runtime(&path, &error)),
    }
    let document = read_global_tool_document(&path)?;
    validate_global_tool_document(&document)?;
    Ok((path, document))
}

pub(super) fn global_tools(
    document: &toml::Value,
) -> Result<toml::map::Map<String, toml::Value>, Diagnostic> {
    document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("tools"))
        .and_then(toml::Value::as_table)
        .cloned()
        .ok_or_else(|| not_found("no global tools are configured"))
}

pub(super) fn global_pins(document: &toml::Value) -> HashMap<String, HashSet<String>> {
    document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("pins"))
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .iter()
                .filter_map(|(key, value)| {
                    value.as_array().map(|versions| {
                        (
                            key.clone(),
                            versions
                                .iter()
                                .filter_map(toml::Value::as_str)
                                .map(str::to_owned)
                                .collect(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn global_native_root(data_root: &Path, tool: &str, version: &str) -> PathBuf {
    data_root.join("tools").join(tool).join(version)
}

pub(super) fn global_native_owned(data_root: &Path, tool: &str, version: &str) -> Option<PathBuf> {
    let path = global_native_root(data_root, tool, version);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    let marker = path.join(GLOBAL_OWNERSHIP_MARKER);
    let marker_metadata = fs::symlink_metadata(&marker).ok()?;
    if !marker_metadata.file_type().is_file() || marker_metadata.file_type().is_symlink() {
        return None;
    }
    // Bounded like every other local read. The marker is nenv-authored and
    // only two short lines, so the budget is never reached in practice; it is
    // here so a corrupt or substituted file cannot be read without limit.
    let contents = read_text_file(&marker, &ResourceBudget::default()).ok()?;
    if contents.lines().eq([tool, version]) {
        Some(path)
    } else {
        None
    }
}

pub(super) fn global_lock_entries(
    data_root: &Path,
    key: &str,
) -> Result<Vec<(PathBuf, ToolLockfile)>, Diagnostic> {
    let locks = data_root.join("locks");
    let Some(entries) = owned_read_dir(&locks)? else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| runtime(&locks, &error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || !name.ends_with(neoenv_core::names::LOCKFILE_LOCK_SUFFIX) {
            continue;
        }
        let path = entry.path();
        if !path.starts_with(&locks)
            || !path.is_file()
            || !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        let Ok(lockfile) = read_lockfile(&path) else {
            continue;
        };
        if lockfile.tools.iter().any(|tool| tool.id == key) {
            result.push((path, lockfile));
        }
    }
    Ok(result)
}

pub(super) fn global_provider_version(
    data_root: &Path,
    key: &str,
    version: &str,
) -> Result<Option<(PathBuf, Option<PathBuf>)>, Diagnostic> {
    for (lock_path, lockfile) in global_lock_entries(data_root, key)? {
        let Some(tool) = lockfile
            .tools
            .iter()
            .find(|tool| tool.id == key && tool.resolved_version == version)
        else {
            continue;
        };
        let path = data_root.join("tools").join(&tool.sha256);
        let storage = neoenv_installer::tools::ToolStorage::global(data_root);
        let owned = installed_versions_in(&storage)?
            .into_iter()
            .any(|entry| entry.sha256 == tool.sha256 && entry.id == key);
        if !owned {
            continue;
        }
        return Ok(Some((path, Some(lock_path))));
    }
    Ok(None)
}

pub(super) fn global_owned_version(
    data_root: &Path,
    key: &str,
    version: &str,
) -> Result<Option<(PathBuf, Option<PathBuf>)>, Diagnostic> {
    if key.contains(':') {
        global_provider_version(data_root, key, version)
    } else {
        Ok(global_native_owned(data_root, key, version).map(|path| (path, None)))
    }
}

pub(super) fn global_all_versions(
    data_root: &Path,
    key: &str,
) -> Result<Vec<(String, PathBuf, Option<PathBuf>)>, Diagnostic> {
    let mut result = Vec::new();
    if key.contains(':') {
        let storage = neoenv_installer::tools::ToolStorage::global(data_root);
        for (lock_path, lockfile) in global_lock_entries(data_root, key)? {
            for tool in lockfile.tools.iter().filter(|tool| tool.id == key) {
                let path = data_root.join("tools").join(&tool.sha256);
                let owned = installed_versions_in(&storage)?
                    .into_iter()
                    .any(|entry| entry.id == key && entry.sha256 == tool.sha256);
                if owned || !path.exists() {
                    result.push((tool.resolved_version.clone(), path, Some(lock_path.clone())));
                }
            }
        }
    } else {
        let directory = data_root.join("tools").join(key);
        let Some(entries) = owned_read_dir(&directory)? else {
            return Ok(result);
        };
        for entry in entries {
            let entry = entry.map_err(|error| runtime(&directory, &error))?;
            let version = entry.file_name().to_string_lossy().into_owned();
            if !safe_component(&version) {
                continue;
            }
            if let Some(path) = global_native_owned(data_root, key, &version) {
                result.push((version, path, None));
            }
        }
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    result.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1 && left.2 == right.2);
    Ok(result)
}

#[allow(clippy::too_many_lines)]
pub(super) fn update_global(
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let (_, document) = global_snapshot(scope)?;
    let configured = global_tools(&document)?;
    let pins = global_pins(&document);
    let data_root = global_tool_data_root(scope)?;
    let mut report = LifecycleReport::new(report_scope(scope), "update", dry_run);
    let mut requests = Vec::new();
    let mut seen = HashSet::new();
    for value in tools {
        let (key, version) = split_global_key_version(value)?;
        let explicit = version.is_some();
        let mut request = parse_global_tool_request(key, version)?;
        if !explicit {
            // Lifecycle update must ask the provider for its current release;
            // an omitted argument in ordinary `use` deliberately means the
            // already selected version for offline repeatability.
            request.version = Some("latest".into());
        }
        if !seen.insert(request.tool.clone()) {
            return Err(validation(format!(
                "duplicate global tool `{}`",
                request.tool
            )));
        }
        let current = configured
            .get(&request.tool)
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| not_found(format!("global tool is not configured: {}", request.tool)))?;
        if !explicit
            && pins
                .get(&request.tool)
                .is_some_and(|versions| !versions.is_empty())
        {
            report.change(
                request.tool.clone(),
                "keep",
                Some(current.clone()),
                Some(current.clone()),
                global_configured_path(&data_root, &document, &request.tool, &current)
                    .or_else(|| Some(global_native_root(&data_root, &request.tool, &current))),
                Some("selected version is pinned"),
            );
            continue;
        }
        if dry_run {
            report.change(
                request.tool.clone(),
                "update",
                Some(current.clone()),
                request.version.clone().or_else(|| Some("latest".into())),
                Some(data_root.join("tools")),
                Some("provider resolution deferred until publish"),
            );
            continue;
        }
        requests.push((request, current, explicit));
    }
    if dry_run || requests.is_empty() {
        return print_report(&report, format);
    }
    let cancellation = global_install_cancellation()?;
    let request_values: Vec<_> = requests
        .iter()
        .map(|(request, _, _)| request.clone())
        .collect();
    let before_versions = global_existing_versions(&request_values, scope)?;
    let installations =
        install_global_tools_transaction(&request_values, &cancellation, false, scope)?;
    let mut selected = Vec::new();
    let mut cleanup = Vec::new();
    for (installation, (_, current, explicit)) in installations.into_iter().zip(requests.iter()) {
        let mut installation = installation;
        if installation.provider.is_none()
            && !before_versions.iter().any(|(tool, version)| {
                tool == &installation.tool && version == &installation.version
            })
        {
            installation.new_install = true;
        }
        if !*explicit
            && compare_versions(&installation.version, current) != std::cmp::Ordering::Greater
        {
            report.change(
                installation.tool.clone(),
                "keep",
                Some(current.clone()),
                Some(installation.version.clone()),
                Some(installation.executable.clone()),
                Some("no newer provider version is available"),
            );
            if let Some(provider) = &installation.provider {
                let recorded = global_recorded_lock_path(&document, &installation.tool);
                if recorded.as_deref() != Some(provider.lock_path.as_path()) {
                    let _ = super::remove_global_path(&provider.lock_path);
                }
            }
            if installation.new_install {
                cleanup.push(installation.clone());
            }
        } else {
            report.change(
                installation.tool.clone(),
                "update",
                Some(current.clone()),
                Some(installation.version.clone()),
                Some(installation.executable.clone()),
                None,
            );
            selected.push(installation.clone());
        }
    }
    if !selected.is_empty()
        && let Err(error) = record_global_tools(&selected, &cancellation, scope)
    {
        cleanup_new_global_installations(&selected, scope);
        cleanup_unselected_global_records(&document, &selected);
        return Err(error);
    }
    cleanup_new_global_installations(&cleanup, scope);
    print_report(&report, format)
}

pub(super) fn cleanup_unselected_global_records(
    document: &toml::Value,
    installations: &[super::GlobalToolInstallation],
) {
    for installation in installations {
        let Some(provider) = &installation.provider else {
            continue;
        };
        let recorded = global_recorded_lock_path(document, &installation.tool);
        if recorded.as_deref() != Some(provider.lock_path.as_path()) {
            let _ = super::remove_global_path(&provider.lock_path);
        }
    }
}

pub(super) fn global_existing_versions(
    requests: &[GlobalToolRequest],
    scope: GlobalScope,
) -> Result<Vec<(String, String)>, Diagnostic> {
    let data_root = global_tool_data_root(scope)?;
    let mut versions = Vec::new();
    for request in requests {
        if request.declaration.is_none() {
            let directory = data_root.join("tools").join(&request.tool);
            if let Some(entries) = owned_read_dir(&directory)? {
                for entry in entries.flatten() {
                    versions.push((
                        request.tool.clone(),
                        entry.file_name().to_string_lossy().into_owned(),
                    ));
                }
            }
        }
    }
    Ok(versions)
}

pub(super) fn pin_global(
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let (path, document) = global_snapshot(scope)?;
    let configured = global_tools(&document)?;
    let data_root = global_tool_data_root(scope)?;
    let mut report = LifecycleReport::new(report_scope(scope), "pin", dry_run);
    let mut requested = Vec::new();
    for value in tools {
        let (key, requested_version) = global_tool_and_version(value)?;
        let version = match requested_version {
            Some(version) => version.to_owned(),
            None => configured_global_version_from_table(&configured, key)?,
        };
        let owned = global_owned_version(&data_root, key, &version)?.ok_or_else(|| {
            not_found(format!("installed global tool not found: {key}@{version}"))
        })?;
        requested.push((key.to_owned(), version, owned.0));
    }
    for (key, version, path_value) in &requested {
        report.change(
            key,
            "pin",
            Some(version.clone()),
            Some(version.clone()),
            Some(path_value.clone()),
            None,
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    let state = state_file::lock(&path).map_err(|error| state_file_diagnostic(&path, error))?;
    let mut document = toml::from_str::<toml::Value>(
        &state
            .read_to_string()
            .map_err(|error| state_file_diagnostic(&path, error))?,
    )
    .map_err(|error| validation(format!("invalid nenv global configuration: {error}")))?;
    let global = document
        .as_table_mut()
        .and_then(|root| root.get_mut("global"))
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| not_found("no global tools are configured"))?;
    let pins = global
        .entry("pins")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| validation("global.pins must be a TOML table"))?;
    for (key, version, _) in requested {
        let versions = pins
            .entry(key)
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| validation("global.pins entries must be TOML arrays"))?;
        if !versions
            .iter()
            .any(|value| value.as_str() == Some(version.as_str()))
        {
            versions.push(toml::Value::String(version));
        }
    }
    let output = toml::to_string_pretty(&document).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
    })?;
    write_locked_state(&state, &output)?;
    print_report(&report, format)
}

pub(super) fn global_recorded_lock_path(document: &toml::Value, key: &str) -> Option<PathBuf> {
    document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("providers"))
        .and_then(toml::Value::as_table)
        .and_then(|providers| providers.get(key))
        .and_then(toml::Value::as_table)
        .and_then(|record| record.get("lock_path"))
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
}

pub(super) fn global_configured_path(
    data_root: &Path,
    document: &toml::Value,
    key: &str,
    version: &str,
) -> Option<PathBuf> {
    if !key.contains(':') {
        return Some(global_native_root(data_root, key, version));
    }
    let record = document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("providers"))
        .and_then(toml::Value::as_table)
        .and_then(|providers| providers.get(key))
        .and_then(toml::Value::as_table)?;
    let recorded_version = record
        .get("resolved_version")
        .and_then(toml::Value::as_str)
        .or_else(|| record.get("version").and_then(toml::Value::as_str))?;
    if recorded_version != version {
        return None;
    }
    let path = PathBuf::from(record.get("install_path")?.as_str()?);
    let tools_root = data_root.join("tools");
    if !path.starts_with(&tools_root)
        || path == tools_root
        || !fs::symlink_metadata(&path).is_ok_and(|metadata| {
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink()
        })
    {
        return None;
    }
    Some(path)
}

pub(super) fn configured_global_version_from_table(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<String, Diagnostic> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| not_found(format!("global tool is not configured: {key}")))
}

pub(super) fn unpin_global(
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let (path, document) = global_snapshot(scope)?;
    let pins = global_pins(&document);
    let mut report = LifecycleReport::new(report_scope(scope), "unpin", dry_run);
    let mut requested = Vec::new();
    for value in tools {
        let (key, version) = global_tool_and_version(value)?;
        if let Some(version) = version {
            if !pins
                .get(key)
                .is_some_and(|versions| versions.contains(&version.to_owned()))
            {
                return Err(not_found(format!(
                    "global tool version is not pinned: {key}@{version}"
                )));
            }
            report.change(
                key,
                "unpin",
                Some(version.into()),
                None,
                None,
                Some("version constraint removed"),
            );
            requested.push((key.to_owned(), Some(version.to_owned())));
        } else {
            if !pins.contains_key(key) {
                return Err(not_found(format!("global tool is not pinned: {key}")));
            }
            report.change(
                key,
                "unpin",
                None,
                None,
                None,
                Some("all version constraints removed"),
            );
            requested.push((key.to_owned(), None));
        }
    }
    if dry_run {
        return print_report(&report, format);
    }
    let state = state_file::lock(&path).map_err(|error| state_file_diagnostic(&path, error))?;
    let mut document = toml::from_str::<toml::Value>(
        &state
            .read_to_string()
            .map_err(|error| state_file_diagnostic(&path, error))?,
    )
    .map_err(|error| validation(format!("invalid nenv global configuration: {error}")))?;
    let pins = document
        .as_table_mut()
        .and_then(|root| root.get_mut("global"))
        .and_then(toml::Value::as_table_mut)
        .and_then(|global| global.get_mut("pins"))
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| not_found("no global tool versions are pinned"))?;
    for (key, version) in requested {
        if let Some(version) = version {
            if let Some(versions) = pins.get_mut(&key).and_then(toml::Value::as_array_mut) {
                versions.retain(|value| value.as_str() != Some(version.as_str()));
                if versions.is_empty() {
                    pins.remove(&key);
                }
            }
        } else {
            pins.remove(&key);
        }
    }
    let output = toml::to_string_pretty(&document).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
    })?;
    write_locked_state(&state, &output)?;
    print_report(&report, format)
}

pub(super) fn global_retained_provider_paths(
    data_root: &Path,
    document: &toml::Value,
) -> Result<HashSet<PathBuf>, Diagnostic> {
    global_retained_provider_paths_except(data_root, document, &[], false)
}

pub(super) fn global_retained_provider_paths_except(
    data_root: &Path,
    document: &toml::Value,
    excluded: &[(String, Option<String>)],
    retain_all_references: bool,
) -> Result<HashSet<PathBuf>, Diagnostic> {
    let configured = global_tools(document)?;
    let pins = global_pins(document);
    let mut retained = HashSet::new();
    let locks = data_root.join("locks");
    let Some(entries) = owned_read_dir(&locks)? else {
        return Ok(retained);
    };
    for entry in entries {
        let entry = entry.map_err(|error| runtime(&locks, &error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || !name.ends_with(neoenv_core::names::LOCKFILE_LOCK_SUFFIX) {
            continue;
        }
        let path = entry.path();
        if !path.starts_with(&locks)
            || !path.is_file()
            || !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        let Ok(lockfile) = read_lockfile(&path) else {
            continue;
        };
        for tool in &lockfile.tools {
            if excluded.iter().any(|(key, version)| {
                key == &tool.id
                    && version
                        .as_ref()
                        .is_none_or(|version| version == &tool.resolved_version)
            }) {
                continue;
            }
            let selected = configured.get(&tool.id).and_then(toml::Value::as_str);
            let pinned = pins
                .get(&tool.id)
                .is_some_and(|versions| versions.contains(&tool.resolved_version));
            if retain_all_references
                || selected.is_some_and(|selected| {
                    compare_versions(selected, &tool.resolved_version) == std::cmp::Ordering::Equal
                })
                || pinned
            {
                retained.insert(data_root.join("tools").join(&tool.sha256));
            }
        }
    }
    Ok(retained)
}

pub(super) fn global_lock_is_exhausted(
    path: &Path,
    key: &str,
    version: Option<&str>,
) -> Result<bool, Diagnostic> {
    let lockfile = read_lockfile(path)?;
    Ok(!lockfile.tools.is_empty()
        && lockfile.tools.iter().all(|tool| {
            tool.id == key && version.is_none_or(|version| tool.resolved_version == version)
        }))
}

pub(super) fn cleanup_global_artifacts(data_root: &Path) -> Result<(), Diagnostic> {
    let storage = neoenv_installer::tools::ToolStorage::global(data_root);
    let mut retained = installed_versions_in(&storage)?
        .into_iter()
        .map(|entry| entry.sha256)
        .collect::<HashSet<_>>();
    let locks = data_root.join("locks");
    if let Some(entries) = owned_read_dir(&locks)? {
        for entry in entries {
            let entry = entry.map_err(|error| runtime(&locks, &error))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || !name.ends_with(neoenv_core::names::LOCKFILE_LOCK_SUFFIX) {
                continue;
            }
            let path = entry.path();
            if !path.starts_with(&locks)
                || !path.is_file()
                || !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file())
            {
                continue;
            }
            if let Ok(lockfile) = read_lockfile(&path) {
                retained.extend(lockfile.tools.into_iter().map(|tool| tool.sha256));
            }
        }
    }
    let Some(entries) = owned_read_dir(storage.artifact_directory())? else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|error| runtime(storage.artifact_directory(), &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !neoenv_core::tools::is_sha256(name) || retained.contains(name) {
            continue;
        }
        let path = entry.path();
        if project_artifact_owned(&path, name) {
            super::remove_global_path(&path)?;
        }
    }
    Ok(())
}

pub(super) fn global_purge_candidates(
    data_root: &Path,
    document: &toml::Value,
    tools: &[String],
) -> Result<Vec<GlobalPurgeCandidate>, Diagnostic> {
    let configured = global_tools(document)?;
    let pins = global_pins(document);
    let retained_paths = global_retained_provider_paths(data_root, document)?;
    let keys = if tools.is_empty() {
        configured.keys().cloned().collect::<Vec<_>>()
    } else {
        tools
            .iter()
            .map(|value| {
                let (key, version) = global_tool_and_version(value)?;
                if version.is_some() {
                    return Err(usage("tool purge accepts tool names, not versions"));
                }
                Ok(key.to_owned())
            })
            .collect::<Result<Vec<_>, Diagnostic>>()?
    };
    let mut result = Vec::new();
    for key in keys {
        let selected = configured.get(&key).and_then(toml::Value::as_str);
        for (version, path, lock_path) in global_all_versions(data_root, &key)? {
            if retained_paths.contains(&path) {
                continue;
            }
            if selected.is_some_and(|selected| {
                compare_versions(selected, &version) == std::cmp::Ordering::Equal
            }) || pins
                .get(&key)
                .is_some_and(|versions| versions.contains(&version))
            {
                continue;
            }
            result.push((key.clone(), version, path, lock_path));
        }
    }
    Ok(result)
}

pub(super) fn purge_global(
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let (_, document) = global_snapshot(scope)?;
    let data_root = global_tool_data_root(scope)?;
    let candidates = global_purge_candidates(&data_root, &document, tools)?;
    let mut report = LifecycleReport::new(report_scope(scope), "purge", dry_run);
    for (key, version, path, _) in &candidates {
        report.change(
            key,
            "purge",
            None,
            Some(version.clone()),
            Some(path.clone()),
            Some("unreferenced nenv-owned version"),
        );
    }
    if dry_run {
        return print_report(&report, format);
    }
    for (key, version, path, lock_path) in candidates {
        let lock_can_be_removed = if let Some(lock_path) = &lock_path {
            global_lock_is_exhausted(lock_path, &key, Some(&version))?
        } else {
            true
        };
        if !lock_can_be_removed {
            continue;
        }
        if path.starts_with(data_root.join("tools")) {
            super::remove_global_path(&path)?;
        }
        if let Some(lock_path) = lock_path {
            super::remove_global_path(&lock_path)?;
        }
    }
    cleanup_global_artifacts(&data_root)?;
    print_report(&report, format)
}

#[allow(clippy::too_many_lines)]
pub(super) fn remove_global(
    tools: &[String],
    dry_run: bool,
    format: OutputFormat,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let (path, document) = global_snapshot(scope)?;
    let configured = global_tools(&document)?;
    let pins = global_pins(&document);
    let data_root = global_tool_data_root(scope)?;
    let mut report = LifecycleReport::new(report_scope(scope), "remove", dry_run);
    let mut one_version = Vec::new();
    let mut whole = Vec::new();
    for value in tools {
        let (key, version) = global_tool_and_version(value)?;
        if let Some(version) = version {
            let selected = configured.get(key).and_then(toml::Value::as_str);
            if selected.is_some_and(|selected| {
                compare_versions(selected, version) == std::cmp::Ordering::Equal
            }) {
                return Err(validation(format!(
                    "selected global tool version cannot be removed one version at a time: {key}@{version}"
                )));
            }
            if pins
                .get(key)
                .is_some_and(|versions| versions.contains(&version.to_owned()))
            {
                return Err(validation(format!(
                    "pinned global tool version cannot be removed: {key}@{version}"
                )));
            }
            let (owned, lock_path) =
                global_owned_version(&data_root, key, version)?.ok_or_else(|| {
                    not_found(format!("installed global tool not found: {key}@{version}"))
                })?;
            one_version.push((key.to_owned(), version.to_owned(), owned, lock_path));
        } else {
            if !configured.contains_key(key) {
                return Err(not_found(format!("global tool is not configured: {key}")));
            }
            whole.push(key.to_owned());
        }
    }
    for (key, version, path, _) in &one_version {
        report.change(
            key,
            "remove",
            Some(version.clone()),
            None,
            Some(path.clone()),
            Some("one version only"),
        );
    }
    for key in &whole {
        let path = global_all_versions(&data_root, key)?
            .first()
            .map(|(_, path, _)| path.clone());
        report.change(key, "remove", None, None, path, Some("whole tool"));
    }
    if dry_run {
        return print_report(&report, format);
    }
    // Publish the config removal first, then remove bytes.  This means a
    // cleanup error can leave recoverable unreferenced data but cannot leave
    // an active global selection pointing at a missing executable.
    let mut next = document.clone();
    if let Some(global) = next
        .as_table_mut()
        .and_then(|root| root.get_mut("global"))
        .and_then(toml::Value::as_table_mut)
    {
        if let Some(table) = global.get_mut("tools").and_then(toml::Value::as_table_mut) {
            for key in &whole {
                table.remove(key);
            }
        }
        if let Some(table) = global
            .get_mut("providers")
            .and_then(toml::Value::as_table_mut)
        {
            for key in &whole {
                table.remove(key);
            }
        }
        if let Some(table) = global.get_mut("pins").and_then(toml::Value::as_table_mut) {
            for key in &whole {
                table.remove(key);
            }
        }
    }
    if !whole.is_empty() {
        let state = state_file::lock(&path).map_err(|error| state_file_diagnostic(&path, error))?;
        let output = toml::to_string_pretty(&next).map_err(|error| {
            Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
        })?;
        write_locked_state(&state, &output)?;
    }
    let exclusions = one_version
        .iter()
        .map(|(key, version, _, _)| (key.clone(), Some(version.clone())))
        .chain(whole.iter().map(|key| (key.clone(), None)))
        .collect::<Vec<_>>();
    let protected = global_retained_provider_paths_except(&data_root, &next, &exclusions, true)?;
    for (key, version, path, lock_path) in one_version {
        let lock_can_be_removed = if let Some(lock_path) = &lock_path {
            global_lock_is_exhausted(lock_path, &key, Some(&version))?
        } else {
            true
        };
        if lock_can_be_removed && !protected.contains(&path) {
            super::remove_global_path(&path)?;
        }
        if lock_can_be_removed && let Some(lock_path) = lock_path {
            super::remove_global_path(&lock_path)?;
        }
    }
    let mut removed_paths = HashSet::new();
    let mut removed_locks = HashSet::new();
    for key in whole {
        for (version, path, lock_path) in global_all_versions(&data_root, &key)? {
            let lock_can_be_removed = if let Some(lock_path) = &lock_path {
                global_lock_is_exhausted(lock_path, &key, Some(&version))?
            } else {
                true
            };
            if lock_can_be_removed
                && !protected.contains(&path)
                && removed_paths.insert(path.clone())
            {
                super::remove_global_path(&path)?;
            }
            if lock_can_be_removed
                && let Some(lock_path) = lock_path
                && removed_locks.insert(lock_path.clone())
            {
                super::remove_global_path(&lock_path)?;
            }
        }
    }
    cleanup_global_artifacts(&data_root)?;
    print_report(&report, format)
}
