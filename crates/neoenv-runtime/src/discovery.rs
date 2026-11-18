//! Filesystem-backed project discovery and source selection.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

use neoenv_config::{
    ConfigProfile, Format, Workspace, parse_project_with_profile,
    sources::{ConfigMergePlan, merge_plan},
};
use neoenv_core::{Diagnostic, DiagnosticCategory};

use crate::budget::{ResourceBudget, read_text_file};

const CONFIGURATION_FILENAMES: [&str; 4] = [
    neoenv_core::names::PROJECT_FILENAMES[0],
    neoenv_core::names::PROJECT_FILENAMES[1],
    neoenv_core::names::PROJECT_FILENAMES[2],
    neoenv_core::names::PROJECT_FILENAMES[3],
];

/// Why project discovery selected a configuration file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionReason {
    ExplicitPath,
    EnvironmentOverride,
    AncestorDiscovery,
}

/// The selected project configuration and its canonical project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredProject {
    pub configuration_path: PathBuf,
    pub project_root: PathBuf,
    pub reason: SelectionReason,
}

/// A workspace configuration with explicitly declared, local project members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredWorkspace {
    pub project: DiscoveredProject,
    pub members: std::collections::BTreeMap<String, DiscoveredProject>,
    pub aliases: std::collections::BTreeMap<String, String>,
}

/// Discovers a project configuration using the supplied precedence inputs.
///
/// # Errors
///
/// Returns not-found diagnostics for missing explicit inputs and runtime
/// diagnostics for filesystem failures.
pub fn discover(
    start: &Path,
    explicit_path: Option<&Path>,
    environment_override: Option<&Path>,
) -> Result<Option<DiscoveredProject>, Diagnostic> {
    if let Some(path) = explicit_path {
        return select_explicit(
            path,
            SelectionReason::ExplicitPath,
            "NEO201",
            "explicit project configuration does not exist",
        );
    }
    if let Some(path) = environment_override {
        return select_explicit(
            path,
            SelectionReason::EnvironmentOverride,
            "NEO202",
            "NEOENV_PROJECT does not exist",
        );
    }

    let mut directory = start_directory(start)?;
    loop {
        for name in CONFIGURATION_FILENAMES {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return select_explicit(
                    &candidate,
                    SelectionReason::AncestorDiscovery,
                    "NEO203",
                    "configuration does not exist",
                );
            }
        }
        if !directory.pop() {
            return Ok(None);
        }
    }
}

/// Discovers a project using `NEOENV_PROJECT` when no explicit path is supplied.
///
/// # Errors
///
/// Returns the same discovery diagnostics as [`discover`].
pub fn discover_from_environment(
    start: &Path,
    explicit_path: Option<&Path>,
) -> Result<Option<DiscoveredProject>, Diagnostic> {
    let environment_override = env::var_os("NEOENV_PROJECT").map(PathBuf::from);
    discover(start, explicit_path, environment_override.as_deref())
}

/// Finds the nearest ancestor project that declares an explicit workspace.
///
/// Member paths are canonicalized and must remain below the workspace root.
/// This function reads only local configuration files and never loads imports.
///
/// # Errors
///
/// Returns discovery, configuration, or workspace-containment diagnostics.
///
pub fn discover_workspace(
    start: &Path,
    profile: ConfigProfile,
) -> Result<Option<DiscoveredWorkspace>, Diagnostic> {
    let mut directory = start_directory(start)?;
    loop {
        for name in CONFIGURATION_FILENAMES {
            let candidate = directory.join(name);
            if !candidate.is_file() {
                continue;
            }
            let project = select_explicit(
                &candidate,
                SelectionReason::AncestorDiscovery,
                "NEO203",
                "configuration does not exist",
            )?
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::NotFound,
                    "NEO203",
                    format!(
                        "configuration disappeared during discovery: {}",
                        candidate.display()
                    ),
                )
            })?;
            let input = read_text_file(&project.configuration_path, &ResourceBudget::default())
                .map_err(|error| {
                    Diagnostic::new(
                        DiagnosticCategory::Runtime,
                        "NEO209",
                        format!(
                            "failed to read workspace configuration {}: {error}",
                            project.configuration_path.display()
                        ),
                    )
                    .with_cause(error)
                })?;
            let parsed = parse_project_with_profile(
                &project.configuration_path,
                &input,
                Format::from_path(&project.configuration_path)?,
                profile,
            )?;
            if !parsed.workspace.members.is_empty() || !parsed.workspace.aliases.is_empty() {
                return build_workspace(project, parsed.workspace).map(Some);
            }
        }
        if !directory.pop() {
            return Ok(None);
        }
    }
}

/// Resolves an explicit workspace alias to one declared member.
///
/// # Errors
///
/// Returns discovery or workspace-validation diagnostics.
pub fn resolve_workspace_alias(
    start: &Path,
    alias: &str,
) -> Result<Option<DiscoveredProject>, Diagnostic> {
    resolve_workspace_alias_with_profile(start, alias, ConfigProfile::process_profile())
}

/// The profile-aware form of [`resolve_workspace_alias`].
///
/// The alias is read out of the workspace document, so the document has to be
/// parsed in the same profile the caller is using. Reading it natively would
/// reject a Go workspace before the alias was ever consulted.
///
/// # Errors
///
/// Returns discovery or workspace-validation diagnostics.
pub fn resolve_workspace_alias_with_profile(
    start: &Path,
    alias: &str,
    profile: ConfigProfile,
) -> Result<Option<DiscoveredProject>, Diagnostic> {
    let Some(workspace) = discover_workspace(start, profile)? else {
        return Ok(None);
    };
    Ok(workspace
        .aliases
        .get(alias)
        .and_then(|member| workspace.members.get(member))
        .cloned())
}

fn build_workspace(
    project: DiscoveredProject,
    workspace: Workspace,
) -> Result<DiscoveredWorkspace, Diagnostic> {
    if workspace.members.is_empty() {
        return Err(workspace_error(
            "NEO210",
            "workspace aliases require declared members",
        ));
    }
    let mut members = std::collections::BTreeMap::new();
    for member in workspace.members {
        if member.is_empty() || Path::new(&member).is_absolute() {
            return Err(workspace_error(
                "NEO211",
                "workspace member must be a relative path",
            ));
        }
        let configuration_path = workspace_member_path(&project.project_root, &member)?;
        let member_project = select_explicit(
            &configuration_path,
            SelectionReason::ExplicitPath,
            "NEO212",
            "workspace member configuration does not exist",
        )?
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO212",
                format!(
                    "workspace member configuration disappeared during discovery: {}",
                    configuration_path.display()
                ),
            )
        })?;
        if !member_project
            .project_root
            .starts_with(&project.project_root)
        {
            return Err(workspace_error(
                "NEO213",
                "workspace member escapes the workspace root",
            ));
        }
        if members.insert(member, member_project).is_some() {
            return Err(workspace_error("NEO214", "duplicate workspace member"));
        }
    }
    let mut aliases = std::collections::BTreeMap::new();
    for alias in workspace.aliases.keys() {
        let mut components = Path::new(alias).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(workspace_error(
                "NEO215",
                "workspace alias must be a bare name",
            ));
        }
        let member = resolve_alias(alias, &workspace.aliases, &members, &mut Vec::new())?;
        aliases.insert(alias.clone(), member);
    }
    Ok(DiscoveredWorkspace {
        project,
        members,
        aliases,
    })
}

fn workspace_member_path(root: &Path, member: &str) -> Result<PathBuf, Diagnostic> {
    let candidate = root.join(member);
    if candidate.is_file() {
        return Ok(candidate);
    }
    CONFIGURATION_FILENAMES
        .iter()
        .map(|name| candidate.join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| workspace_error("NEO212", "workspace member configuration does not exist"))
}

fn resolve_alias(
    alias: &str,
    aliases: &indexmap::IndexMap<String, String>,
    members: &std::collections::BTreeMap<String, DiscoveredProject>,
    resolving: &mut Vec<String>,
) -> Result<String, Diagnostic> {
    if let Some(position) = resolving.iter().position(|item| item == alias) {
        let mut trace = resolving[position..].to_vec();
        trace.push(alias.to_owned());
        return Err(workspace_error(
            "NEO216",
            format!("workspace alias cycle: {}", trace.join(" -> ")),
        ));
    }
    let target = aliases
        .get(alias)
        .ok_or_else(|| workspace_error("NEO217", "workspace alias target is not declared"))?;
    if members.contains_key(target) {
        return Ok(target.clone());
    }
    resolving.push(alias.to_owned());
    let result = resolve_alias(target, aliases, members, resolving);
    resolving.pop();
    result
}

fn workspace_error(code: &str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, code, message)
}

/// Selects existing user and private configuration files into a merge plan.
///
/// Missing user configuration is normal. A requested private overlay must
/// exist and be a canonical descendant of the discovered project root.
///
/// # Errors
///
/// Returns a diagnostic for inaccessible sources, an absent requested private
/// overlay, or an invalid overlay location.
/// The machine-owned file `nenv config set` writes, if it exists.
///
/// **Absent is normal and is not an error.** A project nobody has corrected has no
/// overrides file, and a resolver that complained about the missing one would make the
/// common case loud and the rare case silent -- exactly backwards.
#[must_use]
pub fn user_overrides_path() -> Option<PathBuf> {
    let candidate = user_overrides_file()?;
    candidate.is_file().then_some(candidate)
}

/// Where `nenv config set` writes, whether or not it is there yet.
///
/// **A fixed path, decided whether or not the file exists**, because the writer and the
/// reader have to agree and a reader that only computes a path when a file is present
/// cannot tell a missing file from a missing directory.
#[must_use]
pub fn user_overrides_file() -> Option<PathBuf> {
    Some(user_config_dir()?.join("overrides.yaml"))
}

/// The directory the machine-owned user configuration lives in.
///
/// `NEOENV_CONFIG_HOME` wins, then `XDG_CONFIG_HOME`, then `$HOME/.config`. **The last
/// is skipped when `$HOME` is unset** rather than defaulting to `.`: a relative
/// `nenv/overrides.yaml` would be read from whatever directory the process happens to be
/// in, which is a different answer per invocation and reads as corruption.
#[must_use]
pub fn user_config_dir() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("NEOENV_CONFIG_HOME") {
        return Some(PathBuf::from(explicit));
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        // **The name, not a literal.** `names::source_is_the_module` exists to stop a
        // path segment being spelled out in a second place, and it caught this literal
        // the first time it was compiled -- which is the check doing exactly its job.
        return Some(PathBuf::from(xdg).join(neoenv_core::names::USER_DIRECTORY));
    }
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join(neoenv_core::names::USER_DIRECTORY)
    })
}

/// Builds the low-to-high precedence plan for a discovered project.
///
/// # Errors
///
/// Returns a validation diagnostic when the private overlay is not a descendant of the
/// project root, or when a configuration file cannot be canonicalised. The user-overrides
/// file being **absent** is not an error case -- a project nobody has corrected has none,
/// and that is the common case rather than the exceptional one.
pub fn select_sources(
    project: &DiscoveredProject,
    user_config: Option<&Path>,
    private_overlay: Option<&Path>,
) -> Result<ConfigMergePlan, Diagnostic> {
    let user_config = user_config
        .filter(|path| path.is_file())
        .map(canonicalize)
        .transpose()?;
    let private_overlay = private_overlay
        .map(|path| {
            canonicalize(path).map_err(|error| {
                if error.category == DiagnosticCategory::NotFound {
                    Diagnostic::new(
                        DiagnosticCategory::Validation,
                        "NEO204",
                        format!("private overlay does not exist: {}", path.display()),
                    )
                } else {
                    error
                }
            })
        })
        .transpose()?;
    merge_plan(
        user_config,
        project.configuration_path.clone(),
        &project.project_root,
        private_overlay,
        user_overrides_path(),
    )
}

fn select_explicit(
    path: &Path,
    reason: SelectionReason,
    missing_code: &str,
    missing_message: &str,
) -> Result<Option<DiscoveredProject>, Diagnostic> {
    let configuration_path = match canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.category == DiagnosticCategory::NotFound => {
            return Err(Diagnostic::new(
                DiagnosticCategory::NotFound,
                missing_code,
                format!("{missing_message}: {}", path.display()),
            ));
        }
        Err(error) => return Err(error),
    };
    if !configuration_path.is_file() {
        return Err(Diagnostic::new(
            DiagnosticCategory::NotFound,
            missing_code,
            format!("{missing_message}: {}", path.display()),
        ));
    }
    Format::from_path(&configuration_path)?;
    let project_root = configuration_path
        .parent()
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO205",
                "configuration path has no parent directory",
            )
        })?
        .to_owned();
    Ok(Some(DiscoveredProject {
        configuration_path,
        project_root,
        reason,
    }))
}

fn start_directory(start: &Path) -> Result<PathBuf, Diagnostic> {
    let canonical = canonicalize(start)?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        canonical.parent().map(Path::to_owned).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO206",
                "start path has no parent directory",
            )
        })
    }
}

fn canonicalize(path: &Path) -> Result<PathBuf, Diagnostic> {
    fs::canonicalize(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Diagnostic::new(
            DiagnosticCategory::NotFound,
            "NEO207",
            format!("path does not exist: {}", path.display()),
        )
        .with_cause(error),
        _ => Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO208",
            format!("failed to resolve path {}: {error}", path.display()),
        )
        .with_cause(error),
    })
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, path::Path};

    use neoenv_config::sources::ConfigSourceKind;
    use neoenv_core::ExitCategory;
    use tempfile::TempDir;

    use super::{
        SelectionReason, canonicalize, discover, discover_workspace, resolve_workspace_alias,
        select_sources,
    };

    fn write_configuration(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, "format_version: 1\nenv: {}\n").unwrap();
        path
    }

    use std::path::PathBuf;

    #[test]
    fn selects_nearest_ancestor_after_explicit_inputs() {
        let temp = TempDir::new().unwrap();
        let child = temp.path().join("child");
        let nested = child.join("nested");
        fs::create_dir_all(&nested).unwrap();
        write_configuration(temp.path(), "neoenv.toml");
        write_configuration(&child, "neoenv.yaml");

        let project = discover(&nested, None, None).unwrap().unwrap();

        assert_eq!(project.project_root, fs::canonicalize(child).unwrap());
        assert_eq!(project.reason, SelectionReason::AncestorDiscovery);
    }

    #[test]
    fn explicit_path_wins_over_override_and_ancestor() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let explicit = write_configuration(temp.path(), "explicit.toml");
        let override_path = write_configuration(temp.path(), "override.yaml");
        write_configuration(temp.path(), "neoenv.yaml");

        let project = discover(&nested, Some(&explicit), Some(&override_path))
            .unwrap()
            .unwrap();

        assert_eq!(
            project.configuration_path,
            fs::canonicalize(explicit).unwrap()
        );
        assert_eq!(project.reason, SelectionReason::ExplicitPath);
    }

    #[test]
    fn missing_explicit_path_does_not_fall_back() {
        let temp = TempDir::new().unwrap();
        write_configuration(temp.path(), "neoenv.yaml");

        let error = discover(
            &temp.path().join("missing.toml"),
            Some(&temp.path().join("missing.toml")),
            None,
        )
        .unwrap_err();

        assert_eq!(error.exit_category(), ExitCategory::NotFound);
        assert_eq!(error.code, "NEO201");
    }

    #[test]
    fn missing_path_diagnostic_retains_the_io_source() {
        let temp = TempDir::new().unwrap();
        let error = canonicalize(&temp.path().join("missing")).unwrap_err();

        assert_eq!(error.code, "NEO207");
        assert_eq!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn selects_existing_sources_in_precedence_order() {
        let temp = TempDir::new().unwrap();
        let project_root = temp.path().join("project");
        let private_directory = project_root.join("neoenv/private");
        let user_directory = temp.path().join("user");
        fs::create_dir(&project_root).unwrap();
        fs::create_dir_all(&private_directory).unwrap();
        fs::create_dir(&user_directory).unwrap();
        let project_config = write_configuration(&project_root, "neoenv.yaml");
        let user_config = write_configuration(&user_directory, "neoenv.toml");
        let private_overlay = write_configuration(&private_directory, "local.yaml");
        let project = discover(&project_config, None, None).unwrap().unwrap();

        let plan = select_sources(&project, Some(&user_config), Some(&private_overlay)).unwrap();

        assert_eq!(
            plan.sources()
                .iter()
                .map(neoenv_config::sources::ConfigSource::kind)
                .collect::<Vec<_>>(),
            vec![
                ConfigSourceKind::User,
                ConfigSourceKind::Project,
                ConfigSourceKind::PrivateOverlay
            ]
        );
        assert_eq!(
            plan.sources()[2].path(),
            fs::canonicalize(private_overlay).unwrap()
        );
    }

    #[test]
    fn discovers_nearest_workspace_and_resolves_only_explicit_aliases() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let nested = root.join("apps/app/nested");
        fs::create_dir_all(&nested).unwrap();
        write_configuration(&root.join("apps/app"), "neoenv.yaml");
        fs::write(
            root.join("neoenv.yaml"),
            "workspace:\n  members: [apps/app]\n  aliases:\n    app: apps/app\n    frontend: app\n",
        )
        .unwrap();
        let outer = temp.path().join("outer");
        fs::create_dir(&outer).unwrap();
        fs::write(
            outer.join("neoenv.yaml"),
            "workspace:\n  members: [root/apps/app]\n  aliases: { app: root/apps/app }\n",
        )
        .unwrap();

        let workspace = discover_workspace(&nested, neoenv_config::ConfigProfile::Native)
            .unwrap()
            .unwrap();

        assert_eq!(
            workspace.project.project_root,
            fs::canonicalize(&root).unwrap()
        );
        assert_eq!(workspace.aliases["frontend"], "apps/app");
        assert_eq!(
            resolve_workspace_alias(&nested, "app")
                .unwrap()
                .unwrap()
                .project_root,
            fs::canonicalize(root.join("apps/app")).unwrap()
        );
        assert!(
            resolve_workspace_alias(&nested, "missing")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_workspace_alias_cycles_and_members_outside_the_root() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let member = root.join("app");
        fs::create_dir_all(&member).unwrap();
        write_configuration(&member, "neoenv.yaml");
        fs::write(
            root.join("neoenv.yaml"),
            "workspace:\n  members: [app]\n  aliases: { one: two, two: one }\n",
        )
        .unwrap();
        let error = discover_workspace(&root, neoenv_config::ConfigProfile::Native).unwrap_err();
        assert_eq!(error.code, "NEO216");

        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        write_configuration(&outside, "neoenv.yaml");
        fs::write(
            root.join("neoenv.yaml"),
            "workspace:\n  members: [../outside]\n",
        )
        .unwrap();
        let error = discover_workspace(&root, neoenv_config::ConfigProfile::Native).unwrap_err();
        assert_eq!(error.code, "NEO213");
    }
}
