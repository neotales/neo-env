//! Workspace reporting. Lists only the members and aliases a configuration
//! declares; nothing here scans the filesystem for undeclared projects.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    Diagnostic, DiagnosticCategory, OutputFormat, Path as StdPath, WorkspaceCommand, print_json,
};

/// The JSON document emitted by `--format json`, matching
/// `docs/neoenv/schemas/workspace-list-v1.schema.json`.
#[derive(Debug, Serialize)]
struct WorkspaceListDocument<'a> {
    schema_version: u32,
    members: Vec<WorkspaceMemberDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct WorkspaceMemberDocument<'a> {
    alias: &'a str,
    member: &'a str,
    path: String,
    relative_path: &'a str,
}

/// One row of the listing: a member together with the single alias that selects
/// it, or with no alias when the member declares none.
///
/// A member declared under two aliases produces two rows, because each alias is
/// a separately declared name a caller can select. Members are otherwise
/// emitted exactly once.
///
/// Ordering is fixed: aliases sort by name, then members with no alias sort by
/// declared path. Both come from ordered maps, so the listing is identical
/// between runs and between the text and JSON forms.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceMember {
    alias: String,
    member: String,
    path: PathBuf,
    relative: String,
}

pub(super) fn dispatch_workspace(
    command: &WorkspaceCommand,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let WorkspaceCommand::List { path } = command;
    let start = std::env::current_dir().map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Runtime, "NEO502", error.to_string())
    })?;
    let members = collect_members(&start, path.as_deref(), profile)?;
    match format {
        OutputFormat::Text => {
            for member in &members {
                println!(
                    "{}\t{}\t{}",
                    member.alias,
                    member.path.display(),
                    member.relative
                );
            }
        }
        // A member path is not guaranteed to be valid UTF-8, and `serde_json`
        // has no lossy conversion for a path. Rendering through
        // `to_string_lossy` keeps a non-UTF-8 path a reportable value instead of
        // a panic inside the JSON macro.
        OutputFormat::Json => print_json(&WorkspaceListDocument {
            schema_version: 1,
            members: members
                .iter()
                .map(|member| WorkspaceMemberDocument {
                    alias: &member.alias,
                    member: &member.member,
                    path: member.path.to_string_lossy().into_owned(),
                    relative_path: &member.relative,
                })
                .collect(),
        })?,
    }
    Ok(())
}

/// Resolves the declared members below the workspace that owns `start`.
///
/// An explicit `path` selects the workspace root directly, so
/// `nenv workspace list ../elsewhere` works from inside a member. Without one
/// the nearest declaring ancestor is used, honouring `NEOENV_PROJECT` exactly
/// as project selection does, so this command cannot report a different
/// project than `inspect` and `validate`.
fn collect_members(
    start: &StdPath,
    path: Option<&str>,
    profile: neoenv_config::ConfigProfile,
) -> Result<Vec<WorkspaceMember>, Diagnostic> {
    // An explicit argument wins, then `NEOENV_PROJECT`, then the nearest
    // declaring ancestor. Resolving the first two through `workspace_at` keeps
    // a named location pinned to that directory.
    let explicit = path
        .map(StdPath::new)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("NEOENV_PROJECT").map(PathBuf::from));
    let workspace = match explicit {
        Some(candidate) => workspace_at(&candidate, profile)?,
        None => match neoenv_runtime::discovery::discover_workspace(start, profile)? {
            Some(workspace) => workspace,
            None => return Ok(Vec::new()),
        },
    };
    let root = &workspace.project.project_root;
    // An alias names exactly one member. Tracking the members already claimed
    // keeps a member from also being repeated as a nameless row.
    let mut claimed: BTreeSet<&str> = BTreeSet::new();
    let mut members = Vec::with_capacity(workspace.members.len());
    for (alias, member) in &workspace.aliases {
        // `DiscoveredWorkspace` only records aliases whose target resolved to a
        // declared member, so a missing target here would break that invariant.
        let Some(project) = workspace.members.get(member) else {
            continue;
        };
        claimed.insert(member.as_str());
        members.push(WorkspaceMember {
            alias: alias.clone(),
            member: member.clone(),
            path: project.project_root.clone(),
            relative: relative_to(root, &project.project_root),
        });
    }
    for (member, project) in &workspace.members {
        if claimed.contains(member.as_str()) {
            continue;
        }
        members.push(WorkspaceMember {
            alias: String::new(),
            member: member.clone(),
            path: project.project_root.clone(),
            relative: relative_to(root, &project.project_root),
        });
    }
    Ok(members)
}

/// Loads the workspace declared at an explicit directory or configuration path.
///
/// `discover_workspace` walks ancestors, which is right for the implicit case
/// but surprising for a path the caller named: `nenv workspace list
/// ../unrelated` would otherwise report a workspace several levels above it.
/// An explicit selection is therefore pinned to the requested directory, which
/// also matches how `inspect <path>` and `validate <path>` treat an explicit
/// argument.
fn workspace_at(
    candidate: &Path,
    profile: neoenv_config::ConfigProfile,
) -> Result<neoenv_runtime::discovery::DiscoveredWorkspace, Diagnostic> {
    let directory = if candidate.is_file() {
        candidate.parent().unwrap_or(candidate)
    } else {
        candidate
    };
    // `DiscoveredProject` reports a canonical root, so the comparison below only
    // holds for a canonical candidate. A path that cannot be resolved is a
    // not-found selection when it is absent and a runtime failure otherwise, so
    // a permission error is not reported as "no workspace here".
    let directory = match std::fs::canonicalize(directory) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(not_a_workspace(candidate));
        }
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO502",
                format!("cannot resolve {}: {error}", candidate.display()),
            )
            .with_cause(error));
        }
    };
    let workspace = neoenv_runtime::discovery::discover_workspace(&directory, profile)?
        .ok_or_else(|| not_a_workspace(candidate))?;
    if workspace.project.project_root != directory {
        return Err(not_a_workspace(candidate));
    }
    Ok(workspace)
}

fn not_a_workspace(candidate: &Path) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::NotFound,
        "NEO401",
        format!("no nenv workspace found at {}", candidate.display()),
    )
}

fn relative_to(root: &Path, member: &Path) -> String {
    member
        .strip_prefix(root)
        .unwrap_or(member)
        .to_string_lossy()
        .into_owned()
}
