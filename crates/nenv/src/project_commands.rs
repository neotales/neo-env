//! Project-scoped commands: configuration initialization, repository trust,
//! and remote module cache control.

use super::task_dispatch::task_cancellation;
use super::{
    Diagnostic, DiagnosticCategory, OpenOptions, OutputFormat, Path, RemoteCommand, RemoteModule,
    TrustCommand, Write, clear_module_cache, fetch_module_with_cancellation, fs, print_json,
    trust_path, trust_project, trust_repository, trusted_repositories, untrust_repository,
};
use neoenv_runtime::trust::{self, Contributor, ProjectTrust, TrustIdentity};

/// `nenv init` writes the TOML form, so the name is one of the four project
/// filenames rather than a name of its own. Indexed rather than spelled: the
/// index is pinned by `names::tests::project_filenames_are_in_precedence_order`,
/// so reordering that list cannot silently change what `init` writes.
const TOML_CONFIGURATION_FILENAME: &str = neoenv_core::names::PROJECT_FILENAMES[2];

pub(super) fn initialize_project(format: OutputFormat) -> Result<(), Diagnostic> {
    const CONFIGURATION_FILENAMES: [&str; 4] = [
        neoenv_core::names::PROJECT_FILENAMES[0],
        neoenv_core::names::PROJECT_FILENAMES[1],
        neoenv_core::names::PROJECT_FILENAMES[2],
        neoenv_core::names::PROJECT_FILENAMES[3],
    ];

    let directory = std::env::current_dir().map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Runtime, "NEO503", error.to_string())
    })?;
    if let Some(existing) = CONFIGURATION_FILENAMES
        .iter()
        .map(|name| directory.join(name))
        .find(|path| path.exists())
    {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO104",
            format!("nenv configuration already exists: {}", existing.display()),
        ));
    }

    let path = directory.join(TOML_CONFIGURATION_FILENAME);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO503",
                format!("cannot create {}: {error}", path.display()),
            )
        })?;
    file.write_all(b"format_version = 1\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            let _ = fs::remove_file(&path);
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO503",
                format!("cannot write {}: {error}", path.display()),
            )
        })?;

    match format {
        OutputFormat::Text => println!("initialized: {}", path.display()),
        OutputFormat::Json => print_json(&serde_json::json!({ "path": path }))?,
    }
    Ok(())
}

pub(super) fn dispatch_trust(
    command: &TrustCommand,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    match command {
        TrustCommand::Status => {
            let repositories = trusted_repositories().map_err(|error| remote_diagnostic(&error))?;
            match format {
                OutputFormat::Text => {
                    println!(
                        "policy: {}",
                        trust_path()
                            .map_err(|error| remote_diagnostic(&error))?
                            .display()
                    );
                    println!(
                        "manifest: {}",
                        trust::project_trust_path()
                            .map_err(|error| trust_diagnostic(&error))?
                            .display()
                    );
                    for repository in repositories {
                        println!("repository: {repository}");
                    }
                }
                OutputFormat::Json => {
                    print_json(&serde_json::json!({
                        "repositories": repositories,
                        "policy": trust_path()
                            .map_err(|error| remote_diagnostic(&error))?,
                        "manifest": trust::project_trust_path()
                            .map_err(|error| trust_diagnostic(&error))?,
                    }))?;
                }
            }
        }
        TrustCommand::ProjectStatus { path } => {
            let project = crate::output::load_project_with_profile(Some(path), profile, None)?;
            print_trust_status(&project, format)?;
        }
        TrustCommand::AddRepository { repository } => {
            let repository =
                trust_repository(repository).map_err(|error| remote_diagnostic(&error))?;
            match format {
                OutputFormat::Text => println!("trusted-repository: {repository}"),
                OutputFormat::Json => {
                    print_json(&serde_json::json!({ "trusted_repository": repository }))?;
                }
            }
        }
        TrustCommand::RemoveRepository { repository } => {
            let repository =
                untrust_repository(repository).map_err(|error| remote_diagnostic(&error))?;
            match format {
                OutputFormat::Text => println!("untrusted-repository: {repository}"),
                OutputFormat::Json => {
                    print_json(&serde_json::json!({ "untrusted_repository": repository }))?;
                }
            }
        }
        TrustCommand::AddProject { path } => {
            let project =
                trust_project(Path::new(path)).map_err(|error| trust_diagnostic(&error))?;
            print_project_record(&project, true, format)?;
        }
        TrustCommand::RevokeProject { path } => {
            let identity =
                trust::revoke_local(Path::new(path)).map_err(|error| trust_diagnostic(&error))?;
            let project = ProjectTrust {
                path: identity.path,
                blake3: identity.digest.hex,
            };
            print_project_record(&project, false, format)?;
        }
        TrustCommand::AddRemote { spec } => {
            let root = project_root(None)?;
            let identity = trust::approve_cached_remote(&root, spec)
                .map_err(|error| trust_diagnostic(&error))?;
            print_remote_identity(&identity, true, format)?;
        }
        TrustCommand::RemoveRemote { spec } => {
            let root = project_root(None)?;
            let identity = trust::revoke_cached_remote(&root, spec)
                .map_err(|error| trust_diagnostic(&error))?;
            print_remote_identity(&identity, false, format)?;
        }
    }
    Ok(())
}

fn print_project_record(
    project: &ProjectTrust,
    trusted: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => println!(
            "{}\t{}\tblake3:{}",
            if trusted { "trusted" } else { "untrusted" },
            project.path,
            project.blake3
        ),
        OutputFormat::Json => print_json(&serde_json::json!({
            "path": project.path,
            "blake3": project.blake3,
            "trusted": trusted,
        }))?,
    }
    Ok(())
}

fn print_remote_identity(
    identity: &neoenv_runtime::trust::RemoteTrustIdentity,
    trusted: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Text => println!(
            "{}\t{}@{}//{}\t{}",
            if trusted { "trusted" } else { "untrusted" },
            identity.repository,
            identity.commit,
            identity.path,
            identity.digest
        ),
        OutputFormat::Json => print_json(&serde_json::json!({
            "repository": identity.repository,
            "commit": identity.commit,
            "path": identity.path,
            "digest": identity.digest,
            "trusted": trusted,
        }))?,
    }
    Ok(())
}

fn print_trust_status(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let store = trust::read_trust_store().map_err(|error| trust_diagnostic(&error))?;
    let repositories = trusted_repositories().map_err(|error| remote_diagnostic(&error))?;
    let (root, root_trusted) = trust::local_status(&project.project.configuration_path)
        .map_err(|error| trust_diagnostic(&error))?;
    let contributors = project
        .contributors
        .iter()
        .map(|contributor| {
            (
                contributor,
                trust::contributor_is_trusted(&store, contributor),
            )
        })
        .collect::<Vec<_>>();
    let missing = project
        .contributors
        .iter()
        .filter(|contributor| !trust::contributor_is_trusted(&store, contributor))
        .map(describe_contributor_path)
        .collect::<Vec<_>>();
    match format {
        OutputFormat::Text => {
            println!(
                "manifest: {}",
                trust::project_trust_path()
                    .map_err(|error| trust_diagnostic(&error))?
                    .display()
            );
            println!(
                "policy: {}",
                trust_path()
                    .map_err(|error| remote_diagnostic(&error))?
                    .display()
            );
            for repository in repositories {
                println!("repository: {repository}");
            }
            println!(
                "root: {}\t{}\tblake3:{}",
                if root_trusted { "trusted" } else { "untrusted" },
                root.path,
                root.digest
            );
            for (contributor, trusted) in contributors {
                println!(
                    "contributor: {}\t{}",
                    if trusted { "trusted" } else { "untrusted" },
                    describe_contributor(&contributor.identity)
                );
            }
            for path in &missing {
                println!("approve: nenv trust add {path}");
            }
        }
        OutputFormat::Json => {
            let contributors = project
                .contributors
                .iter()
                .map(|contributor| {
                    serde_json::json!({
                        "trusted": trust::contributor_is_trusted(&store, contributor),
                        "identity": contributor.identity,
                    })
                })
                .collect::<Vec<_>>();
            print_json(&serde_json::json!({
                "manifest": trust::project_trust_path()
                    .map_err(|error| trust_diagnostic(&error))?,
                "policy": trust_path().map_err(|error| remote_diagnostic(&error))?,
                "repositories": repositories,
                "root": {
                    "path": root.path,
                    "digest": root.digest,
                    "trusted": root_trusted,
                },
                "contributors": contributors,
                "missing": missing,
            }))?;
        }
    }
    Ok(())
}

fn describe_contributor(identity: &TrustIdentity) -> String {
    identity.to_string()
}

fn describe_contributor_path(contributor: &Contributor) -> String {
    match &contributor.identity {
        TrustIdentity::Local(identity) => identity.path.clone(),
        TrustIdentity::Remote(identity) => format!(
            "{}@{}//{}",
            identity.repository, identity.commit, identity.path
        ),
    }
}

fn trust_diagnostic(error: &trust::TrustError) -> Diagnostic {
    error.to_diagnostic()
}

pub(super) fn dispatch_remote(
    command: &RemoteCommand,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let (source, action) = match command {
        RemoteCommand::Inspect { source } => (source, None),
        RemoteCommand::Fetch { source, path } | RemoteCommand::Install { source, path } => {
            (source, Some((path.as_deref(), false)))
        }
        RemoteCommand::Update { source, path } => (source, Some((path.as_deref(), true))),
        RemoteCommand::Clear { source, path } => {
            let module = RemoteModule::parse(source).map_err(|error| remote_diagnostic(&error))?;
            let cleared = clear_module_cache(&project_root(path.as_deref())?, &module)
                .map_err(|error| remote_diagnostic(&error))?;
            return match format {
                OutputFormat::Text => {
                    println!(
                        "{}: {}",
                        if cleared { "cleared" } else { "missing" },
                        module.canonical()
                    );
                    Ok(())
                }
                OutputFormat::Json => print_json(
                    &serde_json::json!({ "source": module.canonical(), "cleared": cleared }),
                ),
            };
        }
    };
    let module = RemoteModule::parse(source).map_err(|error| remote_diagnostic(&error))?;
    if let Some((path, update)) = action {
        let root = project_root(path)?;
        let cancellation = task_cancellation()?;
        let cached = fetch_module_with_cancellation(&root, &module, update, Some(&cancellation))
            .map_err(|error| remote_diagnostic(&error))?;
        match format {
            OutputFormat::Text => println!("cached: {}", cached.display()),
            OutputFormat::Json => print_json(
                &serde_json::json!({ "source": module.canonical(), "path": cached, "updated": update }),
            )?,
        }
    } else {
        match format {
            OutputFormat::Text => println!(
                "source: {}\ncache_key: {}",
                module.canonical(),
                module.cache_key()
            ),
            OutputFormat::Json => print_json(
                &serde_json::json!({ "source": module.canonical(), "repository": module.repository, "cache_key": module.cache_key() }),
            )?,
        }
    }
    Ok(())
}

pub(super) fn project_root(path: Option<&str>) -> Result<std::path::PathBuf, Diagnostic> {
    let start = std::env::current_dir().map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Runtime, "NEO502", error.to_string())
    })?;
    neoenv_runtime::discovery::discover_from_environment(&start, path.map(Path::new))?
        .map(|project| project.project_root)
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO401",
                "no nenv configuration found",
            )
        })
}

pub(super) fn remote_diagnostic(error: &neoenv_runtime::remote::RemoteError) -> Diagnostic {
    let category = match error {
        neoenv_runtime::remote::RemoteError::Untrusted(_) => DiagnosticCategory::Trust,
        neoenv_runtime::remote::RemoteError::TrustNotFound(_) => DiagnosticCategory::NotFound,
        neoenv_runtime::remote::RemoteError::Cancelled => DiagnosticCategory::Runtime,
        _ => DiagnosticCategory::Validation,
    };
    Diagnostic::new(category, "NEO616", error.to_string()).with_cause(error.clone())
}
