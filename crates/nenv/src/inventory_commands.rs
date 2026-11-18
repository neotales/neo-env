//! Non-interactive SSH scripts and single-file SCP through explicit inventories.
//! Every alias and endpoint snapshot is authorized before the first network
//! effect. Plans retain the existing alias-only, non-networking contract.
//! See docs/ssh-and-inventory.md for the deliberately narrow first slice.

use neoenv_runtime::inventory::{ConnectDenied, ResolvedHost, check_connect, resolve_targets};
use neoenv_runtime::resolved_config::ResolvedProject;

use crate::{
    Diagnostic, DiagnosticCategory, OutputFormat, cli::InventoryCommand, output::print_json,
};

/// One `ssh` or `scp` invocation's shape, so the two commands cannot disagree.
pub(super) struct RemoteRequest<'a> {
    /// The inventory to resolve against. The project has exactly one by convention
    /// today; the name is a parameter so a second one is a data change rather than a
    /// signature change.
    pub inventory: &'a str,
    /// Host names or `@tag`s, in the order the user wrote them.
    pub targets: &'a [String],
    pub plan_only: bool,
    /// `scp` only. `None` for `ssh`.
    pub copy: Option<Copy>,
    pub script: Option<&'a str>,
}

/// The `scp` half, absent for `ssh`.
pub(super) struct Copy {
    pub source: String,
    pub destination: String,
    /// `true` when the direction is pull (remote to local), which the reference
    /// reports so a plan says which way the bytes go.
    pub pull: bool,
}

impl Copy {
    /// The word the plan and the refusal use for the direction.
    ///
    /// `push` and `pull`, as the reference's `scp` names them at `cli.go:2347`.
    fn direction(&self) -> &'static str {
        if self.pull { "pull" } else { "push" }
    }
}

pub(super) fn dispatch_inventory(
    command: &InventoryCommand,
    format: OutputFormat,
    context: Option<&str>,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let request = match command {
        InventoryCommand::Group { path } | InventoryCommand::List { path } => {
            return list(path.as_deref(), format, context, profile);
        }
        InventoryCommand::Ssh { .. } | InventoryCommand::Scp { .. } => match command {
            InventoryCommand::Ssh {
                inventory,
                targets,
                plan_only,
                script,
                ..
            } => RemoteRequest {
                inventory,
                targets,
                plan_only: *plan_only,
                copy: None,
                script: script.as_deref(),
            },
            InventoryCommand::Scp {
                inventory,
                targets,
                source,
                destination,
                pull,
                plan_only,
                ..
            } => RemoteRequest {
                inventory,
                targets,
                plan_only: *plan_only,
                copy: Some(Copy {
                    source: source.clone(),
                    destination: destination.clone(),
                    pull: *pull,
                }),
                script: None,
            },
            _ => unreachable!("the match above covered every variant"),
        },
    };
    let project = crate::output::load_project_with_profile(None, profile, context)?;
    run(&project, &request, format)
}

/// `nenv inventory` — the declared host lists, and the fact that they authorise
/// nothing.
pub(super) fn list(
    path: Option<&str>,
    format: OutputFormat,
    context: Option<&str>,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let project = crate::output::load_project_with_profile(path, profile, context)?;
    let inventories = project.inventories()?;
    let grants = load_grants()?;
    let environment = endpoint_environment(&project);
    let root = &project.project.project_root;
    match format {
        OutputFormat::Json => print_json(&serde_json::json!(inventories
            .iter()
            .map(|(name, inventory)| serde_json::json!({
                "name": name,
                "hosts": inventory
                    .names()
                    .into_iter()
                    .map(|host| serde_json::json!({
                        "name": host,
                        "address": inventory.address_of(host),
                        "tags": inventory.hosts.get(host).map(|entry| entry.tags.clone()),
                        // **Whether a grant authorises this host**, per host, because
                        // "here is my inventory" and "here is what you may reach" are
                        // different questions and a listing that answers only the first
                        // invites the reader to assume the second.
                        "granted": grants
                            .authorizes(neoenv_policy::Capability::Connect, &neoenv_runtime::inventory::host_subject(name, host)),
                        "endpoint_subject": endpoint_subject(inventory, host, &environment, root).ok(),
                        "endpoint_granted": endpoint_subject(inventory, host, &environment, root)
                            .is_ok_and(|subject| grants.authorizes(neoenv_policy::Capability::Connect, &subject)),
                    }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>())),
        OutputFormat::Text => {
            if inventories.is_empty() {
                // In words. A bare newline is indistinguishable from a crash.
                println!("this project declares no inventories");
                return Ok(());
            }
            for (name, inventory) in &inventories {
                println!("{name}\t{} host(s)", inventory.hosts.len());
                for host in inventory.names() {
                    let address = inventory.address_of(host);
                    let granted = grants.authorizes(
                        neoenv_policy::Capability::Connect,
                        &neoenv_runtime::inventory::host_subject(name, host),
                    );
                    // The address only when it differs, so the common case is one
                    // column wide and the output stays readable.
                    let where_ = if address == host {
                        String::new()
                    } else {
                        format!(" -> {address}")
                    };
                    println!(
                        "  {host}{where_}\t{}",
                        if granted { "granted" } else { "not granted" }
                    );
                    let subject = endpoint_subject(inventory, host, &environment, root)?;
                    println!("    {subject}\t{}", if grants.authorizes(
                        neoenv_policy::Capability::Connect, &subject,
                    ) { "endpoint granted" } else { "endpoint not granted" });
                }
            }
            Ok(())
        }
    }
}

fn endpoint_environment(project: &ResolvedProject) -> std::collections::BTreeMap<String, String> {
    let mut environment = std::env::vars().collect::<std::collections::BTreeMap<_, _>>();
    environment.extend(
        project
            .environment
            .iter()
            .map(|(key, entry)| (key.clone(), entry.value.clone())),
    );
    environment
}

fn endpoint_subject(
    inventory: &neoenv_config::Inventory,
    host: &str,
    environment: &std::collections::BTreeMap<String, String>,
    root: &std::path::Path,
) -> Result<String, Diagnostic> {
    neoenv_runtime::ssh::endpoint_subject_with_context(inventory, host, environment, root)
        .map_err(|message| Diagnostic::new(DiagnosticCategory::Runtime, "NEO443", message))
}

fn load_grants() -> Result<neoenv_policy::CapabilityGrants, Diagnostic> {
    let path = neoenv_runtime::policy::capability_policy_path().map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Trust,
            "NEO442",
            format!("could not locate the capability policy: {error}"),
        )
    })?;
    neoenv_runtime::policy::load_capability_grants(&path).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Trust,
            "NEO442",
            format!("{}: {error}", path.display()),
        )
    })
}

fn run(
    project: &ResolvedProject,
    request: &RemoteRequest<'_>,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let inventories = project.inventories()?;
    let inventory = inventories.get(request.inventory).ok_or_else(|| {
        let available: Vec<&str> = inventories.keys().map(String::as_str).collect();
        Diagnostic::new(
            DiagnosticCategory::NotFound,
            "NEO441",
            format!(
                "this project declares no inventory {:?}. Available: {}",
                request.inventory,
                if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                }
            ),
        )
    })?;

    let hosts = resolve_targets(inventory, request.targets).map_err(|error| error.diagnostic())?;

    // **Every host, before anything is printed.** A plan is the thing a user reads to
    // decide what is about to happen, so a host that is not authorized must not appear
    // in it even as a row that will later be refused.
    let grants = load_grants()?;
    let environment = endpoint_environment(project);
    for host in &hosts {
        check_connect(&grants, &inventories, request.inventory, &host.name)
            .map_err(|denied: ConnectDenied| denied.diagnostic())?;
        if !request.plan_only {
            let subject = endpoint_subject(
                inventory,
                &host.name,
                &environment,
                &project.project.project_root,
            )?;
            if !grants.authorizes(neoenv_policy::Capability::Connect, &subject) {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Trust,
                    "NEO440",
                    format!("SSH endpoint requires connect grant for {subject}"),
                ));
            }
        }
    }

    if request.plan_only {
        return print_plan(&hosts, request, format);
    }
    execute(
        project,
        inventory,
        &hosts,
        request,
        format == OutputFormat::Json,
        &environment,
    )?;
    match format {
        OutputFormat::Json => print_json(&serde_json::json!({
            "status": "succeeded", "completed_hosts": hosts.len(),
        })),
        OutputFormat::Text => {
            println!("{} host(s) completed", hosts.len());
            Ok(())
        }
    }
}

fn print_plan(
    hosts: &[ResolvedHost],
    request: &RemoteRequest<'_>,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Json => print_json(&serde_json::json!(
            hosts
                .iter()
                .map(|host| {
                    let mut item = serde_json::Map::new();
                    item.insert("name".into(), host.name.clone().into());
                    item.insert("target".into(), host.address.clone().into());
                    item.insert("tags".into(), host.tags.clone().into());
                    if let Some(copy) = &request.copy {
                        item.insert("direction".into(), copy.direction().into());
                        item.insert("source".into(), copy.source.clone().into());
                        item.insert("destination".into(), copy.destination.clone().into());
                    }
                    serde_json::Value::Object(item)
                })
                .collect::<Vec<_>>()
        )),
        OutputFormat::Text => {
            // `ssh\t<name>\t<target>`, as the reference prints it at
            // `cli.go:2290`. Two columns because the third is the thing you would
            // type to reach it.
            for host in hosts {
                match &request.copy {
                    Some(copy) => println!(
                        "scp\t{}\t{}\t{} -> {}",
                        host.name, host.address, copy.source, copy.destination
                    ),
                    None => println!("ssh\t{}\t{}", host.name, host.address),
                }
            }
            Ok(())
        }
    }
}

/// Executes an authorized selection with bounded, redacted console groups.
/// All endpoints and copy paths are preflighted before dialing.
fn execute(
    project: &ResolvedProject,
    inventory: &neoenv_config::Inventory,
    hosts: &[ResolvedHost],
    request: &RemoteRequest<'_>,
    stderr_only: bool,
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<(), Diagnostic> {
    use neoenv_runtime::ssh;
    use std::{
        io::{Read as _, Write as _},
        time::Duration,
    };
    let failed = |message: String| Diagnostic::new(DiagnosticCategory::Runtime, "NEO443", message);
    // Resolve every endpoint and path before the first side effect.
    let root = &project.project.project_root;
    let endpoints = hosts
        .iter()
        .map(|host| ssh::Endpoint::resolve_with_root(inventory, &host.name, environment, root))
        .collect::<Result<Vec<_>, _>>()
        .map_err(failed)?;
    let timeout = Duration::from_secs(30);
    if let Some(copy) = &request.copy {
        if copy.pull && endpoints.len() != 1 {
            return Err(failed("SCP pull requires exactly one host".into()));
        }
        let (local, remote) = if copy.pull {
            (&copy.destination, &copy.source)
        } else {
            (&copy.source, &copy.destination)
        };
        ssh::validate_remote_path(remote).map_err(failed)?;
        let local =
            ssh::local_file(&project.project.project_root, local, copy.pull).map_err(failed)?;
        if copy.pull {
            let bytes = ssh::download(&endpoints[0], remote, timeout).map_err(failed)?;
            let mut file =
                tempfile::NamedTempFile::new_in(local.parent().expect("local file has parent"))
                    .map_err(|_| failed("SCP could not create local temporary file".into()))?;
            file.write_all(&bytes)
                .map_err(|_| failed("SCP could not write local file".into()))?;
            file.persist(local)
                .map_err(|_| failed("SCP could not publish local file".into()))?;
        } else {
            let file = std::fs::File::open(local)
                .map_err(|_| failed("SCP could not read local file".into()))?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| failed("SCP could not read local file".into()))?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(failed("SCP file exceeds eight MiB".into()));
            }
            for (completed, endpoint) in endpoints.iter().enumerate() {
                ssh::upload(endpoint, remote, &bytes, timeout).map_err(|message| {
                    failed(format!(
                        "SCP failed after {completed} host(s) completed: {message}"
                    ))
                })?;
            }
        }
    } else {
        let script = request.script.ok_or_else(|| {
            failed(
                "SSH needs a remote script after --; interactive shells are not implemented".into(),
            )
        })?;
        let secrets = console_secrets(project, environment);
        let cancellation = crate::task_dispatch::task_cancellation()?;
        let consoles = endpoints
            .iter()
            .zip(hosts)
            .map(|(endpoint, host)| {
                ssh::prepare_console(
                    endpoint,
                    ssh::ConsoleOptions {
                        alias: &host.name,
                        stderr_only,
                        secrets: &secrets,
                        cancellation: Some(cancellation.clone()),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(failed)?;
        for (completed, console) in consoles.into_iter().enumerate() {
            let status = console.execute(script, timeout).map_err(|message| {
                failed(format!(
                    "SSH failed after {completed} host(s) completed: {message}"
                ))
            })?;
            if status != 0 {
                return Err(failed(format!(
                    "SSH remote command returned status {status} after {completed} host(s) completed"
                )));
            }
        }
    }
    Ok(())
}

fn console_secrets<'a>(
    project: &'a ResolvedProject,
    environment: &'a std::collections::BTreeMap<String, String>,
) -> Vec<&'a str> {
    let mut secrets = environment
        .iter()
        .filter(|(key, _)| neoenv_policy::should_redact_environment(key))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    secrets.extend(
        project
            .environment
            .values()
            .filter(|entry| entry.secret)
            .map(|entry| entry.value.as_str()),
    );
    secrets.sort_unstable();
    secrets.dedup();
    secrets
}
