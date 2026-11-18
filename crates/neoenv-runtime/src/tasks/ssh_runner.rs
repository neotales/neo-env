//! Remote runner validation is shared by preflight and execution.
use super::{BTreeMap, Capability, Duration, TaskDefinition, TaskRunOptions, Template, Value};
use crate::{
    inventory::{check_connect, resolve_targets},
    ssh,
};

fn selection<'a>(
    task: &TaskDefinition,
    options: TaskRunOptions<'a>,
) -> Result<
    (
        &'a neoenv_config::Inventory,
        Vec<crate::inventory::ResolvedHost>,
    ),
    String,
> {
    let action = task.action.as_ref().ok_or("SSH action is missing")?;
    if !action.args.is_empty()
        || action.cwd.is_some()
        || action.source.is_some()
        || action.destination.is_some()
        || !task.outputs.is_empty()
    {
        return Err("SSH tasks do not support args, cwd, source, destination or outputs".into());
    }
    if action
        .with
        .keys()
        .any(|key| !matches!(key.as_str(), "inventory" | "targets" | "timeout"))
    {
        return Err("SSH with accepts only inventory, targets and timeout".into());
    }
    if action.run.as_ref().is_none_or(String::is_empty) {
        return Err("SSH task requires a nonempty run script".into());
    }
    let inventories = options
        .inventories
        .ok_or("SSH runner requires resolved inventories")?;
    let name = action
        .with
        .get("inventory")
        .ok_or("SSH with.inventory is required")?;
    let inventory = inventories
        .get(name)
        .ok_or("SSH inventory is not declared")?;
    let targets = action
        .with
        .get("targets")
        .ok_or("SSH with.targets is required")?
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if targets.iter().any(String::is_empty) {
        return Err("SSH targets cannot contain empty entries".into());
    }
    let hosts = resolve_targets(inventory, &targets).map_err(|_| "SSH target is not declared")?;
    Ok((inventory, hosts))
}

pub(super) fn uses_home_identity(
    task: &TaskDefinition,
    options: TaskRunOptions<'_>,
) -> Result<bool, String> {
    let (inventory, hosts) = selection(task, options)?;
    Ok(hosts.iter().any(|host| {
        let identity = inventory
            .hosts
            .get(&host.name)
            .and_then(|host| host.identity_file.as_ref())
            .or(inventory.defaults.identity_file.as_ref());
        identity.is_some_and(|path| path == "~" || path.starts_with("~/"))
    }))
}

pub(super) fn authorize(
    task: &TaskDefinition,
    options: TaskRunOptions<'_>,
    environment: &BTreeMap<String, String>,
    project_root: &std::path::Path,
) -> Result<(), String> {
    let (inventory, hosts) = selection(task, options)?;
    let name = &task.action.as_ref().expect("validated action").with["inventory"];
    let grants = options
        .capability_grants
        .ok_or("SSH requires explicit connect grants")?;
    for host in hosts {
        check_connect(
            grants,
            options.inventories.expect("validated inventories"),
            name,
            &host.name,
        )
        .map_err(|denied| denied.to_string())?;
        let subject =
            ssh::endpoint_subject_with_context(inventory, &host.name, environment, project_root)?;
        if !grants.authorizes(Capability::Connect, &subject) {
            return Err(format!("SSH endpoint requires connect grant for {subject}"));
        }
    }
    Ok(())
}

pub(super) fn execute(
    task: &TaskDefinition,
    environment: &BTreeMap<String, String>,
    options: &TaskRunOptions<'_>,
    project_root: &std::path::Path,
) -> Result<u32, String> {
    let (inventory, hosts) = selection(task, *options)?;
    authorize(task, *options, environment, project_root)?;
    let action = task.action.as_ref().expect("validated action");
    let timeout = action
        .with
        .get("timeout")
        .map(|value| {
            super::process::parse_timeout(value)
                .map_err(|_| "SSH timeout must be a positive duration")
        })
        .transpose()?
        .unwrap_or(Duration::from_secs(30));
    let endpoints = hosts
        .iter()
        .map(|host| {
            ssh::Endpoint::resolve_with_root(inventory, &host.name, environment, project_root)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut secrets = options.ssh_secret_values.to_vec();
    secrets.extend(
        environment
            .iter()
            .filter(|(key, _)| neoenv_policy::should_redact_environment(key))
            .map(|(_, value)| value.as_str()),
    );
    secrets.sort_unstable();
    secrets.dedup();
    let scripts = render_scripts(
        action.run.as_deref().expect("validated run"),
        &hosts,
        environment,
    )?;
    let consoles = endpoints
        .iter()
        .zip(&hosts)
        .map(|(endpoint, host)| {
            ssh::prepare_console(
                endpoint,
                ssh::ConsoleOptions {
                    alias: &host.name,
                    stderr_only: options.ssh_output_to_stderr,
                    secrets: &secrets,
                    cancellation: Some(options.cancellation.clone()),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (completed, (console, script)) in consoles.into_iter().zip(&scripts).enumerate() {
        if options.cancellation.is_cancelled() {
            return Err("task cancelled".into());
        }
        let start = std::time::Instant::now();
        let execution = console.execute(script, timeout);
        if options.cancellation.is_cancelled() {
            return Err("task cancelled".into());
        }
        if execution.is_err() && start.elapsed() >= timeout {
            return Err("task timed out".into());
        }
        let status = execution.map_err(|message| {
            format!("SSH failed after {completed} host(s) completed: {message}")
        })?;
        if status != 0 {
            return Err(format!(
                "SSH remote command returned status {status} after {completed} host(s) completed"
            ));
        }
    }
    Ok(0)
}

fn render_scripts(
    run: &str,
    hosts: &[crate::inventory::ResolvedHost],
    environment: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let template =
        Template::parse(run).map_err(|_| "SSH script template failed (details suppressed)")?;
    let scripts = hosts
        .iter()
        .map(|host| {
            let host_values = BTreeMap::from([
                ("name".into(), Value::String(host.name.clone())),
                ("address".into(), Value::String(host.address.clone())),
            ]);
            let values = BTreeMap::from([
                (
                    "env".into(),
                    Value::Map(
                        environment
                            .iter()
                            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                            .collect(),
                    ),
                ),
                ("host".into(), Value::Map(host_values)),
                (
                    "shell".into(),
                    Value::Map(BTreeMap::from([
                        (
                            "env".into(),
                            Value::Map(
                                environment
                                    .iter()
                                    .map(|(key, value)| {
                                        (key.clone(), Value::String(shell_word(value)))
                                    })
                                    .collect(),
                            ),
                        ),
                        (
                            "host".into(),
                            Value::Map(BTreeMap::from([
                                ("name".into(), Value::String(shell_word(&host.name))),
                                ("address".into(), Value::String(shell_word(&host.address))),
                            ])),
                        ),
                    ])),
                ),
            ]);
            template
                .render_typed(&values)
                .map_err(|_| "SSH script template failed (details suppressed)")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scripts
        .iter()
        .any(|script| script.is_empty() || script.len() > 1024 * 1024 || script.contains('\0'))
    {
        return Err("SSH rendered scripts must be nonempty and at most one MiB without NUL".into());
    }
    Ok(scripts)
}

// POSIX shell quoting, deliberately distinct from Sprig's JSON/Go `quote`.
// A complete shell word; callers must not wrap it in another pair of quotes.
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
