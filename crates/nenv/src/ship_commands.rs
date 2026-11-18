//! `nenv ship` — the project's deployment workflows, to the limit the reference is at.
//!
//! ## What the reference does, verified
//!
//! `runShipCommand` lists deployments, and for the lifecycle verbs it resolves the
//! deployment, refuses if there is no such one, prints a plan on `--plan`, and then:
//!
//! ```text
//! ship %s for deployment %q (%s)%s is not implemented yet
//! ```
//!
//! on stderr, returning 1 (`~/work/neoenv-ref/cli/cli.go:817`). An unrecognised verb
//! gets `ship %s is not implemented yet` (`cli.go:821`).
//!
//! **So `ship list` and `ship --plan` are real and shipped here, and the verbs refuse
//! by name.** That is the whole of what the reference offers, and the refusal is the
//! deliverable rather than a stub: a command that resolved a deployment and then did
//! nothing about it would be #31 in a new place.
//!
//! ## The verbs are a fixed set, because the reference's are
//!
//! `deploy, up, rollback, destroy, down` — `isShipLifecycle` at `cli.go:2713`. An
//! unrecognised verb is refused with the reference's own words rather than being
//! treated as a deployment name, because `ship prod` is a plausible typo for
//! `ship deploy prod` and answering it as "no such deployment" sends the reader
//! looking in the document instead of at their own command line.
//!
//! ## Only four of the reference's fourteen keys are read, and the rest are refused
//!
//! The reference's `neofile.ShipDeployment` has fourteen fields. Its `ship` path
//! reads `Name`, `Type`, `Desc` and `Contexts`, and refuses at `cli.go:817` before
//! touching the rest. So `env`, `dotenv`, `before`, `after`, `compose`, `cwd` and
//! `timeout` are **refused here by name** rather than accepted and ignored. Ten keys
//! that parse and do nothing would be building a worse version of the defect this
//! repository has shipped eleven of.

use neoenv_core::tasks::DeploymentDefinition;

use crate::{Diagnostic, DiagnosticCategory, OutputFormat, cli::ShipCommand, output::print_json};

/// The lifecycle verbs, as `isShipLifecycle` at `cli.go:2713`.
///
/// A named function rather than a `match` at each use site, so the set is one list
/// and `ship`'s help, its parser and its refusal all agree about what a verb is.
const LIFECYCLE_VERBS: &[&str] = &["deploy", "up", "rollback", "destroy", "down"];

/// Whether `verb` is a lifecycle verb.
///
/// **`deploy` and `up` are the same verb**, as in the reference — it accepts either
/// and reports whichever the user typed. Keeping them distinct here would make
/// `ship up` refuse with "unknown verb" for a spelling the reference accepts.
fn is_lifecycle(verb: &str) -> bool {
    LIFECYCLE_VERBS.contains(&verb)
}

/// The deployment a verb with no name acts on.
///
/// `ShipMap.Resolve` substitutes this for an empty name
/// (`neofile/ship_map.go:119-121`), and a constant here is the same rule in one place
/// rather than a literal at each use site.
const DEFAULT_DEPLOYMENT: &str = "default";

pub(super) fn dispatch_ship(
    command: &ShipCommand,
    path: Option<&str>,
    format: OutputFormat,
    context_override: Option<&str>,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    let project = crate::output::load_project_with_profile(path, profile, context_override)?;
    let context =
        neoenv_core::tasks::select_context(context_override, None, project.context.as_deref());
    match command {
        ShipCommand::Group { .. } | ShipCommand::List { .. } => list(&project.deployments, format),
        ShipCommand::Lifecycle {
            verb,
            deployment,
            plan_only,
            ..
        } => lifecycle(
            &project.deployments,
            verb,
            deployment.as_deref(),
            &context,
            *plan_only,
            format,
        ),
        // A verb the reference does not know, refused with its words.
        ShipCommand::Other { verb, .. } => Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO450",
            format!("ship {verb} is not implemented yet"),
        )),
    }
}

fn label<'a>(key: &'a str, deployment: &'a DeploymentDefinition) -> &'a str {
    deployment.label(key)
}

fn list(
    deployments: &indexmap::IndexMap<String, DeploymentDefinition>,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Json => print_json(&serde_json::json!(
            deployments
                .iter()
                .map(|(key, deployment)| serde_json::json!({
                    "name": key,
                    "type": deployment.reported_type(),
                    "desc": deployment.description,
                }))
                .collect::<Vec<_>>()
        )),
        OutputFormat::Text => {
            if deployments.is_empty() {
                // In words. A bare newline is indistinguishable from a crash.
                println!("this project declares no deployments");
                return Ok(());
            }
            for (key, deployment) in deployments {
                // **`key<TAB>desc`, with the type standing in for a missing
                // description** — the reference's own shape at `cli.go:755-765`,
                // which builds `desc = deployment.Desc` and falls back to
                // `deployment.Type`. Matching it matters because a `desc` that falls
                // back to the type is a two-column line either way, and a three-column
                // one would break every script that cuts column 2 as the description.
                let described = deployment
                    .description
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| deployment.reported_type());
                println!("{key}\t{described}");
            }
            Ok(())
        }
    }
}

fn lifecycle(
    deployments: &indexmap::IndexMap<String, DeploymentDefinition>,
    verb: &str,
    name: Option<&str>,
    context: &str,
    plan_only: bool,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    // An unrecognised verb is refused as a verb, before any deployment is looked up.
    // `ship prod` is a plausible typo for `ship deploy prod`, and answering it as "no
    // such deployment" sends the reader into the document instead of at their own
    // command line.
    if !is_lifecycle(verb) {
        return Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO450",
            format!("ship {verb} is not implemented yet"),
        ));
    }

    let (key, deployment) = resolve(deployments, name, context)?;

    if plan_only {
        let plan = serde_json::json!({
            "action": verb,
            "deployment": label(key, deployment),
            "type": deployment.reported_type(),
            "context": context,
        });
        return match format {
            OutputFormat::Json => print_json(&plan),
            // `would-ship\t<action>\t<deployment>\t<type>\t<context>`, as the
            // reference prints it at `cli.go:811`. Tab-separated so a plan is
            // greppable and a shell can cut a column out of it.
            OutputFormat::Text => {
                println!(
                    "would-ship\t{verb}\t{}\t{}\t{context}",
                    label(key, deployment),
                    deployment.reported_type()
                );
                Ok(())
            }
        };
    }

    // The refusal. Names the verb, the deployment, its type, and the context -- the
    // four facts a user needs to decide whether the *plan* is right even though the
    // execution is not available.
    let context_note = if context.is_empty() {
        String::new()
    } else {
        format!(" for context {context:?}")
    };
    eprintln!(
        "ship {verb} for deployment {:?} ({}){context_note} is not implemented yet",
        label(key, deployment),
        deployment.reported_type()
    );
    // `plan_only` cannot be true here: the plan path returned above. A single
    // message, and it names the flag that *does* work.
    Err(Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO451",
        "deployment is not implemented; --plan shows what would happen",
    ))
}

/// Finds the deployment `ship` would act on.
///
/// **A key convention, not a filter**, exactly as `ShipMap.Resolve`
/// (`~/work/neoenv-ref/neofile/ship_map.go:118-127`):
///
/// ```text
/// Resolve("", "")         -> "default"
/// Resolve("web", "prod")  -> "web:prod" if that key exists, else "web"
/// Resolve("web", "")      -> "web"
/// ```
///
/// So a project writes `web` and `web:prod` as two entries and `--context prod` picks
/// the second. There is **no ambiguity case**, because it is a key lookup rather than a
/// search over candidates — which is why there is no "N deployments apply" refusal
/// here. A first version used a `contexts:` filter and needed one, and the filter was
/// the wrong rule: `ShipDeployment.Contexts` is read in the reference only by shell
/// completion, never by `Resolve`.
///
/// A name is matched exactly first and then case-insensitively, in both the bare and
/// the `{name}:{context}` forms: a deployment key is a label a human wrote, and
/// `Web:Prod` for `web:prod` is a typo rather than a different deployment. The
/// *reference's* spelling is what comes back, because the key is the identity and
/// `--plan` reports it.
fn resolve<'a>(
    deployments: &'a indexmap::IndexMap<String, DeploymentDefinition>,
    name: Option<&str>,
    context: &str,
) -> Result<(&'a String, &'a DeploymentDefinition), Diagnostic> {
    if deployments.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCategory::NotFound,
            "NEO452",
            "no ship deployments found in the selected configuration",
        ));
    }

    // The reference's first line: an empty name is `default`. Done here too, so
    // `ship deploy` with no argument and `ship deploy default` are the same request
    // and a document that names its deployment `default` needs no special casing.
    let wanted = name
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_DEPLOYMENT);

    // The context-qualified key first, then the bare one. The order is the
    // reference's and it is the useful one: the qualified key is the more specific
    // declaration, so it wins when both exist.
    let mut candidates: Vec<String> = Vec::new();
    if !context.is_empty() {
        candidates.push(format!("{wanted}:{context}"));
    }
    candidates.push(wanted.to_owned());

    for candidate in &candidates {
        if let Some(found) = lookup(deployments, candidate) {
            return Ok(found);
        }
    }

    // Not found. **Every candidate is named**, because "not found" with one hint is
    // a worse answer than "not found" with the two keys that were tried: a reader who
    // wrote `web` and a `web:prod` needs to know which one was looked for.
    let context_note = if context.is_empty() {
        String::new()
    } else {
        format!(" for context {context:?}")
    };
    let available: Vec<&str> = deployments.keys().map(String::as_str).collect();
    Err(Diagnostic::new(
        DiagnosticCategory::NotFound,
        "NEO452",
        format!(
            "ship deployment {:?} not found{context_note}. Tried: {}. Available: {}",
            wanted,
            candidates.join(", "),
            if available.is_empty() {
                "none".to_owned()
            } else {
                available.join(", ")
            }
        ),
    ))
}

/// The deployment with this exact key, or the case-insensitive match.
///
/// Exact first, then case-insensitive, so a document that declares both `web` and
/// `Web` resolves each to itself rather than both to whichever sorted first.
fn lookup<'a>(
    deployments: &'a indexmap::IndexMap<String, DeploymentDefinition>,
    key: &str,
) -> Option<(&'a String, &'a DeploymentDefinition)> {
    deployments.get_key_value(key).or_else(|| {
        deployments
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
    })
}
