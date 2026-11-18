//! Reporting for installed native runtimes.
//!
//! **Read-only, and local-only.** Nothing here resolves a version, contacts a release
//! index, or writes to the data directory: every answer comes from a receipt that an
//! installer already wrote. That is a deliberate boundary, and it is the reason `update`
//! and `upgrade` are absent rather than merely unimplemented — see
//! [`crate::cli::RuntimeCommand`]. The path is `cli::RuntimeCommand` rather than
//! `cli::model::RuntimeCommand` because `cli::model` is a private module that `cli`
//! re-exports wholesale; naming the private module makes rustdoc fail the build.
//!
//! Enumeration is evidence-based: a version directory is reported only when its receipt is
//! present, so a version left by an interrupted extraction is invisible here *and*
//! invisible to the shell. A runtime that is half-installed and shown as installed is
//! worse than one that is not shown.

use std::path::Path;

use serde::Serialize;

use neoenv_installer::tools::{InstalledRuntime, installed_runtimes};

use super::{
    Diagnostic, DiagnosticCategory, GlobalScope, OutputFormat, RuntimeCommand,
    global_tool_data_directory, print_json,
};

/// The JSON document emitted by `--format json`.
///
/// Schema version 2. Version 1 had no `scope` field; a consumer that selects a
/// runtime from this document needs to know which scope supplied it.
#[derive(Debug, Serialize)]
struct RuntimeListDocument {
    schema_version: u32,
    runtimes: Vec<RuntimeDocument>,
}

#[derive(Debug, Serialize)]
struct RuntimeDocument {
    scope: &'static str,
    id: String,
    version: String,
    root: String,
    bin_dir: String,
    environment: Vec<RuntimeVariableDocument>,
}

struct ScopedRuntime {
    runtime: InstalledRuntime,
    scope: GlobalScope,
}

#[derive(Debug, Serialize)]
struct RuntimeVariableDocument {
    key: String,
    value: String,
}

/// Where the runtimes for a named runtime are, or a named error saying there are none.
///
/// **A name with no installed version is an error, not an empty answer.** `where` is
/// asked precisely because the caller wants a directory to put on `PATH` or read a
/// variable from, and printing nothing would leave the caller to guess whether the
/// runtime is absent, unreadable, or installed somewhere unexpected. The message names
/// the command that would install it.
pub(super) fn dispatch_runtime(
    command: &RuntimeCommand,
    format: OutputFormat,
) -> Result<(), Diagnostic> {
    let runtimes = enumerate()?;
    match command {
        RuntimeCommand::List => match format {
            OutputFormat::Text => {
                for runtime in &runtimes {
                    println!(
                        "{}\t{}\t{}\t{}",
                        scope_name(runtime.scope),
                        runtime.runtime.id,
                        runtime.runtime.version,
                        runtime.runtime.bin_dir.display()
                    );
                }
            }
            OutputFormat::Json => print_json(&RuntimeListDocument {
                schema_version: 2,
                runtimes: runtimes.iter().map(runtime_document).collect(),
            })?,
        },
        RuntimeCommand::Where { runtime: name } => {
            let found: Vec<&ScopedRuntime> = runtimes
                .iter()
                .filter(|it| it.runtime.id == *name)
                .collect();
            let Some(installed) = found.first() else {
                return Err(Diagnostic::new(
                    DiagnosticCategory::NotFound,
                    "NEO517",
                    format!(
                        "no runtime named {name:?} is installed; install one with \
                         `nenv tool global-use {name}`"
                    ),
                ));
            };
            // More than one version is not an error: the newest is the one the shell
            // uses, and saying so is more useful than refusing to answer. The runtime
            // count is included so a user who did not expect two sees why.
            // Activation applies system runtimes first and user runtimes last,
            // and `runtime_diff` is last-write-wins. The last matching entry is
            // therefore the one the shell uses.
            let newest = found.last().copied().unwrap_or(installed);
            match format {
                OutputFormat::Text => {
                    println!("scope\t{}", scope_name(newest.scope));
                    println!("bin_dir\t{}", newest.runtime.bin_dir.display());
                    for (key, value) in &newest.runtime.environment {
                        println!("{key}\t{value}");
                    }
                }
                OutputFormat::Json => print_json(&runtime_document(newest))?,
            }
        }
    }
    Ok(())
}

fn scope_name(scope: GlobalScope) -> &'static str {
    match scope {
        GlobalScope::User => "user",
        GlobalScope::System => "system",
    }
}

fn runtime_document(scoped: &ScopedRuntime) -> RuntimeDocument {
    let runtime = &scoped.runtime;
    RuntimeDocument {
        scope: scope_name(scoped.scope),
        id: runtime.id.clone(),
        version: runtime.version.clone(),
        root: runtime.root.display().to_string(),
        bin_dir: runtime.bin_dir.display().to_string(),
        environment: runtime
            .environment
            .iter()
            .map(|(key, value)| RuntimeVariableDocument {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    }
}

/// The installed runtimes, or an empty list when the data directory cannot be reached.
///
/// **An unreadable data directory reports nothing rather than failing.** Not having run
/// `nenv global install` is the normal state of a machine, and `runtime list` answering
/// "nothing installed" is the correct answer there. Propagating the I/O failure would
/// make an inspection command fail for the majority of machines.
fn enumerate() -> Result<Vec<ScopedRuntime>, Diagnostic> {
    // System first, then user, so a user's runtime wins the selection below.
    // A broken user layout is an error, not a reason to silently use the system
    // layout.
    let mut runtimes = Vec::new();
    for scope in [GlobalScope::System, GlobalScope::User] {
        let data_root = global_tool_data_directory(scope)?;
        runtimes.extend(
            installed_runtimes(Path::new(&data_root))
                .into_iter()
                .map(|runtime| ScopedRuntime { runtime, scope }),
        );
    }
    Ok(runtimes)
}
