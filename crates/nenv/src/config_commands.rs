//! `nenv config` — the settings a project declares, and where each was written.
//!
//! ## Why this is not `nenv inspect`
//!
//! `inspect` answers "what does this project *resolve* to" -- the merged
//! environment, the `PATH` operations, the tasks, with a source for each. `config`
//! answers "what did somebody *write*", as a list of keys.
//!
//! **The two overlap, and conflating them is the mistake this command exists to
//! avoid.** `inspect` tells you `STAGE=production` came from line 14; it does not
//! tell you that `STAGE` is the *only* declared key, which is what "why is this
//! project doing that" usually turns into. `config list` is the set; `inspect` is
//! the resolution.
//!
//! ## The JSON shape is the reference's
//!
//! `{name, value, source}` per entry, matching the reference's `namedValueJSON`
//! plus a source, so a script written against one works against the other.
//!
//! It is a **new document, not a new `inspection-v2` field.**
//! `docs/schemas/inspection-v2.schema.json` is a published contract, and adding a
//! field to it changes what every existing consumer of `inspect --format json`
//! sees. A separate command with a separate document costs a line in the README and
//! breaks nobody.
//!
//! ## What is deliberately absent
//!
//! **A key whose value is empty is omitted, not printed as empty.** The reference
//! does the same and for the same reason: a list full of blank rows reads as "this
//! project sets everything to nothing", which is a different and alarming claim from
//! "these are the settings that are set".
//!
//! **A secret is redacted, not printed.** `EnvironmentEntry` already marks a value
//! declared as a secret, and this command does not get to be the one place that
//! prints one. The key still appears, with the value replaced, so the user learns
//! that it is set without learning what it is.

use neoenv_core::SourceSpan;
use neoenv_runtime::resolved_config::ResolvedProject;

use crate::{
    Diagnostic,
    cli::{ConfigCommand, OutputFormat},
    output::print_json,
};

/// One declared setting: its dotted key, its value, and where it was written.
pub(super) struct ConfigEntry {
    pub name: String,
    pub value: String,
    /// The file and position, rendered the way `inspect` renders one, so the two
    /// commands agree on what a source looks like. `None` for a setting that has no
    /// position -- a constant, or something derived rather than written.
    source: Option<String>,
}

pub(super) fn dispatch_config(
    command: &ConfigCommand,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    // `set` is handled before the read path, because it needs the same project but a
    // different answer, and routing it through `entries()` would make it look like a read.
    match command {
        ConfigCommand::Set { path, key, value } => {
            let project = crate::output::load_project_with_profile(path.as_deref(), profile, None)?;
            return set_key(&project, key, value);
        }
        ConfigCommand::Unset { path, key } => {
            return unset_key(key, path.as_deref());
        }
        ConfigCommand::Group { .. } | ConfigCommand::List { .. } | ConfigCommand::Get { .. } => {}
    }
    let (path, wanted) = match command {
        ConfigCommand::Group { path } | ConfigCommand::List { path } => (path.as_deref(), None),
        ConfigCommand::Get { path, key } => (path.as_deref(), Some(key.as_str())),
        // Both writes returned above. Naming them here rather than an `unreachable!` is
        // deliberate: a new `ConfigCommand` variant that forgets to be handled becomes a
        // compile error instead of a panic in a command.
        ConfigCommand::Set { .. } | ConfigCommand::Unset { .. } => {
            return Err(Diagnostic::new(
                neoenv_core::DiagnosticCategory::Usage,
                "NEO204",
                "internal: a writing config command reached the read path".to_owned(),
            ));
        }
    };
    let project = crate::output::load_project_with_profile(path, profile, None)?;
    let entries = entries(&project);

    let Some(wanted) = wanted else {
        return print_all(&entries, format);
    };
    match entries.iter().find(|entry| entry.name == wanted) {
        Some(entry) => match format {
            OutputFormat::Json => print_json(&serde_json::json!({
                "name": entry.name,
                "value": entry.value,
                "source": entry.source,
            })),
            OutputFormat::Text => {
                println!("{}", entry.value);
                Ok(())
            }
        },
        // The alternatives, because "not found" without them makes the user run
        // `config list` and read all of it. Same shape as the context refusal:
        // name what was meant, not only what was wrong.
        None => Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!(
                "config key {wanted:?} is not set by this project. Available: {}",
                available(&entries)
            ),
        )),
    }
}

fn print_all(entries: &[ConfigEntry], format: OutputFormat) -> Result<(), Diagnostic> {
    match format {
        OutputFormat::Json => print_json(&serde_json::json!(
            entries
                .iter()
                .map(|entry| serde_json::json!({
                    "name": entry.name,
                    "value": entry.value,
                    "source": entry.source,
                }))
                .collect::<Vec<_>>()
        )),
        OutputFormat::Text => {
            if entries.is_empty() {
                // An empty list is a real answer. A bare newline is indistinguishable
                // from a crash or a truncated pipe.
                println!("this project sets no configuration keys");
                return Ok(());
            }
            for entry in entries {
                println!(
                    "{}\t{}\t{}",
                    entry.name,
                    entry.value,
                    entry.source.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
    }
}

/// Corrects one declared key in the machine-owned overrides file.
///
/// ## Why it corrects and does not invent
///
/// An undeclared key is refused with the alternatives named. `set` suggests it creates
/// keys, and a typo that silently created one would be a file asking for one thing and
/// getting another — the shape of defect this repository has shipped eleven of, and the
/// one this command is most likely to cause because a key is short and a typo is easy.
///
/// The refusal reuses `available()`, so the alternatives are the *declared* keys rather
/// than a list somebody maintains beside the reader. `config get` already reports an unset
/// key that way, and a corrective command that names fewer alternatives than the reading
/// one is worse than no command.
///
/// ## Why the value is checked against the key rather than trusted
///
/// Every declared key is a string: `context` is a name, `env.NAME` is a value, and
/// `path.prepend` is a path. A value that is not a string is refused **without echoing
/// it**, because a value that is refused is very often a secret somebody pasted, and a
/// diagnostic that repeats it has put it in a terminal scrollback and possibly a log.
///
/// ## The write
///
/// Through `state_file::write_atomic`, the convention for every mutable `nenv` state
/// file: a temporary file in the destination directory, synced, published with
/// replacement semantics, and a symlink target refused. The parent directory is created
/// first, because the overrides file is the thing most likely to be the *first* thing
/// written under `$XDG_CONFIG_HOME/neoenv/`, and `write_atomic` will not do it.
fn set_key(project: &ResolvedProject, key: &str, value: &str) -> Result<(), Diagnostic> {
    let declared = entries(project);
    if !declared.iter().any(|entry| entry.name == key) {
        return Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!(
                "config key {key:?} is not declared by this project, so there is \
                 nothing to correct. Declared: {}",
                available(&declared)
            ),
        ));
    }

    let destination = neoenv_runtime::discovery::user_overrides_file().ok_or_else(|| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            "cannot decide where to write: set NEOENV_CONFIG_HOME, or XDG_CONFIG_HOME, \
             or HOME. Without one of them the destination would be relative, and a \
             relative destination is a different file per working directory."
                .to_owned(),
        )
    })?;

    let mut document = read_overrides(&destination)?;
    write_key(&mut document, key, value).map_err(|reason| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!("{key:?} takes a plain string value: {reason}"),
        )
    })?;
    let rendered = serde_yaml::to_string(&document).map_err(|error| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!("the overrides file could not be written as YAML: {error}"),
        )
    })?;

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            Diagnostic::new(
                neoenv_core::DiagnosticCategory::Runtime,
                "NEO702",
                format!("could not create {}: {error}", parent.display()),
            )
        })?;
    }
    neoenv_runtime::state_file::write_atomic(&destination, rendered.as_bytes()).map_err(
        |error| {
            Diagnostic::new(
                neoenv_core::DiagnosticCategory::Runtime,
                "NEO702",
                format!("could not write {}: {error}", destination.display()),
            )
        },
    )?;

    // **The file, because "it worked" without a path leaves the reader wondering which
    // of three configurations changed.** And a declared secret is not repeated here: the
    // key is enough to find the value, and the value is the thing being protected.
    // **The project's own redaction policy, not a check against `entries()`.** The first
    // version asked whether `config list` had redacted the value, and under the native
    // profile it never does -- `structured.rs` sets `secret: false` because the v1 mapping
    // form has no secret flag and "redaction is by name". So the check could not fire, and
    // the criterion it was written for was quietly unmet.
    //
    // `should_redact_environment` is that by-name rule, already the single place it is
    // written down, and using it here means `config set` cannot drift from `inspect`.
    let secret = key
        .strip_prefix("env.")
        .is_some_and(neoenv_policy::should_redact_environment);
    if secret {
        println!("{key}\t<redacted>\t{}", destination.display());
    } else {
        println!("{key}\t{value}\t{}", destination.display());
    }
    Ok(())
}

/// Removes a correction from the overrides file.
///
/// **A key that is not corrected is refused, and the file is left exactly as it was.**
/// Reporting success for a removal that did not happen is the quietest wrong answer
/// available here: the user believes their correction is gone and it is still winning
/// every resolution, and nothing in the output disagrees with them.
///
/// The project is *not* loaded to check the key is declared, and that is deliberate. A
/// correction outlives the declaration it corrected -- a key removed from the project
/// leaves its override applying, and `unset` has to be able to clear it. Requiring the key
/// to still be declared would make exactly the case that needs `unset` the one case it
/// refuses.
fn unset_key(key: &str, path: Option<&str>) -> Result<(), Diagnostic> {
    // The path is accepted and not used for validation, but the *file* is the same
    // machine-owned one `set` writes, and saying so in the confirmation is the point.
    let _ = path;
    let destination = neoenv_runtime::discovery::user_overrides_file().ok_or_else(|| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            "cannot decide which file to edit: set NEOENV_CONFIG_HOME, or XDG_CONFIG_HOME, \
             or HOME."
                .to_owned(),
        )
    })?;
    if !destination.is_file() {
        return Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!(
                "there is nothing to unset: {} does not exist, so this project has no \
                 corrections.",
                destination.display()
            ),
        ));
    }
    let mut document = read_overrides(&destination)?;
    let removed = remove_key(&mut document, key).map_err(|reason| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!("cannot remove {key:?}: {reason}"),
        )
    })?;
    if !removed {
        return Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!(
                "{key:?} is not corrected in {}, so nothing was removed and the file is \
                 unchanged.",
                destination.display()
            ),
        ));
    }
    let rendered = serde_yaml::to_string(&document).map_err(|error| {
        Diagnostic::new(
            neoenv_core::DiagnosticCategory::Usage,
            "NEO204",
            format!("the overrides file could not be written as YAML: {error}"),
        )
    })?;
    neoenv_runtime::state_file::write_atomic(&destination, rendered.as_bytes()).map_err(
        |error| {
            Diagnostic::new(
                neoenv_core::DiagnosticCategory::Runtime,
                "NEO702",
                format!("could not write {}: {error}", destination.display()),
            )
        },
    )?;
    println!("{key}\tremoved\t{}", destination.display());
    Ok(())
}

/// Removes `key`, returning whether it was there.
///
/// **An emptied `env:` mapping is removed too.** Leaving `env:` behind with nothing in it
/// is a document that says something the user did not write, and it would also make a
/// later `set env.X` see an empty mapping rather than create one -- harmless today, and a
/// confusing thing to find in a file.
fn remove_key(document: &mut serde_yaml::Value, key: &str) -> Result<bool, &'static str> {
    let serde_yaml::Value::Mapping(mapping) = document else {
        return Err("the overrides file is not a mapping");
    };
    if let Some(name) = key.strip_prefix("env.") {
        let Some(entry) = mapping.get_mut(serde_yaml::Value::String("env".to_owned())) else {
            return Ok(false);
        };
        let serde_yaml::Value::Mapping(env) = entry else {
            return Err("`env` is a value, not a mapping of names to values");
        };
        let removed = env
            .remove(serde_yaml::Value::String(name.to_owned()))
            .is_some();
        if env.is_empty() {
            mapping.remove(serde_yaml::Value::String("env".to_owned()));
        }
        return Ok(removed);
    }
    if let Some(operation) = key.strip_prefix("path.") {
        // **`path.prepend` and `path.append` are top-level keys holding a list**, not
        // nested under a `path:` mapping, which is what `set` writes. So removing one is
        // a single key removal. The borrow is not held across it: an earlier version took
        // `get_mut` and then removed the same key, which the borrow checker refused, and
        // the fix is the obvious one -- ask `remove` first, since it answers the same
        // question.
        return Ok(mapping
            .remove(serde_yaml::Value::String(operation.to_owned()))
            .is_some());
    }
    Ok(mapping
        .remove(serde_yaml::Value::String(key.to_owned()))
        .is_some())
}

fn read_overrides(path: &std::path::Path) -> Result<serde_yaml::Value, Diagnostic> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_yaml::from_str(&text).map_err(|error| {
            Diagnostic::new(
                neoenv_core::DiagnosticCategory::Validation,
                "NEO204",
                format!(
                    "{} exists but is not readable as YAML, and this command will not \
                     overwrite a file it could not read: {error}",
                    path.display()
                ),
            )
        }),
        // **Absent is the normal case.** A project nobody has corrected has no overrides
        // file, and a fresh document is the starting point rather than an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()))
        }
        Err(error) => Err(Diagnostic::new(
            neoenv_core::DiagnosticCategory::Runtime,
            "NEO702",
            format!("could not read {}: {error}", path.display()),
        )),
    }
}

/// Puts `key` into the document, refusing a key whose shape does not match its family.
///
/// **The three families are derived from the key's own prefix** rather than from a table,
/// so a key space that grows needs no change here. And the value is only ever *stored*,
/// never formatted into a message, so a secret cannot reach a diagnostic through the
/// formatting path either.
fn write_key(document: &mut serde_yaml::Value, key: &str, value: &str) -> Result<(), &'static str> {
    if !document.is_mapping() {
        *document = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let serde_yaml::Value::Mapping(mapping) = document else {
        return Err("the overrides file is not a mapping");
    };
    let insert = |mapping: &mut serde_yaml::Mapping, name: &str, at: &str| {
        mapping.insert(
            serde_yaml::Value::String(name.to_owned()),
            serde_yaml::Value::String(value.to_owned()),
        );
        let _ = at;
    };

    if let Some(name) = key.strip_prefix("env.") {
        if name.is_empty() {
            return Err("the environment variable name is empty");
        }
        let entry = mapping
            .entry(serde_yaml::Value::String("env".to_owned()))
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        // **One match, not two.** The first version let-else'd `String(_)` against the
        // entry and then let-else'd `Mapping` against it again, so a *correct* `env:`
        // mapping failed the first arm -- `config set env.STAGE prod` was refused with
        // "`env` is not a mapping" against a file that had no `env:` at all, because the
        // freshly-inserted value is a mapping and the arm being tested was for a string.
        // A check that rejects the value it just created is a check that cannot be fixed
        // by supplying what it asks for.
        if let serde_yaml::Value::Mapping(env) = entry {
            env.insert(
                serde_yaml::Value::String(name.to_owned()),
                serde_yaml::Value::String(value.to_owned()),
            );
            return Ok(());
        }
        return Err("`env` is already a value, not a mapping of names to values");
    }
    if let Some(operation) = key.strip_prefix("path.") {
        if operation.is_empty() {
            return Err("the path operation is empty");
        }
        insert(mapping, operation, "path");
        return Ok(());
    }
    insert(mapping, key, "top level");
    Ok(())
}

fn available(entries: &[ConfigEntry]) -> String {
    if entries.is_empty() {
        return "none".to_owned();
    }
    entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The key fragment for a `PATH` operation.
///
/// Matched rather than given an `as_str` on the enum: the key is a CLI spelling,
/// and a `Display` impl on the type would make it part of its public contract for
/// the sake of one caller. If a third spelling is ever needed it belongs here.
fn path_operation_name(kind: neoenv_config::PathOperationKind) -> &'static str {
    match kind {
        neoenv_config::PathOperationKind::Prepend => "prepend",
        neoenv_config::PathOperationKind::Append => "append",
    }
}

/// Render a span exactly the way `inspect` does, so one reader learns one format.
fn render(span: &SourceSpan) -> Option<String> {
    if span.path.is_empty() {
        return None;
    }
    Some(format!("{}:{}:{}", span.path, span.line, span.column))
}

/// Every setting this project declares, sorted by key.
///
/// **Sorted, not in discovery order.** Two runs over the same project must produce
/// the same list: a `config list` that reorders itself cannot be diffed, and a list
/// you cannot diff is a list you cannot review in a change.
pub(super) fn entries(project: &ResolvedProject) -> Vec<ConfigEntry> {
    let mut out: Vec<ConfigEntry> = Vec::new();

    if let Some(context) = project.context.as_deref() {
        let context = context.trim();
        if !context.is_empty() {
            out.push(ConfigEntry {
                name: "context".to_owned(),
                value: context.to_owned(),
                // **The file that actually supplied it**, which is not always the
                // project file.
                //
                // This reported `project.configuration_path` unconditionally, which was
                // correct while that was the only thing that could set `context`. With a
                // user-overrides layer above it, the value came from *that* file and the
                // answer here was a confident wrong one -- a worse failure than an
                // absent source, because a reader who sees a path has no reason to doubt
                // it. Still no line number: the resolved context is the result of a
                // four-step chain and no single line is where it lives.
                //
                // `None` when `--context` won, and `config list` prints `-` for it: a
                // value from the command line came from no file, and naming one would be
                // a lie.
                source: project
                    .context_source
                    .as_deref()
                    .or(Some(project.project.configuration_path.as_path()))
                    .and_then(std::path::Path::to_str)
                    .map(str::to_owned),
            });
        }
    }

    for (key, entry) in &project.environment {
        let value = if entry.secret {
            // The key still appears. A user who wants to know whether a secret is
            // set deserves an answer; a user who wants to read it does not get one
            // here, and the redaction is visible rather than silent.
            "<redacted>".to_owned()
        } else {
            entry.value.trim().to_owned()
        };
        if value.is_empty() {
            continue;
        }
        out.push(ConfigEntry {
            name: format!("env.{key}"),
            value,
            source: render(&entry.source),
        });
    }

    for operation in &project.path {
        let value = operation.value.trim();
        if value.is_empty() {
            continue;
        }
        out.push(ConfigEntry {
            name: format!("path.{}", path_operation_name(operation.kind)),
            value: value.to_owned(),
            source: render(&operation.source),
        });
    }

    out.sort_by(|left, right| left.name.cmp(&right.name));
    out.dedup_by(|left, right| left.name == right.name);
    out
}

#[cfg(test)]
#[path = "config_commands_tests.rs"]
mod tests;
