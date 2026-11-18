//! Project selection and run-local environment overrides for `run` and `exec`.
//!
//! Precedence, lowest to highest:
//!
//! 1. the resolved project environment,
//! 2. the task's own `dotenv` and `env` declarations,
//! 3. each `-E/--dotenv` file, in command-line order,
//! 4. tool and `PATH` activation,
//! 5. each `-e/--env KEY=VALUE`, in command-line order.
//!
//! `-E` lands below activation so a dotenv file cannot undo a prepended tool
//! directory, while `-e` lands above it so `-e PATH=...` still wins, which is
//! the usual reason to type it.
//!
//! Overrides are kept out of `ResolvedProject::environment` on purpose: a
//! command-line value has no declaring source, so it must not acquire a
//! fabricated source span or start appearing in `nenv inspect` output. The
//! caller's own environment is never mutated; only the map handed to the child
//! process is.

use indexmap::IndexMap;

use neoenv_config::EnvironmentEntry;
use neoenv_core::Diagnostic;

use super::{Path, RunOverrides};

/// Selects the project path for an invocation.
///
/// An explicit `--project` wins over a positional path. Both are handed to the
/// same loader, so a workspace alias resolves either way.
pub(super) fn project_path<'a>(
    positional: Option<&'a str>,
    overrides: &'a RunOverrides,
) -> Option<&'a str> {
    overrides.project.as_deref().or(positional)
}

/// Applies each `-E/--dotenv` file to `environment`, in command-line order.
///
/// Call this before tool activation. Interpolation resolves against
/// `environment` as it stands, so a dotenv value can reference a project value
/// and a later `-E` can reference an earlier one — the same rule a declared
/// dotenv import gets.
pub(super) fn apply_dotenv_overrides(
    environment: &mut IndexMap<String, String>,
    dotenv: &[String],
) -> Result<IndexMap<String, String>, Diagnostic> {
    // The dotenv reader needs `EnvironmentEntry` values so it can carry a source
    // span; key validation, interpolation, and the NEO105/NEO701/NEO702/NEO703
    // diagnostics therefore stay in one implementation. It is seeded with the
    // current environment so `${NAME}` resolves against what the project
    // declared, then only the keys the files actually set are written back.
    let mut entries = environment
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                EnvironmentEntry {
                    key: key.clone(),
                    value: value.clone(),
                    source: neoenv_core::SourceSpan::new("environment".into(), 1, 1),
                    secret: false,
                },
            )
        })
        .collect::<IndexMap<_, _>>();
    let mut assignments = IndexMap::new();
    for path in dotenv {
        let file_assignments = neoenv_runtime::resolved_config::apply_cli_dotenv_with_assignments(
            &mut entries,
            Path::new(path),
        )?;
        assignments.extend(file_assignments);
    }
    // `insert` updates a seeded key in place, so every entry now holds the value
    // that wins. Writing the seeded ones back unchanged is a no-op.
    for (key, entry) in &entries {
        environment.insert(key.clone(), entry.value.clone());
    }
    // The assignment keys, not a value comparison, are the ownership record. An
    // `-E` value equal to an inherited value is still supplied by the command
    // line and must be resolved if it is a reference.
    Ok(assignments)
}

/// Applies each `-e/--env KEY=VALUE` to `environment`, in command-line order.
///
/// Call this after tool activation so a `-e PATH=...` wins. A repeated key keeps
/// its last value, which is what a map insert gives.
pub(super) fn apply_env_overrides(
    environment: &mut IndexMap<String, String>,
    env: &[(String, String)],
) {
    for (key, value) in env {
        environment.insert(key.clone(), value.clone());
    }
}
