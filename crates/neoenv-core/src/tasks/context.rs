//! Rejecting a context that no task or entry uses.
//!
//! The reference does not do this: `runner.go` looks up `name:context` and falls
//! back to `name`, so a mistyped context silently runs the default-context task.
//! Reproducing that is a choice, and it is the wrong one for a *typo* --
//!
//! ```text
//! $ nenv run build --context releae
//! build Succeeded                        # the release context never ran
//! ```
//!
//! -- because a run that reports success while having run the wrong thing is the
//! most expensive failure a task runner has. The fallback itself is still correct
//! and is kept: a task that genuinely has no contextual variant runs in the
//! default context, which is what `runner.go` does.
//!
//! So the rule is narrow on purpose. A context is *known* if some task key
//! carries it as a `name:context` suffix, or some entry declares it. A context
//! that is unknown is rejected **only when the project declares at least one**
//! -- a project that uses no contexts has nothing for the name to be wrong
//! against, and refusing `default` there would break every invocation.
//!
//! This is a deliberate divergence from the reference. It is on #503.

use std::collections::BTreeSet;

use indexmap::IndexMap;

use super::{DEFAULT_CONTEXT, TaskDefinition, TaskError};

/// Every context name a project actually uses.
///
/// Three sources, because all three exist and none of them is a declaration of
/// "the contexts this project has":
///
/// - a task key's `name:context` suffix, which is how a contextual task is
///   written;
/// - a `contexts:` entry on a `dotenv:` import, which is the reference's own
///   scoping key (`neofile/dotenv.go`) and is honored by the resolver;
/// - a `contexts:` entry on a `paths:` entry, which the same reference declares
///   (`neofile/paths.go`) and which this profile also honors.
///
/// The caller supplies the second and third, because `neoenv-core` does not
/// depend on `neoenv-config` and a dependency in that direction to reach one
/// field would be a worse trade than a slice.
///
/// A `*` is dropped: it is a wildcard, not a name a user can type.
#[must_use]
pub fn known_contexts<'a>(
    tasks: &IndexMap<String, TaskDefinition>,
    declared: impl IntoIterator<Item = &'a String>,
) -> BTreeSet<String> {
    let mut known: BTreeSet<String> = tasks
        .keys()
        // A task *package*'s generated keys are `package-<alias>:<name>`, and
        // the `<name>` half is a task, not a context. Harvesting it made
        // `--context deploy` accepted on a project whose only contextual task is
        // `build:prod` -- the exact #503 failure, reopened by the other task
        // source.
        //
        // Filtered on the *segment count*, not on the `package-` prefix, because a
        // contextual package task is `package-<alias>:<name>:<context>` and there
        // the last segment really is a context. Excluding by prefix dropped `prod`
        // from a project whose only contextual task came from a package, which is
        // the same false positive in the other direction.
        //
        // A user-authored task genuinely named `package-foo` with a `:prod` variant
        // is still excluded: the generated keyspace already claims that shape and
        // the reader reports the collision (NEO626), so there is no way to tell
        // the two apart here and guessing would be worse than either answer.
        .filter(|key| {
            key.strip_prefix("package-")
                .is_none_or(|rest| rest.split(':').count() >= 3)
        })
        .filter_map(|key| key.rsplit_once(':').map(|(_, context)| context))
        .filter(|context| !context.is_empty() && *context != "*")
        .map(str::to_owned)
        .collect();
    known.extend(
        declared
            .into_iter()
            .filter(|context| !context.is_empty() && context.as_str() != "*")
            .cloned(),
    );
    known
}

/// Rejects `context` when the project uses contexts and this is not one of them.
///
/// `declared` is the extra context names from outside the task map -- the
/// `contexts:` lists on `dotenv:` entries. It is a parameter rather than a
/// `Project` because `neoenv-core` does not depend on `neoenv-config`, and a
/// dependency in that direction to read one field would be a worse trade than
/// passing a slice.
///
/// # Errors
///
/// Returns `TaskError::UnknownContext` naming the context and the ones the
/// project does use, when the project declares any context and this is not one.
pub fn validate_context(
    tasks: &IndexMap<String, TaskDefinition>,
    declared: &[String],
    context: &str,
) -> Result<(), TaskError> {
    // An empty name is "unset", not a name that happens to match nothing, and
    // `*` is a wildcard a user can legitimately pass.
    if context.is_empty() || context == "*" || context == DEFAULT_CONTEXT {
        return Ok(());
    }
    let known = known_contexts(tasks, declared);
    // Nothing declared: the project does not use contexts, so there is no set for
    // this name to be wrong against.
    if known.is_empty() || known.contains(context) {
        return Ok(());
    }
    Err(TaskError::UnknownContext {
        context: context.to_owned(),
        known: known.into_iter().collect(),
    })
}
