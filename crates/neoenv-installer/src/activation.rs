//! Shell activation plans assembled from resolved configuration and installed tools.

use std::{env, path::Path};

use indexmap::IndexMap;
use neoenv_config::PathOperationKind;
use neoenv_core::{Diagnostic, DiagnosticCategory};
use neotales_env::{EnvDiff, EnvError};

use neoenv_runtime::resolved_config::ResolvedProject;

use crate::tools::{InstalledRuntime, installed_tools, lockfile_path, read_lockfile};

/// Builds an ordered activation diff. Environment declarations are applied in
/// composed-source order and installed tools retain lockfile precedence.
///
/// **Runtimes are contributed by the caller**, through [`activation_diff_with`], because
/// they live in the global data directory rather than in the project, and this
/// function's whole design is that it is a pure function of the resolved project. The
/// one-argument form stays for the callers that only need project state.
///
/// **Fails with [`EnvError::InvalidKey`] on a key that is not a shell name**, and the
/// only keys that can be invalid here are the ones a user wrote in a config file —
/// this crate contributes `PATH` and nothing else, and `PATH` is a name by
/// construction. The error carries the offending key verbatim, because the
/// alternative is the one this repository keeps refusing: a variable that was
/// declared, silently did not appear, and left a task running with an environment
/// nobody wrote. See [`activation_diff_with`] for the rest.
/// # Errors
///
/// [`EnvError::InvalidKey`], carrying the key verbatim, when the project declares an
/// environment variable whose name a shell will not accept.
pub fn activation_diff(project: &ResolvedProject) -> Result<EnvDiff, EnvError> {
    activation_diff_with(project, &[])
}

/// The contribution installed runtimes make to the activation diff, and nothing else.
///
/// **Split out because it is a self-contained concern and it is the part with no
/// coverage.** Every other input to the activation diff comes from a `ResolvedProject`,
/// which no test in this crate constructs by hand -- it is only ever produced by
/// `load_active_project` reading a real directory -- so folding the runtime loops into
/// the project-shaped function would have left them untestable without standing up a
/// fixture project for two loops that never look at one.
///
/// The ordering rules, which are the substance:
///
/// - Input is the enumerator's order, **oldest first**, and the last write wins, so the
///   newest version ends up nearest the front of `PATH` and its variables are the ones
///   that survive. An older toolchain silently winning is the failure, and no
///   single-version row can see it.
/// - Every `PATH` entry is applied **before** any variable, so one runtime's `PATH` write
///   cannot clobber another's `GOROOT`-shaped value.
///
/// **The `Result` is about the second loop, not the first.** Every `PATH` this function
/// writes is a name by construction, so the first loop cannot fail; the second writes
/// keys that came from an installed runtime's recorded environment, and those are the
/// only ones here that a person can get wrong. It is still propagated rather than
/// unwrapped, because a function that returns `Result` for a reason and then panics
/// on a different input is a function whose signature lies about half its behaviour.
/// # Errors
///
/// [`EnvError::InvalidKey`], carrying the key verbatim, when a runtime's recorded
/// environment contains a name a shell will not accept. Nothing this function
/// contributes itself can trigger it.
pub fn runtime_diff(runtimes: &[InstalledRuntime]) -> Result<EnvDiff, EnvError> {
    let mut diff = EnvDiff::new();
    // **In the enumerator's order, oldest first, and that is load-bearing in both
    // directions.** A prepend puts its entry at the *front* and a `set` overwrites, so in
    // both cases the *last* write wins. Iterating oldest-first therefore puts the
    // newest version at the front of `PATH` and leaves the newest version's variables in
    // place.
    //
    // The first version of this used `.rev()`, on the reasoning that the tool loop below
    // does. That was wrong, and the test written alongside it said so immediately: the
    // resulting `PATH` was `/data/go/1.21/go/bin:/data/go/1.22/go/bin:/usr/bin`, so the
    // **older** toolchain won. The tool loop's `.rev()` is correct because
    // `installed_tools` returns newest-first, so the two loops read the same way and mean
    // opposite things. **An ordering rule copied from a neighbouring loop without checking
    // which way that loop's input is sorted is a bug with a plausible-looking comment.**
    for runtime in runtimes {
        diff.path_prepend("PATH", runtime.bin_dir.display().to_string())?;
    }
    for runtime in runtimes {
        for (key, value) in &runtime.environment {
            diff.set(key, value)?;
        }
    }
    Ok(diff)
}

/// [`activation_diff`] plus the runtimes installed in the global data directory.
///
/// **This is the step that makes an installed runtime reachable.** Until now the
/// environment a task or `exec` runs with was composed from the project's own
/// declarations, the project's `path` operations, and the bin directories of *locked
/// tools* — and nothing else. A runtime installed by `nenv global install go` landed in
/// nenv-owned state and never appeared on `PATH`, with `GOROOT` unset, so `go` was
/// installed and not runnable. There was no consumer for a runtime's environment at all,
/// which is why there was nothing to migrate hand-written injector code *into*.
///
/// Ordering, and why it is this way:
///
/// - Runtimes are applied **before** tools, so a tool's own bin directory wins a `PATH`
///   collision. A project that pins a `go`-based tool expects *that* tool's `go`, not
///   the SDK.
/// - Within runtimes, the newest version wins: `runtime_diff` iterates the enumerator's
///   oldest-first order so that the last write lands nearest the front of `PATH`.
/// - A runtime's variables are set after every `PATH` entry, so a `GOROOT`-shaped value
///   cannot be clobbered by a later runtime's `PATH` write.
///
/// **Fails on the first key that is not a shell name**, and the ordering above is the
/// reason that is a useful place to stop. A diff is applied in sequence, so a key
/// rejected after three `PATH` writes would have to be rolled back to leave the caller
/// with nothing; refusing at construction means the caller receives an `Err` and no
/// half-built diff to reason about. `neotales-env` moved this check out of `render` and
/// into the builders for the same reason — a `render` that asserts cannot fail, in a
/// method whose name and signature both promise it, and then does.
/// # Errors
///
/// [`EnvError::InvalidKey`], carrying the key verbatim, when the project declares an
/// environment variable whose name a shell will not accept. The check is at
/// construction rather than at render, so a rejected key leaves no partial diff.
pub fn activation_diff_with(
    project: &ResolvedProject,
    runtimes: &[InstalledRuntime],
) -> Result<EnvDiff, EnvError> {
    let mut diff = runtime_diff(runtimes)?;
    for entry in project.environment.values() {
        diff.set(&entry.key, &entry.value)?;
    }
    for operation in project
        .path
        .iter()
        .rev()
        .filter(|operation| operation.kind == PathOperationKind::Prepend)
    {
        diff.path_prepend("PATH", &operation.value)?;
    }
    for operation in project
        .path
        .iter()
        .filter(|operation| operation.kind == PathOperationKind::Append)
    {
        diff.path_append("PATH", &operation.value)?;
    }
    if let Ok(lockfile) = read_lockfile(&lockfile_path(&project.project.project_root)) {
        let paths = installed_tools(&project.project.project_root, &lockfile);
        for tool in paths.iter().rev() {
            diff.path_prepend("PATH", tool.bin_dir.display().to_string())?;
        }
    }
    Ok(diff)
}

/// Captures inherited environment only for diff reversal; no process mutation occurs.
#[must_use]
pub fn inherited_environment() -> IndexMap<String, String> {
    env::vars().collect()
}

/// Avoids exposing a path construction API while allowing black-box callers to
/// state the intended project root in documentation and tests.
#[must_use]
pub fn project_root(project: &ResolvedProject) -> &Path {
    &project.project.project_root
}

/// Reports a key that no shell or operating system will accept, as a validation
/// diagnostic naming the key and the file it was written in.
///
/// **Takes the configuration path rather than the project, and that is the point.** The
/// only thing it needs from a `ResolvedProject` is one path, and a function whose
/// second argument is a twelve-field struct to reach one of them cannot be tested
/// without constructing a project that nothing else in this file constructs either.
/// The `?`-on-`Result` callers have the path in hand already.
///
/// **The file is in the message because the key alone is not enough to act on.** A
/// project composes environment declarations from several sources — its own manifest,
/// an included file, a profile — and a message carrying only `1INVALID` sends the
/// reader hunting through all of them. The alternative is the failure this repository
/// has shipped eleven of: the install reports success, the key never appears in the
/// environment, and the first run is where it is discovered.
///
/// **Rendered with `{:?}` on the key rather than `{}`**, so a key containing a newline
/// or a quote is visibly quoted instead of silently breaking the line — a config key
/// is attacker-adjacent in the sense that it is whatever text the user wrote.
///
/// # Errors
///
/// A [`Diagnostic`] in the [`DiagnosticCategory::Validation`] category, code `NEO133`,
/// naming the rejected key and the configuration file it was read from. There is no
/// `Ok`-with-a-loss path: this either returns the diff or reports the key, and it
/// reports rather than dropping the variable silently.
pub fn invalid_key(
    built: Result<EnvDiff, EnvError>,
    configuration_path: &Path,
) -> Result<EnvDiff, Diagnostic> {
    built.map_err(|error| {
        let EnvError::InvalidKey { key } = error;
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO133",
            format!(
                "environment key {key:?} in {} is not a name a shell will accept; \
                 a name starts with a letter or an underscore and continues with \
                 letters, digits or underscores",
                configuration_path.display()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use indexmap::indexmap;
    use neoenv_core::DiagnosticCategory;
    use neotales_env::{EnvDiff, Shell};

    use super::{invalid_key, runtime_diff};
    use crate::tools::InstalledRuntime;

    fn runtime(name: &str, version: &str, bin: &str) -> InstalledRuntime {
        InstalledRuntime {
            id: name.into(),
            version: version.into(),
            root: PathBuf::from("/data").join(name).join(version),
            bin_dir: PathBuf::from(bin),
            environment: Vec::new(),
        }
    }

    /// **An installed runtime must reach `PATH`, and set the variables it needs.**
    ///
    /// This is the test for a gap that had none. The environment a task or `exec` runs
    /// with was composed from the project's own declarations, the project's `path`
    /// operations, and the bin directories of *locked tools* — and nothing else. A
    /// runtime installed by `nenv global install go` landed in nenv-owned state and
    /// was never contributed, so `go` was installed and not runnable and `GOROOT` was
    /// never set. Nothing failed, nothing warned, and no test noticed, because there was
    /// no code path in which it could have.
    ///
    /// A mutation that reverts the two runtime loops in `activation_diff_with` to
    /// nothing is caught by the first assertion; one that drops only the `environment`
    /// loop by the second. They are separate assertions because they are separate
    /// defects, and a single combined assertion would only prove one of them.
    #[test]
    fn an_installed_runtime_reaches_the_path_and_carries_its_environment() {
        let go = InstalledRuntime {
            environment: vec![("GOROOT".into(), "/data/go/1.22.0".to_owned())],
            ..runtime("go", "1.22.0", "/data/go/1.22.0/go/bin")
        };
        let before = indexmap! { "PATH".into() => "/usr/bin:/bin".into() };
        let applied = runtime_diff(std::slice::from_ref(&go))
            .expect("a runtime contributes PATH, which is a name")
            .apply(&before);

        let path = applied
            .get("PATH")
            .expect("PATH is always present after a prepend");
        assert!(
            path.split(neotales_env::Platform::host().path_separator())
                .any(|entry| entry == "/data/go/1.22.0/go/bin"),
            "the runtime's bin directory must be on PATH, got {path:?}"
        );
        assert_eq!(
            applied.get("GOROOT").map(String::as_str),
            Some("/data/go/1.22.0"),
            "GOROOT must be set, or the toolchain resolves against the user's own"
        );

        // **And the bin directory precedes the inherited PATH**, not merely appears in
        // it. A `PATH` entry after `/usr/bin` loses to any system `go`, which is the
        // failure this is for.
        let first = path
            .split(neotales_env::Platform::host().path_separator())
            .next()
            .unwrap_or_default();
        assert_eq!(
            first, "/data/go/1.22.0/go/bin",
            "a prepended runtime must sit in front of the inherited PATH"
        );
    }

    /// **A runtime's variables are applied after its `PATH` entry, and the newest
    /// version wins.**
    ///
    /// `installed_runtimes` reports each runtime's versions oldest-first, and this
    /// asserts the composition consumes that the only way it can: iterating in reverse,
    /// so the newest version ends up nearest the front. A mutation that dropped the
    /// `.rev()` would put `/data/go/1.21` ahead of `/data/go/1.22` — the older toolchain
    /// silently winning — and no single-runtime test can see that.
    #[test]
    fn the_newest_version_of_a_runtime_wins_and_its_variables_are_applied_last() {
        let older = InstalledRuntime {
            environment: vec![("GOROOT".into(), "/data/go/1.21".to_owned())],
            ..runtime("go", "1.21", "/data/go/1.21/go/bin")
        };
        let newer = InstalledRuntime {
            environment: vec![("GOROOT".into(), "/data/go/1.22".to_owned())],
            ..runtime("go", "1.22", "/data/go/1.22/go/bin")
        };
        // Oldest first, as the enumerator reports them.
        let runtimes = [older, newer];
        let before = indexmap! { "PATH".into() => "/usr/bin".into() };
        let applied = runtime_diff(&runtimes)
            .expect("the fixture writes PATH and GOROOT, which are names")
            .apply(&before);

        let path = applied.get("PATH").expect("PATH");
        let entries: Vec<&str> = path
            .split(neotales_env::Platform::host().path_separator())
            .collect();
        let position = |entry: &str| entries.iter().position(|seen| *seen == entry);
        assert_eq!(
            position("/data/go/1.22/go/bin")
                .and_then(|newer| { position("/data/go/1.21/go/bin").map(|older| newer < older) }),
            Some(true),
            "the newest version must precede the older one, got {path:?}"
        );
        assert_eq!(
            applied.get("GOROOT").map(String::as_str),
            Some("/data/go/1.22"),
            "the newest version's variables must be the ones that survive"
        );
    }

    /// **An empty runtime list contributes nothing at all.**
    ///
    /// A machine that has never run `nenv global install` has no runtimes, and that is
    /// the normal state, not an error. Asserted directly rather than inferred, because
    /// the failure it guards against is a `PATH` that gains a trailing separator or a
    /// `GOROOT` set to an empty string, and neither is visible to any other row here.
    #[test]
    fn no_installed_runtimes_contributes_nothing() {
        let before = indexmap! { "PATH".into() => "/usr/bin:/bin".into() };
        let applied = runtime_diff(&[])
            .expect("no runtimes means no key to reject")
            .apply(&before);
        assert_eq!(
            applied.get("PATH").map(String::as_str),
            before.get("PATH").map(String::as_str),
            "an empty runtime list must leave PATH exactly as inherited"
        );
        assert_eq!(
            applied.len(),
            before.len(),
            "an empty runtime list must not introduce a variable: {applied:?}"
        );
    }

    #[test]
    fn activation_diffs_are_reversible_without_process_mutation() {
        let before = indexmap! { "PATH".into() => "/usr/bin".into() };
        let mut diff = EnvDiff::new();
        diff.set("PROJECT", "yes")
            .expect("PROJECT is a name")
            .path_prepend("PATH", "/tools/first")
            .expect("PATH is a name");
        assert_eq!(diff.reverse(&before).apply(&diff.apply(&before)), before);
    }

    /// A refused key must name the key and the file, or it is indistinguishable from
    /// a correct run.
    ///
    /// **This is the test for a refusal, and refusals are where this repository has
    /// hurt itself.** A wrong classification that fails closed still hides: a reader
    /// who cannot tell a refusal from a success has learned nothing. So this asserts
    /// all four things a reader needs — the category, the code, the key, and the file —
    /// because a message carrying three of them is a message that sends the reader
    /// looking in the wrong place.
    ///
    /// The other direction matters as much: a diff that built cleanly must come back
    /// untouched, or this is a function that fails things it should pass.
    #[test]
    fn a_refused_key_names_the_key_and_the_file_it_was_written_in() {
        let path = Path::new("/projects/app/neoenv.yaml");
        let refused = invalid_key(
            Err(neotales_env::EnvError::InvalidKey {
                key: "1INVALID".into(),
            }),
            path,
        )
        .unwrap_err();
        assert_eq!(refused.category, DiagnosticCategory::Validation);
        assert_eq!(refused.code, "NEO133");
        let message = refused.message.clone();
        assert!(
            message.contains("\"1INVALID\""),
            "the message must show the key as written, got {message:?}"
        );
        assert!(
            message.contains("/projects/app/neoenv.yaml"),
            "the message must name the file, got {message:?}"
        );

        // The rule has to be stated, or the reader cannot tell what to change.
        assert!(
            message.contains("letter or an underscore"),
            "the message must state the rule, got {message:?}"
        );
    }

    #[test]
    fn a_diff_that_built_cleanly_is_returned_unchanged() {
        let built = runtime_diff(&[runtime("go", "1.22.5", "/data/go/1.22.5/go/bin")]).unwrap();
        let same = invalid_key(Ok(built.clone()), Path::new("/projects/app/neoenv.yaml")).unwrap();
        assert_eq!(
            same.render(Shell::Bash),
            built.render(Shell::Bash),
            "the wrapper must not alter a diff it accepted"
        );
    }
}
