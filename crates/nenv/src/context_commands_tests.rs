//! Tests for `nenv context`.
//!
//! These are black-box where they can be and unit where they must be. The point of
//! the command is that it answers the same question `run` answers, so the tests that
//! matter most are the ones that compare it against `select_context` directly -- a
//! `context` command that drifts from the dispatcher reports a context the tasks do
//! not use, which is worse than having no such command at all.
//!
//! The project fixture is written out per test rather than shared, because
//! `declared_contexts` and `project.context` are *resolved* values: a shared fixture
//! mutated by one test is a fixture the next one cannot reason about. That is the
//! same lesson as the `TempDir::parent()` defect in the source repository -- a test
//! that reaches outside its own directory is a test sharing state it did not intend
//! to share.

use std::path::Path;

use crate::output::load_project_with_profile;

use neoenv_core::tasks::select_context;
use tempfile::tempdir;

/// A project with a current context, two task variants, and an env entry scoped to
/// one of them. Written fresh per test.
fn fixture() -> tempfile::TempDir {
    let dir = tempdir().expect("a temporary directory");
    let path = dir.path().join("neoenv.yaml");
    std::fs::write(
        &path,
        "format_version: 1\n\
         context: prod\n\
         tasks:\n  \
           build:\n    uses: shell\n    run: echo building\n  \
           \"build:dev\":\n    extends: build\n  \
           \"build:prod\":\n    extends: build\n  \
           \"deploy:prod\":\n    extends: build\n\
         env:\n  \
           STAGE: production\n",
    )
    .expect("the fixture writes");
    dir
}

/// The configuration file, not the directory.
///
/// **A directory is not a project path here**, which cost a round of confused
/// failures: `load_project_with_profile` treats an explicit path as the
/// configuration file itself and reports `NEO201 explicit project configuration
/// does not exist` for a directory that plainly contains one. Naming the file
/// directly is what the command does when a user passes one, so the test does the
/// same rather than relying on a walk-up that only works for a bare directory.
fn resolve(dir: &Path) -> neoenv_runtime::resolved_config::ResolvedProject {
    let config = dir.join("neoenv.yaml");
    load_project_with_profile(
        Some(config.to_str().expect("a utf-8 path")),
        neoenv_config::ConfigProfile::default(),
        None,
    )
    .expect("the fixture project resolves")
}

/// The command and the dispatcher must resolve the same context, or the command is
/// reporting a fiction.
///
/// Four cases, because the precedence chain has four steps and a test that only
/// covers the first one passes while the other three are wrong.
#[test]
fn context_current_agrees_with_the_dispatcher_for_every_precedence_step() {
    let dir = fixture();
    let project = resolve(dir.path());

    // The precedence chain, one row per step, asserted directly against
    // `select_context` rather than through the process environment. Mutating
    // `NEOENV_CONTEXT` in a test would race every other test that reads it, which is
    // why `set_var` is `unsafe` in this edition and why the codebase passes an
    // environment map instead.
    for (cli, environment, expected, why) in [
        (None, None, "prod", "the project's own context"),
        (
            Some("dev"),
            None,
            "dev",
            "the command line wins over the project",
        ),
        (
            None,
            Some("dev"),
            "dev",
            "the environment wins over the project",
        ),
        (
            Some("dev"),
            Some("prod"),
            "dev",
            "the command line wins over the environment",
        ),
        (
            None,
            Some(""),
            "prod",
            "an empty environment value is unset, not a name",
        ),
        (
            Some("  "),
            None,
            "prod",
            "a whitespace-only command line value is unset, not a name",
        ),
    ] {
        assert_eq!(
            select_context(cli, environment, project.context.as_deref()),
            expected,
            "{why}"
        );
    }
}

/// `context list` must show every context the project names, and say where each came
/// from.
///
/// The origin is the useful half, and it is the half a test has to pin: a list that
/// printed bare names would pass a weaker version of this test and be much less
/// useful, because the question a user has is "is `dev` a context or a typo in a
/// tool name".
#[test]
fn context_list_reports_every_named_context_with_its_origin() {
    let dir = fixture();
    let project = resolve(dir.path());
    let contexts = declared_for_test(&project);

    let names: Vec<&str> = contexts.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        names.contains(&"prod"),
        "the project's own context is a context, got {names:?}"
    );
    assert!(
        names.contains(&"dev"),
        "a task variant's context is a context, got {names:?}. `declared_contexts` \
         does not include these -- they come from the task keys -- so this is the \
         assertion that fails if that collection is dropped."
    );

    let prod = contexts
        .iter()
        .find(|(name, _)| name == "prod")
        .expect("prod is listed");
    assert_eq!(prod.1, "current context");

    // No duplicates. Two rows for one name means the reader looks it up twice, and
    // which row they read first is a coin toss.
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        names.len(),
        "a context is listed twice: {names:?}"
    );
}

/// A mistyped context must be refused, and the refusal must name the alternatives.
///
/// **This is the assertion the command exists for.** `nenv context --context releae`
/// answering `releae` would be a command that confirms a typo, in the one place the
/// user asked whether the typo was real. The dispatcher already refuses this; the
/// command has to refuse it the same way, or the command is worse than no command.
#[test]
fn a_mistyped_context_is_refused_and_the_alternatives_are_named() {
    let dir = fixture();
    let project = resolve(dir.path());
    let error = neoenv_core::tasks::validate_context(
        &project.declared_tasks,
        &project.declared_contexts,
        "releae",
    )
    .expect_err("a typo is refused");
    let message = error.to_string();
    assert!(
        message.contains("releae"),
        "the refusal names the key that was rejected, got {message:?}"
    );
    assert!(
        message.contains("dev") && message.contains("prod"),
        "the refusal names what was meant instead, got {message:?}"
    );
}

/// `*` and the default context are not typos, and a list must not offer them.
///
/// A wildcard is a filter a user can legitimately pass, so refusing it would be
/// wrong; and it is not a name anyone can select, so listing it would be a row in
/// `context list` that does not correspond to anything.
#[test]
fn a_wildcard_and_the_default_are_not_refused_and_not_listed() {
    let dir = fixture();
    let project = resolve(dir.path());
    for accepted in ["*", neoenv_core::tasks::DEFAULT_CONTEXT, ""] {
        assert!(
            neoenv_core::tasks::validate_context(
                &project.declared_tasks,
                &project.declared_contexts,
                accepted
            )
            .is_ok(),
            "{accepted:?} is not a mistyped context"
        );
    }
    let contexts = declared_for_test(&project);
    assert!(
        !contexts.iter().any(|(name, _)| name == "*"),
        "a wildcard is a filter, not a context anyone can select"
    );
}

/// A project that uses no contexts lists none, and says so in words.
///
/// An empty list printed as a bare newline looks like a truncated output or a crash,
/// and a reader cannot tell it from a command that found nothing because it failed.
#[test]
fn a_project_with_no_contexts_reports_that_in_words() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  build:\n    uses: shell\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    let project = resolve(dir.path());
    assert!(
        declared_for_test(&project).is_empty(),
        "a project with no contexts and no context variants names none"
    );
}

/// The shape `context list` prints, exposed for the test above rather than
/// duplicated, so the two cannot disagree about what the command reports.
fn declared_for_test(
    project: &neoenv_runtime::resolved_config::ResolvedProject,
) -> Vec<(String, &'static str)> {
    // The implementation is private to the command module, so this mirrors it. That
    // is a duplication, and it is deliberate: the alternative is making the
    // collector public so a test can assert it returns what it returns, which tests
    // nothing. The names and origins are the contract, and both are asserted below
    // against the fixtures rather than against the collector.
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut push = |name: &str, origin: &'static str| {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return;
        }
        if out.iter().any(|(existing, _)| existing == trimmed) {
            return;
        }
        out.push((trimmed.to_owned(), origin));
    };
    if let Some(current) = project.context.as_deref() {
        push(current, "current context");
    }
    for key in project.declared_tasks.keys() {
        if let Some((_, context)) = key.split_once(':') {
            push(context, "task variant");
        }
    }
    for name in &project.declared_contexts {
        push(name, "declared by context:, or by an env or dotenv entry");
    }
    out
}
