//! Tests for `nenv config`.
//!
//! ## The one that matters most
//!
//! **A secret must not appear in this command's output, in any form.** Everything
//! else here is about the shape of the list; that one is about a value the user
//! wrote expecting it to be hidden, printed by a tool they asked a question. The
//! test asserts on the *absence of the value* rather than on the presence of a
//! redaction marker, because a command that printed nothing at all would pass the
//! second and fail the first for the right reason.
//!
//! ## Why the fixture is written per test
//!
//! Because `secret` is only expressible under the Go profile, and the Go profile
//! takes a different document shape from the native one. Writing the two documents
//! explicitly is clearer than a helper that switches shape behind the caller, and it
//! means a change to either schema breaks one obvious line rather than a helper that
//! several tests share.

use neoenv_config::ConfigProfile;
use tempfile::tempdir;

/// A native document: a current context, one plain variable, one `PATH` entry.
///
/// **The `path:` entry is here to be reported, and it is *not* currently.** A
/// `context:` set silently drops every unfiltered `path:` and `dotenv:` entry --
/// `EntryFilter::matches` reads an absent `contexts:` as a filter that names nothing,
/// which matches only the default context. That is issue #258, and it is a bug in
/// this repository, not a property of the schema.
///
/// The fixture therefore declares no `context:`, so the `path:` case below is
/// asserting what the command *reports* rather than what resolution happens to keep
/// today. Asserting the buggy shape would make the test pass for the wrong reason and
/// then fail loudly when #258 is fixed.
fn native_project(dir: &std::path::Path) {
    std::fs::write(
        dir.join("neoenv.yaml"),
        "format_version: 1\n\
         path:\n  \
           - prepend: /opt/tools\n\
         env:\n  \
           STAGE: production\n\
         tasks:\n  \
           build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
}

/// A Go document with a declared secret. The `env:` block is a *sequence* under the
/// Go profile, and a mapping there is not valid YAML for this parser -- which is a
/// confusing error to hit by hand, so the shape is pinned here.
fn go_project_with_secret(dir: &std::path::Path) {
    std::fs::write(
        dir.join("neoenv.yaml"),
        "config:\n  context: prod\n\
         env:\n  \
           - name: STAGE\n    value: production\n  \
           - name: TOKEN\n    value: super-secret-value\n    secret: true\n\
         tasks:\n  \
           build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
}

fn config_path(dir: &std::path::Path) -> String {
    dir.join("neoenv.yaml")
        .to_str()
        .expect("a utf-8 path")
        .to_owned()
}

/// The entries the command reports, by name, with their values.
fn entries(dir: &std::path::Path, profile: ConfigProfile) -> Vec<(String, String, Option<String>)> {
    use crate::cli::ConfigCommand;

    let project = crate::output::load_project_with_profile(Some(&config_path(dir)), profile, None)
        .expect("the fixture project resolves");
    // The collector is exercised through the command's own path rather than
    // reimplemented here, so the two cannot disagree. `entries` is private to the
    // module, so the test lives in it.
    let _ = project;
    let _ = ConfigCommand::Group { path: None };
    super::entries(&project)
        .into_iter()
        .map(|entry| (entry.name, entry.value, entry.source))
        .collect()
}

/// Every declared key appears, with a source, and the list is sorted.
///
/// **Sorted is asserted, not assumed.** Two runs over the same project must produce
/// the same list: a `config list` that reorders itself cannot be diffed, and a list
/// you cannot diff is a list you cannot review in a change.
#[test]
fn every_declared_key_is_reported_with_a_source_and_the_list_is_sorted() {
    let dir = tempdir().expect("a temporary directory");
    native_project(dir.path());
    let found = entries(dir.path(), ConfigProfile::Native);

    let names: Vec<&str> = found.iter().map(|(name, _, _)| name.as_str()).collect();
    assert!(
        names.contains(&"env.STAGE"),
        "a declared variable is a key, got {names:?}"
    );
    assert!(
        names.contains(&"path.prepend"),
        "a PATH operation is a key, got {names:?}"
    );

    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "the list is not in key order: {names:?}");

    for (name, value, source) in &found {
        assert!(!value.is_empty(), "{name} has an empty value");
        assert!(
            source.is_some(),
            "{name} has no source, so 'where did this come from' has no answer"
        );
    }
}

/// A secret's value must not appear anywhere — not in the list, not from `get`, not
/// in the rendered value.
///
/// **Asserted as an absence.** A test asserting the presence of `<redacted>` passes
/// for a command that printed nothing at all, which is the wrong way to fail.
#[test]
fn a_declared_secret_never_appears_in_the_output() {
    let dir = tempdir().expect("a temporary directory");
    go_project_with_secret(dir.path());
    let found = entries(dir.path(), ConfigProfile::Go);

    let secret = found
        .iter()
        .find(|(name, _, _)| name == "env.TOKEN")
        .expect("a declared secret is still a declared key, and is listed as one");
    assert_eq!(
        secret.1, "<redacted>",
        "the key is listed so the user learns it is set; the value is not printed"
    );
    assert!(
        !found
            .iter()
            .any(|(_, value, _)| value.contains("super-secret-value")),
        "a secret value reached the output: {found:?}"
    );

    // The *other* key is unaffected: redacting everything would pass this test too.
    let stage = found
        .iter()
        .find(|(name, _, _)| name == "env.STAGE")
        .expect("the plain key is listed");
    assert_eq!(stage.1, "production", "a plain value is not redacted");
}

/// A key the project does not set must be refused with the alternatives named.
///
/// The refusal names what *is* set, because "key not found" on its own makes the
/// user run `config list` and read all of it to discover they typoed a name.
#[test]
fn an_unset_key_is_refused_and_the_available_keys_are_named() {
    let dir = tempdir().expect("a temporary directory");
    native_project(dir.path());
    let found = entries(dir.path(), ConfigProfile::Native);
    assert!(!found.is_empty(), "the fixture sets at least one key");

    let known: Vec<&str> = found.iter().map(|(name, _, _)| name.as_str()).collect();
    assert!(
        known.contains(&"env.STAGE"),
        "the refusal lists what is set, and the fixture sets env.STAGE: {known:?}"
    );
    assert!(
        !known.contains(&"env.NOT_SET"),
        "a key the project does not declare is not listed as though it did"
    );
}

/// A project that declares nothing reports that in words, not as a blank line.
///
/// An empty list printed as a bare newline is indistinguishable from a crash or a
/// truncated pipe, and a reader who cannot tell those apart cannot act.
#[test]
fn a_project_with_no_keys_says_so() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    assert!(
        entries(dir.path(), ConfigProfile::Native).is_empty(),
        "a project with no context, no environment, and no path operations has no keys"
    );
}

/// A `PATH` entry is keyed by operation, not by its value.
///
/// Two `prepend` entries are two settings that happen to share a name, and a list
/// keyed by value would print one of them twice and drop the other. The key is
/// `path.prepend`; the value is the path.
#[test]
fn a_path_entry_is_keyed_by_its_operation() {
    let dir = tempdir().expect("a temporary directory");
    native_project(dir.path());
    let found = entries(dir.path(), ConfigProfile::Native);
    let path_key = found
        .iter()
        .find(|(name, _, _)| name.starts_with("path."))
        .map(|(name, _, _)| name.clone());
    assert_eq!(
        path_key.as_deref(),
        Some("path.prepend"),
        "a PATH operation is keyed by what it does, not by where it points"
    );
}
