//! The user-overrides layer: it outranks the project, and it says where a value came from.
//!
//! ## Why this layer exists
//!
//! `docs/decision-records/a-user-written-key-goes-in-a-machine-owned-file.md` decides that
//! a user-written key goes in `$XDG_CONFIG_HOME/neoenv/overrides.yaml` — a new,
//! machine-owned file at the **highest** precedence. The reasoning in one line: a
//! `config set` that does not take effect is worse than a missing one, so it cannot sit
//! below the file the user is correcting.
//!
//! This file tests the layer. The `set` command that writes it is a separate piece of
//! work (#262), and **the layer is useful without it** — a user can hand-write the file
//! and have it honoured, with correct provenance.
//!
//! ## The thing that made it a real change rather than an additive one
//!
//! `config list` reported the *project* file as the source of `context`, unconditionally.
//! That was correct while the project file was the only thing that could set `context`.
//! With a higher-precedence layer it became a **confidently wrong provenance** — worse
//! than an absent one, because a reader who sees a path has no reason to doubt it. So the
//! resolver now records which file won, and `ResolvedProject::context_source` is that
//! record. `None` when `--context` won, because a value from the command line came from
//! no file.

use std::{fs, process::Command};

use tempfile::TempDir;

/// A project whose own `neoenv.yaml` says `context: dev`, and an empty config home.
///
/// Everything is scrubbed so a developer's own configuration cannot decide whether these
/// assertions hold. Two `TempDir`s rather than one plus a path, because a `TempDir` owns
/// its directory and handing out a borrow of it means the caller cannot hold both — and
/// the first version of this returned both and did not compile, which is the cheapest
/// possible way to learn it.
fn fixture() -> (TempDir, TempDir, std::path::PathBuf) {
    let project = TempDir::new().unwrap();
    let config_home = TempDir::new().unwrap();
    let path = project.path().join("neoenv.yaml");
    fs::write(
        &path,
        "format_version: 1\n\
         context: dev\n\
         tasks:\n  \
         g:\n    \
         uses: portable\n    \
         run: echo project\n",
    )
    .unwrap();
    (project, config_home, path)
}

fn nenv(config_home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    for name in ["NEOENV_PROJECT", "NEOENV_PROFILE", "NEOENV_STATE_DIR"] {
        command.env_remove(name);
    }
    // The one variable that must be *set*, because the layer is defined in terms of it.
    command.env("XDG_CONFIG_HOME", config_home);
    command.env_remove("NEOENV_CONFIG_HOME");
    command
}

fn overrides_file(config_home: &std::path::Path) -> std::path::PathBuf {
    config_home.join("neoenv").join("overrides.yaml")
}

/// The overrides file outranks the project file.
///
/// The control is the same project with **no** overrides file, and it is in the same test
/// on purpose: "the layer wins" and "the project still wins when there is no layer" are
/// one claim, and separating them into two tests would let the second pass while the first
/// was broken.
#[test]
fn an_overrides_file_outranks_the_project_file() {
    let (_project, config_home, path) = fixture();

    let control = nenv(config_home.path())
        .args(["config", "get", "context", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(control.status.success(), "{control:?}");
    assert_eq!(String::from_utf8_lossy(&control.stdout).trim(), "dev");

    let directory = overrides_file(config_home.path());
    fs::create_dir_all(directory.parent().unwrap()).unwrap();
    fs::write(&directory, "format_version: 1\ncontext: prod\n").unwrap();

    let overridden = nenv(config_home.path())
        .args(["config", "get", "context", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(overridden.status.success(), "{overridden:?}");
    assert_eq!(
        String::from_utf8_lossy(&overridden.stdout).trim(),
        "prod",
        "the overrides file is above the project file, or the layer does nothing"
    );
}

/// `config list` names the file the winning value came from.
///
/// **This is the assertion that makes the layer honest.** Getting it wrong is not a
/// missing feature: it is a *wrong* answer to "where did this come from", printed with
/// the confidence of a path.
#[test]
fn config_list_names_the_file_that_supplied_the_value() {
    let (_project, config_home, path) = fixture();

    let control = nenv(config_home.path())
        .args(["config", "list", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(control.status.success(), "{control:?}");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains("neoenv.yaml"),
        "with no overrides file, the project file is the source"
    );

    let directory = overrides_file(config_home.path());
    fs::create_dir_all(directory.parent().unwrap()).unwrap();
    fs::write(&directory, "format_version: 1\ncontext: prod\n").unwrap();

    let overridden = nenv(config_home.path())
        .args(["config", "list", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(overridden.status.success(), "{overridden:?}");
    let text = String::from_utf8_lossy(&overridden.stdout);
    assert!(
        text.contains("overrides.yaml"),
        "the source must be the overrides file, not the project file. Got: {text}"
    );
    assert!(
        !text.contains("neoenv.yaml"),
        "naming the project file here is the misreport this layer introduces. Got: {text}"
    );
}

/// A malformed overrides file is **refused**, not skipped.
///
/// The failure mode this guards is the expensive one: a file that cannot be parsed looks
/// exactly like a file that is not there, so a typo in a key the user just wrote would
/// silently do nothing and the value would come from the project. **A broken layer must
/// be louder than an absent one**, or the layer is worse than not having it.
#[test]
fn a_malformed_overrides_file_is_refused_rather_than_skipped() {
    let (_project, config_home, path) = fixture();
    let directory = overrides_file(config_home.path());
    fs::create_dir_all(directory.parent().unwrap()).unwrap();
    fs::write(&directory, "format_version: 1\ncontext: [not, a, string]\n").unwrap();

    let output = nenv(config_home.path())
        .args(["config", "get", "context", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "a malformed overrides file must not fall through to the project"
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("overrides.yaml"),
        "the refusal must name the file it could not read. Got: {text}"
    );
}

/// A key the overrides file does not mention still comes from the project.
///
/// The layer is a **merge**, not a replacement. A project with `context: dev` and an
/// overrides file that only sets `env.FOO` keeps `context: dev` — and if the layer
/// shadowed the whole document, a user correcting one key would silently lose every other
/// one, which is the worst thing a corrective command can do.
#[test]
fn an_overrides_file_merges_rather_than_replaces() {
    let (_project, config_home, path) = fixture();
    let directory = overrides_file(config_home.path());
    fs::create_dir_all(directory.parent().unwrap()).unwrap();
    fs::write(&directory, "format_version: 1\nenv:\n  FOO: bar\n").unwrap();

    let context = nenv(config_home.path())
        .args(["config", "get", "context", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(context.status.success(), "{context:?}");
    assert_eq!(
        String::from_utf8_lossy(&context.stdout).trim(),
        "dev",
        "an overrides file that says nothing about `context` must not clear it"
    );

    let tasks = nenv(config_home.path())
        .args(["task", "list", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(tasks.status.success(), "{tasks:?}");
    assert_eq!(
        String::from_utf8_lossy(&tasks.stdout).trim(),
        "g",
        "the project file is still read for everything the overrides file does not set"
    );
}

/// `nenv config get --help` documents `config get <key> [path]`, and the parser refused it.
///
/// **The help text, a comment in the parser and the parser itself all disagreed**, and the
/// only one a user ever meets is the parser. `required_argument` calls `reject_remaining`
/// before the path could be read, so `config get <key> <path>` failed with "unexpected
/// argument for config get".
///
/// It is here rather than in a parser unit test because **the thing that was wrong was a
/// disagreement between three surfaces**, and a parser test would only ever have exercised
/// the one that was already consistent with itself.
#[test]
fn the_documented_config_get_invocation_works() {
    let (_project, config_home, path) = fixture();

    let output = nenv(config_home.path())
        .args(["config", "get", "context", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "dev");
}

/// The **reversed** order is refused, and the refusal names the argument order.
///
/// `config get ./p env.STAGE` would need a rule for telling a key from a path, and the
/// obvious one -- "whichever names a file that exists" -- guesses wrong for a key that
/// happens to be a filename and for a path that does not exist yet. So the order is fixed
/// and a key that *is* a file says so, rather than failing as "explicit project
/// configuration does not exist" and sending the reader to look for a missing file.
#[test]
fn a_path_in_the_key_position_says_the_order_is_wrong() {
    let (_project, config_home, path) = fixture();

    let output = nenv(config_home.path())
        .args(["config", "get", path.to_str().unwrap(), "context"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("is a file") && text.contains("<key> [path]"),
        "the refusal must name the mistake and the order. Got: {text}"
    );
}

// --- `config set` ----------------------------------------------------------
//
// The command is the other half of the layer, and the refusals are most of it: a
// corrective command that creates what it was not asked for is worse than no command.

/// A project with a `context` and one `env` entry, and a config home to write into.
fn settable() -> (TempDir, TempDir, std::path::PathBuf) {
    let project = TempDir::new().unwrap();
    let config_home = TempDir::new().unwrap();
    let path = project.path().join("neoenv.yaml");
    fs::write(
        &path,
        "format_version: 1\n\
         context: dev\n\
         env:\n  \
         STAGE: dev\n\
         tasks:\n  \
         g:\n    \
         uses: portable\n    \
         run: echo hi\n",
    )
    .unwrap();
    (project, config_home, path)
}

fn set(
    config_home: &std::path::Path,
    path: &std::path::Path,
    key: &str,
    value: &str,
) -> std::process::Output {
    nenv(config_home)
        .args(["config", "set", key, value, path.to_str().unwrap()])
        .output()
        .unwrap()
}

fn get(config_home: &std::path::Path, path: &std::path::Path, key: &str) -> String {
    let output = nenv(config_home)
        .args(["config", "get", key, path.to_str().unwrap()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A correction takes effect, and the confirmation names the file it wrote.
#[test]
fn a_correction_takes_effect_and_names_the_file() {
    let (_project, config_home, path) = settable();

    assert_eq!(get(config_home.path(), &path, "context"), "dev");

    let output = set(config_home.path(), &path, "context", "prod");
    assert!(output.status.success(), "{output:?}");

    // **The file, in the confirmation.** "It worked" without a path leaves a reader
    // wondering which of three configurations changed.
    let confirmation = String::from_utf8_lossy(&output.stdout);
    assert!(
        confirmation.contains("overrides.yaml"),
        "the confirmation must name the file. Got: {confirmation}"
    );
    assert_eq!(get(config_home.path(), &path, "context"), "prod");
}

/// Two corrections do not lose each other.
///
/// A second `set` that rewrote the file from scratch would drop the first, and a user
/// correcting two keys would silently lose one with no message. This is the failure that
/// makes a corrective command untrustworthy, so it is the one worth the test.
#[test]
fn a_second_correction_keeps_the_first() {
    let (_project, config_home, path) = settable();

    assert!(
        set(config_home.path(), &path, "context", "prod")
            .status
            .success()
    );
    assert!(
        set(config_home.path(), &path, "env.STAGE", "live")
            .status
            .success()
    );

    assert_eq!(get(config_home.path(), &path, "context"), "prod");
    assert_eq!(get(config_home.path(), &path, "env.STAGE"), "live");
}

/// A key the project does not declare is **refused, with the alternatives named**.
///
/// `set` suggests it creates keys, and a typo that silently created one is a file asking
/// for one thing and getting another. The alternatives come from `entries()`, so they are
/// the declared keys rather than a list maintained beside the reader.
#[test]
fn an_undeclared_key_is_refused_with_the_alternatives() {
    let (_project, config_home, path) = settable();

    let output = set(config_home.path(), &path, "stage", "prod");
    assert!(
        !output.status.success(),
        "an undeclared key must be refused"
    );

    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("not declared"), "{text}");
    for declared in ["context", "env.STAGE"] {
        assert!(
            text.contains(declared),
            "the refusal must name {declared:?} as an alternative. Got: {text}"
        );
    }
    // **And nothing was written.** A refusal that still created the file would leave a
    // key the user never asked for behind.
    assert!(
        !overrides_file(config_home.path()).exists(),
        "a refused set must not create the overrides file"
    );
}

/// The project is still read for everything the overrides file does not set.
///
/// A layer that shadowed the whole document would make a user who corrects one key lose
/// every other one, which is the worst thing a corrective command can do.
#[test]
fn the_project_is_still_read_after_a_correction() {
    let (_project, config_home, path) = settable();
    assert!(
        set(config_home.path(), &path, "context", "prod")
            .status
            .success()
    );

    let output = nenv(config_home.path())
        .args(["task", "list", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "g");
}

/// A correction can be taken back, and the project value comes back with it.
///
/// The round trip is the whole claim. `set` making `get` report the override is one half;
/// `unset` making it report the project's value again is the other, and the second half is
/// the one that proves the layer is a *layer* rather than a copy.
#[test]
fn a_correction_can_be_taken_back() {
    let (_project, config_home, path) = settable();
    assert_eq!(get(config_home.path(), &path, "context"), "dev");

    assert!(
        set(config_home.path(), &path, "context", "prod")
            .status
            .success()
    );
    assert_eq!(get(config_home.path(), &path, "context"), "prod");

    let removal = nenv(config_home.path())
        .args(["config", "unset", "context", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(removal.status.success(), "{removal:?}");
    assert_eq!(get(config_home.path(), &path, "context"), "dev");
}

/// Unsetting a key that is **not corrected** is refused, and the file is unchanged.
///
/// Reporting success for a removal that did not happen is the quietest wrong answer
/// available: the user believes their correction is gone while it is still winning every
/// resolution, and nothing in the output disagrees with them.
#[test]
fn unsetting_an_uncorrected_key_is_refused() {
    let (_project, config_home, path) = settable();
    assert!(
        set(config_home.path(), &path, "context", "prod")
            .status
            .success()
    );
    let before = fs::read(overrides_file(config_home.path())).unwrap();

    let output = nenv(config_home.path())
        .args(["config", "unset", "env.STAGE", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "a key that is not corrected must be refused"
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("nothing was removed"), "{text}");
    assert_eq!(
        fs::read(overrides_file(config_home.path())).unwrap(),
        before,
        "a refused unset must leave the file byte-identical"
    );
}

/// Unsetting one of two corrections keeps the other.
///
/// A removal that rewrote the file from the remaining keys would be fine, and a removal
/// that emptied it would not. The risk is a `remove` that takes the whole section with it,
/// so the assertion is that the *other* key still resolves.
#[test]
fn unsetting_one_correction_keeps_the_other() {
    let (_project, config_home, path) = settable();
    assert!(
        set(config_home.path(), &path, "context", "prod")
            .status
            .success()
    );
    assert!(
        set(config_home.path(), &path, "env.STAGE", "live")
            .status
            .success()
    );

    let removal = nenv(config_home.path())
        .args(["config", "unset", "context", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(removal.status.success(), "{removal:?}");

    assert_eq!(get(config_home.path(), &path, "context"), "dev");
    assert_eq!(get(config_home.path(), &path, "env.STAGE"), "live");
}

/// `unset` with no overrides file says so, rather than reporting a removal.
///
/// A project nobody has corrected has no overrides file, and "removed" for a key in a file
/// that does not exist is the same quiet wrong answer as above, one step earlier.
#[test]
fn unsetting_with_no_overrides_file_says_there_is_nothing_to_unset() {
    let (_project, config_home, path) = settable();

    let output = nenv(config_home.path())
        .args(["config", "unset", "context", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("nothing to unset"), "{text}");
}

/// A value the redaction policy covers is **written but not printed**.
///
/// The first version asked `config list` whether it had redacted the value, and under the
/// native profile it never does -- `structured.rs` sets `secret: false` because the v1
/// mapping form has no secret flag, and redaction there is by *name*. So the check could
/// not fire and the criterion it was written for was quietly unmet. It now asks
/// `neoenv_policy::should_redact_environment`, which is that by-name rule.
///
/// The assertion is on the **absence** of the value, and the second assertion is that the
/// value *is* in the file. Both matter: "printed nothing" would pass the first, and
/// "refused to write" would pass it too.
#[test]
fn a_redacted_value_is_written_but_not_printed() {
    let project = TempDir::new().unwrap();
    let config_home = TempDir::new().unwrap();
    let path = project.path().join("neoenv.yaml");
    fs::write(
        &path,
        "format_version: 1\n\
         context: dev\n\
         env:\n  \
         API_TOKEN: old-token-value\n  \
         MONKEY: banana\n\
         tasks:\n  \
         g:\n    \
         uses: portable\n    \
         run: echo hi\n",
    )
    .unwrap();

    let output = set(config_home.path(), &path, "env.API_TOKEN", "s3cret-value");
    assert!(output.status.success(), "{output:?}");

    let confirmation = String::from_utf8_lossy(&output.stdout);
    assert!(
        !confirmation.contains("s3cret-value"),
        "the value must not reach the confirmation. Got: {confirmation}"
    );
    assert!(
        confirmation.contains("<redacted>"),
        "and the confirmation must say it wrote something. Got: {confirmation}"
    );
    let written = fs::read_to_string(overrides_file(config_home.path())).unwrap();
    assert!(
        written.contains("s3cret-value"),
        "the value must still be written: redaction is for display, not storage. Got: {written}"
    );

    // **And a key the policy does not cover is printed as usual.** Redacting everything
    // would pass the first assertion while making the command useless, which is why the
    // rule is `should_redact_environment` and not "always hide the value".
    let plain = set(config_home.path(), &path, "env.MONKEY", "yellow");
    assert!(plain.status.success(), "{plain:?}");
    assert!(
        String::from_utf8_lossy(&plain.stdout).contains("yellow"),
        "a key outside the policy is not a secret and must be shown"
    );
}
