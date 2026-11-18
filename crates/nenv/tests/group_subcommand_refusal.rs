//! A subcommand that does not exist is refused by name, in every group that has one.
//!
//! ## What was wrong
//!
//! ```text
//! $ nenv config bogus ; echo $?
//! context      dev      /path/to/neoenv.yaml
//! env.STAGE    dev      /path/to/neoenv.yaml:3:3
//! 0
//! ```
//!
//! **Exit 0, and a complete, plausible listing.** `nenv context bogus` printed the
//! current context, `nenv job bogus` printed "this project declares no jobs",
//! `nenv inventory bogus` printed the equivalent. Four commands, one cause.
//!
//! The cause is one function. `next_tree_child_if_present` returned
//! `Option<&CommandSpec>`, and `None` meant both "there is no subcommand here" and
//! "that word is not a subcommand". Each of the four parsers followed a `None` with
//! `optional_path(..)`, so an invented subcommand was read as a **path** and the
//! command answered `nenv config bogus` as if it were `nenv config`.
//!
//! ## Why this is the worst of the three classes, and not the mildest
//!
//! This repository has been bitten by a wrong classification that fails closed, and by
//! a silent wrong install. This is a third shape and it is worse than either, because
//! it is not a failure at all:
//!
//! - a reader who mistypes a subcommand is **told the project is fine**;
//! - a script that mistypes one **exits 0** and continues on a plausible answer;
//! - and the answer looks *complete* — every key, every job, the current context.
//!
//! A failure is a signal. This is a success that hides one, and a reader cannot tell it
//! from the right answer by looking.
//!
//! ## The shape it took here
//!
//! `ship` had the same defect and it was fixed there, by hand, with a bespoke peek — and
//! the fix did not generalise, because the other four parsers were written separately.
//! That is the "two copies of one convention" defect: a correct fix applied to one
//! caller while four others kept the bug. `peek_tree_child` is the one place the
//! question is now decided, and `ship` uses it too.

use std::{fs, path::Path};

use tempfile::tempdir;

const PROJECT: &str = "\
format_version: 1
env:
  STAGE: dev
context: dev
tasks:
  build:
    uses: portable
    run: echo hi
";

mod support;

fn project() -> tempfile::TempDir {
    let directory = tempdir().expect("a temporary directory");
    fs::write(directory.path().join("neoenv.yaml"), PROJECT).expect("the fixture writes");
    directory
}

fn run(directory: &Path, arguments: &[&str]) -> (i32, String, String) {
    let output = support::TestCommand::new()
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **Every group refuses an invented subcommand, and none of them answers anyway.**
///
/// One test, five commands, because the bug was one function reached five ways — and a
/// claim proved for four of the five is the claim that was wrong the first time.
#[test]
fn an_invented_subcommand_is_refused_by_name_in_every_group() {
    let directory = project();

    // The word is `bogus` in all of them, so a refusal that merely *echoed* the input
    // would pass. It has to also say what the group does take, or the reader is sent
    // off to find the list themselves — which is the run they were about to do anyway.
    let cases: [(&[&str], &str); 5] = [
        (&["config", "bogus"], "list"),
        (&["context", "bogus"], "current"),
        (&["job", "bogus"], "list"),
        (&["inventory", "bogus"], "list"),
        // `ship` deliberately answers differently — see the test below — so it is here
        // only to be counted, not to assert the same message.
        (&["ship", "bogus"], "not implemented"),
    ];

    for (arguments, _) in cases {
        // Only the exit code is asserted in this loop; the message and the output
        // are asserted in the loop below, so a failure names *which* property
        // broke rather than reporting whichever it reaches first.
        let (code, _, _) = run(directory.path(), arguments);
        assert_ne!(
            code,
            0,
            "`nenv {}` accepted a subcommand that does not exist. A success here is a \
             success that hides a typo, and a script carrying the typo continues on a \
             plausible answer.",
            arguments.join(" ")
        );
    }

    // The message, for the four that use it. Asserted separately so the exit code and
    // the wording can fail for different reasons.
    for (arguments, expected) in [
        (&["config", "bogus"][..], "list"),
        (&["context", "bogus"][..], "current"),
        (&["job", "bogus"][..], "list"),
        (&["inventory", "bogus"][..], "list"),
    ] {
        let (code, stdout, stderr) = run(directory.path(), arguments);
        let message = stderr.clone();
        assert_ne!(code, 0, "`nenv {}`", arguments.join(" "));
        assert!(
            message.contains("unknown") && message.contains("bogus"),
            "`nenv {}` must name the word it did not recognise, or the reader cannot \
             tell which token to change: {message}",
            arguments.join(" ")
        );
        assert!(
            message.contains(expected),
            "`nenv {}` must list what the group does take ({expected:?}), so the \
             refusal is an answer rather than a dead end: {message}",
            arguments.join(" ")
        );
        assert!(
            !stdout.contains("STAGE") && !stdout.contains("this project declares"),
            "`nenv {}` printed a listing anyway. The refusal and the answer must not \
             both happen, or a script reading stdout cannot tell them apart:\n{stdout}",
            arguments.join(" ")
        );
    }
}

/// **The bare group still means the bare group.** A fix that refuses `config bogus` must
/// not refuse `config`, or the command has stopped working at all.
///
/// Both halves of the old behaviour, because they are different requests: `config` is
/// the group, `config list` is its verb, and they happened to print the same thing.
/// Pinning only one would let the other regress unnoticed.
#[test]
fn the_bare_group_and_its_verb_still_work() {
    let directory = project();

    let (code, stdout, stderr) = run(directory.path(), &["config"]);
    assert_eq!(code, 0, "`nenv config` must still list: {stderr}");
    assert!(stdout.contains("env.STAGE"), "{stdout}");

    let (code, stdout, stderr) = run(directory.path(), &["config", "list"]);
    assert_eq!(code, 0, "`nenv config list` must still list: {stderr}");
    assert!(stdout.contains("env.STAGE"), "{stdout}");

    let (code, stdout, stderr) = run(directory.path(), &["config", "get", "env.STAGE"]);
    assert_eq!(code, 0, "`nenv config get env.STAGE`: {stderr}");
    assert_eq!(stdout.trim(), "dev", "{stdout}");

    let (code, stdout, stderr) = run(directory.path(), &["context"]);
    assert_eq!(
        code, 0,
        "`nenv context` must still print the current context: {stderr}"
    );
    assert_eq!(stdout.trim(), "dev", "{stdout}");

    // An empty project still answers in words, because a bare newline is
    // indistinguishable from a crash.
    let empty = tempdir().expect("a temporary directory");
    fs::write(
        empty.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  b:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    let (code, stdout, stderr) = run(empty.path(), &["job"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("no jobs"),
        "an empty project must say so in words: {stdout:?}"
    );
}

/// `ship` answers differently, and deliberately.
///
/// The reference validates a verb against a fixed set rather than reading it as a
/// deployment name, and `ship prod` is a plausible typo for `ship deploy prod` — so
/// `ship prod is not implemented yet` names the verb and reads correctly, where
/// "unknown ship subcommand" would name a rule the reader does not know exists.
///
/// **The point of this test is that the shared helper did not flatten that**: a single
/// convention applied everywhere is only an improvement if the exceptions are recorded
/// where they are made.
#[test]
fn ship_keeps_its_own_wording_for_an_unrecognised_verb() {
    let directory = project();
    let (code, stdout, stderr) = run(directory.path(), &["ship", "bogus"]);
    assert_ne!(code, 0, "an unrecognised verb must not succeed");
    assert!(
        stderr.contains("ship bogus") && stderr.contains("not implemented"),
        "`ship bogus` should name the verb and say the transport is unimplemented, \
         which is the reference's own wording: {stderr}"
    );
    assert!(
        !stdout.contains("not implemented"),
        "the refusal belongs on stderr, so a script reading stdout sees nothing: \
         {stdout:?}"
    );
}

/// A flag is not a subcommand, and a path is not one either.
///
/// The refusal above must not swallow the two legitimate shapes that also arrive as a
/// bare word after a group: an option, and a project path.
#[test]
fn a_flag_and_a_path_are_still_accepted_after_a_group() {
    let directory = project();

    // An option.
    let (code, stdout, stderr) = run(directory.path(), &["config", "list", "--format", "json"]);
    assert_eq!(code, 0, "a flag after a verb must still work: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON on stdout");
    assert!(
        value.as_array().is_some_and(|rows| !rows.is_empty()),
        "{value}"
    );

    // **A path after the group, and after its verb.** Both take a configuration
    // *file*. The first version of this test passed a *directory*, and the resulting
    // "explicit project configuration does not exist" read like the refusal firing --
    // when it was the tool correctly reporting that the path is not a file. A test
    // that cannot tell those two apart cannot tell success from failure, which is the
    // whole point of the thing it is testing.
    let elsewhere = tempdir().expect("a temporary directory");
    let file = elsewhere.path().join("elsewhere.yaml");
    fs::write(&file, PROJECT).expect("the fixture writes");
    let file = file.to_str().expect("a path").to_owned();

    let (code, stdout, stderr) = run(directory.path(), &["config", &file]);
    assert_eq!(
        code, 0,
        "a path after the *group* must be a path, not an unknown subcommand: {stderr}"
    );
    assert!(stdout.contains("env.STAGE"), "{stdout}");

    let (code, stdout, stderr) = run(directory.path(), &["config", "list", &file]);
    assert_eq!(code, 0, "a path after the *verb* must be a path: {stderr}");
    assert!(stdout.contains("env.STAGE"), "{stdout}");

    // **A relative path**, which is the case that motivated the `exists()` clause in
    // `looks_like_a_path`: a word with no separator that names a real file. Without that
    // clause this is an unknown subcommand, because `nested` looks exactly like a
    // mistyped verb.
    fs::create_dir_all(directory.path().join("nested")).expect("the fixture creates a directory");
    fs::write(directory.path().join("nested/other.yaml"), PROJECT).expect("the fixture writes");
    let (code, _, stderr) = run(directory.path(), &["config", "nested/other.yaml"]);
    assert_eq!(code, 0, "a relative path must be a path: {stderr}");
}
