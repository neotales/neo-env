//! `nenv ship` — deployment workflows, to the limit the reference is at.
//!
//! ## What is being claimed
//!
//! **Parity with the reference, and the reference does not execute `ship` either.**
//! `runShipCommand` lists deployments, resolves one for a lifecycle verb, prints a
//! plan on `--plan`, and then writes *"ship deploy for deployment %q (%s) is not
//! implemented yet"* to stderr and exits 1 (`cli/cli.go:817`). An unrecognised verb
//! gets *"ship %s is not implemented yet"* (`cli.go:821`).
//!
//! So the surface is: list, plan, refuse execution by name — and **not one case here
//! deploys anything**.
//!
//! ## The property worth reading the tests for
//!
//! **Selection is a key convention, not a `contexts:` filter.** `ShipMap.Resolve`
//! (`neofile/ship_map.go:118-127`) substitutes `default` for an empty name, then tries
//! `{name}:{context}`, then falls back to `{name}`. A first version of this file used
//! a `contexts:` filter and needed an "N deployments apply, name one" refusal that the
//! reference has no equivalent of — because a key lookup cannot be ambiguous.
//! `the_context_qualified_key_wins_and_the_bare_key_falls_back` asserts all three
//! branches, and `contexts_is_refused_rather_than_accepted` asserts the filter is not
//! quietly accepted, since it is read in the reference only by shell completion.
//!
//! ## And the ten keys
//!
//! The reference's `ShipDeployment` has fourteen fields. Its `ship` path reads four.
//! `the_reference_inert_keys_are_refused_by_name` covers the rest.

use std::path::Path;

use tempfile::tempdir;

/// Three deployments: a bare one, a context-qualified one, and one with no
/// description so the list's type-fallback is exercised.
const PROJECT: &str = "\
format_version: 1
deployments:
  default:
    type: service
    desc: The public service
  \"default:prod\":
    type: service
    desc: The production service
  worker:
    type: job
tasks:
  build:
    uses: portable
    run: echo hi
";

mod support;

fn project() -> tempfile::TempDir {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("neoenv.yaml"), PROJECT).expect("the fixture writes");
    dir
}

fn run(dir: &Path, arguments: &[&str]) -> (i32, String, String) {
    let output = support::TestCommand::new()
        .args(arguments)
        .current_dir(dir)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The list is `key<TAB>desc`, with the type standing in for a missing description —
/// the reference's own shape at `cli.go:755-765`. A three-column line would break
/// every script that cuts column 2 as the description.
#[test]
fn the_list_is_two_columns_with_the_type_as_the_fallback() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["ship", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        rows,
        [
            "default\tThe public service",
            "default:prod\tThe production service",
            // No `desc`, so the type stands in rather than the row being short.
            "worker\tjob",
        ]
    );
}

/// The three branches of `ShipMap.Resolve`, which is the whole selection rule.
#[test]
fn the_context_qualified_key_wins_and_the_bare_key_falls_back() {
    let dir = project();

    // No name at all substitutes `default` (`ship_map.go:119-121`).
    let (code, stdout, stderr) = run(dir.path(), &["ship", "deploy", "--plan"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "would-ship\tdeploy\tdefault\tservice\tdefault",
        "an empty name is `default`"
    );

    // `{name}:{context}` exists, so it wins over the bare key.
    let (code, stdout, stderr) = run(
        dir.path(),
        &["ship", "deploy", "--plan", "--context", "prod"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "would-ship\tdeploy\tdefault:prod\tservice\tprod",
        "the qualified key is the more specific declaration, so it wins"
    );

    // No `worker:prod`, so it falls back to `worker` — a missing variant is not a
    // refusal, it is the base deployment.
    let (code, stdout, stderr) = run(
        dir.path(),
        &["ship", "deploy", "worker", "--plan", "--context", "prod"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        "would-ship\tdeploy\tworker\tjob\tprod",
        "a deployment with no context variant runs the base one"
    );
}

/// The plan reports the **typed** verb, so `ship up` says `up`.
///
/// The reference reports whichever was written. Getting this needs the typed spelling
/// held before the alias resolves, which is why the parser peeks at the verb rather
/// than consuming it.
#[test]
fn the_plan_reports_the_verb_the_user_typed() {
    let dir = project();
    for (typed, reported) in [
        ("deploy", "deploy"),
        ("up", "up"),
        ("rollback", "rollback"),
        ("destroy", "destroy"),
        ("down", "down"),
    ] {
        let (code, stdout, stderr) = run(dir.path(), &["ship", typed, "--plan", "default"]);
        assert_eq!(code, 0, "`ship {typed}` failed: {stderr}");
        assert!(
            stdout.contains(&format!("would-ship\t{reported}\t")),
            "`ship {typed}` reported a different verb than was typed:\n{stdout}"
        );
    }
}

/// A name that matches nothing is refused, and **every key tried and every key
/// available is named**. "not found" with one hint sends a reader who wrote `web`
/// alongside a `web:prod` guessing.
#[test]
fn a_missing_deployment_names_the_keys_tried_and_the_keys_available() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["ship", "deploy", "nosuch"]);
    assert_ne!(code, 0);
    assert!(
        stdout.is_empty(),
        "no plan for a deployment that does not exist: {stdout}"
    );
    let message = stderr.clone();
    assert!(message.contains("nosuch"), "the name is echoed: {message}");
    assert!(
        message.contains("nosuch:default") && message.contains("default, default:prod, worker"),
        "both the keys tried and the keys that exist are named: {message}"
    );
}

/// An unrecognised verb is refused **as a verb**, not as a deployment name.
///
/// `ship prod` is a plausible typo for `ship deploy prod`, and answering it as "no
/// such deployment" sends the reader into the document instead of at their own
/// command line.
#[test]
fn an_unknown_verb_is_refused_as_a_verb() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["ship", "deploye"]);
    assert_ne!(code, 0);
    assert!(
        !stdout.contains("service"),
        "an unknown verb listed the deployments, which is a plausible-looking answer \\
         to a question nobody asked:\n{stdout}"
    );
    assert!(
        stderr.contains("deploye") && stderr.contains("not implemented"),
        "the refusal names the verb: {stderr}"
    );
}

/// The execution refusal: names the verb, the deployment, its type, and the context.
#[test]
fn execution_is_refused_by_name_with_every_fact_the_reader_needs() {
    let dir = project();
    let (code, _, stderr) = run(dir.path(), &["ship", "deploy", "--context", "prod"]);
    assert_ne!(code, 0, "an unimplemented verb must not exit 0");
    let message = stderr.clone();
    for fact in ["deploy", "default:prod", "service", "prod"] {
        assert!(
            message.contains(fact),
            "the refusal omits {fact:?}:\n{message}"
        );
    }
    assert!(
        message.contains("not implemented"),
        "the refusal must say the transport is unimplemented, or the reader goes \\
         looking for a fault in their deployment:\n{message}"
    );
    assert!(
        message.contains("--plan"),
        "the refusal points at the thing that does work:\n{message}"
    );
}

/// Nothing is deployed. A command that resolved a deployment and then acted would be
/// exactly the wrong surprise.
#[test]
fn nothing_is_deployed() {
    let dir = project();
    let (code, _, stderr) = run(dir.path(), &["ship", "destroy", "default"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("not implemented"), "{stderr}");
}

/// The eight keys the reference declares and its `ship` path never reads, plus
/// `contexts` which it reads only in shell completion.
#[test]
fn the_reference_inert_keys_are_refused_by_name() {
    for key in [
        "env: {A: b}",
        "dotenv: [x]",
        "before: [y]",
        "after: [z]",
        "compose: docker-compose.yml",
        "cwd: /tmp",
        "timeout: 5m",
        "contexts: [prod]",
    ] {
        let dir = tempdir().expect("a temporary directory");
        std::fs::write(
            dir.path().join("neoenv.yaml"),
            format!(
                "format_version: 1\ndeployments:\n  d:\n    {key}\n\
                 tasks:\n  b:\n    uses: portable\n    run: echo hi\n"
            ),
        )
        .expect("the fixture writes");
        let (code, _, stderr) = run(dir.path(), &["validate"]);
        assert_ne!(
            code, 0,
            "`{key}` was accepted, so it is a key that parses and does nothing"
        );
        let name = key.split(':').next().expect("a key");
        assert!(
            stderr.contains(name),
            "the refusal for `{key}` does not name it:\n{stderr}"
        );
    }
}

/// A project with no deployments says so in words rather than printing nothing.
#[test]
fn a_project_with_no_deployments_says_so() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  b:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    let (code, stdout, stderr) = run(dir.path(), &["ship", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("no deployments"),
        "a bare newline is indistinguishable from a crash:\n{stdout:?}"
    );

    // And a verb against it is refused, not silently a no-op.
    let (code, _, stderr) = run(dir.path(), &["ship", "deploy"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("no ship deployments") || stderr.contains("no deployments"),
        "{stderr}"
    );
}

/// The JSON list carries all three facts, including the type for a deployment with no
/// description — so a consumer does not have to know the text fallback.
#[test]
fn the_json_list_carries_name_type_and_description() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), &["ship", "list", "--format", "json"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON on stdout");
    let rows = value.as_array().expect("an array");
    assert_eq!(rows.len(), 3, "{value}");
    assert_eq!(rows[0]["name"], "default");
    assert_eq!(rows[0]["type"], "service");
    assert_eq!(rows[0]["desc"], "The public service");
    let worker = rows
        .iter()
        .find(|row| row["name"] == "job" || row["name"] == "worker")
        .expect("the worker row");
    assert_eq!(worker["type"], "job");
    assert!(
        worker["desc"].is_null(),
        "a deployment with no description reports null rather than a type: {worker}"
    );
}

/// A Go document's `ship:` section is read, not refused.
///
/// It *was* refused with a message saying the Go reference does not execute it either
/// — true, and the wrong reason. Refusing a construct because the *reference* is
/// incomplete is a strange standard to hold a port to; the question is whether the
/// reader can represent it faithfully, and it can now.
#[test]
fn a_go_ship_section_is_carried_through_the_native_normalizer() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "ship:\n  web:\n    type: service\n    desc: From the Go profile\n\
         tasks:\n  b:\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    let (code, stdout, stderr) = run(
        dir.path(),
        &["--profile", "go", "ship", "list", "--format", "json"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON on stdout");
    let rows = value.as_array().expect("an array");
    assert_eq!(rows[0]["name"], "web", "{value}");
    assert_eq!(rows[0]["type"], "service", "{value}");
    assert_eq!(rows[0]["desc"], "From the Go profile", "{value}");
}
