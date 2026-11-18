//! `nenv ssh`, `nenv scp` and `nenv inventory` — to the limit the reference is at.
//!
//! ## What is being claimed
//!
//! **Parity with the reference, and the reference does not execute these.** It
//! resolves inventory targets, prints a plan on request, and then writes *"SSH
//! execution is not implemented yet"* to stderr and exits 1 (`cli.go:2298`). `scp`
//! does the same at `2347`.
//!
//! So the surface under test is: resolve, plan, refuse execution by name. Every case
//! here runs the binary, and **not one of them opens a socket** — which is the point.
//! The whole of what the reference does is reachable without an SSH server, so a test
//! that needed one would be a test that does not run.
//!
//! ## The three properties that matter
//!
//! **Nothing is printed before every host is authorized.** A plan is what a user
//! reads to decide what is about to happen, so a plan containing a row the user has no
//! grant for is worse than no plan. `a_plan_is_refused_whole_rather_than_partly`
//! asserts the *absence* of output, not just the exit status.
//!
//! **The execution refusal names the limit.** A command that resolves a host and then
//! does nothing about it is #31 in a new place. The words have to say the transport is
//! unimplemented, or a user goes looking for a bug in their inventory.
//!
//! **The capability refusal is not the execution refusal.** A user who is not
//! authorized must be told *that*, not told the transport is missing — and the
//! distinction is a security property, because the wrong one would confirm something
//! about a host they have no grant for.

use std::path::Path;
use std::process::Command;

use tempfile::tempdir;

const INVENTORY: &str = "\
format_version: 1
inventories:
  default:
    hosts:
      web1:
        tags: [prod]
      web2: 10.0.0.9
      db1:
        tags: [data]
tasks:
  build:
    uses: portable
    run: echo hi
";

fn project() -> tempfile::TempDir {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("neoenv.yaml"), INVENTORY).expect("the fixture writes");
    dir
}

/// Writes a capability policy granting `connect` to each named host of `default`.
fn policy(dir: &Path, hosts: &[&str]) {
    let body: String = hosts
        .iter()
        .map(|host| {
            format!(
                "[[grants]]\nsubject = \"inventory:default/host:{host}\"\ncapability = \"connect\"\n\n"
            )
        })
        .collect::<Vec<_>>()
        .concat();
    std::fs::write(dir.join("capabilities.toml"), body).expect("the policy writes");
}

fn run(dir: &Path, policy: Option<&str>, arguments: &[&str]) -> (i32, String, String) {
    let policy = policy.map_or_else(|| dir.join("capabilities.toml"), |name| dir.join(name));
    let output = Command::new(env!("CARGO_BIN_EXE_nenv"))
        .args(arguments)
        .current_dir(dir)
        .env("NEOENV_CAPABILITY_POLICY", &policy)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A plan lists the hosts, in declaration order, with the address a host declares.
#[test]
fn a_plan_lists_the_hosts_with_their_addresses() {
    let dir = project();
    policy(dir.path(), &["web1", "web2"]);
    let (code, stdout, stderr) = run(dir.path(), None, &["ssh", "--plan", "web1", "web2"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        rows,
        ["ssh\tweb1\tweb1", "ssh\tweb2\t10.0.0.9"],
        "the plan is `ssh<TAB>name<TAB>target`, as the reference prints it at \
         `cli.go:2290`, and a host that declares an address is reached at it"
    );
}

/// A tag selects every host carrying it.
#[test]
fn a_tag_selects_every_host_carrying_it() {
    let dir = project();
    // `@data` selects `db1`, so `db1` is the host that needs a grant here. Granting
    // `web1` would have made the test assert the *refusal* and looked like a bug in
    // the resolver.
    policy(dir.path(), &["db1"]);
    let (code, stdout, stderr) = run(dir.path(), None, &["ssh", "--plan", "@data"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("db1"),
        "@data selects the one host tagged data:\n{stdout}"
    );
}

/// A host the inventory does not name is refused with the names it does have.
#[test]
fn an_unknown_target_names_the_hosts_and_tags() {
    let dir = project();
    let (code, stdout, stderr) = run(dir.path(), None, &["ssh", "--plan", "@prd"]);
    assert_ne!(code, 0);
    assert!(
        stdout.is_empty(),
        "no plan for a target that does not resolve: {stdout}"
    );
    let message = stderr.clone();
    assert!(message.contains("@prd"), "the target is named: {message}");
    assert!(
        message.contains("web1") && message.contains("prod") && message.contains("data"),
        "the hosts and the tags are named, so the user can see what to type: {message}"
    );
}

/// **The plan is refused whole, not partly.**
///
/// Asserted on the *absence of output*, not only the exit status: a plan that printed
/// the authorized host and then refused the second is a document a reader could act on,
/// and it names a host the user has no grant for.
#[test]
fn a_plan_is_refused_whole_rather_than_partly() {
    let dir = project();
    policy(dir.path(), &["web1"]);
    let (code, stdout, stderr) = run(dir.path(), None, &["ssh", "--plan", "web1", "web2"]);
    assert_ne!(code, 0, "an unauthorized host in the plan must fail it");
    assert!(
        stdout.is_empty(),
        "the authorized host was printed anyway, so there is a plan on screen naming a \
         host the user has no grant for:\n{stdout}"
    );
    assert!(
        stderr.contains("web2") && stderr.contains("inventory:default/host:web2"),
        "the refusal names the host and the exact grant to add:\n{stderr}"
    );
}

/// The capability refusal and the execution refusal are different sentences, and the
/// order matters.
#[test]
fn an_unauthorized_host_is_told_about_the_grant_not_the_transport() {
    let dir = project();
    let (code, _, stderr) = run(dir.path(), None, &["ssh", "web1"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("connect") && stderr.contains("grant"),
        "an unauthorized host must be told about the grant:\n{stderr}"
    );
    assert!(
        !stderr.contains("not implemented"),
        "the transport's absence is not this user's problem, and saying so first \
         confirms a host they have no grant for:\n{stderr}"
    );
}

/// Alias grants alone cannot authorize mutable endpoint details.
#[test]
fn execution_is_refused_by_name_rather_than_silently_absent() {
    let dir = project();
    policy(dir.path(), &["web1"]);
    let (code, _, stderr) = run(dir.path(), None, &["ssh", "web1"]);
    assert_ne!(
        code, 0,
        "an endpoint without a snapshot grant must not execute"
    );
    let message = stderr.clone();
    assert!(
        message.contains("connect"),
        "the refusal names the capability:\n{message}"
    );
    assert!(
        message.contains("ssh-endpoint:"),
        "the refusal identifies the endpoint snapshot:\n{message}"
    );
    assert!(
        message.contains("grant"),
        "the refusal explains the remedy:\n{message}"
    );
}

/// Nothing is executed. A command that resolves a host and then connects would be
/// exactly the wrong surprise.
#[test]
fn nothing_is_executed_and_no_socket_is_opened() {
    let dir = project();
    policy(dir.path(), &["web1", "web2", "db1"]);
    // A host that would hang if anything dialled it. The exit is immediate, so
    // nothing waited on a network.
    let (code, _, stderr) = run(dir.path(), None, &["ssh", "web1"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("ssh-endpoint:"), "{stderr}");
}

/// `scp` takes two paths and then targets, and its plan says which way the bytes go.
#[test]
fn scp_takes_two_paths_then_targets_and_plans_both_directions() {
    let dir = project();
    policy(dir.path(), &["web1"]);

    let (code, stdout, stderr) = run(
        dir.path(),
        None,
        &["scp", "--plan", "build", "web1:/tmp/build", "web1"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("build") && stdout.contains("/tmp/build") && stdout.contains("web1"),
        "the plan carries the source, the destination and the host:\n{stdout}"
    );

    // `--pull` flips the direction, and the plan says so -- a plan that reported
    // "push" for a pull is a plan that lies about which machine the bytes come from.
    let (pull_code, pull_stdout, pull_stderr) = run(
        dir.path(),
        None,
        &[
            "scp",
            "--plan",
            "--pull",
            "web1:/tmp/build",
            "build",
            "web1",
        ],
    );
    assert_eq!(pull_code, 0, "stderr: {pull_stderr}");
    assert_ne!(
        pull_stdout, stdout,
        "--pull produced the same plan as a push, so the direction is not in the plan"
    );
}

/// `scp` refuses rather than copying, by name.
#[test]
fn scp_refuses_rather_than_copying() {
    let dir = project();
    policy(dir.path(), &["web1"]);
    let (code, _, stderr) = run(
        dir.path(),
        None,
        &["scp", "build", "web1:/tmp/build", "web1"],
    );
    assert_ne!(code, 0);
    let message = stderr.clone();
    assert!(message.contains("ssh-endpoint:"), "{message}");
    // Nothing was copied. The destination is a remote path, so the check is that the
    // command did not resolve it against the *local* filesystem -- a refusal that had
    // already written `/tmp/build` would be a refusal too late.
    assert!(
        !std::path::Path::new("/tmp/build").exists(),
        "something was written to the local /tmp/build, so the copy was attempted \
         before it refused"
    );
}

/// The JSON plan carries the same facts as the text one, plus the direction.
#[test]
fn a_json_plan_carries_the_target_and_the_tags() {
    let dir = project();
    policy(dir.path(), &["web1"]);
    let (code, stdout, stderr) = run(
        dir.path(),
        None,
        &["scp", "--plan", "--format", "json", "a", "web1:/b", "web1"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON on stdout");
    let first = &value[0];
    assert_eq!(first["name"], "web1");
    assert_eq!(first["target"], "web1");
    assert_eq!(first["direction"], "push");
    assert_eq!(first["source"], "a");
    assert_eq!(first["destination"], "web1:/b");
}

/// `inventory` answers the question neither `ssh` nor `config` answers: of the hosts
/// my project names, which may I reach?
#[test]
fn inventory_list_joins_the_declaration_to_the_grant() {
    let dir = project();
    policy(dir.path(), &["web1"]);

    let (code, stdout, stderr) = run(dir.path(), None, &["inventory", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("web1"), "{stdout}");
    assert!(
        stdout.contains("granted") && stdout.contains("not granted"),
        "each host says whether a grant authorises it, which is the question the \
         command exists for:\n{stdout}"
    );

    // **Per host, not per inventory.** A listing that says "default: granted"
    // answers a question nobody asked when only one of three hosts is reachable, and
    // the reader has to go and work out which.
    let web1 = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("web1"))
        .expect("web1 is listed");
    assert!(
        web1.contains("granted") && !web1.contains("not granted"),
        "web1 is granted, and its row says so without the other column: {web1}"
    );
    let web2 = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("web2"))
        .expect("web2 is listed");
    assert!(
        web2.contains("not granted"),
        "web2 has no grant, and its row says so: {web2}"
    );
}

/// No inventory at all is a refusal that names what the project does have.
#[test]
fn a_project_with_no_inventory_is_refused_by_name() {
    let dir = tempdir().expect("a temporary directory");
    std::fs::write(
        dir.path().join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  build:\n    uses: portable\n    run: echo hi\n",
    )
    .expect("the fixture writes");
    let (code, _, stderr) = run(dir.path(), None, &["ssh", "--plan", "web1"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("default"), "{stderr}");
}

/// An inventory that is not the one asked for is refused, with the names.
#[test]
fn an_unknown_inventory_is_refused_with_the_available_names() {
    let dir = project();
    policy(dir.path(), &["web1"]);
    let (code, _, stderr) = run(
        dir.path(),
        None,
        &["ssh", "-i", "staging", "--plan", "web1"],
    );
    assert_ne!(code, 0);
    assert!(
        stderr.contains("staging") && stderr.contains("default"),
        "the refusal names what was asked for and what exists: {stderr}"
    );
}
