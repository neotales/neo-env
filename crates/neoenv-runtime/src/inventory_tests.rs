//! Target resolution and the `connect` capability check.
//!
//! ## What is worth testing here, and why it is not all of it
//!
//! Two properties, and one non-property.
//!
//! **The property that is easy to get wrong:** a *host name* and a *tag* can both
//! exist, and `prod` must mean the host while `@prod` means the group. Getting that
//! the other way round silently runs against one host where the reader asked for
//! several, and it produces a *shorter* plan rather than an error -- so nothing
//! downstream notices.
//!
//! **The property the refusal exists for:** a denied `connect` says *which* of the two
//! denials it is, because the remedies differ and a message covering both is a
//! correct refusal nobody can act on. That is asserted on the rendered text, not on a
//! variant, because the text is what a person reads.
//!
//! **The non-property:** this module never opens a socket. The reference's `ssh`
//! resolves its targets and then says *"SSH execution is not implemented yet"*
//! (`cli/cli.go:2298`), so resolution and refusal are the whole of what parity means
//! here, and both are testable without an SSH server. A test that needed one would be
//! a test that does not run.

use indexmap::IndexMap;
use neoenv_config::{Inventory, InventoryDefaults, InventoryHost};
use neoenv_policy::{Capability, CapabilityGrants};

use super::{
    ConnectDenied, TargetError, check_connect, host_subject, inventory_of, resolve_targets,
};

/// An inventory with two hosts, one of them reachable at a different address, and tags
/// spread so a tag match spans both.
fn inventory() -> Inventory {
    Inventory {
        hosts: IndexMap::from([
            (
                "web1".to_owned(),
                InventoryHost {
                    address: None,
                    tags: vec!["prod".to_owned()],
                    ..InventoryHost::default()
                },
            ),
            (
                "web2".to_owned(),
                InventoryHost {
                    address: Some("10.0.0.9".to_owned()),
                    tags: vec!["prod".to_owned(), "web".to_owned()],
                    ..InventoryHost::default()
                },
            ),
            (
                "db1".to_owned(),
                InventoryHost {
                    address: None,
                    tags: vec!["data".to_owned()],
                    ..InventoryHost::default()
                },
            ),
        ]),
        order: vec!["web1".to_owned(), "web2".to_owned(), "db1".to_owned()],
        defaults: InventoryDefaults::default(),
    }
}

fn targets(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn grants(document: &str) -> CapabilityGrants {
    CapabilityGrants::from_toml(document).expect("the grant document parses")
}

/// A host name resolves, and its address is its own unless it names another.
#[test]
fn a_host_name_resolves_to_its_address() {
    let found = resolve_targets(&inventory(), &targets(&["web1", "web2"])).expect("both resolve");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].name, "web1");
    assert_eq!(
        found[0].address, "web1",
        "no address means the name is the address"
    );
    assert_eq!(found[1].address, "10.0.0.9", "a declared address is used");
}

/// A tag resolves to every host carrying it, **in declaration order**.
#[test]
fn a_tag_resolves_to_every_host_carrying_it() {
    let found = resolve_targets(&inventory(), &targets(&["@prod"])).expect("@prod resolves");
    let names: Vec<&str> = found.iter().map(|host| host.name.as_str()).collect();
    assert_eq!(names, ["web1", "web2"], "declaration order, not tag order");
}

/// **The property that is easy to get wrong.**
///
/// A host named `prod` and a tag `prod` both existing means `prod` is the *host* and
/// `@prod` is the *group*. Resolving `prod` as the group would produce a longer plan
/// rather than an error, so nothing downstream would notice — and the reader asked
/// for one machine and got three.
#[test]
fn a_host_name_wins_over_a_tag_of_the_same_name() {
    let mut hosts = IndexMap::new();
    hosts.insert(
        "prod".to_owned(),
        InventoryHost {
            address: None,
            tags: vec!["canary".to_owned()],
            ..InventoryHost::default()
        },
    );
    for name in ["a", "b"] {
        hosts.insert(
            name.to_owned(),
            InventoryHost {
                address: None,
                tags: vec!["prod".to_owned()],
                ..InventoryHost::default()
            },
        );
    }
    let inventory = Inventory {
        hosts: hosts.clone(),
        order: hosts.keys().cloned().collect(),
        defaults: InventoryDefaults::default(),
    };

    let one = resolve_targets(&inventory, &targets(&["prod"])).expect("prod resolves");
    assert_eq!(one.len(), 1, "a bare name is the host, never the tag group");
    assert_eq!(one[0].name, "prod");

    let group = resolve_targets(&inventory, &targets(&["@prod"])).expect("@prod resolves");
    let names: Vec<&str> = group.iter().map(|host| host.name.as_str()).collect();
    assert_eq!(names, ["a", "b"], "@prod is the group");
}

/// A host named with different case is the same machine, and the inventory's spelling
/// is what comes back — because the grant is keyed on the inventory's spelling.
#[test]
fn a_host_name_matches_case_insensitively_and_keeps_the_inventory_spelling() {
    let found = resolve_targets(&inventory(), &targets(&["WEB1"])).expect("WEB1 resolves");
    assert_eq!(
        found[0].name, "web1",
        "the inventory's spelling is the identity"
    );
}

/// Overlapping targets list each host once.
#[test]
fn overlapping_targets_list_a_host_once() {
    let found = resolve_targets(&inventory(), &targets(&["web1", "@prod"])).expect("both resolve");
    let names: Vec<&str> = found.iter().map(|host| host.name.as_str()).collect();
    assert_eq!(
        names,
        ["web1", "web2"],
        "a repeated row reads as 'run this twice' when the intent was 'these hosts'"
    );
}

/// An unknown target names what the inventory **does** have — hosts and tags.
#[test]
fn an_unknown_target_names_the_hosts_and_the_tags() {
    let error = resolve_targets(&inventory(), &targets(&["@prd"])).expect_err("no such tag");
    let TargetError::UnknownTarget {
        target,
        hosts,
        tags,
    } = &error
    else {
        panic!("expected UnknownTarget, got {error:?}");
    };
    assert_eq!(target, "@prd");
    assert_eq!(
        hosts.iter().map(String::as_str).collect::<Vec<_>>(),
        ["web1", "web2", "db1"],
        "the hosts are named"
    );
    assert_eq!(
        tags.iter().map(String::as_str).collect::<Vec<_>>(),
        ["data", "prod", "web"],
        "the tags are named, sorted"
    );
    let rendered = error.to_string();
    assert!(rendered.contains("@prd") && rendered.contains("web1") && rendered.contains("prod"));
}

/// An inventory with no hosts and a run with no target are two different mistakes.
#[test]
fn an_empty_inventory_and_an_empty_target_list_are_different_refusals() {
    let empty = Inventory::default();
    assert_eq!(
        resolve_targets(&empty, &targets(&["web1"])).expect_err("no hosts"),
        TargetError::NoHosts
    );
    assert_eq!(
        resolve_targets(&inventory(), &[]).expect_err("no targets"),
        TargetError::NoTargets
    );
}

// --- the capability check ----------------------------------------------------

/// A grant names a subject, and `host_subject` / `inventory_of` are inverses.
///
/// **Asserted as an inverse pair**, because the grant is written by a person and read
/// by this code: if the two disagree, a user's grant silently authorises nothing and
/// the failure is a permission error against a correctly-spelled line.
#[test]
fn a_subject_and_its_parse_are_inverses() {
    for (inventory, host) in [("prod", "web1"), ("a-b_c", "10.0.0.9"), ("x", "y")] {
        let subject = host_subject(inventory, host);
        assert_eq!(inventory_of(&subject), Some((inventory, host)), "{subject}");
    }
    // And the degenerate forms are *not* subjects, rather than subjects that resolve
    // to nothing.
    for subject in [
        "inventory:",
        "inventory:prod/host:",
        "inventory:/host:web1",
        "other:x",
    ] {
        assert_eq!(inventory_of(subject), None, "{subject} should not parse");
    }
}

/// Default-deny: no grants at all means nothing is authorized.
#[test]
fn an_empty_policy_authorizes_nothing() {
    let error = check_connect(&CapabilityGrants::default(), &map(), "prod", "web1")
        .expect_err("default-deny");
    assert!(
        matches!(error, ConnectDenied::InventoryNotGranted { .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("no `connect` capability"),
        "the refusal has to say what is missing: {error}"
    );
}

/// The granted case, and it is the *only* case that authorizes.
#[test]
fn a_grant_for_this_host_authorizes_it() {
    let document = format!(
        "[[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n",
        host_subject("prod", "web1")
    );
    check_connect(&grants(&document), &map(), "prod", "web1").expect("granted");
}

/// **The distinction the module exists for.**
///
/// A user who granted `web1` and then added `web2` has already authorised this
/// inventory. Telling them to "grant the connect capability" is advice they have
/// already taken, and it sends them to edit the right file for the wrong reason.
#[test]
fn a_grant_for_another_host_says_which_host_and_names_the_granted_ones() {
    let document = format!(
        "[[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n",
        host_subject("prod", "web1")
    );
    let error =
        check_connect(&grants(&document), &map(), "prod", "web2").expect_err("web2 is not granted");
    assert!(
        matches!(error, ConnectDenied::HostNotGranted { .. }),
        "a grant for another host is a *different* refusal, not 'no grants': {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("web2"),
        "the refusal must name the host asked for: {rendered}"
    );
    assert!(
        rendered.contains("web1"),
        "the refusal must name the host that *is* granted, or the reader cannot tell \
         they are in the right file: {rendered}"
    );
    assert!(
        rendered.contains(&host_subject("prod", "web2")),
        "the refusal must carry the exact grant line to add: {rendered}"
    );
}

/// **Adding a host to an inventory requires a new grant.** That is the property the
/// whole design exists for, so it is asserted directly rather than inferred.
#[test]
fn adding_a_host_to_a_granted_inventory_still_denies_the_new_host() {
    let document = format!(
        "[[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n",
        host_subject("prod", "web1")
    );
    let before = map();
    let after = {
        let mut inventories = before.clone();
        inventories
            .get_mut("prod")
            .expect("prod exists")
            .hosts
            .insert(
                "web3".to_owned(),
                InventoryHost {
                    address: None,
                    tags: vec!["prod".to_owned()],
                    ..InventoryHost::default()
                },
            );
        inventories
            .get_mut("prod")
            .expect("prod exists")
            .order
            .push("web3".to_owned());
        inventories
    };

    // The same grant, against an inventory that has grown a host.
    check_connect(&grants(&document), &before, "prod", "web1").expect("web1 stays granted");
    let denied = check_connect(&grants(&document), &after, "prod", "web3")
        .expect_err("a new host needs a new grant");
    assert!(
        matches!(denied, ConnectDenied::HostNotGranted { .. }),
        "growing the inventory must not grow the grant: {denied:?}"
    );
    // And selecting the new host by tag reaches it, so the refusal is real rather
    // than a target-resolution accident.
    let grown = after.get("prod").expect("prod exists").clone();
    let resolved = resolve_targets(&grown, &targets(&["@prod"])).expect("@prod resolves");
    assert!(
        resolved.iter().any(|host| host.name == "web3"),
        "the new host is in the tag group, so the capability check is what refuses it"
    );
}

/// A host the inventory does not name is refused **before** the grant is consulted,
/// and the refusal is the "not granted" one rather than a permission error about a
/// host that does not exist.
#[test]
fn a_host_the_inventory_does_not_name_is_not_a_permission_question() {
    let document = format!(
        "[[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n",
        host_subject("prod", "web1")
    );
    let error = check_connect(&grants(&document), &map(), "prod", "web-1")
        .expect_err("web-1 is not in the inventory");
    assert!(
        matches!(error, ConnectDenied::InventoryNotGranted { .. }),
        "a typo is a spelling problem, not a permission one: {error:?}"
    );
    assert!(
        error.to_string().contains("web1"),
        "the refusal names the hosts that do exist: {error}"
    );
}

/// An inventory the project does not declare is refused by name.
#[test]
fn an_unknown_inventory_is_refused_by_name() {
    let error = check_connect(&CapabilityGrants::default(), &map(), "staging", "web1")
        .expect_err("no such inventory");
    assert!(error.to_string().contains("staging"), "{error}");
}

/// `subjects()` lists what the policy names, sorted, so a refusal's alternatives can
/// be read.
#[test]
fn subjects_are_sorted_and_deduplicated() {
    let document = format!(
        "[[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n\
         [[grants]]\nsubject = \"{}\"\ncapability = \"connect\"\n\
         [[grants]]\nsubject = \"global-task-dir:/x/runner:y\"\ncapability = \"execute\"\n",
        host_subject("prod", "web2"),
        host_subject("prod", "web1"),
    );
    let document = grants(&document);
    let subjects: Vec<&str> = document.subjects().collect();
    assert_eq!(
        subjects,
        [
            "global-task-dir:/x/runner:y",
            "inventory:prod/host:web1",
            "inventory:prod/host:web2",
        ],
        "sorted, and one entry per subject however many capabilities name it"
    );
    assert_eq!(Capability::Connect.name(), "connect");
}

/// The one inventory map every case uses.
fn map() -> IndexMap<String, Inventory> {
    IndexMap::from([("prod".to_owned(), inventory())])
}
