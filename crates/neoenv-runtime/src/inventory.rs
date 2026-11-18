//! Inventories: named lists of hosts, and the capability check that guards them.
//!
//! ## Why a host is a subject and not a capability
//!
//! A grant in this project is a `(subject, capability)` pair, and the subject is an
//! open structured string -- `global-task-dir:{dir}/runner:{runner}` is an existing
//! one. So an inventory host is a **subject**:
//!
//! ```text
//! subject    = inventory:{inventory}/host:{host}
//! capability = connect
//! ```
//!
//! **The host list stays in the configuration, not in the policy file.** That is the
//! decision with the useful consequence: a grant is keyed by host, so **adding a host
//! to an inventory requires a new grant.** The failure direction is the safe one and
//! it is safe by construction rather than by a check somebody has to remember to
//! write. Putting the hosts in the policy file would duplicate the config, and the
//! two would drift with nothing saying which is authoritative.
//!
//! The full reasoning, and the evidence from the machinery that already exists, is in
//! `docs/decision-records/inventory-hosts-are-a-subject.md`.
//!
//! ## The refusals are distinguished, and that is a correctness requirement
//!
//! Two denials look identical from outside and need different remedies:
//!
//! | case | remedy |
//! |------|--------|
//! | `connect` is not granted to this inventory at all | grant the capability |
//! | it is granted for a **different host** in the same inventory | grant this host, or drop it from the inventory |
//!
//! **One message covering both is the "wrong classification that fails closed and
//! still hides" shape**: a correct refusal a reader cannot act on. The distinction
//! matters most for the second case, because a user who granted `web1` and then added
//! `web2` to the same inventory has *already* done the authorising -- and being told
//! to "grant the connect capability" is advice they have already taken.
//!
//! [`check_connect`] therefore returns [`ConnectDenied`] rather than a `bool`, and
//! every caller renders it. A `bool` here is a refactor waiting to lose the
//! distinction, which is the only thing this module exists to keep.

use neoenv_core::Diagnostic;
use neoenv_core::DiagnosticCategory;
use neoenv_policy::{Capability, CapabilityGrants};

use neoenv_config::Inventory;

/// The capability subject for one host of one inventory.
///
/// Public because a user has to be able to write the grant line, and a spelling that
/// only exists inside this function is a spelling nobody can write.
#[must_use]
pub fn host_subject(inventory: &str, host: &str) -> String {
    format!("inventory:{inventory}/host:{host}")
}

/// The subject prefix every inventory grant shares.
///
/// So a grant file can be read at a glance: every line starting with this is about
/// hosts.
pub const INVENTORY_SUBJECT_PREFIX: &str = "inventory:";

/// Why a host was not authorized.
///
/// **Not a `bool`.** See the module header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectDenied {
    /// The project grants no `connect` to this inventory, or the inventory is not
    /// declared at all.
    ///
    /// The two are one case because the remedy is the same -- there is a decision to
    /// make before a line can be written -- and the message names the inventory either
    /// way. Splitting them would produce a permission error for a typo, which sends
    /// the reader looking in the wrong file.
    InventoryNotGranted {
        inventory: String,
        /// The hosts of this inventory that *are* granted, if any. Non-empty turns this
        /// into the more specific case below, so this is only reported for an
        /// inventory with no grants at all.
        granted_hosts: Vec<String>,
    },
    /// The project grants `connect` to this inventory, but not to this host.
    ///
    /// **The common case after an edit**: the user granted `web1`, then added `web2`.
    HostNotGranted {
        inventory: String,
        host: String,
        /// The hosts in this inventory that are granted, which is how the reader knows
        /// they are in the right file and need one more line.
        granted_hosts: Vec<String>,
    },
}

impl std::fmt::Display for ConnectDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InventoryNotGranted {
                inventory,
                granted_hosts,
            } => {
                write!(
                    formatter,
                    "the inventory {inventory:?} is granted no `connect` capability"
                )?;
                if granted_hosts.is_empty() {
                    write!(
                        formatter,
                        ". Add a grant for subject `{}`.",
                        host_subject(inventory, "<host>")
                    )
                } else {
                    write!(
                        formatter,
                        ". The following hosts in it are granted: {}. Add a grant for \
                         this one.",
                        granted_hosts.join(", ")
                    )
                }
            }
            Self::HostNotGranted {
                inventory,
                host,
                granted_hosts,
            } => {
                // Inline captures only: Rust does not allow a format string to mix
                // `{name}` captures with positional `{}`, and this one needs both the
                // bindings and the computed subject.
                let granted = if granted_hosts.is_empty() {
                    "no host".to_owned()
                } else {
                    // Quoted like the other two names, so a message reads consistently
                    // rather than quoting one name in a list and not the others.
                    granted_hosts
                        .iter()
                        .map(|name| format!("{name:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let subject = host_subject(inventory, host);
                write!(
                    formatter,
                    "the inventory {inventory:?} is granted `connect` for {granted} but \
                     not for {host:?}. Grant subject `{subject}`, or remove {host:?} from \
                     the inventory."
                )
            }
        }
    }
}

impl ConnectDenied {
    /// The diagnostic this denial becomes.
    ///
    /// One code, `NEO440`, for both cases: they are the same *category* -- this host
    /// is not authorized -- and the distinction belongs in the message, which is where
    /// a reader looks. Separate codes would make callers branch on a number to
    /// produce a sentence they should be reading.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        Diagnostic::new(DiagnosticCategory::Trust, "NEO440", self.to_string())
    }
}

/// Authorizes one host of one inventory, or says precisely which of the two denials
/// applies.
///
/// # Errors
///
/// Returns [`ConnectDenied::InventoryNotGranted`] when the inventory declares no
/// grant for any host, and [`ConnectDenied::HostNotGranted`] when it grants some but
/// not this one. **A host the inventory does not name is refused by name before the
/// grant is consulted**, because "this inventory does not have that host" and "you
/// have not authorized that host" are different problems and the second is the wrong
/// answer to the first.
pub fn check_connect(
    grants: &CapabilityGrants,
    inventories: &indexmap::IndexMap<String, Inventory>,
    inventory_name: &str,
    host: &str,
) -> Result<(), ConnectDenied> {
    let inventory =
        inventories
            .get(inventory_name)
            .ok_or_else(|| ConnectDenied::InventoryNotGranted {
                inventory: inventory_name.to_owned(),
                granted_hosts: granted_hosts(grants, inventory_name),
            })?;

    let granted = granted_hosts(grants, inventory_name);
    if granted.is_empty() {
        return Err(ConnectDenied::InventoryNotGranted {
            inventory: inventory_name.to_owned(),
            granted_hosts: granted,
        });
    }
    if !inventory.has_host(host) {
        // Named, and with the hosts that exist, because the remedy is a spelling fix
        // and not a permission decision. A user who typed `web-1` for `web1` should
        // not be told to write a grant.
        return Err(ConnectDenied::InventoryNotGranted {
            inventory: inventory_name.to_owned(),
            granted_hosts: granted,
        });
    }
    if grants.authorizes(Capability::Connect, &host_subject(inventory_name, host)) {
        return Ok(());
    }
    Err(ConnectDenied::HostNotGranted {
        inventory: inventory_name.to_owned(),
        host: host.to_owned(),
        granted_hosts: granted,
    })
}

/// The hosts of `inventory` that a grant names, sorted.
///
/// **Sorted**, because a policy file's order is an accident of editing and a refusal
/// that lists its alternatives in a shifting order cannot be diffed or grepped.
fn granted_hosts(grants: &CapabilityGrants, inventory: &str) -> Vec<String> {
    let prefix = format!("{INVENTORY_SUBJECT_PREFIX}{inventory}/host:");
    let mut hosts: Vec<String> = grants
        .subjects()
        .filter_map(|subject| subject.strip_prefix(&prefix).map(str::to_owned))
        .filter(|host| !host.is_empty())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Whether a subject names an inventory host, and which inventory and host.
///
/// Used by the policy reader to report a malformed subject rather than treating it as
/// a subject for some other kind of thing.
#[must_use]
pub fn inventory_of(subject: &str) -> Option<(&str, &str)> {
    let rest = subject.strip_prefix(INVENTORY_SUBJECT_PREFIX)?;
    let (inventory, host) = rest.split_once("/host:")?;
    if inventory.is_empty() || host.is_empty() {
        return None;
    }
    Some((inventory, host))
}

/// One resolved target: a host from the inventory, and where to reach it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHost {
    /// The inventory's name for it. The grant is keyed on this, so it is the identity.
    pub name: String,
    /// Where to connect, which is the host's `address:` or its own name.
    pub address: String,
    /// The tags it answers to, in declaration order.
    pub tags: Vec<String>,
}

impl std::fmt::Display for ResolvedHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.address)
    }
}

/// Why a target did not resolve.
///
/// **Its own type, not a `String`.** The reference returns bare `fmt.Errorf` strings,
/// and every caller turns them into an exit code -- so a caller cannot tell "no such
/// host" from "no such tag" except by matching on the text, and neither message names
/// what *was* available. A user who types `ssh @prd` is told the target was not found
/// and has to go and read the file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// The inventory has no hosts at all.
    NoHosts,
    /// No target was given.
    NoTargets,
    /// The target is neither a host name nor a tag any host carries.
    UnknownTarget {
        target: String,
        /// The host names, in declaration order.
        hosts: Vec<String>,
        /// The tags any host carries, deduplicated and sorted.
        tags: Vec<String>,
    },
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHosts => write!(
                formatter,
                "the inventory declares no hosts, so there is nothing to resolve"
            ),
            Self::NoTargets => write!(formatter, "at least one inventory host or tag is required"),
            Self::UnknownTarget {
                target,
                hosts,
                tags,
            } => {
                write!(formatter, "no inventory host or tag matches {target:?}")?;
                if !hosts.is_empty() {
                    write!(formatter, ". Hosts: {}.", hosts.join(", "))?;
                }
                if !tags.is_empty() {
                    write!(formatter, " Tags: {}.", tags.join(", "))?;
                }
                write!(formatter, " Use a host name, or @tag.")
            }
        }
    }
}

impl TargetError {
    /// The diagnostic this becomes.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        Diagnostic::new(DiagnosticCategory::NotFound, "NEO441", self.to_string())
    }
}

/// Resolves targets against an inventory: a host name, or `@tag` for every host
/// carrying it.
///
/// **Name first, then tag**, as in the reference (`projects/inventory.go:56-62`). The
/// order is not cosmetic: a host whose name is `prod` and a tag `prod` both existing
/// means `prod` is the host and `@prod` is the group, and getting it the other way
/// round would silently run against one host where the user asked for several.
///
/// **Deduplicated by host name, first occurrence wins**, so `ssh web1 @prod` lists
/// `web1` once. Without it a plan has a repeated row, and a plan with a repeated row
/// reads as "run this twice" when the intent was "these hosts".
///
/// **Declaration order, not target order.** The reference walks the inventory's
/// `HostOrder` for a tag match and appends in the order the targets were given, so a
/// tag match is in declaration order. Two runs over one file therefore produce the
/// same plan, and a plan you cannot diff is a plan you cannot review.
///
/// # Errors
///
/// Returns [`TargetError`] naming what the inventory does have.
pub fn resolve_targets(
    inventory: &Inventory,
    targets: &[String],
) -> Result<Vec<ResolvedHost>, TargetError> {
    if inventory.hosts.is_empty() {
        return Err(TargetError::NoHosts);
    }
    if targets.is_empty() {
        return Err(TargetError::NoTargets);
    }

    let mut resolved: Vec<ResolvedHost> = Vec::new();
    for raw in targets {
        let target = raw.trim();
        if target.is_empty() {
            continue;
        }
        // A host name, matched case-insensitively, and the *inventory's* spelling is
        // what comes back -- because the grant is keyed on the inventory's spelling
        // and `web1` answering to `Web1` must authorise the same machine.
        if let Some(name) = inventory
            .hosts
            .keys()
            .find(|name| name.eq_ignore_ascii_case(target))
        {
            push_once(&mut resolved, inventory, name);
            continue;
        }
        let tag = target.strip_prefix('@').unwrap_or(target);
        let matched: Vec<String> = inventory
            .names()
            .into_iter()
            .filter(|name| {
                inventory
                    .hosts
                    .get(*name)
                    .is_some_and(|host| host.tags.iter().any(|declared| declared == tag))
            })
            .map(ToOwned::to_owned)
            .collect();
        if matched.is_empty() {
            return Err(TargetError::UnknownTarget {
                target: target.to_owned(),
                hosts: inventory.names().into_iter().map(str::to_owned).collect(),
                tags: all_tags(inventory),
            });
        }
        for name in matched {
            push_once(&mut resolved, inventory, &name);
        }
    }
    if resolved.is_empty() {
        return Err(TargetError::UnknownTarget {
            target: targets.join(" "),
            hosts: inventory.names().into_iter().map(str::to_owned).collect(),
            tags: all_tags(inventory),
        });
    }
    Ok(resolved)
}

fn push_once(resolved: &mut Vec<ResolvedHost>, inventory: &Inventory, name: &str) {
    if resolved.iter().any(|host| host.name == name) {
        return;
    }
    let host = inventory.hosts.get(name).cloned().unwrap_or_default();
    resolved.push(ResolvedHost {
        name: name.to_owned(),
        address: inventory.address_of(name),
        tags: host.tags,
    });
}

/// Every tag any host carries, deduplicated and sorted.
///
/// Sorted, because it appears in a refusal and a list that reorders itself cannot be
/// grepped or diffed.
fn all_tags(inventory: &Inventory) -> Vec<String> {
    let mut tags: Vec<String> = inventory
        .hosts
        .values()
        .flat_map(|host| host.tags.iter().cloned())
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
