//! Trust, capability, and redaction policy primitives for `nenv`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Reserved legacy SSH identity sentinel. It is never an authorizable subject.
pub const RESERVED_SSH_IDENTITY_SUBJECT: &str = "ssh-endpoint:explicit-identity-context-required";

/// A capability that must be explicitly approved before an effect is allowed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Execute,
    FetchRemote,
    /// Opening a network connection to a host the project names.
    ///
    /// **The host is not the capability; the host is the subject.** A grant reads
    /// `inventory:prod/host:web1` plus this, so adding a host to an inventory requires
    /// a new grant and the failure direction is the safe one. Putting the host list
    /// in the policy file instead would duplicate the config, and the two would drift
    /// with nothing saying which is authoritative. The reasoning, with the evidence
    /// from the existing machinery, is in
    /// `docs/decision-records/inventory-hosts-are-a-subject.md`.
    Connect,
}

impl Capability {
    /// Parses the stable capability name used in declarations and policy files.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "execute" => Some(Self::Execute),
            "fetch-remote" => Some(Self::FetchRemote),
            _ => None,
        }
    }

    /// Returns the stable external policy spelling of this capability.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::FetchRemote => "fetch-remote",
            Self::Connect => "connect",
        }
    }
}

/// Persisted grants made by an authority external to task declarations.
///
/// The TOML format is a sequence of `[[grants]]` tables, each with a `subject`
/// string and a `capability` value. The document contains only approvals; an
/// absent subject-capability pair is denied.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityGrants {
    grants: BTreeSet<(String, Capability)>,
}

impl CapabilityGrants {
    /// Parses a persisted capability-grant document.
    ///
    /// Unknown fields and unknown capability names are rejected by the strict
    /// document schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is malformed or does not match the
    /// grant schema, or contains the reserved SSH identity sentinel.
    pub fn from_toml(document: &str) -> Result<Self, toml::de::Error> {
        let parsed: GrantDocument = toml::from_str(document)?;
        Ok(Self {
            grants: parsed
                .grants
                .into_iter()
                .map(|grant| (grant.subject, grant.capability))
                .collect(),
        })
    }

    /// Serializes this document in a deterministic order.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML serializer cannot encode the document.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        let grants = self
            .grants
            .iter()
            .map(|(subject, capability)| Grant {
                subject: subject.clone(),
                capability: *capability,
            })
            .collect();
        toml::to_string_pretty(&GrantDocument { grants })
    }

    /// Returns whether this external subject has been granted this capability.
    #[must_use]
    pub fn authorizes(&self, capability: Capability, subject: &str) -> bool {
        subject != RESERVED_SSH_IDENTITY_SUBJECT
            && self.grants.contains(&(subject.to_owned(), capability))
    }

    /// Every subject this document names, deduplicated and sorted.
    ///
    /// Exists so a refusal can list the alternatives. A denial that says "not
    /// authorized" and stops there is a correct refusal a reader cannot act on, and
    /// the alternatives are the whole difference between the two -- see
    /// `docs/decision-records/inventory-hosts-are-a-subject.md` and the "wrong
    /// classification that fails closed and still hides" note in `AGENTS.md`.
    ///
    /// Sorted and deduplicated because a policy file's order is an accident of
    /// editing, and a list that reorders itself cannot be grepped or diffed.
    pub fn subjects(&self) -> impl Iterator<Item = &str> {
        let mut seen: Vec<&str> = Vec::new();
        for (subject, _) in &self.grants {
            if !seen.contains(&subject.as_str()) {
                seen.push(subject);
            }
        }
        seen.sort_unstable();
        seen.into_iter()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantDocument {
    #[serde(default)]
    grants: Vec<Grant>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    #[serde(deserialize_with = "deserialize_subject")]
    subject: String,
    capability: Capability,
}

fn deserialize_subject<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let subject = String::deserialize(deserializer)?;
    if subject == RESERVED_SSH_IDENTITY_SUBJECT {
        return Err(serde::de::Error::custom(
            "reserved SSH identity subject cannot be granted",
        ));
    }
    Ok(subject)
}

/// Returns whether an environment variable name must be redacted by default.
///
/// The check matches complete underscore-separated segments to avoid treating
/// incidental names such as `MONKEY` as secrets.
#[must_use]
pub fn should_redact_environment(key: &str) -> bool {
    key.split('_').any(|segment| {
        matches!(
            segment.to_ascii_uppercase().as_str(),
            "SECRET" | "TOKEN" | "PASSWORD" | "PASSWD" | "CREDENTIAL" | "KEY"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilityGrants};

    #[test]
    fn reserved_ssh_identity_subject_is_never_grantable() {
        let sentinel = "ssh-endpoint:explicit-identity-context-required";
        let document = format!("[[grants]]\nsubject = {sentinel:?}\ncapability = 'connect'\n");
        assert!(CapabilityGrants::from_toml(&document).is_err());
        let forged = CapabilityGrants {
            grants: [
                (sentinel.to_owned(), Capability::Connect),
                (sentinel.to_owned(), Capability::Execute),
                (sentinel.to_owned(), Capability::FetchRemote),
            ]
            .into_iter()
            .collect(),
        };
        for capability in [
            Capability::Connect,
            Capability::Execute,
            Capability::FetchRemote,
        ] {
            assert!(!forged.authorizes(capability, sentinel));
        }
    }

    #[test]
    fn capabilities_are_explicit() {
        assert_ne!(Capability::Execute, Capability::FetchRemote);
    }

    #[test]
    fn capability_grants_default_to_deny() {
        let grants = CapabilityGrants::default();

        assert!(!grants.authorizes(Capability::Execute, "project:example"));
    }

    #[test]
    fn capability_grants_require_an_exact_subject_and_capability_match() {
        let grants = CapabilityGrants::from_toml(
            r#"
                [[grants]]
                subject = "project:example"
                capability = "execute"
            "#,
        )
        .expect("document is valid");

        assert!(grants.authorizes(Capability::Execute, "project:example"));
        assert!(!grants.authorizes(Capability::FetchRemote, "project:example"));
        assert!(!grants.authorizes(Capability::Execute, "project:example-dev"));
        assert_eq!(
            grants.to_toml().expect("document serializes"),
            "[[grants]]\nsubject = \"project:example\"\ncapability = \"execute\"\n"
        );
    }

    #[test]
    fn capability_grants_reject_invalid_documents() {
        let error = CapabilityGrants::from_toml(
            r#"
                [[grants]]
                subject = "project:example"
                capability = "run-anything"
            "#,
        );

        assert!(error.is_err());
    }

    #[test]
    fn identifies_sensitive_environment_keys_by_segment() {
        assert!(super::should_redact_environment("API_TOKEN"));
        assert!(super::should_redact_environment("SSH_PRIVATE_KEY"));
        assert!(!super::should_redact_environment("MONKEY"));
    }
}
