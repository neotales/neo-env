//! Proves the public OS backend contract is implementable from another crate.
//!
//! `Secret` has no public fields, so this test defines its backend outside
//! `neoenv-runtime` and constructs values only through `Secret::try_new`. It
//! never touches a platform credential store.

use std::{collections::BTreeMap, sync::Arc};

use indexmap::IndexMap;
use neoenv_config::{OsVault, VaultDeclaration, VaultProvider};
use neoenv_core::SourceSpan;
use neoenv_runtime::vault::{CreateOutcome, MemoryOsBackend, OsBackend, OsError, Secret, VaultSet};

struct ExternalBackend {
    value: String,
}

impl OsBackend for ExternalBackend {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<Secret>, OsError> {
        Secret::try_new(self.value.clone())
            .map(Some)
            .map_err(|_| OsError::Failed)
    }

    fn set(&self, _service: &str, _account: &str, _value: &str) -> Result<(), OsError> {
        Ok(())
    }

    fn create_if_absent(
        &self,
        _service: &str,
        _account: &str,
        _value: &str,
    ) -> Result<CreateOutcome, OsError> {
        Err(OsError::Unsupported)
    }
}

#[test]
fn an_external_backend_can_construct_a_secret_without_private_layout() {
    let declaration = VaultDeclaration {
        name: "external".to_owned(),
        provider: VaultProvider::Os(OsVault {
            service: "external-service".to_owned(),
        }),
        source: SourceSpan::new("neoenv.yaml".to_owned(), 1, 1),
    };
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([("external".to_owned(), declaration)]),
        Arc::new(ExternalBackend {
            value: "external-secret".to_owned(),
        }),
    );
    let secret = vaults
        .get("nsv://external/account", &BTreeMap::new())
        .unwrap();
    assert_eq!(secret.expose(), "external-secret");
}

#[test]
fn the_memory_backend_is_usable_as_a_public_embedding_backend() {
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("service", "account", "value");
    assert_eq!(backend.len(), 1);
    assert!(!backend.is_empty());
}
