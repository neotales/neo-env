//! The `age` provider: an identity plus encrypted bootstrap values.
//!
//! Nothing here discovers a key by itself. The identity is either explicit in
//! the declaration, read from the conventional machine path, or resolved from
//! another vault through an `nsv://` reference. That last form is how an age
//! private identity can live only in the operating-system keyring once the `os`
//! provider exists; this module already follows the reference rather than
//! inventing a second path for it.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use neoenv_config::AgeVault;
use neotales_age::{AgeFile, AgeIdentity, parse_identities};

use super::{
    MAX_SECRET_BYTES, REFERENCE_PREFIX, Reference, Secret, VaultError, VaultSet,
    expand_braced_setting, read_secret_file, resolve_setting_path, validate_secret,
};
use crate::paths::{UserDirectory, neoenv_directory};

/// Resolves one age reference.
#[allow(
    clippy::too_many_arguments,
    reason = "provider resolution passes the resolver state explicitly so recursion is visible"
)]
pub(super) fn get(
    set: &VaultSet,
    vault_name: &str,
    vault: &AgeVault,
    base: &Path,
    reference: &Reference,
    environment: &BTreeMap<String, String>,
    visited: &mut Vec<String>,
    depth: usize,
) -> Result<Secret, VaultError> {
    if reference.fragment.is_some() {
        return Err(VaultError::new(
            "NEO708",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: an age reference does not define a field selector"),
        ));
    }

    let identities = identities(set, vault, base, environment, visited, depth)?;
    let ciphertext = reference
        .query
        .value
        .clone()
        .or_else(|| vault.values.get(&reference.path_string()).cloned())
        .ok_or_else(|| {
            VaultError::new(
                "NEO707",
                neoenv_core::DiagnosticCategory::NotFound,
                format!("vault {vault_name}: no age value exists at the referenced path"),
            )
        })?;
    if ciphertext.len() > MAX_SECRET_BYTES {
        return Err(VaultError::new(
            "NEO710",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: age ciphertext is larger than {MAX_SECRET_BYTES} bytes"),
        ));
    }

    let plaintext = if ciphertext.contains("BEGIN AGE ENCRYPTED FILE") {
        AgeFile::decrypt_armored(&ciphertext, &identities)
    } else {
        AgeFile::decrypt(ciphertext.as_bytes(), &identities)
    }
    .map_err(|_| {
        VaultError::new(
            "NEO706",
            neoenv_core::DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: the age identity could not decrypt the value; the \
                 ciphertext or the identity is wrong"
            ),
        )
    })?;
    let plaintext = String::from_utf8(plaintext).map_err(|_| {
        VaultError::new(
            "NEO706",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the decrypted value is not UTF-8 text"),
        )
    })?;
    validate_secret(plaintext, vault_name)
}

fn identities(
    set: &VaultSet,
    vault: &AgeVault,
    base: &Path,
    environment: &BTreeMap<String, String>,
    visited: &mut Vec<String>,
    depth: usize,
) -> Result<Vec<AgeIdentity>, VaultError> {
    let material = match &vault.identity {
        Some(raw) => {
            let expanded = expand_braced_setting(raw, environment)?;
            if expanded.trim().starts_with(REFERENCE_PREFIX) {
                set.get_nested(expanded.trim(), environment, visited, depth)?
                    .to_owned_string()
            } else {
                expanded
            }
        }
        None => default_identity_path()?.display().to_string(),
    };

    let trimmed = material.trim();
    if trimmed.starts_with("AGE-SECRET-KEY-") {
        let identity = AgeIdentity::from_private_key(trimmed).map_err(|_| {
            VaultError::new(
                "NEO706",
                neoenv_core::DiagnosticCategory::Runtime,
                "an inline age identity is not a valid AGE-SECRET-KEY value",
            )
        })?;
        return Ok(vec![identity]);
    }

    let path = resolve_setting_path(&material, base, environment)?;
    let source = read_secret_file(&path)?;
    parse_identities(&source).map_err(|_| {
        VaultError::new(
            "NEO706",
            neoenv_core::DiagnosticCategory::Runtime,
            "the age identity file does not contain a usable identity",
        )
    })
}

fn default_identity_path() -> Result<PathBuf, VaultError> {
    let directory = neoenv_directory(UserDirectory::Config).ok_or_else(|| {
        VaultError::new(
            "NEO706",
            neoenv_core::DiagnosticCategory::Runtime,
            "no user configuration directory is available, so the default age identity \
             cannot be found",
        )
    })?;
    Ok(directory.join("age").join("identity.txt"))
}
