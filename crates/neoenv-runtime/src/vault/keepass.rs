//! The `KeePass` provider: a KDBX document opened with a master password.
//!
//! The master password is the bootstrap value this provider exists to avoid
//! writing down. It may be a literal in a local private overlay, an
//! interpolated value, or an `nsv://` reference to an age `values:` entry.
//! Whichever form it takes, it is never formatted into an error.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use neoenv_config::KeepassVault;
use neoenv_core::DiagnosticCategory;
use neotales_keepass::{
    Comparison, Entry, Field, Group, KdbxFile, KeePassDatabase, PathOptions, ProtectedValue,
};
use sha2::Digest as _;
use tempfile::NamedTempFile;

use super::{
    REFERENCE_PREFIX, Reference, Secret, VaultError, VaultSet, open_secret_file,
    resolve_setting_path, validate_secret,
};

/// Resolves one `KeePass` reference.
#[allow(
    clippy::too_many_arguments,
    reason = "provider resolution passes the resolver state explicitly so recursion is visible"
)]
pub(super) fn get(
    set: &VaultSet,
    vault_name: &str,
    vault: &KeepassVault,
    base: &Path,
    reference: &Reference,
    environment: &BTreeMap<String, String>,
    visited: &mut Vec<String>,
    depth: usize,
) -> Result<Secret, VaultError> {
    if reference.query.value.is_some() {
        return Err(VaultError::new(
            "NEO708",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: an inline value is only valid on an age vault"),
        ));
    }
    let path = resolve_setting_path(&vault.path, base, environment)?;
    let secret = super::expand_braced_setting(&vault.secret, environment)?;
    let secret = if secret.trim().starts_with(REFERENCE_PREFIX) {
        set.get_nested(secret.trim(), environment, visited, depth)?
            .to_owned_string()
    } else {
        secret
    };
    if secret.is_empty() {
        return Err(VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the resolved KeePass master password is empty"),
        ));
    }

    let file = open_secret_file(&path)?;
    let database = KdbxFile::open(file, secret.as_bytes()).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: could not open the KeePass database; the master password \
                 is wrong or the KDBX form is not supported"
            ),
        )
    })?;

    // **Ordinal comparison, not the library's case-insensitive default.** For a
    // secret lookup, `Token` and `token` are two entries, not two spellings of
    // one; folding them would return an entry the reference did not name.
    let options = PathOptions {
        delimiter: '/',
        comparison: Comparison::Ordinal,
    };
    let entry_path = reference.path_string();
    let entry = database
        .find_entry_by_path(&entry_path, options)
        .map_err(|_| {
            VaultError::new(
                "NEO704",
                DiagnosticCategory::Runtime,
                format!("vault {vault_name}: the referenced entry path is not usable"),
            )
        })?
        .ok_or_else(|| {
            VaultError::new(
                "NEO707",
                DiagnosticCategory::NotFound,
                format!("vault {vault_name}: no KeePass entry exists at the referenced path"),
            )
        })?;

    match reference.fragment.as_deref() {
        None | Some("password") => entry
            .password
            .with_revealed_text(std::borrow::ToOwned::to_owned)
            .map_err(|_| {
                VaultError::new(
                    "NEO706",
                    DiagnosticCategory::Runtime,
                    format!("vault {vault_name}: the password field could not be revealed"),
                )
            })
            .and_then(|value| validate_secret(value, vault_name)),
        Some("username") => {
            // `username` is ordinary model text and is not zeroized by the
            // library; the copy into `Secret` is what gives this module one
            // lifetime for the value.
            validate_secret(entry.username.clone(), vault_name)
        }
        Some(_) => Err(VaultError::new(
            "NEO708",
            DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: KeePass does not define that field; use #username or \
                 #password"
            ),
        )),
    }
}

/// The largest KDBX document this provider will rewrite. The library reads with
/// its own limits; this is the write-side allocation bound.
const MAX_KDBX_BYTES: usize = 64 * 1024 * 1024;

fn credentials(
    set: &VaultSet,
    vault: &KeepassVault,
    base: &Path,
    environment: &BTreeMap<String, String>,
    visited: &mut Vec<String>,
    depth: usize,
) -> Result<(PathBuf, String), VaultError> {
    let path = resolve_setting_path(&vault.path, base, environment)?;
    let secret = super::expand_braced_setting(&vault.secret, environment)?;
    let secret = if secret.trim().starts_with(REFERENCE_PREFIX) {
        set.get_nested(secret.trim(), environment, visited, depth)?
            .to_owned_string()
    } else {
        secret
    };
    if secret.is_empty() {
        return Err(VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            "the resolved KeePass master password is empty",
        ));
    }
    Ok((path, secret))
}

fn canonical_database(path: &Path, vault_name: &str) -> Result<PathBuf, VaultError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError::new(
                "NEO707",
                DiagnosticCategory::NotFound,
                format!("vault {vault_name}: the KeePass database was not found"),
            )
        } else {
            VaultError::new(
                "NEO706",
                DiagnosticCategory::Runtime,
                format!("vault {vault_name}: the KeePass database could not be resolved"),
            )
        }
    })?;
    if !canonical.is_file() {
        return Err(VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the KeePass database is not a regular file"),
        ));
    }
    Ok(canonical)
}

fn open_database(
    path: &Path,
    master: &str,
    vault_name: &str,
) -> Result<KeePassDatabase, VaultError> {
    let file = open_secret_file(path)?;
    KdbxFile::open(file, master.as_bytes()).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: could not open the KeePass database; the master password \
                 is wrong or the KDBX form is not supported"
            ),
        )
    })
}

fn entry_options() -> PathOptions {
    PathOptions {
        delimiter: '/',
        comparison: Comparison::Ordinal,
    }
}

fn field_value(
    entry: &Entry,
    fragment: Option<&str>,
    vault_name: &str,
) -> Result<Secret, VaultError> {
    match fragment {
        None | Some("password") => entry
            .password
            .with_revealed_text(std::borrow::ToOwned::to_owned)
            .map_err(|_| {
                VaultError::new(
                    "NEO706",
                    DiagnosticCategory::Runtime,
                    format!("vault {vault_name}: the password field could not be revealed"),
                )
            })
            .and_then(|value| validate_secret(value, vault_name)),
        Some("username") => validate_secret(entry.username.clone(), vault_name),
        Some(_) => Err(VaultError::new(
            "NEO708",
            DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: KeePass does not define that field; use #username or \
                 #password"
            ),
        )),
    }
}

fn mutable_path<'a>(root_name: &str, segments: &'a [&'a str]) -> Vec<&'a str> {
    let mut segments = segments.to_vec();
    if segments.len() > 1 && segments[0] == root_name {
        segments.remove(0);
    }
    segments
}

fn same_name(comparison: Comparison, left: &str, right: &str) -> bool {
    match comparison {
        Comparison::Ordinal => left == right,
        Comparison::CaseInsensitive => left.eq_ignore_ascii_case(right),
    }
}

fn find_group_mut<'a>(
    group: &'a mut Group,
    segments: &[&str],
    options: PathOptions,
) -> Option<&'a mut Group> {
    let Some((first, rest)) = segments.split_first() else {
        return Some(group);
    };
    let child = group
        .groups
        .iter_mut()
        .find(|child| same_name(options.comparison, &child.name, first))?;
    find_group_mut(child, rest, options)
}

fn find_entry_mut<'a>(
    group: &'a mut Group,
    segments: &[&str],
    options: PathOptions,
) -> Option<&'a mut Entry> {
    let (first, rest) = segments.split_first()?;
    if rest.is_empty() {
        return group
            .entries
            .iter_mut()
            .find(|entry| same_name(options.comparison, &entry.title, first));
    }
    let child = group
        .groups
        .iter_mut()
        .find(|child| same_name(options.comparison, &child.name, first))?;
    find_entry_mut(child, rest, options)
}

fn parent_group_mut<'a>(
    database: &'a mut KeePassDatabase,
    segments: &[&str],
    options: PathOptions,
) -> Option<&'a mut Group> {
    let root_name = database.root.name.clone();
    let parent = &segments[..segments.len().saturating_sub(1)];
    let relative = mutable_path(&root_name, parent);
    find_group_mut(&mut database.root, &relative, options)
}

fn set_field(entry: &mut Entry, fragment: Option<&str>, value: &str) -> Result<(), VaultError> {
    match fragment {
        None | Some("password") => {
            let protected = ProtectedValue::from_text(value.to_owned());
            entry.password = protected.clone();
            // A loaded KDBX keeps the standard fields in `fields` as well as the
            // convenience accessors. The writer emits `fields` when a field of
            // that name exists, so updating only `entry.password` would leave the
            // old value on disk.
            if let Some(field) = entry
                .fields
                .iter_mut()
                .find(|field| field.key == "Password")
            {
                field.value = protected;
            } else {
                entry.set_field(Field {
                    key: "Password".to_owned(),
                    value: protected,
                    protected: true,
                    protect_in_memory: false,
                });
            }
            Ok(())
        }
        Some("username") => {
            entry.username.clear();
            entry.username.push_str(value);
            if let Some(field) = entry
                .fields
                .iter_mut()
                .find(|field| field.key == "UserName")
            {
                field.value = ProtectedValue::from_text(value.to_owned());
            } else {
                entry.set_field(Field::new("UserName", value.to_owned()));
            }
            Ok(())
        }
        Some(_) => Err(VaultError::new(
            "NEO708",
            DiagnosticCategory::Runtime,
            "KeePass does not define that field; use #username or #password",
        )),
    }
}

fn save_bytes(
    database: &KeePassDatabase,
    master: &str,
    vault_name: &str,
) -> Result<Vec<u8>, VaultError> {
    let mut bytes = Vec::new();
    KdbxFile::save_default(database, &mut bytes, master).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the KeePass database could not be saved"),
        )
    })?;
    if bytes.len() > MAX_KDBX_BYTES {
        return Err(VaultError::new(
            "NEO710",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: updated KeePass database is too large"),
        ));
    }
    Ok(bytes)
}

fn publish_database(
    path: &Path,
    bytes: &[u8],
    expected: [u8; 32],
    vault_name: &str,
) -> Result<(), VaultError> {
    let parent = path.parent().ok_or_else(|| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the KeePass database has no parent directory"),
        )
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: could not prepare the KeePass database update"),
        )
    })?;
    if let Ok(metadata) = fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())
            .map_err(|_| {
                VaultError::new(
                    "NEO706",
                    DiagnosticCategory::Runtime,
                    format!("vault {vault_name}: could not preserve KeePass file permissions"),
                )
            })?;
    }
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| {
            VaultError::new(
                "NEO706",
                DiagnosticCategory::Runtime,
                format!("vault {vault_name}: could not write the KeePass database update"),
            )
        })?;
    if source_fingerprint(path, vault_name)? != expected {
        return Err(VaultError::new(
            "NEO712",
            DiagnosticCategory::Runtime,
            format!(
                "vault {vault_name}: KeePass database changed during update; refusing to overwrite it"
            ),
        ));
    }
    temporary.persist(path).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: could not publish the KeePass database update"),
        )
    })?;
    Ok(())
}

fn lock_resource(canonical: &Path) -> String {
    format!("keepass\0{}", canonical.display())
}

fn source_fingerprint(path: &Path, vault_name: &str) -> Result<[u8; 32], VaultError> {
    let source = fs::read(path).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: the KeePass database changed or became unreadable"),
        )
    })?;
    Ok(sha2::Sha256::digest(source).into())
}

fn publish_if_unchanged(
    path: &Path,
    bytes: &[u8],
    expected: [u8; 32],
    vault_name: &str,
) -> Result<(), VaultError> {
    // Revalidate immediately before replacement. This cannot close the final
    // compare/rename race with applications outside the neoenv lock.
    publish_database(path, bytes, expected, vault_name)
}

/// Adds a generated value to an existing `KeePass` database.
#[allow(
    clippy::too_many_arguments,
    reason = "provider mutation passes resolver state and lock root explicitly"
)]
pub(super) fn ensure(
    set: &VaultSet,
    lock_root: &Path,
    vault_name: &str,
    vault: &KeepassVault,
    base: &Path,
    reference: &Reference,
    environment: &BTreeMap<String, String>,
    candidate: Secret,
    visited: &mut Vec<String>,
    depth: usize,
) -> Result<Secret, VaultError> {
    if reference.fragment.is_some() {
        return Err(VaultError::new(
            "NEO708",
            DiagnosticCategory::Runtime,
            format!("vault {vault_name}: ensure cannot create a named field"),
        ));
    }
    let (path, master) = credentials(set, vault, base, environment, visited, depth)?;
    let canonical = canonical_database(&path, vault_name)?;
    let resource = lock_resource(&canonical);
    super::lock::with_mutation_lock(lock_root, resource.as_bytes(), || {
        // Fresh read under the lock. Existing data always wins.
        let fingerprint = source_fingerprint(&canonical, vault_name)?;
        let mut database = open_database(&canonical, &master, vault_name)?;
        let options = entry_options();
        let entry_path = reference.path_string();
        if let Some(entry) = database
            .find_entry_by_path(&entry_path, options)
            .map_err(|_| {
                VaultError::new(
                    "NEO704",
                    DiagnosticCategory::Runtime,
                    format!("vault {vault_name}: the referenced entry path is not usable"),
                )
            })?
        {
            return field_value(entry, None, vault_name);
        }
        let title = reference
            .path
            .last()
            .ok_or_else(|| {
                VaultError::new(
                    "NEO704",
                    DiagnosticCategory::Runtime,
                    format!("vault {vault_name}: the referenced entry path is empty"),
                )
            })?
            .clone();
        let segments: Vec<&str> = reference.path.iter().map(String::as_str).collect();
        let group = parent_group_mut(&mut database, &segments, options).ok_or_else(|| {
            VaultError::new(
                "NEO707",
                DiagnosticCategory::NotFound,
                format!("vault {vault_name}: the parent KeePass group does not exist"),
            )
        })?;
        let mut entry = Entry::new(title);
        entry.password = ProtectedValue::from_text(candidate.expose().to_owned());
        group.add_entry(entry);
        let bytes = save_bytes(&database, &master, vault_name)?;
        publish_if_unchanged(&canonical, &bytes, fingerprint, vault_name)?;
        Ok(candidate)
    })
}

/// Writes one password/username field in an existing `KeePass` database.
#[allow(
    clippy::too_many_arguments,
    reason = "provider mutation passes resolver state and lock root explicitly"
)]
pub(super) fn set(
    set: &VaultSet,
    lock_root: &Path,
    vault_name: &str,
    vault: &KeepassVault,
    base: &Path,
    reference: &Reference,
    environment: &BTreeMap<String, String>,
    value: &str,
) -> Result<(), VaultError> {
    let (path, master) = credentials(set, vault, base, environment, &mut Vec::new(), 0)?;
    let canonical = canonical_database(&path, vault_name)?;
    let resource = lock_resource(&canonical);
    super::lock::with_mutation_lock(lock_root, resource.as_bytes(), || {
        let fingerprint = source_fingerprint(&canonical, vault_name)?;
        let mut database = open_database(&canonical, &master, vault_name)?;
        let options = entry_options();
        let segments: Vec<&str> = reference.path.iter().map(String::as_str).collect();
        let title = reference.path.last().ok_or_else(|| {
            VaultError::new(
                "NEO704",
                DiagnosticCategory::Runtime,
                format!("vault {vault_name}: the referenced entry path is empty"),
            )
        })?;
        let root_name = database.root.name.clone();
        let relative = mutable_path(&root_name, &segments);
        if let Some(entry) = find_entry_mut(&mut database.root, &relative, options) {
            set_field(entry, reference.fragment.as_deref(), value)?;
        } else {
            let group = parent_group_mut(&mut database, &segments, options).ok_or_else(|| {
                VaultError::new(
                    "NEO707",
                    DiagnosticCategory::NotFound,
                    format!("vault {vault_name}: the parent KeePass group does not exist"),
                )
            })?;
            let mut entry = Entry::new(title.clone());
            entry.password = ProtectedValue::from_text(String::new());
            set_field(&mut entry, reference.fragment.as_deref(), value)?;
            group.add_entry(entry);
        }
        let bytes = save_bytes(&database, &master, vault_name)?;
        publish_if_unchanged(&canonical, &bytes, fingerprint, vault_name)
    })
}

#[cfg(test)]
mod conflict_tests {
    use super::{publish_if_unchanged, source_fingerprint};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn intervening_external_change_is_preserved_and_rejected() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("test.kdbx");
        fs::write(&path, b"snapshot").unwrap();
        let fingerprint = source_fingerprint(&path, "test").unwrap();
        fs::write(&path, b"external edit").unwrap();
        let result = publish_if_unchanged(&path, b"neoenv update", fingerprint, "test");
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"external edit");
    }
}
