//! Tests for reference resolution, using real age and KDBX fixtures.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
    sync::Arc,
};

use indexmap::{IndexMap, indexmap};
use neoenv_config::{AgeVault, KeepassVault, OsVault, VaultDeclaration, VaultProvider};
use neoenv_core::SourceSpan;
use neotales_age::{AgeFile, AgeKey, AgeRecipient};
use neotales_keepass::{Entry, Group, KdbxFile, KeePassDatabase, ProtectedValue};
use tempfile::TempDir;

use super::{
    MAX_SECRET_BYTES, MemoryOsBackend, VaultSet,
    os::{CreateOutcome, OsBackend, OsError},
    reference::Reference,
};

fn declaration(name: &str, provider: VaultProvider, config: &Path) -> (String, VaultDeclaration) {
    (
        name.to_owned(),
        VaultDeclaration {
            name: name.to_owned(),
            provider,
            source: SourceSpan::new(config.display().to_string(), 1, 1),
        },
    )
}

fn age_identity(directory: &Path) -> (String, String) {
    let key = AgeKey::generate().unwrap();
    let identity_path = directory.join("identity.txt");
    fs::write(&identity_path, format!("{}\n", key.private_key)).unwrap();
    (identity_path.display().to_string(), key.public_key)
}

fn encrypt(recipient: &str, plaintext: &str) -> String {
    let recipient = AgeRecipient::from_public_key(recipient).unwrap();
    AgeFile::encrypt_armored(plaintext.as_bytes(), &[recipient]).unwrap()
}

fn write_kdbx(path: &Path, password: &str, entries: &[(&str, &str, &str)]) {
    let mut database = KeePassDatabase::default();
    let group = database.root.add_group(Group::new("work"));
    for (title, username, password) in entries {
        let mut entry = Entry::new(*title);
        entry.username = (*username).to_owned();
        entry.password = ProtectedValue::from_text(*password);
        group.add_entry(entry);
    }
    let mut bytes = Vec::new();
    KdbxFile::save_default(&database, &mut bytes, password).unwrap();
    fs::write(path, bytes).unwrap();
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            output.push(char::from(byte));
        } else {
            write!(output, "%{byte:02X}").unwrap();
        }
    }
    output
}

#[test]
fn age_values_resolve_from_an_identity_file() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: indexmap! {
                "database".to_owned() => encrypt(&recipient, "database-secret"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let secret = vaults
        .get("nsv://machine/database", &BTreeMap::new())
        .unwrap();
    assert_eq!(secret.expose(), "database-secret");
}

#[test]
fn an_age_inline_value_is_percent_decoded_and_decrypted() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let ciphertext = encrypt(&recipient, "inline-secret");
    let reference = format!("nsv://machine/inline?value={}", percent_encode(&ciphertext));
    let secret = vaults.get(&reference, &BTreeMap::new()).unwrap();
    assert_eq!(secret.expose(), "inline-secret");
}

#[test]
fn a_keepass_entry_password_and_username_resolve() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "master-password",
        &[("database", "service-account", "entry-secret")],
    );
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let password = vaults
        .get("nsv://work/work/database", &BTreeMap::new())
        .unwrap();
    assert_eq!(password.expose(), "entry-secret");
    let username = vaults
        .get("nsv://work/work/database#username", &BTreeMap::new())
        .unwrap();
    assert_eq!(username.expose(), "service-account");
}

#[test]
fn a_keepass_master_password_can_be_an_age_value() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "bootstrapped-master",
        &[("database", "service-account", "entry-secret")],
    );
    let machine = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: indexmap! {
                "keepass-master".to_owned() => encrypt(&recipient, "bootstrapped-master"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let work = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "nsv://machine/keepass-master".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([machine, work]));
    let secret = vaults
        .get("nsv://work/work/database", &BTreeMap::new())
        .unwrap();
    assert_eq!(secret.expose(), "entry-secret");
}

#[test]
fn a_keepass_path_is_ordinal_and_does_not_fold_case() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "master-password",
        &[("Token", "u", "entry-secret")],
    );
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/work/token", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO707");
}

#[test]
fn age_ensure_is_refused() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://machine/new?ensure=true&size=16", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO708");
    assert!(error.message().contains("not supported for age"));
}

#[test]
fn keepass_ensure_bootstrap_cycle_is_bounded() {
    let directory = TempDir::new().unwrap();
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: directory.path().join("missing.kdbx").display().to_string(),
            secret: "nsv://work/entry?ensure=true".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/entry?ensure=true", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO709");
}

#[test]
fn a_reference_inside_a_larger_value_is_refused() {
    let vaults = VaultSet::empty();
    let error = vaults
        .resolve_value("prefix-nsv://machine/token", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO708");
}

#[test]
fn a_missing_vault_lists_the_declared_names_only() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/token", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO705");
    assert!(error.message().contains("machine"));
}

#[test]
fn a_provider_cycle_is_detected_without_opening_a_file() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("neoenv.yaml");
    let a = declaration(
        "a",
        VaultProvider::Keepass(KeepassVault {
            path: directory.path().join("a.kdbx").display().to_string(),
            secret: "nsv://b/x".to_owned(),
        }),
        &config,
    );
    let b = declaration(
        "b",
        VaultProvider::Keepass(KeepassVault {
            path: directory.path().join("b.kdbx").display().to_string(),
            secret: "nsv://a/x".to_owned(),
        }),
        &config,
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([a, b]));
    let error = vaults.get("nsv://a/x", &BTreeMap::new()).unwrap_err();
    assert_eq!(error.code(), "NEO709");
}

#[test]
fn a_wrong_password_does_not_leak_the_password_or_the_plaintext() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "right-password",
        &[("database", "u", "entry-secret")],
    );
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "wrong-password-sentinel".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/work/database", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO706");
    assert!(!error.message().contains("wrong-password-sentinel"));
    assert!(!error.message().contains("entry-secret"));
}

#[test]
fn a_whole_reference_resolves_in_an_ordered_environment() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: indexmap! {
                "token".to_owned() => encrypt(&recipient, "resolved-token"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let mut environment = IndexMap::from([
        ("PROJECT".to_owned(), "project".to_owned()),
        ("TOKEN".to_owned(), "nsv://machine/token".to_owned()),
        ("PLAIN".to_owned(), "plain".to_owned()),
    ]);
    let scope: BTreeSet<String> = environment.keys().cloned().collect();
    let context: BTreeMap<String, String> = environment
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    vaults
        .resolve_ordered_environment(&mut environment, &scope, &context)
        .unwrap();
    assert_eq!(environment["PROJECT"], "project");
    assert_eq!(environment["TOKEN"], "resolved-token");
    assert_eq!(environment["PLAIN"], "plain");
}

#[test]
fn a_reference_interpolates_from_the_environment_in_effect() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: indexmap! {
                "token".to_owned() => encrypt(&recipient, "resolved-token"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let environment = BTreeMap::from([("VAULT".to_owned(), "machine".to_owned())]);
    let secret = vaults.get("nsv://${VAULT}/token", &environment).unwrap();
    assert_eq!(secret.expose(), "resolved-token");
}

#[test]
fn a_reference_debug_does_not_expose_the_path_or_the_value() {
    let reference =
        Reference::parse("nsv://work/secret/entry?value=aGVsbG8=", &BTreeMap::new()).unwrap();
    let debug = format!("{reference:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("aGVsbG8="));
}

#[test]
fn an_age_identity_can_be_fetched_from_another_vault() {
    // This is the shape an OS-keyring identity will take: the identity material
    // is a value in another vault, resolved lazily through the same reference
    // path, not through a second side door.
    let directory = TempDir::new().unwrap();
    let (source_identity, source_recipient) = age_identity(directory.path());
    let target = AgeKey::generate().unwrap();
    let target_recipient = AgeRecipient::from_public_key(&target.public_key).unwrap();
    let target_token = AgeFile::encrypt_armored(b"token-secret", &[target_recipient]).unwrap();

    let source = declaration(
        "identity-source",
        VaultProvider::Age(AgeVault {
            identity: Some(source_identity),
            values: indexmap! {
                "age-identity".to_owned() => encrypt(&source_recipient, &target.private_key),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let machine = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some("nsv://identity-source/age-identity".to_owned()),
            values: indexmap! {
                "token".to_owned() => target_token,
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([source, machine]));
    let secret = vaults.get("nsv://machine/token", &BTreeMap::new()).unwrap();
    assert_eq!(secret.expose(), "token-secret");
}

#[test]
fn an_age_identity_that_points_back_at_its_own_vault_is_a_cycle() {
    let directory = TempDir::new().unwrap();
    let (_identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some("nsv://machine/identity".to_owned()),
            values: indexmap! {
                "identity".to_owned() => encrypt(&recipient, "unused"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://machine/identity", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO709");
}

#[test]
fn a_keepass_master_password_keeps_a_literal_dollar() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(&database, "pa$word", &[("database", "u", "entry-secret")]);
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "pa$word".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    // `word` is deliberately set: bare `$word` must not be expanded in a secret.
    let environment = BTreeMap::from([("word".to_owned(), "WRONG".to_owned())]);
    let secret = vaults
        .get("nsv://work/work/database", &environment)
        .unwrap();
    assert_eq!(secret.expose(), "entry-secret");
}

#[test]
fn an_inline_value_is_refused_on_a_keepass_vault() {
    let directory = TempDir::new().unwrap();
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: directory.path().join("secrets.kdbx").display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/entry?value=ciphertext", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO708");
}

#[test]
fn a_diagnostic_never_echoes_an_interpolated_query_key() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let environment = BTreeMap::from([(
        "SECRET_QUERY_KEY".to_owned(),
        "query-key-sentinel".to_owned(),
    )]);
    let error = vaults
        .get("nsv://machine/token?${SECRET_QUERY_KEY}=1", &environment)
        .unwrap_err();
    assert!(!error.message().contains("query-key-sentinel"));
    assert!(!error.message().contains("SECRET_QUERY_KEY"));
}

#[test]
fn a_missing_identity_file_does_not_echo_its_path() {
    let directory = TempDir::new().unwrap();
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some("identity-path-sentinel.txt".to_owned()),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://machine/token", &BTreeMap::new())
        .unwrap_err();
    assert!(!error.message().contains("identity-path-sentinel"));
}

#[test]
fn a_missing_entry_diagnostic_does_not_echo_the_provider_path() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(&database, "master-password", &[("present", "u", "v")]);
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://work/work/absent-entry", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO707");
    assert!(!error.message().contains("absent-entry"));
    assert!(!error.message().contains("secrets.kdbx"));
}

#[test]
fn a_missing_age_value_does_not_echo_the_provider_path() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let error = vaults
        .get("nsv://machine/missing-value-path", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO707");
    assert!(!error.message().contains("missing-value-path"));
}

#[test]
fn only_scope_keys_are_resolved_and_an_out_of_scope_value_is_not_scanned() {
    let directory = TempDir::new().unwrap();
    let (identity, recipient) = age_identity(directory.path());
    let declaration = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: indexmap! {
                "token".to_owned() => encrypt(&recipient, "resolved-token"),
            },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]));
    let mut environment = BTreeMap::from([
        ("TOKEN".to_owned(), "nsv://machine/token".to_owned()),
        // This looks like a reference, but it is not in the declared scope. It is
        // inherited, so it is available for an explicit `${INHERITED}` lookup but
        // is never itself scanned or resolved.
        ("INHERITED".to_owned(), "nsv://machine/absent".to_owned()),
    ]);
    let scope = BTreeSet::from(["TOKEN".to_owned()]);
    let context = environment.clone();
    vaults
        .resolve_environment(&mut environment, &scope, &context)
        .unwrap();
    assert_eq!(environment["TOKEN"], "resolved-token");
    assert_eq!(environment["INHERITED"], "nsv://machine/absent");
}

fn os_declaration(name: &str, service: &str, config: &Path) -> (String, VaultDeclaration) {
    declaration(
        name,
        VaultProvider::Os(OsVault {
            service: service.to_owned(),
        }),
        config,
    )
}

#[test]
fn an_os_vault_reads_and_writes_through_the_injected_backend() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("svc", "account", "stored-secret");
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend,
    );
    let secret = vaults.get("nsv://login/account", &BTreeMap::new()).unwrap();
    assert_eq!(secret.expose(), "stored-secret");

    vaults
        .set_secret("nsv://login/account", "replaced-secret", &BTreeMap::new())
        .unwrap();
    let secret = vaults.get("nsv://login/account", &BTreeMap::new()).unwrap();
    assert_eq!(secret.expose(), "replaced-secret");
}

#[test]
fn an_age_identity_can_come_from_the_os_backend() {
    let directory = TempDir::new().unwrap();
    let key = AgeKey::generate().unwrap();
    let recipient = AgeRecipient::from_public_key(&key.public_key).unwrap();
    let token = AgeFile::encrypt_armored(b"token-secret", &[recipient]).unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("svc", "age-identity", key.private_key.clone());

    let os = os_declaration("login", "svc", &directory.path().join("neoenv.yaml"));
    let machine = declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some("nsv://login/age-identity".to_owned()),
            values: indexmap! { "token".to_owned() => token },
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations_with_backend(IndexMap::from([os, machine]), backend);
    let secret = vaults.get("nsv://machine/token", &BTreeMap::new()).unwrap();
    assert_eq!(secret.expose(), "token-secret");
}

#[test]
fn ensure_creates_a_secure_random_value_only_when_absent() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend.clone(),
    );
    let first = vaults
        .get(
            "nsv://login/new?ensure=true&size=24&upper=false",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(first.expose().len(), 24);
    assert!(
        first
            .expose()
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    );
    assert_eq!(backend.len(), 1);

    let second = vaults
        .get(
            "nsv://login/new?ensure=true&size=24&upper=false",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(first.expose(), second.expose());
    assert_eq!(backend.len(), 1);
}

#[test]
fn ensure_does_not_overwrite_an_existing_value() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("svc", "existing", "keep-me");
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend,
    );
    let secret = vaults
        .get("nsv://login/existing?ensure=true&size=8", &BTreeMap::new())
        .unwrap();
    assert_eq!(secret.expose(), "keep-me");
}

struct NonAtomicBackend {
    inner: MemoryOsBackend,
}

impl OsBackend for NonAtomicBackend {
    fn get(&self, service: &str, account: &str) -> Result<Option<super::Secret>, OsError> {
        self.inner.get(service, account)
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), OsError> {
        self.inner.set(service, account, value)
    }
}

#[test]
fn cooperative_ensure_works_without_an_atomic_backend_operation() {
    let directory = TempDir::new().unwrap();
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        Arc::new(NonAtomicBackend {
            inner: MemoryOsBackend::new(),
        }),
    );
    let secret = vaults
        .get("nsv://login/new?ensure=true&size=8", &BTreeMap::new())
        .unwrap();
    assert_eq!(secret.expose().len(), 8);
}

#[test]
fn ensure_is_refused_for_a_read_only_provider() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    )]));
    let error = vaults
        .get("nsv://machine/new?ensure=true&size=8", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO708");
}

#[test]
fn set_secret_refuses_a_read_only_provider_and_resolution_options() {
    let directory = TempDir::new().unwrap();
    let (identity, _recipient) = age_identity(directory.path());
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration(
        "machine",
        VaultProvider::Age(AgeVault {
            identity: Some(identity),
            values: IndexMap::new(),
        }),
        &directory.path().join("neoenv.yaml"),
    )]));
    let read_only = vaults
        .set_secret("nsv://machine/value", "new", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(read_only.code(), "NEO708");

    let backend = Arc::new(MemoryOsBackend::new());
    let os_vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend,
    );
    let option = os_vaults
        .set_secret("nsv://login/value?ensure=true", "new", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(option.code(), "NEO708");
}

struct FailingBackend;

impl OsBackend for FailingBackend {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<super::Secret>, OsError> {
        Err(OsError::Denied)
    }

    fn set(&self, _service: &str, _account: &str, _value: &str) -> Result<(), OsError> {
        Err(OsError::Denied)
    }

    fn create_if_absent(
        &self,
        _service: &str,
        _account: &str,
        _value: &str,
    ) -> Result<CreateOutcome, OsError> {
        Err(OsError::Denied)
    }
}

#[test]
fn an_os_backend_error_does_not_echo_the_account_or_service() {
    let directory = TempDir::new().unwrap();
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "service-sentinel",
            &directory.path().join("neoenv.yaml"),
        )]),
        Arc::new(FailingBackend),
    );
    let error = vaults
        .get("nsv://login/account-sentinel", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO706");
    assert!(!error.message().contains("service-sentinel"));
    assert!(!error.message().contains("account-sentinel"));
}

#[test]
fn set_secret_preserves_exact_bytes_and_applies_the_read_policy() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend.clone(),
    );
    vaults
        .set_secret(
            "nsv://login/account",
            "line one\nline two\n",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(
        vaults
            .get("nsv://login/account", &BTreeMap::new())
            .unwrap()
            .expose(),
        "line one\nline two\n"
    );

    let nul = vaults
        .set_secret("nsv://login/nul", "a\0b", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(nul.code(), "NEO710");
    assert_eq!(backend.len(), 1, "a rejected value must not be written");

    let oversized = "x".repeat(MAX_SECRET_BYTES + 1);
    let too_big = vaults
        .set_secret("nsv://login/large", &oversized, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(too_big.code(), "NEO710");
    assert_eq!(backend.len(), 1, "an oversized value must not be written");
}

#[test]
fn os_get_rejects_an_invalid_backend_value() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("svc", "nul", "a\0b");
    backend.insert("svc", "large", "x".repeat(MAX_SECRET_BYTES + 1));
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend,
    );
    for account in ["nul", "large"] {
        let error = vaults
            .get(&format!("nsv://login/{account}"), &BTreeMap::new())
            .unwrap_err();
        assert_eq!(error.code(), "NEO710");
    }
}

#[test]
fn set_secret_refuses_ensure_false_by_option_presence() {
    let directory = TempDir::new().unwrap();
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        Arc::new(MemoryOsBackend::new()),
    );
    let error = vaults
        .set_secret(
            "nsv://login/account?ensure=false",
            "value",
            &BTreeMap::new(),
        )
        .unwrap_err();
    assert_eq!(error.code(), "NEO708");
    assert!(error.message().contains("plain reference"));
}

#[cfg(windows)]
#[test]
fn windows_mutations_fail_closed_without_a_safe_cross_process_lock() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    let declaration = declaration(
        "login",
        VaultProvider::Os(OsVault {
            service: "test-service".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations_with_backend_and_lock_root(
        IndexMap::from([declaration]),
        backend.clone(),
        Some(directory.path().join("locks")),
    );
    let ensure = vaults
        .get("nsv://login/account?ensure=true&size=8", &BTreeMap::new())
        .unwrap_err();
    assert!(ensure.message().contains("unsupported on this platform"));
    let set = vaults
        .set_secret("nsv://login/account", "test-value", &BTreeMap::new())
        .unwrap_err();
    assert!(set.message().contains("unsupported on this platform"));
    assert!(backend.is_empty());
}

#[test]
fn ensure_validates_an_existing_backend_value_without_overwriting_it() {
    let directory = TempDir::new().unwrap();
    let backend = Arc::new(MemoryOsBackend::new());
    backend.insert("svc", "corrupt", "a\0b");
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        backend.clone(),
    );
    let error = vaults
        .get("nsv://login/corrupt?ensure=true&size=8", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO710");
    assert_eq!(backend.len(), 1);
    assert_eq!(
        vaults
            .get("nsv://login/corrupt", &BTreeMap::new())
            .unwrap_err()
            .code(),
        "NEO710"
    );
}

struct BadCreateBackend;

impl OsBackend for BadCreateBackend {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<super::Secret>, OsError> {
        Ok(Some(super::Secret::new("a\0b".to_owned())))
    }

    fn set(&self, _service: &str, _account: &str, _value: &str) -> Result<(), OsError> {
        Err(OsError::Denied)
    }

    fn create_if_absent(
        &self,
        _service: &str,
        _account: &str,
        _value: &str,
    ) -> Result<CreateOutcome, OsError> {
        Ok(CreateOutcome::Created(super::Secret::new(
            "a\0b".to_owned(),
        )))
    }
}

#[test]
fn an_invalid_existing_value_is_rejected() {
    let directory = TempDir::new().unwrap();
    let vaults = VaultSet::from_declarations_with_backend(
        IndexMap::from([os_declaration(
            "login",
            "svc",
            &directory.path().join("neoenv.yaml"),
        )]),
        Arc::new(BadCreateBackend),
    );
    let error = vaults
        .get("nsv://login/new?ensure=true&size=8", &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code(), "NEO710");
}

fn keepass_vault(directory: &TempDir, database: &Path) -> VaultSet {
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    VaultSet::from_declarations(IndexMap::from([declaration]))
        .with_lock_root(directory.path().join("locks"))
}

#[test]
fn keepass_ensure_creates_a_missing_entry_and_preserves_the_database() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "master-password",
        &[("existing", "u", "existing-secret")],
    );
    let vaults = keepass_vault(&directory, &database);

    let created = vaults
        .get("nsv://work/work/new?ensure=true&size=12", &BTreeMap::new())
        .unwrap();
    assert_eq!(created.expose().len(), 12);
    let read = vaults.get("nsv://work/work/new", &BTreeMap::new()).unwrap();
    assert_eq!(created.expose(), read.expose());
    assert_eq!(
        vaults
            .get("nsv://work/work/existing", &BTreeMap::new())
            .unwrap()
            .expose(),
        "existing-secret"
    );
}

#[test]
fn keepass_ensure_keeps_an_existing_entry_without_rewriting_the_file() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "master-password",
        &[("existing", "u", "keep-me")],
    );
    let before = fs::read(&database).unwrap();
    let vaults = keepass_vault(&directory, &database);
    let secret = vaults
        .get(
            "nsv://work/work/existing?ensure=true&size=12",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(secret.expose(), "keep-me");
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[test]
fn keepass_set_updates_a_password_and_a_username() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(
        &database,
        "master-password",
        &[("entry", "old-user", "old-pass")],
    );
    let vaults = keepass_vault(&directory, &database);
    vaults
        .set_secret("nsv://work/work/entry", "new-pass", &BTreeMap::new())
        .unwrap();
    {
        use std::fs::File;
        let db =
            neotales_keepass::KdbxFile::open(File::open(&database).unwrap(), b"master-password")
                .unwrap();
        for group in &db.root.groups {
            for entry in &group.entries {
                eprintln!(
                    "DEBUG entry {} pass={:?}",
                    entry.title,
                    entry.password.reveal_text().unwrap().as_str()
                );
            }
        }
    }
    assert_eq!(
        vaults
            .get("nsv://work/work/entry", &BTreeMap::new())
            .unwrap()
            .expose(),
        "new-pass"
    );
    vaults
        .set_secret(
            "nsv://work/work/entry#username",
            "new-user",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(
        vaults
            .get("nsv://work/work/entry#username", &BTreeMap::new())
            .unwrap()
            .expose(),
        "new-user"
    );
}

#[test]
fn keepass_set_creates_an_entry_in_an_existing_group() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("secrets.kdbx");
    write_kdbx(&database, "master-password", &[("existing", "u", "v")]);
    let vaults = keepass_vault(&directory, &database);
    vaults
        .set_secret("nsv://work/work/new", "new-secret", &BTreeMap::new())
        .unwrap();
    assert_eq!(
        vaults
            .get("nsv://work/work/new", &BTreeMap::new())
            .unwrap()
            .expose(),
        "new-secret"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_keepass_publish_leaves_the_original_database_unchanged() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TempDir::new().unwrap();
    let database_dir = directory.path().join("database");
    fs::create_dir(&database_dir).unwrap();
    let database = database_dir.join("secrets.kdbx");
    write_kdbx(&database, "master-password", &[("existing", "u", "v")]);
    let before = fs::read(&database).unwrap();
    let declaration = declaration(
        "work",
        VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        &directory.path().join("neoenv.yaml"),
    );
    let vaults = VaultSet::from_declarations(IndexMap::from([declaration]))
        .with_lock_root(directory.path().join("locks"));

    fs::set_permissions(&database_dir, fs::Permissions::from_mode(0o555)).unwrap();
    let result = vaults.get("nsv://work/work/new?ensure=true&size=8", &BTreeMap::new());
    fs::set_permissions(&database_dir, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(result.is_err(), "a read-only database directory must fail");
    assert_eq!(fs::read(&database).unwrap(), before);
}
