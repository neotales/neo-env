//! The operating-system credential store provider.
//!
//! The backend is an injected trait so the vault can be exercised without
//! reading or writing a real keychain. [`PlatformOsBackend`] is the production
//! adapter; [`MemoryOsBackend`] is deliberately in-memory and is what the tests
//! and embedded callers use.
//!
//! **`create_if_absent` is a capability, not a promise.** The platform keyring
//! API this slice links has read and overwrite operations but no atomic
//! create-if-absent operation. [`PlatformOsBackend`] therefore returns
//! `Unsupported` for atomic create-if-absent; the in-memory backend implements the
//! operation atomically under its mutex. A future file or service backend may
//! implement it too. The resolver never claims atomicity the backend did not
//! provide.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use zeroize::Zeroizing;

use super::{Secret, VaultError};

/// A failure from an OS credential backend. It contains no account, service,
/// or secret value, so it is safe to render at the CLI boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsError {
    /// The platform store or its session is unavailable.
    Unavailable,
    /// The store refused access.
    Denied,
    /// The backend does not implement this operation.
    Unsupported,
    /// The service/account pair cannot be encoded into a safe store target.
    InvalidCoordinate,
    /// The backend failed for another reason.
    Failed,
}

impl fmt::Display for OsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the operating-system credential store is unavailable",
            Self::Denied => "the operating-system credential store refused access",
            Self::Unsupported => {
                "the operating-system credential store does not support this operation"
            }
            Self::InvalidCoordinate => "the credential coordinates cannot be encoded safely",
            Self::Failed => "the operating-system credential store failed",
        })
    }
}

impl std::error::Error for OsError {}

/// What an atomic create returned.
pub enum CreateOutcome {
    /// The value did not exist and was stored.
    Created(Secret),
    /// The value already existed and was not overwritten.
    Existing(Secret),
}

impl fmt::Debug for CreateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Created(_) => "CreateOutcome::Created([redacted])",
            Self::Existing(_) => "CreateOutcome::Existing([redacted])",
        })
    }
}

/// The operations the OS provider needs.
///
/// `ensure=true` uses a cooperative cross-process lock around `get` and `set`.
/// This cannot prevent races with applications that do not take that lock.
pub trait OsBackend: Send + Sync {
    /// Reads one entry. `None` means the entry does not exist.
    ///
    /// # Errors
    ///
    /// Returns an [`OsError`] when the store is unavailable, denies access, or
    /// fails.
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, OsError>;

    /// Writes one entry, replacing an existing value.
    ///
    /// # Errors
    ///
    /// Returns an [`OsError`] when the store is unavailable, denies access, or
    /// fails.
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), OsError>;

    /// Stores `value` only when the entry is absent.
    ///
    /// The default is a refusal, not a read-then-write fallback. A fallback
    /// would turn `ensure=true` into a racy overwrite while still looking atomic.
    ///
    /// # Errors
    ///
    /// Returns [`OsError::Unsupported`] unless the backend overrides this.
    fn create_if_absent(
        &self,
        _service: &str,
        _account: &str,
        _value: &str,
    ) -> Result<CreateOutcome, OsError> {
        Err(OsError::Unsupported)
    }
}

/// Windows' generic credential target-name limit. The same bound is applied on
/// the Windows target encoding so it cannot fail after the platform call.
#[cfg(any(target_os = "windows", test))]
const MAX_STORE_TARGET_BYTES: usize = 32_767;

/// The platform-specific keyring target.
///
/// - macOS: `None` means the user keychain domain. A target is a keychain
///   domain (`User`, `System`, `Common`, `Dynamic`), not an identifier; using
///   `neoenv:v1:...` here would make every construction fail.
/// - Linux: `None` means the default collection. Service and account are the
///   identifying attributes; a per-account target would create a collection per
///   account.
/// - Windows: the target name is the sole identifier and is compared
///   case-insensitively, so it must carry a canonical, collision-free encoding.
#[cfg(target_os = "windows")]
fn platform_target(service: &str, account: &str) -> Result<Option<String>, OsError> {
    windows_store_target(service, account).map(Some)
}

#[cfg(not(target_os = "windows"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature is shared with the Windows encoding, which can reject an oversized coordinate"
)]
fn platform_target(_service: &str, _account: &str) -> Result<Option<String>, OsError> {
    Ok(None)
}

/// A canonical Windows target name.
///
/// The Windows Credential Manager compares target names case-insensitively. The
/// original service and account bytes are hex-encoded with fixed lowercase
/// digits, so `token` and `TOKEN` produce different targets and no two byte
/// sequences produce hex that differs only by case. Length prefixes keep
/// delimiter characters unambiguous.
#[cfg(any(target_os = "windows", test))]
fn windows_store_target(service: &str, account: &str) -> Result<String, OsError> {
    let target = format!(
        "neoenv:v1:{}:{}:{}:{}",
        service.len(),
        hex_lower(service.as_bytes()),
        account.len(),
        hex_lower(account.as_bytes())
    );
    if target.len() > MAX_STORE_TARGET_BYTES {
        return Err(OsError::InvalidCoordinate);
    }
    Ok(target)
}

#[cfg(any(target_os = "windows", test))]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// The production platform adapter.
///
/// The `keyring` crate is selected per target with one native backend, so a
/// Linux build does not link the macOS Keychain framework and a Windows build
/// does not require `DBus`. Targets with no adapter return `Unavailable`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformOsBackend;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl OsBackend for PlatformOsBackend {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, OsError> {
        // **Do not use `keyring::Entry`.** Its constructor and its get/set
        // wrappers emit `log::debug!` records containing the service and account,
        // which can be interpolated reference coordinates. Building the platform
        // credential directly and calling the credential trait avoids that log
        // path without changing the caller's logger or global log level.
        let credential = platform_credential(service, account)?;
        get_from_credential(credential.as_ref())
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), OsError> {
        let credential = platform_credential(service, account)?;
        set_to_credential(credential.as_ref(), value)
    }

    // Deliberately not overridden. The linked keyring API has no atomic
    // create-if-absent call, and a read-then-set here would claim a guarantee
    // this adapter cannot make.
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl OsBackend for PlatformOsBackend {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<Secret>, OsError> {
        Err(OsError::Unavailable)
    }

    fn set(&self, _service: &str, _account: &str, _value: &str) -> Result<(), OsError> {
        Err(OsError::Unavailable)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_credential(service: &str, account: &str) -> Result<Box<keyring::Credential>, OsError> {
    let target = platform_target(service, account)?;
    let builder = keyring::default::default_credential_builder();
    builder
        .build(target.as_deref(), service, account)
        .map_err(|error| platform_error(&error))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn get_from_credential(credential: &keyring::Credential) -> Result<Option<Secret>, OsError> {
    match credential.get_password() {
        Ok(value) => Ok(Some(Secret::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(platform_error(&error)),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn set_to_credential(credential: &keyring::Credential, value: &str) -> Result<(), OsError> {
    credential
        .set_password(value)
        .map_err(|error| platform_error(&error))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn platform_error(error: &keyring::Error) -> OsError {
    match error {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            OsError::Unavailable
        }
        // Every other keyring failure is flattened to one safe category. The
        // platform error detail is deliberately not rendered: it is not needed
        // to act on the failure and is not a value this module can vouch for.
        _ => OsError::Failed,
    }
}

/// An in-memory backend for tests and embedding.
///
/// `create_if_absent` is genuinely atomic under this backend's mutex: two
/// concurrent callers for one account cannot both receive `Created`.
#[derive(Default)]
pub struct MemoryOsBackend {
    entries: Mutex<BTreeMap<(String, String), Zeroizing<String>>>,
}

impl MemoryOsBackend {
    /// Creates an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a value directly, for test setup.
    ///
    /// # Panics
    ///
    /// Panics only if a test setup poisoned the mutex.
    pub fn insert(
        &self,
        service: impl Into<String>,
        account: impl Into<String>,
        value: impl Into<String>,
    ) {
        let mut entries = self.entries.lock().expect("memory OS backend mutex");
        entries.insert(
            (service.into(), account.into()),
            Zeroizing::new(value.into()),
        );
    }

    /// The number of stored entries.
    ///
    /// # Panics
    ///
    /// Panics only if a test setup poisoned the mutex.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("memory OS backend mutex").len()
    }

    /// Whether the store holds no entries.
    ///
    /// # Panics
    ///
    /// Panics only if a test setup poisoned the mutex.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for MemoryOsBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryOsBackend")
            .field("entries", &self.len())
            .finish()
    }
}

impl OsBackend for MemoryOsBackend {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, OsError> {
        let entries = self.entries.lock().map_err(|_| OsError::Failed)?;
        Ok(entries
            .get(&(service.to_owned(), account.to_owned()))
            .map(|value| Secret::new(value.to_string())))
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), OsError> {
        let mut entries = self.entries.lock().map_err(|_| OsError::Failed)?;
        entries.insert(
            (service.to_owned(), account.to_owned()),
            Zeroizing::new(value.to_owned()),
        );
        Ok(())
    }

    fn create_if_absent(
        &self,
        service: &str,
        account: &str,
        value: &str,
    ) -> Result<CreateOutcome, OsError> {
        let mut entries = self.entries.lock().map_err(|_| OsError::Failed)?;
        let key = (service.to_owned(), account.to_owned());
        if let Some(existing) = entries.get(&key) {
            return Ok(CreateOutcome::Existing(Secret::new(existing.to_string())));
        }
        entries.insert(key, Zeroizing::new(value.to_owned()));
        Ok(CreateOutcome::Created(Secret::new(value.to_owned())))
    }
}

/// The backend a vault set uses. Kept as a type alias so callers do not name a
/// `dyn` trait object at every construction site.
pub type OsBackendHandle = Arc<dyn OsBackend>;

/// The default production backend.
#[must_use]
pub fn platform_backend() -> OsBackendHandle {
    Arc::new(PlatformOsBackend)
}

/// Resolves one OS reference.
pub(super) fn get(
    backend: &dyn OsBackend,
    vault_name: &str,
    vault: &neoenv_config::OsVault,
    reference: &super::Reference,
) -> Result<Secret, VaultError> {
    if reference.fragment.is_some() {
        return Err(VaultError::new(
            "NEO708",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: an os reference does not define a field selector"),
        ));
    }
    if reference.query.value.is_some() {
        return Err(VaultError::new(
            "NEO708",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: an inline value is not valid on an os vault"),
        ));
    }
    let secret = backend
        .get(&vault.service, &reference.path_string())
        .map_err(|error| backend_error(vault_name, error))?
        .ok_or_else(|| {
            VaultError::new(
                "NEO707",
                neoenv_core::DiagnosticCategory::NotFound,
                format!("vault {vault_name}: no credential exists at the referenced account"),
            )
        })?;
    validate_backend_secret(&secret, vault_name)
}

/// Creates an entry only if absent, using the backend's operation.
pub(super) fn ensure(
    backend: &dyn OsBackend,
    lock_root: &std::path::Path,
    vault_name: &str,
    vault: &neoenv_config::OsVault,
    reference: &super::Reference,
    candidate: Secret,
) -> Result<Secret, VaultError> {
    if reference.fragment.is_some() || reference.query.value.is_some() {
        return Err(VaultError::new(
            "NEO708",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: ensure does not accept a field or inline value"),
        ));
    }
    let account = reference.path_string();
    let resource = format!("os\0{}\0{account}", vault.service);
    super::lock::with_mutation_lock(lock_root, resource.as_bytes(), || {
        // Fresh read under the cooperative lock. An existing value, including an
        // invalid one, wins and is never overwritten by `ensure`.
        if let Some(existing) = backend
            .get(&vault.service, &account)
            .map_err(|error| backend_error(vault_name, error))?
        {
            return validate_backend_secret(&existing, vault_name);
        }
        backend
            .set(&vault.service, &account, candidate.expose())
            .map_err(|error| backend_error(vault_name, error))?;
        Ok(candidate)
    })
}

/// Sets an existing OS entry, replacing its value.
pub(super) fn set(
    backend: &dyn OsBackend,
    lock_root: &std::path::Path,
    vault_name: &str,
    vault: &neoenv_config::OsVault,
    reference: &super::Reference,
    value: &str,
) -> Result<(), VaultError> {
    if reference.fragment.is_some() {
        return Err(VaultError::new(
            "NEO708",
            neoenv_core::DiagnosticCategory::Runtime,
            format!("vault {vault_name}: an os reference does not define a field selector"),
        ));
    }
    let account = reference.path_string();
    let resource = format!("os\0{}\0{account}", vault.service);
    super::lock::with_mutation_lock(lock_root, resource.as_bytes(), || {
        backend
            .set(&vault.service, &account, value)
            .map_err(|error| backend_error(vault_name, error))
    })
}

fn validate_backend_secret(secret: &Secret, vault_name: &str) -> Result<Secret, VaultError> {
    super::validate_secret(secret.to_owned_string(), vault_name)
}

fn backend_error(vault_name: &str, error: OsError) -> VaultError {
    VaultError::new(
        "NEO706",
        neoenv_core::DiagnosticCategory::Runtime,
        format!("vault {vault_name}: {error}"),
    )
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn platform_credential_for_test(
    service: &str,
    account: &str,
) -> Result<Box<keyring::Credential>, OsError> {
    platform_credential(service, account)
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tests {
    use std::{
        any::Any,
        process::Command,
        sync::{Mutex, Once},
    };

    use log::{LevelFilter, Log, Metadata, Record};

    use super::{OsError, windows_store_target};

    static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALL: Once = Once::new();

    struct Capture;

    impl Log for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &Record<'_>) {
            if let Ok(mut records) = RECORDS.lock() {
                records.push(format!("{} {}", record.target(), record.args()));
            }
        }

        fn flush(&self) {}
    }

    fn install() {
        INSTALL.call_once(|| {
            // In the isolated child this must succeed. Callers assert that; a
            // discarded result would make the whole test vacuous.
            log::set_logger(&Capture).expect("capture logger must install");
            log::set_max_level(LevelFilter::Debug);
        });
    }

    struct MockCredential {
        value: Mutex<Option<Vec<u8>>>,
    }

    impl MockCredential {
        fn new(value: &[u8]) -> Self {
            Self {
                value: Mutex::new(Some(value.to_vec())),
            }
        }
    }

    impl keyring::credential::CredentialApi for MockCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            *self.value.lock().expect("mock credential") = Some(secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            self.value
                .lock()
                .expect("mock credential")
                .clone()
                .ok_or(keyring::Error::NoEntry)
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            *self.value.lock().expect("mock credential") = None;
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Runs in a fresh test process so the global logger is genuinely isolated.
    #[test]
    #[ignore = "invoked by the supervising test in a subprocess"]
    fn log_capture_child_exercises_the_adapter_without_coordinates() {
        install();
        RECORDS.lock().expect("capture records").clear();

        // Positive control: keyring::Entry is the logging path this adapter
        // avoids, so its coordinates must appear. If this fails, the capture is
        // not observing logs and the negative assertion below would be vacuous.
        let _ = keyring::Entry::new("service-sentinel", "account-sentinel");
        {
            let records = RECORDS.lock().expect("capture records");
            assert!(
                records
                    .iter()
                    .any(|record| record.contains("service-sentinel"))
                    && records
                        .iter()
                        .any(|record| record.contains("account-sentinel")),
                "positive control did not capture keyring coordinates: {records:?}"
            );
        }
        RECORDS.lock().expect("capture records").clear();

        // Exercise construction, get, set, and target encoding with no platform
        // credential access.
        super::platform_credential_for_test("service-sentinel", "account-sentinel")
            .expect("platform credential construction must succeed without accessing the store");
        let credential = MockCredential::new(b"mock-value");
        let credential_ref: &keyring::Credential = &credential;
        assert_eq!(
            super::get_from_credential(credential_ref)
                .expect("mock get")
                .map(|secret| secret.to_owned_string())
                .as_deref(),
            Some("mock-value")
        );
        super::set_to_credential(credential_ref, "written").expect("mock set");
        let _ = super::windows_store_target("service-sentinel", "account-sentinel");

        let records = RECORDS.lock().expect("capture records");
        assert!(
            !records
                .iter()
                .any(|record| record.contains("service-sentinel")
                    || record.contains("account-sentinel")),
            "adapter leaked coordinates through logging: {records:?}"
        );
    }

    #[test]
    fn the_log_capture_requirement_runs_in_an_isolated_subprocess() {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "vault::os::tests::log_capture_child_exercises_the_adapter_without_coordinates",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("spawn isolated log capture");
        assert!(
            output.status.success(),
            "isolated logger capture failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn target_encoding_separates_pairs_that_the_default_windows_encoding_collides() {
        // The default keyring Windows target is `{user}.{service}`, which maps
        // both of these to `a.b.c`.
        assert_ne!(
            windows_store_target("c", "a.b").unwrap(),
            windows_store_target("b.c", "a").unwrap()
        );
        assert_ne!(
            windows_store_target("svc:1", "acct").unwrap(),
            windows_store_target("svc", "1:acct").unwrap()
        );
        assert_eq!(
            windows_store_target("svc", "acct").unwrap(),
            "neoenv:v1:3:737663:4:61636374"
        );
    }

    #[test]
    fn windows_target_is_distinct_for_case_only_pairs() {
        assert_ne!(
            windows_store_target("svc", "token").unwrap(),
            windows_store_target("svc", "TOKEN").unwrap()
        );
        let target = windows_store_target("svc", "token").unwrap();
        assert!(
            target
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b':')
        );
    }

    #[test]
    fn platform_target_uses_the_backend_contract() {
        #[cfg(target_os = "windows")]
        assert!(super::platform_target("svc", "token").unwrap().is_some());
        #[cfg(not(target_os = "windows"))]
        assert!(super::platform_target("svc", "token").unwrap().is_none());
    }

    #[test]
    fn target_encoding_is_bounded_before_it_reaches_the_store() {
        let long = "x".repeat(super::MAX_STORE_TARGET_BYTES);
        let error = windows_store_target(&long, "account").unwrap_err();
        assert_eq!(error, OsError::InvalidCoordinate);
    }
}
