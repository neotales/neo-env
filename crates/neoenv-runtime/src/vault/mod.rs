//! Secret references and the providers that resolve them.
//!
//! This module is an *effect boundary*. Loading a project never calls it: a
//! configuration value such as `nsv://work/database` stays a string until a
//! command is about to consume the value. `nenv inspect` and `nenv validate`
//! therefore never prompt for a `KeePass` password, and a command that only reads
//! configuration does not need the vault to exist.
//!
//! The implementation is deliberately small:
//!
//! - [`mod@reference`] parses the `nsv://` grammar, including `${NAME}`
//!   interpolation and the query options.
//! - [`VaultSet`] is built from a resolved project's declarations and resolves
//!   a reference through one provider.
//! - age and `KeePass` are the two providers in this slice. The operating-system
//!   keyring is reserved and refused by the configuration parser, not faked
//!   here.
//!
//! A resolved value is carried in [`Secret`], which has no `Display` and a
//! redacted `Debug`. Errors carry the vault name and reference path so a user
//! can act on them, and never the value, the password, or the ciphertext.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{self, Read as _},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use indexmap::IndexMap;
use neoenv_config::{VaultDeclaration, VaultProvider};
use neoenv_core::{Diagnostic, DiagnosticCategory};
use zeroize::Zeroizing;

mod age;
mod keepass;
mod lock;
pub mod os;
pub mod reference;

pub use os::{
    CreateOutcome, MemoryOsBackend, OsBackend, OsBackendHandle, OsError, PlatformOsBackend,
};
pub use reference::{Query, Reference, ReferenceError};

use crate::resolved_config::ResolvedProject;

pub(crate) const REFERENCE_PREFIX: &str = "nsv://";

/// The maximum number of provider lookups one reference may cost.
///
/// The intended chain is a `KeePass` password held in an age `values:` entry,
/// whose identity may itself be an `nsv://` reference. A chain longer than this
/// is a cycle or a configuration nobody meant; both are refused rather than
/// followed.
const MAX_DEPTH: usize = 8;

/// The maximum plaintext size this module will place into an environment value.
///
/// An environment value has no protocol length prefix and a child process
/// inherits it; a vault response larger than this is a wrong answer rather than
/// a large secret.
pub const MAX_SECRET_BYTES: usize = 1 << 20;

/// The number of attempts for an operation that can fail transiently.
const READ_ATTEMPTS: usize = 3;

/// A resolved secret value.
///
/// The inner string is zeroized on drop. `Debug` never prints it, and there is
/// deliberately no `Display` implementation: formatting a secret is how one ends
/// up in a diagnostic. A caller that needs the bytes asks for [`Secret::expose`]
/// at the boundary where it is about to use them.
pub struct Secret(Zeroizing<String>);

/// Why a caller-supplied secret value was rejected.
///
/// This carries a category, not the offending bytes. An external
/// [`os::OsBackend`] uses it to report an invalid value without
/// echoing what it was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRejected {
    /// The value is larger than [`MAX_SECRET_BYTES`].
    TooLarge,
    /// The value contains a NUL byte and cannot be an environment value.
    Nul,
}

impl fmt::Display for SecretRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "secret value is too large",
            Self::Nul => "secret value contains a NUL byte",
        })
    }
}

impl std::error::Error for SecretRejected {}

impl Secret {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Creates a secret for an external backend.
    ///
    /// A backend implementation outside this crate cannot construct [`Secret`]
    /// by layout, so this is its safe constructor. The same size and NUL policy
    /// as the built-in providers is applied here; the error never contains the
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [`SecretRejected::TooLarge`] or [`SecretRejected::Nul`].
    pub fn try_new(value: String) -> Result<Self, SecretRejected> {
        if value.len() > MAX_SECRET_BYTES {
            return Err(SecretRejected::TooLarge);
        }
        if value.contains('\0') {
            return Err(SecretRejected::Nul);
        }
        Ok(Self::new(value))
    }

    /// Borrows the plaintext for the caller's immediate use.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Copies the plaintext out, for a caller whose API requires ownership.
    ///
    /// This copy is not zeroized by this module. Environment maps and child
    /// process environments are ordinary `String`s by design, so the boundary
    /// has to be explicit rather than pretending the value has one lifetime.
    #[must_use]
    pub fn to_owned_string(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

/// Why a reference could not be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultError {
    code: &'static str,
    category: DiagnosticCategory,
    message: String,
    transient: bool,
}

impl VaultError {
    fn new(code: &'static str, category: DiagnosticCategory, message: impl Into<String>) -> Self {
        Self {
            code,
            category,
            message: message.into(),
            transient: false,
        }
    }

    fn transient(message: impl Into<String>) -> Self {
        Self {
            code: "NEO706",
            category: DiagnosticCategory::Runtime,
            message: message.into(),
            transient: true,
        }
    }

    /// The stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The safe human message. It never contains a secret value.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The diagnostic category this failure maps to.
    #[must_use]
    pub const fn category(&self) -> DiagnosticCategory {
        self.category
    }

    /// Converts to the CLI's stable diagnostic shape.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic::new(self.category, self.code, self.message.clone())
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VaultError {}

impl From<ReferenceError> for VaultError {
    fn from(error: ReferenceError) -> Self {
        Self::new("NEO704", DiagnosticCategory::Runtime, error.to_string())
    }
}

/// One declared vault and the directory its relative paths are resolved against.
#[derive(Debug)]
struct DeclaredVault {
    declaration: VaultDeclaration,
    base: PathBuf,
}

/// The providers a project declared, ready to resolve a reference.
///
/// Construction is cheap and does not touch a vault. Resolution is the only
/// operation that reads a file or decrypts anything.
pub struct VaultSet {
    vaults: IndexMap<String, DeclaredVault>,
    os_backend: OsBackendHandle,
    lock_root: Option<PathBuf>,
}

impl fmt::Debug for VaultSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSet")
            .field("vaults", &self.vaults)
            .finish_non_exhaustive()
    }
}

impl VaultSet {
    /// Collects the declarations from a resolved project.
    ///
    /// Infallible: the configuration parser has already validated names and
    /// provider-specific required fields. A provider file that does not exist is
    /// a resolution-time error, not a construction-time one, because the whole
    /// point is that a command that does not consume the value does not need it.
    #[must_use]
    pub fn from_project(project: &ResolvedProject) -> Self {
        Self::from_project_with_backend(project, os::platform_backend())
    }

    /// Collects declarations with an explicit OS backend.
    ///
    /// This is the injection point for tests, embedding, and any future backend
    /// that can implement atomic create-if-absent.
    #[must_use]
    pub fn from_project_with_backend(
        project: &ResolvedProject,
        os_backend: OsBackendHandle,
    ) -> Self {
        Self::from_declarations_with_backend(
            project
                .vaults
                .iter()
                .map(|(name, declaration)| (name.clone(), declaration.clone()))
                .collect(),
            os_backend,
        )
    }

    /// Builds a set from declarations directly.
    ///
    /// This is the constructor for callers that already have the declarations —
    /// a focused library caller, or a test — without standing up a whole
    /// `ResolvedProject`. Relative provider paths are resolved against the
    /// declaring source's parent directory, exactly as [`Self::from_project`]
    /// does.
    #[must_use]
    pub fn from_declarations(vaults: IndexMap<String, VaultDeclaration>) -> Self {
        Self::from_declarations_with_backend(vaults, os::platform_backend())
    }

    /// Builds a set with an explicit OS backend.
    #[must_use]
    pub fn from_declarations_with_backend(
        vaults: IndexMap<String, VaultDeclaration>,
        os_backend: OsBackendHandle,
    ) -> Self {
        Self::from_declarations_with_backend_and_lock_root(
            vaults,
            os_backend,
            lock::default_lock_root(),
        )
    }

    /// Builds a set with explicit backend and mutation-lock root.
    ///
    /// Tests and embedded callers use this so a mutation cannot write a lock
    /// into the user's real state directory.
    #[must_use]
    pub fn from_declarations_with_backend_and_lock_root(
        vaults: IndexMap<String, VaultDeclaration>,
        os_backend: OsBackendHandle,
        lock_root: Option<PathBuf>,
    ) -> Self {
        let vaults = vaults
            .into_iter()
            .map(|(name, declaration)| {
                let base = Path::new(&declaration.source.path)
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                (name, DeclaredVault { declaration, base })
            })
            .collect();
        Self {
            vaults,
            os_backend,
            lock_root,
        }
    }

    /// Replaces the mutation-lock root.
    #[must_use]
    pub fn with_lock_root(mut self, lock_root: impl Into<PathBuf>) -> Self {
        self.lock_root = Some(lock_root.into());
        self
    }

    /// An empty set, for callers that have no project (or a project with no
    /// vaults) and should still be able to ask the resolver a question.
    #[must_use]
    pub fn empty() -> Self {
        Self::empty_with_backend(os::platform_backend())
    }

    /// An empty set with an explicit OS backend.
    #[must_use]
    pub fn empty_with_backend(os_backend: OsBackendHandle) -> Self {
        Self {
            vaults: IndexMap::new(),
            os_backend,
            lock_root: lock::default_lock_root(),
        }
    }

    fn mutation_lock_root(&self) -> Result<&Path, VaultError> {
        self.lock_root.as_deref().ok_or_else(|| {
            VaultError::new(
                "NEO712",
                DiagnosticCategory::Runtime,
                "no vault mutation lock root is available",
            )
        })
    }

    /// Resolves a reference against an environment.
    ///
    /// `environment` is the final effective scope used for `${NAME}`
    /// interpolation in the reference and in provider settings. It must not be
    /// the whole inherited process environment: an unrelated inherited variable
    /// is not a declaration, and a reference that names one is a missing name.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] for malformed syntax, an undeclared vault, an
    /// unsupported option, a provider that cannot be opened, a missing value, or
    /// a reference cycle. The message never contains the resolved value.
    pub fn get(
        &self,
        value: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Secret, VaultError> {
        let mut visited = Vec::new();
        self.get_depth(value, environment, &mut visited, 0)
    }

    /// Resolves `value` when it is a whole `nsv://` reference, and leaves it alone
    /// otherwise.
    ///
    /// A reference must be the whole value: `prefix-nsv://vault/path` is refused
    /// rather than spliced. Concatenating a secret into a larger string makes
    /// the secret boundary invisible and makes redaction a guess.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`VaultSet::get`], plus a refusal when
    /// `nsv://` appears inside a larger value.
    pub fn resolve_value(
        &self,
        value: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Option<Secret>, VaultError> {
        let trimmed = value.trim();
        if trimmed.starts_with(REFERENCE_PREFIX) {
            return self.get(trimmed, environment).map(Some);
        }
        if trimmed.contains(REFERENCE_PREFIX) {
            return Err(VaultError::new(
                "NEO708",
                DiagnosticCategory::Runtime,
                "a secret reference must be the whole value; \
                 `nsv://` inside a larger string is not resolved",
            ));
        }
        Ok(None)
    }

    /// Resolves the effective values named by `scope` in an ordered map.
    ///
    /// **`scope` and `context` are different questions.** `scope` is the set of
    /// keys this run owns, so an unrelated inherited value containing `nsv://` is
    /// never scanned or fetched. `context` is the final effective environment, so
    /// a reference may explicitly read an inherited input such as `${HOME}` or
    /// `${CI}`, with project and CLI values already winning by precedence.
    ///
    /// A plaintext is written into the map exactly once. The context keeps the
    /// values the caller supplied, so a secret cannot become part of a later
    /// reference's path.
    ///
    /// # Errors
    ///
    /// Returns the first resolution failure. A failure leaves earlier entries
    /// resolved in the caller's map; the caller must treat the map as unusable
    /// and must not run the child or print it.
    pub fn resolve_ordered_environment(
        &self,
        environment: &mut IndexMap<String, String>,
        scope: &BTreeSet<String>,
        context: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        for key in scope {
            let Some(value) = environment.get_mut(key) else {
                continue;
            };
            if let Some(secret) = self.resolve_value(value, context)? {
                *value = secret.to_owned_string();
            }
        }
        Ok(())
    }

    /// Resolves the effective values named by `scope` in a `BTreeMap`
    /// environment, such as the one a task receives.
    ///
    /// See [`VaultSet::resolve_ordered_environment`] for the scope/context split
    /// and why plaintext is resolved once.
    ///
    /// # Errors
    ///
    /// Returns the first resolution failure. See
    /// [`VaultSet::resolve_ordered_environment`] for the partial-map caveat.
    pub fn resolve_environment(
        &self,
        environment: &mut BTreeMap<String, String>,
        scope: &BTreeSet<String>,
        context: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        for key in scope {
            let Some(value) = environment.get_mut(key) else {
                continue;
            };
            if let Some(secret) = self.resolve_value(value, context)? {
                *value = secret.to_owned_string();
            }
        }
        Ok(())
    }

    /// Resolves the project's own `env:` values in place.
    ///
    /// This is the shell-activation step. It is deliberately separate from
    /// loading: `ResolvedProject` can be inspected, validated and printed without
    /// calling this function, and only the command that is about to render a
    /// shell environment calls it.
    ///
    /// The interpolation context is the final effective environment: the
    /// caller-supplied inherited map overlaid with the project's declared values.
    /// The resolution scope is only the project's keys, so an unrelated inherited
    /// value is never scanned or resolved, while an explicitly named inherited
    /// input such as `${HOME}` is available.
    ///
    /// # Errors
    ///
    /// Returns the first resolution failure. The project may be partly updated;
    /// the caller must not render it after an error.
    pub fn resolve_project_environment(
        &self,
        project: &mut ResolvedProject,
        inherited: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let mut context = inherited.clone();
        context.extend(
            project
                .environment
                .iter()
                .map(|(key, entry)| (key.clone(), entry.value.clone())),
        );
        let scope: BTreeSet<String> = project.environment.keys().cloned().collect();
        for key in scope {
            if let Some(entry) = project.environment.get_mut(&key)
                && let Some(secret) = self.resolve_value(&entry.value, &context)?
            {
                entry.value = secret.to_owned_string();
            }
        }
        Ok(())
    }

    fn get_depth(
        &self,
        value: &str,
        environment: &BTreeMap<String, String>,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> Result<Secret, VaultError> {
        if depth >= MAX_DEPTH {
            return Err(VaultError::new(
                "NEO709",
                DiagnosticCategory::Runtime,
                "secret reference chain is too deep; this is probably a cycle",
            ));
        }
        let reference = Reference::parse(value, environment)?;
        let Some(declared) = self.vaults.get(&reference.vault) else {
            return Err(VaultError::new(
                "NEO705",
                DiagnosticCategory::Runtime,
                format!(
                    "the referenced vault is not declared; declared vaults: {}",
                    self.names()
                ),
            ));
        };
        let cycle_key = reference.canonical();
        if visited.iter().any(|entry| entry == &cycle_key) {
            return Err(VaultError::new(
                "NEO709",
                DiagnosticCategory::Runtime,
                "secret reference cycle detected",
            ));
        }
        visited.push(cycle_key);
        let resolved = if reference.query.ensure {
            let candidate = generate_secret(
                reference.query.size.unwrap_or(32),
                reference.query.upper.unwrap_or(true),
            )?;
            match &declared.declaration.provider {
                VaultProvider::Os(vault) => os::ensure(
                    self.os_backend.as_ref(),
                    self.mutation_lock_root()?,
                    &declared.declaration.name,
                    vault,
                    &reference,
                    candidate,
                ),
                VaultProvider::Keepass(vault) => keepass::ensure(
                    self,
                    self.mutation_lock_root()?,
                    &declared.declaration.name,
                    vault,
                    &declared.base,
                    &reference,
                    environment,
                    candidate,
                    visited,
                    depth,
                ),
                VaultProvider::Age(_) => {
                    visited.pop();
                    return Err(VaultError::new(
                        "NEO708",
                        DiagnosticCategory::Runtime,
                        "ensure=true is not supported for age; its encrypted configuration file \
                         would have to be rewritten",
                    ));
                }
            }
        } else {
            self.resolve_declared(declared, &reference, environment, visited, depth)
        };
        visited.pop();
        resolved
    }

    /// Writes a whole reference's value through a writable provider.
    ///
    /// Only the OS provider is writable in this slice. The reference may not
    /// carry `ensure`, size/upper, an inline value, or a fragment: those are
    /// resolution options, not write selectors. The caller is responsible for
    /// reading the new value without placing it on a command line.
    ///
    /// # Errors
    ///
    /// Returns a [`VaultError`] for a malformed reference, an undeclared vault,
    /// a read-only provider, an unsupported option, or a backend failure.
    pub fn set_secret(
        &self,
        value: &str,
        new_value: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<(), VaultError> {
        let reference = Reference::parse(value, environment)?;
        if reference.query.ensure_specified
            || reference.query.size.is_some()
            || reference.query.upper.is_some()
            || reference.query.value.is_some()
        {
            return Err(VaultError::new(
                "NEO708",
                DiagnosticCategory::Runtime,
                "set takes a plain reference, not ensure/size/upper, a fragment, or an inline value",
            ));
        }
        let Some(declared) = self.vaults.get(&reference.vault) else {
            return Err(VaultError::new(
                "NEO705",
                DiagnosticCategory::Runtime,
                format!(
                    "the referenced vault is not declared; declared vaults: {}",
                    self.names()
                ),
            ));
        };
        // The same NUL and size policy as a read, applied before the backend can
        // store anything.
        validate_secret(new_value.to_owned(), &declared.declaration.name)?;
        match &declared.declaration.provider {
            VaultProvider::Os(vault) => os::set(
                self.os_backend.as_ref(),
                self.mutation_lock_root()?,
                &declared.declaration.name,
                vault,
                &reference,
                new_value,
            ),
            VaultProvider::Keepass(vault) => keepass::set(
                self,
                self.mutation_lock_root()?,
                &declared.declaration.name,
                vault,
                &declared.base,
                &reference,
                environment,
                new_value,
            ),
            VaultProvider::Age(_) => Err(VaultError::new(
                "NEO708",
                DiagnosticCategory::Runtime,
                "the referenced provider is read-only in this build",
            )),
        }
    }

    fn resolve_declared(
        &self,
        declared: &DeclaredVault,
        reference: &Reference,
        environment: &BTreeMap<String, String>,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> Result<Secret, VaultError> {
        match &declared.declaration.provider {
            VaultProvider::Age(vault) => age::get(
                self,
                &declared.declaration.name,
                vault,
                &declared.base,
                reference,
                environment,
                visited,
                depth,
            ),
            VaultProvider::Keepass(vault) => keepass::get(
                self,
                &declared.declaration.name,
                vault,
                &declared.base,
                reference,
                environment,
                visited,
                depth,
            ),
            VaultProvider::Os(vault) => os::get(
                self.os_backend.as_ref(),
                &declared.declaration.name,
                vault,
                reference,
            ),
        }
    }

    fn names(&self) -> String {
        if self.vaults.is_empty() {
            return "none".to_owned();
        }
        self.vaults.keys().cloned().collect::<Vec<_>>().join(", ")
    }

    fn get_nested(
        &self,
        value: &str,
        environment: &BTreeMap<String, String>,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> Result<Secret, VaultError> {
        self.get_depth(value, environment, visited, depth + 1)
    }
}

/// Generates a uniformly random alphanumeric secret.
///
/// `upper=false` uses lowercase letters and digits; `upper=true` adds uppercase
/// letters. Symbols are deliberately excluded because these values are often
/// placed in shell assignments and URLs. Rejection sampling avoids the modulo
/// bias a direct `byte % alphabet` would introduce.
fn generate_secret(size: u32, upper: bool) -> Result<Secret, VaultError> {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    let mut alphabet = Vec::with_capacity(LOWER.len() + UPPER.len() + DIGITS.len());
    alphabet.extend_from_slice(LOWER);
    if upper {
        alphabet.extend_from_slice(UPPER);
    }
    alphabet.extend_from_slice(DIGITS);
    let len = u8::try_from(alphabet.len()).map_err(|_| {
        VaultError::new(
            "NEO710",
            DiagnosticCategory::Runtime,
            "secret generation alphabet is too large",
        )
    })?;
    let limit = 256 - (256 % u16::from(len));
    let size = usize::try_from(size).unwrap_or(0);
    let mut output = String::with_capacity(size);
    while output.len() < size {
        let mut byte = [0_u8; 1];
        getrandom::fill(&mut byte).map_err(|_| {
            VaultError::new(
                "NEO710",
                DiagnosticCategory::Runtime,
                "operating-system entropy is unavailable",
            )
        })?;
        if u16::from(byte[0]) < limit {
            output.push(char::from(alphabet[usize::from(byte[0]) % alphabet.len()]));
        }
    }
    Ok(Secret::new(output))
}

/// Expands `~` at the start of a provider path.
fn expand_home(value: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    if value == "~" {
        return Some(home);
    }
    value.strip_prefix("~/").map(|rest| home.join(rest))
}

/// Expands only `${NAME}` and refuses a name that is not set.
///
/// Used for a master password, where a bare `$` is far more likely to be part of
/// the password than the start of a variable. `$NAME` is left literal; only the
/// explicit braced form is interpolation.
fn expand_braced_setting(
    value: &str,
    environment: &BTreeMap<String, String>,
) -> Result<String, VaultError> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(dollar) = rest.find('$') {
        output.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        let Some(braced) = after.strip_prefix('{') else {
            output.push('$');
            rest = after;
            continue;
        };
        let Some(end) = braced.find('}') else {
            return Err(VaultError::new(
                "NEO706",
                DiagnosticCategory::Runtime,
                "a vault setting has an unterminated ${...} interpolation",
            ));
        };
        let name = &braced[..end];
        if name.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
            || !name
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            return Err(VaultError::new(
                "NEO706",
                DiagnosticCategory::Runtime,
                "a vault setting has an invalid interpolation name",
            ));
        }
        let resolved = environment.get(name).ok_or_else(|| {
            VaultError::new(
                "NEO706",
                DiagnosticCategory::Runtime,
                format!("a vault setting names {name:?}, which is not set"),
            )
        })?;
        output.push_str(resolved);
        rest = &braced[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn resolve_setting_path(
    value: &str,
    base: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<PathBuf, VaultError> {
    let expanded = expand_braced_setting(value, environment)?;
    if let Some(path) = expand_home(&expanded) {
        return Ok(path);
    }
    let path = PathBuf::from(expanded);
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}

/// Reads a file with bounded retries and no secret in the error.
fn read_secret_file(path: &Path) -> Result<String, VaultError> {
    let mut attempt = 0;
    loop {
        match read_once(path) {
            Ok(value) => return Ok(value),
            Err(error) if error.transient && attempt + 1 < READ_ATTEMPTS => {
                attempt += 1;
                thread::sleep(Duration::from_millis(10 * attempt as u64));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_once(path: &Path) -> Result<String, VaultError> {
    let file = open_secret_file(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(&error))?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(VaultError::new(
            "NEO710",
            DiagnosticCategory::Runtime,
            format!("vault material is larger than {MAX_SECRET_BYTES} bytes"),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        VaultError::new(
            "NEO706",
            DiagnosticCategory::Runtime,
            "vault material is not UTF-8",
        )
    })
}

/// Opens a vault file with bounded retries for a sharing or interruption error.
fn open_secret_file(path: &Path) -> Result<File, VaultError> {
    let mut attempt = 0;
    loop {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(error) if is_transient(&error) && attempt + 1 < READ_ATTEMPTS => {
                attempt += 1;
                thread::sleep(Duration::from_millis(10 * attempt as u64));
            }
            Err(error) => return Err(io_error(&error)),
        }
    }
}

fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn io_error(error: &io::Error) -> VaultError {
    if error.kind() == io::ErrorKind::NotFound {
        return VaultError::new(
            "NEO707",
            DiagnosticCategory::NotFound,
            "the vault file named by the declaration was not found",
        );
    }
    let transient = is_transient(error);
    let message = format!("failed to read the vault file: {error}");
    if transient {
        VaultError::transient(message)
    } else {
        VaultError::new("NEO706", DiagnosticCategory::Runtime, message)
    }
}

fn validate_secret(value: String, vault: &str) -> Result<Secret, VaultError> {
    Secret::try_new(value).map_err(|error| {
        VaultError::new(
            "NEO710",
            DiagnosticCategory::Runtime,
            format!("vault {vault}: {error}"),
        )
    })
}

#[cfg(test)]
mod tests;
