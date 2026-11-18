//! Test support: approve a fixture's files with the real trust API.
//!
//! Execution now requires an explicit trust record for the root and every
//! contributing document. Tests that are not about trust still execute, so they
//! approve the tree they just wrote, using the same store format and BLAKE3
//! identity as the product. Nothing here bypasses the gate: a test that wants
//! an untrusted fixture simply does not call this.

#![allow(dead_code)]

use std::{fs, path::Path};

/// Approves every regular file below `root` into the store at `config_home`.
///
/// Extra records for scripts and templates are harmless; trust is per file and
/// a record that is never consulted changes no decision.
pub fn approve_tree(config_home: &Path, root: &Path) {
    let store = config_home.join("neoenv/projects.toml");
    let user_config = config_home.join("neoenv/neoenv.yaml");
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                // The store and its lock are not configuration; neither is
                // global tool state under the same config root. Only the one
                // user project configuration there can contribute.
                if path.ends_with(".lock")
                    || (path.starts_with(config_home)
                        && !path.starts_with(root)
                        && path != user_config)
                {
                    continue;
                }
                files.push(path);
            }
        }
    }
    let _ = neoenv_runtime::trust::approve_locals_in(&store, &files);
}

/// Approves one file, panicking if the approval cannot be written.
pub fn approve(config_home: &Path, path: &Path) {
    let store = config_home.join("neoenv/projects.toml");
    neoenv_runtime::trust::approve_local_in(&store, path).unwrap();
}

use std::{ffi::OsStr, path::PathBuf, process::Command, sync::OnceLock};

/// One isolated config home per test binary.
fn shared_home() -> &'static Path {
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    HOME.get_or_init(|| tempfile::TempDir::new().unwrap())
        .path()
}

/// A `Command` that approves the fixture it is pointed at.
///
/// Fixtures are written before their command is built, so `current_dir`, path
/// arguments, and redirected XDG roots are enough to find the tree the command
/// will read. Tests that assert untrusted behavior use the binary's own `trust`
/// commands; they do not go through this builder.
pub struct TestCommand {
    inner: Command,
    cwd: Option<PathBuf>,
    store_home: PathBuf,
    roots: Vec<PathBuf>,
    approved: std::collections::HashSet<PathBuf>,
}

impl TestCommand {
    #[must_use]
    pub fn new() -> Self {
        let mut inner = Command::new(env!("CARGO_BIN_EXE_nenv"));
        inner.env("NEOENV_CONFIG_HOME", shared_home());
        Self {
            inner,
            cwd: None,
            store_home: shared_home().to_owned(),
            roots: Vec::new(),
            approved: std::collections::HashSet::new(),
        }
    }

    fn remember(&mut self, root: &Path) {
        if !self.roots.iter().any(|known| known == root) {
            self.roots.push(root.to_owned());
        }
    }

    pub fn current_dir(&mut self, directory: impl AsRef<Path>) -> &mut Self {
        self.cwd = Some(directory.as_ref().to_owned());
        self.remember(directory.as_ref());
        if self.approved.insert(directory.as_ref().to_owned()) {
            approve_tree(&self.store_home, directory.as_ref());
        }
        self.inner.current_dir(directory);
        self
    }

    pub fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        let candidate = Path::new(argument.as_ref());
        if candidate.is_file() {
            if let Some(parent) = candidate.parent() {
                self.remember(parent);
                if self.approved.insert(parent.to_owned()) {
                    approve_tree(&self.store_home, parent);
                }
            }
        } else if candidate.is_dir() {
            self.remember(candidate);
            if self.approved.insert(candidate.to_owned()) {
                approve_tree(&self.store_home, candidate);
            }
        }
        self.inner.arg(argument);
        self
    }

    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for argument in arguments {
            self.arg(argument);
        }
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        let key = key.as_ref();
        let value = value.as_ref();
        let name = key.to_string_lossy();
        if matches!(
            name.as_ref(),
            "XDG_CONFIG_HOME" | "NEOENV_CONFIG_HOME" | "XDG_DATA_HOME" | "NEOENV_DATA_HOME"
        ) {
            if name.contains("CONFIG") {
                self.store_home = PathBuf::from(value);
            }
            self.remember(Path::new(value));
            if let Some(cwd) = self.cwd.clone() {
                self.remember(&cwd);
            }
            for root in self.roots.clone() {
                approve_tree(&self.store_home, &root);
            }
            self.approved.clear();
            if matches!(name.as_ref(), "XDG_CONFIG_HOME" | "XDG_DATA_HOME") {
                let override_key = if name.contains("CONFIG") {
                    "NEOENV_CONFIG_HOME"
                } else {
                    "NEOENV_DATA_HOME"
                };
                self.inner.env(override_key, value);
            }
        }
        self.inner.env(key, value);
        self
    }

    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env_remove(key);
        self
    }

    pub fn stdin(&mut self, configuration: impl Into<std::process::Stdio>) -> &mut Self {
        self.inner.stdin(configuration);
        self
    }

    pub fn stdout(&mut self, configuration: impl Into<std::process::Stdio>) -> &mut Self {
        self.inner.stdout(configuration);
        self
    }

    pub fn stderr(&mut self, configuration: impl Into<std::process::Stdio>) -> &mut Self {
        self.inner.stderr(configuration);
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.inner.env_clear();
        // The builder's own overrides are re-applied by the caller; the store
        // remains the shared home so approvals already written stay visible.
        self.inner.env("NEOENV_CONFIG_HOME", &self.store_home);
        self
    }

    /// The underlying process builder, for options the wrapper does not mirror.
    pub fn inner_mut(&mut self) -> &mut Command {
        &mut self.inner
    }

    pub fn output(&mut self) -> std::io::Result<std::process::Output> {
        self.inner.output()
    }

    pub fn status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.inner.status()
    }

    pub fn spawn(&mut self) -> std::io::Result<std::process::Child> {
        self.inner.spawn()
    }
}

impl Default for TestCommand {
    fn default() -> Self {
        Self::new()
    }
}
