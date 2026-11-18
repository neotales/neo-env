//! Pure configuration source planning.

use std::path::{Component, Path, PathBuf};

use neoenv_core::{Diagnostic, DiagnosticCategory};

/// The origin and precedence of a selected configuration source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigSourceKind {
    User,
    Project,
    PrivateOverlay,
    /// Machine-written, user-scoped, and **above everything else**.
    ///
    /// Its own kind rather than a second `User`, because the two are opposites in every
    /// way that matters: a `User` source is a person editing a YAML file, and this one is
    /// `nenv config set` rewriting a file `nenv` owns. Collapsing them would leave
    /// `config list` unable to say which of the two a value came from, and that is the
    /// one question the extra layer exists to answer.
    ///
    /// Highest so that a correction takes effect. See
    /// `docs/decision-records/a-user-written-key-goes-in-a-machine-owned-file.md`.
    UserOverrides,
    Module,
}

/// Where a module document came from.
///
/// **Carried explicitly rather than inferred from a path.** A remote tarball is
/// extracted into a cache directory whose path does not spell
/// `.neoenv/modules/commits`, and a local project may contain a directory that
/// does. A path-shaped guess is wrong in both directions; the loader knows the
/// import form at the moment it resolves it, so it records that fact here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModuleOrigin {
    Local,
    Remote,
}

/// A selected source file with its merge provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSource {
    kind: ConfigSourceKind,
    path: PathBuf,
    module_origin: Option<ModuleOrigin>,
}

impl ConfigSource {
    #[must_use]
    pub fn module(path: PathBuf) -> Self {
        Self::module_with_origin(path, ModuleOrigin::Local)
    }

    /// A module document that came from a remote import.
    #[must_use]
    pub fn remote_module(path: PathBuf) -> Self {
        Self::module_with_origin(path, ModuleOrigin::Remote)
    }

    /// A module document with an explicit origin.
    #[must_use]
    pub fn module_with_origin(path: PathBuf, module_origin: ModuleOrigin) -> Self {
        Self {
            kind: ConfigSourceKind::Module,
            path,
            module_origin: Some(module_origin),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ConfigSourceKind {
        self.kind
    }

    /// Whether this module document, or a local import inside it, came from a
    /// remote module.
    #[must_use]
    pub fn is_remote_module(&self) -> bool {
        self.module_origin == Some(ModuleOrigin::Remote)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            ConfigSourceKind::User => "user",
            ConfigSourceKind::Project => "project",
            ConfigSourceKind::PrivateOverlay => "private_overlay",
            ConfigSourceKind::UserOverrides => "user_overrides",
            ConfigSourceKind::Module => "module",
        }
    }
}

/// A merge plan ordered from lowest to highest precedence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigMergePlan {
    sources: Vec<ConfigSource>,
}

impl ConfigMergePlan {
    #[must_use]
    pub fn sources(&self) -> &[ConfigSource] {
        &self.sources
    }
}

/// Creates a low-to-high precedence source plan from already canonical paths.
///
/// # Errors
///
/// Returns a validation diagnostic when a private overlay is not a descendant
/// of the project root or contains a parent-directory traversal component.
pub fn merge_plan(
    user_config: Option<PathBuf>,
    project_config: PathBuf,
    project_root: &Path,
    private_overlay: Option<PathBuf>,
    user_overrides: Option<PathBuf>,
) -> Result<ConfigMergePlan, Diagnostic> {
    let mut sources = Vec::with_capacity(4);
    if let Some(path) = user_config {
        sources.push(ConfigSource {
            kind: ConfigSourceKind::User,
            path,
            module_origin: None,
        });
    }
    sources.push(ConfigSource {
        kind: ConfigSourceKind::Project,
        path: project_config,
        module_origin: None,
    });
    if let Some(path) = private_overlay {
        if !is_private_overlay(&path, project_root) {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO210",
                format!(
                    "private overlay must be a project descendant: {}",
                    path.display()
                ),
            ));
        }
        sources.push(ConfigSource {
            kind: ConfigSourceKind::PrivateOverlay,
            path,
            module_origin: None,
        });
    }
    // **Last, and that is the whole point of the layer.** A person who ran
    // `nenv config set context prod` means it, so it outranks the project file and the
    // private overlay. Putting it lower would make the command silently ineffective,
    // and a command that does not take effect is worse than a missing one -- the user
    // has to be told which of two things went wrong.
    if let Some(path) = user_overrides {
        sources.push(ConfigSource {
            kind: ConfigSourceKind::UserOverrides,
            path,
            module_origin: None,
        });
    }
    Ok(ConfigMergePlan { sources })
}

fn is_private_overlay(path: &Path, project_root: &Path) -> bool {
    path != project_root
        && path.starts_with(project_root)
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ConfigSourceKind, merge_plan};

    #[test]
    fn orders_sources_from_low_to_high_precedence() {
        let plan = merge_plan(
            Some("/home/alice/.config/neoenv/neoenv.toml".into()),
            "/work/app/neoenv.yaml".into(),
            Path::new("/work/app"),
            Some("/work/app/neoenv/private/local.yaml".into()),
            Some("/home/alice/.config/neoenv/overrides.yaml".into()),
        )
        .unwrap();

        // **`UserOverrides` last, and the assertion is the point of the test.** A fourth
        // source that sorted anywhere but the end would make `nenv config set` a command
        // that does not take effect, which is worse than not having it.
        assert_eq!(
            plan.sources()
                .iter()
                .map(super::ConfigSource::kind)
                .collect::<Vec<_>>(),
            vec![
                ConfigSourceKind::User,
                ConfigSourceKind::Project,
                ConfigSourceKind::PrivateOverlay,
                ConfigSourceKind::UserOverrides,
            ]
        );
    }

    #[test]
    fn the_overrides_layer_is_optional() {
        // **Absent is the common case and must not be an error.** A resolver that
        // complained about a missing overrides file would make the ordinary case loud
        // and the rare one silent, which is backwards: the rare one is the one a user
        // needs told about.
        let plan = merge_plan(
            None,
            "/work/app/neoenv.yaml".into(),
            Path::new("/work/app"),
            None,
            None,
        )
        .unwrap();

        assert_eq!(plan.sources().len(), 1);
        assert_eq!(plan.sources()[0].kind(), ConfigSourceKind::Project);
    }

    #[test]
    fn rejects_private_overlay_outside_project_or_with_traversal() {
        let root = Path::new("/work/app");
        assert!(
            merge_plan(
                None,
                "/work/app/neoenv.toml".into(),
                root,
                Some("/work/other/private.yaml".into()),
                None,
            )
            .is_err()
        );
        assert!(
            merge_plan(
                None,
                "/work/app/neoenv.toml".into(),
                root,
                Some("/work/app/neoenv/private/../../secret.yaml".into()),
                None,
            )
            .is_err()
        );
    }
}
