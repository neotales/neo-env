//! XDG-style user directories owned by `nenv`.
//!
//! A `NEOENV_*_HOME` override always wins over the matching `XDG_*_HOME`
//! variable. Platform fallbacks deliberately preserve the XDG directory names
//! so that `nenv` has one predictable layout on Linux, macOS, and Windows.

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

/// The user directory category requested by a `nenv` subsystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserDirectory {
    Config,
    Data,
    Cache,
    State,
}

/// Returns the XDG-style root for a `nenv` user directory category.
///
/// `NEOENV_<CATEGORY>_HOME` has priority over `XDG_<CATEGORY>_HOME`. When
/// neither is set, the conventional directory below `HOME`/`USERPROFILE` is
/// used. `HOMEDRIVE` and `HOMEPATH` remain the final Windows fallback.
#[must_use]
pub fn user_directory(kind: UserDirectory) -> Option<PathBuf> {
    let (neoenv, xdg, fallback) = match kind {
        UserDirectory::Config => ("NEOENV_CONFIG_HOME", "XDG_CONFIG_HOME", ".config"),
        UserDirectory::Data => ("NEOENV_DATA_HOME", "XDG_DATA_HOME", ".local/share"),
        UserDirectory::Cache => ("NEOENV_CACHE_HOME", "XDG_CACHE_HOME", ".cache"),
        UserDirectory::State => ("NEOENV_STATE_HOME", "XDG_STATE_HOME", ".local/state"),
    };
    user_directory_from(
        environment_path(neoenv),
        environment_path(xdg),
        home_directory(),
        fallback,
    )
}

/// A system-wide directory category owned by `nenv`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemDirectory {
    /// Machine-wide configuration: `/etc/neoenv`, `%ProgramData%\neoenv`.
    Config,
    /// Machine-wide installed tools: `/usr/local/neoenv`,
    /// `%ProgramFiles%\neoenv`.
    Install,
}

/// Returns the system-wide directory for a category.
///
/// `NEOENV_GLOBAL_CONFIG_DIR` and `NEOENV_GLOBAL_INSTALL_DIR` are explicit
/// overrides. Without one, Unix uses `/etc/neoenv` and `/usr/local/neoenv`.
/// Windows reads `ProgramData` and `ProgramFiles` from the environment rather
/// than assuming a drive letter; a missing variable is a missing directory, not
/// a guessed `C:\`.
#[must_use]
pub fn system_directory(kind: SystemDirectory) -> Option<PathBuf> {
    let (override_name, base_name) = match kind {
        SystemDirectory::Config => ("NEOENV_GLOBAL_CONFIG_DIR", "ProgramData"),
        SystemDirectory::Install => ("NEOENV_GLOBAL_INSTALL_DIR", "ProgramFiles"),
    };
    system_directory_from(
        environment_path(override_name),
        environment_path(base_name).as_deref(),
        unix_system_base(kind),
    )
}

/// The Unix base for a system category.
///
/// macOS exposes `/etc` as a symlink to `/private/etc`. The system-root guard
/// refuses symlinked ancestors, so the default uses the canonical `/private/etc`
/// rather than making ordinary activation fail on a stock Mac. Linux uses
/// `/etc`; installs use `/usr/local` on both.
fn unix_system_base(kind: SystemDirectory) -> &'static str {
    match kind {
        SystemDirectory::Config if cfg!(target_os = "macos") => "/private/etc",
        SystemDirectory::Config => "/etc",
        SystemDirectory::Install => "/usr/local",
    }
}

fn system_directory_from(
    override_path: Option<PathBuf>,
    windows_base: Option<&Path>,
    unix_base: &str,
) -> Option<PathBuf> {
    override_path.or_else(|| {
        #[cfg(windows)]
        {
            windows_base.map(|base| base.join(neoenv_core::names::USER_DIRECTORY))
        }
        #[cfg(not(windows))]
        {
            let _ = windows_base;
            Some(PathBuf::from(unix_base).join(neoenv_core::names::USER_DIRECTORY))
        }
    })
}

/// Returns the nenv-owned directory under the requested XDG root.
///
/// The name comes from [`neoenv_core::names`] rather than being written here,
/// because it is the one string that separates "the product" from "the user's
/// data", and this file is where a workspace-wide find-and-replace gets it
/// wrong. That module holds every filename and directory name `nenv`
/// recognises, with tests that fail if one of them is renamed by accident.
#[must_use]
pub fn neoenv_directory(kind: UserDirectory) -> Option<PathBuf> {
    user_directory(kind).map(|root| root.join(neoenv_core::names::USER_DIRECTORY))
}

fn environment_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_directory() -> Option<PathBuf> {
    environment_path("HOME")
        .or_else(|| environment_path("USERPROFILE"))
        .or_else(|| {
            env::var_os("HOMEDRIVE")
                .zip(env::var_os("HOMEPATH"))
                .map(home_drive_path)
        })
}

fn home_drive_path((drive, path): (OsString, OsString)) -> PathBuf {
    PathBuf::from(format!(
        "{}{}",
        drive.to_string_lossy(),
        path.to_string_lossy()
    ))
}

fn user_directory_from(
    neoenv_override: Option<PathBuf>,
    xdg_override: Option<PathBuf>,
    home: Option<PathBuf>,
    fallback: &str,
) -> Option<PathBuf> {
    neoenv_override
        .or(xdg_override)
        .or_else(|| home.map(|directory| directory.join(fallback)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use std::path::Path;

    use super::{
        SystemDirectory, UserDirectory, system_directory_from, user_directory, user_directory_from,
    };

    #[test]
    fn system_override_precedes_the_platform_default() {
        assert_eq!(
            system_directory_from(
                Some(PathBuf::from("/tmp/etc/neoenv")),
                Some(Path::new("/platform")),
                "/etc",
            ),
            Some(PathBuf::from("/tmp/etc/neoenv")),
        );
    }

    #[test]
    fn system_default_is_used_without_an_override() {
        #[cfg(target_os = "macos")]
        assert_eq!(
            system_directory_from(None, None, "/private/etc"),
            Some(PathBuf::from("/private/etc/neoenv")),
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            system_directory_from(None, None, "/etc"),
            Some(PathBuf::from("/etc/neoenv")),
        );
        assert_eq!(
            system_directory_from(None, None, "/usr/local"),
            Some(PathBuf::from("/usr/local/neoenv")),
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            super::unix_system_base(SystemDirectory::Config),
            "/private/etc",
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(super::unix_system_base(SystemDirectory::Config), "/etc");
    }

    #[test]
    fn neoenv_override_precedes_xdg_and_home() {
        assert_eq!(
            user_directory_from(
                Some(PathBuf::from("neoenv")),
                Some(PathBuf::from("xdg")),
                Some(PathBuf::from("home")),
                ".config",
            ),
            Some(PathBuf::from("neoenv")),
        );
    }

    #[test]
    fn xdg_precedes_home_fallback() {
        assert_eq!(
            user_directory_from(
                None,
                Some(PathBuf::from("xdg")),
                Some(PathBuf::from("home")),
                ".local/share",
            ),
            Some(PathBuf::from("xdg")),
        );
    }

    #[test]
    fn home_uses_the_xdg_default_suffix() {
        assert_eq!(
            user_directory_from(None, None, Some(PathBuf::from("home")), ".local/state"),
            Some(PathBuf::from("home/.local/state")),
        );
    }

    /// The product is called `nenv`. The directory it keeps a user's
    /// configuration, installed tools, trust records and module cache in is
    /// called `nenv`, and the two are not the same string.
    ///
    /// This test exists because they are trivially confusable. Both are the
    /// product's name, both appear as a bare `"neoenv"` in this file's history,
    /// and a find-and-replace across the workspace renames the directory as
    /// happily as the binary. The result is not a compile error and not a
    /// visible failure: `nenv` looks in `~/.config/nenv/`, finds nothing, and
    /// reports no configuration -- which is indistinguishable from a user who
    /// genuinely has none. Every existing config, trust record and installed
    /// tool becomes invisible, silently, on upgrade.
    ///
    /// So the two spellings are pinned here on purpose. If a future rename
    /// intends to move the directory, this test is where that decision gets
    /// made deliberately, with a migration for the data already in it.
    #[test]
    fn the_product_name_and_the_state_directory_name_are_different_strings() {
        assert_eq!(
            env!("CARGO_PKG_NAME"),
            "neoenv-runtime",
            "this crate is not the product, so this assertion guards the test itself"
        );
        assert_eq!(
            super::neoenv_directory(UserDirectory::Config),
            user_directory(UserDirectory::Config).map(|root| root.join("neoenv")),
            "the state directory is `nenv` and must not be renamed to `nenv` \
             without a migration for the data already in it"
        );
    }
}
