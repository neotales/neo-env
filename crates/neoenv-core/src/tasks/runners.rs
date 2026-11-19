//! Named task runners, and the exact-version `uv` request grammar.
//!
//! A task's `uses:` is either one of the engine's built-in runners, one of the
//! named script runners here, or a fallback executable in a configured task
//! directory. The named script runners deliberately do **not** guess between an
//! inline script and a file from the shape of `run` (Cast's `Script` helper does).
//! Inline is `run:`, file is `source:`; [`crate::tasks::TaskAction`] documents
//! both. A one-line `run: ./script.sh` therefore stays inline, which is the
//! reading that cannot surprise a user who wrote it.
//!
//! `uv` is the one runner that is versioned at the point of use. It is not a
//! shell name resolved on `PATH`: `uses: uv@<version>` names an exact managed
//! runtime, and the runtime layer refuses rather than falling back when that
//! version is not installed. `uv` without a version is refused at plan time.

/// Runners whose `run` is script text and whose `source` is a script file.
///
/// The list is the reserved-name boundary for fallback executables. A
/// `task_dirs` entry with one of these names is no longer reachable through
/// `uses:`; see `docs/task-runners.md` for the compatibility note.
pub const SCRIPT_RUNNERS: &[&str] = &[
    "bash",
    "sh",
    "pwsh",
    "powershell",
    "node",
    "bun",
    "deno",
    "python",
    "nu",
    "fish",
    "go",
    "dotnet",
];

/// Whether `name` selects a named script runner.
#[must_use]
pub fn is_script_runner(name: &str) -> bool {
    SCRIPT_RUNNERS.contains(&name)
}

/// Whether `name` selects the file-template runner.
///
/// The Go reference accepts `tmpl` and any `tmpl://...` spelling as the same
/// local file renderer; the part after `tmpl://` has no URL or fetch semantics.
/// `templ` is deliberately **not** an alias because the reference does not
/// accept it.
#[must_use]
pub fn is_template_runner(name: &str) -> bool {
    name == "tmpl" || name.starts_with("tmpl://")
}

/// Whether `name` selects the explicit Windows Subsystem for Linux runner.
#[must_use]
pub fn is_wsl_runner(name: &str) -> bool {
    name == "wsl"
}

/// Whether `name` is reserved by the engine and never means a fallback file.
///
/// `uv` and a malformed `uv@...` are both reserved: a malformed request must be
/// refused, not looked up as a file named `uv@...`.
#[must_use]
pub fn is_builtin_runner(name: &str) -> bool {
    matches!(
        name,
        "portable" | "argv" | "shell" | "render" | "ssh" | "composite" | "docker"
    ) || is_script_runner(name)
        || is_template_runner(name)
        || is_wsl_runner(name)
        || name == "uv"
        || name.starts_with("uv@")
}

/// An exact `uv@<version>` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UvRunner<'a> {
    /// The version text after `uv@`, already validated as exact.
    pub version: &'a str,
}

/// Parses a `uv` runner selector.
///
/// Returns:
/// - `Ok(None)` when `name` is not `uv` or `uv@...`;
/// - `Ok(Some(request))` for a syntactically exact version;
/// - `Err(message)` for `uv`, `uv@`, a range, or `latest`.
///
/// This validates **syntax**, not installation. Selecting the managed runtime of
/// that exact version happens at the runtime layer, where the installed list is
/// available.
///
/// # Errors
///
/// Returns a user-facing message when the selector is a versioned request that
/// cannot name one exact installed version.
pub fn parse_uv_runner(name: &str) -> Result<Option<UvRunner<'_>>, String> {
    if name == "uv" {
        return Err(
            "uv requires an exact version, for example `uses: uv@0.8.0`; an unversioned \
             `uv` would silently select whatever is on PATH"
                .to_owned(),
        );
    }
    let Some(version) = name.strip_prefix("uv@") else {
        return Ok(None);
    };
    if !is_exact_version(version) {
        return Err(format!(
            "uv version {version:?} is not an exact installed version; write an exact \
             version such as `uses: uv@0.8.0`"
        ));
    }
    Ok(Some(UvRunner { version }))
}

/// Whether `version` is one exact version, not a range or a moving channel.
///
/// The character set is deliberately narrow. A version is compared for equality
/// against an installed directory name and is never joined to a path, but a
/// narrow grammar still turns `uv@latest`, `uv@^0.8`, and `uv@../x` into a
/// diagnostic naming the spelling rather than a lookup that finds nothing.
#[must_use]
pub fn is_exact_version(version: &str) -> bool {
    !version.is_empty()
        && version != "."
        && version != ".."
        && !version.eq_ignore_ascii_case("latest")
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_runner_names_are_reserved() {
        for name in SCRIPT_RUNNERS {
            assert!(is_script_runner(name));
            assert!(is_builtin_runner(name));
        }
        assert!(is_template_runner("tmpl"));
        assert!(is_template_runner("tmpl://anything"));
        assert!(!is_template_runner("templ"));
        assert!(is_builtin_runner("tmpl"));
        assert!(is_builtin_runner("tmpl://anything"));
        assert!(!is_builtin_runner("templ"));
        assert!(is_wsl_runner("wsl"));
        assert!(is_builtin_runner("wsl"));
        assert!(is_builtin_runner("composite"));
        assert!(!is_wsl_runner("bash"));
        assert!(!is_script_runner("custom"));
        assert!(!is_builtin_runner("custom"));
    }

    #[test]
    fn uv_requires_one_exact_version() {
        assert_eq!(
            parse_uv_runner("uv@0.8.0").unwrap(),
            Some(UvRunner { version: "0.8.0" })
        );
        assert_eq!(
            parse_uv_runner("uv@0.8.0-rc.1").unwrap(),
            Some(UvRunner {
                version: "0.8.0-rc.1"
            })
        );
        assert_eq!(parse_uv_runner("node").unwrap(), None);
        for invalid in [
            "uv",
            "uv@",
            "uv@latest",
            "uv@^0.8",
            "uv@~0.8",
            "uv@0.8 || 0.9",
            "uv@../0.8",
            "uv@0.8/evil",
            "uv@ 0.8",
        ] {
            assert!(
                parse_uv_runner(invalid).is_err(),
                "{invalid} must be refused"
            );
        }
        assert!(is_builtin_runner("uv"));
        assert!(is_builtin_runner("uv@0.8.0"));
        assert!(is_builtin_runner("uv@latest"));
    }
}
