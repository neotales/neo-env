//! Every filename and directory name `nenv` recognises, in one place.
//!
//! # Why this file exists
//!
//! The product is called `nenv`. The files it reads and the directories it keeps
//! user data in are called `neoenv`. Both are the product's name, both appear as
//! a bare `neoenv` in the same source file, and renaming the binary is a
//! find-and-replace away from renaming the data.
//!
//! That replace does not fail loudly. `nenv` looks in `~/.config/nenv/`, finds
//! nothing, and reports no configuration -- indistinguishable from a user who
//! genuinely has none. Every existing configuration file, trust record, module
//! cache and installed tool becomes invisible on upgrade, with no error and no
//! symptom. It is the worst failure mode this codebase produces, and a rename is
//! the most likely thing to cause it.
//!
//! The first attempt at this rename got it wrong in seven places, and every one
//! of them was a *filename* (`neoenv.module.yaml`, `neoenv.task.toml`) or a
//! *path* (`neoenv/tasks/`) rather than a bare word. A grep for the bare word
//! finds none of them. So the names live here as data, the code reads them from
//! here, and the test `the_names_are_still_the_ones_on_disk` fails if one of them
//! is ever changed by accident. It is named in plain text rather than linked
//! because it is private to this module, and a link to a private item is itself a
//! documentation error.
//!
//! # What is deliberately not here
//!
//! `NEOENV_CONFIG_HOME` and its siblings are environment variables, not
//! filenames, and they are a different decision: renaming those needs a
//! deprecated alias, which is its own ticket. The five library crate names
//! (`neoenv-core` and friends) are not published anywhere and are not ours to
//! churn.

/// The `nenv` directory under a user directory root: `~/.config/neoenv`,
/// `~/.local/share/neoenv`, and so on. Holds configuration, trust records,
/// installed tools and the module cache.
///
/// This is *user data*. Changing it is a migration, not a rename.
pub const USER_DIRECTORY: &str = "neoenv";

/// The per-project state directory: `<project>/.neoenv`. Holds `tools/`,
/// `artifacts/` and `modules/`.
///
/// This is *user data*, and it is git-ignored in every project that uses nenv.
pub const PROJECT_DIRECTORY: &str = ".neoenv";

/// Prefix for the temporary backup file used while a `tmpl` commit rolls back.
/// It lives beside the destination and is removed on success.
pub const TMPL_BACKUP_PREFIX: &str = ".neoenv-tmpl-backup";

/// The lockfile. Its name is internal state rather than a published format, so
/// it is the cheapest of these to rename -- but it is still a file a user has,
/// and a `nenv` that cannot find its lockfile reinstalls everything.
pub const LOCKFILE: &str = "neoenv.lock";

/// The module cache, under the data directory.
pub const MODULE_CACHE: &str = "modules";

/// Downloaded artifact bytes, under the project or data directory.
pub const ARTIFACT_DIRECTORY: &str = "artifacts";

/// Installed tool trees, under the project or data directory.
pub const TOOL_DIRECTORY: &str = "tools";

/// The private overlay inside a project. It may not traverse out of the project
/// root, and it is expected to be git-ignored.
pub const PRIVATE_DIRECTORY: &str = "private";

/// The trust allow-list, under the configuration directory.
pub const TRUST_FILE: &str = "neoenv/trust.toml";

/// The capability grant record, under the configuration directory.
pub const CAPABILITIES_FILE: &str = "neoenv/capabilities.toml";

/// A module's own configuration file, inside a module directory.
pub const MODULE_FILE_YAML: &str = "neoenv.module.yaml";

/// As [`MODULE_FILE_YAML`], for a module that prefers the short extension.
pub const MODULE_FILE_YML: &str = "neoenv.module.yml";

/// The task-package root under the data directory: `<data>/neoenv/tasks`.
///
/// This is the name the rename got wrong. It is a *path*, not a bare word, so a
/// grep for the bare word finds none of it -- which is why it is here, and why
/// `no_name_on_disk_begins_with_the_current_product_name` can see it.
pub const GLOBAL_TASK_DIRECTORY: &str = "neoenv/tasks";

/// The projects file, under the configuration directory.
pub const PROJECTS_FILE: &str = "neoenv/projects.toml";

/// The synthetic Go module path used to resolve a Go module dependency.
///
/// Not a file, but it is an identity that reaches disk: it goes into a generated
/// `go.mod` whose content is hashed, so changing it changes the digest and
/// therefore the resolution. It is here because it is spelled like a path and
/// nobody would think to look for it.
pub const GO_RESOLVE_MODULE: &str = "neoenv.local/resolve";

/// As [`GO_RESOLVE_MODULE`], for the install path.
pub const GO_INSTALL_MODULE: &str = "neoenv.local/install";

/// A tool's install metadata, written beside the installed binary.
pub const INSTALL_METADATA: &str = ".neoenv-install.toml";

/// The receipt naming the artifact a tool was installed from.
pub const INSTALL_RECEIPT: &str = ".neoenv-artifact-sha256";

/// SHA-256 receipt for the managed Go SDK archive.
pub const GO_SDK_RECEIPT: &str = ".neoenv-go-sdk-sha256";
/// SHA-256 receipt for the managed Node.js archive.
pub const NODE_RUNTIME_RECEIPT: &str = ".neoenv-node-sha256";
/// SHA-512 receipt for the managed .NET SDK archive.
pub const DOTNET_SDK_RECEIPT: &str = ".neoenv-dotnet-sdk-sha512";
/// SHA-256 receipt for the managed Zig archive.
pub const ZIG_RUNTIME_RECEIPT: &str = ".neoenv-zig-sha256";
/// SHA-256 receipt for the managed Deno archive.
pub const DENO_RUNTIME_RECEIPT: &str = ".neoenv-deno-sha256";
/// SHA-256 receipt for the managed uv archive.
pub const UV_RUNTIME_RECEIPT: &str = ".neoenv-uv-sha256";
/// SHA-256 receipt for the managed Rust toolchain archive.
pub const RUST_RUNTIME_RECEIPT: &str = ".neoenv-rust-sha256";
/// SHA-256 receipt for the managed Odin archive.
pub const ODIN_RUNTIME_RECEIPT: &str = ".neoenv-odin-sha256";
/// SHA-256 receipt for the managed Python archive.
pub const PYTHON_RUNTIME_RECEIPT: &str = ".neoenv-python-sha256";
/// SHA-256 receipt for the managed Bun archive.
pub const BUN_RUNTIME_RECEIPT: &str = ".neoenv-bun-sha256";
/// SHA-256 receipt for the managed Java archive.
pub const JAVA_RUNTIME_RECEIPT: &str = ".neoenv-java-sha256";

/// The marker recording that nenv owns a globally installed tree.
///
/// A leading dot inside a version directory, not a directory of its own, so it is
/// invisible to a `ls` that is not looking for it.
pub const GLOBAL_OWNERSHIP_MARKER: &str = ".neoenv-owned";

/// The lock beside a *lockfile*, as opposed to a state file. Distinct from
/// [`STATE_LOCK_SUFFIX`], and deliberately so: a lockfile's lock and a state
/// file's lock guard different things and are not interchangeable.
pub const LOCKFILE_LOCK_SUFFIX: &str = ".neoenv.lock";

/// The project-scoped installed-tool directory, dotted: `<project>/.neoenv/tools`.
///
/// Distinct from [`TOOL_DIRECTORY`], which is the *global* one. The asymmetry is
/// deliberate and documented at `ToolStorage::global`: a global installation is
/// handed the data root itself, so it must not acquire a second project-style
/// `.neoenv` component.
pub const PROJECT_TOOL_DIRECTORY: &str = ".neoenv/tools";

/// The project-scoped artifact cache, dotted: `<project>/.neoenv/artifacts`.
pub const PROJECT_ARTIFACT_DIRECTORY: &str = ".neoenv/artifacts";

/// The global tool configuration file, under the configuration directory.
///
/// Not [`PROJECT_FILENAMES`]: this is the file `nenv use -g` records selected
/// versions in, and it is not a project configuration anybody hand-writes. It
/// has its own name so that a future change to the project filenames does not
/// silently move a user's global record.
pub const GLOBAL_CONFIG_FILE: &str = "neoenv.toml";

/// The extracted-module area inside a project's state directory.
pub const PROJECT_MODULE_CACHE: &str = ".neoenv/modules";

/// Where an unpacked module tarball is staged inside the project cache.
pub const MODULE_TARBALLS: &str = ".neoenv/modules/tarballs";

/// The coordination lock beside a state file.
///
/// Deliberately a sibling rather than the state file itself: replacing the state
/// inode must not release a lock another writer holds.
pub const STATE_LOCK_SUFFIX: &str = ".neoenv-state.lock";

/// The prefix of the unpredictable temporary a state write is prepared in.
pub const STATE_TEMPORARY_PREFIX: &str = ".neoenv-state-";

/// A task package's configuration file, inside a task package directory.
pub const TASK_FILE_YAML: &str = "neoenv.task.yaml";

/// As [`TASK_FILE_YAML`], in TOML.
pub const TASK_FILE_TOML: &str = "neoenv.task.toml";

/// Every configuration filename a project may use, highest precedence first.
///
/// The order is a contract: a directory holding two of these is ambiguous, and
/// ambiguity resolved silently is a wrong answer with no symptom. See
/// `neoenv_config::sources` for what happens when two are present.
pub const PROJECT_FILENAMES: &[&str] = &["neoenv.yaml", "neoenv.yml", "neoenv.toml", ".neoenv"];

/// The files a module directory may be configured by, highest precedence first.
pub const MODULE_FILENAMES: &[&str] = &[
    MODULE_FILE_YAML,
    MODULE_FILE_YML,
    "neoenv.yaml",
    "neoenv.yml",
    "neoenv.toml",
];

/// The task-package filenames a task directory may be configured by.
pub const TASK_PACKAGE_FILENAMES: &[&str] = &[TASK_FILE_YAML, TASK_FILE_TOML];

/// Every name above, so a test can assert the whole set at once.
pub const ALL_NAMES: &[&str] = &[
    USER_DIRECTORY,
    PROJECT_DIRECTORY,
    TMPL_BACKUP_PREFIX,
    LOCKFILE,
    MODULE_CACHE,
    ARTIFACT_DIRECTORY,
    TOOL_DIRECTORY,
    PRIVATE_DIRECTORY,
    TRUST_FILE,
    CAPABILITIES_FILE,
    MODULE_FILE_YAML,
    MODULE_FILE_YML,
    TASK_FILE_YAML,
    TASK_FILE_TOML,
    GLOBAL_TASK_DIRECTORY,
    PROJECTS_FILE,
    GO_RESOLVE_MODULE,
    GO_INSTALL_MODULE,
    INSTALL_METADATA,
    INSTALL_RECEIPT,
    GO_SDK_RECEIPT,
    NODE_RUNTIME_RECEIPT,
    DOTNET_SDK_RECEIPT,
    ZIG_RUNTIME_RECEIPT,
    DENO_RUNTIME_RECEIPT,
    UV_RUNTIME_RECEIPT,
    RUST_RUNTIME_RECEIPT,
    ODIN_RUNTIME_RECEIPT,
    PYTHON_RUNTIME_RECEIPT,
    BUN_RUNTIME_RECEIPT,
    JAVA_RUNTIME_RECEIPT,
    GLOBAL_OWNERSHIP_MARKER,
    STATE_LOCK_SUFFIX,
    STATE_TEMPORARY_PREFIX,
    LOCKFILE_LOCK_SUFFIX,
    PROJECT_MODULE_CACHE,
    MODULE_TARBALLS,
    PROJECT_TOOL_DIRECTORY,
    PROJECT_ARTIFACT_DIRECTORY,
    GLOBAL_CONFIG_FILE,
    "neoenv.yaml",
    "neoenv.yml",
    "neoenv.toml",
    ".neoenv",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The names on disk are still spelled `neoenv`.
    ///
    /// The assertion is written out longhand rather than looping, on purpose. A
    /// loop over [`ALL_NAMES`] would compare the constant against itself and
    /// pass no matter what somebody changed the constants to, which is the
    /// mistake this test exists to catch. Each line below is a separate claim
    /// about a separate file, so a failure names the file that moved.
    #[test]
    fn the_names_are_still_the_ones_on_disk() {
        assert_eq!(USER_DIRECTORY, "neoenv", "the user data directory moved");
        assert_eq!(
            PROJECT_DIRECTORY, ".neoenv",
            "the project state directory moved"
        );
        assert_eq!(
            TMPL_BACKUP_PREFIX, ".neoenv-tmpl-backup",
            "the template backup prefix moved"
        );
        assert_eq!(LOCKFILE, "neoenv.lock", "the lockfile name moved");
        assert_eq!(TRUST_FILE, "neoenv/trust.toml", "the trust file moved");
        assert_eq!(
            CAPABILITIES_FILE, "neoenv/capabilities.toml",
            "capabilities moved"
        );
        assert_eq!(
            MODULE_FILE_YAML, "neoenv.module.yaml",
            "the module filename moved"
        );
        assert_eq!(
            MODULE_FILE_YML, "neoenv.module.yml",
            "the module filename moved"
        );
        assert_eq!(
            TASK_FILE_YAML, "neoenv.task.yaml",
            "the task filename moved"
        );
        assert_eq!(
            TASK_FILE_TOML, "neoenv.task.toml",
            "the task filename moved"
        );
    }

    /// Nothing in this module is spelled with the product's *current* name.
    ///
    /// This is the assertion that would have caught the seven wrong renames. A
    /// name on disk that starts with `nenv` is always a mistake: there is no
    /// file called `nenv.yaml`, no directory called `nenv/tasks`, and no
    /// product is helped by one appearing.
    #[test]
    fn no_name_on_disk_begins_with_the_current_product_name() {
        for name in ALL_NAMES {
            assert!(
                !name.starts_with("nenv"),
                "`{name}` is a filename or directory, and no such file should be \
                 named after the current product. Either the rename was applied \
                 here by mistake, or this list is wrong."
            );
        }
    }

    /// The project filenames are ordered, and the order is what discovery uses.
    ///
    /// Asserted as a whole array because the *sequence* is the contract, and a
    /// set comparison would pass with the precedence reversed.
    #[test]
    fn project_filenames_are_in_precedence_order() {
        assert_eq!(
            PROJECT_FILENAMES,
            &["neoenv.yaml", "neoenv.yml", "neoenv.toml", ".neoenv"]
        );
    }

    /// A module directory prefers its own dedicated filename.
    ///
    /// A module is its own document, so `neoenv.module.yaml` has to win over a
    /// bare `neoenv.yaml` sitting beside it -- otherwise a module in a
    /// directory that also happens to contain a project config reads the wrong
    /// file, and the diagnostic names a path that looks correct.
    #[test]
    fn a_module_document_prefers_its_own_filename() {
        assert_eq!(MODULE_FILENAMES[0], MODULE_FILE_YAML);
        assert_eq!(MODULE_FILENAMES[1], MODULE_FILE_YML);
        assert!(
            MODULE_FILENAMES.contains(&"neoenv.yaml"),
            "a module must still be configurable with a bare filename"
        );
    }

    /// The two spellings of the user directory and the project directory differ
    /// by exactly one character, which is the whole problem.
    ///
    /// If this ever stops being true the confusability argument is weaker and
    /// this file's reasoning needs revisiting -- so it is asserted rather than
    /// assumed.
    #[test]
    fn the_two_directory_names_differ_by_one_character() {
        assert_eq!(PROJECT_DIRECTORY, format!(".{USER_DIRECTORY}"));
    }
}

/// Every on-disk name in the six crates is a `names::` reference.
///
/// This is the assertion that makes this module a single source of truth rather
/// than a list somebody maintains. It reads the source of the other five crates
/// at test time and requires that any string literal which names a file or
/// directory `nenv` touches is spelled here.
///
/// It exists because the list was incomplete and nothing noticed. The rename got
/// `neoenv/tasks/`, `neoenv.module.yaml`, `neoenv.task.toml`, `neoenv.local/resolve`
/// and six more wrong, and a grep for the bare word `neoenv` finds none of them,
/// because they are paths and filenames rather than bare words. A list that
/// documents the convention but is not checked against the code is a comment.
///
/// The check is deliberately narrow. It looks for string literals containing
/// `neoenv` that are *not* already a `names::` reference, and it excludes the
/// ones that are legitimately not names:
///
/// - anything under `#[cfg(test)]`, because a test's fixture data is not a
///   contract;
/// - `NEOENV_`-prefixed strings, which are environment variable names and are
///   covered by a different ticket;
/// - `neoenv_core::`, `neoenv_runtime::` and friends, which are module paths.
#[cfg(test)]
mod source_is_the_module {
    use std::path::{Path, PathBuf};

    /// Crates whose on-disk names belong to this module. The five `neoenv-*`
    /// crates plus the binary, which is where `init` writes a configuration file.
    const CRATES: &[&str] = &[
        "crates/neoenv-config",
        "crates/neoenv-core",
        "crates/neoenv-installer",
        "crates/neoenv-policy",
        "crates/neoenv-runtime",
        "crates/nenv",
    ];

    fn repository_root() -> PathBuf {
        // CARGO_MANIFEST_DIR is `.../crates/neoenv-core`, so the root is two up.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("neoenv-core is two directories below the repository root")
            .to_path_buf()
    }

    /// Every production `.rs` file in `crates`, paired with its path.
    ///
    /// Restricted to `src/`, and to the lines before the first `#[cfg(test)]` in
    /// each file. Both are because test data is not a contract: a fixture's own
    /// `neoenv/tasks/local.yaml` is a path a test writes, not a path the program
    /// promises.
    ///
    /// The second restriction is a layout assumption rather than a parse.
    /// Tracking a `#[cfg(test)] mod` to its closing brace by counting braces does
    /// not work here, because the fixtures are full of `{` and `}` inside string
    /// literals and the count drifts. Assuming tests come last is true of every
    /// file in these six crates.
    ///
    /// This check was written three times before it was narrow enough to be
    /// trusted, and each earlier version reported twenty or more false positives
    /// on first run. That is the relevant lesson: **a gate that needs a growing
    /// pile of exclusions to avoid crying wolf will eventually be muted, and a
    /// muted gate is worse than no gate.** So it is scoped to the narrow shape
    /// that actually caused the bug -- a name in production code -- and the
    /// constants plus their longhand assertions carry the rest.
    fn sources() -> Vec<(PathBuf, String)> {
        let root = repository_root();
        let mut found = Vec::new();
        for crate_path in CRATES {
            collect(&root.join(crate_path), &mut found);
        }
        assert!(
            found.len() > 50,
            "only found {} source files, so this check is not looking at the tree \
             it thinks it is",
            found.len()
        );
        found
    }

    fn collect(directory: &Path, into: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // This module is the definition, so every literal in it is expected.
            if path.file_name().is_some_and(|n| n == "names.rs") {
                continue;
            }
            if path.is_dir() {
                collect(&path, into);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // `src/` and `benches/`. A `tests/` directory is the integration
                // suite; a `tests.rs` or `compat_tests.rs` file is a unit-test
                // module pulled in by a `#[cfg(test)] mod` elsewhere. Neither is
                // production. A bench is: `cargo test --all-targets` compiles it,
                // and this repository's bench writes real paths.
                if !path
                    .components()
                    .any(|c| c.as_os_str() == "src" || c.as_os_str() == "benches")
                {
                    continue;
                }
                let stem = path
                    .file_stem()
                    .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
                if stem.ends_with("tests") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    // Everything from the first `#[cfg(test)]` onwards is test
                    // data. See the note on `sources`.
                    let production = match text.find("#[cfg(test)]") {
                        Some(at) => &text[..at],
                        None => &text[..],
                    };
                    into.push((path, production.to_owned()));
                }
            }
        }
    }

    /// Is this line a place where a name is *defined* rather than used?
    ///
    /// A `const NAME: &str = "neoenv.lock";` is the definition, and it is
    /// exempt. A use is a literal that is not the whole right-hand side of a
    /// `const`, which is the only shape this project writes definitions in.
    fn is_a_definition(line: &str) -> bool {
        let trimmed = line.trim_start();
        (trimmed.starts_with("const ") || trimmed.starts_with("pub const "))
            && trimmed.contains(": &str = ")
    }

    fn is_exempt(line: &str) -> bool {
        // A module path, not a filename.
        line.contains("neoenv_core::")
            || line.contains("neoenv_config::")
            || line.contains("neoenv_runtime::")
            || line.contains("neoenv_installer::")
            || line.contains("neoenv_policy::")
            // An environment variable, covered by its own ticket.
            || line.contains("NEOENV_")
            // This module, defining and documenting the names.
            || line.contains("names::")
    }

    #[test]
    fn no_string_literal_names_a_file_without_going_through_this_module() {
        let mut offenders: Vec<String> = Vec::new();

        for (path, text) in sources() {
            for (number, line) in text.lines().enumerate() {
                if is_exempt(line) || is_a_definition(line) {
                    continue;
                }

                // A literal that contains `neoenv` and is shaped like a name:
                // starts with it, or is a path component under it.
                let Some(start) = line.find('"') else {
                    continue;
                };
                let rest = &line[start + 1..];
                let Some(end) = rest.find('"') else {
                    continue;
                };
                let literal = &rest[..end];

                let names_a_file = literal.contains("neoenv")
                    && (literal.contains('/')
                        || literal.contains(".yaml")
                        || literal.contains(".yml")
                        || literal.contains(".toml")
                        || literal.contains(".lock")
                        || literal.starts_with(".neoenv")
                        || literal == "neoenv");

                if names_a_file {
                    offenders.push(format!(
                        "{}:{}: {literal:?}",
                        path.file_name()
                            .expect("a path component")
                            .to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "these literals name a file or directory without referring to \
             neoenv_core::names, so nothing pins them and nothing would notice a \
             rename moving them:\n  {}\n\nAdd the name to lib/neoenv-core/src/names.rs \
             and refer to it, or add it to the exemption with a reason.",
            offenders.join("\n  ")
        );
    }
}
