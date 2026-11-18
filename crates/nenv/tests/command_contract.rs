//! Fast, black-box coverage for the complete public `nenv` command surface.
//!
//! The manifest below is deliberately checked against the catalog embedded in
//! the generated Bash completion.  That catalog is emitted from the typed
//! command tree, so adding a visible node without adding a manifest row makes
//! this test fail before the node can ship.  Aliases are expanded from the
//! same catalog and are exercised through the compiled binary as well.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(unix)]
use std::process::Stdio;

#[cfg(unix)]
use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PINNED_REMOTE: &str =
    "github:octo/repo@0123456789abcdef0123456789abcdef01234567//module.yaml";
const INVALID_REMOTE: &str = "not-a-remote-module";
const LOCAL_HTTP: &str = "http://127.0.0.1:9";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureKind {
    Empty,
    Project,
    ToolProject,
    Trust,
    Unicode,
    Workspace,
    ContextProject,
    JobProject,
    InventoryProject,
    ShipProject,
}

// The manifest is the only command-path table. Scenarios describe fixture
// behavior and are intentionally independent of the command names.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    NoArguments,
    GlobalUse,
    ProjectPath,
    Exec,
    TaskRun,
    TaskHelp,
    ToolPath,
    ToolInstall,
    ToolMissing,
    ToolLifecycle,
    ToolPurge,
    TrustRepository,
    WorkspaceList,
    ContextCurrent,
    ContextList,
    ConfigList,
    ConfigGet,
    ConfigSet,
    ConfigUnset,
    JobList,
    JobHelp,
    JobRun,
    InventoryList,
    SshPlan,
    ScpPlan,
    ShipList,
    ShipDeployPlan,
    ShipRollbackPlan,
    ShipDestroyPlan,
    /// `nenv runtime list` against a data directory with nothing installed.
    ///
    /// The empty case is the one worth pinning, because it is the state of every machine
    /// that has not run `global install` -- and it must exit 0, not fail. A query that
    /// cannot answer on a fresh machine is not a query.
    RuntimeList,
    /// `nenv runtime where <name>` for a name that is not installed: a named refusal
    /// that exits non-zero and says how to install it.
    RuntimeWhere,
    RemoteInspect,
    RemoteInvalid,
}

#[derive(Clone, Copy, Debug)]
struct ManifestCase {
    path: &'static str,
    fixture: FixtureKind,
    scenario: Scenario,
    json: bool,
    expected_code: i32,
}

struct Fixture {
    #[allow(
        dead_code,
        reason = "keeps the temp directory alive; Windows tests also read it"
    )]
    root: TempDir,
    work_dir: PathBuf,
    project: PathBuf,
    config_home: PathBuf,
    data_home: PathBuf,
}

impl Fixture {
    fn new(kind: FixtureKind) -> Self {
        let root = TempDir::new().unwrap();
        let project = root.path().join("project with spaces");
        let config_home = root.path().join("config");
        let data_home = root.path().join("data");
        let work_dir = match kind {
            FixtureKind::Empty | FixtureKind::Trust => root.path().to_path_buf(),
            FixtureKind::Project
            | FixtureKind::ToolProject
            | FixtureKind::Unicode
            | FixtureKind::Workspace
            | FixtureKind::ContextProject
            | FixtureKind::JobProject
            | FixtureKind::InventoryProject
            | FixtureKind::ShipProject => {
                fs::create_dir_all(&project).unwrap();
                project.clone()
            }
        };

        match kind {
            FixtureKind::Empty | FixtureKind::Trust => {}
            FixtureKind::Project | FixtureKind::ToolProject => {
                write_standard_project(&project);
            }
            FixtureKind::Unicode => write_unicode_project(&project),
            FixtureKind::Workspace => write_workspace(&project),
            FixtureKind::ContextProject => write_context_project(&project),
            // A project with one job, so `job list`, `job help` and `job run`
            // all have something real to act on. The step writes nothing and
            // creates no file: the manifest drives the binary, and a case that
            // leaves debris behind makes every later case depend on this one.
            FixtureKind::JobProject => write_job_project(&project),
            // The policy goes in the **config home**, at the default path, rather
            // than beside the project. The runner does `env_remove`
            // ("NEOENV_CAPABILITY_POLICY") on purpose so no case can be influenced by
            // the developer's environment, and the default path is
            // `<config>/neoenv/capabilities.toml`. Writing it there means this case
            // exercises the *default* location rather than a special one.
            FixtureKind::InventoryProject => {
                write_inventory_project(&project);
                write_inventory_policy(&config_home);
            }
            FixtureKind::ShipProject => write_ship_project(&project),
        }
        if kind == FixtureKind::ToolProject {
            fs::write(
                project.join("neoenv.lock"),
                "schema_version = 6\ntools = []\n",
            )
            .unwrap();
        }
        if kind == FixtureKind::Trust {
            let trust = config_home.join("neoenv/trust.toml");
            fs::create_dir_all(trust.parent().unwrap()).unwrap();
            fs::write(&trust, "[remote]\nallow = [\"github.com/octo/repo\"]\n").unwrap();
        }

        Self {
            root,
            work_dir,
            project,
            config_home,
            data_home,
        }
    }

    fn command(&self) -> support::TestCommand {
        let mut command = support::TestCommand::new();
        command
            .env("NEOENV_CONFIG_HOME", &self.config_home)
            .current_dir(&self.work_dir)
            .env("NEOENV_DATA_HOME", &self.data_home)
            .env("NEOENV_GITHUB_API_URL", LOCAL_HTTP)
            .env("NEOENV_NPM_REGISTRY", LOCAL_HTTP)
            .env("NEOENV_DOTNET_TOOL_ENDPOINT", LOCAL_HTTP)
            .env("NEOENV_GEM_REGISTRY", LOCAL_HTTP)
            .env("NO_COLOR", "1")
            .env("NO_PROXY", "*")
            .env_remove("NEOENV_PROJECT")
            .env_remove("NEOENV_CONTEXT")
            .env_remove("NEOENV_CAPABILITY_POLICY")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("MISE_GLOBAL_CONFIG_FILE")
            .env_remove("MISE_DATA_DIR");
        command
    }
}

mod support;

fn write_standard_project(project: &Path) {
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
}

/// A project that declares a current context and two task variants, so `context
/// list` has something to report and `context current` has something to resolve.
///
/// **Its own fixture rather than extending `write_standard_project`**, because the
/// standard project declares no contexts and every case here would then be asserting
/// against an empty list -- which passes for a command that reports nothing.
fn write_context_project(project: &Path) {
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\n\
         context: prod\n\
         tasks:\n  \
           check:\n    uses: portable\n    run: 'true'\n  \
           \"check:dev\":\n    extends: check\n  \
           \"check:prod\":\n    extends: check\n",
    )
    .unwrap();
}

fn write_unicode_project(project: &Path) {
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n    inputs:\n      target:\n        type: string\n        position: 0\n        required: true\n",
    )
    .unwrap();
}

/// Declares a workspace with two aliased members and one member with no alias,
/// so the listing has to cover all three orderings.
fn write_workspace(project: &Path) {
    for member in ["packages/api", "packages/web", "tools/standalone"] {
        fs::create_dir_all(project.join(member)).unwrap();
        fs::write(
            project.join(member).join("neoenv.yaml"),
            "format_version: 1\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n",
        )
        .unwrap();
    }
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\nworkspace:\n  members:\n    - packages/api\n    - packages/web\n    - tools/standalone\n  aliases:\n    api: packages/api\n    web: packages/web\ntasks:\n  check:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogEntry {
    path: String,
    spellings: Vec<String>,
}

fn completion_catalog(shell: &str) -> Vec<CatalogEntry> {
    let directory = TempDir::new().unwrap();
    let output = support::TestCommand::new()
        .current_dir(directory.path())
        .env("NEOENV_CONFIG_HOME", directory.path().join("config"))
        .env("NEOENV_DATA_HOME", directory.path().join("data"))
        .env_remove("NEOENV_PROJECT")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .arg("completion")
        .arg(shell)
        .output()
        .unwrap();
    assert!(output.status.success(), "{shell}: {output:?}");
    let script = String::from_utf8(output.stdout).unwrap();
    let mut entries = Vec::new();
    let mut inside = false;
    for line in script.lines() {
        if line == "# neoenv-command-tree-begin" {
            inside = true;
            continue;
        }
        if line == "# neoenv-command-tree-end" {
            break;
        }
        if !inside {
            continue;
        }
        let payload = line
            .strip_prefix("# neoenv-visible ")
            .unwrap_or_else(|| panic!("unexpected catalog line: {line}"));
        let words = payload.split_whitespace().collect::<Vec<_>>();
        let spelling_start = words
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, word)| (words[index - 1] == *word).then_some(index))
            .unwrap_or_else(|| {
                panic!("catalog entry has no repeated canonical spelling: {payload}")
            });
        let invocation = words[..spelling_start].join(" ");
        let path = invocation
            .strip_prefix("nenv ")
            .unwrap_or(invocation.as_str())
            .to_owned();
        let spellings = words[spelling_start..]
            .iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>();
        assert!(
            !spellings.is_empty(),
            "catalog entry has no spellings: {path}"
        );
        entries.push(CatalogEntry { path, spellings });
    }
    assert!(
        !entries.is_empty(),
        "{shell} completion had no command catalog"
    );
    entries
}

// Keep this list exhaustive: the test below compares it with every visible
// path emitted from the command tree.
const MANIFEST: &[ManifestCase] = &[
    ManifestCase {
        path: "nenv",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "init",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "use",
        fixture: FixtureKind::Empty,
        scenario: Scenario::GlobalUse,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "self",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "validate",
        fixture: FixtureKind::Project,
        scenario: Scenario::ProjectPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "inspect",
        fixture: FixtureKind::Project,
        scenario: Scenario::ProjectPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "exec",
        fixture: FixtureKind::Project,
        scenario: Scenario::Exec,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "task",
        fixture: FixtureKind::Project,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "run",
        fixture: FixtureKind::Project,
        scenario: Scenario::TaskRun,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "trust",
        fixture: FixtureKind::Trust,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "workspace",
        fixture: FixtureKind::Workspace,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "remote",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "self init",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "self use",
        fixture: FixtureKind::Empty,
        scenario: Scenario::GlobalUse,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "task list",
        fixture: FixtureKind::Project,
        scenario: Scenario::ProjectPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "task help",
        fixture: FixtureKind::Project,
        scenario: Scenario::TaskHelp,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "task plan",
        fixture: FixtureKind::Project,
        scenario: Scenario::TaskHelp,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "task run",
        fixture: FixtureKind::Project,
        scenario: Scenario::TaskRun,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool plan",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool lock",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool verify",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool install",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolInstall,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool list",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool which",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolMissing,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool where",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolMissing,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool use",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolMissing,
        json: false,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool remove",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolLifecycle,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool update",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolLifecycle,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool pin",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolLifecycle,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool unpin",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolLifecycle,
        json: true,
        expected_code: 4,
    },
    ManifestCase {
        path: "tool purge",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPurge,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "tool cleanup",
        fixture: FixtureKind::ToolProject,
        scenario: Scenario::ToolPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "trust status",
        fixture: FixtureKind::Trust,
        scenario: Scenario::NoArguments,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "trust add",
        fixture: FixtureKind::Trust,
        scenario: Scenario::TrustRepository,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "trust remove",
        fixture: FixtureKind::Trust,
        scenario: Scenario::TrustRepository,
        json: true,
        expected_code: 0,
    },
    // The harness approves fixture files before a command runs, so this
    // scenario revokes a record that exists. A missing record is asserted by
    // the trust unit tests and the execution_trust integration test.
    ManifestCase {
        path: "trust revoke",
        fixture: FixtureKind::Project,
        scenario: Scenario::ProjectPath,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "workspace list",
        fixture: FixtureKind::Workspace,
        scenario: Scenario::WorkspaceList,
        json: true,
        expected_code: 0,
    },
    // The `runtime` group and its two verbs. A group with no manifest case is exactly
    // what the exhaustiveness assertion below is for: it compares the manifest against
    // the command tree, so a new visible command with no case fails here rather than
    // shipping untested.
    ManifestCase {
        path: "secret",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "secret get",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "secret set",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "runtime",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 2,
    },
    ManifestCase {
        path: "runtime list",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RuntimeList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "runtime where",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RuntimeWhere,
        json: false,
        expected_code: 4,
    },
    // The `context` group and its two verbs, plus the group-with-no-subcommand
    // spelling. `nenv context` and `nenv context current` are separate parse paths
    // and both have to work; the group alone is the one that would silently regress,
    // because it is a convenience rather than a documented subcommand.
    // The `config` group and its two verbs. The group alone is the case that would
    // silently regress, because it is a convenience rather than a documented
    // subcommand -- the same reasoning as the `context` group below.
    ManifestCase {
        path: "config",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ConfigList,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "config list",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ConfigList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "config get",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ConfigGet,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        // **The group and both verbs are in the manifest, and the group is the case that
        // would regress silently** -- a convenience rather than a documented subcommand,
        // the same reasoning as the `context` and `job` groups. `config set` is here for
        // the same reason as the other two: a command that exists in the binary and not in
        // the manifest is a command nothing checks.
        path: "config set",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ConfigSet,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        // The removal half, in the manifest for the same reason as `set`: a command
        // in the binary and not here is a command nothing checks.
        path: "config unset",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ConfigUnset,
        json: false,
        // There is nothing to remove in a fresh fixture, so the honest expectation is
        // the refusal. A `0` here would be the manifest asserting a removal that had
        // not happened -- the manifest must not claim a success it did not observe.
        expected_code: 2,
    },
    // The `job` group and its three verbs. The group alone is the case that would
    // regress silently, because it is a convenience rather than a documented
    // subcommand -- the same reasoning as the `context` and `config` groups.
    ManifestCase {
        path: "job",
        fixture: FixtureKind::JobProject,
        scenario: Scenario::JobList,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "job list",
        fixture: FixtureKind::JobProject,
        scenario: Scenario::JobList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "job help",
        fixture: FixtureKind::JobProject,
        scenario: Scenario::JobHelp,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "job run",
        fixture: FixtureKind::JobProject,
        scenario: Scenario::JobRun,
        json: false,
        expected_code: 0,
    },
    // The three host-naming commands. `ssh` and `scp` are the two the reference has
    // and does not execute; `inventory` is ours, and its manifest case is here because
    // a command nothing exercises is a command nothing keeps working.
    ManifestCase {
        path: "inventory",
        fixture: FixtureKind::InventoryProject,
        scenario: Scenario::InventoryList,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "inventory list",
        fixture: FixtureKind::InventoryProject,
        scenario: Scenario::InventoryList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "ssh",
        fixture: FixtureKind::InventoryProject,
        scenario: Scenario::SshPlan,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "scp",
        fixture: FixtureKind::InventoryProject,
        scenario: Scenario::ScpPlan,
        json: true,
        expected_code: 0,
    },
    // `ship` and its three verbs. The plan case is the one that would regress
    // silently: `ship list` works even if the whole resolution rule is wrong, because
    // listing never resolves anything.
    ManifestCase {
        path: "ship",
        fixture: FixtureKind::ShipProject,
        scenario: Scenario::ShipList,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "ship list",
        fixture: FixtureKind::ShipProject,
        scenario: Scenario::ShipList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "ship deploy",
        fixture: FixtureKind::ShipProject,
        scenario: Scenario::ShipDeployPlan,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "ship rollback",
        fixture: FixtureKind::ShipProject,
        scenario: Scenario::ShipRollbackPlan,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "ship destroy",
        fixture: FixtureKind::ShipProject,
        scenario: Scenario::ShipDestroyPlan,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "context",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ContextCurrent,
        json: false,
        expected_code: 0,
    },
    ManifestCase {
        path: "context current",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ContextCurrent,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "context list",
        fixture: FixtureKind::ContextProject,
        scenario: Scenario::ContextList,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "remote inspect",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RemoteInspect,
        json: true,
        expected_code: 0,
    },
    ManifestCase {
        path: "remote fetch",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RemoteInvalid,
        json: true,
        expected_code: 3,
    },
    ManifestCase {
        path: "remote install",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RemoteInvalid,
        json: true,
        expected_code: 3,
    },
    ManifestCase {
        path: "remote update",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RemoteInvalid,
        json: true,
        expected_code: 3,
    },
    ManifestCase {
        path: "remote clear",
        fixture: FixtureKind::Empty,
        scenario: Scenario::RemoteInvalid,
        json: true,
        expected_code: 3,
    },
    ManifestCase {
        path: "help",
        fixture: FixtureKind::Empty,
        scenario: Scenario::NoArguments,
        json: false,
        expected_code: 0,
    },
];

fn path_with_alias(path: &str, alias: &str) -> Vec<String> {
    if path == "nenv" {
        return if alias == "nenv" {
            Vec::new()
        } else {
            vec![alias.to_owned()]
        };
    }
    let mut tokens = path
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let last = tokens
        .last_mut()
        .expect("a command path must contain a node");
    last.clear();
    last.push_str(alias);
    tokens
}

fn action_arguments(scenario: Scenario, fixture: &Fixture) -> Vec<String> {
    let project = fixture
        .project
        .join("neoenv.yaml")
        .to_string_lossy()
        .into_owned();
    match scenario {
        Scenario::NoArguments => Vec::new(),
        Scenario::GlobalUse => {
            vec!["--global".into(), "--dry-run".into(), "node@22.0.0".into()]
        }
        Scenario::ProjectPath | Scenario::ToolPath => vec![project],
        Scenario::Exec => vec![
            "--".into(),
            env!("CARGO_BIN_EXE_nenv").into(),
            "--version".into(),
        ],
        Scenario::TaskRun | Scenario::TaskHelp => vec!["check".into(), project],
        Scenario::ToolInstall => vec!["--locked".into(), project],
        Scenario::ToolMissing => vec!["demo".into(), project],
        Scenario::ToolLifecycle => {
            vec!["--project".into(), "--dry-run".into(), "demo".into()]
        }
        Scenario::ToolPurge => vec!["--project".into(), "--dry-run".into()],
        Scenario::TrustRepository => vec!["github:octo/repo".into()],
        // All four are read-only queries against the fixture as it stands, so none
        // takes an argument. `context` does take an optional path, but the fixture
        // *is* the working directory for these cases, so passing one would only
        // prove that a redundant argument is accepted.
        //
        // `context` is exercised both bare and with the `current` subcommand, and
        // those are two different parse paths that have to produce the same answer.
        // All five are read-only queries against the fixture as it stands, so none
        // takes a path: the fixture *is* the working directory for these cases, and
        // passing one would only prove a redundant argument is accepted.
        //
        // `context` is exercised both bare and with the `current` subcommand, and
        // those are two different parse paths that have to produce the same answer.
        Scenario::WorkspaceList
        | Scenario::RuntimeList
        | Scenario::ContextCurrent
        | Scenario::ContextList
        | Scenario::ConfigList
        | Scenario::JobList
        | Scenario::InventoryList
        // `nenv ship` with nothing after it lists, as do `nenv job` and `nenv
        // inventory`. Grouped with the other argument-free listers rather than given
        // its own arm, because clippy is right that four arms returning `vec![]` are
        // one arm.
        | Scenario::ShipList => vec![],
        // `config get` needs a key, and the fixture declares `context` -- a key that
        // is always present, so this cannot pass by asking for something absent.
        // `config get` and `config unset` are both `config <verb> context [path]`, so
        // their variable arguments are the same. **One arm, not two** -- the first
        // version had a `ConfigUnset` arm with an identical body and clippy was right
        // that the second says nothing.
        Scenario::ConfigGet | Scenario::ConfigUnset => vec!["context".into()],
        // The scenario runs `config set` against a temp HOME, so the write lands there
        // rather than in the developer's real overrides file. `args` is the *variable*
        // part, which is why the key comes first and the path is not repeated.
        Scenario::ConfigSet => vec!["context".into(), "prod".into()],
        // `job help` and `job run` need a job, and the fixture has to declare one
        // that is safe to run in a test: a single `run: true`-shaped step that
        // writes nothing.
        Scenario::JobHelp | Scenario::JobRun => vec!["release".into()],
        // `ssh` and `scp` both need a grant for the host they name, or they refuse
        // before the command under test runs at all -- and a manifest case that
        // asserts a usage error has proven nothing about the command. So the scenario
        // grants `connect` for the one host the fixture declares.
        Scenario::SshPlan => vec!["--plan".into(), "web1".into()],
        Scenario::ScpPlan => vec!["--plan".into(), "a".into(), "web1:/b".into(), "web1".into()],
        // `nenv ship` with nothing after it lists, so no arguments. The scenario
        // supplies only what the *path* does not already carry -- the manifest builds
        // Each verb's plan case carries its own `--plan`, and they are three separate
        // scenarios rather than one shared `--plan` because the manifest builds
        // `path + arguments`: a shared plan argument would be appended to `ship` for
        // the group case too, where it is not a flag at all.
        Scenario::ShipDeployPlan | Scenario::ShipRollbackPlan | Scenario::ShipDestroyPlan => {
            vec!["--plan".into()]
        }
        Scenario::RuntimeWhere => vec!["go".into()],
        Scenario::RemoteInspect => vec![PINNED_REMOTE.into()],
        Scenario::RemoteInvalid => vec![INVALID_REMOTE.into()],
    }
}

fn assert_help(output: &Output) {
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

fn assert_json_document(bytes: &[u8], expected_code: i32) {
    let document: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "expected a JSON diagnostic/report ({error}): {}",
            String::from_utf8_lossy(bytes)
        )
    });
    assert_eq!(document["schema_version"], 1, "{document}");
    if expected_code != 0 {
        assert!(document["diagnostic"]["category"].is_string(), "{document}");
    }
}

fn assert_contract(output: &Output, expected_code: i32, json: bool) {
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "unexpected command result: {output:?}"
    );
    if json {
        if expected_code == 0 {
            assert!(output.stderr.is_empty(), "{output:?}");
            serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .unwrap_or_else(|error| panic!("expected JSON stdout ({error}): {output:?}"));
        } else {
            assert!(output.stdout.is_empty(), "{output:?}");
            assert_json_document(&output.stderr, expected_code);
        }
    } else if expected_code == 0 {
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

fn manifest_case(path: &str) -> &'static ManifestCase {
    MANIFEST
        .iter()
        .find(|case| case.path == path)
        .unwrap_or_else(|| panic!("visible command has no manifest case: {path}"))
}

#[test]
fn visible_manifest_is_exhaustive_and_all_aliases_drive_the_binary() {
    let bash = completion_catalog("bash");
    let mut declared = BTreeMap::new();
    for case in MANIFEST {
        assert!(
            declared.insert(case.path, case).is_none(),
            "duplicate manifest case: {}",
            case.path
        );
    }
    assert_eq!(
        declared.len(),
        bash.len(),
        "manifest and command-tree sizes differ"
    );
    for entry in &bash {
        assert!(
            declared.contains_key(entry.path.as_str()),
            "command-tree node is missing from the fixture manifest: {}",
            entry.path
        );
    }
    for case in MANIFEST {
        assert!(
            bash.iter().any(|entry| entry.path == case.path),
            "manifest case is no longer a visible command-tree node: {}",
            case.path
        );
    }

    for shell in ["zsh", "fish", "powershell", "nushell"] {
        assert_eq!(
            completion_catalog(shell),
            bash,
            "completion catalog drift: {shell}"
        );
    }

    for entry in bash {
        let case = manifest_case(&entry.path);
        for spelling in entry.spellings {
            for help_flag in ["-h", "--help"] {
                let help_fixture = Fixture::new(case.fixture);
                let help = help_fixture
                    .command()
                    .args(path_with_alias(&entry.path, &spelling))
                    .arg(help_flag)
                    .output()
                    .unwrap();
                assert_help(&help);
            }

            let action_fixture = Fixture::new(case.fixture);
            let mut arguments = Vec::new();
            if case.json {
                arguments.extend(["--format".to_owned(), "json".to_owned()]);
            }
            arguments.extend(path_with_alias(&entry.path, &spelling));
            arguments.extend(action_arguments(case.scenario, &action_fixture));
            let action = action_fixture.command().args(arguments).output().unwrap();
            assert_contract(&action, case.expected_code, case.json);

            if case.json {
                let text_fixture = Fixture::new(case.fixture);
                let mut text_arguments = path_with_alias(&entry.path, &spelling);
                text_arguments.extend(action_arguments(case.scenario, &text_fixture));
                let text = text_fixture
                    .command()
                    .args(text_arguments)
                    .output()
                    .unwrap();
                assert_contract(&text, case.expected_code, false);
            }
        }
    }
}

#[test]
fn direct_task_forms_accept_unicode_spaces_and_leading_dash_values() {
    let fixture = Fixture::new(FixtureKind::Unicode);
    let project = fixture.project.to_string_lossy().into_owned();
    let path = fixture.project.join("neoenv.yaml");
    let path = path.to_string_lossy().into_owned();
    let forms = [
        vec!["check", "héllo world", "--", "--leading-dash"],
        vec![
            "run",
            "check",
            path.as_str(),
            "héllo world",
            "--",
            "--leading-dash",
        ],
        vec![
            "r",
            "check",
            path.as_str(),
            "héllo world",
            "--",
            "--leading-dash",
        ],
        vec![
            "task",
            "run",
            "check",
            path.as_str(),
            "héllo world",
            "--",
            "--leading-dash",
        ],
    ];
    for form in forms {
        let output = fixture.command().args(form.clone()).output().unwrap();
        assert!(output.status.success(), "{form:?}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "check Succeeded\n"
        );
    }
    assert!(project.contains(' '));
}

#[test]
fn a_task_shadowing_init_is_only_reachable_through_self() {
    let fixture = Fixture::new(FixtureKind::Project);
    fs::write(
        fixture.project.join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  init:\n    uses: portable\n    run: 'true'\n",
    )
    .unwrap();
    let shortcut = fixture.command().arg("init").output().unwrap();
    assert!(shortcut.status.success(), "{shortcut:?}");
    assert_eq!(
        String::from_utf8(shortcut.stdout).unwrap(),
        "init Succeeded\n"
    );

    let builtin = fixture.command().args(["self", "init"]).output().unwrap();
    assert_eq!(builtin.status.code(), Some(3), "{builtin:?}");
    assert!(String::from_utf8_lossy(&builtin.stderr).contains("already exists"));
}

#[test]
fn no_configuration_and_corrupt_inputs_keep_their_exit_categories() {
    let empty = Fixture::new(FixtureKind::Empty);
    for arguments in [
        vec!["validate"],
        vec!["inspect"],
        vec!["task", "list"],
        vec!["missing-task"],
    ] {
        let output = empty.command().args(arguments.clone()).output().unwrap();
        assert_eq!(output.status.code(), Some(4), "{arguments:?}: {output:?}");
    }

    let corrupt_project = Fixture::new(FixtureKind::Project);
    fs::write(corrupt_project.project.join("neoenv.yaml"), "tasks: [\n").unwrap();
    let invalid = corrupt_project
        .command()
        .args(["validate"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(3), "{invalid:?}");

    let corrupt_lock = Fixture::new(FixtureKind::Project);
    fs::write(
        corrupt_lock.project.join("neoenv.lock"),
        "schema_version = [\n",
    )
    .unwrap();
    let lock_output = corrupt_lock
        .command()
        .args(["tool", "verify"])
        .output()
        .unwrap();
    assert_eq!(lock_output.status.code(), Some(3), "{lock_output:?}");

    let corrupt_cache = Fixture::new(FixtureKind::Project);
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let repository = "github.com/octo/repo";
    let source = format!("github:octo/repo@{commit}//module.yaml");
    let cache = corrupt_cache
        .project
        .join(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository)))
        .join(commit);
    fs::create_dir_all(cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = \"deadbeef\"\n"),
    )
    .unwrap();
    fs::write(
        corrupt_cache.project.join("neoenv.yaml"),
        format!("imports: [{source:?}]\n"),
    )
    .unwrap();
    let trust = corrupt_cache.config_home.join("neoenv/trust.toml");
    fs::create_dir_all(trust.parent().unwrap()).unwrap();
    fs::write(&trust, "[remote]\nallow = [\"github.com/octo/repo\"]\n").unwrap();
    let cache_output = corrupt_cache
        .command()
        .args(["inspect", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(cache_output.status.code(), Some(3), "{cache_output:?}");
    assert!(String::from_utf8_lossy(&cache_output.stderr).contains("cache"));

    let corrupt_global = Fixture::new(FixtureKind::Empty);
    let global = corrupt_global.config_home.join("neoenv/neoenv.toml");
    fs::create_dir_all(global.parent().unwrap()).unwrap();
    fs::write(&global, "global = [\n").unwrap();
    let global_output = corrupt_global
        .command()
        .args(["tool", "which", "demo", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(global_output.status.code(), Some(3), "{global_output:?}");
    assert_json_document(&global_output.stderr, 3);
}

#[test]
fn option_errors_and_output_formats_are_checked_at_the_process_boundary() {
    let cases: &[(&[&str], bool)] = &[
        (&["--format"], false),
        (&["--format", "yaml"], false),
        (&["--format", "json", "--format", "text"], false),
        (&["init", "--format", "yaml"], false),
        (&["inspect", "--context", "dev"], false),
        (&["task", "list", "--format", "yaml"], false),
        (&["task", "run", "check", "--capability-policy"], false),
        (&["tool", "plan", "--locked", "--locked"], false),
        (&["tool", "install"], false),
        (&["tool", "cleanup", "--dry-run", "--dry-run"], false),
        (&["tool", "use", "demo", "--format", "json"], true),
        (&["trust", "add", "--project"], false),
        (&["trust", "status", "--format", "yaml"], false),
        (&["remote", "inspect", PINNED_REMOTE, "--format"], false),
        (&["run", "check", "--capability-policy"], false),
        (&["exec"], false),
    ];
    for (arguments, json) in cases {
        let fixture = Fixture::new(FixtureKind::Project);
        let output = fixture.command().args(*arguments).output().unwrap();
        assert_contract(&output, 2, *json);
    }
}

#[test]
fn text_only_commands_keep_json_as_a_machine_readable_usage_error() {
    let fixture = Fixture::new(FixtureKind::Project);
    let cases: Vec<Vec<String>> = vec![
        vec![
            "use".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--global".to_owned(),
            "--dry-run".to_owned(),
            "node@22.0.0".to_owned(),
        ],
        vec![
            "self".to_owned(),
            "use".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--global".to_owned(),
            "--dry-run".to_owned(),
            "node@22.0.0".to_owned(),
        ],
        vec![
            "exec".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--".to_owned(),
            env!("CARGO_BIN_EXE_nenv").to_owned(),
            "--version".to_owned(),
        ],
    ];
    for arguments in cases {
        let output = fixture.command().args(arguments).output().unwrap();
        assert_contract(&output, 2, true);
    }

    let help = fixture
        .command()
        .args(["help", "--format", "json"])
        .output()
        .unwrap();
    assert!(help.status.success(), "{help:?}");
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
}

#[test]
fn all_reachable_black_box_exit_categories_are_observed() {
    let fixture = Fixture::new(FixtureKind::Project);
    let success = fixture.command().args(["validate"]).output().unwrap();
    assert_eq!(success.status.code(), Some(0));

    let usage = fixture.command().arg("exec").output().unwrap();
    assert_eq!(usage.status.code(), Some(2));

    let invalid = Fixture::new(FixtureKind::Project);
    fs::write(invalid.project.join("neoenv.yaml"), "tasks: [\n").unwrap();
    let validation = invalid.command().arg("validate").output().unwrap();
    assert_eq!(validation.status.code(), Some(3));

    let missing = Fixture::new(FixtureKind::Empty);
    let not_found = missing.command().arg("validate").output().unwrap();
    assert_eq!(not_found.status.code(), Some(4));

    let guarded = Fixture::new(FixtureKind::Project);
    fs::write(
        guarded.project.join("neoenv.yaml"),
        "format_version: 1\ntasks:\n  guarded:\n    uses: portable\n    run: 'true'\n    capabilities: [execute]\n",
    )
    .unwrap();
    let trust = guarded
        .command()
        .args(["task", "run", "guarded"])
        .output()
        .unwrap();
    assert_eq!(trust.status.code(), Some(5), "{trust:?}");

    let runtime = fixture
        .command()
        .args(["exec", "missing-command"])
        .output()
        .unwrap();
    assert_eq!(runtime.status.code(), Some(6), "{runtime:?}");
}

/// Whether this process is root, and therefore whether a permission bit means
/// anything at all.
///
/// `std` has no `geteuid`, and the workspace sets `unsafe_code = "forbid"`, so
/// the answer comes from `id -u`. That is a subprocess in a test, which is
/// unremarkable next to the alternative of hand-rolling a libc declaration behind
/// an `unsafe` the whole workspace refuses.
#[cfg(unix)]
fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse::<u32>().ok())
        .is_some_and(|uid| uid == 0)
}

#[cfg(unix)]
#[test]
fn a_read_only_directory_reports_a_runtime_error_without_writing() {
    // **This test cannot establish its claim as root, and it must say so rather
    // than pass or fail.**
    //
    // Permission bits are advisory to uid 0. `chmod 0555` on a directory does
    // not stop root from creating a file in it, so `nenv init` succeeds, and the
    // assertion below -- that the write failed with a runtime error -- is false
    // rather than the code being wrong.
    //
    // That is not hypothetical. It is how this test failed the first time it ran
    // in a container: Gitea's runner executes jobs as root, every developer runs
    // as a normal user, and the test was green on every machine and red on the
    // one nobody had run it on. The failure was in the environment, and the
    // diagnostic said nothing about the environment.
    //
    // Which of the two is right matters:
    //
    // - Failing makes the gate red for a reason that is not a defect, which
    //   trains people to re-run, and re-running until green is how a real
    //   intermittent failure gets merged.
    // - Passing silently makes the count a lie: the README says every test runs,
    //   and this one does not.
    //
    // So it prints a skip with the reason and returns. `--nocapture` shows it, so
    // it is distinguishable from a pass, which is the whole requirement. A skip
    // that leaves no trace is the thing to avoid, not a skip.
    if running_as_root() {
        eprintln!(
            "SKIPPED a_read_only_directory_reports_a_runtime_error_without_writing: \
             running as uid 0, and permission bits are advisory to root, so the \
             property under test cannot be established here. It is covered on any \
             non-root checkout."
        );
        return;
    }

    let fixture = Fixture::new(FixtureKind::Empty);
    let mut permissions = fs::metadata(&fixture.work_dir).unwrap().permissions();
    permissions.set_mode(0o555);
    fs::set_permissions(&fixture.work_dir, permissions).unwrap();
    let output = fixture.command().arg("init").output().unwrap();
    let mut writable = fs::metadata(&fixture.work_dir).unwrap().permissions();
    writable.set_mode(0o755);
    fs::set_permissions(&fixture.work_dir, writable).unwrap();
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(!fixture.work_dir.join("neoenv.toml").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn a_non_interactive_macos_path_can_run_an_absolute_project_command() {
    let fixture = Fixture::new(FixtureKind::Project);
    let output = fixture
        .command()
        .env("PATH", "/usr/bin:/bin")
        .args(["exec", "/bin/sh", "-c", "printf macos-path-ok"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "macos-path-ok");
}

#[cfg(windows)]
#[test]
fn windows_exec_finds_git_usr_bin_and_honors_pathext() {
    let fixture = Fixture::new(FixtureKind::Project);
    // Git for Windows puts its MSYS utilities on PATH through a `usr\bin`
    // entry, and a `.cmd` shim resolves through PATHEXT. `cmd.exe` searches the
    // current directory and PATH, not `%ProgramFiles%`, so the fixture has to
    // live on PATH to exercise the real resolution order.
    // Join separate components so PATH uses native backslashes: cmd.exe's batch
    // lookup does not accept the mixed separators retained by join("Git/usr/bin").
    let git_bin = fixture.root.path().join("Git").join("usr").join("bin");
    fs::create_dir_all(&git_bin).unwrap();
    fs::write(git_bin.join("git.cmd"), "@echo off\r\necho fixture-git\r\n").unwrap();
    let path = fixture.root.path().join("empty-path");
    fs::create_dir_all(&path).unwrap();
    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let cmd = PathBuf::from(system_root).join("System32").join("cmd.exe");
    let cmd = cmd.to_string_lossy().into_owned();
    let search_path = format!(
        "{};{};{}",
        git_bin.display(),
        path.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = fixture
        .command()
        .env("PATH", &search_path)
        .env("PATHEXT", ".EXE;.CMD;.BAT")
        .args(["exec", cmd.as_str(), "/d", "/c", "call", "git.cmd"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture-git"));
}

#[cfg(windows)]
#[test]
fn windows_locked_state_reports_a_runtime_error() {
    let fixture = Fixture::new(FixtureKind::ToolProject);
    let lock = fixture.project.join("neoenv.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&lock)
        .unwrap();
    let output = fixture.command().args(["tool", "lock"]).output().unwrap();
    drop(file);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
}

#[cfg(unix)]
struct DelayedServer {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl DelayedServer {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let server_stop = Arc::clone(&stop);
        let server_requests = Arc::clone(&requests);
        let thread = std::thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        server_requests.fetch_add(1, Ordering::AcqRel);
                        let mut request = [0_u8; 2048];
                        let _ = stream.read(&mut request);
                        std::thread::sleep(Duration::from_millis(1_000));
                        let body = b"{\"message\":\"deliberately delayed\"}";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn interrupting_a_loopback_provider_operation_leaves_no_global_state() {
    let fixture = Fixture::new(FixtureKind::Empty);
    let server = DelayedServer::start();
    let endpoint = format!("http://{}/", server.address);
    let child = fixture
        .command()
        .env("NEOENV_GITHUB_API_URL", &endpoint)
        .args(["use", "--user", "gh:octo/repo@1.0.0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if server.requests.load(Ordering::Acquire) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(server.requests.load(Ordering::Acquire) > 0);
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = child.wait_with_output().unwrap();
    server.stop();
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(!fixture.config_home.exists());
    assert!(!fixture.data_home.exists());
}

/// A project with one job, for the `job` manifest cases.
///
/// The single step is a `run:` that prints, so `job run` executes something real and
/// leaves nothing behind. A `task:` step would have needed a task, and a second
/// fixture for the same project -- two fixtures that must agree, which is a way to
/// write a test that passes for the wrong reason.
fn write_job_project(project: &Path) {
    fs::create_dir_all(project).unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\n\
         tasks:\n  \
           build:\n    uses: portable\n    run: echo built\n\
         jobs:\n  \
           release:\n    desc: The one job\n    steps:\n      - task: build\n",
    )
    .unwrap();
}

/// A project with one inventory and one host, for the host-naming manifest cases.
///
/// One host, not three: the manifest drives the binary, and a case that depends on
/// which of several hosts happens to be granted is a case whose result depends on the
/// policy file the scenario wrote.
/// A `connect` grant for the one host the inventory fixture declares.
///
/// At the default policy location, so the `ssh` and `scp` manifest cases reach the
/// plan instead of stopping at the capability refusal — and so a case whose only
/// result is "it refused" cannot pass for the wrong reason.
fn write_inventory_policy(config_home: &Path) {
    let dir = config_home.join("neoenv");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("capabilities.toml"),
        "[[grants]]\nsubject = \"inventory:default/host:web1\"\ncapability = \"connect\"\n",
    )
    .unwrap();
}

fn write_inventory_project(project: &Path) {
    fs::create_dir_all(project).unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\n\
         inventories:\n  \
           default:\n    \
             hosts:\n      \
               web1:\n        \
                 tags: [prod]\n\
         tasks:\n  \
           build:\n    \
             uses: portable\n    \
             run: echo hi\n",
    )
    .unwrap();
}

/// A project with two deployments, the second context-qualified.
///
/// The qualified key is here because a `ship` case that only ever resolved the bare
/// one would pass with the whole context rule removed — `list` never resolves, and
/// `deploy` with no name substitutes `default`, which is the bare key.
fn write_ship_project(project: &Path) {
    fs::create_dir_all(project).unwrap();
    fs::write(
        project.join("neoenv.yaml"),
        "format_version: 1\n\
         deployments:\n  \
           default:\n    \
             type: service\n    \
             desc: The public service\n  \
           \"default:prod\":\n    \
             type: service\n    \
             desc: The production service\n\
         tasks:\n  \
           build:\n    \
             uses: portable\n    \
             run: echo hi\n",
    )
    .unwrap();
}
