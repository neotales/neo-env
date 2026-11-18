#![cfg(unix)]

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TAG: &str = "v1";

struct Fixture {
    _root: TempDir,
    origin: PathBuf,
    repository: String,
    package_sha256: String,
    project: PathBuf,
    config: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    real_git: PathBuf,
    original_path: String,
    commit: String,
    race_cache: PathBuf,
    marker: PathBuf,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let root = TempDir::new().expect("fixture root");
        let origin = root.path().join("origin.git");
        let work = root.path().join("work");
        let project = root.path().join("project");
        let config = root.path().join("config");
        let bin = root.path().join("bin");
        let log = root.path().join("git-invocations.log");
        let marker = root.path().join("remote-task-ran");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&bin).unwrap();

        let real_git = find_executable("git").expect("system Git must be available");
        let original_path = env::var_os("PATH")
            .expect("test PATH")
            .to_string_lossy()
            .into_owned();
        assert!(!env::split_paths(&original_path).any(|entry| Path::new(&entry) == bin));

        must_git(
            &real_git,
            None,
            &["init", "--bare", origin.to_str().unwrap()],
            "create bare fixture origin",
        );
        let origin = origin.canonicalize().unwrap();
        let repository = format!("file://{}", origin.display());
        must_git(
            &real_git,
            Some(&work),
            &["init", "--initial-branch=main"],
            "create fixture worktree",
        );
        for (key, value) in [
            ("user.email", "fixture@example.test"),
            ("user.name", "nenv Fixture"),
        ] {
            must_git(
                &real_git,
                Some(&work),
                &["config", key, value],
                "configure fixture Git identity",
            );
        }
        fs::write(
            work.join("module.yaml"),
            format!(
                "env:\n  MODULE: remote\ntasks:\n  remote:\n    uses: shell\n    run: 'touch {}'\n",
                marker.display()
            ),
        )
        .unwrap();
        let package_sha256 = format!(
            "{:x}",
            Sha256::digest(fs::read(work.join("module.yaml")).unwrap())
        );
        must_git(
            &real_git,
            Some(&work),
            &["add", "module.yaml"],
            "stage fixture module",
        );
        must_git(
            &real_git,
            Some(&work),
            &["commit", "-m", "initial module"],
            "commit fixture module",
        );
        must_git(
            &real_git,
            Some(&work),
            &["tag", "-a", TAG, "-m", TAG],
            "create annotated fixture tag",
        );
        let origin_string = origin.to_string_lossy().into_owned();
        must_git(
            &real_git,
            Some(&work),
            &["remote", "add", "origin", &origin_string],
            "configure fixture origin",
        );
        must_git(
            &real_git,
            Some(&work),
            &["push", "-q", "origin", "main", TAG],
            "publish fixture refs",
        );
        let commit = String::from_utf8_lossy(
            &git_output(&real_git, Some(&work), &["rev-parse", "HEAD"]).stdout,
        )
        .trim()
        .to_ascii_lowercase();

        let wrapper = bin.join("git");
        fs::write(&wrapper, wrapper_script()).unwrap();
        let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&wrapper, permissions).unwrap();

        fs::write(project.join("neoenv.yaml"), "format_version: 1\n").unwrap();
        let race_cache = root_path_join(&root, "race-cache");

        Self {
            _root: root,
            origin,
            repository,
            package_sha256,
            project,
            config,
            bin,
            log,
            real_git,
            original_path,
            commit,
            race_cache,
            marker,
        }
    }

    #[allow(clippy::unused_self)]
    fn source(&self, reference: &str, subpath: Option<&str>) -> String {
        let mut source = format!("{}@{reference}", self.origin.display());
        if let Some(subpath) = subpath {
            source.push_str("//");
            source.push_str(subpath);
        }
        source
    }

    fn command(&self, arguments: &[&str]) -> Output {
        self.command_with_modes(arguments, false, false)
    }

    fn offline_command(&self, arguments: &[&str]) -> Output {
        self.command_with_modes(arguments, true, false)
    }

    fn race_command(&self, arguments: &[&str]) -> Output {
        self.command_with_modes(arguments, false, true)
    }

    fn command_with_modes(&self, arguments: &[&str], offline: bool, rename_race: bool) -> Output {
        let path = format!("{}:{}", self.bin.display(), self.original_path);
        let mut command = support::TestCommand::new();
        command
            .current_dir(&self.project)
            .env("PATH", path)
            .env("NEOENV_CONFIG_HOME", &self.config)
            .env(
                "NEOENV_CAPABILITY_POLICY",
                self.config.join("neoenv/capabilities.toml"),
            )
            .env_remove("NEOENV_PROJECT")
            .env_remove("NEOENV_GIT_TIMEOUT")
            .env("NEOENV_TEST_REAL_GIT", &self.real_git)
            .env("NEOENV_TEST_GIT_LOG", &self.log)
            .env("NEOENV_TEST_RACE_CACHE", &self.race_cache)
            .env("NEOENV_TEST_OFFLINE", if offline { "1" } else { "0" })
            .env(
                "NEOENV_TEST_RENAME_RACE",
                if rename_race { "1" } else { "0" },
            )
            .env("NO_COLOR", "1");
        for variable in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
        ] {
            command.env_remove(variable);
        }
        command
            .args(arguments)
            .output()
            .expect("compiled nenv binary should start")
    }

    fn cache_path(&self, commit: &str) -> PathBuf {
        self.project
            .join(".neoenv/modules/commits")
            .join(format!("{:x}", Sha256::digest(self.repository.as_bytes())))
            .join(commit)
    }

    fn write_project(&self, source: &str) {
        fs::write(
            self.project.join("neoenv.yaml"),
            format!(
                "task_packages:\n  remote:\n    from: {source:?}\n    task: remote\ntasks:\n  check:\n    uses: package:remote\n"
            ),
        )
        .unwrap();
    }

    fn git(&self, path: &Path, arguments: &[&str]) -> Output {
        git_output(&self.real_git, Some(path), arguments)
    }
}

mod support;

fn root_path_join(root: &TempDir, name: &str) -> PathBuf {
    root.path().join(name)
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find_map(|candidate| {
            candidate
                .is_file()
                .then(|| fs::canonicalize(candidate).ok())
                .flatten()
        })
}

fn git_output(git: &Path, working: Option<&Path>, arguments: &[&str]) -> Output {
    let mut command = Command::new(git);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(working) = working {
        command.arg("-C").arg(working);
    }
    command
        .args(arguments)
        .output()
        .expect("system Git should start")
}

fn must_git(git: &Path, working: Option<&Path>, arguments: &[&str], context: &str) -> Output {
    let output = git_output(git, working, arguments);
    assert!(output.status.success(), "{context}: {output:?}");
    output
}

#[allow(clippy::needless_pass_by_value)]
fn expect_success(output: Output, context: &str) {
    assert!(output.status.success(), "{context}: {output:?}");
    assert!(
        output.stderr.is_empty(),
        "{context} wrote stderr: {output:?}"
    );
}

#[allow(clippy::needless_pass_by_value)]
fn expect_failure(output: Output, code: i32, context: &str) {
    assert_eq!(output.status.code(), Some(code), "{context}: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "{context} wrote stdout: {output:?}"
    );
    assert!(!output.stderr.is_empty(), "{context} had no diagnostic");
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn wrapper_script() -> &'static str {
    r#"#!/usr/bin/env bash
set -euo pipefail
args=()
is_fetch=0
source_path=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "-C" ]]; then
    source_path="$arg"
  fi
  previous="$arg"
  if [[ "$arg" == "fetch" ]]; then
    is_fetch=1
    args+=("-c" "protocol.file.allow=always")
  fi
  args+=("$arg")
done
printf '%s\n' "$*" >> "$NEOENV_TEST_GIT_LOG"
if [[ "$is_fetch" == "1" && "${NEOENV_TEST_OFFLINE:-0}" == "1" ]]; then
  printf '%s\n' 'fixture origin is offline' >&2
  exit 128
fi
if [[ "$is_fetch" == "1" && "${NEOENV_TEST_RENAME_RACE:-0}" == "1" ]]; then
  if "$NEOENV_TEST_REAL_GIT" "${args[@]}"; then
    if [[ -z "$source_path" || -z "${NEOENV_TEST_RACE_CACHE:-}" ]]; then
      exit 91
    fi
    destination="$(dirname "$(dirname "$source_path")")/$(printf '%s\n' "${args[@]}" | tail -n 1)"
    mkdir -p "$destination"
    cp -a "$NEOENV_TEST_RACE_CACHE/." "$destination/"
    exit 0
  else
    status=$?
    exit "$status"
  fi
fi
exec "$NEOENV_TEST_REAL_GIT" "${args[@]}"
"#
}

#[test]
#[allow(clippy::too_many_lines)]
fn compiled_binary_drives_commit_lifecycle_for_a_local_repository() {
    let fixture = Fixture::new();
    let commit = fixture.commit.clone();
    let commit_source = fixture.source(&commit, None);
    let commit_import = fixture.source(&commit, Some("module.yaml"));

    expect_success(
        fixture.command(&["trust", "add", &fixture.repository]),
        "trust add",
    );
    assert!(
        String::from_utf8_lossy(&fixture.command(&["trust", "status"]).stdout)
            .contains(&fixture.repository)
    );

    for (command, source, label) in [
        ("install", commit_source.as_str(), "commit install"),
        ("clear", commit_source.as_str(), "commit install clear"),
        ("fetch", commit_source.as_str(), "commit fetch"),
        ("update", commit_source.as_str(), "commit update"),
    ] {
        expect_success(fixture.command(&["remote", command, source]), label);
    }
    // Refetch the commit after the explicit clear so the offline and cache
    // checks below have a populated cache.
    expect_success(
        fixture.command(&["remote", "fetch", &commit_source]),
        "commit refetch",
    );

    // A tag is a mutable name and this build accepts only commits for a local
    // repository.
    let tag_source = fixture.source(&format!("tag:{TAG}"), None);
    expect_failure(
        fixture.command(&["remote", "fetch", &tag_source]),
        3,
        "local tag fetch",
    );
    assert!(
        String::from_utf8_lossy(&fixture.command(&["remote", "fetch", &tag_source]).stderr)
            .contains("not immutable")
    );

    let log_before_offline = fs::read_to_string(&fixture.log).unwrap_or_default();
    expect_success(
        fixture.offline_command(&["remote", "fetch", &commit_source]),
        "offline cached commit fetch",
    );
    fixture.write_project(&commit_import);
    expect_success(
        fixture.offline_command(&["inspect"]),
        "offline cached commit inspect",
    );
    let log_after_offline = fs::read_to_string(&fixture.log).unwrap();
    assert_eq!(
        log_before_offline.matches(" fetch ").count(),
        log_after_offline.matches(" fetch ").count(),
        "cached commit use attempted a fetch"
    );

    expect_success(
        fixture.command(&["remote", "clear", &commit_source]),
        "clear commit before missing-cache check",
    );
    expect_failure(fixture.command(&["inspect"]), 3, "missing cached commit");
    assert!(String::from_utf8_lossy(&fixture.command(&["inspect"]).stderr).contains("not fetched"));

    expect_success(
        fixture.command(&["remote", "fetch", &commit_source]),
        "commit refetch for integrity checks",
    );
    let commit_cache = fixture.cache_path(&commit);
    fs::write(commit_cache.join("source/module.yaml"), "tampered\n").unwrap();
    expect_failure(
        fixture.command(&["remote", "fetch", &commit_source]),
        3,
        "immutable worktree mismatch",
    );
    assert!(
        String::from_utf8_lossy(&fixture.command(&["remote", "fetch", &commit_source]).stderr)
            .contains("cache does not match")
    );
    fixture.git(
        &commit_cache.join("source"),
        &["checkout", "--", "module.yaml"],
    );
    fs::write(
        commit_cache.join("metadata.toml"),
        format!(
            "repository = {:?}\ncommit = \"not-the-provenance\"\n",
            fixture.repository
        ),
    )
    .unwrap();
    expect_failure(
        fixture.command(&["remote", "fetch", &commit_source]),
        3,
        "corrupted provenance",
    );

    expect_success(
        fixture.command(&["remote", "clear", &commit_source]),
        "clear corrupted commit cache",
    );
    expect_success(
        fixture.command(&["remote", "fetch", &commit_source]),
        "valid commit cache for task grant test",
    );
    fixture.write_project(&commit_import);
    // Execution trust is separate from the repository allowlist and from the
    // capability grant: approve the exact cached file this package names.
    expect_success(
        fixture.command(&["trust", "add", "--remote", &commit_import]),
        "remote file trust",
    );
    expect_failure(
        fixture.command(&["task", "run", "check"]),
        5,
        "package task without execute grant",
    );
    assert!(!fixture.marker.exists());

    let subject = format!("package:{}", fixture.package_sha256);
    fs::write(
        fixture.config.join("neoenv/capabilities.toml"),
        format!("[[grants]]\nsubject = {subject:?}\ncapability = \"execute\"\n"),
    )
    .unwrap();
    expect_success(
        fixture.command(&["task", "run", "check"]),
        "package task with execute grant",
    );
    assert!(fixture.marker.exists());

    expect_success(
        fixture.command(&["trust", "remove", &fixture.repository]),
        "trust remove",
    );
    expect_failure(
        fixture.command(&["remote", "fetch", &commit_source]),
        5,
        "fetch after trust removal",
    );
    assert!(
        String::from_utf8_lossy(&fixture.command(&["remote", "fetch", &commit_source]).stderr)
            .contains("not trusted")
    );
    expect_failure(
        fixture.command(&["trust", "remove", &fixture.repository]),
        4,
        "missing trust entry",
    );
    expect_success(
        fixture.command(&["trust", "add", &fixture.repository]),
        "trust add after removal",
    );

    let log = fs::read_to_string(&fixture.log).unwrap();
    for line in log.lines().filter(|line| line.contains(" fetch ")) {
        assert!(
            line.contains(&fixture.origin.display().to_string()),
            "fixture fetch bypassed the local repository: {line}"
        );
        assert!(
            !line.contains("https://") && !line.contains("git@"),
            "fixture fetch reached a network transport: {line}"
        );
    }
}

#[test]
fn failed_cache_publish_keeps_previous_cache_and_removes_staging_directory() {
    let fixture = Fixture::new();
    let source = fixture.source(&fixture.commit, None);
    expect_success(
        fixture.command(&["trust", "add", &fixture.repository]),
        "race trust add",
    );
    expect_success(
        fixture.command(&["remote", "fetch", &source]),
        "race initial fetch",
    );
    let cache = fixture.cache_path(&fixture.commit);
    copy_tree(&cache, &fixture.race_cache);
    fs::remove_dir_all(&cache).unwrap();

    let output = fixture.race_command(&["remote", "fetch", &source]);
    expect_failure(output, 3, "interrupted cache publish");
    assert!(cache.exists(), "previous valid cache was not preserved");
    let staged = fs::read_dir(cache.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("neoenv-module-")
        })
        .count();
    assert_eq!(staged, 0, "failed publish left a staging directory");

    expect_success(
        fixture.command(&["remote", "fetch", &source]),
        "verify preserved cache after failed publish",
    );
}
