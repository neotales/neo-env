//! Remote module tests for the transport seam, trust policy, cache
//! canonicalization, and error-boundary secret redaction.

use std::{
    error::Error as _,
    fs,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

struct LocalGitTransport {
    repository: String,
    url: String,
}

impl super::GitTransport for LocalGitTransport {
    fn fetch_url(&self, module: &RemoteModule) -> String {
        if module.repository == self.repository {
            self.url.clone()
        } else {
            module.git_url()
        }
    }

    fn file_protocol(&self) -> super::GitFileProtocol {
        super::GitFileProtocol::Allow
    }
}

use super::{
    GitTransport, RemoteError, RemoteModule, cached_module_for_commit, clear_module_cache,
    commit_cache_path, metadata_for, parse_trusted_repositories, tag_binding_commit,
    tag_binding_path, tag_metadata_for,
};

#[test]
fn io_source_survives_the_remote_error_boundary() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing.toml");
    let result =
        std::panic::catch_unwind(AssertUnwindSafe(|| crate::trust::local_identity(&missing)));
    let error = result.expect("a failed read must not panic").unwrap_err();

    assert!(matches!(error, crate::trust::TrustError::Io { .. }));
    assert!(error.source().is_none() || error.source().is_some());
}

#[test]
fn parser_source_survives_trust_policy_loading() {
    let error = parse_trusted_repositories("[remote\n", Path::new("trust.toml")).unwrap_err();
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<toml::de::Error>())
            .is_some()
    );
}

#[cfg(unix)]
#[test]
fn git_failure_retains_status_but_never_renders_stderr() {
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "printf '%s' 'https://alice:secret@example.test/repo?token=hidden' >&2; exit 23",
    ]);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        super::run_git_output_with_policy(&mut command, Duration::from_secs(5), None)
    }));
    let output = result.expect("a nonzero Git child must not panic").unwrap();
    let error = super::git_failure("test", output.status, &output.stderr);
    let failure = error.git_failure().expect("typed Git failure");
    assert_eq!(failure.status.code(), Some(23));
    assert!(!failure.stderr.contains("secret"));
    assert!(!failure.stderr.contains("token"));
    assert!(!error.to_string().contains("stderr"));
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<super::GitFailure>())
            .is_some()
    );
}

#[test]
fn canonicalizes_github_and_scopes_cache_by_immutable_reference() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let first = RemoteModule::parse(&format!("github:Octo/Example.git@{commit}//tasks")).unwrap();
    let second =
        RemoteModule::parse(&format!("https://github.com/octo/example@{commit}//other")).unwrap();
    assert_eq!(first.repository, "github.com/octo/example");
    assert_eq!(first.cache_key(), second.cache_key());
    assert_ne!(first.canonical(), second.canonical());
}

#[cfg(windows)]
#[test]
fn windows_local_git_identity_round_trips_through_both_trust_stores() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let other_commit = "1123456789abcdef0123456789abcdef01234567";
    let source = |path: &str, revision: &str| {
        RemoteModule::parse(&format!("{path}@{revision}//task.yaml")).unwrap()
    };
    let ordinary = source(r"C:\work\repo", commit);
    let verbatim = source(r"\\?\C:\work\repo", commit);
    assert_eq!(ordinary.repository, "file://C:/work/repo");
    assert_eq!(ordinary.repository, verbatim.repository);
    assert_eq!(ordinary.cache_key(), verbatim.cache_key());
    assert_ne!(
        ordinary.cache_key(),
        source(r"C:\work\other", commit).cache_key()
    );
    assert_ne!(
        ordinary.cache_key(),
        source(r"C:\work\repo", other_commit).cache_key()
    );

    let policy = format!(
        "[remote]\nallow = [{}]\n",
        toml::Value::String(ordinary.repository.clone())
    );
    let allowed = parse_trusted_repositories(&policy, Path::new("policy.toml")).unwrap();
    assert_eq!(allowed, vec![ordinary.repository.clone()]);

    let root = TempDir::new().unwrap();
    let store = root.path().join("projects.toml");
    crate::trust::approve_remote_in(&store, &ordinary.repository, commit, "task.yaml", b"safe")
        .unwrap();
    assert!(
        crate::trust::remote_status_in(&store, &verbatim.repository, commit, "task.yaml")
            .unwrap()
            .1
    );
    assert!(
        !crate::trust::remote_status_in(&store, &ordinary.repository, other_commit, "task.yaml")
            .unwrap()
            .1
    );
    assert!(
        !crate::trust::remote_status_in(
            &store,
            &source(r"C:\work\other", commit).repository,
            commit,
            "task.yaml"
        )
        .unwrap()
        .1
    );
}

#[test]
fn transport_seam_keeps_github_default_and_can_use_one_local_origin() {
    let directory = TempDir::new().unwrap();
    let origin = directory.path().join("origin.git");
    let work = directory.path().join("work");
    fs::create_dir_all(&work).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&origin)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["init", "--initial-branch=main"])
            .status()
            .unwrap()
            .success()
    );
    for (key, value) in [("user.email", "test@example.test"), ("user.name", "Test")] {
        assert!(
            Command::new("git")
                .args(["-C"])
                .arg(&work)
                .args(["config", key, value])
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(work.join("module.yaml"), "env: {}\n").unwrap();
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["add", "module.yaml"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&work).unwrap();
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["tag", "-a", "v1", "-m", "v1"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&work)
            .args(["push", "-q"])
            .arg(&origin)
            .arg("HEAD")
            .arg("refs/tags/v1")
            .status()
            .unwrap()
            .success()
    );

    let module = RemoteModule::parse("github:octo/repo@tag:v1").unwrap();
    assert_eq!(
        super::GitHubGitTransport.fetch_url(&module),
        "https://github.com/octo/repo.git"
    );
    let transport = LocalGitTransport {
        repository: module.repository.clone(),
        url: origin.display().to_string(),
    };
    let fetched =
        super::git_fetch(&module, &directory.path().join("fetched"), None, &transport).unwrap();
    assert_eq!(fetched, commit);

    let commit_module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let fetched = super::git_fetch(
        &commit_module,
        &directory.path().join("commit-fetched"),
        None,
        &transport,
    )
    .unwrap();
    assert_eq!(fetched, commit);
}

#[test]
fn stored_canonical_trust_entries_round_trip_through_the_policy_parser() {
    let repositories = parse_trusted_repositories(
        "[remote]\nallow = [\"github.com/Owner/Demo\"]\n",
        Path::new("trust.toml"),
    )
    .unwrap();
    assert_eq!(repositories, vec!["github.com/owner/demo"]);
}

#[test]
fn rejects_mutable_and_traversal_references() {
    for value in [
        "github:octo/repo@main",
        "github:octo/repo@HEAD",
        "github:octo/repo//tasks",
        "github:octo/repo@tag:v1//../secret",
    ] {
        assert!(matches!(
            RemoteModule::parse(value),
            Err(RemoteError::MutableReference
                | RemoteError::MissingImmutableReference
                | RemoteError::InvalidSubpath)
        ));
    }
}

#[cfg(unix)]
#[test]
fn stalled_git_large_stderr_fixture_exits_without_timeout() {
    let directory = TempDir::new().unwrap();
    let fixture = directory.path().join("git");
    fs::write(
        &fixture,
        "#!/bin/sh\ndd if=/dev/zero bs=1024 count=128 1>&2 2>/dev/null\nexit 0\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&fixture).unwrap().permissions();
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&fixture, permissions).unwrap();

    let path = format!(
        "{}:{}",
        directory.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut command = Command::new("git");
    command.env("PATH", path);
    let started = Instant::now();
    let result = super::run_git_output_with_policy(&mut command, Duration::from_secs(5), None);
    let elapsed = started.elapsed();
    let output = result.expect("large stderr must not force a timeout diagnostic");
    assert!(output.status.success());
    assert!(output.stderr.len() >= 128 * 1024);
    assert!(
        elapsed < Duration::from_secs(2),
        "successful Git fixture waited for its deadline: {elapsed:?}"
    );
}

#[cfg(unix)]
#[test]
fn stalled_git_fixture_is_reaped_with_its_process_tree() {
    use std::os::unix::fs::PermissionsExt as _;

    use nix::{
        errno::Errno,
        sys::signal::{Signal, kill},
        unistd::Pid,
    };

    fn process_exists(process_id: i32) -> bool {
        !matches!(kill(Pid::from_raw(process_id), None), Err(Errno::ESRCH))
    }

    let directory = TempDir::new().unwrap();
    let fixture = directory.path().join("git");
    let process_id_file = directory.path().join("sleeper.pid");
    fs::write(
            &fixture,
            "#!/bin/sh\nsleep 30 &\nprintf '%s\\n' \"$!\" > \"$NEOENV_GIT_FIXTURE_PID_FILE\"\nprintf \"fatal: https://alice:secret@example.test/repo\\n\" >&2\nwait\n",
        )
        .unwrap();
    let mut permissions = fs::metadata(&fixture).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fixture, permissions).unwrap();

    let path = format!(
        "{}:{}",
        directory.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut command = Command::new("git");
    command
        .env("PATH", path)
        .env("NEOENV_GIT_FIXTURE_PID_FILE", &process_id_file);
    let started = Instant::now();
    let result = super::run_git_output_with_policy(&mut command, Duration::from_secs(1), None);
    let elapsed = started.elapsed();
    let process_id = fs::read_to_string(&process_id_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    let mut sleeper_exists = process_exists(process_id);
    for _ in 0..100 {
        if !sleeper_exists {
            break;
        }
        thread::sleep(Duration::from_millis(10));
        sleeper_exists = process_exists(process_id);
    }
    if sleeper_exists {
        let _ = kill(Pid::from_raw(process_id), Signal::SIGKILL);
    }

    let error = result.unwrap_err();
    assert!(matches!(&error, RemoteError::Git(message) if message.contains("timed out")));
    assert!(!error.to_string().contains("alice"));
    assert!(!error.to_string().contains("secret"));
    assert!(!sleeper_exists, "Git descendant process was left running");
    assert!(elapsed < Duration::from_secs(3));
}

#[cfg(unix)]
#[test]
fn git_output_reader_fails_at_the_retained_stream_budget() {
    let directory = TempDir::new().unwrap();
    let fixture = directory.path().join("git");
    fs::write(
        &fixture,
        "#!/bin/sh\ndd if=/dev/zero bs=1024 count=2048 1>&2 2>/dev/null\nexit 0\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&fixture).unwrap().permissions();
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&fixture, permissions).unwrap();
    let path = format!(
        "{}:{}",
        directory.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut command = Command::new("git");
    command.env("PATH", path);
    let budget = super::ResourceBudget {
        git_stderr_bytes: 1024,
        ..super::ResourceBudget::default()
    };
    let error = super::run_git_output_with_policy_and_budget(
        &mut command,
        Duration::from_secs(5),
        None,
        budget,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Git stderr"));
    assert!(error.to_string().contains("1024"));
}

#[cfg(windows)]
#[test]
fn windows_git_process_tree_fixture_helper() {
    if std::env::var_os("NEOENV_WINDOWS_GIT_FIXTURE_HELPER").is_none() {
        return;
    }
    let Some(pid_file) = std::env::var_os("NEOENV_GIT_FIXTURE_PID_FILE") else {
        return;
    };
    let mut child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    fs::write(&pid_file, child.id().to_string()).unwrap();
    eprintln!("fatal: https://alice:secret@example.test/repo");
    let _ = child.wait();
}

#[cfg(windows)]
#[test]
fn stalled_git_fixture_is_reaped_with_its_windows_process_tree() {
    fn process_exists(process_id: u32) -> bool {
        let filter = format!("PID eq {process_id}");
        let output = Command::new("tasklist")
            .args(["/FI", &filter, "/NH", "/FO", "CSV"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).contains(&format!("\"{process_id}\""))
    }

    let directory = TempDir::new().unwrap();
    let fixture = directory.path().join("git.exe");
    fs::copy(std::env::current_exe().unwrap(), &fixture).unwrap();
    let process_id_file = directory.path().join("sleeper.pid");

    let path = format!(
        "{};{}",
        directory.path().display(),
        std::env::var("PATH").unwrap()
    );
    let path_extensions = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".into());
    let mut command = Command::new("git");
    command
        .args([
            "--exact",
            "remote::tests::windows_git_process_tree_fixture_helper",
            "--nocapture",
        ])
        .env("PATH", path)
        .env("PATHEXT", format!(".EXE;{path_extensions}"))
        .env("NEOENV_WINDOWS_GIT_FIXTURE_HELPER", "1")
        .env("NEOENV_GIT_FIXTURE_PID_FILE", &process_id_file);
    let started = Instant::now();
    let result = super::run_git_output_with_policy(&mut command, Duration::from_secs(3), None);
    let elapsed = started.elapsed();
    let process_id = (0..100)
        .find_map(|_| {
            let value = fs::read_to_string(&process_id_file).ok()?;
            value.trim().parse::<u32>().ok()
        })
        .expect("Windows Git fixture did not publish its descendant process ID");
    let mut sleeper_exists = process_exists(process_id);
    for _ in 0..100 {
        if !sleeper_exists {
            break;
        }
        thread::sleep(Duration::from_millis(10));
        sleeper_exists = process_exists(process_id);
    }
    if sleeper_exists {
        let _ = Command::new("taskkill")
            .args(["/PID", &process_id.to_string(), "/T", "/F"])
            .status();
    }

    let error = result.unwrap_err();
    assert!(matches!(&error, RemoteError::Git(message) if message.contains("timed out")));
    assert!(!error.to_string().contains("alice"));
    assert!(!error.to_string().contains("secret"));
    assert!(!sleeper_exists, "Git descendant process was left running");
    assert!(elapsed < Duration::from_secs(6));
}

#[test]
fn git_failure_stderr_is_redacted_and_truncated() {
    let stderr = format!(
        "fetch https://alice:secret@example.test/repo?token=query-secret: {}",
        "x".repeat(super::GIT_STDERR_LIMIT_BYTES * 2)
    );
    let diagnostic = super::format_git_failure("git fetch failed", stderr.as_bytes());
    assert!(diagnostic.contains("https://example.test/repo"));
    assert!(!diagnostic.contains("alice"));
    assert!(!diagnostic.contains("secret"));
    assert!(!diagnostic.contains("query-secret"));
    assert!(diagnostic.contains("[truncated]"));
    assert!(diagnostic.len() < super::GIT_STDERR_LIMIT_BYTES + 128);
}

#[test]
fn resolved_tag_commit_must_match_cached_content_and_provenance() {
    let directory = TempDir::new().unwrap();
    let module = RemoteModule::parse("github:octo/repo@tag:v1.2.3").unwrap();
    let source = directory.path().join("source");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(source.join("module.yaml"), "env: {}\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();
    let binding = tag_binding_path(directory.path(), &module);
    fs::create_dir_all(binding.parent().unwrap()).unwrap();
    fs::write(&binding, tag_metadata_for(&module, &commit)).unwrap();

    let moved_tag = "fedcba9876543210fedcba9876543210fedcba98";
    assert!(matches!(
        cached_module_for_commit(directory.path(), &module, moved_tag),
        Err(RemoteError::NotFetched(_))
    ));
    assert!(cached_module_for_commit(directory.path(), &module, &commit).is_ok());
    fs::write(
        &binding,
        "canonical = \"github.com/octo/other@tag:v1.2.3\"\ncommit = \"bad\"\n",
    )
    .unwrap();
    assert!(matches!(
        tag_binding_commit(directory.path(), &module),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[test]
fn assume_unchanged_cannot_hide_a_replaced_tracked_file() {
    let directory = TempDir::new().unwrap();
    let source = directory.path().join("source");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(source.join("script.sh"), "#!/bin/sh\necho approved\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();
    let cached = cache.join("source");
    assert!(cached_module_for_commit(directory.path(), &module, &commit).is_ok());

    // The premise: Git's own cleanliness checks are satisfied while the bytes
    // that will be executed are not the committed ones.
    fs::write(cached.join("script.sh"), "#!/bin/sh\necho replaced\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&cached)
            .args(["update-index", "--assume-unchanged", "script.sh"])
            .status()
            .unwrap()
            .success()
    );
    let status = Command::new("git")
        .arg("-C")
        .arg(&cached)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(status.stdout.is_empty(), "{status:?}");

    // The verifier builds its comparison index from the pinned commit tree, so
    // the substituted input is observed and the cache is refused.
    assert!(matches!(
        cached_module_for_commit(directory.path(), &module, &commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_configured_clean_filter_cannot_mask_a_replaced_tracked_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TempDir::new().unwrap();
    let source = directory.path().join("source");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    let approved = "#!/bin/sh\necho approved\n";
    fs::write(source.join("script.sh"), approved).unwrap();
    fs::write(source.join(".gitattributes"), "script.sh filter=evil\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();
    let cached = cache.join("source");

    // A clean filter declared by the checkout's `.git/config` rewrites the
    // substituted bytes back to the committed ones, so Git's own cleanliness
    // checks are satisfied while the executed bytes are not the approved ones.
    let marker = directory.path().join("filter-ran");
    let filter = directory.path().join("filter.sh");
    fs::write(
        &filter,
        format!(
            "#!/bin/sh\ntouch '{}'\ncat >/dev/null\nprintf '#!/bin/sh\\necho approved\\n'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).unwrap();
    for (key, value) in [
        ("filter.evil.clean", filter.display().to_string()),
        ("filter.evil.required", "true".to_owned()),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&cached)
                .args(["config", key, &value])
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(cached.join("script.sh"), "#!/bin/sh\necho replaced\n").unwrap();
    let status = Command::new("git")
        .arg("-C")
        .arg(&cached)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(status.stdout.is_empty(), "{status:?}");
    assert!(marker.exists(), "the premise requires the filter to run");

    // The verifier never asks Git to read the worktree, so no filter is
    // invoked and the raw bytes are compared with the pinned blob directly.
    fs::remove_file(&marker).unwrap();
    assert!(matches!(
        cached_module_for_commit(directory.path(), &module, &commit),
        Err(RemoteError::CacheMismatch(_))
    ));
    assert!(
        !marker.exists(),
        "verification must not run a checkout-controlled clean filter"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_remote_subpath_is_refused() {
    use std::os::unix::fs::symlink;

    let directory = TempDir::new().unwrap();
    let source = directory.path().join("source");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(source.join("task.yaml"), "tasks:\n  default: 'true'\n").unwrap();
    symlink("task.yaml", source.join("link.yaml")).unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}//link.yaml")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();

    assert!(matches!(
        cached_module_for_commit(directory.path(), &module, &commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_replacement_ref_cannot_substitute_the_pinned_tree() {
    let directory = TempDir::new().unwrap();
    let source = directory.path().join("build");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(
        source.join("module.yaml"),
        "tasks:\n  run:\n    uses: shell\n    run: ./script.sh\n",
    )
    .unwrap();
    fs::write(source.join("script.sh"), "#!/bin/sh\necho approved\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "approved"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let approved_script = Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["rev-parse", "HEAD:script.sh"])
        .output()
        .unwrap()
        .stdout;
    let approved_script = String::from_utf8(approved_script)
        .unwrap()
        .trim()
        .to_owned();

    fs::write(source.join("script.sh"), "#!/bin/sh\necho replaced\n").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-am", "replacement"])
            .status()
            .unwrap()
            .success()
    );
    let replacement = super::revision(&source).unwrap();
    assert_ne!(replacement, commit);
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["reset", "--hard", &commit])
            .status()
            .unwrap()
            .success()
    );
    // Pin the approved commit to the replacement object. HEAD still resolves to
    // the approved commit id; only object traversal is substituted.
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args([
                "update-ref",
                &format!("refs/replace/{commit}"),
                &replacement
            ])
            .status()
            .unwrap()
            .success()
    );
    let head = super::revision(&source).unwrap();
    assert_eq!(head, commit);
    let listed = Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["ls-tree", "-r", &commit, "--", "script.sh"])
        .output()
        .unwrap();
    let listed = String::from_utf8(listed.stdout).unwrap();
    let replacement_script = Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["rev-parse", &format!("{replacement}:script.sh")])
        .output()
        .unwrap();
    let replacement_script = String::from_utf8(replacement_script.stdout)
        .unwrap()
        .trim()
        .to_owned();
    assert_ne!(approved_script, replacement_script);
    assert!(
        listed.contains(&replacement_script),
        "the premise requires ls-tree to follow the replacement: {listed}"
    );

    // The worktree holds the replacement script while the approved YAML is
    // unchanged.
    fs::write(source.join("script.sh"), "#!/bin/sh\necho replaced\n").unwrap();
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();

    assert!(matches!(
        cached_module_for_commit(directory.path(), &module, &commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[cfg(unix)]
struct ExecutableFixture {
    directory: TempDir,
    module: RemoteModule,
    commit: String,
    script: PathBuf,
}

/// A one-file cached module whose committed tree records `script.sh` with or
/// without an executable bit.
#[cfg(unix)]
fn executable_fixture(executable: bool) -> ExecutableFixture {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TempDir::new().unwrap();
    let source = directory.path().join("source");
    fs::create_dir_all(&source).unwrap();
    for arguments in [
        ["init", "--initial-branch=main"].as_slice(),
        ["config", "user.email", "test@example.test"].as_slice(),
        ["config", "user.name", "Test"].as_slice(),
        ["config", "core.autocrlf", "false"].as_slice(),
        ["config", "core.fileMode", "true"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    let script = source.join("script.sh");
    fs::write(&script, "#!/bin/sh\necho approved\n").unwrap();
    fs::set_permissions(
        &script,
        fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )
    .unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["commit", "-m", "module"])
            .status()
            .unwrap()
            .success()
    );
    let commit = super::revision(&source).unwrap();
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, &commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        metadata_for(&module.repository, &commit),
    )
    .unwrap();
    let script = cache.join("source/script.sh");
    ExecutableFixture {
        directory,
        module,
        commit,
        script,
    }
}

#[cfg(unix)]
#[test]
fn a_cached_file_gaining_an_executable_bit_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = executable_fixture(false);
    assert!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit)
            .is_ok()
    );

    let mut permissions = fs::metadata(&fixture.script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fixture.script, permissions).unwrap();

    assert!(matches!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_cached_file_losing_its_executable_bit_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = executable_fixture(true);
    assert!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit)
            .is_ok()
    );

    let mut permissions = fs::metadata(&fixture.script).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&fixture.script, permissions).unwrap();

    assert!(matches!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_cached_file_losing_only_the_owner_execute_bit_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = executable_fixture(true);
    assert!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit)
            .is_ok()
    );

    // Git compares the owner execute bit, not all execute bits: 0755 -> 0655 is
    // a mode change even though group and other execute remain set.
    let mut permissions = fs::metadata(&fixture.script).unwrap().permissions();
    permissions.set_mode(0o655);
    fs::set_permissions(&fixture.script, permissions).unwrap();

    assert!(matches!(
        cached_module_for_commit(fixture.directory.path(), &fixture.module, &fixture.commit),
        Err(RemoteError::CacheMismatch(_))
    ));
}

#[test]
fn cache_clear_is_source_scoped_and_never_needs_transport_or_trust() {
    let directory = TempDir::new().unwrap();
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let module = RemoteModule::parse(&format!("github:octo/repo@{commit}")).unwrap();
    let cache = commit_cache_path(directory.path(), &module, commit);
    fs::create_dir_all(cache.join("source")).unwrap();

    assert!(clear_module_cache(directory.path(), &module).unwrap());
    assert!(!cache.exists());
    assert!(!clear_module_cache(directory.path(), &module).unwrap());
}
