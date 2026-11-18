//! Execution-trust contract at the command boundary.
//!
//! These tests run the compiled binary against isolated config homes, so the
//! trust store is a real file in a temporary directory and no developer state
//! is read or written. Identity is checked before every effect: a trusted root
//! with an untrusted module runs nothing, a changed digest names expected and
//! observed identities, and repository allowlisting never authorizes execution.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    project: PathBuf,
    config: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new(config_body: &str) -> Self {
        let root = TempDir::new().unwrap();
        let project = root.path().join("project");
        let config = root.path().join("config");
        let data = root.path().join("data");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(config.join("neoenv")).unwrap();
        fs::write(project.join("neoenv.yaml"), config_body).unwrap();
        Self {
            root,
            project,
            config,
            data,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.project.join(name)
    }

    fn write(&self, name: &str, body: &str) {
        let path = self.path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
        command
            .current_dir(&self.project)
            .env("NEOENV_CONFIG_HOME", &self.config)
            .env("NEOENV_DATA_HOME", &self.data)
            .env("NO_COLOR", "1")
            .env_remove("NEOENV_PROJECT")
            .env_remove("NEOENV_CONTEXT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME");
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command().args(arguments).output().unwrap()
    }

    fn trust_add(&self, path: &Path) -> Output {
        self.command()
            .arg("trust")
            .arg("add")
            .arg(path)
            .output()
            .unwrap()
    }

    fn trust_revoke(&self, path: &Path) -> Output {
        self.command()
            .arg("trust")
            .arg("revoke")
            .arg(path)
            .output()
            .unwrap()
    }

    fn config_path(&self) -> PathBuf {
        self.path("neoenv.yaml").canonicalize().unwrap()
    }

    fn approve_root(&self) {
        let output = self.trust_add(&self.config_path());
        assert!(output.status.success(), "{output:?}");
    }

    fn assert_trust_refusal(output: &Output) {
        assert_eq!(output.status.code(), Some(5), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not trusted")
                || String::from_utf8_lossy(&output.stderr).contains("does not match"),
            "{output:?}"
        );
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn an_untrusted_root_executes_no_task_and_prints_an_actionable_diagnostic() {
    let fixture =
        Fixture::new("tasks:\n  check:\n    uses: shell\n    run: 'touch root-task-ran'\n");
    let output = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&output);
    let message = stderr(&output);
    assert!(message.contains("not trusted"), "{message}");
    assert!(message.contains("nenv trust add"), "{message}");
    assert!(message.contains("neoenv.yaml"), "{message}");
    assert!(!fixture.path("root-task-ran").exists());

    fixture.approve_root();
    let output = fixture.run(&["task", "run", "check"]);
    assert!(output.status.success(), "{output:?}");
    assert!(fixture.path("root-task-ran").exists());
}

/// A missing cache is refused without fetching, and that refusal is a cache
/// diagnostic rather than a trust decision. The trust gate is proven by
/// `a_repository_allowlist_alone_does_not_grant_execution`, which runs against
/// a valid cache.
#[test]
fn an_untrusted_root_does_not_fetch_a_remote_import() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let fixture = Fixture::new(&format!(
        "imports: \"github:octo/repo@{commit}//module.yaml\"\ntasks:\n  check:\n    uses: shell\n    run: 'touch root-task-ran'\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();
    let output = fixture.run(&["task", "run", "check"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        stderr(&output).contains("remote module is not fetched"),
        "{output:?}"
    );
    assert!(!fixture.path(".neoenv/modules").exists(), "nothing fetched");
    assert!(!fixture.path("root-task-ran").exists());
}

#[test]
fn an_untrusted_dependency_does_no_task_render_or_install() {
    let fixture = Fixture::new(
        "imports: [module.yaml]\n\
         tasks:\n  \
           own:\n    uses: shell\n    run: 'touch own-task-ran'\n  \
           render:\n    uses: render\n    source: template.tmpl\n    destination: rendered.txt\n",
    );
    fixture.write("module.yaml", "env:\n  MODULE_VALUE: module\n");
    fixture.write("template.tmpl", "rendered\n");
    fixture.approve_root();

    let own = fixture.run(&["task", "run", "own"]);
    Fixture::assert_trust_refusal(&own);
    let message = stderr(&own);
    assert!(message.contains("module.yaml"), "{message}");
    assert!(!fixture.path("own-task-ran").exists());

    let render = fixture.run(&["task", "run", "render"]);
    Fixture::assert_trust_refusal(&render);
    assert!(!fixture.path("rendered.txt").exists());

    let install = fixture.run(&["tool", "install", "--locked"]);
    Fixture::assert_trust_refusal(&install);
    assert!(!fixture.path(".neoenv/tools").exists());

    let module = fixture.path("module.yaml").canonicalize().unwrap();
    assert!(fixture.trust_add(&module).status.success());
    let own = fixture.run(&["task", "run", "own"]);
    assert!(own.status.success(), "{own:?}");
    assert!(fixture.path("own-task-ran").exists());
    let render = fixture.run(&["task", "run", "render"]);
    assert!(render.status.success(), "{render:?}");
    assert_eq!(
        fs::read_to_string(fixture.path("rendered.txt")).unwrap(),
        "rendered\n"
    );
}

#[test]
fn approval_is_per_content_and_explicit_revocation_governs_execution() {
    let fixture =
        Fixture::new("tasks:\n  check:\n    uses: shell\n    run: 'printf ran >> marker'\n");
    fixture.approve_root();
    assert!(fixture.run(&["task", "run", "check"]).status.success());

    // A status report names the identity and its digest.
    let status = fixture.run(&["trust", "status", "neoenv.yaml"]);
    assert!(status.status.success(), "{status:?}");
    let report = String::from_utf8_lossy(&status.stdout).into_owned();
    assert!(report.contains("blake3:"), "{report}");
    assert!(report.contains("root: trusted"), "{report}");

    // Editing the file invalidates the approval and names both digests.
    fixture.write(
        "neoenv.yaml",
        "tasks:\n  check:\n    uses: shell\n    run: 'printf changed >> marker'\n",
    );
    let refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    let message = stderr(&refused);
    assert!(message.contains("expected blake3:"), "{message}");
    assert!(message.contains("observed blake3:"), "{message}");

    fixture.approve_root();
    assert!(fixture.run(&["task", "run", "check"]).status.success());
    assert_eq!(
        fs::read_to_string(fixture.path("marker")).unwrap(),
        "ranchanged"
    );

    let revoked = fixture.trust_revoke(&fixture.config_path());
    assert!(revoked.status.success(), "{revoked:?}");
    Fixture::assert_trust_refusal(&fixture.run(&["task", "run", "check"]));
}

#[test]
fn a_task_package_must_be_trusted_and_existing_syntax_still_works() {
    let fixture = Fixture::new(
        "task_packages:\n  helper: helper\ntasks:\n  check:\n    uses: package:helper\n",
    );
    fixture.write(
        "neoenv/tasks/helper.yaml",
        "tasks:\n  default:\n    uses: shell\n    run: 'touch package-task-ran'\n",
    );
    fixture.approve_root();
    let refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    assert!(stderr(&refused).contains("helper.yaml"), "{refused:?}");
    assert!(!fixture.path("package-task-ran").exists());

    let package = fixture
        .path("neoenv/tasks/helper.yaml")
        .canonicalize()
        .unwrap();
    let added = fixture.trust_add(&package);
    assert!(added.status.success(), "{added:?}");
    let output = fixture.run(&["task", "run", "check"]);
    assert!(output.status.success(), "{output:?}");
    assert!(fixture.path("package-task-ran").exists());
}

#[test]
fn a_task_package_in_a_nested_subfolder_runs_when_its_path_is_trusted() {
    let fixture = Fixture::new(
        "task_packages:\n  lint:\n    from: ./tasks/lint/task.yaml\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n",
    );
    fixture.write(
        "tasks/lint/task.yaml",
        "tasks:\n  lint:\n    uses: shell\n    run: 'touch nested-package-ran'\n",
    );
    fixture.approve_root();

    let refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    let message = stderr(&refused);
    assert!(
        message.contains(
            &fixture
                .path("tasks/lint/task.yaml")
                .canonicalize()
                .unwrap()
                .display()
                .to_string()
        ),
        "{message}"
    );
    assert!(!fixture.path("nested-package-ran").exists());

    let package = fixture.path("tasks/lint/task.yaml").canonicalize().unwrap();
    let added = fixture.trust_add(&package);
    assert!(added.status.success(), "{added:?}");
    let output = fixture.run(&["task", "run", "check"]);
    assert!(output.status.success(), "{output:?}");
    assert!(fixture.path("nested-package-ran").exists());
}

#[test]
fn parent_traversal_and_symlink_escapes_fail_before_execution() {
    let fixture = Fixture::new(
        "task_packages:\n  escape: ../outside.yaml\ntasks:\n  check:\n    uses: package:escape\n",
    );
    fixture.write(
        "../outside.yaml",
        "tasks:\n  default:\n    uses: shell\n    run: 'touch escaped'\n",
    );
    fixture.approve_root();
    let output = fixture.run(&["task", "run", "check"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("escape"),
        "the refusal must name the escape: {output:?}"
    );
    assert!(!fixture.root.path().join("escaped").exists());

    // A nested reference may not climb out through `..` either.
    let fixture = Fixture::new(
        "task_packages:\n  escape: ./tasks/../../outside.yaml\ntasks:\n  check:\n    uses: package:escape\n",
    );
    fixture.write("tasks/.keep", "");
    fixture.write(
        "../outside.yaml",
        "tasks:\n  default:\n    uses: shell\n    run: 'touch nested-escaped'\n",
    );
    fixture.approve_root();
    let output = fixture.run(&["task", "run", "check"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("escapes project root"),
        "{output:?}"
    );
    assert!(!fixture.root.path().join("nested-escaped").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = fixture.root.path().join("outside-module.yaml");
        fs::write(
            &outside,
            "tasks:\n  link:\n    uses: shell\n    run: 'touch linked'\n",
        )
        .unwrap();
        let fixture = Fixture::new(
            "imports: [linked.yaml]\ntasks:\n  check:\n    uses: shell\n    run: 'touch linked-ran'\n",
        );
        fixture.approve_root();
        symlink(&outside, fixture.path("linked.yaml")).unwrap();
        let output = fixture.run(&["task", "run", "check"]);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            stderr(&output).contains("escapes project root"),
            "{output:?}"
        );
        assert!(!fixture.path("linked-ran").exists());
        assert!(!fixture.path("linked").exists());
    }
}

#[test]
fn a_malformed_trust_store_fails_closed() {
    let fixture =
        Fixture::new("tasks:\n  check:\n    uses: shell\n    run: 'touch must-not-run'\n");
    fixture.approve_root();
    fs::write(
        fixture.config.join("neoenv/projects.toml"),
        "format_version = 2\nunexpected = true\n",
    )
    .unwrap();
    let output = fixture.run(&["task", "run", "check"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        stderr(&output).contains("malformed trust store"),
        "{output:?}"
    );
    assert!(!fixture.path("must-not-run").exists());
}

// --- fixture-based remote cache verification ---------------------------------
//
// No network and no fetch: a real Git checkout is placed where the cache
// verifier expects one, and the trust gate is exercised against those bytes.
// Live remote fetch execution is deliberately not claimed here.

struct RemoteFixture {
    fixture: Fixture,
    commit: String,
    repository: String,
    cache_file: PathBuf,
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["-c", "user.name=Test"])
        .args(["-c", "user.email=test@example.test"])
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn remote_fixture() -> RemoteFixture {
    let repository = "github.com/octo/repo".to_owned();
    // A Git checkout whose HEAD is the commit the config pins. The cache
    // verifier resolves HEAD, so a fabricated commit id would be a different
    // test (and is covered by the trust module's identity tests).
    let staging = TempDir::new().unwrap();
    let source = staging.path().join("source");
    fs::create_dir_all(&source).unwrap();
    git(&source, &["init", "--initial-branch=main"]);
    fs::write(
        source.join("module.yaml"),
        "tasks:\n  remote:\n    uses: shell\n    run: 'touch remote-ran'\n",
    )
    .unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-m", "module"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let fixture = Fixture::new(&format!(
        "imports: \"github:octo/repo@{commit}//module.yaml\"\ntasks:\n  local:\n    uses: shell\n    run: 'touch local-ran'\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();
    // A remote task is an external subject and still needs the ordinary
    // execute grant; trust authorizes the bytes, not a capability.
    let project = fixture.project.canonicalize().unwrap();
    fs::write(
        fixture.config.join("neoenv/capabilities.toml"),
        format!(
            "[[grants]]\nsubject = {:?}\ncapability = \"execute\"\n",
            format!("project:{}/task:remote", project.display())
        ),
    )
    .unwrap();

    // The cache directory is keyed by the repository digest, which is part of
    // the cache layout rather than an execution-trust identity.
    let cache = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();

    RemoteFixture {
        cache_file: cache.join("source/module.yaml"),
        fixture,
        commit,
        repository,
    }
}

#[test]
fn direct_file_module_and_package_require_separate_execution_approval() {
    for package in [false, true] {
        let body = "tasks:\n  remote:\n    uses: shell\n    run: 'touch direct-ran'\n";
        let digest = format!("{:x}", Sha256::digest(body.as_bytes()));
        let spec = format!("https://example.test/task.yaml#sha256={digest}&type=file");
        let config = if package {
            format!(
                "task_packages:\n  direct:\n    from: '{spec}'\n    task: remote\ntasks:\n  check:\n    uses: package:direct\n"
            )
        } else {
            format!("imports: ['{spec}']\n")
        };
        let fixture = Fixture::new(&config);
        let cache = fixture.path(".neoenv/modules/files").join(&digest);
        fs::create_dir_all(cache.parent().unwrap()).unwrap();
        fs::write(&cache, body).unwrap();
        fixture.approve_root();
        let task = if package { "check" } else { "remote" };
        let denied = fixture.run(&["task", "run", task]);
        Fixture::assert_trust_refusal(&denied);
        assert!(!fixture.path("direct-ran").exists());
        let approved = fixture.run(&["trust", "add", "--remote", &spec]);
        assert!(approved.status.success(), "{approved:?}");
        let capability_subject = if package {
            format!("package:{digest}")
        } else {
            format!(
                "project:{}/task:remote",
                fixture.project.canonicalize().unwrap().display()
            )
        };
        fs::write(
            fixture.config.join("neoenv/capabilities.toml"),
            format!("[[grants]]\nsubject = {capability_subject:?}\ncapability = \"execute\"\n"),
        )
        .unwrap();
        let ran = fixture.run(&["task", "run", task]);
        assert!(ran.status.success(), "{ran:?}");
        assert!(fixture.path("direct-ran").exists());
        fs::remove_file(fixture.path("direct-ran")).unwrap();
        fs::write(cache, "tampered").unwrap();
        let denied = fixture.run(&["task", "run", task]);
        assert!(!denied.status.success(), "{denied:?}");
        assert!(!fixture.path("direct-ran").exists());
    }
}

#[test]
fn a_repository_allowlist_alone_does_not_grant_execution() {
    let remote = remote_fixture();
    // The cache is populated, verified, and readable without the execution
    // gate: a refusal below cannot be an artifact of missing cache content.
    let inspect = remote.fixture.run(&["inspect"]);
    assert!(inspect.status.success(), "cache must be valid: {inspect:?}");

    // The root is checked first, so the first refusal is about the project file.
    let root_refusal = remote.fixture.run(&["task", "run", "remote"]);
    Fixture::assert_trust_refusal(&root_refusal);
    assert!(
        stderr(&root_refusal).contains("configuration is not trusted"),
        "{root_refusal:?}"
    );

    remote.fixture.approve_root();
    let output = remote.fixture.run(&["task", "run", "remote"]);
    Fixture::assert_trust_refusal(&output);
    let message = stderr(&output);
    assert!(message.contains("is not trusted"), "{message}");
    assert!(message.contains(&remote.repository), "{message}");
    assert!(message.contains(&remote.commit), "{message}");
    assert!(message.contains("module.yaml"), "{message}");
    assert!(!message.contains("not fetched"), "{message}");
    assert!(
        !message.contains("remote cache does not match"),
        "{message}"
    );
    assert!(!remote.fixture.path("remote-ran").exists());

    let spec = format!("github:octo/repo@{}//module.yaml", remote.commit);
    let approved = remote
        .fixture
        .command()
        .args(["trust", "add", "--remote", &spec])
        .output()
        .unwrap();
    assert!(approved.status.success(), "{approved:?}");
    assert!(
        String::from_utf8_lossy(&approved.stdout).contains("blake3:"),
        "{approved:?}"
    );

    let output = remote.fixture.run(&["task", "run", "remote"]);
    assert!(output.status.success(), "{output:?}");
    assert!(remote.fixture.path("remote-ran").exists());
}

struct RemotePackageFixture {
    fixture: Fixture,
    commit: String,
    repository: String,
    sha256: String,
}

/// A selected task inside a subfolder of a verified immutable cache entry.
///
/// The cache is real: a Git checkout whose HEAD is the commit the config pins,
/// placed where the verifier expects it. Nothing here fetches.
fn remote_package_fixture() -> RemotePackageFixture {
    const BODY: &str = "tasks:\n  lint:\n    uses: shell\n    run: 'touch remote-package-ran'\n";
    let repository = "github.com/octo/repo".to_owned();
    let staging = TempDir::new().unwrap();
    let source = staging.path().join("source");
    fs::create_dir_all(source.join("tasks/lint")).unwrap();
    git(&source, &["init", "--initial-branch=main"]);
    fs::write(source.join("tasks/lint/task.yaml"), BODY).unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-m", "task package"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let spec = format!("github:octo/repo@{commit}//tasks/lint/task.yaml");
    let fixture = Fixture::new(&format!(
        "task_packages:\n  lint:\n    from: {spec}\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();

    let cache = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();

    RemotePackageFixture {
        fixture,
        commit,
        repository,
        sha256: format!("{:x}", Sha256::digest(BODY.as_bytes())),
    }
}

#[test]
fn a_remote_task_package_subpath_is_selected_but_needs_an_execution_trust_record() {
    let remote = remote_package_fixture();

    // Reading resolves the pinned document from the verified cache without a
    // trust record. The repository allow-list authorizes that read, and it is
    // not a fetch.
    let inspect = remote.fixture.run(&["inspect"]);
    assert!(
        inspect.status.success(),
        "the pinned cache must resolve: {inspect:?}"
    );

    remote.fixture.approve_root();
    let refused = remote.fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    let message = stderr(&refused);
    assert!(message.contains(&remote.repository), "{message}");
    assert!(message.contains(&remote.commit), "{message}");
    assert!(message.contains("tasks/lint/task.yaml"), "{message}");
    assert!(!message.contains("not fetched"), "{message}");
    assert!(
        !remote.fixture.path("remote-package-ran").exists(),
        "an allow-listed remote package with no record must not run"
    );

    let spec = format!("github:octo/repo@{}//tasks/lint/task.yaml", remote.commit);
    let approved = remote
        .fixture
        .command()
        .args(["trust", "add", "--remote", &spec])
        .output()
        .unwrap();
    assert!(approved.status.success(), "{approved:?}");
    assert!(
        String::from_utf8_lossy(&approved.stdout).contains("blake3:"),
        "{approved:?}"
    );

    // The bytes are trusted now. An external package still needs its own
    // execute grant: trust authorizes content, never a capability.
    let denied = remote.fixture.run(&["task", "run", "check"]);
    assert!(!denied.status.success(), "{denied:?}");
    assert!(stderr(&denied).contains("capability execute"), "{denied:?}");
    assert!(!remote.fixture.path("remote-package-ran").exists());

    fs::write(
        remote.fixture.config.join("neoenv/capabilities.toml"),
        format!(
            "[[grants]]\nsubject = {:?}\ncapability = \"execute\"\n",
            format!("package:{}", remote.sha256)
        ),
    )
    .unwrap();
    let ran = remote.fixture.run(&["task", "run", "check"]);
    assert!(ran.status.success(), "{ran:?}");
    assert!(remote.fixture.path("remote-package-ran").exists());
}

#[test]
fn a_remote_module_cannot_declare_a_relative_package_as_local() {
    const PACKAGE: &str =
        "tasks:\n  lint:\n    uses: shell\n    run: 'touch remote-declared-package-ran'\n";
    const MODULE: &str = "task_packages:\n  lint:\n    from: tasks/lint/task.yaml\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n";

    let repository = "github.com/octo/repo".to_owned();
    let staging = TempDir::new().unwrap();
    let source = staging.path().join("source");
    fs::create_dir_all(source.join("tasks/lint")).unwrap();
    git(&source, &["init", "--initial-branch=main"]);
    fs::write(source.join("module.yaml"), MODULE).unwrap();
    fs::write(source.join("tasks/lint/task.yaml"), PACKAGE).unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-m", "module"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let fixture = Fixture::new(&format!(
        "imports: \"github:octo/repo@{commit}//module.yaml\"\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();
    let cache = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();

    // Resolution keeps the package inside the declaring checkout's identity.
    let inspect = fixture.run(&["inspect"]);
    assert!(inspect.status.success(), "{inspect:?}");

    fixture.approve_root();
    // The allow-list and a trusted root are not execution approval for either
    // the declaring module or the package it selects.
    let refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    let message = stderr(&refused);
    assert!(message.contains(&repository), "{message}");
    assert!(message.contains(&commit), "{message}");
    assert!(message.contains("module.yaml"), "{message}");
    assert!(
        !fixture.path("remote-declared-package-ran").exists(),
        "an allow-listed remote module must not run"
    );

    let module_spec = format!("github:octo/repo@{commit}//module.yaml");
    let approved = fixture
        .command()
        .args(["trust", "add", "--remote", &module_spec])
        .output()
        .unwrap();
    assert!(approved.status.success(), "{approved:?}");

    // The relative package declared by that module is remote content too: the
    // refusal names it by repository, commit, and repository-relative path, not
    // by the cache path local resolution would have used.
    let package_refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&package_refused);
    let message = stderr(&package_refused);
    assert!(message.contains(&repository), "{message}");
    assert!(message.contains(&commit), "{message}");
    assert!(message.contains("tasks/lint/task.yaml"), "{message}");
    assert!(!message.contains(".neoenv/modules"), "{message}");
    assert!(!fixture.path("remote-declared-package-ran").exists());

    let package_spec = format!("github:octo/repo@{commit}//tasks/lint/task.yaml");
    let approved = fixture
        .command()
        .args(["trust", "add", "--remote", &package_spec])
        .output()
        .unwrap();
    assert!(approved.status.success(), "{approved:?}");

    // Trust authorizes content only. The remote-declared package is external,
    // so it still needs its own execute grant, and the remote module task needs
    // the caller grant every remote task requires.
    let denied = fixture.run(&["task", "run", "check"]);
    assert!(!denied.status.success(), "{denied:?}");
    assert!(stderr(&denied).contains("capability execute"), "{denied:?}");
    assert!(!fixture.path("remote-declared-package-ran").exists());

    let project = fixture.project.canonicalize().unwrap();
    fs::write(
        fixture.config.join("neoenv/capabilities.toml"),
        format!(
            "[[grants]]\nsubject = {:?}\ncapability = \"execute\"\n\n\
             [[grants]]\nsubject = {:?}\ncapability = \"execute\"\n",
            format!("project:{}/task:check", project.display()),
            format!("package:{:x}", Sha256::digest(PACKAGE.as_bytes())),
        ),
    )
    .unwrap();
    let ran = fixture.run(&["task", "run", "check"]);
    assert!(ran.status.success(), "{ran:?}");
    assert!(fixture.path("remote-declared-package-ran").exists());
}

#[cfg(unix)]
#[test]
fn a_remote_module_cannot_select_a_symlinked_relative_package() {
    use std::os::unix::fs::symlink;

    const PACKAGE: &str =
        "tasks:\n  lint:\n    uses: shell\n    run: 'touch symlink-package-ran'\n";
    const MODULE: &str = "task_packages:\n  lint:\n    from: tasks/lint/link.yaml\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n";

    let repository = "github.com/octo/repo".to_owned();
    let staging = TempDir::new().unwrap();
    let source = staging.path().join("source");
    fs::create_dir_all(source.join("tasks/lint")).unwrap();
    git(&source, &["init", "--initial-branch=main"]);
    fs::write(source.join("module.yaml"), MODULE).unwrap();
    fs::write(source.join("tasks/lint/task.yaml"), PACKAGE).unwrap();
    symlink("task.yaml", source.join("tasks/lint/link.yaml")).unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-m", "module"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let fixture = Fixture::new(&format!(
        "imports: \"github:octo/repo@{commit}//module.yaml\"\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();
    let cache = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();
    fixture.approve_root();

    // The relative path names a same-directory link. Resolution refuses it
    // before canonicalization can record the target's identity, and no action
    // is planned or run.
    let output = fixture.run(&["inspect"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(stderr(&output).contains("symbolic link"), "{output:?}");
    let run = fixture.run(&["task", "run", "check"]);
    assert!(!run.status.success(), "{run:?}");
    assert!(!fixture.path("symlink-package-ran").exists());
}

#[cfg(unix)]
#[test]
fn a_remote_module_cannot_select_through_a_link_above_its_directory() {
    use std::os::unix::fs::symlink;

    const PACKAGE: &str =
        "tasks:\n  lint:\n    uses: shell\n    run: 'touch parent-link-package-ran'\n";
    const MODULE: &str = "task_packages:\n  lint:\n    from: ../link/task.yaml\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n";

    let repository = "github.com/octo/repo".to_owned();
    let staging = TempDir::new().unwrap();
    let source = staging.path().join("source");
    fs::create_dir_all(source.join("a")).unwrap();
    fs::create_dir_all(source.join("real")).unwrap();
    git(&source, &["init", "--initial-branch=main"]);
    fs::write(source.join("a/module.yaml"), MODULE).unwrap();
    fs::write(source.join("real/task.yaml"), PACKAGE).unwrap();
    // `link` is beside `a`, so the reference must traverse `..` before it sees
    // the link.
    symlink("real", source.join("link")).unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-m", "module"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();

    let fixture = Fixture::new(&format!(
        "imports: \"github:octo/repo@{commit}//a/module.yaml\"\n"
    ));
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"octo/repo\"]\n",
    )
    .unwrap();
    let cache = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit);
    fs::create_dir_all(&cache).unwrap();
    fs::rename(&source, cache.join("source")).unwrap();
    fs::write(
        cache.join("metadata.toml"),
        format!("repository = {repository:?}\ncommit = {commit:?}\n"),
    )
    .unwrap();
    fixture.approve_root();

    let output = fixture.run(&["inspect"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(stderr(&output).contains("symbolic link"), "{output:?}");
    let run = fixture.run(&["task", "run", "check"]);
    assert!(!run.status.success(), "{run:?}");
    assert!(!fixture.path("parent-link-package-ran").exists());
}

#[test]
fn a_changed_remote_cache_file_fails_closed() {
    let remote = remote_fixture();
    remote.fixture.approve_root();
    let spec = format!("github:octo/repo@{}//module.yaml", remote.commit);
    assert!(
        remote
            .fixture
            .command()
            .args(["trust", "add", "--remote", &spec])
            .output()
            .unwrap()
            .status
            .success()
    );
    let status = remote.fixture.run(&["trust", "status", "neoenv.yaml"]);
    assert!(status.status.success(), "{status:?}");
    let report = String::from_utf8_lossy(&status.stdout).into_owned();
    assert!(report.contains(&remote.commit), "{report}");
    assert!(report.contains("blake3:"), "{report}");
    assert!(report.contains("contributor: trusted"), "{report}");

    assert!(
        remote
            .fixture
            .run(&["task", "run", "remote"])
            .status
            .success()
    );
    fs::remove_file(remote.fixture.path("remote-ran")).unwrap();

    fs::write(
        &remote.cache_file,
        "tasks:\n  remote:\n    uses: shell\n    run: 'touch tampered-ran'\n",
    )
    .unwrap();
    // A changed cache file is refused by cache revalidation before the trust
    // digest is compared; either way it fails closed and executes nothing. The
    // digest-mismatch wording is asserted by the trust unit tests.
    let output = remote.fixture.run(&["task", "run", "remote"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("remote cache does not match")
            || stderr(&output).contains("does not match"),
        "{output:?}"
    );
    assert!(!remote.fixture.path("tampered-ran").exists());
    assert!(!remote.fixture.path("remote-ran").exists());
}

// --- local git fetch ---------------------------------------------------------
//
// A local repository is fetched through Git's file transport only. There is no
// network, credential, or SSH path in these tests, and none is added.

const LOCAL_GIT_PACKAGE: &str =
    "tasks:\n  lint:\n    uses: shell\n    run: 'touch local-git-package-ran'\n";

#[test]
fn yaml_string_encoding_preserves_windows_git_paths() {
    let spec = r"\\?\C:\Users\runner\origin@commit//tasks/lint/task.yaml";
    let document = format!("from: {}\n", serde_json::to_string(spec).unwrap());
    let parsed: serde_yaml::Value = serde_yaml::from_str(&document).unwrap();
    assert_eq!(parsed["from"].as_str(), Some(spec));
}

struct LocalGitFixture {
    fixture: Fixture,
    origin: PathBuf,
    spec: String,
    cached: PathBuf,
    package_sha256: String,
}

// On fixture failure, probe Git with the production protocol restrictions.
// Report only fixed classifications; never print Git's path-bearing stderr.
fn diagnose_local_git(local: &LocalGitFixture) -> String {
    let origin = neoenv_runtime::remote::RemoteModule::parse(&local.spec).unwrap();
    let path = origin.local_path().unwrap();
    #[cfg(windows)]
    let path = path.replace('/', "\\");
    let mut reports = Vec::new();
    // Mirror the production depth and staging layout: Git for Windows may
    // reject a deep worktree even when a shallow temporary repository works.
    let parent = local
        .cached
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    fs::create_dir_all(parent).unwrap();
    let staged = tempfile::Builder::new()
        .prefix("neoenv-module-")
        .tempdir_in(parent)
        .unwrap();
    let target = staged.path().join("source");
    let options = [
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-c",
        "protocol.https.allow=never",
        "-c",
        "protocol.ssh.allow=never",
        "-c",
        "protocol.git.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
    ];
    let reference = local
        .spec
        .rsplit_once('@')
        .unwrap()
        .1
        .split("//")
        .next()
        .unwrap();
    for stage in ["init", "fetch", "rev-parse", "checkout"] {
        let mut command = Command::new("git");
        command.args(options);
        if stage == "init" {
            command.arg("init").arg(&target);
        } else {
            command.arg("-C").arg(&target);
            match stage {
                "fetch" => {
                    command.args(["fetch", "--depth=1", "--no-tags", path.as_ref(), reference]);
                }
                "rev-parse" => {
                    command.args(["rev-parse", "FETCH_HEAD^{commit}"]);
                }
                "checkout" => {
                    command.args(["checkout", "--detach", "--force", reference]);
                }
                _ => unreachable!(),
            }
        }
        let output = command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        let labels = [
            ("config", "config"),
            ("null", "/dev/null"),
            ("protocol", "protocol"),
            ("repository", "repository"),
            ("not_found", "no such file"),
            ("access", "permission denied"),
            ("ownership", "dubious ownership"),
            ("invalid_argument", "invalid argument"),
            ("not_git", "not a git repository"),
            (
                "not_git_repository",
                "does not appear to be a git repository",
            ),
            ("revision", "couldn't find remote ref"),
            ("long_path", "filename too long"),
            ("create_file", "unable to create file"),
            ("invalid_path", "invalid path"),
        ]
        .iter()
        .filter_map(|(label, needle)| stderr.contains(needle).then_some(*label))
        .collect::<Vec<_>>();
        reports.push(format!(
            "{stage} status={} classes={labels:?}",
            output.status
        ));
    }
    reports.join("; ")
}

fn local_git_fixture() -> LocalGitFixture {
    let fixture = Fixture::new("format_version: 1\n");
    let origin = fixture.root.path().join("origin");
    fs::create_dir_all(origin.join("tasks/lint")).unwrap();
    git(&origin, &["init", "--initial-branch=main"]);
    fs::write(origin.join("tasks/lint/task.yaml"), LOCAL_GIT_PACKAGE).unwrap();
    git(&origin, &["add", "."]);
    git(&origin, &["commit", "-m", "task package"]);
    let commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&origin)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let spec = format!(
        "{}@{commit}//tasks/lint/task.yaml",
        origin.canonicalize().unwrap().display()
    );
    let yaml_spec = serde_json::to_string(&spec).unwrap();
    fixture.write(
        "neoenv.yaml",
        &format!(
            "task_packages:\n  lint:\n    from: {yaml_spec}\n    task: lint\ntasks:\n  check:\n    uses: package:lint\n"
        ),
    );
    let repository = neoenv_runtime::remote::RemoteModule::parse(&spec)
        .unwrap()
        .repository;
    let cached = fixture
        .path(".neoenv/modules/commits")
        .join(format!("{:x}", Sha256::digest(repository.as_bytes())))
        .join(&commit)
        .join("source/tasks/lint/task.yaml");
    LocalGitFixture {
        fixture,
        origin: origin.canonicalize().unwrap(),
        spec,
        cached,
        package_sha256: format!("{:x}", Sha256::digest(LOCAL_GIT_PACKAGE.as_bytes())),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_local_git_task_package_fetches_then_needs_execution_trust() {
    let local = local_git_fixture();
    let fixture = &local.fixture;

    // Without the repository allow-list, neither reading nor fetching reaches
    // the local repository.
    let inspect = fixture.run(&["inspect"]);
    assert_eq!(inspect.status.code(), Some(5), "{inspect:?}");
    assert!(stderr(&inspect).contains("not trusted"), "{inspect:?}");
    let fetch = fixture.run(&["remote", "fetch", &local.spec]);
    assert_eq!(fetch.status.code(), Some(5), "{fetch:?}");
    assert!(stderr(&fetch).contains("not trusted"), "{fetch:?}");
    assert!(!fixture.path(".neoenv/modules").exists());

    // The allow-list authorizes a fetch; it does not fetch by itself and does
    // not execute anything.
    let trusted = fixture
        .command()
        .args(["trust", "add"])
        .arg(format!("file://{}", local.origin.display()))
        .output()
        .unwrap();
    assert!(trusted.status.success(), "{trusted:?}");
    assert!(String::from_utf8_lossy(&trusted.stdout).contains("file://"));
    let inspect = fixture.run(&["inspect"]);
    assert_eq!(inspect.status.code(), Some(3), "{inspect:?}");
    assert!(stderr(&inspect).contains("not fetched"), "{inspect:?}");

    // An explicit bounded fetch fills the immutable cache layout. The process
    // environment tries to rewrite the local path to HTTPS/SSH through Git's
    // config-in-environment channel; the fetch must ignore that channel and
    // the non-file protocols are denied, so no network request can be made.
    let origin_path = local.origin.display().to_string();
    let fetched = fixture
        .command()
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "url.https://127.0.0.1:9/.insteadOf")
        .env("GIT_CONFIG_VALUE_0", &origin_path)
        .env("GIT_CONFIG_KEY_1", "url.ssh://127.0.0.1:9/.insteadOf")
        .env("GIT_CONFIG_VALUE_1", &origin_path)
        .env(
            "GIT_CONFIG_PARAMETERS",
            format!("'url.https://127.0.0.1:9/.insteadOf'='{origin_path}'"),
        )
        .args(["remote", "fetch", &local.spec])
        .output()
        .unwrap();
    assert!(
        fetched.status.success(),
        "a rewritten local path must not be followed: {fetched:?}; diagnostic: {}",
        if fetched.status.success() {
            String::new()
        } else {
            diagnose_local_git(&local)
        }
    );
    assert!(local.cached.is_file(), "subfolder document was not cached");
    assert!(
        !fixture.path("local-git-package-ran").exists(),
        "fetch must not execute the task"
    );

    // Fetch success is not execution approval, even with the root approved.
    fixture.approve_root();
    let refused = fixture.run(&["task", "run", "check"]);
    Fixture::assert_trust_refusal(&refused);
    assert!(!fixture.path("local-git-package-ran").exists());

    // Approve the exact repository, commit, and subpath.
    let approved = fixture
        .command()
        .args(["trust", "add", "--remote", &local.spec])
        .output()
        .unwrap();
    assert!(approved.status.success(), "{approved:?}");
    assert!(String::from_utf8_lossy(&approved.stdout).contains("blake3:"));

    // The bytes are trusted. The package is external, so it still needs its
    // own execute grant.
    let denied = fixture.run(&["task", "run", "check"]);
    assert!(!denied.status.success(), "{denied:?}");
    assert!(stderr(&denied).contains("capability execute"), "{denied:?}");
    assert!(!fixture.path("local-git-package-ran").exists());

    fs::write(
        fixture.config.join("neoenv/capabilities.toml"),
        format!(
            "[[grants]]\nsubject = {:?}\ncapability = \"execute\"\n",
            format!("package:{}", local.package_sha256)
        ),
    )
    .unwrap();
    let ran = fixture.run(&["task", "run", "check"]);
    assert!(ran.status.success(), "{ran:?}");
    assert!(fixture.path("local-git-package-ran").exists());

    // Replaced cache bytes are refused before anything runs.
    fs::remove_file(fixture.path("local-git-package-ran")).unwrap();
    fs::write(
        &local.cached,
        "tasks:\n  lint:\n    uses: shell\n    run: 'touch tampered-local-git-ran'\n",
    )
    .unwrap();
    let tampered = fixture.run(&["task", "run", "check"]);
    assert!(!tampered.status.success(), "{tampered:?}");
    assert!(
        stderr(&tampered).contains("remote cache does not match")
            || stderr(&tampered).contains("does not match"),
        "{tampered:?}"
    );
    assert!(!fixture.path("tampered-local-git-ran").exists());
}

#[test]
fn a_local_git_branch_or_tag_is_not_an_execution_identity() {
    let local = local_git_fixture();
    let fixture = &local.fixture;
    assert!(
        fixture
            .command()
            .args(["trust", "add"])
            .arg(format!("file://{}", local.origin.display()))
            .output()
            .unwrap()
            .status
            .success()
    );

    for (revision, expected) in [("main", "not a branch"), ("tag:v1", "not immutable")] {
        let spec = format!(
            "{}@{revision}//tasks/lint/task.yaml",
            local.origin.display()
        );
        let fetched = fixture.run(&["remote", "fetch", &spec]);
        assert_eq!(fetched.status.code(), Some(3), "{fetched:?}");
        assert!(stderr(&fetched).contains(expected), "{fetched:?}");
    }

    let branch_spec = format!("{}@main//tasks/lint/task.yaml", local.origin.display());
    let branch_spec = serde_json::to_string(&branch_spec).unwrap();
    fixture.write(
        "neoenv.yaml",
        &format!("task_packages:\n  lint:\n    from: {branch_spec}\n    task: lint\n"),
    );
    let inspect = fixture.run(&["inspect"]);
    assert_eq!(inspect.status.code(), Some(3), "{inspect:?}");
    assert!(stderr(&inspect).contains("not a branch"), "{inspect:?}");
    assert!(!fixture.path("local-git-package-ran").exists());
}

#[cfg(unix)]
#[test]
fn a_github_fetch_is_refused_without_spawning_a_network_git_command() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new("format_version: 1\n");
    // The repository is allow-listed, so the refusal below is about the
    // transport and not about fetch policy.
    fs::write(
        fixture.config.join("neoenv/trust.toml"),
        "[remote]\nallow = [\"acme/modules\"]\n",
    )
    .unwrap();

    // Every Git child would be recorded here. The refusal must happen before
    // any child starts, so the log cannot exist afterwards.
    let bin = fixture.root.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let log = fixture.root.path().join("git-invocations.log");
    let wrapper = bin.join("git");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 99\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let commit = "0123456789abcdef0123456789abcdef01234567";
    let source = format!("github:acme/modules@{commit}//module.yaml");
    let output = fixture
        .command()
        .env("PATH", path)
        .args(["remote", "fetch", &source])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        stderr(&output).contains("non-local fetch is not enabled"),
        "{output:?}"
    );
    assert!(!fixture.path(".neoenv/modules").exists());
    assert!(
        !log.exists(),
        "a Git child was spawned for a non-local fetch: {:?}",
        fs::read_to_string(&log).ok()
    );
}
