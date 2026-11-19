//! End-to-end checks for lazy `nsv://` resolution through the binary.
//!
//! These are integration tests because the property being verified is *where*
//! resolution happens: `validate` and `inspect` must not open a vault, while
//! shell activation, `exec`, and task execution must. A unit test of the resolver
//! cannot see that distinction.

use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Output, Stdio},
};

use neotales_age::{AgeFile, AgeKey, AgeRecipient};
use tempfile::TempDir;

struct Fixture {
    _directory: TempDir,
    canonical_path: PathBuf,
    config: PathBuf,
    identity: PathBuf,
    recipient: String,
}

impl Fixture {
    fn new() -> Self {
        Self::from_directory(TempDir::new().unwrap())
    }

    fn from_directory(directory: TempDir) -> Self {
        // The vault lock deliberately rejects symlink ancestors. TempDir may
        // retain a symlinked system temp path (for example on macOS).
        #[cfg(unix)]
        let canonical_path = directory.path().canonicalize().unwrap();
        #[cfg(not(unix))]
        let canonical_path = directory.path().to_owned();
        let key = AgeKey::generate().unwrap();
        let identity = canonical_path.join("identity.txt");
        fs::write(&identity, format!("{}\n", key.private_key)).unwrap();
        let config = canonical_path.join("neoenv.yaml");
        Self {
            _directory: directory,
            canonical_path,
            config,
            identity,
            recipient: key.public_key,
        }
    }

    fn seal(&self, plaintext: &str) -> String {
        let recipient = AgeRecipient::from_public_key(&self.recipient).unwrap();
        AgeFile::encrypt_armored(plaintext.as_bytes(), &[recipient]).unwrap()
    }

    fn path(&self) -> &Path {
        &self.canonical_path
    }

    fn write_config(&self, body: &str) {
        fs::write(&self.config, body).unwrap();
    }

    fn project_header(&self) -> String {
        format!(
            "format_version: 1\nvaults:\n  machine:\n    driver: age\n    identity: {}\n    values:\n      token: |\n",
            self.identity.display()
        )
    }

    fn indent_ciphertext(value: &str) -> String {
        value.lines().fold(String::new(), |mut output, line| {
            writeln!(output, "        {line}").unwrap();
            output
        })
    }
}

mod support;

fn run(cwd: &Path, arguments: &[&str]) -> Output {
    support::TestCommand::new()
        .current_dir(cwd)
        .args(arguments)
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .env("NEOENV_STATE_HOME", cwd.join(".state"))
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn shell_activation_resolves_a_project_environment_reference() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str("env:\n  TOKEN: nsv://machine/token\n  PLAIN: visible\n");
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    let rendered = stdout(&output);
    assert!(rendered.contains("TOKEN='resolved-token'"), "{rendered}");
    assert!(rendered.contains("PLAIN='visible'"), "{rendered}");
}

#[test]
fn validate_and_inspect_never_open_the_vault() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("unused")));
    config.push_str("env:\n  ENTRY_REFERENCE: nsv://machine/token\n");
    fixture.write_config(&config);
    // The declaration still names this path. Removing the identity proves the
    // configuration commands did not resolve the reference; if they had, they
    // would fail with the missing identity file.
    fs::remove_file(&fixture.identity).unwrap();

    let validate = run(
        fixture.path(),
        &["validate", fixture.config.to_str().unwrap()],
    );
    assert_success(&validate);
    let inspect = run(
        fixture.path(),
        &["inspect", fixture.config.to_str().unwrap()],
    );
    assert_success(&inspect);
    assert!(stdout(&inspect).contains("nsv://machine/token"));
}

#[test]
fn exec_resolves_dotenv_and_env_overrides() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str("env:\n  PLAIN: visible\n");
    fixture.write_config(&config);
    let dotenv = fixture.path().join("overrides.env");
    fs::write(&dotenv, "CLI_DOTENV=nsv://machine/token\n").unwrap();

    let output = run(
        fixture.path(),
        &[
            "exec",
            "-p",
            fixture.config.to_str().unwrap(),
            "-E",
            dotenv.to_str().unwrap(),
            "-e",
            "CLI_ENV=nsv://machine/token",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$CLI_DOTENV\" \"$CLI_ENV\"",
        ],
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "resolved-token|resolved-token");
}

#[test]
fn task_execution_resolves_task_env_task_dotenv_and_env_overrides() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str(
        "dotenv:\n  - path: task.env\ntasks:\n  show:\n    uses: shell\n    env:\n      FROM_TASK: nsv://machine/token\n    run: 'printf \"%s|%s|%s|%s\" \"$FROM_TASK\" \"$FROM_DOTENV\" \"$FROM_CLI\" \"$FROM_CLI_DOTENV\"'\n",
    );
    fixture.write_config(&config);
    fs::write(
        fixture.path().join("task.env"),
        "FROM_DOTENV=nsv://machine/token\n",
    )
    .unwrap();
    fs::write(
        fixture.path().join("cli.env"),
        "FROM_CLI_DOTENV=nsv://machine/token\n",
    )
    .unwrap();

    let output = run(
        fixture.path(),
        &[
            "run",
            "show",
            "-p",
            fixture.config.to_str().unwrap(),
            "-E",
            "cli.env",
            "-e",
            "FROM_CLI=nsv://machine/token",
        ],
    );
    assert_success(&output);
    assert!(
        stdout(&output).contains("resolved-token|resolved-token|resolved-token|resolved-token")
    );
}

#[test]
fn a_missing_vault_is_a_named_error_not_a_literal_value() {
    let fixture = Fixture::new();
    fixture.write_config("format_version: 1\nenv:\n  TOKEN: nsv://machine/token\n");

    let output = run(
        fixture.path(),
        &[
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("referenced vault is not declared"),
        "{error}"
    );
    assert!(!error.contains("export TOKEN"), "{error}");
}

#[test]
fn a_dry_run_never_opens_a_vault_for_project_env_or_a_predicate() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("unused")));
    config.push_str(
        "env:\n  TOKEN: nsv://machine/token\ntasks:\n  show:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    force: env.TOKEN == resolved-token\n    if: env.TOKEN == resolved-token\n    run: 'true'\n",
    );
    fixture.write_config(&config);
    // A dry run plans the task but never executes it, and it must not resolve the
    // project environment or evaluate a predicate by opening a vault. The missing
    // identity is the proof: if either path resolved, this would fail.
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &[
            "run",
            "show",
            "--dry-run",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("Conditional"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unresolved secret reference"),
        "a conditional predicate must say so: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_project_reference_replaced_by_an_override_is_never_fetched() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("unused")));
    config.push_str(
        "env:\n  TOKEN: nsv://machine/token\ntasks:\n  show:\n    uses: shell\n    run: 'printf %s \"$TOKEN\"'\n",
    );
    fixture.write_config(&config);
    // The identity would be required by the project value, but `-e` replaces that
    // value before any consumption point. Resolving the replaced value first would
    // fail here.
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &[
            "run",
            "show",
            "-p",
            fixture.config.to_str().unwrap(),
            "-e",
            "TOKEN=from-command-line",
        ],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("from-command-line"));
}

#[test]
fn a_reference_sees_the_final_cli_interpolation_context() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str("env:\n  TOKEN: nsv://machine/${WHICH}\n");
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "exec",
            "-p",
            fixture.config.to_str().unwrap(),
            "-e",
            "WHICH=token",
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ],
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "resolved-token");
}

#[test]
fn an_explicitly_named_inherited_input_is_available_to_a_reference() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str("env:\n  TOKEN: nsv://${INHERITED_VAULT}/token\n");
    fixture.write_config(&config);

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ])
        .env("INHERITED_VAULT", "machine")
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert!(stdout(&output).contains("TOKEN='resolved-token'"));
}

#[test]
fn an_unrelated_inherited_reference_is_not_scanned_or_resolved() {
    let fixture = Fixture::new();
    fixture.write_config("format_version: 1\n");
    // The identity does not exist. If the resolver scanned inherited values it
    // would try to resolve this one and fail; it is inherited, not supplied.
    fs::remove_file(&fixture.identity).unwrap();

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "exec",
            "-p",
            fixture.config.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "printf %s \"$INHERITED\"",
        ])
        .env("INHERITED", "nsv://machine/token")
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(stdout(&output), "nsv://machine/token");
}

#[test]
fn a_resolved_plaintext_that_looks_like_a_reference_is_not_resolved_again() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(
        &fixture.seal("nsv://machine/second-pass"),
    ));
    config.push_str("env:\n  TOKEN: nsv://machine/token\n");
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("TOKEN='nsv://machine/second-pass'"));
}

#[test]
fn a_reference_sees_a_later_project_environment_value() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    // TOKEN is declared before ENTRY. The reference must interpolate against the
    // complete final scope, not only the keys that happened to precede it.
    config.push_str("env:\n  TOKEN: nsv://machine/${ENTRY}\n  ENTRY: token\n");
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("TOKEN='resolved-token'"));
}

#[test]
fn a_project_reference_replaced_by_a_task_value_is_never_fetched() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("unused")));
    config.push_str(
        "env:\n  TOKEN: nsv://machine/token\ntasks:\n  show:\n    uses: shell\n    env:\n      TOKEN: from-task\n    run: 'printf %s \"$TOKEN\"'\n",
    );
    fixture.write_config(&config);
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &["run", "show", "-p", fixture.config.to_str().unwrap()],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("from-task"));
}

#[test]
fn an_e_override_equal_to_an_inherited_reference_is_still_supplied_and_resolved() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "exec",
            "-p",
            fixture.config.to_str().unwrap(),
            "-e",
            "TOKEN=nsv://machine/token",
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ])
        .env("TOKEN", "nsv://machine/token")
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert!(stdout(&output).starts_with("resolved-token"));
}

#[test]
fn an_e_dotenv_assignment_equal_to_an_inherited_reference_is_still_supplied() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);
    let dotenv = fixture.path().join("same.env");
    fs::write(&dotenv, "TOKEN=nsv://machine/token\n").unwrap();

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "exec",
            "-p",
            fixture.config.to_str().unwrap(),
            "-E",
            dotenv.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ])
        .env("TOKEN", "nsv://machine/token")
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(stdout(&output), "resolved-token");
}

#[test]
fn a_task_dotenv_assignment_equal_to_an_inherited_reference_is_still_supplied() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str(
        "tasks:\n  show:\n    uses: shell\n    dotenv: task.env\n    run: 'printf %s \"$FROM_DOTENV\"'\n",
    );
    fixture.write_config(&config);
    fs::write(
        fixture.path().join("task.env"),
        "FROM_DOTENV=nsv://machine/token\n",
    )
    .unwrap();

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args(["run", "show", "-p", fixture.config.to_str().unwrap()])
        .env("FROM_DOTENV", "nsv://machine/token")
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert!(stdout(&output).starts_with("resolved-token"));
}

#[test]
fn an_inherited_input_can_supply_an_age_identity_path() {
    let fixture = Fixture::new();
    let mut config = String::from(
        "format_version: 1\nvaults:\n  machine:\n    driver: age\n    identity: ${AGE_IDENTITY}\n    values:\n      token: |\n",
    );
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str("env:\n  TOKEN: nsv://machine/token\n");
    fixture.write_config(&config);

    let output = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ])
        .env("AGE_IDENTITY", fixture.identity.to_str().unwrap())
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .output()
        .unwrap();
    assert_success(&output);
    assert!(stdout(&output).contains("TOKEN='resolved-token'"));
}

#[test]
fn a_numeric_predicate_error_does_not_echo_the_resolved_secret() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(
        &fixture.seal("super-secret-sentinel"),
    ));
    config.push_str(
        "tasks:\n  show:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET && env.SECRET % 2 == 0\n    run: 'true'\n",
    );
    fixture.write_config(&config);

    for arguments in [
        vec!["run", "show", "-p", fixture.config.to_str().unwrap()],
        vec![
            "--format",
            "json",
            "run",
            "show",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    ] {
        let output = run(fixture.path(), &arguments);
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains("super-secret-sentinel"), "{stdout}");
        assert!(!stderr.contains("super-secret-sentinel"), "{stderr}");
    }
}

#[test]
fn a_conditional_task_propagates_through_dependencies_and_outcome_predicates() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("unused")));
    config.push_str(
        "tasks:\n  first:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET == resolved-token\n    run: 'true'\n  second:\n    needs: [first]\n    uses: shell\n    if: outcome.first == succeeded\n    run: 'true'\n  third:\n    needs: [second]\n    uses: shell\n    run: 'true'\n",
    );
    fixture.write_config(&config);
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &[
            "--format",
            "json",
            "run",
            "third",
            "--dry-run",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    let report = stdout(&output);
    for task in ["first", "second", "third"] {
        assert!(
            report.contains(&format!("\"name\": \"{task}\""))
                && report.contains("\"outcome\": \"conditional\""),
            "{task} must be conditional: {report}"
        );
    }
    assert!(!report.contains("\"outcome\": \"skipped\""), "{report}");
    assert!(!report.contains("\"outcome\": \"blocked\""), "{report}");
}

#[test]
fn conditional_state_uses_planner_selection_for_context_needs_and_hooks() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str(
        "context: prod\ntasks:\n  first:prod:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET == resolved-token\n    run: 'true'\n  second:\n    needs: [first]\n    uses: shell\n    run: 'true'\n  build:\n    uses: shell\n    run: 'true'\n    hooks:\n      before: prep\n      after: cleanup\n  build:prep:prod:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET == resolved-token\n    run: 'true'\n  build:cleanup:prod:\n    uses: shell\n    run: 'true'\n",
    );
    fixture.write_config(&config);
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &[
            "--format",
            "json",
            "run",
            "build",
            "--context",
            "prod",
            "--dry-run",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    let report = stdout(&output);
    for task in ["build:prep:prod", "build", "build:cleanup:prod"] {
        assert!(
            report.contains(&format!("\"name\": \"{task}\""))
                && report.contains("\"outcome\": \"conditional\""),
            "{task} must be conditional: {report}"
        );
    }

    let output = run(
        fixture.path(),
        &[
            "--format",
            "json",
            "run",
            "second",
            "--context",
            "prod",
            "--dry-run",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    let report = stdout(&output);
    assert!(report.contains("\"name\": \"first:prod\""), "{report}");
    assert!(report.contains("\"name\": \"second\""), "{report}");
    assert!(!report.contains("\"outcome\": \"skipped\""), "{report}");
    assert!(report.contains("\"outcome\": \"conditional\""), "{report}");
}

#[test]
fn conditional_state_covers_success_and_output_predicates() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str(
        "tasks:\n  first:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET == resolved-token\n    run: 'true'\n  second:\n    needs: [first]\n    uses: shell\n    if: success\n    run: 'true'\n  third:\n    needs: [first]\n    uses: shell\n    if: output.TOKEN == value\n    run: 'true'\n",
    );
    fixture.write_config(&config);
    fs::remove_file(&fixture.identity).unwrap();

    for root in ["second", "third"] {
        let output = run(
            fixture.path(),
            &[
                "--format",
                "json",
                "run",
                root,
                "--dry-run",
                "-p",
                fixture.config.to_str().unwrap(),
            ],
        );
        assert_success(&output);
        let report = stdout(&output);
        assert!(report.contains("\"name\": \"first\""), "{report}");
        assert!(report.contains("\"outcome\": \"conditional\""), "{report}");
        assert!(!report.contains("\"outcome\": \"skipped\""), "{report}");
        assert!(!report.contains("\"outcome\": \"blocked\""), "{report}");
    }
}

#[test]
fn ordered_siblings_without_edges_inherit_conditional_aggregate_state() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    config.push_str(
        "tasks:\n  first:\n    uses: shell\n    env:\n      SECRET: nsv://machine/token\n    if: env.SECRET == resolved-token\n    run: 'true'\n  second:\n    uses: shell\n    if: success\n    run: 'true'\n  third:\n    uses: shell\n    if: output.TOKEN == value\n    run: 'true'\n  root:\n    needs: [first, second, third]\n    uses: shell\n    run: 'true'\n",
    );
    fixture.write_config(&config);
    // No identity: a fetch would fail. The dry run must only inspect that the
    // earlier sibling is conditional.
    fs::remove_file(&fixture.identity).unwrap();

    let output = run(
        fixture.path(),
        &[
            "--format",
            "json",
            "run",
            "root",
            "--dry-run",
            "-p",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    let report = stdout(&output);
    for task in ["first", "second", "third"] {
        assert!(
            report.contains(&format!("\"name\": \"{task}\""))
                && report.contains("\"outcome\": \"conditional\""),
            "{task} must be conditional without a dependency edge: {report}"
        );
    }
    assert!(!report.contains("\"outcome\": \"skipped\""), "{report}");
    assert!(!report.contains("\"outcome\": \"blocked\""), "{report}");
}

#[test]
fn secret_get_reads_a_configured_age_vault() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "secret",
            "get",
            "nsv://machine/token",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "resolved-token");
}

#[test]
fn secret_get_rejects_the_old_scheme() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);

    let output = run(
        fixture.path(),
        &[
            "secret",
            "get",
            "sv://machine/token",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("reference must start with nsv://"),
        "{error}"
    );
}

#[test]
fn shell_activation_does_not_treat_the_old_scheme_as_a_reference() {
    let fixture = Fixture::new();
    fixture.write_config("format_version: 1\nenv:\n  TOKEN: sv://machine/token\n");

    let output = run(
        fixture.path(),
        &[
            "shell",
            "activate",
            "bash",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert!(stdout(&output).contains("TOKEN='sv://machine/token'"));
}

#[test]
fn secret_set_reads_stdin_and_refuses_a_read_only_driver() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);

    let mut child = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "secret",
            "set",
            "nsv://machine/token",
            fixture.config.to_str().unwrap(),
        ])
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .env("NEOENV_STATE_HOME", fixture.path().join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"stdin-secret-sentinel\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("read-only"), "{stderr}");
    assert!(!stderr.contains("stdin-secret-sentinel"), "{stderr}");
    assert!(!stdout(&output).contains("stdin-secret-sentinel"));
}

#[test]
fn secret_set_rejects_oversized_stdin_before_any_write() {
    let fixture = Fixture::new();
    let mut config = fixture.project_header();
    config.push_str(&Fixture::indent_ciphertext(&fixture.seal("resolved-token")));
    fixture.write_config(&config);

    let mut child = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "secret",
            "set",
            "nsv://machine/token",
            fixture.config.to_str().unwrap(),
        ])
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .env("NEOENV_STATE_HOME", fixture.path().join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let oversized = vec![b'x'; neoenv_runtime::vault::MAX_SECRET_BYTES + 1];
    child.stdin.as_mut().unwrap().write_all(&oversized).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("larger than"), "{stderr}");
    assert!(!stderr.contains("read-only"), "{stderr}");
}

fn write_kdbx(path: &std::path::Path) {
    let mut database = neotales_keepass::KeePassDatabase::default();
    let group = database
        .root
        .add_group(neotales_keepass::Group::new("work"));
    let mut entry = neotales_keepass::Entry::new("entry");
    entry.password = neotales_keepass::ProtectedValue::from_text("old-value");
    group.add_entry(entry);
    let mut bytes = Vec::new();
    neotales_keepass::KdbxFile::save_default(&database, &mut bytes, "master-password").unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn secret_set_updates_keepass_and_preserves_exact_stdin_bytes() {
    check_secret_set_updates_keepass(&Fixture::new());
}

#[cfg(unix)]
#[test]
fn secret_set_works_when_fixture_temp_parent_is_a_symlink() {
    use std::os::unix::fs::symlink;

    let parent = TempDir::new().unwrap();
    let link = parent.path().join("temp-link");
    symlink(parent.path().canonicalize().unwrap(), &link).unwrap();
    let fixture = Fixture::from_directory(TempDir::new_in(&link).unwrap());
    check_secret_set_updates_keepass(&fixture);
}

fn check_secret_set_updates_keepass(fixture: &Fixture) {
    let database = fixture.path().join("secrets.kdbx");
    write_kdbx(&database);
    let config = format!(
        "format_version: 1\nvaults:\n  work:\n    driver: keepass\n    path: {}\n    secret: master-password\n",
        database.display()
    );
    fixture.write_config(&config);

    let mut child = support::TestCommand::new()
        .current_dir(fixture.path())
        .args([
            "secret",
            "set",
            "nsv://work/work/entry",
            fixture.config.to_str().unwrap(),
        ])
        .env_remove("NEOENV_PROJECT")
        .env_remove("NEOENV_CONTEXT")
        .env("NEOENV_STATE_HOME", fixture.path().join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"new-value\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_success(&output);

    let output = run(
        fixture.path(),
        &[
            "secret",
            "get",
            "nsv://work/work/entry",
            fixture.config.to_str().unwrap(),
        ],
    );
    assert_success(&output);
    assert_eq!(stdout(&output), "new-value\n");
}
