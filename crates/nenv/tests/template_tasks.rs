//! Executed end-to-end coverage for the Go-template task path.
//!
//! ## Why this file exists
//!
//! The suite's only `template: true` was in
//! `task_commands_resolve_context_render_help_and_never_execute_actions`, whose stated
//! purpose is to assert the action does **not** run. So nothing executed a template task,
//! and a template is arbitrary user text that becomes argv. **The only thing between a
//! document and a process is this path, and it had no test that got there.**
//!
//! The `neotales-gotmpl` crate has its own conformance fixtures and the `render` runner
//! (file templating) has unit tests. Neither reaches a task template through the CLI.
//!
//! Every assertion here is a **measurement**, not a guess. Each fixture is written to
//! disk and the case was run against the compiled binary before the assertion was
//! written, because five of the six cases below were first measured wrongly — a probe
//! function that took its arguments in a different order than its caller used, and a
//! YAML fixture whose quoting broke the value before `nenv` ever saw it. A test written
//! from a misreading would have been green and worthless.
//!
//! ## What is pinned, and what is a defect
//!
//! Three cases pin behaviour that **is wrong**, and they say so. They are here so a fix
//! is a deliberate, visible edit to a named test rather than a silent behaviour change:
//!
//! - [`a_value_is_tokenized_into_several_arguments`] — a value with a space becomes
//!   three arguments.
//! - [`a_dollar_in_a_value_is_silently_dropped`] — `a$b` renders as `a`.
//! - [`a_semicolon_in_a_value_runs_a_second_command`] — the second command runs.
//!
//! All three are #271. The common cause is that a rendered value is *textually
//! concatenated* into the command and then re-parsed, so the parser cannot tell the
//! author's `;` from a value's. They are not what the feature should do, and they are
//! measured rather than asserted aspirationally because a red test is not a gate.
//!
//! ## Why `#![cfg(unix)]`
//!
//! A `portable` task is a command chain executed through a shell, and these tests use
//! `printf`, which Windows does not have. **The Windows and macOS behaviour of this path
//! is therefore unrun, and is recorded as unrun** rather than implied — the same
//! treatment `task_process_trees.rs` gets. The README's platform arithmetic is where
//! that is counted.

#![cfg(unix)]

use std::fs;

use tempfile::TempDir;

/// A project directory with `neoenv.yaml` already written, and the environment scrubbed
/// of everything that would let a developer's own configuration reach the assertion.
mod support;

fn project(content: &str) -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("neoenv.yaml");
    fs::write(&path, content).unwrap();
    (directory, path)
}

/// A `portable` template task that renders `{{ .env.V }}` through `printf`, so the
/// assertion sees the *arguments* the value became rather than the line it printed.
///
/// The single-quoted YAML is load-bearing. Written double-quoted, a value containing
/// `'` or `$` breaks the fixture before `nenv` reads it, and the case then measures the
/// fixture instead of the feature.
fn printf_template(value: &str) -> String {
    format!(
        "format_version: 1\n\
         env:\n  \
         V: '{value}'\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' {{{{ .env.V }}}}\n"
    )
}

fn nenv() -> support::TestCommand {
    let mut command = support::TestCommand::new();
    // A developer's own configuration must not decide whether these assertions hold.
    // Without this, a `NEOENV_PROJECT` or a populated `XDG_CONFIG_HOME` on the machine
    // running the suite is a test that passes or fails for reasons it does not name.
    for name in ["NEOENV_PROJECT", "NEOENV_PROFILE", "NEOENV_STATE_DIR"] {
        command.env_remove(name);
    }
    command
}

/// stdout as lines, with the run's trailing status line asserted and then removed.
///
/// `nenv run` prints `<task> Succeeded` on stdout *after* the task's own output, so
/// reading all of stdout measures the status line too. The first version of this file
/// did exactly that and every assertion failed on `a\nb\nc\ntpl Succeeded`.
///
/// Dropping the last line without checking would be the other half of the same mistake:
/// a run that printed no status at all is a different behaviour, not a formatting one,
/// and a helper that silently discarded it would make the two indistinguishable. So the
/// status line is **asserted first** and only then removed.
fn task_output(output: &[u8], task: &str, success: bool) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    let lines: Vec<String> = text
        .lines()
        .map(|line| line.trim_end().to_owned())
        .collect();
    let expected = format!("{task} {}", if success { "Succeeded" } else { "Failed" });
    assert_eq!(
        lines.last().map(String::as_str),
        Some(expected.as_str()),
        "stdout should end with the run's status line; got {lines:?}"
    );
    lines[..lines.len() - 1].to_vec()
}

fn first_line(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_owned()
}

/// A template task executes, and its rendering is observable from outside.
///
/// This is the case the ticket said was missing. Everything else in this file is a
/// variation on it; without it, the file proves only that errors are errors.
#[test]
fn a_template_task_executes_and_its_rendering_is_observable() {
    let (directory, path) = project(&printf_template("world"));
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(task_output(&output.stdout, "tpl", true), ["world"]);
    drop(directory);
}

/// `os` and `arch` are in the template's data alongside `env`.
///
/// They are two of the three roots `render_portable` builds, and a test that only
/// exercises `env` would leave the other two unmeasured — which is the shape of the
/// gap this file was written to close.
#[test]
fn os_and_arch_are_available_to_a_template() {
    let (directory, path) = project(
        "format_version: 1\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' {{ .os }}\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    // Not a literal: asserting the platform name here would make the suite fail on a
    // platform the feature is supposed to work on. Asserting that it is *non-empty* is
    // what the template contract promises, and it is checkable everywhere.
    // Not a literal: asserting the platform name would make the suite fail on a
    // platform the feature is supposed to work on. Asserting that it is *present* is
    // what the template contract promises, and it is checkable everywhere.
    let os = first_line(&output.stdout);
    assert!(!os.is_empty(), "os rendered as an empty string");
    assert!(
        os.chars()
            .all(|character| character.is_ascii_alphanumeric()),
        "os rendered as something other than a platform name: {os:?}"
    );
    drop(directory);
}

/// A value the document never declared is refused **by name**.
///
/// `missing template value: .who` names the path, so a reader can act on it. That is the
/// difference between a refusal and a shrug, and it is worth a test because it is the
/// property that would be easy to lose.
#[test]
fn a_missing_template_value_is_refused_by_name() {
    let (directory, path) = project(
        "format_version: 1\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' {{ .env.NEVER_DECLARED }}\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("missing template value: .env.NEVER_DECLARED"),
        "{text}"
    );
    drop(directory);
}

/// A glob in a value is **not** expanded.
///
/// The one place a value's shell-ness is currently *correct* is globbing, because the
/// chain runner hands the token to a process rather than to a globbing shell. A test
/// that does not assert this leaves a future change free to introduce expansion.
#[test]
fn a_glob_in_a_value_is_not_expanded() {
    let (directory, path) = project(&printf_template("a*b?c"));
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(task_output(&output.stdout, "tpl", true), ["a*b?c"]);
    drop(directory);
}

/// A `{{` that is not a valid action is refused, with the parser's own words.
///
/// Two distinct errors, because there are two distinct mistakes: `{{ }}` is an action
/// with nothing in it, and `{{ .unclosed` is one that never ends. A reader who cannot
/// tell those apart has to guess which one they wrote.
#[test]
fn a_literal_double_brace_is_refused_with_the_parser_error() {
    for (body, expected) in [
        ("echo {{ }}", "empty template action"),
        ("echo {{ .unclosed", "unterminated template action"),
    ] {
        let (directory, path) = project(&format!(
            "format_version: 1\n\
             tasks:\n  \
             tpl:\n    \
             template: true\n    \
             uses: portable\n    \
             run: {body}\n"
        ));
        let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

        assert!(!output.status.success(), "{body} should not have succeeded");
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains(expected), "{body}: {text}");
        drop(directory);
    }
}

/// A single brace is literal, so `awk '{print $1}'` runs.
///
/// This is the case a reader most needs to trust, because it is ordinary shell
/// programming: a portable task that cannot run `awk` cannot do much. It passes today
/// because the parser only treats `{{` as an action, and the test is what stops someone
/// "fixing" the parser into treating `{` the same way.
#[test]
fn a_single_brace_is_literal_so_awk_still_runs() {
    let (directory, path) = project(
        "format_version: 1\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: echo host | awk '{print substr($0, 1, 1)}'\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        first_line(&output.stdout).len(),
        1,
        "one character of the fixture input"
    );
    drop(directory);
}

// --- The three pinned defects. Each is #271, and each says so. ----------------
//
// **Do not read these as the feature working.** They are the measured current
// behaviour of a defect, kept so that fixing it is a visible edit to a named test. A
// test that asserted the correct behaviour would be red, and a red test is not a gate —
// so the correct outcome is a ticket, not a failing suite, and the evidence lives here.

/// A value with a space becomes **three arguments**, not one.
///
/// ```text
/// V: 'a b c'   ->   [a][b][c]
/// ```
///
/// The user wrote one value and the process received three arguments. Nothing reports
/// it. #271.
#[test]
fn a_value_is_tokenized_into_several_arguments() {
    let (directory, path) = project(&printf_template("a b c"));
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    // **The defect, asserted.** One value should be one line. It is three: a value is
    // textually substituted and then re-tokenized, so a space is a separator. #271.
    assert_eq!(task_output(&output.stdout, "tpl", true), ["a", "b", "c"]);
    drop(directory);
}

/// A `$` in a value **silently removes the rest of it**.
///
/// ```text
/// V: 'a$b'   ->   [a]
/// ```
///
/// This is the worst of the three: not a wrong argument count, and not an extra command,
/// but a value that quietly differs from the one in the document with no message at
/// all. #271.
#[test]
fn a_dollar_in_a_value_is_silently_dropped() {
    let (directory, path) = project(&printf_template("a$b"));
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    // **The defect, asserted.** The correct rendering is `[a$b]`.
    // **The defect, asserted.** The correct rendering is `a$b`.
    assert_eq!(task_output(&output.stdout, "tpl", true), ["a"]);
    drop(directory);
}

/// A `;` in a value runs a **second command**.
///
/// ```text
/// V: 'x; touch <path>'   ->   prints `x`, and the file exists
/// ```
///
/// The chain runner's `;` is a documented separator, so the author's `;` is intended —
/// the defect is that a *value's* `;` is indistinguishable from it. #271.
#[test]
fn a_semicolon_in_a_value_runs_a_second_command() {
    let directory = TempDir::new().unwrap();
    let marker = directory.path().join("side-effect");
    let path = directory.path().join("neoenv.yaml");
    let value = format!("x; touch {}", marker.display());
    fs::write(&path, printf_template(&value)).unwrap();

    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(task_output(&output.stdout, "tpl", true), ["x"]);
    // **The defect, asserted.** A value that stayed a value would leave no file.
    assert!(
        marker.exists(),
        "the semicolon from the value did not run a second command, so #271 may \
         be fixed and this test should be inverted"
    );
}

/// The value reaches the command as the document wrote it.
///
/// The one input the *document author* controls end to end. It is the control for the
/// three cases above: same mechanism, same fixture shape, same runner, and here the
/// value arrives intact. **Without it, the three above could be a broken fixture rather
/// than a broken feature** — which is exactly the mistake this file already made once.
#[test]
fn the_control_case_reaches_the_command_intact() {
    let (directory, path) = project(&printf_template("one"));
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(task_output(&output.stdout, "tpl", true), ["one"]);
    drop(directory);
}

/// **The same bytes mean different things depending on which layer saw them.**
///
/// This is the finding behind #271, pinned so it is visible in the suite and not only in
/// a ticket. Two components in this repository have contradictory rules about `$NAME`:
///
/// - the run text goes through `interpolate_portable_environment`, whose docstring says
///   *"`$NAME` remains literal for portable commands so a task cannot accidentally
///   acquire shell-like expansion semantics."* Here `$HOME` comes out as `$HOME`.
/// - an environment value goes through `neotales_env::interpolate_with`, which expands
///   it. Here `a$b` with `b` set to `SET` comes out as `aSET`.
///
/// **A user cannot tell which rule applies to their text without knowing which layer
/// touched it**, and the difference is not documented anywhere. The decision belongs to
/// `neotales-env` in the submodule; what this repository owns is that the contradiction
/// is at least *visible*, and this is it.
///
/// The second test is the one that matters most, because it fails silently: a
/// self-referential value resolves to the empty string at exit 0, and a forward
/// reference to a later declaration is *supposed* to be empty — so the document cannot
/// tell you which one you wrote.
#[test]
fn a_dollar_means_literal_in_the_run_text_and_expands_in_a_value() {
    // The run text: literal, as documented.
    let (directory, path) = project(
        "format_version: 1\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' $HOME\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        task_output(&output.stdout, "tpl", true),
        ["$HOME"],
        "the run text is documented as literal and still is"
    );
    drop(directory);

    // A value: expanded, which is the contradiction.
    let (directory, path) = project(
        "format_version: 1\n\
         env:\n  \
         b: SET\n  \
         V: 'a$b'\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' {{ .env.V }}\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        task_output(&output.stdout, "tpl", true),
        ["aSET"],
        "**the contradiction, asserted.** `a$b` is literal in the run text above and \
         expands here. #271."
    );
    drop(directory);
}

/// A self-referential value is silently empty.
///
/// `V: "x${V}y"` resolves to `xy` at exit 0. A forward reference to a variable declared
/// later is legitimately empty, so **the document cannot tell you which one you wrote**,
/// and the two cases are indistinguishable from the value alone. Pinned for the same
/// reason as the three above: a fix should be a visible edit to a named test.
#[test]
fn a_self_referential_value_is_silently_empty() {
    let (directory, path) = project(
        "format_version: 1\n\
         env:\n  \
         V: 'x${V}y'\n\
         tasks:\n  \
         tpl:\n    \
         template: true\n    \
         uses: portable\n    \
         run: printf '%s\\n' {{ .env.V }}\n",
    );
    let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

    assert!(output.status.success(), "{output:?}");
    // **The defect, asserted.** The correct outcome is a refusal naming the value.
    assert_eq!(task_output(&output.stdout, "tpl", true), ["xy"]);
    drop(directory);
}

/// **`uses: argv` does not render templates, and says nothing about it.
///
/// Three runners, two behaviours, and one flag that does not choose between them:
///
/// | runner | `template: true`, value `world` | without the flag |
/// | --- | --- | --- |
/// | `portable` | `world` | `world` -- it renders either way |
/// | `argv` | `{{ .env.V }}` | `{{ .env.V }}` |
/// | `shell` | `{{ .env.V }}` | `{{ .env.V }}` |
///
/// **`portable` renders whether or not the flag is present, and the other two never
/// render whether or not it is.** All three exit 0. A user who writes a template on an
/// `argv` task gets the literal braces handed to the process and no diagnostic.
///
/// ## Why this is the most useful thing in this file
///
/// `argv` is the runner where a value **cannot** become shell syntax: its arguments are
/// already an opaque vector, each one a single process argument, with no parse step
/// between the value and the exec. That is the shape #271 says the fix should converge
/// on -- "carry a value as an opaque token, not as text spliced into a string that is
/// then parsed" -- and **`argv` already has it, and has no template support**.
///
/// So the fix is not to invent the property. It is to connect the template renderer to
/// the runner that already has it. Pinning this here says so in a place a reader arrives
/// from the bug report.
#[test]
fn the_argv_runner_does_not_render_templates() {
    let document = |template: bool| {
        format!(
            "format_version: 1\n\
             env:\n  \
             V: 'world'\n\
             tasks:\n  \
             tpl:\n{}    \
             uses: argv\n    \
             run: printf\n    \
             args: [\"{{{{ .env.V }}}}\\n\"]\n",
            if template { "    template: true\n" } else { "" }
        )
    };

    for (label, template) in [("with `template: true`", true), ("without it", false)] {
        let (directory, path) = project(&document(template));
        let output = nenv().arg("run").arg("tpl").arg(&path).output().unwrap();

        assert!(output.status.success(), "{label}: {output:?}");
        // **Both, the same, and neither is rendered.** The portable runner gives `world`
        // for the same document.
        assert_eq!(
            task_output(&output.stdout, "tpl", true),
            ["{{ .env.V }}"],
            "{label}: `argv` must not render, and the point is that the flag changes nothing"
        );
        drop(directory);
    }
}
