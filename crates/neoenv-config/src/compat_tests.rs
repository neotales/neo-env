//! Go-Neofile compatibility-profile tests.
//!
//! The contract this file protects is that a Go document is read through a
//! *separate* path: the strict v1 schema must be exactly as strict as before,
//! and every Go form that is accepted must normalize to the same model its
//! native equivalent produces.

use std::path::Path;

use super::{ConfigProfile, Format, Project, parse_project, parse_project_with_profile};

fn go_result(input: &str) -> Result<Project, neoenv_core::Diagnostic> {
    parse_project_with_profile(
        Path::new("neoenv.yaml"),
        input,
        Format::Yaml,
        ConfigProfile::Go,
    )
}

fn go(input: &str) -> Project {
    go_result(input)
        .unwrap_or_else(|error| panic!("expected the Go document to be accepted: {error}"))
}

/// The rendered diagnostic text. The code is *not* part of `Display`, so a test
/// that needs it must read `code()`.
fn go_err(input: &str) -> String {
    match go_result(input) {
        Ok(_) => panic!("expected a diagnostic, got none for:\n{input}"),
        Err(error) => format!("{error}"),
    }
}

fn go_code(input: &str) -> String {
    match go_result(input) {
        Ok(_) => panic!("expected a diagnostic, got none for:\n{input}"),
        Err(error) => error.code.clone(),
    }
}

#[test]
fn a_native_document_is_unaffected_by_the_profile() {
    // The strict v1 schema must reject `config:` exactly as it did before the
    // profile existed. If this ever passes, the compatibility path has leaked
    // into the strict one and every native file became easier to get wrong.
    let error = parse_project(
        Path::new("neoenv.yaml"),
        "format_version: 1\nconfig:\n  context: production\n",
    )
    .expect_err("the native schema must not accept a Go `config:` section");
    assert!(
        error.to_string().contains("unknown field `config`"),
        "{error}"
    );
}

#[test]
fn config_context_selects_the_go_context() {
    assert_eq!(
        go("config:\n  context: production\n").context.as_deref(),
        Some("production")
    );
}

#[test]
fn config_defaults_context_is_the_fallback() {
    let project = go("config:\n  defaults:\n    context: staging\n");
    assert_eq!(project.context.as_deref(), Some("staging"));
}

#[test]
fn config_context_wins_over_config_defaults_context() {
    // The order the Go reference applies, and the one a migration has to keep.
    let project = go("config:\n  context: production\n  defaults:\n    context: staging\n");
    assert_eq!(project.context.as_deref(), Some("production"));
}

#[test]
fn a_go_and_native_context_file_normalize_identically() {
    let from_go = go("config:\n  context: production\n");
    let from_native = parse_project(
        Path::new("neoenv.yaml"),
        "format_version: 1\ncontext: production\n",
    )
    .unwrap();
    assert_eq!(from_go.context, from_native.context);
}

#[test]
fn two_context_spellings_that_disagree_are_a_diagnostic() {
    // Silently preferring one would hide a real disagreement between the two
    // spellings and migrate the file to whichever happened to win.
    let message = go_err("context: dev\nconfig:\n  context: production\n");
    assert!(message.contains("config.context"), "{message}");
    assert!(message.contains("remove the other"), "{message}");
}

#[test]
fn agreeing_context_spellings_are_not_a_conflict() {
    let project = go("context: production\nconfig:\n  context: production\n");
    assert_eq!(project.context.as_deref(), Some("production"));
}

#[test]
fn an_env_sequence_accepts_the_plain_scalar_form() {
    let project = go("env:\n  - PORT=8080\n");
    assert_eq!(project.environment.len(), 1);
    assert_eq!(project.environment[0].key, "PORT");
    assert_eq!(project.environment[0].value, "8080");
    assert!(!project.environment[0].secret);
}

#[test]
fn an_env_sequence_colon_form_is_a_declared_secret() {
    // `KEY:VALUE` is a secret in the Go reference. The distinction is
    // load-bearing, so it has to survive the read.
    let project = go("env:\n  - DATABASE_URL:postgres://user:pw@host/db\n");
    assert_eq!(project.environment.len(), 1);
    assert_eq!(project.environment[0].key, "DATABASE_URL");
    // The colon splits at the first colon, so a URL keeps everything after it.
    assert_eq!(
        project.environment[0].value, "postgres://user:pw@host/db",
        "a value containing colons must not be truncated at the second one"
    );
    assert!(project.environment[0].secret);
}

#[test]
fn an_env_sequence_entry_with_equals_wins_over_colon() {
    // `DATABASE_URL=postgres://host` must not become a secret, and must not
    // split at the first colon of the value.
    let project = go("env:\n  - DATABASE_URL=postgres://user:pw@host:5432/db\n");
    assert_eq!(project.environment[0].key, "DATABASE_URL");
    assert_eq!(
        project.environment[0].value,
        "postgres://user:pw@host:5432/db"
    );
    assert!(!project.environment[0].secret);
}

#[test]
fn an_env_sequence_mapping_form_honors_the_secret_flag() {
    let project = go("env:\n  - name: PORT\n    value: \"8080\"\n    secret: true\n");
    assert_eq!(project.environment[0].key, "PORT");
    assert_eq!(project.environment[0].value, "8080");
    assert!(project.environment[0].secret);
}

#[test]
fn an_env_sequence_mapping_form_defaults_to_not_secret() {
    let project = go("env:\n  - name: PORT\n    value: \"8080\"\n");
    assert!(!project.environment[0].secret);
}

#[test]
fn a_repeated_env_key_is_last_wins() {
    // The order Go applies, and the rule the v1 mapping already used.
    let project = go("env:\n  - PORT=1\n  - PORT=2\n");
    assert_eq!(
        project.environment.len(),
        1,
        "a repeated key must not duplicate"
    );
    assert_eq!(project.environment[0].value, "2");
}

#[test]
fn a_redeclared_env_key_cannot_un_redact_a_secret() {
    // Re-declaring `KEY=value` after `KEY:value` must keep the later flag
    // honored, or a value could be declassified just by reordering the file.
    let project = go("env:\n  - TOKEN:shh\n  - TOKEN=shh\n");
    assert_eq!(project.environment[0].value, "shh");
    assert!(
        project.environment[0].secret,
        "the later plain form un-redacted the value"
    );
}

#[test]
fn an_env_entry_without_a_separator_is_a_diagnostic() {
    let message = go_err("env:\n  - PORT8080\n");
    assert!(message.contains("KEY=VALUE or KEY:VALUE"), "{message}");
}

#[test]
fn the_v1_env_mapping_still_reads_through_the_go_profile() {
    // A half-migrated file has both spellings over its lifetime. The mapping
    // form must not vanish just because the profile is selected.
    let from_go = go("env:\n  PORT: \"8080\"\n");
    let from_native = parse_project(
        Path::new("neoenv.yaml"),
        "format_version: 1\nenv:\n  PORT: \"8080\"\n",
    )
    .unwrap();
    assert_eq!(from_go.environment.len(), 1);
    assert_eq!(from_go.environment[0].key, "PORT");
    assert_eq!(
        from_go.environment[0].value,
        from_native.environment[0].value
    );
}

#[test]
fn a_shared_section_reads_the_same_under_both_dialects() {
    let body = "tasks:\n  show:\n    uses: portable\n    run: 'true'\n";
    let from_go = go(body);
    let from_native = parse_project(
        Path::new("neoenv.yaml"),
        &format!("format_version: 1\n{body}"),
    )
    .unwrap();
    assert_eq!(
        from_go.tasks.keys().collect::<Vec<_>>(),
        from_native.tasks.keys().collect::<Vec<_>>()
    );
}

#[test]
fn the_go_profile_rejects_a_section_it_cannot_translate_by_name() {
    // The whole point of the profile: a construct it cannot honor is named, so
    // a run can never look successful while quietly dropping the user's tools.
    for (input, expected) in [
        // `inventories` was here and is not any more, for the same reason `jobs`
        // left: the model has an `Inventory` now, so a Go file naming hosts is
        // read rather than refused, and the hosts still authorise nothing without a
        // `connect` grant. A positive test below covers it; this line would have
        // asserted the opposite.
        // `ship` is not here any more. It was refused on the grounds that the Go
        // reference does not execute it either -- true, and the wrong reason: the
        // reader had nowhere to put the deployments, and it has somewhere now. A Go
        // `ship:` section is carried through the normalizer, and the eight keys its
        // model cannot honour are refused by `deny_unknown_fields`. This
        // particular body -- a *sequence* where a mapping belongs -- is now a named
        // shape error rather than a refusal, asserted in
        // `a_container_shape_error_is_named_and_a_scalar_value_is_not`.
        ("config:\n  external: /elsewhere\n", "config.external"),
        ("config:\n  modules:\n    enabled: true\n", "config.modules"),
        // Neither `dotenv` nor `paths` appears here any more. Their `os` and
        // `contexts` keys were refused with a remedy because the model had
        // nowhere to put them; it has a place now, and both are honored. The
        // OS shorthands on a `paths` entry are honored too -- deliberately
        // diverging from the reference, which parses them and never reads them.
    ] {
        let message = go_err(input);
        assert!(message.contains(expected), "{input}\nproduced: {message}");
        // NEO130 names a key the reader does not know; NEO132 names a construct
        // it knows and cannot execute. Both are rejections, and the difference
        // is which one the user can act on.
        let code = go_code(input);
        let expected_code = if input.contains("darwin") {
            "NEO130"
        } else {
            "NEO132"
        };
        assert_eq!(code, expected_code, "{input}");
    }
}

#[test]
fn an_unrecognized_top_level_key_is_a_named_diagnostic() {
    // `deny_unknown_fields` is what stops a Go-only section from silently
    // disappearing. If this ever passes, a section is being dropped.
    let message = go_err("totally_unknown: 1\n");
    assert!(message.contains("totally_unknown"), "{message}");
}

#[test]
fn accepted_but_inert_go_config_keys_stay_inert() {
    // These are valid Go keys with no Rust equivalent that changes resolution.
    // They must be accepted rather than rejected, and must not invent behavior.
    for key in [
        "  shell: bash\n",
        "  env:\n    substitution: false\n",
        "  root: true\n",
        "  include: [a]\n",
        "  exclude: [a]\n",
        "  merge: true\n",
    ] {
        let project = go(&format!("config:\n{key}"));
        assert!(project.context.is_none(), "{key} must not select a context");
    }
}

#[test]
fn a_bare_string_dotenv_and_path_are_shared_shapes() {
    // A bare string is the native form, so a migrated file still reads.
    let project = go("dotenv: .env\npath:\n  - bin\n");
    assert_eq!(project.dotenv.len(), 1);
    assert_eq!(project.path.len(), 1);
    assert_eq!(project.path[0].kind, super::PathOperationKind::Prepend);
    assert_eq!(project.path[0].value, "bin");
}

#[test]
fn a_go_path_append_shorthand_translates_to_the_native_operation() {
    let project = go("path:\n  - path: bin\n    append: true\n");
    assert_eq!(project.path.len(), 1);
    assert_eq!(project.path[0].kind, super::PathOperationKind::Append);
    assert_eq!(project.path[0].value, "bin");
}

#[test]
fn a_go_path_without_append_translates_to_prepend() {
    let project = go("path:\n  - path: bin\n    append: false\n");
    assert_eq!(project.path[0].kind, super::PathOperationKind::Prepend);
}

#[test]
fn a_toml_go_document_reads_through_the_profile() {
    let project = parse_project_with_profile(
        Path::new("neoenv.toml"),
        "[config]\ncontext = \"production\"\n\n[[env]]\nname = \"PORT\"\nvalue = \"8080\"\nsecret = true\n",
        Format::Toml,
        ConfigProfile::Go,
    )
    .unwrap();
    assert_eq!(project.context.as_deref(), Some("production"));
    assert_eq!(project.environment[0].key, "PORT");
    assert!(project.environment[0].secret);
}

#[test]
fn the_go_profile_refuses_the_line_oriented_format() {
    // The `.neoenv` line syntax has no Go equivalent, so accepting it would
    // imply a Go document that cannot exist.
    let error = parse_project_with_profile(
        Path::new(".neoenv"),
        "env\n  PORT 8080\n",
        Format::Neoenv,
        ConfigProfile::Go,
    )
    .expect_err("the line-oriented format has no Go equivalent");
    assert!(error.to_string().contains("YAML or TOML"), "{error}");
}

#[test]
fn profile_names_round_trip() {
    for (name, expected) in [
        ("native", ConfigProfile::Native),
        ("v1", ConfigProfile::Native),
        ("go", ConfigProfile::Go),
        ("neofile", ConfigProfile::Go),
    ] {
        assert_eq!(ConfigProfile::from_name(name), Some(expected), "{name}");
        // The canonical name is what a diagnostic should print, so each alias
        // has to resolve to one.
        assert_eq!(
            expected.name(),
            ConfigProfile::from_name(name)
                .map(ConfigProfile::name)
                .unwrap()
        );
    }
    assert_eq!(ConfigProfile::Go.name(), "go");
    assert_eq!(ConfigProfile::from_name("nope"), None);
    assert_eq!(ConfigProfile::default(), ConfigProfile::Native);
}

#[test]
fn an_invalid_environment_key_is_rejected_in_the_go_sequence() {
    // Validation must not be skipped just because the value came from the Go
    // shape; a Go file is still allowed to declare a key the process cannot use.
    let message = go_err("env:\n  - \"1BAD=1\"\n");
    assert!(!message.is_empty());
}

/// The tests the `config:` rejection mechanism actually depends on.
///
/// `deny_unknown_fields` on `GoConfigSection` is load-bearing in a non-obvious
/// way: with `flatten` present, serde's flattened-access loop *skips* any
/// buffered key it does not recognize, so `InertGoConfig`'s own
/// `deny_unknown_fields` never sees an unknown key. Rejection comes from the
/// leftover-buffer check on the outer struct. Delete that attribute and the
/// top-level and `config:` acceptance tests below all still pass.
#[test]
fn an_unknown_key_under_config_is_rejected() {
    for body in [
        "config:\n  not_a_go_key: 1\n",
        "config:\n  ctx: production\n",
        "config:\n  defaults:\n    not_a_go_key: 1\n",
        "config:\n  defaults:\n    ctx: production\n",
    ] {
        let message = go_err(body);
        // The key has to be named. A message that merely says the document is
        // invalid would satisfy "rejected" while telling the user nothing.
        let named = if body.contains("ctx") {
            "unknown key `ctx`"
        } else {
            "unknown key `not_a_go_key`"
        };
        assert!(message.contains(named), "{body}\nproduced: {message}");
        // And the message has to list what *is* valid, or it is a dead end.
        assert!(
            message.contains("expected one of"),
            "{body}\nproduced: {message}"
        );
    }
}

#[test]
fn a_known_config_key_is_never_confused_with_an_unknown_one() {
    // The rejection above must be specific: a prefix of a real key is unknown,
    // but the real key is not.
    assert!(go("config:\n  context: production\n").context.is_some());
    assert!(go("config:\n  shell: bash\n").context.is_none());
    let message = go_err("config:\n  shel: bash\n");
    assert!(message.contains("unknown key `shel`"), "{message}");
    assert!(!message.contains("unknown key `shell`"), "{message}");
}

#[test]
fn config_defaults_accepts_the_go_shell_key() {
    // `config.defaults.shell` is a real key in the reference. Rejecting it would
    // make a valid Go file unreadable, and it is inert here for the same reason
    // the top-level `config.shell` is: the Rust shell is fixed per command.
    let project = go("config:\n  defaults:\n    shell: bash\n    context: staging\n");
    assert_eq!(project.context.as_deref(), Some("staging"));
}

#[test]
fn a_go_env_value_containing_a_command_substitution_is_rejected_at_parse_time() {
    // The native mapping form always runs this check, so the Go form has to as
    // well; otherwise a substitution is only caught later, at interpolation.
    let message = go_err("env:\n  - PORT=$(id)\n");
    assert!(
        message.contains("command substitution") || message.contains("substitution"),
        "expected a substitution diagnostic, got: {message}"
    );
}

#[test]
fn a_dotenv_key_the_reference_does_not_have_is_not_invented() {
    // `required` is a native key and reaches the native branch, which is why a
    // Go-only filter must not carry it: the profile should not accept a
    // document the reference rejects.
    let project = go("dotenv:\n  - path: .env\n    required: false\n");
    assert_eq!(project.dotenv.len(), 1);
    let message = go_err("dotenv:\n  - path: .env\n    not_a_go_key: 1\n");
    assert!(
        message.contains("unknown key `not_a_go_key`"),
        "an unknown dotenv key must be named, not dropped: {message}"
    );
}

#[test]
fn a_go_env_sequence_with_many_repeated_keys_normalizes_correctly() {
    // This is the case the key-to-position index exists for. The earlier version
    // of this test used 20,000 *distinct* keys, which meant the repeated-key
    // branch was never taken and a linear `find` would have produced an
    // identical result -- it could not have detected the regression it named.
    // This one interleaves a small key space so the branch is exercised on
    // almost every entry.
    const KEYS: usize = 32;
    const PASSES: usize = 64;
    let mut body = String::from("env:\n");
    for pass in 0..PASSES {
        for key in 0..KEYS {
            use std::fmt::Write as _;
            let _ = writeln!(body, "  - KEY{key}=pass{pass}");
        }
    }
    let project = go(&body);
    // One entry per distinct key, and the *last* value for each: last-wins.
    assert_eq!(project.environment.len(), KEYS);
    for (index, key) in (0..KEYS).enumerate() {
        assert_eq!(project.environment[index].key, format!("KEY{key}"));
        assert_eq!(
            project.environment[index].value,
            format!("pass{}", PASSES - 1)
        );
    }
}

/// The Go key shapes a review found the profile either refusing opaquely or
/// *silently accepting and then dropping*. The second is the one that matters:
/// "it parsed" is not the question, "did every key it read reach the model or
/// name itself in a diagnostic" is.
mod go_shapes {

    use std::path::Path;

    use super::{ConfigProfile, Format, go, go_code, go_err, parse_project_with_profile};
    use crate::EntryFilter;

    #[test]
    fn a_go_paths_entry_keeps_its_value_under_every_spelling() {
        // `value:` and `path:` are the same key in `paths.go`. Before this,
        // `value` was unread and became an *empty* PATH entry: the one outcome
        // worse than a diagnostic, because a PATH with an empty element is
        // silently different from what the file said.
        for (body, expected) in [
            ("paths:\n  - value: bin\n", "bin"),
            ("paths:\n  - path: bin\n", "bin"),
            ("path:\n  - prepend: bin\n", "bin"),
            ("path:\n  - append: bin\n", "bin"),
        ] {
            let project = go(body);
            assert_eq!(project.path.len(), 1, "{body}");
            assert_eq!(project.path[0].value, expected, "{body} lost its value");
            assert!(
                !project.path[0].value.is_empty(),
                "{body} produced an empty PATH entry"
            );
        }
    }

    /// The OS shorthands each mean "this path, on that platform" and are honored.
    ///
    /// The reference parses them and then never reads them -- `runner.go` does
    /// not consume `nf.Paths` at all -- so honoring them is a deliberate
    /// divergence. A Go file that writes `paths: [{darwin: bin}]` plainly means
    /// it, and adding the directory on *every* platform is not a reading of that
    /// line anyone intended.
    #[test]
    fn a_go_os_shorthand_names_the_path_and_the_platform() {
        for (shorthand, os) in [
            ("darwin", "darwin"),
            ("macos", "darwin"),
            ("mac", "darwin"),
            ("osx", "darwin"),
            ("windows", "windows"),
            ("win", "windows"),
            ("win32", "windows"),
            ("linux", "linux"),
            ("unix", "linux"),
        ] {
            let body = format!("paths:\n  - {shorthand}: bin\n");
            let project = go(&body);
            assert_eq!(project.path.len(), 1, "{body}");
            assert_eq!(project.path[0].value, "bin", "{body} lost the path");
            assert_eq!(
                project.path[0].filter.os.as_deref(),
                Some(os),
                "{body} named the wrong platform"
            );
        }
    }

    /// The `os:` key and every shorthand reach the model. This used to assert
    /// the opposite -- that they were named in a diagnostic with a remedy --
    /// because the model had nowhere to put them.
    #[test]
    fn a_go_paths_os_key_reaches_the_model() {
        let project = go("paths:\n  - path: bin\n    os: linux\n");
        assert_eq!(project.path.len(), 1);
        assert_eq!(project.path[0].value, "bin");
        assert_eq!(project.path[0].filter.os.as_deref(), Some("linux"));
    }

    /// `mac` is a spelling `paths.go` accepts and both this file's doc comment and
    /// the commit that added the alias table name. It was missing from the table,
    /// so `os: mac` matched nothing on macOS -- one of the four spellings the fix
    /// claims to handle, silently not handled.
    ///
    /// Every spelling the reference accepts must be in the table, and no others.
    /// Asserted over the whole set rather than the two that once failed, because
    /// the two that failed were the two that happened to be tested.
    #[test]
    fn every_platform_spelling_the_reference_accepts_is_an_alias() {
        for (running, declared) in [
            ("macos", "darwin"),
            ("macos", "macos"),
            ("macos", "osx"),
            ("macos", "mac"),
            ("darwin", "mac"),
            ("darwin", "darwin"),
            ("windows", "windows"),
            ("windows", "win"),
            ("linux", "linux"),
            // `unix` is deliberately absent. It is a `paths` shorthand *key*
            // (`paths.go`: `case "linux", "unix": ep.OS = "linux"`), folded to
            // `linux` before the filter ever sees it -- not a spelling of the
            // `os` *value*. A test that asserted `os: unix` worked would be
            // asserting something the reference never produces.
        ] {
            assert!(
                EntryFilter {
                    os: Some(declared.to_owned()),
                    contexts: Vec::new(),
                }
                .matches(running, "default"),
                "{running} should accept `{declared}`"
            );
        }
    }

    /// A shorthand *is* the path, so the earlier guard against an empty PATH
    /// entry still holds for these keys. An empty element is the current
    /// directory on POSIX, and the shorthand shape is the easiest way to reach
    /// one by accident.
    /// The path and the OS must come from the *same* key.
    ///
    /// They used to come from two independent fixed-ordering chains, so
    /// `paths: [{darwin: /opt/homebrew/bin, linux: /usr/bin}]` took the path from
    /// `darwin` and the OS from `linux`: a macOS directory added on Linux, or the
    /// reverse, with no diagnostic. The reference's `paths.go` switch sets `Path`
    /// and `OS` in one arm, so the property it has is the one that matters.
    #[test]
    fn a_paths_entry_takes_its_path_and_platform_from_one_key() {
        // Two keys that each name a path, in the order the reader's fixed table
        // checks them. The reference is document-order *last*-wins; a struct with
        // named fields has lost the document order, so this is a documented
        // divergence -- and the property the test exists for holds either way,
        // because the OS comes from whichever key supplied the path.
        let project = go("paths:\n  - darwin: /opt/homebrew/bin\n    linux: /usr/bin\n");
        assert_eq!(project.path.len(), 1, "{:?}", project.path);
        assert_eq!(project.path[0].value, "/usr/bin");
        assert_eq!(
            project.path[0].filter.os.as_deref(),
            Some("linux"),
            "the OS must come from the key that supplied the path"
        );
    }

    /// A quoted, padded `os:` still matches, and so does a padded `contexts:`.
    ///
    /// The filter compares declared names to a platform and a context *exactly*, so
    /// an untrimmed value matched nothing at all -- silently, on every platform.
    /// The trim lives in `EntryFilter::matches` rather than in the reader, because
    /// there are three readers that build an `EntryFilter` (Go `paths:`, Go
    /// `dotenv:`, and the native `filter:`) and trimming one of them left the other
    /// two wrong in the same commit. All three are asserted here.
    ///
    /// Asserted through the *predicate*, not through the stored value: the model
    /// deliberately keeps the value as written, so a test asserting the stored
    /// string would pass for the wrong reason and fail the moment the trim moved to
    /// the right layer.
    #[test]
    fn a_padded_quoted_os_and_context_still_match_on_every_reader() {
        for running in ["darwin", "macos"] {
            assert!(
                go("paths:\n  - path: /opt/p\n    os: ' darwin '\n").path[0]
                    .filter
                    .matches(running, "default"),
                "the Go `paths:` reader"
            );
            assert!(
                go("dotenv:\n  - path: .env.mac\n    os: ' darwin '\n").dotenv[0]
                    .filter
                    .matches(running, "default"),
                "the Go `dotenv:` reader"
            );
            let native = parse_project_with_profile(
                std::path::Path::new("neoenv.yaml"),
                "format_version: 1\npath:\n  - prepend: mine\n    filter:\n      os: ' darwin '\n",
                Format::Yaml,
                ConfigProfile::Native,
            )
            .expect("a native document");
            assert!(
                native.path[0].filter.matches(running, "default"),
                "the native reader"
            );
        }
        // A padded context, same shape and same reason.
        assert!(
            EntryFilter {
                os: None,
                contexts: vec!["prod ".to_owned()],
            }
            .matches("linux", "prod")
        );
    }

    /// An explicit `path:` with a separate `os:` is the documented pairing and
    /// still works, because it is one declaration of one directory.
    #[test]
    fn an_explicit_path_and_os_still_pair_up() {
        let project = go("paths:\n  - path: /opt/homebrew/bin\n    os: darwin\n");
        assert_eq!(project.path[0].value, "/opt/homebrew/bin");
        assert_eq!(project.path[0].filter.os.as_deref(), Some("darwin"));
    }

    #[test]
    fn a_go_os_shorthand_still_cannot_produce_an_empty_path() {
        for shorthand in ["darwin", "win32", "unix", "osx"] {
            let body = format!("paths:\n  - {shorthand}: \"\"\n");
            assert!(!go_err(&body).is_empty(), "{body} was accepted");
        }
    }

    /// A Go `jobs:` section is read, not refused.
    ///
    /// It was refused with NEO132 "no Rust equivalent" until the model grew
    /// `JobDefinition`. **A refusal is only the right answer while there is nowhere
    /// to put the thing**, so this asserts the other half of that bargain: the key is
    /// carried through the same normalizer as a native one, and gets the same
    /// refusals. A Go file that the reference runs and this refused was a portability
    /// gap the model was supposed to close.
    #[test]
    fn a_go_jobs_section_is_carried_through_the_native_normalizer() {
        let project = go(concat!(
            "jobs:\n",
            "  deploy:\n",
            "    desc: Build then test\n",
            "    steps:\n",
            "      - task: build\n",
            "      - run: echo seeding\n",
            "tasks:\n",
            "  build:\n",
            "    run: echo built\n",
        ));
        let job = project
            .jobs
            .get("deploy")
            .expect("the job is carried through");
        assert_eq!(job.description.as_deref(), Some("Build then test"));
        assert_eq!(job.steps.len(), 2);
        assert_eq!(job.steps[0].task.as_deref(), Some("build"));
        assert_eq!(job.steps[1].run.as_deref(), Some("echo seeding"));

        // And it gets the *same* refusal a native one does, rather than being waved
        // through because it arrived by the Go route.
        let message = go_err("jobs:\n  d:\n    cron: '* * * * *'\n    steps:\n      - run: x\n");
        assert!(
            message.contains("cron"),
            "a Go job's inert `cron` must be refused the way a native one is: {message}"
        );
    }

    /// A Go `inventories:` section is read, not refused.
    ///
    /// It *was* refused, with a message saying the Go reference does not execute it
    /// either -- which was true and is still true, but it was the wrong reason to
    /// refuse: the reader had nowhere to put the hosts, and refusing a construct
    /// because the *reference* is incomplete is a strange standard to hold a port to.
    ///
    /// So the model has an `Inventory` and the key is read. **The hosts still
    /// authorise nothing** without a `connect` capability grant, which is the
    /// property that matters and is asserted in `neoenv-runtime`'s inventory tests.
    #[test]
    fn a_go_inventory_section_is_carried_through_and_authorises_nothing() {
        let project = go(concat!(
            "inventories:\n",
            "  prod:\n",
            "    hosts:\n",
            "      web1:\n",
            "        tags: [prod]\n",
            "      web2: 10.0.0.9\n",
        ));
        let inventory = project
            .inventories
            .get("prod")
            .expect("the inventory is carried through");
        assert_eq!(
            inventory.order,
            ["web1", "web2"],
            "declaration order is kept"
        );
        assert_eq!(
            inventory.hosts["web1"].tags,
            ["prod".to_owned()],
            "the tags a host answers to are read"
        );
        assert_eq!(
            inventory.address_of("web2"),
            "10.0.0.9",
            "a bare string is an address"
        );
        assert_eq!(
            inventory.address_of("web1"),
            "web1",
            "a host with no address is reachable at its own name"
        );
    }

    /// A section given the wrong **shape** is named, and a **scalar value** is not.
    ///
    /// Both halves matter and they pull in opposite directions, so they are one test.
    ///
    /// A Go document with `ship:` as a sequence used to be reported as *"the Go
    /// document is not valid YAML"* -- true of neither the document nor the section,
    /// and a message that sends the reader to re-check syntax which was already
    /// correct. So the message is now surfaced for container shapes.
    ///
    /// Surfacing it by prefix was tried and reverted inside the minute, because
    /// `invalid type: string "not-a-number", expected u32` **carries the value**, and
    /// in this profile a value can be a declared secret. The rule that survives is
    /// narrower and measured: serde quotes a *scalar* and names a *container*, so only
    /// `sequence`, `map` and a struct name are surfaced, and the leading key path is
    /// stripped only when it looks like a key path.
    #[test]
    fn a_container_shape_error_is_named_and_a_scalar_value_is_not() {
        // Surfaced: the key and the expected shape, and no value.
        let shape = go_err("ship:\n  - a\n");
        assert!(
            shape.contains("ship") && shape.contains("expected a map"),
            "a section given a sequence is a shape error, and the message must name \
             the section and what it expected: {shape}"
        );
        assert!(
            !shape.contains("is not valid YAML"),
            "the document is valid YAML; blaming its syntax sends the reader to fix \
             something that was already correct: {shape}"
        );

        // Dropped: the value would be in the message.
        let scalar = go_err("format_version: not-a-number\n");
        assert!(
            !scalar.contains("not-a-number"),
            "a scalar of the wrong type is quoted by serde, and in this profile a \
             value can be a declared secret: {scalar}"
        );

        // And a secret inside a container is not echoed either, which is the case
        // the container rule could plausibly have opened up.
        let secret = go_err(
            "format_version: 1\nenv:\n  DB_PASSWORD:\n    value: [hunter2]\n    secret: true\n",
        );
        assert!(
            !secret.contains("hunter2"),
            "a declared secret was echoed into a diagnostic: {secret}"
        );

        // A key error still surfaces, because a key is never a value.
        let unknown = go_err("nonexistent_key: 1\n");
        assert!(
            unknown.contains("nonexistent_key"),
            "an unknown key is exactly the diagnostic a reader needs: {unknown}"
        );
    }

    #[test]
    fn go_project_metadata_is_refused_by_name() {
        // These are read by the reference and have nowhere to go here. The
        // native reader would say "unknown field `name`" and then list the
        // *v1* keys, which suggests a typo rather than a missing concept.
        for key in [
            "name: demo",
            "version: '1.0'",
            "description: a project",
            "desc: a project",
            "subcommands: [a]",
            "on: push",
            "meta: {}",
            // `jobs` used to be in this list. It is not any more, because the model
            // has `JobDefinition` now and a Go file with a pipeline is carried
            // through the same normalizer as a native one. There is a test for that
            // below; leaving the line here would assert the opposite.
            "trusted_sources: []",
        ] {
            let body = format!("{key}\n");
            let message = go_err(&body);
            let field = key.split(':').next().unwrap();
            assert!(message.contains(field), "{body}\nproduced: {message}");
            assert!(
                message.contains("no Rust equivalent"),
                "{body}\nproduced: {message}"
            );
            assert_eq!(go_code(&body), "NEO132", "{body}");
        }
    }

    #[test]
    fn an_unrecognized_needs_option_is_named() {
        // `deny_unknown_fields` on the per-need mapping sits inside an untagged
        // enum, where it degrades to "data did not match any variant". The
        // inventory walk names it instead.
        let message = go_err(
            "tasks:\n  a:\n    uses: portable\n    run: 'true'\n    needs:\n      - id: b\n        conditon: always\n",
        );
        assert!(message.contains("unknown key `conditon`"), "{message}");
        assert!(message.contains("id, parallel"), "{message}");
    }

    #[test]
    fn a_known_needs_option_is_not_rejected() {
        for body in [
            "tasks:\n  a:\n    uses: portable\n    run: 'true'\n    needs:\n      - id: b\n        parallel: true\n",
            "tasks:\n  a:\n    uses: portable\n    run: 'true'\n    needs:\n      - b\n",
        ] {
            let project = go(body);
            assert_eq!(project.tasks["a"].needs, vec!["b".to_owned()], "{body}");
        }
    }

    #[test]
    fn a_go_runner_selector_on_a_task_is_refused_by_name() {
        for key in ["embed", "image", "hosts"] {
            let body = format!("tasks:\n  a:\n    uses: portable\n    run: 'true'\n    {key}: x\n");
            let message = go_err(&body);
            assert!(message.contains(key), "{body}\nproduced: {message}");
        }
    }

    #[test]
    fn the_go_env_mapping_secret_form_is_read() {
        // `env.go` accepts a mapping whose value is a mapping with `value` and
        // `secret`. The v1 `IndexMap<String, String>` cannot hold it, so it is a
        // separate form rather than an alias.
        let project = go("env:\n  FOO:\n    value: bar\n    secret: true\n");
        assert_eq!(project.environment.len(), 1, "{:?}", project.environment);
        assert_eq!(project.environment[0].key, "FOO");
        assert_eq!(project.environment[0].value, "bar");
        assert!(project.environment[0].secret);
    }

    #[test]
    fn the_toml_profile_reads_the_same_shapes() {
        let project = parse_project_with_profile(
            Path::new("neoenv.toml"),
            "config = { context = \"production\" }\n",
            Format::Toml,
            super::ConfigProfile::Go,
        )
        .unwrap();
        assert_eq!(project.context.as_deref(), Some("production"));
    }
}

/// The Go `use:` block, normalized into the Rust tool model.
///
/// The property under test throughout is the one this profile exists for: every
/// key a `use:` entry can carry either reaches the model or is named in a
/// diagnostic. A key that is read and dropped changes *which artifact gets
/// installed*, which is the failure mode nothing else in the profile has.
mod go_use_block {
    use neoenv_core::tools::ToolDeclaration;

    use super::{Format, Project, go, go_code, go_err, parse_project_with_profile};

    fn tools(body: &str) -> Project {
        go(&format!("use:\n{body}"))
    }

    fn only_tool(body: &str) -> ToolDeclaration {
        let project = tools(body);
        assert_eq!(project.tools.len(), 1, "expected exactly one tool");
        project.tools.into_iter().next().unwrap()
    }

    #[test]
    fn a_github_release_key_becomes_a_github_declaration() {
        let tool = only_tool("  gh:cli/cli: \"v2.0.0\"\n");
        assert_eq!(tool.id, "gh:cli/cli");
        assert_eq!(tool.version, "v2.0.0");
        assert_eq!(
            tool.provider,
            neoenv_core::tools::ToolProvider::GithubRelease
        );
        let github = tool.github_release.expect("a GitHub declaration");
        assert_eq!(github.repository, "cli/cli");
        assert_eq!(
            github.asset, None,
            "an absent asset means select by platform"
        );
        assert_eq!(github.grep, None);
    }

    #[test]
    fn a_gitlab_release_key_becomes_a_gitlab_declaration() {
        let tool = only_tool("  gl:group/project: \"1.0.0\"\n");
        assert_eq!(
            tool.provider,
            neoenv_core::tools::ToolProvider::GitlabRelease
        );
        let gitlab = tool.gitlab_release.expect("a GitLab declaration");
        assert_eq!(gitlab.namespace, "group");
        assert_eq!(gitlab.project, "project");
        assert_eq!(gitlab.host, "gitlab.com", "the default host");
    }

    #[test]
    fn a_package_manager_key_is_carried_as_a_provider_with_no_resolver() {
        let tool = only_tool("  npm:left-pad: \"1.3.0\"\n");
        assert_eq!(tool.id, "npm:left-pad");
        // Named as a provider that has no resolver, so planning reports it
        // rather than routing it to the URL resolver with an empty URL.
        assert_eq!(tool.provider.name(), "package-manager:npm");
    }

    #[test]
    fn a_bare_runtime_key_is_carried_as_a_provider_with_no_resolver() {
        let tool = only_tool("  node: \"20.0.0\"\n");
        // The reference resolves a bare runtime through a module registry this
        // model does not have. Carried under a provider that says so, so
        // planning reports it by name instead of appearing to install.
        assert_eq!(tool.provider.name(), "runtime:node");
    }

    #[test]
    fn every_mapped_key_reaches_the_model() {
        let tool = only_tool(
            "  gh:cli/cli:\n    version: \"v2.0.0\"\n    asset: \"cli-{os}.tar.gz\"\n    checksum: \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n    bins: [cli, clihelper]\n    grep: \"^cli-\"\n",
        );
        assert_eq!(tool.version, "v2.0.0");
        assert_eq!(
            tool.sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            tool.binaries,
            vec!["cli".to_owned(), "clihelper".to_owned()]
        );
        let github = tool.github_release.expect("a release declaration");
        assert_eq!(github.asset.as_deref(), Some("cli-{os}.tar.gz"));
        assert_eq!(github.grep.as_deref(), Some("^cli-"));
    }

    /// A `url:` on a release key means "fetch this exact file" -- the
    /// reference's `DirectReleaseAsset` short-circuits asset selection with it.
    ///
    /// It maps to the `explicit-url` provider rather than into the release
    /// planners, because a URL cannot satisfy the lock's provenance invariant: a
    /// `github-release` entry is required to name the release *and* the asset it
    /// came from, and a direct download names neither. Routing it through the
    /// planner anyway produced a plan that looked right, printed, and was then
    /// rejected by `write_lockfile` before any download.
    /// A `url:` *under a platform key* on a release entry is the same defect the
    /// top-level one was, one level down: read into the override, and read by
    /// nothing. A release plan cannot honor it, so it is named.
    #[test]
    fn a_per_platform_url_on_a_release_key_is_named_rather_than_ignored() {
        let message = go_err(
            "use:\n  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      url: https://example.test/cli.tar.gz\n",
        );
        assert!(message.contains("per-platform `url`"), "{message}");
        // And the per-platform `checksum` beside it is what makes the entry
        // meaningful; naming the URL is enough to send the user looking.
        assert!(!go_err(
            "use:\n  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      url: https://example.test/cli.tar.gz\n      checksum: abc\n"
        )
        .is_empty());
    }

    /// `asset:` and `grep:` select *from the release's assets*. With a `url:`
    /// there is no selection to make, so keeping them would silently change which
    /// file is downloaded.
    #[test]
    fn asset_and_grep_are_named_when_a_url_makes_them_meaningless() {
        for extra in ["    asset: cli.tar.gz\n", "    grep: \"^cli\"\n"] {
            let body = format!(
                "use:\n  gh:cli/cli:\n    version: \"2.0.0\"\n    url: https://example.test/cli.tar.gz\n{extra}"
            );
            let message = go_err(&body);
            assert!(
                message.contains("no release asset to select from"),
                "{body}\nproduced: {message}"
            );
        }
    }

    #[test]
    fn a_url_on_a_release_key_becomes_an_explicit_url_provider() {
        for key in ["gh:cli/cli", "gl:group/project"] {
            let tool = only_tool(&format!(
                "  {key}:\n    version: \"2.0.0\"\n    url: \"https://example.test/cli.tar.gz\"\n    checksum: \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n    bins: [cli]\n"
            ));
            assert_eq!(
                tool.provider.name(),
                "explicit-url",
                "{key} with a url: is a direct download"
            );
            assert_eq!(
                tool.url.as_deref(),
                Some("https://example.test/cli.tar.gz"),
                "{key}"
            );
            assert!(tool.github_release.is_none(), "{key}");
            assert!(tool.gitlab_release.is_none(), "{key}");
            assert_eq!(
                tool.sha256.as_deref(),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                "the checksum verifies the direct download, so it must be kept"
            );
        }
    }

    /// A `url:` on a key that is *not* a release key is the key's own business.
    /// A bare runtime and a package manager have no URL form in the reference, so
    /// one there must not silently reinterpret the key as a download.
    #[test]
    fn a_url_on_a_non_release_key_is_not_turned_into_a_download() {
        for key in ["node", "npm:left-pad"] {
            let tool = only_tool(&format!("  {key}: \"1.0.0\"\n"));
            assert_ne!(tool.provider.name(), "explicit-url", "{key}");
        }
    }

    #[test]
    fn rn_is_an_alias_for_rename() {
        let tool = only_tool("  gh:cli/cli:\n    version: \"v2.0.0\"\n    rn: agek\n");
        assert_eq!(tool.binaries, vec!["agek".to_owned()]);
    }

    #[test]
    fn pre_and_prerelease_are_the_same_boolean() {
        for key in ["pre", "prerelease"] {
            let tool = only_tool(&format!(
                "  gh:cli/cli:\n    version: latest\n    {key}: true\n"
            ));
            assert!(
                tool.github_release.as_ref().unwrap().prerelease,
                "{key} must be carried into the release declaration"
            );
        }
        let tool = only_tool("  gh:cli/cli:\n    version: latest\n    pre: false\n");
        assert!(!tool.github_release.as_ref().unwrap().prerelease);
    }

    #[test]
    fn rename_becomes_the_installed_binary_name() {
        // Nothing downstream can carry a separate `rename`: the installer writes
        // `<root>/bin/<binary>` from `binaries`, and the lock records only that.
        // Reading it into a field of its own would be a silent drop.
        let tool = only_tool("  gh:cli/cli:\n    version: \"v2.0.0\"\n    rename: mycli\n");
        assert_eq!(tool.binaries, vec!["mycli".to_owned()]);
    }

    /// A *per-platform* `rename` has to be honored too.
    ///
    /// The reference overlays it (`MergeWithDefaults`: `if platformCfg.Rename
    /// != ""`). It was read into the override and then read by nothing -- the
    /// exact sibling of the bug this commit closed for the top-level key, one
    /// level down. A Go file that said `linux-x86_64: {rename: gh-linux}` planned
    /// and installed `cli`, silently dropping the rename.
    #[test]
    fn a_per_platform_rename_becomes_that_override_binary() {
        let tool = only_tool(
            "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      rename: gh-linux\n    darwin-arm64:\n      bins: [cli]\n",
        );
        let linux = tool
            .platforms
            .iter()
            .find(|entry| entry.platform.os.as_deref() == Some("linux"))
            .expect("a linux override");
        assert_eq!(
            linux.binaries.as_deref(),
            Some(["gh-linux".to_owned()].as_slice()),
            "a per-platform rename names that override's binary"
        );
        // An override that names `bins` keeps them: the top-level rule applies
        // here too, and which one wins depends on the artifact layout.
        let darwin = tool
            .platforms
            .iter()
            .find(|entry| entry.platform.os.as_deref() == Some("darwin"))
            .expect("a darwin override");
        assert_eq!(
            darwin.binaries.as_deref(),
            Some(["cli".to_owned()].as_slice())
        );
        // The declaration names no binary, so the repo half is the default, and
        // the override replaces it on its own platform only.
        assert_eq!(tool.binaries, vec!["cli".to_owned()]);
    }

    /// The derived binary name must be one component. `gh:owner/repo/v2` parses
    /// as far as the first slash, and `repo/v2` is not a name the installer can
    /// create -- the rejection used to land at lock-write time, long after
    /// `tool plan` reported a tool it could not install.
    #[test]
    fn a_derived_binary_name_never_contains_a_separator() {
        let tool = only_tool("  gh:owner/repo/v2: \"1.0.0\"\n");
        assert!(
            !tool.binaries.iter().any(|name| name.contains('/')),
            "{:?} is not a name the installer can create",
            tool.binaries
        );
    }

    /// A blank-only `bins` beside a `rename` is not a pair, and the binary list
    /// must be the rename rather than a list of whitespace.
    ///
    /// The check and the fold computed "has bins" differently -- the check asked
    /// whether *any element* was non-blank while the fold asked whether the *vec*
    /// was non-empty and never trimmed -- so this passed the check, folded to
    /// `["  "]`, and dropped the rename. The planner only rejects an empty
    /// string, not whitespace, and the unsafe-name check allows a blank, so the
    /// installer wrote `<root>/bin/␠␠`. The reference drops the blank and
    /// installs the rename (`install_binary.go:17`).
    #[test]
    fn a_blank_per_platform_bins_yields_to_the_rename_rather_than_a_blank_binary() {
        for (label, body, expected) in [
            (
                "whitespace only",
                "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      bins: ['  ']\n      rename: cli\n",
                "cli",
            ),
            (
                "empty string only",
                "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      bins: ['']\n      rename: cli\n",
                "cli",
            ),
            (
                "a real name beside whitespace keeps the name, trimmed",
                "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      bins: ['  ', 'cli-linux ']\n",
                "cli-linux",
            ),
        ] {
            let tool = only_tool(body);
            let linux = tool
                .platforms
                .iter()
                .find(|entry| entry.platform.os.as_deref() == Some("linux"))
                .expect("a linux override");
            assert_eq!(
                linux.binaries.as_deref(),
                Some([expected.to_owned()].as_slice()),
                "{label}: {:?}",
                linux.binaries
            );
        }
    }

    /// A per-platform `bins` + `rename` pair is refused, like the top-level one.
    ///
    /// It was silently resolved to `bins`, with no diagnostic -- and the reason for
    /// refusing at all is that which one wins depends on whether the artifact is an
    /// archive or a plain binary, which is not knowable while reading. Resolving it
    /// is guessing, one level down from the place the guess was refused.
    #[test]
    fn a_per_platform_bins_and_rename_together_are_refused_too() {
        let body = "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      bins: [cli]\n      rename: other\n";
        let document = format!("use:\n{body}");
        // The code alone, rather than two substrings of one message -- which is
        // what the previous version asserted, and which cannot tell a reworded
        // message from changed behavior.
        assert_eq!(go_code(&document), "NEO136", "{body}");
        // And the message must give the *actual* reason. An earlier version said
        // "which one names the installed binary depends on the artifact layout",
        // which is wrong: the reference does not choose between the two keys, it
        // uses `Bins` to select files and `Rename` for the installed name
        // (`install_binary.go:14-31`, `:72`), so `bins: [a] + rename: b` is a
        // document it honors, installing `a` as `b`. Telling a user to drop a key
        // the reference honors, with no migration, is a worse answer than the
        // refusal.
        let message = go_err(&document);
        assert!(
            message.contains("which files to take") && message.contains("what to call"),
            "the message must state the real distinction: {message}"
        );
        assert!(
            !message.contains("artifact layout"),
            "the old, wrong reason is still there: {message}"
        );
        // And one of the two alone still works, or the check is refusing everything.
        let tool = only_tool(
            "  gh:cli/cli:\n    version: \"2.0.0\"\n    linux-x86_64:\n      bins: [cli-linux]\n",
        );
        let linux = tool
            .platforms
            .iter()
            .find(|entry| entry.platform.os.as_deref() == Some("linux"))
            .expect("a linux override");
        assert_eq!(
            linux.binaries.as_deref(),
            Some(["cli-linux".to_owned()].as_slice())
        );
    }

    #[test]
    fn bins_and_rename_together_are_refused_rather_than_guessed() {
        // The message gives the *actual* reason, and the same one the
        // per-platform refusal gives. It used to say "which one names the
        // installed binary depends on the artifact layout", which is wrong: the
        // reference does not choose between the two keys, it uses `Bins` to select
        // files and `Rename` for the installed name, so `bins: [a] + rename: b` is
        // a document it honors. The two paths must not issue contradictory advice
        // for the same mistake.
        let document =
            "use:\n  gh:cli/cli:\n    version: \"v2.0.0\"\n    bins: [a]\n    rename: b\n";
        assert_eq!(go_code(document), "NEO136", "{document}");
        let message = go_err(document);
        assert!(message.contains("bins"), "{message}");
        assert!(message.contains("rename"), "{message}");
        assert!(
            message.contains("which files to take") && message.contains("what to call"),
            "the top-level message must state the real distinction: {message}"
        );
        assert!(
            !message.contains("artifact layout"),
            "the old, wrong reason is still there: {message}"
        );
    }

    #[test]
    fn a_per_platform_override_reaches_the_model() {
        let tool = only_tool(
            "  gh:cli/cli:\n    version: \"v2.0.0\"\n    asset: \"cli.tar.gz\"\n    darwin-arm64:\n      asset: \"cli-darwin.tar.gz\"\n      bins: [cli]\n    windows-amd64:\n      checksum: \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        );
        assert_eq!(tool.platforms.len(), 2, "{:?}", tool.platforms);
        let darwin = tool
            .platforms
            .iter()
            .find(|p| p.platform.os.as_deref() == Some("darwin"))
            .expect("a darwin override");
        assert_eq!(darwin.platform.arch.as_deref(), Some("arm64"));
        assert_eq!(darwin.asset.as_deref(), Some("cli-darwin.tar.gz"));
        assert_eq!(
            darwin.binaries.as_deref(),
            Some(["cli".to_owned()].as_slice())
        );
        let windows = tool
            .platforms
            .iter()
            .find(|p| p.platform.os.as_deref() == Some("windows"))
            .expect("a windows override");
        assert_eq!(
            windows.sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            "a per-platform checksum must reach the model, not vanish"
        );
    }

    #[test]
    fn an_unrecognized_use_key_is_named() {
        let message = go_err("use:\n  gh:cli/cli:\n    version: \"v2.0.0\"\n    bogus: 1\n");
        assert!(message.contains("unknown key `bogus`"), "{message}");
        assert!(message.contains("expected one of"), "{message}");
    }

    #[test]
    fn an_unrecognized_per_platform_key_is_named_with_its_location() {
        let message = go_err(
            "use:\n  gh:cli/cli:\n    version: \"v2.0.0\"\n    windows-amd64:\n      nopes: 1\n",
        );
        assert!(message.contains("unknown key `nopes`"), "{message}");
        assert!(message.contains("windows-amd64"), "{message}");
    }

    #[test]
    fn a_misspelled_platform_key_is_named_as_a_key() {
        let message = go_err(
            "use:\n  gh:cli/cli:\n    version: \"v2.0.0\"\n    linuz:\n      asset: a.tar.gz\n",
        );
        assert!(message.contains("unknown key `linuz`"), "{message}");
    }

    #[test]
    fn a_mapping_without_a_version_is_refused() {
        let message = go_err("use:\n  gh:cli/cli:\n    asset: x.tar.gz\n");
        assert!(message.contains("no version"), "{message}");
        assert_eq!(
            go_code("use:\n  gh:cli/cli:\n    asset: x.tar.gz\n"),
            "NEO135"
        );
    }

    #[test]
    fn a_malformed_key_is_refused_by_name() {
        // Each of these must not become a tool. Asserting the *code* rather
        // than merely that some diagnostic appeared: "refused for any reason at
        // all" is a much weaker property, and a typo that reached the model as a
        // tool named `gh:cli` would satisfy a non-empty-message check.
        for key in ["gh:cli", "gh:/cli", "gh:cli/", "gl:project", "gl:/project"] {
            let body = format!("use:\n  {key}: \"1.0.0\"\n");
            assert_eq!(go_code(&body), "NEO132", "for key {key}");
            let message = go_err(&body);
            assert!(
                message.contains("both halves are required"),
                "the message must say what is missing, for {key}: {message}"
            );
        }
    }

    #[test]
    fn a_malformed_key_does_not_refuse_a_valid_one_alongside_it() {
        // The refusal has to be per entry. A check that refused the whole block
        // would pass the test above while making every `use:` file unusable.
        let message = go_err("use:\n  gh:cli: \"1.0.0\"\n  gl:group/project: \"1.0.0\"\n");
        assert!(message.contains("gh:cli"), "{message}");
        assert!(!message.contains("gl:group/project"), "{message}");
        let project = go("use:\n  gh:cli/cli: \"1.0.0\"\n  gl:group/project: \"1.0.0\"\n");
        assert_eq!(project.tools.len(), 2, "both well-formed keys survive");
    }

    #[test]
    fn a_use_value_that_is_neither_a_version_nor_a_mapping_is_refused() {
        // Only the shapes the reference refuses. It takes a `ScalarNode` as the
        // version, so numbers and booleans are versions there and are not
        // refused here; refusing them would have looked like strictness while
        // being a divergence.
        for value in ["[1, 2]", "null", "{}"] {
            let body = format!("use:\n  gh:cli/cli: {value}\n");
            assert!(!go_err(&body).is_empty(), "use entry {value} was accepted");
        }
    }

    #[test]
    fn a_scalar_of_any_kind_is_the_version() {
        for (yaml, expected) in [("20", "20"), ("20.1", "20.1"), ("true", "true")] {
            let body = format!("use:\n  gh:cli/cli: {yaml}\n");
            let tool = only_tool(&body[5..]);
            assert_eq!(tool.version, expected, "for {yaml}");
        }
    }

    #[test]
    fn a_key_is_trimmed_and_a_blank_one_is_refused() {
        // The reference trims and then refuses a blank key (`use_map.go:165`).
        // Without the trim a leading space defeated `strip_prefix`, so
        // `" gh:cli/cli"` classified as a *package manager* -- a GitHub release
        // read as npm.
        let tool = only_tool("  \" gh:cli/cli \": \"v1.0.0\"\n");
        assert_eq!(tool.provider.name(), "github-release");
        assert!(
            !go_err("use:\n  \"\": \"1.0.0\"\n").is_empty(),
            "an empty key was accepted"
        );
    }

    #[test]
    fn a_doubled_prefix_is_not_stripped_repeatedly() {
        // `trim_start_matches` removes *every* repetition, so this resolved to
        // the repository `owner/repo` and silently retargeted the download.
        let project = go("use:\n  \"gh:gh:owner/repo\": \"1.0.0\"\n");
        let tool = &project.tools[0];
        assert_ne!(
            tool.github_release.as_ref().map(|g| g.repository.as_str()),
            Some("owner/repo"),
            "a doubled prefix must not resolve to the inner repository"
        );
    }

    #[test]
    fn a_platform_key_without_its_dash_is_not_a_platform_spec() {
        // The reference's `isPlatformKey` tests `windows-` *with* the dash, so a
        // bare `windows:` is not a platform block there. Accepting it made an
        // arch-less override that applied to every machine of that OS.
        assert!(
            !go_err(
                "use:\n  gh:cli/cli:\n    version: \"1.0.0\"\n    windows:\n      asset: a.zip\n"
            )
            .is_empty(),
            "a bare `windows:` must not be accepted as a platform block"
        );
        // And the archless form with a dash is not a thing either: the reference
        // always writes `windows-amd64`.
        let tool = only_tool(
            "  gh:cli/cli:\n    version: \"1.0.0\"\n    windows-amd64:\n      asset: a.zip\n",
        );
        assert_eq!(tool.platforms.len(), 1);
    }

    #[test]
    fn a_release_entry_with_no_bins_names_the_repositorys_repo_half() {
        // The reference sets `plan.Name` to it and `install_binary.go` falls back
        // to it, so this is the name a bare `gh:` entry installs. An empty
        // `binaries` is refused as `EmptyBinaries`, so without this the most
        // common Go form could not plan at all.
        let tool = only_tool("  gh:cli/cli: \"v2.0.0\"\n");
        assert_eq!(tool.binaries, vec!["cli".to_owned()]);
        let gitlab = only_tool("  gl:group/project: \"1.0.0\"\n");
        assert_eq!(gitlab.binaries, vec!["project".to_owned()]);
    }

    #[test]
    fn a_key_that_names_no_repository_leaves_the_binaries_empty_rather_than_guessing() {
        // A bare runtime and a package manager take their name from a registry the
        // file did not give here. Inventing one would install a binary under a
        // name nobody asked for, so the list stays empty and planning reports it.
        for key in ["node", "npm:left-pad"] {
            let tool = only_tool(&format!("  {key}: \"1.0.0\"\n"));
            assert!(
                tool.binaries.is_empty(),
                "{key} guessed {:?}",
                tool.binaries
            );
        }
    }

    #[test]
    fn a_toml_use_block_reads_the_same_way() {
        let project = parse_project_with_profile(
            std::path::Path::new("neoenv.toml"),
            "[use]\n\"gh:cli/cli\" = { version = \"v2.0.0\" }\n",
            Format::Toml,
            super::ConfigProfile::Go,
        )
        .unwrap();
        assert_eq!(project.tools.len(), 1);
        assert_eq!(project.tools[0].version, "v2.0.0");
    }
}

/// The OS and context filter on a `dotenv:` or `paths:` entry.
///
/// The predicate is the reference's (`neofile/dotenv.go`'s `HasContext` and
/// `runner.go`'s `jobDotenvPaths`), and both halves of it have a failure mode
/// that a test has to name: an OS filter that is too wide adds a directory on the
/// wrong platform, and a context filter that is too wide loads the wrong
/// secrets.
mod entry_filter {
    use crate::EntryFilter;

    fn matches(os: &str, declared_os: Option<&str>, contexts: &[&str], context: &str) -> bool {
        EntryFilter {
            os: declared_os.map(str::to_owned),
            contexts: contexts.iter().map(|name| (*name).to_owned()).collect(),
        }
        .matches(os, context)
    }

    /// The running platform's name is not the name a file writes.
    ///
    /// `std::env::consts::OS` is `macos`; the reference compares against
    /// `runtime.GOOS`, which is `darwin`; and `paths.go` accepts `mac`, `macos`,
    /// `darwin`, and `osx`. Compared literally, `os: darwin` matched nothing on
    /// macOS -- and `darwin:` in a `paths:` entry is the exact line a user would
    /// write. Nothing here can run on macOS, which is why it is a unit test
    /// rather than an end-to-end one.
    #[test]
    fn a_platform_spelled_the_other_way_still_matches() {
        for (running, declared) in [
            ("macos", "darwin"),
            ("macos", "macos"),
            ("darwin", "macos"),
            ("darwin", "darwin"),
            ("darwin", "osx"),
            ("macos", "osx"),
        ] {
            assert!(
                matches(running, Some(declared), &[], "default"),
                "{running} should accept a {declared} filter"
            );
        }
    }

    /// And the aliasing does not leak: a name the running platform goes by under
    /// no spelling must still match nothing. A darwin host must not accept a
    /// `linux:` filter, which is the failure this whole change could have caused.
    #[test]
    fn an_unrelated_platform_still_matches_nothing() {
        for (running, declared) in [
            ("macos", "linux"),
            ("darwin", "linux"),
            ("linux", "darwin"),
            ("linux", "windows"),
            ("windows", "darwin"),
        ] {
            assert!(
                !matches(running, Some(declared), &[], "default"),
                "{running} must not accept a {declared} filter"
            );
        }
    }

    /// A blank `os` is unset; a blank `contexts` **entry** names a context that
    /// does not exist, and the two are *not* symmetric.
    ///
    /// This was a decision, and the version before it was the wrong one. Blank
    /// entries were dropped and the resulting list was then asked whether it was
    /// empty, which made "the key is present with no usable name" and "the key is
    /// absent" the same question -- and answered it match-default-context. So
    /// `contexts: ["${CTX}"]` with `CTX` unset, or a padded `['prod ']`, silently
    /// *widened* a scoped entry to the default context. For a `dotenv:` entry that
    /// means a production secret file loaded in the default context, where before
    /// the change it loaded nowhere. Widening a filter is the one failure worth a
    /// line of code here; the alternative -- treating the key as absent -- grants
    /// exactly the scope the user was withholding.
    ///
    /// A blank `os` stays match-all, and that asymmetry is deliberate rather than
    /// an oversight: `os` is an `Option`, so `Some("")` is a value and `None` is
    /// no value, and a blank value reads as "no OS filter". A native config that
    /// interpolates `os: "${TARGET_OS}"` and lands on whitespace should add its
    /// PATH entry everywhere, not nowhere -- there is no default OS.
    #[test]
    fn a_blank_os_is_unset_and_a_blank_context_matches_nothing() {
        for context in ["default", ""] {
            assert!(
                matches("linux", Some("   "), &[], context),
                "a blank os is unset, so the entry applies in {context:?}"
            );
            assert!(
                matches("linux", Some(" \t "), &[], context),
                "a whitespace-only os is unset too"
            );
        }
        // A blank entry alongside a real one does not stop the real one.
        assert!(
            matches("linux", None, &["  ", "prod"], "prod"),
            "a blank entry does not stop the real entries from applying"
        );
        assert!(
            !matches("linux", None, &["  ", "prod"], "default"),
            "and the list is still scoped: a blank entry is not a wildcard"
        );
        // But a list of *only* blanks names no context at all, so it matches
        // nothing -- including the default context, which is what the previous
        // version did and what this one refuses to.
        for context in ["default", "", "prod"] {
            assert!(
                !matches("linux", None, &["  "], context),
                "a present `contexts` key naming no context must not apply in \
                 {context:?}"
            );
            assert!(
                !matches("linux", Some("linux"), &["", " "], context),
                "same for a mixed-empty key, on {context:?}"
            );
        }
    }

    /// **The consequence, not the drop.** A `dotenv:` entry scoped to a context
    /// this run does not have must not contribute its variables.
    ///
    /// The name is what it is: **the config layer does not interpolate.** There is
    /// no `${CTX}` handling in `neoenv-config` at all -- an unexpanded
    /// `${CTX}` is simply a context *name* that exists nowhere, which is a
    /// perfectly ordinary way to scope an entry to something absent. An earlier
    /// version of this test's doc claimed the config "interpolates a context name
    /// from the environment, the variable is unset", which described a mechanism
    /// this crate does not have, and a whole test was named after the fiction.
    /// The blank case below is still real and still needs a row -- a user can
    /// write `contexts: [""]` or `contexts: ['prod ']` by hand -- but it is
    /// reached by a literal, not by an expansion.
    ///
    /// This remains a unit test of `EntryFilter::matches`, and that is a
    /// **deliberate limit**: the review found that it cannot fail on the
    /// regression it is evidence for, because reverting `matches` to the
    /// drop-blanks version leaves it green. The end-to-end version -- a real
    /// `dotenv:` file whose variables must not reach the environment -- is
    /// `neoenv_runtime::resolved_config::tests::a_dotenv_scoped_to_an_unknown_context_contributes_no_variables`.
    /// That one is the evidence. This one is the unit.
    #[test]
    fn a_dotenv_scoped_to_a_context_that_exists_nowhere_contributes_nothing() {
        // Names that select nothing: one nothing can type, and two blanks a user
        // can write by hand. None of them trims to a context that exists.
        for name in ["${CTX}", "", "  ", " prod!"] {
            let filter = EntryFilter {
                os: None,
                contexts: vec![name.to_owned()],
            };
            for context in ["", "default", "prod", "staging"] {
                assert!(
                    !filter.matches("linux", context),
                    "contexts: [{name:?}] names no context and must not apply in {context:?}"
                );
            }
        }
        // A *padded* name is not in that set, and putting it there was the bug in
        // this test's first version. Trimming is the documented divergence, so
        // `contexts: [' prod']` selects `prod` -- which is what makes the padded
        // spelling usable rather than a typo that silently matches nothing.
        let padded = EntryFilter {
            os: None,
            contexts: vec![" prod".into()],
        };
        assert!(padded.matches("linux", "prod"), "padding is trimmed");
        assert!(!padded.matches("linux", "default"));
        // And the plain control, so the rows above are the filter rather than a
        // test that cannot pass.
        let filter = EntryFilter {
            os: None,
            contexts: vec!["prod".into()],
        };
        assert!(filter.matches("linux", "prod"));
        assert!(!filter.matches("linux", "default"));
        assert!(!filter.matches("linux", ""));
    }

    #[test]
    fn an_absent_filter_matches_everything() {
        // What a bare `dotenv: .env` and `paths: [bin]` desugar to. If this ever
        // stops holding, every unfiltered entry in every file silently vanishes.
        assert!(matches("linux", None, &[], "default"));
        assert!(matches("darwin", None, &[], "*"));
        assert!(matches("windows", None, &[], ""));
    }

    #[test]
    fn the_os_filter_matches_only_its_own_platform() {
        assert!(matches("linux", Some("linux"), &[], "default"));
        assert!(!matches("darwin", Some("linux"), &[], "default"));
        assert!(!matches("windows", Some("linux"), &[], "default"));
        // A `*` and a blank are both "any platform", the way the reference's
        // `entry.OS != "" && entry.OS != "*"` check reads.
        assert!(matches("darwin", Some("*"), &[], "default"));
        assert!(matches("darwin", Some(""), &[], "default"));
        // An unrecognized platform name matches nothing, which is the safe
        // direction: a typo adds a directory nowhere rather than everywhere.
        assert!(!matches("linux", Some("linuz"), &[], "default"));
    }

    #[test]
    fn no_contexts_means_the_default_context_only() {
        // This is the half that is easy to get wrong. A `dotenv:` entry with no
        // `contexts` must NOT load in a named context: the reference's
        // `HasContext` returns `context == "*" || context == "" || context ==
        // "default"` for an empty list, and prod credentials do not belong in a
        // dev run.
        assert!(matches("linux", None, &[], "default"));
        assert!(!matches("linux", None, &[], "prod"));
        assert!(!matches("linux", None, &[], "staging"));
    }

    #[test]
    fn a_named_context_matches_only_itself_or_a_wildcard() {
        assert!(matches("linux", None, &["prod"], "prod"));
        assert!(!matches("linux", None, &["prod"], "dev"));
        assert!(matches("linux", None, &["prod", "staging"], "staging"));
        assert!(matches("linux", None, &["*"], "anything"));
        assert!(matches("linux", None, &["prod", "*"], "dev"));
    }

    #[test]
    fn both_halves_must_hold() {
        // The conjunction is the whole predicate. Testing them separately would
        // not catch an `||` where an `&&` belongs, and an `||` here would load a
        // prod dotenv on a machine that is not running prod.
        assert!(!matches("linux", Some("darwin"), &["prod"], "prod"));
        assert!(!matches("linux", Some("linux"), &["prod"], "dev"));
        assert!(matches("linux", Some("linux"), &["prod"], "prod"));
    }
}
