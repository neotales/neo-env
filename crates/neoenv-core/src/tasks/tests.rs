//! Task model, planning, and predicate tests.

use super::*;
use indexmap::indexmap;

fn task(needs: &[&str]) -> TaskDefinition {
    TaskDefinition {
        action: Some(TaskAction {
            uses: Some("shell".into()),
            run: Some("true".into()),
            ..TaskAction::default()
        }),
        needs: needs.iter().map(ToString::to_string).collect(),
        ..TaskDefinition::default()
    }
}

#[test]
fn context_precedence_and_fallback_are_deterministic() {
    assert_eq!(
        // Trimmed, and blank treated as unset, so the command line and the
        // resolution side cannot disagree about which context is in force. An
        // untrimmed `--context " prod "` gave the dotenv filter `prod` and the task
        // resolver `" prod "`, so the flag loaded prod's dotenv and was then
        // rejected as an unknown context.
        select_context(Some(" prod "), Some("environment"), Some("project")),
        "prod",
    );
    assert_eq!(
        select_context(Some(""), Some("prod"), Some("project")),
        "prod",
    );
    assert_eq!(select_context(Some("   "), None, None), DEFAULT_CONTEXT,);
    assert_eq!(select_context(None, Some("cli"), Some("project")), "cli");
    assert_eq!(
        select_context(None, Some("environment"), Some("project")),
        "environment"
    );
    let tasks = indexmap! { "build".into() => task(&[]), "build:prod".into() => task(&[]) };
    assert_eq!(
        plan_task(&tasks, "build", "prod").unwrap().tasks[0].name,
        "build:prod"
    );
    assert_eq!(
        plan_task(&tasks, "build", "dev").unwrap().tasks[0].name,
        "build"
    );
}

#[test]
fn binds_typed_positions_options_repetition_and_literal_passthrough() {
    let parameters = vec![
        TaskParameter {
            name: "target".into(),
            parameter_type: TaskParameterType::String,
            required: true,
            default: None,
            description: None,
            position: Some(0),
            long: None,
            short: None,
            repeatable: false,
        },
        TaskParameter {
            name: "release".into(),
            parameter_type: TaskParameterType::Boolean,
            required: false,
            default: Some(TaskParameterDefault::Boolean(false)),
            description: None,
            position: None,
            long: Some("release".into()),
            short: Some('r'),
            repeatable: false,
        },
        TaskParameter {
            name: "tag".into(),
            parameter_type: TaskParameterType::String,
            required: false,
            default: None,
            description: None,
            position: None,
            long: Some("tag".into()),
            short: None,
            repeatable: true,
        },
        TaskParameter {
            name: "count".into(),
            parameter_type: TaskParameterType::Integer,
            required: false,
            default: None,
            description: None,
            position: None,
            long: Some("count".into()),
            short: Some('c'),
            repeatable: false,
        },
    ];
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }),
            parameters,
            ..TaskDefinition::default()
        }
    };
    let arguments = [
        "app".into(),
        "-r".into(),
        "--tag=one".into(),
        "--tag".into(),
        "two".into(),
        "-c".into(),
        "02".into(),
        "--".into(),
        "--literal".into(),
    ];
    let binding = bind_task_inputs(&tasks, "build", "default", &arguments).unwrap();
    assert_eq!(binding.values["target"], ["app"]);
    assert_eq!(binding.values["release"], ["true"]);
    assert_eq!(binding.values["tag"], ["one", "two"]);
    assert_eq!(binding.values["count"], ["2"]);
    assert_eq!(binding.passthrough, ["--literal"]);
}

#[test]
fn rejects_unknown_duplicate_and_missing_task_inputs() {
    let parameter = TaskParameter {
        name: "target".into(),
        parameter_type: TaskParameterType::String,
        required: true,
        default: None,
        description: None,
        position: None,
        long: Some("target".into()),
        short: Some('t'),
        repeatable: false,
    };
    let tasks = indexmap! {
        "build".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }),
            parameters: vec![parameter],
            ..TaskDefinition::default()
        }
    };
    assert!(matches!(
        bind_task_inputs(&tasks, "build", "default", &["--unknown".into()]),
        Err(TaskInputError::UnknownOption { .. })
    ));
    assert!(matches!(
        bind_task_inputs(
            &tasks,
            "build",
            "default",
            &["-t".into(), "one".into(), "--target".into(), "two".into()]
        ),
        Err(TaskInputError::DuplicateOption { .. })
    ));
    assert!(matches!(
        bind_task_inputs(&tasks, "build", "default", &[]),
        Err(TaskInputError::MissingRequired { .. })
    ));
}

#[test]
fn rejects_invalid_task_input_bindings_before_execution() {
    let mut definition = task(&[]);
    definition.parameters = vec![TaskParameter {
        name: "context".into(),
        parameter_type: TaskParameterType::String,
        required: false,
        default: None,
        description: None,
        position: None,
        long: Some("context".into()),
        short: None,
        repeatable: false,
    }];
    let tasks = indexmap! { "build".into() => definition };
    assert!(matches!(
        resolve_inheritance(&tasks),
        Err(TaskError::InvalidParameter { .. })
    ));
}

#[test]
fn resolves_inheritance_and_reports_dependency_traces() {
    let tasks = indexmap! {
        "base".into() => TaskDefinition { template: true, help: Some("base".into()), parameters: vec![TaskParameter { name: "mode".into(), parameter_type: TaskParameterType::String, required: false, default: None, description: None, position: None, long: None, short: None, repeatable: false }], ..TaskDefinition::default() },
        "build".into() => TaskDefinition { extends: Some("base".into()), action: Some(TaskAction { uses: Some("shell".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "test".into() => task(&["build"]),
    };
    let resolved = resolve_inheritance(&tasks).unwrap();
    assert_eq!(
        task_help(&resolved, "build", "default")
            .unwrap()
            .parameters
            .len(),
        1
    );
    assert_eq!(
        plan_task(&resolved, "test", "default")
            .unwrap()
            .tasks
            .iter()
            .map(|task| task.name.as_str())
            .collect::<Vec<_>>(),
        ["build", "test"]
    );
}

#[test]
fn reports_cycles_with_the_complete_trace() {
    let tasks = indexmap! { "build".into() => task(&["test"]), "test".into() => task(&["build"]) };
    assert_eq!(
        plan_task(&tasks, "build", "default"),
        Err(TaskError::DependencyCycle {
            trace: vec!["build".into(), "test".into(), "build".into()]
        })
    );
}

#[test]
fn rejects_invalid_inheritance_and_parameter_defaults() {
    let missing = indexmap! {
        "child".into() => TaskDefinition { extends: Some("missing".into()), ..TaskDefinition::default() },
    };
    assert_eq!(
        resolve_inheritance(&missing),
        Err(TaskError::MissingBase {
            task: "child".into(),
            base: "missing".into()
        })
    );
    let invalid_default = indexmap! {
        "build".into() => TaskDefinition {
            action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }),
            parameters: vec![TaskParameter { name: "release".into(), parameter_type: TaskParameterType::Boolean, required: false, default: Some(TaskParameterDefault::String("yes".into())), description: None, position: None, long: None, short: None, repeatable: false }],
            ..TaskDefinition::default()
        },
    };
    assert!(matches!(
        resolve_inheritance(&invalid_default),
        Err(TaskError::InvalidParameterDefault { .. })
    ));
}

#[test]
fn inherits_and_validates_task_predicates() {
    let tasks = indexmap! {
        "base".into() => TaskDefinition { template: true, if_condition: Some("env.RELEASE == yes".into()), force: Some("false".into()), ..TaskDefinition::default() },
        "build".into() => TaskDefinition { extends: Some("base".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    let resolved = resolve_inheritance(&tasks).unwrap();
    assert_eq!(
        resolved["build"].if_condition.as_deref(),
        Some("env.RELEASE == yes")
    );
    assert_eq!(resolved["build"].force.as_deref(), Some("false"));
    assert!(matches!(
        resolve_inheritance(&indexmap! {
            "invalid".into() => TaskDefinition { action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), if_condition: Some("env.BAD-KEY".into()), ..TaskDefinition::default() },
        }),
        Err(TaskError::InvalidPredicate { .. })
    ));
}

#[test]
fn predicates_read_only_declared_engine_values() {
    let environment = BTreeMap::from([("MODE".into(), "release".into())]);
    let inputs = indexmap! { "target".into() => vec!["win-x64".into()] };
    let outcomes = BTreeMap::from([("prepare".into(), TaskOutcome::Succeeded)]);
    let outputs = BTreeMap::from([("ARTIFACT".into(), "dist/app.zip".into())]);
    let context = PredicateContext {
        environment: &environment,
        context: "release",
        inputs: &inputs,
        outcomes: &outcomes,
        outputs: &outputs,
        overrides: None,
        args: &[],
    };
    assert!(evaluate_predicate_with_context(
            "context == release && input.target == win-x64 && outcome.prepare == succeeded && output.ARTIFACT == dist/app.zip && env.MODE == release",
            context,
        )
        .unwrap());
    for predicate in ["$(false)", "input.bad-key", "output.", "outcome."] {
        assert!(
            evaluate_predicate_with_context(predicate, context).is_err(),
            "{predicate}"
        );
    }
}

#[test]
fn validates_render_actions_as_deterministic_file_operations() {
    let valid = indexmap! {
        "render".into() => TaskDefinition { action: Some(TaskAction { uses: Some("render".into()), source: Some("templates/app.tmpl".into()), destination: Some("generated/app".into()), with: indexmap! { "name".into() => "neoenv".into() }, ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    assert!(resolve_inheritance(&valid).is_ok());
    let invalid = indexmap! {
        "render".into() => TaskDefinition { action: Some(TaskAction { uses: Some("render".into()), source: Some("template".into()), destination: Some("output".into()), env: indexmap! { "HOST".into() => "value".into() }, ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    assert!(matches!(
        resolve_inheritance(&invalid),
        Err(TaskError::InvalidAction { .. })
    ));
}

#[test]
fn script_runners_require_an_explicit_inline_or_file_source() {
    let valid = indexmap! {
        "inline".into() => TaskDefinition { action: Some(TaskAction { uses: Some("bash".into()), run: Some("echo inline".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "file".into() => TaskDefinition { action: Some(TaskAction { uses: Some("node".into()), source: Some("scripts/run.js".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "uv".into() => TaskDefinition { action: Some(TaskAction { uses: Some("uv@0.8.0".into()), run: Some("print('inline')".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    assert!(resolve_inheritance(&valid).is_ok());

    for action in [
        // Both: the user wrote two different sources of truth.
        TaskAction {
            uses: Some("bash".into()),
            run: Some("echo inline".into()),
            source: Some("scripts/run.sh".into()),
            ..TaskAction::default()
        },
        // Neither.
        TaskAction {
            uses: Some("python".into()),
            ..TaskAction::default()
        },
        // `source` belongs to render and the named script runners, not to a
        // command runner that will never read it.
        TaskAction {
            uses: Some("portable".into()),
            run: Some("true".into()),
            source: Some("scripts/run.sh".into()),
            ..TaskAction::default()
        },
        // A versioned request must be one exact version.
        TaskAction {
            uses: Some("uv@latest".into()),
            run: Some("print('inline')".into()),
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("uv".into()),
            run: Some("print('inline')".into()),
            ..TaskAction::default()
        },
    ] {
        let tasks = indexmap! {
            "task".into() => TaskDefinition {
                action: Some(action),
                ..TaskDefinition::default()
            },
        };
        assert!(
            matches!(
                resolve_inheritance(&tasks),
                Err(TaskError::InvalidAction { .. })
            ),
            "the action must be refused rather than half-read"
        );
    }
}

#[test]
fn tmpl_requires_files_and_only_known_with_keys() {
    let valid = indexmap! {
        "render".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("tmpl".into()),
                files: vec!["app.yml.gotmpl:out/app.yml".into()],
                with: indexmap! {
                    "values".into() => "values.yaml".into(),
                    "disable-gotmpl".into() => "true".into(),
                },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    assert!(resolve_inheritance(&valid).is_ok());

    for action in [
        TaskAction {
            uses: Some("tmpl".into()),
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("tmpl".into()),
            files: vec!["app.yml.gotmpl".into()],
            with: indexmap! { "file".into() => "app.yml.gotmpl".into() },
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("tmpl".into()),
            files: vec!["app.yml.gotmpl".into()],
            run: Some("echo".into()),
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("tmpl".into()),
            files: vec![":out".into()],
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("shell".into()),
            run: Some("true".into()),
            files: vec!["app.yml.gotmpl".into()],
            ..TaskAction::default()
        },
    ] {
        let tasks = indexmap! {
            "render".into() => TaskDefinition {
                action: Some(action),
                ..TaskDefinition::default()
            },
        };
        assert!(
            matches!(
                resolve_inheritance(&tasks),
                Err(TaskError::InvalidAction { .. })
            ),
            "the tmpl action must be refused"
        );
    }
}

#[test]
fn inherited_tmpl_overrides_keep_their_own_provenance() {
    let base = SourceSpan::new("base.yaml".into(), 1, 1);
    let child = SourceSpan::new("child.yaml".into(), 1, 1);
    let tasks = indexmap! {
        "base".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("tmpl".into()),
                files: vec!["base.tmpl:base.out".into()],
                files_document: Some(base.clone()),
                values_document: Some(base.clone()),
                with: indexmap! { "values".into() => "base-values.yaml".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
        "child".into() => TaskDefinition {
            extends: Some("base".into()),
            action: Some(TaskAction {
                files: vec!["child.tmpl:child.out".into()],
                files_document: Some(child.clone()),
                values_document: Some(child.clone()),
                with: indexmap! { "values".into() => "child-values.yaml".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
        "values-only".into() => TaskDefinition {
            extends: Some("base".into()),
            action: Some(TaskAction {
                values_document: Some(child.clone()),
                with: indexmap! { "values".into() => "child-values.yaml".into() },
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    let resolved = resolve_inheritance(&tasks).unwrap();
    let child_action = resolved["child"].action.as_ref().unwrap();
    assert_eq!(
        child_action.files_document.as_ref().unwrap().path,
        "child.yaml"
    );
    assert_eq!(
        child_action.values_document.as_ref().unwrap().path,
        "child.yaml"
    );
    let values_only = resolved["values-only"].action.as_ref().unwrap();
    assert_eq!(
        values_only.files_document.as_ref().unwrap().path,
        "base.yaml"
    );
    assert_eq!(
        values_only.values_document.as_ref().unwrap().path,
        "child.yaml"
    );
}

#[test]
fn wsl_requires_run_and_only_known_with_keys() {
    let valid = indexmap! {
        "wsl".into() => TaskDefinition {
            action: Some(TaskAction {
                uses: Some("wsl".into()),
                run: Some("echo hi".into()),
                with: indexmap! {
                    "distribution".into() => "Ubuntu-22.04".into(),
                    "mount-root".into() => "/mnt".into(),
                },
                args: vec!["one".into()],
                ..TaskAction::default()
            }),
            ..TaskDefinition::default()
        },
    };
    assert!(resolve_inheritance(&valid).is_ok());

    for action in [
        TaskAction {
            uses: Some("wsl".into()),
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            source: Some("unused.sh".into()),
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            with: indexmap! { "image".into() => "ubuntu".into() },
            ..TaskAction::default()
        },
        TaskAction {
            uses: Some("wsl".into()),
            run: Some("echo hi".into()),
            with: indexmap! { "mount-root".into() => "mnt".into() },
            ..TaskAction::default()
        },
    ] {
        let tasks = indexmap! {
            "wsl".into() => TaskDefinition {
                action: Some(action),
                ..TaskDefinition::default()
            },
        };
        assert!(matches!(
            resolve_inheritance(&tasks),
            Err(TaskError::InvalidAction { .. })
        ));
    }
}

#[test]
fn resolves_explicit_identity_and_legacy_key_fallback_deterministically() {
    let tasks = indexmap! {
        "Build App".into() => TaskDefinition { id: Some("build-app-v2".into()), name: Some("Build application".into()), slug: Some("build-app".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "legacy:task".into() => task(&[]),
    };
    let resolved = resolve_inheritance(&tasks).unwrap();
    let help = task_help(&resolved, "build-app", "default").unwrap();
    assert_eq!(help.id, "build-app-v2");
    assert_eq!(help.name, "Build application");
    assert_eq!(help.slug, "build-app");
    assert_eq!(resolved["legacy:task"].id.as_deref(), Some("legacy:task"));
    assert_eq!(resolved["legacy:task"].slug.as_deref(), Some("legacy-task"));
    assert_eq!(
        plan_task(&resolved, "legacy:task", "default")
            .unwrap()
            .tasks[0]
            .name,
        "legacy:task"
    );
}

#[test]
fn rejects_duplicate_ids_and_slugs_in_declaration_order() {
    let duplicate_ids = indexmap! {
        "first".into() => TaskDefinition { id: Some("same".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "second".into() => TaskDefinition { id: Some("same".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    assert_eq!(
        resolve_inheritance(&duplicate_ids),
        Err(TaskError::DuplicateTaskIdentity {
            field: "id".into(),
            value: "same".into(),
            tasks: vec!["first".into(), "second".into()]
        })
    );
    let duplicate_slugs = indexmap! {
        "first".into() => TaskDefinition { slug: Some("same".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
        "second".into() => TaskDefinition { slug: Some("same".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), ..TaskDefinition::default() },
    };
    assert!(
        matches!(resolve_inheritance(&duplicate_slugs), Err(TaskError::DuplicateTaskIdentity { field, .. }) if field == "slug")
    );
}

#[test]
fn plans_hooks_around_dependencies_with_context_fallback_and_inheritance() {
    let tasks = indexmap! {
        "base".into() => TaskDefinition { template: true, hooks: TaskHooks { before: vec!["before".into()], after: vec!["after".into()] }, ..TaskDefinition::default() },
        "build".into() => TaskDefinition { extends: Some("base".into()), action: Some(TaskAction { uses: Some("portable".into()), run: Some("true".into()), ..TaskAction::default() }), needs: vec!["prepare".into()], ..TaskDefinition::default() },
        "prepare".into() => task(&[]),
        "build:before".into() => task(&[]),
        "build:before:prod".into() => task(&[]),
        "build:after".into() => task(&[]),
    };
    let resolved = resolve_inheritance(&tasks).unwrap();
    assert_eq!(
        plan_task(&resolved, "build", "prod")
            .unwrap()
            .tasks
            .iter()
            .map(|task| task.name.as_str())
            .collect::<Vec<_>>(),
        ["prepare", "build:before:prod", "build", "build:after"]
    );
}

#[test]
fn task_predicates_have_deterministic_truthiness() {
    let environment = BTreeMap::from([("MODE".into(), "release".into())]);
    assert!(!evaluate_predicate("env.MISSING", &environment).unwrap());
    for value in ["0", "false", "NO", "off", "null", "nil"] {
        assert!(!evaluate_predicate(value, &environment).unwrap(), "{value}");
    }
    assert!(
        !evaluate_predicate("env.MODE == release && os == \"unsupported\"", &environment).unwrap()
    );
    assert!(evaluate_predicate("env.MODE == release && arch == arch", &environment).unwrap());
    assert!(evaluate_predicate("!(env.MODE != release) || false", &environment).unwrap());
}

/// A predicate error is rendered at the CLI boundary and a numeric operand can
/// be a resolved secret. The diagnostic must not contain it.
#[test]
fn a_numeric_predicate_error_does_not_include_the_operand() {
    let environment = BTreeMap::from([("SECRET".into(), "super-secret-sentinel".into())]);
    let error = evaluate_predicate("env.SECRET % 2 == 0", &environment).unwrap_err();
    assert!(!error.contains("super-secret-sentinel"), "{error}");
}

/// The Go-reference predicate surface added for #499: `args`, `args.N`,
/// `success`, `outputs.*`, ordered comparisons, and modulo.
///
/// Every case here has a counterpart in the reference's `runner/predicate.go`,
/// and the two behaviors that matter most are pinned explicitly: the language
/// stays closed, and a comparison that cannot be answered is an error rather
/// than a silent `false`.
mod go_predicate_parity {
    use super::{BTreeMap, PredicateContext, TaskOutcome, evaluate_predicate_with_context};
    use indexmap::IndexMap;

    fn evaluate(predicate: &str) -> Result<bool, String> {
        evaluate_predicate_with_context(predicate, PredicateContext::empty(&BTreeMap::new()))
    }

    fn with_args(predicate: &str, args: &[&str]) -> Result<bool, String> {
        let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
        evaluate_predicate_with_context(
            predicate,
            PredicateContext {
                args: &owned,
                ..PredicateContext::empty(&BTreeMap::new())
            },
        )
    }

    fn with_outcomes(predicate: &str, outcomes: &[(&str, TaskOutcome)]) -> Result<bool, String> {
        let outcomes: BTreeMap<String, TaskOutcome> = outcomes
            .iter()
            .map(|(name, outcome)| ((*name).to_owned(), *outcome))
            .collect();
        evaluate_predicate_with_context(
            predicate,
            PredicateContext {
                outcomes: &outcomes,
                ..PredicateContext::empty(&BTreeMap::new())
            },
        )
    }

    fn with_outputs(predicate: &str, outputs: &[(&str, &str)]) -> Result<bool, String> {
        let outputs: BTreeMap<String, String> = outputs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        evaluate_predicate_with_context(
            predicate,
            PredicateContext {
                outputs: &outputs,
                ..PredicateContext::empty(&BTreeMap::new())
            },
        )
    }

    #[test]
    fn args_resolves_the_whole_list_and_one_index() {
        assert!(with_args("args == 'build watch'", &["build", "watch"]).unwrap());
        assert!(with_args("args.0 == build", &["build", "watch"]).unwrap());
        assert!(with_args("args.1 == watch", &["build", "watch"]).unwrap());
        assert!(!with_args("args.0 == watch", &["build", "watch"]).unwrap());
    }

    #[test]
    fn args_accepts_both_the_reference_spelling_and_the_bracket_spelling() {
        // The reference writes `args.0`; a task file that writes `args[0]` means
        // the same thing, and neither spelling should be the "correct" one.
        for predicate in ["args.0 == build", "args[0] == build"] {
            assert!(with_args(predicate, &["build"]).unwrap(), "{predicate}");
        }
    }

    #[test]
    fn an_out_of_range_or_malformed_args_reference_is_handled_predictably() {
        // Out of range is empty, not an error: a predicate that guards an
        // optional argument has to be expressible.
        assert!(!with_args("args.5", &["build"]).unwrap());
        assert!(!with_args("args.5 == build", &["build"]).unwrap());
        assert!(!with_args("args", &[]).unwrap());
        assert!(with_args("args == ''", &[]).unwrap());
        assert!(
            with_args("args.abc", &["build"]).is_err(),
            "a non-numeric index is a mistake worth reporting"
        );
    }

    #[test]
    fn success_tracks_whether_the_run_so_far_is_clean() {
        assert!(with_outcomes("success", &[("a", TaskOutcome::Succeeded)]).unwrap());
        assert!(with_outcomes("success", &[]).unwrap());
        assert!(!with_outcomes("success", &[("a", TaskOutcome::Failed)]).unwrap());
        assert!(!with_outcomes("success", &[("a", TaskOutcome::TimedOut)]).unwrap());
        assert!(!with_outcomes("success", &[("a", TaskOutcome::Cancelled)]).unwrap());
        // Skipped and blocked are not failures: a `needs` that was skipped for
        // a reason other than failure must not read as a failure.
        assert!(with_outcomes("success", &[("a", TaskOutcome::Skipped)]).unwrap());
        assert!(with_outcomes("success", &[("a", TaskOutcome::Blocked)]).unwrap());
    }

    #[test]
    fn outputs_accepts_both_spellings() {
        for predicate in [
            "outputs.ARTIFACT == dist/app.zip",
            "output.ARTIFACT == dist/app.zip",
        ] {
            assert!(
                with_outputs(predicate, &[("ARTIFACT", "dist/app.zip")]).unwrap(),
                "{predicate}"
            );
        }
        assert!(!with_outputs("outputs.MISSING", &[("ARTIFACT", "x")]).unwrap());
        assert!(with_outputs("outputs.", &[("ARTIFACT", "x")]).is_err());
    }

    #[test]
    fn ordered_comparisons_are_numeric() {
        assert!(evaluate("2 > 1").unwrap());
        assert!(!evaluate("1 > 2").unwrap());
        assert!(evaluate("2 >= 2").unwrap());
        assert!(evaluate("1 < 2").unwrap());
        assert!(evaluate("2 <= 2").unwrap());
        assert!(evaluate("-1 < 0").unwrap());
        assert!(evaluate("1.5 > 1").unwrap());
    }

    #[test]
    fn an_ordered_comparison_of_non_numbers_is_an_error() {
        // Comparing two words alphabetically is almost never what a user meant,
        // and answering `false` would hide the mistake.
        for predicate in ["apple > banana", "1 > x", "x <= 1"] {
            assert!(evaluate(predicate).is_err(), "{predicate} must be an error");
        }
    }

    #[test]
    fn equality_compares_numerically_when_both_sides_are_numbers() {
        assert!(evaluate("1 == 1.0").unwrap());
        assert!(evaluate("1.0 == 1").unwrap());
        assert!(!evaluate("1 == 1.5").unwrap());
    }

    #[test]
    fn equality_falls_back_to_a_string_comparison() {
        assert!(evaluate("apple == apple").unwrap());
        assert!(evaluate("apple != banana").unwrap());
        assert!(!evaluate("1 == apple").unwrap());
    }

    #[test]
    fn modulo_binds_tighter_than_comparison() {
        assert!(evaluate("7 % 2 == 1").unwrap());
        assert!(evaluate("8 % 2 == 0").unwrap());
        assert!(evaluate("7 % 2 > 0").unwrap());
        assert!(evaluate("7 % 3 == 1").unwrap(), "7 % 3 is 1");
        assert!(!evaluate("7 % 3 == 2").unwrap());
        // Left-associative, so `7 % 4 % 2` is `(7 % 4) % 2` == `3 % 2` == 1.
        assert!(evaluate("7 % 4 % 2 == 1").unwrap());
    }

    #[test]
    fn a_modulo_that_cannot_be_answered_is_an_error() {
        assert!(evaluate("7 % 0 == 1").is_err());
        assert!(evaluate("7 % x == 1").is_err());
        assert!(evaluate("apple % 2 == 1").is_err());
    }

    #[test]
    fn operator_precedence_matches_the_reference() {
        // Each case below is chosen so that a *different* grouping gives the
        // opposite answer. The earlier version of this test used pairs that were
        // true or false under any grouping, so it asserted nothing about
        // precedence at all.
        //
        // `&&` binds tighter than `||`. Note that `a && b || c` cannot tell
        // `&&`-first from left-to-right apart -- the two agree for every
        // assignment, because `&&` is the only tighter operator. What it *can*
        // distinguish is `||` binding tighter, which is the actual mistake to
        // guard against: `true || true && false` is true under `&&`-first and
        // false under `||`-first.
        assert!(evaluate("true || true && false").unwrap());
        assert!(!evaluate("false || true && false").unwrap());
        // Comparison binds tighter than `&&`, so this asks whether `1 == 1` is
        // true, not whether `1` equals `1 && false`.
        assert!(!evaluate("1 == 1 && false").unwrap());
        // Modulo binds tighter than comparison: `7 % 2 == 1` asks whether
        // `7 % 2` is 1, not whether `7` is `(2 == 1) % ...`.
        assert!(evaluate("7 % 2 == 1 && 2 > 1").unwrap());
        assert!(!evaluate("7 % 2 == 2 && 2 > 1").unwrap());
        // `!` binds tightest, so it negates the whole comparison.
        assert!(evaluate("!(1 == 2)").unwrap());
        assert!(evaluate("!(2 % 2 == 1)").unwrap());
        assert!(!evaluate("!(2 % 2 == 0)").unwrap());
    }

    #[test]
    fn a_short_circuited_operand_is_parsed_but_not_evaluated() {
        // The reference suppresses evaluation on the far side of a decided
        // `&&` or `||`, so these four are values there and errors here without
        // the rule. Each names a case the reference pins in its own test suite.
        for (predicate, expected) in [
            ("false && env.COUNT > nope", false),
            ("false && env.COUNT % 0 == 1", false),
            ("true || args.nope == value", true),
            ("false && args.nope == value", false),
            ("true || env.COUNT % 0 == 1", true),
            // Not short-circuited, so these still report the real problem.
        ] {
            assert_eq!(
                evaluate(predicate),
                Ok(expected),
                "{predicate} must short-circuit to {expected}"
            );
        }
    }

    #[test]
    fn a_short_circuit_reaches_inside_a_nested_subexpression() {
        // The flag has to be *saved and restored* around each operand, and
        // merged with the inherited one rather than assigned over it. A nested
        // `&&`/`||` iteration that cleared the flag on the way out re-arms
        // evaluation for the rest of the parent's operand, and the error the
        // short-circuit exists to suppress escapes. Each of these was an error
        // before the flag was merged rather than assigned.
        for predicate in [
            "false && (a == b || c == d || env.COUNT % 0 == 1)",
            "false && (a == b || c == d || args.x == 1)",
            "false && (a || b || apple > 1)",
            "true || (a && b && env.COUNT % 0 == 1)",
            "false && (a == b && c == d && env.COUNT > nope)",
        ] {
            let expected = predicate.starts_with("true");
            assert_eq!(evaluate(predicate), Ok(expected), "{predicate}");
        }
    }

    #[test]
    fn a_short_circuit_does_not_discard_a_structural_error() {
        // `value || right?` and `value && right?` would let a decided left side
        // short-circuit the `?` itself and drop a structural error in the
        // operand, so the `?` is applied before the operator. An unclosed
        // paren and a stray token are shape errors, not evaluation errors, and
        // stay errors.
        for predicate in ["false && (", "false && a b", "true || ("] {
            assert!(evaluate(predicate).is_err(), "{predicate} must be an error");
        }
    }

    #[test]
    fn a_short_circuit_still_reports_a_malformed_expression() {
        // Suppressing evaluation must not mean ignoring a syntax error: a
        // short-circuited operand is still *parsed*, so a trailing token is
        // still a mistake worth reporting.
        assert!(evaluate("false && (").is_err());
        assert!(evaluate("false && a b").is_err());
    }

    #[test]
    fn an_unterminated_quote_is_an_error_rather_than_an_empty_literal() {
        // Without this, `if: os == '` compared against an empty string and
        // silently skipped the task, which reads as "the condition was false"
        // rather than "the file has a typo".
        for predicate in ["os == '", "'", "os == \"unterminated"] {
            assert!(evaluate(predicate).is_err(), "{predicate} must be an error");
        }
    }

    #[test]
    fn a_quote_inside_a_bare_word_ends_the_word() {
        // The reference splits on a quote character, so `env.FOO"bar"` is two
        // tokens there and must be two here.
        assert!(evaluate("env.FOO\"bar\"").is_err());
    }

    #[test]
    fn the_language_stays_closed() {
        // A command substitution is rejected outright, because `(` makes it
        // unparseable. That is the stronger of the two acceptable answers.
        for predicate in ["$(false)", "$(id)"] {
            assert!(evaluate(predicate).is_err(), "{predicate} must not parse");
        }
        // Quoted, it is a literal and the comparison is simply false.
        assert!(!evaluate("os == '$(uname)'").unwrap());
        // A bare word is a literal, not a call. `__import__` and `eval` are
        // truthy strings, and that is the correct answer: nothing ran.
        assert!(evaluate("__import__").unwrap());
        assert!(evaluate("eval").unwrap());
        // A backtick is not a quote character here, so this is the literal
        // string "`false`" rather than a command.
        assert!(evaluate("`false`").unwrap());
        // A missing reference is empty, so a comparison against it is false.
        assert!(!evaluate("input.NOPE == 'x'").unwrap());
        assert!(!evaluate("env.NEOENV_DEFINITELY_UNSET == 'x'").unwrap());
    }

    #[test]
    fn a_reference_to_a_missing_input_is_empty_not_an_error() {
        let inputs = IndexMap::new();
        let environment = BTreeMap::new();
        assert_eq!(
            evaluate_predicate_with_context(
                "input.absent == x",
                PredicateContext {
                    inputs: &inputs,
                    ..PredicateContext::empty(&environment)
                },
            ),
            Ok(false)
        );
        assert_eq!(
            evaluate_predicate_with_context(
                "input.absent",
                PredicateContext {
                    inputs: &inputs,
                    ..PredicateContext::empty(&environment)
                },
            ),
            Ok(false),
            "a missing input resolves to the empty string, which is not truthy"
        );
    }
}

/// Rejecting a context the project does not use.
///
/// The reference does not do this: `runner.go` looks up `name:context` and falls
/// back to `name`, so a typo silently runs the default-context task and reports
/// success. The fallback is still correct for a task that genuinely has no
/// contextual variant, so the rule here is narrow — a context is rejected only
/// when the project declares *some* context and this is not one of them.
mod context_validation {
    use indexmap::IndexMap;

    use super::{DEFAULT_CONTEXT, TaskDefinition, TaskError};
    use crate::tasks::{known_contexts, validate_context};

    fn tasks(keys: &[&str]) -> IndexMap<String, TaskDefinition> {
        keys.iter()
            .map(|key| ((*key).to_owned(), TaskDefinition::default()))
            .collect()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The bug the ticket is about, stated as a test.
    #[test]
    fn a_mistyped_context_is_rejected_rather_than_running_the_default_task() {
        let error = validate_context(&tasks(&["build", "deploy", "build:prod"]), &[], "releae")
            .expect_err("a typo must not resolve");
        match &error {
            TaskError::UnknownContext { context, known } => {
                assert_eq!(context, "releae");
                // The message has to name what *is* available, or the user has
                // nothing to correct toward.
                assert_eq!(known, &["prod".to_owned()]);
            }
            other => panic!("expected an unknown context, got {other}"),
        }
        // And the message says why, because "unknown context" alone reads as
        // "this project has no contexts".
        let message = error.to_string();
        assert!(
            message.contains("would otherwise run the default-context task"),
            "{message}"
        );
    }

    /// The false positive that would make this feature unusable. A project that
    /// does not use contexts has no set for the name to be wrong against, so
    /// every invocation must keep working.
    #[test]
    fn a_project_with_no_contexts_accepts_any_name() {
        validate_context(&tasks(&["build", "deploy"]), &[], "anything")
            .expect("a project with no contexts must not reject one");
        validate_context(&tasks(&["build", "deploy"]), &[], "staging")
            .expect("a project with no contexts must not reject one");
    }

    /// A task that genuinely has no contextual variant still runs in the default
    /// context. That is the reference's behavior and the reason the fallback
    /// exists; this change must not remove it.
    #[test]
    fn a_task_without_a_variant_still_runs_in_a_known_context() {
        // `deploy` has no `:prod` variant. The context is known, so nothing is
        // rejected -- the resolution itself falls back, which is correct.
        validate_context(&tasks(&["build:prod", "deploy"]), &[], "prod")
            .expect("a known context is valid even for a task with no variant");
    }

    /// A context declared only by a `dotenv:` entry is still a context the
    /// project uses, and is the only signal in a project with no contextual tasks.
    #[test]
    fn a_context_declared_only_by_a_dotenv_counts_as_known() {
        let project = tasks(&["build"]);
        validate_context(&project, &strings(&["prod"]), "prod")
            .expect("a dotenv-declared context is known");
        validate_context(&project, &strings(&["prod"]), "produ")
            .expect_err("and a typo of it is not");
    }

    #[test]
    fn the_default_context_and_the_wildcards_are_always_valid() {
        let project = tasks(&["build:prod"]);
        for context in [DEFAULT_CONTEXT, "", "*"] {
            validate_context(&project, &[], context)
                .unwrap_or_else(|error| panic!("{context:?} must be valid: {error}"));
        }
    }

    /// The known set is what the error message lists, so it has to be complete
    /// and free of the non-names a wildcard introduces.
    #[test]
    fn the_known_set_holds_every_declared_name_and_no_wildcard() {
        let known = known_contexts(
            // A `build:*` key: the wildcard has to be filtered from the *task-key*
            // source as well as from the declared one, or it lands in the list the
            // error message prints and looks like a context a user could pass.
            &tasks(&["build", "build:prod", "deploy:staging", "weird:", "build:*"]),
            &strings(&["qa", "*", ""]),
        );
        let listed: Vec<&str> = known.iter().map(String::as_str).collect();
        assert_eq!(
            listed,
            ["prod", "qa", "staging"],
            "sorted and wildcard-free"
        );
    }

    /// A task *package*'s task is not a context.
    ///
    /// Package keys are `package-<alias>:<name>`, and harvesting every key's last
    /// colon segment made a task named `deploy` into a context. A project whose
    /// only contextual task is `build:prod` then accepted `--context deploy` and
    /// ran the default-context `build` reporting success -- the #503 failure
    /// reopened through the other task source.
    #[test]
    fn a_task_package_name_is_not_a_context() {
        let known = known_contexts(&tasks(&["build", "build:prod", "package-api:deploy"]), &[]);
        let listed: Vec<&str> = known.iter().map(String::as_str).collect();
        assert_eq!(
            listed,
            ["prod"],
            "a package task is not a context: {listed:?}"
        );
        // And so a typo that happens to match a package task is still rejected.
        validate_context(
            &tasks(&["build", "build:prod", "package-api:deploy"]),
            &[],
            "deploy",
        )
        .expect_err("a package task must not make a context known");
    }

    /// A package task that is *itself* contextual does contribute a context.
    ///
    /// Filtering on the `package-` prefix excluded the whole keyspace, so
    /// `package-ci:deploy:prod` -- a package task named `deploy:prod` -- lost
    /// `prod`, and a project whose only contextual task came from a package
    /// answered `UnknownContext` for `--context prod`. That is the same false
    /// positive as the one the prefix filter was added to fix, in the other
    /// direction, which is why the filter is on the segment *count*.
    #[test]
    fn a_contextual_package_task_still_contributes_its_context() {
        let project = tasks(&["package-ci:deploy:prod", "package-ci:build"]);
        assert_eq!(
            known_contexts(&project, &[])
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["prod"],
            "three segments means a contextual package task"
        );
        validate_context(&project, &[], "prod")
            .expect("the context the package task declares is known");
        validate_context(&project, &[], "build")
            .expect_err("and an uncontextual package task's name is not");
    }

    /// A task key may itself contain several colons; only the last segment is the
    /// context. Reading the wrong split would make `a:b` contribute `a`.
    #[test]
    fn only_the_last_segment_of_a_task_key_is_a_context() {
        let known = known_contexts(&tasks(&["group:sub:prod"]), &[]);
        assert_eq!(
            known.iter().map(String::as_str).collect::<Vec<_>>(),
            ["prod"]
        );
    }
}
