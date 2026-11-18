//! Crate-root tests for global tool selection, supervised installs, and
//! provider planning. These drive the crate-root re-exports, so they also
//! pin which `global_install` items the binary is expected to surface.

use std::{
    fs,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

#[cfg(unix)]
use super::state_file_diagnostic;
use super::{
    GlobalInstallEvent, GlobalProviderEnvironment, GlobalScope, GlobalToolInstallation,
    GlobalToolRequest, catch_global_install_panic, global_install_cancellation,
    parse_global_tool_request_with_environment, parse_global_use, record_global_tools_at,
    state_file, supervise_global_installs,
};
use neoenv_core::{Diagnostic, DiagnosticCategory};
use tempfile::tempdir;

#[test]
fn global_use_parses_a_native_tool_and_version() {
    let request = parse_global_use(&["--user".into(), "dotnet@10.0.401".into()]).unwrap();
    assert_eq!(request.scope, GlobalScope::User);
    assert_eq!(request.tools.len(), 1);
    assert_eq!(request.tools[0].tool, "dotnet");
    assert_eq!(request.tools[0].version.as_deref(), Some("10.0.401"));
    assert!(!request.dry_run);
}

#[test]
fn global_use_supports_a_non_mutating_preview() {
    let request =
        parse_global_use(&["--global".into(), "--dry-run".into(), "dotnet".into()]).unwrap();
    assert_eq!(request.scope, GlobalScope::System);
    assert_eq!(request.tools.len(), 1);
    assert_eq!(request.tools[0].tool, "dotnet");
    assert_eq!(request.tools[0].version, None);
    assert!(request.dry_run);
}

#[test]
fn global_use_preserves_multiple_tool_order() {
    let request = parse_global_use(&[
        "--global".into(),
        "dotnet@10.0.401".into(),
        "dotnet@9.0.308".into(),
    ])
    .unwrap();
    assert_eq!(request.tools.len(), 2);
    assert_eq!(request.tools[0].version.as_deref(), Some("10.0.401"));
    assert_eq!(request.tools[1].version.as_deref(), Some("9.0.308"));
}

#[test]
fn global_use_short_g_selects_the_system_scope() {
    let request = parse_global_use(&["-g".into(), "--dry-run".into(), "java@21".into()]).unwrap();
    assert_eq!(request.scope, GlobalScope::System);
}

#[test]
fn global_use_accepts_the_java_runtime_and_a_feature_version() {
    let request = parse_global_use(&["--user".into(), "java@21".into()]).unwrap();
    assert_eq!(request.tools[0].tool, "java");
    assert_eq!(request.tools[0].version.as_deref(), Some("21"));
    assert!(
        request.tools[0].declaration.is_none(),
        "java is a native runtime request, not a provider declaration"
    );
}

#[test]
fn global_use_normalizes_the_golang_runtime_alias() {
    let request = parse_global_use(&["--user".into(), "golang@1.26.1".into()]).unwrap();
    assert_eq!(request.tools[0].tool, "go");
    assert_eq!(request.tools[0].version.as_deref(), Some("1.26.1"));
}

#[test]
fn global_use_accepts_github_and_scoped_package_keys() {
    let request = parse_global_use(&[
        "--user".into(),
        "gh:owner/repo@1.2.3".into(),
        "npm:@scope/demo@2.3.4".into(),
    ])
    .unwrap();
    assert_eq!(request.tools[0].tool, "gh:owner/repo");
    assert!(request.tools[0].declaration.is_some());
    assert_eq!(request.tools[1].tool, "npm:@scope/demo");
    assert_eq!(request.tools[1].version.as_deref(), Some("2.3.4"));
    assert!(request.tools[1].declaration.is_some());
}

#[test]
fn global_provider_planning_consumes_only_typed_environment_input() {
    let environment = GlobalProviderEnvironment {
        github_asset: Some("tool-linux.tar.gz".into()),
        github_checksum_asset: Some("checksums.txt".into()),
        github_binaries: Some(vec!["tool".into(), "tool-helper".into()]),
        github_sha256: Some("a".repeat(64)),
        npm_endpoint: Some("https://npm.example.test".into()),
        nuget_endpoint: Some("https://nuget.example.test".into()),
        gem_endpoint: Some("https://gems.example.test".into()),
        aqua_endpoint: None,
        aqua_revision: None,
        aqua_manifest_sha256: None,
    };
    let request =
        parse_global_tool_request_with_environment("gh:owner/repo", Some("1.2.3"), &environment)
            .unwrap();
    let declaration = request.declaration.unwrap();
    let github = declaration.github_release.unwrap();
    assert_eq!(declaration.version, "1.2.3");
    assert_eq!(declaration.binaries, ["tool", "tool-helper"]);
    assert_eq!(github.asset.as_deref(), Some("tool-linux.tar.gz"));
    assert_eq!(github.checksum_asset.as_deref(), Some("checksums.txt"));
    assert_eq!(declaration.sha256.as_deref(), Some("a".repeat(64).as_str()));
    let mut aqua_environment = environment;
    aqua_environment.aqua_endpoint = Some("https://registry.example.test".into());
    aqua_environment.aqua_revision = Some("0123456789012345678901234567890123456789".into());
    aqua_environment.aqua_manifest_sha256 = Some("b".repeat(64));
    let aqua = parse_global_tool_request_with_environment(
        "aqua:owner/tool",
        Some("1.2.3"),
        &aqua_environment,
    )
    .unwrap()
    .declaration
    .unwrap();
    assert_eq!(aqua.provider, neoenv_core::tools::ToolProvider::Aqua);
    assert_eq!(
        aqua.aqua.as_ref().unwrap().registry_revision,
        "0123456789012345678901234567890123456789"
    );
    aqua_environment.aqua_revision = Some("../../outside".into());
    assert!(
        parse_global_tool_request_with_environment(
            "aqua:owner/tool",
            Some("1.2.3"),
            &aqua_environment,
        )
        .is_err()
    );
}

#[test]
fn github_global_lock_reuse_rejects_changed_repository_asset_and_digest() {
    let environment = GlobalProviderEnvironment {
        github_asset: Some("payload-{os}-{arch}".into()),
        github_sha256: Some("a".repeat(64)),
        ..GlobalProviderEnvironment::default()
    };
    let declaration =
        super::global_install::global_provider_declaration("gh:owner/repo", "1.2.3", &environment)
            .unwrap();
    let platform = neoenv_core::tools::Platform::new("linux", "x86_64");
    let release = neoenv_core::tools::GithubReleaseMetadata {
        id: 42,
        tag: "1.2.3".into(),
        assets: vec![neoenv_core::tools::GithubReleaseAsset {
            id: 7,
            name: "payload-linux-x86_64".into(),
            url: "https://example.test/payload-linux-x86_64".into(),
        }],
    };
    let plan =
        neoenv_core::tools::plan_github_release(&declaration, &platform, &release, None).unwrap();
    let lock = neoenv_core::tools::ToolLockfile::from_plan(&neoenv_core::tools::ToolPlan {
        tools: vec![plan],
    });
    assert!(super::global_install::global_lock_reusable_for_request(
        &declaration,
        &lock,
        "gh:owner/repo",
        "1.2.3"
    ));

    let mut changed_repository = declaration.clone();
    changed_repository
        .github_release
        .as_mut()
        .unwrap()
        .repository = "other/repo".into();
    assert!(!super::global_install::global_lock_reusable_for_request(
        &changed_repository,
        &lock,
        "gh:owner/repo",
        "1.2.3"
    ));

    let mut changed_asset = declaration.clone();
    changed_asset.github_release.as_mut().unwrap().asset = Some("different".into());
    assert!(!super::global_install::global_lock_reusable_for_request(
        &changed_asset,
        &lock,
        "gh:owner/repo",
        "1.2.3"
    ));

    let mut changed_digest = declaration.clone();
    changed_digest.sha256 = Some("b".repeat(64));
    assert!(!super::global_install::global_lock_reusable_for_request(
        &changed_digest,
        &lock,
        "gh:owner/repo",
        "1.2.3"
    ));

    let mut tampered_artifact = lock.clone();
    tampered_artifact.tools[0].sha256 = "c".repeat(64);
    tampered_artifact.tools[0].verification.sha256 = "c".repeat(64);
    assert_eq!(
        tampered_artifact.tools[0].provenance.declaration_sha256,
        lock.tools[0].provenance.declaration_sha256,
        "the stored declaration fingerprint remains unchanged"
    );
    assert!(!super::global_install::global_lock_reusable_for_request(
        &declaration,
        &tampered_artifact,
        "gh:owner/repo",
        "1.2.3"
    ));

    let mut wrong_selected_asset = lock.clone();
    wrong_selected_asset.tools[0].url = "https://example.test/other".into();
    assert!(!super::global_install::global_lock_reusable_for_request(
        &declaration,
        &wrong_selected_asset,
        "gh:owner/repo",
        "1.2.3"
    ));
}

#[test]
fn global_use_rejects_unsupported_and_remote_module_spellings_before_planning() {
    for key in [
        "github:owner/repo",
        "https://github.com/owner/repo",
        "unknown:package",
        "aqua:owner/tool",
        "go:example.com/tool",
        "gl:owner/repo",
    ] {
        let error = parse_global_use(&["--user".into(), key.into()]).unwrap_err();
        assert_eq!(error.code, "NEO510", "{key}: {error}");
    }
}

#[test]
fn global_worker_error_is_a_diagnostic_without_panicking() {
    let tool = GlobalToolRequest {
        tool: "dotnet".into(),
        version: None,
        declaration: None,
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        catch_global_install_panic(&tool, || {
            Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO520",
                "injected worker failure",
            ))
        })
    }))
    .expect("worker error path must not unwind");
    assert_eq!(result.unwrap_err().code, "NEO520");
}

#[test]
fn global_worker_panic_becomes_a_completion_error() {
    let tool = GlobalToolRequest {
        tool: "dotnet".into(),
        version: None,
        declaration: None,
    };
    let result = catch_global_install_panic(&tool, || -> Result<_, _> {
        panic!("injected worker failure");
    });
    let Err(error) = result else {
        panic!("worker panic must be reported");
    };
    assert_eq!(error.code, "NEO702");
    assert!(error.message.contains("dotnet@latest"));
}

fn fake_request(tool: &str) -> GlobalToolRequest {
    GlobalToolRequest {
        tool: tool.into(),
        version: Some("1.0.0".into()),
        declaration: None,
    }
}

fn fake_installation(tool: &str) -> GlobalToolInstallation {
    GlobalToolInstallation {
        tool: tool.into(),
        version: "1.0.0".into(),
        executable: format!("{tool}.exe").into(),
        provider: None,
        new_install: false,
    }
}

#[test]
fn supervisor_joins_a_panicking_worker_and_returns_a_diagnostic() {
    let tools = vec![fake_request("dotnet"), fake_request("node")];
    let outcome = supervise_global_installs(
        &tools,
        &AtomicBool::new(false),
        |index, tool, sender| {
            let name = tool.tool.clone();
            thread::spawn(move || {
                assert!(index != 0, "injected supervisor worker panic");
                let _ = sender.send(GlobalInstallEvent::Finished {
                    index,
                    result: Ok(fake_installation(&name)),
                });
            })
        },
        |_| {},
    );
    let Err(error) = outcome else {
        panic!("worker panic must reach the coordinator");
    };
    assert_eq!(error.code, "NEO702");
}

#[test]
fn supervisor_does_not_wait_forever_when_a_finished_event_is_lost() {
    let tools = vec![fake_request("dotnet")];
    let results = supervise_global_installs(
        &tools,
        &AtomicBool::new(false),
        |_index, _tool, sender| thread::spawn(move || drop(sender)),
        |_| {},
    )
    .unwrap();
    let error = results.into_iter().next().unwrap().unwrap_err();
    assert_eq!(error.code, "NEO701");
    assert!(error.message.contains("dotnet@1.0.0"));
}

#[test]
fn supervise_does_not_misclassify_immediate_finished_sends() {
    const RUNS: usize = 200;

    for _ in 0..RUNS {
        let tools = vec![fake_request("dotnet")];
        let results = supervise_global_installs(
            &tools,
            &AtomicBool::new(false),
            |index, tool, sender| {
                let name = tool.tool.clone();
                thread::spawn(move || {
                    let _ = sender.send(GlobalInstallEvent::Finished {
                        index,
                        result: Ok(fake_installation(&name)),
                    });
                })
            },
            |_| {},
        )
        .unwrap();
        assert!(results.into_iter().all(|result| result.is_ok()));
    }
}

#[test]
fn supervisor_keeps_request_order_when_completion_order_differs() {
    let tools = vec![fake_request("dotnet"), fake_request("node")];
    let results = supervise_global_installs(
        &tools,
        &AtomicBool::new(false),
        |index, tool, sender| {
            let name = tool.tool.clone();
            thread::spawn(move || {
                if index == 0 {
                    thread::sleep(Duration::from_millis(20));
                }
                let _ = sender.send(GlobalInstallEvent::Finished {
                    index,
                    result: Ok(fake_installation(&name)),
                });
            })
        },
        |_| {},
    )
    .unwrap();
    let names = results
        .into_iter()
        .map(|result| result.unwrap().tool)
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["dotnet", "node"]);
}

#[test]
fn supervisor_reports_one_failed_install_without_losing_other_results() {
    let tools = vec![
        fake_request("dotnet"),
        fake_request("node"),
        fake_request("go"),
    ];
    let results = supervise_global_installs(
        &tools,
        &AtomicBool::new(false),
        |index, tool, sender| {
            let name = tool.tool.clone();
            thread::spawn(move || {
                let result = if index == 1 {
                    Err(neoenv_core::Diagnostic::new(
                        neoenv_core::DiagnosticCategory::Runtime,
                        "NEO999",
                        "injected provider failure",
                    ))
                } else {
                    Ok(fake_installation(&name))
                };
                let _ = sender.send(GlobalInstallEvent::Finished { index, result });
            })
        },
        |_| {},
    )
    .unwrap();
    assert!(results[0].is_ok());
    assert_eq!(results[1].as_ref().unwrap_err().code, "NEO999");
    assert!(results[2].is_ok());
}

#[test]
fn supervisor_never_exceeds_ten_active_installers() {
    let tools = (0..23)
        .map(|index| fake_request(&format!("tool-{index}")))
        .collect::<Vec<_>>();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let results = supervise_global_installs(
        &tools,
        &AtomicBool::new(false),
        |index, tool, sender| {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let name = tool.tool.clone();
            thread::spawn(move || {
                let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                maximum.fetch_max(now, Ordering::AcqRel);
                thread::sleep(Duration::from_millis(2));
                active.fetch_sub(1, Ordering::AcqRel);
                let _ = sender.send(GlobalInstallEvent::Finished {
                    index,
                    result: Ok(fake_installation(&name)),
                });
            })
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(results.len(), tools.len());
    assert!(maximum.load(Ordering::Acquire) <= 10);
}

#[test]
fn cancellation_stops_scheduling_and_joins_active_workers() {
    let cancellation = Arc::new(AtomicBool::new(false));
    let tools = vec![fake_request("dotnet")];
    let (started_sender, started_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let worker_cancellation = Arc::clone(&cancellation);
    let mut release_receiver = Some(release_receiver);
    let supervisor = thread::spawn(move || {
        supervise_global_installs(
            &tools,
            worker_cancellation.as_ref(),
            move |index, tool, sender| {
                let release_receiver = release_receiver
                    .take()
                    .expect("the cancellation fixture starts one worker");
                let name = tool.tool.clone();
                let started_sender = started_sender.clone();
                thread::spawn(move || {
                    let _ = started_sender.send(());
                    let _ = release_receiver.recv();
                    let _ = sender.send(GlobalInstallEvent::Finished {
                        index,
                        result: Ok(fake_installation(&name)),
                    });
                })
            },
            |_| {},
        )
    });

    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    cancellation.store(true, Ordering::Release);
    release_sender.send(()).unwrap();
    let Err(error) = supervisor.join().unwrap() else {
        panic!("cancelled installation must fail");
    };
    assert_eq!(error.code, "NEO330");
}

#[test]
fn concurrent_supervisor_invocations_are_independent_and_complete() {
    let cancellation = Arc::new(AtomicBool::new(false));
    let mut supervisors = Vec::new();
    for _ in 0..2 {
        let cancellation = Arc::clone(&cancellation);
        supervisors.push(thread::spawn(move || {
            let tools = vec![fake_request("dotnet"), fake_request("node")];
            supervise_global_installs(
                &tools,
                cancellation.as_ref(),
                |index, tool, sender| {
                    let name = tool.tool.clone();
                    thread::spawn(move || {
                        let _ = sender.send(GlobalInstallEvent::Finished {
                            index,
                            result: Ok(fake_installation(&name)),
                        });
                    })
                },
                |_| {},
            )
        }));
    }
    for supervisor in supervisors {
        assert!(supervisor.join().unwrap().is_ok());
    }
}

#[test]
fn concurrent_global_configuration_updates_preserve_unrelated_keys() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("neoenv.toml");
    fs::write(
        &path,
        "format_version = 1\n[global]\n[global.tools]\nnode = \"old\"\n",
    )
    .unwrap();
    let cancellation = Arc::new(AtomicBool::new(false));
    let mut writers = Vec::new();
    for tool in ["dotnet", "go"] {
        let path = path.clone();
        let installation = fake_installation(tool);
        let worker_cancellation = Arc::clone(&cancellation);
        writers.push(thread::spawn(move || {
            record_global_tools_at(&path, &[installation], worker_cancellation.as_ref()).unwrap();
        }));
    }
    for writer in writers {
        writer.join().unwrap();
    }
    let document = toml::from_str::<toml::Value>(&fs::read_to_string(&path).unwrap()).unwrap();
    let tools = document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("tools"))
        .and_then(toml::Value::as_table)
        .unwrap();
    assert_eq!(tools.get("node").and_then(toml::Value::as_str), Some("old"));
    assert_eq!(
        tools.get("dotnet").and_then(toml::Value::as_str),
        Some("1.0.0")
    );
    assert_eq!(tools.get("go").and_then(toml::Value::as_str), Some("1.0.0"));
}

#[test]
fn cancelled_batch_does_not_publish_global_configuration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("neoenv.toml");
    fs::write(
        &path,
        "format_version = 1\n[global]\n[global.tools]\nnode = \"old\"\n",
    )
    .unwrap();
    let cancellation = AtomicBool::new(true);
    let error =
        record_global_tools_at(&path, &[fake_installation("dotnet")], &cancellation).unwrap_err();
    assert_eq!(error.code, "NEO330");
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("node = \"old\"")
    );
    assert!(!fs::read_to_string(&path).unwrap().contains("dotnet ="));
}

#[test]
fn ctrl_c_handler_is_installed_once_and_shared_by_global_installers() {
    let first = global_install_cancellation().unwrap();
    let second = global_install_cancellation().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn atomic_write_replaces_regular_file_without_leaving_temporary_state() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("neoenv.toml");
    fs::write(&path, "old\n").unwrap();

    state_file::write_atomic(&path, b"new\n").unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn atomic_write_refuses_a_symlink_target() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let target = directory.path().join("outside.toml");
    let path = directory.path().join("neoenv.toml");
    fs::write(&target, "keep\n").unwrap();
    symlink(&target, &path).unwrap();

    let error = state_file::write_atomic(&path, b"replace\n")
        .map_err(|error| state_file_diagnostic(&path, error))
        .unwrap_err();

    assert_eq!(error.code, "NEO522");
    assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
}
