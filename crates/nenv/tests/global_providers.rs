use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::{os::unix::fs::PermissionsExt, process::Stdio};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

mod support;

/// Global tool operations read global state, not project configuration, so they
/// take a plain `Command`. Several of them assert that the config home was not
/// created; an approval write would be exactly that write.
fn global_command(root: &Path, config_home: &Path, data_home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    command
        .current_dir(root)
        .env("NEOENV_CONFIG_HOME", config_home)
        .env("NEOENV_DATA_HOME", data_home)
        .env_remove("MISE_GLOBAL_CONFIG_FILE")
        .env_remove("MISE_DATA_DIR");
    command
}

fn assert_empty(path: &Path) {
    assert!(
        !path.exists(),
        "dry-run unexpectedly created {}",
        path.display()
    );
}

#[test]
fn scope_flags_select_user_and_system_roots() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_data = directory.path().join("system-install");
    let base = || {
        let mut invocation = global_command(directory.path(), &user_config, &user_data);
        invocation
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_data);
        invocation
    };

    let user = base()
        .args(["use", "--user", "--dry-run", "java@21"])
        .output()
        .unwrap();
    assert!(user.status.success(), "{user:?}");
    let user_text = String::from_utf8(user.stdout).unwrap();
    assert!(
        user_text.contains(&user_data.join("neoenv/tools/java").display().to_string()),
        "{user_text}"
    );

    let system = base()
        .args(["use", "--global", "--dry-run", "java@21"])
        .output()
        .unwrap();
    assert!(system.status.success(), "{system:?}");
    let system_text = String::from_utf8(system.stdout).unwrap();
    assert!(
        system_text.contains(&system_data.join("tools/java").display().to_string()),
        "{system_text}"
    );

    let short = base()
        .args(["use", "-g", "--dry-run", "java@21"])
        .output()
        .unwrap();
    assert!(short.status.success(), "{short:?}");
    assert!(
        String::from_utf8(short.stdout)
            .unwrap()
            .contains(&system_data.join("tools/java").display().to_string())
    );
    assert!(!system_config.exists() && !system_data.exists());
}

#[cfg(unix)]
#[test]
fn system_scope_rejects_traversal_symlink_ancestors_and_managed_links() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let real = directory.path().join("real");
    fs::create_dir_all(&real).unwrap();

    let install = |value: &Path| {
        global_command(directory.path(), &user_config, &user_data)
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", value)
            .args(["use", "--global", "--dry-run", "java@21"])
            .output()
            .unwrap()
    };

    let traversal = directory.path().join("..").join("etc");
    let output = install(&traversal);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("contains `..`")
    );

    let linked = directory.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let output = install(&linked.join("neoenv"));
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("symlinked ancestor")
    );

    for managed in ["tools", "locks", "artifacts"] {
        let root = directory.path().join(format!("managed-{managed}"));
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&real, root.join(managed)).unwrap();
        let output = install(&root);
        assert!(!output.status.success(), "{managed}: {output:?}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("managed directory"),
            "{managed} was not refused"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_system_scope_requires_an_absolute_override() {
    let directory = TempDir::new().unwrap();
    let output = global_command(
        directory.path(),
        &directory.path().join("user-config"),
        &directory.path().join("user-data"),
    )
    .env("NEOENV_GLOBAL_CONFIG_DIR", "relative-config")
    .env("NEOENV_GLOBAL_INSTALL_DIR", "relative-install")
    .args(["use", "--global", "--dry-run", "java@21"])
    .output()
    .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("is not absolute")
    );
}

#[test]
fn system_scope_mutation_fails_closed_without_writing() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    let fixture = GithubFixture::start();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .env("NEOENV_GITHUB_API_URL", fixture.api_url())
        .args(["use", "--global", "gh:owner/repo@1.2.3"])
        .output()
        .unwrap();
    let requests = fixture.stop();
    assert!(!output.status.success(), "{output:?}");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("system-scope mutation is disabled"),
        "{error}"
    );
    assert_eq!(
        requests, 0,
        "a refused system mutation must not touch the network"
    );
    assert!(!system_config.exists() && !system_install.exists());
}

fn provider_lock(
    id: &str,
    version: &str,
    sha: &str,
    binary: &str,
    url: &str,
    immutable: &str,
) -> String {
    format!(
        "schema_version = 6\n[[tools]]\nid = \"{id}\"\nresolved_version = \"{version}\"\nurl = \"{url}\"\nplatform = {{ os = \"linux\", arch = \"x86_64\" }}\nsha256 = \"{sha}\"\nbinaries = [\"{binary}\"]\nresolver = \"github-release\"\ndeclaration_source = {{ path = \"global:{id}\", line = 1, column = 1 }}\nverification = {{ sha256 = \"{sha}\" }}\n[tools.provenance]\nprovider = \"github-release\"\nimmutable_id = \"{immutable}\"\nrepository = \"user/name\"\nrelease_id = 1\nasset_id = 1\nauthentication = \"prohibited\"\n"
    )
}

fn provider_config(
    key: &str,
    lock: &Path,
    version: &str,
    sha: &str,
    binary: &str,
    url: &str,
    immutable: &str,
) -> String {
    format!(
        "[global.providers.\"{key}\"]\nversion = \"{version}\"\nresolved_version = \"{version}\"\nsha256 = \"{sha}\"\ndigest = \"{sha}\"\nsource = \"{url}\"\nresolver = \"github-release\"\nimmutable_id = \"{immutable}\"\nlock_path = \"{}\"\nbinaries = [\"{binary}\"]\n",
        lock.display()
    )
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn cargo_provider_selects_only_its_binary_and_allows_an_unrelated_provider() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();

    let sha = "a".repeat(64);
    let cargo_lock_path = user_data.join("neoenv/locks/cargo.neoenv.lock");
    let cargo_url = "https://static.crates.io/crates/ripgrep/ripgrep-14.1.1.crate";
    let cargo_lock = format!(
        "schema_version = 6\n[[tools]]\nid = \"cargo-ripgrep\"\nresolved_version = \"14.1.1\"\nurl = \"{cargo_url}\"\nplatform = {{ os = \"linux\", arch = \"x86_64\" }}\nsha256 = \"{sha}\"\nbinaries = [\"rg\"]\nresolver = \"cargo\"\ncargo_toolchain = \"1.85.0-x86_64-unknown-linux-gnu\"\ndeclaration_source = {{ path = \"global:cargo-ripgrep\", line = 1, column = 1 }}\nverification = {{ sha256 = \"{sha}\" }}\n[tools.provenance]\nprovider = \"cargo\"\nimmutable_id = \"{cargo_url}\"\nregistry_endpoint = \"https://index.crates.io/\"\npackage = \"ripgrep\"\nauthentication = \"prohibited\"\n[cargo_build]\ntool_id = \"cargo-ripgrep\"\ncrate_name = \"ripgrep\"\nversion = \"14.1.1\"\nregistry = \"https://index.crates.io/\"\nchecksum = \"{sha}\"\ntoolchain = \"1.85.0-x86_64-unknown-linux-gnu\"\nscripts = \"deny\"\nbuild = \"isolated\"\nnetwork = \"deny\"\n"
    );
    fs::write(&cargo_lock_path, cargo_lock).unwrap();

    let unrelated_lock_path = user_data.join("neoenv/locks/unrelated.neoenv.lock");
    fs::write(
        &unrelated_lock_path,
        provider_lock(
            "gh:user/unrelated",
            "1.0.0",
            &sha,
            "unrelated-bin",
            "https://example.test/unrelated",
            "unrelated-immutable",
        ),
    )
    .unwrap();
    let unrelated_config = provider_config(
        "gh:user/unrelated",
        &unrelated_lock_path,
        "1.0.0",
        &sha,
        "unrelated-bin",
        "https://example.test/unrelated",
        "unrelated-immutable",
    );
    let cargo_config = format!(
        "[global.providers.\"cargo-ripgrep\"]\nversion = \"14.1.1\"\nresolved_version = \"14.1.1\"\nsha256 = \"{sha}\"\ndigest = \"{sha}\"\nsource = \"{cargo_url}\"\nresolver = \"cargo\"\nimmutable_id = \"{cargo_url}\"\nlock_path = \"{}\"\nbinaries = [\"rg\"]\n",
        cargo_lock_path.display()
    );
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!("{cargo_config}\n{unrelated_config}"),
    )
    .unwrap();
    let unrelated_executable = user_data
        .join("neoenv/tools")
        .join(&sha)
        .join("bin/unrelated-bin");
    fs::create_dir_all(unrelated_executable.parent().unwrap()).unwrap();
    fs::write(&unrelated_executable, b"fixture executable").unwrap();
    let mut permissions = fs::metadata(&unrelated_executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&unrelated_executable, permissions).unwrap();
    fs::write(
        unrelated_executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".neoenv-artifact-sha256"),
        format!("{sha}\n"),
    )
    .unwrap();

    let run = |binary: &str| {
        global_command(directory.path(), &user_config, &user_data)
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
            .args(["tool", "which", binary, "--user"])
            .output()
            .unwrap()
    };
    let unrelated = run("unrelated-bin");
    assert!(unrelated.status.success(), "{unrelated:?}");
    assert!(
        String::from_utf8_lossy(&unrelated.stdout)
            .contains(&unrelated_executable.display().to_string()),
        "{unrelated:?}"
    );
    let selected_cargo = run("rg");
    assert!(!selected_cargo.status.success(), "{selected_cargo:?}");
    assert!(
        String::from_utf8_lossy(&selected_cargo.stderr).contains("selected global provider"),
        "{selected_cargo:?}"
    );
    let cargo_lock = neoenv_installer::tools::read_lockfile(&cargo_lock_path).unwrap();
    let cargo_tool = &cargo_lock.tools[0];
    let cargo_build = cargo_lock.cargo_build.as_ref().unwrap();
    let cargo_key = neoenv_installer::tools::install_key(cargo_tool).unwrap();
    let cargo_install = user_data.join("neoenv/tools").join(cargo_key);
    let cargo_bin = cargo_install.join("bin/rg");
    fs::create_dir_all(cargo_bin.parent().unwrap()).unwrap();
    fs::write(
        &cargo_bin,
        b"#!/bin/sh\nif [ \"$#\" -eq 0 ]; then exit 0; fi\necho cargo-global-ok\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&cargo_bin).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&cargo_bin, permissions).unwrap();
    fs::write(
        cargo_install.join(".neoenv-artifact-sha256"),
        format!("{}\n", cargo_tool.sha256),
    )
    .unwrap();
    let cargo_identity =
        neoenv_installer::tools::cargo_install_identity(cargo_tool, cargo_build).unwrap();
    fs::write(
        cargo_install.join(neoenv_installer::tools::CARGO_BUILD_RECEIPT),
        format!("{cargo_identity}\n"),
    )
    .unwrap();
    let selected_cargo = run("rg");
    assert!(selected_cargo.status.success(), "{selected_cargo:?}");
    assert!(
        String::from_utf8_lossy(&selected_cargo.stdout).contains(&cargo_bin.display().to_string()),
        "{selected_cargo:?}"
    );
    fs::write(directory.path().join("neoenv.yaml"), "format_version: 1\n").unwrap();
    support::approve(&user_config, &directory.path().join("neoenv.yaml"));
    let executed = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["exec", "--", "rg", "pattern"])
        .output()
        .unwrap();
    assert!(executed.status.success(), "{executed:?}");
    assert!(String::from_utf8_lossy(&executed.stdout).contains("cargo-global-ok"));

    // A selected but corrupted unrelated record must fail closed rather than
    // allow resolution from another scope or PATH.
    let damaged_config = unrelated_config.replace(
        &format!("sha256 = \"{sha}\""),
        &format!("sha256 = \"{}\"", "b".repeat(64)),
    );
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!("{cargo_config}\n{damaged_config}"),
    )
    .unwrap();
    let damaged = run("unrelated-bin");
    assert!(!damaged.status.success(), "{damaged:?}");
    assert!(
        String::from_utf8_lossy(&damaged.stderr).contains("mismatched `sha256`"),
        "{damaged:?}"
    );
    assert!(
        !String::from_utf8_lossy(&damaged.stdout)
            .contains(&unrelated_executable.display().to_string()),
        "{damaged:?}"
    );
}

#[test]
fn unrelated_valid_provider_does_not_block_a_working_runtime() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/other.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/other",
            "1.0.0",
            &sha,
            "other",
            "https://example.test/other",
            "other-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        provider_config(
            "gh:user/other",
            &lock,
            "1.0.0",
            &sha,
            "other",
            "https://example.test/other",
            "other-immutable",
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let path = String::from_utf8(output.stdout).unwrap();
    assert!(path.contains("1.22.0"), "{path}");
    assert!(
        path.contains(&system_install.display().to_string()),
        "the working system runtime must be the selected one: {path}"
    );
}

#[test]
fn unrelated_inaccessible_provider_lock_fails_closed() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        "[global.providers.\"gh:user/other\"]\nbinaries = [\"other\"]\nlock_path = \"outside-the-lock-directory\"\n",
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("lock path is outside"),
        "an inaccessible unrelated lock must fail closed under the documented policy"
    );
}
#[test]
fn present_non_string_provider_fields_are_named_and_fail_closed() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/selected.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/selected",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    let baseline = provider_config(
        "gh:user/selected",
        &lock,
        "1.0.0",
        &sha,
        "go",
        "https://example.test/selected",
        "selected-immutable",
    );
    for field in [
        "version",
        "resolved_version",
        "sha256",
        "digest",
        "immutable_id",
        "resolver",
        "source",
    ] {
        let prefix = format!("{field} = ");
        let old = baseline
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{field} missing from fixture"));
        let config = baseline.replace(old, &format!("{field} = 1"));
        fs::write(user_config.join("neoenv/neoenv.toml"), config).unwrap();
        let output = global_command(directory.path(), &user_config, &user_data)
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
            .args(["tool", "which", "go"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{field}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains(&format!("`{field}` must be a string")),
            "{field}: {error}"
        );
        assert!(
            !error.contains("1.22.0"),
            "{field} fell back to the system runtime: {error}"
        );
    }
}

#[test]
fn stale_recorded_binaries_are_detected_before_fallback() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/stale.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/selected",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        provider_config(
            "gh:user/selected",
            &lock,
            "1.0.0",
            &sha,
            "other",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("mismatched `binaries`"), "{error}");
    assert!(
        !error.contains("1.22.0"),
        "a stale user record must not fall back to system: {error}"
    );
}

#[test]
fn cross_provider_lock_entry_is_rejected() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/cross.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/other",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/other",
            "other-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        provider_config(
            "gh:user/selected",
            &lock,
            "1.0.0",
            &sha,
            "go",
            "https://example.test/other",
            "other-immutable",
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no entry for this provider's recorded key")
    );
}

#[test]
fn multiple_records_claiming_the_same_binary_are_ambiguous() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    let sha = "a".repeat(64);
    let first_lock = user_data.join("neoenv/locks/first.neoenv.lock");
    let second_lock = user_data.join("neoenv/locks/second.neoenv.lock");
    fs::write(
        &first_lock,
        provider_lock(
            "gh:user/first",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/first",
            "first-immutable",
        ),
    )
    .unwrap();
    fs::write(
        &second_lock,
        provider_lock(
            "gh:user/second",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/second",
            "second-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!(
            "{}{}",
            provider_config(
                "gh:user/first",
                &first_lock,
                "1.0.0",
                &sha,
                "go",
                "https://example.test/first",
                "first-immutable",
            ),
            provider_config(
                "gh:user/second",
                &second_lock,
                "1.0.0",
                &sha,
                "go",
                "https://example.test/second",
                "second-immutable",
            )
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("multiple global provider records claim `go`")
    );
}
#[test]
fn inaccessible_record_cannot_be_bypassed_by_a_claiming_record() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    let sha = "a".repeat(64);
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!(
            "[global.providers.\"gh:user/unknown\"]\nlock_path = \"unknown\"\n{}",
            provider_config(
                "gh:user/selected",
                &user_data.join("neoenv/locks/selected.neoenv.lock"),
                "1.0.0",
                &sha,
                "go",
                "https://example.test/selected",
                "selected-immutable",
            )
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("lock path is outside"),
        "an inaccessible record must be repaired before another candidate is selected"
    );
}
#[test]
fn provider_record_digest_mismatch_is_rejected() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    let lock_sha = "a".repeat(64);
    let record_sha = "b".repeat(64);
    let lock = user_data.join("neoenv/locks/mismatch.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/selected",
            "1.0.0",
            &lock_sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        provider_config(
            "gh:user/selected",
            &lock,
            "1.0.0",
            &record_sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("mismatched `sha256`")
    );
}

#[test]
fn selected_provider_with_missing_executable_does_not_fall_back() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/selected.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/selected",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        provider_config(
            "gh:user/selected",
            &lock,
            "1.0.0",
            &sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("installed executable is missing or unusable"),
        "selected provider miss must not fall back to system"
    );
}

#[test]
fn missing_binaries_recover_ownership_from_a_valid_unrelated_lock() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/other.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/other",
            "1.0.0",
            &sha,
            "other",
            "https://example.test/other",
            "other-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!(
            "[global.providers.\"gh:user/other\"]\nlock_path = \"{}\"\n",
            lock.display()
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout).unwrap().contains("1.22.0"));
}

#[test]
fn missing_binaries_recover_a_claiming_selected_provider() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(user_data.join("neoenv/locks")).unwrap();
    let sha = "a".repeat(64);
    let lock = user_data.join("neoenv/locks/selected.neoenv.lock");
    fs::write(
        &lock,
        provider_lock(
            "gh:user/selected",
            "1.0.0",
            &sha,
            "go",
            "https://example.test/selected",
            "selected-immutable",
        ),
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        format!(
            "[global.providers.\"gh:user/selected\"]\nlock_path = \"{}\"\n",
            lock.display()
        ),
    )
    .unwrap();
    let output = global_command(directory.path(), &user_config, &user_data)
        .args(["tool", "which", "go"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("installed executable is missing or unusable")
    );
}
#[test]
fn corrupt_user_provider_state_does_not_fall_back_to_system() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(system_install.join("tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        system_install.join("tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        "[global.providers.\"gh:user/bad\"]\nlock_path = \"outside-the-lock-directory\"\n",
    )
    .unwrap();

    let run = || {
        global_command(directory.path(), &user_config, &user_data)
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
            .args(["tool", "which", "go"])
            .output()
            .unwrap()
    };
    let output = run();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("selected global provider"),
        "the corrupt user selection must propagate"
    );

    fs::write(user_config.join("neoenv/neoenv.toml"), "[global.tools]\n").unwrap();
    let output = run();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout).unwrap().contains("1.22.0"));
}

#[test]
fn invalid_config_file_types_are_errors_not_absence() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(&system_config).unwrap();
    fs::create_dir_all(user_config.join("neoenv")).unwrap();

    let run = |scope: &str| {
        global_command(
            directory.path(),
            &user_config,
            &directory.path().join("user-data"),
        )
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "list", scope])
        .output()
        .unwrap()
    };

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            directory.path().join("missing-system.toml"),
            system_config.join("neoenv.toml"),
        )
        .unwrap();
        let output = run("--global");
        assert!(!output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("not a regular file")
        );
        fs::remove_file(system_config.join("neoenv.toml")).unwrap();
    }
    fs::create_dir(system_config.join("neoenv.toml")).unwrap();
    let output = run("--global");
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("not a regular file")
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            directory.path().join("missing-user.toml"),
            user_config.join("neoenv/neoenv.toml"),
        )
        .unwrap();
        let output = global_command(
            directory.path(),
            &user_config,
            &directory.path().join("user-data"),
        )
        .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
        .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
        .args(["tool", "which", "--user", "go"])
        .output()
        .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("not a regular file")
        );
    }
}

#[test]
fn tool_list_which_and_cleanup_honor_scope_without_cross_writes() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    let user_data = directory.path().join("user-data");
    let system_config = directory.path().join("system-config");
    let system_install = directory.path().join("system-install");
    fs::create_dir_all(&system_config).unwrap();
    fs::write(
        system_config.join("neoenv.toml"),
        "[global.tools]\ndemo = \"1.0.0\"\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        global_command(directory.path(), &user_config, &user_data)
            .env("NEOENV_GLOBAL_CONFIG_DIR", &system_config)
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
            .args(args)
            .output()
            .unwrap()
    };

    let listed = run(&["tool", "list", "--global"]);
    assert!(listed.status.success(), "{listed:?}");
    assert!(
        String::from_utf8(listed.stdout)
            .unwrap()
            .contains("configured\tdemo\t1.0.0")
    );
    let listed_json = run(&["tool", "list", "--global", "--format", "json"]);
    assert!(listed_json.status.success(), "{listed_json:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&listed_json.stdout).expect("global list JSON");
    assert_eq!(document["contract"], "global-tool-config");
    assert_eq!(document["scope"], "system");
    assert_eq!(document["installed_state_included"], false);
    assert_eq!(document["configured_tools"][0]["id"], "demo");
    assert_eq!(
        document["configured_tools"][0]["configured_version"],
        "1.0.0"
    );

    let cleanup = run(&["tool", "cleanup", "--global"]);
    assert!(!cleanup.status.success(), "{cleanup:?}");
    assert!(
        String::from_utf8(cleanup.stderr)
            .unwrap()
            .contains("system-scope mutation is disabled")
    );

    // A user-selected `go` is resolvable only in the user scope.
    fs::create_dir_all(user_data.join("neoenv/tools/go/1.22.0/go/bin")).unwrap();
    fs::write(
        user_data.join("neoenv/tools/go/1.22.0/go/bin/go"),
        b"#!/bin/sh\n",
    )
    .unwrap();
    fs::create_dir_all(user_config.join("neoenv")).unwrap();
    fs::write(
        user_config.join("neoenv/neoenv.toml"),
        "[global.tools]\ngo = \"1.22.0\"\n",
    )
    .unwrap();
    let user = run(&["tool", "which", "--user", "go"]);
    assert!(user.status.success(), "{user:?}");
    assert!(String::from_utf8(user.stdout).unwrap().contains("1.22.0"));
    let system = run(&["tool", "which", "--global", "go"]);
    assert!(!system.status.success(), "{system:?}");
    let cleanup_user = run(&["tool", "cleanup", "--user", "--dry-run"]);
    assert!(cleanup_user.status.success(), "{cleanup_user:?}");
}

#[test]
fn invalid_user_layout_is_reported_instead_of_falling_back_to_system() {
    let directory = TempDir::new().unwrap();
    let user_config = directory.path().join("user-config");
    fs::write(&user_config, b"not a directory").unwrap();
    let system_install = directory.path().join("system-install");
    let output = global_command(
        directory.path(),
        &user_config,
        &directory.path().join("user-data"),
    )
    .env(
        "NEOENV_GLOBAL_CONFIG_DIR",
        directory.path().join("system-config"),
    )
    .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install)
    .args(["tool", "which", "--user", "go"])
    .output()
    .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("user-config"), "{error}");
    assert!(!error.contains("system"), "{error}");
}

#[test]
fn runtime_list_and_where_expose_the_scope_activation_uses() {
    let directory = TempDir::new().unwrap();
    let user_data = directory.path().join("user-data");
    let system_install = directory.path().join("system-install");
    let write = |root: &Path, version: &str| {
        let install = root.join("tools").join("go").join(version);
        fs::create_dir_all(install.join("go/bin")).unwrap();
        fs::write(
            install.join("go/bin/go"),
            b"#!/bin/sh
",
        )
        .unwrap();
        fs::write(
            install.join(".neoenv-go-sdk-sha256"),
            format!("{}\n", "a".repeat(64)),
        )
        .unwrap();
    };
    write(&user_data.join("neoenv"), "1.21.0");
    write(&system_install, "1.22.0");
    let env = |command: &mut Command| {
        command
            .env("NEOENV_CONFIG_HOME", directory.path().join("user-config"))
            .env("NEOENV_DATA_HOME", &user_data)
            .env(
                "NEOENV_GLOBAL_CONFIG_DIR",
                directory.path().join("system-config"),
            )
            .env("NEOENV_GLOBAL_INSTALL_DIR", &system_install);
    };

    let mut list = Command::new(env!("CARGO_BIN_EXE_nenv"));
    env(&mut list);
    let output = list.args(["runtime", "list"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("system\tgo\t1.22.0"), "{text}");
    assert!(text.contains("user\tgo\t1.21.0"), "{text}");

    let mut where_command = Command::new(env!("CARGO_BIN_EXE_nenv"));
    env(&mut where_command);
    let output = where_command
        .args(["runtime", "where", "go"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("scope\tuser"), "{text}");
    assert!(text.contains("1.21.0"), "{text}");
}

#[test]
fn global_dry_run_covers_native_github_and_package_keys_without_io() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let output = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", "http://127.0.0.1:9")
        .args([
            "use",
            "--global",
            "--dry-run",
            "node@22.0.0",
            "java@21",
            "bun@1.4.4",
            "gh:owner/repo@1.2.3",
            "npm:@scope/demo@1.2.3",
            "dotnet:demo@1.2.3",
            "gem:demo@1.2.3",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    for key in [
        "node@22.0.0",
        "java@21",
        "bun@1.4.4",
        "gh:owner/repo@1.2.3",
        "npm:@scope/demo@1.2.3",
        "dotnet:demo@1.2.3",
        "gem:demo@1.2.3",
    ] {
        assert!(text.contains(key), "missing {key} in {text}");
    }
    assert_empty(&config_home);
    assert_empty(&data_home);
}

struct GithubFixture {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    maximum_active: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    artifact_digest: String,
}

fn request_headers(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut request = [0_u8; 4096];
    let mut size = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    // A TCP read is not an HTTP request. Consume the headers before routing or
    // closing, including fragmented writes, without allowing unbounded input.
    while size < request.len() && !request[..size].windows(4).any(|end| end == b"\r\n\r\n") {
        if Instant::now() >= deadline {
            return None;
        }
        match stream.read(&mut request[size..]) {
            Ok(0) => return None,
            Ok(read) => size += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return None,
        }
    }
    request[..size]
        .windows(4)
        .any(|end| end == b"\r\n\r\n")
        .then(|| request[..size].to_vec())
}

impl GithubFixture {
    fn start() -> Self {
        Self::start_with_delay(Duration::ZERO)
    }

    fn start_with_delay(delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let artifact = b"#!/bin/sh\nprintf global-provider\n".to_vec();
        let artifact_digest = format!("{:x}", Sha256::digest(&artifact));
        // Deliberately avoid the old `{repo}-{os}-{arch}` template: global
        // resolution must inspect the release metadata and select this asset.
        let asset_name = format!(
            "payload-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let server_requests = Arc::clone(&requests);
        let server_active = Arc::clone(&active);
        let server_maximum_active = Arc::clone(&maximum_active);
        let server_stop = Arc::clone(&stop);
        let server_address = address;
        let server_artifact_digest = artifact_digest.clone();
        let server_delay = delay;
        let thread = thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        server_requests.fetch_add(1, Ordering::Relaxed);
                        if stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .is_err()
                            || stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .is_err()
                        {
                            continue;
                        }
                        let Some(request) = request_headers(&mut stream) else {
                            continue;
                        };
                        let request = String::from_utf8_lossy(&request);
                        let path = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let body = if path.starts_with("/repos/") {
                            let repository = path
                                .strip_prefix("/repos/")
                                .and_then(|value| value.split('/').nth(1))
                                .unwrap_or("repo");
                            let artifact_url =
                                format!("http://{server_address}/artifact/{repository}");
                            let checksum_url =
                                format!("http://{server_address}/checksums/{repository}");
                            format!(
                                "{{\"id\":42,\"tag_name\":\"1.2.3\",\"assets\":[{{\"id\":7,\"name\":\"{asset_name}\",\"browser_download_url\":\"{artifact_url}\"}},{{\"id\":8,\"name\":\"checksums.txt\",\"browser_download_url\":\"{checksum_url}\"}}]}}"
                            )
                            .into_bytes()
                        } else if path.starts_with("/checksums/") {
                            format!("{server_artifact_digest}  {asset_name}\n").into_bytes()
                        } else if path.starts_with("/artifact/") {
                            artifact.clone()
                        } else {
                            b"not found".to_vec()
                        };
                        if path.starts_with("/artifact/") {
                            let now = server_active.fetch_add(1, Ordering::AcqRel) + 1;
                            server_maximum_active.fetch_max(now, Ordering::AcqRel);
                            if !server_delay.is_zero() {
                                thread::sleep(server_delay);
                            }
                            server_active.fetch_sub(1, Ordering::AcqRel);
                        }
                        let status = if path.starts_with("/artifact/")
                            || path.starts_with("/checksums/")
                            || path.starts_with("/repos/")
                        {
                            "200 OK"
                        } else {
                            "404 Not Found"
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(&body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            maximum_active,
            stop,
            thread: Some(thread),
            artifact_digest,
        }
    }

    fn api_url(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn maximum_active(&self) -> usize {
        self.maximum_active.load(Ordering::Acquire)
    }

    fn stop(mut self) -> usize {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        self.requests.load(Ordering::Acquire)
    }
}

fn global_config_path(config_home: &Path) -> PathBuf {
    config_home.join("neoenv/neoenv.toml")
}

// Private fixture protocol branching: TCP may split a request across reads.
#[test]
fn github_fixture_waits_for_complete_request_headers() {
    let fixture = GithubFixture::start();
    let mut stream = std::net::TcpStream::connect(fixture.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    stream.write_all(b"GET /rep").unwrap();
    let error = stream.read(&mut [0_u8; 1]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    stream
        .write_all(b"os/owner/repo/releases/tags/1.2.3 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    fixture.stop();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let host_asset = format!(
        "payload-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    assert!(response.contains(&host_asset), "{response}");
}

#[test]
fn github_global_install_selects_metadata_asset_and_repeats_offline() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = GithubFixture::start();
    let artifact_digest = fixture.artifact_digest.clone();
    let first = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.api_url())
        .args(["use", "--user", "gh:owner/repo@1.2.3"])
        .output()
        .unwrap();
    let request_count = fixture.stop();
    assert!(first.status.success(), "{first:?}");
    assert!(request_count >= 3, "fixture requests: {request_count}");
    let first_text = String::from_utf8(first.stdout).unwrap();
    assert!(first_text.contains("installed gh:owner/repo@1.2.3"));

    let config_path = global_config_path(&config_home);
    let config_text = fs::read_to_string(&config_path).unwrap();
    let config: toml::Value = toml::from_str(&config_text).unwrap();
    let provider = config
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("providers"))
        .and_then(toml::Value::as_table)
        .and_then(|providers| providers.get("gh:owner/repo"))
        .and_then(toml::Value::as_table)
        .unwrap();
    assert_eq!(
        provider
            .get("resolved_version")
            .and_then(toml::Value::as_str),
        Some("1.2.3")
    );
    assert_eq!(
        provider.get("sha256").and_then(toml::Value::as_str),
        Some(artifact_digest.as_str())
    );
    assert!(
        provider
            .get("source")
            .and_then(toml::Value::as_str)
            .is_some_and(|source| source.contains("artifact"))
    );
    assert!(
        provider
            .get("install_path")
            .and_then(toml::Value::as_str)
            .is_some_and(|path| { path.replace('\\', "/").contains("/tools/") })
    );
    assert!(!data_home.join("neoenv/.neoenv").exists());

    let second = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", "http://127.0.0.1:9")
        .args(["use", "--user", "gh:owner/repo@1.2.3"])
        .output()
        .unwrap();
    assert!(second.status.success(), "{second:?}");
    assert!(
        String::from_utf8(second.stdout)
            .unwrap()
            .contains("already installed gh:owner/repo@1.2.3")
    );
    let latest = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", "http://127.0.0.1:9")
        .args(["use", "--user", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(latest.status.success(), "{latest:?}");
    assert!(
        String::from_utf8(latest.stdout)
            .unwrap()
            .contains("already installed gh:owner/repo@latest")
    );

    let project_tools = directory.path().join("project/.neoenv/tools/keep");
    fs::create_dir_all(&project_tools).unwrap();
    fs::write(project_tools.join("sentinel"), "keep").unwrap();
    let removed = global_command(directory.path(), &config_home, &data_home)
        .args(["tool", "remove", "--user", "gh:owner/repo"])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{removed:?}");
    assert!(project_tools.join("sentinel").is_file());
}

#[test]
fn aqua_global_use_requires_and_verifies_pinned_manifest_inputs() {
    fn run_case(manifest_assets: &str, pinned_digest: Option<String>, expected: bool) {
        let directory = TempDir::new().unwrap();
        let config_home = directory.path().join("config");
        let data_home = directory.path().join("data");
        let artifact = b"#!/bin/sh\nexit 0\n";
        let artifact_digest = format!("{:x}", Sha256::digest(artifact));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let manifest_assets = manifest_assets
            .replace("http://127.0.0.1/asset", &format!("http://{address}/asset"))
            .replace("{digest}", &artifact_digest);
        let manifest = format!("package: owner/tool\nassets:\n{manifest_assets}");
        let manifest_digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
        let expected_requests = usize::from(expected) + 1;
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server_thread = thread::spawn(move || {
            let mut served = 0;
            while served < expected_requests && !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .is_err()
                            || stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .is_err()
                        {
                            continue;
                        }
                        let Some(request) = request_headers(&mut stream) else {
                            continue;
                        };
                        let path = String::from_utf8_lossy(&request)
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_owned();
                        let body = if path.ends_with("/registry.yaml") {
                            manifest.as_bytes().to_vec()
                        } else {
                            artifact.to_vec()
                        };
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(&body).unwrap();
                        served += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("Aqua input fixture listener failed: {error}"),
                }
            }
            served
        });
        let mut server = FixtureServer::new(stop, server_thread);
        let mut command = global_command(directory.path(), &config_home, &data_home);
        command.args(["use", "--user", "aqua:owner/tool@1.2.3"]);
        command
            .env("NEOENV_GLOBAL_AQUA_ENDPOINT", format!("http://{address}"))
            .env(
                "NEOENV_GLOBAL_AQUA_REVISION",
                "0123456789012345678901234567890123456789",
            );
        if let Some(digest) = pinned_digest {
            let digest = if digest == "auto" {
                manifest_digest.clone()
            } else {
                digest
            };
            command.env("NEOENV_GLOBAL_AQUA_MANIFEST_SHA256", digest);
        }
        let output = command.output().unwrap();
        let served = server.stop();
        assert_eq!(
            served, expected_requests,
            "Aqua fixture served fewer requests than expected (expected success: {expected})"
        );
        assert_eq!(
            output.status.success(),
            expected,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expected {
            let config = fs::read_to_string(global_config_path(&config_home)).unwrap();
            assert!(config.contains(&manifest_digest));
            assert!(config.contains("0123456789012345678901234567890123456789"));
        } else {
            assert!(!config_home.exists());
            assert!(!data_home.exists());
        }
    }

    let correct_assets = "  - version: 1.2.3\n    os: linux\n    arch: x86_64\n    url: http://127.0.0.1/asset\n    sha256: {digest}\n";
    run_case(correct_assets, Some("auto".into()), true);
    run_case(correct_assets, Some("b".repeat(64)), false);
    let duplicate = format!("{correct_assets}{correct_assets}");
    run_case(&duplicate, Some("auto".into()), false);
}

/// Stops and joins a local fixture server on both normal return and unwind.
struct FixtureServer<T> {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<T>>,
}

impl<T> FixtureServer<T> {
    fn new(stop: Arc<AtomicBool>, thread: thread::JoinHandle<T>) -> Self {
        Self {
            stop,
            thread: Some(thread),
        }
    }

    fn stop(&mut self) -> T {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .expect("fixture server thread")
            .join()
            .expect("fixture server thread")
    }
}

impl<T> Drop for FixtureServer<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Preserve the original assertion panic during unwinding.
            let _ = thread.join();
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn aqua_global_lock_reuse_requires_matching_manifest_pins() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let artifact = b"#!/bin/sh\nexit 0\n";
    let artifact_digest = format!("{:x}", Sha256::digest(artifact));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let manifest = format!(
        "package: owner/tool\nassets:\n  - version: 1.2.3\n    os: linux\n    arch: x86_64\n    url: http://{address}/asset\n    sha256: {artifact_digest}\n"
    );
    let manifest_digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
    let bad_artifact = b"this digest is intentionally not the fixture artifact";
    let bad_artifact_digest = format!("{:x}", Sha256::digest(bad_artifact));
    let bad_manifest = format!(
        "package: owner/tool\nassets:\n  - version: 1.2.3\n    os: linux\n    arch: x86_64\n    url: http://{address}/asset\n    sha256: {bad_artifact_digest}\n"
    );
    let bad_manifest_digest = format!("{:x}", Sha256::digest(bad_manifest.as_bytes()));
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let fail_install = Arc::new(AtomicBool::new(false));
    let server_fail_install = Arc::clone(&fail_install);
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let server_thread = thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .is_err()
                        || stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .is_err()
                    {
                        continue;
                    }
                    let Some(request) = request_headers(&mut stream) else {
                        continue;
                    };
                    let path = String::from_utf8_lossy(&request)
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    let body = if path.ends_with("/registry.yaml") {
                        if server_fail_install.load(Ordering::Acquire) {
                            bad_manifest.as_bytes()
                        } else {
                            manifest.as_bytes()
                        }
                    } else {
                        artifact
                    };
                    if write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .is_ok()
                        && stream.write_all(body).is_ok()
                    {
                        server_requests.fetch_add(1, Ordering::AcqRel);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("Aqua fixture listener failed: {error}"),
            }
        }
    });
    let mut server = FixtureServer::new(Arc::clone(&stop), server_thread);
    let invoke = |revision: &str, digest: &str| {
        global_command(directory.path(), &config_home, &data_home)
            .args(["use", "--user", "aqua:owner/tool@1.2.3"])
            .env("NEOENV_GLOBAL_AQUA_ENDPOINT", format!("http://{address}"))
            .env("NEOENV_GLOBAL_AQUA_REVISION", revision)
            .env("NEOENV_GLOBAL_AQUA_MANIFEST_SHA256", digest)
            .output()
            .unwrap()
    };
    let first = invoke("0123456789012345678901234567890123456789", &manifest_digest);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before_wrong_digest = requests.load(Ordering::Acquire);
    let wrong_digest = invoke("0123456789012345678901234567890123456789", &"b".repeat(64));
    assert!(!wrong_digest.status.success());
    assert_eq!(
        requests.load(Ordering::Acquire),
        before_wrong_digest + 1,
        "wrong digest request incorrectly reused the old lock"
    );
    let before_new_revision = requests.load(Ordering::Acquire);
    let changed_revision = invoke("abcdefabcdefabcdefabcdefabcdefabcdefabcd", &manifest_digest);
    assert!(
        changed_revision.status.success(),
        "{}",
        String::from_utf8_lossy(&changed_revision.stderr)
    );
    assert_eq!(
        requests.load(Ordering::Acquire),
        before_new_revision + 1,
        "changed revision request incorrectly reused the old lock"
    );
    fail_install.store(true, Ordering::Release);
    let before_failed_install = requests.load(Ordering::Acquire);
    let failed_update = invoke(
        "fedcfedcfedcfedcfedcfedcfedcfedcfedcfedc",
        &bad_manifest_digest,
    );
    assert!(!failed_update.status.success());
    assert_eq!(requests.load(Ordering::Acquire), before_failed_install + 2);
    let lock_root = data_home.join("neoenv/locks");
    let lock_path = fs::read_dir(&lock_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".neoenv.lock"))
        })
        .unwrap();
    let preserved = neoenv_installer::tools::read_lockfile(&lock_path).unwrap();
    assert_eq!(
        preserved.tools[0].provenance.registry_revision.as_deref(),
        Some("abcdefabcdefabcdefabcdefabcdefabcdefabcd")
    );
    let before_old_request = requests.load(Ordering::Acquire);
    let selected = invoke("abcdefabcdefabcdefabcdefabcdefabcdefabcd", &manifest_digest);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(
        requests.load(Ordering::Acquire),
        before_old_request,
        "the previous selected tool should remain available from its lock"
    );
    server.stop();
    let lock_path = fs::read_dir(lock_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".neoenv.lock"))
        })
        .unwrap();
    let lock = neoenv_installer::tools::read_lockfile(&lock_path).unwrap();
    assert_eq!(
        lock.tools[0].provenance.registry_revision.as_deref(),
        Some("abcdefabcdefabcdefabcdefabcdefabcdefabcd")
    );
    assert_eq!(
        lock.tools[0].provenance.manifest_sha256.as_deref(),
        Some(manifest_digest.as_str())
    );
}

#[test]
fn global_batch_never_exceeds_ten_provider_installers() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = GithubFixture::start_with_delay(Duration::from_millis(100));
    // Build one argv-compatible invocation after collecting the key/version
    // pairs; this keeps the request order explicit and portable across shells.
    let output = {
        let mut invocation = global_command(directory.path(), &config_home, &data_home);
        invocation.env("NEOENV_GITHUB_API_URL", fixture.api_url());
        invocation.arg("use").arg("--user");
        for index in 0..11 {
            invocation.arg(format!("gh:owner/repo@1.2.{index}"));
        }
        invocation.output().unwrap()
    };
    let maximum = fixture.maximum_active();
    fixture.stop();
    assert!(output.status.success(), "{output:?}");
    assert!(maximum <= 10, "maximum active installers: {maximum}");
}

#[test]
fn mixed_runtime_provider_failure_never_publishes_global_configuration() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let output = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", "http://127.0.0.1:9")
        .args(["use", "--user", "node@bad/version", "gh:owner/repo@1.2.3"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!config_home.exists());
    assert!(!data_home.exists() || fs::read_dir(data_home.join("neoenv/tools")).is_err());
}

#[cfg(unix)]
#[test]
fn ctrl_c_during_provider_batch_publishes_no_global_configuration() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    let fixture = GithubFixture::start_with_delay(Duration::from_secs(1));
    let child = global_command(directory.path(), &config_home, &data_home)
        .env("NEOENV_GITHUB_API_URL", fixture.api_url())
        .args(["use", "--user", "gh:owner/repo@1.2.3"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if fixture.requests.load(Ordering::Acquire) >= 3 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.requests.load(Ordering::Acquire) >= 3);
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = child.wait_with_output().unwrap();
    fixture.stop();
    assert!(!output.status.success());
    assert!(!config_home.exists());
    let tools = data_home.join("neoenv/tools");
    assert!(!tools.exists() || fs::read_dir(tools).unwrap().next().is_none());
}

#[test]
fn global_provider_keys_reject_providers_that_require_pinned_project_declarations() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    for (key, required_detail) in [
        ("aqua:owner/tool", "registry revision"),
        ("go:example.com/tool", "go.sum"),
        ("gl:owner/repo", "GitLab release resolver"),
    ] {
        let output = global_command(directory.path(), &config_home, &data_home)
            .env("NEOENV_GITHUB_API_URL", "http://127.0.0.1:9")
            .args(["use", "--user", key])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{key}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("global provider"), "{key}: {error}");
        assert!(
            error.contains("pinned project declaration"),
            "{key}: {error}"
        );
        assert!(error.contains(required_detail), "{key}: {error}");
        assert_empty(&config_home);
        assert_empty(&data_home);
    }
}

#[test]
fn global_provider_keys_reject_unknown_and_remote_module_spellings() {
    let directory = TempDir::new().unwrap();
    let config_home = directory.path().join("config");
    let data_home = directory.path().join("data");
    for key in [
        "unknown:package",
        "github:owner/repo",
        "https://github.com/owner/repo",
    ] {
        let output = global_command(directory.path(), &config_home, &data_home)
            .args(["use", "--user", key])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{key}: {output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("NEO510") || error.contains("global tool"),
            "{error}"
        );
        assert_empty(&config_home);
        assert_empty(&data_home);
    }
}
