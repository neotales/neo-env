//! Cross-process contention for cooperative OS `ensure`.
//!
//! A file-backed mock is the shared "credential store". It is not a platform
//! keychain and contains only a test value. The two child processes coordinate
//! through the nenv vault lock, so only one generated value is stored.

#![cfg(unix)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use indexmap::IndexMap;
use neoenv_config::{OsVault, VaultDeclaration, VaultProvider};
use neoenv_core::SourceSpan;
use neoenv_runtime::vault::{OsBackend, OsError, Secret, VaultSet};

struct FileBackend {
    path: PathBuf,
}

impl OsBackend for FileBackend {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<Secret>, OsError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).map_err(|_| OsError::Failed)?;
                Secret::try_new(text).map(Some).map_err(|_| OsError::Failed)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(OsError::Failed),
        }
    }

    fn set(&self, _service: &str, _account: &str, value: &str) -> Result<(), OsError> {
        std::fs::write(&self.path, value).map_err(|_| OsError::Failed)
    }
}

fn child_vaults(store: &Path, lock_root: &Path) -> VaultSet {
    let declaration = VaultDeclaration {
        name: "login".to_owned(),
        provider: VaultProvider::Os(OsVault {
            service: "test-service".to_owned(),
        }),
        source: SourceSpan::new("neoenv.yaml".to_owned(), 1, 1),
    };
    VaultSet::from_declarations_with_backend_and_lock_root(
        IndexMap::from([("login".to_owned(), declaration)]),
        Arc::new(FileBackend {
            path: store.to_owned(),
        }),
        Some(lock_root.to_owned()),
    )
}

#[test]
#[ignore = "invoked by the parent contention test"]
fn child_ensure_same_os_entry() {
    let Ok(store) = std::env::var("NEOENV_TEST_OS_STORE") else {
        return;
    };
    let lock_root = std::env::var("NEOENV_TEST_LOCK").expect("lock root");
    let vaults = child_vaults(Path::new(&store), Path::new(&lock_root));
    let secret = vaults
        .get(
            "nsv://login/account?ensure=true&size=8&upper=false",
            &BTreeMap::new(),
        )
        .expect("ensure");
    println!("ENSURE={}", secret.expose());
}

#[test]
fn two_processes_see_one_os_ensure_result() {
    let temp = tempfile::TempDir::new().unwrap();
    let store = temp.path().join("os-store");
    let lock_root = temp.path().join("locks");
    // Touch nothing at the store path; the first child creates it.

    let executable = std::env::current_exe().expect("test executable");
    let spawn = || {
        Command::new(&executable)
            .args([
                "--exact",
                "child_ensure_same_os_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NEOENV_TEST_OS_STORE", &store)
            .env("NEOENV_TEST_LOCK", &lock_root)
            .output()
            .expect("spawn ensure child")
    };

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(spawn);
        let second = scope.spawn(spawn);
        (first.join().unwrap(), second.join().unwrap())
    });

    for output in [&first, &second] {
        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                line.find("ENSURE=")
                    .map(|at| line[at + "ENSURE=".len()..].to_owned())
            })
            .expect("child printed its ensure result")
    };
    let first_value = value(&first);
    let second_value = value(&second);
    assert_eq!(first_value, second_value);
    assert_eq!(std::fs::read_to_string(&store).unwrap(), first_value);
}
