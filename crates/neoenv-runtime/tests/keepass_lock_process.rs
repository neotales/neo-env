//! Cross-process contention for cooperative `KeePass` `ensure`.
//!
//! Each child process is a real `nenv` runtime process with its own memory OS
//! backend. They share only the KDBX file and the lock directory, which is the
//! property under test. No platform keychain is touched.

#![cfg(unix)]

use std::{collections::BTreeMap, path::Path, process::Command, sync::Arc};

use indexmap::IndexMap;
use neoenv_config::{KeepassVault, VaultDeclaration, VaultProvider};
use neoenv_core::SourceSpan;
use neoenv_runtime::vault::{MemoryOsBackend, VaultSet};
use neotales_keepass::{Comparison, Group, KdbxFile, KeePassDatabase, PathOptions};
use tempfile::TempDir;

fn build_database(path: &Path) {
    let mut database = KeePassDatabase::default();
    let work = database.root.add_group(Group::new("work"));
    let mut existing = neotales_keepass::Entry::new("existing");
    existing.password = neotales_keepass::ProtectedValue::from_text("existing-secret");
    work.add_entry(existing);
    let mut bytes = Vec::new();
    KdbxFile::save_default(&database, &mut bytes, "master-password").unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn child_vaults(database: &Path, lock_root: &Path) -> VaultSet {
    let declaration = VaultDeclaration {
        name: "work".to_owned(),
        provider: VaultProvider::Keepass(KeepassVault {
            path: database.display().to_string(),
            secret: "master-password".to_owned(),
        }),
        source: SourceSpan::new("neoenv.yaml".to_owned(), 1, 1),
    };
    VaultSet::from_declarations_with_backend_and_lock_root(
        IndexMap::from([("work".to_owned(), declaration)]),
        Arc::new(MemoryOsBackend::new()),
        Some(lock_root.to_owned()),
    )
}

/// Runs in a child test process. The environment carries the shared paths.
#[test]
#[ignore = "invoked by the parent contention test"]
fn child_ensure_same_keepass_entry() {
    let Ok(database) = std::env::var("NEOENV_TEST_KDBX") else {
        return;
    };
    let lock_root = std::env::var("NEOENV_TEST_LOCK").expect("lock root");
    let vaults = child_vaults(Path::new(&database), Path::new(&lock_root));
    let secret = vaults
        .get(
            "nsv://work/work/new?ensure=true&size=8&upper=false",
            &BTreeMap::new(),
        )
        .expect("ensure");
    println!("ENSURE={}", secret.expose());
}

#[test]
fn two_processes_see_one_keepass_ensure_result() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("secrets.kdbx");
    let lock_root = temp.path().canonicalize().unwrap().join("locks");
    build_database(&database);

    let executable = std::env::current_exe().expect("test executable");
    let spawn = || {
        Command::new(&executable)
            .args([
                "--exact",
                "child_ensure_same_keepass_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NEOENV_TEST_KDBX", &database)
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
            .unwrap_or_else(|| {
                panic!(
                    "child printed its ensure result\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
    };
    let first_value = value(&first);
    let second_value = value(&second);
    assert_eq!(first_value, second_value);

    let file = std::fs::File::open(&database).unwrap();
    let database = KdbxFile::open(file, b"master-password").unwrap();
    let options = PathOptions {
        delimiter: '/',
        comparison: Comparison::Ordinal,
    };
    let entry = database
        .find_entry_by_path("work/new", options)
        .unwrap()
        .expect("the ensured entry exists");
    assert_eq!(
        entry.password.reveal_text().unwrap().as_str(),
        first_value.as_str()
    );
    let some = database.root.groups.first().unwrap();
    assert_eq!(
        some.entries
            .iter()
            .filter(|entry| entry.title == "new")
            .count(),
        1
    );
}
