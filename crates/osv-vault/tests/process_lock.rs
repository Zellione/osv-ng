#![cfg(feature = "test-fixtures")]

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Command, Stdio},
};

use osv_crypto::{KdfParams, Password};
use osv_test_support::TempVault;
use osv_vault::{OpenMode, ServiceError, VaultService};

#[test]
fn process_locks_allow_shared_readers_and_exclude_writers() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let path = parent.path().join("vault");
    let password = Password::new(b"lock fixture password").unwrap();
    VaultService::create(&path, &password, None, KdfParams::new(8, 1, 1).unwrap(), 1)
        .unwrap()
        .close()
        .unwrap();

    let mut reader = held_child(&path, "reader", "reader-held");
    let second = VaultService::open(&path, &password, None, OpenMode::Reader).unwrap();
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Writer),
        Err(ServiceError::LockContended)
    ));
    second.close().unwrap();
    reader.kill().unwrap();
    reader.wait().unwrap();

    let mut writer = held_child(&path, "writer", "writer-held");
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Reader),
        Err(ServiceError::LockContended)
    ));
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Writer),
        Err(ServiceError::LockContended)
    ));
    writer.kill().unwrap();
    writer.wait().unwrap();
}

fn held_child(path: &Path, mode: &str, expected: &str) -> std::process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_osv-vault-lock-fixture"))
        .arg(path)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim_end(), expected);
    child
}
