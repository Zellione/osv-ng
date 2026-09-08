use std::{fs, path::Path, process::Command};

use osv_crypto::Password;
use osv_storage::{PUBLISH_POINTS, UnlockedVault};
use osv_test_support::{TempVault, kill_child_at_boundary};

const PLAINTEXT: &[u8] = b"phase four crash publication plaintext canary";

fn tree_contains(path: &Path, needle: &[u8]) -> bool {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            if tree_contains(&entry.path(), needle) {
                return true;
            }
        } else {
            let bytes = fs::read(entry.path()).unwrap();
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn killed_publication_leaves_only_unlockable_vault_and_orphan_ciphertext() {
    for (index, point) in PUBLISH_POINTS.into_iter().enumerate() {
        let parent = TempVault::create_in(&std::env::temp_dir()).unwrap();
        let path = parent.path().join(format!("object-crash-{index}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-object-publish-crash-fixture"));
        command.arg(&path).arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();

        let password = Password::new(b"object fixture password").unwrap();
        assert!(UnlockedVault::unlock(&path, &password, None).is_ok());
        assert!(!tree_contains(&path, PLAINTEXT));
    }
}
