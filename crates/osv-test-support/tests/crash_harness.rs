use std::{fs, io, process::Command};

use osv_test_support::{TempVault, kill_child_at_boundary};

const FIXTURE_BYTES: &[u8] = b"public crash fixture";

#[test]
fn kill_matrix_exposes_each_persistence_state() -> io::Result<()> {
    for boundary in [
        "after-staging-sync",
        "after-publish-rename",
        "after-directory-sync",
    ] {
        let vault = TempVault::create_in(&std::env::temp_dir())?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-test-crash-fixture"));
        command
            .current_dir(vault.path())
            .env("OSV_TEST_FAULT_POINT", boundary);

        kill_child_at_boundary(&mut command, boundary)?;

        let staged = vault.path().join("staging/object.tmp");
        let published = vault.path().join("objects/object");
        if boundary == "after-staging-sync" {
            assert_eq!(fs::read(staged)?, FIXTURE_BYTES);
            assert!(!published.exists());
        } else {
            assert!(!staged.exists());
            assert_eq!(fs::read(published)?, FIXTURE_BYTES);
        }
    }

    Ok(())
}

#[test]
fn controller_rejects_unbounded_boundary_names() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_osv-test-crash-fixture"));
    let invalid = "x".repeat(256);
    let error = kill_child_at_boundary(&mut command, &invalid).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
