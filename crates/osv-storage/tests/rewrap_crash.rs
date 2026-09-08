use std::process::Command;

use osv_crypto::{KdfParams, Password};
use osv_storage::{REWRAP_POINTS, UnlockedVault};
use osv_test_support::{TempVault, kill_child_at_boundary};

#[test]
fn killed_rewrap_always_recovers_with_old_or_new_credentials() {
    for (index, point) in REWRAP_POINTS.into_iter().enumerate() {
        let parent = TempVault::create_in(&std::env::temp_dir()).unwrap();
        let path = parent.path().join(format!("crash-{index}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-rewrap-crash-fixture"));
        command.arg(&path).arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();

        let old = Password::new(b"old fixture password").unwrap();
        let new = Password::new(b"new fixture password").unwrap();
        let old_result = UnlockedVault::unlock(&path, &old, None);
        let new_result = UnlockedVault::unlock(&path, &new, None);
        assert!(
            old_result.is_ok() || new_result.is_ok(),
            "no credential recovered after kill at {point:?}"
        );
        let params = KdfParams::new(8, 1, 1).unwrap();
        assert_eq!(
            old_result
                .as_ref()
                .or(new_result.as_ref())
                .unwrap()
                .header()
                .kdf_params(),
            params
        );
    }
}
