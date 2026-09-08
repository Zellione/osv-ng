//! Shared test-only fault injection and secret-canary support.

use std::{
    fmt, fs,
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

static NEXT_TEMP_VAULT_ID: AtomicU64 = AtomicU64::new(0);

/// A named boundary at which a multi-step operation may be interrupted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPoint(&'static str);

impl FaultPoint {
    /// Defines a stable fault-point name used by tests and crash harnesses.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Returns the stable, non-secret name of this point.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0
    }
}

/// Allows persistent operations to expose explicit interruption boundaries.
pub trait FaultInjector {
    /// Returns `true` when the operation should fail at `point`.
    fn should_fail(&mut self, point: FaultPoint) -> bool;
}

/// An injector that never interrupts an operation.
#[derive(Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn should_fail(&mut self, _point: FaultPoint) -> bool {
        false
    }
}

/// An injector that interrupts on one selected observation of a fault point.
pub struct FailAt {
    point: FaultPoint,
    observations_before_failure: Option<usize>,
}

impl FailAt {
    /// Configures failure on the `observation`th visit, counting from one.
    #[must_use]
    pub const fn new(point: FaultPoint, observation: usize) -> Self {
        Self {
            point,
            observations_before_failure: Some(observation.saturating_sub(1)),
        }
    }
}

impl FaultInjector for FailAt {
    fn should_fail(&mut self, point: FaultPoint) -> bool {
        if point != self.point || self.observations_before_failure.is_none() {
            return false;
        }

        if self.observations_before_failure == Some(0) {
            self.observations_before_failure = None;
            return true;
        }

        self.observations_before_failure = self.observations_before_failure.map(|count| count - 1);
        false
    }
}

/// An owner-only directory for tests that model a vault on disk.
///
/// The directory is removed on drop. It must contain fixtures only, never user
/// data, and it is not a substitute for the production filesystem API.
pub struct TempVault {
    path: PathBuf,
}

impl TempVault {
    /// Creates an exclusively named directory below `parent`.
    pub fn create_in(parent: &Path) -> io::Result<Self> {
        for _ in 0..128 {
            let sequence = NEXT_TEMP_VAULT_ID.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("osv-test-{}-{sequence}", std::process::id()));
            let mut builder = fs::DirBuilder::new();

            #[cfg(unix)]
            builder.mode(0o700);

            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary vault directory",
        ))
    }

    /// Returns the temporary vault path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns whether the directory has owner-only permissions.
    #[cfg(unix)]
    pub fn has_owner_only_permissions(&self) -> io::Result<bool> {
        let mode = fs::metadata(&self.path)?.permissions().mode() & 0o777;
        Ok(mode == 0o700)
    }
}

impl fmt::Debug for TempVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TempVault([REDACTED PATH])")
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Kills a child after it reports a selected persistence boundary on stdout.
///
/// The child must write exactly `boundary` followed by a newline, flush stdout,
/// and then wait for input without closing. Stderr is discarded so hostile or
/// sensitive fixture values cannot enter the test log. The caller should give
/// the child only public fixture data and non-secret environment values.
pub fn kill_child_at_boundary(command: &mut Command, boundary: &str) -> io::Result<()> {
    if boundary.is_empty() || boundary.len() > 255 || boundary.as_bytes().contains(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid crash boundary name",
        ));
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let result = (|| {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("child stdout was not captured"))?;
        let mut reported = Vec::with_capacity(boundary.len() + 1);
        let bytes_read = BufReader::new(stdout)
            .take(256)
            .read_until(b'\n', &mut reported)?;

        if bytes_read == 0 || !reported.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "child did not report a complete crash boundary",
            ));
        }

        let expected = [boundary.as_bytes(), b"\n"].concat();
        if reported != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "child reported an unexpected crash boundary",
            ));
        }

        child.kill()?;
        let status = child.wait()?;
        if status.success() {
            return Err(io::Error::other(
                "child exited successfully instead of crashing",
            ));
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }

    result
}

/// Bytes planted in tests to detect plaintext persistence.
///
/// Debug output is deliberately redacted. Callers must also avoid including
/// the bytes in assertion messages or paths.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretCanary(Vec<u8>);

impl SecretCanary {
    /// Builds a canary from caller-provided bytes.
    ///
    /// Randomized test suites should supply independently generated bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the bytes for insertion or artifact scanning.
    #[must_use]
    pub fn expose_for_test(&self) -> &[u8] {
        &self.0
    }

    /// Reports whether the canary occurs in an artifact without exposing it.
    #[must_use]
    pub fn occurs_in(&self, artifact: &[u8]) -> bool {
        !self.0.is_empty()
            && artifact
                .windows(self.0.len())
                .any(|window| window == self.0)
    }
}

impl fmt::Debug for SecretCanary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCanary([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use proptest::prelude::*;

    use super::{FailAt, FaultInjector, FaultPoint, NoFaults, SecretCanary, TempVault};

    #[test]
    fn no_faults_never_interrupts() {
        let mut injector = NoFaults;
        assert!(!injector.should_fail(FaultPoint::new("after-file-sync")));
    }

    #[test]
    fn fail_at_counts_only_matching_points() {
        let selected = FaultPoint::new("after-file-sync");
        let mut injector = FailAt::new(selected, 2);

        assert!(!injector.should_fail(FaultPoint::new("before-file-sync")));
        assert!(!injector.should_fail(selected));
        assert!(injector.should_fail(selected));
        assert!(!injector.should_fail(selected));
    }

    #[test]
    fn secret_canary_debug_is_redacted() {
        let canary = SecretCanary::new(b"unique secret marker".to_vec());
        assert_eq!(format!("{canary:?}"), "SecretCanary([REDACTED])");
    }

    #[test]
    fn secret_canary_finds_only_complete_nonempty_marker() {
        let canary = SecretCanary::new(b"secret marker".to_vec());
        assert!(canary.occurs_in(b"prefix secret marker suffix"));
        assert!(!canary.occurs_in(b"secret mark"));
        assert!(!SecretCanary::new(Vec::new()).occurs_in(b"anything"));
    }

    #[test]
    fn temporary_vault_is_private_and_removed_on_drop() -> io::Result<()> {
        let parent = std::env::temp_dir();
        let vault = TempVault::create_in(&parent)?;
        let path = vault.path().to_owned();

        assert!(path.is_dir());
        assert_eq!(format!("{vault:?}"), "TempVault([REDACTED PATH])");

        #[cfg(unix)]
        assert!(vault.has_owner_only_permissions()?);

        fs::write(path.join("fixture"), b"public test fixture")?;
        drop(vault);
        assert!(!path.exists());
        Ok(())
    }

    proptest! {
        #[test]
        fn canary_search_matches_reference(
            marker in prop::collection::vec(any::<u8>(), 0..64),
            artifact in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let expected = !marker.is_empty()
                && artifact.windows(marker.len()).any(|window| window == marker);
            let canary = SecretCanary::new(marker);
            prop_assert_eq!(canary.occurs_in(&artifact), expected);
        }
    }
}
