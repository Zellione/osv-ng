use osv_isolation::{ExitClass, PlaintextBuffer, Supervisor, SupervisorLimits};
use osv_worker_protocol::Role;
use std::{
    fs,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};

static TEST_PROCESSES: Mutex<()> = Mutex::new(());

fn fixture() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_osv-isolation-fixture"))
}

fn limits() -> SupervisorLimits {
    SupervisorLimits {
        startup: Duration::from_millis(500),
        operation: Duration::from_millis(100),
        cancellation_grace: Duration::from_millis(100),
        maximum_restarts: 1,
    }
}

fn address_sanitizer_active() -> bool {
    std::env::var_os("ASAN_OPTIONS").is_some()
}

#[test]
fn hangs_are_deadlined_and_killed_during_startup_and_operation() {
    // ASan's shadow mapping intentionally exceeds the production RLIMIT_AS.
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let error = Supervisor::spawn(fixture(), Role::Media, 1, limits())
        .err()
        .unwrap();
    assert_eq!(error.class, ExitClass::Deadline, "{error:?}");

    let mut worker = Supervisor::spawn(fixture(), Role::Media, 2, limits()).unwrap();
    worker
        .send_authenticated(0, PlaintextBuffer::new(vec![1]).unwrap())
        .unwrap();
    let error = worker.finish().unwrap_err();
    assert_eq!(error.class, ExitClass::Deadline);
}

#[test]
fn downgrade_and_false_sandbox_claims_fail_closed() {
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for request_id in [3, 4] {
        let error = Supervisor::spawn(fixture(), Role::Media, request_id, limits())
            .err()
            .unwrap();
        assert_eq!(error.class, ExitClass::Protocol, "{error:?}");
    }
}

#[test]
fn crashes_are_reaped_and_classified() {
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let error = Supervisor::spawn(fixture(), Role::Media, 5, limits())
        .err()
        .unwrap();
    assert_eq!(error.class, ExitClass::WorkerFailure, "{error:?}");
}

#[test]
fn a_worker_cannot_extend_its_lifetime_after_completion() {
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let worker = Supervisor::spawn(fixture(), Role::Media, 6, limits()).unwrap();
    let error = worker.finish().unwrap_err();
    assert_eq!(error.class, ExitClass::Deadline, "{error:?}");
}

#[test]
fn sandbox_denies_new_filesystem_and_network_authority() {
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (parent, child) = UnixStream::pair().unwrap();
    let child_fd = OwnedFd::from(child);
    let mut command = Command::new(env!("CARGO_BIN_EXE_osv-isolation-fixture"));
    command
        .arg("probe")
        .stdin(Stdio::from(child_fd))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command.status().unwrap();
    drop(parent);
    assert!(status.success(), "probe status: {status:?}");
}

#[test]
fn sandbox_denies_path_mutation_with_and_without_landlock() {
    if address_sanitizer_active() {
        return;
    }
    let _guard = TEST_PROCESSES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for landlock_mode in ["with-landlock", "without-landlock"] {
        let directory = std::env::temp_dir().join(format!(
            "osv-isolation-mutation-{}-{landlock_mode}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("source");
        let renamed = directory.join("renamed");
        fs::write(&path, b"unchanged").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
        fs::set_permissions(&path, permissions).unwrap();

        let (parent, child) = UnixStream::pair().unwrap();
        let status = Command::new(fixture())
            .arg("mutation-probe")
            .arg(&path)
            .arg(&renamed)
            .arg(landlock_mode)
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        drop(parent);

        let landlock_unavailable = landlock_mode == "with-landlock" && status.code() == Some(77);
        assert!(
            status.success() || landlock_unavailable,
            "{landlock_mode} probe status: {status:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"unchanged");
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
                & 0o777,
            0o600
        );
        assert!(!renamed.exists());
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
