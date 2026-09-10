use osv_isolation::{ExitClass, PlaintextBuffer, SupervisorLimits};

#[test]
fn media_worker_completes_a_bounded_stream_under_sandbox() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 41, SupervisorLimits::default()).unwrap();
    assert_ne!(worker.sandbox_flags() & osv_isolation::SECCOMP, 0);
    worker
        .send_authenticated(0, PlaintextBuffer::new(vec![1, 2, 3]).unwrap())
        .unwrap();
    assert_eq!(worker.finish().unwrap(), ExitClass::Success);
}

#[test]
fn media_worker_releases_authority_on_cancellation() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 42, SupervisorLimits::default()).unwrap();
    assert_eq!(worker.cancel(), ExitClass::Success);
}
