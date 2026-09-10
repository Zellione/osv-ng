use osv_isolation::{ExitClass, PlaintextBuffer, SupervisorLimits};

#[test]
fn archive_worker_completes_a_bounded_stream_under_sandbox() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-archive-worker"));
    let mut worker =
        osv_import::spawn_archive_worker(executable, 73, SupervisorLimits::default()).unwrap();
    assert_ne!(
        worker.sandbox_flags() & osv_isolation::DESCRIPTOR_ALLOWLIST,
        0
    );
    worker
        .send_authenticated(0, PlaintextBuffer::new(vec![4, 5, 6]).unwrap())
        .unwrap();
    assert_eq!(worker.finish().unwrap(), ExitClass::Success);
}
