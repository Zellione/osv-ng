fn main() {
    let worker_mode = std::env::args().nth(1).as_deref() == Some("--worker");
    let result = if worker_mode {
        osv_isolation::run_worker(osv_worker_protocol::Role::Archive).map_err(|_| ())
    } else {
        osv_crypto::harden_process().map_err(|_| ())
    };
    if result.is_err() {
        eprintln!("osv-archive-worker: isolated request failed");
        std::process::exit(1);
    }
}
