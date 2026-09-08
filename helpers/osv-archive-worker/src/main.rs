fn main() {
    if osv_crypto::harden_process().is_err() {
        eprintln!("osv-archive-worker: required process hardening failed");
        std::process::exit(1);
    }
}
