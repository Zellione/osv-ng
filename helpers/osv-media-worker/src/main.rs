fn main() {
    if osv_crypto::harden_process().is_err() {
        eprintln!("osv-media-worker: required process hardening failed");
        std::process::exit(1);
    }
}
