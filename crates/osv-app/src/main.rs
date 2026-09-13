fn main() -> gtk::glib::ExitCode {
    if osv_crypto::harden_process().is_err() {
        eprintln!("osv-app: required process hardening failed");
        return gtk::glib::ExitCode::FAILURE;
    }
    if std::env::args().any(|argument| argument == "--self-check") {
        return gtk::glib::ExitCode::SUCCESS;
    }
    osv_app::ui::run()
}
