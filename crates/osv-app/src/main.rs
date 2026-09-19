fn main() -> gtk::glib::ExitCode {
    if let Some(exit_code) = osv_app::portal::run_broker_from_arguments() {
        return exit_code;
    }
    if osv_crypto::harden_process().is_err() {
        eprintln!("osv-app: required process hardening failed");
        return gtk::glib::ExitCode::FAILURE;
    }
    if std::env::args().any(|argument| argument == "--self-check") {
        return gtk::glib::ExitCode::SUCCESS;
    }
    osv_app::ui::run()
}
