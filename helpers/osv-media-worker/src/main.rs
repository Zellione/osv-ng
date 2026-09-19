fn main() {
    let worker_mode = std::env::args().nth(1).as_deref() == Some("--worker");
    let result = if worker_mode {
        osv_isolation::run_worker_transformed(
            osv_worker_protocol::Role::Media,
            osv_media::MAX_ENCODED_BYTES + osv_media::WORKER_REQUEST_HEADER_LEN,
            |bytes| {
                osv_media::image_worker_result_from_request(bytes).map_err(|error| match error {
                    osv_media::ImageError::ResourceLimit => {
                        osv_worker_protocol::FailureClass::ResourceLimit
                    }
                    _ => osv_worker_protocol::FailureClass::InvalidInput,
                })
            },
        )
        .map_err(|_| ())
    } else {
        osv_crypto::harden_process().map_err(|_| ())
    };
    if result.is_err() {
        eprintln!("osv-media-worker: isolated request failed");
        std::process::exit(1);
    }
}
