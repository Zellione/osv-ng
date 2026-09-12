//! Media-worker protocol and decoded-media abstractions.

use std::path::Path;

/// Starts one short-lived, object-scoped media parser.
pub fn spawn_worker(
    executable: &Path,
    request_id: u64,
    limits: osv_isolation::SupervisorLimits,
) -> Result<osv_isolation::Supervisor, osv_isolation::SupervisorError> {
    osv_isolation::Supervisor::spawn(
        executable,
        osv_worker_protocol::Role::Media,
        request_id,
        limits,
    )
}
