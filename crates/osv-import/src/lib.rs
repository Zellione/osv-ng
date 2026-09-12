//! Import plans, archive boundaries, and duplicate decisions.

use std::path::Path;

/// Starts one short-lived, object-scoped archive parser.
pub fn spawn_archive_worker(
    executable: &Path,
    request_id: u64,
    limits: osv_isolation::SupervisorLimits,
) -> Result<osv_isolation::Supervisor, osv_isolation::SupervisorError> {
    osv_isolation::Supervisor::spawn(
        executable,
        osv_worker_protocol::Role::Archive,
        request_id,
        limits,
    )
}
