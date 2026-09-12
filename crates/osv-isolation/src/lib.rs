//! Linux process isolation, bounded IPC, and worker lifecycle management.

mod sandbox;
mod supervisor;
mod transport;
mod worker;

pub use sandbox::{
    DESCRIPTOR_ALLOWLIST, LANDLOCK, NO_NEW_PRIVS, RESOURCE_LIMITS, SECCOMP, SandboxError,
    SandboxReport, apply_worker_sandbox,
};
pub use supervisor::{ExitClass, Supervisor, SupervisorError, SupervisorLimits};
pub use transport::{
    FramedChannel, PlaintextBuffer, TransportError, receive_descriptor, send_descriptor,
};
pub use worker::{WorkerError, run_worker};

pub const WORKER_CONTROL_FD: i32 = 0;
