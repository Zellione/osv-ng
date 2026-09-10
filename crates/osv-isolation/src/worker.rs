use crate::{FramedChannel, SandboxError, TransportError, WORKER_CONTROL_FD, apply_worker_sandbox};
use osv_worker_protocol::{FailureClass, Frame, Message, Role, VERSION};
use std::{error::Error, fmt, os::fd::FromRawFd, os::unix::net::UnixStream};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum WorkerError {
    Sandbox(SandboxError),
    Transport(TransportError),
    Protocol,
}
impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("isolated worker terminated safely")
    }
}
impl Error for WorkerError {}
impl From<SandboxError> for WorkerError {
    fn from(value: SandboxError) -> Self {
        Self::Sandbox(value)
    }
}
impl From<TransportError> for WorkerError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[allow(unsafe_code)]
pub fn run_worker(expected_role: Role) -> Result<(), WorkerError> {
    let report = apply_worker_sandbox(WORKER_CONTROL_FD)?;
    let stream = unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) };
    let mut channel = FramedChannel::new(stream);
    let hello = channel.receive()?;
    let Message::Hello { minimum, maximum } = hello.message else {
        return Err(WorkerError::Protocol);
    };
    if minimum > VERSION || maximum < VERSION {
        return Err(WorkerError::Protocol);
    }
    channel.send(&Frame {
        request_id: hello.request_id,
        message: Message::Ready {
            version: VERSION,
            sandbox_flags: report.flags(),
        },
    })?;
    let start = channel.receive()?;
    if start.request_id != hello.request_id
        || start.message
            != (Message::Start {
                role: expected_role,
            })
    {
        return Err(WorkerError::Protocol);
    }
    let mut next_sequence = 0_u64;
    loop {
        let mut frame = channel.receive()?;
        if frame.request_id != hello.request_id {
            return Err(WorkerError::Protocol);
        }
        match &mut frame.message {
            Message::Data { sequence, bytes } if *sequence == next_sequence => {
                bytes.zeroize();
                next_sequence += 1;
            }
            Message::End { chunks } if *chunks == next_sequence => {
                channel.send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Complete,
                })?;
                return Ok(());
            }
            Message::Cancel => return Ok(()),
            _ => {
                channel.send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Failed {
                        class: FailureClass::InvalidInput,
                    },
                })?;
                return Err(WorkerError::Protocol);
            }
        }
    }
}
