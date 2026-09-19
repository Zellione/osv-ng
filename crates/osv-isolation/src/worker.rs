use crate::{FramedChannel, SandboxError, TransportError, WORKER_CONTROL_FD, apply_worker_sandbox};
use osv_crypto::SecretBytes;
use osv_worker_protocol::{FailureClass, Frame, Message, Role, VERSION};
use std::{error::Error, fmt, os::fd::FromRawFd, os::unix::net::UnixStream};

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
    run_worker_validated(expected_role, 256 * 1024 * 1024, |_| Ok(()))
}

/// Runs a worker that retains a bounded request in protected memory and invokes
/// an object-scoped validator before acknowledging success.
#[allow(unsafe_code)]
pub fn run_worker_validated(
    expected_role: Role,
    maximum_bytes: usize,
    validate: impl FnOnce(&[u8]) -> Result<(), FailureClass>,
) -> Result<(), WorkerError> {
    run_worker_transformed(expected_role, maximum_bytes, move |bytes| {
        validate(bytes)?;
        SecretBytes::zeroed(0).map_err(|_| FailureClass::Internal)
    })
}

/// Runs a bounded transform and streams its protected result back to the broker.
#[allow(unsafe_code)]
pub fn run_worker_transformed(
    expected_role: Role,
    maximum_bytes: usize,
    transform: impl FnOnce(&[u8]) -> Result<SecretBytes, FailureClass>,
) -> Result<(), WorkerError> {
    let report = apply_worker_sandbox(WORKER_CONTROL_FD)?;
    let stream = unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) };
    let mut channel = FramedChannel::new(stream);
    let (hello, _) = channel.receive()?;
    let Message::Hello { minimum, maximum } = hello.message else {
        return Err(WorkerError::Protocol);
    };
    if minimum > VERSION || maximum < VERSION {
        return Err(WorkerError::Protocol);
    }
    let _ = channel.send(&Frame {
        request_id: hello.request_id,
        message: Message::Ready {
            version: VERSION,
            sandbox_flags: report.flags(),
            page_locks: channel.lock_status(),
        },
    })?;
    let (start, _) = channel.receive()?;
    if start.request_id != hello.request_id
        || start.message
            != (Message::Start {
                role: expected_role,
            })
    {
        return Err(WorkerError::Protocol);
    }
    let mut next_sequence = 0_u64;
    let mut payloads = Vec::new();
    let mut total = 0_usize;
    let mut transform = Some(transform);
    let mut plaintext_status = channel.lock_status();
    loop {
        let (frame, receive_status) = channel.receive()?;
        if frame.request_id != hello.request_id {
            return Err(WorkerError::Protocol);
        }
        plaintext_status = plaintext_status.combine(receive_status);
        if receive_status == osv_crypto::LockStatus::Degraded {
            let _ = channel.send(&Frame {
                request_id: hello.request_id,
                message: Message::Failed {
                    class: FailureClass::ResourceLimit,
                    page_locks: channel.lock_status().combine(plaintext_status),
                },
            })?;
            return Err(WorkerError::Protocol);
        }
        match frame.message {
            Message::Data { sequence, bytes } if sequence == next_sequence => {
                let maximum_chunks = maximum_bytes
                    .div_ceil(osv_worker_protocol::MAX_DATA_LEN)
                    .saturating_add(1);
                if payloads.len() >= maximum_chunks || bytes.is_empty() {
                    let _ = channel.send(&Frame {
                        request_id: hello.request_id,
                        message: Message::Failed {
                            class: FailureClass::ResourceLimit,
                            page_locks: channel.lock_status().combine(plaintext_status),
                        },
                    });
                    return Ok(());
                }
                total = match total.checked_add(bytes.len()) {
                    Some(total) if total <= maximum_bytes => total,
                    _ => {
                        let _ = channel.send(&Frame {
                            request_id: hello.request_id,
                            message: Message::Failed {
                                class: FailureClass::ResourceLimit,
                                page_locks: channel.lock_status().combine(plaintext_status),
                            },
                        });
                        return Ok(());
                    }
                };
                plaintext_status = plaintext_status.combine(bytes.lock_status());
                payloads.push(bytes);
                next_sequence += 1;
            }
            Message::End { chunks } if chunks == next_sequence => {
                let mut input = SecretBytes::zeroed(total).map_err(|_| WorkerError::Protocol)?;
                plaintext_status = plaintext_status.combine(input.lock_status());
                let mut offset = 0;
                for chunk in &payloads {
                    let end = offset + chunk.len();
                    input.expose_mut()[offset..end].copy_from_slice(chunk.expose());
                    offset = end;
                }
                let result = match transform.take().expect("transform called once")(input.expose())
                {
                    Ok(result) => result,
                    Err(class) => {
                        let _ = channel.send(&Frame {
                            request_id: hello.request_id,
                            message: Message::Failed {
                                class,
                                page_locks: channel.lock_status().combine(plaintext_status),
                            },
                        });
                        return Ok(());
                    }
                };
                plaintext_status = plaintext_status.combine(result.lock_status());
                let mut result_chunks = 0u64;
                for bytes in result.expose().chunks(osv_worker_protocol::MAX_DATA_LEN) {
                    let protected = SecretBytes::new(bytes).map_err(|_| WorkerError::Protocol)?;
                    plaintext_status = plaintext_status.combine(protected.lock_status());
                    channel.send(&Frame {
                        request_id: hello.request_id,
                        message: Message::ResultData {
                            sequence: result_chunks,
                            bytes: protected,
                        },
                    })?;
                    result_chunks += 1;
                }
                channel.send(&Frame {
                    request_id: hello.request_id,
                    message: Message::ResultEnd {
                        chunks: result_chunks,
                    },
                })?;
                let _ = channel.send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Complete {
                        page_locks: channel.lock_status().combine(plaintext_status),
                    },
                })?;
                return Ok(());
            }
            Message::Cancel => return Ok(()),
            _ => {
                let _ = channel.send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Failed {
                        class: FailureClass::InvalidInput,
                        page_locks: channel.lock_status().combine(plaintext_status),
                    },
                })?;
                return Err(WorkerError::Protocol);
            }
        }
    }
}
