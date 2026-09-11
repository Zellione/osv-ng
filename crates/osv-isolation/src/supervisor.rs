use crate::{FramedChannel, PlaintextBuffer, TransportError};
use osv_worker_protocol::{BrokerMachine, BrokerState, Frame, Message, Role, VERSION};
use std::{
    error::Error,
    fmt, io,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct StartupChild(Option<Child>);
impl StartupChild {
    fn release(mut self) -> Child {
        self.0.take().expect("startup child is present")
    }
}
impl Drop for StartupChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SupervisorLimits {
    pub startup: Duration,
    pub operation: Duration,
    pub cancellation_grace: Duration,
    pub maximum_restarts: u8,
}
impl Default for SupervisorLimits {
    fn default() -> Self {
        Self {
            startup: Duration::from_secs(2),
            operation: Duration::from_secs(30),
            cancellation_grace: Duration::from_millis(250),
            maximum_restarts: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClass {
    Success,
    WorkerFailure,
    Signal,
    Deadline,
    Protocol,
    Spawn,
}

#[derive(Debug)]
pub struct SupervisorError {
    pub class: ExitClass,
    source: Option<Box<dyn Error + Send + Sync>>,
}
impl SupervisorError {
    fn new(class: ExitClass, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            class,
            source: Some(Box::new(source)),
        }
    }
}
impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "isolated worker failed ({:?})", self.class)
    }
}
impl Error for SupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|error| error as _)
    }
}

pub struct Supervisor {
    child: Child,
    channel: FramedChannel,
    machine: BrokerMachine,
    limits: SupervisorLimits,
    sandbox_flags: u32,
    request_id: u64,
    operation_deadline: Instant,
}

impl Supervisor {
    pub fn spawn(
        executable: &Path,
        role: Role,
        request_id: u64,
        limits: SupervisorLimits,
    ) -> Result<Self, SupervisorError> {
        let mut last_error = None;
        for _ in 0..=limits.maximum_restarts {
            match Self::spawn_once(executable, role, request_id, limits) {
                Ok(supervisor) => return Ok(supervisor),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("at least one startup attempt"))
    }

    fn spawn_once(
        executable: &Path,
        role: Role,
        request_id: u64,
        limits: SupervisorLimits,
    ) -> Result<Self, SupervisorError> {
        let (parent, child_socket) =
            UnixStream::pair().map_err(|e| SupervisorError::new(ExitClass::Spawn, e))?;
        parent
            .set_nonblocking(true)
            .map_err(|e| SupervisorError::new(ExitClass::Spawn, e))?;
        let mut command = Command::new(executable);
        command.arg("--worker");
        let child_fd = OwnedFd::from(child_socket);
        command
            .env_clear()
            .stdin(Stdio::from(child_fd))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|e| SupervisorError::new(ExitClass::Spawn, e))?;
        drop(command);
        let startup_child = StartupChild(Some(child));
        let mut channel = FramedChannel::new(parent);
        channel.set_deadline(Some(Instant::now() + limits.startup));
        let mut machine = BrokerMachine::new(request_id);
        let hello = Frame {
            request_id,
            message: Message::Hello {
                minimum: VERSION,
                maximum: VERSION,
            },
        };
        machine.sent(&hello).map_err(protocol)?;
        channel.send(&hello).map_err(transport)?;
        let ready = channel.receive().map_err(transport)?;
        machine.received(&ready).map_err(protocol)?;
        let Message::Ready { sandbox_flags, .. } = ready.message else {
            unreachable!()
        };
        let required = crate::NO_NEW_PRIVS
            | crate::RESOURCE_LIMITS
            | crate::SECCOMP
            | crate::DESCRIPTOR_ALLOWLIST;
        if sandbox_flags & required != required {
            return Err(SupervisorError {
                class: ExitClass::Protocol,
                source: None,
            });
        }
        let start = Frame {
            request_id,
            message: Message::Start { role },
        };
        machine.sent(&start).map_err(protocol)?;
        channel.send(&start).map_err(transport)?;
        let operation_deadline = Instant::now() + limits.operation;
        channel.set_deadline(Some(operation_deadline));
        Ok(Self {
            child: startup_child.release(),
            channel,
            machine,
            limits,
            sandbox_flags,
            request_id,
            operation_deadline,
        })
    }

    pub fn sandbox_flags(&self) -> u32 {
        self.sandbox_flags
    }

    pub fn send_authenticated(
        &mut self,
        sequence: u64,
        plaintext: PlaintextBuffer,
    ) -> Result<(), SupervisorError> {
        self.refresh_operation_timeout()?;
        let mut frame = Frame {
            request_id: self.request_id(),
            message: Message::Data {
                sequence,
                bytes: plaintext.as_slice().to_vec(),
            },
        };
        self.machine.sent(&frame).map_err(protocol)?;
        let result = self.channel.send(&frame).map_err(transport);
        if let Message::Data { bytes, .. } = &mut frame.message {
            zeroize::Zeroize::zeroize(bytes.as_mut_slice());
        }
        result
    }

    pub fn finish(mut self) -> Result<ExitClass, SupervisorError> {
        self.refresh_operation_timeout()?;
        let chunks = match self.machine.state() {
            BrokerState::Streaming { next_sequence } => next_sequence,
            _ => {
                return Err(SupervisorError {
                    class: ExitClass::Protocol,
                    source: None,
                });
            }
        };
        let end = Frame {
            request_id: self.request_id(),
            message: Message::End { chunks },
        };
        self.machine.sent(&end).map_err(protocol)?;
        self.channel.send(&end).map_err(transport)?;
        let result = self.channel.receive().map_err(transport)?;
        self.machine.received(&result).map_err(protocol)?;
        let response_class = match result.message {
            Message::Complete => ExitClass::Success,
            Message::Failed { .. } => ExitClass::WorkerFailure,
            _ => ExitClass::Protocol,
        };
        let status = self.wait_for_exit()?;
        if response_class == ExitClass::Success {
            Ok(classify_status(status))
        } else {
            Ok(response_class)
        }
    }

    pub fn cancel(&mut self) -> ExitClass {
        let deadline = Instant::now() + self.limits.cancellation_grace;
        let cancel = Frame {
            request_id: self.request_id(),
            message: Message::Cancel,
        };
        let _ = self.machine.sent(&cancel);
        let _ = self.channel.send_nonblocking(&cancel);
        let _ = self.channel.stream().shutdown(std::net::Shutdown::Both);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return classify_status(status);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        ExitClass::Deadline
    }

    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn refresh_operation_timeout(&mut self) -> Result<(), SupervisorError> {
        let Some(_remaining) = self
            .operation_deadline
            .checked_duration_since(Instant::now())
        else {
            return Err(SupervisorError {
                class: ExitClass::Deadline,
                source: None,
            });
        };
        self.channel.set_deadline(Some(self.operation_deadline));
        Ok(())
    }

    fn wait_for_exit(&mut self) -> Result<ExitStatus, SupervisorError> {
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| SupervisorError::new(ExitClass::WorkerFailure, error))?
            {
                return Ok(status);
            }
            let Some(remaining) = self
                .operation_deadline
                .checked_duration_since(Instant::now())
            else {
                return Err(SupervisorError {
                    class: ExitClass::Deadline,
                    source: None,
                });
            };
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

fn protocol(error: osv_worker_protocol::ProtocolError) -> SupervisorError {
    SupervisorError::new(ExitClass::Protocol, error)
}
fn transport(error: TransportError) -> SupervisorError {
    let class = match &error {
        TransportError::Io(source)
            if matches!(
                source.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            ExitClass::Deadline
        }
        TransportError::Protocol(_) => ExitClass::Protocol,
        _ => ExitClass::WorkerFailure,
    };
    SupervisorError::new(class, error)
}
fn classify_status(status: ExitStatus) -> ExitClass {
    if status.success() {
        ExitClass::Success
    } else if status.code().is_none() {
        ExitClass::Signal
    } else {
        ExitClass::WorkerFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    #[allow(unsafe_code)]
    fn cancellation_deadline_includes_a_saturated_nonreading_channel() {
        let (broker, _nonreading_worker) = UnixStream::pair().unwrap();
        broker.set_nonblocking(true).unwrap();
        let bytes = [0_u8; 4096];
        loop {
            let result = unsafe {
                libc::send(
                    broker.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if result < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }

        let grace = Duration::from_millis(100);
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let mut supervisor = Supervisor {
            child,
            channel: FramedChannel::new(broker),
            machine: BrokerMachine::new(1),
            limits: SupervisorLimits {
                startup: Duration::from_secs(1),
                operation: Duration::from_secs(30),
                cancellation_grace: grace,
                maximum_restarts: 0,
            },
            sandbox_flags: 0,
            request_id: 1,
            operation_deadline: Instant::now() + Duration::from_secs(30),
        };

        let started = Instant::now();
        assert_eq!(supervisor.cancel(), ExitClass::Deadline);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "cancellation inherited the operation deadline"
        );
    }
}
