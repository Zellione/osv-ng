use osv_isolation::{FramedChannel, WORKER_CONTROL_FD, apply_worker_sandbox};
use osv_worker_protocol::{Frame, Message, Role, VERSION};
use std::{os::fd::FromRawFd, os::unix::net::UnixStream, time::Duration};

#[allow(unsafe_code)]
fn channel_after_sandbox() -> FramedChannel {
    apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
    FramedChannel::new(unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) })
}

fn handshake(channel: &mut FramedChannel, hello: &Frame) {
    channel
        .send(&Frame {
            request_id: hello.request_id,
            message: Message::Ready {
                version: VERSION,
                sandbox_flags: osv_isolation::NO_NEW_PRIVS
                    | osv_isolation::RESOURCE_LIMITS
                    | osv_isolation::SECCOMP
                    | osv_isolation::DESCRIPTOR_ALLOWLIST,
            },
        })
        .unwrap();
    let start = channel.receive().unwrap();
    assert_eq!(start.message, Message::Start { role: Role::Media });
}

#[allow(unsafe_code)]
fn run_hostile_worker() {
    let mut channel = FramedChannel::new(unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) });
    let hello = channel.receive().unwrap();
    match hello.request_id {
        1 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        2 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            handshake(&mut channel, &hello);
            let _ = channel.receive();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        3 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: 0,
                        sandbox_flags: u32::MAX,
                    },
                })
                .unwrap();
        }
        4 => {
            channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: VERSION,
                        sandbox_flags: 0,
                    },
                })
                .unwrap();
        }
        5 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            std::process::exit(23);
        }
        6 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            handshake(&mut channel, &hello);
            let _ = channel.receive().unwrap();
            channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Complete,
                })
                .unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        _ => std::process::exit(64),
    }
}

fn main() {
    let mut arguments = std::env::args();
    let _executable = arguments.next().unwrap_or_default();
    let argument = arguments.next();
    if argument.as_deref() == Some("--worker") {
        run_hostile_worker();
        return;
    }
    let mode = argument.as_deref();
    match mode {
        Some("probe") => {
            let _channel = channel_after_sandbox();
            let file_denied = std::fs::File::open("/etc/passwd").is_err();
            let enumeration_denied = std::fs::read_dir("/").is_err();
            #[allow(unsafe_code)]
            let socket_denied = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) } < 0;
            #[allow(unsafe_code)]
            let process_denied = unsafe { libc::fork() } < 0;
            #[allow(unsafe_code)]
            let dump_change_denied = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) } < 0;
            #[allow(unsafe_code)]
            let extra_descriptor_closed = unsafe { libc::fcntl(3, libc::F_GETFD) } < 0;
            let thread_allowed = std::thread::Builder::new()
                .spawn(|| 7)
                .and_then(|thread| thread.join().map_err(|_| std::io::Error::other("panic")))
                .is_ok_and(|value| value == 7);
            #[allow(unsafe_code)]
            let oversized_mapping_denied = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    2 * 1024 * 1024 * 1024,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) == libc::MAP_FAILED
            };
            let failures = u8::from(!file_denied)
                | (u8::from(!socket_denied) << 1)
                | (u8::from(!process_denied) << 2)
                | (u8::from(!dump_change_denied) << 3)
                | (u8::from(!extra_descriptor_closed) << 4)
                | (u8::from(!thread_allowed) << 5)
                | (u8::from(!enumeration_denied || !oversized_mapping_denied) << 6);
            if failures != 0 {
                std::process::exit(i32::from(failures));
            }
        }
        _ => std::process::exit(64),
    }
}
