use osv_isolation::{FramedChannel, WORKER_CONTROL_FD, apply_worker_sandbox};
use osv_worker_protocol::{Frame, Message, Role, VERSION};
use std::{os::fd::FromRawFd, os::unix::net::UnixStream, time::Duration};

#[allow(unsafe_code)]
fn make_landlock_unavailable() {
    const LD_W_ABS: u16 = 0x20;
    const JMP_JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    let mut filter = [
        libc::sock_filter {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_landlock_create_ruleset as u32,
        },
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: ERRNO | libc::ENOSYS as u32,
        },
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap(),
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program,) },
        0
    );
}

#[allow(unsafe_code)]
fn channel_after_sandbox() -> FramedChannel {
    apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
    FramedChannel::new(unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) })
}

#[allow(unsafe_code)]
fn queued_signal_is_denied(peer: libc::pid_t, pidfd: i32) -> bool {
    let info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let queued = unsafe { libc::syscall(libc::SYS_rt_sigqueueinfo, peer, libc::SIGTERM, &info) };
    let queued_errno = std::io::Error::last_os_error().raw_os_error();
    let thread_queued = unsafe {
        libc::syscall(
            libc::SYS_rt_tgsigqueueinfo,
            peer,
            peer,
            libc::SIGTERM,
            &info,
        )
    };
    let thread_queued_errno = std::io::Error::last_os_error().raw_os_error();
    let pidfd_queued = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let pidfd_queued_errno = std::io::Error::last_os_error().raw_os_error();
    queued == -1
        && queued_errno == Some(libc::EPERM)
        && thread_queued == -1
        && thread_queued_errno == Some(libc::EPERM)
        && pidfd_queued == -1
        && pidfd_queued_errno == Some(libc::EPERM)
}

#[allow(unsafe_code)]
fn disable_page_locks() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
}

fn handshake(channel: &mut FramedChannel, hello: &Frame) {
    let _ = channel
        .send(&Frame {
            request_id: hello.request_id,
            message: Message::Ready {
                version: VERSION,
                sandbox_flags: osv_isolation::NO_NEW_PRIVS
                    | osv_isolation::RESOURCE_LIMITS
                    | osv_isolation::SECCOMP
                    | osv_isolation::DESCRIPTOR_ALLOWLIST,
                page_locks: channel.lock_status(),
            },
        })
        .unwrap();
    let (start, _) = channel.receive().unwrap();
    assert_eq!(start.message, Message::Start { role: Role::Media });
}

#[allow(unsafe_code)]
fn run_hostile_worker() {
    let mut channel = FramedChannel::new(unsafe { UnixStream::from_raw_fd(WORKER_CONTROL_FD) });
    let (hello, _) = channel.receive().unwrap();
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
            let _ = channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: 0,
                        sandbox_flags: u32::MAX,
                        page_locks: channel.lock_status(),
                    },
                })
                .unwrap();
        }
        4 => {
            let _ = channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: VERSION,
                        sandbox_flags: 0,
                        page_locks: channel.lock_status(),
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
            let _ = channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Complete {
                        page_locks: channel.lock_status(),
                    },
                })
                .unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        7 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            let _ = channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: VERSION,
                        sandbox_flags: osv_isolation::NO_NEW_PRIVS
                            | osv_isolation::RESOURCE_LIMITS
                            | osv_isolation::SECCOMP
                            | osv_isolation::DESCRIPTOR_ALLOWLIST,
                        page_locks: osv_crypto::LockStatus::Degraded,
                    },
                })
                .unwrap();
            let _ = channel.receive().unwrap();
            let _ = channel.receive().unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        8 => {
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            let _ = channel
                .send(&Frame {
                    request_id: hello.request_id,
                    message: Message::Ready {
                        version: VERSION,
                        sandbox_flags: 0,
                        page_locks: osv_crypto::LockStatus::Degraded,
                    },
                })
                .unwrap();
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
    if argument.as_deref() == Some("degraded-worker") {
        disable_page_locks();
        std::process::exit(if osv_isolation::run_worker(Role::Media).is_ok() {
            0
        } else {
            1
        });
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
        Some("mutation-probe") => {
            let path = arguments.next().expect("probe path");
            let renamed = arguments.next().expect("renamed probe path");
            let landlock_mode = arguments.next();
            if landlock_mode.as_deref() == Some("without-landlock") {
                make_landlock_unavailable();
            }
            let report = apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            if landlock_mode.as_deref() == Some("with-landlock") && !report.landlock_enforced() {
                std::process::exit(77);
            }
            let chmod_denied = std::fs::set_permissions(
                &path,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644),
            )
            .is_err();
            let rename_denied = std::fs::rename(&path, &renamed).is_err();
            let unlink_denied = std::fs::remove_file(&path).is_err();
            if !(chmod_denied && rename_denied && unlink_denied) {
                std::process::exit(1);
            }
        }
        Some("signal-probe") => {
            let peer: libc::pid_t = arguments.next().unwrap().parse().unwrap();
            apply_worker_sandbox(WORKER_CONTROL_FD).unwrap();
            if !queued_signal_is_denied(peer, WORKER_CONTROL_FD) {
                std::process::exit(1);
            }
        }
        Some("transport-degraded-probe") => {
            disable_page_locks();
            let (left, right) = UnixStream::pair().unwrap();
            let mut sender = FramedChannel::new(left);
            let mut receiver = FramedChannel::new(right);
            let frame = Frame {
                request_id: 8,
                message: Message::Data {
                    sequence: 0,
                    bytes: osv_crypto::SecretBytes::new(b"protected payload").unwrap(),
                },
            };
            let send_status = sender.send(&frame).unwrap();
            let (received, receive_status) = receiver.receive().unwrap();
            let Message::Data { bytes, .. } = received.message else {
                std::process::exit(1);
            };
            if send_status != osv_crypto::LockStatus::Degraded
                || receive_status != osv_crypto::LockStatus::Degraded
                || bytes.lock_status() != osv_crypto::LockStatus::Degraded
                || bytes.expose() != b"protected payload"
            {
                std::process::exit(1);
            }
        }
        _ => std::process::exit(64),
    }
}
