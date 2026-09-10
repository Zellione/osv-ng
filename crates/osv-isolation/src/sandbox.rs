use std::{error::Error, fmt, io};

pub const NO_NEW_PRIVS: u32 = 1 << 0;
pub const RESOURCE_LIMITS: u32 = 1 << 1;
pub const SECCOMP: u32 = 1 << 2;
pub const LANDLOCK: u32 = 1 << 3;
pub const DESCRIPTOR_ALLOWLIST: u32 = 1 << 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxReport {
    flags: u32,
}
impl SandboxReport {
    pub fn flags(self) -> u32 {
        self.flags
    }
    pub fn landlock_enforced(self) -> bool {
        self.flags & LANDLOCK != 0
    }
}

#[derive(Debug)]
pub struct SandboxError {
    operation: &'static str,
    source: io::Error,
}
impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker sandbox setup failed at {}", self.operation)
    }
}
impl Error for SandboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn apply_worker_sandbox(control_fd: i32) -> Result<SandboxReport, SandboxError> {
    if control_fd != crate::WORKER_CONTROL_FD {
        return Err(failure("descriptor allowlist"));
    }
    osv_crypto::harden_process().map_err(|_| failure("dump protection"))?;
    set_limits()?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(failure("parent-death signal"));
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(failure("no_new_privs"));
    }
    close_unlisted()?;
    let landlock = apply_landlock().unwrap_or(false);
    apply_seccomp()?;
    Ok(SandboxReport {
        flags: NO_NEW_PRIVS
            | RESOURCE_LIMITS
            | SECCOMP
            | DESCRIPTOR_ALLOWLIST
            | if landlock { LANDLOCK } else { 0 },
    })
}

#[cfg(target_os = "linux")]
fn failure(operation: &'static str) -> SandboxError {
    SandboxError {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_limits() -> Result<(), SandboxError> {
    let limits = [
        (libc::RLIMIT_CORE, 0, 0),
        (libc::RLIMIT_FSIZE, 0, 0),
        (libc::RLIMIT_NOFILE, 32, 32),
        (libc::RLIMIT_AS, 1024 * 1024 * 1024, 1024 * 1024 * 1024),
        (libc::RLIMIT_CPU, 30, 30),
        (libc::RLIMIT_STACK, 16 * 1024 * 1024, 16 * 1024 * 1024),
    ];
    for (resource, current, maximum) in limits {
        let limit = libc::rlimit {
            rlim_cur: current,
            rlim_max: maximum,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(failure("resource limits"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn close_unlisted() -> Result<(), SandboxError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(failure("descriptor allowlist"))
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_landlock() -> Result<bool, SandboxError> {
    const CREATE_VERSION: u32 = 1;
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            CREATE_VERSION,
        )
    };
    if version < 1 {
        return Ok(false);
    }
    let mut access = (1_u64 << 13) - 1;
    if version >= 2 {
        access |= 1 << 13;
    }
    if version >= 3 {
        access |= 1 << 14;
    }
    if version >= 5 {
        access |= 1 << 15;
    }
    let attributes = LandlockRulesetAttr {
        handled_access_fs: access,
    };
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    } as i32;
    if ruleset < 0 {
        return Ok(false);
    }
    let restricted = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) };
    unsafe {
        libc::close(ruleset);
    }
    if restricted == 0 {
        Ok(true)
    } else {
        Err(failure("Landlock restriction"))
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_seccomp() -> Result<(), SandboxError> {
    const LD_W_ABS: u16 = 0x20;
    const JMP_JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const ERRNO: u32 = 0x0005_0000;
    const EPERM: u32 = libc::EPERM as u32;
    const ENOSYS: u32 = libc::ENOSYS as u32;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    let denied = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_creat,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_statx,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_prctl,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_io_uring_setup,
    ];
    let mut filter = Vec::with_capacity(5 + denied.len() * 2);
    filter.push(libc::sock_filter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    filter.push(libc::sock_filter {
        code: JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH,
    });
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: KILL_PROCESS,
    });
    filter.push(libc::sock_filter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    #[cfg(target_arch = "x86_64")]
    {
        const JMP_JGE_K: u16 = 0x35;
        filter.push(libc::sock_filter {
            code: JMP_JGE_K,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        });
        filter.push(libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: KILL_PROCESS,
        });
    }
    filter.push(libc::sock_filter {
        code: JMP_JEQ_K,
        jt: 0,
        jf: 1,
        k: libc::SYS_clone3 as u32,
    });
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: ERRNO | ENOSYS,
    });
    const JMP_JSET_K: u16 = 0x45;
    filter.push(libc::sock_filter {
        code: JMP_JEQ_K,
        jt: 0,
        jf: 3,
        k: libc::SYS_clone as u32,
    });
    filter.push(libc::sock_filter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 16,
    });
    filter.push(libc::sock_filter {
        code: JMP_JSET_K,
        jt: 1,
        jf: 0,
        k: libc::CLONE_THREAD as u32,
    });
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: ERRNO | EPERM,
    });
    filter.push(libc::sock_filter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for syscall in denied {
        filter.push(libc::sock_filter {
            code: JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: ERRNO | EPERM,
        });
    }
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: ALLOW,
    });
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("small filter"),
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
        return Err(failure("seccomp restriction"));
    }
    Ok(())
}
