use std::{error::Error, fmt, io};

/// Failure to establish release-process dump protections.
#[derive(Debug)]
pub struct HardeningError(io::Error);

impl fmt::Display for HardeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("could not disable process dumps")
    }
}
impl Error for HardeningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Radius-limits process memory disclosure through core dumps and ptrace.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn harden_process() -> Result<(), HardeningError> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(HardeningError(io::Error::last_os_error()));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(HardeningError(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn hardening_disables_core_limits_and_dumpability() {
        harden_process().unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
    }
}
