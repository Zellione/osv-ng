use std::{fmt, io, marker::PhantomData, ptr::NonNull, slice, str};

use zeroize::Zeroize;

/// Whether the operating system accepted the best-effort page lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockStatus {
    /// Pages are locked and marked ineligible for core dumps.
    Locked,
    /// Memory is wipe-on-drop and non-dumpable, but may be swapped.
    Degraded,
}

impl LockStatus {
    /// Combines owners conservatively: any unlocked owner makes the result degraded.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        if matches!(self, Self::Locked) && matches!(other, Self::Locked) {
            Self::Locked
        } else {
            Self::Degraded
        }
    }
}

/// Honest aggregate for project-owned pages and opaque crypto-library temporaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityStatus {
    page_locks: LockStatus,
}

impl SecurityStatus {
    /// Builds a status from the conservative aggregate of project-owned pages.
    #[must_use]
    pub const fn new(page_locks: LockStatus) -> Self {
        Self { page_locks }
    }

    /// Aggregate lock status of every project-owned secret allocation involved.
    #[must_use]
    pub const fn page_locks(self) -> LockStatus {
        self.page_locks
    }

    /// Reports bounded HKDF/HMAC stack temporaries outside project-owned mappings.
    #[must_use]
    pub const fn has_opaque_library_transients(self) -> bool {
        true
    }
}

/// Page-isolated, wipe-on-drop storage for sensitive bytes.
pub struct SecretBytes {
    allocation: platform::Allocation,
    len: usize,
}

/// Typed page-isolated workspace for cryptographic algorithms.
pub(crate) struct SecretArray<T: Default + Zeroize> {
    allocation: platform::ArrayAllocation<T>,
}

impl<T: Default + Zeroize> SecretArray<T> {
    pub(crate) fn zeroed(len: usize) -> io::Result<Self> {
        Ok(Self {
            allocation: platform::ArrayAllocation::new(len)?,
        })
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [T] {
        self.allocation.as_mut_slice()
    }

    pub(crate) const fn lock_status(&self) -> LockStatus {
        self.allocation.lock_status()
    }
}

impl SecretBytes {
    /// Allocates isolated pages and copies `bytes` into them.
    pub fn new(bytes: &[u8]) -> io::Result<Self> {
        let allocation = platform::Allocation::new(bytes.len())?;
        let mut value = Self {
            allocation,
            len: bytes.len(),
        };
        value.expose_mut().copy_from_slice(bytes);
        Ok(value)
    }

    /// Copies bytes into isolated storage and wipes the caller's mutable buffer,
    /// including when allocation fails.
    pub fn take(bytes: &mut [u8]) -> io::Result<Self> {
        let result = Self::new(bytes);
        bytes.zeroize();
        result
    }

    /// Allocates zero-filled isolated pages.
    pub fn zeroed(len: usize) -> io::Result<Self> {
        Ok(Self {
            allocation: platform::Allocation::new(len)?,
            len,
        })
    }

    /// Returns the number of meaningful bytes, excluding page rounding.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Reports whether the secret is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reports page-lock status without exposing contents.
    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.allocation.lock_status()
    }

    /// Explicitly borrows the secret. Callers must not log or persist it.
    #[must_use]
    #[allow(unsafe_code)]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: Allocation owns at least `len` initialized bytes until drop.
        unsafe { slice::from_raw_parts(self.allocation.as_ptr(), self.len) }
    }

    /// Explicitly mutably borrows the secret for cryptographic operations.
    #[allow(unsafe_code)]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` guarantees exclusive access.
        unsafe { slice::from_raw_parts_mut(self.allocation.as_ptr(), self.len) }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.expose_mut().zeroize();
    }
}

/// UTF-8 secret text held in [`SecretBytes`].
pub struct SecretString(SecretBytes);

impl SecretString {
    /// Copies text into page-isolated secret storage.
    pub fn new(value: &str) -> io::Result<Self> {
        SecretBytes::new(value.as_bytes()).map(Self)
    }

    /// Explicitly borrows the secret text.
    #[must_use]
    pub fn expose(&self) -> &str {
        str::from_utf8(self.0.expose()).expect("SecretString invariant")
    }

    /// Reports the backing page-lock status.
    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.0.lock_status()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// A fixed-size key held in isolated, wipe-on-drop pages.
pub struct SecretKey<const N: usize> {
    bytes: SecretBytes,
    marker: PhantomData<[u8; N]>,
}

impl<const N: usize> SecretKey<N> {
    /// Moves an exact-size key into secure storage and wipes the caller's buffer.
    pub fn take(value: &mut [u8; N]) -> io::Result<Self> {
        let result = SecretBytes::new(&value[..]).map(|bytes| Self {
            bytes,
            marker: PhantomData,
        });
        value.zeroize();
        result
    }

    /// Allocates a zero-filled key for an output operation.
    pub fn zeroed() -> io::Result<Self> {
        Ok(Self {
            bytes: SecretBytes::zeroed(N)?,
            marker: PhantomData,
        })
    }

    /// Explicitly borrows the key.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        self.bytes.expose().try_into().expect("fixed key length")
    }

    /// Explicitly mutably borrows the key.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        self.bytes
            .expose_mut()
            .try_into()
            .expect("fixed key length")
    }

    /// Reports the backing page-lock status.
    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.bytes.lock_status()
    }
}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod platform {
    use super::{LockStatus, NonNull};
    use std::{io, ptr};
    use zeroize::Zeroize;

    pub(super) struct Allocation {
        pointer: NonNull<u8>,
        allocation_len: usize,
        lock_status: LockStatus,
    }

    impl Allocation {
        pub(super) fn new(requested_len: usize) -> io::Result<Self> {
            let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size_raw <= 0 {
                return Err(io::Error::last_os_error());
            }
            let page_size = usize::try_from(page_size_raw)
                .map_err(|_| io::Error::other("invalid system page size"))?;
            let allocation_len = requested_len
                .max(1)
                .checked_add(page_size - 1)
                .and_then(|value| value.checked_div(page_size))
                .and_then(|pages| pages.checked_mul(page_size))
                .ok_or_else(|| io::Error::other("secret allocation is too large"))?;
            let raw = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    allocation_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if raw == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let pointer = NonNull::new(raw.cast::<u8>()).expect("mmap returned null");
            if unsafe { libc::madvise(raw, allocation_len, libc::MADV_DONTDUMP) } != 0 {
                unsafe { libc::munmap(raw, allocation_len) };
                return Err(io::Error::last_os_error());
            }
            let lock_status = lock_pages(raw, allocation_len);
            Ok(Self {
                pointer,
                allocation_len,
                lock_status,
            })
        }

        pub(super) const fn as_ptr(&self) -> *mut u8 {
            self.pointer.as_ptr()
        }
        pub(super) const fn lock_status(&self) -> LockStatus {
            self.lock_status
        }
    }

    impl Drop for Allocation {
        fn drop(&mut self) {
            #[cfg(test)]
            LAST_DROP_WAS_ZERO.with(|last| {
                // SAFETY: the mapping remains valid until `munmap` below.
                let bytes = unsafe {
                    std::slice::from_raw_parts(self.pointer.as_ptr(), self.allocation_len)
                };
                last.set(Some(bytes.iter().all(|byte| *byte == 0)));
            });
            // mmap gives each owner whole pages, so munlock cannot affect another owner.
            if self.lock_status == LockStatus::Locked {
                unsafe { libc::munlock(self.pointer.as_ptr().cast(), self.allocation_len) };
            }
            unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.allocation_len) };
        }
    }

    pub(super) struct ArrayAllocation<T: Default + Zeroize> {
        pointer: NonNull<T>,
        len: usize,
        allocation_len: usize,
        lock_status: LockStatus,
    }

    impl<T: Default + Zeroize> ArrayAllocation<T> {
        pub(super) fn new(len: usize) -> io::Result<Self> {
            if std::mem::size_of::<T>() == 0 {
                return Err(io::Error::other("zero-sized secure array type"));
            }
            let requested_len = len
                .checked_mul(std::mem::size_of::<T>())
                .ok_or_else(|| io::Error::other("secret allocation is too large"))?;
            let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size_raw <= 0 {
                return Err(io::Error::last_os_error());
            }
            let page_size = usize::try_from(page_size_raw)
                .map_err(|_| io::Error::other("invalid system page size"))?;
            if std::mem::align_of::<T>() > page_size {
                return Err(io::Error::other("secure array alignment is too large"));
            }
            let allocation_len = requested_len
                .max(1)
                .checked_add(page_size - 1)
                .and_then(|value| value.checked_div(page_size))
                .and_then(|pages| pages.checked_mul(page_size))
                .ok_or_else(|| io::Error::other("secret allocation is too large"))?;
            let raw = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    allocation_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if raw == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::madvise(raw, allocation_len, libc::MADV_DONTDUMP) } != 0 {
                unsafe { libc::munmap(raw, allocation_len) };
                return Err(io::Error::last_os_error());
            }
            let lock_status = lock_pages(raw, allocation_len);
            let pointer = NonNull::new(raw.cast::<T>()).expect("mmap returned null");
            for index in 0..len {
                unsafe { pointer.as_ptr().add(index).write(T::default()) };
            }
            Ok(Self {
                pointer,
                len,
                allocation_len,
                lock_status,
            })
        }

        pub(super) fn as_mut_slice(&mut self) -> &mut [T] {
            unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) }
        }

        pub(super) const fn lock_status(&self) -> LockStatus {
            self.lock_status
        }
    }

    impl<T: Default + Zeroize> Drop for ArrayAllocation<T> {
        fn drop(&mut self) {
            let values = unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) };
            for value in values.iter_mut() {
                value.zeroize();
            }
            unsafe { ptr::drop_in_place(values) };
            if self.lock_status == LockStatus::Locked {
                unsafe { libc::munlock(self.pointer.as_ptr().cast(), self.allocation_len) };
            }
            unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.allocation_len) };
        }
    }

    #[cfg(test)]
    std::thread_local! {
        static LAST_DROP_WAS_ZERO: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
        static FORCE_NEXT_LOCK_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn lock_pages(pointer: *mut libc::c_void, len: usize) -> LockStatus {
        #[cfg(test)]
        if FORCE_NEXT_LOCK_FAILURE.with(|forced| forced.replace(false)) {
            return LockStatus::Degraded;
        }
        if unsafe { libc::mlock(pointer, len) } == 0 {
            LockStatus::Locked
        } else {
            LockStatus::Degraded
        }
    }

    #[cfg(test)]
    pub(super) fn take_last_drop_was_zero() -> Option<bool> {
        LAST_DROP_WAS_ZERO.with(std::cell::Cell::take)
    }

    #[cfg(test)]
    pub(super) fn force_next_lock_failure() {
        FORCE_NEXT_LOCK_FAILURE.with(|forced| forced.set(true));
    }
}

#[cfg(test)]
pub(crate) fn force_next_lock_failure() {
    platform::force_next_lock_failure();
}

#[cfg(not(target_os = "linux"))]
compile_error!("osv-ng secure memory currently requires Linux");

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct DropProbe(u64);

    impl Zeroize for DropProbe {
        fn zeroize(&mut self) {
            self.0 = 0;
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            assert_eq!(self.0, 0, "typed secret was dropped before wiping");
        }
    }

    #[test]
    fn owners_round_trip_and_redact_debug() {
        let bytes = SecretBytes::new(b"sensitive").unwrap();
        let text = SecretString::new("password").unwrap();
        let mut key_input = [7_u8; 32];
        let key = SecretKey::take(&mut key_input).unwrap();
        assert_eq!(bytes.expose(), b"sensitive");
        assert_eq!(text.expose(), "password");
        assert_eq!(key.expose(), &[7; 32]);
        assert_eq!(key_input, [0; 32]);
        assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
        assert_eq!(format!("{text:?}"), "SecretString([REDACTED])");
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
    }

    #[test]
    fn zero_length_owner_is_supported() {
        let secret = SecretBytes::new(&[]).unwrap();
        assert!(secret.is_empty());
        assert!(secret.expose().is_empty());
    }

    #[test]
    fn drop_wipes_the_complete_owned_mapping_before_release() {
        drop(SecretBytes::new(b"wipe this value").unwrap());
        assert_eq!(platform::take_last_drop_was_zero(), Some(true));
    }

    #[test]
    fn impossible_allocation_size_fails_without_allocating() {
        assert!(SecretBytes::zeroed(usize::MAX).is_err());
    }

    #[test]
    fn typed_workspace_wipes_elements_before_drop() {
        let mut workspace = SecretArray::<DropProbe>::zeroed(2).unwrap();
        workspace.expose_mut()[0].0 = 0xfeed_face;
        workspace.expose_mut()[1].0 = 0xdead_beef;
        drop(workspace);
    }

    #[test]
    fn take_wipes_the_callers_buffer() {
        let mut input = b"caller-owned secret".to_vec();
        let secret = SecretBytes::take(&mut input).unwrap();
        assert!(input.iter().all(|byte| *byte == 0));
        assert_eq!(secret.expose(), b"caller-owned secret");
    }
}
