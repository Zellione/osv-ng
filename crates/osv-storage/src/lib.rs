//! Durable vault-header storage and credential rewrap recovery.

mod object;

pub use object::{
    CiphertextInventory, CiphertextObject, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_LOGICAL_LEN,
    MIN_CHUNK_SIZE, OBJECT_FORMAT_VERSION, OBJECT_HEADER_LEN, ObjectDescriptor, ObjectError,
    ObjectId, ObjectPreamble, ObjectReader, ObjectRole, PUBLISH_POINTS, PublishFaultInjector,
    PublishIoPoint, PublishPoint, RemovalFaultInjector, RemovalIoPoint, RemovalPoint,
    WrappedObjectKey,
};

use std::{
    cell::Cell,
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use osv_crypto::{
    DerivedKeys, HEADER_LEN, HeaderError, KdfParams, MasterKey, Password, RandomSource,
    SecretBytes, SecurityStatus, SystemRandom, VaultHeader, derive_subkeys, harden_process,
};

const HEADER_NAME: &str = "vault.header";
const NEW_HEADER_NAME: &str = "vault.header.new";
const BACKUP_HEADER_NAME: &str = "vault.header.prev";

/// A successfully authenticated vault without a catalog or object store.
pub struct UnlockedVault {
    directory: File,
    header: VaultHeader,
    master_key: MasterKey,
    derived_keys: DerivedKeys,
    security_status: SecurityStatus,
    source: HeaderSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderSource {
    Current,
    RecoveryBackup,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedVault")
            .field("header", &self.header)
            .field("keys", &"[REDACTED]")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

impl UnlockedVault {
    /// Creates an owner-only vault directory and durable versioned header.
    pub fn create(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
    ) -> Result<Self, VaultError> {
        Self::create_with_rng(path, password, keyfile, kdf_params, &mut SystemRandom)
    }

    /// Injectable create variant for vectors and randomness-failure tests.
    pub fn create_with_rng(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        random: &mut impl RandomSource,
    ) -> Result<Self, VaultError> {
        harden_process()?;
        let (parent_path, name) = split_parent(path)?;
        let parent = platform::open_directory(&parent_path)?;
        platform::create_directory_at(&parent, &name)?;
        let directory = platform::open_directory_at(&parent, &name)?;
        let result = (|| {
            let master_key = MasterKey::generate(random)?;
            let header = VaultHeader::create(&master_key, password, keyfile, kdf_params, random)?;
            write_new_file(&directory, HEADER_NAME, header.as_bytes())?;
            directory.sync_all()?;
            parent.sync_all()?;
            let derived_keys = derive_subkeys(&master_key, header.vault_id().as_bytes())?;
            let page_locks = header
                .creation_lock_status()
                .expect("new headers record creation status")
                .combine(master_key.lock_status())
                .combine(derived_keys.lock_status());
            let security_status = SecurityStatus::new(page_locks);
            Ok((header, master_key, derived_keys, security_status))
        })();
        match result {
            Ok((header, master_key, derived_keys, security_status)) => Ok(Self {
                directory,
                header,
                master_key,
                derived_keys,
                security_status,
                source: HeaderSource::Current,
            }),
            Err(error) => {
                // Creation failures deliberately preserve all names for explicit
                // recovery. Even an anchored unlink could remove a file substituted
                // between `openat` and cleanup when the parent is attacker-writable.
                let _ = directory.sync_all();
                let _ = parent.sync_all();
                Err(error)
            }
        }
    }

    /// Opens with `O_NOFOLLOW`, validates bounds, and authenticates a header.
    /// A durable backup is accepted after an interrupted credential rewrap.
    pub fn unlock(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
    ) -> Result<Self, VaultError> {
        let directory = platform::open_directory(path)?;
        Self::unlock_from_directory(directory, password, keyfile)
    }

    /// Unlocks an already anchored directory handle. Intended for the vault
    /// service, which must acquire its process lock before deriving secrets.
    pub fn unlock_from_directory(
        directory: File,
        password: &Password,
        keyfile: Option<&SecretBytes>,
    ) -> Result<Self, VaultError> {
        harden_process()?;
        let current = read_header(&directory, HEADER_NAME)
            .and_then(|header| unlock_header(header, password, keyfile));
        let (header, master_key, kdf_status, source) = match current {
            Ok((header, master, status)) => (header, master, status, HeaderSource::Current),
            Err(current_error) => {
                match read_header(&directory, BACKUP_HEADER_NAME)
                    .and_then(|header| unlock_header(header, password, keyfile))
                {
                    Ok((header, master, status)) => {
                        (header, master, status, HeaderSource::RecoveryBackup)
                    }
                    Err(_) => return Err(current_error),
                }
            }
        };
        let derived_keys = derive_subkeys(&master_key, header.vault_id().as_bytes())?;
        let page_locks = kdf_status
            .combine(master_key.lock_status())
            .combine(derived_keys.lock_status());
        let security_status = SecurityStatus::new(page_locks);
        Ok(Self {
            directory,
            header,
            master_key,
            derived_keys,
            security_status,
            source,
        })
    }

    /// Duplicates the anchored vault-directory authority for trusted service code.
    pub fn try_clone_directory(&self) -> io::Result<File> {
        self.directory.try_clone()
    }

    #[must_use]
    pub fn object_locator(id: ObjectId, role: ObjectRole) -> String {
        object::object_locator(id, role)
    }

    pub fn ciphertext_inventory(&self) -> Result<CiphertextInventory, ObjectError> {
        object::inventory(&self.directory)
    }

    pub fn remove_ciphertext(&self, id: ObjectId, role: ObjectRole) -> Result<bool, ObjectError> {
        object::remove_object(&self.directory, id, role)
    }

    pub fn remove_ciphertext_with_faults(
        &self,
        id: ObjectId,
        role: ObjectRole,
        faults: &mut impl RemovalFaultInjector,
    ) -> Result<bool, ObjectError> {
        object::remove_object_with_faults(&self.directory, id, role, faults)
    }

    pub fn remove_staging_ciphertext(&self, id: ObjectId) -> Result<bool, ObjectError> {
        object::remove_staging(&self.directory, id)
    }

    pub fn remove_staging_ciphertext_with_faults(
        &self,
        id: ObjectId,
        faults: &mut impl RemovalFaultInjector,
    ) -> Result<bool, ObjectError> {
        object::remove_staging_with_faults(&self.directory, id, faults)
    }

    /// Atomically replaces credential wrapping without changing the master key.
    pub fn rewrap_credentials(
        &mut self,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
    ) -> Result<(), VaultError> {
        self.rewrap_with(
            password,
            keyfile,
            kdf_params,
            &mut SystemRandom,
            &mut NoFaults,
        )
    }

    /// Injectable rewrap used to exhaustively test persistence boundaries.
    pub fn rewrap_with(
        &mut self,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        random: &mut impl RandomSource,
        faults: &mut impl RewrapFaultInjector,
    ) -> Result<(), VaultError> {
        if self.source == HeaderSource::RecoveryBackup {
            return Err(VaultError::RecoveryCredentialsAreNotCurrent);
        }
        remove_if_exists(&self.directory, NEW_HEADER_NAME)?;
        remove_if_exists(&self.directory, BACKUP_HEADER_NAME)?;
        self.directory.sync_all()?;
        let replacement =
            self.header
                .rewrap(&self.master_key, password, keyfile, kdf_params, random)?;
        write_new_file(&self.directory, NEW_HEADER_NAME, replacement.as_bytes())?;
        fail_if_requested(faults, RewrapPoint::NewHeaderDurable)?;
        platform::rename_at(&self.directory, HEADER_NAME, BACKUP_HEADER_NAME)?;
        self.source = HeaderSource::RecoveryBackup;
        fail_if_requested(faults, RewrapPoint::OldHeaderRenamed)?;
        self.directory.sync_all()?;
        fail_if_requested(faults, RewrapPoint::OldRenameDurable)?;
        platform::rename_at(&self.directory, NEW_HEADER_NAME, HEADER_NAME)?;
        fail_if_requested(faults, RewrapPoint::NewHeaderRenamed)?;
        self.directory.sync_all()?;
        fail_if_requested(faults, RewrapPoint::NewRenameDurable)?;
        platform::unlink_at(&self.directory, BACKUP_HEADER_NAME)?;
        fail_if_requested(faults, RewrapPoint::BackupRemoved)?;
        self.directory.sync_all()?;
        fail_if_requested(faults, RewrapPoint::CleanupDurable)?;
        let page_locks = replacement
            .creation_lock_status()
            .expect("rewrapped headers record creation status")
            .combine(self.master_key.lock_status())
            .combine(self.derived_keys.lock_status());
        self.security_status = SecurityStatus::new(page_locks);
        self.header = replacement;
        self.source = HeaderSource::Current;
        Ok(())
    }

    #[must_use]
    pub const fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Purpose-separated keys, all still held by redacting secure owners.
    #[must_use]
    pub const fn derived_keys(&self) -> &DerivedKeys {
        &self.derived_keys
    }

    /// Aggregate status for key, KDF-workspace, and derived-key page locks.
    #[must_use]
    pub const fn security_status(&self) -> SecurityStatus {
        self.security_status
    }

    /// Streams, verifies, and durably publishes one independently encrypted object.
    pub fn publish_object(
        &self,
        source: &mut impl Read,
        logical_len: u64,
        role: ObjectRole,
    ) -> Result<ObjectDescriptor, ObjectError> {
        object::publish_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            source,
            logical_len,
            role,
            DEFAULT_CHUNK_SIZE,
            &mut SystemRandom,
            &mut object::NoPublishFaults,
            None,
        )
    }

    /// Publication variant which reports every transient allocation status,
    /// including allocations released before an error is returned.
    pub fn publish_object_observed(
        &self,
        source: &mut impl Read,
        logical_len: u64,
        role: ObjectRole,
        observer: &Cell<osv_crypto::LockStatus>,
    ) -> Result<ObjectDescriptor, ObjectError> {
        object::publish_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            source,
            logical_len,
            role,
            DEFAULT_CHUNK_SIZE,
            &mut SystemRandom,
            &mut object::NoPublishFaults,
            Some(observer),
        )
    }

    /// Observed publication variant with deterministic persistence failures.
    pub fn publish_object_observed_with_faults(
        &self,
        source: &mut impl Read,
        logical_len: u64,
        role: ObjectRole,
        observer: &Cell<osv_crypto::LockStatus>,
        faults: &mut impl PublishFaultInjector,
    ) -> Result<ObjectDescriptor, ObjectError> {
        object::publish_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            source,
            logical_len,
            role,
            DEFAULT_CHUNK_SIZE,
            &mut SystemRandom,
            faults,
            Some(observer),
        )
    }

    /// Injectable publication variant for persistence and deterministic-vector tests.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_object_with(
        &self,
        source: &mut impl Read,
        logical_len: u64,
        role: ObjectRole,
        chunk_size: u32,
        random: &mut impl RandomSource,
        faults: &mut impl PublishFaultInjector,
    ) -> Result<ObjectDescriptor, ObjectError> {
        object::publish_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            source,
            logical_len,
            role,
            chunk_size,
            random,
            faults,
            None,
        )
    }

    /// Opens an object only after unwrapping its catalog representation and
    /// authenticating its immutable header against this vault and descriptor.
    pub fn open_object(
        &self,
        descriptor: &ObjectDescriptor,
    ) -> Result<ObjectReader<File>, ObjectError> {
        object::open_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            descriptor,
            None,
        )
    }

    /// Object-open variant which reports transient allocation status even when
    /// authentication fails before a reader can be returned.
    pub fn open_object_observed(
        &self,
        descriptor: &ObjectDescriptor,
        observer: &Cell<osv_crypto::LockStatus>,
    ) -> Result<ObjectReader<File>, ObjectError> {
        object::open_object(
            &self.directory,
            self.header.vault_id(),
            &self.derived_keys.object_wrapping,
            descriptor,
            Some(observer),
        )
    }
}

fn unlock_header(
    header: VaultHeader,
    password: &Password,
    keyfile: Option<&SecretBytes>,
) -> Result<(VaultHeader, MasterKey, osv_crypto::LockStatus), VaultError> {
    let (master, status) = header.unlock_with_status(password, keyfile)?;
    Ok((header, master, status))
}

fn read_header(directory: &File, name: &str) -> Result<VaultHeader, VaultError> {
    let mut file = platform::open_at(directory, name, false)?;
    let mut bytes = [0_u8; HEADER_LEN];
    if let Err(error) = file.read_exact(&mut bytes) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Err(VaultError::Header(HeaderError::InvalidLength))
        } else {
            Err(VaultError::Io(error))
        };
    }
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(VaultError::Header(HeaderError::InvalidLength));
    }
    VaultHeader::parse(&bytes).map_err(VaultError::Header)
}

fn write_new_file(directory: &File, name: &str, bytes: &[u8]) -> Result<(), VaultError> {
    let mut file = platform::open_at(directory, name, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_if_exists(directory: &File, name: &str) -> Result<(), VaultError> {
    match platform::unlink_at(directory, name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VaultError::Io(error)),
    }
}

fn split_parent(path: &Path) -> Result<(PathBuf, std::ffi::OsString), VaultError> {
    let name = path
        .file_name()
        .ok_or_else(|| VaultError::Io(io::Error::from(io::ErrorKind::InvalidInput)))?
        .to_owned();
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => PathBuf::from("."),
    };
    Ok((parent, name))
}

fn fail_if_requested(
    faults: &mut impl RewrapFaultInjector,
    point: RewrapPoint,
) -> Result<(), VaultError> {
    if faults.should_fail(point) {
        Err(VaultError::InjectedFault(point))
    } else {
        Ok(())
    }
}

/// Stable credential-rewrap persistence boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewrapPoint {
    NewHeaderDurable,
    OldHeaderRenamed,
    OldRenameDurable,
    NewHeaderRenamed,
    NewRenameDurable,
    BackupRemoved,
    CleanupDurable,
}

impl RewrapPoint {
    /// Stable public name used by crash-test supervisors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NewHeaderDurable => "new-header-durable",
            Self::OldHeaderRenamed => "old-header-renamed",
            Self::OldRenameDurable => "old-rename-durable",
            Self::NewHeaderRenamed => "new-header-renamed",
            Self::NewRenameDurable => "new-rename-durable",
            Self::BackupRemoved => "backup-removed",
            Self::CleanupDurable => "cleanup-durable",
        }
    }
}

pub const REWRAP_POINTS: [RewrapPoint; 7] = [
    RewrapPoint::NewHeaderDurable,
    RewrapPoint::OldHeaderRenamed,
    RewrapPoint::OldRenameDurable,
    RewrapPoint::NewHeaderRenamed,
    RewrapPoint::NewRenameDurable,
    RewrapPoint::BackupRemoved,
    RewrapPoint::CleanupDurable,
];

pub trait RewrapFaultInjector {
    fn should_fail(&mut self, point: RewrapPoint) -> bool;
}
pub struct NoFaults;
impl RewrapFaultInjector for NoFaults {
    fn should_fail(&mut self, _point: RewrapPoint) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    Header(HeaderError),
    Hardening(osv_crypto::HardeningError),
    Kdf(osv_crypto::KdfError),
    InjectedFault(RewrapPoint),
    RecoveryCredentialsAreNotCurrent,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("vault filesystem operation failed"),
            Self::Header(error) => error.fmt(formatter),
            Self::Hardening(error) => error.fmt(formatter),
            Self::Kdf(error) => error.fmt(formatter),
            Self::InjectedFault(point) => write!(formatter, "injected fault at {point:?}"),
            Self::RecoveryCredentialsAreNotCurrent => formatter
                .write_str("credentials belong to a recovery backup, not the current header"),
        }
    }
}

impl Error for VaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Header(error) => Some(error),
            Self::Hardening(error) => Some(error),
            Self::Kdf(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<HeaderError> for VaultError {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}
impl From<osv_crypto::HardeningError> for VaultError {
    fn from(value: osv_crypto::HardeningError) -> Self {
        Self::Hardening(value)
    }
}
impl From<osv_crypto::KdfError> for VaultError {
    fn from(value: osv_crypto::KdfError) -> Self {
        Self::Kdf(value)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        fs,
        os::{fd::FromRawFd, unix::ffi::OsStrExt},
    };

    pub(super) fn directory_names(directory: &File) -> io::Result<Vec<std::ffi::OsString>> {
        let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        fs::read_dir(path)?
            .map(|entry| entry.map(|value| value.file_name()))
            .collect()
    }

    fn dynamic_name(name: &str) -> io::Result<CString> {
        if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    pub(super) fn open_directory(path: &Path) -> io::Result<File> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn create_directory_at(parent: &File, name: &OsStr) -> io::Result<()> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn create_dynamic_directory_at(parent: &File, name: &str) -> io::Result<()> {
        let name = dynamic_name(name)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn open_dynamic_directory_at(parent: &File, name: &str) -> io::Result<File> {
        let name = dynamic_name(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn open_at(directory: &File, name: &str, create: bool) -> io::Result<File> {
        let name = CString::new(name).expect("fixed file name");
        let flags = libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if create {
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            let file = unsafe { File::from_raw_fd(fd) };
            if !create {
                let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vault header is not a singly linked regular file",
                    ));
                }
            }
            Ok(file)
        }
    }

    pub(super) fn open_dynamic_at(
        directory: &File,
        name: &str,
        create: bool,
        writable: bool,
    ) -> io::Result<File> {
        let name = dynamic_name(name)?;
        let flags = libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if create {
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
            } else if writable {
                libc::O_RDWR | libc::O_NONBLOCK
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object is not a singly linked regular file",
            ));
        }
        Ok(file)
    }

    pub(super) fn rename_between(
        old_directory: &File,
        old: &str,
        new_directory: &File,
        new: &str,
    ) -> io::Result<()> {
        let old = dynamic_name(old)?;
        let new = dynamic_name(new)?;
        if unsafe {
            libc::renameat2(
                old_directory.as_raw_fd(),
                old.as_ptr(),
                new_directory.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn same_file(first: &File, second: &File) -> io::Result<bool> {
        fn identity(file: &File) -> io::Result<(libc::dev_t, libc::ino_t)> {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((metadata.st_dev, metadata.st_ino))
        }

        Ok(identity(first)? == identity(second)?)
    }

    pub(super) fn rename_at(directory: &File, old: &str, new: &str) -> io::Result<()> {
        let old = CString::new(old).expect("fixed file name");
        let new = CString::new(new).expect("fixed file name");
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                old.as_ptr(),
                directory.as_raw_fd(),
                new.as_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlink_at(directory: &File, name: &str) -> io::Result<()> {
        let name = CString::new(name).expect("fixed file name");
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlink_dynamic_at(directory: &File, name: &str) -> io::Result<()> {
        let name = dynamic_name(name)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osv_crypto::{RandomError, VaultId};
    use osv_test_support::TempVault;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    struct Sequence(u8);
    impl RandomSource for Sequence {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct FailRandom;
    impl RandomSource for FailRandom {
        fn fill(&mut self, _output: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
    }

    struct ReplacePathThenFail {
        path: PathBuf,
        moved: PathBuf,
        victim: PathBuf,
        called: bool,
    }

    impl RandomSource for ReplacePathThenFail {
        fn fill(&mut self, _output: &mut [u8]) -> Result<(), RandomError> {
            if !self.called {
                self.called = true;
                fs::rename(&self.path, &self.moved).unwrap();
                symlink(&self.victim, &self.path).unwrap();
            }
            Err(RandomError)
        }
    }

    struct FailAt(RewrapPoint);
    impl RewrapFaultInjector for FailAt {
        fn should_fail(&mut self, point: RewrapPoint) -> bool {
            point == self.0
        }
    }

    fn params() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    fn fixture_path(label: &str) -> (TempVault, PathBuf) {
        let parent = TempVault::create_in(&std::env::temp_dir()).unwrap();
        let path = parent.path().join(label);
        (parent, path)
    }

    #[test]
    fn create_is_exclusive_private_durable_and_unlockable() {
        let (_parent, path) = fixture_path("vault");
        let password = Password::new(b"secret").unwrap();
        let vault =
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path.join(HEADER_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            UnlockedVault::create(&path, &password, None, params()),
            Err(VaultError::Io(_))
        ));
        let id = vault.header().vault_id();
        drop(vault);
        assert_eq!(
            UnlockedVault::unlock(&path, &password, None)
                .unwrap()
                .header()
                .vault_id(),
            id
        );
    }

    #[test]
    fn no_follow_rejects_vault_and_header_symlinks() {
        let (parent, path) = fixture_path("real-vault");
        let password = Password::new(b"secret").unwrap();
        UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(2)).unwrap();
        let vault_link = parent.path().join("vault-link");
        symlink(&path, &vault_link).unwrap();
        assert!(matches!(
            UnlockedVault::unlock(&vault_link, &password, None),
            Err(VaultError::Io(_))
        ));
        fs::remove_file(path.join(HEADER_NAME)).unwrap();
        let outside = parent.path().join("outside");
        fs::write(&outside, [0_u8; HEADER_LEN]).unwrap();
        symlink(outside, path.join(HEADER_NAME)).unwrap();
        assert!(matches!(
            UnlockedVault::unlock(&path, &password, None),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn failed_randomness_leaves_only_an_empty_private_directory() {
        let (_parent, path) = fixture_path("failed");
        let password = Password::new(b"secret").unwrap();
        assert!(
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut FailRandom)
                .is_err()
        );
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(path).unwrap().count(), 0);
    }

    #[test]
    fn creation_cleanup_cannot_follow_a_replaced_directory_name() {
        let (parent, path) = fixture_path("replace-during-create");
        let moved = parent.path().join("moved-created-directory");
        let victim = parent.path().join("victim");
        fs::create_dir(&victim).unwrap();
        let victim_header = victim.join(HEADER_NAME);
        fs::write(&victim_header, b"must survive").unwrap();
        let password = Password::new(b"secret").unwrap();
        let mut random = ReplacePathThenFail {
            path: path.clone(),
            moved,
            victim,
            called: false,
        };
        assert!(
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut random).is_err()
        );
        assert_eq!(fs::read(victim_header).unwrap(), b"must survive");
    }

    #[test]
    #[allow(unsafe_code)]
    fn non_regular_header_is_rejected_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let (_parent, path) = fixture_path("fifo-header");
        let password = Password::new(b"secret").unwrap();
        UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(2)).unwrap();
        let header_path = path.join(HEADER_NAME);
        fs::remove_file(&header_path).unwrap();
        let header_path = CString::new(header_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(header_path.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            UnlockedVault::unlock(&path, &password, None),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn credentials_keyfile_and_master_key_do_not_appear_in_header() {
        let (_parent, path) = fixture_path("canary-scan");
        let password_bytes = b"unique phase three password canary";
        let keyfile_bytes = b"unique phase three keyfile canary";
        let password = Password::new(password_bytes).unwrap();
        let keyfile = SecretBytes::new(keyfile_bytes).unwrap();
        // Sequence(1) fills the generated master key with bytes 1 through 32.
        let master_bytes: Vec<u8> = (1..=32).collect();
        UnlockedVault::create_with_rng(
            &path,
            &password,
            Some(&keyfile),
            params(),
            &mut Sequence(1),
        )
        .unwrap();
        let artifact = fs::read(path.join(HEADER_NAME)).unwrap();
        for secret in [
            password_bytes.as_slice(),
            keyfile_bytes.as_slice(),
            &master_bytes,
        ] {
            assert!(
                !artifact
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
    }

    #[test]
    fn every_rewrap_fault_leaves_old_or_new_credentials_recoverable() {
        for (index, point) in REWRAP_POINTS.into_iter().enumerate() {
            let (_parent, path) = fixture_path(&format!("rewrap-{index}"));
            let old_password = Password::new(b"old password").unwrap();
            let new_password = Password::new(b"new password").unwrap();
            let mut vault = UnlockedVault::create_with_rng(
                &path,
                &old_password,
                None,
                params(),
                &mut Sequence(4),
            )
            .unwrap();
            let expected_id: VaultId = vault.header().vault_id();
            let result = vault.rewrap_with(
                &new_password,
                None,
                params(),
                &mut Sequence(90),
                &mut FailAt(point),
            );
            assert!(matches!(result, Err(VaultError::InjectedFault(actual)) if actual == point));
            let retry = vault.rewrap_with(
                &new_password,
                None,
                params(),
                &mut FailRandom,
                &mut NoFaults,
            );
            if point == RewrapPoint::NewHeaderDurable {
                assert!(retry.is_err());
            } else {
                assert!(matches!(
                    retry,
                    Err(VaultError::RecoveryCredentialsAreNotCurrent)
                ));
            }
            drop(vault);
            let old = UnlockedVault::unlock(&path, &old_password, None);
            let new = UnlockedVault::unlock(&path, &new_password, None);
            assert!(
                old.is_ok() || new.is_ok(),
                "neither credential recovered at {point:?}"
            );
            if let Ok(candidate) = old {
                assert_eq!(candidate.header().vault_id(), expected_id);
            }
            if let Ok(candidate) = new {
                assert_eq!(candidate.header().vault_id(), expected_id);
            }
        }
    }

    #[test]
    fn successful_rewrap_rejects_old_credentials_and_preserves_keys() {
        let (_parent, path) = fixture_path("rewrap-ok");
        let old_password = Password::new(b"old").unwrap();
        let new_password = Password::new(b"new").unwrap();
        let mut vault =
            UnlockedVault::create_with_rng(&path, &old_password, None, params(), &mut Sequence(5))
                .unwrap();
        let catalog = *vault.derived_keys().catalog.expose();
        vault
            .rewrap_with(
                &new_password,
                None,
                params(),
                &mut Sequence(80),
                &mut NoFaults,
            )
            .unwrap();
        drop(vault);
        assert!(UnlockedVault::unlock(&path, &old_password, None).is_err());
        assert_eq!(
            UnlockedVault::unlock(&path, &new_password, None)
                .unwrap()
                .derived_keys()
                .catalog
                .expose(),
            &catalog
        );
        assert!(!path.join(NEW_HEADER_NAME).exists());
        assert!(!path.join(BACKUP_HEADER_NAME).exists());
    }

    struct FailPublishAt(PublishPoint);
    impl PublishFaultInjector for FailPublishAt {
        fn should_fail(&mut self, point: PublishPoint) -> bool {
            point == self.0
        }
    }

    fn tree_contains(path: &Path, needle: &[u8]) -> bool {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                if tree_contains(&entry.path(), needle) {
                    return true;
                }
            } else {
                let bytes = fs::read(entry.path()).unwrap();
                if bytes.windows(needle.len()).any(|window| window == needle) {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn publishes_all_roles_with_opaque_private_paths_and_reopens() {
        let (_parent, path) = fixture_path("objects");
        let password = Password::new(b"secret").unwrap();
        let vault =
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                .unwrap();
        let plaintext = b"phase four plaintext media canary".repeat(400);
        let mut descriptors = Vec::new();
        for (index, role) in [
            ObjectRole::Original,
            ObjectRole::Thumbnail,
            ObjectRole::Poster,
        ]
        .into_iter()
        .enumerate()
        {
            descriptors.push(
                vault
                    .publish_object_with(
                        &mut &plaintext[..],
                        plaintext.len() as u64,
                        role,
                        MIN_CHUNK_SIZE,
                        &mut Sequence(40 + index as u8 * 50),
                        &mut object::NoPublishFaults,
                    )
                    .unwrap(),
            );
        }
        drop(vault);
        assert!(!tree_contains(&path, &plaintext[..64]));
        let vault = UnlockedVault::unlock(&path, &password, None).unwrap();
        for descriptor in &descriptors {
            let mut reader = vault.open_object(descriptor).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, plaintext);
        }
        for entry in ["objects", "derived", "staging"] {
            assert_eq!(
                fs::metadata(path.join(entry)).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn publication_faults_return_no_reference_and_leave_no_plaintext() {
        let plaintext = b"publication fault plaintext canary".repeat(300);
        for (index, point) in PUBLISH_POINTS.into_iter().enumerate() {
            let (_parent, path) = fixture_path(&format!("publish-fault-{index}"));
            let password = Password::new(b"secret").unwrap();
            let vault =
                UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                    .unwrap();
            let result = vault.publish_object_with(
                &mut &plaintext[..],
                plaintext.len() as u64,
                ObjectRole::Original,
                MIN_CHUNK_SIZE,
                &mut Sequence(80),
                &mut FailPublishAt(point),
            );
            assert!(matches!(result, Err(ObjectError::InjectedFault(actual)) if actual == point));
            assert!(!tree_contains(&path, &plaintext[..64]));
        }
    }

    struct SubstituteStaging {
        path: PathBuf,
        triggered: bool,
    }

    impl PublishFaultInjector for SubstituteStaging {
        fn should_fail(&mut self, point: PublishPoint) -> bool {
            if point == PublishPoint::CiphertextVerified && !self.triggered {
                self.triggered = true;
                fs::rename(&self.path, self.path.with_extension("saved")).unwrap();
                fs::write(&self.path, [0_u8; OBJECT_HEADER_LEN]).unwrap();
            }
            false
        }
    }

    #[test]
    fn substituted_staging_path_never_returns_a_descriptor() {
        let (_parent, path) = fixture_path("substituted-staging");
        let password = Password::new(b"secret").unwrap();
        let vault =
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                .unwrap();
        let id = ObjectId::from_bytes(std::array::from_fn(|index| 80 + index as u8));
        let staging_path = path
            .join("staging")
            .join(object::filename(id, ".osvo.part"));
        let plaintext = vec![5; 5000];
        let result = vault.publish_object_with(
            &mut &plaintext[..],
            plaintext.len() as u64,
            ObjectRole::Original,
            MIN_CHUNK_SIZE,
            &mut Sequence(80),
            &mut SubstituteStaging {
                path: staging_path,
                triggered: false,
            },
        );
        assert!(matches!(result, Err(ObjectError::PublishedIdentityChanged)));
    }

    #[test]
    fn failed_object_open_does_not_create_namespaces() {
        let (_parent, path) = fixture_path("read-only-open");
        let password = Password::new(b"secret").unwrap();
        let vault =
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                .unwrap();
        let descriptor = ObjectDescriptor::from_catalog(
            ObjectId::from_bytes([7; 16]),
            ObjectRole::Original,
            0,
            OBJECT_FORMAT_VERSION,
            WrappedObjectKey::parse(&[0; 72]).unwrap(),
        )
        .unwrap();
        assert!(!path.join("objects").exists());
        assert!(vault.open_object(&descriptor).is_err());
        assert!(!path.join("objects").exists());
    }

    #[test]
    fn final_publication_never_replaces_an_existing_object() {
        let (_parent, path) = fixture_path("no-replace");
        let password = Password::new(b"secret").unwrap();
        let vault =
            UnlockedVault::create_with_rng(&path, &password, None, params(), &mut Sequence(1))
                .unwrap();
        let id = ObjectId::from_bytes(std::array::from_fn(|index| 80 + index as u8));
        let shard = path.join("objects").join(object::shard(id));
        fs::create_dir_all(&shard).unwrap();
        fs::set_permissions(path.join("objects"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();
        let target = shard.join(object::filename(id, ".osvo"));
        fs::write(&target, b"existing ciphertext").unwrap();
        let plaintext = vec![6; 5000];
        assert!(
            vault
                .publish_object_with(
                    &mut &plaintext[..],
                    plaintext.len() as u64,
                    ObjectRole::Original,
                    MIN_CHUNK_SIZE,
                    &mut Sequence(80),
                    &mut object::NoPublishFaults,
                )
                .is_err()
        );
        assert_eq!(fs::read(target).unwrap(), b"existing ciphertext");
    }
}
