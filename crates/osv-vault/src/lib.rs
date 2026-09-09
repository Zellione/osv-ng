//! Atomic orchestration for the encrypted catalog and independent object store.
//!
//! The service holds a process lock for its entire lifetime. Its state machines
//! deliberately order durability so a catalog never references unpublished
//! ciphertext and deletion drops the wrapped DEK before ciphertext is unlinked.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use osv_catalog::{
    Catalog, CatalogError, CatalogMode, CatalogTransaction, MediaClass, MediaId, NewDerivedObject,
    NewMedia, NewObject, ObjectState,
};
use osv_crypto::{KdfParams, Password, SecretBytes};
use osv_storage::{ObjectError, ObjectId, ObjectReader, ObjectRole, UnlockedVault, VaultError};

const CATALOG_NAME: &str = "catalog.db";
const LOCK_NAME: &str = "vault.lock";
const DELETE_OPERATION: u8 = 1;
const REPLACE_DERIVED_OPERATION: u8 = 2;
const CLEANUP_PENDING: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    Reader,
    Writer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePoint {
    ObjectDurable,
    BeforeCatalogCommit,
    CatalogCommitted,
    CiphertextRemoved,
    RecoveryRepair,
}

impl ServicePoint {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ObjectDurable => "service-object-durable",
            Self::BeforeCatalogCommit => "service-before-catalog-commit",
            Self::CatalogCommitted => "service-catalog-committed",
            Self::CiphertextRemoved => "service-ciphertext-removed",
            Self::RecoveryRepair => "service-recovery-repair",
        }
    }
}

pub const SERVICE_POINTS: [ServicePoint; 5] = [
    ServicePoint::ObjectDurable,
    ServicePoint::BeforeCatalogCommit,
    ServicePoint::CatalogCommitted,
    ServicePoint::CiphertextRemoved,
    ServicePoint::RecoveryRepair,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupPoint {
    DestinationCreated,
    EntryCopied,
    DestinationDurable,
}

pub trait BackupFaultInjector {
    fn should_fail(&mut self, point: BackupPoint) -> bool;
}

#[derive(Default)]
pub struct NoBackupFaults;

impl BackupFaultInjector for NoBackupFaults {
    fn should_fail(&mut self, _point: BackupPoint) -> bool {
        false
    }
}

pub trait ServiceFaultInjector {
    fn should_fail(&mut self, point: ServicePoint) -> bool;
}

#[derive(Default)]
pub struct NoServiceFaults;

impl ServiceFaultInjector for NoServiceFaults {
    fn should_fail(&mut self, _point: ServicePoint) -> bool {
        false
    }
}

pub struct ImportMetadata<'a> {
    pub id: MediaId,
    pub original_name: &'a str,
    pub class: MediaClass,
    pub mime: &'a str,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub codecs: &'a str,
    pub imported_at_ms: i64,
    pub fingerprint: &'a [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DamageKind {
    Missing,
    Corrupt,
    LocatorMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectIssue {
    pub id: ObjectId,
    pub role: ObjectRole,
    pub kind: DamageKind,
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub repaired_operations: usize,
    pub removed_orphans: usize,
    pub removed_staging_files: usize,
    pub unexpected_entries: usize,
    pub issues: Vec<ObjectIssue>,
}

pub struct VaultService {
    // Declaration order is intentional: fallback Drop closes secret-bearing
    // components before releasing the process lock.
    catalog: Option<Catalog>,
    storage: Option<UnlockedVault>,
    _directory: File,
    lock: VaultLock,
    mode: OpenMode,
    startup_recovery: RecoveryReport,
}

impl fmt::Debug for VaultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultService")
            .field("mode", &self.mode)
            .field("path", &"[REDACTED]")
            .finish()
    }
}

impl VaultService {
    pub fn create(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        created_at_ms: i64,
    ) -> Result<Self, ServiceError> {
        let storage = UnlockedVault::create(path, password, keyfile, kdf_params)?;
        let directory = storage.try_clone_directory()?;
        let mut lock = VaultLock::acquire(&directory, OpenMode::Writer, true)?;
        directory.sync_all()?;
        let catalog = Catalog::create(
            &member_path(&directory, CATALOG_NAME),
            &storage.derived_keys().catalog,
            storage.header().vault_id().as_bytes(),
            created_at_ms,
        )?;
        directory.sync_all()?;
        lock.mark_dirty()?;
        Ok(Self {
            catalog: Some(catalog),
            storage: Some(storage),
            _directory: directory,
            lock,
            mode: OpenMode::Writer,
            startup_recovery: RecoveryReport::default(),
        })
    }

    pub fn open(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        mode: OpenMode,
    ) -> Result<Self, ServiceError> {
        Self::open_with_recovery_faults(path, password, keyfile, mode, &mut NoServiceFaults)
    }

    pub fn open_with_recovery_faults(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        mode: OpenMode,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<Self, ServiceError> {
        let directory = platform::open_directory(path)?;
        let mut lock = VaultLock::acquire(&directory, mode, false)?;
        let storage =
            UnlockedVault::unlock_from_directory(directory.try_clone()?, password, keyfile)?;
        let catalog_mode = match mode {
            OpenMode::Reader => CatalogMode::ReadOnly,
            OpenMode::Writer => CatalogMode::ReadWrite,
        };
        let catalog = Catalog::open(
            &member_path(&directory, CATALOG_NAME),
            &storage.derived_keys().catalog,
            storage.header().vault_id().as_bytes(),
            catalog_mode,
        )?;
        if mode == OpenMode::Writer {
            lock.mark_dirty()?;
        }
        let mut service = Self {
            catalog: Some(catalog),
            storage: Some(storage),
            _directory: directory,
            lock,
            mode,
            startup_recovery: RecoveryReport::default(),
        };
        if mode == OpenMode::Writer {
            service.startup_recovery = service.recover_with(faults)?;
        }
        Ok(service)
    }

    #[must_use]
    pub const fn startup_recovery(&self) -> &RecoveryReport {
        &self.startup_recovery
    }

    pub fn reader(&self) -> osv_catalog::CatalogReader<'_> {
        self.catalog().reader()
    }

    pub fn transaction(&mut self) -> Result<CatalogTransaction<'_>, ServiceError> {
        self.require_writer()?;
        Ok(self.catalog_mut().transaction()?)
    }

    pub fn import(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        metadata: ImportMetadata<'_>,
    ) -> Result<ObjectId, ServiceError> {
        self.import_with(source, logical_len, metadata, &mut NoServiceFaults)
    }

    pub fn import_with(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        metadata: ImportMetadata<'_>,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<ObjectId, ServiceError> {
        self.require_writer()?;
        let descriptor =
            self.storage()
                .publish_object(source, logical_len, ObjectRole::Original)?;
        fail(faults, ServicePoint::ObjectDurable)?;
        let locator = UnlockedVault::object_locator(descriptor.id(), descriptor.role());
        let mut catalog = self.catalog.take().expect("catalog present");
        let result: Result<(), ServiceError> = (|| {
            let tx = catalog.transaction()?;
            tx.insert_object(NewObject {
                descriptor: &descriptor,
                locator: &locator,
                state: ObjectState::Ready,
            })?;
            tx.insert_media(&NewMedia {
                id: metadata.id,
                original_object_id: descriptor.id(),
                original_name: metadata.original_name,
                class: metadata.class,
                mime: metadata.mime,
                width: metadata.width,
                height: metadata.height,
                duration_ms: metadata.duration_ms,
                codecs: metadata.codecs,
                imported_at_ms: metadata.imported_at_ms,
                fingerprint: metadata.fingerprint,
            })?;
            fail(faults, ServicePoint::BeforeCatalogCommit)?;
            tx.commit()?;
            Ok(())
        })();
        self.catalog = Some(catalog);
        result?;
        fail(faults, ServicePoint::CatalogCommitted)?;
        Ok(descriptor.id())
    }

    pub fn delete_media(&mut self, media: MediaId, now_ms: i64) -> Result<(), ServiceError> {
        self.delete_media_with(media, now_ms, &mut NoServiceFaults)
    }

    pub fn delete_media_with(
        &mut self,
        media: MediaId,
        now_ms: i64,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        self.require_writer()?;
        let operation_id = *media.as_bytes();
        let mut catalog = self.catalog.take().expect("catalog present");
        let result: Result<Vec<osv_catalog::CleanupObject>, ServiceError> = (|| {
            let tx = catalog.transaction()?;
            let objects = tx.delete_media(media)?;
            let payload = encode_cleanup(&objects);
            tx.insert_operation(
                operation_id,
                DELETE_OPERATION,
                CLEANUP_PENDING,
                &payload,
                now_ms,
            )?;
            fail(faults, ServicePoint::BeforeCatalogCommit)?;
            tx.commit()?;
            Ok(objects)
        })();
        self.catalog = Some(catalog);
        let objects = result?;
        fail(faults, ServicePoint::CatalogCommitted)?;
        self.cleanup_descriptors(&objects)?;
        fail(faults, ServicePoint::CiphertextRemoved)?;
        let tx = self.catalog_mut().transaction()?;
        tx.remove_operation(operation_id)?;
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replace_derived(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        media: MediaId,
        role: ObjectRole,
        recipe_version: u32,
        width: u32,
        height: u32,
        now_ms: i64,
    ) -> Result<ObjectId, ServiceError> {
        self.replace_derived_with(
            source,
            logical_len,
            media,
            role,
            recipe_version,
            width,
            height,
            now_ms,
            &mut NoServiceFaults,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn replace_derived_with(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        media: MediaId,
        role: ObjectRole,
        recipe_version: u32,
        width: u32,
        height: u32,
        now_ms: i64,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<ObjectId, ServiceError> {
        self.require_writer()?;
        if !matches!(role, ObjectRole::Thumbnail | ObjectRole::Poster) {
            return Err(ServiceError::InvalidInput);
        }
        let descriptor = self.storage().publish_object(source, logical_len, role)?;
        fail(faults, ServicePoint::ObjectDurable)?;
        let locator = UnlockedVault::object_locator(descriptor.id(), role);
        let operation_id = *descriptor.id().as_bytes();
        let mut catalog = self.catalog.take().expect("catalog present");
        let result: Result<Vec<osv_catalog::CleanupObject>, ServiceError> = (|| {
            let tx = catalog.transaction()?;
            let old = tx.replace_derived(
                NewObject {
                    descriptor: &descriptor,
                    locator: &locator,
                    state: ObjectState::Ready,
                },
                NewDerivedObject {
                    object_id: descriptor.id(),
                    media_id: media,
                    recipe_version,
                    width,
                    height,
                },
            )?;
            tx.insert_operation(
                operation_id,
                REPLACE_DERIVED_OPERATION,
                CLEANUP_PENDING,
                &encode_cleanup(&old),
                now_ms,
            )?;
            fail(faults, ServicePoint::BeforeCatalogCommit)?;
            tx.commit()?;
            Ok(old)
        })();
        self.catalog = Some(catalog);
        let old = result?;
        fail(faults, ServicePoint::CatalogCommitted)?;
        self.cleanup_descriptors(&old)?;
        fail(faults, ServicePoint::CiphertextRemoved)?;
        let tx = self.catalog_mut().transaction()?;
        tx.remove_operation(operation_id)?;
        tx.commit()?;
        Ok(descriptor.id())
    }

    pub fn maintenance_scan(&mut self) -> Result<RecoveryReport, ServiceError> {
        self.require_writer()?;
        self.recover_with(&mut NoServiceFaults)
    }

    pub fn recover_with(
        &mut self,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<RecoveryReport, ServiceError> {
        self.require_writer()?;
        let mut report = RecoveryReport::default();
        for entry in self.catalog().reader().operation_journal()? {
            if !matches!(
                entry.operation_kind,
                DELETE_OPERATION | REPLACE_DERIVED_OPERATION
            ) || entry.state != CLEANUP_PENDING
            {
                return Err(ServiceError::InvalidJournal);
            }
            for (id, role) in decode_cleanup(&entry.payload)? {
                if self.storage().remove_ciphertext(id, role)? {
                    report.removed_orphans += 1;
                }
            }
            fail(faults, ServicePoint::RecoveryRepair)?;
            let tx = self.catalog_mut().transaction()?;
            tx.remove_operation(entry.id)?;
            tx.commit()?;
            report.repaired_operations += 1;
        }

        let objects = self.catalog().reader().all_objects()?;
        let referenced: HashMap<_, _> = objects
            .iter()
            .map(|object| (object.descriptor.id(), object.descriptor.role()))
            .collect();
        let inventory = self.storage().ciphertext_inventory()?;
        report.unexpected_entries = inventory.unexpected_entries;
        for id in inventory.staging_ids {
            if self.storage().remove_staging_ciphertext(id)? {
                report.removed_staging_files += 1;
            }
        }
        let physical: HashSet<_> = inventory
            .objects
            .iter()
            .map(|object| (object.id, object.role))
            .collect();
        for object in inventory.objects {
            if referenced.get(&object.id) != Some(&object.role)
                && self.storage().remove_ciphertext(object.id, object.role)?
            {
                report.removed_orphans += 1;
            }
        }
        for object in objects {
            let id = object.descriptor.id();
            let role = object.descriptor.role();
            let expected = UnlockedVault::object_locator(id, role);
            let kind = if object.locator != expected {
                Some(DamageKind::LocatorMismatch)
            } else if !physical.contains(&(id, role)) {
                Some(DamageKind::Missing)
            } else {
                match self.storage().open_object(&object.descriptor) {
                    Ok(mut reader) => reader.verify_all().err().map(|_| DamageKind::Corrupt),
                    Err(_) => Some(DamageKind::Corrupt),
                }
            };
            if let Some(kind) = kind {
                let tx = self.catalog_mut().transaction()?;
                tx.set_object_state(id, ObjectState::Damaged)?;
                tx.commit()?;
                report.issues.push(ObjectIssue { id, role, kind });
            }
        }
        Ok(report)
    }

    pub fn open_object(&self, id: ObjectId) -> Result<ObjectReader<File>, ServiceError> {
        let stored = self.catalog().reader().object(id)?;
        if stored.state != ObjectState::Ready
            || stored.locator
                != UnlockedVault::object_locator(stored.descriptor.id(), stored.descriptor.role())
        {
            return Err(ServiceError::DamagedObject);
        }
        Ok(self.storage().open_object(&stored.descriptor)?)
    }

    pub fn close(mut self) -> Result<(), ServiceError> {
        if self.mode == OpenMode::Writer {
            self.recover_with(&mut NoServiceFaults)?;
        }
        if let Some(catalog) = self.catalog.take() {
            catalog.close()?;
        }
        drop(self.storage.take());
        // Lock is deliberately still live until this function returns.
        if self.mode == OpenMode::Writer {
            self.lock.mark_clean()?;
        }
        Ok(())
    }

    fn cleanup_descriptors(
        &self,
        objects: &[osv_catalog::CleanupObject],
    ) -> Result<(), ServiceError> {
        for object in objects {
            self.storage().remove_ciphertext(object.id, object.role)?;
        }
        Ok(())
    }

    fn require_writer(&self) -> Result<(), ServiceError> {
        if self.mode == OpenMode::Writer {
            Ok(())
        } else {
            Err(ServiceError::ReadOnly)
        }
    }

    fn catalog(&self) -> &Catalog {
        self.catalog.as_ref().expect("catalog present")
    }

    fn catalog_mut(&mut self) -> &mut Catalog {
        self.catalog.as_mut().expect("catalog present")
    }

    fn storage(&self) -> &UnlockedVault {
        self.storage.as_ref().expect("storage present")
    }
}

/// Copies a cleanly closed vault while holding its exclusive process lock.
/// A failure deliberately preserves the incomplete destination for diagnostics.
pub fn backup_closed(source: &Path, destination: &Path) -> Result<(), ServiceError> {
    backup_closed_with(source, destination, &mut NoBackupFaults)
}

pub fn backup_closed_with(
    source: &Path,
    destination: &Path,
    faults: &mut impl BackupFaultInjector,
) -> Result<(), ServiceError> {
    if destination == source || destination.starts_with(source) {
        return Err(ServiceError::InvalidInput);
    }
    let source_directory = platform::open_directory(source)?;
    let mut lock = VaultLock::acquire(&source_directory, OpenMode::Writer, false)?;
    if !lock.is_clean()? {
        return Err(ServiceError::UncleanVault);
    }
    let (destination_parent, destination_name) = split_parent(destination)?;
    let parent = platform::open_directory(&destination_parent)?;
    platform::create_directory(&parent, &destination_name)?;
    let destination_directory = platform::open_directory_at(&parent, &destination_name)?;
    backup_fail(faults, BackupPoint::DestinationCreated)?;
    platform::copy_tree(&source_directory, &destination_directory, faults)?;
    destination_directory.sync_all()?;
    parent.sync_all()?;
    backup_fail(faults, BackupPoint::DestinationDurable)?;
    Ok(())
}

fn split_parent(path: &Path) -> Result<(PathBuf, std::ffi::OsString), ServiceError> {
    let name = path
        .file_name()
        .ok_or(ServiceError::InvalidInput)?
        .to_owned();
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => PathBuf::from("."),
    };
    Ok((parent, name))
}

fn backup_fail(
    faults: &mut impl BackupFaultInjector,
    point: BackupPoint,
) -> Result<(), ServiceError> {
    if faults.should_fail(point) {
        Err(ServiceError::BackupInterrupted(point))
    } else {
        Ok(())
    }
}

fn encode_cleanup(objects: &[osv_catalog::CleanupObject]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(objects.len() * 17);
    for object in objects {
        payload.push(object.role as u8);
        payload.extend_from_slice(object.id.as_bytes());
    }
    payload
}

fn decode_cleanup(payload: &[u8]) -> Result<Vec<(ObjectId, ObjectRole)>, ServiceError> {
    if !payload.len().is_multiple_of(17) {
        return Err(ServiceError::InvalidJournal);
    }
    payload
        .as_chunks::<17>()
        .0
        .iter()
        .map(|entry| {
            let role = match entry[0] {
                1 => ObjectRole::Original,
                2 => ObjectRole::Thumbnail,
                3 => ObjectRole::Poster,
                _ => return Err(ServiceError::InvalidJournal),
            };
            let id = ObjectId::from_bytes(
                entry[1..]
                    .try_into()
                    .map_err(|_| ServiceError::InvalidJournal)?,
            );
            Ok((id, role))
        })
        .collect()
}

fn fail(faults: &mut impl ServiceFaultInjector, point: ServicePoint) -> Result<(), ServiceError> {
    if faults.should_fail(point) {
        Err(ServiceError::InjectedFault(point))
    } else {
        Ok(())
    }
}

fn member_path(directory: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{name}", directory.as_raw_fd()))
}

struct VaultLock {
    file: File,
}

impl VaultLock {
    fn acquire(directory: &File, mode: OpenMode, create: bool) -> Result<Self, ServiceError> {
        let file = platform::open_lock(directory, mode, create)?;
        let operation = match mode {
            OpenMode::Reader => libc::LOCK_SH | libc::LOCK_NB,
            OpenMode::Writer => libc::LOCK_EX | libc::LOCK_NB,
        };
        if let Err(error) = platform::try_lock(&file, operation) {
            return if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(ServiceError::LockContended)
            } else {
                Err(ServiceError::Io(error))
            };
        }
        Ok(Self { file })
    }

    fn mark_dirty(&mut self) -> io::Result<()> {
        self.write_state(b'D')
    }

    fn mark_clean(&mut self) -> io::Result<()> {
        self.write_state(b'C')
    }

    fn write_state(&mut self, state: u8) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(&[state])?;
        self.file.sync_all()
    }

    fn is_clean(&mut self) -> io::Result<bool> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut state = [0_u8; 2];
        Ok(self.file.read(&mut state)? == 1 && state[0] == b'C')
    }
}

#[derive(Debug)]
pub enum ServiceError {
    Io(io::Error),
    Vault(VaultError),
    Catalog(CatalogError),
    Object(ObjectError),
    LockContended,
    ReadOnly,
    InvalidInput,
    InvalidJournal,
    DamagedObject,
    UncleanVault,
    InjectedFault(ServicePoint),
    BackupInterrupted(BackupPoint),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("vault service filesystem operation failed"),
            Self::Vault(error) => error.fmt(formatter),
            Self::Catalog(error) => error.fmt(formatter),
            Self::Object(error) => error.fmt(formatter),
            Self::LockContended => formatter.write_str("vault is locked by another process"),
            Self::ReadOnly => formatter.write_str("vault session is read-only"),
            Self::InvalidInput => formatter.write_str("invalid vault service input"),
            Self::InvalidJournal => formatter.write_str("invalid encrypted recovery journal"),
            Self::DamagedObject => formatter.write_str("vault object is marked damaged"),
            Self::UncleanVault => formatter.write_str("vault was not cleanly closed"),
            Self::InjectedFault(point) => write!(formatter, "injected service fault at {point:?}"),
            Self::BackupInterrupted(point) => {
                write!(formatter, "interrupted offline backup at {point:?}")
            }
        }
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Vault(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ServiceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<VaultError> for ServiceError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}
impl From<CatalogError> for ServiceError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}
impl From<ObjectError> for ServiceError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        os::fd::FromRawFd,
        os::unix::ffi::OsStrExt,
    };

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

    pub(super) fn open_lock(directory: &File, mode: OpenMode, create: bool) -> io::Result<File> {
        let name = CString::new(LOCK_NAME).expect("fixed lock name");
        let mut flags = match mode {
            OpenMode::Reader => libc::O_RDONLY,
            OpenMode::Writer => libc::O_RDWR,
        } | libc::O_NOFOLLOW
            | libc::O_CLOEXEC;
        if create {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
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
                "invalid vault lock",
            ));
        }
        Ok(file)
    }

    pub(super) fn create_directory(parent: &File, name: &OsStr) -> io::Result<()> {
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

    fn names(directory: &File) -> io::Result<Vec<std::ffi::OsString>> {
        std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?
            .map(|entry| entry.map(|value| value.file_name()))
            .collect()
    }

    pub(super) fn copy_tree(
        source: &File,
        destination: &File,
        faults: &mut impl BackupFaultInjector,
    ) -> Result<(), ServiceError> {
        for name in names(source)? {
            let encoded = CString::new(name.as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let source_fd = unsafe {
                libc::openat(
                    source.as_raw_fd(),
                    encoded.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if source_fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let mut source_entry = unsafe { File::from_raw_fd(source_fd) };
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(source_entry.as_raw_fd(), &mut metadata) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            match metadata.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    create_directory(destination, &name)?;
                    let destination_entry = open_directory_at(destination, &name)?;
                    copy_tree(&source_entry, &destination_entry, faults)?;
                    destination_entry.sync_all()?;
                }
                libc::S_IFREG if metadata.st_nlink == 1 => {
                    let destination_fd = unsafe {
                        libc::openat(
                            destination.as_raw_fd(),
                            encoded.as_ptr(),
                            libc::O_WRONLY
                                | libc::O_CREAT
                                | libc::O_EXCL
                                | libc::O_NOFOLLOW
                                | libc::O_CLOEXEC,
                            0o600,
                        )
                    };
                    if destination_fd < 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    let mut destination_entry = unsafe { File::from_raw_fd(destination_fd) };
                    io::copy(&mut source_entry, &mut destination_entry)?;
                    destination_entry.flush()?;
                    destination_entry.sync_all()?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported vault backup entry",
                    )
                    .into());
                }
            }
            backup_fail(faults, BackupPoint::EntryCopied)?;
        }
        Ok(())
    }

    pub(super) fn try_lock(file: &File, operation: libc::c_int) -> io::Result<()> {
        // SAFETY: flock only operates on this owned, valid file descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
