//! Atomic orchestration for the encrypted catalog and independent object store.
//!
//! The service holds a process lock for its entire lifetime. Its state machines
//! deliberately order durability so a catalog never references unpublished
//! ciphertext and deletion drops the wrapped DEK before ciphertext is unlinked.

use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use osv_catalog::{
    Catalog, CatalogError, CatalogMode, CatalogTransaction, Child, GalleryId, MediaClass, MediaId,
    NewDerivedObject, NewGallery, NewMedia, NewObject, ObjectState, SearchResult, TagId,
};
use osv_crypto::{KdfParams, LockStatus, Password, SecretBytes, SecurityStatus};
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
    directory_binding: DirectoryBinding,
    lock: VaultLock,
    mode: OpenMode,
    startup_recovery: RecoveryReport,
    security_lock_status: Cell<LockStatus>,
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
        let directory_binding = DirectoryBinding::capture(path, &directory)?;
        let mut lock = VaultLock::acquire(&directory, OpenMode::Writer, true)?;
        directory.sync_all()?;
        let catalog = Catalog::create_anchored(
            &member_path(&directory, CATALOG_NAME),
            directory.try_clone()?,
            &storage.derived_keys().catalog,
            storage.header().vault_id().as_bytes(),
            created_at_ms,
        )?;
        let directory_binding = directory_binding.bind_catalog(&directory, true, None)?;
        directory_binding.verify()?;
        directory.sync_all()?;
        lock.mark_dirty()?;
        let security_lock_status = storage
            .security_status()
            .page_locks()
            .combine(catalog.security_status().page_locks());
        Ok(Self {
            catalog: Some(catalog),
            storage: Some(storage),
            _directory: directory,
            directory_binding,
            lock,
            mode: OpenMode::Writer,
            startup_recovery: RecoveryReport::default(),
            security_lock_status: Cell::new(security_lock_status),
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
        let directory_binding = DirectoryBinding::capture(path, &directory)?;
        let mut lock = VaultLock::acquire(&directory, mode, false)?;
        if mode == OpenMode::Reader && !lock.is_clean()? {
            return Err(ServiceError::UncleanVault);
        }
        platform::validate_catalog_sidecars(&directory, mode == OpenMode::Reader)?;
        let expected_catalog_identity =
            platform::identity(&platform::open_regular_member(&directory, CATALOG_NAME)?)?;
        let storage =
            UnlockedVault::unlock_from_directory(directory.try_clone()?, password, keyfile)?;
        let catalog_mode = match mode {
            OpenMode::Reader => CatalogMode::ImmutableReadOnly,
            OpenMode::Writer => CatalogMode::PersistentReadWrite,
        };
        let catalog = Catalog::open_anchored(
            &member_path(&directory, CATALOG_NAME),
            directory.try_clone()?,
            &storage.derived_keys().catalog,
            storage.header().vault_id().as_bytes(),
            catalog_mode,
        )?;
        let directory_binding = directory_binding.bind_catalog(
            &directory,
            mode == OpenMode::Writer,
            Some(expected_catalog_identity),
        )?;
        directory_binding.verify()?;
        let security_lock_status = storage
            .security_status()
            .page_locks()
            .combine(catalog.security_status().page_locks());
        if mode == OpenMode::Writer {
            lock.mark_dirty()?;
        }
        let mut service = Self {
            catalog: Some(catalog),
            storage: Some(storage),
            _directory: directory,
            directory_binding,
            lock,
            mode,
            startup_recovery: RecoveryReport::default(),
            security_lock_status: Cell::new(security_lock_status),
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

    pub fn transaction(&mut self) -> Result<MetadataTransaction<'_>, ServiceError> {
        self.require_writer()?;
        self.directory_binding.verify()?;
        Ok(MetadataTransaction(self.catalog_mut().transaction()?))
    }

    #[must_use]
    pub fn security_status(&self) -> SecurityStatus {
        SecurityStatus::new(self.security_lock_status.get())
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
        self.directory_binding.verify()?;
        let descriptor = self.storage().publish_object_observed(
            source,
            logical_len,
            ObjectRole::Original,
            &self.security_lock_status,
        )?;
        self.record_lock_status(
            descriptor
                .publication_security_status()
                .expect("published objects record transient lock status")
                .page_locks(),
        );
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
        self.directory_binding.verify()?;
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
        self.directory_binding.verify()?;
        if !matches!(role, ObjectRole::Thumbnail | ObjectRole::Poster) {
            return Err(ServiceError::InvalidInput);
        }
        let descriptor = self.storage().publish_object_observed(
            source,
            logical_len,
            role,
            &self.security_lock_status,
        )?;
        self.record_lock_status(
            descriptor
                .publication_security_status()
                .expect("published objects record transient lock status")
                .page_locks(),
        );
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
        self.directory_binding.verify()?;
        let mut report = RecoveryReport::default();
        for entry in self.catalog().reader().operation_journal()? {
            if !matches!(
                entry.operation_kind,
                DELETE_OPERATION | REPLACE_DERIVED_OPERATION
            ) || entry.state != CLEANUP_PENDING
            {
                return Err(ServiceError::InvalidJournal);
            }
            let cleanup = decode_cleanup(&entry.payload)?;
            // Validate the complete intent before unlinking anything. A valid
            // cleanup journal can never target an object still carrying a DEK.
            for (id, _role) in &cleanup {
                match self.catalog().reader().object(*id) {
                    Ok(_) => return Err(ServiceError::CleanupConflict),
                    Err(CatalogError::NotFound) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            for (id, role) in cleanup {
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
                match self
                    .storage()
                    .open_object_observed(&object.descriptor, &self.security_lock_status)
                {
                    Ok(mut reader) => {
                        let result = reader.verify_all().err().map(|_| DamageKind::Corrupt);
                        self.record_lock_status(reader.security_status().page_locks());
                        result
                    }
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

    pub fn open_object(&self, id: ObjectId) -> Result<ServiceObjectReader<'_>, ServiceError> {
        self.directory_binding.verify()?;
        let stored = self.catalog().reader().object(id)?;
        if stored.state != ObjectState::Ready
            || stored.locator
                != UnlockedVault::object_locator(stored.descriptor.id(), stored.descriptor.role())
        {
            return Err(ServiceError::DamagedObject);
        }
        let inner = self
            .storage()
            .open_object_observed(&stored.descriptor, &self.security_lock_status)?;
        self.record_lock_status(inner.security_status().page_locks());
        Ok(ServiceObjectReader {
            inner,
            service_status: &self.security_lock_status,
        })
    }

    pub fn close(mut self) -> Result<(), ServiceError> {
        self.directory_binding.verify()?;
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
            match self.catalog().reader().object(object.id) {
                Ok(_) => return Err(ServiceError::CleanupConflict),
                Err(CatalogError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
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

    fn record_lock_status(&self, status: LockStatus) {
        self.security_lock_status
            .set(self.security_lock_status.get().combine(status));
    }
}

struct DirectoryBinding {
    stable_path: PathBuf,
    parent: File,
    name: std::ffi::OsString,
    identity: (u64, u64),
    catalog_identity: Option<(u64, u64)>,
    catalog_sidecars: Vec<(String, File, (u64, u64))>,
    pre_catalog_fds: HashMap<(u64, u64), usize>,
}

impl DirectoryBinding {
    fn capture(path: &Path, directory: &File) -> Result<Self, ServiceError> {
        let (parent_path, name) = split_parent(path)?;
        let parent = platform::open_directory(&parent_path)?;
        let stable_path = std::fs::canonicalize(path)?;
        Ok(Self {
            stable_path,
            parent,
            name,
            identity: platform::identity(directory)?,
            catalog_identity: None,
            catalog_sidecars: Vec::new(),
            pre_catalog_fds: platform::open_fd_identity_counts()?,
        })
    }

    fn bind_catalog(
        mut self,
        directory: &File,
        require_sidecars: bool,
        expected_catalog_identity: Option<(u64, u64)>,
    ) -> Result<Self, ServiceError> {
        let catalog = platform::open_regular_member(directory, CATALOG_NAME)?;
        let catalog_identity = platform::identity(&catalog)?;
        if expected_catalog_identity.is_some_and(|expected| expected != catalog_identity) {
            return Err(ServiceError::PathIdentityChanged);
        }
        if !platform::fd_identity_count_grew(
            &self.pre_catalog_fds,
            catalog_identity,
            catalog.as_raw_fd(),
        )? {
            return Err(ServiceError::PathIdentityChanged);
        }
        if require_sidecars {
            let member = "catalog.db-wal";
            let sidecar = platform::open_regular_member(directory, member)?;
            let identity = platform::identity(&sidecar)?;
            if !platform::fd_identity_count_grew(
                &self.pre_catalog_fds,
                identity,
                sidecar.as_raw_fd(),
            )? {
                return Err(ServiceError::PathIdentityChanged);
            }
            self.catalog_sidecars
                .push((member.to_owned(), sidecar, identity));
        }
        self.catalog_identity = Some(catalog_identity);
        Ok(self)
    }

    fn verify(&self) -> Result<(), ServiceError> {
        let stable = platform::open_directory(&self.stable_path)
            .map_err(|_| ServiceError::PathIdentityChanged)?;
        if platform::identity(&stable)? != self.identity {
            return Err(ServiceError::PathIdentityChanged);
        }
        let current = platform::open_directory_at(&self.parent, &self.name)
            .map_err(|_| ServiceError::PathIdentityChanged)?;
        if platform::identity(&current)? == self.identity {
            let catalog = platform::open_regular_member(&current, CATALOG_NAME)
                .map_err(|_| ServiceError::PathIdentityChanged)?;
            if Some(platform::identity(&catalog)?) == self.catalog_identity {
                for (name, _held, identity) in &self.catalog_sidecars {
                    let sidecar = platform::open_regular_member(&current, name)
                        .map_err(|_| ServiceError::PathIdentityChanged)?;
                    if platform::identity(&sidecar)? != *identity {
                        return Err(ServiceError::PathIdentityChanged);
                    }
                }
                Ok(())
            } else {
                Err(ServiceError::PathIdentityChanged)
            }
        } else {
            Err(ServiceError::PathIdentityChanged)
        }
    }
}

/// Object authority cannot outlive the service session and its process lock.
///
/// Closing or mutating the service while a reader will still be used is a
/// compile-time error:
///
/// ```compile_fail
/// use std::io::Read;
/// use osv_storage::ObjectId;
/// use osv_vault::VaultService;
///
/// fn cannot_close(service: VaultService, id: ObjectId) {
///     let mut reader = service.open_object(id).unwrap();
///     service.close().unwrap();
///     reader.read_to_end(&mut Vec::new()).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use std::io::Read;
/// use osv_catalog::MediaId;
/// use osv_storage::ObjectId;
/// use osv_vault::VaultService;
///
/// fn cannot_delete(mut service: VaultService, object: ObjectId, media: MediaId) {
///     let mut reader = service.open_object(object).unwrap();
///     service.delete_media(media, 1).unwrap();
///     reader.read_to_end(&mut Vec::new()).unwrap();
/// }
/// ```
pub struct ServiceObjectReader<'service> {
    inner: ObjectReader<File>,
    service_status: &'service Cell<LockStatus>,
}

impl Read for ServiceObjectReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buffer);
        self.service_status.set(
            self.service_status
                .get()
                .combine(self.inner.security_status().page_locks()),
        );
        result
    }
}

impl Seek for ServiceObjectReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let result = self.inner.seek(position);
        self.service_status.set(
            self.service_status
                .get()
                .combine(self.inner.security_status().page_locks()),
        );
        result
    }
}

/// Catalog authority deliberately limited to metadata-only mutations.
pub struct MetadataTransaction<'catalog>(CatalogTransaction<'catalog>);

impl MetadataTransaction<'_> {
    pub fn create_gallery(&self, gallery: NewGallery<'_>) -> Result<(), CatalogError> {
        self.0.create_gallery(gallery)
    }

    pub fn add_gallery_child(
        &self,
        parent: GalleryId,
        position: u32,
        child: Child,
    ) -> Result<(), CatalogError> {
        self.0.add_gallery_child(parent, position, child)
    }

    pub fn gallery_children(
        &self,
        parent: GalleryId,
        maximum: u32,
    ) -> Result<Vec<Child>, CatalogError> {
        self.0.gallery_children(parent, maximum)
    }

    pub fn create_tag(&self, name: &str) -> Result<TagId, CatalogError> {
        self.0.create_tag(name)
    }

    pub fn tag_media(&self, media: MediaId, tag: TagId) -> Result<(), CatalogError> {
        self.0.tag_media(media, tag)
    }

    pub fn set_favorite(&self, media: MediaId, favorite: bool) -> Result<(), CatalogError> {
        self.0.set_favorite(media, favorite)
    }

    pub fn search_media(
        &self,
        query: &str,
        maximum: u32,
    ) -> Result<Vec<SearchResult>, CatalogError> {
        self.0.search_media(query, maximum)
    }

    pub fn commit(self) -> Result<(), CatalogError> {
        self.0.commit()
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
    if platform::is_same_or_descendant(&source_directory, &parent)? {
        return Err(ServiceError::InvalidInput);
    }
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
    CleanupConflict,
    PathIdentityChanged,
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
            Self::CleanupConflict => formatter.write_str("cleanup target is still live in catalog"),
            Self::PathIdentityChanged => {
                formatter.write_str("vault directory identity changed during the session")
            }
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

    pub(super) fn open_regular_member(directory: &File, member: &str) -> io::Result<File> {
        let name =
            CString::new(member).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
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
                "invalid catalog member",
            ));
        }
        Ok(file)
    }

    pub(super) fn validate_catalog_sidecars(
        directory: &File,
        require_empty_wal: bool,
    ) -> io::Result<()> {
        for name in ["catalog.db-wal", "catalog.db-shm", "catalog.db-journal"] {
            let encoded = CString::new(name).expect("fixed catalog sidecar name");
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    encoded.as_ptr(),
                    &mut metadata,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                    || metadata.st_nlink != 1
                    || (require_empty_wal && name == "catalog.db-wal" && metadata.st_size != 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid catalog sidecar",
                    ));
                }
                continue;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(error);
            }
        }
        Ok(())
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

    pub(super) fn identity(file: &File) -> io::Result<(u64, u64)> {
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((metadata.st_dev, metadata.st_ino))
    }

    fn open_fd_numbers() -> io::Result<HashSet<i32>> {
        let mut descriptors: HashSet<i32> = std::fs::read_dir("/proc/self/fd")?
            .filter_map(|entry| {
                entry.ok().and_then(|value| {
                    value
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse().ok())
                })
            })
            .collect();
        descriptors.retain(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } != -1);
        Ok(descriptors)
    }

    pub(super) fn open_fd_identity_counts() -> io::Result<HashMap<(u64, u64), usize>> {
        let mut counts = HashMap::new();
        for fd in open_fd_numbers()? {
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut metadata) } == 0 {
                *counts
                    .entry((metadata.st_dev, metadata.st_ino))
                    .or_insert(0) += 1;
            }
        }
        Ok(counts)
    }

    pub(super) fn fd_identity_count_grew(
        prior: &HashMap<(u64, u64), usize>,
        sought: (u64, u64),
        excluded: i32,
    ) -> io::Result<bool> {
        let mut count = 0;
        for fd in open_fd_numbers()? {
            if fd == excluded {
                continue;
            }
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
                continue;
            }
            if (metadata.st_dev, metadata.st_ino) == sought {
                count += 1;
            }
        }
        Ok(count > prior.get(&sought).copied().unwrap_or(0))
    }

    pub(super) fn is_same_or_descendant(ancestor: &File, candidate: &File) -> io::Result<bool> {
        let sought = identity(ancestor)?;
        let mut current = candidate.try_clone()?;
        loop {
            let current_identity = identity(&current)?;
            if current_identity == sought {
                return Ok(true);
            }
            let parent = open_directory_at(&current, OsStr::new(".."))?;
            if identity(&parent)? == current_identity {
                return Ok(false);
            }
            current = parent;
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
        let destination_identity = identity(destination)?;
        let mut visited = HashSet::new();
        copy_tree_inner(
            source,
            destination,
            destination_identity,
            &mut visited,
            faults,
        )
    }

    fn copy_tree_inner(
        source: &File,
        destination: &File,
        destination_identity: (u64, u64),
        visited: &mut HashSet<(u64, u64)>,
        faults: &mut impl BackupFaultInjector,
    ) -> Result<(), ServiceError> {
        if !visited.insert(identity(source)?) {
            return Err(ServiceError::InvalidInput);
        }
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
            if (metadata.st_dev, metadata.st_ino) == destination_identity {
                return Err(ServiceError::InvalidInput);
            }
            match metadata.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    create_directory(destination, &name)?;
                    let destination_entry = open_directory_at(destination, &name)?;
                    copy_tree_inner(
                        &source_entry,
                        &destination_entry,
                        destination_identity,
                        visited,
                        faults,
                    )?;
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
