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
use osv_storage::{
    ObjectError, ObjectId, ObjectReader, ObjectRole, RemovalFaultInjector, RemovalIoPoint,
    RemovalPoint, UnlockedVault, VaultError,
};

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
    CreationStorageDurable,
    CreationCatalogDurable,
    CreationDirtyMarkerTruncated,
    CreationDirtyMarkerWritten,
    CreationDirtyMarkerDurable,
    WriterDirtyMarkerTruncated,
    WriterDirtyMarkerWritten,
    WriterDirtyMarkerDurable,
    ObjectDurable,
    BeforeCatalogCommit,
    CatalogCommitted,
    CiphertextUnlinked,
    CiphertextRemoved,
    RecoveryCiphertextUnlinked,
    RecoveryCiphertextRemoved,
    RecoveryStagingUnlinked,
    RecoveryStagingRemoved,
    RecoveryOrphanUnlinked,
    RecoveryOrphanRemoved,
    RecoveryRepair,
    CloseCatalogClosed,
    CloseCleanMarkerTruncated,
    CloseCleanMarkerWritten,
    CloseCleanMarkerDurable,
}

impl ServicePoint {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreationStorageDurable => "service-creation-storage-durable",
            Self::CreationCatalogDurable => "service-creation-catalog-durable",
            Self::CreationDirtyMarkerTruncated => "service-creation-dirty-marker-truncated",
            Self::CreationDirtyMarkerWritten => "service-creation-dirty-marker-written",
            Self::CreationDirtyMarkerDurable => "service-creation-dirty-marker-durable",
            Self::WriterDirtyMarkerTruncated => "service-writer-dirty-marker-truncated",
            Self::WriterDirtyMarkerWritten => "service-writer-dirty-marker-written",
            Self::WriterDirtyMarkerDurable => "service-writer-dirty-marker-durable",
            Self::ObjectDurable => "service-object-durable",
            Self::BeforeCatalogCommit => "service-before-catalog-commit",
            Self::CatalogCommitted => "service-catalog-committed",
            Self::CiphertextUnlinked => "service-ciphertext-unlinked",
            Self::CiphertextRemoved => "service-ciphertext-removed",
            Self::RecoveryCiphertextUnlinked => "service-recovery-ciphertext-unlinked",
            Self::RecoveryCiphertextRemoved => "service-recovery-ciphertext-removed",
            Self::RecoveryStagingUnlinked => "service-recovery-staging-unlinked",
            Self::RecoveryStagingRemoved => "service-recovery-staging-removed",
            Self::RecoveryOrphanUnlinked => "service-recovery-orphan-unlinked",
            Self::RecoveryOrphanRemoved => "service-recovery-orphan-removed",
            Self::RecoveryRepair => "service-recovery-repair",
            Self::CloseCatalogClosed => "service-close-catalog-closed",
            Self::CloseCleanMarkerTruncated => "service-close-clean-marker-truncated",
            Self::CloseCleanMarkerWritten => "service-close-clean-marker-written",
            Self::CloseCleanMarkerDurable => "service-close-clean-marker-durable",
        }
    }
}

pub const SERVICE_POINTS: [ServicePoint; 24] = [
    ServicePoint::CreationStorageDurable,
    ServicePoint::CreationCatalogDurable,
    ServicePoint::CreationDirtyMarkerTruncated,
    ServicePoint::CreationDirtyMarkerWritten,
    ServicePoint::CreationDirtyMarkerDurable,
    ServicePoint::WriterDirtyMarkerTruncated,
    ServicePoint::WriterDirtyMarkerWritten,
    ServicePoint::WriterDirtyMarkerDurable,
    ServicePoint::ObjectDurable,
    ServicePoint::BeforeCatalogCommit,
    ServicePoint::CatalogCommitted,
    ServicePoint::CiphertextUnlinked,
    ServicePoint::CiphertextRemoved,
    ServicePoint::RecoveryCiphertextUnlinked,
    ServicePoint::RecoveryCiphertextRemoved,
    ServicePoint::RecoveryStagingUnlinked,
    ServicePoint::RecoveryStagingRemoved,
    ServicePoint::RecoveryOrphanUnlinked,
    ServicePoint::RecoveryOrphanRemoved,
    ServicePoint::RecoveryRepair,
    ServicePoint::CloseCatalogClosed,
    ServicePoint::CloseCleanMarkerTruncated,
    ServicePoint::CloseCleanMarkerWritten,
    ServicePoint::CloseCleanMarkerDurable,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceIoPoint {
    CreationDirtyMarkerWrite,
    CreationDirtyMarkerSync,
    WriterDirtyMarkerWrite,
    WriterDirtyMarkerSync,
    CloseCleanMarkerWrite,
    CloseCleanMarkerSync,
    CiphertextDirectorySync,
    RecoveryCiphertextDirectorySync,
    RecoveryStagingDirectorySync,
    RecoveryOrphanDirectorySync,
}

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

    fn io_error(&mut self, _point: ServiceIoPoint) -> Option<io::Error> {
        None
    }
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
        Self::create_with_faults(
            path,
            password,
            keyfile,
            kdf_params,
            created_at_ms,
            &mut NoServiceFaults,
        )
    }

    /// Creation variant exposing only post-durability interruption boundaries.
    pub fn create_with_faults(
        path: &Path,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        created_at_ms: i64,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<Self, ServiceError> {
        let storage = UnlockedVault::create(path, password, keyfile, kdf_params)?;
        fail(faults, ServicePoint::CreationStorageDurable)?;
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
        fail(faults, ServicePoint::CreationCatalogDurable)?;
        lock.mark_creation_dirty(faults)?;
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
            lock.mark_writer_dirty(faults)?;
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
        self.catalog_import(descriptor, metadata, faults)
    }

    /// Publication variant used to prove exact filesystem failures cannot
    /// create catalog references.
    pub fn import_with_publication_faults(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        metadata: ImportMetadata<'_>,
        publication_faults: &mut impl osv_storage::PublishFaultInjector,
    ) -> Result<ObjectId, ServiceError> {
        self.require_writer()?;
        self.directory_binding.verify()?;
        let descriptor = self.storage().publish_object_observed_with_faults(
            source,
            logical_len,
            ObjectRole::Original,
            &self.security_lock_status,
            publication_faults,
        )?;
        self.record_lock_status(
            descriptor
                .publication_security_status()
                .expect("published objects record transient lock status")
                .page_locks(),
        );
        self.catalog_import(descriptor, metadata, &mut NoServiceFaults)
    }

    /// Import variant whose real catalog-commit sync fails in the anchored VFS.
    #[cfg(all(target_os = "linux", feature = "test-fixtures"))]
    pub fn import_with_catalog_sync_failure(
        &mut self,
        source: &mut impl Read,
        logical_len: u64,
        metadata: ImportMetadata<'_>,
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
        self.catalog().fail_next_sync_for_test()?;
        self.catalog_import(descriptor, metadata, &mut NoServiceFaults)
    }

    fn catalog_import(
        &mut self,
        descriptor: osv_storage::ObjectDescriptor,
        metadata: ImportMetadata<'_>,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<ObjectId, ServiceError> {
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
        self.cleanup_descriptors(&objects, faults)?;
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
        self.cleanup_descriptors(&old, faults)?;
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
                let mut removal_faults = ServiceRemovalFaults {
                    faults,
                    unlinked: ServicePoint::RecoveryCiphertextUnlinked,
                    durable: ServicePoint::RecoveryCiphertextRemoved,
                    sync: ServiceIoPoint::RecoveryCiphertextDirectorySync,
                };
                if self
                    .storage()
                    .remove_ciphertext_with_faults(id, role, &mut removal_faults)?
                {
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
            let mut removal_faults = ServiceRemovalFaults {
                faults,
                unlinked: ServicePoint::RecoveryStagingUnlinked,
                durable: ServicePoint::RecoveryStagingRemoved,
                sync: ServiceIoPoint::RecoveryStagingDirectorySync,
            };
            if self
                .storage()
                .remove_staging_ciphertext_with_faults(id, &mut removal_faults)?
            {
                report.removed_staging_files += 1;
            }
        }
        let physical: HashSet<_> = inventory
            .objects
            .iter()
            .map(|object| (object.id, object.role))
            .collect();
        for object in inventory.objects {
            if referenced.get(&object.id) != Some(&object.role) {
                let mut removal_faults = ServiceRemovalFaults {
                    faults,
                    unlinked: ServicePoint::RecoveryOrphanUnlinked,
                    durable: ServicePoint::RecoveryOrphanRemoved,
                    sync: ServiceIoPoint::RecoveryOrphanDirectorySync,
                };
                if self.storage().remove_ciphertext_with_faults(
                    object.id,
                    object.role,
                    &mut removal_faults,
                )? {
                    report.removed_orphans += 1;
                }
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

    pub fn close(self) -> Result<(), ServiceError> {
        self.close_with_faults(&mut NoServiceFaults)
    }

    /// Close variant exposing postcondition boundaries for crash tests.
    pub fn close_with_faults(
        mut self,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        self.directory_binding.verify()?;
        if self.mode == OpenMode::Writer {
            self.recover_with(&mut NoServiceFaults)?;
        }
        if let Some(catalog) = self.catalog.take() {
            catalog.close()?;
        }
        fail(faults, ServicePoint::CloseCatalogClosed)?;
        drop(self.storage.take());
        // Lock is deliberately still live until this function returns.
        if self.mode == OpenMode::Writer {
            self.lock.mark_clean_with(faults)?;
        }
        Ok(())
    }

    fn cleanup_descriptors(
        &self,
        objects: &[osv_catalog::CleanupObject],
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        for object in objects {
            match self.catalog().reader().object(object.id) {
                Ok(_) => return Err(ServiceError::CleanupConflict),
                Err(CatalogError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for object in objects {
            let mut removal_faults = ServiceRemovalFaults {
                faults,
                unlinked: ServicePoint::CiphertextUnlinked,
                durable: ServicePoint::CiphertextRemoved,
                sync: ServiceIoPoint::CiphertextDirectorySync,
            };
            self.storage().remove_ciphertext_with_faults(
                object.id,
                object.role,
                &mut removal_faults,
            )?;
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
        if require_sidecars {
            let member = "catalog.db-wal";
            let sidecar = platform::open_regular_member(directory, member)?;
            let identity = platform::identity(&sidecar)?;
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

fn service_io_fail(
    faults: &mut impl ServiceFaultInjector,
    point: ServiceIoPoint,
) -> Result<(), ServiceError> {
    faults
        .io_error(point)
        .map_or(Ok(()), |error| Err(error.into()))
}

struct ServiceRemovalFaults<'faults, F> {
    faults: &'faults mut F,
    unlinked: ServicePoint,
    durable: ServicePoint,
    sync: ServiceIoPoint,
}

impl<F: ServiceFaultInjector> RemovalFaultInjector for ServiceRemovalFaults<'_, F> {
    fn should_fail(&mut self, point: RemovalPoint) -> bool {
        let service_point = match point {
            RemovalPoint::Unlinked => self.unlinked,
            RemovalPoint::DirectoryDurable => self.durable,
        };
        self.faults.should_fail(service_point)
    }

    fn io_error(&mut self, point: RemovalIoPoint) -> Option<io::Error> {
        match point {
            RemovalIoPoint::DirectorySync => self.faults.io_error(self.sync),
        }
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

    fn mark_creation_dirty(
        &mut self,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        self.write_state_with(
            b'D',
            faults,
            ServicePoint::CreationDirtyMarkerTruncated,
            ServicePoint::CreationDirtyMarkerWritten,
            ServicePoint::CreationDirtyMarkerDurable,
            ServiceIoPoint::CreationDirtyMarkerWrite,
            ServiceIoPoint::CreationDirtyMarkerSync,
        )
    }

    fn mark_writer_dirty(
        &mut self,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        self.write_state_with(
            b'D',
            faults,
            ServicePoint::WriterDirtyMarkerTruncated,
            ServicePoint::WriterDirtyMarkerWritten,
            ServicePoint::WriterDirtyMarkerDurable,
            ServiceIoPoint::WriterDirtyMarkerWrite,
            ServiceIoPoint::WriterDirtyMarkerSync,
        )
    }

    fn mark_clean_with(
        &mut self,
        faults: &mut impl ServiceFaultInjector,
    ) -> Result<(), ServiceError> {
        self.write_state_with(
            b'C',
            faults,
            ServicePoint::CloseCleanMarkerTruncated,
            ServicePoint::CloseCleanMarkerWritten,
            ServicePoint::CloseCleanMarkerDurable,
            ServiceIoPoint::CloseCleanMarkerWrite,
            ServiceIoPoint::CloseCleanMarkerSync,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_state_with(
        &mut self,
        state: u8,
        faults: &mut impl ServiceFaultInjector,
        truncated: ServicePoint,
        written: ServicePoint,
        durable: ServicePoint,
        write_io: ServiceIoPoint,
        sync_io: ServiceIoPoint,
    ) -> Result<(), ServiceError> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        fail(faults, truncated)?;
        service_io_fail(faults, write_io)?;
        self.file.write_all(&[state])?;
        fail(faults, written)?;
        service_io_fail(faults, sync_io)?;
        self.file.sync_all()?;
        fail(faults, durable)
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
