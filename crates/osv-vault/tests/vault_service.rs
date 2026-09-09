use std::{
    fs,
    io::{self, Cursor, Read},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use osv_catalog::{Catalog, CatalogMode, MediaClass, MediaId, ObjectState};
use osv_crypto::{KdfParams, Password};
use osv_storage::{ObjectRole, UnlockedVault};
use osv_test_support::TempVault;
use osv_vault::{
    BackupFaultInjector, BackupPoint, ImportMetadata, OpenMode, ServiceError, ServiceFaultInjector,
    ServicePoint, VaultService, backup_closed, backup_closed_with,
};

fn params() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn metadata(byte: u8) -> ImportMetadata<'static> {
    ImportMetadata {
        id: MediaId::from_bytes([byte; 16]),
        original_name: "private-name.jpg",
        class: MediaClass::Image,
        mime: "image/jpeg",
        width: Some(10),
        height: Some(20),
        duration_ms: None,
        codecs: "",
        imported_at_ms: 1,
        fingerprint: &[0x55; 32],
    }
}

fn create(parent: &Path, name: &str) -> (std::path::PathBuf, Password, VaultService) {
    let path = parent.join(name);
    let password = Password::new(b"test password").unwrap();
    let vault = VaultService::create(&path, &password, None, params(), 1).unwrap();
    (path, password, vault)
}

struct FailAt(ServicePoint);
impl ServiceFaultInjector for FailAt {
    fn should_fail(&mut self, point: ServicePoint) -> bool {
        point == self.0
    }
}

#[test]
fn durable_import_round_trips_and_reader_mode_rejects_mutation() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    let plaintext = b"authenticated payload";
    let id = writer
        .import(
            &mut Cursor::new(plaintext),
            plaintext.len() as u64,
            metadata(1),
        )
        .unwrap();
    let mut opened = writer.open_object(id).unwrap();
    let mut output = Vec::new();
    std::io::Read::read_to_end(&mut opened, &mut output).unwrap();
    assert_eq!(output, plaintext);
    writer.close().unwrap();

    let mut reader = VaultService::open(&path, &password, None, OpenMode::Reader).unwrap();
    assert!(matches!(reader.transaction(), Err(ServiceError::ReadOnly)));
    reader.close().unwrap();
}

#[test]
fn shared_readers_coexist_and_exclude_writers() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, writer) = create(parent.path(), "vault");
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Writer),
        Err(ServiceError::LockContended)
    ));
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Reader),
        Err(ServiceError::LockContended)
    ));
    writer.close().unwrap();

    let first = VaultService::open(&path, &password, None, OpenMode::Reader).unwrap();
    let second = VaultService::open(&path, &password, None, OpenMode::Reader).unwrap();
    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Writer),
        Err(ServiceError::LockContended)
    ));
    first.close().unwrap();
    second.close().unwrap();
}

#[test]
fn interrupted_import_is_an_orphan_and_startup_recovery_removes_it() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    let result = writer.import_with(
        &mut Cursor::new(b"orphan"),
        6,
        metadata(2),
        &mut FailAt(ServicePoint::ObjectDurable),
    );
    assert!(matches!(result, Err(ServiceError::InjectedFault(_))));
    drop(writer);

    let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
    assert_eq!(recovered.startup_recovery().removed_orphans, 1);
    recovered.close().unwrap();
}

#[test]
fn deletion_commits_key_removal_before_recoverable_ciphertext_cleanup() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    let id = writer
        .import(&mut Cursor::new(b"delete me"), 9, metadata(3))
        .unwrap();
    let result = writer.delete_media_with(
        MediaId::from_bytes([3; 16]),
        2,
        &mut FailAt(ServicePoint::CatalogCommitted),
    );
    assert!(matches!(result, Err(ServiceError::InjectedFault(_))));
    assert!(writer.reader().object(id).is_err());
    drop(writer);

    let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
    assert_eq!(recovered.startup_recovery().repaired_operations, 1);
    assert_eq!(recovered.startup_recovery().removed_orphans, 1);
    recovered.close().unwrap();
}

#[test]
fn missing_and_corrupt_objects_are_reported_and_marked_damaged() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    let first = writer
        .import(&mut Cursor::new(b"missing"), 7, metadata(4))
        .unwrap();
    let second = writer
        .import(&mut Cursor::new(b"corrupt"), 7, metadata(5))
        .unwrap();
    let derived = writer
        .replace_derived(
            &mut Cursor::new(b"bad thumb"),
            9,
            MediaId::from_bytes([5; 16]),
            ObjectRole::Thumbnail,
            1,
            5,
            5,
            2,
        )
        .unwrap();
    writer.close().unwrap();

    let locator = |id: osv_storage::ObjectId| {
        let hex: String = id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        path.join("objects")
            .join(&hex[..2])
            .join(format!("{hex}.osvo"))
    };
    fs::remove_file(locator(first)).unwrap();
    let corrupt = locator(second);
    let mut bytes = fs::read(&corrupt).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&corrupt, bytes).unwrap();
    let derived_hex: String = derived
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let corrupt_derived = path
        .join("derived/thumbnails")
        .join(&derived_hex[..2])
        .join(format!("{derived_hex}.osvo"));
    let mut bytes = fs::read(&corrupt_derived).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&corrupt_derived, bytes).unwrap();

    let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
    assert_eq!(recovered.startup_recovery().issues.len(), 3);
    assert_eq!(
        recovered.reader().object(first).unwrap().state,
        ObjectState::Damaged
    );
    assert_eq!(
        recovered.reader().object(second).unwrap().state,
        ObjectState::Damaged
    );
    assert_eq!(
        recovered.reader().object(derived).unwrap().state,
        ObjectState::Damaged
    );
    assert!(matches!(
        recovered.open_object(first),
        Err(ServiceError::DamagedObject)
    ));
    recovered.close().unwrap();
}

struct FailBackup(bool);
impl BackupFaultInjector for FailBackup {
    fn should_fail(&mut self, point: BackupPoint) -> bool {
        point == BackupPoint::EntryCopied && std::mem::replace(&mut self.0, false)
    }
}

#[test]
fn closed_backup_restores_and_partial_backup_fails_closed() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    writer
        .import(&mut Cursor::new(b"backup"), 6, metadata(6))
        .unwrap();
    assert!(matches!(
        backup_closed(&path, &parent.path().join("busy-copy")),
        Err(ServiceError::LockContended)
    ));
    writer.close().unwrap();

    let copy = parent.path().join("copy");
    backup_closed(&path, &copy).unwrap();
    VaultService::open(&copy, &password, None, OpenMode::Writer)
        .unwrap()
        .close()
        .unwrap();

    let partial = parent.path().join("partial");
    assert!(matches!(
        backup_closed_with(&path, &partial, &mut FailBackup(true)),
        Err(ServiceError::BackupInterrupted(_))
    ));
    assert!(VaultService::open(&partial, &password, None, OpenMode::Reader).is_err());
}

#[test]
fn backup_rejects_normalized_and_symlink_aliased_descendants() {
    use std::os::unix::fs::symlink;

    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, _password, writer) = create(parent.path(), "vault");
    writer.close().unwrap();

    fs::create_dir(path.join("nested")).unwrap();
    assert!(matches!(
        backup_closed(&path, &path.join("nested/../copy")),
        Err(ServiceError::InvalidInput)
    ));

    let alias = parent.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(backup_closed(&path, &alias.join("nested/copy")).is_err());
}

#[test]
fn reader_is_non_mutating_and_works_without_directory_write_access() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    writer
        .import(&mut Cursor::new(b"read only"), 9, metadata(12))
        .unwrap();
    writer.close().unwrap();
    fs::remove_file(path.join("catalog.db-wal")).unwrap();
    let mut writer = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
    // Churn allocations after SQLite has retained its delegated VFS filename,
    // then force journal/WAL path use and a clean checkpoint.
    let churn: Vec<String> = (0..2_048)
        .map(|index| format!("allocation-{index}"))
        .collect();
    let transaction = writer.transaction().unwrap();
    transaction.create_tag("recreated WAL").unwrap();
    transaction.commit().unwrap();
    drop(churn);
    writer.close().unwrap();
    assert_eq!(fs::metadata(path.join("catalog.db-wal")).unwrap().len(), 0);
    let before: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    let reader = VaultService::open(&path, &password, None, OpenMode::Reader).unwrap();
    reader.close().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let after: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    assert_eq!(fs::metadata(path.join("catalog.db-wal")).unwrap().len(), 0);
}

#[test]
fn service_rejects_directory_and_catalog_name_substitution() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, _password, mut writer) = create(parent.path(), "directory-vault");
    let moved = parent.path().join("moved-vault");
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        writer.transaction(),
        Err(ServiceError::PathIdentityChanged)
    ));
    drop(writer);

    let ancestor = parent.path().join("ancestor");
    fs::create_dir(&ancestor).unwrap();
    let path = ancestor.join("vault");
    let (_path, _password, mut writer) = create(&ancestor, "vault");
    fs::rename(&ancestor, parent.path().join("moved-ancestor")).unwrap();
    fs::create_dir(&ancestor).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        writer.transaction(),
        Err(ServiceError::PathIdentityChanged)
    ));
    drop(writer);

    let (path, _password, mut writer) = create(parent.path(), "catalog-vault");
    fs::rename(path.join("catalog.db"), path.join("displaced.db")).unwrap();
    fs::File::create(path.join("catalog.db")).unwrap();
    assert!(matches!(
        writer.transaction(),
        Err(ServiceError::PathIdentityChanged)
    ));

    let (path, _password, mut writer) = create(parent.path(), "sidecar-vault");
    let replacement = path.join("catalog.db-wal");
    fs::rename(&replacement, parent.path().join("detached-wal")).unwrap();
    fs::write(&replacement, b"replacement must survive").unwrap();
    assert!(matches!(
        writer.transaction(),
        Err(ServiceError::PathIdentityChanged)
    ));
    assert!(matches!(
        writer.close(),
        Err(ServiceError::PathIdentityChanged)
    ));
    assert_eq!(fs::read(replacement).unwrap(), b"replacement must survive");
}

#[test]
fn writer_rejects_hard_linked_sidecar_before_sqlcipher_touches_it() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, writer) = create(parent.path(), "vault");
    writer.close().unwrap();
    let _ = fs::remove_file(path.join("catalog.db-shm"));
    let victim = parent.path().join("victim");
    let expected = vec![0x77; 32 * 1024];
    fs::write(&victim, &expected).unwrap();
    fs::hard_link(&victim, path.join("catalog.db-shm")).unwrap();

    assert!(VaultService::open(&path, &password, None, OpenMode::Writer).is_err());
    assert_eq!(fs::read(victim).unwrap(), expected);

    let (path, password, writer) = create(parent.path(), "main-file-vault");
    writer.close().unwrap();
    fs::rename(path.join("catalog.db"), path.join("real-catalog.db")).unwrap();
    let victim = parent.path().join("main-file-victim");
    fs::write(&victim, &expected).unwrap();
    fs::hard_link(&victim, path.join("catalog.db")).unwrap();
    assert!(VaultService::open(&path, &password, None, OpenMode::Writer).is_err());
    assert_eq!(fs::read(victim).unwrap(), expected);
}

struct ReparentDestination {
    destination: std::path::PathBuf,
    moved: std::path::PathBuf,
}

impl BackupFaultInjector for ReparentDestination {
    fn should_fail(&mut self, point: BackupPoint) -> bool {
        if point == BackupPoint::DestinationCreated {
            fs::rename(&self.destination, &self.moved).unwrap();
        }
        false
    }
}

#[test]
fn backup_walker_rejects_destination_reparented_into_source() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, _password, writer) = create(parent.path(), "vault");
    writer.close().unwrap();
    let destination = parent.path().join("copy");
    let mut fault = ReparentDestination {
        destination: destination.clone(),
        moved: path.join("copy"),
    };
    assert!(matches!(
        backup_closed_with(&path, &destination, &mut fault),
        Err(ServiceError::InvalidInput)
    ));
    assert!(!path.join("copy/copy").exists());
}

#[test]
fn recovery_refuses_to_unlink_a_live_catalog_object() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    let id = writer
        .import(&mut Cursor::new(b"still live"), 10, metadata(13))
        .unwrap();
    writer.close().unwrap();

    let storage = UnlockedVault::unlock(&path, &password, None).unwrap();
    let mut catalog = Catalog::open(
        &path.join("catalog.db"),
        &storage.derived_keys().catalog,
        storage.header().vault_id().as_bytes(),
        CatalogMode::ReadWrite,
    )
    .unwrap();
    let mut payload = vec![ObjectRole::Original as u8];
    payload.extend_from_slice(id.as_bytes());
    let tx = catalog.transaction().unwrap();
    tx.insert_operation([0x71; 16], 1, 1, &payload, 2).unwrap();
    tx.commit().unwrap();
    catalog.close().unwrap();
    drop(storage);

    assert!(matches!(
        VaultService::open(&path, &password, None, OpenMode::Writer),
        Err(ServiceError::CleanupConflict)
    ));
    assert!(
        path.join(UnlockedVault::object_locator(id, ObjectRole::Original))
            .exists()
    );
}

#[test]
fn unclean_close_blocks_backup_until_writer_recovery_closes_cleanly() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, writer) = create(parent.path(), "vault");
    drop(writer);
    assert!(matches!(
        backup_closed(&path, &parent.path().join("rejected")),
        Err(ServiceError::UncleanVault)
    ));
    VaultService::open(&path, &password, None, OpenMode::Writer)
        .unwrap()
        .close()
        .unwrap();
    backup_closed(&path, &parent.path().join("accepted")).unwrap();
}

#[cfg(unix)]
#[test]
fn publication_permission_failure_never_creates_a_catalog_reference() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, _password, mut writer) = create(parent.path(), "vault");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    let result = writer.import(&mut Cursor::new(b"denied"), 6, metadata(8));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert!(writer.reader().all_objects().unwrap().is_empty());
    writer.close().unwrap();
}

struct DiskFull;

impl Read for DiskFull {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }
}

#[test]
fn disk_full_io_failure_leaves_no_reference_and_staging_is_recoverable() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (path, password, mut writer) = create(parent.path(), "vault");
    assert!(writer.import(&mut DiskFull, 1, metadata(9)).is_err());
    assert!(writer.reader().all_objects().unwrap().is_empty());
    drop(writer);
    let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
    assert_eq!(recovered.startup_recovery().removed_staging_files, 1);
    recovered.close().unwrap();
}

#[test]
fn derived_replacement_switches_catalog_then_removes_old_ciphertext() {
    let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
    let (_path, _password, mut writer) = create(parent.path(), "vault");
    writer
        .import(&mut Cursor::new(b"original"), 8, metadata(7))
        .unwrap();
    let first = writer
        .replace_derived(
            &mut Cursor::new(b"thumb one"),
            9,
            MediaId::from_bytes([7; 16]),
            ObjectRole::Thumbnail,
            1,
            10,
            10,
            2,
        )
        .unwrap();
    let second = writer
        .replace_derived(
            &mut Cursor::new(b"thumb two"),
            9,
            MediaId::from_bytes([7; 16]),
            ObjectRole::Thumbnail,
            2,
            20,
            20,
            3,
        )
        .unwrap();
    assert!(writer.reader().object(first).is_err());
    assert!(writer.reader().object(second).is_ok());
    writer.close().unwrap();
}
