#![cfg(feature = "test-fixtures")]

use std::{io::Cursor, path::Path, process::Command};

use osv_catalog::{MediaClass, MediaId};
use osv_crypto::{KdfParams, Password, SystemRandom};
use osv_storage::{MIN_CHUNK_SIZE, ObjectRole, PublishFaultInjector, PublishPoint, UnlockedVault};
use osv_test_support::{TempVault, kill_child_at_boundary};
use osv_vault::{ImportMetadata, OpenMode, ServiceFaultInjector, ServicePoint, VaultService};

fn create(path: &Path) -> (Password, VaultService) {
    let password = Password::new(b"crash fixture password").unwrap();
    let service =
        VaultService::create(path, &password, None, KdfParams::new(8, 1, 1).unwrap(), 1).unwrap();
    (password, service)
}

fn import_fixture(service: &mut VaultService) {
    service
        .import(
            &mut Cursor::new(b"existing data"),
            13,
            ImportMetadata {
                id: MediaId::from_bytes([0x41; 16]),
                original_name: "existing.jpg",
                class: MediaClass::Image,
                mime: "image/jpeg",
                width: Some(1),
                height: Some(1),
                duration_ms: None,
                codecs: "",
                imported_at_ms: 1,
                fingerprint: &[0x43; 32],
            },
        )
        .unwrap();
}

struct FailPublishAt(PublishPoint);

impl PublishFaultInjector for FailPublishAt {
    fn should_fail(&mut self, point: PublishPoint) -> bool {
        point == self.0
    }
}

struct FailServiceAt(ServicePoint);

impl ServiceFaultInjector for FailServiceAt {
    fn should_fail(&mut self, point: ServicePoint) -> bool {
        point == self.0
    }
}

#[test]
fn subprocess_kills_converge_at_every_composition_boundary() {
    for point in [
        ServicePoint::CreationStorageDurable,
        ServicePoint::CreationCatalogDurable,
        ServicePoint::CreationDirtyMarkerTruncated,
        ServicePoint::CreationDirtyMarkerWritten,
        ServicePoint::CreationDirtyMarkerDurable,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("creation-crash");
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("create").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();

        if point == ServicePoint::CreationStorageDurable {
            assert!(
                VaultService::open(
                    &path,
                    &Password::new(b"crash fixture password").unwrap(),
                    None,
                    OpenMode::Writer
                )
                .is_err()
            );
        } else {
            let recovered = VaultService::open(
                &path,
                &Password::new(b"crash fixture password").unwrap(),
                None,
                OpenMode::Writer,
            )
            .unwrap();
            recovered.close().unwrap();
        }
    }

    for point in [
        ServicePoint::WriterDirtyMarkerTruncated,
        ServicePoint::WriterDirtyMarkerWritten,
        ServicePoint::WriterDirtyMarkerDurable,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("writer-dirty-marker-crash");
        let (password, service) = create(&path);
        service.close().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("recover").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        assert!(matches!(
            VaultService::open(&path, &password, None, OpenMode::Reader),
            Err(osv_vault::ServiceError::UncleanVault)
        ));
        VaultService::open(&path, &password, None, OpenMode::Writer)
            .unwrap()
            .close()
            .unwrap();
    }

    for point in [
        ServicePoint::ObjectDurable,
        ServicePoint::BeforeCatalogCommit,
        ServicePoint::CatalogCommitted,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("import-crash");
        let (password, service) = create(&path);
        service.close().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("import").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
        let expected = usize::from(point == ServicePoint::CatalogCommitted);
        assert_eq!(recovered.reader().all_objects().unwrap().len(), expected);
        assert!(recovered.reader().operation_journal().unwrap().is_empty());
        recovered.close().unwrap();
    }

    for point in [
        ServicePoint::BeforeCatalogCommit,
        ServicePoint::CatalogCommitted,
        ServicePoint::CiphertextUnlinked,
        ServicePoint::CiphertextRemoved,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("delete-crash");
        let (password, mut service) = create(&path);
        import_fixture(&mut service);
        service.close().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("delete").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
        let expected = usize::from(point == ServicePoint::BeforeCatalogCommit);
        assert_eq!(recovered.reader().all_objects().unwrap().len(), expected);
        assert!(recovered.reader().operation_journal().unwrap().is_empty());
        recovered.close().unwrap();
    }

    for point in [
        ServicePoint::ObjectDurable,
        ServicePoint::BeforeCatalogCommit,
        ServicePoint::CatalogCommitted,
        ServicePoint::CiphertextUnlinked,
        ServicePoint::CiphertextRemoved,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("replacement-crash");
        let (password, mut service) = create(&path);
        import_fixture(&mut service);
        service
            .replace_derived(
                &mut Cursor::new(b"old derived"),
                11,
                MediaId::from_bytes([0x41; 16]),
                ObjectRole::Thumbnail,
                1,
                1,
                1,
                2,
            )
            .unwrap();
        service.close().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("replace").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
        let objects = recovered.reader().all_objects().unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(
            objects
                .iter()
                .filter(|object| object.descriptor.role() == ObjectRole::Thumbnail)
                .count(),
            1
        );
        assert!(recovered.reader().operation_journal().unwrap().is_empty());
        recovered.close().unwrap();
    }

    for point in [
        ServicePoint::RecoveryCiphertextUnlinked,
        ServicePoint::RecoveryCiphertextRemoved,
        ServicePoint::RecoveryRepair,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("recovery-crash");
        let (password, mut service) = create(&path);
        import_fixture(&mut service);
        service.close().unwrap();
        let mut deletion = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        deletion
            .arg(&path)
            .arg("delete")
            .arg(ServicePoint::CatalogCommitted.name());
        kill_child_at_boundary(&mut deletion, ServicePoint::CatalogCommitted.name()).unwrap();
        let mut recovery = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        recovery.arg(&path).arg("recover").arg(point.name());
        kill_child_at_boundary(&mut recovery, point.name()).unwrap();
        let recovered = VaultService::open(&path, &password, None, OpenMode::Writer).unwrap();
        assert!(recovered.reader().all_objects().unwrap().is_empty());
        assert!(recovered.reader().operation_journal().unwrap().is_empty());
        recovered.close().unwrap();
    }

    for point in [
        ServicePoint::RecoveryOrphanUnlinked,
        ServicePoint::RecoveryOrphanRemoved,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("orphan-recovery-crash");
        let (password, mut service) = create(&path);
        assert!(
            service
                .import_with(
                    &mut Cursor::new(b"orphan"),
                    6,
                    ImportMetadata {
                        id: MediaId::from_bytes([0x52; 16]),
                        original_name: "orphan.jpg",
                        class: MediaClass::Image,
                        mime: "image/jpeg",
                        width: Some(1),
                        height: Some(1),
                        duration_ms: None,
                        codecs: "",
                        imported_at_ms: 3,
                        fingerprint: &[0x53; 32],
                    },
                    &mut FailServiceAt(ServicePoint::ObjectDurable),
                )
                .is_err()
        );
        drop(service);
        let mut recovery = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        recovery.arg(&path).arg("recover").arg(point.name());
        kill_child_at_boundary(&mut recovery, point.name()).unwrap();
        VaultService::open(&path, &password, None, OpenMode::Writer)
            .unwrap()
            .close()
            .unwrap();
    }

    for point in [
        ServicePoint::RecoveryStagingUnlinked,
        ServicePoint::RecoveryStagingRemoved,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("staging-recovery-crash");
        let (password, service) = create(&path);
        service.close().unwrap();
        let storage = UnlockedVault::unlock(&path, &password, None).unwrap();
        assert!(
            storage
                .publish_object_with(
                    &mut Cursor::new(b"staging"),
                    7,
                    ObjectRole::Original,
                    MIN_CHUNK_SIZE,
                    &mut SystemRandom,
                    &mut FailPublishAt(PublishPoint::StagingCreated),
                )
                .is_err()
        );
        drop(storage);
        let mut recovery = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        recovery.arg(&path).arg("recover").arg(point.name());
        kill_child_at_boundary(&mut recovery, point.name()).unwrap();
        VaultService::open(&path, &password, None, OpenMode::Writer)
            .unwrap()
            .close()
            .unwrap();
    }

    for point in [
        ServicePoint::CloseCatalogClosed,
        ServicePoint::CloseCleanMarkerTruncated,
        ServicePoint::CloseCleanMarkerWritten,
        ServicePoint::CloseCleanMarkerDurable,
    ] {
        let parent = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("close-crash");
        let (password, service) = create(&path);
        service.close().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-vault-crash-fixture"));
        command.arg(&path).arg("close").arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        let mode = if matches!(
            point,
            ServicePoint::CloseCleanMarkerWritten | ServicePoint::CloseCleanMarkerDurable
        ) {
            OpenMode::Reader
        } else {
            OpenMode::Writer
        };
        VaultService::open(&path, &password, None, mode)
            .unwrap()
            .close()
            .unwrap();
    }
}
