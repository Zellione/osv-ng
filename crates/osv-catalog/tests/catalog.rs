use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use osv_catalog::{
    Catalog, CatalogConfig, CatalogError, CatalogMode, Child, GalleryId, MediaClass, MediaId,
    MigrationFaultInjector, MigrationPoint, NewGallery, NewMedia, NewObject, ObjectState, Result,
};
use osv_crypto::SecretKey;
use osv_storage::{ObjectDescriptor, ObjectId, ObjectRole, WrappedObjectKey};
use osv_test_support::{SecretCanary, TempVault};

const VAULT_ID: [u8; 16] = [0x41; 16];

fn key(byte: u8) -> SecretKey<32> {
    let mut bytes = [byte; 32];
    SecretKey::take(&mut bytes).unwrap()
}
fn temp() -> TempVault {
    TempVault::create_in(Path::new("/tmp")).unwrap()
}
fn descriptor(byte: u8, role: ObjectRole) -> ObjectDescriptor {
    ObjectDescriptor::from_catalog(
        ObjectId::from_bytes([byte; 16]),
        role,
        42,
        1,
        WrappedObjectKey::parse(&[byte; 72]).unwrap(),
    )
    .unwrap()
}

fn add_media(catalog: &mut Catalog, byte: u8, name: &str) -> MediaId {
    let object = descriptor(byte, ObjectRole::Original);
    let media_id = MediaId::from_bytes([byte.wrapping_add(100); 16]);
    let transaction = catalog.transaction().unwrap();
    transaction
        .insert_object(NewObject {
            descriptor: &object,
            locator: &format!("objects/{byte:02x}/{byte:02x}.osvo"),
            state: ObjectState::Ready,
        })
        .unwrap();
    transaction
        .insert_media(&NewMedia {
            id: media_id,
            original_object_id: object.id(),
            original_name: name,
            class: MediaClass::Image,
            mime: "image/png",
            width: Some(800),
            height: Some(600),
            duration_ms: None,
            codecs: "png",
            imported_at_ms: 1,
            fingerprint: &[byte; 32],
        })
        .unwrap();
    transaction.commit().unwrap();
    media_id
}

#[test]
fn encrypted_catalog_round_trip_policy_and_wrong_key() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(7);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    let media = add_media(&mut catalog, 1, "雪の café.png");
    let transaction = catalog.transaction().unwrap();
    let hits = transaction.search_media("café", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, media);
    assert!(transaction.search_media("x", 0).is_err());
    drop(transaction);
    assert_eq!(
        catalog.integrity_check().unwrap(),
        osv_catalog::IntegrityReport {
            cipher_ok: true,
            sqlite_ok: true,
            foreign_keys_ok: true
        }
    );
    assert!(catalog.path_is_redacted_in_debug());
    catalog.close().unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(Catalog::open(&path, &key(8), &VAULT_ID, CatalogMode::ReadOnly).is_err());
    Catalog::open(&path, &catalog_key, &VAULT_ID, CatalogMode::ReadOnly)
        .unwrap()
        .close()
        .unwrap();
}

#[test]
fn transactions_rollback_and_descriptors_round_trip() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(2);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    let object = descriptor(3, ObjectRole::Poster);
    {
        let transaction = catalog.transaction().unwrap();
        transaction
            .insert_object(NewObject {
                descriptor: &object,
                locator: "derived/posters/03/03.osvo",
                state: ObjectState::Damaged,
            })
            .unwrap();
    }
    let transaction = catalog.transaction().unwrap();
    assert!(matches!(
        transaction.object(object.id()),
        Err(CatalogError::NotFound)
    ));
    drop(transaction);
    let transaction = catalog.transaction().unwrap();
    transaction
        .insert_object(NewObject {
            descriptor: &object,
            locator: "derived/posters/03/03.osvo",
            state: ObjectState::Damaged,
        })
        .unwrap();
    transaction.commit().unwrap();
    let transaction = catalog.transaction().unwrap();
    let loaded = transaction.object(object.id()).unwrap();
    assert_eq!(loaded.descriptor.id(), object.id());
    assert_eq!(loaded.state, ObjectState::Damaged);
}

#[test]
fn hierarchy_is_ordered_and_cycles_are_rejected() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(3);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    let media = add_media(&mut catalog, 4, "image.png");
    let a = GalleryId::from_bytes([1; 16]);
    let b = GalleryId::from_bytes([2; 16]);
    let c = GalleryId::from_bytes([3; 16]);
    let transaction = catalog.transaction().unwrap();
    for (id, name) in [(a, "A"), (b, "B"), (c, "C")] {
        transaction
            .create_gallery(NewGallery {
                id,
                name,
                created_at_ms: 1,
            })
            .unwrap();
    }
    transaction
        .add_gallery_child(a, 1, Child::Media(media))
        .unwrap();
    transaction
        .add_gallery_child(a, 0, Child::Gallery(b))
        .unwrap();
    transaction
        .add_gallery_child(b, 0, Child::Gallery(c))
        .unwrap();
    assert!(matches!(
        transaction.add_gallery_child(c, 0, Child::Gallery(a)),
        Err(CatalogError::Conflict)
    ));
    assert_eq!(
        transaction.gallery_children(a, 10).unwrap(),
        vec![Child::Gallery(b), Child::Media(media)]
    );
    transaction.commit().unwrap();
}

struct FailAt(MigrationPoint);
impl MigrationFaultInjector for FailAt {
    fn check(&mut self, point: MigrationPoint) -> Result<()> {
        if point == self.0 {
            Err(CatalogError::MigrationInterrupted)
        } else {
            Ok(())
        }
    }
}

#[test]
fn every_migration_boundary_rolls_back_and_resumes() {
    for (index, point) in [
        MigrationPoint::AfterBegin,
        MigrationPoint::AfterSchema,
        MigrationPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = temp();
        let path = directory.path().join("catalog.db");
        let catalog_key = key(10 + index as u8);
        let result = Catalog::create_with(
            &path,
            &catalog_key,
            &VAULT_ID,
            1,
            CatalogConfig::default(),
            &mut FailAt(point),
        );
        assert!(matches!(result, Err(CatalogError::MigrationInterrupted)));
        let catalog = Catalog::resume_migration(&path, &catalog_key, &VAULT_ID, 1).unwrap();
        assert_eq!(
            catalog.integrity_check().unwrap(),
            osv_catalog::IntegrityReport {
                cipher_ok: true,
                sqlite_ok: true,
                foreign_keys_ok: true
            }
        );
        catalog.close().unwrap();
    }
}

#[test]
fn database_wal_shm_temp_and_open_descriptors_hide_plaintext_canary() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(4);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    let canary = SecretCanary::new(b"OSV_PHASE5_CANARY_99f24a89c47d".to_vec());
    let name = std::str::from_utf8(canary.expose_for_test()).unwrap();
    add_media(&mut catalog, 5, name);
    for entry in fs::read_dir(directory.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(!canary.occurs_in(&fs::read(entry.path()).unwrap()));
        }
    }
    for entry in fs::read_dir(format!("/proc/{}/fd", std::process::id())).unwrap() {
        if let Ok(target) = fs::read_link(entry.unwrap().path())
            && target.starts_with(directory.path())
            && target.is_file()
        {
            assert!(!canary.occurs_in(&fs::read(target).unwrap()));
        }
    }
    catalog.close().unwrap();
    for entry in fs::read_dir(directory.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(!canary.occurs_in(&fs::read(entry.path()).unwrap()));
        }
    }
}

#[cfg(feature = "test-fixtures")]
#[test]
fn forced_crash_wal_recovers_without_plaintext_artifacts() {
    use osv_test_support::kill_child_at_boundary;
    use std::process::Command;

    let directory = temp();
    let mut command = Command::new(env!("CARGO_BIN_EXE_osv-catalog-crash-fixture"));
    command.arg(directory.path());
    kill_child_at_boundary(&mut command, "after-commit").unwrap();
    let canary = SecretCanary::new(b"OSV_PHASE5_CRASH_CANARY_4f95e6d3".to_vec());
    for entry in fs::read_dir(directory.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(!canary.occurs_in(&fs::read(entry.path()).unwrap()));
        }
    }
    let catalog = Catalog::open(
        &directory.path().join("catalog.db"),
        &key(0x55),
        &[0x66; 16],
        CatalogMode::ReadWrite,
    )
    .unwrap();
    assert_eq!(
        catalog.integrity_check().unwrap(),
        osv_catalog::IntegrityReport {
            cipher_ok: true,
            sqlite_ok: true,
            foreign_keys_ok: true
        }
    );
    catalog.close().unwrap();
}

#[cfg(feature = "test-fixtures")]
#[test]
fn forced_crash_at_each_migration_boundary_resumes() {
    use osv_test_support::kill_child_at_boundary;
    use std::process::Command;

    for point in [
        MigrationPoint::AfterBegin,
        MigrationPoint::AfterSchema,
        MigrationPoint::BeforeCommit,
    ] {
        let directory = temp();
        let mut command = Command::new(env!("CARGO_BIN_EXE_osv-catalog-crash-fixture"));
        command.arg(directory.path()).arg(point.name());
        kill_child_at_boundary(&mut command, point.name()).unwrap();
        let catalog = Catalog::resume_migration(
            &directory.path().join("catalog.db"),
            &key(0x55),
            &[0x66; 16],
            1,
        )
        .unwrap();
        assert_eq!(
            catalog.integrity_check().unwrap(),
            osv_catalog::IntegrityReport {
                cipher_ok: true,
                sqlite_ok: true,
                foreign_keys_ok: true
            }
        );
        catalog.close().unwrap();
    }
}

#[test]
fn authenticated_page_corruption_fails_closed() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(5);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    add_media(&mut catalog, 6, "corrupt-me.png");
    catalog.close().unwrap();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let len = file.metadata().unwrap().len();
    let offset = len / 2;
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
    if let Ok(catalog) = Catalog::open(&path, &catalog_key, &VAULT_ID, CatalogMode::ReadOnly)
        && let Ok(report) = catalog.integrity_check()
    {
        assert_ne!(
            report,
            osv_catalog::IntegrityReport {
                cipher_ok: true,
                sqlite_ok: true,
                foreign_keys_ok: true
            }
        );
    }
}

#[test]
fn bounds_and_uniqueness_are_enforced() {
    let directory = temp();
    let path = directory.path().join("catalog.db");
    let catalog_key = key(6);
    let mut catalog = Catalog::create(&path, &catalog_key, &VAULT_ID, 1).unwrap();
    let media = add_media(&mut catalog, 7, "name.png");
    let transaction = catalog.transaction().unwrap();
    let tag = transaction.create_tag("タグ").unwrap();
    transaction.tag_media(media, tag).unwrap();
    assert!(matches!(
        transaction.create_tag("タグ"),
        Err(CatalogError::Conflict)
    ));
    assert!(transaction.create_tag(&"x".repeat(4097)).is_err());
    transaction.commit().unwrap();
}
