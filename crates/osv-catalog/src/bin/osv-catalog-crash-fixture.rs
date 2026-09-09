use std::{
    env,
    io::{self, Read, Write},
    path::Path,
};

use osv_catalog::{
    Catalog, CatalogConfig, MediaClass, MediaId, MigrationFaultInjector, MigrationPoint, NewMedia,
    NewObject, ObjectState,
};
use osv_crypto::{LockStatus, SecretKey};
use osv_storage::{ObjectDescriptor, ObjectId, ObjectRole, WrappedObjectKey};

fn main() {
    if let Err(error) = run() {
        eprintln!("catalog crash fixture failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let directory = env::args_os().nth(1).ok_or("missing fixture directory")?;
    let boundary = env::args()
        .nth(2)
        .unwrap_or_else(|| "after-commit".to_owned());
    let path = Path::new(&directory).join("catalog.db");
    let mut bytes = [0x55; 32];
    let key = SecretKey::take(&mut bytes)?;
    if boundary == "security-status-degraded" {
        if key.lock_status() != LockStatus::Locked {
            return Err("fixture catalog key was not page-locked before lowering the limit".into());
        }
        disable_memlock()?;
        let catalog = Catalog::create(&path, &key, &[0x66; 16], 1)?;
        if catalog.security_status().page_locks() != LockStatus::Degraded {
            return Err("catalog did not report degraded raw-key page locking".into());
        }
        catalog.close()?;
        return Ok(());
    }
    if boundary.starts_with("migration-") {
        let mut injector = PauseAt(boundary);
        let _catalog = Catalog::create_with(
            &path,
            &key,
            &[0x66; 16],
            1,
            CatalogConfig::default(),
            &mut injector,
        )?;
        return Err("migration fixture was not interrupted".into());
    }
    let mut catalog = Catalog::create(&path, &key, &[0x66; 16], 1)?;
    let object = ObjectDescriptor::from_catalog(
        ObjectId::from_bytes([0x77; 16]),
        ObjectRole::Original,
        1,
        1,
        WrappedObjectKey::parse(&[0x88; 72])?,
    )?;
    let transaction = catalog.transaction()?;
    transaction.insert_object(NewObject {
        descriptor: &object,
        locator: "objects/77/77.osvo",
        state: ObjectState::Ready,
    })?;
    transaction.insert_media(&NewMedia {
        id: MediaId::from_bytes([0x99; 16]),
        original_object_id: object.id(),
        original_name: "OSV_PHASE5_CRASH_CANARY_4f95e6d3",
        class: MediaClass::Image,
        mime: "image/png",
        width: Some(1),
        height: Some(1),
        duration_ms: None,
        codecs: "png",
        imported_at_ms: 1,
        fingerprint: &[0xaa; 32],
    })?;
    transaction.commit()?;
    println!("after-commit");
    io::stdout().flush()?;
    let mut byte = [0];
    io::stdin().read_exact(&mut byte)?;
    drop(catalog);
    Ok(())
}

#[allow(unsafe_code)]
fn disable_memlock() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid `rlimit` for this short-lived fixture process.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct PauseAt(String);
impl MigrationFaultInjector for PauseAt {
    fn check(&mut self, point: MigrationPoint) -> osv_catalog::Result<()> {
        if point.name() == self.0 {
            println!("{}", point.name());
            io::stdout().flush()?;
            let mut byte = [0];
            io::stdin().read_exact(&mut byte)?;
        }
        Ok(())
    }
}
