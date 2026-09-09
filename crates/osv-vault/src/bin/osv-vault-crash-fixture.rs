use std::{
    env,
    io::{self, Cursor, Read, Write},
    path::Path,
};

use osv_catalog::{MediaClass, MediaId};
use osv_crypto::Password;
use osv_vault::{ImportMetadata, OpenMode, ServiceFaultInjector, ServicePoint, VaultService};

struct PauseAt(ServicePoint);

impl ServiceFaultInjector for PauseAt {
    fn should_fail(&mut self, point: ServicePoint) -> bool {
        if point != self.0 {
            return false;
        }
        println!("{}", point.name());
        io::stdout().flush().expect("flush crash boundary");
        let _ = io::stdin().read(&mut [0_u8; 1]);
        false
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or("missing vault path")?;
    let operation = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing operation")?;
    let boundary = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing boundary")?;
    let point = osv_vault::SERVICE_POINTS
        .into_iter()
        .find(|point| point.name() == boundary)
        .ok_or("invalid boundary")?;
    let password = Password::new(b"crash fixture password")?;
    if operation == "recover" {
        let _vault = VaultService::open_with_recovery_faults(
            Path::new(&path),
            &password,
            None,
            OpenMode::Writer,
            &mut PauseAt(point),
        )?;
        return Err("fixture passed selected boundary without being killed".into());
    }
    let mut vault = VaultService::open(Path::new(&path), &password, None, OpenMode::Writer)?;
    match operation.as_str() {
        "import" => {
            vault.import_with(
                &mut Cursor::new(b"crash import"),
                12,
                ImportMetadata {
                    id: MediaId::from_bytes([0x41; 16]),
                    original_name: "crash-fixture.jpg",
                    class: MediaClass::Image,
                    mime: "image/jpeg",
                    width: Some(1),
                    height: Some(1),
                    duration_ms: None,
                    codecs: "",
                    imported_at_ms: 2,
                    fingerprint: &[0x42; 32],
                },
                &mut PauseAt(point),
            )?;
        }
        "delete" => {
            vault.delete_media_with(MediaId::from_bytes([0x41; 16]), 3, &mut PauseAt(point))?
        }
        "replace" => {
            vault.replace_derived_with(
                &mut Cursor::new(b"new derived"),
                11,
                MediaId::from_bytes([0x41; 16]),
                osv_storage::ObjectRole::Thumbnail,
                2,
                2,
                2,
                4,
                &mut PauseAt(point),
            )?;
        }
        _ => return Err("invalid operation".into()),
    }
    Err("fixture passed selected boundary without being killed".into())
}
