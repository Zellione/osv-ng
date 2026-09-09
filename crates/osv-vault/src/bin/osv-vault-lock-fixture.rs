use std::{
    env, fs,
    io::{self, Cursor, Read, Write},
    path::Path,
};

use osv_catalog::{MediaClass, MediaId};
use osv_crypto::Password;
use osv_storage::{ObjectRole, UnlockedVault};
use osv_vault::{ImportMetadata, OpenMode, VaultService};

#[allow(unsafe_code)]
fn disable_page_locks() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit receives a valid pointer for this process-local limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn metadata(byte: u8) -> ImportMetadata<'static> {
    ImportMetadata {
        id: MediaId::from_bytes([byte; 16]),
        original_name: "fixture.jpg",
        class: MediaClass::Image,
        mime: "image/jpeg",
        width: Some(1),
        height: Some(1),
        duration_ms: None,
        codecs: "",
        imported_at_ms: 1,
        fingerprint: &[0x41; 32],
    }
}

#[allow(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or("missing vault path")?;
    let mode_argument = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing lock mode")?;
    if mode_argument == "security-status" {
        disable_page_locks()?;
        let password = Password::new(b"lock fixture password")?;
        let vault = VaultService::open(Path::new(&path), &password, None, OpenMode::Reader)?;
        println!("{:?}", vault.security_status().page_locks());
        return Ok(());
    }
    if mode_argument == "failed-import-status" {
        let password = Password::new(b"lock fixture password")?;
        let mut vault = VaultService::open(Path::new(&path), &password, None, OpenMode::Writer)?;
        disable_page_locks()?;
        struct FailedSource;
        impl Read for FailedSource {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture input failure"))
            }
        }
        let _ = vault.import(&mut FailedSource, 1, metadata(0x51));
        println!("{:?}", vault.security_status().page_locks());
        return Ok(());
    }
    if mode_argument == "mid-import-status" {
        let password = Password::new(b"lock fixture password")?;
        let mut vault = VaultService::open(Path::new(&path), &password, None, OpenMode::Writer)?;
        struct LowerThenFail(bool);
        impl Read for LowerThenFail {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("fixture second-chunk failure"));
                }
                self.0 = true;
                disable_page_locks()?;
                buffer.fill(0x61);
                Ok(buffer.len())
            }
        }
        let logical_len = u64::from(osv_storage::DEFAULT_CHUNK_SIZE) + 1;
        let _ = vault.import(&mut LowerThenFail(false), logical_len, metadata(0x53));
        println!("{:?}", vault.security_status().page_locks());
        return Ok(());
    }
    if mode_argument == "failed-open-status" {
        let password = Password::new(b"lock fixture password")?;
        let mut vault = VaultService::open(Path::new(&path), &password, None, OpenMode::Writer)?;
        let id = vault.import(&mut Cursor::new(b"x"), 1, metadata(0x52))?;
        fs::write(
            Path::new(&path).join(UnlockedVault::object_locator(id, ObjectRole::Original)),
            b"invalid fixture object",
        )?;
        disable_page_locks()?;
        let _ = vault.open_object(id);
        println!("{:?}", vault.security_status().page_locks());
        return Ok(());
    }
    let mode = match mode_argument.as_str() {
        "reader" => OpenMode::Reader,
        "writer" => OpenMode::Writer,
        _ => return Err("invalid lock mode".into()),
    };
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let password = Password::new(b"lock fixture password")?;
    let _vault = VaultService::open(Path::new(&path), &password, None, mode)?;
    let boundary = match mode {
        OpenMode::Reader => "reader-held",
        OpenMode::Writer => "writer-held",
    };
    println!("{boundary}");
    io::stdout().flush()?;
    let _ = io::stdin().read(&mut [0_u8; 1]);
    Ok(())
}
