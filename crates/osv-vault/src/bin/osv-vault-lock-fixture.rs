use std::{
    env,
    io::{self, Read, Write},
    path::Path,
};

use osv_crypto::Password;
use osv_vault::{OpenMode, VaultService};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or("missing vault path")?;
    let mode = match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("reader") => OpenMode::Reader,
        Some("writer") => OpenMode::Writer,
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
