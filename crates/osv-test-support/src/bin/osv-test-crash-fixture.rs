use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const FIXTURE_BYTES: &[u8] = b"public crash fixture";

fn pause_at(selected: &str, current: &str) -> io::Result<()> {
    if selected != current {
        return Ok(());
    }

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{current}")?;
    stdout.flush()?;
    drop(stdout);

    io::copy(&mut io::stdin().lock(), &mut io::sink())?;
    Ok(())
}

fn main() -> io::Result<()> {
    let selected = env::var("OSV_TEST_FAULT_POINT")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "missing fault point"))?;

    fs::create_dir("staging")?;
    fs::create_dir("objects")?;

    let staged_path = Path::new("staging/object.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut staged = options.open(staged_path)?;
    staged.write_all(FIXTURE_BYTES)?;
    staged.sync_all()?;
    drop(staged);
    pause_at(&selected, "after-staging-sync")?;

    fs::rename(staged_path, "objects/object")?;
    pause_at(&selected, "after-publish-rename")?;

    OpenOptions::new().read(true).open("objects")?.sync_all()?;
    pause_at(&selected, "after-directory-sync")?;

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "unknown fault point",
    ))
}
