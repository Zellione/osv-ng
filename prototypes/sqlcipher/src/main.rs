use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const KEY_BYTES: usize = 32;
const BENCH_ROWS: u32 = 10_000;

#[derive(Debug)]
struct Config {
    directory: PathBuf,
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut directory = None;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--directory" => {
                    directory = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--directory requires a path".to_owned())?,
                    ));
                }
                "--help" | "-h" => return Ok(None),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }
        let directory = directory.unwrap_or_else(|| {
            env::temp_dir().join(format!("osv-sqlcipher-phase1-{}", std::process::id()))
        });
        Ok(Some(Self { directory }))
    }
}

#[derive(Debug)]
struct Benchmark {
    memory_security: bool,
    create_write: Duration,
    query: Duration,
    checkpoint: Duration,
}

fn main() {
    let config = match Config::from_args(env::args()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            println!("Usage: osv-sqlcipher-prototype [--directory EMPTY_DIR]");
            return;
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(&config) {
        eprintln!("SQLCipher prototype failed: {error}");
        std::process::exit(1);
    }
}

fn run(config: &Config) -> Result<(), Box<dyn Error>> {
    create_private_directory(&config.directory)?;
    let database = config.directory.join("crash.db");
    let key = random_bytes::<KEY_BYTES>()?;
    let canary = format!("OSV_PHASE1_CANARY_{}", hex(&random_bytes::<16>()?));

    let mut child = spawn_sqlcipher(&database)?;
    let mut stdin = child.stdin.take().ok_or("SQLCipher stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("SQLCipher stdout unavailable")?;
    let script = format!(
        ".bail on\n\
         PRAGMA key = \"x'{}'\";\n\
         PRAGMA cipher_memory_security = ON;\n\
         PRAGMA temp_store = MEMORY;\n\
         PRAGMA journal_mode = WAL;\n\
         PRAGMA wal_autocheckpoint = 0;\n\
         CREATE TABLE secrets(value TEXT NOT NULL);\n\
         INSERT INTO secrets VALUES('{}');\n\
         CREATE TEMP TABLE temp_secrets(value TEXT NOT NULL);\n\
         INSERT INTO temp_secrets VALUES('{}');\n\
         SELECT 'OSV_PHASE1_READY';\n",
        hex(&key),
        canary,
        canary
    );
    stdin.write_all(script.as_bytes())?;
    stdin.flush()?;
    wait_for_marker(stdout, "OSV_PHASE1_READY")?;

    let open_files = count_database_descriptors(child.id(), &config.directory)?;
    let pre_crash_artifacts = artifact_count(&config.directory)?;
    child.kill()?;
    let status = child.wait()?;
    drop(stdin);
    if status.success() {
        return Err("forced-crash process exited successfully".into());
    }
    let crash_hits = scan_for(&config.directory, canary.as_bytes())?;
    if !crash_hits.is_empty() {
        return Err(format!("plaintext canary found after crash in {crash_hits:?}").into());
    }

    let recovery = run_sql(
        &database,
        &format!(
            ".bail on\nPRAGMA key = \"x'{}'\";\nPRAGMA cipher_memory_security = ON;\nPRAGMA temp_store = MEMORY;\nSELECT value FROM secrets;\nPRAGMA cipher_integrity_check;\nPRAGMA integrity_check;\nPRAGMA temp_store;\nPRAGMA wal_checkpoint(TRUNCATE);\n",
            hex(&key)
        ),
    )?;
    if !recovery.status.success() {
        return Err("crash recovery/integrity process failed".into());
    }
    let recovery_stdout = String::from_utf8(recovery.stdout)?;
    if !recovery_stdout.contains(&canary)
        || recovery_stdout.lines().filter(|line| *line == "ok").count() < 2
        || !recovery_stdout.lines().any(|line| line == "2")
    {
        return Err("recovery, integrity, or memory temp-store verification failed".into());
    }
    let checkpoint_hits = scan_for(&config.directory, canary.as_bytes())?;
    if !checkpoint_hits.is_empty() {
        return Err(
            format!("plaintext canary found after checkpoint in {checkpoint_hits:?}").into(),
        );
    }

    verify_wrong_key_fails(&database, &canary)?;
    let memory_on = benchmark(&config.directory, true)?;
    let memory_off = benchmark(&config.directory, false)?;
    println!(
        "sqlcipher_version={} crash_recovery=true integrity=true temp_store_memory=true canary_disk_hits=0 open_database_fds={} pre_crash_artifacts={}",
        sqlcipher_version()?,
        open_files,
        pre_crash_artifacts
    );
    print_benchmark(&memory_on);
    print_benchmark(&memory_off);
    println!("artifacts_retained={}", config.directory.display());
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        if fs::read_dir(path)?.next().is_some() {
            return Err("experiment directory must be empty".into());
        }
    } else {
        fs::create_dir(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn spawn_sqlcipher(database: &Path) -> Result<Child, Box<dyn Error>> {
    Ok(Command::new("sqlcipher")
        .arg("-batch")
        .arg(database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn wait_for_marker(stdout: impl Read, marker: &str) -> Result<(), Box<dyn Error>> {
    for line in BufReader::new(stdout).lines() {
        if line? == marker {
            return Ok(());
        }
    }
    Err("SQLCipher exited before readiness marker".into())
}

fn run_sql(database: &Path, script: &str) -> Result<Output, Box<dyn Error>> {
    let mut child = spawn_sqlcipher(database)?;
    let mut stdin = child.stdin.take().ok_or("SQLCipher stdin unavailable")?;
    stdin.write_all(script.as_bytes())?;
    drop(stdin);
    Ok(child.wait_with_output()?)
}

fn verify_wrong_key_fails(database: &Path, canary: &str) -> Result<(), Box<dyn Error>> {
    let wrong_key = random_bytes::<KEY_BYTES>()?;
    let output = run_sql(
        database,
        &format!(
            ".bail on\nPRAGMA key = \"x'{}'\";\nSELECT value FROM secrets;\n",
            hex(&wrong_key)
        ),
    )?;
    if output.status.success()
        || output
            .stdout
            .windows(canary.len())
            .any(|window| window == canary.as_bytes())
        || output
            .stderr
            .windows(canary.len())
            .any(|window| window == canary.as_bytes())
    {
        return Err("wrong raw key did not fail safely".into());
    }
    Ok(())
}

fn benchmark(directory: &Path, memory_security: bool) -> Result<Benchmark, Box<dyn Error>> {
    let name = if memory_security {
        "memory-on.db"
    } else {
        "memory-off.db"
    };
    let database = directory.join(name);
    let key = random_bytes::<KEY_BYTES>()?;
    let setting = if memory_security { "ON" } else { "OFF" };
    let prefix = format!(
        ".bail on\nPRAGMA key = \"x'{}'\";\nPRAGMA cipher_memory_security = {setting};\n",
        hex(&key)
    );

    let start = Instant::now();
    ensure_success(run_sql(
        &database,
        &format!(
            "{prefix}PRAGMA journal_mode=WAL;\nPRAGMA wal_autocheckpoint=0;\nCREATE TABLE bench(id INTEGER PRIMARY KEY, value TEXT NOT NULL);\nBEGIN;\nWITH RECURSIVE counter(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM counter WHERE value < {BENCH_ROWS}) INSERT INTO bench(value) SELECT printf('synthetic-row-%08d', value) FROM counter;\nCOMMIT;\n"
        ),
    )?)?;
    let create_write = start.elapsed();

    let start = Instant::now();
    let query_output = run_sql(
        &database,
        &format!("{prefix}SELECT count(*), sum(length(value)) FROM bench;\n"),
    )?;
    ensure_success(query_output)?;
    let query = start.elapsed();

    let start = Instant::now();
    ensure_success(run_sql(
        &database,
        &format!("{prefix}PRAGMA wal_checkpoint(TRUNCATE);\n"),
    )?)?;
    let checkpoint = start.elapsed();
    Ok(Benchmark {
        memory_security,
        create_write,
        query,
        checkpoint,
    })
}

fn ensure_success(output: Output) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("SQLCipher command failed: {stderr}").into())
    }
}

fn print_benchmark(benchmark: &Benchmark) {
    println!(
        "memory_security={} rows={BENCH_ROWS} create_write_ms={:.2} query_ms={:.2} checkpoint_ms={:.2}",
        if benchmark.memory_security {
            "on"
        } else {
            "off"
        },
        benchmark.create_write.as_secs_f64() * 1_000.0,
        benchmark.query.as_secs_f64() * 1_000.0,
        benchmark.checkpoint.as_secs_f64() * 1_000.0,
    );
}

fn count_database_descriptors(pid: u32, directory: &Path) -> Result<usize, Box<dyn Error>> {
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))?;
    let mut count = 0;
    for descriptor in descriptors {
        let target = fs::read_link(descriptor?.path())?;
        if target.starts_with(directory) {
            count += 1;
        }
    }
    Ok(count)
}

fn artifact_count(directory: &Path) -> Result<usize, Box<dyn Error>> {
    Ok(fs::read_dir(directory)?.count())
}

fn scan_for(directory: &Path, needle: &[u8]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut hits = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        if bytes.windows(needle.len()).any(|window| window == needle) {
            hits.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(hits)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], Box<dyn Error>> {
    let mut bytes = [0_u8; N];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn sqlcipher_version() -> Result<String, Box<dyn Error>> {
    let output = Command::new("sqlcipher").arg("--version").output()?;
    ensure_success(output.clone())?;
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().next().unwrap_or("unknown").trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_fixed_width_and_lowercase() {
        assert_eq!(hex(&[0x00, 0x09, 0xaf, 0xff]), "0009afff");
    }

    #[test]
    fn default_directory_is_process_scoped() {
        let config = Config::from_args(["prototype".to_owned()])
            .unwrap()
            .unwrap();
        assert!(
            config
                .directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osv-sqlcipher-phase1-")
        );
    }
}
