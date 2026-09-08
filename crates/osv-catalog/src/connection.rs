use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use osv_crypto::{SecretBytes, SecretKey};
use rusqlite::{Connection, OpenFlags, config::DbConfig, ffi};

use crate::{
    CatalogError, MigrationFaultInjector, NoMigrationFault, Result,
    repository::CatalogTransaction,
    schema::{migrate, validate_migration_record},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug)]
pub struct CatalogConfig {
    pub busy_timeout: Duration,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityReport {
    pub cipher_ok: bool,
    pub sqlite_ok: bool,
    pub foreign_keys_ok: bool,
}

pub struct Catalog {
    pub(crate) connection: Connection,
    mode: CatalogMode,
    path: PathBuf,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Catalog")
            .field("mode", &self.mode)
            .field("path", &"[REDACTED]")
            .finish()
    }
}

impl Catalog {
    pub fn create(
        path: &Path,
        key: &SecretKey<32>,
        vault_id: &[u8; 16],
        created_at_ms: i64,
    ) -> Result<Self> {
        Self::create_with(
            path,
            key,
            vault_id,
            created_at_ms,
            CatalogConfig::default(),
            &mut NoMigrationFault,
        )
    }

    pub fn create_with(
        path: &Path,
        key: &SecretKey<32>,
        vault_id: &[u8; 16],
        created_at_ms: i64,
        config: CatalogConfig,
        faults: &mut impl MigrationFaultInjector,
    ) -> Result<Self> {
        if created_at_ms < 0 {
            return Err(CatalogError::InvalidInput("timestamp"));
        }
        create_catalog_file(path)?;
        let mut catalog = Self::open_connection(path, key, CatalogMode::ReadWrite, config)?;
        migrate(&mut catalog.connection, vault_id, created_at_ms, faults)?;
        catalog.verify_vault(vault_id)?;
        Ok(catalog)
    }

    /// Resumes a transaction-safe migration after an interrupted prior attempt.
    pub fn resume_migration(
        path: &Path,
        key: &SecretKey<32>,
        vault_id: &[u8; 16],
        created_at_ms: i64,
    ) -> Result<Self> {
        let mut catalog =
            Self::open_connection(path, key, CatalogMode::ReadWrite, CatalogConfig::default())?;
        migrate(
            &mut catalog.connection,
            vault_id,
            created_at_ms,
            &mut NoMigrationFault,
        )?;
        catalog.verify_vault(vault_id)?;
        Ok(catalog)
    }

    pub fn open(
        path: &Path,
        key: &SecretKey<32>,
        expected_vault_id: &[u8; 16],
        mode: CatalogMode,
    ) -> Result<Self> {
        let catalog = Self::open_connection(path, key, mode, CatalogConfig::default())?;
        let version: u32 = catalog
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != crate::SCHEMA_VERSION {
            return Err(CatalogError::UnknownSchema(version));
        }
        validate_migration_record(&catalog.connection)?;
        catalog.verify_vault(expected_vault_id)?;
        Ok(catalog)
    }

    fn open_connection(
        path: &Path,
        key: &SecretKey<32>,
        mode: CatalogMode,
        config: CatalogConfig,
    ) -> Result<Self> {
        validate_catalog_file(path)?;
        let flags = match mode {
            CatalogMode::ReadOnly => {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
            }
            CatalogMode::ReadWrite => {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
            }
        };
        let connection = Connection::open_with_flags(path, flags)?;
        apply_raw_key(&connection, key)?;
        configure(&connection, mode, config)?;
        Ok(Self {
            connection,
            mode,
            path: path.to_owned(),
        })
    }

    fn verify_vault(&self, expected: &[u8; 16]) -> Result<()> {
        let actual: Vec<u8> = self.connection.query_row(
            "SELECT vault_id FROM vault_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if actual.as_slice() != expected {
            return Err(CatalogError::IntegrityFailed);
        }
        Ok(())
    }

    pub fn transaction(&mut self) -> Result<CatalogTransaction<'_>> {
        if self.mode != CatalogMode::ReadWrite {
            return Err(CatalogError::InvalidInput("read-only transaction"));
        }
        CatalogTransaction::begin(&mut self.connection)
    }

    pub fn integrity_check(&self) -> Result<IntegrityReport> {
        let cipher_ok = pragma_all_ok(&self.connection, "PRAGMA cipher_integrity_check", true)?;
        let sqlite_ok = pragma_all_ok(&self.connection, "PRAGMA integrity_check", false)?;
        let foreign_keys_ok = self
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none();
        let report = IntegrityReport {
            cipher_ok,
            sqlite_ok,
            foreign_keys_ok,
        };
        Ok(report)
    }

    pub fn checkpoint_for_offline_backup(&mut self) -> Result<()> {
        if self.mode != CatalogMode::ReadWrite {
            return Err(CatalogError::InvalidInput("read-only checkpoint"));
        }
        let (busy, _pages, remaining): (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if busy != 0 || remaining != 0 {
            return Err(CatalogError::Conflict);
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        if self.mode == CatalogMode::ReadWrite {
            self.checkpoint_for_offline_backup()?;
        }
        self.connection
            .close()
            .map_err(|(_, error)| CatalogError::from(error))
    }

    #[must_use]
    pub fn path_is_redacted_in_debug(&self) -> bool {
        !format!("{self:?}").contains(&self.path.to_string_lossy().to_string())
    }
}

fn create_catalog_file(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(CatalogError::AlreadyExists);
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn validate_catalog_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CatalogError::InvalidInput("file"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn apply_raw_key(connection: &Connection, key: &SecretKey<32>) -> Result<()> {
    // SQLCipher's raw-key syntax is x'<64 hex digits>'. Build it in locked,
    // non-dumpable, wipe-on-drop memory rather than an ordinary String.
    let mut raw = SecretBytes::zeroed(67)?;
    let output = raw.expose_mut();
    output[..2].copy_from_slice(b"x'");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in key.expose().iter().copied().enumerate() {
        output[2 + index * 2] = HEX[usize::from(byte >> 4)];
        output[3 + index * 2] = HEX[usize::from(byte & 0x0f)];
    }
    output[66] = b'\'';
    // SAFETY: `connection.handle()` is borrowed only for this synchronous call;
    // SQLCipher copies exactly `raw.len()` bytes before returning and the allocation
    // remains alive. No other operation can access this non-Sync connection.
    let result = unsafe {
        ffi::sqlite3_key(
            connection.handle(),
            raw.expose().as_ptr().cast(),
            i32::try_from(raw.len()).expect("raw SQLCipher key has fixed small length"),
        )
    };
    if result == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(CatalogError::Sql(rusqlite::Error::SqliteFailure(
            ffi::Error::new(result),
            None,
        )))
    }
}

fn configure(connection: &Connection, mode: CatalogMode, config: CatalogConfig) -> Result<()> {
    connection.busy_timeout(config.busy_timeout)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false)?;
    connection.execute_batch("PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON; PRAGMA trusted_schema=OFF; PRAGMA cell_size_check=ON;")?;
    let cipher_version: String =
        connection.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
    let temp_store: i64 = connection.pragma_query_value(None, "temp_store", |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if cipher_version.is_empty() || temp_store != 2 || foreign_keys != 1 {
        return Err(CatalogError::IntegrityFailed);
    }
    match mode {
        CatalogMode::ReadOnly => connection.execute_batch("PRAGMA query_only=ON;")?,
        CatalogMode::ReadWrite => connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA wal_autocheckpoint=1000;")?,
    }
    Ok(())
}

fn pragma_all_ok(connection: &Connection, pragma: &str, empty_is_ok: bool) -> Result<bool> {
    let mut statement = connection.prepare(pragma)?;
    let values = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut count = 0;
    for value in values {
        if value? != "ok" {
            return Ok(false);
        }
        count += 1;
    }
    Ok(empty_is_ok || count > 0)
}

#[cfg(test)]
mod scale_tests {
    use std::{path::Path, time::Instant};

    use osv_crypto::SecretKey;
    use osv_test_support::TempVault;
    use rusqlite::params;

    use super::{Catalog, CatalogMode};

    #[test]
    fn connection_policy_and_schema_identity_fail_closed() {
        let directory = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = directory.path().join("catalog.db");
        let mut key_bytes = [0x21; 32];
        let key = SecretKey::take(&mut key_bytes).unwrap();
        let catalog = Catalog::create(&path, &key, &[0x22; 16], 1).unwrap();
        assert!(
            catalog
                .connection
                .execute("SELECT load_extension('forbidden')", [])
                .is_err()
        );
        assert_eq!(
            catalog
                .connection
                .pragma_query_value::<String, _>(None, "cipher_memory_security", |row| row.get(0))
                .unwrap(),
            "1"
        );
        catalog
            .connection
            .pragma_update(None, "user_version", 2)
            .unwrap();
        catalog.close().unwrap();
        assert!(matches!(
            Catalog::open(&path, &key, &[0x22; 16], CatalogMode::ReadOnly),
            Err(crate::CatalogError::UnknownSchema(2))
        ));

        let second_path = directory.path().join("second.db");
        let catalog = Catalog::create(&second_path, &key, &[0x22; 16], 1).unwrap();
        catalog
            .connection
            .execute(
                "UPDATE schema_migrations SET checksum=zeroblob(32) WHERE version=1",
                [],
            )
            .unwrap();
        catalog.close().unwrap();
        assert!(matches!(
            Catalog::open(&second_path, &key, &[0x22; 16], CatalogMode::ReadOnly),
            Err(crate::CatalogError::IntegrityFailed)
        ));
    }

    #[test]
    #[ignore = "explicit Phase 5 scale benchmark"]
    fn indexed_search_at_10k_100k_and_1m_rows() {
        let directory = TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = directory.path().join("catalog.db");
        let mut key_bytes = [0x31; 32];
        let key = SecretKey::take(&mut key_bytes).unwrap();
        let mut catalog = Catalog::create(&path, &key, &[0x32; 16], 1).unwrap();
        let mut previous = 0_i64;
        for target in [10_000_i64, 100_000, 1_000_000] {
            let started = Instant::now();
            let transaction = catalog.connection.transaction().unwrap();
            transaction.execute(
                "WITH RECURSIVE counter(x) AS (VALUES(?1) UNION ALL SELECT x+1 FROM counter WHERE x<?2) INSERT INTO objects(id,wrapped_dek,role,state,logical_size,format_generation,locator) SELECT unhex(printf('%032x',x)),zeroblob(72),1,1,1,1,printf('objects/%02x/%032x.osvo',x%256,x) FROM counter",
                params![previous + 1, target],
            ).unwrap();
            transaction.execute(
                "WITH RECURSIVE counter(x) AS (VALUES(?1) UNION ALL SELECT x+1 FROM counter WHERE x<?2) INSERT INTO media(id,original_object_id,original_name,media_class,mime,codecs,imported_at_ms,fingerprint) SELECT unhex(printf('%032x',x+2000000)),unhex(printf('%032x',x)),CASE WHEN x%100=0 THEN printf('needle-%d',x) ELSE printf('synthetic-%d',x) END,1,'image/png','png',x,randomblob(32) FROM counter",
                params![previous + 1, target],
            ).unwrap();
            transaction.commit().unwrap();
            let inserted = started.elapsed();
            let queried = Instant::now();
            let matches: i64 = catalog
                .connection
                .query_row(
                    "SELECT count(*) FROM media_search WHERE media_search MATCH 'needle'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let query = queried.elapsed();
            assert_eq!(matches, target / 100);
            eprintln!(
                "phase5_catalog_benchmark rows={target} insert_ms={} indexed_query_ms={}",
                inserted.as_millis(),
                query.as_millis()
            );
            previous = target;
        }
        let plan: String = catalog.connection.query_row(
            "EXPLAIN QUERY PLAN SELECT rowid FROM media_search WHERE media_search MATCH 'needle'",
            [],
            |row| row.get(3),
        ).unwrap();
        assert!(plan.contains("VIRTUAL TABLE INDEX"));
        catalog.checkpoint_for_offline_backup().unwrap();
        catalog.close().unwrap();
    }
}
