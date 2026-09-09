use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{CatalogError, Result};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationPoint {
    AfterBegin,
    AfterSchema,
    BeforeCommit,
}

impl MigrationPoint {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AfterBegin => "migration-after-begin",
            Self::AfterSchema => "migration-after-schema",
            Self::BeforeCommit => "migration-before-commit",
        }
    }
}

pub trait MigrationFaultInjector {
    fn check(&mut self, point: MigrationPoint) -> Result<()>;
}

#[derive(Default)]
pub struct NoMigrationFault;

impl MigrationFaultInjector for NoMigrationFault {
    fn check(&mut self, _point: MigrationPoint) -> Result<()> {
        Ok(())
    }
}

const MIGRATION_1: &str = r#"
CREATE TABLE vault_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), vault_id BLOB NOT NULL UNIQUE CHECK(length(vault_id)=16),
 catalog_format INTEGER NOT NULL CHECK(catalog_format=1), created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;
CREATE TABLE schema_migrations (
 version INTEGER PRIMARY KEY CHECK(version>0), name TEXT NOT NULL UNIQUE CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
 checksum BLOB NOT NULL CHECK(length(checksum)=32), applied_at_ms INTEGER NOT NULL CHECK(applied_at_ms>=0)
) STRICT;
CREATE TABLE objects (
 id BLOB PRIMARY KEY CHECK(length(id)=16), wrapped_dek BLOB NOT NULL CHECK(length(wrapped_dek)=72),
 role INTEGER NOT NULL CHECK(role BETWEEN 1 AND 3), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3),
 logical_size INTEGER NOT NULL CHECK(logical_size BETWEEN 0 AND 17592186044416),
 format_generation INTEGER NOT NULL CHECK(format_generation BETWEEN 1 AND 65535),
 locator TEXT NOT NULL UNIQUE CHECK(length(CAST(locator AS BLOB)) BETWEEN 1 AND 128 AND instr(locator,char(0))=0 AND locator NOT LIKE '/%' AND locator NOT LIKE '%..%')
) STRICT;
CREATE INDEX objects_state_idx ON objects(state);
CREATE TABLE media (
 id BLOB PRIMARY KEY CHECK(length(id)=16), original_object_id BLOB NOT NULL UNIQUE REFERENCES objects(id) ON DELETE RESTRICT,
 original_name TEXT NOT NULL CHECK(length(CAST(original_name AS BLOB)) BETWEEN 1 AND 4096 AND instr(original_name,char(0))=0),
 media_class INTEGER NOT NULL CHECK(media_class BETWEEN 1 AND 3),
 mime TEXT NOT NULL CHECK(length(CAST(mime AS BLOB)) BETWEEN 1 AND 255 AND instr(mime,char(0))=0),
 width INTEGER CHECK(width BETWEEN 1 AND 1000000), height INTEGER CHECK(height BETWEEN 1 AND 1000000),
 duration_ms INTEGER CHECK(duration_ms BETWEEN 0 AND 315360000000),
 codecs TEXT NOT NULL CHECK(length(CAST(codecs AS BLOB))<=4096 AND instr(codecs,char(0))=0),
 imported_at_ms INTEGER NOT NULL CHECK(imported_at_ms>=0), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
 favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN(0,1))
) STRICT;
CREATE INDEX media_imported_idx ON media(imported_at_ms DESC,id);
CREATE INDEX media_favorite_idx ON media(favorite,imported_at_ms DESC) WHERE favorite=1;
CREATE INDEX media_fingerprint_idx ON media(fingerprint);
CREATE TABLE derived_objects (
 object_id BLOB PRIMARY KEY REFERENCES objects(id) ON DELETE CASCADE, media_id BLOB NOT NULL REFERENCES media(id) ON DELETE CASCADE,
 recipe_version INTEGER NOT NULL CHECK(recipe_version BETWEEN 1 AND 4294967295), width INTEGER NOT NULL CHECK(width BETWEEN 1 AND 1000000),
 height INTEGER NOT NULL CHECK(height BETWEEN 1 AND 1000000)
) STRICT;
CREATE INDEX derived_media_idx ON derived_objects(media_id);
CREATE TABLE galleries (
 id BLOB PRIMARY KEY CHECK(length(id)=16), name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 4096 AND instr(name,char(0))=0),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) STRICT;
CREATE TABLE gallery_children (
 parent_gallery_id BLOB NOT NULL REFERENCES galleries(id) ON DELETE CASCADE,
 position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 2147483647), child_kind INTEGER NOT NULL CHECK(child_kind IN(1,2)),
 media_id BLOB REFERENCES media(id) ON DELETE CASCADE, gallery_id BLOB REFERENCES galleries(id) ON DELETE CASCADE,
 PRIMARY KEY(parent_gallery_id,position),
 CHECK((child_kind=1 AND media_id IS NOT NULL AND gallery_id IS NULL) OR (child_kind=2 AND media_id IS NULL AND gallery_id IS NOT NULL)),
 UNIQUE(parent_gallery_id,media_id), UNIQUE(parent_gallery_id,gallery_id)
) STRICT;
CREATE INDEX gallery_child_gallery_idx ON gallery_children(gallery_id) WHERE gallery_id IS NOT NULL;
CREATE INDEX gallery_child_media_idx ON gallery_children(media_id) WHERE media_id IS NOT NULL;
CREATE TRIGGER gallery_cycle_insert BEFORE INSERT ON gallery_children WHEN NEW.gallery_id IS NOT NULL BEGIN
 SELECT CASE WHEN EXISTS(WITH RECURSIVE descendants(id) AS (
  VALUES(NEW.gallery_id) UNION SELECT child.gallery_id FROM gallery_children child JOIN descendants ON child.parent_gallery_id=descendants.id WHERE child.gallery_id IS NOT NULL
 ) SELECT 1 FROM descendants WHERE id=NEW.parent_gallery_id) THEN RAISE(ABORT,'gallery cycle') END;
END;
CREATE TRIGGER gallery_cycle_update BEFORE UPDATE OF parent_gallery_id,gallery_id ON gallery_children WHEN NEW.gallery_id IS NOT NULL BEGIN
 SELECT CASE WHEN EXISTS(WITH RECURSIVE descendants(id) AS (
  VALUES(NEW.gallery_id) UNION SELECT child.gallery_id FROM gallery_children child JOIN descendants ON child.parent_gallery_id=descendants.id
  WHERE child.gallery_id IS NOT NULL AND NOT(child.parent_gallery_id=OLD.parent_gallery_id AND child.position=OLD.position)
 ) SELECT 1 FROM descendants WHERE id=NEW.parent_gallery_id) THEN RAISE(ABORT,'gallery cycle') END;
END;
CREATE TABLE tags (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE BINARY UNIQUE CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 4096 AND instr(name,char(0))=0)
) STRICT;
CREATE TABLE media_tags (
 media_id BLOB NOT NULL REFERENCES media(id) ON DELETE CASCADE, tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
 PRIMARY KEY(media_id,tag_id)
) STRICT;
CREATE INDEX media_tags_tag_idx ON media_tags(tag_id,media_id);
CREATE TABLE catalog_preferences (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), sort_mode INTEGER NOT NULL DEFAULT 1 CHECK(sort_mode BETWEEN 1 AND 8)
) STRICT;
INSERT INTO catalog_preferences(singleton) VALUES(1);
CREATE TABLE saved_searches (
 id BLOB PRIMARY KEY CHECK(length(id)=16), name TEXT NOT NULL UNIQUE CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 4096 AND instr(name,char(0))=0),
 ast_version INTEGER NOT NULL CHECK(ast_version BETWEEN 1 AND 65535), ast BLOB NOT NULL CHECK(length(ast) BETWEEN 1 AND 65536)
) STRICT;
CREATE TABLE operation_journal (
 id BLOB PRIMARY KEY CHECK(length(id)=16), operation_kind INTEGER NOT NULL CHECK(operation_kind BETWEEN 1 AND 32),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 32), object_id BLOB REFERENCES objects(id) ON DELETE SET NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=65536), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0)
) STRICT;
CREATE INDEX operation_journal_state_idx ON operation_journal(state,updated_at_ms);
CREATE VIRTUAL TABLE media_search USING fts5(original_name,mime,codecs,content='media',content_rowid='rowid',tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER media_search_insert AFTER INSERT ON media BEGIN
 INSERT INTO media_search(rowid,original_name,mime,codecs) VALUES(NEW.rowid,NEW.original_name,NEW.mime,NEW.codecs);
END;
CREATE TRIGGER media_search_delete AFTER DELETE ON media BEGIN
 INSERT INTO media_search(media_search,rowid,original_name,mime,codecs) VALUES('delete',OLD.rowid,OLD.original_name,OLD.mime,OLD.codecs);
END;
CREATE TRIGGER media_search_update AFTER UPDATE OF original_name,mime,codecs ON media BEGIN
 INSERT INTO media_search(media_search,rowid,original_name,mime,codecs) VALUES('delete',OLD.rowid,OLD.original_name,OLD.mime,OLD.codecs);
 INSERT INTO media_search(rowid,original_name,mime,codecs) VALUES(NEW.rowid,NEW.original_name,NEW.mime,NEW.codecs);
END;
"#;

pub(crate) fn migrate(
    connection: &mut Connection,
    vault_id: &[u8; 16],
    created_at_ms: i64,
    faults: &mut impl MigrationFaultInjector,
) -> Result<()> {
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(CatalogError::UnknownSchema(current));
    }
    if current == SCHEMA_VERSION {
        return validate_migration_record(connection);
    }
    if current != 0 {
        return Err(CatalogError::UnknownSchema(current));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    faults.check(MigrationPoint::AfterBegin)?;
    transaction.execute_batch(MIGRATION_1)?;
    faults.check(MigrationPoint::AfterSchema)?;
    transaction.execute("INSERT INTO vault_state(singleton,vault_id,catalog_format,created_at_ms) VALUES(1,?1,1,?2)",params![vault_id.as_slice(),created_at_ms])?;
    transaction.execute("INSERT INTO schema_migrations(version,name,checksum,applied_at_ms) VALUES(1,'initial',?1,?2)",params![Sha256::digest(MIGRATION_1).as_slice(),created_at_ms])?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    faults.check(MigrationPoint::BeforeCommit)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn validate_migration_record(connection: &Connection) -> Result<()> {
    let record = connection.query_row(
        "SELECT name,checksum FROM schema_migrations WHERE version=1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    if record.0 != "initial" || record.1.as_slice() != Sha256::digest(MIGRATION_1).as_slice() {
        return Err(CatalogError::IntegrityFailed);
    }
    Ok(())
}
