use osv_storage::{ObjectId, ObjectRole};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    CatalogError, Child, GalleryId, MediaClass, MediaId, NewDerivedObject, NewGallery, NewMedia,
    NewObject, ObjectState, Result, StoredObject, TagId,
    types::{
        MAX_CODEC_BYTES, MAX_DIMENSION, MAX_DURATION_MS, MAX_LOCATOR_BYTES, MAX_NAME_BYTES,
        MAX_QUERY_RESULTS, MAX_SEARCH_BYTES, MAX_SHORT_TEXT_BYTES, parse_descriptor, validate_text,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchResult {
    pub id: MediaId,
    pub class: MediaClass,
    pub favorite: bool,
}

pub struct CatalogTransaction<'connection> {
    transaction: Transaction<'connection>,
}

impl CatalogTransaction<'_> {
    pub(crate) fn begin(connection: &mut Connection) -> Result<CatalogTransaction<'_>> {
        Ok(CatalogTransaction {
            transaction: connection.transaction_with_behavior(TransactionBehavior::Immediate)?,
        })
    }

    pub fn insert_object(&self, object: NewObject<'_>) -> Result<()> {
        validate_text(object.locator, MAX_LOCATOR_BYTES, false, "object locator")?;
        if object.locator.starts_with('/')
            || object
                .locator
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(CatalogError::InvalidInput("object locator"));
        }
        let descriptor = object.descriptor;
        let logical_size = i64::try_from(descriptor.logical_len())
            .map_err(|_| CatalogError::InvalidInput("object size"))?;
        self.transaction.execute(
            "INSERT INTO objects(id,wrapped_dek,role,state,logical_size,format_generation,locator) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![descriptor.id().as_bytes().as_slice(),descriptor.wrapped_key().as_bytes().as_slice(),descriptor.role() as i64,object.state as i64,logical_size,i64::from(descriptor.format_version()),object.locator],
        )?;
        Ok(())
    }

    pub fn object(&self, id: ObjectId) -> Result<StoredObject> {
        let row = self.transaction.query_row(
            "SELECT id,role,logical_size,format_generation,wrapped_dek,locator,state FROM objects WHERE id=?1",
            [id.as_bytes().as_slice()],
            |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,String>(5)?,row.get::<_,i64>(6)?)),
        ).optional()?.ok_or(CatalogError::NotFound)?;
        Ok(StoredObject {
            descriptor: parse_descriptor(row.0, row.1, row.2, row.3, row.4)?,
            locator: row.5,
            state: ObjectState::parse(row.6)?,
        })
    }

    pub fn insert_media(&self, media: &NewMedia<'_>) -> Result<()> {
        validate_text(media.original_name, MAX_NAME_BYTES, false, "media name")?;
        validate_text(media.mime, MAX_SHORT_TEXT_BYTES, false, "media MIME type")?;
        validate_text(media.codecs, MAX_CODEC_BYTES, true, "media codecs")?;
        if media
            .width
            .is_some_and(|value| value == 0 || value > MAX_DIMENSION)
            || media
                .height
                .is_some_and(|value| value == 0 || value > MAX_DIMENSION)
            || media
                .duration_ms
                .is_some_and(|value| value > MAX_DURATION_MS)
            || media.imported_at_ms < 0
        {
            return Err(CatalogError::InvalidInput("media metadata"));
        }
        let object_role: Option<i64> = self
            .transaction
            .query_row(
                "SELECT role FROM objects WHERE id=?1",
                [media.original_object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if object_role != Some(ObjectRole::Original as i64) {
            return Err(CatalogError::InvalidInput("original object"));
        }
        let width = media.width.map(i64::from);
        let height = media.height.map(i64::from);
        let duration = media
            .duration_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| CatalogError::InvalidInput("media duration"))?;
        self.transaction.execute(
            "INSERT INTO media(id,original_object_id,original_name,media_class,mime,width,height,duration_ms,codecs,imported_at_ms,fingerprint) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![media.id.as_bytes().as_slice(),media.original_object_id.as_bytes().as_slice(),media.original_name,media.class as i64,media.mime,width,height,duration,media.codecs,media.imported_at_ms,media.fingerprint.as_slice()],
        )?;
        Ok(())
    }

    pub fn insert_derived_object(&self, derived: NewDerivedObject) -> Result<()> {
        if derived.recipe_version == 0
            || derived.width == 0
            || derived.width > MAX_DIMENSION
            || derived.height == 0
            || derived.height > MAX_DIMENSION
        {
            return Err(CatalogError::InvalidInput("derived object"));
        }
        let role: Option<i64> = self
            .transaction
            .query_row(
                "SELECT role FROM objects WHERE id=?1",
                [derived.object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if !matches!(role,Some(value) if value==ObjectRole::Thumbnail as i64 || value==ObjectRole::Poster as i64)
        {
            return Err(CatalogError::InvalidInput("derived object role"));
        }
        self.transaction.execute("INSERT INTO derived_objects(object_id,media_id,recipe_version,width,height) VALUES(?1,?2,?3,?4,?5)",params![derived.object_id.as_bytes().as_slice(),derived.media_id.as_bytes().as_slice(),i64::from(derived.recipe_version),i64::from(derived.width),i64::from(derived.height)])?;
        Ok(())
    }

    pub fn create_gallery(&self, gallery: NewGallery<'_>) -> Result<()> {
        validate_text(gallery.name, MAX_NAME_BYTES, false, "gallery name")?;
        if gallery.created_at_ms < 0 {
            return Err(CatalogError::InvalidInput("timestamp"));
        }
        self.transaction.execute(
            "INSERT INTO galleries(id,name,created_at_ms) VALUES(?1,?2,?3)",
            params![
                gallery.id.as_bytes().as_slice(),
                gallery.name,
                gallery.created_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn add_gallery_child(&self, parent: GalleryId, position: u32, child: Child) -> Result<()> {
        if position > i32::MAX as u32 {
            return Err(CatalogError::InvalidInput("gallery position"));
        }
        match child {
            Child::Media(id) => {
                self.transaction.execute("INSERT INTO gallery_children(parent_gallery_id,position,child_kind,media_id) VALUES(?1,?2,1,?3)",params![parent.as_bytes().as_slice(),i64::from(position),id.as_bytes().as_slice()])?;
            }
            Child::Gallery(id) => {
                if parent == id || self.gallery_reaches(id, parent)? {
                    return Err(CatalogError::Conflict);
                }
                self.transaction.execute("INSERT INTO gallery_children(parent_gallery_id,position,child_kind,gallery_id) VALUES(?1,?2,2,?3)",params![parent.as_bytes().as_slice(),i64::from(position),id.as_bytes().as_slice()])?;
            }
        }
        Ok(())
    }

    pub fn gallery_children(&self, parent: GalleryId, maximum: u32) -> Result<Vec<Child>> {
        if maximum == 0 || maximum > MAX_QUERY_RESULTS {
            return Err(CatalogError::InvalidInput("gallery result limit"));
        }
        let mut statement = self.transaction.prepare(
            "SELECT child_kind,media_id,gallery_id FROM gallery_children WHERE parent_gallery_id=?1 ORDER BY position LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![parent.as_bytes().as_slice(), i64::from(maximum)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (kind, media, gallery) = row?;
            match (kind, media, gallery) {
                (1, Some(id), None) => Ok(Child::Media(MediaId::parse(id)?)),
                (2, None, Some(id)) => Ok(Child::Gallery(GalleryId::parse(id)?)),
                _ => Err(CatalogError::IntegrityFailed),
            }
        })
        .collect()
    }

    fn gallery_reaches(&self, root: GalleryId, sought: GalleryId) -> Result<bool> {
        Ok(self.transaction.query_row(
            "WITH RECURSIVE descendants(id) AS (VALUES(?1) UNION SELECT child.gallery_id FROM gallery_children child JOIN descendants ON child.parent_gallery_id=descendants.id WHERE child.gallery_id IS NOT NULL) SELECT EXISTS(SELECT 1 FROM descendants WHERE id=?2)",
            params![root.as_bytes().as_slice(),sought.as_bytes().as_slice()],|row| row.get(0))?)
    }

    pub fn create_tag(&self, name: &str) -> Result<TagId> {
        validate_text(name, MAX_NAME_BYTES, false, "tag")?;
        self.transaction
            .execute("INSERT INTO tags(name) VALUES(?1)", [name])?;
        Ok(TagId(self.transaction.last_insert_rowid()))
    }

    pub fn tag_media(&self, media: MediaId, tag: TagId) -> Result<()> {
        if tag.0 <= 0 {
            return Err(CatalogError::InvalidInput("tag id"));
        }
        self.transaction.execute(
            "INSERT INTO media_tags(media_id,tag_id) VALUES(?1,?2)",
            params![media.as_bytes().as_slice(), tag.0],
        )?;
        Ok(())
    }

    pub fn set_favorite(&self, media: MediaId, favorite: bool) -> Result<()> {
        let changed = self.transaction.execute(
            "UPDATE media SET favorite=?2 WHERE id=?1",
            params![media.as_bytes().as_slice(), favorite],
        )?;
        if changed == 0 {
            return Err(CatalogError::NotFound);
        }
        Ok(())
    }

    pub fn search_media(&self, query: &str, maximum: u32) -> Result<Vec<SearchResult>> {
        validate_text(query, MAX_SEARCH_BYTES, false, "search query")?;
        if maximum == 0 || maximum > MAX_QUERY_RESULTS {
            return Err(CatalogError::InvalidInput("search result limit"));
        }
        let mut statement = self.transaction.prepare(
            "SELECT media.id,media.media_class,media.favorite FROM media_search JOIN media ON media.rowid=media_search.rowid WHERE media_search MATCH ?1 ORDER BY rank,media.id LIMIT ?2"
        )?;
        let rows = statement.query_map(params![query, i64::from(maximum)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (id, class, favorite) = row?;
            Ok(SearchResult {
                id: MediaId::parse(id)?,
                class: MediaClass::parse(class)?,
                favorite,
            })
        })
        .collect()
    }

    pub fn commit(self) -> Result<()> {
        self.transaction.commit().map_err(CatalogError::from)
    }
}
