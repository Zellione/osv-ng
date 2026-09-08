use std::fmt;

use osv_storage::{ObjectDescriptor, ObjectId, ObjectRole, WrappedObjectKey};

use crate::{CatalogError, Result};

pub(crate) const ID_LEN: usize = 16;
pub(crate) const MAX_NAME_BYTES: usize = 4_096;
pub(crate) const MAX_SHORT_TEXT_BYTES: usize = 255;
pub(crate) const MAX_CODEC_BYTES: usize = 4_096;
pub(crate) const MAX_LOCATOR_BYTES: usize = 128;
pub(crate) const MAX_SEARCH_BYTES: usize = 1_024;
pub(crate) const MAX_QUERY_RESULTS: u32 = 10_000;
pub(crate) const MAX_DIMENSION: u32 = 1_000_000;
pub(crate) const MAX_DURATION_MS: u64 = 10 * 365 * 24 * 60 * 60 * 1_000;

macro_rules! opaque_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }
            pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self> {
                Ok(Self(
                    bytes
                        .try_into()
                        .map_err(|_| CatalogError::IntegrityFailed)?,
                ))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([OPAQUE])"))
            }
        }
    };
}

opaque_id!(MediaId, "MediaId");
opaque_id!(GalleryId, "GalleryId");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum ObjectState {
    Ready = 1,
    Damaged = 2,
    PendingDeletion = 3,
}

impl ObjectState {
    pub(crate) fn parse(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Damaged),
            3 => Ok(Self::PendingDeletion),
            _ => Err(CatalogError::IntegrityFailed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum MediaClass {
    Image = 1,
    Video = 2,
    ArchiveEntry = 3,
}

impl MediaClass {
    pub(crate) fn parse(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Image),
            2 => Ok(Self::Video),
            3 => Ok(Self::ArchiveEntry),
            _ => Err(CatalogError::IntegrityFailed),
        }
    }
}

pub struct NewObject<'a> {
    pub descriptor: &'a ObjectDescriptor,
    pub locator: &'a str,
    pub state: ObjectState,
}

#[derive(Debug)]
pub struct StoredObject {
    pub descriptor: ObjectDescriptor,
    pub locator: String,
    pub state: ObjectState,
}

pub struct NewMedia<'a> {
    pub id: MediaId,
    pub original_object_id: ObjectId,
    pub original_name: &'a str,
    pub class: MediaClass,
    pub mime: &'a str,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub codecs: &'a str,
    pub imported_at_ms: i64,
    pub fingerprint: &'a [u8; 32],
}

pub struct NewDerivedObject {
    pub object_id: ObjectId,
    pub media_id: MediaId,
    pub recipe_version: u32,
    pub width: u32,
    pub height: u32,
}

pub struct NewGallery<'a> {
    pub id: GalleryId,
    pub name: &'a str,
    pub created_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Child {
    Media(MediaId),
    Gallery(GalleryId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagId(pub i64);

pub(crate) fn validate_text(
    value: &str,
    maximum: usize,
    empty_allowed: bool,
    kind: &'static str,
) -> Result<()> {
    if value.len() > maximum || value.contains('\0') || (!empty_allowed && value.is_empty()) {
        return Err(CatalogError::InvalidInput(kind));
    }
    Ok(())
}

pub(crate) fn parse_role(value: i64) -> Result<ObjectRole> {
    match value {
        1 => Ok(ObjectRole::Original),
        2 => Ok(ObjectRole::Thumbnail),
        3 => Ok(ObjectRole::Poster),
        _ => Err(CatalogError::IntegrityFailed),
    }
}

pub(crate) fn parse_descriptor(
    id: Vec<u8>,
    role: i64,
    logical_len: i64,
    format_version: i64,
    wrapped: Vec<u8>,
) -> Result<ObjectDescriptor> {
    let id = ObjectId::from_bytes(id.try_into().map_err(|_| CatalogError::IntegrityFailed)?);
    let role = parse_role(role)?;
    let logical_len = u64::try_from(logical_len).map_err(|_| CatalogError::IntegrityFailed)?;
    let format_version =
        u16::try_from(format_version).map_err(|_| CatalogError::IntegrityFailed)?;
    let wrapped = WrappedObjectKey::parse(&wrapped).map_err(|_| CatalogError::IntegrityFailed)?;
    ObjectDescriptor::from_catalog(id, role, logical_len, format_version, wrapped)
        .map_err(|_| CatalogError::IntegrityFailed)
}
