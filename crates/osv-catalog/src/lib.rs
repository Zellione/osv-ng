//! Encrypted SQLCipher catalog, schema migrations, and typed repository API.
//!
//! Callers supply the purpose-separated catalog key, never a password. Values
//! accepted by this crate are bounded before SQL execution and every mutation
//! is transactional.

#[cfg(target_os = "linux")]
mod anchored_vfs;
mod connection;
mod error;
mod repository;
mod schema;
mod types;

pub use connection::{Catalog, CatalogConfig, CatalogMode, IntegrityReport};
pub use error::{CatalogError, Result};
pub use repository::{
    CatalogReader, CatalogTransaction, CleanupObject, JournalEntry, SearchResult,
};
pub use schema::{MigrationFaultInjector, MigrationPoint, NoMigrationFault, SCHEMA_VERSION};
pub use types::{
    Child, GalleryId, MediaClass, MediaId, NewDerivedObject, NewGallery, NewMedia, NewObject,
    ObjectState, StoredObject, TagId,
};
