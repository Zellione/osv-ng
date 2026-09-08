//! Cryptographic primitives and secret-memory ownership for OSV vaults.
//!
//! Persistent encodings in this crate are versioned. Secret types deliberately
//! omit `Display`, redact `Debug`, and expose bytes only through explicit
//! borrowing methods.

mod header;
mod kdf;
mod process;
mod random;
mod secret;

pub use header::{
    HEADER_LEN, HeaderError, ParsedHeader, VAULT_FORMAT_VERSION, VaultHeader, VaultId,
};
pub use kdf::{
    DerivedKek, DerivedKeys, KdfError, KdfParams, MasterKey, Password, Purpose, derive_kek,
    derive_subkeys,
};
pub use process::{HardeningError, harden_process};
pub use random::{RandomError, RandomSource, SystemRandom};
pub use secret::{LockStatus, SecretBytes, SecretKey, SecretString, SecurityStatus};
