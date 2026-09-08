use std::{error::Error, fmt, io};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::secret::SecretArray;
use crate::{LockStatus, RandomError, RandomSource, SecretBytes, SecretKey};

const KEK_LEN: usize = 32;
const CREDENTIAL_ENCODING_VERSION: u8 = 1;
const CREDENTIAL_DOMAIN: &[u8] = b"osv-ng credential input";
const MAX_CREDENTIAL_PART_LEN: usize = 1024 * 1024;

/// Validated Argon2id cost parameters stored in a vault header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Lowest accepted memory cost. Primarily useful for fast known-answer tests.
    pub const MIN_MEMORY_KIB: u32 = 8;
    /// Highest accepted memory cost; parsing rejects larger values before KDF work.
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    pub const MAX_ITERATIONS: u32 = 10;
    pub const MAX_PARALLELISM: u32 = 16;

    /// Validates a complete cost tuple.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, KdfError> {
        if !(Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&memory_kib)
            || !(1..=Self::MAX_ITERATIONS).contains(&iterations)
            || !(1..=Self::MAX_PARALLELISM).contains(&parallelism)
            || memory_kib < parallelism.saturating_mul(8)
        {
            return Err(KdfError::ParametersOutOfBounds);
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Recommended interactive default for newly created vaults.
    #[must_use]
    pub const fn interactive_default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }
}

/// Password bytes owned in secure memory.
pub struct Password(SecretBytes);

impl Password {
    /// Copies password bytes into secure storage.
    pub fn new(bytes: &[u8]) -> Result<Self, KdfError> {
        if bytes.len() > MAX_CREDENTIAL_PART_LEN {
            return Err(KdfError::CredentialTooLarge);
        }
        SecretBytes::new(bytes).map(Self).map_err(KdfError::Memory)
    }

    /// Moves password bytes into secure storage and wipes the caller's buffer,
    /// including on bounds or allocation failure.
    pub fn take(bytes: &mut [u8]) -> Result<Self, KdfError> {
        let result = if bytes.len() > MAX_CREDENTIAL_PART_LEN {
            Err(KdfError::CredentialTooLarge)
        } else {
            SecretBytes::new(bytes).map(Self).map_err(KdfError::Memory)
        };
        bytes.zeroize();
        result
    }

    #[must_use]
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.0.lock_status()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Password([REDACTED])")
    }
}

/// Vault master key. It can only be constructed in secure memory.
pub struct MasterKey(pub(crate) SecretKey<32>);

impl MasterKey {
    /// Moves key bytes into secure storage and wipes the caller's buffer.
    pub fn take(bytes: &mut [u8; 32]) -> Result<Self, KdfError> {
        SecretKey::take(bytes).map(Self).map_err(KdfError::Memory)
    }

    /// Generates a master key directly into secure memory.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, KdfError> {
        let mut key = SecretKey::zeroed().map_err(KdfError::Memory)?;
        random.fill(key.expose_mut()).map_err(KdfError::Random)?;
        Ok(Self(key))
    }

    #[must_use]
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.0.lock_status()
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// Stable key-separation labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Catalog,
    ObjectWrapping,
    Internal,
}

impl Purpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Catalog => b"catalog",
            Self::ObjectWrapping => b"object-wrapping",
            Self::Internal => b"internal",
        }
    }
}

/// Purpose-separated keys derived from one vault master key.
pub struct DerivedKeys {
    pub catalog: SecretKey<32>,
    pub object_wrapping: SecretKey<32>,
    pub internal: SecretKey<32>,
}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKeys([REDACTED])")
    }
}

impl DerivedKeys {
    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.catalog
            .lock_status()
            .combine(self.object_wrapping.lock_status())
            .combine(self.internal.lock_status())
    }
}

/// A derived KEK plus the status of its transient Argon2 working allocation.
pub struct DerivedKek {
    key: SecretKey<32>,
    workspace_lock_status: LockStatus,
}

impl DerivedKek {
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.key.expose()
    }

    #[must_use]
    pub const fn lock_status(&self) -> LockStatus {
        self.key.lock_status().combine(self.workspace_lock_status)
    }
}

impl fmt::Debug for DerivedKek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKek([REDACTED])")
    }
}

/// KDF or secure-allocation failure. Messages contain no credentials or keys.
#[derive(Debug)]
pub enum KdfError {
    ParametersOutOfBounds,
    CredentialTooLarge,
    Memory(io::Error),
    Random(RandomError),
    Derivation,
}

impl fmt::Display for KdfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParametersOutOfBounds => formatter.write_str("KDF parameters are out of bounds"),
            Self::CredentialTooLarge => formatter.write_str("credential input is too large"),
            Self::Memory(_) => formatter.write_str("secure memory unavailable"),
            Self::Random(_) => formatter.write_str("cryptographic randomness unavailable"),
            Self::Derivation => formatter.write_str("key derivation failed"),
        }
    }
}

impl Error for KdfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Random(error) => Some(error),
            _ => None,
        }
    }
}

/// Derives a credential-encryption key from unambiguously encoded inputs.
pub fn derive_kek(
    password: &Password,
    keyfile: Option<&SecretBytes>,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<DerivedKek, KdfError> {
    let keyfile_bytes = keyfile.map_or(&[][..], SecretBytes::expose);
    if keyfile_bytes.len() > MAX_CREDENTIAL_PART_LEN {
        return Err(KdfError::CredentialTooLarge);
    }
    let encoded_len =
        CREDENTIAL_DOMAIN.len() + 1 + 8 + password.expose().len() + 8 + keyfile_bytes.len();
    let mut encoded = SecretBytes::zeroed(encoded_len).map_err(KdfError::Memory)?;
    let credential_lock_status = password
        .lock_status()
        .combine(keyfile.map_or(LockStatus::Locked, SecretBytes::lock_status))
        .combine(encoded.lock_status());
    let destination = encoded.expose_mut();
    let mut offset = 0;
    for part in [
        CREDENTIAL_DOMAIN,
        &[CREDENTIAL_ENCODING_VERSION],
        &u64::try_from(password.expose().len())
            .map_err(|_| KdfError::CredentialTooLarge)?
            .to_le_bytes(),
        password.expose(),
        &u64::try_from(keyfile_bytes.len())
            .map_err(|_| KdfError::CredentialTooLarge)?
            .to_le_bytes(),
        keyfile_bytes,
    ] {
        destination[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEK_LEN),
    )
    .map_err(|_| KdfError::ParametersOutOfBounds)?;
    let mut output = SecretKey::zeroed().map_err(KdfError::Memory)?;
    let block_count =
        usize::try_from(params.memory_kib).map_err(|_| KdfError::ParametersOutOfBounds)?;
    let mut memory = SecretArray::<Block>::zeroed(block_count).map_err(KdfError::Memory)?;
    let workspace_lock_status = credential_lock_status.combine(memory.lock_status());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into_with_memory(
            encoded.expose(),
            salt,
            output.expose_mut(),
            memory.expose_mut(),
        )
        .map_err(|_| KdfError::Derivation)?;
    Ok(DerivedKek {
        key: output,
        workspace_lock_status,
    })
}

/// Derives all purpose keys with stable, vault-bound HKDF info values.
pub fn derive_subkeys(master: &MasterKey, vault_id: &[u8; 16]) -> Result<DerivedKeys, KdfError> {
    Ok(DerivedKeys {
        catalog: derive_one(master, vault_id, Purpose::Catalog)?,
        object_wrapping: derive_one(master, vault_id, Purpose::ObjectWrapping)?,
        internal: derive_one(master, vault_id, Purpose::Internal)?,
    })
}

fn derive_one(
    master: &MasterKey,
    vault_id: &[u8; 16],
    purpose: Purpose,
) -> Result<SecretKey<32>, KdfError> {
    let mut output = SecretKey::zeroed().map_err(KdfError::Memory)?;
    let mut info = [0_u8; 64];
    let prefix = b"osv-ng subkey\0v1\0";
    info[..prefix.len()].copy_from_slice(prefix);
    let mut end = prefix.len();
    info[end..end + vault_id.len()].copy_from_slice(vault_id);
    end += vault_id.len();
    let label = purpose.label();
    info[end..end + label.len()].copy_from_slice(label);
    end += label.len();
    Hkdf::<Sha256>::new(None, master.expose())
        .expand(&info[..end], output.expose_mut())
        .map_err(|_| KdfError::Derivation)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn credential_encoding_and_argon2id_project_vector() {
        let password = Password::new(b"password").unwrap();
        let keyfile = SecretBytes::new(b"key-file").unwrap();
        let params = KdfParams::new(8, 1, 1).unwrap();
        let output = derive_kek(&password, Some(&keyfile), &[0x11; 16], params).unwrap();
        assert_eq!(
            hex(output.expose()),
            "2c7c552c63b0397f31b6df499196bce433a3d7d4e76785065046df70ad04111c"
        );
    }

    #[test]
    fn hkdf_purpose_separation_project_vectors() {
        let mut master_bytes = [0x22; 32];
        let master = MasterKey::take(&mut master_bytes).unwrap();
        let keys = derive_subkeys(&master, &[0x33; 16]).unwrap();
        assert_eq!(
            hex(keys.catalog.expose()),
            "a96668c086b7a3d6ff21e24efcfb4e0cf7aa4dba68f490e1a0a509052844ef27"
        );
        assert_eq!(
            hex(keys.object_wrapping.expose()),
            "d630276d3d8a4015fd9878ec4f8dadf89d0dc88402b46460df1106873ed1d173"
        );
        assert_eq!(
            hex(keys.internal.expose()),
            "d47b007ce83d54c9e3bb737e0d0de71e7922cb8483eee3da3f50366d1a517b4a"
        );
        assert_ne!(keys.catalog.expose(), keys.object_wrapping.expose());
        assert_ne!(keys.catalog.expose(), keys.internal.expose());
    }

    #[test]
    fn kek_status_includes_degraded_input_owners() {
        crate::secret::force_next_lock_failure();
        let password = Password::new(b"password").unwrap();
        assert_eq!(password.lock_status(), LockStatus::Degraded);
        let output = derive_kek(
            &password,
            None,
            &[0x11; 16],
            KdfParams::new(8, 1, 1).unwrap(),
        )
        .unwrap();
        assert_eq!(output.lock_status(), LockStatus::Degraded);
    }
}
