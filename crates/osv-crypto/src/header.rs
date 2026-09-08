use std::{error::Error, fmt, io};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, generic_array::GenericArray},
};

use crate::{
    KdfError, KdfParams, LockStatus, MasterKey, Password, RandomError, RandomSource, SecretBytes,
    SecretKey, derive_kek,
};

pub const HEADER_LEN: usize = 256;
pub const VAULT_FORMAT_VERSION: u16 = 1;
const MAGIC: &[u8; 8] = b"OSVVAULT";
const KDF_ENCODING_VERSION: u16 = 1;
const WRAP_SUITE_VERSION: u8 = 1;
const KEYFILE_REQUIRED: u8 = 1;
const VAULT_ID_RANGE: std::ops::Range<usize> = 16..32;
const SALT_RANGE: std::ops::Range<usize> = 44..60;
const NONCE_RANGE: std::ops::Range<usize> = 60..84;
const CIPHERTEXT_RANGE: std::ops::Range<usize> = 84..116;
const TAG_RANGE: std::ops::Range<usize> = 116..132;
const RESERVED_RANGE: std::ops::Range<usize> = 132..HEADER_LEN;
const AAD_LEN: usize = 84 + (HEADER_LEN - 132);

/// Immutable random identity of a vault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VaultId([u8; 16]);

impl VaultId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Validated, serialized plaintext vault header with an encrypted master key.
#[derive(Clone)]
pub struct VaultHeader {
    bytes: [u8; HEADER_LEN],
    vault_id: VaultId,
    kdf_params: KdfParams,
    keyfile_required: bool,
    creation_lock_status: Option<LockStatus>,
}

/// Alias emphasizing that parse and bounds validation have completed.
pub type ParsedHeader = VaultHeader;

impl VaultHeader {
    /// Creates a version-1 header using random vault identity, salt, and nonce.
    pub fn create(
        master: &MasterKey,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        random: &mut impl RandomSource,
    ) -> Result<Self, HeaderError> {
        let mut vault_id = [0_u8; 16];
        random.fill(&mut vault_id)?;
        Self::wrap(
            master,
            password,
            keyfile,
            kdf_params,
            VaultId(vault_id),
            random,
        )
    }

    /// Rewraps an unchanged master key under new credentials and fresh KDF salt.
    pub fn rewrap(
        &self,
        master: &MasterKey,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        random: &mut impl RandomSource,
    ) -> Result<Self, HeaderError> {
        Self::wrap(master, password, keyfile, kdf_params, self.vault_id, random)
    }

    fn wrap(
        master: &MasterKey,
        password: &Password,
        keyfile: Option<&SecretBytes>,
        kdf_params: KdfParams,
        vault_id: VaultId,
        random: &mut impl RandomSource,
    ) -> Result<Self, HeaderError> {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VAULT_FORMAT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&KDF_ENCODING_VERSION.to_le_bytes());
        bytes[14] = WRAP_SUITE_VERSION;
        bytes[15] = u8::from(keyfile.is_some()) * KEYFILE_REQUIRED;
        bytes[VAULT_ID_RANGE].copy_from_slice(vault_id.as_bytes());
        bytes[32..36].copy_from_slice(&kdf_params.memory_kib().to_le_bytes());
        bytes[36..40].copy_from_slice(&kdf_params.iterations().to_le_bytes());
        bytes[40..44].copy_from_slice(&kdf_params.parallelism().to_le_bytes());
        random.fill(&mut bytes[SALT_RANGE])?;
        random.fill(&mut bytes[NONCE_RANGE])?;
        let salt: &[u8; 16] = bytes[SALT_RANGE].try_into().expect("fixed salt");
        let kek = derive_kek(password, keyfile, salt, kdf_params)?;
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(kek.expose()));
        let mut protected = SecretBytes::new(master.expose()).map_err(HeaderError::Memory)?;
        let lock_status = kek.lock_status().combine(protected.lock_status());
        let aad = associated_data(&bytes);
        let nonce = XNonce::from_slice(&bytes[NONCE_RANGE]);
        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, protected.expose_mut())
            .map_err(|_| HeaderError::Cryptography)?;
        bytes[CIPHERTEXT_RANGE].copy_from_slice(protected.expose());
        bytes[TAG_RANGE].copy_from_slice(&tag);
        Ok(Self {
            bytes,
            vault_id,
            kdf_params,
            keyfile_required: keyfile.is_some(),
            creation_lock_status: Some(lock_status),
        })
    }

    /// Parses and bounds-checks a complete fixed-size header without running Argon2.
    pub fn parse(input: &[u8]) -> Result<Self, HeaderError> {
        if input.len() != HEADER_LEN {
            return Err(HeaderError::InvalidLength);
        }
        if &input[..8] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }
        if u16::from_le_bytes(input[8..10].try_into().expect("fixed field")) != VAULT_FORMAT_VERSION
        {
            return Err(HeaderError::UnknownVersion);
        }
        if usize::from(u16::from_le_bytes(
            input[10..12].try_into().expect("fixed field"),
        )) != HEADER_LEN
        {
            return Err(HeaderError::InvalidLength);
        }
        if u16::from_le_bytes(input[12..14].try_into().expect("fixed field"))
            != KDF_ENCODING_VERSION
            || input[14] != WRAP_SUITE_VERSION
        {
            return Err(HeaderError::UnknownVersion);
        }
        if input[15] & !KEYFILE_REQUIRED != 0 || input[RESERVED_RANGE].iter().any(|byte| *byte != 0)
        {
            return Err(HeaderError::UnknownMandatoryFeature);
        }
        let kdf_params = KdfParams::new(
            u32::from_le_bytes(input[32..36].try_into().expect("fixed field")),
            u32::from_le_bytes(input[36..40].try_into().expect("fixed field")),
            u32::from_le_bytes(input[40..44].try_into().expect("fixed field")),
        )?;
        let mut bytes = [0_u8; HEADER_LEN];
        bytes.copy_from_slice(input);
        let vault_id = VaultId(input[VAULT_ID_RANGE].try_into().expect("fixed vault id"));
        Ok(Self {
            bytes,
            vault_id,
            kdf_params,
            keyfile_required: input[15] == KEYFILE_REQUIRED,
            creation_lock_status: None,
        })
    }

    /// Authenticates credentials and returns the key plus aggregate lock status.
    pub fn unlock_with_status(
        &self,
        password: &Password,
        keyfile: Option<&SecretBytes>,
    ) -> Result<(MasterKey, LockStatus), HeaderError> {
        if self.keyfile_required != keyfile.is_some() {
            return Err(HeaderError::Authentication);
        }
        let salt: &[u8; 16] = self.bytes[SALT_RANGE].try_into().expect("fixed salt");
        let kek = derive_kek(password, keyfile, salt, self.kdf_params)?;
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(kek.expose()));
        let mut ciphertext: [u8; 32] = self.bytes[CIPHERTEXT_RANGE]
            .try_into()
            .expect("fixed ciphertext");
        let mut protected = SecretKey::take(&mut ciphertext).map_err(HeaderError::Memory)?;
        let lock_status = kek.lock_status().combine(protected.lock_status());
        let nonce = XNonce::from_slice(&self.bytes[NONCE_RANGE]);
        let tag = GenericArray::from_slice(&self.bytes[TAG_RANGE]);
        cipher
            .decrypt_in_place_detached(
                nonce,
                &associated_data(&self.bytes),
                protected.expose_mut(),
                tag,
            )
            .map_err(|_| HeaderError::Authentication)?;
        Ok((MasterKey(protected), lock_status))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }
    #[must_use]
    pub const fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }
    #[must_use]
    pub const fn keyfile_required(&self) -> bool {
        self.keyfile_required
    }
    /// Secure-memory result from creation, if this in-memory value created the header.
    #[must_use]
    pub const fn creation_lock_status(&self) -> Option<LockStatus> {
        self.creation_lock_status
    }
}

impl fmt::Debug for VaultHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHeader")
            .field("vault_id", &self.vault_id)
            .field("kdf_params", &self.kdf_params)
            .field("keyfile_required", &self.keyfile_required)
            .finish_non_exhaustive()
    }
}

fn associated_data(header: &[u8; HEADER_LEN]) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    aad[..84].copy_from_slice(&header[..84]);
    aad[84..].copy_from_slice(&header[RESERVED_RANGE]);
    aad
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidLength,
    InvalidMagic,
    UnknownVersion,
    UnknownMandatoryFeature,
    Authentication,
    Cryptography,
    Random(RandomError),
    Kdf(KdfError),
    Memory(io::Error),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLength => "invalid vault header length",
            Self::InvalidMagic => "invalid vault header magic",
            Self::UnknownVersion => "unsupported vault header version",
            Self::UnknownMandatoryFeature => "unsupported mandatory vault feature",
            Self::Authentication => "credentials are incorrect or the header was modified",
            Self::Cryptography => "vault header encryption failed",
            Self::Random(_) => "cryptographic randomness unavailable",
            Self::Kdf(_) => "vault key derivation failed",
            Self::Memory(_) => "secure memory unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for HeaderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Random(error) => Some(error),
            Self::Kdf(error) => Some(error),
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RandomError> for HeaderError {
    fn from(error: RandomError) -> Self {
        Self::Random(error)
    }
}
impl From<KdfError> for HeaderError {
    fn from(error: KdfError) -> Self {
        Self::Kdf(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct CountingRandom(u8);
    impl RandomSource for CountingRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn params() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    #[test]
    fn header_round_trip_and_tamper_rejection() {
        let mut master_bytes = [0x42; 32];
        let master = MasterKey::take(&mut master_bytes).unwrap();
        let password = Password::new(b"correct horse").unwrap();
        let mut random = CountingRandom(0);
        let header = VaultHeader::create(&master, &password, None, params(), &mut random).unwrap();
        let parsed = VaultHeader::parse(header.as_bytes()).unwrap();
        assert_eq!(
            parsed
                .unlock_with_status(&password, None)
                .unwrap()
                .0
                .expose(),
            master.expose()
        );
        for index in [0, 8, 12, 14, 15, 20, 32, 44, 60, 84, 116, 132, 255] {
            let mut tampered = *header.as_bytes();
            tampered[index] ^= 1;
            let rejected = VaultHeader::parse(&tampered)
                .and_then(|candidate| candidate.unlock_with_status(&password, None).map(|_| ()));
            assert!(
                rejected.is_err(),
                "tamper at public offset {index} was accepted"
            );
        }
    }

    #[test]
    fn wrong_credentials_and_keyfile_requirement_fail() {
        let mut master_bytes = [3; 32];
        let master = MasterKey::take(&mut master_bytes).unwrap();
        let password = Password::new(b"right").unwrap();
        let keyfile = SecretBytes::new(b"second factor").unwrap();
        let mut random = CountingRandom(9);
        let header =
            VaultHeader::create(&master, &password, Some(&keyfile), params(), &mut random).unwrap();
        assert!(matches!(
            header.unlock_with_status(&Password::new(b"wrong").unwrap(), Some(&keyfile)),
            Err(HeaderError::Authentication)
        ));
        assert!(matches!(
            header.unlock_with_status(&password, None),
            Err(HeaderError::Authentication)
        ));
    }

    #[test]
    fn parser_rejects_lengths_versions_features_and_cost_before_kdf() {
        let mut master_bytes = [3; 32];
        let master = MasterKey::take(&mut master_bytes).unwrap();
        let password = Password::new(b"right").unwrap();
        let mut random = CountingRandom(9);
        let header = VaultHeader::create(&master, &password, None, params(), &mut random).unwrap();
        assert!(matches!(
            VaultHeader::parse(&header.as_bytes()[..255]),
            Err(HeaderError::InvalidLength)
        ));
        for (offset, value) in [(8, 2_u8), (12, 2), (14, 2), (15, 0x80), (132, 1)] {
            let mut bytes = *header.as_bytes();
            bytes[offset] = value;
            assert!(VaultHeader::parse(&bytes).is_err());
        }
        let mut bytes = *header.as_bytes();
        bytes[32..36].copy_from_slice(&(KdfParams::MAX_MEMORY_KIB + 1).to_le_bytes());
        assert!(matches!(
            VaultHeader::parse(&bytes),
            Err(HeaderError::Kdf(KdfError::ParametersOutOfBounds))
        ));
    }

    #[test]
    fn complete_header_project_vector_digest() {
        let mut master_bytes = [0x42; 32];
        let master = MasterKey::take(&mut master_bytes).unwrap();
        let password = Password::new(b"correct horse").unwrap();
        let mut random = CountingRandom(0);
        let header = VaultHeader::create(&master, &password, None, params(), &mut random).unwrap();
        let digest = Sha256::digest(header.as_bytes());
        let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            actual,
            "4fb49a33786a2e4947450bb139208ef648f38586906b66c04595241a7fd49a30"
        );
    }
}
