//! Version-one independently encrypted, seekable object format.

use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use osv_crypto::{
    LockStatus, RandomError, RandomSource, SecretBytes, SecretKey, SecurityStatus, VaultId,
};
use sha2::{Digest, Sha256};

use crate::platform;

pub const OBJECT_FORMAT_VERSION: u16 = 1;
pub const OBJECT_HEADER_LEN: usize = 128;
const PREAMBLE_LEN: usize = 48;
const ENCRYPTED_HEADER_LEN: usize = 64;
const TAG_LEN: usize = 16;
const SUITE_VERSION: u8 = 1;
const MAGIC: &[u8; 8] = b"OSVOBJ\0\0";
const HEADER_DOMAIN: &[u8] = b"osv-ng object header\0v1\0";
const CHUNK_DOMAIN: &[u8] = b"osv-ng object chunk\0v1\0";
const WRAP_DOMAIN: &[u8] = b"osv-ng object DEK wrap\0v1\0";
const NONCE_PREFIX_LEN: usize = 15;
const OBJECT_ID_LEN: usize = 16;
const DEK_LEN: usize = 32;
const WRAPPED_KEY_LEN: usize = 24 + DEK_LEN + TAG_LEN;

pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 8 * 1024 * 1024;
pub const MAX_LOGICAL_LEN: u64 = 16 * 1024 * 1024 * 1024 * 1024;

/// Random catalog identity used as the only filename stem.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObjectId([u8; OBJECT_ID_LEN]);

impl ObjectId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; OBJECT_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectId([OPAQUE])")
    }
}

/// Authenticated namespace role; role substitution always fails authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectRole {
    Original = 1,
    Thumbnail = 2,
    Poster = 3,
}

impl ObjectRole {
    fn from_byte(value: u8) -> Result<Self, ObjectError> {
        match value {
            1 => Ok(Self::Original),
            2 => Ok(Self::Thumbnail),
            3 => Ok(Self::Poster),
            _ => Err(ObjectError::InvalidHeader),
        }
    }

    fn namespace(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Original => ("objects", None),
            Self::Thumbnail => ("derived", Some("thumbnails")),
            Self::Poster => ("derived", Some("posters")),
        }
    }
}

/// Plain fixed framing. It is validated without allocation or cryptographic work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectPreamble {
    bytes: [u8; PREAMBLE_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl ObjectPreamble {
    pub fn parse(input: &[u8]) -> Result<Self, ObjectError> {
        if input.len() != PREAMBLE_LEN {
            return Err(ObjectError::InvalidLength);
        }
        if &input[..8] != MAGIC {
            return Err(ObjectError::InvalidMagic);
        }
        if read_u16(input, 8) != OBJECT_FORMAT_VERSION || input[12] != SUITE_VERSION {
            return Err(ObjectError::UnknownVersion);
        }
        if usize::from(read_u16(input, 10)) != PREAMBLE_LEN
            || usize::from(read_u16(input, 14)) != ENCRYPTED_HEADER_LEN + TAG_LEN
        {
            return Err(ObjectError::InvalidLength);
        }
        if input[13] != 0 || input[31..].iter().any(|byte| *byte != 0) {
            return Err(ObjectError::UnknownMandatoryFeature);
        }
        let mut bytes = [0_u8; PREAMBLE_LEN];
        bytes.copy_from_slice(input);
        let nonce_prefix = input[16..31].try_into().expect("fixed nonce prefix");
        Ok(Self {
            bytes,
            nonce_prefix,
        })
    }

    fn create(random: &mut impl RandomSource) -> Result<Self, ObjectError> {
        let mut bytes = [0_u8; PREAMBLE_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&OBJECT_FORMAT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(PREAMBLE_LEN as u16).to_le_bytes());
        bytes[12] = SUITE_VERSION;
        bytes[14..16].copy_from_slice(&((ENCRYPTED_HEADER_LEN + TAG_LEN) as u16).to_le_bytes());
        random.fill(&mut bytes[16..31])?;
        Self::parse(&bytes)
    }
}

/// Catalog-safe wrapped DEK encoding: random nonce, ciphertext, and tag.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedObjectKey([u8; WRAPPED_KEY_LEN]);

impl WrappedObjectKey {
    pub fn parse(input: &[u8]) -> Result<Self, ObjectError> {
        let bytes = input.try_into().map_err(|_| ObjectError::InvalidLength)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WRAPPED_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for WrappedObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WrappedObjectKey([REDACTED])")
    }
}

/// Data that Phase 5 stores transactionally in the encrypted catalog.
pub struct ObjectDescriptor {
    id: ObjectId,
    role: ObjectRole,
    logical_len: u64,
    format_version: u16,
    wrapped_key: WrappedObjectKey,
    publication_security_status: Option<SecurityStatus>,
}

impl ObjectDescriptor {
    #[must_use]
    pub const fn id(&self) -> ObjectId {
        self.id
    }
    #[must_use]
    pub const fn role(&self) -> ObjectRole {
        self.role
    }
    #[must_use]
    pub const fn logical_len(&self) -> u64 {
        self.logical_len
    }
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }
    #[must_use]
    pub const fn wrapped_key(&self) -> &WrappedObjectKey {
        &self.wrapped_key
    }

    /// Page-lock status for publication-owned key and plaintext buffers.
    /// Catalog-loaded descriptors return `None` because an earlier process's
    /// transient allocations cannot be observed retroactively.
    #[must_use]
    pub const fn publication_security_status(&self) -> Option<SecurityStatus> {
        self.publication_security_status
    }

    /// Reconstructs a catalog-loaded descriptor after applying public bounds.
    pub fn from_catalog(
        id: ObjectId,
        role: ObjectRole,
        logical_len: u64,
        format_version: u16,
        wrapped_key: WrappedObjectKey,
    ) -> Result<Self, ObjectError> {
        if logical_len > MAX_LOGICAL_LEN {
            return Err(ObjectError::LimitExceeded);
        }
        if format_version != OBJECT_FORMAT_VERSION {
            return Err(ObjectError::UnknownVersion);
        }
        Ok(Self {
            id,
            role,
            logical_len,
            format_version,
            wrapped_key,
            publication_security_status: None,
        })
    }
}

impl fmt::Debug for ObjectDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectDescriptor")
            .field("id", &self.id)
            .field("metadata", &"[REDACTED]")
            .finish()
    }
}

struct ObjectDek(SecretKey<DEK_LEN>);

impl ObjectDek {
    fn generate(random: &mut impl RandomSource) -> Result<Self, ObjectError> {
        let mut key = SecretKey::zeroed().map_err(ObjectError::Memory)?;
        random.fill(key.expose_mut())?;
        Ok(Self(key))
    }
}

#[derive(Clone, Copy, Debug)]
struct AuthenticatedHeader {
    logical_len: u64,
    chunk_size: u32,
    chunk_count: u32,
    header_identity: [u8; 32],
    preamble: ObjectPreamble,
    lock_status: LockStatus,
}

/// Random-access reader that releases plaintext only from authenticated chunks.
pub struct ObjectReader<R: Read + Seek> {
    source: R,
    dek: ObjectDek,
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
    header: AuthenticatedHeader,
    position: u64,
    cached_index: Option<u32>,
    cache: SecretBytes,
    aggregate_lock_status: LockStatus,
}

impl<R: Read + Seek> fmt::Debug for ObjectReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectReader")
            .field("context", &"[REDACTED]")
            .finish()
    }
}

impl<R: Read + Seek> ObjectReader<R> {
    fn open(
        mut source: R,
        dek: ObjectDek,
        vault_id: VaultId,
        object_id: ObjectId,
        role: ObjectRole,
    ) -> Result<Self, ObjectError> {
        source.seek(SeekFrom::Start(0))?;
        let header = read_authenticated_header(&mut source, &dek, vault_id, object_id, role)?;
        let expected_len = physical_len(header.logical_len, header.chunk_size, header.chunk_count)?;
        if source.seek(SeekFrom::End(0))? != expected_len {
            return Err(ObjectError::InvalidLength);
        }
        source.seek(SeekFrom::Start(OBJECT_HEADER_LEN as u64))?;
        let cache = SecretBytes::zeroed(0).map_err(ObjectError::Memory)?;
        let aggregate_lock_status = dek
            .0
            .lock_status()
            .combine(header.lock_status)
            .combine(cache.lock_status());
        Ok(Self {
            source,
            dek,
            vault_id,
            object_id,
            role,
            header,
            position: 0,
            cached_index: None,
            cache,
            aggregate_lock_status,
        })
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.header.logical_len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.header.logical_len == 0
    }

    /// Conservative status of every reader-owned key/plaintext allocation so far.
    #[must_use]
    pub const fn security_status(&self) -> SecurityStatus {
        SecurityStatus::new(self.aggregate_lock_status)
    }

    /// Authenticates every chunk without returning its plaintext.
    pub fn verify_all(&mut self) -> Result<(), ObjectError> {
        for index in 0..self.header.chunk_count {
            self.load_chunk(index)?;
        }
        self.cached_index = None;
        let cache = SecretBytes::zeroed(0).map_err(ObjectError::Memory)?;
        self.aggregate_lock_status = self.aggregate_lock_status.combine(cache.lock_status());
        self.cache = cache;
        Ok(())
    }

    fn load_chunk(&mut self, index: u32) -> Result<(), ObjectError> {
        if self.cached_index == Some(index) {
            return Ok(());
        }
        if index >= self.header.chunk_count {
            return Err(ObjectError::InvalidSeek);
        }
        self.cached_index = None;
        let empty_cache = SecretBytes::zeroed(0).map_err(ObjectError::Memory)?;
        self.aggregate_lock_status = self
            .aggregate_lock_status
            .combine(empty_cache.lock_status());
        self.cache = empty_cache;
        let plaintext_len =
            chunk_plaintext_len(self.header.logical_len, self.header.chunk_size, index)?;
        let offset = chunk_offset(self.header.chunk_size, index)?;
        self.source.seek(SeekFrom::Start(offset))?;
        let mut plaintext = SecretBytes::zeroed(plaintext_len).map_err(ObjectError::Memory)?;
        self.aggregate_lock_status = self.aggregate_lock_status.combine(plaintext.lock_status());
        self.source.read_exact(plaintext.expose_mut())?;
        let mut tag = [0_u8; TAG_LEN];
        self.source.read_exact(&mut tag)?;
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(self.dek.0.expose()));
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&object_nonce(
                    &self.header.preamble.nonce_prefix,
                    1,
                    index.into(),
                )),
                &chunk_aad(
                    self.vault_id,
                    self.object_id,
                    self.role,
                    index,
                    self.header.chunk_count,
                    u32::try_from(plaintext_len).map_err(|_| ObjectError::LimitExceeded)?,
                    &self.header.header_identity,
                ),
                plaintext.expose_mut(),
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| ObjectError::Authentication)?;
        self.cache = plaintext;
        self.cached_index = Some(index);
        Ok(())
    }
}

impl<R: Read + Seek> Read for ObjectReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.header.logical_len {
            return Ok(0);
        }
        let index = u32::try_from(self.position / u64::from(self.header.chunk_size))
            .map_err(io::Error::other)?;
        self.load_chunk(index).map_err(io::Error::other)?;
        let within = usize::try_from(self.position % u64::from(self.header.chunk_size))
            .map_err(io::Error::other)?;
        let available = &self.cache.expose()[within..];
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.position = self
            .position
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other(ObjectError::LimitExceeded))?;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for ObjectReader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(value) => i128::from(self.header.logical_len) + i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
        };
        if !(0..=i128::from(self.header.logical_len)).contains(&target) {
            return Err(io::Error::other(ObjectError::InvalidSeek));
        }
        self.position = u64::try_from(target).map_err(io::Error::other)?;
        Ok(self.position)
    }
}

/// Stable durable-publication boundaries for fault and crash testing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishPoint {
    StagingCreated,
    CiphertextWritten,
    CiphertextDurable,
    CiphertextVerified,
    FinalRenamed,
    FinalDirectoryDurable,
    StagingDirectoryDurable,
}

impl PublishPoint {
    /// Stable public name used by crash-test supervisors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StagingCreated => "staging-created",
            Self::CiphertextWritten => "ciphertext-written",
            Self::CiphertextDurable => "ciphertext-durable",
            Self::CiphertextVerified => "ciphertext-verified",
            Self::FinalRenamed => "final-renamed",
            Self::FinalDirectoryDurable => "final-directory-durable",
            Self::StagingDirectoryDurable => "staging-directory-durable",
        }
    }
}

pub const PUBLISH_POINTS: [PublishPoint; 7] = [
    PublishPoint::StagingCreated,
    PublishPoint::CiphertextWritten,
    PublishPoint::CiphertextDurable,
    PublishPoint::CiphertextVerified,
    PublishPoint::FinalRenamed,
    PublishPoint::FinalDirectoryDurable,
    PublishPoint::StagingDirectoryDurable,
];

pub trait PublishFaultInjector {
    fn should_fail(&mut self, point: PublishPoint) -> bool;
}

pub(crate) struct NoPublishFaults;
impl PublishFaultInjector for NoPublishFaults {
    fn should_fail(&mut self, _point: PublishPoint) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_object(
    vault_directory: &File,
    vault_id: VaultId,
    wrapping_key: &SecretKey<32>,
    source: &mut impl Read,
    logical_len: u64,
    role: ObjectRole,
    chunk_size: u32,
    random: &mut impl RandomSource,
    faults: &mut impl PublishFaultInjector,
) -> Result<ObjectDescriptor, ObjectError> {
    let chunk_count = validate_plan(logical_len, chunk_size)?;
    let mut id = [0_u8; OBJECT_ID_LEN];
    random.fill(&mut id)?;
    let id = ObjectId(id);
    let dek = ObjectDek::generate(random)?;
    let (wrapped_key, wrapping_lock_status) =
        wrap_dek(&dek, wrapping_key, vault_id, id, role, random)?;
    let preamble = ObjectPreamble::create(random)?;

    let staging = ensure_directory(vault_directory, "staging")?;
    let staging_name = filename(id, ".osvo.part");
    let mut file = platform::open_dynamic_at(&staging, &staging_name, true, true)?;
    fail(faults, PublishPoint::StagingCreated)?;
    let encryption_lock_status = encrypt_stream(
        source,
        &mut file,
        &dek,
        vault_id,
        id,
        role,
        logical_len,
        chunk_size,
        chunk_count,
        preamble,
    )?;
    fail(faults, PublishPoint::CiphertextWritten)?;
    file.sync_all()?;
    fail(faults, PublishPoint::CiphertextDurable)?;
    // Verify the exact inode created by this operation. The staging pathname is
    // untrusted and may be replaced while the writer descriptor remains open.
    let verification_file = file.try_clone()?;
    let verification_dek = unwrap_dek(&wrapped_key, wrapping_key, vault_id, id, role)?;
    let mut verifier = ObjectReader::open(verification_file, verification_dek, vault_id, id, role)?;
    verifier.verify_all()?;
    let verification_lock_status = verifier.security_status().page_locks();
    fail(faults, PublishPoint::CiphertextVerified)?;

    let namespace = role_directory_create(vault_directory, role)?;
    let shard_name = shard(id);
    let shard = ensure_directory(&namespace, &shard_name)?;
    namespace.sync_all()?;
    let final_name = filename(id, ".osvo");
    platform::rename_between(&staging, &staging_name, &shard, &final_name)?;
    fail(faults, PublishPoint::FinalRenamed)?;
    shard.sync_all()?;
    fail(faults, PublishPoint::FinalDirectoryDurable)?;
    staging.sync_all()?;
    fail(faults, PublishPoint::StagingDirectoryDurable)?;

    // Prove that the expected final path reaches the inode that was written and
    // authenticated. A substituted staging entry or detached/replaced shard
    // must never yield a catalog descriptor.
    let reachable_namespace = role_directory_open(vault_directory, role)?;
    let reachable_shard = platform::open_dynamic_directory_at(&reachable_namespace, &shard_name)?;
    if !platform::same_file(&shard, &reachable_shard)? {
        return Err(ObjectError::PublishedIdentityChanged);
    }
    let published = platform::open_dynamic_at(&reachable_shard, &final_name, false, false)?;
    if !platform::same_file(&file, &published)? {
        return Err(ObjectError::PublishedIdentityChanged);
    }
    let mut descriptor =
        ObjectDescriptor::from_catalog(id, role, logical_len, OBJECT_FORMAT_VERSION, wrapped_key)?;
    descriptor.publication_security_status = Some(SecurityStatus::new(
        wrapping_lock_status
            .combine(encryption_lock_status)
            .combine(verification_lock_status),
    ));
    Ok(descriptor)
}

pub(crate) fn open_object(
    vault_directory: &File,
    vault_id: VaultId,
    wrapping_key: &SecretKey<32>,
    descriptor: &ObjectDescriptor,
) -> Result<ObjectReader<File>, ObjectError> {
    let namespace = role_directory_open(vault_directory, descriptor.role)?;
    let shard = platform::open_dynamic_directory_at(&namespace, &shard(descriptor.id))?;
    let file = platform::open_dynamic_at(&shard, &filename(descriptor.id, ".osvo"), false, false)?;
    let dek = unwrap_dek(
        &descriptor.wrapped_key,
        wrapping_key,
        vault_id,
        descriptor.id,
        descriptor.role,
    )?;
    let mut reader = ObjectReader::open(file, dek, vault_id, descriptor.id, descriptor.role)?;
    reader.aggregate_lock_status = reader
        .aggregate_lock_status
        .combine(wrapping_key.lock_status());
    if reader.len() != descriptor.logical_len {
        return Err(ObjectError::Authentication);
    }
    Ok(reader)
}

#[allow(clippy::too_many_arguments)]
fn encrypt_stream(
    source: &mut impl Read,
    destination: &mut (impl Write + Seek),
    dek: &ObjectDek,
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
    logical_len: u64,
    chunk_size: u32,
    chunk_count: u32,
    preamble: ObjectPreamble,
) -> Result<LockStatus, ObjectError> {
    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&preamble.bytes)?;
    let mut header_plaintext =
        SecretBytes::zeroed(ENCRYPTED_HEADER_LEN).map_err(ObjectError::Memory)?;
    let mut lock_status = dek.0.lock_status().combine(header_plaintext.lock_status());
    header_plaintext.expose_mut()[..16].copy_from_slice(object_id.as_bytes());
    header_plaintext.expose_mut()[16] = role as u8;
    header_plaintext.expose_mut()[24..32].copy_from_slice(&logical_len.to_le_bytes());
    header_plaintext.expose_mut()[32..36].copy_from_slice(&chunk_size.to_le_bytes());
    header_plaintext.expose_mut()[36..40].copy_from_slice(&chunk_count.to_le_bytes());
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(dek.0.expose()));
    let header_tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&object_nonce(&preamble.nonce_prefix, 0, 0)),
            &header_aad(vault_id, object_id, role, &preamble.bytes),
            header_plaintext.expose_mut(),
        )
        .map_err(|_| ObjectError::Cryptography)?;
    destination.write_all(header_plaintext.expose())?;
    destination.write_all(&header_tag)?;
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(preamble.bytes);
    identity_hasher.update(header_plaintext.expose());
    identity_hasher.update(header_tag);
    let header_identity: [u8; 32] = identity_hasher.finalize().into();

    for index in 0..chunk_count {
        let plaintext_len = chunk_plaintext_len(logical_len, chunk_size, index)?;
        let mut plaintext = SecretBytes::zeroed(plaintext_len).map_err(ObjectError::Memory)?;
        lock_status = lock_status.combine(plaintext.lock_status());
        source.read_exact(plaintext.expose_mut())?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&object_nonce(&preamble.nonce_prefix, 1, index.into())),
                &chunk_aad(
                    vault_id,
                    object_id,
                    role,
                    index,
                    chunk_count,
                    u32::try_from(plaintext_len).map_err(|_| ObjectError::LimitExceeded)?,
                    &header_identity,
                ),
                plaintext.expose_mut(),
            )
            .map_err(|_| ObjectError::Cryptography)?;
        destination.write_all(plaintext.expose())?;
        destination.write_all(&tag)?;
    }
    let mut extra = SecretBytes::zeroed(1).map_err(ObjectError::Memory)?;
    lock_status = lock_status.combine(extra.lock_status());
    if source.read(extra.expose_mut())? != 0 {
        return Err(ObjectError::SourceLengthMismatch);
    }
    Ok(lock_status)
}

fn read_authenticated_header(
    source: &mut (impl Read + Seek),
    dek: &ObjectDek,
    vault_id: VaultId,
    expected_id: ObjectId,
    expected_role: ObjectRole,
) -> Result<AuthenticatedHeader, ObjectError> {
    let mut preamble_bytes = [0_u8; PREAMBLE_LEN];
    source.read_exact(&mut preamble_bytes)?;
    let preamble = ObjectPreamble::parse(&preamble_bytes)?;
    let mut plaintext = SecretBytes::zeroed(ENCRYPTED_HEADER_LEN).map_err(ObjectError::Memory)?;
    let lock_status = plaintext.lock_status();
    source.read_exact(plaintext.expose_mut())?;
    let mut tag = [0_u8; TAG_LEN];
    source.read_exact(&mut tag)?;
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(preamble.bytes);
    identity_hasher.update(plaintext.expose());
    identity_hasher.update(tag);
    let header_identity = identity_hasher.finalize().into();
    XChaCha20Poly1305::new(GenericArray::from_slice(dek.0.expose()))
        .decrypt_in_place_detached(
            XNonce::from_slice(&object_nonce(&preamble.nonce_prefix, 0, 0)),
            &header_aad(vault_id, expected_id, expected_role, &preamble.bytes),
            plaintext.expose_mut(),
            GenericArray::from_slice(&tag),
        )
        .map_err(|_| ObjectError::Authentication)?;
    if plaintext.expose()[..16] != expected_id.0
        || ObjectRole::from_byte(plaintext.expose()[16])? != expected_role
        || plaintext.expose()[17..24].iter().any(|byte| *byte != 0)
        || plaintext.expose()[40..].iter().any(|byte| *byte != 0)
    {
        return Err(ObjectError::Authentication);
    }
    let logical_len = read_u64(plaintext.expose(), 24);
    let chunk_size = read_u32(plaintext.expose(), 32);
    let chunk_count = read_u32(plaintext.expose(), 36);
    if validate_plan(logical_len, chunk_size)? != chunk_count {
        return Err(ObjectError::InvalidHeader);
    }
    Ok(AuthenticatedHeader {
        logical_len,
        chunk_size,
        chunk_count,
        header_identity,
        preamble,
        lock_status,
    })
}

fn wrap_dek(
    dek: &ObjectDek,
    wrapping_key: &SecretKey<32>,
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
    random: &mut impl RandomSource,
) -> Result<(WrappedObjectKey, LockStatus), ObjectError> {
    let mut bytes = [0_u8; WRAPPED_KEY_LEN];
    random.fill(&mut bytes[..24])?;
    let mut protected = SecretBytes::new(dek.0.expose()).map_err(ObjectError::Memory)?;
    let tag = XChaCha20Poly1305::new(GenericArray::from_slice(wrapping_key.expose()))
        .encrypt_in_place_detached(
            XNonce::from_slice(&bytes[..24]),
            &wrap_aad(vault_id, object_id, role),
            protected.expose_mut(),
        )
        .map_err(|_| ObjectError::Cryptography)?;
    bytes[24..56].copy_from_slice(protected.expose());
    bytes[56..].copy_from_slice(&tag);
    Ok((
        WrappedObjectKey(bytes),
        dek.0
            .lock_status()
            .combine(wrapping_key.lock_status())
            .combine(protected.lock_status()),
    ))
}

fn unwrap_dek(
    wrapped: &WrappedObjectKey,
    wrapping_key: &SecretKey<32>,
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
) -> Result<ObjectDek, ObjectError> {
    let mut protected = SecretKey::zeroed().map_err(ObjectError::Memory)?;
    protected.expose_mut().copy_from_slice(&wrapped.0[24..56]);
    XChaCha20Poly1305::new(GenericArray::from_slice(wrapping_key.expose()))
        .decrypt_in_place_detached(
            XNonce::from_slice(&wrapped.0[..24]),
            &wrap_aad(vault_id, object_id, role),
            protected.expose_mut(),
            GenericArray::from_slice(&wrapped.0[56..]),
        )
        .map_err(|_| ObjectError::Authentication)?;
    Ok(ObjectDek(protected))
}

fn validate_plan(logical_len: u64, chunk_size: u32) -> Result<u32, ObjectError> {
    if logical_len > MAX_LOGICAL_LEN
        || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)
        || !chunk_size.is_power_of_two()
    {
        return Err(ObjectError::LimitExceeded);
    }
    if logical_len == 0 {
        return Ok(0);
    }
    let count = logical_len
        .checked_add(u64::from(chunk_size) - 1)
        .ok_or(ObjectError::LimitExceeded)?
        / u64::from(chunk_size);
    u32::try_from(count).map_err(|_| ObjectError::LimitExceeded)
}

fn chunk_plaintext_len(
    logical_len: u64,
    chunk_size: u32,
    index: u32,
) -> Result<usize, ObjectError> {
    let start = u64::from(index)
        .checked_mul(u64::from(chunk_size))
        .ok_or(ObjectError::LimitExceeded)?;
    let remaining = logical_len
        .checked_sub(start)
        .ok_or(ObjectError::InvalidHeader)?;
    usize::try_from(remaining.min(u64::from(chunk_size))).map_err(|_| ObjectError::LimitExceeded)
}

fn chunk_offset(chunk_size: u32, index: u32) -> Result<u64, ObjectError> {
    u64::from(index)
        .checked_mul(u64::from(chunk_size) + TAG_LEN as u64)
        .and_then(|value| value.checked_add(OBJECT_HEADER_LEN as u64))
        .ok_or(ObjectError::LimitExceeded)
}

fn physical_len(logical_len: u64, chunk_size: u32, chunk_count: u32) -> Result<u64, ObjectError> {
    let tags = u64::from(chunk_count)
        .checked_mul(TAG_LEN as u64)
        .ok_or(ObjectError::LimitExceeded)?;
    let _ = validate_plan(logical_len, chunk_size)?;
    (OBJECT_HEADER_LEN as u64)
        .checked_add(logical_len)
        .and_then(|value| value.checked_add(tags))
        .ok_or(ObjectError::LimitExceeded)
}

fn object_nonce(prefix: &[u8; NONCE_PREFIX_LEN], domain: u8, sequence: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN] = domain;
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

fn header_aad(
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
    preamble: &[u8; PREAMBLE_LEN],
) -> Vec<u8> {
    [
        HEADER_DOMAIN,
        preamble,
        vault_id.as_bytes(),
        object_id.as_bytes(),
        &[role as u8],
    ]
    .concat()
}

fn chunk_aad(
    vault_id: VaultId,
    object_id: ObjectId,
    role: ObjectRole,
    sequence: u32,
    count: u32,
    plaintext_len: u32,
    header_identity: &[u8; 32],
) -> Vec<u8> {
    [
        CHUNK_DOMAIN,
        &OBJECT_FORMAT_VERSION.to_le_bytes(),
        &[SUITE_VERSION],
        vault_id.as_bytes(),
        object_id.as_bytes(),
        &[role as u8],
        &sequence.to_le_bytes(),
        &count.to_le_bytes(),
        &plaintext_len.to_le_bytes(),
        header_identity,
    ]
    .concat()
}

fn wrap_aad(vault_id: VaultId, object_id: ObjectId, role: ObjectRole) -> Vec<u8> {
    [
        WRAP_DOMAIN,
        &OBJECT_FORMAT_VERSION.to_le_bytes(),
        vault_id.as_bytes(),
        object_id.as_bytes(),
        &[role as u8],
    ]
    .concat()
}

fn role_directory_create(vault: &File, role: ObjectRole) -> Result<File, ObjectError> {
    let (root_name, child_name) = role.namespace();
    let root = ensure_directory(vault, root_name)?;
    match child_name {
        Some(name) => ensure_directory(&root, name),
        None => Ok(root),
    }
}

fn role_directory_open(vault: &File, role: ObjectRole) -> Result<File, ObjectError> {
    let (root_name, child_name) = role.namespace();
    let root = platform::open_dynamic_directory_at(vault, root_name)?;
    match child_name {
        Some(name) => platform::open_dynamic_directory_at(&root, name).map_err(Into::into),
        None => Ok(root),
    }
}

fn ensure_directory(parent: &File, name: &str) -> Result<File, ObjectError> {
    match platform::create_dynamic_directory_at(parent, name) {
        Ok(()) => parent.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    platform::open_dynamic_directory_at(parent, name).map_err(Into::into)
}

pub(crate) fn shard(id: ObjectId) -> String {
    hex(&id.0[..1])
}

pub(crate) fn filename(id: ObjectId, suffix: &str) -> String {
    let mut value = hex(&id.0);
    value.push_str(suffix);
    value
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn fail(faults: &mut impl PublishFaultInjector, point: PublishPoint) -> Result<(), ObjectError> {
    if faults.should_fail(point) {
        Err(ObjectError::InjectedFault(point))
    } else {
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed integer"))
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed integer"))
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed integer"))
}

#[derive(Debug)]
pub enum ObjectError {
    Io(io::Error),
    Memory(io::Error),
    Random(RandomError),
    InvalidLength,
    InvalidMagic,
    UnknownVersion,
    UnknownMandatoryFeature,
    InvalidHeader,
    Authentication,
    Cryptography,
    LimitExceeded,
    SourceLengthMismatch,
    InvalidSeek,
    PublishedIdentityChanged,
    InjectedFault(PublishPoint),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("object filesystem operation failed"),
            Self::Memory(_) => formatter.write_str("secure memory unavailable"),
            Self::Random(_) => formatter.write_str("cryptographic randomness unavailable"),
            Self::InvalidLength => formatter.write_str("invalid encrypted object length"),
            Self::InvalidMagic => formatter.write_str("invalid encrypted object magic"),
            Self::UnknownVersion => formatter.write_str("unsupported encrypted object version"),
            Self::UnknownMandatoryFeature => {
                formatter.write_str("unknown mandatory encrypted object feature")
            }
            Self::InvalidHeader => formatter.write_str("invalid encrypted object header"),
            Self::Authentication => formatter.write_str("encrypted object authentication failed"),
            Self::Cryptography => formatter.write_str("encrypted object cryptography failed"),
            Self::LimitExceeded => formatter.write_str("encrypted object limit exceeded"),
            Self::SourceLengthMismatch => {
                formatter.write_str("object source length differs from declared length")
            }
            Self::InvalidSeek => formatter.write_str("invalid encrypted object seek"),
            Self::PublishedIdentityChanged => {
                formatter.write_str("published object identity changed")
            }
            Self::InjectedFault(point) => write!(formatter, "injected object fault at {point:?}"),
        }
    }
}

impl Error for ObjectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) | Self::Memory(error) => Some(error),
            Self::Random(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ObjectError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<RandomError> for ObjectError {
    fn from(value: RandomError) -> Self {
        Self::Random(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    struct Sequence(u8);
    impl RandomSource for Sequence {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
            for byte in output {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn fixture(
        plaintext: &[u8],
        chunk_size: u32,
    ) -> (Vec<u8>, ObjectDek, VaultId, ObjectId, ObjectRole) {
        let vault_id = VaultId::from_bytes([4; 16]);
        let object_id = ObjectId::from_bytes([7; 16]);
        let role = ObjectRole::Original;
        let mut random = Sequence(30);
        let dek = ObjectDek::generate(&mut random).unwrap();
        let preamble = ObjectPreamble::create(&mut random).unwrap();
        let count = validate_plan(plaintext.len() as u64, chunk_size).unwrap();
        let mut output = Cursor::new(Vec::new());
        encrypt_stream(
            &mut Cursor::new(plaintext),
            &mut output,
            &dek,
            vault_id,
            object_id,
            role,
            plaintext.len() as u64,
            chunk_size,
            count,
            preamble,
        )
        .unwrap();
        (output.into_inner(), dek, vault_id, object_id, role)
    }

    #[test]
    fn empty_boundary_and_multi_chunk_round_trip() {
        for size in [
            0,
            1,
            MIN_CHUNK_SIZE as usize,
            MIN_CHUNK_SIZE as usize + 1,
            12_345,
        ] {
            let plaintext: Vec<u8> = (0..size).map(|index| index as u8).collect();
            let (ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
            let mut reader =
                ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, plaintext);
        }
    }

    #[test]
    fn large_maximum_chunk_round_trip() {
        let size = 2 * MAX_CHUNK_SIZE as usize + 31;
        let plaintext: Vec<u8> = (0..size).map(|index| (index * 29) as u8).collect();
        let (ciphertext, dek, vault, id, role) = fixture(&plaintext, MAX_CHUNK_SIZE);
        let mut reader = ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, plaintext);
    }

    #[test]
    fn seek_matches_plaintext_at_boundaries() {
        let plaintext: Vec<u8> = (0..10_000).map(|index| (index * 17) as u8).collect();
        for offset in [0, 1, 4095, 4096, 4097, 9_999, 10_000] {
            let (ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
            let mut reader =
                ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
            reader.seek(SeekFrom::Start(offset)).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, plaintext[offset as usize..]);
        }
    }

    #[test]
    fn tamper_truncate_context_and_role_substitution_fail_closed() {
        let plaintext = vec![9; 9000];
        let (ciphertext, dek, _vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        let wrong_vault = VaultId::from_bytes([5; 16]);
        assert!(matches!(
            ObjectReader::open(Cursor::new(ciphertext.clone()), dek, wrong_vault, id, role),
            Err(ObjectError::Authentication)
        ));

        let (ciphertext, dek, vault, _, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        assert!(matches!(
            ObjectReader::open(
                Cursor::new(ciphertext),
                dek,
                vault,
                ObjectId::from_bytes([6; 16]),
                role,
            ),
            Err(ObjectError::Authentication)
        ));

        let (ciphertext, dek, vault, id, _) = fixture(&plaintext, MIN_CHUNK_SIZE);
        assert!(matches!(
            ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, ObjectRole::Poster),
            Err(ObjectError::Authentication)
        ));

        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        ciphertext[PREAMBLE_LEN + 3] ^= 1;
        assert!(matches!(
            ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role),
            Err(ObjectError::Authentication)
        ));

        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        ciphertext[OBJECT_HEADER_LEN + 12] ^= 1;
        let mut reader = ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
        assert!(output.is_empty());

        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        ciphertext.pop();
        assert!(matches!(
            ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role),
            Err(ObjectError::InvalidLength)
        ));

        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        ciphertext.push(0);
        assert!(matches!(
            ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role),
            Err(ObjectError::InvalidLength)
        ));
    }

    #[test]
    fn swapped_chunks_are_never_released() {
        let plaintext = vec![3; 8192];
        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        let record = MIN_CHUNK_SIZE as usize + TAG_LEN;
        let (first, second) =
            ciphertext[OBJECT_HEADER_LEN..OBJECT_HEADER_LEN + 2 * record].split_at_mut(record);
        first.swap_with_slice(second);
        let mut reader = ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
        let mut output = [0_u8; 1];
        assert!(reader.read(&mut output).is_err());
    }

    #[test]
    fn failed_next_chunk_authentication_discards_the_previous_cache() {
        let plaintext = vec![3; 8192];
        let (mut ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
        let second_offset = OBJECT_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        ciphertext[second_offset] ^= 1;
        let mut reader = ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
        let mut first = vec![0; MIN_CHUNK_SIZE as usize];
        reader.read_exact(&mut first).unwrap();
        assert!(reader.read(&mut [0]).is_err());
        assert!(reader.cached_index.is_none());
        assert!(reader.cache.is_empty());
    }

    #[test]
    fn preamble_parser_rejects_reserved_and_unknown_fields() {
        let mut random = Sequence(1);
        let valid = ObjectPreamble::create(&mut random).unwrap();
        assert_eq!(ObjectPreamble::parse(&valid.bytes).unwrap(), valid);
        let mut changed = valid.bytes;
        changed[31] = 1;
        assert!(matches!(
            ObjectPreamble::parse(&changed),
            Err(ObjectError::UnknownMandatoryFeature)
        ));
        changed = valid.bytes;
        changed[8] = 2;
        assert!(matches!(
            ObjectPreamble::parse(&changed),
            Err(ObjectError::UnknownVersion)
        ));
    }

    #[test]
    fn chunk_nonces_are_unique_and_domain_separated() {
        let prefix = [8; NONCE_PREFIX_LEN];
        let header = object_nonce(&prefix, 0, 0);
        let first = object_nonce(&prefix, 1, 0);
        let second = object_nonce(&prefix, 1, 1);
        assert_ne!(header, first);
        assert_ne!(first, second);
        assert_ne!(header, second);
    }

    #[test]
    fn wrapped_dek_is_bound_to_vault_object_and_role() {
        let vault = VaultId::from_bytes([1; 16]);
        let id = ObjectId::from_bytes([2; 16]);
        let mut wrapping_bytes = [3; 32];
        let wrapping_key = SecretKey::take(&mut wrapping_bytes).unwrap();
        let mut random = Sequence(4);
        let dek = ObjectDek::generate(&mut random).unwrap();
        let (wrapped, _) = wrap_dek(
            &dek,
            &wrapping_key,
            vault,
            id,
            ObjectRole::Original,
            &mut random,
        )
        .unwrap();
        assert!(unwrap_dek(&wrapped, &wrapping_key, vault, id, ObjectRole::Original).is_ok());
        assert!(matches!(
            unwrap_dek(
                &wrapped,
                &wrapping_key,
                VaultId::from_bytes([9; 16]),
                id,
                ObjectRole::Original,
            ),
            Err(ObjectError::Authentication)
        ));
        assert!(matches!(
            unwrap_dek(
                &wrapped,
                &wrapping_key,
                vault,
                ObjectId::from_bytes([8; 16]),
                ObjectRole::Original,
            ),
            Err(ObjectError::Authentication)
        ));
        assert!(matches!(
            unwrap_dek(&wrapped, &wrapping_key, vault, id, ObjectRole::Poster),
            Err(ObjectError::Authentication)
        ));
    }

    #[test]
    fn source_length_mismatch_is_rejected() {
        let plaintext = vec![0x21; 50];
        let vault_id = VaultId::from_bytes([4; 16]);
        let object_id = ObjectId::from_bytes([7; 16]);
        let role = ObjectRole::Original;
        let mut random = Sequence(30);
        let dek = ObjectDek::generate(&mut random).unwrap();
        let preamble = ObjectPreamble::create(&mut random).unwrap();
        let result = encrypt_stream(
            &mut Cursor::new(&plaintext),
            &mut Cursor::new(Vec::new()),
            &dek,
            vault_id,
            object_id,
            role,
            49,
            MIN_CHUNK_SIZE,
            1,
            preamble,
        );
        assert!(matches!(result, Err(ObjectError::SourceLengthMismatch)));
    }

    #[test]
    fn deterministic_format_fixture() {
        let plaintext = b"osv-ng phase four object fixture";
        let (ciphertext, _dek, _vault, _id, _role) = fixture(plaintext, MIN_CHUNK_SIZE);
        let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
        assert_eq!(
            digest,
            [
                227, 44, 202, 63, 190, 6, 58, 12, 56, 79, 204, 165, 140, 118, 155, 98, 173, 166,
                248, 251, 218, 165, 89, 107, 211, 69, 21, 47, 246, 82, 53, 250,
            ]
        );
    }

    struct ShortIo<T> {
        inner: T,
        maximum: usize,
    }

    impl<T: Read> Read for ShortIo<T> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let limit = output.len().min(self.maximum);
            self.inner.read(&mut output[..limit])
        }
    }

    impl<T: Write> Write for ShortIo<T> {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let limit = input.len().min(self.maximum);
            self.inner.write(&input[..limit])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl<T: Seek> Seek for ShortIo<T> {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn short_reads_and_writes_complete_without_plaintext_loss() {
        let plaintext = vec![0x5a; 10_001];
        let vault_id = VaultId::from_bytes([4; 16]);
        let object_id = ObjectId::from_bytes([7; 16]);
        let role = ObjectRole::Original;
        let mut random = Sequence(30);
        let dek = ObjectDek::generate(&mut random).unwrap();
        let preamble = ObjectPreamble::create(&mut random).unwrap();
        let mut source = ShortIo {
            inner: Cursor::new(&plaintext),
            maximum: 3,
        };
        let mut destination = ShortIo {
            inner: Cursor::new(Vec::new()),
            maximum: 5,
        };
        encrypt_stream(
            &mut source,
            &mut destination,
            &dek,
            vault_id,
            object_id,
            role,
            plaintext.len() as u64,
            MIN_CHUNK_SIZE,
            3,
            preamble,
        )
        .unwrap();
        let mut reader = ObjectReader::open(
            ShortIo {
                inner: Cursor::new(destination.inner.into_inner()),
                maximum: 7,
            },
            dek,
            vault_id,
            object_id,
            role,
        )
        .unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, plaintext);
    }

    proptest! {
        #[test]
        fn seek_equivalence_property(
            plaintext in proptest::collection::vec(any::<u8>(), 0..20_000),
            requested in any::<u16>(),
        ) {
            let offset = usize::from(requested).min(plaintext.len());
            let (ciphertext, dek, vault, id, role) = fixture(&plaintext, MIN_CHUNK_SIZE);
            let mut reader = ObjectReader::open(Cursor::new(ciphertext), dek, vault, id, role).unwrap();
            reader.seek(SeekFrom::Start(offset as u64)).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            prop_assert_eq!(actual, &plaintext[offset..]);
        }

        #[test]
        fn offset_arithmetic_property(
            logical_len in 0_u64..(64 * 1024 * 1024),
            power in 12_u32..=23,
        ) {
            let chunk_size = 1_u32 << power;
            let count = validate_plan(logical_len, chunk_size).unwrap();
            let physical = physical_len(logical_len, chunk_size, count).unwrap();
            prop_assert_eq!(physical, OBJECT_HEADER_LEN as u64 + logical_len + u64::from(count) * TAG_LEN as u64);
            if count > 0 {
                let final_offset = chunk_offset(chunk_size, count - 1).unwrap();
                prop_assert!(final_offset < physical);
                let final_len = chunk_plaintext_len(logical_len, chunk_size, count - 1).unwrap();
                prop_assert_eq!(final_offset + final_len as u64 + TAG_LEN as u64, physical);
            }
        }
    }
}
