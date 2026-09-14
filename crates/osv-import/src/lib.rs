//! Import plans, archive boundaries, and duplicate decisions.

use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateDecision {
    Skip,
    ImportAnotherCopy,
}

/// A pending duplicate never has an implicit default. The UI must record an
/// explicit decision before an import plan can be committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateState {
    Unique,
    AwaitingDecision,
    Decided(DuplicateDecision),
}

#[derive(Clone, Eq, PartialEq)]
pub struct ImportPreview {
    pub fingerprint: [u8; 32],
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
    pub animated: bool,
    pub duplicate: DuplicateState,
}

impl std::fmt::Debug for ImportPreview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportPreview")
            .field("metadata", &"[REDACTED]")
            .field("duplicate", &self.duplicate)
            .finish()
    }
}

impl ImportPreview {
    #[must_use]
    pub fn from_probe(bytes: &[u8], probe: osv_media::ImageProbe, duplicate_exists: bool) -> Self {
        let fingerprint: [u8; 32] = Sha256::digest(bytes).into();
        Self {
            fingerprint,
            mime: probe.format.mime(),
            width: probe.width,
            height: probe.height,
            animated: probe.frames > 1,
            duplicate: if duplicate_exists {
                DuplicateState::AwaitingDecision
            } else {
                DuplicateState::Unique
            },
        }
    }

    pub fn decide(&mut self, decision: DuplicateDecision) {
        if self.duplicate == DuplicateState::AwaitingDecision {
            self.duplicate = DuplicateState::Decided(decision);
        }
    }

    #[must_use]
    pub const fn may_import(&self) -> bool {
        matches!(
            self.duplicate,
            DuplicateState::Unique | DuplicateState::Decided(DuplicateDecision::ImportAnotherCopy)
        )
    }
}

#[derive(Debug)]
pub enum ImageImportError {
    Input,
    Cancelled,
    Worker(osv_isolation::SupervisorError),
    Vault(osv_vault::ServiceError),
    DecisionRequired,
}

impl std::fmt::Display for ImageImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("image import stopped safely")
    }
}
impl std::error::Error for ImageImportError {}

pub struct PreparedImageImport {
    source: osv_crypto::SecretBytes,
    thumbnail: osv_crypto::SecretBytes,
    pub preview: ImportPreview,
    probe: osv_media::ImageProbe,
    thumbnail_width: u32,
    thumbnail_height: u32,
    display_pixels: osv_crypto::SecretBytes,
}

impl std::fmt::Debug for PreparedImageImport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedImageImport([REDACTED])")
    }
}

pub struct CommittedImage {
    pub original: osv_storage::ObjectId,
    pub thumbnail: osv_storage::ObjectId,
    pub display_pixels: osv_crypto::SecretBytes,
    pub display_width: u32,
    pub display_height: u32,
}

pub struct DecodedImage {
    pub pixels: osv_crypto::SecretBytes,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub first_delay_ms: u32,
    pub additional_frames: Vec<DecodedFrame>,
}

pub struct DecodedFrame {
    pub pixels: osv_crypto::SecretBytes,
    pub delay_ms: u32,
}

impl std::fmt::Debug for DecodedFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecodedFrame([REDACTED])")
    }
}

impl std::fmt::Debug for DecodedImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecodedImage([REDACTED])")
    }
}

struct PreparedThumbnail {
    probe: osv_media::ImageProbe,
    bytes: osv_crypto::SecretBytes,
    width: u32,
    height: u32,
    display_pixels: osv_crypto::SecretBytes,
    first_delay_ms: u32,
    additional_frames: Vec<DecodedFrame>,
}

fn prepare_thumbnail_cancellable(
    source: &osv_crypto::SecretBytes,
    worker_executable: &Path,
    request_id: u64,
    cancelled: Option<&AtomicBool>,
) -> Result<PreparedThumbnail, ImageImportError> {
    prepare_rendition_cancellable(
        source,
        worker_executable,
        request_id,
        cancelled,
        osv_media::ImagePurpose::Thumbnail,
        osv_media::THUMBNAIL_EDGE,
        osv_media::MAX_THUMBNAIL_RESULT_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_rendition_cancellable(
    source: &osv_crypto::SecretBytes,
    worker_executable: &Path,
    request_id: u64,
    cancelled: Option<&AtomicBool>,
    purpose: osv_media::ImagePurpose,
    edge: u32,
    maximum_result: usize,
) -> Result<PreparedThumbnail, ImageImportError> {
    // This broker-side pass is deliberately allocation-free. It rejects gross
    // resource abuse before IPC; the confined helper independently performs a
    // complete decode before any result is accepted.
    let probe = osv_media::probe(source.expose()).map_err(|_| ImageImportError::Input)?;
    let mut worker = osv_media::spawn_worker(
        worker_executable,
        request_id,
        osv_isolation::SupervisorLimits::default(),
    )
    .map_err(ImageImportError::Worker)?;
    let request =
        osv_media::encode_worker_request(purpose, edge).map_err(|_| ImageImportError::Input)?;
    worker
        .send_authenticated(
            0,
            osv_isolation::PlaintextBuffer::from_secret(
                osv_crypto::SecretBytes::new(&request).map_err(|_| ImageImportError::Input)?,
            )
            .map_err(|_| ImageImportError::Input)?,
        )
        .map_err(ImageImportError::Worker)?;
    for (sequence, chunk) in source
        .expose()
        .chunks(osv_worker_protocol::MAX_DATA_LEN)
        .enumerate()
    {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            worker.cancel();
            return Err(ImageImportError::Cancelled);
        }
        let sequence = u64::try_from(sequence)
            .ok()
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or(ImageImportError::Input)?;
        let bytes = osv_crypto::SecretBytes::new(chunk).map_err(|_| ImageImportError::Input)?;
        worker
            .send_authenticated(
                sequence,
                osv_isolation::PlaintextBuffer::from_secret(bytes)
                    .map_err(|_| ImageImportError::Input)?,
            )
            .map_err(ImageImportError::Worker)?;
    }
    if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        worker.cancel();
        return Err(ImageImportError::Cancelled);
    }
    let result = if let Some(cancelled) = cancelled {
        worker.finish_with_output_cancellable(maximum_result, cancelled)
    } else {
        worker.finish_with_output(maximum_result)
    };
    let (class, derived) = result.map_err(ImageImportError::Worker)?;
    if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err(ImageImportError::Cancelled);
    }
    if class != osv_isolation::ExitClass::Success {
        return Err(ImageImportError::Input);
    }
    let header = derived.chunks().next().ok_or(ImageImportError::Input)?;
    let worker_result =
        osv_media::decode_worker_result_header(header).map_err(|_| ImageImportError::Input)?;
    if worker_result.source != probe {
        return Err(ImageImportError::Input);
    }
    if worker_result.purpose != purpose || worker_result.requested_edge != edge {
        return Err(ImageImportError::Input);
    }
    validate_worker_frame_cardinality(&worker_result, purpose)?;
    let png_len =
        usize::try_from(worker_result.thumbnail_png_len).map_err(|_| ImageImportError::Input)?;
    let bytes = derived
        .copy_span(osv_media::WORKER_RESULT_HEADER_LEN, png_len)
        .map_err(ImageImportError::Worker)?;
    let rgba_len = usize::try_from(worker_result.rgba_len).map_err(|_| ImageImportError::Input)?;
    let display_pixels = derived
        .copy_span(osv_media::WORKER_RESULT_HEADER_LEN + png_len, rgba_len)
        .map_err(ImageImportError::Worker)?;
    let mut offset = osv_media::WORKER_RESULT_HEADER_LEN + png_len + rgba_len;
    let mut additional_frames = Vec::with_capacity(
        usize::try_from(worker_result.output_frames.saturating_sub(1))
            .map_err(|_| ImageImportError::Input)?,
    );
    for _ in 1..worker_result.output_frames {
        let delay = derived
            .copy_span(offset, 4)
            .map_err(ImageImportError::Worker)?;
        let delay_ms = u32::from_le_bytes(
            delay
                .expose()
                .try_into()
                .map_err(|_| ImageImportError::Input)?,
        );
        if !(10..=60_000).contains(&delay_ms) {
            return Err(ImageImportError::Input);
        }
        offset = offset.checked_add(4).ok_or(ImageImportError::Input)?;
        let pixels = derived
            .copy_span(offset, rgba_len)
            .map_err(ImageImportError::Worker)?;
        offset = offset
            .checked_add(rgba_len)
            .ok_or(ImageImportError::Input)?;
        additional_frames.push(DecodedFrame { pixels, delay_ms });
    }
    if derived.logical_len() != offset
        || usize::try_from(worker_result.additional_frames_len)
            .map_err(|_| ImageImportError::Input)?
            != offset - (osv_media::WORKER_RESULT_HEADER_LEN + png_len + rgba_len)
    {
        return Err(ImageImportError::Input);
    }
    let thumbnail_probe = osv_media::probe(bytes.expose()).map_err(|_| ImageImportError::Input)?;
    if thumbnail_probe.format != osv_media::ImageFormat::Png
        || thumbnail_probe.width != worker_result.thumbnail_width
        || thumbnail_probe.height != worker_result.thumbnail_height
        || thumbnail_probe.frames != 1
    {
        return Err(ImageImportError::Input);
    }
    Ok(PreparedThumbnail {
        probe,
        bytes,
        width: worker_result.thumbnail_width,
        height: worker_result.thumbnail_height,
        display_pixels,
        first_delay_ms: worker_result.first_delay_ms,
        additional_frames,
    })
}

fn validate_worker_frame_cardinality(
    result: &osv_media::WorkerImageResult,
    purpose: osv_media::ImagePurpose,
) -> Result<(), ImageImportError> {
    let expected = match purpose {
        osv_media::ImagePurpose::Thumbnail => 1,
        osv_media::ImagePurpose::Viewer => result.source.frames,
    };
    if result.output_frames != expected
        || (purpose == osv_media::ImagePurpose::Thumbnail
            && (result.first_delay_ms != 0 || result.additional_frames_len != 0))
    {
        return Err(ImageImportError::Input);
    }
    Ok(())
}

/// Reads a stable, already-open source into protected memory, sends it to one
/// short-lived helper, and checks exact duplicates only in the encrypted catalog.
pub fn prepare_image_import(
    source: &mut impl Read,
    logical_len: u64,
    worker_executable: &Path,
    request_id: u64,
    catalog: &osv_catalog::CatalogReader<'_>,
) -> Result<PreparedImageImport, ImageImportError> {
    prepare_image_import_cancellable(
        source,
        logical_len,
        worker_executable,
        request_id,
        catalog,
        &AtomicBool::new(false),
    )
}

pub fn prepare_image_import_cancellable(
    source: &mut impl Read,
    logical_len: u64,
    worker_executable: &Path,
    request_id: u64,
    catalog: &osv_catalog::CatalogReader<'_>,
    cancelled: &AtomicBool,
) -> Result<PreparedImageImport, ImageImportError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ImageImportError::Cancelled);
    }
    let len = usize::try_from(logical_len).map_err(|_| ImageImportError::Input)?;
    if len == 0 || len > osv_media::MAX_ENCODED_BYTES {
        return Err(ImageImportError::Input);
    }
    let mut protected =
        osv_crypto::SecretBytes::zeroed(len).map_err(|_| ImageImportError::Input)?;
    source
        .read_exact(protected.expose_mut())
        .map_err(|_| ImageImportError::Input)?;
    let mut excess = [0u8; 1];
    if source
        .read(&mut excess)
        .map_err(|_| ImageImportError::Input)?
        != 0
    {
        return Err(ImageImportError::Input);
    }
    let prepared =
        prepare_thumbnail_cancellable(&protected, worker_executable, request_id, Some(cancelled))?;
    let probe = prepared.probe;
    let fingerprint: [u8; 32] = Sha256::digest(protected.expose()).into();
    let duplicate = catalog
        .has_fingerprint(&fingerprint)
        .map_err(|_| ImageImportError::Input)?;
    Ok(PreparedImageImport {
        source: protected,
        thumbnail: prepared.bytes,
        preview: ImportPreview::from_probe_with_fingerprint(fingerprint, probe, duplicate),
        probe,
        thumbnail_width: prepared.width,
        thumbnail_height: prepared.height,
        display_pixels: prepared.display_pixels,
    })
}

/// Regenerates one missing/stale thumbnail from the authenticated original.
/// Worker failure or cancellation occurs before publication and therefore
/// cannot invalidate the original or the currently referenced derived object.
pub fn regenerate_image_thumbnail(
    vault: &mut osv_vault::VaultService,
    target: osv_catalog::DerivedRegeneration,
    worker_executable: &Path,
    request_id: u64,
    now_ms: i64,
) -> Result<osv_storage::ObjectId, ImageImportError> {
    regenerate_image_thumbnail_cancellable(
        vault,
        target,
        worker_executable,
        request_id,
        now_ms,
        None,
    )
}

pub fn regenerate_image_thumbnail_cancellable(
    vault: &mut osv_vault::VaultService,
    target: osv_catalog::DerivedRegeneration,
    worker_executable: &Path,
    request_id: u64,
    now_ms: i64,
    cancelled: Option<&AtomicBool>,
) -> Result<osv_storage::ObjectId, ImageImportError> {
    let logical_len = vault
        .reader()
        .object(target.original_object_id)
        .map_err(|_| ImageImportError::Input)?
        .descriptor
        .logical_len();
    let len = usize::try_from(logical_len).map_err(|_| ImageImportError::Input)?;
    if len == 0 || len > osv_media::MAX_ENCODED_BYTES {
        return Err(ImageImportError::Input);
    }
    let mut source = osv_crypto::SecretBytes::zeroed(len).map_err(|_| ImageImportError::Input)?;
    {
        let mut reader = vault
            .open_object(target.original_object_id)
            .map_err(ImageImportError::Vault)?;
        let mut offset = 0;
        while offset < len {
            if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                return Err(ImageImportError::Cancelled);
            }
            let end = (offset + osv_worker_protocol::MAX_DATA_LEN).min(len);
            reader
                .read_exact(&mut source.expose_mut()[offset..end])
                .map_err(|_| ImageImportError::Input)?;
            offset = end;
        }
        let mut excess = [0u8; 1];
        if reader
            .read(&mut excess)
            .map_err(|_| ImageImportError::Input)?
            != 0
        {
            return Err(ImageImportError::Input);
        }
    }
    let prepared =
        prepare_thumbnail_cancellable(&source, worker_executable, request_id, cancelled)?;
    if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err(ImageImportError::Cancelled);
    }
    publish_regenerated_thumbnail(
        vault,
        target,
        prepared,
        now_ms,
        &mut osv_vault::NoServiceFaults,
    )
}

fn publish_regenerated_thumbnail(
    vault: &mut osv_vault::VaultService,
    target: osv_catalog::DerivedRegeneration,
    prepared: PreparedThumbnail,
    now_ms: i64,
    faults: &mut impl osv_vault::ServiceFaultInjector,
) -> Result<osv_storage::ObjectId, ImageImportError> {
    let logical_len = u64::try_from(prepared.bytes.len()).map_err(|_| ImageImportError::Input)?;
    let mut reader = std::io::Cursor::new(prepared.bytes.expose());
    vault
        .replace_derived_with(
            &mut reader,
            logical_len,
            target.media_id,
            osv_storage::ObjectRole::Thumbnail,
            osv_media::THUMBNAIL_RECIPE_VERSION,
            prepared.width,
            prepared.height,
            now_ms,
            faults,
        )
        .map_err(ImageImportError::Vault)
}

/// Reopens one catalog-authorized encrypted object, authenticates every chunk,
/// and gives the confined media worker only the resulting object bytes.
pub fn decode_image_object_cancellable(
    vault: &osv_vault::VaultService,
    object_id: osv_storage::ObjectId,
    worker_executable: &Path,
    request_id: u64,
    cancelled: &AtomicBool,
) -> Result<DecodedImage, ImageImportError> {
    decode_image_object_for(
        vault,
        object_id,
        worker_executable,
        request_id,
        cancelled,
        osv_media::ImagePurpose::Thumbnail,
        osv_media::THUMBNAIL_EDGE,
        osv_media::MAX_THUMBNAIL_RESULT_BYTES,
    )
}

pub fn decode_image_original_view_cancellable(
    vault: &osv_vault::VaultService,
    object_id: osv_storage::ObjectId,
    worker_executable: &Path,
    request_id: u64,
    cancelled: &AtomicBool,
) -> Result<DecodedImage, ImageImportError> {
    decode_image_object_for(
        vault,
        object_id,
        worker_executable,
        request_id,
        cancelled,
        osv_media::ImagePurpose::Viewer,
        osv_media::MAX_VIEWER_EDGE,
        osv_media::MAX_VIEWER_RESULT_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_image_object_for(
    vault: &osv_vault::VaultService,
    object_id: osv_storage::ObjectId,
    worker_executable: &Path,
    request_id: u64,
    cancelled: &AtomicBool,
    purpose: osv_media::ImagePurpose,
    edge: u32,
    maximum_result: usize,
) -> Result<DecodedImage, ImageImportError> {
    let logical_len = vault
        .reader()
        .object(object_id)
        .map_err(|_| ImageImportError::Input)?
        .descriptor
        .logical_len();
    let len = usize::try_from(logical_len).map_err(|_| ImageImportError::Input)?;
    if len == 0 || len > osv_media::MAX_ENCODED_BYTES {
        return Err(ImageImportError::Input);
    }
    let mut source = osv_crypto::SecretBytes::zeroed(len).map_err(|_| ImageImportError::Input)?;
    let mut reader = vault
        .open_object(object_id)
        .map_err(ImageImportError::Vault)?;
    let mut offset = 0;
    while offset < len {
        if cancelled.load(Ordering::Acquire) {
            return Err(ImageImportError::Cancelled);
        }
        let end = (offset + osv_worker_protocol::MAX_DATA_LEN).min(len);
        reader
            .read_exact(&mut source.expose_mut()[offset..end])
            .map_err(|_| ImageImportError::Input)?;
        offset = end;
    }
    let mut excess = [0u8; 1];
    if reader
        .read(&mut excess)
        .map_err(|_| ImageImportError::Input)?
        != 0
    {
        return Err(ImageImportError::Input);
    }
    drop(reader);
    let prepared = prepare_rendition_cancellable(
        &source,
        worker_executable,
        request_id,
        Some(cancelled),
        purpose,
        edge,
        maximum_result,
    )?;
    let frames = worker_result_count(&prepared);
    Ok(DecodedImage {
        pixels: prepared.display_pixels,
        width: prepared.width,
        height: prepared.height,
        frames,
        first_delay_ms: prepared.first_delay_ms,
        additional_frames: prepared.additional_frames,
    })
}

fn worker_result_count(prepared: &PreparedThumbnail) -> u32 {
    u32::try_from(prepared.additional_frames.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1)
}

impl ImportPreview {
    fn from_probe_with_fingerprint(
        fingerprint: [u8; 32],
        probe: osv_media::ImageProbe,
        duplicate_exists: bool,
    ) -> Self {
        Self {
            fingerprint,
            mime: probe.format.mime(),
            width: probe.width,
            height: probe.height,
            animated: probe.frames > 1,
            duplicate: if duplicate_exists {
                DuplicateState::AwaitingDecision
            } else {
                DuplicateState::Unique
            },
        }
    }
}

impl PreparedImageImport {
    pub fn commit(
        self,
        vault: &mut osv_vault::VaultService,
        id: osv_catalog::MediaId,
        original_name: &str,
        imported_at_ms: i64,
    ) -> Result<CommittedImage, ImageImportError> {
        if !self.preview.may_import() {
            return Err(ImageImportError::DecisionRequired);
        }
        let metadata = osv_vault::ImportMetadata {
            id,
            original_name,
            class: osv_catalog::MediaClass::Image,
            mime: self.preview.mime,
            width: Some(self.probe.width),
            height: Some(self.probe.height),
            duration_ms: None,
            codecs: match self.probe.format {
                osv_media::ImageFormat::Png => "png",
                osv_media::ImageFormat::Jpeg => "jpeg",
                osv_media::ImageFormat::Gif => "gif",
                osv_media::ImageFormat::Webp => "webp",
            },
            imported_at_ms,
            fingerprint: &self.preview.fingerprint,
        };
        let mut original_reader = std::io::Cursor::new(self.source.expose());
        let original_len = u64::try_from(self.source.len()).map_err(|_| ImageImportError::Input)?;
        let original = vault
            .import(&mut original_reader, original_len, metadata)
            .map_err(ImageImportError::Vault)?;
        let mut thumbnail_reader = std::io::Cursor::new(self.thumbnail.expose());
        let thumbnail_len = self.thumbnail.len();
        let thumbnail_len = u64::try_from(thumbnail_len).map_err(|_| ImageImportError::Input)?;
        let thumbnail = vault
            .replace_derived(
                &mut thumbnail_reader,
                thumbnail_len,
                id,
                osv_storage::ObjectRole::Thumbnail,
                osv_media::THUMBNAIL_RECIPE_VERSION,
                self.thumbnail_width,
                self.thumbnail_height,
                imported_at_ms,
            )
            .map_err(ImageImportError::Vault)?;
        Ok(CommittedImage {
            original,
            thumbnail,
            display_pixels: self.display_pixels,
            display_width: self.thumbnail_width,
            display_height: self.thumbnail_height,
        })
    }
}

/// Starts one short-lived, object-scoped archive parser.
pub fn spawn_archive_worker(
    executable: &Path,
    request_id: u64,
    limits: osv_isolation::SupervisorLimits,
) -> Result<osv_isolation::Supervisor, osv_isolation::SupervisorError> {
    osv_isolation::Supervisor::spawn(
        executable,
        osv_worker_protocol::Role::Archive,
        request_id,
        limits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailAt(osv_vault::ServicePoint);

    impl osv_vault::ServiceFaultInjector for FailAt {
        fn should_fail(&mut self, point: osv_vault::ServicePoint) -> bool {
            point == self.0
        }
    }

    fn worker_result(
        purpose: osv_media::ImagePurpose,
        source_frames: u32,
    ) -> osv_media::WorkerImageResult {
        osv_media::WorkerImageResult {
            source: osv_media::ImageProbe {
                format: osv_media::ImageFormat::Gif,
                width: 2,
                height: 2,
                frames: source_frames,
                orientation: osv_media::Orientation::Normal,
                has_color_profile: false,
            },
            thumbnail_width: 2,
            thumbnail_height: 2,
            thumbnail_png_len: 1,
            rgba_len: 16,
            purpose,
            requested_edge: osv_media::THUMBNAIL_EDGE,
            output_frames: source_frames,
            first_delay_ms: if source_frames > 1 { 20 } else { 0 },
            additional_frames_len: source_frames.saturating_sub(1) * 20,
        }
    }

    #[test]
    fn broker_requires_exact_frame_cardinality_by_purpose() {
        let mut viewer = worker_result(osv_media::ImagePurpose::Viewer, 2);
        assert!(validate_worker_frame_cardinality(&viewer, viewer.purpose).is_ok());
        viewer.output_frames = 1;
        viewer.first_delay_ms = 0;
        viewer.additional_frames_len = 0;
        assert!(validate_worker_frame_cardinality(&viewer, viewer.purpose).is_err());

        let mut thumbnail = worker_result(osv_media::ImagePurpose::Thumbnail, 2);
        thumbnail.output_frames = 1;
        thumbnail.first_delay_ms = 0;
        thumbnail.additional_frames_len = 0;
        assert!(validate_worker_frame_cardinality(&thumbnail, thumbnail.purpose).is_ok());
        thumbnail.first_delay_ms = 20;
        assert!(validate_worker_frame_cardinality(&thumbnail, thumbnail.purpose).is_err());
    }

    #[test]
    fn duplicate_requires_explicit_choice() {
        let probe = osv_media::ImageProbe {
            format: osv_media::ImageFormat::Png,
            width: 1,
            height: 1,
            frames: 1,
            orientation: osv_media::Orientation::Normal,
            has_color_profile: true,
        };
        let mut preview = ImportPreview::from_probe(b"same bytes", probe, true);
        assert!(!preview.may_import());
        preview.decide(DuplicateDecision::ImportAnotherCopy);
        assert!(preview.may_import());
        let expected: [u8; 32] = Sha256::digest(b"same bytes").into();
        assert_eq!(preview.fingerprint, expected);
        assert!(!format!("{preview:?}").contains("same bytes"));
        assert!(!format!("{preview:?}").contains("image/png"));
    }

    #[test]
    fn pre_cancelled_import_never_starts_a_worker() {
        let cancelled = AtomicBool::new(true);
        let mut source = std::io::Cursor::new(b"not opened".as_slice());
        let parent = osv_test_support::TempVault::create_in(Path::new("/tmp")).unwrap();
        let password = osv_crypto::Password::new(b"cancel test password").unwrap();
        let vault = osv_vault::VaultService::create(
            &parent.path().join("cancel-vault"),
            &password,
            None,
            osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
            1,
        )
        .unwrap();
        assert!(matches!(
            prepare_image_import_cancellable(
                &mut source,
                10,
                Path::new("/missing-worker"),
                1,
                &vault.reader(),
                &cancelled,
            ),
            Err(ImageImportError::Cancelled)
        ));
    }

    #[test]
    fn regeneration_publication_faults_preserve_a_durable_catalog_target() {
        for point in [
            osv_vault::ServicePoint::ObjectDurable,
            osv_vault::ServicePoint::BeforeCatalogCommit,
            osv_vault::ServicePoint::CatalogCommitted,
        ] {
            let parent = osv_test_support::TempVault::create_in(Path::new("/tmp")).unwrap();
            let password = osv_crypto::Password::new(b"regeneration fault password").unwrap();
            let path = parent.path().join(point.name());
            let mut vault = osv_vault::VaultService::create(
                &path,
                &password,
                None,
                osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
                1,
            )
            .unwrap();
            let media_id = osv_catalog::MediaId::from_bytes([0x31; 16]);
            let original = b"authenticated original";
            let original_id = vault
                .import(
                    &mut std::io::Cursor::new(original),
                    original.len() as u64,
                    osv_vault::ImportMetadata {
                        id: media_id,
                        original_name: "private.png",
                        class: osv_catalog::MediaClass::Image,
                        mime: "image/png",
                        width: Some(2),
                        height: Some(2),
                        duration_ms: None,
                        codecs: "",
                        imported_at_ms: 1,
                        fingerprint: &[0x42; 32],
                    },
                )
                .unwrap();
            let old = b"old encrypted thumbnail";
            let old_id = vault
                .replace_derived(
                    &mut std::io::Cursor::new(old),
                    old.len() as u64,
                    media_id,
                    osv_storage::ObjectRole::Thumbnail,
                    2,
                    2,
                    2,
                    2,
                )
                .unwrap();
            let prepared = PreparedThumbnail {
                probe: osv_media::ImageProbe {
                    format: osv_media::ImageFormat::Png,
                    width: 2,
                    height: 2,
                    frames: 1,
                    orientation: osv_media::Orientation::Normal,
                    has_color_profile: false,
                },
                bytes: osv_crypto::SecretBytes::new(b"new encrypted thumbnail").unwrap(),
                width: 2,
                height: 2,
                display_pixels: osv_crypto::SecretBytes::zeroed(16).unwrap(),
                first_delay_ms: 0,
                additional_frames: Vec::new(),
            };
            let result = publish_regenerated_thumbnail(
                &mut vault,
                osv_catalog::DerivedRegeneration {
                    media_id,
                    original_object_id: original_id,
                },
                prepared,
                3,
                &mut FailAt(point),
            );
            assert!(
                matches!(result, Err(ImageImportError::Vault(osv_vault::ServiceError::InjectedFault(actual))) if actual == point)
            );

            let committed_new = point == osv_vault::ServicePoint::CatalogCommitted;
            let recipe = if committed_new {
                osv_media::THUMBNAIL_RECIPE_VERSION
            } else {
                2
            };
            let record = vault.reader().image_records(recipe, 10).unwrap()[0];
            let referenced = record.thumbnail_object_id.unwrap();
            assert_eq!(referenced == old_id, !committed_new);
            let mut plaintext = Vec::new();
            vault
                .open_object(referenced)
                .unwrap()
                .read_to_end(&mut plaintext)
                .unwrap();
            assert_eq!(
                plaintext,
                if committed_new {
                    b"new encrypted thumbnail".as_slice()
                } else {
                    old.as_slice()
                }
            );
            vault.maintenance_scan().unwrap();
            assert!(vault.reader().operation_journal().unwrap().is_empty());
            assert_eq!(
                vault
                    .reader()
                    .all_objects()
                    .unwrap()
                    .iter()
                    .filter(|object| {
                        object.descriptor.role() == osv_storage::ObjectRole::Thumbnail
                    })
                    .count(),
                1
            );
            vault.close().unwrap();
        }
    }
}
