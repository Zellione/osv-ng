//! Serial background ownership for an unlocked production vault session.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use osv_crypto::{KdfParams, Password, RandomSource, SystemRandom};
use osv_import::{DuplicateDecision, ImageImportError};
use osv_vault::{OpenMode, VaultService};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static SESSION_ID: AtomicU64 = AtomicU64::new(1);
static PREPARATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenKind {
    Create,
    Unlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Open,
    Input,
    Duplicate,
    Cancelled,
    Closed,
}

pub struct ImportRequest {
    pub source: std::fs::File,
    pub original_name: osv_crypto::SecretString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportPreview {
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
    pub animated: bool,
    pub duplicate: bool,
}

pub struct ImportedImage {
    pub media_id: osv_catalog::MediaId,
    pub original: osv_storage::ObjectId,
    pub thumbnail: Option<osv_storage::ObjectId>,
    pub pixels: osv_crypto::SecretBytes,
    pub width: u32,
    pub height: u32,
    pub lock_status: osv_crypto::LockStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GalleryImage {
    pub media_id: osv_catalog::MediaId,
    pub width: u32,
    pub height: u32,
    pub favorite: bool,
    pub has_thumbnail: bool,
}

pub struct GalleryFolder {
    pub id: osv_catalog::GalleryId,
    pub name: osv_crypto::SecretString,
}

#[derive(Clone, Copy)]
pub enum GalleryChild {
    Gallery(osv_catalog::GalleryId),
    Image(GalleryImage),
}

pub struct GallerySnapshot {
    pub roots: Vec<GalleryChild>,
    pub folders: HashMap<osv_catalog::GalleryId, GalleryFolder>,
    pub children: HashMap<osv_catalog::GalleryId, Vec<GalleryChild>>,
}

impl GallerySnapshot {
    #[must_use]
    pub fn level(&self, folder: Option<osv_catalog::GalleryId>) -> &[GalleryChild] {
        folder.map_or(self.roots.as_slice(), |id| {
            self.children.get(&id).map_or(&[], Vec::as_slice)
        })
    }
}

pub struct OpenedImage {
    pub media_id: osv_catalog::MediaId,
    pub pixels: osv_crypto::SecretBytes,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub first_delay_ms: u32,
    pub additional_frames: Vec<osv_import::DecodedFrame>,
    pub lock_status: osv_crypto::LockStatus,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceStatus {
    pub total: u32,
    pub completed: u32,
    pub failed: u32,
    pub running: bool,
}

impl std::fmt::Debug for OpenedImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedImage")
            .field("media_id", &self.media_id)
            .field("pixels", &"[REDACTED]")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("frames", &self.frames)
            .field("additional_frames", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for ImportedImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedImage")
            .field("media_id", &self.media_id)
            .field("original", &self.original)
            .field("thumbnail", &self.thumbnail)
            .field("pixels", &"[REDACTED]")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

enum Command {
    ListGallery {
        response: mpsc::Sender<Result<GallerySnapshot, RuntimeError>>,
    },
    OpenThumbnail {
        media_id: osv_catalog::MediaId,
        response: mpsc::Sender<Result<OpenedImage, RuntimeError>>,
    },
    OpenViewer {
        media_id: osv_catalog::MediaId,
        response: mpsc::Sender<Result<OpenedImage, RuntimeError>>,
    },
    PrepareImport {
        preparation_id: PreparationId,
        request: ImportRequest,
        response: mpsc::Sender<Result<ImportPreview, RuntimeError>>,
    },
    CommitImport {
        preparation_id: PreparationId,
        decision: Option<DuplicateDecision>,
        response: mpsc::Sender<Result<Option<ImportedImage>, RuntimeError>>,
    },
    Close,
}

/// GTK owns this capability, never the vault keys/catalog themselves.
pub struct VaultSession {
    generation: u64,
    commands: mpsc::Sender<Command>,
    ready: mpsc::Receiver<Result<(), RuntimeError>>,
    cancelled: Arc<AtomicBool>,
    maintenance: Arc<Mutex<MaintenanceStatus>>,
    catalog_revision: Arc<AtomicU64>,
    security_degraded: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for VaultSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultSession([REDACTED])")
    }
}

impl VaultSession {
    #[must_use]
    pub fn begin(path: PathBuf, mut password_bytes: Vec<u8>, kind: OpenKind) -> Self {
        let generation = SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let (commands, command_rx) = mpsc::channel();
        let (ready_tx, ready) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let maintenance = Arc::new(Mutex::new(MaintenanceStatus::default()));
        let worker_maintenance = Arc::clone(&maintenance);
        let catalog_revision = Arc::new(AtomicU64::new(0));
        let worker_catalog_revision = Arc::clone(&catalog_revision);
        let security_degraded = Arc::new(AtomicBool::new(false));
        let worker_security_degraded = Arc::clone(&security_degraded);
        let thread = thread::spawn(move || {
            let password = match Password::take(&mut password_bytes) {
                Ok(password) => password,
                Err(_) => {
                    let _ = ready_tx.send(Err(RuntimeError::Open));
                    return;
                }
            };
            let opened = match kind {
                OpenKind::Create => VaultService::create(
                    &path,
                    &password,
                    None,
                    KdfParams::interactive_default(),
                    1,
                ),
                OpenKind::Unlock => VaultService::open(&path, &password, None, OpenMode::Writer),
            };
            let Ok(mut vault) = opened else {
                let _ = ready_tx.send(Err(RuntimeError::Open));
                return;
            };
            record_lock_status(
                &worker_security_degraded,
                vault.security_status().page_locks(),
            );
            if ready_tx.send(Ok(())).is_err() {
                let _ = vault.close();
                return;
            }
            let mut pending = None;
            let mut regeneration: VecDeque<_> = vault
                .reader()
                .derived_needing_recipe(
                    osv_storage::ObjectRole::Thumbnail,
                    osv_media::THUMBNAIL_RECIPE_VERSION,
                    10_000,
                )
                .unwrap_or_default()
                .into();
            if let Ok(mut status) = worker_maintenance.lock() {
                status.total = u32::try_from(regeneration.len()).unwrap_or(u32::MAX);
            }
            loop {
                let command = if regeneration.is_empty() {
                    match command_rx.recv() {
                        Ok(command) => Some(command),
                        Err(_) => break,
                    }
                } else {
                    match command_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                        Ok(command) => Some(command),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                };
                let Some(command) = command else {
                    let Some(target) = regeneration.pop_front() else {
                        continue;
                    };
                    if let Ok(mut status) = worker_maintenance.lock() {
                        status.running = true;
                    }
                    let result = osv_import::regenerate_image_thumbnail_cancellable_observed(
                        &mut vault,
                        target,
                        &media_worker_path(),
                        REQUEST_ID.fetch_add(1, Ordering::Relaxed),
                        now_ms().unwrap_or(0),
                        Some(&worker_cancelled),
                    );
                    if let Ok((_, lock_status)) = &result {
                        record_lock_status(&worker_security_degraded, *lock_status);
                    }
                    if let Ok(mut status) = worker_maintenance.lock() {
                        status.running = false;
                        if result.is_ok() {
                            status.completed = status.completed.saturating_add(1);
                            worker_catalog_revision.fetch_add(1, Ordering::Release);
                        } else if !worker_cancelled.load(Ordering::Acquire) {
                            status.failed = status.failed.saturating_add(1);
                        }
                    }
                    continue;
                };
                if worker_cancelled.load(Ordering::Acquire) {
                    match command {
                        Command::ListGallery { response } => {
                            let _ = response.send(Err(RuntimeError::Cancelled));
                        }
                        Command::OpenThumbnail { response, .. }
                        | Command::OpenViewer { response, .. } => {
                            let _ = response.send(Err(RuntimeError::Cancelled));
                        }
                        Command::PrepareImport { response, .. } => {
                            let _ = response.send(Err(RuntimeError::Cancelled));
                        }
                        Command::CommitImport { response, .. } => {
                            let _ = response.send(Err(RuntimeError::Cancelled));
                        }
                        Command::Close => break,
                    }
                    continue;
                }
                match command {
                    Command::ListGallery { response } => {
                        let result = list_gallery(&vault);
                        if let Ok(snapshot) = &result {
                            for folder in snapshot.folders.values() {
                                record_lock_status(
                                    &worker_security_degraded,
                                    folder.name.lock_status(),
                                );
                            }
                        }
                        let _ = response.send(result);
                    }
                    Command::OpenThumbnail { media_id, response } => {
                        let result = open_thumbnail(&vault, media_id, &worker_cancelled);
                        if let Ok(opened) = &result {
                            record_lock_status(&worker_security_degraded, opened.lock_status);
                        }
                        let _ = response.send(result);
                    }
                    Command::OpenViewer { media_id, response } => {
                        let result = open_viewer(&vault, media_id, &worker_cancelled);
                        if let Ok(opened) = &result {
                            record_lock_status(&worker_security_degraded, opened.lock_status);
                        }
                        let _ = response.send(result);
                    }
                    Command::PrepareImport {
                        preparation_id,
                        request,
                        response,
                    } => {
                        pending = None;
                        match prepare_import(&vault, request, &worker_cancelled) {
                            Ok((prepared, original_name, preview)) => {
                                record_lock_status(
                                    &worker_security_degraded,
                                    prepared.lock_status(),
                                );
                                record_lock_status(
                                    &worker_security_degraded,
                                    original_name.lock_status(),
                                );
                                pending = Some((preparation_id, (prepared, original_name)));
                                let _ = response.send(Ok(preview));
                            }
                            Err(error) => {
                                let _ = response.send(Err(error));
                            }
                        }
                    }
                    Command::CommitImport {
                        preparation_id,
                        decision,
                        response,
                    } => {
                        let result = take_pending_for(&mut pending, preparation_id).and_then(
                            |(prepared, name)| commit_import(&mut vault, prepared, name, decision),
                        );
                        if let Ok(Some(imported)) = &result {
                            record_lock_status(&worker_security_degraded, imported.lock_status);
                            worker_catalog_revision.fetch_add(1, Ordering::Release);
                            if imported.thumbnail.is_none() {
                                regeneration.push_back(osv_catalog::DerivedRegeneration {
                                    media_id: imported.media_id,
                                    original_object_id: imported.original,
                                });
                                if let Ok(mut status) = worker_maintenance.lock() {
                                    status.total = status.total.saturating_add(1);
                                }
                            }
                        }
                        let _ = response.send(result);
                    }
                    Command::Close => break,
                }
            }
            let _ = vault.close();
        });
        Self {
            generation,
            commands,
            ready,
            cancelled,
            maintenance,
            catalog_revision,
            security_degraded,
            thread: Some(thread),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn maintenance_status(&self) -> MaintenanceStatus {
        self.maintenance.lock().map_or_else(
            |_| MaintenanceStatus {
                failed: 1,
                ..MaintenanceStatus::default()
            },
            |status| *status,
        )
    }

    #[must_use]
    pub fn catalog_revision(&self) -> u64 {
        self.catalog_revision.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn page_locks(&self) -> osv_crypto::LockStatus {
        if self.security_degraded.load(Ordering::Acquire) {
            osv_crypto::LockStatus::Degraded
        } else {
            osv_crypto::LockStatus::Locked
        }
    }

    pub fn try_ready(&self) -> Option<Result<(), RuntimeError>> {
        match self.ready.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(RuntimeError::Closed)),
        }
    }

    pub fn prepare_import(
        &self,
        request: ImportRequest,
    ) -> Result<
        (
            PreparationId,
            mpsc::Receiver<Result<ImportPreview, RuntimeError>>,
        ),
        RuntimeError,
    > {
        let (response, receiver) = mpsc::channel();
        let preparation_id = PreparationId(PREPARATION_ID.fetch_add(1, Ordering::Relaxed));
        self.commands
            .send(Command::PrepareImport {
                preparation_id,
                request,
                response,
            })
            .map_err(|_| RuntimeError::Closed)?;
        Ok((preparation_id, receiver))
    }

    pub fn list_gallery(
        &self,
    ) -> Result<mpsc::Receiver<Result<GallerySnapshot, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::ListGallery { response })
            .map_err(|_| RuntimeError::Closed)?;
        Ok(receiver)
    }

    pub fn open_thumbnail(
        &self,
        media_id: osv_catalog::MediaId,
    ) -> Result<mpsc::Receiver<Result<OpenedImage, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::OpenThumbnail { media_id, response })
            .map_err(|_| RuntimeError::Closed)?;
        Ok(receiver)
    }

    pub fn open_viewer(
        &self,
        media_id: osv_catalog::MediaId,
    ) -> Result<mpsc::Receiver<Result<OpenedImage, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::OpenViewer { media_id, response })
            .map_err(|_| RuntimeError::Closed)?;
        Ok(receiver)
    }

    pub fn commit_import(
        &self,
        preparation_id: PreparationId,
        decision: Option<DuplicateDecision>,
    ) -> Result<mpsc::Receiver<Result<Option<ImportedImage>, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::CommitImport {
                preparation_id,
                decision,
                response,
            })
            .map_err(|_| RuntimeError::Closed)?;
        Ok(receiver)
    }

    /// Immediately revokes active helper work; clean vault close follows on its
    /// owner thread after any in-flight atomic catalog transition finishes.
    pub fn revoke(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.commands.send(Command::Close);
    }

    pub fn close(mut self) {
        self.revoke();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn take_pending_for<T>(
    pending: &mut Option<(PreparationId, T)>,
    preparation_id: PreparationId,
) -> Result<T, RuntimeError> {
    if pending
        .as_ref()
        .is_none_or(|(pending_id, _)| *pending_id != preparation_id)
    {
        return Err(RuntimeError::Input);
    }
    pending
        .take()
        .map(|(_, value)| value)
        .ok_or(RuntimeError::Input)
}

fn record_lock_status(degraded: &AtomicBool, status: osv_crypto::LockStatus) {
    if status == osv_crypto::LockStatus::Degraded {
        degraded.store(true, Ordering::Release);
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.revoke();
        // Never stall GTK waiting for filesystem sync. A finished session is
        // joined; otherwise its thread retains ownership until clean close.
        if self
            .thread
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

fn prepare_import(
    vault: &VaultService,
    request: ImportRequest,
    cancelled: &AtomicBool,
) -> Result<
    (
        osv_import::PreparedImageImport,
        osv_crypto::SecretString,
        ImportPreview,
    ),
    RuntimeError,
> {
    let worker = media_worker_path();
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let mut source = request.source;
    let metadata = source.metadata().map_err(|_| RuntimeError::Input)?;
    if !metadata.is_file() {
        return Err(RuntimeError::Input);
    }
    let logical_len = metadata.len();
    let prepared = osv_import::prepare_image_import_cancellable(
        &mut source,
        logical_len,
        &worker,
        request_id,
        &vault.reader(),
        cancelled,
    )
    .map_err(map_import_error)?;
    let preview = ImportPreview {
        mime: prepared.preview.mime,
        width: prepared.preview.width,
        height: prepared.preview.height,
        animated: prepared.preview.animated,
        duplicate: prepared.preview.duplicate == osv_import::DuplicateState::AwaitingDecision,
    };
    Ok((prepared, request.original_name, preview))
}

fn list_gallery(vault: &VaultService) -> Result<GallerySnapshot, RuntimeError> {
    const LIMIT: usize = 10_000;
    let images: Vec<_> = vault
        .reader()
        .image_records(osv_media::THUMBNAIL_RECIPE_VERSION, 10_000)
        .map_err(|_| RuntimeError::Input)
        .map(|records| {
            records
                .into_iter()
                .map(|record| GalleryImage {
                    media_id: record.id,
                    width: record.width,
                    height: record.height,
                    favorite: record.favorite,
                    has_thumbnail: record.thumbnail_object_id.is_some(),
                })
                .collect()
        })?;
    let records = vault
        .reader()
        .gallery_records(10_000)
        .map_err(|_| RuntimeError::Input)?;
    if images
        .len()
        .checked_add(records.len())
        .is_none_or(|total| total > LIMIT)
    {
        return Err(RuntimeError::Input);
    }
    let image_by_id: HashMap<_, _> = images
        .iter()
        .map(|image| (image.media_id, *image))
        .collect();
    let gallery_order: Vec<_> = records.iter().map(|record| record.id).collect();
    let mut folders = HashMap::with_capacity(records.len());
    let mut children = HashMap::with_capacity(records.len());
    let mut nested_galleries = HashSet::new();
    let mut nested_media = HashSet::new();
    let mut aggregate = images.len() + records.len();
    for record in records {
        let entries = vault
            .reader()
            .gallery_children(record.id, 10_000)
            .map_err(|_| RuntimeError::Input)?;
        aggregate = aggregate
            .checked_add(entries.len())
            .filter(|total| *total <= LIMIT)
            .ok_or(RuntimeError::Input)?;
        let mut composed = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry {
                osv_catalog::Child::Gallery(id) => {
                    nested_galleries.insert(id);
                    composed.push(GalleryChild::Gallery(id));
                }
                osv_catalog::Child::Media(id) => {
                    let image = image_by_id.get(&id).copied().ok_or(RuntimeError::Input)?;
                    nested_media.insert(id);
                    composed.push(GalleryChild::Image(image));
                }
            }
        }
        folders.insert(
            record.id,
            GalleryFolder {
                id: record.id,
                name: record.name,
            },
        );
        children.insert(record.id, composed);
    }
    if children
        .values()
        .flatten()
        .any(|entry| matches!(entry, GalleryChild::Gallery(id) if !folders.contains_key(id)))
    {
        return Err(RuntimeError::Input);
    }
    let mut roots: Vec<_> = gallery_order
        .iter()
        .filter(|id| !nested_galleries.contains(id))
        .copied()
        .map(GalleryChild::Gallery)
        .collect();
    roots.extend(
        images
            .into_iter()
            .filter(|image| !nested_media.contains(&image.media_id))
            .map(GalleryChild::Image),
    );
    Ok(GallerySnapshot {
        roots,
        folders,
        children,
    })
}

fn open_thumbnail(
    vault: &VaultService,
    media_id: osv_catalog::MediaId,
    cancelled: &AtomicBool,
) -> Result<OpenedImage, RuntimeError> {
    let record = vault
        .reader()
        .image_records(osv_media::THUMBNAIL_RECIPE_VERSION, 10_000)
        .map_err(|_| RuntimeError::Input)?
        .into_iter()
        .find(|record| record.id == media_id)
        .ok_or(RuntimeError::Input)?;
    let thumbnail = record.thumbnail_object_id.ok_or(RuntimeError::Input)?;
    let decoded = osv_import::decode_image_object_cancellable(
        vault,
        thumbnail,
        &media_worker_path(),
        REQUEST_ID.fetch_add(1, Ordering::Relaxed),
        cancelled,
    )
    .map_err(map_import_error)?;
    Ok(OpenedImage {
        media_id,
        pixels: decoded.pixels,
        width: decoded.width,
        height: decoded.height,
        frames: decoded.frames,
        first_delay_ms: decoded.first_delay_ms,
        additional_frames: decoded.additional_frames,
        lock_status: decoded.lock_status,
    })
}

fn open_viewer(
    vault: &VaultService,
    media_id: osv_catalog::MediaId,
    cancelled: &AtomicBool,
) -> Result<OpenedImage, RuntimeError> {
    let record = vault
        .reader()
        .image_records(osv_media::THUMBNAIL_RECIPE_VERSION, 10_000)
        .map_err(|_| RuntimeError::Input)?
        .into_iter()
        .find(|record| record.id == media_id)
        .ok_or(RuntimeError::Input)?;
    let decoded = osv_import::decode_image_original_view_cancellable(
        vault,
        record.original_object_id,
        &media_worker_path(),
        REQUEST_ID.fetch_add(1, Ordering::Relaxed),
        cancelled,
    )
    .map_err(map_import_error)?;
    Ok(OpenedImage {
        media_id,
        pixels: decoded.pixels,
        width: decoded.width,
        height: decoded.height,
        frames: decoded.frames,
        first_delay_ms: decoded.first_delay_ms,
        additional_frames: decoded.additional_frames,
        lock_status: decoded.lock_status,
    })
}

fn commit_import(
    vault: &mut VaultService,
    mut prepared: osv_import::PreparedImageImport,
    original_name: osv_crypto::SecretString,
    decision: Option<DuplicateDecision>,
) -> Result<Option<ImportedImage>, RuntimeError> {
    if prepared.preview.duplicate == osv_import::DuplicateState::AwaitingDecision {
        let Some(decision) = decision else {
            return Err(RuntimeError::Duplicate);
        };
        if decision == DuplicateDecision::Skip {
            return Ok(None);
        }
        prepared.preview.decide(decision);
    } else if decision.is_some() {
        return Err(RuntimeError::Input);
    }
    let mut id = [0u8; 16];
    SystemRandom
        .fill(&mut id)
        .map_err(|_| RuntimeError::Input)?;
    let media_id = osv_catalog::MediaId::from_bytes(id);
    let imported_at_ms = now_ms().ok_or(RuntimeError::Input)?;
    let committed = prepared
        .commit(vault, media_id, original_name.expose(), imported_at_ms)
        .map_err(map_import_error)?;
    Ok(Some(ImportedImage {
        media_id,
        original: committed.original,
        thumbnail: committed.thumbnail,
        pixels: committed.display_pixels,
        width: committed.display_width,
        height: committed.display_height,
        lock_status: committed.lock_status,
    }))
}

fn now_ms() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

fn map_import_error(error: ImageImportError) -> RuntimeError {
    match error {
        ImageImportError::Cancelled => RuntimeError::Cancelled,
        ImageImportError::DecisionRequired => RuntimeError::Duplicate,
        ImageImportError::Input | ImageImportError::Worker(_) | ImageImportError::Vault(_) => {
            RuntimeError::Input
        }
    }
}

fn media_worker_path() -> PathBuf {
    let installed = Path::new("/app/libexec/osv-media-worker");
    if installed.exists() {
        installed.to_owned()
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|path| {
                let parent = path.parent()?;
                let adjacent = parent.join("osv-media-worker");
                if adjacent.exists() {
                    Some(adjacent)
                } else {
                    parent
                        .parent()
                        .map(|target| target.join("osv-media-worker"))
                }
            })
            .unwrap_or_else(|| PathBuf::from("osv-media-worker"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_import_confirmation_does_not_consume_current_preparation() {
        let first = PreparationId(41);
        let second = PreparationId(42);
        let mut pending = Some((second, "prepared B"));

        assert_eq!(
            take_pending_for(&mut pending, first),
            Err(RuntimeError::Input)
        );
        assert_eq!(pending, Some((second, "prepared B")));
        assert_eq!(take_pending_for(&mut pending, second), Ok("prepared B"));
        assert!(pending.is_none());
    }

    #[test]
    fn memlock_exhaustion_is_visible_in_session_security_state() {
        const CHILD: &str = "OSV_APP_MEMLOCK_STATUS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            #[cfg(target_os = "linux")]
            {
                #[allow(unsafe_code)]
                fn disable_memlock() {
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
                }
                disable_memlock();
            }
            let parent = osv_test_support::TempVault::create_in(Path::new("/tmp")).unwrap();
            let session = VaultSession::begin(
                parent.path().join("degraded-session"),
                b"degraded session password".to_vec(),
                OpenKind::Create,
            );
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(result) = session.try_ready() {
                    result.unwrap();
                    break;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(session.page_locks(), osv_crypto::LockStatus::Degraded);
            session.close();
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("runtime::tests::memlock_exhaustion_is_visible_in_session_security_state")
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "memlock child status: {status:?}");
    }

    #[test]
    fn import_request_keeps_selected_inode_after_path_substitution() {
        use std::io::Read;

        let parent = osv_test_support::TempVault::create_in(Path::new("/tmp")).unwrap();
        let selected = parent.path().join("selected.png");
        let replacement = parent.path().join("replacement.png");
        std::fs::write(&selected, b"selected public fixture").unwrap();
        std::fs::write(&replacement, b"replacement public fixture").unwrap();
        let mut request = ImportRequest {
            source: std::fs::File::open(&selected).unwrap(),
            original_name: osv_crypto::SecretString::new("fixture.png").unwrap(),
        };
        std::fs::rename(&replacement, &selected).unwrap();
        let mut bytes = Vec::new();
        request.source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"selected public fixture");
    }

    #[test]
    fn gallery_snapshot_navigates_empty_deep_and_mixed_levels() {
        let ids: Vec<_> = (0u8..64)
            .map(|byte| osv_catalog::GalleryId::from_bytes([byte; 16]))
            .collect();
        let image = GalleryImage {
            media_id: osv_catalog::MediaId::from_bytes([0x80; 16]),
            width: 8,
            height: 6,
            favorite: true,
            has_thumbnail: true,
        };
        let mut folders = HashMap::new();
        let mut children = HashMap::new();
        for (depth, id) in ids.iter().copied().enumerate() {
            folders.insert(
                id,
                GalleryFolder {
                    id,
                    name: osv_crypto::SecretString::new(&format!("Level {depth}")).unwrap(),
                },
            );
            let level = ids
                .get(depth + 1)
                .copied()
                .map_or_else(Vec::new, |child| vec![GalleryChild::Gallery(child)]);
            children.insert(id, level);
        }
        children
            .get_mut(ids.last().unwrap())
            .unwrap()
            .push(GalleryChild::Image(image));
        let snapshot = GallerySnapshot {
            roots: vec![GalleryChild::Gallery(ids[0]), GalleryChild::Image(image)],
            folders,
            children,
        };
        assert_eq!(snapshot.level(None).len(), 2);
        for (depth, id) in ids.iter().enumerate().take(ids.len() - 1) {
            assert!(
                matches!(snapshot.level(Some(*id)), [GalleryChild::Gallery(next)] if *next == ids[depth + 1])
            );
        }
        assert!(
            matches!(snapshot.level(ids.last().copied()), [GalleryChild::Image(found)] if found == &image)
        );
        assert!(
            snapshot
                .level(Some(osv_catalog::GalleryId::from_bytes([0xff; 16])))
                .is_empty()
        );
    }

    #[test]
    fn background_session_creates_and_cleanly_closes_real_vault() {
        let parent = osv_test_support::TempVault::create_in(Path::new("/tmp")).unwrap();
        let path = parent.path().join("runtime-vault");
        let session = VaultSession::begin(
            path.clone(),
            b"runtime test password".to_vec(),
            OpenKind::Create,
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(result) = session.try_ready() {
                result.unwrap();
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let gallery = session.list_gallery().unwrap().recv().unwrap().unwrap();
        assert!(gallery.roots.is_empty());
        assert!(gallery.folders.is_empty());
        assert_ne!(session.generation(), 0);
        assert_eq!(session.catalog_revision(), 0);
        assert_eq!(session.maintenance_status(), MaintenanceStatus::default());
        session.revoke();
        if let Ok(receiver) = session.list_gallery() {
            assert!(
                receiver
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .is_err()
            );
        }
        session.close();
        let password = Password::new(b"runtime test password").unwrap();
        VaultService::open(&path, &password, None, OpenMode::Writer)
            .unwrap()
            .close()
            .unwrap();
    }
}
