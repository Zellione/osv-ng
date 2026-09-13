//! Serial background ownership for an unlocked production vault session.

use std::{
    collections::VecDeque,
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
    pub source_path: PathBuf,
    pub original_name: String,
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
    pub thumbnail: osv_storage::ObjectId,
    pub pixels: osv_crypto::SecretBytes,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GalleryImage {
    pub media_id: osv_catalog::MediaId,
    pub width: u32,
    pub height: u32,
    pub favorite: bool,
    pub has_thumbnail: bool,
}

pub struct OpenedImage {
    pub media_id: osv_catalog::MediaId,
    pub pixels: osv_crypto::SecretBytes,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub first_delay_ms: u32,
    pub additional_frames: Vec<osv_import::DecodedFrame>,
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
    ListImages {
        response: mpsc::Sender<Result<Vec<GalleryImage>, RuntimeError>>,
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
        request: ImportRequest,
        response: mpsc::Sender<Result<ImportPreview, RuntimeError>>,
    },
    CommitImport {
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
                    let result = osv_import::regenerate_image_thumbnail_cancellable(
                        &mut vault,
                        target,
                        &media_worker_path(),
                        REQUEST_ID.fetch_add(1, Ordering::Relaxed),
                        now_ms().unwrap_or(0),
                        Some(&worker_cancelled),
                    );
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
                match command {
                    Command::ListImages { response } => {
                        let result = list_images(&vault);
                        let _ = response.send(result);
                    }
                    Command::OpenThumbnail { media_id, response } => {
                        let result = open_thumbnail(&vault, media_id, &worker_cancelled);
                        let _ = response.send(result);
                    }
                    Command::OpenViewer { media_id, response } => {
                        let result = open_viewer(&vault, media_id, &worker_cancelled);
                        let _ = response.send(result);
                    }
                    Command::PrepareImport { request, response } => {
                        pending = None;
                        match prepare_import(&vault, request, &worker_cancelled) {
                            Ok((prepared, original_name, preview)) => {
                                pending = Some((prepared, original_name));
                                let _ = response.send(Ok(preview));
                            }
                            Err(error) => {
                                let _ = response.send(Err(error));
                            }
                        }
                    }
                    Command::CommitImport { decision, response } => {
                        let result = pending.take().ok_or(RuntimeError::Input).and_then(
                            |(prepared, name)| commit_import(&mut vault, prepared, name, decision),
                        );
                        if matches!(result, Ok(Some(_))) {
                            worker_catalog_revision.fetch_add(1, Ordering::Release);
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
    ) -> Result<mpsc::Receiver<Result<ImportPreview, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::PrepareImport { request, response })
            .map_err(|_| RuntimeError::Closed)?;
        Ok(receiver)
    }

    pub fn list_images(
        &self,
    ) -> Result<mpsc::Receiver<Result<Vec<GalleryImage>, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::ListImages { response })
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
        decision: Option<DuplicateDecision>,
    ) -> Result<mpsc::Receiver<Result<Option<ImportedImage>, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::CommitImport { decision, response })
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
) -> Result<(osv_import::PreparedImageImport, String, ImportPreview), RuntimeError> {
    let worker = media_worker_path();
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let mut source = std::fs::File::open(&request.source_path).map_err(|_| RuntimeError::Input)?;
    let logical_len = source.metadata().map_err(|_| RuntimeError::Input)?.len();
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

fn list_images(vault: &VaultService) -> Result<Vec<GalleryImage>, RuntimeError> {
    vault
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
    })
}

fn commit_import(
    vault: &mut VaultService,
    mut prepared: osv_import::PreparedImageImport,
    original_name: String,
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
        .commit(vault, media_id, &original_name, imported_at_ms)
        .map_err(map_import_error)?;
    Ok(Some(ImportedImage {
        media_id,
        original: committed.original,
        thumbnail: committed.thumbnail,
        pixels: committed.display_pixels,
        width: committed.display_width,
        height: committed.display_height,
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
            .and_then(|path| path.parent().map(|parent| parent.join("osv-media-worker")))
            .unwrap_or_else(|| PathBuf::from("osv-media-worker"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let images = session.list_images().unwrap().recv().unwrap().unwrap();
        assert!(images.is_empty());
        assert_ne!(session.generation(), 0);
        assert_eq!(session.catalog_revision(), 0);
        assert_eq!(session.maintenance_status(), MaintenanceStatus::default());
        session.revoke();
        if let Ok(receiver) = session.list_images() {
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
