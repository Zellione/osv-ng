//! Serial background ownership for an unlocked production vault session.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use osv_crypto::{KdfParams, Password, RandomSource, SystemRandom};
use osv_import::{DuplicateDecision, ImageImportError};
use osv_vault::{OpenMode, VaultService};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

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
    commands: mpsc::Sender<Command>,
    ready: mpsc::Receiver<Result<(), RuntimeError>>,
    cancelled: Arc<AtomicBool>,
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
        let (commands, command_rx) = mpsc::channel();
        let (ready_tx, ready) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
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
            while let Ok(command) = command_rx.recv() {
                match command {
                    Command::PrepareImport { request, response } => {
                        worker_cancelled.store(false, Ordering::Release);
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
                        let _ = response.send(result);
                    }
                    Command::Close => break,
                }
            }
            let _ = vault.close();
        });
        Self {
            commands,
            ready,
            cancelled,
            thread: Some(thread),
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
    ) -> Result<mpsc::Receiver<Result<ImportPreview, RuntimeError>>, RuntimeError> {
        let (response, receiver) = mpsc::channel();
        self.commands
            .send(Command::PrepareImport { request, response })
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
    let imported_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .ok_or(RuntimeError::Input)?;
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
        session.close();
        let password = Password::new(b"runtime test password").unwrap();
        VaultService::open(&path, &password, None, OpenMode::Writer)
            .unwrap()
            .close()
            .unwrap();
    }
}
