use osv_isolation::{ExitClass, PlaintextBuffer, SupervisorLimits};
use std::io::Read;

fn valid_png() -> Vec<u8> {
    use image::ImageEncoder;
    let image = image::RgbaImage::from_pixel(2, 3, image::Rgba([0x33, 0x66, 0x99, 0xff]));
    let mut encoded = Vec::new();
    image::codecs::png::PngEncoder::new(&mut encoded)
        .write_image(image.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
        .unwrap();
    encoded
}

fn animated_gif() -> Vec<u8> {
    let frames = [
        image::Frame::from_parts(
            image::RgbaImage::from_pixel(3, 2, image::Rgba([1, 2, 3, 255])),
            0,
            0,
            image::Delay::from_numer_denom_ms(20, 1),
        ),
        image::Frame::from_parts(
            image::RgbaImage::from_pixel(3, 2, image::Rgba([4, 5, 6, 255])),
            0,
            0,
            image::Delay::from_numer_denom_ms(50, 1),
        ),
    ];
    let mut encoded = Vec::new();
    image::codecs::gif::GifEncoder::new(&mut encoded)
        .encode_frames(frames)
        .unwrap();
    encoded
}

#[test]
fn media_worker_completes_a_bounded_stream_under_sandbox() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 41, SupervisorLimits::default()).unwrap();
    assert_ne!(worker.sandbox_flags() & osv_isolation::SECCOMP, 0);
    let image = valid_png();
    let request = osv_media::encode_worker_request(
        osv_media::ImagePurpose::Thumbnail,
        osv_media::THUMBNAIL_EDGE,
    )
    .unwrap();
    let mut request_buffer = PlaintextBuffer::zeroed(request.len()).unwrap();
    request_buffer.as_mut_slice().copy_from_slice(&request);
    worker.send_authenticated(0, request_buffer).unwrap();
    let mut plaintext = PlaintextBuffer::zeroed(image.len()).unwrap();
    plaintext.as_mut_slice().copy_from_slice(&image);
    worker.send_authenticated(1, plaintext).unwrap();
    let (class, output) = worker
        .finish_with_output(osv_media::MAX_THUMBNAIL_RESULT_BYTES)
        .unwrap();
    assert_eq!(class, ExitClass::Success, "{:?}", output.failure_class());
    assert!(output.logical_len() > osv_media::WORKER_RESULT_HEADER_LEN);
    let first = output.chunks().next().unwrap();
    let probe = osv_media::decode_worker_result_header(first).unwrap();
    assert_eq!((probe.source.width, probe.source.height), (2, 3));
    assert_eq!((probe.thumbnail_width, probe.thumbnail_height), (2, 3));
}

#[test]
fn media_worker_streams_bounded_animation_frames() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 44, SupervisorLimits::default()).unwrap();
    let request = osv_media::encode_worker_request(osv_media::ImagePurpose::Viewer, 512).unwrap();
    let mut request_buffer = PlaintextBuffer::zeroed(request.len()).unwrap();
    request_buffer.as_mut_slice().copy_from_slice(&request);
    worker.send_authenticated(0, request_buffer).unwrap();
    let animation = animated_gif();
    let mut input = PlaintextBuffer::zeroed(animation.len()).unwrap();
    input.as_mut_slice().copy_from_slice(&animation);
    worker.send_authenticated(1, input).unwrap();
    let (class, output) = worker
        .finish_with_output(osv_media::MAX_VIEWER_RESULT_BYTES)
        .unwrap();
    assert_eq!(class, ExitClass::Success);
    let header = osv_media::decode_worker_result_header(output.chunks().next().unwrap()).unwrap();
    assert_eq!(header.output_frames, 2);
    assert_eq!(header.first_delay_ms, 20);
    assert_eq!(header.additional_frames_len, 28);
    assert_eq!(
        output.logical_len(),
        osv_media::WORKER_RESULT_HEADER_LEN
            + header.thumbnail_png_len as usize
            + header.rgba_len as usize
            + header.additional_frames_len as usize
    );
}

#[test]
fn media_worker_releases_authority_on_cancellation() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 42, SupervisorLimits::default()).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        worker.cancel(),
        ExitClass::Success | ExitClass::Deadline
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn media_worker_rejects_malformed_authenticated_input() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 43, SupervisorLimits::default()).unwrap();
    let mut plaintext = PlaintextBuffer::zeroed(3).unwrap();
    plaintext.as_mut_slice().copy_from_slice(b"bad");
    worker.send_authenticated(0, plaintext).unwrap();
    assert_eq!(worker.finish().unwrap(), ExitClass::WorkerFailure);
}

#[test]
fn missing_thumbnail_regenerates_without_replacing_the_original() {
    let parent = osv_test_support::TempVault::create_in(std::path::Path::new("/tmp")).unwrap();
    let path = parent.path().join("image-regeneration");
    let password = osv_crypto::Password::new(b"phase nine regeneration password").unwrap();
    let mut vault = osv_vault::VaultService::create(
        &path,
        &password,
        None,
        osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
        1,
    )
    .unwrap();
    let image = valid_png();
    let media_id = osv_catalog::MediaId::from_bytes([0x73; 16]);
    let fingerprint = [0x91; 32];
    let mut reader = std::io::Cursor::new(&image);
    let original = vault
        .import(
            &mut reader,
            u64::try_from(image.len()).unwrap(),
            osv_vault::ImportMetadata {
                id: media_id,
                original_name: "regenerate.png",
                class: osv_catalog::MediaClass::Image,
                mime: "image/png",
                width: Some(2),
                height: Some(3),
                duration_ms: None,
                codecs: "png",
                imported_at_ms: 1,
                fingerprint: &fingerprint,
            },
        )
        .unwrap();
    let pending = vault
        .reader()
        .derived_needing_recipe(
            osv_storage::ObjectRole::Thumbnail,
            osv_media::THUMBNAIL_RECIPE_VERSION,
            10,
        )
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].original_object_id, original);
    assert!(
        osv_import::regenerate_image_thumbnail(
            &mut vault,
            pending[0],
            std::path::Path::new("/definitely/not/a/worker"),
            73,
            2,
        )
        .is_err()
    );
    assert!(vault.reader().object(original).is_ok());
    let thumbnail = osv_import::regenerate_image_thumbnail(
        &mut vault,
        pending[0],
        std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker")),
        74,
        2,
    )
    .unwrap();
    assert!(vault.reader().object(original).is_ok());
    assert!(vault.reader().object(thumbnail).is_ok());
    assert!(
        vault
            .reader()
            .derived_needing_recipe(
                osv_storage::ObjectRole::Thumbnail,
                osv_media::THUMBNAIL_RECIPE_VERSION,
                10,
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cancelled_regeneration_preserves_original_and_prior_thumbnail() {
    let parent = osv_test_support::TempVault::create_in(std::path::Path::new("/tmp")).unwrap();
    let password = osv_crypto::Password::new(b"cancel regeneration password").unwrap();
    let mut vault = osv_vault::VaultService::create(
        &parent.path().join("cancel-regeneration"),
        &password,
        None,
        osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
        1,
    )
    .unwrap();
    let image = valid_png();
    let media_id = osv_catalog::MediaId::from_bytes([0x74; 16]);
    let mut source = std::io::Cursor::new(&image);
    let original = vault
        .import(
            &mut source,
            image.len() as u64,
            osv_vault::ImportMetadata {
                id: media_id,
                original_name: "cancel.png",
                class: osv_catalog::MediaClass::Image,
                mime: "image/png",
                width: Some(2),
                height: Some(3),
                duration_ms: None,
                codecs: "png",
                imported_at_ms: 1,
                fingerprint: &[0x92; 32],
            },
        )
        .unwrap();
    let mut prior_source = std::io::Cursor::new(&image);
    let prior = vault
        .replace_derived(
            &mut prior_source,
            image.len() as u64,
            media_id,
            osv_storage::ObjectRole::Thumbnail,
            osv_media::THUMBNAIL_RECIPE_VERSION,
            2,
            3,
            2,
        )
        .unwrap();
    let target = osv_catalog::DerivedRegeneration {
        media_id,
        original_object_id: original,
    };
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(matches!(
        osv_import::regenerate_image_thumbnail_cancellable(
            &mut vault,
            target,
            std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker")),
            75,
            3,
            Some(&cancelled),
        ),
        Err(osv_import::ImageImportError::Cancelled)
    ));
    assert!(vault.reader().object(original).is_ok());
    assert!(vault.reader().object(prior).is_ok());
}

#[test]
fn runtime_close_during_active_regeneration_revokes_and_reopens_cleanly() {
    use image::ImageEncoder;

    let parent = osv_test_support::TempVault::create_in(std::path::Path::new("/tmp")).unwrap();
    let path = parent.path().join("runtime-close-regeneration");
    let password_bytes = b"runtime close regeneration password";
    let password = osv_crypto::Password::new(password_bytes).unwrap();
    let mut vault = osv_vault::VaultService::create(
        &path,
        &password,
        None,
        osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
        1,
    )
    .unwrap();
    let dimensions = 4096u32;
    let pixels = vec![0x5a; dimensions as usize * dimensions as usize * 4];
    let mut encoded = Vec::new();
    image::codecs::png::PngEncoder::new(&mut encoded)
        .write_image(
            &pixels,
            dimensions,
            dimensions,
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    let media_id = osv_catalog::MediaId::from_bytes([0x75; 16]);
    vault
        .import(
            &mut std::io::Cursor::new(&encoded),
            encoded.len() as u64,
            osv_vault::ImportMetadata {
                id: media_id,
                original_name: "runtime-close.png",
                class: osv_catalog::MediaClass::Image,
                mime: "image/png",
                width: Some(dimensions),
                height: Some(dimensions),
                duration_ms: None,
                codecs: "png",
                imported_at_ms: 1,
                fingerprint: &[0x93; 32],
            },
        )
        .unwrap();
    vault.close().unwrap();

    let session = osv_app::runtime::VaultSession::begin(
        path.clone(),
        password_bytes.to_vec(),
        osv_app::runtime::OpenKind::Unlock,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(ready) = session.try_ready() {
            ready.unwrap();
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "session did not unlock"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    loop {
        if session.maintenance_status().running {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "regeneration did not become active"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let close_started = std::time::Instant::now();
    session.close();
    assert!(close_started.elapsed() < std::time::Duration::from_secs(2));

    let reopened = osv_vault::VaultService::open(
        &path,
        &osv_crypto::Password::new(password_bytes).unwrap(),
        None,
        osv_vault::OpenMode::Writer,
    )
    .unwrap();
    assert!(reopened.reader().operation_journal().unwrap().is_empty());
    assert_eq!(reopened.reader().image_records(1, 10).unwrap().len(), 1);
    reopened.close().unwrap();
}

#[test]
fn import_publishes_encrypted_original_and_thumbnail_without_plaintext_artifacts() {
    let parent = osv_test_support::TempVault::create_in(std::path::Path::new("/tmp")).unwrap();
    let path = parent.path().join("image-import");
    let password = osv_crypto::Password::new(b"phase nine test password").unwrap();
    let mut vault = osv_vault::VaultService::create(
        &path,
        &password,
        None,
        osv_crypto::KdfParams::new(8, 1, 1).unwrap(),
        1,
    )
    .unwrap();
    let source = valid_png();
    let mut cursor = std::io::Cursor::new(&source);
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let prepared = osv_import::prepare_image_import(
        &mut cursor,
        source.len() as u64,
        executable,
        99,
        &vault.reader(),
    )
    .unwrap();
    let committed = prepared
        .commit(
            &mut vault,
            osv_catalog::MediaId::from_bytes([0x91; 16]),
            "sensitive-name.png",
            2,
        )
        .unwrap();
    let mut original = Vec::new();
    vault
        .open_object(committed.original)
        .unwrap()
        .read_to_end(&mut original)
        .unwrap();
    assert_eq!(original, source);
    let mut thumbnail = Vec::new();
    vault
        .open_object(committed.thumbnail)
        .unwrap()
        .read_to_end(&mut thumbnail)
        .unwrap();
    assert!(thumbnail.starts_with(b"\x89PNG\r\n\x1a\n"));
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let reopened = osv_import::decode_image_object_cancellable(
        &vault,
        committed.thumbnail,
        executable,
        101,
        &cancelled,
    )
    .unwrap();
    assert_eq!(
        (reopened.width, reopened.height, reopened.frames),
        (2, 3, 1)
    );
    assert_eq!(reopened.pixels.len(), 2 * 3 * 4);
    let viewer = osv_import::decode_image_original_view_cancellable(
        &vault,
        committed.original,
        executable,
        102,
        &cancelled,
    )
    .unwrap();
    assert_eq!((viewer.width, viewer.height), (2, 3));
    assert_eq!(viewer.pixels.len(), 2 * 3 * 4);
    for entry in walk_files(&path) {
        let artifact = std::fs::read(entry).unwrap();
        assert!(
            !artifact
                .windows(source.len())
                .any(|window| window == source)
        );
        assert!(
            !artifact
                .windows(18)
                .any(|window| window == b"sensitive-name.png")
        );
    }
    let mut duplicate_source = std::io::Cursor::new(&source);
    let mut duplicate = osv_import::prepare_image_import(
        &mut duplicate_source,
        source.len() as u64,
        executable,
        100,
        &vault.reader(),
    )
    .unwrap();
    assert_eq!(
        duplicate.preview.duplicate,
        osv_import::DuplicateState::AwaitingDecision
    );
    duplicate
        .preview
        .decide(osv_import::DuplicateDecision::Skip);
    assert!(matches!(
        duplicate.commit(
            &mut vault,
            osv_catalog::MediaId::from_bytes([0x92; 16]),
            "second-sensitive-name.png",
            3,
        ),
        Err(osv_import::ImageImportError::DecisionRequired)
    ));
}

fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                files.push(entry.path());
            }
        }
    }
    files
}
