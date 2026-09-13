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

#[test]
fn media_worker_completes_a_bounded_stream_under_sandbox() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_osv-media-worker"));
    let mut worker = osv_media::spawn_worker(executable, 41, SupervisorLimits::default()).unwrap();
    assert_ne!(worker.sandbox_flags() & osv_isolation::SECCOMP, 0);
    let image = valid_png();
    let mut plaintext = PlaintextBuffer::zeroed(image.len()).unwrap();
    plaintext.as_mut_slice().copy_from_slice(&image);
    worker.send_authenticated(0, plaintext).unwrap();
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
