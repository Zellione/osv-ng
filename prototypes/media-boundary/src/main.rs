use std::{
    env,
    error::Error,
    fs,
    io::{self, BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;
use nix::{
    sys::{
        prctl,
        resource::{Resource, rlim_t, setrlimit},
    },
    unistd,
};

const CHUNK_BYTES: usize = 256 * 1024;
const TAG_BYTES: usize = 16;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MSG_CHUNK_REQUEST: u8 = 1;
const MSG_FRAME: u8 = 2;
const MSG_DONE: u8 = 3;
const MSG_CHUNK_RESPONSE: u8 = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundaryMode {
    ObjectKey,
    Broker,
}

impl BoundaryMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "object-key" => Ok(Self::ObjectKey),
            "broker" => Ok(Self::Broker),
            _ => Err("--mode requires object-key or broker".to_owned()),
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::ObjectKey => 1,
            Self::Broker => 2,
        }
    }
}

#[derive(Debug)]
struct Config {
    input: PathBuf,
    mode: BoundaryMode,
    run_seconds: u64,
    exercise_restart: bool,
    real_audio: bool,
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut input = None;
        let mut mode = None;
        let mut run_seconds = 10;
        let mut exercise_restart = false;
        let mut real_audio = false;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--input" => {
                    input = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--input requires a path".to_owned())?,
                    ));
                }
                "--mode" => {
                    mode = Some(BoundaryMode::parse(
                        &args
                            .next()
                            .ok_or_else(|| "--mode requires a value".to_owned())?,
                    )?);
                }
                "--run-seconds" => {
                    run_seconds = args
                        .next()
                        .ok_or_else(|| "--run-seconds requires an integer".to_owned())?
                        .parse()
                        .map_err(|_| "--run-seconds must be an integer".to_owned())?;
                    if !(2..=300).contains(&run_seconds) {
                        return Err("--run-seconds must be between 2 and 300".to_owned());
                    }
                }
                "--exercise-restart" => exercise_restart = true,
                "--real-audio" => real_audio = true,
                "--help" | "-h" => return Ok(None),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }
        Ok(Some(Self {
            input: input.ok_or_else(|| "--input is required".to_owned())?,
            mode: mode.ok_or_else(|| "--mode is required".to_owned())?,
            run_seconds,
            exercise_restart,
            real_audio,
        }))
    }
}

struct EncryptedObject {
    logical_length: u64,
    chunks: Vec<Vec<u8>>,
    key: [u8; 32],
}

#[derive(Default)]
struct WorkerReport {
    success: bool,
    source_requests: u64,
    source_bytes_sent: u64,
    frames: u64,
    frame_bytes: u64,
    elapsed: Duration,
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let result = if arguments
        .get(1)
        .is_some_and(|argument| argument == "--worker")
    {
        worker_main(&arguments[2..])
    } else {
        supervisor_main(arguments)
    };
    if let Err(error) = result {
        eprintln!("media-boundary prototype failed: {error}");
        std::process::exit(1);
    }
}

fn supervisor_main(arguments: Vec<String>) -> Result<(), Box<dyn Error>> {
    let config = match Config::from_args(arguments) {
        Ok(Some(config)) => config,
        Ok(None) => {
            print_help();
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let plaintext = fs::read(&config.input)?;
    if plaintext.is_empty() {
        return Err("input is empty".into());
    }
    let object = encrypt_object(&plaintext)?;

    if config.exercise_restart {
        let crashed = supervise_worker(&object, &config, Some(0))?;
        if crashed.success {
            return Err("fault-injected worker unexpectedly succeeded".into());
        }
        println!("worker_crash_detected=true restart=true");
    }

    let report = supervise_worker(&object, &config, None)?;
    if !report.success {
        return Err("worker failed after restart".into());
    }
    println!(
        "mode={:?} source_requests={} source_bytes_sent={} frames={} frame_bytes={} elapsed_ms={:.2}",
        config.mode,
        report.source_requests,
        report.source_bytes_sent,
        report.frames,
        report.frame_bytes,
        report.elapsed.as_secs_f64() * 1_000.0
    );
    Ok(())
}

fn print_help() {
    println!(
        "Usage: osv-media-boundary-prototype --input FILE \\\n+         --mode object-key|broker [--run-seconds N] [--exercise-restart] \\\n+         [--real-audio]"
    );
}

fn encrypt_object(plaintext: &[u8]) -> Result<EncryptedObject, Box<dyn Error>> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let chunk_count = plaintext.len().div_ceil(CHUNK_BYTES);
    let mut chunks = Vec::with_capacity(chunk_count);
    for (index, chunk) in plaintext.chunks(CHUNK_BYTES).enumerate() {
        let nonce = chunk_nonce(index)?;
        let aad = chunk_aad(index, chunk_count)?;
        chunks.push(cipher.encrypt(
            &nonce,
            Payload {
                msg: chunk,
                aad: &aad,
            },
        )?);
    }
    Ok(EncryptedObject {
        logical_length: plaintext.len() as u64,
        chunks,
        key,
    })
}

fn chunk_nonce(index: usize) -> Result<XNonce, Box<dyn Error>> {
    let index = u64::try_from(index)?;
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(b"osv-phase1-chunk");
    nonce[16..].copy_from_slice(&index.to_le_bytes());
    Ok(XNonce::from(nonce))
}

fn chunk_aad(index: usize, count: usize) -> Result<[u8; 24], Box<dyn Error>> {
    let mut aad = [0_u8; 24];
    aad[..8].copy_from_slice(b"OSVP1IPC");
    aad[8..16].copy_from_slice(&u64::try_from(index)?.to_le_bytes());
    aad[16..].copy_from_slice(&u64::try_from(count)?.to_le_bytes());
    Ok(aad)
}

fn supervise_worker(
    object: &EncryptedObject,
    config: &Config,
    crash_after: Option<u64>,
) -> Result<WorkerReport, Box<dyn Error>> {
    let mut child = spawn_worker(config, crash_after)?;
    let mut writer = BufWriter::new(child.stdin.take().ok_or("worker stdin unavailable")?);
    let mut reader = BufReader::new(child.stdout.take().ok_or("worker stdout unavailable")?);
    write_init(&mut writer, object, config)?;

    let started = Instant::now();
    let mut report = WorkerReport::default();
    loop {
        let mut kind = [0_u8; 1];
        match reader.read_exact(&mut kind) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        }
        match kind[0] {
            MSG_CHUNK_REQUEST => {
                let index = read_u32(&mut reader)? as usize;
                let data = match config.mode {
                    BoundaryMode::ObjectKey => {
                        object.chunks.get(index).ok_or("bad chunk request")?.clone()
                    }
                    BoundaryMode::Broker => decrypt_chunk(object, index)?,
                };
                writer.write_all(&[MSG_CHUNK_RESPONSE])?;
                write_u32(&mut writer, u32::try_from(data.len())?)?;
                writer.write_all(&data)?;
                writer.flush()?;
                report.source_requests += 1;
                report.source_bytes_sent += u64::try_from(data.len())?;
            }
            MSG_FRAME => {
                let length = read_u32(&mut reader)? as usize;
                if length > MAX_FRAME_BYTES {
                    return Err("worker frame exceeds protocol limit".into());
                }
                let mut frame = vec![0_u8; length];
                reader.read_exact(&mut frame)?;
                report.frames += 1;
                report.frame_bytes += u64::try_from(length)?;
            }
            MSG_DONE => break,
            unknown => return Err(format!("unknown worker message: {unknown}").into()),
        }
    }
    drop(writer);
    let status = child.wait()?;
    report.elapsed = started.elapsed();
    report.success = status.success();
    if !status.success() {
        eprintln!("worker exited with {status}");
        return Ok(report);
    }
    if crash_after.is_some() {
        return Err("fault-injected worker exited successfully".into());
    }
    Ok(report)
}

fn spawn_worker(config: &Config, crash_after: Option<u64>) -> Result<Child, Box<dyn Error>> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--worker")
        .arg("--mode")
        .arg(match config.mode {
            BoundaryMode::ObjectKey => "object-key",
            BoundaryMode::Broker => "broker",
        })
        .arg("--run-seconds")
        .arg(config.run_seconds.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if config.real_audio {
        command.arg("--real-audio");
    }
    if let Some(requests) = crash_after {
        command
            .arg("--crash-after-requests")
            .arg(requests.to_string());
    }
    Ok(command.spawn()?)
}

fn write_init(
    writer: &mut BufWriter<ChildStdin>,
    object: &EncryptedObject,
    config: &Config,
) -> Result<(), Box<dyn Error>> {
    writer.write_all(b"OSVP1IPC")?;
    writer.write_all(&[config.mode.wire()])?;
    write_u64(writer, object.logical_length)?;
    write_u32(writer, u32::try_from(CHUNK_BYTES)?)?;
    write_u32(writer, u32::try_from(object.chunks.len())?)?;
    if config.mode == BoundaryMode::ObjectKey {
        writer.write_all(&object.key)?;
    }
    writer.flush()?;
    Ok(())
}

fn decrypt_chunk(object: &EncryptedObject, index: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&object.key)?;
    let nonce = chunk_nonce(index)?;
    let aad = chunk_aad(index, object.chunks.len())?;
    Ok(cipher.decrypt(
        &nonce,
        Payload {
            msg: object.chunks.get(index).ok_or("chunk index out of range")?,
            aad: &aad,
        },
    )?)
}

struct WorkerConfig {
    mode: BoundaryMode,
    run_seconds: u64,
    crash_after_requests: Option<u64>,
    real_audio: bool,
}

fn worker_main(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let config = parse_worker_args(arguments)?;
    apply_worker_hardening()?;
    let reader = Arc::new(Mutex::new(BufReader::new(io::stdin())));
    let writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    let init = read_init(&reader, config.mode)?;
    run_worker_pipeline(&config, init, reader, writer)
}

fn parse_worker_args(arguments: &[String]) -> Result<WorkerConfig, Box<dyn Error>> {
    let mut mode = None;
    let mut run_seconds = 10;
    let mut crash_after_requests = None;
    let mut real_audio = false;
    let mut args = arguments.iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--mode" => mode = Some(BoundaryMode::parse(args.next().ok_or("missing mode")?)?),
            "--run-seconds" => run_seconds = args.next().ok_or("missing run time")?.parse()?,
            "--crash-after-requests" => {
                crash_after_requests = Some(args.next().ok_or("missing crash count")?.parse()?);
            }
            "--real-audio" => real_audio = true,
            unknown => return Err(format!("unknown worker argument: {unknown}").into()),
        }
    }
    Ok(WorkerConfig {
        mode: mode.ok_or("worker mode is required")?,
        run_seconds,
        crash_after_requests,
        real_audio,
    })
}

fn apply_worker_hardening() -> Result<(), Box<dyn Error>> {
    prctl::set_no_new_privs()?;
    prctl::set_dumpable(false)?;
    setrlimit(Resource::RLIMIT_CORE, 0 as rlim_t, 0 as rlim_t)?;
    setrlimit(Resource::RLIMIT_NOFILE, 32 as rlim_t, 32 as rlim_t)?;
    let memory_limit = 768_u64 * 1024 * 1024;
    setrlimit(
        Resource::RLIMIT_AS,
        memory_limit as rlim_t,
        memory_limit as rlim_t,
    )?;
    eprintln!(
        "worker_hardening=no_new_privs,dump_disabled,core_zero,nofile_32,address_space_768MiB uid={} pid={}",
        unistd::getuid(),
        unistd::getpid()
    );
    Ok(())
}

#[derive(Debug)]
struct WorkerInit {
    logical_length: u64,
    chunk_size: usize,
    chunk_count: usize,
    key: Option<[u8; 32]>,
}

fn read_init(
    reader: &Arc<Mutex<BufReader<io::Stdin>>>,
    expected_mode: BoundaryMode,
) -> Result<WorkerInit, Box<dyn Error>> {
    let mut reader = reader.lock().map_err(|_| "reader poisoned")?;
    parse_worker_init(&mut *reader, expected_mode)
}

fn parse_worker_init(
    reader: &mut impl Read,
    expected_mode: BoundaryMode,
) -> Result<WorkerInit, Box<dyn Error>> {
    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != b"OSVP1IPC" {
        return Err("invalid IPC magic".into());
    }
    let mut mode = [0_u8; 1];
    reader.read_exact(&mut mode)?;
    if mode[0] != expected_mode.wire() {
        return Err("IPC boundary mode mismatch".into());
    }
    let logical_length = read_u64(reader)?;
    let chunk_size = read_u32(reader)? as usize;
    let chunk_count = read_u32(reader)? as usize;
    validate_object_bounds(logical_length, chunk_size, chunk_count)?;
    let key = if expected_mode == BoundaryMode::ObjectKey {
        let mut key = [0_u8; 32];
        reader.read_exact(&mut key)?;
        Some(key)
    } else {
        None
    };
    Ok(WorkerInit {
        logical_length,
        chunk_size,
        chunk_count,
        key,
    })
}

fn validate_object_bounds(
    logical_length: u64,
    chunk_size: usize,
    chunk_count: usize,
) -> Result<(), Box<dyn Error>> {
    if chunk_size == 0 || chunk_size > CHUNK_BYTES || chunk_count == 0 {
        return Err("invalid IPC object bounds".into());
    }
    let capacity = u64::try_from(chunk_size)?
        .checked_mul(u64::try_from(chunk_count)?)
        .ok_or("IPC object capacity overflow")?;
    let minimum = capacity.saturating_sub(u64::try_from(chunk_size)?);
    if logical_length == 0 || logical_length > capacity || logical_length <= minimum {
        return Err("IPC logical length does not match chunk framing".into());
    }
    Ok(())
}

struct SourceCursor {
    offset: u64,
    requests: u64,
    cached: Option<(usize, Vec<u8>)>,
}

fn run_worker_pipeline(
    config: &WorkerConfig,
    init: WorkerInit,
    reader: Arc<Mutex<BufReader<io::Stdin>>>,
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
) -> Result<(), Box<dyn Error>> {
    gst::init()?;
    let pipeline = gst::Pipeline::new();
    let source = gst::ElementFactory::make("appsrc").build()?;
    let source = source
        .downcast::<gst_app::AppSrc>()
        .map_err(|_| "appsrc type mismatch")?;
    source.set_stream_type(gst_app::AppStreamType::RandomAccess);
    source.set_format(gst::Format::Bytes);
    source.set_size(i64::try_from(init.logical_length)?);
    source.set_max_bytes(2 * 1024 * 1024);
    source.set_block(true);
    install_worker_source_callbacks(&source, config, &init, reader, Arc::clone(&writer));

    let decode = gst::ElementFactory::make("decodebin3").build()?;
    let video_queue = make_queue("video", 3)?;
    let video_convert = gst::ElementFactory::make("videoconvert").build()?;
    let video_caps = gst::Caps::builder("video/x-raw")
        .field("format", "RGBA")
        .build();
    let video_sink = gst::ElementFactory::make("appsink")
        .property("caps", &video_caps)
        .property("max-buffers", 2_u32)
        .property("drop", false)
        .property("sync", true)
        .build()?;
    let video_sink = video_sink
        .downcast::<gst_app::AppSink>()
        .map_err(|_| "appsink type mismatch")?;
    install_frame_transport(&video_sink, Arc::clone(&writer));

    let audio_queue = make_queue("audio", 16)?;
    let audio_convert = gst::ElementFactory::make("audioconvert").build()?;
    let audio_sink_name = if config.real_audio {
        "pipewiresink"
    } else {
        "fakesink"
    };
    let audio_sink = gst::ElementFactory::make(audio_sink_name)
        .property("sync", true)
        .build()?;
    pipeline.add_many([
        source.upcast_ref(),
        &decode,
        &video_queue,
        &video_convert,
        video_sink.upcast_ref(),
        &audio_queue,
        &audio_convert,
        &audio_sink,
    ])?;
    source.link(&decode)?;
    gst::Element::link_many([&video_queue, &video_convert, video_sink.upcast_ref()])?;
    gst::Element::link_many([&audio_queue, &audio_convert, &audio_sink])?;
    connect_worker_decode_pads(&decode, &video_queue, &audio_queue);

    pipeline.set_state(gst::State::Playing)?;
    let result = drive_worker(&pipeline, config.run_seconds);
    pipeline.set_state(gst::State::Null)?;
    if result.is_ok() {
        let mut writer = writer.lock().map_err(|_| "writer poisoned")?;
        writer.write_all(&[MSG_DONE])?;
        writer.flush()?;
    }
    result
}

fn make_queue(name: &str, buffers: u32) -> Result<gst::Element, Box<dyn Error>> {
    Ok(gst::ElementFactory::make("queue")
        .name(format!("{name}-queue"))
        .property("max-size-buffers", buffers)
        .property("max-size-bytes", 0_u32)
        .property("max-size-time", 0_u64)
        .build()?)
}

fn install_worker_source_callbacks(
    source: &gst_app::AppSrc,
    config: &WorkerConfig,
    init: &WorkerInit,
    reader: Arc<Mutex<BufReader<io::Stdin>>>,
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
) {
    let cursor = Arc::new(Mutex::new(SourceCursor {
        offset: 0,
        requests: 0,
        cached: None,
    }));
    let read_cursor = Arc::clone(&cursor);
    let seek_cursor = Arc::clone(&cursor);
    let mode = config.mode;
    let crash_after = config.crash_after_requests;
    let chunk_size = init.chunk_size;
    let chunk_count = init.chunk_count;
    let key = init.key;
    source.set_callbacks(
        gst_app::AppSrcCallbacks::builder()
            .need_data(move |source, requested| {
                let result = worker_read(
                    mode,
                    key.as_ref(),
                    chunk_size,
                    chunk_count,
                    requested,
                    crash_after,
                    &read_cursor,
                    &reader,
                    &writer,
                );
                match result {
                    Ok(Some(buffer)) => {
                        let _ = source.push_buffer(gst::Buffer::from_mut_slice(buffer));
                    }
                    Ok(None) => {
                        let _ = source.end_of_stream();
                    }
                    Err(error) => {
                        eprintln!("worker source error: {error}");
                        let _ = source.end_of_stream();
                    }
                }
            })
            .seek_data(move |_source, offset| {
                let Ok(mut cursor) = seek_cursor.lock() else {
                    return false;
                };
                cursor.offset = offset;
                true
            })
            .build(),
    );
}

#[allow(clippy::too_many_arguments)]
fn worker_read(
    mode: BoundaryMode,
    key: Option<&[u8; 32]>,
    chunk_size: usize,
    chunk_count: usize,
    requested: u32,
    crash_after: Option<u64>,
    cursor: &Mutex<SourceCursor>,
    reader: &Mutex<BufReader<io::Stdin>>,
    writer: &Mutex<BufWriter<io::Stdout>>,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let mut cursor = cursor.lock().map_err(|_| "cursor poisoned")?;
    let logical_limit = u64::try_from(chunk_size)?.saturating_mul(u64::try_from(chunk_count)?);
    if cursor.offset >= logical_limit {
        return Ok(None);
    }
    let chunk_index = usize::try_from(cursor.offset / u64::try_from(chunk_size)?)?;
    if cursor.cached.as_ref().map(|cached| cached.0) != Some(chunk_index) {
        if crash_after == Some(cursor.requests) {
            eprintln!("fault_injection=worker_crash request={}", cursor.requests);
            std::process::exit(86);
        }
        let mut writer = writer.lock().map_err(|_| "writer poisoned")?;
        writer.write_all(&[MSG_CHUNK_REQUEST])?;
        write_u32(&mut *writer, u32::try_from(chunk_index)?)?;
        writer.flush()?;
        drop(writer);
        let mut reader = reader.lock().map_err(|_| "reader poisoned")?;
        let mut response = [0_u8; 1];
        reader.read_exact(&mut response)?;
        if response[0] != MSG_CHUNK_RESPONSE {
            return Err("invalid chunk response".into());
        }
        let length = read_u32(&mut *reader)? as usize;
        let limit = chunk_size
            + if mode == BoundaryMode::ObjectKey {
                TAG_BYTES
            } else {
                0
            };
        validate_chunk_response_length(length, limit)?;
        let mut data = vec![0_u8; length];
        reader.read_exact(&mut data)?;
        drop(reader);
        if mode == BoundaryMode::ObjectKey {
            let key = key.ok_or("object-key mode did not receive a key")?;
            let cipher = XChaCha20Poly1305::new_from_slice(key)?;
            let nonce = chunk_nonce(chunk_index)?;
            let aad = chunk_aad(chunk_index, chunk_count)?;
            data = cipher.decrypt(
                &nonce,
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            )?;
        }
        cursor.cached = Some((chunk_index, data));
        cursor.requests += 1;
    }
    let within = usize::try_from(cursor.offset % u64::try_from(chunk_size)?)?;
    let cached = cursor.cached.as_ref().ok_or("chunk cache missing")?;
    if within >= cached.1.len() {
        return Ok(None);
    }
    let requested = usize::try_from(requested)
        .unwrap_or(CHUNK_BYTES)
        .clamp(1, CHUNK_BYTES);
    let end = cached.1.len().min(within.saturating_add(requested));
    let output = cached.1[within..end].to_vec();
    cursor.offset = cursor.offset.saturating_add(u64::try_from(output.len())?);
    Ok(Some(output))
}

fn validate_chunk_response_length(length: usize, limit: usize) -> Result<(), Box<dyn Error>> {
    if length == 0 || length > limit {
        return Err("invalid chunk response length".into());
    }
    Ok(())
}

fn install_frame_transport(sink: &gst_app::AppSink, writer: Arc<Mutex<BufWriter<io::Stdout>>>) {
    sink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                if map.size() > MAX_FRAME_BYTES {
                    return Err(gst::FlowError::Error);
                }
                let mut writer = writer.lock().map_err(|_| gst::FlowError::Error)?;
                writer
                    .write_all(&[MSG_FRAME])
                    .map_err(|_| gst::FlowError::Error)?;
                write_u32(
                    &mut *writer,
                    u32::try_from(map.size()).map_err(|_| gst::FlowError::Error)?,
                )
                .map_err(|_| gst::FlowError::Error)?;
                writer
                    .write_all(map.as_slice())
                    .map_err(|_| gst::FlowError::Error)?;
                writer.flush().map_err(|_| gst::FlowError::Error)?;
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );
}

fn connect_worker_decode_pads(
    decode: &gst::Element,
    video_queue: &gst::Element,
    audio_queue: &gst::Element,
) {
    let video_sink = video_queue.static_pad("sink").expect("video queue sink");
    let audio_sink = audio_queue.static_pad("sink").expect("audio queue sink");
    decode.connect_pad_added(move |_decode, source_pad| {
        let caps = source_pad
            .current_caps()
            .unwrap_or_else(|| source_pad.query_caps(None));
        let Some(structure) = caps.structure(0) else {
            return;
        };
        let sink = if structure.name().starts_with("video/") {
            &video_sink
        } else if structure.name().starts_with("audio/") {
            &audio_sink
        } else {
            return;
        };
        if !sink.is_linked() && source_pad.link(sink).is_err() {
            eprintln!("failed to link decoded {} pad", structure.name());
        }
    });
}

fn drive_worker(pipeline: &gst::Pipeline, run_seconds: u64) -> Result<(), Box<dyn Error>> {
    let bus = pipeline.bus().ok_or("pipeline has no bus")?;
    let started = Instant::now();
    let seeks = [70_u64, 20, 85];
    let mut next_seek = 0;
    while started.elapsed() < Duration::from_secs(run_seconds) {
        if next_seek < seeks.len()
            && started.elapsed() >= Duration::from_secs(2 + next_seek as u64 * 2)
            && let Some(duration) = pipeline.query_duration::<gst::ClockTime>()
        {
            let target = gst::ClockTime::from_nseconds(
                duration.nseconds().saturating_mul(seeks[next_seek]) / 100,
            );
            pipeline.seek_simple(gst::SeekFlags::FLUSH | gst::SeekFlags::KEY_UNIT, target)?;
            next_seek += 1;
        }
        if let Some(message) = bus.timed_pop(gst::ClockTime::from_mseconds(50)) {
            match message.view() {
                gst::MessageView::Error(error) => {
                    return Err(format!("worker GStreamer error: {}", error.error()).into());
                }
                gst::MessageView::Eos(_) => break,
                _ => {}
            }
        }
    }
    Ok(())
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_chunks_round_trip_independently() {
        let plaintext = vec![0x5a; CHUNK_BYTES + 31];
        let object = encrypt_object(&plaintext).unwrap();
        assert_eq!(decrypt_chunk(&object, 0).unwrap(), plaintext[..CHUNK_BYTES]);
        assert_eq!(decrypt_chunk(&object, 1).unwrap(), plaintext[CHUNK_BYTES..]);
        assert_eq!(object.chunks[0].len(), CHUNK_BYTES + TAG_BYTES);
    }

    #[test]
    fn chunk_context_rejects_reordering() {
        let plaintext = vec![0x33; CHUNK_BYTES * 2];
        let object = encrypt_object(&plaintext).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&object.key).unwrap();
        let result = cipher.decrypt(
            &chunk_nonce(1).unwrap(),
            Payload {
                msg: &object.chunks[0],
                aad: &chunk_aad(1, 2).unwrap(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_boundary_mode() {
        assert_eq!(
            BoundaryMode::parse("master-key").unwrap_err(),
            "--mode requires object-key or broker"
        );
    }

    #[test]
    fn rejects_malformed_worker_initialization() {
        let mut message = Vec::new();
        message.extend_from_slice(b"OSVP1IPC");
        message.push(BoundaryMode::Broker.wire());
        write_u64(&mut message, u64::try_from(CHUNK_BYTES * 2 + 1).unwrap()).unwrap();
        write_u32(&mut message, u32::try_from(CHUNK_BYTES).unwrap()).unwrap();
        write_u32(&mut message, 2).unwrap();

        let error = parse_worker_init(&mut message.as_slice(), BoundaryMode::Broker).unwrap_err();
        assert_eq!(
            error.to_string(),
            "IPC logical length does not match chunk framing"
        );

        message[0] = b'X';
        let error = parse_worker_init(&mut message.as_slice(), BoundaryMode::Broker).unwrap_err();
        assert_eq!(error.to_string(), "invalid IPC magic");
    }

    #[test]
    fn rejects_malformed_chunk_response_lengths() {
        assert!(validate_chunk_response_length(0, CHUNK_BYTES).is_err());
        assert!(validate_chunk_response_length(CHUNK_BYTES + 1, CHUNK_BYTES).is_err());
        assert!(validate_chunk_response_length(CHUNK_BYTES, CHUNK_BYTES).is_ok());
    }
}
