use std::{
    env,
    error::Error,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

const READ_CHUNK_BYTES: usize = 256 * 1024;
const APP_SOURCE_QUEUE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    Fake,
    Real,
    Flatpak,
}

#[derive(Debug, PartialEq, Eq)]
struct Config {
    input: PathBuf,
    output: OutputMode,
    run_seconds: u64,
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let mut args = args.into_iter();
        let _program = args.next();
        let mut input = None;
        let mut output = OutputMode::Fake;
        let mut run_seconds = 10;

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--input" => {
                    input = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--input requires a file path".to_owned())?,
                    ));
                }
                "--output" => {
                    output = match args.next().as_deref() {
                        Some("fake") => OutputMode::Fake,
                        Some("real") => OutputMode::Real,
                        Some("flatpak") => OutputMode::Flatpak,
                        _ => return Err("--output requires fake, real, or flatpak".to_owned()),
                    };
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
                "--help" | "-h" => return Ok(None),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        let input = input.ok_or_else(|| "--input is required".to_owned())?;
        Ok(Some(Self {
            input,
            output,
            run_seconds,
        }))
    }
}

struct SourceState {
    file: File,
    offset: u64,
}

#[derive(Default)]
struct BranchMetrics {
    buffers: AtomicU64,
    bytes: AtomicU64,
}

fn main() {
    let config = match Config::from_args(env::args()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            print_help();
            return;
        }
        Err(error) => {
            eprintln!("error: {error}\n");
            print_help();
            std::process::exit(2);
        }
    };

    if let Err(error) = run(&config) {
        eprintln!("prototype failed: {error}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "Usage: osv-gstreamer-seek-prototype --input FILE \\\n+         [--output fake|real|flatpak] [--run-seconds 2..300]\n\n\
         fake uses bounded fake sinks; real uses Wayland/PipeWire; flatpak uses\n\
         Wayland and the sandbox PulseAudio-compatible socket."
    );
}

fn run(config: &Config) -> Result<(), Box<dyn Error>> {
    gst::init()?;
    let input = File::open(&config.input)?;
    let input_length = input.metadata()?.len();
    if input_length == 0 {
        return Err("input file is empty".into());
    }

    let pipeline = gst::Pipeline::new();
    let source = gst::ElementFactory::make("appsrc").name("source").build()?;
    let source = source
        .downcast::<gst_app::AppSrc>()
        .map_err(|_| "appsrc type mismatch")?;
    source.set_stream_type(gst_app::AppStreamType::RandomAccess);
    source.set_format(gst::Format::Bytes);
    let input_length_i64 =
        i64::try_from(input_length).map_err(|_| "input is too large for GstAppSrc")?;
    source.set_size(input_length_i64);
    source.set_block(true);
    source.set_max_bytes(APP_SOURCE_QUEUE_BYTES);

    let cancelled = Arc::new(AtomicBool::new(false));
    install_source_callbacks(
        &source,
        SourceState {
            file: input,
            offset: 0,
        },
        Arc::clone(&cancelled),
    );

    let decode = gst::ElementFactory::make("decodebin3")
        .name("decode")
        .build()?;
    let video_metrics = Arc::new(BranchMetrics::default());
    let audio_metrics = Arc::new(BranchMetrics::default());
    let video_queue = add_output_branch(
        &pipeline,
        "video",
        config.output,
        Arc::clone(&video_metrics),
    )?;
    let audio_queue = add_output_branch(
        &pipeline,
        "audio",
        config.output,
        Arc::clone(&audio_metrics),
    )?;

    pipeline.add_many([source.upcast_ref(), &decode])?;
    source.link(&decode)?;
    connect_decode_pads(&decode, &video_queue, &audio_queue);
    log_selected_elements(&pipeline);

    pipeline.set_state(gst::State::Playing)?;
    let result = drive_pipeline(&pipeline, config.run_seconds, &video_queue, &audio_queue);
    cancelled.store(true, Ordering::Release);
    pipeline.set_state(gst::State::Null)?;

    println!(
        "video_buffers={} video_bytes={} audio_buffers={} audio_bytes={} appsrc_max_bytes={APP_SOURCE_QUEUE_BYTES}",
        video_metrics.buffers.load(Ordering::Relaxed),
        video_metrics.bytes.load(Ordering::Relaxed),
        audio_metrics.buffers.load(Ordering::Relaxed),
        audio_metrics.bytes.load(Ordering::Relaxed),
    );
    result
}

fn install_source_callbacks(
    source: &gst_app::AppSrc,
    state: SourceState,
    cancelled: Arc<AtomicBool>,
) {
    let state = Arc::new(Mutex::new(state));
    let read_state = Arc::clone(&state);
    let seek_state = Arc::clone(&state);
    let read_cancelled = Arc::clone(&cancelled);
    let seek_cancelled = Arc::clone(&cancelled);

    source.set_callbacks(
        gst_app::AppSrcCallbacks::builder()
            .need_data(move |source, requested| {
                if read_cancelled.load(Ordering::Acquire) {
                    let _ = source.end_of_stream();
                    return;
                }
                let requested = usize::try_from(requested).unwrap_or(READ_CHUNK_BYTES);
                let mut buffer = vec![0_u8; requested.clamp(1, READ_CHUNK_BYTES)];
                let mut state = read_state.lock().expect("source state poisoned");
                match state.file.read(&mut buffer) {
                    Ok(0) => {
                        let _ = source.end_of_stream();
                    }
                    Ok(read) => {
                        buffer.truncate(read);
                        state.offset = state.offset.saturating_add(read as u64);
                        if let Err(error) = source.push_buffer(gst::Buffer::from_mut_slice(buffer))
                        {
                            eprintln!("appsrc rejected buffer: {error:?}");
                        }
                    }
                    Err(error) => {
                        eprintln!("source read failed: {error}");
                        let _ = source.end_of_stream();
                    }
                }
            })
            .seek_data(move |_source, offset| {
                if seek_cancelled.load(Ordering::Acquire) {
                    return false;
                }
                let mut state = seek_state.lock().expect("source state poisoned");
                match state.file.seek(SeekFrom::Start(offset)) {
                    Ok(actual) => {
                        state.offset = actual;
                        actual == offset
                    }
                    Err(error) => {
                        eprintln!("source seek failed: {error}");
                        false
                    }
                }
            })
            .build(),
    );
}

fn add_output_branch(
    pipeline: &gst::Pipeline,
    kind: &str,
    output: OutputMode,
    metrics: Arc<BranchMetrics>,
) -> Result<gst::Element, Box<dyn Error>> {
    let queue = gst::ElementFactory::make("queue")
        .name(format!("{kind}-queue"))
        .property(
            "max-size-buffers",
            if kind == "video" { 3_u32 } else { 16_u32 },
        )
        .property("max-size-bytes", 0_u32)
        .property("max-size-time", 0_u64)
        .build()?;
    let convert_name = if kind == "video" {
        "videoconvert"
    } else {
        "audioconvert"
    };
    let convert = gst::ElementFactory::make(convert_name).build()?;
    let sink_name = match (kind, output) {
        (_, OutputMode::Fake) => "fakesink",
        ("video", OutputMode::Real | OutputMode::Flatpak) => "waylandsink",
        ("audio", OutputMode::Real) => "pipewiresink",
        ("audio", OutputMode::Flatpak) => "pulsesink",
        _ => return Err("unknown output branch".into()),
    };
    let sink = gst::ElementFactory::make(sink_name)
        .name(format!("{kind}-sink"))
        .property("sync", true)
        .build()?;
    pipeline.add_many([&queue, &convert, &sink])?;
    gst::Element::link_many([&queue, &convert, &sink])?;

    let probe_pad = queue.static_pad("src").ok_or("queue has no source pad")?;
    probe_pad.add_probe(gst::PadProbeType::BUFFER, move |_pad, info| {
        if let Some(buffer) = info.buffer() {
            metrics.buffers.fetch_add(1, Ordering::Relaxed);
            metrics
                .bytes
                .fetch_add(buffer.size() as u64, Ordering::Relaxed);
        }
        gst::PadProbeReturn::Ok
    });
    Ok(queue)
}

fn connect_decode_pads(
    decode: &gst::Element,
    video_queue: &gst::Element,
    audio_queue: &gst::Element,
) {
    let video_sink = video_queue
        .static_pad("sink")
        .expect("video queue must have a sink pad");
    let audio_sink = audio_queue
        .static_pad("sink")
        .expect("audio queue must have a sink pad");
    decode.connect_pad_added(move |_decode, source_pad| {
        let caps = source_pad
            .current_caps()
            .unwrap_or_else(|| source_pad.query_caps(None));
        let Some(structure) = caps.structure(0) else {
            eprintln!("decoded pad {} has no caps structure", source_pad.name());
            return;
        };
        println!("decoded_pad={} caps={caps}", source_pad.name());
        let sink_pad = if structure.name().starts_with("video/") {
            &video_sink
        } else if structure.name().starts_with("audio/") {
            &audio_sink
        } else {
            return;
        };
        if !sink_pad.is_linked() {
            match source_pad.link(sink_pad) {
                Ok(_) => println!("linked decoded {} stream", structure.name()),
                Err(error) => eprintln!("could not link {}: {error:?}", structure.name()),
            }
        }
    });
}

fn drive_pipeline(
    pipeline: &gst::Pipeline,
    run_seconds: u64,
    video_queue: &gst::Element,
    audio_queue: &gst::Element,
) -> Result<(), Box<dyn Error>> {
    let bus = pipeline.bus().ok_or("pipeline has no bus")?;
    let started = Instant::now();
    let seek_percentages = [70_u64, 20, 85];
    let mut next_seek = 0;
    let mut seek_started = None;
    let mut max_video_queue = 0_u32;
    let mut max_audio_queue = 0_u32;

    while started.elapsed() < Duration::from_secs(run_seconds) {
        max_video_queue = max_video_queue.max(video_queue.property("current-level-buffers"));
        max_audio_queue = max_audio_queue.max(audio_queue.property("current-level-buffers"));

        if next_seek < seek_percentages.len()
            && started.elapsed() >= Duration::from_secs(2 + next_seek as u64 * 2)
            && let Some(duration) = pipeline.query_duration::<gst::ClockTime>()
        {
            let target = gst::ClockTime::from_nseconds(
                duration
                    .nseconds()
                    .saturating_mul(seek_percentages[next_seek])
                    / 100,
            );
            println!(
                "seek_request={} target_ms={}",
                next_seek + 1,
                target.mseconds()
            );
            pipeline.seek_simple(gst::SeekFlags::FLUSH | gst::SeekFlags::KEY_UNIT, target)?;
            seek_started = Some(Instant::now());
            next_seek += 1;
        }

        if let Some(message) = bus.timed_pop(gst::ClockTime::from_mseconds(50)) {
            use gst::MessageView;
            match message.view() {
                MessageView::Error(error) => {
                    return Err(format!(
                        "GStreamer error from {:?}: {} ({:?})",
                        error.src().map(|source| source.path_string()),
                        error.error(),
                        error.debug()
                    )
                    .into());
                }
                MessageView::Eos(_) => {
                    println!("end_of_stream=true");
                    break;
                }
                MessageView::AsyncDone(_) => {
                    if let Some(seek_started) = seek_started.take() {
                        println!(
                            "seek_complete_latency_ms={:.2}",
                            seek_started.elapsed().as_secs_f64() * 1_000.0
                        );
                    }
                }
                _ => {}
            }
        }
    }
    println!(
        "cancelled_after_ms={} completed_seeks={} max_video_queue_buffers={max_video_queue} max_audio_queue_buffers={max_audio_queue}",
        started.elapsed().as_millis(),
        next_seek
    );
    Ok(())
}

fn log_selected_elements(pipeline: &gst::Pipeline) {
    pipeline.connect_deep_element_added(|_, _, element| {
        if let Some(factory) = element.factory() {
            let class = factory.metadata("klass").unwrap_or_default();
            if class.contains("Decoder") || class.contains("Sink") {
                println!(
                    "selected_element={} class={} plugin={}",
                    factory.name(),
                    class,
                    factory.plugin_name().unwrap_or_default()
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_input_and_real_output() {
        let config = Config::from_args([
            "prototype".to_owned(),
            "--input".to_owned(),
            "fixture.ogv".to_owned(),
            "--output".to_owned(),
            "real".to_owned(),
            "--run-seconds".to_owned(),
            "20".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.input, PathBuf::from("fixture.ogv"));
        assert_eq!(config.output, OutputMode::Real);
        assert_eq!(config.run_seconds, 20);
    }

    #[test]
    fn rejects_unbounded_run_time() {
        let error = Config::from_args([
            "prototype".to_owned(),
            "--input".to_owned(),
            "fixture.ogv".to_owned(),
            "--run-seconds".to_owned(),
            "301".to_owned(),
        ])
        .unwrap_err();
        assert_eq!(error, "--run-seconds must be between 2 and 300");
    }

    #[test]
    fn parses_flatpak_output_mode() {
        let config = Config::from_args([
            "prototype".to_owned(),
            "--input".to_owned(),
            "fixture.ogv".to_owned(),
            "--output".to_owned(),
            "flatpak".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.output, OutputMode::Flatpak);
    }
}
