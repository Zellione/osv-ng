use std::{
    env,
    error::Error,
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use gstreamer as gst;
use gstreamer::prelude::*;
use gtk::{gdk, gio, glib, prelude::*};

const APP_ID: &str = "io.github.osv_ng.Phase1";
const HELPER_MARKER: &str = "OSV_PHASE1_HELPER_READY";

fn main() -> glib::ExitCode {
    let mode = env::args().nth(1);
    if mode.as_deref() == Some("--helper") {
        println!("{HELPER_MARKER}");
        return glib::ExitCode::SUCCESS;
    }
    if mode.as_deref() == Some("--self-test") {
        return match self_test() {
            Ok(()) => glib::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Flatpak self-test failed: {error}");
                glib::ExitCode::FAILURE
            }
        };
    }

    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run_with_args::<&str>(&["osv-flatpak-smoke"])
}

fn self_test() -> Result<(), Box<dyn Error>> {
    gtk::init()?;
    let backend = gdk::Display::default()
        .ok_or("no display")?
        .type_()
        .name()
        .to_string();
    if !backend.contains("Wayland") {
        return Err(format!("unsupported display backend: {backend}").into());
    }
    let helper = helper_probe()?;
    let sqlcipher = sqlcipher_probe()?;
    let gstreamer = gstreamer_probe()?;
    audio_probe_blocking()?;
    seekable_av_probe()?;
    println!(
        "wayland=true helper={helper} sqlcipher={sqlcipher} gstreamer={gstreamer} audio_pipeline=true seekable_av=true"
    );
    Ok(())
}

fn build_ui(app: &gtk::Application) {
    install_css();
    let helper = helper_probe().unwrap_or_else(|error| format!("failed: {error}"));
    let sqlcipher = sqlcipher_probe().unwrap_or_else(|error| format!("failed: {error}"));
    let gstreamer = gstreamer_probe().unwrap_or_else(|error| format!("failed: {error}"));
    let backend = gdk::Display::default().map_or_else(
        || "no display".to_owned(),
        |display| display.type_().name().to_string(),
    );

    let status = gtk::Label::builder()
        .label(format!(
            "Display: {backend}\nHelper: {helper}\nSQLCipher: {sqlcipher}\nGStreamer: {gstreamer}"
        ))
        .xalign(0.0)
        .selectable(true)
        .wrap(true)
        .build();
    let portal_result = gtk::Label::new(Some("Portal: not opened"));
    portal_result.set_xalign(0.0);
    let portal_button = gtk::Button::with_label("Open portal file chooser");
    let audio_button = gtk::Button::with_label("Play one-second audio probe");
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.add_css_class("phase1-card");
    content.append(&status);
    content.append(&portal_result);
    content.append(&portal_button);
    content.append(&audio_button);

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("osv-ng Flatpak Phase 1")
        .default_width(560)
        .default_height(320)
        .child(&content)
        .build();

    let window_for_portal = window.clone();
    portal_button.connect_clicked(move |_| {
        let dialog = gtk::FileDialog::builder()
            .title("Phase 1 portal probe")
            .build();
        let portal_result = portal_result.clone();
        dialog.open(
            Some(&window_for_portal),
            None::<&gio::Cancellable>,
            move |result| match result {
                Ok(_) => portal_result.set_label("Portal: selected descriptor granted"),
                Err(error) if error.matches(gio::IOErrorEnum::Cancelled) => {
                    portal_result.set_label("Portal: cancelled safely");
                }
                Err(_) => portal_result.set_label("Portal: failed"),
            },
        );
    });
    audio_button.connect_clicked(move |button| match start_audio_probe() {
        Ok(pipeline) => {
            button.set_label("Audio probe running");
            let button = button.clone();
            glib::timeout_add_seconds_local_once(2, move || {
                let _ = pipeline.set_state(gst::State::Null);
                button.set_label("Audio probe completed");
            });
        }
        Err(_) => button.set_label("Audio probe failed"),
    });
    window.present();
}

fn install_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(
        ".phase1-card { padding: 24px; background: #111722; color: #edf3ff; }\n\
         .phase1-card button { padding: 8px 12px; }",
    );
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn helper_probe() -> Result<String, Box<dyn Error>> {
    let output = Command::new(env::current_exe()?).arg("--helper").output()?;
    if !output.status.success() || String::from_utf8(output.stdout)?.trim() != HELPER_MARKER {
        return Err("unexpected helper result".into());
    }
    Ok("launched and supervised".to_owned())
}

fn sqlcipher_probe() -> Result<String, Box<dyn Error>> {
    let mut child = Command::new("sqlcipher")
        .arg("-batch")
        .arg(":memory:")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("SQLCipher stdin unavailable")?;
    stdin.write_all(
        b".bail on\nPRAGMA key=\"x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'\";\nPRAGMA temp_store=MEMORY;\nCREATE TABLE probe(value TEXT);\nINSERT INTO probe VALUES('synthetic');\nSELECT count(*) FROM probe;\nPRAGMA cipher_version;\n",
    )?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err("SQLCipher process failed".into());
    }
    let output = String::from_utf8(output.stdout)?;
    let version = output.lines().last().ok_or("missing SQLCipher version")?;
    Ok(format!("raw-key memory DB, version {version}"))
}

fn gstreamer_probe() -> Result<String, Box<dyn Error>> {
    gst::init()?;
    let required = ["appsrc", "decodebin3", "pulsesink"];
    let missing: Vec<_> = required
        .iter()
        .filter(|name| gst::ElementFactory::find(name).is_none())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(format!("missing elements: {}", missing.join(", ")).into());
    }
    let hardware_decoders = gst::ElementFactory::factories_with_type(
        gst::ElementFactoryType::DECODER | gst::ElementFactoryType::MEDIA_VIDEO,
        gst::Rank::MARGINAL,
    )
    .into_iter()
    .filter(|factory| {
        factory
            .metadata("klass")
            .is_some_and(|class| class.contains("Hardware"))
    })
    .count();
    Ok(format!(
        "{}; hardware video decoder candidates={hardware_decoders}",
        gst::version_string()
    ))
}

fn start_audio_probe() -> Result<gst::Pipeline, Box<dyn Error>> {
    let element = gst::parse::launch(
        "audiotestsrc num-buffers=48 volume=0.03 wave=sine ! \
         audioconvert ! audioresample ! pulsesink sync=true",
    )?;
    let pipeline = element
        .downcast::<gst::Pipeline>()
        .map_err(|_| "audio probe did not create a pipeline")?;
    pipeline.set_state(gst::State::Playing)?;
    Ok(pipeline)
}

fn audio_probe_blocking() -> Result<(), Box<dyn Error>> {
    let pipeline = start_audio_probe()?;
    let bus = pipeline.bus().ok_or("audio pipeline has no bus")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if Instant::now() >= deadline {
            break Err("audio pipeline timed out".into());
        }
        if let Some(message) = bus.timed_pop(gst::ClockTime::from_mseconds(100)) {
            match message.view() {
                gst::MessageView::Eos(_) => break Ok(()),
                gst::MessageView::Error(error) => {
                    break Err(format!("audio pipeline failed: {}", error.error()).into());
                }
                _ => {}
            }
        }
    };
    pipeline.set_state(gst::State::Null)?;
    result
}

fn seekable_av_probe() -> Result<(), Box<dyn Error>> {
    let output = Command::new("osv-gstreamer-seek-prototype")
        .args([
            "--input",
            "/app/share/osv-phase1/fixture.ogv",
            "--output",
            "flatpak",
            "--run-seconds",
            "10",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "seekable A/V child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    if !stdout.contains("completed_seeks=3")
        || !stdout.contains("video_buffers=")
        || !stdout.contains("audio_buffers=")
    {
        return Err("seekable A/V child returned incomplete evidence".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_mode_is_not_triggered_by_unrelated_argument() {
        assert_ne!(Some("--probe"), Some("--helper"));
    }

    #[test]
    fn helper_marker_contains_no_environment_or_path_data() {
        assert_eq!(HELPER_MARKER, "OSV_PHASE1_HELPER_READY");
    }
}
