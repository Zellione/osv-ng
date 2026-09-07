use std::{
    cell::{Cell, RefCell},
    env, fs,
    path::PathBuf,
    rc::Rc,
    time::Instant,
};

use gtk::{gdk, glib, graphene::Rect, prelude::*, subclass::prelude::*};

const DEFAULT_ITEMS: u32 = 10_000;
const MAX_ITEMS: u32 = 100_000;
const APP_ID: &str = "io.github.osv_ng.GalleryPrototype";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    items: u32,
    css: Option<PathBuf>,
    auto_scroll_seconds: Option<u32>,
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, String> {
        let mut items = DEFAULT_ITEMS;
        let mut css = None;
        let mut auto_scroll_seconds = None;
        let mut args = args.into_iter();
        let _program = args.next();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--items" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--items requires 10000 or 100000".to_owned())?;
                    items = value
                        .parse::<u32>()
                        .map_err(|_| "--items must be an integer".to_owned())?;
                    if items != DEFAULT_ITEMS && items != MAX_ITEMS {
                        return Err("--items must be 10000 or 100000".to_owned());
                    }
                }
                "--css" => {
                    css = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "--css requires a file path".to_owned())?,
                    ));
                }
                "--auto-scroll-seconds" => {
                    let seconds = args
                        .next()
                        .ok_or_else(|| "--auto-scroll-seconds requires an integer".to_owned())?
                        .parse::<u32>()
                        .map_err(|_| "--auto-scroll-seconds must be an integer".to_owned())?;
                    if !(5..=300).contains(&seconds) {
                        return Err("--auto-scroll-seconds must be between 5 and 300".to_owned());
                    }
                    auto_scroll_seconds = Some(seconds);
                }
                "--help" | "-h" => return Ok(None),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        Ok(Some(Self {
            items,
            css,
            auto_scroll_seconds,
        }))
    }
}

mod tile {
    use super::*;

    #[derive(Default)]
    pub struct GalleryTile {
        index: Cell<u32>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for GalleryTile {
        const NAME: &'static str = "OsvPhaseOneGalleryTile";
        type Type = super::GalleryTile;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for GalleryTile {}

    impl WidgetImpl for GalleryTile {
        fn measure(&self, orientation: gtk::Orientation, _for_size: i32) -> (i32, i32, i32, i32) {
            match orientation {
                gtk::Orientation::Horizontal => (112, 144, -1, -1),
                gtk::Orientation::Vertical => (112, 144, -1, -1),
                _ => unreachable!("GTK orientation is exhaustive"),
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f32;
            let height = widget.height() as f32;
            if width <= 0.0 || height <= 0.0 {
                return;
            }

            let index = self.index.get();
            let hue = (index.wrapping_mul(47) % 255) as f32 / 255.0;
            let background = gdk::RGBA::new(0.12 + hue * 0.16, 0.18, 0.28 - hue * 0.08, 1.0);
            snapshot.append_color(&background, &Rect::new(0.0, 0.0, width, height));

            let inset = 9.0;
            let preview_height = (height - 42.0).max(1.0);
            let accent = gdk::RGBA::new(0.25 + hue * 0.45, 0.42 + hue * 0.25, 0.76, 1.0);
            snapshot.append_color(
                &accent,
                &Rect::new(inset, inset, width - 2.0 * inset, preview_height - inset),
            );

            let layout = widget.create_pango_layout(Some(&format!("Item {:06}", index + 1)));
            layout.set_ellipsize(gtk::pango::EllipsizeMode::End);
            layout.set_width(((width - 2.0 * inset) * gtk::pango::SCALE as f32) as i32);
            snapshot.save();
            snapshot.translate(&gtk::graphene::Point::new(inset, height - 27.0));
            snapshot.append_layout(&layout, &gdk::RGBA::WHITE);
            snapshot.restore();
        }
    }

    impl GalleryTile {
        pub fn set_index(&self, index: u32) {
            if self.index.replace(index) != index {
                self.obj().queue_draw();
            }
        }
    }
}

glib::wrapper! {
    pub struct GalleryTile(ObjectSubclass<tile::GalleryTile>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl GalleryTile {
    fn new() -> Self {
        glib::Object::builder()
            .property("focusable", false)
            .property("hexpand", true)
            .build()
    }

    fn set_index(&self, index: u32) {
        self.imp().set_index(index);
    }
}

#[derive(Default)]
struct FrameMetrics {
    previous_micros: Option<i64>,
    intervals_micros: Vec<i64>,
}

impl FrameMetrics {
    fn record(&mut self, frame_micros: i64) {
        if let Some(previous) = self.previous_micros.replace(frame_micros) {
            let interval = frame_micros - previous;
            if (0..=1_000_000).contains(&interval) {
                self.intervals_micros.push(interval);
            }
        }
    }

    fn report_and_clear(&mut self) -> Option<(usize, f64, f64)> {
        if self.intervals_micros.is_empty() {
            return None;
        }
        self.intervals_micros.sort_unstable();
        let samples = self.intervals_micros.len();
        let p95_index = (samples * 95).div_ceil(100).saturating_sub(1);
        let p95_ms = self.intervals_micros[p95_index] as f64 / 1_000.0;
        let max_ms = self.intervals_micros[samples - 1] as f64 / 1_000.0;
        self.intervals_micros.clear();
        Some((samples, p95_ms, max_ms))
    }
}

fn main() -> glib::ExitCode {
    let config = match Config::from_args(env::args()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            print_help();
            return glib::ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("error: {error}\n");
            print_help();
            return glib::ExitCode::FAILURE;
        }
    };

    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_activate(move |app| build_ui(app, &config));
    app.run_with_args::<&str>(&["osv-gtk-gallery-prototype"])
}

fn print_help() {
    println!(
        "Usage: osv-gtk-gallery-prototype [--items 10000|100000] [--css FILE]\n\
         [--auto-scroll-seconds 5..300]\n\
         \n\
         Arrow keys navigate; Enter activates; Page Up/Down and Home/End traverse.\n\
         Use GTK_DEBUG=interactive for live scale/style inspection."
    );
}

fn build_ui(app: &gtk::Application, config: &Config) {
    let items = config.items;
    if let Some(path) = &config.css
        && let Err(error) = install_user_css(path)
    {
        eprintln!("Could not load user CSS: {error}");
    }

    let started = Instant::now();
    let model = gtk::StringList::new(&[]);
    for index in 0..items {
        model.append(&index.to_string());
    }
    let population_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let selection = gtk::SingleSelection::new(Some(model.clone()));
    selection.set_autoselect(true);
    selection.set_can_unselect(false);

    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, object| {
        let list_item = object
            .downcast_ref::<gtk::ListItem>()
            .expect("factory setup object must be a GtkListItem");
        list_item.set_child(Some(&GalleryTile::new()));
    });
    factory.connect_bind(|_, object| {
        let list_item = object
            .downcast_ref::<gtk::ListItem>()
            .expect("factory bind object must be a GtkListItem");
        let Some(item) = list_item.item().and_downcast::<gtk::StringObject>() else {
            return;
        };
        let Some(tile) = list_item.child().and_downcast::<GalleryTile>() else {
            return;
        };
        if let Ok(index) = item.string().parse::<u32>() {
            tile.set_index(index);
            list_item.set_accessible_label(&format!("Gallery item {}", index + 1));
        }
    });

    let grid = gtk::GridView::new(Some(selection.clone()), Some(factory));
    grid.set_min_columns(2);
    grid.set_max_columns(12);
    grid.set_enable_rubberband(false);
    grid.add_css_class("osv-gallery");
    grid.connect_activate(|_, position| println!("activated item {}", position + 1));

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&grid)
        .build();
    if let Some(seconds) = config.auto_scroll_seconds {
        install_auto_scroll(&grid, &scroller);
        let grid_to_stop = grid.clone();
        glib::timeout_add_seconds_local_once(seconds, move || {
            if let Some(window) = grid_to_stop.root().and_downcast::<gtk::Window>() {
                window.close();
            }
        });
    }

    let status = gtk::Label::builder()
        .xalign(0.0)
        .selectable(true)
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .margin_bottom(6)
        .build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&status);
    content.append(&scroller);

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("osv-ng · Phase 1 gallery")
        .default_width(1100)
        .default_height(760)
        .child(&content)
        .build();

    update_status(&status, items, population_ms, window.scale_factor(), None);
    let status_for_scale = status.clone();
    window.connect_scale_factor_notify(move |window| {
        update_status(
            &status_for_scale,
            items,
            population_ms,
            window.scale_factor(),
            None,
        );
    });

    let metrics = Rc::new(RefCell::new(FrameMetrics::default()));
    let ticks = Rc::clone(&metrics);
    grid.add_tick_callback(move |_, frame_clock| {
        ticks.borrow_mut().record(frame_clock.frame_time());
        glib::ControlFlow::Continue
    });

    let periodic_metrics = Rc::clone(&metrics);
    let periodic_status = status.clone();
    let periodic_window = window.clone();
    glib::timeout_add_seconds_local(5, move || {
        let report = periodic_metrics.borrow_mut().report_and_clear();
        update_status(
            &periodic_status,
            items,
            population_ms,
            periodic_window.scale_factor(),
            report,
        );
        glib::ControlFlow::Continue
    });

    println!(
        "model_items={} model_population_ms={population_ms:.2} rss_kib={}",
        items,
        resident_set_kib().unwrap_or(0)
    );
    window.present();
}

fn update_status(
    label: &gtk::Label,
    items: u32,
    population_ms: f64,
    scale_factor: i32,
    frame_report: Option<(usize, f64, f64)>,
) {
    let frame_text = frame_report.map_or_else(
        || "frame telemetry: scroll to sample".to_owned(),
        |(samples, p95_ms, max_ms)| {
            println!(
                "frame_samples={samples} frame_interval_p95_ms={p95_ms:.2} frame_interval_max_ms={max_ms:.2} rss_kib={}",
                resident_set_kib().unwrap_or(0)
            );
            format!("frames: {samples} samples, p95 {p95_ms:.1} ms, max {max_ms:.1} ms")
        },
    );
    label.set_label(&format!(
        "{items} rows · model {population_ms:.1} ms · RSS {} MiB · scale {scale_factor}× · {frame_text}",
        resident_set_kib().unwrap_or(0) / 1024
    ));
}

fn install_user_css(path: &PathBuf) -> Result<(), String> {
    let css = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let provider = gtk::CssProvider::new();
    provider.load_from_string(&css);
    let display = gdk::Display::default().ok_or_else(|| "no display is available".to_owned())?;
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_USER,
    );
    Ok(())
}

fn install_auto_scroll(grid: &gtk::GridView, scroller: &gtk::ScrolledWindow) {
    let adjustment = scroller.vadjustment();
    let direction = Rc::new(Cell::new(1.0_f64));
    grid.add_tick_callback(move |_, _| {
        let maximum = (adjustment.upper() - adjustment.page_size()).max(0.0);
        let mut next = adjustment.value() + 24.0 * direction.get();
        if next >= maximum {
            next = maximum;
            direction.set(-1.0);
        } else if next <= 0.0 {
            next = 0.0;
            direction.set(1.0);
        }
        adjustment.set_value(next);
        glib::ControlFlow::Continue
    });
}

fn resident_set_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    line.split_ascii_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_item_counts_and_css() {
        let config = Config::from_args([
            "prototype".to_owned(),
            "--items".to_owned(),
            "100000".to_owned(),
            "--css".to_owned(),
            "theme.css".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.items, 100_000);
        assert_eq!(config.css, Some(PathBuf::from("theme.css")));
        assert_eq!(config.auto_scroll_seconds, None);
    }

    #[test]
    fn rejects_unmeasured_item_counts() {
        let error = Config::from_args([
            "prototype".to_owned(),
            "--items".to_owned(),
            "42".to_owned(),
        ])
        .unwrap_err();
        assert_eq!(error, "--items must be 10000 or 100000");
    }

    #[test]
    fn frame_report_uses_nearest_rank_p95() {
        let mut metrics = FrameMetrics::default();
        for frame in 0..=100 {
            metrics.record(i64::from(frame * 1_000));
        }
        metrics.record(201_000);
        let (samples, p95_ms, max_ms) = metrics.report_and_clear().unwrap();
        assert_eq!(samples, 101);
        assert_eq!(p95_ms, 1.0);
        assert_eq!(max_ms, 101.0);
    }
}
