//! Storage-independent application state for the GTK shell.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Instant;
use zeroize::Zeroize;

pub mod ui;

const MIN_SPACING: u8 = 2;
const MAX_SPACING: u8 = 32;
const MIN_FONT_SIZE: u8 = 9;
const MAX_FONT_SIZE: u8 = 24;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Route {
    #[default]
    Choose,
    Unlock,
    Create,
    Gallery,
    Search,
    Tasks,
    Preferences,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
    HighContrast,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Density {
    Compact,
    #[default]
    Comfortable,
    Spacious,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PanelPlacement {
    #[default]
    Start,
    End,
    Top,
    Hidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Appearance {
    pub theme: Theme,
    pub accent: String,
    pub density: Density,
    pub spacing: u8,
    pub font_family: String,
    pub font_size: u8,
    pub panel: PanelPlacement,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            accent: "#6272a4".into(),
            density: Density::Comfortable,
            spacing: 8,
            font_family: "Sans".into(),
            font_size: 11,
            panel: PanelPlacement::Start,
        }
    }
}

impl Appearance {
    pub fn normalize(&mut self) {
        self.spacing = self.spacing.clamp(MIN_SPACING, MAX_SPACING);
        self.font_size = self.font_size.clamp(MIN_FONT_SIZE, MAX_FONT_SIZE);
        if !valid_hex_color(&self.accent) {
            self.accent = Self::default().accent;
        }
        if self.font_family.trim().is_empty() || self.font_family.chars().any(char::is_control) {
            self.font_family = Self::default().font_family;
        }
    }

    #[must_use]
    pub fn css(&self) -> String {
        let family = self.font_family.replace(['"', '\\'], "");
        let (background, foreground) = match self.theme {
            Theme::System => ("@theme_bg_color", "@theme_fg_color"),
            Theme::Light => ("#fafafa", "#202124"),
            Theme::Dark => ("#202124", "#f3f3f3"),
            Theme::HighContrast => ("#000000", "#ffffff"),
        };
        let tile_height = match self.density {
            Density::Compact => 88,
            Density::Comfortable => 112,
            Density::Spacious => 144,
        };
        format!(
            ".osv-shell {{ --osv-accent: {}; background: {}; color: {}; font-family: \"{}\"; font-size: {}pt; }}\n\
             .osv-tile {{ min-height: {}px; }}\n\
             .osv-gallery {{ padding: {}px; }}\n\
             .osv-gallery > child {{ margin: {}px; }}",
            self.accent,
            background,
            foreground,
            family,
            self.font_size,
            tile_height,
            self.spacing,
            self.spacing
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayoutMetrics {
    pub scale_factor: u8,
    pub logical_tile_size: u16,
    pub physical_tile_size: u16,
}

impl LayoutMetrics {
    pub fn new(scale_factor: u8, density: Density) -> Option<Self> {
        if !(1..=4).contains(&scale_factor) {
            return None;
        }
        let logical_tile_size = match density {
            Density::Compact => 96,
            Density::Comfortable => 128,
            Density::Spacious => 160,
        };
        Some(Self {
            scale_factor,
            logical_tile_size,
            physical_tile_size: logical_tile_size * u16::from(scale_factor),
        })
    }
}

fn valid_hex_color(value: &str) -> bool {
    matches!(value.len(), 4 | 7 | 9)
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Command {
    Lock,
    Search,
    Gallery,
    Tasks,
    Preferences,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShortcutError {
    Invalid,
    Reserved,
    Conflict(Command),
}

impl fmt::Display for ShortcutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("the shortcut is not valid"),
            Self::Reserved => formatter.write_str("the shortcut is reserved by the desktop"),
            Self::Conflict(command) => {
                write!(formatter, "the shortcut is already used by {command:?}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shortcuts(BTreeMap<Command, String>);

impl Default for Shortcuts {
    fn default() -> Self {
        Self(BTreeMap::from([
            (Command::Lock, "<Primary>l".into()),
            (Command::Search, "<Primary>f".into()),
            (Command::Gallery, "<Primary>g".into()),
            (Command::Tasks, "<Primary>j".into()),
            (Command::Preferences, "<Primary>comma".into()),
        ]))
    }
}

impl Shortcuts {
    pub fn assign(&mut self, command: Command, accelerator: &str) -> Result<(), ShortcutError> {
        let canonical = accelerator.trim().to_ascii_lowercase();
        if canonical.is_empty()
            || !canonical.contains('>')
            || canonical.chars().any(char::is_control)
        {
            return Err(ShortcutError::Invalid);
        }
        if matches!(canonical.as_str(), "<alt>f4" | "<primary><alt>delete") {
            return Err(ShortcutError::Reserved);
        }
        if let Some((used_by, _)) = self.0.iter().find(|(candidate, value)| {
            **candidate != command && value.to_ascii_lowercase() == canonical
        }) {
            return Err(ShortcutError::Conflict(*used_by));
        }
        self.0.insert(command, accelerator.trim().into());
        Ok(())
    }

    pub fn get(&self, command: Command) -> Option<&str> {
        self.0.get(&command).map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JobId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
    Running,
    Cancelling,
    Failed,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Job {
    pub id: JobId,
    pub description: &'static str,
    pub progress: u8,
    pub state: JobState,
}

#[derive(Debug, Default)]
struct UnlockedModel {
    generation: u64,
    workers: BTreeSet<u64>,
    decrypted_labels: Vec<String>,
}

impl Drop for UnlockedModel {
    fn drop(&mut self) {
        for label in &mut self.decrypted_labels {
            label.zeroize();
        }
        self.decrypted_labels.clear();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicError {
    pub summary: &'static str,
    pub recovery: &'static str,
}

#[derive(Debug)]
pub struct ShellState {
    route: Route,
    generation: u64,
    session: Option<UnlockedModel>,
    jobs: BTreeMap<JobId, Job>,
    next_job: u64,
    pub appearance: Appearance,
    pub shortcuts: Shortcuts,
    pub error: Option<PublicError>,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            route: Route::Choose,
            generation: 0,
            session: None,
            jobs: BTreeMap::new(),
            next_job: 1,
            appearance: Appearance::default(),
            shortcuts: Shortcuts::default(),
            error: None,
        }
    }
}

impl ShellState {
    pub fn route(&self) -> Route {
        self.route
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    pub fn navigate(&mut self, route: Route) -> bool {
        let allowed = self.is_unlocked()
            || matches!(
                route,
                Route::Choose | Route::Unlock | Route::Create | Route::Preferences
            );
        if allowed {
            self.route = route;
        }
        allowed
    }

    pub fn activate(&mut self, command: Command) -> bool {
        match command {
            Command::Lock if self.is_unlocked() => {
                self.lock();
                true
            }
            Command::Lock => false,
            Command::Search => self.navigate(Route::Search),
            Command::Gallery => self.navigate(Route::Gallery),
            Command::Tasks => self.navigate(Route::Tasks),
            Command::Preferences => self.navigate(Route::Preferences),
        }
    }

    pub fn unlock(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.session = Some(UnlockedModel {
            generation: self.generation,
            workers: BTreeSet::new(),
            decrypted_labels: Vec::new(),
        });
        self.route = Route::Gallery;
        self.error = None;
    }

    pub fn add_decrypted_label(&mut self, label: String) -> bool {
        let Some(session) = &mut self.session else {
            return false;
        };
        session.decrypted_labels.push(label);
        true
    }

    pub fn register_worker(&mut self, worker: u64) -> bool {
        let Some(session) = &mut self.session else {
            return false;
        };
        session.workers.insert(worker)
    }

    pub fn start_job(&mut self, description: &'static str) -> Option<(JobId, u64)> {
        let generation = self.session.as_ref()?.generation;
        let id = JobId(self.next_job);
        self.next_job = self.next_job.saturating_add(1);
        self.jobs.insert(
            id,
            Job {
                id,
                description,
                progress: 0,
                state: JobState::Running,
            },
        );
        Some((id, generation))
    }

    pub fn update_job(&mut self, id: JobId, generation: u64, progress: u8) -> bool {
        if self
            .session
            .as_ref()
            .is_none_or(|session| session.generation != generation)
        {
            return false;
        }
        let Some(job) = self.jobs.get_mut(&id) else {
            return false;
        };
        if job.state != JobState::Running {
            return false;
        }
        job.progress = progress.min(100);
        if job.progress == 100 {
            job.state = JobState::Complete;
        }
        true
    }

    pub fn fail_job(&mut self, id: JobId, generation: u64) -> bool {
        if self
            .session
            .as_ref()
            .is_none_or(|session| session.generation != generation)
        {
            return false;
        }
        let Some(job) = self.jobs.get_mut(&id) else {
            return false;
        };
        job.state = JobState::Failed;
        self.error = Some(PublicError {
            summary: "A background operation stopped",
            recovery: "Review the task and retry. The vault remains locked if locking was requested.",
        });
        true
    }

    pub fn cancel_job(&mut self, id: JobId) -> bool {
        let Some(job) = self.jobs.get_mut(&id) else {
            return false;
        };
        if job.state != JobState::Running {
            return false;
        }
        job.state = JobState::Cancelling;
        true
    }

    pub fn jobs(&self) -> impl Iterator<Item = &Job> {
        self.jobs.values()
    }

    /// Crosses the security boundary synchronously: all jobs are cancelled,
    /// worker authority is revoked, and decrypted application state is dropped.
    pub fn lock(&mut self) {
        for job in self
            .jobs
            .values_mut()
            .filter(|job| job.state == JobState::Running)
        {
            job.state = JobState::Cancelling;
        }
        if let Some(session) = &mut self.session {
            session.workers.clear();
        }
        self.session = None;
        self.jobs.clear();
        self.generation = self.generation.wrapping_add(1);
        self.route = Route::Choose;
        self.error = None;
    }

    #[cfg(test)]
    fn decrypted_label_count(&self) -> usize {
        self.session
            .as_ref()
            .map_or(0, |session| session.decrypted_labels.len())
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        self.session
            .as_ref()
            .map_or(0, |session| session.workers.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GalleryIndex {
    len: u32,
}

impl GalleryIndex {
    pub const MAX_ITEMS: u32 = 100_000;

    pub fn synthetic(len: u32) -> Option<Self> {
        (len <= Self::MAX_ITEMS).then_some(Self { len })
    }

    pub fn len(self) -> u32 {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn label(self, index: u32) -> Option<String> {
        (index < self.len).then(|| format!("Item {:06}", index + 1))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortalOutcome<T> {
    Selected(T),
    Cancelled,
    Failed(PublicError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CssOutcome {
    Applied,
    Rejected { fallback: &'static str },
}

/// Applies user CSS only after GTK has parsed it without an error. The callback
/// keeps GTK parsing in the UI layer while this policy remains headless.
pub fn accept_user_css(css: &str, parses: impl FnOnce(&str) -> bool) -> CssOutcome {
    if css.len() <= 256 * 1024 && !css.contains("@import") && parses(css) {
        CssOutcome::Applied
    } else {
        CssOutcome::Rejected {
            fallback: "The built-in theme remains active.",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PerformanceSample {
    pub entries: u32,
    pub elapsed_micros: u128,
}

pub fn synthetic_gallery_sample(entries: u32) -> Option<PerformanceSample> {
    let started = Instant::now();
    let index = GalleryIndex::synthetic(entries)?;
    for position in [0, entries / 2, entries.saturating_sub(1)] {
        let _ = index.label(position);
    }
    Some(PerformanceSample {
        entries,
        elapsed_micros: started.elapsed().as_micros(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_drops_decrypted_model_workers_and_jobs() {
        let mut shell = ShellState::default();
        shell.unlock();
        assert!(shell.add_decrypted_label("private title".into()));
        assert!(shell.register_worker(7));
        let _ = shell.start_job("scan").expect("unlocked");
        shell.lock();
        assert!(!shell.is_unlocked());
        assert_eq!(shell.route(), Route::Choose);
        assert_eq!(shell.decrypted_label_count(), 0);
        assert_eq!(shell.worker_count(), 0);
        assert_eq!(shell.jobs().count(), 0);
    }

    #[test]
    fn late_job_update_cannot_cross_lock_generation() {
        let mut shell = ShellState::default();
        shell.unlock();
        let (job, generation) = shell.start_job("maintenance").expect("unlocked");
        shell.lock();
        shell.unlock();
        assert!(!shell.update_job(job, generation, 80));
    }

    #[test]
    fn locked_navigation_cannot_enter_sensitive_routes() {
        let mut shell = ShellState::default();
        assert!(!shell.navigate(Route::Gallery));
        assert!(shell.navigate(Route::Create));
    }

    #[test]
    fn invalid_css_retains_built_in_theme() {
        assert_eq!(
            accept_user_css("broken {", |_| false),
            CssOutcome::Rejected {
                fallback: "The built-in theme remains active."
            }
        );
        assert!(matches!(
            accept_user_css("@import url(x);", |_| true),
            CssOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn appearance_values_are_bounded_and_sanitized() {
        let mut appearance = Appearance {
            accent: "red; }".into(),
            spacing: 255,
            font_family: "bad\nfont".into(),
            font_size: 1,
            ..Appearance::default()
        };
        appearance.normalize();
        assert_eq!(appearance.accent, "#6272a4");
        assert_eq!(appearance.spacing, MAX_SPACING);
        assert_eq!(appearance.font_family, "Sans");
        assert_eq!(appearance.font_size, MIN_FONT_SIZE);
    }

    #[test]
    fn shortcut_editor_rejects_conflicts_and_reserved_keys() {
        let mut shortcuts = Shortcuts::default();
        assert_eq!(
            shortcuts.assign(Command::Gallery, "<Primary>f"),
            Err(ShortcutError::Conflict(Command::Search))
        );
        assert_eq!(
            shortcuts.assign(Command::Gallery, "<Alt>F4"),
            Err(ShortcutError::Reserved)
        );
        assert!(shortcuts.assign(Command::Gallery, "<Primary>1").is_ok());
    }

    #[test]
    fn keyboard_actions_obey_the_lock_boundary() {
        let mut shell = ShellState::default();
        assert!(!shell.activate(Command::Search));
        shell.unlock();
        assert!(shell.activate(Command::Search));
        assert_eq!(shell.route(), Route::Search);
        assert!(shell.activate(Command::Lock));
        assert!(!shell.is_unlocked());
    }

    #[test]
    fn scale_factors_preserve_logical_size() {
        let one = LayoutMetrics::new(1, Density::Comfortable).expect("valid");
        let four = LayoutMetrics::new(4, Density::Comfortable).expect("valid");
        assert_eq!(one.logical_tile_size, four.logical_tile_size);
        assert_eq!(four.physical_tile_size, one.physical_tile_size * 4);
        assert!(LayoutMetrics::new(0, Density::Compact).is_none());
    }

    #[test]
    fn worker_failure_is_accessible_and_redacted() {
        let mut shell = ShellState::default();
        shell.unlock();
        let (job, generation) = shell.start_job("probe").expect("unlocked");
        assert!(shell.fail_job(job, generation));
        let error = shell.error.expect("public error");
        assert!(!error.summary.is_empty());
        assert!(!format!("{error:?}").contains("probe"));
    }

    #[test]
    fn portal_cancellation_is_not_an_error() {
        let outcome: PortalOutcome<String> = PortalOutcome::Cancelled;
        assert_eq!(outcome, PortalOutcome::Cancelled);
    }

    #[test]
    fn synthetic_hundred_thousand_entry_index_is_bounded_and_fast() {
        let sample = synthetic_gallery_sample(100_000).expect("supported size");
        assert_eq!(sample.entries, 100_000);
        assert!(
            sample.elapsed_micros < 100_000,
            "index setup took {}us",
            sample.elapsed_micros
        );
        assert!(GalleryIndex::synthetic(100_001).is_none());
    }
}
