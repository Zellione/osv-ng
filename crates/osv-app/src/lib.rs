//! Storage-independent application state for the GTK shell.

use std::collections::BTreeMap;
use std::time::Instant;
use std::{fmt, io};

use osv_crypto::{LockStatus, SecretString};

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
            ".osv-shell {{ background: {}; color: {}; font-family: \"{}\"; font-size: {}pt; }}\n\
             .osv-tile {{ min-height: {}px; }}\n\
             .osv-gallery > child:selected .osv-tile {{ outline: 3px solid {}; }}\n\
             .osv-gallery {{ padding: {}px; }}\n\
             .osv-gallery > child {{ margin: {}px; }}",
            background,
            foreground,
            family,
            self.font_size,
            tile_height,
            self.accent,
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
        let Some(binding) = parse_binding(accelerator) else {
            return Err(ShortcutError::Invalid);
        };
        let reserved = ["<Alt>F4", "<Primary><Alt>Delete"]
            .into_iter()
            .filter_map(parse_binding)
            .any(|candidate| candidate == binding);
        if reserved {
            return Err(ShortcutError::Reserved);
        }
        if let Some((used_by, _)) = self.0.iter().find(|(candidate, value)| {
            **candidate != command && parse_binding(value).is_some_and(|value| value == binding)
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyBinding {
    modifiers: BTreeMap<&'static str, ()>,
    key: String,
}

fn parse_binding(accelerator: &str) -> Option<KeyBinding> {
    let mut remaining = accelerator.trim();
    let mut modifiers = BTreeMap::new();
    while let Some(after_open) = remaining.strip_prefix('<') {
        let close = after_open.find('>')?;
        let modifier = match after_open[..close].to_ascii_lowercase().as_str() {
            "primary" | "control" | "ctrl" => "control",
            "shift" => "shift",
            "alt" => "alt",
            "super" => "super",
            _ => return None,
        };
        if modifiers.insert(modifier, ()).is_some() {
            return None;
        }
        remaining = &after_open[close + 1..];
    }
    let key = remaining.to_ascii_lowercase();
    let named = matches!(
        key.as_str(),
        "comma" | "delete" | "escape" | "space" | "home" | "end" | "page_up" | "page_down"
    ) || key
        .strip_prefix('f')
        .and_then(|number| number.parse::<u8>().ok())
        .is_some_and(|number| (1..=35).contains(&number));
    if !(key.chars().count() == 1 && !key.chars().any(char::is_control)) && !named {
        return None;
    }
    Some(KeyBinding { modifiers, key })
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

pub trait Revocable: fmt::Debug {
    /// Cancels work and synchronously revokes its object-scoped authority.
    fn revoke(&mut self);
}

#[derive(Default)]
struct UnlockedModel {
    generation: u64,
    workers: BTreeMap<u64, Box<dyn Revocable>>,
    job_handles: BTreeMap<JobId, Box<dyn Revocable>>,
    decrypted_labels: Vec<SecretString>,
    lock_status: Option<LockStatus>,
}

impl fmt::Debug for UnlockedModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedModel")
            .field("generation", &self.generation)
            .field("workers", &self.workers.len())
            .field("job_handles", &self.job_handles.len())
            .field("decrypted_labels", &"[REDACTED]")
            .field("lock_status", &self.lock_status)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicError {
    pub summary: &'static str,
    pub recovery: &'static str,
}

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

impl fmt::Debug for ShellState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellState")
            .field("route", &self.route)
            .field("generation", &self.generation)
            .field("unlocked", &self.is_unlocked())
            .field("job_count", &self.jobs.len())
            .field("appearance", &self.appearance)
            .field("shortcuts", &self.shortcuts)
            .field("error", &self.error)
            .finish()
    }
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
            workers: BTreeMap::new(),
            job_handles: BTreeMap::new(),
            decrypted_labels: Vec::new(),
            lock_status: None,
        });
        self.route = Route::Gallery;
        self.error = None;
    }

    pub fn add_decrypted_label(&mut self, label: &str) -> io::Result<Option<LockStatus>> {
        let Some(session) = &mut self.session else {
            return Ok(None);
        };
        let label = SecretString::new(label)?;
        let status = label.lock_status();
        session.lock_status = Some(
            session
                .lock_status
                .map_or(status, |current| current.combine(status)),
        );
        session.decrypted_labels.push(label);
        Ok(Some(status))
    }

    pub fn register_worker(&mut self, worker: u64, handle: Box<dyn Revocable>) -> bool {
        let Some(session) = &mut self.session else {
            return false;
        };
        if let Some(mut replaced) = session.workers.insert(worker, handle) {
            replaced.revoke();
        }
        true
    }

    pub fn start_job(
        &mut self,
        description: &'static str,
        handle: Box<dyn Revocable>,
    ) -> Option<(JobId, u64)> {
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
        self.session.as_mut()?.job_handles.insert(id, handle);
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
            if let Some(session) = &mut self.session
                && let Some(mut handle) = session.job_handles.remove(&id)
            {
                handle.revoke();
            }
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
        if let Some(session) = &mut self.session
            && let Some(mut handle) = session.job_handles.remove(&id)
        {
            handle.revoke();
        }
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
        if let Some(session) = &mut self.session
            && let Some(mut handle) = session.job_handles.remove(&id)
        {
            handle.revoke();
        }
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
            for handle in session.job_handles.values_mut() {
                handle.revoke();
            }
            for handle in session.workers.values_mut() {
                handle.revoke();
            }
            session.job_handles.clear();
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
    // GTK accepts escaped and case-insensitive at-rules. Keep user CSS in a
    // resource-free subset by rejecting every at-rule, escape, and URL token.
    let folded = css.to_ascii_lowercase();
    let has_resource_syntax = css.contains(['@', '\\']) || folded.contains("url");
    if css.len() <= 256 * 1024 && !has_resource_syntax && parses(css) {
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
    let _labels = gallery_labels(entries)?;
    Some(PerformanceSample {
        entries,
        elapsed_micros: started.elapsed().as_micros(),
    })
}

pub fn gallery_labels(entries: u32) -> Option<Vec<String>> {
    let index = GalleryIndex::synthetic(entries)?;
    Some(
        (0..entries)
            .filter_map(|position| index.label(position))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Debug)]
    struct TestHandle(Rc<Cell<bool>>);

    impl Revocable for TestHandle {
        fn revoke(&mut self) {
            self.0.set(true);
        }
    }

    fn handle() -> (Box<dyn Revocable>, Rc<Cell<bool>>) {
        let revoked = Rc::new(Cell::new(false));
        (Box::new(TestHandle(Rc::clone(&revoked))), revoked)
    }

    #[test]
    fn lock_drops_decrypted_model_workers_and_jobs() {
        let mut shell = ShellState::default();
        shell.unlock();
        assert!(
            shell
                .add_decrypted_label("private title")
                .expect("allocate")
                .is_some()
        );
        let (worker, worker_revoked) = handle();
        assert!(shell.register_worker(7, worker));
        let (job, job_revoked) = handle();
        let _ = shell.start_job("scan", job).expect("unlocked");
        shell.lock();
        assert!(worker_revoked.get());
        assert!(job_revoked.get());
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
        let (handle, _) = handle();
        let (job, generation) = shell.start_job("maintenance", handle).expect("unlocked");
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
        assert!(matches!(
            accept_user_css("@IMPORT 'x';", |_| true),
            CssOutcome::Rejected { .. }
        ));
        assert!(matches!(
            accept_user_css(r"@\69mport 'x';", |_| true),
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
            shortcuts.assign(Command::Gallery, "<Control>f"),
            Err(ShortcutError::Conflict(Command::Search))
        );
        assert_eq!(
            shortcuts.assign(Command::Gallery, "<Alt>F4"),
            Err(ShortcutError::Reserved)
        );
        assert_eq!(
            shortcuts.assign(Command::Gallery, "invalid>"),
            Err(ShortcutError::Invalid)
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
        let (handle, _) = handle();
        let (job, generation) = shell.start_job("probe", handle).expect("unlocked");
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
    fn debug_output_redacts_decrypted_labels_and_locked_input_is_not_copied() {
        let mut shell = ShellState::default();
        assert_eq!(
            shell
                .add_decrypted_label("rejected private title")
                .expect("no allocation"),
            None
        );
        shell.unlock();
        shell
            .add_decrypted_label("private title")
            .expect("allocate");
        let debug = format!("{shell:?}");
        assert!(!debug.contains("private title"));
        assert!(debug.contains("unlocked"));
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
