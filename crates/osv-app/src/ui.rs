//! GTK presentation layer. It deliberately owns no vault or storage implementation.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::rc::Rc;

use gtk::{gdk, gio, glib, prelude::*};

use crate::{
    Appearance, Command, CssOutcome, Density, PanelPlacement, Revocable, Route, ShellState, Theme,
    accept_user_css, gallery_labels,
};

const APP_ID: &str = "io.github.osv_ng.App";
const BASE_CSS: &str = r#"
.osv-shell { background: @theme_bg_color; color: @theme_fg_color; }
.osv-sidebar { padding: 12px; border-right: 1px solid alpha(currentColor, .14); }
.osv-gallery { padding: 8px; }
.osv-tile { min-width: 128px; min-height: 112px; border-radius: 8px;
            background: alpha(currentColor, .08); padding: 12px; }
.osv-error { background: alpha(#d33, .18); padding: 10px; }
"#;

struct CssSlots {
    appearance: gtk::CssProvider,
    user: gtk::CssProvider,
}

impl CssSlots {
    fn install() -> Rc<Self> {
        let base = gtk::CssProvider::new();
        base.load_from_string(BASE_CSS);
        let slots = Rc::new(Self {
            appearance: gtk::CssProvider::new(),
            user: gtk::CssProvider::new(),
        });
        if let Some(display) = gdk::Display::default() {
            for (provider, priority) in [
                (&base, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION),
                (
                    &slots.appearance,
                    gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
                ),
                (&slots.user, gtk::STYLE_PROVIDER_PRIORITY_USER),
            ] {
                gtk::style_context_add_provider_for_display(&display, provider, priority);
            }
        }
        slots
    }

    fn set_appearance(&self, appearance: &Appearance) {
        self.appearance.load_from_string(&appearance.css());
    }

    fn set_user(&self, css: &str) {
        self.user.load_from_string(css);
    }
}

pub fn run() -> glib::ExitCode {
    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        if let Some(window) = app.active_window() {
            window.present();
        } else {
            build_window(app);
        }
    });
    app.run()
}

fn build_window(app: &gtk::Application) {
    let css = CssSlots::install();
    let state = Rc::new(RefCell::new(ShellState::default()));
    css.set_appearance(&state.borrow().appearance);
    let password = gtk::PasswordEntry::builder()
        .placeholder_text("Password")
        .show_peek_icon(true)
        .build();
    password.update_property(&[gtk::accessible::Property::Label("Vault password")]);
    let stack = gtk::Stack::builder().hexpand(true).vexpand(true).build();
    stack.add_named(&welcome_page(&state, &stack), Some("choose"));
    stack.add_named(&unlock_page(&state, &stack, &password), Some("unlock"));
    stack.add_named(&create_page(&state, &stack), Some("create"));
    stack.add_named(&vault_page(&state, &stack, &password, &css), Some("vault"));
    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Obscura Safe Vault")
        .default_width(1100)
        .default_height(760)
        .child(&stack)
        .build();
    window.add_css_class("osv-shell");
    install_keyboard(&window, &state, &stack, &password);
    window.present();
}

fn install_keyboard(
    window: &gtk::ApplicationWindow,
    state: &Rc<RefCell<ShellState>>,
    outer: &gtk::Stack,
    password: &gtk::PasswordEntry,
) {
    let keys = gtk::EventControllerKey::new();
    let state = Rc::clone(state);
    let outer = outer.clone();
    let password = password.clone();
    keys.connect_key_pressed(move |_, key, _, modifiers| {
        let command = [
            Command::Lock,
            Command::Search,
            Command::Gallery,
            Command::Tasks,
            Command::Preferences,
        ]
        .into_iter()
        .find(|command| {
            state
                .borrow()
                .shortcuts
                .get(*command)
                .and_then(gtk::accelerator_parse)
                .is_some_and(|(expected_key, expected_modifiers)| {
                    expected_key.to_lower() == key.to_lower()
                        && expected_modifiers
                            == (modifiers & gtk::accelerator_get_default_mod_mask())
                })
        });
        let Some(command) = command else {
            return glib::Propagation::Proceed;
        };
        if state.borrow_mut().activate(command) {
            sync_route(&outer, state.borrow().route(), &password);
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    window.add_controller(keys);
}

fn sync_route(outer: &gtk::Stack, route: Route, password: &gtk::PasswordEntry) {
    if route == Route::Choose {
        password.set_text("");
        outer.set_visible_child_name("choose");
        return;
    }
    if matches!(route, Route::Unlock | Route::Create) {
        outer.set_visible_child_name(match route {
            Route::Unlock => "unlock",
            _ => "create",
        });
        return;
    }
    outer.set_visible_child_name("vault");
    let Some(content) = outer
        .child_by_name("vault")
        .and_then(|vault| vault.downcast::<gtk::Box>().ok())
        .and_then(|root| {
            let mut child = root.first_child();
            while let Some(candidate) = child {
                if candidate.widget_name() == "osv-vault-content" {
                    return Some(candidate);
                }
                child = candidate.next_sibling();
            }
            None
        })
        .and_then(|child| child.downcast::<gtk::Stack>().ok())
    else {
        return;
    };
    content.set_visible_child_name(match route {
        Route::Search => "search",
        Route::Tasks => "tasks",
        Route::Preferences => "preferences",
        _ => "gallery",
    });
}

fn page(title: &str) -> gtk::Box {
    let page = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(36)
        .margin_bottom(36)
        .margin_start(36)
        .margin_end(36)
        .build();
    let heading = gtk::Label::builder().label(title).xalign(0.0).build();
    heading.add_css_class("title-1");
    page.append(&heading);
    page
}

fn welcome_page(state: &Rc<RefCell<ShellState>>, stack: &gtk::Stack) -> gtk::Widget {
    let page = page("Obscura Safe Vault");
    let choose = gtk::Button::with_mnemonic("_Choose vault folder");
    let create = gtk::Button::with_mnemonic("_Create a vault");
    page.append(&choose);
    page.append(&create);
    let state_for_choose = Rc::clone(state);
    let stack_for_choose = stack.clone();
    choose.connect_clicked(move |button| {
        select_folder(button, "Choose a vault folder", {
            let state = Rc::clone(&state_for_choose);
            let stack = stack_for_choose.clone();
            move |outcome| match outcome {
                PortalSelection::Selected => {
                    state.borrow_mut().navigate(Route::Unlock);
                    stack.set_visible_child_name("unlock");
                }
                PortalSelection::Cancelled => {}
                PortalSelection::Failed => show_error(
                    &stack,
                    "The folder chooser could not be opened. Return and try again.",
                ),
            }
        });
    });
    let state = Rc::clone(state);
    let stack = stack.clone();
    create.connect_clicked(move |_| {
        state.borrow_mut().navigate(Route::Create);
        stack.set_visible_child_name("create");
    });
    page.upcast()
}

enum PortalSelection {
    Selected,
    Cancelled,
    Failed,
}

fn select_folder(
    button: &gtk::Button,
    title: &str,
    complete: impl FnOnce(PortalSelection) + 'static,
) {
    let dialog = gtk::FileDialog::builder().title(title).modal(true).build();
    let parent = button.root().and_downcast::<gtk::Window>();
    dialog.select_folder(parent.as_ref(), gio::Cancellable::NONE, move |result| {
        complete(match result {
            Ok(_) => PortalSelection::Selected,
            Err(error) if portal_error_is_cancelled(&error) => PortalSelection::Cancelled,
            Err(_) => PortalSelection::Failed,
        });
    });
}

fn portal_error_is_cancelled(error: &glib::Error) -> bool {
    error.matches(gtk::DialogError::Dismissed)
        || error.matches(gtk::DialogError::Cancelled)
        || error.matches(gio::IOErrorEnum::Cancelled)
}

fn unlock_page(
    state: &Rc<RefCell<ShellState>>,
    stack: &gtk::Stack,
    password: &gtk::PasswordEntry,
) -> gtk::Widget {
    let page = page("Unlock vault");
    let unlock = gtk::Button::with_mnemonic("_Unlock");
    page.append(password);
    page.append(&unlock);
    let state = Rc::clone(state);
    let stack = stack.clone();
    let password = password.clone();
    unlock.connect_clicked(move |_| {
        state.borrow_mut().unlock();
        password.set_text("");
        sync_route(&stack, Route::Gallery, &password);
    });
    page.upcast()
}

fn create_page(state: &Rc<RefCell<ShellState>>, stack: &gtk::Stack) -> gtk::Widget {
    let page = page("Create vault");
    let location = gtk::Button::with_mnemonic("Choose _location…");
    let back = gtk::Button::with_mnemonic("_Back");
    let status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    page.append(&location);
    page.append(&back);
    page.append(&status);
    location.connect_clicked(move |button| {
        let status = status.clone();
        select_folder(button, "Choose where to create the vault", move |outcome| {
            status.set_label(match outcome {
                PortalSelection::Selected => {
                    "Location selected. Creation is ready for the vault service."
                }
                PortalSelection::Cancelled => "Selection cancelled.",
                PortalSelection::Failed => "The folder chooser failed. Try again.",
            });
        });
    });
    let state = Rc::clone(state);
    let stack = stack.clone();
    back.connect_clicked(move |_| {
        state.borrow_mut().navigate(Route::Choose);
        stack.set_visible_child_name("choose");
    });
    page.upcast()
}

fn vault_page(
    state: &Rc<RefCell<ShellState>>,
    outer: &gtk::Stack,
    password: &gtk::PasswordEntry,
    css: &Rc<CssSlots>,
) -> gtk::Widget {
    let root = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 6);
    sidebar.add_css_class("osv-sidebar");
    let content = gtk::Stack::builder().hexpand(true).vexpand(true).build();
    content.set_widget_name("osv-vault-content");
    content.add_named(&gallery_view(100_000), Some("gallery"));
    content.add_named(
        &simple_page("Search", "Search is ready for catalog integration."),
        Some("search"),
    );
    content.add_named(&tasks_page(state), Some("tasks"));
    let root_for_panel = root.clone();
    let sidebar_for_panel = sidebar.clone();
    let content_for_panel = content.clone();
    let set_panel: Rc<dyn Fn(PanelPlacement)> = Rc::new(move |placement| {
        sidebar_for_panel.set_visible(placement != PanelPlacement::Hidden);
        match placement {
            PanelPlacement::Start | PanelPlacement::Hidden => {
                root_for_panel.set_orientation(gtk::Orientation::Horizontal);
                root_for_panel.reorder_child_after(&sidebar_for_panel, None::<&gtk::Widget>);
                root_for_panel.reorder_child_after(&content_for_panel, Some(&sidebar_for_panel));
            }
            PanelPlacement::End => {
                root_for_panel.set_orientation(gtk::Orientation::Horizontal);
                root_for_panel.reorder_child_after(&content_for_panel, None::<&gtk::Widget>);
                root_for_panel.reorder_child_after(&sidebar_for_panel, Some(&content_for_panel));
            }
            PanelPlacement::Top => {
                root_for_panel.set_orientation(gtk::Orientation::Vertical);
                root_for_panel.reorder_child_after(&sidebar_for_panel, None::<&gtk::Widget>);
                root_for_panel.reorder_child_after(&content_for_panel, Some(&sidebar_for_panel));
            }
        }
    });
    content.add_named(
        &preferences_page(state, css, &set_panel),
        Some("preferences"),
    );
    for (label, route, child) in [
        ("Gallery", Route::Gallery, "gallery"),
        ("Search", Route::Search, "search"),
        ("Tasks", Route::Tasks, "tasks"),
        ("Preferences", Route::Preferences, "preferences"),
    ] {
        let button = gtk::Button::with_label(label);
        let state = Rc::clone(state);
        let content = content.clone();
        button.connect_clicked(move |_| {
            if state.borrow_mut().navigate(route) {
                content.set_visible_child_name(child);
            }
        });
        sidebar.append(&button);
    }
    let lock = gtk::Button::with_mnemonic("_Lock");
    sidebar.append(&lock);
    let state_for_lock = Rc::clone(state);
    let outer_for_lock = outer.clone();
    let password_for_lock = password.clone();
    lock.connect_clicked(move |_| {
        state_for_lock.borrow_mut().lock();
        sync_route(&outer_for_lock, Route::Choose, &password_for_lock);
    });
    root.append(&sidebar);
    root.append(&content);
    root.upcast()
}

fn gallery_view(items: u32) -> gtk::Widget {
    let labels = gallery_labels(items).expect("bounded gallery size");
    let references: Vec<&str> = labels.iter().map(String::as_str).collect();
    let model = gtk::StringList::new(&references);
    let selection = gtk::SingleSelection::new(Some(model));
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("list item");
        let label = gtk::Label::builder().wrap(true).xalign(0.0).build();
        label.add_css_class("osv-tile");
        item.set_child(Some(&label));
    });
    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("list item");
        let Some(value) = item.item().and_downcast::<gtk::StringObject>() else {
            return;
        };
        let Some(label) = item.child().and_downcast::<gtk::Label>() else {
            return;
        };
        label.set_label(&value.string());
        item.set_accessible_label(&format!("Gallery {}", value.string()));
    });
    let grid = gtk::GridView::new(Some(selection), Some(factory));
    grid.set_min_columns(2);
    grid.set_max_columns(12);
    grid.add_css_class("osv-gallery");
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&grid)
        .build()
        .upcast()
}

fn simple_page(title: &str, detail: &str) -> gtk::Widget {
    let page = page(title);
    page.append(&gtk::Label::new(Some(detail)));
    page.upcast()
}

#[derive(Debug)]
struct UiCancellation(Rc<Cell<bool>>);

impl Revocable for UiCancellation {
    fn revoke(&mut self) {
        self.0.set(true);
    }
}

fn tasks_page(state: &Rc<RefCell<ShellState>>) -> gtk::Widget {
    let page = page("Background tasks");
    let progress = gtk::ProgressBar::new();
    progress.update_property(&[gtk::accessible::Property::Label(
        "Synthetic background task progress",
    )]);
    let status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    status.update_property(&[gtk::accessible::Property::Label("Task status")]);
    let start = gtk::Button::with_mnemonic("_Start test task");
    let cancel = gtk::Button::with_mnemonic("_Cancel task");
    let fail = gtk::Button::with_mnemonic("Simulate _worker failure");
    page.append(&progress);
    page.append(&status);
    page.append(&start);
    page.append(&cancel);
    page.append(&fail);
    let active = Rc::new(RefCell::new(None));
    let state_for_start = Rc::clone(state);
    let active_for_start = Rc::clone(&active);
    let progress_for_start = progress.clone();
    let status_for_start = status.clone();
    start.connect_clicked(move |_| {
        if active_for_start.borrow().is_some() {
            status_for_start.set_label("Cancel or wait for the current task first.");
            return;
        }
        let revoked = Rc::new(Cell::new(false));
        let Some((job, generation)) = state_for_start.borrow_mut().start_job(
            "Synthetic task",
            Box::new(UiCancellation(Rc::clone(&revoked))),
        ) else {
            return;
        };
        *active_for_start.borrow_mut() = Some((job, generation));
        status_for_start.set_label("Task running");
        let state = Rc::clone(&state_for_start);
        let progress = progress_for_start.clone();
        let status = status_for_start.clone();
        let active = Rc::clone(&active_for_start);
        let step = Rc::new(Cell::new(0_u8));
        glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
            if active.borrow().as_ref() != Some(&(job, generation)) {
                return glib::ControlFlow::Break;
            }
            if revoked.get() {
                let terminal = state.borrow().job(job).map(|job| job.state);
                status.set_label(match terminal {
                    Some(crate::JobState::Failed) => {
                        "A background operation stopped. Review the task and retry."
                    }
                    Some(crate::JobState::Complete) => "Task complete",
                    _ => "Task cancelled",
                });
                *active.borrow_mut() = None;
                return glib::ControlFlow::Break;
            }
            let next = step.get().saturating_add(5);
            step.set(next);
            if !state.borrow_mut().update_job(job, generation, next) {
                return glib::ControlFlow::Break;
            }
            progress.set_fraction(f64::from(next) / 100.0);
            if next == 100 {
                status.set_label("Task complete");
                *active.borrow_mut() = None;
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    });
    let state_for_cancel = Rc::clone(state);
    let active_for_cancel = Rc::clone(&active);
    cancel.connect_clicked(move |_| {
        if let Some((job, _)) = *active_for_cancel.borrow() {
            state_for_cancel.borrow_mut().cancel_job(job);
        }
    });
    let state_for_fail = Rc::clone(state);
    let active_for_fail = Rc::clone(&active);
    let status_for_fail = status.clone();
    fail.connect_clicked(move |_| {
        if let Some((job, generation)) = *active_for_fail.borrow()
            && state_for_fail.borrow_mut().fail_job(job, generation)
        {
            status_for_fail.set_label("A background operation stopped. Review the task and retry.");
        }
    });
    gtk::ScrolledWindow::builder().child(&page).build().upcast()
}

fn labelled<W: IsA<gtk::Widget> + IsA<gtk::Accessible>>(name: &str, widget: &W) -> gtk::Box {
    widget.update_property(&[gtk::accessible::Property::Label(name)]);
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.append(
        &gtk::Label::builder()
            .label(name)
            .xalign(0.0)
            .width_chars(18)
            .build(),
    );
    row.append(widget);
    row
}

fn preferences_page(
    state: &Rc<RefCell<ShellState>>,
    css_slots: &Rc<CssSlots>,
    set_panel: &Rc<dyn Fn(PanelPlacement)>,
) -> gtk::Widget {
    let page = page("Appearance and shortcuts");
    let themes = gtk::DropDown::from_strings(&["System", "Light", "Dark", "High contrast"]);
    let densities = gtk::DropDown::from_strings(&["Compact", "Comfortable", "Spacious"]);
    densities.set_selected(1);
    let panels = gtk::DropDown::from_strings(&["Start", "End", "Top", "Hidden"]);
    let spacing = gtk::Scale::with_range(gtk::Orientation::Horizontal, 2.0, 32.0, 1.0);
    spacing.set_value(8.0);
    let font_family = gtk::Entry::builder().placeholder_text("Sans").build();
    let font_size = gtk::SpinButton::with_range(9.0, 24.0, 1.0);
    font_size.set_value(11.0);
    let accent = gtk::Entry::builder().placeholder_text("#6272a4").build();
    for (name, widget) in [
        ("Theme", themes.clone().upcast::<gtk::Widget>()),
        ("Density", densities.clone().upcast()),
        ("Panel placement", panels.clone().upcast()),
        ("Spacing", spacing.clone().upcast()),
        ("Font family", font_family.clone().upcast()),
        ("Font size", font_size.clone().upcast()),
        ("Accent color", accent.clone().upcast()),
    ] {
        page.append(&labelled(name, &widget));
    }
    let shortcut_command =
        gtk::DropDown::from_strings(&["Lock", "Search", "Gallery", "Tasks", "Preferences"]);
    let shortcut = gtk::Entry::builder().placeholder_text("<Primary>l").build();
    let assign_shortcut = gtk::Button::with_mnemonic("_Assign shortcut");
    let shortcut_status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    page.append(&labelled("Shortcut command", &shortcut_command));
    page.append(&labelled("Shortcut", &shortcut));
    page.append(&assign_shortcut);
    page.append(&shortcut_status);
    let user_css = gtk::TextView::builder()
        .monospace(true)
        .height_request(120)
        .build();
    let css_status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    let apply_css = gtk::Button::with_mnemonic("_Apply user CSS safely");
    let reset_css = gtk::Button::with_mnemonic("_Reset user CSS");
    page.append(&labelled("User CSS", &user_css));
    page.append(&apply_css);
    page.append(&reset_css);
    page.append(&css_status);

    let slots = Rc::clone(css_slots);
    let state_for_theme = Rc::clone(state);
    themes.connect_selected_notify(move |value| {
        let mut state = state_for_theme.borrow_mut();
        state.appearance.theme = match value.selected() {
            1 => Theme::Light,
            2 => Theme::Dark,
            3 => Theme::HighContrast,
            _ => Theme::System,
        };
        slots.set_appearance(&state.appearance);
    });
    let slots = Rc::clone(css_slots);
    let state_for_density = Rc::clone(state);
    densities.connect_selected_notify(move |value| {
        let mut state = state_for_density.borrow_mut();
        state.appearance.density = match value.selected() {
            0 => Density::Compact,
            2 => Density::Spacious,
            _ => Density::Comfortable,
        };
        slots.set_appearance(&state.appearance);
    });
    let state_for_panel = Rc::clone(state);
    let set_panel = Rc::clone(set_panel);
    panels.connect_selected_notify(move |value| {
        let placement = match value.selected() {
            1 => PanelPlacement::End,
            2 => PanelPlacement::Top,
            3 => PanelPlacement::Hidden,
            _ => PanelPlacement::Start,
        };
        state_for_panel.borrow_mut().appearance.panel = placement;
        set_panel(placement);
    });
    {
        let state = Rc::clone(state);
        let spacing = spacing.clone();
        let font_size = font_size.clone();
        let slots = Rc::clone(css_slots);
        spacing.clone().connect_value_changed(move |_| {
            let mut state = state.borrow_mut();
            state.appearance.spacing = spacing.value() as u8;
            state.appearance.font_size = font_size.value() as u8;
            slots.set_appearance(&state.appearance);
        });
    }
    {
        let state = Rc::clone(state);
        let spacing = spacing.clone();
        let font_size = font_size.clone();
        let slots = Rc::clone(css_slots);
        font_size.clone().connect_value_changed(move |_| {
            let mut state = state.borrow_mut();
            state.appearance.spacing = spacing.value() as u8;
            state.appearance.font_size = font_size.value() as u8;
            slots.set_appearance(&state.appearance);
        });
    }
    for (entry, slots) in [
        (&font_family, Rc::clone(css_slots)),
        (&accent, Rc::clone(css_slots)),
    ] {
        let state = Rc::clone(state);
        let family = font_family.clone();
        let accent = accent.clone();
        entry.connect_changed(move |_| {
            let mut state = state.borrow_mut();
            state.appearance.font_family = family.text().into();
            state.appearance.accent = accent.text().into();
            state.appearance.normalize();
            slots.set_appearance(&state.appearance);
        });
    }
    let state_for_shortcut = Rc::clone(state);
    assign_shortcut.connect_clicked(move |_| {
        let command = match shortcut_command.selected() {
            0 => Command::Lock,
            1 => Command::Search,
            2 => Command::Gallery,
            3 => Command::Tasks,
            _ => Command::Preferences,
        };
        let accelerator = shortcut.text();
        let result = if gtk::accelerator_parse(&accelerator).is_none() {
            Err(crate::ShortcutError::Invalid)
        } else {
            state_for_shortcut
                .borrow_mut()
                .shortcuts
                .assign(command, &accelerator)
        };
        match result {
            Ok(()) => shortcut_status.set_label("Shortcut assigned."),
            Err(error) => shortcut_status.set_label(&error.to_string()),
        }
    });
    let slots = Rc::clone(css_slots);
    apply_css.connect_clicked(move |_| {
        let buffer = user_css.buffer();
        let value = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
        let outcome = accept_user_css(&value, css_parses);
        match outcome {
            CssOutcome::Applied => {
                slots.set_user(&value);
                css_status.set_label("Custom CSS applied.");
            }
            CssOutcome::Rejected { fallback } => {
                slots.set_user("");
                css_status.set_label(fallback);
            }
        }
    });
    let slots = Rc::clone(css_slots);
    reset_css.connect_clicked(move |_| slots.set_user(""));
    gtk::ScrolledWindow::builder().child(&page).build().upcast()
}

fn css_parses(css: &str) -> bool {
    let provider = gtk::CssProvider::new();
    let failed = Rc::new(Cell::new(false));
    let signal_failed = Rc::clone(&failed);
    provider.connect_parsing_error(move |_, _, _| signal_failed.set(true));
    provider.load_from_string(css);
    !failed.get()
}

fn show_error(stack: &gtk::Stack, message: &str) {
    if let Some(existing) = stack.child_by_name("error") {
        stack.remove(&existing);
    }
    let box_ = page("Something went wrong");
    let detail = gtk::Label::builder()
        .label(message)
        .wrap(true)
        .xalign(0.0)
        .build();
    detail.add_css_class("osv-error");
    detail.update_property(&[gtk::accessible::Property::Label("Error message")]);
    let back = gtk::Button::with_mnemonic("_Back to vault chooser");
    let stack_for_back = stack.clone();
    back.connect_clicked(move |_| stack_for_back.set_visible_child_name("choose"));
    box_.append(&detail);
    box_.append(&back);
    stack.add_named(&box_, Some("error"));
    stack.set_visible_child_name("error");
}

impl fmt::Debug for CssSlots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CssSlots")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtk_dialog_dismissal_is_portal_cancellation() {
        let dismissed = glib::Error::new(gtk::DialogError::Dismissed, "dismissed");
        assert!(portal_error_is_cancelled(&dismissed));
        let failed = glib::Error::new(gtk::DialogError::Failed, "failed");
        assert!(!portal_error_is_cancelled(&failed));
    }
}
