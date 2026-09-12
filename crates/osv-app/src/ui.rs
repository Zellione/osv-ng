//! GTK presentation layer. It deliberately owns no vault or storage implementation.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::{gdk, gio, glib, prelude::*};

use crate::{
    Appearance, Command, CssOutcome, Density, PanelPlacement, Route, ShellState, Theme,
    accept_user_css,
};

const APP_ID: &str = "io.github.osv_ng.App";
const BASE_CSS: &str = r#"
.osv-shell { background: @theme_bg_color; color: @theme_fg_color; }
.osv-sidebar { padding: 12px; border-right: 1px solid alpha(currentColor, .14); }
.osv-gallery { padding: 8px; }
.osv-tile { min-width: 128px; min-height: 112px; border-radius: 8px;
            background: alpha(@theme_fg_color, .08); padding: 12px; }
.osv-error { background: alpha(#d33, .18); padding: 10px; }
"#;

pub fn run() -> glib::ExitCode {
    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| install_css(BASE_CSS, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION));
    app.connect_activate(build_window);
    app.run()
}

fn install_css(css: &str, priority: u32) {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(css);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &provider, priority);
    }
}

fn build_window(app: &gtk::Application) {
    let state = Rc::new(RefCell::new(ShellState::default()));
    let stack = gtk::Stack::builder().hexpand(true).vexpand(true).build();
    stack.add_named(&welcome_page(&state, &stack), Some("choose"));
    stack.add_named(&unlock_page(&state, &stack), Some("unlock"));
    stack.add_named(&create_page(&state, &stack), Some("create"));
    stack.add_named(&vault_page(&state, &stack), Some("vault"));
    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Obscura Safe Vault")
        .default_width(1100)
        .default_height(760)
        .child(&stack)
        .build();
    window.add_css_class("osv-shell");
    install_keyboard(&window, &state, &stack);
    window.present();
}

fn install_keyboard(
    window: &gtk::ApplicationWindow,
    state: &Rc<RefCell<ShellState>>,
    outer: &gtk::Stack,
) {
    let keys = gtk::EventControllerKey::new();
    let state = Rc::clone(state);
    let outer = outer.clone();
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
                    expected_key == key && expected_modifiers == modifiers
                })
        });
        let Some(command) = command else {
            return glib::Propagation::Proceed;
        };
        if state.borrow_mut().activate(command) {
            sync_route(&outer, state.borrow().route());
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    window.add_controller(keys);
}

fn sync_route(outer: &gtk::Stack, route: Route) {
    if route == Route::Choose {
        outer.set_visible_child_name("choose");
        return;
    }
    outer.set_visible_child_name("vault");
    let Some(vault) = outer.child_by_name("vault") else {
        return;
    };
    let Some(root) = vault.downcast_ref::<gtk::Box>() else {
        return;
    };
    let Some(content) = root.last_child().and_downcast::<gtk::Stack>() else {
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
        let dialog = gtk::FileDialog::builder()
            .title("Choose a vault folder")
            .modal(true)
            .build();
        let parent = button.root().and_downcast::<gtk::Window>();
        let state = Rc::clone(&state_for_choose);
        let stack = stack_for_choose.clone();
        dialog.select_folder(
            parent.as_ref(),
            gio::Cancellable::NONE,
            move |result| match result {
                Ok(_) => {
                    state.borrow_mut().navigate(Route::Unlock);
                    stack.set_visible_child_name("unlock");
                }
                Err(error) if error.matches(gio::IOErrorEnum::Cancelled) => {}
                Err(_) => show_error(&stack, "The folder chooser could not be opened. Try again."),
            },
        );
    });
    let state = Rc::clone(state);
    let stack = stack.clone();
    create.connect_clicked(move |_| {
        state.borrow_mut().navigate(Route::Create);
        stack.set_visible_child_name("create");
    });
    page.upcast()
}

fn unlock_page(state: &Rc<RefCell<ShellState>>, stack: &gtk::Stack) -> gtk::Widget {
    let page = page("Unlock vault");
    let password = gtk::PasswordEntry::builder()
        .placeholder_text("Password")
        .show_peek_icon(true)
        .build();
    let unlock = gtk::Button::with_mnemonic("_Unlock");
    page.append(&password);
    page.append(&unlock);
    let state = Rc::clone(state);
    let stack = stack.clone();
    unlock.connect_clicked(move |_| {
        // Authentication is a service seam; Phase 8 proves only the shell boundary.
        state.borrow_mut().unlock();
        password.set_text("");
        stack.set_visible_child_name("vault");
    });
    page.upcast()
}

fn create_page(state: &Rc<RefCell<ShellState>>, stack: &gtk::Stack) -> gtk::Widget {
    let page = page("Create vault");
    let location = gtk::Button::with_mnemonic("Choose _location…");
    let back = gtk::Button::with_mnemonic("_Back");
    page.append(&location);
    page.append(&back);
    location.connect_clicked(move |button| {
        let dialog = gtk::FileDialog::builder()
            .title("Choose where to create the vault")
            .modal(true)
            .build();
        let parent = button.root().and_downcast::<gtk::Window>();
        dialog.select_folder(parent.as_ref(), gio::Cancellable::NONE, |_| {});
    });
    let state = Rc::clone(state);
    let stack = stack.clone();
    back.connect_clicked(move |_| {
        state.borrow_mut().navigate(Route::Choose);
        stack.set_visible_child_name("choose");
    });
    page.upcast()
}

fn vault_page(state: &Rc<RefCell<ShellState>>, outer: &gtk::Stack) -> gtk::Widget {
    let root = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 6);
    sidebar.add_css_class("osv-sidebar");
    let content = gtk::Stack::builder().hexpand(true).vexpand(true).build();
    content.add_named(&gallery_view(100_000), Some("gallery"));
    content.add_named(
        &simple_page("Search", "Search is ready for catalog integration."),
        Some("search"),
    );
    content.add_named(
        &simple_page(
            "Background tasks",
            "Progress, cancellation, and failures appear here.",
        ),
        Some("tasks"),
    );
    content.add_named(&preferences_page(state), Some("preferences"));
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
    let state = Rc::clone(state);
    let outer = outer.clone();
    lock.connect_clicked(move |_| {
        state.borrow_mut().lock();
        outer.set_visible_child_name("choose");
    });
    root.append(&sidebar);
    root.append(&content);
    root.upcast()
}

fn gallery_view(items: u32) -> gtk::Widget {
    let model = gtk::StringList::new(&[]);
    for index in 0..items {
        model.append(&format!("Item {:06}", index + 1));
    }
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

fn preferences_page(state: &Rc<RefCell<ShellState>>) -> gtk::Widget {
    let page = page("Appearance and shortcuts");
    let themes = gtk::DropDown::from_strings(&["System", "Light", "Dark", "High contrast"]);
    let densities = gtk::DropDown::from_strings(&["Compact", "Comfortable", "Spacious"]);
    densities.set_selected(1);
    let panels = gtk::DropDown::from_strings(&["Start", "End", "Top", "Hidden"]);
    let spacing = gtk::Scale::with_range(gtk::Orientation::Horizontal, 2.0, 32.0, 1.0);
    spacing.set_value(8.0);
    let font_family = gtk::Entry::builder()
        .placeholder_text("Font family: Sans")
        .build();
    let font_size = gtk::SpinButton::with_range(9.0, 24.0, 1.0);
    font_size.set_value(11.0);
    let accent = gtk::Entry::builder()
        .placeholder_text("Accent color: #6272a4")
        .build();
    let css = gtk::TextView::builder()
        .monospace(true)
        .height_request(120)
        .build();
    let status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    let apply = gtk::Button::with_mnemonic("_Apply user CSS safely");
    page.append(&themes);
    page.append(&densities);
    page.append(&panels);
    page.append(&spacing);
    page.append(&font_family);
    page.append(&font_size);
    page.append(&accent);
    let shortcut_command =
        gtk::DropDown::from_strings(&["Lock", "Search", "Gallery", "Tasks", "Preferences"]);
    let shortcut = gtk::Entry::builder()
        .placeholder_text("Shortcut, e.g. <Primary>l")
        .build();
    let assign_shortcut = gtk::Button::with_mnemonic("_Assign shortcut");
    let shortcut_status = gtk::Label::builder().xalign(0.0).wrap(true).build();
    page.append(&shortcut_command);
    page.append(&shortcut);
    page.append(&assign_shortcut);
    page.append(&shortcut_status);
    page.append(&css);
    page.append(&apply);
    page.append(&status);
    let state_for_spacing = Rc::clone(state);
    spacing.connect_value_changed(move |scale| {
        let mut state = state_for_spacing.borrow_mut();
        state.appearance.spacing = scale.value() as u8;
        install_appearance(&state.appearance);
    });
    let state_for_theme = Rc::clone(state);
    themes.connect_selected_notify(move |dropdown| {
        let mut state = state_for_theme.borrow_mut();
        state.appearance.theme = match dropdown.selected() {
            1 => Theme::Light,
            2 => Theme::Dark,
            3 => Theme::HighContrast,
            _ => Theme::System,
        };
        install_appearance(&state.appearance);
    });
    let state_for_density = Rc::clone(state);
    densities.connect_selected_notify(move |dropdown| {
        let mut state = state_for_density.borrow_mut();
        state.appearance.density = match dropdown.selected() {
            0 => Density::Compact,
            2 => Density::Spacious,
            _ => Density::Comfortable,
        };
        install_appearance(&state.appearance);
    });
    let state_for_panel = Rc::clone(state);
    panels.connect_selected_notify(move |dropdown| {
        state_for_panel.borrow_mut().appearance.panel = match dropdown.selected() {
            1 => PanelPlacement::End,
            2 => PanelPlacement::Top,
            3 => PanelPlacement::Hidden,
            _ => PanelPlacement::Start,
        };
    });
    let state_for_family = Rc::clone(state);
    font_family.connect_changed(move |entry| {
        let mut state = state_for_family.borrow_mut();
        state.appearance.font_family = entry.text().into();
        state.appearance.normalize();
        install_appearance(&state.appearance);
    });
    let state_for_font_size = Rc::clone(state);
    font_size.connect_value_changed(move |spin| {
        let mut state = state_for_font_size.borrow_mut();
        state.appearance.font_size = spin.value() as u8;
        install_appearance(&state.appearance);
    });
    let state_for_accent = Rc::clone(state);
    accent.connect_changed(move |entry| {
        let mut state = state_for_accent.borrow_mut();
        state.appearance.accent = entry.text().into();
        state.appearance.normalize();
        install_appearance(&state.appearance);
    });
    let state_for_shortcut = Rc::clone(state);
    assign_shortcut.connect_clicked(move |_| {
        let command = match shortcut_command.selected() {
            0 => Command::Lock,
            1 => Command::Search,
            2 => Command::Gallery,
            3 => Command::Tasks,
            _ => Command::Preferences,
        };
        match state_for_shortcut
            .borrow_mut()
            .shortcuts
            .assign(command, &shortcut.text())
        {
            Ok(()) => shortcut_status.set_label("Shortcut assigned."),
            Err(error) => shortcut_status.set_label(&error.to_string()),
        }
    });
    apply.connect_clicked(move |_| {
        let buffer = css.buffer();
        let value = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
        let parsed_provider = Rc::new(RefCell::new(None));
        let provider_result = Rc::clone(&parsed_provider);
        let outcome = accept_user_css(&value, move |candidate| {
            let provider = gtk::CssProvider::new();
            let failed = Rc::new(Cell::new(false));
            let signal_failed = Rc::clone(&failed);
            provider.connect_parsing_error(move |_, _, _| signal_failed.set(true));
            provider.load_from_string(candidate);
            let accepted = !failed.get();
            if accepted {
                *provider_result.borrow_mut() = Some(provider);
            }
            accepted
        });
        match outcome {
            CssOutcome::Applied => {
                if let Some(provider) = parsed_provider.borrow().as_ref()
                    && let Some(display) = gdk::Display::default()
                {
                    gtk::style_context_add_provider_for_display(
                        &display,
                        provider,
                        gtk::STYLE_PROVIDER_PRIORITY_USER,
                    );
                }
                status.set_label("Custom CSS applied.");
            }
            CssOutcome::Rejected { fallback } => status.set_label(fallback),
        }
    });
    page.upcast()
}

fn install_appearance(appearance: &Appearance) {
    install_css(
        &appearance.css(),
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
    );
}

fn show_error(stack: &gtk::Stack, message: &str) {
    let label = gtk::Label::builder()
        .label(message)
        .wrap(true)
        .selectable(true)
        .build();
    label.add_css_class("osv-error");
    stack.add_named(&label, Some("error"));
    stack.set_visible_child_name("error");
}
