use serde::Serialize;
use tauri::menu::{Menu, MenuItem, Submenu};
use tauri::{AppHandle, Emitter, Runtime};

pub const MENU_EVENT_APP_ACTION: &str = "app-menu-action";
pub const MENU_EVENT_LOG_PRESET_SELECTED: &str = "log-preset-selected";

pub const MENU_ID_FILE_OPEN_LOG_FILE: &str = "file.open_log_file";
pub const MENU_ID_FILE_OPEN_LOG_FOLDER: &str = "file.open_log_folder";
pub const MENU_ID_FILE_QUIT: &str = "file.quit";

pub const MENU_ID_EDIT_FIND: &str = "edit.find";
pub const MENU_ID_EDIT_FILTER: &str = "edit.filter";

pub const MENU_ID_TOOLS_ERROR_LOOKUP: &str = "tools.error_lookup";

pub const MENU_ID_WINDOW_TOGGLE_DETAILS: &str = "window.toggle.details";
pub const MENU_ID_WINDOW_TOGGLE_INFO: &str = "window.toggle.info";
pub const MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS: &str = "window.accessibility.settings";
pub const MENU_ID_HELP_ABOUT: &str = "help.about";

pub const MENU_ID_PRESET_WINDOWS_IME: &str = "preset.windows.ime";

#[derive(Debug, Clone, Serialize)]
pub struct AppMenuActionPayload {
    pub version: u8,
    pub menu_id: &'static str,
    pub action: &'static str,
    pub category: &'static str,
    pub trigger: &'static str,
    pub preset_id: Option<&'static str>,
    pub platform: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogPresetSelectionPayload {
    pub preset_id: &'static str,
    pub platform: &'static str,
    pub trigger: &'static str,
}

pub fn build_app_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let open_log_file =
        MenuItem::with_id(app, MENU_ID_FILE_OPEN_LOG_FILE, "Open Log File...", true, None::<&str>)?;
    let open_log_folder = MenuItem::with_id(
        app,
        MENU_ID_FILE_OPEN_LOG_FOLDER,
        "Open Log Folder...",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, MENU_ID_FILE_QUIT, "Exit", true, None::<&str>)?;
    let known_sources = build_known_sources_submenu(app)?;

    let find = MenuItem::with_id(app, MENU_ID_EDIT_FIND, "Find...", true, Some("Ctrl+F"))?;
    let filter = MenuItem::with_id(
        app,
        MENU_ID_EDIT_FILTER,
        "Filter...",
        true,
        Some("Ctrl+L"),
    )?;

    let error_lookup = MenuItem::with_id(
        app,
        MENU_ID_TOOLS_ERROR_LOOKUP,
        "Lookup Error Code...",
        true,
        None::<&str>,
    )?;

    let toggle_details = MenuItem::with_id(
        app,
        MENU_ID_WINDOW_TOGGLE_DETAILS,
        "Toggle Details Pane",
        true,
        None::<&str>,
    )?;
    let toggle_info = MenuItem::with_id(
        app,
        MENU_ID_WINDOW_TOGGLE_INFO,
        "Toggle Info Pane",
        true,
        None::<&str>,
    )?;
    let accessibility_settings = MenuItem::with_id(
        app,
        MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS,
        "Accessibility Settings...",
        true,
        None::<&str>,
    )?;
    let about = MenuItem::with_id(app, MENU_ID_HELP_ABOUT, "About CMTrace Open", true, None::<&str>)?;

    let file_menu = Submenu::with_items(
        app,
        "File",
        true,
        &[&open_log_file, &open_log_folder, &known_sources, &quit],
    )?;
    let edit_menu = Submenu::with_items(app, "Edit", true, &[&find, &filter])?;
    let tools_menu = Submenu::with_items(app, "Tools", true, &[&error_lookup])?;
    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &toggle_details,
            &toggle_info,
            &accessibility_settings,
        ],
    )?;
    let help_menu = Submenu::with_items(app, "Help", true, &[&about])?;

    Menu::with_items(app, &[&file_menu, &edit_menu, &tools_menu, &window_menu, &help_menu])
}

fn build_known_sources_submenu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Submenu<R>> {
    #[cfg(target_os = "windows")]
    {
        let windows_ime = MenuItem::with_id(
            app,
            MENU_ID_PRESET_WINDOWS_IME,
            "Windows Intune IME Logs",
            true,
            None::<&str>,
        )?;

        let windows_sources = Submenu::with_items(app, "Windows", true, &[&windows_ime])?;
        Submenu::with_items(app, "Known Log Sources", true, &[&windows_sources])
    }

    #[cfg(not(target_os = "windows"))]
    {
        let placeholder = MenuItem::with_id(
            app,
            "preset.unavailable",
            "No known source presets are available on this platform yet",
            false,
            None::<&str>,
        )?;

        Submenu::with_items(app, "Known Log Sources", true, &[&placeholder])
    }
}

pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, menu_id: &str) {
    if menu_id == MENU_ID_FILE_QUIT {
        app.exit(0);
        return;
    }

    let Some(payload) = payload_for_menu_id(menu_id) else {
        return;
    };

    if let Err(error) = app.emit(MENU_EVENT_APP_ACTION, payload.clone()) {
        eprintln!("failed to emit app menu action event: {error}");
    }

    let Some(preset_payload) = legacy_preset_payload_for_action(&payload) else {
        return;
    };

    if let Err(error) = app.emit(MENU_EVENT_LOG_PRESET_SELECTED, preset_payload) {
        eprintln!("failed to emit legacy menu preset selection event: {error}");
    }
}

fn payload_for_menu_id(menu_id: &str) -> Option<AppMenuActionPayload> {
    let payload = match menu_id {
        MENU_ID_FILE_OPEN_LOG_FILE => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_FILE_OPEN_LOG_FILE,
            action: "open_log_file_dialog",
            category: "file",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_FILE_OPEN_LOG_FOLDER => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_FILE_OPEN_LOG_FOLDER,
            action: "open_log_folder_dialog",
            category: "file",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_EDIT_FIND => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_EDIT_FIND,
            action: "show_find",
            category: "edit",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_EDIT_FILTER => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_EDIT_FILTER,
            action: "show_filter",
            category: "edit",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_TOOLS_ERROR_LOOKUP => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_TOOLS_ERROR_LOOKUP,
            action: "show_error_lookup",
            category: "tools",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_WINDOW_TOGGLE_DETAILS => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_TOGGLE_DETAILS,
            action: "toggle_details",
            category: "window",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_WINDOW_TOGGLE_INFO => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_TOGGLE_INFO,
            action: "toggle_info_pane",
            category: "window",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_HELP_ABOUT => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_HELP_ABOUT,
            action: "show_about",
            category: "help",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS,
            action: "show_accessibility_settings",
            category: "window",
            trigger: "menu",
            preset_id: None,
            platform: None,
        },
        MENU_ID_PRESET_WINDOWS_IME => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_PRESET_WINDOWS_IME,
            action: "load_known_source_preset",
            category: "preset",
            trigger: "menu",
            preset_id: Some(MENU_ID_PRESET_WINDOWS_IME),
            platform: Some("windows"),
        },
        _ => return None,
    };

    Some(payload)
}

fn legacy_preset_payload_for_action(payload: &AppMenuActionPayload) -> Option<LogPresetSelectionPayload> {
    let preset_id = payload.preset_id?;
    let platform = payload.platform?;

    Some(LogPresetSelectionPayload {
        preset_id,
        platform,
        trigger: payload.trigger,
    })
}

