use std::collections::BTreeMap;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, Submenu};
use tauri::{AppHandle, Emitter, Runtime};

use crate::commands::file_ops::{build_known_log_sources, KnownSourceGroupingMetadata};

pub const MENU_EVENT_APP_ACTION: &str = "app-menu-action";

pub const MENU_ID_FILE_OPEN_LOG_FILE: &str = "file.open_log_file";
pub const MENU_ID_FILE_OPEN_LOG_FOLDER: &str = "file.open_log_folder";
pub const MENU_ID_FILE_QUIT: &str = "file.quit";

pub const MENU_ID_EDIT_FIND: &str = "edit.find";
pub const MENU_ID_EDIT_FILTER: &str = "edit.filter";

pub const MENU_ID_TOOLS_ERROR_LOOKUP: &str = "tools.error_lookup";
pub const MENU_ID_TOOLS_BUNDLE_SUMMARY: &str = "tools.bundle_summary";

pub const MENU_ID_WINDOW_TOGGLE_DETAILS: &str = "window.toggle.details";
pub const MENU_ID_WINDOW_TOGGLE_INFO: &str = "window.toggle.info";
pub const MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS: &str = "window.accessibility.settings";
pub const MENU_ID_HELP_ABOUT: &str = "help.about";

const KNOWN_SOURCE_MENU_ID_PREFIX: &str = "known-source.";

#[derive(Debug, Clone, Serialize)]
pub struct AppMenuActionPayload {
    pub version: u8,
    pub menu_id: String,
    pub action: String,
    pub category: String,
    pub trigger: String,
    pub source_id: Option<String>,
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
    let bundle_summary = MenuItem::with_id(
        app,
        MENU_ID_TOOLS_BUNDLE_SUMMARY,
        "Bundle Summary...",
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
    let tools_menu = Submenu::with_items(app, "Tools", true, &[&error_lookup, &bundle_summary])?;
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

/// A source entry extracted from the catalog for menu building.
struct SourceMenuItem {
    id: String,
    label: String,
    source_order: u32,
}

/// Build the "Known Log Sources" submenu dynamically from the catalog.
///
/// Sources are grouped by their `KnownSourceGroupingMetadata`:
///   Family (e.g. "Windows Intune") > Group (e.g. "Intune IME") > individual sources
///
/// Ungrouped sources (grouping == None) are added directly at the top level.
fn build_known_sources_submenu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Submenu<R>> {
    let sources = build_known_log_sources();

    if sources.is_empty() {
        let placeholder = MenuItem::with_id(
            app,
            "known-source.unavailable",
            "No known log sources available on this platform",
            false,
            None::<&str>,
        )?;
        return Submenu::with_items(app, "Known Log Sources", true, &[&placeholder]);
    }

    // Group sources: family_id -> (family_label, family_order, group_id -> (group_label, group_order, sources))
    // Use BTreeMap with (order, id) keys to maintain catalog ordering.
    type GroupMap = BTreeMap<(u32, String), (String, Vec<SourceMenuItem>)>;
    type FamilyMap = BTreeMap<(u32, String), (String, GroupMap)>;

    let mut families: FamilyMap = BTreeMap::new();
    let mut ungrouped: Vec<SourceMenuItem> = Vec::new();

    for source in &sources {
        let menu_id = format!("{}{}", KNOWN_SOURCE_MENU_ID_PREFIX, source.id);

        match &source.grouping {
            Some(KnownSourceGroupingMetadata {
                family_id,
                family_label,
                group_id,
                group_label,
                group_order,
                source_order,
            }) => {
                // Derive family_order from the minimum group_order within the family.
                let family_key = (0, family_id.clone());
                let family_entry = families
                    .entry(family_key)
                    .or_insert_with(|| (family_label.clone(), BTreeMap::new()));

                // Update the family key order to use the minimum group_order seen.
                let group_key = (*group_order, group_id.clone());
                let group_entry = family_entry
                    .1
                    .entry(group_key)
                    .or_insert_with(|| (group_label.clone(), Vec::new()));

                group_entry.1.push(SourceMenuItem {
                    id: menu_id,
                    label: source.label.clone(),
                    source_order: *source_order,
                });
            }
            None => {
                ungrouped.push(SourceMenuItem {
                    id: menu_id,
                    label: source.label.clone(),
                    source_order: 0,
                });
            }
        }
    }

    // Now fix family ordering: use the minimum group_order within each family.
    // We need to rebuild with correct family_order keys.
    let mut ordered_families: FamilyMap = BTreeMap::new();
    for ((_order, family_id), (family_label, groups)) in families {
        let min_group_order = groups.keys().map(|(order, _)| *order).min().unwrap_or(0);
        ordered_families.insert((min_group_order, family_id), (family_label, groups));
    }

    let mut top_level_items: Vec<Submenu<R>> = Vec::new();

    for ((_family_order, _family_id), (family_label, groups)) in &ordered_families {
        let mut group_submenus: Vec<Submenu<R>> = Vec::new();

        for ((_group_order, _group_id), (group_label, items)) in groups {
            let mut sorted_items = items.clone();
            sorted_items.sort_by_key(|item| item.source_order);

            let mut menu_items: Vec<MenuItem<R>> = Vec::new();
            for item in &sorted_items {
                menu_items.push(MenuItem::with_id(
                    app,
                    &item.id,
                    &item.label,
                    true,
                    None::<&str>,
                )?);
            }

            let item_refs: Vec<&MenuItem<R>> = menu_items.iter().collect();
            let items_as_refs: Vec<&dyn tauri::menu::IsMenuItem<R>> =
                item_refs.iter().map(|item| *item as &dyn tauri::menu::IsMenuItem<R>).collect();

            group_submenus.push(Submenu::with_items(
                app,
                group_label.as_str(),
                true,
                &items_as_refs,
            )?);
        }

        let submenu_refs: Vec<&dyn tauri::menu::IsMenuItem<R>> =
            group_submenus.iter().map(|s| s as &dyn tauri::menu::IsMenuItem<R>).collect();

        top_level_items.push(Submenu::with_items(
            app,
            family_label.as_str(),
            true,
            &submenu_refs,
        )?);
    }

    // Add ungrouped sources directly.
    let mut ungrouped_menu_items: Vec<MenuItem<R>> = Vec::new();
    for item in &ungrouped {
        ungrouped_menu_items.push(MenuItem::with_id(
            app,
            &item.id,
            &item.label,
            true,
            None::<&str>,
        )?);
    }

    let mut all_items: Vec<&dyn tauri::menu::IsMenuItem<R>> =
        top_level_items.iter().map(|s| s as &dyn tauri::menu::IsMenuItem<R>).collect();
    for item in &ungrouped_menu_items {
        all_items.push(item as &dyn tauri::menu::IsMenuItem<R>);
    }

    Submenu::with_items(app, "Known Log Sources", true, &all_items)
}

// Allow Clone on SourceMenuItem for sorting.
impl Clone for SourceMenuItem {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            label: self.label.clone(),
            source_order: self.source_order,
        }
    }
}

pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, menu_id: &str) {
    if menu_id == MENU_ID_FILE_QUIT {
        app.exit(0);
        return;
    }

    let Some(payload) = payload_for_menu_id(menu_id) else {
        eprintln!("[menu] unrecognized menu_id: {menu_id}");
        return;
    };

    if let Err(error) = app.emit(MENU_EVENT_APP_ACTION, payload) {
        eprintln!("failed to emit app menu action event: {error}");
    }
}

fn payload_for_menu_id(menu_id: &str) -> Option<AppMenuActionPayload> {
    // Handle dynamic known-source menu items.
    if let Some(source_id) = menu_id.strip_prefix(KNOWN_SOURCE_MENU_ID_PREFIX) {
        return Some(AppMenuActionPayload {
            version: 1,
            menu_id: menu_id.to_string(),
            action: "open_known_source".to_string(),
            category: "known_source".to_string(),
            trigger: "menu".to_string(),
            source_id: Some(source_id.to_string()),
        });
    }

    let payload = match menu_id {
        MENU_ID_FILE_OPEN_LOG_FILE => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_FILE_OPEN_LOG_FILE.to_string(),
            action: "open_log_file_dialog".to_string(),
            category: "file".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_FILE_OPEN_LOG_FOLDER => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_FILE_OPEN_LOG_FOLDER.to_string(),
            action: "open_log_folder_dialog".to_string(),
            category: "file".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_EDIT_FIND => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_EDIT_FIND.to_string(),
            action: "show_find".to_string(),
            category: "edit".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_EDIT_FILTER => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_EDIT_FILTER.to_string(),
            action: "show_filter".to_string(),
            category: "edit".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_TOOLS_ERROR_LOOKUP => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_TOOLS_ERROR_LOOKUP.to_string(),
            action: "show_error_lookup".to_string(),
            category: "tools".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_TOOLS_BUNDLE_SUMMARY => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_TOOLS_BUNDLE_SUMMARY.to_string(),
            action: "show_evidence_bundle".to_string(),
            category: "tools".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_WINDOW_TOGGLE_DETAILS => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_TOGGLE_DETAILS.to_string(),
            action: "toggle_details".to_string(),
            category: "window".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_WINDOW_TOGGLE_INFO => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_TOGGLE_INFO.to_string(),
            action: "toggle_info_pane".to_string(),
            category: "window".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_HELP_ABOUT => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_HELP_ABOUT.to_string(),
            action: "show_about".to_string(),
            category: "help".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS => AppMenuActionPayload {
            version: 1,
            menu_id: MENU_ID_WINDOW_ACCESSIBILITY_SETTINGS.to_string(),
            action: "show_accessibility_settings".to_string(),
            category: "window".to_string(),
            trigger: "menu".to_string(),
            source_id: None,
        },
        _ => return None,
    };

    Some(payload)
}
