use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::menu::{
    CheckMenuItem, Menu, MenuItem, MenuItemKind, PredefinedMenuItem, Submenu, HELP_SUBMENU_ID,
};
use tauri::{AppHandle, Emitter, Runtime};

use crate::commands::app_config::get_available_workspaces;
use crate::commands::known_sources::{build_known_log_sources, KnownSourceGroupingMetadata};
use crate::commands::recent_entries::{
    normalize_path, RecentEntriesState, RecentEntry, RecentEntryKind,
};

pub const MENU_EVENT_APP_ACTION: &str = "app-menu-action";

const MENU_ID_APP: &str = "app.menu";
const MENU_ID_FILE: &str = "file.menu";
const MENU_ID_EDIT: &str = "edit.menu";
const MENU_ID_VIEW: &str = "view.menu";
const MENU_ID_WORKSPACE: &str = "workspace.menu";
const MENU_ID_TOOLS: &str = "tools.menu";

pub const MENU_ID_FILE_OPEN_LOG_FILE: &str = "file.open_log_file";
pub const MENU_ID_FILE_OPEN_LOG_FOLDER: &str = "file.open_log_folder";
pub const MENU_ID_FILE_KNOWN_SOURCES: &str = "file.known_sources";
pub const MENU_ID_FILE_RECENT: &str = "file.recent";
pub const MENU_ID_FILE_RECENT_CLEAR: &str = "file.recent.clear";
pub const MENU_ID_FILE_NEW_TIMELINE: &str = "file.new_timeline";
pub const MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER: &str = "file.new_timeline_from_folder";
pub const MENU_ID_FILE_NEW_EMPTY_TIMELINE: &str = "file.new_empty_timeline";
pub const MENU_ID_FILE_SAVE_SESSION: &str = "file.save_session";
pub const MENU_ID_FILE_OPEN_SESSION: &str = "file.open_session";
pub const MENU_ID_FILE_QUIT: &str = "file.quit";

pub const MENU_ID_EDIT_FIND: &str = "edit.find";
pub const MENU_ID_EDIT_FIND_NEXT: &str = "edit.find_next";
pub const MENU_ID_EDIT_FIND_PREVIOUS: &str = "edit.find_previous";
pub const MENU_ID_EDIT_FILTER: &str = "edit.filter";

pub const MENU_ID_VIEW_TOGGLE_SIDEBAR: &str = "view.toggle.sidebar";
pub const MENU_ID_WINDOW_TOGGLE_DETAILS: &str = "window.toggle.details";
pub const MENU_ID_WINDOW_TOGGLE_INFO: &str = "window.toggle.info";
pub const MENU_ID_WINDOW_ALWAYS_ON_TOP: &str = "window.always_on_top";
pub const MENU_ID_VIEW_TOGGLE_PAUSE: &str = "view.toggle.pause";
pub const MENU_ID_VIEW_REFRESH: &str = "view.refresh";
pub const MENU_ID_VIEW_TEXT_SIZE: &str = "view.text_size";
pub const MENU_ID_VIEW_TEXT_SIZE_INCREASE: &str = "view.text_size.increase";
pub const MENU_ID_VIEW_TEXT_SIZE_DECREASE: &str = "view.text_size.decrease";
pub const MENU_ID_VIEW_TEXT_SIZE_RESET: &str = "view.text_size.reset";

pub const MENU_ID_TOOLS_ERROR_LOOKUP: &str = "tools.error_lookup";
pub const MENU_ID_TOOLS_BUNDLE_SUMMARY: &str = "tools.bundle_summary";
pub const MENU_ID_TOOLS_GUID_REGISTRY: &str = "tools.guid_registry";
pub const MENU_ID_TOOLS_COLLECT_DIAGNOSTICS: &str = "tools.collect_diagnostics";
pub const MENU_ID_WINDOW_SETTINGS: &str = "window.settings";

pub const MENU_ID_HELP_CHECK_FOR_UPDATES: &str = "help.check_for_updates";
pub const MENU_ID_HELP_ABOUT: &str = "help.about";

const KNOWN_SOURCE_MENU_ID_PREFIX: &str = "known-source.";
const RECENT_MENU_ID_PREFIX: &str = "recent.";
const RECENT_UNAVAILABLE_MENU_ID: &str = "recent.unavailable";
const WORKSPACE_MENU_ID_PREFIX: &str = "workspace.";
const MENU_SEPARATOR: &str = "__separator__";
const PREDEFINED_HIDE: &str = "__hide__";
const PREDEFINED_HIDE_OTHERS: &str = "__hide_others__";
const PREDEFINED_SHOW_ALL: &str = "__show_all__";
const PREDEFINED_QUIT: &str = "__quit__";

const NON_MAC_TOP_LEVEL_ORDER: &[&str] = &[
    MENU_ID_FILE,
    MENU_ID_EDIT,
    MENU_ID_VIEW,
    MENU_ID_WORKSPACE,
    MENU_ID_TOOLS,
    HELP_SUBMENU_ID,
];
const MAC_TOP_LEVEL_ORDER: &[&str] = &[
    MENU_ID_APP,
    MENU_ID_FILE,
    MENU_ID_EDIT,
    MENU_ID_VIEW,
    MENU_ID_WORKSPACE,
    MENU_ID_TOOLS,
    HELP_SUBMENU_ID,
];
const FILE_ORDER: &[&str] = &[
    MENU_ID_FILE_OPEN_LOG_FILE,
    MENU_ID_FILE_OPEN_LOG_FOLDER,
    MENU_ID_FILE_KNOWN_SOURCES,
    MENU_ID_FILE_RECENT,
    MENU_SEPARATOR,
    MENU_ID_FILE_NEW_TIMELINE,
    MENU_SEPARATOR,
    MENU_ID_FILE_OPEN_SESSION,
    MENU_ID_FILE_SAVE_SESSION,
    MENU_SEPARATOR,
    MENU_ID_FILE_QUIT,
];
const FILE_ORDER_MAC: &[&str] = &[
    MENU_ID_FILE_OPEN_LOG_FILE,
    MENU_ID_FILE_OPEN_LOG_FOLDER,
    MENU_ID_FILE_KNOWN_SOURCES,
    MENU_ID_FILE_RECENT,
    MENU_SEPARATOR,
    MENU_ID_FILE_NEW_TIMELINE,
    MENU_SEPARATOR,
    MENU_ID_FILE_OPEN_SESSION,
    MENU_ID_FILE_SAVE_SESSION,
];
const NEW_TIMELINE_ORDER: &[&str] = &[
    MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER,
    MENU_ID_FILE_NEW_EMPTY_TIMELINE,
];
const EDIT_ORDER: &[&str] = &[
    MENU_ID_EDIT_FIND,
    MENU_ID_EDIT_FIND_NEXT,
    MENU_ID_EDIT_FIND_PREVIOUS,
    MENU_SEPARATOR,
    MENU_ID_EDIT_FILTER,
];
const VIEW_ORDER: &[&str] = &[
    MENU_ID_VIEW_TOGGLE_SIDEBAR,
    MENU_ID_WINDOW_TOGGLE_DETAILS,
    MENU_ID_WINDOW_TOGGLE_INFO,
    MENU_ID_WINDOW_ALWAYS_ON_TOP,
    MENU_SEPARATOR,
    MENU_ID_VIEW_TOGGLE_PAUSE,
    MENU_ID_VIEW_REFRESH,
    MENU_SEPARATOR,
    MENU_ID_VIEW_TEXT_SIZE,
];
const TEXT_SIZE_ORDER: &[&str] = &[
    MENU_ID_VIEW_TEXT_SIZE_INCREASE,
    MENU_ID_VIEW_TEXT_SIZE_DECREASE,
    MENU_ID_VIEW_TEXT_SIZE_RESET,
];
const HELP_ORDER: &[&str] = &[
    MENU_ID_HELP_CHECK_FOR_UPDATES,
    MENU_SEPARATOR,
    MENU_ID_HELP_ABOUT,
];
const HELP_ORDER_MAC: &[&str] = &[MENU_ID_HELP_CHECK_FOR_UPDATES];
const MAC_APP_ORDER: &[&str] = &[
    MENU_ID_HELP_ABOUT,
    MENU_SEPARATOR,
    MENU_ID_WINDOW_SETTINGS,
    MENU_SEPARATOR,
    PREDEFINED_HIDE,
    PREDEFINED_HIDE_OTHERS,
    PREDEFINED_SHOW_ALL,
    MENU_SEPARATOR,
    PREDEFINED_QUIT,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuPlatform {
    Windows,
    Macos,
    // Retained on every target so the pure menu-model tests can exercise all platforms.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Linux,
}

impl MenuPlatform {
    fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceGroup {
    Analysis,
    EndpointManagement,
    SystemSecurity,
}

impl WorkspaceGroup {
    const ALL: [Self; 3] = [
        Self::Analysis,
        Self::EndpointManagement,
        Self::SystemSecurity,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::Analysis => "analysis",
            Self::EndpointManagement => "endpoint-management",
            Self::SystemSecurity => "system-security",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Analysis => "Analysis",
            Self::EndpointManagement => "Endpoint Management",
            Self::SystemSecurity => "System & Security",
        }
    }

    fn native_label(self) -> &'static str {
        match self {
            // Muda treats `&` as a mnemonic marker, so escape the literal ampersand.
            Self::SystemSecurity => "System && Security",
            _ => self.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspacePlatform {
    All,
    Windows,
    Macos,
}

impl WorkspacePlatform {
    fn supports(self, platform: MenuPlatform) -> bool {
        match self {
            Self::All => true,
            Self::Windows => platform == MenuPlatform::Windows,
            Self::Macos => platform == MenuPlatform::Macos,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkspaceDescriptor {
    id: &'static str,
    label: &'static str,
    group: WorkspaceGroup,
    platform: WorkspacePlatform,
}

const WORKSPACE_DESCRIPTORS: &[WorkspaceDescriptor] = &[
    WorkspaceDescriptor {
        id: "log",
        label: "Log Explorer",
        group: WorkspaceGroup::Analysis,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "event-log",
        label: "Event Log Viewer",
        group: WorkspaceGroup::Analysis,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "timeline",
        label: "Timeline",
        group: WorkspaceGroup::Analysis,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "intune",
        label: "Intune Diagnostics",
        group: WorkspaceGroup::EndpointManagement,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "new-intune",
        label: "New Intune Workspace",
        group: WorkspaceGroup::EndpointManagement,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "esp-diagnostics",
        label: "ESP Diagnostics",
        group: WorkspaceGroup::EndpointManagement,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "dsregcmd",
        label: "dsregcmd",
        group: WorkspaceGroup::EndpointManagement,
        platform: WorkspacePlatform::Windows,
    },
    WorkspaceDescriptor {
        id: "deployment",
        label: "Software Deployment",
        group: WorkspaceGroup::EndpointManagement,
        platform: WorkspacePlatform::Windows,
    },
    WorkspaceDescriptor {
        id: "sysmon",
        label: "Sysmon",
        group: WorkspaceGroup::SystemSecurity,
        platform: WorkspacePlatform::Windows,
    },
    WorkspaceDescriptor {
        id: "secureboot",
        label: "Secure Boot Certs",
        group: WorkspaceGroup::SystemSecurity,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "dns-dhcp",
        label: "DNS / DHCP",
        group: WorkspaceGroup::SystemSecurity,
        platform: WorkspacePlatform::All,
    },
    WorkspaceDescriptor {
        id: "macos-diag",
        label: "macOS Diagnostics",
        group: WorkspaceGroup::SystemSecurity,
        platform: WorkspacePlatform::Macos,
    },
];

#[derive(Debug, PartialEq, Eq)]
struct WorkspaceMenuGroup {
    group: WorkspaceGroup,
    workspaces: Vec<&'static WorkspaceDescriptor>,
}

fn workspace_descriptor(id: &str) -> Option<&'static WorkspaceDescriptor> {
    WORKSPACE_DESCRIPTORS
        .iter()
        .find(|workspace| workspace.id == id)
}

fn workspace_groups(
    platform: MenuPlatform,
    available_workspaces: &[&str],
) -> Vec<WorkspaceMenuGroup> {
    let available: HashSet<&str> = available_workspaces.iter().copied().collect();

    WorkspaceGroup::ALL
        .into_iter()
        .filter_map(|group| {
            let workspaces = WORKSPACE_DESCRIPTORS
                .iter()
                .filter(|workspace| {
                    workspace.group == group
                        && workspace.platform.supports(platform)
                        && available.contains(workspace.id)
                })
                .collect::<Vec<_>>();

            (!workspaces.is_empty()).then_some(WorkspaceMenuGroup { group, workspaces })
        })
        .collect()
}

fn visible_workspace_descriptors(
    platform: MenuPlatform,
    available_workspaces: &[&str],
) -> Vec<&'static WorkspaceDescriptor> {
    workspace_groups(platform, available_workspaces)
        .into_iter()
        .flat_map(|group| group.workspaces)
        .collect()
}

fn top_level_menu_order(platform: MenuPlatform) -> &'static [&'static str] {
    if platform == MenuPlatform::Macos {
        MAC_TOP_LEVEL_ORDER
    } else {
        NON_MAC_TOP_LEVEL_ORDER
    }
}

fn file_item_order(platform: MenuPlatform) -> &'static [&'static str] {
    if platform == MenuPlatform::Macos {
        FILE_ORDER_MAC
    } else {
        FILE_ORDER
    }
}

fn edit_item_order() -> &'static [&'static str] {
    EDIT_ORDER
}

fn view_item_order() -> &'static [&'static str] {
    VIEW_ORDER
}

fn tools_item_order(platform: MenuPlatform, collector_available: bool) -> Vec<&'static str> {
    let mut order = vec![
        MENU_ID_TOOLS_ERROR_LOOKUP,
        MENU_ID_TOOLS_GUID_REGISTRY,
        MENU_ID_TOOLS_BUNDLE_SUMMARY,
    ];

    if collector_available && platform == MenuPlatform::Windows {
        order.extend([MENU_SEPARATOR, MENU_ID_TOOLS_COLLECT_DIAGNOSTICS]);
    }

    if platform != MenuPlatform::Macos {
        order.extend([MENU_SEPARATOR, MENU_ID_WINDOW_SETTINGS]);
    }

    order
}

fn help_item_order(platform: MenuPlatform) -> &'static [&'static str] {
    if platform == MenuPlatform::Macos {
        HELP_ORDER_MAC
    } else {
        HELP_ORDER
    }
}

fn mac_app_item_order() -> &'static [&'static str] {
    MAC_APP_ORDER
}

fn menu_accelerator(menu_id: &str, platform: MenuPlatform) -> Option<&'static str> {
    match menu_id {
        MENU_ID_FILE_OPEN_LOG_FILE => Some("CmdOrCtrl+O"),
        MENU_ID_FILE_SAVE_SESSION => Some("Shift+CmdOrCtrl+S"),
        MENU_ID_EDIT_FIND => Some("CmdOrCtrl+F"),
        MENU_ID_EDIT_FIND_NEXT => Some("F3"),
        MENU_ID_EDIT_FIND_PREVIOUS => Some("Shift+F3"),
        MENU_ID_EDIT_FILTER => Some("CmdOrCtrl+Shift+L"),
        MENU_ID_VIEW_TOGGLE_SIDEBAR => Some("CmdOrCtrl+B"),
        MENU_ID_WINDOW_TOGGLE_DETAILS if platform == MenuPlatform::Macos => Some("Ctrl+H"),
        MENU_ID_WINDOW_TOGGLE_DETAILS => Some("CmdOrCtrl+H"),
        MENU_ID_VIEW_TOGGLE_PAUSE => Some("CmdOrCtrl+U"),
        MENU_ID_VIEW_REFRESH => Some("F5"),
        MENU_ID_VIEW_TEXT_SIZE_INCREASE => Some("CmdOrCtrl+="),
        MENU_ID_VIEW_TEXT_SIZE_DECREASE => Some("CmdOrCtrl+-"),
        MENU_ID_VIEW_TEXT_SIZE_RESET => Some("CmdOrCtrl+0"),
        MENU_ID_TOOLS_ERROR_LOOKUP => Some("CmdOrCtrl+L"),
        MENU_ID_WINDOW_SETTINGS => Some("CmdOrCtrl+,"),
        _ => None,
    }
}

fn app_display_name<R: Runtime>(app: &AppHandle<R>) -> String {
    app.config()
        .product_name
        .clone()
        .unwrap_or_else(|| "CMTrace Open".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppMenuActionPayload {
    pub version: u8,
    pub menu_id: String,
    pub action: String,
    pub category: String,
    pub trigger: String,
    pub source_id: Option<String>,
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppMenuState {
    pub active_workspace: String,
    pub open_file_label: String,
    pub open_folder_label: String,
    pub can_open_sources: bool,
    pub can_open_known_sources: bool,
    pub can_find: bool,
    pub has_find_session: bool,
    pub can_filter: bool,
    pub can_pause_resume: bool,
    pub is_paused: bool,
    pub can_refresh: bool,
    pub can_toggle_sidebar: bool,
    pub is_sidebar_visible: bool,
    pub can_toggle_details_pane: bool,
    pub is_details_visible: bool,
    pub can_toggle_info_pane: bool,
    pub is_info_pane_visible: bool,
    pub can_adjust_text_size: bool,
    pub can_show_evidence_bundle: bool,
    pub can_save_session: bool,
    pub can_collect_diagnostics: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuUpdateKind {
    Normal,
    Submenu,
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MenuItemUpdate {
    id: String,
    kind: MenuUpdateKind,
    text: Option<String>,
    enabled: bool,
    checked: Option<bool>,
    optional: bool,
}

impl MenuItemUpdate {
    fn normal(id: &str, enabled: bool) -> Self {
        Self {
            id: id.to_string(),
            kind: MenuUpdateKind::Normal,
            text: None,
            enabled,
            checked: None,
            optional: false,
        }
    }

    fn normal_with_text(id: &str, text: impl Into<String>, enabled: bool) -> Self {
        Self {
            text: Some(text.into()),
            ..Self::normal(id, enabled)
        }
    }

    fn optional_normal(id: &str, enabled: bool) -> Self {
        Self {
            optional: true,
            ..Self::normal(id, enabled)
        }
    }

    fn submenu(id: &str, enabled: bool) -> Self {
        Self {
            id: id.to_string(),
            kind: MenuUpdateKind::Submenu,
            text: None,
            enabled,
            checked: None,
            optional: false,
        }
    }

    fn check(id: impl Into<String>, enabled: bool, checked: bool, optional: bool) -> Self {
        Self {
            id: id.into(),
            kind: MenuUpdateKind::Check,
            text: None,
            enabled,
            checked: Some(checked),
            optional,
        }
    }
}

fn normal_item<R: Runtime>(
    app: &AppHandle<R>,
    id: &str,
    label: impl AsRef<str>,
    platform: MenuPlatform,
) -> tauri::Result<MenuItem<R>> {
    MenuItem::with_id(
        app,
        id,
        label.as_ref(),
        true,
        menu_accelerator(id, platform),
    )
}

fn append_separator<R: Runtime>(app: &AppHandle<R>, submenu: &Submenu<R>) -> tauri::Result<()> {
    let separator = PredefinedMenuItem::separator(app)?;
    submenu.append(&separator)
}

fn build_file_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let open_file = normal_item(app, MENU_ID_FILE_OPEN_LOG_FILE, "Open File…", platform)?;
    let open_folder = normal_item(app, MENU_ID_FILE_OPEN_LOG_FOLDER, "Open Folder…", platform)?;
    let known_sources = build_known_sources_submenu(app)?;
    let recent = build_recent_submenu(app, &recent_entries_for_menu(app))?;

    let new_timeline_from_folder = normal_item(
        app,
        MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER,
        "From Folder…",
        platform,
    )?;
    let new_empty_timeline = normal_item(
        app,
        MENU_ID_FILE_NEW_EMPTY_TIMELINE,
        "Empty Timeline",
        platform,
    )?;
    let new_timeline = Submenu::with_id(app, MENU_ID_FILE_NEW_TIMELINE, "New Timeline", true)?;
    for &item_id in NEW_TIMELINE_ORDER {
        match item_id {
            MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER => {
                new_timeline.append(&new_timeline_from_folder)?
            }
            MENU_ID_FILE_NEW_EMPTY_TIMELINE => new_timeline.append(&new_empty_timeline)?,
            _ => unreachable!("unknown New Timeline menu item: {item_id}"),
        }
    }

    let open_session = normal_item(app, MENU_ID_FILE_OPEN_SESSION, "Open Session…", platform)?;
    let save_session = normal_item(app, MENU_ID_FILE_SAVE_SESSION, "Save Session…", platform)?;
    let quit = normal_item(app, MENU_ID_FILE_QUIT, "Exit", platform)?;

    let submenu = Submenu::with_id(app, MENU_ID_FILE, "File", true)?;
    for &item_id in file_item_order(platform) {
        match item_id {
            MENU_ID_FILE_OPEN_LOG_FILE => submenu.append(&open_file)?,
            MENU_ID_FILE_OPEN_LOG_FOLDER => submenu.append(&open_folder)?,
            MENU_ID_FILE_KNOWN_SOURCES => submenu.append(&known_sources)?,
            MENU_ID_FILE_RECENT => submenu.append(&recent)?,
            MENU_ID_FILE_NEW_TIMELINE => submenu.append(&new_timeline)?,
            MENU_ID_FILE_OPEN_SESSION => submenu.append(&open_session)?,
            MENU_ID_FILE_SAVE_SESSION => submenu.append(&save_session)?,
            MENU_ID_FILE_QUIT => submenu.append(&quit)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown File menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

fn build_edit_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let find = normal_item(app, MENU_ID_EDIT_FIND, "Find…", platform)?;
    let find_next = normal_item(app, MENU_ID_EDIT_FIND_NEXT, "Find Next", platform)?;
    let find_previous = normal_item(app, MENU_ID_EDIT_FIND_PREVIOUS, "Find Previous", platform)?;
    let filter = normal_item(app, MENU_ID_EDIT_FILTER, "Filter…", platform)?;

    let submenu = Submenu::with_id(app, MENU_ID_EDIT, "Edit", true)?;
    for &item_id in edit_item_order() {
        match item_id {
            MENU_ID_EDIT_FIND => submenu.append(&find)?,
            MENU_ID_EDIT_FIND_NEXT => submenu.append(&find_next)?,
            MENU_ID_EDIT_FIND_PREVIOUS => submenu.append(&find_previous)?,
            MENU_ID_EDIT_FILTER => submenu.append(&filter)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown Edit menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

fn build_view_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let sidebar = CheckMenuItem::with_id(
        app,
        MENU_ID_VIEW_TOGGLE_SIDEBAR,
        "Sidebar",
        true,
        true,
        menu_accelerator(MENU_ID_VIEW_TOGGLE_SIDEBAR, platform),
    )?;
    let details = CheckMenuItem::with_id(
        app,
        MENU_ID_WINDOW_TOGGLE_DETAILS,
        "Details Pane",
        true,
        true,
        menu_accelerator(MENU_ID_WINDOW_TOGGLE_DETAILS, platform),
    )?;
    let info = CheckMenuItem::with_id(
        app,
        MENU_ID_WINDOW_TOGGLE_INFO,
        "Info Pane",
        true,
        true,
        menu_accelerator(MENU_ID_WINDOW_TOGGLE_INFO, platform),
    )?;
    // Starts unchecked because a freshly launched window is never pinned. The
    // persisted preference is re-applied on startup via the `set_always_on_top`
    // command, which also keeps this checkmark in sync when the item is toggled.
    let always_on_top = CheckMenuItem::with_id(
        app,
        MENU_ID_WINDOW_ALWAYS_ON_TOP,
        "Always on Top",
        true,
        false,
        menu_accelerator(MENU_ID_WINDOW_ALWAYS_ON_TOP, platform),
    )?;
    let pause = normal_item(
        app,
        MENU_ID_VIEW_TOGGLE_PAUSE,
        "Pause Live Updates",
        platform,
    )?;
    let refresh = normal_item(app, MENU_ID_VIEW_REFRESH, "Refresh", platform)?;

    let increase = normal_item(app, MENU_ID_VIEW_TEXT_SIZE_INCREASE, "Increase", platform)?;
    let decrease = normal_item(app, MENU_ID_VIEW_TEXT_SIZE_DECREASE, "Decrease", platform)?;
    let reset = normal_item(app, MENU_ID_VIEW_TEXT_SIZE_RESET, "Reset", platform)?;
    let text_size = Submenu::with_id(app, MENU_ID_VIEW_TEXT_SIZE, "Text Size", true)?;
    for &item_id in TEXT_SIZE_ORDER {
        match item_id {
            MENU_ID_VIEW_TEXT_SIZE_INCREASE => text_size.append(&increase)?,
            MENU_ID_VIEW_TEXT_SIZE_DECREASE => text_size.append(&decrease)?,
            MENU_ID_VIEW_TEXT_SIZE_RESET => text_size.append(&reset)?,
            _ => unreachable!("unknown Text Size menu item: {item_id}"),
        }
    }

    let submenu = Submenu::with_id(app, MENU_ID_VIEW, "View", true)?;
    for &item_id in view_item_order() {
        match item_id {
            MENU_ID_VIEW_TOGGLE_SIDEBAR => submenu.append(&sidebar)?,
            MENU_ID_WINDOW_TOGGLE_DETAILS => submenu.append(&details)?,
            MENU_ID_WINDOW_TOGGLE_INFO => submenu.append(&info)?,
            MENU_ID_WINDOW_ALWAYS_ON_TOP => submenu.append(&always_on_top)?,
            MENU_ID_VIEW_TOGGLE_PAUSE => submenu.append(&pause)?,
            MENU_ID_VIEW_REFRESH => submenu.append(&refresh)?,
            MENU_ID_VIEW_TEXT_SIZE => submenu.append(&text_size)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown View menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

fn build_workspace_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let available = get_available_workspaces();
    let groups = workspace_groups(platform, &available);
    let submenu = Submenu::with_id(app, MENU_ID_WORKSPACE, "Workspace", true)?;

    for group in groups {
        let group_menu_id = format!("workspace.group.{}", group.group.id());
        let group_submenu = Submenu::with_id(app, group_menu_id, group.group.native_label(), true)?;

        for workspace in group.workspaces {
            let menu_id = format!("{WORKSPACE_MENU_ID_PREFIX}{}", workspace.id);
            let item = CheckMenuItem::with_id(
                app,
                menu_id,
                workspace.label,
                true,
                workspace.id == "log",
                None::<&str>,
            )?;
            group_submenu.append(&item)?;
        }

        submenu.append(&group_submenu)?;
    }

    Ok(submenu)
}

fn build_tools_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let error_lookup = normal_item(
        app,
        MENU_ID_TOOLS_ERROR_LOOKUP,
        "Error Code Lookup…",
        platform,
    )?;
    let guid_registry = normal_item(app, MENU_ID_TOOLS_GUID_REGISTRY, "GUID Registry", platform)?;
    let bundle_summary = normal_item(
        app,
        MENU_ID_TOOLS_BUNDLE_SUMMARY,
        "Evidence Bundle Summary",
        platform,
    )?;
    let collect_diagnostics = normal_item(
        app,
        MENU_ID_TOOLS_COLLECT_DIAGNOSTICS,
        "Collect Diagnostics…",
        platform,
    )?;
    let settings = normal_item(app, MENU_ID_WINDOW_SETTINGS, "Settings…", platform)?;

    let collector_available = cfg!(all(target_os = "windows", feature = "collector"));
    let submenu = Submenu::with_id(app, MENU_ID_TOOLS, "Tools", true)?;
    for item_id in tools_item_order(platform, collector_available) {
        match item_id {
            MENU_ID_TOOLS_ERROR_LOOKUP => submenu.append(&error_lookup)?,
            MENU_ID_TOOLS_GUID_REGISTRY => submenu.append(&guid_registry)?,
            MENU_ID_TOOLS_BUNDLE_SUMMARY => submenu.append(&bundle_summary)?,
            MENU_ID_TOOLS_COLLECT_DIAGNOSTICS => submenu.append(&collect_diagnostics)?,
            MENU_ID_WINDOW_SETTINGS => submenu.append(&settings)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown Tools menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

fn build_help_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: MenuPlatform,
) -> tauri::Result<Submenu<R>> {
    let check_for_updates = normal_item(
        app,
        MENU_ID_HELP_CHECK_FOR_UPDATES,
        "Check for Updates",
        platform,
    )?;
    let about = normal_item(
        app,
        MENU_ID_HELP_ABOUT,
        format!("About {}", app_display_name(app)),
        platform,
    )?;

    let submenu = Submenu::with_id(app, HELP_SUBMENU_ID, "Help", true)?;
    for &item_id in help_item_order(platform) {
        match item_id {
            MENU_ID_HELP_CHECK_FOR_UPDATES => submenu.append(&check_for_updates)?,
            MENU_ID_HELP_ABOUT => submenu.append(&about)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown Help menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

fn build_macos_app_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Submenu<R>> {
    let platform = MenuPlatform::Macos;
    let about = normal_item(
        app,
        MENU_ID_HELP_ABOUT,
        format!("About {}", app_display_name(app)),
        platform,
    )?;
    let settings = normal_item(app, MENU_ID_WINDOW_SETTINGS, "Settings…", platform)?;
    let hide = PredefinedMenuItem::hide(app, None)?;
    let hide_others = PredefinedMenuItem::hide_others(app, None)?;
    let show_all = PredefinedMenuItem::show_all(app, None)?;
    let quit = PredefinedMenuItem::quit(app, None)?;

    let submenu = Submenu::with_id(app, MENU_ID_APP, app_display_name(app), true)?;
    for &item_id in mac_app_item_order() {
        match item_id {
            MENU_ID_HELP_ABOUT => submenu.append(&about)?,
            MENU_ID_WINDOW_SETTINGS => submenu.append(&settings)?,
            PREDEFINED_HIDE => submenu.append(&hide)?,
            PREDEFINED_HIDE_OTHERS => submenu.append(&hide_others)?,
            PREDEFINED_SHOW_ALL => submenu.append(&show_all)?,
            PREDEFINED_QUIT => submenu.append(&quit)?,
            MENU_SEPARATOR => append_separator(app, &submenu)?,
            _ => unreachable!("unknown macOS application menu item: {item_id}"),
        }
    }

    Ok(submenu)
}

pub fn build_app_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let platform = MenuPlatform::current();
    let file_menu = build_file_menu(app, platform)?;
    let edit_menu = build_edit_menu(app, platform)?;
    let view_menu = build_view_menu(app, platform)?;
    let workspace_menu = build_workspace_menu(app, platform)?;
    let tools_menu = build_tools_menu(app, platform)?;
    let help_menu = build_help_menu(app, platform)?;
    let app_menu = if platform == MenuPlatform::Macos {
        Some(build_macos_app_menu(app)?)
    } else {
        None
    };

    let menu = Menu::new(app)?;
    for &menu_id in top_level_menu_order(platform) {
        match menu_id {
            MENU_ID_APP => menu.append(
                app_menu
                    .as_ref()
                    .expect("macOS application menu should be constructed"),
            )?,
            MENU_ID_FILE => menu.append(&file_menu)?,
            MENU_ID_EDIT => menu.append(&edit_menu)?,
            MENU_ID_VIEW => menu.append(&view_menu)?,
            MENU_ID_WORKSPACE => menu.append(&workspace_menu)?,
            MENU_ID_TOOLS => menu.append(&tools_menu)?,
            HELP_SUBMENU_ID => menu.append(&help_menu)?,
            _ => unreachable!("unknown top-level menu: {menu_id}"),
        }
    }

    Ok(menu)
}

fn workspace_menu_updates(
    active_workspace: &str,
    platform: MenuPlatform,
    available_workspaces: &[&str],
) -> Result<Vec<MenuItemUpdate>, String> {
    let visible_workspaces = visible_workspace_descriptors(platform, available_workspaces);
    if !visible_workspaces
        .iter()
        .any(|workspace| workspace.id == active_workspace)
    {
        return Err(format!(
            "active workspace '{active_workspace}' is not available in this build"
        ));
    }

    Ok(visible_workspaces
        .into_iter()
        .map(|workspace| {
            let checked = workspace.id == active_workspace;
            MenuItemUpdate::check(
                format!("{WORKSPACE_MENU_ID_PREFIX}{}", workspace.id),
                true,
                checked,
                !checked,
            )
        })
        .collect())
}

fn app_menu_updates(
    state: &AppMenuState,
    platform: MenuPlatform,
    available_workspaces: &[&str],
) -> Result<Vec<MenuItemUpdate>, String> {
    let mut updates = vec![
        MenuItemUpdate::normal_with_text(
            MENU_ID_FILE_OPEN_LOG_FILE,
            &state.open_file_label,
            state.can_open_sources,
        ),
        MenuItemUpdate::normal_with_text(
            MENU_ID_FILE_OPEN_LOG_FOLDER,
            &state.open_folder_label,
            state.can_open_sources,
        ),
        MenuItemUpdate::submenu(MENU_ID_FILE_KNOWN_SOURCES, state.can_open_known_sources),
        MenuItemUpdate::normal(MENU_ID_FILE_SAVE_SESSION, state.can_save_session),
        MenuItemUpdate::normal(MENU_ID_EDIT_FIND, state.can_find),
        // F3 opens Find when no session exists, so navigation follows Find capability.
        MenuItemUpdate::normal(MENU_ID_EDIT_FIND_NEXT, state.can_find),
        MenuItemUpdate::normal(MENU_ID_EDIT_FIND_PREVIOUS, state.can_find),
        MenuItemUpdate::normal(MENU_ID_EDIT_FILTER, state.can_filter),
        MenuItemUpdate::check(
            MENU_ID_VIEW_TOGGLE_SIDEBAR,
            state.can_toggle_sidebar,
            state.is_sidebar_visible,
            false,
        ),
        MenuItemUpdate::check(
            MENU_ID_WINDOW_TOGGLE_DETAILS,
            state.can_toggle_details_pane,
            state.is_details_visible,
            false,
        ),
        MenuItemUpdate::check(
            MENU_ID_WINDOW_TOGGLE_INFO,
            state.can_toggle_info_pane,
            state.is_info_pane_visible,
            false,
        ),
        MenuItemUpdate::normal_with_text(
            MENU_ID_VIEW_TOGGLE_PAUSE,
            if state.is_paused {
                "Resume Live Updates"
            } else {
                "Pause Live Updates"
            },
            state.can_pause_resume,
        ),
        MenuItemUpdate::normal(MENU_ID_VIEW_REFRESH, state.can_refresh),
        MenuItemUpdate::submenu(MENU_ID_VIEW_TEXT_SIZE, state.can_adjust_text_size),
        MenuItemUpdate::normal(MENU_ID_VIEW_TEXT_SIZE_INCREASE, state.can_adjust_text_size),
        MenuItemUpdate::normal(MENU_ID_VIEW_TEXT_SIZE_DECREASE, state.can_adjust_text_size),
        MenuItemUpdate::normal(MENU_ID_VIEW_TEXT_SIZE_RESET, state.can_adjust_text_size),
        MenuItemUpdate::normal(MENU_ID_TOOLS_BUNDLE_SUMMARY, state.can_show_evidence_bundle),
        MenuItemUpdate::optional_normal(
            MENU_ID_TOOLS_COLLECT_DIAGNOSTICS,
            state.can_collect_diagnostics,
        ),
    ];
    updates.extend(workspace_menu_updates(
        &state.active_workspace,
        platform,
        available_workspaces,
    )?);
    Ok(updates)
}

fn index_menu_items<R: Runtime>(
    items: Vec<MenuItemKind<R>>,
    index: &mut HashMap<String, MenuItemKind<R>>,
) -> Result<(), String> {
    for item in items {
        if let MenuItemKind::Submenu(submenu) = &item {
            let children = submenu.items().map_err(|error| {
                format!(
                    "failed to enumerate submenu '{}': {error}",
                    submenu.id().as_ref()
                )
            })?;
            index_menu_items(children, index)?;
        }

        if matches!(&item, MenuItemKind::Predefined(_) | MenuItemKind::Icon(_)) {
            continue;
        }

        let id = item.id().as_ref().to_string();
        if index.insert(id.clone(), item).is_some() {
            return Err(format!("duplicate native menu item id '{id}'"));
        }
    }

    Ok(())
}

fn app_menu_index<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<HashMap<String, MenuItemKind<R>>, String> {
    let menu = app
        .menu()
        .ok_or_else(|| "application menu is not installed".to_string())?;
    let items = menu
        .items()
        .map_err(|error| format!("failed to enumerate application menu: {error}"))?;
    let mut index = HashMap::new();
    index_menu_items(items, &mut index)?;
    Ok(index)
}

fn item_matches_update<R: Runtime>(item: &MenuItemKind<R>, update: &MenuItemUpdate) -> bool {
    matches!(
        (item, update.kind),
        (MenuItemKind::MenuItem(_), MenuUpdateKind::Normal)
            | (MenuItemKind::Submenu(_), MenuUpdateKind::Submenu)
            | (MenuItemKind::Check(_), MenuUpdateKind::Check)
    )
}

struct MenuItemSnapshot<R: Runtime> {
    item: MenuItemKind<R>,
    text: String,
    enabled: bool,
    checked: Option<bool>,
}

fn snapshot_menu_item<R: Runtime>(item: &MenuItemKind<R>) -> Result<MenuItemSnapshot<R>, String> {
    let (text, enabled, checked) = match item {
        MenuItemKind::MenuItem(item) => (
            item.text().map_err(|error| error.to_string())?,
            item.is_enabled().map_err(|error| error.to_string())?,
            None,
        ),
        MenuItemKind::Submenu(item) => (
            item.text().map_err(|error| error.to_string())?,
            item.is_enabled().map_err(|error| error.to_string())?,
            None,
        ),
        MenuItemKind::Check(item) => (
            item.text().map_err(|error| error.to_string())?,
            item.is_enabled().map_err(|error| error.to_string())?,
            Some(item.is_checked().map_err(|error| error.to_string())?),
        ),
        _ => {
            return Err(format!(
                "unsupported menu item kind for '{}'",
                item.id().as_ref()
            ))
        }
    };

    Ok(MenuItemSnapshot {
        item: item.clone(),
        text,
        enabled,
        checked,
    })
}

fn apply_menu_update<R: Runtime>(
    item: &MenuItemKind<R>,
    update: &MenuItemUpdate,
) -> Result<(), String> {
    match item {
        MenuItemKind::MenuItem(item) => {
            if let Some(text) = &update.text {
                item.set_text(text).map_err(|error| error.to_string())?;
            }
            item.set_enabled(update.enabled)
                .map_err(|error| error.to_string())
        }
        MenuItemKind::Submenu(item) => {
            if let Some(text) = &update.text {
                item.set_text(text).map_err(|error| error.to_string())?;
            }
            item.set_enabled(update.enabled)
                .map_err(|error| error.to_string())
        }
        MenuItemKind::Check(item) => {
            if let Some(text) = &update.text {
                item.set_text(text).map_err(|error| error.to_string())?;
            }
            item.set_enabled(update.enabled)
                .map_err(|error| error.to_string())?;
            item.set_checked(
                update
                    .checked
                    .ok_or_else(|| format!("check update '{}' has no checked state", update.id))?,
            )
            .map_err(|error| error.to_string())
        }
        _ => Err(format!("unsupported menu item kind for '{}'", update.id)),
    }
}

fn restore_menu_item<R: Runtime>(snapshot: &MenuItemSnapshot<R>) -> Result<(), String> {
    match &snapshot.item {
        MenuItemKind::MenuItem(item) => {
            item.set_text(&snapshot.text)
                .map_err(|error| error.to_string())?;
            item.set_enabled(snapshot.enabled)
                .map_err(|error| error.to_string())
        }
        MenuItemKind::Submenu(item) => {
            item.set_text(&snapshot.text)
                .map_err(|error| error.to_string())?;
            item.set_enabled(snapshot.enabled)
                .map_err(|error| error.to_string())
        }
        MenuItemKind::Check(item) => {
            item.set_text(&snapshot.text)
                .map_err(|error| error.to_string())?;
            item.set_enabled(snapshot.enabled)
                .map_err(|error| error.to_string())?;
            item.set_checked(snapshot.checked.ok_or_else(|| {
                format!(
                    "check snapshot '{}' has no checked state",
                    item.id().as_ref()
                )
            })?)
            .map_err(|error| error.to_string())
        }
        _ => Err(format!(
            "unsupported menu item kind for '{}'",
            snapshot.item.id().as_ref()
        )),
    }
}

fn apply_menu_updates<R: Runtime>(
    index: &HashMap<String, MenuItemKind<R>>,
    updates: Vec<MenuItemUpdate>,
) -> Result<(), String> {
    let mut planned = Vec::new();

    for update in updates {
        let Some(item) = index.get(&update.id) else {
            if update.optional {
                continue;
            }
            return Err(format!("native menu item '{}' is missing", update.id));
        };

        if !item_matches_update(item, &update) {
            return Err(format!(
                "native menu item '{}' has the wrong item kind",
                update.id
            ));
        }

        let snapshot = snapshot_menu_item(item)
            .map_err(|error| format!("failed to snapshot '{}': {error}", update.id))?;
        planned.push((update, snapshot));
    }

    for applied_index in 0..planned.len() {
        let (update, snapshot) = &planned[applied_index];
        if let Err(error) = apply_menu_update(&snapshot.item, update) {
            for (rollback_update, rollback_snapshot) in planned[..=applied_index].iter().rev() {
                if let Err(rollback_error) = restore_menu_item(rollback_snapshot) {
                    log::error!(
                        "failed to roll back native menu item '{}': {rollback_error}",
                        rollback_update.id
                    );
                }
            }
            return Err(format!(
                "failed to update native menu item '{}': {error}",
                update.id
            ));
        }
    }

    Ok(())
}

fn sync_app_menu_state_impl<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppMenuState,
) -> Result<(), String> {
    let index = app_menu_index(app)?;
    let available_workspaces = get_available_workspaces();
    let updates = app_menu_updates(state, MenuPlatform::current(), &available_workspaces)?;
    apply_menu_updates(&index, updates)
}

#[tauri::command]
pub fn sync_app_menu_state<R: Runtime>(
    app: AppHandle<R>,
    state: AppMenuState,
) -> Result<(), String> {
    sync_app_menu_state_impl(&app, &state)
}

fn repair_workspace_checks<R: Runtime>(
    app: &AppHandle<R>,
    active_workspace: &str,
) -> Result<(), String> {
    let index = app_menu_index(app)?;
    let available_workspaces = get_available_workspaces();
    let updates = workspace_menu_updates(
        active_workspace,
        MenuPlatform::current(),
        &available_workspaces,
    )?;
    apply_menu_updates(&index, updates)
}

fn workspace_label(id: &str) -> &'static str {
    workspace_descriptor(id)
        .map(|descriptor| descriptor.label)
        .unwrap_or("Unknown Workspace")
}

/// `{name} — {parent} ({Workspace})`. Native menu items carry no tooltip, so
/// the parent folder is what disambiguates same-named logs across bundles.
fn recent_entry_label(entry: &RecentEntry) -> String {
    let path = Path::new(&entry.path);

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| entry.path.clone());

    let parent = path
        .parent()
        .and_then(|parent| parent.file_name())
        .map(|parent| parent.to_string_lossy().into_owned())
        .filter(|parent| !parent.is_empty());

    let workspace = workspace_label(&entry.workspace);

    match parent {
        Some(parent) => format!("{name} — {parent} ({workspace})"),
        None => format!("{name} ({workspace})"),
    }
}

fn recent_entries_for_menu<R: Runtime>(app: &AppHandle<R>) -> Vec<RecentEntry> {
    use tauri::Manager as _;

    app.try_state::<RecentEntriesState>()
        .map(|state| state.snapshot())
        .unwrap_or_default()
}

/// 16 lowercase hex chars derived from the entry's dedup key (normalized path
/// + workspace).
///
/// The full 64-bit digest is kept rather than truncated: a collision would
/// defeat the stale-row check in `enrich_recent_payload` and reopen the wrong
/// entry, and the id is never shown to the user, so there is nothing to gain
/// from a shorter one.
///
/// `DefaultHasher` is not stable across Rust releases, which is fine here: the
/// hash is generated by `recent_menu_id` and verified by
/// `enrich_recent_payload` within a single process run, and is never persisted.
fn recent_entry_hash(entry: &RecentEntry) -> String {
    let mut hasher = DefaultHasher::new();
    normalize_path(&entry.path).hash(&mut hasher);
    entry.workspace.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Menu id for a Recent entry: `recent.{index}.{hash}`. The index alone is
/// not a safe identity — entries can shift between menu build and click
/// (concurrent pushes, or a prune dropping an earlier row) — so the hash lets
/// `enrich_recent_payload` detect a stale index before acting on it.
fn recent_menu_id(index: usize, entry: &RecentEntry) -> String {
    format!("{RECENT_MENU_ID_PREFIX}{index}.{}", recent_entry_hash(entry))
}

/// Inverse of `recent_menu_id`: splits `recent.{index}.{hash}` into its parts.
/// Returns `None` for anything that isn't that exact shape, including the
/// `recent.unavailable` placeholder and a bare `recent.` (neither has a
/// numeric index followed by a `.`).
fn parse_recent_menu_id(menu_id: &str) -> Option<(usize, String)> {
    let rest = menu_id.strip_prefix(RECENT_MENU_ID_PREFIX)?;
    let (index, hash) = rest.split_once('.')?;
    let index = index.parse::<usize>().ok()?;
    Some((index, hash.to_string()))
}

fn recent_submenu_items<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> tauri::Result<Vec<Box<dyn tauri::menu::IsMenuItem<R>>>> {
    if entries.is_empty() {
        let placeholder = MenuItem::with_id(
            app,
            RECENT_UNAVAILABLE_MENU_ID,
            "No recent files",
            false,
            None::<&str>,
        )?;
        return Ok(vec![Box::new(placeholder)]);
    }

    let mut items: Vec<Box<dyn tauri::menu::IsMenuItem<R>>> = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        items.push(Box::new(MenuItem::with_id(
            app,
            recent_menu_id(index, entry),
            recent_entry_label(entry),
            true,
            None::<&str>,
        )?));
    }

    items.push(Box::new(PredefinedMenuItem::separator(app)?));
    items.push(Box::new(MenuItem::with_id(
        app,
        MENU_ID_FILE_RECENT_CLEAR,
        "Clear Recent",
        true,
        None::<&str>,
    )?));

    Ok(items)
}

fn build_recent_submenu<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> tauri::Result<Submenu<R>> {
    let items = recent_submenu_items(app, entries)?;
    let refs: Vec<&dyn tauri::menu::IsMenuItem<R>> =
        items.iter().map(|item| item.as_ref()).collect();

    Submenu::with_id_and_items(app, MENU_ID_FILE_RECENT, "Recent", !entries.is_empty(), &refs)
}

/// Tear down and repopulate the Recent submenu.
///
/// muda's `MenuItem` exposes `set_text`/`set_enabled` but no `set_visible`, so
/// updating fixed slots would leave permanent placeholder rows. Menu mutation
/// is main-thread-only on macOS and Tauri commands run off-thread, hence the
/// `run_on_main_thread` hop.
pub fn rebuild_recent_submenu<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let entries = recent_entries_for_menu(app);
    let handle = app.clone();

    app.run_on_main_thread(move || {
        if let Err(error) = rebuild_recent_submenu_on_main(&handle, &entries) {
            log::error!("[menu] failed to rebuild Recent submenu: {error}");
        }
    })
    .map_err(|error| error.to_string())
}

fn rebuild_recent_submenu_on_main<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> Result<(), String> {
    let index = app_menu_index(app)?;

    let Some(MenuItemKind::Submenu(submenu)) = index.get(MENU_ID_FILE_RECENT) else {
        return Err("Recent submenu is missing from the application menu".to_string());
    };

    while submenu
        .remove_at(0)
        .map_err(|error| error.to_string())?
        .is_some()
    {}

    let items = recent_submenu_items(app, entries).map_err(|error| error.to_string())?;
    for item in &items {
        submenu
            .append(item.as_ref())
            .map_err(|error| error.to_string())?;
    }

    submenu
        .set_enabled(!entries.is_empty())
        .map_err(|error| error.to_string())
}

/// A source entry extracted from the catalog for menu building.
#[derive(Clone)]
struct SourceMenuItem {
    id: String,
    label: String,
    source_order: u32,
}

/// Build the Open Known Source submenu dynamically from the catalog.
///
/// Sources retain the catalog hierarchy:
/// Family (for example, Windows Intune) > Group (for example, Intune IME) > source.
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
        return Submenu::with_id_and_items(
            app,
            MENU_ID_FILE_KNOWN_SOURCES,
            "Open Known Source",
            true,
            &[&placeholder],
        );
    }

    type GroupMap = BTreeMap<(u32, String), (String, Vec<SourceMenuItem>)>;
    type FamilyMap = BTreeMap<(u32, String), (String, GroupMap)>;

    let mut families: FamilyMap = BTreeMap::new();
    let mut ungrouped: Vec<SourceMenuItem> = Vec::new();

    for source in &sources {
        let menu_id = format!("{KNOWN_SOURCE_MENU_ID_PREFIX}{}", source.id);

        match &source.grouping {
            Some(KnownSourceGroupingMetadata {
                family_id,
                family_label,
                group_id,
                group_label,
                group_order,
                source_order,
            }) => {
                let family_key = (0, family_id.clone());
                let family_entry = families
                    .entry(family_key)
                    .or_insert_with(|| (family_label.clone(), BTreeMap::new()));

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

            let item_refs = menu_items
                .iter()
                .map(|item| item as &dyn tauri::menu::IsMenuItem<R>)
                .collect::<Vec<_>>();

            group_submenus.push(Submenu::with_items(
                app,
                group_label.as_str(),
                true,
                &item_refs,
            )?);
        }

        let submenu_refs = group_submenus
            .iter()
            .map(|submenu| submenu as &dyn tauri::menu::IsMenuItem<R>)
            .collect::<Vec<_>>();

        top_level_items.push(Submenu::with_items(
            app,
            family_label.as_str(),
            true,
            &submenu_refs,
        )?);
    }

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

    let mut all_items = top_level_items
        .iter()
        .map(|submenu| submenu as &dyn tauri::menu::IsMenuItem<R>)
        .collect::<Vec<_>>();
    for item in &ungrouped_menu_items {
        all_items.push(item as &dyn tauri::menu::IsMenuItem<R>);
    }

    Submenu::with_id_and_items(
        app,
        MENU_ID_FILE_KNOWN_SOURCES,
        "Open Known Source",
        true,
        &all_items,
    )
}

pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, menu_id: &str) {
    if menu_id == MENU_ID_FILE_QUIT {
        app.exit(0);
        return;
    }

    let Some(mut payload) = payload_for_menu_id(menu_id) else {
        log::warn!("[menu] unrecognized menu_id: {menu_id}");
        return;
    };

    if payload.action == "open_recent_entry"
        && !enrich_recent_payload(&mut payload, &recent_entries_for_menu(app))
    {
        log::warn!("[menu] stale recent entry for menu_id: {menu_id}");
        if let Err(error) = rebuild_recent_submenu(app) {
            log::error!("[menu] failed to repair stale Recent submenu: {error}");
        }
        return;
    }

    if payload.action == "switch_workspace" {
        if let Some(target_id) = payload.target_id.as_deref() {
            if let Err(error) = repair_workspace_checks(app, target_id) {
                log::warn!("failed to repair workspace menu checks for '{target_id}': {error}");
            }
        }
    }

    if let Err(error) = app.emit(MENU_EVENT_APP_ACTION, payload) {
        log::error!("failed to emit app menu action event: {error}");
    }
}

fn base_payload(menu_id: &str, action: &str, category: &str) -> AppMenuActionPayload {
    AppMenuActionPayload {
        version: 1,
        menu_id: menu_id.to_string(),
        action: action.to_string(),
        category: category.to_string(),
        trigger: "menu".to_string(),
        source_id: None,
        target_id: None,
        path: None,
        workspace: None,
        kind: None,
    }
}

/// Fills in `path`/`workspace`/`kind` for an `open_recent_entry` payload by
/// looking up the entry the click targeted and verifying it's still the same
/// entry that produced the menu id (index + hash of the normalized path and
/// workspace). Returns `false` when the id doesn't parse, the index is out of
/// range, or the hash no longer matches — meaning the row went stale between
/// menu build and click and the caller must not emit an action for it.
fn enrich_recent_payload(payload: &mut AppMenuActionPayload, entries: &[RecentEntry]) -> bool {
    let Some((index, hash)) = parse_recent_menu_id(&payload.menu_id) else {
        return false;
    };

    let Some(entry) = entries.get(index) else {
        return false;
    };

    if recent_entry_hash(entry) != hash {
        return false;
    }

    payload.path = Some(entry.path.clone());
    payload.workspace = Some(entry.workspace.clone());
    payload.kind = Some(
        match entry.kind {
            RecentEntryKind::File => "file",
            RecentEntryKind::Folder => "folder",
        }
        .to_string(),
    );

    true
}

fn payload_for_menu_id(menu_id: &str) -> Option<AppMenuActionPayload> {
    if let Some(source_id) = menu_id.strip_prefix(KNOWN_SOURCE_MENU_ID_PREFIX) {
        if source_id.is_empty() || source_id == "unavailable" {
            return None;
        }

        let mut payload = base_payload(menu_id, "open_known_source", "known_source");
        payload.source_id = Some(source_id.to_string());
        return Some(payload);
    }

    if let Some(workspace_id) = menu_id.strip_prefix(WORKSPACE_MENU_ID_PREFIX) {
        workspace_descriptor(workspace_id)?;

        let mut payload = base_payload(menu_id, "switch_workspace", "workspace");
        payload.target_id = Some(workspace_id.to_string());
        return Some(payload);
    }

    if menu_id == MENU_ID_FILE_RECENT_CLEAR {
        return Some(base_payload(menu_id, "clear_recent_entries", "file"));
    }

    // Rejects the "recent.unavailable" placeholder, which shares the prefix
    // but has no `.{hash}` suffix and so fails to parse.
    if let Some((index, _hash)) = parse_recent_menu_id(menu_id) {
        let mut payload = base_payload(menu_id, "open_recent_entry", "file");
        payload.target_id = Some(index.to_string());
        return Some(payload);
    }

    let (action, category) = match menu_id {
        MENU_ID_FILE_OPEN_LOG_FILE => ("open_log_file_dialog", "file"),
        MENU_ID_FILE_OPEN_LOG_FOLDER => ("open_log_folder_dialog", "file"),
        MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER => ("timeline_new_from_folder", "file"),
        MENU_ID_FILE_NEW_EMPTY_TIMELINE => ("timeline_new_empty", "file"),
        MENU_ID_FILE_SAVE_SESSION => ("save_session", "file"),
        MENU_ID_FILE_OPEN_SESSION => ("open_session", "file"),
        MENU_ID_EDIT_FIND => ("show_find", "edit"),
        MENU_ID_EDIT_FIND_NEXT => ("find_next", "edit"),
        MENU_ID_EDIT_FIND_PREVIOUS => ("find_previous", "edit"),
        MENU_ID_EDIT_FILTER => ("show_filter", "edit"),
        MENU_ID_VIEW_TOGGLE_SIDEBAR => ("toggle_sidebar", "view"),
        MENU_ID_VIEW_TOGGLE_PAUSE => ("toggle_pause", "view"),
        MENU_ID_VIEW_REFRESH => ("refresh", "view"),
        MENU_ID_VIEW_TEXT_SIZE_INCREASE => ("increase_text_size", "view"),
        MENU_ID_VIEW_TEXT_SIZE_DECREASE => ("decrease_text_size", "view"),
        MENU_ID_VIEW_TEXT_SIZE_RESET => ("reset_text_size", "view"),
        MENU_ID_TOOLS_ERROR_LOOKUP => ("show_error_lookup", "tools"),
        MENU_ID_TOOLS_BUNDLE_SUMMARY => ("show_evidence_bundle", "tools"),
        MENU_ID_TOOLS_GUID_REGISTRY => ("show_guid_registry", "tools"),
        MENU_ID_TOOLS_COLLECT_DIAGNOSTICS => ("collect_diagnostics", "tools"),
        MENU_ID_WINDOW_TOGGLE_DETAILS => ("toggle_details", "window"),
        MENU_ID_WINDOW_TOGGLE_INFO => ("toggle_info_pane", "window"),
        MENU_ID_WINDOW_ALWAYS_ON_TOP => ("toggle_always_on_top", "window"),
        MENU_ID_HELP_CHECK_FOR_UPDATES => ("check_for_updates", "help"),
        MENU_ID_HELP_ABOUT => ("show_about", "help"),
        MENU_ID_WINDOW_SETTINGS => ("show_settings", "window"),
        _ => return None,
    };

    Some(base_payload(menu_id, action, category))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_workspace_ids() -> Vec<&'static str> {
        WORKSPACE_DESCRIPTORS
            .iter()
            .map(|workspace| workspace.id)
            .collect()
    }

    fn group_ids(groups: &[WorkspaceMenuGroup]) -> Vec<(&'static str, Vec<&'static str>)> {
        groups
            .iter()
            .map(|group| {
                (
                    group.group.label(),
                    group
                        .workspaces
                        .iter()
                        .map(|workspace| workspace.id)
                        .collect(),
                )
            })
            .collect()
    }

    fn sample_menu_state() -> AppMenuState {
        AppMenuState {
            active_workspace: "log".to_string(),
            open_file_label: "Open file…".to_string(),
            open_folder_label: "Open folder…".to_string(),
            can_open_sources: true,
            can_open_known_sources: true,
            can_find: true,
            has_find_session: false,
            can_filter: true,
            can_pause_resume: true,
            is_paused: false,
            can_refresh: true,
            can_toggle_sidebar: true,
            is_sidebar_visible: true,
            can_toggle_details_pane: true,
            is_details_visible: true,
            can_toggle_info_pane: true,
            is_info_pane_visible: true,
            can_adjust_text_size: true,
            can_show_evidence_bundle: false,
            can_save_session: false,
            can_collect_diagnostics: true,
        }
    }

    fn update_by_id<'a>(updates: &'a [MenuItemUpdate], id: &str) -> &'a MenuItemUpdate {
        updates
            .iter()
            .find(|update| update.id == id)
            .unwrap_or_else(|| panic!("missing update for {id}"))
    }

    #[test]
    fn top_level_order_follows_platform_conventions() {
        assert_eq!(
            top_level_menu_order(MenuPlatform::Windows),
            [
                MENU_ID_FILE,
                MENU_ID_EDIT,
                MENU_ID_VIEW,
                MENU_ID_WORKSPACE,
                MENU_ID_TOOLS,
                HELP_SUBMENU_ID,
            ]
        );
        assert_eq!(
            top_level_menu_order(MenuPlatform::Linux),
            top_level_menu_order(MenuPlatform::Windows)
        );
        assert_eq!(
            top_level_menu_order(MenuPlatform::Macos),
            [
                MENU_ID_APP,
                MENU_ID_FILE,
                MENU_ID_EDIT,
                MENU_ID_VIEW,
                MENU_ID_WORKSPACE,
                MENU_ID_TOOLS,
                HELP_SUBMENU_ID,
            ]
        );
    }

    #[test]
    fn submenu_order_matches_the_native_menu_design() {
        assert_eq!(file_item_order(MenuPlatform::Windows), FILE_ORDER);
        assert_eq!(file_item_order(MenuPlatform::Macos), FILE_ORDER_MAC);
        assert_eq!(
            NEW_TIMELINE_ORDER,
            [
                MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER,
                MENU_ID_FILE_NEW_EMPTY_TIMELINE,
            ]
        );
        assert_eq!(edit_item_order(), EDIT_ORDER);
        assert_eq!(view_item_order(), VIEW_ORDER);
        assert_eq!(
            TEXT_SIZE_ORDER,
            [
                MENU_ID_VIEW_TEXT_SIZE_INCREASE,
                MENU_ID_VIEW_TEXT_SIZE_DECREASE,
                MENU_ID_VIEW_TEXT_SIZE_RESET,
            ]
        );
        assert_eq!(help_item_order(MenuPlatform::Windows), HELP_ORDER);
        assert_eq!(help_item_order(MenuPlatform::Macos), HELP_ORDER_MAC);
        assert_eq!(mac_app_item_order(), MAC_APP_ORDER);

        assert_eq!(
            tools_item_order(MenuPlatform::Windows, true),
            [
                MENU_ID_TOOLS_ERROR_LOOKUP,
                MENU_ID_TOOLS_GUID_REGISTRY,
                MENU_ID_TOOLS_BUNDLE_SUMMARY,
                MENU_SEPARATOR,
                MENU_ID_TOOLS_COLLECT_DIAGNOSTICS,
                MENU_SEPARATOR,
                MENU_ID_WINDOW_SETTINGS,
            ]
        );
        assert_eq!(
            tools_item_order(MenuPlatform::Linux, false),
            [
                MENU_ID_TOOLS_ERROR_LOOKUP,
                MENU_ID_TOOLS_GUID_REGISTRY,
                MENU_ID_TOOLS_BUNDLE_SUMMARY,
                MENU_SEPARATOR,
                MENU_ID_WINDOW_SETTINGS,
            ]
        );
        assert_eq!(
            tools_item_order(MenuPlatform::Macos, false),
            [
                MENU_ID_TOOLS_ERROR_LOOKUP,
                MENU_ID_TOOLS_GUID_REGISTRY,
                MENU_ID_TOOLS_BUNDLE_SUMMARY,
            ]
        );
    }

    #[test]
    fn accelerators_match_visible_keyboard_commands() {
        let shared_cases = [
            (MENU_ID_FILE_OPEN_LOG_FILE, "CmdOrCtrl+O"),
            (MENU_ID_FILE_SAVE_SESSION, "Shift+CmdOrCtrl+S"),
            (MENU_ID_EDIT_FIND, "CmdOrCtrl+F"),
            (MENU_ID_EDIT_FIND_NEXT, "F3"),
            (MENU_ID_EDIT_FIND_PREVIOUS, "Shift+F3"),
            (MENU_ID_EDIT_FILTER, "CmdOrCtrl+Shift+L"),
            (MENU_ID_VIEW_TOGGLE_SIDEBAR, "CmdOrCtrl+B"),
            (MENU_ID_VIEW_TOGGLE_PAUSE, "CmdOrCtrl+U"),
            (MENU_ID_VIEW_REFRESH, "F5"),
            (MENU_ID_VIEW_TEXT_SIZE_INCREASE, "CmdOrCtrl+="),
            (MENU_ID_VIEW_TEXT_SIZE_DECREASE, "CmdOrCtrl+-"),
            (MENU_ID_VIEW_TEXT_SIZE_RESET, "CmdOrCtrl+0"),
            (MENU_ID_TOOLS_ERROR_LOOKUP, "CmdOrCtrl+L"),
            (MENU_ID_WINDOW_SETTINGS, "CmdOrCtrl+,"),
        ];

        for (menu_id, accelerator) in shared_cases {
            assert_eq!(
                menu_accelerator(menu_id, MenuPlatform::Windows),
                Some(accelerator),
                "{menu_id}"
            );
        }

        assert_eq!(
            menu_accelerator(MENU_ID_WINDOW_TOGGLE_DETAILS, MenuPlatform::Windows),
            Some("CmdOrCtrl+H")
        );
        assert_eq!(
            menu_accelerator(MENU_ID_WINDOW_TOGGLE_DETAILS, MenuPlatform::Macos),
            Some("Ctrl+H")
        );
    }

    #[test]
    fn workspace_groups_preserve_order_and_filter_by_platform() {
        let available = all_workspace_ids();

        assert_eq!(
            group_ids(&workspace_groups(MenuPlatform::Windows, &available)),
            [
                ("Analysis", vec!["log", "event-log", "timeline"]),
                (
                    "Endpoint Management",
                    vec![
                        "intune",
                        "new-intune",
                        "esp-diagnostics",
                        "dsregcmd",
                        "deployment",
                    ],
                ),
                (
                    "System & Security",
                    vec!["sysmon", "secureboot", "dns-dhcp"],
                ),
            ]
        );
        assert_eq!(
            group_ids(&workspace_groups(MenuPlatform::Macos, &available)),
            [
                ("Analysis", vec!["log", "event-log", "timeline"]),
                (
                    "Endpoint Management",
                    vec!["intune", "new-intune", "esp-diagnostics"],
                ),
                (
                    "System & Security",
                    vec!["secureboot", "dns-dhcp", "macos-diag"],
                ),
            ]
        );
        assert_eq!(
            group_ids(&workspace_groups(MenuPlatform::Linux, &available)),
            [
                ("Analysis", vec!["log", "event-log", "timeline"]),
                (
                    "Endpoint Management",
                    vec!["intune", "new-intune", "esp-diagnostics"],
                ),
                ("System & Security", vec!["secureboot", "dns-dhcp"]),
            ]
        );
    }

    #[test]
    fn workspace_group_labels_preserve_literal_ampersands_in_native_menus() {
        assert_eq!(WorkspaceGroup::SystemSecurity.label(), "System & Security");
        assert_eq!(
            WorkspaceGroup::SystemSecurity.native_label(),
            "System && Security"
        );
    }

    #[test]
    fn every_backend_available_workspace_has_a_menu_descriptor() {
        for workspace_id in get_available_workspaces() {
            assert!(
                workspace_descriptor(workspace_id).is_some(),
                "missing menu descriptor for {workspace_id}"
            );
        }
    }

    #[test]
    fn workspace_groups_omit_empty_groups_in_reduced_builds() {
        let groups = workspace_groups(MenuPlatform::Linux, &["log", "timeline"]);
        assert_eq!(group_ids(&groups), [("Analysis", vec!["log", "timeline"])]);
    }

    #[test]
    fn menu_state_deserializes_the_frontend_camel_case_contract() {
        let state: AppMenuState = serde_json::from_value(serde_json::json!({
            "activeWorkspace": "log",
            "openFileLabel": "Open file…",
            "openFolderLabel": "Open folder…",
            "canOpenSources": true,
            "canOpenKnownSources": true,
            "canFind": true,
            "hasFindSession": false,
            "canFilter": true,
            "canPauseResume": true,
            "isPaused": false,
            "canRefresh": true,
            "canToggleSidebar": true,
            "isSidebarVisible": true,
            "canToggleDetailsPane": true,
            "isDetailsVisible": true,
            "canToggleInfoPane": true,
            "isInfoPaneVisible": true,
            "canAdjustTextSize": true,
            "canShowEvidenceBundle": false,
            "canSaveSession": false,
            "canCollectDiagnostics": true
        }))
        .unwrap();

        assert_eq!(state, sample_menu_state());
    }

    #[test]
    fn menu_state_projects_dynamic_labels_capabilities_and_pause_text() {
        let mut state = sample_menu_state();
        state.open_file_label = "Import captured evidence…".to_string();
        state.open_folder_label = "Import evidence folder…".to_string();
        state.can_open_sources = false;
        state.can_open_known_sources = false;
        state.has_find_session = false;
        state.is_paused = true;
        state.can_adjust_text_size = false;
        state.can_collect_diagnostics = false;

        let updates =
            app_menu_updates(&state, MenuPlatform::Windows, &all_workspace_ids()).unwrap();

        let open_file = update_by_id(&updates, MENU_ID_FILE_OPEN_LOG_FILE);
        assert_eq!(open_file.text.as_deref(), Some("Import captured evidence…"));
        assert!(!open_file.enabled);
        assert!(!update_by_id(&updates, MENU_ID_FILE_KNOWN_SOURCES).enabled);
        assert!(update_by_id(&updates, MENU_ID_EDIT_FIND_NEXT).enabled);
        assert_eq!(
            update_by_id(&updates, MENU_ID_VIEW_TOGGLE_PAUSE)
                .text
                .as_deref(),
            Some("Resume Live Updates")
        );
        assert!(!update_by_id(&updates, MENU_ID_VIEW_TEXT_SIZE).enabled);
        assert!(!update_by_id(&updates, MENU_ID_VIEW_TEXT_SIZE_INCREASE).enabled);
        let collector = update_by_id(&updates, MENU_ID_TOOLS_COLLECT_DIAGNOSTICS);
        assert!(collector.optional);
        assert!(!collector.enabled);
    }

    #[test]
    fn workspace_updates_have_exactly_one_active_check() {
        let mut state = sample_menu_state();
        state.active_workspace = "esp-diagnostics".to_string();
        let updates =
            app_menu_updates(&state, MenuPlatform::Windows, &all_workspace_ids()).unwrap();
        let checked = updates
            .iter()
            .filter(|update| {
                update.id.starts_with(WORKSPACE_MENU_ID_PREFIX) && update.checked == Some(true)
            })
            .collect::<Vec<_>>();

        assert_eq!(checked.len(), 1);
        assert_eq!(checked[0].id, "workspace.esp-diagnostics");
        assert!(!checked[0].optional);
    }

    #[test]
    fn workspace_updates_reject_unknown_platform_or_feature_absent_targets() {
        assert!(
            workspace_menu_updates("not-real", MenuPlatform::Windows, &all_workspace_ids())
                .is_err()
        );
        assert!(
            workspace_menu_updates("sysmon", MenuPlatform::Macos, &all_workspace_ids()).is_err()
        );
        assert!(workspace_menu_updates(
            "esp-diagnostics",
            MenuPlatform::Windows,
            &["log", "timeline"]
        )
        .is_err());
    }

    #[test]
    fn every_static_action_has_the_expected_payload() {
        let cases = [
            (MENU_ID_FILE_OPEN_LOG_FILE, "open_log_file_dialog", "file"),
            (
                MENU_ID_FILE_OPEN_LOG_FOLDER,
                "open_log_folder_dialog",
                "file",
            ),
            (
                MENU_ID_FILE_NEW_TIMELINE_FROM_FOLDER,
                "timeline_new_from_folder",
                "file",
            ),
            (
                MENU_ID_FILE_NEW_EMPTY_TIMELINE,
                "timeline_new_empty",
                "file",
            ),
            (MENU_ID_FILE_OPEN_SESSION, "open_session", "file"),
            (MENU_ID_FILE_SAVE_SESSION, "save_session", "file"),
            (MENU_ID_EDIT_FIND, "show_find", "edit"),
            (MENU_ID_EDIT_FIND_NEXT, "find_next", "edit"),
            (MENU_ID_EDIT_FIND_PREVIOUS, "find_previous", "edit"),
            (MENU_ID_EDIT_FILTER, "show_filter", "edit"),
            (MENU_ID_VIEW_TOGGLE_SIDEBAR, "toggle_sidebar", "view"),
            (MENU_ID_VIEW_TOGGLE_PAUSE, "toggle_pause", "view"),
            (MENU_ID_VIEW_REFRESH, "refresh", "view"),
            (
                MENU_ID_VIEW_TEXT_SIZE_INCREASE,
                "increase_text_size",
                "view",
            ),
            (
                MENU_ID_VIEW_TEXT_SIZE_DECREASE,
                "decrease_text_size",
                "view",
            ),
            (MENU_ID_VIEW_TEXT_SIZE_RESET, "reset_text_size", "view"),
            (MENU_ID_TOOLS_ERROR_LOOKUP, "show_error_lookup", "tools"),
            (MENU_ID_TOOLS_GUID_REGISTRY, "show_guid_registry", "tools"),
            (
                MENU_ID_TOOLS_BUNDLE_SUMMARY,
                "show_evidence_bundle",
                "tools",
            ),
            (
                MENU_ID_TOOLS_COLLECT_DIAGNOSTICS,
                "collect_diagnostics",
                "tools",
            ),
            (MENU_ID_WINDOW_TOGGLE_DETAILS, "toggle_details", "window"),
            (MENU_ID_WINDOW_TOGGLE_INFO, "toggle_info_pane", "window"),
            (
                MENU_ID_WINDOW_ALWAYS_ON_TOP,
                "toggle_always_on_top",
                "window",
            ),
            (MENU_ID_WINDOW_SETTINGS, "show_settings", "window"),
            (MENU_ID_HELP_CHECK_FOR_UPDATES, "check_for_updates", "help"),
            (MENU_ID_HELP_ABOUT, "show_about", "help"),
        ];

        for (menu_id, action, category) in cases {
            let payload = payload_for_menu_id(menu_id).expect(menu_id);
            assert_eq!(payload.action, action);
            assert_eq!(payload.category, category);
            assert_eq!(payload.source_id, None);
            assert_eq!(payload.target_id, None);
            assert_eq!(payload.path, None);
            assert_eq!(payload.workspace, None);
            assert_eq!(payload.kind, None);
        }
    }

    #[test]
    fn workspace_payload_uses_target_id_exclusively() {
        let payload = payload_for_menu_id("workspace.esp-diagnostics").unwrap();
        assert_eq!(payload.action, "switch_workspace");
        assert_eq!(payload.category, "workspace");
        assert_eq!(payload.source_id, None);
        assert_eq!(payload.target_id.as_deref(), Some("esp-diagnostics"));
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }

    #[test]
    fn known_source_payload_uses_source_id_exclusively() {
        let payload = payload_for_menu_id("known-source.intune-ime").unwrap();
        assert_eq!(payload.action, "open_known_source");
        assert_eq!(payload.category, "known_source");
        assert_eq!(payload.source_id.as_deref(), Some("intune-ime"));
        assert_eq!(payload.target_id, None);
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }

    #[test]
    fn placeholders_submenus_and_unknown_ids_do_not_emit_actions() {
        assert!(payload_for_menu_id("known-source.unavailable").is_none());
        assert!(payload_for_menu_id("workspace.group.analysis").is_none());
        assert!(payload_for_menu_id("workspace.not-real").is_none());
        assert!(payload_for_menu_id(MENU_ID_FILE_KNOWN_SOURCES).is_none());
        assert!(payload_for_menu_id(MENU_ID_FILE_RECENT).is_none());
        assert!(payload_for_menu_id("not.a.menu.id").is_none());
    }

    #[test]
    fn recent_submenu_appears_after_known_sources_on_every_platform() {
        for order in [FILE_ORDER, FILE_ORDER_MAC] {
            let known = order
                .iter()
                .position(|id| *id == MENU_ID_FILE_KNOWN_SOURCES)
                .expect("known sources present");
            let recent = order
                .iter()
                .position(|id| *id == MENU_ID_FILE_RECENT)
                .expect("recent present");
            assert_eq!(recent, known + 1);
        }
    }

    #[test]
    fn recent_label_includes_name_parent_and_workspace() {
        let entry = RecentEntry {
            path: "/evidence/IME/IntuneManagementExtension.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "intune".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(
            recent_entry_label(&entry),
            "IntuneManagementExtension.log — IME (Intune Diagnostics)"
        );
    }

    #[test]
    fn recent_label_for_folder_uses_folder_and_its_parent() {
        let entry = RecentEntry {
            path: "/evidence/bundle-01/IME".to_string(),
            kind: RecentEntryKind::Folder,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(
            recent_entry_label(&entry),
            "IME — bundle-01 (Log Explorer)"
        );
    }

    #[test]
    fn recent_label_drops_parent_segment_when_there_is_no_parent() {
        let entry = RecentEntry {
            path: "/only.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(recent_entry_label(&entry), "only.log (Log Explorer)");
    }

    #[test]
    fn recent_label_falls_back_when_the_workspace_is_unknown() {
        let entry = RecentEntry {
            path: "/a/b.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "not-a-workspace".to_string(),
            opened_at_unix_ms: 0,
        };

        assert!(recent_entry_label(&entry).ends_with("(Unknown Workspace)"));
    }

    #[test]
    fn recent_entry_hash_keeps_the_full_64_bit_digest() {
        // A truncated hash raises the odds of a collision, which would defeat
        // the stale-row check and reopen the wrong entry.
        let entry = RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };

        let hash = recent_entry_hash(&entry);

        assert_eq!(hash.len(), 16, "expected a full 64-bit digest");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex, got {hash}"
        );
    }

    #[test]
    fn recent_entry_hash_distinguishes_workspace_from_path() {
        let file = |path: &str, workspace: &str| RecentEntry {
            path: path.to_string(),
            kind: RecentEntryKind::File,
            workspace: workspace.to_string(),
            opened_at_unix_ms: 0,
        };

        assert_ne!(
            recent_entry_hash(&file("/a.log", "log")),
            recent_entry_hash(&file("/a.log", "dsregcmd")),
            "same path in two workspaces must not share an id"
        );
        assert_ne!(
            recent_entry_hash(&file("/a.log", "log")),
            recent_entry_hash(&file("/b.log", "log")),
        );
    }

    #[test]
    fn recent_entry_menu_id_maps_to_open_recent_entry() {
        let entry = RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };
        let menu_id = recent_menu_id(3, &entry);

        let payload = payload_for_menu_id(&menu_id).expect("payload");
        assert_eq!(payload.action, "open_recent_entry");
        assert_eq!(payload.category, "file");
        assert_eq!(payload.target_id.as_deref(), Some("3"));
        // payload_for_menu_id is pure: enrichment is enrich_recent_payload's job.
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }

    #[test]
    fn recent_placeholder_menu_id_produces_no_payload() {
        assert!(payload_for_menu_id(RECENT_UNAVAILABLE_MENU_ID).is_none());
    }

    #[test]
    fn recent_clear_menu_id_maps_to_clear_recent_entries() {
        let payload = payload_for_menu_id(MENU_ID_FILE_RECENT_CLEAR).expect("payload");
        assert_eq!(payload.action, "clear_recent_entries");
        assert_eq!(payload.category, "file");
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }

    #[test]
    fn recent_menu_id_round_trips_through_parse_recent_menu_id() {
        let entry = RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };
        let menu_id = recent_menu_id(2, &entry);

        let (index, hash) = parse_recent_menu_id(&menu_id).expect("parses");
        assert_eq!(index, 2);
        assert_eq!(hash, recent_entry_hash(&entry));
    }

    #[test]
    fn parse_recent_menu_id_rejects_the_placeholder_and_a_bare_prefix() {
        assert!(parse_recent_menu_id(RECENT_UNAVAILABLE_MENU_ID).is_none());
        assert!(parse_recent_menu_id(RECENT_MENU_ID_PREFIX).is_none());
        assert!(parse_recent_menu_id("recent.3").is_none());
        assert!(parse_recent_menu_id("not.a.recent.id").is_none());
    }

    #[test]
    fn enrich_recent_payload_populates_path_workspace_and_kind_for_a_matching_file_entry() {
        let entries = vec![RecentEntry {
            path: "/evidence/IME/IntuneManagementExtension.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "intune".to_string(),
            opened_at_unix_ms: 0,
        }];

        let menu_id = recent_menu_id(0, &entries[0]);
        let mut payload = base_payload(&menu_id, "open_recent_entry", "file");
        payload.target_id = Some("0".to_string());

        assert!(enrich_recent_payload(&mut payload, &entries));
        assert_eq!(
            payload.path.as_deref(),
            Some("/evidence/IME/IntuneManagementExtension.log")
        );
        assert_eq!(payload.workspace.as_deref(), Some("intune"));
        assert_eq!(payload.kind.as_deref(), Some("file"));
    }

    #[test]
    fn enrich_recent_payload_maps_folder_kind_to_folder() {
        let entries = vec![RecentEntry {
            path: "/evidence/bundle-01/IME".to_string(),
            kind: RecentEntryKind::Folder,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        }];

        let menu_id = recent_menu_id(0, &entries[0]);
        let mut payload = base_payload(&menu_id, "open_recent_entry", "file");
        payload.target_id = Some("0".to_string());

        assert!(enrich_recent_payload(&mut payload, &entries));
        assert_eq!(payload.kind.as_deref(), Some("folder"));
    }

    #[test]
    fn enrich_recent_payload_rejects_an_out_of_range_index() {
        let entries = vec![RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        }];

        let mut payload = base_payload("recent.5.deadbeef", "open_recent_entry", "file");
        payload.target_id = Some("5".to_string());

        assert!(!enrich_recent_payload(&mut payload, &entries));
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }

    #[test]
    fn enrich_recent_payload_rejects_an_unparsable_menu_id() {
        let entries = vec![RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        }];

        let mut placeholder_payload =
            base_payload(RECENT_UNAVAILABLE_MENU_ID, "open_recent_entry", "file");
        assert!(!enrich_recent_payload(&mut placeholder_payload, &entries));

        let mut legacy_format_payload = base_payload("recent.0", "open_recent_entry", "file");
        assert!(!enrich_recent_payload(&mut legacy_format_payload, &entries));
    }

    #[test]
    fn enrich_recent_payload_rejects_a_stale_index_whose_hash_no_longer_matches() {
        let original = RecentEntry {
            path: "/evidence/a.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };
        let menu_id = recent_menu_id(0, &original);

        // Entry 0 has since been replaced by a different file at the same
        // index (e.g. a concurrent push, or a prune that dropped an older
        // row) — same shape, same index, different identity.
        let shifted = vec![RecentEntry {
            path: "/evidence/different.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        }];

        let mut payload = base_payload(&menu_id, "open_recent_entry", "file");
        payload.target_id = Some("0".to_string());

        assert!(!enrich_recent_payload(&mut payload, &shifted));
        assert_eq!(payload.path, None);
        assert_eq!(payload.workspace, None);
        assert_eq!(payload.kind, None);
    }
}
