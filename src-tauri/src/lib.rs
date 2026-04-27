#[cfg(feature = "collector")]
pub mod collector;
mod commands;
mod constants;
#[cfg(feature = "dsregcmd")]
pub mod dsregcmd;
pub mod error;
pub use cmtraceopen_parser::error_db;
#[cfg(feature = "event-log")]
pub mod event_log;
#[cfg(target_os = "windows")]
pub mod graph_api;
pub mod intune;
#[cfg(debug_assertions)]
mod ipc_bridge;
#[cfg(feature = "macos-diag")]
pub mod macos_diag;
mod menu;
pub use cmtraceopen_parser::models;
pub mod parser;
pub mod process_util;
#[cfg(feature = "secureboot")]
pub mod secureboot;
mod state;
#[cfg(feature = "sysmon")]
pub mod sysmon;
mod watcher;

use state::app_state::AppState;

#[cfg(target_os = "windows")]
use graph_api::GraphAuthState;
#[cfg(target_os = "windows")]
use tauri::Manager;

/// Returns all non-flag CLI arguments as potential file paths.
///
/// When the OS opens the application via a file association (e.g. double-clicking
/// a `.log` file), the file path is passed as a positional argument.
/// Multiple files can be passed (e.g. `cmtraceopen file1.log file2.log`).
/// Flags (arguments starting with `-`) are skipped so that internal Tauri or
/// platform arguments do not get misidentified as file paths.
fn get_initial_file_paths_from_args() -> Vec<String> {
    std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let initial_file_paths = get_initial_file_paths_from_args();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            #[cfg(desktop)]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;

            let native_menu = menu::build_app_menu(app.handle())?;
            app.set_menu(native_menu)?;

            app.on_menu_event(|app_handle, event| {
                menu::handle_menu_event(app_handle, event.id().as_ref());
            });

            #[cfg(target_os = "windows")]
            app.manage(GraphAuthState::new());

            // Auto-open DevTools in debug builds
            #[cfg(all(debug_assertions, desktop))]
            {
                use tauri::Manager as _;
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }

            // Start the Playwright IPC bridge in debug builds so a browser
            // loaded at the Vite dev server (:1420) can make real Rust IPC calls.
            #[cfg(debug_assertions)]
            tauri::async_runtime::spawn(ipc_bridge::start(1422));

            Ok(())
        })
        .manage(AppState::new(initial_file_paths))
        .invoke_handler(tauri::generate_handler![
            commands::file_association::get_file_association_prompt_status,
            commands::file_association::associate_log_files_with_app,
            commands::file_association::set_file_association_prompt_suppressed,
            commands::app_config::get_available_workspaces,
            commands::file_ops::open_log_file,
            commands::file_ops::parse_files_batch,
            commands::file_ops::open_log_folder_aggregate,
            commands::file_ops::list_log_folder,
            commands::file_ops::inspect_path_kind,
            commands::file_ops::write_text_output_file,
            commands::file_ops::get_initial_file_paths,
            commands::file_ops::compute_file_hash,
            commands::bundle_ops::inspect_evidence_bundle,
            commands::bundle_ops::inspect_evidence_artifact,
            commands::known_sources::get_known_log_sources,
            commands::registry_ops::parse_registry_file,
            commands::system_preferences::get_system_date_time_preferences,
            commands::parsing::start_tail,
            commands::parsing::stop_tail,
            commands::parsing::pause_tail,
            commands::parsing::resume_tail,
            commands::filter::apply_filter,
            commands::error_lookup::lookup_error_code,
            commands::error_lookup::search_error_codes,
            #[cfg(feature = "intune-diagnostics")]
            commands::intune::analyze_intune_logs,
            #[cfg(feature = "deployment")]
            commands::deployment::analyze_deployment_folder,
            commands::fonts::list_system_fonts,
            commands::markers::load_markers,
            commands::markers::save_markers,
            commands::markers::delete_markers,
            commands::reveal::reveal_in_file_manager,
            #[cfg(feature = "dsregcmd")]
            commands::dsregcmd::analyze_dsregcmd,
            #[cfg(feature = "dsregcmd")]
            commands::dsregcmd::capture_dsregcmd,
            #[cfg(feature = "dsregcmd")]
            commands::dsregcmd::load_dsregcmd_source,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_scan_environment,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_scan_intune_logs,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_list_profiles,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_inspect_defender,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_list_packages,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_get_package_info,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_get_package_files,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_query_unified_log,
            #[cfg(feature = "macos-diag")]
            commands::macos_diag::macos_open_system_settings,
            #[cfg(feature = "collector")]
            commands::collector::collect_diagnostics,
            #[cfg(feature = "event-log")]
            event_log::commands::evtx_parse_files,
            #[cfg(feature = "event-log")]
            event_log::commands::evtx_enumerate_channels,
            #[cfg(feature = "event-log")]
            event_log::commands::evtx_query_channels,
            #[cfg(target_os = "windows")]
            commands::graph_api::graph_authenticate,
            #[cfg(target_os = "windows")]
            commands::graph_api::graph_get_auth_status,
            #[cfg(target_os = "windows")]
            commands::graph_api::graph_sign_out,
            #[cfg(target_os = "windows")]
            commands::graph_api::graph_resolve_guids,
            #[cfg(target_os = "windows")]
            commands::graph_api::graph_fetch_all_apps,
            #[cfg(feature = "secureboot")]
            commands::secureboot::analyze_secureboot,
            #[cfg(feature = "secureboot")]
            commands::secureboot::rescan_secureboot,
            #[cfg(feature = "secureboot")]
            commands::secureboot::run_secureboot_detection,
            #[cfg(feature = "secureboot")]
            commands::secureboot::run_secureboot_remediation,
            #[cfg(feature = "sysmon")]
            commands::sysmon::analyze_sysmon_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
