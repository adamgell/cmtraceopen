mod constants;
pub mod collector;
mod commands;
pub mod dsregcmd;
pub mod error;
pub mod macos_diag;
pub mod error_db;
pub mod intune;
mod menu;
mod models;
pub mod parser;
mod state;
mod watcher;

use state::app_state::AppState;

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
            app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
            let native_menu = menu::build_app_menu(app.handle())?;
            app.set_menu(native_menu)?;

            app.on_menu_event(|app_handle, event| {
                menu::handle_menu_event(app_handle, event.id().as_ref());
            });

            Ok(())
        })
        .manage(AppState::new(initial_file_paths))
        .invoke_handler(tauri::generate_handler![
            commands::file_association::get_file_association_prompt_status,
            commands::file_association::associate_log_files_with_app,
            commands::file_association::set_file_association_prompt_suppressed,
            commands::file_ops::open_log_file,
            commands::file_ops::parse_files_batch,
            commands::file_ops::open_log_folder_aggregate,
            commands::file_ops::list_log_folder,
            commands::file_ops::inspect_path_kind,
            commands::file_ops::write_text_output_file,
            commands::file_ops::get_initial_file_paths,
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
            commands::intune::analyze_intune_logs,
            commands::deployment::analyze_deployment_folder,
            commands::fonts::list_system_fonts,
            commands::dsregcmd::analyze_dsregcmd,
            commands::dsregcmd::capture_dsregcmd,
            commands::dsregcmd::load_dsregcmd_source,
            commands::macos_diag::macos_scan_environment,
            commands::macos_diag::macos_scan_intune_logs,
            commands::macos_diag::macos_list_profiles,
            commands::macos_diag::macos_inspect_defender,
            commands::macos_diag::macos_list_packages,
            commands::macos_diag::macos_get_package_info,
            commands::macos_diag::macos_get_package_files,
            commands::macos_diag::macos_query_unified_log,
            commands::macos_diag::macos_open_system_settings,
            commands::fonts::list_system_fonts,
            commands::collector::collect_diagnostics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
