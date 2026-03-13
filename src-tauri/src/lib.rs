mod commands;
mod error_db;
pub mod intune;
mod menu;
mod models;
pub mod parser;
mod state;
mod watcher;

use state::app_state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let native_menu = menu::build_app_menu(app.handle())?;
            app.set_menu(native_menu)?;

            app.on_menu_event(|app_handle, event| {
                menu::handle_menu_event(app_handle, event.id().as_ref());
            });

            Ok(())
        })
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::file_ops::open_log_file,
            commands::file_ops::list_log_folder,
            commands::file_ops::get_known_log_sources,
            commands::parsing::start_tail,
            commands::parsing::stop_tail,
            commands::parsing::pause_tail,
            commands::parsing::resume_tail,
            commands::filter::apply_filter,
            commands::error_lookup::lookup_error_code,
            commands::intune::analyze_intune_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
