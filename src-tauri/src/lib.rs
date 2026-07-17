#[cfg(feature = "collector")]
pub mod collector;
mod commands;
mod constants;
#[cfg(feature = "dsregcmd")]
pub mod dsregcmd;
pub mod error;
pub use cmtraceopen_parser::error_db;
#[cfg(feature = "esp-diagnostics")]
pub mod esp;
#[cfg(feature = "event-log")]
pub mod event_log;
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
pub mod timeline;
mod watcher;

use state::app_state::AppState;

#[cfg(target_os = "windows")]
use graph_api::GraphAuthState;
#[cfg(target_os = "windows")]
use tauri::Manager;

const ESP_STARTUP_WORKSPACE: &str = "esp-diagnostics";

#[derive(Debug, Default, PartialEq, Eq)]
struct InitialLaunchArguments {
    file_paths: Vec<String>,
    workspace: Option<String>,
}

/// Parses app-owned startup options separately from positional file paths.
///
/// The elevation flow emits an exact workspace option so the replacement
/// process returns to ESP Diagnostics. Split workspace values are consumed
/// even when unsupported so they can never be mistaken for file paths.
fn parse_initial_launch_arguments(
    arguments: impl IntoIterator<Item = String>,
) -> InitialLaunchArguments {
    let mut launch = InitialLaunchArguments::default();
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        if argument.eq_ignore_ascii_case("--workspace") {
            if let Some(value) = arguments.next() {
                if cfg!(feature = "esp-diagnostics")
                    && value.eq_ignore_ascii_case(ESP_STARTUP_WORKSPACE)
                {
                    launch.workspace = Some(ESP_STARTUP_WORKSPACE.to_string());
                }
            }
            continue;
        }

        if cfg!(feature = "esp-diagnostics")
            && (argument.eq_ignore_ascii_case("--workspace=esp-diagnostics")
                || argument.eq_ignore_ascii_case("--esp-diagnostics"))
        {
            launch.workspace = Some(ESP_STARTUP_WORKSPACE.to_string());
        } else if !argument.starts_with('-') {
            launch.file_paths.push(argument);
        }
    }

    launch
}

#[cfg(test)]
mod startup_argument_tests {
    use super::parse_initial_launch_arguments;

    fn strings(arguments: &[&str]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| argument.to_string())
            .collect()
    }

    #[cfg(feature = "esp-diagnostics")]
    #[test]
    fn esp_workspace_equals_argument_routes_without_becoming_a_file_path() {
        let launch = parse_initial_launch_arguments(strings(&["--workspace=esp-diagnostics"]));

        assert_eq!(launch.workspace.as_deref(), Some("esp-diagnostics"));
        assert!(launch.file_paths.is_empty());
    }

    #[cfg(feature = "esp-diagnostics")]
    #[test]
    fn esp_workspace_split_argument_consumes_its_value_and_keeps_real_paths() {
        let launch = parse_initial_launch_arguments(strings(&[
            "--workspace",
            "esp-diagnostics",
            r"C:\Windows\Temp\ime.log",
        ]));

        assert_eq!(launch.workspace.as_deref(), Some("esp-diagnostics"));
        assert_eq!(launch.file_paths, [r"C:\Windows\Temp\ime.log"]);
    }

    #[test]
    fn unapproved_workspace_values_are_neither_routed_nor_opened_as_files() {
        let launch = parse_initial_launch_arguments(strings(&[
            "--workspace",
            "future-workspace",
            r"C:\Logs\real.log",
        ]));

        assert_eq!(launch.workspace, None);
        assert_eq!(launch.file_paths, [r"C:\Logs\real.log"]);
    }

    #[cfg(feature = "esp-diagnostics")]
    #[test]
    fn legacy_esp_alias_is_accepted_case_insensitively() {
        let launch = parse_initial_launch_arguments(strings(&["--ESP-DIAGNOSTICS"]));

        assert_eq!(launch.workspace.as_deref(), Some("esp-diagnostics"));
        assert!(launch.file_paths.is_empty());
    }

    #[cfg(not(feature = "esp-diagnostics"))]
    #[test]
    fn esp_workspace_argument_is_ignored_when_the_feature_is_not_built() {
        let launch = parse_initial_launch_arguments(strings(&[
            "--workspace=esp-diagnostics",
            r"C:\Logs\real.log",
        ]));

        assert_eq!(launch.workspace, None);
        assert_eq!(launch.file_paths, [r"C:\Logs\real.log"]);
    }
}

// Keep the ESP Graph commands in one handler fragment so the production app
// and the registration-level test exercise the same generated Tauri routes.
macro_rules! app_invoke_handler {
    ($($command:tt)*) => {
        tauri::generate_handler![
            $($command)*
            #[cfg(feature = "esp-diagnostics")]
            $crate::commands::graph_api::graph_fetch_esp_diagnostics,
            #[cfg(feature = "esp-diagnostics")]
            $crate::commands::graph_api::graph_cancel_esp_diagnostics,
        ]
    };
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let initial_launch = parse_initial_launch_arguments(std::env::args().skip(1));

    // Route panics to the persistent log so a hard crash (e.g. the reported
    // out-of-memory failure) leaves a line users can attach to a report.
    // Chained after the default hook so the standard abort message is kept.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("panic: {info}");
        default_panic_hook(info);
    }));

    let builder = tauri::Builder::default();

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_window_state::Builder::default().build());

    let app = builder
        // Persistent file logging (issue #193): the backend already uses the
        // `log` facade throughout, but no logger backend was ever registered so
        // those messages went nowhere. Write to the OS app-log dir with a size
        // cap + rotation, and keep stderr for `npm run app:dev`.
        .plugin(
            tauri_plugin_log::Builder::new()
                .targets([
                    tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir {
                        file_name: Some("cmtrace-open".into()),
                    }),
                    tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stderr),
                ])
                .level(log::LevelFilter::Info)
                .max_file_size(5_000_000)
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepOne)
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .manage(AppState::with_initial_launch(
            initial_launch.file_paths,
            initial_launch.workspace,
        ))
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

            {
                use tauri::Manager as _;
                app.manage(commands::timeline::TimelineRuntimeMap::new());
            }

            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::initialize_esp_session_manager(app.handle())?;

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
        .invoke_handler(app_invoke_handler![
            commands::file_association::get_file_association_prompt_status,
            commands::file_association::associate_log_files_with_app,
            commands::file_association::set_file_association_prompt_suppressed,
            commands::app_config::get_available_workspaces,
            commands::app_config::get_update_policy,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::get_esp_diagnostics_capability,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::get_esp_elevation_state,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::analyze_esp_evidence,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::start_esp_diagnostics_session,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::get_esp_diagnostics_session,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::stop_esp_diagnostics_session,
            #[cfg(feature = "esp-diagnostics")]
            commands::esp_diagnostics::restart_esp_as_administrator,
            commands::dns_dhcp::check_dns_logging_status,
            commands::dns_dhcp::enable_dns_debug_logging,
            commands::dns_dhcp::collect_dns_dhcp_from_domain,
            commands::file_ops::open_log_file,
            commands::file_ops::parse_files_batch,
            commands::file_ops::open_log_folder_aggregate,
            commands::file_ops::list_log_folder,
            commands::file_ops::inspect_path_kind,
            commands::file_ops::write_text_output_file,
            commands::file_ops::get_initial_file_paths,
            commands::file_ops::get_initial_workspace,
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
            commands::timeline::build_timeline_cmd,
            commands::timeline::close_timeline_cmd,
            commands::timeline::query_incident_details_cmd,
            commands::timeline::query_lane_buckets_cmd,
            commands::timeline::query_timeline_entries_cmd,
            commands::timeline::update_timeline_tunables_cmd,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    #[cfg(feature = "esp-diagnostics")]
    app.run(|app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            if let Err(error) = commands::esp_diagnostics::shutdown_esp_session_manager(app_handle)
            {
                log::error!("ESP diagnostics shutdown failed: {error}");
            }
        }
    });

    #[cfg(not(feature = "esp-diagnostics"))]
    app.run(|_, _| {});
}

#[cfg(all(test, feature = "esp-diagnostics", not(target_os = "windows")))]
mod tests {
    use cmtraceopen_parser::esp::EspIdentityEvidence;
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};

    use crate::graph_api::esp::EspGraphRequest;

    fn invoke_request(command: &str, body: serde_json::Value) -> tauri::webview::InvokeRequest {
        tauri::webview::InvokeRequest {
            cmd: command.into(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            url: "tauri://localhost".parse().expect("test origin"),
            body: tauri::ipc::InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        }
    }

    fn graph_request() -> EspGraphRequest {
        EspGraphRequest {
            request_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            identity: EspIdentityEvidence {
                device_name: Some("DEVICE-01".to_string()),
                managed_device_id: None,
                entra_device_id: None,
                entdm_id: None,
                tenant_id: None,
                tenant_domain: None,
                user_principal_name: None,
                serial_number: None,
                evidence: Vec::new(),
            },
            workload_ids: Vec::new(),
            selected_managed_device_id: None,
            evidence_window_start_utc: None,
            evidence_window_end_utc: None,
            enrollment_configuration_ids: Vec::new(),
            app_ids: Vec::new(),
            policy_references: Vec::new(),
            script_references: Vec::new(),
        }
    }

    #[test]
    fn esp_graph_tauri_commands_are_registered() {
        let app = mock_builder()
            .invoke_handler(app_invoke_handler![])
            .build(mock_context(noop_assets()))
            .expect("mock app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("mock webview");

        let fetch_error = get_ipc_response(
            &webview,
            invoke_request(
                "graph_fetch_esp_diagnostics",
                serde_json::json!({ "request": graph_request() }),
            ),
        )
        .expect_err("Graph ESP is unavailable off Windows");
        let cancel_error = get_ipc_response(
            &webview,
            invoke_request(
                "graph_cancel_esp_diagnostics",
                serde_json::json!({ "requestId": "550e8400-e29b-41d4-a716-446655440000" }),
            ),
        )
        .expect_err("Graph ESP is unavailable off Windows");

        for error in [fetch_error, cancel_error] {
            let rendered = error.to_string();
            assert!(
                rendered.contains("GraphEspDiagnostics"),
                "registered command must return its typed platform error, got: {rendered}"
            );
            assert!(!rendered.to_ascii_lowercase().contains("not found"));
        }
    }
}
