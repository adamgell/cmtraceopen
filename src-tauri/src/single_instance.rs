//! Opening a file in the window that is already running.
//!
//! A file association hands the launch to a new process, so double-clicking a
//! log while CMTrace Open is open produces a second window holding one tab while
//! the window the user works in drifts away (issue #565). The single-instance
//! plugin makes that second process hand its arguments to the first one and
//! exit, which decides *who* opens the file. This module decides *what* is
//! opened and how it reaches the window already on screen.

use tauri::{plugin::TauriPlugin, AppHandle, Emitter, Manager, Runtime};

use crate::{parse_initial_launch_arguments, InitialLaunchArguments};

/// Event the running window receives the forwarded file paths on.
///
/// One event is the whole contract: a forwarded launch reaches the frontend
/// through no other channel, so its paths cannot be opened twice.
const OPEN_EVENT: &str = "second-launch-open";

/// The file paths a second launch asks the running window to open.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct ForwardedOpenRequest {
    paths: Vec<String>,
}

/// Parses the argv a second launch forwards to the running instance.
///
/// A forwarded vector is a whole argv, so element zero is the executable the
/// user launched rather than evidence. Everything after it goes through
/// [`parse_initial_launch_arguments`], so a positional file path keeps one
/// definition across both launches and an app-owned option can never arrive as
/// a file to open.
fn parse_forwarded_open_request(
    arguments: impl IntoIterator<Item = String>,
) -> ForwardedOpenRequest {
    let mut arguments = arguments.into_iter();
    arguments.next();

    ForwardedOpenRequest {
        paths: parse_initial_launch_arguments(arguments).file_paths,
    }
}

/// Whether this launch replaces a running instance rather than joining it.
///
/// An elevated relaunch is started while the process it replaces is still
/// shutting down, and only that process exiting releases the single-instance
/// lock. Routing the relaunch into the closing window would leave the user with
/// nothing on screen, so a launch carrying a restore ticket never registers the
/// handler.
pub(crate) fn is_replacement_launch(launch: &InitialLaunchArguments) -> bool {
    launch.elevation_restore.is_some()
}

/// The plugin that routes a second launch into the running instance.
///
/// It is registered before every other plugin: it detects the running instance
/// and exits while the app is still being built, which is what keeps a second
/// launch from showing the empty window `tauri.conf.json` declares before it
/// exits.
pub(crate) fn plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_single_instance::Builder::new()
        .callback(|app, arguments, _working_directory| {
            handle(app, parse_forwarded_open_request(arguments));
        })
        .build()
}

/// Opens the paths a second launch forwarded in the window that is running.
///
/// The window is raised for every forwarded launch, including one that carries
/// no paths at all: launching the app again is a request for the window that
/// already exists. The paths travel to the frontend as one event, which opens
/// them through the flow it uses for a file passed to the running window, so a
/// forwarded file lands in a tab and in Recent like any other open.
fn handle<R: Runtime>(app: &AppHandle<R>, request: ForwardedOpenRequest) {
    if let Some(window) = app.get_webview_window("main") {
        // The window is where the file opens, so a window the user minimized or
        // hid is raised rather than left behind the app they just launched.
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }

    if request.paths.is_empty() {
        return;
    }

    if let Err(error) = app.emit(OPEN_EVENT, request) {
        log::error!("failed to hand forwarded file paths to the running window: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXECUTABLE: &str = r"C:\Program Files\CMTrace Open\CMTrace Open.exe";

    #[test]
    fn a_forwarded_launch_opens_the_path_that_follows_the_executable() {
        let request = parse_forwarded_open_request(
            [EXECUTABLE, r"C:\Windows\CCM\Logs\ccmexec.log"].map(String::from),
        );

        assert_eq!(request.paths, [r"C:\Windows\CCM\Logs\ccmexec.log"]);
        assert_eq!(
            serde_json::to_value(&request).expect("payload serializes"),
            serde_json::json!({ "paths": [r"C:\Windows\CCM\Logs\ccmexec.log"] }),
        );
    }

    #[test]
    fn a_forwarded_path_containing_spaces_survives_intact() {
        let request = parse_forwarded_open_request(
            [
                EXECUTABLE,
                r"C:\Program Files\Microsoft Intune Management Extension\Logs\IntuneManagementExtension.log",
            ]
            .map(String::from),
        );

        assert_eq!(
            request.paths,
            [r"C:\Program Files\Microsoft Intune Management Extension\Logs\IntuneManagementExtension.log"],
        );
        assert_eq!(
            serde_json::to_value(&request).expect("payload serializes"),
            serde_json::json!({
                "paths": [
                    r"C:\Program Files\Microsoft Intune Management Extension\Logs\IntuneManagementExtension.log",
                ],
            }),
        );
    }

    #[test]
    fn a_forwarded_launch_opens_every_path_it_carries() {
        let request = parse_forwarded_open_request(
            [
                EXECUTABLE,
                r"C:\Windows\CCM\Logs\ccmexec.log",
                r"C:\Windows\CCM\Logs\InventoryAgent.log",
                r"C:\Windows\CCM\Logs\PolicyAgent.log",
            ]
            .map(String::from),
        );

        assert_eq!(
            request.paths,
            [
                r"C:\Windows\CCM\Logs\ccmexec.log",
                r"C:\Windows\CCM\Logs\InventoryAgent.log",
                r"C:\Windows\CCM\Logs\PolicyAgent.log",
            ],
        );
        assert_eq!(
            serde_json::to_value(&request).expect("payload serializes"),
            serde_json::json!({
                "paths": [
                    r"C:\Windows\CCM\Logs\ccmexec.log",
                    r"C:\Windows\CCM\Logs\InventoryAgent.log",
                    r"C:\Windows\CCM\Logs\PolicyAgent.log",
                ],
            }),
        );
    }

    #[test]
    fn a_forwarded_launch_without_paths_opens_nothing() {
        let bare_relaunch = parse_forwarded_open_request([EXECUTABLE].map(String::from));

        assert!(bare_relaunch.paths.is_empty());
        assert_eq!(
            serde_json::to_value(&bare_relaunch).expect("payload serializes"),
            serde_json::json!({ "paths": [] }),
        );

        let no_arguments = parse_forwarded_open_request(Vec::<String>::new());

        assert!(no_arguments.paths.is_empty());
    }

    #[test]
    fn a_forwarded_launch_never_opens_an_app_owned_option_as_a_path() {
        // A relaunch passes the app's own options. They are not evidence, and
        // forwarding one must never ask the running window to open a file.
        let id = crate::elevation::restore_ticket::new_ticket_id();
        let request = parse_forwarded_open_request([
            EXECUTABLE.to_string(),
            format!("--elevation-restore={id}"),
            "--workspace=esp-diagnostics".to_string(),
        ]);

        assert!(request.paths.is_empty());
        assert_eq!(
            serde_json::to_value(&request).expect("payload serializes"),
            serde_json::json!({ "paths": [] }),
        );
    }

    #[test]
    fn an_elevated_relaunch_is_a_replacement_not_a_second_launch() {
        // The elevated process replaces the one that launched it while that
        // process is still shutting down, so suppressing it as a duplicate
        // would leave the user with no window at all.
        let id = crate::elevation::restore_ticket::new_ticket_id();
        let relaunch = crate::parse_initial_launch_arguments([
            format!("--elevation-restore={id}"),
            "--workspace=esp-diagnostics".to_string(),
        ]);

        assert!(is_replacement_launch(&relaunch));

        let association =
            crate::parse_initial_launch_arguments([r"C:\Logs\ime.log".to_string()]);

        assert!(!is_replacement_launch(&association));
    }
}
