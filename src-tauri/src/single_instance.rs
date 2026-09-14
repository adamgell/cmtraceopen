//! Opening a file in the window that is already running.
//!
//! A file association hands the launch to a new process, so double-clicking a
//! log while CMTrace Open is open produces a second window holding one tab while
//! the window the user works in drifts away (issue #565). The single-instance
//! plugin makes that second process hand its arguments to the first one and
//! exit, which decides *who* opens the file. This module decides *what* is
//! opened and how it reaches the window already on screen.

use std::path::Path;

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
///
/// `working_directory` is the directory the second launch ran in, which is what
/// a relative path in its argv means. The running instance cannot answer that
/// for it: its own working directory is wherever it was started, so
/// `cmtraceopen relative.log` from another directory would open the wrong file
/// or none at all.
fn parse_forwarded_open_request(
    arguments: impl IntoIterator<Item = String>,
    working_directory: &str,
) -> ForwardedOpenRequest {
    let mut arguments = arguments.into_iter();
    arguments.next();

    ForwardedOpenRequest {
        paths: parse_initial_launch_arguments(arguments)
            .file_paths
            .into_iter()
            .map(|path| resolve_forwarded_path(&path, working_directory))
            .collect(),
    }
}

/// Resolves a forwarded path against the directory the second launch ran in.
///
/// An absolute path is already what the second launch meant and is handed on
/// exactly as it was typed — it is not normalized, so a `..` segment or a
/// symlinked prefix opens the file the user named rather than a rewritten path.
/// A launch that could not report its directory leaves the path as it arrived:
/// there is nothing better to resolve it against than the running window's own
/// directory.
fn resolve_forwarded_path(path: &str, working_directory: &str) -> String {
    if working_directory.is_empty() || Path::new(path).is_absolute() {
        return path.to_string();
    }

    Path::new(working_directory)
        .join(path)
        .to_string_lossy()
        .into_owned()
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
        .callback(|app, arguments, working_directory| {
            handle(
                app,
                parse_forwarded_open_request(arguments, &working_directory),
            );
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
    use std::path::{Path, PathBuf};

    const EXECUTABLE: &str = r"C:\Program Files\CMTrace Open\CMTrace Open.exe";

    /// A forwarded launch whose working directory was not reported.
    ///
    /// The plugin sends an empty directory when the second process cannot read
    /// its own, and those cases keep the path exactly as it arrived — which is
    /// also what lets a host that is not the launch platform assert the parsed
    /// payload without resolving anything.
    const NO_WORKING_DIRECTORY: &str = "";

    #[test]
    fn a_forwarded_launch_opens_the_path_that_follows_the_executable() {
        let request = parse_forwarded_open_request(
            [EXECUTABLE, r"C:\Windows\CCM\Logs\ccmexec.log"].map(String::from),
            NO_WORKING_DIRECTORY,
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
            NO_WORKING_DIRECTORY,
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
            NO_WORKING_DIRECTORY,
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
    fn a_relative_forwarded_path_resolves_against_the_launch_directory() {
        // `cmtraceopen relative.log` from another directory: the running window
        // has a working directory of its own, so the path has to be resolved
        // against the launch that carried it, not against the window.
        let launch_directory = std::env::temp_dir().join("second-launch-cwd");
        let relative = Path::new("Logs").join("ccmexec.log");

        let request = parse_forwarded_open_request(
            [EXECUTABLE.to_string(), relative.to_string_lossy().to_string()],
            launch_directory.to_string_lossy().as_ref(),
        );

        assert_eq!(request.paths.len(), 1);
        let resolved = PathBuf::from(&request.paths[0]);

        assert!(
            resolved.is_absolute(),
            "a forwarded relative path must be resolved before it is opened, got {resolved:?}",
        );
        assert!(resolved.starts_with(&launch_directory));
        assert!(resolved.ends_with(&relative));
        assert_ne!(resolved, relative);
    }

    #[test]
    fn an_absolute_forwarded_path_is_left_exactly_as_the_launch_typed_it() {
        let absolute = std::env::temp_dir()
            .join("second-launch-absolute")
            .join("ccmexec.log");

        let request = parse_forwarded_open_request(
            [EXECUTABLE.to_string(), absolute.to_string_lossy().to_string()],
            // A different directory: an absolute path never consults it.
            std::env::temp_dir()
                .join("unrelated-cwd")
                .to_string_lossy()
                .as_ref(),
        );

        assert_eq!(request.paths, [absolute.to_string_lossy()]);
    }

    #[test]
    fn a_forwarded_launch_without_paths_opens_nothing() {
        let bare_relaunch =
            parse_forwarded_open_request([EXECUTABLE].map(String::from), NO_WORKING_DIRECTORY);

        assert!(bare_relaunch.paths.is_empty());
        assert_eq!(
            serde_json::to_value(&bare_relaunch).expect("payload serializes"),
            serde_json::json!({ "paths": [] }),
        );

        let no_arguments =
            parse_forwarded_open_request(Vec::<String>::new(), NO_WORKING_DIRECTORY);

        assert!(no_arguments.paths.is_empty());
    }

    #[test]
    fn a_forwarded_launch_never_opens_an_app_owned_option_as_a_path() {
        // A relaunch passes the app's own options. They are not evidence, and
        // forwarding one must never ask the running window to open a file.
        let id = crate::elevation::restore_ticket::new_ticket_id();
        let request = parse_forwarded_open_request(
            [
                EXECUTABLE.to_string(),
                format!("--elevation-restore={id}"),
                "--workspace=esp-diagnostics".to_string(),
            ],
            NO_WORKING_DIRECTORY,
        );

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
