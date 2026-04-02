#[tauri::command]
pub fn get_available_workspaces() -> Vec<&'static str> {
    let mut workspaces = vec!["log"];

    if cfg!(feature = "intune-diagnostics") {
        workspaces.push("intune");
        workspaces.push("new-intune");
    }

    if cfg!(feature = "dsregcmd") {
        workspaces.push("dsregcmd");
    }

    if cfg!(feature = "macos-diag") {
        workspaces.push("macos-diag");
    }

    if cfg!(feature = "deployment") {
        workspaces.push("deployment");
    }

    if cfg!(feature = "event-log") {
        workspaces.push("event-log");
    }

    workspaces
}
