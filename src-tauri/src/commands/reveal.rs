use std::path::Path;

/// Reveal a file in the OS file manager (Explorer, Finder, etc.)
#[tauri::command]
pub async fn reveal_in_file_manager(path: String) -> Result<(), String> {
    let path = Path::new(&path);
    let dir = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };

    #[cfg(target_os = "windows")]
    {
        // On Windows, use explorer /select to highlight the file
        // Deliberately unbounded: this launches the user's file manager, which is
        // interactive and outlives this call. A deadline would terminate the window
        // the user asked for, and there is nothing to wait for.
        if path.is_file() {
            let path_str = path.to_string_lossy();
            std::process::Command::new("explorer")
                .arg(format!("/select,{}", path_str))
                .spawn()
                .map_err(|e| format!("Failed to open Explorer: {}", e))?;
        } else {
            std::process::Command::new("explorer")
                .arg(dir)
                .spawn()
                .map_err(|e| format!("Failed to open Explorer: {}", e))?;
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Deliberately unbounded: this launches the user's file manager, which is
        // interactive and outlives this call. A deadline would terminate the window
        // the user asked for, and there is nothing to wait for.
        if path.is_file() {
            std::process::Command::new("open")
                .arg("-R")
                .arg(path)
                .spawn()
                .map_err(|e| format!("Failed to open Finder: {}", e))?;
        } else {
            std::process::Command::new("open")
                .arg(dir)
                .spawn()
                .map_err(|e| format!("Failed to open Finder: {}", e))?;
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Deliberately unbounded: this launches the user's file manager, which is
        // interactive and outlives this call. A deadline would terminate the window
        // the user asked for, and there is nothing to wait for.
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .map_err(|e| format!("Failed to open file manager: {}", e))?;
    }

    Ok(())
}
