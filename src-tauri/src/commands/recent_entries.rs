use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum number of entries kept in the Recent submenu.
pub const MAX_RECENT_ENTRIES: usize = 10;

const RECENT_ENTRIES_FILE: &str = "recent-entries.json";
const RECENT_ENTRIES_VERSION: u8 = 1;

/// Whole-batch budget for existence checks. `std::fs` has no per-call
/// timeout, so an unreachable network path is bounded here instead.
const PRUNE_BUDGET: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecentEntryKind {
    File,
    Folder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentEntry {
    pub path: String,
    pub kind: RecentEntryKind,
    pub workspace: String,
    pub opened_at_unix_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecentEntriesFile {
    version: u8,
    entries: Vec<RecentEntry>,
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// Build the dedup key for a path. The original string is what gets stored
/// and displayed; only comparison uses this normalized form.
pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    let trimmed = if trimmed.is_empty() { path } else { trimmed };

    #[cfg(windows)]
    {
        trimmed.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        trimmed.to_string()
    }
}

/// Insert `entry` at the front, promoting rather than duplicating an existing
/// `(normalized path, workspace)` pair, then trim to `MAX_RECENT_ENTRIES`.
pub fn push_entry(entries: &mut Vec<RecentEntry>, entry: RecentEntry) {
    let key = normalize_path(&entry.path);
    entries.retain(|existing| {
        normalize_path(&existing.path) != key || existing.workspace != entry.workspace
    });
    entries.insert(0, entry);
    entries.truncate(MAX_RECENT_ENTRIES);
}

/// Drop entries that are provably gone or belong to a workspace this build
/// does not have. Absence of proof is not proof of absence: any error other
/// than `NotFound` keeps the entry.
pub fn prune_entries(
    entries: Vec<RecentEntry>,
    available_workspaces: &[&str],
    deadline: Instant,
) -> Vec<RecentEntry> {
    entries
        .into_iter()
        .filter(|entry| {
            if !available_workspaces.contains(&entry.workspace.as_str()) {
                return false;
            }

            if Instant::now() >= deadline {
                return true;
            }

            match std::fs::metadata(&entry.path) {
                Ok(_) => true,
                Err(error) if error.kind() == ErrorKind::NotFound => false,
                Err(_) => true,
            }
        })
        .collect()
}

pub fn load_entries(config_dir: &Path) -> Vec<RecentEntry> {
    let path = config_dir.join(RECENT_ENTRIES_FILE);

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            if error.kind() != ErrorKind::NotFound {
                log::warn!("[recent] failed to read {}: {error}", path.display());
            }
            return Vec::new();
        }
    };

    match serde_json::from_str::<RecentEntriesFile>(&raw) {
        Ok(file) if file.version == RECENT_ENTRIES_VERSION => file.entries,
        Ok(file) => {
            log::warn!(
                "[recent] ignoring recent-entries.json with unsupported version {}",
                file.version
            );
            Vec::new()
        }
        Err(error) => {
            log::warn!("[recent] failed to parse {}: {error}", path.display());
            Vec::new()
        }
    }
}

pub fn save_entries(config_dir: &Path, entries: &[RecentEntry]) -> Result<(), String> {
    std::fs::create_dir_all(config_dir).map_err(|error| error.to_string())?;

    let payload = serde_json::to_string_pretty(&RecentEntriesFile {
        version: RECENT_ENTRIES_VERSION,
        entries: entries.to_vec(),
    })
    .map_err(|error| error.to_string())?;

    let temp_path = config_dir.join(format!("{RECENT_ENTRIES_FILE}.tmp"));
    std::fs::write(&temp_path, payload).map_err(|error| error.to_string())?;
    std::fs::rename(&temp_path, config_dir.join(RECENT_ENTRIES_FILE))
        .map_err(|error| error.to_string())
}

pub fn validate_workspace(workspace: &str, available: &[&str]) -> Result<(), String> {
    if available.contains(&workspace) {
        Ok(())
    } else {
        Err(format!("unknown workspace '{workspace}'"))
    }
}

/// Managed separately from `AppState` so recents never contend with the
/// open-files / tail-session lock.
pub struct RecentEntriesState {
    config_dir: PathBuf,
    entries: Mutex<Vec<RecentEntry>>,
}

impl RecentEntriesState {
    pub fn load(config_dir: PathBuf, available_workspaces: &[&str]) -> Self {
        let loaded = load_entries(&config_dir);
        let pruned = prune_entries(
            loaded.clone(),
            available_workspaces,
            Instant::now() + PRUNE_BUDGET,
        );

        if pruned != loaded {
            if let Err(error) = save_entries(&config_dir, &pruned) {
                log::warn!("[recent] failed to persist pruned entries: {error}");
            }
        }

        Self {
            config_dir,
            entries: Mutex::new(pruned),
        }
    }

    pub fn snapshot(&self) -> Vec<RecentEntry> {
        match self.entries.lock() {
            Ok(entries) => entries.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn push(&self, entry: RecentEntry) -> Result<(), String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| format!("recent entries lock poisoned: {error}"))?;
        push_entry(&mut entries, entry);
        save_entries(&self.config_dir, &entries)
    }

    pub fn prune(&self, available_workspaces: &[&str]) -> Result<(), String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| format!("recent entries lock poisoned: {error}"))?;

        let pruned = prune_entries(
            entries.clone(),
            available_workspaces,
            Instant::now() + PRUNE_BUDGET,
        );

        if pruned == *entries {
            return Ok(());
        }

        *entries = pruned;
        save_entries(&self.config_dir, &entries)
    }

    pub fn clear(&self) -> Result<(), String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| format!("recent entries lock poisoned: {error}"))?;
        entries.clear();
        save_entries(&self.config_dir, &entries)
    }
}

use tauri::{AppHandle, Runtime, State};

use crate::commands::app_config::get_available_workspaces;

#[tauri::command]
pub fn push_recent_entry<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, RecentEntriesState>,
    path: String,
    kind: RecentEntryKind,
    workspace: String,
) -> Result<(), String> {
    let available = get_available_workspaces();
    validate_workspace(&workspace, &available)?;

    state.push(RecentEntry {
        path,
        kind,
        workspace,
        opened_at_unix_ms: now_unix_ms(),
    })?;
    state.prune(&available)?;

    crate::menu::rebuild_recent_submenu(&app)
}

#[tauri::command]
pub fn clear_recent_entries<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, RecentEntriesState>,
) -> Result<(), String> {
    state.clear()?;
    crate::menu::rebuild_recent_submenu(&app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    fn entry(path: &str, workspace: &str) -> RecentEntry {
        RecentEntry {
            path: path.to_string(),
            kind: RecentEntryKind::File,
            workspace: workspace.to_string(),
            opened_at_unix_ms: 0,
        }
    }

    #[test]
    fn push_promotes_existing_entry_instead_of_duplicating() {
        let mut entries = vec![entry("/a.log", "log"), entry("/b.log", "log")];
        push_entry(&mut entries, entry("/b.log", "log"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/b.log");
    }

    #[test]
    fn push_keeps_same_path_in_different_workspaces_separate() {
        let mut entries = Vec::new();
        push_entry(&mut entries, entry("/a.log", "log"));
        push_entry(&mut entries, entry("/a.log", "intune"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn push_trims_to_max_entries_dropping_the_oldest() {
        let mut entries = Vec::new();
        for index in 0..(MAX_RECENT_ENTRIES + 5) {
            push_entry(&mut entries, entry(&format!("/log-{index}.log"), "log"));
        }
        assert_eq!(entries.len(), MAX_RECENT_ENTRIES);
        assert_eq!(
            entries[0].path,
            format!("/log-{}.log", MAX_RECENT_ENTRIES + 4)
        );
    }

    #[test]
    fn normalize_trims_trailing_separators() {
        assert_eq!(normalize_path("/logs/"), normalize_path("/logs"));
    }

    #[test]
    fn normalize_keeps_root_paths_intact() {
        assert!(!normalize_path("/").is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn normalize_is_case_insensitive_on_windows() {
        assert_eq!(
            normalize_path(r"C:\Logs\A.log"),
            normalize_path(r"c:\logs\a.log")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn normalize_is_case_sensitive_off_windows() {
        assert_ne!(normalize_path("/Logs/A.log"), normalize_path("/logs/a.log"));
    }

    #[test]
    fn load_returns_empty_when_file_is_missing() {
        let dir = tempdir().expect("tempdir");
        assert!(load_entries(dir.path()).is_empty());
    }

    #[test]
    fn load_returns_empty_when_file_is_corrupt() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("recent-entries.json"), "{ not json")
            .expect("write corrupt file");
        assert!(load_entries(dir.path()).is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir().expect("tempdir");
        let entries = vec![entry("/a.log", "log")];
        save_entries(dir.path(), &entries).expect("save");
        assert_eq!(load_entries(dir.path()), entries);
    }

    #[test]
    fn prune_drops_missing_paths_and_keeps_existing_ones() {
        let dir = tempdir().expect("tempdir");
        let present = dir.path().join("present.log");
        std::fs::write(&present, "line").expect("write");
        let entries = vec![
            entry(present.to_str().expect("utf8 path"), "log"),
            entry(
                dir.path().join("missing.log").to_str().expect("utf8 path"),
                "log",
            ),
        ];

        let pruned = prune_entries(entries, &["log"], Instant::now() + Duration::from_secs(1));

        assert_eq!(pruned.len(), 1);
        assert!(pruned[0].path.ends_with("present.log"));
    }

    #[test]
    fn prune_drops_entries_for_unavailable_workspaces() {
        let dir = tempdir().expect("tempdir");
        let present = dir.path().join("present.log");
        std::fs::write(&present, "line").expect("write");
        let entries = vec![entry(present.to_str().expect("utf8 path"), "sysmon")];

        let pruned = prune_entries(entries, &["log"], Instant::now() + Duration::from_secs(1));

        assert!(pruned.is_empty());
    }

    #[test]
    fn prune_keeps_everything_once_the_budget_is_exhausted() {
        let entries = vec![entry("/definitely/missing.log", "log")];
        let pruned = prune_entries(entries, &["log"], Instant::now());
        assert_eq!(pruned.len(), 1);
    }

    #[test]
    fn validate_workspace_rejects_unknown_ids() {
        assert!(validate_workspace("log", &["log", "intune"]).is_ok());
        assert!(validate_workspace("not-a-workspace", &["log", "intune"]).is_err());
    }

    #[test]
    fn state_push_persists_and_clear_empties() {
        let dir = tempdir().expect("tempdir");
        let state = RecentEntriesState::load(dir.path().to_path_buf(), &["log"]);

        state.push(entry("/a.log", "log")).expect("push");
        assert_eq!(state.snapshot().len(), 1);
        assert_eq!(load_entries(dir.path()).len(), 1);

        state.clear().expect("clear");
        assert!(state.snapshot().is_empty());
        assert!(load_entries(dir.path()).is_empty());
    }
}
