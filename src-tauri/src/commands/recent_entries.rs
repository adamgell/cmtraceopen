use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum number of entries kept in the Recent submenu.
pub const MAX_RECENT_ENTRIES: usize = 10;

const RECENT_ENTRIES_FILE: &str = "recent-entries.json";
const RECENT_ENTRIES_VERSION: u8 = 1;

/// Budget for the existence-check batch. Once it is spent, the remaining
/// entries are kept unchecked.
///
/// This caps how many `metadata()` calls a prune makes, not how long any one
/// of them takes: `std::fs` offers no per-call timeout, so a single call
/// against an unreachable network path can still block for as long as the OS
/// takes to give up. Pruning therefore runs off the main thread.
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
    // Only treat backslash as a separator on Windows. Elsewhere it is a legal
    // filename character, so trimming it would collapse `dir/weird\` and
    // `dir/weird` into one key.
    #[cfg(windows)]
    const SEPARATORS: &[char] = &['/', '\\'];
    #[cfg(not(windows))]
    const SEPARATORS: &[char] = &['/'];

    let trimmed = path.trim_end_matches(SEPARATORS);

    // Roots keep their separator. `/` would otherwise normalize to the empty
    // string, and on Windows `C:\` would become `C:` — which means the
    // drive-relative current directory, not the drive root.
    let normalized = if trimmed.is_empty() || trimmed.ends_with(':') {
        path
    } else {
        trimmed
    };

    #[cfg(windows)]
    {
        normalized.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized.to_string()
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
///
/// `deadline` bounds how many entries get an existence check, not how long an
/// individual check may block. Everything still unchecked when it passes is
/// kept.
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
    /// Serializes writes to `recent-entries.json`.
    ///
    /// Held only by `persist`, never together with a mutation of `entries`, so
    /// it cannot reintroduce main-thread stalls: `snapshot()` still only ever
    /// waits on the (I/O-free) `entries` lock.
    persist_lock: Mutex<()>,
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
            persist_lock: Mutex::new(()),
        }
    }

    pub fn snapshot(&self) -> Vec<RecentEntry> {
        match self.entries.lock() {
            Ok(entries) => entries.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Write the current list to disk.
    ///
    /// Two constraints pull in opposite directions here, and this is what
    /// satisfies both:
    ///
    /// * The `entries` lock must not be held across file I/O.
    ///   `handle_menu_event` calls `snapshot()` on the main thread, so holding
    ///   it across a write — or worse, across `prune_entries`' `metadata()`
    ///   calls against a dead network path — stalls the UI.
    /// * Writes must not lose updates. Tauri commands run concurrently, so two
    ///   overlapping mutations could otherwise persist out of order and leave
    ///   an older list on disk than the one in memory.
    ///
    /// So writes take their own lock, and the snapshot is re-read *inside* it.
    /// Whatever a writer persists is the newest state as of its turn, which
    /// makes a stale overwrite impossible without ever coupling the two locks.
    fn persist(&self) -> Result<(), String> {
        let _guard = self
            .persist_lock
            .lock()
            .map_err(|error| format!("recent entries persist lock poisoned: {error}"))?;

        save_entries(&self.config_dir, &self.snapshot())
    }

    pub fn push(&self, entry: RecentEntry) -> Result<(), String> {
        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|error| format!("recent entries lock poisoned: {error}"))?;
            push_entry(&mut entries, entry);
        }

        self.persist()
    }

    /// Drop entries that are provably gone, without holding the lock across
    /// the existence checks.
    ///
    /// `prune_entries` calls `metadata()`, which can block for a long time on
    /// an unreachable network path. Holding the guard across that would freeze
    /// any main-thread `snapshot()` (a Recent click) for the same duration, so
    /// the checks run against a copy. Because a push can land while they run,
    /// the result is applied as a *removal set* rather than by overwriting the
    /// list — otherwise the entry the user just opened would be clobbered by a
    /// stale snapshot.
    pub fn prune(&self, available_workspaces: &[&str]) -> Result<(), String> {
        let before = self.snapshot();
        if before.is_empty() {
            return Ok(());
        }

        let kept = prune_entries(
            before.clone(),
            available_workspaces,
            Instant::now() + PRUNE_BUDGET,
        );

        if kept.len() == before.len() {
            return Ok(());
        }

        let survivors: HashSet<(String, String)> = kept
            .iter()
            .map(|entry| (normalize_path(&entry.path), entry.workspace.clone()))
            .collect();
        let dropped: HashSet<(String, String)> = before
            .iter()
            .map(|entry| (normalize_path(&entry.path), entry.workspace.clone()))
            .filter(|key| !survivors.contains(key))
            .collect();

        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|error| format!("recent entries lock poisoned: {error}"))?;
            entries.retain(|entry| {
                !dropped.contains(&(normalize_path(&entry.path), entry.workspace.clone()))
            });
        }

        self.persist()
    }

    pub fn clear(&self) -> Result<(), String> {
        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|error| format!("recent entries lock poisoned: {error}"))?;
            entries.clear();
        }

        self.persist()
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

    // Both of these update the in-memory list before persisting, so a write
    // failure (disk full, read-only config dir) still leaves the session's
    // list correct. Warn and carry on rather than returning early: aborting
    // here would skip the rebuild and leave the menu showing stale entries
    // that disagree with state we already changed.
    if let Err(error) = state.push(RecentEntry {
        path,
        kind,
        workspace,
        opened_at_unix_ms: now_unix_ms(),
    }) {
        log::warn!("[recent] failed to persist after push: {error}");
    }

    if let Err(error) = state.prune(&available) {
        log::warn!("[recent] failed to persist after prune: {error}");
    }

    crate::menu::rebuild_recent_submenu(&app)
}

#[tauri::command]
pub fn clear_recent_entries<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, RecentEntriesState>,
) -> Result<(), String> {
    // The in-memory list is emptied before the write, so rebuild even if
    // persisting failed — otherwise the menu keeps offering entries the
    // session no longer has.
    if let Err(error) = state.clear() {
        log::warn!("[recent] failed to persist after clear: {error}");
    }

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
    fn normalize_keeps_a_drive_root_distinct_from_the_drive() {
        // `C:` is the drive-relative current directory, not the drive root, so
        // trimming the separator away would merge two different locations.
        assert_ne!(normalize_path(r"C:\"), normalize_path("C:"));
        assert_eq!(normalize_path(r"C:\"), r"c:\");
    }

    #[cfg(not(windows))]
    #[test]
    fn normalize_leaves_a_trailing_backslash_alone_off_windows() {
        // Backslash is a legal filename character outside Windows, so it must
        // not be treated as a separator.
        assert_ne!(normalize_path("/dir/weird\\"), normalize_path("/dir/weird"));
        assert_eq!(normalize_path("/dir/weird\\"), "/dir/weird\\");
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
    fn concurrent_pushes_all_survive_on_disk() {
        // Writes happen outside the entries lock so the main thread never
        // stalls on I/O, which means two overlapping pushes could otherwise
        // persist out of order and leave an older list on disk. persist()
        // re-snapshots under its own lock to make that impossible.
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("tempdir");
        let state = Arc::new(RecentEntriesState::load(dir.path().to_path_buf(), &["log"]));

        let threads: Vec<_> = (0..8)
            .map(|index| {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    state
                        .push(entry(&format!("/racer-{index}.log"), "log"))
                        .expect("push");
                })
            })
            .collect();

        for handle in threads {
            handle.join().expect("thread panicked");
        }

        let in_memory = state.snapshot();
        let on_disk = load_entries(dir.path());
        assert_eq!(in_memory.len(), 8);
        assert_eq!(
            on_disk, in_memory,
            "the last write must reflect the final in-memory list, not a stale snapshot"
        );
    }

    #[test]
    fn state_prune_drops_missing_entries_and_persists() {
        let dir = tempdir().expect("tempdir");
        let present = dir.path().join("present.log");
        std::fs::write(&present, "line").expect("write");

        let state = RecentEntriesState::load(dir.path().to_path_buf(), &["log"]);
        state
            .push(entry(present.to_str().expect("utf8 path"), "log"))
            .expect("push present");
        state
            .push(entry("/definitely/missing.log", "log"))
            .expect("push missing");

        state.prune(&["log"]).expect("prune");

        let remaining = state.snapshot();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].path.ends_with("present.log"));
        assert_eq!(load_entries(dir.path()).len(), 1);
    }

    #[test]
    fn state_prune_keeps_an_entry_pushed_while_it_was_running() {
        // prune() checks existence against a snapshot taken before it releases
        // the lock. Applying the result as a removal set (rather than writing
        // the stale snapshot back) is what keeps a concurrent push alive.
        let dir = tempdir().expect("tempdir");
        let present = dir.path().join("present.log");
        std::fs::write(&present, "line").expect("write");

        let state = RecentEntriesState::load(dir.path().to_path_buf(), &["log"]);
        state
            .push(entry("/definitely/missing.log", "log"))
            .expect("push missing");

        // Stand in for "a push landed during the metadata() calls".
        let before = state.snapshot();
        state
            .push(entry(present.to_str().expect("utf8 path"), "log"))
            .expect("push during prune");

        let kept = prune_entries(before, &["log"], Instant::now() + Duration::from_secs(1));
        assert!(kept.is_empty(), "the pre-push snapshot prunes to nothing");

        state.prune(&["log"]).expect("prune");

        let remaining = state.snapshot();
        assert_eq!(remaining.len(), 1, "the concurrent push must survive");
        assert!(remaining[0].path.ends_with("present.log"));
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
