# Recent Files Submenu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `File > Recent` submenu listing up to 10 recently opened paths, each tagged with the workspace that opened it, so the user can reopen prior evidence in one click.

**Architecture:** The Rust backend owns the list — it persists to `{app_config_dir}/recent-entries.json` and is loaded into a `RecentEntriesState` before the native menu is built, so the menu is correct on first paint. The frontend records a path after each successful open and reacts to `open_recent_entry` / `clear_recent_entries` menu events. The submenu is torn down and rebuilt at runtime (muda's `MenuItem` has no `set_visible`, so fixed slots would leave permanent placeholder rows).

**Tech Stack:** Rust / Tauri v2 (muda 0.19.3 menus, `serde_json`, `tempfile` for tests), React 19 + TypeScript, Zustand, Vitest.

**Spec:** `docs/superpowers/specs/2026-07-29-recent-files-menu-design.md`

## Global Constraints

- Rust 1.88+ (MSRV). `cargo clippy --all-targets -- -D warnings` must be clean — CI gates on zero warnings.
- `npx tsc --noEmit` must pass. This is a hard gate per `CLAUDE.md`; never report a task complete without running it.
- No new dependencies. `serde`, `serde_json`, `log` are in `[dependencies]`; `tempfile = "3"` is already in `[dev-dependencies]`.
- Menu mutation is main-thread-only on macOS. Any menu change made from a Tauri command **must** be wrapped in `app.run_on_main_thread(...)`.
- Cap is exactly 10 entries (`MAX_RECENT_ENTRIES`).
- Each task touches no more than 5 files (per `CLAUDE.md` phased-execution rule).
- Windows-only code paths (case-insensitive path normalization) are verified through CI's Windows jobs, not locally — local `--target x86_64-pc-windows-msvc` builds fail in ring's C build on this macOS host.
- Work happens on branch `feat/recent-files-menu`, which already holds the spec commit `8ea25f66`.

## Corrections to the spec

Two details in the spec do not survive contact with the code. This plan supersedes them:

1. **Workspace label source.** The spec says the label reuses `native_label()`. That method is on `WorkspaceGroup` and returns group names ("Analysis", "Endpoint Management"), not per-workspace names. Use `WorkspaceDescriptor.label` instead (`menu.rs:231-235`), which yields `Log Explorer`, `Intune Diagnostics`, etc. Example label becomes `IntuneManagementExtension.log — IME (Intune Diagnostics)`.
2. **Payload needs `kind`.** The spec adds `path` and `workspace` to `AppMenuActionPayload`. The frontend also needs `kind` to reconstruct a `LogSource` on reopen without a second round-trip. Three optional fields are added, not two.

## File Structure

| File | Responsibility |
|---|---|
| `src-tauri/src/commands/recent_entries.rs` (new) | Entry model, path normalization, push/dedup/trim, prune, JSON load/save, `RecentEntriesState`, the two IPC commands |
| `src-tauri/src/commands/mod.rs` | Register the new module |
| `src-tauri/src/menu.rs` | Menu ids, `FILE_ORDER` placement, label formatting, submenu build + runtime rebuild, click payload mapping |
| `src-tauri/src/lib.rs` | Manage `RecentEntriesState` before the menu is built; register the two commands |
| `src/lib/recent-entries.ts` (new) | Frontend IPC wrappers and kind resolution |
| `src/hooks/use-app-actions.ts` | Record after successful opens; expose `openRecentEntry` |
| `src/hooks/use-app-menu.ts` | Handle `open_recent_entry` and `clear_recent_entries` |

---

### Task 1: Recent entries store

Pure logic plus persistence. No menu, no IPC, no frontend. Fully unit-testable on its own.

**Files:**
- Create: `src-tauri/src/commands/recent_entries.rs`
- Modify: `src-tauri/src/commands/mod.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub enum RecentEntryKind { File, Folder }` (serde `camelCase` → `"file"` / `"folder"`)
  - `pub struct RecentEntry { path: String, kind: RecentEntryKind, workspace: String, opened_at_unix_ms: i64 }`
  - `pub const MAX_RECENT_ENTRIES: usize = 10`
  - `pub fn normalize_path(path: &str) -> String`
  - `pub fn push_entry(entries: &mut Vec<RecentEntry>, entry: RecentEntry)`
  - `pub fn prune_entries(entries: Vec<RecentEntry>, available_workspaces: &[&str], deadline: Instant) -> Vec<RecentEntry>`
  - `pub fn load_entries(config_dir: &Path) -> Vec<RecentEntry>`
  - `pub fn save_entries(config_dir: &Path, entries: &[RecentEntry]) -> Result<(), String>`
  - `pub fn now_unix_ms() -> i64`
  - `pub fn validate_workspace(workspace: &str, available: &[&str]) -> Result<(), String>`
  - `pub struct RecentEntriesState` with `load(config_dir: PathBuf, available_workspaces: &[&str]) -> Self`, `snapshot(&self) -> Vec<RecentEntry>`, `push(&self, entry: RecentEntry) -> Result<(), String>`, `prune(&self, available_workspaces: &[&str]) -> Result<(), String>`, `clear(&self) -> Result<(), String>`

- [ ] **Step 1: Register the module**

In `src-tauri/src/commands/mod.rs`, add in alphabetical position (after `pub mod parsing;`, before `pub mod registry_ops;`):

```rust
pub mod recent_entries;
```

- [ ] **Step 2: Write the failing tests**

Create `src-tauri/src/commands/recent_entries.rs` containing **only** this test module for now (the file will not compile yet — that is the point):

```rust
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
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cd src-tauri && cargo test recent_entries
```

Expected: compile errors — `cannot find type RecentEntry in this scope`, etc.

- [ ] **Step 4: Write the implementation**

Prepend this to `src-tauri/src/commands/recent_entries.rs`, above the `mod tests` block:

```rust
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
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd src-tauri && cargo test recent_entries
```

Expected: all 14 tests PASS. On macOS/Linux the Windows-gated test compiles out and `normalize_is_case_sensitive_off_windows` runs instead.

- [ ] **Step 6: Lint**

```bash
cd src-tauri && cargo clippy --all-targets -- -D warnings
```

Expected: no warnings. If clippy flags `PRUNE_BUDGET` as unused at this point, that is expected only if you skipped `RecentEntriesState` — it is used by `load` and `prune`.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/commands/recent_entries.rs src-tauri/src/commands/mod.rs
git commit -m "feat(recent): add persisted recent entries store"
```

---

### Task 2: Render the Recent submenu

Puts a populated `Recent` submenu in the File menu at startup. After this task, hand-writing a `recent-entries.json` into the app config dir and launching the app shows the entries.

**Files:**
- Modify: `src-tauri/src/menu.rs`
- Modify: `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: `RecentEntry`, `RecentEntryKind`, `RecentEntriesState` from Task 1.
- Produces:
  - `pub const MENU_ID_FILE_RECENT: &str = "file.recent"`
  - `pub const MENU_ID_FILE_RECENT_CLEAR: &str = "file.recent.clear"`
  - `fn recent_entry_label(entry: &RecentEntry) -> String`
  - `fn recent_submenu_items<R: Runtime>(app, entries) -> tauri::Result<Vec<Box<dyn IsMenuItem<R>>>>`
  - `fn recent_entries_for_menu<R: Runtime>(app: &AppHandle<R>) -> Vec<RecentEntry>`

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` block at the bottom of `src-tauri/src/menu.rs`:

```rust
    #[test]
    fn recent_submenu_appears_after_known_sources_on_every_platform() {
        for order in [FILE_ORDER, FILE_ORDER_MAC] {
            let known = order
                .iter()
                .position(|id| *id == MENU_ID_FILE_KNOWN_SOURCES)
                .expect("known sources present");
            let recent = order
                .iter()
                .position(|id| *id == MENU_ID_FILE_RECENT)
                .expect("recent present");
            assert_eq!(recent, known + 1);
        }
    }

    #[test]
    fn recent_label_includes_name_parent_and_workspace() {
        let entry = RecentEntry {
            path: "/evidence/IME/IntuneManagementExtension.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "intune".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(
            recent_entry_label(&entry),
            "IntuneManagementExtension.log — IME (Intune Diagnostics)"
        );
    }

    #[test]
    fn recent_label_for_folder_uses_folder_and_its_parent() {
        let entry = RecentEntry {
            path: "/evidence/bundle-01/IME".to_string(),
            kind: RecentEntryKind::Folder,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(
            recent_entry_label(&entry),
            "IME — bundle-01 (Log Explorer)"
        );
    }

    #[test]
    fn recent_label_drops_parent_segment_when_there_is_no_parent() {
        let entry = RecentEntry {
            path: "/only.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "log".to_string(),
            opened_at_unix_ms: 0,
        };

        assert_eq!(recent_entry_label(&entry), "only.log (Log Explorer)");
    }

    #[test]
    fn recent_label_falls_back_when_the_workspace_is_unknown() {
        let entry = RecentEntry {
            path: "/a/b.log".to_string(),
            kind: RecentEntryKind::File,
            workspace: "not-a-workspace".to_string(),
            opened_at_unix_ms: 0,
        };

        assert!(recent_entry_label(&entry).ends_with("(Unknown Workspace)"));
    }
```

Note: `/only.log` has parent `/`, whose `file_name()` is `None`, so the parent segment is dropped. That is the behavior the third test pins.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd src-tauri && cargo test --lib menu::tests::recent
```

Expected: compile errors — `cannot find value MENU_ID_FILE_RECENT`, `cannot find function recent_entry_label`.

- [ ] **Step 3: Add the ids and menu ordering**

In `src-tauri/src/menu.rs`, add to the imports at the top:

```rust
use std::path::Path;

use crate::commands::recent_entries::{RecentEntriesState, RecentEntry};
```

Add the id constants next to `MENU_ID_FILE_KNOWN_SOURCES` (around line 23):

```rust
pub const MENU_ID_FILE_RECENT: &str = "file.recent";
pub const MENU_ID_FILE_RECENT_CLEAR: &str = "file.recent.clear";
```

Add next to `KNOWN_SOURCE_MENU_ID_PREFIX` (line 56):

```rust
const RECENT_MENU_ID_PREFIX: &str = "recent.";
const RECENT_UNAVAILABLE_MENU_ID: &str = "recent.unavailable";
```

Insert `MENU_ID_FILE_RECENT` immediately after `MENU_ID_FILE_KNOWN_SOURCES` in **both** `FILE_ORDER` and `FILE_ORDER_MAC`:

```rust
const FILE_ORDER: &[&str] = &[
    MENU_ID_FILE_OPEN_LOG_FILE,
    MENU_ID_FILE_OPEN_LOG_FOLDER,
    MENU_ID_FILE_KNOWN_SOURCES,
    MENU_ID_FILE_RECENT,
    MENU_SEPARATOR,
    MENU_ID_FILE_NEW_TIMELINE,
    MENU_SEPARATOR,
    MENU_ID_FILE_OPEN_SESSION,
    MENU_ID_FILE_SAVE_SESSION,
    MENU_SEPARATOR,
    MENU_ID_FILE_QUIT,
];
const FILE_ORDER_MAC: &[&str] = &[
    MENU_ID_FILE_OPEN_LOG_FILE,
    MENU_ID_FILE_OPEN_LOG_FOLDER,
    MENU_ID_FILE_KNOWN_SOURCES,
    MENU_ID_FILE_RECENT,
    MENU_SEPARATOR,
    MENU_ID_FILE_NEW_TIMELINE,
    MENU_SEPARATOR,
    MENU_ID_FILE_OPEN_SESSION,
    MENU_ID_FILE_SAVE_SESSION,
];
```

- [ ] **Step 4: Add label formatting and submenu construction**

Add these functions to `src-tauri/src/menu.rs`, next to `build_known_sources_submenu`:

```rust
fn workspace_label(id: &str) -> &'static str {
    workspace_descriptor(id)
        .map(|descriptor| descriptor.label)
        .unwrap_or("Unknown Workspace")
}

/// `{name} — {parent} ({Workspace})`. Native menu items carry no tooltip, so
/// the parent folder is what disambiguates same-named logs across bundles.
fn recent_entry_label(entry: &RecentEntry) -> String {
    let path = Path::new(&entry.path);

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| entry.path.clone());

    let parent = path
        .parent()
        .and_then(|parent| parent.file_name())
        .map(|parent| parent.to_string_lossy().into_owned())
        .filter(|parent| !parent.is_empty());

    let workspace = workspace_label(&entry.workspace);

    match parent {
        Some(parent) => format!("{name} — {parent} ({workspace})"),
        None => format!("{name} ({workspace})"),
    }
}

fn recent_entries_for_menu<R: Runtime>(app: &AppHandle<R>) -> Vec<RecentEntry> {
    use tauri::Manager as _;

    app.try_state::<RecentEntriesState>()
        .map(|state| state.snapshot())
        .unwrap_or_default()
}

fn recent_submenu_items<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> tauri::Result<Vec<Box<dyn tauri::menu::IsMenuItem<R>>>> {
    if entries.is_empty() {
        let placeholder = MenuItem::with_id(
            app,
            RECENT_UNAVAILABLE_MENU_ID,
            "No recent files",
            false,
            None::<&str>,
        )?;
        return Ok(vec![Box::new(placeholder)]);
    }

    let mut items: Vec<Box<dyn tauri::menu::IsMenuItem<R>>> = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        items.push(Box::new(MenuItem::with_id(
            app,
            format!("{RECENT_MENU_ID_PREFIX}{index}"),
            recent_entry_label(entry),
            true,
            None::<&str>,
        )?));
    }

    items.push(Box::new(PredefinedMenuItem::separator(app)?));
    items.push(Box::new(MenuItem::with_id(
        app,
        MENU_ID_FILE_RECENT_CLEAR,
        "Clear Recent",
        true,
        None::<&str>,
    )?));

    Ok(items)
}

fn build_recent_submenu<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> tauri::Result<Submenu<R>> {
    let items = recent_submenu_items(app, entries)?;
    let refs: Vec<&dyn tauri::menu::IsMenuItem<R>> =
        items.iter().map(|item| item.as_ref()).collect();

    Submenu::with_id_and_items(app, MENU_ID_FILE_RECENT, "Recent", !entries.is_empty(), &refs)
}
```

- [ ] **Step 5: Wire the submenu into the File menu**

In `build_file_menu` (around line 568), after the `known_sources` line, add:

```rust
    let recent = build_recent_submenu(app, &recent_entries_for_menu(app))?;
```

And in the `for &item_id in file_item_order(platform)` match, add an arm next to the known-sources arm:

```rust
            MENU_ID_FILE_RECENT => submenu.append(&recent)?,
```

- [ ] **Step 6: Manage the state before the menu is built**

In `src-tauri/src/lib.rs`, inside `.setup(|app| { ... })`, **before** the `let native_menu = menu::build_app_menu(app.handle())?;` line (currently line 146):

```rust
            {
                use tauri::Manager as _;

                let config_dir = app
                    .path()
                    .app_config_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."));

                app.manage(commands::recent_entries::RecentEntriesState::load(
                    config_dir,
                    &commands::app_config::get_available_workspaces(),
                ));
            }
```

Order matters: `build_app_menu` reads the state through `try_state`, so managing it afterwards would silently produce an empty submenu at startup.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd src-tauri && cargo test --lib menu::tests::recent
```

Expected: 5 tests PASS.

- [ ] **Step 8: Run the full backend suite and lint**

```bash
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
```

Expected: all tests pass, no warnings.

- [ ] **Step 9: Commit**

```bash
git add src-tauri/src/menu.rs src-tauri/src/lib.rs
git commit -m "feat(recent): render Recent submenu from persisted entries"
```

---

### Task 3: Click handling, IPC commands, and runtime rebuild

Makes the submenu live: clicking an entry emits an actionable event, and pushing/clearing rebuilds the menu in place.

**Files:**
- Modify: `src-tauri/src/menu.rs`
- Modify: `src-tauri/src/commands/recent_entries.rs`
- Modify: `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 1 and 2.
- Produces:
  - `AppMenuActionPayload` gains `path: Option<String>`, `workspace: Option<String>`, `kind: Option<String>`
  - Action `"open_recent_entry"` (category `"file"`) carrying `target_id` = index, plus `path` / `workspace` / `kind`
  - Action `"clear_recent_entries"` (category `"file"`)
  - `pub fn rebuild_recent_submenu<R: Runtime>(app: &AppHandle<R>) -> Result<(), String>` in `menu.rs`
  - IPC commands `push_recent_entry(path, kind, workspace)` and `clear_recent_entries()`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` block in `src-tauri/src/menu.rs`:

```rust
    #[test]
    fn recent_entry_menu_id_maps_to_open_recent_entry() {
        let payload = payload_for_menu_id("recent.3").expect("payload");
        assert_eq!(payload.action, "open_recent_entry");
        assert_eq!(payload.category, "file");
        assert_eq!(payload.target_id.as_deref(), Some("3"));
    }

    #[test]
    fn recent_placeholder_menu_id_produces_no_payload() {
        assert!(payload_for_menu_id(RECENT_UNAVAILABLE_MENU_ID).is_none());
    }

    #[test]
    fn recent_clear_menu_id_maps_to_clear_recent_entries() {
        let payload = payload_for_menu_id(MENU_ID_FILE_RECENT_CLEAR).expect("payload");
        assert_eq!(payload.action, "clear_recent_entries");
        assert_eq!(payload.category, "file");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd src-tauri && cargo test --lib menu::tests::recent
```

Expected: the three new tests FAIL — `payload_for_menu_id` returns `None` for `recent.3`, so `.expect("payload")` panics.

- [ ] **Step 3: Extend the payload struct**

In `src-tauri/src/menu.rs`, add three fields to `AppMenuActionPayload` (line 442):

```rust
pub struct AppMenuActionPayload {
    pub version: u8,
    pub menu_id: String,
    pub action: String,
    pub category: String,
    pub trigger: String,
    pub source_id: Option<String>,
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}
```

And initialize them in `base_payload` (line 1407):

```rust
        source_id: None,
        target_id: None,
        path: None,
        workspace: None,
        kind: None,
```

- [ ] **Step 4: Map the new menu ids**

In `payload_for_menu_id`, add these blocks **before** the existing `let (action, category) = match menu_id { ... }` block:

```rust
    if menu_id == MENU_ID_FILE_RECENT_CLEAR {
        return Some(base_payload(menu_id, "clear_recent_entries", "file"));
    }

    if let Some(index) = menu_id.strip_prefix(RECENT_MENU_ID_PREFIX) {
        // Rejects the "recent.unavailable" placeholder, which shares the prefix.
        if index.parse::<usize>().is_err() {
            return None;
        }

        let mut payload = base_payload(menu_id, "open_recent_entry", "file");
        payload.target_id = Some(index.to_string());
        return Some(payload);
    }
```

- [ ] **Step 5: Enrich the payload at click time**

In `handle_menu_event`, change `let Some(payload) = ...` to `let Some(mut payload) = ...` and insert this block after the payload is obtained, before the `switch_workspace` block:

```rust
    if payload.action == "open_recent_entry" {
        let Some(index) = payload
            .target_id
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
        else {
            log::warn!("[menu] open_recent_entry without a usable index: {menu_id}");
            return;
        };

        let entries = recent_entries_for_menu(app);
        let Some(entry) = entries.get(index) else {
            log::warn!("[menu] stale recent entry index {index}");
            return;
        };

        payload.path = Some(entry.path.clone());
        payload.workspace = Some(entry.workspace.clone());
        payload.kind = Some(
            match entry.kind {
                RecentEntryKind::File => "file",
                RecentEntryKind::Folder => "folder",
            }
            .to_string(),
        );
    }
```

Add `RecentEntryKind` to the `crate::commands::recent_entries` import added in Task 2.

- [ ] **Step 6: Add the runtime rebuild**

Add to `src-tauri/src/menu.rs`, next to `build_recent_submenu`:

```rust
/// Tear down and repopulate the Recent submenu.
///
/// muda's `MenuItem` exposes `set_text`/`set_enabled` but no `set_visible`, so
/// updating fixed slots would leave permanent placeholder rows. Menu mutation
/// is main-thread-only on macOS and Tauri commands run off-thread, hence the
/// `run_on_main_thread` hop.
pub fn rebuild_recent_submenu<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let entries = recent_entries_for_menu(app);
    let handle = app.clone();

    app.run_on_main_thread(move || {
        if let Err(error) = rebuild_recent_submenu_on_main(&handle, &entries) {
            log::error!("[menu] failed to rebuild Recent submenu: {error}");
        }
    })
    .map_err(|error| error.to_string())
}

fn rebuild_recent_submenu_on_main<R: Runtime>(
    app: &AppHandle<R>,
    entries: &[RecentEntry],
) -> Result<(), String> {
    let index = app_menu_index(app)?;

    let Some(MenuItemKind::Submenu(submenu)) = index.get(MENU_ID_FILE_RECENT) else {
        return Err("Recent submenu is missing from the application menu".to_string());
    };

    while submenu.remove_at(0).is_some() {}

    let items = recent_submenu_items(app, entries).map_err(|error| error.to_string())?;
    for item in &items {
        submenu
            .append(item.as_ref())
            .map_err(|error| error.to_string())?;
    }

    submenu
        .set_enabled(!entries.is_empty())
        .map_err(|error| error.to_string())
}
```

- [ ] **Step 7: Add the IPC commands**

Append to `src-tauri/src/commands/recent_entries.rs`, above the `mod tests` block:

```rust
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
```

- [ ] **Step 8: Register the commands**

In `src-tauri/src/lib.rs`, add to the `app_invoke_handler![...]` list next to the other `commands::app_config::*` entries:

```rust
            commands::recent_entries::push_recent_entry,
            commands::recent_entries::clear_recent_entries,
```

The unknown-workspace rejection is already covered by `validate_workspace_rejects_unknown_ids` from Task 1, which is why the guard lives in a pure function rather than inline in the command — a `#[tauri::command]` taking `State<'_, _>` cannot be unit-tested without standing up a mock app.

- [ ] **Step 9: Run the tests and lint**

```bash
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
```

Expected: all tests pass, no warnings.

- [ ] **Step 10: Commit**

```bash
git add src-tauri/src/menu.rs src-tauri/src/commands/recent_entries.rs src-tauri/src/lib.rs
git commit -m "feat(recent): wire Recent submenu clicks and rebuild on change"
```

---

### Task 4: Record entries after successful opens

**Files:**
- Create: `src/lib/recent-entries.ts`
- Modify: `src/hooks/use-app-actions.ts`
- Test: `src/lib/recent-entries.test.ts`

**Interfaces:**
- Consumes: IPC commands `push_recent_entry` / `clear_recent_entries` from Task 3.
- Produces:
  - `recordRecentSource(source: LogSource, workspace: WorkspaceId): Promise<void>`
  - `recordRecentPath(path: string, workspace: WorkspaceId): Promise<void>`
  - `clearRecentEntries(): Promise<void>`
  - `AppActionHandlers` gains `openRecentEntry(path: string, kind: "file" | "folder", workspace: WorkspaceId, trigger: string): Promise<void>`

Verified behavior this task depends on: `loadPathAsLogSource` **throws** on failure (`src/lib/log-source.ts` rethrows, and the folder fallback rejects), so recording on the line after `await` is correct. `loadLogWorkspaceSource` in `use-app-actions.ts:340-359` **swallows** errors in a `try/catch`, so it must be changed to report success. It has exactly one caller (line 367).

- [ ] **Step 1: Write the failing test**

Create `src/lib/recent-entries.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
const inspectPathKindMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("./commands", () => ({
  inspectPathKind: (...args: unknown[]) => inspectPathKindMock(...args),
}));

import {
  clearRecentEntries,
  recordRecentPath,
  recordRecentSource,
} from "./recent-entries";

describe("recent-entries", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue(undefined);
    inspectPathKindMock.mockReset();
  });

  it("records a file source", async () => {
    await recordRecentSource({ kind: "file", path: "/a.log" }, "log");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/a.log",
      kind: "file",
      workspace: "log",
    });
  });

  it("records a folder source", async () => {
    await recordRecentSource({ kind: "folder", path: "/bundle" }, "intune");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/bundle",
      kind: "folder",
      workspace: "intune",
    });
  });

  it("ignores known sources", async () => {
    await recordRecentSource(
      {
        kind: "known",
        sourceId: "windows-ime-log",
        defaultPath: "/a.log",
        pathKind: "file",
      },
      "log",
    );

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("resolves the kind for a bare path", async () => {
    inspectPathKindMock.mockResolvedValue("folder");

    await recordRecentPath("/bundle", "log");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/bundle",
      kind: "folder",
      workspace: "log",
    });
  });

  it("skips a path whose kind cannot be resolved", async () => {
    inspectPathKindMock.mockResolvedValue("unknown");

    await recordRecentPath("/gone", "log");

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("never rejects when the backend fails", async () => {
    invokeMock.mockRejectedValue(new Error("disk full"));

    await expect(
      recordRecentSource({ kind: "file", path: "/a.log" }, "log"),
    ).resolves.toBeUndefined();
  });

  it("clears entries", async () => {
    await clearRecentEntries();
    expect(invokeMock).toHaveBeenCalledWith("clear_recent_entries");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
npx vitest run src/lib/recent-entries.test.ts
```

Expected: FAIL — `Failed to resolve import "./recent-entries"`.

- [ ] **Step 3: Write the implementation**

Create `src/lib/recent-entries.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";
import { inspectPathKind } from "./commands";
import type { LogSource, WorkspaceId } from "../types/log";

export type RecentEntryKind = "file" | "folder";

/**
 * Recording must never break opening a log, so every failure here is a warning
 * and the promise always resolves.
 */
async function pushRecentEntry(
  path: string,
  kind: RecentEntryKind,
  workspace: WorkspaceId,
): Promise<void> {
  try {
    await invoke("push_recent_entry", { path, kind, workspace });
  } catch (error) {
    console.warn("[recent] failed to record entry", { path, workspace, error });
  }
}

export async function recordRecentSource(
  source: LogSource,
  workspace: WorkspaceId,
): Promise<void> {
  if (source.kind !== "file" && source.kind !== "folder") {
    return;
  }

  await pushRecentEntry(source.path, source.kind, workspace);
}

export async function recordRecentPath(
  path: string,
  workspace: WorkspaceId,
): Promise<void> {
  let kind: "file" | "folder" | "unknown";

  try {
    kind = await inspectPathKind(path);
  } catch (error) {
    console.warn("[recent] failed to inspect path kind", { path, error });
    return;
  }

  if (kind === "unknown") {
    console.warn("[recent] skipped path with unresolvable kind", { path });
    return;
  }

  await pushRecentEntry(path, kind, workspace);
}

export async function clearRecentEntries(): Promise<void> {
  try {
    await invoke("clear_recent_entries");
  } catch (error) {
    console.warn("[recent] failed to clear entries", { error });
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
npx vitest run src/lib/recent-entries.test.ts
```

Expected: 7 tests PASS.

- [ ] **Step 5: Make `loadLogWorkspaceSource` report success**

In `src/hooks/use-app-actions.ts`, change the callback at line 340 to return a boolean:

```ts
  const loadLogWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string): Promise<boolean> => {
      const currentWorkspace = useUiStore.getState().activeWorkspace;
      if (currentWorkspace !== "deployment") {
        useUiStore.getState().ensureLogViewVisible(trigger);
      }
      useFilterStore.getState().clearFilter();

      try {
        await loadLogSource(source);
        return true;
      } catch (error) {
        console.error("[app-actions] failed to load source", {
          source,
          trigger,
          error,
        });
        return false;
      }
    },
    [],
  );
```

- [ ] **Step 6: Record in `openSourceForWorkspace`**

Replace the callback at line 361:

```ts
  const openSourceForWorkspace = useCallback(
    async (source: LogSource, trigger: string, workspace: WorkspaceId) => {
      const workspaceDefinition = getWorkspace(workspace);

      if (workspaceDefinition.onOpenSource) {
        await workspaceDefinition.onOpenSource(source, trigger);
      } else if (!(await loadLogWorkspaceSource(source, trigger))) {
        return;
      }

      void recordRecentSource(source, workspace);
    },
    [loadLogWorkspaceSource],
  );
```

`onOpenSource` rejects on failure, so reaching the record call means the open succeeded in both branches.

- [ ] **Step 7: Record in every branch of `openPathForActiveWorkspace`**

This function has four early-returning branches; each needs its own call. Replace the callback at line 372:

```ts
  const openPathForActiveWorkspace = useCallback(
    async (path: string) => {
      if (activeWorkspace === "dsregcmd") {
        useUiStore
          .getState()
          .ensureWorkspaceVisible("dsregcmd", "drag-drop.path-open");
        await analyzeDsregcmdPath(path, { fallbackToFolder: true });
        void recordRecentPath(path, "dsregcmd");
        return;
      }

      if (isIntuneWorkspace(activeWorkspace)) {
        const pathKind = await inferPathKind(path);
        const source: LogSource =
          pathKind === "folder"
            ? { kind: "folder", path }
            : { kind: "file", path };
        await getWorkspace(activeWorkspace).onOpenSource!(
          source,
          "drag-drop.path-open",
        );
        void recordRecentSource(source, activeWorkspace);
        return;
      }

      if (activeWorkspace === "deployment") {
        const { useDeploymentStore } = await import(
          "../workspaces/deployment/deployment-store"
        );
        await useDeploymentStore.getState().analyzeFolder(path);
        void recordRecentPath(path, "deployment");
        return;
      }

      useUiStore.getState().ensureLogViewVisible("drag-drop.path-open");
      useFilterStore.getState().clearFilter();
      await loadPathAsLogSource(path, {
        fallbackToFolder: true,
      });
      void recordRecentPath(path, activeWorkspace);
    },
    [activeWorkspace],
  );
```

- [ ] **Step 8: Expose `openRecentEntry`**

Add this callback in `src/hooks/use-app-actions.ts` next to `switchWorkspace` (around line 704):

```ts
  const openRecentEntry = useCallback(
    async (
      path: string,
      kind: "file" | "folder",
      workspace: WorkspaceId,
      trigger: string,
    ) => {
      if (workspace !== activeWorkspace) {
        useUiStore.getState().ensureWorkspaceVisible(workspace, trigger);
      }

      await openSourceForWorkspace({ kind, path }, trigger, workspace);
    },
    [activeWorkspace, openSourceForWorkspace],
  );
```

Add `openRecentEntry: (path: string, kind: "file" | "folder", workspace: WorkspaceId, trigger: string) => Promise<void>;` to the `AppActionHandlers` interface, and `openRecentEntry,` to the returned object.

Add the import at the top of the file:

```ts
import { recordRecentPath, recordRecentSource } from "../lib/recent-entries";
```

- [ ] **Step 9: Verify types and run the suite**

```bash
npx tsc --noEmit && npm test
```

Expected: no type errors, all tests pass.

- [ ] **Step 10: Commit**

```bash
git add src/lib/recent-entries.ts src/lib/recent-entries.test.ts src/hooks/use-app-actions.ts
git commit -m "feat(recent): record paths after successful opens"
```

---

### Task 5: Handle the menu events

**Files:**
- Modify: `src/hooks/use-app-menu.ts`
- Test: `src/hooks/use-app-menu.test.tsx`

**Interfaces:**
- Consumes: `openRecentEntry` from Task 4, `clearRecentEntries` from Task 4, and the `open_recent_entry` / `clear_recent_entries` payloads from Task 3.
- Produces: nothing downstream. This is the last task.

- [ ] **Step 1: Extend the existing test harness**

`src/hooks/use-app-menu.test.tsx` already has everything needed: a `vi.hoisted` `actionMocks.current` object standing in for `useAppActions()`, a `TestMenuPayload` interface, and an `emitMenuAction(partial)` helper that fills in `version`/`menu_id`/`category`/`trigger`/`source_id`/`target_id` defaults. Extend all three rather than adding a parallel harness.

Add to `actionMocks.current` (next to `switchWorkspace`, around line 68):

```tsx
    openRecentEntry: vi.fn(async () => undefined),
```

Add to `TestMenuPayload` (line 82):

```tsx
  path?: string;
  workspace?: string;
  kind?: "file" | "folder";
```

Add a hoisted mock for the recents module, next to the existing `vi.mock` calls:

```tsx
const recentMocks = vi.hoisted(() => ({
  clearRecentEntries: vi.fn(async () => undefined),
}));

vi.mock("../lib/recent-entries", () => ({
  clearRecentEntries: recentMocks.clearRecentEntries,
}));
```

- [ ] **Step 2: Write the failing tests**

Append these inside the `describe("useAppMenu", ...)` block:

```tsx
  it("opens a recent entry in its recorded workspace", async () => {
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    useUiStore.setState({
      currentPlatform: "windows",
      enabledWorkspaces: ["log", "esp-diagnostics"],
    });

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.2",
      category: "file",
      target_id: "2",
      path: "/evidence/IME/IntuneManagementExtension.log",
      workspace: "esp-diagnostics",
      kind: "file",
    });

    expect(actionMocks.current.openRecentEntry).toHaveBeenCalledWith(
      "/evidence/IME/IntuneManagementExtension.log",
      "file",
      "esp-diagnostics",
      "menu",
    );
  });

  it("ignores an open_recent_entry payload missing its resolved fields", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.2",
      category: "file",
      target_id: "2",
    });

    expect(actionMocks.current.openRecentEntry).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("rejects a recent entry whose workspace is unavailable on this platform", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    useUiStore.setState({
      currentPlatform: "macos",
      enabledWorkspaces: ["log"],
    });

    await emitMenuAction({
      action: "open_recent_entry",
      menu_id: "recent.0",
      category: "file",
      target_id: "0",
      path: "/evidence/sysmon.evtx",
      workspace: "sysmon",
      kind: "file",
    });

    expect(actionMocks.current.openRecentEntry).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("clears recent entries", async () => {
    renderHook(() => useAppMenu());
    await waitFor(() => expect(eventMocks.state.callback).not.toBeNull());

    await emitMenuAction({
      action: "clear_recent_entries",
      menu_id: "file.recent.clear",
      category: "file",
    });

    expect(recentMocks.clearRecentEntries).toHaveBeenCalled();
  });
```

`emitMenuAction` defaults `trigger` to `"menu"`, which is why the first test expects `"menu"` as the fourth argument — matching the existing `switch_workspace` test's expectation.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
npx vitest run src/hooks/use-app-menu.test.tsx
```

Expected: FAIL — `openRecentEntry` is never called because no case handles the action.

- [ ] **Step 4: Extend the payload type**

In `src/hooks/use-app-menu.ts`, add the three optional fields to `AppMenuActionPayload` (line 13):

```ts
interface AppMenuActionPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  source_id: string | null;
  target_id: string | null;
  path?: string;
  workspace?: string;
  kind?: "file" | "folder";
}
```

- [ ] **Step 5: Add the two cases**

Add to the `switch (payload.action)` block, next to the `open_known_source` case:

```ts
          case "open_recent_entry": {
            const { path, workspace, kind } = payload;

            if (!path || !workspace || !kind) {
              console.warn(
                "[app-menu] open_recent_entry missing resolved fields",
                { payload },
              );
              return;
            }

            const { currentPlatform, enabledWorkspaces } =
              useUiStore.getState();
            const targetWorkspace = getAvailableWorkspaces(
              currentPlatform,
              enabledWorkspaces,
            ).find((available) => available === workspace);

            if (!targetWorkspace) {
              console.warn("[app-menu] rejected unavailable recent workspace", {
                payload,
                currentPlatform,
              });
              return;
            }

            await openRecentEntry(
              path,
              kind,
              targetWorkspace,
              payload.trigger || "native-menu.recent",
            );
            return;
          }
          case "clear_recent_entries": {
            const { clearRecentEntries } = await import(
              "../lib/recent-entries"
            );
            await clearRecentEntries();
            return;
          }
```

Destructure `openRecentEntry` from `useAppActions()` alongside the other handlers, and add it to the `useEffect` dependency array that wraps `handleAction`.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
npx vitest run src/hooks/use-app-menu.test.tsx
```

Expected: the three new tests PASS.

- [ ] **Step 7: Full verification**

```bash
npx tsc --noEmit && npm test
```

```bash
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
```

Expected: clean on all four.

- [ ] **Step 8: Manual smoke test**

```bash
npm run app:dev
```

Verify, in order:
1. `File > Recent` shows `No recent files` and is greyed out on a clean profile.
2. Open a log via `File > Open File…`; `File > Recent` now lists it as `{name} — {parent} (Log Explorer)`.
3. Open a second, different log; it appears above the first.
4. Reopen the first log; it moves back to the top and is not duplicated.
5. Quit and relaunch; both entries are still there.
6. Delete one of the files on disk, then open any log to force a rebuild; the deleted entry disappears.
7. `File > Recent > Clear Recent` empties the submenu and greys it out.
8. Switch to another workspace, open a folder there, and confirm the entry is tagged with that workspace and reopening it switches back.

- [ ] **Step 9: Commit**

```bash
git add src/hooks/use-app-menu.ts src/hooks/use-app-menu.test.tsx
git commit -m "feat(recent): open and clear recent entries from the File menu"
```

---

## Self-review notes

Checked against the spec:

- Every spec section maps to a task: storage/model → Task 1; menu rendering, labels, `FILE_ORDER` → Task 2; IPC, rebuild, click payload, pruning-on-push → Task 3; recording → Task 4; reopening and clearing → Task 5.
- Pruning placement differs slightly from a literal reading of the spec: it runs at **load** (Task 1, inside `RecentEntriesState::load`) and at **push/clear** (Task 3, before the rebuild), rather than inside the rebuild itself. This keeps `metadata()` calls off the main thread, which the spec requires; running them inside `rebuild_recent_submenu_on_main` would violate it.
- Type consistency: `RecentEntryKind` serializes as `"file"` / `"folder"` in Rust (Task 1) and is typed as `"file" | "folder"` in TypeScript (Tasks 4 and 5). `recordRecentSource` / `recordRecentPath` / `clearRecentEntries` are named identically in their definition (Task 4) and their consumers (Tasks 4 and 5). `openRecentEntry` has the same four-parameter signature where it is defined (Task 4) and called (Task 5).
- The `kind` payload field is an addition beyond the spec, documented under "Corrections to the spec" above.
