# Recent Files Submenu Design

Date: 2026-07-29

## Summary

CMTrace Open has no memory of what the user opened previously. Every session starts from `Open File…`, `Open Folder…`, or the `Open Known Source` catalog, even when the user is returning to the same evidence bundle they were reading an hour ago.

Add a **Recent** submenu to the native File menu, positioned directly after `Open Known Source`. It lists up to 10 recently opened paths, most recent first, each tagged with the workspace it was opened in. Selecting an entry switches to that workspace and reopens the path. The list is owned and persisted by the Rust backend so the menu is correct on first paint, before the webview hydrates.

## Goals

- Record every file and folder the user successfully opens, in any workspace, tagged with that workspace.
- Show those entries in a native `File > Recent` submenu with labels that disambiguate same-named logs from different bundles.
- Reopen an entry into the workspace it came from, switching workspaces when necessary.
- Persist across restarts, independently of frontend `localStorage`.
- Never show an entry that is known not to work, and never let a dead network path wedge the menu or the UI thread.

## Non-goals

- No empty-state, welcome-screen, or sidebar surface. The File menu is the only surface in this change.
- No keyboard accelerators for recent entries (`Ctrl+1..9`).
- No settings toggle to disable recording, and no privacy switch. `Clear Recent` is the escape hatch.
- Do not record Known Source presets (they already have their own submenu) or saved sessions.
- Do not add a `list_recent_entries` IPC command until a UI surface needs to read the list.

## Decisions

| Decision | Choice |
|---|---|
| Scope | Any path opened in any workspace, tagged with that workspace |
| Surface | Native File menu only |
| Ownership | Rust-owned JSON in the app config dir |
| Stale entries | Existence-checked at build time, missing entries dropped |
| Capacity | 10 entries, most recent first, plus `Clear Recent` |
| Label format | `{name} — {parent} ({Workspace})` |

## Architecture

### Data model and storage

New module `src-tauri/src/commands/recent_entries.rs`, self-contained and targeted at roughly 250 LOC.

```rust
pub enum RecentEntryKind { File, Folder }

pub struct RecentEntry {
    path: String,
    kind: RecentEntryKind,
    workspace: String,       // WorkspaceId
    opened_at_unix_ms: i64,
}
```

Persisted to `{app_config_dir}/recent-entries.json`:

```json
{ "version": 1, "entries": [ ... ] }
```

Writes are atomic: serialize to a temp file in the same directory, then rename over the target.

In-memory state is `RecentEntriesState(Mutex<Vec<RecentEntry>>)`, registered with `manage()` and deliberately **separate from `AppState`**. `AppState` guards open files and tail sessions; recents must never contend with that lock.

The list is loaded once during `setup`, before `build_app_menu`, so the first menu build has real entries.

Failure policy:

- File missing: start with an empty list. Not an error.
- File unreadable or JSON corrupt: start with an empty list, emit `log::warn`, and overwrite on the next push.
- Neither case fails startup or blocks the menu.

### Ordering, dedup, and capacity

Entries are stored newest first. The dedup key is `(normalized path, workspace)`; pushing an existing key **promotes** the entry to the front and refreshes `opened_at_unix_ms` rather than creating a duplicate. The same path opened in two different workspaces is two legitimate entries.

Normalization trims trailing path separators. On Windows, comparison is case-insensitive under `#[cfg(windows)]`; elsewhere it is case-sensitive.

The list is trimmed to 10 on every push.

### IPC surface

Two commands, registered in `lib.rs`:

- `push_recent_entry(path: String, kind: RecentEntryKind, workspace: String) -> Result<(), String>` — insert or promote, persist, rebuild the submenu.
- `clear_recent_entries() -> Result<(), String>` — empty the list, persist, rebuild the submenu.

The frontend supplies only `path`, `kind`, and `workspace`. `opened_at_unix_ms` is stamped by Rust at push time so the ordering clock is single-sourced and cannot be skewed by the webview. An unknown `workspace` string is rejected with an error rather than stored.

### Menu integration

In `src-tauri/src/menu.rs`:

```rust
pub const MENU_ID_FILE_RECENT: &str = "file.recent";
pub const MENU_ID_FILE_RECENT_CLEAR: &str = "file.recent.clear";
const RECENT_MENU_ID_PREFIX: &str = "recent.";
```

Individual entries use ids `recent.{index}.{hash}`, where `{hash}` is 8 lowercase hex chars of a `DefaultHasher` digest over the entry's normalized path and workspace. Position alone is not a safe key: a stale-but-in-range index would silently open a different file than the one clicked, which is reachable both from concurrent pushes and from `prune` shifting indices. The hash is recomputed at click time and compared before anything is emitted.

`FILE_ORDER` and `FILE_ORDER_MAC` both gain `MENU_ID_FILE_RECENT` directly after `MENU_ID_FILE_KNOWN_SOURCES`, matching how `Open Known Source` is composed today.

`build_recent_submenu(app, entries)`:

- Empty list: a single disabled item `No recent files`, with the `Recent` submenu itself disabled. This mirrors the existing `known-source.unavailable` placeholder pattern.
- Non-empty: one item per entry, then a separator, then `Clear Recent`.

`rebuild_recent_submenu(app)` drains the live submenu with `while submenu.remove_at(0)?.is_some() {}`, then appends freshly built items. Note that Tauri wraps muda here: `tauri::menu::Submenu::remove_at` returns `Result<Option<MenuItemKind>>`, not muda's bare `Option`.

The fixed-slot alternative — pre-creating ten items and updating their text through the existing `sync_app_menu_state` path — was rejected. muda 0.19.3 `MenuItem` exposes `set_text` and `set_enabled` but **no `set_visible`**, so unused slots would remain permanently visible as disabled placeholder rows.

**Threading constraint:** menu mutation is main-thread-only on macOS, and Tauri commands execute off-thread. The rebuild body must be wrapped in `app.run_on_main_thread(...)`. Missing this produces a wrong-thread crash on macOS.

### Label format

`{name} — {parent} ({Workspace})`, for example:

```
IntuneManagementExtension.log — IME (Intune Diagnostics)
```

Folders use the folder's own name and its parent. A path with no parent (a drive root) drops the `— parent` segment. The workspace label comes from `WorkspaceDescriptor.label` (`Log Explorer`, `Intune Diagnostics`, …). It is **not** `WorkspaceGroup::native_label()`, which returns group names like `Analysis`.

### Stale-entry pruning

Pruning runs on load and on each push/clear, **off the main thread**, before the main-thread hop. It deliberately does not run inside the rebuild closure: that body executes on the main thread, where a `metadata()` call against a dead UNC share would stall the UI.

For each entry, call `std::fs::metadata(path)`:

- `Ok` — keep.
- `Err` with `ErrorKind::NotFound` — drop.
- `Err` with any other kind (permission denied, network unreachable) — **keep**. Absence of proof is not proof of absence.

Entries whose `workspace` is not present in `get_available_workspaces()` are dropped. This handles a `recent-entries.json` carrying a Sysmon entry onto macOS.

`std::fs` has no per-call timeout, so the batch runs against a **whole-batch budget of 1 second**. Any entry unresolved when the budget expires is kept. A dead UNC share can therefore delay a rebuild by at most a second and can never wedge the menu or the UI thread.

If pruning changed the list, the result is persisted.

### Recording

New `src/lib/recent-entries.ts` exporting `recordRecentEntry(source, workspace)`. It invokes `push_recent_entry` for `kind: "file"` and `kind: "folder"` sources only; `kind: "known"` is skipped. The call is fire-and-forget and logs `console.warn` on failure, so a broken recents file can never break opening a log.

It is called **after a successful load**, never on attempt, so failed opens do not pollute the list. There are two choke points in `src/hooks/use-app-actions.ts`:

- `openSourceForWorkspace` — covers the menu, both file dialogs, and every workspace-specific `onOpenSource`.
- `openPathForActiveWorkspace` — covers drag-drop and file association. This function has four early-returning branches (dsregcmd, Intune, deployment, log); **each branch needs the call**.

### Reopening

`handle_menu_event` resolves a `recent.{index}.{hash}` id against the state, verifies the hash, and enriches the payload before emitting. On a hash mismatch or an out-of-range index it logs, re-queues a rebuild to repair the stale row, and returns without emitting. `AppMenuActionPayload` gains three fields:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
path: Option<String>,
#[serde(skip_serializing_if = "Option::is_none")]
workspace: Option<String>,
```

They are populated only for recent actions. A stale or mismatched id logs a warning, triggers a self-repairing rebuild, and no-ops.

`payload_for_menu_id` stays a pure function: it maps `recent.{index}.{hash}` to action `open_recent_entry` with `target_id = {index}` (the bare index, so the wire contract carries no hash), and `handle_menu_event` fills in `path`, `workspace`, and `kind` from state. `file.recent.clear` maps to action `clear_recent_entries`. A malformed id fails closed — no payload, no emit.

A new `open_recent_entry` case in `src/hooks/use-app-menu.ts` switches the workspace if it differs from the active one, then calls `openSourceForWorkspace` with the reconstructed `LogSource`. A `clear_recent_entries` case invokes the clear command.

On open failure the entry is left alone; the next rebuild's prune removes it if the path is genuinely gone.

## Data flow

```
User opens a path
  → openSourceForWorkspace / openPathForActiveWorkspace succeeds
  → recordRecentEntry(source, workspace)
  → invoke push_recent_entry
  → RecentEntriesState: normalize, promote-or-insert, trim to 10
  → persist recent-entries.json (temp + rename)
  → prune off-thread (1s budget)
  → run_on_main_thread: rebuild_recent_submenu

User clicks File > Recent > entry
  → handle_menu_event parses recent.{index}.{hash}, verifies hash vs entries[index]
  → on mismatch: log, re-queue rebuild, no emit
  → emit app-menu-action { action: "open_recent_entry", path, workspace }
  → use-app-menu: switchWorkspace if needed
  → openSourceForWorkspace({ kind, path }, "menu.recent", workspace)
```

## Error handling

| Condition | Behavior |
|---|---|
| `recent-entries.json` missing | Empty list, no error |
| `recent-entries.json` corrupt | Empty list, `log::warn`, overwritten on next push |
| Persist fails (disk full, read-only) | `log::warn`, in-memory list still updated, menu still rebuilt |
| `push_recent_entry` rejected | `console.warn` on the frontend, opening the log is unaffected |
| Path is `NotFound` at prune | Entry dropped, list persisted |
| Path errors for any other reason | Entry kept |
| Prune budget exhausted | Unresolved entries kept |
| Workspace unavailable on this platform | Entry dropped at prune |
| Click resolves to a stale index | `log::warn`, no-op |
| Menu rebuild fails | `log::error`, previous submenu contents remain |

## Testing

### Rust

- Dedup promotes rather than duplicates; `(path, workspace)` pairs are distinct keys.
- Capacity trims to 10, oldest first.
- Windows case-insensitive normalization under `#[cfg(windows)]`; case-sensitive elsewhere.
- Trailing-separator normalization.
- Corrupt JSON yields an empty list without panicking.
- Prune drops `NotFound`, keeps permission-denied.
- Prune drops entries whose workspace is not in `get_available_workspaces()`.
- `push_recent_entry` rejects an unknown workspace string and leaves the list untouched.
- Label formatting: file, folder, and a path with no parent.
- `FILE_ORDER` and `FILE_ORDER_MAC` both contain `MENU_ID_FILE_RECENT` in the expected position.
- `payload_for_menu_id` for an id built via `recent_menu_id(...)`, and for `file.recent.clear`.
- `parse_recent_menu_id` rejects `recent.`, `recent.unavailable`, `recent.3` (no hash), and `recent..abc`.
- `enrich_recent_payload` returns false on unparsable id, out-of-range index, and hash mismatch.
- `payload_for_menu_id(MENU_ID_FILE_RECENT)` yields `None` (the container id is a prefix of `file.recent.clear`).

### Frontend

- `recordRecentEntry` fires exactly once on a successful open.
- It does not fire when the open throws.
- Known sources are not recorded.
- `open_recent_entry` switches workspace before opening when the workspace differs.
- `clear_recent_entries` invokes the clear command.

## Platform notes

The feature is cross-platform. The only `cfg`-gated code is Windows case-insensitive path normalization. Per `CLAUDE.md`, Windows-only behavior is verified through CI's Windows jobs rather than locally.
