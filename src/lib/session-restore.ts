import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import { loadPathAsLogSource, loadFilesAsLogSource } from "./log-source";
import { validateSession, type FileChangeWarning } from "./session";

interface FileHashResult {
  hash: string;
  sizeBytes: number;
}

export async function openSessionDialog(): Promise<string | null> {
  const filePath = await open({
    title: "Open Session",
    filters: [{ name: "CMTrace Session", extensions: ["cmtrace"] }],
    multiple: false,
  });

  if (!filePath || Array.isArray(filePath)) return null;
  return restoreSession(filePath);
}

export async function restoreSession(sessionPath: string): Promise<string | null> {
  let content: string;
  try {
    content = await readTextFile(sessionPath);
  } catch (error) {
    console.error("[session] failed to read session file", { sessionPath, error });
    return null;
  }

  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    console.error("[session] invalid JSON in session file", { sessionPath });
    return null;
  }
  const session = validateSession(data);

  if (!session) {
    console.error("[session] invalid session file", { sessionPath });
    return null;
  }

  // Check file integrity for sessions that have tabs
  const warnings: FileChangeWarning[] = [];
  const validTabs: typeof session.tabs = [];

  for (const tab of session.tabs) {
    try {
      const result = await invoke<FileHashResult>("compute_file_hash", { path: tab.filePath });
      if (tab.fileHash && result.hash !== tab.fileHash) {
        warnings.push({
          filePath: tab.filePath,
          issue: "changed",
          savedHash: tab.fileHash,
          savedSize: tab.fileSize,
          currentHash: result.hash,
          currentSize: result.sizeBytes,
        });
      }
      validTabs.push(tab);
    } catch {
      warnings.push({
        filePath: tab.filePath,
        issue: "missing",
        savedHash: tab.fileHash,
        savedSize: tab.fileSize,
      });
    }
  }

  if (warnings.length > 0) {
    const missing = warnings.filter((w) => w.issue === "missing");
    const changed = warnings.filter((w) => w.issue === "changed");
    const parts: string[] = [];
    if (missing.length > 0) {
      parts.push(`${missing.length} file(s) not found: ${missing.map((w) => w.filePath.split(/[\\/]/).pop()).join(", ")}`);
    }
    if (changed.length > 0) {
      parts.push(`${changed.length} file(s) changed since session was saved`);
    }
    console.warn("[session] file integrity warnings:", parts.join("; "), warnings);
  }

  if (validTabs.length === 0) {
    console.error("[session] no valid files to restore");
    return null;
  }

  // Clear current state
  useLogStore.getState().clear();
  useUiStore.getState().clearTabs();

  // Set workspace
  const uiStore = useUiStore.getState();
  if (session.workspace) {
    uiStore.setActiveWorkspace(session.workspace as Parameters<typeof uiStore.setActiveWorkspace>[0]);
  }

  // Add to recent sessions
  uiStore.addRecentSession(sessionPath);

  // Load each file individually to create proper per-file tabs.
  // If every file fails, fall back to the aggregate load path so the user
  // isn't left with empty tabs after the pre-clear above.
  // Track which paths actually opened so the index/scroll restore below
  // targets the right tab even when some files failed to load.
  const filePaths = validTabs.map((t) => t.filePath);
  const loadedTabsByPath = new Map<string, (typeof validTabs)[number]>();
  for (const tab of validTabs) {
    try {
      await loadPathAsLogSource(tab.filePath, { fallbackToFolder: false });
      loadedTabsByPath.set(tab.filePath, tab);
    } catch (error) {
      console.warn("[session] failed to load file during restore", { filePath: tab.filePath, error });
    }
  }

  if (loadedTabsByPath.size === 0 && filePaths.length > 0) {
    try {
      await loadFilesAsLogSource(filePaths);
      // Aggregate load opens one tab per file in the same order.
      for (const tab of validTabs) loadedTabsByPath.set(tab.filePath, tab);
    } catch (fallbackError) {
      console.error("[session] aggregate fallback load failed", fallbackError);
    }
  }

  // Restore index / scroll using the actual openTabs list; openTab in
  // ui-store may dedupe, reorder, or skip based on existing state, so
  // session indices aren't trustworthy after partial failures.
  const openTabs = useUiStore.getState().openTabs;
  const activeSessionTab = validTabs[session.activeTabIndex];
  if (activeSessionTab) {
    const liveIndex = openTabs.findIndex((t) => t.filePath === activeSessionTab.filePath);
    if (liveIndex >= 0) {
      uiStore.switchTab(liveIndex);
    }
  }

  for (const [filePath, savedTab] of loadedTabsByPath) {
    const liveIndex = openTabs.findIndex((t) => t.filePath === filePath);
    if (liveIndex >= 0 && (savedTab.scrollPosition != null || savedTab.selectedId != null)) {
      uiStore.saveTabScrollState(
        liveIndex,
        savedTab.scrollPosition ?? 0,
        savedTab.selectedId ?? null,
      );
    }
  }

  // Restore filters AFTER files are loaded so find/highlight operate on the loaded entries
  const logStore = useLogStore.getState();
  if (session.filters) {
    logStore.setHighlightText(session.filters.highlightText || "");
    logStore.setFindQuery(session.filters.findQuery || "");
    logStore.setFindCaseSensitive(session.filters.findCaseSensitive ?? false);
    logStore.setFindUseRegex(session.filters.findUseRegex ?? false);
  }

  return sessionPath;
}
