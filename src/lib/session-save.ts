import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { useLogStore, getCachedTabSnapshot } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import { useFilterStore } from "../stores/filter-store";
import { useIntuneStore } from "../workspaces/intune/intune-store";
import type { SessionFile, SessionTab } from "./session";

interface FileHashResult {
  hash: string;
  sizeBytes: number;
}

export async function saveSession(): Promise<string | null> {
  const logState = useLogStore.getState();
  const uiState = useUiStore.getState();
  const filterState = useFilterStore.getState();

  const openTabs = uiState.openTabs;
  if (openTabs.length === 0 && uiState.activeWorkspace === "log") {
    return null;
  }

  // Build tab entries with file hashes
  const tabs: SessionTab[] = [];
  for (let i = 0; i < openTabs.length; i++) {
    const tab = openTabs[i];
    let hash = "";
    let size = 0;
    try {
      const result = await invoke<FileHashResult>("compute_file_hash", { path: tab.filePath });
      hash = result.hash;
      size = result.sizeBytes;
    } catch {
      // File might not exist or be inaccessible — save without hash
    }

    const snapshot = getCachedTabSnapshot(tab.filePath);
    tabs.push({
      filePath: tab.filePath,
      fileHash: hash,
      fileSize: size,
      selectedId: i === uiState.activeTabIndex ? logState.selectedId : null,
      scrollPosition: null,
      activeColumns: snapshot?.activeColumns ?? [],
    });
  }

  // Build workspace state
  let workspaceState: SessionFile["workspaceState"] = { type: "log" };
  if (uiState.activeWorkspace === "intune") {
    const intuneState = useIntuneStore.getState();
    workspaceState = {
      type: "intune",
      sourceFile: intuneState.sourceFile,
      activeTab: intuneState.activeTab,
      filterEventType: intuneState.filterEventType,
      filterStatus: intuneState.filterStatus,
      timelineViewMode: intuneState.timelineViewMode,
    };
  } else if (uiState.activeWorkspace === "dsregcmd") {
    workspaceState = {
      type: "dsregcmd",
      sourcePath: null,
    };
  }

  const session: SessionFile = {
    version: 1,
    savedAt: new Date().toISOString(),
    workspace: uiState.activeWorkspace,
    tabs,
    activeTabIndex: uiState.activeTabIndex,
    mergedTabState: logState.mergedTabState
      ? {
          sourceFilePaths: logState.mergedTabState.sourceFilePaths,
          fileVisibility: logState.mergedTabState.fileVisibility,
          correlationWindowMs: logState.correlationWindowMs,
          autoCorrelate: logState.autoCorrelate,
        }
      : null,
    filters: {
      clauses: filterState.clauses ?? [],
      findQuery: logState.findQuery,
      findCaseSensitive: logState.findCaseSensitive,
      findUseRegex: logState.findUseRegex,
      highlightText: logState.highlightText,
    },
    workspaceState,
  };

  const filePath = await save({
    title: "Save Session",
    filters: [{ name: "CMTrace Session", extensions: ["cmtrace"] }],
    defaultPath: "session.cmtrace",
  });

  if (!filePath) return null;

  await writeTextFile(filePath, JSON.stringify(session, null, 2));

  // Add to recent sessions
  useUiStore.getState().addRecentSession(filePath);

  return filePath;
}
