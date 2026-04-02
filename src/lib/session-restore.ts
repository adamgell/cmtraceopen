import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
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
  const content = await readTextFile(sessionPath);
  const data = JSON.parse(content);
  const session = validateSession(data);

  if (!session) {
    console.error("[session] invalid session file", { sessionPath });
    return null;
  }

  // Check file integrity
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

  // Set workspace
  const uiStore = useUiStore.getState();
  if (session.workspace) {
    uiStore.setActiveWorkspace(session.workspace as Parameters<typeof uiStore.setActiveWorkspace>[0]);
  }

  // Restore filters
  const logStore = useLogStore.getState();
  if (session.filters) {
    logStore.setHighlightText(session.filters.highlightText || "");
    logStore.setFindQuery(session.filters.findQuery || "");
    logStore.setFindCaseSensitive(session.filters.findCaseSensitive ?? false);
    logStore.setFindUseRegex(session.filters.findUseRegex ?? false);
  }

  // Add to recent sessions
  uiStore.addRecentSession(sessionPath);

  // Return the list of file paths to open — the caller handles parsing
  // via the existing file open flow
  return validTabs.map((t) => t.filePath).join("\n");
}
