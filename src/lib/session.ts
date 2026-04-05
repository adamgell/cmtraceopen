export interface SessionFile {
  version: number;
  savedAt: string;
  workspace: string;
  tabs: SessionTab[];
  activeTabIndex: number;
  mergedTabState: SessionMergedState | null;
  filters: SessionFilters;
  workspaceState: SessionWorkspaceState;
}

export interface SessionTab {
  filePath: string;
  fileHash: string;
  fileSize: number;
  selectedId: number | null;
  scrollPosition: number | null;
  activeColumns: string[];
}

export interface SessionMergedState {
  sourceFilePaths: string[];
  fileVisibility: Record<string, boolean>;
  correlationWindowMs: number;
  autoCorrelate: boolean;
}

export interface SessionFilters {
  clauses: unknown[];
  findQuery: string;
  findCaseSensitive: boolean;
  findUseRegex: boolean;
  highlightText: string;
}

export type SessionWorkspaceState =
  | { type: "log" }
  | {
      type: "intune";
      sourceFile: string | null;
      activeTab: string;
      filterEventType: string;
      filterStatus: string;
      timelineViewMode: string;
    }
  | {
      type: "dsregcmd";
      sourcePath: string | null;
    }
  | { type: string };

const CURRENT_VERSION = 1;

export function createEmptySession(): SessionFile {
  return {
    version: CURRENT_VERSION,
    savedAt: new Date().toISOString(),
    workspace: "log",
    tabs: [],
    activeTabIndex: 0,
    mergedTabState: null,
    filters: {
      clauses: [],
      findQuery: "",
      findCaseSensitive: false,
      findUseRegex: false,
      highlightText: "",
    },
    workspaceState: { type: "log" },
  };
}

export function validateSession(data: unknown): SessionFile | null {
  if (typeof data !== "object" || data === null) return null;
  const obj = data as Record<string, unknown>;
  if (typeof obj.version !== "number") return null;
  if (obj.version > CURRENT_VERSION) return null;
  if (!Array.isArray(obj.tabs)) return null;
  // Validate each tab has required fields
  for (const tab of obj.tabs) {
    if (typeof tab !== "object" || tab === null) return null;
    const t = tab as Record<string, unknown>;
    if (typeof t.filePath !== "string") return null;
  }
  if (typeof obj.workspace !== "string") return null;
  return obj as unknown as SessionFile;
}

export interface FileChangeWarning {
  filePath: string;
  issue: "missing" | "changed";
  savedHash: string;
  savedSize: number;
  currentHash?: string;
  currentSize?: number;
}
