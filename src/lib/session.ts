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
  if (typeof obj.workspace !== "string") return null;

  // Validate and sanitize each tab
  const tabs: SessionTab[] = [];
  for (const tab of obj.tabs) {
    if (typeof tab !== "object" || tab === null) return null;
    const t = tab as Record<string, unknown>;
    if (typeof t.filePath !== "string") return null;
    tabs.push({
      filePath: t.filePath,
      fileHash: typeof t.fileHash === "string" ? t.fileHash : "",
      fileSize: typeof t.fileSize === "number" ? t.fileSize : 0,
      selectedId: typeof t.selectedId === "number" ? t.selectedId : null,
      scrollPosition: typeof t.scrollPosition === "number" ? t.scrollPosition : null,
      activeColumns: Array.isArray(t.activeColumns) ? t.activeColumns.filter((c): c is string => typeof c === "string") : [],
    });
  }

  const defaults = createEmptySession();

  // Sanitize filters
  const rawFilters = typeof obj.filters === "object" && obj.filters !== null
    ? obj.filters as Record<string, unknown>
    : {};
  const filters: SessionFilters = {
    clauses: Array.isArray(rawFilters.clauses) ? rawFilters.clauses : [],
    findQuery: typeof rawFilters.findQuery === "string" ? rawFilters.findQuery : "",
    findCaseSensitive: typeof rawFilters.findCaseSensitive === "boolean" ? rawFilters.findCaseSensitive : false,
    findUseRegex: typeof rawFilters.findUseRegex === "boolean" ? rawFilters.findUseRegex : false,
    highlightText: typeof rawFilters.highlightText === "string" ? rawFilters.highlightText : "",
  };

  // Sanitize merged tab state
  let mergedTabState: SessionMergedState | null = null;
  if (typeof obj.mergedTabState === "object" && obj.mergedTabState !== null) {
    const m = obj.mergedTabState as Record<string, unknown>;
    if (Array.isArray(m.sourceFilePaths)) {
      mergedTabState = {
        sourceFilePaths: m.sourceFilePaths.filter((p): p is string => typeof p === "string"),
        fileVisibility: typeof m.fileVisibility === "object" && m.fileVisibility !== null
          ? m.fileVisibility as Record<string, boolean>
          : {},
        correlationWindowMs: typeof m.correlationWindowMs === "number" ? m.correlationWindowMs : 1000,
        autoCorrelate: typeof m.autoCorrelate === "boolean" ? m.autoCorrelate : false,
      };
    }
  }

  const activeTabIndex = typeof obj.activeTabIndex === "number"
    ? Math.max(0, Math.min(obj.activeTabIndex, tabs.length - 1))
    : 0;

  return {
    version: obj.version,
    savedAt: typeof obj.savedAt === "string" ? obj.savedAt : defaults.savedAt,
    workspace: obj.workspace as string,
    tabs,
    activeTabIndex,
    mergedTabState,
    filters,
    workspaceState: typeof obj.workspaceState === "object" && obj.workspaceState !== null
      ? obj.workspaceState as SessionWorkspaceState
      : defaults.workspaceState,
  };
}

export interface FileChangeWarning {
  filePath: string;
  issue: "missing" | "changed";
  savedHash: string;
  savedSize: number;
  currentHash?: string;
  currentSize?: number;
}
