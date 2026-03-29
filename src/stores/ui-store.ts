import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  clampLogDetailsFontSize,
  clampLogListFontSize,
  DEFAULT_LOG_DETAILS_FONT_SIZE,
  DEFAULT_LOG_LIST_FONT_SIZE,
} from "../lib/log-accessibility";
import type { ThemeId } from "../lib/themes/types";
import { DEFAULT_THEME_ID } from "../lib/themes";
import { clearCachedTabSnapshot } from "./log-store";
import type { ColumnId } from "../lib/column-config";
import type { CollectionResult } from "../lib/commands";

export interface ErrorLookupHistoryEntry {
  codeHex: string;
  codeDecimal: string;
  description: string;
  category: string;
  found: boolean;
  timestamp: number;
}

export type IntuneWorkspaceId = "intune" | "new-intune";
export type WorkspaceId = "log" | IntuneWorkspaceId | "dsregcmd" | "macos-diag" | "deployment";
export type AppView = WorkspaceId;

export type PlatformId = "windows" | "macos" | "linux";

export interface CollectionProgressState {
  requestId: string;
  message: string;
  currentItem: string | null;
  completedItems: number;
  totalItems: number;
}

/** Which workspaces are available on each platform. */
const WORKSPACE_PLATFORM_MAP: Record<WorkspaceId, PlatformId[] | "all"> = {
  log: "all",
  intune: "all",
  "new-intune": "all",
  dsregcmd: ["windows"],
  "macos-diag": ["macos"],
  deployment: ["windows"],
};

export function getAvailableWorkspaces(platform: PlatformId): WorkspaceId[] {
  return (Object.keys(WORKSPACE_PLATFORM_MAP) as WorkspaceId[]).filter((ws) => {
    const platforms = WORKSPACE_PLATFORM_MAP[ws];
    return platforms === "all" || platforms.includes(platform);
  });
}

/** Source context for a tab — enough to restore sidebar and skip redundant folder re-parsing. */
export interface TabSourceContext {
  /** The broad source container kind that produced this tab's content. */
  sourceKind: "file" | "folder" | "known";
  /** The folder or known-source container path (null for standalone file tabs). */
  sourcePath: string | null;
  /** The full LogSource object for restoring state on tab switch. */
  source: import("../types/log").LogSource;
}

export type TabFileKind = "log" | "registry";

export interface TabState {
  id: string;
  filePath: string;
  fileName: string;
  scrollPosition: number;
  selectedLineId: number | null;
  /** Source context — where this file was loaded from. Null for legacy/migrated tabs. */
  sourceContext: TabSourceContext | null;
  /** What kind of viewer to use for this tab. Defaults to "log". */
  fileKind: TabFileKind;
}

export function isIntuneWorkspace(workspace: WorkspaceId): workspace is IntuneWorkspaceId {
  return workspace === "intune" || workspace === "new-intune";
}

export interface UiChromeStatus {
  viewLabel: string;
  detailsLabel: string;
  infoLabel: string;
}

export function getUiChromeStatus(
  activeView: AppView,
  showDetails: boolean,
  showInfoPane: boolean
): UiChromeStatus {
  if (activeView === "new-intune") {
    return {
      viewLabel: "New Intune Workspace",
      detailsLabel: "Details hidden in New Intune Workspace",
      infoLabel: "Info hidden in New Intune Workspace",
    };
  }

  if (activeView === "intune") {
    return {
      viewLabel: "Intune workspace",
      detailsLabel: "Details hidden in Intune workspace",
      infoLabel: "Info hidden in Intune workspace",
    };
  }

  if (activeView === "dsregcmd") {
    return {
      viewLabel: "dsregcmd workspace",
      detailsLabel: "Details hidden in dsregcmd workspace",
      infoLabel: "Info hidden in dsregcmd workspace",
    };
  }

  if (activeView === "macos-diag") {
    return {
      viewLabel: "macOS Diagnostics workspace",
      detailsLabel: "Details hidden in macOS Diagnostics workspace",
      infoLabel: "Info hidden in macOS Diagnostics workspace",
    };
  }

  if (activeView === "deployment") {
    return {
      viewLabel: "Software Deployment workspace",
      detailsLabel: "Details hidden in Software Deployment workspace",
      infoLabel: "Info hidden in Software Deployment workspace",
    };
  }

  return {
    viewLabel: "Log view",
    detailsLabel: showDetails ? "Details on" : "Details off",
    infoLabel: showInfoPane ? "Info on" : "Info off",
  };
}

interface UiState {
  activeWorkspace: WorkspaceId;
  activeView: AppView;
  showInfoPane: boolean;
  showDetails: boolean;
  infoPaneHeight: number;
  showFindBar: boolean;
  showFilterDialog: boolean;
  showErrorLookupDialog: boolean;
  showAboutDialog: boolean;
  showAccessibilityDialog: boolean;
  showEvidenceBundleDialog: boolean;
  showFileAssociationPrompt: boolean;
  logListFontSize: number;
  logDetailsFontSize: number;
  fontFamily: string | null;
  themeId: ThemeId;
  columnWidths: Record<string, number>;
  columnOrder: ColumnId[] | null;
  sidebarCollapsed: boolean;
  openTabs: TabState[];
  activeTabIndex: number;
  errorLookupHistory: ErrorLookupHistoryEntry[];
  focusedErrorCode: {
    codeHex: string;
    codeDecimal: string;
    description: string;
    category: string;
  } | null;
  currentPlatform: PlatformId;
  collectionProgress: CollectionProgressState | null;
  collectionResult: CollectionResult | null;
  showCollectDiagnosticsDialog: boolean;
  showUpdateDialog: boolean;

  setActiveWorkspace: (workspace: WorkspaceId) => void;
  setCurrentPlatform: (platform: PlatformId) => void;
  setActiveView: (view: AppView) => void;
  ensureWorkspaceVisible: (workspace: WorkspaceId, trigger: string) => void;
  ensureLogViewVisible: (trigger: string) => void;
  toggleInfoPane: () => void;
  toggleDetails: () => void;
  setInfoPaneHeight: (height: number) => void;
  setShowFindBar: (show: boolean) => void;
  setShowFilterDialog: (show: boolean) => void;
  setShowErrorLookupDialog: (show: boolean) => void;
  setShowAboutDialog: (show: boolean) => void;
  setShowAccessibilityDialog: (show: boolean) => void;
  setShowEvidenceBundleDialog: (show: boolean) => void;
  setShowFileAssociationPrompt: (show: boolean) => void;
  setLogListFontSize: (fontSize: number) => void;
  increaseLogListFontSize: () => void;
  decreaseLogListFontSize: () => void;
  resetLogListFontSize: () => void;
  setLogDetailsFontSize: (fontSize: number) => void;
  resetLogDetailsFontSize: () => void;
  setFontFamily: (family: string | null) => void;
  resetFontFamily: () => void;
  setThemeId: (id: ThemeId) => void;
  resetLogAccessibilityPreferences: () => void;
  setFocusedErrorCode: (
    code: {
      codeHex: string;
      codeDecimal: string;
      description: string;
      category: string;
    } | null
  ) => void;
  addErrorLookupHistoryEntry: (entry: ErrorLookupHistoryEntry) => void;
  clearErrorLookupHistory: () => void;
  closeTransientDialogs: (trigger: string) => void;
  setColumnWidth: (columnId: string, width: number) => void;
  resetColumnWidths: () => void;
  setColumnOrder: (order: ColumnId[]) => void;
  resetColumnOrder: () => void;
  toggleSidebar: () => void;
  resetColumns: () => void;
  openTab: (filePath: string, fileName: string, sourceContext?: TabSourceContext | null, fileKind?: TabFileKind) => void;
  closeTab: (index: number) => void;
  switchTab: (index: number) => void;
  saveTabScrollState: (index: number, scrollPosition: number, selectedLineId: number | null) => void;
  setCollectionProgress: (progress: CollectionProgressState | null) => void;
  setCollectionResult: (result: CollectionResult | null) => void;
  setShowCollectDiagnosticsDialog: (show: boolean) => void;
  setShowUpdateDialog: (show: boolean) => void;
}

const DEFAULT_WORKSPACE: WorkspaceId = "log";

const sanitizePersistedUiState = (
  state: Partial<UiState>
): Partial<UiState> => {
  const sanitized: Partial<UiState> = { ...state };

  if (sanitized.logListFontSize !== undefined) {
    const raw = Number(sanitized.logListFontSize);
    const base = Number.isFinite(raw) ? raw : DEFAULT_LOG_LIST_FONT_SIZE;
    sanitized.logListFontSize = clampLogListFontSize(base);
  }

  if (sanitized.logDetailsFontSize !== undefined) {
    const raw = Number(sanitized.logDetailsFontSize);
    const base = Number.isFinite(raw) ? raw : DEFAULT_LOG_DETAILS_FONT_SIZE;
    sanitized.logDetailsFontSize = clampLogDetailsFontSize(base);
  }

  if (sanitized.fontFamily !== undefined && sanitized.fontFamily !== null) {
    if (typeof sanitized.fontFamily !== "string") {
      sanitized.fontFamily = null;
    }
  }

  if (sanitized.themeId !== undefined) {
    const validThemeIds: ThemeId[] = [
      "light", "dark", "high-contrast", "classic-cmtrace",
      "solarized-dark", "nord", "dracula", "hotdog-stand",
    ];

    if (!validThemeIds.includes(sanitized.themeId as ThemeId)) {
      sanitized.themeId = DEFAULT_THEME_ID;
    }
  }

  return sanitized;
};

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      activeWorkspace: DEFAULT_WORKSPACE,
      activeView: DEFAULT_WORKSPACE,
      showInfoPane: true,
      showDetails: true,
      infoPaneHeight: 200,
      showFindBar: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
      showAccessibilityDialog: false,
      showEvidenceBundleDialog: false,
      showFileAssociationPrompt: false,
      logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
      logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
      fontFamily: null,
      themeId: DEFAULT_THEME_ID,
      columnWidths: {},
      columnOrder: null,
      sidebarCollapsed: false,
      openTabs: [],
      activeTabIndex: -1,
      errorLookupHistory: [],
      focusedErrorCode: null,
      currentPlatform: "windows" as PlatformId,
      collectionProgress: null,
      collectionResult: null,
      showCollectDiagnosticsDialog: false,
      showUpdateDialog: false,

      setCurrentPlatform: (platform) => set({ currentPlatform: platform }),
      setActiveWorkspace: (workspace) => {
        const available = getAvailableWorkspaces(get().currentPlatform);
        if (!available.includes(workspace)) {
          console.warn(`Workspace "${workspace}" not available on ${get().currentPlatform}`);
          return;
        }

        const previousWorkspace = get().activeWorkspace;

        if (previousWorkspace === workspace) {
          return;
        }

        console.info("[ui-store] changing active workspace", {
          previousWorkspace,
          workspace,
        });

        set({
          activeWorkspace: workspace,
          activeView: workspace,
        });
      },
      setActiveView: (view) => {
        get().setActiveWorkspace(view);
      },
      ensureWorkspaceVisible: (workspace, trigger) => {
        const available = getAvailableWorkspaces(get().currentPlatform);
        if (!available.includes(workspace)) {
          console.warn(`Workspace "${workspace}" not available on ${get().currentPlatform}`);
          return;
        }

        if (get().activeWorkspace === workspace) {
          console.info("[ui-store] workspace already visible", { trigger, workspace });
          return;
        }

        console.info("[ui-store] switching workspace for command", {
          trigger,
          workspace,
        });

        set({
          activeWorkspace: workspace,
          activeView: workspace,
        });
      },
      ensureLogViewVisible: (trigger) => {
        get().ensureWorkspaceVisible("log", trigger);
      },
      toggleInfoPane: () =>
        set((state) => ({ showInfoPane: !state.showInfoPane })),
      toggleDetails: () =>
        set((state) => ({ showDetails: !state.showDetails })),
      setInfoPaneHeight: (height) => set({ infoPaneHeight: height }),
      setShowFindBar: (show) => set({ showFindBar: show }),
      setShowFilterDialog: (show) => set({ showFilterDialog: show }),
      setShowErrorLookupDialog: (show) => set({ showErrorLookupDialog: show }),
      setShowAboutDialog: (show) => set({ showAboutDialog: show }),
      setShowAccessibilityDialog: (show) => set({ showAccessibilityDialog: show }),
      setShowEvidenceBundleDialog: (show) => set({ showEvidenceBundleDialog: show }),
      setShowFileAssociationPrompt: (show) => set({ showFileAssociationPrompt: show }),
      setLogListFontSize: (fontSize) =>
        set({ logListFontSize: clampLogListFontSize(fontSize) }),
      increaseLogListFontSize: () =>
        set((state) => ({
          logListFontSize: clampLogListFontSize(state.logListFontSize + 1),
        })),
      decreaseLogListFontSize: () =>
        set((state) => ({
          logListFontSize: clampLogListFontSize(state.logListFontSize - 1),
        })),
      resetLogListFontSize: () => set({ logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE }),
      setLogDetailsFontSize: (fontSize) =>
        set({ logDetailsFontSize: clampLogDetailsFontSize(fontSize) }),
      resetLogDetailsFontSize: () =>
        set({ logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE }),
      setFontFamily: (family) => set({ fontFamily: family }),
      resetFontFamily: () => set({ fontFamily: null }),
      setThemeId: (id) => set({ themeId: id }),
      resetLogAccessibilityPreferences: () =>
        set({
          logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
          logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
          fontFamily: null,
          themeId: DEFAULT_THEME_ID,
        }),
      setFocusedErrorCode: (code) => set({ focusedErrorCode: code }),
      addErrorLookupHistoryEntry: (entry) =>
        set((state) => ({
          errorLookupHistory: [
            entry,
            ...state.errorLookupHistory.filter((e) => e.codeHex !== entry.codeHex),
          ].slice(0, 10),
        })),
      clearErrorLookupHistory: () => set({ errorLookupHistory: [] }),
      closeTransientDialogs: (trigger) => {
        const state = get();

        if (
          !state.showFindBar &&
          !state.showFilterDialog &&
          !state.showErrorLookupDialog &&
          !state.showAboutDialog &&
          !state.showAccessibilityDialog &&
          !state.showEvidenceBundleDialog &&
          !state.showFileAssociationPrompt &&
          !state.showCollectDiagnosticsDialog &&
          !state.showUpdateDialog
        ) {
          return;
        }

        console.info("[ui-store] closing transient dialogs", { trigger });

        set({
          showFindBar: false,
          showFilterDialog: false,
          showErrorLookupDialog: false,
          showAboutDialog: false,
          showAccessibilityDialog: false,
          showEvidenceBundleDialog: false,
          showFileAssociationPrompt: false,
          showCollectDiagnosticsDialog: false,
          showUpdateDialog: false,
        });
      },

      setColumnWidth: (columnId, width) =>
        set((state) => ({
          columnWidths: { ...state.columnWidths, [columnId]: width },
        })),
      resetColumnWidths: () => set({ columnWidths: {} }),
      setColumnOrder: (order) => set({ columnOrder: order }),
      resetColumnOrder: () => set({ columnOrder: null }),
      toggleSidebar: () =>
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      resetColumns: () => set({ columnWidths: {}, columnOrder: null }),

      openTab: (filePath, fileName, sourceContext, fileKind) => {
        if (!filePath) {
          console.warn("[ui-store] openTab called with empty filePath, ignoring");
          return;
        }
        const { openTabs } = get();
        const existingIndex = openTabs.findIndex((t) => t.filePath === filePath);
        if (existingIndex >= 0) {
          // Update source context and fileKind if provided (may have changed)
          const updates: Partial<TabState> = {};
          if (sourceContext) updates.sourceContext = sourceContext;
          if (fileKind) updates.fileKind = fileKind;
          if (Object.keys(updates).length > 0) {
            const updatedTabs = [...openTabs];
            updatedTabs[existingIndex] = { ...updatedTabs[existingIndex], ...updates };
            set({ openTabs: updatedTabs, activeTabIndex: existingIndex });
          } else {
            set({ activeTabIndex: existingIndex });
          }
          return;
        }
        const newTab: TabState = {
          id: crypto.randomUUID(),
          filePath,
          fileName,
          scrollPosition: 0,
          selectedLineId: null,
          sourceContext: sourceContext ?? null,
          fileKind: fileKind ?? "log",
        };
        set({
          openTabs: [...openTabs, newTab],
          activeTabIndex: openTabs.length,
        });
      },

      closeTab: (index) => {
        const { openTabs, activeTabIndex } = get();
        if (index < 0 || index >= openTabs.length) {
          console.warn("[ui-store] closeTab: invalid index", { index, tabCount: openTabs.length });
          return;
        }
        // Evict parsed entry cache for the closed tab
        clearCachedTabSnapshot(openTabs[index].filePath);
        const newTabs = openTabs.filter((_, i) => i !== index);
        let newActive = activeTabIndex;
        if (newTabs.length === 0) {
          newActive = -1;
        } else if (index === activeTabIndex) {
          newActive = index > 0 ? index - 1 : 0;
        } else if (index < activeTabIndex) {
          newActive = activeTabIndex - 1;
        }
        set({ openTabs: newTabs, activeTabIndex: newActive });
      },

      switchTab: (index) => {
        const { openTabs } = get();
        if (index < 0 || index >= openTabs.length) {
          console.warn("[ui-store] switchTab: invalid index", { index, tabCount: openTabs.length });
          return;
        }
        set({ activeTabIndex: index });
      },

      saveTabScrollState: (index, scrollPosition, selectedLineId) => {
        const { openTabs } = get();
        if (index < 0 || index >= openTabs.length) {
          console.warn("[ui-store] saveTabScrollState: invalid index", { index, tabCount: openTabs.length });
          return;
        }
        const updated = [...openTabs];
        updated[index] = { ...updated[index], scrollPosition, selectedLineId };
        set({ openTabs: updated });
      },
      setCollectionProgress: (progress) => set({ collectionProgress: progress }),
      setCollectionResult: (result) => set({ collectionResult: result }),
      setShowCollectDiagnosticsDialog: (show) => set({ showCollectDiagnosticsDialog: show }),
      setShowUpdateDialog: (show) => set({ showUpdateDialog: show }),
    }),
    {
      name: "cmtraceopen-ui-preferences",
      partialize: (state) => ({
        logListFontSize: state.logListFontSize,
        logDetailsFontSize: state.logDetailsFontSize,
        fontFamily: state.fontFamily,
        themeId: state.themeId,
        columnWidths: state.columnWidths,
        columnOrder: state.columnOrder,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
      merge: (persistedState, currentState) => {
        const raw = persistedState as Partial<UiState> & {
          logSeverityPaletteMode?: string;
        };

        // Migration: map legacy logSeverityPaletteMode to themeId
        if (raw.logSeverityPaletteMode && !raw.themeId) {
          raw.themeId =
            raw.logSeverityPaletteMode === "classic"
              ? "classic-cmtrace"
              : "light";
          delete raw.logSeverityPaletteMode;
        }

        const sanitized = sanitizePersistedUiState(raw);
        return {
          ...currentState,
          ...sanitized,
        };
      },
    }
  )
);
