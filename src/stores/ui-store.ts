import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  clampLogDetailsFontSize,
  clampLogListFontSize,
  DEFAULT_LOG_DETAILS_FONT_SIZE,
  DEFAULT_LOG_LIST_FONT_SIZE,
} from "../lib/log-accessibility";
import { type LogSeverityPaletteMode } from "../lib/constants";

export type WorkspaceId = "log" | "intune" | "dsregcmd";
export type AppView = WorkspaceId;

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
  showFindDialog: boolean;
  showFilterDialog: boolean;
  showErrorLookupDialog: boolean;
  showAboutDialog: boolean;
  showAccessibilityDialog: boolean;
  showFileAssociationPrompt: boolean;
  logListFontSize: number;
  logDetailsFontSize: number;
  logSeverityPaletteMode: LogSeverityPaletteMode;

  setActiveWorkspace: (workspace: WorkspaceId) => void;
  setActiveView: (view: AppView) => void;
  ensureWorkspaceVisible: (workspace: WorkspaceId, trigger: string) => void;
  ensureLogViewVisible: (trigger: string) => void;
  toggleInfoPane: () => void;
  toggleDetails: () => void;
  setInfoPaneHeight: (height: number) => void;
  setShowFindDialog: (show: boolean) => void;
  setShowFilterDialog: (show: boolean) => void;
  setShowErrorLookupDialog: (show: boolean) => void;
  setShowAboutDialog: (show: boolean) => void;
  setShowAccessibilityDialog: (show: boolean) => void;
  setShowFileAssociationPrompt: (show: boolean) => void;
  setLogListFontSize: (fontSize: number) => void;
  increaseLogListFontSize: () => void;
  decreaseLogListFontSize: () => void;
  resetLogListFontSize: () => void;
  setLogDetailsFontSize: (fontSize: number) => void;
  resetLogDetailsFontSize: () => void;
  setLogSeverityPaletteMode: (mode: LogSeverityPaletteMode) => void;
  resetLogAccessibilityPreferences: () => void;
  closeTransientDialogs: (trigger: string) => void;
}

const DEFAULT_WORKSPACE: WorkspaceId = "log";

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      activeWorkspace: DEFAULT_WORKSPACE,
      activeView: DEFAULT_WORKSPACE,
      showInfoPane: true,
      showDetails: true,
      infoPaneHeight: 200,
      showFindDialog: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
      showAccessibilityDialog: false,
      showFileAssociationPrompt: false,
      logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
      logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
      logSeverityPaletteMode: "classic",

      setActiveWorkspace: (workspace) => {
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
      setShowFindDialog: (show) => set({ showFindDialog: show }),
      setShowFilterDialog: (show) => set({ showFilterDialog: show }),
      setShowErrorLookupDialog: (show) => set({ showErrorLookupDialog: show }),
      setShowAboutDialog: (show) => set({ showAboutDialog: show }),
      setShowAccessibilityDialog: (show) => set({ showAccessibilityDialog: show }),
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
      setLogSeverityPaletteMode: (mode) => set({ logSeverityPaletteMode: mode }),
      resetLogAccessibilityPreferences: () =>
        set({
          logListFontSize: DEFAULT_LOG_LIST_FONT_SIZE,
          logDetailsFontSize: DEFAULT_LOG_DETAILS_FONT_SIZE,
          logSeverityPaletteMode: "classic",
        }),
      closeTransientDialogs: (trigger) => {
        const state = get();

        if (
          !state.showFindDialog &&
          !state.showFilterDialog &&
          !state.showErrorLookupDialog &&
          !state.showAboutDialog &&
          !state.showAccessibilityDialog &&
          !state.showFileAssociationPrompt
        ) {
          return;
        }

        console.info("[ui-store] closing transient dialogs", { trigger });

        set({
          showFindDialog: false,
          showFilterDialog: false,
          showErrorLookupDialog: false,
          showAboutDialog: false,
          showAccessibilityDialog: false,
          showFileAssociationPrompt: false,
        });
      },
    }),
    {
      name: "cmtraceopen-ui-preferences",
      partialize: (state) => ({
        logListFontSize: state.logListFontSize,
        logDetailsFontSize: state.logDetailsFontSize,
        logSeverityPaletteMode: state.logSeverityPaletteMode,
      }),
    }
  )
);
