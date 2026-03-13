import { create } from "zustand";

export type WorkspaceId = "log" | "intune";
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
  if (activeView !== "log") {
    return {
      viewLabel: "Intune view",
      detailsLabel: "Details hidden in Intune view",
      infoLabel: "Info hidden in Intune view",
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
  closeTransientDialogs: (trigger: string) => void;
}

const DEFAULT_WORKSPACE: WorkspaceId = "log";

export const useUiStore = create<UiState>((set, get) => ({
  activeWorkspace: DEFAULT_WORKSPACE,
  activeView: DEFAULT_WORKSPACE,
  showInfoPane: true,
  showDetails: true,
  infoPaneHeight: 200,
  showFindDialog: false,
  showFilterDialog: false,
  showErrorLookupDialog: false,
  showAboutDialog: false,

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
  closeTransientDialogs: (trigger) => {
    const state = get();

    if (
      !state.showFindDialog &&
      !state.showFilterDialog &&
      !state.showErrorLookupDialog &&
      !state.showAboutDialog
    ) {
      return;
    }

    console.info("[ui-store] closing transient dialogs", { trigger });

    set({
      showFindDialog: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
    });
  },
}));
