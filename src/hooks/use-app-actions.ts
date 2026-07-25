import { useCallback, useMemo } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { inspectPathKind } from "../lib/commands";
import {
  analyzeDsregcmdPath,
  analyzeDsregcmdSource,
  refreshCurrentDsregcmdSource,
} from "../lib/dsregcmd-source";
import {
  getKnownSourceMetadataById,
  loadFilesAsLogSource,
  loadLogSource,
  loadPathAsLogSource,
  resolveKnownSourceIdFromCatalogAction,
  type KnownSourceCatalogActionIds,
} from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useLogStore } from "../stores/log-store";
import {
  isIntuneWorkspace,
  type WorkspaceId,
  useUiStore,
} from "../stores/ui-store";
import type { LogSource } from "../types/log";
import { useDsregcmdStore } from "../workspaces/dsregcmd/dsregcmd-store";
import { useEspDiagnosticsStore } from "../workspaces/esp-diagnostics/esp-diagnostics-store";
import { useIntuneStore } from "../workspaces/intune/intune-store";
import { getWorkspace } from "../workspaces/registry";
import { useSysmonStore } from "../workspaces/sysmon/sysmon-store";

const LIVE_SYSMON_SOURCE_ID = "windows-sysmon-live-events";

function normalizeDialogSelection(
  selected: string | string[] | null,
): string | null {
  if (!selected) {
    return null;
  }

  return Array.isArray(selected) ? selected[0] ?? null : selected;
}

function resolveRefreshSource(
  activeSource: LogSource | null,
  openFilePath: string | null,
): LogSource | null {
  if (activeSource) {
    return activeSource;
  }

  if (openFilePath) {
    return { kind: "file", path: openFilePath };
  }

  return null;
}

function toNativeMenuLabel(label: string): string {
  const normalizedLabel = label.replace(/\.\.\.$/, "…");

  if (normalizedLabel === "Open file…") {
    return "Open File…";
  }

  if (normalizedLabel === "Open folder…") {
    return "Open Folder…";
  }

  return normalizedLabel;
}

async function inferPathKind(
  path: string,
): Promise<"file" | "folder" | "unknown"> {
  try {
    return await inspectPathKind(path);
  } catch {
    return "unknown";
  }
}

export interface OpenKnownSourceCatalogAction
  extends KnownSourceCatalogActionIds {
  trigger: string;
}

export interface AppCommandState {
  canOpenSources: boolean;
  canOpenKnownSources: boolean;
  canPauseResume: boolean;
  canFind: boolean;
  hasFindSession: boolean;
  canFilter: boolean;
  canRefresh: boolean;
  canToggleSidebar: boolean;
  canToggleDetailsPane: boolean;
  canToggleInfoPane: boolean;
  canAdjustTextSize: boolean;
  canShowEvidenceBundle: boolean;
  canSaveSession: boolean;
  canCollectDiagnostics: boolean;
  isLoading: boolean;
  isPaused: boolean;
  hasActiveSource: boolean;
  isSidebarVisible: boolean;
  isDetailsVisible: boolean;
  isInfoPaneVisible: boolean;
  activeFilterCount: number;
  isFiltering: boolean;
  filterError: string | null;
  activeWorkspace: WorkspaceId;
  openFileLabel: string;
  openFolderLabel: string;
}

export interface AppActionHandlers {
  commandState: AppCommandState;
  openSourceFileDialog: () => Promise<void>;
  openSourceFolderDialog: () => Promise<void>;
  openPathForActiveWorkspace: (path: string) => Promise<void>;
  openKnownSourceCatalogAction: (
    action: OpenKnownSourceCatalogAction,
  ) => Promise<void>;
  openKnownSourceById: (sourceId: string, trigger: string) => Promise<void>;
  pasteDsregcmdSource: () => Promise<void>;
  captureDsregcmdSource: () => Promise<void>;
  showFindBar: () => void;
  findNext: (trigger: string) => void;
  findPrevious: (trigger: string) => void;
  showFilterDialog: () => void;
  showErrorLookupDialog: () => void;
  showAboutDialog: () => void;
  showSettingsDialog: () => void;
  showEvidenceBundleDialog: () => void;
  increaseLogListTextSize: () => void;
  decreaseLogListTextSize: () => void;
  resetLogListTextSize: () => void;
  togglePauseResume: () => void;
  refreshActiveSource: () => Promise<void>;
  toggleSidebar: () => void;
  toggleDetailsPane: () => void;
  toggleInfoPane: () => void;
  switchWorkspace: (workspace: WorkspaceId, trigger: string) => void;
  dismissTransientDialogs: (trigger: string) => void;
}

export function useAppActions(): AppActionHandlers {
  const isLoading = useLogStore((state) => state.isLoading);
  const isPaused = useLogStore((state) => state.isPaused);
  const entriesCount = useLogStore((state) => state.entries.length);
  const activeSource = useLogStore((state) => state.activeSource);
  const openFilePath = useLogStore((state) => state.openFilePath);
  const selectedSourceFilePath = useLogStore(
    (state) => state.selectedSourceFilePath,
  );
  const bundleMetadata = useLogStore((state) => state.bundleMetadata);
  const findQuery = useLogStore((state) => state.findQuery);
  const findMatchCount = useLogStore((state) => state.findMatchIds.length);
  const knownSourceCount = useLogStore((state) =>
    state.knownSourceToolbarFamilies.reduce(
      (familyTotal, family) =>
        familyTotal +
        family.groups.reduce(
          (groupTotal, group) => groupTotal + group.sources.length,
          0,
        ),
      0,
    ),
  );
  const intuneIsAnalyzing = useIntuneStore((state) => state.isAnalyzing);
  const intuneEvidenceBundle = useIntuneStore((state) => state.evidenceBundle);
  const dsregcmdIsAnalyzing = useDsregcmdStore((state) => state.isAnalyzing);
  const dsregcmdSource = useDsregcmdStore(
    (state) => state.sourceContext.source,
  );
  const dsregcmdBundlePath = useDsregcmdStore(
    (state) => state.sourceContext.bundlePath,
  );
  const espPhase = useEspDiagnosticsStore((state) => state.phase);
  const espSessionId = useEspDiagnosticsStore((state) => state.sessionId);
  const sysmonIsAnalyzing = useSysmonStore((state) => state.isAnalyzing);
  const sysmonSourcePath = useSysmonStore((state) => state.sourcePath);

  const activeWorkspace = useUiStore((state) => state.activeWorkspace);
  const showDetails = useUiStore((state) => state.showDetails);
  const showInfoPane = useUiStore((state) => state.showInfoPane);
  const sidebarCollapsed = useUiStore((state) => state.sidebarCollapsed);
  const openTabCount = useUiStore((state) => state.openTabs.length);
  const collectionProgress = useUiStore((state) => state.collectionProgress);
  const setShowFindBar = useUiStore((state) => state.setShowFindBar);
  const setShowFilterDialog = useUiStore(
    (state) => state.setShowFilterDialog,
  );
  const setShowErrorLookupDialog = useUiStore(
    (state) => state.setShowErrorLookupDialog,
  );
  const setShowAboutDialog = useUiStore(
    (state) => state.setShowAboutDialog,
  );
  const setShowSettingsDialog = useUiStore(
    (state) => state.setShowSettingsDialog,
  );
  const setShowEvidenceBundleDialog = useUiStore(
    (state) => state.setShowEvidenceBundleDialog,
  );
  const increaseLogListFontSize = useUiStore(
    (state) => state.increaseLogListFontSize,
  );
  const decreaseLogListFontSize = useUiStore(
    (state) => state.decreaseLogListFontSize,
  );
  const resetLogListFontSize = useUiStore(
    (state) => state.resetLogListFontSize,
  );

  const activeFilterCount = useFilterStore((state) => state.clauses.length);
  const isFiltering = useFilterStore((state) => state.isFiltering);
  const filterError = useFilterStore((state) => state.filterError);

  const refreshSource = useMemo(
    () => resolveRefreshSource(activeSource, openFilePath),
    [activeSource, openFilePath],
  );
  const isEspSourceCommandBusy =
    espSessionId !== null ||
    espPhase === "analyzing" ||
    espPhase === "starting" ||
    espPhase === "live" ||
    espPhase === "stopping";
  const isSourceCommandBusy =
    activeWorkspace === "log"
      ? isLoading
      : isIntuneWorkspace(activeWorkspace)
        ? intuneIsAnalyzing
        : activeWorkspace === "dsregcmd"
          ? dsregcmdIsAnalyzing
          : activeWorkspace === "sysmon"
            ? sysmonIsAnalyzing
            : activeWorkspace === "esp-diagnostics"
              ? isEspSourceCommandBusy
              : false;

  const commandState = useMemo<AppCommandState>(() => {
    const workspace = getWorkspace(activeWorkspace);
    const capabilities = workspace.capabilities ?? {};
    const canToggleSidebar = capabilities.sidebar ?? true;
    const canToggleDetailsPane = capabilities.detailsPane ?? false;
    const canToggleInfoPane = capabilities.infoPane ?? false;
    const hasFindSession =
      findQuery.trim().length > 0 && findMatchCount > 0;

    return {
      canOpenSources: !isSourceCommandBusy,
      canOpenKnownSources:
        !isSourceCommandBusy &&
        knownSourceCount > 0 &&
        (capabilities.knownSources ?? true),
      canPauseResume:
        (capabilities.tailing ?? false) &&
        !isLoading &&
        refreshSource !== null,
      canFind: (capabilities.findBar ?? false) && entriesCount > 0,
      hasFindSession,
      canFilter:
        (capabilities.findBar ?? false) &&
        entriesCount > 0 &&
        !isFiltering,
      canRefresh:
        !isSourceCommandBusy &&
        (activeWorkspace === "log"
          ? refreshSource !== null
          : activeWorkspace === "dsregcmd"
            ? dsregcmdSource !== null
            : activeWorkspace === "sysmon"
              ? sysmonSourcePath !== null
              : false),
      canToggleSidebar,
      canToggleDetailsPane,
      canToggleInfoPane,
      canAdjustTextSize: capabilities.fontSizing ?? false,
      canShowEvidenceBundle:
        activeWorkspace === "log"
          ? bundleMetadata !== null
          : isIntuneWorkspace(activeWorkspace)
            ? intuneEvidenceBundle !== null
            : activeWorkspace === "dsregcmd"
              ? dsregcmdBundlePath !== null
              : false,
      canSaveSession: openTabCount > 0,
      canCollectDiagnostics: collectionProgress === null,
      isLoading: isSourceCommandBusy,
      isPaused,
      hasActiveSource:
        activeWorkspace === "log"
          ? refreshSource !== null
          : activeWorkspace === "dsregcmd"
            ? dsregcmdSource !== null
            : activeWorkspace === "sysmon"
              ? sysmonSourcePath !== null
              : false,
      isSidebarVisible: canToggleSidebar && !sidebarCollapsed,
      isDetailsVisible: canToggleDetailsPane && showDetails,
      isInfoPaneVisible: canToggleInfoPane && showInfoPane,
      activeFilterCount,
      isFiltering,
      filterError,
      activeWorkspace,
      openFileLabel: toNativeMenuLabel(
        workspace.actionLabels?.file ?? "Open File…",
      ),
      openFolderLabel: toNativeMenuLabel(
        workspace.actionLabels?.folder ?? "Open Folder…",
      ),
    };
  }, [
    activeFilterCount,
    activeWorkspace,
    bundleMetadata,
    collectionProgress,
    dsregcmdBundlePath,
    dsregcmdSource,
    entriesCount,
    filterError,
    findMatchCount,
    findQuery,
    intuneEvidenceBundle,
    isFiltering,
    isLoading,
    isPaused,
    isSourceCommandBusy,
    knownSourceCount,
    openTabCount,
    refreshSource,
    showDetails,
    showInfoPane,
    sidebarCollapsed,
    sysmonSourcePath,
  ]);

  const loadLogWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string) => {
      const currentWorkspace = useUiStore.getState().activeWorkspace;
      if (currentWorkspace !== "deployment") {
        useUiStore.getState().ensureLogViewVisible(trigger);
      }
      useFilterStore.getState().clearFilter();

      try {
        await loadLogSource(source);
      } catch (error) {
        console.error("[app-actions] failed to load source", {
          source,
          trigger,
          error,
        });
      }
    },
    [],
  );

  const openSourceForWorkspace = useCallback(
    async (source: LogSource, trigger: string, workspace: WorkspaceId) => {
      const workspaceDefinition = getWorkspace(workspace);
      if (workspaceDefinition.onOpenSource) {
        await workspaceDefinition.onOpenSource(source, trigger);
      } else {
        await loadLogWorkspaceSource(source, trigger);
      }
    },
    [loadLogWorkspaceSource],
  );

  const openPathForActiveWorkspace = useCallback(
    async (path: string) => {
      if (activeWorkspace === "dsregcmd") {
        useUiStore
          .getState()
          .ensureWorkspaceVisible("dsregcmd", "drag-drop.path-open");
        await analyzeDsregcmdPath(path, { fallbackToFolder: true });
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
        return;
      }

      if (activeWorkspace === "deployment") {
        const { useDeploymentStore } = await import(
          "../workspaces/deployment/deployment-store"
        );
        await useDeploymentStore.getState().analyzeFolder(path);
        return;
      }

      useUiStore.getState().ensureLogViewVisible("drag-drop.path-open");
      useFilterStore.getState().clearFilter();
      await loadPathAsLogSource(path, {
        fallbackToFolder: true,
      });
    },
    [activeWorkspace],
  );

  const openKnownSourceCatalogAction = useCallback(
    async (action: OpenKnownSourceCatalogAction) => {
      const sourceId = resolveKnownSourceIdFromCatalogAction(action);

      if (!sourceId) {
        console.warn("[app-actions] could not resolve known source for action", {
          action,
        });
        return;
      }

      if (activeWorkspace === "dsregcmd") {
        throw new Error(
          "Known source presets are not available in the dsregcmd workspace.",
        );
      }

      const metadata = await getKnownSourceMetadataById(sourceId);

      if (!metadata) {
        throw new Error(
          `[app-actions] known source metadata was not found for id '${sourceId}'`,
        );
      }

      await openSourceForWorkspace(
        metadata.source,
        action.trigger,
        activeWorkspace,
      );
    },
    [activeWorkspace, openSourceForWorkspace],
  );

  const openSourceFileDialog = useCallback(async () => {
    if (!commandState.canOpenSources) {
      return;
    }

    const isLogWorkspace = activeWorkspace === "log";
    const activeWorkspaceDefinition = getWorkspace(activeWorkspace);
    const fileDialogFilters = activeWorkspaceDefinition.fileFilters ?? [
      {
        name: "Log Files",
        extensions: ["log", "txt", "csv", "json", "xml", "evtx"],
      },
      { name: "All Files", extensions: ["*"] },
    ];

    const selected = await open({
      multiple: isLogWorkspace,
      filters: fileDialogFilters,
    });

    if (!selected) {
      return;
    }

    const paths = Array.isArray(selected) ? selected : [selected];
    if (paths.length === 0) {
      return;
    }

    if (paths.length === 1) {
      await openSourceForWorkspace(
        { kind: "file", path: paths[0] },
        "app-actions.open-file",
        activeWorkspace,
      );
    } else {
      await loadFilesAsLogSource(paths);
    }
  }, [activeWorkspace, commandState.canOpenSources, openSourceForWorkspace]);

  const openSourceFolderDialog = useCallback(async () => {
    if (!commandState.canOpenSources) {
      return;
    }

    const selected = await open({
      multiple: false,
      directory: true,
    });

    const folderPath = normalizeDialogSelection(selected);

    if (!folderPath) {
      return;
    }

    await openSourceForWorkspace(
      { kind: "folder", path: folderPath },
      "app-actions.open-folder",
      activeWorkspace,
    );
  }, [activeWorkspace, commandState.canOpenSources, openSourceForWorkspace]);

  const openKnownSourceById = useCallback(
    async (sourceId: string, trigger: string) => {
      await openKnownSourceCatalogAction({
        sourceId,
        trigger,
      });
    },
    [openKnownSourceCatalogAction],
  );

  const pasteDsregcmdSource = useCallback(async () => {
    if (isSourceCommandBusy) {
      return;
    }

    useUiStore
      .getState()
      .ensureWorkspaceVisible("dsregcmd", "app-actions.dsregcmd-paste");
    await analyzeDsregcmdSource({ kind: "clipboard" });
  }, [isSourceCommandBusy]);

  const captureDsregcmdSource = useCallback(async () => {
    if (isSourceCommandBusy) {
      return;
    }

    useUiStore
      .getState()
      .ensureWorkspaceVisible("dsregcmd", "app-actions.dsregcmd-capture");
    await analyzeDsregcmdSource({ kind: "capture" });
  }, [isSourceCommandBusy]);

  const showFindBar = useCallback(() => {
    if (!commandState.canFind) {
      return;
    }

    useUiStore.getState().ensureLogViewVisible("app-actions.show-find");
    setShowFindBar(true);
  }, [commandState.canFind, setShowFindBar]);

  const findNext = useCallback(
    (trigger: string) => {
      if (!commandState.canFind) {
        return;
      }

      const logState = useLogStore.getState();
      if (!logState.hasFindSession()) {
        showFindBar();
        return;
      }

      logState.findNext(trigger);
    },
    [commandState.canFind, showFindBar],
  );

  const findPrevious = useCallback(
    (trigger: string) => {
      if (!commandState.canFind) {
        return;
      }

      const logState = useLogStore.getState();
      if (!logState.hasFindSession()) {
        showFindBar();
        return;
      }

      logState.findPrevious(trigger);
    },
    [commandState.canFind, showFindBar],
  );

  const showFilterDialog = useCallback(() => {
    if (!commandState.canFilter) {
      return;
    }

    useUiStore.getState().ensureLogViewVisible("app-actions.show-filter");
    setShowFilterDialog(true);
  }, [commandState.canFilter, setShowFilterDialog]);

  const showErrorLookupDialog = useCallback(() => {
    setShowErrorLookupDialog(true);
  }, [setShowErrorLookupDialog]);

  const showAboutDialog = useCallback(() => {
    setShowAboutDialog(true);
  }, [setShowAboutDialog]);

  const showSettingsDialog = useCallback(() => {
    setShowSettingsDialog(true);
  }, [setShowSettingsDialog]);

  const showEvidenceBundleDialog = useCallback(() => {
    if (!commandState.canShowEvidenceBundle) {
      return;
    }

    setShowEvidenceBundleDialog(true);
  }, [commandState.canShowEvidenceBundle, setShowEvidenceBundleDialog]);

  const increaseLogListTextSize = useCallback(() => {
    if (commandState.canAdjustTextSize) {
      increaseLogListFontSize();
    }
  }, [commandState.canAdjustTextSize, increaseLogListFontSize]);

  const decreaseLogListTextSize = useCallback(() => {
    if (commandState.canAdjustTextSize) {
      decreaseLogListFontSize();
    }
  }, [commandState.canAdjustTextSize, decreaseLogListFontSize]);

  const resetLogListTextSize = useCallback(() => {
    if (commandState.canAdjustTextSize) {
      resetLogListFontSize();
    }
  }, [commandState.canAdjustTextSize, resetLogListFontSize]);

  const togglePauseResume = useCallback(() => {
    if (!commandState.canPauseResume) {
      return;
    }

    useLogStore.getState().togglePause();
  }, [commandState.canPauseResume]);

  const refreshActiveSource = useCallback(async () => {
    if (!commandState.canRefresh) {
      return;
    }

    if (activeWorkspace === "dsregcmd") {
      await refreshCurrentDsregcmdSource();
      return;
    }

    if (activeWorkspace === "sysmon") {
      if (sysmonSourcePath) {
        const isLiveSource = sysmonSourcePath === "live-event-log";
        await getWorkspace("sysmon").onOpenSource!(
          isLiveSource
            ? {
                kind: "known",
                sourceId: LIVE_SYSMON_SOURCE_ID,
                defaultPath: sysmonSourcePath,
                pathKind: "folder",
              }
            : { kind: "file", path: sysmonSourcePath },
          "app-actions.refresh",
        );
      }
      return;
    }

    if (activeWorkspace !== "log" || !refreshSource) {
      return;
    }

    useUiStore.getState().ensureLogViewVisible("app-actions.refresh");
    useFilterStore.getState().clearFilter();

    await loadLogSource(refreshSource, {
      selectedFilePath: selectedSourceFilePath,
    });
  }, [
    activeWorkspace,
    commandState.canRefresh,
    refreshSource,
    selectedSourceFilePath,
    sysmonSourcePath,
  ]);

  const toggleSidebar = useCallback(() => {
    if (commandState.canToggleSidebar) {
      useUiStore.getState().toggleSidebar();
    }
  }, [commandState.canToggleSidebar]);

  const toggleDetailsPane = useCallback(() => {
    if (commandState.canToggleDetailsPane) {
      useUiStore.getState().toggleDetails();
    }
  }, [commandState.canToggleDetailsPane]);

  const toggleInfoPane = useCallback(() => {
    if (commandState.canToggleInfoPane) {
      useUiStore.getState().toggleInfoPane();
    }
  }, [commandState.canToggleInfoPane]);

  const switchWorkspace = useCallback(
    (workspace: WorkspaceId, trigger: string) => {
      useUiStore.getState().ensureWorkspaceVisible(workspace, trigger);
    },
    [],
  );

  const dismissTransientDialogs = useCallback((trigger: string) => {
    useUiStore.getState().closeTransientDialogs(trigger);
  }, []);

  return {
    commandState,
    openSourceFileDialog,
    openSourceFolderDialog,
    openPathForActiveWorkspace,
    openKnownSourceCatalogAction,
    openKnownSourceById,
    pasteDsregcmdSource,
    captureDsregcmdSource,
    showFindBar,
    findNext,
    findPrevious,
    showFilterDialog,
    showErrorLookupDialog,
    showAboutDialog,
    showSettingsDialog,
    showEvidenceBundleDialog,
    increaseLogListTextSize,
    decreaseLogListTextSize,
    resetLogListTextSize,
    togglePauseResume,
    refreshActiveSource,
    toggleSidebar,
    toggleDetailsPane,
    toggleInfoPane,
    switchWorkspace,
    dismissTransientDialogs,
  };
}
