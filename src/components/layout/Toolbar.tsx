import {
  startTransition,
  useCallback,
  useEffect,
  useMemo,
} from "react";
import {
  Button,
  Divider,
  Dropdown,
  Input,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  Option,
  tokens,
} from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { platform } from "@tauri-apps/plugin-os";
import {
  analyzeIntuneLogs,
  analyzeSysmonLogs,
  getAvailableWorkspaces as getAvailableBackendWorkspaces,
  inspectPathKind,
} from "../../lib/commands";
import {
  analyzeDsregcmdPath,
  analyzeDsregcmdSource,
  refreshCurrentDsregcmdSource,
} from "../../lib/dsregcmd-source";
import { useLogStore } from "../../stores/log-store";
import { useFilterStore } from "../../stores/filter-store";
import { useIntuneStore } from "../../stores/intune-store";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import { useSysmonStore } from "../../stores/sysmon-store";
import { isIntuneWorkspace, getAvailableWorkspaces, type IntuneWorkspaceId, type WorkspaceId, type PlatformId, useUiStore } from "../../stores/ui-store";
import { ThemePicker } from "./ThemePicker";
import {
  getLogSourcePath,
  getKnownSourceMetadataById,
  loadLogSource,
  loadPathAsLogSource,
  refreshKnownLogSources,
  resolveKnownSourceIdFromCatalogAction,
  type KnownSourceCatalogActionIds,
} from "../../lib/log-source";
import type { LogSource } from "../../types/log";

function normalizeDialogSelection(
  selected: string | string[] | null
): string | null {
  if (!selected) {
    return null;
  }

  return Array.isArray(selected) ? selected[0] ?? null : selected;
}

function resolveRefreshSource(
  activeSource: LogSource | null,
  openFilePath: string | null
): LogSource | null {
  if (activeSource) {
    return activeSource;
  }

  if (openFilePath) {
    return { kind: "file", path: openFilePath };
  }

  return null;
}

const LOG_FILE_DIALOG_FILTERS = [
  { name: "Log Files", extensions: ["log"] },
  { name: "Old Log Files", extensions: ["lo_"] },
  { name: "Registry Files", extensions: ["reg"] },
  { name: "All Files", extensions: ["*"] },
];

const INTUNE_FILE_DIALOG_FILTERS = [
  { name: "Intune IME Logs", extensions: ["log"] },
  { name: "All Files", extensions: ["*"] },
];

const DSREGCMD_FILE_DIALOG_FILTERS = [
  { name: "Text Files", extensions: ["txt"] },
  { name: "Log Files", extensions: ["log"] },
  { name: "All Files", extensions: ["*"] },
];

const LIVE_INTUNE_SOURCE_ID = "windows-intune-ime-logs";
const LIVE_SYSMON_SOURCE_ID = "windows-sysmon-live-events";

const WORKSPACE_LABELS: Record<WorkspaceId, string> = {
  log: "Log Explorer",
  intune: "Intune Diagnostics",
  "new-intune": "New Intune Workspace",
  dsregcmd: "dsregcmd",
  "macos-diag": "macOS Diagnostics",
  deployment: "Software Deployment",
  "event-log": "Event Log Viewer",
  sysmon: "Sysmon",
};

const SYSMON_FILE_DIALOG_FILTERS = [
  { name: "EVTX Files", extensions: ["evtx"] },
  { name: "All Files", extensions: ["*"] },
];

function getOpenFileDialogFilters(workspace: WorkspaceId) {
  if (isIntuneWorkspace(workspace)) {
    return INTUNE_FILE_DIALOG_FILTERS;
  }

  if (workspace === "dsregcmd") {
    return DSREGCMD_FILE_DIALOG_FILTERS;
  }

  if (workspace === "sysmon") {
    return SYSMON_FILE_DIALOG_FILTERS;
  }

  return LOG_FILE_DIALOG_FILTERS;
}

function getOpenActionLabels(workspace: WorkspaceId) {
  if (workspace === "dsregcmd") {
    return {
      file: "Open Text File",
      folder: "Open Evidence Folder",
      openPlaceholder: "Open dsregcmd Source...",
    };
  }

  if (isIntuneWorkspace(workspace)) {
    return {
      file: "Open IME Log File",
      folder: "Open IME Or Evidence Folder",
      openPlaceholder: "Open Intune Source...",
    };
  }

  if (workspace === "sysmon") {
    return {
      file: "Open EVTX File",
      folder: "Open EVTX Folder",
      openPlaceholder: "Open Sysmon Source...",
    };
  }

  return {
    file: "Open File",
    folder: "Open Folder",
    openPlaceholder: "Open...",
  };
}

async function inferPathKind(path: string): Promise<"file" | "folder" | "unknown"> {
  try {
    return await inspectPathKind(path);
  } catch {
    return "unknown";
  }
}

function createIntuneAnalysisRequestId(): string {
  return `intune-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function shouldSyncSourceBeforeIntuneAnalysis(source: LogSource): boolean {
  if (source.kind === "file") {
    return true;
  }

  return source.kind === "known" && source.pathKind === "file";
}

function shouldIncludeLiveEventLogs(source: LogSource): boolean {
  return source.kind === "known" && source.sourceId === LIVE_INTUNE_SOURCE_ID;
}

function shouldIncludeSysmonLiveEventLogs(source: LogSource): boolean {
  return source.kind === "known" && source.sourceId === LIVE_SYSMON_SOURCE_ID;
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
  canFilter: boolean;
  canRefresh: boolean;
  canToggleDetailsPane: boolean;
  canToggleInfoPane: boolean;
  canShowEvidenceBundle: boolean;
  isLoading: boolean;
  isPaused: boolean;
  hasActiveSource: boolean;
  isDetailsVisible: boolean;
  isInfoPaneVisible: boolean;
  activeFilterCount: number;
  isFiltering: boolean;
  filterError: string | null;
  activeView: WorkspaceId;
}

export interface AppActionHandlers {
  commandState: AppCommandState;
  openSourceFileDialog: () => Promise<void>;
  openSourceFolderDialog: () => Promise<void>;
  openPathForActiveWorkspace: (path: string) => Promise<void>;
  openKnownSourceCatalogAction: (
    action: OpenKnownSourceCatalogAction
  ) => Promise<void>;
  openKnownSourceById: (sourceId: string, trigger: string) => Promise<void>;
  openKnownSourcePresetByMenuId: (presetMenuId: string) => Promise<void>;
  pasteDsregcmdSource: () => Promise<void>;
  captureDsregcmdSource: () => Promise<void>;
  showFindBar: () => void;
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
  toggleDetailsPane: () => void;
  toggleInfoPane: () => void;
  dismissTransientDialogs: (trigger: string) => void;
}


export function useAppActions(): AppActionHandlers {
  const isLoading = useLogStore((s) => s.isLoading);
  const isPaused = useLogStore((s) => s.isPaused);
  const entriesCount = useLogStore((s) => s.entries.length);
  const activeSource = useLogStore((s) => s.activeSource);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const selectedSourceFilePath = useLogStore((s) => s.selectedSourceFilePath);
  const bundleMetadata = useLogStore((s) => s.bundleMetadata);
  const intuneIsAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const intuneEvidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const beginIntuneAnalysis = useIntuneStore((s) => s.beginAnalysis);
  const failIntuneAnalysis = useIntuneStore((s) => s.failAnalysis);
  const setIntuneResults = useIntuneStore((s) => s.setResults);
  const dsregcmdIsAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const dsregcmdSource = useDsregcmdStore((s) => s.sourceContext.source);
  const dsregcmdBundlePath = useDsregcmdStore((s) => s.sourceContext.bundlePath);
  const sysmonIsAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const sysmonSourcePath = useSysmonStore((s) => s.sourcePath);
  const beginSysmonAnalysis = useSysmonStore((s) => s.beginAnalysis);
  const setSysmonResults = useSysmonStore((s) => s.setResults);
  const failSysmonAnalysis = useSysmonStore((s) => s.failAnalysis);

  const activeWorkspace = useUiStore((s) => s.activeWorkspace);
  const activeView = useUiStore((s) => s.activeView);
  const showDetails = useUiStore((s) => s.showDetails);
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const setShowFindBar = useUiStore((s) => s.setShowFindBar);
  const setShowFilterDialog = useUiStore((s) => s.setShowFilterDialog);
  const setShowErrorLookupDialog = useUiStore(
    (s) => s.setShowErrorLookupDialog
  );
  const setShowAboutDialog = useUiStore((s) => s.setShowAboutDialog);
  const setShowSettingsDialog = useUiStore(
    (s) => s.setShowSettingsDialog
  );
  const setShowEvidenceBundleDialog = useUiStore(
    (s) => s.setShowEvidenceBundleDialog
  );
  const increaseLogListFontSize = useUiStore(
    (s) => s.increaseLogListFontSize
  );
  const decreaseLogListFontSize = useUiStore(
    (s) => s.decreaseLogListFontSize
  );
  const resetLogListFontSize = useUiStore((s) => s.resetLogListFontSize);

  const activeFilterCount = useFilterStore((s) => s.clauses.length);
  const isFiltering = useFilterStore((s) => s.isFiltering);
  const filterError = useFilterStore((s) => s.filterError);

  const refreshSource = useMemo(
    () => resolveRefreshSource(activeSource, openFilePath),
    [activeSource, openFilePath]
  );
  const isSourceCommandBusy = isLoading || intuneIsAnalyzing || dsregcmdIsAnalyzing || sysmonIsAnalyzing;

  const commandState = useMemo<AppCommandState>(
    () => ({
      canOpenSources: !isSourceCommandBusy,
      canOpenKnownSources:
        !isSourceCommandBusy && activeWorkspace !== "dsregcmd",
      canPauseResume:
        activeWorkspace === "log" && !isLoading && refreshSource !== null,
      canFind: activeWorkspace === "log" && entriesCount > 0,
      canFilter:
        activeWorkspace === "log" && entriesCount > 0 && !isFiltering,
      canRefresh:
        !isSourceCommandBusy &&
        (activeWorkspace === "dsregcmd"
          ? dsregcmdSource !== null
          : activeWorkspace === "sysmon"
            ? sysmonSourcePath !== null
            : refreshSource !== null),
      canToggleDetailsPane: activeView === "log",
      canToggleInfoPane: activeView === "log",
      canShowEvidenceBundle:
        activeView === "log"
          ? bundleMetadata !== null
          : isIntuneWorkspace(activeView)
            ? intuneEvidenceBundle !== null
            : dsregcmdBundlePath !== null,
      isLoading: isSourceCommandBusy,
      isPaused,
      hasActiveSource:
        activeWorkspace === "dsregcmd"
          ? dsregcmdSource !== null
          : activeWorkspace === "sysmon"
            ? sysmonSourcePath !== null
            : refreshSource !== null,
      isDetailsVisible: showDetails,
      isInfoPaneVisible: showInfoPane,
      activeFilterCount,
      isFiltering,
      filterError,
      activeView,
    }),
    [
      activeWorkspace,
      activeFilterCount,
      activeView,
      bundleMetadata,
      dsregcmdBundlePath,
      dsregcmdSource,
      entriesCount,
      filterError,
      intuneEvidenceBundle,
      intuneIsAnalyzing,
      isFiltering,
      isLoading,
      isPaused,
      isSourceCommandBusy,
      refreshSource,
      showDetails,
      showInfoPane,
      sysmonSourcePath,
    ]
  );

  const loadLogWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string) => {
      // Don't switch away from deployment workspace — it shows logs too
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
    []
  );

  const analyzeIntuneWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string, workspace: IntuneWorkspaceId) => {
      useUiStore.getState().ensureWorkspaceVisible(workspace, trigger);
      const requestId = createIntuneAnalysisRequestId();
      beginIntuneAnalysis(
        getLogSourcePath(source),
        source.kind === "known" ? "known" : source.kind,
        requestId
      );

      try {
        if (shouldSyncSourceBeforeIntuneAnalysis(source)) {
          await loadLogSource(source).catch((error) => {
            console.warn("[app-actions] failed to sync source before Intune analysis", {
              source,
              trigger,
              error,
            });
          });
        }

        const result = await analyzeIntuneLogs(getLogSourcePath(source), requestId, {
          includeLiveEventLogs: shouldIncludeLiveEventLogs(source),
        });

        startTransition(() => {
          setIntuneResults(
            result.events,
            result.downloads,
            result.summary,
            result.diagnostics,
            result.sourceFile,
            result.sourceFiles,
            {
              diagnosticsConfidence: result.diagnosticsConfidence,
              diagnosticsCoverage: result.diagnosticsCoverage,
              repeatedFailures: result.repeatedFailures,
              evidenceBundle: result.evidenceBundle ?? null,
              eventLogAnalysis: result.eventLogAnalysis ?? null,
              policyMetadata: result.policyMetadata ?? undefined,
              guidRegistry: result.guidRegistry,
            }
          );
        });
      } catch (error) {
        console.error("[app-actions] failed to analyze Intune source", {
          source,
          trigger,
          error,
        });
        failIntuneAnalysis(error);
      }
    },
    [beginIntuneAnalysis, failIntuneAnalysis, setIntuneResults]
  );

  const analyzeDsregcmdWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string) => {
      useUiStore.getState().ensureWorkspaceVisible("dsregcmd", trigger);

      if (source.kind === "known") {
        throw new Error("Known log presets are not supported in the dsregcmd workspace.");
      }

      await analyzeDsregcmdSource(source);
    },
    []
  );

  const analyzeSysmonWorkspaceSource = useCallback(
    async (source: LogSource, trigger: string) => {
      useUiStore.getState().ensureWorkspaceVisible("sysmon", trigger);
      const sourcePath = getLogSourcePath(source);
      const requestId = `sysmon-${Date.now()}`;
      beginSysmonAnalysis(sourcePath, requestId);

      try {
        const result = await analyzeSysmonLogs(sourcePath, requestId, {
          includeLiveEventLogs: shouldIncludeSysmonLiveEventLogs(source),
        });
        startTransition(() => {
          setSysmonResults(result);
        });
      } catch (error) {
        console.error("[app-actions] failed to analyze Sysmon source", {
          source,
          trigger,
          error,
        });
        failSysmonAnalysis(error instanceof Error ? error.message : String(error));
      }
    },
    [beginSysmonAnalysis, setSysmonResults, failSysmonAnalysis]
  );

  const openSourceForWorkspace = useCallback(
    async (source: LogSource, trigger: string, workspace: WorkspaceId) => {
      if (isIntuneWorkspace(workspace)) {
        await analyzeIntuneWorkspaceSource(source, trigger, workspace);
        return;
      }

      if (workspace === "dsregcmd") {
        await analyzeDsregcmdWorkspaceSource(source, trigger);
        return;
      }

      if (workspace === "sysmon") {
        await analyzeSysmonWorkspaceSource(source, trigger);
        return;
      }

      if (workspace === "deployment") {
        // Extract folder path from source
        const folderPath =
          source.kind === "folder"
            ? source.path
            : source.kind === "known"
              ? source.defaultPath
              : null;
        if (folderPath) {
          const { useDeploymentStore } = await import("../../stores/deployment-store");
          await useDeploymentStore.getState().analyzeFolder(folderPath);
          return;
        }
      }

      await loadLogWorkspaceSource(source, trigger);
    },
    [
      analyzeDsregcmdWorkspaceSource,
      analyzeIntuneWorkspaceSource,
      analyzeSysmonWorkspaceSource,
      loadLogWorkspaceSource,
    ]
  );

  const openPathForActiveWorkspace = useCallback(
    async (path: string) => {
      if (activeWorkspace === "dsregcmd") {
        useUiStore.getState().ensureWorkspaceVisible("dsregcmd", "drag-drop.path-open");
        await analyzeDsregcmdPath(path, { fallbackToFolder: true });
        return;
      }

      if (isIntuneWorkspace(activeWorkspace)) {
        const pathKind = await inferPathKind(path);
        const source: LogSource =
          pathKind === "folder"
            ? { kind: "folder", path }
            : { kind: "file", path };
        await analyzeIntuneWorkspaceSource(source, "drag-drop.path-open", activeWorkspace);
        return;
      }

      if (activeWorkspace === "deployment") {
        const { useDeploymentStore } = await import("../../stores/deployment-store");
        await useDeploymentStore.getState().analyzeFolder(path);
        return;
      }

      useUiStore.getState().ensureLogViewVisible("drag-drop.path-open");
      useFilterStore.getState().clearFilter();
      await loadPathAsLogSource(path, {
        fallbackToFolder: true,
      });
    },
    [activeWorkspace, analyzeIntuneWorkspaceSource]
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
        throw new Error("Known source presets are not available in the dsregcmd workspace.");
      }

      const metadata = await getKnownSourceMetadataById(sourceId);

      if (!metadata) {
        throw new Error(
          `[app-actions] known source metadata was not found for id '${sourceId}'`
        );
      }

      const targetWorkspace: WorkspaceId = activeWorkspace;

      await openSourceForWorkspace(
        metadata.source,
        action.trigger,
        targetWorkspace
      );
    },
    [activeWorkspace, openSourceForWorkspace]
  );

  const openSourceFileDialog = useCallback(async () => {
    if (!commandState.canOpenSources) {
      return;
    }

    const isLogWorkspace = activeWorkspace === "log";

    const selected = await open({
      multiple: isLogWorkspace,
      filters: getOpenFileDialogFilters(activeWorkspace),
    });

    if (!selected) return;

    // Normalize: open() returns string | string[] | null depending on multiple flag
    const paths = Array.isArray(selected) ? selected : [selected];
    if (paths.length === 0) return;

    if (paths.length === 1) {
      await openSourceForWorkspace(
        { kind: "file", path: paths[0] },
        "app-actions.open-file",
        activeWorkspace
      );
    } else {
      const { loadFilesAsLogSource } = await import("../../lib/log-source");
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
      activeWorkspace
    );
  }, [activeWorkspace, commandState.canOpenSources, openSourceForWorkspace]);

  const openKnownSourceById = useCallback(
    async (sourceId: string, trigger: string) => {
      await openKnownSourceCatalogAction({
        sourceId,
        trigger,
      });
    },
    [openKnownSourceCatalogAction]
  );

  const openKnownSourcePresetByMenuId = useCallback(
    async (presetMenuId: string) => {
      await openKnownSourceCatalogAction({
        presetMenuId,
        trigger: "native-menu.log-preset-selected",
      });
    },
    [openKnownSourceCatalogAction]
  );

  const pasteDsregcmdSource = useCallback(async () => {
    if (isSourceCommandBusy) {
      return;
    }

    useUiStore.getState().ensureWorkspaceVisible("dsregcmd", "app-actions.dsregcmd-paste");
    await analyzeDsregcmdSource({ kind: "clipboard" });
  }, [isSourceCommandBusy]);

  const captureDsregcmdSource = useCallback(async () => {
    if (isSourceCommandBusy) {
      return;
    }

    useUiStore.getState().ensureWorkspaceVisible("dsregcmd", "app-actions.dsregcmd-capture");
    await analyzeDsregcmdSource({ kind: "capture" });
  }, [isSourceCommandBusy]);

  const showFindBar = useCallback(() => {
    if (!commandState.canFind) {
      return;
    }

    useUiStore.getState().ensureLogViewVisible("app-actions.show-find");
    setShowFindBar(true);
  }, [commandState.canFind, setShowFindBar]);

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
    const canShowForView =
      activeView === "log"
        ? bundleMetadata !== null
        : isIntuneWorkspace(activeView)
          ? intuneEvidenceBundle !== null
          : dsregcmdBundlePath !== null;

    if (!canShowForView) {
      return;
    }

    setShowEvidenceBundleDialog(true);
  }, [
    activeView,
    bundleMetadata,
    dsregcmdBundlePath,
    intuneEvidenceBundle,
    setShowEvidenceBundleDialog,
  ]);

  const increaseLogListTextSize = useCallback(() => {
    increaseLogListFontSize();
  }, [increaseLogListFontSize]);

  const decreaseLogListTextSize = useCallback(() => {
    decreaseLogListFontSize();
  }, [decreaseLogListFontSize]);

  const resetLogListTextSize = useCallback(() => {
    resetLogListFontSize();
  }, [resetLogListFontSize]);

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
        await analyzeSysmonWorkspaceSource(
          isLiveSource
            ? { kind: "known", sourceId: LIVE_SYSMON_SOURCE_ID, defaultPath: sysmonSourcePath, pathKind: "folder" }
            : { kind: "file", path: sysmonSourcePath },
          "app-actions.refresh"
        );
      }
      return;
    }

    if (!refreshSource) {
      return;
    }

    if (isIntuneWorkspace(activeWorkspace)) {
      await analyzeIntuneWorkspaceSource(refreshSource, "app-actions.refresh", activeWorkspace);
      return;
    }

    useUiStore.getState().ensureLogViewVisible("app-actions.refresh");
    useFilterStore.getState().clearFilter();

    await loadLogSource(refreshSource, {
      selectedFilePath: selectedSourceFilePath,
    });
  }, [
    activeWorkspace,
    analyzeIntuneWorkspaceSource,
    analyzeSysmonWorkspaceSource,
    commandState.canRefresh,
    refreshSource,
    selectedSourceFilePath,
    sysmonSourcePath,
  ]);

  const toggleDetailsPane = useCallback(() => {
    if (!commandState.canToggleDetailsPane) {
      return;
    }

    useUiStore.getState().toggleDetails();
  }, [commandState.canToggleDetailsPane]);

  const toggleInfoPane = useCallback(() => {
    if (!commandState.canToggleInfoPane) {
      return;
    }

    useUiStore.getState().toggleInfoPane();
  }, [commandState.canToggleInfoPane]);

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
    openKnownSourcePresetByMenuId,
    pasteDsregcmdSource,
    captureDsregcmdSource,
    showFindBar,
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
    toggleDetailsPane,
    toggleInfoPane,
    dismissTransientDialogs,
  };
}

export function Toolbar() {
  const highlightText = useLogStore((s) => s.highlightText);
  const setHighlightText = useLogStore((s) => s.setHighlightText);
  const knownSourceToolbarFamilies = useLogStore((s) => s.knownSourceToolbarFamilies);

  const activeView = useUiStore((s) => s.activeView);
  const setActiveView = useUiStore((s) => s.setActiveView);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const enabledWorkspaces = useUiStore((s) => s.enabledWorkspaces);
  const availableWorkspaces = useMemo(
    () => getAvailableWorkspaces(currentPlatform, enabledWorkspaces),
    [currentPlatform, enabledWorkspaces]
  );

  const {
    commandState,
    openSourceFileDialog,
    openSourceFolderDialog,
    openKnownSourceCatalogAction,
    pasteDsregcmdSource,
    captureDsregcmdSource,
    showErrorLookupDialog,
    toggleDetailsPane,
    toggleInfoPane,
  } = useAppActions();


  useEffect(() => {
    refreshKnownLogSources().catch((error) => {
      console.warn("[toolbar] failed to refresh known sources", { error });
    });

    let disposed = false;

    void getAvailableBackendWorkspaces()
      .then((workspaces) => {
        if (disposed) {
          return;
        }

        const store = useUiStore.getState();
        store.setEnabledWorkspaces(workspaces);
      })
      .catch((error) => {
        console.warn("[toolbar] failed to load build workspace availability", {
          error,
        });
      });

    try {
      const p = platform();
      const mapped: PlatformId = p === "macos" ? "macos" : p === "windows" ? "windows" : "linux";
      const store = useUiStore.getState();
      store.setCurrentPlatform(mapped);
      const available = getAvailableWorkspaces(mapped, store.enabledWorkspaces);
      if (!available.includes(store.activeWorkspace)) {
        store.setActiveWorkspace("log");
      }
    } catch (error) {
      console.warn("[toolbar] failed to detect platform", { error });
    }

    return () => {
      disposed = true;
    };
  }, []);

  const openLabels = useMemo(
    () => getOpenActionLabels(activeView),
    [activeView]
  );


  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: "10px",
        padding: "10px 12px",
        backgroundColor: tokens.colorNeutralBackground2,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        flexShrink: 0,
      }}
    >
      <Menu>
        <MenuTrigger disableButtonEnhancement>
          <Button
            size="small"
            disabled={!commandState.canOpenSources}
            title={openLabels.openPlaceholder}
          >
            {openLabels.openPlaceholder}
          </Button>
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            <MenuItem onClick={() => void openSourceFileDialog().catch((err) => console.error("Failed to open file dialog", err))}>
              {openLabels.file}
            </MenuItem>
            <MenuItem onClick={() => void openSourceFolderDialog().catch((err) => console.error("Failed to open folder dialog", err))}>
              {openLabels.folder}
            </MenuItem>
            {activeView === "dsregcmd" && (
              <>
                <MenuItem onClick={() => void pasteDsregcmdSource().catch((err) => console.error("Failed to paste dsregcmd source", err))}>
                  Paste Clipboard
                </MenuItem>
                <MenuItem onClick={() => void captureDsregcmdSource().catch((err) => console.error("Failed to capture dsregcmd source", err))}>
                  Capture Live Output
                </MenuItem>
              </>
            )}
          </MenuList>
        </MenuPopover>
      </Menu>
      <Menu>
        <MenuTrigger disableButtonEnhancement>
          <Button
            size="small"
            disabled={
              !commandState.canOpenKnownSources ||
              knownSourceToolbarFamilies.length === 0
            }
            title="Open a known log source"
          >
            {commandState.canOpenKnownSources
              ? knownSourceToolbarFamilies.length > 0
                ? isIntuneWorkspace(activeView)
                  ? "Open Known Intune Source..."
                  : "Open Known Log Source..."
                : "No Known Log Sources"
              : "Known Sources Unavailable"}
          </Button>
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            {knownSourceToolbarFamilies.map((family) => (
              <Menu key={family.id}>
                <MenuTrigger disableButtonEnhancement>
                  <MenuItem>{family.label}</MenuItem>
                </MenuTrigger>
                <MenuPopover>
                  <MenuList>
                    {family.groups.map((group) => (
                      <Menu key={group.id}>
                        <MenuTrigger disableButtonEnhancement>
                          <MenuItem>{group.label}</MenuItem>
                        </MenuTrigger>
                        <MenuPopover>
                          <MenuList>
                            {group.sources.map((source) => (
                              <MenuItem
                                key={source.id}
                                title={source.description}
                                onClick={() =>
                                  void openKnownSourceCatalogAction({
                                    sourceId: source.id,
                                    trigger: "toolbar.known-source-select",
                                  }).catch((err) =>
                                    console.error(
                                      "Failed to open known source catalog action",
                                      err
                                    )
                                  )
                                }
                              >
                                {source.label}
                              </MenuItem>
                            ))}
                          </MenuList>
                        </MenuPopover>
                      </Menu>
                    ))}
                  </MenuList>
                </MenuPopover>
              </Menu>
            ))}
          </MenuList>
        </MenuPopover>
      </Menu>

      <Divider vertical />

      <Input
        value={highlightText}
        onChange={(e) => setHighlightText(e.target.value)}
        placeholder="Highlight..."
        disabled={commandState.activeView !== "log"}
        size="small"
        style={{
          width: "200px",
          minWidth: "120px",
        }}
      />

      <Divider vertical />

      <Button
        onClick={showErrorLookupDialog}
        title="Error Lookup (Ctrl+E)"
        size="small"
        appearance="secondary"
      >
        Error Lookup
      </Button>

      <Divider vertical />

      <Button
        onClick={toggleDetailsPane}
        title="Show / Hide Details (Ctrl+H)"
        disabled={!commandState.canToggleDetailsPane}
        aria-pressed={commandState.isDetailsVisible}
        size="small"
        appearance={commandState.isDetailsVisible ? "primary" : "secondary"}
      >
        Details
      </Button>
      <Button
        onClick={toggleInfoPane}
        title="Toggle Info Pane"
        disabled={!commandState.canToggleInfoPane}
        aria-pressed={commandState.isInfoPaneVisible}
        size="small"
        appearance={commandState.isInfoPaneVisible ? "primary" : "secondary"}
      >
        Info
      </Button>

      {enabledWorkspaces !== null && availableWorkspaces.length > 1 && (
        <>
          <Divider vertical />

          <label
            style={{
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
              whiteSpace: "nowrap",
            }}
          >
            Workspace:
          </label>
          <Dropdown
            value={WORKSPACE_LABELS[activeView]}
            selectedOptions={[activeView]}
            onOptionSelect={(_e, data) => {
              if (data.optionValue) {
                setActiveView(data.optionValue as WorkspaceId);
              }
            }}
            size="small"
            style={{ minWidth: "180px" }}
            aria-label="Workspace"
          >
            {availableWorkspaces.map((wsId) => (
              <Option key={wsId} value={wsId}>{WORKSPACE_LABELS[wsId]}</Option>
            ))}
          </Dropdown>
        </>
      )}

      <div style={{ flex: 1 }} />

      <ThemePicker />
    </div>
  );
}
