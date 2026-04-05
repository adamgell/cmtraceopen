import {
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
import { useIntuneStore } from "../../workspaces/intune/intune-store";
import { useDsregcmdStore } from "../../workspaces/dsregcmd/dsregcmd-store";
import { useSysmonStore } from "../../workspaces/sysmon/sysmon-store";
import { isIntuneWorkspace, getAvailableWorkspaces, type WorkspaceId, type PlatformId, useUiStore } from "../../stores/ui-store";
import { getWorkspace } from "../../workspaces/registry";
import { ThemePicker } from "./ThemePicker";
import {
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

const LIVE_SYSMON_SOURCE_ID = "windows-sysmon-live-events";

async function inferPathKind(path: string): Promise<"file" | "folder" | "unknown"> {
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
  const dsregcmdIsAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const dsregcmdSource = useDsregcmdStore((s) => s.sourceContext.source);
  const dsregcmdBundlePath = useDsregcmdStore((s) => s.sourceContext.bundlePath);
  const sysmonIsAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const sysmonSourcePath = useSysmonStore((s) => s.sourcePath);

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

  const commandState = useMemo<AppCommandState>(() => {
    const ws = getWorkspace(activeWorkspace);
    const wsCaps = ws.capabilities ?? {};
    return {
      canOpenSources: !isSourceCommandBusy,
      canOpenKnownSources: !isSourceCommandBusy && (wsCaps.knownSources ?? true),
      canPauseResume: (wsCaps.tailing ?? false) && !isLoading && refreshSource !== null,
      canFind: (wsCaps.findBar ?? false) && entriesCount > 0,
      canFilter: (wsCaps.findBar ?? false) && entriesCount > 0 && !isFiltering,
      canRefresh:
        !isSourceCommandBusy &&
        (activeWorkspace === "dsregcmd"
          ? dsregcmdSource !== null
          : activeWorkspace === "sysmon"
            ? sysmonSourcePath !== null
            : refreshSource !== null),
      canToggleDetailsPane: wsCaps.detailsPane ?? false,
      canToggleInfoPane: wsCaps.infoPane ?? false,
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
    };
  }, [
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
  ]);

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

  const openSourceForWorkspace = useCallback(
    async (source: LogSource, trigger: string, workspace: WorkspaceId) => {
      const ws = getWorkspace(workspace);
      if (ws.onOpenSource) {
        await ws.onOpenSource(source, trigger);
      } else {
        await loadLogWorkspaceSource(source, trigger);
      }
    },
    [loadLogWorkspaceSource],
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
        await getWorkspace(activeWorkspace).onOpenSource!(source, "drag-drop.path-open");
        return;
      }

      if (activeWorkspace === "deployment") {
        const { useDeploymentStore } = await import("../../workspaces/deployment/deployment-store");
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

    const activeWorkspaceDefinition = getWorkspace(activeWorkspace);
    const fileDialogFilters = activeWorkspaceDefinition.fileFilters ?? [
      { name: "Log Files", extensions: ["log", "txt", "csv", "json", "xml", "evtx"] },
      { name: "All Files", extensions: ["*"] },
    ];

    const selected = await open({
      multiple: isLogWorkspace,
      filters: fileDialogFilters,
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
        await getWorkspace("sysmon").onOpenSource!(
          isLiveSource
            ? { kind: "known", sourceId: LIVE_SYSMON_SOURCE_ID, defaultPath: sysmonSourcePath, pathKind: "folder" }
            : { kind: "file", path: sysmonSourcePath },
          "app-actions.refresh",
        );
      }
      return;
    }

    if (!refreshSource) {
      return;
    }

    if (isIntuneWorkspace(activeWorkspace)) {
      await getWorkspace(activeWorkspace).onOpenSource!(refreshSource, "app-actions.refresh");
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
  const activeWorkspace = useUiStore((s) => s.activeWorkspace);
  const openTabs = useUiStore((s) => s.openTabs);
  const setShowMergeTabsDialog = useUiStore((s) => s.setShowMergeTabsDialog);
  const setShowDiffConfigDialog = useUiStore((s) => s.setShowDiffConfigDialog);
  const enabledWorkspaces = useUiStore((s) => s.enabledWorkspaces);
  const availableWorkspaces = useMemo(
    () => getAvailableWorkspaces(currentPlatform, enabledWorkspaces),
    [currentPlatform, enabledWorkspaces]
  );

  const canMergeTabs = activeWorkspace === "log" && openTabs.length >= 2;

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

  const openLabels = useMemo(() => {
    const ws = getWorkspace(activeView);
    return ws.actionLabels ?? {
      file: "Open File",
      folder: "Open Folder",
      placeholder: "Open...",
    };
  }, [activeView]);


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
            title={openLabels.placeholder}
          >
            {openLabels.placeholder}
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

      {canMergeTabs && (
        <button
          type="button"
          onClick={() => setShowMergeTabsDialog(true)}
          title="Merge open tabs into a unified timeline"
          style={{
            fontSize: "12px",
            padding: "4px 10px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            backgroundColor: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          Merge Tabs...
        </button>
      )}
      {canMergeTabs && (
        <button
          type="button"
          onClick={() => setShowDiffConfigDialog(true)}
          title="Compare two open tabs"
          style={{
            fontSize: "12px",
            padding: "4px 10px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            backgroundColor: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          Diff Tabs...
        </button>
      )}

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
            value={getWorkspace(activeView).label}
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
              <Option key={wsId} value={wsId}>{getWorkspace(wsId).label}</Option>
            ))}
          </Dropdown>
        </>
      )}

      <div style={{ flex: 1 }} />

      <ThemePicker />
    </div>
  );
}
