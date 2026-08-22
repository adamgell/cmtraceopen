import { useCallback, useEffect, useLayoutEffect, useMemo, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getAvailableWorkspaces, useUiStore } from "../stores/ui-store";
import { useLogStore } from "../stores/log-store";
import { buildElevationRequest } from "../lib/elevation-request";
import type { WorkspaceId } from "../types/log";
import { useAppActions, type AppCommandState } from "./use-app-actions";

const MENU_EVENT_APP_ACTION = "app-menu-action";

let appMenuSyncQueue: Promise<void> = Promise.resolve();
let appMenuSyncWarningShown = false;
let alwaysOnTopUpdateQueue: Promise<void> = Promise.resolve();

function enqueueAlwaysOnTopUpdate(
  update: () => Promise<void>,
): Promise<void> {
  const nextUpdate = alwaysOnTopUpdateQueue.then(update);
  alwaysOnTopUpdateQueue = nextUpdate.catch(() => undefined);
  return nextUpdate;
}

interface AppMenuActionPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  source_id: string | null;
  target_id: string | null;
  path?: string;
  workspace?: WorkspaceId;
  kind?: "file" | "folder";
}

interface AppMenuState {
  activeWorkspace: WorkspaceId;
  openFileLabel: string;
  openFolderLabel: string;
  canOpenSources: boolean;
  canOpenKnownSources: boolean;
  canFind: boolean;
  hasFindSession: boolean;
  canFilter: boolean;
  canPauseResume: boolean;
  isPaused: boolean;
  canRefresh: boolean;
  canToggleSidebar: boolean;
  isSidebarVisible: boolean;
  canToggleDetailsPane: boolean;
  isDetailsVisible: boolean;
  canToggleInfoPane: boolean;
  isInfoPaneVisible: boolean;
  canAdjustTextSize: boolean;
  canShowEvidenceBundle: boolean;
  canSaveSession: boolean;
  canCollectDiagnostics: boolean;
}

function projectMenuState(commandState: AppCommandState): AppMenuState {
  return {
    activeWorkspace: commandState.activeWorkspace,
    openFileLabel: commandState.openFileLabel,
    openFolderLabel: commandState.openFolderLabel,
    canOpenSources: commandState.canOpenSources,
    canOpenKnownSources: commandState.canOpenKnownSources,
    canFind: commandState.canFind,
    hasFindSession: commandState.hasFindSession,
    canFilter: commandState.canFilter,
    canPauseResume: commandState.canPauseResume,
    isPaused: commandState.isPaused,
    canRefresh: commandState.canRefresh,
    canToggleSidebar: commandState.canToggleSidebar,
    isSidebarVisible: commandState.isSidebarVisible,
    canToggleDetailsPane: commandState.canToggleDetailsPane,
    isDetailsVisible: commandState.isDetailsVisible,
    canToggleInfoPane: commandState.canToggleInfoPane,
    isInfoPaneVisible: commandState.isInfoPaneVisible,
    canAdjustTextSize: commandState.canAdjustTextSize,
    canShowEvidenceBundle: commandState.canShowEvidenceBundle,
    canSaveSession: commandState.canSaveSession,
    canCollectDiagnostics: commandState.canCollectDiagnostics,
  };
}

export function useAppMenu() {
  const {
    commandState,
    openSourceFileDialog,
    openSourceFolderDialog,
    openKnownSourceCatalogAction,
    showFindBar,
    findNext,
    findPrevious,
    showFilterDialog,
    showErrorLookupDialog,
    showEvidenceBundleDialog,
    showAboutDialog,
    showSettingsDialog,
    togglePauseResume,
    refreshActiveSource,
    toggleSidebar,
    toggleDetailsPane,
    toggleInfoPane,
    increaseLogListTextSize,
    decreaseLogListTextSize,
    resetLogListTextSize,
    switchWorkspace,
    openRecentEntry,
  } = useAppActions();

  const menuState = useMemo(
    () => projectMenuState(commandState),
    [
      commandState.activeWorkspace,
      commandState.canAdjustTextSize,
      commandState.canCollectDiagnostics,
      commandState.canFilter,
      commandState.canFind,
      commandState.canOpenKnownSources,
      commandState.canOpenSources,
      commandState.canPauseResume,
      commandState.canRefresh,
      commandState.canSaveSession,
      commandState.canShowEvidenceBundle,
      commandState.canToggleDetailsPane,
      commandState.canToggleInfoPane,
      commandState.canToggleSidebar,
      commandState.hasFindSession,
      commandState.isDetailsVisible,
      commandState.isInfoPaneVisible,
      commandState.isPaused,
      commandState.isSidebarVisible,
      commandState.openFileLabel,
      commandState.openFolderLabel,
    ],
  );
  const latestMenuStateRef = useRef(menuState);
  const syncActiveRef = useRef(true);
  latestMenuStateRef.current = menuState;

  const enqueueMenuSync = useCallback((state: AppMenuState): Promise<void> => {
    const nextSync = appMenuSyncQueue.then(async () => {
      if (!syncActiveRef.current) {
        return;
      }

      try {
        await invoke("sync_app_menu_state", { state });
        appMenuSyncWarningShown = false;
      } catch (error) {
        if (!appMenuSyncWarningShown) {
          console.warn("[app-menu] failed to synchronize native menu state", {
            error,
          });
          appMenuSyncWarningShown = true;
        }
      }
    });

    appMenuSyncQueue = nextSync;
    return nextSync;
  }, []);

  useEffect(() => {
    syncActiveRef.current = true;

    return () => {
      syncActiveRef.current = false;
    };
  }, []);

  useEffect(() => {
    void enqueueMenuSync(menuState);
  }, [enqueueMenuSync, menuState]);

  const latestMenuActionHandlerRef = useRef<
    (payload: AppMenuActionPayload) => Promise<void>
  >(async () => undefined);
  useLayoutEffect(() => {
    latestMenuActionHandlerRef.current = async (payload) => {
      try {
        switch (payload.action) {
          case "open_log_file_dialog":
            await openSourceFileDialog();
            return;
          case "open_log_folder_dialog":
            await openSourceFolderDialog();
            return;
          case "show_find":
            showFindBar();
            return;
          case "find_next":
            findNext("native-menu.find-next");
            return;
          case "find_previous":
            findPrevious("native-menu.find-previous");
            return;
          case "show_filter":
            showFilterDialog();
            return;
          case "show_error_lookup":
            showErrorLookupDialog();
            return;
          case "show_evidence_bundle":
            showEvidenceBundleDialog();
            return;
          case "toggle_pause":
            togglePauseResume();
            return;
          case "refresh":
            await refreshActiveSource();
            return;
          case "toggle_sidebar":
            toggleSidebar();
            return;
          case "toggle_details":
            toggleDetailsPane();
            return;
          case "toggle_info_pane":
            toggleInfoPane();
            return;
          case "toggle_always_on_top": {
            const nextToggle = enqueueAlwaysOnTopUpdate(async () => {
              const next = !useUiStore.getState().alwaysOnTop;
              await invoke("set_always_on_top", { enabled: next });
              useUiStore.getState().setAlwaysOnTop(next);
            });
            await nextToggle;
            return;
          }
          case "increase_text_size":
            increaseLogListTextSize();
            return;
          case "decrease_text_size":
            decreaseLogListTextSize();
            return;
          case "reset_text_size":
            resetLogListTextSize();
            return;
          case "show_about":
            showAboutDialog();
            return;
          case "show_settings":
            showSettingsDialog();
            return;
          case "show_guid_registry":
            useUiStore.getState().setShowGuidRegistryDialog(true);
            return;
          case "collect_diagnostics":
            useUiStore.getState().setShowCollectDiagnosticsDialog(true);
            return;
          case "check_for_updates":
            useUiStore.getState().setShowUpdateDialog(true);
            return;
          case "save_session": {
            const { saveSession } = await import("../lib/session-save");
            await saveSession();
            return;
          }
          case "open_session": {
            const { openSessionDialog } = await import("../lib/session-restore");
            await openSessionDialog();
            return;
          }
          case "restart_as_administrator": {
            // Never replace a confirmation already on screen. Overwriting it
            // resets the dialog's submitting and failure state mid-flight, and
            // would let a menu click clobber an Access Denied recovery prompt
            // the user is part-way through. Matches the same guard in
            // offerElevationForSourceFailure.
            if (useUiStore.getState().elevationPrompt) return;

            // Confirm first: the backend is never called straight from a menu
            // click, so UAC can only appear after a second, deliberate action.
            const activeWorkspace = useUiStore.getState().activeWorkspace;
            useUiStore.getState().setElevationPrompt({
              request: buildElevationRequest({
                reason: "explicitMenu",
                workspace: activeWorkspace,
                // The active source rides along only when the user is actually
                // looking at it. `activeSource` survives a workspace switch, so
                // restarting from ESP or Intune would otherwise reopen whatever
                // log was last loaded instead of just the workspace on screen.
                source:
                  activeWorkspace === "log"
                    ? useLogStore.getState().activeSource
                    : null,
              }),
            });
            return;
          }
          case "switch_workspace": {
            const { currentPlatform, enabledWorkspaces } =
              useUiStore.getState();
            const targetWorkspace = getAvailableWorkspaces(
              currentPlatform,
              enabledWorkspaces,
            ).find((workspace) => workspace === payload.target_id);

            if (!targetWorkspace) {
              console.warn(
                "[app-menu] rejected unavailable workspace target",
                { payload, currentPlatform },
              );
              void enqueueMenuSync(latestMenuStateRef.current);
              return;
            }

            switchWorkspace(
              targetWorkspace,
              payload.trigger || "native-menu.workspace",
            );
            return;
          }
          case "open_recent_entry": {
            const { path, workspace, kind } = payload;

            if (!path || !workspace || !kind) {
              console.warn(
                "[app-menu] open_recent_entry missing resolved fields",
                { payload },
              );
              return;
            }

            const { currentPlatform, enabledWorkspaces } =
              useUiStore.getState();
            const targetWorkspace = getAvailableWorkspaces(
              currentPlatform,
              enabledWorkspaces,
            ).find((available) => available === workspace);

            if (!targetWorkspace) {
              console.warn("[app-menu] rejected unavailable recent workspace", {
                payload,
                currentPlatform,
              });
              return;
            }

            await openRecentEntry(
              path,
              kind,
              targetWorkspace,
              payload.trigger || "native-menu.recent",
            );
            return;
          }
          case "clear_recent_entries": {
            const { clearRecentEntries } = await import(
              "../lib/recent-entries"
            );
            await clearRecentEntries();
            return;
          }
          case "open_known_source": {
            if (payload.source_id) {
              await openKnownSourceCatalogAction({
                sourceId: payload.source_id,
                trigger: payload.trigger || "native-menu.known-source",
              });
            } else {
              console.warn("[app-menu] open_known_source received without source_id", { payload });
            }
            return;
          }
          case "timeline_new_from_folder": {
            const { open: openDialog } = await import("@tauri-apps/plugin-dialog");
            const folder = await openDialog({ directory: true });
            if (!folder || Array.isArray(folder)) return;
            const folderPath = folder as string;
            try {
              const { replaceTimelineSource } = await import(
                "../workspaces/timeline/open-timeline-source"
              );
              useUiStore.getState().ensureWorkspaceVisible(
                "timeline",
                "native-menu.timeline-new-from-folder",
              );
              await replaceTimelineSource({ kind: "folder", path: folderPath });
            } catch (error) {
              console.error("[app-menu] failed to build timeline from folder", {
                folderPath,
                error,
              });
              const { useTimelineStore } = await import(
                "../stores/timeline-store"
              );
              useTimelineStore.getState().setLoadError(
                error instanceof Error ? error.message : String(error),
              );
            }
            return;
          }
          case "timeline_new_empty": {
            const { useTimelineStore } = await import("../stores/timeline-store");
            useTimelineStore.getState().setBundle(null);
            useUiStore.getState().ensureWorkspaceVisible("timeline", "native-menu.timeline-new-empty");
            return;
          }
          default:
            console.warn("[app-menu] unhandled native menu action", { payload });
        }
      } catch (error) {
        console.error("[app-menu] failed to handle native menu action", {
          payload,
          error,
        });
      }
    };
  });

  useEffect(() => {
    let active = true;

    const unlistenActionPromise = listen<AppMenuActionPayload>(
      MENU_EVENT_APP_ACTION,
      async (event) => {
        if (!active) {
          return;
        }
        await latestMenuActionHandlerRef.current(event.payload);
      }
    );

    return () => {
      active = false;

      unlistenActionPromise
        .then((unlisten) => unlisten())
        .catch((error) => {
          console.error("[app-menu] failed to clean up menu action listener", {
            error,
          });
        });
    };
  }, []);

  // Re-apply the persisted "Always on Top" preference on startup so the window
  // and the native menu checkmark reflect the restored state. Only the enabled
  // case needs syncing: a freshly launched window starts un-pinned and the
  // CheckMenuItem is built unchecked, so the disabled case already matches the
  // native defaults.
  useEffect(() => {
    if (!useUiStore.getState().alwaysOnTop) {
      return;
    }

    void enqueueAlwaysOnTopUpdate(async () => {
      try {
        await invoke("set_always_on_top", { enabled: true });
      } catch (error) {
        console.error(
          "[app-menu] failed to apply always-on-top on startup",
          error,
        );
      }
    });
  }, []);
}
