import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppActions } from "../components/layout/Toolbar";
import { useUiStore } from "../stores/ui-store";

const MENU_EVENT_APP_ACTION = "app-menu-action";

interface AppMenuActionPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  source_id: string | null;
}

export function useAppMenu() {
  const {
    openSourceFileDialog,
    openSourceFolderDialog,
    openKnownSourceCatalogAction,
    showFindBar,
    showFilterDialog,
    showErrorLookupDialog,
    showEvidenceBundleDialog,
    showAboutDialog,
    showSettingsDialog,
    togglePauseResume,
    refreshActiveSource,
    toggleDetailsPane,
    toggleInfoPane,
  } = useAppActions();

  useEffect(() => {
    let disposed = false;

    const handleAction = async (payload: AppMenuActionPayload) => {
      if (disposed) {
        return;
      }

      console.info("[app-menu] handling native menu action", { payload });

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
          case "toggle_details":
            toggleDetailsPane();
            return;
          case "toggle_info_pane":
            toggleInfoPane();
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

    const unlistenActionPromise = listen<AppMenuActionPayload>(
      MENU_EVENT_APP_ACTION,
      async (event) => {
        await handleAction(event.payload);
      }
    );

    return () => {
      disposed = true;

      unlistenActionPromise
        .then((unlisten) => unlisten())
        .catch((error) => {
          console.error("[app-menu] failed to clean up menu action listener", {
            error,
          });
        });
    };
  }, [
    openKnownSourceCatalogAction,
    openSourceFileDialog,
    openSourceFolderDialog,
    refreshActiveSource,
    showSettingsDialog,
    showAboutDialog,
    showErrorLookupDialog,
    showEvidenceBundleDialog,
    showFilterDialog,
    showFindBar,
    toggleDetailsPane,
    toggleInfoPane,
    togglePauseResume,
  ]);
}
