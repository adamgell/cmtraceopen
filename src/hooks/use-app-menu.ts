import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppActions } from "../components/layout/Toolbar";

const MENU_EVENT_APP_ACTION = "app-menu-action";

interface AppMenuActionPayload {
  version: number;
  menu_id: string;
  action: string;
  category: string;
  trigger: string;
  preset_id: string | null;
  platform: string | null;
}

export function useAppMenu() {
  const {
    openSourceFileDialog,
    openSourceFolderDialog,
    openKnownSourceCatalogAction,
    showFindDialog,
    showFilterDialog,
    showErrorLookupDialog,
    showAboutDialog,
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
            showFindDialog();
            return;
          case "show_filter":
            showFilterDialog();
            return;
          case "show_error_lookup":
            showErrorLookupDialog();
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
          case "load_known_source_preset": {
            await openKnownSourceCatalogAction({
              presetMenuId: payload.preset_id,
              menuId: payload.menu_id,
              trigger: payload.trigger || "native-menu.log-preset-selected",
            });
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
    showAboutDialog,
    showErrorLookupDialog,
    showFilterDialog,
    showFindDialog,
    toggleDetailsPane,
    toggleInfoPane,
    togglePauseResume,
  ]);
}
