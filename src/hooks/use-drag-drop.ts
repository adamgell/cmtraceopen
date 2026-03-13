import { useEffect } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { loadPathAsLogSource } from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";

/**
 * Hook that handles file/folder drag-and-drop onto the application window.
 * It routes dropped paths through the shared source-loading flow.
 */
export function useDragDrop() {
  const clearFilter = useFilterStore((s) => s.clearFilter);

  useEffect(() => {
    const appWindow = getCurrentWebviewWindow();

    const unlisten = appWindow.onDragDropEvent(async (event) => {
      if (event.payload.type !== "drop") {
        return;
      }

      const paths = event.payload.paths;
      if (paths.length === 0) {
        return;
      }

      const droppedPath = paths[0];

      useUiStore.getState().ensureLogViewVisible("drag-drop.path-open");
      clearFilter();

      try {
        await loadPathAsLogSource(droppedPath, {
          fallbackToFolder: true,
        });
      } catch (error) {
        console.error("[drag-drop] failed to open dropped path", {
          droppedPath,
          error,
        });
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [clearFilter]);
}
