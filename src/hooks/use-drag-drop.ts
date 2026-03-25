import { useEffect } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useAppActions } from "../components/layout/Toolbar";
import { loadFilesAsLogSource } from "../lib/log-source";

/**
 * Hook that handles file/folder drag-and-drop onto the application window.
 * Single file/folder drops route through the active workspace's source-loading flow.
 * Multiple file drops merge into an aggregate view.
 */
export function useDragDrop() {
  const { openPathForActiveWorkspace } = useAppActions();

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

      try {
        if (paths.length === 1) {
          await openPathForActiveWorkspace(paths[0]);
        } else {
          await loadFilesAsLogSource(paths);
        }
      } catch (error) {
        console.error("[drag-drop] failed to open dropped paths", {
          pathCount: paths.length,
          error,
        });
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [openPathForActiveWorkspace]);
}
