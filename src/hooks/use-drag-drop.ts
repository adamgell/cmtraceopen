import { useEffect } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useAppActions } from "../components/layout/Toolbar";

/**
 * Hook that handles file/folder drag-and-drop onto the application window.
 * It routes dropped paths through the active workspace's source-loading flow.
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

      const droppedPath = paths[0];

      try {
        await openPathForActiveWorkspace(droppedPath);
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
  }, [openPathForActiveWorkspace]);
}
