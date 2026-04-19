import { useEffect } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useAppActions } from "../components/layout/Toolbar";
import { loadFilesAsLogSource } from "../lib/log-source";
import { useUiStore } from "../stores/ui-store";
import { isTauri } from "../lib/runtime";

/**
 * Hook that handles file/folder drag-and-drop onto the application window.
 * Single file/folder drops route through the active workspace's source-loading flow.
 * Multiple file drops merge into an aggregate log view (log workspace only).
 *
 * In WASM/browser mode, OS drag-drop is not available via Tauri; the browser's
 * native dragover/drop events can be handled separately if needed in future.
 */
export function useDragDrop() {
  const { openPathForActiveWorkspace } = useAppActions();

  useEffect(() => {
    if (!isTauri) return; // Tauri drag-drop API not available in browser mode
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
          const activeWorkspace = useUiStore.getState().activeWorkspace;
          if (activeWorkspace === "log") {
            await loadFilesAsLogSource(paths);
          } else {
            // Non-log workspaces don't support multi-file; open the first path
            await openPathForActiveWorkspace(paths[0]);
          }
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
