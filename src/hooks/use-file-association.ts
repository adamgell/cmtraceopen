import { useEffect } from "react";
import { getInitialFilePaths } from "../lib/commands";
import { loadPathAsLogSource, loadFilesAsLogSource } from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";

/**
 * Hook that handles file paths passed via OS file association at app startup.
 *
 * When the user opens `.log` files with CMTrace Open (e.g. by selecting
 * multiple files and choosing "Open with"), the OS launches the application
 * with the file paths as CLI arguments. This hook retrieves those paths on
 * mount and routes them through the appropriate loading flow — single-file
 * for one path, aggregate merge for multiple.
 */
export function useFileAssociation() {
  const clearFilter = useFilterStore((s) => s.clearFilter);

  useEffect(() => {
    getInitialFilePaths()
      .then(async (paths) => {
        if (paths.length === 0) {
          return;
        }

        useUiStore.getState().ensureLogViewVisible("file-association.path-open");
        clearFilter();

        if (paths.length === 1) {
          await loadPathAsLogSource(paths[0], {
            fallbackToFolder: false,
          });
          return;
        }

        await loadFilesAsLogSource(paths);
      })
      .catch((error) => {
        console.error("[file-association] failed to open initial file paths", {
          error,
        });
      });
  }, [clearFilter]);
}
