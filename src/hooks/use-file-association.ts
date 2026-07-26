import { useEffect } from "react";
import { getInitialFilePaths, getInitialWorkspace } from "../lib/commands";
import { loadPathAsLogSource, loadFilesAsLogSource } from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";

/**
 * Hook that handles validated launch intent at app startup.
 *
 * When the user opens `.log` files with CMTrace Open (e.g. by selecting
 * multiple files and choosing "Open with"), the OS launches the application
 * with the file paths as CLI arguments. This hook retrieves those paths on
 * mount and routes them through the appropriate loading flow — explicit file
 * opens take precedence, otherwise an administrator relaunch can return to
 * ESP Diagnostics.
 */
export function useFileAssociation() {
  const clearFilter = useFilterStore((s) => s.clearFilter);

  useEffect(() => {
    Promise.all([getInitialFilePaths(), getInitialWorkspace()])
      .then(async ([paths, workspace]) => {
        if (paths.length === 0) {
          if (workspace === "esp-diagnostics") {
            useUiStore
              .getState()
              .ensureWorkspaceVisible("esp-diagnostics", "startup.workspace");
          }
          return;
        }

        useUiStore
          .getState()
          .ensureLogViewVisible("file-association.path-open");
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
