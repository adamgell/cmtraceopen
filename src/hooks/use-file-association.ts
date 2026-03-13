import { useEffect } from "react";
import { getInitialFilePath } from "../lib/commands";
import { loadPathAsLogSource } from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";

/**
 * Hook that handles a file path passed via OS file association at app startup.
 *
 * When the user opens a `.log` or `.lo_` file with CMTrace Open (e.g. by
 * double-clicking it or right-clicking and choosing "Open with"), the OS
 * launches the application with the file path as a CLI argument.  This hook
 * retrieves that path on mount and routes it through the shared source-loading
 * flow, reusing the same logic as drag-and-drop file opens.
 */
export function useFileAssociation() {
  const clearFilter = useFilterStore((s) => s.clearFilter);

  useEffect(() => {
    getInitialFilePath()
      .then((filePath) => {
        if (!filePath) {
          return;
        }

        useUiStore.getState().ensureLogViewVisible("file-association.path-open");
        clearFilter();

        return loadPathAsLogSource(filePath, {
          fallbackToFolder: false,
        });
      })
      .catch((error) => {
        console.error("[file-association] failed to open initial file path", {
          error,
        });
      });
  }, [clearFilter]);
}
