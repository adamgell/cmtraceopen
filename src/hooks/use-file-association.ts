import { useEffect } from "react";
import {
  getInitialElevationRestore,
  getInitialFilePaths,
  getInitialWorkspace,
} from "../lib/commands";
import { markElevationRetryAttempted } from "../lib/elevation";
import {
  getKnownSourceMetadataById,
  loadFilesAsLogSource,
  loadLogSource,
  loadPathAsLogSource,
} from "../lib/log-source";
import { useFilterStore } from "../stores/filter-store";
import { useUiStore } from "../stores/ui-store";
import type { RestoreTicket } from "../types/elevation";

/**
 * Hook that handles validated launch intent at app startup.
 *
 * Three launch intents can arrive together and they never blend into each
 * other. Precedence, highest first:
 *
 *   1. positional file paths from an OS file association;
 *   2. a valid, unconsumed elevation restore ticket;
 *   3. an approved workspace-only startup argument;
 *   4. normal default startup.
 *
 * A restore ticket reopens exactly one workspace and at most one source. Other
 * tabs, filters, searches, and selected rows are deliberately not restored.
 */
export function useFileAssociation() {
  const clearFilter = useFilterStore((s) => s.clearFilter);

  useEffect(() => {
    Promise.all([
      getInitialFilePaths(),
      getInitialWorkspace(),
      getInitialElevationRestore().catch((error) => {
        // A restore that cannot even be read must not stop the app starting.
        console.warn("[elevation] unable to read the restore ticket", {
          error,
        });
        return null;
      }),
    ])
      .then(async ([paths, workspace, ticket]) => {
        if (ticket) {
          // Mark before restoring: if the restored source is still denied, the
          // failure must offer troubleshooting rather than a second prompt.
          markElevationRetryAttempted();
        }

        if (paths.length > 0) {
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
          return;
        }

        if (ticket) {
          await restoreElevatedSource(ticket, clearFilter);
          return;
        }

        if (workspace === "esp-diagnostics") {
          useUiStore
            .getState()
            .ensureWorkspaceVisible("esp-diagnostics", "startup.workspace");
        }
      })
      .catch((error) => {
        console.error("[file-association] failed to open initial file paths", {
          error,
        });
      });
  }, [clearFilter]);
}

/**
 * Reopen the one workspace and source a validated restore ticket names.
 *
 * The workspace is routed through the normal availability check, so a ticket
 * naming a workspace this platform or build does not offer falls back to the
 * default rather than forcing an unavailable view.
 */
async function restoreElevatedSource(
  ticket: RestoreTicket,
  clearFilter: () => void,
): Promise<void> {
  const { target, workspace } = ticket;

  if (target.kind === "workspace") {
    useUiStore
      .getState()
      .ensureWorkspaceVisible(workspace, "startup.elevation-restore");
    return;
  }

  useUiStore.getState().ensureLogViewVisible("startup.elevation-restore");
  clearFilter();

  switch (target.kind) {
    case "file":
      await loadPathAsLogSource(target.path, { fallbackToFolder: false });
      return;
    case "folder":
      await loadPathAsLogSource(target.path, { fallbackToFolder: true });
      return;
    case "knownSource":
      // Known sources resolve through the catalog by stable id rather than a
      // persisted expanded path, so the elevated process reads current metadata.
      await openKnownSourceById(target.sourceId);
  }
}

/**
 * Open a catalog entry by its stable identifier.
 *
 * Resolving current catalog metadata rather than replaying a persisted expanded
 * path means the elevated process opens whatever that source means now, and a
 * source that has since disappeared degrades to a warning instead of a bad path.
 */
async function openKnownSourceById(sourceId: string): Promise<void> {
  const source = await getKnownSourceMetadataById(sourceId);
  if (!source) {
    console.warn("[elevation] restored known source is no longer available", {
      sourceId,
    });
    return;
  }
  await loadLogSource(source.source);
}
