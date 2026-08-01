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
 * Launch intents can arrive together and they never blend into each other.
 * Precedence, highest first, ending in the ordinary no-intent case:
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
          // Mark here, not on ticket arrival: a positional file association wins
          // the precedence contest above and returns without restoring, and
          // latching the loop guard for a restore that never ran would suppress
          // legitimate elevation offers for the rest of the session.
          //
          // Marked before restoring, so a restored source that is still denied
          // offers troubleshooting rather than a second prompt. Read from the
          // ticket so the guard has one source of truth.
          if (ticket.retryAttempted) {
            markElevationRetryAttempted();
          }
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
        // Covers all three launch intents, not just file association: a restore
        // ticket that failed to reopen is exactly the case someone is
        // troubleshooting when they read this line.
        console.error("[startup] failed to handle launch intent", { error });
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

  // Honour the ticket's workspace whether or not a source rides along. An
  // Access Denied raised inside ESP or Intune carries that workspace with a
  // file target, so forcing the log view here would reopen the right source on
  // the wrong screen. `ensureLogViewVisible` is only
  // `ensureWorkspaceVisible("log", ...)`, so the log case is unchanged.
  useUiStore
    .getState()
    .ensureWorkspaceVisible(workspace, "startup.elevation-restore");

  if (target.kind === "workspace") return;

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
