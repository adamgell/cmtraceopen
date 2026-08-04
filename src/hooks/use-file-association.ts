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
import type { LogSource } from "../types/log";

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

        if (workspace) {
          useUiStore
            .getState()
            .ensureWorkspaceVisible(workspace, "startup.workspace");
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

  if (useUiStore.getState().activeWorkspace !== workspace) {
    // A feature-disabled or platform-incompatible workspace cannot safely lend
    // its source intent to whichever workspace happened to remain visible.
    // Keep the app open at its normal fallback and make the coverage gap
    // explicit without logging the source path.
    console.warn(
      "[elevation] requested workspace is unavailable; source restore skipped",
      { workspace },
    );
    return;
  }

  let source: LogSource;
  if (target.kind === "knownSource") {
    const restored = await resolveKnownSourceById(target.sourceId);
    if (!restored) return;
    source = restored;
  } else {
    source = { kind: target.kind, path: target.path };
  }

  // Replay the source through the same handler as an ordinary open in the
  // workspace that actually survived the availability check above. This is
  // load-bearing for diagnostic workspaces: loading an Intune folder into the
  // generic log store would leave the right workspace visible with no analysis.
  const { getWorkspace } = await import("../workspaces/registry");

  // Source and workspace resolution above are asynchronous. Reassert the
  // ticket's workspace immediately before dispatch so a workspace change that
  // raced either lookup cannot route the restored source behind another view.
  useUiStore
    .getState()
    .ensureWorkspaceVisible(workspace, "startup.elevation-restore");
  if (useUiStore.getState().activeWorkspace !== workspace) {
    console.warn(
      "[elevation] requested workspace is unavailable; source restore skipped",
      { workspace },
    );
    return;
  }

  const workspaceHandler = getWorkspace(workspace).onOpenSource;
  if (workspaceHandler) {
    await workspaceHandler(source, "startup.elevation-restore");
    return;
  }

  if (workspace !== "log") {
    // A validated ticket may still combine an allowlisted workspace with a
    // source that workspace does not know how to open. Do not populate hidden
    // Log Explorer state behind a different screen.
    console.warn(
      "[elevation] requested workspace cannot restore sources; source restore skipped",
      { workspace },
    );
    return;
  }

  clearFilter();
  await loadLogSource(source);
}

/**
 * Open a catalog entry by its stable identifier.
 *
 * Resolving current catalog metadata rather than replaying a persisted expanded
 * path means the elevated process opens whatever that source means now, and a
 * source that has since disappeared degrades to a warning instead of a bad path.
 */
async function resolveKnownSourceById(
  sourceId: string,
): Promise<LogSource | null> {
  const source = await getKnownSourceMetadataById(sourceId);
  if (!source) {
    console.warn("[elevation] restored known source is no longer available", {
      sourceId,
    });
    return null;
  }
  return source.source;
}
