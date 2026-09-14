import { useCallback, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
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
import { useAppActions } from "./use-app-actions";

/**
 * Event the backend emits when a second launch forwards its file paths.
 *
 * A second launch — a file-association double-click, or a path on the command
 * line — opens in the window that is already running instead of starting a
 * second one. Those paths arrive here, and here only, so a forwarded launch
 * cannot be opened twice.
 */
const SECOND_LAUNCH_OPEN_EVENT = "second-launch-open";

/** Why a forwarded path is being opened, for diagnostics. */
const SECOND_LAUNCH_TRIGGER = "second-launch.path-open";

/**
 * Reads the paths out of a forwarded launch payload.
 *
 * The payload crosses the IPC boundary, so its shape is checked rather than
 * trusted: an unreadable delivery is ignored instead of throwing inside launch
 * handling. A readable payload with no paths is not an error — a launch with
 * nothing to open only asked for the window.
 */
function parseForwardedPaths(payload: unknown): string[] | null {
  if (typeof payload !== "object" || payload === null) {
    return null;
  }

  const { paths } = payload as { paths?: unknown };
  if (
    !Array.isArray(paths) ||
    !paths.every((path) => typeof path === "string")
  ) {
    return null;
  }

  return paths;
}

/**
 * Opens the paths one forwarded launch asked for, in turn.
 *
 * A path open supersedes one that is still in flight, so a launch carrying
 * several files must await each open before starting the next: starting them
 * together would drop all but the last.
 */
async function openForwardedPaths(
  paths: string[],
  openPath: (path: string, trigger: string) => Promise<void>,
): Promise<void> {
  for (const path of paths) {
    try {
      await openPath(path, SECOND_LAUNCH_TRIGGER);
    } catch (error) {
      console.error("[file-association] failed to open a forwarded path", {
        path,
        error,
      });
    }
  }
}

/**
 * Opens the files the first launch carried.
 *
 * These come from the OS file association: a single file is opened as itself,
 * and several selected files merge into one stream, which is what that launch
 * asked for.
 */
async function openLaunchPaths(
  paths: string[],
  clearFilter: () => void,
): Promise<void> {
  useUiStore.getState().ensureLogViewVisible("file-association.path-open");
  clearFilter();

  if (paths.length === 1) {
    await loadPathAsLogSource(paths[0], { fallbackToFolder: false });
    return;
  }

  await loadFilesAsLogSource(paths);
}

/**
 * Hook that handles validated launch intent.
 *
 * At startup, launch intents can arrive together and they never blend into each
 * other. Precedence, highest first, ending in the ordinary no-intent case:
 *
 *   1. positional file paths from an OS file association;
 *   2. a valid, unconsumed elevation restore ticket;
 *   3. an approved workspace-only startup argument;
 *   4. normal default startup.
 *
 * A restore ticket reopens exactly one workspace and at most one source. Other
 * tabs, filters, searches, and selected rows are deliberately not restored.
 *
 * Once the window is running, a second launch delivers its file paths here
 * rather than opening a second window, and they are opened in the window that
 * already exists.
 */
export function useFileAssociation() {
  const clearFilter = useFilterStore((s) => s.clearFilter);
  const { openPathForActiveWorkspace } = useAppActions();
  // Every launch open runs through one queue. A path open in this window
  // supersedes one that is still in flight, so a second launch waits for the
  // file the first launch opened instead of taking its place, and two launches
  // arriving back to back wait for each other.
  const launchOpens = useRef<Promise<void>>(Promise.resolve());

  /**
   * Runs one launch's file opens behind every launch already in flight.
   *
   * The queued promise is returned so the launch that owns the open reports its
   * own failure; the queue recovers independently, because one failed launch
   * must not stall the launches after it.
   */
  const enqueueLaunchOpens = useCallback(
    (open: () => Promise<void>): Promise<void> => {
      const queued = launchOpens.current.catch(() => undefined).then(open);
      launchOpens.current = queued.catch(() => undefined);
      return queued;
    },
    [],
  );

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
          await enqueueLaunchOpens(() => openLaunchPaths(paths, clearFilter));
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
          // Queued for the same reason as the file branch: a restored source is
          // an open, and an open started beside it would supersede it.
          await enqueueLaunchOpens(() =>
            restoreElevatedSource(ticket, clearFilter),
          );
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
  }, [clearFilter, enqueueLaunchOpens]);

  // A second launch opens its files in this window. Each path goes through the
  // same flow a path handed to the running window already uses, so it lands in
  // a tab and in Recent like any other open — and through the same queue as the
  // first launch, so a second launch waits for a startup open still in flight
  // instead of superseding it.
  useEffect(() => {
    const unlisten = listen<unknown>(SECOND_LAUNCH_OPEN_EVENT, (event) => {
      const paths = parseForwardedPaths(event.payload);
      if (paths === null) {
        console.warn(
          "[file-association] ignored an unreadable second-launch payload",
        );
        return;
      }

      void enqueueLaunchOpens(() =>
        openForwardedPaths(paths, openPathForActiveWorkspace),
      ).catch((error) => {
        console.error("[file-association] forwarded launch failed", { error });
      });
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [enqueueLaunchOpens, openPathForActiveWorkspace]);
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
