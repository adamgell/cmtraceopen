/**
 * Bridges current application state to an elevation request.
 *
 * Kept apart from `elevation.ts` so the coordinator stays free of store
 * imports: the coordinator is called from components, hooks, and the menu, and
 * none of them should have to agree on where state lives.
 */

import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";
import type { LogSource } from "../types/log";
import type {
  ElevationReason,
  ElevationRequest,
  RestoreTarget,
  SourceAccessDenied,
} from "../types/elevation";

/**
 * Map the active log source onto the one source intent worth restoring.
 *
 * Returns a workspace-only target when nothing is open, which is the correct
 * request for a global menu restart with no active source.
 */
export function restoreTargetForSource(
  source: LogSource | null,
): RestoreTarget {
  if (!source) return { kind: "workspace" };

  switch (source.kind) {
    case "file":
      return { kind: "file", path: source.path };
    case "folder":
      return { kind: "folder", path: source.path, aggregate: true };
    case "known":
      // Restore by stable id, never by the expanded path: the elevated process
      // should resolve whatever that catalog entry means now.
      return { kind: "knownSource", sourceId: source.sourceId };
  }
}

/** Build the request a global restart should carry from current state. */
export function activeElevationRequest(
  reason: ElevationReason = "explicitMenu",
): ElevationRequest {
  return {
    reason,
    workspace: useUiStore.getState().activeWorkspace,
    target: restoreTargetForSource(useLogStore.getState().activeSource),
  };
}

/**
 * A compact label for the confirmation prompt.
 *
 * Prefers a file or folder name over the full path so the confirmation does not
 * expose a sensitive location when a short label conveys the same thing.
 */
export function describeRestoreTarget(target: RestoreTarget): string {
  switch (target.kind) {
    case "workspace":
      return "the current workspace";
    case "file":
      return basename(target.path);
    case "folder":
      return `${basename(target.path)} (folder)`;
    case "knownSource":
      return target.sourceId;
  }
}

/** Last path segment, tolerating both separators and a trailing one. */
function basename(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  const index = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  return index >= 0 ? trimmed.slice(index + 1) || trimmed : trimmed;
}

/**
 * Rebuild the restore intent from the source that was actually refused.
 *
 * The Access Denied prompt must retry the exact failed source, not whatever tab
 * happens to be selected when the user clicks. That is why the backend echoes a
 * bounded context back with the classification.
 */
export function restoreTargetForDenial(
  denial: SourceAccessDenied,
): RestoreTarget {
  const { context, operation } = denial;
  if (!context) return { kind: "workspace" };

  if (context.kind === "knownSource") {
    return { kind: "knownSource", sourceId: context.sourceId };
  }

  return operation === "listFolder"
    ? { kind: "folder", path: context.path, aggregate: true }
    : { kind: "file", path: context.path };
}

/** The elevation request an Access Denied recovery should carry. */
export function elevationRequestForDenial(
  denial: SourceAccessDenied,
): ElevationRequest {
  return {
    reason: "accessDenied",
    workspace: useUiStore.getState().activeWorkspace,
    target: restoreTargetForDenial(denial),
  };
}

/** The confirmation shown before any UAC prompt is requested. */
export function elevationConfirmationMessage(target: RestoreTarget): string {
  return [
    "CMTrace Open will close and reopen as administrator.",
    "",
    `Reopens: ${describeRestoreTarget(target)}`,
    "",
    "Other tabs, filters, and searches are not restored.",
  ].join("\n");
}
