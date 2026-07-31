/**
 * Builds elevation requests from the current application context.
 *
 * Kept pure and separate from the coordinator in `src/lib/elevation.ts` so the
 * menu action, the Access Denied recovery prompt, and the ESP banner all derive
 * a request the same way instead of each reaching into stores and inventing its
 * own shape.
 *
 * Two rules drive everything here:
 *
 * 1. Exactly one source travels with a request. The issue's non-goals are
 *    explicit that other tabs, filters, searches, and selected rows are not
 *    restored, so there is deliberately no way to express more than one target.
 * 2. Confirmation copy identifies the target without pasting a full path into
 *    the UI when a compact label exists. Elevation prompts are screenshotted and
 *    pasted into tickets; a bare file name is enough to recognise the source.
 */

import type { LogSource, WorkspaceId } from "../types/log";
import type {
  ElevationReason,
  ElevationRequest,
  RestoreTarget,
} from "../types/elevation";

/** Splits on both separators so a Windows path is handled on a macOS test host. */
function baseName(path: string): string {
  const segments = path.split(/[\\/]+/).filter((segment) => segment.length > 0);
  return segments[segments.length - 1] ?? path;
}

/**
 * Maps the active source to the target that should reopen after elevation.
 *
 * A null source is the global-menu case: restore the workspace only. A known
 * source travels by stable ID rather than its expanded path, so the elevated
 * process resolves current catalog metadata instead of trusting a stale path.
 */
export function buildRestoreTarget(source: LogSource | null): RestoreTarget {
  if (!source) return { kind: "workspace" };

  switch (source.kind) {
    case "file":
      return { kind: "file", path: source.path };
    case "folder":
      return { kind: "folder", path: source.path };
    case "known":
      return { kind: "knownSource", sourceId: source.sourceId };
  }
}

/**
 * Compact, non-sensitive description of what will reopen.
 *
 * Known sources return their ID because that is already a stable, non-secret
 * identifier; file and folder targets return only the last path segment.
 */
export function describeRestoreTarget(target: RestoreTarget): string {
  switch (target.kind) {
    case "workspace":
      return "the current workspace";
    case "file":
      return baseName(target.path);
    case "folder":
      return baseName(target.path);
    case "knownSource":
      return target.sourceId;
  }
}

export interface ElevationRequestContext {
  reason: ElevationReason;
  workspace: WorkspaceId;
  /** The source to reopen, or null to restore the workspace alone. */
  source?: LogSource | null;
}

export function buildElevationRequest({
  reason,
  workspace,
  source = null,
}: ElevationRequestContext): ElevationRequest {
  return { reason, workspace, target: buildRestoreTarget(source) };
}

/**
 * The sentence shown above the confirm/cancel buttons.
 *
 * The reason changes the framing but never the permissions: an Access Denied
 * recovery and an explicit menu restart perform the identical backend call.
 */
export function describeElevationPrompt(request: ElevationRequest): string {
  const target = describeRestoreTarget(request.target);

  if (request.target.kind === "workspace") {
    return `CMTrace Open will close and reopen as administrator, returning to ${target}. Open files, filters, and searches are not restored.`;
  }

  return `CMTrace Open will close and reopen as administrator, reopening ${target}. Other tabs, filters, and searches are not restored.`;
}
