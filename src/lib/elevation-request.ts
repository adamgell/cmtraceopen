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
import type { WorkspaceDefinition } from "../workspaces/types";
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

/**
 * The workspaces the backend accepts in a restore ticket: `AppWorkspace` in
 * src-tauri/src/elevation/mod.rs. `WorkspaceId` has one more, "sccm", and a ticket that names it is
 * refused at the backend boundary, so no ticket may. A test reads the Rust enum and fails if this
 * list drifts from it.
 */
export const BACKEND_ELEVATION_WORKSPACES: readonly WorkspaceId[] = [
  "log",
  "intune",
  "new-intune",
  "dsregcmd",
  "macos-diag",
  "macos-jamf",
  "deployment",
  "event-log",
  "esp-diagnostics",
  "secureboot",
  "sysmon",
  "timeline",
  "dns-dhcp",
];

/** A file, or a known source that is one file: what a text-log handler can reopen as a text log. */
function isTextLogFile(source: LogSource | null): boolean {
  if (source === null) return false;
  return source.kind === "file" || (source.kind === "known" && source.pathKind === "file");
}

/**
 * The workspace a restore ticket names when a TEXT-LOG load failed Access Denied.
 *
 * After the elevated restart the ticket's workspace opens the source through its own
 * `onOpenSource` (`restoreElevatedSource`), and only the Log workspace, which has none, falls
 * through to the text-log loader. So the active workspace keeps its own ticket only if it is the Log
 * workspace, or it says its handler reopens text-log files (the Intune workspaces load a file
 * through the log store before they analyze it) and this source is a file. Every other workspace,
 * and an Intune folder, names the Log workspace, whose restore is the text-log load the user asked
 * for. That includes the workspaces with no handler at all: a workspace the backend does not accept
 * (SCCM) can never be named.
 */
export function textLogRestoreWorkspace(
  active: WorkspaceId,
  definition: Pick<WorkspaceDefinition, "capabilities">,
  source: LogSource | null,
): WorkspaceId {
  if (active === "log") return "log";
  return definition.capabilities?.reopensTextLogFiles === true && isTextLogFile(source)
    ? active
    : "log";
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
 * Driven by the restore target, deliberately not by `reason`. An Access Denied
 * recovery and an explicit menu restart perform the identical backend call and
 * restore the same thing, so wording them differently would imply a difference
 * in what is about to happen when there is none.
 */
export function describeElevationPrompt(request: ElevationRequest): string {
  const target = describeRestoreTarget(request.target);

  if (request.target.kind === "workspace") {
    return `CMTrace Open will close and reopen as administrator, returning to ${target}. Open files, filters, and searches are not restored.`;
  }

  return `CMTrace Open will close and reopen as administrator, reopening ${target}. Other tabs, filters, and searches are not restored.`;
}
