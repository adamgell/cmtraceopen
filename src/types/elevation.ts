/**
 * Wire types for application-wide elevation.
 *
 * These mirror `src-tauri/src/elevation/` exactly. They live apart from the
 * coordinator in `src/lib/elevation.ts` so the command wrappers can reference
 * them without importing the coordinator that calls those wrappers.
 */

import type { WorkspaceId } from "./log";

/** Why elevation was requested. Drives confirmation copy, never permissions. */
export type ElevationReason =
  | "explicitMenu"
  | "accessDenied"
  | "coverageRecommended";

/**
 * The source intent to reopen after elevation.
 *
 * Exactly one source travels with a request. Other tabs, filters, searches,
 * and selected rows are deliberately not restored.
 */
export type RestoreTarget =
  | { kind: "workspace" }
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string; aggregate?: boolean }
  | { kind: "knownSource"; sourceId: string };

export interface ElevationRequest {
  reason: ElevationReason;
  workspace: WorkspaceId;
  target: RestoreTarget;
}

export interface AppElevationState {
  /** Elevation is only offered where the platform provides UAC. */
  platformSupported: boolean;
  isElevated: boolean;
  /** Present when the elevation state could not be determined. */
  detail?: string;
}

export type RelaunchReason =
  | "launched"
  | "alreadyElevated"
  | "elevationCancelled"
  | "unsupportedPlatform";

export interface RelaunchResult {
  launched: boolean;
  reason: RelaunchReason;
}

/**
 * Which source operation was refused.
 *
 * Mirrors `SourceOperation` in `src-tauri/src/source_access.rs`.
 */
export type SourceOperation =
  | "readFile"
  | "listFolder"
  | "openKnownSource"
  | "workspaceAction";

/** Bounded identification of the source that was refused. */
export type SourceContext =
  | { kind: "path"; path: string }
  | { kind: "knownSource"; sourceId: string };

/**
 * A structurally classified source failure.
 *
 * This is the whole reason the backend serializes one error variant as an
 * object: the recovery prompt must never be gated on matching localized OS
 * text like "Access is denied" or "os error 5".
 */
export interface SourceAccessDenied {
  kind: "accessDenied";
  operation: SourceOperation;
  context?: SourceContext;
  /** Safe, app-authored text — never the raw OS message. */
  message: string;
}

/**
 * The claimed restore ticket, as read back by the elevated process.
 *
 * Mirrors `RestoreTicket` in `src-tauri/src/elevation/restore_ticket.rs`. The
 * backend has already validated every field; the frontend still treats
 * `workspace` as advisory and routes it through the normal availability check.
 */
export interface RestoreTicket {
  schemaVersion: number;
  ticketId: string;
  createdAtMs: number;
  originPid: number;
  workspace: WorkspaceId;
  target: RestoreTarget;
  reason: ElevationReason;
  /** Always true on a restored request, so a second failure cannot re-prompt. */
  retryAttempted: boolean;
}
