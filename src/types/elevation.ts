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
  | { kind: "folder"; path: string }
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
