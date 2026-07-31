/**
 * Application-wide elevation coordinator.
 *
 * One owner for "restart as administrator" across the whole app. The global
 * menu, the Access Denied recovery prompt, and the ESP coverage banner all call
 * `requestElevatedRestart` rather than each holding their own relaunch state.
 *
 * The backend does the security work: it validates the request, mints a
 * single-use restore ticket, and exits the current process only after Windows
 * confirms the elevated child started. This module's job is to make sure the
 * user is asked exactly once, that concurrent requests collapse into one, and
 * that a restored retry cannot start an elevation loop.
 */

import type {
  AppElevationState,
  ElevationRequest,
} from "../types/elevation";
import { getAppElevationState, restartAsAdministrator } from "./commands";

export type {
  AppElevationState,
  ElevationReason,
  ElevationRequest,
  RelaunchReason,
  RelaunchResult,
  RestoreTarget,
  RestoreTicket,
} from "../types/elevation";

/**
 * What the caller should tell the user.
 *
 * `launched` is terminal: the process is about to exit, so a caller should stop
 * rather than render a result the user will never see.
 */
export type ElevationOutcome =
  | { status: "launched" }
  | { status: "alreadyElevated" }
  | { status: "cancelled" }
  | { status: "unsupported" }
  | { status: "busy" }
  | { status: "failed"; message: string };

/**
 * Collapses concurrent requests.
 *
 * A double-clicked button, or a menu action racing a recovery prompt, must
 * produce one UAC prompt. The backend enforces this too; this is the cheap
 * front line that also keeps the UI honest.
 */
let inFlight: Promise<ElevationOutcome> | null = null;

/**
 * Set once a restored source has been retried, so a second failure offers
 * troubleshooting rather than another elevation prompt.
 */
let retryAttempted = false;

/** Records that this session already came back from an elevated restart. */
export function markElevationRetryAttempted(): void {
  retryAttempted = true;
}

/**
 * Whether an Access Denied failure may still offer elevation.
 *
 * False once a restored retry has been attempted: that is the loop guard.
 */
export function canOfferElevation(state: AppElevationState | null): boolean {
  if (retryAttempted) return false;
  if (!state) return false;
  return state.platformSupported && !state.isElevated;
}

/** Read the current elevation capability, or null when the probe fails. */
export async function readElevationState(): Promise<AppElevationState | null> {
  try {
    return await getAppElevationState();
  } catch (error) {
    console.warn("[elevation] unable to read elevation state", { error });
    return null;
  }
}

/**
 * Ask the backend to relaunch elevated.
 *
 * Never throws: every failure is reported as an outcome so callers can render
 * one consistent message instead of each inventing its own catch block.
 */
export async function requestElevatedRestart(
  request: ElevationRequest,
): Promise<ElevationOutcome> {
  if (inFlight) return { status: "busy" };

  const attempt = (async (): Promise<ElevationOutcome> => {
    try {
      const result = await restartAsAdministrator(request);
      if (result.launched) return { status: "launched" };
      switch (result.reason) {
        case "elevationCancelled":
          return { status: "cancelled" };
        case "alreadyElevated":
          return { status: "alreadyElevated" };
        case "unsupportedPlatform":
          return { status: "unsupported" };
        default:
          return {
            status: "failed",
            message: "Administrator restart could not be started.",
          };
      }
    } catch (error) {
      return {
        status: "failed",
        message:
          error instanceof Error
            ? error.message
            : "Administrator restart could not be started.",
      };
    }
  })();

  inFlight = attempt;

  let outcome: ElevationOutcome;
  try {
    outcome = await attempt;
  } catch (error) {
    // `attempt` converts every failure into an outcome, so this is unreachable
    // in practice. Release the guard anyway rather than wedging the app shut if
    // that contract is ever broken.
    inFlight = null;
    throw error;
  }

  // Deliberately leave the guard set after a successful launch. The process is
  // exiting, and the ESP banner calls this coordinator directly rather than
  // through the confirmation dialog, so nothing else would stop a late click
  // from raising a second UAC prompt during teardown.
  if (outcome.status !== "launched") {
    inFlight = null;
  }

  return outcome;
}

/** Human-readable status text for the outcomes a caller may still be around to show. */
export function describeElevationOutcome(outcome: ElevationOutcome): string {
  switch (outcome.status) {
    case "launched":
      return "Administrator restart requested.";
    case "alreadyElevated":
      return "CMTrace Open is already running as administrator.";
    case "cancelled":
      return "Administrator restart was cancelled.";
    case "unsupported":
      return "Restarting as administrator is only supported on Windows.";
    case "busy":
      return "An administrator restart is already in progress.";
    case "failed":
      return outcome.message;
  }
}

/** Test-only reset so module-level guards do not leak between cases. */
export function resetElevationCoordinatorForTests(): void {
  inFlight = null;
  retryAttempted = false;
}
