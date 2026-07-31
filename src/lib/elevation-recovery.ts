/**
 * Turns a confirmed Access Denied into an elevation offer.
 *
 * This is the only place a source failure is allowed to raise the recovery
 * prompt, and it refuses in every case the issue calls out: an unclassified
 * failure, a missing file, a parse error, a non-Windows host, an
 * already-elevated process, or a retry that has already come back from an
 * elevated restart. Everything it does is gated on a verdict the operating
 * system produced, never on message text.
 *
 * It only opens the confirmation. The user still has to click through
 * `RestartAsAdministratorDialog` before any UAC prompt appears, so a failing
 * background load can never make Windows throw a consent dialog at someone.
 */

import type { LogSource } from "../types/log";
import { canOfferElevation, readElevationState } from "./elevation";
import { buildElevationRequest } from "./elevation-request";
import { readAccessDenied } from "./source-error";

/**
 * Collapses concurrent offers.
 *
 * An aggregate folder load can fail on many files at once; the user should be
 * asked once, not once per file.
 */
let offerPending = false;

export interface ElevationRecoveryContext {
  /** The rejection from the failed source operation. */
  error: unknown;
  /** The source the user was trying to open, or null for a workspace action. */
  source?: LogSource | null;
}

/**
 * Offers to retry the failed source with elevation.
 *
 * Returns true when the confirmation was opened. Never throws: a failure to
 * probe elevation state must not replace the original source error the user
 * actually needs to see.
 */
export async function offerElevationForSourceFailure({
  error,
  source = null,
}: ElevationRecoveryContext): Promise<boolean> {
  if (offerPending) return false;

  const accessDenied = readAccessDenied(error);
  // No verdict means no offer. This is the guard that keeps missing files,
  // parse failures, and network timeouts from ever reaching a UAC prompt.
  if (!accessDenied) return false;

  offerPending = true;
  try {
    const state = await readElevationState();
    // Covers unsupported platform, already elevated, and the post-retry loop
    // guard in one call.
    if (!canOfferElevation(state)) return false;

    const { useUiStore } = await import("../stores/ui-store");
    const ui = useUiStore.getState();

    // Never stack the recovery prompt on top of a confirmation already open.
    if (ui.elevationPrompt) return false;

    ui.setElevationPrompt({
      request: buildElevationRequest({
        reason: "accessDenied",
        workspace: ui.activeWorkspace,
        // Restore the source that actually failed, not whatever tab happens to
        // be selected when the user gets around to clicking.
        source,
      }),
    });

    return true;
  } catch (probeError) {
    console.warn("[elevation] unable to offer access-denied recovery", {
      probeError,
    });
    return false;
  } finally {
    offerPending = false;
  }
}

/** Test-only reset so the concurrency guard does not leak between cases. */
export function resetElevationRecoveryForTests(): void {
  offerPending = false;
}
