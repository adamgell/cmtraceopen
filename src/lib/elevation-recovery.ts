/**
 * Access Denied recovery.
 *
 * The one place that decides whether a failed source operation may offer to
 * restart elevated. Every guard the issue requires lives here rather than in
 * each caller's catch block:
 *
 * - only a confirmed `accessDenied` classification qualifies, never a string match;
 * - a missing file, parse failure, or timeout never reaches this path at all;
 * - the user must click before UAC is requested;
 * - a restored retry cannot offer elevation a second time.
 */

import { getSourceAccessDenial } from "./commands";
import {
  canOfferElevation,
  readElevationState,
  requestElevatedRestart,
  type ElevationOutcome,
} from "./elevation";
import {
  describeRestoreTarget,
  elevationRequestForDenial,
  restoreTargetForDenial,
} from "./elevation-context";
import type { SourceAccessDenied } from "../types/elevation";

/** What a caller should do about a failed source operation. */
export type RecoveryOffer =
  | { kind: "none" }
  | { kind: "offer"; denial: SourceAccessDenied; prompt: string };

/**
 * Decide whether a rejected source operation may offer elevation.
 *
 * Returns `none` for everything that elevation would not fix, and for the
 * second failure after a restored retry — that is the loop guard.
 */
export async function evaluateRecovery(
  error: unknown,
): Promise<RecoveryOffer> {
  const denial = getSourceAccessDenial(error);
  if (!denial) return { kind: "none" };

  const state = await readElevationState();
  if (!canOfferElevation(state)) return { kind: "none" };

  return {
    kind: "offer",
    denial,
    prompt: recoveryPrompt(denial),
  };
}

/** The recovery prompt body, naming the source that will be retried. */
export function recoveryPrompt(denial: SourceAccessDenied): string {
  const target = describeRestoreTarget(restoreTargetForDenial(denial));
  return [
    denial.message,
    "",
    `Restarting as administrator will reopen: ${target}`,
    "",
    "Other tabs, filters, and searches are not restored.",
  ].join("\n");
}

/**
 * Run the recovery: confirm, then request the elevated restart.
 *
 * `confirm` is injected so this stays testable without the Tauri dialog plugin
 * and so the caller controls which dialog implementation is used.
 */
export async function runRecovery(
  denial: SourceAccessDenied,
  confirmAction: (message: string) => Promise<boolean>,
): Promise<ElevationOutcome | { status: "declined" }> {
  const confirmed = await confirmAction(recoveryPrompt(denial));
  if (!confirmed) return { status: "declined" };

  return requestElevatedRestart(elevationRequestForDenial(denial));
}
