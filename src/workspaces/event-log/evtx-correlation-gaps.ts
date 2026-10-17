/**
 * What the engine's correlation coverage gaps say about completeness (soul.md rule 4, ADR-001).
 *
 * A missing edge is evidence of "no link" only for an origin the engine actually correlated. The
 * engine says when it did not, in `UnifiedTimeline.coverageGaps`: an exact group over the
 * 256-member limit gets no edges at all, the relation budget can leave an origin out, an origin
 * with no machine identity is restricted, the input limit drops origins from correlation, and the
 * edge-output and gap-limit budgets truncate. Reading an uncorrelated record as having no link is
 * a coverage state read as success.
 *
 * Pure. Gaps are discriminated by their `source` field alone, never by the reason text (the
 * wording is the engine's to change). A gap record carries exactly `{ source, reason }`
 * (`TimelineCoverageGap`, unified_timeline/mod.rs:252). What the `source` is:
 * - an ORIGIN ID, for a gap about one origin: the fan-out and relation-budget gaps, "machine
 *   identity unavailable", identity conflicts, process-start identity (unified_timeline/mod.rs
 *   :792-818, :1105-1119; event_log/timeline.rs observation gaps carry `stable_id`);
 * - `"correlation"`, for the reducer's own truncation: the candidate budget, the edge-output
 *   budget and the gap-limit marker (mod.rs:655, :997, :1073, :1136);
 * - `"timeline-correlation-projection"`, for the input limit that dropped origins from correlation
 *   altogether (event_log/timeline.rs:19, :541);
 * - `"timeline-item-projection"` and `"timeline-message-projection"`, for list-view compaction.
 *   They are about display, not correlation (timeline.rs:25-26).
 *
 * Any other source is a CANDIDATE origin id. It still has to be found among the origins read
 * before it can be attributed to a record; one that cannot be found is unattributable.
 */
import type { TimelineCoverageGap } from "./unified-timeline";

/** Sources of gaps about the whole correlation, not one origin. Each means origins went uncorrelated. */
export const GLOBAL_CORRELATION_GAP_SOURCES: ReadonlySet<string> = new Set([
  "correlation",
  "timeline-correlation-projection",
]);

/** Sources of gaps about list-view compaction. They say nothing about correlation. */
export const DISPLAY_GAP_SOURCES: ReadonlySet<string> = new Set([
  "timeline-item-projection",
  "timeline-message-projection",
]);

export interface CorrelationGaps {
  /**
   * Candidate origin ids: the sources of the gaps in the preview that are neither global nor
   * about display. Each makes its origin's records unknown once the origin is found.
   */
  originIds: ReadonlySet<string>;
  /** A gap about the whole correlation exists (a limit or a truncation): some origins were never correlated. */
  global: boolean;
  /**
   * The preview does not show every gap: the session counts more than the preview holds (the
   * preview is capped at 100 rows and there is no pager), or the count is not known. Which origins
   * the missing gaps name cannot be told.
   */
  previewCut: boolean;
}

/**
 * The gaps of an unknown session. It is the safe value for "no gap information": it claims a cut
 * preview, so nothing downstream reads the absence of gaps as completeness.
 */
export const UNKNOWN_CORRELATION_GAPS: CorrelationGaps = {
  originIds: new Set(),
  global: false,
  previewCut: true,
};

/**
 * Classifies the first page's coverage gap preview. `totalCoverageGaps` is the same reply's count
 * of every gap the session holds; null when it was not a trusted count.
 */
export function classifyCoverageGaps(
  preview: readonly TimelineCoverageGap[],
  totalCoverageGaps: number | null,
): CorrelationGaps {
  const originIds = new Set<string>();
  let global = false;
  for (const gap of preview) {
    if (GLOBAL_CORRELATION_GAP_SOURCES.has(gap.source)) global = true;
    else if (!DISPLAY_GAP_SOURCES.has(gap.source)) originIds.add(gap.source);
  }
  return {
    originIds,
    global,
    // A count below what the preview holds is a contradiction, and a contradiction is not proof.
    previewCut: totalCoverageGaps === null || totalCoverageGaps !== preview.length,
  };
}

/**
 * Whether the gaps alone make a "no link" claim impossible for EVERY origin: a limit or truncation
 * left origins uncorrelated, or gaps exist that were not shown.
 */
export function gapsClearCompleteness(gaps: CorrelationGaps): boolean {
  return gaps.global || gaps.previewCut;
}
