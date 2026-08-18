/**
 * Accumulating the report of what is missing from a loaded set of events.
 *
 * Lives outside the store because the store imports the Tauri IPC bridge at module scope, which a
 * unit test cannot load. The rule being tested is small but easy to get wrong in a way nobody
 * notices: gaps must accumulate across channels, and must not multiply when a channel is
 * re-queried.
 */

import type { EvtxCoverageGap, EvtxCoverageGapKind } from "./types";

const COVERAGE_GAP_KINDS: Record<EvtxCoverageGapKind, true> = {
  unsupported: true,
  accessDenied: true,
  missing: true,
  invalidPattern: true,
  limitReached: true,
  empty: true,
  file: true,
  chunk: true,
  record: true,
  xml: true,
  limit: true,
};

function isCoverageGap(value: unknown): value is EvtxCoverageGap {
  if (typeof value !== "object" || value === null) return false;
  const gap = value as Partial<EvtxCoverageGap>;
  return (
    typeof gap.source === "string" &&
    typeof gap.reason === "string" &&
    typeof gap.kind === "string" &&
    COVERAGE_GAP_KINDS[gap.kind as EvtxCoverageGapKind] === true &&
    (gap.chunkId === undefined ||
      (typeof gap.chunkId === "number" && Number.isSafeInteger(gap.chunkId) && gap.chunkId >= 0)) &&
    (gap.eventRecordId === undefined ||
      (typeof gap.eventRecordId === "number" &&
        Number.isSafeInteger(gap.eventRecordId) &&
        gap.eventRecordId >= 0))
  );
}

/** Formats structured parser coverage for the existing operator-facing banner. */
export function formatCoverageGap(gap: EvtxCoverageGap): string {
  const location =
    gap.chunkId !== undefined
      ? ` chunk ${gap.chunkId}`
      : gap.eventRecordId !== undefined
        ? ` record ${gap.eventRecordId}`
        : "";
  return `${gap.source}${location}: ${gap.reason}`;
}

/** Accumulates structured gaps without duplicating a rejected region on refresh. */
export function mergeStructuredCoverageGaps(
  existing: readonly EvtxCoverageGap[],
  incoming: readonly EvtxCoverageGap[]
): EvtxCoverageGap[] {
  const merged = [...existing];
  const seen = new Set(
    existing.map((gap) =>
      JSON.stringify([gap.source, gap.kind, gap.reason, gap.chunkId, gap.eventRecordId])
    )
  );
  for (const gap of incoming) {
    const key = JSON.stringify([gap.source, gap.kind, gap.reason, gap.chunkId, gap.eventRecordId]);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(gap);
    }
  }
  return merged;
}

/**
 * Merges newly reported gaps into the ones already on screen.
 *
 * Channels load one at a time and each reports its own gaps, so these accumulate rather than
 * replace. They are deduplicated because re-querying a channel reports the same gap again, and a
 * banner that grows every refresh trains an operator to stop reading it.
 *
 * Order is preserved so a gap does not move around the list as more channels finish.
 */
export function mergeCoverageGaps(
  existing: readonly string[],
  incoming: readonly string[]
): string[] {
  return [...new Set([...existing, ...incoming])];
}

/** Wording for the legacy string banner summary. */
export function summarizeCoverageGaps(gaps: readonly string[]): string {
  return gaps.length === 1 ? "1 gap in this view" : `${gaps.length} gaps in this view`;
}

/** Wording for the banner summary. */
export function assertParseResultShape(value: unknown): {
  records: unknown[];
  channels: unknown[];
  errorMessages: string[];
  coverageGaps: EvtxCoverageGap[];
  totalRecords: number | null;
} {
  const reply = value as {
    records?: unknown;
    channels?: unknown;
    errorMessages?: unknown;
    coverageGaps?: unknown;
    totalRecords?: unknown;
  };
  if (!Array.isArray(reply?.records) || !Array.isArray(reply?.channels)) {
    throw new Error("the event log reader returned a reply this build cannot read");
  }
  return {
    records: reply.records,
    channels: reply.channels,
    // Absent means the reader reported no gaps, which is different from a malformed reply.
    errorMessages: Array.isArray(reply.errorMessages)
      ? reply.errorMessages.filter((entry): entry is string => typeof entry === "string")
      : [],
    coverageGaps: Array.isArray(reply.coverageGaps)
      ? reply.coverageGaps.filter(isCoverageGap)
      : [],
    // How many records the reader says it sent, counting any streamed separately from this reply.
    // `null` when the reader did not say, which must stay distinguishable from zero: treating an
    // absent count as zero would turn "I cannot check completeness" into "nothing was missing".
    // A non-finite or negative count is no answer either, so it is rejected the same way.
    totalRecords:
      typeof reply.totalRecords === "number" &&
      Number.isFinite(reply.totalRecords) &&
      reply.totalRecords >= 0
        ? reply.totalRecords
        : null,
  };
}
