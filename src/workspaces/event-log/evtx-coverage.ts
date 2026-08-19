import type { EventLogSourceCoverage } from "./types";

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
  provider: true,
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

/**
 * Converts typed source coverage into the stable operator-facing banner wording.
 *
 * The backend keeps coverage structured so source kind and path survive IPC. The banner remains
 * textual because it is a compact list, but this conversion is the only boundary where that
 * structure is flattened.
 */
export function sourceCoverageMessages(
  coverage: readonly EventLogSourceCoverage[],
): string[] {
  return coverage.map(({ path, reason }) => `${path}: ${reason}`);
}

/**
 * The parts of an event-log IPC reply the store reads, verified once.
 *
 * Not a schema validator, and deliberately not per-handler checks: it guards the fields the store
 * destructures and iterates. If a future backend change dropped `errorMessages`, spreading it
 * would throw somewhere unrelated and surface as a confusing load error; this fails at the
 * boundary with a message that names the contract.
 *
 * Throws rather than returning a default, because a reply the store cannot read is not a reply
 * with no events, and quietly showing an empty list is the failure this workspace exists to avoid.
 */
export function assertParseResultShape(value: unknown): {
  records: unknown[];
  channels: unknown[];
  errorMessages: string[];
  coverageGaps: EvtxCoverageGap[];
  coverage: EventLogSourceCoverage[];
  totalRecords: number | null;
} {
  const reply = value as {
    records?: unknown;
    channels?: unknown;
    errorMessages?: unknown;
    coverageGaps?: unknown;
    coverage?: unknown;
    totalRecords?: unknown;
  };
  if (!Array.isArray(reply?.records) || !Array.isArray(reply?.channels)) {
    throw new Error("the event log reader returned a reply this build cannot read");
  }
  const coverage = Array.isArray(reply.coverage)
    ? reply.coverage.filter(isEventLogSourceCoverage)
    : [];
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
    coverage,
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

function isEventLogSourceCoverage(value: unknown): value is EventLogSourceCoverage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    (candidate.kind === "unsupported" ||
      candidate.kind === "accessDenied" ||
      candidate.kind === "missing" ||
      candidate.kind === "empty" ||
      candidate.kind === "invalidPattern" ||
      candidate.kind === "limitReached") &&
    typeof candidate.path === "string" &&
    typeof candidate.reason === "string"
  );
}
