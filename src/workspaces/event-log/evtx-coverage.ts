/**
 * Accumulating the report of what is missing from a loaded set of events.
 *
 * Lives outside the store because the store imports the Tauri IPC bridge at module scope, which a
 * unit test cannot load. The rule being tested is small but easy to get wrong in a way nobody
 * notices: gaps must accumulate across channels, and must not multiply when a channel is
 * re-queried.
 */

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

/** Wording for the banner summary. */
export function summarizeCoverageGaps(gaps: readonly string[]): string {
  return gaps.length === 1 ? "1 gap in this view" : `${gaps.length} gaps in this view`;
}

/**
 * The parts of an event-log IPC reply the store reads, verified once.
 *
 * Not a schema validator, and deliberately not per-handler checks: it guards the three fields the
 * store destructures and iterates. If a future backend change dropped `errorMessages`, spreading
 * it would throw somewhere unrelated and surface as a confusing load error; this fails at the
 * boundary with a message that names the contract.
 *
 * Throws rather than returning a default, because a reply the store cannot read is not a reply
 * with no events, and quietly showing an empty list is the failure this workspace exists to avoid.
 */
export function assertParseResultShape(value: unknown): {
  records: unknown[];
  channels: unknown[];
  errorMessages: string[];
  totalRecords: number | null;
} {
  const reply = value as {
    records?: unknown;
    channels?: unknown;
    errorMessages?: unknown;
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
