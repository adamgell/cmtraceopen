
/**
 * Accumulating the report of what is missing from a loaded set of events.
 *
 * Lives outside the store because the store imports the Tauri IPC bridge at module scope, which a
 * unit test cannot load. The rule being tested is small but easy to get wrong in a way nobody
 * notices: gaps must accumulate across channels, and must not multiply when a channel is
 * re-queried.
 */

import type {
  EvtxArchiveMember,
  EvtxCoverageGap,
  EvtxCoverageGapKind,
  EventLogSourceCoverage,
} from "./types";

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
const ARCHIVE_MEMBER_KINDS = ["evtx", "text", "registry", "binary"] as const;
const ARCHIVE_MEMBER_OUTCOMES = [
  "parsed",
  "unsupported",
  "malformed",
  "duplicate",
  "limit",
] as const;
const MAX_U64 = 18_446_744_073_709_551_615n;

function parseU64Text(value: unknown): bigint | null {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  try {
    const parsed = BigInt(value);
    return parsed <= MAX_U64 ? parsed : null;
  } catch {
    return null;
  }
}

function isArchiveMember(value: unknown): value is EvtxArchiveMember {
  if (typeof value !== "object" || value === null) return false;
  const member = value as Partial<EvtxArchiveMember>;
  return (
    typeof member.path === "string" &&
    member.path.length > 0 &&
    typeof member.kind === "string" &&
    ARCHIVE_MEMBER_KINDS.includes(member.kind as (typeof ARCHIVE_MEMBER_KINDS)[number]) &&
    typeof member.outcome === "string" &&
    ARCHIVE_MEMBER_OUTCOMES.includes(
      member.outcome as (typeof ARCHIVE_MEMBER_OUTCOMES)[number]
    ) &&
    (member.sha256 === undefined ||
      (typeof member.sha256 === "string" && /^[0-9a-fA-F]{64}$/.test(member.sha256)))
  );
}

function parseArchiveMembers(value: unknown): EvtxArchiveMember[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error("the event log reader returned an invalid archive member list");
  }
  const invalidIndex = value.findIndex((member) => !isArchiveMember(member));
  if (invalidIndex >= 0) {
    throw new Error(
      `the event log reader returned an invalid archive member at index ${invalidIndex}`
    );
  }
  return value as EvtxArchiveMember[];
}

function parseOptionalArray<T>(
  value: unknown,
  fieldName: string,
  validator: (entry: unknown) => entry is T
): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error(`the event log reader returned an invalid ${fieldName} list`);
  }
  const invalidIndex = value.findIndex((entry) => !validator(entry));
  if (invalidIndex >= 0) {
    throw new Error(
      `the event log reader returned an invalid ${fieldName} at index ${invalidIndex}`
    );
  }
  return value as T[];
}

function isCoverageGap(value: unknown): value is EvtxCoverageGap {
  if (typeof value !== "object" || value === null) return false;
  const gap = value as Partial<EvtxCoverageGap>;
  const recordIdText =
    gap.eventRecordIdText === undefined
      ? null
      : parseU64Text(gap.eventRecordIdText);
  const recordIdIsValid =
    gap.eventRecordId === undefined ||
    (typeof gap.eventRecordId === "number" &&
      Number.isFinite(gap.eventRecordId) &&
      Number.isInteger(gap.eventRecordId) &&
      gap.eventRecordId >= 0 &&
      (Number.isSafeInteger(gap.eventRecordId) || recordIdText !== null) &&
      (recordIdText === null || Number(recordIdText) === gap.eventRecordId));
  return (
    typeof gap.source === "string" &&
    typeof gap.reason === "string" &&
    typeof gap.kind === "string" &&
    COVERAGE_GAP_KINDS[gap.kind as EvtxCoverageGapKind] === true &&
    (gap.chunkId === undefined ||
      (typeof gap.chunkId === "number" && Number.isSafeInteger(gap.chunkId) && gap.chunkId >= 0)) &&
    recordIdIsValid &&
    (gap.eventRecordIdText === undefined || recordIdText !== null)
  );
}

/** Formats structured parser coverage for the existing operator-facing banner. */
export function formatCoverageGap(gap: EvtxCoverageGap): string {
  const location =
    gap.chunkId !== undefined
      ? ` chunk ${gap.chunkId}`
      : gap.eventRecordIdText !== undefined
        ? ` record ${gap.eventRecordIdText}`
        : gap.eventRecordId !== undefined
          ? ` record ${gap.eventRecordId}`
        : "";
  return `${gap.source}${location}: ${gap.reason}`;
}

function coverageGapKey(gap: EvtxCoverageGap): string {
  const textRecordIdentity = parseU64Text(gap.eventRecordIdText);
  const recordIdentity =
    textRecordIdentity !== null
      ? textRecordIdentity.toString()
      : gap.eventRecordId === undefined
        ? undefined
        : BigInt(gap.eventRecordId).toString();
  return JSON.stringify([
    gap.source,
    gap.kind,
    gap.reason,
    gap.chunkId,
    recordIdentity,
  ]);
}

/** Accumulates structured gaps without duplicating a rejected region on refresh. */
export function mergeStructuredCoverageGaps(
  existing: readonly EvtxCoverageGap[],
  incoming: readonly EvtxCoverageGap[]
): EvtxCoverageGap[] {
  const merged = [...existing];
  const seen = new Set(existing.map(coverageGapKey));
  for (const gap of incoming) {
    const key = coverageGapKey(gap);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(gap);
    }
  }
  return merged;
}

const MAX_DIAGNOSIS_COVERAGE_GAPS = 256;

function legacyGapKind(reason: string): EvtxCoverageGapKind {
  const lower = reason.toLowerCase();
  if (/(access denied|permission denied|\bdenied\b)/.test(lower)) return "accessDenied";
  if (/(empty|no events?|no records?)/.test(lower)) return "empty";
  if (/(malformed|invalid)/.test(lower)) return "invalidPattern";
  if (/(unavailable|unsupported)/.test(lower)) return "unsupported";
  if (
    /\breader\s+stopped\s+at\s+\d[\d,]*\s+events?\b[\s,;:()-]*the\s+source\s+may\s+contain\s+more\b/.test(
      lower
    ) ||
    /\bstopped\s+after\s+\d[\d,]*\s+events?\b[\s,;:()-]*the\s+channel\s+could\s+not\s+be\s+read\s+further\b/.test(
      lower
    ) ||
    /(shortfall|not reached|not received|not delivered|delivery|limit|capped|truncat|maximum)/.test(
      lower
    )
  ) {
    return "limitReached";
  }
  if (/(missing|does not exist|not found)/.test(lower)) return "missing";
  return "record";
}

function legacyCoverageGap(value: string, fallbackSource: string): EvtxCoverageGap {
  const message = value.trim();
  const separator = message.indexOf(": ");
  const source = separator > 0 ? message.slice(0, separator) : fallbackSource;
  const reason = separator > 0 ? message.slice(separator + 2) : message;
  return {
    source: source || fallbackSource,
    kind: legacyGapKind(reason),
    reason,
  };
}

/**
 * Builds the bounded coverage contract sent to operational diagnosis.
 *
 * Structured parser and manifest gaps retain their exact kinds. Legacy stream strings are
 * classified into non-healthy kinds so delivery, shortfall, and unavailable states cannot be
 * mistaken for a complete source. The synthetic final gap makes the frontend bound explicit; the
 * backend applies its own independent diagnosis bound after this conversion.
 */
export function mergeDiagnosisCoverageGaps(
  coverageDetails: readonly EvtxCoverageGap[],
  manifestCoverage: readonly EventLogSourceCoverage[],
  legacyCoverageGaps: readonly string[],
  tailCoverageGaps: readonly string[]
): EvtxCoverageGap[] {
  const typedManifestGaps: EvtxCoverageGap[] = manifestCoverage.map((gap) => ({
    source: gap.path,
    kind: gap.kind,
    reason: gap.reason,
  }));
  const formattedCoverageGaps = new Set(
    [...coverageDetails, ...typedManifestGaps].map(formatCoverageGap)
  );
  const legacyGaps = legacyCoverageGaps
    .filter((gap) => !formattedCoverageGaps.has(gap.trim()))
    .map((gap) => legacyCoverageGap(gap, "event-log"));
  const tailGaps = tailCoverageGaps
    .filter((gap) => !formattedCoverageGaps.has(gap.trim()))
    .map((gap) => legacyCoverageGap(gap, "live-tail"));
  const merged = mergeStructuredCoverageGaps(
    [],
    [...coverageDetails, ...typedManifestGaps, ...legacyGaps, ...tailGaps]
  );
  if (merged.length <= MAX_DIAGNOSIS_COVERAGE_GAPS) return merged;

  const omitted = merged.length - (MAX_DIAGNOSIS_COVERAGE_GAPS - 1);
  return [
    ...merged.slice(0, MAX_DIAGNOSIS_COVERAGE_GAPS - 1),
    {
      source: "frontend-diagnosis",
      kind: "limitReached",
      reason:
        `frontend coverage bound omitted ${omitted} additional gaps; ` +
        "backend diagnosis also enforces an input cap",
    },
  ];
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
 * destructures and iterates. Optional arrays may be omitted by older readers, but a present
 * malformed array fails at the boundary with a message naming its field and invalid index. A
 * present totalRecords count must be a nonnegative safe integer.
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
  archiveMembers: EvtxArchiveMember[];
  totalRecords: number | null;
} {
  const reply = value as {
    records?: unknown;
    channels?: unknown;
    errorMessages?: unknown;
    coverageGaps?: unknown;
    coverage?: unknown;
    archiveMembers?: unknown;
    totalRecords?: unknown;
  };
  if (!Array.isArray(reply?.records) || !Array.isArray(reply?.channels)) {
    throw new Error("the event log reader returned a reply this build cannot read");
  }
  const errorMessages = parseOptionalArray(
    reply.errorMessages,
    "errorMessages",
    (entry): entry is string => typeof entry === "string"
  );
  const coverageGaps = parseOptionalArray(reply.coverageGaps, "coverageGaps", isCoverageGap);
  const coverage = parseOptionalArray(reply.coverage, "coverage", isEventLogSourceCoverage);
  const totalRecords = reply.totalRecords;
  if (
    totalRecords !== undefined &&
    (typeof totalRecords !== "number" ||
      !Number.isSafeInteger(totalRecords) ||
      totalRecords < 0)
  ) {
    throw new Error("the event log reader returned an invalid totalRecords count");
  }
  return {
    records: reply.records,
    channels: reply.channels,
    // Absent means the reader reported no gaps, which is different from a malformed reply.
    errorMessages,
    coverageGaps,
    coverage,
    archiveMembers: parseArchiveMembers(reply.archiveMembers),
    // How many records the reader says it sent, counting any streamed separately from this reply.
    // `null` when the reader did not say, which must stay distinguishable from zero: treating an
    // absent count as zero would turn "I cannot check completeness" into "nothing was missing".
    totalRecords: totalRecords === undefined ? null : totalRecords,
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
