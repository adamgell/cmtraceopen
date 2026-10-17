/**
 * How the diagnose command carries coverage gaps to the engine, as a pure projection.
 *
 * Kept apart from `commands.ts` so code that needs to know what the engine received (which input
 * ordinal is which caller gap) can compute it without the IPC module, which many tests replace.
 */
import { boundUtf8WithDigest } from "./bounded-utf8";
import type { EvtxCoverageGap } from "../workspaces/event-log/types";

export const EVENT_LOG_DIAGNOSIS_COVERAGE_FIELD_BYTE_LIMIT = 4 * 1024;
const EVENT_LOG_DIAGNOSIS_COVERAGE_GAP_LIMIT = 256;
const DIAGNOSIS_COVERAGE_PROJECTION_SOURCE = "diagnosis-input-projection";
const MAX_U64_TEXT = "18446744073709551615";

function canonicalCoverageRecordIdText(value: string): string {
  if (!/^\d+$/.test(value)) {
    throw new Error("EventRecordID text must be an unsigned decimal integer.");
  }
  let firstSignificant = 0;
  while (
    firstSignificant < value.length - 1 &&
    value.charCodeAt(firstSignificant) === 0x30
  ) {
    firstSignificant += 1;
  }
  const canonical = value.slice(firstSignificant);
  if (
    canonical.length > MAX_U64_TEXT.length ||
    (canonical.length === MAX_U64_TEXT.length && canonical > MAX_U64_TEXT)
  ) {
    throw new Error("EventRecordID text exceeds the unsigned 64-bit range.");
  }
  return canonical;
}

/**
 * The coverage gaps as the diagnose command sends them, and how many of the caller's gaps reach the
 * engine at their own ordinal. The engine echoes those ordinals on its rows (`inputIndices`); a
 * bounded transport keeps the first gaps and puts its notice after them, so the notice's ordinal
 * belongs to no caller gap.
 */
export function projectDiagnosisCoverageGaps(coverageGaps: EvtxCoverageGap[]): {
  gaps: EvtxCoverageGap[];
  ordinalCount: number;
} {
  let compactedFieldCount = 0;
  let transportChanged = false;
  const projected = coverageGaps.map((gap) => {
    const source = boundUtf8WithDigest(
      gap.source,
      EVENT_LOG_DIAGNOSIS_COVERAGE_FIELD_BYTE_LIMIT,
    );
    const reason = boundUtf8WithDigest(
      gap.reason,
      EVENT_LOG_DIAGNOSIS_COVERAGE_FIELD_BYTE_LIMIT,
    );
    const provider =
      gap.providerMessage === undefined
        ? undefined
        : boundUtf8WithDigest(
            gap.providerMessage.provider,
            EVENT_LOG_DIAGNOSIS_COVERAGE_FIELD_BYTE_LIMIT,
          );
    const eventRecordIdText =
      gap.eventRecordIdText === undefined
        ? undefined
        : canonicalCoverageRecordIdText(gap.eventRecordIdText);
    compactedFieldCount += Number(source !== gap.source);
    compactedFieldCount += Number(reason !== gap.reason);
    compactedFieldCount += Number(
      provider !== undefined && provider !== gap.providerMessage?.provider,
    );
    const unchanged =
      source === gap.source &&
      reason === gap.reason &&
      provider === gap.providerMessage?.provider &&
      eventRecordIdText === gap.eventRecordIdText;
    transportChanged ||= !unchanged;
    if (unchanged) return gap;
    return {
      ...gap,
      source,
      reason,
      ...(eventRecordIdText === undefined ? {} : { eventRecordIdText }),
      ...(gap.providerMessage === undefined
        ? {}
        : {
            providerMessage: {
              ...gap.providerMessage,
              provider: provider!,
            },
          }),
    };
  });

  if (
    compactedFieldCount === 0 &&
    projected.length <= EVENT_LOG_DIAGNOSIS_COVERAGE_GAP_LIMIT
  ) {
    return {
      gaps: transportChanged ? projected : coverageGaps,
      ordinalCount: coverageGaps.length,
    };
  }

  const retainedOriginalCount = Math.min(
    projected.length,
    EVENT_LOG_DIAGNOSIS_COVERAGE_GAP_LIMIT - 1,
  );
  const omittedOriginalGapCount = projected.length - retainedOriginalCount;
  const fieldLabel = compactedFieldCount === 1 ? "field" : "fields";
  const gapLabel = omittedOriginalGapCount === 1 ? "gap" : "gaps";
  return {
    gaps: [
      ...projected.slice(0, retainedOriginalCount),
      {
        source: DIAGNOSIS_COVERAGE_PROJECTION_SOURCE,
        kind: "limit",
        reason:
          `Diagnosis coverage transport compacted ${compactedFieldCount} oversized text ${fieldLabel} ` +
          `to ${EVENT_LOG_DIAGNOSIS_COVERAGE_FIELD_BYTE_LIMIT} UTF-8 bytes and omitted ` +
          `${omittedOriginalGapCount} original coverage ${gapLabel} to reserve this projection notice.`,
      },
    ],
    ordinalCount: retainedOriginalCount,
  };
}


/**
 * How many of `coverageGaps` reach the diagnosis engine at their own ordinal: all of them, unless
 * the transport bounds them (then the first ones, followed by its notice).
 */
export function diagnosisCoverageInputOrdinalCount(coverageGaps: EvtxCoverageGap[]): number {
  return projectDiagnosisCoverageGaps(coverageGaps).ordinalCount;
}
