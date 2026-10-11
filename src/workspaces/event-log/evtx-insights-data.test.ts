import { describe, expect, it } from "vitest";
import {
  buildSameIdSeries,
  correlationBreakdown,
  eventEvidenceLabel,
  findingForRecord,
  formatCount,
  neighborRecordId,
  summarizeRecords,
} from "./evtx-insights-data";
import type { DiagnosisFinding, DiagnosisSummary, EvtxRecord } from "./types";

function record(id: number, overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  return {
    id,
    eventRecordId: 1000 + id,
    timestamp: "",
    timestampEpoch: id * 1000,
    provider: "P",
    channel: "Application",
    eventId: 100,
    level: "Information",
    computer: "PC-1",
    message: "",
    eventData: [],
    rawXml: "",
    sourceLabel: "a.evtx",
    ...overrides,
  };
}

describe("summarizeRecords", () => {
  it("counts levels most severe first and ranks IDs by count then ID", () => {
    const summary = summarizeRecords([
      record(1, { level: "Warning", eventId: 7 }),
      record(2, { level: "Critical", eventId: 7 }),
      record(3, { level: "Warning", eventId: 3 }),
      record(4, { level: "Warning", eventId: 3 }),
    ]);
    expect(summary.total).toBe(4);
    expect(summary.levelMix).toEqual([
      { level: "Critical", count: 1 },
      { level: "Warning", count: 3 },
    ]);
    expect(summary.topEventIds).toEqual([
      { eventId: 3, count: 2 },
      { eventId: 7, count: 2 },
    ]);
  });
});

describe("buildSameIdSeries", () => {
  it("bins only records with a usable timestamp and never counts the rest as bin 0", () => {
    const selected = record(1, { timestampEpoch: 1000 });
    const window = [
      selected,
      record(2, { timestampEpoch: 5000 }),
      record(3, { timestampEpoch: 0 }),
      record(4, { timestampEpoch: Number.NaN }),
      record(5, { timestampEpoch: 9000, eventId: 999 }),
    ];
    const series = buildSameIdSeries(window, selected, 4);
    expect(series.occurrences).toBe(4);
    expect(series.bins.reduce((a, b) => a + b, 0)).toBe(2);
    expect(series.bins[0]).toBe(1);
    expect(series.firstEpoch).toBe(1000);
  });

  it("matches on the provider as well as the event ID", () => {
    const selected = record(1);
    const series = buildSameIdSeries([selected, record(2, { provider: "Other" })], selected);
    expect(series.occurrences).toBe(1);
  });

  it("returns no bins and no first time when no match has a usable timestamp", () => {
    const selected = record(1, { timestampEpoch: 0 });
    expect(buildSameIdSeries([selected], selected)).toEqual({
      occurrences: 1,
      bins: [],
      firstEpoch: null,
    });
  });

  it("puts a single instant in the first bin", () => {
    const selected = record(1, { timestampEpoch: 4000 });
    const series = buildSameIdSeries([selected], selected, 4);
    expect(series.bins).toEqual([1, 0, 0, 0]);
  });
});

describe("neighborRecordId", () => {
  const ordered = [record(1), record(2), record(3)];
  it("steps through the list and stops at the ends", () => {
    expect(neighborRecordId(ordered, 2, -1)).toBe(1);
    expect(neighborRecordId(ordered, 2, 1)).toBe(3);
    expect(neighborRecordId(ordered, 1, -1)).toBeNull();
    expect(neighborRecordId(ordered, 3, 1)).toBeNull();
  });
  it("has no neighbor for a hidden or absent selection", () => {
    expect(neighborRecordId(ordered, 99, 1)).toBeNull();
    expect(neighborRecordId(ordered, null, 1)).toBeNull();
  });
});

const evidence = (overrides: Record<string, unknown>) => ({
  kind: "event" as const,
  value: {
    source: "a.evtx",
    provider: "P",
    eventId: 100,
    recordId: 1001,
    ...overrides,
  },
});

function findingWith(...refs: ReturnType<typeof evidence>[]): DiagnosisFinding {
  return {
    findingId: "f",
    class: "confirmedFailure",
    severity: "error",
    confidence: "high",
    title: "t",
    summary: "s",
    evidence: refs,
    coverageGaps: [],
    recommendedChecks: [],
  };
}

describe("findingForRecord", () => {
  const selected = record(1);
  it("matches event evidence on ID, provider and record", () => {
    const finding = findingWith(evidence({}));
    expect(findingForRecord([finding], selected)).toBe(finding);
  });
  it("does not match a different record, provider, channel or machine", () => {
    for (const overrides of [
      { recordId: 5 },
      { provider: "Q" },
      { channel: "System" },
      { machine: "PC-2" },
    ]) {
      expect(findingForRecord([findingWith(evidence(overrides))], selected)).toBeNull();
    }
  });
  it("prefers the record id text, and never matches an unnumbered record", () => {
    const withText = record(1, { eventRecordIdText: "88456" });
    expect(
      findingForRecord([findingWith(evidence({ recordIdText: "88456", recordId: 7 }))], withText),
    ).not.toBeNull();
    const unnumbered = record(1, { eventRecordId: 0 });
    expect(findingForRecord([findingWith(evidence({ recordId: 0 }))], unnumbered)).toBeNull();
  });
});

describe("eventEvidenceLabel", () => {
  it("falls back from the record id text to the fallback identity to the record id", () => {
    const base = { source: "a", provider: "P", eventId: 1, recordId: 0 } as const;
    expect(eventEvidenceLabel({ ...base, recordIdText: "9" }, false)).toBe("1 · P · record 9");
    expect(eventEvidenceLabel({ ...base, fallbackIdentity: "0123456789" }, false)).toBe(
      "1 · P · ref 01234567",
    );
    expect(eventEvidenceLabel(base, false)).toBe("1 · P · no record ID");
    expect(eventEvidenceLabel({ ...base, recordId: 4 }, false)).toBe("1 · P · record 4");
  });
});

describe("correlationBreakdown", () => {
  it("keeps coverage-blocked, not-causal and timestamp-only edges out of the correlation total", () => {
    const edge = (status: string) => ({ status, left: "l", basis: "b", candidateIds: [], evidence: [] });
    const summary = {
      correlations: [edge("exact"), edge("candidate"), edge("coverageBlocked"), edge("notCausal")],
      overview: { correlationCount: 4 },
    } as unknown as DiagnosisSummary;
    const breakdown = correlationBreakdown(summary);
    expect(breakdown.correlations).toBe(2);
    expect(breakdown.coverageBlocked).toBe(1);
    expect(breakdown.complete).toBe(true);
  });
});

describe("formatCount", () => {
  it("uses the locale's thousands separator like the status bar", () => {
    expect(formatCount(1331)).toBe((1331).toLocaleString());
  });
});
