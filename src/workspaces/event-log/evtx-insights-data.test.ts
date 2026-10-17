import { describe, expect, it } from "vitest";
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import { countByLevel, EVTX_LEVELS } from "./evtx-filter";
import {
  buildSameIdSeries,
  correlationBreakdown,
  eventEvidenceLabel,
  findRecordById,
  findingForRecord,
  formatCount,
  redactedValueMatches,
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

describe("summarizeRecords level mix", () => {
  const all = EVTX_LEVELS.flatMap((level, index) =>
    Array.from({ length: index + 1 }, (_, copy) => record(index * 10 + copy, { level })),
  );

  it("lists the levels in EVTX_LEVELS order and omits a level with no records", () => {
    expect(summarizeRecords(all).levelMix.map((entry) => entry.level)).toEqual([...EVTX_LEVELS]);
    expect(
      summarizeRecords(all.filter((r) => r.level !== "Warning")).levelMix.map((entry) => entry.level),
    ).toEqual(["Critical", "Error", "Information", "Verbose"]);
  });

  it("counts exactly what the filter row's toggles count", () => {
    const counts = countByLevel(all);
    for (const entry of summarizeRecords(all).levelMix) expect(entry.count).toBe(counts[entry.level]);
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

const HOST = "[host:0123456789abcdef]";
const OTHER_HOST = "[host:fedcba9876543210]";
const USER = "[user:00112233445566ff]";

describe("redactedValueMatches", () => {
  it("compares a value with no token exactly", () => {
    expect(redactedValueMatches("Application", "Application")).toBe(true);
    expect(redactedValueMatches("Application", "System")).toBe(false);
  });

  it("matches a profile path with an embedded user token", () => {
    const evidence = `C:\\Users\\${USER}\\Downloads\\System.evtx`;
    expect(redactedValueMatches(evidence, "C:\\Users\\adam.gell\\Downloads\\System.evtx")).toBe(true);
    expect(redactedValueMatches(evidence, "C:\\Users\\adam.gell\\Downloads\\Other.evtx")).toBe(false);
    // A token stands for a non-empty segment.
    expect(redactedValueMatches(evidence, "C:\\Users\\\\Downloads\\System.evtx")).toBe(false);
  });

  it("matches a host-named bundle folder and a remote source", () => {
    expect(
      redactedValueMatches(`bundle\\${HOST}\\System.evtx`, "bundle\\LAB-PC-07\\System.evtx"),
    ).toBe(true);
    expect(redactedValueMatches(`Remote: ${HOST}`, "Remote: LAB-PC-07")).toBe(true);
    expect(redactedValueMatches(`Remote: ${HOST}`, "Local: LAB-PC-07")).toBe(false);
    expect(redactedValueMatches(HOST, "LAB-PC-07")).toBe(true);
  });

  it("treats regular-expression characters in the literal parts literally", () => {
    expect(redactedValueMatches(`a.b(${HOST})`, "a.b(PC)")).toBe(true);
    expect(redactedValueMatches(`a.b(${HOST})`, "aXb(PC)")).toBe(false);
  });

  it("anchors the pattern at both ends", () => {
    const evidence = `bundle\\${HOST}\\System.evtx`;
    expect(redactedValueMatches(evidence, "bundle\\PC\\System.evtx")).toBe(true);
    expect(redactedValueMatches(evidence, "old-bundle\\PC\\System.evtx")).toBe(false);
    expect(redactedValueMatches(evidence, "bundle\\PC\\System.evtx.bak")).toBe(false);
  });

  describe("digest-bounded identity fields (the real boundUtf8WithDigest)", () => {
    const long = `Microsoft-Windows-${"Very".repeat(80)}-Provider`;
    const bounded = boundUtf8WithDigest(long, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);

    it("bounds the value for real: a prefix plus the truncated suffix", () => {
      expect(bounded).not.toBe(long);
      expect(bounded).toMatch(/\u2026\[truncated:[0-9a-f]{16}\]$/);
    });

    it("matches the same long value, bounded the same way", () => {
      expect(redactedValueMatches(bounded, long)).toBe(true);
    });

    it("does not match another long value, even one sharing the prefix: the digest differs", () => {
      expect(redactedValueMatches(bounded, `${long}-other`)).toBe(false);
    });

    it("does not match a short record value, or treat an unbounded evidence value as bounded", () => {
      expect(redactedValueMatches(bounded, "short")).toBe(false);
      expect(redactedValueMatches("short", long)).toBe(false);
      expect(redactedValueMatches(long, long)).toBe(true);
    });

    it("strips the suffix before tokenizing, so it is not read as a redaction token", () => {
      // Without stripping, `[truncated:hex16]` would look like a token and match any digest.
      const other = boundUtf8WithDigest(`${long}x`, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
      expect(redactedValueMatches(other, long)).toBe(false);
    });

    it("matches a bounded value whose prefix had a machine name redacted", () => {
      const path = `bundle\\LAB-PC-07\\${"x".repeat(300)}.evtx`;
      const boundedPath = boundUtf8WithDigest(path, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
      const redacted = boundedPath.replace("LAB-PC-07", HOST);
      expect(redacted).not.toBe(boundedPath);
      expect(redactedValueMatches(redacted, path)).toBe(true);
      expect(
        redactedValueMatches(redacted, `bundle\\LAB-PC-07\\${"x".repeat(301)}.evtx`),
      ).toBe(false);
    });
  });
});

describe("findingForRecord", () => {
  const selected = record(1);
  const loaded = [selected, record(2)];
  it("matches event evidence on ID, provider and record", () => {
    const finding = findingWith(evidence({}));
    expect(findingForRecord([finding], selected, loaded)).toBe(finding);
  });
  it("does not match a different record, provider or channel", () => {
    for (const overrides of [{ recordId: 5 }, { provider: "Q" }, { channel: "System" }]) {
      expect(findingForRecord([findingWith(evidence(overrides))], selected, loaded)).toBeNull();
    }
  });
  it("matches the real redacted projection: host, user and path tokens inside longer strings", () => {
    const home = record(1, {
      computer: "LAB-PC-07",
      sourceLabel: "C:\\Users\\adam.gell\\Downloads\\System.evtx",
    });
    const ipc = findingWith(
      evidence({
        machine: HOST,
        source: `C:\\Users\\${USER}\\Downloads\\System.evtx`,
      }),
    );
    expect(findingForRecord([ipc], home, [home])).toBe(ipc);

    const bundle = record(1, { computer: "LAB-PC-07", sourceLabel: "bundle\\LAB-PC-07\\System.evtx" });
    const folder = findingWith(evidence({ machine: HOST, source: `bundle\\${HOST}\\System.evtx` }));
    expect(findingForRecord([folder], bundle, [bundle])).toBe(folder);

    const remote = record(1, { computer: "LAB-PC-07", sourceLabel: "Remote: LAB-PC-07" });
    const live = findingWith(evidence({ machine: HOST, source: `Remote: ${HOST}` }));
    expect(findingForRecord([live], remote, [remote])).toBe(live);
  });
  it("matches when the provider and channel were digest-bounded in transit", () => {
    const longProvider = `Microsoft-Windows-${"Very".repeat(80)}-Provider`;
    const longChannel = `${longProvider}/Admin`;
    const rec = record(1, { provider: longProvider, channel: longChannel });
    const bound = (value: string) =>
      boundUtf8WithDigest(value, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
    const finding = findingWith(
      evidence({ provider: bound(longProvider), channel: bound(longChannel) }),
    );
    expect(findingForRecord([finding], rec, [rec])).toBe(finding);
    // Another record whose long provider differs does not match, though the prefix is shared.
    const other = record(1, { provider: `${longProvider}-b`, channel: longChannel });
    expect(findingForRecord([finding], other, [other])).toBeNull();
  });
  it("rejects a different raw machine or source around a token", () => {
    const wrong = findingWith(evidence({ machine: "PC-2" }));
    expect(findingForRecord([wrong], selected, loaded)).toBeNull();
    const other = findingWith(evidence({ source: `b.evtx` }));
    expect(findingForRecord([other], selected, loaded)).toBeNull();
    const raw = findingWith(evidence({ machine: "PC-1", source: "a.evtx" }));
    expect(findingForRecord([raw], selected, loaded)).toBe(raw);
  });
  it("shows no match when two loaded records from different machines share every matched field", () => {
    const first = record(1, { computer: "LAB-PC-07", sourceLabel: "bundle\\LAB-PC-07\\System.evtx" });
    const twin = record(2, { computer: "LAB-PC-08", sourceLabel: "bundle\\LAB-PC-08\\System.evtx", eventRecordId: 1001 });
    // Both hosts are tokens, and the provider, channel, ID and record ID agree.
    const ipc = findingWith(evidence({ machine: HOST, source: `bundle\\${HOST}\\System.evtx` }));
    expect(findingForRecord([ipc], first, [first, twin])).toBeNull();
    expect(findingForRecord([ipc], twin, [first, twin])).toBeNull();
    // A different token for the other host changes nothing: the UI cannot tell which is which.
    const other = findingWith(evidence({ machine: OTHER_HOST, source: `bundle\\${OTHER_HOST}\\System.evtx` }));
    expect(findingForRecord([other], first, [first, twin])).toBeNull();
    // A raw machine tells them apart.
    const raw = findingWith(evidence({ machine: "LAB-PC-07", source: `bundle\\${HOST}\\System.evtx` }));
    expect(findingForRecord([raw], first, [first, twin])).toBe(raw);
    expect(findingForRecord([raw], twin, [first, twin])).toBeNull();
  });
  it("prefers the record id text, and never matches an unnumbered record or a fallback identity", () => {
    const withText = record(1, { eventRecordIdText: "88456" });
    expect(
      findingForRecord(
        [findingWith(evidence({ recordIdText: "88456", recordId: 7 }))],
        withText,
        [withText],
      ),
    ).not.toBeNull();
    const unnumbered = record(1, { eventRecordId: 0 });
    expect(
      findingForRecord([findingWith(evidence({ recordId: 0 }))], unnumbered, [unnumbered]),
    ).toBeNull();
    expect(
      findingForRecord(
        [findingWith(evidence({ recordId: 0, fallbackIdentity: "abcdef" }))],
        selected,
        loaded,
      ),
    ).toBeNull();
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

describe("findRecordById", () => {
  it("finds a record by index and falls back to a scan when ids are not indexes", () => {
    const records = [record(0), record(1), record(7)];
    expect(findRecordById(records, 1)).toBe(records[1]);
    expect(findRecordById(records, 7)).toBe(records[2]);
    expect(findRecordById(records, 99)).toBeNull();
    expect(findRecordById(records, null)).toBeNull();
  });
});
