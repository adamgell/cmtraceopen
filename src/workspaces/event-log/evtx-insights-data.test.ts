import { describe, expect, it } from "vitest";
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import { countByLevel, EVTX_LEVELS } from "./evtx-filter";
import { displayReference } from "./evtx-engine-compaction-test-fixtures";
import {
  buildEvidenceIndex,
  buildSameIdSeries,
  describeScopeCounts,
  DIAGNOSIS_NESTED_ROW_CAP,
  DIAGNOSIS_PROJECTION_GAP_SOURCE,
  engineRecordIdentity,
  eventEvidenceLabel,
  evidenceMatchesRecord,
  findRecordById,
  findingForRecord,
  formatCount,
  redactedValueMatches,
  neighborRecordId,
  recordsForIdentity,
  scopeForFinding,
  summarizeRecords,
  summaryIsBounded,
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
  it("matches evidence the diagnosis compacted at 4096 bytes (compact_display_text), and only the record it was compacted from", () => {
    const longSource = `C:\\Users\\case.user\\Cases\\${"x".repeat(5000)}.evtx`;
    const longProvider = `Provider-${"y".repeat(4200)}`;
    const longChannel = `Channel/${"z".repeat(4100)}`;
    const longMachine = `HOST-${"m".repeat(4300)}`;
    const rec = record(1, {
      sourceLabel: longSource,
      provider: longProvider,
      channel: longChannel,
      computer: longMachine,
    });
    const compacted = {
      // The engine compacts first and redacts the kept prefix afterwards.
      source: displayReference(longSource).replace("case.user", USER),
      provider: displayReference(longProvider),
      channel: displayReference(longChannel),
      machine: displayReference(longMachine),
    };
    for (const text of Object.values(compacted)) expect(text).toMatch(/\.\.\.\[\d+ bytes; digest=[0-9a-f]{8}\]$/);
    const finding = findingWith(evidence(compacted));
    expect(findingForRecord([finding], rec, [rec])).toBe(finding);
    // The same prefix with another tail has another length and digest, and is not the record.
    for (const other of [
      record(1, { sourceLabel: `${longSource}z`, provider: longProvider, channel: longChannel, computer: longMachine }),
      record(1, { sourceLabel: longSource, provider: `${longProvider}z`, channel: longChannel, computer: longMachine }),
      record(1, { sourceLabel: longSource, provider: longProvider, channel: longChannel, computer: `${longMachine}z` }),
    ]) {
      expect(findingForRecord([finding], other, [other])).toBeNull();
    }
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

describe("engineRecordIdentity (the engine's rule, timeline.rs stable_event_id)", () => {
  it.each([
    ["7", 7, "7"],
    [" 7", 7, "7"],
    ["  42\t", 0, "42"],
    ["007", 7, "007"],
    ["000", 7, "7"],
    ["0", 7, "7"],
    ["", 7, "7"],
    ["x7", 7, "7"],
    ["7x", 7, "7"],
    ["-7", 7, "7"],
    [null, 7, "7"],
    [undefined, 7, "7"],
    ["000", 0, null],
    ["0", 0, null],
    ["", 0, null],
    [null, 0, null],
    ["x", 0, null],
    [" ", 0, null],
    ["x", -3, null],
    ["x", Number.NaN, null],
  ] as [string | null | undefined, number, string | null][])(
    "reads text %j with number %d as %j",
    (text, numericId, expected) => {
      expect(engineRecordIdentity(text, numericId)).toBe(expected);
    },
  );

  it("takes the text over a different number, as the engine does", () => {
    expect(engineRecordIdentity("42", 7)).toBe("42");
  });

  it("reads a number past the safe range as 2^53, which is how the transport sends it", () => {
    expect(engineRecordIdentity(null, Number.MAX_SAFE_INTEGER + 5)).toBe("9007199254740992");
    expect(engineRecordIdentity("9007199254740993", 9007199254740992)).toBe("9007199254740993");
  });

  it("keys a record by it, so padded, zero and non-digit text all land on the record the number names", () => {
    const plain = record(1, { eventId: 7, eventRecordId: 7, eventRecordIdText: "7" });
    const padded = record(2, { eventId: 7, eventRecordId: 7, eventRecordIdText: " 7" });
    const zero = record(3, { eventId: 7, eventRecordId: 7, eventRecordIdText: "000" });
    const text = record(4, { eventId: 7, eventRecordId: 7, eventRecordIdText: "x7" });
    const index = buildEvidenceIndex([plain, padded, zero, text]);
    expect(recordsForIdentity(index, 7, "7")).toEqual([plain, padded, zero, text]);
  });
});

describe("recordsForIdentity", () => {
  it("returns every loaded record for one event ID and record identity, in load order", () => {
    const first = record(1, { eventId: 7, eventRecordId: 42, eventRecordIdText: "42" });
    const twin = record(2, { eventId: 7, eventRecordId: 42, eventRecordIdText: "42", sourceLabel: "b.evtx" });
    const index = buildEvidenceIndex([first, twin, record(3, { eventId: 8, eventRecordId: 42 })]);
    expect(recordsForIdentity(index, 7, "42")).toEqual([first, twin]);
  });

  it("separates the event ID from the identity, so 7 and 42 is not 74 and 2", () => {
    const index = buildEvidenceIndex([record(1, { eventId: 7, eventRecordId: 42 })]);
    expect(recordsForIdentity(index, 74, "2")).toEqual([]);
    expect(recordsForIdentity(index, 7, "42")).toHaveLength(1);
  });

  it("is empty for an identity nothing loaded has, and for a record the provider never numbered", () => {
    const unnumbered = record(1, { eventRecordId: 0, eventRecordIdText: "0" });
    const index = buildEvidenceIndex([unnumbered]);
    expect(recordsForIdentity(index, 100, "0")).toEqual([]);
    expect(recordsForIdentity(index, 100, "5")).toEqual([]);
  });
});

describe("scopeForFinding", () => {
  const find = (finding: DiagnosisFinding, loaded: EvtxRecord[], engineBounded = false) =>
    scopeForFinding(finding, buildEvidenceIndex(loaded), engineBounded);
  const names = (list: EvtxRecord[]) => list.map((r) => r.id);

  it("resolves the loaded records the finding's event evidence names, once each", () => {
    const loaded = [record(1), record(2), record(3)];
    const finding = findingWith(
      evidence({ recordId: 1001 }),
      evidence({ recordId: 1003 }),
      evidence({ recordId: 1001 }),
    );
    const scope = find(finding, loaded);
    expect(names(scope.records)).toEqual([1, 3]);
    expect(scope.records[0]).toBe(loaded[0]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("resolves a record whose source label the engine compacted in the evidence, counting nothing as not loaded", () => {
    const longSource = `bundle\\${"d".repeat(5000)}\\System.evtx`;
    const loaded = [record(1, { sourceLabel: longSource }), record(2)];
    const scope = find(findingWith(evidence({ recordId: 1001, source: displayReference(longSource) })), loaded);
    expect(names(scope.records)).toEqual([1]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("is the set evidenceMatchesRecord selects, for every shape of reference", () => {
    const loaded = [
      record(1, { eventRecordIdText: "88456", eventRecordId: 88456 }),
      record(2, { provider: "Q" }),
      record(3, { computer: "LAB-PC-07", sourceLabel: "bundle\\LAB-PC-07\\System.evtx" }),
      record(4, { eventId: 7 }),
      record(5, { eventRecordId: 0 }),
    ];
    const refs = [
      evidence({ recordIdText: "88456", recordId: 88456 }),
      evidence({ recordId: 1002, provider: "Q" }),
      evidence({ recordId: 1003, machine: HOST, source: `bundle\\${HOST}\\System.evtx` }),
      evidence({ recordId: 1004, eventId: 7 }),
      evidence({ recordId: 1004, eventId: 8 }),
      evidence({ recordId: 1001 }),
    ];
    const finding = findingWith(...refs);
    const brute = loaded.filter((r) =>
      refs.some((ref) => evidenceMatchesRecord(ref.value, r)),
    );
    expect(find(finding, loaded).records).toEqual(brute);
    expect(brute.length).toBeGreaterThan(3);
  });

  it("resolves a value that was digest-bounded in transit, and not one with another digest", () => {
    const longSource = `C:\\${"deep\\".repeat(80)}System.evtx`;
    const loaded = [record(1, { sourceLabel: longSource })];
    const bound = boundUtf8WithDigest(longSource, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
    expect(find(findingWith(evidence({ source: bound })), loaded).records).toEqual(loaded);

    const other = boundUtf8WithDigest(`${longSource}x`, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);
    const wrong = find(findingWith(evidence({ source: other })), loaded);
    expect(wrong.records).toEqual([]);
    expect(wrong.counts.notLoaded).toBe(1);
  });

  it("resolves a record id too large for a number through its text, not its numeric stand-in", () => {
    const huge = record(1, { eventRecordIdText: "18446744073709551615", eventRecordId: 9007199254740991 });
    const scope = find(
      findingWith(evidence({ recordIdText: "18446744073709551615", recordId: 9007199254740991 })),
      [huge, record(2, { eventRecordId: 9007199254740991 })],
    );
    expect(scope.records).toEqual([huge]);
  });

  it("counts a reference that names no loaded record as not loaded", () => {
    const scope = find(findingWith(evidence({ recordId: 1001 }), evidence({ recordId: 9999 })), [record(1)]);
    expect(names(scope.records)).toEqual([1]);
    expect(scope.counts.notLoaded).toBe(1);
    expect(scope.counts.noUsableIdentity).toBe(0);
  });

  it("counts a reference with no usable identity apart from one that is not loaded", () => {
    const loaded = [record(1)];
    const scope = find(
      findingWith(
        evidence({ recordId: 0, fallbackIdentity: "abcdef0123456789" }),
        evidence({ recordId: 0 }),
        evidence({ recordId: 5555 }),
      ),
      loaded,
    );
    expect(scope.records).toEqual([]);
    expect(scope.counts).toMatchObject({ noUsableIdentity: 2, notLoaded: 1 });
  });

  it("includes every candidate of an ambiguous reference and counts it", () => {
    const first = record(1, { sourceLabel: "bundle\\LAB-PC-07\\System.evtx", computer: "LAB-PC-07" });
    const twin = record(2, { sourceLabel: "bundle\\LAB-PC-08\\System.evtx", computer: "LAB-PC-08", eventRecordId: 1001 });
    // The reference names neither source nor machine, so it fits both.
    const scope = find(findingWith(evidence({ source: undefined, machine: undefined })), [first, twin]);
    expect(scope.records).toEqual([first, twin]);
    expect(scope.counts.ambiguous).toBe(1);
  });

  it("ignores evidence that is not an event and does not count it", () => {
    const finding = findingWith(evidence({ recordId: 1001 }));
    finding.evidence = [
      ...finding.evidence,
      { kind: "textLog", value: { source: "s", filePath: "f", lineNumber: 1, entryId: 1 } },
      { kind: "dsregcmdRaw", value: "raw" },
    ];
    const scope = find(finding, [record(1)]);
    expect(names(scope.records)).toEqual([1]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("marks the scope bounded at the engine's evidence cap, and when the response was bounded", () => {
    const refs = (n: number) => Array.from({ length: n }, (_, i) => evidence({ recordId: 1001 + i }));
    const loaded = [1, 2, 3, 4, 5].map((n) => record(n));
    expect(find(findingWith(...refs(DIAGNOSIS_NESTED_ROW_CAP - 1)), loaded).counts.bounded).toBe(false);
    expect(find(findingWith(...refs(DIAGNOSIS_NESTED_ROW_CAP)), loaded).counts.bounded).toBe(true);
    expect(find(findingWith(...refs(1)), loaded, true).counts.bounded).toBe(true);
  });

  it("is an empty scope for a finding that cites no event", () => {
    const finding = findingWith();
    expect(find(finding, [record(1)])).toEqual({
      records: [],
      references: [],
      counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
    });
  });

  describe("counts references, not records", () => {
    it("counts one event cited twice once, loaded or not", () => {
      const loaded = [record(1)];
      const unloadedTwice = find(findingWith(evidence({ recordId: 9999 }), evidence({ recordId: 9999 })), loaded);
      expect(unloadedTwice.counts.notLoaded).toBe(1);
      expect(unloadedTwice.references).toEqual([[]]);

      const loadedTwice = find(findingWith(evidence({ recordId: 1001 }), evidence({ recordId: 1001 })), loaded);
      expect(loadedTwice.references).toEqual([[loaded[0]]]);
      expect(loadedTwice.records).toEqual(loaded);
    });

    it("counts a reference with no usable identity once however often it is cited", () => {
      const hash = { recordId: 0, fallbackIdentity: "abcdef0123456789" };
      const scope = find(findingWith(evidence(hash), evidence(hash), evidence({ ...hash, fallbackIdentity: "0123456789abcdef" })), [
        record(1),
      ]);
      expect(scope.counts.noUsableIdentity).toBe(2);
      expect(scope.references).toEqual([]);
    });

    it("keeps the same record ID from two sources as two references", () => {
      const a = record(1, { sourceLabel: "a.evtx" });
      const b = record(2, { sourceLabel: "b.evtx", eventRecordId: 1001 });
      const scope = find(findingWith(evidence({ source: "a.evtx" }), evidence({ source: "b.evtx" })), [a, b]);
      expect(scope.references).toEqual([[a], [b]]);
      expect(scope.counts).toMatchObject({ notLoaded: 0, ambiguous: 0 });
    });

    it("gives each distinct reference its own candidate set, and derives the counts from them", () => {
      const a = record(1);
      const b1 = record(2, { eventRecordId: 1002, sourceLabel: "x1.evtx" });
      const b2 = record(3, { eventRecordId: 1002, sourceLabel: "x2.evtx" });
      const scope = find(
        findingWith(
          evidence({ recordId: 1001 }),
          evidence({ recordId: 1002, source: undefined }),
          evidence({ recordId: 7777 }),
        ),
        [a, b1, b2],
      );
      expect(scope.references).toEqual([[a], [b1, b2], []]);
      expect(scope.records).toEqual([a, b1, b2]);
      expect(scope.counts).toEqual({ notLoaded: 1, noUsableIdentity: 0, ambiguous: 1, bounded: false });
    });
  });
});

describe("evidence identity follows the engine's rule, as the record and the origin do (J3)", () => {
  const scopeOf = (evidenceValue: Record<string, unknown>, loaded: EvtxRecord[]) =>
    scopeForFinding(findingWith(evidence(evidenceValue)), buildEvidenceIndex(loaded), false);

  it("reads evidence with all-zero text and no number as having no usable identity, never as not loaded", () => {
    const scope = scopeOf({ recordIdText: "000", recordId: 0 }, [record(1)]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 1, ambiguous: 0, bounded: false });
    expect(scope.references).toEqual([]);
  });

  it("ignores all-zero evidence text and falls back to the number, as the engine does", () => {
    const loaded = record(7, { eventRecordId: 7, eventRecordIdText: "7" });
    const scope = scopeOf({ recordIdText: "000", recordId: 7 }, [loaded]);
    expect(scope.references).toEqual([[loaded]]);
    expect(evidenceMatchesRecord(evidence({ recordIdText: "000", recordId: 7 }).value, loaded)).toBe(true);
  });

  it("falls back to the fallback identity, which a record cannot reproduce, when the text is all zero", () => {
    const loaded = record(7, { eventRecordId: 7, eventRecordIdText: "7" });
    const scope = scopeOf({ recordIdText: "000", fallbackIdentity: "abc123", recordId: 7 }, [loaded]);
    expect(scope.counts).toMatchObject({ noUsableIdentity: 1, notLoaded: 0 });
    expect(evidenceMatchesRecord(evidence({ fallbackIdentity: "abc123", recordId: 7 }).value, loaded)).toBe(false);
  });

  it("lets usable text win over a fallback identity and over a different number", () => {
    const loaded = record(7, { eventRecordId: 42, eventRecordIdText: "42" });
    const value = evidence({ recordIdText: "42", fallbackIdentity: "abc123", recordId: 7 }).value;
    expect(evidenceMatchesRecord(value, loaded)).toBe(true);
  });

  it("reads padded evidence text as the trimmed text, on either side", () => {
    const plain = record(1, { eventRecordId: 7, eventRecordIdText: "7" });
    const padded = record(2, { eventRecordId: 7, eventRecordIdText: " 7" });
    for (const text of [" 7", "7", "  7\t"]) {
      const scope = scopeOf({ recordIdText: text, recordId: 7 }, [plain, padded]);
      expect(scope.references, JSON.stringify(text)).toEqual([[plain, padded]]);
      expect(scope.counts.ambiguous, JSON.stringify(text)).toBe(1);
    }
  });

  it("takes padded text as the text, not as a reason to use the number", () => {
    // The number differs from the text, so only the trimmed text names this record.
    const loaded = record(5, { eventRecordId: 42, eventRecordIdText: "42" });
    expect(evidenceMatchesRecord(evidence({ recordIdText: " 42 ", recordId: 7 }).value, loaded)).toBe(true);
    expect(evidenceMatchesRecord(evidence({ recordIdText: " 43 ", recordId: 42 }).value, loaded)).toBe(false);
  });

  it("matches a loaded record whose own text is all zero by the number, from either shape of evidence", () => {
    const zero = record(3, { eventRecordId: 7, eventRecordIdText: "000" });
    for (const evidenceValue of [{ recordIdText: "7", recordId: 7 }, { recordId: 7 }, { recordIdText: "000", recordId: 7 }]) {
      expect(scopeOf(evidenceValue, [zero]).references, JSON.stringify(evidenceValue)).toEqual([[zero]]);
    }
  });

  it("keeps a number-only reference with no number as no usable identity", () => {
    const scope = scopeOf({ recordId: 0 }, [record(1)]);
    expect(scope.counts).toMatchObject({ noUsableIdentity: 1, notLoaded: 0 });
  });
});

describe("summaryIsBounded", () => {
  const gap = (source: string) => ({ id: "g", source, state: "capped" as const, detail: "", evidence: [] });
  const summary = (overrides: Partial<DiagnosisSummary>): DiagnosisSummary =>
    ({ findings: [], coverageGaps: [], evidence: [], correlations: [], events: [], ...overrides }) as unknown as DiagnosisSummary;

  it("is true when the engine's projection gap is present, in the summary or on a finding", () => {
    expect(summaryIsBounded(summary({ coverageGaps: [gap(DIAGNOSIS_PROJECTION_GAP_SOURCE)] }))).toBe(true);
    const finding = { ...findingWith(), coverageGaps: [gap(DIAGNOSIS_PROJECTION_GAP_SOURCE)] };
    expect(summaryIsBounded(summary({ findings: [finding] }))).toBe(true);
  });

  it("is false for any other coverage gap", () => {
    expect(summaryIsBounded(summary({ coverageGaps: [gap("System.evtx")] }))).toBe(false);
    expect(summaryIsBounded(summary({}))).toBe(false);
  });
});

describe("describeScopeCounts", () => {
  const counts = (overrides: Partial<Parameters<typeof describeScopeCounts>[0]>) => ({
    notLoaded: 0,
    noUsableIdentity: 0,
    ambiguous: 0,
    bounded: false,
    ...overrides,
  });

  it("says nothing when the scope fell short in no way", () => {
    expect(describeScopeCounts(counts({}), "finding")).toEqual([]);
  });

  it("names each class on its own line, in a fixed order", () => {
    expect(
      describeScopeCounts(counts({ notLoaded: 2, noUsableIdentity: 1, ambiguous: 3, bounded: true }), "finding"),
    ).toEqual([
      "2 cited events are not loaded.",
      "1 cited event cannot be matched to a loaded event: no usable record identity.",
      "3 cited references match more than one loaded event. Every match is included.",
      "The diagnosis response is bounded, so this finding may cite more events than were sent.",
    ]);
  });

  it("names references it could not look for apart from ones that are not loaded, and claims no absence", () => {
    expect(describeScopeCounts(counts({ unresolved: 3 }), "finding")).toEqual([
      "3 cited entries could not be matched to a record because their timeline items were not read.",
    ]);
    expect(describeScopeCounts(counts({ unresolved: 1 }), "finding")).toEqual([
      "1 cited entry could not be matched to a record because its timeline item was not read.",
    ]);
    const text = describeScopeCounts(counts({ unresolved: 5 }), "finding").join(" ");
    expect(text).not.toMatch(/not loaded|no record|absent|missing/);
  });

  it("puts the unresolved sentence after no usable identity and before ambiguous", () => {
    expect(
      describeScopeCounts(counts({ notLoaded: 1, noUsableIdentity: 1, unresolved: 1, ambiguous: 1 }), "finding"),
    ).toEqual([
      "1 cited event is not loaded.",
      "1 cited event cannot be matched to a loaded event: no usable record identity.",
      "1 cited entry could not be matched to a record because its timeline item was not read.",
      "1 cited reference matches more than one loaded event. Every match is included.",
    ]);
  });

  describe("for a chain scope", () => {
    it("names each class in a chain's words, in the same fixed order", () => {
      expect(
        describeScopeCounts(
          counts({ notLoaded: 2, noUsableIdentity: 1, unresolved: 4, ambiguous: 3, bounded: true }),
          "chain",
        ),
      ).toEqual([
        "2 events of this chain are not loaded.",
        "1 event of this chain cannot be matched to a loaded event: no usable record identity.",
        "4 entries of this chain could not be matched to a record because their timeline items were not read.",
        "3 entries of this chain match more than one loaded event. Every match is included.",
        "Edges were not all loaded, so this chain may include more events.",
      ]);
    });

    it("uses the singular for one", () => {
      expect(describeScopeCounts(counts({ notLoaded: 1 }), "chain")).toEqual(["1 event of this chain is not loaded."]);
      expect(describeScopeCounts(counts({ unresolved: 1 }), "chain")).toEqual([
        "1 entry of this chain could not be matched to a record because its timeline item was not read.",
      ]);
      expect(describeScopeCounts(counts({ ambiguous: 1 }), "chain")).toEqual([
        "1 entry of this chain matches more than one loaded event. Every match is included.",
      ]);
    });

    it("never speaks of a finding, a citation or a diagnosis response", () => {
      const text = describeScopeCounts(
        counts({ notLoaded: 2, noUsableIdentity: 1, unresolved: 4, ambiguous: 3, bounded: true }),
        "chain",
      ).join(" ");
      expect(text).not.toMatch(/cited|cite|finding|diagnosis response/i);
    });

    it("claims no absence for an entry whose item was not read", () => {
      const text = describeScopeCounts(counts({ unresolved: 5 }), "chain").join(" ");
      expect(text).not.toMatch(/not loaded|no record|absent|missing/);
    });

    it("keeps a finding's words for the same counts", () => {
      const same = counts({ notLoaded: 2, bounded: true });
      expect(describeScopeCounts(same, "finding")).not.toEqual(describeScopeCounts(same, "chain"));
      expect(describeScopeCounts(same, "finding").join(" ")).toMatch(/cited events are not loaded/);
      expect(describeScopeCounts(same, "finding").join(" ")).toMatch(/diagnosis response is bounded/);
    });
  });

  it("uses the singular for one", () => {
    expect(describeScopeCounts(counts({ notLoaded: 1 }), "finding")).toEqual(["1 cited event is not loaded."]);
    expect(describeScopeCounts(counts({ ambiguous: 1 }), "finding")).toEqual([
      "1 cited reference matches more than one loaded event. Every match is included.",
    ]);
  });
});
