/**
 * The join between timeline origins and loaded event records.
 *
 * `originOf` builds an origin the way the engine does (`origin_of` in event_log/timeline.rs): the
 * provider, channel, source label and machine are the record's, bounded to the transport's
 * identity limit and the machine normalized. Its stable id is deliberately opaque: the join must
 * never read it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import fixtureDocument from "./__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  itemsByOriginId,
  linkCountsByRecord,
  linkPartnerCounts,
  originIdentityText,
  resolveOriginRecords,
  scopeForChain,
  soleRecordForOrigin,
} from "./evtx-correlation-origin-index";
import { buildEvidenceIndex } from "./evtx-insights-data";
import type { EvtxRecord } from "./types";
import {
  assertUnifiedTimelineShape,
  timelineOriginId,
  type TimelineCorrelationEdge,
  type TimelineItem,
  type TimelineOrigin,
} from "./unified-timeline";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => undefined)),
}));
// Imported after the mocks: the store subscribes to the bridge at module scope.
const { useEvtxStore } = await import("./evtx-store");

type EventOrigin = Extract<TimelineOrigin, { kind: "event" }>;

const bounded = (value: string) =>
  boundUtf8WithDigest(value, EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT);

function record(recordId: number, overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  return {
    id: recordId,
    eventRecordId: recordId,
    eventRecordIdText: String(recordId),
    timestamp: "",
    timestampEpoch: 1_000 * recordId,
    provider: "Provider",
    channel: "System",
    eventId: 100,
    level: "Information",
    computer: "DESKTOP-01",
    message: `message ${recordId}`,
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
    ...overrides,
  };
}

/** The engine's placeholder words, copied from `normalized_provenance` (event_log/timeline.rs). */
const ENGINE_NO_PROVENANCE = [
  "unknown",
  "n/a",
  "na",
  "none",
  "null",
  "not available",
  "not_applicable",
];

function normalizedMachine(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === "" || ENGINE_NO_PROVENANCE.includes(trimmed.toLowerCase()) ? null : trimmed;
}

/** The engine's `record_id_text`: the trimmed text when it is all digits, else none. */
function engineRecordIdText(text: string | null | undefined): string | null {
  const trimmed = (text ?? "").trim();
  return /^\d+$/.test(trimmed) ? trimmed : null;
}

function originOf(source: EvtxRecord, overrides: Partial<EventOrigin> = {}): EventOrigin {
  return {
    kind: "event",
    // Opaque on purpose: nothing may be parsed out of it.
    stableId: `opaque-${source.sourceLabel}-${source.eventRecordId}`,
    source: bounded(source.sourceLabel),
    machine: normalizedMachine(bounded(source.computer)),
    bundle: null,
    channel: bounded(source.channel),
    provider: bounded(source.provider),
    processId: null,
    eventId: source.eventId,
    recordId: source.eventRecordId,
    recordIdText: engineRecordIdText(source.eventRecordIdText),
    ...overrides,
  };
}

function itemOf(origin: TimelineOrigin, timestampMs = 1_000): TimelineItem {
  return { timestampMs, severity: "info", message: "m", origin };
}

const indexOf = (records: EvtxRecord[]) => buildEvidenceIndex(records);

describe("resolveOriginRecords: the strict field join", () => {
  it("names the one record whose event ID, identity, provider, channel, source and machine all agree", () => {
    const wanted = record(42);
    const resolution = resolveOriginRecords(
      originOf(wanted),
      indexOf([record(41), wanted, record(43)]),
    );
    expect(resolution).toEqual({ kind: "matches", records: [wanted] });
  });

  it.each([
    ["event ID", { eventId: 101 }],
    ["provider", { provider: "Other" }],
    ["channel", { channel: "Application" }],
    ["source label", { sourceLabel: "Other.evtx" }],
    ["machine", { computer: "DESKTOP-02" }],
    ["record identity", { eventRecordId: 43, eventRecordIdText: "43" }],
  ] satisfies [string, Partial<EvtxRecord>][])(
    "does not name a record that differs in its %s",
    (_label, change) => {
      const origin = originOf(record(42));
      const other = record(42, change);
      expect(resolveOriginRecords(origin, indexOf([other]))).toEqual({
        kind: "matches",
        records: [],
      });
    },
  );

  it("never reads the stable id: a lying one changes nothing", () => {
    const wanted = record(42);
    const index = indexOf([wanted]);
    for (const stableId of ["", "x|missing-1", "source4:Live|machine10:DESKTOP-01|channel6:System|record7"]) {
      expect(soleRecordForOrigin(originOf(wanted, { stableId }), index)).toBe(wanted);
    }
  });

  it("treats an origin with no usable identity as matching nothing, from its fields and not its stable id", () => {
    const unnumbered = record(0, { eventRecordIdText: "0" });
    const index = indexOf([unnumbered, record(42)]);
    for (const origin of [
      // The stable id of a numbered record, on an origin whose fields carry no identity.
      originOf(unnumbered, {
        stableId: "source4:Live|machine10:DESKTOP-01|channel6:System|record42",
        recordId: 0,
        recordIdText: null,
      }),
      originOf(unnumbered, { recordId: 0, recordIdText: "0" }),
      originOf(unnumbered, { recordId: 0, recordIdText: "000" }),
      originOf(unnumbered, { recordId: 0, recordIdText: "" }),
      originOf(unnumbered, { recordId: 0, recordIdText: "not digits" }),
    ]) {
      expect(resolveOriginRecords(origin, index)).toEqual({ kind: "noUsableIdentity" });
    }
  });

  it("matches a numbered record whose stable id would read as missing", () => {
    const wanted = record(9);
    expect(
      soleRecordForOrigin(originOf(wanted, { stableId: "x|missingdeadbeef-3" }), indexOf([wanted])),
    ).toBe(wanted);
  });

  it("reads identity in the engine's order: a usable text, then a non-zero number", () => {
    const base = record(5);
    expect(originIdentityText(originOf(base, { recordIdText: "00042", recordId: 7 }))).toBe("00042");
    expect(originIdentityText(originOf(base, { recordIdText: " 42 ", recordId: 7 }))).toBe("42");
    expect(originIdentityText(originOf(base, { recordIdText: "000", recordId: 7 }))).toBe("7");
    expect(originIdentityText(originOf(base, { recordIdText: null, recordId: 7 }))).toBe("7");
    expect(originIdentityText(originOf(base, { recordIdText: null, recordId: 0 }))).toBeNull();
    expect(originIdentityText(originOf(base, { recordIdText: "x", recordId: 0 }))).toBeNull();
  });

  it("matches a record that only carries the numeric identity", () => {
    const numeric = record(42, { eventRecordIdText: undefined });
    expect(soleRecordForOrigin(originOf(numeric, { recordIdText: null }), indexOf([numeric]))).toBe(
      numeric,
    );
  });

  describe("one identity rule for the record side and the origin side (the engine's)", () => {
    const twin = () => record(7, { eventRecordIdText: "7" });

    it.each([
      ["padded text", " 7"],
      ["all-zero text", "000"],
      ["text that is not digits", "x7"],
      ["empty text", ""],
    ])("reads a record with %s and number 7 as record 7, so it and a twin with text '7' are both named", (_label, text) => {
      const odd = record(7, { eventRecordIdText: text });
      const other = twin();
      const index = indexOf([odd, other]);
      for (const wanted of [odd, other]) {
        const resolution = resolveOriginRecords(originOf(wanted), index);
        expect(resolution).toEqual({ kind: "matches", records: [odd, other] });
      }
    });

    it.each([" 7", "000", "x7", ""])("finds a record with text %j on its own", (text) => {
      const odd = record(7, { eventRecordIdText: text });
      expect(soleRecordForOrigin(originOf(odd), indexOf([odd]))).toBe(odd);
    });

    it("keeps leading zeros in usable digit text, as the engine's stable id does", () => {
      const padded = record(7, { eventRecordIdText: "007" });
      const plain = record(7, { eventRecordIdText: "7" });
      expect(soleRecordForOrigin(originOf(padded), indexOf([padded, plain]))).toBe(padded);
      expect(soleRecordForOrigin(originOf(plain), indexOf([padded, plain]))).toBe(plain);
    });
  });

  it("keeps two archives apart by their source label", () => {
    const a = record(42, { sourceLabel: "a.evtx" });
    const b = record(42, { sourceLabel: "b.evtx" });
    const index = indexOf([a, b]);
    expect(soleRecordForOrigin(originOf(a), index)).toBe(a);
    expect(soleRecordForOrigin(originOf(b), index)).toBe(b);
  });

  it("reports identical duplicates, such as the same archive loaded twice, as one ambiguous reference with every candidate", () => {
    const first = record(42);
    const twin = record(42);
    const resolution = resolveOriginRecords(originOf(first), indexOf([first, twin]));
    expect(resolution).toEqual({ kind: "matches", records: [first, twin] });
    expect(soleRecordForOrigin(originOf(first), indexOf([first, twin]))).toBeNull();
  });

  it("is not a record for a text-log origin", () => {
    const origin: TimelineOrigin = {
      kind: "log",
      file: "C:\\Logs\\a.log",
      component: null,
      line: 1,
      source: "a.cpp",
      machine: null,
      bundle: null,
      recordId: 1,
    };
    expect(resolveOriginRecords(origin, indexOf([record(1)]))).toEqual({ kind: "notEvent" });
    expect(soleRecordForOrigin(origin, indexOf([record(1)]))).toBeNull();
  });

  describe("the engine's bounding and normalization of identity fields", () => {
    const long = (tail: string) => `C:\\${"Archive".repeat(60)}\\${tail}.evtx`;

    it("matches a source label the transport bounded with a digest, and not a different long one with the same prefix", () => {
      const wanted = record(42, { sourceLabel: long("one") });
      const lookalike = record(42, { sourceLabel: long("two") });
      expect(bounded(wanted.sourceLabel)).toMatch(/truncated:/);
      const origin = originOf(wanted);
      expect(origin.source).toBe(bounded(wanted.sourceLabel));
      const index = indexOf([wanted, lookalike]);
      expect(resolveOriginRecords(origin, index)).toEqual({ kind: "matches", records: [wanted] });
    });

    it("matches a machine the transport bounded", () => {
      const wanted = record(42, { computer: `HOST-${"X".repeat(400)}` });
      expect(soleRecordForOrigin(originOf(wanted), indexOf([wanted]))).toBe(wanted);
      const other = record(42, { computer: `HOST-${"Y".repeat(400)}` });
      expect(soleRecordForOrigin(originOf(wanted), indexOf([other]))).toBeNull();
    });

    it("reads a machine of padding or a placeholder word as no machine, on both sides", () => {
      for (const computer of ["", "   ", "unknown", "N/A", "None"]) {
        const wanted = record(42, { computer });
        const origin = originOf(wanted);
        expect(origin.machine).toBeNull();
        expect(soleRecordForOrigin(origin, indexOf([wanted])), computer).toBe(wanted);
        // An origin with no machine does not name a record that has one.
        expect(soleRecordForOrigin(origin, indexOf([record(42)])), computer).toBeNull();
      }
    });

    it.each(ENGINE_NO_PROVENANCE)(
      "reads the engine's placeholder %j as no machine, in any case and padding",
      (word) => {
        for (const computer of [word, word.toUpperCase(), `  ${word}  `, word[0]!.toUpperCase() + word.slice(1)]) {
          const wanted = record(42, { computer });
          const origin = originOf(wanted);
          expect(origin.machine, `engine: ${computer}`).toBeNull();
          // The record side must reach the same answer, or this record would read as not loaded.
          expect(soleRecordForOrigin(origin, indexOf([wanted])), `join: ${computer}`).toBe(wanted);
        }
      },
    );

    it("does not read a longer word that merely contains a placeholder as no machine", () => {
      for (const computer of ["unknown-host", "nan", "nonexistent", "n/a1"]) {
        const wanted = record(42, { computer });
        expect(originOf(wanted).machine, computer).toBe(computer);
        expect(soleRecordForOrigin(originOf(wanted), indexOf([wanted])), computer).toBe(wanted);
      }
    });

    it("trims a machine as the engine does", () => {
      const wanted = record(42, { computer: "  DESKTOP-01  " });
      const origin = originOf(wanted);
      expect(origin.machine).toBe("DESKTOP-01");
      expect(soleRecordForOrigin(origin, indexOf([wanted]))).toBe(wanted);
    });
  });

  it("holds records by object, so a renumbered id changes nothing", () => {
    const wanted = record(42);
    const origin = originOf(wanted);
    expect(soleRecordForOrigin(origin, indexOf([wanted]))).toBe(wanted);
    wanted.id = 9_999;
    expect(soleRecordForOrigin(origin, indexOf([wanted]))).toBe(wanted);
  });
});

/** The fixture's origin id of record `n`: the engine's own id format, used here only as an opaque key. */
const rid = (n: number) => `source4:Live|machine10:DESKTOP-01|channel6:System|record${n}`;

function fixtureEdges(name: string): TimelineCorrelationEdge[] {
  const scenarios = fixtureDocument.scenarios as unknown as Record<
    string,
    { edges: unknown[]; coverageGaps: unknown[] }
  >;
  const scenario = scenarios[name];
  if (scenario === undefined) throw new Error(`no fixture scenario ${name}`);
  return assertUnifiedTimelineShape({
    items: [],
    unplaced: [],
    edges: scenario.edges,
    coverageGaps: scenario.coverageGaps,
  }).edges;
}

/** A record and its timeline item for fixture record `n`, shaped like the engine's for that id. */
function fixturePair(n: number) {
  const source = record(n, { eventId: 100 + n });
  const origin = originOf(source, { stableId: rid(n) });
  return { source, item: itemOf(origin, 1_000 * n) };
}

describe("scopeForChain", () => {
  it("scopes a real exact pair to its two records, one reference each, and counts nothing missing", () => {
    const pairs = [1, 2].map(fixturePair);
    const model = buildCorrelationChains({
      items: pairs.map((pair) => pair.item),
      timelineEdges: fixtureEdges("exactPair"),
      totalTimelineEdges: 1,
      findings: [],
    });
    const chain = model.chains[0]!;
    expect(chain.strength).toBe("exact");
    const scope = scopeForChain(
      chain,
      itemsByOriginId(pairs.map((pair) => pair.item)),
      indexOf(pairs.map((pair) => pair.source)),
      { edgeInputComplete: model.edgeInputComplete },
    );
    expect(scope.records).toEqual(pairs.map((pair) => pair.source));
    expect(scope.references).toEqual(pairs.map((pair) => [pair.source]));
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("always returns one reference per event member, so a scope can be pruned by reference", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      itemsByOriginId([a.item, b.item]),
      indexOf([a.source, b.source]),
      { edgeInputComplete: true },
    );
    expect(scope.references).toBeDefined();
    expect(scope.references).toHaveLength(2);
  });

  it("marks the scope bounded when edges were not all loaded, and not otherwise", () => {
    const a = fixturePair(1);
    const chain = { memberIds: [rid(1)], unresolvedMemberIds: [] };
    const items = itemsByOriginId([a.item]);
    const index = indexOf([a.source]);
    expect(scopeForChain(chain, items, index, { edgeInputComplete: false }).counts.bounded).toBe(true);
    expect(scopeForChain(chain, items, index, { edgeInputComplete: true }).counts.bounded).toBe(false);
  });

  it("counts a member whose record is no longer loaded as a reference that names none", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      itemsByOriginId([a.item, b.item]),
      indexOf([a.source]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([a.source]);
    expect(scope.references).toEqual([[a.source], []]);
    expect(scope.counts).toMatchObject({ notLoaded: 1, ambiguous: 0 });
  });

  it("keeps every candidate of an ambiguous member and counts that reference once", () => {
    const a = fixturePair(1);
    const twin = record(1, { eventId: 101 });
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [] },
      itemsByOriginId([a.item]),
      indexOf([a.source, twin]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([a.source, twin]);
    expect(scope.references).toEqual([[a.source, twin]]);
    expect(scope.counts).toMatchObject({ ambiguous: 1, notLoaded: 0 });
  });

  it("counts a member with no usable identity apart and gives it no reference", () => {
    const unnumbered = record(0, { eventRecordIdText: "0", eventId: 100 });
    const origin = originOf(unnumbered, { stableId: "u", recordId: 0, recordIdText: null });
    const b = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: ["u", rid(2)], unresolvedMemberIds: [] },
      itemsByOriginId([itemOf(origin), b.item]),
      indexOf([unnumbered, b.source]),
      { edgeInputComplete: true },
    );
    // "u" is the opaque stable id of the first origin, which is what the items are keyed by.
    expect(scope.references).toEqual([[b.source]]);
    expect(scope.counts).toMatchObject({ noUsableIdentity: 1, notLoaded: 0 });
  });

  it("counts each member with no item as a reference that names no loaded record", () => {
    const a = fixturePair(1);
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [rid(8), rid(9)] },
      itemsByOriginId([a.item]),
      indexOf([a.source]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([a.source]);
    expect(scope.references).toEqual([[a.source], [], []]);
    expect(scope.counts.notLoaded).toBe(2);
  });

  it("does not count a text-log member, which is not a grid record", () => {
    const a = fixturePair(1);
    const log: TimelineItem = itemOf({
      kind: "log",
      file: "C:\\Logs\\a.log",
      component: null,
      line: 3,
      source: "a.cpp",
      machine: null,
      bundle: null,
      recordId: 3,
    });
    const logId = timelineOriginId(log.origin);
    const scope = scopeForChain(
      { memberIds: [rid(1), logId], unresolvedMemberIds: [] },
      itemsByOriginId([a.item, log]),
      indexOf([a.source]),
      { edgeInputComplete: true },
    );
    expect(scope.references).toEqual([[a.source]]);
    expect(scope.counts).toMatchObject({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0 });
  });
});

describe("a chain scope applied to the store keeps its by-reference counts (6a record 24)", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation(() => new Promise(() => undefined));
    useEvtxStore.getState().reset();
  });

  /** Three loaded records, and one the chain also names that is not loaded. */
  function setup() {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const twin = record(2, { eventId: 102 });
    const loaded = [a.source, b.source, twin];
    loaded.forEach((entry, index) => {
      entry.id = index;
    });
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "System", eventCount: 3, sourceType: "live" }],
      records: loaded,
      loadedChannels: new Set(["System"]),
      selectedChannels: new Set(["System"]),
      isLoading: false,
    });
    return { a, b, twin };
  }

  it("passes references to setRecordScope, so a record that leaves is not a not-loaded reference when its twin stays", () => {
    const { a, b, twin } = setup();
    // The scope is made while a third record of reference 2 is still loaded, then it is not.
    const ghost = record(2, { eventId: 102, sourceLabel: "Live" });
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      itemsByOriginId([a.item, b.item]),
      indexOf([a.source, b.source, twin, ghost]),
      { edgeInputComplete: true },
    );
    expect(scope.references[1]).toHaveLength(3);
    const applied = useEvtxStore.getState().setRecordScope({
      kind: "chain",
      title: "Chain",
      records: new Set(scope.records),
      references: scope.references,
      counts: scope.counts,
    });
    expect(applied).toBe(true);
    const held = useEvtxStore.getState().recordScope;
    // `ghost` is not in the store's records, so it leaves the scope on apply. Both loaded
    // candidates of reference 2 remain: it is still ambiguous, and nothing is "not loaded".
    expect(held?.references?.[1]).toEqual([b.source, twin]);
    expect(held?.counts).toMatchObject({ notLoaded: 0, ambiguous: 1 });
  });

  it("without references the same prune would count a record that left as one not-loaded reference", () => {
    const { a, b, twin } = setup();
    const ghost = record(2, { eventId: 102 });
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      itemsByOriginId([a.item, b.item]),
      indexOf([a.source, b.source, twin, ghost]),
      { edgeInputComplete: true },
    );
    useEvtxStore.getState().setRecordScope({
      kind: "chain",
      title: "Chain",
      records: new Set(scope.records),
      counts: scope.counts,
    });
    // The contrast that makes the references field load-bearing.
    expect(useEvtxStore.getState().recordScope?.counts.notLoaded).toBe(1);
  });
});

describe("linkPartnerCounts", () => {
  it("counts distinct partners per origin and leaves an unlinked origin out", () => {
    const counts = linkPartnerCounts([
      { left: "a", right: "b" },
      { left: "a", right: "c" },
      { left: "d", right: "e" },
    ]);
    expect([...counts]).toEqual([
      ["a", 2],
      ["b", 1],
      ["c", 1],
      ["d", 1],
      ["e", 1],
    ]);
    expect(counts.has("z")).toBe(false);
  });

  it("counts a partner once however many times the pair is listed, and ignores a self pair", () => {
    const counts = linkPartnerCounts([
      { left: "a", right: "b" },
      { left: "b", right: "a" },
      { left: "a", right: "b" },
      { left: "c", right: "c" },
    ]);
    expect(counts.get("a")).toBe(1);
    expect(counts.get("b")).toBe(1);
    expect(counts.has("c")).toBe(false);
  });

  it("never holds a zero", () => {
    expect([...linkPartnerCounts([]).values()]).toEqual([]);
    for (const count of linkPartnerCounts([{ left: "a", right: "b" }]).values()) {
      expect(count).toBeGreaterThan(0);
    }
  });

  it("counts from the model's uncapped pairs, so an origin in chain 120 of 150 has its link", () => {
    const edges = Array.from({ length: 150 }, (_, i) => {
      const left = `l${String(i).padStart(3, "0")}`;
      const right = `r${String(i).padStart(3, "0")}`;
      return syntheticEdge(`e${i}`, left, right, "exact");
    });
    const model = buildCorrelationChains({
      items: [],
      timelineEdges: edges,
      totalTimelineEdges: edges.length,
      findings: [],
    });
    expect(model.chains).toHaveLength(100);
    const counts = linkPartnerCounts(model.linkedPairs);
    expect(counts.get("l149")).toBe(1);
    expect(counts.get("r149")).toBe(1);
    expect(counts.size).toBe(300);
  });

  it("gives an ambiguous group's members no partner count, and a vetoed pair none", () => {
    const edges = [
      syntheticEdge("e1", "a", "b", "exact"),
      syntheticEdge("e2", "a", "b", "ambiguous", {
        coverage: { state: "gap", gap: { source: "s", reason: "two candidates" } },
      }),
      syntheticEdge("g1", "x", "y", "ambiguous", {
        candidateIds: ["z"],
        coverage: { state: "gap", gap: { source: "s", reason: "multiple" } },
      }),
    ];
    const model = buildCorrelationChains({
      items: [],
      timelineEdges: edges,
      totalTimelineEdges: edges.length,
      findings: [],
    });
    expect(linkPartnerCounts(model.linkedPairs).size).toBe(0);
  });
});

function syntheticEdge(
  id: string,
  fromId: string,
  toId: string,
  strength: TimelineCorrelationEdge["strength"],
  overrides: Partial<TimelineCorrelationEdge> = {},
): TimelineCorrelationEdge {
  return {
    id,
    fromId,
    toId,
    key: { kind: "activityId", value: `key-${id}` },
    strength,
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: fromId, field: "activityId", value: `key-${id}` },
      { originId: toId, field: "activityId", value: `key-${id}` },
    ],
    coverage: { state: "covered" },
    ...overrides,
  };
}

describe("linkCountsByRecord", () => {
  it("gives each record the partners of the one origin it names, held by object", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const c = fixturePair(3);
    const partners = linkPartnerCounts([
      { left: rid(1), right: rid(2) },
      { left: rid(1), right: rid(3) },
    ]);
    const result = linkCountsByRecord(
      partners,
      itemsByOriginId([a.item, b.item, c.item]),
      indexOf([a.source, b.source, c.source]),
    );
    expect(result.counts.get(a.source)).toBe(2);
    expect(result.counts.get(b.source)).toBe(1);
    expect(result.counts.get(c.source)).toBe(1);
    expect(result.unmatchedOrigins).toBe(0);
    expect(result.ambiguousOrigins).toBe(0);
  });

  it("gives no record the count of an origin that names several, and says so", () => {
    const a = fixturePair(1);
    const twin = record(1, { eventId: 101 });
    const b = fixturePair(2);
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      itemsByOriginId([a.item, b.item]),
      indexOf([a.source, twin, b.source]),
    );
    expect(result.counts.has(a.source)).toBe(false);
    expect(result.counts.has(twin)).toBe(false);
    expect(result.counts.get(b.source)).toBe(1);
    expect(result.ambiguousOrigins).toBe(1);
  });

  it("counts an origin it cannot give to a record, rather than showing it as no link", () => {
    const a = fixturePair(1);
    const unnumbered = record(0, { eventRecordIdText: "0" });
    const noIdentity = itemOf(
      originOf(unnumbered, { stableId: "no-id", recordId: 0, recordIdText: null }),
    );
    const result = linkCountsByRecord(
      linkPartnerCounts([
        { left: rid(1), right: "never-loaded" },
        { left: rid(1), right: "no-id" },
        { left: rid(1), right: "log|1:a|1:b|1|1" },
      ]),
      itemsByOriginId([a.item, noIdentity]),
      indexOf([a.source]),
    );
    expect(result.counts.get(a.source)).toBe(3);
    // never-loaded (no item), no-id (no identity) and the log id (no item) are unmatched.
    expect(result.unmatchedOrigins).toBe(3);
    for (const count of result.counts.values()) expect(count).toBeGreaterThan(0);
  });

  it("is empty when nothing is linked", () => {
    const result = linkCountsByRecord(new Map(), new Map(), indexOf([record(1)]));
    expect(result).toEqual({ counts: new Map(), unmatchedOrigins: 0, ambiguousOrigins: 0 });
  });
});
