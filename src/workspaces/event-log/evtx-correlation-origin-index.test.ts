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
import vectorDocument from "./__fixtures__/engine-compaction-vectors.json";
import { timelineReference } from "./evtx-engine-compaction-test-fixtures";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  originLookup,
  linkCountsByRecord,
  linkPartnerCounts,
  originIdentityText,
  recordLinkStatus,
  resolveOriginRecords,
  scopeForChain,
  soleRecordForOrigin,
} from "./evtx-correlation-origin-index";
import {
  classifyCoverageGaps,
  type CorrelationGaps,
} from "./evtx-correlation-gaps";
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
// Imported after the mocks: the store subscribes to Tauri events (`listen`) at module scope.
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

/**
 * The origin of a record the TRANSPORT projected (over 8 MiB): its identity texts reached the engine
 * already bounded to 256 bytes in the transport's own form, which the engine leaves alone.
 * `engineOriginOf` (below) is the origin of a record that reached the engine whole, the common case.
 */
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

/** The engine reported no coverage gap and the preview shows all of them (none). */
const CLEAR_GAPS = classifyCoverageGaps([], 0);
const FAN_OUT = "exact UserId identity group exceeds the 256-member correlation limit";

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
      originLookup(pairs.map((pair) => pair.item), []),
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
      originLookup([a.item, b.item], []),
      indexOf([a.source, b.source]),
      { edgeInputComplete: true },
    );
    expect(scope.references).toBeDefined();
    expect(scope.references).toHaveLength(2);
  });

  it("marks the scope bounded when edges were not all loaded, and not otherwise", () => {
    const a = fixturePair(1);
    const chain = { memberIds: [rid(1)], unresolvedMemberIds: [] };
    const items = originLookup([a.item], []);
    const index = indexOf([a.source]);
    expect(scopeForChain(chain, items, index, { edgeInputComplete: false }).counts.bounded).toBe(true);
    expect(scopeForChain(chain, items, index, { edgeInputComplete: true }).counts.bounded).toBe(false);
  });

  it("counts a member whose record is no longer loaded as a reference that names none", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      originLookup([a.item, b.item], []),
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
      originLookup([a.item], []),
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
      originLookup([itemOf(origin), b.item], []),
      indexOf([unnumbered, b.source]),
      { edgeInputComplete: true },
    );
    // "u" is the opaque stable id of the first origin, which is what the items are keyed by.
    expect(scope.references).toEqual([[b.source]]);
    expect(scope.counts).toMatchObject({ noUsableIdentity: 1, notLoaded: 0 });
  });

  it("counts a member with no origin as unresolved, never as not loaded, and does not look for its record", () => {
    const a = fixturePair(1);
    const stranger = fixturePair(8);
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [rid(8), rid(9)] },
      originLookup([a.item], []),
      // Record 8 IS loaded, but nothing says that member 8 names it: its item was not read.
      indexOf([a.source, stranger.source]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([a.source]);
    expect(scope.references).toEqual([[a.source]]);
    expect(scope.counts).toEqual({
      notLoaded: 0,
      noUsableIdentity: 0,
      ambiguous: 0,
      bounded: false,
      unresolved: 2,
    });
  });

  it("resolves an untimed member through the unplaced origins, so a loaded record is in the scope", () => {
    const a = fixturePair(1);
    const untimed = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [rid(2)] },
      originLookup([a.item], [{ origin: untimed.item.origin, reason: "missingTimestamp" }]),
      indexOf([a.source, untimed.source]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([a.source, untimed.source]);
    expect(scope.references).toEqual([[a.source], [untimed.source]]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("still reports an untimed member whose record is not loaded as not loaded: its identity is known", () => {
    const a = fixturePair(1);
    const untimed = fixturePair(2);
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [rid(2)] },
      originLookup([a.item], [{ origin: untimed.item.origin, reason: "missingTimestamp" }]),
      indexOf([a.source]),
      { edgeInputComplete: true },
    );
    expect(scope.references).toEqual([[a.source], []]);
    expect(scope.counts).toMatchObject({ notLoaded: 1 });
    expect(scope.counts.unresolved).toBeUndefined();
  });

  it("counts every member as unresolved when the scan read nothing, and never as not loaded", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const scope = scopeForChain(
      // The scan stopped at the byte budget before reading either item.
      { memberIds: [], unresolvedMemberIds: [rid(1), rid(2)] },
      originLookup([], []),
      indexOf([a.source, b.source]),
      { edgeInputComplete: true },
    );
    expect(scope.records).toEqual([]);
    expect(scope.references).toEqual([]);
    expect(scope.counts.notLoaded).toBe(0);
    expect(scope.counts.unresolved).toBe(2);
  });

  it("counts a placed member whose item is missing from the lookup the same way", () => {
    const a = fixturePair(1);
    const scope = scopeForChain(
      { memberIds: [rid(1), rid(2)], unresolvedMemberIds: [] },
      originLookup([a.item], []),
      indexOf([a.source]),
      { edgeInputComplete: true },
    );
    expect(scope.counts).toMatchObject({ notLoaded: 0, unresolved: 1 });
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
      originLookup([a.item, log], []),
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
      originLookup([a.item, b.item], []),
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
      originLookup([a.item, b.item], []),
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

describe("originLookup", () => {
  it("holds the placed items' origins and the unplaced origins by id", () => {
    const placed = fixturePair(1);
    const unplaced = fixturePair(2);
    const lookup = originLookup([placed.item], [{ origin: unplaced.item.origin, reason: "missingTimestamp" }]);
    expect([...lookup.keys()].sort()).toEqual([rid(1), rid(2)]);
    expect(lookup.get(rid(2))).toBe(unplaced.item.origin);
  });

  it("lets a placed item win over an unplaced origin with the same id", () => {
    const placed = fixturePair(1);
    const twin = { origin: { ...placed.item.origin, provider: "Other" } as TimelineOrigin, reason: "missingTimestamp" as const };
    expect(originLookup([placed.item], [twin]).get(rid(1))).toBe(placed.item.origin);
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
  /** Edges, scan and the engine's gaps all complete, so only the origins can make the index incomplete. */
  const complete = (records: EvtxRecord[], gaps: CorrelationGaps = CLEAR_GAPS) => ({
    records,
    edgeInputComplete: true,
    scanComplete: true,
    gaps,
  });

  it("gives each record the partners of the one origin it names, held by object", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const c = fixturePair(3);
    const loaded = [a.source, b.source, c.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([
        { left: rid(1), right: rid(2) },
        { left: rid(1), right: rid(3) },
      ]),
      originLookup([a.item, b.item, c.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.counts.get(a.source)).toBe(2);
    expect(result.counts.get(b.source)).toBe(1);
    expect(result.counts.get(c.source)).toBe(1);
    expect(result).toMatchObject({
      unmatchedOrigins: 0,
      ambiguousOrigins: 0,
      unloadedOrigins: 0,
      complete: true,
    });
    expect(result.unknownRecords.size).toBe(0);
    expect(recordLinkStatus(result, a.source)).toEqual({ kind: "linked", count: 2, atLeast: false });
  });

  it("reads a record with no link as none only when the index is complete", () => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const quiet = fixturePair(5);
    const loaded = [a.source, b.source, quiet.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup([a.item, b.item, quiet.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
  });

  it("never gives the Links cell an empty answer for the copies of an origin that names several: both are unknown, not zero", () => {
    // The same archive loaded twice: each linked origin resolves to two identical records.
    const a = fixturePair(1);
    const aCopy = record(1, { eventId: 101 });
    const b = fixturePair(2);
    const bCopy = record(2, { eventId: 102 });
    const loaded = [a.source, aCopy, b.source, bCopy];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup([a.item, b.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.counts.size).toBe(0);
    expect(result.ambiguousOrigins).toBe(2);
    expect(result.complete).toBe(true);
    for (const copy of loaded) {
      expect(result.unknownRecords.has(copy)).toBe(true);
      expect(recordLinkStatus(result, copy)).toEqual({ kind: "unknown" });
    }
  });

  it("marks a record that has a count but is also a candidate of an ambiguous origin as at least that count", () => {
    const a = fixturePair(1);
    const twin = record(1, { eventId: 101 });
    const c = fixturePair(3);
    const loaded = [a.source, twin, c.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([
        { left: rid(1), right: rid(3) },
      ]),
      originLookup([a.item, c.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    // c names one record and gets its count of 1; a's origin names two, so neither copy is counted.
    expect(recordLinkStatus(result, c.source)).toEqual({ kind: "linked", count: 1, atLeast: false });
    expect(recordLinkStatus(result, a.source)).toEqual({ kind: "unknown" });
    const both = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(3), right: rid(1) }, { left: rid(3), right: rid(9) }]),
      originLookup([a.item, c.item, fixturePair(9).item], []),
      indexOf([...loaded, fixturePair(9).source]),
      complete([...loaded, fixturePair(9).source]),
    );
    expect(both.counts.get(c.source)).toBe(2);
  });

  it.each([
    ["the edges are not all loaded", { edgeInputComplete: false, scanComplete: true }],
    ["the scan did not finish", { edgeInputComplete: true, scanComplete: false }],
  ])("is not complete when %s, so a record with no count is unknown and a count is a floor", (_why, flags) => {
    const a = fixturePair(1);
    const b = fixturePair(2);
    const quiet = fixturePair(5);
    const loaded = [a.source, b.source, quiet.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup([a.item, b.item, quiet.item], []),
      indexOf(loaded),
      { records: loaded, gaps: CLEAR_GAPS, ...flags },
    );
    expect(result.complete).toBe(false);
    expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
    expect(recordLinkStatus(result, a.source)).toEqual({ kind: "linked", count: 1, atLeast: true });
  });

  it("is not complete when a linked origin was never read, and counts it as unmatched", () => {
    const a = fixturePair(1);
    const quiet = fixturePair(5);
    const loaded = [a.source, quiet.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: "never-read" }]),
      originLookup([a.item, quiet.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.unmatchedOrigins).toBe(1);
    expect(result.complete).toBe(false);
    expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
    for (const count of result.counts.values()) expect(count).toBeGreaterThan(0);
  });

  it("marks every record of the source and channel an identity-less origin could be in as unknown, and no other", () => {
    const a = fixturePair(1);
    const unnumbered = record(0, { eventRecordIdText: "0", eventId: 150 });
    const noIdentity = itemOf(originOf(unnumbered, { stableId: "no-id", recordId: 0, recordIdText: null }));
    const sameChannel = record(30, { eventId: 140 });
    const otherChannel = record(31, { eventId: 141, channel: "Application" });
    const otherSource = record(32, { eventId: 142, sourceLabel: "b.evtx" });
    const loaded = [a.source, unnumbered, sameChannel, otherChannel, otherSource];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: "no-id" }]),
      originLookup([a.item, noIdentity], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.complete).toBe(true);
    expect(recordLinkStatus(result, unnumbered)).toEqual({ kind: "unknown" });
    expect(recordLinkStatus(result, sameChannel)).toEqual({ kind: "unknown" });
    expect(recordLinkStatus(result, otherChannel)).toEqual({ kind: "none" });
    expect(recordLinkStatus(result, otherSource)).toEqual({ kind: "none" });
    // a is in the same source and channel, so it cannot be spoken for either, though it has a count.
    expect(recordLinkStatus(result, a.source)).toEqual({ kind: "linked", count: 1, atLeast: true });
  });

  it("does not make a record unknown for an origin whose record is not loaded", () => {
    const a = fixturePair(1);
    const gone = fixturePair(4);
    const quiet = fixturePair(5);
    const loaded = [a.source, quiet.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(4) }]),
      originLookup([a.item, gone.item, quiet.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.unloadedOrigins).toBe(1);
    expect(result.complete).toBe(true);
    expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
  });

  it("ignores a text-log origin: it is not a record and changes no record's status", () => {
    const a = fixturePair(1);
    const quiet = fixturePair(5);
    const log = itemOf({
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
    const loaded = [a.source, quiet.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: logId }]),
      originLookup([a.item, log, quiet.item], []),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.counts.get(a.source)).toBe(1);
    expect(result.unmatchedOrigins).toBe(0);
    expect(result.complete).toBe(true);
    expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
  });

  it("resolves an untimed origin through the unplaced list", () => {
    const a = fixturePair(1);
    const untimed = fixturePair(2);
    const loaded = [a.source, untimed.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup([a.item], [{ origin: untimed.item.origin, reason: "missingTimestamp" }]),
      indexOf(loaded),
      complete(loaded),
    );
    expect(result.counts.get(untimed.source)).toBe(1);
    expect(result.unmatchedOrigins).toBe(0);
  });

  describe("the engine's correlation coverage gaps (J1)", () => {
    /** Two loaded records and a third the engine never correlated: it has no edge, and no edge was computed. */
    function setup() {
      const linked = fixturePair(1);
      const partner = fixturePair(2);
      const uncorrelated = fixturePair(5);
      const quiet = fixturePair(6);
      const loaded = [linked.source, partner.source, uncorrelated.source, quiet.source];
      const origins = originLookup([linked.item, partner.item, uncorrelated.item, quiet.item], []);
      const partners = linkPartnerCounts([{ left: rid(1), right: rid(2) }]);
      return { linked, partner, uncorrelated, quiet, loaded, origins, partners };
    }
    const gapOn = (id: string, reason = FAN_OUT) => ({ source: id, reason });

    it("makes the records of an origin a fan-out gap names unknown, though it has no edge at all", () => {
      const { uncorrelated, quiet, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps([gapOn(rid(5))], 1);
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(recordLinkStatus(result, uncorrelated.source)).toEqual({ kind: "unknown" });
      // The index is otherwise complete, so a record the engine did correlate and found nothing for is none.
      expect(result.complete).toBe(true);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
      expect(result.unattributedGapOrigins).toBe(0);
    });

    it("makes a record that has a count and is named by a gap a floor", () => {
      const { linked, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps([gapOn(rid(1))], 1);
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(recordLinkStatus(result, linked.source)).toEqual({ kind: "linked", count: 1, atLeast: true });
    });

    it("makes complete false for a global correlation limit, so every uncounted record is unknown", () => {
      const { quiet, loaded, origins, partners } = setup();
      for (const source of ["timeline-correlation-projection", "correlation"]) {
        const gaps = classifyCoverageGaps([{ source, reason: "limit" }], 1);
        const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
        expect(result.complete, source).toBe(false);
        expect(recordLinkStatus(result, quiet.source), source).toEqual({ kind: "unknown" });
      }
    });

    it("makes complete false when the session counts more gaps than the preview shows", () => {
      const { quiet, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps([gapOn(rid(5))], 301);
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(result.complete).toBe(false);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
    });

    it("makes complete false when the gap count is not known", () => {
      const { quiet, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps([], null);
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(result.complete).toBe(false);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
    });

    it("makes complete false for a gap whose origin was not read, and counts it", () => {
      const { quiet, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps([gapOn(rid(99))], 1);
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(result.unattributedGapOrigins).toBe(1);
      expect(result.complete).toBe(false);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
    });

    it("lets list-view compaction gaps pass: they say nothing about correlation", () => {
      const { quiet, loaded, origins, partners } = setup();
      const gaps = classifyCoverageGaps(
        [
          { source: "timeline-item-projection", reason: "compacted" },
          { source: "timeline-message-projection", reason: "budget" },
        ],
        2,
      );
      const result = linkCountsByRecord(partners, origins, indexOf(loaded), complete(loaded, gaps));
      expect(result.complete).toBe(true);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
    });

    it("names both copies of a duplicated record when a gap names their origin", () => {
      const { uncorrelated, loaded, origins, partners } = setup();
      const copy = record(5, { eventId: 105 });
      const gaps = classifyCoverageGaps([gapOn(rid(5))], 1);
      const result = linkCountsByRecord(partners, origins, indexOf([...loaded, copy]), complete([...loaded, copy], gaps));
      expect(recordLinkStatus(result, uncorrelated.source)).toEqual({ kind: "unknown" });
      expect(recordLinkStatus(result, copy)).toEqual({ kind: "unknown" });
    });

    it("marks the source and channel unknown for a gap on an origin with no usable identity", () => {
      const { linked, partner, quiet, loaded, partners } = setup();
      const unnumbered = record(0, { eventRecordIdText: "0", eventId: 150 });
      const noIdentity = itemOf(originOf(unnumbered, { stableId: "no-id", recordId: 0, recordIdText: null }));
      const otherChannel = record(40, { eventId: 140, channel: "Application" });
      const all = [...loaded, unnumbered, otherChannel];
      const gaps = classifyCoverageGaps([gapOn("no-id", "machine identity unavailable; exact correlation is restricted")], 1);
      const result = linkCountsByRecord(
        partners,
        originLookup([linked.item, partner.item, noIdentity], []),
        indexOf(all),
        complete(all, gaps),
      );
      // Everything else in System of that source is unknown; another channel is not.
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "unknown" });
      expect(recordLinkStatus(result, otherChannel)).toEqual({ kind: "none" });
    });

    it("ignores a gap on a text-log origin: it is not a record", () => {
      const { quiet, loaded, origins, partners } = setup();
      const log = itemOf({
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
      const gaps = classifyCoverageGaps([gapOn(logId, "machine identity unavailable")], 1);
      const result = linkCountsByRecord(
        partners,
        originLookup([...origins.values()].map((origin) => itemOf(origin)).concat([log]), []),
        indexOf(loaded),
        complete(loaded, gaps),
      );
      expect(result.complete).toBe(true);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
    });

    it("finds the origin of a gap among the unplaced origins too", () => {
      const { linked, partner, loaded, partners } = setup();
      const untimed = fixturePair(7);
      const all = [...loaded, untimed.source];
      const gaps = classifyCoverageGaps([gapOn(rid(7))], 1);
      const result = linkCountsByRecord(
        partners,
        originLookup([linked.item, partner.item], [{ origin: untimed.item.origin, reason: "missingTimestamp" }]),
        indexOf(all),
        complete(all, gaps),
      );
      expect(result.unattributedGapOrigins).toBe(0);
      expect(recordLinkStatus(result, untimed.source)).toEqual({ kind: "unknown" });
    });

    it("does not make a record unknown for a gap whose origin names no loaded record", () => {
      const { quiet, loaded, origins, partners } = setup();
      const gone = fixturePair(8);
      const gaps = classifyCoverageGaps([gapOn(rid(8))], 1);
      const result = linkCountsByRecord(
        partners,
        originLookup([...origins.values()].map((origin) => itemOf(origin)).concat([gone.item]), []),
        indexOf(loaded),
        complete(loaded, gaps),
      );
      expect(result.complete).toBe(true);
      expect(recordLinkStatus(result, quiet.source)).toEqual({ kind: "none" });
    });
  });

  it("is complete and empty when nothing is linked and everything is read", () => {
    const loaded = [record(1)];
    const result = linkCountsByRecord(new Map(), new Map(), indexOf(loaded), complete(loaded));
    expect(result).toEqual({
      counts: new Map(),
      unknownRecords: new Set(),
      unmatchedOrigins: 0,
      ambiguousOrigins: 0,
      unloadedOrigins: 0,
      unattributedGapOrigins: 0,
      complete: true,
    });
    expect(recordLinkStatus(result, loaded[0]!)).toEqual({ kind: "none" });
  });
});

/**
 * The origin the ENGINE builds from a record that reached it whole (`origin_of`, then
 * `compact_timeline_origin`): source label, channel and provider over 256 bytes in the engine's own
 * `...[{len} bytes; digest={hex}]` form, and the machine trimmed BEFORE it is compacted. The format
 * is `timelineReference`, checked against the Rust vectors in evtx-engine-compaction.test.ts.
 */
function engineOriginOf(source: EvtxRecord, overrides: Partial<EventOrigin> = {}): EventOrigin {
  const machine = normalizedMachine(source.computer);
  return originOf(source, {
    source: timelineReference(source.sourceLabel),
    channel: timelineReference(source.channel),
    provider: timelineReference(source.provider),
    machine: machine === null ? null : timelineReference(machine),
    ...overrides,
  });
}

const vectorText = (name: string) =>
  (vectorDocument.timelineText.find((c) => c.name === name) as { input: string }).input;

/** The same text with its last character replaced by another of the same UTF-8 width. */
function sameWidthVariant(text: string): string {
  const characters = [...text];
  const last = characters.pop() as string;
  const width = new TextEncoder().encode(last).length;
  const swap = width === 3 ? (last === "\u4ef6" ? "\u6848" : "\u4ef6") : last === "Q" ? "R" : "Q";
  return `${characters.join("")}${swap}`;
}

const LONG_LABELS: readonly (readonly [string, string])[] = [
  ["257 bytes", vectorText("ascii-257")],
  ["300 bytes with backslashes", vectorText("ascii-300-backslashes")],
  ["a collector bundle path of 276 bytes", vectorText("bundle-path-276")],
  ["3-byte characters past 256 bytes", vectorText("cjk-273")],
];

describe("an origin the engine compacted (a record that reached the engine whole)", () => {
  it.each(LONG_LABELS)("names the record whose source label is %s", (_why, label) => {
    const wanted = record(42, { sourceLabel: label });
    const resolution = resolveOriginRecords(
      engineOriginOf(wanted),
      indexOf([record(41), wanted, record(43)]),
    );
    expect(wanted.sourceLabel).not.toBe(engineOriginOf(wanted).source);
    expect(resolution).toEqual({ kind: "matches", records: [wanted] });
  });

  it.each(LONG_LABELS)("names the record whose channel is %s", (_why, label) => {
    const wanted = record(42, { channel: label });
    expect(resolveOriginRecords(engineOriginOf(wanted), indexOf([record(41), wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it.each(LONG_LABELS)("names the record whose provider is %s", (_why, label) => {
    const wanted = record(42, { provider: label });
    expect(resolveOriginRecords(engineOriginOf(wanted), indexOf([record(41), wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it.each(LONG_LABELS)(
    "does not name a record with the same prefix and another length or digest (%s)",
    (_why, label) => {
      const wanted = record(42, { sourceLabel: label });
      const longer = record(42, { sourceLabel: `${label}z` });
      const otherDigest = record(42, { sourceLabel: sameWidthVariant(label) });
      expect(otherDigest.sourceLabel).not.toBe(label);
      expect(
        resolveOriginRecords(engineOriginOf(wanted), indexOf([longer, otherDigest, wanted])),
      ).toEqual({ kind: "matches", records: [wanted] });
      // And the other way round: neither of them is named by the origin of the wanted record.
      expect(
        resolveOriginRecords(engineOriginOf(wanted), indexOf([longer, otherDigest])),
      ).toEqual({ kind: "matches", records: [] });
    },
  );

  it("does not name a record when the origin's suffix names another length, with its digest and prefix untouched", () => {
    const label = vectorText("ascii-300-backslashes");
    const wanted = record(42, { sourceLabel: label });
    const compacted = engineOriginOf(wanted).source;
    expect(compacted).toContain("[300 bytes;");
    const forged = engineOriginOf(wanted, { source: compacted.replace("[300 bytes;", "[301 bytes;") });
    expect(resolveOriginRecords(forged, indexOf([wanted]))).toEqual({ kind: "matches", records: [] });
  });

  it("finds the record through a short source label that stays exact", () => {
    const wanted = record(42);
    expect(engineOriginOf(wanted).source).toBe("Live");
    expect(resolveOriginRecords(engineOriginOf(wanted), indexOf([wanted, record(42, { sourceLabel: "Live2" })]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it.each([
    ["padded past 256 bytes and fitting once trimmed", `  ${"H".repeat(254)}  `],
    ["padded and over 256 bytes once trimmed", `  ${"H".repeat(300)}  `],
    ["padded and short", "  DESKTOP-01  "],
  ])("names a record whose machine is %s", (_why, computer) => {
    const wanted = record(42, { computer });
    const origin = engineOriginOf(wanted);
    expect(origin.machine).toBe(
      computer.trim().length > 256 ? timelineReference(computer.trim()) : computer.trim(),
    );
    expect(resolveOriginRecords(origin, indexOf([wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it("does not name a record whose machine differs from the origin's, however it is padded", () => {
    const wanted = record(42, { computer: `  ${"H".repeat(300)}  ` });
    const other = record(42, { computer: `  ${"H".repeat(299)}J  ` });
    const shorter = record(42, { computer: `  ${"H".repeat(299)}  ` });
    expect(
      resolveOriginRecords(engineOriginOf(wanted), indexOf([other, shorter])),
    ).toEqual({ kind: "matches", records: [] });
  });

  it("reads a placeholder machine as none, padded or not", () => {
    const wanted = record(42, { computer: "  N/A  " });
    expect(engineOriginOf(wanted).machine).toBeNull();
    expect(resolveOriginRecords(engineOriginOf(wanted), indexOf([wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
    expect(
      resolveOriginRecords(engineOriginOf(wanted), indexOf([record(42, { computer: "DESKTOP-01" })])),
    ).toEqual({ kind: "matches", records: [] });
  });

  it("still names a record the transport projected, whose texts are in the transport's form", () => {
    const label = vectorText("ascii-300-backslashes");
    const wanted = record(42, { sourceLabel: label, computer: `  ${"H".repeat(300)}  ` });
    expect(originOf(wanted).source).toMatch(/\u2026\[truncated:/);
    expect(resolveOriginRecords(originOf(wanted), indexOf([wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it("selects the marker's record by its origin (soleRecordForOrigin)", () => {
    const wanted = record(42, { sourceLabel: vectorText("bundle-path-276") });
    expect(soleRecordForOrigin(engineOriginOf(wanted), indexOf([record(41), wanted]))).toBe(wanted);
  });

  it("scopes a chain whose records carry long source labels, counting nothing as missing", () => {
    const pairs = [1, 2].map((n) => {
      const source = record(n, { eventId: 100 + n, sourceLabel: vectorText("bundle-path-276") });
      return { source, item: itemOf(engineOriginOf(source, { stableId: rid(n) }), 1_000 * n) };
    });
    const model = buildCorrelationChains({
      items: pairs.map((pair) => pair.item),
      timelineEdges: fixtureEdges("exactPair"),
      totalTimelineEdges: 1,
      findings: [],
    });
    const scope = scopeForChain(
      model.chains[0]!,
      originLookup(pairs.map((pair) => pair.item), []),
      indexOf(pairs.map((pair) => pair.source)),
      { edgeInputComplete: model.edgeInputComplete },
    );
    expect(scope.records).toEqual(pairs.map((pair) => pair.source));
    expect(scope.references).toEqual(pairs.map((pair) => [pair.source]));
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("counts a linked record with a long source label as linked, not as an origin whose record is not here", () => {
    const pairs = [1, 2].map((n) => {
      const source = record(n, { eventId: 100 + n, sourceLabel: vectorText("cjk-273") });
      return { source, item: itemOf(engineOriginOf(source, { stableId: rid(n) }), 1_000 * n) };
    });
    const loaded = pairs.map((pair) => pair.source);
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup(pairs.map((pair) => pair.item), []),
      indexOf(loaded),
      { records: loaded, edgeInputComplete: true, scanComplete: true, gaps: CLEAR_GAPS },
    );
    expect(result).toMatchObject({ unloadedOrigins: 0, ambiguousOrigins: 0, unmatchedOrigins: 0, complete: true });
    expect(recordLinkStatus(result, loaded[0]!)).toEqual({ kind: "linked", count: 1, atLeast: false });
    expect(recordLinkStatus(result, loaded[1]!)).toEqual({ kind: "linked", count: 1, atLeast: false });
  });

  it("marks the records of a lane unknown when an origin there has no usable identity, with a long source and channel", () => {
    const label = vectorText("bundle-path-276");
    const channel = vectorText("ascii-257");
    const unidentified = record(7, { sourceLabel: label, channel, eventRecordId: 0, eventRecordIdText: null });
    const sameLane = record(8, { sourceLabel: label, channel });
    const otherLane = record(9, { sourceLabel: `${label}z`, channel });
    const origin = engineOriginOf(unidentified, { recordId: 0, recordIdText: null, stableId: rid(7) });
    const partner = fixturePair(1);
    const loaded = [sameLane, otherLane, partner.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(7), right: rid(1) }]),
      originLookup([itemOf(origin), partner.item], []),
      indexOf(loaded),
      { records: loaded, edgeInputComplete: true, scanComplete: true, gaps: CLEAR_GAPS },
    );
    expect(result.unknownRecords.has(sameLane)).toBe(true);
    expect(result.unknownRecords.has(otherLane)).toBe(false);
  });
});

describe("an origin the engine rewrote because it refused the record's identity", () => {
  type IdentityVector = {
    name: string;
    originKind: string;
    text: string | null;
    id: number;
    originRecordIdText: string | null;
    originRecordId: number;
  };
  const vectors = (vectorDocument.identities as unknown as IdentityVector[]).filter(
    (c) => c.originKind === "event",
  );
  const loadedRecord = (c: IdentityVector, overrides: Partial<EvtxRecord> = {}) =>
    record(c.id, { eventRecordId: c.id, eventRecordIdText: c.text, ...overrides });
  const engineOrigin = (c: IdentityVector, source: EvtxRecord) =>
    engineOriginOf(source, { recordId: c.originRecordId, recordIdText: c.originRecordIdText });

  it.each(vectors.map((c) => [c.name, c] as const))(
    "joins the record to the origin the engine built for %s",
    (_name, c) => {
      const wanted = loadedRecord(c);
      const origin = engineOrigin(c, wanted);
      const resolution = resolveOriginRecords(origin, indexOf([wanted, record(3_000)]));
      if (originIdentityText(origin) === null) {
        // The engine left the origin no identity: it is counted as having none, never as not loaded.
        expect(resolution).toEqual({ kind: "noUsableIdentity" });
      } else {
        expect(resolution).toEqual({ kind: "matches", records: [wanted] });
      }
    },
  );

  it("does not find a record under the identity it came with when the engine rewrote it", () => {
    const rewritten = vectors.find((c) => c.name === "conflict-positive-number") as IdentityVector;
    expect(rewritten).toMatchObject({ text: "5", id: 9, originRecordIdText: "9" });
    const wanted = loadedRecord(rewritten);
    // An origin for a record whose identity really is 5 does not name it, and one for 9 does.
    const askingForFive = engineOriginOf(record(5));
    expect(resolveOriginRecords(askingForFive, indexOf([wanted]))).toEqual({ kind: "matches", records: [] });
    expect(resolveOriginRecords(engineOriginOf(record(9)), indexOf([wanted]))).toEqual({
      kind: "matches",
      records: [wanted],
    });
  });

  it("counts a chain member the engine left no identity as having none, not as not loaded", () => {
    const refused = vectors.find((c) => c.name === "conflict-zero-number") as IdentityVector;
    const source = loadedRecord(refused, { eventId: 101 });
    const origin = engineOrigin(refused, { ...source, eventId: 101 });
    const scope = scopeForChain(
      { memberIds: [rid(1)], unresolvedMemberIds: [] },
      originLookup([itemOf({ ...origin, stableId: rid(1) })], []),
      indexOf([source]),
      { edgeInputComplete: true },
    );
    expect(scope.counts).toMatchObject({ noUsableIdentity: 1, notLoaded: 0 });
    expect(scope.records).toEqual([]);
  });

  it("does not count an origin with a rewritten identity as an origin whose record is not here", () => {
    const rewritten = vectors.find((c) => c.name === "padded-text-other-number") as IdentityVector;
    const a = loadedRecord(rewritten, { eventId: 101 });
    const b = fixturePair(2);
    const loaded = [a, b.source];
    const result = linkCountsByRecord(
      linkPartnerCounts([{ left: rid(1), right: rid(2) }]),
      originLookup([itemOf({ ...engineOrigin(rewritten, a), eventId: 101, stableId: rid(1) }), b.item], []),
      indexOf(loaded),
      { records: loaded, edgeInputComplete: true, scanComplete: true, gaps: CLEAR_GAPS },
    );
    expect(result.unloadedOrigins).toBe(0);
    expect(result.counts.get(a)).toBe(1);
  });
});
