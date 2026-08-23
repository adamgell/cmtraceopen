import { describe, expect, it, vi } from "vitest";
import { parseEventIdFilter, selectVisibleRecords, sortRecords, isWithinTimeWindow } from "./evtx-filter";
import * as evtxColumns from "./evtx-columns";
import type { EvtxRecord } from "./types";

const record = (overrides: Partial<EvtxRecord> = {}): EvtxRecord => ({
  id: 1,
  eventRecordId: 1,
  timestamp: "2026-08-18T12:00:00.000Z",
  timestampEpoch: Date.parse("2026-08-18T12:00:00.000Z"),
  provider: "Microsoft-Boot",
  channel: "Application",
  eventId: 4624,
  level: "Information",
  computer: "DESKTOP",
  message: "Boot completed",
  eventData: [{ name: "User", value: "Ada" }],
  rawXml: "<Event />",
  sourceLabel: "Application",
  ...overrides,
});

const quick = (overrides: Partial<import("./evtx-filter").EvtxQuickFilter> = {}): import("./evtx-filter").EvtxQuickFilter => ({
  mode: "oneString",
  query: "",
  scope: "allColumns",
  action: "show",
  caseSensitive: false,
  highlight: true,
  ...overrides,
});

const visible = (
  quickFilter: import("./evtx-filter").EvtxQuickFilter,
  records: EvtxRecord[] = [record()]
) =>
  selectVisibleRecords({
    records,
    selectedChannels: new Set(["Application"]),
    filterLevels: new Set(["Critical", "Error", "Warning", "Information", "Verbose"]),
    filterEventIds: "",
    filterSearch: "",
    quickFilter,
    visibleColumns: ["message"],
  });
describe("parseEventIdFilter", () => {
  it("returns null when the box constrains nothing", () => {
    expect(parseEventIdFilter("")).toBeNull();
    expect(parseEventIdFilter("   ")).toBeNull();
  });

  it("parses a comma separated list", () => {
    expect(parseEventIdFilter("4624,4625")).toEqual(new Set([4624, 4625]));
  });

  it("tolerates spaces as separators and around commas", () => {
    expect(parseEventIdFilter("4624 4625")).toEqual(new Set([4624, 4625]));
    expect(parseEventIdFilter(" 4624 , 4625 ")).toEqual(new Set([4624, 4625]));
  });

  it("expands an inclusive range", () => {
    expect(parseEventIdFilter("5-8")).toEqual(new Set([5, 6, 7, 8]));
  });

  it("normalizes a reversed range rather than yielding nothing", () => {
    expect(parseEventIdFilter("8-5")).toEqual(new Set([5, 6, 7, 8]));
  });

  it("mixes singles and ranges", () => {
    expect(parseEventIdFilter("1, 4-6, 9")).toEqual(new Set([1, 4, 5, 6, 9]));
  });

  it("ignores tokens that are not ids instead of failing the whole filter", () => {
    // A half-typed filter should narrow by what is parseable, not silently match everything.
    expect(parseEventIdFilter("4624, abc")).toEqual(new Set([4624]));
  });

  it("returns an empty set when a nonempty selector has no valid IDs", () => {
    expect(parseEventIdFilter("abc, def")).toEqual(new Set());
  });
});
describe("quick filter modes", () => {
  it("matches one string as a single substring", () => {
    expect(visible(quick({ query: "Boot completed" }))).toHaveLength(1);
    expect(visible(quick({ query: "Boot Ada" }))).toHaveLength(0);
  });

  it("matches any whitespace-delimited word in multiple-words mode", () => {
    expect(visible(quick({ mode: "multipleWords", query: "missing Boot" }))).toHaveLength(1);
  });

  it("matches any comma-delimited string in multiple-strings mode", () => {
    expect(visible(quick({ mode: "multipleStrings", query: "missing, Boot" }))).toHaveLength(1);
  });
  it("accepts newline-separated strings", () => {
    expect(visible(quick({ mode: "allStrings", query: "Boot\ncompleted" }))).toHaveLength(1);
  });
  it("accepts carriage-return-separated strings", () => {
    expect(visible(quick({ mode: "allStrings", query: "Boot\rcompleted" }))).toHaveLength(1);
  });
  it("requires every word in all-words mode", () => {
    expect(
      visible(quick({ mode: "allWords", query: "Boot Ada", scope: "visibleColumns" }))
    ).toHaveLength(0);
    expect(visible(quick({ mode: "allWords", query: "Boot completed" }))).toHaveLength(1);
  });

  it("requires every string in all-strings mode", () => {
    expect(visible(quick({ mode: "allStrings", query: "Boot, missing" }))).toHaveLength(0);
    expect(visible(quick({ mode: "allStrings", query: "Boot, completed" }))).toHaveLength(1);
  });

  it("uses the Event ID parser for quick Event ID mode", () => {
    const rows = [
      record({ eventId: 4624 }),
      record({ id: 2, eventRecordId: 2, eventId: 4625 }),
      record({ id: 3, eventRecordId: 3, eventId: 4630 }),
    ];
    expect(visible(quick({ mode: "eventIds", query: "4624-4625" }), rows)).toHaveLength(2);
  });
});

describe("quick filter semantics", () => {
  it("honours case sensitivity", () => {
    expect(visible(quick({ query: "boot" }))).toHaveLength(1);
    expect(visible(quick({ query: "boot", caseSensitive: true }))).toHaveLength(0);
  });

  it("limits matching to visible columns when requested", () => {
    expect(
      visible(quick({ query: "Ada", scope: "visibleColumns" }))
    ).toHaveLength(0);
    expect(
      visible(quick({ query: "Ada", scope: "allColumns" }))
    ).toHaveLength(1);
  });
  it("discovers all-column fields once for a visible-record pass", () => {
    const records = [
      record({ id: 1, eventRecordId: 1 }),
      record({ id: 2, eventRecordId: 2 }),
      record({ id: 3, eventRecordId: 3 }),
    ];
    const discovery = vi.spyOn(evtxColumns, "discoverMappedProperties");

    try {
      expect(visible(quick({ query: "Boot", scope: "allColumns" }), records)).toHaveLength(3);
      expect(discovery).toHaveBeenCalledTimes(1);
      expect(discovery).toHaveBeenCalledWith(records);
    } finally {
      discovery.mockRestore();
    }
  });
  it("keeps visible-column quick filters out of hidden provider values", () => {
    const providerOnly = record({
      provider: "HiddenProvider",
      message: "Visible message",
    });
    expect(
      visible(
        quick({ query: "HiddenProvider", scope: "visibleColumns" }),
        [providerOnly]
      )
    ).toHaveLength(0);
    expect(
      visible(
        quick({ query: "Visible message", scope: "visibleColumns" }),
        [providerOnly]
      )
    ).toHaveLength(1);
  });

  it("applies the ordinary provider search used by the timeline and export", () => {
    const providerOnly = record({ provider: "ProviderOnly", message: "Other message" });
    expect(
      selectVisibleRecords({
        records: [providerOnly],
        selectedChannels: new Set(["Application"]),
        filterLevels: new Set(["Information"]),
        filterEventIds: "",
        filterSearch: "ProviderOnly",
        quickFilter: quick(),
        visibleColumns: ["message"],
      })
    ).toHaveLength(1);
  });

  it("can hide matching records instead of showing them", () => {
    expect(visible(quick({ query: "Boot", action: "hide" }))).toHaveLength(0);
    expect(visible(quick({ query: "Other", action: "hide" }))).toHaveLength(1);
  });

  it("does not broaden invalid Event ID quick filters under show or hide", () => {
    expect(visible(quick({ mode: "eventIds", query: "not-an-id" }))).toHaveLength(0);
    expect(
      visible(quick({ mode: "eventIds", query: "99999999999", action: "hide" }))
    ).toHaveLength(0);
  });

  it("does not constrain an empty quick filter", () => {
    expect(visible(quick())).toHaveLength(1);
  });
  it("rejects separator-only all-strings queries", () => {
    expect(visible(quick({ mode: "allStrings", query: ",,,; ;" }))).toHaveLength(0);
  });
});
describe("ordinary Event ID invalid input", () => {
  it.each(["70000", "-1", "not-an-id"])("matches no records for %s", (filterEventIds) => {
    expect(
      selectVisibleRecords({
        records: [record()],
        selectedChannels: new Set(["Application"]),
        filterLevels: new Set(["Information"]),
        filterEventIds,
        filterSearch: "",
      })
    ).toHaveLength(0);
  });
});
it("excludes records outside the selected level set", () => {
  expect(
    selectVisibleRecords({
      records: [record({ level: "Error" })],
      selectedChannels: new Set(["Application"]),
      filterLevels: new Set(["Information"]),
      filterEventIds: "",
      filterSearch: "",
    })
  ).toHaveLength(0);
});



describe("event id range bounds", () => {
  it("does not expand past the 16-bit event id space", () => {
    // Typed on every keystroke. Unbounded, "4624-46240000" builds a set of tens of millions on the
    // UI thread and the tab stops responding before the operator finishes typing.
    const started = Date.now();
    const ids = parseEventIdFilter("4624-46240000");
    expect(Date.now() - started).toBeLessThan(1000);
    expect(ids).not.toBeNull();
    expect(ids!.size).toBeLessThanOrEqual(65536);
    expect(ids!.has(4624)).toBe(true);
    expect(ids!.has(65535)).toBe(true);
    expect(ids!.has(65536)).toBe(false);
  });

  it("clamps the first value beyond the bounded range", () => {
    const ids = parseEventIdFilter("1-65536");
    expect(ids?.size).toBe(65535);
    expect(ids?.has(1)).toBe(true);
    expect(ids?.has(65535)).toBe(true);
    expect(ids?.has(65536)).toBe(false);
  });

  it("preserves the complete 16-bit event ID space", () => {
    expect(parseEventIdFilter("0-65535")?.size).toBe(65536);
    expect(parseEventIdFilter("1-65535,0")?.size).toBe(65536);
  });

  it("yields an empty set for a range entirely above the id space", () => {
    expect(parseEventIdFilter("100000-200000")).toEqual(new Set());
  });

  it("still expands an ordinary range", () => {
    const ids = parseEventIdFilter("4624-4626");
    expect([...ids!].sort((a, b) => a - b)).toEqual([4624, 4625, 4626]);
  });

  it("handles a large Event ID range across many records in one visible pass", () => {
    const records = Array.from({ length: 5000 }, (_, index) =>
      record({ eventId: index % 65536 })
    );
    expect(
      selectVisibleRecords({
        records,
        selectedChannels: new Set(["Application"]),
        filterLevels: new Set(["Information"]),
        filterEventIds: "1-65535",
        filterSearch: "",
      })
    ).toHaveLength(4999);
  });
});
describe("time-window boundaries", () => {
  it("includes the exact lower boundary and excludes older records", () => {
    const now = 10_000;
    expect(isWithinTimeWindow(now - 60 * 60 * 1000, "1h", now)).toBe(true);
    expect(isWithinTimeWindow(now - 60 * 60 * 1000 - 1, "1h", now)).toBe(false);
    expect(isWithinTimeWindow(now - 1, "all", now)).toBe(true);
  });
  it("applies the before-load window in the production visible predicate", () => {
    const now = Date.parse("2026-08-18T12:00:00.000Z");
    const inWindow = record({ timestampEpoch: now - 60 * 60 * 1000 });
    const old = record({ timestampEpoch: now - 60 * 60 * 1000 - 1 });
    const visibleRecords = selectVisibleRecords({
      records: [inWindow, old],
      selectedChannels: new Set(["Application"]),
      filterLevels: new Set(["Information"]),
      filterEventIds: "",
      filterSearch: "",
      visibleColumns: ["timestamp"],
      timeZoneMode: "utc",
      timeWindow: "1h",
      nowEpoch: now,
    });
    expect(visibleRecords).toEqual([inWindow]);
  });
});


describe("sortRecords", () => {
  it("preserves the active timeline order for exports", () => {
    const records = [
      { eventId: 2, timestampEpoch: 20, level: "Information", provider: "P", channel: "C" },
      { eventId: 1, timestampEpoch: 10, level: "Error", provider: "P", channel: "C" },
    ] as EvtxRecord[];
    expect(sortRecords(records, "time", "asc").map((record) => record.eventId)).toEqual([1, 2]);
    expect(sortRecords(records, "time", "desc").map((record) => record.eventId)).toEqual([2, 1]);
  });
});
