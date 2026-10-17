import { describe, expect, it, vi } from "vitest";
import {
  compileFieldQuery,
  countByLevel,
  countHiddenForWantOfTimestamp,
  EVTX_LEVELS,
  EVTX_LEVEL_RANK,
  EVTX_RAW_LEVEL,
  fieldQueryError,
  hasUsableTimestamp,
  isWithinTimeRange,
  isWithinTimeWindow,
  levelsAfterToggle,
  levelsFilteredAtSource,
  matchesQuickFilter,
  parseEventIdSelectors,
  quickFilterApplies,
  selectVisibleRecords,
  sortRecords,
  type EvtxQuickFilter,
} from "./evtx-filter";
import * as evtxColumns from "./evtx-columns";
import * as evtxQueryGrammar from "./evtx-query-grammar";
import { migratePersistedSavedFilters } from "./evtx-filter-store";
import {
  buildFilterExport,
  parseFilterExport,
  SAVED_FILTER_SCHEMA,
  sanitizeCriteria,
  sanitizeQuickFilter,
  type EvtxSavedFilter,
} from "./evtx-saved-filters";
import type { EvtxLevel, EvtxRecord } from "./types";

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

/** The two transient criteria off: every call of the selector states them (they are required). */
const NO_TRANSIENT = { timeRange: null, scopeRecords: null } as const;

const quick = (overrides: Partial<EvtxQuickFilter> = {}): EvtxQuickFilter => ({
  mode: "oneString",
  query: "",
  scope: "allColumns",
  action: "show",
  caseSensitive: false,
  highlight: true,
  ...overrides,
});

const visible = (
  quickFilter: EvtxQuickFilter,
  records: EvtxRecord[] = [record()]
) =>
  selectVisibleRecords({
    ...NO_TRANSIENT,
    records,
    selectedChannels: new Set(["Application"]),
    filterLevels: new Set(EVTX_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    quickFilter,
    visibleColumns: ["message"],
  });

describe("Event ID selectors", () => {
  it("returns no selectors for an empty filter", () => {
    expect(parseEventIdSelectors("   ")).toEqual({ selectors: [], invalid: false });
  });

  it("parses singles and normalized ranges without expanding them", () => {
    expect(parseEventIdSelectors("1, 8-5 4294967295")).toEqual({
      selectors: [
        { kind: "single", id: 1 },
        { kind: "range", low: 5, high: 8 },
        { kind: "single", id: 4294967295 },
      ],
      invalid: false,
    });
  });

  it("marks the whole selector invalid when any token is malformed or out of range", () => {
    expect(parseEventIdSelectors("4624,not-an-id").invalid).toBe(true);
    expect(parseEventIdSelectors("4294967296").invalid).toBe(true);
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
        ...NO_TRANSIENT,
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

  it("treats an invalid Event ID query as matching nothing for either action", () => {
    expect(visible(quick({ mode: "eventIds", query: "not-an-id" }))).toHaveLength(0);
    expect(
      visible(quick({ mode: "eventIds", query: "99999999999", action: "hide" }))
    ).toHaveLength(1);
  });

  it("does not constrain an empty quick filter", () => {
    expect(visible(quick())).toHaveLength(1);
  });
  it("rejects separator-only all-strings queries", () => {
    expect(visible(quick({ mode: "allStrings", query: ",,,; ;" }))).toHaveLength(0);
  });
});
describe("ordinary Event ID invalid input", () => {
  it.each(["4294967296", "-1", "not-an-id"])("matches no records for %s", (filterEventIds) => {
    expect(
      selectVisibleRecords({
        ...NO_TRANSIENT,
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
      ...NO_TRANSIENT,
      records: [record({ level: "Error" })],
      selectedChannels: new Set(["Application"]),
      filterLevels: new Set(["Information"]),
      filterEventIds: "",
      filterSearch: "",
    })
  ).toHaveLength(0);
});



describe("event id range matching", () => {
  it("handles a large Event ID range across many records in one visible pass", () => {
    const records = Array.from({ length: 5000 }, (_, index) =>
      record({ eventId: index % 65536 })
    );
    expect(
      selectVisibleRecords({
        ...NO_TRANSIENT,
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
      ...NO_TRANSIENT,
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
      record({ eventId: 2, timestampEpoch: 20, level: "Information", provider: "P", channel: "C" }),
      record({ eventId: 1, timestampEpoch: 10, level: "Error", provider: "P", channel: "C" }),
    ];
    expect(sortRecords(records, "time", "asc").map((record) => record.eventId)).toEqual([1, 2]);
    expect(sortRecords(records, "time", "desc").map((record) => record.eventId)).toEqual([2, 1]);
  });
});

describe("countByLevel", () => {
  it("counts every level in one pass and reports a level with no records as zero", () => {
    const records = [
      record({ level: "Error" }),
      record({ level: "Error" }),
      record({ level: "Warning" }),
      record({ level: "Information" }),
      record({ level: "Information" }),
      record({ level: "Information" }),
    ];

    expect(countByLevel(records)).toEqual({
      Critical: 0,
      Error: 2,
      Warning: 1,
      Information: 3,
      Verbose: 0,
    });
  });

  it("counts the records it is given and nothing else: channel and level filters do not apply", () => {
    // The level toggles show what is loaded, so a record in a deselected channel still counts.
    const records = [
      record({ level: "Critical", channel: "Security" }),
      record({ level: "Critical", channel: "Application" }),
    ];

    expect(countByLevel(records).Critical).toBe(2);
  });

  it("returns all zeros for no records", () => {
    expect(countByLevel([])).toEqual({
      Critical: 0,
      Error: 0,
      Warning: 0,
      Information: 0,
      Verbose: 0,
    });
  });

  it("has a key for every level the filter bar lists, in severity order", () => {
    expect(EVTX_LEVELS).toEqual(["Critical", "Error", "Warning", "Information", "Verbose"]);
    expect(Object.keys(countByLevel([]))).toEqual([...EVTX_LEVELS]);
  });
});

describe("the level maps", () => {
  it("names the Windows raw level of every level, apart from the display order", () => {
    expect(EVTX_RAW_LEVEL).toEqual({
      Critical: 1,
      Error: 2,
      Warning: 3,
      Information: 4,
      Verbose: 5,
    });
    expect(Object.keys(EVTX_RAW_LEVEL).sort()).toEqual([...EVTX_LEVELS].sort());
  });

  it("ranks the levels by their place in EVTX_LEVELS, most severe first", () => {
    expect(EVTX_LEVEL_RANK).toEqual({
      Critical: 0,
      Error: 1,
      Warning: 2,
      Information: 3,
      Verbose: 4,
    });
    const sorted = sortRecords(
      [record({ level: "Verbose" }), record({ level: "Critical" }), record({ level: "Warning" })],
      "level",
      "asc",
    );
    expect(sorted.map((r) => r.level)).toEqual(["Critical", "Warning", "Verbose"]);
  });
});

describe("levelsFilteredAtSource", () => {
  const set = (...levels: EvtxLevel[]) => new Set<EvtxLevel>(levels);

  it("is false when every level is selected, because no level predicate is sent", () => {
    expect(levelsFilteredAtSource(set(...EVTX_LEVELS))).toBe(false);
  });

  it("is false while Information is selected, because Information is an unbounded raw-level domain kept local", () => {
    expect(levelsFilteredAtSource(set("Critical", "Information"))).toBe(false);
    expect(levelsFilteredAtSource(set("Information"))).toBe(false);
  });

  it("is true for a strict subset without Information", () => {
    expect(levelsFilteredAtSource(set("Critical", "Error"))).toBe(true);
    expect(levelsFilteredAtSource(set("Verbose"))).toBe(true);
  });

  it("is false for an empty selection, which the store never sends", () => {
    expect(levelsFilteredAtSource(set())).toBe(false);
  });
});

describe("levelsAfterToggle", () => {
  const set = (...levels: EvtxLevel[]) => new Set<EvtxLevel>(levels);

  it("flips one level without touching the others or the input", () => {
    const before = set(...EVTX_LEVELS);
    const after = levelsAfterToggle(before, "Verbose");
    expect([...after]).toEqual(["Critical", "Error", "Warning", "Information"]);
    expect(before.has("Verbose")).toBe(true);
    expect(levelsAfterToggle(after, "Verbose").has("Verbose")).toBe(true);
  });

  it("selects every level again when the last one is toggled off", () => {
    expect([...levelsAfterToggle(set("Error"), "Error")].sort()).toEqual([...EVTX_LEVELS].sort());
  });
});

/** Four records with distinct values in every field the grammar can name. */
const fieldRecords = {
  aad: record({
    id: 1,
    eventRecordId: 1,
    provider: "Microsoft-Windows-AAD",
    channel: "Microsoft-Windows-AAD/Operational",
    eventId: 1098,
    level: "Error",
    computer: "PC-01",
    message: "Token broker error",
    eventData: [{ name: "Error", value: "0xCAA2000C" }],
    sourceLabel: "Live/AAD",
  }),
  mdm: record({
    id: 2,
    eventRecordId: 2,
    provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
    channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    eventId: 76,
    level: "Error",
    computer: "PC-01",
    message: "Auto MDM Enroll: Failed",
    eventData: [{ name: "ErrorCode", value: "0x80180001" }],
    sourceLabel: "C:\\logs\\dm.evtx",
  }),
  power: record({
    id: 3,
    eventRecordId: 3,
    provider: "Microsoft-Windows-Kernel-Power",
    channel: "System",
    eventId: 41,
    level: "Critical",
    computer: "PC-01",
    message: "The system has rebooted without cleanly shutting down first.",
    eventData: [{ name: "BugcheckCode", value: "0" }],
    sourceLabel: "Live/System",
  }),
  service: record({
    id: 4,
    eventRecordId: 4,
    provider: "Service Control Manager",
    channel: "System",
    eventId: 7036,
    level: "Information",
    computer: "PC-02",
    message: "Logon failed. Status: 0xC000006D at C:\\Windows\\System32\\svchost.exe",
    eventData: [{ name: "param1", value: "Windows Update" }],
    sourceLabel: "Live/System",
  }),
};
const allFieldRecords = Object.values(fieldRecords);
const fieldChannels = new Set(allFieldRecords.map((entry) => entry.channel));
const names = (records: EvtxRecord[]) =>
  records.map((entry) => Object.keys(fieldRecords).find((key) =>
    fieldRecords[key as keyof typeof fieldRecords] === entry));

/** The records the search box leaves on screen for `filterSearch`. */
const searched = (filterSearch: string, quickFilter?: EvtxQuickFilter) =>
  names(
    selectVisibleRecords({
      ...NO_TRANSIENT,
      records: allFieldRecords,
      selectedChannels: fieldChannels,
      filterLevels: new Set(EVTX_LEVELS),
      filterEventIds: "",
      filterSearch,
      quickFilter,
      visibleColumns: ["message"],
    }),
  );

/** The records a `fieldQuery` quick filter leaves on screen. */
const fieldQuick = (query: string, overrides: Partial<EvtxQuickFilter> = {}) =>
  searched("", quick({ mode: "fieldQuery", query, ...overrides }));

describe("field query terms", () => {
  it("id: matches single IDs and inclusive ranges exactly, as the Event IDs mode does", () => {
    expect(searched("id:76")).toEqual(["mdm"]);
    expect(searched("id:1098,76")).toEqual(["aad", "mdm"]);
    expect(searched("id:40-80")).toEqual(["mdm", "power"]);
    // Exact, never a substring of 76 or 7036.
    expect(searched("id:7")).toEqual([]);
  });

  it("id: rejects a value the Event ID grammar rejects, at the value", () => {
    expect(fieldQueryError("level:error id:12x")).toEqual({
      position: 15,
      message:
        'id: takes Event IDs and ranges from 0 to 4294967295, as in id:4624,4625 or id:4624-4634, not "12x".',
    });
    expect(fieldQueryError("id:4294967296")).toMatchObject({ position: 3 });
    expect(fieldQueryError("id:,")).toMatchObject({ position: 3 });
  });

  it("level: maps names through EVTX_LEVELS case-insensitively, with info and comma lists", () => {
    expect(searched("level:ERROR")).toEqual(["aad", "mdm"]);
    // "Info" is the filter row's label for Information.
    expect(searched("level:info")).toEqual(["service"]);
    expect(searched("level:Information")).toEqual(["service"]);
    expect(searched("level:critical,information")).toEqual(["power", "service"]);
  });

  it("level: rejects an unknown name at that name, and an empty list at the term", () => {
    expect(fieldQueryError("level:error,erro")).toEqual({
      position: 12,
      message: 'level: takes critical, error, warning, info, information or verbose, not "erro".',
    });
    expect(fieldQueryError('level:"error, erro"')).toMatchObject({ position: 14 });
    expect(fieldQueryError("level:,")).toEqual({ position: 0, message: "level: needs a value." });
  });

  it("provider, channel, computer and source match a case-insensitive substring", () => {
    expect(searched("provider:aad")).toEqual(["aad"]);
    expect(searched("channel:SYSTEM")).toEqual(["power", "service"]);
    expect(searched("computer:pc-02")).toEqual(["service"]);
    // The record's source label: a live channel or a file path.
    expect(searched("source:live/")).toEqual(["aad", "power", "service"]);
    expect(searched('source:"dm.evtx"')).toEqual(["mdm"]);
  });

  it("data.<Name>: matches the EventData field of that name, the name case-insensitively", () => {
    expect(searched("data.errorcode:0x8018")).toEqual(["mdm"]);
    expect(searched("data.Error:caa2")).toEqual(["aad"]);
    // The value is searched only in the named field: the AAD record's code is in Error.
    expect(searched("data.ErrorCode:CAA2")).toEqual([]);
  });

  it("a negated data term keeps the records that lack the field", () => {
    expect(searched("-data.ErrorCode:0x8018")).toEqual(["aad", "power", "service"]);
  });

  it("ANDs clauses, ORs within a clause, and excludes negated terms", () => {
    expect(searched("provider:DeviceManagement OR id:1098,1014")).toEqual(["aad", "mdm"]);
    expect(searched("level:error -provider:aad")).toEqual(["mdm"]);
    expect(searched("channel:system -id:7036")).toEqual(["power"]);
    expect(searched("level:error computer:PC-01 OR id:41")).toEqual(["aad", "mdm"]);
  });
});

describe("the search box speaks the field grammar", () => {
  it("keeps the old free-text rule for a word: a case-insensitive substring of message or provider", () => {
    expect(searched("TOKEN")).toEqual(["aad"]);
    expect(searched("kernel-power")).toEqual(["power"]);
    // Free text never searched the computer or EventData, and still does not.
    expect(searched("PC-02")).toEqual([]);
    expect(searched("0xCAA2000C")).toEqual([]);
  });

  it("matches each bare word anywhere, where it used to match the whole text as one phrase", () => {
    expect(searched("broker token")).toEqual(["aad"]);
    expect(searched('"broker token"')).toEqual([]);
    expect(searched('"token broker"')).toEqual(["aad"]);
  });

  it("reads text with a colon before something that is not a field as text", () => {
    expect(searched("Status: 0xC000006D")).toEqual(["service"]);
    expect(searched("C:\\Windows\\System32")).toEqual(["service"]);
    expect(fieldQueryError("Status: 0xC000006D C:\\Windows\\System32 http://host 12:00:01")).toBeNull();
  });

  it("does not apply a query that does not parse, not even in part, and says why (spec 8.3)", () => {
    const every = ["aad", "mdm", "power", "service"];
    expect(searched("level:erro")).toEqual(every);
    // "token" alone would narrow to one record: the valid part is not applied either.
    expect(searched('token "broker')).toEqual(every);
    expect(searched("token OR")).toEqual(every);
    expect(fieldQueryError("level:erro")?.message).toBe(
      'level: takes critical, error, warning, info, information or verbose, not "erro".',
    );
    expect(fieldQueryError('token "broker')?.message).toBe("The quote at character 7 is not closed.");
  });

  it("has no error for blank text or a query that parses", () => {
    expect(fieldQueryError("   ")).toBeNull();
    expect(fieldQueryError("id:76  level:error  provider:AAD")).toBeNull();
  });

  it("compiles the search and a field quick filter once per pass, not once per record", () => {
    const parse = vi.spyOn(evtxQueryGrammar, "parseFieldQuery");
    try {
      expect(searched("level:error", quick({ mode: "fieldQuery", query: "-id:76" }))).toEqual([
        "aad",
      ]);
      expect(parse).toHaveBeenCalledTimes(2);
    } finally {
      parse.mockRestore();
    }
  });
});

describe("the fieldQuery quick-filter mode", () => {
  it("searches free text in the quick filter's scope, EventData included for all columns", () => {
    expect(fieldQuick("0xcaa2", { scope: "allColumns" })).toEqual(["aad"]);
    expect(fieldQuick("0xcaa2", { scope: "visibleColumns" })).toEqual([]);
    // Unlike the search box, the computer column is searched when it is in scope.
    expect(fieldQuick("PC-02", { scope: "allColumns" })).toEqual(["service"]);
  });

  it("applies field terms whatever the scope: the term names its field", () => {
    expect(fieldQuick("provider:aad", { scope: "visibleColumns" })).toEqual(["aad"]);
    // The visible columns are only the message here, so no field these terms name is in scope.
    expect(
      fieldQuick("channel:system source:live/ data.param1:update", { scope: "visibleColumns" }),
    ).toEqual(["service"]);
  });

  it("applies Case to free text only: every field value matches whatever its case (spec 8.3)", () => {
    const caseOn = { caseSensitive: true };
    expect(fieldQuick("token", caseOn)).toEqual([]);
    expect(fieldQuick("Token", caseOn)).toEqual(["aad"]);
    expect(fieldQuick("provider:aad", caseOn)).toEqual(["aad"]);
    expect(fieldQuick("PROVIDER:AAD", caseOn)).toEqual(["aad"]);
    expect(fieldQuick("channel:SYSTEM", caseOn)).toEqual(["power", "service"]);
    expect(fieldQuick("computer:pc-02", caseOn)).toEqual(["service"]);
    // source: and data.<Name>: follow the same rule, a recorded addition to spec 8.3.
    expect(fieldQuick("source:LIVE/aad", caseOn)).toEqual(["aad"]);
    expect(fieldQuick("data.Error:caa2", caseOn)).toEqual(["aad"]);
    expect(fieldQuick("data.ERRORCODE:0X8018", caseOn)).toEqual(["mdm"]);
    expect(fieldQuick("LEVEL:ERROR", caseOn)).toEqual(["aad", "mdm"]);
  });

  it("still applies Case to the free text of a query that also has field terms", () => {
    const caseOn = { caseSensitive: true };
    expect(fieldQuick("provider:aad token", caseOn)).toEqual([]);
    expect(fieldQuick("provider:aad Token", caseOn)).toEqual(["aad"]);
  });

  it("ignores Case for field values under negation and inside an OR group", () => {
    const caseOn = { caseSensitive: true };
    expect(fieldQuick("-provider:aad", caseOn)).toEqual(["mdm", "power", "service"]);
    expect(fieldQuick("provider:aad OR channel:system", caseOn)).toEqual([
      "aad",
      "power",
      "service",
    ]);
    expect(fieldQuick("-data.errorcode:0x8018 level:error", caseOn)).toEqual(["aad"]);
  });

  it("ignores Case for field values in a quick filter loaded from a saved filter", () => {
    const loaded = sanitizeQuickFilter(
      quick({ mode: "fieldQuery", query: "provider:aad", caseSensitive: true }),
    );
    expect(loaded.caseSensitive).toBe(true);
    expect(searched("", loaded)).toEqual(["aad"]);
  });

  it("removes the matches with a hide rule", () => {
    expect(fieldQuick("level:error", { action: "hide" })).toEqual(["power", "service"]);
  });

  it("does not apply a query that does not parse, as a show rule or a hide rule (spec 8.3)", () => {
    const every = ["aad", "mdm", "power", "service"];
    expect(fieldQuick("level:erro")).toEqual(every);
    expect(fieldQuick("level:error -id:", { action: "hide" })).toEqual(every);
  });

  it("can be applied as edited unless it is a field query that does not parse", () => {
    expect(quickFilterApplies(quick({ mode: "fieldQuery", query: "level:error" }))).toBe(true);
    expect(quickFilterApplies(quick({ mode: "fieldQuery", query: "  " }))).toBe(true);
    expect(quickFilterApplies(quick({ mode: "fieldQuery", query: "level:" }))).toBe(false);
    // Other modes have no grammar to fail, and Event IDs keeps its own rule for a bad list.
    expect(quickFilterApplies(quick({ mode: "oneString", query: "level:" }))).toBe(true);
    expect(quickFilterApplies(quick({ mode: "eventIds", query: "abc" }))).toBe(true);
  });

  it("gives the row's match state the same answer, and false for a query that does not parse", () => {
    const filter = quick({ mode: "fieldQuery", query: "level:error -id:76" });
    expect(matchesQuickFilter(fieldRecords.aad, filter, ["message"])).toBe(true);
    expect(matchesQuickFilter(fieldRecords.mdm, filter, ["message"])).toBe(false);
    expect(
      matchesQuickFilter(fieldRecords.aad, quick({ mode: "fieldQuery", query: "level:" }), ["message"]),
    ).toBe(false);
  });

  it("compiles free text with the Case setting and every field value in lower case", () => {
    const compiled = compileFieldQuery("Token provider:AAD data.Error:CAA2", true);
    expect(compiled.ok && compiled.query.clauses).toMatchObject([
      [{ kind: "text", needle: "Token" }],
      [{ kind: "textField", field: "provider", needle: "aad" }],
      [{ kind: "data", name: "error", needle: "caa2" }],
    ]);
  });
});

describe("saved filters carry the fieldQuery mode", () => {
  const fieldFilter: EvtxQuickFilter = {
    mode: "fieldQuery",
    query: "provider:DeviceManagement OR id:1098,1014",
    scope: "visibleColumns",
    action: "hide",
    caseSensitive: true,
    highlight: false,
  };
  const saved: EvtxSavedFilter = {
    id: "enrollment",
    name: "Enrollment",
    favorite: false,
    tags: [],
    lastUsed: null,
    criteria: sanitizeCriteria({
      onLoad: { search: "level:error -source:dm.evtx", quickFilter: fieldFilter },
    }),
  };

  it("keeps the mode and every quick-filter setting when sanitized", () => {
    expect(sanitizeQuickFilter(fieldFilter)).toEqual(fieldFilter);
    expect(saved.criteria.onLoad).toEqual({
      search: "level:error -source:dm.evtx",
      quickFilter: fieldFilter,
    });
  });

  it("round-trips through an export file without a schema change", () => {
    expect(SAVED_FILTER_SCHEMA).toBe(2);
    const imported = parseFilterExport(buildFilterExport([saved]));
    expect(imported).toEqual({ filters: [saved], skipped: 0 });
    expect(imported.filters[0].criteria.onLoad.quickFilter).toEqual(fieldFilter);
  });

  it("round-trips through local storage", () => {
    const restored = migratePersistedSavedFilters({ savedFilters: [saved] }, 2);
    expect(restored).toEqual({ savedFilters: [saved] });
    expect(restored.savedFilters[0].criteria.onLoad.quickFilter).toEqual(fieldFilter);
  });

  it("falls back in an older build to One string: a show rule matches nothing, a hide rule hides nothing", () => {
    // An older build's sanitizer has no fieldQuery, so it treats the value as this one treats any
    // unknown mode: One string, with the query kept as typed.
    const older = sanitizeQuickFilter({ ...fieldFilter, mode: "aModeThisBuildDoesNotKnow" });
    expect(older).toEqual({ ...fieldFilter, mode: "oneString" });
    const unscoped = { ...older, scope: "allColumns" as const, caseSensitive: false };
    expect(searched("", { ...unscoped, action: "show" })).toEqual([]);
    // Reported to Main: no record contains the query text, so an older build's hide rule widens
    // to every record. That build cannot be changed from here.
    expect(searched("", { ...unscoped, action: "hide" })).toEqual([
      "aad",
      "mdm",
      "power",
      "service",
    ]);
  });
});

describe("source: matches the grid record's source label", () => {
  // The labels the backend gives grid records: an EVTX file's path, an archive member's
  // "<archive>::<member>" label (text members too), and "Live" or "Remote: <machine>".
  const evtxFile = record({
    id: 21,
    eventRecordId: 21,
    sourceLabel: "C:\\logs\\System.evtx",
    channel: "System",
  });
  const archiveText = record({
    id: 22,
    eventRecordId: 22,
    originKind: "log",
    sourceLabel: "evidence.zip::logs/AppIntent.log",
    channel: "evidence.zip::logs/AppIntent.log",
    provider: "AppIntentHandler",
  });
  const live = record({ id: 23, eventRecordId: 23, sourceLabel: "Live", channel: "Application" });
  const remote = record({ id: 24, eventRecordId: 24, sourceLabel: "Remote: PC-07", channel: "Application" });
  const sources = [evtxFile, archiveText, live, remote];
  const matching = (query: string) =>
    selectVisibleRecords({
      ...NO_TRANSIENT,
      records: sources,
      selectedChannels: new Set(sources.map((entry) => entry.channel)),
      filterLevels: new Set(EVTX_LEVELS),
      filterEventIds: "",
      filterSearch: query,
    }).map((entry) => entry.id);

  it("matches each kind of label by substring", () => {
    expect(matching("source:System.evtx")).toEqual([21]);
    // A text-log line from an evidence archive: its label is the file it came from, which is the
    // origin.file the analysis session records for it, never the code file a CCM line names.
    expect(matching("source:AppIntent.log")).toEqual([22]);
    expect(matching("source:evidence.zip::")).toEqual([22]);
    expect(matching("source:live")).toEqual([23]);
    expect(matching('source:"Remote: PC-07"')).toEqual([24]);
  });
});

describe("transient criteria in selectVisibleRecords", () => {
  const at = (id: number, timestampEpoch: number, overrides: Partial<EvtxRecord> = {}) =>
    record({ id, eventRecordId: id, timestampEpoch, ...overrides });
  const base = (records: EvtxRecord[]) => ({
    records,
    selectedChannels: new Set(["Application", "System"]),
    filterLevels: new Set(EVTX_LEVELS),
    filterEventIds: "",
    filterSearch: "",
    ...NO_TRANSIENT,
  });
  const ids = (list: EvtxRecord[]) => list.map((r) => r.id);

  describe("the time range", () => {
    const records = [at(1, 99), at(2, 100), at(3, 200), at(4, 299), at(5, 300), at(6, 301)];
    const range = { startMs: 100, endMs: 300 };

    it("is half open: the start is inside it and the end is not", () => {
      expect(ids(selectVisibleRecords({ ...base(records), timeRange: range }))).toEqual([2, 3, 4]);
      expect(isWithinTimeRange(at(1, 100), range)).toBe(true);
      expect(isWithinTimeRange(at(1, 300), range)).toBe(false);
    });

    it("lets two adjacent ranges share no event", () => {
      const left = selectVisibleRecords({ ...base(records), timeRange: { startMs: 100, endMs: 200 } });
      const right = selectVisibleRecords({ ...base(records), timeRange: { startMs: 200, endMs: 300 } });
      expect(ids(left)).toEqual([2]);
      expect(ids(right)).toEqual([3, 4]);
    });

    it("places no record without a usable timestamp, even in a range that holds zero", () => {
      const untimed = [at(1, 0), at(2, Number.NaN), at(3, -5), at(4, 150)];
      expect(ids(selectVisibleRecords({ ...base(untimed), timeRange: { startMs: -10, endMs: 1000 } }))).toEqual([4]);
      expect([0, Number.NaN, -5, Infinity].map((t) => hasUsableTimestamp(at(1, t)))).toEqual([
        false,
        false,
        false,
        false,
      ]);
      expect(hasUsableTimestamp(at(1, 1))).toBe(true);
    });

    it("changes nothing when it is null", () => {
      expect(selectVisibleRecords({ ...base(records), timeRange: null })).toEqual(records);
    });
  });

  describe("the record scope", () => {
    const records = [at(1, 10), at(2, 20), at(3, 30), at(4, 40)];

    it("keeps only the scoped records, and nothing for an empty scope", () => {
      expect(ids(selectVisibleRecords({ ...base(records), scopeRecords: new Set([records[1], records[3]]) }))).toEqual([
        2, 4,
      ]);
      expect(selectVisibleRecords({ ...base(records), scopeRecords: new Set() })).toEqual([]);
    });

    it("changes nothing when it is null", () => {
      expect(selectVisibleRecords({ ...base(records), scopeRecords: null })).toEqual(records);
    });

    it("holds records by object, so a record that merely looks the same is not in the scope", () => {
      const twin = { ...records[1] };
      expect(selectVisibleRecords({ ...base(records), scopeRecords: new Set([twin]) })).toEqual([]);
    });

    it("keeps its records when the store renumbers their ids in place", () => {
      const scope = new Set([records[0], records[2]]);
      // A merge sorts the list again and rewrites every id; the objects stay.
      const renumbered = [at(0, 5), ...records];
      renumbered.forEach((r, index) => {
        r.id = index;
      });
      expect(selectVisibleRecords({ ...base(renumbered), scopeRecords: scope })).toEqual([
        records[0],
        records[2],
      ]);
      expect(ids(selectVisibleRecords({ ...base(renumbered), scopeRecords: scope }))).toEqual([1, 3]);
    });
  });

  describe("with every other criterion", () => {
    const records = [
      at(1, 100, { level: "Error", channel: "System", message: "disk failure" }),
      at(2, 110, { level: "Error", channel: "Application", message: "disk failure" }),
      at(3, 120, { level: "Warning", channel: "System", message: "disk failure" }),
      at(4, 130, { level: "Error", channel: "System", message: "network down" }),
      at(5, 500, { level: "Error", channel: "System", message: "disk failure" }),
    ];
    const everything = {
      ...base(records),
      selectedChannels: new Set(["System"]),
      filterLevels: new Set<EvtxLevel>(["Error"]),
      filterSearch: "disk",
      timeRange: { startMs: 100, endMs: 200 },
      scopeRecords: new Set(records),
    };

    it("ANDs the range and the scope with channels, levels and the search", () => {
      expect(ids(selectVisibleRecords(everything))).toEqual([1]);
    });

    it("lets each one narrow what the rest leave", () => {
      expect(ids(selectVisibleRecords({ ...everything, timeRange: null }))).toEqual([1, 5]);
      expect(ids(selectVisibleRecords({ ...everything, scopeRecords: new Set([records[4]]) }))).toEqual([]);
      expect(ids(selectVisibleRecords({ ...everything, scopeRecords: new Set([records[0], records[3]]) }))).toEqual([1]);
    });

    it("ANDs them with a hide rule", () => {
      // Hiding "disk" leaves record 4, which the range and the scope still allow.
      const hide = quick({ query: "disk", action: "hide" });
      expect(ids(selectVisibleRecords({ ...everything, filterSearch: "", quickFilter: hide }))).toEqual([4]);
    });

    it("ANDs them with the time window", () => {
      const hour = 60 * 60 * 1000;
      // The window's lower edge is 100 ms: record 1 sits on it and stays, one ms later it does not.
      expect(ids(selectVisibleRecords({ ...everything, timeWindow: "1h", nowEpoch: 100 + hour }))).toEqual([1]);
      expect(ids(selectVisibleRecords({ ...everything, timeWindow: "1h", nowEpoch: 101 + hour }))).toEqual([]);
    });
  });

  describe("countHiddenForWantOfTimestamp", () => {
    const records = [
      at(1, 150),
      at(2, 0, { message: "no clock" }),
      at(3, Number.NaN, { message: "no clock either" }),
      at(4, 0, { channel: "Elsewhere" }),
      at(5, 0, { level: "Verbose" }),
    ];
    const input = {
      ...base(records),
      filterLevels: new Set<EvtxLevel>(["Error", "Information"]),
      timeRange: { startMs: 100, endMs: 200 },
    };

    it("counts the events the other criteria show and the range cannot place", () => {
      // Record 4 is in a channel that is not selected and record 5 is a level that is not.
      expect(countHiddenForWantOfTimestamp(input)).toBe(2);
    });

    it("is zero without a range", () => {
      expect(countHiddenForWantOfTimestamp({ ...input, timeRange: null })).toBe(0);
    });
  });
});
