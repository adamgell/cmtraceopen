import { describe, expect, it, vi } from "vitest";
import {
  compileFieldQuery,
  countByLevel,
  EVTX_LEVELS,
  fieldQueryError,
  isWithinTimeWindow,
  levelsAfterToggle,
  levelsFilteredAtSource,
  matchesQuickFilter,
  parseEventIdSelectors,
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



describe("event id range matching", () => {
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

  it("matches nothing for a query that does not parse, and says why", () => {
    expect(searched("level:erro")).toEqual([]);
    expect(searched('token "broker')).toEqual([]);
    expect(searched("token OR")).toEqual([]);
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
  });

  it("honours Case for text values, but not for field names, levels or IDs", () => {
    expect(fieldQuick("token", { caseSensitive: true })).toEqual([]);
    expect(fieldQuick("Token", { caseSensitive: true })).toEqual(["aad"]);
    expect(fieldQuick("provider:aad", { caseSensitive: true })).toEqual([]);
    expect(fieldQuick("PROVIDER:AAD", { caseSensitive: true })).toEqual(["aad"]);
    expect(fieldQuick("LEVEL:ERROR", { caseSensitive: true })).toEqual(["aad", "mdm"]);
  });

  it("removes the matches with a hide rule", () => {
    expect(fieldQuick("level:error", { action: "hide" })).toEqual(["power", "service"]);
  });

  it("shows nothing for a query that does not parse, for a hide rule as well", () => {
    expect(fieldQuick("level:erro")).toEqual([]);
    // The Event IDs mode hides nothing for an invalid hide rule. This mode does not: every record
    // under an exclusion that never applied would read as a complete result.
    expect(fieldQuick("level:erro", { action: "hide" })).toEqual([]);
  });

  it("gives the row's match state the same answer, and false for a query that does not parse", () => {
    const filter = quick({ mode: "fieldQuery", query: "level:error -id:76" });
    expect(matchesQuickFilter(fieldRecords.aad, filter, ["message"])).toBe(true);
    expect(matchesQuickFilter(fieldRecords.mdm, filter, ["message"])).toBe(false);
    expect(
      matchesQuickFilter(fieldRecords.aad, quick({ mode: "fieldQuery", query: "level:" }), ["message"]),
    ).toBe(false);
  });

  it("compiles with the quick filter's case rule", () => {
    const compiled = compileFieldQuery("Token", true);
    expect(compiled.ok && compiled.query.caseSensitive).toBe(true);
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
