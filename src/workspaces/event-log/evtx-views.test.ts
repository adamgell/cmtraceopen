import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { EVTX_LEVELS, fieldQueryError, selectVisibleRecords } from "./evtx-filter";
import { sanitizeCriteria, SAVED_FILTER_SCHEMA, type EvtxFilterCriteria } from "./evtx-saved-filters";
import {
  buildViewExport,
  captureLayout,
  cleanViewName,
  ENROLLMENT_TRIAGE_ID,
  ENROLLMENT_TRIAGE_QUERY,
  EVTX_BUILT_IN_VIEWS,
  listViews,
  MAX_CUSTOM_VIEWS,
  MAX_VIEW_FILE_LENGTH,
  MAX_VIEW_NAME_LENGTH,
  mergeViews,
  missingViewChannels,
  parseViewExport,
  sanitizeStoredViews,
  sanitizeViewBody,
  SAVED_VIEW_SCHEMA,
  uniqueViewName,
  viewDescription,
  viewMatchesCriteria,
  viewNameKey,
  viewNameTaken,
  viewSubtitle,
  type EvtxStoredView,
  type EvtxView,
  type EvtxViewBody,
} from "./evtx-views";
import type { EvtxRecord } from "./types";

/** Spec section 9 and Q-2, as 6a spells the names in code (record 1): the issue says scopeRecordIds. */
const TRANSIENT = /timeRange|startMs|endMs|recordScope|scopeRecord/i;

const DMEDP = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";
const DMEDP_PROVIDER = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider";
const AAD = "Microsoft-Windows-AAD/Operational";
const DNS_PROVIDER = "Microsoft-Windows-DNS-Client";

const ch = (code: number) => String.fromCodePoint(code);

let nextId = 0;
const makeId = () => `made-${++nextId}`;

function record(partial: Partial<EvtxRecord> & Pick<EvtxRecord, "channel" | "provider" | "eventId" | "level">): EvtxRecord {
  nextId += 1;
  return {
    id: nextId,
    eventRecordId: nextId,
    timestamp: "2026-10-06T10:20:00Z",
    timestampEpoch: 1_790_000_000_000,
    computer: "CONTOSO-PC01",
    message: "m",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "fixture.evtx",
    ...partial,
  };
}

function body(partial: Partial<EvtxViewBody> = {}): EvtxViewBody {
  return {
    name: "Errors",
    criteria: sanitizeCriteria({
      beforeLoad: {
        levels: ["Error", "Critical"],
        eventIds: "41,6008",
        timeWindow: "7d",
        selectedChannels: ["System", "Application"],
      },
      onLoad: {
        search: "provider:Kernel",
        quickFilter: {
          mode: "fieldQuery",
          query: "id:41",
          scope: "visibleColumns",
          action: "hide",
          caseSensitive: true,
          highlight: false,
        },
      },
      afterLoad: { groupBy: ["provider", "level"] },
    }),
    layout: {
      activeView: "grouped",
      panels: { channels: true, insights: false, dock: false },
    },
    ...partial,
  };
}

/** A view body as JSON text a file or a hand edit would hold, ready to corrupt one field of. */
function plain(view: EvtxViewBody = body()): Record<string, any> {
  return JSON.parse(JSON.stringify(view));
}

describe("the schema and the limits", () => {
  it("starts at schema 1 and leaves the saved-filter schema at 2", () => {
    expect(SAVED_VIEW_SCHEMA).toBe(1);
    expect(SAVED_FILTER_SCHEMA).toBe(2);
    expect(JSON.parse(buildViewExport([])).schema).toBe(1);
  });

  it("pins the keys of a view: a field added to it is a schema decision", () => {
    expectTypeOf<keyof EvtxViewBody>().toEqualTypeOf<"name" | "criteria" | "layout">();
    expectTypeOf<keyof EvtxStoredView>().toEqualTypeOf<"id" | "name" | "criteria" | "layout">();
    expectTypeOf<keyof EvtxFilterCriteria>().toEqualTypeOf<"beforeLoad" | "onLoad" | "afterLoad">();
    expect(Object.keys(sanitizeViewBody(plain())!)).toEqual(["name", "criteria", "layout"]);
  });
});

// ---------------------------------------------------------------------------------------------
// Enrollment triage (Q-12)
// ---------------------------------------------------------------------------------------------

describe("the built-in Enrollment triage view", () => {
  const triage = EVTX_BUILT_IN_VIEWS[0];

  it("is the only built-in, and it is a built-in", () => {
    expect(EVTX_BUILT_IN_VIEWS).toHaveLength(1);
    expect(triage.id).toBe(ENROLLMENT_TRIAGE_ID);
    expect(triage.builtIn).toBe(true);
    expect(triage.name).toBe("Enrollment triage");
  });

  it("is a filter only: three exact channels, every level, no Event IDs, any time, no layout", () => {
    expect(triage.criteria.beforeLoad).toEqual({
      levels: [...EVTX_LEVELS],
      eventIds: "",
      timeWindow: "all",
      selectedChannels: [DMEDP, AAD, "System"],
    });
    expect(triage.criteria.onLoad.search).toBe(ENROLLMENT_TRIAGE_QUERY);
    expect(triage.criteria.onLoad.quickFilter.query).toBe("");
    expect(triage.criteria.afterLoad.groupBy).toEqual([]);
    expect(triage.layout).toBeNull();
    // The search is the field query, not the quick filter (a Top IDs click replaces the quick filter).
    expect(fieldQueryError(ENROLLMENT_TRIAGE_QUERY)).toBeNull();
  });

  it("is a view that survives being read back unchanged", () => {
    expect(sanitizeViewBody(JSON.parse(JSON.stringify(triage)))).toEqual({
      name: triage.name,
      criteria: triage.criteria,
      layout: null,
    });
  });

  /**
   * The union the spec asks for (8.15, Q-12): DeviceManagement Admin 75 and 76, AAD Operational at
   * Warning and above, DNS-Client 1014. Written here once, as a predicate, and compared with what
   * the query shows over the whole cross product.
   */
  const union = (r: EvtxRecord): boolean =>
    (r.channel.toLowerCase().includes("devicemanagement-enterprise-diagnostics-provider/admin") &&
      [75, 76].includes(r.eventId)) ||
    (r.channel.toLowerCase().includes("aad/operational") &&
      ["Critical", "Error", "Warning"].includes(r.level)) ||
    (r.provider.toLowerCase().includes("dns-client") && r.eventId === 1014);

  const shownBy = (query: string, records: EvtxRecord[]) =>
    new Set(
      selectVisibleRecords({
        records,
        selectedChannels: new Set(records.map((r) => r.channel)),
        filterLevels: new Set(EVTX_LEVELS),
        filterEventIds: "",
        filterSearch: query,
        timeRange: null,
        scopeRecords: null,
      }),
    );

  const IDS = [5, 72, 75, 76, 404, 813, 1014, 1098, 7036];
  const sources: Array<[string, string]> = [
    [DMEDP, DMEDP_PROVIDER],
    [AAD, "Microsoft-Windows-AAD"],
    ["System", DNS_PROVIDER],
    ["System", "Service Control Manager"],
    ["Application", "MsiInstaller"],
    // DNS-Client's own Operational log: its 1014 would still be DNS-Client 1014.
    ["Microsoft-Windows-DNS-Client/Operational", DNS_PROVIDER],
  ];
  const everyRecord = sources.flatMap(([channel, provider]) =>
    IDS.flatMap((eventId) =>
      EVTX_LEVELS.map((level) => record({ channel, provider, eventId, level })),
    ),
  );

  it("shows exactly the union of the three selections over every channel, provider, ID and level", () => {
    const shown = shownBy(ENROLLMENT_TRIAGE_QUERY, everyRecord);
    const wrong = everyRecord.filter((r) => shown.has(r) !== union(r));
    expect(wrong).toEqual([]);
    expect(shown.size).toBeGreaterThan(0);
    expect(shown.size).toBeLessThan(everyRecord.length);
  });

  it.each<[string, EvtxRecord, boolean]>([
    ["DeviceManagement Admin 75", record({ channel: DMEDP, provider: DMEDP_PROVIDER, eventId: 75, level: "Information" }), true],
    ["DeviceManagement Admin 76", record({ channel: DMEDP, provider: DMEDP_PROVIDER, eventId: 76, level: "Error" }), true],
    ["DeviceManagement Admin 72 is not part of it (Q-12)", record({ channel: DMEDP, provider: DMEDP_PROVIDER, eventId: 72, level: "Information" }), false],
    ["DeviceManagement Admin 404", record({ channel: DMEDP, provider: DMEDP_PROVIDER, eventId: 404, level: "Error" }), false],
    ["AAD Warning", record({ channel: AAD, provider: "Microsoft-Windows-AAD", eventId: 1098, level: "Warning" }), true],
    ["AAD Error", record({ channel: AAD, provider: "Microsoft-Windows-AAD", eventId: 1097, level: "Error" }), true],
    ["AAD Critical", record({ channel: AAD, provider: "Microsoft-Windows-AAD", eventId: 1, level: "Critical" }), true],
    ["AAD Information", record({ channel: AAD, provider: "Microsoft-Windows-AAD", eventId: 1104, level: "Information" }), false],
    ["AAD Verbose", record({ channel: AAD, provider: "Microsoft-Windows-AAD", eventId: 1104, level: "Verbose" }), false],
    ["DNS-Client 1014", record({ channel: "System", provider: DNS_PROVIDER, eventId: 1014, level: "Warning" }), true],
    ["another DNS-Client event", record({ channel: "System", provider: DNS_PROVIDER, eventId: 1015, level: "Warning" }), false],
    ["1014 from another provider", record({ channel: "System", provider: "Service Control Manager", eventId: 1014, level: "Warning" }), false],
    ["a Service Control Manager error in System", record({ channel: "System", provider: "Service Control Manager", eventId: 7031, level: "Error" }), false],
    ["an Application error", record({ channel: "Application", provider: "Application Error", eventId: 1000, level: "Error" }), false],
  ])("%s", (_name, r, shown) => {
    expect(shownBy(ENROLLMENT_TRIAGE_QUERY, [r]).has(r)).toBe(shown);
  });

  /**
   * The one place the 4-clause query and the union differ, pinned so a change to it is deliberate.
   * The query reads each clause as "not this source, or its rule", which equals the union only for a
   * record that belongs to one source. A record in the DeviceManagement or AAD channel whose
   * provider is DNS-Client belongs to two, and does not occur: DNS-Client does not log to them.
   */
  it("differs from the union only for a record in two sources at once (known, documented)", () => {
    const rows = [
      record({ channel: DMEDP, provider: DNS_PROVIDER, eventId: 75, level: "Information" }),
      record({ channel: AAD, provider: DNS_PROVIDER, eventId: 5, level: "Warning" }),
    ];
    const shown = shownBy(ENROLLMENT_TRIAGE_QUERY, rows);
    expect(rows.map((r) => union(r))).toEqual([true, true]);
    expect(rows.map((r) => shown.has(r))).toEqual([false, false]);
  });

  it("holds the same selections when the DeviceManagement channel has no Microsoft-Windows prefix", () => {
    const bare = record({
      channel: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
      provider: "DeviceManagement-Enterprise-Diagnostics-Provider",
      eventId: 76,
      level: "Error",
    });
    expect(shownBy(ENROLLMENT_TRIAGE_QUERY, [bare]).has(bare)).toBe(true);
  });

  it("states what it selects and makes no claim that the events are related", () => {
    // Every string the view shows, pinned: a change to any of them must be read.
    expect(triage.name).toBe("Enrollment triage");
    expect(viewSubtitle(triage)).toBe("Built-in, 3 filters");
    expect(viewDescription(triage)).toBe(
      "Selects events from three sources. " +
        "DeviceManagement Admin: Event IDs 75 and 76. " +
        "AAD Operational: Warning, Error and Critical events. " +
        "DNS-Client: Event ID 1014. " +
        "Channels: DeviceManagement Admin, AAD Operational and System. Time window: all.",
    );
    const RELATIONAL =
      /\b(relat\w*|caus\w*|because|lead\w*|led|precede\w*|follow\w*|then|after|before|chain\w*|link\w*|correlat\w*|due to|root cause|result\w*|trigger\w*|impl(y|ies|ied)|together)\b/i;
    for (const text of [triage.name, viewSubtitle(triage), viewDescription(triage)]) {
      expect(text).not.toMatch(RELATIONAL);
    }
    // The scan itself catches what it should.
    expect("Events that lead to enrollment failure").toMatch(RELATIONAL);
    expect("Related enrollment events").toMatch(RELATIONAL);
  });
});

// ---------------------------------------------------------------------------------------------
// The list, names and the library's integrity
// ---------------------------------------------------------------------------------------------

describe("listing and naming views", () => {
  const custom: EvtxStoredView[] = [{ id: "a", ...body({ name: "First" }) }, { id: "b", ...body({ name: "Second" }) }];

  it("lists the built-ins first, then custom views in the order they were made, never as built-ins", () => {
    const views: EvtxView[] = listViews(custom);
    expect(views.map((v) => v.name)).toEqual(["Enrollment triage", "First", "Second"]);
    expect(views.map((v) => v.builtIn)).toEqual([true, false, false]);
  });

  it("describes a custom view by what it holds", () => {
    const [, first] = listViews([{ id: "a", ...body({ layout: null }) }, ...custom]);
    expect(viewSubtitle(first)).toBe("Filters");
    expect(viewSubtitle(listViews(custom)[1])).toBe("Filters and layout");
  });

  it("cleans a name and refuses one with nothing usable left", () => {
    expect(cleanViewName("  Login   storms ")).toBe("Login storms");
    expect(cleanViewName("x".repeat(MAX_VIEW_NAME_LENGTH))).toBe("x".repeat(MAX_VIEW_NAME_LENGTH));
    expect(cleanViewName("x".repeat(MAX_VIEW_NAME_LENGTH + 1))).toBeNull();
    for (const bad of ["", "   ", 5, null, undefined, {}, ch(7), ch(0x202e), `${ch(0x200b)} ${ch(0xfeff)}`]) {
      expect(cleanViewName(bad)).toBeNull();
    }
  });

  describe("a name is stored as typed, minus control and bidi control characters (U1)", () => {
    // Removed from the stored name: \p{Cc} and \p{Bidi_Control}.
    const removed: Array<[string, number]> = [
      ["U+0007 bell (control)", 0x07],
      ["U+061C arabic letter mark", 0x61c],
      ["U+200E left-to-right mark", 0x200e],
      ["U+200F right-to-left mark", 0x200f],
      ["U+202A left-to-right embedding", 0x202a],
      ["U+202E right-to-left override", 0x202e],
      ["U+2066 left-to-right isolate", 0x2066],
      ["U+2069 pop directional isolate", 0x2069],
    ];

    it.each(removed)("removes %s from the stored name", (_label, code) => {
      expect(cleanViewName(`Ab${ch(code)}c`)).toBe("Abc");
      expect(cleanViewName(`${ch(code)}Abc${ch(code)}`)).toBe("Abc");
    });

    // Kept as typed: they change how neighbours are drawn, or draw nothing and are only ignored
    // when names are compared.
    const kept: Array<[string, number]> = [
      ["U+00AD soft hyphen", 0xad],
      ["U+034F combining grapheme joiner", 0x34f],
      ["U+180E mongolian vowel separator", 0x180e],
      ["U+200B zero width space", 0x200b],
      ["U+200C zero width non-joiner", 0x200c],
      ["U+200D zero width joiner", 0x200d],
      ["U+2060 word joiner", 0x2060],
      ["U+3164 hangul filler", 0x3164],
      ["U+FE0F variation selector 16", 0xfe0f],
      ["U+E0001 language tag", 0xe0001],
      ["U+E0041 tag latin capital a", 0xe0041],
      ["U+E007F cancel tag", 0xe007f],
    ];

    it.each(kept)("keeps %s in the stored name", (_label, code) => {
      expect(cleanViewName(`Ab${ch(code)}c`)).toBe(`Ab${ch(code)}c`);
    });

    it("stores a text-style or emoji-style heart as typed, not as the bare heart", () => {
      expect(cleanViewName(`${ch(0x2764)}${ch(0xfe0f)} Boot`)).toBe(`${ch(0x2764)}${ch(0xfe0f)} Boot`);
      expect(cleanViewName(`${ch(0x2764)}${ch(0xfe0e)} Boot`)).toBe(`${ch(0x2764)}${ch(0xfe0e)} Boot`);
    });

    it("stores a ZWJ family emoji unchanged, as one family and not three people", () => {
      const family = [0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467].map(ch).join("");
      expect(cleanViewName(`${family} Triage`)).toBe(`${family} Triage`);
      expect(cleanViewName(family)).toBe(family);
    });

    it("stores an emoji tag sequence unchanged: the flag of England", () => {
      const england = [0x1f3f4, 0xe0067, 0xe0062, 0xe0065, 0xe006e, 0xe0067, 0xe007f].map(ch).join("");
      expect(cleanViewName(england)).toBe(england);
    });

    it("stores a Persian name with a zero width non-joiner unchanged, so its letters stay apart", () => {
      const persian = [0x645, 0x6cc, 0x200c, 0x62e, 0x648, 0x627, 0x647, 0x645].map(ch).join("");
      expect(cleanViewName(persian)).toBe(persian);
    });

    it("keeps a tab or a newline as the space it is, not as a control character that joins two words", () => {
      expect(cleanViewName("one\ttwo\nthree")).toBe("one two three");
      expect(cleanViewName(`one${ch(0x85)}two${ch(0xa0)}three${ch(0x2028)}four`)).toBe("one two three four");
      expect(cleanViewName(`one ${ch(0x202e)} two`)).toBe("one two");
    });

    it("lets a name that is only text through untouched, accents and CJK included", () => {
      expect(cleanViewName("Enrollment triage")).toBe("Enrollment triage");
      expect(cleanViewName("Crème brûlée 登録")).toBe("Crème brûlée 登録");
    });

    it("measures the length on the stored name", () => {
      // The bidi control is removed, so it does not count; the zero width space is kept, so it does.
      expect(cleanViewName(`${"x".repeat(MAX_VIEW_NAME_LENGTH)}${ch(0x61c)}`)).toBe("x".repeat(MAX_VIEW_NAME_LENGTH));
      expect(cleanViewName(`${"x".repeat(MAX_VIEW_NAME_LENGTH)}${ch(0x200b)}`)).toBeNull();
    });

    it("refuses a name with nothing visible in it, which would read as blank", () => {
      expect(cleanViewName(`${ch(0x200b)}${ch(0x61c)}`)).toBeNull();
      expect(cleanViewName(`${ch(0x200d)} ${ch(0x2060)}`)).toBeNull();
      expect(cleanViewName(`${ch(0xe0041)}${ch(0xfe0f)}`)).toBeNull();
    });
  });

  describe("names compare by a fully stripped, case-folded key (U1)", () => {
    const lookAlikes: Array<[string, string]> = [
      ["followed by U+061C", `Enrollment triage${ch(0x61c)}`],
      ["followed by U+200B", `Enrollment triage${ch(0x200b)}`],
      ["followed by U+2060", `Enrollment triage${ch(0x2060)}`],
      ["with U+200B inside a word", `Enroll${ch(0x200b)}ment triage`],
      ["with a soft hyphen inside a word", `Enroll${ch(0xad)}ment triage`],
      ["with a zero width joiner", `Enrollment${ch(0x200d)} triage`],
      ["in other case", `ENROLLMENT TRIAGE${ch(0x200b)}`],
      ["with a tag character", `Enrollment triage${ch(0xe0041)}`],
    ];

    it("gives a name and its look-alike the same key", () => {
      expect(viewNameKey("Enrollment triage")).toBe("enrollment triage");
      for (const [, name] of lookAlikes) expect(viewNameKey(name)).toBe("enrollment triage");
    });

    it.each(lookAlikes)("takes the built-in's name when it is %s", (_label, spoof) => {
      const stored = cleanViewName(spoof)!;
      expect(viewNameTaken(stored, [])).toBe(true);
      // From a file: it is added under a suffix, never posing as the built-in.
      const merged = mergeViews([], [{ ...body(), name: stored }], makeId);
      expect(merged.views).toHaveLength(1);
      expect(merged.views[0].name).toMatch(/ \(2\)$/);
      expect(viewNameKey(merged.views[0].name)).not.toBe("enrollment triage");
      // From storage.
      const { views } = sanitizeStoredViews([{ id: "9d1b3f6c-3d2a-4a43-9a6f-1c0d4f2e8b11", ...plain(body({ name: stored })) }], makeId);
      expect(views[0].name).toMatch(/ \(2\)$/);
    });

    it("makes a look-alike of a custom view unique, in the library and within one file", () => {
      const custom: EvtxStoredView[] = [{ id: "a", ...body({ name: "Boot triage" }) }];
      expect(viewNameTaken(`Boot${ch(0x200b)} triage`, custom)).toBe(true);
      const merged = mergeViews([], [body({ name: "Boot triage" }), body({ name: `Boot triage${ch(0x2060)}` })], makeId);
      expect(merged).toMatchObject({ added: 2, replaced: 0 });
      expect(merged.views[1].name).toMatch(/ \(2\)$/);
      const replaced = mergeViews(custom, [body({ name: `BOOT${ch(0x200b)} TRIAGE` })], makeId);
      expect(replaced).toMatchObject({ added: 0, replaced: 1 });
      // A second entry of the file that reads as the first never replaces the library's view again.
      const twice = mergeViews(custom, [body({ name: "Boot triage" }), body({ name: `Boot triage${ch(0x2060)}` })], makeId);
      expect(twice).toMatchObject({ added: 1, replaced: 1, skipped: 0 });
      expect(twice.views.map((v) => v.name)).toEqual(["Boot triage", `Boot triage${ch(0x2060)} (2)`]);
    });

    it("does not make two different names collide", () => {
      expect(viewNameKey("Boot")).not.toBe(viewNameKey("Boot 2"));
      expect(viewNameKey(`${ch(0x2764)}${ch(0xfe0f)} Boot`)).not.toBe(viewNameKey("Boot"));
      expect(viewNameKey(`${ch(0x2764)} Boot`)).not.toBe(viewNameKey("Boot"));
    });

    it("cuts a made-unique name by whole code points, so it stays valid and inside the limit", () => {
      // 59 UTF-16 units: a plain cut at 56 would fall between the halves of a surrogate pair.
      const astral = `x${ch(0x1f4a5).repeat(29)}`;
      expect(astral.length).toBe(59);
      const name = uniqueViewName(astral, [{ name: astral }]);
      expect(name.length).toBeLessThanOrEqual(MAX_VIEW_NAME_LENGTH);
      expect(name.endsWith(" (2)")).toBe(true);
      expect(name).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
    });
  });

  it("makes names unique ignoring case, across the built-ins and the custom views", () => {
    expect(viewNameTaken("enrollment TRIAGE", [])).toBe(true);
    expect(viewNameTaken("first", custom)).toBe(true);
    expect(viewNameTaken("Third", custom)).toBe(false);
    expect(uniqueViewName("Third", custom)).toBe("Third");
    expect(uniqueViewName("first", custom)).toBe("first (2)");
    expect(uniqueViewName("Enrollment triage", custom)).toBe("Enrollment triage (2)");
    expect(uniqueViewName("First", [...custom, { name: "First (2)" }])).toBe("First (3)");
  });

  it("keeps a made-unique name inside the length limit", () => {
    const full = "y".repeat(MAX_VIEW_NAME_LENGTH);
    const name = uniqueViewName(full, [{ name: full }]);
    expect(name.length).toBeLessThanOrEqual(MAX_VIEW_NAME_LENGTH);
    expect(name.endsWith(" (2)")).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// Reading a view
// ---------------------------------------------------------------------------------------------

describe("sanitizeViewBody", () => {
  it("reads a well-formed view back exactly: the export of a view is the view", () => {
    const view = body();
    expect(sanitizeViewBody(plain(view))).toEqual(view);
    expect(sanitizeViewBody(plain(body({ layout: null })))).toEqual(body({ layout: null }));
  });

  it("reads a layout of null as none, and skips a view that does not write one", () => {
    expect(sanitizeViewBody(plain(body({ layout: null })))?.layout).toBeNull();
    const input = plain();
    delete input.layout;
    expect(sanitizeViewBody(input)).toBeNull();
  });

  it("reads a view with no channel list, leaving the selection alone", () => {
    const input = plain();
    delete input.criteria.beforeLoad.selectedChannels;
    expect(sanitizeViewBody(input)?.criteria.beforeLoad.selectedChannels).toBeUndefined();
  });

  it("reads nothing from a minimal view: a default for a missing key would not be what the author meant", () => {
    expect(sanitizeViewBody({ name: "Bare", criteria: {} })).toBeNull();
    expect(sanitizeViewBody({ name: "Bare", criteria: {}, layout: null })).toBeNull();
    expect(sanitizeViewBody({ name: "Bare", criteria: sanitizeCriteria({}) })).toBeNull();
    // Written in full it is a view, and its window is its own, not the 24 hour default.
    expect(sanitizeViewBody({ name: "Bare", criteria: sanitizeCriteria({}), layout: null })).not.toBeNull();
  });

  describe("the transient criteria are never in a view (Q-2)", () => {
    const hostile = () => {
      const input = plain();
      const transients = {
        timeRange: { startMs: 1, endMs: 2 },
        scopeRecordIds: [1, 2],
        scopeRecords: [1],
        recordScope: { kind: "finding", title: "t", records: [{ id: 1 }] },
      };
      Object.assign(input, transients);
      Object.assign(input.criteria, transients);
      Object.assign(input.criteria.beforeLoad, transients);
      Object.assign(input.criteria.onLoad, transients);
      Object.assign(input.criteria.onLoad.quickFilter, transients);
      Object.assign(input.criteria.afterLoad, transients);
      Object.assign(input.layout, transients);
      Object.assign(input.layout.panels, transients);
      return input;
    };

    it("drops them wherever a file writes them, and keeps what the file did say", () => {
      const read = sanitizeViewBody(hostile());
      expect(read).not.toBeNull();
      expect(JSON.stringify(read)).not.toMatch(TRANSIENT);
      expect(read).toEqual(body());
    });

    it("drops them from an import, and from the export written after it", () => {
      const file = JSON.stringify({ schema: SAVED_VIEW_SCHEMA, views: [hostile()] });
      const result = parseViewExport(file);
      expect(result.ok && result.views).toHaveLength(1);
      expect(JSON.stringify(result)).not.toMatch(TRANSIENT);
      if (result.ok) expect(buildViewExport(result.views)).not.toMatch(TRANSIENT);
    });

    it("drops them from the persisted list", () => {
      const { views } = sanitizeStoredViews([{ id: "x", ...hostile() }], makeId);
      expect(views).toHaveLength(1);
      expect(JSON.stringify(views)).not.toMatch(TRANSIENT);
    });
  });

  it("copies nothing it was not told to: no id, no builtIn, no lastUsed, no extra key", () => {
    const input: Record<string, any> = { ...plain(), id: "builtin:enrollment-triage", builtIn: true, lastUsed: 5, extra: { a: 1 } };
    input.criteria.extra = true;
    input.criteria.beforeLoad.extra = true;
    const read = sanitizeViewBody(input)!;
    expect(Object.keys(read)).toEqual(["name", "criteria", "layout"]);
    expect(Object.keys(read.criteria)).toEqual(["beforeLoad", "onLoad", "afterLoad"]);
    expect(Object.keys(read.criteria.beforeLoad)).toEqual(["levels", "eventIds", "timeWindow", "selectedChannels"]);
    expect(JSON.stringify(read)).not.toMatch(/builtIn|lastUsed|extra|builtin:/);
  });

  it("is not polluted by a __proto__ or constructor key", () => {
    // A complete view with the dangerous keys written in at every depth. JSON.parse makes them own
    // properties, which is what a file does.
    const text = JSON.stringify(plain())
      .replace(/^\{/, '{"__proto__":{"polluted":1},"constructor":{"prototype":{"polluted":2}},')
      .replace('"criteria":{', '"criteria":{"__proto__":{"polluted":3},')
      .replace('"beforeLoad":{', '"beforeLoad":{"__proto__":{"polluted":4},')
      .replace('"layout":{', '"layout":{"__proto__":{"polluted":5},');
    expect(text.match(/__proto__/g)).toHaveLength(4);
    const read = sanitizeViewBody(JSON.parse(text));
    expect(read).toEqual(body());
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(JSON.stringify(read)).not.toMatch(/polluted/);
  });

  describe("a view that cannot be read exactly as written is skipped, never approximated (R9)", () => {
    const baseline = () => sanitizeViewBody(plain());
    it("reads the unmodified view, so every row below fails for its own mutation", () => {
      expect(baseline()).not.toBeNull();
    });

    const corruptions: Array<[string, (v: Record<string, any>) => void]> = [
      ["no name", (v) => delete v.name],
      ["a numeric name", (v) => (v.name = 5)],
      ["an empty name", (v) => (v.name = "")],
      ["a blank name", (v) => (v.name = "   ")],
      ["a name that is only invisible characters", (v) => (v.name = `${ch(0x200b)}${ch(0x61c)}`)],
      ["an over-long name", (v) => (v.name = "n".repeat(MAX_VIEW_NAME_LENGTH + 1))],
      ["no criteria", (v) => delete v.criteria],
      ["criteria that is an array", (v) => (v.criteria = [])],
      ["criteria that is a string", (v) => (v.criteria = "x")],
      ["beforeLoad that is a string", (v) => (v.criteria.beforeLoad = "x")],
      ["onLoad that is an array", (v) => (v.criteria.onLoad = [])],
      ["afterLoad that is a number", (v) => (v.criteria.afterLoad = 5)],
      ["an unknown level", (v) => v.criteria.beforeLoad.levels.push("Foo")],
      ["only unknown levels (which would widen to every level)", (v) => (v.criteria.beforeLoad.levels = ["Foo"])],
      ["no levels at all", (v) => (v.criteria.beforeLoad.levels = [])],
      ["levels that is a string", (v) => (v.criteria.beforeLoad.levels = "Error")],
      ["a numeric level", (v) => (v.criteria.beforeLoad.levels = [1])],
      ["an unknown time window", (v) => (v.criteria.beforeLoad.timeWindow = "2d")],
      ["a numeric time window", (v) => (v.criteria.beforeLoad.timeWindow = 24)],
      ["Event IDs that do not parse", (v) => (v.criteria.beforeLoad.eventIds = "4624,abc")],
      ["a numeric Event ID list", (v) => (v.criteria.beforeLoad.eventIds = 5)],
      ["an Event ID above the limit", (v) => (v.criteria.beforeLoad.eventIds = "99999999999")],
      ["a channel list that is a string", (v) => (v.criteria.beforeLoad.selectedChannels = "System")],
      ["a channel that is not a string", (v) => v.criteria.beforeLoad.selectedChannels.push(7)],
      ["a numeric search", (v) => (v.criteria.onLoad.search = 5)],
      ["an unknown quick-filter mode (the 5b hazard)", (v) => (v.criteria.onLoad.quickFilter.mode = "futureMode")],
      ["an unknown quick-filter scope", (v) => (v.criteria.onLoad.quickFilter.scope = "someColumns")],
      ["an unknown quick-filter action", (v) => (v.criteria.onLoad.quickFilter.action = "mute")],
      ["a numeric quick-filter case flag", (v) => (v.criteria.onLoad.quickFilter.caseSensitive = 1)],
      ["a string quick-filter highlight flag", (v) => (v.criteria.onLoad.quickFilter.highlight = "yes")],
      ["a numeric quick-filter query", (v) => (v.criteria.onLoad.quickFilter.query = 5)],
      ["a quick filter that is a string", (v) => (v.criteria.onLoad.quickFilter = "x")],
      ["an unknown grouping", (v) => v.criteria.afterLoad.groupBy.push("nope")],
      ["a grouping that is a string", (v) => (v.criteria.afterLoad.groupBy = "level")],
      ["a layout that is a string", (v) => (v.layout = "table")],
      ["an unknown layout view", (v) => (v.layout.activeView = "sankey")],
      ["no layout view", (v) => delete v.layout.activeView],
      ["no panels", (v) => delete v.layout.panels],
      ["a panel that is missing", (v) => delete v.layout.panels.insights],
      ["a panel that is not a boolean", (v) => (v.layout.panels.channels = "yes")],
      ["more than one view's worth of JSON", (v) => (v.criteria.onLoad.search = "q".repeat(70_000))],
    ];

    it.each(corruptions)("skips a view with %s", (_label, corrupt) => {
      const input = plain();
      corrupt(input);
      expect(sanitizeViewBody(input)).toBeNull();
    });

    // Every key the view is rebuilt with must be written (R9, T2): only selectedChannels is optional.
    const requiredKeys: string[][] = [
      ["layout"],
      ["criteria", "beforeLoad"],
      ["criteria", "onLoad"],
      ["criteria", "afterLoad"],
      ["criteria", "beforeLoad", "levels"],
      ["criteria", "beforeLoad", "eventIds"],
      ["criteria", "beforeLoad", "timeWindow"],
      ["criteria", "onLoad", "search"],
      ["criteria", "onLoad", "quickFilter"],
      ["criteria", "onLoad", "quickFilter", "mode"],
      ["criteria", "onLoad", "quickFilter", "query"],
      ["criteria", "onLoad", "quickFilter", "scope"],
      ["criteria", "onLoad", "quickFilter", "action"],
      ["criteria", "onLoad", "quickFilter", "caseSensitive"],
      ["criteria", "onLoad", "quickFilter", "highlight"],
      ["criteria", "afterLoad", "groupBy"],
    ];

    it.each(requiredKeys.map((path) => [path.join("."), path] as const))("skips a view that does not write %s", (_label, path) => {
      const input = plain();
      let holder: Record<string, any> = input;
      for (const key of path.slice(0, -1)) holder = holder[key];
      delete holder[path[path.length - 1]];
      expect(sanitizeViewBody(input)).toBeNull();
    });

    it("reads a view that does not write its channel list: the one optional key", () => {
      const input = plain();
      delete input.criteria.beforeLoad.selectedChannels;
      expect(sanitizeViewBody(input)).not.toBeNull();
    });

    it("reads nothing from a value that is not an object", () => {
      for (const input of [null, undefined, 5, "view", [], [plain()]]) {
        expect(sanitizeViewBody(input)).toBeNull();
      }
    });
  });

  describe("the layout", () => {
    it("turns off a panel this build cannot show, as the layout store does, and still reads the view", () => {
      const input = plain();
      input.layout.panels = { channels: true, insights: true, dock: true };
      expect(sanitizeViewBody(input)?.layout?.panels).toEqual({ channels: true, insights: true, dock: false });
    });

    it("captures a layout from named fields, with the dock off", () => {
      const source = { activeView: "charts" as const, panels: { channels: false, insights: true, dock: true }, railWidth: 400 };
      const layout = captureLayout(source);
      expect(layout).toEqual({ activeView: "charts", panels: { channels: false, insights: true, dock: false } });
      expect(Object.keys(layout)).toEqual(["activeView", "panels"]);
    });
  });
});

// ---------------------------------------------------------------------------------------------
// The persisted list
// ---------------------------------------------------------------------------------------------

describe("sanitizeStoredViews", () => {
  it("reads nothing from input that is not a list", () => {
    for (const input of [undefined, null, "x", 5, {}, { views: [] }]) {
      expect(sanitizeStoredViews(input, makeId)).toEqual({ views: [], skipped: 0 });
    }
  });

  const ID_A = "0b3d3a58-6a34-4c8e-9f0b-2c1d7e5a9b01";
  const ID_B = "f4a1c2d3-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

  it("keeps readable views in order with their ids, and counts the rest", () => {
    const { views, skipped } = sanitizeStoredViews(
      [{ id: ID_A, ...plain(body({ name: "One" })) }, "junk", { id: ID_B, ...plain(body({ name: "Two" })) }, { name: "" }],
      makeId,
    );
    expect(views.map((v) => [v.id, v.name])).toEqual([[ID_A, "One"], [ID_B, "Two"]]);
    expect(skipped).toBe(2);
  });

  it("makes an id anew when it is missing, repeated, or one of the built-ins'", () => {
    const { views } = sanitizeStoredViews(
      [
        plain(body({ name: "A" })),
        { id: ID_A, ...plain(body({ name: "B" })) },
        { id: ID_A, ...plain(body({ name: "C" })) },
        { id: ENROLLMENT_TRIAGE_ID, ...plain(body({ name: "D" })) },
      ],
      makeId,
    );
    const ids = views.map((v) => v.id);
    expect(new Set(ids).size).toBe(4);
    expect(ids).not.toContain(ENROLLMENT_TRIAGE_ID);
    expect(ids[1]).toBe(ID_A);
    expect(ids[2]).not.toBe(ID_A);
  });

  describe("a stored id is kept only in the shape the library makes (T9)", () => {
    const stored = (id: unknown) => sanitizeStoredViews([{ id, ...plain(body({ name: "Mine" })) }], makeId).views[0].id;

    it("keeps a UUID, in either case", () => {
      expect(stored(ID_A)).toBe(ID_A);
      expect(stored(ID_A.toUpperCase())).toBe(ID_A.toUpperCase());
    });

    it.each<[string, unknown]>([
      ["an id with a space", "a b"],
      ["an id with a space inside a UUID's shape", "0b3d3a58-6a34-4c8e-9f0b-2c1d7e5a9b0 "],
      ["a short id", "a"],
      ["an id that is a UUID plus a suffix", `${ID_A}x`],
      ["an id with a quote and a space, as would break aria-describedby", 'x" y'],
      ["a number", 5],
      ["an empty id", ""],
      ["an id of one megabyte", "x".repeat(1_048_576)],
      ["a UUID-shaped id of a megabyte of leading text", `${"x".repeat(1_048_576)}${ID_A}`],
    ])("makes an id anew for %s", (_label, id) => {
      const kept = stored(id);
      expect(kept).not.toBe(id);
      expect(kept).toMatch(/^made-\d+$/);
      expect(kept.length).toBeLessThan(40);
    });
  });

  it("makes a repeated name, or a built-in's, unique", () => {
    const { views } = sanitizeStoredViews(
      [
        { id: "1", ...plain(body({ name: "Same" })) },
        { id: "2", ...plain(body({ name: "SAME" })) },
        { id: "3", ...plain(body({ name: "Enrollment triage" })) },
      ],
      makeId,
    );
    expect(views.map((v) => v.name)).toEqual(["Same", "SAME (2)", "Enrollment triage (2)"]);
  });

  it("never reads a view as a built-in, whatever it claims", () => {
    const { views } = sanitizeStoredViews(
      [{ id: ENROLLMENT_TRIAGE_ID, builtIn: true, ...plain(body({ name: "Mine" })) }],
      makeId,
    );
    expect(listViews(views).map((v) => v.builtIn)).toEqual([true, false]);
    expect(views[0].id).not.toBe(ENROLLMENT_TRIAGE_ID);
    expect(JSON.stringify(views)).not.toMatch(/builtIn/);
  });

  it("keeps at most the limit", () => {
    const many = Array.from({ length: MAX_CUSTOM_VIEWS + 5 }, (_, i) => ({ id: `v${i}`, ...plain(body({ name: `View ${i}` })) }));
    const { views, skipped } = sanitizeStoredViews(many, makeId);
    expect(views).toHaveLength(MAX_CUSTOM_VIEWS);
    expect(skipped).toBe(5);
  });
});

// ---------------------------------------------------------------------------------------------
// Export and import
// ---------------------------------------------------------------------------------------------

describe("export and import", () => {
  const views: EvtxViewBody[] = [body({ name: "One" }), body({ name: "Two", layout: null })];

  it("writes the schema and each view's name, criteria and layout, and nothing about this machine", () => {
    const stored: EvtxStoredView[] = views.map((v, i) => ({ id: `machine-id-${i}`, ...v }));
    const text = buildViewExport(stored);
    const file = JSON.parse(text);
    expect(file.schema).toBe(1);
    expect(file.views.map((v: object) => Object.keys(v))).toEqual([["name", "criteria", "layout"], ["name", "criteria", "layout"]]);
    expect(text).not.toMatch(/machine-id|builtIn|lastUsed/);
    expect(text).not.toMatch(TRANSIENT);
  });

  it("round-trips: what is exported is what is imported", () => {
    const result = parseViewExport(buildViewExport(views));
    expect(result).toEqual({ ok: true, views, skipped: 0 });
  });

  it("round-trips the built-in as an ordinary view", () => {
    const [triage] = EVTX_BUILT_IN_VIEWS;
    const result = parseViewExport(buildViewExport([triage]));
    expect(result.ok && result.views).toEqual([{ name: triage.name, criteria: triage.criteria, layout: null }]);
  });

  it("refuses text that is too large before it parses it", () => {
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(parseViewExport("x".repeat(MAX_VIEW_FILE_LENGTH + 1))).toEqual({ ok: false, reason: "too-large" });
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each<[string, string, string]>([
    ["text that is not JSON", "{not json", "not-json"],
    ["an empty file", "", "not-json"],
    ["a root array", "[]", "unsupported-schema"],
    ["a null root", "null", "unsupported-schema"],
    ["schema 0", JSON.stringify({ schema: 0, views: [] }), "unsupported-schema"],
    ["schema 2", JSON.stringify({ schema: 2, views: [] }), "unsupported-schema"],
    ["a string schema", JSON.stringify({ schema: "1", views: [] }), "unsupported-schema"],
    ["no schema", JSON.stringify({ views: [] }), "unsupported-schema"],
    ["a saved-filter file (schema 2)", JSON.stringify({ schema: 2, filters: [] }), "unsupported-schema"],
    ["views that is not a list", JSON.stringify({ schema: 1, views: {} }), "not-a-view-file"],
    ["no views", JSON.stringify({ schema: 1 }), "not-a-view-file"],
  ])("refuses %s, and converts nothing", (_label, text, reason) => {
    expect(parseViewExport(text)).toEqual({ ok: false, reason });
  });

  it("skips and counts what it cannot read, and keeps the rest", () => {
    const file = JSON.stringify({
      schema: 1,
      views: [plain(body({ name: "Good" })), 5, null, { name: "No criteria" }, plain(body({ name: "Also good" }))],
    });
    const result = parseViewExport(file);
    expect(result.ok && result.views.map((v) => v.name)).toEqual(["Good", "Also good"]);
    expect(result.ok && result.skipped).toBe(3);
  });

  it("reads at most the limit from a file and counts the rest as skipped", () => {
    const file = JSON.stringify({
      schema: 1,
      views: Array.from({ length: MAX_CUSTOM_VIEWS + 3 }, (_, i) => plain(body({ name: `V${i}` }))),
    });
    const result = parseViewExport(file);
    expect(result.ok && result.views).toHaveLength(MAX_CUSTOM_VIEWS);
    expect(result.ok && result.skipped).toBe(3);
  });

  describe("merging into the library", () => {
    const library: EvtxStoredView[] = [{ id: "mine-1", ...body({ name: "Mine" }) }];

    it("adds a view under a fresh id, never the one the file carries", () => {
      const file = { ...plain(body({ name: "Shared" })), id: "from-the-file" };
      const parsed = parseViewExport(JSON.stringify({ schema: 1, views: [file] }));
      if (!parsed.ok) throw new Error("unreadable");
      const merged = mergeViews(library, parsed.views, makeId);
      expect(merged).toMatchObject({ added: 1, replaced: 0, skipped: 0 });
      expect(merged.views.map((v) => v.name)).toEqual(["Mine", "Shared"]);
      expect(merged.views[1].id).not.toBe("from-the-file");
    });

    it("replaces a custom view of the same name, ignoring case, and keeps its id", () => {
      const merged = mergeViews(library, [body({ name: "MINE", layout: null })], makeId);
      expect(merged).toMatchObject({ added: 0, replaced: 1 });
      expect(merged.views).toHaveLength(1);
      expect(merged.views[0].id).toBe("mine-1");
      expect(merged.views[0].layout).toBeNull();
    });

    it("makes a duplicate within one file unique: it is added, never a replacement, and the first entry survives", () => {
      const a = body({ name: "A", criteria: sanitizeCriteria({ beforeLoad: { levels: ["Error"], timeWindow: "1h" } }) });
      const lower = body({ name: "a", criteria: sanitizeCriteria({ beforeLoad: { levels: ["Warning"], timeWindow: "7d" } }) });
      const merged = mergeViews([], [a, lower], makeId);
      expect(merged).toMatchObject({ added: 2, replaced: 0, skipped: 0 });
      expect(merged.views.map((v) => v.name)).toEqual(["A", "a (2)"]);
      expect(merged.views[0].criteria).toEqual(a.criteria);
      expect(merged.views[1].criteria).toEqual(lower.criteria);
    });

    it("replaces a library view once, and adds the file's later entry of that name under a unique one", () => {
      const merged = mergeViews(library, [body({ name: "Mine", layout: null }), body({ name: "MINE" })], makeId);
      expect(merged).toMatchObject({ added: 1, replaced: 1, skipped: 0 });
      expect(merged.views.map((v) => v.name)).toEqual(["Mine", "MINE (2)"]);
      expect(merged.views[0].id).toBe("mine-1");
      expect(merged.views[0].layout).toBeNull();
      expect(merged.views[1].layout).not.toBeNull();
    });

    it("counts a duplicate within a file that does not fit as skipped, not as replaced", () => {
      const full: EvtxStoredView[] = Array.from({ length: MAX_CUSTOM_VIEWS }, (_, i) => ({ id: `f${i}`, ...body({ name: `F${i}` }) }));
      const merged = mergeViews(full, [body({ name: "New" }), body({ name: "new" })], makeId);
      expect(merged).toMatchObject({ added: 0, replaced: 0, skipped: 2 });
    });

    it("can neither replace nor pose as a built-in", () => {
      const merged = mergeViews(library, [body({ name: "Enrollment triage" }), body({ name: "enrollment TRIAGE" })], makeId);
      expect(merged.views.map((v) => v.name)).toEqual(["Mine", "Enrollment triage (2)", "enrollment TRIAGE (3)"]);
      expect(merged.views.every((v) => v.id !== ENROLLMENT_TRIAGE_ID)).toBe(true);
      expect(EVTX_BUILT_IN_VIEWS[0].criteria.onLoad.search).toBe(ENROLLMENT_TRIAGE_QUERY);
    });

    it("leaves out what does not fit, and says how many", () => {
      const full: EvtxStoredView[] = Array.from({ length: MAX_CUSTOM_VIEWS }, (_, i) => ({ id: `f${i}`, ...body({ name: `F${i}` }) }));
      const merged = mergeViews(full, [body({ name: "New" }), body({ name: "F0", layout: null })], makeId);
      expect(merged).toMatchObject({ added: 0, replaced: 1, skipped: 1 });
      expect(merged.views).toHaveLength(MAX_CUSTOM_VIEWS);
    });

    it("does not change the library it was given", () => {
      const before = JSON.stringify(library);
      mergeViews(library, [body({ name: "MINE" }), body({ name: "Other" })], makeId);
      expect(JSON.stringify(library)).toBe(before);
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Which view is active
// ---------------------------------------------------------------------------------------------

describe("viewMatchesCriteria", () => {
  const view = body();
  const current = (): EvtxFilterCriteria => structuredClone(view.criteria);

  it("matches the criteria it was made from", () => {
    expect(viewMatchesCriteria(view, current())).toBe(true);
  });

  it("reads levels and channels as sets", () => {
    const c = current();
    c.beforeLoad.levels = [...c.beforeLoad.levels].reverse();
    c.beforeLoad.selectedChannels = [...(c.beforeLoad.selectedChannels ?? [])].reverse();
    expect(viewMatchesCriteria(view, c)).toBe(true);
  });

  it("does not compare the layout", () => {
    expect(viewMatchesCriteria({ ...view, layout: null }, current())).toBe(true);
    expect(viewMatchesCriteria({ ...view, layout: { activeView: "charts", panels: { channels: false, insights: false, dock: false } } }, current())).toBe(true);
  });

  it("does not constrain the channels of a view that saved none", () => {
    const noChannels = body();
    delete noChannels.criteria.beforeLoad.selectedChannels;
    const c = current();
    c.beforeLoad.selectedChannels = ["Anything", "At all"];
    expect(viewMatchesCriteria(noChannels, c)).toBe(true);
  });

  const edits: Array<[string, (c: EvtxFilterCriteria) => void]> = [
    ["a level toggled", (c) => (c.beforeLoad.levels = ["Error"])],
    ["a level added", (c) => c.beforeLoad.levels.push("Warning")],
    ["the Event IDs", (c) => (c.beforeLoad.eventIds = "41")],
    ["the time window", (c) => (c.beforeLoad.timeWindow = "24h")],
    ["a channel removed", (c) => c.beforeLoad.selectedChannels?.pop()],
    ["a channel added", (c) => c.beforeLoad.selectedChannels?.push("Security")],
    ["every channel replaced by as many others", (c) => (c.beforeLoad.selectedChannels = ["A", "B"])],
    ["the channels cleared to none known", (c) => (c.beforeLoad.selectedChannels = undefined)],
    ["the search", (c) => (c.onLoad.search = "provider:Kernel x")],
    ["the quick-filter query", (c) => (c.onLoad.quickFilter.query = "id:42")],
    ["the quick-filter mode", (c) => (c.onLoad.quickFilter.mode = "oneString")],
    ["the quick-filter scope", (c) => (c.onLoad.quickFilter.scope = "allColumns")],
    ["the quick-filter action", (c) => (c.onLoad.quickFilter.action = "show")],
    ["the quick-filter case", (c) => (c.onLoad.quickFilter.caseSensitive = false)],
    ["the quick-filter highlight", (c) => (c.onLoad.quickFilter.highlight = true)],
    ["the grouping", (c) => (c.afterLoad.groupBy = ["level"])],
    ["the grouping order", (c) => (c.afterLoad.groupBy = ["level", "provider"])],
  ];

  it.each(edits)("stops matching when %s is edited", (_label, edit) => {
    const c = current();
    edit(c);
    expect(viewMatchesCriteria(view, c)).toBe(false);
  });

  it("matches the built-in only when its channels are exactly its own", () => {
    const [triage] = EVTX_BUILT_IN_VIEWS;
    expect(viewMatchesCriteria(triage, structuredClone(triage.criteria))).toBe(true);
    const wider = structuredClone(triage.criteria);
    wider.beforeLoad.selectedChannels?.push("Application");
    expect(viewMatchesCriteria(triage, wider)).toBe(false);
  });
});

describe("missingViewChannels", () => {
  it("names the view's channels that are not held", () => {
    const [triage] = EVTX_BUILT_IN_VIEWS;
    expect(missingViewChannels(triage, new Set([DMEDP, AAD, "System"]))).toEqual([]);
    expect(missingViewChannels(triage, new Set(["System"]))).toEqual([DMEDP, AAD]);
    expect(missingViewChannels(triage, new Set())).toEqual([DMEDP, AAD, "System"]);
  });

  it("names none for a view that saved no channels", () => {
    const noChannels = body();
    delete noChannels.criteria.beforeLoad.selectedChannels;
    expect(missingViewChannels(noChannels, new Set())).toEqual([]);
  });
});
