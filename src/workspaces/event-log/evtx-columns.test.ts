import { eventDateKey, formatEventTime } from "./evtx-time";
import { describe, expect, it } from "vitest";
import {
  availableColumns,
  discoverMappedProperties,
  mappedColumnId,
  columnValue,
  columnWidth,
  defaultColumnConfig,
  EVTX_COLUMNS,
  moveColumn,
  sanitizeColumnConfig,
  type EvtxColumnId,
  type EvtxColumnSpec,
  toggleColumn,
  visibleColumns,
  type EvtxColumnConfig,
} from "./evtx-columns";
import { DEFAULT_QUICK_FILTER, matchesQuickFilter } from "./evtx-filter";
import type { EvtxRecord } from "./types";

/**
 * The spec for `id`, failing with the id when it is absent.
 *
 * A non-null assertion would hide a removed column behind a confusing undefined access; this says
 * which column went missing.
 */
function columnSpec(id: EvtxColumnId): EvtxColumnSpec {
  const found = EVTX_COLUMNS.find((column) => column.id === id);
  if (!found) throw new Error(`no column spec for ${id}`);
  return found;
}

const config = (order: string[], widths = {}): EvtxColumnConfig =>
  sanitizeColumnConfig({ order, widths });

function record(partial: Partial<EvtxRecord> = {}): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 42,
    timestamp: "2026-08-09 12:00:00",
    timestampEpoch: 0,
    provider: "ESENT",
    channel: "Application",
    eventId: 326,
    level: "Error",
    computer: "TESTHOST-01",
    message: "something happened",
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
    ...partial,
  };
}

describe("sanitizeColumnConfig", () => {
  it("drops ids this build does not know", () => {
    // Configuration outlives the build that wrote it; a removed column would render an empty cell.
    expect(config(["level", "notAColumn", "provider"]).order).toEqual(["level", "provider"]);
  });

  it("deduplicates repeated ids", () => {
    expect(config(["level", "level", "provider"]).order).toEqual(["level", "provider"]);
  });

  it("falls back to defaults when every column is hidden", () => {
    // An empty list has no affordance to recover from.
    expect(sanitizeColumnConfig({ order: [] }).order).toEqual(defaultColumnConfig().order);
    expect(sanitizeColumnConfig(null).order).toEqual(defaultColumnConfig().order);
  });

  it("rejects widths that would hide a column the operator believes is shown", () => {
    const sanitized = config(["level"], { level: 0, provider: -5, channel: 120 });
    expect(sanitized.widths.level).toBeUndefined();
    expect(sanitized.widths.provider).toBeUndefined();
    expect(sanitized.widths.channel).toBe(120);
  });

  it("ignores width entries for unknown columns", () => {
    expect(config(["level"], { bogus: 100 }).widths).toEqual({});
  });
});

describe("visibleColumns", () => {
  it("returns specs in the configured order", () => {
    expect(visibleColumns(config(["provider", "level"])).map((c) => c.id)).toEqual([
      "provider",
      "level",
    ]);
  });
});

describe("columnWidth", () => {
  it("prefers an override over the default", () => {
    const level = columnSpec("level");
    expect(columnWidth(config(["level"], { level: 88 }), level)).toBe(88);
    expect(columnWidth(config(["level"]), level)).toBe(level.defaultWidth);
  });

  it("keeps the description column unbounded", () => {
    const message = columnSpec("message");
    expect(columnWidth(config(["message"]), message)).toBeNull();
  });
});

describe("moveColumn", () => {
  it("swaps with its neighbour", () => {
    const moved = moveColumn(config(["level", "provider", "channel"]), "provider", -1);
    expect(moved.order).toEqual(["provider", "level", "channel"]);
  });

  it("ignores moves off either end", () => {
    const start = config(["level", "provider"]);
    expect(moveColumn(start, "level", -1).order).toEqual(start.order);
    expect(moveColumn(start, "provider", 1).order).toEqual(start.order);
  });

  it("ignores a column that is not shown", () => {
    const start = config(["level"]);
    expect(moveColumn(start, "keywords", 1).order).toEqual(start.order);
  });
});

describe("toggleColumn", () => {
  it("appends a newly shown column", () => {
    expect(toggleColumn(config(["level"]), "keywords").order).toEqual(["level", "keywords"]);
  });

  it("removes a shown column", () => {
    expect(toggleColumn(config(["level", "keywords"]), "keywords").order).toEqual(["level"]);
  });

  it("refuses to hide the last remaining column", () => {
    const start = config(["level"]);
    expect(toggleColumn(start, "level").order).toEqual(["level"]);
  });
});

describe("columnValue", () => {
  it("renders present values", () => {
    const r = record({ task: 13312, processId: 1234, keywords: "0x80" });
    expect(columnValue(r, "eventId")).toBe("326");
    expect(columnValue(r, "recordId")).toBe("42");
    expect(columnValue(r, "task")).toBe("13312");
    expect(columnValue(r, "processId")).toBe("1234");
    expect(columnValue(r, "keywords")).toBe("0x80");
  });
  it("preserves a lossless EventRecordID when the numeric field is rounded", () => {
    const exact = "9007199254740993";
    const r = record({
      eventRecordId: Number(exact),
      eventRecordIdText: exact,
    });
    expect(columnValue(r, "recordId")).toBe(exact);
  });


  it("renders an absent value as empty rather than zero", () => {
    // Consistent with the record model: 0 would be a value the provider never claimed.
    const r = record({ task: undefined, opcode: null, threadId: null });
    expect(columnValue(r, "task")).toBe("");
    expect(columnValue(r, "opcode")).toBe("");
    expect(columnValue(r, "threadId")).toBe("");
  });

  it("covers every declared column", () => {
    const r = record();
    for (const column of EVTX_COLUMNS) {
      expect(typeof columnValue(r, column.id)).toBe("string");
    }
  });
});

describe("the timestamp column", () => {
  it("agrees with the day the same record groups under", () => {
    // The bug this replaced: the column printed the raw UTC string Windows wrote while grouping
    // bucketed by local date, so an evening event could show a UTC time from the following day
    // while sitting under today's group.
    const evening = Date.UTC(2026, 1, 10, 23, 30, 0);
    const r = record({ timestampEpoch: evening, timestamp: "2026-02-10T23:30:00.000Z" });
    for (const zone of ["local", "utc"] as const) {
      const shown = columnValue(r, "timestamp", zone);
      expect(shown.slice(0, 10)).toBe(eventDateKey(evening, zone));
    }
  });

  it("shows UTC when UTC is selected", () => {
    const r = record({
      timestampEpoch: Date.UTC(2026, 1, 10, 16, 36, 4, 390),
      timestamp: "2026-02-10T16:36:04.390987Z",
    });
    expect(columnValue(r, "timestamp", "utc")).toBe("2026-02-10 16:36:04.390987");
  });

  it("defaults to local rather than to whatever the record string held", () => {
    const epoch = Date.UTC(2026, 1, 10, 16, 36, 4, 390);
    const r = record({ timestampEpoch: epoch, timestamp: "2026-02-10T16:36:04.390Z" });
    expect(columnValue(r, "timestamp")).toBe(formatEventTime(epoch, "local", r.timestamp));
  });
});

describe("map columns", () => {
  const mapped = (property: string, text: string, complete = true) =>
    record({ mapped: [{ property, text, complete }] });

  it("renders a map-produced value", () => {
    // The whole point of the map engine: these have to be scannable as a column, not reachable
    // only by clicking each row open.
    const r = mapped("PayloadData1", "cmd.exe");
    expect(columnValue(r, mappedColumnId("PayloadData1"))).toBe("cmd.exe");
  });

  it("renders empty for an event the map did not match", () => {
    expect(columnValue(record({}), mappedColumnId("PayloadData1"))).toBe("");
    expect(columnValue(mapped("UserName", "adam"), mappedColumnId("RemoteHost"))).toBe("");
  });

  it("renders empty rather than showing an unsubstituted template", () => {
    // A partially applied map would otherwise put a literal %3 in a column being scanned.
    const r = mapped("PayloadData1", "ran %3 as adam", false);
    expect(columnValue(r, mappedColumnId("PayloadData1"))).toBe("");
  });

  it("offers only the properties the loaded records actually carry", () => {
    // Offering everything every map could emit fills the chooser with columns that are empty for
    // the log in front of the operator.
    const properties = discoverMappedProperties([
      mapped("PayloadData1", "a"),
      mapped("UserName", "b"),
      mapped("PayloadData1", "c"),
      record({}),
    ]);
    expect(properties).toEqual(["PayloadData1", "UserName"]);
  });

  it("lists fixed columns before map columns", () => {
    const columns = availableColumns(["PayloadData1"]);
    expect(columns.slice(0, EVTX_COLUMNS.length)).toEqual(EVTX_COLUMNS);
    expect(columns[columns.length - 1]).toMatchObject({
      id: mappedColumnId("PayloadData1"),
      label: "PayloadData1",
    });
  });

  it("keeps a stored map column even when its map is not loaded", () => {
    // The maps loaded now need not be the ones loaded when the layout was saved. Dropping the
    // column would silently discard an arrangement the operator made; an unmatched map column
    // renders empty, exactly as an unmatched event already does.
    const config = sanitizeColumnConfig({
      order: ["level", mappedColumnId("RemoteHost")],
      widths: { [mappedColumnId("RemoteHost")]: 200 },
    });
    expect(config.order).toContain(mappedColumnId("RemoteHost"));
    const visible = visibleColumns(config);
    expect(visible.map((c) => c.id)).toEqual(["level", mappedColumnId("RemoteHost")]);
    expect(columnWidth(config, visible[1])).toBe(200);
  });

  it("still rejects an id that is neither fixed nor a map column", () => {
    const config = sanitizeColumnConfig({ order: ["level", "notAColumn", "mapped:"] });
    expect(config.order).toEqual(["level"]);
  });
});

describe("default column widths (spec 8.7)", () => {
  it.each([
    ["level", 32],
    ["timestamp", 154],
    ["eventId", 52],
    ["channel", 120],
    ["provider", 162],
    ["links", 44],
  ] as const)("gives %s a default width of %i", (id, width) => {
    expect(columnSpec(id).defaultWidth).toBe(width);
    expect(columnWidth(defaultColumnConfig(), columnSpec(id))).toBe(width);
  });

  it("leaves the columns the spec does not name as they were", () => {
    // 8.7 lists "others" as unchanged: the widths of the optional columns must not move.
    expect(
      EVTX_COLUMNS.filter((column) =>
        ["recordId", "computer", "task", "opcode", "processId", "threadId", "keywords"].includes(
          column.id,
        ),
      ).map((column) => [column.id, column.defaultWidth]),
    ).toEqual([
      ["recordId", 70],
      ["computer", 120],
      ["task", 60],
      ["opcode", 60],
      ["processId", 60],
      ["threadId", 60],
      ["keywords", 140],
    ]);
  });
});

describe("column header labels", () => {
  it("gives the Event ID column a short header and no other column one", () => {
    expect(
      EVTX_COLUMNS.filter((column) => column.headerLabel !== undefined).map((column) => [
        column.id,
        column.headerLabel,
      ]),
    ).toEqual([["eventId", "ID"]]);
    // The cells, the chooser and quick filter use the full label.
    expect(columnSpec("eventId").label).toBe("Event ID");
  });
});

describe("the links column", () => {
  it("is shown by default, after the unbounded description", () => {
    expect(defaultColumnConfig().order).toEqual([
      "level",
      "timestamp",
      "eventId",
      "channel",
      "provider",
      "message",
      "links",
    ]);
    expect(columnSpec("links")).toMatchObject({ label: "Links", defaultVisible: true });
  });

  it("can be hidden and shown again like any other column", () => {
    const hidden = toggleColumn(defaultColumnConfig(), "links");
    expect(hidden.order).not.toContain("links");
    const shown = toggleColumn(hidden, "links").order;
    expect(shown[shown.length - 1]).toBe("links");
  });

  it("has no text value, so an unknown count is never read as none", () => {
    // The count comes from correlation edges the record does not carry. A "0" here would be a
    // value nothing established.
    expect(columnValue(record(), "links")).toBe("");
  });

  describe("quick-filter search", () => {
    // Every searched value of this record is free of the digit 0 (the time renders as
    // 2111-11-11 11:11:11.111 in UTC), so a "0" could only come from the links column.
    const zeroless = record({
      timestampEpoch: Date.UTC(2111, 10, 11, 11, 11, 11, 111),
      computer: "HOST-A",
    });
    const search = (scope: "visibleColumns" | "allColumns") => ({
      ...DEFAULT_QUICK_FILTER,
      query: "0",
      scope,
    });

    it("never finds a value in the links column of the visible columns", () => {
      expect(matchesQuickFilter(zeroless, search("visibleColumns"), ["links"], "utc")).toBe(false);
      // Control: the matcher does find the digit in a visible column that holds it.
      expect(
        matchesQuickFilter({ ...zeroless, eventId: 4100 }, search("visibleColumns"), ["links", "eventId"], "utc"),
      ).toBe(true);
      expect(
        matchesQuickFilter(zeroless, search("visibleColumns"), ["eventId", "recordId"], "utc"),
      ).toBe(false);
    });

    it("never finds a value in the links column under the all-columns scope either", () => {
      // The all-columns scope reaches every column the chooser offers, links included.
      expect(matchesQuickFilter(zeroless, search("allColumns"), undefined, "utc")).toBe(false);
      // Control: the same scope does find the digit once another column holds it.
      expect(
        matchesQuickFilter({ ...zeroless, eventId: 4100 }, search("allColumns"), undefined, "utc"),
      ).toBe(true);
    });
  });
});

describe("column configurations saved before the links column existed", () => {
  // What a build before the links column wrote for the default layout: the six visible columns,
  // with the width overrides an operator had set against the old default widths.
  const savedBeforeLinks = JSON.stringify({
    order: ["level", "timestamp", "eventId", "channel", "provider", "message"],
    widths: { level: 40, timestamp: 165, eventId: 50, channel: 140, provider: 160 },
  });

  it("loads with the same order, and does not inject the links column", () => {
    const loaded = sanitizeColumnConfig(JSON.parse(savedBeforeLinks));
    expect(loaded.order).toEqual(["level", "timestamp", "eventId", "channel", "provider", "message"]);
    expect(visibleColumns(loaded).map((column) => column.id)).not.toContain("links");
  });

  it("keeps every saved width override rather than applying the new defaults", () => {
    const loaded = sanitizeColumnConfig(JSON.parse(savedBeforeLinks));
    expect(loaded.widths).toEqual({
      level: 40,
      timestamp: 165,
      eventId: 50,
      channel: 140,
      provider: 160,
    });
    expect(columnWidth(loaded, columnSpec("timestamp"))).toBe(165);
    expect(columnWidth(loaded, columnSpec("level"))).toBe(40);
  });

  it("gives a column the saved config left no override for the new default width", () => {
    const loaded = sanitizeColumnConfig({ order: ["level", "timestamp", "provider"], widths: { level: 40 } });
    expect(columnWidth(loaded, columnSpec("level"))).toBe(40);
    expect(columnWidth(loaded, columnSpec("timestamp"))).toBe(154);
    expect(columnWidth(loaded, columnSpec("provider"))).toBe(162);
  });

  it("loads the old default layout, which carried no width overrides", () => {
    const loaded = sanitizeColumnConfig({
      order: ["level", "timestamp", "eventId", "channel", "provider", "message"],
      widths: {},
    });
    expect(loaded.order).not.toContain("links");
    expect(columnWidth(loaded, columnSpec("provider"))).toBe(162);
  });

  it("preserves a customized layout: reordered, with optional columns and a map column", () => {
    const custom = sanitizeColumnConfig({
      order: ["message", "level", "recordId", mappedColumnId("RemoteHost"), "timestamp"],
      widths: { message: 400, recordId: 90 },
    });
    expect(custom.order).toEqual([
      "message",
      "level",
      "recordId",
      mappedColumnId("RemoteHost"),
      "timestamp",
    ]);
    expect(custom.widths).toEqual({ message: 400, recordId: 90 });
  });

  it("keeps the links column, and a width for it, when a later build saved them", () => {
    const loaded = sanitizeColumnConfig({
      order: ["level", "message", "links"],
      widths: { links: 60 },
    });
    expect(loaded.order).toEqual(["level", "message", "links"]);
    expect(columnWidth(loaded, columnSpec("links"))).toBe(60);
  });
});
