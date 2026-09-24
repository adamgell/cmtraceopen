import { eventDateKey, formatEventTime } from "./evtx-time";
import { describe, expect, it } from "vitest";
import { EVTX_COLUMNS, MAX_INSERTION_STRING_COLUMNS, availableColumns, columnValue, columnWidth, defaultColumnConfig, discoverInsertionStrings, discoverMappedProperties, mappedColumnId, moveColumn, retainedInsertionStrings, sanitizeColumnConfig, stringColumnPosition, toggleColumn, type EvtxColumnConfig, type EvtxColumnId, type EvtxColumnSpec, visibleColumns } from "./evtx-columns";
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

  it("rejects an insertion-string id that is not the canonical spelling", () => {
    // Only what `stringColumnId` writes is a column: a persisted configuration
    // carrying `string:1.5`, `string:1e0` or `string:01` names nothing, and
    // accepting it lets a stray id inflate the discovered count or reach the
    // renderer as a fractional position.
    for (const id of ["string:1.5", "string:1e0", "string:01", "string: 2", "string:0", "string:11"]) {
      expect(stringColumnPosition(id)).toBeNull();
    }
    expect(stringColumnPosition("string:1")).toBe(1);
    expect(stringColumnPosition("string:10")).toBe(10);
  });

  it("still rejects an id that is neither fixed nor a map column", () => {
    const config = sanitizeColumnConfig({ order: ["level", "notAColumn", "mapped:"] });
    expect(config.order).toEqual(["level"]);
  });
});

describe("insertion-string columns", () => {
  const field = (name: string, value: string) => ({ name, value });

  it("offers a column per value the records carry, after the map columns", () => {
    const columns = availableColumns(["PayloadData1"], 3).map((column) => column.id);
    expect(columns).toEqual([
      ...EVTX_COLUMNS.map((column) => column.id),
      "mapped:PayloadData1",
      "string:1",
      "string:2",
      "string:3",
    ]);
  });

  it("counts the widest record and stops at the cap", () => {
    expect(
      discoverInsertionStrings([record({ eventData: [field("A", "1")] })])
    ).toBe(1);
    expect(
      discoverInsertionStrings([
        record({ eventData: [field("A", "1")] }),
        record({
          eventData: Array.from({ length: 14 }, (_, index) =>
            field(`F${index}`, `${index}`)
          ),
        }),
      ])
    ).toBe(MAX_INSERTION_STRING_COLUMNS);
    expect(availableColumns([], 99)).toHaveLength(
      EVTX_COLUMNS.length + MAX_INSERTION_STRING_COLUMNS
    );
  });

  it("renders the value in that position and nothing for a shorter record", () => {
    const wide = record({
      eventData: [field("Product", "Contoso"), field("Version", "2.1")],
    });
    expect(columnValue(wide, "string:1")).toBe("Contoso");
    expect(columnValue(wide, "string:2")).toBe("2.1");
    expect(columnValue(wide, "string:3")).toBe("");
    expect(columnValue(record(), "string:1")).toBe("");
  });

  it("keeps a stored insertion-string column and refuses one past the cap", () => {
    const kept = sanitizeColumnConfig({
      order: ["level", "string:2"],
      widths: { "string:2": 90 },
    });
    expect(kept.order).toEqual(["level", "string:2"]);
    expect(kept.widths["string:2"]).toBe(90);
    expect(sanitizeColumnConfig({ order: ["level", "string:11"] }).order).toEqual([
      "level",
    ]);
    expect(sanitizeColumnConfig({ order: ["level", "string:0"] }).order).toEqual([
      "level",
    ]);
  });

  it("resolves their label from the id alone", () => {
    expect(visibleColumns(config(["string:2"])).map((spec) => spec.label)).toEqual([
      "String 2",
    ]);
  });

  it("keeps an arranged column offerable when the records are narrower", () => {
    const arranged = sanitizeColumnConfig({ order: ["level", "string:3"] });
    expect(retainedInsertionStrings(arranged)).toBe(3);

    const narrowerRecords = [record({ eventData: [field("A", "1")] })];
    const offered = availableColumns(
      [],
      Math.max(
        discoverInsertionStrings(narrowerRecords),
        retainedInsertionStrings(arranged)
      )
    ).map((column) => column.id);
    expect(offered).toContain("string:3");
    expect(offered).not.toContain("string:4");

    // A hidden column keeps its width, so it stays offerable too.
    expect(retainedInsertionStrings(config([], { "string:4": 90 }))).toBe(4);
  });

  it("is hidden until an operator asks for it", () => {
    expect(defaultColumnConfig().order).not.toContain("string:1");
  });
});
