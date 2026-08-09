import { describe, expect, it } from "vitest";
import {
  columnValue,
  columnWidth,
  defaultColumnConfig,
  EVTX_COLUMNS,
  moveColumn,
  sanitizeColumnConfig,
  toggleColumn,
  visibleColumns,
  type EvtxColumnConfig,
} from "./evtx-columns";
import type { EvtxRecord } from "./types";

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
    computer: "RING0IVY24-01",
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
    const level = EVTX_COLUMNS.find((c) => c.id === "level")!;
    expect(columnWidth(config(["level"], { level: 88 }), level)).toBe(88);
    expect(columnWidth(config(["level"]), level)).toBe(level.defaultWidth);
  });

  it("keeps the description column unbounded", () => {
    const message = EVTX_COLUMNS.find((c) => c.id === "message")!;
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
