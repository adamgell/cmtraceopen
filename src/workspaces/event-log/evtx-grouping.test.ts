import { describe, expect, it } from "vitest";
import {
  allGroupKeys,
  buildGroupedRows,
  type EvtxGroupField,
  type EvtxRow,
} from "./evtx-filter";
import type { EvtxRecord } from "./types";

function record(partial: Partial<EvtxRecord>): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 0,
    timestamp: "",
    timestampEpoch: 0,
    provider: "P",
    channel: "C",
    eventId: 1,
    level: "Information",
    computer: "H",
    message: "",
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
    ...partial,
  };
}

const groups = (rows: EvtxRow[]) =>
  rows.filter((r): r is Extract<EvtxRow, { kind: "group" }> => r.kind === "group");
const records = (rows: EvtxRow[]) => rows.filter((r) => r.kind === "record");

describe("buildGroupedRows", () => {
  it("returns plain record rows when nothing is grouped", () => {
    const rows = buildGroupedRows([record({ id: 1 }), record({ id: 2 })], [], new Set());
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.kind === "record")).toBe(true);
  });

  it("emits a header per distinct value with its record count", () => {
    const rows = buildGroupedRows(
      [
        record({ id: 1, level: "Error" }),
        record({ id: 2, level: "Error" }),
        record({ id: 3, level: "Warning" }),
      ],
      ["level"],
      new Set()
    );
    const headers = groups(rows);
    expect(headers.map((h) => [h.label, h.count])).toEqual([
      ["Error", 2],
      ["Warning", 1],
    ]);
    expect(records(rows)).toHaveLength(3);
  });

  it("preserves incoming order so the operator's sort still applies", () => {
    // Warning is seen first, so its group comes first. Alphabetising would override the sort.
    const rows = buildGroupedRows(
      [record({ id: 1, level: "Warning" }), record({ id: 2, level: "Error" })],
      ["level"],
      new Set()
    );
    expect(groups(rows).map((h) => h.label)).toEqual(["Warning", "Error"]);
  });

  it("nests groups in the order given and counts every descendant", () => {
    const rows = buildGroupedRows(
      [
        record({ id: 1, level: "Error", provider: "A" }),
        record({ id: 2, level: "Error", provider: "B" }),
        record({ id: 3, level: "Warning", provider: "A" }),
      ],
      ["level", "provider"],
      new Set()
    );
    const headers = groups(rows);
    expect(headers.map((h) => [h.depth, h.label, h.count])).toEqual([
      [0, "Error", 2],
      [1, "A", 1],
      [1, "B", 1],
      [0, "Warning", 1],
      [1, "A", 1],
    ]);
  });

  it("gives sibling groups distinct keys even when their labels match", () => {
    // Provider A appears under both levels; colliding keys would collapse both at once.
    const rows = buildGroupedRows(
      [
        record({ id: 1, level: "Error", provider: "A" }),
        record({ id: 2, level: "Warning", provider: "A" }),
      ],
      ["level", "provider"],
      new Set()
    );
    const keys = groups(rows)
      .filter((h) => h.depth === 1)
      .map((h) => h.key);
    expect(new Set(keys).size).toBe(2);
  });

  it("hides descendants of a collapsed group but keeps its count", () => {
    const rows = buildGroupedRows(
      [
        record({ id: 1, level: "Error", provider: "A" }),
        record({ id: 2, level: "Error", provider: "B" }),
        record({ id: 3, level: "Warning" }),
      ],
      ["level", "provider"],
      new Set(["/level=Error"])
    );
    const headers = groups(rows);
    expect(headers.find((h) => h.label === "Error")?.count).toBe(2);
    expect(headers.some((h) => h.depth === 1 && h.label === "A")).toBe(false);
    expect(records(rows)).toHaveLength(1);
  });

  it("groups by local day", () => {
    const day = new Date(2026, 7, 9, 12).getTime();
    const nextDay = new Date(2026, 7, 10, 12).getTime();
    const rows = buildGroupedRows(
      [
        record({ id: 1, timestampEpoch: day }),
        record({ id: 2, timestampEpoch: day }),
        record({ id: 3, timestampEpoch: nextDay }),
      ],
      ["day"],
      new Set()
    );
    expect(groups(rows).map((h) => h.count)).toEqual([2, 1]);
  });

  it("labels missing values instead of showing an empty header", () => {
    const rows = buildGroupedRows([record({ provider: "" })], ["provider"], new Set());
    expect(groups(rows)[0].label).toBe("(no provider)");
  });

  it("handles an empty record set", () => {
    expect(buildGroupedRows([], ["level"], new Set())).toEqual([]);
  });
});

describe("allGroupKeys", () => {
  it("returns every key including nested ones", () => {
    const keys = allGroupKeys(
      [
        record({ id: 1, level: "Error", provider: "A" }),
        record({ id: 2, level: "Warning", provider: "B" }),
      ],
      ["level", "provider"] as EvtxGroupField[]
    );
    expect(keys.size).toBe(4);
  });

  it("is empty when nothing is grouped", () => {
    expect(allGroupKeys([record({})], []).size).toBe(0);
  });
});

describe("group key encoding", () => {
  it("keeps distinct ancestries distinct when a value contains the delimiters", () => {
    // Unencoded, a provider literally named "x/level=Error" produces the same key as the
    // Error subgroup of provider "x", and collapsing one would collapse the other.
    const rows = buildGroupedRows(
      [
        record({ id: 1, provider: "x/level=Error", level: "Information" }),
        record({ id: 2, provider: "x", level: "Error" }),
      ],
      ["provider", "level"],
      new Set()
    );

    const keys = rows.flatMap((r) => (r.kind === "group" ? [r.key] : []));
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("collapsing one group does not collapse an unrelated one", () => {
    const all = buildGroupedRows(
      [
        record({ id: 1, provider: "x/level=Error", level: "Information" }),
        record({ id: 2, provider: "x", level: "Error" }),
      ],
      ["provider", "level"],
      new Set()
    );
    const target = all.find((r) => r.kind === "group" && r.label === "Error");
    expect(target?.kind).toBe("group");
    const targetKey = target && target.kind === "group" ? target.key : "";

    const collapsed = buildGroupedRows(
      [
        record({ id: 1, provider: "x/level=Error", level: "Information" }),
        record({ id: 2, provider: "x", level: "Error" }),
      ],
      ["provider", "level"],
      new Set([targetKey])
    );

    // Exactly one record disappears; the other ancestry is untouched.
    const visible = collapsed.filter((r) => r.kind === "record");
    expect(visible).toHaveLength(1);
    expect(visible[0].record.id).toBe(1);
  });
});

describe("day grouping honours the time zone", () => {
  it("buckets by UTC date when asked for UTC", () => {
    // Every other test here relies on the default, so a regression that ignored the argument and
    // always bucketed by local date would pass the whole file. This instant sits on either side of
    // midnight depending on the zone.
    const lateUtc = Date.UTC(2026, 1, 10, 23, 30, 0);
    const rows = buildGroupedRows(
      [record({ id: 1, timestampEpoch: lateUtc })],
      ["day"],
      new Set(),
      "utc"
    );
    const header = rows.find((r) => r.kind === "group");
    expect(header && header.kind === "group" ? header.label : "").toBe("2026-02-10");
  });

  it("buckets by the machine's own date when asked for local", () => {
    const lateUtc = Date.UTC(2026, 1, 10, 23, 30, 0);
    const local = new Date(lateUtc);
    const expected =
      `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, "0")}-` +
      `${String(local.getDate()).padStart(2, "0")}`;
    const rows = buildGroupedRows(
      [record({ id: 1, timestampEpoch: lateUtc })],
      ["day"],
      new Set(),
      "local"
    );
    const header = rows.find((r) => r.kind === "group");
    expect(header && header.kind === "group" ? header.label : "").toBe(expected);
  });
});
