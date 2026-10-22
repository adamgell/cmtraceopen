import { describe, expect, it } from "vitest";
import { allGroupKeys } from "./evtx-filter";
import { renderedRecords, sortForGrid } from "./evtx-row-order";
import type { EvtxRecord } from "./types";

function record(id: number, provider: string, timestampEpoch: number): EvtxRecord {
  return {
    id,
    eventRecordId: 100 + id,
    timestamp: "",
    timestampEpoch,
    provider,
    channel: "Application",
    eventId: 1,
    level: "Information",
    computer: "PC",
    message: "",
    eventData: [],
    rawXml: "",
    sourceLabel: "a.evtx",
  };
}

const records = [
  record(0, "B", 10),
  record(1, "A", 20),
  record(2, "B", 30),
  record(3, "A", 40),
];
const ids = (list: EvtxRecord[]) => list.map((r) => r.id);

describe("renderedRecords", () => {
  it("is the sorted order with no grouping", () => {
    const sorted = sortForGrid(records, "time", "desc");
    expect(ids(renderedRecords(sorted, [], new Set(), "utc"))).toEqual([3, 2, 1, 0]);
  });

  it("walks groups in first-seen order, keeping the sort inside each group", () => {
    const sorted = sortForGrid(records, "time", "asc");
    expect(ids(renderedRecords(sorted, ["provider"], new Set(), "utc"))).toEqual([0, 2, 1, 3]);
  });

  it("leaves out the records of a collapsed group, because they have no row", () => {
    const sorted = sortForGrid(records, "time", "asc");
    const collapsed = new Set([[...allGroupKeys(sorted, ["provider"])][0]]);
    // The first group is B (first seen in time order).
    expect(ids(renderedRecords(sorted, ["provider"], collapsed, "utc"))).toEqual([1, 3]);
    const both = allGroupKeys(sorted, ["provider"]);
    expect(renderedRecords(sorted, ["provider"], both, "utc")).toEqual([]);
  });
});
