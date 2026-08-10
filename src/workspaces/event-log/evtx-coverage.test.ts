import { describe, expect, it } from "vitest";
import { mergeCoverageGaps, summarizeCoverageGaps } from "./evtx-coverage";

describe("mergeCoverageGaps", () => {
  it("accumulates gaps across channels", () => {
    // Each channel loads separately and reports its own gaps. Replacing rather than accumulating
    // would leave only the last channel's gaps visible and silently drop the rest.
    const merged = mergeCoverageGaps(["Application: 3 records unreadable"], [
      "System: stopped at 100000 events",
    ]);
    expect(merged).toEqual([
      "Application: 3 records unreadable",
      "System: stopped at 100000 events",
    ]);
  });

  it("does not repeat a gap when a channel is re-queried", () => {
    // A banner that grows on every refresh trains an operator to stop reading it.
    const first = mergeCoverageGaps([], ["Application: 3 records unreadable"]);
    const second = mergeCoverageGaps(first, ["Application: 3 records unreadable"]);
    expect(second).toHaveLength(1);
  });

  it("keeps the order gaps were first reported in", () => {
    // A gap that moves around the list as later channels finish is hard to read past.
    const merged = mergeCoverageGaps(["first", "second"], ["third", "first"]);
    expect(merged).toEqual(["first", "second", "third"]);
  });

  it("reports nothing when nothing is missing", () => {
    expect(mergeCoverageGaps([], [])).toEqual([]);
  });
});

describe("summarizeCoverageGaps", () => {
  it("uses the singular for one gap", () => {
    expect(summarizeCoverageGaps(["only"])).toBe("1 gap in this view");
  });

  it("uses the plural otherwise", () => {
    expect(summarizeCoverageGaps(["a", "b"])).toBe("2 gaps in this view");
  });
});

describe("gaps across load paths", () => {
  it("a refresh replaces gaps rather than carrying stale ones forward", () => {
    // The refresh clears records, so the gaps describing them have to go too. Keeping them would
    // report a gap from a set no longer on screen while the new result's own gap went unsaid.
    const beforeRefresh = ["Application: 3 records unreadable"];
    const afterClear = mergeCoverageGaps([], ["System: stopped at 100000 events"]);
    expect(afterClear).not.toContain(beforeRefresh[0]);
    expect(afterClear).toEqual(["System: stopped at 100000 events"]);
  });

  it("an incremental channel load adds to what is already reported", () => {
    // Channels load one at a time, so replacing here would leave only the last channel's gaps.
    const first = mergeCoverageGaps([], ["Application: 3 records unreadable"]);
    const second = mergeCoverageGaps(first, ["Security: 1 record unreadable"]);
    expect(second).toHaveLength(2);
  });
});
