import { describe, expect, it } from "vitest";
import { parseEventIdFilter } from "./evtx-filter";

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

  it("returns null when nothing in the box parsed", () => {
    expect(parseEventIdFilter("abc, def")).toBeNull();
  });
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

  it("yields nothing for a range entirely above the id space", () => {
    expect(parseEventIdFilter("100000-200000")).toBeNull();
  });

  it("still expands an ordinary range", () => {
    const ids = parseEventIdFilter("4624-4626");
    expect([...ids!].sort((a, b) => a - b)).toEqual([4624, 4625, 4626]);
  });
});
