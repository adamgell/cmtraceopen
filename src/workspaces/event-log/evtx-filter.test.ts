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
