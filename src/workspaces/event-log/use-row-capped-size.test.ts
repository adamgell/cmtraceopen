import { describe, expect, it } from "vitest";
import { effectiveResizeRange } from "./use-row-capped-size";

describe("effectiveResizeRange", () => {
  it("keeps the nominal range and the requested value when nothing is measured", () => {
    expect(effectiveResizeRange(250, 200, 500, { rendered: 0, cap: 0 })).toEqual({
      value: 250,
      min: 200,
      max: 500,
    });
  });

  it("keeps the nominal range at a normal width, where the cap is above the maximum", () => {
    expect(effectiveResizeRange(250, 200, 500, { rendered: 250, cap: 576 })).toEqual({
      value: 250,
      min: 200,
      max: 500,
    });
  });

  it("reports the rendered width and caps the maximum on a narrow row", () => {
    expect(effectiveResizeRange(250, 200, 500, { rendered: 240, cap: 240 })).toEqual({
      value: 240,
      min: 200,
      max: 240,
    });
  });

  it("lowers the minimum when the cap is below it, so the value stays inside the range", () => {
    const range = effectiveResizeRange(340, 280, 480, { rendered: 200, cap: 200 });
    expect(range).toEqual({ value: 200, min: 200, max: 200 });
  });
});
