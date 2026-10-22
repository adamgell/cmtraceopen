import { describe, expect, it } from "vitest";
import { effectiveResizeRange, proposeResize } from "./use-row-capped-size";

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

describe("proposeResize", () => {
  it("returns null when a capped proposal clamps to the rendered width", () => {
    const range = { value: 200, min: 200, max: 200 };
    expect(proposeResize(216, range)).toBeNull();
    expect(proposeResize(500, range)).toBeNull();
    expect(proposeResize(0, range)).toBeNull();
  });

  it("returns the clamped width when the visible width would change", () => {
    const range = { value: 240, min: 200, max: 240 };
    expect(proposeResize(220, range)).toBe(220);
    expect(proposeResize(100, range)).toBe(200);
  });

  it("is a no-op at normal widths when the proposal equals the current width", () => {
    const range = { value: 250, min: 200, max: 500 };
    expect(proposeResize(250, range)).toBeNull();
    expect(proposeResize(266, range)).toBe(266);
    expect(proposeResize(900, range)).toBe(500);
  });
});

describe("proposeResize with fractional proposals", () => {
  it("returns null for a sub-pixel proposal that rounds back to the capped value", () => {
    expect(proposeResize(299.6, { value: 300, min: 160, max: 300 })).toBeNull();
    expect(proposeResize(399.7, { value: 400, min: 280, max: 400 })).toBeNull();
    expect(proposeResize(300.4, { value: 300, min: 160, max: 300 })).toBeNull();
  });

  it("still writes a real shrink of 1 px or more under a binding cap", () => {
    expect(proposeResize(299, { value: 300, min: 160, max: 300 })).toBe(299);
    expect(proposeResize(298.6, { value: 300, min: 160, max: 300 })).toBe(299);
    expect(proposeResize(398.4, { value: 400, min: 280, max: 400 })).toBe(398);
  });

  it("rounds a fractional proposal away from the cap as the store would", () => {
    const range = { value: 250, min: 200, max: 500 };
    expect(proposeResize(266.4, range)).toBe(266);
    expect(proposeResize(266.5, range)).toBe(267);
    expect(Number.isInteger(proposeResize(333.3, range))).toBe(true);
    expect(proposeResize(0.2, range)).toBe(200);
    expect(proposeResize(900.4, range)).toBe(500);
  });
});
