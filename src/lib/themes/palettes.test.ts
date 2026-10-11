import { describe, expect, it } from "vitest";

import { themeSeverityPalettes } from "./palettes";
import type { ThemeId } from "./types";

const WCAG_AA_TEXT = 4.5;

function relativeLuminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!match) throw new Error(`Expected #RRGGBB, got ${hex}`);
  const channels = [0, 2, 4].map((offset) => {
    const value = parseInt(match[1].slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(foreground: string, background: string): number {
  const a = relativeLuminance(foreground);
  const b = relativeLuminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

// CIE L*a*b* (D65) so "reads red" and "visibly different" are perceptual checks.
function hexToLab(hex: string): { l: number; a: number; b: number } {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!match) throw new Error(`Expected #RRGGBB, got ${hex}`);
  const [r, g, b] = [0, 2, 4].map((offset) => {
    const value = parseInt(match[1].slice(offset, offset + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  const x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047;
  const y = 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
  const z = (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883;
  const f = (t: number) => (t > 216 / 24389 ? Math.cbrt(t) : (24389 / 27 * t + 16) / 116);
  const [fx, fy, fz] = [f(x), f(y), f(z)];
  return { l: 116 * fy - 16, a: 500 * (fx - fy), b: 200 * (fy - fz) };
}

function chroma(hex: string): number {
  const { a, b } = hexToLab(hex);
  return Math.hypot(a, b);
}

function hue(hex: string): number {
  const { a, b } = hexToLab(hex);
  return ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360;
}

function deltaE76(first: string, second: string): number {
  const x = hexToLab(first);
  const y = hexToLab(second);
  return Math.hypot(x.l - y.l, x.a - y.a, x.b - y.b);
}

/** Red family in Lab hue degrees: [345, 360] or [0, 50]. */
function isRed(hex: string): boolean {
  const h = hue(hex);
  return (h >= 345 || h <= 50) && chroma(hex) >= MIN_RED_CHROMA;
}

const MIN_RED_CHROMA = 30;
const MIN_ROW_DELTA_E = 10;

const themeIds = Object.keys(themeSeverityPalettes) as ThemeId[];
// Every kind LogRow.tsx renders from the palette (rowStyle and the dot color).
const rowKinds = ["error", "warning", "info", "success"] as const;

// Every unordered pair of row kinds must be distinguishable at a glance.
const rowKindPairs = rowKinds.flatMap((first, index) =>
  rowKinds.slice(index + 1).map((second) => [first, second] as const),
);

describe("theme severity row palettes", () => {
  describe.each(themeIds)("%s", (themeId) => {
    const palette = themeSeverityPalettes[themeId];

    it.each(rowKinds)("%s row text meets WCAG AA against its row background", (kind) => {
      const { text, background } = palette[kind];
      expect(contrastRatio(text, background)).toBeGreaterThanOrEqual(WCAG_AA_TEXT);
    });

    it.each(rowKindPairs)("%s and %s rows are visually distinct", (first, second) => {
      expect(palette[first]).not.toEqual(palette[second]);
      const look = Math.max(
        deltaE76(palette[first].text, palette[second].text),
        deltaE76(palette[first].background, palette[second].background),
      );
      expect(look).toBeGreaterThanOrEqual(MIN_ROW_DELTA_E);
    });

    it("error row reads red (text or background in the red family)", () => {
      const { text, background } = palette.error;
      expect(isRed(text) || isRed(background)).toBe(true);
    });
  });
});
