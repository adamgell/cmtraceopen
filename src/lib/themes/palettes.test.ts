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

// hotdog-stand is excluded because its removal is in flight on a separate branch.
const EXCLUDED_THEMES: ThemeId[] = ["hotdog-stand"];
const themeIds = (Object.keys(themeSeverityPalettes) as ThemeId[]).filter(
  (id) => !EXCLUDED_THEMES.includes(id),
);
const rowKinds = ["error", "warning", "info"] as const;

describe("theme severity row palettes", () => {
  describe.each(themeIds)("%s", (themeId) => {
    const palette = themeSeverityPalettes[themeId];

    it.each(rowKinds)("%s row text meets WCAG AA against its row background", (kind) => {
      const { text, background } = palette[kind];
      expect(contrastRatio(text, background)).toBeGreaterThanOrEqual(WCAG_AA_TEXT);
    });

    it("error row is visually distinct from the info row", () => {
      expect(palette.error).not.toEqual(palette.info);
    });
  });
});
