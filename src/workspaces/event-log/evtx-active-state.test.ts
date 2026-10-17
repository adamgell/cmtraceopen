import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import {
  EVTX_ACTIVE_TEXT_MIN_CONTRAST,
  evtxActiveSurface,
  evtxActiveTextColor,
} from "./evtx-active-state";
import { resolveToken } from "./evtx-visual-tokens";
import { tokens } from "@fluentui/react-components";

describe("active Layout tab and checked panel toggle text", () => {
  it("covers all seven themes", () => {
    expect(getAllThemes()).toHaveLength(7);
  });

  for (const theme of getAllThemes()) {
    it(`reaches 4.5:1 on the selected surface in ${theme.id}`, () => {
      const surface = evtxActiveSurface(theme);
      const text = evtxActiveTextColor(theme);
      const ratio = contrastRatio(text, surface);
      // Reported per theme so a regression shows the number.
      console.info(`active text ${theme.id}: ${text} on ${surface} = ${ratio.toFixed(2)}`);
      expect(ratio).toBeGreaterThanOrEqual(EVTX_ACTIVE_TEXT_MIN_CONTRAST);
    });

    it(`keeps the brand foreground where it already passes in ${theme.id}`, () => {
      const surface = evtxActiveSurface(theme);
      const brand = resolveToken(tokens.colorBrandForeground1, theme);
      if (contrastRatio(brand, surface) >= EVTX_ACTIVE_TEXT_MIN_CONTRAST) {
        expect(evtxActiveTextColor(theme)).toBe(brand);
      } else {
        expect(["#000000", "#ffffff"]).toContain(evtxActiveTextColor(theme));
      }
    });
  }
});
