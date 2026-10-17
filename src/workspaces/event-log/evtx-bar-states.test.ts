import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { evtxActiveSurface, evtxActiveTextColor } from "./evtx-active-state";
import {
  EVTX_FOCUS_RING,
  FOCUS_SURFACES,
  LAYOUT_TAB_STATES,
} from "./evtx-bar-states";
import { resolveToken } from "./evtx-visual-tokens";

const TEXT_MIN = 4.5;
const GRAPHIC_MIN = 3;

const hex = (value: string, theme: CMTraceTheme) => resolveToken(value, theme);

/**
 * A two-tone ring is visible on a surface when its two rings differ from each other and at least
 * one of them contrasts with the surface. A ring that equals its fill fails on its own.
 */
function ringVisible(rings: string[], surface: string): boolean {
  const contrasts = rings.map((ring) => contrastRatio(ring, surface));
  if (rings.length === 1) return contrasts[0] >= GRAPHIC_MIN;
  return contrastRatio(rings[0], rings[1]) >= GRAPHIC_MIN && Math.max(...contrasts) >= GRAPHIC_MIN;
}

describe("focus ring on every surface, in every theme", () => {
  it("fails a single ring that is the same color as its fill (the old high-contrast tab)", () => {
    const theme = getAllThemes().find((candidate) => candidate.id === "high-contrast");
    if (!theme) throw new Error("high-contrast theme is missing");
    const ring = hex(EVTX_FOCUS_RING.outer, theme);
    const selected = evtxActiveSurface(theme);
    expect(contrastRatio(ring, selected)).toBeLessThan(1.5);
    expect(ringVisible([ring], selected)).toBe(false);
  });

  for (const theme of getAllThemes()) {
    for (const [name, token] of Object.entries(FOCUS_SURFACES)) {
      it(`shows the two-tone ring on the ${name} surface in ${theme.id}`, () => {
        const outer = hex(EVTX_FOCUS_RING.outer, theme);
        const inner = hex(EVTX_FOCUS_RING.inner, theme);
        const surface = hex(token, theme);
        const detail = `${theme.id}/${name}: outer ${outer} inner ${inner} on ${surface}`;
        expect(ringVisible([inner, outer], surface), detail).toBe(true);
      });
    }
  }
});

describe("interactive state pairs, in every theme", () => {
  for (const theme of getAllThemes()) {
    for (const [state, pair] of Object.entries(LAYOUT_TAB_STATES)) {
      it(`keeps inactive tab ${state} text at 4.5:1 in ${theme.id}`, () => {
        const ratio = contrastRatio(hex(pair.foreground, theme), hex(pair.background, theme));
        expect(ratio, `${theme.id}/${state}`).toBeGreaterThanOrEqual(TEXT_MIN);
      });
    }

    it(`keeps active tab and checked toggle text, icon and hover border visible in ${theme.id}`, () => {
      const surface = evtxActiveSurface(theme);
      const text = evtxActiveTextColor(theme);
      // Text and icon (currentColor) at 4.5:1; the hover and pressed border uses the same color
      // and must reach 3:1 on the fill it is drawn on.
      expect(contrastRatio(text, surface)).toBeGreaterThanOrEqual(TEXT_MIN);
      expect(contrastRatio(text, surface)).toBeGreaterThanOrEqual(GRAPHIC_MIN);
    });

    it(`has a distinct inner and outer ring color in ${theme.id}`, () => {
      expect(hex(EVTX_FOCUS_RING.inner, theme)).not.toBe(hex(EVTX_FOCUS_RING.outer, theme));
    });
  }
});
