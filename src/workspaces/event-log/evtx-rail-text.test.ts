import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { pickRailTextColors } from "./evtx-rail-text";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";

const FLOOR = 4.5;

describe("rail text colors on the rail surface (colorNeutralBackground2)", () => {
  it("covers all seven themes", () => {
    expect(getAllThemes()).toHaveLength(7);
  });

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "%s: every text color the rail draws directly on its surface reaches 4.5:1",
    (_id, theme) => {
      const surface = resolveToken(tokens.colorNeutralBackground2, theme);
      const picked = pickRailTextColors(theme);
      const visuals = buildEvtxVisualTokens(theme);
      const drawn: Record<string, string> = {
        primary: picked.primary,
        secondary: picked.secondary,
        // Fluent's own unselected tab and the empty-state line.
        foreground2: tokens.colorNeutralForeground2,
        // The incomplete mapped field in Details.
        "warning text": visuals.levels.Warning.textColor,
        // The level word in the Details header.
        "level word": visuals.levels.Error.textColor,
      };
      for (const [name, color] of Object.entries(drawn)) {
        expect(
          contrastRatio(resolveToken(color, theme), surface),
          `${theme.id} ${name} on ${surface}`,
        ).toBeGreaterThanOrEqual(FLOOR);
      }
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "%s: every text color the rail's cards draw on colorNeutralBackground1 reaches 4.5:1",
    (_id, theme) => {
      const surface = resolveToken(tokens.colorNeutralBackground1, theme);
      const picked = pickRailTextColors(theme);
      const drawn: Record<string, string> = {
        "card caption": picked.cardSecondary,
        foreground1: tokens.colorNeutralForeground1,
        foreground2: tokens.colorNeutralForeground2,
        "level text": buildEvtxVisualTokens(theme).levels.Error.textColor,
      };
      for (const [name, color] of Object.entries(drawn)) {
        expect(
          contrastRatio(resolveToken(color, theme), surface),
          `${theme.id} ${name} on ${surface}`,
        ).toBeGreaterThanOrEqual(FLOOR);
      }
    },
  );

  it("keeps the designed Foreground1 and Foreground3 wherever they pass, and falls back to Foreground2 only where they miss", () => {
    const byId = (id: string) => pickRailTextColors(getAllThemes().find((theme) => theme.id === id)!);
    // Measured on the rail surface: solarized-dark Foreground1 4.11, Foreground3 2.92;
    // dracula Foreground3 3.36.
    // On the card surface (Background1) Foreground3 measures 3.37:1 in solarized-dark and 3.03:1 in
    // dracula.
    expect(byId("solarized-dark")).toEqual({
      primary: tokens.colorNeutralForeground2,
      secondary: tokens.colorNeutralForeground2,
      cardSecondary: tokens.colorNeutralForeground2,
    });
    expect(byId("dracula")).toEqual({
      primary: tokens.colorNeutralForeground1,
      secondary: tokens.colorNeutralForeground2,
      cardSecondary: tokens.colorNeutralForeground2,
    });
    for (const id of ["light", "dark", "high-contrast", "classic-cmtrace", "nord"]) {
      expect(byId(id)).toEqual({
        primary: tokens.colorNeutralForeground1,
        secondary: tokens.colorNeutralForeground3,
        cardSecondary: tokens.colorNeutralForeground3,
      });
    }
  });
});
