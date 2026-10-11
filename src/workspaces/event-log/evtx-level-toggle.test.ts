/**
 * The level toggles' colors in every state, measured on resolved colors in all seven themes.
 *
 * Adam's acceptance criterion for Phase 5 (issue #832, carried over from the Phase 1 token review):
 * the dot on a level toggle must stay readable in hover, pressed and the other states, including
 * high contrast, where `colorNeutralBackground1Hover` equals `colorNeutralBackground1Selected`.
 * Fluent draws the label and the background; this module decides what the toggle paints instead of
 * leaving a failing pair to the component library. The component test proves the rendered button
 * paints these same values (EvtxFilterBar.test.tsx).
 */
import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import {
  LEVEL_TOGGLE_BACKGROUNDS,
  LEVEL_TOGGLE_STATES,
  levelToggleStates,
  type LevelToggleState,
} from "./evtx-level-toggle";
import { evtxActiveTextColor } from "./evtx-active-state";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import { EVTX_LEVELS } from "./evtx-filter";

const themes = getAllThemes().map((theme) => [theme.id, theme] as const);

/** WCAG 2.x: normal text 4.5:1, non-text marks 3:1. */
const TEXT_MINIMUM = 4.5;
const MARK_MINIMUM = 3;

describe("level toggle states", () => {
  it("covers all seven themes", () => {
    expect(themes.map(([id]) => id).sort()).toEqual([
      "classic-cmtrace",
      "dark",
      "dracula",
      "high-contrast",
      "light",
      "nord",
      "solarized-dark",
    ]);
  });

  it("names the states the issue lists: rest, hover, mouse-down and pressed", () => {
    expect([...LEVEL_TOGGLE_STATES]).toEqual(["rest", "hover", "active", "pressed"]);
  });

  it("paints Fluent's own surfaces for the unpressed states and the selection surface when pressed", () => {
    expect(LEVEL_TOGGLE_BACKGROUNDS).toEqual({
      rest: "var(--colorNeutralBackground1)",
      hover: "var(--colorNeutralBackground1Hover)",
      active: "var(--colorNeutralBackground1Pressed)",
      pressed: "var(--colorNeutralBackground1Selected)",
    });
  });
});

describe.each(themes)("level toggle contrast in the %s theme", (id, theme) => {
  const visual = buildEvtxVisualTokens(theme);
  const states = levelToggleStates(theme, visual);
  const background = (state: LevelToggleState) =>
    resolveToken(LEVEL_TOGGLE_BACKGROUNDS[state], theme);

  it.each(LEVEL_TOGGLE_STATES)(
    "keeps every level dot at 3:1 or better in the %s state",
    (state) => {
      const failures: string[] = [];
      for (const level of EVTX_LEVELS) {
        const fill = resolveToken(visual.levels[level].dotColor, theme);
        const ring = states[state].dotRing;
        // A ring is the mark when there is one: it is drawn around the dot, so the dot is as
        // readable as its outline. Without a ring the fill itself is the mark.
        const mark = ring ?? fill;
        const ratio = contrastRatio(mark, background(state));
        if (ratio < MARK_MINIMUM) {
          failures.push(
            `${id}: ${level} dot ${fill}${ring ? ` ringed ${ring}` : ""} on ${state} ${background(state)} = ${ratio.toFixed(2)}`,
          );
        }
      }
      expect(failures, failures.join("; ")).toEqual([]);
    },
  );

  it("rings the dot in every state that is not the neutral surface", () => {
    expect(states.rest.dotRing).toBeNull();
    for (const state of ["hover", "active", "pressed"] as const) {
      expect(states[state].dotRing, `${id}: ${state}`).not.toBeNull();
    }
  });

  it("leaves the rest state's dot readable on the surface without a ring", () => {
    const failures: string[] = [];
    for (const level of EVTX_LEVELS) {
      const fill = resolveToken(visual.levels[level].dotColor, theme);
      const ratio = contrastRatio(fill, background("rest"));
      if (ratio < MARK_MINIMUM) {
        failures.push(`${id}: ${level} dot ${fill} on rest = ${ratio.toFixed(2)}`);
      }
    }
    expect(failures, failures.join("; ")).toEqual([]);
  });

  it.each(LEVEL_TOGGLE_STATES)("draws the label at 4.5:1 in the %s state", (state) => {
    const ratio = contrastRatio(states[state].label, background(state));
    expect(ratio, `${id}: ${state} label ${states[state].label}`).toBeGreaterThanOrEqual(
      TEXT_MINIMUM,
    );
  });

  it.each(LEVEL_TOGGLE_STATES)("draws the count at 4.5:1 in the %s state", (state) => {
    const ratio = contrastRatio(states[state].count, background(state));
    expect(ratio, `${id}: ${state} count ${states[state].count}`).toBeGreaterThanOrEqual(
      TEXT_MINIMUM,
    );
  });

  it("takes the pressed label from the view bar's active text rule, not a second copy of it", () => {
    expect(states.pressed.label, id).toBe(evtxActiveTextColor(theme));
  });

  it("uses the spec's pressed text, colorBrandForeground1, wherever it is readable", () => {
    // Spec 6.2. It measures below 4.5:1 on the selection surface in high contrast, classic and
    // dracula, and only there; those three fall back to black or white.
    const brand = resolveToken(tokens.colorBrandForeground1, theme);
    const readable =
      contrastRatio(brand, background("pressed")) >= TEXT_MINIMUM;
    if (readable) {
      expect(states.pressed.label.toLowerCase()).toBe(brand.toLowerCase());
    } else {
      expect(["#000000", "#ffffff"]).toContain(states.pressed.label.toLowerCase());
    }
  });
});

describe("level toggle states in high contrast, where hover equals the selection surface", () => {
  const theme = getAllThemes().find((candidate) => candidate.id === "high-contrast")!;
  const visual = buildEvtxVisualTokens(theme);
  const states = levelToggleStates(theme, visual);

  it("has one surface for hover, mouse-down and pressed", () => {
    const hover = resolveToken(LEVEL_TOGGLE_BACKGROUNDS.hover, theme);
    expect(resolveToken(LEVEL_TOGGLE_BACKGROUNDS.active, theme)).toBe(hover);
    expect(resolveToken(LEVEL_TOGGLE_BACKGROUNDS.pressed, theme)).toBe(hover);
    expect(hover.toLowerCase()).toBe("#1aebff");
  });

  it("would lose every dot on that surface without the ring", () => {
    const hover = resolveToken(LEVEL_TOGGLE_BACKGROUNDS.hover, theme);
    for (const level of EVTX_LEVELS) {
      const fill = resolveToken(visual.levels[level].dotColor, theme);
      expect(contrastRatio(fill, hover), `${level} ${fill}`).toBeLessThan(MARK_MINIMUM);
    }
  });

  it("rings the dot in black and draws black text on the cyan surface", () => {
    for (const state of ["hover", "active", "pressed"] as const) {
      expect(states[state].dotRing?.toLowerCase(), state).toBe("#000000");
      expect(states[state].label.toLowerCase(), state).toBe("#000000");
    }
  });

  it("takes the pressed ring from the token map's markOutline", () => {
    expect(states.pressed.dotRing).toBe(visual.markOutline("pressed"));
  });
});
