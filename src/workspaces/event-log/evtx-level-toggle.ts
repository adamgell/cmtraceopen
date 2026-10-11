/**
 * What a level toggle paints in each of its states (spec sections 8.3 and 6.2).
 *
 * Pure and Tauri-free so a test can measure it on resolved colors in every theme.
 *
 * The toggle is not a Fluent `ToggleButton`. Fluent draws the label and the background itself, and
 * in some themes its pairs fail: in high contrast the hover, mouse-down and selected surfaces are
 * one cyan (`#1aebff`) and `colorBrandForeground1` text on it measures 1.46:1; `colorNeutralForeground3`
 * counts drop to 1.94:1 on the dracula selection. So the component takes its colors from here and
 * the contrast test measures this table instead of trusting the library.
 *
 * Four states, because the checked toggle keeps one surface whether or not it is hovered or held:
 * - `rest`: unpressed, on the neutral surface.
 * - `hover`: unpressed, pointer over.
 * - `active`: unpressed, pointer or Space held down.
 * - `pressed`: the level is shown (`aria-pressed`), on `colorNeutralBackground1Selected`.
 */
import { tokens } from "@fluentui/react-components";
import { contrastRatio, readableOn } from "../../lib/color-contrast";
import type { CMTraceTheme } from "../../lib/themes/types";
import { evtxActiveTextColor } from "./evtx-active-state";
import { resolveToken, type EvtxVisualTokens } from "./evtx-visual-tokens";

export type LevelToggleState = "rest" | "hover" | "active" | "pressed";

export const LEVEL_TOGGLE_STATES: readonly LevelToggleState[] = [
  "rest",
  "hover",
  "active",
  "pressed",
];

/**
 * The surface behind the toggle in each state, as Fluent token references. The component's styles
 * and the contrast test both read this table, so a surface cannot change in one without the other.
 */
export const LEVEL_TOGGLE_BACKGROUNDS: Record<LevelToggleState, string> = {
  rest: tokens.colorNeutralBackground1,
  hover: tokens.colorNeutralBackground1Hover,
  active: tokens.colorNeutralBackground1Pressed,
  pressed: tokens.colorNeutralBackground1Selected,
};

export interface LevelToggleStateVisual {
  /** Resolved label color, at least 4.5:1 on this state's surface. */
  label: string;
  /** Resolved count color, at least 4.5:1 on this state's surface. */
  count: string;
  /**
   * Resolved 1 px ring drawn around the level dot, at least 3:1 on this state's surface; null at
   * rest, where the dot sits on the neutral surface and is measured without a ring. Every other
   * state is a non-neutral surface (spec 6.3 marks rule), so the ring is drawn there even in themes
   * where the fill alone would pass: a ring that appears in some themes and not others is a
   * different control per theme.
   */
  dotRing: string | null;
}

/** WCAG 2.x normal text. The label is 11 px at the default list size, so it is not large text. */
const TEXT_MINIMUM = 4.5;
const MARK_MINIMUM = 3;

/**
 * The first candidate that reads at 4.5:1 on `background`, else black or white, whichever contrasts
 * more. Candidates run from the most to the least de-emphasized.
 */
function readableText(background: string, candidates: readonly string[]): string {
  for (const candidate of candidates) {
    if (contrastRatio(candidate, background) >= TEXT_MINIMUM) return candidate;
  }
  return readableOn(background, candidates[0], TEXT_MINIMUM);
}

export function levelToggleStates(
  theme: CMTraceTheme,
  visual: EvtxVisualTokens,
): Record<LevelToggleState, LevelToggleStateVisual> {
  const resolve = (token: string) => resolveToken(token, theme);
  const surface = (state: LevelToggleState) => resolve(LEVEL_TOGGLE_BACKGROUNDS[state]);

  // Fluent's own foreground for the surface in each unpressed state, so the label follows the
  // library's hover and press behavior wherever that behavior is readable.
  const labelPreferred = {
    rest: resolve(tokens.colorNeutralForeground1),
    hover: resolve(tokens.colorNeutralForeground1Hover),
    active: resolve(tokens.colorNeutralForeground1Pressed),
  } as const;

  const build = (
    state: LevelToggleState,
    dotRing: string | null,
  ): LevelToggleStateVisual => {
    const background = surface(state);
    // Pressed is the spec's active-toggle text (6.2) on the selection surface: the same rule the view
    // bar's active tab and checked panel toggles use, so it comes from the one copy of it.
    const label =
      state === "pressed"
        ? evtxActiveTextColor(theme)
        : readableText(background, [labelPreferred[state]]);
    // The count is de-emphasized (spec: colorNeutralForeground3), then the secondary text token,
    // then the label itself, which is already readable. Solarized-dark and dracula fall through to
    // the secondary token at rest; high contrast reaches the label on every non-neutral surface.
    const count = readableText(background, [
      resolve(tokens.colorNeutralForeground3),
      resolve(tokens.colorNeutralForeground2),
      label,
    ]);
    return { label, count, dotRing };
  };

  return {
    rest: build("rest", null),
    hover: build("hover", readableOn(surface("hover"), labelPreferred.hover, MARK_MINIMUM)),
    active: build("active", readableOn(surface("active"), labelPreferred.active, MARK_MINIMUM)),
    // Spec 6.3 names this ring: markOutline("pressed") on the pressed surface.
    pressed: build("pressed", visual.markOutline("pressed")),
  };
}
