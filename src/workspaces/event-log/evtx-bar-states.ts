/**
 * The color pairs behind the workbench's own interactive states (view bar tabs, checked panel
 * toggles, resize handles), kept as data so a test can measure exactly what the styles use.
 *
 * Every background a state paints sets its paired foreground (and, where a border is drawn, a
 * border that stays visible on that fill), because a bare `colorNeutralForeground2` on a hover
 * fill is 1.46:1 in the high-contrast theme.
 */
import { tokens } from "@fluentui/react-components";

/** Fluent's two-tone focus ring: an outer `colorStrokeFocus2` and an inner `colorStrokeFocus1`. */
export const EVTX_FOCUS_RING = {
  outer: tokens.colorStrokeFocus2,
  inner: tokens.colorStrokeFocus1,
} as const;

/**
 * Styles that draw the two-tone ring INSIDE a box (the tablist clips to rounded corners, so an
 * outside ring would be cut off). The outer 2 px ring is an outline, which forced-colors mode
 * keeps; the inner 2 px ring is an inset shadow beneath it. Because the two rings differ, a
 * ring is visible on any fill: at least one of them contrasts with it.
 */
export const twoToneFocusInside = {
  outlineStyle: "solid",
  outlineWidth: "2px",
  outlineColor: EVTX_FOCUS_RING.outer,
  outlineOffset: "-2px",
  boxShadow: `inset 0 0 0 4px ${EVTX_FOCUS_RING.inner}`,
} as const;

export interface TextState {
  foreground: string;
  background: string;
}

/** Inactive Layout tab states. Active tabs use `evtxActiveTextColor` on the selected surface. */
export const LAYOUT_TAB_STATES: Record<"rest" | "hover" | "pressed", TextState> = {
  rest: {
    foreground: tokens.colorNeutralForeground2,
    background: tokens.colorNeutralBackground1,
  },
  hover: {
    foreground: tokens.colorNeutralForeground2Hover,
    background: tokens.colorNeutralBackground1Hover,
  },
  pressed: {
    foreground: tokens.colorNeutralForeground2Pressed,
    background: tokens.colorNeutralBackground1Pressed,
  },
};

/** Surfaces a focus ring can sit on in Phase 3 (tab and toggle states, bar and region fills). */
export const FOCUS_SURFACES: Record<string, string> = {
  bar: tokens.colorNeutralBackground1,
  region: tokens.colorNeutralBackground2,
  hover: tokens.colorNeutralBackground1Hover,
  pressed: tokens.colorNeutralBackground1Pressed,
  selected: tokens.colorNeutralBackground1Selected,
};
