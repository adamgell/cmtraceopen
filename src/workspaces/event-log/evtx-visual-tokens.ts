/**
 * The single color and icon map for the Event Logs workspace (spec sections
 * 6 and 7.3). Components read every color from here and never index a
 * palette or write a color literal themselves.
 *
 * Values are CSS colors: Fluent token references (`var(--…)`), hex entries of
 * the active theme's severity palette, or `color-mix()` expressions, so they
 * follow every theme. Canvas and SVG consumers cannot read `var()` or
 * `color-mix()` directly and must resolve these strings themselves.
 *
 * Level marks and channel colors come from the theme's `eventLog` semantic
 * tokens, not from the Fluent palette tokens named in spec section 6.3
 * (spec Q-17 and D22): those Fluent tokens collapse to the same color in
 * high-contrast and nearly match in the dark themes.
 */
import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import {
  Circle12Regular,
  Circle16Regular,
  DismissCircle12Regular,
  DismissCircle16Regular,
  ErrorCircle12Regular,
  ErrorCircle16Regular,
  Info12Regular,
  Info16Regular,
  PlugDisconnected16Regular,
  Warning12Regular,
  Warning16Regular,
  type FluentIcon,
} from "@fluentui/react-icons";
import { readableOn } from "../../lib/color-contrast";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import type {
  DiagnosisCorrelationStatus,
  DiagnosisFindingSeverity,
  EvtxLevel,
} from "./types";

export interface EvtxLevelVisual {
  /** Level name, used as the icon's accessible label. */
  label: EvtxLevel;
  /** Histogram bars and level-filter fills (drawn on the surface, never a row tint). */
  barColor: string;
  /** 8px severity dots. Drawn on the surface or the rail, never on a row tint. */
  dotColor: string;
  /**
   * Grid icon on the level's own row tint. Falls back to black or white when
   * the mark lacks 3:1 there.
   */
  iconColor: string;
  /**
   * Grid icon on a selected row. Selection replaces the tint with the
   * selection background, so this is the selection foreground (4.5:1 on that
   * background). The icon shape and its aria-label carry the level.
   */
  selectedIconColor: string;
  /**
   * The level word or count drawn as text off the row tint: finding-card
   * eyebrow (8.13) and Details level word (8.13) for every level, plus the
   * 8.6 err and warn counts and the 8.3 grammar error (which uses
   * `levels.Warning.textColor`). Critical, Error and Warning reach 4.5:1 on
   * Background1, Background2 and the selection background; Information and
   * Verbose are neutral grays used on Background1 and Background2 only (8.13).
   * Deviates from spec 8.6, which names status.error.foreground and
   * warning.text for the counts: those measure 2.19:1 on the solarized-dark
   * selection background and 2.46:1 on the nord rail. Not for text on the row
   * tint; that pairing is `rowText`.
   */
  textColor: string;
  /** Rail icon, drawn on colorNeutralBackground2. Same as the mark. */
  railIconColor: string;
  rowBackground: string;
  rowText: string;
  /** 12px icon for grid cells. */
  GridIcon: FluentIcon;
  /** 16px icon for the insights rail. */
  RailIcon: FluentIcon;
}

export interface EvtxBadgeVisual {
  label: string;
  background: string;
  foreground: string;
  border: string;
  borderStyle: "solid" | "dashed" | "dotted";
  Icon?: FluentIcon;
}

export interface EvtxColorTriplet {
  background: string;
  border: string;
  foreground: string;
}

export interface EvtxVisualTokens {
  levels: Record<EvtxLevel, EvtxLevelVisual>;
  strengths: Record<DiagnosisCorrelationStatus, EvtxBadgeVisual>;
  /** Selected row, chain, view card and active brushed-time chip (Q-1). */
  selection: EvtxColorTriplet;
  /** Error finding callouts in the rail. */
  findingCallout: EvtxColorTriplet;
  /**
   * The level visual for a diagnosis finding severity (8.13 finding cards),
   * so consumers do not map severities themselves.
   */
  findingSeverityVisual: (
    severity: DiagnosisFindingSeverity,
  ) => EvtxLevelVisual;
  /** Color for the channel at `index` in channel display order. */
  channelColor: (index: number) => string;
  /**
   * 1px outline for any dot, swatch or similar small mark drawn on a
   * non-neutral background. The context names that background: a level (its
   * row tint, 8.7) returns the level's `iconColor`; "selected" (the selection
   * background: selected grid row, channel pane row, chain row or card)
   * returns `selectedIconColor`; "pressed" (`colorNeutralBackground1Selected`,
   * pressed level toggles in 8.3 and 6.2) returns the active-toggle text token
   * `colorBrandForeground1`, resolved per theme: high-contrast inverts
   * polarity on pressed toggles (white on cyan), so there the black or white
   * fallback is returned instead of the brand foreground. Fills are not guaranteed 3:1 on those
   * backgrounds, so such marks must draw this outline.
   */
  markOutline: (context: EvtxLevel | "selected" | "pressed") => string;
  /**
   * Thin data lines (sparklines) on a selected row cannot carry an outline;
   * they use the selection foreground, 3:1 or better on the selection
   * background (8.6 selected channel rows).
   */
  selectedDataColor: string;
  /** Heat-map fills, faintest first (Q-3 interim, no ramp token yet). */
  heatSteps: readonly string[];
  /** Bars of single-series charts (top IDs, crashes per day). */
  singleSeries: string;
  /**
   * The 8.1 live source pill (v1, not a v2 scenario state). `foreground`
   * colors the label and the 7px dot and is the theme's `eventLog.live`.
   * `border` is decorative: the label identifies the pill, so it carries no
   * contrast floor (INVENTORY_EXEMPTIONS). Spec 8.1 names
   * colorPaletteGreenBackground3 for it. Measured:
   * against the pill fill it is 3.07 to 21.00:1 (3.07 in every theme but
   * light and classic 5.03 and high-contrast 21.00); against the toolbar
   * that hosts the pill (colorNeutralBackground2, Toolbar.tsx) it is 1.87
   * (nord) to 21.00:1, with solarized-dark 2.42, dracula 2.94, dark 3.07,
   * light 5.14 and classic 5.05.
   */
  liveSource: EvtxColorTriplet;
}

const FINDING_SEVERITY_LEVEL: Record<DiagnosisFindingSeverity, EvtxLevel> = {
  info: "Information",
  warning: "Warning",
  error: "Error",
  critical: "Critical",
};

const HEAT_STEP_PERCENTAGES = [15, 30, 45, 60, 75, 90] as const;

/**
 * Resolves a Fluent token value (`var(--name)`) to its hex in this theme,
 * else returns the value unchanged. Used only where a `readableOn` decision
 * needs a concrete background.
 */
export function resolveToken(value: string, theme: CMTraceTheme): string {
  const match = /^var\(\s*--([\w-]+)\s*(?:,[^)]*)?\)$/.exec(value.trim());
  if (!match) return value;
  const resolved = (theme.fluentTheme as unknown as Record<string, string>)[
    match[1]
  ];
  if (typeof resolved !== "string") {
    throw new Error(`Unknown Fluent token ${match[1]} in theme ${theme.id}`);
  }
  return resolved;
}

export function buildEvtxVisualTokens(theme: CMTraceTheme): EvtxVisualTokens {
  const palette = theme.severityPalette;
  const { eventLog } = palette;
  const selection: EvtxColorTriplet = {
    background: tokens.colorPaletteBlueBackground2,
    border: tokens.colorPaletteBlueBorderActive,
    foreground: tokens.colorPaletteBlueForeground2,
  };
  const plainRow = {
    rowBackground: tokens.colorNeutralBackground1,
    rowText: tokens.colorNeutralForeground1,
  };

  const levels: Record<EvtxLevel, EvtxLevelVisual> = {
    Critical: {
      label: "Critical",
      barColor: eventLog.critical,
      dotColor: eventLog.critical,
      iconColor: readableOn(palette.error.background, eventLog.critical),
      selectedIconColor: selection.foreground,
      railIconColor: eventLog.critical,
      textColor: eventLog.text.critical,
      rowBackground: palette.error.background,
      rowText: palette.error.text,
      GridIcon: DismissCircle12Regular,
      RailIcon: DismissCircle16Regular,
    },
    Error: {
      label: "Error",
      barColor: eventLog.error,
      dotColor: eventLog.error,
      iconColor: readableOn(palette.error.background, eventLog.error),
      selectedIconColor: selection.foreground,
      railIconColor: eventLog.error,
      textColor: eventLog.text.error,
      rowBackground: palette.error.background,
      rowText: palette.error.text,
      GridIcon: ErrorCircle12Regular,
      RailIcon: ErrorCircle16Regular,
    },
    Warning: {
      label: "Warning",
      barColor: eventLog.warning,
      dotColor: eventLog.warning,
      iconColor: readableOn(palette.warning.background, eventLog.warning),
      selectedIconColor: selection.foreground,
      railIconColor: eventLog.warning,
      textColor: eventLog.text.warning,
      rowBackground: palette.warning.background,
      rowText: palette.warning.text,
      GridIcon: Warning12Regular,
      RailIcon: Warning16Regular,
    },
    Information: {
      label: "Information",
      barColor: eventLog.information,
      dotColor: eventLog.information,
      iconColor: eventLog.information,
      selectedIconColor: selection.foreground,
      railIconColor: eventLog.information,
      textColor: eventLog.text.information,
      ...plainRow,
      GridIcon: Info12Regular,
      RailIcon: Info16Regular,
    },
    // The spec gives Verbose an icon but no colors. Its mark comes from the
    // theme's eventLog.verbose neutral; like Information it is untinted (D3).
    Verbose: {
      label: "Verbose",
      barColor: eventLog.verbose,
      dotColor: eventLog.verbose,
      iconColor: eventLog.verbose,
      selectedIconColor: selection.foreground,
      railIconColor: eventLog.verbose,
      textColor: eventLog.text.verbose,
      ...plainRow,
      GridIcon: Circle12Regular,
      RailIcon: Circle16Regular,
    },
  };

  return {
    levels,
    strengths: {
      exact: {
        label: "Exact",
        background: tokens.colorPaletteBlueBackground2,
        foreground: tokens.colorPaletteBlueForeground2,
        border: tokens.colorPaletteBlueBorderActive,
        borderStyle: "solid",
      },
      candidate: {
        label: "Candidate",
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralForeground2,
        borderStyle: "dashed",
      },
      ambiguous: {
        label: "Ambiguous",
        background: palette.warning.background,
        // Deviates from spec 6.3 (palette.warning.text label): in
        // solarized-dark that pair is 4.05:1 on the badge, so the label falls
        // back to black or white when it misses 4.5:1.
        foreground: readableOn(
          palette.warning.background,
          palette.warning.text,
          4.5,
        ),
        // Deviates from spec 6.3 (colorPaletteMarigoldBorder2): that token is
        // 2.16:1 on the light surface; the warning text color reaches 3:1.
        border: palette.warning.text,
        borderStyle: "solid",
      },
      // The spec names the label and icon but no colors. A coverage gap is
      // neither success nor failure, so it stays neutral, with the icon
      // carrying the meaning. Its solid accessible border keeps it from being
      // mistaken for Candidate (dashed) or Not linked (dotted). Background3
      // plus Foreground2 keep the label at 4.5:1 in every theme; on a surface
      // background the label drops below that in dracula and solarized.
      coverageBlocked: {
        label: "Coverage blocked",
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralStrokeAccessible,
        borderStyle: "solid",
        Icon: PlugDisconnected16Regular,
      },
      notCausal: {
        label: "Not linked",
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        // Deviates from spec 6.3 (colorNeutralForeground3): that token is
        // 2.92:1 on the solarized-dark rail and 2.16 to 2.28:1 on the
        // selection background; the accessible stroke reaches 3:1 on every
        // surface the badge sits on. The dotted style still marks the state.
        border: tokens.colorNeutralStrokeAccessible,
        borderStyle: "dotted",
      },
    },
    findingSeverityVisual: (severity) =>
      levels[FINDING_SEVERITY_LEVEL[severity]],
    selection,
    findingCallout: {
      background: palette.error.background,
      border: tokens.colorPaletteRedBorder2,
      foreground: palette.error.text,
    },
    channelColor: (index) => {
      const count = eventLog.channels.length;
      return eventLog.channels[((index % count) + count) % count];
    },
    markOutline: (context) => {
      // Every level shares selectedIconColor (the selection foreground).
      if (context === "selected") return selection.foreground;
      if (context === "pressed") {
        return readableOn(
          resolveToken(tokens.colorNeutralBackground1Selected, theme),
          resolveToken(tokens.colorBrandForeground1, theme),
        );
      }
      return levels[context].iconColor;
    },
    selectedDataColor: selection.foreground,
    heatSteps: HEAT_STEP_PERCENTAGES.map(
      (percent) =>
        `color-mix(in srgb, ${palette.mergeColors[0]} ${percent}%, ${tokens.colorNeutralBackground1})`,
    ),
    singleSeries: palette.mergeColors[0],
    liveSource: {
      background: tokens.colorPaletteGreenBackground1,
      border: tokens.colorPaletteGreenBackground3,
      foreground: eventLog.live,
    },
  };
}

/** Event Logs visual tokens for the active theme. */
export function useEvtxVisualTokens(): EvtxVisualTokens {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => buildEvtxVisualTokens(getThemeById(themeId)), [themeId]);
}
