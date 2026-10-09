/**
 * The single color and icon map for the Event Logs workspace (spec sections
 * 6 and 7.3). Components read every color from here and never index a
 * palette or write a color literal themselves.
 *
 * Values are CSS colors: Fluent token references (`var(--…)`), hex entries of
 * the active theme's severity palette, or `color-mix()` expressions, so they
 * follow all eight themes. Canvas and SVG consumers cannot read `var()` or
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
import type { LogSeverityPalette } from "../../lib/constants";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import type { DiagnosisCorrelationStatus, EvtxLevel } from "./types";

export interface EvtxLevelVisual {
  /** Level name, used as the icon's accessible label. */
  label: EvtxLevel;
  /** Histogram bars and level-filter fills (drawn on the surface, never a row tint). */
  barColor: string;
  /** 8px severity dots. */
  dotColor: string;
  /** Icon on the level's row tint; falls back to black or white when the mark lacks 3:1 there. */
  iconColor: string;
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

export interface EvtxSelectionVisual {
  background: string;
  border: string;
  foreground: string;
}

export interface EvtxVisualTokens {
  levels: Record<EvtxLevel, EvtxLevelVisual>;
  strengths: Record<DiagnosisCorrelationStatus, EvtxBadgeVisual>;
  /** Selected row, chain, view card and active brushed-time chip (Q-1). */
  selection: EvtxSelectionVisual;
  /** Error finding callouts in the rail. */
  findingCallout: EvtxSelectionVisual;
  /** Color for the channel at `index` in channel display order. */
  channelColor: (index: number) => string;
  /** Heat-map fills, lightest first (Q-3 interim, no ramp token yet). */
  heatSteps: readonly string[];
  /** Bars of single-series charts (top IDs, crashes per day). */
  singleSeries: string;
  /** v2 scenario states. */
  scenario: {
    succeeded: { bar: string; foreground: string; background: string };
    running: string;
    retrying: string;
    sleep: string;
    notStarted: { stroke: string; background: string };
  };
}

const HEAT_STEP_PERCENTAGES = [15, 30, 45, 60, 75, 90] as const;

export function buildEvtxVisualTokens(
  palette: LogSeverityPalette,
): EvtxVisualTokens {
  const { eventLog } = palette;
  const plainRow = {
    rowBackground: tokens.colorNeutralBackground1,
    rowText: tokens.colorNeutralForeground1,
  };

  return {
    levels: {
      Critical: {
        label: "Critical",
        barColor: eventLog.critical,
        dotColor: eventLog.critical,
        iconColor: readableOn(palette.error.background, eventLog.critical),
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
        ...plainRow,
        GridIcon: Circle12Regular,
        RailIcon: Circle16Regular,
      },
    },
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
        foreground: palette.warning.text,
        border: tokens.colorPaletteMarigoldBorder2,
        borderStyle: "solid",
      },
      // Foreground and border use Foreground3 rather than Foreground2 or
      // StrokeAccessible: in hotdog-stand those two resolve to pure yellow, the
      // error text color, which would read as a failure state.
      // The spec names the label and icon but no colors. A coverage gap is
      // neither success nor failure, so it stays neutral, with the icon
      // carrying the meaning. Its own solid border keeps it from
      // being mistaken for Candidate (dashed) or Not linked (dotted).
      coverageBlocked: {
        label: "Coverage blocked",
        background: tokens.colorNeutralBackground1,
        foreground: tokens.colorNeutralForeground3,
        border: tokens.colorNeutralForeground3,
        borderStyle: "solid",
        Icon: PlugDisconnected16Regular,
      },
      notCausal: {
        label: "Not linked",
        background: tokens.colorNeutralBackground1,
        foreground: tokens.colorNeutralForeground3,
        border: tokens.colorNeutralForeground3,
        borderStyle: "dotted",
      },
    },
    selection: {
      background: tokens.colorPaletteBlueBackground2,
      border: tokens.colorPaletteBlueBorderActive,
      foreground: tokens.colorPaletteBlueForeground2,
    },
    findingCallout: {
      background: palette.error.background,
      border: tokens.colorPaletteRedBorder2,
      foreground: palette.error.text,
    },
    channelColor: (index) =>
      eventLog.channels[index % eventLog.channels.length],
    heatSteps: HEAT_STEP_PERCENTAGES.map(
      (percent) =>
        `color-mix(in srgb, ${palette.mergeColors[0]} ${percent}%, ${tokens.colorNeutralBackground1})`,
    ),
    singleSeries: palette.mergeColors[0],
    scenario: {
      succeeded: {
        bar: tokens.colorPaletteGreenBackground3,
        foreground: palette.status.success.foreground,
        background: tokens.colorPaletteGreenBackground1,
      },
      running: tokens.colorPaletteBlueBorderActive,
      retrying: tokens.colorPaletteBlueBorderActive,
      sleep: tokens.colorPaletteBlueBackground2,
      notStarted: {
        stroke: tokens.colorNeutralStroke2,
        background: tokens.colorNeutralBackground3,
      },
    },
  };
}

/** Event Logs visual tokens for the active theme. */
export function useEvtxVisualTokens(): EvtxVisualTokens {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(
    () => buildEvtxVisualTokens(getThemeById(themeId).severityPalette),
    [themeId],
  );
}
