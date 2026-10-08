/**
 * The single color and icon map for the Event Logs workspace (spec sections
 * 6 and 7.3). Components read every color from here and never index a
 * palette or write a color literal themselves.
 *
 * Values are Fluent token references (`var(--…)`) or entries of the active
 * theme's severity palette, so they follow all eight themes. Canvas and SVG
 * drawing that needs resolved strings resolves them once per theme change.
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
import type { LogSeverityPalette } from "../../lib/constants";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import type { DiagnosisCorrelationStatus, EvtxLevel } from "./types";

export interface EvtxLevelVisual {
  /** Level name, used as the icon's accessible label. */
  label: EvtxLevel;
  /** Histogram bars and level-filter fills. */
  barColor: string;
  /** 8px severity dots. */
  dotColor: string;
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

/**
 * Merge palette indices used for channels, in assignment order. Indices 1
 * (red) and 2 (green) are skipped so a channel never reads as a severity
 * (spec D10).
 */
export const CHANNEL_MERGE_COLOR_INDICES = [0, 4, 5, 3, 6, 7] as const;

const HEAT_STEP_PERCENTAGES = [15, 30, 45, 60, 75, 90] as const;

export function buildEvtxVisualTokens(
  palette: LogSeverityPalette,
): EvtxVisualTokens {
  const plainRow = {
    rowBackground: tokens.colorNeutralBackground1,
    rowText: tokens.colorNeutralForeground1,
  };

  return {
    levels: {
      Critical: {
        label: "Critical",
        barColor: tokens.colorPaletteDarkRedBorderActive,
        dotColor: tokens.colorPaletteDarkRedBorderActive,
        iconColor: tokens.colorPaletteDarkRedBorderActive,
        rowBackground: palette.error.background,
        rowText: palette.error.text,
        GridIcon: DismissCircle12Regular,
        RailIcon: DismissCircle16Regular,
      },
      Error: {
        label: "Error",
        barColor: tokens.colorPaletteRedBackground3,
        dotColor: tokens.colorPaletteRedBackground3,
        iconColor: palette.status.error.foreground,
        rowBackground: palette.error.background,
        rowText: palette.error.text,
        GridIcon: ErrorCircle12Regular,
        RailIcon: ErrorCircle16Regular,
      },
      Warning: {
        label: "Warning",
        barColor: tokens.colorPaletteMarigoldBackground3,
        dotColor: tokens.colorPaletteMarigoldBackground3,
        iconColor: palette.status.warning.foreground,
        rowBackground: palette.warning.background,
        rowText: palette.warning.text,
        GridIcon: Warning12Regular,
        RailIcon: Warning16Regular,
      },
      Information: {
        label: "Information",
        barColor: tokens.colorNeutralStroke1,
        dotColor: tokens.colorNeutralForeground4,
        iconColor: tokens.colorNeutralForeground3,
        ...plainRow,
        GridIcon: Info12Regular,
        RailIcon: Info16Regular,
      },
      // The spec gives Verbose an icon but no colors. It shares Information's
      // neutrals: it is the lowest rank and, like Information, untinted (D3).
      Verbose: {
        label: "Verbose",
        barColor: tokens.colorNeutralStroke1,
        dotColor: tokens.colorNeutralForeground4,
        iconColor: tokens.colorNeutralForeground3,
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
      // The spec names the label and icon but no colors. A coverage gap is
      // neither success nor failure, so it stays neutral and dashed, with
      // the icon carrying the meaning.
      coverageBlocked: {
        label: "Coverage blocked",
        background: tokens.colorNeutralBackground1,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralStroke1,
        borderStyle: "dashed",
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
      palette.mergeColors[
        CHANNEL_MERGE_COLOR_INDICES[index % CHANNEL_MERGE_COLOR_INDICES.length]
      ],
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
