export type LogSeverityPaletteMode = "classic" | "accessible";

export interface LogSeverityPalette {
  error: {
    background: string;
    text: string;
  };
  warning: {
    background: string;
    text: string;
  };
  info: {
    background: string;
    text: string;
  };
  highlightDefault: string;
}

/** Color rules extracted from CMTrace binary */
const LOG_SEVERITY_PALETTES: Record<LogSeverityPaletteMode, LogSeverityPalette> = {
  classic: {
    error: {
      background: "#FF0000",
      text: "#FFFF00",
    },
    warning: {
      background: "#FFFF00",
      text: "#000000",
    },
    info: {
      background: "#FFFFFF",
      text: "#000000",
    },
    highlightDefault: "#FFFF00",
  },
  accessible: {
    error: {
      background: "#FEE2E2",
      text: "#7F1D1D",
    },
    warning: {
      background: "#FEF3C7",
      text: "#78350F",
    },
    info: {
      background: "#FFFFFF",
      text: "#111827",
    },
    highlightDefault: "#FDE68A",
  },
};

export const COLORS = LOG_SEVERITY_PALETTES.classic;

export function getLogSeverityPalette(
  mode: LogSeverityPaletteMode
): LogSeverityPalette {
  const palette = LOG_SEVERITY_PALETTES[mode];
  return palette ?? LOG_SEVERITY_PALETTES.classic;
}

/** Default update interval in ms (minimum 500, from string table ID=37) */
export const DEFAULT_UPDATE_INTERVAL_MS = 500;

/** Column names from string table IDs 2-5 */
export const COLUMN_NAMES = {
  logText: "Log Text",
  component: "Component",
  dateTime: "Date/Time",
  thread: "Thread",
} as const;

export const LOG_VIEW_COLUMN_WIDTHS = {
  component: 180,
  dateTime: 200,
  thread: 120,
} as const;

export function getLogViewGridTemplateColumns(showDetails: boolean): string {
  if (!showDetails) {
    return "minmax(0, 1fr)";
  }

  return [
    "minmax(0, 1fr)",
    `${LOG_VIEW_COLUMN_WIDTHS.component}px`,
    `${LOG_VIEW_COLUMN_WIDTHS.dateTime}px`,
    `${LOG_VIEW_COLUMN_WIDTHS.thread}px`,
  ].join(" ");
}
