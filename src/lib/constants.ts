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

  /** Fixed 8-color palette for merge tab / section identification (OQ-2). */
  mergeColors: [string, string, string, string, string, string, string, string];

  /** Semi-transparent overlay color for WhatIf badge background (OQ-3). */
  whatifOverlay: string;
  /** Opaque text color for WhatIf badges (OQ-3). */
  whatifText: string;

  /** Status indicator colors for collection dialogs and similar (OQ-4). */
  status: {
    success: { foreground: string; background: string };
    warning: { foreground: string; background: string };
    error: { foreground: string; background: string };
  };
}

/** Default update interval in ms (minimum 500, from string table ID=37) */
export const DEFAULT_UPDATE_INTERVAL_MS = 500;
