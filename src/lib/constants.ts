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

/** Default update interval in ms (minimum 500, from string table ID=37) */
export const DEFAULT_UPDATE_INTERVAL_MS = 500;
