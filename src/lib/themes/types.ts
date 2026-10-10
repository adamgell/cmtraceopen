import type { Theme } from "@fluentui/react-components";
import type { LogSeverityPalette } from "../constants";

export type ThemeId =
  | "light"
  | "dark"
  | "high-contrast"
  | "classic-cmtrace"
  | "solarized-dark"
  | "nord"
  | "dracula";

export type ColorScheme = "light" | "dark";

export interface CMTraceTheme {
  id: ThemeId;
  label: string;
  colorScheme: ColorScheme;
  fluentTheme: Theme;
  severityPalette: LogSeverityPalette;
  swatchColor: string;
}
