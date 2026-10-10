import type { ThemeId, CMTraceTheme } from "./types";
import { lightTheme } from "./theme-light";
import { darkTheme } from "./theme-dark";
import { highContrastTheme } from "./theme-high-contrast";
import { classicCmtraceTheme } from "./theme-classic-cmtrace";
import { solarizedDarkTheme } from "./theme-solarized-dark";
import { nordTheme } from "./theme-nord";
import { draculaTheme } from "./theme-dracula";

export const DEFAULT_THEME_ID: ThemeId = "light";

const themeRegistry = new Map<ThemeId, CMTraceTheme>([
  ["light", lightTheme],
  ["dark", darkTheme],
  ["high-contrast", highContrastTheme],
  ["classic-cmtrace", classicCmtraceTheme],
  ["solarized-dark", solarizedDarkTheme],
  ["nord", nordTheme],
  ["dracula", draculaTheme],
]);

export function getThemeById(id: ThemeId): CMTraceTheme {
  return themeRegistry.get(id) ?? themeRegistry.get(DEFAULT_THEME_ID)!;
}

export function getAllThemes(): CMTraceTheme[] {
  return Array.from(themeRegistry.values());
}
