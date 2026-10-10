// Types
export type { ThemeId, ColorScheme, CMTraceTheme } from "./types";

// Shared design tokens (non-color)
export { sharedOverrides } from "./shared-overrides";

// Brand color ramps
export {
  tealBrand,
  steelBrand,
  cyanBrand,
  frostBrand,
  purpleBrand,
} from "./brand-ramps";

// Severity palettes
export { themeSeverityPalettes } from "./palettes";

// Individual themes
export { lightTheme } from "./theme-light";
export { darkTheme } from "./theme-dark";
export { highContrastTheme } from "./theme-high-contrast";
export { classicCmtraceTheme } from "./theme-classic-cmtrace";
export { solarizedDarkTheme } from "./theme-solarized-dark";
export { nordTheme } from "./theme-nord";
export { draculaTheme } from "./theme-dracula";

// Registry (lookup + enumeration)
export { DEFAULT_THEME_ID, getThemeById, getAllThemes } from "./registry";
