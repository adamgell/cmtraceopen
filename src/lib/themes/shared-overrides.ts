import type { Theme } from "@fluentui/react-components";

/**
 * Non-color design tokens shared across every CMTrace theme.
 * Extracted from the original fluent-theme.ts so all themes
 * get identical border radii, typography, spacing, motion, and shadows.
 */
export const sharedOverrides: Partial<Theme> = {
  // ── Border radii ──────────────────────────────────────────────
  borderRadiusNone: "0",
  borderRadiusSmall: "2px",
  borderRadiusMedium: "4px",
  borderRadiusLarge: "6px",
  borderRadiusXLarge: "8px",
  borderRadius2XLarge: "12px",
  borderRadius3XLarge: "16px",
  borderRadius4XLarge: "24px",
  borderRadius5XLarge: "32px",
  borderRadius6XLarge: "40px",
  borderRadiusCircular: "10000px",

  // ── Font sizes ────────────────────────────────────────────────
  fontSizeBase100: "10px",
  fontSizeBase200: "12px",
  fontSizeBase300: "14px",
  fontSizeBase400: "16px",
  fontSizeBase500: "20px",
  fontSizeBase600: "24px",
  fontSizeHero700: "28px",
  fontSizeHero800: "32px",
  fontSizeHero900: "40px",
  fontSizeHero1000: "68px",

  // ── Line heights ──────────────────────────────────────────────
  lineHeightBase100: "14px",
  lineHeightBase200: "16px",
  lineHeightBase300: "20px",
  lineHeightBase400: "22px",
  lineHeightBase500: "28px",
  lineHeightBase600: "32px",
  lineHeightHero700: "36px",
  lineHeightHero800: "40px",
  lineHeightHero900: "52px",
  lineHeightHero1000: "92px",

  // ── Font families ─────────────────────────────────────────────
  fontFamilyBase:
    "var(--cmtrace-font-family-ui, 'Segoe UI', 'Segoe UI Web (West European)', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif)",
  fontFamilyMonospace:
    "var(--cmtrace-font-family-mono, Consolas, 'Courier New', Courier, monospace)",
  fontFamilyNumeric:
    "var(--cmtrace-font-family-ui, Bahnschrift, 'Segoe UI', 'Segoe UI Web (West European)', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif)",

  // ── Font weights ──────────────────────────────────────────────
  fontWeightRegular: 400,
  fontWeightMedium: 500,
  fontWeightSemibold: 600,
  fontWeightBold: 700,

  // ── Stroke widths ─────────────────────────────────────────────
  strokeWidthThin: "1px",
  strokeWidthThick: "2px",
  strokeWidthThicker: "3px",
  strokeWidthThickest: "4px",

  // ── Spacing (horizontal) ──────────────────────────────────────
  spacingHorizontalNone: "0",
  spacingHorizontalXXS: "2px",
  spacingHorizontalXS: "4px",
  spacingHorizontalSNudge: "6px",
  spacingHorizontalS: "8px",
  spacingHorizontalMNudge: "10px",
  spacingHorizontalM: "12px",
  spacingHorizontalL: "16px",
  spacingHorizontalXL: "20px",
  spacingHorizontalXXL: "24px",
  spacingHorizontalXXXL: "32px",

  // ── Spacing (vertical) ────────────────────────────────────────
  spacingVerticalNone: "0",
  spacingVerticalXXS: "2px",
  spacingVerticalXS: "4px",
  spacingVerticalSNudge: "6px",
  spacingVerticalS: "8px",
  spacingVerticalMNudge: "10px",
  spacingVerticalM: "12px",
  spacingVerticalL: "16px",
  spacingVerticalXL: "20px",
  spacingVerticalXXL: "24px",
  spacingVerticalXXXL: "32px",

  // ── Durations ─────────────────────────────────────────────────
  durationUltraFast: "50ms",
  durationFaster: "100ms",
  durationFast: "150ms",
  durationNormal: "200ms",
  durationGentle: "250ms",
  durationSlow: "300ms",
  durationSlower: "400ms",
  durationUltraSlow: "500ms",

  // ── Curves ────────────────────────────────────────────────────
  curveAccelerateMax: "cubic-bezier(0.9,0.1,1,0.2)",
  curveAccelerateMid: "cubic-bezier(1,0,1,1)",
  curveAccelerateMin: "cubic-bezier(0.8,0,0.78,1)",
  curveDecelerateMax: "cubic-bezier(0.1,0.9,0.2,1)",
  curveDecelerateMid: "cubic-bezier(0,0,0,1)",
  curveDecelerateMin: "cubic-bezier(0.33,0,0.1,1)",
  curveEasyEaseMax: "cubic-bezier(0.8,0,0.2,1)",
  curveEasyEase: "cubic-bezier(0.33,0,0.67,1)",
  curveLinear: "cubic-bezier(0,0,1,1)",

  // ── Shadows ───────────────────────────────────────────────────
  shadow2: "0 0 2px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.14)",
  shadow4: "0 0 2px rgba(0,0,0,0.12), 0 2px 4px rgba(0,0,0,0.14)",
  shadow8: "0 0 2px rgba(0,0,0,0.12), 0 4px 8px rgba(0,0,0,0.14)",
  shadow16: "0 0 2px rgba(0,0,0,0.12), 0 8px 16px rgba(0,0,0,0.14)",
  shadow28: "0 0 8px rgba(0,0,0,0.12), 0 14px 28px rgba(0,0,0,0.14)",
  shadow64: "0 0 8px rgba(0,0,0,0.12), 0 32px 64px rgba(0,0,0,0.14)",
  shadow2Brand: "0 0 2px rgba(0,0,0,0.30), 0 1px 2px rgba(0,0,0,0.25)",
  shadow4Brand: "0 0 2px rgba(0,0,0,0.30), 0 2px 4px rgba(0,0,0,0.25)",
  shadow8Brand: "0 0 2px rgba(0,0,0,0.30), 0 4px 8px rgba(0,0,0,0.25)",
  shadow16Brand: "0 0 2px rgba(0,0,0,0.30), 0 8px 16px rgba(0,0,0,0.25)",
  shadow28Brand: "0 0 8px rgba(0,0,0,0.30), 0 14px 28px rgba(0,0,0,0.25)",
  shadow64Brand: "0 0 8px rgba(0,0,0,0.30), 0 32px 64px rgba(0,0,0,0.25)",
};
