import { useMemo } from "react";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";

/** WCAG AA minimum contrast for normal-size text. */
export const WCAG_AA_NORMAL_TEXT = 4.5;

const BLACK = "#000000";
const WHITE = "#ffffff";

function channelToLinear(channel: number): number {
  const value = channel / 255;
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

const HEX_COLOR = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;

function relativeLuminance(hex: string): number {
  // Theme tokens are expected to be plain hex. Anything else would parse to
  // NaN and silently pick a foreground, so fail loudly instead; the per-theme
  // contrast test turns that into a CI failure.
  if (!HEX_COLOR.test(hex)) {
    throw new Error(`Expected a #rgb or #rrggbb color, got "${hex}"`);
  }
  const digits = hex.slice(1);
  const full =
    digits.length === 3
      ? digits
          .split("")
          .map((digit) => digit + digit)
          .join("")
      : digits;
  const r = parseInt(full.slice(0, 2), 16);
  const g = parseInt(full.slice(2, 4), 16);
  const b = parseInt(full.slice(4, 6), 16);
  return (
    0.2126 * channelToLinear(r) +
    0.7152 * channelToLinear(g) +
    0.0722 * channelToLinear(b)
  );
}

/** WCAG 2.x contrast ratio between two `#rgb` / `#rrggbb` colors. */
export function contrastRatio(foreground: string, background: string): number {
  const a = relativeLuminance(foreground);
  const b = relativeLuminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/**
 * Foreground for text and icons on the status bar's brand background.
 *
 * The theme's own on-brand foreground wins when it already meets AA. Some
 * themes do not (solarized-dark, nord, classic-cmtrace) or set it equal to the
 * brand color, so those fall back to whichever of black and
 * white contrasts more.
 */
export function pickStatusBarForeground(
  brandBackground: string,
  onBrandForeground: string,
): string {
  if (
    contrastRatio(onBrandForeground, brandBackground) >= WCAG_AA_NORMAL_TEXT
  ) {
    return onBrandForeground;
  }

  return contrastRatio(BLACK, brandBackground) >=
    contrastRatio(WHITE, brandBackground)
    ? BLACK
    : WHITE;
}

/** The status bar foreground for the active theme. */
export function useStatusBarForeground(): string {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => {
    const fluent = getThemeById(themeId).fluentTheme;
    return pickStatusBarForeground(
      fluent.colorBrandBackground as string,
      fluent.colorNeutralForegroundOnBrand as string,
    );
  }, [themeId]);
}
