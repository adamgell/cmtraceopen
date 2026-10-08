/** WCAG AA minimum contrast for normal-size text. */
export const WCAG_AA_NORMAL_TEXT = 4.5;

const BLACK = "#000000";
const WHITE = "#ffffff";

function channelToLinear(channel: number): number {
  const value = channel / 255;
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance(hex: string): number {
  const digits = hex.replace("#", "");
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
 * brand color (hotdog-stand), so those fall back to whichever of black and
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
