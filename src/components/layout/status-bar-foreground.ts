import { useMemo } from "react";
import { readableOn } from "../../lib/color-contrast";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";

/**
 * Foreground for text and icons on the status bar's brand background.
 *
 * The theme's own on-brand foreground wins when it already meets AA. Some
 * themes do not (solarized-dark, nord, classic-cmtrace) or set it equal to the
 * brand color, so those fall back to whichever of black and white contrasts
 * more. Delegates to `readableOn` at the 4.5:1 WCAG AA text threshold.
 */
export function pickStatusBarForeground(
  brandBackground: string,
  onBrandForeground: string,
): string {
  return readableOn(brandBackground, onBrandForeground, 4.5);
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
