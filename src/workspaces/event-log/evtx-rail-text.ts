/**
 * Text colors for what the rail draws directly on `colorNeutralBackground2`, its own surface.
 *
 * The designed colors are Foreground1 and Foreground3, but on that surface Foreground1 measures
 * 4.11:1 in solarized-dark, and Foreground3 measures 2.92:1 there and 3.36:1 in dracula, under the
 * 4.5:1 text floor. Where a designed color misses, Foreground2 stands in (4.86:1 on solarized-dark,
 * 14.81:1 on dracula). The decision reads each theme's own token values, so a theme that passes is
 * untouched, and no token value changes.
 */
import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { contrastRatio } from "../../lib/color-contrast";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";

const TEXT_FLOOR = 4.5;

export interface RailTextColors {
  /** Headlines and values: Foreground1, or Foreground2 where Foreground1 misses the floor. */
  primary: string;
  /** Labels, counts and captions: Foreground3, or Foreground2 where Foreground3 misses it. */
  secondary: string;
  /**
   * The same rule for captions drawn on the `colorNeutralBackground1` cards inside the rail
   * (Foreground3 measures 3.37:1 there in solarized-dark and 3.03:1 in dracula).
   */
  cardSecondary: string;
}

export function pickRailTextColors(theme: CMTraceTheme): RailTextColors {
  const fluent = theme.fluentTheme as unknown as Record<string, string>;
  const passes = (key: string, surfaceKey = "colorNeutralBackground2") =>
    contrastRatio(fluent[key], fluent[surfaceKey]) >= TEXT_FLOOR;
  return {
    primary: passes("colorNeutralForeground1")
      ? tokens.colorNeutralForeground1
      : tokens.colorNeutralForeground2,
    secondary: passes("colorNeutralForeground3")
      ? tokens.colorNeutralForeground3
      : tokens.colorNeutralForeground2,
    cardSecondary: passes("colorNeutralForeground3", "colorNeutralBackground1")
      ? tokens.colorNeutralForeground3
      : tokens.colorNeutralForeground2,
  };
}

export function useRailTextColors(): RailTextColors {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => pickRailTextColors(getThemeById(themeId)), [themeId]);
}
