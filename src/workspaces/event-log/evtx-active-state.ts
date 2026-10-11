/**
 * Text color for the active Layout tab and the checked panel toggles (spec 6.2: brand foreground
 * on `colorNeutralBackground1Selected`).
 *
 * The brand foreground does not reach 4.5:1 on that surface in every theme (high-contrast, classic
 * and dracula fall short), and token values are never changed here, so the rendering falls back to
 * black or white when the brand color is not readable.
 */
import { tokens } from "@fluentui/react-components";
import { useMemo } from "react";
import { readableOn } from "../../lib/color-contrast";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import { resolveToken } from "./evtx-visual-tokens";

export const EVTX_ACTIVE_TEXT_MIN_CONTRAST = 4.5;

export function evtxActiveSurface(theme: CMTraceTheme): string {
  return resolveToken(tokens.colorNeutralBackground1Selected, theme);
}

export function evtxActiveTextColor(theme: CMTraceTheme): string {
  return readableOn(
    evtxActiveSurface(theme),
    resolveToken(tokens.colorBrandForeground1, theme),
    EVTX_ACTIVE_TEXT_MIN_CONTRAST,
  );
}

/** The active-state text color for the current theme. */
export function useEvtxActiveTextColor(): string {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => evtxActiveTextColor(getThemeById(themeId)), [themeId]);
}
