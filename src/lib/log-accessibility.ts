export const LOG_UI_FONT_FAMILY =
  "var(--cmtrace-font-family-ui, 'Segoe UI', Tahoma, sans-serif)";
export const LOG_MONOSPACE_FONT_FAMILY =
  "var(--cmtrace-font-family-mono, 'Consolas', 'Cascadia Mono', 'Courier New', monospace)";

export const DEFAULT_LOG_LIST_FONT_SIZE = 13;
export const MIN_LOG_LIST_FONT_SIZE = 11;
export const MAX_LOG_LIST_FONT_SIZE = 20;

export const DEFAULT_LOG_DETAILS_FONT_SIZE = 13;
export const MIN_LOG_DETAILS_FONT_SIZE = 11;
export const MAX_LOG_DETAILS_FONT_SIZE = 24;

function clampFontSize(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(value)));
}

export function clampLogListFontSize(value: number): number {
  return clampFontSize(value, MIN_LOG_LIST_FONT_SIZE, MAX_LOG_LIST_FONT_SIZE);
}

export function clampLogDetailsFontSize(value: number): number {
  return clampFontSize(value, MIN_LOG_DETAILS_FONT_SIZE, MAX_LOG_DETAILS_FONT_SIZE);
}

export interface LogListMetrics {
  fontSize: number;
  rowLineHeight: number;
  rowHeight: number;
  headerFontSize: number;
  headerLineHeight: number;
}

export function getLogListMetrics(fontSize: number): LogListMetrics {
  const clampedFontSize = clampLogListFontSize(fontSize);
  const rowLineHeight = Math.max(20, Math.round(clampedFontSize * 1.5));
  const rowVerticalPadding = 2;

  return {
    fontSize: clampedFontSize,
    rowLineHeight,
    rowHeight: rowLineHeight + rowVerticalPadding + 1,
    headerFontSize: Math.max(12, clampedFontSize),
    headerLineHeight: rowLineHeight + 4,
  };
}

/**
 * Returns a canvas-compatible font string.
 * Prefers reading the resolved font-family from a real DOM element (most accurate),
 * falling back to resolving the CSS custom property, then a hardcoded fallback.
 * canvas.measureText() cannot handle var(--...) syntax.
 */
export function getCanvasFont(
  size: number,
  bold = false,
  sourceElement?: Element | null
): string {
  let family: string;
  if (sourceElement) {
    family = getComputedStyle(sourceElement).fontFamily;
  } else {
    family =
      getComputedStyle(document.documentElement)
        .getPropertyValue("--cmtrace-font-family-ui")
        .trim() || "'Segoe UI', Tahoma, sans-serif";
  }
  return `${bold ? "bold " : ""}${size}px ${family}`;
}

export function getLogDetailsLineHeight(fontSize: number): number {
  const clampedFontSize = clampLogDetailsFontSize(fontSize);
  return Math.max(20, Math.round(clampedFontSize * 1.6));
}