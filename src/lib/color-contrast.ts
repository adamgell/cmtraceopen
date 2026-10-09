/** Pure color contrast helpers (WCAG 2.x). No React or DOM. */

function parseHex(color: string): [number, number, number] {
  const match = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color.trim());
  if (!match) {
    throw new Error(`Expected a #rgb or #rrggbb color, got ${color}`);
  }
  const hex = match[1];
  const full =
    hex.length === 3
      ? hex
          .split("")
          .map((c) => c + c)
          .join("")
      : hex;
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ];
}

function relativeLuminance(color: string): number {
  const [r, g, b] = parseHex(color).map((channel) => {
    const c = channel / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2.x contrast ratio between two `#rgb` or `#rrggbb` colors. */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/**
 * Returns `preferred` when it reaches `minimum` contrast against
 * `background`, otherwise black or white, whichever contrasts more.
 */
export function readableOn(
  background: string,
  preferred: string,
  minimum = 3,
): string {
  if (contrastRatio(preferred, background) >= minimum) return preferred;
  const black = "#000000";
  const white = "#ffffff";
  return contrastRatio(black, background) >= contrastRatio(white, background)
    ? black
    : white;
}
