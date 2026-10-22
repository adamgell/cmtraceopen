/**
 * Measures a resizable column that the workspace caps to a share of the body row (see the 40%
 * cap on the channel region and the rail). A narrow window makes the cap smaller than the
 * requested width, so the pane renders narrower than the stored value. The resize handle must
 * report and step from what is actually on screen, and its maximum must not exceed the cap.
 */
import { useLayoutEffect, useState } from "react";

export interface RowCappedSize {
  /** Rendered width in px, or 0 when not laid out (hidden, or no layout engine). */
  rendered: number;
  /** The cap in px (share of the row), or 0 when the row cannot be measured. */
  cap: number;
}

/**
 * @param requested the stored (requested) width. Measurement is redone whenever it changes, so
 *   the reported width never lags a store write, with or without ResizeObserver (without one,
 *   only a window resize would otherwise trigger a read and keyboard resizing would stall).
 * @param rowLevelsUp how many parents above the element the body row is (the channel pane sits
 *   inside its region wrapper, so 2; the rail is the row's own child, so 1)
 * @param share the row share used by the CSS cap
 * @returns a CALLBACK ref to attach to the sized element, plus its measurements. A callback ref
 *   follows the element's real mount: when the layout subtree unmounts and remounts (through the
 *   spinner or the source picker) the new element is attached and measured, which an effect on a
 *   stable ref object would miss.
 */
export function useRowCappedSize(
  rowLevelsUp: number,
  requested: number,
  share = 0.4,
): RowCappedSize & { ref: (element: HTMLElement | null) => void } {
  const [element, setElement] = useState<HTMLElement | null>(null);
  const [size, setSize] = useState<RowCappedSize>({ rendered: 0, cap: 0 });

  useLayoutEffect(() => {
    if (!element) {
      setSize((previous) => (previous.rendered === 0 && previous.cap === 0 ? previous : { rendered: 0, cap: 0 }));
      return;
    }
    let row: HTMLElement | null = element;
    for (let level = 0; level < rowLevelsUp && row; level += 1) row = row.parentElement;

    // Both numbers come from the same fractional source (getBoundingClientRect) and the same
    // rounding (floor), so a binding cap always renders at exactly `cap`: rounding one and
    // flooring the other made them differ by 1 px on 2 of 5 row widths.
    const read = () => {
      const rendered = Math.floor(element.getBoundingClientRect().width);
      const cap = row ? Math.floor(row.getBoundingClientRect().width * share) : 0;
      setSize((previous) =>
        previous.rendered === rendered && previous.cap === cap ? previous : { rendered, cap },
      );
    };
    read();

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", read);
      return () => window.removeEventListener("resize", read);
    }
    const observer = new ResizeObserver(read);
    observer.observe(element);
    if (row) observer.observe(row);
    return () => observer.disconnect();
  }, [element, rowLevelsUp, requested, share]);

  return { ...size, ref: setElement };
}

/** The handle's value and bounds for a column with a nominal range and a measured cap. */
export function effectiveResizeRange(
  requested: number,
  min: number,
  max: number,
  { rendered, cap }: RowCappedSize,
): { value: number; min: number; max: number } {
  const effectiveMax = cap > 0 ? Math.min(max, cap) : max;
  const effectiveMin = Math.min(min, effectiveMax);
  // The reported value is always inside the reported range, so aria-valuenow can never exceed
  // aria-valuemax (nor fall below aria-valuemin) whatever the measurements say.
  const value = Math.max(effectiveMin, Math.min(rendered > 0 ? rendered : requested, effectiveMax));
  return { value, min: effectiveMin, max: effectiveMax };
}

/**
 * The width to store for a proposed resize, or null when the proposal cannot change what is on
 * screen. While a cap binds, the rendered width is below the stored (requested) width; clamping a
 * proposal into the effective range and finding it equal to the rendered width means the visible
 * pane would not move, so the stored preference must be left alone (the pane returns to it when
 * the window widens again). The result is always an integer.
 */
export function proposeResize(
  next: number,
  range: { value: number; min: number; max: number },
): number | null {
  // Round first, as the stores do (`clampNumber`): the guard must judge the number that would be
  // kept. A sub-pixel pointer drag proposes `cap - 0.4`, which the store rounds back to the cap
  // and would persist over the stored preference.
  const clamped = Math.max(range.min, Math.min(Math.round(next), range.max));
  return clamped === range.value ? null : clamped;
}
