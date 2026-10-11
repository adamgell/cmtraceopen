/**
 * Measures a resizable column that the workspace caps to a share of the body row (see the 40%
 * cap on the channel region and the rail). A narrow window makes the cap smaller than the
 * requested width, so the pane renders narrower than the stored value. The resize handle must
 * report and step from what is actually on screen, and its maximum must not exceed the cap.
 */
import { useLayoutEffect, useState, type RefObject } from "react";

export interface RowCappedSize {
  /** Rendered width in px, or 0 when not laid out (hidden, or no layout engine). */
  rendered: number;
  /** The cap in px (share of the row), or 0 when the row cannot be measured. */
  cap: number;
}

/**
 * @param ref the sized element
 * @param rowLevelsUp how many parents above `ref` the body row is (the channel pane sits inside
 *   its region wrapper, so 2; the rail is the row's own child, so 1)
 * @param share the row share used by the CSS cap
 */
export function useRowCappedSize(
  ref: RefObject<HTMLElement | null>,
  rowLevelsUp: number,
  share = 0.4,
): RowCappedSize {
  const [size, setSize] = useState<RowCappedSize>({ rendered: 0, cap: 0 });

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;
    let row: HTMLElement | null = element;
    for (let level = 0; level < rowLevelsUp && row; level += 1) row = row.parentElement;

    const read = () => {
      const rendered = Math.round(element.getBoundingClientRect().width);
      const cap = row ? Math.floor(row.clientWidth * share) : 0;
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
  }, [ref, rowLevelsUp, share]);

  return size;
}

/** The handle's value and bounds for a column with a nominal range and a measured cap. */
export function effectiveResizeRange(
  requested: number,
  min: number,
  max: number,
  { rendered, cap }: RowCappedSize,
): { value: number; min: number; max: number } {
  const effectiveMax = cap > 0 ? Math.min(max, cap) : max;
  return {
    value: rendered > 0 ? rendered : requested,
    min: Math.min(min, effectiveMax),
    max: effectiveMax,
  };
}
