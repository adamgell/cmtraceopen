/**
 * A drag and keyboard handle for the workbench regions that resize (rail width, dock height).
 *
 * The visible edge is the region's own 1 px border. This handle is a wider transparent strip laid
 * over that border, so the region measures its nominal size and the drag target is still easy to
 * hit. It is a focusable `separator` so a keyboard-only operator can resize too.
 */
import { useEffect, useRef, type CSSProperties, type KeyboardEvent } from "react";

interface EvtxResizeHandleProps {
  /** `vertical` separates left from right (drag moves X); `horizontal` separates top from bottom. */
  orientation: "vertical" | "horizontal";
  label: string;
  value: number;
  min: number;
  max: number;
  /**
   * +1 when moving the pointer toward the end of the axis (right or down) grows the region, -1
   * when it shrinks it. The rail sits right of its edge (-1 on X), the dock below it (-1 on Y).
   */
  direction: 1 | -1;
  onChange: (next: number) => void;
}

const KEY_STEP = 16;

export function EvtxResizeHandle({
  orientation,
  label,
  value,
  min,
  max,
  direction,
  onChange,
}: EvtxResizeHandleProps) {
  const dragRef = useRef<{ start: number; startValue: number } | null>(null);
  const horizontal = orientation === "horizontal";
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    const release = () => {
      if (dragRef.current) {
        dragRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    const onMove = (event: MouseEvent) => {
      const drag = dragRef.current;
      if (!drag) return;
      const position = horizontal ? event.clientY : event.clientX;
      onChangeRef.current(drag.startValue + (position - drag.start) * direction);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", release);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", release);
      release();
    };
  }, [horizontal, direction]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const grow = horizontal ? "ArrowUp" : "ArrowLeft";
    const shrink = horizontal ? "ArrowDown" : "ArrowRight";
    if (event.key === grow) onChange(value + KEY_STEP);
    else if (event.key === shrink) onChange(value - KEY_STEP);
    else if (event.key === "Home") onChange(min);
    else if (event.key === "End") onChange(max);
    else return;
    event.preventDefault();
  };

  const style: CSSProperties = horizontal
    ? { left: 0, right: 0, top: -3, height: 7, cursor: "row-resize" }
    : { top: 0, bottom: 0, left: -3, width: 7, cursor: "col-resize" };

  return (
    <div
      role="separator"
      aria-orientation={horizontal ? "horizontal" : "vertical"}
      aria-label={label}
      aria-valuenow={Math.round(value)}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onKeyDown={onKeyDown}
      onMouseDown={(event) => {
        event.preventDefault();
        dragRef.current = {
          start: horizontal ? event.clientY : event.clientX,
          startValue: value,
        };
        document.body.style.cursor = horizontal ? "row-resize" : "col-resize";
        document.body.style.userSelect = "none";
      }}
      style={{ position: "absolute", zIndex: 2, background: "transparent", ...style }}
    />
  );
}
