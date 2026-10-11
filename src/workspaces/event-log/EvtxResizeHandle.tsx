/**
 * A drag and keyboard handle for the workbench regions that resize (channel pane, rail, dock).
 *
 * The visible edge is the region's own 1 px border. This handle is a wider transparent strip laid
 * over that border, so the region measures its nominal size and the drag target is still easy to
 * hit. Mount it in a NON-scrolling, positioned wrapper: inside a scroll container the strip would
 * be clipped to the padding box and would scroll away with the content.
 *
 * It is a focusable `separator` so a keyboard-only operator can resize too. `direction` states
 * which way the pointer must move to GROW the region, and both drag and arrow keys follow it.
 */
import { useEffect, useRef, type CSSProperties, type KeyboardEvent } from "react";
import { makeStyles, tokens } from "@fluentui/react-components";

const useStyles = makeStyles({
  handle: {
    position: "absolute",
    zIndex: 2,
    backgroundColor: "transparent",
    ":hover": { backgroundColor: tokens.colorNeutralStroke1 },
    ":focus-visible": {
      backgroundColor: tokens.colorStrokeFocus2,
      outlineStyle: "none",
    },
  },
});

interface EvtxResizeHandleProps {
  /** `vertical` separates left from right (drag moves X); `horizontal` separates top from bottom. */
  orientation: "vertical" | "horizontal";
  /** Which edge of the positioned wrapper the strip sits on. */
  edge: "start" | "end";
  label: string;
  /** Id of the region this handle sizes (`aria-controls`). */
  controls: string;
  value: number;
  min: number;
  max: number;
  /**
   * +1 when moving the pointer toward the end of the axis (right or down) grows the region, -1
   * when it shrinks it. The rail sits right of its edge (-1 on X), the dock below it (-1 on Y),
   * the channel pane left of its edge (+1 on X).
   */
  direction: 1 | -1;
  onChange: (next: number) => void;
}

const KEY_STEP = 16;

export function EvtxResizeHandle({
  orientation,
  edge,
  label,
  controls,
  value,
  min,
  max,
  direction,
  onChange,
}: EvtxResizeHandleProps) {
  const styles = useStyles();
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
    // The key's pointer-axis sign: right and down move toward the end of the axis.
    const towardEnd = horizontal ? "ArrowDown" : "ArrowRight";
    const towardStart = horizontal ? "ArrowUp" : "ArrowLeft";
    if (event.key === towardEnd) onChange(value + KEY_STEP * direction);
    else if (event.key === towardStart) onChange(value - KEY_STEP * direction);
    else if (event.key === "Home") onChange(min);
    else if (event.key === "End") onChange(max);
    else return;
    event.preventDefault();
  };

  const position: CSSProperties = horizontal
    ? {
        left: 0,
        right: 0,
        height: 7,
        cursor: "row-resize",
        ...(edge === "start" ? { top: -3 } : { bottom: -3 }),
      }
    : {
        top: 0,
        bottom: 0,
        width: 7,
        cursor: "col-resize",
        ...(edge === "start" ? { left: -3 } : { right: -3 }),
      };

  return (
    <div
      role="separator"
      className={styles.handle}
      aria-orientation={horizontal ? "horizontal" : "vertical"}
      aria-label={label}
      aria-controls={controls}
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
      style={position}
    />
  );
}
