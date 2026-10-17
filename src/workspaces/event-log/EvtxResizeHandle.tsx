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
import {
  useCallback,
  useEffect,
  useRef,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent,
} from "react";
import { makeStyles, tokens } from "@fluentui/react-components";
import { EVTX_FOCUS_RING } from "./evtx-bar-states";

const useStyles = makeStyles({
  handle: {
    position: "absolute",
    zIndex: 2,
    backgroundColor: "transparent",
    ":hover": { backgroundColor: tokens.colorNeutralStroke1 },
    // Two-tone ring inside the 7 px strip: the outer 2 px is an outline (forced-colors mode keeps
    // outlines, which drop fills) in the outer focus color and the 3 px core is filled with the
    // inner focus color, so the ring is visible on any region fill.
    ":focus-visible": {
      backgroundColor: EVTX_FOCUS_RING.inner,
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: EVTX_FOCUS_RING.outer,
      outlineOffset: "-2px",
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

  const release = useCallback(() => {
    if (dragRef.current) {
      dragRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
  }, []);

  // A drag can also end without a pointerup reaching the handle (window blur, the window losing
  // focus mid-drag), so release there too, and on unmount.
  useEffect(() => {
    window.addEventListener("blur", release);
    return () => {
      window.removeEventListener("blur", release);
      release();
    };
  }, [release]);

  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    // The button was released outside the page or the capture was lost: stop rather than follow
    // a pointer that is no longer dragging.
    if (event.buttons === 0) {
      release();
      return;
    }
    const position = horizontal ? event.clientY : event.clientX;
    onChange(drag.startValue + (position - drag.start) * direction);
  };

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
      onPointerDown={(event) => {
        // Primary button only: a right-click opens the context menu and must not arm a drag.
        if (event.button !== 0 || !event.isPrimary) return;
        event.preventDefault();
        event.currentTarget.setPointerCapture?.(event.pointerId);
        dragRef.current = {
          start: horizontal ? event.clientY : event.clientX,
          startValue: value,
        };
        document.body.style.cursor = horizontal ? "row-resize" : "col-resize";
        document.body.style.userSelect = "none";
      }}
      onPointerMove={onPointerMove}
      onPointerUp={release}
      onPointerCancel={release}
      onLostPointerCapture={release}
      style={{ touchAction: "none", ...position }}
    />
  );
}
