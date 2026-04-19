import { useRef, useState } from "react";
import { useTimelineStore } from "../../stores/timeline-store";

interface Props {
  timeRangeMs: [number, number];
  width: number;
  height: number;
}

export function BrushOverlay({ timeRangeMs, width, height }: Props) {
  const brushRange = useTimelineStore((s) => s.brushRange);
  const setBrushRange = useTimelineStore((s) => s.setBrushRange);
  const clearBrushRange = useTimelineStore((s) => s.clearBrushRange);

  const [dragStart, setDragStart] = useState<number | null>(null);
  const [dragEnd, setDragEnd] = useState<number | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const [lo, hi] = timeRangeMs;
  const span = Math.max(1, hi - lo);

  const pxToTs = (px: number) => lo + (px / width) * span;
  const tsToPx = (ts: number) => ((ts - lo) / span) * width;

  const onMouseDown = (e: React.MouseEvent) => {
    const rect = rootRef.current?.getBoundingClientRect();
    if (!rect) return;
    const x = e.clientX - rect.left;
    setDragStart(x);
    setDragEnd(x);
  };
  const onMouseMove = (e: React.MouseEvent) => {
    if (dragStart == null) return;
    const rect = rootRef.current?.getBoundingClientRect();
    if (!rect) return;
    setDragEnd(e.clientX - rect.left);
  };
  const onMouseUp = () => {
    if (dragStart == null || dragEnd == null) {
      setDragStart(null);
      setDragEnd(null);
      return;
    }
    const s = Math.min(dragStart, dragEnd);
    const e = Math.max(dragStart, dragEnd);
    if (Math.abs(e - s) < 3) {
      clearBrushRange();
    } else {
      setBrushRange([pxToTs(s), pxToTs(e)]);
    }
    setDragStart(null);
    setDragEnd(null);
  };

  const selection = (() => {
    if (dragStart != null && dragEnd != null) {
      return {
        x: Math.min(dragStart, dragEnd),
        w: Math.abs(dragEnd - dragStart),
      };
    }
    if (brushRange) {
      const x = tsToPx(brushRange[0]);
      const w = tsToPx(brushRange[1]) - x;
      return { x, w };
    }
    return null;
  })();

  return (
    <div
      ref={rootRef}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={onMouseUp}
      onMouseLeave={onMouseUp}
      style={{
        position: "absolute",
        inset: 0,
        width,
        height,
        cursor: "crosshair",
      }}
    >
      {selection && (
        <div
          style={{
            position: "absolute",
            left: selection.x,
            width: selection.w,
            top: 0,
            bottom: 0,
            background: "rgba(37,99,235,.10)",
            borderLeft: "1px dashed #2563eb",
            borderRight: "1px dashed #2563eb",
            pointerEvents: "none",
          }}
        />
      )}
    </div>
  );
}
