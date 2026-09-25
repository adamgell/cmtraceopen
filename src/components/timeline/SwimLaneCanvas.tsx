import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import type { LaneBucket, TimelineSourceMeta } from "../../types/timeline";

/** Resolve a Fluent token (CSS custom-property string) to its computed value. */
function resolveToken(el: HTMLElement, token: string): string {
  // tokens.* values are `var(--xxx)` strings — extract the custom-property name.
  const match = token.match(/var\(([^)]+)\)/);
  if (!match) return token;
  return getComputedStyle(el).getPropertyValue(match[1]).trim() || token;
}

/** Hit testing for the lane geometry, which only the canvas measures. */
export interface SwimLaneCanvasHandle {
  /** Bucket under a viewport point, or null when the point is outside a lane. */
  bucketAtPoint: (clientX: number, clientY: number) => LaneBucket | null;
}

interface Props {
  sources: TimelineSourceMeta[];
  buckets: LaneBucket[];
  timeRangeMs: [number, number];
  width: number;
  laneHeight: number;
  laneVisibility: Record<number, boolean>;
  soloSourceIdx: number | null;
}

export const SwimLaneCanvas = forwardRef<SwimLaneCanvasHandle, Props>(
  function SwimLaneCanvas(props, ref) {
    const {
      sources,
      buckets,
      timeRangeMs,
      width,
      laneHeight,
      laneVisibility,
      soloSourceIdx,
    } = props;
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [lo, hi] = timeRangeMs;
    const span = Math.max(1, hi - lo);

    const visible = sources.filter(
      (s) =>
        (soloSourceIdx == null || s.idx === soloSourceIdx) &&
        laneVisibility[s.idx] !== false,
    );
    const height = visible.length * laneHeight;

    useEffect(() => {
      const cv = canvasRef.current;
      const ctx = cv?.getContext("2d");
      if (!cv || !ctx) return;
      const dpr = window.devicePixelRatio || 1;
      cv.width = Math.max(1, width * dpr);
      cv.height = Math.max(1, height * dpr);
      cv.style.width = `${width}px`;
      cv.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const laneBg = resolveToken(cv, tokens.colorNeutralBackground2);
      const errorFill = resolveToken(cv, tokens.colorPaletteRedForeground1);
      const warnFill = resolveToken(cv, tokens.colorPaletteYellowForeground1);

      visible.forEach((src, laneIdx) => {
        const y = laneIdx * laneHeight;
        ctx.fillStyle = laneBg;
        ctx.fillRect(0, y, width, laneHeight - 2);

        const laneBuckets = buckets.filter((b) => b.sourceIdx === src.idx);
        laneBuckets.forEach((b) => {
          const x = ((b.tsStartMs - lo) / span) * width;
          const w = Math.max(1, ((b.tsEndMs - b.tsStartMs) / span) * width);
          let fill = src.color;
          if (b.errorCount > 0) fill = errorFill;
          else if (b.warnCount > 0) fill = warnFill;
          const density = Math.min(1, b.totalCount / 20);
          ctx.globalAlpha = 0.35 + 0.6 * density;
          ctx.fillStyle = fill;
          ctx.fillRect(x, y + 2, w, laneHeight - 6);
        });
        ctx.globalAlpha = 1;
      });
    }, [buckets, visible, lo, span, width, height, laneHeight]);

    // The brush overlay covers the lanes and owns the pointer, so a canvas
    // mousemove never fires. The lane readout resolves its bucket through this
    // handle instead, which keeps the geometry in the one component that
    // measures it.
    useImperativeHandle(ref, () => ({
      bucketAtPoint: (clientX, clientY) => {
        const cv = canvasRef.current;
        if (!cv) return null;
        const rect = cv.getBoundingClientRect();
        const laneIdx = Math.floor((clientY - rect.top) / laneHeight);
        const src = visible[laneIdx];
        if (!src) return null;
        const tsAt = lo + ((clientX - rect.left) / width) * span;
        return (
          buckets.find(
            (b) =>
              b.sourceIdx === src.idx &&
              tsAt >= b.tsStartMs &&
              tsAt <= b.tsEndMs,
          ) ?? null
        );
      },
    }));

    return <canvas ref={canvasRef} style={{ display: "block" }} />;
  },
);
