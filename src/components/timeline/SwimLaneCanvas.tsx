import { useEffect, useRef } from "react";
import type { LaneBucket, TimelineSourceMeta } from "../../types/timeline";

interface Props {
  sources: TimelineSourceMeta[];
  buckets: LaneBucket[];
  timeRangeMs: [number, number];
  width: number;
  laneHeight: number;
  laneVisibility: Record<number, boolean>;
  soloSourceIdx: number | null;
  onBucketHover?: (b: LaneBucket | null) => void;
  onBucketDoubleClick?: (b: LaneBucket) => void;
}

export function SwimLaneCanvas(props: Props) {
  const {
    sources,
    buckets,
    timeRangeMs,
    width,
    laneHeight,
    laneVisibility,
    soloSourceIdx,
    onBucketHover,
    onBucketDoubleClick,
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

    visible.forEach((src, laneIdx) => {
      const y = laneIdx * laneHeight;
      ctx.fillStyle = "#f9fafb";
      ctx.fillRect(0, y, width, laneHeight - 2);

      const laneBuckets = buckets.filter((b) => b.sourceIdx === src.idx);
      laneBuckets.forEach((b) => {
        const x = ((b.tsStartMs - lo) / span) * width;
        const w = Math.max(1, ((b.tsEndMs - b.tsStartMs) / span) * width);
        let fill = src.color;
        if (b.errorCount > 0) fill = "#dc2626";
        else if (b.warnCount > 0) fill = "#f59e0b";
        const density = Math.min(1, b.totalCount / 20);
        ctx.globalAlpha = 0.35 + 0.6 * density;
        ctx.fillStyle = fill;
        ctx.fillRect(x, y + 2, w, laneHeight - 6);
      });
      ctx.globalAlpha = 1;
    });
  }, [buckets, visible, lo, span, width, height, laneHeight]);

  const bucketAt = (e: React.MouseEvent): LaneBucket | null => {
    const cv = canvasRef.current;
    if (!cv) return null;
    const rect = cv.getBoundingClientRect();
    const xPx = e.clientX - rect.left;
    const yPx = e.clientY - rect.top;
    const laneIdx = Math.floor(yPx / laneHeight);
    const src = visible[laneIdx];
    if (!src) return null;
    const tsAt = lo + (xPx / width) * span;
    return (
      buckets.find(
        (b) =>
          b.sourceIdx === src.idx &&
          tsAt >= b.tsStartMs &&
          tsAt <= b.tsEndMs,
      ) ?? null
    );
  };

  return (
    <canvas
      ref={canvasRef}
      onMouseMove={(e) => onBucketHover?.(bucketAt(e))}
      onMouseLeave={() => onBucketHover?.(null)}
      onDoubleClick={(e) => {
        const hit = bucketAt(e);
        if (hit) onBucketDoubleClick?.(hit);
      }}
      style={{ display: "block", cursor: "pointer" }}
    />
  );
}
