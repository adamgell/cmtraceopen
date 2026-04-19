import { useMemo } from "react";

interface Props {
  timeRangeMs: [number, number];
  width: number;
}

export function TimelineRuler({ timeRangeMs, width }: Props) {
  const [lo, hi] = timeRangeMs;
  const ticks = useMemo(() => {
    const count = Math.max(4, Math.min(12, Math.floor(width / 120)));
    const step = (hi - lo) / count;
    return Array.from({ length: count + 1 }, (_, i) => {
      const ts = lo + step * i;
      const x = ((ts - lo) / (hi - lo || 1)) * width;
      return { ts, x, label: formatTime(ts) };
    });
  }, [lo, hi, width]);

  return (
    <svg width={width} height={20} role="presentation">
      {ticks.map((t, i) => (
        <g key={i} transform={`translate(${t.x},0)`}>
          <line y2={6} stroke="#6b7280" />
          <text y={18} fontSize={10} fill="#6b7280" textAnchor="middle">
            {t.label}
          </text>
        </g>
      ))}
    </svg>
  );
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}
