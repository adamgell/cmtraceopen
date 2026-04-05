import { useState } from "react";
import { tokens, Dropdown, Option } from "@fluentui/react-components";
import { VerticalBarChart } from "@fluentui/react-charts";
import type { SysmonDashboardData, TimeBucket } from "./types";

interface DashboardTimelineProps {
  dashboard: SysmonDashboardData;
}

type Granularity = "minute" | "hour" | "day";

const GRANULARITY_OPTIONS: { value: Granularity; label: string }[] = [
  { value: "minute", label: "Per Minute" },
  { value: "hour", label: "Per Hour" },
  { value: "day", label: "Per Day" },
];

function fmtLabel(ts: string, granularity: Granularity): string {
  try {
    const d = new Date(ts);
    if (granularity === "day") {
      return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    }
    if (granularity === "hour") {
      return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    }
    // minute
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  } catch {
    return ts;
  }
}

const MAX_BARS = 100;

function downsampleBuckets(buckets: TimeBucket[]): TimeBucket[] {
  if (buckets.length <= MAX_BARS) return buckets;
  // Merge adjacent buckets to fit within MAX_BARS
  const factor = Math.ceil(buckets.length / MAX_BARS);
  const result: TimeBucket[] = [];
  for (let i = 0; i < buckets.length; i += factor) {
    const slice = buckets.slice(i, i + factor);
    const merged: TimeBucket = {
      timestamp: slice[0].timestamp,
      timestampMs: slice[0].timestampMs,
      count: slice.reduce((sum, b) => sum + b.count, 0),
    };
    result.push(merged);
  }
  return result;
}

function bucketsToChartData(buckets: TimeBucket[], granularity: Granularity) {
  const sampled = downsampleBuckets(buckets);
  return sampled.map((b) => ({
    x: fmtLabel(b.timestamp, granularity),
    y: b.count,
    legend: fmtLabel(b.timestamp, granularity),
    color: tokens.colorBrandBackground,
  }));
}

export function DashboardTimeline({ dashboard }: DashboardTimelineProps) {
  const [granularity, setGranularity] = useState<Granularity>("hour");

  const buckets =
    granularity === "minute"
      ? dashboard.timelineMinute
      : granularity === "hour"
        ? dashboard.timelineHourly
        : dashboard.timelineDaily;

  const data = bucketsToChartData(buckets, granularity);

  const selectedLabel =
    GRANULARITY_OPTIONS.find((o) => o.value === granularity)?.label ?? "Per Hour";

  return (
    <div
      style={{
        gridColumn: "1 / -1",
        padding: "16px",
        backgroundColor: tokens.colorNeutralBackground1,
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <h4 style={{ margin: 0, fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          Event Timeline
        </h4>
        <Dropdown
          value={selectedLabel}
          selectedOptions={[granularity]}
          onOptionSelect={(_, d) => setGranularity(d.optionValue as Granularity)}
          size="small"
          style={{ minWidth: "130px" }}
        >
          {GRANULARITY_OPTIONS.map((o) => (
            <Option key={o.value} value={o.value}>
              {o.label}
            </Option>
          ))}
        </Dropdown>
      </div>

      {data.length === 0 ? (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, padding: "8px 0" }}>
          No timeline data available.
        </div>
      ) : (
        <div style={{ width: "100%", overflow: "hidden" }}>
          <VerticalBarChart
            data={data}
            chartTitle="Event Timeline"
            barWidth={Math.max(4, Math.min(16, Math.floor(800 / data.length)))}
            useSingleColor
            colors={[tokens.colorBrandBackground]}
            height={180}
          />
        </div>
      )}
    </div>
  );
}
