import { useState } from "react";
import { tokens, Dropdown, Option } from "@fluentui/react-components";
import { VerticalBarChart } from "@fluentui/react-charts";
import type { SysmonDashboardData, TimeBucket } from "../../types/sysmon";

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

function bucketsToChartData(buckets: TimeBucket[], granularity: Granularity) {
  return buckets.map((b) => ({
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
        <VerticalBarChart
          data={data}
          chartTitle="Event Timeline"
          barWidth="auto"
          useSingleColor
          colors={[tokens.colorBrandBackground]}
          height={220}
        />
      )}
    </div>
  );
}
