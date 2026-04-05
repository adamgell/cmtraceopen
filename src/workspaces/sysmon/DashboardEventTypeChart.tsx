import { tokens } from "@fluentui/react-components";
import { DonutChart } from "@fluentui/react-charts";
import type { SysmonSummary } from "./types";

interface DashboardEventTypeChartProps {
  summary: SysmonSummary;
}

// Theme-aware palette using Fluent UI tokens for chart colors
const CHART_COLORS = [
  tokens.colorPaletteBlueForeground2,
  tokens.colorPaletteRedForeground1,
  tokens.colorPaletteGreenForeground1,
  tokens.colorPalettePurpleForeground2,
  tokens.colorPaletteMarigoldForeground1,
  tokens.colorPaletteTealForeground2,
  tokens.colorPalettePinkForeground2,
  tokens.colorPaletteBerryForeground1,
];

export function DashboardEventTypeChart({ summary }: DashboardEventTypeChartProps) {
  const chartData = summary.eventTypeCounts.map((etc, i) => ({
    legend: etc.displayName,
    data: etc.count,
    color: CHART_COLORS[i % CHART_COLORS.length],
  }));

  return (
    <div
      style={{
        padding: "16px",
        backgroundColor: tokens.colorNeutralBackground1,
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <h4 style={{ margin: "0 0 12px 0", fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
        Event Type Distribution
      </h4>
      {chartData.length === 0 ? (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          No event type data available.
        </div>
      ) : (
        <DonutChart
          data={{ chartData }}
          innerRadius={40}
          valueInsideDonut={summary.totalEvents.toLocaleString()}
          hideLabels={false}
          height={200}
        />
      )}
    </div>
  );
}
