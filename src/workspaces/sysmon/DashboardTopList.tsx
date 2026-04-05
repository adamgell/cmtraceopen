import { tokens } from "@fluentui/react-components";
import { HorizontalBarChart } from "@fluentui/react-charts";
import type { RankedItem } from "./types";

interface DashboardTopListProps {
  title: string;
  items: RankedItem[];
  emptyMessage?: string;
  color?: string;
}

export function DashboardTopList({
  title,
  items,
  emptyMessage = "No data available.",
  color,
}: DashboardTopListProps) {
  if (items.length === 0) {
    return (
      <div style={containerStyle}>
        <h4 style={titleStyle}>{title}</h4>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3, padding: "8px 0" }}>
          {emptyMessage}
        </div>
      </div>
    );
  }

  const maxCount = Math.max(...items.map((i) => i.count), 1);
  const barColor = color ?? tokens.colorBrandBackground;

  // HorizontalBarChart expects ChartProps[] where each ChartProps has chartTitle and chartData
  const chartData = items.map((item) => ({
    chartTitle: item.name,
    chartData: [
      {
        legend: item.name,
        horizontalBarChartdata: { x: item.count, y: maxCount },
        color: barColor,
      },
    ],
  }));

  return (
    <div style={containerStyle}>
      <h4 style={titleStyle}>{title}</h4>
      <HorizontalBarChart
        data={chartData}
        hideRatio={items.map(() => true)}
        barHeight={14}
      />
    </div>
  );
}

const containerStyle: React.CSSProperties = {
  padding: "16px",
  backgroundColor: tokens.colorNeutralBackground1,
  borderRadius: "6px",
  border: `1px solid ${tokens.colorNeutralStroke2}`,
};

const titleStyle: React.CSSProperties = {
  margin: "0 0 12px 0",
  fontSize: "13px",
  fontWeight: 600,
  color: tokens.colorNeutralForeground1,
};
