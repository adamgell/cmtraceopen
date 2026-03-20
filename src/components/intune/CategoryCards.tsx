import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { useIntuneStore } from "../../stores/intune-store";
import type { IntuneBusinessCategory, IntuneEvent } from "../../types/intune";
import { BUSINESS_CATEGORIES, getBusinessCategory } from "../../types/intune";

interface CategoryStat {
  category: IntuneBusinessCategory;
  total: number;
  failed: number;
  succeeded: number;
}

const CATEGORY_DISPLAY: Record<
  IntuneBusinessCategory,
  { label: string; color: string; icon: string }
> = {
  Devices: { label: "Devices", color: "#0ea5e9", icon: "\u{1F5A5}" },
  Apps: { label: "Applications", color: "#8b5cf6", icon: "\u{1F4E6}" },
  Configurations: { label: "Configurations", color: "#f97316", icon: "\u2699\uFE0F" },
  Compliance: { label: "Compliance", color: "#22c55e", icon: "\u2705" },
  Sync: { label: "Sync Status", color: "#06b6d4", icon: "\u{1F504}" },
  Other: { label: "Other", color: "#6b7280", icon: "\u2026" },
};

function computeCategoryStats(events: IntuneEvent[]): CategoryStat[] {
  const counts = new Map<IntuneBusinessCategory, { total: number; failed: number; succeeded: number }>();

  for (const category of BUSINESS_CATEGORIES) {
    counts.set(category, { total: 0, failed: 0, succeeded: 0 });
  }

  for (const event of events) {
    const category = getBusinessCategory(event.eventType);
    const stat = counts.get(category)!;
    stat.total += 1;
    if (event.status === "Failed" || event.status === "Timeout") {
      stat.failed += 1;
    } else if (event.status === "Success") {
      stat.succeeded += 1;
    }
  }

  return BUSINESS_CATEGORIES.map((category) => ({
    category,
    ...counts.get(category)!,
  }));
}

export function CategoryCards({ events }: { events: IntuneEvent[] }) {
  const drillIntoCategory = useIntuneStore((s) => s.drillIntoCategory);
  const stats = useMemo(() => computeCategoryStats(events), [events]);
  const nonEmptyStats = stats.filter((s) => s.total > 0);
  const emptyStats = stats.filter((s) => s.total === 0);

  if (events.length === 0) {
    return (
      <div
        style={{
          padding: "20px",
          color: tokens.colorNeutralForeground3,
          textAlign: "center",
          fontSize: "13px",
        }}
      >
        No Intune events available to categorize.
      </div>
    );
  }

  return (
    <div style={{ padding: "16px", overflow: "auto", height: "100%" }}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: "12px",
          maxWidth: "900px",
        }}
      >
        {nonEmptyStats.map((stat) => {
          const display = CATEGORY_DISPLAY[stat.category];
          const successRate =
            stat.total > 0
              ? Math.round((stat.succeeded / stat.total) * 100)
              : 0;

          return (
            <button
              key={stat.category}
              onClick={() => drillIntoCategory(stat.category)}
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "8px",
                padding: "14px 16px",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "8px",
                backgroundColor: tokens.colorNeutralBackground1,
                cursor: "pointer",
                textAlign: "left",
                transition: "border-color 0.15s, box-shadow 0.15s",
                borderLeft: `4px solid ${display.color}`,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = display.color;
                e.currentTarget.style.boxShadow = `0 2px 8px ${display.color}22`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = tokens.colorNeutralStroke2;
                e.currentTarget.style.borderLeftColor = display.color;
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <span style={{ fontSize: "18px" }}>{display.icon}</span>
                <span
                  style={{
                    fontSize: "14px",
                    fontWeight: 600,
                    color: tokens.colorNeutralForeground1,
                  }}
                >
                  {display.label}
                </span>
              </div>

              <div
                style={{
                  display: "flex",
                  gap: "12px",
                  alignItems: "baseline",
                }}
              >
                <span
                  style={{
                    fontSize: "24px",
                    fontWeight: 700,
                    color: tokens.colorNeutralForeground1,
                    lineHeight: 1,
                  }}
                >
                  {stat.total}
                </span>
                <span
                  style={{
                    fontSize: "11px",
                    color: tokens.colorNeutralForeground3,
                  }}
                >
                  event{stat.total !== 1 ? "s" : ""}
                </span>
              </div>

              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  fontSize: "11px",
                  fontWeight: 500,
                }}
              >
                {stat.failed > 0 && (
                  <span style={{ color: "#ef4444" }}>
                    {stat.failed} failed
                  </span>
                )}
                {stat.succeeded > 0 && (
                  <span style={{ color: "#22c55e" }}>
                    {stat.succeeded} success
                  </span>
                )}
                <span style={{ color: tokens.colorNeutralForeground3 }}>
                  {successRate}% success rate
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {emptyStats.length > 0 && (
        <div
          style={{
            marginTop: "16px",
            display: "flex",
            gap: "8px",
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <span
            style={{
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
              fontWeight: 600,
              textTransform: "uppercase",
            }}
          >
            No activity:
          </span>
          {emptyStats.map((stat) => {
            const display = CATEGORY_DISPLAY[stat.category];
            return (
              <span
                key={stat.category}
                style={{
                  fontSize: "11px",
                  color: tokens.colorNeutralForeground3,
                  backgroundColor: tokens.colorNeutralBackground3,
                  padding: "2px 8px",
                  borderRadius: "999px",
                }}
              >
                {display.icon} {display.label}
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}
