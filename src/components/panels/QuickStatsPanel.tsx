import { memo, useCallback, useEffect, useState } from "react";
import { Badge, Text, tokens } from "@fluentui/react-components";
import { ChevronDownRegular, ChevronUpRegular } from "@fluentui/react-icons";
import { useQuickStats } from "../../hooks/use-quick-stats";
import { useUiStore } from "../../stores/ui-store";
import { StatCard } from "./quick-stats/StatCard";
import { getCategoryColor } from "../../lib/error-categories";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

export interface QuickStatsPanelProps {
  isExpanded?: boolean;
  onToggle?: (expanded: boolean) => void;
}

export const QuickStatsPanel = memo(function QuickStatsPanel({
  isExpanded: controlledExpanded,
  onToggle,
}: QuickStatsPanelProps) {
  const [internalExpanded, setInternalExpanded] = useState(false);
  const isExpanded = controlledExpanded ?? internalExpanded;

  const stats = useQuickStats();

  const setShowErrorLookupDialog = useUiStore((s) => s.setShowErrorLookupDialog);
  const setLookupErrorCode = useUiStore((s) => s.setLookupErrorCode);

  const handleToggle = useCallback(() => {
    const newExpanded = !isExpanded;
    if (onToggle) {
      onToggle(newExpanded);
    } else {
      setInternalExpanded(newExpanded);
    }
  }, [isExpanded, onToggle]);

  const handleErrorCodeClick = (hex: string) => {
    setLookupErrorCode(hex);
    setShowErrorLookupDialog(true);
  };

  const handleRowKeyDown = (e: React.KeyboardEvent, hex: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleErrorCodeClick(hex);
    }
  };

  // Auto-collapse when no log is open
  useEffect(() => {
    if (stats.isEmpty && isExpanded) {
      if (onToggle) {
        onToggle(false);
      } else {
        setInternalExpanded(false);
      }
    }
  }, [stats.isEmpty, isExpanded, onToggle]);

  if (stats.isEmpty) {
    return null;
  }

  return (
    <div
      style={{
        backgroundColor: tokens.colorNeutralBackground1,
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
      }}
    >
      {/* Header bar with collapse toggle */}
      <button
        type="button"
        aria-expanded={isExpanded}
        onClick={handleToggle}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "8px 16px",
          cursor: "pointer",
          userSelect: "none",
          width: "100%",
          border: "none",
          background: "transparent",
          color: "inherit",
          font: "inherit",
          textAlign: "left",
        }}
      >
        {isExpanded ? (
          <ChevronUpRegular
            style={{ color: tokens.colorNeutralForeground3 }}
          />
        ) : (
          <ChevronDownRegular
            style={{ color: tokens.colorNeutralForeground3 }}
          />
        )}
        <Text size={300} style={{ color: tokens.colorNeutralForeground1, fontWeight: 500 }}>
          Quick Stats
        </Text>
        <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
          {stats.totalLines.toLocaleString()} total
          {stats.filteredLineCount !== stats.totalLines
            ? ` (${stats.filteredLineCount.toLocaleString()} filtered)`
            : ""}
        </Text>
      </button>

      {/* Expanded content */}
      {isExpanded && (
        <div
          style={{
            borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            gap: "16px",
          }}
        >
          {/* Severity breakdown */}
          <div
            style={{
              display: "flex",
              gap: "12px",
              flexWrap: "wrap",
            }}
          >
            <StatCard
              label="Errors"
              value={stats.bySeverity.error}
              color="error"
              subtitle={
                stats.filteredLineCount > 0
                  ? `${((stats.bySeverity.error / stats.filteredLineCount) * 100).toFixed(1)}%`
                  : "0%"
              }
            />
            <StatCard
              label="Warnings"
              value={stats.bySeverity.warning}
              color="warning"
              subtitle={
                stats.filteredLineCount > 0
                  ? `${((stats.bySeverity.warning / stats.filteredLineCount) * 100).toFixed(1)}%`
                  : "0%"
              }
            />
            <StatCard
              label="Info"
              value={stats.bySeverity.info}
              color="info"
              subtitle={
                stats.filteredLineCount > 0
                  ? `${((stats.bySeverity.info / stats.filteredLineCount) * 100).toFixed(1)}%`
                  : "0%"
              }
            />
          </div>

          {/* Error code table */}
          {stats.errorCodes.length > 0 && (
            <div>
              <Text size={300} style={{ color: tokens.colorNeutralForeground2, marginBottom: "8px", display: "block" }}>
                Error Codes ({stats.errorCodes.length})
              </Text>
              <div
                style={{
                  maxHeight: "200px",
                  overflowY: "auto",
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  borderRadius: "4px",
                }}
              >
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    fontSize: "12px",
                  }}
                >
                  <thead>
                    <tr
                      style={{
                        backgroundColor: tokens.colorNeutralBackground3,
                        position: "sticky",
                        top: 0,
                        zIndex: 1,
                      }}
                    >
                      <th style={{ ...thStyle, width: "120px" }}>Code</th>
                      <th style={thStyle}>Description</th>
                      <th style={{ ...thStyle, width: "130px" }}>Category</th>
                      <th style={{ ...thStyle, width: "70px", textAlign: "right" }}>Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.errorCodes.map((err) => (
                      <tr
                        key={err.hex}
                        role="button"
                        tabIndex={0}
                        onClick={() => handleErrorCodeClick(err.hex)}
                        onKeyDown={(e) => handleRowKeyDown(e, err.hex)}
                        style={{
                          cursor: "pointer",
                          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = tokens.colorNeutralBackground1Hover;
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = "";
                        }}
                        title="Click to look up this error code"
                      >
                        <td
                          style={{
                            ...tdStyle,
                            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                            color: tokens.colorStatusDangerForeground1,
                            fontWeight: 500,
                          }}
                        >
                          {err.hex}
                        </td>
                        <td
                          style={{
                            ...tdStyle,
                            color: tokens.colorNeutralForeground1,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: "0",
                          }}
                          title={err.description}
                        >
                          {err.description || "Unknown"}
                        </td>
                        <td style={tdStyle}>
                          <Badge
                            appearance="filled"
                            color={getCategoryColor(err.category)}
                            size="small"
                          >
                            {err.category || "Unknown"}
                          </Badge>
                        </td>
                        <td
                          style={{
                            ...tdStyle,
                            textAlign: "right",
                            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                            color: tokens.colorNeutralForeground2,
                          }}
                        >
                          {err.count.toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Time range */}
          {stats.earliestTimestamp != null && stats.latestTimestamp != null && (
            <Text size={200} style={{ color: tokens.colorNeutralForeground3 }}>
              Time Range: {new Date(stats.earliestTimestamp).toLocaleString()} — {new Date(stats.latestTimestamp).toLocaleString()}
            </Text>
          )}
        </div>
      )}
    </div>
  );
});

const thStyle: React.CSSProperties = {
  padding: "6px 10px",
  textAlign: "left",
  fontWeight: 600,
  color: tokens.colorNeutralForeground2,
  borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  whiteSpace: "nowrap",
};

const tdStyle: React.CSSProperties = {
  padding: "5px 10px",
};
