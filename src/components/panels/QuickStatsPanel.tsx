import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { Badge, Text, tokens } from "@fluentui/react-components";
import {
  ArrowSortDownRegular,
  ArrowSortUpRegular,
  ChevronDownRegular,
  ChevronUpRegular,
} from "@fluentui/react-icons";
import { useQuickStats } from "../../hooks/use-quick-stats";

type SortKey = "hex" | "description" | "category" | "count";
type SortDir = "asc" | "desc";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
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

  const setFilteredIds = useFilterStore((s) => s.setFilteredIds);
  const clearFilter = useFilterStore((s) => s.clearFilter);
  const entries = useLogStore((s) => s.entries);

  // Track which severity is actively filtered via stat cards (local state,
  // kept separate from the clause-based filter system to avoid the heavy IPC path).
  const [activeSeverity, setActiveSeverity] = useState<string | null>(null);

  // Clear local severity state when an external action clears all filters
  const hasActiveFilter = useFilterStore((s) => s.hasActiveFilter);
  useEffect(() => {
    if (!hasActiveFilter() && activeSeverity !== null) {
      setActiveSeverity(null);
    }
  }, [hasActiveFilter, activeSeverity]);

  const handleSeverityClick = useCallback(
    (severity: string) => {
      if (activeSeverity === severity) {
        // Toggle off
        setActiveSeverity(null);
        clearFilter();
      } else {
        // Compute filtered IDs directly on the frontend — no IPC needed
        const ids = new Set<number>();
        for (const entry of entries) {
          if (entry.severity === severity) {
            ids.add(entry.id);
          }
        }
        setActiveSeverity(severity);
        setFilteredIds(ids);
      }
    },
    [activeSeverity, entries, clearFilter, setFilteredIds]
  );

  // Error code table sorting
  const [sortKey, setSortKey] = useState<SortKey>("count");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const handleSort = useCallback((key: SortKey) => {
    setSortKey((prev) => {
      if (prev === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        return key;
      }
      setSortDir(key === "count" ? "desc" : "asc");
      return key;
    });
  }, []);

  const sortedErrorCodes = useMemo(() => {
    const codes = [...stats.errorCodes];
    codes.sort((a, b) => {
      let cmp: number;
      switch (sortKey) {
        case "hex":
          cmp = a.hex.localeCompare(b.hex);
          break;
        case "description":
          cmp = (a.description || "").localeCompare(b.description || "");
          break;
        case "category":
          cmp = (a.category || "").localeCompare(b.category || "");
          break;
        case "count":
          cmp = a.count - b.count;
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return codes;
  }, [stats.errorCodes, sortKey, sortDir]);

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
              gap: "8px",
              flexWrap: "wrap",
            }}
          >
            <StatCard
              label="Errors"
              value={stats.bySeverity.error}
              color="error"
              active={activeSeverity === "Error"}
              onClick={() => handleSeverityClick("Error")}
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
              active={activeSeverity === "Warning"}
              onClick={() => handleSeverityClick("Warning")}
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
              active={activeSeverity === "Info"}
              onClick={() => handleSeverityClick("Info")}
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
                      <SortableTh sortKey="hex" currentKey={sortKey} dir={sortDir} onClick={handleSort} style={{ width: "120px" }}>Code</SortableTh>
                      <SortableTh sortKey="description" currentKey={sortKey} dir={sortDir} onClick={handleSort}>Description</SortableTh>
                      <SortableTh sortKey="category" currentKey={sortKey} dir={sortDir} onClick={handleSort} style={{ width: "130px" }}>Category</SortableTh>
                      <SortableTh sortKey="count" currentKey={sortKey} dir={sortDir} onClick={handleSort} style={{ width: "70px", textAlign: "right" }}>Count</SortableTh>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedErrorCodes.map((err) => (
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

function SortableTh({
  sortKey: key,
  currentKey,
  dir,
  onClick,
  style,
  children,
}: {
  sortKey: SortKey;
  currentKey: SortKey;
  dir: SortDir;
  onClick: (key: SortKey) => void;
  style?: React.CSSProperties;
  children: React.ReactNode;
}) {
  const isActive = currentKey === key;
  return (
    <th
      onClick={(e) => { e.stopPropagation(); onClick(key); }}
      style={{
        padding: "6px 10px",
        textAlign: "left",
        fontWeight: 600,
        color: isActive ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground2,
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        whiteSpace: "nowrap",
        cursor: "default",
        userSelect: "none",
        position: "relative",
        zIndex: 2,
        ...style,
      }}
    >
      <span style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
        {children}
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onClick(key); }}
          title={`Sort by ${typeof children === "string" ? children : key}`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1px 2px",
            border: `1px solid ${isActive ? tokens.colorNeutralStroke1 : tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            background: isActive ? tokens.colorNeutralBackground1 : "transparent",
            cursor: "pointer",
            color: isActive ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground3,
            fontSize: "10px",
            lineHeight: 1,
          }}
        >
          {isActive
            ? (dir === "asc" ? <ArrowSortUpRegular style={{ fontSize: "10px" }} /> : <ArrowSortDownRegular style={{ fontSize: "10px" }} />)
            : <ArrowSortDownRegular style={{ fontSize: "10px" }} />}
        </button>
      </span>
    </th>
  );
}

const tdStyle: React.CSSProperties = {
  padding: "4px 10px",
};
