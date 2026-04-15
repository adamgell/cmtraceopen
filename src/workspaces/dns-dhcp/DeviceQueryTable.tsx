import { useMemo, useRef } from "react";
import { Dropdown, Option, tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { LogEntry } from "../../types/log";
import type { Device } from "./types";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";

const RCODE_OPTIONS = ["All", "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"] as const;
const QTYPE_OPTIONS = ["All", "A", "AAAA", "SOA", "NS", "PTR", "SRV", "CNAME", "MX", "TXT"] as const;

const COLUMNS = [
  { key: "time", label: "Time", width: 170 },
  { key: "queryName", label: "Query Name", width: 260 },
  { key: "type", label: "Type", width: 60 },
  { key: "rcode", label: "RCODE", width: 100 },
  { key: "dir", label: "Dir", width: 45 },
  { key: "proto", label: "Proto", width: 50 },
  { key: "flags", label: "Flags", width: 80 },
] as const;

function getRcodeColor(rcode: string | null | undefined): {
  color: string;
  bold: boolean;
} {
  if (!rcode) return { color: tokens.colorNeutralForeground1, bold: false };
  const upper = rcode.toUpperCase();
  if (
    upper === "SERVFAIL" ||
    upper === "SERVER_FAILURE" ||
    upper === "REFUSED" ||
    upper === "FORMERR" ||
    upper === "FORMAT_ERROR"
  ) {
    return { color: tokens.colorPaletteRedForeground2, bold: true };
  }
  if (upper === "NXDOMAIN" || upper === "NAME_ERROR") {
    return { color: tokens.colorPaletteYellowForeground2, bold: true };
  }
  return { color: tokens.colorNeutralForeground1, bold: false };
}

function formatTime(ts: number | null): string {
  if (ts === null) return "--";
  return new Date(ts).toLocaleString();
}

export function DeviceQueryTable({ device }: { device: Device }) {
  const rcodeFilter = useDnsDhcpStore((s) => s.rcodeFilter);
  const qtypeFilter = useDnsDhcpStore((s) => s.qtypeFilter);
  const setRcodeFilter = useDnsDhcpStore((s) => s.setRcodeFilter);
  const setQtypeFilter = useDnsDhcpStore((s) => s.setQtypeFilter);
  const fontSize = useUiStore((s) => s.logListFontSize);
  const metrics = getLogListMetrics(fontSize);

  const parentRef = useRef<HTMLDivElement>(null);

  const filteredEntries = useMemo(() => {
    let entries: LogEntry[] = device.allEntries;

    if (rcodeFilter !== "All") {
      entries = entries.filter((e) => {
        const rc = e.responseCode?.toUpperCase();
        const filter = rcodeFilter.toUpperCase();
        if (filter === "NXDOMAIN") return rc === "NXDOMAIN" || rc === "NAME_ERROR";
        if (filter === "SERVFAIL") return rc === "SERVFAIL" || rc === "SERVER_FAILURE";
        if (filter === "FORMERR") return rc === "FORMERR" || rc === "FORMAT_ERROR";
        return rc === filter;
      });
    }

    if (qtypeFilter !== "All") {
      entries = entries.filter(
        (e) => e.queryType?.toUpperCase() === qtypeFilter.toUpperCase()
      );
    }

    return entries;
  }, [device.allEntries, rcodeFilter, qtypeFilter]);

  const virtualizer = useVirtualizer({
    count: filteredEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => metrics.rowHeight,
    overscan: 20,
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "6px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          fontSize: "12px",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span style={{ color: tokens.colorNeutralForeground3 }}>RCODE</span>
          <Dropdown
            size="small"
            value={rcodeFilter}
            selectedOptions={[rcodeFilter]}
            onOptionSelect={(_, data) => setRcodeFilter(data.optionValue ?? "All")}
            style={{ minWidth: 110 }}
          >
            {RCODE_OPTIONS.map((opt) => (
              <Option key={opt} value={opt}>
                {opt}
              </Option>
            ))}
          </Dropdown>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span style={{ color: tokens.colorNeutralForeground3 }}>QTYPE</span>
          <Dropdown
            size="small"
            value={qtypeFilter}
            selectedOptions={[qtypeFilter]}
            onOptionSelect={(_, data) => setQtypeFilter(data.optionValue ?? "All")}
            style={{ minWidth: 90 }}
          >
            {QTYPE_OPTIONS.map((opt) => (
              <Option key={opt} value={opt}>
                {opt}
              </Option>
            ))}
          </Dropdown>
        </div>

        <span style={{ color: tokens.colorNeutralForeground3, marginLeft: "auto" }}>
          {filteredEntries.length.toLocaleString()} entries
        </span>
      </div>

      {/* Column headers */}
      <div
        style={{
          display: "flex",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          fontSize: `${metrics.headerFontSize}px`,
          lineHeight: `${metrics.headerLineHeight}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground3,
          paddingLeft: "8px",
        }}
      >
        {COLUMNS.map((col) => (
          <div
            key={col.key}
            style={{
              width: col.width,
              minWidth: col.width,
              padding: "0 4px",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {col.label}
          </div>
        ))}
      </div>

      {/* Virtual rows */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div
          style={{
            height: virtualizer.getTotalSize(),
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const entry = filteredEntries[virtualRow.index];
            const rcodeStyle = getRcodeColor(entry.responseCode);

            return (
              <div
                key={virtualRow.key}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                  display: "flex",
                  alignItems: "center",
                  fontSize: `${metrics.fontSize}px`,
                  lineHeight: `${metrics.rowLineHeight}px`,
                  color: rcodeStyle.color,
                  borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
                  paddingLeft: "8px",
                }}
              >
                <div
                  style={{
                    width: 170,
                    minWidth: 170,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {formatTime(entry.timestamp)}
                </div>
                <div
                  style={{
                    width: 260,
                    minWidth: 260,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={entry.queryName ?? entry.message ?? undefined}
                >
                  {entry.queryName ?? entry.message ?? "--"}
                </div>
                <div
                  style={{
                    width: 60,
                    minWidth: 60,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {entry.queryType ?? "--"}
                </div>
                <div
                  style={{
                    width: 100,
                    minWidth: 100,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontWeight: rcodeStyle.bold ? 700 : 400,
                  }}
                >
                  {entry.responseCode ?? "--"}
                </div>
                <div
                  style={{
                    width: 45,
                    minWidth: 45,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {entry.dnsDirection ?? "--"}
                </div>
                <div
                  style={{
                    width: 50,
                    minWidth: 50,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {entry.dnsProtocol ?? "--"}
                </div>
                <div
                  style={{
                    width: 80,
                    minWidth: 80,
                    padding: "0 4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {entry.dnsFlags ?? "--"}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
