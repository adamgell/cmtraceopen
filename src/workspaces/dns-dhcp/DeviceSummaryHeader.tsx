import { Badge, tokens } from "@fluentui/react-components";
import type { Device } from "./types";

function formatTimestamp(ts: number): string {
  if (ts === 0) return "--";
  return new Date(ts).toLocaleString();
}

export function DeviceSummaryHeader({ device }: { device: Device }) {
  const displayName = device.hostname ?? device.ip;

  return (
    <div
      style={{
        padding: "12px 16px",
        backgroundColor: tokens.colorNeutralBackground2,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "12px",
      }}
    >
      {/* Identity */}
      <div style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
        <span
          style={{
            fontWeight: 600,
            fontSize: "14px",
            color: tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={displayName}
        >
          {displayName}
        </span>
        {device.hostname && (
          <span
            style={{
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
            }}
          >
            {device.ip}
            {device.mac && ` \u00B7 ${device.mac}`}
          </span>
        )}
        {!device.hostname && device.mac && (
          <span
            style={{
              fontSize: "12px",
              color: tokens.colorNeutralForeground3,
            }}
          >
            {device.mac}
          </span>
        )}
      </div>

      {/* Separator */}
      <div
        style={{
          width: 1,
          height: 28,
          backgroundColor: tokens.colorNeutralStroke2,
        }}
      />

      {/* Stats */}
      <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
        <StatItem label="Queries" value={device.totalQueries.toLocaleString()} />

        {device.nxdomainCount > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
              NXDOMAIN
            </span>
            <Badge appearance="filled" color="warning" size="small">
              {device.nxdomainCount}
            </Badge>
          </div>
        )}

        {device.servfailCount > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
              SERVFAIL
            </span>
            <Badge appearance="filled" color="danger" size="small">
              {device.servfailCount}
            </Badge>
          </div>
        )}

        {device.dhcpEntries.length > 0 && (
          <StatItem label="DHCP" value={device.dhcpEntries.length.toLocaleString()} />
        )}

        <StatItem label="First seen" value={formatTimestamp(device.firstSeen)} />
        <StatItem label="Last seen" value={formatTimestamp(device.lastSeen)} />
      </div>
    </div>
  );
}

function StatItem({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
      <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
        {label}
      </span>
      <span style={{ fontSize: "12px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
        {value}
      </span>
    </div>
  );
}
