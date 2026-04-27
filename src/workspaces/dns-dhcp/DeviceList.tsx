import { useMemo } from "react";
import { Badge, Input, tokens } from "@fluentui/react-components";
import { Search20Regular } from "@fluentui/react-icons";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";

export function DeviceList() {
  const devices = useDnsDhcpStore((s) => s.devices);
  const selectedDeviceIp = useDnsDhcpStore((s) => s.selectedDeviceIp);
  const selectDevice = useDnsDhcpStore((s) => s.selectDevice);
  const searchQuery = useDnsDhcpStore((s) => s.searchQuery);
  const setSearchQuery = useDnsDhcpStore((s) => s.setSearchQuery);
  const fontSize = useUiStore((s) => s.logListFontSize);
  const metrics = getLogListMetrics(fontSize);

  const filteredDevices = useMemo(() => {
    if (!searchQuery.trim()) return devices;
    const q = searchQuery.toLowerCase();
    return devices.filter(
      (d) =>
        d.ip.toLowerCase().includes(q) ||
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        (d.mac && d.mac.toLowerCase().includes(q))
    );
  }, [devices, searchQuery]);

  return (
    <div
      style={{
        width: 300,
        minWidth: 300,
        maxWidth: 300,
        borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        display: "flex",
        flexDirection: "column",
        height: "100%",
        overflow: "hidden",
      }}
    >
      {/* Search input */}
      <div
        style={{
          padding: "8px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <Input
          size="small"
          placeholder="Search IP, hostname, MAC..."
          value={searchQuery}
          onChange={(_, data) => setSearchQuery(data.value)}
          contentBefore={<Search20Regular />}
          style={{ width: "100%" }}
        />
      </div>

      {/* Device list */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {filteredDevices.length === 0 && (
          <div
            style={{
              padding: "16px",
              color: tokens.colorNeutralForeground3,
              fontSize: `${metrics.fontSize}px`,
              textAlign: "center",
            }}
          >
            {devices.length === 0 ? "No devices loaded" : "No matching devices"}
          </div>
        )}
        {filteredDevices.map((device) => {
          const isSelected = device.ip === selectedDeviceIp;
          const displayName = device.hostname ?? device.ip;

          return (
            <div
              key={device.ip}
              role="button"
              tabIndex={0}
              onClick={() => selectDevice(device.ip)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  selectDevice(device.ip);
                }
              }}
              style={{
                padding: "8px 12px",
                borderLeft: isSelected
                  ? `3px solid ${tokens.colorBrandForeground1}`
                  : "3px solid transparent",
                backgroundColor: isSelected
                  ? tokens.colorNeutralBackground1Selected
                  : "transparent",
                cursor: "pointer",
                borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
                fontSize: `${metrics.fontSize}px`,
                transition: "background-color 0.1s",
              }}
              onMouseEnter={(e) => {
                if (!isSelected) {
                  e.currentTarget.style.backgroundColor =
                    tokens.colorNeutralBackground1Hover;
                }
              }}
              onMouseLeave={(e) => {
                if (!isSelected) {
                  e.currentTarget.style.backgroundColor = "transparent";
                }
              }}
            >
              {/* Row 1: hostname/IP + badges */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "8px",
                }}
              >
                <span
                  style={{
                    fontWeight: 600,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                    opacity: device.hostname ? 1 : 0.7,
                    color: tokens.colorNeutralForeground1,
                  }}
                  title={displayName}
                >
                  {displayName}
                </span>
                <div style={{ display: "flex", gap: "4px", flexShrink: 0 }}>
                  {device.totalQueries > 0 && (
                    <Badge
                      appearance="filled"
                      color="informative"
                      size="small"
                    >
                      {device.totalQueries.toLocaleString()}
                    </Badge>
                  )}
                  {device.servfailCount > 0 && (
                    <Badge appearance="filled" color="danger" size="small">
                      {device.servfailCount}
                    </Badge>
                  )}
                </div>
              </div>

              {/* Row 2: IP and MAC (when enriched) */}
              {device.isEnriched && (
                <div
                  style={{
                    marginTop: "2px",
                    fontSize: `${Math.max(10, metrics.fontSize - 2)}px`,
                    color: tokens.colorNeutralForeground3,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {device.ip}
                  {device.mac && ` \u00B7 ${device.mac}`}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
