import { tokens } from "@fluentui/react-components";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { DeviceSummaryHeader } from "./DeviceSummaryHeader";
import { DeviceQueryTable } from "./DeviceQueryTable";

export function DeviceDetail() {
  const devices = useDnsDhcpStore((s) => s.devices);
  const selectedDeviceIp = useDnsDhcpStore((s) => s.selectedDeviceIp);

  const device = devices.find((d) => d.ip === selectedDeviceIp) ?? null;

  if (!device) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
        }}
      >
        Select a device to view DNS activity
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <DeviceSummaryHeader device={device} />
      <DeviceQueryTable device={device} />
    </div>
  );
}
