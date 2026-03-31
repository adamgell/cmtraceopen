import { tokens } from "@fluentui/react-components";
import { useSysmonStore } from "../../stores/sysmon-store";
import { DashboardMetricCards } from "./DashboardMetricCards";
import { DashboardTimeline } from "./DashboardTimeline";
import { DashboardEventTypeChart } from "./DashboardEventTypeChart";
import { DashboardSecurityAlerts } from "./DashboardSecurityAlerts";
import { DashboardTopList } from "./DashboardTopList";

export function SysmonDashboardView() {
  const summary = useSysmonStore((s) => s.summary);
  const dashboard = useSysmonStore((s) => s.dashboard);

  if (!summary || !dashboard) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
        }}
      >
        No dashboard data available.
      </div>
    );
  }

  return (
    <div
      style={{
        height: "100%",
        overflow: "auto",
        padding: "16px",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      {/* Hero metric cards — full width above grid */}
      <DashboardMetricCards summary={summary} />

      {/* Main grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(400px, 1fr))",
          gap: "16px",
          alignItems: "start",
        }}
      >
        {/* Timeline spans full width */}
        <DashboardTimeline dashboard={dashboard} />

        {/* Donut + Security stacked left, Top Processes right */}
        <div style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", alignItems: "start" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <DashboardEventTypeChart summary={summary} />
            <DashboardSecurityAlerts securityEvents={dashboard.securityEvents} />
          </div>
          <DashboardTopList
            title="Top Processes"
            items={dashboard.topProcesses}
            emptyMessage="No process data available."
            color={tokens.colorBrandBackground}
          />
        </div>
        {/* Network, DNS, Ports on same row */}
        <div style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px" }}>
          <DashboardTopList
            title="Network Destinations"
            items={dashboard.topDestinations}
            emptyMessage="No network destination data available."
            color={tokens.colorPaletteTealBackground2}
          />
          <DashboardTopList
            title="DNS Queries"
            items={dashboard.topDnsQueries}
            emptyMessage="No DNS query data available."
            color={tokens.colorPaletteGreenBackground2}
          />
          <DashboardTopList
            title="Top Ports"
            items={dashboard.topPorts}
            emptyMessage="No port data available."
            color={tokens.colorPalettePurpleBackground2}
          />
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <DashboardTopList
            title="File Activity"
            items={dashboard.topTargetFiles}
            emptyMessage="No file activity data available."
            color={tokens.colorPaletteMarigoldBackground2}
          />
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <DashboardTopList
            title="Registry Activity"
            items={dashboard.topRegistryKeys}
            emptyMessage="No registry activity data available."
            color={tokens.colorPaletteCranberryBackground2}
          />
        </div>
      </div>
    </div>
  );
}
