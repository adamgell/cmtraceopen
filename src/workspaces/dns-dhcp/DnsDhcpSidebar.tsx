import { Switch, tokens } from "@fluentui/react-components";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { SourceSummaryCard, SectionHeader } from "../../components/common/sidebar-primitives";

function formatBadgeText(format: string): string {
  switch (format) {
    case "DnsDebug":
      return "DNS Debug";
    case "DnsAudit":
      return "DNS Audit";
    default:
      return format;
  }
}

export function DnsDhcpSidebar() {
  const sources = useDnsDhcpStore((s) => s.sources);
  const devices = useDnsDhcpStore((s) => s.devices);
  const toggleSource = useDnsDhcpStore((s) => s.toggleSource);
  const loadError = useDnsDhcpStore((s) => s.loadError);

  const totalEntries = sources
    .filter((s) => s.enabled)
    .reduce((sum, s) => sum + s.entryCount, 0);
  const enrichedCount = devices.filter((d) => d.isEnriched).length;

  const subtitle =
    sources.length > 0
      ? `${sources.length} source${sources.length === 1 ? "" : "s"}`
      : "Open DNS or DHCP logs to begin.";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <SourceSummaryCard
        badge="dns-dhcp"
        title="DNS / DHCP"
        subtitle={subtitle}
        body={
          <div
            style={{
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {loadError && (
              <div style={{ color: tokens.colorPaletteRedForeground2 }}>
                {loadError}
              </div>
            )}
            {sources.length > 0 && (
              <>
                <div>Events: {totalEntries.toLocaleString()}</div>
                <div>Devices: {devices.length.toLocaleString()}</div>
                {enrichedCount > 0 && (
                  <div>Enriched: {enrichedCount.toLocaleString()}</div>
                )}
              </>
            )}
            {sources.length === 0 && !loadError && <div>Ready</div>}
          </div>
        }
      />

      {sources.length > 0 && (
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <SectionHeader title="Sources" />
          <div style={{ flex: 1, overflowY: "auto" }}>
            {sources.map((source) => (
              <div
                key={source.path}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "8px 12px",
                  borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
                  gap: "8px",
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: "12px",
                      fontWeight: 600,
                      color: source.enabled
                        ? tokens.colorNeutralForeground1
                        : tokens.colorNeutralForeground4,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={source.path}
                  >
                    {source.fileName}
                  </div>
                  <div
                    style={{
                      fontSize: "11px",
                      color: tokens.colorNeutralForeground3,
                      marginTop: "2px",
                    }}
                  >
                    {formatBadgeText(source.format)} &middot;{" "}
                    {source.entryCount.toLocaleString()} entries
                  </div>
                </div>
                <Switch
                  checked={source.enabled}
                  onChange={() => toggleSource(source.path)}
                  style={{ flexShrink: 0 }}
                />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
