import { Card, CardHeader, Body1, Caption1, Subtitle2 } from "@fluentui/react-components";
import { useJamfStore } from "./jamf-store";

function formatBool(b: boolean) {
  return b ? "Yes" : "No";
}

// The backend sends a UTC instant; show it in the reader's own zone rather than
// printing a raw ISO string that looks like local time but is not.
function formatTimestamp(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function MacosJamfOverviewTab() {
  const env = useJamfStore((s) => s.environment.data);
  const status = useJamfStore((s) => s.environment.status);
  const error = useJamfStore((s) => s.environment.error);
  // Distinguish failure from loading; the banner above carries the retry.
  if (status === "error") {
    return <div>Failed to load JAMF environment{error ? `: ${error}` : "."}</div>;
  }
  if (status === "loading" || !env) return <div>Loading...</div>;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
      <Card>
        <CardHeader header={<Subtitle2>JAMF Pro</Subtitle2>} />
        <Body1>
          <div>Binary: {formatBool(env.jamfInstalled)}</div>
          <div>Version: {env.jamfVersion ?? "-"}</div>
          <div>JSS URL: {env.jssUrl ?? "-"}</div>
          <div>Last check-in: {formatTimestamp(env.lastCheckIn)}</div>
          <div>MDM profile: {formatBool(env.mdmProfilePresent)}</div>
          <div>MDM org: {env.mdmOrganization ?? "-"}</div>
        </Body1>
      </Card>
      <Card>
        <CardHeader header={<Subtitle2>JAMF Connect</Subtitle2>} />
        <Body1>
          <div>Installed: {formatBool(env.jamfConnectInstalled)}</div>
          <div>Version: {env.jamfConnectVersion ?? "-"}</div>
          <div>IdP: {env.jamfConnectIdp ?? "-"}</div>
        </Body1>
      </Card>
      <Card>
        <CardHeader header={<Subtitle2>Environment</Subtitle2>} />
        <Body1>
          <div>FDA: {env.fdaStatus}</div>
          <Caption1>
            Detected paths: {Object.entries(env.directories)
              .filter(([, v]) => v)
              .map(([k]) => k)
              .join(", ") || "none"}
          </Caption1>
        </Body1>
      </Card>
    </div>
  );
}
