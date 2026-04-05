import { tokens } from "@fluentui/react-components";
import { useSysmonStore } from "../../stores/sysmon-store";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

export function SysmonConfigView() {
  const config = useSysmonStore((s) => s.config);

  if (!config || !config.found) {
    return (
      <div style={{ padding: "24px", color: tokens.colorNeutralForeground3 }}>
        No Sysmon configuration data found in the analyzed events.
      </div>
    );
  }

  return (
    <div style={{ padding: "16px 24px", overflow: "auto", height: "100%" }}>
      <h3 style={{ margin: "0 0 16px 0", fontSize: "16px", fontWeight: 600 }}>
        Sysmon Configuration
      </h3>

      {/* Config metadata */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "180px 1fr",
          gap: "4px 16px",
          marginBottom: "24px",
          fontSize: "13px",
        }}
      >
        {config.schemaVersion && (
          <>
            <span style={labelStyle}>Schema Version</span>
            <span>{config.schemaVersion}</span>
          </>
        )}
        {config.sysmonVersion && (
          <>
            <span style={labelStyle}>Sysmon Version</span>
            <span>{config.sysmonVersion}</span>
          </>
        )}
        {config.hashAlgorithms && (
          <>
            <span style={labelStyle}>Hash Algorithms</span>
            <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>{config.hashAlgorithms}</span>
          </>
        )}
        {config.lastConfigChange && (
          <>
            <span style={labelStyle}>Last Config Change</span>
            <span>{config.lastConfigChange}</span>
          </>
        )}
      </div>

      {/* Active event types */}
      {config.activeEventTypes.length > 0 && (
        <div style={{ marginBottom: "24px" }}>
          <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", fontWeight: 600 }}>
            Active Event Types (observed in data)
          </h4>
          <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
            <p style={{ margin: "0 0 8px 0", color: tokens.colorNeutralForeground3 }}>
              These event types were found in the analyzed EVTX files, indicating they are enabled
              in the Sysmon configuration.
            </p>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "6px",
              }}
            >
              {config.activeEventTypes.map((et) => (
                <span
                  key={et.eventId}
                  style={{
                    padding: "3px 10px",
                    backgroundColor: tokens.colorNeutralBackground3,
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    borderRadius: "12px",
                    fontSize: "11px",
                  }}
                >
                  ID {et.eventId}: {et.displayName} ({et.count.toLocaleString()})
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Configuration XML if available */}
      {config.configurationXml && (
        <div>
          <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", fontWeight: 600 }}>
            Configuration Details (from Event ID 16)
          </h4>
          <pre
            style={{
              padding: "12px",
              backgroundColor: tokens.colorNeutralBackground3,
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "4px",
              fontSize: "11px",
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              overflow: "auto",
              maxHeight: "400px",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {config.configurationXml}
          </pre>
        </div>
      )}
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontWeight: 600,
  color: tokens.colorNeutralForeground3,
};
