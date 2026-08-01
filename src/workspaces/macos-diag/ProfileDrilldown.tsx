import { useMemo } from "react";
import {
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { parsePayloadData, getPayloadTypeInfo } from "../../lib/profile-utils";
import type { MacosMdmProfile } from "./types";

const useStyles = makeStyles({
  body: {
    ...shorthands.padding("0px", "12px", "12px"),
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  payloadType: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "10.5px",
    color: tokens.colorBrandForeground1,
    backgroundColor: tokens.colorPaletteBlueBackground2,
    ...shorthands.padding("1px", "6px"),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
  },
  metadataGrid: {
    display: "grid",
    gridTemplateColumns: "auto 1fr",
    gap: "4px 12px",
    marginBottom: "12px",
    ...shorthands.padding("10px", "0px"),
  },
  metadataLabel: {
    fontSize: "11px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    whiteSpace: "nowrap" as const,
  },
  metadataValue: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground1,
    fontFamily: tokens.fontFamilyMonospace,
    wordBreak: "break-all" as const,
  },
  payloadCard: {
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding("10px", "12px"),
    marginBottom: "6px",
  },
  payloadHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "4px",
  },
  payloadName: {
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  payloadId: {
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground3,
    marginTop: "2px",
  },
  payloadDataBlock: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11px",
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    ...shorthands.padding("8px", "10px"),
    marginTop: "8px",
    whiteSpace: "pre-wrap" as const,
    wordBreak: "break-all" as const,
    lineHeight: "1.5",
    color: tokens.colorNeutralForeground1,
    overflowX: "auto" as const,
  },
  payloadsHeader: {
    fontSize: "11px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    marginBottom: "8px",
    ...shorthands.padding("8px", "0px", "4px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  settingsTable: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    overflow: "hidden",
  },
  settingsTarget: {
    ...shorthands.padding("6px", "10px"),
    backgroundColor: tokens.colorNeutralBackground3,
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground3,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  settingsHeader: {
    textAlign: "left" as const,
    ...shorthands.padding("6px", "10px"),
    backgroundColor: tokens.colorNeutralBackground3,
    fontSize: "10.5px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  settingsRow: {
    ":hover": {
      backgroundColor: tokens.colorNeutralBackground3,
    },
  },
  settingKey: {
    ...shorthands.padding("4px", "10px"),
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    whiteSpace: "nowrap" as const,
    verticalAlign: "top" as const,
  },
  settingValue: {
    ...shorthands.padding("4px", "10px"),
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    wordBreak: "break-all" as const,
  },
  boolTrue: {
    color: tokens.colorPaletteGreenForeground1,
    fontWeight: 600,
  },
  boolFalse: {
    color: tokens.colorNeutralForeground3,
  },
  arrayValue: {
    color: tokens.colorBrandForeground1,
  },
  settingDesc: {
    display: "block",
    fontSize: "10px",
    color: tokens.colorNeutralForeground3,
    fontFamily: tokens.fontFamilyBase,
    fontStyle: "italic" as const,
    marginTop: "1px",
  },
  payloadTypeInfo: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic" as const,
    ...shorthands.padding("4px", "12px", "8px"),
  },
});

export interface ProfileDrilldownProps {
  profile: MacosMdmProfile;
}

export function ProfileDrilldown({ profile }: ProfileDrilldownProps) {
  const styles = useStyles();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  return (
    <div className={styles.body}>
      {/* Metadata Grid */}
      <div className={styles.metadataGrid}>
        {profile.profileOrganization && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Organization</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.profileOrganization}</span>
          </>
        )}
        {profile.description && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Description</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.description}</span>
          </>
        )}
        {profile.source && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Source</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.source}</span>
          </>
        )}
        {profile.verificationState && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Verified</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.verificationState}</span>
          </>
        )}
        {profile.removalDisallowed != null && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Removal</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.removalDisallowed ? "Disallowed" : "Allowed"}</span>
          </>
        )}
        {profile.installDate && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>Installed</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.installDate}</span>
          </>
        )}
        {profile.profileUuid && (
          <>
            <span className={styles.metadataLabel} style={{ fontSize: metrics.fontSize - 2 }}>UUID</span>
            <span className={styles.metadataValue} style={{ fontSize: metrics.fontSize - 1 }}>{profile.profileUuid}</span>
          </>
        )}
      </div>

      {/* Payloads */}
      {profile.payloads.length > 0 && (
        <>
          <div className={styles.payloadsHeader}>
            Payloads ({profile.payloads.length})
          </div>
          {profile.payloads.map((payload) => (
            <div key={payload.payloadIdentifier} className={styles.payloadCard}>
              <div className={styles.payloadHeader}>
                <span className={styles.payloadName} style={{ fontSize: metrics.fontSize }}>
                  {getPayloadTypeInfo(payload.payloadType)?.friendlyName ?? payload.payloadDisplayName ?? payload.payloadType}
                </span>
                <span className={styles.payloadType}>
                  {payload.payloadType}
                </span>
              </div>
              <div className={styles.payloadId} style={{ fontSize: metrics.fontSize - 2 }}>
                {payload.payloadIdentifier}
              </div>
              {(() => {
                const typeInfo = getPayloadTypeInfo(payload.payloadType);
                return typeInfo ? (
                  <div className={styles.payloadTypeInfo} style={{ fontSize: metrics.fontSize - 2 }}>
                    {typeInfo.description}
                  </div>
                ) : null;
              })()}
              {payload.payloadData && (() => {
                const parsed = parsePayloadData(payload.payloadData);
                if (parsed.entries.length === 0) {
                  return (
                    <div
                      className={styles.payloadDataBlock}
                      style={{ fontSize: Math.max(10, metrics.fontSize - 2) }}
                    >
                      {payload.payloadData}
                    </div>
                  );
                }
                return (
                  <div className={styles.settingsTable} style={{ marginTop: "8px" }}>
                    {parsed.appTarget && (
                      <div className={styles.settingsTarget} style={{ fontSize: metrics.fontSize - 2 }}>
                        Target: <span style={{ fontWeight: 600 }}>{parsed.appTarget}</span>
                      </div>
                    )}
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          <th className={styles.settingsHeader} style={{ fontSize: metrics.fontSize - 2 }}>Setting</th>
                          <th className={styles.settingsHeader} style={{ fontSize: metrics.fontSize - 2 }}>Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {parsed.entries.map((entry) => (
                          <tr key={entry.key} className={styles.settingsRow}>
                            <td className={styles.settingKey} style={{ fontSize: metrics.fontSize - 1 }}>
                              {entry.key}
                              {entry.description && (
                                <span className={styles.settingDesc}>{entry.description}</span>
                              )}
                            </td>
                            <td className={styles.settingValue} style={{ fontSize: metrics.fontSize - 1 }}>
                              {entry.type === "boolean" ? (
                                <span className={entry.value === "1" ? styles.boolTrue : styles.boolFalse}>
                                  {entry.value === "1" ? "Yes" : "No"}
                                </span>
                              ) : entry.type === "array" ? (
                                <span className={styles.arrayValue}>{entry.value}</span>
                              ) : (
                                entry.value
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              })()}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
