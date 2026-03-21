import { useCallback, useEffect, useState } from "react";
import {
  Body1,
  Button,
  makeStyles,
  shorthands,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "../../stores/macos-diag-store";
import { macosListProfiles } from "../../lib/commands";

const useStyles = makeStyles({
  enrollmentCard: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.padding("16px"),
    marginBottom: "16px",
    boxShadow: tokens.shadow2,
    display: "flex",
    gap: "24px",
    alignItems: "center",
    flexWrap: "wrap" as const,
  },
  enrollmentStatus: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  enrollmentDot: {
    width: "10px",
    height: "10px",
    ...shorthands.borderRadius("50%"),
    backgroundColor: "#107c10",
  },
  enrollmentDotNotEnrolled: {
    backgroundColor: "#c42b1c",
  },
  enrollmentLabel: {
    fontSize: "14px",
    fontWeight: 600,
  },
  enrollmentDetail: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
  },
  enrollmentDetailStrong: {
    color: tokens.colorNeutralForeground1,
    fontWeight: 600,
  },
  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "10px",
  },
  sectionTitle: {
    fontSize: "13px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  sectionActions: {
    display: "flex",
    gap: "6px",
  },
  profileList: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  },
  profileCard: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    overflow: "hidden",
    boxShadow: tokens.shadow2,
  },
  profileCardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("12px", "14px"),
    cursor: "pointer",
    transitionProperty: "background",
    transitionDuration: "0.15s",
    ":hover": {
      backgroundColor: tokens.colorNeutralBackground3,
    },
  },
  profileCardName: {
    fontSize: "13px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  profileCardId: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    marginTop: "2px",
  },
  profileCardMeta: {
    display: "flex",
    gap: "8px",
    alignItems: "center",
    flexShrink: 0,
  },
  managedBadge: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: "#e8f0fe",
    color: "#0f6cbd",
  },
  installDate: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
  },
  chevron: {
    color: tokens.colorNeutralForeground3,
    fontSize: "12px",
    transitionProperty: "transform",
    transitionDuration: "0.2s",
  },
  chevronOpen: {
    transform: "rotate(180deg)",
  },
  profileCardBody: {
    ...shorthands.padding("0px", "14px", "14px"),
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  payloadList: {
    marginTop: "10px",
  },
  payloadItem: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("6px", "10px"),
    marginBottom: "4px",
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    fontSize: "12px",
  },
  payloadType: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "10.5px",
    color: tokens.colorBrandForeground1,
    backgroundColor: "#e8f0fe",
    ...shorthands.padding("1px", "6px"),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
  },
  centered: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    ...shorthands.padding("40px"),
  },
  errorText: {
    color: tokens.colorPaletteRedForeground1,
    textAlign: "center" as const,
  },
});

export function MacosDiagProfilesTab() {
  const styles = useStyles();
  const profilesResult = useMacosDiagStore((s) => s.profilesResult);
  const loading = useMacosDiagStore((s) => s.profilesLoading);
  const setProfilesResult = useMacosDiagStore((s) => s.setProfilesResult);
  const setLoading = useMacosDiagStore((s) => s.setProfilesLoading);

  const [expandedProfiles, setExpandedProfiles] = useState<Set<string>>(
    new Set()
  );

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const result = await macosListProfiles();
      setProfilesResult(result);
    } catch (err) {
      console.error("[macos-diag] profiles fetch failed", err);
      setLoading(false);
    }
  }, [setLoading, setProfilesResult]);

  useEffect(() => {
    if (!profilesResult && !loading) {
      fetch();
    }
  }, [profilesResult, loading, fetch]);

  const toggleProfile = (id: string) => {
    setExpandedProfiles((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  if (loading) {
    return (
      <div className={styles.centered}>
        <Spinner size="medium" label="Loading MDM profiles..." />
      </div>
    );
  }

  if (!profilesResult) {
    return (
      <div className={styles.centered}>
        <Body1 className={styles.errorText}>
          No profile data available.
        </Body1>
        <Button appearance="primary" size="small" onClick={fetch}>
          Refresh
        </Button>
      </div>
    );
  }

  const { profiles, enrollmentStatus } = profilesResult;

  return (
    <>
      {/* Enrollment Status Card */}
      <div className={styles.enrollmentCard}>
        <div className={styles.enrollmentStatus}>
          <div
            className={`${styles.enrollmentDot} ${!enrollmentStatus.enrolled ? styles.enrollmentDotNotEnrolled : ""}`}
          />
          <div className={styles.enrollmentLabel}>
            {enrollmentStatus.enrolled
              ? `Enrolled${enrollmentStatus.enrollmentType ? ` via ${enrollmentStatus.enrollmentType}` : ""}`
              : "Not Enrolled"}
          </div>
        </div>
        {enrollmentStatus.mdmServer && (
          <div className={styles.enrollmentDetail}>
            MDM Server:{" "}
            <span className={styles.enrollmentDetailStrong}>
              {enrollmentStatus.mdmServer}
            </span>
          </div>
        )}
        {enrollmentStatus.enrollmentType && (
          <div className={styles.enrollmentDetail}>
            Enrollment Type:{" "}
            <span className={styles.enrollmentDetailStrong}>
              {enrollmentStatus.enrollmentType}
            </span>
          </div>
        )}
      </div>

      {/* Section Header */}
      <div className={styles.sectionHeader}>
        <div className={styles.sectionTitle}>
          Installed Configuration Profiles ({profiles.length})
        </div>
        <div className={styles.sectionActions}>
          <Button size="small" appearance="subtle" onClick={fetch}>
            Refresh
          </Button>
        </div>
      </div>

      {/* Profile List */}
      <div className={styles.profileList}>
        {profiles.map((profile) => {
          const isExpanded = expandedProfiles.has(profile.profileIdentifier);

          return (
            <div key={profile.profileIdentifier} className={styles.profileCard}>
              <div
                className={styles.profileCardHeader}
                onClick={() => toggleProfile(profile.profileIdentifier)}
              >
                <div>
                  <div className={styles.profileCardName}>
                    {profile.profileDisplayName}
                  </div>
                  <div className={styles.profileCardId}>
                    {profile.profileIdentifier}
                  </div>
                </div>
                <div className={styles.profileCardMeta}>
                  {profile.isManaged && (
                    <span className={styles.managedBadge}>Managed</span>
                  )}
                  {profile.installDate && (
                    <span className={styles.installDate}>
                      Installed {profile.installDate}
                    </span>
                  )}
                  <span
                    className={`${styles.chevron} ${isExpanded ? styles.chevronOpen : ""}`}
                  >
                    &#x25BC;
                  </span>
                </div>
              </div>

              {isExpanded && profile.payloads.length > 0 && (
                <div className={styles.profileCardBody}>
                  <div className={styles.payloadList}>
                    {profile.payloads.map((payload) => (
                      <div
                        key={payload.payloadIdentifier}
                        className={styles.payloadItem}
                      >
                        <span>
                          {payload.payloadDisplayName ?? payload.payloadIdentifier}
                        </span>
                        <span className={styles.payloadType}>
                          {payload.payloadType}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {profiles.length === 0 && (
          <div className={styles.centered}>
            <Body1>No configuration profiles installed.</Body1>
          </div>
        )}
      </div>
    </>
  );
}
