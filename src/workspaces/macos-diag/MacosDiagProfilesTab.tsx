import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Body1,
  Button,
  makeStyles,
  shorthands,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "./macos-diag-store";
import { useUiStore } from "../../stores/ui-store";
import { macosListProfiles } from "../../lib/commands";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { deriveFriendlyName } from "../../lib/profile-utils";
import { ProfileDrilldown } from "./ProfileDrilldown";

const useStyles = makeStyles({
  enrollmentCard: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.padding("16px"),
    marginBottom: "16px",
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
    backgroundColor: tokens.colorPaletteGreenForeground1,
  },
  enrollmentDotNotEnrolled: {
    backgroundColor: tokens.colorPaletteRedForeground1,
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
  },
  profileCardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("12px", "16px"),
    cursor: "pointer",
    transitionProperty: "background",
    transitionDuration: "0.15s",
    width: "100%",
    backgroundColor: "transparent",
    ...shorthands.border("0"),
    textAlign: "left" as const,
    fontFamily: "inherit",
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
    ...shorthands.padding("2px", "8px"),
    ...shorthands.borderRadius(tokens.borderRadiusCircular),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
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
  verifiedBadge: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "8px"),
    ...shorthands.borderRadius(tokens.borderRadiusCircular),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteGreenBackground1,
    color: tokens.colorPaletteGreenForeground1,
  },
  sourceBadge: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "8px"),
    ...shorthands.borderRadius(tokens.borderRadiusCircular),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
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
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const [expandedProfiles, setExpandedProfiles] = useState<Set<string>>(
    new Set()
  );
  const [copied, setCopied] = useState(false);

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

  const copyAll = useCallback(() => {
    if (!profilesResult) return;
    navigator.clipboard.writeText(profilesResult.rawOutput).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [profilesResult]);

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
          <div className={styles.enrollmentDetail} style={{ fontSize: metrics.fontSize }}>
            MDM Server:{" "}
            <span className={styles.enrollmentDetailStrong}>
              {enrollmentStatus.mdmServer}
            </span>
          </div>
        )}
        {enrollmentStatus.enrollmentType && (
          <div className={styles.enrollmentDetail} style={{ fontSize: metrics.fontSize }}>
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
          <Button size="small" appearance="subtle" onClick={copyAll}>
            {copied ? "Copied" : "Copy all"}
          </Button>
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
              <button
                type="button"
                className={styles.profileCardHeader}
                onClick={() => toggleProfile(profile.profileIdentifier)}
              >
                <div>
                  <div className={styles.profileCardName} style={{ fontSize: metrics.fontSize }}>
                    {deriveFriendlyName(profile) ?? profile.profileDisplayName}
                  </div>
                  {deriveFriendlyName(profile) && (
                    <div className={styles.profileCardId} style={{ fontSize: metrics.fontSize - 2 }}>
                      {profile.profileDisplayName}
                    </div>
                  )}
                  <div className={styles.profileCardId} style={{ fontSize: metrics.fontSize - 2 }}>
                    {profile.profileIdentifier}
                  </div>
                </div>
                <div className={styles.profileCardMeta}>
                  {profile.isManaged && (
                    <span className={styles.managedBadge}>Managed</span>
                  )}
                  {profile.source && (
                    <span className={styles.sourceBadge}>{profile.source}</span>
                  )}
                  {profile.verificationState === "verified" && (
                    <span className={styles.verifiedBadge}>Verified</span>
                  )}
                  {profile.installDate && (
                    <span className={styles.installDate} style={{ fontSize: metrics.fontSize - 2 }}>
                      {profile.installDate}
                    </span>
                  )}
                  <span
                    className={`${styles.chevron} ${isExpanded ? styles.chevronOpen : ""}`}
                  >
                    &#x25BC;
                  </span>
                </div>
              </button>

              {isExpanded && <ProfileDrilldown profile={profile} />}
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
