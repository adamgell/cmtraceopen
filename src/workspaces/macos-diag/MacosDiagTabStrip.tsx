import {
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "./macos-diag-store";
import type { MacosDiagTabId } from "./types";

const useStyles = makeStyles({
  strip: {
    display: "flex",
    gap: "0px",
    ...shorthands.padding("0px", "20px"),
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  tab: {
    fontSize: "12.5px",
    fontWeight: 500,
    ...shorthands.padding("10px", "16px"),
    ...shorthands.border("0px", "none", "transparent"),
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground3,
    cursor: "pointer",
    position: "relative" as const,
    whiteSpace: "nowrap" as const,
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    transitionProperty: "color",
    transitionDuration: "0.15s",
    ":hover": {
      color: tokens.colorNeutralForeground1,
    },
  },
  tabActive: {
    color: tokens.colorBrandForeground1,
    fontWeight: 600,
    "::after": {
      content: '""',
      position: "absolute" as const,
      bottom: "0px",
      left: "12px",
      right: "12px",
      height: "2px",
      backgroundColor: tokens.colorBrandForeground1,
      ...shorthands.borderRadius("2px", "2px", "0px", "0px"),
    },
  },
  countBadge: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("1px", "6px"),
    ...shorthands.borderRadius("100px"),
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground3,
  },
  countBadgeActive: {
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
  },
});

interface TabDef {
  id: MacosDiagTabId;
  label: string;
}

const TABS: TabDef[] = [
  { id: "intune-logs", label: "Intune Logs" },
  { id: "profiles", label: "Profiles & MDM" },
  { id: "defender", label: "Defender" },
  { id: "packages", label: "Packages" },
  { id: "unified-log", label: "Unified Log" },
];

export function MacosDiagTabStrip() {
  const styles = useStyles();
  const activeTab = useMacosDiagStore((s) => s.activeTab);
  const setActiveTab = useMacosDiagStore((s) => s.setActiveTab);

  const intuneLogScan = useMacosDiagStore((s) => s.intuneLogScan);
  const profilesResult = useMacosDiagStore((s) => s.profilesResult);
  const packagesResult = useMacosDiagStore((s) => s.packagesResult);

  const getCount = (tabId: MacosDiagTabId): number | null => {
    switch (tabId) {
      case "intune-logs":
        return intuneLogScan ? intuneLogScan.files.length : null;
      case "profiles":
        return profilesResult ? profilesResult.profiles.length : null;
      case "packages":
        return packagesResult ? packagesResult.microsoftCount : null;
      default:
        return null;
    }
  };

  return (
    <div className={styles.strip}>
      {TABS.map((tab) => {
        const isActive = activeTab === tab.id;
        const count = getCount(tab.id);

        return (
          <button
            key={tab.id}
            className={`${styles.tab} ${isActive ? styles.tabActive : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {count !== null && (
              <span
                className={`${styles.countBadge} ${isActive ? styles.countBadgeActive : ""}`}
              >
                {count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
