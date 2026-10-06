import {
  makeStyles,
  shorthands,
  Tab,
  TabList,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "./macos-diag-store";
import type { MacosDiagTabId } from "./types";

const useStyles = makeStyles({
  strip: {
    ...shorthands.padding("0px", "20px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  countBadge: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("1px", "6px"),
    ...shorthands.margin("0px", "0px", "0px", "6px"),
    ...shorthands.borderRadius(tokens.borderRadiusCircular),
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
      <TabList
        selectedValue={activeTab}
        onTabSelect={(_, data) => setActiveTab(data.value as MacosDiagTabId)}
      >
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          const count = getCount(tab.id);

          return (
            <Tab key={tab.id} value={tab.id}>
              {tab.label}
              {count !== null && (
                <span
                  className={`${styles.countBadge} ${isActive ? styles.countBadgeActive : ""}`}
                >
                  {count}
                </span>
              )}
            </Tab>
          );
        })}
      </TabList>
    </div>
  );
}
