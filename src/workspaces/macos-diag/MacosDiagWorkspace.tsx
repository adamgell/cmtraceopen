import { useCallback, useEffect } from "react";
import {
  Body1,
  makeStyles,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "./macos-diag-store";
import { macosScanEnvironment } from "../../lib/commands";
import { MacosDiagEnvironmentBanner } from "./MacosDiagEnvironmentBanner";
import { MacosDiagTabStrip } from "./MacosDiagTabStrip";
import { MacosDiagFdaGuide } from "./MacosDiagFdaGuide";
import { MacosDiagIntuneLogsTab } from "./MacosDiagIntuneLogsTab";
import { MacosDiagProfilesTab } from "./MacosDiagProfilesTab";
import { MacosDiagDefenderTab } from "./MacosDiagDefenderTab";
import { MacosDiagPackagesTab } from "./MacosDiagPackagesTab";
import { MacosDiagUnifiedLogTab } from "./MacosDiagUnifiedLogTab";

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
    minHeight: 0,
    overflow: "hidden",
    backgroundColor: tokens.colorNeutralBackground1,
  },
  tabContent: {
    flex: 1,
    overflow: "auto",
    padding: "18px 20px 20px",
    backgroundColor: tokens.colorNeutralBackground2,
  },
  centered: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    flex: 1,
    gap: "12px",
    padding: "40px",
  },
  errorText: {
    color: tokens.colorPaletteRedForeground1,
    textAlign: "center" as const,
    maxWidth: "480px",
  },
});

export function MacosDiagWorkspace() {
  const styles = useStyles();
  const environmentPhase = useMacosDiagStore((s) => s.environmentPhase);
  const environment = useMacosDiagStore((s) => s.environment);
  const environmentError = useMacosDiagStore((s) => s.environmentError);
  const activeTab = useMacosDiagStore((s) => s.activeTab);
  const beginEnvironmentScan = useMacosDiagStore((s) => s.beginEnvironmentScan);
  const setEnvironment = useMacosDiagStore((s) => s.setEnvironment);
  const failEnvironmentScan = useMacosDiagStore((s) => s.failEnvironmentScan);

  const runScan = useCallback(async () => {
    beginEnvironmentScan();
    try {
      const env = await macosScanEnvironment();
      setEnvironment(env);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err);
      failEnvironmentScan(message);
    }
  }, [beginEnvironmentScan, setEnvironment, failEnvironmentScan]);

  useEffect(() => {
    if (environmentPhase === "idle") {
      runScan();
    }
  }, [environmentPhase, runScan]);

  // Scanning state
  if (environmentPhase === "scanning") {
    return (
      <div className={styles.root}>
        <div className={styles.centered}>
          <Spinner size="medium" label="Scanning macOS environment..." />
        </div>
      </div>
    );
  }

  // Error state -- likely not macOS or backend command not available
  if (environmentPhase === "error") {
    const isNotMacOS =
      environmentError?.includes("only available on macOS");
    return (
      <div className={styles.root}>
        <div className={styles.centered}>
          <Body1 className={styles.errorText}>
            {isNotMacOS
              ? "macOS Diagnostics is only available on macOS. This workspace requires a macOS system to scan Intune logs, MDM profiles, Defender status, and unified logs."
              : `Environment scan failed: ${environmentError}`}
          </Body1>
        </div>
      </div>
    );
  }

  // Idle / not yet scanned
  if (!environment) {
    return (
      <div className={styles.root}>
        <div className={styles.centered}>
          <Spinner size="medium" label="Initializing..." />
        </div>
      </div>
    );
  }

  // FDA not granted -- show the blocker guide
  if (environment.fullDiskAccess === "notGranted") {
    return (
      <div className={styles.root}>
        <MacosDiagFdaGuide onRecheck={runScan} />
      </div>
    );
  }

  const renderActiveTab = () => {
    switch (activeTab) {
      case "intune-logs":
        return <MacosDiagIntuneLogsTab />;
      case "profiles":
        return <MacosDiagProfilesTab />;
      case "defender":
        return <MacosDiagDefenderTab />;
      case "packages":
        return <MacosDiagPackagesTab />;
      case "unified-log":
        return <MacosDiagUnifiedLogTab />;
    }
  };

  return (
    <div className={styles.root}>
      <MacosDiagEnvironmentBanner environment={environment} onRefresh={runScan} />
      <MacosDiagTabStrip />
      <div className={styles.tabContent}>{renderActiveTab()}</div>
    </div>
  );
}
