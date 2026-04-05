import React, { useCallback, useEffect, useMemo } from "react";
import {
  Body1,
  Button,
  makeStyles,
  shorthands,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "../../stores/macos-diag-store";
import { useUiStore } from "../../stores/ui-store";
import {
  macosListPackages,
  macosGetPackageInfo,
  macosGetPackageFiles,
} from "../../lib/commands";
import { getLogListMetrics } from "../../lib/log-accessibility";

/** pkgutil install-time is a Unix timestamp (seconds). Parse to Date. */
function formatInstallTime(raw: string | null): string {
  if (!raw) return "--";
  const num = Number(raw);
  if (isNaN(num) || num <= 0) return "--";
  return new Date(num * 1000).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/** Map well-known Microsoft package IDs to friendly names. */
const PACKAGE_FRIENDLY_NAMES: Record<string, string> = {
  "com.microsoft.edgemac": "Microsoft Edge",
  "com.microsoft.Word": "Microsoft Word",
  "com.microsoft.Excel": "Microsoft Excel",
  "com.microsoft.Powerpoint": "Microsoft PowerPoint",
  "com.microsoft.Outlook": "Microsoft Outlook",
  "com.microsoft.onenote.mac": "Microsoft OneNote",
  "com.microsoft.OneDrive": "OneDrive",
  "com.microsoft.teams": "Microsoft Teams",
  "com.microsoft.teams2": "Microsoft Teams (New)",
  "com.microsoft.CompanyPortalMac": "Company Portal",
  "com.microsoft.intuneMDMAgent": "Intune MDM Agent",
  "com.microsoft.remotehelp": "Remote Help",
  "com.microsoft.rdc.macos": "Remote Desktop",
  "com.microsoft.wdav": "Microsoft Defender",
  "com.microsoft.powershell": "PowerShell",
  "com.microsoft.package.Microsoft_AutoUpdate.app": "Microsoft AutoUpdate",
};

function getPackageFriendlyName(packageId: string): string | null {
  // Exact match first
  if (PACKAGE_FRIENDLY_NAMES[packageId]) return PACKAGE_FRIENDLY_NAMES[packageId];
  // Try prefix match for dotnet SDK components
  if (packageId.startsWith("com.microsoft.dotnet.")) {
    const parts = packageId.replace("com.microsoft.dotnet.", "").split(".");
    // e.g. "sharedframework.Microsoft.NETCore.App.10.0.3..." → ".NET Runtime 10.0.3"
    if (packageId.includes("sharedframework")) return `.NET Runtime`;
    if (packageId.includes("sharedhost")) return `.NET Shared Host`;
    if (packageId.includes("hostfxr")) return `.NET Host FX Resolver`;
    if (packageId.includes("pack.targeting")) return `.NET Targeting Pack`;
    if (packageId.includes("pack.apphost")) return `.NET App Host Pack`;
    if (packageId.includes("dev.")) return `.NET SDK`;
    return `.NET (${parts[0]})`;
  }
  return null;
}

const useStyles = makeStyles({
  statCards: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "12px",
    marginBottom: "16px",
  },
  statCard: {
    ...shorthands.padding("14px", "16px"),
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    boxShadow: tokens.shadow2,
  },
  statLabel: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
    fontWeight: 600,
    marginBottom: "4px",
  },
  statValue: {
    fontSize: "22px",
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    letterSpacing: "-0.5px",
  },
  statSub: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    marginTop: "2px",
  },
  tableWrap: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    overflow: "hidden",
    boxShadow: tokens.shadow2,
  },
  tableHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("10px", "14px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
  },
  tableTitle: {
    fontSize: "12px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
  },
  th: {
    textAlign: "left" as const,
    ...shorthands.padding("8px", "14px"),
    fontSize: "10.5px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
  },
  td: {
    ...shorthands.padding("9px", "14px"),
    fontSize: "12.5px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    color: tokens.colorNeutralForeground1,
  },
  trSelected: {
    backgroundColor: tokens.colorNeutralBackground1Selected,
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11.5px",
  },
  packageDetail: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.padding("16px"),
    marginTop: "12px",
    boxShadow: tokens.shadow2,
  },
  pkgDetailHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "12px",
  },
  pkgDetailTitle: {
    fontSize: "13px",
    fontWeight: 600,
  },
  pkgDetailGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
    gap: "10px",
    marginBottom: "14px",
  },
  pkgDetailItem: {
    ...shorthands.padding("6px", "10px"),
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
  },
  pkgDetailLabel: {
    fontSize: "10px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
  },
  pkgDetailValue: {
    fontSize: "12px",
    fontWeight: 500,
    marginTop: "2px",
  },
  fileListLabel: {
    fontSize: "11px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    marginBottom: "6px",
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
  },
  fileList: {
    maxHeight: "200px",
    overflowY: "auto" as const,
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    ...shorthands.padding("8px", "12px"),
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    lineHeight: "1.7",
    whiteSpace: "pre-wrap" as const,
    wordBreak: "break-all" as const,
  },
  centered: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    ...shorthands.padding("40px"),
    gap: "8px",
  },
  errorText: {
    color: tokens.colorPaletteRedForeground1,
    textAlign: "center" as const,
  },
});

export function MacosDiagPackagesTab() {
  const styles = useStyles();
  const packagesResult = useMacosDiagStore((s) => s.packagesResult);
  const loading = useMacosDiagStore((s) => s.packagesLoading);
  const selectedPackageId = useMacosDiagStore((s) => s.selectedPackageId);
  const selectedPackageInfo = useMacosDiagStore((s) => s.selectedPackageInfo);
  const selectedPackageFiles = useMacosDiagStore((s) => s.selectedPackageFiles);
  const packageDrillLoading = useMacosDiagStore((s) => s.packageDrillLoading);
  const setPackagesResult = useMacosDiagStore((s) => s.setPackagesResult);
  const setLoading = useMacosDiagStore((s) => s.setPackagesLoading);
  const setSelectedPackageId = useMacosDiagStore((s) => s.setSelectedPackageId);
  const setSelectedPackageInfo = useMacosDiagStore(
    (s) => s.setSelectedPackageInfo
  );
  const setSelectedPackageFiles = useMacosDiagStore(
    (s) => s.setSelectedPackageFiles
  );
  const setPackageDrillLoading = useMacosDiagStore(
    (s) => s.setPackageDrillLoading
  );
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const result = await macosListPackages();
      setPackagesResult(result);
    } catch (err) {
      console.error("[macos-diag] packages fetch failed", err);
      setLoading(false);
    }
  }, [setLoading, setPackagesResult]);

  useEffect(() => {
    if (!packagesResult && !loading) {
      fetch();
    }
  }, [packagesResult, loading, fetch]);

  const handleDetails = async (packageId: string) => {
    if (selectedPackageId === packageId) {
      setSelectedPackageId(null);
      return;
    }

    setSelectedPackageId(packageId);
    setPackageDrillLoading(true);

    try {
      const [info, files] = await Promise.all([
        macosGetPackageInfo(packageId),
        macosGetPackageFiles(packageId),
      ]);
      // Guard against race condition: only update if this package is still selected
      if (useMacosDiagStore.getState().selectedPackageId === packageId) {
        setSelectedPackageInfo(info);
        setSelectedPackageFiles(files);
      }
    } catch (err) {
      console.error("[macos-diag] package details fetch failed", err);
    } finally {
      setPackageDrillLoading(false);
    }
  };

  if (loading) {
    return (
      <div className={styles.centered}>
        <Spinner size="medium" label="Listing packages..." />
      </div>
    );
  }

  if (!packagesResult) {
    return (
      <div className={styles.centered}>
        <Body1 className={styles.errorText}>
          No package data available.
        </Body1>
        <Button appearance="primary" size="small" onClick={fetch}>
          Rescan
        </Button>
      </div>
    );
  }

  const { packages, totalCount, microsoftCount } = packagesResult;

  // Find latest install
  const latestPkg =
    packages.length > 0
      ? packages.reduce((latest, pkg) => {
          if (!latest.installTime) return pkg;
          if (!pkg.installTime) return latest;
          const pkgTime = Number(pkg.installTime) || 0;
          const latestTime = Number(latest.installTime) || 0;
          return pkgTime > latestTime ? pkg : latest;
        })
      : null;

  return (
    <>
      <div className={styles.statCards}>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Microsoft Packages</div>
          <div className={styles.statValue}>{microsoftCount}</div>
          <div className={styles.statSub}>of {totalCount} total packages</div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Latest Install</div>
          <div className={styles.statValue}>
            {formatInstallTime(latestPkg?.installTime ?? null)}
          </div>
          <div className={styles.statSub}>
            {latestPkg?.packageId ?? "No packages"}
          </div>
        </div>
      </div>

      <div className={styles.tableWrap}>
        <div className={styles.tableHeader}>
          <div className={styles.tableTitle}>Microsoft Package Receipts</div>
          <Button size="small" appearance="subtle" onClick={fetch}>
            Rescan
          </Button>
        </div>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.th}>Package ID</th>
              <th className={styles.th}>Version</th>
              <th className={styles.th}>Install Date</th>
              <th className={styles.th}></th>
            </tr>
          </thead>
          <tbody>
            {packages.map((pkg) => {
              const isSelected = selectedPackageId === pkg.packageId;
              return (
                <React.Fragment key={pkg.packageId}>
                  <tr
                    className={isSelected ? styles.trSelected : ""}
                    style={{ height: metrics.rowHeight }}
                  >
                    <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                      {getPackageFriendlyName(pkg.packageId) ? (
                        <>
                          <div style={{ fontWeight: 600 }}>{getPackageFriendlyName(pkg.packageId)}</div>
                          <div style={{ fontSize: metrics.fontSize - 2, color: tokens.colorNeutralForeground3, fontFamily: tokens.fontFamilyMonospace }}>{pkg.packageId}</div>
                        </>
                      ) : (
                        <span style={{ fontFamily: tokens.fontFamilyMonospace }}>{pkg.packageId}</span>
                      )}
                    </td>
                    <td className={styles.td} style={{ fontSize: metrics.fontSize }}>{pkg.version}</td>
                    <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                      {formatInstallTime(pkg.installTime)}
                    </td>
                    <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                      <Button
                        size="small"
                        appearance={isSelected ? "primary" : "subtle"}
                        onClick={() => handleDetails(pkg.packageId)}
                      >
                        {isSelected ? "Close" : "Details"}
                      </Button>
                    </td>
                  </tr>
                  {isSelected && (
                    <tr>
                      <td colSpan={4} style={{ padding: 0 }}>
                        <div className={styles.packageDetail}>
                          {packageDrillLoading && (
                            <div className={styles.centered}>
                              <Spinner size="small" label="Loading package details..." />
                            </div>
                          )}
                          {!packageDrillLoading && selectedPackageInfo && (
                            <>
                              <div className={styles.pkgDetailGrid}>
                                <div className={styles.pkgDetailItem}>
                                  <div className={styles.pkgDetailLabel}>Version</div>
                                  <div className={styles.pkgDetailValue} style={{ fontSize: metrics.fontSize }}>{selectedPackageInfo.version}</div>
                                </div>
                                <div className={styles.pkgDetailItem}>
                                  <div className={styles.pkgDetailLabel}>Volume</div>
                                  <div className={styles.pkgDetailValue} style={{ fontSize: metrics.fontSize }}>{selectedPackageInfo.volume ?? "/"}</div>
                                </div>
                                <div className={styles.pkgDetailItem}>
                                  <div className={styles.pkgDetailLabel}>Location</div>
                                  <div className={styles.pkgDetailValue} style={{ fontSize: metrics.fontSize }}>{selectedPackageInfo.location ?? "--"}</div>
                                </div>
                                <div className={styles.pkgDetailItem}>
                                  <div className={styles.pkgDetailLabel}>Install Time</div>
                                  <div className={styles.pkgDetailValue} style={{ fontSize: metrics.fontSize }}>{formatInstallTime(selectedPackageInfo.installTime)}</div>
                                </div>
                              </div>
                              {selectedPackageFiles && (
                                <>
                                  <div className={styles.fileListLabel}>Installed Files ({selectedPackageFiles.fileCount})</div>
                                  <div className={styles.fileList} style={{ fontSize: metrics.fontSize - 2 }}>{selectedPackageFiles.files.join("\n")}</div>
                                </>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {packages.length === 0 && (
              <tr>
                <td
                  className={styles.td}
                  colSpan={4}
                  style={{ textAlign: "center", fontSize: metrics.fontSize }}
                >
                  No Microsoft packages found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Detail panel is now rendered inline in the table */}
    </>
  );
}
