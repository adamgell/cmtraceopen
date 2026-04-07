import { tokens } from "@fluentui/react-components";
import { useSecureBootStore } from "./secureboot-store";
import {
  EmptyState,
  SidebarActionButton,
  SourceStatusNotice,
  SourceSummaryCard,
} from "../../components/common/sidebar-primitives";
import {
  rescanSecureBoot,
  runSecureBootDetection,
  runSecureBootRemediation,
} from "../../lib/commands";

const isWindows = navigator.userAgent.includes("Windows");

export function SecureBootSidebar() {
  const result = useSecureBootStore((s) => s.result);
  const analysisState = useSecureBootStore((s) => s.analysisState);
  const isAnalyzing = useSecureBootStore((s) => s.isAnalyzing);
  const scriptRunning = useSecureBootStore((s) => s.scriptRunning);
  const setScriptRunning = useSecureBootStore((s) => s.setScriptRunning);
  const beginAnalysis = useSecureBootStore((s) => s.beginAnalysis);
  const setResult = useSecureBootStore((s) => s.setResult);
  const failAnalysis = useSecureBootStore((s) => s.failAnalysis);

  const deviceName = result?.scanState.deviceName ?? null;
  const title = deviceName ?? "Secure Boot Certificates";

  const dataSourceLabel: string = result
    ? result.dataSource === "liveScan"
      ? "Live device scan"
      : result.dataSource === "logImport"
        ? "Log file import"
        : "Live scan + log import"
    : "No source loaded";

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter((d) => d.severity === "error").length;
  const warnCount = diagnostics.filter((d) => d.severity === "warning").length;
  const infoCount = diagnostics.filter((d) => d.severity === "info").length;

  const handleRunDetection = () => {
    beginAnalysis("Running detection script...");
    setScriptRunning("detection");
    runSecureBootDetection()
      .then((r) => {
        setResult(r);
        setScriptRunning(null);
      })
      .catch((e) => {
        failAnalysis(e);
        setScriptRunning(null);
      });
  };

  const handleRunRemediation = () => {
    if (!confirm("Run the Secure Boot remediation script on this device?")) {
      return;
    }
    beginAnalysis("Running remediation script...");
    setScriptRunning("remediation");
    runSecureBootRemediation()
      .then((r) => {
        setResult(r);
        setScriptRunning(null);
      })
      .catch((e) => {
        failAnalysis(e);
        setScriptRunning(null);
      });
  };

  const handleRescan = () => {
    beginAnalysis("Rescanning device...");
    rescanSecureBoot()
      .then((r) => setResult(r))
      .catch((e) => failAnalysis(e));
  };

  const isBusy = isAnalyzing || scriptRunning !== null;

  return (
    <>
      {isWindows && (
        <div
          style={{
            padding: "8px 10px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "6px",
          }}
        >
          <SidebarActionButton
            label="Run Detection"
            disabled={isBusy}
            onClick={handleRunDetection}
          />
          <SidebarActionButton
            label="Run Remediation"
            disabled={isBusy}
            onClick={handleRunRemediation}
          />
          <SidebarActionButton
            label="Rescan"
            disabled={isBusy}
            onClick={handleRescan}
          />
        </div>
      )}

      <SourceSummaryCard
        badge="secureboot"
        title={title}
        subtitle={dataSourceLabel}
        body={
          <div
            style={{
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {result ? (
              <>
                <div>Stage: {result.stage}</div>
                {result.scanState.osBuild && (
                  <div>OS Build: {result.scanState.osBuild}</div>
                )}
              </>
            ) : (
              <div>{analysisState.message}</div>
            )}
          </div>
        }
      />

      {(analysisState.phase === "analyzing" || analysisState.phase === "error") && (
        <SourceStatusNotice
          kind={analysisState.phase === "error" ? "error" : "info"}
          message={analysisState.message}
          detail={analysisState.detail ?? undefined}
        />
      )}

      <div
        style={{
          flex: 1,
          overflow: "auto",
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        {!result && !isAnalyzing && analysisState.phase !== "error" && (
          <EmptyState
            title="No analysis yet"
            body="Use the toolbar actions to scan this device or open a Secure Boot log file."
          />
        )}

        {result && (
          <div
            style={{
              padding: "12px 10px",
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.6,
            }}
          >
            <div>
              <strong>Errors:</strong> {errorCount}
            </div>
            <div>
              <strong>Warnings:</strong> {warnCount}
            </div>
            <div>
              <strong>Info:</strong> {infoCount}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
