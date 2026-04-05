import { useEffect } from "react";
import { tokens, Spinner, Button } from "@fluentui/react-components";
import {
  useDeploymentStore,
  type DeploymentLogFile,
} from "./deployment-store";
import { useLogStore } from "../../stores/log-store";
import { DeploymentErrorCard } from "./DeploymentErrorCard";
import { DeploymentSuccessTable } from "./DeploymentSuccessTable";

function InventoryBar({
  files,
}: {
  files: DeploymentLogFile[];
}) {
  const counts = {
    psadt: files.filter(
      (f) => f.format === "psadt-cmtrace" || f.format === "psadt-legacy"
    ).length,
    msi: files.filter((f) => f.format === "msi-verbose").length,
    burn: files.filter((f) => f.format === "burn").length,
    wrapper: files.filter((f) => f.format === "psadt-wrapper").length,
    unknown: files.filter((f) => f.format === "unknown").length,
  };

  return (
    <div
      style={{
        display: "flex",
        gap: "12px",
        padding: "8px 12px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderRadius: "4px",
        fontSize: "12px",
      }}
    >
      {counts.psadt > 0 && <span>{counts.psadt} PSADT</span>}
      {counts.msi > 0 && <span>{counts.msi} MSI verbose</span>}
      {counts.burn > 0 && <span>{counts.burn} WiX/Burn</span>}
      {counts.wrapper > 0 && <span>{counts.wrapper} Wrapper</span>}
      {counts.unknown > 0 && <span>{counts.unknown} Other</span>}
      <span style={{ color: tokens.colorNeutralForeground3 }}>
        {files.length} total
      </span>
    </div>
  );
}

function OutcomeSummary({
  succeeded,
  failed,
  deferred,
  unknown,
}: {
  succeeded: number;
  failed: number;
  deferred: number;
  unknown: number;
}) {
  return (
    <div
      style={{
        display: "flex",
        gap: "16px",
        padding: "8px 0",
        fontSize: "13px",
      }}
    >
      {failed > 0 && (
        <span style={{ color: tokens.colorPaletteRedForeground1 }}>
          {failed} failed
        </span>
      )}
      {succeeded > 0 && (
        <span style={{ color: tokens.colorPaletteGreenForeground1 }}>
          {succeeded} succeeded
        </span>
      )}
      {deferred > 0 && (
        <span style={{ color: tokens.colorPaletteYellowForeground1 }}>
          {deferred} deferred
        </span>
      )}
      {unknown > 0 && (
        <span style={{ color: tokens.colorNeutralForeground3 }}>
          {unknown} unknown
        </span>
      )}
    </div>
  );
}

export function DeploymentWorkspace() {
  const phase = useDeploymentStore((s) => s.phase);
  const result = useDeploymentStore((s) => s.result);
  const errorMessage = useDeploymentStore((s) => s.errorMessage);
  const analyzeFolder = useDeploymentStore((s) => s.analyzeFolder);

  // Auto-trigger analysis when workspace activates and a folder is already loaded
  const activeSource = useLogStore((s) => s.activeSource);
  useEffect(() => {
    if (phase !== "idle") return;
    if (!activeSource) return;
    const folderPath =
      activeSource.kind === "folder"
        ? activeSource.path
        : activeSource.kind === "known"
          ? activeSource.defaultPath
          : null;
    if (folderPath) {
      analyzeFolder(folderPath);
    }
  }, [phase, activeSource, analyzeFolder]);

  if (phase === "idle") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
          color: tokens.colorNeutralForeground3,
          padding: "40px",
        }}
      >
        <div style={{ fontSize: "16px", fontWeight: 600 }}>
          Software Deployment Analysis
        </div>
        <div style={{ fontSize: "13px" }}>
          Open a deployment log folder to analyze PSADT, MSI, PatchMyPC, and WiX/Burn logs.
        </div>
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground4 }}>
          Use the Known Sources menu to open C:\Windows\Logs\Software,
          C:\ProgramData\PatchMyPCInstallLogs, or another deployment log folder.
        </div>
      </div>
    );
  }

  if (phase === "analyzing") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
        }}
      >
        <Spinner size="medium" />
        <div style={{ fontSize: "13px", color: tokens.colorNeutralForeground3 }}>
          Scanning folder for deployment logs...
        </div>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
          padding: "40px",
        }}
      >
        <div
          style={{
            fontSize: "13px",
            color: tokens.colorPaletteRedForeground1,
          }}
        >
          {errorMessage ?? "An error occurred during analysis."}
        </div>
        <Button
          size="small"
          onClick={() => {
            if (result?.folderPath) {
              analyzeFolder(result.folderPath);
            }
          }}
        >
          Retry
        </Button>
      </div>
    );
  }

  if (phase === "empty") {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
          color: tokens.colorNeutralForeground3,
          padding: "40px",
        }}
      >
        <div style={{ fontSize: "14px" }}>
          No deployment logs found in this folder.
        </div>
        <div style={{ fontSize: "12px" }}>
          Expected PSADT, MSI verbose, WiX/Burn, or PatchMyPC logs.
        </div>
      </div>
    );
  }

  // phase === "ready"
  if (!result) return null;

  const failedFiles = result.files.filter((f) => f.outcome === "failure");
  const succeededFiles = result.files.filter(
    (f) => f.outcome === "success" || f.outcome === "deferred"
  );
  const unknownFiles = result.files.filter((f) => f.outcome === "unknown");

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "16px",
        padding: "16px",
        overflow: "auto",
        height: "100%",
      }}
    >
      <div>
        <div
          style={{
            fontSize: "16px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            marginBottom: "4px",
          }}
        >
          Software Deployment Analysis
        </div>
        <div
          style={{
            fontSize: "12px",
            color: tokens.colorNeutralForeground3,
          }}
        >
          {result.folderPath}
        </div>
      </div>

      <InventoryBar files={result.files} />

      <OutcomeSummary
        succeeded={result.succeeded}
        failed={result.failed}
        deferred={result.deferred}
        unknown={result.unknown}
      />

      {failedFiles.length > 0 && (
        <div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 600,
              marginBottom: "8px",
              color: tokens.colorPaletteRedForeground1,
            }}
          >
            Failed Deployments
          </div>
          {failedFiles.map((file, index) => (
            <DeploymentErrorCard
              key={file.path}
              file={file}
              index={index}
            />
          ))}
        </div>
      )}

      {succeededFiles.length > 0 && (
        <div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 600,
              marginBottom: "8px",
              color: tokens.colorPaletteGreenForeground1,
            }}
          >
            Succeeded / Deferred
          </div>
          <DeploymentSuccessTable files={succeededFiles} />
        </div>
      )}

      {unknownFiles.length > 0 && (
        <div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 600,
              marginBottom: "8px",
              color: tokens.colorNeutralForeground3,
            }}
          >
            Other / Unclassified ({unknownFiles.length})
          </div>
          <DeploymentSuccessTable files={unknownFiles} />
        </div>
      )}
    </div>
  );
}
