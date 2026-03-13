import { useMemo, useState, type ReactNode } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import { useAppActions } from "../layout/Toolbar";
import type {
  DsregcmdAnalysisResult,
  DsregcmdDiagnosticInsight,
  DsregcmdFacts,
  DsregcmdSeverity,
} from "../../types/dsregcmd";

interface FactRow {
  label: string;
  value: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}

interface FactGroup {
  id: string;
  title: string;
  caption: string;
  rows: FactRow[];
}

function formatBool(value: boolean | null): string {
  if (value === true) {
    return "Yes";
  }

  if (value === false) {
    return "No";
  }

  return "Unknown";
}

function formatValue(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "(missing)";
  }

  if (typeof value === "boolean") {
    return formatBool(value);
  }

  return String(value);
}

function toneForBool(value: boolean | null | undefined): FactRow["tone"] {
  if (value === true) {
    return "good";
  }

  if (value === false) {
    return "bad";
  }

  return "neutral";
}

function getSeverityColor(severity: DsregcmdSeverity) {
  switch (severity) {
    case "Error":
      return { border: "#fecaca", background: "#fef2f2", text: "#991b1b" };
    case "Warning":
      return { border: "#fde68a", background: "#fffbeb", text: "#92400e" };
    case "Info":
      return { border: "#bfdbfe", background: "#eff6ff", text: "#1e40af" };
  }
}

function getFactGroups(result: DsregcmdAnalysisResult): FactGroup[] {
  const { facts, derived } = result;

  return [
    {
      id: "join-state",
      title: "Join State",
      caption: "Identity, join posture, and major derived signals.",
      rows: [
        { label: "Join Type", value: formatValue(derived.joinTypeLabel), tone: "good" },
        {
          label: "Azure AD Joined",
          value: formatBool(facts.joinState.azureAdJoined),
          tone: toneForBool(facts.joinState.azureAdJoined),
        },
        {
          label: "Domain Joined",
          value: formatBool(facts.joinState.domainJoined),
          tone: facts.joinState.domainJoined == null ? "neutral" : "good",
        },
        {
          label: "Workplace Joined",
          value: formatBool(facts.joinState.workplaceJoined),
          tone: toneForBool(facts.joinState.workplaceJoined),
        },
        {
          label: "Enterprise Joined",
          value: formatBool(facts.joinState.enterpriseJoined),
          tone: toneForBool(facts.joinState.enterpriseJoined),
        },
        {
          label: "Device Auth Status",
          value: formatValue(facts.deviceDetails.deviceAuthStatus),
          tone:
            facts.deviceDetails.deviceAuthStatus?.toUpperCase() === "SUCCESS"
              ? "good"
              : facts.deviceDetails.deviceAuthStatus
                ? "bad"
                : "neutral",
        },
      ],
    },
    {
      id: "tenant-device",
      title: "Tenant and Device",
      caption: "Core identifiers and certificate-related device details.",
      rows: [
        { label: "Tenant Id", value: formatValue(facts.tenantDetails.tenantId) },
        { label: "Tenant Name", value: formatValue(facts.tenantDetails.tenantName) },
        { label: "Domain Name", value: formatValue(facts.tenantDetails.domainName) },
        { label: "Device Id", value: formatValue(facts.deviceDetails.deviceId) },
        { label: "Thumbprint", value: formatValue(facts.deviceDetails.thumbprint) },
        {
          label: "TPM Protected",
          value: formatBool(facts.deviceDetails.tpmProtected),
          tone: toneForBool(facts.deviceDetails.tpmProtected),
        },
        {
          label: "Certificate Validity",
          value: formatValue(facts.deviceDetails.deviceCertificateValidity),
          tone: derived.certificateExpiringSoon ? "warn" : "neutral",
        },
      ],
    },
    {
      id: "management",
      title: "Management and MDM",
      caption: "Enrollment, compliance, and device management service endpoints.",
      rows: [
        {
          label: "MDM Enrolled",
          value: formatBool(derived.mdmEnrolled),
          tone: toneForBool(derived.mdmEnrolled),
        },
        {
          label: "MDM URL",
          value: formatValue(facts.managementDetails.mdmUrl),
          tone: derived.missingMdm ? "bad" : "neutral",
        },
        {
          label: "Compliance URL",
          value: formatValue(facts.managementDetails.mdmComplianceUrl),
          tone: derived.missingComplianceUrl ? "warn" : "neutral",
        },
        { label: "Settings URL", value: formatValue(facts.managementDetails.settingsUrl) },
        {
          label: "DM Service URL",
          value: formatValue(facts.managementDetails.deviceManagementSrvUrl),
        },
        {
          label: "DM Service ID",
          value: formatValue(facts.managementDetails.deviceManagementSrvId),
        },
      ],
    },
    {
      id: "sso-prt",
      title: "SSO and PRT",
      caption: "Token presence, freshness, and user session indicators.",
      rows: [
        {
          label: "Azure AD PRT",
          value: formatBool(facts.ssoState.azureAdPrt),
          tone: toneForBool(facts.ssoState.azureAdPrt),
        },
        {
          label: "PRT Update Time",
          value: formatValue(facts.ssoState.azureAdPrtUpdateTime),
          tone: derived.stalePrt ? "warn" : "neutral",
        },
        {
          label: "PRT Age Hours",
          value:
            derived.prtAgeHours == null ? "(unknown)" : `${derived.prtAgeHours.toFixed(1)}h`,
          tone: derived.stalePrt ? "warn" : "neutral",
        },
        {
          label: "Enterprise PRT",
          value: formatBool(facts.ssoState.enterprisePrt),
          tone: toneForBool(facts.ssoState.enterprisePrt),
        },
        {
          label: "WAM Default Set",
          value: formatBool(facts.userState.wamDefaultSet),
          tone: toneForBool(facts.userState.wamDefaultSet),
        },
        {
          label: "User Context",
          value: formatValue(facts.diagnostics.userContext),
          tone: derived.remoteSessionSystem ? "warn" : "neutral",
        },
      ],
    },
    {
      id: "diagnostics",
      title: "Diagnostics and Errors",
      caption: "Correlation, transport, and registration error fields.",
      rows: [
        { label: "Attempt Status", value: formatValue(facts.diagnostics.attemptStatus) },
        { label: "HTTP Error", value: formatValue(facts.diagnostics.httpError) },
        { label: "HTTP Status", value: formatValue(facts.diagnostics.httpStatus) },
        { label: "Endpoint URI", value: formatValue(facts.diagnostics.endpointUri) },
        { label: "Correlation ID", value: formatValue(facts.diagnostics.correlationId) },
        { label: "Request ID", value: formatValue(facts.diagnostics.requestId) },
        { label: "Client Error", value: formatValue(facts.registration.clientErrorCode) },
        { label: "Server Error", value: formatValue(facts.registration.serverErrorCode) },
        { label: "Server Message", value: formatValue(facts.registration.serverMessage) },
      ],
    },
    {
      id: "prejoin-registration",
      title: "Pre-Join and Registration",
      caption: "Hybrid join readiness and registration workflow checks.",
      rows: [
        { label: "AD Connectivity", value: formatValue(facts.preJoinTests.adConnectivityTest) },
        { label: "AD Configuration", value: formatValue(facts.preJoinTests.adConfigurationTest) },
        { label: "DRS Discovery", value: formatValue(facts.preJoinTests.drsDiscoveryTest) },
        { label: "DRS Connectivity", value: formatValue(facts.preJoinTests.drsConnectivityTest) },
        {
          label: "Token Acquisition",
          value: formatValue(facts.preJoinTests.tokenAcquisitionTest),
        },
        {
          label: "Fallback to Sync-Join",
          value: formatValue(facts.preJoinTests.fallbackToSyncJoin),
        },
        { label: "Error Phase", value: formatValue(facts.registration.errorPhase) },
        { label: "PreReq Result", value: formatValue(facts.registration.preReqResult) },
        {
          label: "Logon Cert Template",
          value: formatValue(facts.registration.logonCertTemplateReady),
        },
      ],
    },
    {
      id: "service-endpoints",
      title: "Service Endpoints",
      caption: "Relevant identity and registration service URLs.",
      rows: [
        { label: "Join Server URL", value: formatValue(facts.serviceEndpoints.joinSrvUrl) },
        { label: "Join Server ID", value: formatValue(facts.serviceEndpoints.joinSrvId) },
        { label: "Key Server URL", value: formatValue(facts.serviceEndpoints.keySrvUrl) },
        { label: "Auth Code URL", value: formatValue(facts.serviceEndpoints.authCodeUrl) },
        { label: "Access Token URL", value: formatValue(facts.serviceEndpoints.accessTokenUrl) },
        {
          label: "WebAuthn Service URL",
          value: formatValue(facts.serviceEndpoints.webAuthnSrvUrl),
        },
      ],
    },
  ];
}

function getSummaryText(result: DsregcmdAnalysisResult, sourceLabel: string): string {
  const errorCount = result.diagnostics.filter((item) => item.severity === "Error").length;
  const warningCount = result.diagnostics.filter((item) => item.severity === "Warning").length;
  const infoCount = result.diagnostics.filter((item) => item.severity === "Info").length;
  const criticalIssue = result.diagnostics.find((item) => item.severity === "Error");

  return [
    `Source: ${sourceLabel}`,
    `Join type: ${result.derived.joinTypeLabel}`,
    `Diagnostics: ${errorCount} errors, ${warningCount} warnings, ${infoCount} info`,
    criticalIssue ? `Top issue: ${criticalIssue.title}` : "Top issue: No critical issues detected",
    `PRT present: ${formatBool(result.derived.azureAdPrtPresent)}`,
    `MDM enrolled: ${formatBool(result.derived.mdmEnrolled)}`,
    `Device auth status: ${formatValue(result.facts.deviceDetails.deviceAuthStatus)}`,
  ].join("\n");
}

function StatCard({
  title,
  value,
  caption,
  tone = "neutral",
}: {
  title: string;
  value: string;
  caption: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const tones = {
    neutral: { border: "#d1d5db", background: "#ffffff", value: "#111827" },
    good: { border: "#bbf7d0", background: "#f0fdf4", value: "#166534" },
    warn: { border: "#fde68a", background: "#fffbeb", value: "#92400e" },
    bad: { border: "#fecaca", background: "#fef2f2", value: "#991b1b" },
  } as const;

  const colors = tones[tone];

  return (
    <div
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        minWidth: 0,
      }}
    >
      <div style={{ fontSize: "11px", color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {title}
      </div>
      <div style={{ marginTop: "6px", fontSize: "20px", fontWeight: 700, color: colors.value }}>
        {value}
      </div>
      <div style={{ marginTop: "6px", fontSize: "12px", color: "#4b5563", lineHeight: 1.4 }}>
        {caption}
      </div>
    </div>
  );
}

function SectionFrame({ title, caption, children }: { title: string; caption: string; children: ReactNode }) {
  return (
    <section
      style={{
        border: "1px solid #d1d5db",
        backgroundColor: "#ffffff",
      }}
    >
      <div style={{ padding: "12px 14px", borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
        <div style={{ fontSize: "14px", fontWeight: 700, color: "#111827" }}>{title}</div>
        <div style={{ marginTop: "4px", fontSize: "12px", color: "#6b7280" }}>{caption}</div>
      </div>
      <div style={{ padding: "14px" }}>{children}</div>
    </section>
  );
}

function IssueCard({ issue }: { issue: DsregcmdDiagnosticInsight }) {
  const colors = getSeverityColor(issue.severity);

  return (
    <article
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: "10px",
            fontWeight: 700,
            padding: "2px 6px",
            border: `1px solid ${colors.border}`,
            color: colors.text,
            backgroundColor: "#ffffff",
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {issue.severity}
        </span>
        <span style={{ fontSize: "11px", color: "#6b7280", textTransform: "uppercase" }}>
          {issue.category}
        </span>
      </div>
      <div style={{ marginTop: "8px", fontSize: "15px", fontWeight: 700, color: "#111827" }}>{issue.title}</div>
      <div style={{ marginTop: "6px", fontSize: "13px", color: "#374151", lineHeight: 1.5 }}>{issue.summary}</div>

      {issue.suggestedFixes.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Suggested fixes</div>
          <ul style={{ marginTop: "6px", paddingLeft: "18px", color: "#374151", lineHeight: 1.5 }}>
            {issue.suggestedFixes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.nextChecks.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Next checks</div>
          <ul style={{ marginTop: "6px", paddingLeft: "18px", color: "#374151", lineHeight: 1.5 }}>
            {issue.nextChecks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.evidence.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Evidence</div>
          <ul style={{ marginTop: "6px", paddingLeft: "18px", color: "#374151", lineHeight: 1.5 }}>
            {issue.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

function FactsTable({ group }: { group: FactGroup }) {
  return (
    <div style={{ border: "1px solid #e5e7eb", backgroundColor: "#ffffff" }}>
      <div style={{ padding: "10px 12px", borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
        <div style={{ fontSize: "13px", fontWeight: 700, color: "#111827" }}>{group.title}</div>
        <div style={{ marginTop: "4px", fontSize: "11px", color: "#6b7280" }}>{group.caption}</div>
      </div>
      <div>
        {group.rows.map((row) => {
          const tones = {
            neutral: { value: "#111827", background: "#ffffff" },
            good: { value: "#166534", background: "#f0fdf4" },
            warn: { value: "#92400e", background: "#fffbeb" },
            bad: { value: "#991b1b", background: "#fef2f2" },
          } as const;
          const palette = tones[row.tone ?? "neutral"];

          return (
            <div
              key={`${group.id}-${row.label}`}
              style={{
                display: "grid",
                gridTemplateColumns: "170px minmax(0, 1fr)",
                gap: "8px",
                padding: "9px 12px",
                borderTop: "1px solid #f3f4f6",
                alignItems: "start",
              }}
            >
              <div style={{ fontSize: "12px", fontWeight: 600, color: "#4b5563" }}>{row.label}</div>
              <div
                style={{
                  fontSize: "12px",
                  color: palette.value,
                  backgroundColor: palette.background,
                  padding: "2px 6px",
                  borderRadius: "2px",
                  wordBreak: "break-word",
                  whiteSpace: "pre-wrap",
                }}
              >
                {row.value}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function EmptyWorkspace({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        margin: "18px",
        border: "1px dashed #cbd5e1",
        backgroundColor: "#f8fafc",
        padding: "24px",
        color: "#334155",
      }}
    >
      <div style={{ fontSize: "18px", fontWeight: 700 }}>{title}</div>
      <div style={{ marginTop: "8px", fontSize: "13px", lineHeight: 1.6 }}>{body}</div>
    </div>
  );
}

function buildTimelineItems(facts: DsregcmdFacts, result: DsregcmdAnalysisResult) {
  return [
    {
      id: "cert-valid-from",
      label: "Certificate valid from",
      value: result.derived.certificateValidFrom ?? facts.deviceDetails.deviceCertificateValidity,
      tone: "neutral" as const,
    },
    {
      id: "cert-valid-to",
      label: "Certificate valid to",
      value: result.derived.certificateValidTo ?? facts.deviceDetails.deviceCertificateValidity,
      tone: result.derived.certificateExpiringSoon ? "warn" as const : "neutral" as const,
    },
    {
      id: "previous-prt",
      label: "Previous PRT attempt",
      value: facts.diagnostics.previousPrtAttempt,
      tone: "neutral" as const,
    },
    {
      id: "prt-update",
      label: "Azure AD PRT update",
      value: facts.ssoState.azureAdPrtUpdateTime,
      tone: result.derived.stalePrt ? "warn" as const : "good" as const,
    },
    {
      id: "client-time",
      label: "Client reference time",
      value: facts.diagnostics.clientTime,
      tone: "neutral" as const,
    },
  ].filter((item) => item.value);
}

function FlowBox({ title, detail, tone = "neutral" }: { title: string; detail: string; tone?: "neutral" | "good" | "warn" | "bad" }) {
  const colors = {
    neutral: { border: "#d1d5db", background: "#ffffff", text: "#111827" },
    good: { border: "#bbf7d0", background: "#f0fdf4", text: "#166534" },
    warn: { border: "#fde68a", background: "#fffbeb", text: "#92400e" },
    bad: { border: "#fecaca", background: "#fef2f2", text: "#991b1b" },
  } as const;
  const palette = colors[tone];

  return (
    <div
      style={{
        flex: 1,
        minWidth: "180px",
        border: `1px solid ${palette.border}`,
        backgroundColor: palette.background,
        padding: "12px",
      }}
    >
      <div style={{ fontSize: "12px", fontWeight: 700, color: palette.text }}>{title}</div>
      <div style={{ marginTop: "6px", fontSize: "12px", color: "#374151", lineHeight: 1.5 }}>{detail}</div>
    </div>
  );
}

export function DsregcmdWorkspace() {
  const result = useDsregcmdStore((s) => s.result);
  const rawInput = useDsregcmdStore((s) => s.rawInput);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const { openSourceFileDialog, openSourceFolderDialog, pasteDsregcmdSource, captureDsregcmdSource } = useAppActions();
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [showRawInput, setShowRawInput] = useState(false);

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter((item) => item.severity === "Error").length;
  const warningCount = diagnostics.filter((item) => item.severity === "Warning").length;
  const infoCount = diagnostics.filter((item) => item.severity === "Info").length;

  const factGroups = useMemo(() => (result ? getFactGroups(result) : []), [result]);
  const summaryText = useMemo(
    () => (result ? getSummaryText(result, sourceContext.displayLabel) : ""),
    [result, sourceContext.displayLabel]
  );
  const timelineItems = useMemo(
    () => (result ? buildTimelineItems(result.facts, result) : []),
    [result]
  );

  const handleCopyJson = async () => {
    if (!result) {
      return;
    }

    await writeText(JSON.stringify(result, null, 2));
    setExportMessage("Copied dsregcmd analysis JSON to the clipboard.");
  };

  const handleCopySummary = async () => {
    if (!result) {
      return;
    }

    await writeText(summaryText);
    setExportMessage("Copied dsregcmd summary to the clipboard.");
  };

  const handleSaveExport = async (kind: "json" | "summary") => {
    if (!result) {
      return;
    }

    const defaultPath =
      kind === "json" ? "dsregcmd-analysis.json" : "dsregcmd-summary.txt";

    const destination = await save({
      defaultPath,
      filters:
        kind === "json"
          ? [{ name: "JSON", extensions: ["json"] }]
          : [{ name: "Text", extensions: ["txt"] }],
    });

    if (!destination) {
      return;
    }

    const contents = kind === "json" ? JSON.stringify(result, null, 2) : summaryText;
    await writeTextFile(destination, contents);
    setExportMessage(`Saved ${kind === "json" ? "JSON export" : "summary export"} to ${destination}.`);
  };

  if (!result && isAnalyzing) {
    return (
      <EmptyWorkspace
        title="Analyzing dsregcmd source"
        body={analysisState.detail ?? "Reading source text, extracting facts, and building the first-pass health view..."}
      />
    );
  }

  if (!result && analysisState.phase === "error") {
    return (
      <EmptyWorkspace
        title="dsregcmd analysis failed"
        body={analysisState.detail ?? "The selected dsregcmd source could not be analyzed."}
      />
    );
  }

  if (!result) {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "#f8fafc" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "10px",
            padding: "8px 12px",
            backgroundColor: "#f3f4f6",
            borderBottom: "1px solid #d1d5db",
          }}
        >
          <div>
            <div style={{ fontSize: "14px", fontWeight: 700, color: "#111827" }}>dsregcmd Workspace</div>
            <div style={{ marginTop: "4px", fontSize: "12px", color: "#4b5563" }}>
              Capture a live snapshot, paste clipboard text, open a text file, or select an evidence bundle folder.
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button type="button" onClick={() => void captureDsregcmdSource()}>
              Capture
            </button>
            <button type="button" onClick={() => void pasteDsregcmdSource()}>
              Paste
            </button>
            <button type="button" onClick={() => void openSourceFileDialog()}>
              Open Text File
            </button>
            <button type="button" onClick={() => void openSourceFolderDialog()}>
              Open Evidence Folder
            </button>
          </div>
        </div>

        <EmptyWorkspace
          title="No dsregcmd source loaded"
          body="Use the workspace actions above to analyze dsregcmd /status output. Evidence bundle support looks for evidence/command-output/dsregcmd-status.txt and also accepts a top-level dsregcmd-status.txt file."
        />
      </div>
    );
  }

  const issueSpotlight = diagnostics.find((item) => item.severity === "Error") ?? diagnostics[0] ?? null;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "#f8fafc" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "10px",
          padding: "8px 12px",
          backgroundColor: "#f3f4f6",
          borderBottom: "1px solid #d1d5db",
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: "14px", fontWeight: 700, color: "#111827" }}>dsregcmd Workspace</div>
          <div style={{ marginTop: "4px", fontSize: "12px", color: "#4b5563", lineHeight: 1.4 }}>
            {sourceContext.displayLabel}
            {sourceContext.resolvedPath && ` • ${sourceContext.resolvedPath}`}
            {sourceContext.evidenceFilePath && sourceContext.evidenceFilePath !== sourceContext.resolvedPath
              ? ` • evidence ${sourceContext.evidenceFilePath}`
              : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          <button type="button" onClick={() => void captureDsregcmdSource()} disabled={isAnalyzing}>
            Capture
          </button>
          <button type="button" onClick={() => void pasteDsregcmdSource()} disabled={isAnalyzing}>
            Paste
          </button>
          <button type="button" onClick={() => void openSourceFileDialog()} disabled={isAnalyzing}>
            Open Text File
          </button>
          <button type="button" onClick={() => void openSourceFolderDialog()} disabled={isAnalyzing}>
            Open Evidence Folder
          </button>
        </div>
      </div>

      <div style={{ flex: 1, overflow: "auto", padding: "16px", display: "flex", flexDirection: "column", gap: "16px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px" }}>
          <StatCard
            title="Join Type"
            value={result.derived.joinTypeLabel}
            caption="Derived from AzureAdJoined and DomainJoined fields."
            tone={result.derived.joinType === "NotJoined" ? "bad" : "good"}
          />
          <StatCard
            title="Issues"
            value={`${errorCount} / ${warningCount} / ${infoCount}`}
            caption="Errors / warnings / informational findings."
            tone={errorCount > 0 ? "bad" : warningCount > 0 ? "warn" : "good"}
          />
          <StatCard
            title="PRT State"
            value={formatBool(result.derived.azureAdPrtPresent)}
            caption={
              result.derived.stalePrt
                ? `Stale by ${result.derived.prtAgeHours?.toFixed(1) ?? "?"} hours.`
                : "Primary Refresh Token presence derived from SSO state."
            }
            tone={result.derived.azureAdPrtPresent ? (result.derived.stalePrt ? "warn" : "good") : "bad"}
          />
          <StatCard
            title="MDM"
            value={formatBool(result.derived.mdmEnrolled)}
            caption="Based on MdmUrl and compliance endpoint presence."
            tone={result.derived.mdmEnrolled ? (result.derived.missingComplianceUrl ? "warn" : "good") : "warn"}
          />
          <StatCard
            title="Certificate"
            value={
              result.derived.certificateDaysRemaining == null
                ? "Unknown"
                : `${result.derived.certificateDaysRemaining} days`
            }
            caption="Remaining device certificate lifetime, when the validity range was parsed."
            tone={result.derived.certificateExpiringSoon ? "warn" : "neutral"}
          />
          <StatCard
            title="Source"
            value={`${sourceContext.rawLineCount} lines`}
            caption={`${sourceContext.rawCharCount} characters analyzed.`}
            tone="neutral"
          />
        </div>

        <SectionFrame title="Health Summary" caption="Fast first-pass readout of the current dsregcmd capture.">
          <div style={{ display: "grid", gridTemplateColumns: "minmax(260px, 1.2fr) minmax(220px, 0.8fr)", gap: "16px" }}>
            <div>
              <div style={{ fontSize: "13px", lineHeight: 1.6, color: "#374151", whiteSpace: "pre-wrap" }}>{summaryText}</div>
              {issueSpotlight && (
                <div style={{ marginTop: "12px", padding: "10px", border: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
                  <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Issue spotlight</div>
                  <div style={{ marginTop: "6px", fontSize: "13px", fontWeight: 600, color: "#111827" }}>{issueSpotlight.title}</div>
                  <div style={{ marginTop: "4px", fontSize: "12px", color: "#4b5563", lineHeight: 1.5 }}>{issueSpotlight.summary}</div>
                </div>
              )}
            </div>
            <div style={{ border: "1px solid #e5e7eb", backgroundColor: "#ffffff", padding: "12px" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Quick interpretation</div>
              <ul style={{ marginTop: "8px", paddingLeft: "18px", color: "#374151", lineHeight: 1.6 }}>
                <li>{result.derived.joinTypeLabel} describes the current device join posture.</li>
                <li>{result.derived.hasNetworkError ? `Network marker detected: ${result.derived.networkErrorCode}.` : "No explicit network marker was detected in the capture."}</li>
                <li>{result.derived.remoteSessionSystem ? "Capture looks like SYSTEM in a remote session, so user token fields may be misleading." : "Capture does not look like a SYSTEM remote-session snapshot."}</li>
                <li>{result.derived.certificateExpiringSoon ? "Device certificate is nearing expiry and deserves follow-up." : "Certificate expiry was not flagged as near-term."}</li>
              </ul>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame title="Issues Overview" caption="Ordered diagnostic findings with evidence, recommended checks, and suggested fixes.">
          {diagnostics.length === 0 ? (
            <div style={{ fontSize: "13px", color: "#374151" }}>No diagnostics were produced for this dsregcmd capture.</div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "12px" }}>
              {diagnostics.map((issue) => (
                <IssueCard key={issue.id} issue={issue} />
              ))}
            </div>
          )}
        </SectionFrame>

        <SectionFrame title="Facts by Group" caption="Backend-extracted facts organized for quick review rather than raw line order.">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "12px" }}>
            {factGroups.map((group) => (
              <FactsTable key={group.id} group={group} />
            ))}
          </div>
        </SectionFrame>

        <SectionFrame title="Timeline" caption="Important timestamps surfaced from PRT, certificate, and diagnostics fields.">
          {timelineItems.length === 0 ? (
            <div style={{ fontSize: "13px", color: "#374151" }}>No timeline-friendly timestamps were found in this capture.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {timelineItems.map((item, index) => {
                const palette =
                  item.tone === "warn"
                    ? { line: "#f59e0b", dot: "#f59e0b", card: "#fffbeb" }
                    : item.tone === "good"
                      ? { line: "#16a34a", dot: "#16a34a", card: "#f0fdf4" }
                      : { line: "#94a3b8", dot: "#64748b", card: "#f8fafc" };

                return (
                  <div key={item.id} style={{ display: "grid", gridTemplateColumns: "20px 1fr", gap: "10px", alignItems: "stretch" }}>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                      <div style={{ width: "10px", height: "10px", borderRadius: "999px", backgroundColor: palette.dot, marginTop: "8px" }} />
                      {index < timelineItems.length - 1 && (
                        <div style={{ flex: 1, width: "2px", backgroundColor: palette.line, marginTop: "4px" }} />
                      )}
                    </div>
                    <div style={{ border: "1px solid #e5e7eb", backgroundColor: palette.card, padding: "10px 12px" }}>
                      <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>{item.label}</div>
                      <div style={{ marginTop: "4px", fontSize: "12px", color: "#374151", wordBreak: "break-word" }}>{item.value}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </SectionFrame>

        <SectionFrame title="Flows" caption="Pragmatic first-pass flow boxes for registration, management, and token health.">
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "stretch" }}>
            <FlowBox
              title="Join posture"
              detail={`${result.derived.joinTypeLabel}. Azure AD joined: ${formatBool(result.facts.joinState.azureAdJoined)}. Domain joined: ${formatBool(result.facts.joinState.domainJoined)}.`}
              tone={result.derived.joinType === "NotJoined" ? "bad" : "good"}
            />
            <FlowBox
              title="Device authentication"
              detail={`Device auth status: ${formatValue(result.facts.deviceDetails.deviceAuthStatus)}. TPM protected: ${formatBool(result.facts.deviceDetails.tpmProtected)}.`}
              tone={result.facts.deviceDetails.deviceAuthStatus?.toUpperCase() === "SUCCESS" ? "good" : "bad"}
            />
            <FlowBox
              title="Management"
              detail={`MDM enrolled: ${formatBool(result.derived.mdmEnrolled)}. Compliance URL present: ${formatBool(result.derived.complianceUrlPresent)}.`}
              tone={result.derived.mdmEnrolled ? (result.derived.missingComplianceUrl ? "warn" : "good") : "warn"}
            />
            <FlowBox
              title="PRT and session"
              detail={`PRT present: ${formatBool(result.derived.azureAdPrtPresent)}. Stale: ${formatBool(result.derived.stalePrt)}. Remote SYSTEM: ${formatBool(result.derived.remoteSessionSystem)}.`}
              tone={result.derived.azureAdPrtPresent ? (result.derived.stalePrt ? "warn" : "good") : "bad"}
            />
          </div>
        </SectionFrame>

        <SectionFrame title="Explainer" caption="Short practical notes for what this workspace is showing and how to use it.">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
            <div style={{ border: "1px solid #e5e7eb", padding: "12px", backgroundColor: "#ffffff" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>What the health cards mean</div>
              <div style={{ marginTop: "8px", fontSize: "12px", lineHeight: 1.6, color: "#374151" }}>
                Cards summarize join posture, token state, MDM visibility, certificate lifetime, and issue counts. They are not a replacement for the raw dsregcmd output, but they do make triage faster.
              </div>
            </div>
            <div style={{ border: "1px solid #e5e7eb", padding: "12px", backgroundColor: "#ffffff" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>When the capture may mislead</div>
              <div style={{ marginTop: "8px", fontSize: "12px", lineHeight: 1.6, color: "#374151" }}>
                SYSTEM and remote-session captures can distort user-scoped token state. Evidence bundle captures can also be older than the current device state, so compare timestamps before acting.
              </div>
            </div>
            <div style={{ border: "1px solid #e5e7eb", padding: "12px", backgroundColor: "#ffffff" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "#111827" }}>Suggested next step</div>
              <div style={{ marginTop: "8px", fontSize: "12px", lineHeight: 1.6, color: "#374151" }}>
                Start with the highest-severity issue card, validate the evidence line items against the grouped facts below, and then re-run capture after remediation to confirm the signal changes.
              </div>
            </div>
          </div>
        </SectionFrame>

        <SectionFrame title="Export" caption="No-dependency export controls for handing off or attaching analysis output.">
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button type="button" onClick={() => void handleCopyJson()}>
              Copy JSON
            </button>
            <button type="button" onClick={() => void handleCopySummary()}>
              Copy Summary
            </button>
            <button type="button" onClick={() => void handleSaveExport("json")}>
              Save JSON
            </button>
            <button type="button" onClick={() => void handleSaveExport("summary")}>
              Save Summary
            </button>
            <button type="button" onClick={() => setShowRawInput((value) => !value)}>
              {showRawInput ? "Hide Raw Input" : "Show Raw Input"}
            </button>
          </div>
          {exportMessage && (
            <div style={{ marginTop: "10px", fontSize: "12px", color: "#166534" }}>{exportMessage}</div>
          )}
          {showRawInput && (
            <textarea
              readOnly
              value={rawInput}
              style={{
                marginTop: "12px",
                width: "100%",
                minHeight: "220px",
                resize: "vertical",
                fontFamily: "Consolas, 'Courier New', monospace",
                fontSize: "12px",
                padding: "10px",
                border: "1px solid #d1d5db",
                backgroundColor: "#f9fafb",
              }}
            />
          )}
        </SectionFrame>
      </div>
    </div>
  );
}
