import { useMemo, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { LinkRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import type {
  EspDiagnosticsSnapshot,
  EspErrorCode,
  EspNormalizedStatus,
  EspTrackedKind,
  EspWorkload,
} from "./types";

const kindLabels: Record<EspTrackedKind, string> = {
  msi: "MSI",
  office: "Microsoft 365 Apps",
  modernApp: "Modern app",
  win32App: "Win32 app",
  policy: "Policy",
  scepCertificate: "SCEP certificate",
  platformScript: "Platform script",
  devicePreparationWorkload: "Device Preparation workload",
};

function statusGlyph(status: EspNormalizedStatus): string {
  switch (status) {
    case "succeeded":
    case "processed":
    case "downloaded":
      return "✓";
    case "failed":
      return "!";
    case "downloading":
    case "installing":
    case "inProgress":
      return "▶";
    case "rebootRequired":
      return "↻";
    case "unknown":
      return "?";
    default:
      return "○";
  }
}

function statusColor(status: EspNormalizedStatus): string {
  switch (status) {
    case "succeeded":
    case "processed":
    case "downloaded":
      return tokens.colorPaletteGreenForeground1;
    case "failed":
      return tokens.colorPaletteRedForeground1;
    case "downloading":
    case "installing":
    case "inProgress":
      return tokens.colorBrandForeground1;
    case "rebootRequired":
      return tokens.colorPaletteYellowForeground2;
    default:
      return tokens.colorNeutralForeground3;
  }
}

function formatCode(code: EspErrorCode | null, absentLabel: string): string {
  if (!code) return absentLabel;
  return code.hex ? `${code.raw} · ${code.hex}` : code.raw;
}

function timestampValue(workload: EspWorkload): number {
  const value =
    workload.timestamps.started?.normalizedUtc ??
    workload.timestamps.firstObserved.normalizedUtc ??
    workload.timestamps.firstObserved.rawText;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
}

function graphNames(snapshot: EspDiagnosticsSnapshot): Map<string, string> {
  const names = new Map<string, string>();
  for (const app of snapshot.graph?.apps.data ?? []) {
    if (app.displayName) names.set(app.appId, app.displayName);
  }
  for (const policy of snapshot.graph?.policies.data ?? []) {
    if (policy.displayName) names.set(policy.policyId, policy.displayName);
  }
  for (const script of snapshot.graph?.scripts.data ?? []) {
    if (script.displayName) names.set(script.scriptId, script.displayName);
  }
  return names;
}

interface WorkloadRowProps {
  workload: EspWorkload;
  graphName: string | undefined;
}

function WorkloadRow({ workload, graphName }: WorkloadRowProps) {
  return (
    <tr style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }}>
      <td style={{ width: "31%", padding: "7px 9px", verticalAlign: "top" }}>
        <strong
          style={{
            display: "block",
            overflow: "hidden",
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 11,
            lineHeight: "14px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={workload.displayName ?? "Local name unavailable"}
        >
          {workload.displayName ?? "Local name unavailable"}
        </strong>
        {graphName ? (
          <div
            style={{
              marginTop: 1,
              overflow: "hidden",
              color: tokens.colorBrandForeground1,
              fontSize: 9,
              lineHeight: "13px",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={`Graph · ${graphName}`}
          >
            Graph · {graphName}
          </div>
        ) : null}
        <code
          title={workload.rawIdentifier}
          style={{
            display: "block",
            marginTop: 2,
            overflow: "hidden",
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {workload.rawIdentifier}
        </code>
      </td>
      <td style={{ width: "18%", padding: "7px 9px", verticalAlign: "top" }}>
        <div style={{ fontSize: 10, fontWeight: 650, lineHeight: "14px" }}>
          {kindLabels[workload.kind]}
        </div>
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          {workload.scope === "device" ? "Device scope" : "User scope"}
        </div>
      </td>
      <td style={{ width: "17%", padding: "7px 9px", verticalAlign: "top" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            color: statusColor(workload.status.normalized),
            fontSize: 10,
            fontWeight: 700,
            lineHeight: "14px",
          }}
        >
          <span aria-hidden="true">
            {statusGlyph(workload.status.normalized)}
          </span>
          <span>{workload.status.display}</span>
        </div>
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          Raw · {String(workload.status.raw)}
        </div>
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          {workload.blocking === null
            ? "Blocking unknown"
            : workload.blocking
              ? "Blocking"
              : "Non-blocking"}
        </div>
      </td>
      <td style={{ width: "22%", padding: "7px 9px", verticalAlign: "top" }}>
        <div
          style={{
            color: workload.exitCode
              ? tokens.colorNeutralForeground1
              : tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          {formatCode(workload.exitCode, "Exit code unknown")}
        </div>
        <div
          style={{
            marginTop: 1,
            color: workload.enforcementErrorCode
              ? tokens.colorPaletteRedForeground1
              : tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 9,
            lineHeight: "13px",
          }}
        >
          {formatCode(
            workload.enforcementErrorCode,
            "Enforcement code unknown",
          )}
        </div>
      </td>
      <td style={{ width: "12%", padding: "7px 9px", verticalAlign: "top" }}>
        <details>
          <summary
            style={{
              cursor: "pointer",
              color: tokens.colorBrandForegroundLink,
              fontSize: 9,
              fontWeight: 650,
              lineHeight: "13px",
            }}
          >
            View full values
          </summary>
          <div
            style={{
              marginTop: 4,
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 8,
              lineHeight: "12px",
              overflowWrap: "anywhere",
            }}
          >
            <div>Workload · {workload.workloadId}</div>
            <div>Session · {workload.sessionId}</div>
            <div>First observed · {workload.timestamps.firstObserved.rawText}</div>
            {workload.evidence.map((reference) => (
              <a
                key={reference.evidenceId}
                href={`#evidence-${reference.evidenceId}`}
                aria-label={`Open evidence ${reference.evidenceId}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 2,
                  color: tokens.colorBrandForegroundLink,
                  textDecoration: "none",
                }}
              >
                <LinkRegular aria-hidden="true" />
                <code>{reference.evidenceId}</code>
              </a>
            ))}
          </div>
        </details>
      </td>
    </tr>
  );
}

interface EspWorkloadTableProps {
  snapshot: EspDiagnosticsSnapshot;
}

export function EspWorkloadTable({ snapshot }: EspWorkloadTableProps) {
  const [showAllSessions, setShowAllSessions] = useState(false);
  const names = useMemo(() => graphNames(snapshot), [snapshot]);
  const latestSessionIds = useMemo(
    () =>
      new Set(
        snapshot.sessions
          .filter((session) => session.isLatest)
          .map((session) => session.sessionId),
      ),
    [snapshot.sessions],
  );
  const visibleWorkloads = useMemo(
    () =>
      [...snapshot.workloads]
        .filter(
          (workload) =>
            showAllSessions ||
            latestSessionIds.size === 0 ||
            latestSessionIds.has(workload.sessionId),
        )
        .sort(
          (left, right) =>
            timestampValue(left) - timestampValue(right) ||
            left.workloadId.localeCompare(right.workloadId),
        ),
    [latestSessionIds, showAllSessions, snapshot.workloads],
  );
  const countLabel = showAllSessions
    ? `All sessions · ${visibleWorkloads.length} workloads`
    : `Latest sessions · ${visibleWorkloads.length} of ${snapshot.workloads.length} workloads`;

  return (
    <section
      role="region"
      aria-labelledby="esp-workloads-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 38,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "0 10px",
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.09em",
              lineHeight: "11px",
              textTransform: "uppercase",
            }}
          >
            Apps · scripts · policies · certificates
          </div>
          <h2
            id="esp-workloads-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            Tracked workloads
          </h2>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 9 }}>
            {countLabel}
          </strong>
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              fontSize: 10,
              fontWeight: 600,
            }}
          >
            <input
              type="checkbox"
              aria-label="Show all sessions"
              checked={showAllSessions}
              onChange={(event) => setShowAllSessions(event.currentTarget.checked)}
            />
            Show all sessions
          </label>
        </div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table
          style={{
            width: "100%",
            minWidth: 840,
            borderCollapse: "collapse",
            tableLayout: "fixed",
          }}
        >
          <thead>
            <tr
              style={{
                color: tokens.colorNeutralForeground3,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 8,
                fontWeight: 700,
                letterSpacing: "0.07em",
                textAlign: "left",
                textTransform: "uppercase",
              }}
            >
              <th scope="col" style={{ padding: "5px 9px" }}>Workload / raw ID</th>
              <th scope="col" style={{ padding: "5px 9px" }}>Type / scope</th>
              <th scope="col" style={{ padding: "5px 9px" }}>State</th>
              <th scope="col" style={{ padding: "5px 9px" }}>Exit / enforcement</th>
              <th scope="col" style={{ padding: "5px 9px" }}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {visibleWorkloads.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  style={{
                    padding: "14px 9px",
                    color: tokens.colorNeutralForeground2,
                    fontSize: 11,
                    textAlign: "center",
                  }}
                >
                  No workload records were observed for the selected session view.
                </td>
              </tr>
            ) : (
              visibleWorkloads.map((workload) => (
                <WorkloadRow
                  key={workload.workloadId}
                  workload={workload}
                  graphName={names.get(workload.rawIdentifier)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
