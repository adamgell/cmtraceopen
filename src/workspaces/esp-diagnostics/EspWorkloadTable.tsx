import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { LinkRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { requestEspEvidenceNavigation } from "./evidence-navigation";
import type {
  EspDiagnosticsSnapshot,
  EspErrorCode,
  EspNormalizedStatus,
  EspStatus,
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

const statusSeverity: Record<EspNormalizedStatus, number> = {
  failed: 6,
  cancelled: 5,
  rebootRequired: 4,
  downloading: 3,
  installing: 3,
  inProgress: 3,
  pending: 2,
  initialized: 2,
  notStarted: 2,
  notInstalled: 2,
  skipped: 2,
  uninstalled: 2,
  unknown: 2,
  downloaded: 1,
  processed: 1,
  succeeded: 1,
};

function effectiveNormalizedStatus(status: EspStatus): EspNormalizedStatus {
  const detail = status.detail?.normalized;
  return detail && statusSeverity[detail] > statusSeverity[status.normalized]
    ? detail
    : status.normalized;
}

function formatCode(code: EspErrorCode | null, absentLabel: string): string {
  if (!code) return absentLabel;
  return code.hex ? `${code.raw} · ${code.hex}` : code.raw;
}

function timestampValue(workload: EspWorkload): number | null {
  const normalizedUtc =
    workload.timestamps.started?.normalizedUtc ??
    workload.timestamps.firstObserved.normalizedUtc;
  if (!normalizedUtc) return null;
  const parsed = Date.parse(normalizedUtc);
  return Number.isFinite(parsed) ? parsed : null;
}

function compareWorkloads(left: EspWorkload, right: EspWorkload): number {
  const leftTimestamp = timestampValue(left);
  const rightTimestamp = timestampValue(right);
  if (leftTimestamp !== null && rightTimestamp !== null) {
    return (
      leftTimestamp - rightTimestamp ||
      left.workloadId.localeCompare(right.workloadId)
    );
  }
  if (leftTimestamp !== null) return -1;
  if (rightTimestamp !== null) return 1;
  return left.workloadId.localeCompare(right.workloadId);
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
  const [showFullValues, setShowFullValues] = useState(false);
  const effectiveStatus = effectiveNormalizedStatus(workload.status);
  return (
    <tr
      data-testid="esp-workload-row"
      style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }}
    >
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
              fontSize: 10,
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
            fontSize: 10,
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
          data-effective-status={effectiveStatus}
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
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
            color: statusColor(effectiveStatus),
            fontSize: 10,
            fontWeight: 700,
            lineHeight: "14px",
          }}
        >
          <span aria-hidden="true">
            {statusGlyph(effectiveStatus)}
          </span>
          <span>{workload.status.display}</span>
        </div>
        {workload.status.detail ? (
          <div
            style={{
              color: statusColor(workload.status.detail.normalized),
              fontSize: 10,
              fontWeight: 650,
              lineHeight: "14px",
            }}
          >
            Detail · {workload.status.detail.display}
          </div>
        ) : null}
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            lineHeight: "13px",
          }}
        >
          Raw · {String(workload.status.raw)}
        </div>
        {workload.status.detail ? (
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              lineHeight: "13px",
            }}
          >
            Detail raw · {String(workload.status.detail.raw)}
          </div>
        ) : null}
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontSize: 10,
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
            fontSize: 10,
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
            fontSize: 10,
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
        <details open={showFullValues}>
          <summary
            aria-expanded={showFullValues}
            onClick={(event) => {
              event.preventDefault();
              setShowFullValues((current) => !current);
            }}
            style={{
              cursor: "pointer",
              color: tokens.colorBrandForegroundLink,
              fontSize: 10,
              fontWeight: 650,
              lineHeight: "13px",
            }}
          >
            View full values
          </summary>
          {showFullValues ? (
            <div
              data-testid="esp-workload-full-values"
              style={{
                marginTop: 4,
                color: tokens.colorNeutralForeground3,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 10,
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
                  onClick={() =>
                    requestEspEvidenceNavigation({
                      kind: "evidence",
                      id: reference.evidenceId,
                    })
                  }
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
          ) : null}
        </details>
      </td>
    </tr>
  );
}

interface EspWorkloadTableProps {
  snapshot: EspDiagnosticsSnapshot;
}

export const ESP_WORKLOAD_WINDOW_SIZE = 80;

export function EspWorkloadTable({ snapshot }: EspWorkloadTableProps) {
  const [showAllSessions, setShowAllSessions] = useState(false);
  const [workloadPage, setWorkloadPage] = useState(0);
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
  const filteredWorkloads = useMemo(
    () =>
      [...snapshot.workloads]
        .filter(
          (workload) =>
            showAllSessions ||
            latestSessionIds.size === 0 ||
            latestSessionIds.has(workload.sessionId),
        )
        .sort(compareWorkloads),
    [latestSessionIds, showAllSessions, snapshot.workloads],
  );
  const maximumPage = Math.max(
    0,
    Math.ceil(filteredWorkloads.length / ESP_WORKLOAD_WINDOW_SIZE) - 1,
  );
  const safePage = Math.min(workloadPage, maximumPage);
  const workloadStart = safePage * ESP_WORKLOAD_WINDOW_SIZE;
  const workloadEnd = Math.min(
    workloadStart + ESP_WORKLOAD_WINDOW_SIZE,
    filteredWorkloads.length,
  );
  const visibleWorkloads = filteredWorkloads.slice(workloadStart, workloadEnd);
  const countLabel = showAllSessions
    ? `All sessions · ${filteredWorkloads.length} workloads`
    : `Latest sessions · ${filteredWorkloads.length} of ${snapshot.workloads.length} workloads`;

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
              fontSize: 10,
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
          <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 10 }}>
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
              onChange={(event) => {
                setShowAllSessions(event.currentTarget.checked);
                setWorkloadPage(0);
              }}
            />
            Show all sessions
          </label>
        </div>
      </div>

      {filteredWorkloads.length > ESP_WORKLOAD_WINDOW_SIZE ? (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
            padding: "5px 9px",
            borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
            color: tokens.colorNeutralForeground2,
            fontSize: 10,
          }}
        >
          <span>
            Showing {workloadStart + 1}–{workloadEnd} of {filteredWorkloads.length} workloads
          </span>
          <span style={{ display: "inline-flex", gap: 5 }}>
            <Button
              size="small"
              disabled={safePage === 0}
              onClick={() => setWorkloadPage(Math.max(0, safePage - 1))}
            >
              Previous workloads
            </Button>
            <Button
              size="small"
              disabled={safePage >= maximumPage}
              onClick={() =>
                setWorkloadPage(Math.min(maximumPage, safePage + 1))
              }
            >
              Next workloads
            </Button>
          </span>
        </div>
      ) : null}

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
                fontSize: 10,
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
            {filteredWorkloads.length === 0 ? (
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
