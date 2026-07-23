import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { LinkRegular } from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { buildEspGraphNameMap, lookupEspGraphName } from "./esp-graph-names";
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


interface WorkloadRowProps {
  workload: EspWorkload;
  graphName: string | undefined;
  /** Dense cell text sized from the accessibility control (10px at the default). */
  bodyFontSize: number;
  /** Emphasized workload display name (11px at the default). */
  strongFontSize: number;
}

function WorkloadRow({
  workload,
  graphName,
  bodyFontSize,
  strongFontSize,
}: WorkloadRowProps) {
  const [showFullValues, setShowFullValues] = useState(false);
  const effectiveStatus = effectiveNormalizedStatus(workload.status);
  const effectiveDisplay =
    workload.status.detail &&
    effectiveStatus === workload.status.detail.normalized
      ? workload.status.detail.display
      : workload.status.display;
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
            fontSize: strongFontSize,
            lineHeight: 1.4,
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={workload.displayName ?? graphName ?? "Local name unavailable"}
        >
          {workload.displayName ?? graphName ?? "Local name unavailable"}
        </strong>
        {graphName && workload.displayName ? (
          <div
            style={{
              marginTop: 1,
              overflow: "hidden",
              color: tokens.colorBrandForeground1,
              fontSize: bodyFontSize,
              lineHeight: 1.3,
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
            fontSize: bodyFontSize,
            lineHeight: 1.3,
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {workload.rawIdentifier}
        </code>
      </td>
      <td style={{ width: "18%", padding: "7px 9px", verticalAlign: "top" }}>
        <div style={{ fontSize: bodyFontSize, fontWeight: 650, lineHeight: 1.4 }}>
          {kindLabels[workload.kind]}
        </div>
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: bodyFontSize,
            lineHeight: 1.3,
          }}
        >
          {workload.scope === "device" ? "Device scope" : "User scope"}
        </div>
      </td>
      <td style={{ width: "17%", padding: "7px 9px", verticalAlign: "top" }}>
        <div
          data-testid="esp-workload-effective-status"
          data-effective-status={effectiveStatus}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            color: statusColor(effectiveStatus),
            fontSize: bodyFontSize,
            fontWeight: 700,
            lineHeight: 1.4,
          }}
        >
          <span aria-hidden="true">{statusGlyph(effectiveStatus)}</span>
          <span>{effectiveDisplay}</span>
        </div>
        {workload.status.detail &&
        effectiveStatus === workload.status.detail.normalized ? (
          <div
            style={{
              color: statusColor(workload.status.normalized),
              fontSize: bodyFontSize,
              fontWeight: 650,
              lineHeight: 1.4,
            }}
          >
            Outer · {workload.status.display}
          </div>
        ) : null}
        {workload.status.detail ? (
          <div
            style={{
              color: statusColor(workload.status.detail.normalized),
              fontSize: bodyFontSize,
              fontWeight: 650,
              lineHeight: 1.4,
            }}
          >
            Detail · {workload.status.detail.display}
          </div>
        ) : null}
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: bodyFontSize,
            lineHeight: 1.3,
          }}
        >
          Raw · {String(workload.status.raw)}
        </div>
        {workload.status.detail ? (
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: bodyFontSize,
              lineHeight: 1.3,
            }}
          >
            Detail raw · {String(workload.status.detail.raw)}
          </div>
        ) : null}
        <div
          style={{
            color: tokens.colorNeutralForeground3,
            fontSize: bodyFontSize,
            lineHeight: 1.3,
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
            fontSize: bodyFontSize,
            lineHeight: 1.3,
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
            fontSize: bodyFontSize,
            lineHeight: 1.3,
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
              fontSize: bodyFontSize,
              fontWeight: 650,
              lineHeight: 1.3,
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
                fontSize: bodyFontSize,
                lineHeight: 1.2,
                overflowWrap: "anywhere",
              }}
            >
              <div>Workload · {workload.workloadId}</div>
              <div>Session · {workload.sessionId}</div>
              <div>
                First observed · {workload.timestamps.firstObserved.rawText}
              </div>
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
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize],
  );
  // The workload grid keeps its compact CMTrace density (one tier below the
  // standard log row) while tracking the shared accessibility font-size control.
  const bodyFontSize = Math.max(9, metrics.fontSize - 3);
  const strongFontSize = Math.max(10, metrics.fontSize - 2);
  const headingFontSize = metrics.fontSize;
  const [showAllSessions, setShowAllSessions] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null,
  );
  const [workloadPage, setWorkloadPage] = useState(0);
  const names = useMemo(() => buildEspGraphNameMap(snapshot), [snapshot]);
  const availableSessionIds = useMemo(
    () => new Set(snapshot.sessions.map((session) => session.sessionId)),
    [snapshot.sessions],
  );
  const effectiveSelectedSessionId =
    selectedSessionId && availableSessionIds.has(selectedSessionId)
      ? selectedSessionId
      : null;
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
        .filter((workload) =>
          effectiveSelectedSessionId
            ? workload.sessionId === effectiveSelectedSessionId
            : showAllSessions ||
              latestSessionIds.size === 0 ||
              latestSessionIds.has(workload.sessionId),
        )
        .sort(compareWorkloads),
    [
      effectiveSelectedSessionId,
      latestSessionIds,
      showAllSessions,
      snapshot.workloads,
    ],
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
  const countLabel = effectiveSelectedSessionId
    ? `Selected session · ${filteredWorkloads.length} of ${snapshot.workloads.length} workloads`
    : showAllSessions
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
          flexWrap: "wrap",
          gap: 12,
          padding: "6px 10px",
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: bodyFontSize,
              fontWeight: 700,
              letterSpacing: "0.09em",
              lineHeight: 1.1,
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
              fontSize: headingFontSize,
              fontWeight: 650,
              lineHeight: 1.3,
            }}
          >
            Tracked workloads
          </h2>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <strong
            style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: bodyFontSize }}
          >
            {countLabel}
          </strong>
          {snapshot.sessions.length > 0 ? (
            <select
              aria-label="Select enrollment session"
              value={effectiveSelectedSessionId ?? ""}
              onChange={(event) => {
                const sessionId = event.currentTarget.value || null;
                setSelectedSessionId(sessionId);
                if (sessionId) setShowAllSessions(false);
                setWorkloadPage(0);
              }}
              style={{
                minWidth: 190,
                maxWidth: 280,
                height: 25,
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                borderRadius: 3,
                backgroundColor: tokens.colorNeutralBackground1,
                color: tokens.colorNeutralForeground1,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: bodyFontSize,
              }}
            >
              <option value="">Select a session…</option>
              {snapshot.sessions.map((session) => (
                <option key={session.sessionId} value={session.sessionId}>
                  {session.isLatest ? "Latest · " : ""}
                  {session.scope} ·{" "}
                  {session.startedAt?.rawText ?? "time unknown"}
                  {" · "}
                  {session.sessionId}
                </option>
              ))}
            </select>
          ) : null}
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              fontSize: bodyFontSize,
              fontWeight: 600,
            }}
          >
            <input
              type="checkbox"
              aria-label="Show all sessions"
              checked={showAllSessions}
              onChange={(event) => {
                setShowAllSessions(event.currentTarget.checked);
                if (event.currentTarget.checked) setSelectedSessionId(null);
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
            fontSize: bodyFontSize,
          }}
        >
          <span>
            Showing {workloadStart + 1}–{workloadEnd} of{" "}
            {filteredWorkloads.length} workloads
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
                fontSize: bodyFontSize,
                fontWeight: 700,
                letterSpacing: "0.07em",
                textAlign: "left",
                textTransform: "uppercase",
              }}
            >
              <th scope="col" style={{ padding: "5px 9px" }}>
                Workload / raw ID
              </th>
              <th scope="col" style={{ padding: "5px 9px" }}>
                Type / scope
              </th>
              <th scope="col" style={{ padding: "5px 9px" }}>
                State
              </th>
              <th scope="col" style={{ padding: "5px 9px" }}>
                Exit / enforcement
              </th>
              <th scope="col" style={{ padding: "5px 9px" }}>
                Evidence
              </th>
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
                    fontSize: strongFontSize,
                    textAlign: "center",
                  }}
                >
                  No workload records were observed for the selected session
                  view.
                </td>
              </tr>
            ) : (
              visibleWorkloads.map((workload) => (
                <WorkloadRow
                  key={workload.workloadId}
                  workload={workload}
                  graphName={lookupEspGraphName(names, workload.rawIdentifier)}
                  bodyFontSize={bodyFontSize}
                  strongFontSize={strongFontSize}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
