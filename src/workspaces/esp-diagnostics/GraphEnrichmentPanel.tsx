import { useState, type ReactNode } from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  ArrowClockwiseRegular,
  CheckmarkCircleRegular,
  DismissCircleRegular,
  PlugDisconnectedRegular,
  StopRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import {
  useEspDiagnosticsStore,
  type EspGraphPhase,
  type EspGraphUnavailableReason,
} from "./esp-diagnostics-store";
import {
  cancelEspGraphData,
  refreshEspGraphData,
} from "./use-esp-session-updates";
import type {
  EspDiagnosticsSnapshot,
  EspGraphAssignment,
  EspGraphManagedDevice,
  GraphSection,
  GraphSectionStatus,
} from "./types";

interface GraphEnrichmentPanelProps {
  snapshot: EspDiagnosticsSnapshot;
  onRefresh?: () => void | Promise<void>;
  onCancel?: () => void | Promise<void>;
  onSelectDevice?: (managedDeviceId: string) => void | Promise<void>;
}

interface GlobalStateCopy {
  title: string;
  detail: string;
  tone: "neutral" | "brand" | "warning" | "error" | "success";
}

function label(value: string): string {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}

function globalStateCopy(
  phase: EspGraphPhase,
  reason: EspGraphUnavailableReason | null,
  graphApiEnabled: boolean,
  graphApiStatus: string,
  error: string | null,
): GlobalStateCopy {
  if (!graphApiEnabled || phase === "disabled") {
    return {
      title: "Graph enrichment is off",
      detail:
        "Local evidence is complete on its own. Enable the existing Graph option in Settings when remote names and status are useful.",
      tone: "neutral",
    };
  }
  if (reason === "unsupportedPlatform") {
    return {
      title: "Graph unavailable on this platform",
      detail:
        "The existing Windows WAM connection is required. Local evidence remains available.",
      tone: "warning",
    };
  }
  if (reason === "graphNotConnected" || graphApiStatus !== "connected") {
    return {
      title: "GraphNotConnected",
      detail:
        "Connect in Settings → Graph API, then return here and refresh explicitly. This workspace never opens Windows sign-in or queues a request behind it.",
      tone: "warning",
    };
  }
  switch (phase) {
    case "idle":
    case "unavailable":
      return {
        title: "Ready for explicit refresh",
        detail:
          "The existing WAM connection is ready. Refresh adds remote context without replacing local evidence.",
        tone: "brand",
      };
    case "loading":
      return {
        title: "Graph query in progress",
        detail:
          "Read-only sections resolve independently. You can cancel without stopping local collection.",
        tone: "brand",
      };
    case "ready":
      return {
        title: "Enrichment complete",
        detail:
          "Remote names and device status are shown beside the original local identifiers.",
        tone: "success",
      };
    case "partial":
      return {
        title: "Partial enrichment",
        detail:
          "Available sections are shown below. Denied, offline, skipped, and cancelled sections remain distinct.",
        tone: "warning",
      };
    case "error":
      return {
        title: "Graph query failed",
        detail: error ?? "Microsoft Graph enrichment could not be completed.",
        tone: "error",
      };
    case "cancelled":
      return {
        title: "Graph query cancelled",
        detail:
          "Local evidence was preserved. Refresh again whenever the existing connection is ready.",
        tone: "neutral",
      };
  }
}

function toneColor(tone: GlobalStateCopy["tone"]): string {
  switch (tone) {
    case "brand":
      return tokens.colorBrandForeground1;
    case "warning":
      return tokens.colorPaletteYellowForeground2;
    case "error":
      return tokens.colorPaletteRedForeground1;
    case "success":
      return tokens.colorPaletteGreenForeground1;
    case "neutral":
      return tokens.colorNeutralForeground3;
  }
}

function statusLabel(status: GraphSectionStatus): string {
  switch (status) {
    case "available":
      return "Available";
    case "notFound":
      return "Not found";
    case "permissionDenied":
      return "Permission denied";
    case "failed":
      return "Failed";
    case "skipped":
      return "Skipped";
    case "cancelled":
      return "Cancelled";
    default:
      return `Unknown · ${status}`;
  }
}

function statusColor(status: GraphSectionStatus): string {
  switch (status) {
    case "available":
      return tokens.colorPaletteGreenForeground1;
    case "permissionDenied":
    case "failed":
      return tokens.colorPaletteRedForeground1;
    case "notFound":
    case "cancelled":
      return tokens.colorPaletteYellowForeground2;
    default:
      return tokens.colorNeutralForeground3;
  }
}

function StatusIcon({ status }: { status: GraphSectionStatus }) {
  switch (status) {
    case "available":
      return <CheckmarkCircleRegular aria-hidden="true" />;
    case "permissionDenied":
    case "failed":
      return <DismissCircleRegular aria-hidden="true" />;
    case "notFound":
    case "cancelled":
      return <WarningRegular aria-hidden="true" />;
    default:
      return <PlugDisconnectedRegular aria-hidden="true" />;
  }
}

function GraphSectionCard<T>({
  title,
  section,
  children,
}: {
  title: string;
  section: GraphSection<T>;
  children?: ReactNode;
}) {
  return (
    <article
      aria-label={`Graph section ${title}`}
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderTop: `2px solid ${statusColor(section.status)}`,
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "start",
          justifyContent: "space-between",
          gap: 8,
          padding: "8px 9px 7px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <h3
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 11,
              fontWeight: 650,
              lineHeight: "15px",
            }}
          >
            {title}
          </h3>
          <div
            title={section.requiredScope ?? undefined}
            style={{
              marginTop: 1,
              overflow: "hidden",
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              lineHeight: "13px",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {section.requiredScope ?? "No additional scope requested"}
          </div>
        </div>
        <div
          style={{
            display: "flex",
            flexShrink: 0,
            alignItems: "center",
            gap: 5,
            color: statusColor(section.status),
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            fontWeight: 700,
          }}
        >
          {section.apiVersion === "beta" ? (
            <span
              style={{
                padding: "1px 4px",
                border: `1px solid ${tokens.colorPaletteYellowBorder2}`,
              }}
            >
              Beta
            </span>
          ) : section.apiVersion !== "notRequested" ? (
            <span>{section.apiVersion}</span>
          ) : null}
          <StatusIcon status={section.status} />
          <span>{statusLabel(section.status)}</span>
        </div>
      </div>
      <div
        style={{
          display: "grid",
          gap: 6,
          padding: "8px 9px 9px",
          color: tokens.colorNeutralForeground2,
          fontSize: 10,
          lineHeight: "14px",
        }}
      >
        {section.error ? (
          <div
            role={
              section.status === "failed" ||
              section.status === "permissionDenied"
                ? "alert"
                : "status"
            }
            style={{ color: statusColor(section.status) }}
          >
            <strong>{section.error.code}</strong> · {section.error.message}
            {section.error.blockedBy
              ? ` · Blocked by ${section.error.blockedBy}`
              : ""}
            {section.error.retryAfterSeconds !== null
              ? ` · Retry after ${section.error.retryAfterSeconds} seconds`
              : ""}
          </div>
        ) : null}
        {children}
      </div>
    </article>
  );
}

function AssignmentList({
  assignments,
}: {
  assignments: EspGraphAssignment[];
}) {
  if (assignments.length === 0) return null;
  return (
    <ul style={{ display: "grid", gap: 3, margin: "5px 0 0", paddingLeft: 17 }}>
      {assignments.map((assignment) => (
        <li key={assignment.assignmentId}>
          <strong>Declared targeting</strong> · {label(assignment.intent)} ·{" "}
          {assignment.targetKind} ·{" "}
          {assignment.targetId ?? "target unavailable"}
          {assignment.filterId ? (
            <span style={{ display: "block" }}>
              Filter · {assignment.filterId}
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function DeviceCandidate({
  candidate,
  disabled,
  onSelect,
}: {
  candidate: EspGraphManagedDevice;
  disabled: boolean;
  onSelect(managedDeviceId: string): void;
}) {
  return (
    <li
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 8,
        padding: "5px 0",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <span style={{ minWidth: 0 }}>
        <strong style={{ display: "block" }}>
          {candidate.deviceName ?? "Device name unavailable"}
        </strong>
        <code style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
          {candidate.managedDeviceId}
        </code>
      </span>
      <Button
        size="small"
        disabled={disabled}
        aria-label={`Select Graph device ${candidate.managedDeviceId}`}
        onClick={() => onSelect(candidate.managedDeviceId)}
      >
        Use device
      </Button>
    </li>
  );
}

function selectedDeviceLabel(device: EspGraphManagedDevice): string {
  return device.deviceName ?? device.managedDeviceId;
}

export function GraphEnrichmentPanel({
  snapshot,
  onRefresh,
  onCancel,
  onSelectDevice,
}: GraphEnrichmentPanelProps) {
  const graphApiEnabled = useUiStore((state) => state.graphApiEnabled);
  const graphApiStatus = useUiStore((state) => state.graphApiStatus);
  const graphPhase = useEspDiagnosticsStore((state) => state.graphPhase);
  const graphUnavailableReason = useEspDiagnosticsStore(
    (state) => state.graphUnavailableReason,
  );
  const graphError = useEspDiagnosticsStore((state) => state.graphError);
  const [controlError, setControlError] = useState<string | null>(null);
  const overlay = snapshot.graph;
  const stateCopy = globalStateCopy(
    graphPhase,
    graphUnavailableReason,
    graphApiEnabled,
    graphApiStatus,
    graphError,
  );
  const connected = graphApiEnabled && graphApiStatus === "connected";
  const loading = graphPhase === "loading";
  const localWorkloadIds = new Set(
    snapshot.workloads.map((workload) => workload.rawIdentifier),
  );

  const invokeControl = (operation: () => void | Promise<void>) => {
    setControlError(null);
    void Promise.resolve(operation()).catch((error: unknown) => {
      setControlError(error instanceof Error ? error.message : String(error));
    });
  };
  const refresh = onRefresh ?? (() => refreshEspGraphData());
  const cancel = onCancel ?? cancelEspGraphData;
  const selectDevice =
    onSelectDevice ??
    ((managedDeviceId: string) => refreshEspGraphData(managedDeviceId));

  const match = overlay?.deviceMatch.data;

  return (
    <section
      role="region"
      aria-labelledby="esp-graph-enrichment-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "8px 10px",
          borderLeft: `3px solid ${toneColor(stateCopy.tone)}`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div style={{ minWidth: 0 }}>
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
            Optional · existing WAM connection · read-only
          </div>
          <h2
            id="esp-graph-enrichment-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            Microsoft Graph enrichment
          </h2>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {loading ? (
            <Button
              size="small"
              appearance="secondary"
              icon={<StopRegular />}
              onClick={() => invokeControl(cancel)}
            >
              Cancel Graph query
            </Button>
          ) : null}
          <Button
            size="small"
            appearance="secondary"
            icon={<ArrowClockwiseRegular />}
            disabled={!connected || loading}
            onClick={() => invokeControl(refresh)}
          >
            Refresh Graph data
          </Button>
        </div>
      </div>

      <div
        aria-live="polite"
        style={{
          padding: "7px 10px 8px",
          borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          color: toneColor(stateCopy.tone),
          fontSize: 10,
          lineHeight: "14px",
        }}
      >
        <strong>{stateCopy.title}</strong>
        <span style={{ color: tokens.colorNeutralForeground2 }}>
          {" "}
          · {stateCopy.detail}
        </span>
        {controlError ? (
          <span
            role="alert"
            style={{
              display: "block",
              color: tokens.colorPaletteRedForeground1,
            }}
          >
            {controlError}
          </span>
        ) : null}
      </div>

      {overlay ? (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            alignItems: "start",
            gap: 8,
            padding: "0 10px 10px",
          }}
        >
          <GraphSectionCard
            title="Managed device"
            section={overlay.deviceMatch}
          >
            {match?.selected ? (
              <div>
                <strong>
                  Selected device · {selectedDeviceLabel(match.selected)}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {match.selected.managedDeviceId}
                </code>
                <span>
                  Match basis · {match.matchBasis ?? "unavailable"} ·{" "}
                  {label(match.confidence)} confidence
                </span>
              </div>
            ) : match && match.candidates.length > 0 ? (
              <div>
                <strong>
                  Selection is required before dependent queries can continue
                </strong>
                <ul
                  style={{ margin: "5px 0 0", padding: 0, listStyle: "none" }}
                >
                  {match.candidates.map((candidate) => (
                    <DeviceCandidate
                      key={candidate.managedDeviceId}
                      candidate={candidate}
                      disabled={!connected || loading}
                      onSelect={(managedDeviceId) =>
                        invokeControl(() => selectDevice(managedDeviceId))
                      }
                    />
                  ))}
                </ul>
              </div>
            ) : overlay.deviceMatch.status === "notFound" ? (
              <strong>No managed device match</strong>
            ) : null}
          </GraphSectionCard>

          <GraphSectionCard
            title="Autopilot identity"
            section={overlay.autopilotIdentity}
          >
            {overlay.autopilotIdentity.data ? (
              <div>
                <strong>
                  {overlay.autopilotIdentity.data.autopilotDeviceId}
                </strong>
                <span style={{ display: "block" }}>
                  Group tag ·{" "}
                  {overlay.autopilotIdentity.data.groupTag ?? "Not set"}
                </span>
              </div>
            ) : null}
          </GraphSectionCard>

          <GraphSectionCard
            title="Deployment profile"
            section={overlay.deploymentProfile}
          >
            {overlay.deploymentProfile.data ? (
              <div>
                <strong>
                  {overlay.deploymentProfile.data.displayName ??
                    "Profile name unavailable"}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {overlay.deploymentProfile.data.profileId}
                </code>
              </div>
            ) : null}
          </GraphSectionCard>

          <GraphSectionCard
            title="Intended deployment profile"
            section={overlay.intendedDeploymentProfile}
          >
            {overlay.intendedDeploymentProfile.data ? (
              <div>
                <strong>
                  {overlay.intendedDeploymentProfile.data.displayName ??
                    "Profile name unavailable"}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {overlay.intendedDeploymentProfile.data.profileId}
                </code>
              </div>
            ) : null}
          </GraphSectionCard>

          <GraphSectionCard
            title="Profile assignments"
            section={overlay.profileAssignments}
          >
            <AssignmentList
              assignments={overlay.profileAssignments.data ?? []}
            />
          </GraphSectionCard>

          <GraphSectionCard
            title="Autopilot events"
            section={overlay.autopilotEvents}
          >
            {(overlay.autopilotEvents.data ?? []).map((event) => (
              <div key={event.eventId}>
                <strong>{event.deploymentState.display}</strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {event.eventId}
                </code>
                {event.policyStatusDetails.map((detail) => (
                  <span
                    key={detail.statusDetailId}
                    style={{ display: "block" }}
                  >
                    Effective Autopilot status ·{" "}
                    {detail.displayName ??
                      detail.relatedObjectId ??
                      "Unnamed item"}{" "}
                    · {detail.status.display}
                  </span>
                ))}
              </div>
            ))}
          </GraphSectionCard>

          <GraphSectionCard
            title="Enrollment Status Page configuration"
            section={overlay.enrollmentConfiguration}
          >
            {overlay.enrollmentConfiguration.data ? (
              <div>
                <strong>
                  {overlay.enrollmentConfiguration.data.displayName ??
                    "Configuration name unavailable"}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {overlay.enrollmentConfiguration.data.configurationId}
                </code>
                <AssignmentList
                  assignments={overlay.enrollmentConfiguration.data.assignments}
                />
              </div>
            ) : null}
          </GraphSectionCard>

          <GraphSectionCard title="Applications" section={overlay.apps}>
            {(overlay.apps.data ?? []).map((app) => {
              const locallyTracked = localWorkloadIds.has(app.appId);
              return (
                <div
                  key={app.appId}
                  data-testid={`graph-record-${app.appId}`}
                  style={{
                    paddingTop: 5,
                    borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                  }}
                >
                  <strong>
                    {app.displayName ?? "Application name unavailable"}
                  </strong>
                  <code
                    style={{
                      display: "block",
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    }}
                  >
                    {app.appId}
                  </code>
                  {locallyTracked ? (
                    <span
                      style={{
                        display: "block",
                        color: tokens.colorPaletteGreenForeground1,
                      }}
                    >
                      Effective · local ESP tracking observed
                    </span>
                  ) : app.trackedOnEnrollmentStatus ? (
                    <span style={{ display: "block" }}>
                      Declared ESP tracking configuration
                    </span>
                  ) : null}
                  {app.status ? (
                    <span style={{ display: "block" }}>
                      Effective device status · {app.status.display}
                    </span>
                  ) : null}
                  <AssignmentList assignments={app.assignments} />
                  {app.assignments.length > 0 ? (
                    <span style={{ display: "block", marginTop: 3 }}>
                      Assignment intent alone does not prove this app is
                      blocking ESP.
                    </span>
                  ) : null}
                </div>
              );
            })}
          </GraphSectionCard>

          <GraphSectionCard title="Policies" section={overlay.policies}>
            {(overlay.policies.data ?? []).map((policy) => (
              <div
                key={policy.policyId}
                data-testid={`graph-record-${policy.policyId}`}
              >
                <strong>
                  {policy.displayName ?? "Policy name unavailable"}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {policy.policyId}
                </code>
                {policy.status ? (
                  <span style={{ display: "block" }}>
                    Effective device status · {policy.status.display}
                  </span>
                ) : null}
                <AssignmentList assignments={policy.assignments} />
              </div>
            ))}
          </GraphSectionCard>

          <GraphSectionCard title="Scripts" section={overlay.scripts}>
            {(overlay.scripts.data ?? []).map((script) => (
              <div
                key={script.scriptId}
                data-testid={`graph-record-${script.scriptId}`}
              >
                <strong>
                  {script.displayName ?? "Script name unavailable"}
                </strong>
                <code
                  style={{
                    display: "block",
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  }}
                >
                  {script.scriptId}
                </code>
                {script.status ? (
                  <span style={{ display: "block" }}>
                    Effective device status · {script.status.display}
                  </span>
                ) : null}
                <AssignmentList assignments={script.assignments} />
              </div>
            ))}
          </GraphSectionCard>
        </div>
      ) : null}
    </section>
  );
}
