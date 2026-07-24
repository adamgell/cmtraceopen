import type { ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type {
  EspDiagnosticsStore,
  EspGraphPhase,
  EspWorkspacePhase,
} from "./esp-diagnostics-store";
import type {
  EspDiagnosticsSnapshot,
  EspElevationState,
  EspPhase,
  EspScenario,
} from "./types";

const scenarioLabels: Record<EspScenario, string> = {
  unknown: "Scenario not detected",
  autopilotV1: "Classic Autopilot ESP",
  existingDeviceJson: "Autopilot for existing devices",
  espOnly: "ESP only",
  autopilotDevicePreparationV2: "Autopilot Device Preparation",
};

const espPhaseLabels: Record<EspPhase, string> = {
  notStarted: "Not started",
  devicePreparation: "Device preparation",
  deviceSetup: "Device setup",
  accountSetup: "Account setup",
  completed: "Completed",
  failed: "Failed",
  unknown: "Unknown phase",
};

const localStateLabels: Record<EspWorkspacePhase, string> = {
  idle: "Waiting for evidence",
  analyzing: "Analyzing captured evidence",
  starting: "Starting live diagnostics",
  live: "Local collection live",
  stopping: "Stopping live diagnostics",
  ready: "Analysis ready",
  error: "Evidence analysis failed",
};

const graphStateLabels: Record<EspGraphPhase, string> = {
  disabled: "Off",
  unavailable: "Unavailable",
  idle: "Local only",
  loading: "Loading",
  ready: "Connected",
  partial: "Partial",
  error: "Error",
  cancelled: "Cancelled",
};

function elapsedLabel(snapshot: EspDiagnosticsSnapshot | null): string {
  if (!snapshot) return "Not available";

  const latestSessions = snapshot.sessions.filter(
    (session) => session.isLatest,
  );
  const candidates =
    latestSessions.length > 0 ? latestSessions : snapshot.sessions;
  const currentSession = [...candidates].sort((left, right) => {
    const leftStart = Date.parse(
      left.startedAt?.normalizedUtc ?? left.startedAt?.rawText ?? "",
    );
    const rightStart = Date.parse(
      right.startedAt?.normalizedUtc ?? right.startedAt?.rawText ?? "",
    );
    const leftValue = Number.isFinite(leftStart)
      ? leftStart
      : Number.MAX_SAFE_INTEGER;
    const rightValue = Number.isFinite(rightStart)
      ? rightStart
      : Number.MAX_SAFE_INTEGER;
    return (
      leftValue - rightValue || left.sessionId.localeCompare(right.sessionId)
    );
  })[0];
  const startedAt = currentSession?.startedAt?.normalizedUtc;
  if (!startedAt) return "Not available";

  const start = Date.parse(startedAt);
  const end = Date.parse(
    currentSession?.endedAt?.normalizedUtc ?? snapshot.generatedAtUtc,
  );
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
    return "Not available";
  }

  const totalSeconds = Math.floor((end - start) / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return [
    hours > 0 ? `${hours}h` : null,
    hours > 0 || minutes > 0 ? `${minutes}m` : null,
    `${String(seconds).padStart(2, "0")}s`,
  ]
    .filter(Boolean)
    .join(" ");
}

function coverageLabel(snapshot: EspDiagnosticsSnapshot | null): string {
  if (!snapshot || snapshot.coverage.length === 0) return "Not measured";
  const available = snapshot.coverage.filter(
    (source) => source.status === "available",
  ).length;
  return `${available} / ${snapshot.coverage.length} sources`;
}

interface MetricProps {
  label: string;
  value: string;
  detail?: string;
  accent?: boolean;
}

function Metric({ label, value, detail, accent = false }: MetricProps) {
  return (
    <div
      style={{
        minWidth: 0,
        padding: "9px 12px 10px",
        borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        borderTop: `2px solid ${
          accent ? tokens.colorBrandStroke1 : "transparent"
        }`,
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        style={{
          color: tokens.colorNeutralForeground3,
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: "0.1em",
          lineHeight: "13px",
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
      <strong
        style={{
          display: "block",
          marginTop: 3,
          overflow: "hidden",
          color: accent
            ? tokens.colorBrandForeground1
            : tokens.colorNeutralForeground1,
          fontFamily: LOG_UI_FONT_FAMILY,
          fontSize: 12,
          fontWeight: 650,
          lineHeight: "17px",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={value}
      >
        {value}
      </strong>
      {detail ? (
        <span
          style={{
            display: "block",
            overflow: "hidden",
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            lineHeight: "12px",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {detail}
        </span>
      ) : null}
    </div>
  );
}

interface EspWorkspaceHeaderProps {
  snapshot: EspDiagnosticsSnapshot | null;
  elevation: EspElevationState | null;
  workspacePhase: EspDiagnosticsStore["phase"];
  graphPhase: EspDiagnosticsStore["graphPhase"];
  actions: ReactNode;
}

export function EspWorkspaceHeader({
  snapshot,
  elevation,
  workspacePhase,
  graphPhase,
  actions,
}: EspWorkspaceHeaderProps) {
  const scenario = snapshot
    ? scenarioLabels[snapshot.scenario]
    : "Scenario not detected";
  const espPhase = snapshot
    ? espPhaseLabels[snapshot.phase]
    : "No evidence loaded";
  const elevationLabel = !elevation
    ? "Unknown"
    : elevation.isElevated
      ? "Elevated"
      : "Standard user";

  return (
    <header
      style={{
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 54,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 16,
          padding: "8px 14px 8px 16px",
          background: `linear-gradient(90deg, ${tokens.colorNeutralBackground1} 0%, ${tokens.colorNeutralBackground2} 100%)`,
        }}
      >
        <div style={{ minWidth: 220 }}>
          <div
            style={{
              color: tokens.colorBrandForeground1,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.13em",
              lineHeight: "12px",
              textTransform: "uppercase",
            }}
          >
            Enrollment status page · read-only local evidence
          </div>
          <h1
            id="esp-diagnostics-heading"
            style={{
              margin: "1px 0 0",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 20,
              fontWeight: 650,
              lineHeight: "25px",
            }}
          >
            ESP Diagnostics
          </h1>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            flexWrap: "wrap",
            gap: 6,
          }}
        >
          {actions}
        </div>
      </div>

      <div
        aria-label="ESP session summary"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(7, minmax(112px, 1fr))",
          borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          overflowX: "auto",
        }}
      >
        <Metric label="Scenario" value={scenario} />
        <Metric label="ESP phase" value={espPhase} />
        <Metric label="Elapsed" value={elapsedLabel(snapshot)} />
        <Metric label="Local coverage" value={coverageLabel(snapshot)} />
        <Metric
          label="Local state"
          value={localStateLabels[workspacePhase]}
          detail={
            workspacePhase === "live" ? "Event stream attached" : undefined
          }
          accent={workspacePhase === "live"}
        />
        <Metric label="Graph" value={graphStateLabels[graphPhase]} />
        <Metric label="Administrator" value={elevationLabel} />
      </div>
    </header>
  );
}
