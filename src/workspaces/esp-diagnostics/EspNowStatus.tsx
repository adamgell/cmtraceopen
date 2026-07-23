import type { ReactNode } from "react";
import { Spinner, tokens } from "@fluentui/react-components";
import {
  CheckmarkCircleFilled,
  ClockRegular,
  ErrorCircleFilled,
} from "@fluentui/react-icons";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { EspCurrentTask, EspTaskState } from "./esp-current-task";
import { lookupEspGraphName } from "./esp-graph-names";
import type { EspPhase, EspWorkload } from "./types";

function phaseLabel(phase: EspPhase): string {
  switch (phase) {
    case "notStarted":
      return "Not started";
    case "devicePreparation":
      return "Device preparation";
    case "deviceSetup":
      return "Device setup";
    case "accountSetup":
      return "Account setup";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "unknown":
      return "Unknown phase";
  }
}

function accentColor(state: EspTaskState): string {
  switch (state) {
    case "running":
      return tokens.colorBrandForeground1;
    case "complete":
      return tokens.colorPaletteGreenForeground1;
    case "failed":
      return tokens.colorPaletteRedForeground1;
    case "waiting":
    case "idle":
      return tokens.colorNeutralForeground3;
  }
}

function workloadName(
  workload: EspWorkload,
  graphNames: Map<string, string>,
): string {
  return (
    workload.displayName ??
    lookupEspGraphName(graphNames, workload.rawIdentifier) ??
    workload.rawIdentifier
  );
}

interface Headline {
  label: string;
  primary: string;
}

function headlineFor(
  task: EspCurrentTask,
  graphNames: Map<string, string>,
): Headline {
  const { state, workload, runningCount, stats } = task;
  switch (state) {
    case "running": {
      const extra = runningCount > 1 ? ` +${runningCount - 1} more` : "";
      return {
        label: `${(workload?.status.display ?? "Working").toUpperCase()}${extra}`,
        primary: workload ? workloadName(workload, graphNames) : "Working",
      };
    }
    case "complete":
      return { label: "COMPLETE", primary: "Enrollment complete" };
    case "failed":
      return {
        label: "FAILED",
        primary: workload ? workloadName(workload, graphNames) : "Setup failed",
      };
    case "waiting":
      return {
        label: "WAITING",
        primary:
          stats.queued > 0
            ? `Next of ${stats.queued} queued workload${stats.queued === 1 ? "" : "s"}`
            : "Waiting for next workload",
      };
    case "idle":
      return {
        label: "IDLE",
        primary:
          stats.total === 0
            ? "Awaiting workload telemetry"
            : "No active workload",
      };
  }
}

function glyphFor(state: EspTaskState, accent: string): ReactNode {
  switch (state) {
    case "running":
      return <Spinner size="tiny" aria-hidden />;
    case "complete":
      return <CheckmarkCircleFilled aria-hidden style={{ color: accent }} />;
    case "failed":
      return <ErrorCircleFilled aria-hidden style={{ color: accent }} />;
    case "waiting":
    case "idle":
      return <ClockRegular aria-hidden style={{ color: accent }} />;
  }
}

function ProgressBar({ stats }: { stats: EspCurrentTask["stats"] }) {
  const total = Math.max(stats.total, 1);
  const segment = (count: number, color: string, key: string): ReactNode =>
    count > 0 ? (
      <div
        key={key}
        style={{ width: `${(count / total) * 100}%`, backgroundColor: color }}
      />
    ) : null;
  return (
    <div
      aria-hidden
      style={{
        display: "flex",
        height: 6,
        marginTop: 8,
        borderRadius: 3,
        overflow: "hidden",
        backgroundColor: tokens.colorNeutralBackground4,
      }}
    >
      {segment(stats.done, tokens.colorPaletteGreenBackground3, "done")}
      {segment(stats.running, tokens.colorBrandBackground, "running")}
      {segment(stats.failed, tokens.colorPaletteRedBackground3, "failed")}
    </div>
  );
}

function Count({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <span style={{ color }}>
      <strong>{value}</strong> {label}
    </span>
  );
}

interface EspNowStatusProps {
  task: EspCurrentTask;
  phase: EspPhase;
  graphNames: Map<string, string>;
  isLive: boolean;
}

export function EspNowStatus({
  task,
  phase,
  graphNames,
  isLive,
}: EspNowStatusProps) {
  const accent = accentColor(task.state);
  const { label, primary } = headlineFor(task, graphNames);
  const { stats } = task;

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Current task: ${label}. ${primary}. ${stats.done} of ${stats.total} workloads complete.`}
      style={{
        minWidth: 0,
        borderLeft: `4px solid ${accent}`,
        padding: "9px 12px 11px",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
        }}
      >
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.09em",
            textTransform: "uppercase",
          }}
        >
          <span
            className={isLive ? "esp-now-pulse-dot" : undefined}
            aria-hidden
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              backgroundColor: isLive
                ? tokens.colorPaletteGreenForeground1
                : tokens.colorNeutralForeground4,
            }}
          />
          {isLive ? "Live" : "Captured"} · {phaseLabel(phase)}
        </span>
        <span
          style={{
            color: tokens.colorNeutralForeground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: 10,
          }}
        >
          {stats.total} tracked
        </span>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 9,
          marginTop: 7,
        }}
      >
        <span
          style={{
            display: "inline-flex",
            fontSize: 18,
            color: accent,
            lineHeight: 0,
          }}
        >
          {glyphFor(task.state, accent)}
        </span>
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              color: accent,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.07em",
              lineHeight: "12px",
            }}
          >
            {label}
          </div>
          <div
            style={{
              marginTop: 1,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 15,
              fontWeight: 650,
              lineHeight: "19px",
              overflowWrap: "anywhere",
              wordBreak: "break-word",
            }}
          >
            {primary}
          </div>
        </div>
      </div>

      <ProgressBar stats={stats} />

      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "2px 12px",
          marginTop: 6,
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: 10,
          color: tokens.colorNeutralForeground2,
        }}
      >
        <Count
          value={stats.done}
          label={`/ ${stats.total} complete`}
          color={tokens.colorPaletteGreenForeground1}
        />
        {stats.running > 0 ? (
          <Count
            value={stats.running}
            label="running"
            color={tokens.colorBrandForeground1}
          />
        ) : null}
        {stats.failed > 0 ? (
          <Count
            value={stats.failed}
            label="failed"
            color={tokens.colorPaletteRedForeground1}
          />
        ) : null}
        {stats.queued > 0 ? (
          <Count
            value={stats.queued}
            label="queued"
            color={tokens.colorNeutralForeground3}
          />
        ) : null}
      </div>
    </div>
  );
}
