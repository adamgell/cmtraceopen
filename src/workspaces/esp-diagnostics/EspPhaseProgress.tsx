import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import type { EspDiagnosticsSnapshot, EspPhase } from "./types";

type StepState = "Complete" | "Current" | "Pending" | "Failed" | "Unknown";

interface PhaseStep {
  id: string;
  label: string;
}

const classicSteps: PhaseStep[] = [
  { id: "devicePreparation", label: "Device preparation" },
  { id: "deviceSetup", label: "Device setup" },
  { id: "accountSetup", label: "Account setup" },
];

const devicePreparationSteps: PhaseStep[] = [
  { id: "agent", label: "Agent bootstrap" },
  { id: "policy", label: "Policy + scripts" },
  { id: "workloads", label: "Applications + certificates" },
  { id: "completion", label: "Completion" },
];

function currentStepIndex(phase: EspPhase, isDevicePreparationV2: boolean) {
  if (isDevicePreparationV2) {
    switch (phase) {
      case "notStarted":
      case "devicePreparation":
        return 0;
      case "deviceSetup":
        return 1;
      case "accountSetup":
        return 2;
      case "completed":
        return 4;
      case "failed":
        return 3;
      case "unknown":
        return -1;
    }
  }

  switch (phase) {
    case "notStarted":
    case "devicePreparation":
      return 0;
    case "deviceSetup":
      return 1;
    case "accountSetup":
      return 2;
    case "completed":
      return 3;
    case "failed":
      return 2;
    case "unknown":
      return -1;
  }
}

function stateForStep(
  stepIndex: number,
  currentIndex: number,
  phase: EspPhase,
): StepState {
  if (phase === "unknown") return "Unknown";
  if (phase === "failed" && stepIndex === currentIndex) return "Failed";
  if (currentIndex >= 0 && stepIndex < currentIndex) return "Complete";
  if (stepIndex === currentIndex) return "Current";
  return "Pending";
}

function stateGlyph(state: StepState): string {
  switch (state) {
    case "Complete":
      return "✓";
    case "Current":
      return "▶";
    case "Failed":
      return "!";
    case "Pending":
      return "○";
    case "Unknown":
      return "?";
  }
}

function stateColor(state: StepState): string {
  switch (state) {
    case "Complete":
      return tokens.colorPaletteGreenForeground1;
    case "Current":
      return tokens.colorBrandForeground1;
    case "Failed":
      return tokens.colorPaletteRedForeground1;
    case "Pending":
    case "Unknown":
      return tokens.colorNeutralForeground3;
  }
}

interface EspPhaseProgressProps {
  snapshot: EspDiagnosticsSnapshot;
}

export function EspPhaseProgress({ snapshot }: EspPhaseProgressProps) {
  const latestSession =
    snapshot.sessions.find((session) => session.isLatest) ??
    snapshot.sessions[snapshot.sessions.length - 1];
  const isDevicePreparationV2 =
    snapshot.scenario === "autopilotDevicePreparationV2" ||
    latestSession?.kind === "devicePreparationV2";
  const steps = isDevicePreparationV2
    ? devicePreparationSteps
    : classicSteps;
  const currentIndex = currentStepIndex(snapshot.phase, isDevicePreparationV2);

  return (
    <section
      role="region"
      aria-labelledby="esp-phase-progress-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
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
            Scenario-specific state machine
          </div>
          <h2
            id="esp-phase-progress-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            ESP phase progress
          </h2>
        </div>
        <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 10 }}>
          {isDevicePreparationV2
            ? "Device Preparation phases"
            : "Classic ESP phases"}
        </strong>
      </div>

      <ol
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${steps.length}, minmax(100px, 1fr))`,
          margin: 0,
          padding: 0,
          listStyle: "none",
        }}
      >
        {steps.map((step, index) => {
          const state = stateForStep(index, currentIndex, snapshot.phase);
          return (
            <li
              key={step.id}
              style={{
                minWidth: 0,
                padding: "9px 9px 10px",
                borderTop: `2px solid ${stateColor(state)}`,
                borderRight:
                  index === steps.length - 1
                    ? "none"
                    : `1px solid ${tokens.colorNeutralStroke2}`,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                  color: stateColor(state),
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: 10,
                  fontWeight: 700,
                  lineHeight: "14px",
                }}
              >
                <span aria-hidden="true">{stateGlyph(state)}</span>
                <span>
                  {step.label} · {state}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
      <div
        style={{
          padding: "5px 9px",
          borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          color: tokens.colorNeutralForeground3,
          fontSize: 9,
          lineHeight: "13px",
        }}
      >
        {isDevicePreparationV2
          ? "Device Preparation tracks agent, scripts, applications, and certificates under its own timeout and skip rules."
          : "Classic ESP evaluates device and account setup as separate blocking phases."}
      </div>
    </section>
  );
}
