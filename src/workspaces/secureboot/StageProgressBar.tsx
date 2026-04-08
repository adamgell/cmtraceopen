import { tokens } from "@fluentui/react-components";
import type { SecureBootStage } from "./types";

const SEGMENTS: { stage: SecureBootStage; label: string }[] = [
  { stage: "stage0", label: "Boot" },
  { stage: "stage1", label: "Opt-in" },
  { stage: "stage2", label: "WU" },
  { stage: "stage3", label: "Update" },
  { stage: "stage4", label: "Reboot" },
  { stage: "stage5", label: "Done" },
];

function stageIndex(stage: SecureBootStage): number {
  return parseInt(stage.replace("stage", ""), 10);
}

export interface StageProgressBarProps {
  currentStage: SecureBootStage;
}

export function StageProgressBar({ currentStage }: StageProgressBarProps) {
  const current = stageIndex(currentStage);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      <div style={{ display: "flex", gap: "3px", alignItems: "stretch" }}>
        {SEGMENTS.map(({ stage, label }, index) => {
          const segIndex = stageIndex(stage);
          const isFilled = segIndex <= current;
          const isActive = segIndex === current;

          return (
            <div
              key={stage}
              style={{
                flex: 1,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: "4px",
              }}
            >
              <div
                style={{
                  width: "100%",
                  height: "10px",
                  borderRadius:
                    index === 0
                      ? "5px 0 0 5px"
                      : index === SEGMENTS.length - 1
                        ? "0 5px 5px 0"
                        : "0",
                  backgroundColor: isFilled
                    ? tokens.colorPaletteGreenBackground3
                    : tokens.colorNeutralBackground4,
                  border: isActive
                    ? `2px solid ${tokens.colorPaletteGreenBorder2}`
                    : isFilled
                      ? `1px solid ${tokens.colorPaletteGreenBorder1}`
                      : `1px solid ${tokens.colorNeutralStroke2}`,
                  boxShadow: isActive
                    ? `0 0 6px 1px ${tokens.colorPaletteGreenBackground3}`
                    : undefined,
                  transition: "background-color 0.2s ease",
                }}
              />
              <div
                style={{
                  fontSize: "10px",
                  fontWeight: isActive ? 700 : 400,
                  color: isActive
                    ? tokens.colorPaletteGreenForeground2
                    : isFilled
                      ? tokens.colorPaletteGreenForeground1
                      : tokens.colorNeutralForeground4,
                  textAlign: "center",
                  letterSpacing: isActive ? "0.02em" : undefined,
                }}
              >
                {label}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
