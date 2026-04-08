import { Button, tokens } from "@fluentui/react-components";
import type { SecureBootStage } from "./types";

const STAGE_LABELS: Record<SecureBootStage, string> = {
  stage0: "Secure Boot Disabled",
  stage1: "Opt-in Not Configured",
  stage2: "Awaiting Windows Update",
  stage3: "Update In Progress",
  stage4: "Pending Reboot",
  stage5: "Compliant",
};

const STAGE_DESCRIPTIONS: Record<SecureBootStage, string> = {
  stage0: "Secure Boot is not enabled on this device. UEFI CA 2023 opt-in cannot proceed until Secure Boot is active.",
  stage1: "Secure Boot is enabled but the managed opt-in registry key is not configured. Policy or script deployment is required.",
  stage2: "Opt-in is configured and the device is eligible. Waiting for Windows Update to deliver the UEFI CA 2023 update.",
  stage3: "The Windows Update is available and the remediation script is actively applying the update.",
  stage4: "The update has been applied. A reboot is required to activate the new UEFI CA 2023 certificate.",
  stage5: "The UEFI CA 2023 certificate is active and the device is compliant.",
};

type StageTier = "good" | "warn" | "bad";

function stageTier(stage: SecureBootStage): StageTier {
  if (stage === "stage5") return "good";
  if (stage === "stage0" || stage === "stage1") return "bad";
  return "warn";
}

function stageColors(tier: StageTier) {
  switch (tier) {
    case "good":
      return {
        background: tokens.colorPaletteGreenBackground2,
        text: tokens.colorPaletteGreenForeground2,
        border: tokens.colorPaletteGreenBorder2,
        badge: tokens.colorPaletteGreenBackground1,
      };
    case "bad":
      return {
        background: tokens.colorPaletteRedBackground2,
        text: tokens.colorPaletteRedForeground2,
        border: tokens.colorPaletteRedBorder2,
        badge: tokens.colorPaletteRedBackground1,
      };
    case "warn":
    default:
      return {
        background: tokens.colorPaletteYellowBackground2,
        text: tokens.colorPaletteYellowForeground2,
        border: tokens.colorPaletteYellowBorder2,
        badge: tokens.colorPaletteYellowBackground1,
      };
  }
}

export interface StatusBannerProps {
  stage: SecureBootStage;
  scanTimestamp?: string;
  onRescan?: () => void;
  isScanning?: boolean;
}

export function StatusBanner({
  stage,
  scanTimestamp,
  onRescan,
  isScanning = false,
}: StatusBannerProps) {
  const tier = stageTier(stage);
  const colors = stageColors(tier);
  const stageNum = parseInt(stage.replace("stage", ""), 10);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        padding: "12px 16px",
        backgroundColor: colors.background,
        border: `1px solid ${colors.border}`,
        borderRadius: "8px",
        flexWrap: "wrap",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", minWidth: 0 }}>
        <div
          style={{
            flexShrink: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: "32px",
            height: "32px",
            borderRadius: "50%",
            backgroundColor: colors.badge,
            border: `1px solid ${colors.border}`,
            fontSize: "14px",
            fontWeight: 700,
            color: colors.text,
          }}
        >
          {stageNum}
        </div>
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontSize: "inherit",
              fontWeight: 700,
              color: colors.text,
              lineHeight: 1.3,
            }}
          >
            {STAGE_LABELS[stage]}
          </div>
          <div
            style={{
              marginTop: "4px",
              fontSize: "12px",
              color: colors.text,
              opacity: 0.85,
              lineHeight: 1.5,
            }}
          >
            {STAGE_DESCRIPTIONS[stage]}
          </div>
          {scanTimestamp && (
            <div
              style={{
                marginTop: "6px",
                fontSize: "11px",
                color: colors.text,
                opacity: 0.65,
              }}
            >
              Scanned: {scanTimestamp}
            </div>
          )}
        </div>
      </div>

      {onRescan && (
        <Button
          appearance="secondary"
          disabled={isScanning}
          onClick={onRescan}
          style={{ flexShrink: 0 }}
        >
          {isScanning ? "Scanning…" : "Rescan"}
        </Button>
      )}
    </div>
  );
}
