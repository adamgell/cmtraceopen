import { useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import {
  ShieldArrowRightRegular,
  WarningShieldRegular,
} from "@fluentui/react-icons";
import { restartEspAsAdministrator } from "../../lib/commands";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { EspElevationState } from "./types";

interface ElevationBannerProps {
  elevation: EspElevationState;
}

export function ElevationBanner({ elevation }: ElevationBannerProps) {
  const [actionState, setActionState] = useState<
    "idle" | "requesting" | "requested" | "cancelled" | "failed"
  >("idle");

  if (elevation.isElevated) return null;

  const restart = async () => {
    setActionState("requesting");
    try {
      const result = await restartEspAsAdministrator();
      setActionState(
        result.launched
          ? "requested"
          : result.reason === "elevationCancelled"
            ? "cancelled"
            : "failed",
      );
    } catch {
      setActionState("failed");
    }
  };

  const restrictedCount = elevation.restrictedSources.length;
  const coverageStatement =
    restrictedCount === 0
      ? "Protected evidence coverage may still be incomplete."
      : `${restrictedCount} restricted evidence ${
          restrictedCount === 1 ? "source is" : "sources are"
        } unavailable:`;

  return (
    <section
      role="region"
      aria-label="Administrator coverage recommendation"
      style={{
        display: "grid",
        gridTemplateColumns: "auto minmax(0, 1fr) auto",
        alignItems: "center",
        gap: 12,
        padding: "9px 14px",
        borderBottom: `1px solid ${tokens.colorPaletteYellowBorder2}`,
        backgroundColor: tokens.colorPaletteYellowBackground1,
        color: tokens.colorNeutralForeground1,
      }}
    >
      <WarningShieldRegular
        aria-hidden="true"
        style={{
          width: 22,
          height: 22,
          color: tokens.colorPaletteYellowForeground2,
        }}
      />
      <div style={{ minWidth: 0, fontFamily: LOG_UI_FONT_FAMILY }}>
        <div style={{ fontSize: 12, fontWeight: 650, lineHeight: "17px" }}>
          Administrator access recommended · Coverage impact:{" "}
          {coverageStatement}
        </div>
        {restrictedCount > 0 ? (
          <ul
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "2px 14px",
              margin: "3px 0 0",
              padding: 0,
              color: tokens.colorNeutralForeground2,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 10,
              lineHeight: "14px",
              listStylePosition: "inside",
            }}
          >
            {elevation.restrictedSources.map((source) => (
              <li key={source}>{source}</li>
            ))}
          </ul>
        ) : null}
        {!elevation.restartSupported ? (
          <div style={{ marginTop: 3, fontSize: 11, fontWeight: 600 }}>
            Close CMTrace Open and relaunch it explicitly as administrator.
          </div>
        ) : null}
        <div aria-live="polite" style={{ marginTop: 2, fontSize: 11 }}>
          {actionState === "requested"
            ? "Administrator restart requested."
            : actionState === "cancelled"
              ? "Administrator restart was cancelled; coverage remains partial."
              : actionState === "failed"
                ? "Administrator restart could not be started; coverage remains partial."
                : null}
        </div>
      </div>
      {elevation.restartSupported ? (
        <Button
          appearance="primary"
          size="small"
          icon={<ShieldArrowRightRegular />}
          disabled={actionState === "requesting" || actionState === "requested"}
          onClick={restart}
        >
          Restart as administrator
        </Button>
      ) : null}
    </section>
  );
}
