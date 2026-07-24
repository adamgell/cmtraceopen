import { useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import {
  ArrowResetRegular,
  FlashRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import { espFlipAppInstalled, espRestoreAppState } from "../../lib/commands";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { lookupEspGraphName } from "./esp-graph-names";
import type { EspAppFlipBackup, EspWorkload } from "./types";

type Outcome =
  | { kind: "flipped"; backup: EspAppFlipBackup }
  | { kind: "error"; message: string };

interface EspActionsProps {
  failedApps: EspWorkload[];
  graphNames: Map<string, string>;
  elevated: boolean;
}

function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "The action failed.";
}

function appName(
  workload: EspWorkload,
  graphNames: Map<string, string>,
): string {
  return (
    workload.displayName ??
    lookupEspGraphName(graphNames, workload.rawIdentifier) ??
    workload.rawIdentifier
  );
}

const eyebrow = {
  color: tokens.colorNeutralForeground3,
  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
  fontSize: 10,
  fontWeight: 700,
  letterSpacing: "0.09em",
  lineHeight: "11px",
  textTransform: "uppercase",
} as const;

export function EspActions({ failedApps, graphNames, elevated }: EspActionsProps) {
  const [confirming, setConfirming] = useState<EspWorkload | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<Map<string, Outcome>>(new Map());

  if (failedApps.length === 0) {
    return null;
  }

  const setOutcome = (appId: string, outcome: Outcome | null) =>
    setOutcomes((prev) => {
      const next = new Map(prev);
      if (outcome) next.set(appId, outcome);
      else next.delete(appId);
      return next;
    });

  const runFlip = async (workload: EspWorkload) => {
    const appId = workload.rawIdentifier;
    setConfirming(null);
    setPending(appId);
    setOutcome(appId, null);
    try {
      const result = await espFlipAppInstalled(appId);
      setOutcome(appId, { kind: "flipped", backup: result.backup });
    } catch (error) {
      setOutcome(appId, { kind: "error", message: errorText(error) });
    } finally {
      setPending(null);
    }
  };

  const runRestore = async (workload: EspWorkload, backup: EspAppFlipBackup) => {
    const appId = workload.rawIdentifier;
    setPending(appId);
    try {
      await espRestoreAppState(backup);
      setOutcome(appId, null);
    } catch (error) {
      setOutcome(appId, { kind: "error", message: errorText(error) });
    } finally {
      setPending(null);
    }
  };

  return (
    <section
      role="region"
      aria-labelledby="esp-actions-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorPaletteRedBorder2}`,
        borderLeft: `4px solid ${tokens.colorPaletteRedBorderActive}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          padding: "8px 12px",
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div style={eyebrow}>Actions · writes to this device</div>
        <h2
          id="esp-actions-heading"
          style={{
            margin: "1px 0 0",
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 13,
            fontWeight: 650,
            lineHeight: "17px",
          }}
        >
          Force ESP past a failed app
        </h2>
        <p
          style={{
            margin: "4px 0 0",
            color: tokens.colorNeutralForeground2,
            fontSize: 11,
            lineHeight: "15px",
          }}
        >
          Flips the app's ESP tracking state to Installed and clears its error so
          setup can continue. This does not install the app — it only stops ESP
          blocking on it. A backup is taken first so it can be undone.
        </p>
      </div>

      {!elevated ? (
        <div
          role="status"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 7,
            padding: "7px 12px",
            borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
            color: tokens.colorPaletteYellowForeground2,
            fontSize: 11,
          }}
        >
          <WarningRegular aria-hidden="true" /> Run CMTrace Open as administrator
          to use these actions (writing to HKLM requires elevation).
        </div>
      ) : null}

      <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
        {failedApps.map((workload) => {
          const appId = workload.rawIdentifier;
          const outcome = outcomes.get(appId);
          const busy = pending === appId;
          return (
            <li
              key={appId}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
                padding: "8px 12px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontFamily: LOG_UI_FONT_FAMILY,
                    fontSize: 12,
                    fontWeight: 650,
                    overflowWrap: "anywhere",
                    wordBreak: "break-word",
                  }}
                >
                  {appName(workload, graphNames)}
                </div>
                <div
                  style={{
                    color: tokens.colorNeutralForeground3,
                    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    fontSize: 10,
                    marginTop: 1,
                  }}
                >
                  {workload.enforcementErrorCode?.hex ??
                    workload.exitCode?.hex ??
                    "Failed"}
                </div>
                {outcome?.kind === "flipped" ? (
                  <div
                    style={{
                      color: tokens.colorPaletteGreenForeground1,
                      fontSize: 10,
                      marginTop: 2,
                    }}
                  >
                    Forced to Installed. Click Try again on the ESP; the app is
                    still not installed.
                  </div>
                ) : null}
                {outcome?.kind === "error" ? (
                  <div
                    style={{
                      color: tokens.colorPaletteRedForeground1,
                      fontSize: 10,
                      marginTop: 2,
                      overflowWrap: "anywhere",
                    }}
                  >
                    {outcome.message}
                  </div>
                ) : null}
              </div>

              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                {outcome?.kind === "flipped" ? (
                  <Button
                    size="small"
                    icon={busy ? <Spinner size="tiny" /> : <ArrowResetRegular />}
                    disabled={busy}
                    onClick={() => runRestore(workload, outcome.backup)}
                  >
                    Restore
                  </Button>
                ) : (
                  <Button
                    appearance="primary"
                    size="small"
                    icon={busy ? <Spinner size="tiny" /> : <FlashRegular />}
                    disabled={busy || !elevated}
                    onClick={() => setConfirming(workload)}
                  >
                    Force past ESP
                  </Button>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      <Dialog
        open={confirming !== null}
        onOpenChange={(_, data) => {
          if (!data.open) setConfirming(null);
        }}
      >
        <DialogSurface>
          <DialogBody>
            <DialogTitle>Force ESP past this app?</DialogTitle>
            <DialogContent>
              <p style={{ marginTop: 0 }}>
                This writes to <strong>this device's</strong> registry for{" "}
                <strong>
                  {confirming ? appName(confirming, graphNames) : ""}
                </strong>
                :
              </p>
              <ul style={{ margin: "6px 0", paddingLeft: 20, fontSize: 13 }}>
                <li>Sets its ESP InstallationState to Installed (3).</li>
                <li>Clears the recorded error.</li>
                <li>Backs up the current values first, so you can undo it.</li>
              </ul>
              <p style={{ marginBottom: 0 }}>
                The app is <strong>not installed</strong> by this — it only stops
                ESP from blocking on it.
              </p>
            </DialogContent>
            <DialogActions>
              <Button
                appearance="secondary"
                onClick={() => setConfirming(null)}
              >
                Cancel
              </Button>
              <Button
                appearance="primary"
                onClick={() => confirming && runFlip(confirming)}
              >
                Force past ESP
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </section>
  );
}
