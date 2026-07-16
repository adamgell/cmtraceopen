import { useCallback } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import {
  DocumentArrowUpRegular,
  FolderOpenRegular,
  PlayRegular,
  StopRegular,
} from "@fluentui/react-icons";
import { open } from "@tauri-apps/plugin-dialog";
import {
  startEspDiagnosticsSession,
  stopEspDiagnosticsSession,
} from "../../lib/commands";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { createUuidRequestId } from "../../lib/uuid-request-id";
import { useUiStore } from "../../stores/ui-store";
import { ActionCenter } from "./ActionCenter";
import { ElevationBanner } from "./ElevationBanner";
import { EvidenceSections } from "./EvidenceSections";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import { EspPhaseProgress } from "./EspPhaseProgress";
import { EspWorkloadTable } from "./EspWorkloadTable";
import { EspWorkspaceHeader } from "./EspWorkspaceHeader";
import { GraphEnrichmentPanel } from "./GraphEnrichmentPanel";
import {
  analyzeEspEvidenceSource,
  ESP_EVIDENCE_SOURCE_ERROR,
  resolveEspEvidenceSource,
} from "./index";
import { LiveActivity } from "./LiveActivity";
import { MsiexecStatus } from "./MsiexecStatus";
import "./esp-diagnostics.css";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function normalizeSelection(
  selection: string | string[] | null,
): string | null {
  if (!selection) return null;
  return Array.isArray(selection) ? (selection[0] ?? null) : selection;
}

async function analyzePath(
  path: string,
  sourceKind: "file" | "folder",
): Promise<void> {
  const source = { kind: sourceKind, path } as const;
  const store = useEspDiagnosticsStore.getState();
  if (!resolveEspEvidenceSource(source)) {
    store.rejectAnalysisInput(ESP_EVIDENCE_SOURCE_ERROR);
    return;
  }

  await analyzeEspEvidenceSource(source, "esp-workspace.import");
}

export function EspDiagnosticsWorkspace() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const graphPhase = useEspDiagnosticsStore((state) => state.graphPhase);
  const sessionId = useEspDiagnosticsStore((state) => state.sessionId);
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  const error = useEspDiagnosticsStore((state) => state.error);
  const graphError = useEspDiagnosticsStore((state) => state.graphError);
  const liveSupported = currentPlatform === "windows";
  const isBusy = ["analyzing", "starting", "stopping"].includes(phase);

  const importCapturedEvidence = useCallback(async () => {
    const path = normalizeSelection(
      await open({
        multiple: false,
        filters: [{ name: "ESP evidence", extensions: ["json", "cab", "zip"] }],
      }),
    );
    if (path) await analyzePath(path, "file");
  }, []);

  const importEvidenceFolder = useCallback(async () => {
    const path = normalizeSelection(
      await open({ multiple: false, directory: true }),
    );
    if (path) await analyzePath(path, "folder");
  }, []);

  const startLive = useCallback(async () => {
    const requestId = createUuidRequestId();
    const store = useEspDiagnosticsStore.getState();
    store.beginLiveStart(requestId);

    try {
      const envelope = await startEspDiagnosticsSession(requestId);
      store.applySessionUpdate({
        ...envelope,
        reason: "initialSnapshot",
        emittedAtUtc: envelope.snapshot.generatedAtUtc,
      });
    } catch (error) {
      store.fail(requestId, errorMessage(error));
    }
  }, []);

  const stopLive = useCallback(async () => {
    const activeSessionId = useEspDiagnosticsStore.getState().sessionId;
    if (!activeSessionId) return;

    const store = useEspDiagnosticsStore.getState();
    store.beginStop(activeSessionId);
    try {
      await stopEspDiagnosticsSession(activeSessionId);
      store.clearStoppedSession(activeSessionId);
    } catch (error) {
      const requestId = store.requestId;
      if (requestId) store.fail(requestId, errorMessage(error));
    }
  }, []);

  const headerActions = (
    <>
      <Button
        appearance="secondary"
        size="small"
        icon={<FolderOpenRegular />}
        disabled={isBusy || sessionId !== null}
        onClick={importEvidenceFolder}
      >
        Import evidence folder
      </Button>
      <Button
        appearance="secondary"
        size="small"
        icon={<DocumentArrowUpRegular />}
        disabled={isBusy || sessionId !== null}
        onClick={importCapturedEvidence}
      >
        Import captured evidence
      </Button>
      {sessionId ? (
        <Button
          appearance="primary"
          size="small"
          icon={<StopRegular />}
          disabled={phase === "stopping"}
          onClick={stopLive}
        >
          Stop live diagnostics
        </Button>
      ) : (
        <Button
          appearance="primary"
          size="small"
          icon={<PlayRegular />}
          disabled={!liveSupported || isBusy}
          onClick={startLive}
        >
          Start live diagnostics
        </Button>
      )}
    </>
  );

  return (
    <main
      aria-labelledby="esp-diagnostics-heading"
      className="esp-diagnostics-workspace"
      style={{
        width: "100%",
        height: "100%",
        minWidth: 0,
        overflow: "auto",
        color: tokens.colorNeutralForeground1,
        backgroundColor: tokens.colorNeutralBackground2,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <EspWorkspaceHeader
        snapshot={snapshot}
        workspacePhase={phase}
        graphPhase={graphPhase}
        actions={headerActions}
      />

      {snapshot ? <ElevationBanner elevation={snapshot.elevation} /> : null}

      <div
        style={{
          display: "grid",
          alignContent: "start",
          gap: 10,
          padding: 10,
        }}
      >
        {error ? (
          <div
            role="alert"
            style={{
              padding: "10px 12px",
              border: `1px solid ${tokens.colorPaletteRedBorder2}`,
              borderLeftWidth: 4,
              backgroundColor: tokens.colorPaletteRedBackground1,
              color: tokens.colorPaletteRedForeground1,
              fontSize: 12,
              fontWeight: 650,
            }}
          >
            {error}
          </div>
        ) : null}

        {graphError ? (
          <div
            role="alert"
            aria-label="Graph enrichment error"
            style={{
              padding: "10px 12px",
              border: `1px solid ${tokens.colorPaletteRedBorder2}`,
              borderLeftWidth: 4,
              backgroundColor: tokens.colorPaletteRedBackground1,
              color: tokens.colorPaletteRedForeground1,
              fontSize: 12,
              fontWeight: 650,
            }}
          >
            Graph enrichment failed. Local evidence remains available; check the
            Graph connection and retry.
          </div>
        ) : null}

        {snapshot ? (
          <>
            <div
              className="esp-cockpit-panel-grid"
              style={{
                display: "grid",
                alignItems: "start",
                gap: 10,
              }}
            >
              <ActionCenter findings={snapshot.findings} />
              <MsiexecStatus snapshot={snapshot} />
            </div>

            <EspWorkloadTable snapshot={snapshot} />

            <GraphEnrichmentPanel snapshot={snapshot} />

            <div
              className="esp-cockpit-panel-grid"
              style={{
                display: "grid",
                alignItems: "start",
                gap: 10,
              }}
            >
              <EspPhaseProgress snapshot={snapshot} />
              <LiveActivity entries={snapshot.activity} />
            </div>

            <EvidenceSections snapshot={snapshot} />
          </>
        ) : (
          <section
            aria-label="Diagnostic input status"
            style={{
              display: "grid",
              gridTemplateColumns: "auto minmax(0, 1fr)",
              alignItems: "center",
              gap: 12,
              minHeight: 88,
              padding: "14px 16px",
              border: `1px solid ${
                phase === "error"
                  ? tokens.colorPaletteRedBorder2
                  : tokens.colorNeutralStroke1
              }`,
              borderLeft: `4px solid ${
                phase === "analyzing" || phase === "starting"
                  ? tokens.colorBrandStroke1
                  : tokens.colorNeutralStrokeAccessible
              }`,
              backgroundColor: tokens.colorNeutralBackground1,
              boxShadow: tokens.shadow2,
            }}
          >
            {isBusy ? <Spinner size="small" /> : null}
            <div>
              <div
                style={{
                  color: tokens.colorNeutralForeground3,
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                }}
              >
                Diagnostic input
              </div>
              <strong style={{ display: "block", marginTop: 4, fontSize: 13 }}>
                {phase === "analyzing"
                  ? "Reading local artifacts…"
                  : phase === "starting"
                    ? "Starting the bounded local collector…"
                    : "Import captured evidence or start local diagnostics"}
              </strong>
              <div
                style={{
                  marginTop: 3,
                  color: tokens.colorNeutralForeground2,
                  fontSize: 11,
                  lineHeight: "16px",
                }}
              >
                CMTrace evidence folders, manifest.json, CAB, and ZIP are
                supported.
                {liveSupported
                  ? " Windows live acquisition is read-only."
                  : " Live acquisition requires Windows."}
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
