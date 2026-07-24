import { useCallback, useEffect, useMemo } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import {
  ArrowDownloadRegular,
  ArrowUploadRegular,
  DocumentArrowUpRegular,
  FolderOpenRegular,
  PlayRegular,
  StopRegular,
} from "@fluentui/react-icons";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import {
  getEspDiagnosticsSession,
  getEspElevationState,
  startEspDiagnosticsSession,
  stopEspDiagnosticsSession,
  writeTextOutputFile,
} from "../../lib/commands";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import { createUuidRequestId } from "../../lib/uuid-request-id";
import { useUiStore } from "../../stores/ui-store";
import { ActionCenter } from "./ActionCenter";
import { buildEspGraphNameMap } from "./esp-graph-names";
import { ElevationBanner } from "./ElevationBanner";
import { EvidenceSections } from "./EvidenceSections";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import { EspPhaseProgress } from "./EspPhaseProgress";
import { EspWorkloadTable } from "./EspWorkloadTable";
import { EspWorkspaceHeader } from "./EspWorkspaceHeader";
import {
  buildEspSessionCapture,
  parseEspSessionCapture,
  serializeEspSessionCapture,
} from "./esp-session-capture";
import { GraphEnrichmentPanel } from "./GraphEnrichmentPanel";
import {
  analyzeEspEvidenceSource,
  ESP_EVIDENCE_SOURCE_ERROR,
  resolveEspEvidenceSource,
} from "./index";
import { LiveActivity } from "./LiveActivity";
import { MsiexecStatus } from "./MsiexecStatus";
import type {
  EspElevationState,
  EspSessionState,
  EspUpdateReason,
} from "./types";
import "./esp-diagnostics.css";

const STARTING_SESSION_POLL_INTERVAL_MS = 100;

const ELEVATION_PROBE_FALLBACK: EspElevationState = {
  isElevated: false,
  restartSupported: true,
  restrictedSources: [],
};

function validElevationState(value: unknown): value is EspElevationState {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<EspElevationState>;
  return (
    typeof candidate.isElevated === "boolean" &&
    typeof candidate.restartSupported === "boolean" &&
    Array.isArray(candidate.restrictedSources) &&
    candidate.restrictedSources.every((source) => typeof source === "string")
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function updateReasonForSessionState(state: EspSessionState): EspUpdateReason {
  switch (state) {
    case "stopped":
    case "completed":
      return "stopped";
    case "expired":
      return "expired";
    case "error":
      return "error";
    case "starting":
    case "live":
    case "stopping":
      return "initialSnapshot";
  }
}

function ownsStartingSession(requestId: string, sessionId: string): boolean {
  const state = useEspDiagnosticsStore.getState();
  return (
    state.phase === "starting" &&
    state.requestId === requestId &&
    state.sessionId === sessionId
  );
}

async function recoverStartingSession(
  requestId: string,
  sessionId: string,
): Promise<void> {
  while (ownsStartingSession(requestId, sessionId)) {
    try {
      const envelope = await getEspDiagnosticsSession(sessionId);
      const store = useEspDiagnosticsStore.getState();
      if (store.requestId !== requestId || store.sessionId !== sessionId) {
        return;
      }
      store.applySessionUpdate({
        ...envelope,
        reason: updateReasonForSessionState(envelope.state),
        emittedAtUtc: envelope.snapshot.generatedAtUtc,
      });
      if (envelope.state !== "starting") {
        return;
      }
    } catch {
      // A registered event listener can still complete startup. Retry only
      // while this exact session remains the current Starting owner.
    }

    if (!ownsStartingSession(requestId, sessionId)) {
      return;
    }
    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, STARTING_SESSION_POLL_INTERVAL_MS);
    });
  }
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

// A `.json` reached via "Import captured evidence" can be either a manifest.json
// evidence bundle OR an exported ESP session capture. Detect the capture and
// replay it directly; otherwise hand the path to the bundle analyzer. Without
// this, feeding a session capture to the importer runs the bundle analyzer and
// yields an empty "0 evidence" analysis.
async function importCapturedFile(path: string): Promise<void> {
  if (path.toLowerCase().endsWith(".json")) {
    const store = useEspDiagnosticsStore.getState();
    let text: string;
    try {
      text = await readTextFile(path);
    } catch (error) {
      store.rejectAnalysisInput(`Could not read ${path}: ${errorMessage(error)}`);
      return;
    }
    const parsed = parseEspSessionCapture(text);
    if (parsed.ok) {
      store.loadReplaySession(parsed.snapshot);
      return;
    }
  }
  await analyzePath(path, "file");
}

export function EspDiagnosticsWorkspace() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const graphPhase = useEspDiagnosticsStore((state) => state.graphPhase);
  const sessionId = useEspDiagnosticsStore((state) => state.sessionId);
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  const error = useEspDiagnosticsStore((state) => state.error);
  const graphError = useEspDiagnosticsStore((state) => state.graphError);
  const elevationProbe = useEspDiagnosticsStore((state) => state.elevationProbe);
  const setElevationProbe = useEspDiagnosticsStore(
    (state) => state.setElevationProbe,
  );
  // One shared GUID -> friendly-name map (Graph names, then known workload
  // names) so every panel rewrites identifiers to readable names identically.
  const graphNames = useMemo(
    () => (snapshot ? buildEspGraphNameMap(snapshot) : new Map<string, string>()),
    [snapshot],
  );
  const liveSupported = currentPlatform === "windows";
  const isBusy = ["analyzing", "starting", "stopping"].includes(phase);
  // Elevation is a constant property of the running process. The standalone
  // probe and the (collected-later) snapshot both derive from the same process
  // token, and neither can falsely report "elevated" -- so treat the process as
  // elevated if EITHER source confirms it. This fixes the case where the
  // snapshot still holds its default "not elevated" because a live session
  // stalled before reducing the elevation fact, without regressing when only
  // one source is available. Restricted-source coverage is only discovered
  // during collection, so keep the snapshot's list when present.
  const effectiveElevation: EspElevationState | null =
    elevationProbe || snapshot
      ? {
          isElevated:
            (elevationProbe?.isElevated ?? false) ||
            (snapshot?.elevation.isElevated ?? false),
          restartSupported:
            elevationProbe?.restartSupported ??
            snapshot?.elevation.restartSupported ??
            true,
          restrictedSources:
            snapshot?.elevation.restrictedSources ??
            elevationProbe?.restrictedSources ??
            [],
        }
      : null;

  useEffect(() => {
    if (currentPlatform !== "windows") {
      setElevationProbe(null);
      return;
    }

    let disposed = false;
    const applyFallback = () => {
      if (!disposed) setElevationProbe(ELEVATION_PROBE_FALLBACK);
    };
    void getEspElevationState()
      .then((elevation) => {
        if (disposed) return;
        setElevationProbe(
          validElevationState(elevation) ? elevation : ELEVATION_PROBE_FALLBACK,
        );
      })
      .catch(applyFallback);
    return () => {
      disposed = true;
    };
  }, [currentPlatform, setElevationProbe]);

  const importCapturedEvidence = useCallback(async () => {
    const path = normalizeSelection(
      await open({
        multiple: false,
        filters: [{ name: "ESP evidence", extensions: ["json", "cab", "zip"] }],
      }),
    );
    if (path) await importCapturedFile(path);
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
      if (envelope.state === "starting") {
        void recoverStartingSession(requestId, envelope.sessionId);
      }
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

  const exportSession = useCallback(async () => {
    const current = useEspDiagnosticsStore.getState().snapshot;
    if (!current) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const destination = await save({
      title: "Export ESP session",
      defaultPath: `esp-session-${stamp}.json`,
      filters: [{ name: "ESP session capture", extensions: ["json"] }],
    });
    if (!destination) return;
    try {
      const capture = buildEspSessionCapture(current, {
        capturedAtUtc: new Date().toISOString(),
      });
      await writeTextOutputFile(
        destination,
        serializeEspSessionCapture(capture),
      );
    } catch (error) {
      useEspDiagnosticsStore
        .getState()
        .rejectAnalysisInput(
          `Could not export the ESP session: ${errorMessage(error)}`,
        );
    }
  }, []);

  const openSession = useCallback(async () => {
    const path = normalizeSelection(
      await open({
        multiple: false,
        filters: [{ name: "ESP session capture", extensions: ["json"] }],
      }),
    );
    if (!path) return;
    const store = useEspDiagnosticsStore.getState();
    let text: string;
    try {
      text = await readTextFile(path);
    } catch (error) {
      store.rejectAnalysisInput(`Could not read ${path}: ${errorMessage(error)}`);
      return;
    }
    const parsed = parseEspSessionCapture(text);
    if (!parsed.ok) {
      store.rejectAnalysisInput(parsed.error);
      return;
    }
    store.loadReplaySession(parsed.snapshot);
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
      <Button
        appearance="secondary"
        size="small"
        icon={<ArrowUploadRegular />}
        disabled={isBusy || sessionId !== null}
        onClick={openSession}
      >
        Open session
      </Button>
      <Button
        appearance="secondary"
        size="small"
        icon={<ArrowDownloadRegular />}
        disabled={!snapshot}
        onClick={exportSession}
      >
        Export session
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
        elevation={effectiveElevation}
        workspacePhase={phase}
        graphPhase={graphPhase}
        actions={headerActions}
      />

      {effectiveElevation ? (
        <ElevationBanner elevation={effectiveElevation} />
      ) : null}

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
              <ActionCenter
                findings={snapshot.findings}
                graphNames={graphNames}
                workloads={snapshot.workloads}
                sessions={snapshot.sessions}
                phase={snapshot.phase}
                isLive={sessionId !== null}
              />
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
              <LiveActivity
                entries={snapshot.activity}
                graphNames={graphNames}
              />
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
