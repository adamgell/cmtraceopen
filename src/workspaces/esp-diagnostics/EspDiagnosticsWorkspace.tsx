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
import { useUiStore } from "../../stores/ui-store";
import { useEspDiagnosticsStore } from "./esp-diagnostics-store";
import {
  analyzeEspEvidenceSource,
  ESP_EVIDENCE_SOURCE_ERROR,
  resolveEspEvidenceSource,
} from "./index";

function createRequestId(prefix: "analysis" | "live"): string {
  return `esp-${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function normalizeSelection(selection: string | string[] | null): string | null {
  if (!selection) return null;
  return Array.isArray(selection) ? selection[0] ?? null : selection;
}

async function analyzePath(
  path: string,
  sourceKind: "file" | "folder",
): Promise<void> {
  const source = { kind: sourceKind, path } as const;
  const store = useEspDiagnosticsStore.getState();
  if (!resolveEspEvidenceSource(source)) {
    const requestId = createRequestId("analysis");
    store.beginAnalysis(requestId);
    store.fail(requestId, ESP_EVIDENCE_SOURCE_ERROR);
    return;
  }

  await analyzeEspEvidenceSource(source, "esp-workspace.import");
}

const phaseLabels = {
  idle: "Waiting for evidence",
  analyzing: "Analyzing captured evidence",
  starting: "Starting live diagnostics",
  live: "Live diagnostics running",
  stopping: "Stopping live diagnostics",
  ready: "Evidence analysis ready",
  error: "Evidence analysis failed",
} as const;

export function EspDiagnosticsWorkspace() {
  const currentPlatform = useUiStore((state) => state.currentPlatform);
  const phase = useEspDiagnosticsStore((state) => state.phase);
  const sessionId = useEspDiagnosticsStore((state) => state.sessionId);
  const snapshot = useEspDiagnosticsStore((state) => state.snapshot);
  const error = useEspDiagnosticsStore((state) => state.error);
  const liveSupported = currentPlatform === "windows";
  const isBusy = ["analyzing", "starting", "stopping"].includes(phase);

  const importCapturedEvidence = useCallback(async () => {
    const path = normalizeSelection(
      await open({
        multiple: false,
        filters: [
          { name: "ESP evidence", extensions: ["json", "cab", "zip"] },
        ],
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
    const requestId = createRequestId("live");
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

  return (
    <main
      aria-labelledby="esp-diagnostics-heading"
      style={{
        display: "flex",
        flexDirection: "column",
        width: "100%",
        height: "100%",
        minWidth: 0,
        overflow: "auto",
        color: tokens.colorNeutralForeground1,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 20,
          padding: "16px 20px 14px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          backgroundColor: tokens.colorNeutralBackground1,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: tokens.fontFamilyMonospace,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
            }}
          >
            Enrollment Status Page / Local evidence
          </div>
          <h1
            id="esp-diagnostics-heading"
            style={{ margin: "3px 0 0", fontSize: 21, lineHeight: 1.2 }}
          >
            ESP Diagnostics
          </h1>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Button
            appearance="secondary"
            icon={<FolderOpenRegular />}
            disabled={isBusy || sessionId !== null}
            onClick={importEvidenceFolder}
          >
            Import evidence folder
          </Button>
          <Button
            appearance="secondary"
            icon={<DocumentArrowUpRegular />}
            disabled={isBusy || sessionId !== null}
            onClick={importCapturedEvidence}
          >
            Import captured evidence
          </Button>
          {sessionId ? (
            <Button
              appearance="primary"
              icon={<StopRegular />}
              disabled={phase === "stopping"}
              onClick={stopLive}
            >
              Stop live diagnostics
            </Button>
          ) : (
            <Button
              appearance="primary"
              icon={<PlayRegular />}
              disabled={!liveSupported || isBusy}
              onClick={startLive}
            >
              Start live diagnostics
            </Button>
          )}
        </div>
      </header>

      <section
        aria-live="polite"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          minHeight: 38,
          padding: "0 20px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor:
            phase === "error"
              ? tokens.colorPaletteRedBackground1
              : tokens.colorNeutralBackground3,
          fontFamily: tokens.fontFamilyMonospace,
          fontSize: 12,
        }}
      >
        {isBusy ? <Spinner size="tiny" /> : null}
        <span style={{ fontWeight: 700 }}>{phaseLabels[phase]}</span>
        <span style={{ color: tokens.colorNeutralForeground3 }}>
          {liveSupported
            ? "Offline analysis + Windows live acquisition"
            : "Offline analysis available; live acquisition requires Windows"}
        </span>
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(140px, 1fr))",
          gap: 1,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralStroke2,
        }}
      >
        {[
          ["MODE", sessionId ? "LIVE" : snapshot ? "CAPTURED" : "STANDBY"],
          ["SCENARIO", snapshot?.scenario ?? "Not detected"],
          ["ESP PHASE", snapshot?.phase ?? "No evidence"],
          ["RAW RECORDS", String(snapshot?.rawEvidence.length ?? 0)],
        ].map(([label, value]) => (
          <div
            key={label}
            style={{
              minHeight: 68,
              padding: "10px 14px",
              backgroundColor: tokens.colorNeutralBackground1,
            }}
          >
            <div
              style={{
                color: tokens.colorNeutralForeground3,
                fontFamily: tokens.fontFamilyMonospace,
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: "0.08em",
              }}
            >
              {label}
            </div>
            <div style={{ marginTop: 7, fontSize: 14, fontWeight: 650 }}>
              {value}
            </div>
          </div>
        ))}
      </section>

      <section
        style={{
          flex: 1,
          display: "grid",
          placeItems: "center",
          minHeight: 240,
          padding: 32,
        }}
      >
        <div
          style={{
            width: "min(720px, 100%)",
            border: `1px solid ${
              phase === "error"
                ? tokens.colorPaletteRedBorder2
                : tokens.colorNeutralStroke1
            }`,
            backgroundColor: tokens.colorNeutralBackground1,
            boxShadow: tokens.shadow4,
          }}
        >
          <div
            style={{
              padding: "10px 14px",
              borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
              backgroundColor: tokens.colorNeutralBackground3,
              fontFamily: tokens.fontFamilyMonospace,
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: "0.05em",
            }}
          >
            DIAGNOSTIC INPUT
          </div>
          <div style={{ padding: "20px 22px" }}>
            {error ? (
              <div
                role="alert"
                style={{
                  color: tokens.colorPaletteRedForeground1,
                  fontSize: 13,
                  fontWeight: 600,
                }}
              >
                {error}
              </div>
            ) : snapshot ? (
              <div style={{ fontSize: 13, lineHeight: 1.6 }}>
                Local evidence is loaded. The diagnostic cockpit is ready with{" "}
                <strong>{snapshot.findings.length}</strong> findings across{" "}
                <strong>{snapshot.coverage.length}</strong> coverage checks.
              </div>
            ) : (
              <div
                style={{
                  color: tokens.colorNeutralForeground2,
                  fontSize: 13,
                  lineHeight: 1.6,
                }}
              >
                Import a CMTrace evidence folder, manifest.json, CAB, or ZIP. On
                Windows, start a read-only live session to watch ESP enrollment
                state as evidence changes.
              </div>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
