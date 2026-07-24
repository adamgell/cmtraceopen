import { isEspDiagnosticsSnapshot } from "./esp-wire-validation";
import type { EspDiagnosticsSnapshot } from "./types";

// A portable, self-contained record of a single ESP diagnostics session, written
// to disk so a real device's state can be re-opened and replayed anywhere (a
// developer's macOS build, a support engineer's laptop, a CI fixture) without the
// device, a signed build on it, or a live Graph connection. The reduced snapshot
// already carries everything the frontend renders -- workloads, findings,
// activity, raw evidence, AND the Graph overlay (`snapshot.graph`) -- so a single
// snapshot is a complete, replayable session.

export const ESP_SESSION_CAPTURE_KIND = "esp-session-capture" as const;
export const ESP_SESSION_CAPTURE_VERSION = 1 as const;

export interface EspSessionCaptureApp {
  version?: string | null;
  commit?: string | null;
}

export interface EspSessionCapture {
  kind: typeof ESP_SESSION_CAPTURE_KIND;
  version: number;
  capturedAtUtc: string;
  app?: EspSessionCaptureApp | null;
  snapshot: EspDiagnosticsSnapshot;
}

export interface EspSessionCaptureMeta {
  capturedAtUtc: string;
  appVersion?: string | null;
  appCommit?: string | null;
}

export function buildEspSessionCapture(
  snapshot: EspDiagnosticsSnapshot,
  meta: EspSessionCaptureMeta,
): EspSessionCapture {
  return {
    kind: ESP_SESSION_CAPTURE_KIND,
    version: ESP_SESSION_CAPTURE_VERSION,
    capturedAtUtc: meta.capturedAtUtc,
    app: { version: meta.appVersion ?? null, commit: meta.appCommit ?? null },
    snapshot,
  };
}

export function serializeEspSessionCapture(capture: EspSessionCapture): string {
  return JSON.stringify(capture, null, 2);
}

export type EspSessionCaptureParse =
  | { ok: true; snapshot: EspDiagnosticsSnapshot; capture: EspSessionCapture | null }
  | { ok: false; error: string };

function isCaptureEnvelope(
  value: unknown,
): value is { kind: string; version: number; snapshot: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { kind?: unknown }).kind === ESP_SESSION_CAPTURE_KIND &&
    typeof (value as { version?: unknown }).version === "number" &&
    "snapshot" in value
  );
}

/**
 * Parse a file's text as an ESP session capture. Accepts either the capture
 * envelope written by {@link serializeEspSessionCapture} or a bare
 * `EspDiagnosticsSnapshot` (so a snapshot pulled straight off the wire loads
 * too). The snapshot is always revalidated with the same wire guard the live
 * session listener uses, so a schema-drifted or hand-mangled file is rejected
 * with a message instead of reaching the store.
 */
export function parseEspSessionCapture(text: string): EspSessionCaptureParse {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, error: "That file is not valid JSON." };
  }

  if (isCaptureEnvelope(value)) {
    if (value.version > ESP_SESSION_CAPTURE_VERSION) {
      return {
        ok: false,
        error: `This capture is version ${value.version}, newer than this build understands (${ESP_SESSION_CAPTURE_VERSION}). Update CMTrace Open to open it.`,
      };
    }
    if (!isEspDiagnosticsSnapshot(value.snapshot)) {
      return {
        ok: false,
        error:
          "This capture's snapshot is malformed or from an incompatible schema.",
      };
    }
    return { ok: true, snapshot: value.snapshot, capture: value as EspSessionCapture };
  }

  if (isEspDiagnosticsSnapshot(value)) {
    return { ok: true, snapshot: value, capture: null };
  }

  return {
    ok: false,
    error: "That file is not an ESP session capture or diagnostics snapshot.",
  };
}
