import { describe, expect, it } from "vitest";
import {
  buildEspSessionCapture,
  ESP_SESSION_CAPTURE_KIND,
  ESP_SESSION_CAPTURE_VERSION,
  parseEspSessionCapture,
  serializeEspSessionCapture,
} from "./esp-session-capture";
import {
  makeEspAppsSection,
  makeEspGraphApp,
  makeEspGraphOverlay,
  makeEspRawEvidence,
  makeEspSnapshot,
  makeEspWorkload,
} from "./esp-session-fixtures";

describe("esp session capture", () => {
  it("round-trips a snapshot (incl. its Graph overlay) through build/serialize/parse", () => {
    const snapshot = makeEspSnapshot({
      workloads: [makeEspWorkload()],
      graph: makeEspGraphOverlay({
        apps: makeEspAppsSection([makeEspGraphApp()]),
      }),
    });
    const capture = buildEspSessionCapture(snapshot, {
      capturedAtUtc: "2026-07-23T21:30:00Z",
    });
    expect(capture.kind).toBe(ESP_SESSION_CAPTURE_KIND);
    expect(capture.version).toBe(ESP_SESSION_CAPTURE_VERSION);

    const parsed = parseEspSessionCapture(serializeEspSessionCapture(capture));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot).toEqual(snapshot);
    // The overlay survives the round-trip, so offline replay renders Graph names.
    expect(parsed.snapshot.graph?.apps.data?.[0]?.displayName).toBe(
      "Contoso VPN",
    );
  });

  it("round-trips raw evidence carrying a FILETIME QWORD above safe-integer range", () => {
    // Regression: every real device has registry QWORDs (ChannelExpiryTime,
    // CreationTime...) that exceed Number.MAX_SAFE_INTEGER, so a strict
    // safe-integer guard rejected the whole snapshot on load.
    const snapshot = makeEspSnapshot({
      rawEvidence: [makeEspRawEvidence({ rawValue: { unsigned: 134319134940000000 } })],
    });
    const capture = buildEspSessionCapture(snapshot, {
      capturedAtUtc: "2026-07-23T21:30:00Z",
    });
    const parsed = parseEspSessionCapture(serializeEspSessionCapture(capture));
    expect(parsed.ok).toBe(true);
  });

  it("accepts a bare snapshot with no capture envelope", () => {
    const snapshot = makeEspSnapshot();
    const parsed = parseEspSessionCapture(JSON.stringify(snapshot));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.capture).toBeNull();
    expect(parsed.snapshot).toEqual(snapshot);
  });

  it("rejects non-JSON input", () => {
    const parsed = parseEspSessionCapture("not json {");
    expect(parsed.ok).toBe(false);
  });

  it("rejects a capture from a newer format version", () => {
    const capture = buildEspSessionCapture(makeEspSnapshot(), {
      capturedAtUtc: "2026-07-23T21:30:00Z",
    });
    const bumped = { ...capture, version: ESP_SESSION_CAPTURE_VERSION + 1 };
    const parsed = parseEspSessionCapture(JSON.stringify(bumped));
    expect(parsed.ok).toBe(false);
  });

  it("rejects a malformed snapshot inside a valid envelope", () => {
    const capture = buildEspSessionCapture(makeEspSnapshot(), {
      capturedAtUtc: "2026-07-23T21:30:00Z",
    });
    const broken = {
      ...capture,
      snapshot: { ...capture.snapshot, schemaVersion: 999 },
    };
    const parsed = parseEspSessionCapture(JSON.stringify(broken));
    expect(parsed.ok).toBe(false);
  });

  it("rejects a file that is neither a capture nor a snapshot", () => {
    const parsed = parseEspSessionCapture(JSON.stringify({ hello: "world" }));
    expect(parsed.ok).toBe(false);
  });
});
