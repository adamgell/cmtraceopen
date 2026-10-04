import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import type { EspAcquisitionCapability } from "../workspaces/esp-diagnostics/types";
import { getEspDiagnosticsCapability } from "./commands";

// These shapes match EspAcquisitionCapability's camelCase serde output in
// src-tauri/src/esp/mod.rs, including the explicit null Option<String>.
const supported = {
  offlineAnalysisSupported: true,
  liveAcquisitionSupported: true,
  liveAcquisitionDetail: null,
} satisfies EspAcquisitionCapability;
const unsupported = {
  offlineAnalysisSupported: true,
  liveAcquisitionSupported: false,
  liveAcquisitionDetail: "Live ESP evidence acquisition is only supported on Windows",
} satisfies EspAcquisitionCapability;

beforeEach(() => {
  vi.mocked(invoke).mockReset();
});

describe("ESP acquisition capability command", () => {
  it.each([supported, unsupported])("decodes the backend capability %j", async (capability) => {
    vi.mocked(invoke).mockResolvedValue(capability);

    const result = await getEspDiagnosticsCapability();

    expectTypeOf(result).toEqualTypeOf<EspAcquisitionCapability>();
    expect(result).toEqual(capability);
    expect(invoke).toHaveBeenCalledWith("get_esp_diagnostics_capability", undefined);
  });

  it.each([
    null,
    [],
    true,
    {},
    { ...supported, offlineAnalysisSupported: undefined },
    { ...supported, offlineAnalysisSupported: "true" },
    { ...supported, liveAcquisitionSupported: undefined },
    { ...supported, liveAcquisitionSupported: "false" },
    { ...supported, liveAcquisitionDetail: undefined },
    { ...supported, liveAcquisitionDetail: 42 },
    {
      offline_analysis_supported: true,
      live_acquisition_supported: true,
      live_acquisition_detail: null,
    },
  ])("rejects malformed capability %j", async (capability) => {
    vi.mocked(invoke).mockResolvedValue(capability);

    await expect(getEspDiagnosticsCapability()).rejects.toThrow(
      "Command 'get_esp_diagnostics_capability' returned an invalid response.",
    );
  });

  it("preserves normalized command rejection semantics", async () => {
    vi.mocked(invoke).mockRejectedValue({ message: "Capability probe unavailable" });

    await expect(getEspDiagnosticsCapability()).rejects.toThrow("Capability probe unavailable");
  });
});
