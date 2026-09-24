import { beforeEach, describe, expect, it } from "vitest";
import { useSccmStore } from "./sccm-store";
import type { SccmEnvironmentDiscovery } from "./types";

const discovery: SccmEnvironmentDiscovery = {
  supported: true,
  configmgrVersion: null,
  roles: [{ role: "client", basis: "registry" }],
  sources: [],
  issues: [],
  advancedSources: [],
};

beforeEach(() => {
  useSccmStore.getState().reset();
});

describe("useSccmStore", () => {
  it("preserves the last discovery when a refresh fails", () => {
    const store = useSccmStore.getState();
    store.beginDiscovery();
    store.completeDiscovery(discovery);
    store.beginDiscovery();
    store.fail("The environment probe failed.");

    expect(useSccmStore.getState()).toMatchObject({
      phase: "ready",
      discovery,
      error: "The environment probe failed.",
    });
  });

  it("keeps an opaque advanced capability only for the active operation", () => {
    const store = useSccmStore.getState();
    const capability = {
      capabilityHandle: `cmtraceopen.capture-capability.sha256.v1:${"a".repeat(64)}`,
      cardId: "reporting",
      cardVersion: "1.0.0",
      sourceId: "advanced-reporting",
      roleScope: "reportingServicesPoint",
      pathClass: "configuredRoleLogRoot",
      sourceVersion: null,
    };
    store.completeDiscovery(discovery);
    store.beginAdvancedAuthorization();
    store.completeAdvancedAuthorization(capability);
    store.beginAdvancedCapture();
    expect(useSccmStore.getState()).toMatchObject({
      phase: "capturingAdvanced",
      advancedCapability: capability,
    });

    useSccmStore.getState().fail("capture failed");
    expect(useSccmStore.getState()).toMatchObject({
      phase: "ready",
      advancedCapability: null,
    });
  });

  it("marks capture busy without clearing discovery", () => {
    const store = useSccmStore.getState();
    store.completeDiscovery(discovery);
    store.beginCapture();

    expect(useSccmStore.getState()).toMatchObject({
      phase: "capturing",
      discovery,
      error: null,
    });
  });

  it("refuses capture state when a supported discovery has no SCCM roles", () => {
    const rolelessDiscovery: SccmEnvironmentDiscovery = {
      ...discovery,
      roles: [],
    };
    const store = useSccmStore.getState();
    store.completeDiscovery(rolelessDiscovery);
    store.beginCapture();

    expect(useSccmStore.getState()).toMatchObject({
      phase: "ready",
      discovery: rolelessDiscovery,
      capture: null,
      error: null,
    });
  });
});
