import { beforeEach, describe, expect, it } from "vitest";
import { useSccmStore } from "./sccm-store";
import type { SccmEnvironmentDiscovery } from "./types";

const discovery: SccmEnvironmentDiscovery = {
  supported: true,
  roles: [{ role: "client", basis: "registry" }],
  sources: [],
  issues: [],
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
});
