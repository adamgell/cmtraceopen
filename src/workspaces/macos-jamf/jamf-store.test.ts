import { describe, it, expect, beforeEach } from "vitest";
import { useJamfStore } from "./jamf-store";

describe("jamf-store", () => {
  beforeEach(() => {
    useJamfStore.getState().reset();
  });

  it("starts on the overview tab with all slices idle", () => {
    const s = useJamfStore.getState();
    expect(s.activeTab).toBe("overview");
    expect(s.environment.status).toBe("idle");
    expect(s.policies.status).toBe("idle");
  });

  it("setActiveTab switches tab", () => {
    useJamfStore.getState().setActiveTab("policies");
    expect(useJamfStore.getState().activeTab).toBe("policies");
  });

  it("beginLoad → finishLoad transitions a slice to ok with data", () => {
    useJamfStore.getState().beginLoad("environment");
    expect(useJamfStore.getState().environment.status).toBe("loading");

    useJamfStore.getState().finishLoad("environment", {
      jamfInstalled: true,
      jamfVersion: "11.26.1",
      jssUrl: "https://example.jamfcloud.com/",
      lastCheckIn: null,
      mdmProfilePresent: false,
      mdmOrganization: null,
      jamfConnectInstalled: false,
      jamfConnectVersion: null,
      jamfConnectIdp: null,
      fdaStatus: "unknown",
      directories: {
        jamfLog: true,
        jamfAppSupport: true,
        jamfReceipts: true,
        jamfUserLogs: true,
        selfServiceLog: true,
        connectLog: false,
        connectUserLogs: false,
      },
      summary: "JAMF binary detected (11.26.1)",
    });

    const env = useJamfStore.getState().environment;
    expect(env.status).toBe("ok");
    expect(env.data?.jamfVersion).toBe("11.26.1");
    expect(env.lastLoadedAt).not.toBeNull();
  });

  it("failLoad sets error state but keeps prior data", () => {
    useJamfStore.getState().beginLoad("policies");
    useJamfStore.getState().finishLoad("policies", {
      events: [],
      totalLines: 0,
      unparsedLines: 0,
      sourcePath: "/var/log/jamf.log",
    });
    useJamfStore.getState().failLoad("policies", "permission denied");
    const p = useJamfStore.getState().policies;
    expect(p.status).toBe("error");
    expect(p.error).toBe("permission denied");
    expect(p.data?.sourcePath).toBe("/var/log/jamf.log");
  });

  it("markNotInstalled clears prior data", () => {
    useJamfStore.getState().markNotInstalled("connect");
    expect(useJamfStore.getState().connect.status).toBe("notInstalled");
    expect(useJamfStore.getState().connect.data).toBeNull();
  });
});
