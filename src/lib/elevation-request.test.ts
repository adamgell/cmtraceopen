import { describe, expect, it } from "vitest";
import { workspaceRegistry } from "../workspaces/registry";
import type { WorkspaceId } from "../types/log";
import {
  buildElevationRequest,
  buildRestoreTarget,
  describeElevationPrompt,
  describeRestoreTarget,
  textLogRestoreWorkspace,
} from "./elevation-request";

describe("buildRestoreTarget", () => {
  it("restores the workspace alone when no source is active", () => {
    expect(buildRestoreTarget(null)).toEqual({ kind: "workspace" });
  });

  it("carries a file source by path", () => {
    expect(
      buildRestoreTarget({ kind: "file", path: "C:\\Windows\\Logs\\CBS.log" }),
    ).toEqual({ kind: "file", path: "C:\\Windows\\Logs\\CBS.log" });
  });

  it("carries a folder source by path", () => {
    expect(
      buildRestoreTarget({ kind: "folder", path: "/var/log/intune" }),
    ).toEqual({ kind: "folder", path: "/var/log/intune" });
  });

  it("carries a known source by stable id, never by its expanded path", () => {
    const target = buildRestoreTarget({
      kind: "known",
      sourceId: "ime-agent-executor",
      defaultPath: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs",
      pathKind: "folder",
    });

    expect(target).toEqual({ kind: "knownSource", sourceId: "ime-agent-executor" });
    expect(JSON.stringify(target)).not.toContain("ProgramData");
  });
});

describe("describeRestoreTarget", () => {
  it("reduces a Windows path to its file name", () => {
    expect(
      describeRestoreTarget({
        kind: "file",
        path: "C:\\Users\\adam\\Documents\\Secret Project\\CBS.log",
      }),
    ).toBe("CBS.log");
  });

  it("reduces a POSIX path to its last segment", () => {
    expect(
      describeRestoreTarget({ kind: "folder", path: "/var/log/intune/" }),
    ).toBe("intune");
  });

  it("names the workspace when there is no source", () => {
    expect(describeRestoreTarget({ kind: "workspace" })).toBe(
      "the current workspace",
    );
  });
});

describe("buildElevationRequest", () => {
  it("builds a workspace-only request for the global menu", () => {
    expect(
      buildElevationRequest({ reason: "explicitMenu", workspace: "log" }),
    ).toEqual({
      reason: "explicitMenu",
      workspace: "log",
      target: { kind: "workspace" },
    });
  });

  it("preserves the failed source intent for an Access Denied recovery", () => {
    expect(
      buildElevationRequest({
        reason: "accessDenied",
        workspace: "log",
        source: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
      }),
    ).toEqual({
      reason: "accessDenied",
      workspace: "log",
      target: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
    });
  });
});

describe("describeElevationPrompt", () => {
  it("does not put a full path in confirmation copy", () => {
    const copy = describeElevationPrompt({
      reason: "accessDenied",
      workspace: "log",
      target: { kind: "file", path: "C:\\Users\\adam\\Private\\CBS.log" },
    });

    expect(copy).toContain("CBS.log");
    expect(copy).not.toContain("C:\\Users\\adam\\Private");
  });

  it("states that unrelated state is not restored", () => {
    const copy = describeElevationPrompt({
      reason: "explicitMenu",
      workspace: "log",
      target: { kind: "workspace" },
    });

    expect(copy).toMatch(/filters/i);
    expect(copy).toMatch(/not restored/i);
  });
});

describe("textLogRestoreWorkspace", () => {
  const handler = async () => undefined;

  it("keeps a workspace that has no handler: Log restores through the text-log loader", () => {
    expect(textLogRestoreWorkspace("log", {})).toBe("log");
    expect(textLogRestoreWorkspace("macos-jamf", { capabilities: { keepsViewOnLogLoad: true } })).toBe(
      "macos-jamf",
    );
  });

  it("keeps a workspace whose handler says it reopens text logs", () => {
    expect(
      textLogRestoreWorkspace("intune", {
        onOpenSource: handler,
        capabilities: { reopensTextLogs: true },
      }),
    ).toBe("intune");
  });

  it("names the Log workspace for a handler that does not say so", () => {
    expect(textLogRestoreWorkspace("event-log", { onOpenSource: handler })).toBe("log");
    expect(
      textLogRestoreWorkspace("event-log", {
        onOpenSource: handler,
        capabilities: { reopensTextLogs: false },
      }),
    ).toBe("log");
  });

  // The audit of every workspace, as a table. A workspace added later is not in it, and the test
  // after it fails until someone has decided what its ticket restores.
  const EXPECTED: Record<WorkspaceId, WorkspaceId> = {
    log: "log",
    "macos-jamf": "macos-jamf",
    "macos-diag": "macos-diag",
    sccm: "sccm",
    intune: "intune",
    "new-intune": "new-intune",
    "event-log": "log",
    "esp-diagnostics": "log",
    dsregcmd: "log",
    sysmon: "log",
    secureboot: "log",
    timeline: "log",
    deployment: "log",
    "dns-dhcp": "log",
  };

  it.each([...workspaceRegistry.values()].map((workspace) => [workspace.id, workspace] as const))(
    "names %s's ticket as the workspace that reopens a text log",
    (id, workspace) => {
      expect(textLogRestoreWorkspace(id, workspace)).toBe(EXPECTED[id]);
    },
  );

  it("has a decision for every workspace in the registry", () => {
    expect([...workspaceRegistry.keys()].sort()).toEqual(Object.keys(EXPECTED).sort());
  });
});
