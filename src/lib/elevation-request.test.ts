import { describe, expect, it } from "vitest";
// The backend's allowlist, read as text: the one place the closed workspace list is defined.
import backendElevationSource from "../../src-tauri/src/elevation/mod.rs?raw";
import { workspaceRegistry } from "../workspaces/registry";
import type { LogSource, WorkspaceId } from "../types/log";
import {
  BACKEND_ELEVATION_WORKSPACES,
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
  const FILE: LogSource = { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" };
  const FOLDER: LogSource = { kind: "folder", path: "C:\\Windows\\Logs" };
  const KNOWN_FILE: LogSource = {
    kind: "known",
    sourceId: "ime-agent-executor",
    defaultPath: "C:\\ProgramData\\Logs\\AgentExecutor.log",
    pathKind: "file",
  };
  const KNOWN_FOLDER: LogSource = {
    kind: "known",
    sourceId: "ime-logs",
    defaultPath: "C:\\ProgramData\\Logs",
    pathKind: "folder",
  };
  const withFiles = { capabilities: { reopensTextLogFiles: true } };

  it("keeps the Log workspace, which restores through the text-log loader", () => {
    expect(textLogRestoreWorkspace("log", {}, FILE)).toBe("log");
    expect(textLogRestoreWorkspace("log", {}, FOLDER)).toBe("log");
    expect(textLogRestoreWorkspace("log", {}, null)).toBe("log");
  });

  it.each([
    ["a file", FILE],
    ["a known source that is one file", KNOWN_FILE],
  ])("keeps a workspace that reopens text-log files, for %s", (_label, source) => {
    expect(textLogRestoreWorkspace("intune", withFiles, source)).toBe("intune");
  });

  it.each([
    ["a folder", FOLDER],
    ["a known source that is a folder", KNOWN_FOLDER],
    ["no source", null],
  ])("names the Log workspace for %s even in a workspace that reopens text-log files", (_label, source) => {
    expect(textLogRestoreWorkspace("intune", withFiles, source)).toBe("log");
  });

  it("names the Log workspace for every other workspace, whatever the target", () => {
    for (const source of [FILE, FOLDER, KNOWN_FILE, KNOWN_FOLDER, null]) {
      expect(textLogRestoreWorkspace("event-log", {}, source)).toBe("log");
      expect(
        textLogRestoreWorkspace("event-log", { capabilities: { reopensTextLogFiles: false } }, source),
      ).toBe("log");
      // A workspace with no handler at all is no exception: SCCM is not even in the backend's list.
      expect(textLogRestoreWorkspace("sccm", {}, source)).toBe("log");
      expect(textLogRestoreWorkspace("macos-jamf", {}, source)).toBe("log");
    }
  });

  // The audit of every workspace, as a table. A workspace added later is not in it, and the test
  // after it fails until someone has decided what its ticket restores.
  const EXPECTED_FOR_A_FILE: Record<WorkspaceId, WorkspaceId> = {
    log: "log",
    intune: "intune",
    "new-intune": "new-intune",
    "macos-jamf": "log",
    "macos-diag": "log",
    sccm: "log",
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
    "names %s's ticket for a text-log file, and the Log workspace for a folder",
    (id, workspace) => {
      expect(textLogRestoreWorkspace(id, workspace, FILE)).toBe(EXPECTED_FOR_A_FILE[id]);
      expect(textLogRestoreWorkspace(id, workspace, FOLDER)).toBe("log");
    },
  );

  it("has a decision for every workspace in the registry", () => {
    expect([...workspaceRegistry.keys()].sort()).toEqual(Object.keys(EXPECTED_FOR_A_FILE).sort());
  });

  it("never names a workspace the backend's allowlist rejects, for any workspace or target", () => {
    for (const workspace of workspaceRegistry.values()) {
      for (const source of [FILE, FOLDER, KNOWN_FILE, KNOWN_FOLDER, null]) {
        expect(BACKEND_ELEVATION_WORKSPACES).toContain(
          textLogRestoreWorkspace(workspace.id, workspace, source),
        );
      }
    }
  });
});

describe("BACKEND_ELEVATION_WORKSPACES", () => {
  it("is the AppWorkspace enum in the backend, which it mirrors", () => {
    const body = /pub enum AppWorkspace \{([^}]*)\}/.exec(backendElevationSource)?.[1];
    expect(body, "pub enum AppWorkspace was not found in elevation/mod.rs").toBeDefined();
    // serde(rename_all = "kebab-case"): MacosDiag is "macos-diag", DnsDhcp is "dns-dhcp".
    const variants = body!
      .split(",")
      .map((variant) => variant.trim())
      .filter((variant) => /^[A-Z]\w*$/.test(variant))
      .map((variant) => variant.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase());
    expect([...BACKEND_ELEVATION_WORKSPACES].sort()).toEqual(variants.sort());
  });

  it("leaves out exactly the frontend workspaces the backend does not know", () => {
    const missing = [...workspaceRegistry.keys()].filter(
      (id) => !BACKEND_ELEVATION_WORKSPACES.includes(id),
    );
    expect(missing).toEqual(["sccm"]);
  });
});
