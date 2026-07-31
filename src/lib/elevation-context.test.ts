import { beforeEach, describe, expect, it } from "vitest";
import {
  activeElevationRequest,
  describeRestoreTarget,
  elevationConfirmationMessage,
  restoreTargetForSource,
} from "./elevation-context";
import { useLogStore } from "../stores/log-store";
import { useUiStore } from "../stores/ui-store";

describe("elevation context", () => {
  beforeEach(() => {
    useUiStore.setState({ activeWorkspace: "log", activeView: "log" });
    useLogStore.setState({ activeSource: null });
  });

  it("maps no open source to a workspace-only restore", () => {
    expect(restoreTargetForSource(null)).toEqual({ kind: "workspace" });
  });

  it("maps a file source to the exact file", () => {
    expect(
      restoreTargetForSource({ kind: "file", path: "C:\\Logs\\ime.log" }),
    ).toEqual({ kind: "file", path: "C:\\Logs\\ime.log" });
  });

  it("maps a folder source to an aggregate folder restore", () => {
    expect(
      restoreTargetForSource({ kind: "folder", path: "C:\\Logs" }),
    ).toEqual({ kind: "folder", path: "C:\\Logs", aggregate: true });
  });

  it("maps a known source by id rather than its expanded path", () => {
    expect(
      restoreTargetForSource({
        kind: "known",
        sourceId: "ccm-client-logs",
        defaultPath: "C:\\Windows\\CCM\\Logs",
        pathKind: "folder",
      }),
    ).toEqual({ kind: "knownSource", sourceId: "ccm-client-logs" });
  });

  it("builds the request from the active workspace and source", () => {
    useUiStore.setState({
      activeWorkspace: "esp-diagnostics",
      activeView: "esp-diagnostics",
    });
    useLogStore.setState({
      activeSource: { kind: "file", path: "/var/log/app.log" },
    });

    expect(activeElevationRequest()).toEqual({
      reason: "explicitMenu",
      workspace: "esp-diagnostics",
      target: { kind: "file", path: "/var/log/app.log" },
    });
  });

  it("carries the caller's reason", () => {
    expect(activeElevationRequest("accessDenied").reason).toBe("accessDenied");
  });

  it("labels a target by name rather than full path", () => {
    // The confirmation should not spell out a sensitive location when the
    // file name already identifies what will reopen.
    expect(describeRestoreTarget({ kind: "file", path: "C:\\Logs\\ime.log" })).toBe(
      "ime.log",
    );
    expect(
      describeRestoreTarget({ kind: "folder", path: "/var/log/ccm/" }),
    ).toBe("ccm (folder)");
    expect(describeRestoreTarget({ kind: "workspace" })).toBe(
      "the current workspace",
    );
    expect(
      describeRestoreTarget({ kind: "knownSource", sourceId: "ccm-logs" }),
    ).toBe("ccm-logs");
  });

  it("falls back to the whole string when there is no separator", () => {
    expect(describeRestoreTarget({ kind: "file", path: "app.log" })).toBe(
      "app.log",
    );
  });

  it("states what will and will not be restored", () => {
    const message = elevationConfirmationMessage({
      kind: "file",
      path: "C:\\Logs\\ime.log",
    });

    expect(message).toContain("close and reopen as administrator");
    expect(message).toContain("ime.log");
    expect(message).toContain(
      "Other tabs, filters, and searches are not restored.",
    );
  });
});
