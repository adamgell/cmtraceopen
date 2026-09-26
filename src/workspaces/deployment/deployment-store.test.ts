import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  useDeploymentStore,
  type DeploymentAnalysisResult,
  type DeploymentLogFile,
} from "./deployment-store";

// Wire values from the existing DeploymentWorkspace fixtures, not log text.
function file(): DeploymentLogFile {
  return {
    path: "C:\\Windows\\Logs\\Software\\fail.log",
    fileName: "fail.log",
    format: "psadt-cmtrace",
    outcome: "failure",
    exitCode: 1603,
    errorSummary: "Installation failed with 1603",
    errorLines: [
      { lineNumber: 42, message: "CustomAction failed", severity: "Error" },
    ],
    appName: "Broken App",
    appVersion: "1.2.0",
    deployType: "Install",
    startTime: "2026-01-15T12:00:00",
    endTime: "2026-01-15T12:01:00",
  };
}

function result(files: DeploymentLogFile[] = []): DeploymentAnalysisResult {
  return {
    folderPath: "C:\\Windows\\Logs\\Software",
    files,
    totalFiles: files.length,
    succeeded: files.filter((item) => item.outcome === "success").length,
    failed: files.filter((item) => item.outcome === "failure").length,
    deferred: files.filter((item) => item.outcome === "deferred").length,
    unknown: files.filter((item) => item.outcome === "unknown").length,
    limitations: [],
  };
}

describe("deployment analysis response boundary", () => {
  beforeEach(() => {
    useDeploymentStore.getState().reset();
    vi.mocked(invoke).mockReset();
  });

  it.each([
    ["missing", undefined],
    ["null", null],
    ["empty string", ""],
    ["string", "Directory depth budget of 32 was exhausted."],
    ["non-string entry", [{}]],
  ])("rejects %s limitations before publishing an empty result", async (_, limitations) => {
    const response: Record<string, unknown> = { ...result(), limitations };
    if (limitations === undefined) delete response.limitations;
    vi.mocked(invoke).mockResolvedValue(response);

    await useDeploymentStore.getState().analyzeFolder(response.folderPath as string);

    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "error",
      result: null,
      errorMessage: "Command 'analyze_deployment_folder' returned an invalid response.",
    });
  });

  it.each([
    ["complete", []],
    ["incomplete", ["Directory depth budget of 32 was exhausted."]],
  ])("preserves a valid %s empty scan", async (_, limitations) => {
    const response = { ...result(), limitations };
    vi.mocked(invoke).mockResolvedValue(response);

    await useDeploymentStore.getState().analyzeFolder(response.folderPath);

    expect(invoke).toHaveBeenCalledWith("analyze_deployment_folder", {
      folderPath: response.folderPath,
    });
    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "empty",
      result: response,
      errorMessage: null,
    });
  });

  it("preserves a valid populated scan and nested error evidence", async () => {
    const response = result([file()]);
    vi.mocked(invoke).mockResolvedValue(response);

    await useDeploymentStore.getState().analyzeFolder(response.folderPath);

    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "ready",
      result: response,
      errorMessage: null,
    });
  });

  it.each([0, 2])("rejects totalFiles %s when it contradicts the returned file list", async (totalFiles) => {
    vi.mocked(invoke).mockResolvedValue({ ...result([file()]), totalFiles });

    await useDeploymentStore.getState().analyzeFolder(result().folderPath);

    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "error",
      result: null,
      errorMessage: "Command 'analyze_deployment_folder' returned an invalid response.",
    });
  });

  it.each<DeploymentLogFile["format"]>([
    "psadt-cmtrace", "psadt-legacy", "msi-verbose", "psadt-wrapper",
    "burn", "patchmypc", "unknown",
  ])("accepts the producer's %s format", async (format) => {
    const response = result([{ ...file(), format }]);
    vi.mocked(invoke).mockResolvedValue(response);

    await useDeploymentStore.getState().analyzeFolder(response.folderPath);

    expect(useDeploymentStore.getState().result).toEqual(response);
    expect(useDeploymentStore.getState().phase).toBe("ready");
  });

  it.each([
    ["success", 0], ["failure", -2_147_483_648],
    ["deferred", 1618], ["unknown", null],
  ] as const)("accepts %s with nullable metadata", async (outcome, exitCode) => {
    const response = result([{
      ...file(), outcome, exitCode,
      errorSummary: null, appName: null, appVersion: null,
      deployType: null, startTime: null, endTime: null,
      errorLines: [{ lineNumber: 42, message: "CustomAction failed", severity: "Warning" }],
    }]);
    vi.mocked(invoke).mockResolvedValue(response);

    await useDeploymentStore.getState().analyzeFolder(response.folderPath);

    expect(useDeploymentStore.getState().result).toEqual(response);
    expect(useDeploymentStore.getState().phase).toBe("ready");
  });

  it.each([
    ["missing files", { files: undefined }],
    ["negative count", { failed: -1 }],
    ["fractional count", { totalFiles: 0.5 }],
    ["nonfinite count", { unknown: Number.NaN }],
    ["unsafe count", { succeeded: Number.MAX_SAFE_INTEGER + 1 }],
    ["missing folder path", { folderPath: undefined }],
  ])("rejects %s", async (_, change) => {
    vi.mocked(invoke).mockResolvedValue({ ...result(), ...change });

    await useDeploymentStore.getState().analyzeFolder(result().folderPath);

    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "error",
      result: null,
      errorMessage: "Command 'analyze_deployment_folder' returned an invalid response.",
    });
  });

  it.each([
    ["unknown format", { format: "new-format" }],
    ["unknown outcome", { outcome: "healthy" }],
    ["fractional exit code", { exitCode: 1.5 }],
    ["exit code outside i32", { exitCode: 2_147_483_648 }],
    ["missing nullable field", { appName: undefined }],
    ["malformed errors", { errorLines: [null] }],
    ["unknown severity", { errorLines: [{ lineNumber: 42, message: "CustomAction failed", severity: "Info" }] }],
    ["negative line number", { errorLines: [{ lineNumber: -1, message: "CustomAction failed", severity: "Error" }] }],
  ])("rejects %s before publishing a ready result", async (_, change) => {
    vi.mocked(invoke).mockResolvedValue({ ...result([file()]), files: [{ ...file(), ...change }] });

    await useDeploymentStore.getState().analyzeFolder(result().folderPath);

    expect(useDeploymentStore.getState()).toMatchObject({
      phase: "error",
      result: null,
      errorMessage: "Command 'analyze_deployment_folder' returned an invalid response.",
    });
  });
});
