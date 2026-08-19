import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DeploymentWorkspace } from "./DeploymentWorkspace";
import {
  useDeploymentStore,
  type DeploymentAnalysisResult,
  type DeploymentLogFile,
} from "./deployment-store";

function file(overrides: Partial<DeploymentLogFile> = {}): DeploymentLogFile {
  return {
    path: "C:\\Windows\\Logs\\Software\\app.log",
    fileName: "app.log",
    format: "psadt-cmtrace",
    outcome: "success",
    exitCode: 0,
    errorSummary: null,
    errorLines: [],
    appName: "Contoso App",
    appVersion: "1.2.0",
    deployType: "Install",
    startTime: "2026-01-15T12:00:00",
    endTime: "2026-01-15T12:01:00",
    ...overrides,
  };
}

function readyResult(): DeploymentAnalysisResult {
  return {
    folderPath: "C:\\Windows\\Logs\\Software",
    files: [
      file({
        path: "C:\\Windows\\Logs\\Software\\fail.log",
        fileName: "fail.log",
        format: "psadt-cmtrace",
        outcome: "failure",
        exitCode: 1603,
        appName: "Broken App",
        errorSummary: "Installation failed with 1603",
        errorLines: [
          { lineNumber: 42, message: "CustomAction failed", severity: "Error" },
        ],
      }),
      file({
        path: "C:\\Windows\\Logs\\Software\\ok.msi.log",
        fileName: "ok.msi.log",
        format: "msi-verbose",
        outcome: "success",
        appName: "Good MSI",
      }),
      file({
        path: "C:\\Windows\\Logs\\Software\\later.log",
        fileName: "later.log",
        format: "burn",
        outcome: "deferred",
        appName: "Deferred Burn",
        exitCode: 1618,
      }),
      file({
        path: "C:\\Windows\\Logs\\Software\\mystery.log",
        fileName: "mystery.log",
        format: "unknown",
        outcome: "unknown",
        appName: null,
      }),
    ],
    totalFiles: 4,
    succeeded: 1,
    failed: 1,
    deferred: 1,
    unknown: 1,
  };
}

function seedReady() {
  useDeploymentStore.setState({
    phase: "ready",
    result: readyResult(),
    errorMessage: null,
    expandedErrorIndex: null,
  });
}

afterEach(() => {
  cleanup();
  useDeploymentStore.getState().reset();
});

beforeEach(() => {
  useDeploymentStore.getState().reset();
});

describe("DeploymentWorkspace fixtures", () => {
  it("DEP-001 shows folder analysis inventory and outcome counts", () => {
    seedReady();
    render(<DeploymentWorkspace />);

    expect(screen.getByText("Software Deployment Analysis")).toBeInTheDocument();
    expect(screen.getByText("C:\\Windows\\Logs\\Software")).toBeInTheDocument();
    expect(screen.getByText("1 PSADT")).toBeInTheDocument();
    expect(screen.getByText("1 MSI verbose")).toBeInTheDocument();
    expect(screen.getByText("1 WiX/Burn")).toBeInTheDocument();
    expect(screen.getByText("1 Other")).toBeInTheDocument();
    expect(screen.getByText("4 total")).toBeInTheDocument();
    expect(screen.getByText("1 failed")).toBeInTheDocument();
    expect(screen.getByText("1 succeeded")).toBeInTheDocument();
    expect(screen.getByText("1 deferred")).toBeInTheDocument();
    expect(screen.getByText("1 unknown")).toBeInTheDocument();
  });

  it("DEP-002 shows failed cards and succeeded/deferred/unclassified tables", () => {
    seedReady();
    render(<DeploymentWorkspace />);

    expect(screen.getByText("Failed Deployments")).toBeInTheDocument();
    expect(screen.getByText("Broken App")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open in Log Viewer" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "1 error" })).toBeInTheDocument();
    expect(screen.getByText("Installation failed with 1603")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "1 error" }));
    expect(screen.getByText(/L42/)).toBeInTheDocument();
    expect(screen.getByText("CustomAction failed")).toBeInTheDocument();

    expect(screen.getByText("Succeeded / Deferred")).toBeInTheDocument();
    expect(screen.getByText("Good MSI")).toBeInTheDocument();
    expect(screen.getByText("Deferred Burn")).toBeInTheDocument();
    expect(screen.getByText("Other / Unclassified (1)")).toBeInTheDocument();
    expect(screen.getAllByText("Application").length).toBeGreaterThan(0);
  });
});
