import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecureBootWorkspace } from "./SecureBootWorkspace";
import { useSecureBootStore } from "./secureboot-store";
import type { SecureBootAnalysisResult, SecureBootScanState } from "./types";

function scanState(): SecureBootScanState {
  return {
    secureBootEnabled: true,
    managedOptIn: 1,
    availableUpdates: null,
    uefiCa2023Capable: 1,
    uefiCa2023Status: 0,
    uefiCa2023Error: null,
    managedOptInDate: null,
    telemetryLevel: null,
    diagtrackRunning: null,
    diagtrackStartType: null,
    tpmPresent: true,
    tpmEnabled: true,
    tpmActivated: null,
    tpmSpecVersion: null,
    bitlockerProtectionOn: true,
    bitlockerEncryptionStatus: null,
    bitlockerKeyProtectors: [],
    diskPartitionStyle: "GPT",
    payloadFolderExists: null,
    payloadBinCount: null,
    scheduledTaskExists: null,
    scheduledTaskLastRun: null,
    scheduledTaskLastResult: null,
    wincsAvailable: null,
    pendingRebootSources: [],
    deviceName: null,
    osCaption: null,
    osBuild: null,
    oemManufacturer: null,
    oemModel: null,
    firmwareVersion: null,
    firmwareDate: null,
    rawRegistryDump: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot",
  };
}

function analysis(): SecureBootAnalysisResult {
  return {
    stage: "stage5",
    dataSource: "liveScan",
    scanState: scanState(),
    sessions: [],
    timeline: [
      {
        timestamp: "2026-01-15T12:00:00.000Z",
        source: "detect",
        level: "info",
        eventType: "sessionStart",
        message: "Secure Boot detection started",
        stage: "stage5",
        errorCode: null,
      },
    ],
    diagnostics: [
      {
        ruleId: "SB-COMPLIANT",
        severity: "info",
        title: "UEFI CA 2023 is active",
        detail: "The 2023 certificate is present and Secure Boot is enabled.",
        recommendation: "No action required.",
      },
    ],
    scriptResult: null,
  };
}

afterEach(() => {
  cleanup();
  useSecureBootStore.getState().clear();
});

beforeEach(() => {
  useSecureBootStore.getState().clear();
});

describe("SecureBootWorkspace fixtures", () => {
  it("SB-002 shows diagnostics, timeline columns, and raw dump copy", () => {
    useSecureBootStore.getState().setResult(analysis());
    render(<SecureBootWorkspace />);

    expect(screen.getByRole("button", { name: /Diagnostics/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Timeline/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Raw Data" })).toBeInTheDocument();

    expect(screen.getByText("SB-COMPLIANT")).toBeInTheDocument();
    expect(screen.getByText("UEFI CA 2023 is active")).toBeInTheDocument();
    expect(
      screen.getByText("The 2023 certificate is present and Secure Boot is enabled."),
    ).toBeInTheDocument();
    expect(screen.getByText("No action required.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Timeline/ }));
    expect(screen.getByText("Timestamp")).toBeInTheDocument();
    expect(screen.getByText("Source")).toBeInTheDocument();
    expect(screen.getByText("Message")).toBeInTheDocument();
    expect(screen.getByText("Secure Boot detection started")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Raw Data" }));
    expect(
      screen.getByText("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
  });
});
