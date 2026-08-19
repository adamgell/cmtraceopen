import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { inspectEvidenceArtifact, inspectEvidenceBundle } from "../../lib/commands";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import type { EvidenceBundleDetails, EvidenceBundleMetadata } from "../../types/evidence";
import { EvidenceBundleDialog } from "./EvidenceBundleDialog";

vi.mock("../../lib/commands", () => ({
  inspectEvidenceBundle: vi.fn(),
  inspectEvidenceArtifact: vi.fn(),
}));

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    openPathForActiveWorkspace: vi.fn(),
  }),
}));

const inspectEvidenceBundleMock = vi.mocked(inspectEvidenceBundle);
const inspectEvidenceArtifactMock = vi.mocked(inspectEvidenceArtifact);

function metadata(overrides: Partial<EvidenceBundleMetadata> = {}): EvidenceBundleMetadata {
  return {
    manifestPath: "/tmp/bundle/manifest.json",
    notesPath: "/tmp/bundle/notes.md",
    evidenceRoot: "/tmp/bundle/evidence",
    primaryEntryPoints: ["evidence/ime.log"],
    availablePrimaryEntryPoints: ["evidence/ime.log"],
    bundleId: "bundle-fixture",
    bundleLabel: "Fixture evidence bundle",
    createdUtc: "2026-08-18T12:00:00Z",
    caseReference: "CASE-018",
    summary: "Minimal fixture inventory.",
    collectorProfile: "quick",
    collectorVersion: "1.0.0",
    collectedUtc: "2026-08-18T12:00:00Z",
    deviceName: "TEST-PC",
    primaryUser: "analyst",
    platform: "windows",
    osVersion: "10.0.26100",
    tenant: "contoso",
    artifactCounts: {
      collected: 0,
      missing: 0,
      failed: 0,
      skipped: 0,
    },
    ...overrides,
  };
}

function details(overrides: Partial<EvidenceBundleDetails> = {}): EvidenceBundleDetails {
  const meta = overrides.metadata ?? metadata();
  return {
    bundleRootPath: "/tmp/bundle",
    metadata: meta,
    manifestContent: '{"bundleId":"bundle-fixture"}',
    notesContent: "Collector notes.",
    artifacts: [],
    expectedEvidence: [],
    observedGaps: [],
    priorityQuestions: [],
    handoffSummary: null,
    ...overrides,
  };
}

function tabButton(container: HTMLElement, name: string): HTMLButtonElement {
  const button = Array.from(container.querySelectorAll("button")).find(
    (element) => element.textContent === name,
  );
  if (!(button instanceof HTMLButtonElement)) {
    throw new Error(`Missing tab button: ${name}`);
  }
  return button;
}

describe("EvidenceBundleDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({
      activeView: "log",
      activeWorkspace: "log",
    });
    useLogStore.getState().clear();
    inspectEvidenceBundleMock.mockResolvedValue(details());
    inspectEvidenceArtifactMock.mockResolvedValue({
      path: "/tmp/bundle/evidence/ime.log",
      intakeKind: "log",
      summary: "log preview",
      registrySnapshot: null,
      eventLogExport: null,
    });
  });

  it("renders nothing without bundle metadata", () => {
    render(<EvidenceBundleDialog isOpen onClose={() => {}} />);
    expect(screen.queryByText("Evidence Bundle")).not.toBeInTheDocument();
    expect(inspectEvidenceBundleMock).not.toHaveBeenCalled();
  });

  it("opens Summary/Inventory/Notes/Manifest and empty inventory copy from a store fixture", async () => {
    useLogStore.getState().setBundleMetadata(metadata());
    useLogStore.getState().setActiveSource({
      kind: "folder",
      path: "/tmp/bundle",
    });

    const { container } = render(<EvidenceBundleDialog isOpen onClose={() => {}} />);

    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", "Evidence bundle summary");
    expect(screen.getByText("Fixture evidence bundle")).toBeInTheDocument();
    expect(screen.getByText("Minimal fixture inventory.")).toBeInTheDocument();
    expect(tabButton(container, "Summary")).toHaveAttribute("aria-pressed", "true");
    expect(tabButton(container, "Inventory")).toBeTruthy();
    expect(tabButton(container, "Notes")).toBeTruthy();
    expect(tabButton(container, "Manifest")).toBeTruthy();
    expect(screen.getByText("Bundle metadata")).toBeInTheDocument();
    expect(screen.getByText("Primary evidence entry points")).toBeInTheDocument();
    expect(tabButton(container, "Close")).toBeTruthy();

    await waitFor(() => {
      expect(inspectEvidenceBundleMock).toHaveBeenCalledWith("/tmp/bundle");
    });
    await waitFor(() => {
      expect(screen.queryByText("Loading evidence bundle details...")).not.toBeInTheDocument();
    });

    fireEvent.click(tabButton(container, "Inventory"));
    expect(tabButton(container, "Inventory")).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByText("No artifact records were found in the manifest."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("No intake diagnostics are available yet."),
    ).toBeInTheDocument();
    expect(screen.getByText("No artifact detail was available.")).toBeInTheDocument();
    expect(
      screen.getByText("No expected-evidence detail was recorded in the manifest."),
    ).toBeInTheDocument();

    fireEvent.click(tabButton(container, "Notes"));
    expect(tabButton(container, "Notes")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Collector notes.")).toBeInTheDocument();

    fireEvent.click(tabButton(container, "Manifest"));
    expect(tabButton(container, "Manifest")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText('{"bundleId":"bundle-fixture"}')).toBeInTheDocument();
  });

  it("shows inspect error copy while keeping the dialog and tabs visible", async () => {
    useLogStore.getState().setBundleMetadata(metadata());
    useLogStore.getState().setActiveSource({
      kind: "folder",
      path: "/tmp/bundle",
    });
    inspectEvidenceBundleMock.mockRejectedValue(new Error("inspect failed"));

    const { container } = render(<EvidenceBundleDialog isOpen onClose={() => {}} />);

    expect(await screen.findByText("inspect failed")).toBeInTheDocument();
    expect(container.querySelector('[role="dialog"]')).not.toBeNull();
    expect(tabButton(container, "Summary")).toBeTruthy();
    expect(tabButton(container, "Inventory")).toBeTruthy();
    expect(tabButton(container, "Notes")).toBeTruthy();
    expect(tabButton(container, "Manifest")).toBeTruthy();

    fireEvent.click(tabButton(container, "Notes"));
    expect(screen.getByText("No content was available for this file.")).toBeInTheDocument();
  });
});
