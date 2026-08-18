import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CollectDiagnosticsDialog } from "./CollectDiagnosticsDialog";
import { CollectionCompleteDialog } from "./CollectionCompleteDialog";
import { useUiStore } from "../../stores/ui-store";
import { COLLECTION_PRESETS } from "../../lib/collection-categories";

const collectDiagnostics = vi.hoisted(() => vi.fn());

vi.mock("../../lib/commands", () => ({
  collectDiagnostics,
}));

vi.mock("../../lib/log-source", () => ({
  loadPathAsLogSource: vi.fn(),
}));

describe("CollectDiagnosticsDialog", () => {
  afterEach(() => {
    cleanup();
    useUiStore.setState({ collectionProgress: null, collectionResult: null });
  });

  it("exposes a dialog landmark when open", () => {
    render(<CollectDiagnosticsDialog isOpen onClose={() => {}} />);
    const dialog = screen.getByRole("dialog", { name: "Collect Diagnostics" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("shows presets, category checkboxes, and starts collection", async () => {
    collectDiagnostics.mockResolvedValue({
      bundlePath: "C:/Users/Public/cmtrace-bundle",
      bundleId: "bundle-1",
      artifactCounts: { collected: 4, missing: 1, failed: 0, total: 5 },
      durationMs: 1200,
      gaps: [{ artifactId: "cbs", category: "general", reason: "not present" }],
    });
    const onClose = vi.fn();
    render(<CollectDiagnosticsDialog isOpen onClose={onClose} />);

    expect(screen.getByText("Collect Diagnostics")).toBeInTheDocument();
    expect(screen.getByText("Quick Presets")).toBeInTheDocument();
    for (const preset of COLLECTION_PRESETS) {
      expect(screen.getByRole("button", { name: preset.label })).toBeInTheDocument();
    }
    expect(screen.getByText("Intune & MDM")).toBeInTheDocument();
    expect(screen.getByText("Autopilot & Provisioning")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Intune + Autopilot" }));
    fireEvent.click(screen.getByRole("button", { name: "Collect" }));
    expect(onClose).toHaveBeenCalled();
    expect(collectDiagnostics).toHaveBeenCalled();
  });
});

describe("CollectionCompleteDialog", () => {
  afterEach(() => {
    cleanup();
  });

  it("exposes a dialog landmark when complete", () => {
    render(
      <CollectionCompleteDialog
        onClose={() => {}}
        result={{
          bundlePath: "C:/Users/Public/cmtrace-bundle",
          bundleId: "bundle-1",
          artifactCounts: { collected: 4, missing: 1, failed: 0, total: 5 },
          durationMs: 1500,
          gaps: [],
        }}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "Collection Complete" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("shows counts, gaps, Close, and Open Bundle", () => {
    const onClose = vi.fn();
    render(
      <CollectionCompleteDialog
        onClose={onClose}
        result={{
          bundlePath: "C:/Users/Public/cmtrace-bundle",
          bundleId: "bundle-1",
          artifactCounts: { collected: 4, missing: 1, failed: 0, total: 5 },
          durationMs: 1500,
          gaps: [{ artifactId: "cbs", category: "general", reason: "CBS.log not present" }],
        }}
      />,
    );
    expect(screen.getByText("Collection Complete")).toBeInTheDocument();
    expect(screen.getByText("Collected")).toBeInTheDocument();
    expect(screen.getByText("Missing")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Show 1 missing/i }));
    expect(screen.getByText(/CBS.log not present/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open Bundle" })).toBeInTheDocument();
  });
});
