import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { useEvtxStore } from "./evtx-store";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

describe("EvtxCoverageBanner archive provenance", () => {
  beforeEach(() => {
    useEvtxStore.setState({
      coverageGaps: [],
      coverageDetails: [],
      tailCoverageGaps: [],
      archiveMembers: [],
    });
  });

  it("renders every archive member decision, including duplicate paths", () => {
    const member = {
      path: "bundle.zip::logs/Application.evtx",
      kind: "evtx" as const,
      sha256: "abc123",
      outcome: "duplicate" as const,
    };
    useEvtxStore.setState({ archiveMembers: [member, { ...member }] });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("2 archive members in this view")).toBeInTheDocument();
    expect(screen.getByText("Archive member provenance (2)")).toBeInTheDocument();
    expect(
      screen.getAllByText(
        "bundle.zip::logs/Application.evtx: evtx duplicate (sha256:abc123)"
      )
    ).toHaveLength(2);
  });
});
