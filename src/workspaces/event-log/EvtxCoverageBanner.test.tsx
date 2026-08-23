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

  it("reports the full archive count when member messages reach the display limit", () => {
    useEvtxStore.setState({
      archiveMembers: Array.from({ length: 4_098 }, (_, index) => ({
        path: `bundle.zip::logs/member-${index}.evtx`,
        kind: "evtx" as const,
        outcome: "parsed" as const,
      })),
    });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("4098 archive members in this view")).toBeInTheDocument();
    expect(screen.getByText("Archive member provenance (4098)")).toBeInTheDocument();
    expect(
      screen.getByText("<archive member metadata: 2 omitted by display limit>"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("bundle.zip::logs/member-4096.evtx: evtx parsed"),
    ).not.toBeInTheDocument();
  });

  it("bounds rendered coverage gaps and reports the omitted count", () => {
    useEvtxStore.setState({
      coverageGaps: Array.from(
        { length: 258 },
        (_, index) => `source-${index}: coverage gap ${index}`,
      ),
    });

    render(<EvtxCoverageBanner />);

    expect(screen.getByText("258 gaps in this view")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(256);
    expect(
      screen.getByText("<coverage gaps: 3 omitted by display limit>"),
    ).toBeInTheDocument();
    expect(screen.queryByText("source-257: coverage gap 257")).not.toBeInTheDocument();
  });
});
