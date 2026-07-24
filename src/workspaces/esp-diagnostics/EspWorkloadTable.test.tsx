import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EspWorkloadTable } from "./EspWorkloadTable";
import {
  makeEspSession,
  makeEspSnapshot,
  makeEspWorkload,
} from "./esp-session-fixtures";
import type { EspNormalizedStatus, EspWorkload } from "./types";

function row(
  id: string,
  normalized: EspNormalizedStatus,
  display: string,
  name: string,
): EspWorkload {
  return makeEspWorkload({
    workloadId: id,
    sessionId: "s1",
    rawIdentifier: `Win32App_${id}`,
    displayName: name,
    status: { raw: normalized, normalized, display, detail: null },
  });
}

function snapshot() {
  return makeEspSnapshot({
    sessions: [makeEspSession({ sessionId: "s1", isLatest: true })],
    workloads: [
      row("citrix", "failed", "Failed", "Citrix Workspace"),
      row("vc", "succeeded", "Installed", "Visual C++"),
      row("seven", "installing", "Installing", "7-Zip"),
    ],
  });
}

describe("EspWorkloadTable filter/search", () => {
  it("shows status chips with per-category counts", () => {
    render(<EspWorkloadTable snapshot={snapshot()} />);
    expect(screen.getByRole("button", { name: /Failed 1/ })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Running 1/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Installed 1/ }),
    ).toBeInTheDocument();
  });

  it("filters to failed apps when the Failed chip is clicked", () => {
    render(<EspWorkloadTable snapshot={snapshot()} />);
    fireEvent.click(screen.getByRole("button", { name: /Failed 1/ }));
    expect(screen.getByText("Citrix Workspace")).toBeInTheDocument();
    expect(screen.queryByText("Visual C++")).not.toBeInTheDocument();
    expect(screen.queryByText("7-Zip")).not.toBeInTheDocument();
  });

  it("searches by name across all statuses", () => {
    render(<EspWorkloadTable snapshot={snapshot()} />);
    fireEvent.change(screen.getByRole("searchbox", { name: /Search workloads/ }), {
      target: { value: "7-zip" },
    });
    expect(screen.getByText("7-Zip")).toBeInTheDocument();
    expect(screen.queryByText("Citrix Workspace")).not.toBeInTheDocument();
  });

  it("reports when a filter matches nothing without hiding the session", () => {
    render(<EspWorkloadTable snapshot={snapshot()} />);
    fireEvent.change(screen.getByRole("searchbox", { name: /Search workloads/ }), {
      target: { value: "nonexistent-app" },
    });
    expect(
      screen.getByText(/No workloads match the current search or filter/),
    ).toBeInTheDocument();
  });
});
