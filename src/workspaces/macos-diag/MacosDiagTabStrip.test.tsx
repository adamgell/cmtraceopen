import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MacosDiagTabStrip } from "./MacosDiagTabStrip";
import { useMacosDiagStore } from "./macos-diag-store";

const INITIAL = useMacosDiagStore.getInitialState();

afterEach(() => {
  cleanup();
  useMacosDiagStore.setState(INITIAL, true);
});

describe("MacosDiagTabStrip", () => {
  it("exposes the row as a tab list rather than a row of buttons", () => {
    render(<MacosDiagTabStrip />);

    // The active tab used to be conveyed by a CSS class alone, so a screen
    // reader heard buttons with no indication of which one was current, and the
    // row had no tab list for it to navigate.
    expect(screen.getByRole("tablist")).toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(5);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("reports the selected tab, and moves the mark when another is chosen", () => {
    render(<MacosDiagTabStrip />);

    const tabs = screen.getAllByRole("tab");
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    for (const tab of tabs.slice(1)) {
      expect(tab).toHaveAttribute("aria-selected", "false");
    }

    fireEvent.click(tabs[2]);
    expect(useMacosDiagStore.getState().activeTab).toBe("defender");
    expect(screen.getAllByRole("tab")[2]).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getAllByRole("tab")[0]).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  it("still shows each tab's count, and none where there is nothing to count", () => {
    useMacosDiagStore.setState({
      packagesResult: { packages: [], totalCount: 0, microsoftCount: 4 },
    });

    render(<MacosDiagTabStrip />);

    // Rewriting the row on the library component must not quietly drop the badges.
    const packages = screen.getAllByRole("tab")[3];
    expect(packages).toHaveTextContent("Packages");
    expect(packages).toHaveTextContent("4");

    // "Unified Log" has no count source, so it must not grow a badge.
    const unifiedLog = screen.getAllByRole("tab")[4];
    expect(unifiedLog).toHaveTextContent("Unified Log");
    expect(unifiedLog).not.toHaveTextContent(/\d/);
  });
});
