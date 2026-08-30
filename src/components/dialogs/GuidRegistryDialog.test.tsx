import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useIntuneStore } from "../../workspaces/intune/intune-store";
import { GuidRegistryDialog } from "./GuidRegistryDialog";

const writeTextMock = vi.mocked(writeText);

describe("GuidRegistryDialog (CHROME-017)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useIntuneStore.getState().clear();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the empty-state hint when no GUID registry has been built", () => {
    render(<GuidRegistryDialog isOpen onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: "GUID Registry" })).toBeVisible();
    expect(
      screen.getByText(
        "No GUID registry data available. Run an Intune analysis or enable Graph API in Settings.",
      ),
    ).toBeVisible();
  });

  it("filters by name and copies the GUID on row click", async () => {
    useIntuneStore.setState({
      guidRegistry: {
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": {
          name: "Company Portal",
          source: "ApplicationName",
          category: "app",
          publisher: "Microsoft",
        },
        "11111111-2222-3333-4444-555555555555": {
          name: "Remediate Disk",
          source: "NameField",
          category: "remediation",
        },
      },
    });

    render(<GuidRegistryDialog isOpen onClose={() => {}} />);
    expect(screen.getByText("All (2)")).toBeVisible();
    expect(screen.getByText("Company Portal")).toBeVisible();
    expect(screen.getByText("Remediate Disk")).toBeVisible();

    fireEvent.click(screen.getByText("Apps (1)"));
    expect(screen.getByText("Company Portal")).toBeVisible();
    expect(screen.queryByText("Remediate Disk")).not.toBeInTheDocument();

    fireEvent.change(
      screen.getByPlaceholderText("Filter by name, GUID, or publisher..."),
      { target: { value: "zzzz" } },
    );
    expect(screen.getByText(/No matches for/)).toBeVisible();

    fireEvent.change(
      screen.getByPlaceholderText("Filter by name, GUID, or publisher..."),
      { target: { value: "company" } },
    );
    expect(screen.getByText("Company Portal")).toBeVisible();

    fireEvent.click(screen.getByLabelText("Copy GUID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    expect(writeTextMock).toHaveBeenCalledWith("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  });
});
