import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useUiStore } from "../../stores/ui-store";
import { ErrorLookupDialog } from "./ErrorLookupDialog";

const invokeMock = vi.mocked(invoke);
const writeTextMock = vi.mocked(writeText);

describe("ErrorLookupDialog (CHROME-016)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({
      errorLookupHistory: [],
      lookupErrorCode: null,
    });
    invokeMock.mockResolvedValue([]);
  });

  afterEach(() => {
    cleanup();
  });

  it("searches immediately for a hex code and copies the result", async () => {
    invokeMock.mockResolvedValue([
      {
        codeHex: "0x80070005",
        codeDecimal: "-2147024891",
        description: "Access is denied.",
        category: "Windows",
        found: true,
      },
    ]);

    render(<ErrorLookupDialog isOpen onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: "Error Code Lookup" })).toBeVisible();

    fireEvent.change(
      screen.getByPlaceholderText("Search by code (0x80070005) or description (access denied)"),
      { target: { value: "0x80070005" } },
    );

    await waitFor(() => {
      expect(screen.getAllByText("0x80070005").length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText("Access is denied.").length).toBeGreaterThan(0);
    expect(invokeMock).toHaveBeenCalledWith("search_error_codes", { query: "0x80070005" });

    fireEvent.click(screen.getAllByRole("button", { name: "Copy to clipboard" })[0]);
    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledWith("0x80070005 - Access is denied.");
    });
  });

  it("reruns a lookup from recent history", async () => {
    useUiStore.setState({
      errorLookupHistory: [
        {
          codeHex: "0x80004005",
          codeDecimal: "-2147467259",
          description: "Unspecified error",
          category: "Windows",
          found: true,
          timestamp: Date.now(),
        },
      ],
    });
    invokeMock.mockResolvedValue([
      {
        codeHex: "0x80004005",
        codeDecimal: "-2147467259",
        description: "Unspecified error",
        category: "Windows",
        found: true,
      },
    ]);

    render(<ErrorLookupDialog isOpen onClose={() => {}} />);
    expect(screen.getByText("Recent lookups")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: /0x80004005/ }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("search_error_codes", { query: "0x80004005" });
    });
  });
});
