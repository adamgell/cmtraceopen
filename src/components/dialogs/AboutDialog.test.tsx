import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { getIdentifier, getName, getTauriVersion, getVersion } from "@tauri-apps/api/app";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { openAppLogsFolder } from "../../lib/commands";
import { AboutDialog } from "./AboutDialog";

vi.mock("@tauri-apps/api/app", () => ({
  getIdentifier: vi.fn(),
  getName: vi.fn(),
  getTauriVersion: vi.fn(),
  getVersion: vi.fn(),
}));

vi.mock("../../lib/commands", () => ({
  openAppLogsFolder: vi.fn(),
}));

const consoleErrorMock = vi.spyOn(console, "error").mockImplementation(() => {});
const getIdentifierMock = vi.mocked(getIdentifier);
const getNameMock = vi.mocked(getName);
const getTauriVersionMock = vi.mocked(getTauriVersion);
const getVersionMock = vi.mocked(getVersion);
const openAppLogsFolderMock = vi.mocked(openAppLogsFolder);

afterAll(() => {
  consoleErrorMock.mockRestore();
});

describe("AboutDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getIdentifierMock.mockResolvedValue("com.cmtrace.open");
    getNameMock.mockResolvedValue("CMTrace Open");
    getTauriVersionMock.mockResolvedValue("2.11.1");
    getVersionMock.mockResolvedValue("1.3.2");
    openAppLogsFolderMock.mockResolvedValue(undefined);
  });

  it("shows main channel app metadata", async () => {
    render(<AboutDialog isOpen onClose={() => {}} />);

    await expect(screen.findByText("CMTrace Open")).resolves.toBeVisible();
    expect(await screen.findByText("Version 1.3.2")).toBeVisible();
    expect(screen.getByText("Main channel")).toBeVisible();
    expect(screen.getByText(/github\.com\/adamgell\/cmtraceopen/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Open Logs Folder" })).toBeVisible();
  });

  it("shows nightly channel app metadata", async () => {
    getIdentifierMock.mockResolvedValue("com.cmtrace.open.nightly");
    getNameMock.mockResolvedValue("CMTrace Open Nightly");
    getVersionMock.mockResolvedValue("1.3.2-nightly.20260515.12.gbf866b4d3f2e");

    render(<AboutDialog isOpen onClose={() => {}} />);

    await expect(screen.findByText("CMTrace Open Nightly")).resolves.toBeVisible();
    expect(
      await screen.findByText("Version 1.3.2-nightly.20260515.12.gbf866b4d3f2e")
    ).toBeVisible();
    expect(screen.getByText("Nightly channel")).toBeVisible();
    expect(screen.getByText(/com\.cmtrace\.open\.nightly/i)).toBeVisible();
  });

  it("opens the application logs folder from the about dialog", async () => {
    render(<AboutDialog isOpen onClose={() => {}} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open Logs Folder" }));

    await waitFor(() => {
      expect(openAppLogsFolderMock).toHaveBeenCalledTimes(1);
    });
  });

  it("shows a user-friendly error when opening the logs folder fails", async () => {
    openAppLogsFolderMock.mockRejectedValue(new Error("I/O error: Access denied"));

    render(<AboutDialog isOpen onClose={() => {}} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open Logs Folder" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "File operation failed: Access denied"
    );
    expect(consoleErrorMock).toHaveBeenCalledWith("Failed to open app logs folder", {
      error: expect.any(Error),
    });
  });
});
