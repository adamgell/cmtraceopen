import { render, screen } from "@testing-library/react";
import { getIdentifier, getName, getTauriVersion, getVersion } from "@tauri-apps/api/app";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AboutDialog } from "./AboutDialog";

vi.mock("@tauri-apps/api/app", () => ({
  getIdentifier: vi.fn(),
  getName: vi.fn(),
  getTauriVersion: vi.fn(),
  getVersion: vi.fn(),
}));

const getIdentifierMock = vi.mocked(getIdentifier);
const getNameMock = vi.mocked(getName);
const getTauriVersionMock = vi.mocked(getTauriVersion);
const getVersionMock = vi.mocked(getVersion);

describe("AboutDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getIdentifierMock.mockResolvedValue("com.cmtrace.open");
    getNameMock.mockResolvedValue("CMTrace Open");
    getTauriVersionMock.mockResolvedValue("2.11.1");
    getVersionMock.mockResolvedValue("1.3.2");
  });

  it("shows main channel app metadata", async () => {
    render(<AboutDialog isOpen onClose={() => {}} />);

    await expect(screen.findByText("CMTrace Open")).resolves.toBeVisible();
    expect(await screen.findByText("Version 1.3.2")).toBeVisible();
    expect(screen.getByText("Main channel")).toBeVisible();
    expect(screen.getByText(/github\.com\/adamgell\/cmtraceopen/i)).toBeVisible();
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
});
