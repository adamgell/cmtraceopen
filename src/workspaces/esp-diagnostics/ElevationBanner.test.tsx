import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ElevationBanner } from "./ElevationBanner";
import { requestElevatedRestart } from "../../lib/elevation";
import type { EspElevationState } from "./types";

vi.mock("../../lib/elevation", async () => {
  const actual =
    await vi.importActual<typeof import("../../lib/elevation")>(
      "../../lib/elevation",
    );
  return { ...actual, requestElevatedRestart: vi.fn() };
});

const requestElevatedRestartMock = vi.mocked(requestElevatedRestart);

const ELEVATION: EspElevationState = {
  isElevated: false,
  restartSupported: true,
  restrictedSources: ["HKLM Enrollment Status Tracking registry"],
};

function clickRestart() {
  fireEvent.click(
    screen.getByRole("button", { name: "Restart as administrator" }),
  );
}

describe("ElevationBanner restart outcomes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reports an in-flight restart as in progress rather than a failure", async () => {
    // `busy` means another entry point (the menu dialog, the Access Denied
    // prompt, or a double click here) already has a request with Windows.
    // Falling through to the failure branch told the user nothing had started
    // when something already had.
    requestElevatedRestartMock.mockResolvedValue({ status: "busy" });
    render(<ElevationBanner elevation={ELEVATION} />);

    clickRestart();

    expect(
      await screen.findByText("An administrator restart is already in progress."),
    ).toBeVisible();
    expect(
      screen.queryByText(
        "Administrator restart could not be started; coverage remains partial.",
      ),
    ).toBeNull();
    // The in-flight request belongs to another entry point. If it settles as
    // cancelled or failed nothing would re-enable this button, so "busy" must
    // not strand the user on a dead control until a reload.
    expect(
      screen.getByRole("button", { name: "Restart as administrator" }),
    ).toBeEnabled();
  });

  it("still reports a genuine launch failure as a failure", async () => {
    requestElevatedRestartMock.mockResolvedValue({
      status: "failed",
      message: "Administrator restart could not be started.",
    });
    render(<ElevationBanner elevation={ELEVATION} />);

    clickRestart();

    expect(
      await screen.findByText(
        "Administrator restart could not be started; coverage remains partial.",
      ),
    ).toBeVisible();
  });

  it("confirms a successful launch", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });
    render(<ElevationBanner elevation={ELEVATION} />);

    clickRestart();

    expect(
      await screen.findByText("Administrator restart requested."),
    ).toBeVisible();
  });

  it("reports a cancelled UAC prompt without claiming a failure", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "cancelled" });
    render(<ElevationBanner elevation={ELEVATION} />);

    clickRestart();

    expect(
      await screen.findByText(
        "Administrator restart was cancelled; coverage remains partial.",
      ),
    ).toBeVisible();
    // Cancelling is recoverable: the user must be able to try again.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Restart as administrator" }),
      ).toBeEnabled(),
    );
  });
});
