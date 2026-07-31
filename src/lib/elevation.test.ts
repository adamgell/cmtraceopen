import { beforeEach, describe, expect, it, vi } from "vitest";
import { getAppElevationState, restartAsAdministrator } from "./commands";
import {
  canOfferElevation,
  describeElevationOutcome,
  markElevationRetryAttempted,
  readElevationState,
  requestElevatedRestart,
  resetElevationCoordinatorForTests,
} from "./elevation";
import type { AppElevationState, ElevationRequest } from "../types/elevation";

vi.mock("./commands", () => ({
  getAppElevationState: vi.fn(),
  restartAsAdministrator: vi.fn(),
}));

const getAppElevationStateMock = vi.mocked(getAppElevationState);
const restartAsAdministratorMock = vi.mocked(restartAsAdministrator);

const menuRequest: ElevationRequest = {
  reason: "explicitMenu",
  workspace: "log",
  target: { kind: "workspace" },
};

function state(overrides: Partial<AppElevationState> = {}): AppElevationState {
  return { platformSupported: true, isElevated: false, ...overrides };
}

describe("elevation coordinator", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetElevationCoordinatorForTests();
  });

  it("reports a launch so the caller can stop rendering", async () => {
    restartAsAdministratorMock.mockResolvedValue({
      launched: true,
      reason: "launched",
    });

    expect(await requestElevatedRestart(menuRequest)).toEqual({
      status: "launched",
    });
  });

  it("treats a cancelled UAC prompt as an outcome, not a failure", async () => {
    restartAsAdministratorMock.mockResolvedValue({
      launched: false,
      reason: "elevationCancelled",
    });

    expect(await requestElevatedRestart(menuRequest)).toEqual({
      status: "cancelled",
    });
  });

  it("distinguishes already-elevated and unsupported from failure", async () => {
    restartAsAdministratorMock.mockResolvedValue({
      launched: false,
      reason: "alreadyElevated",
    });
    expect(await requestElevatedRestart(menuRequest)).toEqual({
      status: "alreadyElevated",
    });

    restartAsAdministratorMock.mockResolvedValue({
      launched: false,
      reason: "unsupportedPlatform",
    });
    expect(await requestElevatedRestart(menuRequest)).toEqual({
      status: "unsupported",
    });
  });

  it("never throws — a rejected invoke becomes a failure outcome", async () => {
    restartAsAdministratorMock.mockRejectedValue(
      new Error("the elevation restore ticket could not be prepared"),
    );

    expect(await requestElevatedRestart(menuRequest)).toEqual({
      status: "failed",
      message: "the elevation restore ticket could not be prepared",
    });
  });

  it("collapses duplicate clicks into a single backend request", async () => {
    let release: (value: { launched: boolean; reason: "launched" }) => void =
      () => {};
    restartAsAdministratorMock.mockReturnValue(
      new Promise((resolve) => {
        release = resolve;
      }),
    );

    const first = requestElevatedRestart(menuRequest);
    const second = await requestElevatedRestart(menuRequest);

    // The second click is refused outright rather than queued behind the first,
    // so the user cannot stack UAC prompts.
    expect(second).toEqual({ status: "busy" });
    expect(restartAsAdministratorMock).toHaveBeenCalledOnce();

    release({ launched: true, reason: "launched" });
    expect(await first).toEqual({ status: "launched" });
  });

  it("allows a fresh request once the previous one settles", async () => {
    restartAsAdministratorMock.mockResolvedValue({
      launched: false,
      reason: "elevationCancelled",
    });

    await requestElevatedRestart(menuRequest);
    await requestElevatedRestart(menuRequest);

    expect(restartAsAdministratorMock).toHaveBeenCalledTimes(2);
  });

  it("offers elevation only on a supported, non-elevated platform", () => {
    expect(canOfferElevation(state())).toBe(true);
    expect(canOfferElevation(state({ isElevated: true }))).toBe(false);
    expect(canOfferElevation(state({ platformSupported: false }))).toBe(false);
    expect(canOfferElevation(null)).toBe(false);
  });

  it("stops offering elevation once a restored retry was attempted", () => {
    expect(canOfferElevation(state())).toBe(true);

    markElevationRetryAttempted();

    // This is the loop guard: a restored source that is still denied must not
    // produce a second elevation prompt.
    expect(canOfferElevation(state())).toBe(false);
  });

  it("returns null rather than throwing when the elevation probe fails", async () => {
    getAppElevationStateMock.mockRejectedValue(new Error("probe failed"));

    expect(await readElevationState()).toBeNull();
  });

  it("passes through a successful elevation probe", async () => {
    getAppElevationStateMock.mockResolvedValue(state({ isElevated: true }));

    expect(await readElevationState()).toEqual(state({ isElevated: true }));
  });

  it("describes every outcome", () => {
    expect(describeElevationOutcome({ status: "launched" })).toContain(
      "requested",
    );
    expect(describeElevationOutcome({ status: "cancelled" })).toContain(
      "cancelled",
    );
    expect(describeElevationOutcome({ status: "alreadyElevated" })).toContain(
      "already running as administrator",
    );
    expect(describeElevationOutcome({ status: "unsupported" })).toContain(
      "Windows",
    );
    expect(describeElevationOutcome({ status: "busy" })).toContain(
      "already in progress",
    );
    expect(
      describeElevationOutcome({ status: "failed", message: "disk full" }),
    ).toBe("disk full");
  });
});
