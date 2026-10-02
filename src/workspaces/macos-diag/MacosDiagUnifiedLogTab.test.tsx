import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { macosQueryUnifiedLog } from "../../lib/commands";
import { createTestVirtualizer } from "../../test-utils/virtualizer";
import { MacosDiagUnifiedLogTab } from "./MacosDiagUnifiedLogTab";
import { useMacosDiagStore } from "./macos-diag-store";
import type { MacosUnifiedLogResult } from "./types";

vi.mock("../../lib/commands", () => ({ macosQueryUnifiedLog: vi.fn() }));
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: Parameters<typeof createTestVirtualizer>[0]) =>
    createTestVirtualizer(options),
}));

const previousResult: MacosUnifiedLogResult = {
  entries: [{
    timestamp: "2026-01-15T12:00:00.000Z",
    process: "mdmclient",
    subsystem: null,
    category: null,
    level: "info",
    message: "Previous query entry",
    pid: 100,
    tid: 1,
  }],
  totalMatched: 10,
  capped: true,
  resultCap: 1,
  predicateUsed: 'process == "mdmclient"',
  timeRange: null,
};
const oversizedError = "Unified log output exceeded the size limit. Narrow the time range.";

beforeEach(() => {
  vi.resetAllMocks();
  useMacosDiagStore.getState().clear();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  useMacosDiagStore.getState().clear();
  vi.restoreAllMocks();
});

describe("unified log query failures", () => {
  it.each(["success", "clear"])("clears the stored error on %s", async (transition) => {
    vi.mocked(macosQueryUnifiedLog).mockRejectedValueOnce(oversizedError);
    render(<MacosDiagUnifiedLogTab />);
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(oversizedError);

    act(() => {
      if (transition === "success") {
        useMacosDiagStore.getState().setUnifiedLogResult(previousResult);
      } else {
        useMacosDiagStore.getState().clear();
      }
    });

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(useMacosDiagStore.getState().unifiedLogError).toBeNull();
  });

  it.each(["before", "after"])("preserves an error that arrives %s unmount", async (timing) => {
    useMacosDiagStore.getState().setUnifiedLogResult(previousResult);
    let rejectQuery!: (error: string) => void;
    vi.mocked(macosQueryUnifiedLog).mockReturnValueOnce(
      new Promise((_resolve, reject) => { rejectQuery = reject; }),
    );
    const tab = render(<MacosDiagUnifiedLogTab />);
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    if (timing === "after") tab.unmount();

    await act(async () => { rejectQuery(oversizedError); });
    if (timing === "before") tab.unmount();
    render(<MacosDiagUnifiedLogTab />);

    expect(screen.getByRole("alert")).toHaveTextContent(oversizedError);
    expect(screen.queryByText("Previous query entry")).not.toBeInTheDocument();
    expect(screen.queryByText(/Select a preset and time range/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Query" })).toBeEnabled();
  });

  it("clears the error while retrying and shows fresh results on success", async () => {
    vi.mocked(macosQueryUnifiedLog).mockRejectedValueOnce(oversizedError);
    render(<MacosDiagUnifiedLogTab />);
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(oversizedError);

    let resolveRetry!: (result: MacosUnifiedLogResult) => void;
    vi.mocked(macosQueryUnifiedLog).mockReturnValueOnce(
      new Promise((resolve) => { resolveRetry = resolve; }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Querying..." })).toBeDisabled();

    await act(async () => {
      resolveRetry({
        ...previousResult,
        capped: false,
        entries: [{ ...previousResult.entries[0], message: "Fresh query entry" }],
      });
    });
    expect(screen.getByText("Fresh query entry")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Query" })).toBeEnabled();
  });

  it.each([oversizedError, new Error(oversizedError)])(
    "replaces stale results with a visible failure for %s",
    async (error) => {
      useMacosDiagStore.getState().setUnifiedLogResult(previousResult);
      vi.mocked(macosQueryUnifiedLog).mockRejectedValueOnce(error);
      render(<MacosDiagUnifiedLogTab />);
      expect(screen.getByText("Previous query entry")).toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: "Run Query" }));

      expect(await screen.findByRole("alert")).toHaveTextContent(oversizedError);
      expect(screen.queryByText("Previous query entry")).not.toBeInTheDocument();
      expect(screen.queryByText(/Unified Log \(/)).not.toBeInTheDocument();
      expect(screen.queryByText(/Results capped/)).not.toBeInTheDocument();
      expect(screen.queryByText(/No log entries matched/)).not.toBeInTheDocument();
      expect(screen.queryByText(/Select a preset and time range/)).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Run Query" })).toBeEnabled();
      expect(useMacosDiagStore.getState().unifiedLogResult).toBeNull();
    },
  );
});
