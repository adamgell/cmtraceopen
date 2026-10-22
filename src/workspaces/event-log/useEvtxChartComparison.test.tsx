import { act, cleanup, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => undefined)),
}));
vi.mock("./evtx-store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-store")>();
  return { ...actual, comparePreviousPeriod: vi.fn(actual.comparePreviousPeriod) };
});
vi.mock("./evtx-comparison", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-comparison")>();
  return { ...actual, countCurrentPeriod: vi.fn(actual.countCurrentPeriod) };
});

import { getLogListMetrics } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import { EvtxChartsView } from "./EvtxChartsView";
import {
  cancelComparison,
  computePriorWindow,
  countCurrentPeriod,
  getComparisonState,
  markTailAppended,
  publishComparisonUnavailable,
  resolveFilesPrior,
  useComparisonStore,
  type ComparisonOutcome,
  type PriorWindow,
} from "./evtx-comparison";
import { comparePreviousPeriod, useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import { useEvtxChartComparison } from "./useEvtxChartComparison";
import type { EvtxRecord } from "./types";

const NOT_COVERED = "The loaded files do not cover the previous period.";
const ANCHOR = Date.parse("2026-08-10T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const visualTokens = buildEvtxVisualTokens(getAllThemes()[0]);
const compareSpy = vi.mocked(comparePreviousPeriod);
const countSpy = vi.mocked(countCurrentPeriod);
const actualStore = await vi.importActual<typeof import("./evtx-store")>("./evtx-store");

let nextId = 1;
function fileRecord(overrides: Partial<EvtxRecord> = {}): EvtxRecord {
  const id = nextId++;
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-09T06:00:00.000Z",
    timestampEpoch: ANCHOR - 30 * HOUR,
    provider: "Contoso-Provider",
    channel: "System",
    eventId: 12,
    level: "Information",
    computer: "CONTOSO-PC01",
    message: "synthetic",
    eventData: [],
    rawXml: "<Event/>",
    sourceLabel: "System.evtx",
    ...overrides,
  };
}

function priorFor(): PriorWindow {
  const result = computePriorWindow("24h", ANCHOR);
  if (result.status !== "available") throw new Error("expected an available prior window");
  return result.prior;
}

/** Records a capture of System that spans the previous 24 h and reaches the anchor. */
function coveringRecords(): EvtxRecord[] {
  const prior = priorFor();
  return [
    fileRecord({ timestampEpoch: prior.fromMs, level: "Error", provider: "A", eventId: 1 }),
    fileRecord({ timestampEpoch: prior.fromMs + HOUR, level: "Error", provider: "A", eventId: 1 }),
    fileRecord({ timestampEpoch: prior.toMs, level: "Warning", provider: "B", eventId: 2 }),
    // The current period: six errors across three IDs, A 1 among them.
    ...Array.from({ length: 6 }, (_, i) =>
      fileRecord({
        timestampEpoch: ANCHOR - 2 * HOUR + i * 1000,
        level: "Error",
        provider: i < 4 ? "A" : "C",
        eventId: i < 4 ? 1 : 3 + (i % 2),
      }),
    ),
    fileRecord({ timestampEpoch: ANCHOR }),
  ];
}

function setFiles(records: EvtxRecord[], overrides: Record<string, unknown> = {}) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({
    sourceMode: "files",
    records,
    channels: [],
    selectedChannels: new Set(["System"]),
    loadedChannels: new Set<string>(),
    timeWindow: "24h",
    isLoading: false,
    ...overrides,
  });
}

function Harness({ active = true, nowEpoch = ANCHOR }: { active?: boolean; nowEpoch?: number }) {
  const comparison = useEvtxChartComparison(active, nowEpoch);
  const records = useEvtxStore((s) => s.records);
  return (
    <EvtxChartsView
      records={records}
      chains={null}
      hideRules={[]}
      channelOrder={["System"]}
      timeZoneMode="utc"
      loadedChannelCount={1}
      textLogCount={0}
      windowLabel="24 h"
      comparison={comparison}
      metrics={getLogListMetrics(13)}
      visualTokens={visualTokens}
    />
  );
}

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue(undefined);
  // A test that stubs the comparison must not leave it stubbed for the next one.
  compareSpy.mockReset();
  compareSpy.mockImplementation(actualStore.comparePreviousPeriod);
  countSpy.mockClear();
  cancelComparison();
});

afterEach(() => {
  cancelComparison();
  cleanup();
  vi.useRealTimers();
});

/** The view moves its tiles and its comparison together after the update throttle; let that pass. */
const flush = () =>
  act(async () => {
    await new Promise<void>((resolve) => setTimeout(resolve, 120));
  });

const compareButton = () => screen.queryByRole("button", { name: "Compare with previous period" });
const errorsSublabel = () => screen.queryByTestId("kpi-sublabel-errors")?.textContent ?? null;
const status = () => screen.getByTestId("comparison-status");

describe("useEvtxChartComparison", () => {
  describe("when Charts is not showing", () => {
    it("builds nothing and counts nothing", () => {
      setFiles(coveringRecords());
      const { result } = renderHook(() => useEvtxChartComparison(false, ANCHOR));
      expect(result.current).toBeNull();
      expect(countSpy).not.toHaveBeenCalled();
    });

    it("counts nothing, even for a comparison on show, until the view is active", () => {
      setFiles(coveringRecords());
      render(<Harness />);
      fireEvent.click(compareButton()!);
      expect(getComparisonState().phase).toBe("settled");
      cleanup();
      countSpy.mockClear();
      renderHook(() => useEvtxChartComparison(false, ANCHOR));
      expect(countSpy).not.toHaveBeenCalled();
    });
  });

  describe("the control before anything is compared", () => {
    it("is disabled for All time in files mode, with the comparison's reason", () => {
      setFiles(coveringRecords(), { timeWindow: "all" });
      render(<Harness />);
      expect(compareButton()).toHaveAttribute("aria-disabled", "true");
      expect(screen.getByTestId("comparison-disabled-reason").textContent).toBe(
        "All time has no previous period.",
      );
    });

    it("is disabled for All time in live mode as well, since no query is needed to know", () => {
      setFiles(coveringRecords(), { sourceMode: "live", timeWindow: "all" });
      render(<Harness />);
      expect(compareButton()).toHaveAttribute("aria-disabled", "true");
      expect(screen.getByTestId("comparison-disabled-reason").textContent).toBe(
        "All time has no previous period.",
      );
    });

    it("is enabled in live mode for a window that has a previous period", () => {
      setFiles(coveringRecords(), { sourceMode: "live" });
      render(<Harness />);
      expect(compareButton()).not.toHaveAttribute("aria-disabled", "true");
    });

    it("is enabled in files mode when the loaded files span the previous period", () => {
      setFiles(coveringRecords());
      render(<Harness />);
      expect(compareButton()).not.toHaveAttribute("aria-disabled", "true");
    });

    // Pinned by the comparison's reason code. The words are the comparison's own, rendered whole.
    it.each([
      {
        name: "the files do not span the period",
        records: () => [fileRecord({ timestampEpoch: ANCHOR })],
        selected: ["System"],
        reason: "priorPeriodNotSpanned",
      },
      {
        name: "a capture has no timed entry",
        records: () => [fileRecord({ timestampEpoch: 0 })],
        selected: ["System"],
        reason: "noTimedRecords",
      },
      {
        name: "nothing is loaded for the selected channels",
        records: () => [fileRecord({ channel: "Security", timestampEpoch: ANCHOR })],
        selected: ["System"],
        reason: "noTimedRecords",
      },
    ])("when $name: shows the comparison's words verbatim", ({ records, selected, reason }) => {
      const loaded = records();
      setFiles(loaded, { selectedChannels: new Set(selected) });
      const resolved = resolveFilesPrior(loaded, new Set(selected), "24h", ANCHOR);
      expect(resolved.status).toBe("unavailable");
      if (resolved.status !== "unavailable") return;
      expect(resolved.reason).toBe(reason);
      render(<Harness />);
      expect(screen.getByTestId("comparison-disabled-reason").textContent).toBe(resolved.detail);
      expect(compareButton()).toHaveAccessibleDescription(resolved.detail);
      expect(resolved.detail.startsWith(NOT_COVERED)).toBe(reason === "priorPeriodNotSpanned");
    });

    it("uses the instant the grid is measured from, so the control and Compare agree", async () => {
      // Covered from the capture's end, not covered from a clock a year later.
      setFiles(coveringRecords());
      const { rerender } = render(<Harness nowEpoch={ANCHOR} />);
      expect(compareButton()).not.toHaveAttribute("aria-disabled", "true");
      rerender(<Harness nowEpoch={ANCHOR + 365 * 24 * HOUR} />);
      await flush();
      expect(compareButton()).toHaveAttribute("aria-disabled", "true");
    });
  });

  describe("Compare", () => {
    it("measures a files comparison from the instant the grid is measured from", async () => {
      setFiles(coveringRecords());
      render(<Harness nowEpoch={ANCHOR} />);
      fireEvent.click(compareButton()!);
      expect(compareSpy).toHaveBeenCalledTimes(1);
      expect(compareSpy).toHaveBeenCalledWith(ANCHOR);
    });

    it("shows the delta of a complete files comparison, from the whole record set's current period", async () => {
      setFiles(coveringRecords());
      render(<Harness />);
      expect(errorsSublabel()).toBeNull();
      fireEvent.click(compareButton()!);
      await flush();
      // Six errors now against two in the previous period. The current period holds A 1, C 3, C 4
      // and the event stamped at the anchor, of which the previous period had only A 1.
      expect(errorsSublabel()).toBe("\u25b2 Up 3\u00d7 vs prior 24 h");
      expect(screen.getByTestId("kpi-sublabel-distinctIds").textContent).toBe("3 new vs prior 24 h");
      expect(screen.getByTestId("comparison-label")).toHaveTextContent("Comparing with ");
    });

    it("counts the current period over every loaded record, not over the rows the grid shows", async () => {
      setFiles(coveringRecords());
      // The grid shows only errors of A; the comparison counted every record under the view's
      // criteria, and so must the current side.
      render(<Harness />);
      fireEvent.click(compareButton()!);
      await flush();
      expect(countSpy).toHaveBeenCalled();
      const [records] = countSpy.mock.calls[0];
      expect(records).toBe(useEvtxStore.getState().records);
    });

    it("counts the current period under the criteria the comparison was made under", async () => {
      // Only event ID 1 is shown. Counted under the same criteria, the current period's IDs are
      // just A 1, which the previous period had, so none is new; counted under none, three would be.
      setFiles(coveringRecords(), { filterEventIds: "1" });
      render(<Harness />);
      fireEvent.click(compareButton()!);
      await flush();
      expect(screen.getByTestId("kpi-sublabel-distinctIds").textContent).toBe("0 new vs prior 24 h");
    });

    it("states how many tail events the current period left out, from the same count", async () => {
      const records = coveringRecords();
      markTailAppended([records[3]]);
      setFiles(records);
      render(<Harness />);
      fireEvent.click(compareButton()!);
      await flush();
      expect(screen.getByTestId("comparison-notes")).toHaveTextContent(
        "Left out of the current period: 1 event appended by the live tail.",
      );
    });

    it("does not start a second comparison while one is running", () => {
      setFiles(coveringRecords(), { sourceMode: "live" });
      useComparisonStore.setState({
        state: {
          phase: "running",
          mode: "live",
          requestId: "event-log-compare-9",
          prior: priorFor(),
          channels: ["System"],
          scanned: 0,
        },
      });
      const { result } = renderHook(() => useEvtxChartComparison(true, ANCHOR));
      act(() => result.current!.onCompare());
      expect(compareSpy).not.toHaveBeenCalled();
    });
  });

  describe("Clear", () => {
    it("ends the comparison, restores Compare, and says nothing about it being cleared", async () => {
      setFiles(coveringRecords());
      render(<Harness />);
      fireEvent.click(compareButton()!);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Clear comparison" }));
      await flush();
      expect(getComparisonState().phase).toBe("idle");
      expect(errorsSublabel()).toBeNull();
      expect(compareButton()).not.toHaveAttribute("aria-disabled", "true");
      expect(status()).toBeEmptyDOMElement();
    });

    it("cancels a comparison still reading, so the backend scan is stopped", async () => {
      setFiles(coveringRecords(), { sourceMode: "live" });
      useComparisonStore.setState({
        state: {
          phase: "running",
          mode: "live",
          requestId: "event-log-compare-10",
          prior: priorFor(),
          channels: ["System"],
          scanned: 3,
        },
      });
      render(<Harness />);
      fireEvent.click(screen.getByRole("button", { name: "Clear comparison" }));
      expect(getComparisonState().phase).toBe("idle");
    });
  });

  describe("a comparison that what it measured outlives", () => {
    it("is cleared with one quiet line when the criteria change, until the next comparison", async () => {
      setFiles(coveringRecords());
      render(<Harness />);
      fireEvent.click(compareButton()!);
      await flush();
      act(() => useEvtxStore.getState().setFilterSearch("synthetic"));
      await flush();
      expect(getComparisonState().phase).toBe("idle");
      expect(status()).toHaveTextContent("The comparison was cleared because what it measured changed.");
      expect(errorsSublabel()).toBeNull();
      fireEvent.click(compareButton()!);
      await flush();
      expect(status()).not.toHaveTextContent("was cleared");
      // The notice was spent by that comparison: the operator's own Clear does not bring it back.
      fireEvent.click(screen.getByRole("button", { name: "Clear comparison" }));
      await flush();
      expect(getComparisonState().phase).toBe("idle");
      expect(status()).not.toHaveTextContent("was cleared");
    });
  });

  describe("an out-of-date comparison", () => {
    it("withholds the delta once the grid's instant has drifted past the tolerance, and re-compares files from the current instant", async () => {
      setFiles(coveringRecords());
      const { rerender } = render(<Harness nowEpoch={ANCHOR} />);
      fireEvent.click(compareButton()!);
      await flush();
      expect(errorsSublabel()).not.toBeNull();
      rerender(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      expect(errorsSublabel()).toBeNull();
      expect(status()).toHaveTextContent("Out of date.");
      compareSpy.mockClear();
      fireEvent.click(screen.getByRole("button", { name: "Compare again" }));
      expect(compareSpy).toHaveBeenCalledTimes(1);
      expect(compareSpy).toHaveBeenCalledWith(ANCHOR + 3 * HOUR);
    });
  });

  describe("Refresh and compare again, in live mode", () => {
    const liveOutcome = (): ComparisonOutcome => {
      const prior = priorFor();
      const files = resolveFilesPrior(coveringRecords(), new Set(["System"]), "24h", ANCHOR);
      if (files.status !== "available") throw new Error("expected available");
      return {
        status: "complete",
        result: {
          mode: "live",
          window: "24h",
          prior,
          anchorBasis: "load",
          counts: {
            total: 3,
            levels: { Critical: 0, Error: 2, Warning: 1, Information: 0, Verbose: 0 },
            channels: new Map([["System", 3]]),
            distinctEvents: new Set(["A\u00001", "B\u00002"]),
          },
          gaps: [],
          notes: [],
          unplacedRecords: 0,
          unreadChannels: [],
          comparedChannels: ["System"],
          channelsWithGaps: [],
        },
      };
    };

    function staleLive() {
      setFiles(coveringRecords(), { sourceMode: "live", loadedChannels: new Set(["System"]) });
      useComparisonStore.setState({ state: { phase: "settled", outcome: liveOutcome() } });
    }

    it("reloads the loaded channels first, then compares from the clock, and says it will", async () => {
      staleLive();
      const order: string[] = [];
      const refresh = vi.fn(async () => {
        order.push("refresh");
        useEvtxStore.setState({ loadGeneration: useEvtxStore.getState().loadGeneration + 1 });
      });
      useEvtxStore.setState({ refreshLoadedChannels: refresh });
      compareSpy.mockImplementation(async () => {
        order.push("compare");
      });
      render(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Refresh and compare again" }));
      await flush();
      expect(order).toEqual(["refresh", "compare"]);
      expect(compareSpy).toHaveBeenCalledTimes(1);
      // From the clock now, not from the instant the stale comparison was made at.
      expect(Math.abs(compareSpy.mock.calls[0][0] - Date.now())).toBeLessThan(60_000);
    });

    it("never shows a delta from the old session while the reload runs, and no cleared notice", async () => {
      staleLive();
      let release: () => void = () => undefined;
      const pending = new Promise<void>((resolve) => {
        release = resolve;
      });
      useEvtxStore.setState({
        refreshLoadedChannels: async () => {
          useEvtxStore.setState({ loadGeneration: useEvtxStore.getState().loadGeneration + 1 });
          await pending;
        },
      });
      compareSpy.mockImplementation(async () => undefined);
      render(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Refresh and compare again" }));
      // The reload bumped the load generation, which cancelled the old comparison.
      expect(getComparisonState().phase).toBe("idle");
      await flush();
      expect(errorsSublabel()).toBeNull();
      expect(status()).not.toHaveTextContent("was cleared");
      release();
      await flush();
      expect(compareSpy).toHaveBeenCalledTimes(1);
      expect(errorsSublabel()).toBeNull();
    });

    it("shows the refusal the comparison gives after the reload, such as the cap", async () => {
      staleLive();
      const detail =
        "Security reached the automatic load's cap of 2,000 events, so the current period is only partly loaded. Deselect Security to compare the other channels.";
      useEvtxStore.setState({
        refreshLoadedChannels: async () => {
          useEvtxStore.setState({ loadGeneration: useEvtxStore.getState().loadGeneration + 1 });
        },
      });
      compareSpy.mockImplementation(async () => {
        publishComparisonUnavailable("currentPeriodIncomplete", detail);
      });
      render(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Refresh and compare again" }));
      await flush();
      expect(compareSpy).toHaveBeenCalledTimes(1);
      expect(status().textContent).toBe(`Comparison unavailable: ${detail}`);
    });

    it("does not reload for a files comparison", async () => {
      setFiles(coveringRecords());
      const refresh = vi.fn(async () => undefined);
      useEvtxStore.setState({ refreshLoadedChannels: refresh });
      const { rerender } = render(<Harness nowEpoch={ANCHOR} />);
      fireEvent.click(compareButton()!);
      await flush();
      rerender(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Compare again" }));
      expect(refresh).not.toHaveBeenCalled();
    });

    it("logs a failed reload and still lets the comparison say what it can", async () => {
      staleLive();
      const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      useEvtxStore.setState({
        refreshLoadedChannels: async () => {
          throw new Error("service unavailable");
        },
      });
      compareSpy.mockImplementation(async () => undefined);
      render(<Harness nowEpoch={ANCHOR + 3 * HOUR} />);
      await flush();
      fireEvent.click(screen.getByRole("button", { name: "Refresh and compare again" }));
      await flush();
      expect(warn).toHaveBeenCalled();
      warn.mockRestore();
    });
  });

  describe("entries the current period could not place", () => {
    it("withholds the delta and says why, whatever the previous period holds", async () => {
      setFiles(coveringRecords(), { sourceMode: "live", loadedChannels: new Set(["System"]) });
      useComparisonStore.setState({
        state: {
          phase: "settled",
          outcome: {
            status: "complete",
            result: {
              mode: "live",
              window: "24h",
              prior: priorFor(),
              anchorBasis: "load",
              counts: {
                total: 1,
                levels: { Critical: 0, Error: 1, Warning: 0, Information: 0, Verbose: 0 },
                channels: new Map([["System", 1]]),
                distinctEvents: new Set(["A\u00001"]),
              },
              gaps: [],
              notes: [],
              unplacedRecords: 0,
              unreadChannels: [],
              comparedChannels: ["System"],
              channelsWithGaps: [],
            },
          },
        },
      });
      // One more entry has no usable timestamp: the count placed it nowhere.
      useEvtxStore.setState({
        records: [...useEvtxStore.getState().records, fileRecord({ timestampEpoch: 0 })],
      });
      render(<Harness />);
      await flush();
      expect(errorsSublabel()).toBeNull();
      expect(status()).toHaveTextContent(
        "1 loaded entry has no usable timestamp or level and could not be placed in the current period, so no change is shown.",
      );
    });
  });
});
