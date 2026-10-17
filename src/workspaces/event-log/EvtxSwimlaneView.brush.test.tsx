import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { useUiStore } from "../../stores/ui-store";
import { installRecordingCanvas, type RecordingCanvases } from "./__fixtures__/recording-canvas";
import { EvtxFilterChips } from "./EvtxFilterChips";
import { EvtxHistogram } from "./EvtxHistogram";
import { DRAG_THRESHOLD_PX, EvtxSwimlaneView } from "./EvtxSwimlaneView";
import { buildHistogram } from "./evtx-histogram";
import { useEvtxLayoutStore, sanitizeLayout } from "./evtx-layout-store";
import { hitRadiusOf, hitTest, PLOT_INSET_PX } from "./evtx-swimlane-canvas";
import { buildSwimlanes, describeDot, describeLaneCell, laneHeightFor } from "./evtx-swimlanes";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS } from "./evtx-throttle";
import { formatTimeRange, timeRangeNeedsYear } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const FIRST = Date.UTC(2026, 9, 6, 10, 20, 0);
/** Plot left edge and bucket width in the stubbed layout: 72 buckets across 720 px. */
const LEFT = 100;
const PLOT_W = 720;
const BUCKET_PX = 10;
const LANE = 36;

let nextId = 1000;
const rec = (
  timestampEpoch: number,
  level: EvtxLevel = "Information",
  provider = "A",
  eventId = 1,
): EvtxRecord =>
  ({
    id: nextId++,
    eventRecordId: nextId,
    timestamp: "",
    timestampEpoch,
    provider,
    channel: "System",
    eventId,
    level,
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** One event per 20 minutes for a day, plus one at the end: 72 buckets of 20 minutes, in two lanes. */
const records: EvtxRecord[] = [
  ...Array.from({ length: 72 }, (_, i) =>
    rec(FIRST + i * 20 * MINUTE + 1000, i % 7 === 0 ? "Error" : "Information", i % 2 === 0 ? "A" : "B", 100 + i),
  ),
  rec(FIRST + DAY - 1, "Warning", "A", 99),
];
const histogram = buildHistogram(records, "utc");
const edge = (index: number) => histogram.edges[index];
const x = (bucket: number, offset = 4) => LEFT + bucket * BUCKET_PX + offset;
const rangeOf = (first: number, last: number) => ({ startMs: edge(first), endMs: edge(last + 1) });

const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);

let setTimeRangeSpy: ReturnType<typeof vi.fn>;
const realSetTimeRange = useEvtxStore.getState().setTimeRange;
let canvases: RecordingCanvases;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
  canvases = installRecordingCanvas();
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(
    () =>
      ({
        left: LEFT,
        top: 0,
        right: LEFT + PLOT_W,
        bottom: 200,
        width: PLOT_W,
        height: 200,
        x: LEFT,
        y: 0,
        toJSON: () => ({}),
      }) as DOMRect,
  );
  Object.defineProperty(window, "devicePixelRatio", { value: 1, configurable: true });
  setTimeRangeSpy = vi.fn(realSetTimeRange);
  useEvtxStore.setState({
    timeZoneMode: "utc",
    timeRange: null,
    recordScope: null,
    isLoading: false,
    selectedRecordId: null,
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
    setTimeRange: setTimeRangeSpy as typeof realSetTimeRange,
  });
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(() => {
  cleanup();
  canvases.restore();
  vi.restoreAllMocks();
  vi.useRealTimers();
  useEvtxStore.setState({ setTimeRange: realSetTimeRange, timeRange: null, isLoading: false, selectedRecordId: null });
});

/** The Timeline view's stack, as the workspace renders it: chips, histogram, lanes. */
const stack = (list: readonly EvtxRecord[], loading = false) => (
  <>
    <EvtxFilterChips visibleCount={list.length} loadedCount={list.length} />
    <EvtxHistogram records={list} loading={loading} />
    <EvtxSwimlaneView records={list} loading={loading} />
  </>
);

/**
 * The store's records for a list: the same objects, with ids that are their indexes, which is what the
 * store leaves after a merge. A click selects by id, and only a record the store holds under its id.
 */
function syncStore(list: readonly EvtxRecord[]) {
  list.forEach((record, index) => {
    record.id = index;
  });
  useEvtxStore.setState({ records: [...list] });
}

function mount(list: readonly EvtxRecord[] = records) {
  syncStore(list);
  const view = render(stack(list));
  return { ...view, ...sliders() };
}

const sliders = () => ({
  histogramSlider: screen.getByRole("slider", { name: "Time range" }),
  laneSlider: screen.getByRole("slider", { name: "Time range, by lane" }),
});

const down = (target: Element, clientX: number, clientY = 18, init: Record<string, unknown> = {}) =>
  fireEvent.pointerDown(target, { clientX, clientY, button: 0, buttons: 1, isPrimary: true, pointerId: 1, ...init });
const move = (target: Element, clientX: number, clientY = 18, buttons = 1) =>
  fireEvent.pointerMove(target, { clientX, clientY, buttons, pointerId: 1 });
const up = (target: Element, clientX: number, clientY = 18) =>
  fireEvent.pointerUp(target, { clientX, clientY, pointerId: 1 });
const key = (target: Element, name: string, init: Record<string, unknown> = {}) =>
  fireEvent.keyDown(target, { key: name, ...init });

const region = (name: "histogram" | "swimlanes") => document.querySelector<HTMLElement>(`[data-evtx-region="${name}"]`)!;
const layer = (name: "histogram" | "swimlanes", which: string) =>
  region(name).querySelector<HTMLElement>(`[data-evtx-layer="${which}"]`);
const edges = (name: "histogram" | "swimlanes") =>
  [...region(name).querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]')];
const percent = (value: string) => parseFloat(value);
const storeRange = () => useEvtxStore.getState().timeRange;
const seedRange = (range: { startMs: number; endMs: number } | null) =>
  act(() => {
    useEvtxStore.setState({ timeRange: range });
  });
const tooltip = () => document.querySelector<HTMLElement>('[data-evtx-region="swimlanes"] [data-evtx-tooltip]');
const cursorText = (name: "histogram" | "swimlanes") => region(name).querySelector<HTMLElement>("[data-evtx-cursor-text]");
const chipLabel = (startMs: number, endMs: number) =>
  `Time: brushed ${formatTimeRange(startMs, endMs, "utc", timeRangeNeedsYear(startMs, endMs, "utc", Date.now()))}`;

/** Where a dot of the lanes is on screen. */
function dotPoint(list: readonly EvtxRecord[], lane: number, dot: number) {
  const scene = buildSwimlanes(list, "provider", "utc");
  const fraction = scene.lanes[lane].fractions[dot];
  return {
    record: scene.lanes[lane].records[dot],
    level: scene.lanes[lane].records[dot].level,
    x: LEFT + fraction * PLOT_W,
    y: lane * LANE + LANE / 2,
  };
}

const subjects = [
  { name: "histogram" as const, label: "Time range" },
  { name: "swimlanes" as const, label: "Time range, by lane" },
];

/**
 * The histogram's gestures, run against both figures with the same code. A lane drag sets the same
 * criterion as a histogram drag over the same x (spec 9), and the keyboard, Escape and load rules
 * are the same rules.
 */
describe.each(subjects)("$name brush", ({ name, label }) => {
  const slider = () => screen.getByRole("slider", { name: label });

  it("draws a draft while dragging and sets the range once, on release, from whole buckets", () => {
    mount();
    down(slider(), x(3));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    move(slider(), x(5));
    move(slider(), x(7));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toBeNull();
    const draft = layer(name, "wash")!;
    expect(draft.dataset.evtxDraft).toBe("true");
    expect(percent(draft.style.left)).toBeCloseTo((3 / 72) * 100, 6);
    expect(percent(draft.style.right)).toBeCloseTo(((72 - 8) / 72) * 100, 6);
    expect(edges(name).every((el) => el.style.borderLeft.includes("dashed"))).toBe(true);

    up(slider(), x(7));
    expect(setTimeRangeSpy).toHaveBeenCalledTimes(1);
    expect(setTimeRangeSpy).toHaveBeenCalledWith(rangeOf(3, 7));
    expect(storeRange()).toEqual(rangeOf(3, 7));
    expect(layer(name, "wash")!.dataset.evtxDraft).toBe("false");
    expect(edges(name).every((el) => el.style.borderLeft.includes("solid"))).toBe(true);
  });

  it("gives the same range dragged right to left, and clamps a drag that leaves the plot", () => {
    mount();
    down(slider(), x(7));
    move(slider(), x(3));
    up(slider(), x(3));
    expect(storeRange()).toEqual(rangeOf(3, 7));
    down(slider(), x(5));
    move(slider(), LEFT - 50);
    up(slider(), LEFT - 50);
    expect(storeRange()).toEqual(rangeOf(0, 5));
    down(slider(), x(60));
    move(slider(), LEFT + PLOT_W + 80);
    up(slider(), LEFT + PLOT_W + 80);
    expect(storeRange()).toEqual(rangeOf(60, 71));
  });

  it("shows the draft alone over an applied range, so the wash is never twice as opaque as solved", () => {
    mount();
    seedRange(rangeOf(30, 40));
    down(slider(), x(3));
    move(slider(), x(8));
    expect(region(name).querySelectorAll('[data-evtx-layer="wash"]')).toHaveLength(1);
    expect(layer(name, "wash")!.dataset.evtxDraft).toBe("true");
    expect(percent(layer(name, "wash")!.style.left)).toBeCloseTo((3 / 72) * 100, 6);
  });

  it("makes the Time chip appear with the range it set", () => {
    mount();
    down(slider(), x(3));
    move(slider(), x(7));
    up(slider(), x(7));
    const range = rangeOf(3, 7);
    expect(screen.getByText(chipLabel(range.startMs, range.endMs))).toBeInTheDocument();
  });

  it("freezes what a drag began on while a live tail regrids the chart", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender } = mount();
    down(slider(), x(3));
    const grown = [...records, rec(FIRST + 5 * DAY, "Error", "A")];
    rerender(stack(grown));
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    move(slider(), x(7));
    up(slider(), x(7));
    expect(storeRange()).toEqual(rangeOf(3, 7));
  });

  it("anchors under the pointer on the grid a pending keyboard selection froze, not the regridded chart", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender } = mount();
    fireEvent.focus(slider());
    key(slider(), "ArrowLeft", { shiftKey: true });
    const grown = [...records, rec(FIRST + 5 * DAY, "Error", "A")];
    expect(buildHistogram(grown, "utc").buckets.length).not.toBe(72);
    rerender(stack(grown));
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    // A drag from mid-plot on the 72 buckets still on screen: press at bucket 36, move to 40.
    down(slider(), LEFT + 360);
    move(slider(), LEFT + 400);
    up(slider(), LEFT + 400);
    expect(storeRange()).toEqual(rangeOf(36, 40));
  });

  it("sets nothing when the pointer is cancelled or loses capture, or the button was released outside", () => {
    mount();
    down(slider(), x(3));
    move(slider(), x(8));
    fireEvent.pointerCancel(slider(), { pointerId: 1 });
    expect(layer(name, "wash")).toBeNull();
    down(slider(), x(3));
    move(slider(), x(8));
    fireEvent.lostPointerCapture(slider(), { pointerId: 1 });
    up(slider(), x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    down(slider(), x(3));
    move(slider(), x(6), 18, 0);
    expect(layer(name, "wash")).toBeNull();
    up(slider(), x(6));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  it("cancels a drag with Escape and spends the key, so the applied range survives", () => {
    mount();
    seedRange(rangeOf(30, 33));
    down(slider(), x(3));
    move(slider(), x(8));
    expect(key(slider(), "Escape")).toBe(false);
    expect(layer(name, "wash")!.dataset.evtxDraft).toBe("false");
    up(slider(), x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toEqual(rangeOf(30, 33));
  });

  it("draws nothing and sets nothing when a load starts before the release", () => {
    const { rerender } = mount();
    down(slider(), x(3));
    move(slider(), x(8));
    expect(layer(name, "wash")!.dataset.evtxDraft).toBe("true");
    act(() => {
      useEvtxStore.setState({ isLoading: true });
    });
    rerender(stack([], true));
    expect(layer(name, "wash")).toBeNull();
    up(slider(), x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  describe("the keyboard", () => {
    it("is one slider, starting at the newest bucket", () => {
      mount();
      expect(slider()).toHaveAttribute("aria-valuemin", "0");
      expect(slider()).toHaveAttribute("aria-valuemax", "71");
      expect(slider()).toHaveAttribute("aria-valuenow", "71");
      expect(slider().getAttribute("tabindex")).toBe("0");
    });

    it("moves a one-bucket cursor with the arrows, Home and End", () => {
      mount();
      fireEvent.focus(slider());
      key(slider(), "ArrowLeft");
      key(slider(), "ArrowLeft");
      expect(slider()).toHaveAttribute("aria-valuenow", "69");
      key(slider(), "Home");
      expect(slider()).toHaveAttribute("aria-valuenow", "0");
      key(slider(), "ArrowLeft");
      expect(slider()).toHaveAttribute("aria-valuenow", "0");
      key(slider(), "End");
      expect(slider()).toHaveAttribute("aria-valuenow", "71");
    });

    it("extends a draft with Shift, then Enter applies it", () => {
      mount();
      fireEvent.focus(slider());
      key(slider(), "ArrowLeft");
      key(slider(), "ArrowLeft", { shiftKey: true });
      key(slider(), "ArrowLeft", { shiftKey: true });
      expect(layer(name, "wash")!.dataset.evtxDraft).toBe("true");
      expect(setTimeRangeSpy).not.toHaveBeenCalled();
      key(slider(), "Enter");
      expect(storeRange()).toEqual(rangeOf(68, 70));
    });

    it("applies the one bucket under the cursor on Enter, and clears it on the second Enter", () => {
      mount();
      fireEvent.focus(slider());
      key(slider(), "Home");
      key(slider(), "Enter");
      expect(storeRange()).toEqual(rangeOf(0, 0));
      key(slider(), "Enter");
      expect(storeRange()).toBeNull();
    });

    it("adjusts an applied range from the bucket at one of its ends", () => {
      mount();
      seedRange(rangeOf(10, 14));
      fireEvent.focus(slider());
      expect(slider()).toHaveAttribute("aria-valuenow", "14");
      key(slider(), "ArrowRight", { shiftKey: true });
      key(slider(), "Enter");
      expect(storeRange()).toEqual(rangeOf(10, 15));
    });

    it("takes Escape for a pending selection first, and passes it up to clear the range second", () => {
      mount();
      seedRange(rangeOf(10, 14));
      fireEvent.focus(slider());
      key(slider(), "ArrowRight", { shiftKey: true });
      expect(layer(name, "wash")!.dataset.evtxDraft).toBe("true");
      // The first Escape cancels the draft and is spent (preventDefault), so the workspace's window
      // handler, which skips a key that was already handled, leaves the applied range alone.
      expect(key(slider(), "Escape")).toBe(false);
      expect(storeRange()).toEqual(rangeOf(10, 14));
      expect(layer(name, "wash")!.dataset.evtxDraft).toBe("false");
      // The second has nothing pending, is not prevented, and reaches that handler.
      expect(key(slider(), "Escape")).toBe(true);
    });

    it("ignores keys with Control, Alt or Meta", () => {
      mount();
      fireEvent.focus(slider());
      key(slider(), "ArrowLeft", { ctrlKey: true });
      key(slider(), "ArrowLeft", { altKey: true });
      key(slider(), "ArrowLeft", { metaKey: true });
      expect(slider()).toHaveAttribute("aria-valuenow", "71");
    });

    it("drops a pending selection and the cursor when focus leaves", () => {
      mount();
      fireEvent.focus(slider());
      key(slider(), "ArrowLeft", { shiftKey: true });
      fireEvent.blur(slider());
      expect(layer(name, "cursor")).toBeNull();
      expect(layer(name, "wash")).toBeNull();
      expect(setTimeRangeSpy).not.toHaveBeenCalled();
    });

    it("freezes a pending selection while a tail regrids the chart", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const { rerender } = mount();
      fireEvent.focus(slider());
      key(slider(), "ArrowLeft", { shiftKey: true });
      rerender(stack([...records, rec(FIRST + 5 * DAY, "Error", "A")]));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      key(slider(), "Enter");
      expect(storeRange()).toEqual(rangeOf(70, 71));
    });
  });

  describe("focus modality", () => {
    it("shows no cursor text when a pointer press focused the plot, and shows it after the next key", () => {
      mount();
      down(slider(), x(9));
      act(() => {
        slider().focus();
      });
      up(slider(), x(9));
      expect(cursorText(name)).toBeNull();
      key(slider(), "ArrowLeft");
      expect(cursorText(name)).not.toBeNull();
    });

    it("shows the cursor text on Tab focus, and it goes when focus leaves", () => {
      mount();
      fireEvent.focus(slider());
      expect(cursorText(name)).not.toBeNull();
      fireEvent.blur(slider());
      expect(cursorText(name)).toBeNull();
    });

    it("does not let a finished press mark a later focus event as the pointer's", () => {
      mount();
      down(slider(), x(9));
      up(slider(), x(9));
      fireEvent.focus(slider());
      expect(cursorText(name)).not.toBeNull();
    });
  });

  describe("a load", () => {
    it("keeps the plot focusable and aria-disabled while loading, and usable again afterwards", () => {
      const { rerender } = mount();
      act(() => {
        slider().focus();
      });
      rerender(stack([], true));
      expect(slider().getAttribute("tabindex")).toBe("0");
      expect(slider()).toHaveAttribute("aria-disabled", "true");
      expect(document.activeElement).toBe(slider());
      key(slider(), "ArrowLeft");
      key(slider(), "Enter");
      expect(setTimeRangeSpy).not.toHaveBeenCalled();
      rerender(stack(records));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(slider()).not.toHaveAttribute("aria-disabled", "true");
      expect(document.activeElement).toBe(slider());
      expect(slider()).toHaveAttribute("aria-valuenow", "71");
    });

    it("counts a press during a load as the pointer's: no cursor line once the load ends", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const { rerender } = render(stack([], true));
      down(slider(), 10);
      act(() => {
        slider().focus();
      });
      up(slider(), 10);
      rerender(stack(records));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(slider()).toHaveAttribute("aria-valuenow", "71");
      expect(cursorText(name)).toBeNull();
    });

    it("shows no stale grid and commits none after a load, when a Shift selection was pending", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const { rerender } = render(stack(records));
      act(() => {
        slider().focus();
      });
      key(slider(), "ArrowLeft", { shiftKey: true });
      expect(layer(name, "wash")!.dataset.evtxDraft).toBe("true");
      rerender(stack([], true));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      const reloaded = [...records, rec(FIRST + 5 * DAY, "Error", "A")];
      const fresh = buildHistogram(reloaded, "utc");
      rerender(stack(reloaded));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(layer(name, "wash")).toBeNull();
      expect(slider().getAttribute("aria-valuetext")).not.toMatch(/selecting/);
      key(slider(), "Enter");
      const last = fresh.buckets.length - 1;
      expect(storeRange()).toEqual({ startMs: fresh.edges[last], endMs: fresh.edges[last + 1] });
    });
  });
});

describe("a lane drag and a histogram drag over the same x set one criterion", () => {
  const drags: [string, number, number][] = [
    ["a few buckets", x(3), x(7)],
    ["right to left", x(40), x(12)],
    ["one bucket wide", x(5, 1), x(5, 8)],
    ["off the left edge", x(10), LEFT - 90],
    ["off the right edge", x(65), LEFT + PLOT_W + 90],
    ["the whole plot", LEFT + 1, LEFT + PLOT_W - 1],
  ];

  it.each(drags)("%s", (_, from, to) => {
    mount();
    const dragOn = (target: Element) => {
      act(() => useEvtxStore.setState({ timeRange: null }));
      down(target, from);
      move(target, (from + to) / 2);
      move(target, to);
      up(target, to);
      return storeRange();
    };
    const { histogramSlider, laneSlider } = sliders();
    const viaHistogram = dragOn(histogramSlider);
    const viaLanes = dragOn(laneSlider);
    expect(viaLanes).toEqual(viaHistogram);
    expect(viaLanes).not.toBeNull();
  });

  // A drag over an applied range: the one place the commit differs from setting the dragged buckets.
  // A drag that covers exactly the one bucket that is the whole applied range clears it (the second
  // click on the sole active ID does the same); every other drag sets what it covers.
  type AppliedCase = [string, [number, number], number, number, [number, number] | null];
  const overApplied: AppliedCase[] = [
    ["a single bucket applied, dragged within that bucket: clears it", [5, 5], x(5, 1), x(5, 8), null],
    ["a single bucket applied, dragged within another bucket: sets that one", [5, 5], x(6, 1), x(6, 8), [6, 6]],
    ["a single bucket applied, dragged over several buckets: sets them", [5, 5], x(3), x(7), [3, 7]],
    ["a single bucket applied, dragged over it and its neighbours: sets them", [5, 5], x(4, 1), x(6, 8), [4, 6]],
    ["several buckets applied, dragged over exactly them: keeps them", [10, 20], x(10, 1), x(20, 8), [10, 20]],
    ["several buckets applied, dragged within one of them: sets that one", [10, 20], x(12, 1), x(12, 8), [12, 12]],
    ["several buckets applied, dragged elsewhere: sets the dragged buckets", [10, 20], x(3), x(7), [3, 7]],
  ];

  it.each(overApplied)("%s", (_, applied, from, to, expected) => {
    mount();
    const dragOn = (target: Element) => {
      seedRange(rangeOf(applied[0], applied[1]));
      down(target, from);
      move(target, (from + to) / 2);
      move(target, to);
      up(target, to);
      return storeRange();
    };
    const { histogramSlider, laneSlider } = sliders();
    const viaHistogram = dragOn(histogramSlider);
    const viaLanes = dragOn(laneSlider);
    expect(viaLanes).toEqual(viaHistogram);
    expect(viaLanes).toEqual(expected === null ? null : rangeOf(expected[0], expected[1]));
  });

  it.each([
    ["Shift selection", ["ArrowLeft", "ArrowLeft", "S:ArrowLeft", "S:ArrowLeft", "S:ArrowLeft", "Enter"]],
    ["Home, then Shift+End", ["Home", "S:End", "Enter"]],
    ["one bucket, applied and cleared", ["Home", "ArrowRight", "Enter", "Enter"]],
    ["a cancelled draft", ["ArrowLeft", "S:ArrowLeft", "Escape", "Enter"]],
  ])("%s by keyboard", (_, sequence) => {
    mount();
    const run = (target: Element) => {
      act(() => useEvtxStore.setState({ timeRange: null }));
      fireEvent.focus(target);
      const prevented: boolean[] = [];
      for (const step of sequence) {
        const shift = step.startsWith("S:");
        prevented.push(key(target, shift ? step.slice(2) : step, { shiftKey: shift }));
      }
      fireEvent.blur(target);
      return { range: storeRange(), prevented };
    };
    const { histogramSlider, laneSlider } = sliders();
    const viaHistogram = run(histogramSlider);
    const viaLanes = run(laneSlider);
    expect(viaLanes).toEqual(viaHistogram);
  });
});

describe("clicking a dot", () => {
  const pick = (lane = 0, dot = 3) => dotPoint(records, lane, dot);

  it("selects the record, switches the rail to Details and shows a hidden rail", () => {
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(true);
  });

  it("leaves the time range alone: no range is set, and an applied one is kept", () => {
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toBeNull();

    seedRange(rangeOf(30, 33));
    const other = pick(1, 5);
    down(laneSlider, other.x, other.y);
    up(laneSlider, other.x, other.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(other.record.id);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toEqual(rangeOf(30, 33));
  });

  it("does nothing on empty lane space: no selection, no range, no toggle of a bucket", () => {
    const { laneSlider } = mount();
    seedRange(rangeOf(30, 33));
    useEvtxStore.setState({ selectedRecordId: 7 });
    // Lane 0 is at y 18; this is the middle of the gap between the first two dots, far from both.
    const between = (pick(0, 3).x + pick(0, 4).x) / 2;
    expect(hitTest(buildSwimlanes(records, "provider", "utc"), { plotWidth: PLOT_W, laneHeight: LANE }, between - LEFT + PLOT_INSET_PX, 18)).toBeNull();
    down(laneSlider, between, 18);
    up(laneSlider, between, 18);
    expect(useEvtxStore.getState().selectedRecordId).toBe(7);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toEqual(rangeOf(30, 33));
  });

  it("hits within 4 px of a dot's edge and not 4.5 px", () => {
    const { laneSlider } = mount();
    const target = pick(0, 3);
    const reach = hitRadiusOf(target.level) + 4;
    down(laneSlider, target.x + reach, target.y);
    up(laneSlider, target.x + reach, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
    useEvtxStore.setState({ selectedRecordId: null });
    down(laneSlider, target.x + reach + 0.5, target.y);
    up(laneSlider, target.x + reach + 0.5, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });

  it("is still a click when the pointer moves 2 px, and a brush at 3 px", () => {
    // The numbers are written out: the threshold is the line between a click and a brush.
    expect(DRAG_THRESHOLD_PX).toBe(3);
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    move(laneSlider, target.x + 2, target.y);
    up(laneSlider, target.x + 2, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();

    useEvtxStore.setState({ selectedRecordId: null });
    down(laneSlider, target.x, target.y);
    move(laneSlider, target.x + 3, target.y);
    up(laneSlider, target.x + 3, target.y);
    expect(setTimeRangeSpy).toHaveBeenCalledTimes(1);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });

  it("selects nothing when a press on a dot becomes a drag", () => {
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    move(laneSlider, target.x + 60, target.y);
    up(laneSlider, target.x + 60, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(storeRange()).not.toBeNull();
  });

  it("reads the record's id when the click happens: the store renumbers ids in place", () => {
    const { laneSlider } = mount();
    const target = pick(1, 4);
    const before = target.record.id;
    // A merge: the same objects, in another order, with the ids their new indexes give them.
    const merged = [...useEvtxStore.getState().records].reverse();
    merged.forEach((record, index) => {
      record.id = index;
    });
    act(() => {
      useEvtxStore.setState({ records: merged });
    });
    expect(target.record.id).not.toBe(before);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
  });

  it("still selects a dot after the store dropped other records and left the ids as they were", () => {
    // A channel cleared or re-read removes records without renumbering the rest until the next merge.
    const { laneSlider } = mount();
    const dropped = useEvtxStore.getState().records.filter((_, index) => index !== 2);
    act(() => {
      useEvtxStore.setState({ records: dropped });
    });
    const target = pick(1, 5);
    expect(target.record.id).toBeGreaterThan(2);
    expect(dropped[target.record.id]).not.toBe(target.record);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
  });

  it("ignores the secondary button, a non-primary pointer and a release with no press", () => {
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y, { button: 2 });
    up(laneSlider, target.x, target.y);
    down(laneSlider, target.x, target.y, { isPrimary: false });
    up(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });

  it("selects nothing while a load runs", () => {
    const { rerender } = mount();
    const target = pick(0, 3);
    rerender(stack([], true));
    const laneSlider = screen.getByRole("slider", { name: "Time range, by lane" });
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });

  it("rings the selected dot where it is drawn, and drops the ring when the record is not charted", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender, laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    const ring = region("swimlanes").querySelector<HTMLElement>('[data-evtx-layer="selected"]')!;
    expect(ring).toHaveAttribute("aria-hidden", "true");
    const scene = buildSwimlanes(records, "provider", "utc");
    expect(percent(ring.style.left)).toBeCloseTo(scene.lanes[0].fractions[3] * 100, 6);
    expect(percent(ring.style.top)).toBe(LANE / 2);
    expect(ring.style.border).toContain("var(--colorPaletteBlueForeground2)");
    const without = records.filter((record) => record !== target.record);
    rerender(stack(without));
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    expect(region("swimlanes").querySelector('[data-evtx-layer="selected"]')).toBeNull();
  });

  describe.each([720.49, 720.6])("on a fractional layout, the plot measuring %s px", (measured) => {
    /** The canvas is drawn on the rounded width. */
    const drawn = Math.round(measured);
    const fractional = () =>
      vi.mocked(HTMLElement.prototype.getBoundingClientRect).mockImplementation(
        () =>
          ({
            left: LEFT,
            top: 0,
            right: LEFT + measured,
            bottom: 200,
            width: measured,
            height: 200,
            x: LEFT,
            y: 0,
            toJSON: () => ({}),
          }) as DOMRect,
      );
    const lastErrorOfLaneA = () => {
      const lane = buildSwimlanes(records, "provider", "utc").lanes[0];
      const dot = lane.records.map((record) => record.level).lastIndexOf("Error");
      return { record: lane.records[dot], plotX: lane.fractions[dot] * drawn, y: LANE / 2 };
    };

    it("hits on the geometry the canvas drew, to the pixel, at the far end of the plot", () => {
      fractional();
      const { laneSlider } = mount();
      const target = lastErrorOfLaneA();
      expect(target.plotX).toBeGreaterThan(600);
      // 4.5 px of radius and 4 px of slop is 8.5 px from the drawn centre; 8.7 is just outside it and
      // 8.3 just inside. The sub-pixel width, or a floored one, puts the centre 0.5 to 1 px away.
      down(laneSlider, LEFT + target.plotX + 8.7, target.y);
      up(laneSlider, LEFT + target.plotX + 8.7, target.y);
      expect(useEvtxStore.getState().selectedRecordId).toBeNull();
      down(laneSlider, LEFT + target.plotX + 8.3, target.y);
      up(laneSlider, LEFT + target.plotX + 8.3, target.y);
      expect(useEvtxStore.getState().selectedRecordId).toBe(target.record.id);
    });

    it("selects the dot on the very last instant when the click is on the plot's right edge", () => {
      fractional();
      const { laneSlider } = mount();
      const scene = buildSwimlanes(records, "provider", "utc");
      const lane = scene.lanes[0];
      const last = lane.count - 1;
      expect(lane.fractions[last]).toBeCloseTo(1, 1);
      down(laneSlider, LEFT + measured, LANE / 2);
      up(laneSlider, LEFT + measured, LANE / 2);
      expect(useEvtxStore.getState().selectedRecordId).toBe(lane.records[last].id);
    });
  });

  it("takes focus for the plot, as a press on the histogram does", () => {
    const { laneSlider } = mount();
    const target = pick(0, 3);
    down(laneSlider, target.x, target.y);
    expect(document.activeElement).toBe(laneSlider);
    up(laneSlider, target.x, target.y);
  });
});

describe("hovering a dot", () => {
  const point = () => dotPoint(records, 0, 3);

  it("shows the dot's own words in a tooltip, and drops it when the pointer leaves", () => {
    const { laneSlider } = mount();
    const target = point();
    move(laneSlider, target.x + 2, target.y, 0);
    expect(tooltip()).toHaveTextContent(describeDot(target.record, "utc", 0));
    expect(region("swimlanes").querySelector('[data-evtx-layer="hover"]')).not.toBeNull();
    fireEvent.pointerLeave(laneSlider);
    expect(tooltip()).toBeNull();
    expect(region("swimlanes").querySelector('[data-evtx-layer="hover"]')).toBeNull();
  });

  /** Midway between two neighbouring dots of the first lane: further than the slop from both. */
  const gap = () => (dotPoint(records, 0, 3).x + dotPoint(records, 0, 4).x) / 2;

  it("shows nothing over empty lane space", () => {
    const { laneSlider } = mount();
    const target = point();
    move(laneSlider, target.x + 2, target.y, 0);
    expect(tooltip()).not.toBeNull();
    move(laneSlider, gap(), target.y, 0);
    expect(tooltip()).toBeNull();
  });

  it("says how many other events sit within the slop of the pointer", () => {
    const crowded = [...records, rec(records[3].timestampEpoch + 1, "Error", records[3].provider, 5), rec(records[3].timestampEpoch + 2, "Error", records[3].provider, 6)];
    const { laneSlider } = mount(crowded);
    const target = dotPoint(crowded, 0, 0);
    // Aim at the densest dot: the first record of lane A's third dot cluster.
    const scene = buildSwimlanes(crowded, "provider", "utc");
    const cluster = scene.lanes[0].records.findIndex((record) => record.timestampEpoch === records[3].timestampEpoch + 1);
    void target;
    const at = dotPoint(crowded, 0, cluster);
    move(laneSlider, at.x, at.y, 0);
    expect(tooltip()!.textContent).toMatch(/\+\d+ more within 4 px/);
  });

  it("is never the only carrier: it is hidden from assistive technology and is no role=tooltip", () => {
    const { laneSlider } = mount();
    const target = point();
    move(laneSlider, target.x, target.y, 0);
    expect(tooltip()).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("lets Escape through to clear the range while a tooltip is showing, or the cursor text", () => {
    const { laneSlider } = mount();
    seedRange(rangeOf(10, 14));
    const target = point();
    move(laneSlider, target.x, target.y, 0);
    expect(tooltip()).not.toBeNull();
    expect(key(laneSlider, "Escape")).toBe(true);
    expect(key(document.body, "Escape")).toBe(true);
    fireEvent.pointerLeave(laneSlider);
    fireEvent.focus(laneSlider);
    expect(cursorText("swimlanes")).not.toBeNull();
    expect(key(laneSlider, "Escape")).toBe(true);
  });

  it("changes the mouse cursor to a pointer over a dot, and back", () => {
    const { laneSlider } = mount();
    const before = laneSlider.className;
    const target = point();
    move(laneSlider, target.x, target.y, 0);
    expect(laneSlider.className).not.toBe(before);
    move(laneSlider, gap(), target.y, 0);
    expect(laneSlider.className).toBe(before);
  });

  it("puts a first-lane tooltip below its dot, where there is room", () => {
    const { laneSlider } = mount();
    const target = point();
    move(laneSlider, target.x, target.y, 0);
    expect(tooltip()!.style.transform).toContain("translateY(12px)");
  });
});

describe("the lane cursor", () => {
  it("names the lane and bucket the cursor is on, as the slider's value text", () => {
    const { laneSlider } = mount();
    const scene = buildSwimlanes(records, "provider", "utc");
    const bucket = scene.axis.buckets[71];
    expect(laneSlider).toHaveAttribute(
      "aria-valuetext",
      describeLaneCell(scene.lanes[0], bucket.startMs, bucket.endMs, "utc", scene.axis.showYear),
    );
    expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("A, ")).toBe(true);
  });

  it("moves between lanes with Up and Down, and stops at the first and last", () => {
    const { laneSlider } = mount();
    fireEvent.focus(laneSlider);
    const lane = () => laneSlider.getAttribute("aria-valuetext")!.split(", ")[0];
    expect(lane()).toBe("A");
    key(laneSlider, "ArrowDown");
    expect(lane()).toBe("B");
    key(laneSlider, "ArrowDown");
    expect(lane()).toBe("B");
    key(laneSlider, "ArrowUp");
    key(laneSlider, "ArrowUp");
    expect(lane()).toBe("A");
    const outline = layer("swimlanes", "cursor")!;
    expect(outline.style.top).toBe("0px");
    key(laneSlider, "ArrowDown");
    expect(layer("swimlanes", "cursor")!.style.top).toBe(`${LANE}px`);
    expect(layer("swimlanes", "cursor")!.style.height).toBe(`${LANE}px`);
  });

  describe("while a live tail re-ranks the lanes", () => {
    const at = (hours: number, provider: string, level: EvtxLevel = "Information") =>
      rec(FIRST + hours * HOUR, level, provider);
    // first 5 events, second 3 (the newest event overall is its), third 2: lanes first, second, third.
    const start = () => [
      ...[0, 1, 2, 3, 4].map((h) => at(h, "first")),
      ...[1, 3, 5].map((h) => at(h, "second", h === 5 ? "Error" : "Information")),
      ...[0, 2].map((h) => at(h, "third")),
    ];
    // third gains four events inside the same span: third 6, first 5, second 3.
    const grown = (list: EvtxRecord[]) => [...list, ...[0.5, 1.5, 2.5, 3.5].map((h) => at(h, "third"))];
    const labels = () =>
      [...region("swimlanes").querySelectorAll<HTMLElement>("[data-evtx-lane]")].map((li) => li.children[0].textContent);

    it("holds the cursor on the lane it was moved to, and selects from that lane's cell", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const list = start();
      const { laneSlider, rerender } = mount(list);
      expect(labels()).toEqual(["first", "second", "third"]);
      fireEvent.focus(laneSlider);
      key(laneSlider, "ArrowDown");
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("second, ")).toBe(true);

      const next = grown(list);
      syncStore(next);
      rerender(stack(next));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      // Second now ranks third, in row 2, and the cursor went with it.
      expect(labels()).toEqual(["third", "first", "second"]);
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("second, ")).toBe(true);
      expect(layer("swimlanes", "cursor")!.style.top).toBe(`${2 * LANE}px`);
      key(laneSlider, " ");
      // The newest event overall is second's, in the newest bucket the cursor started on.
      expect(useEvtxStore.getState().selectedRecordId).toBe(list[7].id);
    });

    it("moves on from where it is after a re-rank, by one lane", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const list = start();
      const { laneSlider, rerender } = mount(list);
      fireEvent.focus(laneSlider);
      key(laneSlider, "ArrowDown");
      rerender(stack(grown(list)));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      key(laneSlider, "ArrowUp");
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("first, ")).toBe(true);
    });

    it("binds a cursor that was never moved to the lane it started on", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const list = start();
      const { laneSlider, rerender } = mount(list);
      fireEvent.focus(laneSlider);
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("first, ")).toBe(true);
      rerender(stack(grown(list)));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(labels()).toEqual(["third", "first", "second"]);
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("first, ")).toBe(true);
    });

    it("falls back to the clamped row only when the lane is gone", () => {
      vi.useFakeTimers({ now: PINNED_NOW });
      const list = start();
      const { laneSlider, rerender } = mount(list);
      fireEvent.focus(laneSlider);
      key(laneSlider, "ArrowDown");
      key(laneSlider, "ArrowDown");
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("third, ")).toBe(true);
      rerender(stack(list.filter((record) => record.provider !== "third")));
      act(() => {
        vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
      });
      expect(labels()).toEqual(["first", "second"]);
      // Row 2 no longer exists: the cursor is on the last row, and then follows that lane.
      expect(laneSlider.getAttribute("aria-valuetext")!.startsWith("second, ")).toBe(true);
      expect(layer("swimlanes", "cursor")!.style.top).toBe(`${LANE}px`);
    });
  });

  it("keeps the bucket when it changes lane", () => {
    const { laneSlider } = mount();
    fireEvent.focus(laneSlider);
    key(laneSlider, "ArrowLeft");
    key(laneSlider, "ArrowDown");
    expect(laneSlider).toHaveAttribute("aria-valuenow", "70");
  });

  it("shows the cell's words inline in the caption while the keyboard has focus", () => {
    const { laneSlider } = mount();
    fireEvent.focus(laneSlider);
    expect(cursorText("swimlanes")!.textContent).toBe(laneSlider.getAttribute("aria-valuetext"));
  });

  it("selects the most severe event in the cell with Space, earliest on a tie, and shows it in Details", () => {
    const base = Date.UTC(2026, 9, 6, 12, 0, 0);
    const crowded = [
      rec(base, "Information", "A", 1),
      rec(base + 1000, "Error", "A", 2),
      rec(base + 2000, "Error", "A", 3),
      rec(base + 3000, "Warning", "A", 4),
      rec(base + 6 * HOUR, "Information", "A", 5),
    ];
    useEvtxLayoutStore.setState({ panels: { channels: true, insights: false, dock: false } });
    const { laneSlider } = mount(crowded);
    const scene = buildSwimlanes(crowded, "provider", "utc");
    const index = scene.axis.buckets.findIndex((bucket) => bucket.startMs <= base && base < bucket.endMs);
    fireEvent.focus(laneSlider);
    key(laneSlider, "Home");
    for (let step = 0; step < index; step += 1) key(laneSlider, "ArrowRight");
    expect(key(laneSlider, " ")).toBe(false);
    expect(useEvtxStore.getState().selectedRecordId).toBe(crowded[1].id);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(true);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  it("selects nothing with Space in an empty cell", () => {
    const { laneSlider } = mount([rec(FIRST, "Error", "A"), rec(FIRST + 6 * HOUR, "Error", "A")]);
    fireEvent.focus(laneSlider);
    const scene = buildSwimlanes([rec(FIRST), rec(FIRST + 6 * HOUR)], "provider", "utc");
    key(laneSlider, "Home");
    key(laneSlider, "ArrowRight");
    key(laneSlider, "ArrowRight");
    expect(scene.axis.buckets.length).toBeGreaterThan(5);
    key(laneSlider, " ");
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
  });
});

describe("the whole scene is frozen during a drag", () => {
  it("keeps the lane order a drag began with, though a tail would reorder the top 12", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const start = [
      ...Array.from({ length: 5 }, (_, i) => rec(FIRST + i * HOUR, "Information", "first")),
      ...Array.from({ length: 2 }, (_, i) => rec(FIRST + i * HOUR, "Information", "second")),
    ];
    const { rerender, laneSlider } = mount(start);
    const labels = () =>
      [...region("swimlanes").querySelectorAll<HTMLElement>("[data-evtx-lane]")].map((li) => li.children[0].textContent);
    expect(labels()).toEqual(["first", "second"]);
    const scene = buildSwimlanes(start, "provider", "utc");
    const edgeOf = (index: number) => scene.axis.edges[index];
    down(laneSlider, LEFT + 20);
    move(laneSlider, LEFT + 80);
    // The tail appends more "second" events, inside the same span: the live ranking flips.
    const grown = [...start, ...Array.from({ length: 6 }, (_, i) => rec(FIRST + i * 30 * MINUTE + 5, "Information", "second"))];
    rerender(stack(grown));
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    expect(labels()).toEqual(["first", "second"]);
    up(laneSlider, LEFT + 80);
    const count = scene.axis.buckets.length;
    const first = Math.floor((20 / PLOT_W) * count);
    const last = Math.floor((80 / PLOT_W) * count);
    expect(storeRange()).toEqual({ startMs: edgeOf(first), endMs: edgeOf(last + 1) });
    expect(labels()).toEqual(["second", "first"]);
  });
});

describe("a press whose capture is lost before the release", () => {
  it("is no click, and lets go of the scene it held", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const start = [
      ...Array.from({ length: 5 }, (_, i) => rec(FIRST + i * HOUR, "Information", "first")),
      ...Array.from({ length: 2 }, (_, i) => rec(FIRST + i * HOUR, "Information", "second")),
    ];
    const { rerender, laneSlider } = mount(start);
    const labels = () =>
      [...region("swimlanes").querySelectorAll<HTMLElement>("[data-evtx-lane]")].map((li) => li.children[0].textContent);
    const target = dotPoint(start, 0, 2);
    down(laneSlider, target.x, target.y);
    const grown = [...start, ...Array.from({ length: 6 }, (_, i) => rec(FIRST + i * 30 * MINUTE + 5, "Information", "second"))];
    rerender(stack(grown));
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    // Held while the press is down, as a drag would hold it.
    expect(labels()).toEqual(["first", "second"]);
    fireEvent.lostPointerCapture(laneSlider, { pointerId: 1 });
    expect(labels()).toEqual(["second", "first"]);
    up(laneSlider, target.x, target.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });
});

describe("a reload that finishes inside the throttle window", () => {
  const settle = () =>
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
  /** A second load: other objects with the same small ids (their indexes), and the old scene still on screen. */
  function reloadWithinTheWindow(rerender: (ui: React.ReactElement) => void) {
    const fresh = records.map((record) => ({ ...record }));
    // The load starts (records empty, loading) and ends before the 75 ms timer fires.
    rerender(stack([], true));
    syncStore(fresh);
    rerender(stack(fresh));
    return fresh;
  }

  it("selects nothing when an old dot is clicked, and the new set's dot once the scene catches up", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { laneSlider, rerender } = mount();
    const old = dotPoint(records, 0, 3);
    const fresh = reloadWithinTheWindow(rerender);
    // The old dots are still drawn and clickable, and their ids are indexes of the new set.
    expect(laneSlider).not.toHaveAttribute("aria-disabled", "true");
    down(laneSlider, old.x, old.y);
    up(laneSlider, old.x, old.y);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    settle();
    const now = dotPoint(fresh, 0, 3);
    down(laneSlider, now.x, now.y);
    up(laneSlider, now.x, now.y);
    expect(useEvtxStore.getState().selectedRecordId).toBe(now.record.id);
    expect(useEvtxStore.getState().records[now.record.id]).toBe(now.record);
  });

  it("selects nothing with Space on the old scene, and the new set's event once it catches up", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { laneSlider, rerender } = mount();
    fireEvent.focus(laneSlider);
    reloadWithinTheWindow(rerender);
    key(laneSlider, " ");
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    settle();
    key(laneSlider, " ");
    const selected = useEvtxStore.getState().selectedRecordId;
    expect(selected).not.toBeNull();
    expect(useEvtxStore.getState().records[selected!].provider).toBe("A");
  });

  it("rings no dot of the old scene, and rings the selected id's dot in the new one", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { laneSlider, rerender } = mount();
    const target = dotPoint(records, 0, 3);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(region("swimlanes").querySelector('[data-evtx-layer="selected"]')).not.toBeNull();
    const selected = useEvtxStore.getState().selectedRecordId;
    reloadWithinTheWindow(rerender);
    // The selected id is still a small number, and an old record still carries it: it is not the
    // store's, so nothing is ringed.
    expect(useEvtxStore.getState().selectedRecordId).toBe(selected);
    expect(region("swimlanes").querySelector('[data-evtx-layer="selected"]')).toBeNull();
    settle();
    expect(region("swimlanes").querySelector('[data-evtx-layer="selected"]')).not.toBeNull();
  });
});

describe("the lane stack scrolls", () => {
  const many = Array.from({ length: 8 }, (_, lane) =>
    Array.from({ length: 3 }, (_, i) => rec(FIRST + (lane * 3 + i) * HOUR, "Information", `lane-${lane}`)),
  ).flat();

  function scrollerOf(container: HTMLElement) {
    const scroller = container.querySelector<HTMLElement>("[data-evtx-swimlane-scroller]")!;
    // jsdom has no layout: give the scroller a 100 px window onto the stack.
    Object.defineProperty(scroller, "clientHeight", { value: 100, configurable: true });
    Object.defineProperty(scroller, "scrollTop", { value: 0, writable: true, configurable: true });
    return scroller;
  }

  it("brings the lane the keyboard cursor moves to into view, and back", () => {
    const { container, laneSlider } = mount(many);
    const scroller = scrollerOf(container);
    fireEvent.focus(laneSlider);
    for (let step = 0; step < 5; step += 1) key(laneSlider, "ArrowDown");
    // Lane 5 spans 180 to 216: its bottom sits at the bottom of the 100 px window.
    expect(scroller.scrollTop).toBe(216 - 100);
    for (let step = 0; step < 5; step += 1) key(laneSlider, "ArrowUp");
    expect(scroller.scrollTop).toBe(0);
  });

  it("does not move the scroll for a lane already in view, or for a pointer that has focus", () => {
    const { container, laneSlider } = mount(many);
    const scroller = scrollerOf(container);
    fireEvent.focus(laneSlider);
    key(laneSlider, "ArrowDown");
    expect(scroller.scrollTop).toBe(0);
    scroller.scrollTop = 50;
    fireEvent.blur(laneSlider);
    const target = dotPoint(many, 4, 1);
    down(laneSlider, target.x, target.y);
    up(laneSlider, target.x, target.y);
    expect(scroller.scrollTop).toBe(50);
  });
});

describe("the slider", () => {
  it("is named apart from the histogram's, so both can be on screen", () => {
    mount();
    expect(screen.getAllByRole("slider")).toHaveLength(2);
    expect(screen.getByRole("slider", { name: "Time range" })).toBeInTheDocument();
    expect(screen.getByRole("slider", { name: "Time range, by lane" })).toBeInTheDocument();
  });

  it("documents its keys and where every event can be read", () => {
    const { laneSlider } = mount();
    expect(laneSlider.getAttribute("aria-keyshortcuts")).toContain("ArrowUp");
    expect(laneSlider.getAttribute("aria-keyshortcuts")).toContain("Space");
    const description = document.getElementById(laneSlider.getAttribute("aria-describedby")!)!;
    expect(description.textContent).toMatch(/Space selects the most severe event/);
    expect(description.textContent).toMatch(/Table view lists every event/);
  });

  it("offers no slider with nothing to chart", () => {
    render(<EvtxSwimlaneView records={[]} loading={false} />);
    expect(screen.queryByRole("slider")).toBeNull();
  });

  it("keeps the dot at the pointer reachable at the largest font, where the lanes are taller", () => {
    useUiStore.setState({ logListFontSize: 20 });
    const { laneSlider } = mount();
    const height = laneHeightFor(20);
    const scene = buildSwimlanes(records, "provider", "utc");
    const target = scene.lanes[1];
    down(laneSlider, LEFT + target.fractions[2] * PLOT_W, height + height / 2);
    up(laneSlider, LEFT + target.fractions[2] * PLOT_W, height + height / 2);
    expect(useEvtxStore.getState().selectedRecordId).toBe(target.records[2].id);
  });
});
