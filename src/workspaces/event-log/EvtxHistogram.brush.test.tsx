import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { useUiStore } from "../../stores/ui-store";
import { EvtxFilterChips } from "./EvtxFilterChips";
import { EvtxHistogram } from "./EvtxHistogram";
import { buildHistogram, describeBucket } from "./evtx-histogram";
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
const BUCKET_PX = 10;

const rec = (timestampEpoch: number, level: EvtxLevel = "Information", id = 1): EvtxRecord =>
  ({
    id,
    eventRecordId: id,
    timestamp: "",
    timestampEpoch,
    provider: "P",
    channel: "System",
    eventId: 1,
    level,
    computer: "C",
    message: "m",
    eventData: [],
    rawXml: "",
    sourceLabel: "System",
  }) as EvtxRecord;

/** One event per 20 minutes for a day, plus one at the end: 72 buckets of 20 minutes. */
const records: EvtxRecord[] = [
  ...Array.from({ length: 72 }, (_, i) => rec(FIRST + i * 20 * MINUTE + 1000, i % 7 === 0 ? "Error" : "Information", i)),
  rec(FIRST + DAY - 1, "Warning", 99),
];
const histogram = buildHistogram(records, "utc");
const edge = (index: number) => histogram.edges[index];
const x = (bucket: number, offset = 4) => LEFT + bucket * BUCKET_PX + offset;

let setTimeRangeSpy: ReturnType<typeof vi.fn>;
const realSetTimeRange = useEvtxStore.getState().setTimeRange;

/** The chart and the chip name the year by the same rule, which compares with the current one. */
const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
  setTimeRangeSpy = vi.fn(realSetTimeRange);
  useEvtxStore.setState({
    timeZoneMode: "utc",
    timeRange: null,
    recordScope: null,
    isLoading: false,
    coverageGaps: [],
    coverageDetails: [],
    tailCoverageGaps: [],
    setTimeRange: setTimeRangeSpy as typeof realSetTimeRange,
  });
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  useEvtxStore.setState({ setTimeRange: realSetTimeRange, timeRange: null, isLoading: false });
});

function mount(extra?: { records?: readonly EvtxRecord[] }) {
  const view = render(
    <>
      <EvtxFilterChips visibleCount={records.length} loadedCount={records.length} />
      <EvtxHistogram records={extra?.records ?? records} loading={false} />
    </>,
  );
  const slider = screen.getByRole("slider", { name: "Time range" });
  slider.getBoundingClientRect = () =>
    ({ left: LEFT, top: 0, right: LEFT + 720, bottom: 56, width: 720, height: 56, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect;
  return { ...view, slider };
}

const down = (target: Element, clientX: number, init: Record<string, unknown> = {}) =>
  fireEvent.pointerDown(target, { clientX, button: 0, buttons: 1, isPrimary: true, pointerId: 1, ...init });
const move = (target: Element, clientX: number, buttons = 1) =>
  fireEvent.pointerMove(target, { clientX, buttons, pointerId: 1 });
const up = (target: Element, clientX: number) => fireEvent.pointerUp(target, { clientX, pointerId: 1 });
const key = (target: Element, name: string, init: Record<string, unknown> = {}) =>
  fireEvent.keyDown(target, { key: name, ...init });

const wash = (container: HTMLElement) => container.querySelector<HTMLElement>('[data-evtx-layer="wash"]');
const edges = (container: HTMLElement) => [...container.querySelectorAll<HTMLElement>('[data-evtx-layer="edge"]')];
const percent = (value: string) => parseFloat(value);
const storeRange = () => useEvtxStore.getState().timeRange;
/** Seeds the range without going through the action under test. */
const seedRange = (range: { startMs: number; endMs: number } | null) =>
  act(() => {
    useEvtxStore.setState({ timeRange: range });
  });
/** The chip's label for a range, which names the year when the range is not in the current one. */
const chipLabel = (startMs: number, endMs: number, mode: "utc" | "local" = "utc") =>
  `Time: brushed ${formatTimeRange(startMs, endMs, mode, timeRangeNeedsYear(startMs, endMs, mode, Date.now()))}`;
const tooltip = () => document.querySelector<HTMLElement>("[data-evtx-tooltip]");
/** The cursor bucket's text shown inline in the caption line while the plot has keyboard focus. */
const cursorText = () => document.querySelector<HTMLElement>("[data-evtx-cursor-text]");
const rangeOf = (first: number, last: number) => ({ startMs: edge(first), endMs: edge(last + 1) });

describe("dragging a range", () => {
  it("draws a draft while dragging and sets the range once, on release, from whole buckets", () => {
    const { slider, container } = mount();
    down(slider, x(3));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    move(slider, x(5));
    move(slider, x(7));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toBeNull();
    const draft = wash(container)!;
    expect(draft.dataset.evtxDraft).toBe("true");
    expect(percent(draft.style.left)).toBeCloseTo((3 / 72) * 100, 6);
    expect(percent(draft.style.right)).toBeCloseTo(((72 - 8) / 72) * 100, 6);
    expect(edges(container).every((el) => el.style.borderLeft.includes("dashed"))).toBe(true);

    up(slider, x(7));
    expect(setTimeRangeSpy).toHaveBeenCalledTimes(1);
    expect(setTimeRangeSpy).toHaveBeenCalledWith(rangeOf(3, 7));
    expect(storeRange()).toEqual(rangeOf(3, 7));
    expect(wash(container)!.dataset.evtxDraft).toBe("false");
    expect(edges(container).every((el) => el.style.borderLeft.includes("solid"))).toBe(true);
  });

  it("shows the draft alone over an applied range, so the wash is never twice as opaque as solved", () => {
    const { slider, container } = mount();
    seedRange(rangeOf(30, 33));
    expect(container.querySelectorAll('[data-evtx-layer="wash"]')).toHaveLength(1);
    down(slider, x(3));
    move(slider, x(8));
    const washes = container.querySelectorAll<HTMLElement>('[data-evtx-layer="wash"]');
    expect(washes).toHaveLength(1);
    expect(washes[0].dataset.evtxDraft).toBe("true");
    expect(percent(washes[0].style.left)).toBeCloseTo((3 / 72) * 100, 6);
    expect(edges(container)).toHaveLength(2);
    up(slider, x(8));
    expect(container.querySelectorAll('[data-evtx-layer="wash"]')).toHaveLength(1);
    expect(storeRange()).toEqual(rangeOf(3, 8));
  });

  it("makes the Time chip appear with the range it set, in the chosen zone", () => {
    const { slider } = mount();
    down(slider, x(10));
    up(slider, x(14));
    const label = chipLabel(edge(10), edge(15));
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: `Remove ${label}` })).toBeInTheDocument();
  });

  it("gives the same range when dragged right to left", () => {
    const { slider } = mount();
    down(slider, x(20));
    move(slider, x(12));
    up(slider, x(12));
    expect(storeRange()).toEqual(rangeOf(12, 20));
  });

  it("clamps a drag that leaves the plot to the first and last bucket", () => {
    const { slider } = mount();
    down(slider, x(60));
    move(slider, 5000);
    up(slider, 5000);
    expect(storeRange()).toEqual(rangeOf(60, 71));
    down(slider, x(2));
    move(slider, -300);
    up(slider, -300);
    expect(storeRange()).toEqual(rangeOf(0, 2));
  });

  it("freezes the buckets a drag began on while a live tail re-buckets the chart", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { slider, rerender } = mount();
    down(slider, x(3));
    // The tail appends days of events: the chart would regrid to a wider interval.
    const grown = [...records, rec(FIRST + 5 * DAY, "Error", 500)];
    rerender(
      <>
        <EvtxFilterChips visibleCount={grown.length} loadedCount={grown.length} />
        <EvtxHistogram records={grown} loading={false} />
      </>,
    );
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    move(slider, x(7));
    up(slider, x(7));
    expect(storeRange()).toEqual(rangeOf(3, 7));
  });
});

describe("a press while a keyboard selection is pending", () => {
  it("anchors under the pointer on the grid the selection froze, not the regridded chart", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { slider, rerender } = mount();
    fireEvent.focus(slider);
    // A Shift selection freezes the 72 buckets of 20 minutes it began on.
    key(slider, "ArrowLeft", { shiftKey: true });
    // The tail then appends days of events: the live chart regrids to a coarser interval.
    const grown = [...records, rec(FIRST + 5 * DAY, "Error", 500)];
    expect(buildHistogram(grown, "utc").buckets.length).not.toBe(72);
    rerender(
      <>
        <EvtxFilterChips visibleCount={grown.length} loadedCount={grown.length} />
        <EvtxHistogram records={grown} loading={false} />
      </>,
    );
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    // Mid-plot is bucket 36 of the 72 the plot still shows, and the press releases in the same place.
    down(slider, LEFT + 360);
    up(slider, LEFT + 360);
    expect(storeRange()).toEqual(rangeOf(36, 36));
  });
});

describe("the chart and the chip name the year by one rule", () => {
  /** Two events a day for six months of a single past year. */
  const inYear = (year: number) =>
    Array.from({ length: 360 }, (_, i) => rec(Date.UTC(year, 2, 3) + Math.floor(i / 2) * 12 * HOUR + (i % 2) * HOUR, "Information", i));

  function brushBucket(list: readonly EvtxRecord[]) {
    const view = render(
      <>
        <EvtxFilterChips visibleCount={list.length} loadedCount={list.length} />
        <EvtxHistogram records={list} loading={false} />
      </>,
    );
    const slider = screen.getByRole("slider", { name: "Time range" });
    const shown = buildHistogram(list, "utc");
    const wide = 720 / shown.buckets.length;
    slider.getBoundingClientRect = () =>
      ({ left: LEFT, top: 0, right: LEFT + 720, bottom: 56, width: 720, height: 56, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect;
    down(slider, LEFT + 10 * wide + 1);
    up(slider, LEFT + 10 * wide + 1);
    return { ...view, slider, shown };
  }

  it("a chart of a single past year names the year, and a bucket brushed on it gives a chip with the same year", () => {
    const { slider, shown } = brushBucket(inYear(2024));
    expect(shown.showYear).toBe(true);
    const chip = document.querySelector("[data-evtx-chip='timeRange'] span")!.textContent!;
    expect(chip).toMatch(/^Time: brushed [A-Z][a-z]{2} \d{1,2} 2024 \d\d:\d\d/);
    expect(slider.getAttribute("aria-valuetext")).toMatch(/ 2024 \d\d:\d\d.* 2024 \d\d:\d\d \u00b7 .*time range [A-Z][a-z]{2} \d{1,2} 2024 /);
    // The year in the chip is the year in the chart's own labels.
    expect(chip.match(/\b\d{4}\b/)![0]).toBe(slider.getAttribute("aria-valuetext")!.match(/\b\d{4}\b/)![0]);
  });

  it("a chart within the current year names no year on either side", () => {
    const { slider, shown } = brushBucket(inYear(2026));
    expect(shown.showYear).toBe(false);
    const chip = document.querySelector("[data-evtx-chip='timeRange'] span")!.textContent!;
    expect(chip).not.toMatch(/\b20\d\d\b/);
    expect(slider.getAttribute("aria-valuetext")).not.toMatch(/\b20\d\d\b/);
  });
});

describe("a click", () => {
  it("selects the bucket it lands on", () => {
    const { slider } = mount();
    down(slider, x(9));
    up(slider, x(9));
    expect(storeRange()).toEqual(rangeOf(9, 9));
  });

  it("clears the range when the bucket is already the whole range", () => {
    const { slider, container } = mount();
    down(slider, x(9));
    up(slider, x(9));
    down(slider, x(9));
    up(slider, x(9));
    expect(setTimeRangeSpy).toHaveBeenLastCalledWith(null);
    expect(storeRange()).toBeNull();
    expect(wash(container)).toBeNull();
  });

  it("replaces a different range with the bucket", () => {
    const { slider } = mount();
    seedRange(rangeOf(2, 6));
    down(slider, x(9));
    up(slider, x(9));
    expect(storeRange()).toEqual(rangeOf(9, 9));
  });

  it("takes focus", () => {
    const { slider } = mount();
    down(slider, x(9));
    expect(document.activeElement).toBe(slider);
    up(slider, x(9));
  });

  it("ignores a secondary button and a release with no press", () => {
    const { slider } = mount();
    down(slider, x(9), { button: 2 });
    up(slider, x(9));
    down(slider, x(9), { isPrimary: false });
    up(slider, x(9));
    up(slider, x(20));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });
});

describe("a gesture that does not finish", () => {
  it("sets nothing when the pointer is cancelled or loses capture", () => {
    const { slider, container } = mount();
    down(slider, x(3));
    move(slider, x(8));
    fireEvent.pointerCancel(slider, { pointerId: 1 });
    expect(wash(container)).toBeNull();
    down(slider, x(3));
    fireEvent.lostPointerCapture(slider, { pointerId: 1 });
    up(slider, x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  it("stops following a pointer whose button was released outside the page", () => {
    const { slider, container } = mount();
    down(slider, x(3));
    move(slider, x(6), 0);
    expect(wash(container)).toBeNull();
    up(slider, x(6));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  it("cancels a drag with Escape and spends the key, so the applied range survives", () => {
    const { slider, container } = mount();
    seedRange(rangeOf(30, 33));
    down(slider, x(3));
    move(slider, x(8));
    const notPrevented = key(slider, "Escape");
    expect(notPrevented).toBe(false);
    expect(wash(container)!.dataset.evtxDraft).toBe("false");
    up(slider, x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    expect(storeRange()).toEqual(rangeOf(30, 33));
  });

  it("draws nothing and sets nothing when a load starts before the release", () => {
    const { slider, container } = mount();
    down(slider, x(3));
    act(() => {
      useEvtxStore.setState({ isLoading: true });
    });
    up(slider, x(7));
    expect(setTimeRangeSpy).toHaveBeenCalledTimes(1);
    expect(storeRange()).toBeNull();
    expect(wash(container)).toBeNull();
    expect(edges(container)).toHaveLength(0);
  });
});

describe("the keyboard", () => {
  it("is one slider named Time range, starting at the newest bucket with its tooltip text as the value", () => {
    const { slider } = mount();
    expect(slider).toHaveAttribute("aria-orientation", "horizontal");
    expect(slider).toHaveAttribute("aria-valuemin", "0");
    expect(slider).toHaveAttribute("aria-valuemax", "71");
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    expect(slider).toHaveAttribute("aria-valuetext", describeBucket(histogram.buckets[71], "utc"));
    expect(slider.tabIndex).toBe(0);
    expect(slider).toHaveAttribute("aria-keyshortcuts");
    const description = document.getElementById(slider.getAttribute("aria-describedby")!)!;
    expect(description.textContent).toMatch(/Shift/);
    expect(description.textContent).toMatch(/Escape/);
  });

  it("moves a one-bucket cursor with the arrows, Home and End, and shows its text inline, not in a tooltip", () => {
    const { slider, container } = mount();
    fireEvent.focus(slider);
    expect(container.querySelector('[data-evtx-layer="cursor"]')).not.toBeNull();
    // The floating tooltip is for the pointer: at the keyboard cursor it would cover the chip row.
    expect(tooltip()).toBeNull();
    expect(cursorText()).toHaveTextContent(describeBucket(histogram.buckets[71], "utc"));
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[71], "utc"));
    key(slider, "ArrowLeft");
    expect(tooltip()).toBeNull();
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[70], "utc"));
    expect(slider).toHaveAttribute("aria-valuenow", "70");
    expect(slider).toHaveAttribute("aria-valuetext", describeBucket(histogram.buckets[70], "utc"));
    key(slider, "Home");
    expect(slider).toHaveAttribute("aria-valuenow", "0");
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[0], "utc"));
    key(slider, "ArrowLeft");
    expect(slider).toHaveAttribute("aria-valuenow", "0");
    key(slider, "End");
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    key(slider, "ArrowRight");
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    expect(parseFloat((container.querySelector('[data-evtx-layer="cursor"]') as HTMLElement).style.left)).toBeCloseTo(
      (71 / 72) * 100,
      6,
    );
  });

  it("shows no cursor text when a pointer press focused the plot, and shows it after the next key", () => {
    const { slider } = mount();
    down(slider, x(9));
    expect(document.activeElement).toBe(slider);
    expect(cursorText()).toBeNull();
    up(slider, x(9));
    expect(cursorText()).toBeNull();
    key(slider, "ArrowLeft");
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[8], "utc"));
    // Another press returns to the pointer: the line is for the keyboard only.
    down(slider, x(20));
    expect(cursorText()).toBeNull();
    up(slider, x(20));
    expect(cursorText()).toBeNull();
  });

  it("shows the cursor text on Tab focus, and keeps it through an arrow key", () => {
    const { slider } = mount();
    // Tab focus is a focus event with no pointer press before it.
    fireEvent.focus(slider);
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[71], "utc"));
    key(slider, "ArrowLeft");
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[70], "utc"));
  });

  it("is a persistent line in the figure, not an overlay, and goes when focus leaves", () => {
    const { slider } = mount();
    fireEvent.focus(slider);
    const line = cursorText()!;
    expect(line.closest("figcaption")).not.toBeNull();
    expect(line.closest("[data-evtx-region='histogram']")).not.toBeNull();
    fireEvent.blur(slider);
    expect(cursorText()).toBeNull();
  });

  it("still shows the floating tooltip for the pointer, and not the inline text", () => {
    const { slider } = mount();
    fireEvent.pointerMove(slider, { clientX: x(20) });
    expect(tooltip()).toHaveTextContent(describeBucket(histogram.buckets[20], "utc"));
    expect(cursorText()).toBeNull();
  });

  it("extends a draft with Shift, then Enter applies it", () => {
    const { slider, container } = mount();
    fireEvent.focus(slider);
    key(slider, "ArrowLeft", { shiftKey: true });
    key(slider, "ArrowLeft", { shiftKey: true });
    expect(slider.getAttribute("aria-valuetext")).toContain(
      `selecting ${formatTimeRange(edge(69), edge(72), "utc")}`,
    );
    expect(wash(container)!.dataset.evtxDraft).toBe("true");
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
    key(slider, "Enter");
    expect(setTimeRangeSpy).toHaveBeenCalledTimes(1);
    expect(storeRange()).toEqual(rangeOf(69, 71));
    expect(slider.getAttribute("aria-valuetext")).toContain(
      `time range ${formatTimeRange(edge(69), edge(72), "utc")} applied`,
    );
  });

  it("applies the one bucket under the cursor on Enter, and clears it on the second Enter", () => {
    const { slider } = mount();
    fireEvent.focus(slider);
    key(slider, "ArrowLeft");
    key(slider, "Enter");
    expect(storeRange()).toEqual(rangeOf(70, 70));
    key(slider, "Enter");
    expect(storeRange()).toBeNull();
  });

  it("adjusts an applied range from the bucket at one of its ends", () => {
    const { slider } = mount();
    seedRange(rangeOf(10, 14));
    fireEvent.focus(slider);
    expect(slider).toHaveAttribute("aria-valuenow", "14");
    key(slider, "ArrowRight", { shiftKey: true });
    key(slider, "Enter");
    expect(storeRange()).toEqual(rangeOf(10, 15));
    key(slider, "ArrowLeft", { shiftKey: true });
    key(slider, "ArrowLeft", { shiftKey: true });
    key(slider, "Enter");
    expect(storeRange()).toEqual(rangeOf(10, 13));
  });

  it("takes Escape for a pending selection first, and passes it up to clear the range second", () => {
    const { slider, container } = mount();
    seedRange(rangeOf(10, 14));
    fireEvent.focus(slider);
    key(slider, "ArrowRight", { shiftKey: true });
    expect(wash(container)!.dataset.evtxDraft).toBe("true");
    // The first Escape cancels the draft and is spent (preventDefault), so the workspace's window
    // handler, which skips a key that was already handled, leaves the applied range alone.
    expect(key(slider, "Escape")).toBe(false);
    expect(storeRange()).toEqual(rangeOf(10, 14));
    expect(wash(container)!.dataset.evtxDraft).toBe("false");
    // The second has nothing pending, is not prevented, and reaches that handler.
    expect(key(slider, "Escape")).toBe(true);
  });

  it("lets Escape through to clear the range while a tooltip is showing, or the cursor text", () => {
    const { slider } = mount();
    seedRange(rangeOf(10, 14));
    fireEvent.pointerMove(slider, { clientX: x(20) });
    expect(tooltip()).not.toBeNull();
    // Not prevented: the workspace's window handler, which skips a handled key, receives it.
    expect(key(slider, "Escape")).toBe(true);
    expect(key(document.body, "Escape")).toBe(true);
    fireEvent.pointerLeave(slider);
    fireEvent.focus(slider);
    expect(cursorText()).not.toBeNull();
    expect(key(slider, "Escape")).toBe(true);
  });

  it("ignores keys with Control, Alt or Meta, and arrow keys while there are no buckets", () => {
    const { slider } = mount();
    fireEvent.focus(slider);
    key(slider, "ArrowLeft", { ctrlKey: true });
    key(slider, "ArrowLeft", { altKey: true });
    key(slider, "ArrowLeft", { metaKey: true });
    expect(slider).toHaveAttribute("aria-valuenow", "71");
  });

  it("drops a pending selection and the cursor when focus leaves", () => {
    const { slider, container } = mount();
    fireEvent.focus(slider);
    key(slider, "ArrowLeft", { shiftKey: true });
    fireEvent.blur(slider);
    expect(container.querySelector('[data-evtx-layer="cursor"]')).toBeNull();
    expect(wash(container)).toBeNull();
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });

  it("freezes the buckets of a pending selection while a tail re-buckets the chart", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { slider, rerender } = mount();
    fireEvent.focus(slider);
    key(slider, "ArrowLeft", { shiftKey: true });
    const grown = [...records, rec(FIRST + 5 * DAY, "Error", 500)];
    rerender(
      <>
        <EvtxFilterChips visibleCount={grown.length} loadedCount={grown.length} />
        <EvtxHistogram records={grown} loading={false} />
      </>,
    );
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });
    key(slider, "Enter");
    expect(storeRange()).toEqual(rangeOf(70, 71));
  });
});

describe("keeping the overlay and the Time chip in step", () => {
  it("draws the range the store holds, wherever it was set", () => {
    const { container } = mount();
    expect(wash(container)).toBeNull();
    seedRange(rangeOf(10, 19));
    expect(percent(wash(container)!.style.left)).toBeCloseTo((10 / 72) * 100, 6);
    expect(percent(wash(container)!.style.right)).toBeCloseTo(((72 - 20) / 72) * 100, 6);
    expect(edges(container)).toHaveLength(2);
  });

  it("clears the overlay when the chip's remove button is pressed", () => {
    const { slider, container } = mount();
    down(slider, x(5));
    up(slider, x(9));
    expect(wash(container)).not.toBeNull();
    const label = chipLabel(edge(5), edge(10));
    fireEvent.click(screen.getByRole("button", { name: `Remove ${label}` }));
    expect(storeRange()).toBeNull();
    expect(wash(container)).toBeNull();
    expect(edges(container)).toHaveLength(0);
  });

  it("clears the overlay when a load starts, which clears the range", () => {
    const { container } = mount();
    seedRange(rangeOf(10, 19));
    act(() => {
      useEvtxStore.setState({ isLoading: true });
      useEvtxStore.setState({ timeRange: null });
    });
    expect(wash(container)).toBeNull();
  });

  it("draws one edge fewer where a range runs past the plot, and clips the wash to it", () => {
    const { container } = mount();
    seedRange({ startMs: edge(0) - HOUR, endMs: edge(4) });
    expect(percent(wash(container)!.style.left)).toBe(0);
    expect(percent(wash(container)!.style.right)).toBeCloseTo(((72 - 4) / 72) * 100, 6);
    expect(edges(container).map((el) => el.dataset.evtxEdge)).toEqual(["end"]);
    seedRange({ startMs: edge(70), endMs: edge(72) + HOUR });
    expect(edges(container).map((el) => el.dataset.evtxEdge)).toEqual(["start"]);
    expect(percent(wash(container)!.style.right)).toBe(0);
  });

  it("says so, and draws no wash, when the range lies wholly off the charted events", () => {
    const { container } = mount();
    seedRange({ startMs: edge(72) + HOUR, endMs: edge(72) + 2 * HOUR });
    expect(wash(container)).toBeNull();
    expect(screen.getByText("The time range is outside the charted events.")).toBeInTheDocument();
    seedRange(rangeOf(1, 2));
    expect(screen.queryByText("The time range is outside the charted events.")).toBeNull();
  });

  it("keeps the same instants when the zone changes, and relabels the chip", () => {
    const { container } = mount();
    seedRange(rangeOf(10, 19));
    act(() => {
      useEvtxStore.setState({ timeZoneMode: "local" });
    });
    expect(storeRange()).toEqual(rangeOf(10, 19));
    expect(screen.getByText(chipLabel(edge(10), edge(20), "local"))).toBeInTheDocument();
    expect(wash(container)).not.toBeNull();
    // Where the wash sits depends on the local grid, which the host's zone decides; that it is still
    // drawn from the same instants is what the store's unchanged range says.
  });
});

describe("what it cannot be used for", () => {
  it("offers no slider with nothing to chart", () => {
    render(<EvtxHistogram records={[]} loading={false} />);
    expect(screen.queryByRole("slider")).toBeNull();
    cleanup();
    render(<EvtxHistogram records={[rec(0)]} loading={false} />);
    expect(screen.queryByRole("slider")).toBeNull();
    expect(tooltip()).toBeNull();
  });

  it("offers a disabled slider while loading, which sets nothing", () => {
    render(<EvtxHistogram records={[]} loading />);
    const slider = screen.getByRole("slider", { name: "Time range" });
    expect(slider).toHaveAttribute("aria-disabled", "true");
    key(slider, "Enter");
    down(slider, 10);
    up(slider, 10);
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });
});

describe("a load that ends a gesture", () => {
  const withChips = (list: readonly EvtxRecord[], loading: boolean) => (
    <>
      <EvtxFilterChips visibleCount={list.length} loadedCount={list.length} />
      <EvtxHistogram records={list} loading={loading} />
    </>
  );
  const settle = () =>
    act(() => {
      vi.advanceTimersByTime(DERIVATION_THROTTLE_MS);
    });

  it("derives the cursor from the chart once it is ready, when focus arrived during the load", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender } = render(withChips([], true));
    const slider = screen.getByRole("slider", { name: "Time range" });
    act(() => {
      slider.focus();
    });
    expect(document.activeElement).toBe(slider);
    rerender(withChips(records, false));
    settle();
    // The newest bucket, not the oldest that an empty chart's cursor would have been.
    expect(screen.getByRole("slider", { name: "Time range" })).toBe(slider);
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    expect(slider).toHaveAttribute("aria-valuetext", describeBucket(histogram.buckets[71], "utc"));
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[71], "utc"));
  });

  it("shows no stale grid and commits none after a load, when a Shift selection was pending", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { container, rerender } = render(withChips(records, false));
    const slider = screen.getByRole("slider", { name: "Time range" });
    act(() => {
      slider.focus();
    });
    key(slider, "ArrowLeft", { shiftKey: true });
    expect(wash(container)!.dataset.evtxDraft).toBe("true");

    // A load starts and ends with different events: a different grid.
    rerender(withChips([], true));
    settle();
    const reloaded = [...records, rec(FIRST + 5 * DAY, "Error", 500)];
    const fresh = buildHistogram(reloaded, "utc");
    expect(fresh.buckets.length).not.toBe(72);
    rerender(withChips(reloaded, false));
    settle();

    expect(container.querySelectorAll("[data-evtx-bucket]")).toHaveLength(fresh.buckets.length);
    expect(wash(container)).toBeNull();
    expect(slider.getAttribute("aria-valuetext")).not.toMatch(/selecting/);
    expect(slider).toHaveAttribute("aria-valuenow", String(fresh.buckets.length - 1));
    // Enter applies the newest bucket of the grid on screen, not a range from the grid before the load.
    key(slider, "Enter");
    const last = fresh.buckets.length - 1;
    expect(storeRange()).toEqual({ startMs: fresh.edges[last], endMs: fresh.edges[last + 1] });
  });

  it("counts a press during a load as the pointer's: no cursor line once the load ends", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender } = render(withChips([], true));
    const slider = screen.getByRole("slider", { name: "Time range" });
    // The chart is not ready, so the handler returns early; the browser then focuses the plot itself.
    down(slider, 10);
    act(() => {
      slider.focus();
    });
    up(slider, 10);
    rerender(withChips(records, false));
    settle();
    expect(document.activeElement).toBe(slider);
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    expect(cursorText()).toBeNull();
    // The keyboard then brings the line.
    key(slider, "ArrowLeft");
    expect(cursorText()!.textContent).toBe(describeBucket(histogram.buckets[70], "utc"));
  });

  it("does not let a finished press mark a later focus event as the pointer's", () => {
    const { slider } = mount();
    down(slider, x(9));
    up(slider, x(9));
    expect(cursorText()).toBeNull();
    // No blur in between: the release alone ends the press, so the next focus is the keyboard's.
    fireEvent.focus(slider);
    expect(cursorText()).not.toBeNull();
  });

  it("does not let a blur leave the press marked: a Tab back in is the keyboard's", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { rerender } = render(withChips([], true));
    const slider = screen.getByRole("slider", { name: "Time range" });
    // A press during a load whose release never reaches the plot, then focus leaves.
    down(slider, 10);
    act(() => {
      slider.focus();
    });
    act(() => {
      slider.blur();
    });
    fireEvent.focus(slider);
    rerender(withChips(records, false));
    settle();
    expect(cursorText()).not.toBeNull();
  });

  it("drops a drag in progress when a load starts, and commits nothing on release", () => {
    vi.useFakeTimers({ now: PINNED_NOW });
    const { container, rerender } = render(withChips(records, false));
    const slider = screen.getByRole("slider", { name: "Time range" });
    slider.getBoundingClientRect = () =>
      ({ left: LEFT, top: 0, right: LEFT + 720, bottom: 56, width: 720, height: 56, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect;
    down(slider, x(3));
    move(slider, x(8));
    expect(wash(container)!.dataset.evtxDraft).toBe("true");
    rerender(withChips([], true));
    expect(wash(container)).toBeNull();
    up(slider, x(8));
    expect(setTimeRangeSpy).not.toHaveBeenCalled();
  });
});

describe("a load while the plot has focus", () => {
  const withChips = (extra: { records: readonly EvtxRecord[]; loading: boolean }) => (
    <>
      <EvtxFilterChips visibleCount={records.length} loadedCount={records.length} />
      <EvtxHistogram records={extra.records} loading={extra.loading} />
    </>
  );

  it("keeps the plot focusable and aria-disabled while loading, and usable again afterwards", () => {
    const { slider, rerender } = mount();
    act(() => {
      slider.focus();
    });
    expect(document.activeElement).toBe(slider);

    rerender(withChips({ records: [], loading: true }));
    // Still the same element, still in the tab order, and said to be unavailable.
    expect(screen.getByRole("slider", { name: "Time range" })).toBe(slider);
    expect(slider.getAttribute("tabindex")).toBe("0");
    expect(slider).toHaveAttribute("aria-disabled", "true");
    expect(document.activeElement).toBe(slider);
    key(slider, "ArrowLeft");
    key(slider, "Enter");
    expect(setTimeRangeSpy).not.toHaveBeenCalled();

    rerender(withChips({ records, loading: false }));
    expect(screen.getByRole("slider", { name: "Time range" })).toBe(slider);
    expect(slider).not.toHaveAttribute("aria-disabled", "true");
    expect(document.activeElement).toBe(slider);
    expect(slider).toHaveAttribute("aria-valuenow", "71");
    key(slider, "ArrowLeft");
    expect(slider).toHaveAttribute("aria-valuenow", "70");
  });
});
