import { describe, expect, it } from "vitest";
import { MIN_DOCK_HEIGHT } from "./evtx-layout-store";
import {
  DOCK_MIN_HEIGHT_PX,
  TABLE_GRID_FLOOR_ROWS,
  correlationViewMinHeightPx,
  dockHandleBounds,
  genericViewMinHeightPx,
  listRowPx,
  tableGridFloorPx,
  tableViewMinHeightPx,
  timelineStripHeightPx,
  viewMinHeightPx,
} from "./evtx-main-column-layout";

describe("the floors of the main column", () => {
  it("counts a list row as the lists measure it", () => {
    expect(listRowPx(23)).toBe(25);
  });

  it("keeps five grid rows", () => {
    expect(TABLE_GRID_FLOOR_ROWS).toBe(5);
    expect(tableGridFloorPx(25)).toBe(125);
  });

  it("draws the strip at 320 px, at most half the window, and never under 240 px", () => {
    expect(timelineStripHeightPx(900)).toBe(320);
    expect(timelineStripHeightPx(640)).toBe(320);
    expect(timelineStripHeightPx(600)).toBe(300);
    expect(timelineStripHeightPx(481)).toBe(240.5);
    // The minimum wins when the two meet, as `min-height` beat `max-height` before.
    expect(timelineStripHeightPx(480)).toBe(240);
    expect(timelineStripHeightPx(300)).toBe(240);
    expect(timelineStripHeightPx(0)).toBe(240);
  });

  it("holds the Table view at its strip plus the grid floor", () => {
    expect(tableViewMinHeightPx(25, 900)).toBe(320 + 125);
    expect(tableViewMinHeightPx(25, 600)).toBe(300 + 125);
    expect(tableViewMinHeightPx(25, 100)).toBe(240 + 125);
    // A taller row (a larger font) raises the floor with it.
    expect(tableViewMinHeightPx(35, 900)).toBe(320 + 175);
  });

  it("gives the dock one minimum, its header and one lane at the largest font, that the store shares", () => {
    expect(DOCK_MIN_HEIGHT_PX).toBe(107);
    // The stored height, the rendered minimum and the handle's range start at the same number, so a
    // handle at its minimum is at the least the dock can be set to.
    expect(MIN_DOCK_HEIGHT).toBe(DOCK_MIN_HEIGHT_PX);
  });
});

describe("the floor of every view", () => {
  it("keeps the Correlation view's chain list header and three chain rows in sight", () => {
    // At the default font: a 36 px header, and three 83 px rows (16 px of padding, 6 px of gaps, a
    // 1 px border and three 20 px lines); the detail header and legend need only 88 px.
    expect(correlationViewMinHeightPx(13)).toBe(36 + 3 * 83);
  });

  it("raises the Correlation floor with the font, because its lines do", () => {
    // Text over 13 px outgrows the 20 px minimum line: 26 px for the header, 29 for a row's title.
    expect(correlationViewMinHeightPx(20)).toBe(16 + 26 + 3 * (23 + 3 * 29));
    expect(correlationViewMinHeightPx(20)).toBeGreaterThan(correlationViewMinHeightPx(13));
  });

  it("gives the placeholder views one generic minimum: a header and three list rows", () => {
    expect(genericViewMinHeightPx(13)).toBe(36 + 3 * 25);
    expect(genericViewMinHeightPx(20)).toBeGreaterThan(genericViewMinHeightPx(13));
  });

  it("decides every view's floor in one place", () => {
    const base = { gridRowPx: 29, windowHeight: 900, logListFontSize: 13 };
    expect(viewMinHeightPx({ ...base, view: "table" })).toBe(320 + 145);
    expect(viewMinHeightPx({ ...base, view: "correlation" })).toBe(285);
    for (const view of ["grouped", "timeline", "charts"] as const) {
      expect(viewMinHeightPx({ ...base, view })).toBe(111);
    }
    // None of them is 0: no view can be squeezed away by the dock.
    for (const view of ["table", "grouped", "timeline", "charts", "correlation"] as const) {
      expect(viewMinHeightPx({ ...base, view })).toBeGreaterThan(0);
    }
  });
});

describe("the dock's resize handle range", () => {
  it("reports the rendered height, within the dock minimum and what the column leaves it", () => {
    // 117 rendered of a chosen 210: the handle says 117, and 135 is all the column can give.
    expect(dockHandleBounds({ renderedHeight: 117, availableHeight: 135, storeMax: 450 })).toEqual({
      value: 117,
      min: 107,
      max: 135,
    });
  });

  it("never offers more than the store's maximum, and a column with room gives that", () => {
    expect(dockHandleBounds({ renderedHeight: 210, availableHeight: 5000, storeMax: 450 }).max).toBe(450);
  });

  it("ends at the minimum when the column has less than that, and the value says so", () => {
    const bounds = dockHandleBounds({ renderedHeight: 107, availableHeight: 60, storeMax: 450 });
    expect(bounds).toEqual({ value: 107, min: 107, max: 107 });
  });

  it("keeps the value inside the range whatever was measured", () => {
    expect(dockHandleBounds({ renderedHeight: 40, availableHeight: 300, storeMax: 450 }).value).toBe(107);
    expect(dockHandleBounds({ renderedHeight: 900, availableHeight: 300, storeMax: 450 }).value).toBe(300);
  });
});
