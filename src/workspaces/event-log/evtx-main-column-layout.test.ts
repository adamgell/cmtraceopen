import { describe, expect, it } from "vitest";
import { DEFAULT_LOG_LIST_FONT_SIZE, MAX_LOG_LIST_FONT_SIZE } from "../../lib/log-accessibility";
import { MIN_DOCK_HEIGHT } from "./evtx-layout-store";
import {
  TABLE_GRID_FLOOR_ROWS,
  dockMinHeightPx,
  listRowPx,
  tableGridFloorPx,
  tableViewMinHeightPx,
  timelineStripHeightPx,
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

  it("gives the dock a minimum of its header and one lane, under the least a user can drag it to", () => {
    const atDefault = dockMinHeightPx(DEFAULT_LOG_LIST_FONT_SIZE);
    expect(atDefault).toBe(100);
    expect(atDefault).toBeLessThan(MIN_DOCK_HEIGHT);
    // The axis text grows with the font, so the minimum does too, and stays under that floor.
    expect(dockMinHeightPx(MAX_LOG_LIST_FONT_SIZE)).toBeGreaterThan(atDefault);
    expect(dockMinHeightPx(MAX_LOG_LIST_FONT_SIZE)).toBeLessThan(MIN_DOCK_HEIGHT);
  });
});
