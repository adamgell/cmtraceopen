import { describe, expect, it } from "vitest";
import { eventDateKey, formatEventTime, timeZoneLabel } from "./evtx-time";

// 2026-02-10T16:36:04.390Z
const EPOCH = Date.UTC(2026, 1, 10, 16, 36, 4, 390);

describe("formatEventTime", () => {
  it("shows UTC when asked for UTC, regardless of where the machine is", () => {
    expect(formatEventTime(EPOCH, "utc")).toBe("2026-02-10 16:36:04.390");
  });

  it("shows the same instant in local time", () => {
    // Compared against the platform's own conversion rather than a hardcoded string, so the test
    // is not pinned to the timezone the suite happens to run in.
    const local = new Date(EPOCH);
    expect(formatEventTime(EPOCH, "local")).toBe(
      `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, "0")}-` +
        `${String(local.getDate()).padStart(2, "0")} ` +
        `${String(local.getHours()).padStart(2, "0")}:` +
        `${String(local.getMinutes()).padStart(2, "0")}:` +
        `${String(local.getSeconds()).padStart(2, "0")}.390`
    );
  });

  it("keeps the sub-millisecond digits Windows wrote", () => {
    // Ordering two events inside the same millisecond is exactly what this tool is for, so the
    // precision the source supplied must survive.
    expect(formatEventTime(EPOCH, "utc", "2026-02-10T16:36:04.390987Z")).toBe(
      "2026-02-10 16:36:04.390987"
    );
  });

  it("invents no precision the source did not have", () => {
    expect(formatEventTime(EPOCH, "utc", "2026-02-10T16:36:04Z")).toBe(
      "2026-02-10 16:36:04.390"
    );
    expect(formatEventTime(EPOCH, "utc", "2026-02-10T16:36:04.390Z")).toBe(
      "2026-02-10 16:36:04.390"
    );
  });

  it("takes the displayed value from the epoch, not the string", () => {
    // The epoch is what rows are sorted by. Rendering from the string instead would let a row
    // display a time that disagrees with the position it was sorted into.
    expect(formatEventTime(EPOCH, "utc", "1999-01-01T00:00:00.000123Z")).toBe(
      "2026-02-10 16:36:04.390123"
    );
  });

  it("pads every field so times stay column-aligned", () => {
    const early = Date.UTC(2026, 0, 2, 3, 4, 5, 6);
    expect(formatEventTime(early, "utc")).toBe("2026-01-02 03:04:05.006");
  });
});

describe("eventDateKey", () => {
  it("buckets by the same zone the time is shown in", () => {
    // An event must not appear under a day that disagrees with the timestamp printed beside it.
    expect(eventDateKey(EPOCH, "utc")).toBe("2026-02-10");
    const local = new Date(EPOCH);
    expect(eventDateKey(EPOCH, "local")).toBe(
      `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, "0")}-` +
        `${String(local.getDate()).padStart(2, "0")}`
    );
  });

  it("puts an instant near midnight UTC on the UTC day", () => {
    expect(eventDateKey(Date.UTC(2026, 1, 10, 23, 59, 59), "utc")).toBe("2026-02-10");
    expect(eventDateKey(Date.UTC(2026, 1, 11, 0, 0, 1), "utc")).toBe("2026-02-11");
  });
});

describe("timeZoneLabel", () => {
  it("labels UTC plainly", () => {
    expect(timeZoneLabel("utc")).toBe("UTC");
  });

  it("labels local with its actual offset, not the word local", () => {
    // A screenshot or a pasted note has to still say which clock it was.
    const label = timeZoneLabel("local", EPOCH);
    expect(label).toMatch(/^UTC[+-]\d{2}:\d{2}$/);
  });
});
