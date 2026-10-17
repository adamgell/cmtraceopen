import { describe, expect, it } from "vitest";
import {
  eventDateKey,
  formatClock,
  formatDayClock,
  formatEventTime,
  formatTimeRange,
  TIME_RANGE_SEPARATOR,
  timeZoneLabel,
} from "./evtx-time";

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

describe("formatClock", () => {
  it("shows HH:mm in UTC, with seconds on request", () => {
    expect(formatClock(EPOCH, "utc")).toBe("16:36");
    expect(formatClock(EPOCH, "utc", true)).toBe("16:36:04");
    expect(formatClock(Date.UTC(2026, 1, 10, 3, 5, 9), "utc", true)).toBe("03:05:09");
  });

  it("shows the same instant in the platform's local time", () => {
    const local = new Date(EPOCH);
    const pad = (n: number) => String(n).padStart(2, "0");
    expect(formatClock(EPOCH, "local")).toBe(`${pad(local.getHours())}:${pad(local.getMinutes())}`);
  });
});

describe("formatTimeRange", () => {
  const utc = (day: number, hour: number, minute: number, second = 0) =>
    Date.UTC(2026, 9, day, hour, minute, second);
  const SEP = "\u2013";

  it("separates the two times with an en dash, written as an escape", () => {
    expect(TIME_RANGE_SEPARATOR).toBe(SEP);
    expect(formatTimeRange(utc(16, 9, 0), utc(16, 9, 45), "utc")).toBe(`09:00${SEP}09:45`);
  });

  it("adds the date to each end when the range crosses a day in the chosen zone", () => {
    expect(formatTimeRange(utc(16, 22, 0), utc(17, 3, 0), "utc")).toBe(`Oct 16 22:00${SEP}Oct 17 03:00`);
  });

  it("stays on one day when it ends at midnight, because the end is not inside the range", () => {
    expect(formatTimeRange(utc(16, 23, 0), utc(17, 0, 0), "utc")).toBe(`23:00${SEP}00:00`);
    expect(formatTimeRange(utc(16, 23, 0), utc(17, 0, 0, 1), "utc")).toBe(`Oct 16 23:00${SEP}Oct 17 00:00`);
  });

  it("shows seconds below two minutes and not from two minutes", () => {
    expect(formatTimeRange(utc(16, 9, 0, 10), utc(16, 9, 1, 5), "utc")).toBe(`09:00:10${SEP}09:01:05`);
    expect(formatTimeRange(utc(16, 9, 0), utc(16, 9, 2), "utc")).toBe(`09:00${SEP}09:02`);
    expect(formatTimeRange(utc(16, 9, 0), utc(16, 9, 1, 59), "utc")).toBe(`09:00:00${SEP}09:01:59`);
  });

  it("reads the same instants on the local clock in local mode", () => {
    const start = utc(16, 9, 0);
    const end = utc(16, 9, 45);
    expect(formatTimeRange(start, end, "local")).toBe(
      `${formatClock(start, "local")}${SEP}${formatClock(end, "local")}`,
    );
  });
});

describe("formatDayClock", () => {
  const utc = (day: number, hour: number, minute: number, second = 0) =>
    Date.UTC(2026, 9, day, hour, minute, second);

  it("puts the zone's month and day before the clock", () => {
    expect(formatDayClock(utc(16, 22, 0), "utc")).toBe("Oct 16 22:00");
    expect(formatDayClock(utc(3, 4, 5, 9), "utc", true)).toBe("Oct 3 04:05:09");
  });

  it("reads the day on the chosen clock, not the UTC one", () => {
    const local = new Date(utc(16, 22, 0));
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    expect(formatDayClock(utc(16, 22, 0), "local")).toBe(
      `${months[local.getMonth()]} ${local.getDate()} ${formatClock(utc(16, 22, 0), "local")}`,
    );
  });

  it("is the form a range label uses for each end when the range crosses a day", () => {
    const start = utc(16, 22, 0);
    const end = utc(17, 3, 0);
    expect(formatTimeRange(start, end, "utc")).toBe(
      `${formatDayClock(start, "utc")}${TIME_RANGE_SEPARATOR}${formatDayClock(end, "utc")}`,
    );
  });
});

describe("the year in day labels", () => {
  const utc = (year: number, month: number, day: number, hour = 0, minute = 0) =>
    Date.UTC(year, month - 1, day, hour, minute);

  it("puts the zone's year between the day and the clock when asked", () => {
    expect(formatDayClock(utc(2024, 1, 5, 22), "utc", false, true)).toBe("Jan 5 2024 22:00");
    expect(formatDayClock(utc(2026, 10, 16, 3, 4), "utc", true, true)).toBe("Oct 16 2026 03:04:00");
    expect(formatDayClock(utc(2026, 10, 16, 3, 4), "utc")).toBe("Oct 16 03:04");
  });

  it("reads the year on the chosen clock, not the UTC one", () => {
    const local = new Date(utc(2025, 12, 31, 23, 30));
    expect(formatDayClock(utc(2025, 12, 31, 23, 30), "local", false, true)).toContain(` ${local.getFullYear()} `);
  });

  it("gives a range both days and years, even one inside a single day, so two ends are never alike", () => {
    expect(formatTimeRange(utc(2026, 2, 14), utc(2027, 2, 14), "utc", true)).toBe(
      `Feb 14 2026 00:00${TIME_RANGE_SEPARATOR}Feb 14 2027 00:00`,
    );
    expect(formatTimeRange(utc(2026, 10, 16, 9), utc(2026, 10, 16, 9, 45), "utc", true)).toBe(
      `Oct 16 2026 09:00${TIME_RANGE_SEPARATOR}Oct 16 2026 09:45`,
    );
    expect(formatTimeRange(utc(2026, 10, 16, 9), utc(2026, 10, 16, 9, 45), "utc")).toBe(
      `09:00${TIME_RANGE_SEPARATOR}09:45`,
    );
  });
});
