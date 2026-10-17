import { describe, expect, it } from "vitest";
import {
  eventDateKey,
  formatClock,
  formatDayClock,
  formatEventTime,
  formatTimeRange,
  TIME_RANGE_SEPARATOR,
  offsetLabel,
  tellRangeEndsApart,
  timeRangeNeedsYear,
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

describe("timeRangeNeedsYear", () => {
  const utc = (year: number, month: number, day: number, hour = 0, minute = 0) =>
    Date.UTC(year, month - 1, day, hour, minute);
  const NOW = utc(2026, 10, 16, 12);
  const needs = (start: number, end: number) => timeRangeNeedsYear(start, end, "utc", NOW);

  it("leaves the year out of a range inside the current year", () => {
    expect(needs(utc(2026, 10, 16, 9), utc(2026, 10, 16, 9, 45))).toBe(false);
    expect(needs(utc(2026, 1, 2), utc(2026, 8, 30))).toBe(false);
  });

  it("names the year of a range in a past year or a future one", () => {
    expect(needs(utc(2024, 3, 3), utc(2024, 4, 2))).toBe(true);
    expect(needs(utc(2027, 1, 5), utc(2027, 1, 6))).toBe(true);
  });

  it("names the year of a range whose ends fall in different years, across New Year", () => {
    expect(needs(utc(2025, 12, 31, 22), utc(2026, 1, 1, 3))).toBe(true);
    expect(needs(utc(2026, 12, 31, 22), utc(2027, 1, 1, 3))).toBe(true);
  });

  it("names the year of a range of 365 days or more, even one inside the current year's dates", () => {
    expect(needs(utc(2026, 1, 1), utc(2027, 1, 1))).toBe(true);
    expect(needs(utc(2026, 1, 1), utc(2026, 12, 31))).toBe(false);
  });

  it("names the year of a range of exactly 365 days inside one leap year, whose ends share the current year", () => {
    const now2028 = utc(2028, 6, 1);
    expect(timeRangeNeedsYear(utc(2028, 1, 1), utc(2028, 12, 31), "utc", now2028)).toBe(true);
    expect(timeRangeNeedsYear(utc(2028, 1, 1), utc(2028, 12, 30), "utc", now2028)).toBe(false);
  });

  it("reads the year on the chosen clock, not the UTC one", () => {
    // Built from the host's own calendar, so it holds in any zone: local New Year's Eve into the new year.
    const eve = new Date(2026, 11, 31, 23, 0).getTime();
    const newYear = new Date(2027, 0, 1, 1, 0).getTime();
    const june = new Date(2026, 5, 15, 12, 0).getTime();
    expect(timeRangeNeedsYear(eve, newYear, "local", june)).toBe(true);
    expect(timeRangeNeedsYear(june - 3600_000, june, "local", june)).toBe(false);
  });
});

describe("a range label never reads with its start equal to its end", () => {
  const utc = (year: number, month: number, day: number, hour = 0, minute = 0, second = 0, ms = 0) =>
    Date.UTC(year, month - 1, day, hour, minute, second, ms);

  it("names the year for a range of 365 days or more even when the caller did not ask", () => {
    const label = formatTimeRange(utc(2026, 2, 14), utc(2027, 2, 14), "utc");
    const [start, end] = label.split(TIME_RANGE_SEPARATOR);
    expect(start).not.toBe(end);
    expect(label).toBe(`Feb 14 2026 00:00${TIME_RANGE_SEPARATOR}Feb 14 2027 00:00`);
  });

  it("adds milliseconds to a range shorter than a second, which seconds alone cannot tell apart", () => {
    const label = formatTimeRange(utc(2026, 10, 16, 9, 0, 0, 0), utc(2026, 10, 16, 9, 0, 0, 500), "utc");
    expect(label).toBe(`09:00:00.000${TIME_RANGE_SEPARATOR}09:00:00.500`);
    const across = formatTimeRange(utc(2026, 10, 16, 23, 59, 59, 600), utc(2026, 10, 16, 23, 59, 59, 900), "utc");
    expect(across).toBe(`23:59:59.600${TIME_RANGE_SEPARATOR}23:59:59.900`);
  });

  it("leaves a range that already reads apart alone", () => {
    expect(formatTimeRange(utc(2026, 10, 16, 9, 0, 0, 0), utc(2026, 10, 16, 9, 0, 1, 500), "utc")).toBe(
      `09:00:00${TIME_RANGE_SEPARATOR}09:00:01`,
    );
  });
});

describe("a range whose two ends read alike across a DST fall-back", () => {
  const SEP = TIME_RANGE_SEPARATOR;

  describe("tellRangeEndsApart, a pure rule that takes the two offsets", () => {
    it("labels each end with its offset when the texts are equal and the offsets differ (Europe/London, 26 Oct 2025)", () => {
      // 01:00 BST (UTC+01:00) to 01:00 GMT (UTC+00:00): the same wall text twice, an hour apart.
      expect(tellRangeEndsApart("Oct 26 2025 01:00", "Oct 26 2025 01:00", 60, 0)).toEqual({
        start: "Oct 26 2025 01:00 UTC+01:00",
        end: "Oct 26 2025 01:00 UTC+00:00",
      });
      expect(tellRangeEndsApart("01:00", "01:00", 60, 0)).toEqual({
        start: "01:00 UTC+01:00",
        end: "01:00 UTC+00:00",
      });
    });

    it("does the same across America/New_York's fall-back and a half-hour zone's", () => {
      expect(tellRangeEndsApart("Nov 2 2025 01:00", "Nov 2 2025 01:00", -240, -300)).toEqual({
        start: "Nov 2 2025 01:00 UTC-04:00",
        end: "Nov 2 2025 01:00 UTC-05:00",
      });
      expect(tellRangeEndsApart("01:30", "01:30", 345, 330)).toEqual({
        start: "01:30 UTC+05:45",
        end: "01:30 UTC+05:30",
      });
    });

    it("leaves a normal range alone: texts that differ get no offset, even when the offsets differ", () => {
      expect(tellRangeEndsApart("00:30", "02:30", 60, 0)).toEqual({ start: "00:30", end: "02:30" });
      expect(tellRangeEndsApart("09:00", "09:45", 0, 0)).toEqual({ start: "09:00", end: "09:45" });
    });

    it("leaves equal texts alone when the offsets do not differ: that is a sub-second range, for milliseconds", () => {
      expect(tellRangeEndsApart("09:00:00", "09:00:00", 0, 0)).toEqual({ start: "09:00:00", end: "09:00:00" });
    });

    it("writes an offset as UTC+hh:mm, the way timeZoneLabel does", () => {
      expect(offsetLabel(60)).toBe("UTC+01:00");
      expect(offsetLabel(0)).toBe("UTC+00:00");
      expect(offsetLabel(-300)).toBe("UTC-05:00");
      expect(offsetLabel(345)).toBe("UTC+05:45");
    });
  });

  describe("formatTimeRange", () => {
    const utc = (hour: number, minute = 0, second = 0, ms = 0) => Date.UTC(2026, 9, 16, hour, minute, second, ms);

    it("still adds milliseconds to a genuinely sub-second range, and gives it no offset", () => {
      expect(formatTimeRange(utc(9, 0, 0, 0), utc(9, 0, 0, 500), "utc")).toBe(
        `09:00:00.000${SEP}09:00:00.500`,
      );
    });

    it("gives a normal range no offset", () => {
      expect(formatTimeRange(utc(9), utc(9, 45), "utc")).toBe(`09:00${SEP}09:45`);
      const local = formatTimeRange(utc(9), utc(9, 45), "local");
      expect(local).not.toMatch(/UTC/);
    });

    it("never reads with its two ends alike, across every hour of a year in the host's own zone", () => {
      // The host's zone decides whether any of these ranges is a repeated hour: run under TZ=Europe/London
      // or TZ=America/New_York to cover a fall-back. Under UTC it checks only that nothing reads alike.
      const from = Date.UTC(2025, 0, 1);
      let checked = 0;
      for (let at = from; at < from + 365 * 24 * 3600_000; at += 3600_000) {
        for (const span of [20 * 60_000, 3600_000, 2 * 3600_000]) {
          for (const withYear of [false, true]) {
            const [start, end] = formatTimeRange(at, at + span, "local", withYear).split(SEP);
            if (start === end) throw new Error(`${new Date(at).toISOString()} + ${span}: ${start} ${SEP} ${end}`);
            checked += 1;
          }
        }
      }
      expect(checked).toBe(365 * 24 * 3 * 2);
    });
  });
});
