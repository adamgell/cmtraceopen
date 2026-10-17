/**
 * Formatting event timestamps in a stated zone.
 *
 * Three places rendered event times three different ways: the list column printed the raw ISO
 * string Windows wrote, which is UTC; the unified timeline printed local time; and day grouping
 * bucketed by local date. So the same event showed a different clock depending on where you looked
 * at it, and nothing on screen said which zone any of them was. An admin correlating an event to
 * the time a user reported a problem would be silently hours out.
 *
 * Everything now goes through here, and the zone is always labelled.
 *
 * Windows writes sub-millisecond precision (`.390987`) that an epoch-milliseconds value cannot
 * hold. Those digits are read back off the original string rather than dropped, because ordering
 * two events inside the same millisecond is exactly the kind of question this tool exists to
 * answer.
 */

/** Which clock event times are shown in. */
export type EvtxTimeZoneMode = "local" | "utc";

const pad = (value: number, width = 2) => String(value).padStart(width, "0");

/**
 * The fractional-seconds digits Windows wrote, beyond the three an epoch value keeps.
 *
 * Returns an empty string when the source had no more precision to offer, so nothing is invented.
 */
function extraPrecision(isoTimestamp: string | undefined): string {
  if (!isoTimestamp) return "";
  const match = /\.(\d+)/.exec(isoTimestamp);
  if (!match) return "";
  return match[1].slice(3);
}

/**
 * Formats an event time as `YYYY-MM-DD HH:MM:SS.mmm`.
 *
 * `isoTimestamp` is optional and only supplies precision past milliseconds. The value shown always
 * comes from `epochMs`, so a row cannot disagree with the order it was sorted into.
 */
export function formatEventTime(
  epochMs: number,
  mode: EvtxTimeZoneMode,
  isoTimestamp?: string
): string {
  const date = new Date(epochMs);
  const parts =
    mode === "utc"
      ? {
          year: date.getUTCFullYear(),
          month: date.getUTCMonth() + 1,
          day: date.getUTCDate(),
          hours: date.getUTCHours(),
          minutes: date.getUTCMinutes(),
          seconds: date.getUTCSeconds(),
          ms: date.getUTCMilliseconds(),
        }
      : {
          year: date.getFullYear(),
          month: date.getMonth() + 1,
          day: date.getDate(),
          hours: date.getHours(),
          minutes: date.getMinutes(),
          seconds: date.getSeconds(),
          ms: date.getMilliseconds(),
        };

  return (
    `${parts.year}-${pad(parts.month)}-${pad(parts.day)} ` +
    `${pad(parts.hours)}:${pad(parts.minutes)}:${pad(parts.seconds)}.` +
    `${pad(parts.ms, 3)}${extraPrecision(isoTimestamp)}`
  );
}

/**
 * The date an event falls on, for grouping.
 *
 * Uses the same zone as the displayed time, so an event never appears under a day that disagrees
 * with the timestamp printed next to it.
 */
export function eventDateKey(epochMs: number, mode: EvtxTimeZoneMode): string {
  const date = new Date(epochMs);
  return mode === "utc"
    ? `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`
    : `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

const MONTH_ABBREVIATIONS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** The wall clock of an instant in the chosen zone. */
function wallClock(epochMs: number, mode: EvtxTimeZoneMode) {
  const date = new Date(epochMs);
  return mode === "utc"
    ? {
        year: date.getUTCFullYear(),
        month: date.getUTCMonth(),
        day: date.getUTCDate(),
        hours: date.getUTCHours(),
        minutes: date.getUTCMinutes(),
        seconds: date.getUTCSeconds(),
      }
    : {
        year: date.getFullYear(),
        month: date.getMonth(),
        day: date.getDate(),
        hours: date.getHours(),
        minutes: date.getMinutes(),
        seconds: date.getSeconds(),
      };
}

/** `HH:mm`, or `HH:mm:ss` with `withSeconds`, in the chosen zone. */
export function formatClock(epochMs: number, mode: EvtxTimeZoneMode, withSeconds = false): string {
  const clock = wallClock(epochMs, mode);
  const hhmm = `${pad(clock.hours)}:${pad(clock.minutes)}`;
  return withSeconds ? `${hhmm}:${pad(clock.seconds)}` : hhmm;
}

/**
 * A clock reading with its day, `Oct 16 22:00` (`Oct 16 22:00:05` with `withSeconds`), in the chosen
 * zone. For labels that sit on a span longer than a day, where a bare `22:00` would not say which one.
 * With `withYear` the zone's year follows the day, `Oct 16 2026 22:00`, for a span that crosses a
 * calendar year or buckets a year wide: without it the same label names two different years alike.
 */
export function formatDayClock(
  epochMs: number,
  mode: EvtxTimeZoneMode,
  withSeconds = false,
  withYear = false,
): string {
  const { year, month, day } = wallClock(epochMs, mode);
  const date = withYear ? `${MONTH_ABBREVIATIONS[month]} ${day} ${year}` : `${MONTH_ABBREVIATIONS[month]} ${day}`;
  return `${date} ${formatClock(epochMs, mode, withSeconds)}`;
}

/** Between the two times of a range label: an en dash, the spec's glyph (section 8.4). */
export const TIME_RANGE_SEPARATOR = "\u2013";

/** A range this long or longer always names the year in its label. */
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

/** A range shorter than this shows seconds, so its two ends do not read as the same minute. */
const SECONDS_BELOW_MS = 2 * 60 * 1000;

/**
 * A half-open time range as a label: `09:00-09:45` on one day, `Oct 16 22:00-Oct 17 03:00` across
 * days, and with seconds when the range is shorter than two minutes. The days are the zone's own,
 * and the last instant inside the range decides whether it crosses one, so a range that ends at
 * midnight stays on its day. The separator is `TIME_RANGE_SEPARATOR`. `withYear` is `formatDayClock`'s.
 */
export function formatTimeRange(
  startMs: number,
  endMs: number,
  mode: EvtxTimeZoneMode,
  withYear = false,
): string {
  const withSeconds = endMs - startMs < SECONDS_BELOW_MS;
  // A range a year wide or more always names the year: its two ends would otherwise read alike.
  const year = withYear || endMs - startMs >= YEAR_MS;
  // With the year, both ends always carry their day and year.
  const crossesDays =
    year || eventDateKey(startMs, mode) !== eventDateKey(Math.max(startMs, endMs - 1), mode);
  const end = (epochMs: number) =>
    crossesDays
      ? formatDayClock(epochMs, mode, withSeconds, year)
      : formatClock(epochMs, mode, withSeconds);
  // Across a DST fall-back a range as wide as the shift runs from the first occurrence of a wall time
  // to the second, so both ends read alike; each then names its own offset.
  const ends = tellRangeEndsApart(
    end(startMs),
    end(endMs),
    zoneOffsetMinutes(startMs, mode),
    zoneOffsetMinutes(endMs, mode),
  );
  if (ends.start !== ends.end || endMs - startMs >= 1000) {
    return `${ends.start}${TIME_RANGE_SEPARATOR}${ends.end}`;
  }
  // Under a second, even seconds read alike: the milliseconds tell the ends apart.
  const milliseconds = (epochMs: number) => String(((epochMs % 1000) + 1000) % 1000).padStart(3, "0");
  return `${ends.start}.${milliseconds(startMs)}${TIME_RANGE_SEPARATOR}${ends.end}.${milliseconds(endMs)}`;
}

/**
 * The two end texts of a range, each with its zone offset when they read alike and the offsets
 * differ: `01:00 UTC+01:00` and `01:00 UTC+00:00` for the hour that repeats when the clocks go back.
 * Anything else is returned as it came: texts that differ need nothing, and equal texts at one offset
 * are a sub-second range, which `formatTimeRange` tells apart by milliseconds. Pure, so it is tested
 * with any two offsets whatever the host's zone.
 */
export function tellRangeEndsApart(
  startText: string,
  endText: string,
  startOffsetMinutes: number,
  endOffsetMinutes: number,
): { start: string; end: string } {
  if (startText !== endText || startOffsetMinutes === endOffsetMinutes) {
    return { start: startText, end: endText };
  }
  return {
    start: `${startText} ${offsetLabel(startOffsetMinutes)}`,
    end: `${endText} ${offsetLabel(endOffsetMinutes)}`,
  };
}

/** A zone's offset from UTC in minutes at an instant: zero in UTC, the host's own in local mode. */
function zoneOffsetMinutes(epochMs: number, mode: EvtxTimeZoneMode): number {
  // getTimezoneOffset is minutes *behind* UTC, so the sign is inverted.
  return mode === "utc" ? 0 : -new Date(epochMs).getTimezoneOffset();
}

/** An offset as `UTC+01:00` (`UTC-05:00`, `UTC+00:00`). */
export function offsetLabel(offsetMinutes: number): string {
  const sign = offsetMinutes < 0 ? "-" : "+";
  const absolute = Math.abs(offsetMinutes);
  return `UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
}

/**
 * Whether a range label must name the year: either end is not in the current year (`nowMs`, in the
 * chosen zone), the two ends fall in different years, or the range is 365 days or longer. The Time
 * chip uses it, so a range brushed on a multi-year chart reads as the chart's own labels do.
 */
export function timeRangeNeedsYear(
  startMs: number,
  endMs: number,
  mode: EvtxTimeZoneMode,
  nowMs: number,
): boolean {
  const current = wallClock(nowMs, mode).year;
  return (
    endMs - startMs >= YEAR_MS ||
    wallClock(startMs, mode).year !== current ||
    wallClock(endMs, mode).year !== current
  );
}

/**
 * How the current zone is labelled in the UI.
 *
 * A time with no zone next to it is a time the reader has to guess at, which is the problem this
 * module exists to remove. The local label carries the actual offset rather than the word "local",
 * so a screenshot or an exported note still says which clock it was.
 */
export function timeZoneLabel(mode: EvtxTimeZoneMode, epochMs = Date.now()): string {
  if (mode === "utc") return "UTC";
  return offsetLabel(zoneOffsetMinutes(epochMs, mode));
}
