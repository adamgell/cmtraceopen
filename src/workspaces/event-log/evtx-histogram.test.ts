import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isWithinTimeRange } from "./evtx-filter";
import {
  HISTOGRAM_BAR_AREA_PX,
  HISTOGRAM_INTERVALS_MS,
  HISTOGRAM_STACK_ORDER,
  MAX_BUCKETS,
  MIN_SEGMENT_PX,
  SEPARATOR_PX,
  UTC_CLOCK,
  bucketEdges,
  bucketIndexAt,
  bucketSegments,
  buildAxisTicks,
  buildHistogram,
  chooseBuckets,
  describeBucket,
  describeCounts,
  describeCoverage,
  describeFigure,
  describeInterval,
  describeUntimed,
  fitScale,
  fractionAt,
  rangeOnPlot,
  zoneClockFor,
  type EvtxHistogram,
  type HistogramBucket,
  type WallParts,
  type ZoneClock,
} from "./evtx-histogram";
import { LONDON_2026, modelZone } from "./__fixtures__/model-zone";
import { TIME_RANGE_SEPARATOR, formatTimeRange, timeRangeNeedsYear } from "./evtx-time";
import type { EvtxLevel, EvtxRecord } from "./types";

/**
 * Day labels name the year when the charted domain is not entirely within the current year, so the
 * clock is pinned (Date only; timers stay real) and the labels below do not change on 1 January.
 */
const PINNED_NOW = Date.UTC(2026, 9, 16, 12, 0);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(PINNED_NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const utc = (month: number, day: number, hour = 0, minute = 0, second = 0, ms = 0) =>
  Date.UTC(2026, month - 1, day, hour, minute, second, ms);

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

/**
 * A zone built from its offsets (minutes east of UTC), so the DST and half-hour paths run the same
 * on any host. `instant` picks the earliest instant whose offset gives that wall time, and a wall
 * time the zone skips resolves forward on the offset in force before the gap, as `Date` does.
 */
function syntheticZone(offsetAt: (epochMs: number) => number, offsets: number[]): ZoneClock {
  const wallAsUtc = (p: WallParts) => Date.UTC(p.year, p.month, p.day, p.hours, p.minutes, p.seconds);
  return {
    wall: (epochMs) => {
      const date = new Date(epochMs + offsetAt(epochMs) * MINUTE);
      return {
        year: date.getUTCFullYear(),
        month: date.getUTCMonth(),
        day: date.getUTCDate(),
        hours: date.getUTCHours(),
        minutes: date.getUTCMinutes(),
        seconds: date.getUTCSeconds(),
      };
    },
    instant: (parts) => {
      const wall = wallAsUtc(parts);
      const valid = offsets
        .map((offset) => ({ offset, epochMs: wall - offset * MINUTE }))
        .filter((candidate) => offsetAt(candidate.epochMs) === candidate.offset)
        .map((candidate) => candidate.epochMs)
        .sort((a, b) => a - b);
      return valid.length > 0 ? valid[0] : wall - Math.min(...offsets) * MINUTE;
    },
  };
}

// America/New_York in 2026: DST starts 2026-03-08 07:00Z and ends 2026-11-01 06:00Z.
const NEW_YORK = syntheticZone(
  (epochMs) => (epochMs >= Date.UTC(2026, 2, 8, 7) && epochMs < Date.UTC(2026, 10, 1, 6) ? -240 : -300),
  [-300, -240],
);
const KOLKATA = syntheticZone(() => 330, [330]);
const KATHMANDU = syntheticZone(() => 345, [345]);

const deltas = (edges: readonly number[]) => edges.slice(1).map((edge, index) => edge - edges[index]);

describe("the width ladder", () => {
  it("rises, and holds every rung the spec lists", () => {
    expect([...HISTOGRAM_INTERVALS_MS]).toEqual([...HISTOGRAM_INTERVALS_MS].sort((a, b) => a - b));
    for (const spec of [
      MINUTE, 2 * MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 20 * MINUTE, 30 * MINUTE,
      HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY,
    ]) {
      expect(HISTOGRAM_INTERVALS_MS).toContain(spec);
    }
  });

  it("gives 24 hours 72 buckets of 20 minutes (spec 8.5)", () => {
    const min = utc(10, 6, 10, 20);
    const { intervalMs, edges } = chooseBuckets(min, min + DAY - 1, UTC_CLOCK);
    expect(intervalMs).toBe(20 * MINUTE);
    expect(edges.length - 1).toBe(72);
  });

  it("chooses the screenshot fixture's span the same way, from its first record to its last", () => {
    const histogram = buildHistogram(
      [rec(utc(10, 6, 10, 20, 47)), rec(utc(10, 7, 10, 19, 59))],
      "utc",
    );
    expect(histogram.intervalMs).toBe(20 * MINUTE);
    expect(histogram.buckets).toHaveLength(72);
    expect(histogram.edges[0]).toBe(utc(10, 6, 10, 20));
    expect(histogram.edges[72]).toBe(utc(10, 7, 10, 20));
  });

  it("picks the rung nearest 72, not the finest one that stays at or under 96", () => {
    // 15 minutes would give 96 buckets for a day; the rule is nearest 72, which is 20 minutes.
    const min = utc(10, 6, 0, 0);
    expect(chooseBuckets(min, min + DAY - 1, UTC_CLOCK).intervalMs).not.toBe(15 * MINUTE);
  });

  it("keeps every span from a millisecond to two centuries covered, ordered and at most 96 buckets", () => {
    let spans = 0;
    for (let exponent = 0; exponent <= 14; exponent += 0.25) {
      const span = Math.round(10 ** exponent);
      if (span > 200 * 365 * DAY) break;
      for (const offset of [0, 7 * MINUTE + 13, 5 * HOUR + 1, 3 * DAY + 17]) {
        const min = utc(2, 14, 3, 7, 9) + offset;
        const max = min + span;
        const { edges } = chooseBuckets(min, max, UTC_CLOCK);
        const count = edges.length - 1;
        expect(count).toBeGreaterThanOrEqual(1);
        expect(count).toBeLessThanOrEqual(MAX_BUCKETS);
        expect(edges[0]).toBeLessThanOrEqual(min);
        expect(edges[count]).toBeGreaterThan(max);
        for (const width of deltas(edges)) expect(width).toBeGreaterThan(0);
        spans += 1;
      }
    }
    expect(spans).toBeGreaterThan(50);
  });

  it("stays in the 48 to 96 band for spans of two minutes to ten years, bar a rung jump", () => {
    for (const span of [2 * MINUTE, 10 * MINUTE, 45 * MINUTE, HOUR, 3 * HOUR, 6 * HOUR, 2 * DAY, 7 * DAY, 30 * DAY, 90 * DAY, 365 * DAY, 3650 * DAY]) {
      for (const offset of [0, 3 * MINUTE + 11, 4 * HOUR + 7]) {
        const min = utc(5, 20, 1, 1, 1) + offset;
        const count = chooseBuckets(min, min + span, UTC_CLOCK).edges.length - 1;
        expect(count).toBeGreaterThanOrEqual(36);
        expect(count).toBeLessThanOrEqual(MAX_BUCKETS);
      }
    }
  });

  describe("where the ladder jumps by more than two", () => {
    /** The count each rung would give a span, from its real edges; a rung far past 96 is not built. */
    const rungCounts = (min: number, max: number) =>
      HISTOGRAM_INTERVALS_MS.map((intervalMs) => ({
        intervalMs,
        count:
          Math.ceil((max - min + 1) / intervalMs) + 1 > 300
            ? Number.POSITIVE_INFINITY
            : bucketEdges(min, max, intervalMs, UTC_CLOCK).length - 1,
      }));

    /**
     * The rule: of the rungs that fit in 96 buckets, one in 48 to 96 nearest 72 where there is one,
     * and otherwise the finest that fits. A 365 day multiple only when every rung is over 96.
     */
    const expectChoice = (min: number, max: number) => {
      const fitting = rungCounts(min, max).filter((rung) => rung.count <= MAX_BUCKETS);
      const { intervalMs, edges } = chooseBuckets(min, max, UTC_CLOCK);
      const count = edges.length - 1;
      const label = `${(max - min + 1) / MINUTE} minutes from ${new Date(min).toISOString()}`;
      expect(count, label).toBeLessThanOrEqual(MAX_BUCKETS);
      if (fitting.length === 0) {
        expect(intervalMs, label).toBeGreaterThanOrEqual(2 * 365 * DAY);
        return;
      }
      expect(HISTOGRAM_INTERVALS_MS, label).toContain(intervalMs);
      if (fitting.some((rung) => rung.count >= 48)) expect(count, label).toBeGreaterThanOrEqual(48);
      else expect(count, label).toBe(Math.max(...fitting.map((rung) => rung.count)));
    };

    it("never falls back to a multiple of 365 days while a rung fits in 96 buckets", () => {
      let checked = 0;
      for (let step = 0; step <= 600; step += 1) {
        const span = Math.round(Math.exp(Math.log(SECOND) + (step / 600) * (Math.log(60 * 365 * DAY) - Math.log(SECOND))));
        for (const offset of [0, 7 * MINUTE + 13, 5 * HOUR + 1]) {
          const min = utc(2, 14, 3, 7, 9) + offset;
          expectChoice(min, min + span);
          checked += 1;
        }
      }
      expect(checked).toBe(1803);
    });

    it.each([
      ["2 s to 5 s", 195 * SECOND, 5 * SECOND],
      ["2 min to 5 min", 3 * HOUR + 15 * MINUTE, 5 * MINUTE],
      ["2 d to 7 d", Math.round(205.8 * DAY), 7 * DAY],
      ["14 d to 30 d", 1360 * DAY, 30 * DAY],
      ["30 d to 90 d", 3000 * DAY, 90 * DAY],
      ["90 d to 365 d", 9500 * DAY, 365 * DAY],
    ])("takes the finest rung that fits inside the %s window", (_window, span, rung) => {
      const min = utc(10, 6, 10, 1);
      const { intervalMs, edges } = chooseBuckets(min, min + span, UTC_CLOCK);
      expect(intervalMs).toBe(rung);
      expect(edges.length - 1).toBeLessThanOrEqual(MAX_BUCKETS);
      expectChoice(min, min + span);
    });

    it("charts a live channel's 3 h 15 min as 5 minute buckets, not one bucket of two years", () => {
      const histogram = buildHistogram([rec(utc(10, 6, 10, 1)), rec(utc(10, 6, 13, 16))], "utc");
      expect(histogram.intervalMs).toBe(5 * MINUTE);
      expect(histogram.buckets).toHaveLength(40);
      expect(histogram.domain).toEqual({ startMs: utc(10, 6, 10, 0), endMs: utc(10, 6, 13, 20) });
      expect(describeFigure(histogram, "utc")).toMatch(/^Events per 5 minutes over 10:00.13:20 \(UTC\), stacked by level$/);
    });

    it("keeps a 365 day multiple for spans where every rung is over 96 buckets", () => {
      for (const years of [100, 150, 400]) {
        const min = utc(1, 1, 0, 0);
        const { intervalMs, edges } = chooseBuckets(min, min + years * 365 * DAY, UTC_CLOCK);
        expect(intervalMs % (365 * DAY)).toBe(0);
        expect(intervalMs).toBeGreaterThanOrEqual(2 * 365 * DAY);
        expect(edges.length - 1).toBeLessThanOrEqual(MAX_BUCKETS);
      }
    });
  });

  it("gives one record, or records at one instant, a single bucket one second wide", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 10, 20, 47, 250)), rec(utc(10, 6, 10, 20, 47, 250))], "utc");
    expect(histogram.intervalMs).toBe(SECOND);
    expect(histogram.buckets).toHaveLength(1);
    expect(histogram.buckets[0].total).toBe(2);
    expect(histogram.edges).toEqual([utc(10, 6, 10, 20, 47), utc(10, 6, 10, 20, 48)]);
  });
});

describe("buildHistogram", () => {
  it("puts a record on an edge in the later bucket and the one before it in the earlier", () => {
    const first = utc(10, 6, 10, 0);
    const records = [
      rec(first),
      rec(first + 20 * MINUTE - 1),
      rec(first + 20 * MINUTE),
      rec(first + DAY - 1),
    ];
    const histogram = buildHistogram(records, "utc");
    expect(histogram.intervalMs).toBe(20 * MINUTE);
    expect(histogram.buckets[0].total).toBe(2);
    expect(histogram.buckets[1].total).toBe(1);
    expect(histogram.buckets[histogram.buckets.length - 1].total).toBe(1);
  });

  it("counts the records of every level, Verbose included, and places every timed one once", () => {
    const base = utc(10, 6, 12, 0);
    const levels: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
    const records = levels.flatMap((level, index) =>
      Array.from({ length: index + 1 }, (_, n) => rec(base + (index * 7 + n) * MINUTE, level, index * 10 + n)),
    );
    const histogram = buildHistogram(records, "utc");
    expect(histogram.placed).toBe(15);
    expect(histogram.untimed).toBe(0);
    const sum = (level: EvtxLevel) => histogram.buckets.reduce((total, bucket) => total + bucket.counts[level], 0);
    expect(levels.map(sum)).toEqual([1, 2, 3, 4, 5]);
    expect(histogram.buckets.reduce((total, bucket) => total + bucket.total, 0)).toBe(15);
  });

  it("counts a record with no usable timestamp as untimed and in no bucket", () => {
    const records = [
      rec(utc(10, 6, 12, 0)),
      rec(utc(10, 6, 13, 0)),
      rec(0),
      rec(-5),
      rec(Number.NaN),
      rec(Number.POSITIVE_INFINITY),
    ];
    const histogram = buildHistogram(records, "utc");
    expect(histogram.untimed).toBe(4);
    expect(histogram.placed).toBe(2);
    expect(histogram.placed + histogram.untimed).toBe(records.length);
    // The extent is the timed records', not stretched to the epoch origin by the untimed ones.
    expect(histogram.domain?.startMs).toBeGreaterThan(utc(10, 6, 11, 0));
  });

  it("has no buckets when nothing is timed, and says how many it could not place", () => {
    const histogram = buildHistogram([rec(0), rec(Number.NaN)], "utc");
    expect(histogram.buckets).toEqual([]);
    expect(histogram.edges).toEqual([]);
    expect(histogram.domain).toBeNull();
    expect(histogram.untimed).toBe(2);
    expect(buildHistogram([], "utc").untimed).toBe(0);
  });

  it("selects exactly the events its bars count when a brush covers whole buckets", () => {
    const base = utc(10, 6, 0, 0);
    const records: EvtxRecord[] = [];
    let seed = 11;
    for (let i = 0; i < 600; i += 1) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      const at = base + Math.floor((seed / 2 ** 32) * 3 * DAY);
      records.push(rec(i % 7 === 0 ? Math.floor(at / (20 * MINUTE)) * 20 * MINUTE : at, "Warning", i));
    }
    // Events exactly on a bucket edge, which the half-open range must keep with the later bucket.
    const histogram = buildHistogram(records, "utc");
    for (const [a, b] of [[0, 0], [3, 9], [10, 10], [0, histogram.buckets.length - 1], [5, histogram.buckets.length - 1]]) {
      const range = { startMs: histogram.edges[a], endMs: histogram.edges[b + 1] };
      const inRange = records.filter((record) => isWithinTimeRange(record, range)).length;
      const counted = histogram.buckets.slice(a, b + 1).reduce((total, bucket) => total + bucket.total, 0);
      expect(inRange).toBe(counted);
    }
  });

  it("does the same in the host's local zone", () => {
    const base = utc(3, 1, 0, 0);
    const records = Array.from({ length: 400 }, (_, i) => rec(base + i * 37 * MINUTE + (i % 5) * SECOND, "Error", i));
    const histogram = buildHistogram(records, "local");
    expect(histogram.placed).toBe(400);
    expect(histogram.edges.length - 1).toBeLessThanOrEqual(MAX_BUCKETS);
    for (const width of deltas(histogram.edges)) expect(width).toBeGreaterThan(0);
    for (const [a, b] of [[0, 4], [2, 2], [4, histogram.buckets.length - 1]]) {
      const range = { startMs: histogram.edges[a], endMs: histogram.edges[b + 1] };
      expect(records.filter((record) => isWithinTimeRange(record, range)).length).toBe(
        histogram.buckets.slice(a, b + 1).reduce((total, bucket) => total + bucket.total, 0),
      );
    }
    expect(zoneClockFor("local").instant(zoneClockFor("local").wall(base))).toBe(base);
  });

  it("reads each record a fixed number of times, whatever the number of buckets", () => {
    const readsFor = (spanMs: number) => {
      const reads = { time: 0, level: 0 };
      const count = 2000;
      const base = utc(10, 6, 0, 0);
      const records = Array.from({ length: count }, (_, i) => {
        const at = base + Math.floor((i / (count - 1)) * spanMs);
        const record = rec(0, "Information", i);
        Object.defineProperty(record, "timestampEpoch", {
          get: () => {
            reads.time += 1;
            return at;
          },
        });
        Object.defineProperty(record, "level", {
          get: () => {
            reads.level += 1;
            return "Information";
          },
        });
        return record;
      });
      const histogram = buildHistogram(records, "utc");
      return { reads, buckets: histogram.buckets.length, count };
    };
    const few = readsFor(10 * MINUTE);
    const many = readsFor(30 * HOUR);
    expect(many.buckets).toBeGreaterThanOrEqual(48);
    expect(few.reads).toEqual(many.reads);
    // Two passes at most, each reading the time a handful of times, and the level once.
    expect(many.reads.time / many.count).toBeLessThanOrEqual(8);
    expect(many.reads.level / many.count).toBeLessThanOrEqual(1);
  });

  it("rebuckets 100,000 records within a generous ceiling, and prints the figure", () => {
    const count = 100_000;
    const base = utc(10, 1, 0, 0);
    const levels: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
    let seed = 7;
    const records = Array.from({ length: count }, (_, i) => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return rec(base + Math.floor((seed / 2 ** 32) * 7 * DAY), levels[i % 5], i);
    });
    const timings: number[] = [];
    let histogram: EvtxHistogram | null = null;
    for (let run = 0; run < 5; run += 1) {
      const started = performance.now();
      histogram = buildHistogram(records, "utc");
      timings.push(performance.now() - started);
    }
    timings.sort((a, b) => a - b);
    const median = timings[2];
    // The spec's figure is 50 ms on the Windows dev box (lab item). CI only guards against a gross
    // regression such as Intl formatting per record (about 600 ms here); the one-pass test above is
    // the structural guard.
    console.info(`[evtx-histogram] 100,000 records rebucketed in ${median.toFixed(1)} ms (median of 5)`);
    expect(histogram?.placed).toBe(count);
    expect(median).toBeLessThan(250);
  });
});

describe("zones", () => {
  it("steps whole local days, so a day is 23 hours when the clocks go forward and 25 when they go back", () => {
    const forward = bucketEdges(utc(3, 7, 12), utc(3, 10, 12), DAY, NEW_YORK);
    expect(forward[0]).toBe(Date.UTC(2026, 2, 7, 5));
    expect(deltas(forward).map((delta) => delta / HOUR)).toEqual([24, 23, 24, 24]);
    const back = bucketEdges(utc(10, 31, 12), utc(11, 3, 12), DAY, NEW_YORK);
    expect(deltas(back).map((delta) => delta / HOUR)).toEqual([24, 25, 24, 24]);
  });

  it("keeps every bucket below a day the same real length across a DST change, with the labels shifting", () => {
    const edges = bucketEdges(utc(3, 7, 12), utc(3, 9, 12), 6 * HOUR, NEW_YORK);
    expect(new Set(deltas(edges))).toEqual(new Set([6 * HOUR]));
    // The first edge is on the local 6 hour grid: 12:00Z is 07:00 EST, so the grid mark is 06:00 EST.
    expect(edges[0]).toBe(Date.UTC(2026, 2, 7, 11));
  });

  it("starts at the first record, not an hour before it, when its wall time is the repeated hour of a fall-back", () => {
    // 1 Nov 2026 01:30 EST (06:30Z) is the second 01:30 that night. The wall time floors to 01:30,
    // which a clock resolves to the FIRST one (EDT, 05:30Z), an hour earlier.
    const first = Date.UTC(2026, 10, 1, 6, 30);
    const edges = bucketEdges(first, first + 59 * MINUTE, MINUTE, NEW_YORK);
    expect(edges[0]).toBe(first);
    const histogram = buildHistogram([rec(first), rec(first + 59 * MINUTE, "Warning", 2)], "utc", NEW_YORK);
    expect(histogram.intervalMs).toBe(MINUTE);
    expect(histogram.edges[0]).toBe(first);
    expect(histogram.buckets[0].total).toBe(1);
    expect(histogram.buckets).toHaveLength(60);
    expect(histogram.buckets.filter((bucket) => bucket.total === 0).length).toBe(58);
  });

  it("aligns hour buckets to a zone that sits at +5:30 and 20 minute buckets to one at +5:45", () => {
    const hours = bucketEdges(utc(10, 1, 10, 10), utc(10, 1, 14, 0), HOUR, KOLKATA);
    expect(hours[0]).toBe(Date.UTC(2026, 9, 1, 9, 30));
    expect(hours.every((edge) => new Date(edge).getUTCMinutes() === 30)).toBe(true);
    const twenty = bucketEdges(utc(10, 1, 10, 10), utc(10, 1, 12, 0), 20 * MINUTE, KATHMANDU);
    expect(twenty.every((edge) => [15, 35, 55].includes(new Date(edge).getUTCMinutes()))).toBe(true);
    expect(twenty[0]).toBeLessThanOrEqual(utc(10, 1, 10, 10));
  });

  it("builds a whole histogram on a half-hour zone with every record placed once and edges that cover them", () => {
    const base = utc(10, 1, 3, 17);
    const records = Array.from({ length: 300 }, (_, i) => rec(base + i * 11 * MINUTE, "Warning", i));
    const histogram = buildHistogram(records, "utc", KOLKATA);
    expect(histogram.placed).toBe(300);
    expect(histogram.edges[0]).toBeLessThanOrEqual(base);
    expect(histogram.edges[histogram.edges.length - 1]).toBeGreaterThan(records[records.length - 1].timestampEpoch);
    expect(histogram.edges.every((edge) => new Date(edge).getUTCMinutes() % 30 === 0)).toBe(true);
  });
});

describe("positions on the plot", () => {
  const records = Array.from({ length: 48 }, (_, i) => rec(utc(10, 6, 0, 0) + i * 30 * MINUTE));
  const histogram = buildHistogram(records, "utc");
  const count = histogram.buckets.length;

  it("puts bucket edges at their share of the plot and a point inside a bucket part of the way across it", () => {
    expect(fractionAt(histogram, histogram.edges[0])).toBe(0);
    expect(fractionAt(histogram, histogram.edges[count])).toBe(1);
    expect(fractionAt(histogram, histogram.edges[10])).toBeCloseTo(10 / count, 12);
    const half = histogram.edges[10] + (histogram.edges[11] - histogram.edges[10]) / 2;
    expect(fractionAt(histogram, half)).toBeCloseTo(10.5 / count, 12);
    expect(fractionAt(histogram, histogram.edges[0] - histogram.intervalMs)).toBeLessThan(0);
    expect(fractionAt(histogram, histogram.edges[count] + histogram.intervalMs)).toBeGreaterThan(1);
  });

  it("finds the bucket of an instant, and none outside the domain", () => {
    expect(bucketIndexAt(histogram, histogram.edges[3])).toBe(3);
    expect(bucketIndexAt(histogram, histogram.edges[4] - 1)).toBe(3);
    expect(bucketIndexAt(histogram, histogram.edges[0] - 1)).toBe(-1);
    expect(bucketIndexAt(histogram, histogram.edges[count])).toBe(-1);
  });

  it("clips a range that runs past the plot, and reports one wholly outside as none", () => {
    const inside = rangeOnPlot(histogram, { startMs: histogram.edges[2], endMs: histogram.edges[5] });
    expect(inside).toEqual({ left: 2 / count, right: 5 / count, clippedLeft: false, clippedRight: false });
    const partly = rangeOnPlot(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[4] });
    expect(partly).toMatchObject({ left: 0, clippedLeft: true, clippedRight: false });
    const over = rangeOnPlot(histogram, { startMs: histogram.edges[count - 2], endMs: histogram.edges[count] + HOUR });
    expect(over).toMatchObject({ right: 1, clippedRight: true });
    expect(rangeOnPlot(histogram, { startMs: histogram.edges[count], endMs: histogram.edges[count] + HOUR })).toBeNull();
    expect(rangeOnPlot(histogram, { startMs: histogram.edges[0] - HOUR, endMs: histogram.edges[0] })).toBeNull();
    expect(rangeOnPlot(buildHistogram([], "utc"), { startMs: 1, endMs: 2 })).toBeNull();
  });
});

describe("text", () => {
  const bucket = (counts: Partial<Record<EvtxLevel, number>>, startMs = utc(10, 6, 9, 0)): HistogramBucket => {
    const full = { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0, ...counts };
    return {
      startMs,
      endMs: startMs + 20 * MINUTE,
      counts: full,
      total: Object.values(full).reduce((a, b) => a + b, 0),
    };
  };

  it("reads a bucket as the spec's tooltip does, with the range separator and the zone", () => {
    expect(describeBucket(bucket({ Error: 3, Warning: 5, Information: 40 }), "utc")).toBe(
      `09:00${TIME_RANGE_SEPARATOR}09:20 \u00b7 3 errors, 5 warnings, 40 info (UTC)`,
    );
  });

  it("uses the singular for one, and names Critical and Verbose only when there are some", () => {
    expect(describeCounts(bucket({ Error: 1, Warning: 1, Information: 1 }))).toBe("1 error, 1 warning, 1 info");
    expect(describeCounts(bucket({ Critical: 2, Information: 4 }))).toBe(
      "2 critical, 0 errors, 0 warnings, 4 info",
    );
    expect(describeCounts(bucket({ Verbose: 9, Information: 1 }))).toBe("0 errors, 0 warnings, 1 info, 9 verbose");
  });

  it("lists the spec's trio as zeros for an empty bucket, and never says 'no events'", () => {
    expect(describeCounts(bucket({}))).toBe("0 errors, 0 warnings, 0 info");
    expect(describeBucket(bucket({}), "utc")).toBe(
      `09:00${TIME_RANGE_SEPARATOR}09:20 \u00b7 0 errors, 0 warnings, 0 info (UTC)`,
    );
  });

  it("writes thousands with separators", () => {
    expect(describeCounts(bucket({ Information: 12345 }))).toContain("12,345 info");
  });

  it("gives a bucket across a DST change its own zone", () => {
    const local = describeBucket(bucket({ Information: 1 }, utc(3, 8, 6, 0)), "local");
    expect(local).toMatch(/\(UTC[+-]\d\d:\d\d\)$/);
  });

  it("names the interval in whole units, singular for one", () => {
    expect(describeInterval(20 * MINUTE)).toBe("20 minutes");
    expect(describeInterval(HOUR)).toBe("1 hour");
    expect(describeInterval(2 * HOUR)).toBe("2 hours");
    expect(describeInterval(DAY)).toBe("1 day");
    expect(describeInterval(30 * SECOND)).toBe("30 seconds");
    expect(describeInterval(730 * DAY)).toBe("730 days");
  });

  it("names the figure by its interval, the span charted and the zone", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 10, 20, 47)), rec(utc(10, 7, 10, 19, 59))], "utc");
    expect(describeFigure(histogram, "utc")).toBe(
      `Events per 20 minutes over Oct 6 10:20${TIME_RANGE_SEPARATOR}Oct 7 10:20 (UTC), stacked by level`,
    );
  });

  it("reads a zero-offset local zone as UTC+00:00, which is what the capture's figure name must match", () => {
    // The screenshot spec leaves the store in local mode and pins the browser zone to UTC (e2e
    // event-logs.spec.ts), so the figure's name ends with the offset form, not the word UTC.
    const spy = vi.spyOn(Date.prototype, "getTimezoneOffset").mockReturnValue(0);
    try {
      const histogram = buildHistogram([rec(utc(10, 6, 10, 20, 47)), rec(utc(10, 7, 10, 19, 59))], "local");
      expect(describeFigure(histogram, "local")).toMatch(/ \(UTC\+00:00\), stacked by level$/);
      expect(describeFigure(histogram, "local")).not.toMatch(/\(UTC\)/);
      expect(describeFigure(buildHistogram([rec(utc(10, 6, 10, 20, 47))], "utc"), "utc")).toMatch(/ \(UTC\), stacked by level$/);
    } finally {
      spy.mockRestore();
    }
  });

  it("writes the untimed and coverage notes, singular for one", () => {
    expect(describeUntimed(1)).toBe("1 event without a timestamp is not charted.");
    expect(describeUntimed(2500)).toBe("2,500 events without a timestamp are not charted.");
    expect(describeCoverage(1)).toContain("1 gap in this view");
    expect(describeCoverage(3)).toContain("3 gaps in this view");
  });
});

describe("axis ticks", () => {
  it("makes seven evenly spaced labels, each on a bucket edge", () => {
    const histogram = buildHistogram([rec(utc(10, 6, 9, 0)), rec(utc(10, 6, 14, 59))], "utc");
    const ticks = buildAxisTicks(histogram, "utc");
    expect(ticks).toHaveLength(7);
    expect(ticks[0]).toMatchObject({ edgeIndex: 0, fraction: 0, label: "09:00" });
    expect(ticks[ticks.length - 1]).toMatchObject({ fraction: 1, label: "15:00" });
    const count = histogram.buckets.length;
    for (const tick of ticks) {
      expect(tick.fraction).toBeCloseTo(tick.edgeIndex / count, 12);
      expect(Math.abs(tick.edgeIndex - (ticks.indexOf(tick) * count) / 6)).toBeLessThanOrEqual(0.5);
    }
  });

  it("adds the day when the span crosses one, and seconds when buckets are under a minute", () => {
    const across = buildAxisTicks(
      buildHistogram([rec(utc(10, 6, 22, 0)), rec(utc(10, 7, 3, 0))], "utc"),
      "utc",
    );
    expect(across[0].label).toBe("Oct 6 22:00");
    const quick = buildAxisTicks(buildHistogram([rec(utc(10, 6, 9, 0, 0)), rec(utc(10, 6, 9, 0, 40))], "utc"), "utc");
    expect(quick[0].label).toBe("09:00:00");
  });

  it("makes fewer labels when there are fewer than six buckets, without repeating one", () => {
    const one = buildAxisTicks(buildHistogram([rec(utc(10, 6, 9, 0, 0, 5))], "utc"), "utc");
    expect(one.map((tick) => tick.edgeIndex)).toEqual([0, 1]);
    expect(buildAxisTicks(buildHistogram([], "utc"), "utc")).toEqual([]);
  });
});

describe("bar geometry", () => {
  const buildOf = (rows: Partial<Record<EvtxLevel, number>>[]): EvtxHistogram => {
    const base = utc(10, 6, 0, 0);
    const records: EvtxRecord[] = [];
    rows.forEach((row, index) => {
      for (const [level, count] of Object.entries(row)) {
        for (let n = 0; n < (count as number); n += 1) {
          records.push(rec(base + index * 20 * MINUTE + n, level as EvtxLevel, records.length));
        }
      }
    });
    return buildHistogram(records, "utc");
  };

  it("fits the tallest bucket in the bar area and gives it the room it can", () => {
    const histogram = buildOf([{ Information: 1000, Error: 50 }, { Information: 10 }]);
    const scale = fitScale(histogram);
    const heights = histogram.buckets.map((bucket) =>
      bucketSegments(bucket, scale).reduce((total, segment) => total + segment.heightPx, 0),
    );
    expect(Math.max(...heights)).toBeLessThanOrEqual(HISTOGRAM_BAR_AREA_PX);
    expect(Math.max(...heights)).toBeGreaterThanOrEqual(HISTOGRAM_BAR_AREA_PX - 3);
  });

  it("never draws a non-empty segment with under 2 px of colour, even one Critical event in a tall bucket", () => {
    const histogram = buildOf([{ Information: 5000, Critical: 1 }]);
    const segments = bucketSegments(histogram.buckets[0], fitScale(histogram));
    const critical = segments.find((segment) => segment.level === "Critical")!;
    // The segment's height includes its 1 px separator, so 2 px of colour is a 3 px segment.
    expect(critical.heightPx - SEPARATOR_PX).toBe(MIN_SEGMENT_PX);
    expect(MIN_SEGMENT_PX).toBe(2);
    expect(SEPARATOR_PX).toBe(1);
    for (const segment of segments) {
      expect(segment.heightPx - SEPARATOR_PX).toBeGreaterThanOrEqual(MIN_SEGMENT_PX);
    }
    const total = segments.reduce((sum, segment) => sum + segment.heightPx, 0);
    expect(total).toBeLessThanOrEqual(HISTOGRAM_BAR_AREA_PX);
  });

  it("fits the area even when every level is present and the counts are small", () => {
    const histogram = buildOf([{ Critical: 1, Error: 1, Warning: 1, Information: 1, Verbose: 1 }]);
    const segments = bucketSegments(histogram.buckets[0], fitScale(histogram));
    expect(segments).toHaveLength(5);
    expect(segments.reduce((total, segment) => total + segment.heightPx, 0)).toBeLessThanOrEqual(HISTOGRAM_BAR_AREA_PX);
  });

  it("stacks bottom to top as Verbose, Info, Warning, Error, Critical, and omits an empty level", () => {
    const histogram = buildOf([{ Critical: 3, Information: 4, Verbose: 2 }]);
    const segments = bucketSegments(histogram.buckets[0], 4);
    expect(segments.map((segment) => segment.level)).toEqual(["Verbose", "Information", "Critical"]);
    expect([...HISTOGRAM_STACK_ORDER]).toEqual(["Verbose", "Information", "Warning", "Error", "Critical"]);
  });

  it("scales taller counts taller, in proportion once above the floor", () => {
    const histogram = buildOf([{ Information: 100 }, { Information: 50 }]);
    const scale = fitScale(histogram);
    const [tall, short] = histogram.buckets
      .filter((bucket) => bucket.total > 0)
      .map((bucket) => bucketSegments(bucket, scale)[0].heightPx);
    expect(tall).toBeGreaterThan(short);
    expect(Math.abs(tall - 2 * short)).toBeLessThanOrEqual(1);
  });

  it("has no scale when nothing is placed", () => {
    expect(fitScale(buildHistogram([], "utc"))).toBe(0);
  });
});

describe("the year in day labels", () => {
  const on = (year: number, month: number, day: number, hour = 0, minute = 0) =>
    Date.UTC(year, month - 1, day, hour, minute);
  const SEP = TIME_RANGE_SEPARATOR;

  it("names the year on the axis, the figure and every bucket when the span crosses a calendar year", () => {
    const histogram = buildHistogram([rec(on(2024, 1, 5)), rec(on(2026, 10, 1))], "utc");
    expect(histogram.showYear).toBe(true);
    const ticks = buildAxisTicks(histogram, "utc");
    expect(ticks[0].label).toMatch(/^[A-Z][a-z]{2} \d{1,2} 2024 00:00$/);
    expect(ticks[ticks.length - 1].label).toMatch(/ 2026 /);
    expect(describeFigure(histogram, "utc")).toMatch(/over [A-Z][a-z]{2} \d{1,2} 2024 00:00.*2026 00:00 \(UTC\)/);
    for (const bucket of histogram.buckets) {
      expect(describeBucket(bucket, "utc", histogram.showYear)).toMatch(/ \d{4} \d\d:\d\d.* \d{4} \d\d:\d\d \u00b7 /);
    }
  });

  it("names the year for a span of hours that crosses New Year", () => {
    const histogram = buildHistogram([rec(on(2025, 12, 31, 22)), rec(on(2026, 1, 1, 3))], "utc");
    expect(histogram.showYear).toBe(true);
    expect(buildAxisTicks(histogram, "utc")[0].label).toBe("Dec 31 2025 22:00");
    expect(describeBucket(histogram.buckets[0], "utc", histogram.showYear)).toMatch(/^Dec 31 2025 22:/);
  });

  it("leaves the year out when the span stays inside one year", () => {
    const histogram = buildHistogram([rec(on(2026, 3, 2)), rec(on(2026, 9, 20))], "utc");
    expect(histogram.showYear).toBe(false);
    expect(buildAxisTicks(histogram, "utc")[0].label).toMatch(/^Mar \d{1,2} \d\d:\d\d$/);
    expect(describeFigure(histogram, "utc")).not.toMatch(/2026/);
    expect(describeBucket(histogram.buckets[0], "utc", histogram.showYear)).not.toMatch(/2026/);
  });

  it("always names the year on the 365 day rung, and no bucket reads with its start equal to its end", () => {
    const histogram = buildHistogram([rec(on(2000, 3, 1)), rec(on(2026, 9, 1))], "utc");
    expect(histogram.intervalMs).toBe(365 * DAY);
    expect(histogram.showYear).toBe(true);
    for (const bucket of histogram.buckets) {
      const [start, end] = describeBucket(bucket, "utc", histogram.showYear).split(" \u00b7 ")[0].split(SEP);
      expect(start).not.toBe(end);
      expect(start).toMatch(/ \d{4} \d\d:\d\d$/);
    }
  });

  it("names the year on a chart of a single past year, on its axis, figure, buckets and nowhere ambiguous", () => {
    const histogram = buildHistogram([rec(on(2024, 3, 3)), rec(on(2024, 9, 1))], "utc");
    // The span is inside one calendar year, but not the current one (2026): 'Mar 3' would not say which.
    expect(histogram.showYear).toBe(true);
    expect(buildAxisTicks(histogram, "utc")[0].label).toMatch(/^Mar 3 2024 00:00$/);
    expect(describeFigure(histogram, "utc")).toMatch(/over Mar 3 2024 00:00.*Sep \d{1,2} 2024 00:00 \(UTC\)/);
    for (const bucket of histogram.buckets) {
      expect(describeBucket(bucket, "utc", histogram.showYear)).toMatch(/ 2024 \d\d:\d\d.* 2024 \d\d:\d\d \u00b7 /);
    }
  });

  it("names no year on a chart within the current year", () => {
    const histogram = buildHistogram([rec(on(2026, 3, 3)), rec(on(2026, 9, 1))], "utc");
    expect(histogram.showYear).toBe(false);
    expect(buildAxisTicks(histogram, "utc")[0].label).toMatch(/^Mar 3 00:00$/);
    expect(describeFigure(histogram, "utc")).not.toMatch(/\b20\d\d\b/);
  });

  it("compares with the clock it is given: the same chart names the year in another year", () => {
    const records = [rec(on(2026, 3, 3)), rec(on(2026, 9, 1))];
    expect(buildHistogram(records, "utc", UTC_CLOCK, on(2026, 10, 16)).showYear).toBe(false);
    expect(buildHistogram(records, "utc", UTC_CLOCK, on(2030, 1, 1)).showYear).toBe(true);
  });

  it("uses the one label rule, the Time chip's: showYear is timeRangeNeedsYear of the domain", () => {
    const samples: [number, number][] = [
      [on(2026, 3, 3), on(2026, 9, 1)],
      [on(2024, 3, 3), on(2024, 9, 1)],
      [on(2025, 12, 31, 22), on(2026, 1, 1, 3)],
      [on(2000, 3, 1), on(2026, 9, 1)],
      [on(2027, 1, 5), on(2027, 1, 6)],
    ];
    for (const [from, to] of samples) {
      const histogram = buildHistogram([rec(from), rec(to)], "utc");
      expect(histogram.showYear, `${new Date(from).toISOString()}`).toBe(
        timeRangeNeedsYear(histogram.domain!.startMs, histogram.domain!.endMs, "utc", PINNED_NOW),
      );
    }
  });

  it("names the year on a 365 day rung even when the span sits inside one calendar year", () => {
    // A wider-than-a-year bucket always spans a year boundary in its label, whatever the domain.
    const histogram = buildHistogram([rec(on(2026, 3, 1)), rec(on(2026, 3, 2))], "utc");
    expect(histogram.showYear).toBe(false);
    const wide = { startMs: on(2026, 2, 14), endMs: on(2027, 2, 14), counts: histogram.buckets[0].counts, total: 0 };
    expect(describeBucket(wide, "utc", true)).toContain("Feb 14 2026 00:00");
  });
});

describe("no bucket ever reads with its two ends alike", () => {
  const SEP = TIME_RANGE_SEPARATOR;
  const LONDON = syntheticZone(LONDON_2026, [0, 60]);
  // The fall-back: the hour 00:00Z to 01:00Z on 25 Oct 2026 is 01:00 BST, then 01:00 GMT again.
  const FALL_BACK = Date.UTC(2026, 9, 25, 0);
  /** Every rung of the ladder, and the 365 day multiples the fallback takes beyond it. */
  const RUNGS = [...HISTOGRAM_INTERVALS_MS, 2 * 365 * DAY, 3 * 365 * DAY];

  const zones = [
    { name: "UTC", mode: "utc" as const, clock: UTC_CLOCK, model: null },
    { name: "a modelled London fall-back", mode: "local" as const, clock: LONDON, model: LONDON_2026 },
  ];

  /** The buckets of one rung, aligned, around the fall-back or from the start of the current year. */
  const bucketsOf = (rung: number, clock: ZoneClock): HistogramBucket[] => {
    const subDay = rung < DAY;
    const min = subDay ? FALL_BACK - 30 * rung : Date.UTC(2026, 0, 1);
    const max = subDay ? FALL_BACK + 30 * rung : min + 40 * rung - 1;
    const edges = bucketEdges(min, max, rung, clock);
    return edges.slice(1).map((end, index) => ({
      startMs: edges[index],
      endMs: end,
      counts: { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0 },
      total: 0,
    }));
  };

  for (const zone of zones) {
    it(`reads the ends of every bucket of every rung apart, in ${zone.name}`, () => {
      const restore = zone.model === null ? () => undefined : modelZone(zone.model);
      try {
        let checked = 0;
        for (const rung of RUNGS) {
          const buckets = bucketsOf(rung, zone.clock);
          const withYear = timeRangeNeedsYear(
            buckets[0].startMs,
            buckets[buckets.length - 1].endMs,
            zone.mode,
            PINNED_NOW,
          );
          for (const bucket of buckets) {
            const context = `${zone.name}, rung ${rung / SECOND} s, ${new Date(bucket.startMs).toISOString()}`;
            const range = formatTimeRange(bucket.startMs, bucket.endMs, zone.mode, withYear);
            const [from, to] = range.split(SEP);
            expect(to, context).toBeDefined();
            expect(from, context).not.toBe(to);
            const [text] = describeBucket(bucket, zone.mode, withYear).split(" \u00b7 ");
            const [textFrom, textTo] = text.split(SEP);
            expect(textFrom, context).not.toBe(textTo);
            // A span of a second or more is told apart without milliseconds: that step is for under one.
            expect(range, context).not.toMatch(/\.\d{3}/);
            checked += 1;
          }
        }
        expect(checked).toBeGreaterThan(600);
      } finally {
        restore();
      }
    });
  }

  it("reads a current-year 1 day bucket with its date, not as 00:00 to 00:00", () => {
    const histogram = buildHistogram([rec(Date.UTC(2026, 7, 1)), rec(Date.UTC(2026, 9, 15))], "utc");
    expect(histogram.intervalMs).toBe(DAY);
    expect(histogram.showYear).toBe(false);
    expect(describeBucket(histogram.buckets[0], "utc", histogram.showYear)).toBe(
      `Aug 1 00:00${SEP}Aug 2 00:00 \u00b7 0 errors, 0 warnings, 1 info (UTC)`,
    );
  });
});
