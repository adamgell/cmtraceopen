/**
 * A modelled time zone for tests, independent of the host's: `modelZone` replaces the local getters of
 * `Date` (the ones `evtx-time` reads) with a zone given as an offset function, so a DST fall-back can
 * be exercised under the UTC zone CI runs in. The technique is the one the zone-label tests use for
 * `getTimezoneOffset`, taken to the wall-clock getters as well.
 *
 * It does not touch the `Date` constructor, so code that builds an instant from local parts
 * (`LOCAL_CLOCK.instant`) must be given a `ZoneClock` of the same zone instead.
 */
import { vi } from "vitest";

/** Minutes east of UTC at an instant. */
export type OffsetAt = (epochMs: number) => number;

/** Europe/London in 2026: BST (UTC+01:00) from 29 Mar 01:00Z to 25 Oct 01:00Z, GMT otherwise. */
export const LONDON_2026: OffsetAt = (epochMs) =>
  epochMs >= Date.UTC(2026, 2, 29, 1) && epochMs < Date.UTC(2026, 9, 25, 1) ? 60 : 0;

/** America/New_York in 2026: EDT (UTC-04:00) from 8 Mar 07:00Z to 1 Nov 06:00Z, EST otherwise. */
export const NEW_YORK_2026: OffsetAt = (epochMs) =>
  epochMs >= Date.UTC(2026, 2, 8, 7) && epochMs < Date.UTC(2026, 10, 1, 6) ? -240 : -300;

const between = (epochMs: number, fromMs: number, toMs: number) => epochMs >= fromMs && epochMs < toMs;

/** Europe/London over two years: BST for 29 Mar to 25 Oct 2026 and for 28 Mar to 31 Oct 2027, GMT otherwise. */
export const LONDON_2026_2027: OffsetAt = (epochMs) =>
  between(epochMs, Date.UTC(2026, 2, 29, 1), Date.UTC(2026, 9, 25, 1)) ||
  between(epochMs, Date.UTC(2027, 2, 28, 1), Date.UTC(2027, 9, 31, 1))
    ? 60
    : 0;

/** America/New_York over two years: EDT for 9 Mar to 2 Nov 2025 and for 8 Mar to 1 Nov 2026, EST otherwise. */
export const NEW_YORK_2025_2026: OffsetAt = (epochMs) =>
  between(epochMs, Date.UTC(2025, 2, 9, 7), Date.UTC(2025, 10, 2, 6)) ||
  between(epochMs, Date.UTC(2026, 2, 8, 7), Date.UTC(2026, 10, 1, 6))
    ? -240
    : -300;

/** The instant of the first wall time repeated by the 2026 fall-back, as UTC: London's 01:00 BST. */
export const LONDON_REPEATED_HOUR_START = Date.UTC(2026, 9, 25, 0);

/**
 * Makes `Date`'s local getters read `offsetAt`'s zone. Returns the function that restores them; call
 * it in a `finally`, or from `afterEach`.
 */
export function modelZone(offsetAt: OffsetAt): () => void {
  const wall = (date: Date) => new Date(date.getTime() + offsetAt(date.getTime()) * 60_000);
  const spies = [
    vi.spyOn(Date.prototype, "getFullYear").mockImplementation(function (this: Date) {
      return wall(this).getUTCFullYear();
    }),
    vi.spyOn(Date.prototype, "getMonth").mockImplementation(function (this: Date) {
      return wall(this).getUTCMonth();
    }),
    vi.spyOn(Date.prototype, "getDate").mockImplementation(function (this: Date) {
      return wall(this).getUTCDate();
    }),
    vi.spyOn(Date.prototype, "getHours").mockImplementation(function (this: Date) {
      return wall(this).getUTCHours();
    }),
    vi.spyOn(Date.prototype, "getMinutes").mockImplementation(function (this: Date) {
      return wall(this).getUTCMinutes();
    }),
    vi.spyOn(Date.prototype, "getSeconds").mockImplementation(function (this: Date) {
      return wall(this).getUTCSeconds();
    }),
    vi.spyOn(Date.prototype, "getTimezoneOffset").mockImplementation(function (this: Date) {
      // Minutes *behind* UTC, so the sign is inverted.
      return -offsetAt(this.getTime()) || 0;
    }),
  ];
  return () => {
    for (const spy of spies) spy.mockRestore();
  };
}
