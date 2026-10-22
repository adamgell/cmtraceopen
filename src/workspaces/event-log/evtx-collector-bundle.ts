/**
 * The collector's bundle id, read off a source path: a mirror of the engine's `bundle_from_source`
 * and `is_collector_bundle_id` (crates/cmtraceopen-parser/src/unified_timeline/mod.rs). The engine
 * computes a log origin's `bundle` from the record's source label with those functions, so a log
 * origin can only be matched to a record if this agrees with them. Pinned to the Rust text by
 * evtx-bundle-source-pin.test.ts and to its accepted and rejected examples by this module's test.
 */

const BUNDLE_PREFIX = "cmtrace-";
const BUNDLE_NONCE_LENGTH = 32;

function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * The collector's generated bundle-directory id: `CMTRACE-{yyyyMMdd}-{HHmmss}-{host}-{32 hex}`, with
 * a real calendar date from year 1 and a real time of day. A mirror of `is_collector_bundle_id` in
 * crates/cmtraceopen-parser/src/unified_timeline/mod.rs; the origin's `bundle` is computed from the
 * source label by that function, so a log origin can only be matched if this agrees with it. Its
 * test pins the engine's own accepted and rejected examples.
 */
function isCollectorBundleId(segment: string): boolean {
  if (segment.length < BUNDLE_PREFIX.length || segment.slice(0, BUNDLE_PREFIX.length).toLowerCase() !== BUNDLE_PREFIX) {
    return false;
  }
  const rest = segment.slice(BUNDLE_PREFIX.length);
  const firstDash = rest.indexOf("-");
  if (firstDash < 0) return false;
  const secondDash = rest.indexOf("-", firstDash + 1);
  if (secondDash < 0) return false;
  const date = rest.slice(0, firstDash);
  const time = rest.slice(firstDash + 1, secondDash);
  const hostAndNonce = rest.slice(secondDash + 1);
  const lastDash = hostAndNonce.lastIndexOf("-");
  if (lastDash < 0) return false;
  const hostname = hostAndNonce.slice(0, lastDash);
  const nonce = hostAndNonce.slice(lastDash + 1);
  if (!/^\d{8}$/.test(date) || !/^\d{6}$/.test(time)) return false;
  const year = Number(date.slice(0, 4));
  const month = Number(date.slice(4, 6));
  const day = Number(date.slice(6, 8));
  const validDate = year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth(year, month);
  const validTime =
    Number(time.slice(0, 2)) < 24 && Number(time.slice(2, 4)) < 60 && Number(time.slice(4, 6)) < 60;
  return (
    validDate &&
    validTime &&
    hostname !== "" &&
    nonce.length === BUNDLE_NONCE_LENGTH &&
    /^[0-9a-fA-F]+$/.test(nonce)
  );
}

/**
 * The bundle id of a source path laid out as `{bundle id}/evidence/...`, or null: the first pair of
 * path segments (split on `/` and `\`, empty segments dropped) whose second is "evidence" (any case)
 * and whose first is a collector bundle id. A mirror of `bundle_from_source` in the parser crate.
 */
export function bundleOfSource(source: string): string | null {
  const segments = source.split(/[/\\]/).filter((segment) => segment !== "");
  for (let i = 0; i + 1 < segments.length; i += 1) {
    const bundle = segments[i] as string;
    if ((segments[i + 1] as string).toLowerCase() === "evidence" && isCollectorBundleId(bundle)) {
      return bundle;
    }
  }
  return null;
}
