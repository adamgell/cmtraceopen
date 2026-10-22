/**
 * Drift guard for the bundle mirror (the style of evtx-engine-compaction-pin.test.ts): the Rust
 * rules that `bundleOfSource` and the log matcher copy, pinned in the Rust source. If the engine
 * changes any of them this file fails and says which, and `isCollectorBundleId` and `bundleOfSource`
 * (evtx-collector-bundle.ts) and `logOriginNamesRecord` (evtx-correlation-origin-index.ts) have to be
 * revisited with it.
 *
 * Pinned, each as the function's source with whitespace and `//` comments ignored, so reformatting
 * and a reworded comment do not matter:
 * - crates/cmtraceopen-parser/src/unified_timeline/mod.rs: `is_collector_bundle_id` (the prefix
 *   word and its case rule, the three dash-separated fields and the split before the nonce, the
 *   date and time shapes, the year, calendar and time-of-day bounds, the host, the nonce length and
 *   its hex digits) and `bundle_from_source` (the separators, the empty-segment filter, the pair of
 *   segments, the case-insensitive "evidence", the first match);
 * - src-tauri/src/event_log/timeline.rs: the Log arm of `origin_of` (which record fields become the
 *   origin's file, component, line, source, machine, bundle and record id). The normalization it
 *   calls (`normalized_provenance`, `machine_of`, `component_of`) and the Event arm are pinned in
 *   evtx-engine-compaction-pin.test.ts, so they are not repeated here.
 *
 * What it does not prove, as text-scan limits: it pins the text of those functions, not their
 * behavior (the parser crate's own tests pin the behavior, and origin-index.test.ts holds the
 * engine's accepted and rejected examples); a rule moved into a function it does not name, or a new
 * place that derives a bundle, is not seen; and a change to chrono's date rules is not seen.
 */
import { describe, expect, it } from "vitest";
import parserTimelineSource from "../../../crates/cmtraceopen-parser/src/unified_timeline/mod.rs?raw";
import timelineSource from "../../../src-tauri/src/event_log/timeline.rs?raw";
import { itemText, squashCode } from "./rust-source-test-helpers";

const IS_COLLECTOR_BUNDLE_ID = `
fn is_collector_bundle_id(segment: &str) -> bool {
    const PREFIX: &str = "CMTRACE-";
    const NONCE_LENGTH: usize = 32;

    let Some(prefix) = segment.get(..PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    let mut parts = segment[PREFIX.len()..].splitn(3, '-');
    let (Some(date), Some(time), Some(host_and_nonce)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some((hostname, nonce)) = host_and_nonce.rsplit_once('-') else {
        return false;
    };
    let valid_date = date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit()) && {
        let year = date[..4].parse::<i32>().expect("validated year digits");
        let month = date[4..6].parse::<u32>().expect("validated month digits");
        let day = date[6..8].parse::<u32>().expect("validated day digits");
        year >= 1 && chrono::NaiveDate::from_ymd_opt(year, month, day).is_some()
    };
    let valid_time = time.len() == 6 && time.bytes().all(|byte| byte.is_ascii_digit()) && {
        let hour = time[..2].parse::<u32>().expect("validated hour digits");
        let minute = time[2..4].parse::<u32>().expect("validated minute digits");
        let second = time[4..6].parse::<u32>().expect("validated second digits");
        chrono::NaiveTime::from_hms_opt(hour, minute, second).is_some()
    };
    valid_date
        && valid_time
        && !hostname.is_empty()
        && nonce.len() == NONCE_LENGTH
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}
`;

const BUNDLE_FROM_SOURCE = `
pub fn bundle_from_source(source: &str) -> Option<String> {
    let segments = source
        .split(['/', '\\\\'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    segments.windows(2).find_map(|pair| {
        let [bundle_id, evidence] = pair else {
            return None;
        };
        (evidence.eq_ignore_ascii_case("evidence") && is_collector_bundle_id(bundle_id))
            .then(|| (*bundle_id).to_string())
    })
}
`;

const LOG_ARM = `
    if record.origin_kind == EvtxOriginKind::Log {
        return TimelineOrigin::Log {
            file: record.source_label.clone(),
            component: component_of(&record.provider),
            line: u32::try_from(record.event_record_id).unwrap_or(u32::MAX),
            source: record.source_label.clone(),
            machine: machine_of(&record.computer),
            bundle: bundle_from_source(&record.source_label),
            record_id: record.event_record_id,
        };
    }
`;

describe("the bundle id rule the log matcher mirrors", () => {
  const collectorId = itemText(parserTimelineSource, "fn is_collector_bundle_id(");
  const bundleFromSource = itemText(parserTimelineSource, "pub fn bundle_from_source(");

  it("is the same function as the one this repository's mirror was written from", () => {
    expect(squashCode(collectorId)).toBe(squashCode(IS_COLLECTOR_BUNDLE_ID));
    expect(squashCode(bundleFromSource)).toBe(squashCode(BUNDLE_FROM_SOURCE));
  });

  describe("and, so that a failure names the rule that changed, each rule on its own", () => {
    const id = squashCode(collectorId);

    it("the prefix word, matched without regard to ASCII case", () => {
      expect(id).toContain('constPREFIX:&str="CMTRACE-";');
      expect(id).toContain("segment.get(..PREFIX.len())");
      expect(id).toContain("prefix.eq_ignore_ascii_case(PREFIX)");
    });

    it("three dash-separated fields, then the host and the nonce split at the last dash", () => {
      expect(id).toContain("segment[PREFIX.len()..].splitn(3,'-')");
      expect(id).toContain("host_and_nonce.rsplit_once('-')");
    });

    it("the shapes: a date of 8 ASCII digits and a time of 6", () => {
      expect(id).toContain("date.len()==8&&date.bytes().all(|byte|byte.is_ascii_digit())");
      expect(id).toContain("time.len()==6&&time.bytes().all(|byte|byte.is_ascii_digit())");
    });

    it("the bounds: a year from 1, a real calendar date, a real time of day", () => {
      expect(id).toContain("year>=1&&chrono::NaiveDate::from_ymd_opt(year,month,day).is_some()");
      expect(id).toContain("chrono::NaiveTime::from_hms_opt(hour,minute,second).is_some()");
    });

    it("the host is not empty and the nonce is 32 hex digits", () => {
      expect(id).toContain("constNONCE_LENGTH:usize=32;");
      expect(id).toContain("!hostname.is_empty()");
      expect(id).toContain("nonce.len()==NONCE_LENGTH");
      expect(id).toContain("nonce.bytes().all(|byte|byte.is_ascii_hexdigit())");
    });

    it("bundle_from_source: either separator, empty segments dropped, the first pair whose second is 'evidence'", () => {
      const source = squashCode(bundleFromSource);
      expect(source).toContain(".split(['/','\\\\'])");
      expect(source).toContain(".filter(|segment|!segment.is_empty())");
      expect(source).toContain("segments.windows(2).find_map(|pair|");
      expect(source).toContain('evidence.eq_ignore_ascii_case("evidence")&&is_collector_bundle_id(bundle_id)');
    });
  });
});

describe("what the engine puts on a log origin", () => {
  const originOf = itemText(timelineSource, "fn origin_of(");

  it("builds it from an archive text row's own fields, as logOriginNamesRecord compares them", () => {
    expect(squashCode(originOf)).toContain(squashCode(LOG_ARM));
  });
});
