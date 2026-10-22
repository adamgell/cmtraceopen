/**
 * Drift guard: the engine rules the origin join and the evidence matcher copy, pinned in the Rust
 * source (the style of evtx-correlation-gaps-engine.test.ts). If the engine changes any of these,
 * this file fails and says which, and the frontend copy (`timelineTextMatches`, `evidenceTextMatches`,
 * `provenanceAgrees`, `engineTimelineRecordIdentity`) has to be revisited with the engine.
 *
 * Pinned, each as the function's source with whitespace ignored, so reformatting does not matter:
 * - timeline.rs: `MAX_TIMELINE_IDENTITY_TEXT_BYTES`, `compact_text_digest` (the two FNV lanes and
 *   their constants), `compact_timeline_text` (the suffix format, the prefix budget, the cut back
 *   to a character boundary), `normalized_provenance` (the placeholder words), which fields
 *   `compact_timeline_origin` compacts, that `origin_of` normalizes machine and component and copies
 *   the full source label, channel and provider, and that `push_event_record` compacts AFTER
 *   `origin_of`;
 * - analysis_session.rs: `MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES`, `display_text_digest` (the first
 *   lane), `compact_display_text`, which evidence fields `compact_evidence` compacts, and
 *   `sanitize_malformed_timeline_record` with the append branch that calls it for event records;
 * - commands.rs: `diagnosis_record_identity`;
 * - models.rs: `MAX_SAFE_EVENT_RECORD_ID` and the default origin kind.
 *
 * What it does not prove, as text-scan limits: it pins the text of those functions, not their
 * behavior (the Rust tests over `engine-compaction-vectors.json` pin the behavior); a rule moved into
 * a function it does not name, or a new place that compacts identity text, is not seen; a change to
 * `MAX_SAFE_EVENT_RECORD_ID` is seen but a helper that stops using it is not.
 */
import { describe, expect, it } from "vitest";
import analysisSessionSource from "../../../src-tauri/src/event_log/analysis_session.rs?raw";
import commandsSource from "../../../src-tauri/src/event_log/commands.rs?raw";
import modelsSource from "../../../src-tauri/src/event_log/models.rs?raw";
import timelineSource from "../../../src-tauri/src/event_log/timeline.rs?raw";
import { EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT } from "./event-analysis-session";
import { normalizedProvenance } from "./evtx-correlation-origin-index";
import {
  ENGINE_DIAGNOSIS_DISPLAY_TEXT_BYTES,
  ENGINE_TIMELINE_IDENTITY_TEXT_BYTES,
} from "./evtx-insights-data";
import { constantValue, itemText, squash } from "./rust-source-test-helpers";

describe("timeline.rs: identity text compaction", () => {
  it("limits identity text to the bytes the frontend copy assumes", () => {
    expect(constantValue(timelineSource, "MAX_TIMELINE_IDENTITY_TEXT_BYTES")).toBe(
      ENGINE_TIMELINE_IDENTITY_TEXT_BYTES,
    );
    // The transport's own bound is a different rule that happens to share the number.
    expect(EVENT_LOG_ANALYSIS_IDENTITY_BYTE_LIMIT).toBe(ENGINE_TIMELINE_IDENTITY_TEXT_BYTES);
  });

  it("digests the whole value with two FNV lanes", () => {
    expect(squash(itemText(timelineSource, "fn compact_text_digest("))).toBe(
      squash(`fn compact_text_digest(value: &str) -> String {
        let mut first = 2_166_136_261_u32;
        let mut second = first ^ 0x9e37_79b9;
        for &byte in value.as_bytes() {
            first = (first ^ u32::from(byte)).wrapping_mul(16_777_619);
            second = (second ^ u32::from(byte ^ 0xa5)).wrapping_mul(16_777_619);
        }
        format!("{first:08x}{second:08x}")
    }`),
    );
  });

  it("writes the prefix, then \"...[{len} bytes; digest={hex}]\", with a budget of the limit less the suffix, cut back to a character boundary", () => {
    expect(squash(itemText(timelineSource, "fn compact_timeline_text("))).toBe(
      squash(`fn compact_timeline_text(value: &str, max_bytes: usize) -> (String, bool) {
        if value.len() <= max_bytes {
            return (value.to_string(), false);
        }
        let suffix = format!(
            "...[{} bytes; digest={}]",
            value.len(),
            compact_text_digest(value)
        );
        let prefix_budget = max_bytes.saturating_sub(suffix.len());
        let mut prefix_end = prefix_budget.min(value.len());
        while prefix_end > 0 && !value.is_char_boundary(prefix_end) {
            prefix_end -= 1;
        }
        (format!("{}{}", &value[..prefix_end], suffix), true)
    }`),
    );
  });

  it("compacts the source label, channel and provider of an event origin, and the file and source of a log origin, at the identity limit", () => {
    const text = squash(itemText(timelineSource, "fn compact_timeline_origin("));
    expect(text).toContain(
      squash(`for value in [file, source] {
                let (compacted, value_changed) =
                    compact_timeline_text(value, MAX_TIMELINE_IDENTITY_TEXT_BYTES);`),
    );
    expect(text).toContain(
      squash(`for value in [stable_id, source, channel, provider] {
                let (compacted, value_changed) =
                    compact_timeline_text(value, MAX_TIMELINE_IDENTITY_TEXT_BYTES);`),
    );
  });

  it("compacts a machine and a component, as optional text at the same limit", () => {
    const text = squash(itemText(timelineSource, "fn compact_timeline_origin("));
    expect(text).toContain("changed|=compact_optional_timeline_text(component);");
    expect(text).toContain("changed|=compact_optional_timeline_text(machine);");
    expect(text).toContain("forvaluein[machine,bundle,activity_id,related_activity_id,session_id,device_id,user_id,process_start_time,record_id_text,]");
    expect(squash(itemText(timelineSource, "fn compact_optional_timeline_text("))).toContain(
      "compact_timeline_text(current,MAX_TIMELINE_IDENTITY_TEXT_BYTES)",
    );
  });

  it("normalizes a machine and a component (trim, then the placeholder words) before the origin is built", () => {
    expect(squash(itemText(timelineSource, "fn normalized_provenance("))).toBe(
      squash(`fn normalized_provenance(value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "unknown" | "n/a" | "na" | "none" | "null" | "not available" | "not_applicable"
            )
        {
            None
        } else {
            Some(trimmed.to_string())
        }
    }`),
    );
    const words = [...(/matches!\(\s*trimmed\.to_ascii_lowercase\(\)\.as_str\(\),([^)]*)\)/.exec(timelineSource)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
      (match) => match[1] as string,
    );
    expect(words).toHaveLength(7);
    for (const word of words) {
      expect(normalizedProvenance(`  ${word.toUpperCase()}  `), word).toBeNull();
      expect(normalizedProvenance(` x${word} `), word).toBe(`x${word}`);
    }
    expect(squash(itemText(timelineSource, "fn machine_of("))).toContain("normalized_provenance(value)");
    expect(squash(itemText(timelineSource, "fn component_of("))).toContain("normalized_provenance(provider)");
  });

  it("builds the origin from the whole source label, channel and provider and the normalized machine", () => {
    const text = squash(itemText(timelineSource, "fn origin_of("));
    expect(text).toContain("component:component_of(&record.provider)");
    expect(text).toContain("source:record.source_label.clone()");
    expect(text).toContain("machine:machine_of(&record.computer)");
    expect(text).toContain("channel:record.channel.clone()");
    expect(text).toContain("provider:record.provider.clone()");
  });

  it("compacts an event origin after origin_of has normalized it, not before", () => {
    const text = squash(itemText(timelineSource, "pub(crate) fn push_event_record("));
    expect(text.indexOf(squash("let mut origin = origin_of(record, 0);"))).toBeGreaterThanOrEqual(0);
    expect(text.indexOf(squash("let mut origin = origin_of(record, 0);"))).toBeLessThan(
      text.indexOf(squash("compact_timeline_origin(&mut origin)")),
    );
  });
});

describe("analysis_session.rs: diagnosis display compaction and the malformed-identity rewrite", () => {
  it("limits diagnosis display text to 4096 bytes", () => {
    expect(constantValue(analysisSessionSource, "MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES")).toBe(
      ENGINE_DIAGNOSIS_DISPLAY_TEXT_BYTES,
    );
  });

  it("digests with the first FNV lane only, and writes the same suffix shape", () => {
    expect(squash(itemText(analysisSessionSource, "fn display_text_digest("))).toBe(
      squash(`fn display_text_digest(value: &str) -> String {
        let mut digest = 2_166_136_261_u32;
        for &byte in value.as_bytes() {
            digest = (digest ^ u32::from(byte)).wrapping_mul(16_777_619);
        }
        format!("{digest:08x}")
    }`),
    );
    expect(squash(itemText(analysisSessionSource, "fn compact_display_text("))).toBe(
      squash(`fn compact_display_text(value: &mut String, stats: &mut DiagnosisDisplayProjectionStats) {
        if value.len() <= MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES {
            return;
        }
        let suffix = format!(
            "...[{} bytes; digest={}]",
            value.len(),
            display_text_digest(value)
        );
        let mut end = MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES.saturating_sub(suffix.len());
        end = end.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str(&suffix);
        stats.compacted_text_fields += 1;
    }`),
    );
  });

  it("compacts the source, provider, machine and channel of event evidence", () => {
    expect(squash(itemText(analysisSessionSource, "fn compact_evidence("))).toContain(
      squash(`EvidenceRef::Event(value) => {
            compact_display_text(&mut value.source, stats);
            compact_display_text(&mut value.provider, stats);
            compact_optional_display_text(&mut value.record_id_text, stats);
            compact_optional_display_text(&mut value.fallback_identity, stats);
            compact_optional_display_text(&mut value.machine, stats);
            compact_optional_display_text(&mut value.channel, stats);
            compact_optional_display_text(&mut value.activity_id, stats);
        }`),
    );
  });

  it("rewrites a refused event identity to the numeric id when that is 1 to 2^53 - 1, and to none otherwise", () => {
    expect(squash(itemText(analysisSessionSource, "fn sanitize_malformed_timeline_record("))).toBe(
      squash(`fn sanitize_malformed_timeline_record(record: &mut EvtxRecord) {
        record.activity_id = None;
        record.related_activity_id = None;
        record.session_id = None;
        record.device_id = None;
        record.user_id = None;
        record.user_sid = None;
        record.process_id = None;
        record.process_start_time = None;
        record.event_data.clear();
        record.mapped.clear();
        record.raw_xml.clear();
        if record.event_record_id > 0 && record.event_record_id <= MAX_SAFE_EVENT_RECORD_ID {
            record.event_record_id_text = Some(record.event_record_id.to_string());
        } else {
            record.event_record_id = 0;
            record.event_record_id_text = None;
        }
    }`),
    );
  });

  it("applies the rewrite to event records only, before the timeline origin is built", () => {
    const text = squash(itemText(analysisSessionSource, "fn append_inputs("));
    const branch = text.indexOf(squash("if matches!(record.origin_kind, EvtxOriginKind::Event) {"));
    expect(branch).toBeGreaterThanOrEqual(0);
    const malformed = text.indexOf(
      squash("if let DiagnosisRecordIdentity::Malformed { detail } = &identity {"),
      branch,
    );
    expect(malformed).toBeGreaterThan(branch);
    const rewrite = text.indexOf(squash("sanitize_malformed_timeline_record(&mut record);"), malformed);
    expect(rewrite).toBeGreaterThan(malformed);
    expect(text.indexOf(squash(".push_event_record(&record);"), rewrite)).toBeGreaterThan(rewrite);
  });
});

describe("commands.rs and models.rs: which identities the engine refuses", () => {
  it("refuses text that is empty, not all digits, outside u64, or conflicting with a numeric id it can hold, and an unsafe id without text", () => {
    expect(squash(itemText(commandsSource, "pub(crate) fn diagnosis_record_identity("))).toBe(
      squash(`pub(crate) fn diagnosis_record_identity(
        record: &super::models::EvtxRecord,
    ) -> DiagnosisRecordIdentity {
        match record.event_record_id_text.as_deref() {
            Some(value) if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) => {
                DiagnosisRecordIdentity::Malformed {
                    detail: "EventRecordID text must be a non-empty decimal value".to_string(),
                }
            }
            Some(value) => match value.parse::<u64>() {
                Ok(parsed)
                    if record.event_record_id <= MAX_SAFE_EVENT_RECORD_ID
                        && parsed != record.event_record_id =>
                {
                    DiagnosisRecordIdentity::Malformed {
                        detail: "EventRecordID text conflicts with the numeric identity".to_string(),
                    }
                }
                Ok(parsed) => DiagnosisRecordIdentity::Valid {
                    id: parsed,
                    text: Some(value.to_string()),
                },
                Err(_) => DiagnosisRecordIdentity::Malformed {
                    detail: "EventRecordID text is outside the u64 range".to_string(),
                },
            },
            None if record.event_record_id > MAX_SAFE_EVENT_RECORD_ID => {
                DiagnosisRecordIdentity::Malformed {
                    detail:
                        "EventRecordID exceeds JavaScript safe integer precision without exact text"
                            .to_string(),
                }
            }
            None => DiagnosisRecordIdentity::Valid {
                id: record.event_record_id,
                text: None,
            },
        }
    }`),
    );
  });

  it("holds 2^53 - 1 as the largest safe id, and reads a record with no origin kind as an event", () => {
    expect(constantValue(modelsSource, "MAX_SAFE_EVENT_RECORD_ID")).toBe(Number.MAX_SAFE_INTEGER);
    expect(squash(itemText(modelsSource, "pub enum EvtxOriginKind"))).toBe(
      squash(`pub enum EvtxOriginKind {
        #[default]
        Event,
        Log,
    }`),
    );
  });
});
