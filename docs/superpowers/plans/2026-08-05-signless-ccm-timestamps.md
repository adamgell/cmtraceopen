# Signless CCM and CmtLog Timestamp Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct CCM and CmtLog timestamps so an unsigned fractional tail is always fractional seconds, while an explicit signed offset remains an offset.

**Architecture:** Keep one CCM timestamp interpretation for both the public `LogEntry` projection and SCCM evidence provenance; remove the obsolete compatibility-only split and admission gate. Normalize fractions in the existing shared helper, then make CmtLog's regex boundary explicit: it captures all unsigned digits as the fraction and only a signed suffix as the timezone.

**Tech Stack:** Rust, `chrono`, `regex`, Cargo unit/integration tests, Clippy, rustfmt.

---

## File structure

- `crates/cmtraceopen-parser/src/parser/ccm.rs` owns CCM structural parsing, timestamp projection, and SCCM timestamp provenance. Remove its legacy public-tail split and compatibility demotion.
- `crates/cmtraceopen-parser/src/parser/cmtlog.rs` owns CmtLog's relaxed record grammar. Make its optional signed timezone self-delimiting and retain ASCII-only structural numeric fields.
- `crates/cmtraceopen-parser/tests/sccm_spine_contract.rs` owns public CCM projection and SCCM timeline-ordering contract assertions. Replace the pinned wrong public baseline with the corrected semantic table.
- `library.md` owns workspace routing. Add the condition-first pointer for this implementation plan.

### Task 1: Pin the corrected public and CmtLog contracts (red)

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_spine_contract.rs:5845-6015`
- Modify: `crates/cmtraceopen-parser/src/parser/cmtlog.rs:352-410`

- [ ] **Step 1: Replace the compatibility-baseline CCM table with semantic public projection assertions**

Replace `public_ccm_digit_only_timestamp_tails_match_pre_spine_baseline` and `signless_ccm_offset_is_enriched_only_in_sccm_provenance` with a table that parses each tail through `ccm::parse_content` and `normalize_ccm_artifact`, asserting these public/evidence values:

```rust
let cases = [
    ("1", 100, "07-30-2026 10:00:00.100", None, SccmTimeOrderingState::OffsetMissing),
    ("12", 120, "07-30-2026 10:00:00.120", None, SccmTimeOrderingState::OffsetMissing),
    ("123", 123, "07-30-2026 10:00:00.123", None, SccmTimeOrderingState::OffsetMissing),
    ("000240", 0, "07-30-2026 10:00:00.000", None, SccmTimeOrderingState::OffsetMissing),
    ("1234567", 123, "07-30-2026 10:00:00.123", None, SccmTimeOrderingState::OffsetMissing),
];
```

For every case, assert `entries[0].timezone_offset == Some(0)`, its epoch is the naive UTC epoch using `public_millis`, provenance `original_display` retains the complete fractional text, and `utc_millis == None`. Rename the microsecond test to state that both projections are fraction-only and assert `entries[0].timezone_offset == Some(0)`.

- [ ] **Step 2: Add explicit signed-offset and timeline-order contracts**

Add one test using `time="10:00:00.123+240"`: both public projection and evidence must retain `Some(240)`, display `.123`, normalize to `07:??` relative to UTC, and state `NormalizedUtc`. Add a two-record evidence test in source order where the first record is `10:00:00.123456` and the second is `09:59:59.999+000`; assert the signless record is `OffsetMissing`, has no `utc_millis`, and is not used to fabricate an ordering edge ahead of the normalized record.

- [ ] **Step 3: Add CmtLog unit regressions for the explicit boundary and ASCII structural fields**

Append these tests to `cmtlog.rs`'s existing test module:

```rust
#[test]
fn signless_fractional_tails_never_become_cmtlog_offsets() {
    let line = r#"<![LOG[fractional payload ✓]LOG]!><time="10:00:00.123456" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="">"#;
    let (entries, errors) = parse_lines(&[line], "test.cmtlog");
    assert_eq!(errors, 0);
    assert_eq!(entries[0].timestamp_display.as_deref(), Some("04-13-2026 10:00:00.123"));
    assert_eq!(entries[0].timezone_offset, Some(0));
    assert_eq!(entries[0].message, "fractional payload ✓");
}

#[test]
fn cmtlog_accepts_signed_offsets_and_rejects_unicode_structural_digits() {
    let signed = r#"<![LOG[Résumé ✓]LOG]!><time="10:00:00.12-240" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="">"#;
    let unicode = r#"<![LOG[日本語 payload]LOG]!><time="10:00:00.12١" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="">"#;
    let (entries, errors) = parse_lines(&[signed, unicode], "test.cmtlog");
    assert_eq!(entries[0].timezone_offset, Some(-240));
    assert_eq!(entries[0].timestamp_display.as_deref(), Some("04-13-2026 10:00:00.120"));
    assert_eq!(entries[0].message, "Résumé ✓");
    assert_eq!(errors, 1);
    assert_eq!(entries[1].timestamp, None);
    assert_eq!(entries[1].message, unicode);
}
```

- [ ] **Step 4: Run the red tests**

Run: `cargo test -p cmtraceopen-parser --lib parser::cmtlog::tests::signless_fractional_tails_never_become_cmtlog_offsets -- --exact`

Expected: FAIL because greedy `(?P<ms>\\d+)(?P<tz>[+-]*\\d+)` parses `123456` as a timezone-bearing timestamp.

Run: `cargo test -p cmtraceopen-parser --test sccm_spine_contract public_ccm_digit_only_timestamp_tails_are_fraction_only -- --exact`

Expected: FAIL because the public projection still uses `split_legacy_public_time_tail`.

### Task 2: Unify CCM projection and make CmtLog's offset boundary explicit (green)

**Files:**
- Modify: `crates/cmtraceopen-parser/src/parser/ccm.rs:31-64,169-256,540-586,666-758`
- Modify: `crates/cmtraceopen-parser/src/parser/cmtlog.rs:35-153`

- [ ] **Step 1: Make CCM's structural grammar ASCII-only and delete the signless-offset heuristic**

Change CCM structural digit classes from `\\d` to `[0-9]`. Delete `MAX_UTC_OFFSET_MINUTES`, `UTC_OFFSET_STEP_MINUTES`, `signless_offset_is_real`, and all comments describing signless offset interpretation. Implement the tail split as:

```rust
fn split_ccm_time_tail(value: &str) -> (&str, Option<&str>) {
    if let Some(index) = value
        .as_bytes()
        .iter()
        .position(|byte| matches!(byte, b'+' | b'-'))
    {
        return (&value[..index], Some(&value[index..]));
    }
    (value, None)
}
```

- [ ] **Step 2: Scale short fractions and make the corrected parse the public projection**

Replace `truncate_subsecond_to_millis` with:

```rust
pub(crate) fn truncate_subsecond_to_millis(value: &str) -> Option<u32> {
    match value.len() {
        1 => value.parse::<u32>().ok().map(|millis| millis * 100),
        2 => value.parse::<u32>().ok().map(|millis| millis * 10),
        _ => value.get(..3)?.parse().ok(),
    }
}
```

Delete `split_legacy_public_time_tail`, `CcmParsed::public_compatible`, and the `PublicProjection` demotion branches in `parse_line`/`scan_ccm_content`. In `parse_captures`, build `timestamp`, `timestamp_display`, and `timezone_offset` only from `ms` and `parsed_timezone`; use `parsed_timezone.unwrap_or_default()` for the public `LogEntry` offset. Keep `CcmTimestampParse` based on the same `ms_str` and signed-only `timezone_text`.

- [ ] **Step 3: Give CmtLog an optional signed-offset capture and use CCM fraction scaling**

Replace CmtLog's time pattern and parse with the explicit signed boundary:

```rust
r#"<time="(?P<h>[0-9]{1,2}):(?P<m>[0-9]{1,2}):(?P<s>[0-9]{1,2})\.(?P<ms>[0-9]+)(?P<tz>[+-][0-9]+)?""#,
```

Use `[0-9]` for every other structural numeric field. Parse milliseconds via `ccm::truncate_subsecond_to_millis(caps.name("ms")?.as_str())?`; parse `tz` with `and_then(|value| value.parse::<i32>().ok()).unwrap_or(0)`. A missing signed group therefore remains a zero display offset without manufacturing timezone provenance.

- [ ] **Step 4: Run green tests**

Run: `cargo test -p cmtraceopen-parser --lib parser::ccm::tests -- --nocapture`

Expected: PASS.

Run: `cargo test -p cmtraceopen-parser --lib parser::cmtlog::tests -- --nocapture`

Expected: PASS.

Run: `cargo test -p cmtraceopen-parser --test sccm_spine_contract -- public_ccm_digit_only_timestamp_tails_are_fraction_only explicit_signed_ccm_offsets_remain_normalized timeline_does_not_order_signless_fraction_as_utc`

Expected: PASS.

- [ ] **Step 5: Commit the coherent parser repair**

```bash
git add crates/cmtraceopen-parser/src/parser/ccm.rs crates/cmtraceopen-parser/src/parser/cmtlog.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "fix(parser): treat signless CCM tails as fractions"
```

### Task 3: Verify cross-parser safety and publish the review artifact

**Files:**
- Modify: `library.md`

- [ ] **Step 1: Add the plan route**

Append exactly:

```markdown
- IF implementing or reviewing signless CCM/CmtLog timestamp repairs (#410, #414) → read [[docs/superpowers/plans/2026-08-05-signless-ccm-timestamps.md]]
```

- [ ] **Step 2: Run the required parser and safety suites**

Run:

```bash
cargo test -p cmtraceopen-parser --lib parser::ccm::tests parser::cmtlog::tests
cargo test -p cmtraceopen-parser --test sccm_spine_contract
cargo test -p cmtraceopen-parser --test issue_413_unicode_panics
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --package cmtraceopen-parser
git diff --check
git status --short --branch
```

Expected: all commands exit 0; the #413 suite remains available from its owning branch or must be explicitly restored before this step, because the CmtLog grammar must keep ASCII structural digits while accepting Unicode payload text.

- [ ] **Step 3: Commit documentation, push, and open the PR**

```bash
git add library.md docs/superpowers/plans/2026-08-05-signless-ccm-timestamps.md
git commit -m "docs: plan signless CCM timestamp repair"
git push -u origin codex/issue-410-414-signless-timestamps
gh pr create --base main --head codex/issue-410-414-signless-timestamps --title "fix(parser): treat signless CCM tails as fractions" --body $'Closes #410\nCloses #414\n\nCorrects public CCM and CmtLog fractional-tail parsing; signed offsets remain explicit.'
```

Expected: one open, unmerged PR containing the frozen branch SHA.

## Self-review

- [x] **Spec coverage:** Task 1 covers one/two/three-plus digit fractional semantics, public projection, provenance, and ordering. Task 2 removes the obsolete compatibility/demotion code and repairs CmtLog grammar while preserving explicit signed offsets and ASCII structural fields. Task 3 covers focused tests, #413 protection, full parser checks, lint/format/diff, and PR publication.
- [x] **Placeholder scan:** Every code edit and command is named; no deferred implementation markers remain.
- [x] **Type consistency:** The plan uses existing `LogEntry`, `CcmTimestampParseState`/`SccmTimeOrderingState`, `parse_content`, `parse_lines`, and shared `truncate_subsecond_to_millis` interfaces only.
