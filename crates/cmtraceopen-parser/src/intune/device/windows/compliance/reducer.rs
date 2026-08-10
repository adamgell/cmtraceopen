//! Reduce classified compliance observations into an immutable snapshot.
//!
//! The reduction runs strictly phase by phase and never lets a later phase
//! rewrite an earlier one:
//!
//! 1. **local** — merge setting observations by grouping token;
//! 2. **aggregate** — fold the local settings into one device result;
//! 3. **reporting** — record submission state and compare service records
//!    against the *timestamp* of the local evaluation, not against its verdict;
//! 4. **access** — attach downstream decisions, correlated only on explicit
//!    identity plus explicit time provenance.
//!
//! Findings are derived last, from the finished snapshot, so no rule can see a
//! half-built state.

use std::collections::BTreeMap;
use std::fmt::Debug;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::models::*;
use super::rules::derive_findings;
use super::sources::{
    classify_event, classify_setting_report, decode_bundle, ComplianceSignal,
    ComplianceSourceInput, SettingObservation,
};
use crate::intune::evidence::{
    IntuneErrorCode, IntuneEvidenceRef, IntuneTimestamp, IntuneTimestampKind,
};

/// Decode a supplied evidence bundle and reduce it in one call.
pub fn analyze_compliance_bundle(
    sources: &[ComplianceSourceInput],
    generated_at_utc: &str,
) -> ComplianceSnapshot {
    analyze_compliance(&decode_bundle(sources, generated_at_utc))
}

/// Reduce already-decoded compliance facts into a snapshot.
pub fn analyze_compliance(input: &ComplianceInput) -> ComplianceSnapshot {
    let generated_at = parse_rfc3339(&input.generated_at_utc);

    let device_context = reduce_device_context(input);
    let local = reduce_local(input, generated_at);
    let aggregate = reduce_aggregate(&local);
    let reporting = reduce_reporting(input, &local, &aggregate, generated_at);
    let access_impact = reduce_access(input, &reporting);

    let mut snapshot = ComplianceSnapshot {
        schema_version: INTUNE_COMPLIANCE_SCHEMA_VERSION,
        generated_at_utc: input.generated_at_utc.clone(),
        device_context,
        local_evaluation: local,
        aggregate,
        reporting,
        access_impact,
        coverage: input.coverage.clone(),
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

// ── Device context ──────────────────────────────────────────────────────────

fn reduce_device_context(input: &ComplianceInput) -> ComplianceDeviceContextView {
    let Some(fact) = input.device_context.as_ref() else {
        return ComplianceDeviceContextView::default();
    };

    // A user key alone does not prove a user session was available for
    // evaluation; only the explicit flag does. Inferring presence from the key
    // would make an unevaluated user-scoped setting look like a failure.
    let user_evaluation_context = match fact.user_session_present {
        Some(true) => ComplianceUserContext::UserPresent,
        Some(false) => ComplianceUserContext::NoUserSession,
        None => ComplianceUserContext::Unknown,
    };

    ComplianceDeviceContextView {
        device_key: fact.device_key.clone(),
        tenant_key: fact.tenant_key.clone(),
        enrollment_id: fact.enrollment_id.clone(),
        windows_build: fact.windows_build.clone(),
        active_user_key: fact.active_user_key.clone(),
        user_evaluation_context,
        evidence: vec![fact.context.evidence_ref.clone()],
    }
}

// ── Phase 1: local evaluation ───────────────────────────────────────────────

/// One policy-level statement, before the statements about that policy are
/// merged. Held rather than folded on arrival so the merge can see all of them.
struct PolicyStatement {
    state: CompliancePolicyState,
    scope: ComplianceScope,
    evidence: IntuneEvidenceRef,
}

/// One prerequisite statement, before merging. See [`PolicyStatement`].
struct PrerequisiteStatement {
    state: CompliancePrerequisiteState,
    detail: Option<String>,
    evidence: IntuneEvidenceRef,
}

fn reduce_local(
    input: &ComplianceInput,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceLocalPhase {
    let mut phase = ComplianceLocalPhase::default();
    let mut grouped: BTreeMap<String, Vec<SettingObservation>> = BTreeMap::new();
    let mut policies: BTreeMap<String, Vec<PolicyStatement>> = BTreeMap::new();
    let mut prerequisites: BTreeMap<String, Vec<PrerequisiteStatement>> = BTreeMap::new();
    let mut evidence = Vec::new();

    for event in &input.events {
        evidence.push(event.context.evidence_ref.clone());
        let reference = event.context.evidence_ref.clone();
        match classify_event(event) {
            Some(ComplianceSignal::SettingEvaluation(observation)) => {
                grouped
                    .entry(observation.grouping_token.clone())
                    .or_default()
                    .push(*observation);
            }
            Some(ComplianceSignal::Prerequisite {
                name,
                state,
                detail,
            }) => prerequisites
                .entry(name)
                .or_default()
                .push(PrerequisiteStatement {
                    state,
                    detail,
                    evidence: reference,
                }),
            Some(ComplianceSignal::PolicyState {
                policy_id,
                state,
                scope,
            }) => policies.entry(policy_id).or_default().push(PolicyStatement {
                state,
                scope,
                evidence: reference,
            }),
            // Reporting signals belong to phase 3.
            Some(ComplianceSignal::ReportSubmission { .. }) => {}
            // The record was supplied as compliance evidence but names no
            // setting, policy, prerequisite, or report status. It is recorded as
            // unattributed coverage rather than dropped, so a bundle that
            // produced no result can be told apart from one that was never read.
            None => phase.unkeyed_observations.push(reference),
        }
    }

    for report in &input.setting_reports {
        evidence.push(report.context.evidence_ref.clone());
        match classify_setting_report(report) {
            Some(observation) => grouped
                .entry(observation.grouping_token.clone())
                .or_default()
                .push(observation),
            None => phase
                .unkeyed_observations
                .push(report.context.evidence_ref.clone()),
        }
    }

    phase.settings = grouped
        .into_iter()
        .map(|(token, observations)| merge_setting(token, observations, generated_at))
        .collect();
    phase.policies = policies
        .into_iter()
        .map(|(policy_id, statements)| merge_policy(policy_id, statements))
        .collect();
    phase.prerequisites = prerequisites
        .into_iter()
        .map(|(name, statements)| merge_prerequisite(name, statements))
        .collect();

    phase.custom_compliance = input
        .custom_compliance
        .iter()
        .map(|fact| {
            evidence.push(fact.context.evidence_ref.clone());
            ComplianceCustomEvaluation {
                policy_id: fact.policy_id.clone(),
                run_id: fact.run_id.clone(),
                setting_name: fact.setting_name.clone(),
                state: fact.outcome,
                error: fact.error.clone(),
                raw_output: fact.raw_output.clone(),
                evidence: vec![fact.context.evidence_ref.clone()],
                named_data: fact.named_data.clone(),
            }
        })
        .collect();
    // The exported array is a set of results, not a sequence: no custom-compliance
    // source states a run order, so leaving it in the caller's vector order made
    // the serialized snapshot a function of the collector.
    //
    // Evidence first, because a ref is the one identifier every fact is
    // guaranteed to carry, then the record's own identity from broadest to
    // narrowest: the policy the run belonged to, the run within it, the setting
    // the run reported on. Nothing dedupes or renumbers evidence ids, so two
    // facts sharing one ref are reachable, and a sort on the ref alone left them
    // in the caller's order because `sort_by` is stable.
    //
    // Those four fields are the *reading* order and nothing more. `content_key`
    // is what makes the comparison total: `state`, `error`, `raw_output` and
    // `named_data` are not named above, and neither is whatever field this
    // record gains next. See its doc for why it is not just four more links.
    phase.custom_compliance.sort_by(|left, right| {
        left.evidence
            .cmp(&right.evidence)
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.run_id.cmp(&right.run_id))
            .then_with(|| left.setting_name.cmp(&right.setting_name))
            .then_with(|| content_key(left).cmp(&content_key(right)))
    });

    phase.latest_evaluation_at_utc = latest_evaluation(&phase.settings).map(format_utc);
    normalize_evidence(&mut phase.unkeyed_observations);
    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

/// Fold every statement about one policy into one observation.
///
/// Both fields resolve by *agreement*, not by arrival: two sources saying the
/// policy was received and not received are equally authoritative here, and
/// there is no third fact to break the tie. Reporting `Unknown` says that
/// outright, where naming a winner would have made the export a function of the
/// caller's vector (ADR-003).
fn merge_policy(policy_id: String, statements: Vec<PolicyStatement>) -> CompliancePolicyObservation {
    CompliancePolicyObservation {
        policy_id,
        state: agreed(
            statements
                .iter()
                .map(|statement| statement.state)
                .filter(|state| *state != CompliancePolicyState::Unknown),
        )
        .unwrap_or(CompliancePolicyState::Unknown),
        scope: agreed_scope(statements.iter().map(|statement| statement.scope)),
        evidence: collect_evidence(statements.iter().map(|statement| &statement.evidence)),
    }
}

/// Fold every statement about one prerequisite into one entry.
///
/// The precedence is a rank rather than an order: a device saying "blocked" at
/// any point is the fact worth surfacing, so `Unmet` outranks `Met`, which
/// outranks `Unknown`. The detail is then the smallest stated by the statements
/// that carry the winning state — previously the *last* unmet statement's detail
/// won, which two unmet rows swapped between them.
fn merge_prerequisite(
    name: String,
    statements: Vec<PrerequisiteStatement>,
) -> CompliancePrerequisite {
    let state = [
        CompliancePrerequisiteState::Unmet,
        CompliancePrerequisiteState::Met,
    ]
    .into_iter()
    .find(|ranked| {
        statements
            .iter()
            .any(|statement| statement.state == *ranked)
    })
    .unwrap_or(CompliancePrerequisiteState::Unknown);

    CompliancePrerequisite {
        name,
        state,
        detail: statements
            .iter()
            .filter(|statement| statement.state == state)
            .filter_map(|statement| statement.detail.as_ref())
            .min()
            .cloned(),
        evidence: collect_evidence(statements.iter().map(|statement| &statement.evidence)),
    }
}

/// The one value every stating source agreed on, or `None` when they disagreed.
///
/// This is the conservative merge ADR-003 asks for: an unresolved contradiction
/// between equally authoritative sources is reported as no value rather than as
/// whichever the caller listed first.
fn agreed<T: PartialEq>(values: impl IntoIterator<Item = T>) -> Option<T> {
    let mut agreed: Option<T> = None;
    for value in values {
        match &agreed {
            None => agreed = Some(value),
            Some(existing) if *existing == value => {}
            Some(_) => return None,
        }
    }
    agreed
}

/// The scope every source that stated one agreed on.
///
/// Scope decides whether a setting is read as a user-targeted policy that was
/// never evaluated — missing coverage — or as a device failure, so a
/// disagreement must not be settled by vector position. `Unknown` covers both
/// "nobody said" and "they disagreed"; the observations stay cited either way.
fn agreed_scope(scopes: impl IntoIterator<Item = ComplianceScope>) -> ComplianceScope {
    agreed(
        scopes
            .into_iter()
            .filter(|scope| *scope != ComplianceScope::Unknown),
    )
    .unwrap_or(ComplianceScope::Unknown)
}

/// Fold every observation that shares a grouping token into one evaluation.
///
/// Two *definite* states that disagree produce
/// [`ComplianceSettingState::Contradictory`] rather than an arbitrary winner.
/// Preferring the newest would silently pick a side in exactly the case where
/// the evidence does not support picking one.
///
/// # Why no field here reads the vector
///
/// ADR-003 lets a reducer read caller order as chronology only where the source
/// contract defines it, and no compliance source defines it: these records reach
/// the group from an event log, an exported report, and a script host,
/// interleaved by the collector. Every field below is therefore derived from
/// record *content* — the smallest stated value, the agreed value, or the newest
/// timestamp — and never from a position. Real chronology comes from
/// [`latest_evaluated_at`].
fn merge_setting(
    grouping_token: String,
    mut observations: Vec<SettingObservation>,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceSettingEvaluation {
    // Canonicalize anyway. Every merge below is individually content-determined,
    // so today this changes no output; it is here so that a field added later
    // which *does* walk the vector inherits a stable order rather than silently
    // reintroducing the defect this function was rewritten to remove.
    //
    // That promise only holds if the order is total, and two observations may
    // share an evidence ref, so the ref alone did not keep it. `SettingObservation`
    // is internal and not `Serialize`, so the structural form stands in for the
    // serialized one; it names every field the same way.
    observations.sort_by(|left, right| {
        left.context
            .evidence_ref
            .cmp(&right.context.evidence_ref)
            .then_with(|| structural_key(left).cmp(&structural_key(right)))
    });

    let key = ComplianceSettingKey {
        policy_id: smallest_stated(&observations, |observation| observation.key.policy_id.as_ref()),
        setting_id: smallest_stated(&observations, |observation| {
            observation.key.setting_id.as_ref()
        }),
        setting_uri: smallest_stated(&observations, |observation| {
            observation.key.setting_uri.as_ref()
        }),
    };
    // Unchanged in meaning: more than one usable value for one identifier is a
    // contradiction. Asking whether the stating records agree gives the same
    // answer as comparing each record against the accumulated key did, without
    // reading the order they arrived in.
    let identity_contradiction = contradicts(&observations, |observation| {
        observation.key.policy_id.as_ref()
    }) || contradicts(&observations, |observation| {
        observation.key.setting_id.as_ref()
    }) || contradicts(&observations, |observation| {
        observation.key.setting_uri.as_ref()
    });

    let mut definite = Vec::new();
    let mut indefinite = Vec::new();
    let mut named_data = Vec::new();
    for observation in &observations {
        if observation.state.is_definite() {
            definite.push(observation.state);
        } else {
            indefinite.push(observation.state);
        }
        named_data.extend(observation.named_data.iter().cloned());
    }

    definite.sort();
    definite.dedup();
    let state = match definite.len() {
        1 => definite[0],
        0 => most_informative_indefinite(&indefinite),
        _ => ComplianceSettingState::Contradictory,
    };

    // A record stamped after the snapshot was generated is a provenance
    // contradiction whichever record it is, so this is a property of the set.
    let time_contradiction = observations.iter().any(|observation| {
        match (
            observation
                .evaluated_at
                .as_ref()
                .and_then(normalized_timestamp),
            generated_at,
        ) {
            (Some(candidate), Some(generated_at)) => candidate > generated_at,
            _ => false,
        }
    });

    // This vector is concatenated across observations, so its input order is the
    // collector's, and it is exported. Name and value are the reading order;
    // `content_key` is what keeps the comparison total, because `IntuneNamedValue`
    // is a shared evidence type and a field added to it there would otherwise
    // reintroduce caller order here, in another module, with nothing to fail.
    // `dedup` reads full equality, so a widened value stops collapsing too.
    named_data.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| content_key(left).cmp(&content_key(right)))
    });
    named_data.dedup();

    ComplianceSettingEvaluation {
        key,
        grouping_token,
        scope: agreed_scope(observations.iter().map(|observation| observation.scope)),
        state,
        // The noncompliance and evaluation-error findings quote this name, so two
        // records naming one setting differently used to change the exported
        // summary depending on the caller's vector. The smallest is named
        // instead; both records stay cited, so nothing is hidden.
        display_name: smallest_stated(&observations, |observation| {
            observation.display_name.as_ref()
        }),
        error: terminal_error(&observations),
        evaluated_at: latest_evaluated_at(
            observations
                .iter()
                .filter_map(|observation| observation.evaluated_at.as_ref()),
        ),
        observed_states: definite,
        time_contradiction,
        identity_contradiction,
        evidence: collect_evidence(
            observations
                .iter()
                .map(|observation| &observation.context.evidence_ref),
        ),
        named_data,
    }
}

/// The smallest value stated by any observation in the group.
///
/// "Smallest" is arbitrary but *content-determined*, which "first" was not.
///
/// A present-but-blank value states nothing and is skipped, so it can never win
/// the `min` and be exported as this group's identifier or display name. Every
/// other reader of these fields already agrees: [`ComplianceSettingKey::is_identified`]
/// and [`ComplianceSettingKey::grouping_token`] both drop a blank before deciding,
/// and [`contradicts`] reads one through [`usable_identifier`]. Only this function
/// took `Some("")` at face value, which let a group merged on its URI export
/// `settingId: ""` while `contradicts` had already ruled the same value out.
///
/// The gap is reachable through the report path but not the event path:
/// `sources::classify_setting_report` copies `policy_id`, `setting_id`, and
/// `setting_uri` verbatim from a `NormalizedSettingReport` deserialized straight
/// out of the `settingReports` envelope, where `"settingId": ""` is valid JSON,
/// whereas `sources::event_setting_key` reads every field through `named_any`,
/// which trims and rejects a blank before it becomes a key at all.
///
/// The winning value is still exported verbatim; only the decision about whether
/// a value was stated is normalized.
fn smallest_stated(
    observations: &[SettingObservation],
    pick: fn(&SettingObservation) -> Option<&String>,
) -> Option<String> {
    observations
        .iter()
        .filter_map(pick)
        .filter(|value| usable_identifier(value).is_some())
        .min()
        .cloned()
}

/// The terminal code this setting reported.
///
/// When two records report different codes the smallest by canonical ordering is
/// named rather than whichever arrived first. Both records stay cited either
/// way; only the choice of which code to lead with is made stable.
fn terminal_error(observations: &[SettingObservation]) -> Option<IntuneErrorCode> {
    observations
        .iter()
        .filter_map(|observation| observation.error.as_ref())
        .min_by(|left, right| {
            (&left.decimal, &left.hex, &left.raw).cmp(&(&right.decimal, &right.hex, &right.raw))
        })
        .cloned()
}

/// Whether two records state different non-empty values for one identifier.
///
/// Deliberately not expressed as `agreed(..).is_none()`: `agreed` also returns
/// `None` for an empty set, and "nobody stated an id" is not a contradiction.
fn contradicts(
    observations: &[SettingObservation],
    pick: fn(&SettingObservation) -> Option<&String>,
) -> bool {
    let mut stated: Option<String> = None;
    for value in observations
        .iter()
        .filter_map(pick)
        .filter_map(|value| usable_identifier(value))
    {
        match &stated {
            None => stated = Some(value),
            Some(existing) if *existing == value => {}
            Some(_) => return true,
        }
    }
    false
}

/// An identifier reduced to its comparable form, or `None` when it states nothing.
///
/// [`smallest_stated`] reuses the `None` half as the module's single test for
/// "this string states nothing", including for the display name, which is not an
/// identifier but is just as meaningless when blank.
fn usable_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

/// Rank the non-definite states so a merge keeps the most informative one.
fn most_informative_indefinite(states: &[ComplianceSettingState]) -> ComplianceSettingState {
    let rank = |state: &ComplianceSettingState| match state {
        ComplianceSettingState::PrerequisiteUnmet => 4,
        ComplianceSettingState::Contradictory => 3,
        ComplianceSettingState::NotEvaluated => 2,
        ComplianceSettingState::InsufficientEvidence => 1,
        _ => 0,
    };
    states
        .iter()
        .max_by_key(|state| rank(state))
        .copied()
        .unwrap_or(ComplianceSettingState::InsufficientEvidence)
}

/// The most recent evaluation instant a group of records states.
///
/// An orderable instant always beats an unorderable one, and among orderable
/// instants the newest wins — the behavior this reducer has always had. What is
/// new is the tie-break: two records whose instants compare equal, and a group in
/// which *nothing* is orderable, used to resolve to whichever the caller listed
/// last. Both now resolve to the smallest by content.
///
/// Unlike [`latest_submission_at`] this does not refuse an unorderable group.
/// The field is provenance rather than a conclusion, and the one place a
/// conclusion is drawn from it — [`latest_evaluation`] — re-filters to orderable
/// instants anyway, so keeping the raw stamp loses nothing and preserves evidence.
fn latest_evaluated_at<'a>(
    stamps: impl IntoIterator<Item = &'a IntuneTimestamp>,
) -> Option<IntuneTimestamp> {
    stamps
        .into_iter()
        .max_by(|left, right| {
            normalized_timestamp(left)
                .cmp(&normalized_timestamp(right))
                // Reversed, so `max_by` settles a tie on the *smallest* content.
                .then_with(|| timestamp_content_key(right).cmp(&timestamp_content_key(left)))
        })
        .cloned()
}

/// The most recent instant at which a report is known to have been submitted.
///
/// This is the input to the staleness gate, so the semantics are chosen for what
/// that gate asks: "does the service hold a copy of the most recent local
/// evaluation?" The answer depends on the **latest** successful submission, by
/// timestamp. It never depended on vector position, which is what the previous
/// unconditional last-wins assignment actually read — two submissions straddling
/// the evaluation exported `Submitted` or `Stale` according to the collector's
/// serialization order.
///
/// Where the evidence cannot support an answer, none is given:
///
/// - a single submission is unambiguous whatever its zone, so it is reported;
/// - several submissions are ordered only when *every* one of them carries a
///   timestamp whose zone is known. One zone-less stamp among them means we
///   cannot say which submission is last, and naming one anyway would let the
///   gate declare `Stale` on a guess. `None` is reported instead, which leaves
///   the state at `Submitted` — the claim the evidence does support.
fn latest_submission_at<'a>(
    stamps: impl IntoIterator<Item = &'a IntuneTimestamp>,
) -> Option<IntuneTimestamp> {
    let mut distinct: Vec<&IntuneTimestamp> = Vec::new();
    for stamp in stamps {
        if !distinct.contains(&stamp) {
            distinct.push(stamp);
        }
    }
    match distinct.len() {
        0 => None,
        1 => distinct.first().copied().cloned(),
        _ if distinct
            .iter()
            .any(|stamp| normalized_timestamp(stamp).is_none()) =>
        {
            None
        }
        _ => distinct
            .into_iter()
            .max_by(|left, right| {
                normalized_timestamp(left)
                    .cmp(&normalized_timestamp(right))
                    .then_with(|| timestamp_content_key(left).cmp(&timestamp_content_key(right)))
            })
            .cloned(),
    }
}

/// Where a record sits on the timeline, or that it cannot be placed on one.
///
/// [`normalized_timestamp`] declines a stamp whose zone is unknown, so `None`
/// here means "not placeable", never "earliest". The leading flag says so in the
/// ordering: `false < true`, so every placeable record sorts before every
/// unplaceable one and the dated run stays contiguous instead of being prefixed
/// by a block whose position would read as "before everything".
///
/// This key is deliberately *not* total. It answers only "when", and a caller
/// that needs a total order must chain something after it — the raw stamp for
/// records that share an instant or have none, and eventually [`content_key`].
fn chronological_key(timestamp: Option<&IntuneTimestamp>) -> (bool, Option<DateTime<Utc>>) {
    let instant = timestamp.and_then(normalized_timestamp);
    (instant.is_none(), instant)
}

/// A total, content-derived ordering key, used only to settle ties deterministically.
fn timestamp_content_key(timestamp: &IntuneTimestamp) -> (&str, Option<&str>, Option<&str>, u8) {
    let kind = match timestamp.kind {
        IntuneTimestampKind::Utc => 0,
        IntuneTimestampKind::Offset => 1,
        IntuneTimestampKind::Local => 2,
        IntuneTimestampKind::Unspecified => 3,
        IntuneTimestampKind::Invalid => 4,
    };
    (
        &timestamp.raw_text,
        timestamp.original_offset.as_deref(),
        timestamp.normalized_utc.as_deref(),
        kind,
    )
}

/// A total ordering key over a whole record, derived from the record itself.
///
/// The three exported fact arrays are canonicalized by sorting, and twice now
/// the sort key was a hand-written list of fields: first `evidence` alone, then
/// `evidence` plus a few of the record's own identifiers. Both were partial.
/// `slice::sort_by` is stable, so every pair the key did not separate kept the
/// caller's vector order, and the set of such pairs is decided by whichever
/// fields a human remembered to name. Adding a field to one of those records is
/// enough to widen it again, silently, with no test to fail.
///
/// This key is the record's own serialized form, so it names every field by
/// construction and a field added later participates without anyone touching
/// this module. Two records compare Equal here exactly when they serialize
/// identically, which is exactly when swapping them leaves the exported
/// snapshot byte-identical: at that point the order genuinely does not matter,
/// and there is nothing left for caller order to decide.
///
/// It is a *tie-breaker*, appended after the named chain each call site states,
/// not a replacement for it. The named chain is what a reader sees (containment
/// for the two result arrays, time for the decision array); this only settles
/// pairs that chain leaves Equal, which no corpus scenario contains, so the
/// serialization runs on essentially no comparison in practice.
fn content_key<T: Serialize + Debug>(record: &T) -> (u8, String) {
    match serde_json::to_string(record) {
        Ok(json) => (0, json),
        // Unreachable for these records: every field is a string, an integer, a
        // fieldless enum, or a struct or vector of the same, and none of those
        // can fail to serialize. Falling back to a constant would put the pair
        // back in caller order, though, so fall back to another total form
        // instead. The leading tag keeps the two key spaces from colliding.
        Err(_) => structural_key(record),
    }
}

/// [`content_key`]'s guarantee for a record that is never exported and so is not
/// `Serialize`. The derived `Debug` form names every field the same way.
fn structural_key<T: Debug>(record: &T) -> (u8, String) {
    (1, format!("{record:?}"))
}

fn latest_evaluation(settings: &[ComplianceSettingEvaluation]) -> Option<DateTime<Utc>> {
    settings
        .iter()
        .filter_map(|setting| setting.evaluated_at.as_ref())
        .filter_map(normalized_timestamp)
        .max()
}

// ── Phase 2: aggregate ──────────────────────────────────────────────────────

/// Fold local settings and custom-compliance results into one device result.
///
/// Precedence is by severity of claim, and a custom-compliance *script failure*
/// is folded in as an error, never as a noncompliance: a script that did not run
/// produced no verdict to aggregate.
fn reduce_aggregate(local: &ComplianceLocalPhase) -> ComplianceAggregatePhase {
    let mut phase = ComplianceAggregatePhase::default();

    for setting in &local.settings {
        match setting.state {
            ComplianceSettingState::Compliant => phase.compliant_count += 1,
            ComplianceSettingState::Noncompliant => phase.noncompliant_count += 1,
            ComplianceSettingState::EvaluationError => phase.error_count += 1,
            ComplianceSettingState::NotApplicable => phase.not_applicable_count += 1,
            ComplianceSettingState::NotEvaluated
            | ComplianceSettingState::PrerequisiteUnmet
            | ComplianceSettingState::InsufficientEvidence => phase.not_evaluated_count += 1,
            ComplianceSettingState::Contradictory => phase.contradictory_count += 1,
        }
    }

    let custom_noncompliant = local
        .custom_compliance
        .iter()
        .filter(|custom| custom.state == ComplianceCustomState::DiscoveryNoncompliant)
        .collect::<Vec<_>>();
    let custom_failed = local
        .custom_compliance
        .iter()
        .filter(|custom| {
            matches!(
                custom.state,
                ComplianceCustomState::ScriptFailed | ComplianceCustomState::OutputInvalid
            )
        })
        .collect::<Vec<_>>();

    let has_local_source = !local.settings.is_empty() || !local.custom_compliance.is_empty();

    let (state, rationale, evidence) = if phase.noncompliant_count > 0 {
        (
            ComplianceAggregateState::Noncompliant,
            ComplianceAggregateRationale::LocalSettingNoncompliant,
            evidence_for(local, ComplianceSettingState::Noncompliant),
        )
    } else if !custom_noncompliant.is_empty() {
        (
            ComplianceAggregateState::Noncompliant,
            ComplianceAggregateRationale::CustomComplianceDiscoveryNoncompliant,
            collect_evidence(custom_noncompliant.iter().flat_map(|c| c.evidence.iter())),
        )
    } else if phase.error_count > 0 {
        (
            ComplianceAggregateState::EvaluationError,
            ComplianceAggregateRationale::LocalEvaluationError,
            evidence_for(local, ComplianceSettingState::EvaluationError),
        )
    } else if !custom_failed.is_empty() {
        (
            ComplianceAggregateState::EvaluationError,
            ComplianceAggregateRationale::CustomComplianceScriptFailed,
            collect_evidence(custom_failed.iter().flat_map(|c| c.evidence.iter())),
        )
    } else if phase.contradictory_count > 0 {
        (
            ComplianceAggregateState::InsufficientEvidence,
            ComplianceAggregateRationale::ContradictoryLocalEvidence,
            evidence_for(local, ComplianceSettingState::Contradictory),
        )
    } else if phase.compliant_count > 0 {
        (
            ComplianceAggregateState::Compliant,
            ComplianceAggregateRationale::AllEvaluatedSettingsCompliant,
            evidence_for(local, ComplianceSettingState::Compliant),
        )
    } else if has_local_source {
        (
            ComplianceAggregateState::NotEvaluated,
            ComplianceAggregateRationale::NoSettingEvaluated,
            collect_evidence(local.settings.iter().flat_map(|s| s.evidence.iter())),
        )
    } else {
        (
            ComplianceAggregateState::InsufficientEvidence,
            ComplianceAggregateRationale::NoLocalSourceAvailable,
            Vec::new(),
        )
    };

    phase.state = state;
    phase.rationale = rationale;
    phase.evidence = evidence;
    phase
}

fn evidence_for(
    local: &ComplianceLocalPhase,
    state: ComplianceSettingState,
) -> Vec<IntuneEvidenceRef> {
    collect_evidence(
        local
            .settings
            .iter()
            .filter(|setting| setting.state == state)
            .flat_map(|setting| setting.evidence.iter()),
    )
}

// ── Phase 3: reporting and service state ────────────────────────────────────

fn reduce_reporting(
    input: &ComplianceInput,
    local: &ComplianceLocalPhase,
    aggregate: &ComplianceAggregatePhase,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceReportingPhase {
    let mut phase = ComplianceReportingPhase::default();
    let mut evidence = Vec::new();
    let latest_local = local
        .latest_evaluation_at_utc
        .as_deref()
        .and_then(parse_rfc3339);

    let mut submissions = Vec::new();
    for event in &input.events {
        let Some(ComplianceSignal::ReportSubmission {
            state,
            report_id,
            error,
            submitted_at,
        }) = classify_event(event)
        else {
            continue;
        };
        evidence.push(event.context.evidence_ref.clone());
        submissions.push((state, report_id, error, submitted_at));
    }

    // A submission is the terminal outcome: once the bundle shows the report went
    // out, a queued or failed row elsewhere cannot take that back. A failure still
    // outranks queued, because an observed submission failure is not undone by a
    // queued row. Expressed as a rank over the whole set rather than as a running
    // assignment: the two strongest tokens were already order-free, but the
    // remaining three fell through to a plain last-writer-wins, so a queued row
    // and an uninterpretable one swapped the exported state between them.
    phase.state = submissions
        .iter()
        .map(|(state, ..)| *state)
        .max_by_key(|state| report_state_rank(*state))
        .unwrap_or(ComplianceReportState::Unknown);
    // Smallest stated rather than first stated, for the same reason the setting
    // merge names the smallest: "first" was the collector's serializer. Every
    // submission row stays cited, so neither value is hidden.
    phase.report_id = submissions
        .iter()
        .filter_map(|(_, report_id, ..)| report_id.as_ref())
        .min()
        .cloned();
    phase.error = submissions
        .iter()
        .filter_map(|(_, _, error, _)| error.as_ref())
        .min_by(|left, right| {
            (&left.decimal, &left.hex, &left.raw).cmp(&(&right.decimal, &right.hex, &right.raw))
        })
        .cloned();
    phase.last_submission_at = latest_submission_at(
        submissions
            .iter()
            .filter(|(state, ..)| *state == ComplianceReportState::Submitted)
            .filter_map(|(_, _, _, submitted_at)| submitted_at.as_ref()),
    );

    // A submission that predates the most recent local evaluation cannot carry
    // that evaluation's result, whatever the submission itself reported.
    if phase.state == ComplianceReportState::Submitted {
        if let (Some(submitted), Some(latest_local)) = (
            phase
                .last_submission_at
                .as_ref()
                .and_then(normalized_timestamp),
            latest_local,
        ) {
            if submitted < latest_local {
                phase.state = ComplianceReportState::Stale;
            }
        }
    }

    phase.service_results = input
        .service_results
        .iter()
        .map(|fact| {
            evidence.push(fact.context.evidence_ref.clone());
            let reported = fact.reported_at.as_ref().and_then(normalized_timestamp);
            let freshness = match (reported, latest_local) {
                (Some(reported), Some(local)) if reported >= local => {
                    ComplianceServiceFreshness::Fresh
                }
                (Some(_), Some(_)) => ComplianceServiceFreshness::Stale,
                _ => ComplianceServiceFreshness::Unknown,
            };
            ComplianceServiceResult {
                policy_id: fact.policy_id.clone(),
                setting_id: fact.setting_id.clone(),
                state: fact.state.clone(),
                reported_at: fact.reported_at.clone(),
                freshness,
                device_key: fact.device_key.clone(),
                user_key: fact.user_key.clone(),
                evidence: vec![fact.context.evidence_ref.clone()],
            }
        })
        .collect();

    // As with the custom-compliance results: a set of service records, not a
    // sequence. Nothing downstream reads their position, and leaving them in the
    // caller's order put it in the serialized snapshot.
    //
    // Evidence first, then what the record is about (the policy, then the setting
    // within it), then when the service reported it. The instant is last because
    // it is the weakest of the three: two service rows for one setting differ by
    // time, but two rows for different settings should not be interleaved by it.
    // `timestamp_content_key` is reused rather than the normalized instant, so a
    // zone-less stamp still orders by content instead of collapsing to `None`.
    //
    // `content_key` closes the comparison over `state`, `device_key`, `user_key`
    // and every field added after this was written.
    phase.service_results.sort_by(|left, right| {
        left.evidence
            .cmp(&right.evidence)
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.setting_id.cmp(&right.setting_id))
            .then_with(|| {
                left.reported_at
                    .as_ref()
                    .map(timestamp_content_key)
                    .cmp(&right.reported_at.as_ref().map(timestamp_content_key))
            })
            .then_with(|| content_key(left).cmp(&content_key(right)))
    });

    phase.service_freshness = fold_freshness(&phase.service_results);
    phase.service_disagrees_with_local = phase
        .service_results
        .iter()
        .any(|result| disagrees(&result.state, aggregate.state));

    // A service record stamped after the snapshot was generated is a provenance
    // contradiction, not a fresher truth; surface it as unknown freshness.
    if let Some(generated_at) = generated_at {
        let future = phase.service_results.iter().any(|result| {
            result
                .reported_at
                .as_ref()
                .and_then(normalized_timestamp)
                .is_some_and(|reported| reported > generated_at)
        });
        if future {
            phase.service_freshness = ComplianceServiceFreshness::Unknown;
        }
    }

    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

/// Precedence of one report-status token over another, strongest first.
///
/// Injective over the five variants, so a fold by maximum rank has no ties to
/// break and cannot depend on the order the rows were read in.
fn report_state_rank(state: ComplianceReportState) -> u8 {
    match state {
        ComplianceReportState::Submitted => 4,
        ComplianceReportState::Failed => 3,
        // A source calling its own submission stale still reports a completed
        // one, which says more than a row that is only queued.
        ComplianceReportState::Stale => 2,
        ComplianceReportState::Queued => 1,
        ComplianceReportState::Unknown => 0,
    }
}

fn fold_freshness(results: &[ComplianceServiceResult]) -> ComplianceServiceFreshness {
    if results.is_empty() {
        return ComplianceServiceFreshness::Unknown;
    }
    if results
        .iter()
        .any(|result| result.freshness == ComplianceServiceFreshness::Stale)
    {
        return ComplianceServiceFreshness::Stale;
    }
    if results
        .iter()
        .all(|result| result.freshness == ComplianceServiceFreshness::Fresh)
    {
        return ComplianceServiceFreshness::Fresh;
    }
    ComplianceServiceFreshness::Unknown
}

/// Whether a service-held state contradicts the locally derived aggregate.
///
/// Only the two unambiguous pairings count. An unrecognized service token, a
/// grace period, or an error state is not a disagreement, because we cannot say
/// what it disagrees with.
fn disagrees(service: &ComplianceServiceState, aggregate: ComplianceAggregateState) -> bool {
    matches!(
        (service, aggregate),
        (
            ComplianceServiceState::Noncompliant,
            ComplianceAggregateState::Compliant
        ) | (
            ComplianceServiceState::Compliant,
            ComplianceAggregateState::Noncompliant
        )
    )
}

// ── Phase 4: downstream access ──────────────────────────────────────────────

/// Attach access decisions as downstream impact.
///
/// A decision reaches [`ComplianceAccessLinkage::MatchedComplianceState`] only
/// when a device or user key matches a compliance record *and* both sides carry
/// a normalized timestamp with the compliance record preceding the decision.
/// Everything weaker is explicitly uncorrelated; the rules then refuse to make a
/// causal claim from it.
fn reduce_access(
    input: &ComplianceInput,
    reporting: &ComplianceReportingPhase,
) -> ComplianceAccessPhase {
    let mut phase = ComplianceAccessPhase::default();
    let mut evidence = Vec::new();

    for fact in &input.access_decisions {
        evidence.push(fact.context.evidence_ref.clone());
        let occurred = fact.occurred_at.as_ref().and_then(normalized_timestamp);

        let matched = reporting
            .service_results
            .iter()
            .filter(|result| keys_match(fact, result))
            .filter(|result| {
                match (
                    result.reported_at.as_ref().and_then(normalized_timestamp),
                    occurred,
                ) {
                    (Some(reported), Some(occurred)) => reported <= occurred,
                    // Time-only proximity, or no time at all, cannot correlate.
                    _ => false,
                }
            })
            .collect::<Vec<_>>();

        let identity_declared = fact.device_key.is_some() || fact.user_key.is_some();
        let candidates_exist = !reporting.service_results.is_empty();

        let linkage = if !matched.is_empty() {
            ComplianceAccessLinkage::MatchedComplianceState
        } else if !candidates_exist {
            ComplianceAccessLinkage::NoMatchingComplianceEvidence
        } else if !identity_declared || occurred.is_none() {
            ComplianceAccessLinkage::InsufficientProvenance
        } else if reporting
            .service_results
            .iter()
            .any(|result| keys_match(fact, result))
        {
            // Identity lines up but the times do not; provenance is incomplete.
            ComplianceAccessLinkage::InsufficientProvenance
        } else {
            ComplianceAccessLinkage::IdentityMismatch
        };

        phase.decisions.push(ComplianceAccessObservation {
            decision: fact.decision,
            linkage,
            failure_code: fact.failure_code.clone(),
            occurred_at: fact.occurred_at.clone(),
            device_key: fact.device_key.clone(),
            user_key: fact.user_key.clone(),
            resource: fact.resource.clone(),
            matched_evidence: collect_evidence(matched.iter().flat_map(|r| r.evidence.iter())),
            evidence: vec![fact.context.evidence_ref.clone()],
        });
    }

    // Access decisions are correlated by identity and time, never by position, so
    // the exported order is a set order like the two above.
    //
    // Time leads here where it trailed the record fields for service results: a
    // denial *is* an event, and a reader scans the array as a sequence of
    // attempts, so ordering two denials by when they happened is the reading
    // that matches the data.
    //
    // The leading key is [`chronological_key`], the *normalized instant*, not
    // `timestamp_content_key`. That key compares `raw_text` first, so leading
    // with it would order by how the source spelled the time rather than by when
    // it happened: "07/31/2026 11:50:00" sorts before "2026-07-30T00:00:00Z"
    // because '0' < '2', and an `Offset` stamp reading 13:50+02:00 sorts after a
    // `Utc` stamp reading 12:00Z though it is the earlier instant. The corpus
    // hides this because every stamp in it is one shape, and same-shape RFC 3339
    // happens to sort chronologically as text.
    //
    // A decision whose zone is unknown has no instant `normalized_timestamp`
    // will vouch for, so it cannot be placed on that timeline at all.
    // `chronological_key` sorts those after every dated decision instead of
    // interleaving them on a guess, and `timestamp_content_key` follows so they
    // still separate from each other by their raw stamps rather than collapsing.
    // That link also settles two dated decisions whose instants are equal but
    // whose stamps are spelled differently. Evidence, subject and resource then
    // separate attempts that agree on all of it.
    //
    // `content_key` closes the comparison over `decision`, `linkage`,
    // `failure_code` and `matched_evidence`, none of which are named above, and
    // over every field added after this was written.
    phase.decisions.sort_by(|left, right| {
        chronological_key(left.occurred_at.as_ref())
            .cmp(&chronological_key(right.occurred_at.as_ref()))
            .then_with(|| {
                left.occurred_at
                    .as_ref()
                    .map(timestamp_content_key)
                    .cmp(&right.occurred_at.as_ref().map(timestamp_content_key))
            })
            .then_with(|| left.evidence.cmp(&right.evidence))
            .then_with(|| left.device_key.cmp(&right.device_key))
            .then_with(|| left.user_key.cmp(&right.user_key))
            .then_with(|| left.resource.cmp(&right.resource))
            .then_with(|| content_key(left).cmp(&content_key(right)))
    });

    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

/// Whether one access decision and one service record name the same subject.
///
/// Every identity the decision declares must match. A decision that names both a
/// device and a user is only about the service record that names both the same
/// way; accepting either half alone would correlate a denial for one user with
/// another user's compliance state on the same device. A decision that declares
/// no identity at all cannot be correlated with anything.
fn keys_match(fact: &ComplianceAccessFact, result: &ComplianceServiceResult) -> bool {
    let same = |left: &Option<String>, right: &Option<String>| match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    };

    match (fact.device_key.is_some(), fact.user_key.is_some()) {
        (true, true) => {
            same(&fact.device_key, &result.device_key) && same(&fact.user_key, &result.user_key)
        }
        (true, false) => same(&fact.device_key, &result.device_key),
        (false, true) => same(&fact.user_key, &result.user_key),
        (false, false) => false,
    }
}

// ── Time helpers ────────────────────────────────────────────────────────────

/// Only a timestamp whose kind is trustworthy for ordering may be used.
///
/// A local or unspecified-zone timestamp has no known offset, so its normalized
/// form is a guess; using it to order a submission against an evaluation, or a
/// service record against an access decision, would manufacture a correlation
/// out of an unknown. Such timestamps are declined here and surface as missing
/// provenance instead.
pub(super) fn normalized_timestamp(timestamp: &IntuneTimestamp) -> Option<DateTime<Utc>> {
    match timestamp.kind {
        IntuneTimestampKind::Utc | IntuneTimestampKind::Offset => {
            timestamp.normalized_utc.as_deref().and_then(parse_rfc3339)
        }
        _ => None,
    }
}

pub(super) fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneNamedValue;

    /// A fully populated observation, so every field has a stated value to lose.
    ///
    /// Every `Option` is `Some` and the collection is non-empty on purpose. A
    /// mutation from `None` to `Some(_)` changes the `Debug` rendering even if
    /// the inner value never reaches it, so it would pass against exactly the
    /// lossy `Debug` this test exists to catch. Each mutation below changes a
    /// stated value into a different stated value instead.
    fn observation_for_key_coverage() -> SettingObservation {
        SettingObservation {
            key: ComplianceSettingKey {
                policy_id: Some("policy".to_owned()),
                setting_id: Some("setting".to_owned()),
                setting_uri: Some("./Device/Vendor/MSFT/Policy/Result/Probe".to_owned()),
            },
            grouping_token: "uri:./device/vendor/msft/policy/result/probe".to_owned(),
            scope: ComplianceScope::Device,
            state: ComplianceSettingState::Compliant,
            display_name: Some("a name".to_owned()),
            error: Some(IntuneErrorCode {
                raw: "0x80070005".to_owned(),
                decimal: Some(-2147024891),
                hex: Some("0x80070005".to_owned()),
            }),
            evaluated_at: Some(timestamp("2026-07-31T10:00:00Z")),
            named_data: vec![IntuneNamedValue {
                name: "probe".to_owned(),
                value: "a value".to_owned(),
            }],
            context: context("obs-1", "mdm-report"),
        }
    }

    /// Every field of `SettingObservation`, paired with an observation that
    /// differs from [`observation_for_key_coverage`] in that field alone.
    ///
    /// The table is self-maintaining, which is the point of writing it this way
    /// rather than as a literal list:
    ///
    /// - the destructuring carries no `..`, so a field added to
    ///   `SettingObservation` later stops this function compiling until it is
    ///   named here;
    /// - every binding the destructuring introduces is consumed by the
    ///   `assert_ne!` guarding its mutation, and `unused_variables` is denied
    ///   below rather than left as a warning, so naming a field without
    ///   mutating it is a compile error too;
    /// - those same assertions prove each mutation is a real change rather than
    ///   a restatement of the base, so no row can pass vacuously.
    ///
    /// A field cannot reach the export order without passing through here.
    #[deny(unused_variables)]
    fn single_field_mutations() -> Vec<(&'static str, SettingObservation)> {
        let SettingObservation {
            key,
            grouping_token,
            scope,
            state,
            display_name,
            error,
            evaluated_at,
            named_data,
            context: base_context,
        } = observation_for_key_coverage();

        let mutated_key = ComplianceSettingKey {
            policy_id: Some("other-policy".to_owned()),
            ..key.clone()
        };
        let mutated_grouping_token = "uri:./device/vendor/msft/policy/result/other".to_owned();
        let mutated_scope = ComplianceScope::User;
        let mutated_state = ComplianceSettingState::Noncompliant;
        let mutated_display_name = Some("another name".to_owned());
        let mutated_error = Some(IntuneErrorCode {
            raw: "0x80070002".to_owned(),
            decimal: Some(-2147024894),
            hex: Some("0x80070002".to_owned()),
        });
        let mutated_evaluated_at = Some(timestamp("2026-07-31T11:00:00Z"));
        let mutated_named_data = vec![IntuneNamedValue {
            name: "probe".to_owned(),
            value: "another value".to_owned(),
        }];
        let mutated_context = context("obs-2", "mdm-report");

        assert_ne!(mutated_key, key, "the `key` mutation must change `key`");
        assert_ne!(
            mutated_grouping_token, grouping_token,
            "the `grouping_token` mutation must change `grouping_token`"
        );
        assert_ne!(
            mutated_scope, scope,
            "the `scope` mutation must change `scope`"
        );
        assert_ne!(
            mutated_state, state,
            "the `state` mutation must change `state`"
        );
        assert_ne!(
            mutated_display_name, display_name,
            "the `display_name` mutation must change `display_name`"
        );
        assert_ne!(
            mutated_error, error,
            "the `error` mutation must change `error`"
        );
        assert_ne!(
            mutated_evaluated_at, evaluated_at,
            "the `evaluated_at` mutation must change `evaluated_at`"
        );
        assert_ne!(
            mutated_named_data, named_data,
            "the `named_data` mutation must change `named_data`"
        );
        assert_ne!(
            mutated_context, base_context,
            "the `context` mutation must change `context`"
        );

        vec![
            (
                "key",
                SettingObservation {
                    key: mutated_key,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "grouping_token",
                SettingObservation {
                    grouping_token: mutated_grouping_token,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "scope",
                SettingObservation {
                    scope: mutated_scope,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "state",
                SettingObservation {
                    state: mutated_state,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "display_name",
                SettingObservation {
                    display_name: mutated_display_name,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "error",
                SettingObservation {
                    error: mutated_error,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "evaluated_at",
                SettingObservation {
                    evaluated_at: mutated_evaluated_at,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "named_data",
                SettingObservation {
                    named_data: mutated_named_data,
                    ..observation_for_key_coverage()
                },
            ),
            (
                "context",
                SettingObservation {
                    context: mutated_context,
                    ..observation_for_key_coverage()
                },
            ),
        ]
    }

    /// `structural_key` orders observations by their `Debug` rendering, so every
    /// field must reach that rendering. A hand-written or lossy `Debug` on
    /// `SettingObservation`, or on any type it nests, would silently drop a field
    /// from the key: `merge_setting` chains `structural_key` after the evidence
    /// ref and `slice::sort_by` is stable, so a pair the key stops separating
    /// falls back to the caller's vector order.
    ///
    /// This pins each field individually rather than the struct as a whole, so a
    /// field that stops participating fails here and names itself.
    /// [`single_field_mutations`] is what makes "each field" true, and what keeps
    /// it true as the struct grows.
    #[test]
    fn structural_key_separates_observations_differing_in_any_single_field() {
        let base = observation_for_key_coverage();
        for (field, mutated) in single_field_mutations() {
            assert_ne!(
                structural_key(&base),
                structural_key(&mutated),
                "changing `{field}` must change the structural key, or that field \
                 stops participating in the export order"
            );
        }
    }

    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestampKind,
    };
    use crate::intune::normalized::{
        NormalizedEventLevel, NormalizedSettingOutcome, NormalizedSettingReport,
        NormalizedWindowsEvent,
    };

    fn context(evidence_id: &str, artifact: &str) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: evidence_id.to_owned(),
                source_artifact_id: artifact.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: artifact.to_owned(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    fn timestamp(value: &str) -> IntuneTimestamp {
        IntuneTimestamp {
            raw_text: value.to_owned(),
            original_offset: None,
            normalized_utc: Some(value.to_owned()),
            kind: IntuneTimestampKind::Utc,
        }
    }

    fn setting_event(
        evidence_id: &str,
        uri: &str,
        result: &str,
        at: &str,
    ) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: IntuneObservationContext {
                source_timestamp: Some(timestamp(at)),
                ..context(evidence_id, "events")
            },
            channel: "channel".to_owned(),
            provider: "provider".to_owned(),
            event_id: 100,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: None,
            activity_id: None,
            event_version: None,
            named_data: vec![
                crate::intune::evidence::IntuneNamedValue {
                    name: "SettingUri".to_owned(),
                    value: uri.to_owned(),
                },
                crate::intune::evidence::IntuneNamedValue {
                    name: "EvaluationResult".to_owned(),
                    value: result.to_owned(),
                },
            ],
            message: None,
        }
    }

    #[test]
    fn two_disagreeing_definite_sources_produce_a_contradiction() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                setting_event("e1", "./Device/X", "compliant", "2026-07-31T10:00:00Z"),
                setting_event("e2", "./Device/X", "noncompliant", "2026-07-31T10:05:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.local_evaluation.settings.len(), 1);
        assert_eq!(
            snapshot.local_evaluation.settings[0].state,
            ComplianceSettingState::Contradictory
        );
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::InsufficientEvidence
        );
    }

    #[test]
    fn a_stale_service_record_never_changes_the_local_state() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![setting_event(
                "e1",
                "./Device/X",
                "compliant",
                "2026-07-31T10:00:00Z",
            )],
            service_results: vec![ComplianceServiceFact {
                context: context("s1", "service"),
                policy_id: None,
                setting_id: None,
                state: ComplianceServiceState::Noncompliant,
                reported_at: Some(timestamp("2026-07-30T09:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::Compliant
        );
        assert_eq!(
            snapshot.reporting.service_freshness,
            ComplianceServiceFreshness::Stale
        );
        assert!(snapshot.reporting.service_disagrees_with_local);
        assert!(
            snapshot
                .local_evaluation
                .settings
                .iter()
                .all(|setting| setting.state == ComplianceSettingState::Compliant),
            "a service record must never rewrite a local setting state"
        );
    }

    #[test]
    fn an_access_denial_alone_correlates_to_nothing() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            access_decisions: vec![ComplianceAccessFact {
                context: context("a1", "access"),
                decision: ComplianceAccessDecision::Denied,
                failure_code: None,
                occurred_at: Some(timestamp("2026-07-31T11:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: None,
                resource: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.access_impact.decisions[0].linkage,
            ComplianceAccessLinkage::NoMatchingComplianceEvidence
        );
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::InsufficientEvidence,
            "an access denial must not produce a local compliance verdict"
        );
    }

    #[test]
    fn a_custom_script_failure_is_an_error_not_a_noncompliance() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            custom_compliance: vec![ComplianceCustomFact {
                context: context("c1", "custom"),
                policy_id: Some("policy-1".to_owned()),
                run_id: Some("run-1".to_owned()),
                setting_name: Some("DiskEncryption".to_owned()),
                outcome: ComplianceCustomState::ScriptFailed,
                error: None,
                raw_output: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::EvaluationError
        );
        assert_eq!(
            snapshot.aggregate.rationale,
            ComplianceAggregateRationale::CustomComplianceScriptFailed
        );
    }

    #[test]
    fn a_submission_predating_the_latest_evaluation_is_stale() {
        let mut submitted = setting_event("e2", "./Device/Y", "compliant", "2026-07-31T09:00:00Z");
        submitted.named_data = vec![crate::intune::evidence::IntuneNamedValue {
            name: "ReportStatus".to_owned(),
            value: "submitted".to_owned(),
        }];
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                setting_event("e1", "./Device/X", "compliant", "2026-07-31T10:00:00Z"),
                submitted,
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.reporting.state, ComplianceReportState::Stale);
    }

    fn report_event(evidence_id: &str, status: &str, at: &str) -> NormalizedWindowsEvent {
        let mut event = setting_event(evidence_id, "./Device/X", "compliant", at);
        event.named_data = vec![crate::intune::evidence::IntuneNamedValue {
            name: "ReportStatus".to_owned(),
            value: status.to_owned(),
        }];
        event
    }

    #[test]
    fn a_submission_after_a_failure_is_reported_as_submitted() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                report_event("r1", "failed", "2026-07-31T10:00:00Z"),
                report_event("r2", "submitted", "2026-07-31T11:00:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.reporting.state,
            ComplianceReportState::Submitted,
            "a later successful submission must not stay hidden behind an earlier failure"
        );
    }

    #[test]
    fn a_queued_row_after_a_failure_does_not_undo_the_failure() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                report_event("r1", "failed", "2026-07-31T10:00:00Z"),
                report_event("r2", "queued", "2026-07-31T11:00:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.reporting.state, ComplianceReportState::Failed);
    }

    #[test]
    fn a_denial_naming_a_different_user_on_the_same_device_is_not_correlated() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![setting_event(
                "e1",
                "./Device/X",
                "compliant",
                "2026-07-31T09:00:00Z",
            )],
            service_results: vec![ComplianceServiceFact {
                context: context("s1", "service"),
                policy_id: None,
                setting_id: None,
                state: ComplianceServiceState::Noncompliant,
                reported_at: Some(timestamp("2026-07-31T10:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: Some("user-1".to_owned()),
                named_data: Vec::new(),
            }],
            access_decisions: vec![ComplianceAccessFact {
                context: context("a1", "access"),
                decision: ComplianceAccessDecision::Denied,
                failure_code: None,
                occurred_at: Some(timestamp("2026-07-31T11:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: Some("user-2".to_owned()),
                resource: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.access_impact.decisions[0].linkage,
            ComplianceAccessLinkage::IdentityMismatch,
            "a denial that names a different user must not borrow another user's state"
        );
    }

    fn access_decision(evidence_id: &str, occurred_at: IntuneTimestamp) -> ComplianceAccessFact {
        ComplianceAccessFact {
            context: context(evidence_id, "access"),
            decision: ComplianceAccessDecision::Denied,
            failure_code: None,
            occurred_at: Some(occurred_at),
            device_key: Some("device-1".to_owned()),
            user_key: None,
            resource: None,
            named_data: Vec::new(),
        }
    }

    /// The exported decision array reads chronologically, and nothing else
    /// decides it.
    ///
    /// The bundle is built so every other candidate ordering disagrees with
    /// chronology, which is what makes the assertion mean something:
    ///
    /// - evidence ids sort `a-later` before `z-earlier`, the reverse of time, so
    ///   a comparison led by `evidence` cannot produce this order;
    /// - raw stamp text sorts `07/31/2026 ...` before `2026-07-31T...`, also the
    ///   reverse of time, so `timestamp_content_key` cannot produce it either;
    /// - the decision whose zone is unknown carries the raw stamp and the
    ///   evidence id that both sort first, so only refusing to place it on the
    ///   timeline puts it last.
    ///
    /// Only the normalized instant, with the unplaceable stamp sorted after every
    /// placeable one, yields the asserted sequence.
    #[test]
    fn access_decisions_export_in_chronological_order() {
        let earlier = access_decision(
            "z-earlier",
            IntuneTimestamp {
                raw_text: "2026-07-31T11:00:00Z".to_owned(),
                original_offset: None,
                normalized_utc: Some("2026-07-31T11:00:00Z".to_owned()),
                kind: IntuneTimestampKind::Utc,
            },
        );
        let later = access_decision(
            "a-later",
            IntuneTimestamp {
                raw_text: "07/31/2026 09:30:00 -02:00".to_owned(),
                original_offset: Some("-02:00".to_owned()),
                normalized_utc: Some("2026-07-31T11:30:00Z".to_owned()),
                kind: IntuneTimestampKind::Offset,
            },
        );
        let unplaceable = access_decision(
            "a-unplaceable",
            IntuneTimestamp {
                raw_text: "07/31/2026 08:00:00".to_owned(),
                original_offset: None,
                normalized_utc: Some("2026-07-31T08:00:00Z".to_owned()),
                kind: IntuneTimestampKind::Unspecified,
            },
        );

        let order = |access_decisions: Vec<ComplianceAccessFact>| {
            analyze_compliance(&ComplianceInput {
                generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
                access_decisions,
                ..ComplianceInput::default()
            })
            .access_impact
            .decisions
            .iter()
            .map(|decision| decision.evidence[0].evidence_id.clone())
            .collect::<Vec<_>>()
        };

        let expected = vec![
            "z-earlier".to_owned(),
            "a-later".to_owned(),
            "a-unplaceable".to_owned(),
        ];
        assert_eq!(
            order(vec![earlier.clone(), later.clone(), unplaceable.clone()]),
            expected,
            "the decision array must read as a sequence of attempts in time, with \
             a decision whose zone is unknown after every decision that can be \
             placed on that timeline"
        );
        assert_eq!(
            order(vec![unplaceable, later, earlier]),
            expected,
            "and the resolved order must not depend on the caller's vector"
        );
    }

    /// A report row may carry a present-but-blank identifier, because
    /// `classify_setting_report` copies the key verbatim from JSON while the
    /// event path filters every field through `named_any`. A blank states
    /// nothing, so it must not be exported as this setting's id.
    #[test]
    fn a_blank_identifier_is_not_exported_as_an_identifier() {
        let report = NormalizedSettingReport {
            context: context("r1", "report"),
            setting_uri: Some("./Device/X".to_owned()),
            setting_id: Some(String::new()),
            policy_id: Some("   ".to_owned()),
            display_name: Some(String::new()),
            outcome: NormalizedSettingOutcome::Applied,
            value: None,
            error: None,
            named_data: Vec::new(),
        };
        let snapshot = analyze_compliance(&ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            setting_reports: vec![report],
            ..ComplianceInput::default()
        });

        let setting = &snapshot.local_evaluation.settings[0];
        assert_eq!(
            setting.key.setting_uri.as_deref(),
            Some("./Device/X"),
            "the one identifier the row actually states must survive"
        );
        assert_eq!(
            setting.key.setting_id, None,
            "an empty setting id states nothing and must not be exported as one"
        );
        assert_eq!(
            setting.key.policy_id, None,
            "a whitespace-only policy id states nothing and must not be exported as one"
        );
        assert_eq!(
            setting.display_name, None,
            "an empty display name must not be quoted by a finding as this setting's name"
        );
        assert!(
            !setting.identity_contradiction,
            "a blank alongside a stated id is not two records disagreeing"
        );
    }

    #[test]
    fn a_timestamp_with_no_known_zone_cannot_order_anything() {
        let unusable = IntuneTimestamp {
            raw_text: "2026-07-31T10:00:00".to_owned(),
            original_offset: None,
            normalized_utc: Some("2026-07-31T10:00:00Z".to_owned()),
            kind: IntuneTimestampKind::Unspecified,
        };
        assert_eq!(
            normalized_timestamp(&unusable),
            None,
            "a zone-less timestamp must not be treated as an ordered UTC instant"
        );
    }

    // ── Caller order must not decide anything ───────────────────────────────

    fn named(name: &str, value: &str) -> crate::intune::evidence::IntuneNamedValue {
        crate::intune::evidence::IntuneNamedValue {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    fn analyze_events(events: Vec<NormalizedWindowsEvent>) -> ComplianceSnapshot {
        analyze_compliance(&ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events,
            ..ComplianceInput::default()
        })
    }

    /// The severe case: the staleness gate reads `last_submission_at`, which was
    /// an unconditional last-wins overwrite. Two submissions straddling the most
    /// recent local evaluation therefore exported `Submitted` or `Stale`
    /// depending only on which one the caller listed last.
    #[test]
    fn two_submissions_straddling_the_evaluation_do_not_flip_the_report_state() {
        let evaluated = setting_event("e1", "./Device/X", "compliant", "2026-07-31T10:00:00Z");
        let early = report_event("r-early", "submitted", "2026-07-31T09:00:00Z");
        let late = report_event("r-late", "submitted", "2026-07-31T11:00:00Z");

        let forward = analyze_events(vec![evaluated.clone(), early.clone(), late.clone()]);
        let reverse = analyze_events(vec![evaluated, late, early]);

        assert_eq!(
            forward.reporting.state, reverse.reporting.state,
            "the staleness gate must not read whichever submission the caller listed last"
        );
        assert_eq!(
            forward.reporting.state,
            ComplianceReportState::Submitted,
            "a submission that postdates the evaluation carries it, whatever else was submitted earlier"
        );
        assert_eq!(
            forward.reporting.last_submission_at, reverse.reporting.last_submission_at,
            "the reported submission instant must be a function of the evidence, not the vector"
        );
    }

    /// The `Submitted` and `Failed` arms of the report fold outrank everything,
    /// but the remaining tokens fell through to a plain last-writer-wins
    /// assignment, so a queued row and an uninterpretable one swapped the
    /// exported state between them.
    #[test]
    fn a_queued_row_and_an_unknown_row_do_not_swap_the_report_state() {
        let queued = report_event("r-queued", "queued", "2026-07-31T10:00:00Z");
        let unknown = report_event("r-unknown", "banana", "2026-07-31T11:00:00Z");

        let forward = analyze_events(vec![queued.clone(), unknown.clone()]);
        let reverse = analyze_events(vec![unknown, queued]);

        assert_eq!(
            forward.reporting.state, reverse.reporting.state,
            "the weaker report tokens must fold by rank like the stronger ones do"
        );
        assert_eq!(
            forward.reporting.state,
            ComplianceReportState::Queued,
            "an uninterpretable status must not erase an observed queued submission"
        );
    }

    /// Two submission rows naming different report ids or codes must not let the
    /// caller's vector pick which one the export leads with.
    #[test]
    fn two_submission_rows_do_not_let_caller_order_pick_the_report_id_or_error() {
        let mut zebra = report_event("r-zebra", "failed", "2026-07-31T10:00:00Z");
        zebra
            .named_data
            .extend([named("ReportId", "zebra"), named("ErrorCode", "0x80070005")]);
        let mut alpha = report_event("r-alpha", "failed", "2026-07-31T11:00:00Z");
        alpha
            .named_data
            .extend([named("ReportId", "alpha"), named("ErrorCode", "0x80070002")]);

        let forward = analyze_events(vec![zebra.clone(), alpha.clone()]);
        let reverse = analyze_events(vec![alpha, zebra]);

        assert_eq!(
            forward.reporting.report_id, reverse.reporting.report_id,
            "the exported report id must not depend on the caller's vector"
        );
        assert_eq!(
            forward.reporting.error, reverse.reporting.error,
            "the exported submission error must not depend on the caller's vector"
        );
    }

    /// A merged setting's display name is quoted by the noncompliance finding, so
    /// letting the first record in the vector win made the exported summary a
    /// function of the serializer.
    #[test]
    fn a_merged_setting_display_name_does_not_follow_caller_order() {
        let mut zebra = setting_event("e-zebra", "./Device/X", "compliant", "2026-07-31T10:00:00Z");
        zebra.named_data.push(named("DisplayName", "Zebra setting"));
        let mut alpha = setting_event("e-alpha", "./Device/X", "compliant", "2026-07-31T10:05:00Z");
        alpha.named_data.push(named("DisplayName", "Alpha setting"));

        let forward = analyze_events(vec![zebra.clone(), alpha.clone()]);
        let reverse = analyze_events(vec![alpha, zebra]);

        assert_eq!(
            forward.local_evaluation.settings[0].display_name,
            reverse.local_evaluation.settings[0].display_name,
            "two records naming one setting differently must not flip which name is exported"
        );
    }

    /// Two records stating different terminal codes for one setting must not flip
    /// which code the export quotes.
    #[test]
    fn a_merged_setting_error_does_not_follow_caller_order() {
        let mut first = setting_event("e-first", "./Device/X", "error", "2026-07-31T10:00:00Z");
        first.named_data.push(named("ErrorCode", "0x80070005"));
        let mut second = setting_event("e-second", "./Device/X", "error", "2026-07-31T10:05:00Z");
        second.named_data.push(named("ErrorCode", "0x80070002"));

        let forward = analyze_events(vec![first.clone(), second.clone()]);
        let reverse = analyze_events(vec![second, first]);

        assert_eq!(
            forward.local_evaluation.settings[0].error, reverse.local_evaluation.settings[0].error,
            "the exported setting error must not depend on the caller's vector"
        );
    }

    /// Scope decides whether the "user-targeted policy was never evaluated"
    /// finding fires at all, so two sources disagreeing about it must not be
    /// resolved by vector position.
    #[test]
    fn two_records_disagreeing_about_scope_do_not_follow_caller_order() {
        let mut as_device =
            setting_event("e-device", "./Device/X", "notevaluated", "2026-07-31T10:00:00Z");
        as_device.named_data.push(named("Scope", "device"));
        let mut as_user =
            setting_event("e-user", "./Device/X", "notevaluated", "2026-07-31T10:05:00Z");
        as_user.named_data.push(named("Scope", "user"));

        let forward = analyze_events(vec![as_device.clone(), as_user.clone()]);
        let reverse = analyze_events(vec![as_user, as_device]);

        assert_eq!(
            forward.local_evaluation.settings[0].scope, reverse.local_evaluation.settings[0].scope,
            "an unresolved scope disagreement must not be decided by vector position"
        );
        assert_eq!(
            forward.local_evaluation.settings[0].scope,
            ComplianceScope::Unknown,
            "two equally authoritative sources disagreeing about scope state no scope (ADR-003)"
        );
    }

    /// Two rows describing one policy differently must not export whichever the
    /// caller happened to hand over first.
    #[test]
    fn two_policy_rows_do_not_let_caller_order_pick_the_policy_state() {
        let policy_event = |evidence_id: &str, state: &str, scope: &str, at: &str| {
            let mut event = setting_event(evidence_id, "./Device/X", "compliant", at);
            event.named_data = vec![
                named("PolicyId", "policy-1"),
                named("PolicyState", state),
                named("Scope", scope),
            ];
            event
        };
        let received = policy_event("p-received", "received", "device", "2026-07-31T10:00:00Z");
        let missing = policy_event("p-missing", "missing", "user", "2026-07-31T11:00:00Z");

        let forward = analyze_events(vec![received.clone(), missing.clone()]);
        let reverse = analyze_events(vec![missing, received]);

        assert_eq!(
            forward.local_evaluation.policies[0].state, reverse.local_evaluation.policies[0].state,
            "the exported policy state must not depend on the caller's vector"
        );
        assert_eq!(
            forward.local_evaluation.policies[0].scope, reverse.local_evaluation.policies[0].scope,
            "the exported policy scope must not depend on the caller's vector"
        );
        // Symmetry alone is too weak an assertion to protect the rule. Replacing
        // the ADR-003 conservative merge with any fixed rank over the variants
        // (Received over NotReceived, Device over User, or the reverse) would be
        // just as symmetric and would still pass the two assertions above. These
        // two pin what the rows must actually resolve to: two equally
        // authoritative sources that disagree name no state and no scope, and
        // both rows stay cited so neither claim is hidden.
        assert_eq!(
            forward.local_evaluation.policies[0].state,
            CompliancePolicyState::Unknown,
            "received and missing are equally authoritative, so the merge names no state (ADR-003)"
        );
        assert_eq!(
            forward.local_evaluation.policies[0].scope,
            ComplianceScope::Unknown,
            "device and user are equally authoritative, so the merge names no scope (ADR-003)"
        );
    }
}
