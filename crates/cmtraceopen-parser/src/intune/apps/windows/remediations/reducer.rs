//! Reduction of classified remediation records into keyed runs.
//!
//! Two records join a run only when they carry the same [`RemediationKey`].
//! Inside the executor log a record may inherit the key *and the stage* of its
//! own execution block -- a contiguous run of records on one CCM thread that
//! begins at a launch -- because that block is written by one execution. It may
//! never inherit either across threads, across artifacts, or from a neighbouring
//! timestamp.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext, IntuneParseState,
    IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestamp, IntuneTimestampKind,
};
use crate::intune::ime_parser::parse_ime_content;

use super::findings::derive_findings;
use super::models::{
    coverage_status, is_readable, lower_confidence, DetectionOutcome, DetectionResult,
    PostRemediationResult, PostRemediationState, RemediationActionResult, RemediationArtifact,
    RemediationEvent, RemediationInvocation, RemediationKey, RemediationObservation,
    RemediationOutcome, RemediationPhase, RemediationRun, RemediationSnapshot, RemediationSourceKind,
    RemediationStage, ReportingResult, ReportingState, REMEDIATION_SCHEMA_VERSION,
};
use super::rules::{classify_record, RecordClassification};
use super::sources::{
    candidate_source_kind, classify_source_kind, output_artifact_identity, rotation_ordinal,
    RemediationSourceInput,
};

/// The observation time reported when the caller supplied none.
///
/// The crate is pure and has no clock, so inventing one would make golden
/// serialization non-deterministic. Callers that care pass `captured_at_utc`.
const UNKNOWN_OBSERVED_AT: &str = "unknown";

/// Render a CCM offset in minutes as `+HH:MM` / `-HH:MM`.
fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

fn source_kind_for(kind: RemediationSourceKind) -> IntuneSourceKind {
    match kind {
        RemediationSourceKind::HealthScripts | RemediationSourceKind::IntuneManagementExtension => {
            IntuneSourceKind::ImeLog
        }
        RemediationSourceKind::AgentExecutor => IntuneSourceKind::AgentLog,
        RemediationSourceKind::RemediationOutput => IntuneSourceKind::PlainTextLog,
        RemediationSourceKind::PolicyMetadata => IntuneSourceKind::SuppliedFact,
        RemediationSourceKind::Unknown => IntuneSourceKind::Unknown("unknown".to_owned()),
    }
}

fn family_for(kind: RemediationSourceKind) -> &'static str {
    match kind {
        RemediationSourceKind::HealthScripts => "healthScripts",
        RemediationSourceKind::AgentExecutor => "agentExecutor",
        RemediationSourceKind::IntuneManagementExtension => "intuneManagementExtension",
        RemediationSourceKind::RemediationOutput => "remediationOutput",
        RemediationSourceKind::PolicyMetadata => "policyMetadata",
        RemediationSourceKind::Unknown => "unknown",
    }
}

/// A classified record plus where it came from, before keying.
struct PendingRecord {
    artifact_index: usize,
    artifact_id: String,
    source_kind: RemediationSourceKind,
    record_number: u32,
    line_number: Option<u32>,
    thread: Option<u32>,
    timestamp: Option<IntuneTimestamp>,
    message: String,
    classification: RecordClassification,
    /// Assigned during block resolution and key reconciliation.
    resolved_policy_id: Option<String>,
    resolved_run_id: Option<String>,
    resolved_stage: Option<RemediationStage>,
    resolved_invocation: RemediationInvocation,
}

impl PendingRecord {
    fn observation_id(&self) -> String {
        format!("{}:{}", self.artifact_id, self.record_number)
    }

    fn evidence(&self) -> IntuneEvidenceRef {
        IntuneEvidenceRef {
            evidence_id: self.observation_id(),
            source_artifact_id: self.artifact_id.clone(),
        }
    }

    fn is_framed(&self) -> bool {
        self.timestamp.is_some() || self.classification.in_scope
    }
}

/// A caller-supplied fact about a policy or a specific run.
struct SuppliedFact {
    policy_id: String,
    run_id: Option<String>,
    invocation: RemediationInvocation,
    retained: Vec<IntuneNamedValue>,
}

/// Reduce a supplied remediation bundle into an immutable snapshot.
///
/// The caller owns all I/O: it reads and decodes each artifact and reports how
/// the collection went. This function performs no filesystem, registry, or
/// network access.
pub fn analyze_remediation_bundle(inputs: &[RemediationSourceInput]) -> RemediationSnapshot {
    let mut artifacts: Vec<RemediationArtifact> = Vec::new();
    let mut records: Vec<PendingRecord> = Vec::new();
    let mut coverage: Vec<IntuneArtifactCoverage> = Vec::new();
    let mut facts: Vec<SuppliedFact> = Vec::new();
    let mut output_artifact_keys: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unreadable_expected_source = false;

    for (artifact_index, input) in inputs.iter().enumerate() {
        let candidate = candidate_source_kind(input);
        let observed_at = input
            .captured_at_utc
            .clone()
            .unwrap_or_else(|| UNKNOWN_OBSERVED_AT.to_owned());

        if !is_readable(&input.access_state) {
            // The name is the only signal left, so it is what coverage reports
            // as missing. Nothing is parsed and nothing is inferred.
            if matches!(
                candidate,
                RemediationSourceKind::HealthScripts | RemediationSourceKind::AgentExecutor
            ) {
                unreadable_expected_source = true;
            }
            artifacts.push(RemediationArtifact {
                artifact_id: input.artifact_id.clone(),
                file_name: input.file_name.clone(),
                file_path: input.file_path.clone(),
                source_kind: candidate,
                rotation_ordinal: rotation_ordinal(&input.file_name),
                access_state: input.access_state.clone(),
                framed_records: 0,
                unframed_records: 0,
            });
            coverage.push(IntuneArtifactCoverage {
                artifact_id: input.artifact_id.clone(),
                family: family_for(candidate).to_owned(),
                status: coverage_status(&input.access_state),
                detail: Some(format!(
                    "{} was not read; no remediation record from it is available",
                    input.file_name
                )),
                observed_at_utc: observed_at,
                evidence: Vec::new(),
            });
            continue;
        }

        let content = input.content.as_deref().unwrap_or_default();

        // A retained output artifact is evidence by its identity alone. Its
        // contents are raw script stdout/stderr -- unbounded and frequently
        // sensitive -- so it is registered and never parsed.
        if candidate == RemediationSourceKind::RemediationOutput {
            if let Some(identity) = output_artifact_identity(input) {
                output_artifact_keys.insert(identity);
            }
            artifacts.push(RemediationArtifact {
                artifact_id: input.artifact_id.clone(),
                file_name: input.file_name.clone(),
                file_path: input.file_path.clone(),
                source_kind: candidate,
                rotation_ordinal: None,
                access_state: input.access_state.clone(),
                framed_records: 0,
                unframed_records: 0,
            });
            coverage.push(IntuneArtifactCoverage {
                artifact_id: input.artifact_id.clone(),
                family: family_for(candidate).to_owned(),
                status: coverage_status(&input.access_state),
                detail: Some(
                    "retained stage output; registered by name and deliberately not parsed"
                        .to_owned(),
                ),
                observed_at_utc: observed_at,
                evidence: Vec::new(),
            });
            continue;
        }

        if candidate == RemediationSourceKind::PolicyMetadata {
            let parsed = parse_policy_metadata(content);
            let detail = match &parsed {
                Some(fact) => format!("supplied policy fact for {}", fact.policy_id),
                None => "supplied policy metadata could not be parsed".to_owned(),
            };
            let status = if parsed.is_some() {
                coverage_status(&input.access_state)
            } else {
                coverage_status(&IntuneAccessState::Failed)
            };
            if let Some(fact) = parsed {
                facts.push(fact);
            }
            artifacts.push(RemediationArtifact {
                artifact_id: input.artifact_id.clone(),
                file_name: input.file_name.clone(),
                file_path: input.file_path.clone(),
                source_kind: candidate,
                rotation_ordinal: None,
                access_state: input.access_state.clone(),
                framed_records: 0,
                unframed_records: 0,
            });
            coverage.push(IntuneArtifactCoverage {
                artifact_id: input.artifact_id.clone(),
                family: family_for(candidate).to_owned(),
                status,
                detail: Some(detail),
                observed_at_utc: observed_at,
                evidence: Vec::new(),
            });
            continue;
        }

        let lines = parse_ime_content(content);
        let components: Vec<Option<String>> =
            lines.iter().map(|line| line.component.clone()).collect();
        let source_kind = classify_source_kind(input, &components);

        let mut framed = 0u32;
        let mut unframed = 0u32;
        let mut first_evidence: Option<IntuneEvidenceRef> = None;

        for (record_index, line) in lines.iter().enumerate() {
            let classification =
                classify_record(source_kind, line.component.as_deref(), &line.message);

            let timestamp = line.timestamp.as_ref().map(|raw| IntuneTimestamp {
                raw_text: raw.clone(),
                original_offset: line.timezone_offset.map(format_offset),
                // Only trust the UTC form when the record stated its own offset.
                // Without one the shared parser fills `timestamp_utc` from the
                // reading machine's local offset, which is a property of whoever
                // opened the log rather than of the evidence.
                normalized_utc: line.timezone_offset.and(line.timestamp_utc.clone()),
                kind: match line.timezone_offset {
                    Some(_) => IntuneTimestampKind::Offset,
                    None => IntuneTimestampKind::Local,
                },
            });

            let record = PendingRecord {
                artifact_index,
                artifact_id: input.artifact_id.clone(),
                source_kind,
                record_number: (record_index + 1) as u32,
                line_number: Some(line.line_number),
                thread: line.thread,
                timestamp,
                message: line.message.clone(),
                resolved_policy_id: classification.policy_id.clone(),
                resolved_run_id: classification.run_id.clone(),
                resolved_stage: classification.stage,
                resolved_invocation: classification.invocation,
                classification,
            };

            if record.is_framed() {
                framed += 1;
            } else {
                // A line the CCM framer could not turn into a logical record.
                // Typically the tail of a record split by a rotation; it never
                // carries a key and can never terminate a run.
                unframed += 1;
            }
            if record.classification.in_scope && first_evidence.is_none() {
                first_evidence = Some(record.evidence());
            }
            records.push(record);
        }

        if matches!(
            candidate,
            RemediationSourceKind::HealthScripts | RemediationSourceKind::AgentExecutor
        ) && source_kind == RemediationSourceKind::Unknown
        {
            // Named like an expected source, contents say otherwise.
            unreadable_expected_source = true;
        }

        artifacts.push(RemediationArtifact {
            artifact_id: input.artifact_id.clone(),
            file_name: input.file_name.clone(),
            file_path: input.file_path.clone(),
            source_kind,
            rotation_ordinal: rotation_ordinal(&input.file_name),
            access_state: input.access_state.clone(),
            framed_records: framed,
            unframed_records: unframed,
        });
        coverage.push(IntuneArtifactCoverage {
            artifact_id: input.artifact_id.clone(),
            family: family_for(source_kind).to_owned(),
            status: coverage_status(&input.access_state),
            detail: Some(format!(
                "{framed} framed record(s), {unframed} unframed line(s)"
            )),
            observed_at_utc: observed_at,
            evidence: first_evidence.into_iter().collect(),
        });
    }

    resolve_executor_blocks(&mut records);
    resolve_orchestration_blocks(&mut records);
    reconcile_partial_keys(&mut records);
    apply_supplied_facts(&mut records, &facts);

    // Group into runs.
    let mut grouped: BTreeMap<RemediationKey, Vec<usize>> = BTreeMap::new();
    let mut unkeyed_observations: Vec<String> = Vec::new();
    let mut bundle_caution = false;

    for (index, record) in records.iter().enumerate() {
        let has_event = record.classification.event != RemediationEvent::Unclassified;
        let names_its_own_policy = record.classification.policy_id.is_some();
        let belongs = has_event || names_its_own_policy;

        if record.classification.payload_malformed
            || (record.classification.lifecycle_shaped_but_unmatched
                && record.resolved_policy_id.is_none())
        {
            bundle_caution = true;
        }

        match &record.resolved_policy_id {
            Some(policy_id) if belongs => {
                grouped
                    .entry(RemediationKey {
                        policy_id: policy_id.clone(),
                        run_id: record.resolved_run_id.clone(),
                        invocation: record.resolved_invocation,
                    })
                    .or_default()
                    .push(index);
            }
            _ if has_event => unkeyed_observations.push(record.observation_id()),
            _ => {}
        }
    }

    let mut runs: Vec<RemediationRun> = Vec::new();
    for (key, indices) in grouped {
        let has_output_artifact = key.run_id.as_ref().is_some_and(|run| {
            output_artifact_keys.contains(&(key.policy_id.clone(), run.clone()))
        });
        let fact_values = facts
            .iter()
            .filter(|fact| {
                fact.policy_id == key.policy_id
                    && (fact.run_id.is_none() || fact.run_id == key.run_id)
            })
            .flat_map(|fact| fact.retained.iter().cloned())
            .collect::<Vec<_>>();
        runs.push(reduce_run(
            key,
            &indices,
            &records,
            RunContext {
                has_output_artifact,
                unreadable_expected_source,
                bundle_caution,
                retained_facts: fact_values,
            },
        ));
    }

    let observations = records
        .iter()
        .filter(|record| record.classification.in_scope)
        .map(|record| to_observation(record, inputs))
        .collect();

    let mut snapshot = RemediationSnapshot {
        schema_version: REMEDIATION_SCHEMA_VERSION,
        artifacts,
        runs,
        observations,
        unkeyed_observations,
        coverage,
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

/// Parse a caller-supplied policy metadata document.
///
/// A supplied fact may name a run's cadence or mark it on demand. It can never
/// create a run: without log evidence there is nothing to describe.
fn parse_policy_metadata(content: &str) -> Option<SuppliedFact> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(content) else {
        return None;
    };

    let mut policy_id = None;
    let mut run_id = None;
    let mut invocation = RemediationInvocation::Unknown;
    let mut retained = Vec::new();

    for (name, value) in &map {
        match name.to_ascii_lowercase().as_str() {
            "policyid" => {
                if let Value::String(text) = value {
                    policy_id = Some(text.to_ascii_lowercase());
                }
            }
            "runid" => {
                if let Value::String(text) = value {
                    run_id = Some(text.to_ascii_lowercase());
                }
            }
            "invocation" | "triggertype" => {
                if let Value::String(text) = value {
                    invocation = match text.to_ascii_lowercase().replace(['-', '_', ' '], "").as_str()
                    {
                        "scheduled" | "recurring" => RemediationInvocation::Scheduled,
                        "ondemand" | "manual" => RemediationInvocation::OnDemand,
                        _ => RemediationInvocation::Unknown,
                    };
                }
            }
            _ => retained.push(IntuneNamedValue {
                name: name.clone(),
                value: match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                },
            }),
        }
    }

    retained.sort_by(|left, right| left.name.cmp(&right.name));

    Some(SuppliedFact {
        policy_id: policy_id?,
        run_id,
        invocation,
        retained,
    })
}

/// Resolve keys and stages inside each executor artifact.
///
/// Records are grouped per artifact and per CCM thread. Within a thread a new
/// block begins at each launch; every record in a block shares the block's key
/// and stage, which come from whichever record in that block named them. A
/// block that never names a policy stays unkeyed, so its exit code or timeout
/// cannot terminate somebody else's run. A block naming two policies or two
/// stages is refused outright rather than merged.
fn resolve_executor_blocks(records: &mut [PendingRecord]) {
    let mut by_thread: BTreeMap<(usize, Option<u32>), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if record.source_kind != RemediationSourceKind::AgentExecutor {
            continue;
        }
        by_thread
            .entry((record.artifact_index, record.thread))
            .or_default()
            .push(index);
    }

    for indices in by_thread.into_values() {
        let mut block: Vec<usize> = Vec::new();
        for &index in &indices {
            let starts_new_block =
                records[index].classification.event == RemediationEvent::Launched && !block.is_empty();
            if starts_new_block {
                apply_block_key(records, &block);
                block.clear();
            }
            block.push(index);
        }
        apply_block_key(records, &block);
    }
}

fn apply_block_key(records: &mut [PendingRecord], block: &[usize]) {
    if block.is_empty() {
        return;
    }

    let mut policy_id: Option<String> = None;
    let mut run_id: Option<String> = None;
    let mut stage: Option<RemediationStage> = None;
    let mut conflicting = false;

    for &index in block {
        let classification = &records[index].classification;
        if let Some(candidate) = &classification.policy_id {
            match &policy_id {
                Some(existing) if existing != candidate => conflicting = true,
                Some(_) => {}
                None => policy_id = Some(candidate.clone()),
            }
        }
        if let Some(candidate) = &classification.run_id {
            if run_id.is_none() {
                run_id = Some(candidate.clone());
            }
        }
        if let Some(candidate) = classification.stage {
            match stage {
                Some(existing) if existing != candidate => conflicting = true,
                Some(_) => {}
                None => stage = Some(candidate),
            }
        }
    }

    // Two policies or two stages inside one block means the block boundary is
    // wrong for this agent version. Refuse to key rather than merge.
    if conflicting {
        return;
    }
    let Some(policy_id) = policy_id else {
        return;
    };

    for &index in block {
        records[index].resolved_policy_id = Some(policy_id.clone());
        records[index].resolved_run_id = run_id.clone();
        records[index].resolved_stage = stage;
    }
}

/// Carry the orchestration log's current policy forward within one thread.
///
/// `HealthScripts.log` names the policy when it picks it up and then writes the
/// whole stage sequence for it without repeating the identifier. Those records
/// are not unrelated: they are the continuation of the block the naming record
/// opened, on the same thread of the same artifact. The carried key is replaced
/// as soon as a record names a different policy, and it never crosses a thread
/// or an artifact, so two policies processed in the same minute on different
/// threads cannot contaminate each other.
///
/// A record whose payload was malformed is deliberately excluded: it must
/// contribute nothing at all, and a carried key would make it look like part of
/// a run whose identity it never actually stated.
fn resolve_orchestration_blocks(records: &mut [PendingRecord]) {
    let mut by_thread: BTreeMap<(usize, Option<u32>), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if !matches!(
            record.source_kind,
            RemediationSourceKind::HealthScripts | RemediationSourceKind::IntuneManagementExtension
        ) {
            continue;
        }
        if !record.classification.in_scope || record.classification.payload_malformed {
            continue;
        }
        by_thread
            .entry((record.artifact_index, record.thread))
            .or_default()
            .push(index);
    }

    for indices in by_thread.into_values() {
        let mut current: Option<(String, Option<String>, RemediationInvocation)> = None;

        for &index in &indices {
            let (policy, run, invocation) = {
                let classification = &records[index].classification;
                (
                    classification.policy_id.clone(),
                    classification.run_id.clone(),
                    classification.invocation,
                )
            };

            if let Some(policy) = policy {
                current = Some(match current.take() {
                    // The same policy continuing: keep whatever half of the key
                    // this record did not restate.
                    Some((existing, existing_run, existing_invocation))
                        if existing == policy =>
                    {
                        (
                            policy,
                            run.or(existing_run),
                            if invocation == RemediationInvocation::Unknown {
                                existing_invocation
                            } else {
                                invocation
                            },
                        )
                    }
                    _ => (policy, run, invocation),
                });
            }

            let Some((policy, run, invocation)) = &current else {
                continue;
            };
            records[index].resolved_policy_id = Some(policy.clone());
            if records[index].resolved_run_id.is_none() {
                records[index].resolved_run_id = run.clone();
            }
            if records[index].resolved_invocation == RemediationInvocation::Unknown {
                records[index].resolved_invocation = *invocation;
            }
        }
    }
}

/// Complete partial keys using *identity*, never time.
///
/// The orchestration log names a policy but not always the run; the executor
/// log names both. A record that knows only the policy may adopt a run id when
/// that policy has exactly one run in the supplied evidence -- there is then no
/// other execution it could belong to. With two or more runs the record keeps
/// its partial key, so an ambiguous record is reported as ambiguous rather than
/// attached to a guess. The same reasoning widens an unknown invocation.
fn reconcile_partial_keys(records: &mut [PendingRecord]) {
    let mut runs_by_policy: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in records.iter() {
        if let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id) {
            runs_by_policy
                .entry(policy.clone())
                .or_default()
                .insert(run.clone());
        }
    }

    for record in records.iter_mut() {
        if record.resolved_run_id.is_some() {
            continue;
        }
        let Some(policy) = record.resolved_policy_id.clone() else {
            continue;
        };
        if let Some(runs) = runs_by_policy.get(&policy) {
            if runs.len() == 1 {
                record.resolved_run_id = runs.iter().next().cloned();
            }
        }
    }

    let mut invocations: BTreeMap<(String, Option<String>), BTreeSet<RemediationInvocation>> =
        BTreeMap::new();
    for record in records.iter() {
        if record.resolved_invocation == RemediationInvocation::Unknown {
            continue;
        }
        if let Some(policy) = &record.resolved_policy_id {
            invocations
                .entry((policy.clone(), record.resolved_run_id.clone()))
                .or_default()
                .insert(record.resolved_invocation);
        }
    }

    for record in records.iter_mut() {
        if record.resolved_invocation != RemediationInvocation::Unknown {
            continue;
        }
        let Some(policy) = &record.resolved_policy_id else {
            continue;
        };
        if let Some(observed) = invocations.get(&(policy.clone(), record.resolved_run_id.clone())) {
            if observed.len() == 1 {
                record.resolved_invocation =
                    *observed.iter().next().expect("checked len");
            }
        }
    }
}

/// Apply caller-supplied facts to records that still lack an invocation.
///
/// A fact never overrides what a log actually said, and never creates a record.
fn apply_supplied_facts(records: &mut [PendingRecord], facts: &[SuppliedFact]) {
    for fact in facts {
        if fact.invocation == RemediationInvocation::Unknown {
            continue;
        }
        for record in records.iter_mut() {
            if record.resolved_invocation != RemediationInvocation::Unknown {
                continue;
            }
            if record.resolved_policy_id.as_deref() != Some(fact.policy_id.as_str()) {
                continue;
            }
            if fact.run_id.is_some() && fact.run_id != record.resolved_run_id {
                continue;
            }
            record.resolved_invocation = fact.invocation;
        }
    }
}

fn to_observation(
    record: &PendingRecord,
    inputs: &[RemediationSourceInput],
) -> RemediationObservation {
    let input = inputs.get(record.artifact_index);
    let parse_state = if record.classification.payload_malformed {
        IntuneParseState::Malformed
    } else if record.classification.event == RemediationEvent::Unclassified {
        IntuneParseState::Raw
    } else {
        IntuneParseState::Parsed
    };

    RemediationObservation {
        observation_id: record.observation_id(),
        context: IntuneObservationContext {
            evidence_ref: record.evidence(),
            provenance: IntuneProvenance {
                source_kind: source_kind_for(record.source_kind),
                source_artifact_id: record.artifact_id.clone(),
                file_path: input.and_then(|input| input.file_path.clone()),
                line_number: record.line_number.map(u64::from),
                record_number: Some(u64::from(record.record_number)),
                registry: None,
                event: None,
            },
            source_timestamp: record.timestamp.clone(),
            observed_at_utc: input
                .and_then(|input| input.captured_at_utc.clone())
                .unwrap_or_else(|| UNKNOWN_OBSERVED_AT.to_owned()),
            // Remediation records quote script output, command lines, and user
            // identities; the whole record text is treated as sensitive.
            sensitivity: IntuneSensitivity::Sensitive,
            parse_state,
            access_state: input
                .map(|input| input.access_state.clone())
                .unwrap_or(IntuneAccessState::Available),
        },
        source_kind: record.source_kind,
        event: record.classification.event,
        stage: record.resolved_stage,
        policy_id: record.resolved_policy_id.clone(),
        run_id: record.resolved_run_id.clone(),
        invocation: record.resolved_invocation,
        attempt: record.classification.attempt,
        exit_code: record.classification.exit_code.clone(),
        message: record.message.clone(),
        retained_fields: record.classification.retained_fields.clone(),
    }
}

struct RunContext {
    has_output_artifact: bool,
    unreadable_expected_source: bool,
    bundle_caution: bool,
    retained_facts: Vec<IntuneNamedValue>,
}

/// Attempts counted separately per source, then reconciled by taking the
/// larger of the two.
///
/// One launch is written twice: the orchestration log says it is starting the
/// script and the executor log says it is starting the process. Summing them
/// would report every healthy single run as a retry. Taking the maximum keeps a
/// genuine retry visible -- both logs record both attempts -- while a single
/// attempt stays one attempt however many logs described it.
#[derive(Default)]
struct AttemptCounts {
    orchestration: u32,
    executor: u32,
}

impl AttemptCounts {
    fn record(&mut self, source_kind: RemediationSourceKind) {
        match source_kind {
            RemediationSourceKind::AgentExecutor => self.executor += 1,
            _ => self.orchestration += 1,
        }
    }

    fn resolved(&self) -> u32 {
        self.orchestration.max(self.executor)
    }
}

/// Per-stage accumulators, filled in evidence order.
///
/// The last record for a stage is the outcome of that stage's most recent
/// attempt, which is what makes a retry sequence report its final attempt
/// instead of its first.
#[derive(Default)]
struct StageTally {
    detection: Option<DetectionOutcome>,
    detection_code: Option<IntuneErrorCode>,
    detection_launches: AttemptCounts,
    detection_completions: AttemptCounts,
    detection_evidence: Vec<IntuneEvidenceRef>,

    remediation: Option<RemediationOutcome>,
    remediation_code: Option<IntuneErrorCode>,
    remediation_launches: AttemptCounts,
    remediation_completions: AttemptCounts,
    remediation_evidence: Vec<IntuneEvidenceRef>,

    post: Option<PostRemediationState>,
    post_code: Option<IntuneErrorCode>,
    post_evidence: Vec<IntuneEvidenceRef>,

    reporting: Option<ReportingState>,
    reporting_code: Option<IntuneErrorCode>,
    reporting_evidence: Vec<IntuneEvidenceRef>,

    /// A completion record whose exit code could not be read. The stage stays at
    /// the furthest point actually proven and confidence drops.
    unresolved_completion: bool,
    /// The record's exit code and its own compliance statement disagreed.
    conflicting_evidence: bool,
    /// A record shaped like remediation execution that matched no rule.
    unknown_shape: bool,
}

fn detection_outcome_for(
    code: Option<&IntuneErrorCode>,
    stated: Option<bool>,
    tally: &mut StageTally,
) -> Option<DetectionOutcome> {
    match code.and_then(|code| code.decimal) {
        Some(0) => {
            if stated == Some(false) {
                tally.conflicting_evidence = true;
            }
            Some(DetectionOutcome::Compliant)
        }
        Some(1) => {
            if stated == Some(true) {
                tally.conflicting_evidence = true;
            }
            Some(DetectionOutcome::NonCompliant)
        }
        // Detection reserves exactly two codes for compliance. Anything else is
        // the script failing, not a third compliance answer.
        Some(_) => Some(DetectionOutcome::Failed),
        None => match stated {
            Some(true) => Some(DetectionOutcome::Compliant),
            Some(false) => Some(DetectionOutcome::NonCompliant),
            None => {
                tally.unresolved_completion = true;
                None
            }
        },
    }
}

fn post_state_for(
    code: Option<&IntuneErrorCode>,
    stated: Option<bool>,
    tally: &mut StageTally,
) -> Option<PostRemediationState> {
    match code.and_then(|code| code.decimal) {
        Some(0) => Some(PostRemediationState::Compliant),
        Some(1) => Some(PostRemediationState::NonCompliant),
        Some(_) => Some(PostRemediationState::Failed),
        None => match stated {
            Some(true) => Some(PostRemediationState::Compliant),
            Some(false) => Some(PostRemediationState::NonCompliant),
            None => {
                tally.unresolved_completion = true;
                None
            }
        },
    }
}

fn phase_for(event: RemediationEvent, stage: Option<RemediationStage>) -> Option<RemediationPhase> {
    let terminal = matches!(
        event,
        RemediationEvent::Completed | RemediationEvent::TimedOut | RemediationEvent::LaunchFailed
    );
    match (event, stage) {
        (RemediationEvent::PolicyReceived, _) => Some(RemediationPhase::PolicyReceived),
        (RemediationEvent::Scheduled, _) | (RemediationEvent::OnDemandRequested, _) => {
            Some(RemediationPhase::Scheduled)
        }
        (RemediationEvent::RemediationNotRequired, _) => Some(RemediationPhase::DetectionCompleted),
        (RemediationEvent::Launched, Some(RemediationStage::Detection)) => {
            Some(RemediationPhase::DetectionLaunched)
        }
        (RemediationEvent::Launched, Some(RemediationStage::Remediation)) => {
            Some(RemediationPhase::RemediationLaunched)
        }
        (_, Some(RemediationStage::Detection)) if terminal => {
            Some(RemediationPhase::DetectionCompleted)
        }
        (_, Some(RemediationStage::Remediation)) if terminal => {
            Some(RemediationPhase::RemediationCompleted)
        }
        (_, Some(RemediationStage::PostRemediationDetection)) if terminal => {
            Some(RemediationPhase::PostRemediationCompleted)
        }
        (RemediationEvent::ReportSubmitted, _)
        | (RemediationEvent::ReportFailed, _)
        | (RemediationEvent::ReportRetryDeferred, _) => Some(RemediationPhase::Reported),
        _ => None,
    }
}

fn reduce_run(
    key: RemediationKey,
    indices: &[usize],
    records: &[PendingRecord],
    context: RunContext,
) -> RemediationRun {
    let ordered = order_records(indices, records);
    let ordered = promote_post_remediation(&ordered, records);

    let mut tally = StageTally::default();
    let mut last_confirmed_phase: Option<RemediationPhase> = None;

    for &index in &ordered.order {
        let record = &records[index];
        let classification = &record.classification;
        let stage = ordered
            .stage_overrides
            .get(&index)
            .copied()
            .unwrap_or(record.resolved_stage);

        if classification.lifecycle_shaped_but_unmatched {
            tally.unknown_shape = true;
        }

        if let Some(phase) = phase_for(classification.event, stage) {
            last_confirmed_phase = Some(match last_confirmed_phase {
                Some(existing) if existing > phase => existing,
                _ => phase,
            });
        }

        apply_record(&mut tally, record, stage);
    }

    // A launch we never saw start, but whose result we did, still counts.
    let detection_attempts = match tally.detection_launches.resolved() {
        0 => tally.detection_completions.resolved(),
        launches => launches,
    };
    let remediation_attempts = match tally.remediation_launches.resolved() {
        0 => tally.remediation_completions.resolved(),
        launches => launches,
    };

    let missing_evidence_default = |resolved: bool| {
        if resolved {
            DetectionOutcome::NotStarted
        } else {
            DetectionOutcome::InsufficientEvidence
        }
    };

    let detection = DetectionResult {
        outcome: tally
            .detection
            .unwrap_or_else(|| missing_evidence_default(!context.unreadable_expected_source)),
        exit_code: tally.detection_code.clone(),
        attempts: detection_attempts,
        evidence: tally.detection_evidence.clone(),
    };

    let remediation_outcome = tally.remediation.unwrap_or({
        if context.unreadable_expected_source {
            RemediationOutcome::InsufficientEvidence
        } else {
            RemediationOutcome::NotStarted
        }
    });

    let remediation = RemediationActionResult {
        outcome: remediation_outcome,
        exit_code: tally.remediation_code.clone(),
        attempts: remediation_attempts,
        evidence: tally.remediation_evidence.clone(),
    };

    let post_remediation = PostRemediationResult {
        state: tally.post.unwrap_or(PostRemediationState::NotEvaluated),
        exit_code: tally.post_code.clone(),
        evidence: tally.post_evidence.clone(),
    };

    let reporting = ReportingResult {
        state: tally.reporting.unwrap_or({
            if context.unreadable_expected_source {
                ReportingState::InsufficientEvidence
            } else {
                ReportingState::NotStarted
            }
        }),
        error_code: tally.reporting_code.clone(),
        evidence: tally.reporting_evidence.clone(),
    };

    let mut run = RemediationRun {
        key,
        detection,
        remediation,
        post_remediation,
        reporting,
        last_confirmed_phase,
        confidence: IntuneFindingConfidence::High,
        observations: ordered
            .order
            .iter()
            .map(|&index| records[index].observation_id())
            .collect(),
        evidence: ordered
            .order
            .iter()
            .map(|&index| records[index].evidence())
            .collect(),
        next_evidence_request: None,
        retained_facts: context.retained_facts.clone(),
    };

    run.next_evidence_request = next_evidence_request(&run, &context);
    run.confidence = confidence_for(&run, &tally, &context);
    run
}

fn apply_record(tally: &mut StageTally, record: &PendingRecord, stage: Option<RemediationStage>) {
    let classification = &record.classification;
    let evidence = record.evidence();

    match classification.event {
        RemediationEvent::ReportSubmitted => {
            tally.reporting = Some(ReportingState::Submitted);
            tally.reporting_evidence.push(evidence);
            return;
        }
        RemediationEvent::ReportFailed => {
            tally.reporting = Some(ReportingState::Failed);
            tally.reporting_code = classification.exit_code.clone();
            tally.reporting_evidence.push(evidence);
            return;
        }
        RemediationEvent::ReportRetryDeferred => {
            tally.reporting = Some(ReportingState::RetryDeferred);
            tally.reporting_evidence.push(evidence);
            return;
        }
        RemediationEvent::RemediationNotRequired => {
            tally.remediation = Some(RemediationOutcome::Skipped);
            tally.remediation_evidence.push(evidence);
            return;
        }
        _ => {}
    }

    // Everything below is stage-specific. Without a stage the record stays an
    // observation: an exit code that could belong to either half of the pair is
    // not evidence for either.
    let Some(stage) = stage else {
        if matches!(
            classification.event,
            RemediationEvent::Completed | RemediationEvent::TimedOut
        ) {
            tally.unresolved_completion = true;
        }
        return;
    };

    match stage {
        RemediationStage::Detection => match classification.event {
            RemediationEvent::Launched => {
                tally.detection = Some(DetectionOutcome::Launched);
                tally.detection_launches.record(record.source_kind);
                tally.detection_evidence.push(evidence);
            }
            RemediationEvent::Completed => {
                tally.detection_completions.record(record.source_kind);
                if let Some(outcome) = detection_outcome_for(
                    classification.exit_code.as_ref(),
                    classification.stated_compliance,
                    tally,
                ) {
                    tally.detection = Some(outcome);
                    tally.detection_code = classification.exit_code.clone();
                }
                tally.detection_evidence.push(evidence);
            }
            RemediationEvent::LaunchFailed => {
                tally.detection = Some(DetectionOutcome::Failed);
                tally.detection_evidence.push(evidence);
            }
            RemediationEvent::TimedOut => {
                tally.detection = Some(DetectionOutcome::TimedOut);
                tally.detection_evidence.push(evidence);
            }
            RemediationEvent::OutputCaptured => tally.detection_evidence.push(evidence),
            _ => {}
        },
        RemediationStage::Remediation => match classification.event {
            RemediationEvent::Launched => {
                tally.remediation = Some(RemediationOutcome::Launched);
                tally.remediation_launches.record(record.source_kind);
                tally.remediation_evidence.push(evidence);
            }
            RemediationEvent::Completed => {
                tally.remediation_completions.record(record.source_kind);
                match classification.exit_code.as_ref().and_then(|code| code.decimal) {
                    Some(0) => {
                        tally.remediation = Some(RemediationOutcome::Succeeded);
                        tally.remediation_code = classification.exit_code.clone();
                    }
                    Some(_) => {
                        tally.remediation = Some(RemediationOutcome::ExitedNonZero);
                        tally.remediation_code = classification.exit_code.clone();
                    }
                    None => tally.unresolved_completion = true,
                }
                tally.remediation_evidence.push(evidence);
            }
            RemediationEvent::LaunchFailed => {
                tally.remediation = Some(RemediationOutcome::FailedToLaunch);
                tally.remediation_evidence.push(evidence);
            }
            RemediationEvent::TimedOut => {
                tally.remediation = Some(RemediationOutcome::TimedOut);
                tally.remediation_evidence.push(evidence);
            }
            RemediationEvent::OutputCaptured => tally.remediation_evidence.push(evidence),
            _ => {}
        },
        RemediationStage::PostRemediationDetection => match classification.event {
            RemediationEvent::Completed => {
                if let Some(state) = post_state_for(
                    classification.exit_code.as_ref(),
                    classification.stated_compliance,
                    tally,
                ) {
                    tally.post = Some(state);
                    tally.post_code = classification.exit_code.clone();
                }
                tally.post_evidence.push(evidence);
            }
            RemediationEvent::LaunchFailed | RemediationEvent::TimedOut => {
                tally.post = Some(PostRemediationState::Failed);
                tally.post_evidence.push(evidence);
            }
            RemediationEvent::Launched | RemediationEvent::OutputCaptured => {
                tally.post_evidence.push(evidence)
            }
            _ => {}
        },
    }
}

struct OrderedRun {
    order: Vec<usize>,
    stage_overrides: BTreeMap<usize, Option<RemediationStage>>,
}

/// Order a run's records.
///
/// When every record states its own UTC offset, real time is the better order
/// and is used. Otherwise source order is used, because the alternative -- a UTC
/// value derived from the reading machine's timezone -- is not evidence. Source
/// order means artifact order as the caller supplied it, so a caller passing
/// rotations oldest first gets the sequence it expects.
fn order_records(indices: &[usize], records: &[PendingRecord]) -> Vec<usize> {
    let mut ordered = indices.to_vec();
    let all_trustworthy = ordered.iter().all(|&index| {
        records[index]
            .timestamp
            .as_ref()
            .is_some_and(|timestamp| timestamp.normalized_utc.is_some())
    });

    if all_trustworthy {
        ordered.sort_by(|&left, &right| {
            let key = |index: usize| {
                (
                    records[index]
                        .timestamp
                        .as_ref()
                        .and_then(|timestamp| timestamp.normalized_utc.clone())
                        .unwrap_or_default(),
                    records[index].artifact_index,
                    records[index].record_number,
                )
            };
            key(left).cmp(&key(right))
        });
    } else {
        ordered.sort_by_key(|&index| (records[index].artifact_index, records[index].record_number));
    }
    ordered
}

/// Re-read executor detection blocks that ran *after* this run's remediation
/// completed as the post-remediation detection.
///
/// The executor log launches the same `detect.ps1` for both detections, so its
/// records cannot distinguish them on their own. Within one already-keyed run
/// the lifecycle order is fixed -- detect, remediate, detect again -- so a
/// detection that follows a completed remediation *of the same run* is the
/// post-remediation check. This is not a join across records: both blocks
/// already carry the same explicit policy and run id from their script paths.
/// Orchestration records that named their own stage are never re-read.
fn promote_post_remediation(order: &[usize], records: &[PendingRecord]) -> OrderedRun {
    let remediation_completed_at = order.iter().position(|&index| {
        records[index].resolved_stage == Some(RemediationStage::Remediation)
            && matches!(
                records[index].classification.event,
                RemediationEvent::Completed
                    | RemediationEvent::TimedOut
                    | RemediationEvent::LaunchFailed
            )
    });

    let mut stage_overrides = BTreeMap::new();
    if let Some(boundary) = remediation_completed_at {
        for (position, &index) in order.iter().enumerate() {
            if position <= boundary {
                continue;
            }
            let record = &records[index];
            if record.source_kind != RemediationSourceKind::AgentExecutor {
                continue;
            }
            if record.resolved_stage != Some(RemediationStage::Detection) {
                continue;
            }
            stage_overrides.insert(index, Some(RemediationStage::PostRemediationDetection));
        }
    }

    OrderedRun {
        order: order.to_vec(),
        stage_overrides,
    }
}

fn next_evidence_request(run: &RemediationRun, context: &RunContext) -> Option<String> {
    match run.detection.outcome {
        DetectionOutcome::InsufficientEvidence => {
            return Some(
                "HealthScripts.log covering this policy and run identifier".to_owned(),
            )
        }
        DetectionOutcome::NotStarted => {
            return Some(
                "HealthScripts.log records for the detection stage of this policy".to_owned(),
            )
        }
        DetectionOutcome::Launched => {
            return Some(
                "the AgentExecutor.log record stating the detection script exit code for this run"
                    .to_owned(),
            )
        }
        DetectionOutcome::NonCompliant
            if matches!(
                run.remediation.outcome,
                RemediationOutcome::NotStarted | RemediationOutcome::InsufficientEvidence
            ) =>
        {
            return Some(
                "HealthScripts.log records for the remediation stage of this run".to_owned(),
            )
        }
        _ => {}
    }

    if run.remediation.outcome == RemediationOutcome::Launched {
        return Some(
            "the AgentExecutor.log record stating the remediation script exit code for this run"
                .to_owned(),
        );
    }

    // A process that never started cannot have written output, so asking for a
    // retained output artifact would send an operator after a file that does not
    // exist. A launch failure is identified by having no exit code at all.
    if run.detection.outcome == DetectionOutcome::Failed && run.detection.exit_code.is_none() {
        return Some(
            "AgentExecutor.log context around the failed detection launch".to_owned(),
        );
    }
    if run.remediation.outcome == RemediationOutcome::FailedToLaunch {
        return Some(
            "AgentExecutor.log context around the failed remediation launch".to_owned(),
        );
    }

    if matches!(
        run.remediation.outcome,
        RemediationOutcome::ExitedNonZero | RemediationOutcome::TimedOut
    ) && !context.has_output_artifact
    {
        return Some("the retained remediation output artifact for this policy and run".to_owned());
    }

    if matches!(
        run.detection.outcome,
        DetectionOutcome::Failed | DetectionOutcome::TimedOut
    ) && !context.has_output_artifact
    {
        return Some("the retained detection output artifact for this policy and run".to_owned());
    }

    // Checked before the post-remediation request: when the orchestration log
    // itself was never read, asking for one record out of it would be asking for
    // the smaller half of a file the operator has to collect anyway.
    if run.reporting.state == ReportingState::InsufficientEvidence {
        return Some("HealthScripts.log covering this policy and run identifier".to_owned());
    }

    if run.remediation.outcome == RemediationOutcome::Succeeded
        && run.post_remediation.state == PostRemediationState::NotEvaluated
    {
        return Some("the post-remediation detection record for this run".to_owned());
    }

    if run.is_locally_resolved() && run.reporting.state == ReportingState::NotStarted {
        return Some(
            "HealthScripts.log or IntuneManagementExtension.log records reporting this run to the service"
                .to_owned(),
        );
    }

    None
}

/// Confidence describes how well evidenced the *reduced run* is.
///
/// It is not a verdict on the bundle's completeness -- a missing source is
/// reported through coverage and the next-evidence request as well -- but an
/// unread expected source, an unattributable execution record, and a payload we
/// could not parse all mean the reduction could still be wrong, so each one
/// lowers it.
fn confidence_for(
    run: &RemediationRun,
    tally: &StageTally,
    context: &RunContext,
) -> IntuneFindingConfidence {
    if tally.unknown_shape
        || tally.unresolved_completion
        || tally.conflicting_evidence
        || !run.is_locally_resolved()
    {
        return IntuneFindingConfidence::Low;
    }

    let mut confidence = IntuneFindingConfidence::High;
    if run.key.run_id.is_none() {
        confidence = lower_confidence(confidence, IntuneFindingConfidence::Medium);
    }
    if context.unreadable_expected_source || context.bundle_caution {
        confidence = lower_confidence(confidence, IntuneFindingConfidence::Medium);
    }
    confidence
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "11111111-2222-3333-4444-555555555555";
    const RUN: &str = "66666666-7777-8888-9999-000000000000";

    fn record(message: &str, time: &str, component: &str, thread: u32) -> String {
        format!(
            "<![LOG[{message}]LOG]!><time=\"{time}+000\" date=\"03-12-2026\" \
             component=\"{component}\" context=\"\" type=\"1\" thread=\"{thread}\" file=\"\">\n"
        )
    }

    fn health(messages: &[(&str, &str)]) -> String {
        messages
            .iter()
            .map(|(message, time)| record(message, time, "HealthScripts", 7))
            .collect()
    }

    fn analyze(content: &str) -> RemediationSnapshot {
        analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "hs",
            "HealthScripts.log",
            content,
        )])
    }

    #[test]
    fn a_compliant_detection_skips_remediation_and_reports() {
        let snapshot = analyze(&health(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}, Invocation = Scheduled"),
                "10:00:00.000",
            ),
            (
                &format!("Start to execute the detection script for policy {POLICY}"),
                "10:00:01.000",
            ),
            (
                "Detection script completed, exit code = 0, compliance result = Compliant",
                "10:00:05.000",
            ),
            (
                "Detection reported compliant, remediation is not required",
                "10:00:05.100",
            ),
            (
                "Health script result has been sent to service successfully",
                "10:00:06.000",
            ),
        ]));

        assert_eq!(snapshot.runs.len(), 1);
        let run = &snapshot.runs[0];
        assert_eq!(run.key.policy_id, POLICY);
        assert_eq!(run.key.run_id.as_deref(), Some(RUN));
        assert_eq!(run.key.invocation, RemediationInvocation::Scheduled);
        assert_eq!(run.detection.outcome, DetectionOutcome::Compliant);
        assert_eq!(run.remediation.outcome, RemediationOutcome::Skipped);
        assert_eq!(run.reporting.state, ReportingState::Submitted);
        assert_eq!(run.next_evidence_request, None);
        assert_eq!(run.confidence, IntuneFindingConfidence::High);
    }

    #[test]
    fn detection_and_remediation_exit_codes_are_read_stage_specifically() {
        let snapshot = analyze(&health(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:05.000",
            ),
            ("Start to execute the remediation script", "10:00:06.000"),
            ("Remediation script completed, exit code = 1", "10:00:09.000"),
        ]));

        let run = &snapshot.runs[0];
        // The same code: "remediation required" for detection, "the script
        // failed" for remediation.
        assert_eq!(run.detection.outcome, DetectionOutcome::NonCompliant);
        assert_eq!(run.remediation.outcome, RemediationOutcome::ExitedNonZero);
    }

    #[test]
    fn an_unstaged_exit_code_terminates_nothing() {
        let content = format!(
            "{}{}",
            health(&[(
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000"
            )]),
            record(
                "Powershell execution is done, exitCode = 1",
                "10:00:05.000",
                "HealthScripts",
                7
            )
        );
        let snapshot = analyze(&content);
        let run = &snapshot.runs[0];
        assert_eq!(run.detection.outcome, DetectionOutcome::NotStarted);
        assert_eq!(run.remediation.outcome, RemediationOutcome::NotStarted);
        assert_eq!(run.confidence, IntuneFindingConfidence::Low);
    }

    #[test]
    fn scheduled_and_on_demand_runs_of_one_policy_stay_separate() {
        let snapshot = analyze(&health(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}, Invocation = Scheduled"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 0, compliance result = Compliant",
                "10:00:02.000",
            ),
            (
                &format!("On demand health script run requested for policy {POLICY}, RunId = aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1"),
                "10:05:00.000",
            ),
            (
                &format!("Detection script completed for policy {POLICY}, RunId = aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1, exit code = 1, compliance result = NonCompliant"),
                "10:05:02.000",
            ),
        ]));

        assert_eq!(snapshot.runs.len(), 2, "runs: {:?}", snapshot.runs);
        let scheduled = snapshot
            .runs
            .iter()
            .find(|run| run.key.invocation == RemediationInvocation::Scheduled)
            .expect("scheduled run");
        let on_demand = snapshot
            .runs
            .iter()
            .find(|run| run.key.invocation == RemediationInvocation::OnDemand)
            .expect("on demand run");
        assert_eq!(scheduled.detection.outcome, DetectionOutcome::Compliant);
        assert_eq!(on_demand.detection.outcome, DetectionOutcome::NonCompliant);
    }

    #[test]
    fn an_executor_block_carries_its_script_path_stage_to_the_exit_record() {
        let executor = format!(
            "{}{}{}",
            record("Starting Powershell Execution", "10:00:01.000", "AgentExecutor", 12),
            record(
                &format!(
                    r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"
                ),
                "10:00:01.100",
                "AgentExecutor",
                12
            ),
            record(
                "Powershell execution is done, exitCode = 1",
                "10:00:04.000",
                "AgentExecutor",
                12
            ),
        );
        let snapshot = analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "ae",
            "AgentExecutor.log",
            executor,
        )]);

        assert_eq!(snapshot.runs.len(), 1);
        assert_eq!(
            snapshot.runs[0].detection.outcome,
            DetectionOutcome::NonCompliant
        );
        assert_eq!(snapshot.runs[0].detection.attempts, 1);
    }

    #[test]
    fn a_second_executor_detection_after_remediation_is_the_post_check() {
        let executor = [
            record("Starting Powershell Execution", "10:00:01.000", "AgentExecutor", 12),
            record(
                &format!(r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"),
                "10:00:01.100",
                "AgentExecutor",
                12,
            ),
            record("Powershell execution is done, exitCode = 1", "10:00:04.000", "AgentExecutor", 12),
            record("Starting Powershell Execution", "10:00:05.000", "AgentExecutor", 12),
            record(
                &format!(r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\remediate.ps1"),
                "10:00:05.100",
                "AgentExecutor",
                12,
            ),
            record("Powershell execution is done, exitCode = 0", "10:00:09.000", "AgentExecutor", 12),
            record("Starting Powershell Execution", "10:00:10.000", "AgentExecutor", 12),
            record(
                &format!(r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"),
                "10:00:10.100",
                "AgentExecutor",
                12,
            ),
            record("Powershell execution is done, exitCode = 0", "10:00:13.000", "AgentExecutor", 12),
        ]
        .concat();

        let snapshot = analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "ae",
            "AgentExecutor.log",
            executor,
        )]);
        let run = &snapshot.runs[0];
        // The detection that decided remediation was needed keeps its answer.
        assert_eq!(run.detection.outcome, DetectionOutcome::NonCompliant);
        assert_eq!(run.remediation.outcome, RemediationOutcome::Succeeded);
        assert_eq!(run.post_remediation.state, PostRemediationState::Compliant);
    }

    #[test]
    fn a_block_that_names_no_policy_stays_unkeyed() {
        let executor = [
            record("Starting Powershell Execution", "10:00:01.000", "AgentExecutor", 12),
            record("Powershell execution is done, exitCode = 1", "10:00:04.000", "AgentExecutor", 12),
        ]
        .concat();
        let snapshot = analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "ae",
            "AgentExecutor.log",
            executor,
        )]);
        assert!(snapshot.runs.is_empty());
        assert_eq!(snapshot.unkeyed_observations.len(), 2);
    }

    #[test]
    fn an_absent_source_is_reported_as_a_coverage_gap_not_as_a_result() {
        let snapshot = analyze_remediation_bundle(&[
            RemediationSourceInput::captured(
                "hs",
                "HealthScripts.log",
                health(&[(
                    &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                    "10:00:00.000",
                )]),
            ),
            RemediationSourceInput::absent("ae", "AgentExecutor.log"),
        ]);

        let run = &snapshot.runs[0];
        assert_eq!(run.detection.outcome, DetectionOutcome::InsufficientEvidence);
        assert!(run.next_evidence_request.is_some());
        let gap = snapshot
            .coverage
            .iter()
            .find(|entry| entry.artifact_id == "ae")
            .expect("coverage entry");
        assert_eq!(
            gap.status,
            crate::intune::evidence::IntuneArtifactStatus::Missing
        );
    }

    #[test]
    fn supplied_facts_annotate_a_run_without_creating_one() {
        let metadata = format!(
            r#"{{"policyId":"{POLICY}","runId":"{RUN}","invocation":"onDemand","displayName":"Synthetic remediation","cadence":"hourly"}}"#
        );
        let snapshot = analyze_remediation_bundle(&[
            RemediationSourceInput::captured(
                "hs",
                "HealthScripts.log",
                health(&[
                    (
                        &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                        "10:00:00.000",
                    ),
                    (
                        "Detection script completed, exit code = 0, compliance result = Compliant",
                        "10:00:02.000",
                    ),
                ]),
            ),
            RemediationSourceInput::captured("meta", "remediation-policy.json", metadata),
        ]);

        assert_eq!(snapshot.runs.len(), 1);
        assert_eq!(snapshot.runs[0].key.invocation, RemediationInvocation::OnDemand);
        assert_eq!(
            snapshot.runs[0]
                .retained_facts
                .iter()
                .map(|fact| fact.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cadence", "displayName"]
        );
    }

    #[test]
    fn metadata_alone_never_produces_a_run() {
        let metadata = format!(r#"{{"policyId":"{POLICY}","invocation":"scheduled"}}"#);
        let snapshot = analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "meta",
            "remediation-policy.json",
            metadata,
        )]);
        assert!(snapshot.runs.is_empty());
    }

    #[test]
    fn reduction_is_deterministic() {
        let content = health(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:02.000",
            ),
        ]);
        let first = serde_json::to_string(&analyze(&content)).expect("serializes");
        let second = serde_json::to_string(&analyze(&content)).expect("serializes");
        assert_eq!(first, second);
    }
}
