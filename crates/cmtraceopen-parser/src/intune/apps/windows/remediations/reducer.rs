//! Reduction of classified remediation records into keyed detection/remediation
//! pairs.
//!
//! Two records join a pair only when they carry the same [`RemediationKey`].
//! Detection and remediation are reduced into separate stage outcomes and are
//! never pooled: a nonzero exit means "remediation required" from detection and
//! "remediation failed" from remediation, so mixing them inverts the diagnosis.

use std::collections::{BTreeMap, BTreeSet};

use crate::intune::ime_parser::parse_ime_content;

use super::models::{
    DetectionState, RemediationAnalysis, RemediationArtifact, RemediationClassifiedString,
    RemediationConfidence, RemediationCoverage, RemediationEvidenceRef, RemediationInvocation,
    RemediationKey, RemediationObservation, RemediationPayload, RemediationReportState,
    RemediationRunState, RemediationSignal, RemediationSourceKind, RemediationStage,
    RemediationTimestamp, RemediationTransaction, StageOutcome,
};
use super::rules::{classify_record, RecordClassification};
use super::sources::{
    candidate_source_kind, classify_artifact, output_artifact_identity, RemediationSourceInput,
};

/// Render a CCM offset in minutes as `+HH:MM` / `-HH:MM`.
fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

/// A classified record plus where it came from, before keying.
struct PendingRecord {
    artifact_index: usize,
    artifact_id: String,
    source_kind: RemediationSourceKind,
    record_number: u32,
    line_number: Option<u32>,
    thread: Option<u32>,
    timestamp: Option<RemediationTimestamp>,
    message: String,
    classification: RecordClassification,
    resolved_policy_id: Option<String>,
    resolved_run_id: Option<String>,
    resolved_invocation: RemediationInvocation,
    /// Stage inherited from the record's own block, when it named none itself.
    resolved_stage: Option<RemediationStage>,
}

impl PendingRecord {
    fn observation_id(&self) -> String {
        format!("{}:{}", self.artifact_id, self.record_number)
    }

    fn evidence(&self) -> RemediationEvidenceRef {
        RemediationEvidenceRef {
            artifact_id: self.artifact_id.clone(),
            record_number: self.record_number,
            line_number: self.line_number,
        }
    }
}

/// Resolve keys and stages inside each `HealthScripts` artifact.
///
/// Records are grouped per artifact and per CCM thread. A new block begins at
/// each stage-launch record, and every record in a block shares that block's
/// policy, run, and **stage**. A block that never names a stage leaves its
/// records unstaged, so their exit codes cannot terminate either half.
///
/// Blocks never span artifacts. Two rotations reuse thread numbers freely, so
/// an execution split across a rotation boundary leaves an unkeyed tail rather
/// than a guessed join.
fn resolve_blocks(records: &mut [PendingRecord]) {
    let mut by_thread: BTreeMap<(usize, Option<u32>), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if record.source_kind != RemediationSourceKind::HealthScripts {
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
            let starts_new_block = records[index].classification.signal
                == RemediationSignal::StageLaunched
                && !block.is_empty();
            if starts_new_block {
                apply_block(records, &block);
                block.clear();
            }
            block.push(index);
        }
        apply_block(records, &block);
    }
}

fn apply_block(records: &mut [PendingRecord], block: &[usize]) {
    if block.is_empty() {
        return;
    }

    let mut policy_id: Option<String> = None;
    let mut run_id: Option<String> = None;
    let mut invocation = RemediationInvocation::Unknown;
    let mut stage: Option<RemediationStage> = None;
    let mut conflicting_policy = false;
    let mut conflicting_stage = false;

    for &index in block {
        let classification = &records[index].classification;
        if let Some(candidate) = &classification.policy_id {
            match &policy_id {
                Some(existing) if existing != candidate => conflicting_policy = true,
                Some(_) => {}
                None => policy_id = Some(candidate.clone()),
            }
        }
        if let Some(candidate) = &classification.run_id {
            if run_id.is_none() {
                run_id = Some(candidate.clone());
            }
        }
        if classification.invocation != RemediationInvocation::Unknown
            && invocation == RemediationInvocation::Unknown
        {
            invocation = classification.invocation;
        }
        if let Some(candidate) = classification.stage {
            match stage {
                Some(existing) if existing != candidate => conflicting_stage = true,
                Some(_) => {}
                None => stage = Some(candidate),
            }
        }
    }

    // Two policies, or two stages, inside one block means our block boundary is
    // wrong for this agent version. Refuse to key rather than merge.
    if conflicting_policy {
        return;
    }

    for &index in block {
        if let Some(policy_id) = &policy_id {
            records[index].resolved_policy_id = Some(policy_id.clone());
            records[index].resolved_run_id = run_id.clone();
            records[index].resolved_invocation = invocation;
        }
        if !conflicting_stage {
            if let Some(stage) = stage {
                records[index].resolved_stage = Some(stage);
            }
        }
    }
}

/// Complete partial keys using identity, never time.
///
/// A record that knows only the policy may adopt a run id when that policy has
/// exactly one run in the supplied evidence. With two or more it keeps its
/// partial key, so an ambiguous record stays ambiguous.
fn reconcile_partial_keys(records: &mut [PendingRecord]) {
    let mut runs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in records.iter() {
        if let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id) {
            runs.entry(policy.clone()).or_default().insert(run.clone());
        }
    }
    for record in records.iter_mut() {
        if record.resolved_run_id.is_some() {
            continue;
        }
        let Some(policy) = record.resolved_policy_id.clone() else {
            continue;
        };
        if let Some(candidates) = runs.get(&policy) {
            if candidates.len() == 1 {
                record.resolved_run_id = candidates.iter().next().cloned();
            }
        }
    }

    // Unify invocation per (policy, run) when exactly one was ever stated.
    let mut invocations: BTreeMap<(String, String), BTreeSet<RemediationInvocation>> =
        BTreeMap::new();
    for record in records.iter() {
        if let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id) {
            if record.resolved_invocation != RemediationInvocation::Unknown {
                invocations
                    .entry((policy.clone(), run.clone()))
                    .or_default()
                    .insert(record.resolved_invocation);
            }
        }
    }
    for record in records.iter_mut() {
        if record.resolved_invocation != RemediationInvocation::Unknown {
            continue;
        }
        let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id)
        else {
            continue;
        };
        if let Some(observed) = invocations.get(&(policy.clone(), run.clone())) {
            if observed.len() == 1 {
                record.resolved_invocation = *observed.iter().next().expect("checked len");
            }
        }
    }
}

fn to_observation(record: &PendingRecord) -> RemediationObservation {
    RemediationObservation {
        observation_id: record.observation_id(),
        evidence: record.evidence(),
        source_kind: record.source_kind,
        timestamp: record.timestamp.clone(),
        signal: record.classification.signal,
        stage: record.resolved_stage,
        policy_id: record.resolved_policy_id.clone(),
        run_id: record.resolved_run_id.clone(),
        invocation: record.resolved_invocation,
        attempt: record.classification.attempt,
        exit_token: record.classification.exit_token.clone(),
        message: RemediationClassifiedString::sensitive(record.message.clone()),
    }
}

/// Reduce a supplied remediation bundle.
///
/// The caller owns all I/O: it reads and decodes each artifact and passes the
/// text in. This function performs no filesystem, registry, or network access.
pub fn analyze_remediation_bundle(inputs: &[RemediationSourceInput]) -> RemediationAnalysis {
    let mut artifacts: Vec<RemediationArtifact> = Vec::new();
    let mut records: Vec<PendingRecord> = Vec::new();
    let mut unclassified_records = 0u32;
    let mut unknown_version_observed = false;
    let mut malformed_payloads = 0u32;
    let mut output_artifact_keys: BTreeSet<(String, String)> = BTreeSet::new();

    for (artifact_index, input) in inputs.iter().enumerate() {
        // A retained output artifact is evidence by its identity alone. Its
        // contents are raw script stdout/stderr -- unbounded and frequently
        // sensitive -- so they are registered by name and never parsed.
        if candidate_source_kind(input) == RemediationSourceKind::ScriptOutput {
            artifacts.push(classify_artifact(input, &[]));
            if let Some(identity) = output_artifact_identity(input) {
                output_artifact_keys.insert(identity);
            }
            continue;
        }

        let lines = parse_ime_content(&input.content);
        let components: Vec<Option<String>> =
            lines.iter().map(|line| line.component.clone()).collect();
        let artifact = classify_artifact(input, &components);
        let source_kind = artifact.source_kind;
        artifacts.push(artifact);

        for (record_index, line) in lines.iter().enumerate() {
            let classification =
                classify_record(source_kind, line.component.as_deref(), &line.message);

            if classification.stage_shaped_but_unmatched {
                unknown_version_observed = true;
            }
            if let Some((_, parsed)) = &classification.payload {
                if !parsed {
                    malformed_payloads += 1;
                }
            }
            // Only in-scope records can be "unclassified remediation records".
            if classification.in_scope
                && classification.signal == RemediationSignal::Unclassified
                && classification.policy_id.is_none()
            {
                unclassified_records += 1;
            }

            let timestamp = line.timestamp.as_ref().map(|raw| RemediationTimestamp {
                raw_text: raw.clone(),
                original_offset: line.timezone_offset.map(format_offset),
                // Only trust the UTC form when the record stated its own
                // offset; otherwise it is derived from the parsing machine.
                normalized_utc: line.timezone_offset.and(line.timestamp_utc.clone()),
            });

            records.push(PendingRecord {
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
                resolved_invocation: classification.invocation,
                resolved_stage: classification.stage,
                classification,
            });
        }
    }

    resolve_blocks(&mut records);
    reconcile_partial_keys(&mut records);

    let mut grouped: BTreeMap<RemediationKey, Vec<usize>> = BTreeMap::new();
    let mut unkeyed_observations: Vec<String> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let has_signal = record.classification.signal != RemediationSignal::Unclassified;
        let names_its_own_policy = record.classification.policy_id.is_some();
        let belongs = has_signal || names_its_own_policy;

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
            _ if belongs => unkeyed_observations.push(record.observation_id()),
            _ => {}
        }
    }

    let saw = |kind: RemediationSourceKind| artifacts.iter().any(|a| a.source_kind == kind);
    let mut missing_expected_sources = Vec::new();
    if !saw(RemediationSourceKind::HealthScripts) {
        missing_expected_sources.push("HealthScripts.log".to_string());
    }
    if !saw(RemediationSourceKind::AgentExecutor) {
        missing_expected_sources.push("AgentExecutor.log".to_string());
    }

    let transactions = grouped
        .into_iter()
        .map(|(key, indices)| {
            let has_output_artifact = key.run_id.as_ref().is_some_and(|run| {
                output_artifact_keys.contains(&(key.policy_id.clone(), run.clone()))
            });
            reduce_transaction(key, &indices, &records, has_output_artifact)
        })
        .collect();

    let observations = records.iter().map(to_observation).collect();

    RemediationAnalysis {
        transactions,
        observations,
        unkeyed_observations,
        coverage: RemediationCoverage {
            artifacts,
            unclassified_records,
            missing_expected_sources,
            unknown_version_observed,
            malformed_payloads,
        },
    }
}

/// Detection exit semantics: 0 is compliant, nonzero means remediation is
/// required. This is the opposite reading from the remediation stage, which is
/// exactly why the stage must be explicit before a code is interpreted.
fn detection_state_for_exit(decimal: Option<i64>) -> DetectionState {
    match decimal {
        Some(0) => DetectionState::Compliant,
        Some(_) => DetectionState::Noncompliant,
        // A completion whose code we could not read proves the stage ran but
        // not what it concluded.
        None => DetectionState::InsufficientEvidence,
    }
}

/// Remediation exit semantics: 0 succeeded, anything else did not.
fn remediation_state_for_exit(decimal: Option<i64>) -> RemediationRunState {
    match decimal {
        Some(0) => RemediationRunState::Succeeded,
        Some(_) => RemediationRunState::ExitedNonZero,
        None => RemediationRunState::InsufficientEvidence,
    }
}

fn next_evidence_request(
    detection: &StageOutcome<DetectionState>,
    remediation: &StageOutcome<RemediationRunState>,
    report: RemediationReportState,
    has_output_evidence: bool,
) -> Option<String> {
    match detection.state {
        DetectionState::NotStarted | DetectionState::InsufficientEvidence => {
            return Some("HealthScripts.log records for this policy's detection stage".to_string())
        }
        DetectionState::Launched => {
            return Some("HealthScripts.log record reporting the detection result".to_string())
        }
        DetectionState::Failed | DetectionState::TimedOut if !has_output_evidence => {
            return Some("retained detection output artifact for this policy and run".to_string())
        }
        DetectionState::Compliant => {
            // Nothing was wrong. The only thing left to confirm is reporting.
            return match report {
                RemediationReportState::NotObserved => Some(
                    "IntuneManagementExtension.log or HealthScripts.log records reporting this result"
                        .to_string(),
                ),
                _ => None,
            };
        }
        _ => {}
    }

    match remediation.state {
        RemediationRunState::NotStarted | RemediationRunState::InsufficientEvidence => Some(
            "HealthScripts.log records for this policy's remediation stage".to_string(),
        ),
        RemediationRunState::Launched => {
            Some("HealthScripts.log record reporting the remediation result".to_string())
        }
        RemediationRunState::FailedToLaunch => Some(
            "AgentExecutor.log context around the failed launch, and the HealthScripts.log record for this policy"
                .to_string(),
        ),
        RemediationRunState::ExitedNonZero | RemediationRunState::TimedOut
            if !has_output_evidence =>
        {
            Some("retained remediation output artifact for this policy and run".to_string())
        }
        _ => match report {
            RemediationReportState::NotObserved => Some(
                "IntuneManagementExtension.log or HealthScripts.log records reporting this result"
                    .to_string(),
            ),
            _ => None,
        },
    }
}

fn confidence_for(
    detection: &StageOutcome<DetectionState>,
    remediation: &StageOutcome<RemediationRunState>,
    unknown_version: bool,
    saw_orchestrator: bool,
) -> RemediationConfidence {
    if unknown_version || !saw_orchestrator {
        return RemediationConfidence::Low;
    }

    let detection_terminal = matches!(
        detection.state,
        DetectionState::Compliant
            | DetectionState::Noncompliant
            | DetectionState::Failed
            | DetectionState::TimedOut
    );
    if !detection_terminal {
        return RemediationConfidence::Low;
    }

    // These detection outcomes are complete stories on their own: compliant
    // means nothing needed fixing, and failed/timed-out means the run ended
    // there. In all three, remediation is legitimately absent rather than
    // unevidenced, so the pair is fully evidenced.
    if matches!(
        detection.state,
        DetectionState::Compliant | DetectionState::Failed | DetectionState::TimedOut
    ) {
        return RemediationConfidence::High;
    }

    match remediation.state {
        RemediationRunState::Succeeded
        | RemediationRunState::ExitedNonZero
        | RemediationRunState::FailedToLaunch
        | RemediationRunState::TimedOut => RemediationConfidence::High,
        _ => RemediationConfidence::Medium,
    }
}

fn reduce_transaction(
    key: RemediationKey,
    indices: &[usize],
    records: &[PendingRecord],
    has_output_artifact: bool,
) -> RemediationTransaction {
    let mut ordered: Vec<usize> = indices.to_vec();
    // Real time when every record in the pair states its own offset; source
    // order otherwise, since a machine-derived UTC value is not evidence.
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
                        .and_then(|t| t.normalized_utc.clone())
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

    let mut detection = StageOutcome::new(DetectionState::NotStarted);
    let mut remediation = StageOutcome::new(RemediationRunState::NotStarted);
    let mut post_detection: Option<StageOutcome<DetectionState>> = None;
    let mut report = RemediationReportState::NotObserved;
    let mut attempts = 0u32;
    let mut payloads: Vec<RemediationPayload> = Vec::new();
    let mut has_output_evidence = has_output_artifact;
    let mut saw_orchestrator = false;
    let mut unknown_version = false;

    for &index in &ordered {
        let record = &records[index];
        let classification = &record.classification;
        let evidence = record.evidence();

        if record.source_kind == RemediationSourceKind::HealthScripts {
            saw_orchestrator = true;
        }
        if classification.stage_shaped_but_unmatched {
            unknown_version = true;
        }
        if classification.signal == RemediationSignal::OutputCaptured {
            has_output_evidence = true;
        }
        if classification.signal == RemediationSignal::StageLaunched {
            attempts += 1;
        }
        if let Some((raw, parsed)) = &classification.payload {
            payloads.push(RemediationPayload {
                evidence: evidence.clone(),
                parsed: *parsed,
                raw_text: RemediationClassifiedString::sensitive(raw.clone()),
            });
        }

        match classification.signal {
            RemediationSignal::ReportSubmitted => report = RemediationReportState::Submitted,
            RemediationSignal::ReportFailed => report = RemediationReportState::Failed,
            _ => {}
        }

        // Everything below needs a stage. A record that named none cannot move
        // either half, regardless of what exit code it carries.
        let Some(stage) = record.resolved_stage else {
            continue;
        };

        match stage {
            RemediationStage::Detection => {
                apply_detection(&mut detection, classification, &evidence)
            }
            RemediationStage::PostDetection => {
                let outcome = post_detection
                    .get_or_insert_with(|| StageOutcome::new(DetectionState::NotStarted));
                apply_detection(outcome, classification, &evidence);
            }
            RemediationStage::Remediation => {
                apply_remediation(&mut remediation, classification, &evidence)
            }
        }
    }

    // Detection found nothing wrong, and no remediation record exists: the
    // remediation was correctly skipped rather than merely absent.
    if detection.state == DetectionState::Compliant
        && remediation.state == RemediationRunState::NotStarted
    {
        remediation.state = RemediationRunState::Skipped;
    }

    let confidence = confidence_for(&detection, &remediation, unknown_version, saw_orchestrator);
    let next_evidence_request =
        next_evidence_request(&detection, &remediation, report, has_output_evidence);

    RemediationTransaction {
        key,
        detection,
        remediation,
        post_detection,
        report,
        attempts,
        confidence,
        payloads,
        observations: ordered
            .iter()
            .map(|&index| records[index].observation_id())
            .collect(),
        evidence: ordered
            .iter()
            .map(|&index| records[index].evidence())
            .collect(),
        next_evidence_request,
    }
}

fn apply_detection(
    outcome: &mut StageOutcome<DetectionState>,
    classification: &RecordClassification,
    evidence: &RemediationEvidenceRef,
) {
    let next = match classification.signal {
        RemediationSignal::StageLaunched => Some(DetectionState::Launched),
        RemediationSignal::StageLaunchFailed => Some(DetectionState::Failed),
        RemediationSignal::StageTimedOut => Some(DetectionState::TimedOut),
        RemediationSignal::StageCompleted => Some(detection_state_for_exit(
            classification.exit_token.as_ref().and_then(|t| t.decimal),
        )),
        _ => None,
    };
    let Some(next) = next else {
        return;
    };
    outcome.state = next;
    // The token always reflects the most recent completion, including one whose
    // code could not be read.
    if classification.signal == RemediationSignal::StageCompleted {
        outcome.exit_token = classification.exit_token.clone();
    }
    outcome.evidence.push(evidence.clone());
}

fn apply_remediation(
    outcome: &mut StageOutcome<RemediationRunState>,
    classification: &RecordClassification,
    evidence: &RemediationEvidenceRef,
) {
    let next = match classification.signal {
        RemediationSignal::StageLaunched => Some(RemediationRunState::Launched),
        RemediationSignal::StageLaunchFailed => Some(RemediationRunState::FailedToLaunch),
        RemediationSignal::StageTimedOut => Some(RemediationRunState::TimedOut),
        RemediationSignal::StageCompleted => Some(remediation_state_for_exit(
            classification.exit_token.as_ref().and_then(|t| t.decimal),
        )),
        _ => None,
    };
    let Some(next) = next else {
        return;
    };
    outcome.state = next;
    if classification.signal == RemediationSignal::StageCompleted {
        outcome.exit_token = classification.exit_token.clone();
    }
    outcome.evidence.push(evidence.clone());
}
