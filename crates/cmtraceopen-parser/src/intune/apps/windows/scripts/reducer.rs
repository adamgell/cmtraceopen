//! Reduction of classified platform-script records into keyed transactions.
//!
//! Two records join a transaction only when they carry the same
//! [`ScriptTransactionKey`]. Within the AgentExecutor log a record may inherit
//! the key of its own execution block -- a contiguous run of records on one
//! CCM thread -- because that block is written by one execution. It may never
//! inherit a key across threads, across artifacts, or from a neighbouring
//! timestamp.

use std::collections::{BTreeMap, BTreeSet};

use crate::intune::ime_parser::parse_ime_content;

use super::models::{
    ScriptAnalysis, ScriptArtifact, ScriptClassifiedString, ScriptConfidence, ScriptCoverage,
    ScriptEvidenceRef, ScriptExecutionContext, ScriptExitToken, ScriptInterpreterBitness,
    ScriptObservation, ScriptPhase, ScriptSignal, ScriptSourceKind, ScriptState, ScriptTimestamp,
    ScriptTransaction, ScriptTransactionKey,
};
use super::rules::{classify_record, RecordClassification};
use super::sources::{classify_artifact, output_artifact_identity, ScriptSourceInput};

/// Render a CCM offset in minutes as `+HH:MM` / `-HH:MM`.
fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

/// Lifecycle rank. A later-ranked signal replaces an earlier one; equal ranks
/// resolve to the later record, which is how a retry sequence lands on its
/// final attempt instead of its first.
fn state_rank(state: ScriptState) -> u8 {
    match state {
        ScriptState::InsufficientEvidence => 0,
        ScriptState::PolicyReceived => 1,
        ScriptState::Scheduled => 2,
        ScriptState::Retried => 3,
        ScriptState::Launched => 4,
        ScriptState::FailedToLaunch => 5,
        ScriptState::TimedOut => 6,
        ScriptState::ExitedZero | ScriptState::ExitedNonZero => 7,
        ScriptState::ReportSubmitted | ScriptState::ReportFailed => 8,
    }
}

fn phase_for(signal: ScriptSignal) -> Option<ScriptPhase> {
    match signal {
        ScriptSignal::PolicyReceived => Some(ScriptPhase::PolicyReceived),
        ScriptSignal::Scheduled | ScriptSignal::RetryScheduled => Some(ScriptPhase::Scheduled),
        ScriptSignal::LaunchAttempted | ScriptSignal::LaunchFailed => Some(ScriptPhase::Launched),
        ScriptSignal::ExecutionCompleted
        | ScriptSignal::ExecutionTimedOut
        | ScriptSignal::OutputCaptured => Some(ScriptPhase::Executed),
        ScriptSignal::ReportSubmitted | ScriptSignal::ReportFailed => Some(ScriptPhase::Reported),
        ScriptSignal::Unclassified => None,
    }
}

fn state_for(signal: ScriptSignal, exit_token: Option<&ScriptExitToken>) -> Option<ScriptState> {
    match signal {
        ScriptSignal::PolicyReceived => Some(ScriptState::PolicyReceived),
        ScriptSignal::Scheduled => Some(ScriptState::Scheduled),
        ScriptSignal::RetryScheduled => Some(ScriptState::Retried),
        ScriptSignal::LaunchAttempted => Some(ScriptState::Launched),
        ScriptSignal::LaunchFailed => Some(ScriptState::FailedToLaunch),
        ScriptSignal::ExecutionTimedOut => Some(ScriptState::TimedOut),
        ScriptSignal::ExecutionCompleted => match exit_token.and_then(|token| token.decimal) {
            Some(0) => Some(ScriptState::ExitedZero),
            // A completion record whose code we could not read is still a
            // completion, but it cannot claim success.
            Some(_) | None => Some(ScriptState::ExitedNonZero),
        },
        ScriptSignal::ReportSubmitted => Some(ScriptState::ReportSubmitted),
        ScriptSignal::ReportFailed => Some(ScriptState::ReportFailed),
        ScriptSignal::OutputCaptured | ScriptSignal::Unclassified => None,
    }
}

/// A classified record plus where it came from, before keying.
struct PendingRecord {
    artifact_index: usize,
    artifact_id: String,
    source_kind: ScriptSourceKind,
    record_number: u32,
    line_number: Option<u32>,
    thread: Option<u32>,
    timestamp: Option<ScriptTimestamp>,
    message: String,
    classification: RecordClassification,
    /// Assigned during block resolution for AgentExecutor records.
    resolved_policy_id: Option<String>,
    resolved_run_id: Option<String>,
    resolved_context: ScriptExecutionContext,
}

impl PendingRecord {
    fn observation_id(&self) -> String {
        format!("{}:{}", self.artifact_id, self.record_number)
    }

    fn evidence(&self) -> ScriptEvidenceRef {
        ScriptEvidenceRef {
            artifact_id: self.artifact_id.clone(),
            record_number: self.record_number,
            line_number: self.line_number,
        }
    }
}

/// Resolve keys inside each AgentExecutor artifact.
///
/// Records are grouped per artifact and per CCM thread. Within a thread a new
/// block begins at each `LaunchAttempted`; every record in a block shares the
/// block's key, which comes from whichever record in that block named a policy.
/// A block that never names a policy stays unkeyed -- its timeout or exit code
/// cannot terminate somebody else's script.
///
/// Blocks never span artifacts. Two rotations of the same log reuse thread
/// numbers freely, so an execution split across a rotation boundary leaves an
/// unkeyed tail rather than a guessed join.
fn resolve_agent_executor_blocks(records: &mut [PendingRecord]) {
    // Collect indices per artifact and thread, preserving source order.
    let mut by_thread: BTreeMap<(usize, Option<u32>), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if record.source_kind != ScriptSourceKind::AgentExecutor {
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
                == ScriptSignal::LaunchAttempted
                && !block.is_empty();

            if starts_new_block {
                apply_block_key(records, &block);
                block.clear();
            }
            block.push(index);
        }
        apply_block_key(records, &block);
    }
}

/// Give every record in a block the block's single key, if it has one.
fn apply_block_key(records: &mut [PendingRecord], block: &[usize]) {
    if block.is_empty() {
        return;
    }

    let mut policy_id: Option<String> = None;
    let mut run_id: Option<String> = None;
    let mut context = ScriptExecutionContext::Unknown;
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
        if classification.context != ScriptExecutionContext::Unknown
            && context == ScriptExecutionContext::Unknown
        {
            context = classification.context;
        }
    }

    // Two different policies inside one block means our block boundary is
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
        records[index].resolved_context = context;
    }
}

/// Complete partial keys using *identity*, never time.
///
/// The primary IME log names a policy but almost never names the run; the
/// AgentExecutor log names both. A record that knows only the policy may adopt
/// a run id when that policy has exactly one run in the supplied evidence --
/// there is then no other execution it could belong to. When a policy has two
/// or more runs the record keeps its partial key, so an ambiguous report is
/// reported as ambiguous instead of being attached to a guess.
///
/// The same reasoning widens an unknown execution context to the single
/// context actually observed for that policy.
fn reconcile_partial_keys(records: &mut [PendingRecord]) {
    // policy id -> run id -> contexts seen for that run
    let mut runs: BTreeMap<String, BTreeMap<String, BTreeSet<ScriptExecutionContext>>> =
        BTreeMap::new();

    for record in records.iter() {
        if let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id) {
            runs.entry(policy.clone())
                .or_default()
                .entry(run.clone())
                .or_default()
                .insert(record.resolved_context);
        }
    }

    for record in records.iter_mut() {
        let Some(policy) = record.resolved_policy_id.clone() else {
            continue;
        };
        let Some(by_run) = runs.get(&policy) else {
            continue;
        };

        // Exactly one run for this policy: a policy-only record can only mean
        // that run.
        if record.resolved_run_id.is_none() {
            if by_run.len() == 1 {
                let (run, _) = by_run.iter().next().expect("checked len");
                record.resolved_run_id = Some(run.clone());
            } else {
                continue;
            }
        }
    }

    // Now that policy-only records carry a run, unify the execution context
    // across each run. The AgentExecutor log frequently omits the context that
    // the primary IME log states explicitly, and vice versa; when exactly one
    // context was ever stated for a run, every record of that run shares it.
    let mut contexts: BTreeMap<(String, String), BTreeSet<ScriptExecutionContext>> =
        BTreeMap::new();
    for record in records.iter() {
        if let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id) {
            if record.resolved_context != ScriptExecutionContext::Unknown {
                contexts
                    .entry((policy.clone(), run.clone()))
                    .or_default()
                    .insert(record.resolved_context);
            }
        }
    }

    for record in records.iter_mut() {
        if record.resolved_context != ScriptExecutionContext::Unknown {
            continue;
        }
        let (Some(policy), Some(run)) = (&record.resolved_policy_id, &record.resolved_run_id)
        else {
            continue;
        };
        if let Some(observed) = contexts.get(&(policy.clone(), run.clone())) {
            if observed.len() == 1 {
                record.resolved_context = *observed.iter().next().expect("checked len");
            }
        }
    }
}

fn to_observation(record: &PendingRecord) -> ScriptObservation {
    ScriptObservation {
        observation_id: record.observation_id(),
        evidence: record.evidence(),
        source_kind: record.source_kind,
        timestamp: record.timestamp.clone(),
        signal: record.classification.signal,
        policy_id: record.resolved_policy_id.clone(),
        run_id: record.resolved_run_id.clone(),
        context: record.resolved_context,
        bitness: record.classification.bitness,
        attempt: record.classification.attempt,
        exit_token: record.classification.exit_token.clone(),
        message: ScriptClassifiedString::sensitive(record.message.clone()),
    }
}

fn next_evidence_request(state: ScriptState, has_output_evidence: bool) -> Option<String> {
    match state {
        ScriptState::PolicyReceived | ScriptState::Scheduled | ScriptState::Retried => {
            Some("AgentExecutor.log covering the scheduled execution window".to_string())
        }
        ScriptState::Launched => {
            Some("AgentExecutor.log rotation containing the execution result".to_string())
        }
        ScriptState::ExitedNonZero | ScriptState::TimedOut | ScriptState::FailedToLaunch
            if !has_output_evidence =>
        {
            Some("retained script output artifact for this policy and run".to_string())
        }
        ScriptState::ExitedZero | ScriptState::ExitedNonZero => {
            Some("IntuneManagementExtension.log records reporting this result".to_string())
        }
        ScriptState::InsufficientEvidence => {
            Some("IntuneManagementExtension.log and AgentExecutor.log for this policy".to_string())
        }
        _ => None,
    }
}

/// Confidence describes how well evidenced the *reduced state* is.
///
/// It is not a judgement about the bundle's completeness -- a missing source is
/// reported through coverage and the next-evidence request instead. An exit
/// code written by the executor is strong evidence that the script exited with
/// that code, even when the reporting half of the lifecycle was never supplied.
fn confidence_for(
    state: ScriptState,
    key: &ScriptTransactionKey,
    unknown_version: bool,
    transaction_saw_executor: bool,
) -> ScriptConfidence {
    let terminal = matches!(
        state,
        ScriptState::ExitedZero
            | ScriptState::ExitedNonZero
            | ScriptState::TimedOut
            | ScriptState::FailedToLaunch
            | ScriptState::ReportSubmitted
            | ScriptState::ReportFailed
    );

    if unknown_version {
        return ScriptConfidence::Low;
    }
    if !terminal {
        return ScriptConfidence::Low;
    }
    // A terminal execution outcome we never saw the executor write, or one we
    // cannot pin to a specific run, is corroborating rather than conclusive.
    if key.run_id.is_none() || !transaction_saw_executor {
        return ScriptConfidence::Medium;
    }
    ScriptConfidence::High
}

/// Reduce a supplied platform-script bundle.
///
/// The caller owns all I/O: it reads and decodes each artifact and passes the
/// text in. This function performs no filesystem, registry, or network access.
pub fn analyze_script_bundle(inputs: &[ScriptSourceInput]) -> ScriptAnalysis {
    let mut artifacts: Vec<ScriptArtifact> = Vec::new();
    let mut records: Vec<PendingRecord> = Vec::new();
    let mut unclassified_records = 0u32;
    let mut unknown_version_observed = false;
    // (policy, run) pairs proven to have a retained output artifact.
    let mut output_artifact_keys: BTreeSet<(String, String)> = BTreeSet::new();

    for (artifact_index, input) in inputs.iter().enumerate() {
        let lines = parse_ime_content(&input.content);
        let components: Vec<Option<String>> =
            lines.iter().map(|line| line.component.clone()).collect();
        let artifact = classify_artifact(input, &components);
        let source_kind = artifact.source_kind;
        artifacts.push(artifact);

        // A retained output artifact is evidence by its identity alone. Its
        // contents are raw script stdout/stderr -- unbounded and frequently
        // sensitive -- so they are registered, never parsed.
        if source_kind == ScriptSourceKind::ScriptOutput {
            if let Some(identity) = output_artifact_identity(input) {
                output_artifact_keys.insert(identity);
            }
            continue;
        }

        for (record_index, line) in lines.iter().enumerate() {
            let classification = classify_record(source_kind, &line.message);
            if classification.execution_shaped_but_unmatched {
                unknown_version_observed = true;
            }
            if classification.signal == ScriptSignal::Unclassified
                && classification.policy_id.is_none()
            {
                unclassified_records += 1;
            }

            let timestamp = line.timestamp.as_ref().map(|raw| ScriptTimestamp {
                raw_text: raw.clone(),
                original_offset: line.timezone_offset.map(format_offset),
                // Only trust the UTC form when the record stated its own
                // offset. Without one, `ime_parser` fills `timestamp_utc` from
                // the parsing machine's local offset, which is a property of
                // whoever opened the log rather than of the evidence.
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
                resolved_context: classification.context,
                classification,
            });
        }
    }

    resolve_agent_executor_blocks(&mut records);
    reconcile_partial_keys(&mut records);

    // Group into transactions.
    let mut grouped: BTreeMap<ScriptTransactionKey, Vec<usize>> = BTreeMap::new();
    let mut unkeyed_observations: Vec<String> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let has_signal = record.classification.signal != ScriptSignal::Unclassified;
        // A record that named the policy itself is evidence even when it
        // carries no signal: it is what proves the transaction's identity, and
        // a transaction that cannot cite it is citing an incomplete case. A
        // record that merely inherited its block's key is not included, so the
        // evidence list stays the records that actually said something.
        let names_its_own_policy = record.classification.policy_id.is_some();
        let belongs = has_signal || names_its_own_policy;

        match &record.resolved_policy_id {
            Some(policy_id) if belongs => {
                grouped
                    .entry(ScriptTransactionKey {
                        policy_id: policy_id.clone(),
                        run_id: record.resolved_run_id.clone(),
                        context: record.resolved_context,
                    })
                    .or_default()
                    .push(index);
            }
            _ if has_signal => unkeyed_observations.push(record.observation_id()),
            _ => {}
        }
    }

    let saw_agent_executor = artifacts
        .iter()
        .any(|artifact| artifact.source_kind == ScriptSourceKind::AgentExecutor);
    let saw_ime = artifacts
        .iter()
        .any(|artifact| artifact.source_kind == ScriptSourceKind::IntuneManagementExtension);

    let mut transactions: Vec<ScriptTransaction> = Vec::new();
    for (key, indices) in grouped {
        let has_output_artifact = key.run_id.as_ref().is_some_and(|run| {
            output_artifact_keys.contains(&(key.policy_id.clone(), run.clone()))
        });
        transactions.push(reduce_transaction(
            key,
            &indices,
            &records,
            has_output_artifact,
        ));
    }

    let mut missing_expected_sources = Vec::new();
    if !saw_ime {
        missing_expected_sources.push("IntuneManagementExtension.log".to_string());
    }
    if !saw_agent_executor {
        missing_expected_sources.push("AgentExecutor.log".to_string());
    }

    let observations = records.iter().map(to_observation).collect();

    ScriptAnalysis {
        transactions,
        observations,
        unkeyed_observations,
        coverage: ScriptCoverage {
            artifacts,
            unclassified_records,
            missing_expected_sources,
            unknown_version_observed,
        },
    }
}

fn reduce_transaction(
    key: ScriptTransactionKey,
    indices: &[usize],
    records: &[PendingRecord],
    has_output_artifact: bool,
) -> ScriptTransaction {
    let mut ordered: Vec<usize> = indices.to_vec();
    // Ordering decides which attempt a retry sequence reports, so it has to be
    // defensible. When every record in this transaction states its own UTC
    // offset, real time is the better order and is used. Otherwise we fall back
    // to source order, because the alternative -- a UTC value derived from the
    // parsing machine's timezone -- is not evidence.
    //
    // Source order means artifact order as the caller supplied it. That matters
    // when one transaction spans a live log and a rotation: the caller is
    // expected to pass rotations oldest first.
    let all_timestamps_trustworthy = ordered.iter().all(|&index| {
        records[index]
            .timestamp
            .as_ref()
            .is_some_and(|timestamp| timestamp.normalized_utc.is_some())
    });

    if all_timestamps_trustworthy {
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

    let mut state = ScriptState::InsufficientEvidence;
    let mut last_confirmed_phase: Option<ScriptPhase> = None;
    let mut exit_token: Option<ScriptExitToken> = None;
    let mut attempts = 0u32;
    let mut bitness = ScriptInterpreterBitness::Unknown;
    let mut has_output_evidence = has_output_artifact;
    let mut executions = 0u32;
    let mut transaction_saw_executor = false;
    let mut transaction_unknown_version = false;

    for &index in &ordered {
        let record = &records[index];
        let classification = &record.classification;

        if classification.signal == ScriptSignal::LaunchAttempted {
            attempts += 1;
        }
        if matches!(
            classification.signal,
            ScriptSignal::ExecutionCompleted | ScriptSignal::ExecutionTimedOut
        ) {
            executions += 1;
        }
        if classification.signal == ScriptSignal::OutputCaptured {
            has_output_evidence = true;
        }
        if record.source_kind == ScriptSourceKind::AgentExecutor {
            transaction_saw_executor = true;
        }
        // Scoped to this transaction on purpose. An unrecognised record
        // belonging to some other policy in the same bundle must not silently
        // demote a fully evidenced result over here.
        if classification.execution_shaped_but_unmatched {
            transaction_unknown_version = true;
        }
        if classification.bitness != ScriptInterpreterBitness::Unknown
            && bitness == ScriptInterpreterBitness::Unknown
        {
            bitness = classification.bitness;
        }

        if let Some(phase) = phase_for(classification.signal) {
            last_confirmed_phase = Some(match last_confirmed_phase {
                Some(existing) if existing > phase => existing,
                _ => phase,
            });
        }

        if let Some(candidate) =
            state_for(classification.signal, classification.exit_token.as_ref())
        {
            if state_rank(candidate) >= state_rank(state) {
                state = candidate;
            }
        }

        // The exit token always reflects the most recent completion record, so
        // a retry that finally succeeds does not keep reporting the old code.
        if classification.signal == ScriptSignal::ExecutionCompleted {
            if let Some(token) = &classification.exit_token {
                exit_token = Some(token.clone());
            }
        }
    }

    // A launch we never saw start, but whose result we did, still counts.
    if attempts == 0 {
        attempts = executions;
    }

    let confidence = confidence_for(
        state,
        &key,
        transaction_unknown_version,
        transaction_saw_executor,
    );

    ScriptTransaction {
        key,
        bitness,
        observations: ordered
            .iter()
            .map(|&index| records[index].observation_id())
            .collect(),
        last_confirmed_phase,
        state,
        exit_token,
        attempts,
        confidence,
        evidence: ordered
            .iter()
            .map(|&index| records[index].evidence())
            .collect(),
        next_evidence_request: next_evidence_request(state, has_output_evidence),
    }
}
