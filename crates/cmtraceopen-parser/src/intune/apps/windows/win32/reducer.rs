//! Reduction of classified Win32 records into keyed deployment transactions.
//!
//! Two records join a transaction only when they carry the same
//! [`Win32TransactionKey`]. Within one artifact and one CCM thread a record may
//! inherit the key of its own execution block -- a contiguous run written by one
//! app's processing pass -- because that block belongs to a single deployment.
//! It may never inherit a key across threads, across artifacts, or from a
//! neighbouring timestamp.
//!
//! Everything that cannot be keyed stays visible: unkeyed signals, physical-line
//! fragments, unmatched rotation tails, and supplemental installer artifacts
//! nothing referenced. None of them can terminate somebody else's deployment.

use std::collections::{BTreeMap, BTreeSet};

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode,
    IntuneEvidenceRef, IntuneObservationContext, IntuneParseState, IntuneProvenance,
    IntuneSensitivity, IntuneTimestamp, IntuneTimestampKind,
};
use crate::intune::ime_parser::{parse_ime_content, ImeLine};

use super::models::{
    Win32Analysis, Win32AppMetadata, Win32Confidence, Win32Coverage, Win32ExecutionContext,
    Win32Intent, Win32Observation, Win32Outcome, Win32Phase, Win32ReturnCodeKind,
    Win32ReturnCodeMapping, Win32Signal, Win32SourceKind, Win32SupersededFailure,
    Win32Transaction, Win32TransactionKey, WIN32_SCHEMA_VERSION,
};
use super::rules::{classify_record, RecordClassification};
use super::sources::{
    artifact_coverage, candidate_source_kind, classify_artifact, coverage_family,
    intune_source_kind, split_rotation, Win32SourceInput,
};

/// Artifacts a complete Win32 bundle is expected to contain.
///
/// A caller that omits one entirely still gets a coverage entry, so "we never
/// looked" and "we looked and it was gone" stay distinguishable.
const EXPECTED_PRIMARY_ARTIFACTS: [&str; 3] = [
    "IntuneManagementExtension.log",
    "AppWorkload.log",
    "AppActionProcessor.log",
];

/// Upper bound on framed records read from one artifact.
///
/// An adversarial or corrupted artifact must not be able to make the reduction
/// retain unbounded state. Records beyond the cap are dropped and the artifact
/// is reported as `Capped` in coverage, which degrades coverage exactly like a
/// caller-declared truncation — the absence of a signal past the cap proves
/// nothing. IME's own rotation policy keeps real artifacts far below this.
const MAX_RECORDS_PER_ARTIFACT: usize = 100_000;

/// Optional caller-supplied context for a reduction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Win32AnalysisOptions {
    /// Privacy-safe display names for synthetic ids. Never inferred from a log.
    pub metadata: Vec<Win32AppMetadata>,
    /// The per-app return-code table Intune was configured with.
    pub return_codes: Vec<Win32ReturnCodeMapping>,
}

/// Intune's documented default Win32 app return codes.
///
/// This is a product contract, not an interpretation invented here: Intune ships
/// exactly these five mappings on every new deployment type. Anything else stays
/// [`Win32ReturnCodeKind::Unmapped`] until a caller supplies the app's own table.
const DEFAULT_RETURN_CODES: [(i64, Win32ReturnCodeKind); 5] = [
    (0, Win32ReturnCodeKind::Success),
    (1707, Win32ReturnCodeKind::Success),
    (3010, Win32ReturnCodeKind::SoftReboot),
    (1641, Win32ReturnCodeKind::HardReboot),
    (1618, Win32ReturnCodeKind::Retry),
];

fn classify_return_code(
    key: &Win32TransactionKey,
    code: &IntuneErrorCode,
    table: &[Win32ReturnCodeMapping],
) -> Win32ReturnCodeKind {
    let Some(decimal) = code.decimal else {
        return Win32ReturnCodeKind::Unmapped;
    };
    // Intune configures the table per deployment type, so an entry scoped to
    // this transaction's deployment type wins over an app-wide entry.
    let matches_app = |mapping: &&Win32ReturnCodeMapping| {
        mapping.app_id == key.app_id && mapping.code == decimal
    };
    let scoped = table.iter().filter(matches_app).find(|mapping| {
        mapping.deployment_type_id.is_some()
            && mapping.deployment_type_id == key.deployment_type_id
    });
    if let Some(mapping) = scoped.or_else(|| {
        table
            .iter()
            .filter(matches_app)
            .find(|mapping| mapping.deployment_type_id.is_none())
    }) {
        return mapping.kind;
    }
    DEFAULT_RETURN_CODES
        .iter()
        .find(|(candidate, _)| *candidate == decimal)
        .map(|(_, kind)| *kind)
        .unwrap_or(Win32ReturnCodeKind::Unmapped)
}

/// Lifecycle rank for the *in-flight* states.
///
/// Only non-terminal states are ever resolved by rank: a policy receipt, an
/// enforcement start, and a scheduled retry are progress markers, and the
/// furthest one describes the deployment best. Terminal statements are
/// equal-authority candidates resolved by [`resolve_outcome`] using a source's
/// own ordering, never by a rank ladder that would let an unlinked success
/// absorb a proven failure (ADR-003).
fn pending_rank(outcome: Win32Outcome) -> u8 {
    match outcome {
        Win32Outcome::Assigned => 1,
        Win32Outcome::Enforcing => 2,
        Win32Outcome::Deferred => 3,
        // `InsufficientEvidence` and every other variant either is the fold's
        // starting point or never flows through the pending state.
        _ => 0,
    }
}

/// Render a CCM offset in minutes as `+HH:MM` / `-HH:MM`.
fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

/// A framed record plus where it came from, before keying.
struct PendingRecord {
    artifact_index: usize,
    artifact_id: String,
    file_path: Option<String>,
    source_kind: Win32SourceKind,
    access_state: IntuneAccessState,
    captured_at_utc: String,
    record_number: u32,
    line_number: u32,
    thread: Option<u32>,
    timestamp: Option<IntuneTimestamp>,
    message: String,
    /// True for a physical-line fragment or an unmatched rotation tail.
    is_fragment: bool,
    classification: RecordClassification,
    resolved_app_id: Option<String>,
    resolved_deployment_type_id: Option<String>,
    /// True when `resolved_deployment_type_id` was filled by bundle-wide
    /// uniqueness inference rather than stated by the record or its own
    /// execution block. Inferred key components complete the key but are not
    /// observed evidence, so they never count toward confidence (ADR-001).
    deployment_type_inferred: bool,
    resolved_context: Win32ExecutionContext,
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

    fn context(&self) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: self.evidence(),
            provenance: IntuneProvenance {
                source_kind: intune_source_kind(self.source_kind),
                source_artifact_id: self.artifact_id.clone(),
                file_path: self.file_path.clone(),
                line_number: Some(u64::from(self.line_number)),
                record_number: Some(u64::from(self.record_number)),
                registry: None,
                event: None,
            },
            source_timestamp: self.timestamp.clone(),
            observed_at_utc: self.captured_at_utc.clone(),
            // Win32 records routinely quote install command lines, UPNs, and
            // profile paths, so the whole record is sensitive by default and the
            // export projection masks it.
            sensitivity: IntuneSensitivity::Sensitive,
            parse_state: if self.is_fragment {
                IntuneParseState::Malformed
            } else {
                IntuneParseState::Parsed
            },
            access_state: self.access_state.clone(),
        }
    }
}

/// A physical-line fragment or an unmatched rotation tail.
///
/// `parse_ime_content` emits these for text outside a complete `<![LOG[…]LOG]!>`
/// record. They carry neither a CCM timestamp nor a component, which is exactly
/// why they cannot create a transaction event: there is no framed record to
/// classify and no attribute to key on.
fn is_fragment(line: &ImeLine) -> bool {
    line.timestamp.is_none() && line.component.is_none()
}

fn build_timestamp(line: &ImeLine) -> Option<IntuneTimestamp> {
    let raw_text = line.timestamp.clone()?;
    let has_offset = line.timezone_offset.is_some();
    Some(IntuneTimestamp {
        raw_text,
        original_offset: line.timezone_offset.map(format_offset),
        // Only trust the UTC form when the record stated its own offset.
        // Without one, `ime_parser` fills `timestamp_utc` from the parsing
        // machine's local offset, which is a property of whoever opened the log
        // rather than of the evidence.
        normalized_utc: has_offset.then(|| line.timestamp_utc.clone()).flatten(),
        kind: if has_offset {
            IntuneTimestampKind::Offset
        } else {
            IntuneTimestampKind::Unspecified
        },
    })
}

/// Resolve keys inside each artifact, per CCM thread.
///
/// Within a thread a new block begins at each `AppPolicyReceived`; every record
/// in the block that did not name an app itself adopts the block's app id. A
/// block naming two different apps refuses to key at all, because the block
/// boundary is then wrong for this IME version and merging would be a guess.
///
/// Fragments never inherit. A record we could not frame has no proven position
/// in any block.
fn resolve_blocks(records: &mut [PendingRecord]) {
    let mut by_thread: BTreeMap<(usize, Option<u32>), Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if !record.classification.in_scope || record.is_fragment {
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
                == Win32Signal::AppPolicyReceived
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

fn apply_block_key(records: &mut [PendingRecord], block: &[usize]) {
    if block.is_empty() {
        return;
    }

    let mut app_id: Option<String> = None;
    let mut deployment_type_id: Option<String> = None;
    let mut context = Win32ExecutionContext::Unknown;
    let mut conflicting = false;

    for &index in block {
        let classification = &records[index].classification;
        if let Some(candidate) = &classification.app_id {
            match &app_id {
                Some(existing) if existing != candidate => conflicting = true,
                Some(_) => {}
                None => app_id = Some(candidate.clone()),
            }
        }
        if let Some(candidate) = &classification.deployment_type_id {
            if deployment_type_id.is_none() {
                deployment_type_id = Some(candidate.clone());
            }
        }
        if classification.execution_context != Win32ExecutionContext::Unknown
            && context == Win32ExecutionContext::Unknown
        {
            context = classification.execution_context;
        }
    }

    // Two apps inside one block means the boundary is wrong for this IME
    // version. Refuse to spread a key rather than merge two deployments; each
    // record that named its own app keeps it.
    if conflicting {
        return;
    }
    let Some(app_id) = app_id else {
        return;
    };

    for &index in block {
        if records[index].resolved_app_id.is_none() {
            records[index].resolved_app_id = Some(app_id.clone());
        }
        if records[index].resolved_deployment_type_id.is_none() {
            records[index].resolved_deployment_type_id = deployment_type_id.clone();
        }
        if records[index].resolved_context == Win32ExecutionContext::Unknown {
            records[index].resolved_context = context;
        }
    }
}

/// Complete partial keys using *identity*, never time.
///
/// A record that named an app but no deployment type may adopt one when that app
/// has exactly one deployment type in the supplied evidence: there is then no
/// other deployment it could belong to. An app with two or more keeps its partial
/// key, so an ambiguous record is reported as ambiguous instead of attached to a
/// guess. The same reasoning widens an unknown execution context.
fn reconcile_partial_keys(records: &mut [PendingRecord]) {
    let mut types_by_app: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut contexts_by_app: BTreeMap<String, BTreeSet<Win32ExecutionContext>> = BTreeMap::new();

    for record in records.iter() {
        let Some(app) = &record.resolved_app_id else {
            continue;
        };
        if let Some(deployment_type) = &record.resolved_deployment_type_id {
            types_by_app
                .entry(app.clone())
                .or_default()
                .insert(deployment_type.clone());
        }
        if record.resolved_context != Win32ExecutionContext::Unknown {
            contexts_by_app
                .entry(app.clone())
                .or_default()
                .insert(record.resolved_context);
        }
    }

    for record in records.iter_mut() {
        let Some(app) = record.resolved_app_id.clone() else {
            continue;
        };
        if record.resolved_deployment_type_id.is_none() {
            if let Some(types) = types_by_app.get(&app) {
                if types.len() == 1 {
                    record.resolved_deployment_type_id = types.iter().next().cloned();
                    record.deployment_type_inferred = true;
                }
            }
        }
        if record.resolved_context == Win32ExecutionContext::Unknown {
            if let Some(contexts) = contexts_by_app.get(&app) {
                if contexts.len() == 1 {
                    record.resolved_context = *contexts.iter().next().expect("checked len");
                }
            }
        }
    }
}

fn to_observation(record: &PendingRecord) -> Win32Observation {
    Win32Observation {
        observation_id: record.observation_id(),
        context: record.context(),
        source_kind: record.source_kind,
        signal: record.classification.signal,
        enforcement_shaped_but_unmatched: record.classification.enforcement_shaped_but_unmatched
            || (record.classification.signal == Win32Signal::InstallerCompleted
                && record.classification.error_code.is_none()),
        app_id: record.resolved_app_id.clone(),
        deployment_type_id: record.resolved_deployment_type_id.clone(),
        content_version: record.classification.content_version.clone(),
        dependency_app_id: record.classification.dependency_app_id.clone(),
        requirement_name: record.classification.requirement_name.clone(),
        execution_context: record.resolved_context,
        intent: record.classification.intent,
        error_code: record.classification.error_code.clone(),
        attributes: record.classification.attributes.clone(),
        message: record.message.clone(),
    }
}

/// Reduce a supplied Win32 app bundle with default options.
///
/// The caller owns all I/O: it reads and decodes each artifact and passes the
/// text in. This function performs no filesystem, registry, or network access.
pub fn analyze_win32_bundle(inputs: &[Win32SourceInput]) -> Win32Analysis {
    analyze_win32_bundle_with(inputs, &Win32AnalysisOptions::default())
}

/// Reduce a supplied Win32 app bundle with caller-supplied metadata and return
/// codes.
pub fn analyze_win32_bundle_with(
    inputs: &[Win32SourceInput],
    options: &Win32AnalysisOptions,
) -> Win32Analysis {
    let mut coverage_entries: Vec<IntuneArtifactCoverage> = Vec::new();
    let mut records: Vec<PendingRecord> = Vec::new();
    let mut unclassified_records = 0u32;
    let mut fragment_records = 0u32;
    let mut unknown_vocabulary_observed = false;
    // File name -> artifact id, for supplemental installer artifacts.
    let mut installer_artifacts: BTreeMap<String, String> = BTreeMap::new();
    let mut seen_basenames: BTreeSet<String> = BTreeSet::new();

    for (artifact_index, input) in inputs.iter().enumerate() {
        // A supplemental installer artifact is evidence by its identity alone.
        // Its contents are installer stdout/stderr -- unbounded and frequently
        // sensitive -- so it is registered, never parsed. The check runs before
        // framing, because framing first and discarding after would pay full
        // time and peak memory for data this module has promised not to read.
        if candidate_source_kind(input) == Win32SourceKind::InstallerOutput {
            coverage_entries.push(artifact_coverage(
                input,
                Win32SourceKind::InstallerOutput,
                Some("supplemental installer artifact; contents are not parsed".to_owned()),
            ));
            installer_artifacts.insert(
                input.file_name.trim().to_ascii_lowercase(),
                input.artifact_id.clone(),
            );
            continue;
        }

        let mut lines = if input.has_content() {
            parse_ime_content(&input.content)
        } else {
            Vec::new()
        };
        let capped_by_analyzer = lines.len() > MAX_RECORDS_PER_ARTIFACT;
        lines.truncate(MAX_RECORDS_PER_ARTIFACT);

        let components: Vec<Option<String>> =
            lines.iter().map(|line| line.component.clone()).collect();
        let source_kind = classify_artifact(input, &components);
        let candidate = candidate_source_kind(input);
        let detail = (source_kind == Win32SourceKind::Unknown
            && candidate != Win32SourceKind::Unknown)
            .then(|| {
                format!(
                    "named like {candidate:?} but its records did not confirm it; \
                     excluded from reduction"
                )
            });
        let mut entry = artifact_coverage(input, source_kind, detail);
        if capped_by_analyzer {
            entry.status = IntuneArtifactStatus::Capped;
            entry.detail = Some(format!(
                "record count exceeded the analyzer bound of {MAX_RECORDS_PER_ARTIFACT}; \
                 records past the bound were not read"
            ));
        }
        coverage_entries.push(entry);

        // An artifact only satisfies the expected-artifact check when it is
        // usable evidence of its kind: readable content whose records confirmed
        // the candidate, or a caller-declared gap whose own coverage entry
        // already expresses the absence. A zero-byte capture or a
        // content-misclassified file must leave the gap open — coverage gaps
        // cannot raise confidence (ADR-001). The stem is normalized through
        // split_rotation so a rotated or prefixed variant (AppWorkload-1.log,
        // _AppWorkload.log) resolves to the same canonical basename.
        let usable = if input.has_content() {
            source_kind != Win32SourceKind::Unknown
        } else {
            input.access_state != IntuneAccessState::Available
        };
        if usable {
            seen_basenames.insert(split_rotation(&input.file_name).0.to_ascii_lowercase());
        }

        for (record_index, line) in lines.iter().enumerate() {
            let fragment = is_fragment(line);
            if fragment {
                fragment_records += 1;
            }

            // A fragment is never classified: there is no framed record to
            // classify, and letting one carry a signal would let an unmatched
            // rotation tail terminate a deployment.
            let classification = if fragment {
                classify_record(Win32SourceKind::Unknown, None, "")
            } else {
                classify_record(source_kind, line.component.as_deref(), &line.message)
            };

            if classification.enforcement_shaped_but_unmatched {
                unknown_vocabulary_observed = true;
            }
            // A completion record whose code we could not read means the
            // enforcement grammar changed under us. It is a coverage problem,
            // not a failure.
            if classification.signal == Win32Signal::InstallerCompleted
                && classification.error_code.is_none()
            {
                unknown_vocabulary_observed = true;
            }
            // Only in-scope records can be "unclassified Win32 records". A
            // PowerShell line in the shared IME log is another workload's
            // evidence, not a gap in this one's coverage.
            if classification.in_scope
                && classification.signal == Win32Signal::Unclassified
                && classification.app_id.is_none()
            {
                unclassified_records += 1;
            }

            records.push(PendingRecord {
                artifact_index,
                artifact_id: input.artifact_id.clone(),
                file_path: input.file_path.clone(),
                source_kind,
                access_state: input.access_state.clone(),
                captured_at_utc: input.captured_at_utc.clone().unwrap_or_default(),
                record_number: u32::try_from(record_index + 1)
                    .expect("record index is bounded by MAX_RECORDS_PER_ARTIFACT"),
                line_number: line.line_number,
                thread: line.thread,
                timestamp: build_timestamp(line),
                message: line.message.clone(),
                is_fragment: fragment,
                resolved_app_id: classification.app_id.clone(),
                resolved_deployment_type_id: classification.deployment_type_id.clone(),
                deployment_type_inferred: false,
                resolved_context: classification.execution_context,
                classification,
            });
        }
    }

    resolve_blocks(&mut records);
    reconcile_partial_keys(&mut records);

    // Supplemental artifacts join a transaction only when a keyed record names
    // them. Timestamp proximity is explicitly not a join condition. The map is
    // keyed by the full transaction identity (app + deployment type + execution
    // context), not app id alone, so two deployment types of the same app never
    // pull each other's corroborating artifacts.
    let mut linked_artifacts: BTreeMap<Win32TransactionKey, BTreeSet<String>> = BTreeMap::new();
    let mut linked_ids: BTreeSet<String> = BTreeSet::new();
    for record in records.iter() {
        let (Some(app), Some(referenced)) = (
            record.resolved_app_id.as_ref(),
            record.classification.referenced_output_file.as_ref(),
        ) else {
            continue;
        };
        if let Some(artifact_id) = installer_artifacts.get(&referenced.to_ascii_lowercase()) {
            linked_artifacts
                .entry(Win32TransactionKey {
                    app_id: app.clone(),
                    deployment_type_id: record.resolved_deployment_type_id.clone(),
                    execution_context: record.resolved_context,
                })
                .or_default()
                .insert(artifact_id.clone());
            linked_ids.insert(artifact_id.clone());
        }
    }

    let mut grouped: BTreeMap<Win32TransactionKey, Vec<usize>> = BTreeMap::new();
    let mut unkeyed_observations: Vec<String> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let has_signal = record.classification.signal != Win32Signal::Unclassified;
        // A record that named the app itself is evidence even without a signal:
        // it is what proves the transaction's identity. A record that merely
        // inherited its block's key is not, so the evidence list stays the
        // records that actually said something.
        let names_its_own_app = record.classification.app_id.is_some();

        match &record.resolved_app_id {
            Some(app_id) if has_signal || names_its_own_app => {
                grouped
                    .entry(Win32TransactionKey {
                        app_id: app_id.clone(),
                        deployment_type_id: record.resolved_deployment_type_id.clone(),
                        execution_context: record.resolved_context,
                    })
                    .or_default()
                    .push(index);
            }
            _ if has_signal => unkeyed_observations.push(record.observation_id()),
            _ => {}
        }
    }

    // Expected artifacts the caller never mentioned at all still get a coverage
    // entry, so "we never looked" is not silently reported as "nothing to see".
    // This runs before degraded_coverage is computed so a missing expected
    // artifact actually degrades the confidence reduce_transaction receives.
    for expected in EXPECTED_PRIMARY_ARTIFACTS {
        // split_rotation returns the stem without its extension; the expected
        // names carry `.log`, so strip it the same way for the comparison.
        let expected_stem = split_rotation(expected).0.to_ascii_lowercase();
        if seen_basenames.contains(&expected_stem) {
            continue;
        }
        coverage_entries.push(IntuneArtifactCoverage {
            artifact_id: format!("expected:{expected}"),
            family: coverage_family(Win32SourceKind::AppWorkload).to_owned(),
            status: IntuneArtifactStatus::Missing,
            detail: Some(format!(
                "no usable {expected} was supplied to the analyzer"
            )),
            observed_at_utc: String::new(),
            evidence: Vec::new(),
        });
    }

    let degraded_coverage = coverage_entries
        .iter()
        .any(|entry| entry.status != IntuneArtifactStatus::Available);

    let mut transactions: Vec<Win32Transaction> = Vec::new();
    for (key, indices) in grouped {
        let corroborating = linked_artifacts
            .get(&key)
            .map(|ids| ids.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        transactions.push(reduce_transaction(
            key,
            &indices,
            &records,
            options,
            corroborating,
            degraded_coverage,
        ));
    }

    let unlinked_installer_artifacts = installer_artifacts
        .values()
        .filter(|artifact_id| !linked_ids.contains(*artifact_id))
        .cloned()
        .collect();

    Win32Analysis {
        schema_version: WIN32_SCHEMA_VERSION,
        transactions,
        observations: records.iter().map(to_observation).collect(),
        unkeyed_observations,
        coverage: Win32Coverage {
            artifacts: coverage_entries,
            unclassified_records,
            fragment_records,
            unknown_vocabulary_observed,
            unlinked_installer_artifacts,
        },
    }
}

/// One record's terminal statement about the transaction, with the provenance
/// needed to order it against other statements.
///
/// Mirrors the Store pilot's `StateCandidate`: terminal outcomes are
/// equal-authority claims, ordered only by the source's own record numbers or
/// by timestamps the records themselves stated. Caller vector order is never
/// consulted (ADR-003).
struct TerminalCandidate {
    outcome: Win32Outcome,
    /// The failing/succeeding token this record itself carried, if any.
    return_code: Option<IntuneErrorCode>,
    /// The local outcome a `ReportingFailed` candidate is layered on top of.
    local_outcome: Option<Win32Outcome>,
    artifact_id: String,
    record_number: u32,
    normalized_utc: Option<String>,
    evidence: IntuneEvidenceRef,
}

/// A point in evidence order that can supersede an earlier candidate.
struct SequencePoint<'a> {
    artifact_id: &'a str,
    record_number: u32,
    normalized_utc: Option<&'a str>,
}

impl TerminalCandidate {
    fn sequence(&self) -> SequencePoint<'_> {
        SequencePoint {
            artifact_id: &self.artifact_id,
            record_number: self.record_number,
            normalized_utc: self.normalized_utc.as_deref(),
        }
    }
}

/// Whether `later` is explicitly ordered after `earlier`.
///
/// Two linkages exist and nothing else counts (ADR-003):
///
/// * the same artifact's own record numbers — a CCM log is the agent's
///   append-ordered journal, so a later record in the same file is proven to
///   have been written after an earlier one, across enforcement-cycle
///   boundaries included;
/// * strictly later trusted timestamps — a UTC value is only present when the
///   record stated its own offset, so comparing two of them compares evidence,
///   not the parsing machine's clock. Equal timestamps prove nothing.
///
/// Records in different artifacts without trusted timestamps share no clock
/// and no counter, so they stay incomparable and a contradiction between them
/// stays conservative.
fn sequenced_after(later: &SequencePoint<'_>, earlier: &SequencePoint<'_>) -> bool {
    if later.artifact_id == earlier.artifact_id {
        return later.record_number > earlier.record_number;
    }
    matches!(
        (later.normalized_utc, earlier.normalized_utc),
        (Some(later), Some(earlier)) if later > earlier
    )
}

/// Everything the fold over one transaction's records accumulates.
struct Fold {
    /// Furthest in-flight state, resolved by [`pending_rank`]. Used only when
    /// no terminal candidate exists at all.
    pending: Win32Outcome,
    /// Every terminal statement, kept for [`resolve_outcome`].
    terminals: Vec<TerminalCandidate>,
    /// `ReportSubmitted` records. Each one clears a `ReportingFailed` candidate
    /// it is explicitly ordered after: the retry upload landing is the source's
    /// own statement that the transient failure was superseded.
    report_clearances: Vec<(String, u32, Option<String>)>,
    /// The last non-reporting terminal outcome seen, in evidence order. This is
    /// what a reporting failure is layered on top of.
    latest_local_terminal: Option<Win32Outcome>,
    last_confirmed_phase: Option<Win32Phase>,
    return_code: Option<IntuneErrorCode>,
    return_code_kind: Option<Win32ReturnCodeKind>,
    reboot_required: bool,
    seen_enforcement: bool,
    installer_succeeded: bool,
    unresolved_dependencies: BTreeSet<String>,
    failed_requirements: BTreeSet<String>,
    unknown_vocabulary: bool,
    intent: Win32Intent,
    content_version: Option<String>,
}

impl Fold {
    fn new() -> Self {
        Self {
            pending: Win32Outcome::InsufficientEvidence,
            terminals: Vec::new(),
            report_clearances: Vec::new(),
            latest_local_terminal: None,
            last_confirmed_phase: None,
            return_code: None,
            return_code_kind: None,
            reboot_required: false,
            seen_enforcement: false,
            installer_succeeded: false,
            unresolved_dependencies: BTreeSet::new(),
            failed_requirements: BTreeSet::new(),
            unknown_vocabulary: false,
            intent: Win32Intent::Unknown,
            content_version: None,
        }
    }

    fn advance(&mut self, phase: Win32Phase) {
        self.last_confirmed_phase = Some(match self.last_confirmed_phase {
            Some(existing) if existing > phase => existing,
            _ => phase,
        });
    }

    /// Record an in-flight state. The furthest one wins; a terminal candidate
    /// always outranks all of them at resolution time.
    fn set_pending(&mut self, candidate: Win32Outcome) {
        debug_assert!(!candidate.is_terminal());
        if pending_rank(candidate) >= pending_rank(self.pending) {
            self.pending = candidate;
        }
    }

    /// Record a terminal statement as a candidate for [`resolve_outcome`].
    fn push_terminal(&mut self, record: &PendingRecord, outcome: Win32Outcome) {
        debug_assert!(outcome.is_terminal());
        let local_outcome = if outcome == Win32Outcome::ReportingFailed {
            self.latest_local_terminal
        } else {
            self.latest_local_terminal = Some(outcome);
            None
        };
        self.terminals.push(TerminalCandidate {
            outcome,
            return_code: record.classification.error_code.clone(),
            local_outcome,
            artifact_id: record.artifact_id.clone(),
            record_number: record.record_number,
            normalized_utc: record
                .timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.clone()),
            evidence: record.evidence(),
        });
    }
}

/// What [`resolve_outcome`] concluded from the candidates.
struct OutcomeResolution {
    outcome: Win32Outcome,
    local_outcome: Option<Win32Outcome>,
    superseded_failures: Vec<Win32SupersededFailure>,
}

/// Resolve the transaction outcome from every terminal statement at once.
///
/// This must give the same answer for any permutation of the same evidence
/// (ADR-003):
///
/// 1. a `ReportingFailed` candidate that a later `ReportSubmitted` from an
///    ordered position supersedes is dropped — the retry upload landed;
/// 2. a candidate explicitly ordered before another candidate is superseded by
///    it, which is what lets a linked retry land on its final outcome;
/// 3. superseded *failures* survive as [`Win32SupersededFailure`] entries: an
///    erased failure is still a proven failed enforcement cycle;
/// 4. if the surviving candidates state more than one distinct outcome, the
///    evidence is an unresolved authoritative contradiction and the reduction
///    stays conservative — [`Win32Outcome::Conflicting`], never whichever
///    record the caller happened to list last.
fn resolve_outcome(fold: &Fold) -> OutcomeResolution {
    let cleared: Vec<&TerminalCandidate> = fold
        .terminals
        .iter()
        .filter(|candidate| {
            candidate.outcome != Win32Outcome::ReportingFailed
                || !fold.report_clearances.iter().any(|(artifact, record, utc)| {
                    sequenced_after(
                        &SequencePoint {
                            artifact_id: artifact,
                            record_number: *record,
                            normalized_utc: utc.as_deref(),
                        },
                        &candidate.sequence(),
                    )
                })
        })
        .collect();

    if cleared.is_empty() {
        return OutcomeResolution {
            outcome: fold.pending,
            local_outcome: None,
            superseded_failures: Vec::new(),
        };
    }

    let survives = |index: usize| {
        !cleared.iter().enumerate().any(|(other, candidate)| {
            other != index && sequenced_after(&candidate.sequence(), &cleared[index].sequence())
        })
    };
    let mut surviving: Vec<&TerminalCandidate> = (0..cleared.len())
        .filter(|&index| survives(index))
        .map(|index| cleared[index])
        .collect();
    // Canonical evidence order, independent of the caller's input order.
    surviving.sort_by(|left, right| {
        (left.artifact_id.as_str(), left.record_number)
            .cmp(&(right.artifact_id.as_str(), right.record_number))
    });

    let mut superseded_failures: Vec<Win32SupersededFailure> = Vec::new();
    for candidate in (0..cleared.len())
        .filter(|&index| cleared[index].outcome.is_failure() && !survives(index))
        .map(|index| cleared[index])
    {
        let raw = candidate.return_code.as_ref().map(|code| code.raw.clone());
        match superseded_failures.iter_mut().find(|entry| {
            entry.outcome == candidate.outcome
                && entry.return_code.as_ref().map(|code| code.raw.clone()) == raw
        }) {
            Some(entry) => entry.evidence.push(candidate.evidence.clone()),
            None => superseded_failures.push(Win32SupersededFailure {
                outcome: candidate.outcome,
                return_code: candidate.return_code.clone(),
                evidence: vec![candidate.evidence.clone()],
            }),
        }
    }
    for entry in &mut superseded_failures {
        entry.evidence.sort_by(|left, right| {
            (left.source_artifact_id.as_str(), left.evidence_id.as_str())
                .cmp(&(right.source_artifact_id.as_str(), right.evidence_id.as_str()))
        });
    }
    superseded_failures.sort_by(|left, right| {
        (left.outcome, left.return_code.as_ref().map(|code| &code.raw))
            .cmp(&(right.outcome, right.return_code.as_ref().map(|code| &code.raw)))
    });

    let outcome = surviving[0].outcome;
    if surviving.iter().any(|candidate| candidate.outcome != outcome) {
        return OutcomeResolution {
            outcome: Win32Outcome::Conflicting,
            local_outcome: None,
            superseded_failures,
        };
    }

    OutcomeResolution {
        outcome,
        local_outcome: surviving
            .iter()
            .rev()
            .find_map(|candidate| candidate.local_outcome),
        superseded_failures,
    }
}

fn reduce_transaction(
    key: Win32TransactionKey,
    indices: &[usize],
    records: &[PendingRecord],
    options: &Win32AnalysisOptions,
    corroborating_artifacts: Vec<String>,
    degraded_coverage: bool,
) -> Win32Transaction {
    let ordered = order_records(indices, records);
    let mut fold = Fold::new();

    for &index in &ordered {
        let record = &records[index];
        apply_record(&mut fold, record, &key, options);
    }

    let resolution = resolve_outcome(&fold);
    // A conservative contradiction has no single return token: asserting the
    // code of either side would silently pick the winner the outcome refuses
    // to pick.
    let (return_code, return_code_kind, reboot_required) =
        if resolution.outcome == Win32Outcome::Conflicting {
            (None, None, false)
        } else {
            (
                fold.return_code.clone(),
                fold.return_code_kind,
                fold.reboot_required,
            )
        };

    // An entry scoped to this transaction's deployment type wins; an entry
    // without one applies app-wide. An entry for a *different* deployment type
    // of the same app must never label this transaction.
    let metadata = options
        .metadata
        .iter()
        .filter(|entry| entry.app_id == key.app_id)
        .find(|entry| {
            entry.deployment_type_id.is_some()
                && entry.deployment_type_id == key.deployment_type_id
        })
        .or_else(|| {
            options
                .metadata
                .iter()
                .filter(|entry| entry.app_id == key.app_id)
                .find(|entry| entry.deployment_type_id.is_none())
        });

    // Only a deployment type some record *stated* — itself or through its own
    // execution block — counts toward confidence. One reconcile_partial_keys
    // filled in from bundle-wide uniqueness completes the key without
    // strengthening the evidence (ADR-001).
    let deployment_type_observed = ordered.iter().any(|&index| {
        records[index].resolved_deployment_type_id.is_some()
            && !records[index].deployment_type_inferred
    });

    let confidence = confidence_for(
        resolution.outcome,
        deployment_type_observed,
        fold.unknown_vocabulary,
        degraded_coverage,
        !corroborating_artifacts.is_empty(),
    );

    Win32Transaction {
        display_name: metadata.and_then(|entry| entry.display_name.clone()),
        content_version: fold
            .content_version
            .clone()
            .or_else(|| metadata.and_then(|entry| entry.content_version.clone())),
        intent: fold.intent,
        observations: ordered
            .iter()
            .map(|&index| records[index].observation_id())
            .collect(),
        last_confirmed_phase: fold.last_confirmed_phase,
        outcome: resolution.outcome,
        local_outcome: resolution.local_outcome,
        return_code,
        return_code_kind,
        reboot_required,
        unresolved_dependencies: fold.unresolved_dependencies.into_iter().collect(),
        failed_requirements: fold.failed_requirements.into_iter().collect(),
        superseded_failures: resolution.superseded_failures,
        corroborating_artifacts,
        confidence,
        evidence: ordered
            .iter()
            .map(|&index| records[index].evidence())
            .collect(),
        next_evidence_request: next_evidence_request(resolution.outcome),
        key,
    }
}

/// Ordering feeds the fold's phase reasoning, so it has to be defensible --
/// and it must never consult the position an artifact happened to occupy in
/// the caller's vector, which is an acquisition detail (ADR-003).
///
/// When every record in this transaction stated its own UTC offset, real time
/// is the order, with the canonical artifact id and the source's own record
/// number as tie-breaks. Otherwise records are ordered by (artifact id, record
/// number): within one artifact that is the source's own append order, and
/// across artifacts it is arbitrary but *canonical*, so permuting the input
/// vector cannot change any conclusion.
///
/// Per-record timestamp trust is deliberately all-or-nothing here: mixing
/// trusted timestamps with untrusted positions yields a partial order, and any
/// total sort over a partial order smuggles in an arbitrary tie-break that
/// would then decide phase semantics. Outcome resolution does use per-record
/// linkage -- see [`sequenced_after`] -- where a partial order is safe.
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
            let sort_key = |index: usize| {
                (
                    records[index]
                        .timestamp
                        .as_ref()
                        .and_then(|timestamp| timestamp.normalized_utc.clone())
                        .unwrap_or_default(),
                    records[index].artifact_id.clone(),
                    records[index].record_number,
                )
            };
            sort_key(left).cmp(&sort_key(right))
        });
    } else {
        ordered.sort_by(|&left, &right| {
            (
                records[left].artifact_id.as_str(),
                records[left].record_number,
            )
                .cmp(&(
                    records[right].artifact_id.as_str(),
                    records[right].record_number,
                ))
        });
    }
    ordered
}

fn apply_record(
    fold: &mut Fold,
    record: &PendingRecord,
    key: &Win32TransactionKey,
    options: &Win32AnalysisOptions,
) {
    let classification = &record.classification;
    if classification.enforcement_shaped_but_unmatched {
        fold.unknown_vocabulary = true;
    }
    if fold.intent == Win32Intent::Unknown && classification.intent != Win32Intent::Unknown {
        fold.intent = classification.intent;
    }
    if fold.content_version.is_none() {
        fold.content_version = classification.content_version.clone();
    }

    match classification.signal {
        Win32Signal::AppPolicyReceived => {
            fold.advance(Win32Phase::Assignment);
            fold.set_pending(Win32Outcome::Assigned);
        }
        Win32Signal::NotTargeted => fold.push_terminal(record, Win32Outcome::NotTargeted),
        Win32Signal::ApplicabilityPassed => fold.advance(Win32Phase::Applicability),
        Win32Signal::ApplicabilityFailed => {
            fold.push_terminal(record, Win32Outcome::NotApplicable);
        }
        Win32Signal::RequirementPassed => fold.advance(Win32Phase::Requirements),
        Win32Signal::RequirementFailed => {
            if let Some(name) = &classification.requirement_name {
                fold.failed_requirements.insert(name.clone());
            }
            fold.push_terminal(record, Win32Outcome::RequirementNotMet);
        }
        Win32Signal::DependencyResolved => fold.advance(Win32Phase::Dependencies),
        Win32Signal::DependencyUnresolved => {
            if let Some(dependency) = &classification.dependency_app_id {
                fold.unresolved_dependencies.insert(dependency.clone());
            }
            fold.push_terminal(record, Win32Outcome::DependencyUnresolved);
        }
        Win32Signal::DetectionSatisfied => {
            if !fold.seen_enforcement {
                fold.advance(Win32Phase::PreEnforcementDetection);
                fold.push_terminal(record, Win32Outcome::DetectedBeforeEnforcement);
            } else if fold.installer_succeeded {
                fold.advance(Win32Phase::PostEnforcementDetection);
                fold.push_terminal(record, Win32Outcome::Succeeded);
            }
            // Detected after an installer failure is a contradiction the
            // evidence does not resolve. The reported return code stays the
            // stronger claim; `push_installer_failed_but_detected` surfaces the
            // conflict instead of silently picking a side.
        }
        Win32Signal::DetectionNotSatisfied => {
            if !fold.seen_enforcement {
                fold.advance(Win32Phase::PreEnforcementDetection);
            } else if fold.installer_succeeded {
                fold.push_terminal(record, Win32Outcome::InstalledNotDetected);
            }
        }
        Win32Signal::ContentUnavailable => {
            fold.push_terminal(record, Win32Outcome::ContentUnavailable);
        }
        // A stall is trouble in flight, not a proven outcome: the record stays
        // cited evidence, and neither a phase nor a state is claimed from it.
        Win32Signal::DownloadStarted | Win32Signal::DownloadStalled => {}
        Win32Signal::DownloadCompleted => fold.advance(Win32Phase::Content),
        Win32Signal::DownloadFailed
        | Win32Signal::HashValidationFailed
        | Win32Signal::StagingFailed => {
            fold.push_terminal(record, Win32Outcome::ContentDeliveryFailed);
        }
        Win32Signal::EnforcementStarted => {
            fold.seen_enforcement = true;
            fold.set_pending(Win32Outcome::Enforcing);
        }
        Win32Signal::EnforcementCommandFailed => {
            fold.seen_enforcement = true;
            fold.push_terminal(record, Win32Outcome::EnforcementCommandFailed);
        }
        Win32Signal::InstallerCompleted => {
            fold.seen_enforcement = true;
            apply_installer_completion(fold, record, key, options);
        }
        Win32Signal::RetryScheduled => {
            // A retry is an in-flight marker. It can never erase a proven
            // terminal outcome -- terminal candidates always outrank the
            // pending state -- and it can never mask a failure recorded after
            // it, because the failure is its own candidate.
            fold.set_pending(Win32Outcome::Deferred);
        }
        Win32Signal::ReportSubmitted => {
            fold.advance(Win32Phase::Reporting);
            // The source's own statement that a status upload landed. It
            // clears any reporting failure it is explicitly ordered after.
            fold.report_clearances.push((
                record.artifact_id.clone(),
                record.record_number,
                record
                    .timestamp
                    .as_ref()
                    .and_then(|timestamp| timestamp.normalized_utc.clone()),
            ));
        }
        Win32Signal::ReportFailed => {
            fold.push_terminal(record, Win32Outcome::ReportingFailed);
        }
        Win32Signal::Unclassified => {}
    }
}

fn apply_installer_completion(
    fold: &mut Fold,
    record: &PendingRecord,
    key: &Win32TransactionKey,
    options: &Win32AnalysisOptions,
) {
    let classification = &record.classification;
    let Some(code) = classification.error_code.clone() else {
        // A completion we matched but whose code we could not read cannot claim
        // success or failure. It leaves the deployment enforcing and raises the
        // unknown-vocabulary flag set at framing time.
        fold.unknown_vocabulary = true;
        fold.set_pending(Win32Outcome::Enforcing);
        return;
    };

    let kind = classify_return_code(key, &code, &options.return_codes);
    fold.return_code = Some(code);
    fold.return_code_kind = Some(kind);

    match kind {
        Win32ReturnCodeKind::Success => {
            fold.advance(Win32Phase::Enforcement);
            fold.installer_succeeded = true;
            fold.reboot_required = false;
            fold.push_terminal(record, Win32Outcome::Succeeded);
        }
        Win32ReturnCodeKind::SoftReboot | Win32ReturnCodeKind::HardReboot => {
            fold.advance(Win32Phase::Enforcement);
            fold.installer_succeeded = true;
            fold.reboot_required = true;
            fold.push_terminal(record, Win32Outcome::Succeeded);
        }
        Win32ReturnCodeKind::Retry => {
            fold.set_pending(Win32Outcome::Deferred);
        }
        Win32ReturnCodeKind::Failed | Win32ReturnCodeKind::Unmapped => {
            // An observed installer exit code proves enforcement completed, even
            // when the installer reported failure. Failed phases do not advance,
            // but this is a terminal enforcement result rather than a launch
            // failure.
            fold.advance(Win32Phase::Enforcement);
            fold.reboot_required = false;
            fold.push_terminal(record, Win32Outcome::InstallerReportedFailure);
        }
    }
}

/// Confidence describes how well evidenced the *reduced outcome* is.
///
/// It is not a judgement about the cause: an unmapped return code proves the
/// installer failed just as strongly as a mapped one, and the fact that its
/// meaning is unknown is reported by the finding, not by demoting the outcome.
///
/// `deployment_type_observed` is true only when a record stated the deployment
/// type; a key completed by inference is deliberately excluded (ADR-001).
///
/// Capped artifacts: a complete framed record inside a truncated artifact is
/// authentic evidence — truncation removes records, it does not corrupt the
/// ones that framed, and fragments are excluded at framing time. A capped
/// artifact may therefore still prove a terminal outcome, including
/// `Succeeded`. What it can never do is prove one at High confidence: the
/// missing tail is a coverage gap, `degraded_coverage` is true whenever any
/// artifact is capped, and the demotion below applies (ADR-001: coverage gaps
/// cannot raise confidence; non-assessable evidence is a different case and
/// never reaches a terminal outcome at all).
fn confidence_for(
    outcome: Win32Outcome,
    deployment_type_observed: bool,
    unknown_vocabulary: bool,
    degraded_coverage: bool,
    corroborated: bool,
) -> Win32Confidence {
    if unknown_vocabulary || !outcome.is_terminal() {
        return Win32Confidence::Low;
    }
    let base = if deployment_type_observed || corroborated {
        Win32Confidence::High
    } else {
        Win32Confidence::Medium
    };
    if degraded_coverage && base == Win32Confidence::High {
        Win32Confidence::Medium
    } else {
        base
    }
}

/// The smallest artifact that would advance this diagnosis.
fn next_evidence_request(outcome: Win32Outcome) -> Option<String> {
    let request = match outcome {
        Win32Outcome::InsufficientEvidence => {
            "AppWorkload.log and IntuneManagementExtension.log covering this app's check-in"
        }
        Win32Outcome::Assigned => "AppWorkload.log covering the applicability and detection pass",
        Win32Outcome::Enforcing => "AppWorkload.log rotation containing the enforcement result",
        Win32Outcome::Deferred => "the AppWorkload.log rotation covering the next retry window",
        Win32Outcome::ContentUnavailable | Win32Outcome::ContentDeliveryFailed => {
            "AppWorkload.log content-download records and the Delivery Optimization log"
        }
        Win32Outcome::EnforcementCommandFailed => {
            "AppWorkload.log records around the failed launch, and the install command line"
        }
        Win32Outcome::InstallerReportedFailure => {
            "the installer-native log named by the install output file record"
        }
        Win32Outcome::InstalledNotDetected => {
            "AppActionProcessor.log detection-rule evaluation for this app"
        }
        Win32Outcome::ReportingFailed => {
            "IntuneManagementExtension.log records for the status upload attempt"
        }
        Win32Outcome::Conflicting => {
            "a single capture containing every AppWorkload.log rotation, so the conflicting \
             check-ins can be ordered by one source"
        }
        Win32Outcome::RequirementNotMet => "AppActionProcessor.log requirement-rule evaluation",
        Win32Outcome::DependencyUnresolved => {
            "AppWorkload.log records for the dependency app's own deployment"
        }
        Win32Outcome::NotTargeted
        | Win32Outcome::NotApplicable
        | Win32Outcome::DetectedBeforeEnforcement
        | Win32Outcome::Succeeded => return None,
    };
    Some(request.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const OTHER: &str = "22222222-3333-4444-8555-666666666666";
    const DT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    /// One framed CCM record. The explicit `+000` offset keeps ordering and the
    /// normalized UTC value independent of the machine running the test.
    fn record(message: &str) -> String {
        record_on_thread(message, 5)
    }

    fn record_on_thread(message: &str, thread: u32) -> String {
        record_at("10:00:00.000+000", "7-31-2026", message, thread)
    }

    /// A record at an explicit time. Passing a time without an offset yields a
    /// record whose UTC form is untrusted, which is how offset-less evidence is
    /// simulated.
    fn record_at(time: &str, date: &str, message: &str, thread: u32) -> String {
        format!(
            "<![LOG[{message}]LOG]!><time=\"{time}\" date=\"{date}\" \
             component=\"Win32App\" context=\"\" type=\"1\" thread=\"{thread}\" file=\"\">\n"
        )
    }

    fn workload(records: &[String]) -> Win32SourceInput {
        Win32SourceInput::captured("aw", "AppWorkload.log", records.concat())
    }

    fn only_transaction(analysis: &Win32Analysis) -> &Win32Transaction {
        assert_eq!(
            analysis.transactions.len(),
            1,
            "expected exactly one transaction, got {:?}",
            analysis
                .transactions
                .iter()
                .map(|transaction| &transaction.key)
                .collect::<Vec<_>>()
        );
        &analysis.transactions[0]
    }

    #[test]
    fn a_complete_run_reduces_to_succeeded_at_the_reporting_phase() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}, intent = Required")),
            record(&format!("[Win32App] app with id: {APP} is applicable")),
            record(&format!("[Win32App] Requirement rules check passed for app with id: {APP}")),
            record(&format!("[Win32App] Detection state for app with id: {APP} = Not Detected")),
            record(&format!("[Win32App] Download completed for app with id: {APP}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
            record(&format!("[Win32App] Detection state for app with id: {APP} = Detected")),
            record(&format!("[Win32App] App status report was sent to service successfully for app with id: {APP}")),
        ])]);

        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
        assert_eq!(
            transaction.last_confirmed_phase,
            Some(Win32Phase::Reporting)
        );
        // Only AppWorkload.log was supplied; the other two expected primary
        // artifacts (IntuneManagementExtension.log, AppActionProcessor.log) are
        // absent, so coverage is degraded and confidence is Medium, not High.
        assert_eq!(transaction.confidence, Win32Confidence::Medium);
        assert_eq!(transaction.next_evidence_request, None);
    }

    #[test]
    fn an_unmapped_return_code_is_a_failure_whose_meaning_is_not_asserted() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Installation is done for app with id: {APP}, exit code: 0x80070643"
            )),
        ])]);

        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::InstallerReportedFailure);
        assert_eq!(
            transaction.return_code_kind,
            Some(Win32ReturnCodeKind::Unmapped)
        );
        assert_eq!(
            transaction
                .return_code
                .as_ref()
                .map(|code| code.raw.as_str()),
            Some("0x80070643")
        );
    }

    #[test]
    fn a_documented_reboot_code_is_success_with_a_reboot_not_a_failure() {
        // The whole point of the return-code table: a nonzero code is not
        // automatically a failed deployment.
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Installation is done for app with id: {APP}, exit code: 3010"
            )),
        ])]);

        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
        assert!(transaction.reboot_required);
    }

    #[test]
    fn a_caller_supplied_table_overrides_the_defaults() {
        let options = Win32AnalysisOptions {
            return_codes: vec![Win32ReturnCodeMapping {
                app_id: APP.to_owned(),
                deployment_type_id: None,
                code: 1603,
                kind: Win32ReturnCodeKind::Success,
            }],
            ..Win32AnalysisOptions::default()
        };
        let analysis = analyze_win32_bundle_with(
            &[workload(&[
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            ])],
            &options,
        );
        assert_eq!(only_transaction(&analysis).outcome, Win32Outcome::Succeeded);
    }

    #[test]
    fn a_retry_after_a_proven_failure_does_not_erase_it() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!("[Win32App] Hash mismatch for app with id: {APP}")),
            record(&format!(
                "[Win32App] Will retry app with id: {APP} at the next check-in"
            )),
        ])]);
        assert_eq!(
            only_transaction(&analysis).outcome,
            Win32Outcome::ContentDeliveryFailed
        );
    }

    #[test]
    fn a_retry_before_any_terminal_outcome_leaves_the_deployment_deferred() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Will retry app with id: {APP} at the next check-in"
            )),
        ])]);
        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Deferred);
        assert_eq!(transaction.confidence, Win32Confidence::Low);
    }

    #[test]
    fn a_block_naming_two_apps_refuses_to_spread_a_key() {
        // Both records named their own app, so both stay keyed to themselves and
        // neither inherits. A third, unkeyed record in the same block adopts
        // nothing.
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}"
            )),
            record(&format!("[Win32App] app with id: {OTHER} is applicable")),
            record("[Win32App] Installation is done, exit code: 1603"),
        ])]);

        assert_eq!(analysis.transactions.len(), 2);
        assert_eq!(
            analysis.unkeyed_observations,
            vec!["aw:3".to_owned()],
            "the unkeyed completion must not terminate either deployment"
        );
        for transaction in &analysis.transactions {
            assert_ne!(transaction.outcome, Win32Outcome::InstallerReportedFailure);
        }
    }

    #[test]
    fn an_unkeyed_thread_cannot_terminate_a_deployment_on_another_thread() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record_on_thread(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"), 5),
            record_on_thread(&format!("[Win32App] Install command line: setup.exe /quiet for app with id: {APP}"), 5),
            record_on_thread("[Win32App] Installation is done, exit code: 1603", 9),
        ])]);
        assert_eq!(only_transaction(&analysis).outcome, Win32Outcome::Enforcing);
        assert_eq!(analysis.unkeyed_observations, vec!["aw:3".to_owned()]);
    }

    #[test]
    fn an_unmatched_rotation_tail_cannot_create_a_transaction_event() {
        let mut body = record(&format!(
            "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
        ));
        // A record the rotation cut in half: no closing marker, so no attributes.
        body.push_str(&format!(
            "<![LOG[[Win32App] Installation is done for app with id: {APP}, exit code: 1603"
        ));

        let analysis = analyze_win32_bundle(&[workload(&[body])]);
        assert_eq!(analysis.coverage.fragment_records, 1);
        assert_eq!(only_transaction(&analysis).outcome, Win32Outcome::Assigned);
    }

    #[test]
    fn a_supplemental_installer_artifact_joins_only_when_a_keyed_record_names_it() {
        let referenced = analyze_win32_bundle(&[
            workload(&[
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Install output file: D:\\IMECache\\Contoso-Setup.msi.log for app with id: {APP}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            ]),
            Win32SourceInput::captured("msi", "Contoso-Setup.msi.log", "MSI (s) install failed"),
        ]);
        assert_eq!(
            only_transaction(&referenced).corroborating_artifacts,
            vec!["msi".to_owned()]
        );
        assert!(referenced.coverage.unlinked_installer_artifacts.is_empty());

        let unreferenced = analyze_win32_bundle(&[
            workload(&[
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            ]),
            Win32SourceInput::captured("msi", "Contoso-Setup.msi.log", "MSI (s) install failed"),
        ]);
        assert!(only_transaction(&unreferenced)
            .corroborating_artifacts
            .is_empty());
        assert_eq!(
            unreferenced.coverage.unlinked_installer_artifacts,
            vec!["msi".to_owned()],
            "an artifact nothing referenced must stay visible, never merged on time"
        );
    }

    #[test]
    fn expected_artifacts_the_caller_never_mentioned_still_get_a_coverage_entry() {
        let analysis = analyze_win32_bundle(&[workload(&[record(&format!(
            "[Win32App] Processing app policy for app with id: {APP}"
        ))])]);
        let missing: Vec<&str> = analysis
            .coverage
            .artifacts
            .iter()
            .filter(|entry| entry.status == IntuneArtifactStatus::Missing)
            .map(|entry| entry.artifact_id.as_str())
            .collect();
        assert_eq!(
            missing,
            vec![
                "expected:IntuneManagementExtension.log",
                "expected:AppActionProcessor.log"
            ]
        );
    }

    #[test]
    fn a_declared_unreadable_artifact_reports_its_own_coverage_status() {
        let analysis = analyze_win32_bundle(&[
            workload(&[record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}"
            ))]),
            Win32SourceInput::unreadable(
                "ime",
                "IntuneManagementExtension.log",
                IntuneAccessState::PermissionDenied,
            ),
        ]);
        let entry = analysis
            .coverage
            .artifacts
            .iter()
            .find(|entry| entry.artifact_id == "ime")
            .expect("declared artifact must appear in coverage");
        assert_eq!(entry.status, IntuneArtifactStatus::PermissionDenied);
    }

    #[test]
    fn reporting_failure_preserves_the_local_outcome_underneath_it() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
            record(&format!("[Win32App] Failed to send app status to service for app with id: {APP}, error code: 0x80072EE2")),
        ])]);
        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::ReportingFailed);
        assert_eq!(transaction.local_outcome, Some(Win32Outcome::Succeeded));
    }

    // ── Coverage honesty (ADR-001) ─────────────────────────────────────────

    /// A minimal confirmed record for an expected artifact, so a test can hold
    /// coverage complete while it varies one artifact of interest.
    fn confirmed_filler(artifact_id: &str, file_name: &str) -> Win32SourceInput {
        Win32SourceInput::captured(
            artifact_id,
            file_name,
            record("[Win32App] Cleaning up the staging directory"),
        )
    }

    #[test]
    fn an_empty_expected_artifact_does_not_close_its_coverage_gap() {
        // A zero-byte AppWorkload.log proves nothing about the phases it alone
        // records. Its file name must not satisfy the expected-artifact check,
        // and confidence must stay degraded (ADR-001: coverage gaps cannot
        // raise confidence).
        let analysis = analyze_win32_bundle(&[
            Win32SourceInput::captured(
                "ime",
                "IntuneManagementExtension.log",
                [
                    record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                    record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
                ]
                .concat(),
            ),
            Win32SourceInput::captured("aw", "AppWorkload.log", ""),
            confirmed_filler("aap", "AppActionProcessor.log"),
        ]);

        assert!(
            analysis
                .coverage
                .artifacts
                .iter()
                .any(|entry| entry.artifact_id == "expected:AppWorkload.log"
                    && entry.status == IntuneArtifactStatus::Missing),
            "an empty artifact must leave the expected-artifact gap open: {:?}",
            analysis
                .coverage
                .artifacts
                .iter()
                .map(|entry| (&entry.artifact_id, &entry.status))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            only_transaction(&analysis).confidence,
            Win32Confidence::Medium,
            "degraded coverage must cap confidence"
        );
    }

    #[test]
    fn a_content_misclassified_artifact_does_not_close_its_coverage_gap() {
        // A file named AppWorkload.log whose records did not confirm it is not
        // usable AppWorkload evidence; the gap and the degradation must both
        // survive.
        let unrelated = "<![LOG[unrelated CCM traffic]LOG]!><time=\"10:00:00.000+000\" \
             date=\"7-31-2026\" component=\"CcmExec\" context=\"\" type=\"1\" thread=\"5\" \
             file=\"\">\n"
            .to_owned();
        let analysis = analyze_win32_bundle(&[
            Win32SourceInput::captured(
                "ime",
                "IntuneManagementExtension.log",
                [
                    record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                    record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
                ]
                .concat(),
            ),
            Win32SourceInput::captured("aw", "AppWorkload.log", unrelated),
            confirmed_filler("aap", "AppActionProcessor.log"),
        ]);

        assert!(analysis
            .coverage
            .artifacts
            .iter()
            .any(|entry| entry.artifact_id == "expected:AppWorkload.log"));
        assert_eq!(only_transaction(&analysis).confidence, Win32Confidence::Medium);
    }

    #[test]
    fn a_declared_unreadable_expected_artifact_still_closes_the_synthesized_gap() {
        // The caller-declared entry already expresses this gap with better
        // fidelity (its own artifact id and access state), and it degrades
        // coverage by itself; a second synthesized entry would double-count it.
        let analysis = analyze_win32_bundle(&[
            confirmed_filler("ime", "IntuneManagementExtension.log"),
            Win32SourceInput::unreadable(
                "aw",
                "AppWorkload.log",
                IntuneAccessState::PermissionDenied,
            ),
            confirmed_filler("aap", "AppActionProcessor.log"),
        ]);
        assert!(!analysis
            .coverage
            .artifacts
            .iter()
            .any(|entry| entry.artifact_id == "expected:AppWorkload.log"));
    }

    #[test]
    fn a_capped_artifact_proves_a_terminal_outcome_only_at_demoted_confidence() {
        // Decision (ADR-001, documented at confidence_for): framed records in
        // a truncated artifact are authentic evidence, so the terminal outcome
        // stands -- but the missing tail is a coverage gap, so High is
        // unreachable.
        let mut capped = workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
        ]);
        capped.access_state = IntuneAccessState::Capped;
        let analysis = analyze_win32_bundle(&[
            capped,
            confirmed_filler("ime", "IntuneManagementExtension.log"),
            confirmed_filler("aap", "AppActionProcessor.log"),
        ]);

        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
        assert_eq!(
            transaction.confidence,
            Win32Confidence::Medium,
            "a capped artifact must cap confidence below High"
        );
    }

    #[test]
    fn a_deployment_type_scoped_return_code_entry_wins_over_an_app_wide_one() {
        let options = Win32AnalysisOptions {
            return_codes: vec![
                Win32ReturnCodeMapping {
                    app_id: APP.to_owned(),
                    deployment_type_id: None,
                    code: 7,
                    kind: Win32ReturnCodeKind::Failed,
                },
                Win32ReturnCodeMapping {
                    app_id: APP.to_owned(),
                    deployment_type_id: Some(DT.to_owned()),
                    code: 7,
                    kind: Win32ReturnCodeKind::Success,
                },
            ],
            ..Win32AnalysisOptions::default()
        };
        let analysis = analyze_win32_bundle_with(
            &[workload(&[
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 7")),
            ])],
            &options,
        );
        assert_eq!(only_transaction(&analysis).outcome, Win32Outcome::Succeeded);
    }

    #[test]
    fn metadata_scoped_to_another_deployment_type_never_labels_this_one() {
        let options = Win32AnalysisOptions {
            metadata: vec![Win32AppMetadata {
                app_id: APP.to_owned(),
                display_name: Some("Other deployment type".to_owned()),
                deployment_type_id: Some(OTHER.to_owned()),
                ..Win32AppMetadata::default()
            }],
            ..Win32AnalysisOptions::default()
        };
        let analysis = analyze_win32_bundle_with(
            &[workload(&[record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            ))])],
            &options,
        );
        assert_eq!(only_transaction(&analysis).display_name, None);
    }

    #[test]
    fn an_inferred_deployment_type_cannot_promote_confidence_to_high() {
        // The System-context transaction only has a deployment type because
        // reconcile_partial_keys inferred it from bundle-wide uniqueness. An
        // inferred key component is not observed evidence, so the base
        // confidence stays Medium (ADR-001) even with full coverage.
        let analysis = analyze_win32_bundle(&[
            Win32SourceInput::captured(
                "ime",
                "IntuneManagementExtension.log",
                record(&format!(
                    "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT} in user context"
                )),
            ),
            Win32SourceInput::captured(
                "aw",
                "AppWorkload.log",
                record(&format!(
                    "[Win32App] Installation is done for app with id: {APP}, exit code: 0 in system context"
                )),
            ),
            confirmed_filler("aap", "AppActionProcessor.log"),
        ]);

        let inferred = analysis
            .transactions
            .iter()
            .find(|transaction| {
                transaction.key.execution_context == Win32ExecutionContext::System
            })
            .expect("the system-context transaction exists");
        assert_eq!(
            inferred.key.deployment_type_id.as_deref(),
            Some(DT),
            "the inference itself still completes the key"
        );
        assert_eq!(
            inferred.confidence,
            Win32Confidence::Medium,
            "an inferred key component must not count as an observed one"
        );

        let observed = analysis
            .transactions
            .iter()
            .find(|transaction| transaction.key.execution_context == Win32ExecutionContext::User)
            .expect("the user-context transaction exists");
        assert_eq!(observed.confidence, Win32Confidence::Low,
            "non-terminal outcome stays low regardless");
    }

    // ── Terminal precedence, retry linkage, and order independence ─────────
    //
    // These pin the ADR-003 shape the Store pilot proved out: caller vector
    // order is an acquisition detail, terminal statements are equal-authority
    // candidates ordered only by a source's own record numbers or by trusted
    // timestamps, and an unresolved contradiction stays conservative.

    #[test]
    fn a_linked_later_success_supersedes_a_failure_but_the_failure_survives() {
        // Two enforcement cycles in ONE artifact: the log's own record order is
        // explicit retry linkage, so the later success is the outcome -- and the
        // proven failure must survive as a superseded entry, never vanish.
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
        ])]);

        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
        assert_eq!(
            transaction.return_code.as_ref().map(|code| code.raw.as_str()),
            Some("0")
        );
        assert_eq!(transaction.superseded_failures.len(), 1);
        let superseded = &transaction.superseded_failures[0];
        assert_eq!(superseded.outcome, Win32Outcome::InstallerReportedFailure);
        assert_eq!(
            superseded.return_code.as_ref().map(|code| code.raw.as_str()),
            Some("1603")
        );
        assert!(!superseded.evidence.is_empty());
    }

    #[test]
    fn an_unorderable_success_in_another_artifact_cannot_overwrite_a_failure() {
        // Same trusted timestamp in two different artifacts: neither record can
        // be proven later than the other, so per ADR-003 the contradiction is
        // reported instead of an arbitrary winner -- in either input order.
        let failure = Win32SourceInput::captured(
            "aw-old",
            "AppWorkload-1.log",
            [
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            ]
            .concat(),
        );
        let success = Win32SourceInput::captured(
            "aw-new",
            "AppWorkload.log",
            [
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
            ]
            .concat(),
        );

        for inputs in [
            vec![failure.clone(), success.clone()],
            vec![success, failure],
        ] {
            let analysis = analyze_win32_bundle(&inputs);
            let transaction = only_transaction(&analysis);
            assert_eq!(
                transaction.outcome,
                Win32Outcome::Conflicting,
                "an unordered contradiction must stay conservative"
            );
            assert_eq!(transaction.return_code, None);
            assert_eq!(transaction.confidence, Win32Confidence::Low);
        }
    }

    #[test]
    fn offsetless_records_across_artifacts_cannot_be_sequenced_either() {
        // Without an embedded offset the UTC form is the parsing machine's
        // opinion, not evidence, so two artifacts stay unordered.
        let failure = Win32SourceInput::captured(
            "aw-old",
            "AppWorkload-1.log",
            [
                record_at("10:00:00.000", "7-27-2026", &format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"), 5),
                record_at("10:00:01.000", "7-27-2026", &format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603"), 5),
            ]
            .concat(),
        );
        let success = Win32SourceInput::captured(
            "aw-new",
            "AppWorkload.log",
            [
                record_at("10:00:00.000", "7-31-2026", &format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"), 5),
                record_at("10:00:01.000", "7-31-2026", &format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0"), 5),
            ]
            .concat(),
        );

        for inputs in [
            vec![failure.clone(), success.clone()],
            vec![success, failure],
        ] {
            let analysis = analyze_win32_bundle(&inputs);
            assert_eq!(
                only_transaction(&analysis).outcome,
                Win32Outcome::Conflicting
            );
        }
    }

    #[test]
    fn a_trusted_strictly_later_cycle_in_another_artifact_is_explicit_linkage() {
        // Both artifacts state their own offsets and do not overlap in time, so
        // real time orders them (ADR-003 permits timestamps whose semantics are
        // known). The later success wins; the Monday failure survives as a
        // superseded entry instead of silently vanishing.
        let monday = Win32SourceInput::captured(
            "aw-old",
            "AppWorkload-1.log",
            [
                record_at("16:03:00.000+000", "7-27-2026", &format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"), 5),
                record_at("16:03:10.000+000", "7-27-2026", &format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603"), 5),
            ]
            .concat(),
        );
        let friday = Win32SourceInput::captured(
            "aw-new",
            "AppWorkload.log",
            [
                record_at("09:00:00.000+000", "7-31-2026", &format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"), 5),
                record_at("09:00:10.000+000", "7-31-2026", &format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0"), 5),
            ]
            .concat(),
        );

        for inputs in [
            vec![monday.clone(), friday.clone()],
            vec![friday, monday],
        ] {
            let analysis = analyze_win32_bundle(&inputs);
            let transaction = only_transaction(&analysis);
            assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
            assert_eq!(transaction.superseded_failures.len(), 1);
            assert_eq!(
                transaction.superseded_failures[0].outcome,
                Win32Outcome::InstallerReportedFailure
            );
        }
    }

    #[test]
    fn a_report_submitted_after_a_reporting_failure_clears_it() {
        // The same artifact's own record order proves the retry upload landed,
        // so the transient failure must not remain the outcome.
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
            record(&format!("[Win32App] Failed to send app status to service for app with id: {APP}, error code: 0x80072EE2")),
            record(&format!("[Win32App] App status report was sent to service successfully for app with id: {APP}")),
        ])]);
        let transaction = only_transaction(&analysis);
        assert_eq!(transaction.outcome, Win32Outcome::Succeeded);
        assert_eq!(transaction.local_outcome, None);
        assert_eq!(
            transaction.last_confirmed_phase,
            Some(Win32Phase::Reporting)
        );
    }

    #[test]
    fn a_scheduled_retry_cannot_mask_a_later_content_failure() {
        let analysis = analyze_win32_bundle(&[workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Will retry app with id: {APP} at the next check-in")),
            record(&format!("[Win32App] Hash mismatch for app with id: {APP}")),
        ])]);
        assert_eq!(
            only_transaction(&analysis).outcome,
            Win32Outcome::ContentDeliveryFailed,
            "a deferral noted before the failure must not outrank the failure"
        );
    }

    #[test]
    fn permuting_the_input_vector_changes_no_conclusion() {
        let ime = Win32SourceInput::captured(
            "ime",
            "IntuneManagementExtension.log",
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}, intent = Required"
            )),
        );
        let aw = Win32SourceInput::captured(
            "aw",
            "AppWorkload.log",
            [
                record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
                record(&format!("[Win32App] Install output file: D:\\IMECache\\Contoso-Setup.msi.log for app with id: {APP}")),
                record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 1603")),
            ]
            .concat(),
        );
        let msi = Win32SourceInput::captured("msi", "Contoso-Setup.msi.log", "MSI (s) failed");
        let bundle = vec![ime, aw, msi];

        let baseline = analyze_win32_bundle(&bundle);
        let mut reversed = bundle.clone();
        reversed.reverse();
        let mut rotated = bundle.clone();
        rotated.rotate_left(1);

        for permutation in [reversed, rotated] {
            let permuted = analyze_win32_bundle(&permutation);
            assert_eq!(
                serde_json::to_value(&permuted.transactions).expect("serialize"),
                serde_json::to_value(&baseline.transactions).expect("serialize"),
                "ADR-003: caller vector order must not change any conclusion"
            );
        }
    }

    #[test]
    fn duplicating_an_artifact_changes_no_conclusion() {
        let aw = workload(&[
            record(&format!("[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}")),
            record(&format!("[Win32App] Installation is done for app with id: {APP}, exit code: 0")),
        ]);
        let mut copy = aw.clone();
        copy.artifact_id = "aw-copy".to_owned();
        copy.file_name = "AppWorkload-1.log".to_owned();

        let baseline = analyze_win32_bundle(std::slice::from_ref(&aw));
        let duplicated = analyze_win32_bundle(&[aw, copy]);

        let transaction = only_transaction(&duplicated);
        assert_eq!(
            transaction.outcome,
            baseline.transactions[0].outcome,
            "a re-collected copy of the same evidence adds nothing"
        );
        assert_eq!(transaction.confidence, baseline.transactions[0].confidence);
        assert!(transaction.superseded_failures.is_empty());
    }

    #[test]
    fn observations_carry_the_shared_evidence_envelope() {
        let analysis = analyze_win32_bundle(&[workload(&[record(&format!(
            "[Win32App] Processing app policy for app with id: {APP}"
        ))])]);
        let observation = &analysis.observations[0];
        assert_eq!(observation.context.evidence_ref.evidence_id, "aw:1");
        assert_eq!(observation.context.evidence_ref.source_artifact_id, "aw");
        assert_eq!(observation.context.parse_state, IntuneParseState::Parsed);
        assert_eq!(
            observation.context.access_state,
            IntuneAccessState::Available
        );
        assert_eq!(
            observation.context.sensitivity,
            IntuneSensitivity::Sensitive
        );
        assert_eq!(
            observation
                .context
                .source_timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.original_offset.as_deref()),
            Some("+00:00")
        );
    }
}
