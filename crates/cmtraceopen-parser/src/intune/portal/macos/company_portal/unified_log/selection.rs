//! The conservative source-selection predicate.
//!
//! Selection answers one question: *is this record Company Portal evidence?*
//! It is deliberately stricter than the `log show` predicate that collected the
//! capture, and it is evaluated only over structured fields.
//!
//! # Rules
//!
//! 1. A record whose `(process, subsystem)` pair is in [`PORTAL_VERIFIED_SOURCES`]
//!    is selected.
//! 2. A record from a capture-predicate process whose subsystem is missing or
//!    unverified is **not** selected on its own — a process name alone is not
//!    sufficient — but is selected if it shares an *explicit* activity,
//!    signpost, trace, request, or correlation identifier with a record already
//!    selected under rule 1. That is a documented structural relationship, not
//!    a coincidence.
//! 3. The literal text `CompanyPortal` (or `Intune`) inside a free-text message
//!    body is never a selection signal. Any process may write any string.
//! 4. Everything else is unrelated.
//!
//! Non-selection is recorded as coverage, never as a silent drop.

use std::collections::BTreeSet;

use super::models::*;
use super::schema::*;

/// Category values whose meaning is proven, mapped to an evidence class.
///
/// Compared ASCII-case-insensitively against the record's `category`. An
/// unrecognised category still yields evidence, but as
/// [`PortalUnifiedLogEvidenceKind::Unclassified`] with reduced confidence.
const CATEGORY_KINDS: &[(&str, PortalUnifiedLogEvidenceKind)] = &[
    ("startup", PortalUnifiedLogEvidenceKind::ProcessStartup),
    ("launch", PortalUnifiedLogEvidenceKind::ProcessStartup),
    ("lifecycle", PortalUnifiedLogEvidenceKind::ProcessStartup),
    (
        "authentication",
        PortalUnifiedLogEvidenceKind::Authentication,
    ),
    ("auth", PortalUnifiedLogEvidenceKind::Authentication),
    ("sso", PortalUnifiedLogEvidenceKind::Authentication),
    ("msal", PortalUnifiedLogEvidenceKind::Authentication),
    ("signin", PortalUnifiedLogEvidenceKind::Authentication),
    (
        "enrollment",
        PortalUnifiedLogEvidenceKind::EnrollmentProfile,
    ),
    ("profile", PortalUnifiedLogEvidenceKind::EnrollmentProfile),
    ("mdm", PortalUnifiedLogEvidenceKind::EnrollmentProfile),
    ("sync", PortalUnifiedLogEvidenceKind::SyncCompliance),
    ("compliance", PortalUnifiedLogEvidenceKind::SyncCompliance),
    ("checkin", PortalUnifiedLogEvidenceKind::SyncCompliance),
    ("policy", PortalUnifiedLogEvidenceKind::SyncCompliance),
    ("app", PortalUnifiedLogEvidenceKind::AppAction),
    ("appinstall", PortalUnifiedLogEvidenceKind::AppAction),
    ("catalog", PortalUnifiedLogEvidenceKind::AppAction),
    ("device", PortalUnifiedLogEvidenceKind::DeviceAction),
    ("deviceaction", PortalUnifiedLogEvidenceKind::DeviceAction),
    ("remoteaction", PortalUnifiedLogEvidenceKind::DeviceAction),
    ("network", PortalUnifiedLogEvidenceKind::NetworkRequest),
    ("http", PortalUnifiedLogEvidenceKind::NetworkRequest),
    ("service", PortalUnifiedLogEvidenceKind::NetworkRequest),
    ("graph", PortalUnifiedLogEvidenceKind::NetworkRequest),
    ("diagnostics", PortalUnifiedLogEvidenceKind::Diagnostics),
    ("logging", PortalUnifiedLogEvidenceKind::Diagnostics),
    ("telemetry", PortalUnifiedLogEvidenceKind::Diagnostics),
];

/// Maps a category value onto a proven evidence class, if one is known.
pub fn classify_category(category: Option<&str>) -> Option<PortalUnifiedLogEvidenceKind> {
    let category = category?.trim();
    CATEGORY_KINDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(category))
        .map(|(_, kind)| kind.clone())
}

/// Evaluates rule 1, 3, and 4 for a single record, with no cross-record context.
pub fn classify_record(record: &PortalUnifiedLogRecord) -> PortalSelection {
    let subsystem = record.subsystem.as_deref().unwrap_or_default();

    if let Some(source) = verified_source(&record.process, subsystem) {
        return PortalSelection {
            selected: true,
            reason: PortalSelectionReason::VerifiedProcessAndSubsystem,
            predicate_version: PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION,
            matched_process: Some(source.process.to_string()),
            matched_subsystem: Some(source.subsystem.to_string()),
        };
    }

    if is_capture_process(&record.process) {
        return PortalSelection {
            selected: false,
            reason: PortalSelectionReason::ProcessOnlyInsufficient,
            predicate_version: PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION,
            matched_process: Some(record.process.clone()),
            matched_subsystem: None,
        };
    }

    let reason = if mentions_company_portal(&record.event_message.value) {
        PortalSelectionReason::MessageMentionOnlyIgnored
    } else {
        PortalSelectionReason::UnrelatedSource
    };

    PortalSelection {
        selected: false,
        reason,
        predicate_version: PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION,
        matched_process: None,
        matched_subsystem: None,
    }
}

/// True when free text merely names Company Portal or Intune.
///
/// Used only to explain *why* a record was rejected. It never selects.
fn mentions_company_portal(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("companyportal")
        || lowered.contains("company portal")
        || lowered.contains("intune")
}

/// Namespace an identifier belongs to.
///
/// Identifiers only relate when they are the same kind. Flattening every field
/// into one untyped set let a candidate's `trace_id` match an anchor's
/// `activity_id` and be selected as activity-linked although the two share no
/// relationship in any single namespace. That is exactly the coincidence rule 2
/// says it does not accept, and it is not theoretical: the committed fixtures
/// already use the same `0x1a2b` shape for both activity and signpost ids.
/// `correlation.rs` pairs same-kind fields only, and this now matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PortalIdentifierKind {
    /// `activity_id` and `parent_activity_id` share one namespace on purpose: a
    /// child record carrying its parent's activity id is a real structural link.
    Activity,
    Signpost,
    Trace,
    Request,
    Correlation,
}

/// Explicit identifiers a record contributes to the activity graph, each tagged
/// with the namespace it came from.
fn explicit_ids(record: &PortalUnifiedLogRecord) -> Vec<(PortalIdentifierKind, &str)> {
    let activity = &record.activity;
    [
        (
            PortalIdentifierKind::Activity,
            activity.activity_id.as_deref(),
        ),
        (
            PortalIdentifierKind::Activity,
            activity.parent_activity_id.as_deref(),
        ),
        (
            PortalIdentifierKind::Signpost,
            activity.signpost_id.as_deref(),
        ),
        (PortalIdentifierKind::Trace, activity.trace_id.as_deref()),
        (
            PortalIdentifierKind::Request,
            activity.request_id.as_deref(),
        ),
        (
            PortalIdentifierKind::Correlation,
            activity.correlation_id.as_deref(),
        ),
    ]
    .into_iter()
    .filter_map(|(kind, id)| id.map(|id| (kind, id)))
    .collect()
}

/// Evaluates selection across the whole capture, applying rule 2.
///
/// Returns one verdict per record, in the input order.
pub fn classify_records(records: &[PortalUnifiedLogRecord]) -> Vec<PortalSelection> {
    let mut verdicts: Vec<PortalSelection> = records.iter().map(classify_record).collect();

    // Identifiers reachable from records selected on their own merits.
    let mut anchor_ids: BTreeSet<(PortalIdentifierKind, &str)> = BTreeSet::new();
    for (record, verdict) in records.iter().zip(verdicts.iter()) {
        if verdict.reason == PortalSelectionReason::VerifiedProcessAndSubsystem {
            anchor_ids.extend(explicit_ids(record));
        }
    }

    if anchor_ids.is_empty() {
        return verdicts;
    }

    for (record, verdict) in records.iter().zip(verdicts.iter_mut()) {
        if verdict.reason != PortalSelectionReason::ProcessOnlyInsufficient {
            continue;
        }
        if explicit_ids(record)
            .iter()
            .any(|id| anchor_ids.contains(id))
        {
            verdict.selected = true;
            verdict.reason = PortalSelectionReason::ActivityLinkedToSelected;
            verdict.matched_subsystem = record.subsystem.clone();
        }
    }

    verdicts
}

/// Human-readable explanation of a rejection, used as coverage detail.
pub fn rejection_detail(record: &PortalUnifiedLogRecord, selection: &PortalSelection) -> String {
    match selection.reason {
        PortalSelectionReason::ProcessOnlyInsufficient => format!(
            "record `{}` is from capture process `{}` but subsystem {} is not a verified \
             Company Portal source and no explicit activity links it to one; \
             a process name alone is not sufficient",
            record.record_id,
            record.process,
            record
                .subsystem
                .as_deref()
                .map(|s| format!("`{s}`"))
                .unwrap_or_else(|| "(absent)".to_string()),
        ),
        PortalSelectionReason::MessageMentionOnlyIgnored => format!(
            "record `{}` is from unrelated process `{}`; the message body names Company Portal \
             but free text is never a selection signal",
            record.record_id, record.process,
        ),
        PortalSelectionReason::UnrelatedSource => format!(
            "record `{}` is from unrelated process `{}` with subsystem {}",
            record.record_id,
            record.process,
            record
                .subsystem
                .as_deref()
                .map(|s| format!("`{s}`"))
                .unwrap_or_else(|| "(absent)".to_string()),
        ),
        PortalSelectionReason::VerifiedProcessAndSubsystem
        | PortalSelectionReason::ActivityLinkedToSelected => format!(
            "record `{}` was selected; no rejection applies",
            record.record_id
        ),
    }
}
