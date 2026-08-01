//! Findings derived from a reduced Android diagnostic bundle.
//!
//! Every rule states something about the *import*, never about the device. That
//! restraint is forced by the state of the source contract: with no verified
//! artifact layout, nothing here has read a device fact, and a rule that
//! claimed one would be inventing it.
//!
//! Two invariants hold across the whole file and are asserted in this leaf's
//! tests:
//!
//! * every finding cites at least one evidence reference or one coverage-gap
//!   identifier, per [`IntuneFinding::is_evidence_backed`];
//! * no finding text interpolates member content, a path, an identity, or a
//!   correlation identifier. Findings are built from counts and vocabulary
//!   tokens only, which is what lets the redacted export projection pass them
//!   through untouched.

use serde::Serialize;

use super::contract::{
    verified_contract_count, AndroidManagementMode, AndroidUploadOutcome,
    AndroidVerboseLoggingState,
};
use super::models::{
    AndroidBundleClassification, AndroidDiagnosticMember, AndroidDiagnosticsSnapshot,
    AndroidMemberClassification,
};
use crate::intune::evidence::{
    IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
    IntuneTimestampKind,
};

/// Derive every finding the snapshot supports, in a stable presentation order.
///
/// The order is the call order below: what the bundle *is*, then what is wrong
/// with it, then what limits how far it can be read.
pub fn derive_findings(snapshot: &AndroidDiagnosticsSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_not_company_portal_diagnostics(snapshot, &mut findings);
    push_empty_bundle(snapshot, &mut findings);
    push_unverified_artifact_contract(snapshot, &mut findings);
    push_unsafe_members(snapshot, &mut findings);
    push_incomplete_member_coverage(snapshot, &mut findings);
    push_unknown_app_or_version(snapshot, &mut findings);
    push_unusable_collection_time(snapshot, &mut findings);
    push_work_profile_collection_limits(snapshot, &mut findings);
    push_verbose_logging_disabled(snapshot, &mut findings);
    push_incident_id_without_upload_confirmation(snapshot, &mut findings);

    findings
}

/// The serialized token of a raw-preserving enum, used to name a value in a
/// summary without hand-writing a `Display` impl per vocabulary.
fn wire(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Evidence references for the members matching `predicate`, in member order.
fn member_evidence(
    snapshot: &AndroidDiagnosticsSnapshot,
    predicate: impl Fn(&AndroidDiagnosticMember) -> bool,
) -> Vec<IntuneEvidenceRef> {
    snapshot
        .members
        .iter()
        .filter(|member| predicate(member))
        .map(|member| member.context.evidence_ref.clone())
        .collect()
}

fn supplied_evidence(snapshot: &AndroidDiagnosticsSnapshot) -> Vec<IntuneEvidenceRef> {
    vec![snapshot.metadata.supplied_context.evidence_ref.clone()]
}

/// Do the envelope rules have anything to say about this bundle?
///
/// The importer's claims about app, mode, timing, and submission only mean
/// something once the bundle is being treated as Android diagnostics at all.
/// Reporting "verbose logging was off" about an archive that was just declined
/// as not Company Portal diagnostics would be noise dressed as a diagnosis.
/// Safety and coverage rules are deliberately *not* gated this way: an unsafe
/// member matters no matter what the archive turned out to be.
fn envelope_rules_apply(snapshot: &AndroidDiagnosticsSnapshot) -> bool {
    matches!(
        snapshot.metadata.classification,
        AndroidBundleClassification::VerifiedContract
            | AndroidBundleClassification::CandidateUnverifiedContract
    )
}

#[allow(clippy::too_many_arguments)]
fn finding(
    finding_id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: &[&str],
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> IntuneFinding {
    IntuneFinding {
        finding_id: finding_id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks: recommended_checks
            .iter()
            .map(|check| (*check).to_owned())
            .collect(),
        evidence,
        coverage_gap_ids,
    }
}

fn push_not_company_portal_diagnostics(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.metadata.classification != AndroidBundleClassification::NotCompanyPortalDiagnostics {
        return;
    }

    let logcat_members = member_evidence(snapshot, |member| {
        member.classification == AndroidMemberClassification::RecognizedForeignLogcat
    });
    let recognized_logcat = !logcat_members.is_empty();
    let evidence = if recognized_logcat {
        logcat_members
    } else {
        let all = member_evidence(snapshot, |_| true);
        if all.is_empty() {
            supplied_evidence(snapshot)
        } else {
            all
        }
    };

    let summary = if recognized_logcat {
        "Every member that carried content reads as an Android logcat capture. \
         A logcat line is not Company Portal evidence, and a general logcat parser \
         is out of scope, so this bundle was not treated as Company Portal diagnostics."
            .to_owned()
    } else {
        "Nothing identified this bundle as Android Company Portal or Microsoft Intune \
         app diagnostics, so it was not treated as either. An arbitrary archive is not \
         a diagnostic report."
            .to_owned()
    };

    findings.push(finding(
        "android-diagnostics/not-company-portal",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Bundle was not treated as Android Company Portal diagnostics",
        summary,
        &[
            "Confirm the archive came from Company Portal 'Save logs' or 'Send logs', or from the Microsoft Intune app 'Upload logs'",
            "Re-import with the collecting app and management mode declared",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_empty_bundle(snapshot: &AndroidDiagnosticsSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.metadata.classification != AndroidBundleClassification::EmptyBundle {
        return;
    }
    findings.push(finding(
        "android-diagnostics/empty-bundle",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "No members were supplied for this bundle",
        "The import supplied no archive members, so nothing was enumerated and no \
         conclusion about the collection is available."
            .to_owned(),
        &["Confirm the archive extracted successfully before import"],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

/// The finding that carries this issue's central limitation.
fn push_unverified_artifact_contract(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.metadata.classification != AndroidBundleClassification::CandidateUnverifiedContract {
        return;
    }

    let enumerated = snapshot
        .members
        .iter()
        .filter(|member| member.classification == AndroidMemberClassification::Enumerated)
        .count();
    let mut evidence = member_evidence(snapshot, |member| {
        member.classification == AndroidMemberClassification::Enumerated
    });
    let coverage_gap_ids = snapshot.coverage_gap_ids();
    if evidence.is_empty() && coverage_gap_ids.is_empty() {
        evidence = supplied_evidence(snapshot);
    }

    findings.push(finding(
        "android-diagnostics/unverified-artifact-contract",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "No verified Android diagnostic artifact contract matched",
        format!(
            "{enumerated} member(s) were enumerated, but this build has {} verified Android \
             Company Portal artifact contract(s), so no member was interpreted and no \
             diagnostic record is claimed. The bundle's origin, app, and management mode are \
             recorded as importer-supplied facts rather than as findings read from the artifact.",
            verified_contract_count()
        ),
        &[
            "Attach a sanitized artifact to issue #371 so the container, member list, schema token, encoding, and timestamp format can be recorded",
            "Read the member contents directly until a contract is verified",
        ],
        evidence,
        coverage_gap_ids,
    ));
}

fn push_unsafe_members(snapshot: &AndroidDiagnosticsSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unsafe_members: Vec<&AndroidDiagnosticMember> = snapshot
        .members
        .iter()
        .filter(|member| !member.safety_flags.is_empty())
        .collect();
    if unsafe_members.is_empty() {
        return;
    }

    let mut flags: Vec<&'static str> = unsafe_members
        .iter()
        .flat_map(|member| member.safety_flags.iter().map(|flag| flag.wire()))
        .collect();
    flags.sort_unstable();
    flags.dedup();

    findings.push(finding(
        "android-diagnostics/unsafe-members",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Archive members were excluded as unsafe",
        format!(
            "{} member(s) were excluded from evidence because the import reported or the entry \
             names showed: {}. Their contents were not read.",
            unsafe_members.len(),
            flags.join(", ")
        ),
        &[
            "Re-extract the archive with an extractor that rejects traversal, absolute, duplicate, and oversized entries",
            "Confirm the archive was not modified in transit",
        ],
        member_evidence(snapshot, |member| !member.safety_flags.is_empty()),
        Vec::new(),
    ));
}

fn push_incomplete_member_coverage(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let gaps = snapshot.coverage_gap_ids();
    if gaps.is_empty() {
        return;
    }
    findings.push(finding(
        "android-diagnostics/incomplete-member-coverage",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "Some expected members were not fully collected",
        format!(
            "{} of {} member(s) were missing, capped, denied, skipped, unsupported, or failed to \
             decode. The absence of a signal in this bundle proves nothing about the device.",
            gaps.len(),
            snapshot.coverage.len()
        ),
        &["Re-collect the bundle and confirm every expected member is present and complete"],
        Vec::new(),
        gaps,
    ));
}

fn push_unknown_app_or_version(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !envelope_rules_apply(snapshot) {
        return;
    }
    // A declared schema token that matches nothing is the interesting case: the
    // importer read a version marker off an artifact this build has never seen.
    let unknown_schema = snapshot.metadata.declared_schema_token.is_some()
        && snapshot.metadata.verified_contract_id.is_none();
    let unknown_app = matches!(
        snapshot.metadata.app,
        Some(super::contract::AndroidDiagnosticApp::Unknown(_))
    );
    if !unknown_schema && !unknown_app {
        return;
    }

    let mut parts = Vec::new();
    if unknown_app {
        parts.push("the collecting app is not one this build recognizes");
    }
    if unknown_schema {
        parts.push("the declared schema token matches no verified contract");
    }

    findings.push(finding(
        "android-diagnostics/unknown-app-or-schema",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "Unrecognized app or artifact schema",
        format!(
            "This bundle is handled as experimental because {}. Both values are preserved \
             verbatim so a later build can recognize them without a re-import.",
            parts.join(" and ")
        ),
        &["Record the app name and schema token against issue #371 so the contract can be classified"],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

fn push_unusable_collection_time(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !envelope_rules_apply(snapshot) {
        return;
    }
    let kind = snapshot
        .metadata
        .collected_at
        .as_ref()
        .map(|stamp| stamp.kind.clone());
    let problem = match kind {
        None => "no collection time was supplied",
        Some(IntuneTimestampKind::Invalid) => "the supplied collection time could not be read",
        Some(IntuneTimestampKind::Unspecified) => {
            "the supplied collection time states neither an offset nor a time zone"
        }
        Some(IntuneTimestampKind::Local) => {
            "the supplied collection time is a wall-clock reading in a named zone this crate cannot resolve"
        }
        Some(IntuneTimestampKind::Utc) | Some(IntuneTimestampKind::Offset) => return,
    };

    findings.push(finding(
        "android-diagnostics/unusable-collection-time",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "Collection time cannot be placed on a UTC timeline",
        format!(
            "This bundle cannot be ordered against other evidence because {problem}. The original \
             text is preserved and no offset was assumed from the machine running this analysis."
        ),
        &["Re-import with a collection time that carries its own UTC offset"],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

fn push_work_profile_collection_limits(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !envelope_rules_apply(snapshot) {
        return;
    }
    if snapshot.metadata.management_mode != Some(AndroidManagementMode::WorkProfile) {
        return;
    }
    findings.push(finding(
        "android-diagnostics/work-profile-collection-scope",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Collection was scoped to the work profile",
        "Company Portal and the file-viewing app that saved these logs both run inside the work \
         profile, so this bundle describes the work profile only. Nothing here is evidence about \
         the personal profile."
            .to_owned(),
        &["Collect separately from the personal profile if the problem reproduces there"],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

fn push_verbose_logging_disabled(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !envelope_rules_apply(snapshot) {
        return;
    }
    if snapshot.metadata.verbose_logging != AndroidVerboseLoggingState::Off {
        return;
    }
    findings.push(finding(
        "android-diagnostics/verbose-logging-disabled",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Verbose logging was off when this bundle was collected",
        "Verbose logging is on by default in Company Portal and was reported off here, so the \
         bundle carries less detail than a default collection would. A signal missing from it is \
         not evidence that the action did not happen."
            .to_owned(),
        &[
            "Turn Verbose Logging back on under Settings > Troubleshooting, reproduce the problem, and re-collect",
        ],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

fn push_incident_id_without_upload_confirmation(
    snapshot: &AndroidDiagnosticsSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if !envelope_rules_apply(snapshot) {
        return;
    }
    if snapshot.metadata.incident_id.is_none() {
        return;
    }
    if snapshot.metadata.upload_outcome == AndroidUploadOutcome::Confirmed {
        return;
    }

    findings.push(finding(
        "android-diagnostics/incident-id-without-upload-confirmation",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "An incident ID is present but no successful upload is reported",
        format!(
            "The send-logs flow pre-populates an incident ID into a mail draft when a submission \
             is started, and the reported upload outcome here is '{}'. An incident ID is a \
             correlation identifier for a submission attempt, not a receipt, so it is not treated \
             as proof that Microsoft received the logs.",
            wire(&snapshot.metadata.upload_outcome)
        ),
        &[
            "Confirm with the user that the send-logs step completed before quoting the incident ID to support",
        ],
        supplied_evidence(snapshot),
        Vec::new(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneArtifactStatus;
    use super::super::contract::{
        AndroidCollectionFlow, AndroidDiagnosticApp,
    };
    use super::super::models::{
        AndroidDiagnosticBundleInput, AndroidDiagnosticMemberInput, AndroidImportLimits,
        AndroidSuppliedCollectionFacts,
    };
    use super::super::reducer::analyze_android_diagnostic_bundle;

    fn member(artifact_id: &str, entry_name: &str, text: Option<&str>) -> AndroidDiagnosticMemberInput {
        AndroidDiagnosticMemberInput {
            artifact_id: artifact_id.to_owned(),
            entry_name: entry_name.to_owned(),
            sanitized_entry_path: None,
            status: IntuneArtifactStatus::Available,
            declared_bytes: text.map(|value| value.len() as u64).unwrap_or_default(),
            encoding: Some("utf-8".to_owned()),
            rotation: None,
            text: text.map(str::to_owned),
            safety_flags: Vec::new(),
        }
    }

    fn analyze(
        supplied: AndroidSuppliedCollectionFacts,
        members: Vec<AndroidDiagnosticMemberInput>,
    ) -> AndroidDiagnosticsSnapshot {
        analyze_android_diagnostic_bundle(&AndroidDiagnosticBundleInput {
            bundle_id: "bundle-1".to_owned(),
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            supplied,
            members,
            limits: AndroidImportLimits::default(),
        })
    }

    fn company_portal_facts() -> AndroidSuppliedCollectionFacts {
        AndroidSuppliedCollectionFacts {
            app: Some(AndroidDiagnosticApp::CompanyPortal),
            collection_flow: Some(AndroidCollectionFlow::SavedLogs),
            collected_at_text: Some("2026-07-31T09:14:02+10:00".to_owned()),
            ..Default::default()
        }
    }

    fn finding_ids(snapshot: &AndroidDiagnosticsSnapshot) -> Vec<&str> {
        snapshot
            .findings
            .iter()
            .map(|entry| entry.finding_id.as_str())
            .collect()
    }

    #[test]
    fn every_finding_cites_evidence_or_a_coverage_gap() {
        let mut facts = company_portal_facts();
        facts.management_mode = Some(AndroidManagementMode::WorkProfile);
        facts.verbose_logging = Some(AndroidVerboseLoggingState::Off);
        facts.incident_id = Some("SYNTHETIC-INCIDENT-0001".to_owned());
        facts.declared_schema_token = Some("synthetic-v0".to_owned());

        let mut absent = member("b-absent", "absent.txt", None);
        absent.status = IntuneArtifactStatus::Missing;
        let snapshot = analyze(
            facts,
            vec![member("a-present", "summary.txt", Some("key = value\n")), absent],
        );

        assert!(!snapshot.findings.is_empty());
        assert!(snapshot.findings_are_evidence_backed());
    }

    #[test]
    fn a_candidate_bundle_always_reports_the_unverified_contract() {
        let snapshot = analyze(
            company_portal_facts(),
            vec![member("a", "summary.txt", Some("key = value\n"))],
        );
        assert!(finding_ids(&snapshot)
            .contains(&"android-diagnostics/unverified-artifact-contract"));
    }

    #[test]
    fn a_logcat_bundle_is_refused_and_never_reports_an_unverified_contract() {
        let logcat = concat!(
            "07-31 09:14:02.113  4120  4120 I SynthTag: synthetic line one\n",
            "07-31 09:14:02.114  4120  4155 D SynthTag: synthetic line two\n",
        );
        let snapshot = analyze(
            company_portal_facts(),
            vec![member("a", "logcat.txt", Some(logcat))],
        );
        let ids = finding_ids(&snapshot);
        assert!(ids.contains(&"android-diagnostics/not-company-portal"));
        assert!(!ids.contains(&"android-diagnostics/unverified-artifact-contract"));
    }

    #[test]
    fn an_incident_id_alone_never_confirms_an_upload() {
        let mut facts = company_portal_facts();
        facts.incident_id = Some("SYNTHETIC-INCIDENT-0001".to_owned());
        let snapshot = analyze(facts, vec![member("a", "summary.txt", Some("key = value\n"))]);
        assert!(finding_ids(&snapshot)
            .contains(&"android-diagnostics/incident-id-without-upload-confirmation"));
    }

    #[test]
    fn a_confirmed_upload_suppresses_the_incident_id_caveat() {
        let mut facts = company_portal_facts();
        facts.incident_id = Some("SYNTHETIC-INCIDENT-0001".to_owned());
        facts.upload_outcome = Some(AndroidUploadOutcome::Confirmed);
        let snapshot = analyze(facts, vec![member("a", "summary.txt", Some("key = value\n"))]);
        assert!(!finding_ids(&snapshot)
            .contains(&"android-diagnostics/incident-id-without-upload-confirmation"));
    }

    #[test]
    fn no_finding_text_repeats_a_supplied_identifier() {
        // Findings are copied through the redacted export projection untouched,
        // so anything sensitive that leaked into one would leak into the export.
        let mut facts = company_portal_facts();
        facts.incident_id = Some("SYNTHETIC-INCIDENT-0001".to_owned());
        facts.app_version = Some("0.0.0-synthetic".to_owned());
        facts.declared_schema_token = Some("synthetic-v0".to_owned());
        let snapshot = analyze(
            facts,
            vec![member("a", "com.synthetic.fixture.portal.txt", Some("key = value\n"))],
        );

        for entry in &snapshot.findings {
            let text = format!("{} {} {}", entry.finding_id, entry.title, entry.summary);
            assert!(!text.contains("SYNTHETIC-INCIDENT-0001"), "{text}");
            assert!(!text.contains("synthetic-v0"), "{text}");
            assert!(!text.contains("com.synthetic.fixture.portal"), "{text}");
        }
    }

    #[test]
    fn finding_order_is_stable() {
        let mut facts = company_portal_facts();
        facts.management_mode = Some(AndroidManagementMode::WorkProfile);
        facts.verbose_logging = Some(AndroidVerboseLoggingState::Off);
        let snapshot = analyze(facts, vec![member("a", "summary.txt", Some("key = value\n"))]);
        assert_eq!(
            finding_ids(&snapshot),
            vec![
                "android-diagnostics/unverified-artifact-contract",
                "android-diagnostics/work-profile-collection-scope",
                "android-diagnostics/verbose-logging-disabled",
            ]
        );
    }
}
