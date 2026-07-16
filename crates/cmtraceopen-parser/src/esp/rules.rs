use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::models::*;

const STALLED_WORKLOAD_SECONDS: i64 = 15 * 60;

/// Derive stable, read-only diagnostic findings from an immutable snapshot.
///
/// Rules only emit when their triggering evidence is present. Every returned
/// finding therefore carries at least one evidence reference or explicit
/// coverage-gap identifier.
pub fn derive_findings(snapshot: &EspDiagnosticsSnapshot) -> Vec<EspDiagnosticFinding> {
    let mut findings = Vec::new();

    push_failed_blocking_app(snapshot, &mut findings);
    push_stalled_workload(snapshot, &mut findings);
    push_esp_timeout(snapshot, &mut findings);
    push_failed_registration(snapshot, &mut findings);
    push_unprocessed_workloads(snapshot, &mut findings);
    push_ime_coverage_gap(snapshot, &mut findings);
    push_non_elevated_coverage_loss(snapshot, &mut findings);
    push_ambiguous_installer(snapshot, &mut findings);
    push_local_graph_conflict(snapshot, &mut findings);
    push_malformed_source(snapshot, &mut findings);
    push_successful_completion(snapshot, &mut findings);

    findings
}

fn push_failed_blocking_app(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let workloads = snapshot.workloads.iter().filter(|workload| {
        workload.blocking == Some(true)
            && is_app_kind(&workload.kind)
            && workload.status.normalized == EspNormalizedStatus::Failed
    });
    let evidence = collect_evidence(workloads.flat_map(|workload| workload.evidence.iter()));
    push_finding(
        findings,
        finding(
            "blocking-app-failed",
            EspFindingSeverity::Blocker,
            EspFindingConfidence::High,
            "A blocking application failed",
            "At least one application explicitly marked as blocking reached a failed state.",
            "Inspect the cited IME or deployment log around the app's final failure.",
            evidence,
            vec![],
        ),
    );
}

fn push_stalled_workload(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let Some(generated_at) = parse_rfc3339(&snapshot.generated_at_utc) else {
        return;
    };
    let workloads = snapshot.workloads.iter().filter(|workload| {
        if !matches!(
            workload.status.normalized,
            EspNormalizedStatus::Downloading
                | EspNormalizedStatus::Installing
                | EspNormalizedStatus::InProgress
        ) {
            return false;
        }
        workload
            .timestamps
            .last_updated
            .as_ref()
            .or(workload.timestamps.started.as_ref())
            .and_then(normalized_timestamp)
            .is_some_and(|updated| {
                generated_at.signed_duration_since(updated).num_seconds()
                    >= STALLED_WORKLOAD_SECONDS
            })
    });
    let evidence = collect_evidence(workloads.flat_map(|workload| workload.evidence.iter()));
    push_finding(
        findings,
        finding(
            "workload-stalled",
            EspFindingSeverity::Error,
            EspFindingConfidence::High,
            "A download or installation has stopped updating",
            "A workload remains active and its cited last-update timestamp is at least 15 minutes old.",
            "Compare the cited workload's last update with IME and Delivery Optimization activity.",
            evidence,
            vec![],
        ),
    );
}

fn push_esp_timeout(snapshot: &EspDiagnosticsSnapshot, findings: &mut Vec<EspDiagnosticFinding>) {
    if snapshot.phase == EspPhase::Completed {
        return;
    }
    let Some(generated_at) = parse_rfc3339(&snapshot.generated_at_utc) else {
        return;
    };
    let timeout_values = snapshot
        .enrollments
        .iter()
        .filter_map(|enrollment| enrollment.settings.timeout_seconds)
        .filter(|timeout| *timeout > 0)
        .collect::<BTreeSet<_>>();
    if timeout_values.len() != 1 {
        return;
    }
    let Some(timeout_seconds) = timeout_values.iter().next().copied() else {
        return;
    };
    let Ok(timeout_seconds_i64) = i64::try_from(timeout_seconds) else {
        return;
    };
    let timed_out_sessions = snapshot.sessions.iter().filter(|session| {
        session.is_latest
            && !matches!(session.phase, EspPhase::Completed)
            && session
                .started_at
                .as_ref()
                .and_then(normalized_timestamp)
                .is_some_and(|started| {
                    generated_at.signed_duration_since(started).num_seconds() >= timeout_seconds_i64
                })
    });
    let mut evidence =
        collect_evidence(timed_out_sessions.flat_map(|session| session.evidence.iter()));
    if evidence.is_empty() {
        return;
    }
    evidence.extend(collect_evidence(
        snapshot
            .enrollments
            .iter()
            .filter(|enrollment| enrollment.settings.timeout_seconds == Some(timeout_seconds))
            .flat_map(|enrollment| enrollment.evidence.iter()),
    ));
    normalize_evidence(&mut evidence);
    push_finding(
        findings,
        finding(
            "esp-timeout-reached",
            EspFindingSeverity::Blocker,
            EspFindingConfidence::High,
            "The configured ESP timeout has been reached",
            "The current time is beyond the configured timeout for a cited active ESP session.",
            "Compare the cited ESP session start time with the configured timeout.",
            evidence,
            vec![],
        ),
    );
}

fn push_failed_registration(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let events = snapshot.registration_events.iter().filter(|event| {
        event.status.normalized == EspNormalizedStatus::Failed
            && matches!(event.event_id, 100 | 304 | 1924)
    });
    let evidence = collect_evidence(events.flat_map(|event| event.evidence.iter()));
    push_finding(
        findings,
        finding(
            "registration-or-join-failed",
            EspFindingSeverity::Error,
            EspFindingConfidence::High,
            "Device registration or join failed",
            "A cited device-registration event has an explicit failed status.",
            "Inspect the cited Device Registration event and its named data.",
            evidence,
            vec![],
        ),
    );
}

fn push_unprocessed_workloads(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    push_unprocessed_kind(
        snapshot,
        findings,
        EspTrackedKind::Policy,
        "policy-not-processed",
        "A tracked policy has not been processed",
        "At least one cited policy remains in a pre-processing state.",
        "Inspect the cited policy tracking state and enrollment scope.",
    );
    push_unprocessed_kind(
        snapshot,
        findings,
        EspTrackedKind::ScepCertificate,
        "certificate-not-processed",
        "A tracked certificate has not been processed",
        "At least one cited certificate remains in a pre-processing state.",
        "Inspect the cited certificate tracking state and enrollment scope.",
    );
}

#[allow(clippy::too_many_arguments)]
fn push_unprocessed_kind(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
    kind: EspTrackedKind,
    id: &str,
    title: &str,
    summary: &str,
    check: &str,
) {
    let workloads = snapshot
        .workloads
        .iter()
        .filter(|workload| workload.kind == kind && is_not_processed(&workload.status.normalized));
    let evidence = collect_evidence(workloads.flat_map(|workload| workload.evidence.iter()));
    push_finding(
        findings,
        finding(
            id,
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            title,
            summary,
            check,
            evidence,
            vec![],
        ),
    );
}

fn push_ime_coverage_gap(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let coverage = snapshot.coverage.iter().filter(|coverage| {
        let identity = format!("{} {}", coverage.artifact_id, coverage.family).to_ascii_lowercase();
        identity.contains("ime")
            && matches!(
                coverage.status,
                EspArtifactStatus::Missing | EspArtifactStatus::PermissionDenied
            )
    });
    let entries = coverage.collect::<Vec<_>>();
    let evidence = collect_evidence(entries.iter().flat_map(|coverage| coverage.evidence.iter()));
    let gaps = collect_gap_ids(entries.iter().map(|coverage| coverage.artifact_id.as_str()));
    push_finding(
        findings,
        finding(
            "ime-evidence-unavailable",
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            "IME evidence is unavailable",
            "The source inventory explicitly reports missing or unreadable Intune Management Extension logs.",
            "Open the cited IME coverage entry and verify the protected log path is readable.",
            evidence,
            gaps,
        ),
    );
}

fn push_non_elevated_coverage_loss(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    if snapshot.elevation.is_elevated {
        return;
    }
    let denied = snapshot
        .coverage
        .iter()
        .filter(|coverage| coverage.status == EspArtifactStatus::PermissionDenied)
        .collect::<Vec<_>>();
    let evidence = collect_evidence(denied.iter().flat_map(|coverage| coverage.evidence.iter()));
    let gaps = collect_gap_ids(
        denied
            .iter()
            .map(|coverage| coverage.artifact_id.as_str())
            .chain(
                snapshot
                    .elevation
                    .restricted_sources
                    .iter()
                    .map(String::as_str),
            ),
    );
    push_finding(
        findings,
        finding(
            "non-elevated-coverage-loss",
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            "Non-elevated access is hiding diagnostic evidence",
            "The session is not elevated and one or more protected evidence sources are unavailable.",
            "Review the cited coverage gaps, then relaunch CMTrace Open as administrator if deeper evidence is required.",
            evidence,
            gaps,
        ),
    );
}

fn push_ambiguous_installer(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let correlations = snapshot
        .installer_correlations
        .iter()
        .filter(|correlation| {
            correlation.workload_id.is_none()
                && correlation.confidence == EspCorrelationConfidence::Uncorrelated
                && correlation.candidate_workload_ids.len() > 1
        });
    let evidence =
        collect_evidence(correlations.flat_map(|correlation| correlation.evidence.iter()));
    push_finding(
        findings,
        finding(
            "installer-correlation-ambiguous",
            EspFindingSeverity::Warning,
            EspFindingConfidence::Medium,
            "The active installer cannot be matched to one workload",
            "Multiple candidate workloads remain after the available installer evidence is compared.",
            "Compare the cited process start time, log path, app ID, and product code with each candidate workload.",
            evidence,
            vec![],
        ),
    );
}

fn push_local_graph_conflict(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let Some(graph) = &snapshot.graph else {
        return;
    };
    if graph.apps.status != GraphSectionStatus::Available {
        return;
    }
    let Some(apps) = &graph.apps.data else {
        return;
    };
    let mut evidence = Vec::new();
    for workload in &snapshot.workloads {
        for app in apps.iter().filter(|app| {
            identifiers_equal(&app.app_id, &workload.raw_identifier)
                || identifiers_equal(&app.app_id, &workload.workload_id)
        }) {
            let Some(graph_status) = &app.status else {
                continue;
            };
            if statuses_contradict(&workload.status.normalized, &graph_status.normalized) {
                evidence.extend(workload.evidence.iter().cloned());
                evidence.extend(app.evidence.iter().cloned());
            }
        }
    }
    normalize_evidence(&mut evidence);
    push_finding(
        findings,
        finding(
            "local-graph-state-conflict",
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            "Local and Graph application states conflict",
            "The same exact application identifier has contradictory terminal local and Graph states.",
            "Compare the cited local workload and Graph app status without changing either source.",
            evidence,
            vec![],
        ),
    );
}

fn push_malformed_source(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    let malformed_coverage = snapshot
        .coverage
        .iter()
        .filter(|coverage| coverage.status == EspArtifactStatus::ParseFailed)
        .collect::<Vec<_>>();
    let mut evidence = collect_evidence(
        malformed_coverage
            .iter()
            .flat_map(|coverage| coverage.evidence.iter())
            .chain(
                snapshot
                    .raw_evidence
                    .iter()
                    .filter(|raw| raw.parse_state == EspParseState::Malformed)
                    .flat_map(|raw| raw.evidence.iter()),
            ),
    );
    normalize_evidence(&mut evidence);
    let gaps = collect_gap_ids(
        malformed_coverage
            .iter()
            .map(|coverage| coverage.artifact_id.as_str()),
    );
    push_finding(
        findings,
        finding(
            "source-evidence-malformed",
            EspFindingSeverity::Warning,
            EspFindingConfidence::High,
            "A diagnostic source is malformed",
            "At least one cited source failed parsing; its raw evidence remains available for inspection.",
            "Inspect the cited raw source record and its parse state.",
            evidence,
            gaps,
        ),
    );
}

fn push_successful_completion(
    snapshot: &EspDiagnosticsSnapshot,
    findings: &mut Vec<EspDiagnosticFinding>,
) {
    if snapshot.phase != EspPhase::Completed
        || snapshot.workloads.iter().any(|workload| {
            !matches!(
                workload.status.normalized,
                EspNormalizedStatus::Succeeded
                    | EspNormalizedStatus::Processed
                    | EspNormalizedStatus::Skipped
                    | EspNormalizedStatus::Uninstalled
            )
        })
    {
        return;
    }
    let completed_sessions = snapshot
        .sessions
        .iter()
        .filter(|session| session.is_latest && session.phase == EspPhase::Completed);
    let mut evidence =
        collect_evidence(completed_sessions.flat_map(|session| session.evidence.iter()));
    if evidence.is_empty() {
        return;
    }
    evidence.extend(collect_evidence(
        snapshot
            .workloads
            .iter()
            .flat_map(|workload| workload.evidence.iter()),
    ));
    normalize_evidence(&mut evidence);
    push_finding(
        findings,
        finding(
            "esp-completed",
            EspFindingSeverity::Info,
            EspFindingConfidence::High,
            "ESP completed successfully",
            "The cited latest session completed and all observed workloads are in successful terminal states.",
            "Review the cited completed session and terminal workload states.",
            evidence,
            vec![],
        ),
    );
}

#[allow(clippy::too_many_arguments)]
fn finding(
    id: &str,
    severity: EspFindingSeverity,
    confidence: EspFindingConfidence,
    title: &str,
    summary: &str,
    check: &str,
    evidence: Vec<EspEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> Option<EspDiagnosticFinding> {
    if evidence.is_empty() && coverage_gap_ids.is_empty() {
        return None;
    }
    Some(EspDiagnosticFinding {
        finding_id: id.to_string(),
        severity,
        confidence,
        title: title.to_string(),
        summary: summary.to_string(),
        recommended_checks: vec![check.to_string()],
        evidence,
        coverage_gap_ids,
    })
}

fn push_finding(findings: &mut Vec<EspDiagnosticFinding>, finding: Option<EspDiagnosticFinding>) {
    if let Some(finding) = finding {
        findings.push(finding);
    }
}

fn is_app_kind(kind: &EspTrackedKind) -> bool {
    matches!(
        kind,
        EspTrackedKind::Msi
            | EspTrackedKind::Office
            | EspTrackedKind::ModernApp
            | EspTrackedKind::Win32App
            | EspTrackedKind::DevicePreparationWorkload
    )
}

fn is_not_processed(status: &EspNormalizedStatus) -> bool {
    matches!(
        status,
        EspNormalizedStatus::NotStarted
            | EspNormalizedStatus::NotInstalled
            | EspNormalizedStatus::Initialized
            | EspNormalizedStatus::Pending
    )
}

fn statuses_contradict(local: &EspNormalizedStatus, remote: &EspNormalizedStatus) -> bool {
    matches!(
        (local, remote),
        (EspNormalizedStatus::Failed, EspNormalizedStatus::Succeeded)
            | (EspNormalizedStatus::Failed, EspNormalizedStatus::Processed)
            | (EspNormalizedStatus::Succeeded, EspNormalizedStatus::Failed)
            | (EspNormalizedStatus::Processed, EspNormalizedStatus::Failed)
    )
}

fn identifiers_equal(left: &str, right: &str) -> bool {
    left.trim_matches(['{', '}'])
        .eq_ignore_ascii_case(right.trim_matches(['{', '}']))
}

fn normalized_timestamp(timestamp: &EspTimestamp) -> Option<DateTime<Utc>> {
    timestamp.normalized_utc.as_deref().and_then(parse_rfc3339)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn collect_evidence<'a>(
    evidence: impl IntoIterator<Item = &'a EspEvidenceRef>,
) -> Vec<EspEvidenceRef> {
    let mut collected = evidence.into_iter().cloned().collect::<Vec<_>>();
    normalize_evidence(&mut collected);
    collected
}

fn normalize_evidence(evidence: &mut Vec<EspEvidenceRef>) {
    evidence.sort_by(|left, right| {
        left.evidence_id
            .cmp(&right.evidence_id)
            .then_with(|| left.source_artifact_id.cmp(&right.source_artifact_id))
    });
    evidence.dedup_by(|left, right| {
        left.evidence_id == right.evidence_id && left.source_artifact_id == right.source_artifact_id
    });
}

fn collect_gap_ids<'a>(gaps: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut gaps = gaps
        .into_iter()
        .filter(|gap| !gap.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    gaps.sort();
    gaps.dedup();
    gaps
}
