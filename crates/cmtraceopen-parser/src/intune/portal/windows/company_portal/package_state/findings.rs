//! Deterministic findings derived from a package-state capture.
//!
//! Every finding is a statement about the *capture*, not about the device. The
//! central rule is that absence is only claimable when the adapter proved it
//! enumerated the relevant scope: a missing row under a failed, denied, capped,
//! timed-out, or never-queried scope is coverage, not evidence of absence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::models::{
    ExpectedPackageFact, PackageCaptureCommandStatus, PackageCaptureSource, PackageInstallState,
    PackageRow, PackageScope, PackageScopeCoverageStatus, PackageStateCapture, PackageStateError,
    PackageStatus, PortalApp, COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PackageStateFindingKind {
    MalformedCapture,
    UnsupportedSchema,
    IncompleteQuery,
    PackageStatusProblem,
    VersionMismatch,
    MultiplePackageRegistrations,
    PackageAbsentFromCapturedScope,
    PackageInstalled,
}

impl PackageStateFindingKind {
    /// Stable presentation rank. Most actionable first; ties break on the
    /// finding id so the whole list is a total order.
    fn rank(self) -> u8 {
        match self {
            Self::MalformedCapture => 0,
            Self::UnsupportedSchema => 1,
            Self::IncompleteQuery => 2,
            Self::PackageStatusProblem => 3,
            Self::VersionMismatch => 4,
            Self::MultiplePackageRegistrations => 5,
            Self::PackageAbsentFromCapturedScope => 6,
            Self::PackageInstalled => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PackageStateFindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PackageStateFindingConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PackageStateEvidenceKind {
    PackageRow,
    CaptureField,
    ScopeCoverage,
    ExpectedFact,
}

/// Pointer back to the exact capture element a finding was derived from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageStateEvidenceRef {
    pub kind: PackageStateEvidenceKind,
    pub package_index: Option<usize>,
    pub package_full_name: Option<String>,
    pub capture_field: Option<String>,
    pub scope: Option<PackageScope>,
}

impl PackageStateEvidenceRef {
    fn package(index: usize, row: &PackageRow) -> Self {
        Self {
            kind: PackageStateEvidenceKind::PackageRow,
            package_index: Some(index),
            package_full_name: Some(row.full_name.clone()),
            capture_field: None,
            scope: None,
        }
    }

    fn capture_field(field: &str) -> Self {
        Self {
            kind: PackageStateEvidenceKind::CaptureField,
            package_index: None,
            package_full_name: None,
            capture_field: Some(field.to_string()),
            scope: None,
        }
    }

    fn scope_coverage(scope: &PackageScope) -> Self {
        Self {
            kind: PackageStateEvidenceKind::ScopeCoverage,
            package_index: None,
            package_full_name: None,
            capture_field: Some("capture.scopeCoverage".to_string()),
            scope: Some(scope.clone()),
        }
    }

    fn expected_fact(source: &str) -> Self {
        Self {
            kind: PackageStateEvidenceKind::ExpectedFact,
            package_index: None,
            package_full_name: None,
            capture_field: Some(source.to_string()),
            scope: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageStateFinding {
    pub id: String,
    pub kind: PackageStateFindingKind,
    pub severity: PackageStateFindingSeverity,
    pub confidence: PackageStateFindingConfidence,
    pub message: String,
    pub evidence: Vec<PackageStateEvidenceRef>,
}

/// Serialized wire form of a raw-preserving enum, used to build stable ids and
/// readable messages without a bespoke `Display` impl per enum.
fn wire(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_string(),
    }
}

/// A legacy `Format-List` import can never be more than a low-confidence
/// reading of display text, so it caps the confidence of everything derived
/// from it.
fn confidence_for(
    capture: &PackageStateCapture,
    ceiling: PackageStateFindingConfidence,
) -> PackageStateFindingConfidence {
    if capture.capture.source == PackageCaptureSource::LegacyFormatList {
        PackageStateFindingConfidence::Low
    } else {
        ceiling
    }
}

/// Build the single finding that represents a capture we could not read.
pub fn malformed_capture_finding(error: &PackageStateError) -> PackageStateFinding {
    PackageStateFinding {
        id: "package-state/malformed-capture".to_string(),
        kind: PackageStateFindingKind::MalformedCapture,
        severity: PackageStateFindingSeverity::Error,
        confidence: PackageStateFindingConfidence::High,
        message: format!("Package state capture could not be read: {error}"),
        evidence: vec![PackageStateEvidenceRef::capture_field("$")],
    }
}

/// Derive every finding a capture supports, in a deterministic order.
///
/// `expected` carries version expectations from other evidence. Nothing here
/// looks a version up; an empty slice simply produces no version findings.
pub fn derive_package_state_findings(
    capture: &PackageStateCapture,
    expected: &[ExpectedPackageFact],
) -> Vec<PackageStateFinding> {
    let mut findings = Vec::new();

    if capture.is_unsupported_schema() {
        findings.push(PackageStateFinding {
            id: format!(
                "package-state/unsupported-schema/{}",
                capture.schema_version
            ),
            kind: PackageStateFindingKind::UnsupportedSchema,
            severity: PackageStateFindingSeverity::Warning,
            confidence: PackageStateFindingConfidence::High,
            message: format!(
                "Capture declares schema version {} but this build understands version {}. \
                 The raw document is preserved and no package facts are claimed.",
                capture.schema_version, COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION
            ),
            evidence: vec![PackageStateEvidenceRef::capture_field("schemaVersion")],
        });
        sort_findings(&mut findings);
        return findings;
    }

    push_coverage_findings(capture, &mut findings);
    push_package_findings(capture, &mut findings);
    push_duplicate_registration_findings(capture, &mut findings);
    push_version_mismatch_findings(capture, expected, &mut findings);
    push_absence_findings(capture, expected, &mut findings);

    sort_findings(&mut findings);
    findings
}

fn sort_findings(findings: &mut [PackageStateFinding]) {
    findings.sort_by(|left, right| {
        left.kind
            .rank()
            .cmp(&right.kind.rank())
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn push_coverage_findings(capture: &PackageStateCapture, findings: &mut Vec<PackageStateFinding>) {
    let command_status = &capture.capture.command_status;
    if command_status != &PackageCaptureCommandStatus::Completed {
        let severity = match command_status {
            PackageCaptureCommandStatus::Failed | PackageCaptureCommandStatus::AccessDenied => {
                PackageStateFindingSeverity::Error
            }
            _ => PackageStateFindingSeverity::Warning,
        };
        // The adapter's error message is classified sensitive: it can name a
        // profile path or an account. Findings are a separate type that the
        // redaction projection never sees, so interpolating that text here
        // would smuggle it past redaction. The stable error code carries no
        // identity and is enough to act on; the message stays in the capture,
        // where redaction covers it.
        let detail = capture
            .capture
            .error
            .as_ref()
            .and_then(|error| error.code.as_ref())
            .map(|code| format!(" ({code})"))
            .unwrap_or_default();
        findings.push(PackageStateFinding {
            id: format!(
                "package-state/incomplete-query/command/{}",
                wire(command_status)
            ),
            kind: PackageStateFindingKind::IncompleteQuery,
            severity,
            confidence: PackageStateFindingConfidence::High,
            message: format!(
                "Package enumeration command reported status '{}'{detail}. \
                 Package absence cannot be claimed from this capture.",
                wire(command_status)
            ),
            evidence: vec![PackageStateEvidenceRef::capture_field(
                "capture.commandStatus",
            )],
        });
    }

    for coverage in &capture.capture.scope_coverage {
        if coverage.status == PackageScopeCoverageStatus::Complete {
            continue;
        }
        let severity = match coverage.status {
            PackageScopeCoverageStatus::Denied | PackageScopeCoverageStatus::Failed => {
                PackageStateFindingSeverity::Error
            }
            _ => PackageStateFindingSeverity::Warning,
        };
        // Same reasoning as the command error above: adapter-supplied detail
        // text is free-form and can carry a path or an account, so it stays in
        // the capture rather than being copied into a finding.
        findings.push(PackageStateFinding {
            id: format!(
                "package-state/incomplete-query/scope/{}/{}",
                wire(&coverage.scope),
                wire(&coverage.status)
            ),
            kind: PackageStateFindingKind::IncompleteQuery,
            severity,
            confidence: PackageStateFindingConfidence::High,
            message: format!(
                "Scope '{}' coverage is '{}'. Missing rows in this scope are unknown, not absent.",
                wire(&coverage.scope),
                wire(&coverage.status)
            ),
            evidence: vec![PackageStateEvidenceRef::scope_coverage(&coverage.scope)],
        });
    }
}

fn push_package_findings(capture: &PackageStateCapture, findings: &mut Vec<PackageStateFinding>) {
    for (index, row) in capture.packages.iter().enumerate() {
        if row.install_state == PackageInstallState::Installed {
            findings.push(PackageStateFinding {
                id: format!("package-state/installed/{index}/{}", row.full_name),
                kind: PackageStateFindingKind::PackageInstalled,
                severity: PackageStateFindingSeverity::Info,
                confidence: confidence_for(capture, PackageStateFindingConfidence::High),
                message: format!(
                    "{} {} is installed ({}, {}).",
                    row.name,
                    row.version,
                    wire(&row.architecture),
                    wire(&row.signature_kind)
                ),
                evidence: vec![PackageStateEvidenceRef::package(index, row)],
            });
        }

        // A row that omits `status` deserializes to an empty Unknown, because
        // PackageRow carries #[serde(default)]. An unreported status is not a
        // health problem, and reporting one as an Error would invent a fault
        // out of a missing field.
        let status_reported = !matches!(&row.status, PackageStatus::Unknown(raw) if raw.is_empty());
        if status_reported && row.status != PackageStatus::Ok {
            findings.push(PackageStateFinding {
                id: format!("package-state/status-problem/{index}/{}", row.full_name),
                kind: PackageStateFindingKind::PackageStatusProblem,
                severity: PackageStateFindingSeverity::Error,
                confidence: confidence_for(capture, PackageStateFindingConfidence::High),
                message: format!(
                    "{} {} reports package status '{}' (install state '{}').",
                    row.name,
                    row.version,
                    wire(&row.status),
                    wire(&row.install_state)
                ),
                evidence: vec![PackageStateEvidenceRef::package(index, row)],
            });
        }
    }
}

fn push_duplicate_registration_findings(
    capture: &PackageStateCapture,
    findings: &mut Vec<PackageStateFinding>,
) {
    let mut by_family: BTreeMap<&str, Vec<(usize, &PackageRow)>> = BTreeMap::new();
    for (index, row) in capture.packages.iter().enumerate() {
        by_family
            .entry(row.family_name.as_str())
            .or_default()
            .push((index, row));
    }

    for (family, rows) in by_family {
        if rows.len() < 2 {
            continue;
        }
        let mut versions: Vec<&str> = rows.iter().map(|(_, row)| row.version.as_str()).collect();
        versions.sort_unstable();
        versions.dedup();
        findings.push(PackageStateFinding {
            id: format!("package-state/multiple-registrations/{family}"),
            kind: PackageStateFindingKind::MultiplePackageRegistrations,
            severity: PackageStateFindingSeverity::Warning,
            confidence: confidence_for(capture, PackageStateFindingConfidence::High),
            message: format!(
                "Package family '{family}' has {} registrations (versions: {}).",
                rows.len(),
                versions.join(", ")
            ),
            evidence: rows
                .iter()
                .map(|(index, row)| PackageStateEvidenceRef::package(*index, row))
                .collect(),
        });
    }
}

fn push_version_mismatch_findings(
    capture: &PackageStateCapture,
    expected: &[ExpectedPackageFact],
    findings: &mut Vec<PackageStateFinding>,
) {
    for fact in expected {
        for (index, row) in capture.packages.iter().enumerate() {
            if row.app != fact.app {
                continue;
            }
            if let Some(family) = &fact.family_name {
                if &row.family_name != family {
                    continue;
                }
            }
            if row.version == fact.expected_version {
                continue;
            }
            findings.push(PackageStateFinding {
                // The source belongs in the id: two facts naming the same app
                // and the same expected version but coming from different
                // sources both match this row, and without the source they
                // would collide on one id with two different messages.
                id: format!(
                    "package-state/version-mismatch/{index}/{}/{}",
                    fact.expected_version, fact.source
                ),
                kind: PackageStateFindingKind::VersionMismatch,
                severity: PackageStateFindingSeverity::Warning,
                confidence: confidence_for(capture, PackageStateFindingConfidence::Medium),
                message: format!(
                    "{} is version {} but the supplied fact from {} expects {}.",
                    row.name, row.version, fact.source, fact.expected_version
                ),
                evidence: vec![
                    PackageStateEvidenceRef::package(index, row),
                    PackageStateEvidenceRef::expected_fact(&fact.source),
                ],
            });
        }
    }
}

/// Absence is claimed for Company Portal, which is the subject of this
/// contract, plus any app the caller supplied a fact for. It is claimed only
/// against a scope the adapter proved it enumerated completely, and only when
/// the app has no registration attributed to that scope.
fn push_absence_findings(
    capture: &PackageStateCapture,
    expected: &[ExpectedPackageFact],
    findings: &mut Vec<PackageStateFinding>,
) {
    if capture.capture.command_status != PackageCaptureCommandStatus::Completed {
        return;
    }
    let complete_scopes = capture.capture.complete_scopes();
    if complete_scopes.is_empty() {
        return;
    }

    // Company Portal is the subject of this contract, so it is always checked.
    // Any additional app the caller supplied a fact for is checked too.
    let mut apps = vec![PortalApp::CompanyPortal];
    for fact in expected {
        if !apps.contains(&fact.app) {
            apps.push(fact.app.clone());
        }
    }

    for app in apps {
        let rows = capture.rows_for_app(&app);

        // A row carrying no scope attribution cannot be placed. Claiming it
        // absent from a scope it might belong to would over-claim, so this app
        // stays silent until the adapter attributes every row it returned.
        if rows.iter().any(|(_, row)| row.scopes.is_empty()) {
            continue;
        }

        for scope in &complete_scopes {
            // Absence is decided per scope, not per app. A registration in one
            // completely enumerated scope proves nothing about another: an app
            // present only in currentUser really is absent from allUsers, and
            // that is a deployment signal worth reporting rather than a reason
            // to stay quiet.
            if rows.iter().any(|(_, row)| row.scopes.contains(scope)) {
                continue;
            }
            findings.push(PackageStateFinding {
                id: format!(
                    "package-state/absent/{}/{}",
                    wire(&app),
                    wire(scope)
                ),
                kind: PackageStateFindingKind::PackageAbsentFromCapturedScope,
                severity: PackageStateFindingSeverity::Warning,
                confidence: confidence_for(capture, PackageStateFindingConfidence::High),
                message: format!(
                    "No '{}' package registration was found in scope '{}', which the adapter enumerated completely.",
                    wire(&app),
                    wire(scope)
                ),
                evidence: vec![
                    PackageStateEvidenceRef::scope_coverage(scope),
                    PackageStateEvidenceRef::capture_field("capture.commandStatus"),
                ],
            });
        }
    }
}
