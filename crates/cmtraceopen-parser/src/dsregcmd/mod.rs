use chrono::DateTime;
use chrono::Utc;

pub mod derive;
pub mod extended;
pub mod models;
pub mod parser;
pub mod redaction;
pub mod rules;

pub use models::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdBundleEvidence,
    DsregcmdConnectivityResult, DsregcmdDerived, DsregcmdDiagnosticInsight,
    DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdEvidenceSource, DsregcmdFacts,
    DsregcmdJoinType, DsregcmdOsVersionEvidence, DsregcmdPolicyEvidenceValue,
    DsregcmdProxyEvidence, DsregcmdScheduledTaskEvidence, DsregcmdScpQueryResult,
    DsregcmdWhfbPolicyEvidence,
};
pub use redaction::{redacted_analysis, redacted_status_text};

/// Pure analyzer entry point: parse `dsregcmd /status` text + evaluate rules.
///
/// The returned analysis is the **projected** export form: the tenant id, the
/// tenant and on-premises domains, the device id, the device certificate
/// thumbprint, the user principal name and the user SID have been masked by
/// [`redaction`] before it is returned, so no caller holds an unprojected
/// analysis to copy to a clipboard or write to a file
/// (ADR-004 revision 1, Ruling 1). The unprojected analysis is not reachable
/// from outside this crate at all: it exists only for the rules that read an
/// identifier's shape and for the crate's own tests.
///
/// Returns `Err(String)` with a human-readable parse failure; callers wrap
/// into their own error type as needed.
pub fn analyze_text(
    input: &str,
    evaluated_at: DateTime<Utc>,
) -> Result<DsregcmdAnalysisResult, String> {
    analyze_text_with_evidence(input, DsregcmdBundleEvidence::default(), evaluated_at)
}

/// The analyzer entry point the application uses: parse `dsregcmd /status`
/// text, attach the evidence a native collector read from a capture bundle,
/// evaluate every rule, and project the result.
///
/// The bundle evidence is passed in because this crate performs no I/O. The
/// assembly lives here rather than in the caller so the extended diagnostics
/// are built from the unprojected values the evidence carries — several of them
/// read an identifier's shape, not just its presence — while the value that
/// leaves the crate is projected either way.
pub fn analyze_text_with_evidence(
    input: &str,
    evidence: DsregcmdBundleEvidence,
    evaluated_at: DateTime<Utc>,
) -> Result<DsregcmdAnalysisResult, String> {
    let mut result = analyze_text_preserving_local_values(input, evaluated_at)?;

    evidence.apply_to(&mut result);
    rules::apply_enrollment_cross_reference(&mut result);

    let mut extended = rules::build_extended_diagnostics(&result);
    extended.append(&mut rules::build_active_diagnostics_rules(&result));
    extended.append(&mut rules::build_event_log_diagnostics(&result));
    result.diagnostics.append(&mut extended);

    Ok(redaction::redacted_analysis(&result))
}

/// Parse and evaluate without projecting anything.
///
/// **Local-only, crate-internal.** The result still carries the device's tenant
/// id, domains, device id, thumbprint, user principal name and user SID as the
/// capture printed them, so it must not be exported, uploaded, attached to a
/// support case, or handed to a renderer that can copy it. It is not `pub`: the
/// only callers that may see it are the rules that read an identifier's shape
/// while the value is still real, and the crate's own tests. Everything that
/// publishes calls [`analyze_text`] or [`analyze_text_with_evidence`].
pub(crate) fn analyze_text_preserving_local_values(
    input: &str,
    evaluated_at: DateTime<Utc>,
) -> Result<DsregcmdAnalysisResult, String> {
    let facts = parser::parse_dsregcmd(input)?;
    Ok(rules::analyze_facts(facts, input, evaluated_at))
}
