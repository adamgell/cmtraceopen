pub mod derive;
pub mod extended;
pub mod models;
pub mod parser;
pub mod rules;

pub use models::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdConnectivityResult, DsregcmdDerived,
    DsregcmdDiagnosticInsight, DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence,
    DsregcmdEvidenceSource, DsregcmdFacts, DsregcmdJoinType, DsregcmdOsVersionEvidence,
    DsregcmdPolicyEvidenceValue, DsregcmdProxyEvidence, DsregcmdScheduledTaskEvidence,
    DsregcmdScpQueryResult, DsregcmdWhfbPolicyEvidence,
};

/// Pure analyzer entry point: parse `dsregcmd /status` text + evaluate rules.
/// Returns `Err(String)` with a human-readable parse failure; callers wrap
/// into their own error type as needed.
pub fn analyze_text(input: &str) -> Result<DsregcmdAnalysisResult, String> {
    let facts = parser::parse_dsregcmd(input)?;
    Ok(rules::analyze_facts(facts, input))
}
