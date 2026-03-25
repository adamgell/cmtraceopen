pub mod connectivity;
pub mod event_logs;
pub mod models;
pub mod parser;
pub mod registry;
pub mod rules;

pub use models::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdConnectivityResult,
    DsregcmdDerived, DsregcmdDiagnosticInsight, DsregcmdEnrollmentEntry,
    DsregcmdEnrollmentEvidence, DsregcmdEvidenceSource, DsregcmdFacts, DsregcmdJoinType,
    DsregcmdOsVersionEvidence, DsregcmdPolicyEvidenceValue, DsregcmdProxyEvidence,
    DsregcmdScheduledTaskEvidence, DsregcmdScpQueryResult, DsregcmdWhfbPolicyEvidence,
};

pub fn analyze_text(input: &str) -> Result<DsregcmdAnalysisResult, String> {
    let facts = parser::parse_dsregcmd(input)?;
    Ok(rules::analyze_facts(facts, input))
}
