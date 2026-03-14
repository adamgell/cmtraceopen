pub mod models;
pub mod parser;
pub mod registry;
pub mod rules;

pub use models::{
    DsregcmdAnalysisResult, DsregcmdDerived, DsregcmdDiagnosticInsight,
    DsregcmdEvidenceSource, DsregcmdFacts, DsregcmdJoinType, DsregcmdPolicyEvidenceValue,
    DsregcmdWhfbPolicyEvidence,
};

pub fn analyze_text(input: &str) -> Result<DsregcmdAnalysisResult, String> {
    let facts = parser::parse_dsregcmd(input)?;
    Ok(rules::analyze_facts(facts, input))
}
