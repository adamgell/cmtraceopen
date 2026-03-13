pub mod models;
pub mod parser;
pub mod rules;

pub use models::{
    DsregcmdAnalysisResult, DsregcmdDerived, DsregcmdDiagnosticInsight, DsregcmdFacts,
    DsregcmdJoinType,
};

pub fn analyze_text(input: &str) -> Result<DsregcmdAnalysisResult, String> {
    let facts = parser::parse_dsregcmd(input)?;
    Ok(rules::analyze_facts(facts, input))
}
