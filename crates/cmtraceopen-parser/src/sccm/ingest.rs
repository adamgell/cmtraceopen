use crate::parser::ccm::scan_logical_records;

use super::evidence::SccmRawEvidenceSnapshot;
use super::models::{SccmArtifact, SccmEvidence};

/// Pure, normalized SCCM input shared by every workflow analyzer.
///
/// The bundle owns no raw file handles or collection behavior. Its evidence has
/// already passed through the shared CCM logical-record scanner, so this is an
/// intake contract rather than any single workflow's type: it lives beside
/// [`normalize_ccm_artifact`], which produces the evidence it carries.
#[derive(Debug, Clone, PartialEq)]
pub struct SccmNormalizedBundle {
    pub artifacts: Vec<SccmArtifact>,
    pub evidence: Vec<SccmEvidence>,
}

pub fn normalize_ccm_artifact(artifact: SccmArtifact, content: &str) -> Vec<SccmEvidence> {
    scan_logical_records(content, &artifact.display_name)
        .into_iter()
        .map(|record| SccmRawEvidenceSnapshot::from_record(&artifact, record).export())
        .collect()
}
