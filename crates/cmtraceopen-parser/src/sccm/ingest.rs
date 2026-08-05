use crate::parser::ccm::scan_logical_records;

use super::evidence::SccmRawEvidenceSnapshot;
use super::models::{SccmArtifact, SccmEvidence};

pub fn normalize_ccm_artifact(artifact: SccmArtifact, content: &str) -> Vec<SccmEvidence> {
    scan_logical_records(content, &artifact.display_name)
        .into_iter()
        .map(|record| SccmRawEvidenceSnapshot::from_record(&artifact, record).export())
        .collect()
}
