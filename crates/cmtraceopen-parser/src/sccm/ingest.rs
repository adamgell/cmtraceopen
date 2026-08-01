use crate::parser::ccm::scan_logical_records;

use super::evidence::SccmRawEvidenceSnapshot;
use super::models::{SccmArtifact, SccmEvidence};

pub fn normalize_ccm_artifact(artifact: SccmArtifact, content: &str) -> Vec<SccmEvidence> {
    scan_logical_records(content, &artifact.display_name)
        .into_iter()
        .map(|record| SccmRawEvidenceSnapshot::from_record(&artifact, record).export())
        .collect()
}

/// Physical lines that no complete logical record covers.
///
/// Capped, rotation-split, and non-CCM supplemental sources leave bytes behind
/// that a diagnosis must be able to see and cite without ever treating them as
/// a record. The returned evidence carries no timestamp and no component, so a
/// consumer cannot order it, join it across a rotation boundary, or promote it
/// into a fact.
pub fn normalize_physical_lines(artifact: &SccmArtifact, content: &str) -> Vec<SccmEvidence> {
    let covered = scan_logical_records(content, &artifact.display_name)
        .into_iter()
        .map(|record| (record.line_start, record.line_end))
        .collect::<Vec<_>>();

    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line_number = u32::try_from(index + 1).ok()?;
            let is_covered = covered
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&line_number));
            if is_covered || line.trim().is_empty() {
                return None;
            }
            Some(SccmRawEvidenceSnapshot::from_physical_line(artifact, line_number, line).export())
        })
        .collect()
}
