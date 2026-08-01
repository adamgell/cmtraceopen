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
    let mut covered = scan_logical_records(content, &artifact.display_name)
        .into_iter()
        .map(|record| (record.line_start, record.line_end))
        .collect::<Vec<_>>();
    // Sorting the spans lets both sequences be walked once. Rescanning every
    // record for every line is quadratic, and a capped or rotated source is
    // exactly the large input that leaves the most uncovered lines behind.
    covered.sort_unstable();

    // Records may nest or overlap, so the furthest end seen so far decides
    // coverage. That is the same answer as asking whether any span contains the
    // line, because every span starting at or before it has been folded in.
    let mut next_span = 0usize;
    let mut covered_through = 0u32;
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line_number = u32::try_from(index + 1).ok()?;
            while let Some((start, end)) = covered.get(next_span).copied() {
                if start > line_number {
                    break;
                }
                covered_through = covered_through.max(end);
                next_span += 1;
            }
            if covered_through >= line_number || line.trim().is_empty() {
                return None;
            }
            Some(SccmRawEvidenceSnapshot::from_physical_line(artifact, line_number, line).export())
        })
        .collect()
}
