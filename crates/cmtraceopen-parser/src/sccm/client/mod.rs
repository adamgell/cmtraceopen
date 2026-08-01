mod deployment;

pub use deployment::*;

use super::{SccmArtifact, SccmEvidence};

/// Pure, normalized SCCM input shared by client workflow analyzers.
///
/// The bundle owns no raw file handles or collection behavior. Its evidence has
/// already passed through the shared CCM logical-record scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct SccmNormalizedBundle {
    pub artifacts: Vec<SccmArtifact>,
    pub evidence: Vec<SccmEvidence>,
}
