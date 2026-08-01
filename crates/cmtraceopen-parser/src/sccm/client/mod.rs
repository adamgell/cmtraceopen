//! Pure SCCM client diagnostics.
//!
//! This module accepts already-supplied metadata. Native discovery and capture
//! remain outside `cmtraceopen-parser`.

pub(crate) mod admission;
mod deployment;
mod intake;
mod inventory;
mod updates;

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod authority_contract_tests;

pub use admission::{
    admit_client_evidence, SccmClientAdmittedEvidence, SccmClientCapturedPayload,
    SccmClientEvidenceAdmissionError,
};
pub use deployment::*;
pub use intake::*;
pub use inventory::{
    analyze_client_extended, SccmClientExtendedAnalysis, SccmClientExtendedArtifactRequest,
    SccmClientExtendedCoverage, SccmClientExtendedFinding, SccmClientExtendedObservation,
    SccmClientExtendedPhase, SccmClientExtendedSourceCitation, SccmClientExtendedState,
    SccmClientExtendedTransaction, SccmClientExtendedWorkflow,
};
pub use updates::*;

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
