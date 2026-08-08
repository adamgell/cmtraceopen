//! Pure SCCM client diagnostics.
//!
//! This module accepts already-supplied metadata. Native discovery and capture
//! remain outside `cmtraceopen-parser`.

pub(crate) const TASK_SEQUENCE_TEST_PROFILE_ID: &str = "task-sequence-client-5.00.test-v1";
pub(crate) const TASK_SEQUENCE_TEST_VERSION: &str = "5.00.TEST.0000";

pub(crate) mod admission;
mod deployment;
mod health;
mod intake;
mod inventory;
mod policy;
mod task_sequence;
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
pub use health::*;
pub use intake::*;
pub use inventory::{
    analyze_client_extended, SccmClientExtendedAnalysis, SccmClientExtendedArtifactRequest,
    SccmClientExtendedCoverage, SccmClientExtendedFinding, SccmClientExtendedObservation,
    SccmClientExtendedPhase, SccmClientExtendedSourceCitation, SccmClientExtendedState,
    SccmClientExtendedTransaction, SccmClientExtendedWorkflow,
};
pub use policy::*;
pub use task_sequence::*;
pub use updates::*;
