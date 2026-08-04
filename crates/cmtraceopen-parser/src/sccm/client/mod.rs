//! Pure SCCM client diagnostics.
//!
//! This module accepts already-supplied metadata. Native discovery and capture
//! remain outside `cmtraceopen-parser`.

pub(crate) mod admission;
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
pub use intake::*;
pub use inventory::{
    analyze_client_extended, SccmClientAnalysis, SccmCoverageGap, SccmPhase, SccmSourceObservation,
    SccmTransaction, SccmTransactionState, SccmWorkflow,
};
pub use updates::*;
