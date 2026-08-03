//! Pure SCCM client diagnostics.
//!
//! This module accepts already-supplied metadata. Native discovery and capture
//! remain outside `cmtraceopen-parser`.

pub(crate) mod admission;
mod health;
mod intake;

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod authority_contract_tests;

pub use admission::{
    admit_client_evidence, SccmClientAdmittedEvidence, SccmClientCapturedPayload,
    SccmClientEvidenceAdmissionError,
};
pub use health::*;
pub use intake::*;
