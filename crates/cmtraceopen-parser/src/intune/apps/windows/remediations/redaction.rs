//! Deterministic privacy projection for remediation evidence.
//!
//! Remediation records are the most output-heavy of the Intune workloads: a
//! detection script emits arbitrary data, and that data lands verbatim in both
//! the record text and the embedded JSON payloads. Both are masked; the stage,
//! state, exit codes, and policy/run GUIDs survive, because those are the
//! contract the export exists to convey.
//!
//! The masking itself lives in [`crate::intune::apps::windows::common`], shared
//! with the platform-script analyzer. This module decides only *what* is
//! sensitive.

use crate::intune::apps::windows::common::redact_text;

use super::models::{
    RemediationAnalysis, RemediationArtifact, RemediationClassifiedString, RemediationObservation,
    RemediationPayload, RemediationSensitivity, RemediationTransaction,
};

fn redact_classified(value: &RemediationClassifiedString) -> RemediationClassifiedString {
    match value.sensitivity {
        RemediationSensitivity::Public => value.clone(),
        RemediationSensitivity::Sensitive => RemediationClassifiedString {
            value: redact_text(&value.value),
            sensitivity: RemediationSensitivity::Sensitive,
        },
    }
}

fn redact_artifact(artifact: &RemediationArtifact) -> RemediationArtifact {
    RemediationArtifact {
        file_path: artifact.file_path.as_ref().map(redact_classified),
        ..artifact.clone()
    }
}

fn redact_observation(observation: &RemediationObservation) -> RemediationObservation {
    RemediationObservation {
        message: redact_classified(&observation.message),
        ..observation.clone()
    }
}

fn redact_payload(payload: &RemediationPayload) -> RemediationPayload {
    RemediationPayload {
        raw_text: redact_classified(&payload.raw_text),
        ..payload.clone()
    }
}

fn redact_transaction(transaction: &RemediationTransaction) -> RemediationTransaction {
    RemediationTransaction {
        payloads: transaction.payloads.iter().map(redact_payload).collect(),
        ..transaction.clone()
    }
}

/// Project an analysis into its default-safe export form.
pub fn redacted_export_projection(analysis: &RemediationAnalysis) -> RemediationAnalysis {
    let mut coverage = analysis.coverage.clone();
    coverage.artifacts = coverage.artifacts.iter().map(redact_artifact).collect();

    RemediationAnalysis {
        transactions: analysis
            .transactions
            .iter()
            .map(redact_transaction)
            .collect(),
        observations: analysis
            .observations
            .iter()
            .map(redact_observation)
            .collect(),
        unkeyed_observations: analysis.unkeyed_observations.clone(),
        coverage,
    }
}
