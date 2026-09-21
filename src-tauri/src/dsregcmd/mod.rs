// Pure analyzer modules live in cmtraceopen-parser::dsregcmd and are
// re-exported here so existing references to the models, the derivation
// helpers and the diagnostic-rule helpers keep resolving unchanged.
//
// The unprojected half of that lane is *not* reachable from here: the crate's
// `parser::parse_dsregcmd` and `rules::analyze_facts` are crate-internal, and
// the unprojected analysis is only obtainable through
// `analyze_text_preserving_local_values`, which is crate-internal too. This
// crate publishes through `analyze_text_with_evidence` (projected),
// `redacted_status_text` (the capture text) and `redacted_bundle_artifacts`
// (a capture bundle on its way off the machine) — ADR-004 revision 1,
// Ruling 1.
//
// `registry` stays in src-tauri because it reads `.reg` hive files from disk
// (native-only).

pub use cmtraceopen_parser::dsregcmd::{derive, extended, models, parser, rules};

// Native-only (stay in src-tauri):
//   connectivity  - uses ureq for HTTPS probes + process_util for nltest/powershell
//   event_logs    - calls into intune::eventlog_win32 and intune::evtx_parser
// Both consume crate types (DsregcmdConnectivityResult, EventLogAnalysis, etc.)
// via `crate::intune::models::*` and `crate::dsregcmd::models::*`.
pub mod connectivity;
pub mod event_logs;

pub use cmtraceopen_parser::dsregcmd::{
    redacted_bundle_artifacts, redacted_status_text, DsregcmdActiveEvidence,
    DsregcmdAnalysisResult, DsregcmdBundleArtifact, DsregcmdBundleEvidence,
    DsregcmdConnectivityResult, DsregcmdDerived, DsregcmdDiagnosticInsight,
    DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdEvidenceSource, DsregcmdFacts,
    DsregcmdJoinType, DsregcmdOsVersionEvidence, DsregcmdPolicyEvidenceValue,
    DsregcmdProxyEvidence, DsregcmdScheduledTaskEvidence, DsregcmdScpQueryResult,
    DsregcmdWhfbPolicyEvidence,
};

pub mod registry;

/// Desktop entry point — same contract as the crate's `analyze_text` but
/// wraps the parse error into the Tauri-facing `AppError`.
pub fn analyze_text_with_evidence(
    input: &str,
    evidence: DsregcmdBundleEvidence,
) -> Result<DsregcmdAnalysisResult, crate::error::AppError> {
    cmtraceopen_parser::dsregcmd::analyze_text_with_evidence(input, evidence)
        .map_err(crate::error::AppError::InvalidInput)
}
