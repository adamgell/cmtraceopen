// Pure analyzer modules live in cmtraceopen-parser::dsregcmd and are
// re-exported here so existing references like
// `crate::dsregcmd::parser::parse_dsregcmd` and
// `crate::dsregcmd::DsregcmdAnalysisResult` keep resolving unchanged.
//
// `registry` stays in src-tauri because it reads `.reg` hive files from disk
// (native-only).

pub use cmtraceopen_parser::dsregcmd::{
    derive, extended, models, parser, rules,
};

// Native-only (stay in src-tauri):
//   connectivity  - uses ureq for HTTPS probes + process_util for nltest/powershell
//   event_logs    - calls into intune::eventlog_win32 and intune::evtx_parser
// Both consume crate types (DsregcmdConnectivityResult, EventLogAnalysis, etc.)
// via `crate::intune::models::*` and `crate::dsregcmd::models::*`.
pub mod connectivity;
pub mod event_logs;

pub use cmtraceopen_parser::dsregcmd::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdConnectivityResult, DsregcmdDerived,
    DsregcmdDiagnosticInsight, DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence,
    DsregcmdEvidenceSource, DsregcmdFacts, DsregcmdJoinType, DsregcmdOsVersionEvidence,
    DsregcmdPolicyEvidenceValue, DsregcmdProxyEvidence, DsregcmdScheduledTaskEvidence,
    DsregcmdScpQueryResult, DsregcmdWhfbPolicyEvidence,
};

pub mod registry;

/// Desktop entry point — same contract as the crate's `analyze_text` but
/// wraps the parse error into the Tauri-facing `AppError`.
pub fn analyze_text(input: &str) -> Result<DsregcmdAnalysisResult, crate::error::AppError> {
    cmtraceopen_parser::dsregcmd::analyze_text(input).map_err(crate::error::AppError::InvalidInput)
}
