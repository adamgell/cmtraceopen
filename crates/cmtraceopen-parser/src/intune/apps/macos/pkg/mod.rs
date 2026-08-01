//! Intune macOS package deployment evidence.
//!
//! Owner: issue #361 of epic #356.
//!
//! This is a **semantic analyzer over supplied agent evidence**, not a log
//! format. Records are framed first by the shared raw parser in
//! [`shared::agent_log`]; only then are they classified and reduced. The module
//! performs no I/O of any kind and is `wasm32`-clean.
//!
//! # Relationship to shell scripts
//!
//! Issue #361 requires a single raw record parser and separate reducers.
//! [`shared`] holds the parser, and
//! [`crate::intune::apps::macos::shell_scripts`] consumes it from here. The two
//! reducers stay apart because their phases and terminal semantics genuinely
//! differ: a package has a download, a signature check, an installer exit, and a
//! post-install detection step; a script has none of those. A package record and
//! a script record may share an agent, a thread, and a timestamp, and they never
//! merge on any of the three.
//!
//! # What the analyzer will not do
//!
//! * apply `.pkg` terminal semantics to a DMG or bare `.app` — an unmodelled
//!   type reaches [`PkgOutcome::UnsupportedAppType`] and stops there;
//! * treat a zero installer exit as proof the app is present — that is
//!   [`PkgOutcome::InstalledPendingDetection`] until detection confirms it;
//! * key a transaction on anything but a stated `AppId`;
//! * let a reporting failure turn a successful install into a failed one.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::macos::pkg::{
//!     analyze_pkg_bundle, MacAgentArtifactInput, MacAgentCaptureState, PkgOutcome,
//! };
//!
//! let app = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
//! let content = format!(
//!     "2026-07-29 09:10:00:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | \
//!      Received app policy AppId={app} Type=pkg\n\
//!      2026-07-29 09:10:20:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | \
//!      Installer finished for AppId={app} ExitCode=0\n\
//!      2026-07-29 09:10:21:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | \
//!      Detection succeeded for AppId={app}\n"
//! );
//!
//! let snapshot = analyze_pkg_bundle(
//!     &[MacAgentArtifactInput {
//!         artifact_id: "daemon-current".to_string(),
//!         family: "intuneMdmDaemon".to_string(),
//!         file_name: "IntuneMDMDaemon.log".to_string(),
//!         sanitized_source_path: None,
//!         capture_state: MacAgentCaptureState::Captured,
//!         content: Some(content),
//!         detail: None,
//!     }],
//!     "2026-07-31T00:00:00Z",
//! );
//!
//! assert_eq!(snapshot.transactions.len(), 1);
//! assert_eq!(snapshot.transactions[0].outcome, PkgOutcome::Installed);
//! ```

mod export;
mod models;
mod reducer;
mod rules;
pub mod shared;
mod signals;

pub use export::redacted_export_projection;
pub use models::{
    PkgAppType, PkgOutcome, PkgPhase, PkgPhaseEvent, PkgReportingState, PkgSnapshot, PkgTransaction,
    PkgTransactionKey,
};
pub use reducer::analyze_pkg_bundle;
pub use rules::derive_findings;
pub use signals::{classify_message, classify_record, PkgSignal, PkgSignalKind, PKG_COMPONENTS};

// Re-exported so a caller can build inputs without reaching into `shared`,
// which exists for the shell-script leaf rather than for consumers.
pub use shared::agent_log::{
    parse_agent_log, MacAgentArtifactInput, MacAgentCaptureState, MacAgentGrammar, MacAgentLog,
    MacAgentProcess, MacAgentRecord, MacAgentRotation, MacAgentSeverity, MacAgentSourceRoot,
    KNOWN_GRAMMAR_VERSIONS, MACOS_AGENT_SCHEMA_VERSION,
};
