//! Intune macOS shell-script execution evidence.
//!
//! Owner: issue #361 of epic #356.
//!
//! A **semantic analyzer over supplied agent evidence**, not a log format.
//! Records are framed by the shared raw parser that the package leaf owns
//! ([`crate::intune::apps::macos::pkg::shared::agent_log`]); only then are they
//! classified and reduced here. The module performs no I/O and is `wasm32`-clean.
//!
//! # Why the reducer is separate from the package reducer
//!
//! Issue #361 requires one raw parser and two reducers. Package and script
//! records share an agent, a process, a thread, and often a timestamp, but they
//! do not share a lifecycle: a script has an execution context, a timeout, and a
//! stdout/stderr question; a package has a download, a signature check, an
//! installer exit, and a detection step. Neither set of terminal states is
//! meaningful for the other workload, so the two never merge on time or
//! component — only on explicit policy and run identifiers.
//!
//! # What the analyzer will not do
//!
//! * promote a nonzero exit to a root cause; it is an execution outcome;
//! * conflate a launch failure with a script that ran and failed;
//! * read a missing output artifact as proof that a script was silent — that is
//!   [`ShellOutputPresence::NotObserved`], not `ExplicitlyEmpty`;
//! * merge two runs of one policy that differ only by run id.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::macos::pkg::{
//!     MacAgentArtifactInput, MacAgentCaptureState,
//! };
//! use cmtraceopen_parser::intune::apps::macos::shell_scripts::{
//!     analyze_shell_script_bundle, ShellScriptOutcome,
//! };
//!
//! let policy = "11111111-1111-4111-8111-111111111111";
//! let run = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
//! let content = format!(
//!     "2026-07-29 09:10:01:000 | IntuneMDM-Daemon | I | 10 | ShellScriptManager | \
//!      Launching shell script PolicyId={policy} RunId={run} Context=system\n\
//!      2026-07-29 09:10:06:000 | IntuneMDM-Daemon | I | 10 | ShellScriptManager | \
//!      Shell script finished PolicyId={policy} RunId={run} ExitCode=0\n"
//! );
//!
//! let snapshot = analyze_shell_script_bundle(
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
//! assert_eq!(snapshot.runs.len(), 1);
//! assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::Succeeded);
//! ```

mod export;
mod models;
mod reducer;
mod rules;
mod signals;

pub use export::redacted_export_projection;
pub use models::{
    ShellExecutionContext, ShellOutputPresence, ShellReportingState, ShellScriptOutcome,
    ShellScriptPhase, ShellScriptPhaseEvent, ShellScriptRun, ShellScriptRunKey, ShellScriptSnapshot,
};
pub use reducer::analyze_shell_script_bundle;
pub use rules::derive_findings;
pub use signals::{
    classify_message, classify_record, ShellSignal, ShellSignalKind, SHELL_SCRIPT_COMPONENTS,
};
