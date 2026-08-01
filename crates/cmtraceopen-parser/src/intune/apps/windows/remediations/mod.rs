//! Intune Windows detection and remediation script evidence.
//!
//! Owner: issue #360 of epic #356.
//!
//! This is a **semantic analyzer over supplied IME evidence**, not a log
//! format. Raw records are framed by the shared CCM parser first
//! ([`crate::intune::ime_parser`]); only then are signals classified and
//! reduced. The module performs no I/O of any kind, and every public type is
//! built from the shared contracts in [`crate::intune::evidence`].
//!
//! It answers six questions about one run, and keeps them separate:
//!
//! 1. did detection run;
//! 2. was remediation required;
//! 3. did remediation run;
//! 4. what was its outcome;
//! 5. what was the post-remediation state;
//! 6. did the result reach Intune.
//!
//! The rule the rest of the module is built around: **an exit code without a
//! stage decides nothing**. `exitCode = 1` means "remediation is required"
//! after detection and "the remediation script failed" after remediation, so a
//! record that did not name its stage stays an observation and never becomes a
//! keyed terminal outcome.
//!
//! What the analyzer will not do:
//!
//! - join a detection and a remediation because they happened close together;
//! - let a record from an unconfirmed artifact carry a policy key;
//! - read anything at all out of an embedded payload it could not parse;
//! - concatenate record fragments across a rotation boundary;
//! - treat a missing reporting record as a reporting failure, or a successful
//!   exit code as proof the device's condition was actually fixed.
//!
//! # Relationship to platform scripts
//!
//! `HealthScripts` records are remediation evidence and are deliberately never
//! classified into a platform-script signal by
//! [`crate::intune::apps::windows::scripts`]; this module owns them. The two
//! lifecycles stay separate because their stages and terminal semantics differ.
//!
//! Consolidating the legacy `HealthScripts`/`AgentExecutor` heuristics in
//! `crate::intune::event_tracker` behind this API is a follow-up: that module
//! feeds the existing Intune workspace timeline, and moving it is a behavioural
//! change for a shipped surface that belongs in its own commit with its own
//! regression coverage.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::windows::remediations::{
//!     analyze_remediation_bundle, DetectionOutcome, RemediationOutcome, RemediationSourceInput,
//! };
//!
//! let health_scripts = concat!(
//!     r#"<![LOG[[HealthScripts] Processing health script policy with id = 11111111-2222-3333-4444-555555555555, RunId = 66666666-7777-8888-9999-000000000000, Invocation = Scheduled]LOG]!>"#,
//!     r#"<time="10:15:22.100+000" date="03-12-2026" component="HealthScripts" context="" type="1" thread="7" file="">"#,
//!     "\n",
//!     r#"<![LOG[[HealthScripts] Detection script completed, exit code = 0, compliance result = Compliant]LOG]!>"#,
//!     r#"<time="10:15:26.400+000" date="03-12-2026" component="HealthScripts" context="" type="1" thread="7" file="">"#,
//!     "\n",
//!     r#"<![LOG[[HealthScripts] Detection reported compliant, remediation is not required]LOG]!>"#,
//!     r#"<time="10:15:26.500+000" date="03-12-2026" component="HealthScripts" context="" type="1" thread="7" file="">"#,
//! );
//!
//! let snapshot = analyze_remediation_bundle(&[RemediationSourceInput::captured(
//!     "health-scripts-current",
//!     "HealthScripts.log",
//!     health_scripts,
//! )]);
//!
//! assert_eq!(snapshot.runs.len(), 1);
//! assert_eq!(snapshot.runs[0].detection.outcome, DetectionOutcome::Compliant);
//! assert_eq!(snapshot.runs[0].remediation.outcome, RemediationOutcome::Skipped);
//! ```

mod findings;
mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use findings::derive_findings;
pub use models::*;
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::analyze_remediation_bundle;
pub use rules::{classify_record, RecordClassification};
pub use sources::{
    candidate_source_kind, classify_source_kind, output_artifact_identity, rotation_ordinal,
    RemediationSourceInput,
};
