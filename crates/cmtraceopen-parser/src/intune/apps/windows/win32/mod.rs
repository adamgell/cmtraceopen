//! Intune Win32 app deployment transactions.
//!
//! Owner: issue #357 of epic #356.
//!
//! # What this is
//!
//! A **semantic analyzer over supplied IME and installer evidence**, not a log
//! format. Raw records are framed into complete logical records by the shared
//! CCM parser first ([`crate::intune::ime_parser`]); only then are signals
//! classified, keyed, and reduced. The module performs no I/O of any kind: no
//! filesystem, registry, event log, Graph, or process execution. The caller
//! reads and decodes each artifact and hands over the text.
//!
//! The result explains *where a deployment stopped* across assignment,
//! applicability, requirements, dependencies, content, detection, enforcement,
//! post-install detection, and reporting. It deliberately does not present a
//! severity keyword or an isolated installer return code as the full diagnosis:
//! a nonzero code can mean success-with-reboot, and a zero code sits next to a
//! failing detection rule often enough that reporting it alone is misleading.
//!
//! # What it will not do
//!
//! - promote a return code to a root cause; it is an execution outcome, and
//!   [`Win32ReturnCodeKind::Unmapped`] is reported rather than guessed at;
//! - let an unkeyed record, a physical-line fragment, or an unmatched rotation
//!   tail terminate a transaction;
//! - merge two deployments on timestamp, display name, or a shared `Win32App`
//!   component; identity is the only join;
//! - merge a supplemental MSI, PSADT, Burn, or EXE-output artifact into a
//!   transaction unless a keyed record explicitly names it;
//! - treat a missing artifact as proof that the phase it records did not happen.
//!
//! # Layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | `models` | the public types, all built on [`crate::intune::evidence`] |
//! | `sources` | which artifact a file is, and what its coverage status is |
//! | `rules` | classification: what one framed record said |
//! | `reducer` | keying and reduction into an immutable snapshot |
//! | `findings` | [`derive_findings`], one `push_*` rule at a time |
//! | `redaction` | the deterministic default-safe export projection |
//!
//! # Relationship to the older IME modules
//!
//! `intune::event_tracker`, `intune::download_stats`, and `intune::timeline`
//! keep their public APIs and their current behavior; nothing here changes what
//! they return, and existing consumers are unaffected. This module is the
//! canonical *transaction* view and owns that behavior alone. It adds no second
//! raw CCM parser, and it does not keep parallel copies of shared vocabulary:
//! the content-download phrases are consumed from `download_stats` and the GUID
//! shape from `guid_registry`, so one grammar owns each set of words. Where a
//! primitive is deliberately not reused (the retry vocabulary), the reason is
//! documented at the call site in `rules`.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::windows::win32::{
//!     analyze_win32_bundle, derive_findings, Win32Outcome, Win32SourceInput,
//! };
//!
//! let app = "11111111-2222-4333-8444-555555555555";
//! let workload = format!(
//!     concat!(
//!         r#"<![LOG[[Win32App] Processing app policy for app with id: {app}]LOG]!>"#,
//!         r#"<time="10:15:22.100+000" date="7-31-2026" component="Win32App" "#,
//!         r#"context="" type="1" thread="12" file="">"#,
//!         "\n",
//!         r#"<![LOG[[Win32App] Installation is done for app with id: {app}, exit code: 0]LOG]!>"#,
//!         r#"<time="10:16:04.900+000" date="7-31-2026" component="Win32App" "#,
//!         r#"context="" type="1" thread="12" file="">"#,
//!     ),
//!     app = app,
//! );
//!
//! let analysis = analyze_win32_bundle(&[Win32SourceInput::captured(
//!     "app-workload",
//!     "AppWorkload.log",
//!     workload,
//! )]);
//!
//! assert_eq!(analysis.transactions.len(), 1);
//! assert_eq!(analysis.transactions[0].key.app_id, app);
//! assert_eq!(analysis.transactions[0].outcome, Win32Outcome::Succeeded);
//!
//! // Every finding cites the exact records it was drawn from.
//! for finding in derive_findings(&analysis) {
//!     assert!(finding.is_evidence_backed());
//! }
//! ```

// Private modules with one curated public surface, matching the family shape.
// Every name below is reachable at exactly one path (`win32::Name`); the
// previous `pub mod` layout published every item at two paths.
mod findings;
mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use findings::derive_findings;
pub use models::*;
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::{analyze_win32_bundle, analyze_win32_bundle_with, Win32AnalysisOptions};
pub use rules::{classify_record, RecordClassification};
pub use sources::{candidate_source_kind, classify_artifact, Win32SourceInput};
