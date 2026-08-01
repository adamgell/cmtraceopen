//! Intune Windows platform-script execution evidence.
//!
//! This is a **semantic analyzer over supplied IME evidence**, not a log
//! format. Raw records are framed by the shared CCM parser first
//! ([`crate::intune::ime_parser`]); only then are signals classified and
//! reduced. The module performs no I/O of any kind.
//!
//! Platform scripts have a deliberately separate public lifecycle from
//! remediations and from Win32 installers, because their phases and terminal
//! semantics differ. A `HealthScripts` record is remediation evidence and is
//! never classified into a platform-script signal here.
//!
//! What the analyzer will not do:
//!
//! - promote a nonzero exit code to a root cause; it is an execution outcome;
//! - let a timeout or exit record terminate a transaction it cannot be keyed to;
//! - merge two executions on timestamp, display name, or a shared
//!   `AgentExecutor` component;
//! - treat a missing output artifact as proof that a script produced no output.
//!
//! ```
//! use cmtraceopen_parser::intune::apps::windows::scripts::{
//!     analyze_script_bundle, ScriptSourceInput,
//! };
//!
//! let agent_executor = concat!(
//!     r#"<![LOG[Starting Powershell Execution]LOG]!><time="10:15:22.100+000" "#,
//!     r#"date="3-12-2026" component="AgentExecutor" context="" type="1" thread="12" file="">"#,
//!     "\n",
//!     r#"<![LOG[Powershell script is: C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\11111111-2222-3333-4444-555555555555_66666666-7777-8888-9999-000000000000.ps1]LOG]!><time="10:15:22.200+000" "#,
//!     r#"date="3-12-2026" component="AgentExecutor" context="" type="1" thread="12" file="">"#,
//!     "\n",
//!     r#"<![LOG[Powershell execution is done, exitCode = 0]LOG]!><time="10:15:31.900+000" "#,
//!     r#"date="3-12-2026" component="AgentExecutor" context="" type="1" thread="12" file="">"#,
//! );
//!
//! let analysis = analyze_script_bundle(&[ScriptSourceInput {
//!     artifact_id: "agent-executor".to_string(),
//!     file_name: "AgentExecutor.log".to_string(),
//!     file_path: None,
//!     content: agent_executor.to_string(),
//! }]);
//!
//! assert_eq!(analysis.transactions.len(), 1);
//! assert_eq!(
//!     analysis.transactions[0].key.policy_id,
//!     "11111111-2222-3333-4444-555555555555"
//! );
//! ```

mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use crate::intune::apps::windows::common::redact_text;
pub use models::*;
pub use redaction::redacted_export_projection;
pub use reducer::analyze_script_bundle;
pub use rules::{classify_record, RecordClassification};
pub use sources::{candidate_source_kind, classify_artifact, ScriptSourceInput};
