//! Intune Windows remediation (detection + remediation pair) evidence.
//!
//! This is a **semantic analyzer over supplied IME evidence**, not a log
//! format. Raw records are framed by the shared CCM parser first
//! ([`crate::intune::ime_parser`]); only then are signals classified and
//! reduced. The module performs no I/O of any kind.
//!
//! Remediations have a deliberately separate public lifecycle from platform
//! scripts (issue #359) because they are a *pair*: detection decides whether
//! anything is wrong, and remediation runs only if it was.
//!
//! The one rule everything else rests on: **an exit code with no stage
//! terminates nothing.** `0` means "compliant" from a detection script and
//! "succeeded" from a remediation script. Attributing a code to the wrong half
//! inverts the diagnosis, so a record that does not name its stage yields no
//! exit token at all.
//!
//! What the analyzer will not do:
//!
//! - pool detection and remediation outcomes, or read one stage's exit code
//!   with the other stage's semantics;
//! - join a detection to a remediation because they occurred near each other;
//! - treat a missing output artifact as proof that a script produced no output;
//! - repair a malformed embedded JSON payload, or concatenate payload fragments
//!   across records to close a brace;
//! - interpret an exit code using a stage the record did not state itself.
//!
//! That last one is a deliberate asymmetry and is worth spelling out. A record
//! may *inherit* its block's stage for routing, so a completion line is filed
//! under the right half. It may not inherit a stage for *interpretation*: the
//! exit token is only built when the record's own text named the stage. A
//! block boundary is inferred, and an inferred boundary that is wrong would
//! turn "compliant" into "succeeded" silently. Routing a record to the wrong
//! stage costs an unresolved half; interpreting a code under the wrong stage
//! costs an inverted diagnosis, so only the first is allowed to rest on
//! inference.

mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use models::*;
pub use redaction::redacted_export_projection;
pub use reducer::analyze_remediation_bundle;
pub use rules::{classify_record, RecordClassification};
pub use sources::{candidate_source_kind, classify_artifact, RemediationSourceInput};
