//! Primitives shared by the Intune Windows workload analyzers.
//!
//! Each analyzer owns its own state machine, because a platform script, a
//! remediation pair, and a Win32 installer reach terminal states for different
//! reasons. What they legitimately share is lower-level machinery -- privacy
//! masking, for now -- and that lives here so there is a single owner.

mod redaction;

pub use redaction::{redact_text, sid_occurrences};
