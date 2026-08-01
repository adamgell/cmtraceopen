//! Machinery shared by the two Intune macOS app leaves of issue #361.
//!
//! Issue #361 requires a **single** raw record parser and **separate** package
//! and shell-script reducers. That asymmetry is why this module exists and why
//! it lives inside the `pkg` leaf rather than beside the two leaves: the parser
//! family's namespace `mod.rs` files are owned by the skeleton, so a shared
//! sibling module could not be added without editing a file this issue does not
//! own.
//!
//! `pkg` is therefore the declared owner of the raw grammar, and
//! [`crate::intune::apps::macos::shell_scripts`] consumes it from here. Nothing
//! in this module knows anything about packages specifically; a future move to a
//! neutral location is a pure path change.

pub mod agent_log;
pub mod fields;
pub mod redaction;
