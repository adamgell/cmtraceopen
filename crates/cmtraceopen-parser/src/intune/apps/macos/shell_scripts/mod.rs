//! Intune macOS shell-script execution evidence.
//!
//! Owner: issue #361 of epic #356. Implementation pending.
//!
//! Shares a raw record parser with package deployment, but reduces separately because script phases and terminal semantics differ.
//!
//! This is a reserved slot created by the parser-family skeleton so that issue
//! #361 can be implemented without editing any file shared with a sibling issue.
//! Add source classification, reduction, and findings submodules here, and
//! consume the shared contracts in [`crate::intune::evidence`].
