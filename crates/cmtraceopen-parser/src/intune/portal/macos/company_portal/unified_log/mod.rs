//! Apple unified-log records relevant to Company Portal.
//!
//! Owner: issue #370 of epic #356. Implementation pending.
//!
//! Consumes normalized records; it does not run `log show` or decode the binary `.tracev3` store in the pure crate.
//!
//! This is a reserved slot created by the parser-family skeleton so that issue
//! #370 can be implemented without editing any file shared with a sibling issue.
//! Add source classification, reduction, and findings submodules here, and
//! consume the shared contracts in [`crate::intune::evidence`].
