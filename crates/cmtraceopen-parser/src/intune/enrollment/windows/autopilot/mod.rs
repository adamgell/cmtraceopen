//! Windows Autopilot identity, profile, and OOBE evidence outside ESP.
//!
//! Owner: issue #362 of epic #356. Implementation pending.
//!
//! ESP remains a sibling reducer in `crate::esp` and may be correlated through explicit enrollment/session keys; it is not renamed into Autopilot.
//!
//! This is a reserved slot created by the parser-family skeleton so that issue
//! #362 can be implemented without editing any file shared with a sibling issue.
//! Add source classification, reduction, and findings submodules here, and
//! consume the shared contracts in [`crate::intune::evidence`].
