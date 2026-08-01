//! macOS Company Portal saved diagnostic reports.
//!
//! Owner: issue #369 of epic #356. Implementation pending.
//!
//! Separate from direct app logs because the saved report may be an archive or multi-artifact package with its own schema. Archive I/O stays outside the pure parser.
//!
//! This is a reserved slot created by the parser-family skeleton so that issue
//! #369 can be implemented without editing any file shared with a sibling issue.
//! Add source classification, reduction, and findings submodules here, and
//! consume the shared contracts in [`crate::intune::evidence`].
