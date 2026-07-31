//! macOS Company Portal artifacts.
//!
//! `logs` covers the direct application log files discovered under
//! `~/Library/Logs/CompanyPortal`. Saved diagnostic reports and Apple
//! unified-log exports are deliberately *not* handled here; they are distinct
//! source kinds and are rejected by this parser's detection.

pub mod logs;
