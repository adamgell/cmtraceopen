//! Canonical, evidence-backed analyzers for Intune app and script workloads.
//!
//! Each leaf owns one workload lifecycle. They deliberately do not share a
//! single "app" state machine, because a platform script, a remediation pair,
//! and a Win32 installer reach terminal states for different reasons.

pub mod windows;
