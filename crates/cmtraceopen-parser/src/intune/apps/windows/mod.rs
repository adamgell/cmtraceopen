//! Windows-side Intune workload analyzers.
//!
//! These modules are pure: they consume artifacts the caller already read and
//! decoded, and they never touch the filesystem, registry, or network.

pub mod scripts;
