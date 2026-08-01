//! Company Portal evidence surfaces.
//!
//! Company Portal spans sign-in, enrollment, the app catalog, compliance, sync,
//! device actions, and support, so it is a first-class surface rather than a
//! sub-case of IME or ESP. Platform-specific contracts live under the matching
//! platform module.

pub mod android;
pub mod ios_ipados;
pub mod macos;
pub mod windows;
