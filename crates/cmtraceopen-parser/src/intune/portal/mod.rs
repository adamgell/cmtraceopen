//! Company Portal evidence surfaces, grouped by platform.
//!
//! Company Portal is a first-class Intune surface because it spans sign-in,
//! enrollment, app catalog, compliance, sync, device actions, and support. It
//! is deliberately kept out of the IME and ESP module trees even where the
//! workflows overlap, so a Company Portal artifact is never attributed to an
//! agent that did not write it.

pub mod windows;
