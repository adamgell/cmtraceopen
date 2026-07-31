//! Company Portal parser surfaces, grouped by platform.
//!
//! Company Portal is a first-class `intune::portal` surface rather than a
//! variant of the IME or ESP pipelines: it spans sign-in, enrollment, the app
//! catalog, compliance, sync, device actions, and support, and those artifacts
//! must keep their own identity instead of being folded into a neighbouring
//! workflow.

pub mod macos;
