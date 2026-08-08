mod correlation;
mod models;
mod normalize;
mod redaction;
mod reducer;
mod rules;
mod timeline;

pub use correlation::*;
pub use models::*;
pub use normalize::*;
pub use redaction::*;
pub use reducer::*;
pub use rules::*;
pub use timeline::*;

// Crate-internal: the free-text redaction pipeline is evidence-agnostic, so
// other evidence modules reuse it rather than growing a second rule table that
// could drift out of step with this one. Not part of the published API.
pub(crate) use redaction::redact_text;
