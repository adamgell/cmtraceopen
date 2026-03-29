/// Default evidence bundle primary entry point directories.
///
/// When a bundle manifest does not specify entry points, these directories
/// are checked for evidence artifacts.
pub const DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS: &[&str] = &[
    "evidence/logs",
    "evidence/registry",
    "evidence/event-logs",
    "evidence/exports",
    "evidence/screenshots",
    "evidence/command-output",
];
