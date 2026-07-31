//! Versioned identity of the normalized Apple unified-log capture schema, plus
//! the conservative source-selection tables the pure crate is allowed to trust.
//!
//! # Native / pure boundary
//!
//! Everything in this module describes a *contract*, not a collection
//! mechanism. Collection lives in macOS-only native code (`src-tauri`), which
//! runs `log show --predicate <p> --style ndjson` and emits records shaped like
//! [`crate::intune::portal::macos::company_portal::unified_log::models`]. This
//! crate never shells out, never touches the filesystem, and never decodes
//! `.tracev3`; it validates and reduces whatever the collector supplies.

/// Stable identifier of the normalized capture schema.
///
/// A capture whose `schemaId` is anything else is refused as
/// [`super::models::PortalCoverageStatus::UnknownSchema`] rather than guessed at.
pub const PORTAL_UNIFIED_LOG_SCHEMA_ID: &str =
    "cmtraceopen.intune.portal.macos.companyPortal.unifiedLog";

/// Schema version this build emits and fully understands.
pub const PORTAL_UNIFIED_LOG_SCHEMA_VERSION: u32 = 1;

/// Lowest schema version this build still reduces.
pub const PORTAL_UNIFIED_LOG_MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Identifier of the native collection preset that produced a capture.
///
/// Mirrors the `intune-agent` preset id in the native macOS unified-log adapter.
pub const PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE_ID: &str = "intune-agent";

/// The verbatim `log show` predicate used by the native `intune-agent` preset.
///
/// Recorded in capture provenance so a reduction is reproducible: a consumer can
/// tell exactly which slice of the unified log the records were drawn from.
/// This is a *collection* predicate. It is deliberately broader than the
/// selection rules below, which decide what counts as Company Portal evidence.
pub const PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE: &str =
    r#"process == "IntuneMdmAgent" OR process == "IntuneMdmDaemon" OR process == "CompanyPortal""#;

/// Version of the in-crate selection predicate (the verified source tables
/// below). Bump whenever [`PORTAL_VERIFIED_SOURCES`] changes so stored
/// reductions remain interpretable.
pub const PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION: u32 = 1;

/// Identifier of the redaction policy applied by [`super::redaction`].
pub const PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID: &str = "cmtraceopen.portal.macos.unifiedLog.v1";

/// Placeholder style emitted by [`super::redaction`]: `[redacted:<category>]`.
pub const PORTAL_UNIFIED_LOG_REDACTION_PLACEHOLDER_STYLE: &str = "bracketed-category";

/// One verified (process, subsystem) pair that may originate Company Portal
/// evidence.
///
/// # Why a pair and not a process name
///
/// A process name on its own is *not* sufficient evidence. Process names are
/// not namespaced, are trivially spoofable by any unsigned binary a user drops
/// on disk, and the native collection predicate already matches on process
/// alone. Requiring a Microsoft-owned subsystem alongside the process is the
/// conservative half of the contract. The word `CompanyPortal` appearing inside
/// a free-text `eventMessage` is never considered at all.
///
/// Extend this table only with values confirmed against a real capture; an
/// unrecognised subsystem degrades to
/// [`super::models::PortalSelectionReason::ProcessOnlyInsufficient`], which is
/// visible coverage rather than a silent guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalVerifiedSource {
    /// Unified-log `process` value (leaf of `processImagePath`).
    pub process: &'static str,
    /// Unified-log `subsystem` value owned by that process.
    pub subsystem: &'static str,
}

/// Verified process/subsystem pairs accepted as Company Portal sources.
pub const PORTAL_VERIFIED_SOURCES: &[PortalVerifiedSource] = &[
    PortalVerifiedSource {
        process: "CompanyPortal",
        subsystem: "com.microsoft.CompanyPortalMac",
    },
    PortalVerifiedSource {
        process: "IntuneMdmAgent",
        subsystem: "com.microsoft.intune.mdm.agent",
    },
    PortalVerifiedSource {
        process: "IntuneMdmDaemon",
        subsystem: "com.microsoft.intune.mdm.daemon",
    },
];

/// Processes named by the native collection predicate.
///
/// Membership here is necessary but *never* sufficient for selection; it only
/// distinguishes "in scope of the capture but unverified" from "unrelated".
pub const PORTAL_CAPTURE_PROCESSES: &[&str] =
    &["CompanyPortal", "IntuneMdmAgent", "IntuneMdmDaemon"];

/// Returns the verified source entry for a process/subsystem pair, if any.
///
/// Process matching is case-sensitive (unified-log process names are exact);
/// subsystem matching is ASCII-case-insensitive because reverse-DNS subsystem
/// identifiers are not case-significant.
pub fn verified_source(process: &str, subsystem: &str) -> Option<&'static PortalVerifiedSource> {
    PORTAL_VERIFIED_SOURCES
        .iter()
        .find(|entry| entry.process == process && entry.subsystem.eq_ignore_ascii_case(subsystem))
}

/// True when a process is named by the native collection predicate.
pub fn is_capture_process(process: &str) -> bool {
    PORTAL_CAPTURE_PROCESSES.contains(&process)
}

/// True when the supplied predicate text is the known `intune-agent` preset.
pub fn is_known_capture_predicate(predicate: &str) -> bool {
    predicate.trim() == PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE
}

/// True when this build can reduce the supplied schema version.
pub fn is_supported_schema_version(version: u32) -> bool {
    (PORTAL_UNIFIED_LOG_MIN_SUPPORTED_SCHEMA_VERSION..=PORTAL_UNIFIED_LOG_SCHEMA_VERSION)
        .contains(&version)
}
