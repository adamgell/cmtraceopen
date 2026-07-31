//! Versioned capture schema for Windows Company Portal / Authenticator AppX
//! package state.
//!
//! The canonical input is JSON emitted by a native Windows adapter. Human
//! formatted PowerShell output (`Format-List`) is *not* a protocol: its field
//! order, labels, wrapping, and truncation all vary by locale and host version.
//! Everything in this module therefore describes the JSON envelope, and the
//! legacy text adapter in [`super::legacy`] is explicitly experimental.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::wire::raw_preserving_string_enum;

/// Rebuild a preserved JSON blob with object keys in sorted order.
///
/// `serde_json::Map` is a `BTreeMap` by default but an insertion-ordered
/// `IndexMap` whenever anything in the build graph enables serde_json's
/// `preserve_order` feature. Cargo unifies features across a workspace, so this
/// crate cannot control which one it is compiled against: in the workspace build
/// `evtx` turns `preserve_order` on, while a standalone
/// `cargo test -p cmtraceopen-parser` leaves it off.
///
/// Serialization of this schema is a golden-tested contract, so every blob that
/// reaches a `Value` is canonicalized on the way in and the bytes come out the
/// same under either build. Only key *order* is normalized; no key or value is
/// added, dropped, or rewritten.
pub(super) fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(entries) => {
            let mut sorted: Vec<(String, Value)> = entries.into_iter().collect();
            sorted.sort_by(|(left, _), (right, _)| left.cmp(right));
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, nested)| (key, canonical_json(nested)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

/// Wire version of the capture envelope.
///
/// Breaking changes to the capture shape require an explicit bump. Readers stay
/// tolerant of this version forever; a higher version is reported as
/// [`super::PackageStateFindingKind::UnsupportedSchema`] rather than an error.
pub const COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION: u32 = 1;

raw_preserving_string_enum! {
    /// Outcome of the adapter command that produced the capture.
    pub enum PackageCaptureCommandStatus {
        Completed => "completed",
        Failed => "failed",
        AccessDenied => "accessDenied",
        TimedOut => "timedOut",
        Capped => "capped",
        NotRun => "notRun",
    }
}

raw_preserving_string_enum! {
    /// How the capture reached the parser.
    pub enum PackageCaptureSource {
        Json => "json",
        LegacyFormatList => "legacyFormatList",
    }
}

raw_preserving_string_enum! {
    /// Registration scope a package row was observed in.
    ///
    /// Per-user registration is expressed as [`PackageScope::CurrentUser`], never
    /// as a raw username.
    pub enum PackageScope {
        CurrentUser => "currentUser",
        AllUsers => "allUsers",
        Provisioned => "provisioned",
    }
}

raw_preserving_string_enum! {
    /// How completely the adapter managed to enumerate one scope.
    pub enum PackageScopeCoverageStatus {
        Complete => "complete",
        Partial => "partial",
        Denied => "denied",
        Failed => "failed",
        NotQueried => "notQueried",
    }
}

raw_preserving_string_enum! {
    pub enum PackageArchitecture {
        X86 => "x86",
        X64 => "x64",
        Arm => "arm",
        Arm64 => "arm64",
        Neutral => "neutral",
    }
}

raw_preserving_string_enum! {
    pub enum PackageSignatureKind {
        Store => "store",
        System => "system",
        Enterprise => "enterprise",
        Developer => "developer",
        None => "none",
    }
}

raw_preserving_string_enum! {
    /// AppX package health as reported by the platform.
    pub enum PackageStatus {
        Ok => "ok",
        Modified => "modified",
        Tampered => "tampered",
        LicenseIssue => "licenseIssue",
        NeedsRemediation => "needsRemediation",
        NotAvailable => "notAvailable",
    }
}

raw_preserving_string_enum! {
    pub enum PackageInstallState {
        Installed => "installed",
        Staged => "staged",
        NotInstalled => "notInstalled",
        NeedsRemediation => "needsRemediation",
    }
}

raw_preserving_string_enum! {
    /// Which Intune portal app a package row belongs to.
    pub enum PortalApp {
        CompanyPortal => "companyPortal",
        Authenticator => "authenticator",
        Other => "other",
    }
}

/// Privacy classification for a scalar that may carry identity or path data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PackageStateSensitivity {
    Public,
    Sensitive,
    Restricted,
}

/// A string plus the privacy classification the redaction projection acts on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageStateClassifiedString {
    pub value: String,
    pub sensitivity: PackageStateSensitivity,
}

impl PackageStateClassifiedString {
    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PackageStateSensitivity::Sensitive,
        }
    }

    pub fn restricted(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PackageStateSensitivity::Restricted,
        }
    }
}

/// Per-scope enumeration coverage. Absence is only claimable against a scope
/// whose status is [`PackageScopeCoverageStatus::Complete`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageScopeCoverage {
    pub scope: PackageScope,
    pub status: PackageScopeCoverageStatus,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Adapter-reported failure detail. The message can quote paths or account
/// names, so it is treated as sensitive by the redaction projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageCaptureError {
    #[serde(default)]
    pub code: Option<String>,
    pub message: String,
}

/// Provenance and coverage of one capture run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct PackageStateCaptureMetadata {
    pub captured_at_utc: String,
    pub adapter_version: String,
    pub command_status: PackageCaptureCommandStatus,
    pub windows_build: Option<String>,
    pub power_shell_version: Option<String>,
    pub locale: Option<String>,
    pub source: PackageCaptureSource,
    pub scope_coverage: Vec<PackageScopeCoverage>,
    pub error: Option<PackageCaptureError>,
}

impl Default for PackageStateCaptureMetadata {
    fn default() -> Self {
        Self {
            captured_at_utc: String::new(),
            adapter_version: String::new(),
            command_status: PackageCaptureCommandStatus::NotRun,
            windows_build: None,
            power_shell_version: None,
            locale: None,
            source: PackageCaptureSource::Json,
            scope_coverage: Vec::new(),
            error: None,
        }
    }
}

impl PackageStateCaptureMetadata {
    /// Coverage entry for one scope, if the adapter reported that scope.
    pub fn coverage_for(&self, scope: &PackageScope) -> Option<&PackageScopeCoverage> {
        self.scope_coverage
            .iter()
            .find(|coverage| &coverage.scope == scope)
    }

    /// Scopes the adapter proved it fully enumerated.
    pub fn complete_scopes(&self) -> Vec<PackageScope> {
        self.scope_coverage
            .iter()
            .filter(|coverage| coverage.status == PackageScopeCoverageStatus::Complete)
            .map(|coverage| coverage.scope.clone())
            .collect()
    }
}

/// One AppX package registration observed by the adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct PackageRow {
    pub name: String,
    pub family_name: String,
    pub full_name: String,
    pub version: String,
    pub architecture: PackageArchitecture,
    pub publisher: Option<String>,
    pub signature_kind: PackageSignatureKind,
    pub status: PackageStatus,
    pub install_state: PackageInstallState,
    pub scopes: Vec<PackageScope>,
    /// Opaque count of per-user registrations. Deliberately not a user list.
    pub user_registration_count: Option<u32>,
    /// Present only when an adapter supplied an identifier despite the schema
    /// discouraging it. Always classified and always masked on export.
    pub user_identifier: Option<PackageStateClassifiedString>,
    /// Filesystem path, so privacy-sensitive.
    pub install_location: Option<PackageStateClassifiedString>,
    pub app: PortalApp,
    /// Adapter fields this schema version does not recognize, preserved verbatim.
    pub raw: Option<serde_json::Value>,
}

impl Default for PackageRow {
    fn default() -> Self {
        Self {
            name: String::new(),
            family_name: String::new(),
            full_name: String::new(),
            version: String::new(),
            architecture: PackageArchitecture::Unknown(String::new()),
            publisher: None,
            signature_kind: PackageSignatureKind::Unknown(String::new()),
            status: PackageStatus::Unknown(String::new()),
            install_state: PackageInstallState::Unknown(String::new()),
            scopes: Vec::new(),
            user_registration_count: None,
            user_identifier: None,
            install_location: None,
            app: PortalApp::Other,
            raw: None,
        }
    }
}

/// Field names this schema version consumes from a package row. Anything else
/// an adapter emits is folded into [`PackageRow::raw`] rather than dropped.
pub(super) const KNOWN_PACKAGE_ROW_FIELDS: &[&str] = &[
    "name",
    "familyName",
    "fullName",
    "version",
    "architecture",
    "publisher",
    "signatureKind",
    "status",
    "installState",
    "scopes",
    "userRegistrationCount",
    "userIdentifier",
    "installLocation",
    "app",
    "raw",
];

/// A complete package-state capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct PackageStateCapture {
    pub schema_version: u32,
    pub capture: PackageStateCaptureMetadata,
    pub packages: Vec<PackageRow>,
    /// Whole source document, retained only when the schema version is newer
    /// than this build understands so nothing is lost across the gap.
    pub raw_document: Option<serde_json::Value>,
}

impl Default for PackageStateCapture {
    fn default() -> Self {
        Self {
            schema_version: COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
            capture: PackageStateCaptureMetadata::default(),
            packages: Vec::new(),
            raw_document: None,
        }
    }
}

impl PackageStateCapture {
    /// True when this build cannot interpret the capture body.
    pub fn is_unsupported_schema(&self) -> bool {
        self.schema_version > COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION
    }

    /// Package rows classified as the given portal app.
    pub fn rows_for_app(&self, app: &PortalApp) -> Vec<(usize, &PackageRow)> {
        self.packages
            .iter()
            .enumerate()
            .filter(|(_, row)| &row.app == app)
            .collect()
    }
}

/// A version expectation supplied by the caller from some other evidence
/// source. The parser never invents or looks up an expected version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedPackageFact {
    pub app: PortalApp,
    /// Optional narrowing to one package family, when the caller knows it.
    #[serde(default)]
    pub family_name: Option<String>,
    pub expected_version: String,
    /// Where the expectation came from, echoed into the finding message.
    pub source: String,
}

/// Failure modes of [`super::parse_package_state_capture`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackageStateError {
    #[error("package state capture is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("package state capture must be a JSON object, found {0}")]
    NotAnObject(String),
    #[error("package state capture is missing a numeric schemaVersion")]
    MissingSchemaVersion,
    #[error("package state capture body does not match schema version {version}: {detail}")]
    InvalidBody { version: u32, detail: String },
}
