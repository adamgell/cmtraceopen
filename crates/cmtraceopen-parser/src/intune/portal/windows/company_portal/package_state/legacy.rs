//! Experimental import of legacy PowerShell `Format-List` package output.
//!
//! `Format-List` is a *display* rendering, not a protocol. Its labels are
//! localized, long values wrap onto continuation lines, and wide consoles
//! truncate. This adapter therefore refuses far more readily than it parses:
//! a refusal is an explicit outcome, distinguishable from "captured nothing",
//! so a caller can never mistake a failed read for evidence of absence.
//!
//! Anything imported here is stamped
//! [`PackageCaptureSource::LegacyFormatList`] and its scope coverage is
//! `partial`, which structurally prevents an absence finding.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::models::{
    canonical_json, PackageArchitecture, PackageCaptureCommandStatus, PackageCaptureSource,
    PackageInstallState, PackageRow, PackageScope, PackageScopeCoverage,
    PackageScopeCoverageStatus, PackageSignatureKind, PackageStateCapture,
    PackageStateCaptureMetadata, PackageStateClassifiedString, PackageStatus, PortalApp,
    COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
};

/// Metadata the caller must supply before a legacy text import is attempted.
///
/// `locale` is required rather than optional-with-a-guess: English field labels
/// cannot be assumed for output produced under another UI culture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LegacyImportMetadata {
    pub locale: Option<String>,
    pub adapter_version: String,
    pub captured_at_utc: String,
    #[serde(default)]
    pub windows_build: Option<String>,
    #[serde(default)]
    pub power_shell_version: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LegacyRefusalReason {
    /// No locale was declared, so the labels cannot be trusted to be English.
    MissingLocale,
    /// A non-English locale was declared; the labels are localized.
    UnsupportedLocale,
    /// A line could not be resolved into exactly one label/value pair, which is
    /// what wrapping and truncation look like.
    AmbiguousRecord,
    /// A record was recognizable as a record but lacked the identifying label.
    IncompleteRecord,
    /// Nothing in the text looked like `Format-List` output at all.
    NoRecognizableRecords,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LegacyRefusal {
    pub reason: LegacyRefusalReason,
    pub detail: String,
    pub locale: Option<String>,
    /// 1-based source line the adapter gave up on, when it can point at one.
    pub line_number: Option<usize>,
}

/// Outcome of a legacy import. `Refused` is deliberately a distinct variant
/// from an imported-but-empty capture.
///
/// The capture is boxed because it dwarfs the refusal; `clippy::large_enum_variant`
/// rejects the unboxed form under this repo's `-D warnings` gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LegacyImportOutcome {
    Imported(Box<PackageStateCapture>),
    Refused(LegacyRefusal),
}

impl LegacyImportOutcome {
    pub fn imported(&self) -> Option<&PackageStateCapture> {
        match self {
            Self::Imported(capture) => Some(capture),
            Self::Refused(_) => None,
        }
    }

    pub fn refusal(&self) -> Option<&LegacyRefusal> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Imported(_) => None,
        }
    }
}

/// Import legacy `Format-List` text, or refuse with a reason.
pub fn import_legacy_format_list(
    text: &str,
    metadata: LegacyImportMetadata,
) -> LegacyImportOutcome {
    let Some(locale) = metadata.locale.as_deref() else {
        return refuse(
            LegacyRefusalReason::MissingLocale,
            "Legacy Format-List import requires a declared locale; field labels are localized.",
            &metadata,
            None,
        );
    };
    if !is_english_locale(locale) {
        return refuse(
            LegacyRefusalReason::UnsupportedLocale,
            &format!(
                "Locale '{locale}' is not English, so the English field labels this adapter \
                 understands cannot be assumed."
            ),
            &metadata,
            None,
        );
    }

    let mut records: Vec<LegacyRecord> = Vec::new();
    let mut current = LegacyRecord::default();

    for (offset, line) in text.lines().enumerate() {
        let line_number = offset + 1;
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }

        match split_label_value(line) {
            Some((label, value)) => current.push(label, value, line_number),
            None => {
                // A line that is neither blank nor a label/value pair is a
                // wrapped continuation or a truncated value. Either way the
                // original value cannot be reconstructed, so do not guess.
                // Locate the line, never quote it. The refusal detail is
                // free text that no redaction projection covers, and a
                // Format-List line can carry an install path or an account.
                return refuse(
                    LegacyRefusalReason::AmbiguousRecord,
                    &format!(
                        "Line {line_number} is not a complete label/value pair ({} characters), \
                         which indicates wrapped or truncated Format-List output.",
                        line.trim().chars().count()
                    ),
                    &metadata,
                    Some(line_number),
                );
            }
        }
    }
    if !current.is_empty() {
        records.push(current);
    }

    if records.is_empty() {
        return refuse(
            LegacyRefusalReason::NoRecognizableRecords,
            "No Format-List records were recognized in the supplied text.",
            &metadata,
            None,
        );
    }

    let mut packages = Vec::with_capacity(records.len());
    for record in &records {
        match record.to_row() {
            Ok(row) => packages.push(row),
            Err((reason, detail, line_number)) => {
                return refuse(reason, &detail, &metadata, line_number)
            }
        }
    }

    LegacyImportOutcome::Imported(Box::new(PackageStateCapture {
        schema_version: COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
        capture: PackageStateCaptureMetadata {
            captured_at_utc: metadata.captured_at_utc,
            adapter_version: metadata.adapter_version,
            command_status: PackageCaptureCommandStatus::Completed,
            windows_build: metadata.windows_build,
            power_shell_version: metadata.power_shell_version,
            locale: metadata.locale,
            source: PackageCaptureSource::LegacyFormatList,
            // Display output cannot prove which scopes were enumerated, so
            // coverage stays partial and absence stays unclaimable.
            scope_coverage: vec![PackageScopeCoverage {
                scope: PackageScope::AllUsers,
                status: PackageScopeCoverageStatus::Partial,
                detail: Some(
                    "Imported from legacy Format-List text, which does not report scope coverage."
                        .to_string(),
                ),
            }],
            error: None,
        },
        packages,
        raw_document: None,
    }))
}

fn refuse(
    reason: LegacyRefusalReason,
    detail: &str,
    metadata: &LegacyImportMetadata,
    line_number: Option<usize>,
) -> LegacyImportOutcome {
    LegacyImportOutcome::Refused(LegacyRefusal {
        reason,
        detail: detail.to_string(),
        locale: metadata.locale.clone(),
        line_number,
    })
}

fn is_english_locale(locale: &str) -> bool {
    let language = locale
        .split(['-', '_'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    language == "en"
}

/// Split `Label : value` without mistaking a colon inside a value (a drive
/// path, a `CN=` publisher) for the separator. `Format-List` always pads the
/// separator with a space on each side.
fn split_label_value(line: &str) -> Option<(String, String)> {
    if line.starts_with(char::is_whitespace) {
        // Continuation lines are indented under the value column.
        return None;
    }
    let (label, value) = line.split_once(" : ").or_else(|| {
        // A label with an empty value renders as "Label :" with no trailing
        // space; accept that, but nothing looser.
        line.strip_suffix(" :").map(|label| (label, ""))
    })?;
    let label = label.trim();
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ') {
        return None;
    }
    Some((label.to_string(), value.trim_end().to_string()))
}

#[derive(Debug, Default)]
struct LegacyRecord {
    fields: Vec<(String, String)>,
    first_line: usize,
}

impl LegacyRecord {
    fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    fn push(&mut self, label: String, value: String, line_number: usize) {
        if self.fields.is_empty() {
            self.first_line = line_number;
        }
        self.fields.push((label, value));
    }

    fn get(&self, label: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(label))
            .map(|(_, value)| value.as_str())
    }

    fn to_row(&self) -> Result<PackageRow, (LegacyRefusalReason, String, Option<usize>)> {
        // `get` returns the first match and unknown labels overwrite in `raw`,
        // so two records that lost their blank separator would silently
        // collapse into one row carrying the first Name and a mixture of both
        // records' fields. This module refuses wrapped and truncated input
        // precisely so a bad read never looks like a good one; a repeated
        // identifying label is the same class of problem.
        let name_count = self
            .fields
            .iter()
            .filter(|(label, _)| label.eq_ignore_ascii_case("Name"))
            .count();
        if name_count > 1 {
            return Err((
                LegacyRefusalReason::AmbiguousRecord,
                format!(
                    "Record starting at line {} repeats the 'Name' label {name_count} times, \
                     which indicates two records merged by a missing blank separator.",
                    self.first_line
                ),
                Some(self.first_line),
            ));
        }

        let name = self.get("Name").filter(|value| !value.is_empty()).ok_or((
            LegacyRefusalReason::IncompleteRecord,
            format!(
                "Record starting at line {} has no usable 'Name' label.",
                self.first_line
            ),
            Some(self.first_line),
        ))?;

        let full_name = self.get("PackageFullName").unwrap_or_default().to_string();
        let (derived_family, derived_architecture) = derive_from_full_name(&full_name);

        let mut raw = Map::new();
        for (label, value) in &self.fields {
            if !LEGACY_KNOWN_LABELS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(label))
            {
                raw.insert(label.clone(), Value::String(value.clone()));
            }
        }

        Ok(PackageRow {
            name: name.to_string(),
            family_name: self
                .get("PackageFamilyName")
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or(derived_family)
                .unwrap_or_else(|| name.to_string()),
            full_name,
            version: self.get("Version").unwrap_or_default().to_string(),
            architecture: self
                .get("Architecture")
                .filter(|value| !value.is_empty())
                .map(camel_case_enum::<PackageArchitecture>)
                .or(derived_architecture)
                .unwrap_or_else(|| PackageArchitecture::Unknown(String::new())),
            publisher: self
                .get("Publisher")
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            signature_kind: camel_case_enum::<PackageSignatureKind>(
                self.get("SignatureKind").unwrap_or_default(),
            ),
            status: camel_case_enum::<PackageStatus>(self.get("Status").unwrap_or_default()),
            // Display text says nothing about per-user install state, and
            // inventing one would be a false fact.
            install_state: PackageInstallState::Unknown(String::new()),
            scopes: Vec::new(),
            user_registration_count: None,
            user_identifier: None,
            install_location: self
                .get("InstallLocation")
                .filter(|value| !value.is_empty())
                .map(PackageStateClassifiedString::sensitive),
            app: classify_app(name),
            raw: (!raw.is_empty()).then(|| canonical_json(Value::Object(raw))),
        })
    }
}

const LEGACY_KNOWN_LABELS: &[&str] = &[
    "Name",
    "PackageFamilyName",
    "PackageFullName",
    "Version",
    "Architecture",
    "Publisher",
    "SignatureKind",
    "Status",
    "InstallLocation",
];

/// `Name_Version_Architecture__PublisherId` is the documented AppX full-name
/// shape, so family name and architecture are recoverable without guessing.
fn derive_from_full_name(full_name: &str) -> (Option<String>, Option<PackageArchitecture>) {
    let parts: Vec<&str> = full_name.split('_').collect();
    if parts.len() < 5 || parts[0].is_empty() {
        return (None, None);
    }
    let publisher_id = parts[parts.len() - 1];
    if publisher_id.is_empty() {
        return (None, None);
    }
    let family = format!("{}_{publisher_id}", parts[0]);
    let architecture =
        (!parts[2].is_empty()).then(|| camel_case_enum::<PackageArchitecture>(parts[2]));
    (Some(family), architecture)
}

/// PowerShell renders these enums in PascalCase; the wire form is camelCase.
fn camel_case_enum<T: for<'de> Deserialize<'de>>(value: &str) -> T {
    let mut chars = value.chars();
    let camel = match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    };
    serde_json::from_value(Value::String(camel))
        .expect("raw-preserving enums accept any string value")
}

fn classify_app(name: &str) -> PortalApp {
    let lowered = name.to_ascii_lowercase();
    if lowered.contains("companyportal") {
        PortalApp::CompanyPortal
    } else if lowered.contains("authenticator") {
        PortalApp::Authenticator
    } else {
        PortalApp::Other
    }
}
