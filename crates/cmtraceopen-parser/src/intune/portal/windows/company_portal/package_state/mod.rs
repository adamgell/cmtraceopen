//! Deterministic Company Portal / Authenticator AppX package-state evidence.
//!
//! The canonical input is a versioned JSON capture produced by the native
//! Windows adapter ([`parse_package_state_capture`]). Findings derived from it
//! ([`derive_package_state_findings`]) never claim package absence unless the
//! capture proved it enumerated the relevant scope.
//!
//! Legacy PowerShell `Format-List` text can be imported through the
//! experimental adapter in [`legacy`], which refuses rather than guessing when
//! the text is localized, wrapped, or truncated. Legacy imports are marked in
//! [`models::PackageStateCaptureMetadata::source`] and never become the
//! canonical serialized form.

mod findings;
mod legacy;
mod models;
mod redaction;

pub use findings::*;
pub use legacy::*;
pub use models::*;
pub use redaction::*;

use serde_json::{Map, Value};

/// Parse a JSON package-state capture.
///
/// A capture whose `schemaVersion` is newer than this build understands is
/// *not* an error: the raw document is retained, no package facts are claimed,
/// and [`derive_package_state_findings`] reports
/// [`PackageStateFindingKind::UnsupportedSchema`].
pub fn parse_package_state_capture(json: &str) -> Result<PackageStateCapture, PackageStateError> {
    let document: Value = serde_json::from_str(json)
        .map_err(|error| PackageStateError::InvalidJson(error.to_string()))?;

    let object = document
        .as_object()
        .ok_or_else(|| PackageStateError::NotAnObject(json_type_name(&document).to_string()))?;

    let schema_version = object
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or(PackageStateError::MissingSchemaVersion)?;
    let schema_version = u32::try_from(schema_version).unwrap_or(u32::MAX);

    if schema_version > COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION {
        // Read only what a future schema cannot have moved: provenance. The
        // body is preserved verbatim instead of being guessed at.
        let capture = object
            .get("capture")
            .cloned()
            .and_then(|value| serde_json::from_value::<PackageStateCaptureMetadata>(value).ok())
            .unwrap_or_default();
        return Ok(PackageStateCapture {
            schema_version,
            capture,
            packages: Vec::new(),
            raw_document: Some(canonical_json(document)),
        });
    }

    let mut capture: PackageStateCapture = serde_json::from_value(document.clone()).map_err(
        |error| PackageStateError::InvalidBody {
            version: schema_version,
            detail: error.to_string(),
        },
    )?;
    capture.schema_version = schema_version;
    capture.raw_document = None;
    preserve_unknown_package_fields(&document, &mut capture);
    Ok(capture)
}

/// Parse and derive in one step, turning a parse failure into the
/// [`PackageStateFindingKind::MalformedCapture`] finding rather than an error.
pub fn parse_package_state_findings(
    json: &str,
    expected: &[ExpectedPackageFact],
) -> Vec<PackageStateFinding> {
    match parse_package_state_capture(json) {
        Ok(capture) => derive_package_state_findings(&capture, expected),
        Err(error) => vec![malformed_capture_finding(&error)],
    }
}

/// Fold adapter fields this schema version does not recognize into each row's
/// `raw` bag so a newer collector never loses data against an older reader.
fn preserve_unknown_package_fields(document: &Value, capture: &mut PackageStateCapture) {
    let Some(rows) = document.get("packages").and_then(Value::as_array) else {
        return;
    };

    for (row, source) in capture.packages.iter_mut().zip(rows) {
        if let Some(source) = source.as_object() {
            let unknown: Map<String, Value> = source
                .iter()
                .filter(|(key, _)| !KNOWN_PACKAGE_ROW_FIELDS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !unknown.is_empty() {
                match row.raw.take() {
                    Some(Value::Object(mut existing)) => {
                        existing.extend(unknown);
                        row.raw = Some(Value::Object(existing));
                    }
                    None => row.raw = Some(Value::Object(unknown)),
                    Some(other) => {
                        // An adapter put a non-object in `raw`; keep it and park
                        // the unknown fields beside it rather than discarding
                        // either.
                        let mut merged = unknown;
                        merged.insert("raw".to_string(), other);
                        row.raw = Some(Value::Object(merged));
                    }
                }
            }
        }

        // Canonicalize whatever ended up in `raw`, including a bag the adapter
        // supplied verbatim, so the serialized bytes never depend on which
        // serde_json map implementation this build was compiled against.
        row.raw = row.raw.take().map(canonical_json);
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
