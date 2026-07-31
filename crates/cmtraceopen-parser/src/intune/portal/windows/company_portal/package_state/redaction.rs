//! Opt-in redacted export projection for package-state captures.
//!
//! This is a projection, never a mutation: the caller keeps its own fully
//! detailed capture and gets back a parallel value safe to attach to a ticket.
//! It masks only what leaks identity or filesystem layout. Publisher `CN`
//! values and package versions stay intact, because over-redaction destroys the
//! diagnostic value the export exists for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::models::{PackageStateCapture, PackageStateClassifiedString};

const REDACTED: &str = "[redacted]";

/// Return a redacted copy of `capture`, leaving the input untouched.
///
/// The projection is idempotent: applying it to its own output is a no-op.
pub fn redacted_package_state_export(capture: &PackageStateCapture) -> PackageStateCapture {
    let mut safe = capture.clone();

    // Stable, order-independent pseudonyms so the same identifier reads the
    // same way everywhere in one export.
    let identifiers: BTreeSet<String> = safe
        .packages
        .iter()
        .filter_map(|row| row.user_identifier.as_ref())
        .map(|identifier| identifier.value.clone())
        .collect();
    let pseudonyms: BTreeMap<String, String> = identifiers
        .into_iter()
        .enumerate()
        .map(|(index, value)| (value, format!("[redacted-user-{}]", index + 1)))
        .collect();

    if let Some(error) = safe.capture.error.as_mut() {
        error.message = REDACTED.to_string();
    }

    for row in &mut safe.packages {
        mask(&mut row.install_location);
        if let Some(identifier) = row.user_identifier.as_mut() {
            if let Some(pseudonym) = pseudonyms.get(&identifier.value) {
                identifier.value = pseudonym.clone();
            } else {
                identifier.value = REDACTED.to_string();
            }
        }
        if let Some(raw) = row.raw.as_mut() {
            redact_raw_value(raw, &pseudonyms);
        }
    }

    if let Some(document) = safe.raw_document.as_mut() {
        redact_raw_value(document, &pseudonyms);
    }

    safe
}

fn mask(value: &mut Option<PackageStateClassifiedString>) {
    if let Some(classified) = value.as_mut() {
        classified.value = REDACTED.to_string();
    }
}

/// Walk a preserved raw blob and mask the two things it can plausibly leak:
/// user-profile paths and identifiers we already pseudonymized elsewhere.
fn redact_raw_value(value: &mut Value, pseudonyms: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            if let Some(pseudonym) = pseudonyms.get(text.as_str()) {
                *text = pseudonym.clone();
            } else if looks_like_user_path(text) {
                *text = REDACTED.to_string();
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_raw_value(item, pseudonyms);
            }
        }
        Value::Object(entries) => {
            for (_, entry) in entries.iter_mut() {
                redact_raw_value(entry, pseudonyms);
            }
        }
        _ => {}
    }
}

fn looks_like_user_path(value: &str) -> bool {
    user_profile_path_pattern().is_match(value)
}

fn user_profile_path_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Deliberately narrow: only paths that name a user directory. Program
        // Files and WindowsApps paths carry no identity and stay readable.
        Regex::new(r"(?i)(?:^|[\\/])(?:users|documents and settings)[\\/][^\\/\r\n]+")
            .expect("user profile path pattern must compile")
    })
}
