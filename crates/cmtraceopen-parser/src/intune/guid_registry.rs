use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::ime_parser::ImeLine;
use std::sync::OnceLock;

// ── Shared regexes (also used by download_stats.rs) ─────────────────────────

pub(crate) fn app_id_json_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"\"AppId\"\s*:\s*\"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\""#,
        )
        .unwrap()
    })
}
pub(crate) fn app_name_json_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)\"(?:ApplicationName|Name)\"\s*:\s*\"([^\",\}]+)"#).unwrap()
    })
}
pub(crate) fn setup_file_json_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"\"SetUpFilePath\"\s*:\s*\"([^\"]+)\""#).unwrap())
}

/// Generic GUID pattern for secondary extraction.
pub(crate) fn guid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#,
        )
        .unwrap()
    })
}

const APP_ID_FIELD_SYNTAXES: [(&str, &str); 2] = [("\"AppId\"", "\""), ("\\\"AppId\\\"", "\\\"")];
const ID_FIELD_SYNTAXES: [(&str, &str); 2] = [("\"Id\"", "\""), ("\\\"Id\\\"", "\\\"")];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExplicitAppIdentity {
    Absent,
    Valid(String),
    Invalid,
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Fast prefix/suffix JSON field extraction without regex overhead.
pub(crate) fn extract_json_field<'a>(msg: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = msg.find(prefix)? + prefix.len();
    let remainder = msg.get(start..)?;
    let end = remainder.find(suffix)?;
    remainder.get(..end)
}

/// Extract just the filename from a SetUpFilePath value.
/// Handles Windows-style backslash paths on all platforms.
pub(crate) fn setup_file_name(path: &str) -> String {
    // Split on both forward and backslash to handle Windows paths on Linux CI
    path.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

// ── GUID registry types ─────────────────────────────────────────────────────

/// Indicates where a GUID→name association was found, ranked by confidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GuidNameSource {
    /// `"SetUpFilePath"` — lowest confidence (just a filename)
    SetUpFilePath = 0,
    /// `"Name"` JSON field
    NameField = 1,
    /// `"ApplicationName"` JSON field
    ApplicationName = 2,
    /// Microsoft Graph API — highest confidence (canonical display name)
    GraphApi = 3,
}

/// A resolved identity for a GUID observed in IME logs.
#[derive(Debug, Clone)]
pub struct GuidEntry {
    /// Human-readable display name.
    pub name: String,
    /// Source of the name — used for confidence ranking during merges.
    pub source: GuidNameSource,
}

/// A global GUID→name registry built by scanning IME log lines.
///
/// Any module that needs to translate a GUID into an application/script/policy
/// name can use this registry. It is built per-file during parallel analysis
/// and then merged into a single global instance.
#[derive(Debug, Clone, Default)]
pub struct GuidRegistry {
    entries: HashMap<String, GuidEntry>,
}

impl GuidRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan all lines from a single log file, accumulating GUID→name pairs.
    pub fn ingest_lines(&mut self, lines: &[ImeLine]) {
        for line in lines {
            self.ingest_message(&line.message);
        }
    }

    /// Extract GUID→name pairs from a single message string.
    fn ingest_message(&mut self, msg: &str) {
        // Multi-pair path: extract all "Id"+"Name" pairs from JSON arrays
        // e.g. Get policies = [{"Id":"guid1","Name":"name1"},{"Id":"guid2","Name":"name2"}]
        for (guid, name, source) in extract_all_id_name_pairs(msg) {
            self.insert_if_dominated(guid, name, source);
        }

        // Single-GUID path: handles AppId, ApplicationName, SetUpFilePath
        if let Some(guid) = extract_app_id(msg) {
            if let Some((name, source)) = extract_app_name_with_source(msg) {
                self.insert_if_dominated(guid, name, source);
            }
        }
    }

    /// Insert an entry if no higher-confidence entry already exists for this GUID.
    fn insert_if_dominated(&mut self, guid: String, name: String, source: GuidNameSource) {
        let dominated = self
            .entries
            .get(&guid)
            .is_none_or(|existing| source > existing.source);
        if dominated {
            self.entries.insert(guid, GuidEntry { name, source });
        }
    }

    /// Merge another registry into this one.
    /// Keeps the higher-confidence entry when the same GUID appears in both.
    pub fn merge(&mut self, other: &GuidRegistry) {
        for (guid, entry) in &other.entries {
            self.insert_if_dominated(guid.clone(), entry.name.clone(), entry.source.clone());
        }
    }

    /// Look up the display name for a GUID.
    pub fn resolve(&self, guid: &str) -> Option<&str> {
        self.entries.get(guid).map(|entry| entry.name.as_str())
    }

    /// If `current_name` looks like a short-id fallback (e.g. "Download (a1b2c3d4...)"),
    /// return the resolved name for the GUID. Otherwise return `None`.
    pub fn resolve_fallback_name(&self, current_name: &str, guid: &str) -> Option<String> {
        if is_fallback_name(current_name) {
            self.resolve(guid).map(|name| name.to_string())
        } else {
            None
        }
    }

    /// Enrich an event name that ends with a short-GUID suffix like `(00591936...)`.
    ///
    /// For example:
    /// - `"AppWorkload Download Retry (00591936...)"` → `"AppWorkload Download Retry — Contoso App"`
    /// - `"Win32 App (a1b2c3d4...)"` → `"Win32 App — Contoso App"`
    ///
    /// Returns `None` if the name doesn't match the pattern or the GUID is unknown.
    pub fn enrich_event_name(&self, current_name: &str, guid: &str) -> Option<String> {
        let resolved = self.resolve(guid)?;
        // Strip the trailing "(shortguid...)" suffix and replace with the resolved name
        strip_short_guid_suffix(current_name).map(|prefix| format!("{prefix}{resolved}"))
    }

    /// Number of entries in the registry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the registry contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert a GUID→name entry from an external source (e.g. Graph API).
    pub fn insert(&mut self, guid: String, name: String, source: GuidNameSource) {
        self.insert_if_dominated(guid, name, source);
    }

    /// Collect all GUIDs that have no resolved name.
    pub fn unresolved_guids_from<'a>(&self, guids: impl Iterator<Item = &'a str>) -> Vec<String> {
        guids
            .filter(|g| !self.entries.contains_key(*g))
            .map(|g| g.to_string())
            .collect()
    }

    /// Iterate over all `(guid, entry)` pairs in the registry.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &GuidEntry)> {
        self.entries.iter()
    }

    /// Convert to a serializable map for the frontend.
    pub fn to_serializable(&self) -> HashMap<String, GuidRegistryEntry> {
        self.entries
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    GuidRegistryEntry {
                        name: v.name.clone(),
                        source: v.source.clone(),
                    },
                )
            })
            .collect()
    }
}

/// Serializable entry for the frontend GUID registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuidRegistryEntry {
    pub name: String,
    pub source: GuidNameSource,
}

// ── Private extraction helpers ───────────────────────────────────────────────

/// Extract all `"Id"` + `"Name"` pairs from a message that may contain a JSON array.
///
/// Handles lines like:
/// ```text
/// Get policies = [{"Id":"guid1","Name":"name1","Version":1},{"Id":"guid2","Name":"name2"}]
/// ```
///
/// Returns one `(guid, name, NameField)` tuple per valid pair found.
fn extract_all_id_name_pairs(msg: &str) -> Vec<(String, String, GuidNameSource)> {
    // Try direct JSON, then escaped JSON
    for &(id_pre, id_suf, name_pre, name_suf) in &[
        ("\"Id\":\"", "\"", "\"Name\":\"", "\""),
        ("\\\"Id\\\":\\\"", "\\\"", "\\\"Name\\\":\\\"", "\\\""),
    ] {
        let ids = extract_all_field_values(msg, id_pre, id_suf);
        if ids.is_empty() {
            continue;
        }
        let names = extract_all_field_values(msg, name_pre, name_suf);
        if names.is_empty() {
            continue;
        }

        let mut pairs = Vec::new();
        for (id_val, name_val) in ids.into_iter().zip(names) {
            if id_val.len() == 36 && guid_re().is_match(&id_val) {
                pairs.push((id_val, name_val, GuidNameSource::NameField));
            }
        }
        if !pairs.is_empty() {
            return pairs;
        }
    }

    Vec::new()
}

/// Find all occurrences of a `prefix…suffix` delimited field in `msg`.
fn extract_all_field_values(msg: &str, prefix: &str, suffix: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = msg[search_from..].find(prefix) {
        let start = search_from + pos + prefix.len();
        let Some(remainder) = msg.get(start..) else {
            break;
        };
        let Some(end) = remainder.find(suffix) else {
            break;
        };
        if let Some(value) = remainder.get(..end) {
            results.push(value.to_string());
        }
        search_from = start + end + suffix.len();
    }
    results
}

/// Extract a GUID from a log message via JSON identity fields.
///
/// Checks (in order): `"AppId"`, `"Id"`, then falls back to a generic
/// GUID regex when a name field is also present on the same line.
pub(crate) fn extract_app_id(msg: &str) -> Option<String> {
    match explicit_app_identity(msg) {
        ExplicitAppIdentity::Valid(guid) => Some(guid),
        ExplicitAppIdentity::Invalid => None,
        ExplicitAppIdentity::Absent => {
            // Only fall back to generic GUID if a name field is present
            // (avoids polluting registry with context-free GUIDs)
            if has_name_field(msg) {
                guid_re()
                    .captures(msg)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            } else {
                None
            }
        }
    }
}

/// Classify explicit JSON `AppId`/`Id` fields without falling back to other
/// GUIDs on the line. An invalid explicit field is an identity boundary: its
/// presence suppresses line-wide GUID inference.
pub(crate) fn explicit_app_identity(msg: &str) -> ExplicitAppIdentity {
    // Preserve the established fast paths and their ordering.
    for (prefix, suffix) in [
        ("\"AppId\":\"", "\""),
        ("\\\"AppId\\\":\\\"", "\\\""),
        ("\"Id\":\"", "\""),
        ("\\\"Id\\\":\\\"", "\\\""),
    ] {
        if let Some(value) = extract_guid_field(msg, prefix, suffix) {
            return ExplicitAppIdentity::Valid(value);
        }
    }

    // Preserve the whitespace-tolerant AppId path with its canonical GUID
    // grammar. The field scanner below covers escaped spacing and Id fields.
    if let Some(value) = app_id_json_re()
        .captures(msg)
        .and_then(|captures| captures.get(1))
    {
        return ExplicitAppIdentity::Valid(value.as_str().to_string());
    }

    let allow_decorated = has_name_field(msg);
    let (app_id_present, app_id) =
        scan_identity_fields(msg, &APP_ID_FIELD_SYNTAXES, allow_decorated);
    if let Some(value) = app_id {
        return ExplicitAppIdentity::Valid(value);
    }

    let (id_present, id) = scan_identity_fields(msg, &ID_FIELD_SYNTAXES, allow_decorated);
    if let Some(value) = id {
        return ExplicitAppIdentity::Valid(value);
    }

    if app_id_present || id_present {
        ExplicitAppIdentity::Invalid
    } else {
        ExplicitAppIdentity::Absent
    }
}

fn scan_identity_fields(
    msg: &str,
    syntaxes: &[(&str, &str)],
    allow_decorated: bool,
) -> (bool, Option<String>) {
    let mut present = false;

    for &(key, quote) in syntaxes {
        let mut remaining = msg;
        while let Some(key_index) = remaining.find(key) {
            present = true;
            let after_key = &remaining[key_index + key.len()..];
            if let Some(value) = json_string_value_after_key(after_key, quote) {
                if let Some(guid) = exact_guid(value).or_else(|| {
                    if allow_decorated {
                        guid_re()
                            .captures(value)
                            .and_then(|captures| captures.get(1))
                            .map(|matched| matched.as_str().to_string())
                    } else {
                        None
                    }
                }) {
                    return (true, Some(guid));
                }
            }
            remaining = after_key;
        }
    }

    (present, None)
}

fn json_string_value_after_key<'a>(after_key: &'a str, quote: &str) -> Option<&'a str> {
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    let value = after_colon.strip_prefix(quote)?;
    let end = value.find(quote)?;
    value.get(..end)
}

fn exact_guid(value: &str) -> Option<String> {
    let matched = guid_re().find(value)?;
    (matched.start() == 0 && matched.end() == value.len()).then(|| value.to_string())
}

/// Extract a GUID from an identity field, rejecting arbitrary log content.
fn extract_guid_field(msg: &str, prefix: &str, suffix: &str) -> Option<String> {
    let value = extract_json_field(msg, prefix, suffix)?;
    exact_guid(value)
}

/// Returns `true` if the message contains any name-bearing JSON field.
fn has_name_field(msg: &str) -> bool {
    msg.contains("ApplicationName")
        || msg.contains("\"Name\"")
        || msg.contains("\\\"Name\\\"")
        || msg.contains("SetUpFilePath")
}

/// Extract a display name, discarding the confidence source.
pub(crate) fn extract_app_name(msg: &str) -> Option<String> {
    extract_app_name_with_source(msg).map(|(name, _)| name)
}

/// Extract a display name along with its confidence source.
pub(crate) fn extract_app_name_with_source(msg: &str) -> Option<(String, GuidNameSource)> {
    // ApplicationName (highest confidence)
    if let Some(value) = extract_json_field(msg, "\"ApplicationName\":\"", "\"") {
        return Some((value.to_string(), GuidNameSource::ApplicationName));
    }
    if let Some(value) = extract_json_field(msg, "\\\"ApplicationName\\\":\\\"", "\\\"") {
        return Some((value.to_string(), GuidNameSource::ApplicationName));
    }

    // Generic "Name" field — direct and escaped JSON
    if let Some(value) = extract_json_field(msg, "\"Name\":\"", "\"") {
        return Some((value.to_string(), GuidNameSource::NameField));
    }
    if let Some(value) = extract_json_field(msg, "\\\"Name\\\":\\\"", "\\\"") {
        return Some((value.to_string(), GuidNameSource::NameField));
    }

    // Regex fallback for ApplicationName/Name (handles edge cases)
    if let Some(caps) = app_name_json_re().captures(msg) {
        if let Some(m) = caps.get(1) {
            let name = m.as_str().to_string();
            let source = if msg.contains("ApplicationName") {
                GuidNameSource::ApplicationName
            } else {
                GuidNameSource::NameField
            };
            return Some((name, source));
        }
    }

    // SetUpFilePath (lowest confidence)
    if let Some(value) = extract_json_field(msg, "\"SetUpFilePath\":\"", "\"") {
        return Some((setup_file_name(value), GuidNameSource::SetUpFilePath));
    }
    if let Some(value) = extract_json_field(msg, "\\\"SetUpFilePath\\\":\\\"", "\\\"") {
        return Some((setup_file_name(value), GuidNameSource::SetUpFilePath));
    }
    setup_file_json_re()
        .captures(msg)
        .and_then(|c| c.get(1))
        .map(|m| (setup_file_name(m.as_str()), GuidNameSource::SetUpFilePath))
}

/// Detect whether a name is a fallback like "Download (guid)" or "Download: id".
pub(crate) fn is_fallback_name(name: &str) -> bool {
    name.starts_with("Download (") || name.starts_with("Download:")
}

/// If `name` ends with a parenthesised GUID (full or short), strip that suffix
/// and return the prefix with a ` — ` separator ready for the resolved name.
///
/// Examples:
/// - `"AppWorkload Download Retry (00591936-3d7f-4c79-bd9e-550b09c2e8d9)"` → `Some("AppWorkload Download Retry — ")`
/// - `"Win32 App (a1b2c3d4-e5f6-7890-abcd-ef1234567890)"` → `Some("Win32 App — ")`
/// - `"AppWorkload Download Retry (00591936...)"` → `Some("AppWorkload Download Retry — ")` (legacy short format)
/// - `"Contoso App"` → `None`
fn strip_short_guid_suffix(name: &str) -> Option<String> {
    let trimmed = name.trim_end();
    if !trimmed.ends_with(')') {
        return None;
    }
    let paren_open = trimmed.rfind('(')?;
    let inner = &trimmed[paren_open + 1..trimmed.len() - 1]; // content between ( and )
    if inner.is_empty() {
        return None;
    }
    // Accept full GUID: hex + dashes, 36 chars
    let is_full_guid =
        inner.len() == 36 && inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    // Accept legacy short format: hex chars followed by "..."
    let is_short_guid = inner.ends_with("...")
        && inner[..inner.len() - 3]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        && inner.len() > 3;
    if !is_full_guid && !is_short_guid {
        return None;
    }
    let prefix = trimmed[..paren_open].trim_end();
    Some(format!("{prefix} — "))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn line(msg: &str) -> ImeLine {
        ImeLine {
            line_number: 1,
            timestamp: None,
            timestamp_utc: None,
            message: msg.to_string(),
            component: None,
            thread: None,
            timezone_offset: None,
        }
    }

    #[test]
    fn ingest_direct_json() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Processing app: {"AppId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","ApplicationName":"Contoso App"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("Contoso App")
        );
    }

    #[test]
    fn ingest_escaped_json() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Payload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Remote Desktop\"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("Remote Desktop")
        );
    }

    #[test]
    fn higher_confidence_wins_on_merge() {
        let mut a = GuidRegistry::new();
        a.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "setup.exe".to_string(),
                source: GuidNameSource::SetUpFilePath,
            },
        );

        let mut b = GuidRegistry::new();
        b.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        a.merge(&b);
        assert_eq!(a.resolve("guid-1"), Some("Contoso App"));
    }

    #[test]
    fn lower_confidence_does_not_overwrite() {
        let mut a = GuidRegistry::new();
        a.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        let mut b = GuidRegistry::new();
        b.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "setup.exe".to_string(),
                source: GuidNameSource::SetUpFilePath,
            },
        );

        a.merge(&b);
        assert_eq!(a.resolve("guid-1"), Some("Contoso App"));
    }

    #[test]
    fn resolve_fallback_name_replaces_short_id() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.resolve_fallback_name(
                "Download (a1b2c3d4...)",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            Some("Contoso App".to_string())
        );
    }

    #[test]
    fn resolve_fallback_name_preserves_real_name() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Other App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.resolve_fallback_name("Contoso App", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            None
        );
    }

    #[test]
    fn empty_registry() {
        let reg = GuidRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.resolve("anything"), None);
    }

    #[test]
    fn setup_file_path_extraction() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Download started: {"AppId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","SetUpFilePath":"C:\\Cache\\MyInstaller.exe"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("MyInstaller.exe")
        );
    }

    #[test]
    fn policy_payload_id_and_name_extracted() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{"Id":"00591936-3d7f-4c79-bd9e-550b09c2e8d9","Name":"Update for Remote Desktop Manager 2026.1.12.0","Version":1}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
    }

    #[test]
    fn escaped_policy_payload_id_and_name_extracted() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{\"Id\":\"00591936-3d7f-4c79-bd9e-550b09c2e8d9\",\"Name\":\"Update for Remote Desktop Manager 2026.1.12.0\",\"Version\":1}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
    }

    #[test]
    fn multi_entry_policy_array_extracts_all_guids() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{"Id":"00591936-3d7f-4c79-bd9e-550b09c2e8d9","Name":"Update for Remote Desktop Manager 2026.1.12.0","Version":1},{"Id":"bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d","Name":"7-Zip 24.09","Version":3}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
        assert_eq!(
            reg.resolve("bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d"),
            Some("7-Zip 24.09")
        );
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn multi_entry_escaped_policy_array_extracts_all_guids() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{\"Id\":\"00591936-3d7f-4c79-bd9e-550b09c2e8d9\",\"Name\":\"Update for RDM\",\"Version\":1},{\"Id\":\"bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d\",\"Name\":\"7-Zip\",\"Version\":3}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for RDM")
        );
        assert_eq!(
            reg.resolve("bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d"),
            Some("7-Zip")
        );
    }

    #[test]
    fn enrich_event_name_replaces_full_guid_suffix() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "00591936-aaaa-bbbb-cccc-ddddeeeeeeee".to_string(),
            GuidEntry {
                name: "Remote Desktop Manager".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download Retry (00591936-aaaa-bbbb-cccc-ddddeeeeeeee)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            Some("AppWorkload Download Retry — Remote Desktop Manager".to_string())
        );
    }

    #[test]
    fn enrich_event_name_replaces_legacy_short_guid_suffix() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "00591936-aaaa-bbbb-cccc-ddddeeeeeeee".to_string(),
            GuidEntry {
                name: "Remote Desktop Manager".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download Retry (00591936...)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            Some("AppWorkload Download Retry — Remote Desktop Manager".to_string())
        );
    }

    #[test]
    fn enrich_event_name_works_for_win32_app() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "Win32 App (a1b2c3d4-e5f6-7890-abcd-ef1234567890)",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            Some("Win32 App — Contoso App".to_string())
        );
    }

    #[test]
    fn enrich_event_name_returns_none_for_real_name() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Other".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "ClientHealth Heartbeat Failed",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            None
        );
    }

    #[test]
    fn enrich_event_name_returns_none_for_unknown_guid() {
        let reg = GuidRegistry::new();
        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download (00591936-aaaa-bbbb-cccc-ddddeeeeeeee)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            None
        );
    }

    #[test]
    fn strip_guid_suffix_unit() {
        // Full GUID format
        assert_eq!(
            strip_short_guid_suffix(
                "AppWorkload Download Retry (00591936-aaaa-bbbb-cccc-ddddeeeeeeee)"
            ),
            Some("AppWorkload Download Retry — ".to_string())
        );
        assert_eq!(
            strip_short_guid_suffix("Win32 App (a1b2c3d4-e5f6-7890-abcd-ef1234567890)"),
            Some("Win32 App — ".to_string())
        );
        // Legacy short format
        assert_eq!(
            strip_short_guid_suffix("AppWorkload Download Retry (00591936...)"),
            Some("AppWorkload Download Retry — ".to_string())
        );
        assert_eq!(
            strip_short_guid_suffix("Win32 App (a1b2c3d4...)"),
            Some("Win32 App — ".to_string())
        );
        // Non-matching
        assert_eq!(
            strip_short_guid_suffix("ClientHealth Heartbeat Failed"),
            None
        );
        assert_eq!(strip_short_guid_suffix("Some Name (not-hex...)"), None);
        assert_eq!(strip_short_guid_suffix("Some Name (not a guid)"), None);
    }

    #[test]
    fn to_serializable_preserves_entries_and_sources() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[
            line(r#"Processing app: {"AppId":"aaaa1111-2222-3333-4444-555566667777","ApplicationName":"Contoso App"}"#),
            line(r#"Download started: {"AppId":"bbbb1111-2222-3333-4444-555566667777","SetUpFilePath":"C:\\Cache\\installer.exe"}"#),
        ]);

        let map = reg.to_serializable();
        assert_eq!(map.len(), 2);

        let contoso = &map["aaaa1111-2222-3333-4444-555566667777"];
        assert_eq!(contoso.name, "Contoso App");
        assert_eq!(contoso.source, GuidNameSource::ApplicationName);

        let installer = &map["bbbb1111-2222-3333-4444-555566667777"];
        assert_eq!(installer.name, "installer.exe");
        assert_eq!(installer.source, GuidNameSource::SetUpFilePath);

        // Verify JSON serialization contract
        let json = serde_json::to_value(&map).expect("serialize registry map");
        assert_eq!(
            json["aaaa1111-2222-3333-4444-555566667777"]["name"].as_str(),
            Some("Contoso App")
        );
        assert_eq!(
            json["aaaa1111-2222-3333-4444-555566667777"]["source"].as_str(),
            Some("ApplicationName")
        );
        assert_eq!(
            json["bbbb1111-2222-3333-4444-555566667777"]["source"].as_str(),
            Some("SetUpFilePath")
        );
    }

    #[test]
    fn app_id_fields_only_supply_valid_guid_identities() {
        let valid_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        assert_eq!(
            extract_app_id(&format!(r#"launch {{"AppId":"{valid_guid}"}}"#)),
            Some(valid_guid.to_string())
        );
        assert_eq!(extract_app_id(r#"launch {"AppId":"script-你好"}"#), None);
        assert_eq!(
            extract_app_id(r#"launch {"AppId":"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"}"#),
            None
        );

        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&[line(
            r#"Processing app: {"AppId":"script-你好","ApplicationName":"Contoso Script"}"#,
        )]);
        assert!(registry.is_empty());
    }

    #[test]
    fn spaced_app_id_fallback_rejects_malformed_guid_shapes() {
        let malformed_values = [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "a1b2c3d-e5f67-890a-abcd-ef1234567890",
        ];

        for value in malformed_values {
            let message = format!(
                r#"Processing app: {{"AppId" : "{value}","ApplicationName":"Contoso App"}}"#
            );
            assert_eq!(extract_app_id(&message), None, "accepted {value}");

            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "registered {value}");
        }
    }

    #[test]
    fn spaced_app_id_and_named_context_guid_fallback_remain_supported() {
        let valid_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        assert_eq!(
            extract_app_id(&format!(r#"launch {{"AppId" : "{valid_guid}"}}"#)),
            Some(valid_guid.to_string())
        );
        assert_eq!(
            extract_app_id(&format!(
                r#"Processing identity {valid_guid} for {{"ApplicationName":"Contoso App"}}"#
            )),
            Some(valid_guid.to_string())
        );
    }

    #[test]
    fn invalid_explicit_identity_fields_suppress_line_wide_guid_fallback() {
        let unrelated_guid = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(
                r#"tenant {unrelated_guid} {{"AppId":"not-an-app-guid","ApplicationName":"Contoso"}}"#
            ),
            format!(
                r#"tenant {unrelated_guid} {{\"AppId\":\"not-an-app-guid\",\"ApplicationName\":\"Contoso\"}}"#
            ),
            format!(r#"tenant {unrelated_guid} {{"Id":"not-an-app-guid","Name":"Contoso"}}"#),
            format!(
                r#"tenant {unrelated_guid} {{\"Id\" : \"not-an-app-guid\",\"Name\":\"Contoso\"}}"#
            ),
        ];

        for message in messages {
            assert_eq!(extract_app_id(&message), None, "accepted {message}");

            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "registered from {message}");
        }
    }

    #[test]
    fn valid_explicit_identity_fields_beat_unrelated_line_guids() {
        let unrelated_guid = "11111111-2222-3333-4444-555555555555";
        let app_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let messages = [
            format!(
                r#"tenant {unrelated_guid} {{"AppId":"{app_guid}","ApplicationName":"Contoso"}}"#
            ),
            format!(
                r#"tenant {unrelated_guid} {{\"AppId\" : \"{app_guid}\",\"ApplicationName\":\"Contoso\"}}"#
            ),
            format!(r#"tenant {unrelated_guid} {{"Id" : "{app_guid}","Name":"Contoso"}}"#),
            format!(r#"tenant {unrelated_guid} {{\"Id\":\"{app_guid}\",\"Name\":\"Contoso\"}}"#),
            format!(
                r#"tenant {unrelated_guid} {{"AppId":"invalid","Id":"{app_guid}","Name":"Contoso"}}"#
            ),
        ];

        for message in messages {
            assert_eq!(
                extract_app_id(&message),
                Some(app_guid.to_string()),
                "wrong identity for {message}"
            );
        }
    }

    #[test]
    fn named_context_fallback_remains_available_without_identity_fields() {
        let app_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert_eq!(
            extract_app_id(&format!(
                r#"Processing identity {app_guid} for {{"ApplicationName":"Contoso"}}"#
            )),
            Some(app_guid.to_string())
        );
    }

    #[test]
    fn decorated_identity_field_uses_its_field_local_guid() {
        let unrelated_guid = "11111111-2222-3333-4444-555555555555";
        let app_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let message = format!(
            r#"tenant {unrelated_guid} {{"AppId":"Win32App_{app_guid}_1","ApplicationName":"Contoso"}}"#
        );

        assert_eq!(extract_app_id(&message), Some(app_guid.to_string()));
    }
}
