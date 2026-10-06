use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// ── Shared regexes (also used by download_stats.rs) ─────────────────────────

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

/// The one textual GUID shape every Intune analyzer matches against.
///
/// Owned here so `event_tracker`, `download_stats`, and the Win32 transaction
/// analyzer compose their identifier rules from a single grammar instead of
/// each spelling its own copy that can drift.
pub(crate) const GUID_PATTERN: &str =
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

/// Generic GUID pattern for secondary extraction.
pub(crate) fn guid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(&format!("({GUID_PATTERN})")).unwrap())
}

const MAX_JSON_CONTAINER_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExplicitAppIdentity {
    Absent,
    Valid(String),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplicitAppIdentityContext {
    pub identity: ExplicitAppIdentity,
    pub local_name: Option<String>,
    /// Populated only for an absent explicit identity when the caller enables
    /// the legacy named-GUID fallback; valid and invalid identities keep this `None`.
    pub fallback_app_id: Option<String>,
}

#[cfg(test)]
std::thread_local! {
    static NAMED_GUID_FALLBACK_EXTRACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_named_guid_fallback_extraction_count() {
    NAMED_GUID_FALLBACK_EXTRACTIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn named_guid_fallback_extraction_count() -> usize {
    NAMED_GUID_FALLBACK_EXTRACTIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_named_guid_fallback_extraction() {
    NAMED_GUID_FALLBACK_EXTRACTIONS.with(|count| count.set(count.get().saturating_add(1)));
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdentityFieldState {
    Absent,
    Valid(String),
    Malformed,
    Conflict,
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

pub(crate) fn identity_name_pairs(msg: &str) -> Vec<(String, String, GuidNameSource)> {
    let Ok(scan) = scan_json_fields(msg) else {
        return Vec::new();
    };
    let mut pairs = extract_all_identity_name_pairs(&scan);
    if !scan.has_explicit_identity_fields() {
        let guid = guid_re()
            .captures(msg)
            .and_then(|captures| captures.get(1))
            .map(|matched| matched.as_str().to_ascii_lowercase());
        if let Some(guid) = guid {
            if let Some((name, source)) = extract_app_name_with_source(msg) {
                pairs.push((guid, name, source));
            }
        }
    }
    pairs
}

// ── Private extraction helpers ───────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonFieldKind {
    AppId,
    Id,
    ApplicationName,
    Name,
    SetUpFilePath,
}

#[derive(Clone, Copy)]
struct JsonField<'a> {
    kind: JsonFieldKind,
    value: Option<&'a str>,
}

struct JsonObjectScope<'a> {
    start: usize,
    end: usize,
    tree_start: usize,
    fields: Vec<JsonField<'a>>,
}

struct JsonFieldScan<'a> {
    root: JsonObjectScope<'a>,
    scopes: Vec<JsonObjectScope<'a>>,
}

enum ExplicitAppIdentitySelection<'scan, 'msg> {
    Absent,
    Valid {
        guid: String,
        scope: &'scan JsonObjectScope<'msg>,
    },
    Invalid,
}

impl JsonFieldScan<'_> {
    fn has_explicit_identity_fields(&self) -> bool {
        self.root
            .fields
            .iter()
            .chain(self.scopes.iter().flat_map(|scope| scope.fields.iter()))
            .any(|field| matches!(field.kind, JsonFieldKind::AppId | JsonFieldKind::Id))
    }
}

struct ObjectFrame<'a> {
    scope: JsonObjectScope<'a>,
    expect_key: bool,
}

enum ContainerFrame<'a> {
    Object(ObjectFrame<'a>),
    Array,
}

#[derive(Debug, Clone, Copy)]
struct JsonScanError;

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteStyle {
    Direct,
    BackslashEscaped,
}

struct ActiveString {
    style: QuoteStyle,
    content_start: usize,
}

/// Scan only direct, relevant string fields in JSON-like objects. Values are
/// borrowed from the input and nested objects own their own fields, keeping
/// retained memory linear in the number of relevant fields rather than in
/// `nesting depth * line length`.
fn scan_json_fields(msg: &str) -> Result<JsonFieldScan<'_>, JsonScanError> {
    let bytes = msg.as_bytes();
    let mut active_string: Option<ActiveString> = None;
    let mut containers: Vec<ContainerFrame<'_>> = Vec::new();
    let mut object_depth: usize = 0;
    let mut current_tree_start = None;
    let mut scopes = Vec::new();
    let mut root = ObjectFrame {
        scope: JsonObjectScope {
            start: 0,
            end: msg.len(),
            tree_start: 0,
            fields: Vec::new(),
        },
        expect_key: true,
    };

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'"' {
            let backslashes = preceding_backslash_count(bytes, index);
            if let Some(active) = active_string.as_ref() {
                if quote_closes(active.style, backslashes) {
                    let content_end = match active.style {
                        QuoteStyle::Direct => index,
                        QuoteStyle::BackslashEscaped => index.saturating_sub(1),
                    };
                    if let Some(content) = msg.get(active.content_start..content_end) {
                        if containers.is_empty() {
                            process_string_token(&mut root, msg, content, index + 1, false);
                        } else if let Some(ContainerFrame::Object(frame)) = containers.last_mut() {
                            process_string_token(frame, msg, content, index + 1, true);
                        }
                    }
                    active_string = None;
                }
            } else if let Some(style) = quote_opens(backslashes) {
                active_string = Some(ActiveString {
                    style,
                    content_start: index + 1,
                });
            }
            continue;
        }
        if active_string.is_some() {
            continue;
        }

        match byte {
            b'{' => {
                if containers.len() >= MAX_JSON_CONTAINER_DEPTH {
                    return Err(JsonScanError);
                }
                let tree_start = current_tree_start.unwrap_or(index);
                current_tree_start = Some(tree_start);
                containers.push(ContainerFrame::Object(ObjectFrame {
                    scope: JsonObjectScope {
                        start: index,
                        end: msg.len(),
                        tree_start,
                        fields: Vec::new(),
                    },
                    expect_key: true,
                }));
                object_depth += 1;
            }
            b'[' => {
                if containers.len() >= MAX_JSON_CONTAINER_DEPTH {
                    return Err(JsonScanError);
                }
                containers.push(ContainerFrame::Array);
            }
            b'}' => {
                if matches!(containers.last(), Some(ContainerFrame::Object(_))) {
                    let Some(ContainerFrame::Object(mut frame)) = containers.pop() else {
                        unreachable!();
                    };
                    frame.scope.end = index + 1;
                    object_depth = object_depth.saturating_sub(1);
                    if object_depth == 0 {
                        current_tree_start = None;
                    }
                    if !frame.scope.fields.is_empty() {
                        scopes.push(frame.scope);
                    }
                }
            }
            b']' => {
                if matches!(containers.last(), Some(ContainerFrame::Array)) {
                    containers.pop();
                }
            }
            b',' => {
                if let Some(ContainerFrame::Object(frame)) = containers.last_mut() {
                    frame.expect_key = true;
                }
            }
            _ => {}
        }
    }

    // Keep relevant fields from truncated raw-log payloads. The depth cap is
    // the only scanner error because an incomplete log line is common input,
    // while an attacker-controlled nesting explosion must fail closed.
    for container in containers {
        if let ContainerFrame::Object(frame) = container {
            if !frame.scope.fields.is_empty() {
                scopes.push(frame.scope);
            }
        }
    }
    scopes.sort_by_key(|scope| (scope.tree_start, scope.start));
    Ok(JsonFieldScan {
        root: root.scope,
        scopes,
    })
}

fn quote_opens(backslashes: usize) -> Option<QuoteStyle> {
    if backslashes & 1 == 0 {
        Some(QuoteStyle::Direct)
    } else if backslashes & 3 == 1 {
        Some(QuoteStyle::BackslashEscaped)
    } else {
        None
    }
}

fn quote_closes(style: QuoteStyle, backslashes: usize) -> bool {
    match style {
        QuoteStyle::Direct => backslashes & 1 == 0,
        QuoteStyle::BackslashEscaped => backslashes & 3 == 1,
    }
}

fn preceding_backslash_count(bytes: &[u8], quote_index: usize) -> usize {
    bytes[..quote_index]
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
}

fn process_string_token<'a>(
    frame: &mut ObjectFrame<'a>,
    msg: &'a str,
    content: &'a str,
    token_end: usize,
    enforce_object_state: bool,
) {
    if enforce_object_state && !frame.expect_key {
        return;
    }

    let Some(colon) = colon_after_token(msg, token_end) else {
        return;
    };
    if enforce_object_state {
        frame.expect_key = false;
    }

    let Some(kind) = json_field_kind(content) else {
        return;
    };
    frame.scope.fields.push(JsonField {
        kind,
        value: json_string_value_after_colon(msg, colon + 1),
    });
}

fn colon_after_token(msg: &str, token_end: usize) -> Option<usize> {
    let bytes = msg.as_bytes();
    let mut index = token_end;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    (bytes.get(index) == Some(&b':')).then_some(index)
}

fn json_string_value_after_colon(msg: &str, start: usize) -> Option<&str> {
    let bytes = msg.as_bytes();
    let mut index = start;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }

    let (style, quote_index) = match (bytes.get(index), bytes.get(index + 1)) {
        (Some(b'"'), _) => (QuoteStyle::Direct, index),
        (Some(b'\\'), Some(b'"')) => (QuoteStyle::BackslashEscaped, index + 1),
        _ => return None,
    };
    let content_start = quote_index + 1;

    for closing_quote in content_start..bytes.len() {
        if bytes[closing_quote] != b'"' {
            continue;
        }
        let backslashes = preceding_backslash_count(bytes, closing_quote);
        if quote_closes(style, backslashes) {
            let content_end = match style {
                QuoteStyle::Direct => closing_quote,
                QuoteStyle::BackslashEscaped => closing_quote.checked_sub(1)?,
            };
            return msg.get(content_start..content_end);
        }
    }
    None
}

fn json_field_kind(key: &str) -> Option<JsonFieldKind> {
    match key {
        "AppId" => Some(JsonFieldKind::AppId),
        "Id" => Some(JsonFieldKind::Id),
        "ApplicationName" => Some(JsonFieldKind::ApplicationName),
        "Name" => Some(JsonFieldKind::Name),
        "SetUpFilePath" => Some(JsonFieldKind::SetUpFilePath),
        _ => None,
    }
}

fn extract_all_identity_name_pairs(
    scan: &JsonFieldScan<'_>,
) -> Vec<(String, String, GuidNameSource)> {
    std::iter::once(&scan.root)
        .chain(scan.scopes.iter())
        .filter_map(identity_name_pair)
        .collect()
}

fn identity_name_pair(scope: &JsonObjectScope<'_>) -> Option<(String, String, GuidNameSource)> {
    let guid = match classify_scope_identity(scope) {
        ExplicitAppIdentity::Valid(guid) => guid,
        ExplicitAppIdentity::Absent | ExplicitAppIdentity::Invalid => return None,
    };
    let (name, source) = scope_name(scope)?;
    Some((guid, name, source))
}

fn scope_name(scope: &JsonObjectScope<'_>) -> Option<(String, GuidNameSource)> {
    for kind in [
        JsonFieldKind::ApplicationName,
        JsonFieldKind::Name,
        JsonFieldKind::SetUpFilePath,
    ] {
        let mut values = scope
            .fields
            .iter()
            .filter(|field| field.kind == kind)
            .filter_map(|field| field.value);
        let Some(value) = values.next() else {
            continue;
        };
        // Repeated identical values are deterministic. Conflicting values of
        // the highest-priority available name kind make the scope ambiguous.
        if values.any(|candidate| candidate != value) {
            return None;
        }
        return Some(match kind {
            JsonFieldKind::ApplicationName => (value.to_string(), GuidNameSource::ApplicationName),
            JsonFieldKind::Name => (value.to_string(), GuidNameSource::NameField),
            JsonFieldKind::SetUpFilePath => (setup_file_name(value), GuidNameSource::SetUpFilePath),
            JsonFieldKind::AppId | JsonFieldKind::Id => unreachable!(),
        });
    }
    None
}

/// Extract a GUID from a log message via JSON identity fields.
///
/// Checks (in order): `"AppId"`, `"Id"`, then falls back to a generic
/// GUID regex when a name field is also present on the same line.
pub(crate) fn extract_app_id(msg: &str) -> Option<String> {
    let context = explicit_app_identity_context_with_named_guid_fallback(msg);
    match context.identity {
        ExplicitAppIdentity::Valid(guid) => Some(guid),
        ExplicitAppIdentity::Invalid => None,
        ExplicitAppIdentity::Absent => context.fallback_app_id,
    }
}

/// Resolve one explicit identity selection and its object-local name in a
/// single bounded scan. A valid identity without a local unambiguous name is
/// an enrichment boundary; callers must not substitute a global registry name.
pub(crate) fn explicit_app_identity_context(msg: &str) -> ExplicitAppIdentityContext {
    explicit_app_identity_context_impl(msg, false)
}

/// Resolve explicit identity context and opt into the legacy named-GUID
/// fallback. Callers that already apply their own GUID heuristics should use
/// `explicit_app_identity_context` so this fallback is not computed twice.
pub(crate) fn explicit_app_identity_context_with_named_guid_fallback(
    msg: &str,
) -> ExplicitAppIdentityContext {
    explicit_app_identity_context_impl(msg, true)
}

fn explicit_app_identity_context_impl(
    msg: &str,
    include_named_guid_fallback: bool,
) -> ExplicitAppIdentityContext {
    let Ok(scan) = scan_json_fields(msg) else {
        return ExplicitAppIdentityContext {
            identity: ExplicitAppIdentity::Invalid,
            local_name: None,
            fallback_app_id: None,
        };
    };

    match select_explicit_app_identity(&scan) {
        ExplicitAppIdentitySelection::Absent => ExplicitAppIdentityContext {
            identity: ExplicitAppIdentity::Absent,
            local_name: None,
            // Preserve the established named-context fallback without running
            // the structural scanner a second time.
            fallback_app_id: if include_named_guid_fallback && scan_has_name_field(&scan) {
                #[cfg(test)]
                record_named_guid_fallback_extraction();
                guid_re()
                    .captures(msg)
                    .and_then(|captures| captures.get(1))
                    .map(|matched| matched.as_str().to_ascii_lowercase())
            } else {
                None
            },
        },
        ExplicitAppIdentitySelection::Valid { guid, scope } => ExplicitAppIdentityContext {
            identity: ExplicitAppIdentity::Valid(guid),
            local_name: scope_name(scope).map(|(name, _)| name),
            fallback_app_id: None,
        },
        ExplicitAppIdentitySelection::Invalid => ExplicitAppIdentityContext {
            identity: ExplicitAppIdentity::Invalid,
            local_name: None,
            fallback_app_id: None,
        },
    }
}

/// Classify explicit JSON `AppId`/`Id` fields without falling back to other
/// GUIDs on the line. An invalid explicit field is an identity boundary: its
/// presence suppresses line-wide GUID inference.
#[cfg(test)]
pub(crate) fn explicit_app_identity(msg: &str) -> ExplicitAppIdentity {
    explicit_app_identity_context(msg).identity
}

fn select_explicit_app_identity<'scan, 'msg>(
    scan: &'scan JsonFieldScan<'msg>,
) -> ExplicitAppIdentitySelection<'scan, 'msg> {
    let root_identity = classify_scope_identity(&scan.root);
    let mut selected =
        (root_identity != ExplicitAppIdentity::Absent).then_some((&scan.root, root_identity));
    let mut start = 0;
    while start < scan.scopes.len() {
        let tree_start = scan.scopes[start].tree_start;
        let mut end = start;
        let mut tree_identity = None;
        let mut identity_span = None;
        let mut ambiguous = false;
        while end < scan.scopes.len() && scan.scopes[end].tree_start == tree_start {
            let identity = classify_scope_identity(&scan.scopes[end]);
            if identity != ExplicitAppIdentity::Absent {
                match identity_span {
                    None => {
                        identity_span = Some((scan.scopes[end].start, scan.scopes[end].end));
                        tree_identity = Some((&scan.scopes[end], identity));
                    }
                    Some((outer_start, outer_end))
                        if scan.scopes[end].start >= outer_start
                            && scan.scopes[end].end <= outer_end => {}
                    Some(_) => ambiguous = true,
                }
            }
            end += 1;
        }

        if let Some((scope, mut identity)) = tree_identity {
            if ambiguous {
                identity = ExplicitAppIdentity::Invalid;
            }
            if selected.is_some() {
                return ExplicitAppIdentitySelection::Invalid;
            }
            selected = Some((scope, identity));
        }
        start = end;
    }

    match selected {
        None => ExplicitAppIdentitySelection::Absent,
        Some((scope, ExplicitAppIdentity::Valid(guid))) => {
            ExplicitAppIdentitySelection::Valid { guid, scope }
        }
        Some((_, ExplicitAppIdentity::Invalid)) => ExplicitAppIdentitySelection::Invalid,
        Some((_, ExplicitAppIdentity::Absent)) => unreachable!(),
    }
}

fn classify_scope_identity(scope: &JsonObjectScope<'_>) -> ExplicitAppIdentity {
    let allow_decorated = scope.fields.iter().any(|field| {
        matches!(
            field.kind,
            JsonFieldKind::ApplicationName | JsonFieldKind::Name | JsonFieldKind::SetUpFilePath
        ) && field.value.is_some()
    });
    let app_id = classify_identity_fields(scope, JsonFieldKind::AppId, allow_decorated);
    let app_id_absent = matches!(app_id, IdentityFieldState::Absent);
    match app_id {
        IdentityFieldState::Valid(value) => return ExplicitAppIdentity::Valid(value),
        IdentityFieldState::Conflict => return ExplicitAppIdentity::Invalid,
        IdentityFieldState::Absent | IdentityFieldState::Malformed => {}
    }

    match classify_identity_fields(scope, JsonFieldKind::Id, allow_decorated) {
        IdentityFieldState::Valid(value) => ExplicitAppIdentity::Valid(value),
        IdentityFieldState::Absent if app_id_absent => ExplicitAppIdentity::Absent,
        IdentityFieldState::Absent
        | IdentityFieldState::Malformed
        | IdentityFieldState::Conflict => ExplicitAppIdentity::Invalid,
    }
}

fn classify_identity_fields(
    scope: &JsonObjectScope<'_>,
    kind: JsonFieldKind,
    allow_decorated: bool,
) -> IdentityFieldState {
    let members = scope
        .fields
        .iter()
        .filter(|field| field.kind == kind)
        .map(|field| {
            field.value.and_then(|value| {
                exact_guid(value).or_else(|| {
                    if allow_decorated {
                        guid_re()
                            .captures(value)
                            .and_then(|captures| captures.get(1))
                            .map(|matched| matched.as_str().to_ascii_lowercase())
                    } else {
                        None
                    }
                })
            })
        })
        .collect::<Vec<_>>();

    match members.as_slice() {
        [] => IdentityFieldState::Absent,
        [Some(guid)] => IdentityFieldState::Valid(guid.clone()),
        [None] => IdentityFieldState::Malformed,
        many if many.iter().any(Option::is_none) => IdentityFieldState::Conflict,
        [Some(first), rest @ ..]
            if rest
                .iter()
                .all(|value| value.as_ref().is_some_and(|guid| guid == first)) =>
        {
            IdentityFieldState::Valid(first.clone())
        }
        _ => IdentityFieldState::Conflict,
    }
}

fn exact_guid(value: &str) -> Option<String> {
    let matched = guid_re().find(value)?;
    (matched.start() == 0 && matched.end() == value.len()).then(|| value.to_ascii_lowercase())
}

pub(crate) fn normalize_guid_key(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn scan_has_name_field(scan: &JsonFieldScan<'_>) -> bool {
    scan.root
        .fields
        .iter()
        .chain(scan.scopes.iter().flat_map(|scope| scope.fields.iter()))
        .any(|field| {
            matches!(
                field.kind,
                JsonFieldKind::ApplicationName | JsonFieldKind::Name | JsonFieldKind::SetUpFilePath
            ) && field.value.is_some()
        })
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
    // Accept only a complete 8-4-4-4-12 GUID shape.
    let is_full_guid = exact_guid(inner).is_some();
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

pub(crate) fn enrich_event_name_with_name(
    current_name: &str,
    resolved_name: &str,
) -> Option<String> {
    strip_short_guid_suffix(current_name).map(|prefix| format!("{prefix}{resolved_name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn strip_guid_suffix_rejects_malformed_full_length_shape() {
        assert_eq!(
            strip_short_guid_suffix("Some Name (------------------------------------)"),
            None
        );
        assert_eq!(
            strip_short_guid_suffix("Some Name (a1b2c3d4e5f6-7890-abcd-ef12-34567890)"),
            None
        );
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
    fn named_context_fallback_normalizes_guid_case() {
        let upper = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
        let lower = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        assert_eq!(
            extract_app_id(&format!(
                r#"Processing identity {upper} for {{"ApplicationName":"Contoso"}}"#
            )),
            Some(lower.to_string())
        );
    }

    #[test]
    fn explicit_identity_context_carries_the_named_guid_fallback_from_its_scan() {
        let upper = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
        let lower = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let messages = [
            format!(r#"Processing identity {upper} for {{"ApplicationName":"Contoso"}}"#),
            format!(r#"Processing identity {upper} for {{\"Name\":\"Contoso\"}}"#),
        ];

        for message in messages {
            let context = explicit_app_identity_context(&message);
            assert_eq!(context.identity, ExplicitAppIdentity::Absent);
            assert_eq!(context.fallback_app_id, None);

            let context = explicit_app_identity_context_with_named_guid_fallback(&message);
            assert_eq!(context.identity, ExplicitAppIdentity::Absent);
            assert_eq!(context.fallback_app_id.as_deref(), Some(lower));
        }

        let context = explicit_app_identity_context(&format!("Processing identity {upper}"));
        assert_eq!(context.identity, ExplicitAppIdentity::Absent);
        assert_eq!(context.fallback_app_id, None);

        let valid = explicit_app_identity_context_with_named_guid_fallback(&format!(
            r#"Processing identity {upper} for {{"AppId":"{lower}","Name":"Contoso"}}"#
        ));
        assert_eq!(
            valid.identity,
            ExplicitAppIdentity::Valid(lower.to_string())
        );
        assert_eq!(valid.fallback_app_id, None);

        let invalid = explicit_app_identity_context_with_named_guid_fallback(&format!(
            r#"Processing identity {upper} for {{"AppId":"invalid","Name":"Contoso"}}"#
        ));
        assert_eq!(invalid.identity, ExplicitAppIdentity::Invalid);
        assert_eq!(invalid.fallback_app_id, None);
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

    #[test]
    fn duplicate_identical_normalized_identity_values_remain_valid() {
        let lower = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let upper = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
        let messages = [
            format!(r#"{{"AppId":"{upper}",\"AppId\":\"{lower}\"}}"#),
            format!(r#"{{\"Id\":\"{upper}\","Id":"{lower}"}}"#),
            format!(r#"{{"AppId":"{lower}","AppId":"{lower}"}}"#),
        ];

        for message in messages {
            assert_eq!(
                explicit_app_identity(&message),
                ExplicitAppIdentity::Valid(lower.to_string()),
                "duplicate normalization depended on order for {message}"
            );
        }

        let fallback = format!(r#"{{"AppId":"invalid","Id":"{lower}"}}"#);
        assert_eq!(
            explicit_app_identity(&fallback),
            ExplicitAppIdentity::Valid(lower.to_string())
        );
    }

    #[test]
    fn outer_identity_precedes_nested_identity_fields() {
        let outer = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let nested = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(
                r#"{{"AppId":"{outer}","Name":"Outer","Metadata":{{"AppId":"{nested}","Name":"Nested"}}}}"#
            ),
            format!(
                r#"{{"Id":"{outer}","Name":"Outer","Metadata":{{"AppId":"{nested}","Name":"Nested"}}}}"#
            ),
            format!(
                r#"{{\"AppId\":\"{outer}\",\"Name\":\"Outer\",\"Metadata\":{{\"Id\":\"{nested}\",\"Name\":\"Nested\"}}}}"#
            ),
            format!(
                r#"{{"Wrapper":{{"AppId":"{outer}","Name":"Outer","Metadata":{{"AppId":"{nested}","Name":"Nested"}}}}}}"#
            ),
        ];

        for message in messages {
            assert_eq!(
                explicit_app_identity(&message),
                ExplicitAppIdentity::Valid(outer.to_string()),
                "nested identity overrode outer scope for {message}"
            );
        }
    }

    #[test]
    fn escaped_quote_braces_remain_inside_one_object_scope() {
        let message = r#"{\"AppId\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"ApplicationName\":\"Quoted \\\"value with { braces }\\\" tail\"}"#;
        let scan = scan_json_fields(message).expect("bounded payload should scan");

        assert_eq!(
            scan.scopes.len(),
            1,
            "escaped string was split into child scopes"
        );
        assert!(
            scope_name(&scan.scopes[0]).is_some_and(|(name, _)| name.contains("{ braces }")),
            "braces inside the escaped quoted value were not retained"
        );
    }

    #[test]
    fn independent_sibling_identity_objects_are_ambiguous() {
        let first = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let second = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(r#"[{{"AppId":"{first}"}},{{"AppId":"{second}"}}]"#),
            format!(r#"[{{"AppId":"{second}"}},{{"AppId":"{first}"}}]"#),
            format!(r#"[{{"Id":"{first}"}},{{"AppId":"{second}"}}]"#),
            format!(r#"[{{"AppId":"{second}"}},{{"Id":"{first}"}}]"#),
            format!(r#"{{"Items":[{{"Id":"{first}"}},{{"AppId":"{second}"}}]}}"#),
            format!(
                r#"{{"Left":{{"AppId":"{first}"}},"Right":{{"Metadata":{{"AppId":"{second}"}}}}}}"#
            ),
            format!(
                r#"{{"Left":{{"Metadata":{{"AppId":"{second}"}}}},"Right":{{"AppId":"{first}"}}}}"#
            ),
            format!(r#""Id":"{first}" {{"Metadata":{{"AppId":"{second}"}}}}"#),
            format!(r#"[{{\"Id\":\"{first}\"}},{{\"AppId\":\"{second}\"}}]"#),
        ];

        for message in messages {
            assert_eq!(
                explicit_app_identity(&message),
                ExplicitAppIdentity::Invalid,
                "selected one independent sibling for {message}"
            );
        }
    }

    #[test]
    fn quoted_key_like_text_is_not_an_identity_field() {
        let selected = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let injected = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(r#"{{"AppId":"{selected}","Name":"literal \"AppId\":\"{injected}\" text"}}"#),
            format!(r#"{{"Name":"literal \"AppId\":\"{injected}\" text","AppId":"{selected}"}}"#),
            format!(r#"{{"Id":"{selected}","Name":"literal \"AppId\":\"{injected}\" text"}}"#),
            format!(
                r#"{{\"AppId\":\"{selected}\",\"Name\":\"literal \\\"AppId\\\":\\\"{injected}\\\" text\"}}"#
            ),
        ];

        for message in messages {
            assert_eq!(
                explicit_app_identity(&message),
                ExplicitAppIdentity::Valid(selected.to_string()),
                "treated quoted value text as a field for {message}"
            );
        }
    }
}
