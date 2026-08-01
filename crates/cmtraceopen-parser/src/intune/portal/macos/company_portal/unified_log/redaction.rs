//! Deterministic redacted export.
//!
//! # Contract
//!
//! * **Deterministic** — redaction is a fixed, ordered sequence of pure regex
//!   substitutions. It holds no counters, no maps keyed on iteration order, and
//!   no time or randomness. The same input always yields byte-identical output.
//! * **Stable placeholders** — every removed value becomes `[redacted:<category>]`
//!   with a category drawn from a closed set, so a reader can tell *what* was
//!   removed without being able to recover it.
//! * **Stable ordering** — evidence stays in exact source sequence, activities
//!   stay in first-appearance order, coverage is sorted by its deterministic id,
//!   and unknown fields live in `BTreeMap`s.
//!
//! # What is redacted
//!
//! Identity and UPN/email, tenant/device/user/object identifiers, serial
//! numbers, tokens and secrets, URLs (which removes their query values whole),
//! certificate subjects and thumbprints, host names, and file paths.
//!
//! Fields whose entire value is one identifier — `hostName`,
//! `processImagePath`, `senderImagePath` — are replaced wholesale rather than
//! pattern-matched, because a pattern only removes the part it recognises.
//!
//! # What is deliberately preserved
//!
//! Activity, signpost, trace, request, and correlation identifiers survive
//! redaction. They are ephemeral per-boot or per-operation handles that name no
//! person, tenant, or device, and the issue's contract requires that
//! activity/signpost relationships and the direct-log join keys stay intact in
//! an exported reduction. Capture predicate, window, and version metadata also
//! survive, because provenance is what makes an export reproducible.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::models::*;
use super::schema::{
    PORTAL_UNIFIED_LOG_REDACTION_PLACEHOLDER_STYLE, PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID,
};

const IDENTITY: &str = "[redacted:identity]";
const GUID: &str = "[redacted:guid]";
const SERIAL: &str = "[redacted:serial]";
const TOKEN: &str = "[redacted:token]";
const URL: &str = "[redacted:url]";
const CERTIFICATE: &str = "[redacted:certificate]";
const PATH: &str = "[redacted:path]";
const HOST: &str = "[redacted:host]";

/// A value separator: `=`, `:`, or whitespace after a label.
///
/// The optional closing quote matters. A malformed NDJSON line is kept verbatim
/// as a coverage excerpt and redacted by these patterns alone, and in JSON the
/// label arrives as `"serialNumber":"C02..."`. Without tolerating the quote
/// between the label and the separator, every label-scoped rule failed to match
/// exactly the input that needs them most.
const LABEL_SEPARATOR: &str = r#"(["']?\s*[:=]\s*|\s+)"#;
/// A quoted or bare value, stopping at the usual delimiters.
const LABEL_VALUE: &str = r#"(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;"']+)"#;

fn compiled(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("portal unified-log redaction pattern"))
}

fn jwt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    )
}

fn labeled_secret_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        &format!(
            r#"(?i)\b(access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|auth[_-]?token|client[_-]?secret|api[_-]?key|apikey|authorization|password|passwd|pwd|secret|token){LABEL_SEPARATOR}{LABEL_VALUE}"#
        ),
    )
}

/// `Authorization: Bearer <opaque>` and friends.
///
/// `labeled_secret_pattern` alone stops its value at the first whitespace, so on
/// `Authorization: Bearer abc123...` it redacts the scheme word `Bearer` and
/// leaves the credential in plaintext. A JWT is already caught by shape, but an
/// opaque bearer or a Basic blob is not. This runs first and takes the
/// credential that follows the scheme.
fn auth_scheme_credential_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        r"(?i)\b(Bearer|Basic|Digest|Negotiate|NTLM)\s+([A-Za-z0-9._~+/=-]{8,})",
    )
}

/// Dotted-quad IPv4, each octet bounded to 0-255 so version strings do not match.
fn ipv4_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
    )
}

/// Six colon- or dash-separated hex pairs. Runs before the IPv6 matcher, which
/// needs eight groups or a `::` run and so cannot claim a MAC.
fn mac_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(&CELL, r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
}

/// Fully expanded eight-group IPv6 or any `::`-compressed form, preceded by a
/// captured delimiter in group 1 that the replacement must write back out.
///
/// The address is **not** wrapped in `\b`. `\b` is a word-boundary assertion and
/// `:` is not a word character, so it fails in both directions here: it cannot
/// anchor an address that begins or ends with a colon, which every
/// `::`-compressed form does at one end or both, and it happily anchors a bare
/// `::` sitting between two word characters, which turned `std::process::exit`
/// in prose into two host placeholders.
///
/// This engine has no look-around, so the left edge is a *consumed* guard group
/// and the right edge has no assertion at all. That asymmetry is deliberate:
///
/// * Consuming only the left delimiter keeps two addresses separated by a single
///   character both matchable. A guard on both sides would eat the delimiter the
///   following address needs, and `^` cannot stand in for it because it anchors
///   to the start of the text, not to where scanning resumed.
/// * No right-edge assertion is needed because the alternatives are already
///   self-limiting: they consume only hex and colons, and each requires either
///   eight groups or a `::` run. A MAC (`00:11:22:33:44:55`) and a wall-clock
///   timestamp (`08:18:00:104`) have neither, so neither can be claimed.
///
/// A bare `::` carrying no group is excluded on purpose: it is the all-zeros
/// address, it identifies nothing, and matching it damages prose.
fn ipv6_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        r"(?i)(^|[^0-9A-Za-z:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)",
    )
}

fn labeled_certificate_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        &format!(
            r"(?i)\b(thumbprint|fingerprint|cert[_-]?hash){LABEL_SEPARATOR}[0-9a-fA-F][0-9a-fA-F:]{{15,}}"
        ),
    )
}

fn labeled_serial_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        &format!(
            r#"(?i)\b(device[_-]?serial(?:[_-]?number)?|serial[_-]?number|serial){LABEL_SEPARATOR}{LABEL_VALUE}"#
        ),
    )
}

fn labeled_identifier_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        &format!(
            r#"(?i)\b(tenant[_-]?id|aad[_-]?device[_-]?id|entra[_-]?device[_-]?id|azure[_-]?ad[_-]?device[_-]?id|managed[_-]?device[_-]?id|device[_-]?id|object[_-]?id|user[_-]?id|upn){LABEL_SEPARATOR}{LABEL_VALUE}"#
        ),
    )
}

fn url_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(&CELL, r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+"#)
}

fn user_path_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    // Real macOS paths contain spaces: `/Users/alice/Applications/Company
    // Portal.app/...`. Stopping at the first space redacted only the head and
    // left the tail in the export. Absorb a space only when the run that
    // follows it still contains a `/`, so a path keeps going but ordinary prose
    // after a path does not get swallowed. Written without look-ahead, which
    // this regex engine does not support.
    compiled(
        &CELL,
        r#"(?i)/Users/[^\s"'<>,;)]*(?:\x20[^\s"'<>,;)]*/[^\s"'<>,;)]*)*"#,
    )
}

fn certificate_subject_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(&CELL, r"(?i)\bCN=[^,;\r\n]+")
}

fn email_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    // Unicode-aware. An ASCII-only class does not truncate a non-ASCII identity,
    // it misses it entirely: with an accented leading character there is no word
    // boundary for the leading `\b` to anchor on, so the whole address survives.
    compiled(&CELL, r"(?i)[\w.%+\-]+@[\w.\-]+\.\w{2,}")
}

fn guid_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    compiled(
        &CELL,
        r"(?i)\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b",
    )
}

/// Applies the redaction policy to free text.
///
/// The substitution order is fixed and part of the contract: label-scoped rules
/// run before shape-based ones so a labelled secret is never partially matched
/// by a broader pattern first.
pub fn redact_text(input: &str) -> String {
    let step1 = jwt_pattern().replace_all(input, TOKEN);
    // Before the generic labelled rule, whose value stops at the first space and
    // would otherwise redact only the scheme word.
    let step2 = auth_scheme_credential_pattern().replace_all(&step1, format!("${{1}} {TOKEN}"));
    let step3 = labeled_secret_pattern().replace_all(&step2, format!("${{1}}${{2}}{TOKEN}"));
    let step4 =
        labeled_certificate_pattern().replace_all(&step3, format!("${{1}}${{2}}{CERTIFICATE}"));
    let step5 = labeled_serial_pattern().replace_all(&step4, format!("${{1}}${{2}}{SERIAL}"));
    let step6 = labeled_identifier_pattern().replace_all(&step5, format!("${{1}}${{2}}{GUID}"));
    let step7 = url_pattern().replace_all(&step6, URL);
    let step8 = user_path_pattern().replace_all(&step7, PATH);
    let step9 = certificate_subject_pattern().replace_all(&step8, CERTIFICATE);
    let step10 = email_pattern().replace_all(&step9, IDENTITY);
    let step11 = guid_pattern().replace_all(&step10, GUID);
    // Network addresses last, after URLs have already taken any embedded host.
    // IPv4 before IPv6 so an IPv4-mapped IPv6 cannot leak its dotted tail, and
    // MAC between the two so it is not mistaken for a compressed IPv6 run.
    let step12 = ipv4_address_pattern().replace_all(&step11, HOST);
    let step13 = mac_address_pattern().replace_all(&step12, HOST);
    // `${1}` is the delimiter the IPv6 pattern had to consume on the left; it is
    // evidence framing, not part of the address, so it is written back out.
    ipv6_address_pattern()
        .replace_all(&step13, format!("${{1}}{HOST}"))
        .into_owned()
}

fn redact_classified(value: &PortalClassifiedString) -> PortalClassifiedString {
    match value.sensitivity {
        PortalSensitivity::Public => value.clone(),
        PortalSensitivity::Sensitive => PortalClassifiedString {
            value: redact_text(&value.value),
            sensitivity: PortalSensitivity::Sensitive,
        },
    }
}

fn redact_optional(value: &Option<PortalClassifiedString>) -> Option<PortalClassifiedString> {
    value.as_ref().map(redact_classified)
}

/// Replaces a whole field value with a single placeholder.
///
/// Used for fields whose *entire* value is one identifier — a file path, a host
/// name. Pattern matching is the wrong tool there: it only removes the parts it
/// recognises and leaves the rest, so `/Users/someone/Applications/App.app`
/// would keep its tail, and a bare host name matches no pattern at all.
fn redact_opaque(
    value: &Option<PortalClassifiedString>,
    placeholder: &str,
) -> Option<PortalClassifiedString> {
    value.as_ref().map(|value| match value.sensitivity {
        PortalSensitivity::Public => value.clone(),
        PortalSensitivity::Sensitive => PortalClassifiedString::sensitive(placeholder),
    })
}

/// Placeholder implied by a sensitive JSON member name.
///
/// Free text carries its own labels (`tenantId=...`), but a JSON member puts
/// the label in the key and the secret in the value, where no text pattern can
/// see it. This closes that gap for the `unknownFields` a collector may attach.
fn placeholder_for_member(key: &str) -> Option<&'static str> {
    let normalized: String = key
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect();

    let placeholder = match normalized.as_str() {
        "serial" | "serialnumber" | "deviceserial" | "deviceserialnumber" => SERIAL,
        "tenantid" | "deviceid" | "aaddeviceid" | "entradeviceid" | "azureaddeviceid"
        | "manageddeviceid" | "objectid" | "userid" | "accountid" => GUID,
        "upn" | "userprincipalname" | "email" | "emailaddress" | "username" | "user" => IDENTITY,
        "token" | "accesstoken" | "refreshtoken" | "idtoken" | "bearertoken" | "authtoken"
        | "authorization" | "password" | "passwd" | "pwd" | "secret" | "clientsecret"
        | "apikey" => TOKEN,
        "url" | "uri" | "endpoint" | "requesturl" | "reporturl" | "serviceurl" => URL,
        "thumbprint" | "fingerprint" | "certhash" | "certificate" => CERTIFICATE,
        "path" | "filepath" | "imagepath" | "directory" => PATH,
        _ => return None,
    };
    Some(placeholder)
}

fn redact_json(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let redacted = match placeholder_for_member(key) {
                        Some(placeholder) => Value::String(placeholder.to_string()),
                        None => redact_json(item),
                    };
                    (key.clone(), redacted)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn redact_capture(capture: &PortalUnifiedLogCapture) -> PortalUnifiedLogCapture {
    let mut capture = capture.clone();
    capture.host.host_name = redact_opaque(&capture.host.host_name, HOST);
    capture.redaction = PortalCaptureRedaction {
        applied: true,
        policy_id: Some(PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID.to_string()),
        placeholder_style: Some(PORTAL_UNIFIED_LOG_REDACTION_PLACEHOLDER_STYLE.to_string()),
    };
    capture
}

fn redact_coverage(coverage: &[PortalCoverageEntry]) -> Vec<PortalCoverageEntry> {
    let mut entries: Vec<PortalCoverageEntry> = coverage
        .iter()
        .map(|entry| PortalCoverageEntry {
            coverage_id: entry.coverage_id.clone(),
            status: entry.status.clone(),
            scope: entry.scope.clone(),
            detail: redact_text(&entry.detail),
            stream_index: entry.stream_index,
            raw_excerpt: redact_optional(&entry.raw_excerpt),
            evidence: entry.evidence.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.coverage_id.cmp(&b.coverage_id));
    entries
}

fn redact_record(record: &PortalUnifiedLogRecord) -> PortalUnifiedLogRecord {
    let unknown_fields: BTreeMap<String, Value> = record
        .unknown_fields
        .iter()
        .map(|(key, value)| (key.clone(), redact_json(value)))
        .collect();

    let mut redaction = record.redaction.clone();
    redaction.applied = true;
    redaction.policy_id = Some(PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID.to_string());
    // Only claim a field was redacted when it actually carried a sensitive
    // value. `build_record` classifies these three as `Sensitive`, but public
    // construction and deserialization can hand us `Public` values, which
    // redaction deliberately leaves alone. Listing them unconditionally told a
    // consumer that a value had been scrubbed when it had been passed through.
    let mut claim = |field: &str, sensitivity: &PortalSensitivity| {
        if *sensitivity == PortalSensitivity::Sensitive
            && !redaction.redacted_fields.iter().any(|f| f == field)
        {
            redaction.redacted_fields.push(field.to_string());
        }
    };
    claim("eventMessage", &record.event_message.sensitivity);
    if let Some(path) = &record.process_image_path {
        claim("processImagePath", &path.sensitivity);
    }
    if let Some(path) = &record.sender_image_path {
        claim("senderImagePath", &path.sensitivity);
    }
    redaction.redacted_fields.sort();

    PortalUnifiedLogRecord {
        process_image_path: redact_opaque(&record.process_image_path, PATH),
        sender_image_path: redact_opaque(&record.sender_image_path, PATH),
        event_message: redact_classified(&record.event_message),
        unknown_fields,
        redaction,
        ..record.clone()
    }
}

/// Deterministic redacted projection of a validated capture, records included.
pub fn redacted_capture_projection(
    capture_set: &PortalUnifiedLogCaptureSet,
) -> PortalUnifiedLogCaptureSet {
    PortalUnifiedLogCaptureSet {
        schema_id: capture_set.schema_id.clone(),
        schema_version: capture_set.schema_version,
        supported: capture_set.supported,
        capture: capture_set.capture.as_ref().map(redact_capture),
        records: capture_set.records.iter().map(redact_record).collect(),
        coverage: redact_coverage(&capture_set.coverage),
        stats: capture_set.stats.clone(),
        raw_unsupported: capture_set
            .raw_unsupported
            .iter()
            .map(redact_json)
            .collect(),
    }
}

/// Deterministic redacted projection of a reduction, suitable for export.
pub fn redacted_export_projection(
    reduction: &PortalUnifiedLogReduction,
) -> PortalUnifiedLogReduction {
    let evidence: Vec<PortalUnifiedLogEvidence> = reduction
        .evidence
        .iter()
        .map(|item| PortalUnifiedLogEvidence {
            summary: redact_classified(&item.summary),
            ..item.clone()
        })
        .collect();

    let mut activities = reduction.activities.clone();
    activities.sort_by(|a, b| {
        a.first_stream_index
            .cmp(&b.first_stream_index)
            .then_with(|| a.activity_id.cmp(&b.activity_id))
    });

    PortalUnifiedLogReduction {
        schema_id: reduction.schema_id.clone(),
        schema_version: reduction.schema_version,
        supported: reduction.supported,
        capture: reduction.capture.as_ref().map(redact_capture),
        evidence,
        activities,
        coverage: redact_coverage(&reduction.coverage),
        stats: reduction.stats.clone(),
    }
}
