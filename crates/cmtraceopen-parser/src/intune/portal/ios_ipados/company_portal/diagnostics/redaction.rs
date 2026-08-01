//! Deterministic redaction projection for an imported Console capture.
//!
//! Redaction is a pure, order-fixed sequence of pattern replacements onto *stable* typed
//! placeholder tokens. There are no counters, no hashes, and no per-run state, so the same
//! input always produces byte-identical output, and applying the projection twice is a
//! no-op.
//!
//! Structural attribution fields survive redaction. The Company Portal subsystem namespace
//! is what proves a record belongs to Company Portal at all, so redacting it would destroy
//! the evidence chain rather than protect anyone; it identifies Microsoft's own app, not the
//! customer.

use std::sync::OnceLock;

use regex::Regex;

use super::models::*;

pub const REDACTED_EMAIL: &str = "[redacted:email]";
pub const REDACTED_URL: &str = "[redacted:url]";
pub const REDACTED_TOKEN: &str = "[redacted:token]";
pub const REDACTED_CERTIFICATE: &str = "[redacted:certificate]";
pub const REDACTED_TENANT_ID: &str = "[redacted:tenant-id]";
pub const REDACTED_DEVICE_ID: &str = "[redacted:device-id]";
pub const REDACTED_GUID: &str = "[redacted:guid]";
pub const REDACTED_APP_ID: &str = "[redacted:app-id]";
pub const REDACTED_ADDRESS: &str = "[redacted:address]";

/// The separator between a label and its value: `=` or `:`, with the closing quote of a
/// JSON member name tolerated in front of it.
///
/// Console payloads routinely carry a serialized JSON body verbatim, so the label arrives as
/// `"password":"hunter2"` rather than `password=hunter2`. Requiring only whitespace between
/// the label and the separator made every label-scoped rule fail on exactly the shape that
/// needs it most, and no other rule caught a bare secret behind it.
const LABEL_SEPARATOR: &str = r#"["']?\s*[=:]\s*"#;

/// The one reverse-DNS namespace kept in the clear: it is Microsoft's Company Portal itself,
/// and it is the structural signature the capture is filtered on.
const PRESERVED_NAMESPACE_ROOT: &str = "com.microsoft.CompanyPortal";

/// Produce a redacted copy of `capture`.
///
/// Deterministic: record order is source order, and every replacement is a fixed token.
pub fn redacted_export_projection(capture: &PortalConsoleCapture) -> PortalConsoleCapture {
    let mut redacted = capture.clone();

    for record in &mut redacted.records {
        record.message.value = redact_text(&record.message.value);
        record.raw_text = redact_text(&record.raw_text);
        record.source.library = record.source.library.as_deref().map(redact_text);
        // `process`, `subsystem`, and `category` are structural attribution fields and are
        // preserved so the filtering decision stays auditable after export.
    }

    for coverage in &mut redacted.coverage {
        coverage.raw_text = redact_text(&coverage.raw_text);
        coverage.detail = redact_text(&coverage.detail);
    }

    if let Some(layout) = &mut redacted.layout {
        layout.header_raw = redact_text(&layout.header_raw);
    }
    if let Some(layout) = &mut redacted.detection.layout {
        layout.header_raw = redact_text(&layout.header_raw);
    }

    redacted
}

/// Apply every redaction rule in a fixed order.
///
/// Order matters and is part of the contract: URLs are removed before bare reverse-DNS
/// identifiers so a hostname inside a URL is not relabelled as an app identifier,
/// key-anchored tenant/device identifiers are removed before the generic GUID rule so they
/// keep their specific token, and network addresses are removed after URLs so a host inside a
/// URL is already gone by the time the address matchers run.
pub(super) fn redact_text(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }

    let value = certificate_block_pattern().replace_all(value, REDACTED_CERTIFICATE);
    let value = certificate_thumbprint_pattern().replace_all(&value, REDACTED_CERTIFICATE);
    let value = email_pattern().replace_all(&value, REDACTED_EMAIL);
    let value = url_pattern().replace_all(&value, REDACTED_URL);
    let value = bearer_token_pattern().replace_all(&value, format!("Bearer {REDACTED_TOKEN}"));
    let value = jwt_pattern().replace_all(&value, REDACTED_TOKEN);
    let value =
        keyed_secret_pattern().replace_all(&value, format!("${{key}}${{assign}}{REDACTED_TOKEN}"));
    let value = tenant_id_pattern().replace_all(
        &value,
        format!("${{key}}${{assign}}${{open}}{REDACTED_TENANT_ID}"),
    );
    let value = device_id_pattern().replace_all(
        &value,
        format!("${{key}}${{assign}}${{open}}{REDACTED_DEVICE_ID}"),
    );
    let value = guid_pattern().replace_all(&value, REDACTED_GUID);
    // Network addresses run last, after URLs have already taken any embedded host, and in
    // IPv4 -> MAC -> IPv6 order so an IPv4-mapped IPv6 address cannot leak its dotted tail
    // and a MAC is not consumed as a compressed IPv6 run.
    let value = ipv4_address_pattern().replace_all(&value, REDACTED_ADDRESS);
    let value = mac_address_pattern().replace_all(&value, REDACTED_ADDRESS);
    let value = redact_ipv6_addresses(&value);

    redact_app_identifiers(&value)
}

/// Replace IPv6 addresses, including every `::`-compressed form.
///
/// The boundary is checked against the neighbouring characters instead of with `\b`, because
/// `\b` expresses the opposite of the rule this needs. A word boundary requires a word
/// character on exactly one side, so against an address token it fired in precisely the wrong
/// places:
///
/// * a compressed address begins or ends with `:`, so `::1`, `[::1]`, `fe80::` and a bare `::`
///   had no boundary to anchor on and were exported in the clear;
/// * a boundary *does* exist between an identifier character and a colon, so the `::` inside
///   C++ scope resolution matched, and `std::cout` was rewritten to `std[redacted:address]cout`.
///
/// Losing symbol names out of a backtrace destroys the evidence a Console capture is collected
/// for, so the rule cannot simply be widened. The regex crate has no lookaround, so the
/// neighbours are inspected directly, the same way [`redact_app_identifiers`] does.
fn redact_ipv6_addresses(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;

    for matched in ipv6_address_pattern().find_iter(value) {
        output.push_str(&value[cursor..matched.start()]);
        let before = value[..matched.start()].chars().next_back();
        let after = value[matched.end()..].chars().next();
        if before.is_some_and(binds_to_neighbouring_word)
            || after.is_some_and(binds_to_neighbouring_word)
        {
            output.push_str(matched.as_str());
        } else {
            output.push_str(REDACTED_ADDRESS);
        }
        cursor = matched.end();
    }

    output.push_str(&value[cursor..]);
    output
}

/// Whether a neighbouring character makes a candidate a slice of a longer word rather than a
/// whole address token.
///
/// Only identifier characters bind. A trailing `:` deliberately does not: an IPv4-mapped
/// address arrives here as `::ffff:[redacted:address]` because the IPv4 rule already took the
/// dotted tail, and the dangling separator must not stop the `::ffff` head from being redacted.
fn binds_to_neighbouring_word(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Replace reverse-DNS application identifiers, keeping the Company Portal namespace.
fn redact_app_identifiers(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;

    for matched in app_identifier_pattern().find_iter(value) {
        let text = matched.as_str();
        output.push_str(&value[cursor..matched.start()]);
        if text == PRESERVED_NAMESPACE_ROOT
            || text
                .strip_prefix(PRESERVED_NAMESPACE_ROOT)
                .is_some_and(|rest| rest.starts_with('.'))
        {
            output.push_str(text);
        } else {
            output.push_str(REDACTED_APP_ID);
        }
        cursor = matched.end();
    }

    output.push_str(&value[cursor..]);
    output
}

fn email_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Unicode-aware: `\w` covers non-ASCII letters in this engine. An ASCII-only class
        // does not merely truncate a non-ASCII identity, it misses it outright, because with
        // an accented leading character there is no word boundary for a leading `\b` to
        // anchor on and the whole address survives export.
        Regex::new(r"(?i)[\w.%+\-]+@[\w.\-]+\.\w{2,}").expect("email pattern must compile")
    })
}

fn url_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)\bhttps?://[^\s\]\)'"<>]+"#).expect("url pattern must compile")
    })
}

fn bearer_token_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]+=*").expect("bearer pattern must compile")
    })
}

fn jwt_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
            .expect("jwt pattern must compile")
    })
}

fn keyed_secret_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Deliberately over-broad: the value runs to the end of the line instead of stopping
        // at the first delimiter. `password=my secret pass phrase` is a real shape, and a
        // whitespace-bounded value class redacted `my` and exported the rest of the
        // passphrase. Losing the tail of one line to over-redaction is strictly better than
        // leaking a credential; the narrow, GUID-bounded value class is kept below for the
        // low-signal tenant/device labels, where over-capture would destroy evidence.
        //
        // The compound labels are spelled out because `_` is a word character, so a `\b`
        // before `secret` never matches inside `client_secret`.
        //
        // Substituting to the end of the line keeps the projection idempotent: re-running it
        // on `password=[redacted:token]` reproduces the same line byte for byte.
        Regex::new(&format!(
            r"(?i)(?P<key>\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|auth[_-]?token|client[_-]?secret|api[_-]?key|apikey|token|secret|password|passwd|pwd))(?P<assign>{LABEL_SEPARATOR})[^\r\n]*"
        ))
        .expect("keyed secret pattern must compile")
    })
}

fn tenant_id_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<key>\btenant(?:[_-]?id)?\b)(?P<assign>{LABEL_SEPARATOR})(?P<open>[{{'"]?)[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}"#
        ))
        .expect("tenant id pattern must compile")
    })
}

fn device_id_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?P<key>\b(?:device|aad[_-]?device|entra[_-]?device|managed[_-]?device)[_-]?id\b)(?P<assign>{LABEL_SEPARATOR})(?P<open>[{{'"]?)[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}"#
        ))
        .expect("device id pattern must compile")
    })
}

fn guid_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("guid pattern must compile")
    })
}

fn certificate_block_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]*CERTIFICATE-----.*?-----END [A-Z ]*CERTIFICATE-----")
            .expect("certificate block pattern must compile")
    })
}

fn certificate_thumbprint_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)\b(?:thumbprint|fingerprint|cert[_-]?hash){LABEL_SEPARATOR}["']?[0-9a-f]{{2}}(?::?[0-9a-f]{{2}}){{15,}}"#
        ))
        .expect("certificate thumbprint pattern must compile")
    })
}

/// Dotted-quad IPv4, each octet bounded to 0-255 so a dotted version string such as
/// `5.2504.0.1234` is not read as an address.
fn ipv4_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        )
        .expect("IPv4 pattern must compile")
    })
}

/// Six colon- or dash-separated hex pairs. Runs before the IPv6 matcher, which needs eight
/// groups or a `::` run and so cannot claim a MAC.
fn mac_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
            .expect("MAC address pattern must compile")
    })
}

/// Fully expanded eight-group IPv6 or any `::`-compressed form.
///
/// The quantifiers are greedy so the scan consumes the whole address and never leaves a
/// trailing fragment in the clear. Deliberately unanchored: token boundaries are decided by
/// [`redact_ipv6_addresses`], which explains why `\b` cannot express them.
fn ipv6_address_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)",
        )
        .expect("IPv6 pattern must compile")
    })
}

fn app_identifier_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\b[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9\-]*){2,}\b")
            .expect("app identifier pattern must compile")
    })
}
