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
/// identifiers so a hostname inside a URL is not relabelled as an app identifier, and
/// key-anchored tenant/device identifiers are removed before the generic GUID rule so they
/// keep their specific token.
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
    let value = keyed_token_pattern().replace_all(&value, format!("${{key}}={REDACTED_TOKEN}"));
    let value = tenant_id_pattern().replace_all(
        &value,
        format!("${{key}}${{assign}}${{open}}{REDACTED_TENANT_ID}"),
    );
    let value = device_id_pattern().replace_all(
        &value,
        format!("${{key}}${{assign}}${{open}}{REDACTED_DEVICE_ID}"),
    );
    let value = guid_pattern().replace_all(&value, REDACTED_GUID);

    redact_app_identifiers(&value)
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
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
            .expect("email pattern must compile")
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

fn keyed_token_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // `[` is excluded from the value class so an already-substituted
        // `token=[redacted:token]` cannot match again. The regex crate has no lookaround,
        // so the character class is what makes this projection idempotent.
        Regex::new(
            r"(?i)(?P<key>\b(?:access_token|refresh_token|id_token|token|secret|password)\b)\s*=\s*[^\s,;\[\]\)]+",
        )
        .expect("keyed token pattern must compile")
    })
}

fn tenant_id_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<key>\btenant(?:_?id)?\b)(?P<assign>\s*[=:]\s*)(?P<open>[{'"]?)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        )
        .expect("tenant id pattern must compile")
    })
}

fn device_id_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<key>\b(?:device|aad_device|entra_device)_?id\b)(?P<assign>\s*[=:]\s*)(?P<open>[{'"]?)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        )
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
        Regex::new(r"(?i)\b(?:thumbprint|fingerprint)\s*[=:]\s*[0-9a-f]{2}(?::?[0-9a-f]{2}){15,}")
            .expect("certificate thumbprint pattern must compile")
    })
}

fn app_identifier_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\b[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9\-]*){2,}\b")
            .expect("app identifier pattern must compile")
    })
}
