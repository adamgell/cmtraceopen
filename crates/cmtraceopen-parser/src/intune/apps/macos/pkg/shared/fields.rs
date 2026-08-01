//! `Key=Value` field extraction shared by both macOS app leaves.
//!
//! Every message either of the reducers keys on states its identifiers
//! explicitly. This module is the only place that reads them, so "a transaction
//! is keyed on stated identifiers, never on time or component proximity" is
//! enforced in one place rather than restated per rule.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};

/// The start of a `Key=` field: a bare word plus `=`, at the start of the
/// message or after whitespace.
///
/// Requiring the preceding whitespace is what keeps a URL intact. In
/// `Url=https://host/a?sig=abc` the inner `sig=` is preceded by `?`, so it is
/// not a field start and the URL is not split in half.
fn field_start_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?:^|\s)(?P<key>[A-Za-z][A-Za-z0-9_]*)=").expect("field regex must compile")
    })
}

fn guid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .expect("guid regex must compile")
    })
}

/// Every `Key=Value` pair in a message, in source order.
///
/// A value runs from its `=` to the start of the next field, so a display name
/// containing spaces survives whole. Truncating one at the first space would
/// silently change which app a reader thinks a transaction is about.
pub fn fields(message: &str) -> Vec<IntuneNamedValue> {
    let starts = field_start_re()
        .captures_iter(message)
        .collect::<Vec<_>>();

    starts
        .iter()
        .enumerate()
        .filter_map(|(index, caps)| {
            let whole = caps.get(0)?;
            let key = caps.name("key")?;
            let value_end = starts
                .get(index + 1)
                .and_then(|next| next.get(0))
                .map_or(message.len(), |next| next.start());

            Some(IntuneNamedValue {
                name: key.as_str().to_owned(),
                value: message[whole.end()..value_end].trim().to_owned(),
            })
        })
        .collect()
}

/// The value of one field, matched case-insensitively.
pub fn field<'a>(fields: &'a [IntuneNamedValue], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|pair| pair.name.eq_ignore_ascii_case(name))
        .map(|pair| pair.value.as_str())
        .filter(|value| !value.is_empty())
}

/// A field whose value must be a GUID to be usable as a transaction key.
///
/// An identifier that is not a GUID is not rejected outright elsewhere, but it
/// may not *key* a transaction: correlating on an arbitrary token is how two
/// unrelated runs get merged.
pub fn guid_field<'a>(fields: &'a [IntuneNamedValue], name: &str) -> Option<&'a str> {
    field(fields, name).filter(|value| guid_re().is_match(value))
}

/// Whether a value has the shape of a GUID.
pub fn is_guid(value: &str) -> bool {
    guid_re().is_match(value)
}

/// Parse a numeric result token into every form it may be quoted in.
///
/// macOS agent logs mix signed decimals (`-1009`), unsigned decimals, and hex
/// (`0xFFFFFC17`). All three are retained because the raw token is often the
/// only string an administrator can search for.
pub fn error_code(raw: &str) -> IntuneErrorCode {
    let trimmed = raw.trim();
    let decimal = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
            .ok()
            .map(|value| i64::from(value as i32))
    } else {
        trimmed.parse::<i64>().ok()
    };

    IntuneErrorCode {
        raw: trimmed.to_owned(),
        decimal,
        // Render through the 32-bit two's-complement form so `-1009` and
        // `0xFFFFFC0F` are visibly the same code.
        hex: decimal
            .and_then(|value| i32::try_from(value).ok())
            .map(|value| format!("0x{:08X}", value as u32)),
    }
}

/// An exit or error field parsed into a code, when the message states one.
pub fn error_code_field(fields: &[IntuneNamedValue], name: &str) -> Option<IntuneErrorCode> {
    field(fields, name).map(error_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_display_name_containing_spaces_survives_extraction() {
        let parsed = fields("Received app policy AppId=1 Name=Contoso Reader Pro Type=pkg");
        assert_eq!(field(&parsed, "Name"), Some("Contoso Reader Pro"));
        assert_eq!(field(&parsed, "Type"), Some("pkg"));
    }

    #[test]
    fn field_lookup_is_case_insensitive() {
        let parsed = fields("AppId=abc");
        assert_eq!(field(&parsed, "appid"), Some("abc"));
    }

    #[test]
    fn a_non_guid_identifier_cannot_key_a_transaction() {
        let parsed = fields("AppId=not-a-guid PolicyId=11111111-1111-4111-8111-111111111111");
        assert_eq!(guid_field(&parsed, "AppId"), None);
        assert_eq!(
            guid_field(&parsed, "PolicyId"),
            Some("11111111-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn a_negative_decimal_and_its_hex_form_resolve_to_the_same_code() {
        let decimal = error_code("-1009");
        assert_eq!(decimal.decimal, Some(-1009));
        assert_eq!(decimal.hex.as_deref(), Some("0xFFFFFC0F"));

        let hex = error_code("0xFFFFFC0F");
        assert_eq!(hex.decimal, Some(-1009));
        assert_eq!(hex.raw, "0xFFFFFC0F");
    }

    #[test]
    fn an_unparseable_code_still_retains_its_raw_token() {
        let code = error_code("kCFErrorDomainCFNetwork");
        assert_eq!(code.decimal, None);
        assert_eq!(code.hex, None);
        assert_eq!(code.raw, "kCFErrorDomainCFNetwork");
    }

    #[test]
    fn a_url_query_string_is_not_mistaken_for_a_second_field() {
        let parsed = fields("Downloading Url=https://host.example/a.pkg?sig=abc Bytes=10");
        assert_eq!(
            field(&parsed, "Url"),
            Some("https://host.example/a.pkg?sig=abc")
        );
        assert_eq!(field(&parsed, "Bytes"), Some("10"));
        assert_eq!(field(&parsed, "sig"), None);
    }

    #[test]
    fn an_empty_field_value_reads_as_absent() {
        let parsed = fields("AppId= Name=Thing");
        assert_eq!(field(&parsed, "AppId"), None);
    }
}
