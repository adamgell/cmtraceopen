//! ASCII-strict parsing of decimal digit runs captured by a regex.
//!
//! The `regex` crate's `\d` is Unicode-aware: it matches the whole `\p{Nd}`
//! category, so a `\d+` capture can hold multi-byte digits such as Arabic-Indic
//! `٠١٢` (U+0660..U+0669, two bytes each) or Devanagari `०१२` (U+0966..U+096F,
//! three bytes each). Code that then pads such a capture to a *character* width
//! and indexes it by *byte* offset panics on a character boundary.
//!
//! That is a denial of service for consumers of this crate. It aborts the parse
//! of a whole file that the user merely opened, and for `reporting_events` it
//! fires during format *detection*, before the file is routed to any parser.
//!
//! These helpers reject non-ASCII bytes up front and do the arithmetic
//! themselves, so no caller can reach a byte-indexed slice while holding a
//! multi-byte digit. Rejecting is the right answer rather than transliterating:
//! the sibling hour/minute/second fields at every call site already reject a
//! non-ASCII digit by failing their `parse()`, and the log formats this crate
//! reads are specified in ASCII.

/// Parse `value` as a `u32`, accepting only ASCII digits.
///
/// Returns `None` for an empty string, for any byte that is not `0`-`9`, and on
/// overflow. Note this is deliberately stricter than [`str::parse`], which also
/// accepts a leading `+`.
pub(crate) fn parse_ascii_u32(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let mut parsed = 0u32;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }

        parsed = parsed
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
    }

    Some(parsed)
}

/// Read `value` as the digits of a fractional second and return whole
/// milliseconds, right-padding a shorter run and truncating past three digits.
///
/// `"12"` is 120ms because a fraction is positional: `.12` of a second is
/// twelve hundredths. Use this for formats whose field is a true fraction.
/// Returns `None` if any byte is not an ASCII digit.
pub(crate) fn fraction_to_millis(value: &str) -> Option<u32> {
    let mut millis = 0u32;
    let mut digits = 0u8;

    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }

        if digits < 3 {
            millis = (millis * 10) + u32::from(byte - b'0');
            digits += 1;
        }
    }

    while digits < 3 {
        millis *= 10;
        digits += 1;
    }

    Some(millis)
}

/// Read `value` as a subsecond field that is *already expressed* in
/// milliseconds, truncating past three digits.
///
/// Unlike [`fraction_to_millis`] a shorter run is not padded: `"12"` is 12ms,
/// because these formats write a millisecond count rather than a fraction.
/// Returns `None` for an empty string or any byte that is not an ASCII digit.
pub(crate) fn truncate_subsecond_to_millis(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let mut millis = 0u32;
    let mut digits = 0u8;

    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }

        if digits < 3 {
            millis = (millis * 10) + u32::from(byte - b'0');
            digits += 1;
        }
    }

    Some(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ascii_u32_reads_ascii_runs() {
        assert_eq!(parse_ascii_u32("0"), Some(0));
        assert_eq!(parse_ascii_u32("0530"), Some(530));
        assert_eq!(parse_ascii_u32("4294967295"), Some(u32::MAX));
    }

    #[test]
    fn parse_ascii_u32_rejects_non_ascii_empty_and_overflow() {
        assert_eq!(parse_ascii_u32(""), None);
        assert_eq!(parse_ascii_u32("\u{0661}\u{0662}"), None);
        assert_eq!(parse_ascii_u32("1\u{0662}"), None);
        assert_eq!(parse_ascii_u32("+5"), None);
        assert_eq!(parse_ascii_u32("4294967296"), None);
    }

    #[test]
    fn fraction_to_millis_pads_and_truncates() {
        assert_eq!(fraction_to_millis(""), Some(0));
        assert_eq!(fraction_to_millis("1"), Some(100));
        assert_eq!(fraction_to_millis("12"), Some(120));
        assert_eq!(fraction_to_millis("123"), Some(123));
        assert_eq!(fraction_to_millis("1234567"), Some(123));
    }

    #[test]
    fn fraction_to_millis_rejects_non_ascii_at_any_position() {
        assert_eq!(fraction_to_millis("\u{0661}\u{0662}"), None);
        // Past the third digit the value no longer affects the result, but the
        // field is still malformed and must not be reported as valid.
        assert_eq!(fraction_to_millis("123\u{0661}"), None);
        assert_eq!(fraction_to_millis("12\u{0661}\u{0662}"), None);
    }

    #[test]
    fn truncate_subsecond_to_millis_truncates_without_padding() {
        assert_eq!(truncate_subsecond_to_millis("1"), Some(1));
        assert_eq!(truncate_subsecond_to_millis("12"), Some(12));
        assert_eq!(truncate_subsecond_to_millis("123"), Some(123));
        assert_eq!(truncate_subsecond_to_millis("1234567"), Some(123));
    }

    #[test]
    fn truncate_subsecond_to_millis_rejects_non_ascii_and_empty() {
        assert_eq!(truncate_subsecond_to_millis(""), None);
        assert_eq!(truncate_subsecond_to_millis("\u{0661}\u{0662}"), None);
        assert_eq!(truncate_subsecond_to_millis("1\u{0662}3"), None);
        assert_eq!(truncate_subsecond_to_millis("123\u{0661}"), None);
    }
}
