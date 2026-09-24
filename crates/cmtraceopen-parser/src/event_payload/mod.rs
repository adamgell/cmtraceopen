//! Decoding the `EventPayload` element found in `.etl` traces.
//!
//! Some providers, notably the Windows Update trace under `C:\Windows\Logs\WindowsUpdate`, do not
//! write structured `EventData`. They write a single `EventPayload` element holding the message as
//! a hexadecimal string. Rendered as-is it is a wall of hex digits, which is why those traces are
//! usually described as unreadable without a dedicated tool.
//!
//! FullEventLogView added this conversion in 1.55 and it is the reason those logs are readable
//! there at all. This is the same idea, implemented as a pure function.
//!
//! Encoding is decided by inspection rather than assumption. Windows writes these payloads as
//! UTF-16LE, but not universally, and guessing wrong turns readable text into interleaved nulls or
//! mojibake. Both interpretations are scored and the better one wins, with a refusal when neither
//! is convincing, in which case the caller shows the hex unchanged.

use crate::eventmap::EventNode;

/// How the payload bytes were interpreted.
// Growable: UTF-16BE and single-byte code pages are both plausible additions. Marking it now keeps
// adding one a minor change; after the first release that exposes the type it is itself breaking.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncoding {
    /// UTF-16 little endian, which is what Windows writes most often.
    Utf16Le,
    /// Single-byte text, either ASCII or UTF-8.
    Utf8,
}

/// A decoded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    /// The decoded message, with any trailing NUL padding already removed.
    ///
    /// Never empty: a payload that decodes to nothing is refused rather than returned, since empty
    /// text would read as an event that said nothing rather than one that was not understood.
    pub text: String,
    /// Which reading of the bytes produced [`text`](Self::text).
    ///
    /// Reported rather than hidden because it is a decision made by inspection, and an operator
    /// looking at a suspicious message needs to know the encoding was inferred.
    pub encoding: PayloadEncoding,
}

/// Parses a hexadecimal string into bytes.
///
/// Whitespace is ignored, since providers sometimes wrap long payloads. An odd digit count or a
/// non-hex character means this is not a hex payload at all, which is a refusal rather than a best
/// effort: decoding half a string would present truncated evidence as complete.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }

    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Some(bytes)
}

/// Fraction of characters that are ASCII printable or ordinary whitespace.
///
/// Deliberately stricter than "not a control character". Misreading arbitrary bytes as UTF-16
/// produces letter-like characters from the Latin Extended and CJK ranges, which are not control
/// characters and would sail through a looser check. Requiring ASCII rejects that, because the
/// signature of a wrong interpretation is text that is suddenly not ASCII at all.
///
/// The cost is that a payload written in a non-Latin script falls back to raw hex rather than
/// being decoded. That is the conservative direction: raw hex is visibly unreadable, whereas
/// mojibake looks like data and misleads. Windows writes these traces in English.
fn readable_ratio(text: &str) -> f32 {
    let total = text.chars().count();
    if total == 0 {
        return 0.0;
    }
    let readable = text
        .chars()
        .filter(|c| matches!(c, ' '..='~' | '\n' | '\r' | '\t'))
        .count();
    readable as f32 / total as f32
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Text is accepted only when this much of it is readable.
///
/// Set high because the alternative to accepting is showing the raw hex, which is at least
/// obviously unreadable. Mojibake looks like data and misleads.
const MINIMUM_READABLE_RATIO: f32 = 0.9;

/// Decodes an `EventPayload` hex string into readable text.
///
/// Returns `None` when the input is not hexadecimal, or when neither interpretation produces
/// convincingly readable text. The caller should then show the payload unchanged.
pub fn decode_event_payload(hex: &str) -> Option<DecodedPayload> {
    let bytes = hex_to_bytes(hex.trim())?;

    let mut best: Option<(String, f32, PayloadEncoding)> = None;

    if let Some(text) = decode_utf16le(&bytes) {
        let trimmed = text.trim_end_matches('\0').to_string();
        let ratio = readable_ratio(&trimmed);
        best = Some((trimmed, ratio, PayloadEncoding::Utf16Le));
    }

    if let Ok(text) = String::from_utf8(bytes) {
        let trimmed = text.trim_end_matches('\0').to_string();
        let ratio = readable_ratio(&trimmed);
        // Strictly greater, so ties go to UTF-16: Windows writes these payloads that way far more
        // often, and a short ASCII payload decodes plausibly under both readings.
        let better = match &best {
            Some((_, best_ratio, _)) => ratio > *best_ratio,
            None => true,
        };
        if better {
            best = Some((trimmed, ratio, PayloadEncoding::Utf8));
        }
    }

    let (text, ratio, encoding) = best?;
    if text.is_empty() || ratio < MINIMUM_READABLE_RATIO {
        return None;
    }

    Some(DecodedPayload { text, encoding })
}

/// The element name providers use for a hex-encoded message body.
const PAYLOAD_ELEMENT: &str = "EventPayload";

/// Finds and decodes the `EventPayload` element anywhere in a parsed event.
///
/// The element's position varies: some providers put it under `UserData`, others under
/// `EventData`, and the wrapper element carries the provider's own name. Searching the whole tree
/// avoids hard-coding a path that would silently match nothing for half of them.
///
/// The first decodable payload wins. Events carrying more than one are not something Windows
/// emits, and picking the first is at least deterministic.
pub fn decode_payload_in(root: &EventNode) -> Option<DecodedPayload> {
    if root.name == PAYLOAD_ELEMENT {
        if let Some(decoded) = root.text.as_deref().and_then(decode_event_payload) {
            return Some(decoded);
        }
    }
    root.children.iter().find_map(decode_payload_in)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_hex(text: &str) -> String {
        text.encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn utf8_hex(text: &str) -> String {
        text.bytes().map(|byte| format!("{byte:02X}")).collect()
    }

    #[test]
    fn decodes_a_utf16le_payload() {
        let decoded =
            decode_event_payload(&utf16_hex("Agent  * START *  Finding updates")).expect("decodes");
        assert_eq!(decoded.text, "Agent  * START *  Finding updates");
        assert_eq!(decoded.encoding, PayloadEncoding::Utf16Le);
    }

    #[test]
    fn decodes_a_single_byte_payload() {
        // Long enough that the UTF-16 reading is clearly worse, which is what decides it.
        let text = "Downloading update 8f21b4c2 from the delivery service";
        let decoded = decode_event_payload(&utf8_hex(text)).expect("decodes");
        assert_eq!(decoded.text, text);
        assert_eq!(decoded.encoding, PayloadEncoding::Utf8);
    }

    #[test]
    fn tolerates_whitespace_between_digits() {
        assert_eq!(
            decode_event_payload("48 00 69 00").expect("decodes").text,
            "Hi"
        );
    }

    #[test]
    fn accepts_lowercase_hex() {
        assert_eq!(
            decode_event_payload(&utf16_hex("Hi").to_lowercase())
                .expect("decodes")
                .text,
            "Hi"
        );
    }

    #[test]
    fn strips_a_trailing_null_terminator() {
        assert_eq!(
            decode_event_payload(&utf16_hex("Done\0"))
                .expect("decodes")
                .text,
            "Done"
        );
    }

    #[test]
    fn preserves_embedded_newlines() {
        assert_eq!(
            decode_event_payload(&utf16_hex("line one\r\nline two"))
                .expect("decodes")
                .text,
            "line one\r\nline two"
        );
    }

    #[test]
    fn refuses_an_odd_number_of_digits() {
        // Decoding half of it would present truncated evidence as complete.
        assert!(decode_event_payload("48656C6C6").is_none());
    }

    #[test]
    fn refuses_input_that_is_not_hexadecimal() {
        assert!(decode_event_payload("not hex at all").is_none());
        assert!(decode_event_payload("ZZ00").is_none());
        assert!(decode_event_payload("").is_none());
    }

    #[test]
    fn refuses_binary_that_is_not_text() {
        // Both readings "succeed" here and neither is text: as UTF-8 these are control bytes, and
        // as UTF-16 they become Latin Extended letters that look like language but are not. Showing
        // either as a message would be a confident wrong answer; raw hex is at least honest.
        let binary: String = (0u8..64).map(|byte| format!("{byte:02X}")).collect();
        assert!(decode_event_payload(&binary).is_none());
    }

    #[test]
    fn refuses_a_payload_that_decodes_to_nothing() {
        assert!(decode_event_payload("0000").is_none());
    }

    #[test]
    fn a_short_ascii_payload_is_read_as_utf16_when_both_are_plausible() {
        let decoded = decode_event_payload(&utf16_hex("OK")).expect("decodes");
        assert_eq!(decoded.text, "OK");
        assert_eq!(decoded.encoding, PayloadEncoding::Utf16Le);
    }

    #[test]
    fn finds_a_payload_nested_under_a_provider_wrapper() {
        // The wrapper element carries the provider's own name, so the path cannot be hard-coded.
        let root = EventNode::new("Event").with_child(
            EventNode::new("UserData")
                .with_child(EventNode::new("WindowsUpdateClient").with_child(
                    EventNode::new("EventPayload").with_text(utf16_hex("Agent ready")),
                )),
        );
        assert_eq!(decode_payload_in(&root).expect("found").text, "Agent ready");
    }

    #[test]
    fn an_event_without_a_payload_yields_nothing() {
        let root = EventNode::new("Event").with_child(
            EventNode::new("EventData")
                .with_child(EventNode::new("Data").with_text(utf16_hex("not a payload"))),
        );
        assert!(decode_payload_in(&root).is_none());
    }

    #[test]
    fn an_undecodable_payload_does_not_hide_a_later_decodable_one() {
        // Refusing the first must not end the search, or one malformed element would suppress the
        // readable message that follows it.
        let root = EventNode::new("Event")
            .with_child(EventNode::new("EventPayload").with_text("ZZZZ"))
            .with_child(EventNode::new("EventPayload").with_text(utf16_hex("readable")));
        assert_eq!(decode_payload_in(&root).expect("found").text, "readable");
    }

    #[test]
    fn round_trips_a_realistic_windows_update_line() {
        let line = "2026-08-09 12:00:00.1234567 1234 5678 Agent  Update service is being installed";
        assert_eq!(
            decode_event_payload(&utf16_hex(line))
                .expect("decodes")
                .text,
            line
        );
    }
}
