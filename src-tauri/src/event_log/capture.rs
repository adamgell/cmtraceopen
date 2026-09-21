//! Provider metadata capture.
//!
//! The Windows implementation deliberately keeps all `wevtapi` handles and unsafe pointer
//! handling in this module. The resulting [`ProviderMetadata`] is a parser-side value and remains
//! portable.

use std::path::Path;
#[cfg(target_os = "windows")]
use std::sync::{LazyLock, Mutex};

// The provider destination is replaced as one logical snapshot. Serializing captures prevents
// concurrent command invocations from interleaving DELETE/INSERT transactions into one file.
#[cfg(target_os = "windows")]
static CAPTURE_WRITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

use super::models::ProviderCaptureFailure;
#[cfg(any(target_os = "windows", test))]
fn is_unavailable_message_error(code: u32) -> bool {
    matches!(code, 15007 | 15027 | 15028 | 15029 | 15030 | 15033)
}
#[cfg(any(target_os = "windows", test))]
fn is_unavailable_provider_error(code: u32) -> bool {
    matches!(code, 2 | 1813 | 15007 | 15023 | 15105)
}

#[cfg(any(target_os = "windows", test))]
fn is_unavailable_publisher_metadata_error(code: u32) -> bool {
    code == 13 || is_unavailable_provider_error(code)
}

#[cfg(any(target_os = "windows", test))]
/// Maximum retained failure records, including the single overflow sentinel.
const MAX_PROVIDER_CAPTURE_FAILURES: usize = 256;
#[cfg(any(target_os = "windows", test))]
const MAX_PROVIDER_FAILURE_NAME_CHARS: usize = 256;
#[cfg(any(target_os = "windows", test))]
const MAX_PROVIDER_FAILURE_ERROR_CHARS: usize = 512;
#[cfg(any(target_os = "windows", test))]
const FAILURE_TRUNCATION_PROVIDER: &str = "<provider capture>";
#[cfg(any(target_os = "windows", test))]
const FAILURE_TRUNCATION_ERROR: &str = "additional provider capture failures were truncated";

#[cfg(any(target_os = "windows", test))]
fn sanitize_provider_failure_field(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn safe_provider_failure(provider_name: &str, error: &str) -> ProviderCaptureFailure {
    ProviderCaptureFailure {
        provider_name: sanitize_provider_failure_field(
            provider_name,
            MAX_PROVIDER_FAILURE_NAME_CHARS,
        ),
        error: sanitize_provider_failure_field(error, MAX_PROVIDER_FAILURE_ERROR_CHARS),
    }
}

#[cfg(any(target_os = "windows", test))]
fn record_provider_failure(
    failures: &mut Vec<ProviderCaptureFailure>,
    provider_name: &str,
    error: String,
    unavailable: bool,
) {
    if failures.len() >= MAX_PROVIDER_CAPTURE_FAILURES {
        return;
    }
    if failures.len() == MAX_PROVIDER_CAPTURE_FAILURES - 1 {
        let failure = safe_provider_failure(FAILURE_TRUNCATION_PROVIDER, FAILURE_TRUNCATION_ERROR);
        log::warn!(
            "event=provider_capture_failures_truncated provider={:?} error={:?}",
            failure.provider_name,
            failure.error
        );
        failures.push(failure);
        return;
    }

    let failure = safe_provider_failure(provider_name, &error);
    if unavailable {
        log::warn!(
            "event=provider_capture_unavailable provider={:?} error={:?}",
            failure.provider_name,
            failure.error
        );
    }
    failures.push(failure);
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, PartialEq, Eq)]
enum PublisherEnumerationStep {
    Publisher(String),
    Exhausted,
    Failed,
}

#[cfg(any(target_os = "windows", test))]
fn publisher_enumeration_step(
    identifier: Option<String>,
    failures: &mut Vec<ProviderCaptureFailure>,
) -> PublisherEnumerationStep {
    match identifier {
        None => PublisherEnumerationStep::Exhausted,
        Some(identifier) if identifier.is_empty() => {
            record_provider_failure(
                failures,
                "<publisher enumeration>",
                "publisher enumeration returned an empty identifier".to_string(),
                false,
            );
            PublisherEnumerationStep::Failed
        }
        Some(identifier) => PublisherEnumerationStep::Publisher(identifier),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureErrorKind {
    Unsupported,
    Traversal,
    ProviderFailures,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureError {
    pub kind: CaptureErrorKind,
    pub message: String,
    pub failures: Vec<ProviderCaptureFailure>,
}

impl CaptureError {
    #[cfg(not(target_os = "windows"))]
    fn unsupported() -> Self {
        Self {
            kind: CaptureErrorKind::Unsupported,
            message: "Provider capture is only available on Windows".to_string(),
            failures: Vec::new(),
        }
    }

    #[cfg(any(target_os = "windows", test))]
    fn traversal(message: impl Into<String>) -> Self {
        Self {
            kind: CaptureErrorKind::Traversal,
            message: message.into(),
            failures: Vec::new(),
        }
    }

    #[cfg(any(target_os = "windows", test))]
    fn provider_failures(failures: Vec<ProviderCaptureFailure>) -> Self {
        Self {
            kind: CaptureErrorKind::ProviderFailures,
            message: "one or more providers could not be captured".to_string(),
            failures,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
/// Gate publication so a captured prefix can never replace the last complete database.
fn finalize_provider_capture(
    captured_count: usize,
    mut failures: Vec<ProviderCaptureFailure>,
    hit_safety_bound: bool,
    publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), CaptureError> {
    if hit_safety_bound {
        record_provider_failure(
            &mut failures,
            "<publisher enumeration>",
            "publisher enumeration exceeded bound".to_string(),
            false,
        );
    }
    if !failures.is_empty() {
        return Err(CaptureError::provider_failures(failures));
    }
    if captured_count == 0 {
        return Err(CaptureError::traversal(
            "publisher enumeration returned no providers",
        ));
    }
    publish().map_err(CaptureError::traversal)
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CaptureError {}

#[cfg(not(target_os = "windows"))]
pub fn capture_providers_to_db(_db_path: &Path) -> Result<(), CaptureError> {
    Err(CaptureError::unsupported())
}

#[cfg(any(target_os = "windows", test))]
fn category_message_text(
    message_id: Option<u32>,
    formatted: Option<String>,
    inline_name: String,
) -> Option<String> {
    message_id.map(|_| formatted).unwrap_or(Some(inline_name))
}
#[cfg(any(target_os = "windows", test))]
fn event_message_text(message_id: Option<u32>, formatted: Option<String>) -> Option<String> {
    message_id.and(formatted)
}
#[cfg(any(target_os = "windows", test))]
fn trim_provider_text(value: String) -> String {
    value
        .trim_end_matches(['\0', '\r', '\n', '\t', ' '])
        .to_string()
}

#[cfg(target_os = "windows")]
mod windows_capture {
    use super::*;
    use cmtraceopen_parser::provider::{ProviderEvent, ProviderMessage, ProviderMetadata};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND,
        ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS,
    };
    use windows::Win32::System::EventLog::*;

    use winreg::enums::HKEY_LOCAL_MACHINE;
    const MAX_PUBLISHERS: usize = 100_000;
    const MAX_EVENTS_PER_PROVIDER: usize = 100_000;
    const MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
    const MAX_CAPTURED_METADATA_ITEMS: usize = 4_000_000;
    const MAX_OBJECT_ARRAY_ITEMS: usize = 100_000;
    const BUFFER_RETRY: usize = 256;
    const PUBLISHER_NAME_RETRY_LIMIT: usize = 256;
    const LOCALE_NEUTRAL: u32 = 0;

    struct EvtHandle(EVT_HANDLE);

    impl Drop for EvtHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        (error.code().0 as u32) & 0xFFFF
    }
    #[derive(Debug)]
    struct ProviderCaptureError {
        code: Option<u32>,
        message: String,
    }

    impl ProviderCaptureError {
        fn message(message: impl Into<String>) -> Self {
            Self {
                code: None,
                message: message.into(),
            }
        }

        fn win32(code: u32, message: impl Into<String>) -> Self {
            Self {
                code: Some(code),
                message: message.into(),
            }
        }
    }

    impl std::fmt::Display for ProviderCaptureError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl From<String> for ProviderCaptureError {
        fn from(message: String) -> Self {
            Self::message(message)
        }
    }

    impl From<&str> for ProviderCaptureError {
        fn from(message: &str) -> Self {
            Self::message(message)
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    enum OwnedVariant {
        Null,
        String(String),
        Number(u64),
        Handle(EVT_HANDLE),
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ChannelReference {
        path: String,
        message_id: Option<u32>,
    }
    fn number(value: OwnedVariant) -> Option<u64> {
        match value {
            OwnedVariant::Number(value) => Some(value),
            _ => None,
        }
    }
    fn string(value: OwnedVariant) -> Option<String> {
        match value {
            OwnedVariant::String(value) => Some(value),
            _ => None,
        }
    }
    fn optional_number(value: OwnedVariant) -> Result<Option<u64>, String> {
        match value {
            OwnedVariant::Null => Ok(None),
            OwnedVariant::Number(value) => Ok(Some(value)),
            _ => Err("metadata value has an invalid type".to_string()),
        }
    }
    fn optional_message_id(value: OwnedVariant) -> Result<Option<u32>, String> {
        let Some(value) = optional_number(value)? else {
            return Ok(None);
        };
        let value = u32::try_from(value)
            .map_err(|_| format!("message id {value} exceeds the UInt32 range"))?;
        Ok((value != u32::MAX).then_some(value))
    }
    fn short_message_id(raw_id: u32) -> u32 {
        u32::from((raw_id & 0xFFFF) as u16)
    }
    fn opcode_metadata_key(raw_value: u64) -> u64 {
        (raw_value >> 16) & 0xFFFF
    }
    fn metadata_key_value(target: u8, raw_value: u64) -> u64 {
        match target {
            0 => raw_value & 0xFFFF,
            1 => opcode_metadata_key(raw_value),
            _ => raw_value,
        }
    }
    fn optional_string(value: OwnedVariant) -> Result<Option<String>, String> {
        match value {
            OwnedVariant::Null => Ok(None),
            OwnedVariant::String(value) => Ok(Some(value)),
            _ => Err("metadata string has an invalid type".to_string()),
        }
    }
    fn optional_template(value: OwnedVariant) -> Result<Option<String>, String> {
        Ok(optional_string(value)?.filter(|value| !value.is_empty()))
    }
    fn base32(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut output = String::new();
        let mut buffer = 0u64;
        let mut bits = 0u8;
        for &byte in bytes {
            buffer = (buffer << 8) | u64::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
            if bits != 0 {
                buffer &= (1u64 << bits) - 1;
            } else {
                buffer = 0;
            }
        }
        if bits != 0 {
            output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        output
    }
    fn write_byte(output: &mut Vec<u8>, value: u8) {
        output.push(value);
    }
    fn write_i32(output: &mut Vec<u8>, value: i32) {
        output.extend_from_slice(&value.to_le_bytes());
    }
    fn write_i64(output: &mut Vec<u8>, value: i64) {
        output.extend_from_slice(&value.to_le_bytes());
    }
    fn write_levels_map(output: &mut Vec<u8>, map: &BTreeMap<String, String>) {
        if map.is_empty() {
            write_i32(output, 0);
            return;
        }
        write_i32(output, 1);
        write_string(output, Some("levels"));
        write_byte(output, 0);
        let mut entries: Vec<(u32, &str)> = map
            .iter()
            .filter_map(|(key, value)| key.parse().ok().map(|key| (key, value.as_str())))
            .collect();
        entries.sort_by_key(|(key, _)| *key);
        write_i32(output, i32::try_from(entries.len()).unwrap_or(i32::MAX));
        for (key, value) in entries {
            output.extend_from_slice(&key.to_le_bytes());
            write_string(output, Some(value));
        }
    }
    fn write_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }
    fn write_string(output: &mut Vec<u8>, value: Option<&str>) {
        let Some(value) = value else {
            write_i32(output, -1);
            return;
        };
        let byte_count = value.encode_utf16().count().saturating_mul(2);
        write_i32(output, i32::try_from(byte_count).unwrap_or(i32::MAX));
        for unit in value.encode_utf16() {
            write_u16(output, unit);
        }
    }
    fn write_sorted_blobs(output: &mut Vec<u8>, mut blobs: Vec<Vec<u8>>) {
        blobs.sort();
        blobs.dedup();
        write_i32(output, i32::try_from(blobs.len()).unwrap_or(i32::MAX));
        for blob in blobs {
            output.extend(blob);
        }
    }
    enum TemplateNode {
        Raw(String),
        Parsed([String; 5]),
    }
    fn template_nodes(template: Option<&str>) -> Vec<TemplateNode> {
        let Some(template) = template else {
            return Vec::new();
        };
        let folded = template.to_ascii_lowercase();
        let mut nodes = Vec::new();
        let mut search = 0;
        while search < template.len() {
            let Some(relative) = folded[search..].find("<data") else {
                break;
            };
            let start = search + relative;
            let after_tag = start + 5;
            if after_tag < template.len() {
                let next = template[after_tag..].chars().next().unwrap_or_default();
                if !matches!(next, ' ' | '\t' | '\r' | '\n' | '/' | '>') {
                    search = after_tag;
                    continue;
                }
            }
            let from_data = &template[start..];
            let Some(close) = from_data
                .char_indices()
                .skip(5)
                .find_map(|(index, ch)| (ch == '>').then_some(index))
            else {
                nodes.push(TemplateNode::Raw(from_data.to_string()));
                break;
            };
            let element_end = if from_data[..close].ends_with('/') {
                close - 1
            } else {
                close
            };
            let element = &from_data[..element_end];
            let chars: Vec<char> = element.chars().collect();
            let mut pos = 5;
            let mut values = [
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ];
            let mut raw = false;
            while pos < chars.len() {
                while pos < chars.len() && matches!(chars[pos], ' ' | '\t' | '\r' | '\n' | '/') {
                    pos += 1;
                }
                if pos >= chars.len() {
                    break;
                }
                let name_start = pos;
                while pos < chars.len()
                    && !matches!(chars[pos], '=' | ' ' | '\t' | '\r' | '\n' | '/')
                {
                    pos += 1;
                }
                let name: String = chars[name_start..pos].iter().collect();
                let slot = match name.to_ascii_lowercase().as_str() {
                    "name" => Some(0),
                    "intype" => Some(1),
                    "outtype" => Some(2),
                    "length" => Some(3),
                    "map" => Some(4),
                    _ => None,
                };
                while pos < chars.len() && matches!(chars[pos], ' ' | '\t' | '\r' | '\n') {
                    pos += 1;
                }
                if pos >= chars.len() || chars[pos] != '=' {
                    raw |= slot.is_some();
                    continue;
                }
                pos += 1;
                while pos < chars.len() && matches!(chars[pos], ' ' | '\t' | '\r' | '\n') {
                    pos += 1;
                }
                if pos >= chars.len() || chars[pos] != '"' {
                    raw |= slot.is_some();
                    while pos < chars.len() && !matches!(chars[pos], ' ' | '\t' | '\r' | '\n') {
                        pos += 1;
                    }
                    continue;
                }
                pos += 1;
                let value_start = pos;
                while pos < chars.len() && chars[pos] != '"' {
                    pos += 1;
                }
                if pos >= chars.len() {
                    raw |= slot.is_some();
                    break;
                }
                if let Some(slot) = slot {
                    values[slot] = chars[value_start..pos].iter().collect();
                }
                pos += 1;
            }
            if raw || values.iter().all(String::is_empty) {
                nodes.push(TemplateNode::Raw(element.to_string()));
            } else {
                nodes.push(TemplateNode::Parsed(values));
            }
            search = start + close + 1;
        }
        nodes
    }
    fn write_template_signature(output: &mut Vec<u8>, template: Option<&str>) {
        let nodes = template_nodes(template);
        write_i32(output, i32::try_from(nodes.len()).unwrap_or(i32::MAX));
        for node in nodes {
            match node {
                TemplateNode::Raw(raw) => {
                    write_byte(output, 1);
                    write_string(output, Some(&raw));
                }
                TemplateNode::Parsed(values) => {
                    write_byte(output, 0);
                    for value in values {
                        write_string(output, Some(&value));
                    }
                }
            }
        }
    }
    fn encode_event(event: &ProviderEvent) -> Vec<u8> {
        let mut output = Vec::new();
        write_i64(&mut output, i64::from(event.id));
        write_byte(&mut output, event.version as u8);
        write_i32(&mut output, event.level.unwrap_or_default() as i32);
        write_i32(&mut output, event.opcode.unwrap_or_default() as i32);
        write_i32(&mut output, event.task.unwrap_or_default() as i32);
        let mut keywords = event.keywords.clone();
        keywords.sort_unstable();
        keywords.dedup();
        write_i32(
            &mut output,
            i32::try_from(keywords.len()).unwrap_or(i32::MAX),
        );
        for keyword in keywords {
            write_i64(&mut output, keyword as i64);
        }
        write_template_signature(&mut output, event.template.as_deref());
        write_string(&mut output, event.description.as_deref());
        write_string(&mut output, event.log_name.as_deref());
        output
    }
    fn encode_message(message: &ProviderMessage) -> Vec<u8> {
        let mut output = Vec::new();
        write_u16(&mut output, message.short_id as u16);
        write_i64(&mut output, message.raw_id as i64);
        write_string(&mut output, message.log_link.as_deref());
        write_string(&mut output, message.tag.as_deref());
        write_string(&mut output, message.template.as_deref());
        write_string(&mut output, message.text.as_deref());
        output
    }
    fn write_i64_dictionary(output: &mut Vec<u8>, map: &BTreeMap<String, String>) {
        let mut entries: Vec<(i64, &str)> = map
            .iter()
            .filter_map(|(key, value)| {
                key.parse::<i64>()
                    .ok()
                    .or_else(|| key.parse::<u64>().ok().map(|value| value as i64))
                    .map(|key| (key, value.as_str()))
            })
            .collect();
        entries.sort_by_key(|(key, _)| *key);
        write_i32(output, i32::try_from(entries.len()).unwrap_or(i32::MAX));
        for (key, value) in entries {
            write_i64(output, key);
            write_string(output, Some(value));
        }
    }
    fn write_i32_dictionary(output: &mut Vec<u8>, map: &BTreeMap<String, String>) {
        let mut entries: Vec<(i32, &str)> = map
            .iter()
            .filter_map(|(key, value)| {
                key.parse::<u32>()
                    .map(|key| key as i32)
                    .or_else(|_| key.parse::<i32>())
                    .ok()
                    .map(|key| (key, value.as_str()))
            })
            .collect();
        entries.sort_by_key(|(key, _)| *key);
        write_i32(output, i32::try_from(entries.len()).unwrap_or(i32::MAX));
        for (key, value) in entries {
            write_i32(output, key);
            write_string(output, Some(value));
        }
    }
    fn canonical_version_key(metadata: &ProviderMetadata) -> String {
        let mut encoded = Vec::new();
        write_byte(&mut encoded, 1);
        // ProviderName and source provenance identify the database row, not rendered content.
        // The current parser model has no owning-publisher field, so it is the canonical null.
        write_string(&mut encoded, None);
        write_sorted_blobs(
            &mut encoded,
            metadata.events.iter().map(encode_event).collect(),
        );
        write_sorted_blobs(
            &mut encoded,
            metadata.messages.iter().map(encode_message).collect(),
        );
        // Parameters are not represented by ProviderMetadata yet.
        write_i32(&mut encoded, 0);
        write_i64_dictionary(&mut encoded, &metadata.keywords);
        write_i32_dictionary(&mut encoded, &metadata.opcodes);
        write_i32_dictionary(&mut encoded, &metadata.tasks);
        write_levels_map(&mut encoded, &metadata.levels);
        let digest = Sha256::digest(encoded);
        format!("vk1:{}", base32(&digest))
    }
    fn metadata_item_count(metadata: &ProviderMetadata) -> usize {
        metadata
            .events
            .len()
            .saturating_add(metadata.messages.len())
            .saturating_add(metadata.levels.len())
            .saturating_add(metadata.tasks.len())
            .saturating_add(metadata.opcodes.len())
            .saturating_add(metadata.keywords.len())
    }
    fn resolve_channel_name(
        channels: &BTreeMap<u32, ChannelReference>,
        channel_id: u64,
    ) -> Option<String> {
        channels
            .get(&(channel_id as u32))
            .map(|channel| channel.path.clone())
    }
    fn insert_named_metadata(map: &mut BTreeMap<String, String>, key: u64, value: String) {
        map.entry(key.to_string()).or_insert(value);
    }
    fn keyword_bits(mut mask: u64) -> Vec<u64> {
        let mut bits = Vec::new();
        while mask != 0 {
            let bit = 1u64 << (u64::BITS - 1 - mask.leading_zeros());
            bits.push(bit);
            mask &= !bit;
        }
        bits
    }
    unsafe fn decode_variant(variant: &EVT_VARIANT) -> Option<OwnedVariant> {
        let kind = variant.Type & EVT_VARIANT_TYPE_MASK;
        let number = match kind {
            value if value == EvtVarTypeUInt64.0 as u32 => Some(variant.Anonymous.UInt64Val),
            value if value == EvtVarTypeInt64.0 as u32 => Some(variant.Anonymous.Int64Val as u64),
            value if value == EvtVarTypeUInt32.0 as u32 => Some(variant.Anonymous.UInt32Val as u64),
            value if value == EvtVarTypeInt32.0 as u32 => Some(variant.Anonymous.Int32Val as u64),
            value if value == EvtVarTypeUInt16.0 as u32 => Some(variant.Anonymous.UInt16Val as u64),
            value if value == EvtVarTypeInt16.0 as u32 => Some(variant.Anonymous.Int16Val as u64),
            _ => None,
        };
        if let Some(number) = number {
            return Some(OwnedVariant::Number(number));
        }
        if kind == EvtVarTypeNull.0 as u32 {
            return Some(OwnedVariant::Null);
        }
        if kind == EvtVarTypeGuid.0 as u32 {
            let pointer = variant.Anonymous.GuidVal;
            return (!pointer.is_null()).then(|| {
                let guid = *pointer;
                OwnedVariant::String(format!(
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    guid.data1,
                    guid.data2,
                    guid.data3,
                    guid.data4[0],
                    guid.data4[1],
                    guid.data4[2],
                    guid.data4[3],
                    guid.data4[4],
                    guid.data4[5],
                    guid.data4[6],
                    guid.data4[7],
                ))
            });
        }
        if kind == EvtVarTypeEvtHandle.0 as u32 {
            return Some(OwnedVariant::Handle(variant.Anonymous.EvtHandleVal));
        }
        if kind != EvtVarTypeString.0 as u32 {
            return None;
        }
        let pointer = variant.Anonymous.StringVal;
        (!pointer.is_null())
            .then(|| pointer.to_string().ok())
            .flatten()
            .map(OwnedVariant::String)
    }

    unsafe fn read_variant(
        size: usize,
        mut read: impl FnMut(*mut EVT_VARIANT, u32, &mut u32) -> windows::core::Result<()>,
    ) -> Result<OwnedVariant, ProviderCaptureError> {
        if size == 0 || size > MAX_BUFFER_BYTES {
            return Err(ProviderCaptureError::message(format!(
                "metadata property size {size} exceeds bounded buffer"
            )));
        }
        let words = size.div_ceil(std::mem::size_of::<u64>());
        let mut buffer = vec![0u64; words];
        let destination = buffer.as_mut_ptr() as *mut EVT_VARIANT;
        let mut used = 0u32;
        read(
            destination,
            u32::try_from(buffer.len() * std::mem::size_of::<u64>())
                .map_err(|_| ProviderCaptureError::message("metadata buffer size overflow"))?,
            &mut used,
        )
        .map_err(|error| ProviderCaptureError::win32(win32_code(&error), error.to_string()))?;
        decode_variant(&*destination)
            .ok_or_else(|| ProviderCaptureError::message("unsupported EVT_VARIANT type"))
    }
    unsafe fn get_publisher_variant(
        metadata: EVT_HANDLE,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    ) -> Result<Option<OwnedVariant>, ProviderCaptureError> {
        let mut used = 0u32;
        let first = EvtGetPublisherMetadataProperty(metadata, property, 0, 0, None, &mut used);
        if let Err(error) = first {
            let code = win32_code(&error);
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(ProviderCaptureError::win32(
                    code,
                    format!("property {} query failed: {}", property.0, error),
                ));
            }
        } else {
            return Ok(None);
        }
        let size = usize::try_from(used)
            .map_err(|_| ProviderCaptureError::message("metadata property size overflow"))?;
        read_variant(size, |destination, buffer_size, used| {
            EvtGetPublisherMetadataProperty(
                metadata,
                property,
                0,
                buffer_size,
                Some(destination),
                used,
            )
        })
        .map(Some)
    }
    unsafe fn optional_publisher_variant(
        metadata: EVT_HANDLE,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    ) -> Result<(Option<OwnedVariant>, bool), ProviderCaptureError> {
        match get_publisher_variant(metadata, property) {
            Ok(value) => Ok((value, false)),
            Err(error)
                if error.code.is_some_and(|code| {
                    code == ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND.0
                        || code == ERROR_EVT_CHANNEL_NOT_FOUND.0
                        || code == ERROR_NOT_FOUND.0
                }) =>
            {
                Ok((None, true))
            }
            Err(error) => Err(error),
        }
    }
    unsafe fn get_event_variant(
        metadata: EVT_HANDLE,
        property: EVT_EVENT_METADATA_PROPERTY_ID,
    ) -> Result<OwnedVariant, ProviderCaptureError> {
        let mut used = 0u32;
        let first = EvtGetEventMetadataProperty(metadata, property, 0, 0, None, &mut used);
        if let Err(error) = first {
            let code = win32_code(&error);
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(ProviderCaptureError::win32(
                    code,
                    format!("event property {} query failed: {}", property.0, error),
                ));
            }
        } else {
            return Err(ProviderCaptureError::message(format!(
                "event property {} is empty",
                property.0
            )));
        }
        let size = usize::try_from(used)
            .map_err(|_| ProviderCaptureError::message("event property size overflow"))?;
        read_variant(size, |destination, buffer_size, used| {
            EvtGetEventMetadataProperty(metadata, property, 0, buffer_size, Some(destination), used)
        })
    }

    unsafe fn object_property(
        array_handle: isize,
        index: u32,
        property: u32,
    ) -> Result<OwnedVariant, ProviderCaptureError> {
        let mut used = 0u32;
        let first = EvtGetObjectArrayProperty(array_handle, property, index, 0, 0, None, &mut used);
        if let Err(error) = first {
            let code = win32_code(&error);
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(ProviderCaptureError::win32(
                    code,
                    format!("object property {property} query failed: {error}"),
                ));
            }
        } else {
            return Err(ProviderCaptureError::message(format!(
                "object property {property} is empty"
            )));
        }
        let size = usize::try_from(used)
            .map_err(|_| ProviderCaptureError::message("object property size overflow"))?;
        read_variant(size, |destination, buffer_size, used| {
            EvtGetObjectArrayProperty(
                array_handle,
                property,
                index,
                0,
                buffer_size,
                Some(destination),
                used,
            )
        })
    }
    unsafe fn format_message(
        metadata: EVT_HANDLE,
        message_id: u32,
    ) -> Result<Option<String>, ProviderCaptureError> {
        let mut used = 0u32;
        let initial = EvtFormatMessage(
            Some(metadata),
            None,
            message_id,
            None,
            EvtFormatMessageId.0,
            None,
            &mut used,
        );
        if let Err(error) = initial {
            let code = win32_code(&error);
            if is_unavailable_message_error(code) {
                return Ok(None);
            }
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(ProviderCaptureError::win32(
                    code,
                    format!("message {message_id} query failed: {error}"),
                ));
            }
        }
        let units = usize::try_from(used).map_err(|_| {
            ProviderCaptureError::message(format!("message {message_id} buffer size overflow"))
        })?;
        if units <= 1 {
            return Ok(None);
        }
        if units > MAX_BUFFER_BYTES / 2 {
            return Err(ProviderCaptureError::message(format!(
                "message {message_id} exceeds bounded buffer"
            )));
        }
        let mut buffer = vec![0u16; units];
        if let Err(error) = EvtFormatMessage(
            Some(metadata),
            None,
            message_id,
            None,
            EvtFormatMessageId.0,
            Some(&mut buffer),
            &mut used,
        ) {
            let code = win32_code(&error);
            if is_unavailable_message_error(code) {
                return Ok(None);
            }
            return Err(ProviderCaptureError::win32(
                code,
                format!("message {message_id} read failed: {error}"),
            ));
        }
        let length = usize::try_from(used)
            .map_err(|_| {
                ProviderCaptureError::message(format!("message {message_id} length overflow"))
            })?
            .min(buffer.len());
        Ok(Some(
            String::from_utf16_lossy(&buffer[..length])
                .trim_end_matches('\0')
                .to_string(),
        ))
    }
    unsafe fn collect_messages(
        metadata: EVT_HANDLE,
        ids: &mut BTreeMap<u64, ProviderMessage>,
    ) -> Result<(), ProviderCaptureError> {
        let mut add = |value: OwnedVariant| -> Result<(), ProviderCaptureError> {
            if let Some(raw_id) = optional_message_id(value)? {
                let short_id = short_message_id(raw_id);
                let text = format_message(metadata, raw_id)?;
                ids.entry(raw_id as u64).or_insert_with(|| ProviderMessage {
                    raw_id: raw_id as u64,
                    short_id,
                    provider_name: None,
                    template: None,
                    tag: None,
                    log_link: None,
                    text,
                });
            }
            Ok(())
        };
        if let (Some(value), _) =
            optional_publisher_variant(metadata, EvtPublisherMetadataPublisherMessageID)?
        {
            add(value)?;
        }
        Ok(())
    }

    unsafe fn channel_names(
        metadata: EVT_HANDLE,
    ) -> Result<(BTreeMap<u32, ChannelReference>, bool), ProviderCaptureError> {
        let (channel_value, unavailable) =
            optional_publisher_variant(metadata, EvtPublisherMetadataChannelReferences)?;
        let Some(channel_value) = channel_value else {
            return Ok((BTreeMap::new(), unavailable));
        };
        let OwnedVariant::Handle(array_handle) = channel_value else {
            return Err(ProviderCaptureError::message(
                "channel references metadata has an invalid type",
            ));
        };
        let array_handle = EvtHandle(array_handle);
        let mut count = 0u32;
        EvtGetObjectArraySize(array_handle.0 .0, &mut count).map_err(|error| {
            ProviderCaptureError::win32(
                win32_code(&error),
                format!("channel reference array size failed: {error}"),
            )
        })?;
        let count = usize::try_from(count)
            .map_err(|_| ProviderCaptureError::message("channel reference size overflow"))?;
        if count > MAX_OBJECT_ARRAY_ITEMS {
            return Err(ProviderCaptureError::message(
                "channel reference array exceeds bound",
            ));
        }
        let mut names = BTreeMap::new();
        for index in 0..count {
            let index = u32::try_from(index)
                .map_err(|_| ProviderCaptureError::message("channel reference index overflow"))?;
            let channel_id = number(object_property(
                array_handle.0 .0,
                index,
                EvtPublisherMetadataChannelReferenceID.0 as u32,
            )?)
            .ok_or_else(|| {
                ProviderCaptureError::message("channel reference ID has an invalid type")
            })?;
            let path = string(object_property(
                array_handle.0 .0,
                index,
                EvtPublisherMetadataChannelReferencePath.0 as u32,
            )?)
            .ok_or_else(|| {
                ProviderCaptureError::message("channel reference path has an invalid type")
            })?;
            let message_id = optional_message_id(object_property(
                array_handle.0 .0,
                index,
                EvtPublisherMetadataChannelReferenceMessageID.0 as u32,
            )?)?;
            names.insert(channel_id as u32, ChannelReference { path, message_id });
        }
        Ok((names, unavailable))
    }

    fn merge_provider_message(
        message: &mut ProviderMessage,
        provider_name: &str,
        template: Option<String>,
        text: Option<String>,
    ) {
        if message.provider_name.is_none() {
            message.provider_name = Some(provider_name.to_string());
        }
        if message.template.is_none() {
            message.template = template;
        }
        if message.text.is_none() {
            message.text = text;
        }
    }
    unsafe fn capture_provider(
        publisher_name: &str,
        metadata_handle: EVT_HANDLE,
        source_os_build: Option<u32>,
    ) -> Result<ProviderMetadata, ProviderCaptureError> {
        let mut metadata = ProviderMetadata {
            provider_name: publisher_name.to_string(),
            source_os_build,
            ..ProviderMetadata::default()
        };
        let (channels, channels_unavailable) = channel_names(metadata_handle)?;
        if channels_unavailable {
            metadata
                .unavailable_categories
                .insert("channels".to_string());
        }
        let mut messages = BTreeMap::new();
        collect_messages(metadata_handle, &mut messages)?;
        for channel in channels.values() {
            if let Some(message_id) = channel.message_id {
                let text = format_message(metadata_handle, message_id)?;
                messages
                    .entry(message_id as u64)
                    .or_insert(ProviderMessage {
                        raw_id: message_id as u64,
                        short_id: short_message_id(message_id),
                        provider_name: Some(publisher_name.to_string()),
                        template: None,
                        tag: None,
                        log_link: None,
                        text,
                    });
            }
        }

        for message in messages.values_mut() {
            message.provider_name = Some(publisher_name.to_string());
        }
        for (array_property, name_property, value_property, message_property, target) in [
            (
                EvtPublisherMetadataLevels,
                EvtPublisherMetadataLevelName,
                EvtPublisherMetadataLevelValue,
                EvtPublisherMetadataLevelMessageID,
                3u8,
            ),
            (
                EvtPublisherMetadataTasks,
                EvtPublisherMetadataTaskName,
                EvtPublisherMetadataTaskValue,
                EvtPublisherMetadataTaskMessageID,
                0u8,
            ),
            (
                EvtPublisherMetadataOpcodes,
                EvtPublisherMetadataOpcodeName,
                EvtPublisherMetadataOpcodeValue,
                EvtPublisherMetadataOpcodeMessageID,
                1u8,
            ),
            (
                EvtPublisherMetadataKeywords,
                EvtPublisherMetadataKeywordName,
                EvtPublisherMetadataKeywordValue,
                EvtPublisherMetadataKeywordMessageID,
                2u8,
            ),
        ] {
            let (array_value, unavailable) =
                optional_publisher_variant(metadata_handle, array_property)?;
            if unavailable {
                let category = match target {
                    0 => "tasks",
                    1 => "opcodes",
                    2 => "keywords",
                    _ => "levels",
                };
                metadata.unavailable_categories.insert(category.to_string());
            }
            let Some(array_value) = array_value else {
                continue;
            };
            let OwnedVariant::Handle(array_handle) = array_value else {
                return Err(ProviderCaptureError::message(format!(
                    "metadata array {} has an invalid type",
                    array_property.0
                )));
            };
            let array_handle = EvtHandle(array_handle);
            let mut count = 0u32;
            EvtGetObjectArraySize(array_handle.0 .0, &mut count).map_err(|error| {
                ProviderCaptureError::win32(
                    win32_code(&error),
                    format!("metadata array {} size failed: {error}", array_property.0),
                )
            })?;
            let count = usize::try_from(count)
                .map_err(|_| ProviderCaptureError::message("metadata array size overflow"))?;
            if count > MAX_OBJECT_ARRAY_ITEMS {
                return Err(ProviderCaptureError::message(format!(
                    "metadata array {} exceeds bound",
                    array_property.0
                )));
            }
            for index in 0..count {
                let index = u32::try_from(index)
                    .map_err(|_| ProviderCaptureError::message("metadata array index overflow"))?;
                let name = string(object_property(
                    array_handle.0 .0,
                    index,
                    name_property.0 as u32,
                )?)
                .ok_or_else(|| {
                    format!(
                        "metadata array {} name has an invalid type",
                        array_property.0
                    )
                })?;
                let raw_value = number(object_property(
                    array_handle.0 .0,
                    index,
                    value_property.0 as u32,
                )?)
                .ok_or_else(|| {
                    format!(
                        "metadata array {} value has an invalid type",
                        array_property.0
                    )
                })?;
                let value = metadata_key_value(target, raw_value);
                let message_id = optional_message_id(object_property(
                    array_handle.0 .0,
                    index,
                    message_property.0 as u32,
                )?)?;
                let message_text = if let Some(message_id) = message_id {
                    let text = format_message(metadata_handle, message_id)?;
                    let entry =
                        messages
                            .entry(message_id as u64)
                            .or_insert_with(|| ProviderMessage {
                                raw_id: message_id as u64,
                                short_id: short_message_id(message_id),
                                provider_name: Some(publisher_name.to_string()),
                                template: None,
                                tag: None,
                                log_link: None,
                                text: text.clone(),
                            });
                    merge_provider_message(entry, publisher_name, None, text.clone());
                    category_message_text(
                        Some(message_id),
                        text.map(trim_provider_text),
                        trim_provider_text(name),
                    )
                } else {
                    category_message_text(None, None, trim_provider_text(name))
                };
                let Some(message_text) = message_text else {
                    continue;
                };
                let target_map = match target {
                    0 => &mut metadata.tasks,
                    1 => &mut metadata.opcodes,
                    2 => &mut metadata.keywords,
                    _ => &mut metadata.levels,
                };
                insert_named_metadata(target_map, value, message_text);
            }
        }

        let event_enum = EvtOpenEventMetadataEnum(metadata_handle, 0).map_err(|error| {
            ProviderCaptureError::win32(
                win32_code(&error),
                format!("event metadata enumeration failed: {error}"),
            )
        })?;
        let event_enum = EvtHandle(event_enum);
        let mut exhausted = false;
        for _ in 0..MAX_EVENTS_PER_PROVIDER {
            let event_handle = match EvtNextEventMetadata(event_enum.0, 0) {
                Ok(handle) => EvtHandle(handle),
                Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS.0 => {
                    exhausted = true;
                    break;
                }
                Err(error) => {
                    return Err(ProviderCaptureError::win32(
                        win32_code(&error),
                        format!("event metadata enumeration failed: {error}"),
                    ));
                }
            };
            let id = optional_number(get_event_variant(event_handle.0, EventMetadataEventID)?)?
                .ok_or_else(|| "event metadata is missing EventID".to_string())?
                as u32;
            let version = optional_number(get_event_variant(
                event_handle.0,
                EventMetadataEventVersion,
            )?)?
            .unwrap_or(0) as u32;
            let channel_index = optional_number(get_event_variant(
                event_handle.0,
                EventMetadataEventChannel,
            )?)?
            .unwrap_or(0);
            let log_name = resolve_channel_name(&channels, channel_index);
            let level =
                optional_number(get_event_variant(event_handle.0, EventMetadataEventLevel)?)?
                    .map(|value| value as u32);
            let task = optional_number(get_event_variant(event_handle.0, EventMetadataEventTask)?)?
                .map(|value| value as u32);
            let opcode =
                optional_number(get_event_variant(event_handle.0, EventMetadataEventOpcode)?)?
                    .map(|value| value as u32);
            let keywords = optional_number(get_event_variant(
                event_handle.0,
                EventMetadataEventKeyword,
            )?)?
            .map(keyword_bits)
            .unwrap_or_default();
            let template = optional_template(get_event_variant(
                event_handle.0,
                EventMetadataEventTemplate,
            )?)?;
            let description = if let Some(message_id) = optional_message_id(get_event_variant(
                event_handle.0,
                EventMetadataEventMessageID,
            )?)? {
                let text = format_message(metadata_handle, message_id)?;
                let entry = messages
                    .entry(message_id as u64)
                    .or_insert_with(|| ProviderMessage {
                        raw_id: message_id as u64,
                        short_id: short_message_id(message_id),
                        provider_name: Some(publisher_name.to_string()),
                        template: template.clone(),
                        tag: None,
                        log_link: None,
                        text: text.clone(),
                    });
                merge_provider_message(entry, publisher_name, template.clone(), text.clone());
                event_message_text(Some(message_id), text.map(trim_provider_text))
            } else {
                event_message_text(None, None)
            };
            metadata.events.push(ProviderEvent {
                description,
                id,
                version,
                log_name,
                level,
                task,
                opcode,
                keywords,
                template,
            });
        }
        if !exhausted {
            return Err(ProviderCaptureError::message(
                "event metadata enumeration exceeded bound",
            ));
        }
        metadata.messages = messages.into_values().collect();
        Ok(metadata)
    }

    fn provider_version_key(metadata: &ProviderMetadata) -> String {
        canonical_version_key(metadata)
    }

    fn current_os_build() -> Option<u32> {
        let key = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
            .ok()?;
        key.get_value::<String, _>("CurrentBuildNumber")
            .ok()
            .or_else(|| key.get_value::<String, _>("CurrentBuild").ok())
            .and_then(|value| value.parse().ok())
    }

    pub fn capture_providers_to_db(db_path: &Path) -> Result<(), CaptureError> {
        let _capture_guard = CAPTURE_WRITE_LOCK
            .lock()
            .map_err(|_| CaptureError::traversal("provider capture lock is poisoned"))?;
        let publisher_enum = unsafe { EvtOpenPublisherEnum(None, 0) }.map_err(|error| {
            CaptureError::traversal(format!("cannot open publisher enumeration: {error}"))
        })?;
        let publisher_enum = EvtHandle(publisher_enum);
        let mut captured = Vec::new();
        let mut captured_items = 0usize;
        let mut failures = Vec::new();
        let mut hit_safety_bound = true;
        let source_os_build = current_os_build();

        for _ in 0..MAX_PUBLISHERS {
            let mut publisher_buffer = vec![0u16; BUFFER_RETRY];
            let mut used = 0u32;
            let mut retries = 0usize;
            let publisher_step = loop {
                match unsafe {
                    EvtNextPublisherId(publisher_enum.0, Some(&mut publisher_buffer), &mut used)
                } {
                    Ok(()) => {
                        let length = usize::try_from(used)
                            .unwrap_or(0)
                            .min(publisher_buffer.len());
                        let publisher_name = String::from_utf16_lossy(&publisher_buffer[..length])
                            .trim_end_matches('\0')
                            .to_string();
                        break publisher_enumeration_step(Some(publisher_name), &mut failures);
                    }
                    Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS.0 => {
                        break publisher_enumeration_step(None, &mut failures);
                    }
                    Err(error) if win32_code(&error) == ERROR_INSUFFICIENT_BUFFER.0 => {
                        let required = usize::try_from(used).unwrap_or(0);
                        if required == 0 || required > MAX_BUFFER_BYTES / 2 {
                            record_provider_failure(
                                &mut failures,
                                "<publisher enumeration>",
                                format!("publisher name buffer size {required} exceeds bound"),
                                false,
                            );
                            break PublisherEnumerationStep::Failed;
                        }
                        if retries >= PUBLISHER_NAME_RETRY_LIMIT {
                            record_provider_failure(
                                &mut failures,
                                "<publisher enumeration>",
                                "publisher name buffer retry budget exhausted".to_string(),
                                false,
                            );
                            break PublisherEnumerationStep::Failed;
                        }
                        retries += 1;
                        publisher_buffer.resize(required + 1, 0);
                    }
                    Err(error) => {
                        record_provider_failure(
                            &mut failures,
                            "<publisher enumeration>",
                            error.to_string(),
                            false,
                        );
                        break PublisherEnumerationStep::Failed;
                    }
                }
            };
            let publisher_name = match publisher_step {
                PublisherEnumerationStep::Publisher(publisher_name) => publisher_name,
                PublisherEnumerationStep::Exhausted | PublisherEnumerationStep::Failed => {
                    hit_safety_bound = false;
                    break;
                }
            };
            let publisher_wide = wide(&publisher_name);
            match unsafe {
                EvtOpenPublisherMetadata(
                    None,
                    PCWSTR(publisher_wide.as_ptr()),
                    PCWSTR::null(),
                    LOCALE_NEUTRAL,
                    0,
                )
            } {
                Ok(handle) => {
                    let handle = EvtHandle(handle);
                    match unsafe { capture_provider(&publisher_name, handle.0, source_os_build) } {
                        Ok(metadata) => {
                            let item_count = metadata_item_count(&metadata);
                            if item_count > MAX_CAPTURED_METADATA_ITEMS
                                || captured_items
                                    .checked_add(item_count)
                                    .is_none_or(|total| total > MAX_CAPTURED_METADATA_ITEMS)
                            {
                                record_provider_failure(
                                    &mut failures,
                                    &publisher_name,
                                    "captured provider metadata exceeds aggregate bound"
                                        .to_string(),
                                    false,
                                );
                                continue;
                            }
                            captured_items += item_count;
                            let version_key = provider_version_key(&metadata);
                            captured.push(
                                crate::event_log::provider_db::CapturedProviderMetadata {
                                    metadata,
                                    version_key,
                                },
                            );
                        }
                        Err(error) => {
                            let unavailable = error.code.is_some_and(is_unavailable_provider_error);
                            record_provider_failure(
                                &mut failures,
                                &publisher_name,
                                error.to_string(),
                                unavailable,
                            );
                        }
                    }
                }
                Err(error) => {
                    let code = win32_code(&error);
                    let message = format!("cannot open publisher metadata: {error}");
                    record_provider_failure(
                        &mut failures,
                        &publisher_name,
                        message,
                        is_unavailable_publisher_metadata_error(code),
                    );
                }
            }
        }
        finalize_provider_capture(captured.len(), failures, hit_safety_bound, || {
            crate::event_log::provider_db::write_provider_database(db_path, &captured).map(|_| ())
        })
    }
    #[cfg(test)]
    mod windows_tests {
        use super::*;

        #[test]
        fn null_optional_metadata_is_not_a_capture_error() {
            assert_eq!(
                optional_number(OwnedVariant::Null).expect("null is valid"),
                None
            );
            assert_eq!(
                optional_string(OwnedVariant::Null).expect("null is valid"),
                None
            );
        }
        #[test]
        fn empty_optional_template_is_absent() {
            assert_eq!(
                optional_template(OwnedVariant::String(String::new())).expect("empty is valid"),
                None
            );
            assert_eq!(
                optional_template(OwnedVariant::String("xml".to_string())).expect("text is valid"),
                Some("xml".to_string())
            );
        }

        #[test]
        fn version_keys_are_canonical_base32() {
            let key = canonical_version_key(&ProviderMetadata::default());
            assert!(key.starts_with("vk1:"));
            assert!(key[4..]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || b"234567".contains(&byte)));
            assert_eq!(base32(&[0]), "aa");
            assert_eq!(base32(&[0xff; 32]).len(), 52);
        }
        #[test]
        fn template_signature_uses_rendered_fields_not_attribute_order() {
            let first = ProviderEvent {
            template: Some(
                r#"<template><data name="Name" inType="win:UnicodeString" length="4"/></template>"#
                    .to_string(),
            ),
            ..ProviderEvent::default()
        };
            let second = ProviderEvent {
            template: Some(
                r#"<template><data length="4" inType="win:UnicodeString" name="Name"/></template>"#
                    .to_string(),
            ),
            ..ProviderEvent::default()
        };
            assert_eq!(encode_event(&first), encode_event(&second));
        }
        #[test]
        fn aggregate_metadata_item_count_is_bounded() {
            let metadata = ProviderMetadata {
                events: vec![ProviderEvent::default()],
                messages: vec![ProviderMessage::default()],
                levels: BTreeMap::from([("1".to_string(), "level".to_string())]),
                tasks: BTreeMap::from([("2".to_string(), "task".to_string())]),
                opcodes: BTreeMap::from([("3".to_string(), "opcode".to_string())]),
                keywords: BTreeMap::from([("4".to_string(), "keyword".to_string())]),
                ..ProviderMetadata::default()
            };
            assert_eq!(metadata_item_count(&metadata), 6);
            assert!(metadata_item_count(&metadata) < MAX_CAPTURED_METADATA_ITEMS);
        }
        #[test]
        fn zero_event_values_are_preserved_but_message_sentinel_is_absent() {
            assert_eq!(
                optional_number(OwnedVariant::Number(0)).expect("zero is valid"),
                Some(0)
            );
            assert_eq!(
                optional_message_id(OwnedVariant::Number(0)).expect("zero message id is valid"),
                Some(0)
            );
            assert_eq!(
                optional_message_id(OwnedVariant::Number(u32::MAX as u64))
                    .expect("sentinel is valid"),
                None
            );
            assert_eq!(
                optional_message_id(OwnedVariant::Number(0x1_0001)).expect("message id is valid"),
                Some(0x1_0001)
            );
            assert!(optional_message_id(OwnedVariant::Number(u32::MAX as u64 + 1)).is_err());
            assert_eq!(short_message_id(0x1_0001), 1);
        }
        #[test]
        fn duplicate_provider_messages_fill_missing_fields_without_overwriting() {
            let mut message = ProviderMessage {
                provider_name: None,
                template: None,
                text: None,
                ..ProviderMessage::default()
            };
            merge_provider_message(
                &mut message,
                "Provider",
                Some("<template/>".to_string()),
                Some("first".to_string()),
            );
            merge_provider_message(
                &mut message,
                "Other",
                Some("<replacement/>".to_string()),
                Some("replacement".to_string()),
            );
            assert_eq!(message.provider_name.as_deref(), Some("Provider"));
            assert_eq!(message.template.as_deref(), Some("<template/>"));
            assert_eq!(message.text.as_deref(), Some("first"));
        }

        #[test]
        fn canonical_event_and_message_ids_use_wire_widths() {
            let mut event = ProviderEvent {
                version: 1,
                ..ProviderEvent::default()
            };
            let first_event = encode_event(&event);
            event.version = 257;
            assert_eq!(first_event, encode_event(&event));

            let mut message = ProviderMessage {
                short_id: 1,
                ..ProviderMessage::default()
            };
            let first_message = encode_message(&message);
            message.short_id = 65_537;
            assert_eq!(first_message, encode_message(&message));
        }

        #[test]
        fn event_keyword_masks_preserve_all_captured_bits() {
            let bits = keyword_bits(0xFFFF_0000_0000_0005);
            assert_eq!(bits.len(), 18);
            assert_eq!(bits[0], 0x8000_0000_0000_0000);
            assert_eq!(bits[15], 0x0001_0000_0000_0000);
            assert_eq!(&bits[16..], &[4, 1]);
        }

        #[test]
        fn opcode_metadata_lookup_projects_packed_values_and_tasks_use_low_word() {
            let mut names = BTreeMap::new();
            insert_named_metadata(
                &mut names,
                opcode_metadata_key(0x000B_0000),
                "global".to_string(),
            );
            insert_named_metadata(
                &mut names,
                opcode_metadata_key(0x000B_0002),
                "task two".to_string(),
            );
            insert_named_metadata(
                &mut names,
                opcode_metadata_key(0x000B_0007),
                "task seven".to_string(),
            );
            assert_eq!(names.get("11").map(String::as_str), Some("global"));

            let mut tasks = BTreeMap::new();
            insert_named_metadata(
                &mut tasks,
                metadata_key_value(0, 0x000B_0002),
                "task two".to_string(),
            );
            assert_eq!(tasks.get("2").map(String::as_str), Some("task two"));
        }

        #[test]
        fn canonical_version_keys_ignore_order_but_change_with_content() {
            let first = ProviderMetadata {
                provider_name: "provider-a".to_string(),
                events: vec![
                    ProviderEvent {
                        id: 2,
                        version: 1,
                        description: Some("two".to_string()),
                        keywords: vec![4, 1, 4],
                        ..ProviderEvent::default()
                    },
                    ProviderEvent {
                        id: 1,
                        description: Some("one".to_string()),
                        ..ProviderEvent::default()
                    },
                ],
                messages: vec![ProviderMessage {
                    raw_id: 7,
                    short_id: 7,
                    text: Some("message".to_string()),
                    ..ProviderMessage::default()
                }],
                keywords: BTreeMap::from([("1".to_string(), "one".to_string())]),
                ..ProviderMetadata::default()
            };
            let mut reordered = first.clone();
            reordered.provider_name = "provider-b".to_string();
            reordered.events.reverse();
            reordered.events[1].keywords.reverse();
            assert_eq!(
                canonical_version_key(&first),
                canonical_version_key(&reordered)
            );
            let mut changed = first.clone();
            changed.events[0].description = Some("different".to_string());
            assert_ne!(
                canonical_version_key(&first),
                canonical_version_key(&changed)
            );
            let mut changed_build = first.clone();
            changed_build.source_os_build = Some(26200);
            assert_eq!(
                canonical_version_key(&first),
                canonical_version_key(&changed_build)
            );
            let mut changed_categories = first.clone();
            changed_categories
                .unavailable_categories
                .insert("keywords".to_string());
            assert_eq!(
                canonical_version_key(&first),
                canonical_version_key(&changed_categories)
            );
        }
        #[test]
        fn event_keyword_masks_expand_to_declared_bits() {
            assert_eq!(
                keyword_bits(0x8001_0000_0000_0005),
                vec![0x8000_0000_0000_0000, 0x0001_0000_0000_0000, 4, 1]
            );
            assert!(keyword_bits(0).is_empty());
        }

        #[test]
        fn opcode_metadata_key_projects_opcode_and_task_values() {
            assert_eq!(metadata_key_value(1, 0x000B_0000), 11);
            assert_eq!(metadata_key_value(1, 0x000B_0002), 11);
            assert_eq!(metadata_key_value(1, 0x0001_0000), 1);
            assert_eq!(metadata_key_value(0, 0x000B_0002), 2);
            assert_eq!(
                metadata_key_value(2, 0x8000_0000_0000_0001),
                0x8000_0000_0000_0001
            );
        }
        #[test]
        fn opcode_name_collision_keeps_first_display_name() {
            let mut names = BTreeMap::new();
            insert_named_metadata(&mut names, 11, "first".to_string());
            insert_named_metadata(&mut names, 11, "second".to_string());
            assert_eq!(names.get("11").map(String::as_str), Some("first"));
        }
        #[test]
        fn channel_resolution_uses_reference_id_not_array_position() {
            let channels = BTreeMap::from([
                (
                    7,
                    ChannelReference {
                        path: "Admin".to_string(),
                        message_id: Some(100),
                    },
                ),
                (
                    42,
                    ChannelReference {
                        path: "Operational".to_string(),
                        message_id: None,
                    },
                ),
            ]);
            assert_eq!(resolve_channel_name(&channels, 7).as_deref(), Some("Admin"));
            assert_eq!(resolve_channel_name(&channels, 1), None);
            assert_eq!(
                channels.get(&7).and_then(|channel| channel.message_id),
                Some(100)
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_capture::capture_providers_to_db;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_event_message_id_stays_absent_even_for_empty_text() {
        assert_eq!(event_message_text(None, Some(String::new())), None);
        assert_eq!(
            event_message_text(Some(7), Some(String::new())),
            Some(String::new())
        );
    }

    #[test]
    fn unresolved_category_message_does_not_fallback_to_inline_name() {
        assert_eq!(
            category_message_text(Some(7), None, "InlineName".to_string()),
            None
        );
        assert_eq!(
            category_message_text(None, None, "InlineName".to_string()),
            Some("InlineName".to_string())
        );
    }
    #[test]
    fn inline_category_names_trim_provider_controls() {
        assert_eq!(
            trim_provider_text("InlineName\r\n\t \0".to_string()),
            "InlineName"
        );
    }

    #[test]
    fn unresolved_message_errors_are_unavailable_but_resource_errors_are_not() {
        for code in [15007, 15027, 15028, 15029, 15030, 15033] {
            assert!(is_unavailable_message_error(code), "code {code}");
        }
        for code in [2, 1813, 15031, 15032] {
            assert!(!is_unavailable_message_error(code), "code {code}");
        }
    }

    #[test]
    fn unavailable_provider_resources_are_classified_without_being_dropped() {
        for code in [2, 1813, 15007, 15023, 15105] {
            assert!(is_unavailable_provider_error(code), "code {code}");
        }
        assert!(!is_unavailable_provider_error(13));
        assert!(is_unavailable_publisher_metadata_error(13));
        for code in [0, 5, 15031, 15032] {
            assert!(!is_unavailable_provider_error(code), "code {code}");
        }

        let mut failures = Vec::new();
        for (provider_name, error, unavailable) in [
            (
                "Capture-Provider",
                "provider capture is unavailable",
                is_unavailable_provider_error(2),
            ),
            (
                "Open-Provider",
                "publisher metadata is unavailable",
                is_unavailable_publisher_metadata_error(13),
            ),
        ] {
            record_provider_failure(&mut failures, provider_name, error.to_string(), unavailable);
        }

        assert_eq!(
            failures,
            vec![
                ProviderCaptureFailure {
                    provider_name: "Capture-Provider".to_string(),
                    error: "provider capture is unavailable".to_string(),
                },
                ProviderCaptureFailure {
                    provider_name: "Open-Provider".to_string(),
                    error: "publisher metadata is unavailable".to_string(),
                },
            ]
        );
    }

    #[test]
    fn provider_capture_failures_are_bounded_and_control_sanitized() {
        let mut failures = Vec::new();
        record_provider_failure(
            &mut failures,
            &format!("Bad\r\n{}\0", "p".repeat(300)),
            format!("failed\n{}\u{7}", "e".repeat(600)),
            false,
        );
        for index in 1..300 {
            record_provider_failure(
                &mut failures,
                &format!("Provider-{index}"),
                format!("failure-{index}"),
                false,
            );
        }

        assert_eq!(failures.len(), 256);
        assert_eq!(failures[0].provider_name.chars().count(), 256);
        assert_eq!(failures[0].error.chars().count(), 512);
        assert!(failures.iter().all(|failure| {
            !failure.provider_name.chars().any(char::is_control)
                && !failure.error.chars().any(char::is_control)
        }));
        assert_eq!(
            failures
                .iter()
                .filter(|failure| {
                    failure.provider_name == "<provider capture>"
                        && failure.error == "additional provider capture failures were truncated"
                })
                .count(),
            1
        );
    }

    #[test]
    fn publisher_exhaustion_is_distinct_from_an_empty_success() {
        let mut exhausted_failures = Vec::new();
        assert_eq!(
            publisher_enumeration_step(None, &mut exhausted_failures),
            PublisherEnumerationStep::Exhausted
        );
        assert!(exhausted_failures.is_empty());

        let mut empty_failures = Vec::new();
        assert_eq!(
            publisher_enumeration_step(Some(String::new()), &mut empty_failures),
            PublisherEnumerationStep::Failed
        );
        assert_eq!(
            empty_failures,
            vec![ProviderCaptureFailure {
                provider_name: "<publisher enumeration>".to_string(),
                error: "publisher enumeration returned an empty identifier".to_string(),
            }]
        );
    }

    #[test]
    fn incomplete_capture_states_preserve_the_existing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for captured_count in [0, 1] {
            let destination = directory
                .path()
                .join(format!("capture-{captured_count}.db"));
            std::fs::write(&destination, b"existing provider database").expect("seed destination");
            let mut failures = Vec::new();
            record_provider_failure(
                &mut failures,
                "Missing-Provider",
                "metadata unavailable".to_string(),
                true,
            );
            let writes = std::cell::Cell::new(0usize);

            let error = finalize_provider_capture(captured_count, failures, false, || {
                writes.set(writes.get() + 1);
                std::fs::write(&destination, b"partial replacement")
                    .map_err(|error| error.to_string())
            })
            .expect_err("incomplete capture must not publish");

            assert_eq!(error.kind, CaptureErrorKind::ProviderFailures);
            assert_eq!(writes.get(), 0);
            assert_eq!(
                std::fs::read(&destination).expect("read preserved destination"),
                b"existing provider database"
            );
        }
    }

    #[test]
    fn empty_publisher_success_prevents_publishing_a_captured_prefix() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("providers.db");
        std::fs::write(&destination, b"existing provider database").expect("seed destination");
        let mut failures = Vec::new();
        assert_eq!(
            publisher_enumeration_step(Some(String::new()), &mut failures),
            PublisherEnumerationStep::Failed
        );
        let writes = std::cell::Cell::new(0usize);

        let error = finalize_provider_capture(1, failures, false, || {
            writes.set(writes.get() + 1);
            std::fs::write(&destination, b"captured prefix").map_err(|error| error.to_string())
        })
        .expect_err("empty publisher identifiers make capture incomplete");

        assert_eq!(error.kind, CaptureErrorKind::ProviderFailures);
        assert_eq!(writes.get(), 0);
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"existing provider database"
        );
    }

    #[test]
    fn publisher_safety_bound_prevents_publishing_a_captured_prefix() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("providers.db");
        std::fs::write(&destination, b"existing provider database").expect("seed destination");
        let writes = std::cell::Cell::new(0usize);

        let error = finalize_provider_capture(1, Vec::new(), true, || {
            writes.set(writes.get() + 1);
            std::fs::write(&destination, b"captured prefix").map_err(|error| error.to_string())
        })
        .expect_err("hitting the publisher bound makes capture incomplete");

        assert_eq!(error.kind, CaptureErrorKind::ProviderFailures);
        assert_eq!(
            error.failures,
            vec![ProviderCaptureFailure {
                provider_name: "<publisher enumeration>".to_string(),
                error: "publisher enumeration exceeded bound".to_string(),
            }]
        );
        assert_eq!(writes.get(), 0);
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"existing provider database"
        );
    }

    #[test]
    fn clean_capture_publishes_once_after_documented_exhaustion() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("providers.db");
        std::fs::write(&destination, b"existing provider database").expect("seed destination");
        let mut failures = Vec::new();
        assert_eq!(
            publisher_enumeration_step(None, &mut failures),
            PublisherEnumerationStep::Exhausted
        );
        let writes = std::cell::Cell::new(0usize);

        finalize_provider_capture(1, failures, false, || {
            writes.set(writes.get() + 1);
            std::fs::write(&destination, b"complete replacement").map_err(|error| error.to_string())
        })
        .expect("clean capture should publish");

        assert_eq!(writes.get(), 1);
        assert_eq!(
            std::fs::read(&destination).expect("read published destination"),
            b"complete replacement"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn provider_capture_is_structured_unsupported_on_non_windows() {
        let error = capture_providers_to_db(Path::new("providers.db"))
            .expect_err("capture must be unsupported");
        assert_eq!(error.kind, CaptureErrorKind::Unsupported);
        assert!(error.to_string().contains("only available on Windows"));
        let json = serde_json::to_value(&error).expect("capture errors serialize");
        assert_eq!(json["kind"], "unsupported");
        assert!(json["failures"].as_array().is_some_and(Vec::is_empty));
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires an authorized Windows guest"]
    fn windows_provider_walk_writes_named_rows_with_composite_keys() {
        let path = std::env::temp_dir().join(format!(
            "cmtraceopen-provider-capture-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        capture_providers_to_db(&path).expect("the Windows publisher walk should complete");
        let connection = rusqlite::Connection::open(&path).expect("capture database opens");
        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM ProviderDetails \
                 WHERE ProviderName <> '' AND VersionKey LIKE 'vk1:%'",
                [],
                |row| row.get(0),
            )
            .expect("provider rows query");
        assert!(rows > 0, "capture should write named provider/version rows");
        let _ = std::fs::remove_file(path);
    }
}
