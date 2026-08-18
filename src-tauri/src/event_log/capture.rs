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
    fn unsupported() -> Self {
        Self {
            kind: CaptureErrorKind::Unsupported,
            message: "Provider capture is only available on Windows".to_string(),
            failures: Vec::new(),
        }
    }

    #[cfg(target_os = "windows")]
    fn traversal(message: impl Into<String>) -> Self {
        Self {
            kind: CaptureErrorKind::Traversal,
            message: message.into(),
            failures: Vec::new(),
        }
    }

    #[cfg(target_os = "windows")]
    fn provider_failures(failures: Vec<ProviderCaptureFailure>) -> Self {
        Self {
            kind: CaptureErrorKind::ProviderFailures,
            message: "one or more providers could not be captured".to_string(),
            failures,
        }
    }
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
fn expand_windows_environment(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut remainder = value;
    while let Some(start) = remainder.find('%') {
        output.push_str(&remainder[..start]);
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('%') else {
            output.push_str(&remainder[start..]);
            return output;
        };
        let name = &after_start[..end];
        output.push_str(&std::env::var(name).unwrap_or_else(|_| format!("%{name}%")));
        remainder = &after_start[end + 1..];
    }
    output.push_str(remainder);
    output
}

#[cfg(any(target_os = "windows", test))]
fn provider_file_paths(value: &str) -> Vec<String> {
    value
        .split(';')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(expand_windows_environment)
        .collect()
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
        .trim_end_matches(|character| matches!(character, '\0' | '\r' | '\n' | '\t' | ' '))
        .to_string()
}


#[cfg(target_os = "windows")]
mod windows_capture {
    use super::*;
    use cmtraceopen_parser::provider::{ProviderEvent, ProviderMessage, ProviderMetadata};
    use std::collections::{BTreeMap, BTreeSet};
    use sha2::{Digest, Sha256};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_MESSAGE_ID_NOT_FOUND, ERROR_EVT_MESSAGE_NOT_FOUND,
        ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
        ERROR_NOT_FOUND,
    };
    use windows::Win32::System::EventLog::*;

    use winreg::enums::HKEY_LOCAL_MACHINE;
    const MAX_PUBLISHERS: usize = 100_000;
    const MAX_EVENTS_PER_PROVIDER: usize = 100_000;
    const MAX_IDENTITY_FILE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
    const MAX_OBJECT_ARRAY_ITEMS: usize = 100_000;
    const BUFFER_RETRY: usize = 256;
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

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    enum OwnedVariant {
        Null,
        String(String),
        Number(u64),
        Handle(EVT_HANDLE),
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
    fn optional_nonzero_number(value: OwnedVariant) -> Result<Option<u64>, String> {
        Ok(optional_number(value)?.filter(|value| *value != 0))
    }
    fn optional_message_id(value: OwnedVariant) -> Result<Option<u32>, String> {
        Ok(optional_number(value)?.and_then(|value| {
            let value = value as u32;
            (value != u32::MAX).then_some(value)
        }))
    }
    fn short_message_id(raw_id: u32) -> u32 {
        u32::from((raw_id & 0xFFFF) as u16)
    }
    fn metadata_key_value(target: u8, raw_value: u64) -> u64 {
        if target == 1 { (raw_value >> 16) & 0xFFFF } else { raw_value }
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
    fn canonical_version_key(identity: &[(&str, &str, &[u8])]) -> String {
        let mut digest = Sha256::new();
        for (label, _path, content) in identity {
            digest.update(label.as_bytes());
            digest.update((label.len() as u64).to_le_bytes());
            digest.update(content);
            digest.update((content.len() as u64).to_le_bytes());
        }
        format!("vk1:{}", base32(&digest.finalize()))
    }
    fn resolve_channel_name(channels: &BTreeMap<u32, String>, channel_id: u64) -> Option<String> {
        channels.get(&(channel_id as u32)).cloned()
    }
    fn canonical_version_key_owned(identity: &[(String, String, Vec<u8>)]) -> String {
        let parts: Vec<(&str, &str, &[u8])> = identity
            .iter()
            .map(|(label, path, content)| (label.as_str(), path.as_str(), content.as_slice()))
            .collect();
        canonical_version_key(&parts)
    }
    fn insert_named_metadata(map: &mut BTreeMap<String, String>, key: u64, value: String) {
        map.entry(key.to_string()).or_insert(value);
    }
    fn keyword_bits(mask: u64) -> Vec<u64> {
        (0..u64::BITS)
            .rev()
            .filter_map(|shift| {
                let bit = 1u64 << shift;
                (mask & bit != 0).then_some(bit)
            })
            .collect()
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
    ) -> Result<OwnedVariant, String> {
        if size == 0 || size > MAX_BUFFER_BYTES {
            return Err(format!("metadata property size {size} exceeds bounded buffer"));
        }
        let words = (size + std::mem::size_of::<u64>() - 1) / std::mem::size_of::<u64>();
        let mut buffer = vec![0u64; words];
        let destination = buffer.as_mut_ptr() as *mut EVT_VARIANT;
        let mut used = 0u32;
        read(
            destination,
            u32::try_from(buffer.len() * std::mem::size_of::<u64>())
                .map_err(|_| "metadata buffer size overflow".to_string())?,
            &mut used,
        )
        .map_err(|error| error.to_string())?;
        decode_variant(&*destination).ok_or_else(|| "unsupported EVT_VARIANT type".to_string())
    }

    unsafe fn get_publisher_variant(
        metadata: EVT_HANDLE,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    ) -> Result<Option<OwnedVariant>, String> {
        let mut used = 0u32;
        let first = EvtGetPublisherMetadataProperty(metadata, property, 0, 0, None, &mut used);
        if let Err(error) = first {
            let code = win32_code(&error);
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!("property {} query failed (code {}): {}", property.0, code, error));
            }
        } else {
            return Ok(None);
        }
        let size = usize::try_from(used).map_err(|_| "metadata property size overflow".to_string())?;
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
    ) -> Result<(Option<OwnedVariant>, bool), String> {
        match get_publisher_variant(metadata, property) {
            Ok(value) => Ok((value, false)),
            Err(error)
                if error.contains(&format!("code {}", ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND.0))
                    || error.contains(&format!("code {}", ERROR_EVT_CHANNEL_NOT_FOUND.0))
                    || error.contains(&format!("code {}", ERROR_NOT_FOUND.0)) =>
            {
                Ok((None, true))
            }
            Err(error) => Err(error),
        }
    }
    unsafe fn get_event_variant(
        metadata: EVT_HANDLE,
        property: EVT_EVENT_METADATA_PROPERTY_ID,
    ) -> Result<OwnedVariant, String> {
        let mut used = 0u32;
        let first = EvtGetEventMetadataProperty(metadata, property, 0, 0, None, &mut used);
        if let Err(error) = first {
            if win32_code(&error) != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!("event property {} query failed: {}", property.0, error));
            }
        } else {
            return Err(format!("event property {} is empty", property.0));
        }
        let size = usize::try_from(used).map_err(|_| "event property size overflow".to_string())?;
        read_variant(size, |destination, buffer_size, used| {
            EvtGetEventMetadataProperty(
                metadata,
                property,
                0,
                buffer_size,
                Some(destination),
                used,
            )
        })
    }

    unsafe fn object_property(
        array_handle: isize,
        index: u32,
        property: u32,
    ) -> Result<OwnedVariant, String> {
        let mut used = 0u32;
        let first = EvtGetObjectArrayProperty(array_handle, property, index, 0, 0, None, &mut used);
        if let Err(error) = first {
            if win32_code(&error) != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!("object property {property} query failed: {error}"));
            }
        } else {
            return Err(format!("object property {property} is empty"));
        }
        let size = usize::try_from(used).map_err(|_| "object property size overflow".to_string())?;
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
    unsafe fn format_message(metadata: EVT_HANDLE, message_id: u32) -> Result<Option<String>, String> {
        let mut used = 0u32;
        let initial = EvtFormatMessage(
            Some(metadata),
            None,
            message_id,
            None,
            EvtFormatMessageId.0 as u32,
            None,
            &mut used,
        );
        if let Err(error) = initial {
            let code = win32_code(&error);
            if code == ERROR_EVT_MESSAGE_NOT_FOUND.0 || code == ERROR_EVT_MESSAGE_ID_NOT_FOUND.0 {
                return Ok(None);
            }
            if code != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!("message {message_id} query failed: {error}"));
            }
        }
        let units = usize::try_from(used)
            .map_err(|_| format!("message {message_id} buffer size overflow"))?;
        if units == 0 || units > MAX_BUFFER_BYTES / 2 {
            return Err(format!("message {message_id} exceeds bounded buffer"));
        }
        let mut buffer = vec![0u16; units];
        if let Err(error) = EvtFormatMessage(
            Some(metadata),
            None,
            message_id,
            None,
            EvtFormatMessageId.0 as u32,
            Some(&mut buffer),
            &mut used,
        ) {
            let code = win32_code(&error);
            if code == ERROR_EVT_MESSAGE_NOT_FOUND.0 || code == ERROR_EVT_MESSAGE_ID_NOT_FOUND.0 {
                return Ok(None);
            }
            return Err(format!("message {message_id} read failed: {error}"));
        }
        let length = usize::try_from(used)
            .map_err(|_| format!("message {message_id} length overflow"))?
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
    ) -> Result<(), String> {
        let mut add = |value: OwnedVariant| -> Result<(), String> {
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

    unsafe fn channel_names(metadata: EVT_HANDLE) -> Result<(BTreeMap<u32, String>, bool), String> {
        let (channel_value, unavailable) =
            optional_publisher_variant(metadata, EvtPublisherMetadataChannelReferences)?;
        let Some(channel_value) = channel_value else {
            return Ok((BTreeMap::new(), unavailable));
        };
        let OwnedVariant::Handle(array_handle) = channel_value else {
            return Err("channel references metadata has an invalid type".to_string());
        };
        let array_handle = EvtHandle(array_handle);
        let mut count = 0u32;
        EvtGetObjectArraySize(array_handle.0.0, &mut count)
            .map_err(|error| format!("channel reference array size failed: {error}"))?;
        let count = usize::try_from(count).map_err(|_| "channel reference size overflow".to_string())?;
        if count > MAX_OBJECT_ARRAY_ITEMS {
            return Err("channel reference array exceeds bound".to_string());
        }
        let mut names = BTreeMap::new();
        for index in 0..count {
            let index = u32::try_from(index).map_err(|_| "channel reference index overflow".to_string())?;
            let channel_id = number(object_property(
                array_handle.0.0,
                index,
                EvtPublisherMetadataChannelReferenceID.0 as u32,
            )?)
            .ok_or_else(|| "channel reference ID has an invalid type".to_string())?;
            let path = string(object_property(
                array_handle.0.0,
                index,
                EvtPublisherMetadataChannelReferencePath.0 as u32,
            )?)
            .ok_or_else(|| "channel reference path has an invalid type".to_string())?;
            names.insert(channel_id as u32, path);
        }
        Ok((names, unavailable))
    }

    unsafe fn capture_provider(
        publisher_name: &str,
        metadata_handle: EVT_HANDLE,
        source_os_build: Option<u32>,
    ) -> Result<ProviderMetadata, String> {
        let mut metadata = ProviderMetadata {
            provider_name: publisher_name.to_string(),
            source_os_build,
            ..ProviderMetadata::default()
        };
        let (channels, channels_unavailable) = channel_names(metadata_handle)?;
        if channels_unavailable {
            metadata.unavailable_categories.insert("channels".to_string());
        }
        let mut messages = BTreeMap::new();
        collect_messages(metadata_handle, &mut messages)?;

        for message in messages.values_mut() {
            message.provider_name = Some(publisher_name.to_string());
        }
        for (array_property, name_property, value_property, message_property, target) in [
            (EvtPublisherMetadataLevels, EvtPublisherMetadataLevelName, EvtPublisherMetadataLevelValue, EvtPublisherMetadataLevelMessageID, 3u8),
            (EvtPublisherMetadataTasks, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskValue, EvtPublisherMetadataTaskMessageID, 0u8),
            (EvtPublisherMetadataOpcodes, EvtPublisherMetadataOpcodeName, EvtPublisherMetadataOpcodeValue, EvtPublisherMetadataOpcodeMessageID, 1u8),
            (EvtPublisherMetadataKeywords, EvtPublisherMetadataKeywordName, EvtPublisherMetadataKeywordValue, EvtPublisherMetadataKeywordMessageID, 2u8),
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
                return Err(format!(
                    "metadata array {} has an invalid type",
                    array_property.0
                ));
            };
            let array_handle = EvtHandle(array_handle);
            let mut count = 0u32;
            EvtGetObjectArraySize(array_handle.0.0, &mut count)
                .map_err(|error| format!("metadata array {} size failed: {error}", array_property.0))?;
            let count = usize::try_from(count).map_err(|_| "metadata array size overflow".to_string())?;
            if count > MAX_OBJECT_ARRAY_ITEMS {
                return Err(format!("metadata array {} exceeds bound", array_property.0));
            }
            for index in 0..count {
                let index = u32::try_from(index).map_err(|_| "metadata array index overflow".to_string())?;
                let name = string(object_property(array_handle.0.0, index, name_property.0 as u32)?)
                    .ok_or_else(|| format!("metadata array {} name has an invalid type", array_property.0))?;
                let raw_value = number(object_property(array_handle.0.0, index, value_property.0 as u32)?)
                    .ok_or_else(|| format!("metadata array {} value has an invalid type", array_property.0))?;
                let value = metadata_key_value(target, raw_value);
                let message_id = optional_message_id(object_property(
                    array_handle.0.0,
                    index,
                    message_property.0 as u32,
                )?)?;
                let message_text = if let Some(message_id) = message_id {
                    let text = format_message(metadata_handle, message_id)?;
                    messages.entry(message_id as u64).or_insert(ProviderMessage {
                        raw_id: message_id as u64,
                        short_id: short_message_id(message_id),
                        provider_name: Some(publisher_name.to_string()),
                        template: None,
                        tag: None,
                        log_link: None,
                        text: text.clone(),
                    });
                    category_message_text(Some(message_id), text.map(trim_provider_text), trim_provider_text(name))
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

        let event_enum = EvtOpenEventMetadataEnum(metadata_handle, 0)
            .map_err(|error| format!("event metadata enumeration failed: {error}"))?;
        let event_enum = EvtHandle(event_enum);
        let mut exhausted = false;
        for _ in 0..MAX_EVENTS_PER_PROVIDER {
            let event_handle = match EvtNextEventMetadata(event_enum.0, 0) {
                Ok(handle) => EvtHandle(handle),
                Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS.0 => {
                    exhausted = true;
                    break;
                }
                Err(error) => return Err(format!("event metadata enumeration failed: {error}")),
            };
            let id = optional_number(get_event_variant(event_handle.0, EventMetadataEventID)?)?
                .ok_or_else(|| "event metadata is missing EventID".to_string())? as u32;
            let version = optional_number(get_event_variant(event_handle.0, EventMetadataEventVersion)?)?
                .unwrap_or(0) as u32;
            let channel_index = optional_number(get_event_variant(event_handle.0, EventMetadataEventChannel)?)?
                .unwrap_or(0);
            let log_name = channels.get(&(channel_index as u32)).cloned();
            let level = optional_number(get_event_variant(event_handle.0, EventMetadataEventLevel)?)?
                .map(|value| value as u32)
                .unwrap_or(0);
            let task_metadata = optional_number(get_event_variant(event_handle.0, EventMetadataEventTask)?)?
                .map(|value| value as u32);
            let opcode_raw =
                optional_number(get_event_variant(event_handle.0, EventMetadataEventOpcode)?)?;
            let opcode = opcode_raw.map(|value| value as u32).unwrap_or(0);
            let task = task_metadata.unwrap_or(0);
            let keywords = optional_number(get_event_variant(event_handle.0, EventMetadataEventKeyword)?)?
                .map(keyword_bits)
                .unwrap_or_default();
            let template = optional_template(get_event_variant(event_handle.0, EventMetadataEventTemplate)?)?;
            let description = if let Some(message_id) =
                optional_message_id(get_event_variant(event_handle.0, EventMetadataEventMessageID)?)?
            {
                let text = format_message(metadata_handle, message_id)?;
                messages.entry(message_id as u64).or_insert(ProviderMessage {
                    raw_id: message_id as u64,
                    short_id: short_message_id(message_id),
                    provider_name: Some(publisher_name.to_string()),
                    template: template.clone(),
                    tag: None,
                    log_link: None,
                    text: text.clone(),
                });
                event_message_text(Some(message_id), text.map(trim_provider_text))
            } else {
                event_message_text(None, None)
            };
            metadata.events.push(ProviderEvent {
                description,
                id,
                version,
                log_name,
                level: Some(level),
                task: Some(task),
                opcode: Some(opcode),
                keywords,
                template,
            });
        }
        if !exhausted {
            return Err("event metadata enumeration exceeded bound".to_string());
        }
        metadata.messages = messages.into_values().collect();
        Ok(metadata)
    }

    unsafe fn provider_version_key(metadata: EVT_HANDLE) -> Result<String, String> {
        let read = |property: EVT_PUBLISHER_METADATA_PROPERTY_ID| -> Result<Option<String>, String> {
            match optional_publisher_variant(metadata, property) {
                Ok((value, _unavailable)) => value
                    .map(|variant| {
                        string(variant)
                            .ok_or_else(|| format!("publisher property {} has an invalid type", property.0))
                    })
                    .transpose(),
                Err(error)
                    if error.contains(&format!("code {}", ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND.0))
                        || error.contains(&format!("code {}", ERROR_EVT_CHANNEL_NOT_FOUND.0))
                        || error.contains(&format!("code {}", ERROR_NOT_FOUND.0)) =>
                {
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        };
        let guid = read(EvtPublisherMetadataPublisherGuid)?.unwrap_or_default();
        let resource = read(EvtPublisherMetadataResourceFilePath)?.unwrap_or_default();
        let parameter = read(EvtPublisherMetadataParameterFilePath)?.unwrap_or_default();
        let message = read(EvtPublisherMetadataMessageFilePath)?.unwrap_or_default();
        if guid.is_empty() && resource.is_empty() && parameter.is_empty() && message.is_empty() {
            return Err("publisher metadata has no identity fields for VersionKey".to_string());
        }
        let mut identity = vec![("guid".to_string(), guid.clone(), guid.into_bytes())];
        for (label, raw_paths) in [
            ("resource", resource.as_str()),
            ("parameter", parameter.as_str()),
            ("message", message.as_str()),
        ] {
            for path in provider_file_paths(raw_paths) {
                let canonical = std::fs::canonicalize(&path)
                    .map_err(|error| format!("cannot canonicalize {label} identity file {path}: {error}"))?;
                let canonical_path = canonical.to_string_lossy().into_owned();
                let size = std::fs::metadata(&canonical)
                    .map_err(|error| format!("cannot inspect {label} identity file {canonical_path}: {error}"))?
                    .len();
                if size > MAX_IDENTITY_FILE_BYTES {
                    return Err(format!(
                        "{label} identity file {canonical_path} exceeds {MAX_IDENTITY_FILE_BYTES} bytes"
                    ));
                }
                let content = std::fs::read(&canonical)
                    .map_err(|error| format!("cannot read {label} identity file {canonical_path}: {error}"))?;
                if content.len() as u64 > MAX_IDENTITY_FILE_BYTES {
                    return Err(format!(
                        "{label} identity file {canonical_path} grew beyond {MAX_IDENTITY_FILE_BYTES} bytes"
                    ));
                }
                identity.push((label.to_string(), String::new(), content));
            }
        }
        Ok(canonical_version_key_owned(&identity))
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
        let publisher_enum = unsafe { EvtOpenPublisherEnum(None, 0) }
            .map_err(|error| CaptureError::traversal(format!("cannot open publisher enumeration: {error}")))?;
        let publisher_enum = EvtHandle(publisher_enum);
        let mut captured = Vec::new();
        let mut failures = Vec::new();
        let mut hit_safety_bound = true;
        let source_os_build = current_os_build();

        for _ in 0..MAX_PUBLISHERS {
            let mut publisher_buffer = vec![0u16; BUFFER_RETRY];
            let mut used = 0u32;
            let publisher_name = loop {
                match unsafe { EvtNextPublisherId(publisher_enum.0, Some(&mut publisher_buffer), &mut used) } {
                    Ok(()) => {
                        let length = usize::try_from(used).unwrap_or(0).min(publisher_buffer.len());
                        break String::from_utf16_lossy(&publisher_buffer[..length]).trim_end_matches('\0').to_string();
                    }
                    Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS.0 => {
                        hit_safety_bound = false;
                        if captured.is_empty() && failures.is_empty() {
                            return Err(CaptureError::traversal("publisher enumeration returned no providers"));
                        }
                        break String::new();
                    }
                    Err(error) if win32_code(&error) == ERROR_INSUFFICIENT_BUFFER.0 => {
                        let required = usize::try_from(used).unwrap_or(0);
                        if required == 0 || required > MAX_BUFFER_BYTES / 2 {
                            hit_safety_bound = false;
                            failures.push(ProviderCaptureFailure { provider_name: "<publisher enumeration>".to_string(), error: format!("publisher name buffer size {required} exceeds bound") });
                            break String::new();
                        }
                        publisher_buffer.resize(required + 1, 0);
                    }
                    Err(error) => {
                        hit_safety_bound = false;
                        failures.push(ProviderCaptureFailure { provider_name: "<publisher enumeration>".to_string(), error: error.to_string() });
                        break String::new();
                    }
                }
            };
            if publisher_name.is_empty() {
                hit_safety_bound = false;
                break;
            }
            let publisher_wide = wide(&publisher_name);
            match unsafe { EvtOpenPublisherMetadata(None, PCWSTR(publisher_wide.as_ptr()), PCWSTR::null(), LOCALE_NEUTRAL, 0) } {
                Ok(handle) => {
                    let handle = EvtHandle(handle);
                    match unsafe { capture_provider(&publisher_name, handle.0, source_os_build) } {
                        Ok(metadata) => {
                            match unsafe { provider_version_key(handle.0) } {
                                Ok(version_key) => {
                                    captured.push(crate::event_log::provider_db::CapturedProviderMetadata {
                                        metadata,
                                        version_key,
                                    });
                                }
                                Err(error) => failures.push(ProviderCaptureFailure { provider_name: publisher_name.clone(), error }),
                            }
                        }
                        Err(error) => failures.push(ProviderCaptureFailure { provider_name: publisher_name.clone(), error }),
                    }
                }
                Err(error) => failures.push(ProviderCaptureFailure { provider_name: publisher_name.clone(), error: format!("cannot open publisher metadata: {error}") }),
            }
        }
        if captured.is_empty() {
            if failures.is_empty() {
                return Err(CaptureError::traversal("publisher enumeration exceeded its safety bound"));
            }
            return Err(CaptureError::provider_failures(failures));
        }
        if hit_safety_bound {
            failures.push(ProviderCaptureFailure {
                provider_name: "<publisher enumeration>".to_string(),
                error: "publisher enumeration exceeded bound".to_string(),
            });
        }
        if !failures.is_empty() {
            return Err(CaptureError::provider_failures(failures));
        }
        crate::event_log::provider_db::write_provider_database(db_path, &captured)
            .map_err(CaptureError::traversal)?;
        Ok(())
    }
#[cfg(test)]
mod windows_tests {
    use super::*;

    #[test]
    fn null_optional_metadata_is_not_a_capture_error() {
        assert_eq!(optional_number(OwnedVariant::Null).expect("null is valid"), None);
        assert_eq!(optional_string(OwnedVariant::Null).expect("null is valid"), None);
    }
    #[test]
    fn zero_optional_event_metadata_is_absent() {
        assert_eq!(optional_nonzero_number(OwnedVariant::Number(0)).expect("zero is valid"), None);
        assert_eq!(optional_nonzero_number(OwnedVariant::Number(7)).expect("number is valid"), Some(7));
        assert_eq!(optional_template(OwnedVariant::String(String::new())).expect("empty is valid"), None);
        assert_eq!(optional_template(OwnedVariant::String("xml".to_string())).expect("text is valid"), Some("xml".to_string()));
    }

    #[test]
    fn version_keys_are_canonical_base32_and_include_file_content() {
        let first = canonical_version_key(&[("resource", "same.dll", b"one")]);
        let second = canonical_version_key(&[("resource", "same.dll", b"two")]);
        assert!(first.starts_with("vk1:"));
        assert!(first[4..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || b"234567".contains(&byte)));
        assert_eq!(base32(&[0]), "aa");
        assert_ne!(first, second, "same payload content change needs a new version");
        assert_eq!(
            first,
            canonical_version_key(&[("resource", "different-machine-path.dll", b"one")])
        );
        let high_bytes = base32(&[0xff; 32]);
        assert_eq!(high_bytes.len(), 52);
    }
    #[test]
    fn zero_event_values_are_preserved_but_message_sentinel_is_absent() {
        assert_eq!(optional_number(OwnedVariant::Number(0)).expect("zero is valid"), Some(0));
        assert_eq!(
            optional_message_id(OwnedVariant::Number(0)).expect("zero message id is valid"),
            Some(0)
        );
        assert_eq!(
            optional_message_id(OwnedVariant::Number(u32::MAX as u64)).expect("sentinel is valid"),
            None
        );
        assert_eq!(
            optional_message_id(OwnedVariant::Number(0x1_0001)).expect("message id is valid"),
            Some(0x1_0001)
        );
        assert_eq!(short_message_id(0x1_0001), 1);
    }
    #[test]
    fn event_keyword_masks_expand_to_individual_bits() {
        assert_eq!(keyword_bits(0x8000_0000_0000_0005), vec![0x8000_0000_0000_0000, 4, 1]);
        assert!(keyword_bits(0).is_empty());
    }

    #[test]
    fn opcode_metadata_uses_high_word_while_task_keeps_low_word() {
        assert_eq!(metadata_key_value(1, 0x000B_0002), 11);
        assert_eq!(metadata_key_value(0, 0x0000_0007), 7);
        assert_eq!(metadata_key_value(2, 0x8000_0000_0000_0001), 0x8000_0000_0000_0001);
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
        let channels = BTreeMap::from([(7, "Admin".to_string()), (42, "Operational".to_string())]);
        assert_eq!(resolve_channel_name(&channels, 0), None);
        assert_eq!(resolve_channel_name(&channels, 1), None);
    }
}

}

#[cfg(target_os = "windows")]
pub use windows_capture::capture_providers_to_db;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_file_paths_split_and_trim_semicolon_lists() {
        assert_eq!(
            provider_file_paths(" first.dll ; ;second.dll "),
            vec!["first.dll".to_string(), "second.dll".to_string()]
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn provider_file_paths_preserve_unresolved_windows_variables() {
        assert_eq!(
            provider_file_paths("%CMTRACEOPEN_MISSING_ENV%/messages.dll"),
            vec!["%CMTRACEOPEN_MISSING_ENV%/messages.dll".to_string()]
        );
    }

    #[test]
    fn unmatched_environment_variable_preserves_literal_remainder() {
        assert_eq!(
            expand_windows_environment("prefix/%MISSING%/suffix/%UNMATCHED"),
            "prefix/%MISSING%/suffix/%UNMATCHED"
        );
    }
    #[test]
    fn absent_event_message_id_stays_absent_even_for_empty_text() {
        assert_eq!(event_message_text(None, Some(String::new())), None);
        assert_eq!(event_message_text(Some(7), Some(String::new())), Some(String::new()));
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