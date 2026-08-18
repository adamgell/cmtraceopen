//! Provider metadata capture.
//!
//! The Windows implementation deliberately keeps all `wevtapi` handles and unsafe pointer
//! handling in this module. The resulting [`ProviderMetadata`] is a parser-side value and remains
//! portable.

use std::path::Path;

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

    fn traversal(message: impl Into<String>) -> Self {
        Self {
            kind: CaptureErrorKind::Traversal,
            message: message.into(),
            failures: Vec::new(),
        }
    }

    fn provider_failures(failures: Vec<ProviderCaptureFailure>) -> Self {
        let message = format!(
            "{} provider(s) could not be captured: {}",
            failures.len(),
            failures
                .iter()
                .map(|failure| format!("{} ({})", failure.provider_name, failure.error))
                .collect::<Vec<_>>()
                .join("; ")
        );
        Self {
            kind: CaptureErrorKind::ProviderFailures,
            message,
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

#[cfg(target_os = "windows")]
mod windows_capture {
    use super::*;
    use cmtraceopen_parser::provider::{ProviderEvent, ProviderMessage, ProviderMetadata};
    use std::collections::BTreeMap;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
    use windows::Win32::System::EventLog::*;

    use winreg::enums::HKEY_LOCAL_MACHINE;
    const MAX_PUBLISHERS: usize = 100_000;
    const MAX_EVENTS_PER_PROVIDER: usize = 100_000;
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
            if win32_code(&error) != ERROR_INSUFFICIENT_BUFFER.0 {
                return Err(format!("property {} query failed: {}", property.0, error));
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
    unsafe fn format_message(metadata: EVT_HANDLE, message_id: u32) -> Option<String> {
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
            if win32_code(&error) != ERROR_INSUFFICIENT_BUFFER.0 {
                return None;
            }
        }
        let units = usize::try_from(used).ok()?;
        if units == 0 || units > MAX_BUFFER_BYTES / 2 {
            return None;
        }
        let mut buffer = vec![0u16; units];
        EvtFormatMessage(
            Some(metadata),
            None,
            message_id,
            None,
            EvtFormatMessageId.0 as u32,
            Some(&mut buffer),
            &mut used,
        )
        .ok()?;
        let length = usize::try_from(used).ok()?.min(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..length]).trim_end_matches('\0').to_string())
    }

    unsafe fn collect_messages(metadata: EVT_HANDLE, ids: &mut BTreeMap<u64, ProviderMessage>) {
        let mut add = |raw_id: Option<u64>| {
            if let Some(raw_id) = raw_id {
                let short_id = raw_id as u32;
                ids.entry(raw_id).or_insert_with(|| ProviderMessage {
                    raw_id,
                    short_id,
                    text: format_message(metadata, short_id),
                });
            }
        };
        add(get_publisher_variant(metadata, EvtPublisherMetadataPublisherMessageID).ok().flatten().and_then(number));
        for property in [
            EvtPublisherMetadataLevelMessageID,
            EvtPublisherMetadataTaskMessageID,
            EvtPublisherMetadataOpcodeMessageID,
            EvtPublisherMetadataKeywordMessageID,
        ] {
            if let Ok(Some(value)) = get_publisher_variant(metadata, property) {
                add(number(value));
            }
        }
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
        let mut messages = BTreeMap::new();
        collect_messages(metadata_handle, &mut messages);

        for (array_property, name_property, value_property, message_property, target) in [
            (EvtPublisherMetadataTasks, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskValue, EvtPublisherMetadataTaskMessageID, 0u8),
            (EvtPublisherMetadataOpcodes, EvtPublisherMetadataOpcodeName, EvtPublisherMetadataOpcodeValue, EvtPublisherMetadataOpcodeMessageID, 1u8),
            (EvtPublisherMetadataKeywords, EvtPublisherMetadataKeywordName, EvtPublisherMetadataKeywordValue, EvtPublisherMetadataKeywordMessageID, 2u8),
        ] {
            let array_values = get_publisher_variant(metadata_handle, array_property)?;
            let Some(OwnedVariant::Handle(array_handle)) = array_values else { continue };
            let array_handle = EvtHandle(array_handle);
            let mut count = 0u32;
            EvtGetObjectArraySize(array_handle.0.0, &mut count)
                .map_err(|error| format!("metadata array {} size failed: {error}", array_property.0))?;
            let count = usize::try_from(count).map_err(|_| "metadata array size overflow".to_string())?;
            if count > MAX_OBJECT_ARRAY_ITEMS { return Err("metadata object array exceeds bound".to_string()); }
            for index in 0..count {
                let index = u32::try_from(index).map_err(|_| "metadata array index overflow".to_string())?;
                let name = object_property(array_handle.0.0, index, name_property.0 as u32)
                    .ok()
                    .and_then(string);
                let value = object_property(array_handle.0.0, index, value_property.0 as u32)
                    .ok()
                    .and_then(number);
                let message_id = object_property(array_handle.0.0, index, message_property.0 as u32)
                    .ok()
                    .and_then(number);
                if let (Some(name), Some(value)) = (name, value) {
                    let target_map = match target {
                        0 => &mut metadata.tasks,
                        1 => &mut metadata.opcodes,
                        _ => &mut metadata.keywords,
                    };
                    target_map.insert(value.to_string(), name);
                }
                if let Some(message_id) = message_id {
                    messages.entry(message_id).or_insert_with(|| ProviderMessage {
                        raw_id: message_id,
                        short_id: message_id as u32,
                        text: format_message(metadata_handle, message_id as u32),
                    });
                }
            }
        }

        let event_enum = EvtOpenEventMetadataEnum(metadata_handle, 0)
            .map_err(|error| format!("event metadata enumeration failed: {error}"))?;
        let event_enum = EvtHandle(event_enum);
        for _ in 0..MAX_EVENTS_PER_PROVIDER {
            let event_handle = match EvtNextEventMetadata(event_enum.0, 0) {
                Ok(handle) => EvtHandle(handle),
                Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS.0 => break,
                Err(error) => return Err(format!("event metadata enumeration failed: {error}")),
            };
            let id = number(get_event_variant(event_handle.0, EventMetadataEventID)?).unwrap_or(0) as u32;
            let version = number(get_event_variant(event_handle.0, EventMetadataEventVersion)?).unwrap_or(0) as u32;
            let log_name = get_event_variant(event_handle.0, EventMetadataEventChannel)
                .ok()
                .and_then(string);
            let level = get_event_variant(event_handle.0, EventMetadataEventLevel)
                .ok()
                .and_then(number)
                .map(|value| value as u32);
            let task = get_event_variant(event_handle.0, EventMetadataEventTask)
                .ok()
                .and_then(number)
                .map(|value| value as u32);
            let opcode = get_event_variant(event_handle.0, EventMetadataEventOpcode)
                .ok()
                .and_then(number)
                .map(|value| value as u32);
            let keywords = get_event_variant(event_handle.0, EventMetadataEventKeyword)
                .ok()
                .and_then(number)
                .into_iter()
                .collect();
            let template = get_event_variant(event_handle.0, EventMetadataEventTemplate)
                .ok()
                .and_then(string);
            let description = get_event_variant(event_handle.0, EventMetadataEventMessageID)
                .ok()
                .and_then(number)
                .and_then(|message_id| {
                    messages.entry(message_id).or_insert_with(|| ProviderMessage {
                        raw_id: message_id,
                        short_id: message_id as u32,
                        text: format_message(metadata_handle, message_id as u32),
                    });
                    messages.get(&message_id).and_then(|message| message.text.clone())
                });
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
        metadata.messages = messages.into_values().collect();
        Ok(metadata)
    }

    unsafe fn provider_version_key(metadata: EVT_HANDLE) -> Result<String, String> {
        let read = |property: EVT_PUBLISHER_METADATA_PROPERTY_ID| -> Result<String, String> {
            Ok(get_publisher_variant(metadata, property)?
                .and_then(string)
                .unwrap_or_default())
        };
        let guid = read(EvtPublisherMetadataPublisherGuid)?;
        let resource = read(EvtPublisherMetadataResourceFilePath)?;
        let parameter = read(EvtPublisherMetadataParameterFilePath)?;
        let message = read(EvtPublisherMetadataMessageFilePath)?;
        if guid.is_empty() && resource.is_empty() && parameter.is_empty() && message.is_empty() {
            return Err("publisher metadata has no identity fields for VersionKey".to_string());
        }
        Ok(format!(
            "guid={guid}|resource={resource}|parameter={parameter}|message={message}"
        ))
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
        let publisher_enum = unsafe { EvtOpenPublisherEnum(None, 0) }
            .map_err(|error| CaptureError::traversal(format!("cannot open publisher enumeration: {error}")))?;
        let publisher_enum = EvtHandle(publisher_enum);
        let mut captured = Vec::new();
        let mut failures = Vec::new();
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
                        if captured.is_empty() && failures.is_empty() {
                            return Err(CaptureError::traversal("publisher enumeration returned no providers"));
                        }
                        break String::new();
                    }
                    Err(error) if win32_code(&error) == ERROR_INSUFFICIENT_BUFFER.0 => {
                        let required = usize::try_from(used).unwrap_or(0);
                        if required == 0 || required > MAX_BUFFER_BYTES / 2 {
                            failures.push(ProviderCaptureFailure { provider_name: "<publisher enumeration>".to_string(), error: format!("publisher name buffer size {required} exceeds bound") });
                            break String::new();
                        }
                        publisher_buffer.resize(required + 1, 0);
                    }
                    Err(error) => {
                        failures.push(ProviderCaptureFailure { provider_name: "<publisher enumeration>".to_string(), error: error.to_string() });
                        break String::new();
                    }
                }
            };
            if publisher_name.is_empty() { break; }
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
        if captured.is_empty() && failures.is_empty() {
            return Err(CaptureError::traversal("publisher enumeration exceeded its safety bound"));
        }
        crate::event_log::provider_db::write_provider_database(db_path, &captured)
            .map_err(CaptureError::traversal)?;
        if failures.is_empty() { Ok(()) } else { Err(CaptureError::provider_failures(failures)) }
    }
}

#[cfg(target_os = "windows")]
pub use windows_capture::capture_providers_to_db;

#[cfg(test)]
mod tests {
    use super::*;

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
                 WHERE ProviderName <> '' AND instr(VersionKey, '|') > 0",
                [],
                |row| row.get(0),
            )
            .expect("provider rows query");
        assert!(rows > 0, "capture should write named provider/version rows");
        let _ = std::fs::remove_file(path);
    }
}