//! Captures provider metadata into an EventLogExpert-compatible database (issue #539, Phase 2).
//!
//! Walks the registered publishers with `wevtapi`, extracts each one's event definitions and
//! message tables, and writes one `.db` the application reads back through
//! [`provider_db::ProviderDb`](app_lib::event_log::provider_db::ProviderDb). This is the capture
//! half of the curated-databases deliverable; the read half already ships.
//!
//! Windows only, because there is no Event Log service to walk anywhere else.
//!
//! ```text
//! cargo run --release --example provider_capture --features event-log -- --output providers.db
//! cargo run --release --example provider_capture --features event-log -- \
//!   --output intune.db --provider Microsoft-Windows-DeviceManagement
//! ```

use std::path::PathBuf;

fn main() {
    // A flag may repeat: `--provider A --provider B`. Values run until the next flag.
    let args: Vec<String> = std::env::args().collect();
    let values_of = |flag: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if args[i] == flag {
                i += 1;
                while i < args.len() && !args[i].starts_with("--") {
                    out.push(args[i].clone());
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        out
    };

    let output = values_of("--output").into_iter().next().map(PathBuf::from);
    let providers = values_of("--provider");

    run(output, providers);
}

#[cfg(target_os = "windows")]
fn run(output: Option<PathBuf>, providers: Vec<String>) {
    let destination = output.unwrap_or_else(|| PathBuf::from("providers.db"));
    match capture::capture(&destination, &providers) {
        Ok(count) => println!("captured {count} providers into {}", destination.display()),
        Err(error) => {
            eprintln!("capture failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn run(_output: Option<PathBuf>, _providers: Vec<String>) {
    eprintln!("provider_capture needs a Windows Event Log service; nothing to capture here.");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
mod capture {
    use std::collections::BTreeMap;
    use std::path::Path;

    use cmtraceopen_parser::provider::{ProviderEvent, ProviderMessage, ProviderMetadata};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtFormatMessage, EvtFormatMessageId, EvtGetEventMetadataProperty,
        EvtGetObjectArrayProperty, EvtGetObjectArraySize, EvtGetPublisherMetadataProperty,
        EvtNextEventMetadata, EvtNextPublisherId, EvtOpenEventMetadataEnum,
        EvtOpenPublisherEnum, EvtOpenPublisherMetadata, EvtPublisherMetadataChannelReferenceIndex,
        EvtPublisherMetadataChannelReferencePath, EvtPublisherMetadataChannelReferences,
        EvtPublisherMetadataKeywordMessageID, EvtPublisherMetadataKeywordName, EvtPublisherMetadataKeywordValue,
        EvtPublisherMetadataKeywords, EvtPublisherMetadataOpcodeMessageID, EvtPublisherMetadataOpcodeName,
        EvtPublisherMetadataOpcodeValue, EvtPublisherMetadataOpcodes,
        EvtPublisherMetadataTaskMessageID, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskValue,
        EvtPublisherMetadataTasks, EvtVarTypeEvtHandle, EvtVarTypeString, EvtVarTypeUInt32,
        EvtVarTypeUInt64, EventMetadataEventChannel, EventMetadataEventID,
        EventMetadataEventKeyword, EventMetadataEventLevel, EventMetadataEventMessageID,
        EventMetadataEventOpcode, EventMetadataEventTask, EventMetadataEventTemplate,
        EventMetadataEventVersion, EVT_EVENT_METADATA_PROPERTY_ID,
        EVT_PUBLISHER_METADATA_PROPERTY_ID, EVT_HANDLE, EVT_VARIANT,
    };

    /// RAII wrapper so every handle is closed once, including on early return.
    struct OwnedEvtHandle(EVT_HANDLE);

    impl OwnedEvtHandle {
        fn new(handle: EVT_HANDLE) -> Self {
            Self(handle)
        }

        fn raw(&self) -> EVT_HANDLE {
            self.0
        }
    }

    impl Drop for OwnedEvtHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    /// Captures every matching publisher and writes one database.
    pub fn capture(destination: &Path, filter: &[String]) -> Result<usize, String> {
        let publishers = enumerate_publishers()?;
        let selected: Vec<String> = publishers
            .into_iter()
            .filter(|name| filter.is_empty() || filter.iter().any(|prefix| name.starts_with(prefix)))
            .collect();

        let mut metadata = Vec::with_capacity(selected.len());
        for name in &selected {
            match capture_provider(name) {
                Some(provider) => {
                    println!("captured {name}: {} events", provider.events.len());
                    metadata.push(provider);
                }
                None => println!("skipped {name}: no metadata"),
            }
        }

        app_lib::event_log::provider_db::write_provider_database(destination, &metadata)
    }

    fn enumerate_publishers() -> Result<Vec<String>, String> {
        let handle = unsafe { EvtOpenPublisherEnum(None, 0) }
            .map_err(|error| format!("EvtOpenPublisherEnum failed: {error}"))?;
        let handle = OwnedEvtHandle::new(handle);

        let mut publishers = Vec::new();
        let mut buffer = vec![0u16; 256];
        loop {
            let mut used = 0u32;
            match unsafe { EvtNextPublisherId(handle.raw(), Some(buffer.as_mut_slice()), &mut used) } {
                Ok(()) => {
                    let len = used.saturating_sub(1) as usize;
                    publishers.push(String::from_utf16_lossy(&buffer[..len]));
                }
                Err(error) if win32_code(&error) == 259 => break, // ERROR_NO_MORE_ITEMS
                Err(error) if win32_code(&error) == 122 => {
                    // ERROR_INSUFFICIENT_BUFFER: the id was longer than the buffer.
                    buffer.resize(used.max(buffer.len() as u32 * 2) as usize, 0);
                }
                Err(error) => return Err(format!("EvtNextPublisherId failed: {error}")),
            }
        }
        Ok(publishers)
    }

    /// Extracts one publisher's metadata, or `None` when it opens to nothing.
    fn capture_provider(name: &str) -> Option<ProviderMetadata> {
        let provider = HSTRING::from(name);
        let metadata = unsafe { EvtOpenPublisherMetadata(None, &provider, PCWSTR::null(), 0, 0) }
            .ok()
            .map(OwnedEvtHandle::new)?;

        let channels = channel_index_map(&metadata);

        let mut events = Vec::new();
        let mut messages = Vec::new();

        let event_enum = unsafe { EvtOpenEventMetadataEnum(metadata.raw(), 0) }
            .ok()
            .map(OwnedEvtHandle::new)?;

        loop {
            // `EvtNextEventMetadata` errors once the enumeration is exhausted.
            let Ok(event) = (unsafe { EvtNextEventMetadata(event_enum.raw(), 0) }) else {
                break;
            };
            let event = OwnedEvtHandle::new(event);

            let id = event_property_u32(event.raw(), EventMetadataEventID)?;
            let version = event_property_u32(event.raw(), EventMetadataEventVersion).unwrap_or(0);
            let message_id = event_property_u32(event.raw(), EventMetadataEventMessageID)?;
            let description = format_message(metadata.raw(), message_id, EvtFormatMessageId.0);

            let channel_index = event_property_u32(event.raw(), EventMetadataEventChannel);
            let log_name = channel_index.and_then(|index| channels.get(&index).cloned());

            events.push(ProviderEvent {
                id,
                version,
                description: description.clone(),
                log_name,
                level: event_property_u32(event.raw(), EventMetadataEventLevel),
                task: event_property_u32(event.raw(), EventMetadataEventTask),
                opcode: event_property_u32(event.raw(), EventMetadataEventOpcode),
                keywords: event_property_u64(event.raw(), EventMetadataEventKeyword)
                    .map(|mask| vec![mask])
                    .unwrap_or_default(),
                template: event_property_string(event.raw(), EventMetadataEventTemplate),
            });
            messages.push(ProviderMessage {
                raw_id: message_id as u64,
                short_id: id,
                text: description,
            });
        }

        let tasks = name_table(
            &metadata,
            EvtPublisherMetadataTasks,
            EvtPublisherMetadataTaskValue,
            EvtPublisherMetadataTaskName,
            EvtPublisherMetadataTaskMessageID,
            false,
        );
        let opcodes = name_table(
            &metadata,
            EvtPublisherMetadataOpcodes,
            EvtPublisherMetadataOpcodeValue,
            EvtPublisherMetadataOpcodeName,
            EvtPublisherMetadataOpcodeMessageID,
            false,
        );
        let keywords = name_table(
            &metadata,
            EvtPublisherMetadataKeywords,
            EvtPublisherMetadataKeywordValue,
            EvtPublisherMetadataKeywordName,
            EvtPublisherMetadataKeywordMessageID,
            true,
        );

        Some(ProviderMetadata {
            provider_name: name.to_string(),
            events,
            messages,
            tasks,
            keywords,
            opcodes,
            source_os_build: None,
        })
    }

    /// Maps a channel reference index to its path, for the event's `log_name`.
    fn channel_index_map(metadata: &OwnedEvtHandle) -> BTreeMap<u32, String> {
        let mut map = BTreeMap::new();
        let Some(array) = handle_property(metadata, EvtPublisherMetadataChannelReferences) else {
            return map;
        };
        let mut size = 0u32;
        if unsafe { EvtGetObjectArraySize(array.raw().0, &mut size) }.is_err() {
            return map;
        }
        for index in 0..size {
            let Some(value) =
                object_property_u32(array.raw().0, EvtPublisherMetadataChannelReferenceIndex, index)
            else {
                continue;
            };
            let Some(path) =
                object_property_string(array.raw().0, EvtPublisherMetadataChannelReferencePath, index)
            else {
                continue;
            };
            map.insert(value, path);
        }
        map
    }

    /// Reads a value-to-name table (tasks, keywords, or opcodes) as a map.
    ///
    /// Task and opcode values are 32-bit; keyword values are 64-bit bit masks. A value's name is
    /// either a direct name string (`name_prop`) or a message id to format; the direct name wins.
    fn name_table(
        metadata: &OwnedEvtHandle,
        array_prop: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        value_prop: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        name_prop: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        message_id_prop: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        value_is_u64: bool,
    ) -> BTreeMap<String, String> {
        let mut table = BTreeMap::new();
        let Some(array) = handle_property(metadata, array_prop) else {
            return table;
        };
        let mut size = 0u32;
        if unsafe { EvtGetObjectArraySize(array.raw().0, &mut size) }.is_err() {
            return table;
        }
        for index in 0..size {
            let value = if value_is_u64 {
                object_property_u64(array.raw().0, value_prop, index).map(|v| v.to_string())
            } else {
                object_property_u32(array.raw().0, value_prop, index).map(|v| v.to_string())
            };
            let Some(value) = value else { continue };

            let direct = object_property_string(array.raw().0, name_prop, index)
                .filter(|name| !name.trim().is_empty());
            let name = direct.or_else(|| {
                let message_id = object_property_u32(array.raw().0, message_id_prop, index)?;
                (message_id != u32::MAX).then(|| ())?;
                format_message(metadata.raw(), message_id, EvtFormatMessageId.0)
            });
            if let Some(name) = name {
                table.insert(value, name);
            }
        }
        table
    }

    /// Reads an `EVT_HANDLE`-valued publisher metadata property (an object array).
    fn handle_property(
        metadata: &OwnedEvtHandle,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    ) -> Option<OwnedEvtHandle> {
        let mut variant = EVT_VARIANT::default();
        let mut used = 0u32;
        let result = unsafe {
            EvtGetPublisherMetadataProperty(
                metadata.raw(),
                property,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                Some(&mut variant),
                &mut used,
            )
        };
        if result.is_err() || variant.Type != EvtVarTypeEvtHandle.0 as u32 {
            return None;
        }
        Some(OwnedEvtHandle::new(unsafe { variant.Anonymous.EvtHandleVal }))
    }

    /// Reads a `u32` event metadata property.
    fn event_property_u32(
        event: EVT_HANDLE,
        property: EVT_EVENT_METADATA_PROPERTY_ID,
    ) -> Option<u32> {
        let mut variant = EVT_VARIANT::default();
        let mut used = 0u32;
        let result = unsafe {
            EvtGetEventMetadataProperty(
                event,
                property,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                Some(&mut variant),
                &mut used,
            )
        };
        if result.is_err() || variant.Type != EvtVarTypeUInt32.0 as u32 {
            return None;
        }
        Some(unsafe { variant.Anonymous.UInt32Val })
    }

    /// Reads a `u64` event metadata property (the keyword mask).
    fn event_property_u64(
        event: EVT_HANDLE,
        property: EVT_EVENT_METADATA_PROPERTY_ID,
    ) -> Option<u64> {
        let mut variant = EVT_VARIANT::default();
        let mut used = 0u32;
        let result = unsafe {
            EvtGetEventMetadataProperty(
                event,
                property,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                Some(&mut variant),
                &mut used,
            )
        };
        if result.is_err() || variant.Type != EvtVarTypeUInt64.0 as u32 {
            return None;
        }
        Some(unsafe { variant.Anonymous.UInt64Val })
    }

    /// Reads a string event metadata property (the manifest template).
    fn event_property_string(
        event: EVT_HANDLE,
        property: EVT_EVENT_METADATA_PROPERTY_ID,
    ) -> Option<String> {
        let mut used = 0u32;
        unsafe {
            let _ = EvtGetEventMetadataProperty(event, property, 0, 0, None, &mut used);
        }
        if used == 0 {
            return None;
        }
        let mut buffer = vec![0u8; used as usize];
        let variant = buffer.as_mut_ptr() as *mut EVT_VARIANT;
        let result =
            unsafe { EvtGetEventMetadataProperty(event, property, 0, used, Some(variant), &mut used) };
        if result.is_err() || unsafe { (*variant).Type } != EvtVarTypeString.0 as u32 {
            return None;
        }
        unsafe { (*variant).Anonymous.StringVal.to_string() }.ok()
    }

    /// Reads a `u32` value from one element of an object array.
    fn object_property_u32(
        array: isize,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        index: u32,
    ) -> Option<u32> {
        let mut variant = EVT_VARIANT::default();
        let mut used = 0u32;
        let result = unsafe {
            EvtGetObjectArrayProperty(
                array,
                property.0 as u32,
                index,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                Some(&mut variant),
                &mut used,
            )
        };
        if result.is_err() || variant.Type != EvtVarTypeUInt32.0 as u32 {
            return None;
        }
        Some(unsafe { variant.Anonymous.UInt32Val })
    }

    /// Reads a `u64` value from one element of an object array.
    fn object_property_u64(
        array: isize,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        index: u32,
    ) -> Option<u64> {
        let mut variant = EVT_VARIANT::default();
        let mut used = 0u32;
        let result = unsafe {
            EvtGetObjectArrayProperty(
                array,
                property.0 as u32,
                index,
                0,
                std::mem::size_of::<EVT_VARIANT>() as u32,
                Some(&mut variant),
                &mut used,
            )
        };
        if result.is_err() || variant.Type != EvtVarTypeUInt64.0 as u32 {
            return None;
        }
        Some(unsafe { variant.Anonymous.UInt64Val })
    }

    /// Reads a string from one element of an object array.
    fn object_property_string(
        array: isize,
        property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
        index: u32,
    ) -> Option<String> {
        let mut used = 0u32;
        unsafe {
            let _ = EvtGetObjectArrayProperty(array, property.0 as u32, index, 0, 0, None, &mut used);
        }
        if used == 0 {
            return None;
        }
        let mut buffer = vec![0u8; used as usize];
        let variant = buffer.as_mut_ptr() as *mut EVT_VARIANT;
        let result = unsafe {
            EvtGetObjectArrayProperty(array, property.0 as u32, index, 0, used, Some(variant), &mut used)
        };
        if result.is_err() || unsafe { (*variant).Type } != EvtVarTypeString.0 as u32 {
            return None;
        }
        unsafe { (*variant).Anonymous.StringVal.to_string() }.ok()
    }

    /// Formats one message by id, returning the template with `%n` markers left in place.
    fn format_message(metadata: EVT_HANDLE, message_id: u32, flags: u32) -> Option<String> {
        let mut used = 0u32;
        let mut buffer = vec![0u16; 2048];
        loop {
            match unsafe {
                EvtFormatMessage(
                    Some(metadata),
                    None,
                    message_id,
                    None,
                    flags,
                    Some(buffer.as_mut_slice()),
                    &mut used,
                )
            } {
                Ok(()) => {
                    let text = String::from_utf16_lossy(&buffer[..used as usize]);
                    let text = text.trim_end_matches('\0').trim();
                    return (!text.is_empty()).then_some(text.to_string());
                }
                Err(error) if win32_code(&error) == 122 => {
                    buffer.resize(used.max(buffer.len() as u32 * 2) as usize, 0);
                }
                Err(_) => return None,
            }
        }
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        (error.code().0 & 0xFFFF) as u32
    }
}
