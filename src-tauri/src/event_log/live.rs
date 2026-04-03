use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::OnceLock;

use regex::Regex;

use super::models::{ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxRecord};

#[cfg(target_os = "windows")]
use windows::core::{Error, HSTRING, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtRender, EvtRenderEventXml,
};

// ── RAII handle wrapper ─────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
struct OwnedEvtHandle(EVT_HANDLE);

#[cfg(target_os = "windows")]
impl OwnedEvtHandle {
    fn new(handle: EVT_HANDLE) -> Self {
        Self(handle)
    }
    fn raw(&self) -> EVT_HANDLE {
        self.0
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedEvtHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all registered Windows Event Log channels on the local system.
#[cfg(target_os = "windows")]
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    // Use raw wevtapi.dll FFI — the high-level windows crate wrapper may not
    // pass NULL correctly for the local-computer session handle.
    #[link(name = "wevtapi")]
    extern "system" {
        fn EvtOpenChannelEnum(session: isize, flags: u32) -> isize;
        fn EvtNextChannelPath(
            channelenum: isize,
            channelpathbuffersize: u32,
            channelpathbuffer: *mut u16,
            channelpathbufferused: *mut u32,
        ) -> i32;
    }

    let raw_handle = unsafe { EvtOpenChannelEnum(0, 0) };
    if raw_handle == 0 {
        return Err("EvtOpenChannelEnum returned null handle".to_string());
    }

    let mut channels = Vec::new();
    let mut buffer = vec![0u16; 512];

    loop {
        let mut used = 0u32;
        let ok = unsafe {
            EvtNextChannelPath(
                raw_handle,
                buffer.len() as u32,
                buffer.as_mut_ptr(),
                &mut used,
            )
        };

        if ok != 0 {
            let len = used.saturating_sub(1) as usize;
            let name = String::from_utf16_lossy(&buffer[..len]);
            channels.push(EvtxChannelInfo {
                name,
                event_count: 0,
                source_type: ChannelSourceType::Live,
            });
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if err == 259 {
                // ERROR_NO_MORE_ITEMS — done
                break;
            } else if err == 122 {
                // ERROR_INSUFFICIENT_BUFFER — resize and retry
                buffer.resize(used as usize, 0);
            } else {
                unsafe { let _ = EvtClose(EVT_HANDLE(raw_handle)); }
                return Err(format!("EvtNextChannelPath failed: error {err}"));
            }
        }
    }

    unsafe { let _ = EvtClose(EVT_HANDLE(raw_handle)); }

    channels.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(channels)
}

/// Query events from a live Windows Event Log channel.
///
/// Returns newest events first, capped at `max_events` (default 1000).
#[cfg(target_os = "windows")]
pub fn query_channel(
    channel: &str,
    max_events: Option<u64>,
) -> Result<Vec<EvtxRecord>, String> {
    query_channel_with_progress(channel, max_events, |_, _| {})
}

/// Query with a progress callback: `on_progress(fetched_so_far, total_estimate)`.
#[cfg(target_os = "windows")]
pub fn query_channel_with_progress(
    channel: &str,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
) -> Result<Vec<EvtxRecord>, String> {
    let limit = max_events.map(|n| n as usize).unwrap_or(usize::MAX);
    let channel_hstring = HSTRING::from(channel);
    let query_string = HSTRING::from("*");

    let query_handle = unsafe {
        EvtQuery(
            None,
            &channel_hstring,
            &query_string,
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }
    .map_err(|e| format_error(&format!("EvtQuery({channel})"), &e))?;
    let query_handle = OwnedEvtHandle::new(query_handle);
    log::info!("event=evtx_live_query channel=\"{channel}\" limit={limit}");

    let mut records = Vec::new();
    let mut publisher_metadata = HashMap::<String, Option<OwnedEvtHandle>>::new();

    while records.len() < limit {
        let mut raw_handles = [0isize; 16];
        let mut returned = 0u32;

        match unsafe { EvtNext(query_handle.raw(), &mut raw_handles, 0, 0, &mut returned) } {
            Ok(()) => {}
            Err(e) => {
                if !is_no_more_items(&e) {
                    eprintln!("[evtx] EvtNext error: code=0x{:08x} w32={} msg=\"{}\"",
                        e.code().0 as u32, win32_code(&e), e.message());
                }
                break;
            }
        }

        if returned == 0 {
            break;
        }

        for raw_handle in raw_handles.into_iter().take(returned as usize) {
            if records.len() >= limit {
                // Close remaining handles we won't use
                unsafe { let _ = EvtClose(EVT_HANDLE(raw_handle)); }
                continue;
            }

            let event_handle = OwnedEvtHandle::new(EVT_HANDLE(raw_handle));
            let xml = render_event_xml(event_handle.raw())
                .map_err(|e| format_error("EvtRender", &e))?;

            let provider_name = extract_xml_attr(&xml, "Provider", "Name");

            // Try to get a formatted message via EvtFormatMessage
            let rendered_message = provider_name.as_deref().and_then(|provider| {
                format_event_message(event_handle.raw(), provider, &mut publisher_metadata)
                    .ok()
                    .flatten()
            });

            if let Some(record) = parse_xml_to_record(&xml, channel, rendered_message.as_deref())
            {
                records.push(record);
                // Report progress every 100 records
                if records.len() % 100 == 0 {
                    on_progress(records.len(), None);
                }
            } else if records.is_empty() {
                // Log the first unparseable XML so we can debug the format
                log::warn!("event=evtx_parse_failed channel=\"{channel}\" xml_prefix=\"{}\"",
                    &xml[..xml.len().min(300)]);
            }
        }
    }

    log::info!("event=evtx_live_query_done channel=\"{channel}\" records={}", records.len());
    Ok(records)
}

// ── Non-Windows stubs ───────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_with_progress(
    _channel: &str,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
) -> Result<Vec<EvtxRecord>, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel(
    _channel: &str,
    _max_events: Option<u64>,
) -> Result<Vec<EvtxRecord>, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

// ── Win32 helpers (Windows only) ────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn render_event_xml(event_handle: EVT_HANDLE) -> Result<String, Error> {
    let mut buffer_used = 0u32;
    let mut property_count = 0u32;
    let mut buffer = vec![0u16; 4096];

    loop {
        match unsafe {
            EvtRender(
                None,
                event_handle,
                EvtRenderEventXml.0,
                (buffer.len() * std::mem::size_of::<u16>()) as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut buffer_used,
                &mut property_count,
            )
        } {
            Ok(()) => {
                let utf16_len =
                    (buffer_used as usize / std::mem::size_of::<u16>()).saturating_sub(1);
                return Ok(String::from_utf16_lossy(&buffer[..utf16_len]));
            }
            Err(e) if is_insufficient_buffer(&e) => {
                let next_len =
                    (buffer_used as usize / std::mem::size_of::<u16>()).max(buffer.len() * 2);
                buffer.resize(next_len, 0);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn format_event_message(
    event_handle: EVT_HANDLE,
    provider_name: &str,
    cache: &mut HashMap<String, Option<OwnedEvtHandle>>,
) -> Result<Option<String>, Error> {
    if !cache.contains_key(provider_name) {
        let provider = HSTRING::from(provider_name);
        let metadata =
            unsafe { EvtOpenPublisherMetadata(EVT_HANDLE::default(), &provider, PCWSTR::null(), 0, 0) }
                .ok()
                .map(OwnedEvtHandle::new);
        cache.insert(provider_name.to_string(), metadata);
    }

    let Some(Some(metadata)) = cache.get(provider_name) else {
        return Ok(None);
    };

    let mut buffer_used = 0u32;
    let mut buffer = vec![0u16; 2048];

    loop {
        match unsafe {
            EvtFormatMessage(
                metadata.raw(),
                event_handle,
                0,
                None,
                EvtFormatMessageEvent.0,
                Some(buffer.as_mut_slice()),
                &mut buffer_used,
            )
        } {
            Ok(()) => {
                let utf16_len = buffer_used.saturating_sub(1) as usize;
                let rendered = String::from_utf16_lossy(&buffer[..utf16_len])
                    .trim()
                    .to_string();
                return Ok((!rendered.is_empty()).then_some(rendered));
            }
            Err(e) if is_insufficient_buffer(&e) => {
                buffer.resize(buffer_used.max(buffer.len() as u32 * 2) as usize, 0);
            }
            Err(e) if is_not_found(&e) || is_message_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

// ── XML parsing helpers ─────────────────────────────────────────────────────

/// Parse rendered event XML into an EvtxRecord.
fn parse_xml_to_record(
    xml: &str,
    channel: &str,
    rendered_message: Option<&str>,
) -> Option<EvtxRecord> {
    let event_id_str = extract_xml_text(xml, "EventID").unwrap_or_default();
    let event_id: u32 = event_id_str.parse().unwrap_or(0);

    let level_str = extract_xml_text(xml, "Level").unwrap_or_default();
    let level_val: u8 = level_str.parse().unwrap_or(4);
    let level = EvtxLevel::from_level_value(level_val);

    let provider = extract_xml_attr(xml, "Provider", "Name").unwrap_or_default();
    let computer = extract_xml_text(xml, "Computer").unwrap_or_default();
    let event_record_id: u64 = extract_xml_text(xml, "EventRecordID")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let timestamp = extract_xml_attr(xml, "TimeCreated", "SystemTime").unwrap_or_default();
    let timestamp_epoch = parse_timestamp_to_epoch_ms(&timestamp);

    let event_data = extract_xml_event_data(xml);

    // Use rendered message if available, otherwise build summary from EventData
    let message = rendered_message
        .map(|s| s.to_string())
        .unwrap_or_else(|| build_event_data_summary(&event_data));

    Some(EvtxRecord {
        id: 0, // assigned by commands.rs after sorting
        event_record_id,
        timestamp,
        timestamp_epoch,
        provider,
        channel: channel.to_string(),
        event_id,
        level,
        computer,
        message,
        event_data,
        raw_xml: xml.to_string(),
        source_label: "Live".to_string(),
    })
}

/// Extract an attribute value from an XML tag.
/// e.g. `extract_xml_attr(xml, "Provider", "Name")` for `<Provider Name='...'>`
fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_start = xml.find(&format!("<{tag}"))?;
    let tag_end = xml[tag_start..].find('>')? + tag_start;
    let tag_content = &xml[tag_start..=tag_end];

    // Try both quote styles: Name='value' and Name="value"
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        if let Some(attr_start) = tag_content.find(&pattern) {
            let value_start = attr_start + pattern.len();
            if let Some(value_end) = tag_content[value_start..].find(quote) {
                return Some(tag_content[value_start..value_start + value_end].to_string());
            }
        }
    }
    None
}

/// Extract text content between XML tags.
/// e.g. `extract_xml_text(xml, "EventID")` for `<EventID>123</EventID>`
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let open_with_attrs = format!("<{tag} ");
    let close = format!("</{tag}>");

    // Try simple <Tag>value</Tag>
    if let Some(start) = xml.find(&open) {
        let value_start = start + open.len();
        if let Some(end) = xml[value_start..].find(&close) {
            return Some(xml[value_start..value_start + end].trim().to_string());
        }
    }

    // Try <Tag attr="...">value</Tag>
    if let Some(start) = xml.find(&open_with_attrs) {
        let after_tag = &xml[start..];
        let tag_close = after_tag.find('>')?;
        let value_start = start + tag_close + 1;
        if let Some(end) = xml[value_start..].find(&close) {
            return Some(xml[value_start..value_start + end].trim().to_string());
        }
    }

    None
}

/// Extract `<Data Name='key'>value</Data>` pairs from EventData section.
fn extract_xml_event_data(xml: &str) -> Vec<EvtxField> {
    fn data_name_re() -> &'static Regex {
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| {
            Regex::new(r#"<Data Name=['"](.*?)['"]>(.*?)</Data>"#).expect("data regex")
        })
    }

    data_name_re()
        .captures_iter(xml)
        .map(|cap| EvtxField {
            name: cap[1].to_string(),
            value: cap[2].to_string(),
        })
        .collect()
}

/// Build a summary message from EventData fields (fallback when EvtFormatMessage unavailable).
fn build_event_data_summary(fields: &[EvtxField]) -> String {
    fields
        .iter()
        .take(5)
        .map(|f| {
            let val = if f.value.len() > 80 {
                format!("{}...", &f.value[..77])
            } else {
                f.value.clone()
            };
            format!("{}: {val}", f.name)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Parse an ISO 8601 timestamp to epoch milliseconds.
fn parse_timestamp_to_epoch_ms(timestamp: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .or_else(|_| {
            // Windows timestamps may omit timezone, assume UTC
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|naive| naive.and_utc().fixed_offset())
        })
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

// ── Error helpers ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn format_error(context: &str, error: &Error) -> String {
    let msg = error.message();
    if msg.trim().is_empty() {
        format!("{context}: Windows error 0x{:08x}", error.code().0 as u32)
    } else {
        format!("{context}: {}", msg.trim())
    }
}

/// Extract the Win32 error code from an HRESULT or raw error code.
#[cfg(target_os = "windows")]
fn win32_code(error: &Error) -> u32 {
    (error.code().0 & 0xFFFF) as u32
}

#[cfg(target_os = "windows")]
fn is_insufficient_buffer(error: &Error) -> bool {
    win32_code(error) == 122
}

#[cfg(target_os = "windows")]
fn is_no_more_items(error: &Error) -> bool {
    win32_code(error) == 259
}

#[cfg(target_os = "windows")]
fn is_not_found(error: &Error) -> bool {
    win32_code(error) == 1168
}

#[cfg(target_os = "windows")]
fn is_message_not_found(error: &Error) -> bool {
    win32_code(error) == 15027
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;

    #[test]
    fn live_query_application() {
        let channels = enumerate_channels().expect("enumerate should work");
        println!("Total channels: {}", channels.len());
        let has_app = channels.iter().any(|c| c.name == "Application");
        println!("Has Application channel: {has_app}");

        let records = query_channel("Application", Some(3)).expect("query should work");
        println!("Application records: {}", records.len());
        for (i, r) in records.iter().enumerate() {
            println!("--- Record {i} ---");
            println!("  EventID: {}, Provider: {}, Level: {:?}", r.event_id, r.provider, r.level);
            println!("  Timestamp: {}", r.timestamp);
            println!("  Message: {}", &r.message[..r.message.len().min(100)]);
            println!("  XML prefix: {}", &r.raw_xml[..r.raw_xml.len().min(300)]);
        }
    }
}
