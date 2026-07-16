#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEventLogError {
    pub code: Option<u32>,
    pub message: String,
}

impl std::fmt::Display for LiveEventLogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LiveEventLogError {}

pub const MAX_LIVE_EVENT_XML_BYTES: usize = 512 * 1024;
pub const MAX_LIVE_EVENT_MESSAGE_BYTES: usize = 256 * 1024;
pub const MAX_LIVE_EVENT_CHANNEL_BYTES: usize = 16 * 1024 * 1024;

#[cfg(any(target_os = "windows", test))]
fn event_size_limit_error(kind: &str, max_bytes: usize) -> LiveEventLogError {
    LiveEventLogError {
        code: None,
        message: format!("Windows Event Log {kind} exceeded the {max_bytes}-byte size limit"),
    }
}

#[cfg(any(target_os = "windows", test))]
fn next_utf16_buffer_len(
    current_units: usize,
    required_bytes: u32,
    max_bytes: usize,
) -> Result<usize, LiveEventLogError> {
    let required_bytes = required_bytes as usize;
    if required_bytes > max_bytes {
        return Err(event_size_limit_error("record", max_bytes));
    }
    let max_units = max_bytes / std::mem::size_of::<u16>();
    let required_units = required_bytes.div_ceil(std::mem::size_of::<u16>());
    let next_units = required_units
        .max(current_units.saturating_mul(2))
        .min(max_units);
    if next_units <= current_units {
        return Err(event_size_limit_error("record", max_bytes));
    }
    Ok(next_units)
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct LiveEventByteBudget {
    max_bytes: usize,
    retained_bytes: usize,
}

#[cfg(any(target_os = "windows", test))]
impl LiveEventByteBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            retained_bytes: 0,
        }
    }

    fn try_retain(&mut self, xml_bytes: usize, message_bytes: usize) -> bool {
        let record_bytes = xml_bytes.saturating_add(message_bytes);
        if record_bytes > self.max_bytes.saturating_sub(self.retained_bytes) {
            return false;
        }
        self.retained_bytes += record_bytes;
        true
    }

    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_event_buffer_growth_rejects_required_bytes_above_the_cap() {
        assert_eq!(
            next_utf16_buffer_len(8_192, 32 * 1024, MAX_LIVE_EVENT_XML_BYTES)
                .expect("bounded XML growth"),
            16_384
        );

        let error = next_utf16_buffer_len(
            8_192,
            MAX_LIVE_EVENT_XML_BYTES as u32 + 2,
            MAX_LIVE_EVENT_XML_BYTES,
        )
        .expect_err("oversized XML must be rejected before Vec::resize");
        assert!(error.message.contains("size limit"));

        let error = next_utf16_buffer_len(
            MAX_LIVE_EVENT_XML_BYTES / std::mem::size_of::<u16>(),
            MAX_LIVE_EVENT_XML_BYTES as u32,
            MAX_LIVE_EVENT_XML_BYTES,
        )
        .expect_err("an insufficient-buffer retry must always make bounded progress");
        assert!(error.message.contains("size limit"));
    }

    #[test]
    fn live_event_channel_budget_rejects_records_before_retained_bytes_exceed_cap() {
        let mut budget = LiveEventByteBudget::new(10);
        assert!(budget.try_retain(6, 4));
        assert!(!budget.try_retain(1, 0));
        assert_eq!(budget.retained_bytes(), 10);
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::OnceLock;

    use regex::Regex;
    use windows::core::{Error, HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext, EvtOpenPublisherMetadata,
        EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
        EVT_HANDLE,
    };

    fn provider_re() -> &'static Regex {
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| {
            Regex::new(r#"<Provider[^>]*Name=['\"]([^'\"]+)['\"]"#)
                .expect("provider regex must compile")
        })
    }

    #[derive(Debug, Clone)]
    pub struct LiveEventRecord {
        pub xml: String,
        pub rendered_message: Option<String>,
        pub source_file: String,
    }

    #[derive(Debug, Clone)]
    pub struct LiveChannelQueryResult {
        pub channel_path: String,
        pub source_file: String,
        pub records: Vec<LiveEventRecord>,
        pub partial_detail: Option<String>,
    }

    #[derive(Debug)]
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

    pub fn query_live_channel(
        channel: &str,
        entry_limit: usize,
    ) -> Result<LiveChannelQueryResult, super::LiveEventLogError> {
        query_live_channel_with_xpath(channel, "*", entry_limit)
    }

    pub fn query_live_channel_with_xpath(
        channel: &str,
        xpath: &str,
        entry_limit: usize,
    ) -> Result<LiveChannelQueryResult, super::LiveEventLogError> {
        let channel_string = HSTRING::from(channel);
        let query_string = HSTRING::from(xpath);
        let source_file = format!("live-event-log/{}.evtx", sanitize_channel_name(channel));
        let query = unsafe {
            EvtQuery(
                None,
                &channel_string,
                &query_string,
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
        }
        .map_err(format_windows_error)?;
        let query = OwnedEvtHandle::new(query);

        let mut records = Vec::new();
        let mut publisher_metadata = HashMap::<String, Option<OwnedEvtHandle>>::new();
        let mut byte_budget = super::LiveEventByteBudget::new(super::MAX_LIVE_EVENT_CHANNEL_BYTES);
        let mut partial_detail = None;

        'query: while records.len() < entry_limit {
            let mut raw_handles = [0isize; 16];
            let mut returned = 0u32;

            match unsafe { EvtNext(query.raw(), &mut raw_handles, 0, 0, &mut returned) } {
                Ok(()) => {}
                Err(error) => {
                    if is_no_more_items(&error) {
                        break;
                    }

                    return Err(format_windows_error(error));
                }
            }

            if returned == 0 {
                break;
            }

            let event_handles = raw_handles
                .into_iter()
                .take(returned as usize)
                .map(|raw_handle| OwnedEvtHandle::new(EVT_HANDLE(raw_handle)))
                .collect::<Vec<_>>();
            for event_handle in event_handles {
                if records.len() >= entry_limit {
                    break;
                }

                let xml = match render_event_xml(event_handle.raw()) {
                    Ok(xml) => xml,
                    Err(error) if error.code.is_none() => {
                        partial_detail = Some(error.message);
                        break 'query;
                    }
                    Err(error) => return Err(error),
                };
                let provider_name = extract_provider_name(&xml);
                let rendered_message = if let Some(provider) = provider_name.as_deref() {
                    match format_event_message(
                        event_handle.raw(),
                        provider,
                        &mut publisher_metadata,
                    ) {
                        Ok(message) => message,
                        Err(error) if error.code.is_none() => {
                            partial_detail = Some(error.message);
                            break 'query;
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                };
                if !byte_budget
                    .try_retain(xml.len(), rendered_message.as_ref().map_or(0, String::len))
                {
                    partial_detail = Some(format!(
                        "Windows Event Log channel exceeded the {}-byte retained-data limit",
                        super::MAX_LIVE_EVENT_CHANNEL_BYTES
                    ));
                    break 'query;
                }

                records.push(LiveEventRecord {
                    xml,
                    rendered_message,
                    source_file: source_file.clone(),
                });
            }
        }

        Ok(LiveChannelQueryResult {
            channel_path: channel.to_string(),
            source_file,
            records,
            partial_detail,
        })
    }

    fn render_event_xml(event_handle: EVT_HANDLE) -> Result<String, super::LiveEventLogError> {
        let mut buffer_used = 0u32;
        let mut property_count = 0u32;
        // 16 KB initial buffer — Sysmon events with long command lines and
        // hashes can easily exceed the previous 4 KB default.
        let mut buffer = vec![0u16; 8192];

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
                    if buffer_used as usize > super::MAX_LIVE_EVENT_XML_BYTES {
                        return Err(super::event_size_limit_error(
                            "XML",
                            super::MAX_LIVE_EVENT_XML_BYTES,
                        ));
                    }
                    let utf16_len =
                        (buffer_used as usize / std::mem::size_of::<u16>()).saturating_sub(1);
                    return Ok(String::from_utf16_lossy(&buffer[..utf16_len]));
                }
                Err(error) if is_insufficient_buffer(&error) => {
                    let next_len = super::next_utf16_buffer_len(
                        buffer.len(),
                        buffer_used,
                        super::MAX_LIVE_EVENT_XML_BYTES,
                    )?;
                    buffer.resize(next_len, 0);
                }
                Err(error) => return Err(format_windows_error(error)),
            }
        }
    }

    fn format_event_message(
        event_handle: EVT_HANDLE,
        provider_name: &str,
        cache: &mut HashMap<String, Option<OwnedEvtHandle>>,
    ) -> Result<Option<String>, super::LiveEventLogError> {
        if !cache.contains_key(provider_name) {
            let provider = HSTRING::from(provider_name);
            let metadata =
                unsafe { EvtOpenPublisherMetadata(None, &provider, PCWSTR::null(), 0, 0) }
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
                    Some(metadata.raw()),
                    Some(event_handle),
                    0,
                    None,
                    EvtFormatMessageEvent.0,
                    Some(buffer.as_mut_slice()),
                    &mut buffer_used,
                )
            } {
                Ok(()) => {
                    if buffer_used as usize * std::mem::size_of::<u16>()
                        > super::MAX_LIVE_EVENT_MESSAGE_BYTES
                    {
                        return Err(super::event_size_limit_error(
                            "message",
                            super::MAX_LIVE_EVENT_MESSAGE_BYTES,
                        ));
                    }
                    let utf16_len = buffer_used.saturating_sub(1) as usize;
                    let rendered = String::from_utf16_lossy(&buffer[..utf16_len])
                        .trim()
                        .to_string();
                    return Ok((!rendered.is_empty()).then_some(rendered));
                }
                Err(error) if is_insufficient_buffer(&error) => {
                    let required_bytes = buffer_used.saturating_mul(2);
                    let next_len = super::next_utf16_buffer_len(
                        buffer.len(),
                        required_bytes,
                        super::MAX_LIVE_EVENT_MESSAGE_BYTES,
                    )?;
                    buffer.resize(next_len, 0);
                }
                Err(error) if is_not_found(&error) || is_message_not_found(&error) => {
                    return Ok(None);
                }
                Err(error) => return Err(format_windows_error(error)),
            }
        }
    }

    fn extract_provider_name(xml: &str) -> Option<String> {
        provider_re()
            .captures(xml)
            .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string()))
    }

    fn sanitize_channel_name(channel: &str) -> String {
        channel
            .chars()
            .map(|value| match value {
                '/' | '\\' | ':' | ' ' => '-',
                other => other,
            })
            .collect()
    }

    fn format_windows_error(error: Error) -> super::LiveEventLogError {
        let message = error.message();
        super::LiveEventLogError {
            code: Some(error.code().0 as u32),
            message: if message.trim().is_empty() {
                format!(
                    "Windows Event Log API error 0x{:08x}",
                    error.code().0 as u32
                )
            } else {
                message.trim().to_string()
            },
        }
    }

    /// Check if an error matches a Win32 error code.
    /// Handles both raw Win32 codes and HRESULT-wrapped forms
    /// (the Windows crate may return either depending on the API).
    fn is_win32_error(error: &Error, win32_code: u32) -> bool {
        let raw = error.code().0 as u32;
        // Direct Win32 code comparison
        if raw == win32_code {
            return true;
        }
        // HRESULT_FROM_WIN32: 0x80070000 | win32_code
        raw == (0x8007_0000 | win32_code)
    }

    fn is_insufficient_buffer(error: &Error) -> bool {
        is_win32_error(error, 122) // ERROR_INSUFFICIENT_BUFFER
    }

    fn is_no_more_items(error: &Error) -> bool {
        is_win32_error(error, 259) // ERROR_NO_MORE_ITEMS
    }

    fn is_not_found(error: &Error) -> bool {
        is_win32_error(error, 1168) // ERROR_NOT_FOUND
    }

    fn is_message_not_found(error: &Error) -> bool {
        is_win32_error(error, 15027) // ERROR_EVT_MESSAGE_NOT_FOUND
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{
    query_live_channel, query_live_channel_with_xpath, LiveChannelQueryResult, LiveEventRecord,
};

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone)]
pub struct LiveEventRecord {
    pub xml: String,
    pub rendered_message: Option<String>,
    pub source_file: String,
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone)]
pub struct LiveChannelQueryResult {
    pub channel_path: String,
    pub source_file: String,
    pub records: Vec<LiveEventRecord>,
    pub partial_detail: Option<String>,
}

#[cfg(not(target_os = "windows"))]
pub fn query_live_channel(
    _channel: &str,
    _entry_limit: usize,
) -> Result<LiveChannelQueryResult, LiveEventLogError> {
    Err(LiveEventLogError {
        code: None,
        message: "Live Windows Event Log queries are only supported on Windows".to_string(),
    })
}

#[cfg(not(target_os = "windows"))]
pub fn query_live_channel_with_xpath(
    _channel: &str,
    _xpath: &str,
    _entry_limit: usize,
) -> Result<LiveChannelQueryResult, LiveEventLogError> {
    Err(LiveEventLogError {
        code: None,
        message: "Live Windows Event Log queries are only supported on Windows".to_string(),
    })
}
