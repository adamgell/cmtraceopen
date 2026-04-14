#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::sync::OnceLock;

    use regex::Regex;
    use windows::core::{Error, HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
        EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderEventXml,
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
    ) -> Result<LiveChannelQueryResult, crate::error::AppError> {
        let channel_string = HSTRING::from(channel);
        let query_string = HSTRING::from("*");
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

        while records.len() < entry_limit {
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

            for raw_handle in raw_handles.into_iter().take(returned as usize) {
                if records.len() >= entry_limit {
                    break;
                }

                let event_handle = OwnedEvtHandle::new(EVT_HANDLE(raw_handle));
                let xml = render_event_xml(event_handle.raw()).map_err(format_windows_error)?;
                let provider_name = extract_provider_name(&xml);
                let rendered_message = provider_name.as_deref().and_then(|provider| {
                    format_event_message(
                        event_handle.raw(),
                        provider,
                        &mut publisher_metadata,
                    )
                    .ok()
                    .flatten()
                });

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
        })
    }

    fn render_event_xml(event_handle: EVT_HANDLE) -> Result<String, Error> {
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
                    let utf16_len = (buffer_used as usize / std::mem::size_of::<u16>())
                        .saturating_sub(1);
                    return Ok(String::from_utf16_lossy(&buffer[..utf16_len]));
                }
                Err(error) if is_insufficient_buffer(&error) => {
                    let next_len = (buffer_used as usize / std::mem::size_of::<u16>())
                        .max(buffer.len() * 2);
                    buffer.resize(next_len, 0);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn format_event_message(
        event_handle: EVT_HANDLE,
        provider_name: &str,
        cache: &mut HashMap<String, Option<OwnedEvtHandle>>,
    ) -> Result<Option<String>, Error> {
        if !cache.contains_key(provider_name) {
            let provider = HSTRING::from(provider_name);
            let metadata = unsafe {
                EvtOpenPublisherMetadata(None, &provider, PCWSTR::null(), 0, 0)
            }
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
                    let utf16_len = buffer_used.saturating_sub(1) as usize;
                    let rendered = String::from_utf16_lossy(&buffer[..utf16_len])
                        .trim()
                        .to_string();
                    return Ok((!rendered.is_empty()).then_some(rendered));
                }
                Err(error) if is_insufficient_buffer(&error) => {
                    buffer.resize(buffer_used.max(buffer.len() as u32 * 2) as usize, 0);
                }
                Err(error) if is_not_found(&error) || is_message_not_found(&error) => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
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

    fn format_windows_error(error: Error) -> crate::error::AppError {
        let message = error.message();
        if message.trim().is_empty() {
            crate::error::AppError::Internal(format!("Windows Event Log API error 0x{:08x}", error.code().0 as u32))
        } else {
            crate::error::AppError::Internal(message.trim().to_string())
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
pub use windows_impl::{query_live_channel, LiveChannelQueryResult, LiveEventRecord};

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
}

#[cfg(not(target_os = "windows"))]
pub fn query_live_channel(
    _channel: &str,
    _entry_limit: usize,
) -> Result<LiveChannelQueryResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported("Live Windows Event Log queries are only supported on Windows".to_string()))
}