use std::collections::HashMap;
use std::ffi::c_void;

use super::event_node::{extract_event_data, extract_system_fields, parse_event_xml};
use super::models::{ChannelSourceType, EvtxChannelInfo, EvtxRecord};
use super::provider_db::ProviderStore;
use cmtraceopen_parser::event_query::{build_query, EventQueryFilter};
use cmtraceopen_parser::eventmap::MapRegistry;

#[cfg(target_os = "windows")]
use windows::core::{Error, HSTRING, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::{
    EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext, EvtOpenPublisherMetadata, EvtQuery,
    EvtQueryChannelPath, EvtQueryReverseDirection, EvtQueryTolerateQueryErrors, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

/// Event handles fetched per `EvtNext` call.
///
/// Each call is a round trip to the Event Log service, so this is the dominant cost of a scan.
/// FullEventLogView hardcodes 1, paying one round trip per event. The API accepts up to 1024;
/// 256 keeps the per-call array modest while cutting round trips by that factor.
#[cfg(target_os = "windows")]
const EVENT_FETCH_BATCH: usize = 256;

/// Smallest batch to fall back to before treating the channel as unreadable.
///
/// Some channels reject a 256-handle request with `RPC_S_INVALID_BOUND`. Measuring a full scan
/// found one doing exactly that, and the loop's response was to stop reading and return what it
/// already had as a complete result. Halving down to this floor reads the channel instead.
#[cfg(target_os = "windows")]
const MIN_FETCH_BATCH: usize = 8;

/// What one channel yielded, including why anything is missing from it.
///
/// The records used to be returned on their own, which left no way to say "this channel was read,
/// but not all of it". A partial read then reported as a complete one: the caller saw `Ok`, counted
/// the events, and showed a channel that looked fully loaded. Events that were never fetched are
/// indistinguishable on screen from events that do not exist.
pub struct ChannelScan {
    /// Records the caller did not take. Empty for a caller that streamed every batch away.
    pub records: Vec<EvtxRecord>,
    /// How many records this channel produced in total, whether or not the caller kept them.
    ///
    /// Separate from `records.len()` because a streaming caller empties that vector as it goes.
    /// Reporting the length instead would tell the frontend a fully read channel held no events,
    /// which is the same wrong answer as a channel that failed.
    pub delivered: usize,
    /// Operator-facing explanations of what is missing. Empty means the channel was read whole.
    pub gaps: Vec<String>,
}

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
                unsafe {
                    let _ = EvtClose(EVT_HANDLE(raw_handle));
                }
                return Err(format!("EvtNextChannelPath failed: error {err}"));
            }
        }
    }

    unsafe {
        let _ = EvtClose(EVT_HANDLE(raw_handle));
    }

    channels.sort_by_key(|c| c.name.to_lowercase());
    Ok(channels)
}

/// Query events from a live Windows Event Log channel.
///
/// Returns newest events first. `None` means no cap, which is what every caller in the application
/// passes; there is no default limit, and the comment claiming a default of 1000 described a
/// behaviour this function has not had. A cap that is documented but absent is worse than either,
/// because it invites callers to rely on a bound nothing enforces.
#[cfg(target_os = "windows")]
pub fn query_channel(
    channel: &str,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    query_channel_with_progress(channel, maps, providers, max_events, |_, _| {})
}

/// Queries a channel with server-side filtering.
///
/// The filter is compiled to XPath and evaluated by the service, so events that do not match are
/// never fetched, rendered, or transferred.
#[cfg(target_os = "windows")]
pub fn query_channel_filtered(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        |_, _| {},
        |_| {},
    )
}

/// Query with a progress callback: `on_progress(fetched_so_far, total_estimate)`.
#[cfg(target_os = "windows")]
pub fn query_channel_with_progress(
    channel: &str,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        &EventQueryFilter::default(),
        maps,
        providers,
        max_events,
        on_progress,
        |_| {},
    )
}

/// Queries a channel with server-side filtering, reporting progress as events arrive.
#[cfg(target_os = "windows")]
pub fn query_channel_filtered_with_progress(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    query_channel_inner(channel, filter, maps, providers, max_events, on_progress, |_| {})
}

/// Queries a channel, delivering each batch of records as it is read.
///
/// `on_batch` is handed every batch and is expected to take the records from it. Whatever it leaves
/// is returned in the [`ChannelScan`], so a caller that forgets to drain still gets correct results
/// rather than losing them; it simply holds the channel in memory as before.
#[cfg(target_os = "windows")]
pub fn query_channel_streamed(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
    on_batch: impl FnMut(&mut Vec<EvtxRecord>),
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        on_progress,
        on_batch,
    )
}

/// Reads a channel, handing each fetched batch to `on_batch` as it is built.
///
/// `on_batch` receives the batch by mutable reference and may take the records out of it. Whatever
/// it leaves behind is accumulated into the returned [`ChannelScan`]. That is the whole difference
/// between streaming and collecting: a caller that drains never holds more than one batch, and a
/// caller that ignores the argument gets the channel in one piece exactly as before.
///
/// The distinction matters because one channel dominates a scan. On a measured seven-day scan,
/// Security was 286,401 of 404,769 events and 191.8 seconds of 267, so a caller waiting for this
/// function to return waits three minutes with nothing to show.
#[cfg(target_os = "windows")]
fn query_channel_inner(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &ProviderStore,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
    mut on_batch: impl FnMut(&mut Vec<EvtxRecord>),
) -> Result<ChannelScan, String> {
    let limit = max_events.map(|n| n as usize).unwrap_or(usize::MAX);
    let channel_hstring = HSTRING::from(channel);
    // A filter that cannot be expressed is refused here rather than silently degraded to "*",
    // which would return everything and look like the filter simply matched a lot.
    let compiled = build_query(filter)
        .map_err(|error| format!("cannot compile event query for {channel}: {error}"))?;
    let query_string = HSTRING::from(compiled.as_str());

    let query_handle = unsafe {
        EvtQuery(
            None,
            &channel_hstring,
            &query_string,
            // TolerateQueryErrors keeps a scan alive when one part of a query cannot be evaluated,
            // for example a provider that is not registered on this machine. Without it a single
            // bad element aborts the whole channel and the result silently looks empty.
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0 | EvtQueryTolerateQueryErrors.0,
        )
    }
    .map_err(|e| format_error(&format!("EvtQuery({channel})"), &e))?;
    let query_handle = OwnedEvtHandle::new(query_handle);
    log::info!("event=evtx_live_query channel=\"{channel}\" limit={limit}");

    let mut records = Vec::new();
    let mut publisher_metadata = HashMap::<String, Option<OwnedEvtHandle>>::new();
    let mut unparsable = 0usize;
    let mut unrenderable = 0usize;

    let mut gaps = Vec::new();
    let mut batch = EVENT_FETCH_BATCH;
    // Counted separately from `records`, which a streaming caller empties as it goes. Using the
    // length of a vector the caller is allowed to drain would restart the limit at zero after every
    // batch and read the channel forever.
    let mut produced = 0usize;

    while produced < limit {
        let mut raw_handles = [0isize; EVENT_FETCH_BATCH];
        let mut returned = 0u32;

        let fetched = unsafe {
            EvtNext(
                query_handle.raw(),
                &mut raw_handles[..batch],
                0,
                0,
                &mut returned,
            )
        };

        if let Err(error) = fetched {
            // How to respond is decided in `super::fetch`, where it is tested on every platform.
            // Everything else in this loop is Windows-only, so a rule encoded here is a rule CI
            // cannot check on any runner.
            match super::fetch::classify_fetch_failure(win32_code(&error), batch, MIN_FETCH_BATCH) {
                super::fetch::FetchFailure::Exhausted => break,
                super::fetch::FetchFailure::RetryWith(smaller) => {
                    batch = smaller;
                    log::info!(
                        "event=evtx_batch_reduced channel=\"{channel}\" batch={batch} \
                         reason=\"the service rejected the previous batch size\""
                    );
                    continue;
                }
                super::fetch::FetchFailure::Truncated => {
                    // Recorded as a gap, not only logged. The records already read are still
                    // returned because they are real, but the channel must not be presented as
                    // complete when the rest of it was never fetched.
                    log::warn!(
                        "event=evtx_next_failed channel=\"{channel}\" batch={batch} \
                         w32={} code=0x{:08x}",
                        win32_code(&error),
                        error.code().0 as u32
                    );
                    gaps.push(format!(
                        "{channel}: stopped after {} events, the channel could not be read further ({}, 0x{:08x})",
                        produced,
                        error.message().trim(),
                        error.code().0 as u32
                    ));
                    break;
                }
            }
        }

        if returned == 0 {
            break;
        }

        // Built per fetch rather than appended straight to `records`, so the caller can take each
        // batch as it is produced. A caller that takes them holds nothing here, which is what keeps
        // a channel the size of Security from occupying its whole result set before anything is
        // shown.
        let mut batch_records: Vec<EvtxRecord> = Vec::new();

        for raw_handle in raw_handles.into_iter().take(returned as usize) {
            if produced + batch_records.len() >= limit {
                // Close remaining handles we won't use
                unsafe {
                    let _ = EvtClose(EVT_HANDLE(raw_handle));
                }
                continue;
            }

            let event_handle = OwnedEvtHandle::new(EVT_HANDLE(raw_handle));
            // A handle that fails to render is counted, not fatal. Propagating it here returned
            // Err for the whole channel and threw away every record already read, which the caller
            // then reported as a channel with no events.
            let xml = match render_event_xml(event_handle.raw()) {
                Ok(xml) => xml,
                Err(error) => {
                    unrenderable += 1;
                    if unrenderable == 1 {
                        log::warn!(
                            "event=evtx_render_failed channel=\"{channel}\" error=\"{}\"",
                            format_error("EvtRender", &error)
                        );
                    }
                    continue;
                }
            };

            // Parsed once here and handed to the record builder. The provider has to be known
            // before the record exists, because it names the publisher whose message template the
            // service is asked to render, and parsing a second time to learn the rest would double
            // the cost of the hottest loop in this view.
            let parsed = match parse_event_xml(&xml) {
                Ok(parsed) => parsed,
                Err(error) => {
                    unparsable += 1;
                    if unparsable == 1 {
                        // Sliced by character rather than by byte. A byte cut that lands inside a
                        // multi-byte character panics, and this XML carries account names and paths
                        // that are routinely not ASCII.
                        let prefix: String = xml.chars().take(300).collect();
                        log::warn!(
                            "event=evtx_parse_failed channel=\"{channel}\" error=\"{error}\" xml_prefix=\"{prefix}\""
                        );
                    }
                    continue;
                }
            };
            let system = extract_system_fields(&parsed);

            // A loaded provider database answers first, because it costs no round trip. When it has
            // no answer the message is rendered by the service, one RPC per event, which a measured
            // scan found to be the dominant cost of the whole live path.
            let rendered_message = system.provider.as_deref().and_then(|provider| {
                let insertions = extract_event_data(&parsed).insertions;
                super::parser::describe_event(
                    providers,
                    provider,
                    system.event_id.unwrap_or(0),
                    &insertions,
                )
                .or_else(|| {
                    format_event_message(event_handle.raw(), provider, &mut publisher_metadata)
                        .ok()
                        .flatten()
                })
            });

            batch_records.push(super::rendered::record_from_parts(
                &parsed,
                system,
                &xml,
                channel,
                maps,
                rendered_message.as_deref(),
            ));
        }

        produced += batch_records.len();
        on_progress(produced, None);

        // The caller sees the batch before anything else happens to it. Draining it here is what
        // makes delivery incremental; leaving it collects the channel as before.
        on_batch(&mut batch_records);
        records.append(&mut batch_records);
    }

    if unparsable > 0 {
        // Counted and reported rather than passed over. Events that never arrived look exactly like
        // evidence that the thing being investigated did not happen.
        log::warn!("event=evtx_live_query_gap channel=\"{channel}\" unparsable={unparsable}");
        gaps.push(format!(
            "{channel}: {unparsable} events could not be read and are missing from this view"
        ));
    }
    if unrenderable > 0 {
        log::warn!("event=evtx_live_query_gap channel=\"{channel}\" unrenderable={unrenderable}");
        gaps.push(format!(
            "{channel}: {unrenderable} events could not be rendered and are missing from this view"
        ));
    }
    log::info!(
        "event=evtx_live_query_done channel=\"{channel}\" records={} unparsable={unparsable} unrenderable={unrenderable} gaps={}",
        records.len(),
        gaps.len()
    );
    Ok(ChannelScan {
        records,
        delivered: produced,
        gaps,
    })
}

// ── Non-Windows stubs ───────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_with_progress(
    _channel: &str,
    _maps: &MapRegistry,
    _providers: &ProviderStore,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel(
    _channel: &str,
    _maps: &MapRegistry,
    _providers: &ProviderStore,
    _max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_filtered(
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &ProviderStore,
    _max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_filtered_with_progress(
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &ProviderStore,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
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
        let metadata = unsafe { EvtOpenPublisherMetadata(None, &provider, PCWSTR::null(), 0, 0) }
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
            Err(e) if is_insufficient_buffer(&e) => {
                buffer.resize(buffer_used.max(buffer.len() as u32 * 2) as usize, 0);
            }
            Err(e) if is_not_found(&e) || is_message_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
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

// `ERROR_NO_MORE_ITEMS` and `RPC_S_INVALID_BOUND` are recognised in `super::fetch`, which owns the
// decision they feed and is tested on every platform rather than only on this one.

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

        let records = query_channel("Application", &MapRegistry::new(), &ProviderStore::default(), Some(3))
            .expect("query should work")
            .records;
        println!("Application records: {}", records.len());
        for (i, r) in records.iter().enumerate() {
            println!("--- Record {i} ---");
            println!(
                "  EventID: {}, Provider: {}, Level: {:?}",
                r.event_id, r.provider, r.level
            );
            println!("  Timestamp: {}", r.timestamp);
            println!("  Message: {}", &r.message[..r.message.len().min(100)]);
            println!("  XML prefix: {}", &r.raw_xml[..r.raw_xml.len().min(300)]);
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod live_service_tests {
    //! Exercises the live path against the machine's own Event Log service.
    //!
    //! Ignored by default because it needs a real service with real events, which CI runners and
    //! developer machines cannot be relied on to have. Run deliberately on a Windows host:
    //!
    //! ```text
    //! cargo test --lib event_log::live::live_service_tests -- --ignored --nocapture
    //! ```
    //!
    //! These exist because every assumption in this file that was checked only by reasoning turned
    //! out to be wrong at least once. Compilation proves nothing about whether the service accepts
    //! what we send it.

    use super::*;
    // Only the assertions need the level type; the query path itself no longer builds records, so
    // importing it at module scope would warn in a non-test build.
    use super::super::models::EvtxLevel;
    use cmtraceopen_parser::event_query::{EventQueryFilter, TimeWindow};

    const CHANNEL: &str = "Application";

    /// A registry local to the call, replacing what used to be an implicit process global. These
    /// tests are about the query reaching the service, not about mapping.
    fn no_maps() -> MapRegistry {
        MapRegistry::new()
    }

    /// An empty provider store, so the query exercises the `EvtFormatMessage` fallback rather than
    /// a database-backed renderer. These tests are about the service round trip, not about mapping.
    fn no_providers() -> ProviderStore {
        ProviderStore::default()
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn an_unfiltered_query_returns_records() {
        let scan = query_channel(CHANNEL, &no_maps(), &no_providers(), Some(50)).expect("query succeeds");
        let records = scan.records;
        assert!(
            !records.is_empty(),
            "Application channel should have events"
        );
        let first = &records[0];
        assert!(!first.provider.is_empty(), "provider should be populated");
        assert_eq!(first.channel, CHANNEL);
        assert!(first.event_id > 0);
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn a_time_filter_is_applied_by_the_service_and_narrows_the_result() {
        // The narrow window is queried first. Running the wide one first leaves a gap in which a
        // newly written event lands inside the one-hour result and outside the thirty-day one
        // already collected, failing the assertion for a reason that has nothing to do with
        // filtering. Querying narrow first makes any new event land in the wide result, which is
        // the direction the assertion tolerates.
        let narrow = query_channel_filtered(
            CHANNEL,
            &EventQueryFilter {
                time: Some(TimeWindow::Last {
                    milliseconds: 60 * 60 * 1000,
                }),
                ..Default::default()
            },
            &no_maps(),
            &no_providers(),
            None,
        )
        .expect("1 hour query succeeds")
        .records;

        let wide = query_channel_filtered(
            CHANNEL,
            &EventQueryFilter {
                time: Some(TimeWindow::Last {
                    milliseconds: 30 * 24 * 60 * 60 * 1000,
                }),
                ..Default::default()
            },
            &no_maps(),
            &no_providers(),
            None,
        )
        .expect("30 day query succeeds")
        .records;

        assert!(
            narrow.len() <= wide.len(),
            "a narrower window cannot return more events: {} vs {}",
            narrow.len(),
            wide.len()
        );
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn a_level_filter_returns_only_that_level() {
        // Level 2 is Error. If the predicate were dropped or malformed the service would either
        // reject the query or return everything, and both show up here.
        let records = query_channel_filtered(
            CHANNEL,
            &EventQueryFilter {
                levels: vec![2],
                ..Default::default()
            },
            &no_maps(),
            &no_providers(),
            Some(200),
        )
        .expect("level query succeeds")
        .records;

        for record in &records {
            assert_eq!(
                record.level,
                EvtxLevel::Error,
                "level filter must be applied by the service, got {:?}",
                record.level
            );
        }
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn an_impossible_filter_returns_nothing_rather_than_everything() {
        // A malformed predicate that the service ignores would show up as a full result set.
        let records = query_channel_filtered(
            CHANNEL,
            &EventQueryFilter {
                event_ids: vec![cmtraceopen_parser::event_query::EventIdSelector::Single {
                    id: 999_999,
                }],
                ..Default::default()
            },
            &no_maps(),
            &no_providers(),
            Some(50),
        )
        .expect("query succeeds")
        .records;

        assert!(
            records.is_empty(),
            "event id 999999 should match nothing, got {}",
            records.len()
        );
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn system_fields_are_populated_from_real_events() {
        let records =
            query_channel_filtered(CHANNEL, &EventQueryFilter::default(), &no_maps(), &no_providers(), Some(200))
                .expect("query succeeds")
                .records;

        assert!(!records.is_empty());
        assert!(
            records.iter().any(|r| r.process_id.is_some()),
            "at least one real event should carry Execution/@ProcessID"
        );
        assert!(
            records.iter().any(|r| r.keywords.is_some()),
            "at least one real event should carry Keywords"
        );
    }
}
