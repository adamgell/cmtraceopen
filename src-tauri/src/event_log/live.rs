#[cfg(any(target_os = "windows", test))]
use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use std::hash::{Hash, Hasher};

#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::sync::{Arc, LazyLock, Mutex};
#[cfg(target_os = "windows")]
use std::thread;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use super::event_node::{extract_event_data, extract_system_fields, parse_event_xml};
#[cfg(target_os = "windows")]
use super::models::{
    ChannelSourceType, EvtxClearResult, EvtxClearStatus, EvtxLiveMode, EvtxTailBatch,
    EvtxTailStatus,
};
use super::models::{EvtxChannelInfo, EvtxCoverageGap, EvtxRecord};
#[cfg(any(target_os = "windows", test))]
use super::models::{EvtxCoverageGapKind, ProviderMessageCoverage, ProviderMessageStage};
#[cfg(any(target_os = "windows", test))]
use super::parser::DescriptionOutcome;
use super::provider_db::ProviderStore;
#[cfg(target_os = "windows")]
use cmtraceopen_parser::event_query::build_query;
use cmtraceopen_parser::event_query::EventQueryFilter;
use cmtraceopen_parser::eventmap::MapRegistry;

#[cfg(target_os = "windows")]
use tauri::{AppHandle, Emitter};

#[cfg(target_os = "windows")]
use windows::core::{Error, HSTRING, PCWSTR, PWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::{
    EvtClearLog, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtOpenSession, EvtQuery, EvtQueryChannelPath,
    EvtQueryReverseDirection, EvtQueryTolerateQueryErrors, EvtRender, EvtRenderEventXml,
    EvtRpcLogin, EvtRpcLoginAuthDefault, EvtSubscribe, EvtSubscribeActionDeliver,
    EvtSubscribeActionError, EvtSubscribeToFutureEvents, EvtSubscribeTolerateQueryErrors,
    EVT_HANDLE, EVT_RPC_LOGIN, EVT_SUBSCRIBE_CALLBACK, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

/// Event handles fetched per `EvtNext` call.
///
/// Each call is a round trip to the Event Log service, so this is the dominant cost of a scan.
/// FullEventLogView hardcodes 1, paying one round trip per event. The API accepts up to 1024;
/// 256 keeps the per-call array modest while cutting round trips by that factor.
#[cfg(any(target_os = "windows", test))]
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
    /// Description failures for records that were still delivered successfully.
    pub provider_gaps: Vec<EvtxCoverageGap>,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeProviderFailure {
    stage: ProviderMessageStage,
    error_code: u32,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default)]
struct MessageRenderOutcome {
    message: Option<String>,
    provider_gaps: Vec<EvtxCoverageGap>,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct RenderedTailEvent {
    record: EvtxRecord,
    provider_gaps: Vec<EvtxCoverageGap>,
}

#[cfg(any(target_os = "windows", test))]
impl RenderedTailEvent {
    fn new(record: EvtxRecord, provider_gaps: Vec<EvtxCoverageGap>) -> Self {
        Self {
            record,
            provider_gaps,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProviderGapKey {
    Native(String, ProviderMessageStage),
    Other(String, EvtxCoverageGapKind, String),
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default)]
struct ProviderGapDedup {
    seen: HashSet<ProviderGapKey>,
}

#[cfg(any(target_os = "windows", test))]
impl ProviderGapDedup {
    fn keep(&mut self, gap: &EvtxCoverageGap) -> bool {
        let key = match &gap.provider_message {
            Some(context) => {
                ProviderGapKey::Native(context.provider.trim().to_lowercase(), context.stage)
            }
            None => ProviderGapKey::Other(gap.source.clone(), gap.kind, gap.reason.clone()),
        };
        self.seen.insert(key)
    }
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn provider_message_gap(
    source: &str,
    provider: &str,
    stage: ProviderMessageStage,
    error_code: u32,
) -> EvtxCoverageGap {
    let reason = format!(
        "provider message for {provider} could not be rendered at {} (Windows error \
         {error_code}); raw event data is shown instead",
        stage.api_name()
    );
    let mut gap = EvtxCoverageGap::new(source, EvtxCoverageGapKind::Provider, reason);
    gap.provider_message = Some(Box::new(ProviderMessageCoverage {
        provider: provider.to_string(),
        stage,
        error_code,
    }));
    gap
}

#[cfg(any(target_os = "windows", test))]
fn provider_database_gap(source: &str, provider: &str, error: String) -> EvtxCoverageGap {
    EvtxCoverageGap::new(
        source,
        EvtxCoverageGapKind::Provider,
        format!(
            "provider database lookup failed for {provider}: {error}; native message formatting \
             was attempted"
        ),
    )
}

#[cfg(any(target_os = "windows", test))]
fn provider_database_channel<'a>(
    system_channel: Option<&'a str>,
    queried_channel: &'a str,
) -> &'a str {
    system_channel.unwrap_or(queried_channel)
}

#[cfg(any(target_os = "windows", test))]
fn select_provider_message(
    described: Result<Option<DescriptionOutcome>, String>,
    source: &str,
    provider: &str,
    native: impl FnOnce() -> Result<Option<String>, NativeProviderFailure>,
) -> MessageRenderOutcome {
    if let Ok(Some(DescriptionOutcome::Rendered(message))) = &described {
        return MessageRenderOutcome {
            message: Some(message.clone()),
            provider_gaps: Vec::new(),
        };
    }

    let mut provider_gaps = match described {
        Err(error) => vec![provider_database_gap(source, provider, error)],
        Ok(None)
        | Ok(Some(DescriptionOutcome::MissingInsertions(_)))
        | Ok(Some(DescriptionOutcome::ChannelMetadataUnavailable { .. })) => Vec::new(),
        Ok(Some(DescriptionOutcome::Rendered(_))) => {
            unreachable!("rendered outcome returned above")
        }
    };
    let message = match native() {
        Ok(message) => message,
        Err(failure) => {
            provider_gaps.push(provider_message_gap(
                source,
                provider,
                failure.stage,
                failure.error_code,
            ));
            None
        }
    };
    MessageRenderOutcome {
        message,
        provider_gaps,
    }
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn format_provider_gap(gap: &EvtxCoverageGap) -> String {
    format!("{}: {}", gap.source, gap.reason)
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
#[cfg(target_os = "windows")]
pub fn normalize_remote_machine_name(machine: &str) -> Result<String, String> {
    let normalized = machine.trim().trim_start_matches('\\').to_string();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains('\0')
        || normalized.chars().any(char::is_control)
    {
        return Err("remote machine name must be a hostname or UNC computer name".to_string());
    }
    Ok(normalized)
}
#[cfg(target_os = "windows")]
fn remote_login(server: &mut [u16]) -> EVT_RPC_LOGIN {
    EVT_RPC_LOGIN {
        Server: PWSTR::from_raw(server.as_mut_ptr()),
        // Null credentials deliberately select the current Windows logon token. User-entered
        // passwords and tokens never cross this API boundary or enter persisted settings.
        User: PWSTR::null(),
        Domain: PWSTR::null(),
        Password: PWSTR::null(),
        Flags: EvtRpcLoginAuthDefault.0,
    }
}

#[cfg(target_os = "windows")]
fn open_remote_session(machine: &str) -> Result<(OwnedEvtHandle, String), String> {
    let machine = normalize_remote_machine_name(machine)?;
    let mut server: Vec<u16> = machine.encode_utf16().chain(std::iter::once(0)).collect();
    let login = remote_login(&mut server);
    let session = unsafe {
        EvtOpenSession(
            EvtRpcLogin,
            &login as *const EVT_RPC_LOGIN as *const c_void,
            None,
            None,
        )
    }
    .map_err(|error| {
        format_remote_error(&format!("cannot open remote session to {machine}"), &error)
    })?;
    Ok((OwnedEvtHandle::new(session), machine))
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all registered Windows Event Log channels on the local system.
#[cfg(target_os = "windows")]
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    enumerate_channels_for_session(None, ChannelSourceType::Live)
}

/// Enumerate channels from a remote computer using the current Windows credentials.
#[cfg(target_os = "windows")]
pub fn enumerate_remote_channels(machine: &str) -> Result<Vec<EvtxChannelInfo>, String> {
    let (session, machine) = open_remote_session(machine)?;
    enumerate_channels_for_session(Some(session.raw()), ChannelSourceType::Remote { machine })
}

#[cfg(target_os = "windows")]
fn enumerate_channels_for_session(
    session: Option<EVT_HANDLE>,
    source_type: ChannelSourceType,
) -> Result<Vec<EvtxChannelInfo>, String> {
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

    let raw_handle = unsafe { EvtOpenChannelEnum(session.map(|h| h.0).unwrap_or(0), 0) };
    if raw_handle == 0 {
        let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(format_channel_code(
            "EvtOpenChannelEnum",
            error,
            session.is_some(),
        ));
    }
    let enum_handle = OwnedEvtHandle::new(EVT_HANDLE(raw_handle));

    let mut channels = Vec::new();
    let mut buffer = vec![0u16; 512];

    loop {
        let mut used = 0u32;
        let ok = unsafe {
            EvtNextChannelPath(
                enum_handle.raw().0,
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
                source_type: source_type.clone(),
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
                return Err(format_channel_code(
                    "EvtNextChannelPath",
                    err,
                    session.is_some(),
                ));
            }
        }
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
    providers: &std::sync::RwLock<ProviderStore>,
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
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        None,
        "Live",
        |_, _| {},
        |_| Ok(()),
    )
}

/// Query with a progress callback: `on_progress(fetched_so_far, total_estimate)`.
#[cfg(target_os = "windows")]
pub fn query_channel_with_progress(
    channel: &str,
    maps: &MapRegistry,
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        &EventQueryFilter::default(),
        maps,
        providers,
        max_events,
        None,
        "Live",
        on_progress,
        |_| Ok(()),
    )
}

/// Queries a channel with server-side filtering, reporting progress as events arrive.
#[cfg(target_os = "windows")]
pub fn query_channel_filtered_with_progress(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        None,
        "Live",
        on_progress,
        |_| Ok(()),
    )
}

/// Queries a channel, delivering each batch of records as it is read.
///
/// `on_batch` is handed every batch and is expected to take the records from it. Whatever it leaves
/// is returned in the [`ChannelScan`], so a caller that forgets to drain still gets correct results
/// rather than losing them; it simply holds the channel in memory as before. A callback error
/// aborts the query and is returned to the caller.
#[cfg(target_os = "windows")]
pub fn query_channel_streamed(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
    on_batch: impl FnMut(&mut Vec<EvtxRecord>) -> Result<(), String>,
) -> Result<ChannelScan, String> {
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        None,
        "Live",
        on_progress,
        on_batch,
    )
}

/// Queries one channel from a remote computer using the current Windows credentials.
#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
pub fn query_remote_channel_streamed(
    machine: &str,
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
    on_batch: impl FnMut(&mut Vec<EvtxRecord>) -> Result<(), String>,
) -> Result<ChannelScan, String> {
    let (session, machine) = open_remote_session(machine)?;
    let source_label = format!("Remote: {machine}");
    query_channel_inner(
        channel,
        filter,
        maps,
        providers,
        max_events,
        Some(session.raw()),
        &source_label,
        on_progress,
        on_batch,
    )
}

/// Reads a channel, handing each fetched batch to `on_batch` as it is built.
///
/// `on_batch` receives the batch by mutable reference and may take the records out of it. Whatever
/// it leaves behind is accumulated into the returned [`ChannelScan`]. That is the whole difference
/// between streaming and collecting: a caller that drains never holds more than one batch, and a
/// caller that ignores the argument gets the channel in one piece exactly as before. A callback
/// error aborts the query and is returned to the caller.
///
/// The distinction matters because one channel dominates a scan. On a measured seven-day scan,
/// Security was 286,401 of 404,769 events and 191.8 seconds of 267, so a caller waiting for this
/// function to return waits three minutes with nothing to show.
#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn query_channel_inner(
    channel: &str,
    filter: &EventQueryFilter,
    maps: &MapRegistry,
    providers: &std::sync::RwLock<ProviderStore>,
    max_events: Option<u64>,
    session: Option<EVT_HANDLE>,
    source_label: &str,
    on_progress: impl Fn(usize, Option<usize>),
    mut on_batch: impl FnMut(&mut Vec<EvtxRecord>) -> Result<(), String>,
) -> Result<ChannelScan, String> {
    let remote = source_label.starts_with("Remote:");
    let coverage_channel = if let Some(machine) = source_label.strip_prefix("Remote: ") {
        format!("{machine}/{channel}")
    } else {
        channel.to_string()
    };
    let limit = max_events.map(|n| n as usize).unwrap_or(usize::MAX);
    let channel_hstring = HSTRING::from(channel);
    // A filter that cannot be expressed is refused here rather than silently degraded to "*",
    // which would return everything and look like the filter simply matched a lot.
    let compiled = build_query(filter)
        .map_err(|error| format!("cannot compile event query for {coverage_channel}: {error}"))?;
    let query_string = HSTRING::from(compiled.as_str());
    let query_handle = unsafe {
        EvtQuery(
            session,
            &channel_hstring,
            &query_string,
            // TolerateQueryErrors keeps a scan alive when one part of a query cannot be evaluated,
            // for example a provider that is not registered on this machine. Without it a single
            // bad element aborts the whole channel and the result silently looks empty.
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0 | EvtQueryTolerateQueryErrors.0,
        )
    }
    .map_err(|e| format_source_error(&format!("EvtQuery({coverage_channel})"), &e, remote))?;
    let query_handle = OwnedEvtHandle::new(query_handle);
    log::info!("event=evtx_live_query channel=\"{channel}\" limit={limit}");

    let mut records = Vec::new();
    let mut publisher_metadata = HashMap::<String, PublisherMetadata>::new();
    let mut unparsable = 0usize;
    let mut unrenderable = 0usize;
    let mut first_render_error = None;
    let mut message_failures = 0usize;
    let mut gaps = Vec::new();
    let mut provider_gaps = Vec::new();
    let mut provider_gap_dedup = ProviderGapDedup::default();
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
                    push_bounded_tail_coverage_gap(
                        &mut gaps,
                        format!(
                            "{coverage_channel}: stopped after {} events, the channel could not be read further ({})",
                            produced,
                            format_source_error("EvtNext", &error, remote),
                        ),
                    );
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
                    let detail = format_source_error("EvtRender", &error, remote);
                    if unrenderable == 1 {
                        first_render_error = Some(detail.clone());
                        log::warn!(
                            "event=evtx_render_failed channel=\"{channel}\" error=\"{}\"",
                            detail
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

            // Only attempted when the event named a provider. Asking the service for the metadata
            // of a publisher the event never named would fail once per event and cache the failure
            // under a name no provider has.
            let message_outcome = match system.provider.as_deref() {
                Some(provider) => {
                    let provider_channel =
                        provider_database_channel(system.channel.as_deref(), channel);
                    let insertions = extract_event_data(&parsed).insertions;
                    let described = providers
                        .read()
                        .map_err(|_| "provider store lock was poisoned".to_string())
                        .and_then(|store| {
                            super::parser::describe_event(
                                &store,
                                provider,
                                provider_channel,
                                system.event_id.unwrap_or(0),
                                system.version,
                                &insertions,
                            )
                        });
                    select_provider_message(described, &coverage_channel, provider, || {
                        format_event_message(
                            event_handle.raw(),
                            provider,
                            session,
                            &mut publisher_metadata,
                        )
                    })
                }
                None => MessageRenderOutcome::default(),
            };
            for gap in message_outcome.provider_gaps.iter() {
                message_failures += 1;
                if provider_gap_dedup.keep(gap) {
                    log::warn!(
                        "event=evtx_provider_message_gap channel=\"{channel}\" diagnostic=\"{}\"",
                        gap.reason
                    );
                    provider_gaps.push(gap.clone());
                }
            }

            let mut record = super::rendered::record_from_parts(
                &parsed,
                system,
                &xml,
                channel,
                maps,
                message_outcome.message.as_deref(),
            );
            record.source_label = source_label.to_string();
            batch_records.push(record);
        }

        produced += batch_records.len();
        on_progress(produced, None);

        // The caller sees the batch before anything else happens to it. Draining it here is what
        // makes delivery incremental; leaving it collects the channel as before.
        on_batch(&mut batch_records)?;
        records.append(&mut batch_records);
    }

    if unparsable > 0 {
        // Counted and reported rather than passed over. Events that never arrived look exactly like
        // evidence that the thing being investigated did not happen.
        log::warn!("event=evtx_live_query_gap channel=\"{channel}\" unparsable={unparsable}");
        push_bounded_tail_coverage_gap(
            &mut gaps,
            format!(
                "{coverage_channel}: {unparsable} events could not be read and are missing from this view"
            ),
        );
    }
    if unrenderable > 0 {
        log::warn!("event=evtx_live_query_gap channel=\"{channel}\" unrenderable={unrenderable}");
        push_bounded_tail_coverage_gap(
            &mut gaps,
            format!(
                "{coverage_channel}: {unrenderable} events could not be rendered and are missing \
                 from this view ({})",
                first_render_error.unwrap_or_else(|| "EvtRender failed".to_string())
            ),
        );
    }
    if message_failures > 0 {
        log::warn!(
            "event=evtx_live_query_gap channel=\"{channel}\" message_failures={message_failures}"
        );
    }
    log::info!(
        "event=evtx_live_query_done channel=\"{channel}\" records={} unparsable={unparsable} unrenderable={unrenderable} record_gaps={} provider_gaps={}",
        records.len(),
        gaps.len(),
        provider_gaps.len()
    );
    Ok(ChannelScan {
        records,
        delivered: produced,
        gaps,
        provider_gaps,
    })
}

#[cfg(target_os = "windows")]
const POLL_INTERVAL: Duration = Duration::from_millis(750);

#[cfg(target_os = "windows")]
const SUBSCRIPTION_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(any(target_os = "windows", test))]
const MAX_TAIL_COVERAGE_GAPS: usize = 256;

#[cfg(any(target_os = "windows", test))]
const TAIL_COVERAGE_SUMMARY_PREFIX: &str = "<live tail coverage>: ";

#[cfg(any(target_os = "windows", test))]
const TAIL_COVERAGE_SUMMARY_SUFFIX: &str = " additional live tail diagnostics were coalesced";

#[cfg(any(target_os = "windows", test))]
fn push_bounded_tail_coverage_gap(gaps: &mut Vec<String>, gap: String) {
    if gaps.len() < MAX_TAIL_COVERAGE_GAPS - 1 {
        gaps.push(gap);
        return;
    }
    if gaps.len() == MAX_TAIL_COVERAGE_GAPS - 1 {
        gaps.push(format!(
            "{TAIL_COVERAGE_SUMMARY_PREFIX}1{TAIL_COVERAGE_SUMMARY_SUFFIX}"
        ));
        return;
    }

    let Some(summary) = gaps.last_mut() else {
        return;
    };
    let Some(omitted) = summary
        .strip_prefix(TAIL_COVERAGE_SUMMARY_PREFIX)
        .and_then(|summary| summary.strip_suffix(TAIL_COVERAGE_SUMMARY_SUFFIX))
        .and_then(|count| count.parse::<usize>().ok())
    else {
        *summary = format!("{TAIL_COVERAGE_SUMMARY_PREFIX}2{TAIL_COVERAGE_SUMMARY_SUFFIX}");
        return;
    };
    *summary = format!(
        "{TAIL_COVERAGE_SUMMARY_PREFIX}{}{TAIL_COVERAGE_SUMMARY_SUFFIX}",
        omitted.saturating_add(1)
    );
}

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
struct PendingTailBatch {
    records: Vec<EvtxRecord>,
    coverage_gaps: Vec<String>,
}

#[cfg(any(target_os = "windows", test))]
impl PendingTailBatch {
    fn is_full(&self) -> bool {
        self.records.len() >= EVENT_FETCH_BATCH
    }

    fn is_ready(&self) -> bool {
        self.is_full()
    }

    fn push_rendered(&mut self, record: EvtxRecord, gaps: Vec<String>) -> bool {
        self.records.push(record);
        for gap in gaps {
            push_bounded_tail_coverage_gap(&mut self.coverage_gaps, gap);
        }
        self.is_ready()
    }

    fn take(&mut self) -> (Vec<EvtxRecord>, Vec<String>) {
        (
            std::mem::take(&mut self.records),
            std::mem::take(&mut self.coverage_gaps),
        )
    }
}

#[cfg(target_os = "windows")]
struct TailBatcher {
    app: AppHandle,
    request_id: String,
    channel: String,
    sequence: Arc<AtomicU64>,
    coverage_gaps: Arc<Mutex<Vec<String>>>,
    pending: Mutex<PendingTailBatch>,
    emission: Mutex<()>,
}

#[cfg(target_os = "windows")]
impl TailBatcher {
    fn push_rendered(&self, record: EvtxRecord, gaps: Vec<String>) {
        loop {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if pending.is_full() {
                drop(pending);
                self.flush();
                continue;
            }
            let should_flush = pending.push_rendered(record, gaps);
            drop(pending);
            if should_flush {
                self.flush();
            }
            return;
        }
    }

    fn push_gap(&self, gap: String) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        push_bounded_tail_coverage_gap(&mut pending.coverage_gaps, gap);
    }

    fn flush(&self) {
        let _emission = self
            .emission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((records, gaps, sequence)) = ({
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if pending.records.is_empty() && pending.coverage_gaps.is_empty() {
                None
            } else {
                let (records, gaps) = pending.take();
                let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);
                Some((records, gaps, sequence))
            }
        }) else {
            return;
        };
        emit_tail_event(
            &self.app,
            self.coverage_gaps.as_ref(),
            EvtxTailBatch {
                request_id: self.request_id.clone(),
                channel: self.channel.clone(),
                sequence,
                mode: EvtxLiveMode::Subscription,
                records,
                coverage_gaps: gaps,
            },
        );
    }
}

#[cfg(target_os = "windows")]
fn subscription_flush_worker(
    batcher: Arc<TailBatcher>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            thread::sleep(SUBSCRIPTION_FLUSH_INTERVAL);
            batcher.flush();
        }
        // EvtClose waits for callbacks already in flight. Flush anything they queued before the
        // worker exits so stopping a tail does not silently discard rendered records.
        batcher.flush();
    })
}

#[cfg(target_os = "windows")]
struct TailContext {
    channel: String,
    source_label: String,
    session: Option<EVT_HANDLE>,
    maps: Arc<std::sync::RwLock<MapRegistry>>,
    providers: Arc<std::sync::RwLock<ProviderStore>>,
    batcher: Arc<TailBatcher>,
    publisher_metadata: Mutex<HashMap<String, PublisherMetadata>>,
    provider_gap_dedup: Mutex<ProviderGapDedup>,
}

#[cfg(target_os = "windows")]
struct ActiveTail {
    request_id: String,
    channel: String,
    mode: EvtxLiveMode,
    stop: Arc<AtomicBool>,
    sequence: Arc<AtomicU64>,
    coverage_gaps: Arc<Mutex<Vec<String>>>,
    subscription: Option<OwnedEvtHandle>,
    context: Option<Box<TailContext>>,
    session: Option<OwnedEvtHandle>,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl Drop for ActiveTail {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // EvtClose waits for callbacks that are already in flight. Keeping the context boxed until
        // after this point prevents a late service callback from dereferencing freed state.
        self.subscription.take();
        if let Some(context) = self.context.as_ref() {
            context.batcher.flush();
        }
        self.context.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // A polling worker borrows the raw handle owned by this tail. Close the session only after
        // the stop flag has been observed and the worker has exited.
        self.session.take();
    }
}
#[cfg(target_os = "windows")]
static ACTIVE_TAILS: LazyLock<Mutex<HashMap<String, ActiveTail>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(target_os = "windows")]
fn active_tails() -> &'static Mutex<HashMap<String, ActiveTail>> {
    &ACTIVE_TAILS
}
#[cfg(target_os = "windows")]
fn merge_tail_coverage_gaps(stored: &Mutex<Vec<String>>, gaps: &mut Vec<String>) {
    let pending = stored
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for gap in pending.iter() {
        if !gaps.iter().any(|existing| existing == gap) {
            push_bounded_tail_coverage_gap(gaps, gap.clone());
        }
    }
}

#[cfg(target_os = "windows")]
fn remember_tail_coverage_gaps(stored: &Mutex<Vec<String>>, gaps: &[String]) {
    let mut pending = stored
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for gap in gaps {
        if !pending.iter().any(|existing| existing == gap) {
            push_bounded_tail_coverage_gap(&mut pending, gap.clone());
        }
    }
}

#[cfg(target_os = "windows")]
fn clear_tail_coverage_gaps(stored: &Mutex<Vec<String>>) {
    stored
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

#[cfg(target_os = "windows")]
fn emit_tail_event(app: &AppHandle, stored_gaps: &Mutex<Vec<String>>, mut batch: EvtxTailBatch) {
    merge_tail_coverage_gaps(stored_gaps, &mut batch.coverage_gaps);
    let sequence = batch.sequence;
    let channel = batch.channel.clone();
    let delivered_gaps = batch.coverage_gaps.clone();
    if let Err(error) = app.emit("evtx-tail-batch", batch) {
        remember_tail_coverage_gaps(stored_gaps, &delivered_gaps);
        let delivery_gap =
            format!("{channel}: live tail batch {sequence} was not delivered ({error})");
        remember_tail_coverage_gaps(stored_gaps, &[delivery_gap]);
        log::warn!(
            "event=evtx_tail_batch_dropped channel=\"{}\" sequence={} error=\"{}\"",
            channel,
            sequence,
            error
        );
    } else {
        clear_tail_coverage_gaps(stored_gaps);
    }
}

#[cfg(target_os = "windows")]
fn render_tail_event(
    context: &TailContext,
    event: EVT_HANDLE,
) -> Result<RenderedTailEvent, String> {
    let xml = render_event_xml(event).map_err(|error| {
        format_source_error(
            "EvtRender",
            &error,
            context.source_label.starts_with("Remote:"),
        )
    })?;
    let parsed =
        parse_event_xml(&xml).map_err(|error| format!("event XML could not be parsed: {error}"))?;
    let system = extract_system_fields(&parsed);
    let message_outcome = match system.provider.as_deref() {
        Some(provider) => {
            let coverage_source = context
                .source_label
                .strip_prefix("Remote: ")
                .map(|machine| format!("{machine}/{}", context.channel))
                .unwrap_or_else(|| context.channel.clone());
            let provider_channel =
                provider_database_channel(system.channel.as_deref(), &context.channel);
            let insertions = extract_event_data(&parsed).insertions;
            let described = context
                .providers
                .read()
                .map_err(|_| "provider store lock was poisoned".to_string())
                .and_then(|store| {
                    super::parser::describe_event(
                        &store,
                        provider,
                        provider_channel,
                        system.event_id.unwrap_or(0),
                        system.version,
                        &insertions,
                    )
                });
            let mut metadata_lock_error = None;
            let outcome = select_provider_message(described, &coverage_source, provider, || {
                let Ok(mut metadata) = context.publisher_metadata.lock() else {
                    metadata_lock_error = Some("publisher metadata lock was poisoned".to_string());
                    return Ok(None);
                };
                format_event_message(event, provider, context.session, &mut metadata)
            });
            if let Some(error) = metadata_lock_error {
                return Err(error);
            }
            outcome
        }
        None => MessageRenderOutcome::default(),
    };
    let mut record = {
        let maps = context
            .maps
            .read()
            .map_err(|_| "event map registry lock was poisoned".to_string())?;
        super::rendered::record_from_parts(
            &parsed,
            system,
            &xml,
            &context.channel,
            &maps,
            message_outcome.message.as_deref(),
        )
    };
    record.source_label = context.source_label.clone();
    Ok(RenderedTailEvent::new(
        record,
        message_outcome.provider_gaps,
    ))
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn evt_subscribe_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if user_context.is_null() {
        return 1;
    }
    let context = &*(user_context as *const TailContext);
    if action == EvtSubscribeActionDeliver {
        let result = render_tail_event(context, event);
        unsafe {
            let _ = EvtClose(event);
        }
        match result {
            Ok(rendered) => {
                let mut dedup = context
                    .provider_gap_dedup
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let gaps = rendered
                    .provider_gaps
                    .iter()
                    .filter(|gap| dedup.keep(gap))
                    .map(format_provider_gap)
                    .collect();
                drop(dedup);
                context.batcher.push_rendered(rendered.record, gaps);
            }
            Err(error) => context
                .batcher
                .push_gap(format!("{}: {error}", context.channel)),
        }
    } else if action == EvtSubscribeActionError {
        context.batcher.push_gap(format!(
            "{}: subscription callback reported an error",
            context.channel
        ));
    }
    0
}

#[cfg(target_os = "windows")]
fn subscription_unavailable(error: &Error) -> bool {
    // These are platform/service capability failures. Access denied and missing channels are
    // returned to the operator instead of silently changing acquisition semantics.
    matches!(win32_code(error), 1 | 50 | 120 | 127)
}

#[cfg(target_os = "windows")]
fn clear_error_status(channel: &str, error: &Error, remote: bool) -> EvtxClearResult {
    let code = win32_code(error);
    let detail = format_source_error("EvtClearLog", error, remote);
    let denied = code == 5
        || (remote
            && matches!(
                remote_error_kind(code),
                "access denied" | "credentials rejected"
            ));
    if denied {
        EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Denied { detail },
        }
    } else {
        EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Unavailable { detail },
        }
    }
}

#[cfg(target_os = "windows")]
fn clear_remote_session_error(channel: &str, detail: String) -> EvtxClearResult {
    let denied = detail.to_ascii_lowercase().contains("access denied")
        || detail.to_ascii_lowercase().contains("credentials rejected");
    let result = if denied {
        EvtxClearStatus::Denied { detail }
    } else {
        EvtxClearStatus::Unavailable { detail }
    };
    EvtxClearResult {
        channel: channel.to_string(),
        result,
    }
}
/// Identity used by polling tails to reject a record already emitted by an earlier poll.
///
/// The numeric field is a transport convenience, not a complete identity: it loses precision in
/// JavaScript for large IDs and maps an absent EventRecordID to zero. Keep the lossless text and a
/// bounded fingerprint of the event payload so distinct missing-ID records remain visible.
#[cfg(target_os = "windows")]
fn polling_record_identity(record: &EvtxRecord) -> (String, u64) {
    let id_text = record
        .event_record_id_text
        .clone()
        .unwrap_or_else(|| record.event_record_id.to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if record.raw_xml.is_empty() {
        record.timestamp.hash(&mut hasher);
        record.timestamp_epoch.hash(&mut hasher);
        record.provider.hash(&mut hasher);
        record.channel.hash(&mut hasher);
        record.event_id.hash(&mut hasher);
        format!("{:?}", record.level).hash(&mut hasher);
        record.computer.hash(&mut hasher);
        record.message.hash(&mut hasher);
        record.source_label.hash(&mut hasher);
        record.task.hash(&mut hasher);
        record.opcode.hash(&mut hasher);
        record.process_id.hash(&mut hasher);
        record.thread_id.hash(&mut hasher);
        record.user_sid.hash(&mut hasher);
        record.keywords.hash(&mut hasher);
        for field in &record.event_data {
            field.name.hash(&mut hasher);
            field.value.hash(&mut hasher);
        }
    } else {
        record.raw_xml.hash(&mut hasher);
    }
    (id_text, hasher.finish())
}

#[cfg(target_os = "windows")]
fn start_polling_tail(
    app: AppHandle,
    request_id: String,
    channel: String,
    filter: EventQueryFilter,
    maps: Arc<std::sync::RwLock<MapRegistry>>,
    providers: Arc<std::sync::RwLock<ProviderStore>>,
    remote_session: Option<(OwnedEvtHandle, String)>,
    fallback_gap: String,
) -> Result<EvtxTailStatus, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let sequence = Arc::new(AtomicU64::new(0));
    let coverage_gaps = Arc::new(Mutex::new(Vec::new()));
    let worker_stop = Arc::clone(&stop);
    let worker_sequence = Arc::clone(&sequence);
    let worker_coverage_gaps = Arc::clone(&coverage_gaps);
    let worker_providers = Arc::clone(&providers);
    let worker_request = request_id.clone();
    let worker_channel = channel.clone();
    let worker_fallback_gap = fallback_gap.clone();
    let worker_session = remote_session
        .as_ref()
        .map(|(session, _machine)| session.raw());
    let worker_source_label = remote_session
        .as_ref()
        .map(|(_session, machine)| format!("Remote: {machine}"))
        .unwrap_or_else(|| "Live".to_string());
    let worker = thread::spawn(move || {
        let mut seen = HashSet::<(String, u64)>::new();
        let mut seen_order = VecDeque::<(String, u64)>::new();
        let mut provider_gap_dedup = ProviderGapDedup::default();
        let mut first_poll = true;
        while !worker_stop.load(Ordering::Acquire) {
            let outcome = query_channel_inner(
                &worker_channel,
                &filter,
                &maps.read().unwrap_or_else(|poisoned| poisoned.into_inner()),
                &worker_providers,
                Some(EVENT_FETCH_BATCH as u64),
                worker_session,
                &worker_source_label,
                |_, _| {},
                |_| Ok(()),
            );

            match outcome {
                Ok(scan) => {
                    let saturated = scan.delivered >= EVENT_FETCH_BATCH;
                    let mut records = scan.records;
                    records.retain(|record| {
                        let identity = polling_record_identity(record);
                        if seen.insert(identity.clone()) {
                            seen_order.push_back(identity);
                            true
                        } else {
                            false
                        }
                    });
                    if seen.len() > 8192 {
                        for _ in 0..4096 {
                            let Some(identity) = seen_order.pop_front() else {
                                break;
                            };
                            seen.remove(&identity);
                        }
                    }
                    let mut gaps = scan.gaps;
                    for gap in scan.provider_gaps {
                        if provider_gap_dedup.keep(&gap) {
                            push_bounded_tail_coverage_gap(&mut gaps, format_provider_gap(&gap));
                        }
                    }
                    if saturated {
                        push_bounded_tail_coverage_gap(
                            &mut gaps,
                            format!(
                                "{}: the polling window returned its full {EVENT_FETCH_BATCH}-record \
                                 batch; events written between polls may be missing",
                                worker_channel
                            ),
                        );
                    }
                    if first_poll && !worker_fallback_gap.is_empty() {
                        push_bounded_tail_coverage_gap(&mut gaps, worker_fallback_gap.clone());
                    }
                    merge_tail_coverage_gaps(worker_coverage_gaps.as_ref(), &mut gaps);
                    first_poll = false;
                    if !records.is_empty() || !gaps.is_empty() {
                        let sequence_number = worker_sequence.fetch_add(1, Ordering::AcqRel);
                        emit_tail_event(
                            &app,
                            worker_coverage_gaps.as_ref(),
                            EvtxTailBatch {
                                request_id: worker_request.clone(),
                                channel: worker_channel.clone(),
                                sequence: sequence_number,
                                mode: EvtxLiveMode::Polling,
                                records,
                                coverage_gaps: gaps,
                            },
                        );
                    }
                }
                Err(error) => {
                    let sequence_number = worker_sequence.fetch_add(1, Ordering::AcqRel);
                    emit_tail_event(
                        &app,
                        worker_coverage_gaps.as_ref(),
                        EvtxTailBatch {
                            request_id: worker_request.clone(),
                            channel: worker_channel.clone(),
                            sequence: sequence_number,
                            mode: EvtxLiveMode::Polling,
                            records: Vec::new(),
                            coverage_gaps: vec![format!("{}: {error}", worker_channel)],
                        },
                    );
                }
            }
            let mut waited = Duration::ZERO;
            while waited < POLL_INTERVAL && !worker_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(50));
                waited += Duration::from_millis(50);
            }
        }
        log::debug!(
            "event=evtx_tail_polling_stopped request_id=\"{}\" channel=\"{}\"",
            worker_request,
            worker_channel
        );
    });

    let status = EvtxTailStatus {
        request_id: request_id.clone(),
        channel: channel.clone(),
        mode: EvtxLiveMode::Polling,
        active: true,
        next_sequence: 0,
        coverage_gaps: vec![fallback_gap],
    };
    active_tails()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            tail_key(&request_id, &channel),
            ActiveTail {
                request_id,
                channel,
                mode: EvtxLiveMode::Polling,
                stop,
                sequence,
                coverage_gaps,
                subscription: None,
                context: None,
                session: remote_session.map(|(session, _machine)| session),
                worker: Some(worker),
            },
        );
    Ok(status)
}

/// Start a push subscription, falling back to polling only when the service does not expose
/// EvtSubscribe on this Windows build.
#[cfg(target_os = "windows")]
pub fn start_channel_tail(
    app: AppHandle,
    request_id: String,
    channel: String,
    filter: EventQueryFilter,
    maps: Arc<std::sync::RwLock<MapRegistry>>,
    providers: Arc<std::sync::RwLock<ProviderStore>>,
    remote_machine: Option<String>,
) -> Result<EvtxTailStatus, String> {
    let _ = stop_channel_tail(&request_id, &channel);
    let fallback_app = app.clone();
    let fallback_maps = maps.clone();
    let fallback_providers = providers.clone();
    let remote_session = remote_machine
        .as_deref()
        .map(open_remote_session)
        .transpose()?;
    let remote = remote_session.is_some();
    let session_handle = remote_session.as_ref().map(|(session, _)| session.raw());
    let source_label = remote_session
        .as_ref()
        .map(|(_, machine)| format!("Remote: {machine}"))
        .unwrap_or_else(|| "Live".to_string());
    let compiled = build_query(&filter)
        .map_err(|error| format!("cannot compile event query for {channel}: {error}"))?;
    let channel_hstring = HSTRING::from(channel.as_str());
    let query_hstring = HSTRING::from(compiled.as_str());
    let sequence = Arc::new(AtomicU64::new(0));
    let coverage_gaps = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let batcher = Arc::new(TailBatcher {
        app,
        request_id: request_id.clone(),
        channel: channel.clone(),
        sequence: Arc::clone(&sequence),
        coverage_gaps: Arc::clone(&coverage_gaps),
        pending: Mutex::new(PendingTailBatch::default()),
        emission: Mutex::new(()),
    });
    let context = Box::new(TailContext {
        channel: channel.clone(),
        source_label,
        session: session_handle,
        maps,
        providers,
        batcher: Arc::clone(&batcher),
        publisher_metadata: Mutex::new(HashMap::new()),
        provider_gap_dedup: Mutex::new(ProviderGapDedup::default()),
    });
    let context_ptr = (&*context) as *const TailContext as *const c_void;
    let callback: EVT_SUBSCRIBE_CALLBACK = Some(evt_subscribe_callback);
    let subscription = unsafe {
        EvtSubscribe(
            session_handle,
            None,
            &channel_hstring,
            &query_hstring,
            None,
            Some(context_ptr),
            callback,
            EvtSubscribeToFutureEvents.0 | EvtSubscribeTolerateQueryErrors.0,
        )
    };
    match subscription {
        Ok(handle) => {
            let handle = OwnedEvtHandle::new(handle);
            let worker = subscription_flush_worker(Arc::clone(&batcher), Arc::clone(&stop));
            let status = EvtxTailStatus {
                request_id: request_id.clone(),
                channel: channel.clone(),
                mode: EvtxLiveMode::Subscription,
                active: true,
                next_sequence: 0,
                coverage_gaps: Vec::new(),
            };
            active_tails()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    tail_key(&request_id, &channel),
                    ActiveTail {
                        request_id,
                        channel,
                        mode: EvtxLiveMode::Subscription,
                        stop,
                        sequence,
                        coverage_gaps,
                        subscription: Some(handle),
                        context: Some(context),
                        session: remote_session.map(|(session, _)| session),
                        worker: Some(worker),
                    },
                );
            Ok(status)
        }
        Err(error) if subscription_unavailable(&error) => {
            let fallback_gap = format!(
                "{}: EvtSubscribe unavailable; polling fallback is active ({})",
                channel,
                format_source_error("EvtSubscribe", &error, remote),
            );
            drop(context);
            start_polling_tail(
                fallback_app,
                request_id,
                channel,
                filter,
                fallback_maps,
                fallback_providers,
                remote_session,
                fallback_gap,
            )
        }
        Err(error) => {
            drop(context);
            Err(format_source_error("EvtSubscribe", &error, remote))
        }
    }
}

/// Stop a tail and synchronously release its subscription/session resources.
#[cfg(target_os = "windows")]
pub fn stop_channel_tail(request_id: &str, channel: &str) -> Result<EvtxTailStatus, String> {
    let key = tail_key(request_id, channel);
    let tail = active_tails()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key)
        .ok_or_else(|| format!("live tail {channel} for request {request_id} was not found"))?;
    let status_request_id = tail.request_id.clone();
    let status_channel = tail.channel.clone();
    let status_mode = tail.mode;
    let sequence = Arc::clone(&tail.sequence);
    let stored_gaps = Arc::clone(&tail.coverage_gaps);
    drop(tail);
    let next_sequence = sequence.load(Ordering::Acquire);
    let coverage_gaps = stored_gaps
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    Ok(EvtxTailStatus {
        request_id: status_request_id,
        channel: status_channel,
        mode: status_mode,
        active: false,
        next_sequence,
        coverage_gaps,
    })
}
#[cfg(target_os = "windows")]
fn tail_key(request_id: &str, channel: &str) -> String {
    format!("{request_id}\u{0}{channel}")
}

/// Clear a live channel only from an already-elevated application process.
#[cfg(target_os = "windows")]
pub fn clear_channel(
    channel: &str,
    confirmed: bool,
    remote_machine: Option<&str>,
) -> EvtxClearResult {
    if !confirmed {
        return EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Cancelled,
        };
    }
    let elevation = crate::elevation::current_elevation_state();
    if !elevation.platform_supported {
        return EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Unsupported {
                detail: elevation
                    .detail
                    .unwrap_or_else(|| "channel clearing is only available on Windows".to_string()),
            },
        };
    }
    if !elevation.is_elevated {
        return EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Denied {
                detail: "clearing an event channel requires the application to run elevated"
                    .to_string(),
            },
        };
    }

    // A remote request must own a valid RPC session before EvtClearLog is reached. In particular,
    // never fall through to the local `None` session when opening the requested target fails.
    let remote_session = match remote_machine {
        Some(machine) => match open_remote_session(machine) {
            Ok((session, _normalized_machine)) => Some(session),
            Err(detail) => return clear_remote_session_error(channel, detail),
        },
        None => None,
    };
    let session_handle = remote_session.as_ref().map(OwnedEvtHandle::raw);
    let channel_hstring = HSTRING::from(channel);
    let remote = remote_machine.is_some();
    let result = unsafe { EvtClearLog(session_handle, &channel_hstring, PCWSTR::null(), 0) };
    let result = match result {
        Ok(()) => EvtxClearResult {
            channel: channel.to_string(),
            result: EvtxClearStatus::Cleared,
        },
        Err(error) => clear_error_status(channel, &error, remote),
    };
    // Re-probe after the operation. The clear path must not claim that an elevation transition
    // happened or leave the frontend believing the process changed privilege.
    let after = crate::elevation::current_elevation_state();
    if elevation.is_elevated != after.is_elevated {
        log::warn!(
            "event=evtx_clear_elevation_changed channel=\"{}\" before={} after={}",
            channel,
            elevation.is_elevated,
            after.is_elevated
        );
    }
    result
}

// ── Non-Windows stubs ───────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_remote_channels(_machine: &str) -> Result<Vec<EvtxChannelInfo>, String> {
    Err("Remote event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_with_progress(
    _channel: &str,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel(
    _channel: &str,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_filtered(
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn query_channel_filtered_with_progress(
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}
#[cfg(not(target_os = "windows"))]
pub fn query_channel_streamed(
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
    _on_batch: impl FnMut(&mut Vec<EvtxRecord>) -> Result<(), String>,
) -> Result<ChannelScan, String> {
    Err("Live event log queries are only available on Windows.".to_string())
}

#[cfg(not(target_os = "windows"))]
#[allow(clippy::too_many_arguments)]
pub fn query_remote_channel_streamed(
    _machine: &str,
    _channel: &str,
    _filter: &EventQueryFilter,
    _maps: &MapRegistry,
    _providers: &std::sync::RwLock<ProviderStore>,
    _max_events: Option<u64>,
    _on_progress: impl Fn(usize, Option<usize>),
    _on_batch: impl FnMut(&mut Vec<EvtxRecord>) -> Result<(), String>,
) -> Result<ChannelScan, String> {
    Err("Remote event log queries are only available on Windows.".to_string())
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
enum PublisherMetadata {
    Open(OwnedEvtHandle),
    Failed(NativeProviderFailure),
}

#[cfg(target_os = "windows")]
fn format_event_message(
    event_handle: EVT_HANDLE,
    provider_name: &str,
    session: Option<EVT_HANDLE>,
    cache: &mut HashMap<String, PublisherMetadata>,
) -> Result<Option<String>, NativeProviderFailure> {
    if !cache.contains_key(provider_name) {
        let provider = HSTRING::from(provider_name);
        let metadata =
            match unsafe { EvtOpenPublisherMetadata(session, &provider, PCWSTR::null(), 0, 0) } {
                Ok(handle) => PublisherMetadata::Open(OwnedEvtHandle::new(handle)),
                Err(error) => {
                    let failure = publisher_metadata_failure(&error);
                    cache.insert(
                        provider_name.to_string(),
                        PublisherMetadata::Failed(failure),
                    );
                    return Err(failure);
                }
            };
        cache.insert(provider_name.to_string(), metadata);
    }

    let metadata = match cache.get(provider_name) {
        Some(PublisherMetadata::Open(metadata)) => metadata,
        Some(PublisherMetadata::Failed(failure)) => return Err(*failure),
        None => unreachable!("publisher metadata cache insertion failed"),
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
            Err(error) => {
                return Err(event_message_failure(&error));
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn publisher_metadata_failure(error: &Error) -> NativeProviderFailure {
    NativeProviderFailure {
        stage: ProviderMessageStage::OpenPublisherMetadata,
        error_code: win32_code(error),
    }
}

#[cfg(target_os = "windows")]
fn event_message_failure(error: &Error) -> NativeProviderFailure {
    NativeProviderFailure {
        stage: ProviderMessageStage::FormatMessage,
        error_code: win32_code(error),
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
#[cfg(target_os = "windows")]
fn format_remote_error(context: &str, error: &Error) -> String {
    let code = win32_code(error);
    let message = error.message();
    let detail = if message.trim().is_empty() {
        format!("Windows error 0x{:08x}", error.code().0 as u32)
    } else {
        message.trim().to_string()
    };
    format!(
        "{context}: {} ({detail}, error {code})",
        remote_error_kind(code)
    )
}

#[cfg(target_os = "windows")]
fn format_source_error(context: &str, error: &Error, remote: bool) -> String {
    if remote {
        format_remote_error(context, error)
    } else {
        format_error(context, error)
    }
}

#[cfg(target_os = "windows")]
fn format_remote_code(context: &str, code: u32) -> String {
    format!("{context}: {} (error {code})", remote_error_kind(code))
}

#[cfg(target_os = "windows")]
fn format_channel_code(context: &str, code: u32, remote: bool) -> String {
    if remote {
        format_remote_code(context, code)
    } else {
        format!("{context}: Windows error {code}")
    }
}

#[cfg(target_os = "windows")]
fn remote_error_kind(code: u32) -> &'static str {
    match code {
        // ERROR_LOGON_FAILURE, ERROR_INVALID_PASSWORD, ERROR_ACCOUNT_RESTRICTION,
        // ERROR_LOGON_TYPE_NOT_GRANTED.
        1326 | 86 | 1327 | 1385 => "credentials rejected",
        // ERROR_ACCESS_DENIED and ERROR_PRIVILEGE_NOT_HELD.
        5 | 1314 => "access denied",
        // Network/path failures indicate an unavailable computer or Event Log service, not an
        // empty channel and not proof that the caller lacks permission.
        3 | 53 | 64 | 67 | 121 | 1231 | 1232 | 1237 | 1722 | 1723 | 1727 => {
            "remote source unavailable"
        }
        _ => "remote source query failed",
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

#[cfg(test)]
mod portable_tests {
    use std::cell::Cell;

    use super::super::models::{
        EvtxCoverageGapKind, EvtxLevel, EvtxOriginKind, ProviderMessageStage,
    };
    use super::super::parser::DescriptionOutcome;
    use super::*;

    #[test]
    fn provider_gap_preserves_remote_source_stage_code_and_stable_text() {
        let gap = provider_message_gap(
            "remote-host/ForwardedEvents",
            "Example.Provider",
            ProviderMessageStage::OpenPublisherMetadata,
            2,
        );

        assert_eq!(gap.source, "remote-host/ForwardedEvents");
        assert_eq!(gap.kind, EvtxCoverageGapKind::Provider);
        assert_eq!(
            *gap.provider_message.expect("typed provider context"),
            super::super::models::ProviderMessageCoverage {
                provider: "Example.Provider".to_string(),
                stage: ProviderMessageStage::OpenPublisherMetadata,
                error_code: 2,
            }
        );
        assert_eq!(
            gap.reason,
            "provider message for Example.Provider could not be rendered at \
             EvtOpenPublisherMetadata (Windows error 2); raw event data is shown instead"
        );
    }

    #[test]
    fn forwarded_event_uses_its_own_system_channel_for_provider_database_selection() {
        assert_eq!(
            provider_database_channel(Some("Original/Operational"), "ForwardedEvents"),
            "Original/Operational"
        );
        assert_eq!(
            provider_database_channel(None, "Application"),
            "Application"
        );
    }

    #[test]
    fn provider_message_context_serializes_as_typed_camel_case_wire_data() {
        let gap = provider_message_gap(
            "Application",
            "Example.Provider",
            ProviderMessageStage::FormatMessage,
            15027,
        );
        let json = serde_json::to_value(&gap).expect("provider gap serializes");

        assert_eq!(json["providerMessage"]["provider"], "Example.Provider");
        assert_eq!(json["providerMessage"]["stage"], "formatMessage");
        assert_eq!(json["providerMessage"]["errorCode"], 15027);
        assert!(serde_json::to_value(EvtxCoverageGap::new(
            "offline.evtx",
            EvtxCoverageGapKind::Provider,
            "offline provider description unavailable",
        ))
        .expect("offline gap serializes")["providerMessage"]
            .is_null());
    }

    #[test]
    fn complete_database_description_wins_without_calling_native() {
        let native_calls = Cell::new(0);
        let outcome = select_provider_message(
            Ok(Some(DescriptionOutcome::Rendered(
                "database message".to_string(),
            ))),
            "Application",
            "Example.Provider",
            || {
                native_calls.set(native_calls.get() + 1);
                Ok(Some("native message".to_string()))
            },
        );

        assert_eq!(outcome.message.as_deref(), Some("database message"));
        assert!(outcome.provider_gaps.is_empty());
        assert_eq!(native_calls.get(), 0);
    }

    #[test]
    fn database_miss_falls_through_to_native_without_warning() {
        let native_calls = Cell::new(0);
        let outcome = select_provider_message(Ok(None), "Application", "Example.Provider", || {
            native_calls.set(native_calls.get() + 1);
            Ok(Some("native message".to_string()))
        });

        assert_eq!(outcome.message.as_deref(), Some("native message"));
        assert!(outcome.provider_gaps.is_empty());
        assert_eq!(native_calls.get(), 1);
    }

    #[test]
    fn incomplete_database_description_is_healed_by_native_success() {
        let outcome = select_provider_message(
            Ok(Some(DescriptionOutcome::MissingInsertions(vec![2]))),
            "Application",
            "Example.Provider",
            || Ok(Some("native message".to_string())),
        );

        assert_eq!(outcome.message.as_deref(), Some("native message"));
        assert!(outcome.provider_gaps.is_empty());
    }

    #[test]
    fn database_lookup_error_stays_visible_while_native_is_attempted() {
        let native_calls = Cell::new(0);
        let outcome = select_provider_message(
            Err("provider database payload is corrupt".to_string()),
            "Application",
            "Example.Provider",
            || {
                native_calls.set(native_calls.get() + 1);
                Ok(Some("native message".to_string()))
            },
        );

        assert_eq!(outcome.message.as_deref(), Some("native message"));
        assert_eq!(native_calls.get(), 1);
        assert_eq!(outcome.provider_gaps.len(), 1);
        assert_eq!(outcome.provider_gaps[0].kind, EvtxCoverageGapKind::Provider);
        assert!(outcome.provider_gaps[0].provider_message.is_none());
        assert!(outcome.provider_gaps[0]
            .reason
            .contains("provider database lookup failed for Example.Provider"));
    }

    #[test]
    fn native_description_failure_keeps_tail_record_and_typed_diagnostic() {
        let outcome = select_provider_message(Ok(None), "Application", "Example.Provider", || {
            Err(NativeProviderFailure {
                stage: ProviderMessageStage::FormatMessage,
                error_code: 15027,
            })
        });
        let rendered = RenderedTailEvent::new(test_record("raw fallback"), outcome.provider_gaps);

        assert_eq!(rendered.record.message, "raw fallback");
        assert_eq!(rendered.provider_gaps.len(), 1);
        assert_eq!(
            rendered.provider_gaps[0]
                .provider_message
                .as_ref()
                .map(|context| (context.stage, context.error_code)),
            Some((ProviderMessageStage::FormatMessage, 15027))
        );
    }

    #[test]
    fn provider_gap_dedup_normalizes_provider_and_keeps_stages_distinct() {
        let mut dedup = ProviderGapDedup::default();
        let first = provider_message_gap(
            "Application",
            "Example.Provider",
            ProviderMessageStage::OpenPublisherMetadata,
            2,
        );
        let repeated = provider_message_gap(
            "Application",
            " example.provider ",
            ProviderMessageStage::OpenPublisherMetadata,
            15002,
        );
        let distinct_stage = provider_message_gap(
            "Application",
            "EXAMPLE.PROVIDER",
            ProviderMessageStage::FormatMessage,
            2,
        );

        assert!(dedup.keep(&first));
        assert!(!dedup.keep(&repeated));
        assert!(dedup.keep(&distinct_stage));
    }

    #[test]
    fn subscription_batch_keeps_boundary_record_and_provider_diagnostic_together() {
        let mut pending = PendingTailBatch::default();
        for _ in 0..EVENT_FETCH_BATCH - 1 {
            assert!(!pending.push_rendered(test_record("raw fallback"), Vec::new()));
        }
        let gap = provider_message_gap(
            "Application",
            "Example.Provider",
            ProviderMessageStage::FormatMessage,
            15027,
        );

        assert!(
            pending.push_rendered(test_record("raw fallback"), vec![format_provider_gap(&gap)],)
        );
        let (records, gaps) = pending.take();

        assert_eq!(records.len(), EVENT_FETCH_BATCH);
        assert_eq!(gaps, vec![format_provider_gap(&gap)]);
    }

    fn test_record(message: &str) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            event_record_id: 7,
            event_record_id_text: Some("7".to_string()),
            timestamp: String::new(),
            timestamp_epoch: 0,
            provider: "Example.Provider".to_string(),
            channel: "Application".to_string(),
            event_id: 7,
            level: EvtxLevel::Information,
            computer: "HOST".to_string(),
            message: message.to_string(),
            event_data: Vec::new(),
            raw_xml: "<Event/>".to_string(),
            source_label: "Live".to_string(),
            origin_kind: EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;
    use windows::core::HRESULT;

    #[test]
    fn live_query_application() {
        let channels = enumerate_channels().expect("enumerate should work");
        println!("Total channels: {}", channels.len());
        let has_app = channels.iter().any(|c| c.name == "Application");
        println!("Has Application channel: {has_app}");

        let providers = std::sync::RwLock::new(ProviderStore::default());
        let records = query_channel("Application", &MapRegistry::new(), &providers, Some(3))
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
    #[test]
    fn remote_render_and_metadata_errors_preserve_source_taxonomy() {
        assert!(format_remote_code("EvtRender", 5).contains("access denied"));
        assert!(format_remote_code("EvtOpenPublisherMetadata", 53)
            .contains("remote source unavailable"));
    }
    #[test]
    fn cached_publisher_metadata_failure_is_reused_without_rpc() {
        let mut cache = HashMap::from([(
            "provider".to_string(),
            PublisherMetadata::Failed(NativeProviderFailure {
                stage: ProviderMessageStage::OpenPublisherMetadata,
                error_code: 5,
            }),
        )]);
        let error = format_event_message(EVT_HANDLE(0), "provider", None, &mut cache)
            .expect_err("cached metadata failure must remain an error");
        assert_eq!(error.stage, ProviderMessageStage::OpenPublisherMetadata);
        assert_eq!(error.error_code, 5);
        assert_eq!(cache.len(), 1);
    }
    #[test]
    fn native_error_codes_keep_the_api_stage_that_produced_them() {
        for code in [2, 15002] {
            let failure =
                publisher_metadata_failure(&Error::from_hresult(HRESULT::from_win32(code)));
            assert_eq!(failure.stage, ProviderMessageStage::OpenPublisherMetadata);
            assert_eq!(failure.error_code, code);
        }
        for code in [2, 15027] {
            let failure = event_message_failure(&Error::from_hresult(HRESULT::from_win32(code)));
            assert_eq!(failure.stage, ProviderMessageStage::FormatMessage);
            assert_eq!(failure.error_code, code);
        }
    }
    #[test]
    fn stopping_an_unknown_tail_returns_an_error() {
        let error = stop_channel_tail("missing-request", "Application")
            .expect_err("missing tails must not report a clean stop");
        assert!(error.contains("was not found"));
    }
    #[test]
    fn tail_delivery_gaps_are_replayed_and_cleared() {
        let stored = Mutex::new(vec!["previous gap".to_string()]);
        let mut gaps = vec!["current gap".to_string()];
        merge_tail_coverage_gaps(&stored, &mut gaps);
        assert_eq!(gaps, vec!["current gap", "previous gap"]);

        remember_tail_coverage_gaps(
            &stored,
            &["current gap".to_string(), "delivery failed".to_string()],
        );
        let mut replay = Vec::new();
        merge_tail_coverage_gaps(&stored, &mut replay);
        assert_eq!(
            replay,
            vec![
                "previous gap".to_string(),
                "current gap".to_string(),
                "delivery failed".to_string(),
            ]
        );

        clear_tail_coverage_gaps(&stored);
        assert!(stored.lock().expect("gap state").is_empty());
    }

    #[test]
    fn remote_machine_names_reject_control_characters() {
        assert!(normalize_remote_machine_name("host\0suffix").is_err());
        assert!(normalize_remote_machine_name("host\nsuffix").is_err());
        assert_eq!(normalize_remote_machine_name(r"\\host").unwrap(), "host");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn subscription_coverage_gaps_are_bounded_and_coalesced() {
        let mut gaps = Vec::new();
        for index in 0..MAX_TAIL_COVERAGE_GAPS {
            push_bounded_tail_coverage_gap(&mut gaps, format!("gap-{index}"));
        }

        assert_eq!(gaps.len(), MAX_TAIL_COVERAGE_GAPS);
        assert_eq!(gaps[0], "gap-0");
        assert_eq!(
            gaps.last().expect("coalesced gap"),
            "<live tail coverage>: 1 additional live tail diagnostics were coalesced"
        );

        push_bounded_tail_coverage_gap(&mut gaps, "overflow".to_string());
        assert_eq!(
            gaps.last().expect("updated coalesced gap"),
            "<live tail coverage>: 2 additional live tail diagnostics were coalesced"
        );
        let mut full = (0..MAX_TAIL_COVERAGE_GAPS)
            .map(|index| format!("raw-{index}"))
            .collect();
        push_bounded_tail_coverage_gap(&mut full, "raw-overflow".to_string());
        assert_eq!(
            full.last().expect("raw coalesced gap"),
            "<live tail coverage>: 2 additional live tail diagnostics were coalesced"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn subscription_pending_batch_is_bounded_and_drains_at_fetch_limit() {
        let mut pending = PendingTailBatch::default();
        for event_record_id in 0..EVENT_FETCH_BATCH {
            assert!(!pending.is_full());
            let should_flush = pending.push_rendered(
                identity_test_record(event_record_id as u64, None, "<Event/>"),
                Vec::new(),
            );
            assert_eq!(should_flush, event_record_id + 1 == EVENT_FETCH_BATCH);
        }

        assert!(pending.is_ready());
        let (records, gaps) = pending.take();
        assert_eq!(records.len(), EVENT_FETCH_BATCH);
        assert!(gaps.is_empty());
        assert!(pending.records.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn subscription_pending_record_is_retried_after_batch_drain() {
        let mut pending = PendingTailBatch::default();
        for event_record_id in 0..EVENT_FETCH_BATCH {
            assert!(!pending.is_full());
            pending.push_rendered(
                identity_test_record(event_record_id as u64, None, "<Event/>"),
                Vec::new(),
            );
        }

        assert!(pending.is_full());
        let next_record = identity_test_record(EVENT_FETCH_BATCH as u64, None, "<Event/>");
        let (records, gaps) = pending.take();
        assert_eq!(records.len(), EVENT_FETCH_BATCH);
        assert!(gaps.is_empty());
        assert!(!pending.is_full());
        assert!(!pending.push_rendered(next_record, Vec::new()));
        assert_eq!(pending.records.len(), 1);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn polling_identity_keeps_lossless_large_id_text() {
        let mut first =
            identity_test_record(u64::MAX, Some(u64::MAX.to_string()), "<Event>A</Event>");
        let mut second = first.clone();
        second.event_record_id_text = Some("18446744073709551616".to_string());
        assert_ne!(
            polling_record_identity(&first),
            polling_record_identity(&second)
        );
        first.event_record_id_text = None;
        second.event_record_id_text = None;
        assert_eq!(
            polling_record_identity(&first),
            polling_record_identity(&second)
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn polling_identity_keeps_distinct_missing_id_xml_records() {
        let first = identity_test_record(0, Some("0".to_string()), "<Event>A</Event>");
        let second = identity_test_record(0, Some("0".to_string()), "<Event>B</Event>");
        assert_ne!(
            polling_record_identity(&first),
            polling_record_identity(&second)
        );
    }

    #[cfg(target_os = "windows")]
    fn identity_test_record(
        event_record_id: u64,
        event_record_id_text: Option<String>,
        raw_xml: &str,
    ) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            event_record_id,
            event_record_id_text,
            timestamp: String::new(),
            timestamp_epoch: 0,
            provider: String::new(),
            channel: String::new(),
            event_id: 0,
            level: super::super::models::EvtxLevel::Information,
            computer: String::new(),
            message: String::new(),
            event_data: Vec::new(),
            raw_xml: raw_xml.to_string(),
            source_label: String::new(),
            origin_kind: super::super::models::EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
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

    fn no_providers() -> std::sync::RwLock<ProviderStore> {
        std::sync::RwLock::new(ProviderStore::default())
    }

    #[test]
    #[ignore = "requires a live Windows Event Log service with events"]
    fn an_unfiltered_query_returns_records() {
        let scan =
            query_channel(CHANNEL, &no_maps(), &no_providers(), Some(50)).expect("query succeeds");
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
        let records = query_channel_filtered(
            CHANNEL,
            &EventQueryFilter::default(),
            &no_maps(),
            &no_providers(),
            Some(200),
        )
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
    #[test]
    fn remote_login_uses_the_current_windows_credentials() {
        let mut server: Vec<u16> = "lab-host"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let login = remote_login(&mut server);

        assert!(!login.Server.0.is_null());
        assert!(login.User.0.is_null());
        assert!(login.Domain.0.is_null());
        assert!(login.Password.0.is_null());
        assert_eq!(login.Flags, EvtRpcLoginAuthDefault.0);
    }

    #[test]
    fn remote_errors_keep_credentials_access_and_availability_distinct() {
        assert_eq!(remote_error_kind(1326), "credentials rejected");
        assert_eq!(remote_error_kind(5), "access denied");
        assert_eq!(remote_error_kind(53), "remote source unavailable");
    }

    #[test]
    #[ignore = "requires a reachable Windows Event Log source"]
    fn a_remote_session_can_enumerate_and_query_a_channel() {
        let machine = std::env::var("CMTRACE_REMOTE_MACHINE")
            .expect("set CMTRACE_REMOTE_MACHINE for the Windows remote-source scenario");
        let normalized = normalize_remote_machine_name(&machine).expect("valid remote machine");
        let channels = enumerate_remote_channels(&machine).expect("remote enumeration succeeds");
        assert!(
            channels.iter().any(|channel| channel.name == CHANNEL),
            "remote source should expose {CHANNEL}"
        );
        assert!(
            channels.iter().all(|channel| {
                channel.source_type
                    == ChannelSourceType::Remote {
                        machine: normalized.clone(),
                    }
            }),
            "remote channels must retain normalized machine provenance"
        );
        let mut received = Vec::new();
        let scan = query_remote_channel_streamed(
            &machine,
            CHANNEL,
            &EventQueryFilter::default(),
            &no_maps(),
            &no_providers(),
            Some(10),
            |_, _| {},
            |batch| {
                received.append(batch);
                Ok(())
            },
        )
        .expect("remote query succeeds");
        let records = if received.is_empty() {
            scan.records
        } else {
            received
        };
        if records.is_empty() {
            assert_eq!(scan.delivered, 0, "empty remote channels must be explicit");
        } else {
            assert!(records
                .iter()
                .all(|record| record.source_label == format!("Remote: {normalized}")));
        }
    }

    #[test]
    #[ignore = "requires a reachable Windows source and intentionally invalid credentials"]
    fn remote_credential_failure_is_not_reported_as_an_empty_channel() {
        let machine = std::env::var("CMTRACE_REMOTE_DENIED_MACHINE")
            .expect("set CMTRACE_REMOTE_DENIED_MACHINE for the Windows credential scenario");
        let error = enumerate_remote_channels(&machine).expect_err("remote access should fail");
        assert!(
            error.contains("credentials rejected") || error.contains("access denied"),
            "remote denial must retain the native credential/access classification: {error}"
        );
        assert!(!error.contains("0 events"));
    }

    #[ignore = "requires a reachable Windows Event Log source"]
    #[test]
    fn remote_session_and_event_handles_are_closed_at_scope_end() {
        let machine = std::env::var("CMTRACE_REMOTE_MACHINE")
            .expect("set CMTRACE_REMOTE_MACHINE for the Windows cleanup scenario");
        let normalized = normalize_remote_machine_name(&machine).expect("valid remote machine");
        for _attempt in 0..3 {
            let mut received = Vec::new();
            let scan = query_remote_channel_streamed(
                &machine,
                CHANNEL,
                &EventQueryFilter::default(),
                &no_maps(),
                &no_providers(),
                Some(10),
                |_, _| {},
                |batch| {
                    received.append(batch);
                    Ok(())
                },
            )
            .expect("remote query succeeds");
            let records = if received.is_empty() {
                scan.records
            } else {
                received
            };
            assert!(
                scan.delivered >= records.len(),
                "streamed delivery count must include every returned record"
            );
            if records.is_empty() {
                assert_eq!(scan.delivered, 0);
            } else {
                assert!(records
                    .iter()
                    .all(|record| record.source_label == format!("Remote: {normalized}")));
            }

            let (session, opened_machine) = open_remote_session(&machine).expect("session reopens");
            assert_eq!(opened_machine, normalized);
            assert_ne!(session.raw().0, 0);
            drop(session);
        }
        // Repeated successful queries and session opens exercise the RAII guards: a leaked session,
        // query, event, or publisher-metadata handle would eventually exhaust the Event Log RPC
        // resource quota rather than pass this loop.
    }
}
