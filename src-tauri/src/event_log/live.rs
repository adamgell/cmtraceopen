use super::models::{EvtxChannelInfo, EvtxRecord};

/// Enumerate available Windows Event Log channels.
///
/// Uses `wevtapi.dll` functions `EvtOpenChannelEnum` and `EvtNextChannelPath`
/// to discover all registered channels on the system.
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    // Implementation uses wevtapi.dll — Windows only
    // EvtOpenChannelEnum, EvtNextChannelPath
    Err("Live event log queries are not yet implemented".to_string())
}

/// Query a specific Windows Event Log channel for recent events.
///
/// Uses `wevtapi.dll` functions `EvtQuery` and `EvtRender` to read
/// events from the specified channel.
pub fn query_channel(
    _channel: &str,
    _max_events: Option<u64>,
) -> Result<Vec<EvtxRecord>, String> {
    Err("Live event log queries are not yet implemented".to_string())
}
