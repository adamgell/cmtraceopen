use crate::intune::models::EventLogAnalysis;

#[cfg(target_os = "windows")]
const DSREGCMD_EVENT_CHANNELS: &[&str] = &[
    "Microsoft-Windows-AAD/Operational",
    "Microsoft-Windows-User Device Registration/Admin",
    "Microsoft-Windows-Crypto-DPAPI/Operational",
    "Microsoft-Windows-Kerberos/Operational",
    "System",
];

#[cfg(target_os = "windows")]
const MAX_ENTRIES_PER_CHANNEL: usize = 200;

#[cfg(target_os = "windows")]
pub fn collect_dsregcmd_event_logs() -> Option<EventLogAnalysis> {
    use crate::intune::eventlog_win32;
    use crate::intune::evtx_parser;
    use crate::intune::models::{
        EventLogAnalysisSource, EventLogLiveQueryChannelResult, EventLogLiveQueryMetadata,
        EventLogLiveQueryStatus,
    };

    let mut all_entries = Vec::new();
    let mut channel_results = Vec::new();
    let mut entry_id: u64 = 0;

    for channel_path in DSREGCMD_EVENT_CHANNELS {
        match eventlog_win32::query_live_channel(channel_path, MAX_ENTRIES_PER_CHANNEL) {
            Ok(query_result) => {
                let mut channel_entry_count = 0u32;

                for record in &query_result.records {
                    if let Some(entry) = evtx_parser::parse_live_event_record(
                        &record.xml,
                        &record.source_file,
                        record.rendered_message.clone(),
                        entry_id,
                        channel_path,
                    ) {
                        all_entries.push(entry);
                        entry_id += 1;
                        channel_entry_count += 1;
                    }
                }

                let status = if channel_entry_count > 0 {
                    EventLogLiveQueryStatus::Success
                } else {
                    EventLogLiveQueryStatus::Empty
                };

                channel_results.push(EventLogLiveQueryChannelResult {
                    channel: crate::intune::models::EventLogChannel::from_channel_string(
                        channel_path,
                    ),
                    channel_display: crate::intune::models::EventLogChannel::from_channel_string(
                        channel_path,
                    )
                    .display_name()
                    .to_string(),
                    channel_path: channel_path.to_string(),
                    source_file: query_result.source_file.clone(),
                    status,
                    entry_count: channel_entry_count,
                    error_message: None,
                });
            }
            Err(error) => {
                log::error!(
                    "event=dsregcmd_event_log_query_failed channel={} error={}",
                    channel_path,
                    error
                );

                channel_results.push(EventLogLiveQueryChannelResult {
                    channel: crate::intune::models::EventLogChannel::from_channel_string(
                        channel_path,
                    ),
                    channel_display: crate::intune::models::EventLogChannel::from_channel_string(
                        channel_path,
                    )
                    .display_name()
                    .to_string(),
                    channel_path: channel_path.to_string(),
                    source_file: String::new(),
                    status: EventLogLiveQueryStatus::Failed,
                    entry_count: 0,
                    error_message: Some(error.to_string()),
                });
            }
        }
    }

    let attempted = u32::try_from(channel_results.len()).unwrap_or(u32::MAX);
    let successful = u32::try_from(
        channel_results
            .iter()
            .filter(|r| !matches!(r.status, EventLogLiveQueryStatus::Failed))
            .count(),
    )
    .unwrap_or(0);
    let with_results = u32::try_from(
        channel_results
            .iter()
            .filter(|r| matches!(r.status, EventLogLiveQueryStatus::Success))
            .count(),
    )
    .unwrap_or(0);
    let failed = u32::try_from(
        channel_results
            .iter()
            .filter(|r| matches!(r.status, EventLogLiveQueryStatus::Failed))
            .count(),
    )
    .unwrap_or(0);

    let live_query = Some(EventLogLiveQueryMetadata {
        attempted_channel_count: attempted,
        successful_channel_count: successful,
        channels_with_results_count: with_results,
        failed_channel_count: failed,
        per_channel_entry_limit: u32::try_from(MAX_ENTRIES_PER_CHANNEL).unwrap_or(u32::MAX),
        channels: channel_results,
    });

    evtx_parser::build_event_log_analysis(
        all_entries,
        u32::try_from(DSREGCMD_EVENT_CHANNELS.len()).unwrap_or(0),
        EventLogAnalysisSource::Live,
        live_query,
    )
}

#[cfg(not(target_os = "windows"))]
pub fn collect_dsregcmd_event_logs() -> Option<EventLogAnalysis> {
    None
}
