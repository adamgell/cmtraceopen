use crate::intune::apps::windows::ime::models::EventLogAnalysis;

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
    use crate::intune::apps::windows::ime::models::{
        EventLogAnalysisSource, EventLogLiveQueryChannelResult, EventLogLiveQueryMetadata,
        EventLogLiveQueryStatus,
    };
    use crate::intune::eventlog_win32;
    use crate::intune::evtx_parser;

    let mut all_entries = Vec::new();
    let mut channel_results = Vec::new();
    let mut entry_id: u64 = 0;

    for channel_path in DSREGCMD_EVENT_CHANNELS {
        match eventlog_win32::query_live_channel(channel_path, MAX_ENTRIES_PER_CHANNEL) {
            Ok(query_result) => {
                channel_results.push(process_channel_result(
                    channel_path,
                    &query_result,
                    &mut all_entries,
                    &mut entry_id,
                ));
            }
            Err(error) => {
                log::error!(
                    "event=dsregcmd_event_log_query_failed channel={} error={}",
                    channel_path,
                    error
                );

                channel_results.push(EventLogLiveQueryChannelResult {
                    channel: crate::intune::apps::windows::ime::models::EventLogChannel::from_channel_string(
                        channel_path,
                    ),
                    channel_display: crate::intune::apps::windows::ime::models::EventLogChannel::from_channel_string(
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
    let with_results = channels_with_results_count(&channel_results);
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

#[cfg(any(target_os = "windows", test))]
fn channels_with_results_count(
    channels: &[crate::intune::apps::windows::ime::models::EventLogLiveQueryChannelResult],
) -> u32 {
    u32::try_from(
        channels
            .iter()
            .filter(|channel| channel.entry_count > 0)
            .count(),
    )
    .unwrap_or(0)
}

#[cfg(any(target_os = "windows", test))]
fn process_channel_result(
    channel_path: &str,
    query_result: &crate::intune::eventlog_win32::LiveChannelQueryResult,
    all_entries: &mut Vec<crate::intune::apps::windows::ime::models::EventLogEntry>,
    entry_id: &mut u64,
) -> crate::intune::apps::windows::ime::models::EventLogLiveQueryChannelResult {
    use crate::intune::apps::windows::ime::models::EventLogLiveQueryChannelResult;
    use crate::intune::evtx_parser;
    let mut channel_entry_count = 0u32;
    let mut parse_failure_count = 0usize;

    for record in &query_result.records {
        if let Some(entry) = evtx_parser::parse_live_event_record(
            &record.xml,
            &record.source_file,
            record.rendered_message.clone(),
            *entry_id,
            channel_path,
        ) {
            all_entries.push(entry);
            *entry_id += 1;
            channel_entry_count += 1;
        } else {
            parse_failure_count += 1;
        }
    }

    let (status, entry_count, error_message) = evtx_parser::live_channel_outcome(
        channel_entry_count,
        query_result.partial_detail.as_deref(),
        parse_failure_count,
    );

    EventLogLiveQueryChannelResult {
        channel: crate::intune::apps::windows::ime::models::EventLogChannel::from_channel_string(
            channel_path,
        ),
        channel_display:
            crate::intune::apps::windows::ime::models::EventLogChannel::from_channel_string(
                channel_path,
            )
            .display_name()
            .to_string(),
        channel_path: channel_path.to_string(),
        source_file: query_result.source_file.clone(),
        status,
        entry_count,
        error_message,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn collect_dsregcmd_event_logs() -> Option<EventLogAnalysis> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::windows::ime::models::EventLogLiveQueryStatus;
    use crate::intune::eventlog_win32::{LiveChannelQueryResult, LiveEventRecord};

    const CHANNEL: &str = "Microsoft-Windows-AAD/Operational";
    // Anchor: evtx_parser::tests::parse_live_event_record_extracts_rendered_xml_fields.
    // Only the channel is changed for this lane; parse failures remove its timestamp.
    const XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider'/><EventID>813</EventID><Level>2</Level><TimeCreated SystemTime='2026-03-12T16:01:23.456Z'/><Channel>Microsoft-Windows-AAD/Operational</Channel><Computer>CONTOSO-01</Computer><Correlation ActivityID='{123}'/></System><RenderingInfo Culture='en-US'><Message>Enrollment failed &amp; needs attention</Message></RenderingInfo></Event>"#;

    fn check(
        records: Vec<String>,
        partial: Option<&str>,
        retained: u32,
        status: EventLogLiveQueryStatus,
        detail: Option<&str>,
    ) {
        let query = LiveChannelQueryResult {
            channel_path: CHANNEL.to_string(),
            source_file: "channel-source".to_string(),
            records: records
                .into_iter()
                .map(|xml| LiveEventRecord {
                    xml,
                    source_file: "record-source".to_string(),
                    rendered_message: Some("rendered message".to_string()),
                })
                .collect(),
            partial_detail: partial.map(str::to_string),
        };
        let mut entries = Vec::new();
        let mut next_id = 7;
        let result = process_channel_result(CHANNEL, &query, &mut entries, &mut next_id);
        assert_eq!(result.entry_count, retained);
        assert_eq!(
            channels_with_results_count(std::slice::from_ref(&result)),
            u32::from(retained > 0)
        );
        assert_eq!(entries.len(), retained as usize);
        assert_eq!(next_id, 7 + u64::from(retained));
        assert_eq!(result.channel_path, CHANNEL);
        assert_eq!(result.source_file, "channel-source");
        for (offset, entry) in entries.into_iter().enumerate() {
            assert_eq!(entry.id, 7 + offset as u64);
            assert_eq!(entry.source_file, "record-source");
            assert_eq!(entry.message, "rendered message");
            assert_eq!(entry.event_id, 813);
        }
        assert_eq!(result.status, status);
        assert_eq!(result.error_message.as_deref(), detail);
    }

    #[test]
    fn complete_channels_report_success_or_empty() {
        check(
            vec![XML.to_string()],
            None,
            1,
            EventLogLiveQueryStatus::Success,
            None,
        );
        check(vec![], None, 0, EventLogLiveQueryStatus::Empty, None);
    }
    #[test]
    fn partial_channels_report_failure_with_retained_records() {
        for retained in 0..=2 {
            check(
                vec![XML.to_string(); retained],
                Some("read interrupted"),
                retained as u32,
                EventLogLiveQueryStatus::Failed,
                Some("read interrupted"),
            );
        }
    }
    #[test]
    fn unparseable_records_report_failure_with_retained_records() {
        for retained in 0..=2 {
            let mut records =
                vec![XML.replace("<TimeCreated SystemTime='2026-03-12T16:01:23.456Z'/>", "")];
            records.extend(vec![XML.to_string(); retained]);
            check(
                records,
                None,
                retained as u32,
                EventLogLiveQueryStatus::Failed,
                Some("1 Windows Event Log record(s) could not be parsed"),
            );
        }
    }
    #[test]
    fn partial_and_parse_failure_details_are_preserved() {
        check(
            vec![
                XML.to_string(),
                XML.replace("<TimeCreated SystemTime='2026-03-12T16:01:23.456Z'/>", ""),
            ],
            Some("read interrupted"),
            1,
            EventLogLiveQueryStatus::Failed,
            Some("read interrupted. 1 Windows Event Log record(s) could not be parsed"),
        );
    }
}
