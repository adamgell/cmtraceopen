//! Times a live scan so a performance claim can be checked instead of asserted.
//!
//! This exists because the epic's Phase 1 gate requires a reproducible scenario with recorded
//! numbers, and because every change in the live path so far has been argued from reading the code
//! rather than from measurement. Wall clock is printed here; peak working set is measured by the
//! caller, since a process cannot observe its own peak as reliably as the parent can.
//!
//! Windows only, because there is no Event Log service to scan anywhere else. On other platforms it
//! prints why it did nothing rather than reporting a zero that would look like a fast scan.
//!
//! ```text
//! cargo run --release --example evtx_scan --features event-log -- --days 7
//! cargo run --release --example evtx_scan --features event-log -- --days 7 --channel Application
//! ```

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let value_of = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let days: u64 = value_of("--days").and_then(|v| v.parse().ok()).unwrap_or(7);
    let only_channel = value_of("--channel");
    // Absent means no cap, which is the case the gate cares about: the cap is the thing being
    // replaced, so measuring with it in place would measure the cap rather than the scan.
    let max_events: Option<u64> = value_of("--max").and_then(|v| v.parse().ok());

    run(days, only_channel, max_events);
}

#[cfg(target_os = "windows")]
fn run(days: u64, only_channel: Option<String>, max_events: Option<u64>) {
    use app_lib::event_log::live;
    use cmtraceopen_parser::event_query::{EventQueryFilter, TimeWindow};
    use cmtraceopen_parser::eventmap::MapRegistry;
    use std::time::Instant;

    let enumerated = Instant::now();
    let channels = match live::enumerate_channels() {
        Ok(channels) => channels,
        Err(error) => {
            eprintln!("enumerate_channels failed: {error}");
            std::process::exit(1);
        }
    };
    let channels: Vec<String> = channels
        .into_iter()
        .map(|c| c.name)
        .filter(|name| only_channel.as_ref().is_none_or(|only| only == name))
        .collect();
    let enumerate_ms = enumerated.elapsed().as_millis();

    let Some(milliseconds) = days.checked_mul(24 * 60 * 60 * 1000) else {
        eprintln!("--days is too large");
        std::process::exit(2);
    };

    let filter = EventQueryFilter {
        time: Some(TimeWindow::Last { milliseconds }),
        ..Default::default()
    };

    // No maps loaded. The map engine has its own benchmark; mixing it in here would make a change
    // to either one move this number.
    let maps = MapRegistry::new();

    let mut total = 0usize;
    let mut failed = 0usize;
    let mut slowest = (String::new(), 0u128);
    // Attributing memory rather than guessing at it. Every record carries the whole rendered XML it
    // was built from, and that string is then serialized to the frontend and held there too, so if
    // it dominates the record it dominates three copies rather than one.
    let mut xml_bytes = 0usize;
    let mut field_bytes = 0usize;
    let mut widest_channel = (String::new(), 0usize);
    // A channel read only partly is neither a success nor a failure, and counting it as
    // either hides it. The scan's own truncations are the thing most likely to make a
    // faster number look like an improvement.
    let mut gap_reports = 0usize;

    let started = Instant::now();
    for channel in &channels {
        let at = Instant::now();
        match live::query_channel_filtered(channel, &filter, &maps, max_events) {
            Ok(scan) => {
                let records = scan.records;
                gap_reports += scan.gaps.len();
                total += records.len();
                if records.len() > widest_channel.1 {
                    widest_channel = (channel.clone(), records.len());
                }
                for record in &records {
                    xml_bytes += record.raw_xml.len();
                    field_bytes += record.message.len()
                        + record
                            .event_data
                            .iter()
                            .map(|f| f.name.len() + f.value.len())
                            .sum::<usize>();
                }
            }
            // A channel that cannot be read is counted, not ignored. Treating it as zero events
            // would report a faster scan of a smaller corpus as an improvement.
            Err(_) => failed += 1,
        }
        let took = at.elapsed().as_millis();
        if took > slowest.1 {
            slowest = (channel.clone(), took);
        }
    }
    let elapsed = started.elapsed();

    let per_event_us = if total > 0 {
        elapsed.as_micros() as f64 / total as f64
    } else {
        0.0
    };

    println!("days={days}");
    println!("channels_scanned={}", channels.len());
    println!("channels_failed={failed}");
    println!("channels_with_gaps={gap_reports}");
    println!("events={total}");
    println!("enumerate_ms={enumerate_ms}");
    println!("scan_ms={}", elapsed.as_millis());
    println!("per_event_us={per_event_us:.2}");
    println!("slowest_channel={} ({}ms)", slowest.0, slowest.1);
    println!(
        "widest_channel={} ({} events)",
        widest_channel.0, widest_channel.1
    );
    println!("raw_xml_mb={:.1}", xml_bytes as f64 / (1024.0 * 1024.0));
    println!(
        "message_and_fields_mb={:.1}",
        field_bytes as f64 / (1024.0 * 1024.0)
    );
    if xml_bytes + field_bytes > 0 {
        let share = xml_bytes as f64 / (xml_bytes + field_bytes) as f64 * 100.0;
        println!("raw_xml_share_pct={share:.0}");
    }
}

#[cfg(not(target_os = "windows"))]
fn run(_days: u64, _only_channel: Option<String>, _max_events: Option<u64>) {
    eprintln!("evtx_scan needs a Windows Event Log service; nothing to measure on this platform.");
    std::process::exit(2);
}
