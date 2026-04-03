use std::path::Path;

use evtx::EvtxParser;
use serde_json::Value;

use super::models::{
    ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxParseResult, EvtxRecord,
};

/// Maximum entries to parse from a single .evtx file to prevent memory issues.
const MAX_ENTRIES_PER_FILE: usize = 100_000;

/// Parse one or more .evtx files and return a unified result.
pub fn parse_evtx_files(paths: &[String]) -> Result<EvtxParseResult, String> {
    let mut all_records = Vec::new();
    let mut channels = Vec::new();
    let mut parse_errors = 0u32;

    for path_str in paths {
        let path = Path::new(path_str);
        match parse_single_file(path) {
            Ok((records, file_parse_errors)) => {
                parse_errors += file_parse_errors;
                let source_label = path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| path_str.clone());

                // Build one EvtxChannelInfo per distinct channel string found in the records,
                // so that ChannelPicker can match against r.channel values.
                let mut channel_counts: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for r in &records {
                    *channel_counts.entry(r.channel.clone()).or_insert(0) += 1;
                }

                if channel_counts.is_empty() {
                    // No records — still emit an entry keyed by the file basename so the
                    // file appears in the picker.
                    channels.push(EvtxChannelInfo {
                        name: source_label.clone(),
                        event_count: 0,
                        source_type: ChannelSourceType::File {
                            path: path_str.clone(),
                        },
                    });
                } else {
                    for (channel_name, count) in channel_counts {
                        channels.push(EvtxChannelInfo {
                            name: channel_name,
                            event_count: count,
                            source_type: ChannelSourceType::File {
                                path: path_str.clone(),
                            },
                        });
                    }
                }

                all_records.extend(records);
            }
            Err(e) => {
                log::warn!("event=evtx_parse_error file=\"{}\" error=\"{}\"", path_str, e);
                parse_errors += 1;
            }
        }
    }

    // Sort all records by timestamp and reassign sequential IDs
    all_records.sort_by_key(|r| r.timestamp_epoch);
    for (i, record) in all_records.iter_mut().enumerate() {
        record.id = i as u64;
    }

    let total_records = all_records.len() as u64;

    Ok(EvtxParseResult {
        records: all_records,
        channels,
        total_records,
        parse_errors,
        error_messages: vec![],
    })
}

/// Parse a single .evtx file into a Vec of EvtxRecord and a count of per-record parse errors.
fn parse_single_file(path: &Path) -> Result<(Vec<EvtxRecord>, u32), String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_label = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut records = Vec::new();
    let mut parse_errors = 0u32;

    for record_result in parser.records_json_value() {
        if records.len() >= MAX_ENTRIES_PER_FILE {
            log::warn!(
                "event=evtx_entry_cap_reached file=\"{}\" cap={}",
                path.display(),
                MAX_ENTRIES_PER_FILE
            );
            break;
        }

        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "event=evtx_record_skip file=\"{}\" error=\"{}\"",
                    path.display(),
                    e
                );
                parse_errors += 1;
                continue;
            }
        };

        let json = &record.data;
        let system = &json["Event"]["System"];
        let event_data_val = &json["Event"]["EventData"];

        let provider = system["Provider"]["#attributes"]["Name"]
            .as_str()
            .unwrap_or("Unknown")
            .to_string();

        let channel = system["Channel"]
            .as_str()
            .unwrap_or("Unknown")
            .to_string();

        let event_id = extract_event_id(system);

        let level = system["Level"].as_u64().unwrap_or(0) as u8;
        let evtx_level = EvtxLevel::from_level_value(level);

        let computer = system["Computer"]
            .as_str()
            .unwrap_or("Unknown")
            .to_string();

        let timestamp_str = system["TimeCreated"]["#attributes"]["SystemTime"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let timestamp_epoch = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0);

        let event_record_id = record.event_record_id;

        let event_data = extract_event_data(event_data_val);
        let message = build_message(&event_data);

        // Build raw XML placeholder from JSON (actual XML not available via json_value API)
        let raw_xml = serde_json::to_string_pretty(json).unwrap_or_default();

        records.push(EvtxRecord {
            id: 0, // Will be reassigned after sorting
            event_record_id,
            timestamp: timestamp_str,
            timestamp_epoch,
            provider,
            channel,
            event_id,
            level: evtx_level,
            computer,
            message,
            event_data,
            raw_xml,
            source_label: source_label.clone(),
        });
    }

    Ok((records, parse_errors))
}

/// Extract EventID which can appear as `{"#text": N}` or just `N`.
fn extract_event_id(system: &Value) -> u32 {
    if let Some(id) = system["EventID"].as_u64() {
        return id as u32;
    }
    if let Some(id) = system["EventID"]["#text"].as_u64() {
        return id as u32;
    }
    if let Some(s) = system["EventID"]["#text"].as_str() {
        return s.parse().unwrap_or(0);
    }
    0
}

/// Extract EventData fields as key-value pairs.
fn extract_event_data(event_data: &Value) -> Vec<EvtxField> {
    let mut fields = Vec::new();

    if let Some(obj) = event_data.as_object() {
        for (key, value) in obj {
            if key == "#attributes" {
                continue;
            }
            let val_str = match value {
                Value::String(s) => s.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            if !val_str.is_empty() {
                fields.push(EvtxField {
                    name: key.clone(),
                    value: val_str,
                });
            }
        }
    }

    fields
}

/// Build a human-readable message from the first few EventData fields.
fn build_message(event_data: &[EvtxField]) -> String {
    event_data
        .iter()
        .take(5)
        .map(|f| format!("{}: {}", f.name, f.value))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evtx_level_from_level_value() {
        assert_eq!(EvtxLevel::from_level_value(1), EvtxLevel::Critical);
        assert_eq!(EvtxLevel::from_level_value(2), EvtxLevel::Error);
        assert_eq!(EvtxLevel::from_level_value(3), EvtxLevel::Warning);
        assert_eq!(EvtxLevel::from_level_value(4), EvtxLevel::Information);
        assert_eq!(EvtxLevel::from_level_value(5), EvtxLevel::Verbose);
        assert_eq!(EvtxLevel::from_level_value(0), EvtxLevel::Information);
        assert_eq!(EvtxLevel::from_level_value(255), EvtxLevel::Information);
    }

    #[test]
    fn test_extract_event_id_numeric() {
        let json: Value = serde_json::json!({"EventID": 4624});
        assert_eq!(extract_event_id(&json), 4624);
    }

    #[test]
    fn test_extract_event_id_text_object() {
        let json: Value = serde_json::json!({"EventID": {"#text": 1001}});
        assert_eq!(extract_event_id(&json), 1001);
    }

    #[test]
    fn test_extract_event_id_text_string() {
        let json: Value = serde_json::json!({"EventID": {"#text": "999"}});
        assert_eq!(extract_event_id(&json), 999);
    }

    #[test]
    fn test_extract_event_data() {
        let json: Value = serde_json::json!({
            "#attributes": {"Name": "test"},
            "SubjectUserName": "SYSTEM",
            "TargetLogonId": "0x3e7"
        });
        let fields = extract_event_data(&json);
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|f| f.name == "SubjectUserName" && f.value == "SYSTEM"));
    }

    #[test]
    fn test_build_message() {
        let fields = vec![
            EvtxField { name: "Key1".into(), value: "Val1".into() },
            EvtxField { name: "Key2".into(), value: "Val2".into() },
        ];
        let msg = build_message(&fields);
        assert_eq!(msg, "Key1: Val1; Key2: Val2");
    }
}
