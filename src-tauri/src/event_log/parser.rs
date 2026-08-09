use std::path::Path;

use evtx::EvtxParser;

use super::models::{
    ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxParseResult, EvtxRecord,
};
use super::{parse_timestamp_to_epoch_ms, sanitize_control_chars};

/// Maximum entries to parse from a single .evtx file to prevent memory issues.
const MAX_ENTRIES_PER_FILE: usize = 100_000;

/// Parse one or more .evtx files and return a unified result.
pub fn parse_evtx_files(paths: &[String]) -> Result<EvtxParseResult, String> {
    let mut all_records = Vec::new();
    let mut channels = Vec::new();
    let mut parse_errors = 0u32;
    let mut error_messages = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        match parse_single_file(path) {
            Ok(file) => {
                let records = file.records;
                parse_errors += file.parse_errors;
                error_messages.extend(file.messages);
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
                log::warn!(
                    "event=evtx_parse_error file=\"{}\" error=\"{}\"",
                    path_str,
                    e
                );
                parse_errors += 1;
                // A file that could not be opened at all is reported by name. Counting it without
                // saying which file, or why, leaves an operator with a number and no next step.
                error_messages.push(format!("{path_str}: {e}"));
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
        error_messages,
    })
}

/// What one file yielded, including why anything was missing from it.
struct ParsedFile {
    records: Vec<EvtxRecord>,
    /// Records that could not be read. Kept as a count because a damaged file can produce
    /// thousands, and thousands of near-identical strings are not worth carrying.
    parse_errors: u32,
    /// Operator-facing explanations, already summarised.
    messages: Vec<String>,
}

/// Parse a single .evtx file.
///
/// Anything missing from the result is explained rather than merely counted. A damaged file, a
/// record whose XML will not parse, and a file so large it was truncated are all cases where the
/// view is incomplete, and a view that is silently incomplete is worse than one that is empty:
/// the absent events look like evidence that the thing being investigated did not happen.
fn parse_single_file(path: &Path) -> Result<ParsedFile, String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_label = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut records = Vec::new();
    let mut parse_errors = 0u32;
    let mut messages = Vec::new();
    let mut truncated = false;

    // XML rather than JSON. The JSON projection cannot be re-parsed into an event tree, which is
    // what the map engine, the System block, and the XML export all consume; reading XML here is
    // what makes those work on an opened file at all.
    for record_result in parser.records() {
        if records.len() >= MAX_ENTRIES_PER_FILE {
            log::warn!(
                "event=evtx_entry_cap_reached file=\"{}\" cap={}",
                path.display(),
                MAX_ENTRIES_PER_FILE
            );
            truncated = true;
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

        let raw_xml = record.data;
        let event_record_id = record.event_record_id;

        // Parsed once and used for identity, the System block, the decoded payload, and any
        // registered map, so none of them costs an extra parse. A record whose XML will not parse
        // is counted as an error rather than pushed with every field defaulted, which would show a
        // row claiming provider "Unknown" at the epoch.
        let parsed = match super::event_node::parse_event_xml(&raw_xml) {
            Ok(root) => root,
            Err(error) => {
                log::warn!(
                    "event=evtx_record_unparsable file=\"{}\" error=\"{}\"",
                    path.display(),
                    error
                );
                parse_errors += 1;
                continue;
            }
        };

        let system = super::event_node::extract_system_fields(&parsed);
        let provider = system.provider.clone().unwrap_or_else(|| "Unknown".into());
        let channel = system.channel.clone().unwrap_or_else(|| "Unknown".into());
        let event_id = system.event_id.unwrap_or(0);
        let evtx_level = EvtxLevel::from_level_value(system.level.unwrap_or(0));
        let computer = system.computer.clone().unwrap_or_else(|| "Unknown".into());
        let timestamp_str = system.time_created.clone().unwrap_or_default();
        let timestamp_epoch = parse_timestamp_to_epoch_ms(&timestamp_str);

        let mut event_data = extract_event_data(&parsed);

        // Same treatment as the live path: a trace-backed event carries its message as hex, and
        // without decoding it the row is a wall of digits.
        let payload = cmtraceopen_parser::event_payload::decode_payload_in(&parsed)
            .map(|decoded| sanitize_control_chars(&decoded.text));
        if let Some(text) = &payload {
            event_data.push(EvtxField {
                name: "EventPayload".to_string(),
                value: text.clone(),
            });
        }

        // A provider database, when one is loaded, turns raw field values into the sentence the
        // provider intended. Without it the file path can only summarise EventData, which is what
        // every other cross-platform reader shows and why they are hard to read.
        let message = describe_event(&provider, event_id, &event_data)
            .or(payload)
            .unwrap_or_else(|| build_message(&event_data));

        let mapped = super::maps::apply_global(&channel, &provider, event_id, &parsed);
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
            task: system.task,
            opcode: system.opcode,
            process_id: system.process_id,
            thread_id: system.thread_id,
            user_sid: system.user_sid,
            keywords: system.keywords,
            mapped,
        });
    }

    if truncated {
        // Previously only logged. An operator saw exactly the cap as the event count with nothing
        // saying the file held more, which reads as a complete picture of a file that was cut off.
        messages.push(format!(
            "{}: stopped at {} events, the most this reader loads from one file. The file holds more.",
            source_label, MAX_ENTRIES_PER_FILE
        ));
    }
    if parse_errors > 0 {
        messages.push(format!(
            "{source_label}: {parse_errors} of {} records could not be read and are missing from the view.",
            parse_errors as usize + records.len()
        ));
    }

    Ok(ParsedFile {
        records,
        parse_errors,
        messages,
    })
}

/// Extract event fields as name-value pairs.
///
/// Both `EventData` and `UserData` are read. Manifest providers use the former and classic or
/// trace-backed providers the latter, and skipping `UserData` would leave those events with no
/// fields at all.
///
/// A `Data` element with no `Name` attribute is numbered by its position, matching how the event
/// message template refers to it. Values are sanitized to strip control characters that would
/// render as unexpected glyphs.
fn extract_event_data(root: &cmtraceopen_parser::eventmap::EventNode) -> Vec<EvtxField> {
    let mut fields = Vec::new();
    let mut unnamed = 0usize;

    let containers = root
        .children
        .iter()
        .filter(|child| child.name == "EventData" || child.name == "UserData");

    for container in containers {
        // UserData wraps its fields in a provider-named element, so descend through a single
        // wrapper when the container holds no Data of its own.
        let holders: Vec<_> = if container.children.iter().any(|c| c.name == "Data") {
            vec![container]
        } else {
            container.children.iter().collect()
        };

        for holder in holders {
            for child in &holder.children {
                let value = sanitize_control_chars(child.text.as_deref().unwrap_or_default());
                if value.is_empty() {
                    continue;
                }
                let name = match child.attribute("Name") {
                    Some(name) => name.to_string(),
                    // A positional field. Named from one so it lines up with the `%1` style
                    // insertion numbering that message templates use.
                    None if child.name == "Data" => {
                        unnamed += 1;
                        format!("Data{unnamed}")
                    }
                    None => child.name.clone(),
                };
                fields.push(EvtxField { name, value });
            }
        }
    }

    fields
}

/// Renders the provider's own description for this event, when metadata for it is loaded.
///
/// Returns `None` when no database is loaded, the provider is absent from it, or the provider does
/// not define this event. Falling back to a field summary is right in all three cases: an absent
/// description is a coverage gap, not a reason to show nothing.
///
/// A partially rendered description is rejected rather than shown. If the template references
/// insertions the event did not supply, the metadata and the event disagree, and a sentence with
/// `%4` embedded in it is less honest than the field summary it would replace.
fn describe_event(provider: &str, event_id: u32, event_data: &[EvtxField]) -> Option<String> {
    let metadata = super::provider_db::provider(provider)?;
    let event = metadata.event(event_id, None)?;
    let template = event.description.as_deref()?;

    let insertions: Vec<String> = event_data.iter().map(|field| field.value.clone()).collect();
    let rendered = cmtraceopen_parser::provider::render_description(template, &insertions);
    if rendered.is_complete() {
        Some(super::sanitize_control_chars(&rendered.text))
    } else {
        None
    }
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

    fn parse(xml: &str) -> cmtraceopen_parser::eventmap::EventNode {
        super::super::event_node::parse_event_xml(xml).expect("well formed")
    }

    fn fields_of(xml: &str) -> Vec<EvtxField> {
        extract_event_data(&parse(xml))
    }

    #[test]
    fn a_file_that_cannot_be_opened_is_named_in_the_result() {
        // A count with no file name and no reason leaves an operator with a number and no next
        // step. The message is what makes a missing log actionable.
        let result = parse_evtx_files(&["/no/such/file.evtx".to_string()]).expect("returns");
        assert_eq!(result.parse_errors, 1);
        assert_eq!(result.error_messages.len(), 1);
        assert!(
            result.error_messages[0].contains("/no/such/file.evtx"),
            "{:?}",
            result.error_messages
        );
        assert!(result.records.is_empty());
    }

    #[test]
    fn a_clean_parse_reports_nothing() {
        // The messages are a gap report, so an empty run must not manufacture one.
        let result = parse_evtx_files(&[]).expect("returns");
        assert_eq!(result.parse_errors, 0);
        assert!(result.error_messages.is_empty());
        assert_eq!(result.total_records, 0);
    }

    #[test]
    fn named_event_data_becomes_named_fields() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="SubjectUserName">SYSTEM</Data>
                 <Data Name="TargetLogonId">0x3e7</Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "SubjectUserName");
        assert_eq!(fields[0].value, "SYSTEM");
        assert_eq!(fields[1].name, "TargetLogonId");
    }

    #[test]
    fn an_empty_data_element_is_dropped_rather_than_shown_blank() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="Present">yes</Data>
                 <Data Name="Absent"></Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Present");
    }

    #[test]
    fn unnamed_data_is_numbered_from_one_to_match_insertion_order() {
        // Classic providers emit positional Data. Numbering from one lines the fields up with the
        // %1 style references in the provider's message template.
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data>first</Data>
                 <Data>second</Data>
               </EventData></Event>"#,
        );
        assert_eq!(fields[0].name, "Data1");
        assert_eq!(fields[0].value, "first");
        assert_eq!(fields[1].name, "Data2");
        assert_eq!(fields[1].value, "second");
    }

    #[test]
    fn user_data_fields_are_read_through_the_provider_wrapper() {
        // Skipping UserData would leave every classic and trace-backed event with no fields at all.
        let fields = fields_of(
            r#"<Event><UserData>
                 <RuleAndFileData xmlns="http://example">
                   <PolicyName>Enforce</PolicyName>
                   <FilePath>C:\app.exe</FilePath>
                 </RuleAndFileData>
               </UserData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "PolicyName");
        assert_eq!(fields[1].value, "C:\\app.exe");
    }

    #[test]
    fn control_characters_in_a_value_are_stripped() {
        let fields = fields_of(
            "<Event><EventData><Data Name=\"Path\">C:\\app.exe\r</Data></EventData></Event>",
        );
        assert_eq!(fields[0].value, "C:\\app.exe");
    }

    #[test]
    fn system_identity_comes_off_the_parsed_tree() {
        // The file path used to re-parse a JSON projection as XML, which always failed, leaving
        // every System-derived column empty on an opened file.
        let system = super::super::event_node::extract_system_fields(&parse(
            r#"<Event><System>
                 <Provider Name="Microsoft-Windows-Kernel-General" />
                 <EventID Qualifiers="49152">12</EventID>
                 <Level>2</Level>
                 <TimeCreated SystemTime="2026-08-09T12:00:00.000Z" />
                 <Channel>System</Channel>
                 <Computer>RING0IVY24-01</Computer>
                 <Execution ProcessID="4" ThreadID="8" />
               </System></Event>"#,
        ));
        assert_eq!(
            system.provider.as_deref(),
            Some("Microsoft-Windows-Kernel-General")
        );
        // The qualifier is a separate value; the id is still the element text.
        assert_eq!(system.event_id, Some(12));
        assert_eq!(system.level, Some(2));
        assert_eq!(system.channel.as_deref(), Some("System"));
        assert_eq!(system.computer.as_deref(), Some("RING0IVY24-01"));
        assert_eq!(system.process_id, Some(4));
        assert_eq!(
            parse_timestamp_to_epoch_ms(system.time_created.as_deref().unwrap_or_default()),
            1_786_276_800_000
        );
    }

    #[test]
    fn test_build_message() {
        let fields = vec![
            EvtxField {
                name: "Key1".into(),
                value: "Val1".into(),
            },
            EvtxField {
                name: "Key2".into(),
                value: "Val2".into(),
            },
        ];
        let msg = build_message(&fields);
        assert_eq!(msg, "Key1: Val1; Key2: Val2");
    }
}

#[cfg(test)]
mod description_tests {
    use super::*;

    fn fields(values: &[(&str, &str)]) -> Vec<EvtxField> {
        values
            .iter()
            .map(|(name, value)| EvtxField {
                name: name.to_string(),
                value: value.to_string(),
            })
            .collect()
    }

    #[test]
    fn with_no_database_loaded_it_falls_back_to_the_field_summary() {
        // The common case until an operator loads metadata. Must not fail or blank the message.
        let data = fields(&[("HRESULT", "0x80180005")]);
        assert!(describe_event("Nobody-Has-This-Provider", 1, &data).is_none());
    }

    #[test]
    fn an_unknown_event_id_falls_back_rather_than_inventing_a_description() {
        let data = fields(&[("X", "1")]);
        assert!(describe_event("Still-Not-Loaded", 999_999, &data).is_none());
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn a_loaded_database_renders_a_real_provider_description() {
        // The whole chain: SQLite on disk, gzip payload, provider metadata, insertion rendering.
        let path = std::env::var("CMTRACEOPEN_PROVIDER_DB").expect("database path");
        let directory = std::path::Path::new(&path)
            .parent()
            .expect("database has a parent directory");
        super::super::provider_db::load_directory(directory).expect("databases load");

        let data = fields(&[("HRESULT", "0x80180005")]);
        let described = describe_event(
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
            2,
            &data,
        )
        .expect("the MDM provider defines event 2");

        println!("rendered: {described}");
        assert!(described.contains("0x80180005"), "{described}");
        assert!(!described.contains("%1"), "{described}");
        assert!(
            described.len() > "0x80180005".len(),
            "a description should be a sentence, not just the value: {described}"
        );
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn an_event_the_database_does_not_cover_still_falls_back() {
        let path = std::env::var("CMTRACEOPEN_PROVIDER_DB").expect("database path");
        let directory = std::path::Path::new(&path).parent().expect("parent");
        super::super::provider_db::load_directory(directory).expect("databases load");

        // A provider that genuinely is not in a Windows capture.
        assert!(
            describe_event("Definitely-Not-A-Real-Provider", 1, &fields(&[("a", "b")])).is_none()
        );
    }
}
