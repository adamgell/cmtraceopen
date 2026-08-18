use std::path::Path;
use std::sync::RwLock;

use cmtraceopen_parser::eventmap::MapRegistry;
use evtx::EvtxParser;

// `extract_event_data` sits in `event_node` alongside `extract_system_fields`: both read a parsed
// tree, and both are needed by the live path as well as this one. Keeping the data extractor here
// while the live path scanned raw XML for itself is what let the two drift apart.
use super::event_node::{extract_event_data, EventFields};
use super::provider_db::ProviderStore;

use super::models::{
    ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxParseResult, EvtxRecord,
};
use super::{parse_timestamp_to_epoch_ms, sanitize_control_chars};

/// Maximum entries to parse from a single .evtx file to prevent memory issues.
const MAX_ENTRIES_PER_FILE: usize = 100_000;

/// Keeps the normalized manifest member path as the record's source identity.
///
/// A basename is only a display label: two folder members commonly share one and would otherwise
/// collide in a merged timeline.
fn source_label_for_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Parse one or more .evtx files and return a unified result.
///
/// The map registry and provider store are passed in rather than reached for. They belong to the
/// application state, so the caller decides which set is in effect; that is also what lets a test
/// use its own without another test on a parallel thread replacing it.
pub fn parse_evtx_files(
    paths: &[String],
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<EvtxParseResult, String> {
    let mut all_records = Vec::new();
    let mut channels = Vec::new();
    let mut parse_errors = 0u32;
    let mut error_messages = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        match parse_single_file(path, maps, providers) {
            Ok(file) => {
                let records = file.records;
                parse_errors += file.parse_errors;
                error_messages.extend(file.messages);
                let source_label = source_label_for_path(path);

                // Build one EvtxChannelInfo per distinct channel string found in the records,
                // so that ChannelPicker can match against r.channel values.
                let mut channel_counts: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for r in &records {
                    *channel_counts.entry(r.channel.clone()).or_insert(0) += 1;
                }

                if channel_counts.is_empty() {
                    // No records — still emit an entry keyed by the full source path so the file
                    // appears in the picker without colliding with a same-named member.
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
fn parse_single_file(
    path: &Path,
    maps: &RwLock<MapRegistry>,
    providers: &RwLock<ProviderStore>,
) -> Result<ParsedFile, String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file {}: {}", path.display(), e))?;

    let source_label = source_label_for_path(path);

    let mut records = Vec::new();
    let mut parse_errors = 0u32;
    let mut messages = Vec::new();
    let mut truncated = false;

    // Locked once for the whole file rather than per record. A hundred thousand lock round trips
    // would cost more than the parsing does.
    let maps = maps
        .read()
        .map_err(|_| "map registry lock was poisoned".to_string())?;
    // A read guard: looking a provider up caches internally, so it needs no exclusive access.
    // Taking the write lock here blocked every other reader for the length of the file.
    let providers = providers
        .read()
        .map_err(|_| "provider store lock was poisoned".to_string())?;

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

        let EventFields {
            mut fields,
            insertions,
        } = extract_event_data(&parsed);

        // Same treatment as the live path: a trace-backed event carries its message as hex, and
        // without decoding it the row is a wall of digits.
        let payload = cmtraceopen_parser::event_payload::decode_payload_in(&parsed)
            .map(|decoded| sanitize_control_chars(&decoded.text));
        if let Some(text) = &payload {
            // Appended after every real field, so it cannot disturb the positional insertions.
            fields.push(EvtxField {
                name: "EventPayload".to_string(),
                value: text.clone(),
            });
        }

        // A provider database, when one is loaded, turns raw field values into the sentence the
        // provider intended. Without it the file path can only summarise EventData, which is what
        // every other cross-platform reader shows and why they are hard to read.
        let message = describe_event(&providers, &provider, event_id, &insertions)
            .or(payload)
            .unwrap_or_else(|| super::rendered::build_event_data_summary(&fields));

        let mapped = super::maps::apply_registered(&maps, &channel, &provider, event_id, &parsed);
        records.push(EvtxRecord {
            id: 0, // Will be reassigned after sorting
            event_record_id,
            event_record_id_text: Some(event_record_id.to_string()),
            timestamp: timestamp_str,
            timestamp_epoch,
            provider,
            channel,
            event_id,
            level: evtx_level,
            computer,
            message,
            event_data: fields,
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

/// Renders the provider's own description for this event, when metadata for it is loaded.
///
/// Returns `None` when no database is loaded, the provider is absent from it, or the provider does
/// not define this event. Falling back to a field summary is right in all three cases: an absent
/// description is a coverage gap, not a reason to show nothing.
///
/// A partially rendered description is rejected rather than shown. If the template references
/// insertions the event did not supply, the metadata and the event disagree, and a sentence with
/// `%4` embedded in it is less honest than the field summary it would replace.
fn describe_event(
    store: &ProviderStore,
    provider: &str,
    event_id: u32,
    insertions: &[String],
) -> Option<String> {
    let metadata = store.provider(provider)?;
    let event = metadata.event(event_id, None)?;
    let template = event.description.as_deref()?;

    let rendered = cmtraceopen_parser::provider::render_description(template, insertions);
    if rendered.is_complete() {
        Some(super::sanitize_control_chars(&rendered.text))
    } else {
        None
    }
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

    /// Empty registries, for tests that only care about parsing.
    ///
    /// Each test gets its own, so nothing here can be perturbed by another test on a parallel
    /// thread loading a different set.
    fn empty_state() -> (RwLock<MapRegistry>, RwLock<ProviderStore>) {
        (
            RwLock::new(MapRegistry::new()),
            RwLock::new(ProviderStore::default()),
        )
    }

    fn parse(xml: &str) -> cmtraceopen_parser::eventmap::EventNode {
        super::super::event_node::parse_event_xml(xml).expect("well formed")
    }

    fn fields_of(xml: &str) -> Vec<EvtxField> {
        extract_event_data(&parse(xml)).fields
    }

    fn insertions_of(xml: &str) -> Vec<String> {
        extract_event_data(&parse(xml)).insertions
    }

    #[test]
    fn source_label_keeps_full_manifest_member_path_for_timeline_identity() {
        let path = Path::new("bundle\\server-a\\capture.evtx");
        assert_eq!(
            source_label_for_path(path),
            "bundle\\server-a\\capture.evtx"
        );
    }
    #[test]
    fn a_file_that_cannot_be_opened_is_named_in_the_result() {
        // A count with no file name and no reason leaves an operator with a number and no next
        // step. The message is what makes a missing log actionable.
        let (maps, providers) = empty_state();
        let result = parse_evtx_files(&["/no/such/file.evtx".to_string()], &maps, &providers)
            .expect("returns");
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
        let (maps, providers) = empty_state();
        let result = parse_evtx_files(&[], &maps, &providers).expect("returns");
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
    fn an_empty_field_still_holds_its_insertion_position() {
        // The provider's template addresses fields by position. Dropping the empty one would make
        // %3 resolve to what %4 said, and the rendered description would state it as fact.
        let xml = r#"<Event><EventData>
                 <Data Name="First">alpha</Data>
                 <Data Name="Second"></Data>
                 <Data Name="Third">gamma</Data>
               </EventData></Event>"#;

        assert_eq!(insertions_of(xml), vec!["alpha", "", "gamma"]);
        // The display list still omits the blank, because a column of blanks is noise.
        assert_eq!(
            fields_of(xml)
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["First", "Third"]
        );
    }

    #[test]
    fn a_leading_empty_field_does_not_shift_the_rest() {
        let xml = "<Event><EventData><Data></Data><Data>second</Data></EventData></Event>";
        assert_eq!(insertions_of(xml), vec!["", "second"]);
    }

    #[test]
    fn a_positional_label_matches_the_slot_the_template_addresses() {
        // The label is how an operator matches a field against the provider's template. Skipping
        // the count for a blank slot labelled the survivor Data1 while the template calls it %2.
        let xml = "<Event><EventData><Data></Data><Data>second</Data></EventData></Event>";
        let fields = fields_of(xml);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Data2");
        assert_eq!(fields[0].value, "second");
    }

    #[test]
    fn insertions_cover_user_data_too() {
        let xml = r#"<Event><UserData><Wrapper>
                 <A>one</A><B></B><C>three</C>
               </Wrapper></UserData></Event>"#;
        assert_eq!(insertions_of(xml), vec!["one", "", "three"]);
    }

    #[test]
    fn a_binary_only_event_keeps_its_value() {
        // Classic providers emit <Binary> with no <Data> at all. Treating a container without
        // <Data> as a set of wrappers descends into <Binary>, finds no children, and drops the
        // only value the event carried.
        let fields = fields_of("<Event><EventData><Binary>DEADBEEF</Binary></EventData></Event>");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Binary");
        assert_eq!(fields[0].value, "DEADBEEF");
    }

    #[test]
    fn data_and_binary_together_both_survive() {
        let fields = fields_of(
            r#"<Event><EventData>
                 <Data Name="Reason">timeout</Data>
                 <Binary>00FF</Binary>
               </EventData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Reason");
        assert_eq!(fields[1].name, "Binary");
    }

    #[test]
    fn a_wrapper_and_a_direct_field_can_coexist() {
        // Decided per child rather than per container, so one shape does not suppress the other.
        let fields = fields_of(
            r#"<Event><UserData>
                 <Direct>here</Direct>
                 <Wrapper><Nested>there</Nested></Wrapper>
               </UserData></Event>"#,
        );
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Direct");
        assert_eq!(fields[1].name, "Nested");
    }

    #[test]
    fn positional_numbering_continues_across_containers() {
        // The %1 style references in a message template are numbered over the whole event, not
        // restarted per container.
        let fields = fields_of(
            r#"<Event>
                 <EventData><Data>one</Data></EventData>
                 <UserData><Data>two</Data></UserData>
               </Event>"#,
        );
        assert_eq!(fields[0].name, "Data1");
        assert_eq!(fields[1].name, "Data2");
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
                 <Computer>TESTHOST-01</Computer>
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
        assert_eq!(system.computer.as_deref(), Some("TESTHOST-01"));
        assert_eq!(system.process_id, Some(4));
        assert_eq!(
            parse_timestamp_to_epoch_ms(system.time_created.as_deref().unwrap_or_default()),
            1_786_276_800_000
        );
    }
}

#[cfg(test)]
mod description_tests {
    use super::*;

    /// Positional insertions, which is what a description template consumes.
    ///
    /// Names are kept in the call sites for readability but are not what the template addresses;
    /// it refers to fields by position, which is why the insertion list carries empties.
    fn insertions(values: &[(&str, &str)]) -> Vec<String> {
        values
            .iter()
            .map(|(_name, value)| value.to_string())
            .collect()
    }

    /// A store with nothing registered, which is the state until an operator loads a database.
    fn empty_store() -> ProviderStore {
        ProviderStore::default()
    }

    /// A store with the databases beside `CMTRACEOPEN_PROVIDER_DB` registered.
    ///
    /// Built per test. A shared one would let these interfere with each other, since registering a
    /// directory replaces whatever was there.
    fn loaded_store() -> ProviderStore {
        let path = std::env::var("CMTRACEOPEN_PROVIDER_DB").expect("database path");
        let directory = std::path::Path::new(&path)
            .parent()
            .expect("database has a parent directory");
        let mut store = ProviderStore::default();
        store.load_directory(directory).expect("databases load");
        store
    }

    #[test]
    fn with_no_database_loaded_it_falls_back_to_the_field_summary() {
        // The common case until an operator loads metadata. Must not fail or blank the message.
        let data = insertions(&[("HRESULT", "0x80180005")]);
        assert!(describe_event(&empty_store(), "Nobody-Has-This-Provider", 1, &data).is_none());
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn an_unknown_event_id_falls_back_rather_than_inventing_a_description() {
        // Needs a store that actually holds the provider. Against an empty one the lookup returns
        // None on the provider itself and the event-id branch is never reached, so this only
        // repeated the no-database case while claiming to cover something else.
        let store = loaded_store();
        let data = insertions(&[("X", "1")]);
        assert!(
            describe_event(
                &store,
                "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
                999_999,
                &data
            )
            .is_none(),
            "a provider that is loaded but does not define this id must fall back"
        );
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn a_loaded_database_renders_a_real_provider_description() {
        // The whole chain: SQLite on disk, gzip payload, provider metadata, insertion rendering.
        let store = loaded_store();

        let data = insertions(&[("HRESULT", "0x80180005")]);
        let described = describe_event(
            &store,
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
        let store = loaded_store();

        // A provider that genuinely is not in a Windows capture.
        assert!(describe_event(
            &store,
            "Definitely-Not-A-Real-Provider",
            1,
            &insertions(&[("a", "b")])
        )
        .is_none());
    }
}
