//! Turning one rendered event into one [`EvtxRecord`].
//!
//! The live path renders each event to XML with `EvtRender` and then has to translate it. That
//! translation is pure: it takes a string and returns a record, and nothing about it needs the
//! Event Log service. It lives here rather than in `live` so it compiles and is tested on every
//! platform, not only the one that can produce the input.
//!
//! It reads the parsed tree that the map engine already needs, rather than scanning the XML text.
//! The scanning version this replaces re-derived six System fields with substring searches and
//! matched `EventData` with a regular expression, on top of the parse it was doing anyway. That
//! regex required a `Name` attribute, could not match a value containing a newline, and never saw
//! `UserData` at all, so three whole classes of event field were dropped from the live view without
//! anything indicating a field was missing. The file path never had those bugs because it read the
//! tree. Sharing one extractor is what stops the two paths drifting again.

use cmtraceopen_parser::eventmap::{EventNode, MapRegistry};

use super::event_node::{
    extract_event_data, extract_event_identity, extract_system_fields, parse_event_xml,
    EventFields, SystemFields,
};
use super::models::{EvtxField, EvtxLevel, EvtxRecord};
use super::{parse_timestamp_to_epoch_ms, sanitize_control_chars};

/// Names a provider that identified itself in neither of the two ways it can.
///
/// Matches what the file path shows for the same event. A blank cell reads as a missing column
/// rather than as an event that did not name its source.
const UNKNOWN: &str = "Unknown";

/// Builds a record from one rendered event.
///
/// Returns `None` when the XML will not parse. The caller counts those rather than pushing a record
/// with every field defaulted, which would put a row on screen claiming provider "Unknown" at the
/// epoch and looking exactly like a real event that happened in 1970.
///
/// The live path calls [`record_from_parts`] instead, because it needs the provider name before the
/// record exists in order to ask the service to render the message.
pub fn parse_xml_to_record(
    xml: &str,
    channel: &str,
    maps: &MapRegistry,
    rendered_message: Option<&str>,
) -> Option<EvtxRecord> {
    let parsed = parse_event_xml(xml).ok()?;
    let system = extract_system_fields(&parsed);
    Some(record_from_parts(
        &parsed,
        system,
        xml,
        channel,
        maps,
        rendered_message,
    ))
}

/// Builds a record from a tree and System block the caller has already read.
///
/// Both are taken as arguments so the document is parsed once per event. The live path needs the
/// provider name first, to name the publisher whose message template it asks the service to render,
/// and parsing again to get the rest would double the cost of the hottest loop in the view.
///
/// `parsed` is used for the System block, the event fields, the decoded payload and any registered
/// map, so none of them costs an extra pass over the document.
pub fn record_from_parts(
    parsed: &EventNode,
    system: SystemFields,
    xml: &str,
    channel: &str,
    maps: &MapRegistry,
    rendered_message: Option<&str>,
) -> EvtxRecord {
    // `Provider` carries `Name` for a manifest provider and `EventSourceName` for a classic one.
    // Some carry both, and then `Name` is the identity. `extract_system_fields` already encodes
    // that; the live path used to search the raw text for `Name=`, which also matches the tail of
    // `EventSourceName=`.
    let provider = system.provider.unwrap_or_else(|| UNKNOWN.to_string());
    let event_id = system.event_id.unwrap_or(0);
    // Defaulted to the same value the file path uses, so one event cannot show two severities
    // depending on how it was opened. `EvtxLevel` maps every unrecognised value to Information, so
    // this is Information in practice; it is written as 0 to keep the two paths textually identical
    // if that mapping ever gains a distinct "unspecified" variant.
    let level = EvtxLevel::from_level_value(system.level.unwrap_or(0));
    let computer = system.computer.unwrap_or_else(|| UNKNOWN.to_string());
    let timestamp = system.time_created.unwrap_or_default();
    let timestamp_epoch = parse_timestamp_to_epoch_ms(&timestamp);
    let event_record_id = system.event_record_id.unwrap_or(0);

    // The live path renders its message with `EvtFormatMessage`, which does its own substitution
    // inside the service, so the positional insertion list has no consumer here.
    let EventFields {
        fields: mut event_data,
        insertions: _,
    } = extract_event_data(parsed);
    let identity = extract_event_identity(&event_data);
    // Derived conflict markers are useful in the detail surface, but they are not event data and
    // must not become the fallback row message when no real field has a value.
    let fallback_message = build_event_data_summary(&event_data);

    // Keep a conflict visible even though the conflicting value is intentionally not promoted.
    // `event_data` is already the record's wire-level detail surface and carries derived
    // `EventPayload` values, so this preserves the existing `EvtxRecord` shape while making an
    // ambiguous identity distinguishable from an absent one.
    for conflict in &identity.conflicts {
        event_data.push(EvtxField {
            name: "IdentityConflict".to_string(),
            value: conflict.clone(),
        });
    }

    // Trace-backed channels carry their message as a hex blob rather than as EventData, so without
    // this the row reads as a wall of hex digits. Surfaced as a field of its own because the raw
    // hex never appears in EventData. Appended after every real field so it cannot disturb the
    // positional insertions.
    let payload = cmtraceopen_parser::event_payload::decode_payload_in(parsed)
        .map(|decoded| sanitize_control_chars(&decoded.text));
    if let Some(text) = &payload {
        event_data.push(EvtxField {
            name: "EventPayload".to_string(),
            value: text.clone(),
        });
    }

    // The provider's own rendered message wins when there is one. A decoded payload comes next,
    // used whole rather than through the summary, which would truncate the only text the event has
    // at 80 characters. Sanitized to strip control characters that render as unexpected glyphs.
    let message = rendered_message
        .map(sanitize_control_chars)
        .or(payload)
        .unwrap_or(fallback_message);

    let mapped = super::maps::apply_registered(maps, channel, &provider, event_id, parsed);

    EvtxRecord {
        id: 0, // assigned by commands.rs after sorting
        event_record_id,
        event_record_id_text: system.event_record_id.map(|value| value.to_string()),
        timestamp,
        timestamp_epoch,
        provider,
        // The queried channel names the record. The caller knows which channel it asked for, and a
        // forwarded event names the channel it came from rather than the one holding it.
        channel: channel.to_string(),
        event_id,
        level,
        computer,
        message,
        event_data,
        raw_xml: xml.to_string(),
        source_label: "Live".to_string(),
        origin_kind: super::models::EvtxOriginKind::Event,
        task: system.task,
        opcode: system.opcode,
        process_id: system.process_id,
        activity_id: system.activity_id.or(identity.activity_id),
        related_activity_id: system.related_activity_id.or(identity.related_activity_id),
        session_id: identity.session_id,
        device_id: identity.device_id,
        user_id: identity.user_id,
        process_start_time: identity.process_start_time,
        thread_id: system.thread_id,
        user_sid: system.user_sid,
        keywords: system.keywords,
        mapped,
    }
}

/// Builds a summary from event fields, for events the provider will not describe.
pub fn build_event_data_summary(fields: &[EvtxField]) -> String {
    fields
        .iter()
        .take(5)
        .map(|f| {
            let val = if f.value.chars().count() > 80 {
                // Sliced by character rather than by byte. A value whose 78th byte lands inside a
                // multi-byte character panics on a byte slice, and event fields carry paths and
                // user names that are routinely not ASCII.
                let head: String = f.value.chars().take(77).collect();
                format!("{head}...")
            } else {
                f.value.clone()
            };
            format!("{}: {val}", f.name)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    //! `EvtRender` writes attributes in single quotes, so the fixtures do too. Double-quoted
    //! fixtures would exercise a shape the service never emits.

    use super::*;

    fn record_for(xml: &str, channel: &str) -> EvtxRecord {
        parse_xml_to_record(xml, channel, &MapRegistry::new(), None)
            .expect("a well formed event should produce a record")
    }

    fn field<'a>(record: &'a EvtxRecord, name: &str) -> Option<&'a str> {
        record
            .event_data
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    }

    /// Manifest provider: `Name` is present, and that is the identity to use.
    const MANIFEST: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime='2026-08-11T12:00:00.000000000Z'/>
    <EventRecordID>4242</EventRecordID>
    <Channel>Security</Channel>
    <Computer>RING0IVY24-01</Computer>
    <Execution ProcessID='1234' ThreadID='5678'/>
    <Security UserID='S-1-5-18'/>
    <Keywords>0x8020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name='TargetUserName'>adam</Data>
  </EventData>
</Event>"#;

    #[test]
    fn a_manifest_provider_is_read_from_name() {
        let record = record_for(MANIFEST, "Security");
        assert_eq!(record.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(record.event_id, 4624);
        assert_eq!(record.event_record_id, 4242);
        assert_eq!(record.computer, "RING0IVY24-01");
        assert_eq!(record.process_id, Some(1234));
        assert_eq!(record.thread_id, Some(5678));
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(record.keywords.as_deref(), Some("0x8020000000000000"));
        assert_eq!(field(&record, "TargetUserName"), Some("adam"));
    }

    #[test]
    fn explicit_correlation_and_identity_fields_are_preserved() {
        let xml = r#"<Event>
  <System>
    <Provider Name='Provider'/>
    <EventID>7</EventID>
    <Correlation ActivityID='{activity}' RelatedActivityID='{related}'/>
    <Channel>Application</Channel>
    <Computer>HOST-A</Computer>
    <Execution ProcessID='123'/>
  </System>
  <EventData>
    <Data Name='SessionId'>session-1</Data>
    <Data Name='DeviceId'>device-1</Data>
    <Data Name='UserId'>user-1</Data>
    <Data Name='ProcessStartTime'>2026-08-18T10:00:00Z</Data>
  </EventData>
</Event>"#;
        let record = record_for(xml, "Application");
        assert_eq!(record.activity_id.as_deref(), Some("{activity}"));
        assert_eq!(record.related_activity_id.as_deref(), Some("{related}"));
        assert_eq!(record.session_id.as_deref(), Some("session-1"));
        assert_eq!(record.device_id.as_deref(), Some("device-1"));
        assert_eq!(record.user_id.as_deref(), Some("user-1"));
        assert_eq!(
            record.process_start_time.as_deref(),
            Some("2026-08-18T10:00:00Z")
        );
    }

    #[test]
    fn conflicting_identity_aliases_are_reported_without_promoting_a_value() {
        let xml = r#"<Event>
  <System><Provider Name='Provider'/><EventID>7</EventID></System>
  <EventData>
    <Data Name='ActivityId'>activity-a</Data>
    <Data Name='CorrelationID'>activity-b</Data>
  </EventData>
</Event>"#;
        let record = record_for(xml, "Application");
        assert!(!record.message.contains("IdentityConflict"));

        assert_eq!(record.activity_id, None);
        assert_eq!(
            record
                .event_data
                .iter()
                .filter(|field| field.name == "IdentityConflict")
                .map(|field| field.value.as_str())
                .collect::<Vec<_>>(),
            vec!["activityId"]
        );
    }

    #[test]
    fn a_classic_source_still_names_its_provider() {
        // A classic source names itself only in EventSourceName. Losing it leaves the row blank and
        // stops every map from matching, and neither failure looks like a failure.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider EventSourceName='Print'/>
    <EventID Qualifiers='16384'>10</EventID>
    <Level>4</Level>
    <Channel>Application</Channel>
  </System>
</Event>"#;
        let record = record_for(xml, "Application");
        assert_eq!(record.provider, "Print");
        assert_eq!(record.event_id, 10, "Qualifiers is not part of the id");
    }

    #[test]
    fn a_manifest_name_wins_over_a_legacy_source_alias() {
        // Both attributes are present, and the text `Name='` occurs inside `EventSourceName='`.
        // Anything searching the raw XML for that substring can match the alias and report the
        // wrong provider depending only on attribute order.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider EventSourceName='Software Protection Platform Service' Name='Microsoft-Windows-Security-SPP'/>
    <EventID>16384</EventID>
  </System>
</Event>"#;
        assert_eq!(
            record_for(xml, "Application").provider,
            "Microsoft-Windows-Security-SPP"
        );
    }

    #[test]
    fn an_unnamed_data_element_is_kept_and_numbered_by_position() {
        // Classic providers write positional Data with no Name. Requiring a Name attribute dropped
        // every one of them, so the event arrived with no fields and the detail pane was empty.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='MsiInstaller'/><EventID>1033</EventID></System>
  <EventData>
    <Data>Product Name</Data>
    <Data>1.2.3</Data>
  </EventData>
</Event>"#;
        let record = record_for(xml, "Application");
        assert_eq!(field(&record, "Data1"), Some("Product Name"));
        assert_eq!(field(&record, "Data2"), Some("1.2.3"));
    }

    #[test]
    fn a_multi_line_value_survives() {
        // Stack traces, path lists and MSI output all span lines. A regex whose `.` stops at a
        // newline matched none of them, and the field vanished rather than arriving truncated,
        // which is the harder failure to notice.
        let xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\n  <System><Provider Name='Application Error'/><EventID>1000</EventID></System>\n  <EventData>\n    <Data Name='Trace'>at Frame.One\nat Frame.Two</Data>\n  </EventData>\n</Event>";
        assert_eq!(
            field(&record_for(xml, "Application"), "Trace"),
            Some("at Frame.One\nat Frame.Two")
        );
    }

    #[test]
    fn user_data_fields_are_read() {
        // Trace-backed and classic providers put their fields in UserData, nested under a
        // provider-named wrapper. Reading only EventData left these events with no fields at all.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Winlogon'/><EventID>811</EventID></System>
  <UserData>
    <EventXML xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
      <SubscriptionId>WinlogonSubscription</SubscriptionId>
    </EventXML>
  </UserData>
</Event>"#;
        assert_eq!(
            field(&record_for(xml, "Application"), "SubscriptionId"),
            Some("WinlogonSubscription")
        );
    }

    #[test]
    fn an_absent_level_defaults_to_what_the_file_path_shows() {
        // The two paths must default identically, or the same event shows one severity when opened
        // from a file and another when read live. They previously wrote different literals, 0 here
        // and 4 there, which happens to be the same value only because `EvtxLevel` folds every
        // unrecognised level into Information.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='X'/><EventID>1</EventID></System>
</Event>"#;
        assert_eq!(
            record_for(xml, "Application").level,
            EvtxLevel::from_level_value(0)
        );
    }

    #[test]
    fn an_unnamed_provider_is_reported_as_unknown_not_as_blank() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>1</EventID></System>
</Event>"#;
        assert_eq!(record_for(xml, "Application").provider, UNKNOWN);
    }

    #[test]
    fn malformed_xml_yields_no_record_rather_than_an_empty_one() {
        // A record with every field defaulted is indistinguishable on screen from a real event that
        // happened at the epoch with no provider.
        assert!(
            parse_xml_to_record("<Event><System>", "Application", &MapRegistry::new(), None)
                .is_none()
        );
    }

    #[test]
    fn the_rendered_message_is_preferred_over_a_field_summary() {
        let record = parse_xml_to_record(
            MANIFEST,
            "Security",
            &MapRegistry::new(),
            Some("An account was successfully logged on."),
        )
        .expect("record");
        assert_eq!(record.message, "An account was successfully logged on.");
    }

    #[test]
    fn without_a_rendered_message_the_fields_are_summarised() {
        assert_eq!(
            record_for(MANIFEST, "Security").message,
            "TargetUserName: adam"
        );
    }

    #[test]
    fn a_long_non_ascii_value_is_truncated_without_panicking() {
        // Truncating by byte offset panics when the cut lands inside a multi-byte character, and
        // event fields carry paths and account names that are routinely not ASCII.
        let value = "é".repeat(200);
        let summary = build_event_data_summary(&[EvtxField {
            name: "Path".to_string(),
            value,
        }]);
        assert!(summary.ends_with("..."));
        assert_eq!(summary.chars().filter(|c| *c == 'é').count(), 77);
    }
}
