//! Converting rendered event XML into the parser crate's [`EventNode`] tree.
//!
//! `cmtraceopen-parser` is wasm32-compatible and carries no XML reader, so the map engine takes an
//! already-parsed tree. This is the host-side adapter that produces one from the XML that
//! `EvtRender` and the `evtx` crate both emit.
//!
//! Namespace prefixes are stripped. Event XML declares a default namespace and providers
//! occasionally emit prefixed elements, but map path expressions are written without prefixes
//! (`/Event/EventData/Data`), so keeping them would make every such map silently match nothing.

use cmtraceopen_parser::eventmap::EventNode;
use quick_xml::events::Event as XmlEvent;
use quick_xml::{Reader, XmlVersion};

/// Parses rendered event XML into a node tree rooted at `Event`.
///
/// Returns `Err` only when the document is not well formed. A document that is well formed but
/// unexpected in shape yields whatever tree it describes, so a provider emitting something unusual
/// degrades to unmapped columns rather than to a failed query.
pub fn parse_event_xml(xml: &str) -> Result<EventNode, String> {
    let mut reader = Reader::from_str(xml);
    // Text is not trimmed globally. Trimming would strip meaningful spaces from field values, and
    // because entity references arrive as separate events, "a &amp; b" would be reassembled from
    // individually trimmed fragments as "a&b". Whitespace-only text on a container element is
    // dropped when the element closes instead, which removes pretty-printing without touching
    // real content.
    reader.config_mut().trim_text(false);

    let mut stack: Vec<EventNode> = Vec::new();
    let mut root: Option<EventNode> = None;
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(XmlEvent::Start(start)) => stack.push(element_from(&start)?),
            Ok(XmlEvent::Empty(empty)) => {
                let node = element_from(&empty)?;
                close(&mut stack, &mut root, node);
            }
            Ok(XmlEvent::Text(text)) => {
                let value = text
                    .xml10_content()
                    .map_err(|error| format!("undecodable text: {error}"))?
                    .into_owned();
                push_text(&mut stack, &value);
            }
            Ok(XmlEvent::GeneralRef(reference)) => {
                // Entity references are their own event in quick-xml 0.41. Ignoring them would
                // silently drop every '&', '<' and '>' from event data, which is common in command
                // lines and file paths.
                let name = reference
                    .decode()
                    .map_err(|error| format!("undecodable entity reference: {error}"))?
                    .into_owned();
                let raw = format!("&{name};");
                let resolved = quick_xml::escape::unescape(&raw)
                    .map(|value| value.into_owned())
                    .unwrap_or(raw);
                push_text(&mut stack, &resolved);
            }
            Ok(XmlEvent::CData(data)) => {
                let value = String::from_utf8_lossy(&data).into_owned();
                push_text(&mut stack, &value);
            }
            Ok(XmlEvent::End(_)) => {
                let Some(node) = stack.pop() else { continue };
                close(&mut stack, &mut root, node);
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("malformed event XML: {error}")),
        }
        buffer.clear();
    }

    root.ok_or_else(|| "event XML contained no elements".to_string())
}

fn push_text(stack: &mut [EventNode], value: &str) {
    if let Some(current) = stack.last_mut() {
        match current.text.as_mut() {
            Some(existing) => existing.push_str(value),
            None => current.text = Some(value.to_string()),
        }
    }
}

fn close(stack: &mut [EventNode], root: &mut Option<EventNode>, mut node: EventNode) {
    // Pretty-printed XML puts newlines and indentation inside container elements. That is layout,
    // not content, so it is dropped once we know the element has children.
    if !node.children.is_empty()
        && node
            .text
            .as_deref()
            .is_some_and(|text| text.trim().is_empty())
    {
        node.text = None;
    }

    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        // The outermost element is the root. Later siblings at depth zero are ignored rather than
        // replacing it, so a stray trailing element cannot discard the event.
        None => {
            if root.is_none() {
                *root = Some(node);
            }
        }
    }
}

fn element_from(start: &quick_xml::events::BytesStart<'_>) -> Result<EventNode, String> {
    let mut node = EventNode::new(local_name(start.name().as_ref()));
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| format!("malformed attribute: {error}"))?;
        let name = local_name(attribute.key.as_ref());
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| format!("undecodable attribute value: {error}"))?
            .into_owned();
        node.attributes.push((name, value));
    }
    Ok(node)
}

fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    match text.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => text.into_owned(),
    }
}

/// System-block fields that every event carries, regardless of provider.
///
/// Unlike map-derived columns, which only exist where someone has written a map, these are present
/// on every event, so they are extracted unconditionally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemFields {
    pub provider: Option<String>,
    pub event_id: Option<u32>,
    pub level: Option<u8>,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub time_created: Option<String>,
    pub task: Option<u32>,
    pub opcode: Option<u32>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub user_sid: Option<String>,
    pub keywords: Option<String>,
}

/// Reads the `System` block of a parsed event.
///
/// Every field is optional because providers legitimately omit them: a task of zero is commonly
/// written as no element at all, and `Security` carries no `UserID` for events raised outside a
/// user context. An absent field stays `None` rather than defaulting to zero, which would claim
/// the provider said something it did not.
pub fn extract_system_fields(root: &EventNode) -> SystemFields {
    let Some(system) = root.children.iter().find(|child| child.name == "System") else {
        return SystemFields::default();
    };

    let text_of = |name: &str| -> Option<&str> {
        system
            .children
            .iter()
            .find(|child| child.name == name)
            .and_then(|child| child.text.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let attribute_of = |element: &str, attribute: &str| -> Option<String> {
        system
            .children
            .iter()
            .find(|child| child.name == element)
            .and_then(|child| child.attribute(attribute))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };

    SystemFields {
        provider: attribute_of("Provider", "Name"),
        // Classic providers write `<EventID Qualifiers="49152">1000</EventID>`. The id is the
        // element text in both shapes; the qualifier is separate and not part of the id.
        event_id: text_of("EventID").and_then(|value| value.parse().ok()),
        level: text_of("Level").and_then(|value| value.parse().ok()),
        channel: text_of("Channel").map(str::to_string),
        computer: text_of("Computer").map(str::to_string),
        time_created: attribute_of("TimeCreated", "SystemTime"),
        task: text_of("Task").and_then(|value| value.parse().ok()),
        opcode: text_of("Opcode").and_then(|value| value.parse().ok()),
        process_id: attribute_of("Execution", "ProcessID").and_then(|v| v.parse().ok()),
        thread_id: attribute_of("Execution", "ThreadID").and_then(|v| v.parse().ok()),
        user_sid: attribute_of("Security", "UserID"),
        keywords: text_of("Keywords").map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmtraceopen_parser::eventmap::ValuePath;

    /// Shape emitted by EvtRender for a real Security 4624, trimmed to the interesting parts.
    const RENDERED: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-08-09T12:00:00.000000000Z" />
    <Correlation ActivityID="{2f8b0c1e-0000-0000-0000-000000000000}" />
    <Channel>Security</Channel>
    <Computer>RING0IVY24-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">adam</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="Empty"></Data>
  </EventData>
</Event>"#;

    fn resolve(xml: &str, path: &str) -> Option<String> {
        let root = parse_event_xml(xml).expect("parses");
        ValuePath::parse(path)
            .expect("path parses")
            .evaluate(&root)
            .map(|value| value.into_owned())
    }

    #[test]
    fn the_root_is_the_event_element() {
        let root = parse_event_xml(RENDERED).expect("parses");
        assert_eq!(root.name, "Event");
        assert_eq!(root.children.len(), 2);
    }

    #[test]
    fn named_event_data_resolves_through_a_map_path() {
        assert_eq!(
            resolve(RENDERED, r#"/Event/EventData/Data[@Name="LogonType"]"#).as_deref(),
            Some("10")
        );
    }

    #[test]
    fn self_closing_elements_keep_their_attributes() {
        assert_eq!(
            resolve(RENDERED, "/Event/System/Provider/@Name").as_deref(),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(
            resolve(RENDERED, "/Event/System/Correlation/@ActivityID").as_deref(),
            Some("{2f8b0c1e-0000-0000-0000-000000000000}")
        );
    }

    #[test]
    fn element_text_resolves() {
        assert_eq!(
            resolve(RENDERED, "/Event/System/Computer").as_deref(),
            Some("RING0IVY24-01")
        );
    }

    #[test]
    fn a_namespace_prefix_is_stripped_so_unprefixed_map_paths_still_match() {
        let prefixed = r#"<e:Event xmlns:e="urn:x"><e:EventData><e:Data e:Name="X">v</e:Data></e:EventData></e:Event>"#;
        assert_eq!(
            resolve(prefixed, r#"/Event/EventData/Data[@Name="X"]"#).as_deref(),
            Some("v")
        );
    }

    #[test]
    fn repeated_unnamed_data_is_preserved_for_the_engine_to_join() {
        let xml =
            "<Event><EventData><Data>a</Data><Data>b</Data><Data>c</Data></EventData></Event>";
        assert_eq!(
            resolve(xml, "/Event/EventData/Data").as_deref(),
            Some("a, b, c")
        );
    }

    #[test]
    fn an_empty_element_is_present_but_has_no_text() {
        let root = parse_event_xml(RENDERED).expect("parses");
        let event_data = root
            .children
            .iter()
            .find(|child| child.name == "EventData")
            .expect("EventData present");
        let empty = event_data
            .children
            .iter()
            .find(|child| child.attribute("Name") == Some("Empty"))
            .expect("empty Data present");
        assert_eq!(empty.text, None);
    }

    #[test]
    fn escaped_entities_are_decoded() {
        let xml =
            r#"<Event><EventData><Data Name="Cmd">a &amp; b &lt;c&gt;</Data></EventData></Event>"#;
        assert_eq!(
            resolve(xml, r#"/Event/EventData/Data[@Name="Cmd"]"#).as_deref(),
            Some("a & b <c>")
        );
    }

    #[test]
    fn cdata_content_is_captured() {
        let xml =
            "<Event><EventData><Data Name=\"X\"><![CDATA[raw <text>]]></Data></EventData></Event>";
        assert_eq!(
            resolve(xml, r#"/Event/EventData/Data[@Name="X"]"#).as_deref(),
            Some("raw <text>")
        );
    }

    #[test]
    fn system_fields_are_read_from_a_full_event() {
        let xml = r#"<Event><System>
            <Task>13312</Task><Opcode>11</Opcode><Keywords>0x8020000000000000</Keywords>
            <Execution ProcessID="1234" ThreadID="5678" />
            <Security UserID="S-1-5-18" />
        </System></Event>"#;
        let fields = extract_system_fields(&parse_event_xml(xml).expect("parses"));
        assert_eq!(fields.task, Some(13312));
        assert_eq!(fields.opcode, Some(11));
        assert_eq!(fields.process_id, Some(1234));
        assert_eq!(fields.thread_id, Some(5678));
        assert_eq!(fields.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(fields.keywords.as_deref(), Some("0x8020000000000000"));
    }

    #[test]
    fn an_omitted_field_stays_none_rather_than_defaulting_to_zero() {
        // Claiming task 0 when the provider wrote no Task element would be inventing evidence.
        let xml = "<Event><System><EventID>1</EventID></System></Event>";
        let fields = extract_system_fields(&parse_event_xml(xml).expect("parses"));
        assert_eq!(
            fields,
            SystemFields {
                event_id: Some(1),
                ..SystemFields::default()
            }
        );
    }

    #[test]
    fn an_empty_security_element_yields_no_sid() {
        let xml = r#"<Event><System><Security /></System></Event>"#;
        let fields = extract_system_fields(&parse_event_xml(xml).expect("parses"));
        assert_eq!(fields.user_sid, None);
    }

    #[test]
    fn a_non_numeric_task_is_ignored_rather_than_failing_the_record() {
        let xml = "<Event><System><Task>not-a-number</Task></System></Event>";
        let fields = extract_system_fields(&parse_event_xml(xml).expect("parses"));
        assert_eq!(fields.task, None);
    }

    #[test]
    fn an_event_without_a_system_block_yields_defaults() {
        let xml = "<Event><EventData><Data>x</Data></EventData></Event>";
        assert_eq!(
            extract_system_fields(&parse_event_xml(xml).expect("parses")),
            SystemFields::default()
        );
    }

    #[test]
    fn malformed_xml_is_an_error_rather_than_a_partial_tree() {
        assert!(parse_event_xml("<Event><System>").is_err() || parse_event_xml("<Event").is_err());
        assert!(parse_event_xml("").is_err());
    }
}
