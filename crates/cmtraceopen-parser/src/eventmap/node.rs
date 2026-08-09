//! A minimal, XML-free event tree.
//!
//! The map engine has to read values out of a rendered Windows event, but this crate is pure
//! Rust and wasm32-compatible, so it must not depend on an XML reader. Callers convert whatever
//! they already have (rendered event XML in `src-tauri`, an `evtx` record, a test literal) into
//! [`EventNode`] and hand that across.

/// A single element in a rendered event.
///
/// `name` is the local element name with any namespace prefix already stripped, because event
/// XML paths in maps are written without prefixes (`/Event/EventData/Data`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventNode {
    /// Local element name, for example `Data`.
    pub name: String,
    /// Attributes in document order, for example `("Name", "LogonType")`.
    pub attributes: Vec<(String, String)>,
    /// Element text content, if the element has any.
    pub text: Option<String>,
    /// Child elements in document order.
    pub children: Vec<EventNode>,
}

impl EventNode {
    /// Creates an element with no attributes, text, or children.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Sets the element's text content.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// Appends an attribute.
    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((name.into(), value.into()));
        self
    }

    /// Appends a child element.
    #[must_use]
    pub fn with_child(mut self, child: EventNode) -> Self {
        self.children.push(child);
        self
    }

    /// Returns the value of `name`, compared case-sensitively as event XML declares it.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Returns the child elements called `name`, in document order.
    ///
    /// `name` carries its own lifetime so callers can pass a short-lived borrow, such as a field
    /// of a path step being walked, without tying it to how long this node lives.
    pub fn children_named<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = &'a EventNode> + use<'a, 'n> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EventNode {
        EventNode::new("EventData")
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "SubjectUserName")
                    .with_text("adam"),
            )
            .with_child(
                EventNode::new("Data")
                    .with_attribute("Name", "LogonType")
                    .with_text("10"),
            )
    }

    #[test]
    fn attribute_lookup_is_case_sensitive() {
        let node = sample();
        let first = node.children.first().expect("first child");
        assert_eq!(first.attribute("Name"), Some("SubjectUserName"));
        assert_eq!(first.attribute("name"), None);
    }

    #[test]
    fn children_named_preserves_document_order() {
        let node = sample();
        let texts: Vec<_> = node
            .children_named("Data")
            .map(|child| child.text.as_deref().unwrap_or_default())
            .collect();
        assert_eq!(texts, vec!["adam", "10"]);
    }

    #[test]
    fn children_named_ignores_other_elements() {
        let node = EventNode::new("Event")
            .with_child(EventNode::new("System"))
            .with_child(EventNode::new("EventData"));
        assert_eq!(node.children_named("Data").count(), 0);
        assert_eq!(node.children_named("System").count(), 1);
    }
}
