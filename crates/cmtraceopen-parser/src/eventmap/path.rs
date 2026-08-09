//! The tiny path language used by EvtxECmd map `Value` expressions.
//!
//! Map files describe where a value lives with what looks like XPath, but the corpus only uses a
//! very small subset. Measured across all 468 upstream maps (1,837 expressions):
//!
//! | Shape | Count |
//! |---|---|
//! | `/Event/EventData/Data[@Name="X"]` | 1,441 |
//! | `/Event/UserData/<Container>/<Field>` | 204 |
//! | `/Event/EventData/Data` | 176 |
//! | `/Event/System/...`, including `Correlation/@ActivityID` | 12 |
//! | `/Event/EventData/Data[N]` | 3 |
//! | `/Event/EventData` | 1 |
//!
//! So this is an absolute element path where each step may carry an attribute-equality or
//! 1-based index predicate, optionally ending in an attribute selector. A general XPath engine
//! would be far more machinery than the grammar justifies.

use thiserror::Error;

use super::node::EventNode;

/// A failure to parse a map `Value` expression.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    /// The expression did not start with `/`.
    #[error("value path must be absolute, starting with '/': {0}")]
    NotAbsolute(String),
    /// The expression had no element steps.
    #[error("value path has no steps: {0}")]
    Empty(String),
    /// A predicate was opened but not closed, or was not understood.
    #[error("value path has a malformed predicate in step '{step}': {path}")]
    MalformedPredicate { path: String, step: String },
    /// An attribute selector appeared somewhere other than the final step.
    #[error("value path may only select an attribute in its final step: {0}")]
    MisplacedAttribute(String),
}

/// Narrows which sibling a step selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    /// `[@Name="value"]`, selecting the first sibling whose attribute matches.
    AttributeEquals { name: String, value: String },
    /// `[n]`, a 1-based index across same-named siblings, as XPath numbers them.
    Index(usize),
}

/// One element step of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Element name to match.
    pub name: String,
    /// Optional narrowing predicate.
    pub predicate: Option<Predicate>,
}

/// A parsed map `Value` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValuePath {
    steps: Vec<Step>,
    attribute: Option<String>,
}

impl ValuePath {
    /// Parses an expression such as `/Event/EventData/Data[@Name="LogonType"]`.
    pub fn parse(expression: &str) -> Result<Self, PathError> {
        let trimmed = expression.trim();
        let Some(body) = trimmed.strip_prefix('/') else {
            return Err(PathError::NotAbsolute(expression.to_string()));
        };

        let mut steps = Vec::new();
        let mut attribute = None;
        let segments: Vec<&str> = body.split('/').filter(|s| !s.is_empty()).collect();

        for (index, segment) in segments.iter().enumerate() {
            if let Some(attribute_name) = segment.strip_prefix('@') {
                if index + 1 != segments.len() {
                    return Err(PathError::MisplacedAttribute(expression.to_string()));
                }
                attribute = Some(attribute_name.to_string());
                continue;
            }
            steps.push(parse_step(segment, expression)?);
        }

        if steps.is_empty() {
            return Err(PathError::Empty(expression.to_string()));
        }

        Ok(Self { steps, attribute })
    }

    /// Resolves the path against `root`, which must be the `Event` element itself.
    ///
    /// Returns `None` when any step fails to match, which is the normal case for an optional
    /// field rather than an error: maps are written against a provider's superset of fields and
    /// individual events legitimately omit some of them.
    pub fn evaluate<'a>(&self, root: &'a EventNode) -> Option<&'a str> {
        let mut steps = self.steps.iter();
        let first = steps.next()?;
        if first.name != root.name || first.predicate.is_some() {
            return None;
        }

        let mut current = root;
        for step in steps {
            current = select(current, step)?;
        }

        match &self.attribute {
            Some(name) => current.attribute(name),
            None => current.text.as_deref(),
        }
    }
}

fn parse_step(segment: &str, expression: &str) -> Result<Step, PathError> {
    let Some(open) = segment.find('[') else {
        return Ok(Step {
            name: segment.to_string(),
            predicate: None,
        });
    };

    let malformed = || PathError::MalformedPredicate {
        path: expression.to_string(),
        step: segment.to_string(),
    };

    if !segment.ends_with(']') {
        return Err(malformed());
    }

    let name = segment[..open].to_string();
    let inner = &segment[open + 1..segment.len() - 1];

    let predicate = if let Some(rest) = inner.strip_prefix('@') {
        let (attribute, raw_value) = rest.split_once('=').ok_or_else(malformed)?;
        let value = raw_value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| {
                raw_value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
            })
            .ok_or_else(malformed)?;
        Predicate::AttributeEquals {
            name: attribute.to_string(),
            value: value.to_string(),
        }
    } else {
        let index: usize = inner.parse().map_err(|_| malformed())?;
        if index == 0 {
            return Err(malformed());
        }
        Predicate::Index(index)
    };

    Ok(Step {
        name,
        predicate: Some(predicate),
    })
}

fn select<'a>(parent: &'a EventNode, step: &Step) -> Option<&'a EventNode> {
    // Filtered inline rather than through EventNode::children_named so the step's lifetime stays
    // independent of the node's; the iterator does not outlive this call.
    let mut candidates = parent
        .children
        .iter()
        .filter(|child| child.name == step.name);
    match &step.predicate {
        // Bare step takes the first match. Whether EvtxECmd instead joins repeated unnamed
        // <Data> elements is not yet confirmed against the tool; see issue #539.
        None => candidates.next(),
        Some(Predicate::Index(index)) => candidates.nth(index - 1),
        Some(Predicate::AttributeEquals { name, value }) => {
            candidates.find(|child| child.attribute(name) == Some(value.as_str()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> EventNode {
        EventNode::new("Event")
            .with_child(
                EventNode::new("System")
                    .with_child(EventNode::new("Computer").with_text("RING0IVY24-01"))
                    .with_child(
                        EventNode::new("Correlation")
                            .with_attribute("ActivityID", "{2f8b0c1e-0000-0000-0000-000000000000}"),
                    ),
            )
            .with_child(
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
                    ),
            )
            .with_child(
                EventNode::new("UserData").with_child(
                    EventNode::new("EventInfo")
                        .with_child(EventNode::new("Username").with_text("TEST\\adam")),
                ),
            )
    }

    fn eval(expression: &str) -> Option<String> {
        ValuePath::parse(expression)
            .expect("path parses")
            .evaluate(&event())
            .map(str::to_string)
    }

    #[test]
    fn resolves_named_event_data() {
        assert_eq!(
            eval(r#"/Event/EventData/Data[@Name="LogonType"]"#).as_deref(),
            Some("10")
        );
    }

    #[test]
    fn resolves_single_quoted_predicate_value() {
        assert_eq!(
            eval("/Event/EventData/Data[@Name='SubjectUserName']").as_deref(),
            Some("adam")
        );
    }

    #[test]
    fn bare_step_takes_the_first_match() {
        assert_eq!(eval("/Event/EventData/Data").as_deref(), Some("adam"));
    }

    #[test]
    fn index_predicate_is_one_based() {
        assert_eq!(eval("/Event/EventData/Data[1]").as_deref(), Some("adam"));
        assert_eq!(eval("/Event/EventData/Data[2]").as_deref(), Some("10"));
        assert_eq!(eval("/Event/EventData/Data[3]"), None);
    }

    #[test]
    fn resolves_nested_user_data() {
        assert_eq!(
            eval("/Event/UserData/EventInfo/Username").as_deref(),
            Some("TEST\\adam")
        );
    }

    #[test]
    fn resolves_system_element_and_attribute() {
        assert_eq!(
            eval("/Event/System/Computer").as_deref(),
            Some("RING0IVY24-01")
        );
        assert_eq!(
            eval("/Event/System/Correlation/@ActivityID").as_deref(),
            Some("{2f8b0c1e-0000-0000-0000-000000000000}")
        );
    }

    #[test]
    fn missing_field_is_none_not_an_error() {
        assert_eq!(eval(r#"/Event/EventData/Data[@Name="Absent"]"#), None);
        assert_eq!(eval("/Event/EventData/Missing"), None);
    }

    #[test]
    fn container_without_text_resolves_to_none() {
        assert_eq!(eval("/Event/EventData"), None);
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(matches!(
            ValuePath::parse("Event/EventData"),
            Err(PathError::NotAbsolute(_))
        ));
    }

    #[test]
    fn rejects_attribute_before_the_final_step() {
        assert!(matches!(
            ValuePath::parse("/Event/@Name/EventData"),
            Err(PathError::MisplacedAttribute(_))
        ));
    }

    #[test]
    fn rejects_malformed_predicates() {
        for expression in [
            "/Event/EventData/Data[@Name=\"unterminated",
            "/Event/EventData/Data[@Name]",
            "/Event/EventData/Data[abc]",
            "/Event/EventData/Data[0]",
        ] {
            assert!(
                matches!(
                    ValuePath::parse(expression),
                    Err(PathError::MalformedPredicate { .. })
                ),
                "expected malformed predicate for {expression}"
            );
        }
    }

    #[test]
    fn rejects_empty_paths() {
        assert!(matches!(ValuePath::parse("/"), Err(PathError::Empty(_))));
    }

    #[test]
    fn root_mismatch_resolves_to_none() {
        let path = ValuePath::parse("/Other/EventData").expect("parses");
        assert_eq!(path.evaluate(&event()), None);
    }
}
