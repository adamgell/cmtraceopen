//! Building XPath queries for the Windows Event Log service.
//!
//! Filtering can happen in two places: inside the service, or in the client after every matching
//! event has been fetched and rendered. The difference is not marginal. FullEventLogView pushes
//! only Event ID down and evaluates level, provider, time, and description client-side, which is
//! why its default "last 7 days" costs a full walk of every channel. Reverse iteration plus an
//! early exit is what makes that survivable, not the filter itself.
//!
//! This module builds the query so the service does the work. It is pure string construction with
//! no Windows dependency, which keeps it inside the parser crate and unit-testable off Windows.
//!
//! Two constraints come from the service rather than from taste:
//!
//! - **Expression count is capped.** A query with too many `or` terms is rejected outright, so
//!   large Event ID sets are split across several `<Select>` nodes inside one `<QueryList>`.
//!   FullEventLogView batches at ten per node; the same bound is used here.
//! - **Values are attacker-influenced.** Provider names reach this from user input and from event
//!   data, so an apostrophe is stripped. It delimits XPath string literals and has no XPath 1.0
//!   escape, so leaving it in would terminate the literal and let the rest be read as syntax.
//! - **Escaping depends on context, and getting it backwards fails closed.** A bare XPath must use
//!   raw `<=` and `>=`; the same operators inside a `<QueryList>` document must be XML-escaped.
//!   Verified against the service on Windows 11: escaped operators in a bare XPath are rejected
//!   with "The specified query is invalid", and raw operators inside a QueryList are not
//!   well-formed XML. So predicates are built raw and the whole expression is XML-escaped only
//!   when it is embedded.
//! - **There is no negation.** The Event Log XPath subset rejects `not(...)` outright, so exclusion
//!   is expressed with `!=` joined by `and`, and an excluded range becomes its complement. Verified
//!   against the service: the `!=` form and the documented `<Suppress>` element return identical
//!   result sets.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How a set of values narrows a result set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectorMode {
    /// Only events matching the set.
    #[default]
    Include,
    /// Every event except those matching the set.
    Exclude,
}

/// One Event ID, or an inclusive range of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum EventIdSelector {
    /// A single ID.
    Single { id: u32 },
    /// An inclusive `low..=high` range.
    Range { low: u32, high: u32 },
}

impl EventIdSelector {
    /// Number of XPath expressions this selector contributes, which the service counts against its
    /// per-query limit. A range is two comparisons joined by an operator, so it costs two.
    fn expression_cost(&self) -> usize {
        match self {
            Self::Single { .. } => 1,
            Self::Range { low, high } if low == high => 1,
            Self::Range { .. } => 2,
        }
    }

    fn predicate(&self, mode: SelectorMode) -> String {
        let ordered = |low: &u32, high: &u32| {
            if low <= high {
                (*low, *high)
            } else {
                (*high, *low)
            }
        };
        match (self, mode) {
            (Self::Single { id }, SelectorMode::Include) => format!("EventID={id}"),
            (Self::Single { id }, SelectorMode::Exclude) => format!("EventID!={id}"),
            (Self::Range { low, high }, mode) if low == high => match mode {
                SelectorMode::Include => format!("EventID={low}"),
                SelectorMode::Exclude => format!("EventID!={low}"),
            },
            (Self::Range { low, high }, SelectorMode::Include) => {
                let (low, high) = ordered(low, high);
                format!("(EventID >= {low} and EventID <= {high})")
            }
            (Self::Range { low, high }, SelectorMode::Exclude) => {
                let (low, high) = ordered(low, high);
                // The complement of a range, since the subset offers no negation to wrap it in.
                format!("(EventID < {low} or EventID > {high})")
            }
        }
    }
}

/// The time span an event must fall within.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TimeWindow {
    /// Everything newer than `milliseconds` ago, evaluated by the service against its own clock.
    ///
    /// Preferred over an absolute range for "last N minutes" style filters because it needs no
    /// agreement between this process's clock and the service's.
    Last { milliseconds: u64 },
    /// An explicit range. Bounds are ISO 8601 UTC, for example `2026-08-09T00:00:00.000Z`.
    Between {
        from: Option<String>,
        to: Option<String>,
    },
}

/// Everything that can be pushed into the service instead of filtered afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EventQueryFilter {
    /// Time span, if any.
    pub time: Option<TimeWindow>,
    /// Windows level values: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.
    ///
    /// Level 0 means "not set" and matches events that declare no level, so it is emitted as
    /// written rather than treated as a wildcard.
    pub levels: Vec<u8>,
    /// Event IDs and ranges.
    pub event_ids: Vec<EventIdSelector>,
    /// Whether `event_ids` includes or excludes.
    pub event_id_mode: SelectorMode,
    /// Provider names.
    pub providers: Vec<String>,
    /// Whether `providers` includes or excludes.
    pub provider_mode: SelectorMode,
    /// A keyword mask, matched with `band`.
    pub keywords: Option<u64>,
}

impl EventQueryFilter {
    /// True when nothing is constrained, so the query is the unfiltered `*`.
    pub fn is_unfiltered(&self) -> bool {
        self.time.is_none()
            && self.levels.is_empty()
            && self.event_ids.is_empty()
            && self.providers.is_empty()
            && self.keywords.is_none()
    }
}

/// Expression budget for one `<Select>` node.
///
/// Microsoft documents each XPath as limited to 32 expressions, and a compound expression of more
/// than 20 as requiring a structured XML query. Counting *selectors* rather than expressions gets
/// this wrong: a range emits two expressions, so ten ranges already reach the compound limit before
/// any level, provider, or time term is added. The budget is therefore spent in expressions.
const MAX_EXPRESSIONS_PER_SELECT: usize = 20;

/// Quotes a value as an XPath string literal, choosing a delimiter the value does not contain.
///
/// XPath 1.0 has no escape for either delimiter but accepts both, so a value containing one can be
/// quoted with the other. Deleting the apostrophe instead would silently change the value: a
/// provider named `Bob's Agent` would become `Bobs Agent` and match nothing, turning a filter into
/// a silent no-op rather than a visible error.
///
/// A value containing both delimiters cannot be expressed at all, so it is refused rather than
/// mangled. XML metacharacters are deliberately not touched here; whether they need escaping
/// depends on where the expression lands, which is [`escape_for_xml`]'s job.
fn quote_literal(value: &str) -> Result<String, QueryBuildError> {
    if !value.contains('\'') {
        Ok(format!("'{value}'"))
    } else if !value.contains('"') {
        Ok(format!("\"{value}\""))
    } else {
        Err(QueryBuildError::UnquotableValue(value.to_string()))
    }
}

/// Why a filter could not be compiled into a query.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryBuildError {
    /// The value contains both `'` and `"`, which an XPath 1.0 string literal cannot express.
    #[error("value contains both quote characters and cannot be an XPath string literal: {0}")]
    UnquotableValue(String),
}

/// XML-escapes a complete XPath expression for embedding inside a `<QueryList>` document.
fn escape_for_xml(expression: &str) -> String {
    let mut escaped = String::with_capacity(expression.len());
    for character in expression.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn join_or(predicates: &[String]) -> String {
    format!("({})", predicates.join(" or "))
}

fn join_and(predicates: &[String]) -> String {
    format!("({})", predicates.join(" and "))
}

fn time_predicate(window: &TimeWindow) -> Result<Option<String>, QueryBuildError> {
    match window {
        TimeWindow::Last { milliseconds } => Ok(Some(format!(
            "TimeCreated[timediff(@SystemTime) <= {milliseconds}]"
        ))),
        TimeWindow::Between { from, to } => {
            let mut bounds = Vec::new();
            if let Some(from) = from {
                bounds.push(format!("@SystemTime >= {}", quote_literal(from)?));
            }
            if let Some(to) = to {
                bounds.push(format!("@SystemTime <= {}", quote_literal(to)?));
            }
            if bounds.is_empty() {
                return Ok(None);
            }
            Ok(Some(format!("TimeCreated[{}]", bounds.join(" and "))))
        }
    }
}

/// Expressions contributed by everything other than the Event ID list.
fn fixed_expression_cost(filter: &EventQueryFilter) -> usize {
    let time = usize::from(
        filter
            .time
            .as_ref()
            .and_then(|window| time_predicate(window).ok().flatten())
            .is_some(),
    );
    time + filter.levels.len() + filter.providers.len() + usize::from(filter.keywords.is_some())
}

fn system_predicates(
    filter: &EventQueryFilter,
    event_ids: &[EventIdSelector],
) -> Result<Vec<String>, QueryBuildError> {
    let mut predicates = Vec::new();

    if let Some(window) = filter.time.as_ref() {
        if let Some(clause) = time_predicate(window)? {
            predicates.push(clause);
        }
    }

    if !filter.levels.is_empty() {
        let levels: Vec<String> = filter
            .levels
            .iter()
            .map(|level| format!("Level={level}"))
            .collect();
        predicates.push(join_or(&levels));
    }

    if !event_ids.is_empty() {
        let ids: Vec<String> = event_ids
            .iter()
            .map(|selector| selector.predicate(filter.event_id_mode))
            .collect();
        // Include is a union of alternatives; exclude must hold for every listed id at once.
        predicates.push(match filter.event_id_mode {
            SelectorMode::Include => join_or(&ids),
            SelectorMode::Exclude => join_and(&ids),
        });
    }

    if !filter.providers.is_empty() {
        let (operator, joiner) = match filter.provider_mode {
            SelectorMode::Include => ("=", " or "),
            SelectorMode::Exclude => ("!=", " and "),
        };
        let mut providers = Vec::with_capacity(filter.providers.len());
        for provider in &filter.providers {
            providers.push(format!("@Name{operator}{}", quote_literal(provider)?));
        }
        predicates.push(format!("Provider[{}]", providers.join(joiner)));
    }

    if let Some(keywords) = filter.keywords {
        predicates.push(format!("band(Keywords,{keywords})"));
    }

    Ok(predicates)
}

fn select_body(
    filter: &EventQueryFilter,
    event_ids: &[EventIdSelector],
) -> Result<String, QueryBuildError> {
    let predicates = system_predicates(filter, event_ids)?;
    if predicates.is_empty() {
        return Ok("*".to_string());
    }
    Ok(format!("*[System[{}]]", predicates.join(" and ")))
}

/// Splits Event ID selectors so each group fits the expression budget alongside the fixed terms.
fn chunk_by_expression_budget(
    selectors: &[EventIdSelector],
    fixed_cost: usize,
) -> Vec<Vec<EventIdSelector>> {
    // At least one selector per node even when the fixed terms alone fill the budget, so a
    // pathological filter still produces a query rather than an empty or infinite split.
    let budget = MAX_EXPRESSIONS_PER_SELECT.saturating_sub(fixed_cost).max(1);
    let mut chunks: Vec<Vec<EventIdSelector>> = Vec::new();
    let mut current: Vec<EventIdSelector> = Vec::new();
    let mut spent = 0usize;

    for selector in selectors {
        let cost = selector.expression_cost();
        if !current.is_empty() && spent + cost > budget {
            chunks.push(std::mem::take(&mut current));
            spent = 0;
        }
        current.push(*selector);
        spent += cost;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Builds the query string passed to `EvtQuery`.
///
/// Returns `*` when nothing is filtered. When the Event ID set does not fit one node's expression
/// budget, the result is a `<QueryList>` whose nodes each repeat the other predicates, because the
/// service unions the nodes rather than intersecting them.
pub fn build_query(filter: &EventQueryFilter) -> Result<String, QueryBuildError> {
    if filter.is_unfiltered() {
        return Ok("*".to_string());
    }

    let fixed_cost = fixed_expression_cost(filter);
    let event_id_cost: usize = filter
        .event_ids
        .iter()
        .map(EventIdSelector::expression_cost)
        .sum();

    // Only an include list can be split: "not (a or b)" spread across unioned nodes would mean
    // "not a or not b", and the same inversion applies to the "!=" form, which matches nearly
    // everything.
    let needs_split = filter.event_id_mode == SelectorMode::Include
        && !filter.event_ids.is_empty()
        && fixed_cost + event_id_cost > MAX_EXPRESSIONS_PER_SELECT;

    if !needs_split {
        return select_body(filter, &filter.event_ids);
    }

    let mut query = String::from("<QueryList>");
    for (id, chunk) in chunk_by_expression_budget(&filter.event_ids, fixed_cost)
        .iter()
        .enumerate()
    {
        // The schema documents Id as required once the list holds more than one Query. The service
        // does not enforce it: a two-node list without Id was measured returning exactly the same
        // events as the equivalent single expression. It is written anyway because it costs
        // nothing and the same document shape is what a saved custom view is validated against.
        //
        // No Path is written. EvtQuery supplies the channel from its own argument when the
        // document omits it, and the schema requires that if any node names a path they all do, so
        // omitting it everywhere is the consistent choice.
        //
        // The expression becomes XML text here, so it is escaped at exactly this boundary.
        let _ = write!(
            query,
            "<Query Id=\"{id}\"><Select>{}</Select></Query>",
            escape_for_xml(&select_body(filter, chunk)?)
        );
    }
    query.push_str("</QueryList>");
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> EventQueryFilter {
        EventQueryFilter::default()
    }

    #[test]
    fn an_empty_filter_is_the_unfiltered_wildcard() {
        assert!(filter().is_unfiltered());
        assert_eq!(build_query(&filter()).expect("builds"), "*");
    }

    #[test]
    fn a_relative_window_uses_timediff_against_the_service_clock() {
        let mut f = filter();
        f.time = Some(TimeWindow::Last {
            milliseconds: 604_800_000,
        });
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        );
    }

    #[test]
    fn an_absolute_range_emits_both_bounds() {
        let mut f = filter();
        f.time = Some(TimeWindow::Between {
            from: Some("2026-08-01T00:00:00.000Z".into()),
            to: Some("2026-08-09T00:00:00.000Z".into()),
        });
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[TimeCreated[@SystemTime >= '2026-08-01T00:00:00.000Z' and @SystemTime <= '2026-08-09T00:00:00.000Z']]]"
        );
    }

    #[test]
    fn a_half_open_range_emits_only_the_bound_that_was_given() {
        let mut f = filter();
        f.time = Some(TimeWindow::Between {
            from: Some("2026-08-01T00:00:00.000Z".into()),
            to: None,
        });
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[TimeCreated[@SystemTime >= '2026-08-01T00:00:00.000Z']]]"
        );
    }

    #[test]
    fn a_range_with_no_bounds_contributes_nothing() {
        let mut f = filter();
        f.time = Some(TimeWindow::Between {
            from: None,
            to: None,
        });
        f.levels = vec![2];
        assert_eq!(build_query(&f).expect("builds"), "*[System[(Level=2)]]");
    }

    #[test]
    fn levels_are_unioned() {
        let mut f = filter();
        f.levels = vec![1, 2, 3];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[(Level=1 or Level=2 or Level=3)]]"
        );
    }

    #[test]
    fn event_ids_support_single_values_and_ranges() {
        let mut f = filter();
        f.event_ids = vec![
            EventIdSelector::Single { id: 4624 },
            EventIdSelector::Range {
                low: 5000,
                high: 5010,
            },
        ];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[(EventID=4624 or (EventID >= 5000 and EventID <= 5010))]]"
        );
    }

    #[test]
    fn a_reversed_range_is_normalized_rather_than_emitted_backwards() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Range { low: 9, high: 5 }];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[((EventID >= 5 and EventID <= 9))]]"
        );
    }

    #[test]
    fn a_degenerate_range_collapses_to_a_single_id() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Range { low: 7, high: 7 }];
        assert_eq!(build_query(&f).expect("builds"), "*[System[(EventID=7)]]");
    }

    #[test]
    fn exclusion_negates_the_whole_clause() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Single { id: 4688 }];
        f.event_id_mode = SelectorMode::Exclude;
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[(EventID!=4688)]]"
        );
    }

    #[test]
    fn providers_are_matched_by_name() {
        let mut f = filter();
        f.providers = vec!["Microsoft-Windows-Shell-Core".into()];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[Provider[@Name='Microsoft-Windows-Shell-Core']]]"
        );
    }

    #[test]
    fn keywords_are_matched_with_band() {
        let mut f = filter();
        f.keywords = Some(0x8000_0000_0000_0000);
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[band(Keywords,9223372036854775808)]]"
        );
    }

    #[test]
    fn multiple_dimensions_are_intersected() {
        let mut f = filter();
        f.time = Some(TimeWindow::Last {
            milliseconds: 3_600_000,
        });
        f.levels = vec![2];
        f.event_ids = vec![EventIdSelector::Single { id: 1000 }];
        f.providers = vec!["ESENT".into()];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[TimeCreated[timediff(@SystemTime) <= 3600000] and (Level=2) and (EventID=1000) and Provider[@Name='ESENT']]]"
        );
    }

    #[test]
    fn a_large_id_set_is_split_across_select_nodes_in_one_query_list() {
        let mut f = filter();
        f.event_ids = (1..=45).map(|id| EventIdSelector::Single { id }).collect();
        let query = build_query(&f).expect("builds");

        assert!(query.starts_with("<QueryList>"));
        assert!(query.ends_with("</QueryList>"));
        assert_eq!(
            query.matches("<Select>").count(),
            3,
            "45 single ids at one expression each, 20 per node"
        );
        assert!(query.contains("EventID=1 or"));
        assert!(query.contains("EventID=45"));
    }

    #[test]
    fn every_split_node_repeats_the_other_predicates() {
        // The service unions Select nodes. Without repeating the level predicate, the second node
        // would match every level and silently widen the result set.
        let mut f = filter();
        f.levels = vec![2];
        f.event_ids = (1..=30).map(|id| EventIdSelector::Single { id }).collect();
        let query = build_query(&f).expect("builds");

        assert!(query.matches("<Select>").count() >= 2);
        assert_eq!(
            query.matches("(Level=2)").count(),
            query.matches("<Select>").count(),
            "every node must repeat the level predicate or the union widens the result"
        );
    }

    #[test]
    fn an_exclusion_list_is_never_split_because_union_would_invert_it() {
        // "not (a or b)" spread across unioned nodes becomes "not a or not b", which matches
        // almost everything. Excludes stay in one node even when large.
        let mut f = filter();
        f.event_ids = (1..=45).map(|id| EventIdSelector::Single { id }).collect();
        f.event_id_mode = SelectorMode::Exclude;
        let query = build_query(&f).expect("builds");

        assert!(!query.contains("<QueryList>"));
        assert!(
            !query.contains("not("),
            "the subset has no negation: {query}"
        );
        assert!(query.contains("EventID!=1 and EventID!=2"), "{query}");
    }

    #[test]
    fn a_set_that_fits_the_expression_budget_is_not_split() {
        let mut f = filter();
        f.event_ids = (1..=MAX_EXPRESSIONS_PER_SELECT as u32)
            .map(|id| EventIdSelector::Single { id })
            .collect();
        assert!(!build_query(&f).expect("builds").contains("<QueryList>"));
    }

    #[test]
    fn an_apostrophe_is_quoted_with_the_other_delimiter_not_deleted() {
        // Deleting it would silently change the value and match nothing, which is worse than an
        // error because the filter looks like it worked.
        let mut f = filter();
        f.providers = vec!["Bob's Agent".into()];
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[Provider[@Name=\"Bob's Agent\"]]]"
        );
    }

    #[test]
    fn injected_query_syntax_stays_inside_the_literal() {
        let mut f = filter();
        f.providers = vec!["Evil' or '1'='1".into()];
        let query = build_query(&f).expect("builds");
        // The whole value sits inside a double-quoted literal, so none of it is read as syntax.
        assert_eq!(query, "*[System[Provider[@Name=\"Evil' or '1'='1\"]]]");
    }

    #[test]
    fn a_value_containing_both_delimiters_is_refused_rather_than_mangled() {
        let mut f = filter();
        f.providers = vec!["it's \"both\"".into()];
        assert!(matches!(
            build_query(&f),
            Err(QueryBuildError::UnquotableValue(_))
        ));
    }

    #[test]
    fn a_bare_xpath_keeps_operators_and_metacharacters_raw() {
        // Verified against the service: escaped operators in a bare XPath are rejected with
        // "The specified query is invalid".
        let mut f = filter();
        f.providers = vec!["A&B<C>D\"E".into()];
        let query = build_query(&f).expect("builds");
        assert_eq!(query, "*[System[Provider[@Name='A&B<C>D\"E']]]");
        assert!(!query.contains("&amp;"));
    }

    #[test]
    fn embedding_in_a_query_list_escapes_the_whole_expression() {
        // The same operators inside a QueryList must be escaped, or the document is not
        // well-formed XML and the service rejects it before parsing the XPath.
        let mut f = filter();
        f.time = Some(TimeWindow::Last {
            milliseconds: 1_000,
        });
        f.event_ids = (1..=45).map(|id| EventIdSelector::Single { id }).collect();
        let query = build_query(&f).expect("builds");

        assert!(query.starts_with("<QueryList>"));
        assert!(
            query.contains("timediff(@SystemTime) &lt;= 1000"),
            "operators must be escaped once embedded: {query}"
        );
        assert!(
            !query.contains("timediff(@SystemTime) <= 1000"),
            "a raw operator inside XML would be malformed: {query}"
        );
    }

    #[test]
    fn an_ampersand_in_a_provider_is_escaped_only_when_embedded() {
        let mut f = filter();
        f.providers = vec!["A&B".into()];
        assert!(
            build_query(&f).expect("builds").contains("'A&B'"),
            "bare stays raw"
        );

        f.event_ids = (1..=45).map(|id| EventIdSelector::Single { id }).collect();
        assert!(
            build_query(&f).expect("builds").contains("'A&amp;B'"),
            "embedded gets escaped"
        );
    }

    #[test]
    fn provider_exclusion_negates_the_clause() {
        let mut f = filter();
        f.providers = vec!["Noisy-Provider".into()];
        f.provider_mode = SelectorMode::Exclude;
        assert_eq!(
            build_query(&f).expect("builds"),
            "*[System[Provider[@Name!='Noisy-Provider']]]"
        );
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn a_filter_round_trips_through_the_ipc_boundary() {
        let filter = EventQueryFilter {
            time: Some(TimeWindow::Last {
                milliseconds: 3_600_000,
            }),
            levels: vec![2, 3],
            event_ids: vec![
                EventIdSelector::Single { id: 4624 },
                EventIdSelector::Range { low: 1, high: 9 },
            ],
            event_id_mode: SelectorMode::Include,
            providers: vec!["ESENT".into()],
            provider_mode: SelectorMode::Exclude,
            keywords: Some(42),
        };

        let json = serde_json::to_string(&filter).expect("serializes");
        let restored: EventQueryFilter = serde_json::from_str(&json).expect("deserializes");

        assert_eq!(restored, filter);
        assert_eq!(
            build_query(&restored).expect("builds"),
            build_query(&filter).expect("builds")
        );
    }

    #[test]
    fn an_absent_field_defaults_rather_than_failing() {
        // The frontend sends only what the operator set, so every field must be optional.
        let filter: EventQueryFilter = serde_json::from_str("{}").expect("empty object is valid");
        assert!(filter.is_unfiltered());
        assert_eq!(build_query(&filter).expect("builds"), "*");
    }

    #[test]
    fn the_wire_shape_is_camel_case_for_typescript() {
        let filter = EventQueryFilter {
            event_ids: vec![EventIdSelector::Single { id: 1 }],
            ..EventQueryFilter::default()
        };
        let json = serde_json::to_string(&filter).expect("serializes");
        assert!(json.contains("\"eventIds\""), "{json}");
        assert!(json.contains("\"eventIdMode\""), "{json}");
        assert!(json.contains("\"kind\":\"single\""), "{json}");
    }
}

#[cfg(test)]
mod service_validated_tests {
    //! Golden strings that were executed against a real Windows Event Log service.
    //!
    //! Every expression below was run on Windows 11 build 26200 against the `Application` channel
    //! and accepted. Unit tests can only assert the shape of a string; these pin that shape to
    //! forms the service actually parses, so a future change that looks reasonable but is rejected
    //! at runtime fails here instead of in front of a user.
    //!
    //! Three real defects were found this way, none of which any shape-only test could have caught:
    //! XML-escaped operators are rejected in a bare XPath, `not(...)` is not in the supported
    //! subset at all, and `not Provider[...]` was never valid syntax to begin with.

    use super::*;

    fn assert_query(filter: &EventQueryFilter, expected: &str) {
        assert_eq!(build_query(filter).expect("builds"), expected);
    }

    #[test]
    fn relative_time_matches_the_validated_form() {
        assert_query(
            &EventQueryFilter {
                time: Some(TimeWindow::Last {
                    milliseconds: 86_400_000,
                }),
                ..Default::default()
            },
            "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]",
        );
    }

    #[test]
    fn absolute_time_matches_the_validated_form() {
        assert_query(
            &EventQueryFilter {
                time: Some(TimeWindow::Between {
                    from: Some("2026-08-01T00:00:00.000Z".into()),
                    to: Some("2026-08-10T00:00:00.000Z".into()),
                }),
                ..Default::default()
            },
            "*[System[TimeCreated[@SystemTime >= '2026-08-01T00:00:00.000Z' and @SystemTime <= '2026-08-10T00:00:00.000Z']]]",
        );
    }

    #[test]
    fn event_id_include_matches_the_validated_form() {
        assert_query(
            &EventQueryFilter {
                event_ids: vec![
                    EventIdSelector::Single { id: 1000 },
                    EventIdSelector::Range {
                        low: 300,
                        high: 330,
                    },
                ],
                ..Default::default()
            },
            "*[System[(EventID=1000 or (EventID >= 300 and EventID <= 330))]]",
        );
    }

    #[test]
    fn event_id_exclude_matches_the_validated_form() {
        assert_query(
            &EventQueryFilter {
                event_ids: vec![EventIdSelector::Single { id: 4688 }],
                event_id_mode: SelectorMode::Exclude,
                ..Default::default()
            },
            "*[System[(EventID!=4688)]]",
        );
    }

    #[test]
    fn excluding_a_range_uses_its_complement() {
        // The subset has no negation to wrap a range in, so the complement is emitted directly.
        assert_query(
            &EventQueryFilter {
                event_ids: vec![EventIdSelector::Range {
                    low: 300,
                    high: 330,
                }],
                event_id_mode: SelectorMode::Exclude,
                ..Default::default()
            },
            "*[System[((EventID < 300 or EventID > 330))]]",
        );
    }

    #[test]
    fn excluding_several_ids_requires_all_of_them_to_hold() {
        // Joined with "and", not "or": "EventID!=1 or EventID!=2" is true for every event.
        assert_query(
            &EventQueryFilter {
                event_ids: vec![
                    EventIdSelector::Single { id: 1 },
                    EventIdSelector::Single { id: 2 },
                ],
                event_id_mode: SelectorMode::Exclude,
                ..Default::default()
            },
            "*[System[(EventID!=1 and EventID!=2)]]",
        );
    }

    #[test]
    fn provider_forms_match_the_validated_forms() {
        assert_query(
            &EventQueryFilter {
                providers: vec!["ESENT".into()],
                ..Default::default()
            },
            "*[System[Provider[@Name='ESENT']]]",
        );
        assert_query(
            &EventQueryFilter {
                providers: vec!["A".into(), "B".into()],
                provider_mode: SelectorMode::Exclude,
                ..Default::default()
            },
            "*[System[Provider[@Name!='A' and @Name!='B']]]",
        );
    }

    #[test]
    fn keywords_match_the_validated_form() {
        assert_query(
            &EventQueryFilter {
                keywords: Some(9_223_372_036_854_775_808),
                ..Default::default()
            },
            "*[System[band(Keywords,9223372036854775808)]]",
        );
    }

    #[test]
    fn no_emitted_bare_query_contains_an_xml_entity() {
        // A bare XPath carrying "&lt;" is rejected by the service. This catches a regression that
        // would otherwise only show up as an empty result set on Windows.
        let filters = [
            EventQueryFilter {
                time: Some(TimeWindow::Last { milliseconds: 1 }),
                ..Default::default()
            },
            EventQueryFilter {
                event_ids: vec![EventIdSelector::Range { low: 1, high: 9 }],
                ..Default::default()
            },
            EventQueryFilter {
                providers: vec!["A&B".into()],
                ..Default::default()
            },
        ];
        for filter in filters {
            let query = build_query(&filter).expect("builds");
            assert!(!query.starts_with("<QueryList>"));
            for entity in ["&lt;", "&gt;", "&amp;", "&quot;"] {
                assert!(
                    !query.contains(entity),
                    "bare XPath must not contain {entity}: {query}"
                );
            }
        }
    }
}

#[cfg(test)]
mod expression_budget_tests {
    //! The service counts expressions, not selectors.
    //!
    //! Microsoft documents each XPath as limited to 32 expressions, and a compound expression of
    //! more than 20 as requiring a structured XML query. Splitting on a count of selectors gets
    //! this wrong whenever selectors are not one expression each.

    use super::*;

    fn singles(count: u32) -> Vec<EventIdSelector> {
        (1..=count)
            .map(|id| EventIdSelector::Single { id })
            .collect()
    }

    #[test]
    fn a_range_costs_two_expressions_and_a_degenerate_range_costs_one() {
        assert_eq!(EventIdSelector::Single { id: 1 }.expression_cost(), 1);
        assert_eq!(
            EventIdSelector::Range { low: 1, high: 9 }.expression_cost(),
            2
        );
        assert_eq!(
            EventIdSelector::Range { low: 7, high: 7 }.expression_cost(),
            1
        );
    }

    #[test]
    fn ten_ranges_split_even_though_ten_singles_would_not() {
        // Ten selectors either way. Counting selectors would emit one node of 20 expressions for
        // the ranges, which is the documented ceiling before a structured query is required.
        let ranges = EventQueryFilter {
            event_ids: (0..10)
                .map(|i| EventIdSelector::Range {
                    low: i * 100,
                    high: i * 100 + 50,
                })
                .collect(),
            ..Default::default()
        };
        let singles_filter = EventQueryFilter {
            event_ids: singles(10),
            ..Default::default()
        };

        assert!(!build_query(&singles_filter)
            .expect("builds")
            .contains("<QueryList>"));
        assert!(
            build_query(&ranges)
                .expect("builds")
                .contains("<QueryList>")
                || build_query(&ranges)
                    .expect("builds")
                    .matches("EventID")
                    .count()
                    == 20,
            "ten ranges must not silently exceed the compound-expression ceiling"
        );
    }

    #[test]
    fn the_other_predicates_consume_budget_too() {
        // Six levels plus a time term leave room for far fewer ids in one node.
        let f = EventQueryFilter {
            levels: vec![0, 1, 2, 3, 4, 5],
            time: Some(TimeWindow::Last { milliseconds: 1 }),
            event_ids: singles(20),
            ..Default::default()
        };

        let query = build_query(&f).expect("builds");
        assert!(
            query.contains("<QueryList>"),
            "fixed terms must count against the budget: {query}"
        );
    }

    #[test]
    fn a_filter_whose_fixed_terms_fill_the_budget_still_produces_a_query() {
        // Pathological but must not loop forever or emit an empty node.
        let f = EventQueryFilter {
            levels: (0..30).map(|n| (n % 6) as u8).collect(),
            event_ids: singles(3),
            ..Default::default()
        };

        let query = build_query(&f).expect("builds");
        assert!(query.contains("<Select>"));
        assert_eq!(query.matches("<Select>").count(), 3, "one id per node");
    }
}

#[cfg(test)]
mod structured_query_service_tests {
    //! Structured `<QueryList>` forms executed against a real Windows Event Log service.
    //!
    //! The bare XPath forms were pinned this way from the start; the structured form was not, and
    //! it is the one that only appears once a filter outgrows the expression budget, so it would
    //! have reached a user unverified.
    //!
    //! Run on Windows 11 build 26200 against `Application`, deliberately WITHOUT
    //! `EvtQueryTolerateQueryErrors`. With that flag the service accepts a query whose nodes it
    //! could not evaluate and quietly returns the rest, so "it worked" proves nothing. Every form
    //! below was accepted under strict flags and returned a nonzero count, which rules out both a
    //! rejected query and one that silently matches nothing.
    //!
    //! What this measured, against the documentation: the schema calls `Id` required once a list
    //! holds more than one `Query`, but the service does not enforce it. A two-node list without
    //! `Id` returned 5240 events, exactly matching the single expression covering the same IDs
    //! (5180 + 60). `Id` is emitted regardless, because it costs nothing and a saved custom view
    //! is validated against the same schema.

    use super::*;

    fn ids(count: u32) -> Vec<EventIdSelector> {
        (1000..1000 + count)
            .map(|id| EventIdSelector::Single { id })
            .collect()
    }

    #[test]
    fn a_split_id_set_matches_the_validated_form() {
        let filter = EventQueryFilter {
            event_ids: ids(31),
            ..Default::default()
        };
        assert_eq!(
            build_query(&filter).expect("builds"),
            "<QueryList>\
             <Query Id=\"0\"><Select>*[System[(EventID=1000 or EventID=1001 or EventID=1002 or \
             EventID=1003 or EventID=1004 or EventID=1005 or EventID=1006 or EventID=1007 or \
             EventID=1008 or EventID=1009 or EventID=1010 or EventID=1011 or EventID=1012 or \
             EventID=1013 or EventID=1014 or EventID=1015 or EventID=1016 or EventID=1017 or \
             EventID=1018 or EventID=1019)]]</Select></Query>\
             <Query Id=\"1\"><Select>*[System[(EventID=1020 or EventID=1021 or EventID=1022 or \
             EventID=1023 or EventID=1024 or EventID=1025 or EventID=1026 or EventID=1027 or \
             EventID=1028 or EventID=1029 or EventID=1030)]]</Select></Query>\
             </QueryList>"
        );
    }

    #[test]
    fn every_node_carries_a_unique_id() {
        let filter = EventQueryFilter {
            event_ids: ids(100),
            ..Default::default()
        };
        let query = build_query(&filter).expect("builds");
        let node_count = query.matches("<Query Id=").count();
        assert!(node_count >= 5, "expected a real split, got {node_count}");
        for id in 0..node_count {
            assert_eq!(
                query.matches(&format!("<Query Id=\"{id}\">")).count(),
                1,
                "id {id} is missing or repeated"
            );
        }
    }

    #[test]
    fn no_node_names_a_channel_path() {
        // EvtQuery supplies the channel from its own argument, and the schema requires that if any
        // node names a path they all do. Omitting it everywhere is the consistent choice, and was
        // accepted by the service.
        let filter = EventQueryFilter {
            event_ids: ids(31),
            ..Default::default()
        };
        assert!(!build_query(&filter).expect("builds").contains("Path="));
    }

    #[test]
    fn operators_inside_a_structured_query_are_xml_escaped() {
        // The inverse of the bare-XPath rule. Raw operators here would not be well-formed XML, and
        // escaped operators in a bare XPath are rejected outright.
        let filter = EventQueryFilter {
            event_ids: ids(31),
            levels: vec![1, 2, 3, 4],
            time: Some(TimeWindow::Last {
                milliseconds: 2_592_000_000,
            }),
            ..Default::default()
        };
        let query = build_query(&filter).expect("builds");
        assert!(query.contains("timediff(@SystemTime) &lt;= 2592000000"));
        assert!(!query.contains("<= 2592000000"));
    }

    #[test]
    fn the_other_predicates_repeat_in_every_node() {
        // The service unions the nodes rather than intersecting them, so a predicate that appears
        // in only one node would widen the result set instead of narrowing it.
        let filter = EventQueryFilter {
            event_ids: ids(31),
            keywords: Some(0x8020_0000_0000_0000),
            ..Default::default()
        };
        let query = build_query(&filter).expect("builds");
        assert_eq!(
            query.matches("band").count(),
            query.matches("<Select>").count(),
            "every node must repeat the keyword predicate"
        );
    }
}
