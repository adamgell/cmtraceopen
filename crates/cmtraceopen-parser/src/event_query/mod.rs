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
//!   data, so every interpolated value is escaped. An unescaped apostrophe would otherwise
//!   terminate the literal and let the rest of the string be read as query syntax.

use std::fmt::Write as _;

/// How a set of values narrows a result set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectorMode {
    /// Only events matching the set.
    #[default]
    Include,
    /// Every event except those matching the set.
    Exclude,
}

/// One Event ID, or an inclusive range of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIdSelector {
    /// A single ID.
    Single(u32),
    /// An inclusive `low..=high` range.
    Range(u32, u32),
}

impl EventIdSelector {
    fn predicate(&self) -> String {
        match self {
            Self::Single(id) => format!("EventID={id}"),
            Self::Range(low, high) if low == high => format!("EventID={low}"),
            Self::Range(low, high) => {
                let (low, high) = if low <= high {
                    (low, high)
                } else {
                    (high, low)
                };
                format!("(EventID &gt;= {low} and EventID &lt;= {high})")
            }
        }
    }
}

/// The time span an event must fall within.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

/// Event IDs per `<Select>` node.
///
/// The service rejects a query whose expression count is too high. FullEventLogView splits at ten
/// per node, a bound reached by its own changelog after users hit the limit at twenty-three
/// expressions, so ten is used here too rather than rediscovering the ceiling in production.
const EVENT_IDS_PER_SELECT: usize = 10;

/// Escapes a value for inclusion inside an XPath string literal within XML.
///
/// Both layers matter. The XML layer would otherwise break on `&` or `<`, and the XPath layer
/// would break on the apostrophe that delimits the literal.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            // No XPath 1.0 escape exists for the delimiter, so it is dropped rather than allowed
            // to terminate the literal. Provider names do not legitimately contain apostrophes.
            '\'' => {}
            _ => escaped.push(character),
        }
    }
    escaped
}

fn join_or(predicates: &[String]) -> String {
    format!("({})", predicates.join(" or "))
}

fn time_predicate(window: &TimeWindow) -> Option<String> {
    match window {
        TimeWindow::Last { milliseconds } => Some(format!(
            "TimeCreated[timediff(@SystemTime) &lt;= {milliseconds}]"
        )),
        TimeWindow::Between { from, to } => {
            let mut bounds = Vec::new();
            if let Some(from) = from {
                bounds.push(format!("@SystemTime &gt;= '{}'", escape(from)));
            }
            if let Some(to) = to {
                bounds.push(format!("@SystemTime &lt;= '{}'", escape(to)));
            }
            if bounds.is_empty() {
                return None;
            }
            Some(format!("TimeCreated[{}]", bounds.join(" and ")))
        }
    }
}

fn system_predicates(filter: &EventQueryFilter, event_ids: &[EventIdSelector]) -> Vec<String> {
    let mut predicates = Vec::new();

    if let Some(window) = filter.time.as_ref().and_then(time_predicate) {
        predicates.push(window);
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
        let ids: Vec<String> = event_ids.iter().map(EventIdSelector::predicate).collect();
        let clause = join_or(&ids);
        predicates.push(match filter.event_id_mode {
            SelectorMode::Include => clause,
            SelectorMode::Exclude => format!("not {clause}"),
        });
    }

    if !filter.providers.is_empty() {
        let providers: Vec<String> = filter
            .providers
            .iter()
            .map(|provider| format!("@Name='{}'", escape(provider)))
            .collect();
        let clause = format!("Provider[{}]", providers.join(" or "));
        predicates.push(match filter.provider_mode {
            SelectorMode::Include => clause,
            SelectorMode::Exclude => format!("not {clause}"),
        });
    }

    if let Some(keywords) = filter.keywords {
        predicates.push(format!("band(Keywords,{keywords})"));
    }

    predicates
}

fn select_body(filter: &EventQueryFilter, event_ids: &[EventIdSelector]) -> String {
    let predicates = system_predicates(filter, event_ids);
    if predicates.is_empty() {
        return "*".to_string();
    }
    format!("*[System[{}]]", predicates.join(" and "))
}

/// Builds the query string passed to `EvtQuery`.
///
/// Returns `*` when nothing is filtered. When the Event ID set is larger than one `<Select>` can
/// carry, the result is a `<QueryList>` whose nodes each repeat the other predicates, because the
/// service unions the nodes rather than intersecting them.
pub fn build_query(filter: &EventQueryFilter) -> String {
    if filter.is_unfiltered() {
        return "*".to_string();
    }

    // Only an include list can be split: "not (a or b)" spread across unioned nodes would mean
    // "not a or not b", which matches nearly everything.
    let needs_split = filter.event_id_mode == SelectorMode::Include
        && filter.event_ids.len() > EVENT_IDS_PER_SELECT;

    if !needs_split {
        return select_body(filter, &filter.event_ids);
    }

    let mut query = String::from("<QueryList>");
    for chunk in filter.event_ids.chunks(EVENT_IDS_PER_SELECT) {
        let _ = write!(
            query,
            "<Query><Select>{}</Select></Query>",
            select_body(filter, chunk)
        );
    }
    query.push_str("</QueryList>");
    query
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
        assert_eq!(build_query(&filter()), "*");
    }

    #[test]
    fn a_relative_window_uses_timediff_against_the_service_clock() {
        let mut f = filter();
        f.time = Some(TimeWindow::Last {
            milliseconds: 604_800_000,
        });
        assert_eq!(
            build_query(&f),
            "*[System[TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]"
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
            build_query(&f),
            "*[System[TimeCreated[@SystemTime &gt;= '2026-08-01T00:00:00.000Z' and @SystemTime &lt;= '2026-08-09T00:00:00.000Z']]]"
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
            build_query(&f),
            "*[System[TimeCreated[@SystemTime &gt;= '2026-08-01T00:00:00.000Z']]]"
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
        assert_eq!(build_query(&f), "*[System[(Level=2)]]");
    }

    #[test]
    fn levels_are_unioned() {
        let mut f = filter();
        f.levels = vec![1, 2, 3];
        assert_eq!(
            build_query(&f),
            "*[System[(Level=1 or Level=2 or Level=3)]]"
        );
    }

    #[test]
    fn event_ids_support_single_values_and_ranges() {
        let mut f = filter();
        f.event_ids = vec![
            EventIdSelector::Single(4624),
            EventIdSelector::Range(5000, 5010),
        ];
        assert_eq!(
            build_query(&f),
            "*[System[(EventID=4624 or (EventID &gt;= 5000 and EventID &lt;= 5010))]]"
        );
    }

    #[test]
    fn a_reversed_range_is_normalized_rather_than_emitted_backwards() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Range(9, 5)];
        assert_eq!(
            build_query(&f),
            "*[System[((EventID &gt;= 5 and EventID &lt;= 9))]]"
        );
    }

    #[test]
    fn a_degenerate_range_collapses_to_a_single_id() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Range(7, 7)];
        assert_eq!(build_query(&f), "*[System[(EventID=7)]]");
    }

    #[test]
    fn exclusion_negates_the_whole_clause() {
        let mut f = filter();
        f.event_ids = vec![EventIdSelector::Single(4688)];
        f.event_id_mode = SelectorMode::Exclude;
        assert_eq!(build_query(&f), "*[System[not (EventID=4688)]]");
    }

    #[test]
    fn providers_are_matched_by_name() {
        let mut f = filter();
        f.providers = vec!["Microsoft-Windows-Shell-Core".into()];
        assert_eq!(
            build_query(&f),
            "*[System[Provider[@Name='Microsoft-Windows-Shell-Core']]]"
        );
    }

    #[test]
    fn keywords_are_matched_with_band() {
        let mut f = filter();
        f.keywords = Some(0x8000_0000_0000_0000);
        assert_eq!(
            build_query(&f),
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
        f.event_ids = vec![EventIdSelector::Single(1000)];
        f.providers = vec!["ESENT".into()];
        assert_eq!(
            build_query(&f),
            "*[System[TimeCreated[timediff(@SystemTime) &lt;= 3600000] and (Level=2) and (EventID=1000) and Provider[@Name='ESENT']]]"
        );
    }

    #[test]
    fn a_large_id_set_is_split_across_select_nodes_in_one_query_list() {
        let mut f = filter();
        f.event_ids = (1..=25).map(EventIdSelector::Single).collect();
        let query = build_query(&f);

        assert!(query.starts_with("<QueryList>"));
        assert!(query.ends_with("</QueryList>"));
        assert_eq!(
            query.matches("<Select>").count(),
            3,
            "25 ids at 10 per node"
        );
        assert!(query.contains("EventID=1 or"));
        assert!(query.contains("EventID=25"));
    }

    #[test]
    fn every_split_node_repeats_the_other_predicates() {
        // The service unions Select nodes. Without repeating the level predicate, the second node
        // would match every level and silently widen the result set.
        let mut f = filter();
        f.levels = vec![2];
        f.event_ids = (1..=15).map(EventIdSelector::Single).collect();
        let query = build_query(&f);

        assert_eq!(query.matches("<Select>").count(), 2);
        assert_eq!(query.matches("(Level=2)").count(), 2);
    }

    #[test]
    fn an_exclusion_list_is_never_split_because_union_would_invert_it() {
        // "not (a or b)" spread across unioned nodes becomes "not a or not b", which matches
        // almost everything. Excludes stay in one node even when large.
        let mut f = filter();
        f.event_ids = (1..=25).map(EventIdSelector::Single).collect();
        f.event_id_mode = SelectorMode::Exclude;
        let query = build_query(&f);

        assert!(!query.contains("<QueryList>"));
        assert!(query.starts_with("*[System[not ("));
    }

    #[test]
    fn a_set_exactly_at_the_bound_is_not_split() {
        let mut f = filter();
        f.event_ids = (1..=EVENT_IDS_PER_SELECT as u32)
            .map(EventIdSelector::Single)
            .collect();
        assert!(!build_query(&f).contains("<QueryList>"));
    }

    #[test]
    fn an_apostrophe_cannot_terminate_a_string_literal() {
        let mut f = filter();
        f.providers = vec!["Evil' or '1'='1".into()];
        let query = build_query(&f);

        assert!(
            !query.contains("or '1'='1"),
            "injected syntax must not survive: {query}"
        );
        assert_eq!(query, "*[System[Provider[@Name='Evil or 1=1']]]");
    }

    #[test]
    fn xml_metacharacters_in_a_provider_are_escaped() {
        let mut f = filter();
        f.providers = vec!["A&B<C>D\"E".into()];
        assert_eq!(
            build_query(&f),
            "*[System[Provider[@Name='A&amp;B&lt;C&gt;D&quot;E']]]"
        );
    }

    #[test]
    fn provider_exclusion_negates_the_clause() {
        let mut f = filter();
        f.providers = vec!["Noisy-Provider".into()];
        f.provider_mode = SelectorMode::Exclude;
        assert_eq!(
            build_query(&f),
            "*[System[not Provider[@Name='Noisy-Provider']]]"
        );
    }
}
