//! Console plain-text export layout detection.
//!
//! The header row is the layout contract. Console lets the operator choose which columns
//! are visible before copying, and localizes the header titles, so a layout is resolved in
//! two steps:
//!
//! 1. tokenize the header row and map each title to a [`PortalConsoleColumn`] role through
//!    an alias table;
//! 2. look the resulting role sequence up in an explicit registry of known layouts.
//!
//! An unmapped title or an unregistered role sequence is a *detected* unknown layout, never
//! a guess. That is what keeps a different Console version or locale from being mis-parsed.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{PortalConsoleColumn, PortalConsoleDecimalSeparator};

/// Header titles that resolve to a column role.
///
/// English titles are the documented default. The non-English aliases are a best-effort
/// extension point: an unrecognized title simply yields an unknown layout, which degrades
/// conservatively, so adding aliases can only ever widen support and never mis-parse.
const COLUMN_ALIASES: &[(&str, PortalConsoleColumn, Option<&str>)] = &[
    // English (documented default layout).
    ("timestamp", PortalConsoleColumn::Timestamp, None),
    ("time", PortalConsoleColumn::Timestamp, None),
    ("thread", PortalConsoleColumn::Thread, None),
    ("type", PortalConsoleColumn::Type, None),
    ("activity", PortalConsoleColumn::Activity, None),
    ("pid", PortalConsoleColumn::Pid, None),
    ("ttl", PortalConsoleColumn::Ttl, None),
    ("subsystem", PortalConsoleColumn::Subsystem, None),
    ("category", PortalConsoleColumn::Category, None),
    ("process", PortalConsoleColumn::Process, None),
    ("library", PortalConsoleColumn::Library, None),
    ("message", PortalConsoleColumn::Message, None),
    // German.
    ("zeitstempel", PortalConsoleColumn::Timestamp, Some("de")),
    ("typ", PortalConsoleColumn::Type, Some("de")),
    ("art", PortalConsoleColumn::Type, Some("de")),
    ("aktivität", PortalConsoleColumn::Activity, Some("de")),
    ("teilsystem", PortalConsoleColumn::Subsystem, Some("de")),
    ("kategorie", PortalConsoleColumn::Category, Some("de")),
    ("prozess", PortalConsoleColumn::Process, Some("de")),
    ("nachricht", PortalConsoleColumn::Message, Some("de")),
];

/// Explicitly registered layouts. A role sequence outside this list is unsupported.
const LAYOUT_REGISTRY: &[(&str, &[PortalConsoleColumn])] = &[
    (
        "console-plaintext-v1",
        &[
            PortalConsoleColumn::Timestamp,
            PortalConsoleColumn::Thread,
            PortalConsoleColumn::Type,
            PortalConsoleColumn::Activity,
            PortalConsoleColumn::Pid,
            PortalConsoleColumn::Ttl,
        ],
    ),
    (
        "console-plaintext-v2-subsystem-columns",
        &[
            PortalConsoleColumn::Timestamp,
            PortalConsoleColumn::Thread,
            PortalConsoleColumn::Type,
            PortalConsoleColumn::Activity,
            PortalConsoleColumn::Pid,
            PortalConsoleColumn::Ttl,
            PortalConsoleColumn::Subsystem,
            PortalConsoleColumn::Category,
        ],
    ),
];

/// The layout assumed when Console-shaped records appear without a header row.
pub(super) const FALLBACK_LAYOUT_ID: &str = "console-plaintext-v1";

/// Outcome of resolving a header row.
pub(super) enum HeaderResolution {
    /// The role sequence matched a registered layout.
    Registered {
        layout_id: &'static str,
        columns: Vec<PortalConsoleColumn>,
        locale_hint: Option<String>,
    },
    /// The line is header-shaped but its layout is not registered.
    Unregistered { detail: String },
    /// The line is not a Console header row at all.
    NotAHeader,
}

/// Split a Console header row into column titles.
///
/// Console pads columns with runs of spaces, so a run of two or more spaces is the
/// separator. Titles may contain single spaces.
fn split_header(line: &str) -> Vec<String> {
    separator_pattern()
        .split(line.trim())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn separator_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"\s{2,}").expect("column separator pattern must compile"))
}

fn resolve_title(title: &str) -> Option<(PortalConsoleColumn, Option<&'static str>)> {
    let normalized = title.trim().to_lowercase();
    COLUMN_ALIASES
        .iter()
        .find(|(alias, _, _)| *alias == normalized)
        .map(|(_, column, locale)| (*column, *locale))
}

/// Resolve a candidate header line into a registered layout.
pub(super) fn resolve_header(line: &str) -> HeaderResolution {
    let titles = split_header(line);

    // A Console header has at least a timestamp title and one more column, and never
    // begins with record data.
    if titles.len() < 2 {
        return HeaderResolution::NotAHeader;
    }

    let mut columns = Vec::with_capacity(titles.len());
    let mut locale_hint: Option<String> = None;

    for title in &titles {
        match resolve_title(title) {
            Some((column, locale)) => {
                // The Timestamp-first rule decides whether this line can be a header at all,
                // so it has to be applied to the first resolved role rather than after the
                // loop. A later unknown title used to short-circuit to `Unregistered` first,
                // which reported unrelated text such as a process table as a Console export
                // with an unsupported layout instead of as not a Console export.
                if columns.is_empty() && column != PortalConsoleColumn::Timestamp {
                    return HeaderResolution::NotAHeader;
                }
                columns.push(column);
                if let Some(tag) = locale {
                    locale_hint.get_or_insert_with(|| tag.to_string());
                }
            }
            None => {
                // A line whose *first* title is unresolvable is almost certainly not a
                // header. A line that starts with a recognized timestamp title but then
                // carries an unknown one is a header from a layout we do not know.
                if columns.is_empty() {
                    return HeaderResolution::NotAHeader;
                }
                return HeaderResolution::Unregistered {
                    detail: format!("unrecognized Console header column title {title:?}"),
                };
            }
        }
    }

    match LAYOUT_REGISTRY
        .iter()
        .find(|(_, registered)| *registered == columns.as_slice())
    {
        Some((layout_id, _)) => HeaderResolution::Registered {
            layout_id,
            columns,
            locale_hint,
        },
        None => HeaderResolution::Unregistered {
            detail: format!("Console header column sequence {titles:?} is not a registered layout"),
        },
    }
}

/// Column roles of a registered layout id.
pub(super) fn registered_columns(layout_id: &str) -> Option<Vec<PortalConsoleColumn>> {
    LAYOUT_REGISTRY
        .iter()
        .find(|(id, _)| *id == layout_id)
        .map(|(_, columns)| columns.to_vec())
}

/// Detect the fractional-seconds separator from record data.
///
/// The header does not carry the separator, so it is read from the first record that has
/// one. Defaults to [`PortalConsoleDecimalSeparator::Dot`] when no record shows one.
pub(super) fn detect_decimal_separator(lines: &[&str]) -> PortalConsoleDecimalSeparator {
    for line in lines {
        if let Some(captures) = fractional_separator_pattern().captures(line) {
            return if &captures[1] == "," {
                PortalConsoleDecimalSeparator::Comma
            } else {
                PortalConsoleDecimalSeparator::Dot
            };
        }
    }
    PortalConsoleDecimalSeparator::Dot
}

fn fractional_separator_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}([.,])\d")
            .expect("fractional separator pattern must compile")
    })
}
