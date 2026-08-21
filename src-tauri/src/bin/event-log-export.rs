use serde::de::{self, SeqAccess, Visitor};
use serde::Deserialize;
use std::borrow::Borrow;
#[cfg(test)]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::RwLock;

use app_lib::event_log::export::ExportFormat;
use app_lib::event_log::models::{EvtxLevel, EvtxRecord};
use app_lib::event_log::parser::{
    build_source_manifest, parse_evtx_manifest, EventLogSource, EventLogSourceManifest,
    SourceCoverage, MAX_SOURCE_MANIFEST_ENTRIES,
};
use app_lib::event_log::provider_db::ProviderStore;
use cmtraceopen_parser::eventmap::MapRegistry;

use chrono::TimeZone;
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Filter {
    channels: Option<Vec<String>>,
    levels: Option<Vec<EvtxLevel>>,
    event_ids: String,
    search: Option<String>,
    quick_filter: Option<QuickFilter>,
    visible_columns: Option<Vec<String>>,
    time_window: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuickFilter {
    mode: String,
    query: String,
    scope: String,
    action: String,
    case_sensitive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Coverage {
    total_records: u64,
    parse_errors: u32,
    error_messages: Vec<String>,
}

#[derive(Debug, Clone)]
struct Cli {
    sources: Vec<String>,
    source_manifest: Option<EventLogSourceManifest>,
    manifest: Option<String>,
    records: Vec<EvtxRecord>,
    format: ExportFormat,
    output: Option<String>,
    filter: Filter,
    coverage: Coverage,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ManifestFilter {
    #[serde(alias = "channels")]
    selected_channels: Option<Vec<String>>,
    #[serde(alias = "levels")]
    filter_levels: Option<Vec<EvtxLevel>>,
    #[serde(default, alias = "eventIds")]
    filter_event_ids: String,
    #[serde(default, alias = "search")]
    filter_search: Option<String>,
    #[serde(default)]
    time_window: Option<String>,
    #[serde(default)]
    quick_filter: Option<ManifestQuickFilter>,
    #[serde(default)]
    visible_columns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestQuickFilter {
    mode: String,
    query: String,
    scope: String,
    action: String,
    #[serde(default)]
    case_sensitive: bool,
}

#[derive(Debug, Deserialize, Default)]
struct BoundedManifestRecords(
    #[serde(deserialize_with = "deserialize_bounded_records")] Vec<EvtxRecord>,
);

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    sources: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    entries: Vec<EventLogSource>,
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    coverage: Vec<SourceCoverage>,
    source_manifest: Option<BoundedSourceManifest>,
    #[serde(default)]
    records: Option<BoundedManifestRecords>,
    #[serde(default)]
    total_records: Option<u64>,
    #[serde(default)]
    parse_errors: u32,
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    error_messages: Vec<String>,
    #[serde(default)]
    filter: ManifestFilter,
    #[serde(default)]
    before_load: Option<ManifestFilter>,
    #[serde(default)]
    on_load: Option<ManifestFilter>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BoundedSourceManifest {
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    entries: Vec<EventLogSource>,
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    coverage: Vec<SourceCoverage>,
}
impl Cli {
    fn from_manifest_json(input: &str) -> Result<Self, String> {
        if input.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(format!(
                "source manifest exceeds the {MAX_MANIFEST_BYTES}-byte input limit"
            ));
        }
        let manifest: Manifest = serde_json::from_str(input)
            .map_err(|error| format!("invalid source manifest: {error}"))?;
        let Manifest {
            sources,
            entries,
            coverage,
            source_manifest,
            records,
            total_records,
            parse_errors,
            error_messages,
            filter,
            before_load,
            on_load,
        } = manifest;
        if source_manifest.is_some() && (!entries.is_empty() || !coverage.is_empty()) {
            return Err(
                "source manifest cannot combine top-level and nested entries or coverage"
                    .to_owned(),
            );
        }
        let (entries, coverage) = source_manifest
            .as_ref()
            .map(|manifest| (manifest.entries.clone(), manifest.coverage.clone()))
            .unwrap_or((entries, coverage));
        if entries
            .iter()
            .any(|entry| entry.source_id.trim().is_empty() || entry.path.trim().is_empty())
        {
            return Err("source manifest entries must include sourceId and path".to_owned());
        }
        if coverage.iter().any(|item| {
            source_coverage_path(item).trim().is_empty()
                || match item {
                    SourceCoverage::Unsupported { reason, .. }
                    | SourceCoverage::AccessDenied { reason, .. }
                    | SourceCoverage::Missing { reason, .. }
                    | SourceCoverage::Empty { reason, .. }
                    | SourceCoverage::InvalidPattern { reason, .. }
                    | SourceCoverage::LimitReached { reason, .. } => reason.trim().is_empty(),
                }
        }) {
            return Err("source manifest coverage entries must include path and reason".to_owned());
        }
        let has_source_manifest =
            source_manifest.is_some() || !entries.is_empty() || !coverage.is_empty();
        if sources.iter().any(|source| source.trim().is_empty()) {
            return Err("source manifest sources must not be empty".to_owned());
        }
        if !entries.is_empty() && records.is_some() {
            return Err("source manifest entries cannot be combined with records".to_owned());
        }
        if has_source_manifest && !sources.is_empty() {
            return Err("source manifest cannot contain both entries and sources".to_owned());
        }
        if !sources.is_empty() && records.is_some() {
            return Err("source manifest cannot contain both sources and records".to_owned());
        }
        let source_manifest = has_source_manifest.then_some(EventLogSourceManifest {
            entries: entries.clone(),
            coverage: coverage.clone(),
        });
        let records = records.map(|records| records.0).unwrap_or_default();
        if records.len() > MAX_RETAINED_RECORDS {
            return Err(format!(
                "source manifest retains more than {MAX_RETAINED_RECORDS} records"
            ));
        }
        let total_records = total_records.unwrap_or(records.len() as u64);
        if total_records < records.len() as u64 {
            return Err(format!(
                "source manifest totalRecords {total_records} is below retained record count {}",
                records.len()
            ));
        }
        if total_records > MAX_TOTAL_RECORDS {
            return Err(format!(
                "source manifest totalRecords exceeds the {MAX_TOTAL_RECORDS} record limit"
            ));
        }
        let before = before_load.unwrap_or_default();
        let on = on_load.unwrap_or_default();
        let search = on
            .filter_search
            .or(filter.filter_search)
            .unwrap_or_default();
        let filter = Filter {
            channels: before.selected_channels.or(filter.selected_channels),
            levels: before.filter_levels.or(filter.filter_levels),
            event_ids: if before.filter_event_ids.trim().is_empty() {
                filter.filter_event_ids
            } else {
                before.filter_event_ids
            },
            search: (!search.trim().is_empty()).then_some(search),
            quick_filter: on
                .quick_filter
                .or(filter.quick_filter)
                .map(quick_filter_from_manifest),
            visible_columns: on.visible_columns.or(filter.visible_columns),
            time_window: before.time_window.or(filter.time_window),
        };
        if let Some(time_window) = filter.time_window.as_deref() {
            parse_time_window(time_window)?;
        }
        if let Some(quick_filter) = filter.quick_filter.as_ref() {
            validate_quick_filter(quick_filter)?;
        }
        let mut error_messages = error_messages;
        append_unique_messages(
            &mut error_messages,
            coverage.iter().map(source_coverage_message),
        );
        Ok(Self {
            sources: source_manifest
                .as_ref()
                .map(|value| {
                    value
                        .entries
                        .iter()
                        .map(|entry| entry.path.clone())
                        .collect()
                })
                .unwrap_or(sources),
            source_manifest,
            manifest: None,
            records,
            format: ExportFormat::Json,
            output: None,
            filter,
            coverage: Coverage {
                total_records,
                parse_errors,
                error_messages,
            },
        })
    }
}

const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RETAINED_RECORDS: usize = 1_000_000;
const MAX_TOTAL_RECORDS: u64 = MAX_RETAINED_RECORDS as u64;
const MAX_MANIFEST_VECTOR_ITEMS: usize = MAX_SOURCE_MANIFEST_ENTRIES;

struct BoundedVecVisitor<T> {
    marker: PhantomData<T>,
    limit: usize,
    label: &'static str,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < self.limit {
            match sequence.next_element()? {
                Some(value) => values.push(value),
                None => return Ok(values),
            }
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(format!(
                "{} are limited to {} items",
                self.label, self.limit
            )));
        }
        Ok(values)
    }
}

fn deserialize_bounded_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor {
        marker: PhantomData,
        limit: MAX_MANIFEST_VECTOR_ITEMS,
        label: "source manifest vectors",
    })
}

fn deserialize_bounded_records<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor {
        marker: PhantomData,
        limit: MAX_RETAINED_RECORDS,
        label: "retained records",
    })
}

fn quick_filter_from_manifest(value: ManifestQuickFilter) -> QuickFilter {
    QuickFilter {
        mode: value.mode,
        query: value.query,
        scope: value.scope,
        action: value.action,
        case_sensitive: value.case_sensitive,
    }
}

fn validate_quick_filter(quick_filter: &QuickFilter) -> Result<(), String> {
    if !matches!(
        quick_filter.mode.as_str(),
        "eventIds"
            | "oneString"
            | "multipleStrings"
            | "allStrings"
            | "oneWord"
            | "multipleWords"
            | "allWords"
    ) {
        return Err(format!("unknown quick-filter mode {:?}", quick_filter.mode));
    }
    if !matches!(quick_filter.scope.as_str(), "visibleColumns" | "allColumns") {
        return Err(format!(
            "unknown quick-filter scope {:?}",
            quick_filter.scope
        ));
    }
    if !matches!(quick_filter.action.as_str(), "show" | "hide") {
        return Err(format!(
            "unknown quick-filter action {:?}",
            quick_filter.action
        ));
    }
    Ok(())
}

fn displayed_timestamp(record: &EvtxRecord) -> String {
    if record.timestamp_epoch == 0 {
        return String::new();
    }
    let Some(timestamp) = chrono::Utc
        .timestamp_millis_opt(record.timestamp_epoch)
        .single()
    else {
        return String::new();
    };
    let mut displayed = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
    let fraction = record
        .timestamp
        .split_once('.')
        .map(|(_, fraction)| fraction.split(['Z', '+', '-']).next().unwrap_or(fraction))
        .filter(|fraction| {
            !fraction.is_empty() && fraction.chars().all(|value| value.is_ascii_digit())
        });
    if let Some(fraction) = fraction {
        displayed.push('.');
        displayed.push_str(fraction);
    } else {
        displayed.push_str(&timestamp.format(".%3f").to_string());
    }
    displayed
}

fn source_coverage_path(coverage: &SourceCoverage) -> &str {
    match coverage {
        SourceCoverage::Unsupported { path, .. }
        | SourceCoverage::AccessDenied { path, .. }
        | SourceCoverage::Missing { path, .. }
        | SourceCoverage::Empty { path, .. }
        | SourceCoverage::InvalidPattern { path, .. }
        | SourceCoverage::LimitReached { path, .. } => path,
    }
}

fn source_coverage_message(coverage: &SourceCoverage) -> String {
    format!(
        "{}: {}",
        source_coverage_path(coverage),
        match coverage {
            SourceCoverage::Unsupported { reason, .. }
            | SourceCoverage::AccessDenied { reason, .. }
            | SourceCoverage::Missing { reason, .. }
            | SourceCoverage::Empty { reason, .. }
            | SourceCoverage::InvalidPattern { reason, .. }
            | SourceCoverage::LimitReached { reason, .. } => reason,
        }
    )
}

fn append_unique_messages<I>(target: &mut Vec<String>, messages: I)
where
    I: IntoIterator<Item = String>,
{
    for message in messages {
        if !target.iter().any(|existing| existing == &message) {
            target.push(message);
        }
    }
}

fn format_from_arg(value: &str) -> Result<ExportFormat, String> {
    match value {
        "csv" => Ok(ExportFormat::Csv),
        "tsv" => Ok(ExportFormat::Tsv),
        "json" => Ok(ExportFormat::Json),
        "xml" => Ok(ExportFormat::Xml),
        "html" => Ok(ExportFormat::Html),
        "rawXml" => Ok(ExportFormat::RawXml),
        other => Err(format!(
            "unknown format {other:?}; expected csv, tsv, json, xml, html, or rawXml"
        )),
    }
}

fn parse_args<I, S>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let mut cli = Cli {
        sources: Vec::new(),
        source_manifest: None,
        manifest: None,
        records: Vec::new(),
        format: ExportFormat::Json,
        output: None,
        filter: Filter::default(),
        coverage: Coverage::default(),
    };
    let mut manifest_supplied = false;
    let mut filter_supplied = false;
    while let Some(argument) = args.next() {
        let value = |argument: &str, args: &mut dyn Iterator<Item = String>| {
            args.next()
                .ok_or_else(|| format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--source" => cli.sources.push(value("--source", &mut args)?),
            "--manifest" => {
                manifest_supplied = true;
                cli.manifest = Some(value("--manifest", &mut args)?);
            }
            "--format" => cli.format = format_from_arg(&value("--format", &mut args)?)?,
            "--output" => cli.output = Some(value("--output", &mut args)?),
            "--channel" => {
                filter_supplied = true;
                cli.filter
                    .channels
                    .get_or_insert_with(Vec::new)
                    .push(value("--channel", &mut args)?);
            }
            "--level" => {
                filter_supplied = true;
                let level = value("--level", &mut args)?;
                cli.filter
                    .levels
                    .get_or_insert_with(Vec::new)
                    .push(match level.as_str() {
                        "Critical" => EvtxLevel::Critical,
                        "Error" => EvtxLevel::Error,
                        "Warning" => EvtxLevel::Warning,
                        "Information" => EvtxLevel::Information,
                        "Verbose" => EvtxLevel::Verbose,
                        other => return Err(format!("unknown level {other:?}")),
                    });
            }
            "--event-id" => {
                filter_supplied = true;
                if !cli.filter.event_ids.is_empty() {
                    cli.filter.event_ids.push(',');
                }
                cli.filter
                    .event_ids
                    .push_str(&value("--event-id", &mut args)?);
            }
            "--search" => {
                filter_supplied = true;
                cli.filter.search = Some(value("--search", &mut args)?);
            }
            "--help" | "-h" => {
                return Err(
                    "usage: event-log-export --source <file.evtx>... [--manifest <manifest.json>] \
                     [--format csv|tsv|json|xml|html|rawXml] [--output <path|-] \
                     [--channel <name>]... [--level <level>]... [--event-id <id>]... [--search <text>]"
                        .to_owned(),
                )
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if cli.sources.is_empty() && cli.manifest.is_none() {
        return Err("at least one --source or --manifest is required".to_owned());
    }
    if manifest_supplied && (!cli.sources.is_empty() || filter_supplied) {
        return Err("--manifest cannot be combined with --source or filter arguments".to_owned());
    }
    Ok(cli)
}

const MAX_EVENT_ID: u32 = u32::MAX;
const MAX_EVENT_ID_FILTER_SELECTORS: usize = 65_536;
#[cfg(test)]
const MAX_EVENT_ID_FILTER_VALUES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventIdSelector {
    Single(u32),
    Range(u32, u32),
}

fn parse_event_id_selectors(input: &str) -> Result<Vec<EventIdSelector>, String> {
    let mut selectors = Vec::new();
    for part in input
        .split([',', ' ', '\t', '\r', '\n'])
        .filter(|part| !part.is_empty())
    {
        if selectors.len() >= MAX_EVENT_ID_FILTER_SELECTORS {
            return Err(format!(
                "event ID filter contains more than {MAX_EVENT_ID_FILTER_SELECTORS} selectors"
            ));
        }
        let selector = if let Some((low, high)) = part.split_once('-') {
            if low.is_empty()
                || high.is_empty()
                || !low.bytes().all(|byte| byte.is_ascii_digit())
                || !high.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Ok(Vec::new());
            }
            let low = match low.parse::<u64>() {
                Ok(value) => value,
                Err(_) => return Ok(Vec::new()),
            };
            let high = match high.parse::<u64>() {
                Ok(value) => value,
                Err(_) => return Ok(Vec::new()),
            };
            if low > MAX_EVENT_ID as u64 || high > MAX_EVENT_ID as u64 {
                return Ok(Vec::new());
            }
            EventIdSelector::Range(low.min(high) as u32, low.max(high) as u32)
        } else {
            if !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok(Vec::new());
            }
            let value = match part.parse::<u64>() {
                Ok(value) => value,
                Err(_) => return Ok(Vec::new()),
            };
            if value > MAX_EVENT_ID as u64 {
                return Ok(Vec::new());
            }
            EventIdSelector::Single(value as u32)
        };
        selectors.push(selector);
    }

    selectors.sort_unstable_by_key(|selector| match selector {
        EventIdSelector::Single(value) => (*value, *value),
        EventIdSelector::Range(from, to) => (*from, *to),
    });
    let mut merged = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let (from, to) = match selector {
            EventIdSelector::Single(value) => (value, value),
            EventIdSelector::Range(from, to) => (from, to),
        };
        if let Some(last) = merged.last_mut() {
            let (last_from, last_to) = match *last {
                EventIdSelector::Single(value) => (value, value),
                EventIdSelector::Range(from, to) => (from, to),
            };
            if from <= last_to || (last_to != MAX_EVENT_ID && from == last_to + 1) {
                *last = EventIdSelector::Range(last_from, last_to.max(to));
                continue;
            }
        }
        merged.push(selector);
    }
    Ok(merged)
}

#[cfg(test)]
fn parse_event_ids(input: &str) -> Result<Vec<u32>, String> {
    let selectors = parse_event_id_selectors(input)?;
    let mut event_ids = BTreeSet::new();
    for selector in selectors {
        match selector {
            EventIdSelector::Single(value) => {
                event_ids.insert(value);
            }
            EventIdSelector::Range(from, to) => {
                let bounded_to = to.min((MAX_EVENT_ID_FILTER_VALUES - 1) as u32);
                if from <= bounded_to {
                    event_ids.extend(from..=bounded_to);
                }
            }
        }
    }
    Ok(event_ids.into_iter().collect())
}

fn event_id_matches(value: u32, selectors: &[EventIdSelector]) -> bool {
    selectors
        .binary_search_by(|selector| {
            let (from, to) = match selector {
                EventIdSelector::Single(expected) => (*expected, *expected),
                EventIdSelector::Range(from, to) => (*from, *to),
            };
            if value < from {
                std::cmp::Ordering::Greater
            } else if value > to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
fn record_values(
    record: &EvtxRecord,
    visible_columns: Option<&[String]>,
    include_event_data: bool,
) -> Vec<String> {
    let mut values = Vec::new();
    let include = |name: &str| {
        visible_columns.is_none_or(|columns| {
            columns.iter().any(|column| {
                column == name
                    || (column == "timestamp" && name == "time")
                    || (column == "description" && name == "message")
                    || (column == "eventRecordId" && name == "recordId")
            })
        })
    };
    let include_mapped = |property: &str| {
        visible_columns.is_none_or(|columns| {
            let id = format!("mapped:{property}");
            columns.iter().any(|column| column == &id)
        })
    };
    let fixed = [
        ("time", displayed_timestamp(record)),
        (
            "recordId",
            record
                .event_record_id_text
                .clone()
                .unwrap_or_else(|| record.event_record_id.to_string()),
        ),
        ("eventId", record.event_id.to_string()),
        ("level", format!("{:?}", record.level)),
        ("provider", record.provider.clone()),
        ("channel", record.channel.clone()),
        ("computer", record.computer.clone()),
        (
            "task",
            record
                .task
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "opcode",
            record
                .opcode
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "processId",
            record
                .process_id
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "threadId",
            record
                .thread_id
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        ("keywords", record.keywords.clone().unwrap_or_default()),
        ("message", record.message.clone()),
    ];
    values.extend(
        fixed
            .into_iter()
            .filter(|(name, _)| include(name))
            .map(|(_, value)| value),
    );
    values.extend(
        record
            .mapped
            .iter()
            .filter(|column| column.complete && include_mapped(&column.property))
            .map(|column| column.text.clone()),
    );
    if include_event_data {
        values.extend(record.event_data.iter().map(|field| field.value.clone()));
    }
    values
}

fn quick_filter_matches(
    record: &EvtxRecord,
    quick_filter: &QuickFilter,
    visible_columns: Option<&[String]>,
    event_id_selectors: Option<&[EventIdSelector]>,
) -> bool {
    let query = quick_filter.query.trim();
    // GUI quick-filter controls are always serialized, including their inactive empty default.
    if validate_quick_filter(quick_filter).is_err() {
        return false;
    }
    if query.is_empty() {
        return true;
    }
    if quick_filter.mode == "eventIds" {
        let selectors = event_id_selectors.unwrap_or(&[]);
        if selectors.is_empty() {
            return false;
        }
        let matched = event_id_matches(record.event_id, selectors);
        return if quick_filter.action == "hide" {
            !matched
        } else {
            matched
        };
    }
    let values = record_values(
        record,
        if quick_filter.scope == "visibleColumns" {
            visible_columns
        } else {
            None
        },
        quick_filter.scope == "allColumns",
    );
    let normalize = |value: &str| {
        if quick_filter.case_sensitive {
            value.to_owned()
        } else {
            value.to_lowercase()
        }
    };
    let values = values
        .iter()
        .map(|value| normalize(value))
        .collect::<Vec<_>>();
    let query = normalize(query);
    let contains = |term: &str| values.iter().any(|value| value.contains(term));
    let terms = match quick_filter.mode.as_str() {
        "multipleStrings" | "allStrings" => query
            .split([',', ';', '\n'])
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>(),
        "multipleWords" | "allWords" => query
            .split_whitespace()
            .filter(|term| !term.is_empty())
            .collect::<Vec<_>>(),
        _ => vec![query.as_str()],
    };
    let matched = match quick_filter.mode.as_str() {
        "multipleWords" | "multipleStrings" => terms.iter().any(|term| contains(term)),
        "allWords" | "allStrings" => !terms.is_empty() && terms.iter().all(|term| contains(term)),
        _ => contains(query.as_str()),
    };
    if quick_filter.action == "hide" {
        !matched
    } else {
        matched
    }
}

#[derive(Debug, Clone)]
struct PreparedFilter {
    filter: Filter,
    event_id_filter_active: bool,
    event_ids: Vec<EventIdSelector>,
    invalid_event_id_filter: bool,
    quick_event_ids: Option<Vec<EventIdSelector>>,
    search: Option<String>,
    time_window: Option<(i64, i64)>,
}

impl PreparedFilter {
    fn new(filter: &Filter) -> Result<Self, String> {
        let quick_event_ids = match filter.quick_filter.as_ref() {
            Some(quick_filter) => {
                validate_quick_filter(quick_filter)?;
                (quick_filter.mode == "eventIds")
                    .then(|| parse_event_id_selectors(quick_filter.query.trim()))
                    .transpose()?
            }
            None => None,
        };
        let event_id_filter_active = !filter.event_ids.trim().is_empty();
        let event_ids = parse_event_id_selectors(&filter.event_ids)?;
        let invalid_event_id_filter = event_id_filter_active && event_ids.is_empty();
        let search = filter
            .search
            .as_deref()
            .map(str::trim)
            .filter(|search| !search.is_empty())
            .map(str::to_lowercase);
        let time_window = match filter.time_window.as_deref() {
            Some(value) => parse_time_window(value)?,
            None => None,
        };
        Ok(Self {
            filter: filter.clone(),
            event_id_filter_active,
            event_ids,
            invalid_event_id_filter,
            quick_event_ids,
            search,
            time_window,
        })
    }

    fn matches(&self, record: &EvtxRecord) -> bool {
        !self.invalid_event_id_filter
            && self
                .filter
                .channels
                .as_ref()
                .is_none_or(|channels| channels.iter().any(|channel| channel == &record.channel))
            && self
                .filter
                .levels
                .as_ref()
                .is_none_or(|levels| levels.contains(&record.level))
            && (!self.event_id_filter_active || event_id_matches(record.event_id, &self.event_ids))
            && self.search.as_deref().is_none_or(|search| {
                [record.message.as_str(), record.provider.as_str()]
                    .iter()
                    .any(|value| value.to_lowercase().contains(search))
            })
            && self
                .time_window
                .is_none_or(|(start, _end)| record.timestamp_epoch >= start)
            && self.filter.quick_filter.as_ref().is_none_or(|quick| {
                quick_filter_matches(
                    record,
                    quick,
                    self.filter.visible_columns.as_deref(),
                    self.quick_event_ids.as_deref(),
                )
            })
    }
}

fn filter_with<'a, I, R>(records: I, filter: &'a PreparedFilter) -> impl Iterator<Item = R> + 'a
where
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord> + 'a,
    <I as IntoIterator>::IntoIter: 'a,
{
    records
        .into_iter()
        .filter(move |record| filter.matches(record.borrow()))
}

#[cfg(test)]
fn filtered_record_iter<I, R>(
    records: I,
    filter: &Filter,
) -> Result<impl Iterator<Item = R>, String>
where
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    let prepared = PreparedFilter::new(filter)?;
    Ok(records
        .into_iter()
        .filter(move |record| prepared.matches(record.borrow())))
}

#[cfg(test)]
fn filtered_records(records: Vec<EvtxRecord>, filter: &Filter) -> Result<Vec<EvtxRecord>, String> {
    Ok(filtered_record_iter(records, filter)?.collect())
}

fn parse_time_window(value: &str) -> Result<Option<(i64, i64)>, String> {
    let now = chrono::Utc::now().timestamp_millis();
    let milliseconds = match value {
        "1h" => 60 * 60 * 1000,
        "24h" => 24 * 60 * 60 * 1000,
        "7d" => 7 * 24 * 60 * 60 * 1000,
        "30d" => 30 * 24 * 60 * 60 * 1000,
        "all" => return Ok(None),
        other => {
            return Err(format!(
                "unsupported time window {other:?}; expected 1h, 24h, 7d, 30d, or all"
            ))
        }
    };
    Ok(Some((now.saturating_sub(milliseconds), now)))
}

fn load_manifest(path: &str) -> Result<Cli, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read source manifest {path}: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("cannot stat source manifest {path}: {error}"))?
        .len();
    if length > MAX_MANIFEST_BYTES {
        return Err(format!(
            "source manifest {path} exceeds the {MAX_MANIFEST_BYTES}-byte input limit"
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read source manifest {path}: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "source manifest {path} exceeds the {MAX_MANIFEST_BYTES}-byte input limit"
        ));
    }
    let input = String::from_utf8(bytes)
        .map_err(|error| format!("source manifest {path} is not valid UTF-8: {error}"))?;
    Cli::from_manifest_json(&input)
}

fn load_cli(mut cli: Cli) -> Result<Cli, String> {
    if let Some(path) = cli.manifest.take() {
        let manifest = load_manifest(&path)?;
        cli.sources = manifest.sources;
        cli.source_manifest = manifest.source_manifest;
        cli.records = manifest.records;
        cli.filter = manifest.filter;
        cli.coverage = manifest.coverage;
    }

    if cli.records.is_empty() && !cli.sources.is_empty() {
        let maps = RwLock::new(MapRegistry::default());
        let providers = RwLock::new(ProviderStore::default());
        let mut coverage = cli.coverage.clone();
        let result = if let Some(source_manifest) = cli.source_manifest.as_ref() {
            parse_evtx_manifest(source_manifest, &maps, &providers)?
        } else {
            let source_manifest = build_source_manifest(&cli.sources)?;
            let result = parse_evtx_manifest(&source_manifest, &maps, &providers)?;
            cli.source_manifest = Some(source_manifest);
            result
        };
        coverage.total_records = result.total_records;
        coverage.parse_errors = coverage.parse_errors.max(result.parse_errors);
        append_unique_messages(&mut coverage.error_messages, result.error_messages);
        cli.coverage = coverage;
        cli.records = result.records;
    } else if cli.coverage.total_records == 0 {
        cli.coverage.total_records = cli.records.len() as u64;
    }
    Ok(cli)
}
fn reject_source_destination(sources: &[String], output: Option<&str>) -> Result<(), String> {
    app_lib::event_log::writer::reject_source_destination(sources, output.map(Path::new))
}

fn coverage_report(coverage: &Coverage, exported_records: &str) -> String {
    let mut report = format!(
        "coverage: sourceRecords={} exportedRecords={} parseErrors={} gaps={}",
        coverage.total_records,
        exported_records,
        coverage.parse_errors,
        coverage.error_messages.len()
    );
    for error in &coverage.error_messages {
        report.push_str(&format!("\ncoverage-gap: {error}"));
    }
    report
}

fn run_with_args<I, S>(args: I, stdout: &mut dyn Write) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let parsed = parse_args(args)?;
    let manifest_path = parsed.manifest.clone();
    let cli = load_cli(parsed)?;
    let mut protected_sources = cli.sources.clone();
    protected_sources.extend(
        cli.records
            .iter()
            .map(|record| record.source_label.clone())
            .filter(|source| !source.is_empty()),
    );
    if let Some(source_manifest) = cli.source_manifest.as_ref() {
        protected_sources.extend(
            source_manifest
                .entries
                .iter()
                .map(|entry| entry.path.clone())
                .filter(|path| !path.is_empty()),
        );
        protected_sources.extend(
            source_manifest
                .coverage
                .iter()
                .map(source_coverage_path)
                .filter(|path| !path.is_empty())
                .map(str::to_owned),
        );
    }
    if let Some(manifest_path) = manifest_path {
        protected_sources.push(manifest_path);
    }
    reject_source_destination(&protected_sources, cli.output.as_deref())?;
    let prepared_filter = PreparedFilter::new(&cli.filter)?;
    app_lib::event_log::writer::validate_raw_xml_iter(
        filter_with(cli.records.iter(), &prepared_filter),
        cli.format,
    )
    .map_err(|error| {
        format!(
            "{}\nexport failed: {error}",
            coverage_report(&cli.coverage, "unknown")
        )
    })?;
    let mapped_columns = app_lib::event_log::export::mapped_columns_iter(filter_with(
        cli.records.iter(),
        &prepared_filter,
    ))
    .map_err(|error| {
        format!(
            "{}\nexport failed: {error}",
            coverage_report(&cli.coverage, "unknown")
        )
    })?;
    let records = filter_with(cli.records, &prepared_filter);
    let stats = match cli
        .output
        .as_deref()
        .filter(|output| *output != "-")
        .map(Path::new)
    {
        Some(path) => app_lib::event_log::writer::write_record_stream_to_destination(
            records,
            cli.format,
            Some(path),
            &mapped_columns,
        ),
        None => app_lib::event_log::writer::write_record_stream_to_writer(
            stdout,
            records,
            cli.format,
            &mapped_columns,
        ),
    }
    .map_err(|error| {
        format!(
            "{}\nexport failed: {error}",
            coverage_report(&cli.coverage, "unknown")
        )
    })?;
    Ok(coverage_report(&cli.coverage, &stats.records.to_string()))
}

fn utf8_arguments<I>(args: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = OsString>,
{
    args.into_iter()
        .map(|argument| {
            argument.into_string().map_err(|argument| {
                format!("command-line argument is not valid UTF-8: {argument:?}")
            })
        })
        .collect()
}

fn run() -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    let arguments = utf8_arguments(std::env::args_os())?;
    let report = run_with_args(arguments, &mut stdout)?;
    eprintln!("{report}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("event-log-export: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::utf8_arguments;
    use super::{
        displayed_timestamp, event_id_matches, filtered_records, parse_args,
        parse_event_id_selectors, parse_event_ids, reject_source_destination, run_with_args, Cli,
        EventIdSelector, Filter, QuickFilter, MAX_EVENT_ID_FILTER_SELECTORS,
    };
    use app_lib::event_log::export::{mapped_columns_iter, MAX_MAPPED_COLUMNS};
    use app_lib::event_log::maps::MappedColumn;
    use app_lib::event_log::models::{EvtxField, EvtxLevel, EvtxRecord};

    #[cfg(unix)]
    #[test]
    fn non_utf8_cli_arguments_are_rejected() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![b's', 0xff]);
        let error = utf8_arguments([invalid]).expect_err("non-UTF-8 argument must be rejected");
        assert!(error.contains("not valid UTF-8"));
    }

    fn make_record() -> EvtxRecord {
        EvtxRecord {
            id: 1,
            event_record_id: 1,
            event_record_id_text: Some("1".into()),
            timestamp: String::new(),
            timestamp_epoch: 0,
            provider: "Provider".into(),
            channel: "Application".into(),
            event_id: 1,
            level: EvtxLevel::Error,
            computer: "HOST".into(),
            message: "message".into(),
            event_data: Vec::new(),
            raw_xml: "<Event />".into(),
            source_label: "source".into(),
            origin_kind: app_lib::event_log::models::EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
    }

    #[test]
    fn displayed_timestamp_is_empty_without_source_or_epoch() {
        assert_eq!(displayed_timestamp(&make_record()), "");
    }
    #[test]
    fn displayed_timestamp_is_empty_for_unparsed_text_without_epoch() {
        let mut record = make_record();
        record.timestamp = "raw-timestamp-only".into();
        assert_eq!(displayed_timestamp(&record), "");
    }

    #[test]
    fn displayed_timestamp_formats_epoch_in_utc() {
        let mut record = make_record();
        record.timestamp_epoch = 1_786_276_800_000;
        assert_eq!(displayed_timestamp(&record), "2026-08-09 12:00:00.000");
    }

    #[test]
    fn displayed_timestamp_preserves_source_fractional_precision() {
        let mut record = make_record();
        record.timestamp = "2026-08-09T12:00:00.123456Z".into();
        record.timestamp_epoch = 1_786_276_800_123;
        assert_eq!(displayed_timestamp(&record), "2026-08-09 12:00:00.123456");
    }
    #[test]
    fn parses_source_format_output_and_gui_filter_shape() {
        let cli = parse_args([
            "event-log-export",
            "--source",
            "Application.evtx",
            "--format",
            "csv",
            "--output",
            "events.csv",
            "--channel",
            "Application",
            "--search",
            "token",
        ])
        .expect("valid CLI");
        assert_eq!(cli.sources, vec!["Application.evtx"]);
        assert_eq!(cli.format, app_lib::event_log::export::ExportFormat::Csv);
        assert_eq!(cli.output.as_deref(), Some("events.csv"));
        assert_eq!(cli.filter.channels, Some(vec!["Application".into()]));
        assert_eq!(cli.filter.search.as_deref(), Some("token"));
    }

    #[test]
    fn rejects_missing_sources_and_unknown_formats() {
        assert!(parse_args(["event-log-export", "--format", "csv"]).is_err());
        assert!(parse_args([
            "event-log-export",
            "--source",
            "events.evtx",
            "--format",
            "yaml",
        ])
        .is_err());
    }

    #[test]
    fn parses_a_manifest_with_the_frontend_wire_names() {
        let manifest = r#"{
            "records": [],
            "channels": [],
            "totalRecords": 4,
            "parseErrors": 1,
            "errorMessages": ["damaged.evtx: truncated"],
            "filter": {
                "selectedChannels": ["Application"],
                "filterLevels": ["Error"],
                "filterEventIds": "326",
                "filterSearch": "boot"
            }
        }"#;
        let cli = Cli::from_manifest_json(manifest).expect("manifest parses");
        assert_eq!(cli.coverage.total_records, 4);
        assert_eq!(cli.coverage.parse_errors, 1);
        assert_eq!(cli.filter.channels, Some(vec!["Application".into()]));
        assert_eq!(cli.filter.search.as_deref(), Some("boot"));
    }

    #[test]
    fn explicit_empty_on_load_search_clears_top_level_search() {
        let cli = Cli::from_manifest_json(
            r#"{
                "records": [],
                "filter": {"filterSearch": "boot"},
                "onLoad": {"filterSearch": ""}
            }"#,
        )
        .expect("manifest parses");
        assert_eq!(cli.filter.search, None);
    }

    #[test]
    fn applies_gui_filter_fields_before_writing() {
        let make = |id: u32, message: &str| app_lib::event_log::models::EvtxRecord {
            id: id as u64,
            event_record_id: id as u64,
            event_record_id_text: Some(id.to_string()),
            timestamp: String::new(),
            timestamp_epoch: id as i64,
            provider: "Provider".into(),
            channel: "Application".into(),
            event_id: id,
            level: EvtxLevel::Error,
            computer: "HOST".into(),
            message: message.into(),
            event_data: Vec::new(),
            raw_xml: "<Event />".into(),
            source_label: "source".into(),
            origin_kind: app_lib::event_log::models::EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        };
        let selected = filtered_records(
            vec![make(326, "boot token"), make(4624, "other")],
            &Filter {
                channels: Some(vec!["Application".into()]),
                levels: Some(vec![EvtxLevel::Error]),
                event_ids: "326".into(),
                search: Some("boot".into()),
                ..Filter::default()
            },
        )
        .expect("filter succeeds");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].event_id, 326);
    }

    #[test]
    fn rejects_manifest_conflicts_instead_of_overwriting_sources_or_filters() {
        assert!(parse_args([
            "event-log-export",
            "--manifest",
            "events.json",
            "--source",
            "events.evtx",
        ])
        .is_err());
        assert!(parse_args([
            "event-log-export",
            "--manifest",
            "events.json",
            "--search",
            "boot",
        ])
        .is_err());
    }

    #[test]
    fn rejects_manifest_internal_source_record_conflicts_without_precedence() {
        let record = serde_json::to_string(&make_record()).expect("record");
        assert!(Cli::from_manifest_json(&format!(
            r#"{{"sources":["events.evtx"],"records":[{record}]}}"#
        ))
        .is_err());
    }

    #[test]
    fn accepts_source_only_manifests_without_inventing_records() {
        let cli =
            Cli::from_manifest_json(r#"{"sources":["events.evtx"]}"#).expect("source manifest");
        assert_eq!(cli.sources, vec!["events.evtx"]);
        assert!(cli.records.is_empty());
    }

    #[test]
    fn preserves_empty_manifest_selections_as_match_none() {
        let cli = Cli::from_manifest_json(
            r#"{"records":[],"filter":{"selectedChannels":[],"filterLevels":[]}}"#,
        )
        .expect("manifest parses");
        assert_eq!(
            filtered_records(
                vec![app_lib::event_log::models::EvtxRecord {
                    channel: "Application".into(),
                    level: EvtxLevel::Error,
                    ..make_record()
                }],
                &cli.filter,
            )
            .expect("filter succeeds")
            .len(),
            0
        );
    }

    #[test]
    fn canonicalizes_event_id_selectors_and_matches_interval_boundaries() {
        let selectors = parse_event_id_selectors("9,4-6,6-8,12,10-11,5").expect("selectors");
        assert_eq!(selectors, vec![EventIdSelector::Range(4, 12)]);
        assert!(!event_id_matches(3, &selectors));
        assert!(event_id_matches(4, &selectors));
        assert!(event_id_matches(12, &selectors));
        assert!(!event_id_matches(13, &selectors));
    }

    #[test]
    fn clamps_event_id_ranges_like_the_frontend_filter() {
        assert!(parse_event_ids("1-999999999999999999999999")
            .expect("invalid oversized range")
            .is_empty());
        assert_eq!(parse_event_ids("1-65535").expect("range").len(), 65_535);
        assert_eq!(
            parse_event_ids("1-65536").expect("clamped range").len(),
            65_535
        );
        assert!(parse_event_ids("1.5-2").expect("decimal range").is_empty());
        assert!(parse_event_ids("1-1e400")
            .expect("exponent range")
            .is_empty());
        assert_eq!(
            parse_event_ids("100000-200000").expect("out-of-space range"),
            Vec::<u32>::new()
        );
        assert_eq!(
            parse_event_ids("0-65535").expect("full range").len(),
            65_536
        );
        assert_eq!(
            parse_event_ids("1-65535,0")
                .expect("full range with single")
                .len(),
            65_536
        );
        assert_eq!(
            parse_event_ids("1-40000,40000-65535")
                .expect("overlapping ranges")
                .len(),
            65_535
        );
        assert!(parse_event_ids("326,abc")
            .expect("invalid mixed tokens")
            .is_empty());
        assert!(parse_event_ids("1.0,326")
            .expect("invalid decimal token")
            .is_empty());
        assert!(parse_event_ids("-1,326")
            .expect("invalid negative token")
            .is_empty());
    }

    #[test]
    fn rejects_event_id_selector_lists_over_the_production_budget() {
        let selectors = std::iter::repeat_n("1", MAX_EVENT_ID_FILTER_SELECTORS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let error = filtered_records(
            vec![make_record()],
            &Filter {
                event_ids: selectors,
                ..Filter::default()
            },
        )
        .expect_err("over-budget selectors must be rejected");
        assert!(error.contains("event ID filter contains more than"));
    }

    #[test]
    fn invalid_nonempty_event_id_selector_matches_no_records() {
        for event_ids in ["not-an-id", "1.0", "-1", "999999999999999999999999"] {
            let selected = filtered_records(
                vec![make_record()],
                &Filter {
                    event_ids: event_ids.into(),
                    ..Filter::default()
                },
            )
            .expect("filter succeeds");
            assert!(
                selected.is_empty(),
                "invalid selector {event_ids:?} must match no records"
            );
        }
    }

    #[test]
    fn quick_filter_all_columns_includes_event_data_and_mapped_values() {
        let mut record = make_record();
        record.event_data = vec![EvtxField {
            name: "Target".into(),
            value: "event-data-token".into(),
        }];
        record.mapped = vec![MappedColumn {
            property: "RemoteHost".into(),
            text: "mapped-host".into(),
            complete: true,
        }];

        let all_columns = filtered_records(
            vec![record.clone()],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "event-data-token".into(),
                    scope: "allColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("all-column filter succeeds");
        assert_eq!(all_columns.len(), 1);

        let visible_default = filtered_records(
            vec![record.clone()],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "mapped-host".into(),
                    scope: "visibleColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("visible default-column filter succeeds");
        assert_eq!(visible_default.len(), 1);

        let visible_event_data = filtered_records(
            vec![record.clone()],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "event-data-token".into(),
                    scope: "visibleColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("visible event-data filter succeeds");
        assert!(visible_event_data.is_empty());

        let visible_mapped = filtered_records(
            vec![record.clone()],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "mapped-host".into(),
                    scope: "visibleColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                visible_columns: Some(vec!["mapped:RemoteHost".into()]),
                ..Filter::default()
            },
        )
        .expect("visible mapped-column filter succeeds");
        assert_eq!(visible_mapped.len(), 1);

        let mut incomplete = record;
        incomplete.mapped[0].complete = false;
        let incomplete_mapped = filtered_records(
            vec![incomplete],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "mapped-host".into(),
                    scope: "allColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("incomplete mapped-column filter succeeds");
        assert!(incomplete_mapped.is_empty());
    }

    #[test]
    fn quick_filter_keywords_matches_all_and_visible_columns() {
        let mut record = make_record();
        record.keywords = Some("keyword-token".into());

        let all_columns = filtered_records(
            vec![record.clone()],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "keyword-token".into(),
                    scope: "allColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("all-column keyword filter succeeds");
        assert_eq!(all_columns.len(), 1);

        let visible_columns = filtered_records(
            vec![record],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "keyword-token".into(),
                    scope: "visibleColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                visible_columns: Some(vec!["keywords".into()]),
                ..Filter::default()
            },
        )
        .expect("visible-column keyword filter succeeds");
        assert_eq!(visible_columns.len(), 1);
    }

    #[test]
    fn invalid_nonempty_event_id_quick_filter_matches_no_records_for_hide() {
        for query in ["not-an-id", "1.0", "-1"] {
            let selected = filtered_records(
                vec![make_record()],
                &Filter {
                    quick_filter: Some(QuickFilter {
                        mode: "eventIds".into(),
                        query: query.into(),
                        scope: "allColumns".into(),
                        action: "hide".into(),
                        case_sensitive: false,
                    }),
                    ..Filter::default()
                },
            )
            .expect("quick filter succeeds");
            assert!(
                selected.is_empty(),
                "invalid quick selector {query:?} must match no records"
            );
        }
    }

    #[test]
    fn event_id_parser_accepts_newline_separated_values() {
        assert_eq!(
            parse_event_ids("326\n4624\r\n1").expect("IDs"),
            vec![1, 326, 4624]
        );
    }

    #[test]
    fn source_destination_collision_is_rejected_before_writing() {
        let directory = tempfile::tempdir().expect("temp directory");
        let source = directory.path().join("events.evtx");
        std::fs::write(&source, "evidence").expect("source");
        let error = reject_source_destination(
            &[source.to_str().expect("source path").to_owned()],
            Some(source.to_str().expect("source path")),
        )
        .expect_err("source overwrite rejected");
        assert!(error.contains("overwrite"));
        assert_eq!(std::fs::read_to_string(source).expect("source"), "evidence");
    }

    #[test]
    fn wildcard_selected_parse_failure_source_is_protected_before_writing() {
        let directory = tempfile::tempdir().expect("temp directory");
        let source = directory.path().join("selected.evtx");
        let pattern = directory.path().join("*.evtx");
        std::fs::write(&source, b"not an EVTX file").expect("source");
        let mut stdout = Vec::new();

        let error = run_with_args(
            [
                "event-log-export",
                "--source",
                pattern.to_str().expect("wildcard source"),
                "--format",
                "json",
                "--output",
                source.to_str().expect("source path"),
            ],
            &mut stdout,
        )
        .expect_err("wildcard-selected source overwrite rejected");

        assert!(error.contains("overwrite"));
        assert_eq!(
            std::fs::read(&source).expect("source remains intact"),
            b"not an EVTX file"
        );
    }

    #[test]
    fn manifest_path_is_protected_from_output_overwrite() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        std::fs::write(&manifest_path, r#"{"records":[]}"#).expect("manifest");
        let mut stdout = Vec::new();
        let error = run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "json",
                "--output",
                manifest_path.to_str().expect("manifest path"),
            ],
            &mut stdout,
        )
        .expect_err("manifest overwrite rejected");
        assert!(error.contains("overwrite") || error.contains("collision"));
    }
    #[test]
    fn run_writes_direct_file_and_returns_coverage_report() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        let output_path = directory.path().join("events.json");
        let mut event = make_record();
        event.message = "PASSWORD=hunter2".into();
        let manifest = serde_json::json!({
            "records": [event],
            "totalRecords": 1,
            "parseErrors": 1,
            "errorMessages": ["damaged.evtx: truncated"]
        });
        std::fs::write(&manifest_path, manifest.to_string()).expect("manifest");
        let mut stdout = Vec::new();
        let report = run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "json",
                "--output",
                output_path.to_str().expect("output path"),
            ],
            &mut stdout,
        )
        .expect("CLI succeeds");
        let output = std::fs::read_to_string(output_path).expect("output file");
        assert!(!output.contains("hunter2"));
        assert!(report.contains("parseErrors=1"));
        assert!(report.contains("coverage-gap: damaged.evtx: truncated"));
        assert!(stdout.is_empty());
    }

    #[test]
    fn run_writes_stdout_through_the_shared_writer() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::json!({"records": [make_record()]}).to_string(),
        )
        .expect("manifest");
        let mut stdout = Vec::new();
        run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "json",
                "--output",
                "-",
            ],
            &mut stdout,
        )
        .expect("CLI succeeds");
        assert!(String::from_utf8(stdout).expect("JSON").starts_with('['));
    }

    #[test]
    fn run_writes_archive_log_with_empty_raw_xml_as_json() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        let mut event = make_record();
        event.origin_kind = app_lib::event_log::models::EvtxOriginKind::Log;
        event.raw_xml.clear();
        event.message = "PASSWORD=hunter2".into();
        std::fs::write(
            &manifest_path,
            serde_json::json!({"records": [event]}).to_string(),
        )
        .expect("manifest");

        let mut stdout = Vec::new();
        run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "json",
                "--output",
                "-",
            ],
            &mut stdout,
        )
        .expect("JSON CLI export succeeds");

        let value: serde_json::Value =
            serde_json::from_slice(&stdout).expect("CLI output is valid JSON");
        assert_eq!(value[0]["originKind"], "log");
        assert_eq!(value[0]["rawXml"], "");
        assert!(!String::from_utf8(stdout)
            .expect("UTF-8 JSON")
            .contains("hunter2"));
    }

    #[test]
    fn run_surfaces_writer_errors_for_xml_without_raw_content() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        let mut event = make_record();
        event.raw_xml.clear();
        std::fs::write(
            &manifest_path,
            serde_json::json!({"records": [event]}).to_string(),
        )
        .expect("manifest");
        let mut stdout = Vec::new();
        let error = run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "xml",
            ],
            &mut stdout,
        )
        .expect_err("missing raw XML fails");
        assert!(error.contains("raw XML"));
    }

    #[test]
    fn one_hour_window_uses_epoch_milliseconds_and_all_is_unbounded() {
        let now = chrono::Utc::now().timestamp_millis();
        let mut recent = make_record();
        recent.timestamp_epoch = now - 30 * 60 * 1000;
        let mut old = make_record();
        old.id = 2;
        old.timestamp_epoch = now - 2 * 60 * 60 * 1000;
        let mut future = make_record();
        future.id = 3;
        future.timestamp_epoch = now + 2 * 60 * 60 * 1000;

        let selected = filtered_records(
            vec![recent.clone(), old.clone(), future.clone()],
            &Filter {
                time_window: Some("1h".into()),
                ..Filter::default()
            },
        )
        .expect("one-hour filter succeeds");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].id, recent.id);
        assert_eq!(selected[1].id, future.id);

        let all = filtered_records(
            vec![recent, old, future],
            &Filter {
                time_window: Some("all".into()),
                ..Filter::default()
            },
        )
        .expect("all-time filter succeeds");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn unsupported_time_windows_are_rejected_instead_of_becoming_unbounded() {
        let error = filtered_records(
            vec![make_record()],
            &Filter {
                time_window: Some("forever".into()),
                ..Filter::default()
            },
        )
        .expect_err("unsupported time window must fail");
        assert!(error.contains("unsupported time window"));
    }

    #[test]
    fn search_matches_only_visible_message_and_provider_fields_case_insensitively() {
        let mut provider_match = make_record();
        provider_match.provider = "Microsoft-Windows-FOO".into();
        provider_match.message = "unrelated".into();
        let mut hidden_field_match = make_record();
        hidden_field_match.id = 2;
        hidden_field_match.computer = "Microsoft-Windows-FOO".into();
        hidden_field_match.message = "unrelated".into();
        let selected = filtered_records(
            vec![provider_match, hidden_field_match],
            &Filter {
                search: Some("mIcRoSoFt-wInDoWs-FoO".into()),
                ..Filter::default()
            },
        )
        .expect("search succeeds");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, 1);
    }

    #[test]
    fn mapped_columns_are_derived_from_filtered_records() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest_path = directory.path().join("manifest.json");
        let mut keep = make_record();
        keep.message = "keep".into();
        keep.mapped = vec![app_lib::event_log::maps::MappedColumn {
            property: "KeepColumn".into(),
            text: "kept".into(),
            complete: true,
        }];
        let mut drop = make_record();
        drop.id = 2;
        drop.message = "drop".into();
        drop.mapped = vec![app_lib::event_log::maps::MappedColumn {
            property: "DropColumn".into(),
            text: "dropped".into(),
            complete: true,
        }];
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "records": [keep, drop],
                "filter": {"filterSearch": "keep"}
            })
            .to_string(),
        )
        .expect("manifest");

        let mut stdout = Vec::new();
        run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "csv",
                "--output",
                "-",
            ],
            &mut stdout,
        )
        .expect("filtered CSV succeeds");
        let output = String::from_utf8(stdout).expect("CSV");
        assert!(output.contains("KeepColumn"));
        assert!(!output.contains("DropColumn"));
    }
    #[test]
    fn quick_filter_matches_the_displayed_timestamp_but_not_hidden_identity_fields() {
        let mut record = make_record();
        record.timestamp = "raw-timestamp-only".into();
        record.timestamp_epoch = 946_728_000_000;
        record.user_sid = Some("hidden-user-sid-only".into());
        record.source_label = "hidden-source-label-only".into();

        for query in [
            "hidden-user-sid-only",
            "hidden-source-label-only",
            "raw-timestamp-only",
        ] {
            let selected = filtered_records(
                vec![record.clone()],
                &Filter {
                    quick_filter: Some(QuickFilter {
                        mode: "oneString".into(),
                        query: query.into(),
                        scope: "allColumns".into(),
                        action: "show".into(),
                        case_sensitive: false,
                    }),
                    ..Filter::default()
                },
            )
            .expect("quick filter succeeds");
            assert!(
                selected.is_empty(),
                "quick filter must not search hidden or raw-only field {query:?}"
            );
        }

        let selected = filtered_records(
            vec![record],
            &Filter {
                quick_filter: Some(QuickFilter {
                    mode: "oneString".into(),
                    query: "2000".into(),
                    scope: "allColumns".into(),
                    action: "show".into(),
                    case_sensitive: false,
                }),
                ..Filter::default()
            },
        )
        .expect("quick filter succeeds");
        assert_eq!(
            selected.len(),
            1,
            "quick filter must use the epoch-backed displayed timestamp"
        );
    }

    #[test]
    fn rejects_unknown_quick_filter_mode_scope_and_action() {
        for (field, value) in [
            ("mode", "futureMode"),
            ("scope", "hiddenColumns"),
            ("action", "toggle"),
        ] {
            let mut quick_filter = serde_json::json!({
                "mode": "oneString",
                "query": "token",
                "scope": "allColumns",
                "action": "show",
            });
            quick_filter[field] = serde_json::Value::String(value.into());
            let manifest = serde_json::json!({
                "records": [],
                "filter": {"quickFilter": quick_filter},
            });
            let error = Cli::from_manifest_json(&manifest.to_string())
                .expect_err("unknown quick-filter enum must be rejected");
            assert!(
                error.contains(field),
                "error should identify the invalid quick-filter field: {error}"
            );
        }
    }

    #[test]
    fn rejects_conflicting_nested_and_top_level_source_manifests() {
        let manifest = serde_json::json!({
            "entries": [{
                "sourceId": "top-level",
                "path": "top-level.evtx",
                "kind": "file",
            }],
            "sourceManifest": {
                "entries": [{
                    "sourceId": "nested",
                    "path": "nested.evtx",
                    "kind": "file",
                }],
                "coverage": [],
            },
        });
        assert!(
            Cli::from_manifest_json(&manifest.to_string()).is_err(),
            "nested source manifest must not silently replace top-level entries"
        );
    }

    #[test]
    fn nested_source_manifest_vectors_default_when_omitted() {
        for manifest in [
            serde_json::json!({"sourceManifest": {"coverage": []}}),
            serde_json::json!({"sourceManifest": {"entries": []}}),
        ] {
            Cli::from_manifest_json(&manifest.to_string())
                .expect("omitted nested source-manifest vector defaults to empty");
        }
    }

    #[test]
    fn protects_expanded_zero_record_source_paths_from_output_collision() {
        let directory = tempfile::tempdir().expect("temp directory");
        let source_path = directory.path().join("empty.evtx");
        let manifest_path = directory.path().join("manifest.json");
        std::fs::write(&source_path, "source bytes").expect("source");
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "sourceManifest": {
                    "entries": [],
                    "coverage": [{
                        "kind": "empty",
                        "path": source_path.to_str().expect("source path"),
                        "reason": "source produced zero records",
                    }],
                },
            })
            .to_string(),
        )
        .expect("manifest");

        let mut stdout = Vec::new();
        let error = run_with_args(
            [
                "event-log-export",
                "--manifest",
                manifest_path.to_str().expect("manifest path"),
                "--format",
                "json",
                "--output",
                source_path.to_str().expect("source path"),
            ],
            &mut stdout,
        )
        .expect_err("expanded source path must be protected");
        assert!(error.contains("overwrite") || error.contains("collision"));
        assert_eq!(
            std::fs::read_to_string(source_path).expect("source"),
            "source bytes"
        );
    }

    #[test]
    fn rejects_oversized_declared_manifest_record_count() {
        let manifest = serde_json::json!({
            "records": [],
            "totalRecords": u64::MAX,
        });
        assert!(
            Cli::from_manifest_json(&manifest.to_string()).is_err(),
            "an unrepresentable export count must be rejected"
        );
    }

    #[test]
    fn rejects_oversized_manifest_json_before_deserialization() {
        let input = " ".repeat(super::MAX_MANIFEST_BYTES as usize + 1);
        let error = Cli::from_manifest_json(&input).expect_err("oversized manifest must fail");
        assert!(error.contains("byte"));
    }
    #[test]
    fn rejects_manifest_vectors_over_the_deserialization_budget() {
        let sources = vec!["source.evtx"; super::MAX_MANIFEST_VECTOR_ITEMS + 1];
        let source_error =
            Cli::from_manifest_json(&serde_json::json!({ "sources": sources }).to_string())
                .expect_err("oversized source vector must fail");
        assert!(source_error.contains("vectors"));

        let messages = vec!["parse error"; super::MAX_MANIFEST_VECTOR_ITEMS + 1];
        let message_error =
            Cli::from_manifest_json(&serde_json::json!({ "errorMessages": messages }).to_string())
                .expect_err("oversized error vector must fail");
        assert!(message_error.contains("vectors"));
    }
    #[test]
    fn rejects_record_vectors_over_the_deserialization_budget() {
        #[derive(Debug, serde::Deserialize)]
        struct BoundedRecords {
            #[allow(dead_code)]
            #[serde(deserialize_with = "super::deserialize_bounded_records")]
            records: Vec<serde_json::Value>,
        }

        let input = format!(
            r#"{{"records":[{}]}}"#,
            std::iter::repeat_n("null", super::MAX_RETAINED_RECORDS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        let error =
            serde_json::from_str::<BoundedRecords>(&input).expect_err("record vector must fail");
        assert!(error.to_string().contains("records"));
    }

    #[test]
    fn rejects_declared_total_records_below_retained_records() {
        let first = serde_json::to_value(make_record()).expect("first record");
        let mut second_record = make_record();
        second_record.id = 2;
        let second = serde_json::to_value(second_record).expect("second record");
        let manifest = serde_json::json!({
            "records": [first, second],
            "totalRecords": 1,
        });
        assert!(
            Cli::from_manifest_json(&manifest.to_string()).is_err(),
            "coverage cannot claim fewer source records than the retained payload"
        );
    }

    #[test]
    fn rejects_a_mapped_column_union_over_the_export_budget() {
        let records = (0..=MAX_MAPPED_COLUMNS)
            .map(|index| {
                let mut record = make_record();
                record.id = index as u64;
                record.mapped = vec![MappedColumn {
                    property: format!("mapped-{index}"),
                    text: "value".into(),
                    complete: true,
                }];
                record
            })
            .collect::<Vec<_>>();
        let error = mapped_columns_iter(records.iter()).expect_err("column budget must fail");
        assert!(
            error.contains("mapped-column") && error.contains("budget"),
            "{error}"
        );
    }
}
