use std::path::Path;
use std::sync::RwLock;

use app_lib::event_log::export::ExportFormat;
use app_lib::event_log::models::{EvtxLevel, EvtxRecord};
use app_lib::event_log::parser::parse_evtx_files;
use app_lib::event_log::provider_db::ProviderStore;
use cmtraceopen_parser::eventmap::MapRegistry;
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Filter {
    channels: Vec<String>,
    levels: Vec<EvtxLevel>,
    event_ids: String,
    search: Option<String>,
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
    #[serde(default)]
    selected_channels: Vec<String>,
    #[serde(default)]
    filter_levels: Vec<EvtxLevel>,
    #[serde(default)]
    filter_event_ids: String,
    #[serde(default)]
    filter_search: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    records: Vec<EvtxRecord>,
    #[serde(default)]
    total_records: u64,
    #[serde(default)]
    parse_errors: u32,
    #[serde(default)]
    error_messages: Vec<String>,
    #[serde(default)]
    filter: ManifestFilter,
}

impl Cli {
    fn from_manifest_json(input: &str) -> Result<Self, String> {
        let manifest: Manifest =
            serde_json::from_str(input).map_err(|error| format!("invalid source manifest: {error}"))?;
        let filter = Filter {
            channels: manifest.filter.selected_channels,
            levels: manifest.filter.filter_levels,
            event_ids: manifest.filter.filter_event_ids,
            search: (!manifest.filter.filter_search.trim().is_empty())
                .then_some(manifest.filter.filter_search),
        };
        Ok(Self {
            sources: manifest.sources,
            manifest: None,
            records: manifest.records,
            format: ExportFormat::Json,
            output: None,
            filter,
            coverage: Coverage {
                total_records: manifest.total_records,
                parse_errors: manifest.parse_errors,
                error_messages: manifest.error_messages,
            },
        })
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
        manifest: None,
        records: Vec::new(),
        format: ExportFormat::Json,
        output: None,
        filter: Filter::default(),
        coverage: Coverage::default(),
    };
    while let Some(argument) = args.next() {
        let value = |argument: &str, args: &mut dyn Iterator<Item = String>| {
            args.next()
                .ok_or_else(|| format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--source" => cli.sources.push(value("--source", &mut args)?),
            "--manifest" => cli.manifest = Some(value("--manifest", &mut args)?),
            "--format" => cli.format = format_from_arg(&value("--format", &mut args)?)?,
            "--output" => cli.output = Some(value("--output", &mut args)?),
            "--channel" => cli.filter.channels.push(value("--channel", &mut args)?),
            "--level" => {
                let level = value("--level", &mut args)?;
                cli.filter.levels.push(match level.as_str() {
                    "Critical" => EvtxLevel::Critical,
                    "Error" => EvtxLevel::Error,
                    "Warning" => EvtxLevel::Warning,
                    "Information" => EvtxLevel::Information,
                    "Verbose" => EvtxLevel::Verbose,
                    other => return Err(format!("unknown level {other:?}")),
                });
            }
            "--event-id" => {
                if !cli.filter.event_ids.is_empty() {
                    cli.filter.event_ids.push(',');
                }
                cli.filter.event_ids.push_str(&value("--event-id", &mut args)?);
            }
            "--search" => cli.filter.search = Some(value("--search", &mut args)?),
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
    Ok(cli)
}

fn parse_event_ids(input: &str) -> Vec<u32> {
    input
        .split([',', ' ', '\t'])
        .filter_map(|part| {
            if let Some((low, high)) = part.split_once('-') {
                let low = low.parse::<u32>().ok()?;
                let high = high.parse::<u32>().ok()?;
                Some((low.min(high)..=low.max(high)).collect::<Vec<_>>())
            } else {
                Some(vec![part.parse::<u32>().ok()?])
            }
        })
        .flatten()
        .collect()
}

fn filtered_records(records: Vec<EvtxRecord>, filter: &Filter) -> Vec<EvtxRecord> {
    let event_ids = parse_event_ids(&filter.event_ids);
    records
        .into_iter()
        .filter(|record| {
            (filter.channels.is_empty() || filter.channels.iter().any(|channel| channel == &record.channel))
                && (filter.levels.is_empty() || filter.levels.contains(&record.level))
                && (event_ids.is_empty() || event_ids.contains(&record.event_id))
                && filter.search.as_deref().is_none_or(|search| {
                    let search = search.to_ascii_lowercase();
                    record.message.to_ascii_lowercase().contains(&search)
                        || record.provider.to_ascii_lowercase().contains(&search)
                })
        })
        .collect()
}

fn load_manifest(path: &str) -> Result<Cli, String> {
    let input = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read source manifest {path}: {error}"))?;
    Cli::from_manifest_json(&input)
}

fn run() -> Result<(), String> {
    let mut cli = parse_args(std::env::args())?;
    if let Some(path) = cli.manifest.take() {
        let manifest = load_manifest(&path)?;
        cli.sources = manifest.sources;
        cli.records = manifest.records;
        cli.filter = manifest.filter;
        cli.coverage = manifest.coverage;
    }

    if cli.records.is_empty() && !cli.sources.is_empty() {
        let maps = RwLock::new(MapRegistry::default());
        let providers = RwLock::new(ProviderStore::default());
        let result = parse_evtx_files(&cli.sources, &maps, &providers)?;
        cli.coverage = Coverage {
            total_records: result.total_records,
            parse_errors: result.parse_errors,
            error_messages: result.error_messages,
        };
        cli.records = result.records;
    } else if cli.coverage.total_records == 0 {
        cli.coverage.total_records = cli.records.len() as u64;
    }

    let records = filtered_records(cli.records, &cli.filter);
    let path = cli.output.as_deref().map(Path::new);
    let stats = app_lib::event_log::writer::write_records_to_destination(&records, cli.format, path)?;
    eprintln!(
        "coverage: sourceRecords={} exportedRecords={} parseErrors={} gaps={}",
        cli.coverage.total_records,
        stats.records,
        cli.coverage.parse_errors,
        cli.coverage.error_messages.len()
    );
    for error in cli.coverage.error_messages {
        eprintln!("coverage-gap: {error}");
    }
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
    use super::{filtered_records, parse_args, Cli, Filter};
    use app_lib::event_log::models::EvtxLevel;

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
        assert_eq!(cli.filter.channels, vec!["Application"]);
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
        assert_eq!(cli.filter.channels, vec!["Application"]);
        assert_eq!(cli.filter.search.as_deref(), Some("boot"));
    }

    #[test]
    fn applies_gui_filter_fields_before_writing() {
        let make = |id: u32, message: &str| app_lib::event_log::models::EvtxRecord {
            id: id as u64,
            event_record_id: id as u64,
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
            task: None,
            opcode: None,
            process_id: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        };
        let selected = filtered_records(
            vec![make(326, "boot token"), make(4624, "other")],
            &Filter {
                channels: vec!["Application".into()],
                levels: vec![EvtxLevel::Error],
                event_ids: "326".into(),
                search: Some("boot".into()),
            },
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].event_id, 326);
    }
}
