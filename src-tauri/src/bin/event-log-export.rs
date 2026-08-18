use std::collections::BTreeSet;
use std::io::Write;
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
    channels: Option<Vec<String>>,
    levels: Option<Vec<EvtxLevel>>,
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
    selected_channels: Option<Vec<String>>,
    filter_levels: Option<Vec<EvtxLevel>>,
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

const MAX_EVENT_ID_FILTER_VALUES: usize = 65_535;

fn parse_event_ids(input: &str) -> Result<Vec<u32>, String> {
    let mut event_ids = BTreeSet::new();
    for part in input.split([',', ' ', '\t']).filter(|part| !part.is_empty()) {
        if let Some((low, high)) = part.split_once('-') {
            let low = low
                .parse::<u32>()
                .map_err(|_| format!("invalid event-ID range {part:?}"))?;
            let high = high
                .parse::<u32>()
                .map_err(|_| format!("invalid event-ID range {part:?}"))?;
            let from = low.min(high);
            let to = high.max(low).min(MAX_EVENT_ID_FILTER_VALUES as u32);
            if from <= to {
                for value in from..=to {
                    if event_ids.len() >= MAX_EVENT_ID_FILTER_VALUES {
                        break;
                    }
                    event_ids.insert(value);
                }
            }
        } else if event_ids.len() < MAX_EVENT_ID_FILTER_VALUES {
            event_ids.insert(
                part.parse::<u32>()
                    .map_err(|_| format!("invalid event ID {part:?}"))?,
            );
        }
    }
    Ok(event_ids.into_iter().collect())
}

fn filtered_records(records: Vec<EvtxRecord>, filter: &Filter) -> Result<Vec<EvtxRecord>, String> {
    let event_ids = parse_event_ids(&filter.event_ids)?;
    let search = filter
        .search
        .as_deref()
        .map(str::trim)
        .filter(|search| !search.is_empty())
        .map(str::to_lowercase);
    Ok(records
        .into_iter()
        .filter(|record| {
            filter.channels.as_ref().is_none_or(|channels| {
                channels.iter().any(|channel| channel == &record.channel)
            }) && filter
                .levels
                .as_ref()
                .is_none_or(|levels| levels.contains(&record.level))
                && (event_ids.is_empty() || event_ids.contains(&record.event_id))
                && search.as_deref().is_none_or(|search| {
                    record.message.to_lowercase().contains(search)
                        || record.provider.to_lowercase().contains(search)
                })
        })
        .collect())
}

fn load_manifest(path: &str) -> Result<Cli, String> {
    let input = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read source manifest {path}: {error}"))?;
    Cli::from_manifest_json(&input)
}

fn load_cli(mut cli: Cli) -> Result<Cli, String> {
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
    Ok(cli)
}

fn run_with_args<I, S>(args: I, stdout: &mut dyn Write) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let cli = load_cli(parse_args(args)?)?;
    let records = filtered_records(cli.records, &cli.filter)?;
    let stats = match cli.output.as_deref().map(Path::new) {
        Some(path) => app_lib::event_log::writer::write_records_to_destination(
            &records,
            cli.format,
            Some(path),
        )?,
        None => app_lib::event_log::writer::write_records(stdout, cli.format, &records)
            .map_err(|error| error.to_string())?,
    };
    let mut report = format!(
        "coverage: sourceRecords={} exportedRecords={} parseErrors={} gaps={}",
        cli.coverage.total_records,
        stats.records,
        cli.coverage.parse_errors,
        cli.coverage.error_messages.len()
    );
    for error in cli.coverage.error_messages {
        report.push_str(&format!("\ncoverage-gap: {error}"));
    }
    Ok(report)
}

fn run() -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    let report = run_with_args(std::env::args(), &mut stdout)?;
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
    use super::{filtered_records, parse_args, parse_event_ids, run_with_args, Cli, Filter};
    use app_lib::event_log::models::{EvtxLevel, EvtxRecord};

    fn make_record() -> EvtxRecord {
        EvtxRecord {
            id: 1,
            event_record_id: 1,
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
            task: None,
            opcode: None,
            process_id: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
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
                channels: Some(vec!["Application".into()]),
                levels: Some(vec![EvtxLevel::Error]),
                event_ids: "326".into(),
                search: Some("boot".into()),
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
    fn clamps_event_id_ranges_like_the_frontend_filter() {
        assert_eq!(parse_event_ids("1-65535").expect("range").len(), 65_535);
        assert_eq!(parse_event_ids("1-65536").expect("clamped range").len(), 65_535);
        assert_eq!(parse_event_ids("100000-200000").expect("out-of-space range"), Vec::<u32>::new());
        assert_eq!(
            parse_event_ids("1-40000,40000-65535")
                .expect("overlapping ranges")
                .len(),
            65_535
        );
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
            ],
            &mut stdout,
        )
        .expect("CLI succeeds");
        assert!(String::from_utf8(stdout).expect("JSON").starts_with('['));
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
}
