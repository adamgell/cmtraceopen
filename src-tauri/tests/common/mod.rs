#![allow(dead_code)]

use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TempBenchFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TempBenchFile {
    pub fn new(file_name: &str, content: String) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cmtrace-open-bench-{unique}"));
        fs::create_dir_all(&dir).expect("create temp benchmark dir");

        let path = dir.join(file_name);
        fs::write(&path, content).expect("write benchmark fixture");

        Self { dir, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn path_string(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for TempBenchFile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub struct IntuneBenchFixture {
    file: TempBenchFile,
    pub logical_record_count: usize,
    pub expected_event_count: usize,
    pub expected_timeline_count: usize,
    pub expected_download_count: usize,
    pub file_size_bytes: usize,
}

impl IntuneBenchFixture {
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    pub fn path_string(&self) -> String {
        self.file.path_string()
    }
}

pub fn build_ccm_bench_file(record_count: usize) -> TempBenchFile {
    let mut content = String::with_capacity(record_count * 180);

    for index in 0..record_count {
        let second = index % 60;
        let millis = index % 1000;
        let severity = match index % 3 {
            0 => 1,
            1 => 2,
            _ => 3,
        };
        let _ = writeln!(
            content,
            "<![LOG[Benchmark parse record {index}]LOG]!><time=\"11:16:{second:02}.{millis:03}0000\" date=\"3-12-2026\" component=\"CcmExec\" context=\"\" type=\"{severity}\" thread=\"50\" file=\"\">"
        );
    }

    TempBenchFile::new("BenchmarkParse.log", content)
}

pub fn build_intune_bench_file(pair_count: usize) -> IntuneBenchFixture {
    let mut content = String::with_capacity(pair_count * 520);

    for index in 0..pair_count {
        let app_id = format!("{index:08x}-1234-5678-9abc-{index:012x}");
        let app_name = format!("Benchmark App {index}");
        let start = bench_timestamp_parts(index * 2);
        let end = bench_timestamp_parts(index * 2 + 1);

        let _ = writeln!(
            content,
            "<![LOG[Starting content download RequestPayload: {{\\\"AppId\\\":\\\"{app_id}\\\",\\\"ApplicationName\\\":\\\"{app_name}\\\"}}]LOG]!><time=\"{}\" date=\"{}\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"9\" file=\"\">",
            start.0,
            start.1
        );
        let _ = writeln!(
            content,
            "<![LOG[Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5% RequestPayload: {{\\\"AppId\\\":\\\"{app_id}\\\",\\\"ApplicationName\\\":\\\"{app_name}\\\"}}]LOG]!><time=\"{}\" date=\"{}\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"9\" file=\"\">",
            end.0,
            end.1
        );
    }

    let logical_record_count = pair_count * 2;
    let file_size_bytes = content.len();
    let file = TempBenchFile::new("AppWorkload.log", content);

    IntuneBenchFixture {
        file,
        logical_record_count,
        expected_event_count: pair_count,
        expected_timeline_count: pair_count,
        expected_download_count: pair_count,
        file_size_bytes,
    }
}

fn bench_timestamp_parts(total_seconds: usize) -> (String, String) {
    let start_day = 15usize;
    let day_offset = total_seconds / 86_400;
    let seconds_in_day = total_seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;

    (
        format!("{hour:02}:{minute:02}:{second:02}.0000000"),
        format!("1-{}-2024", start_day + day_offset),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionSnapshot {
    pub parser: String,
    pub implementation: String,
    pub provenance: String,
    pub parse_quality: String,
    pub record_framing: String,
    pub specialization: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySnapshot {
    pub id: u64,
    pub line_number: u32,
    pub message: String,
    pub component: Option<String>,
    pub timestamp_display: Option<String>,
    pub severity: String,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFixture {
    pub selection: SelectionSnapshot,
    pub compatibility_format: String,
    pub total_lines: u32,
    pub parse_errors: u32,
    pub file_size: u64,
    pub byte_offset: u64,
    pub entries: Vec<EntrySnapshot>,
}

pub fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(relative)
}

pub fn detect_fixture(relative: &str) -> SelectionSnapshot {
    let path = fixture_path(relative);
    let content = fs::read_to_string(&path).expect("fixture should be readable as UTF-8");
    let selection = app_lib::parser::detect::detect_parser(&path.to_string_lossy(), &content);

    selection_snapshot(&selection)
}

pub fn parse_fixture(relative: &str) -> ParsedFixture {
    let path = fixture_path(relative);
    let path_str = path.to_string_lossy().to_string();
    let file_size = fs::metadata(&path)
        .expect("fixture metadata should be readable")
        .len();
    let (result, selection) =
        app_lib::parser::parse_file(&path_str).expect("fixture should parse successfully");

    ParsedFixture {
        selection: selection_snapshot(&selection),
        compatibility_format: format!("{:?}", result.format_detected),
        total_lines: result.total_lines,
        parse_errors: result.parse_errors,
        file_size,
        byte_offset: result.byte_offset,
        entries: result
            .entries
            .into_iter()
            .map(|entry| EntrySnapshot {
                id: entry.id,
                line_number: entry.line_number,
                message: entry.message,
                component: entry.component,
                timestamp_display: entry.timestamp_display,
                severity: format!("{:?}", entry.severity),
                format: format!("{:?}", entry.format),
            })
            .collect(),
    }
}

fn selection_snapshot(selection: &app_lib::parser::ResolvedParser) -> SelectionSnapshot {
    SelectionSnapshot {
        parser: format!("{:?}", selection.parser),
        implementation: format!("{:?}", selection.implementation),
        provenance: format!("{:?}", selection.provenance),
        parse_quality: format!("{:?}", selection.parse_quality),
        record_framing: format!("{:?}", selection.record_framing),
        specialization: selection.specialization.map(|value| format!("{:?}", value)),
    }
}
