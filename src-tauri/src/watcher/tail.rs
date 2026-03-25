use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::models::log_entry::{LogEntry, ParserSpecialization, RecordFraming};
use crate::parser::{self, ResolvedParser, FileEncoding};

const IME_RECORD_START: &str = "<![LOG[";
const IME_RECORD_ATTRS_START: &str = "]LOG]!><";

/// Manages incremental reading of a log file from a tracked byte offset.
pub struct TailReader {
    path: PathBuf,
    byte_offset: u64,
    parser_selection: ResolvedParser,
    next_id: u64,
    next_line: u32,
    /// Leftover partial record fragment from the previous read.
    pending_fragment: String,
    /// File encoding detected from BOM during initial parse.
    encoding: FileEncoding,
    /// Leftover partial byte from a UTF-16 read boundary split.
    pending_byte: Option<u8>,
}

impl TailReader {
    /// Create a new TailReader starting after the initial parse.
    pub fn new(
        path: PathBuf,
        byte_offset: u64,
        parser_selection: ResolvedParser,
        next_id: u64,
        next_line: u32,
    ) -> Self {
        // Detect encoding from the file's BOM
        let encoding = std::fs::read(&path)
            .map(|bytes| crate::parser::detect_encoding(&bytes))
            .unwrap_or(FileEncoding::Utf8);

        Self {
            path,
            byte_offset,
            parser_selection,
            next_id,
            next_line,
            pending_fragment: String::new(),
            encoding,
            pending_byte: None,
        }
    }

    /// Read new content from the file since last read, parse into entries.
    /// Returns new entries and updates internal byte_offset.
    pub fn read_new_entries(&mut self) -> Result<Vec<LogEntry>, String> {
        let mut file = std::fs::File::open(&self.path)
            .map_err(|e| format!("Failed to open file for tailing: {}", e))?;

        let metadata = file
            .metadata()
            .map_err(|e| format!("Failed to read metadata: {}", e))?;

        let file_size = metadata.len();

        // File was truncated (e.g. log rotation) — reset to beginning
        if file_size < self.byte_offset {
            self.byte_offset = 0;
            self.pending_fragment.clear();
            self.pending_byte = None;
        }

        // No new data
        if file_size == self.byte_offset {
            return Ok(vec![]);
        }

        // Seek to our byte offset
        file.seek(SeekFrom::Start(self.byte_offset))
            .map_err(|e| format!("Failed to seek: {}", e))?;

        let bytes_to_read = file_size - self.byte_offset;
        let mut buffer = vec![0u8; bytes_to_read as usize];
        file.read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read new bytes: {}", e))?;

        // For UTF-16, handle partial code unit from previous read
        let decode_buffer = if let Some(prev_byte) = self.pending_byte.take() {
            let mut combined = vec![prev_byte];
            combined.extend_from_slice(&buffer);
            combined
        } else {
            buffer
        };

        // For UTF-16, save trailing odd byte
        let (to_decode, leftover) = match self.encoding {
            FileEncoding::Utf16Le | FileEncoding::Utf16Be if decode_buffer.len() % 2 != 0 => {
                let split = decode_buffer.len() - 1;
                self.pending_byte = Some(decode_buffer[split]);
                (&decode_buffer[..split], true)
            }
            _ => (&decode_buffer[..], false),
        };
        let _ = leftover; // suppress unused warning

        let new_text = crate::parser::decode_bytes(to_decode, self.encoding)
            .map_err(|e| format!("Failed to decode tailed bytes: {}", e))?;

        // Prepend any partial record fragment from the last read.
        let full_text = if self.pending_fragment.is_empty() {
            new_text
        } else {
            let combined = format!("{}{}", self.pending_fragment, new_text);
            self.pending_fragment.clear();
            combined
        };

        let lines = match self.parser_selection.record_framing {
            RecordFraming::PhysicalLine => {
                collect_complete_lines(&full_text, &mut self.pending_fragment)
            }
            RecordFraming::LogicalRecord => {
                if matches!(
                    self.parser_selection.specialization,
                    Some(ParserSpecialization::Ime)
                ) {
                    collect_complete_ime_lines(&full_text, &mut self.pending_fragment)
                } else {
                    collect_complete_lines(&full_text, &mut self.pending_fragment)
                }
            }
        };

        if lines.is_empty() {
            self.byte_offset = file_size;
            return Ok(vec![]);
        }

        // Parse the new complete records through the same dispatch path as initial parsing.
        let path_str = self.path.to_string_lossy().to_string();
        let (mut entries, _) = parser::parse_lines_with_selection(&lines, &path_str, &self.parser_selection);

        // Update IDs and line numbers to be sequential from where we left off
        for entry in &mut entries {
            entry.id = self.next_id;
            entry.line_number = self.next_line;
            self.next_id += 1;
            self.next_line += 1;
        }

        // Update byte offset (subtract the pending fragment bytes we kept).
        self.byte_offset = file_size - self.pending_fragment.len() as u64;

        Ok(entries)
    }
}

fn collect_complete_lines<'a>(text: &'a str, pending_fragment: &mut String) -> Vec<&'a str> {
    let ends_with_newline = text.ends_with('\n') || text.ends_with("\r\n");
    let mut lines: Vec<&str> = text.lines().collect();

    if !ends_with_newline && !lines.is_empty() {
        pending_fragment.push_str(lines.pop().unwrap_or(""));
    }

    lines
}

fn collect_complete_ime_lines<'a>(text: &'a str, pending_fragment: &mut String) -> Vec<&'a str> {
    let cutoff = find_complete_ime_cutoff(text);

    if cutoff < text.len() {
        pending_fragment.push_str(&text[cutoff..]);
    }

    text[..cutoff].lines().collect()
}

fn find_complete_ime_cutoff(text: &str) -> usize {
    let mut cursor = 0usize;

    loop {
        let Some(relative_start) = text[cursor..].find(IME_RECORD_START) else {
            return cursor + complete_unmatched_tail_len(&text[cursor..]);
        };

        let record_start = cursor + relative_start;

        let Some(record_end) = find_complete_ime_record_end(text, record_start) else {
            return record_start;
        };

        cursor = record_end;
    }
}

fn find_complete_ime_record_end(text: &str, record_start: usize) -> Option<usize> {
    let message_start = record_start + IME_RECORD_START.len();
    let attrs_relative_start = text[message_start..].find(IME_RECORD_ATTRS_START)?;
    let attrs_start = message_start + attrs_relative_start + IME_RECORD_ATTRS_START.len();
    let attrs_relative_end = text[attrs_start..].find('>')?;

    Some(attrs_start + attrs_relative_end + 1)
}

fn complete_unmatched_tail_len(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }

    if text.ends_with('\n') {
        return text.len();
    }

    text.rfind('\n').map(|index| index + 1).unwrap_or(0)
}

/// Represents an active tail-watching session
pub struct TailSession {
    /// Flag to signal the watcher thread to stop
    stop_flag: Arc<AtomicBool>,
    /// Flag to pause emitting events (file is still tracked)
    paused: Arc<AtomicBool>,
}

impl TailSession {
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

/// Start watching a file for changes.
/// Spawns a background thread that monitors the file and calls `on_new_entries`
/// whenever new log entries appear.
pub fn start_tail_session<F>(
    path: PathBuf,
    byte_offset: u64,
    parser_selection: ResolvedParser,
    next_id: u64,
    next_line: u32,
    on_new_entries: F,
) -> Result<TailSession, String>
where
    F: Fn(Vec<LogEntry>) + Send + 'static,
{
    let stop_flag = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));

    let stop_flag_clone = stop_flag.clone();
    let paused_clone = paused.clone();
    let watch_path = path.clone();

    std::thread::spawn(move || {
        let mut tail_reader = TailReader::new(path, byte_offset, parser_selection, next_id, next_line);

        // Create a channel for notify events
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                log::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        // Watch the parent directory (some systems don't notify on file-level watch
        // when the file is recreated/rotated)
        let watch_dir = watch_path.parent().unwrap_or(Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            log::error!("Failed to start watching {}: {}", watch_dir.display(), e);
            return;
        }

        log::info!("Tail watcher started for {}", watch_path.display());

        // Also do a periodic poll as a fallback (some editors/log writers
        // may not trigger filesystem events reliably)
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            if stop_flag_clone.load(Ordering::Relaxed) {
                log::info!("Tail watcher stopped for {}", watch_path.display());
                break;
            }

            // Wait for a notify event or poll timeout
            match rx.recv_timeout(poll_interval) {
                Ok(Ok(event)) => {
                    // Only react to modify/create events for our file
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            if event.paths.iter().any(|p| p == &watch_path)
                                && !paused_clone.load(Ordering::Relaxed)
                            {
                                if let Ok(entries) = tail_reader.read_new_entries() {
                                    if !entries.is_empty() {
                                        on_new_entries(entries);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Watcher error: {}", e);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Periodic poll — check for changes even without FS event
                    if !paused_clone.load(Ordering::Relaxed) {
                        if let Ok(entries) = tail_reader.read_new_entries() {
                            if !entries.is_empty() {
                                on_new_entries(entries);
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    log::info!("Watcher channel disconnected");
                    break;
                }
            }
        }
    });

    Ok(TailSession { stop_flag, paused })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{LogFormat, ParserSpecialization};
    use crate::parser;
    use crate::parser::detect::ResolvedParser;
    use crate::parser::timestamped::DateOrder;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PANTHER_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/panther/clean/setupact.log"
    ));
    const CBS_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/cbs/clean/CBS.log"
    ));
    const DISM_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/dism/clean/dism.log"
    ));
    const REPORTING_EVENTS_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/reporting_events/clean/ReportingEvents.log"
    ));
    fn unique_test_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("cmtrace-open-{name}-{stamp}.log"))
    }

    fn hinted_test_path(root: &Path, relative: &str) -> PathBuf {
        root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    fn hinted_test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!("cmtrace-open-{name}-{stamp}"))
    }

    fn split_fixture(fixture: &str, initial_line_count: usize) -> (String, String) {
        let lines: Vec<&str> = fixture.lines().collect();
        let initial = format!("{}\n", lines[..initial_line_count].join("\n"));
        let appended = format!("{}\n", lines[initial_line_count..].join("\n"));
        (initial, appended)
    }

    fn assert_entries_match(actual: &LogEntry, expected: &LogEntry) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.line_number, expected.line_number);
        assert_eq!(actual.message, expected.message);
        assert_eq!(actual.component, expected.component);
        assert_eq!(actual.timestamp, expected.timestamp);
        assert_eq!(actual.timestamp_display, expected.timestamp_display);
        assert_eq!(actual.severity, expected.severity);
        assert_eq!(actual.format, expected.format);
        assert_eq!(actual.file_path, expected.file_path);
    }

    #[test]
    fn test_tail_reader_reuses_backend_parser_selection() {
        let path = unique_test_path("tail-reader-selection");
        let initial = "15/01/2024 08:00:00 Initial entry\n";
        fs::write(&path, initial).expect("should write initial file");

        let byte_offset = fs::metadata(&path)
            .expect("metadata should exist")
            .len();

        let selection = ResolvedParser::generic_timestamped(DateOrder::DayFirst);
        let mut reader = TailReader::new(path.clone(), byte_offset, selection, 1, 2);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "16/01/2024 09:30:00 Follow-up entry").expect("should append log line");
        drop(file);

        let entries = reader.read_new_entries().expect("tail read should succeed");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].format, LogFormat::Timestamped);
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[0].line_number, 2);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-16 09:30:00.000")
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_matches_open_parse_for_regression_corpus_cases() {
        struct TailParityCase<'a> {
            name: &'a str,
            hinted_relative_path: &'a str,
            fixture: &'a str,
            initial_line_count: usize,
        }

        let cases = [
            TailParityCase {
                name: "panther-parity",
                hinted_relative_path: "Windows/Panther/setupact.log",
                fixture: PANTHER_CLEAN_FIXTURE,
                initial_line_count: 3,
            },
            TailParityCase {
                name: "cbs-parity",
                hinted_relative_path: "Windows/Logs/CBS/CBS.log",
                fixture: CBS_CLEAN_FIXTURE,
                initial_line_count: 3,
            },
            TailParityCase {
                name: "dism-parity",
                hinted_relative_path: "Windows/Logs/DISM/dism.log",
                fixture: DISM_CLEAN_FIXTURE,
                initial_line_count: 2,
            },
            TailParityCase {
                name: "reporting-events-parity",
                hinted_relative_path: "Windows/SoftwareDistribution/ReportingEvents.log",
                fixture: REPORTING_EVENTS_CLEAN_FIXTURE,
                initial_line_count: 1,
            },
        ];

        for case in cases {
            let root = hinted_test_root(case.name);
            let path = hinted_test_path(&root, case.hinted_relative_path);
            let parent = path.parent().expect("fixture path should have a parent");
            fs::create_dir_all(parent).expect("should create temporary parser hint directories");

            let (initial, appended) = split_fixture(case.fixture, case.initial_line_count);
            fs::write(&path, &initial).expect("should write initial fixture chunk");

            let path_str = path.to_string_lossy().to_string();
            let (initial_result, selection) =
                parser::parse_file(&path_str).expect("initial fixture should parse");

            let mut reader = TailReader::new(
                path.clone(),
                initial_result.byte_offset,
                selection,
                initial_result.entries.len() as u64,
                initial_result.total_lines + 1,
            );

            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("should reopen temp file");
            write!(file, "{}", appended).expect("should append trailing fixture chunk");
            drop(file);

            let tail_entries = reader.read_new_entries().expect("tail read should succeed");
            let (full_result, _) = parser::parse_file(&path_str).expect("full fixture should parse");
            let expected_entries = &full_result.entries[initial_result.entries.len()..];

            assert_eq!(tail_entries.len(), expected_entries.len(), "case={}", case.name);

            for (actual, expected) in tail_entries.iter().zip(expected_entries.iter()) {
                assert_entries_match(actual, expected);
            }

            fs::remove_dir_all(root).expect("should clean up temp parity fixture");
        }
    }

    #[test]
    fn test_tail_reader_buffers_incomplete_ime_record_until_complete() {
        let root = hinted_test_root("ime-tail-boundary");
        let path = hinted_test_path(
            &root,
            "ProgramData/Microsoft/IntuneManagementExtension/Logs/HealthScripts.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create temporary parser hint directories");

        let initial = "<![LOG[Powershell execution is done, exitCode = 1]LOG]!><time=\"11:16:37.3093207\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"1\" thread=\"50\" file=\"\">\n";
        fs::write(&path, initial).expect("should write initial fixture chunk");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");

        assert_eq!(selection.specialization, Some(ParserSpecialization::Ime));

        let mut reader = TailReader::new(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
        );

        let partial_append = concat!(
            "<![LOG[[HS] err output = Downloaded profile payload is not valid JSON.\n",
            "At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9\n"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{}", partial_append).expect("should append partial IME record");
        drop(file);

        let partial_entries = reader
            .read_new_entries()
            .expect("partial IME tail read should succeed");

        assert!(partial_entries.is_empty());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "]LOG]!><time=\"11:16:42.3322734\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"3\" thread=\"50\" file=\"\">"
        )
        .expect("should append IME record terminator");
        drop(file);

        let tail_entries = reader
            .read_new_entries()
            .expect("complete IME tail read should succeed");
        let (full_result, _) = parser::parse_file(&path_str).expect("full fixture should parse");

        assert_eq!(tail_entries.len(), 1);
        assert_entries_match(&tail_entries[0], &full_result.entries[1]);

        let repeat_entries = reader
            .read_new_entries()
            .expect("subsequent IME tail read should succeed");
        assert!(repeat_entries.is_empty());

        fs::remove_dir_all(root).expect("should clean up temp IME fixture");
    }
}
