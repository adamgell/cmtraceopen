//! EVTX subset export (spec 8.17, Phase 18b).
//!
//! `evtx_export_subset` copies a chosen set of events, by `EventRecordID`, out of live channels and
//! `.evtx` files into new `.evtx` files with `EvtExportLog`, then calls `EvtArchiveExportedLog` so
//! the localized messages travel with each file. The files are raw copies: the shared redaction
//! module cannot apply, which is why the UI puts an explicit confirmation in front of this command.
//!
//! The Windows-only part is deliberately tiny (`windows_backend`): two API calls behind the
//! `SubsetBackend` trait. Everything that can be decided without the Event Log service (request
//! validation, file naming, range coalescing, query building, the existing-file policy, per-source
//! failure isolation, result assembly) lives in `engine`, which compiles and is tested on every
//! platform.
//!
//! Output policy:
//! - One output file per source log, named `{label}-subset.evtx` inside the chosen folder. The
//!   label is sanitized so a channel path or file name can never leave that folder.
//! - Nothing is overwritten. The whole request is refused before any API call if a target name is
//!   already taken, and `EvtExportLogOverwrite` is never passed, so the service refuses too.
//! - One source failing (Security without elevation, a channel that no longer exists) does not
//!   abort the others. Each source reports its own status.

use serde::{Deserialize, Serialize};

/// What an exported source is: a registered channel, or an `.evtx` file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxSubsetSourceKind {
    Channel,
    File,
}

/// One source log and the events to keep from it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetSource {
    pub kind: EvtxSubsetSourceKind,
    /// The channel name (`Microsoft-Windows-AAD/Operational`) or the absolute `.evtx` path.
    pub path: String,
    /// `EventRecordID`s as decimal strings, so a value outside JavaScript's safe-integer range is
    /// never rounded on its way here. The frontend sends the lossless text field.
    pub record_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxSubsetFileStatus {
    Exported,
    Failed,
}

/// What happened to one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetFileResult {
    pub kind: EvtxSubsetSourceKind,
    pub source_path: String,
    pub file_name: String,
    pub output_path: String,
    /// Distinct `EventRecordID`s that were asked for.
    pub requested_records: u64,
    pub status: EvtxSubsetFileStatus,
    /// Records found in the written file by reading it back. `None` is "could not be verified",
    /// never zero: a file that was written but could not be read back still exists.
    pub exported_records: Option<u64>,
    /// True only when `EvtArchiveExportedLog` succeeded, so the file renders without the provider.
    pub messages_archived: bool,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetResult {
    pub folder: String,
    pub files: Vec<EvtxSubsetFileResult>,
}

#[cfg(not(target_os = "windows"))]
const UNSUPPORTED_MESSAGE: &str = "EVTX subset export is only available on Windows.";

#[tauri::command]
pub async fn evtx_export_subset(
    folder: String,
    sources: Vec<EvtxSubsetSource>,
) -> Result<EvtxSubsetResult, String> {
    // EvtExportLog is synchronous and can take a long time on a large log, so it must not run on
    // the async runtime's worker threads.
    tokio::task::spawn_blocking(move || export_subset(&folder, &sources))
        .await
        .map_err(|error| format!("Task join error: {error}"))?
}

#[cfg(target_os = "windows")]
pub fn export_subset(
    folder: &str,
    sources: &[EvtxSubsetSource],
) -> Result<EvtxSubsetResult, String> {
    let plan = engine::plan_subset_export(folder, sources)?;
    log::info!(
        "event=evtx_export_subset sources={} folder_chosen=true",
        plan.exports.len()
    );
    Ok(engine::run_plan(&plan, &windows_backend::WindowsBackend))
}

#[cfg(not(target_os = "windows"))]
pub fn export_subset(
    _folder: &str,
    _sources: &[EvtxSubsetSource],
) -> Result<EvtxSubsetResult, String> {
    Err(UNSUPPORTED_MESSAGE.to_string())
}

#[cfg(any(target_os = "windows", test))]
mod engine {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::super::models::MAX_SAFE_EVENT_RECORD_ID;
    use super::{
        EvtxSubsetFileResult, EvtxSubsetFileStatus, EvtxSubsetResult, EvtxSubsetSource,
        EvtxSubsetSourceKind,
    };

    /// Spec 8.17: XPath is limited to about 20 expressions, so a query that needs more becomes a
    /// structured XML query. Counted as comparisons: one per single ID, two per range.
    pub(super) const XPATH_EXPRESSION_LIMIT: usize = 20;
    /// A ceiling on the disjoint ranges one source may need. A filtered view of a large log can
    /// fragment into thousands of ranges; the query text grows with them and the service's limit
    /// on a structured query is not documented, so the request is refused with a message rather
    /// than sent. Unverified: tune on the Windows lab.
    pub(super) const MAX_RANGES_PER_SOURCE: usize = 10_000;
    pub(super) const LABEL_MAX_CHARS: usize = 100;
    /// The folder `EvtArchiveExportedLog` fills with the localized strings, next to the export.
    pub(super) const LOCALE_METADATA_DIR: &str = "LocaleMetaData";
    const FALLBACK_LABEL: &str = "events";

    // ---- record IDs -------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct RecordIdRange {
        pub(super) start: u64,
        pub(super) end: u64,
    }

    /// Parses decimal `EventRecordID` text. Strict on purpose: a sign, a space, a hex prefix or a
    /// fraction is a malformed request, not something to guess at.
    pub(super) fn parse_record_ids(source: &str, ids: &[String]) -> Result<Vec<u64>, String> {
        if ids.is_empty() {
            return Err(format!("{source}: no record IDs were given"));
        }
        let mut parsed = Vec::with_capacity(ids.len());
        for text in ids {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{source}: {text:?} is not a decimal EventRecordID"));
            }
            let id: u64 = text
                .parse()
                .map_err(|_| format!("{source}: EventRecordID {text} does not fit in 64 bits"))?;
            // XPath numbers are IEEE doubles, so above 2^53 - 1 the service compares a rounded
            // value and could export the wrong event. Refuse rather than export a different set.
            if id > MAX_SAFE_EVENT_RECORD_ID {
                return Err(format!(
                    "{source}: EventRecordID {id} is above {MAX_SAFE_EVENT_RECORD_ID}, which the \
                     Event Log query language cannot match exactly"
                ));
            }
            parsed.push(id);
        }
        Ok(parsed)
    }

    /// Sorts, removes duplicates and merges adjacent IDs into inclusive ranges.
    pub(super) fn coalesce_record_ids(ids: &[u64]) -> Vec<RecordIdRange> {
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<RecordIdRange> = Vec::new();
        for id in sorted {
            match ranges.last_mut() {
                // `checked_add` so a range ending at u64::MAX cannot wrap into a false merge.
                Some(last) if last.end.checked_add(1) == Some(id) => last.end = id,
                _ => ranges.push(RecordIdRange { start: id, end: id }),
            }
        }
        ranges
    }

    pub(super) fn distinct_record_count(ranges: &[RecordIdRange]) -> u64 {
        ranges.iter().map(|range| range.end - range.start + 1).sum()
    }

    // ---- query building ---------------------------------------------------------------------

    /// The text passed as `EvtExportLog`'s `Query`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct SubsetQuery {
        pub(super) text: String,
        /// True for a `<QueryList>` document, false for a bare XPath.
        pub(super) structured: bool,
    }

    fn range_cost(range: &RecordIdRange) -> usize {
        if range.start == range.end {
            1
        } else {
            2
        }
    }

    fn range_term(range: &RecordIdRange) -> String {
        if range.start == range.end {
            format!("EventRecordID={}", range.start)
        } else {
            format!(
                "(EventRecordID>={} and EventRecordID<={})",
                range.start, range.end
            )
        }
    }

    fn xpath_for(ranges: &[RecordIdRange]) -> String {
        let terms: Vec<String> = ranges.iter().map(range_term).collect();
        format!("*[System[{}]]", terms.join(" or "))
    }

    fn escape_xml(text: &str, attribute: bool) -> String {
        let mut out = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' if attribute => out.push_str("&quot;"),
                '\'' if attribute => out.push_str("&apos;"),
                other => out.push(other),
            }
        }
        out
    }

    /// The `Path` of a structured query's `<Select>`. Unverified for files: a log file is written
    /// as a `file://` URI in structured queries; confirm on the Windows lab (report item).
    fn select_path(kind: EvtxSubsetSourceKind, path: &str) -> String {
        match kind {
            EvtxSubsetSourceKind::Channel => path.to_string(),
            EvtxSubsetSourceKind::File => format!("file://{path}"),
        }
    }

    /// Builds the query that keeps exactly `ranges`.
    ///
    /// Up to [`XPATH_EXPRESSION_LIMIT`] comparisons it is one XPath. Beyond that it is a structured
    /// XML query with several `<Select>` elements on the same path, each holding at most that many
    /// comparisons (a single `<Select>` XPath is itself limited), which the service unions.
    pub(super) fn build_subset_query(
        kind: EvtxSubsetSourceKind,
        path: &str,
        ranges: &[RecordIdRange],
    ) -> Result<SubsetQuery, String> {
        if ranges.is_empty() {
            return Err(format!("{path}: no record ranges to export"));
        }
        if ranges.len() > MAX_RANGES_PER_SOURCE {
            return Err(format!(
                "{path}: the selected events fall in {} separate runs of record IDs, more than the \
                 {MAX_RANGES_PER_SOURCE} one export can express. Narrow the filter and try again.",
                ranges.len()
            ));
        }
        let total_cost: usize = ranges.iter().map(range_cost).sum();
        if total_cost <= XPATH_EXPRESSION_LIMIT {
            return Ok(SubsetQuery {
                text: xpath_for(ranges),
                structured: false,
            });
        }

        let mut chunks: Vec<&[RecordIdRange]> = Vec::new();
        let mut start = 0usize;
        let mut cost = 0usize;
        for (index, range) in ranges.iter().enumerate() {
            let next = range_cost(range);
            if cost + next > XPATH_EXPRESSION_LIMIT {
                chunks.push(&ranges[start..index]);
                start = index;
                cost = 0;
            }
            cost += next;
        }
        chunks.push(&ranges[start..]);

        let path_attribute = escape_xml(&select_path(kind, path), true);
        let mut text = String::from("<QueryList><Query Id=\"0\">");
        for chunk in chunks {
            text.push_str(&format!(
                "<Select Path=\"{path_attribute}\">{}</Select>",
                escape_xml(&xpath_for(chunk), false)
            ));
        }
        text.push_str("</Query></QueryList>");
        Ok(SubsetQuery {
            text,
            structured: true,
        })
    }

    // ---- file naming ------------------------------------------------------------------------

    fn is_invisible_format_char(ch: char) -> bool {
        matches!(
            ch,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
    }

    fn is_reserved_device_name(label: &str) -> bool {
        // Windows treats `NUL.anything` as the NUL device, so the part before the first dot decides.
        let head = label.split('.').next().unwrap_or("").trim_end();
        let upper = head.to_ascii_uppercase();
        matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit())
    }

    /// Turns a channel name or file stem into a single safe path component fragment.
    ///
    /// Characters Windows forbids in a file name, control characters, directional overrides and
    /// every path separator become `-`; runs of them collapse to one. A source name therefore
    /// cannot carry the file out of the chosen folder, whatever it contains.
    pub(super) fn sanitize_label(label: &str) -> String {
        let mut out = String::with_capacity(label.len());
        let mut after_replacement = false;
        let mut after_dot = false;
        for ch in label.chars() {
            let forbidden = ch.is_control()
                || is_invisible_format_char(ch)
                || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
            if forbidden {
                if !after_replacement {
                    out.push('-');
                    after_replacement = true;
                }
                after_dot = false;
            } else if ch == '.' {
                // A run of dots becomes one, so `..` never survives inside a name.
                if !after_dot {
                    out.push('.');
                }
                after_dot = true;
                after_replacement = false;
            } else {
                out.push(ch);
                after_replacement = false;
                after_dot = false;
            }
        }
        // Windows silently drops trailing dots and spaces, so two different names would collide.
        // Leading and trailing `-` are only ever the residue of a replaced separator.
        let trim = |text: &str| -> String {
            text.trim_matches(|c: char| c == '.' || c == '-' || c.is_whitespace())
                .to_string()
        };
        let mut label: String = trim(&out).chars().take(LABEL_MAX_CHARS).collect();
        label = trim(&label);
        if label.is_empty() {
            return FALLBACK_LABEL.to_string();
        }
        if is_reserved_device_name(&label) {
            label.insert(0, '_');
        }
        label
    }

    /// The label a source contributes to its output name. For a file this is the file stem, not
    /// the path; the spec's `{source-label}` is read as the name an operator would recognize.
    pub(super) fn source_label(kind: EvtxSubsetSourceKind, path: &str) -> String {
        match kind {
            EvtxSubsetSourceKind::Channel => sanitize_label(path),
            EvtxSubsetSourceKind::File => {
                // Split on both separators so the result does not depend on the host OS.
                let name = path.rsplit(['/', '\\']).next().unwrap_or("");
                let stem = match name.len().checked_sub(5) {
                    Some(cut)
                        if name.is_char_boundary(cut)
                            && name[cut..].eq_ignore_ascii_case(".evtx") =>
                    {
                        &name[..cut]
                    }
                    _ => name,
                };
                sanitize_label(stem)
            }
        }
    }

    pub(super) fn output_file_name(label: &str, ordinal: usize) -> String {
        if ordinal <= 1 {
            format!("{label}-subset.evtx")
        } else {
            format!("{label}-{ordinal}-subset.evtx")
        }
    }

    /// Two sources can sanitize to the same name (two `Application.evtx` from different folders;
    /// `A/B` and `A-B`). The file system is case-insensitive on Windows, so compare lowercased and
    /// number the later ones in request order.
    pub(super) fn assign_unique_file_names(labels: &[String]) -> Vec<String> {
        let mut taken: HashSet<String> = HashSet::new();
        labels
            .iter()
            .map(|label| {
                let mut ordinal = 1usize;
                loop {
                    let candidate = output_file_name(label, ordinal);
                    if taken.insert(candidate.to_lowercase()) {
                        return candidate;
                    }
                    ordinal += 1;
                }
            })
            .collect()
    }

    // ---- planning ---------------------------------------------------------------------------

    pub(super) fn validate_output_folder(folder: &str) -> Result<PathBuf, String> {
        if folder.trim().is_empty() {
            return Err("Choose a folder for the exported files.".to_string());
        }
        if folder.chars().any(char::is_control) {
            return Err("The output folder path contains control characters.".to_string());
        }
        let path = PathBuf::from(folder);
        if !path.is_absolute() {
            return Err(format!(
                "The output folder must be an absolute path: {folder}"
            ));
        }
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => Ok(path),
            Ok(_) => Err(format!("The output path is not a folder: {folder}")),
            Err(error) => Err(format!("Cannot use the output folder {folder}: {error}")),
        }
    }

    fn validate_source(source: &EvtxSubsetSource) -> Result<(), String> {
        let path = source.path.as_str();
        if path.trim().is_empty() || path.chars().any(char::is_control) {
            return Err("A source has an empty or invalid name.".to_string());
        }
        if source.kind == EvtxSubsetSourceKind::File {
            let candidate = Path::new(path);
            if !candidate.is_absolute() {
                return Err(format!("{path}: an .evtx source must be an absolute path"));
            }
            if !path.to_ascii_lowercase().ends_with(".evtx") {
                return Err(format!("{path}: only .evtx files can be exported"));
            }
            match fs::metadata(candidate) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => return Err(format!("{path}: not a file")),
                Err(error) => return Err(format!("{path}: cannot read the source file: {error}")),
            }
        }
        Ok(())
    }

    #[derive(Debug, Clone)]
    pub(super) struct PlannedExport {
        pub(super) kind: EvtxSubsetSourceKind,
        pub(super) source_path: String,
        pub(super) file_name: String,
        pub(super) target: PathBuf,
        pub(super) requested: u64,
        pub(super) query: SubsetQuery,
    }

    #[derive(Debug, Clone)]
    pub(super) struct SubsetPlan {
        pub(super) folder: PathBuf,
        pub(super) exports: Vec<PlannedExport>,
        /// Set when archiving must be skipped for the whole request, with the reason.
        pub(super) archive_blocked: Option<String>,
    }

    /// True when `path` names anything at all, including a directory or a dangling link: none of
    /// those may be replaced.
    fn path_is_taken(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    /// `EvtArchiveExportedLog` writes into a `LocaleMetaData` folder next to the export, and the
    /// `wevtutil al` documentation warns that it overwrites files there and that the location must
    /// not hold untrusted links. A link in that spot could redirect those writes, so archiving is
    /// skipped (and reported) rather than followed.
    fn locale_metadata_block_reason(folder: &Path) -> Option<String> {
        let locale_dir = folder.join(LOCALE_METADATA_DIR);
        match fs::symlink_metadata(&locale_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => Some(format!(
                "{} is a link, so the localized messages were not archived into it",
                locale_dir.display()
            )),
            Ok(metadata) if !metadata.is_dir() => Some(format!(
                "{} exists and is not a folder, so the localized messages were not archived",
                locale_dir.display()
            )),
            _ => None,
        }
    }

    pub(super) fn plan_subset_export(
        folder: &str,
        sources: &[EvtxSubsetSource],
    ) -> Result<SubsetPlan, String> {
        let folder = validate_output_folder(folder)?;
        if sources.is_empty() {
            return Err("There are no events to export.".to_string());
        }

        let mut seen: HashSet<(EvtxSubsetSourceKind, String)> = HashSet::new();
        let mut labels = Vec::with_capacity(sources.len());
        let mut prepared = Vec::with_capacity(sources.len());
        for source in sources {
            validate_source(source)?;
            if !seen.insert((source.kind, source.path.to_lowercase())) {
                return Err(format!("{}: listed more than once", source.path));
            }
            let ids = parse_record_ids(&source.path, &source.record_ids)?;
            let ranges = coalesce_record_ids(&ids);
            let query = build_subset_query(source.kind, &source.path, &ranges)?;
            labels.push(source_label(source.kind, &source.path));
            prepared.push((source, distinct_record_count(&ranges), query));
        }

        let names = assign_unique_file_names(&labels);
        let mut exports = Vec::with_capacity(prepared.len());
        for ((source, requested, query), file_name) in prepared.into_iter().zip(names) {
            let target = folder.join(&file_name);
            // The name has no separator and cannot be `.` or `..`, so this holds by construction;
            // asserted anyway because a failure here would be a path escape.
            if target.parent() != Some(folder.as_path()) {
                return Err(format!(
                    "{}: the output name is not a plain file name",
                    source.path
                ));
            }
            exports.push(PlannedExport {
                kind: source.kind,
                source_path: source.path.clone(),
                file_name,
                target,
                requested,
                query,
            });
        }

        let conflicts: Vec<&str> = exports
            .iter()
            .filter(|export| path_is_taken(&export.target))
            .map(|export| export.file_name.as_str())
            .collect();
        if !conflicts.is_empty() {
            return Err(format!(
                "These files already exist in {} and are never overwritten: {}. Choose another \
                 folder, or move or rename them.",
                folder.display(),
                conflicts.join(", ")
            ));
        }

        let archive_blocked = locale_metadata_block_reason(&folder);
        Ok(SubsetPlan {
            folder,
            exports,
            archive_blocked,
        })
    }

    // ---- execution --------------------------------------------------------------------------

    pub(super) struct ExportLogError {
        pub(super) message: String,
        /// The service refused because the target already existed. Such a file is not ours.
        pub(super) already_exists: bool,
    }

    /// The part that needs the Event Log service. Windows implements it; tests fake it.
    pub(super) trait SubsetBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError>;
        fn archive_log(&self, target: &Path) -> Result<(), String>;
        fn count_records(&self, target: &Path) -> Result<u64, String>;
    }

    /// Win32 codes that `EvtExportLog` and `EvtArchiveExportedLog` return in practice, with what
    /// each means to an operator. Anything else is reported by its system message alone.
    pub(super) fn win32_hint(code: u32) -> Option<&'static str> {
        match code {
            2 | 3 => Some("the source log or the output folder was not found"),
            5 => Some("access denied; reading this log may need the application to run elevated"),
            32 => Some("the log file is in use by another process"),
            80 | 183 => Some("the target file already exists"),
            112 => Some("the output disk is full"),
            15000 | 15007 => Some("the channel was not found"),
            15001 => Some("the Event Log service rejected the query"),
            15008 => Some("the structured query was not well-formed XML"),
            _ => None,
        }
    }

    pub(super) fn win32_already_exists(code: u32) -> bool {
        matches!(code, 80 | 183)
    }

    /// Reads the written file back and counts its events. An unreadable record makes the count
    /// unknown rather than low, so it is an error, not a smaller number.
    pub(super) fn count_evtx_records(path: &Path) -> Result<u64, String> {
        let mut parser = evtx::EvtxParser::from_path(path)
            .map_err(|error| format!("cannot open the exported file: {error}"))?;
        let mut readable = 0u64;
        let mut unreadable = 0u64;
        for record in parser.records() {
            match record {
                Ok(_) => readable += 1,
                Err(_) => unreadable += 1,
            }
        }
        if unreadable > 0 {
            return Err(format!(
                "{unreadable} records in the exported file could not be read back ({readable} could)"
            ));
        }
        Ok(readable)
    }

    fn remove_partial_output(export: &PlannedExport) -> Option<String> {
        if !path_is_taken(&export.target) {
            return None;
        }
        match fs::remove_file(&export.target) {
            Ok(()) => None,
            Err(error) => Some(format!(
                "a partial file may remain at {}: {error}",
                export.target.display()
            )),
        }
    }

    pub(super) fn run_plan(plan: &SubsetPlan, backend: &dyn SubsetBackend) -> EvtxSubsetResult {
        let files = plan
            .exports
            .iter()
            .map(|export| run_one(plan, export, backend))
            .collect();
        EvtxSubsetResult {
            folder: plan.folder.to_string_lossy().into_owned(),
            files,
        }
    }

    fn run_one(
        plan: &SubsetPlan,
        export: &PlannedExport,
        backend: &dyn SubsetBackend,
    ) -> EvtxSubsetFileResult {
        let mut result = EvtxSubsetFileResult {
            kind: export.kind,
            source_path: export.source_path.clone(),
            file_name: export.file_name.clone(),
            output_path: export.target.to_string_lossy().into_owned(),
            requested_records: export.requested,
            status: EvtxSubsetFileStatus::Failed,
            exported_records: None,
            messages_archived: false,
            error: None,
            warnings: Vec::new(),
        };

        // Checked again immediately before the call: the plan was made earlier, and a file may
        // have appeared since. The service refuses to overwrite as well; this keeps the message
        // clear and guarantees the cleanup below only ever removes a file this call created.
        if path_is_taken(&export.target) {
            result.error = Some(format!(
                "{} already exists and is never overwritten",
                export.file_name
            ));
            return result;
        }

        log::info!(
            "event=evtx_export_subset_file kind={:?} requested={} structured_query={}",
            export.kind,
            export.requested,
            export.query.structured
        );
        if let Err(error) = backend.export_log(export) {
            let mut message = error.message;
            if !error.already_exists {
                if let Some(note) = remove_partial_output(export) {
                    message = format!("{message} ({note})");
                }
            }
            result.error = Some(message);
            return result;
        }
        result.status = EvtxSubsetFileStatus::Exported;

        match &plan.archive_blocked {
            Some(reason) => result.warnings.push(reason.clone()),
            None => match backend.archive_log(&export.target) {
                Ok(()) => result.messages_archived = true,
                Err(error) => result.warnings.push(format!(
                    "the localized messages were not archived, so events from providers that are \
                     not installed on the machine that opens this file may show no message text \
                     ({error})"
                )),
            },
        }

        match backend.count_records(&export.target) {
            Ok(count) => {
                result.exported_records = Some(count);
                if count != export.requested {
                    result.warnings.push(format!(
                        "the file holds {count} events but {} were requested; the log may have \
                         wrapped or been cleared since they were loaded",
                        export.requested
                    ));
                }
            }
            Err(error) => result
                .warnings
                .push(format!("the record count could not be verified ({error})")),
        }
        result
    }
}

#[cfg(target_os = "windows")]
mod windows_backend {
    use std::path::Path;

    use windows::core::{Error, HSTRING};
    use windows::Win32::System::EventLog::{
        EvtArchiveExportedLog, EvtExportLog, EvtExportLogChannelPath, EvtExportLogFilePath,
    };

    use super::engine::{
        count_evtx_records, win32_already_exists, win32_hint, ExportLogError, PlannedExport,
        SubsetBackend,
    };
    use super::EvtxSubsetSourceKind;

    pub(super) struct WindowsBackend;

    fn win32_code(error: &Error) -> u32 {
        (error.code().0 & 0xFFFF) as u32
    }

    fn describe(context: &str, error: &Error) -> String {
        let message = error.message();
        let message = message.trim();
        let base = if message.is_empty() {
            format!("{context}: Windows error 0x{:08x}", error.code().0 as u32)
        } else {
            format!("{context}: {message}")
        };
        match win32_hint(win32_code(error)) {
            Some(hint) => format!("{base} ({hint})"),
            None => base,
        }
    }

    impl SubsetBackend for WindowsBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
            let flags = match export.kind {
                EvtxSubsetSourceKind::Channel => EvtExportLogChannelPath,
                EvtxSubsetSourceKind::File => EvtExportLogFilePath,
            };
            let source = HSTRING::from(export.source_path.as_str());
            let query = HSTRING::from(export.query.text.as_str());
            let target = HSTRING::from(export.target.as_path());
            // SAFETY: every argument is a valid, NUL-terminated wide string that outlives the
            // call. A local session (`None`) is used, and no overwrite flag is passed, so the
            // service itself refuses an existing target.
            unsafe { EvtExportLog(None, &source, &query, &target, flags.0) }.map_err(|error| {
                ExportLogError {
                    message: describe("EvtExportLog", &error),
                    already_exists: win32_already_exists(win32_code(&error)),
                }
            })
        }

        fn archive_log(&self, target: &Path) -> Result<(), String> {
            let target = HSTRING::from(target);
            // SAFETY: `target` is a valid wide string for the duration of the call. Locale 0 uses
            // the calling thread's locale and the flags are reserved and must be zero.
            unsafe { EvtArchiveExportedLog(None, &target, 0, 0) }
                .map_err(|error| describe("EvtArchiveExportedLog", &error))
        }

        fn count_records(&self, target: &Path) -> Result<u64, String> {
            count_evtx_records(target)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::engine::*;
    use super::*;

    fn ids(values: &[u64]) -> Vec<String> {
        values.iter().map(u64::to_string).collect()
    }

    fn range(start: u64, end: u64) -> RecordIdRange {
        RecordIdRange { start, end }
    }

    // ---- coalescing -------------------------------------------------------------------------

    #[test]
    fn coalesce_sorts_dedups_and_merges_only_adjacent_ids() {
        let got = coalesce_record_ids(&[9, 3, 4, 5, 3, 7, 10, 1]);
        assert_eq!(
            got,
            vec![range(1, 1), range(3, 5), range(7, 7), range(9, 10)]
        );
    }

    #[test]
    fn coalesce_does_not_wrap_at_the_top_of_u64() {
        let got = coalesce_record_ids(&[u64::MAX, 0, u64::MAX - 1]);
        assert_eq!(got, vec![range(0, 0), range(u64::MAX - 1, u64::MAX)]);
        assert_eq!(coalesce_record_ids(&[]), Vec::<RecordIdRange>::new());
    }

    #[test]
    fn distinct_count_counts_ids_not_ranges() {
        let ranges = coalesce_record_ids(&[1, 2, 3, 3, 3, 10]);
        assert_eq!(distinct_record_count(&ranges), 4);
    }

    #[test]
    fn record_id_text_is_strict() {
        assert_eq!(
            parse_record_ids("S", &["0".into(), "42".into()]).unwrap(),
            vec![0, 42]
        );
        for bad in ["", " 5", "5 ", "+5", "-1", "1.5", "0x10", "abc", "1e3"] {
            assert!(
                parse_record_ids("S", &[bad.to_string()]).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(parse_record_ids("S", &[]).is_err());
        assert!(parse_record_ids("S", &["99999999999999999999999".into()]).is_err());
    }

    #[test]
    fn ids_the_query_language_cannot_match_exactly_are_refused() {
        let safe = MAX_SAFE_EVENT_RECORD_ID_FOR_TEST;
        assert!(parse_record_ids("S", &[safe.to_string()]).is_ok());
        let error = parse_record_ids("S", &[(safe + 1).to_string()]).unwrap_err();
        assert!(error.contains("cannot match exactly"), "{error}");
    }
    const MAX_SAFE_EVENT_RECORD_ID_FOR_TEST: u64 = 9_007_199_254_740_991;

    // ---- queries ----------------------------------------------------------------------------

    /// Evaluates the only XPath shapes this module emits against one ID. Written independently of
    /// the builder so a wrong operator or a dropped term shows up as a mismatch.
    fn xpath_matches(xpath: &str, id: u64) -> bool {
        let inner = xpath
            .strip_prefix("*[System[")
            .and_then(|rest| rest.strip_suffix("]]"))
            .expect("shape *[System[...]]");
        inner.split(" or ").any(|term| {
            if let Some(value) = term.strip_prefix("EventRecordID=") {
                return value.parse::<u64>().unwrap() == id;
            }
            let body = term
                .strip_prefix("(EventRecordID>=")
                .and_then(|rest| rest.strip_suffix(')'))
                .expect("range term");
            let (low, high) = body
                .split_once(" and EventRecordID<=")
                .expect("range bounds");
            low.parse::<u64>().unwrap() <= id && id <= high.parse::<u64>().unwrap()
        })
    }

    fn unescape(text: &str) -> String {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    fn select_texts(query: &str) -> Vec<String> {
        query
            .split("</Select>")
            .filter_map(|part| part.split_once('>').map(|(_, rest)| rest))
            .filter_map(|part| part.rsplit_once('>').map(|(_, rest)| rest).or(Some(part)))
            .map(str::to_string)
            .collect()
    }

    fn selects(query: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = query;
        while let Some(start) = rest.find("<Select Path=\"") {
            rest = &rest[start + "<Select Path=\"".len()..];
            let (path, after) = rest.split_once("\">").unwrap();
            let (text, after) = after.split_once("</Select>").unwrap();
            out.push((unescape(path), unescape(text)));
            rest = after;
        }
        out
    }

    #[test]
    fn a_short_selection_is_one_xpath_with_ranges_and_single_ids() {
        let ranges = coalesce_record_ids(&[5, 6, 7, 8, 9, 12]);
        let query = build_subset_query(EvtxSubsetSourceKind::Channel, "System", &ranges).unwrap();
        assert!(!query.structured);
        assert_eq!(
            query.text,
            "*[System[(EventRecordID>=5 and EventRecordID<=9) or EventRecordID=12]]"
        );
    }

    #[test]
    fn the_xpath_limit_counts_comparisons_so_a_range_costs_two() {
        // 20 singles is 20 comparisons: still one XPath.
        let singles: Vec<u64> = (0..20).map(|n| n * 2).collect();
        let at_limit = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "System",
            &coalesce_record_ids(&singles),
        )
        .unwrap();
        assert!(!at_limit.structured);

        // 21 singles is over.
        let over: Vec<u64> = (0..21).map(|n| n * 2).collect();
        let over = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "System",
            &coalesce_record_ids(&over),
        )
        .unwrap();
        assert!(over.structured);

        // 10 ranges is 20 comparisons; 11 ranges is 22.
        let ten: Vec<RecordIdRange> = (0..10).map(|n| range(n * 10, n * 10 + 3)).collect();
        assert!(
            !build_subset_query(EvtxSubsetSourceKind::Channel, "S", &ten)
                .unwrap()
                .structured
        );
        let eleven: Vec<RecordIdRange> = (0..11).map(|n| range(n * 10, n * 10 + 3)).collect();
        assert!(
            build_subset_query(EvtxSubsetSourceKind::Channel, "S", &eleven)
                .unwrap()
                .structured
        );
    }

    #[test]
    fn a_structured_query_splits_into_selects_within_the_limit_and_keeps_every_id() {
        // Disjoint ids with a few runs, 200 ranges, so the query needs many Select elements.
        let mut values = Vec::new();
        for n in 0..200u64 {
            values.push(n * 10);
            if n % 3 == 0 {
                values.push(n * 10 + 1);
            }
        }
        let ranges = coalesce_record_ids(&values);
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "Application", &ranges).unwrap();
        assert!(query.structured);
        let parsed = selects(&query.text);
        assert!(parsed.len() > 1);
        for (path, xpath) in &parsed {
            assert_eq!(path, "Application");
            let comparisons = xpath.matches("EventRecordID").count();
            assert!(
                comparisons <= XPATH_EXPRESSION_LIMIT,
                "{comparisons}: {xpath}"
            );
        }
        // Semantics: an id is kept by the query exactly when it was asked for.
        let wanted: std::collections::HashSet<u64> = values.iter().copied().collect();
        for id in 0..2_010u64 {
            let kept = parsed.iter().any(|(_, xpath)| xpath_matches(xpath, id));
            assert_eq!(kept, wanted.contains(&id), "id {id}");
        }
    }

    #[test]
    fn the_structured_text_is_escaped_and_well_formed() {
        let ranges: Vec<RecordIdRange> = (0..30).map(|n| range(n * 10, n * 10 + 4)).collect();
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "A&B'\"<C>", &ranges).unwrap();
        assert!(query.structured);
        // Inside element text the comparison operators are entities, never raw.
        for text in select_texts(&query.text) {
            assert!(!text.contains("<="), "{text}");
        }
        assert!(query.text.contains("&gt;="));
        assert!(query.text.contains("&lt;="));
        // The attribute carries the channel name with every XML-special character escaped.
        assert!(query.text.contains("Path=\"A&amp;B&apos;&quot;&lt;C&gt;\""));
        // A real XML parser accepts it end to end.
        let mut reader = quick_xml::Reader::from_str(&query.text);
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("not well-formed: {error}"),
            }
        }
        // And the round trip gives back the original name.
        assert_eq!(selects(&query.text)[0].0, "A&B'\"<C>");
    }

    #[test]
    fn a_file_source_is_addressed_by_file_uri_in_a_structured_query_only() {
        let ranges: Vec<RecordIdRange> = (0..30).map(|n| range(n * 10, n * 10 + 4)).collect();
        let structured =
            build_subset_query(EvtxSubsetSourceKind::File, "C:\\logs\\System.evtx", &ranges)
                .unwrap();
        assert_eq!(
            selects(&structured.text)[0].0,
            "file://C:\\logs\\System.evtx"
        );
        let plain = build_subset_query(
            EvtxSubsetSourceKind::File,
            "C:\\logs\\System.evtx",
            &[range(1, 5)],
        )
        .unwrap();
        assert!(!plain.structured);
        assert!(!plain.text.contains("file://"));
    }

    #[test]
    fn an_empty_or_over_fragmented_selection_is_refused_not_truncated() {
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "S", &[]).is_err());
        let fragmented: Vec<RecordIdRange> = (0..=MAX_RANGES_PER_SOURCE as u64)
            .map(|n| range(n * 2, n * 2))
            .collect();
        let error =
            build_subset_query(EvtxSubsetSourceKind::Channel, "System", &fragmented).unwrap_err();
        assert!(error.contains("Narrow the filter"), "{error}");
        let at_cap: Vec<RecordIdRange> = (0..MAX_RANGES_PER_SOURCE as u64)
            .map(|n| range(n * 2, n * 2))
            .collect();
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "System", &at_cap).is_ok());
    }

    // ---- naming -----------------------------------------------------------------------------

    fn assert_single_component(name: &str) {
        let path = Path::new(name);
        assert_eq!(path.components().count(), 1, "{name}");
        assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        assert_ne!(name, ".");
        assert_ne!(name, "..");
        assert!(!name.chars().any(char::is_control), "{name:?}");
    }

    #[test]
    fn sanitized_labels_cannot_leave_the_folder() {
        for hostile in [
            "../../evil",
            "..\\..\\evil",
            "/etc/passwd",
            "C:\\Windows\\System32\\config",
            "\\\\server\\share\\x",
            "a/b:c*d?e\"f<g>h|i",
            "..",
            ".",
            "",
            "   ",
            "evil\u{202e}gpj.exe",
            "tab\tand\nnewline\0nul",
        ] {
            let label = sanitize_label(hostile);
            let name = output_file_name(&label, 1);
            assert_single_component(&name);
            assert!(name.ends_with("-subset.evtx"), "{name}");
            assert!(!label.contains(".."), "{hostile:?} -> {label:?}");
        }
    }

    #[test]
    fn labels_follow_the_spec_for_ordinary_names() {
        assert_eq!(
            sanitize_label("Microsoft-Windows-AAD/Operational"),
            "Microsoft-Windows-AAD-Operational"
        );
        assert_eq!(sanitize_label("Application"), "Application");
        assert_eq!(
            output_file_name(&sanitize_label("Application"), 1),
            "Application-subset.evtx"
        );
    }

    #[test]
    fn trailing_dots_spaces_and_reserved_device_names_are_handled() {
        assert_eq!(sanitize_label("name. . "), "name");
        assert_eq!(sanitize_label("NUL"), "_NUL");
        assert_eq!(sanitize_label("nul.x"), "_nul.x");
        assert_eq!(sanitize_label("COM1"), "_COM1");
        assert_eq!(sanitize_label("lpt9"), "_lpt9");
        assert_eq!(sanitize_label("COM10"), "COM10");
        assert_eq!(sanitize_label("CONSOLE"), "CONSOLE");
        assert_eq!(sanitize_label("\u{FEFF}"), "events");
    }

    #[test]
    fn long_labels_are_capped() {
        let label = sanitize_label(&"x".repeat(500));
        assert_eq!(label.chars().count(), LABEL_MAX_CHARS);
        let wide = sanitize_label(&"\u{4e2d}".repeat(500));
        assert_eq!(wide.chars().count(), LABEL_MAX_CHARS);
    }

    #[test]
    fn a_file_source_is_named_by_its_stem_whatever_the_host_separator() {
        use EvtxSubsetSourceKind::File;
        assert_eq!(source_label(File, "C:\\logs\\System.evtx"), "System");
        assert_eq!(source_label(File, "/var/log/System.EVTX"), "System");
        assert_eq!(source_label(File, "D:\\x\\my.log.evtx"), "my.log");
        assert_eq!(source_label(File, "D:\\x\\noext"), "noext");
        assert_eq!(source_label(File, "D:\\x\\.evtx"), "events");
        assert_eq!(
            source_label(
                EvtxSubsetSourceKind::Channel,
                "Microsoft-Windows-AAD/Operational"
            ),
            "Microsoft-Windows-AAD-Operational"
        );
    }

    #[test]
    fn names_that_collide_are_numbered_in_request_order_case_insensitively() {
        let labels: Vec<String> = ["Application", "application", "System", "Application"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            assign_unique_file_names(&labels),
            vec![
                "Application-subset.evtx",
                "application-2-subset.evtx",
                "System-subset.evtx",
                "Application-3-subset.evtx",
            ]
        );
    }

    // ---- folder and plan --------------------------------------------------------------------

    fn channel(name: &str, record_ids: &[u64]) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::Channel,
            path: name.to_string(),
            record_ids: ids(record_ids),
        }
    }

    fn file_source(path: &Path, record_ids: &[u64]) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::File,
            path: path.to_string_lossy().into_owned(),
            record_ids: ids(record_ids),
        }
    }

    fn folder_str(dir: &tempfile::TempDir) -> String {
        dir.path().to_string_lossy().into_owned()
    }

    #[test]
    fn the_output_folder_must_be_an_existing_absolute_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_output_folder(&folder_str(&dir)).is_ok());
        assert!(validate_output_folder("").is_err());
        assert!(validate_output_folder("   ").is_err());
        assert!(validate_output_folder("relative/dir").is_err());
        assert!(validate_output_folder(&format!("{}/missing", folder_str(&dir))).is_err());
        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        let error = validate_output_folder(&file.to_string_lossy()).unwrap_err();
        assert!(error.contains("not a folder"), "{error}");
        assert!(validate_output_folder(&format!("{}\n", folder_str(&dir))).is_err());
    }

    #[test]
    fn a_plan_names_one_file_per_source_inside_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("src").join("Setup.evtx");
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        fs::write(&log, b"evtx").unwrap();
        let out = tempfile::tempdir().unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[
                channel("Microsoft-Windows-AAD/Operational", &[3, 4, 5, 9]),
                file_source(&log, &[1, 2]),
            ],
        )
        .unwrap();
        let names: Vec<&str> = plan.exports.iter().map(|e| e.file_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Microsoft-Windows-AAD-Operational-subset.evtx",
                "Setup-subset.evtx"
            ]
        );
        for export in &plan.exports {
            assert_eq!(export.target.parent(), Some(out.path()));
        }
        assert_eq!(plan.exports[0].requested, 4);
        assert_eq!(plan.exports[1].requested, 2);
        assert!(plan.archive_blocked.is_none());
    }

    #[test]
    fn a_request_is_refused_before_any_work_when_a_target_name_is_taken() {
        let out = tempfile::tempdir().unwrap();
        fs::write(out.path().join("System-subset.evtx"), b"previous export").unwrap();
        let error = plan_subset_export(
            &folder_str(&out),
            &[channel("Application", &[1]), channel("System", &[1])],
        )
        .unwrap_err();
        assert!(error.contains("System-subset.evtx"), "{error}");
        assert!(error.contains("never overwritten"), "{error}");
        assert!(!error.contains("Application-subset.evtx"), "{error}");
        // The existing file is untouched.
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"previous export"
        );
    }

    #[test]
    fn a_folder_or_link_at_a_target_name_also_counts_as_taken() {
        let out = tempfile::tempdir().unwrap();
        fs::create_dir(out.path().join("System-subset.evtx")).unwrap();
        assert!(plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_link_at_a_target_name_counts_as_taken() {
        let out = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            out.path().join("does-not-exist"),
            out.path().join("System-subset.evtx"),
        )
        .unwrap();
        assert!(plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).is_err());
    }

    #[test]
    fn an_output_can_never_be_the_source_it_was_made_from() {
        let out = tempfile::tempdir().unwrap();
        // Re-exporting a previous subset names the new file after the old one's full stem, so it
        // lands beside it rather than on it.
        let previous = out.path().join("System-subset.evtx");
        fs::write(&previous, b"evtx").unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[file_source(&previous, &[1])]).unwrap();
        assert_eq!(plan.exports[0].file_name, "System-subset-subset.evtx");
        assert_ne!(plan.exports[0].target, previous);

        // A source that already holds the name a collision would give the second export
        // (`System-2-subset.evtx`) is refused as an existing target, not overwritten.
        let other = tempfile::tempdir().unwrap();
        let first = other.path().join("System.evtx");
        fs::write(&first, b"evtx").unwrap();
        let second = out.path().join("System.evtx");
        fs::write(&second, b"evtx").unwrap();
        let colliding = out.path().join("System-2-subset.evtx");
        fs::write(&colliding, b"evtx").unwrap();
        let error = plan_subset_export(
            &folder_str(&out),
            &[file_source(&first, &[1]), file_source(&second, &[1])],
        )
        .unwrap_err();
        assert!(error.contains("System-2-subset.evtx"), "{error}");
        assert_eq!(fs::read(&colliding).unwrap(), b"evtx");
    }

    #[test]
    fn structural_request_errors_are_reported_before_anything_is_written() {
        let out = tempfile::tempdir().unwrap();
        let folder = folder_str(&out);
        assert!(plan_subset_export(&folder, &[]).is_err());
        assert!(plan_subset_export(&folder, &[channel("System", &[])]).is_err());
        assert!(plan_subset_export(&folder, &[channel("", &[1])]).is_err());
        assert!(plan_subset_export(&folder, &[channel("Sys\0tem", &[1])]).is_err());
        assert!(
            plan_subset_export(&folder, &[channel("System", &[1]), channel("SYSTEM", &[2])])
                .is_err()
        );
        let mut bad_id = channel("System", &[1]);
        bad_id.record_ids.push("not a number".into());
        assert!(plan_subset_export(&folder, &[bad_id]).is_err());
        // File sources: relative, wrong extension and missing files are all refused.
        let missing = out.path().join("missing.evtx");
        assert!(plan_subset_export(&folder, &[file_source(&missing, &[1])]).is_err());
        let wrong = out.path().join("notes.txt");
        fs::write(&wrong, b"x").unwrap();
        assert!(plan_subset_export(&folder, &[file_source(&wrong, &[1])]).is_err());
        let relative = EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::File,
            path: "System.evtx".into(),
            record_ids: ids(&[1]),
        };
        assert!(plan_subset_export(&folder, &[relative]).is_err());
        // Only the file the test created is there: nothing was written by the refused requests.
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_locale_folder_blocks_archiving_instead_of_following_it() {
        let out = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).unwrap();
        let reason = plan.archive_blocked.expect("archiving is blocked");
        assert!(reason.contains("is a link"), "{reason}");
    }

    #[test]
    fn a_real_locale_folder_does_not_block_archiving() {
        let out = tempfile::tempdir().unwrap();
        fs::create_dir(out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).unwrap();
        assert!(plan.archive_blocked.is_none());
    }

    // ---- execution with a fake backend ------------------------------------------------------

    #[derive(Default)]
    struct FakeBackend {
        /// Source path -> outcome of `export_log`: Ok writes a file, Err returns the message.
        export_failures: HashMap<String, (String, bool)>,
        /// Partial file written before a failure.
        write_partial_on_failure: bool,
        archive_error: Option<String>,
        counts: HashMap<String, Result<u64, String>>,
        calls: RefCell<Vec<String>>,
    }

    impl SubsetBackend for FakeBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
            self.calls
                .borrow_mut()
                .push(format!("export:{}", export.file_name));
            if let Some((message, already_exists)) = self.export_failures.get(&export.source_path) {
                if self.write_partial_on_failure {
                    fs::write(&export.target, b"partial").unwrap();
                }
                return Err(ExportLogError {
                    message: message.clone(),
                    already_exists: *already_exists,
                });
            }
            fs::write(&export.target, b"evtx").unwrap();
            Ok(())
        }

        fn archive_log(&self, target: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(format!(
                "archive:{}",
                target.file_name().unwrap().to_string_lossy()
            ));
            match &self.archive_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn count_records(&self, target: &Path) -> Result<u64, String> {
            let key = target.file_name().unwrap().to_string_lossy().into_owned();
            self.counts.get(&key).cloned().unwrap_or(Ok(0))
        }
    }

    fn plan_for(out: &tempfile::TempDir, sources: &[EvtxSubsetSource]) -> SubsetPlan {
        plan_subset_export(&folder_str(out), sources).unwrap()
    }

    fn counts(pairs: &[(&str, u64)]) -> HashMap<String, Result<u64, String>> {
        pairs
            .iter()
            .map(|(name, count)| (name.to_string(), Ok(*count)))
            .collect()
    }

    #[test]
    fn a_clean_export_reports_the_verified_count_and_archives_the_messages() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(
            &out,
            &[channel("System", &[1, 2, 3]), channel("Application", &[7])],
        );
        let backend = FakeBackend {
            counts: counts(&[("System-subset.evtx", 3), ("Application-subset.evtx", 1)]),
            ..Default::default()
        };
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files.len(), 2);
        for file in &result.files {
            assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
            assert_eq!(file.exported_records, Some(file.requested_records));
            assert!(file.messages_archived);
            assert!(file.error.is_none());
            assert!(file.warnings.is_empty(), "{:?}", file.warnings);
            assert!(Path::new(&file.output_path).exists());
        }
        // The files were archived after being exported, one at a time.
        assert_eq!(
            *backend.calls.borrow(),
            vec![
                "export:System-subset.evtx",
                "archive:System-subset.evtx",
                "export:Application-subset.evtx",
                "archive:Application-subset.evtx",
            ]
        );
    }

    #[test]
    fn one_source_failing_does_not_stop_the_others_and_leaves_no_partial_file() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(
            &out,
            &[channel("Security", &[1]), channel("System", &[1, 2])],
        );
        let mut backend = FakeBackend {
            write_partial_on_failure: true,
            counts: counts(&[("System-subset.evtx", 2)]),
            ..Default::default()
        };
        backend.export_failures.insert(
            "Security".into(),
            (
                "EvtExportLog: access denied (needs elevation)".into(),
                false,
            ),
        );
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert!(result.files[0]
            .error
            .as_deref()
            .unwrap()
            .contains("access denied"));
        assert_eq!(result.files[0].exported_records, None);
        assert!(!out.path().join("Security-subset.evtx").exists());
        assert_eq!(result.files[1].status, EvtxSubsetFileStatus::Exported);
        assert!(out.path().join("System-subset.evtx").exists());
    }

    #[test]
    fn a_file_that_appeared_after_planning_is_never_replaced_or_deleted() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        fs::write(out.path().join("System-subset.evtx"), b"someone else's").unwrap();
        let backend = FakeBackend::default();
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert!(result.files[0]
            .error
            .as_deref()
            .unwrap()
            .contains("never overwritten"));
        assert!(
            backend.calls.borrow().is_empty(),
            "the API must not be called"
        );
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"someone else's"
        );
    }

    #[test]
    fn when_the_service_reports_the_target_exists_the_existing_file_is_kept() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        let mut backend = FakeBackend::default();
        backend
            .export_failures
            .insert("System".into(), ("EvtExportLog: exists".into(), true));
        // The file appears between the in-process check and the service call.
        struct Racing(FakeBackend);
        impl SubsetBackend for Racing {
            fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
                fs::write(&export.target, b"raced in").unwrap();
                self.0.export_log(export)
            }
            fn archive_log(&self, target: &Path) -> Result<(), String> {
                self.0.archive_log(target)
            }
            fn count_records(&self, target: &Path) -> Result<u64, String> {
                self.0.count_records(target)
            }
        }
        let result = run_plan(&plan, &Racing(backend));
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"raced in",
            "a file the service said already existed is not ours to delete"
        );
    }

    #[test]
    fn an_archive_failure_keeps_the_file_and_says_the_messages_are_missing() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1, 2])]);
        let backend = FakeBackend {
            archive_error: Some("EvtArchiveExportedLog: not found".into()),
            counts: counts(&[("System-subset.evtx", 2)]),
            ..Default::default()
        };
        let file = &run_plan(&plan, &backend).files[0];
        assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
        assert!(!file.messages_archived);
        assert_eq!(file.exported_records, Some(2));
        assert!(file.warnings.iter().any(|w| w.contains("not archived")));
        assert!(out.path().join("System-subset.evtx").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_blocked_locale_folder_skips_the_archive_call_and_says_so() {
        let out = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        let backend = FakeBackend {
            counts: counts(&[("System-subset.evtx", 1)]),
            ..Default::default()
        };
        let file = &run_plan(&plan, &backend).files[0];
        assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
        assert!(!file.messages_archived);
        assert!(file.warnings.iter().any(|w| w.contains("is a link")));
        assert!(backend
            .calls
            .borrow()
            .iter()
            .all(|call| !call.starts_with("archive")));
    }

    #[test]
    fn a_short_file_is_flagged_and_an_unreadable_one_is_unknown_not_zero() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(
            &out,
            &[channel("System", &[1, 2, 3]), channel("Application", &[1])],
        );
        let mut backend = FakeBackend {
            counts: counts(&[("System-subset.evtx", 2)]),
            ..Default::default()
        };
        backend
            .counts
            .insert("Application-subset.evtx".into(), Err("cannot open".into()));
        let result = run_plan(&plan, &backend);
        let system = &result.files[0];
        assert_eq!(system.exported_records, Some(2));
        assert_eq!(system.requested_records, 3);
        assert!(system
            .warnings
            .iter()
            .any(|w| w.contains("holds 2 events but 3")));
        let application = &result.files[1];
        assert_eq!(application.status, EvtxSubsetFileStatus::Exported);
        assert_eq!(application.exported_records, None);
        assert!(application
            .warnings
            .iter()
            .any(|w| w.contains("could not be verified")));
    }

    // ---- error mapping and platform ---------------------------------------------------------

    #[test]
    fn the_win32_hints_name_elevation_and_existing_targets() {
        assert!(win32_hint(5).unwrap().contains("elevated"));
        assert!(win32_hint(15007).unwrap().contains("channel"));
        assert!(win32_hint(15001).is_some());
        assert!(win32_hint(1).is_none());
        assert!(win32_already_exists(80) && win32_already_exists(183));
        assert!(!win32_already_exists(5));
    }

    #[test]
    fn an_unreadable_exported_file_is_an_error_not_a_count() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("bogus-subset.evtx");
        fs::write(&bogus, b"not an evtx file").unwrap();
        assert!(count_evtx_records(&bogus).is_err());
        assert!(count_evtx_records(&dir.path().join("missing.evtx")).is_err());
    }

    /// Needs a real capture, which carries real machine data and stays out of the repo. Point
    /// `CMTRACE_EVTX_FIXTURE` at an .evtx file to run it; without it the test says so and passes.
    #[test]
    fn the_read_back_count_matches_the_parser_on_a_real_log() {
        let Some(raw) = std::env::var_os("CMTRACE_EVTX_FIXTURE") else {
            eprintln!("SKIP: CMTRACE_EVTX_FIXTURE is not set; the real-log count did not run.");
            return;
        };
        let path = PathBuf::from(raw);
        let mut parser = evtx::EvtxParser::from_path(&path).expect("fixture opens");
        let expected = parser.records().filter(Result::is_ok).count() as u64;
        assert_eq!(count_evtx_records(&path).unwrap(), expected);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn off_windows_the_command_body_reports_that_the_feature_is_unsupported() {
        let out = tempfile::tempdir().unwrap();
        let error = export_subset(&folder_str(&out), &[channel("System", &[1])]).unwrap_err();
        assert!(error.contains("only available on Windows"), "{error}");
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }
}
