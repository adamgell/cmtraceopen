//! The single raw record parser for the Intune macOS agent log grammar.
//!
//! Issue #361 requires exactly one owner for this grammar. Both the package
//! leaf and the shell-script leaf frame their records here and then reduce
//! separately, because their phases and terminal semantics differ.
//!
//! # Grammar
//!
//! ```text
//! YYYY-MM-DD HH:MM:SS:mmm | Process | S | ThreadId | Component | Message
//! ```
//!
//! Ground truth for the field layout is `crate::parser::intune_macos`, which
//! frames the same lines for the log viewer. This module does not replace it;
//! it re-frames the same grammar into evidence-carrying records so a semantic
//! reducer can cite provenance per record.
//!
//! # What this parser refuses to do
//!
//! * It never infers a timezone. The grammar carries no offset, so
//!   [`IntuneTimestamp::normalized_utc`] stays `None` and the raw text is the
//!   only ordering key. Rendering a UTC value derived from the *parsing
//!   machine's* offset would be a fact the evidence never stated.
//! * It never classifies a line as an Intune record from punctuation alone. A
//!   pipe-delimited line whose process token is not an Intune agent process is
//!   retained as an unconfirmed record, not promoted into the corpus.
//! * It never discards a line it could not parse. Malformed lines survive as
//!   records with [`IntuneParseState::Malformed`] so coverage stays honest.

use std::sync::OnceLock;

use regex::Regex;
// Required in scope by `intune_raw_preserving_string_enum`, which hand-writes
// the serde impls rather than deriving them.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneEvidenceRef, IntuneParseState, IntuneProvenance,
    IntuneSourceKind, IntuneTimestamp, IntuneTimestampKind,
};

/// Schema version for every type in this module and both leaves built on it.
pub const MACOS_AGENT_SCHEMA_VERSION: u32 = 1;

/// Agent-log grammar revisions this build claims to understand.
///
/// Microsoft rewords agent messages between releases. A log whose declared
/// version is outside this set is still parsed, but every conclusion drawn from
/// it is confidence-capped, because the message vocabulary the reducers key on
/// may have changed underneath them.
pub const KNOWN_GRAMMAR_VERSIONS: &[&str] = &["2026.03", "2026.05", "2026.07"];

intune_raw_preserving_string_enum! {
    /// The agent process that emitted a record.
    ///
    /// The daemon runs as root against the system log root; the agent runs in a
    /// user session. Unknown processes round-trip so a renamed binary does not
    /// silently become "not Intune".
    pub enum MacAgentProcess {
        Daemon => "IntuneMDM-Daemon",
        Agent => "IntuneMDM-Agent",
    }
}

intune_raw_preserving_string_enum! {
    /// The single-letter severity token.
    pub enum MacAgentSeverity {
        Info => "I",
        Warning => "W",
        Error => "E",
        Debug => "D",
    }
}

impl MacAgentProcess {
    /// Decode a process token, preserving anything unrecognized verbatim.
    pub fn from_wire(value: &str) -> Self {
        match value {
            "IntuneMDM-Daemon" => Self::Daemon,
            "IntuneMDM-Agent" => Self::Agent,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Whether this token identifies a first-party Intune agent process.
    pub fn is_intune_agent(&self) -> bool {
        matches!(self, Self::Daemon | Self::Agent)
    }
}

impl MacAgentSeverity {
    /// Decode a severity token, preserving anything unrecognized verbatim.
    pub fn from_wire(value: &str) -> Self {
        match value {
            "I" => Self::Info,
            "W" => Self::Warning,
            "E" => Self::Error,
            "D" => Self::Debug,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Which log root an artifact came from.
///
/// This is a manifest fact derived from the artifact's own name, never from a
/// filesystem probe: the parser crate performs no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MacAgentSourceRoot {
    /// `/Library/Logs/Microsoft/Intune/IntuneMDMDaemon *.log`
    System,
    /// `~/Library/Logs/Microsoft/Intune/IntuneMDMAgent *.log`
    User,
    Unknown,
}

impl MacAgentSourceRoot {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Unknown => "unknown",
        }
    }
}

/// Where an artifact sits in the rotation sequence.
///
/// Ordering matters: a rotated fragment holds earlier activity than the current
/// file, and a transaction routinely straddles the boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MacAgentRotation {
    /// A dated rotation, e.g. `IntuneMDMDaemon 2026-07-29--09-10-11.log`. The
    /// stamp sorts lexicographically, which is also chronological.
    Rotated(String),
    /// The live file, which always holds the most recent activity.
    Current,
}

/// How the collector reported an artifact.
///
/// These mirror the fixture manifest's `captureState` vocabulary exactly, so a
/// caller can hand the manifest through without a lossy translation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAgentCaptureState {
    Captured,
    Capped,
    Absent,
    AccessDenied,
    Skipped,
    Unsupported,
    ParseFailed,
}

impl MacAgentCaptureState {
    /// Parse the manifest wire token.
    pub fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "captured" => Self::Captured,
            "capped" => Self::Capped,
            "absent" => Self::Absent,
            "accessDenied" => Self::AccessDenied,
            "skipped" => Self::Skipped,
            "unsupported" => Self::Unsupported,
            "parseFailed" => Self::ParseFailed,
            _ => return None,
        })
    }

    /// The coverage status this capture state requires.
    pub fn artifact_status(self) -> crate::intune::evidence::IntuneArtifactStatus {
        use crate::intune::evidence::IntuneArtifactStatus as S;
        match self {
            Self::Captured => S::Available,
            Self::Capped => S::Capped,
            Self::Absent => S::Missing,
            Self::AccessDenied => S::PermissionDenied,
            Self::Skipped => S::Skipped,
            Self::Unsupported => S::Unsupported,
            Self::ParseFailed => S::ParseFailed,
        }
    }

    /// The per-observation access state this capture state implies.
    pub fn access_state(self) -> crate::intune::evidence::IntuneAccessState {
        use crate::intune::evidence::IntuneAccessState as A;
        match self {
            Self::Captured => A::Available,
            Self::Capped => A::Capped,
            Self::Absent => A::Missing,
            Self::AccessDenied => A::PermissionDenied,
            Self::Skipped => A::Skipped,
            Self::Unsupported => A::Unsupported,
            Self::ParseFailed => A::Failed,
        }
    }

    /// Whether records read from this artifact may support a conclusion.
    ///
    /// `Capped` is deliberately usable: a truncated log's records are real, and
    /// only the *absence* of a record in it proves nothing.
    pub fn yields_records(self) -> bool {
        matches!(self, Self::Captured | Self::Capped | Self::ParseFailed)
    }
}

/// One supplied artifact, before parsing.
///
/// The pure crate never opens files. A native collector reads the bytes,
/// decodes them, and hands over the text with its sanitized identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAgentArtifactInput {
    pub artifact_id: String,
    /// Coverage family, e.g. `intuneMdmAgent`.
    pub family: String,
    pub file_name: String,
    /// Already-sanitized path. Never a real user path.
    pub sanitized_source_path: Option<String>,
    pub capture_state: MacAgentCaptureState,
    /// Decoded text. `None` for any state with no bytes.
    pub content: Option<String>,
    /// Free-text collector note, surfaced in coverage.
    pub detail: Option<String>,
}

/// The grammar revision an artifact declared, and whether this build knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAgentGrammar {
    pub declared_version: Option<String>,
    pub recognized: bool,
}

impl MacAgentGrammar {
    fn absent() -> Self {
        Self {
            declared_version: None,
            recognized: false,
        }
    }

    /// A version is recognized when a known revision is a prefix of it, so a
    /// build number like `2026.07.1234` matches the `2026.07` revision.
    fn from_declared(version: &str) -> Self {
        let recognized = KNOWN_GRAMMAR_VERSIONS
            .iter()
            .any(|known| version.starts_with(known));
        Self {
            declared_version: Some(version.to_owned()),
            recognized,
        }
    }
}

/// One framed record with everything needed to cite it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAgentRecord {
    pub artifact_id: String,
    /// Index among the records of this artifact, 0-based and stable.
    pub record_number: u64,
    /// 1-based physical line in the artifact.
    pub line_number: u64,
    pub raw_text: String,
    pub timestamp: Option<IntuneTimestamp>,
    pub process: Option<MacAgentProcess>,
    pub severity: Option<MacAgentSeverity>,
    pub thread_id: Option<u64>,
    pub component: Option<String>,
    pub message: String,
    pub parse_state: IntuneParseState,
}

impl MacAgentRecord {
    /// The stable evidence identifier a finding cites.
    pub fn evidence_ref(&self) -> IntuneEvidenceRef {
        IntuneEvidenceRef {
            evidence_id: format!("{}#{}", self.artifact_id, self.record_number),
            source_artifact_id: self.artifact_id.clone(),
        }
    }

    /// Provenance pointing at the exact line this record was framed from.
    pub fn provenance(&self, file_path: Option<&str>) -> IntuneProvenance {
        IntuneProvenance {
            source_kind: IntuneSourceKind::AgentLog,
            source_artifact_id: self.artifact_id.clone(),
            file_path: file_path.map(str::to_owned),
            line_number: Some(self.line_number),
            record_number: Some(self.record_number),
            registry: None,
            event: None,
        }
    }

    /// The ordering key: timestamp text, then physical position.
    ///
    /// The timestamp format is fixed-width, so lexicographic order on the raw
    /// text is chronological without inventing a timezone. Records with no
    /// parseable timestamp sort last within their artifact rather than being
    /// dropped.
    fn sort_text(&self) -> &str {
        self.timestamp
            .as_ref()
            .map(|stamp| stamp.raw_text.as_str())
            .unwrap_or("9999-99-99 99:99:99:999")
    }

    pub fn component_is(&self, expected: &[&str]) -> bool {
        self.component.as_deref().is_some_and(|component| {
            expected
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(component))
        })
    }
}

/// One parsed artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAgentLog {
    pub artifact_id: String,
    pub family: String,
    pub file_name: String,
    pub sanitized_source_path: Option<String>,
    pub capture_state: MacAgentCaptureState,
    pub source_root: MacAgentSourceRoot,
    pub rotation: MacAgentRotation,
    pub grammar: MacAgentGrammar,
    pub records: Vec<MacAgentRecord>,
    pub malformed_records: u64,
    /// Whether the supplied text still carried a UTF-8 BOM.
    pub had_bom: bool,
    pub detail: Option<String>,
}

impl MacAgentLog {
    /// Whether any record confirmed this artifact really is an Intune agent log.
    ///
    /// A file name is a candidate, never proof. Without a record carrying a
    /// known agent process token the artifact stays unconfirmed and its records
    /// are not fed to a reducer.
    pub fn is_confirmed(&self) -> bool {
        self.records
            .iter()
            .filter_map(|record| record.process.as_ref())
            .any(MacAgentProcess::is_intune_agent)
    }
}

/// `2026-07-29 09:10:11:888 | Process | S | 12345 | Component | message`
fn record_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}:\d{3})",
            r"\s*\|\s*(?P<process>[^|]+?)\s*",
            r"\|\s*(?P<severity>[A-Z])\s*",
            r"\|\s*(?P<thread>\d+)\s*",
            r"\|\s*(?P<component>[^|]+?)\s*",
            r"\|\s*(?P<message>.*)$",
        ))
        .expect("macOS agent record regex must compile")
    })
}

/// The agent version banner, e.g. `Intune MDM Agent version 2026.07.1 starting`.
fn version_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bagent\s+version\s+(?P<version>[0-9][0-9A-Za-z.\-]*)")
            .expect("agent version regex must compile")
    })
}

/// Split `IntuneMDMDaemon 2026-07-29--09-10-11.log` into root and rotation.
///
/// The date stamp is what marks a rotation; the live file has none. Both the
/// space-separated form Microsoft ships and a hyphen-separated variant are
/// accepted, because rotation naming has changed between agent releases and a
/// misread rotation silently reorders a transaction.
fn classify_file_name(file_name: &str) -> (MacAgentSourceRoot, MacAgentRotation) {
    let trimmed = file_name.trim();
    let stem = trimmed
        .strip_suffix(".log")
        .or_else(|| trimmed.strip_suffix(".LOG"))
        .unwrap_or(trimmed);

    let (name_part, remainder) = match stem.split_once(' ') {
        Some((name, rest)) => (name, Some(rest)),
        None => (stem, None),
    };

    let root = match name_part.to_ascii_lowercase().as_str() {
        "intunemdmdaemon" => MacAgentSourceRoot::System,
        "intunemdmagent" => MacAgentSourceRoot::User,
        _ => MacAgentSourceRoot::Unknown,
    };

    let rotation = match remainder.map(str::trim).filter(|rest| !rest.is_empty()) {
        Some(stamp) => MacAgentRotation::Rotated(stamp.to_owned()),
        None => MacAgentRotation::Current,
    };

    (root, rotation)
}

fn parse_timestamp(raw: &str) -> IntuneTimestamp {
    IntuneTimestamp {
        raw_text: raw.to_owned(),
        // The grammar carries no offset. Reporting one, or deriving a UTC value
        // from the parsing machine's clock, would assert a fact the log never
        // stated.
        original_offset: None,
        normalized_utc: None,
        kind: IntuneTimestampKind::Unspecified,
    }
}

/// Frame one supplied artifact into records.
///
/// Artifacts with no bytes still produce a [`MacAgentLog`], because their
/// coverage entry is the point: an absent log is a diagnostic fact, not a gap
/// in the output.
pub fn parse_agent_log(input: &MacAgentArtifactInput) -> MacAgentLog {
    let (source_root, rotation) = classify_file_name(&input.file_name);

    let raw = input.content.as_deref().unwrap_or_default();
    let had_bom = raw.starts_with('\u{feff}');
    let body = raw.strip_prefix('\u{feff}').unwrap_or(raw);

    let mut records = Vec::new();
    let mut malformed_records = 0u64;
    let mut grammar = MacAgentGrammar::absent();

    if input.capture_state.yields_records() {
        for (index, line) in body.lines().enumerate() {
            let line_number = (index + 1) as u64;
            let trimmed = line.trim_end_matches('\r').trim();
            if trimmed.is_empty() {
                continue;
            }

            let record_number = records.len() as u64;
            match record_re().captures(trimmed) {
                Some(caps) => {
                    let message = caps["message"].trim().to_owned();
                    if grammar.declared_version.is_none() {
                        if let Some(found) = version_re().captures(&message) {
                            grammar = MacAgentGrammar::from_declared(&found["version"]);
                        }
                    }
                    records.push(MacAgentRecord {
                        artifact_id: input.artifact_id.clone(),
                        record_number,
                        line_number,
                        raw_text: trimmed.to_owned(),
                        timestamp: Some(parse_timestamp(&caps["timestamp"])),
                        process: Some(MacAgentProcess::from_wire(&caps["process"])),
                        severity: Some(MacAgentSeverity::from_wire(&caps["severity"])),
                        thread_id: caps["thread"].parse().ok(),
                        component: Some(caps["component"].trim().to_owned()),
                        message,
                        parse_state: IntuneParseState::Parsed,
                    });
                }
                None => {
                    malformed_records += 1;
                    records.push(MacAgentRecord {
                        artifact_id: input.artifact_id.clone(),
                        record_number,
                        line_number,
                        raw_text: trimmed.to_owned(),
                        timestamp: None,
                        process: None,
                        severity: None,
                        thread_id: None,
                        component: None,
                        message: trimmed.to_owned(),
                        parse_state: IntuneParseState::Malformed,
                    });
                }
            }
        }
    }

    MacAgentLog {
        artifact_id: input.artifact_id.clone(),
        family: input.family.clone(),
        file_name: input.file_name.clone(),
        sanitized_source_path: input.sanitized_source_path.clone(),
        capture_state: input.capture_state,
        source_root,
        rotation,
        grammar,
        records,
        malformed_records,
        had_bom,
        detail: input.detail.clone(),
    }
}

/// Frame every artifact, then order records deterministically across artifacts.
///
/// Ordering is (rotation, timestamp text, artifact id, record number). Rotated
/// fragments precede the current file because they hold earlier activity, and
/// the trailing artifact/record tiebreak means two records sharing a timestamp
/// to the millisecond still have exactly one stable order.
pub fn parse_bundle(inputs: &[MacAgentArtifactInput]) -> Vec<MacAgentLog> {
    let mut logs = inputs.iter().map(parse_agent_log).collect::<Vec<_>>();
    logs.sort_by(|left, right| {
        left.rotation
            .cmp(&right.rotation)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
    logs
}

/// Every record of every artifact, in deterministic global order.
///
/// Only artifacts whose capture state yields records and whose contents confirm
/// an Intune agent process contribute. An unconfirmed artifact stays visible in
/// coverage instead of feeding a reducer.
pub fn ordered_records(logs: &[MacAgentLog]) -> Vec<&MacAgentRecord> {
    let mut ordered = logs
        .iter()
        .filter(|log| log.capture_state.yields_records() && log.is_confirmed())
        .flat_map(|log| {
            log.records
                .iter()
                .map(move |record| (&log.rotation, &log.artifact_id, record))
        })
        .collect::<Vec<_>>();

    ordered.sort_by(|left, right| {
        left.0
            .cmp(right.0)
            .then_with(|| left.2.sort_text().cmp(right.2.sort_text()))
            .then_with(|| left.1.cmp(right.1))
            .then_with(|| left.2.record_number.cmp(&right.2.record_number))
    });

    ordered.into_iter().map(|(_, _, record)| record).collect()
}

/// The grammar verdict for a whole bundle.
///
/// A single unrecognized artifact is enough to cap confidence: the reducers key
/// on message wording, and one fragment written by an unknown revision can
/// silently withhold the record that would have changed an outcome.
pub fn bundle_grammar(logs: &[MacAgentLog]) -> MacAgentGrammar {
    let mut declared: Option<String> = None;
    let mut recognized = true;
    let mut saw_any = false;

    for log in logs {
        let Some(version) = log.grammar.declared_version.as_ref() else {
            continue;
        };
        saw_any = true;
        if declared.is_none() {
            declared = Some(version.clone());
        }
        recognized &= log.grammar.recognized;
    }

    MacAgentGrammar {
        declared_version: declared,
        // No banner at all is not a recognized grammar: it is an unknown one.
        recognized: saw_any && recognized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(file_name: &str, content: &str) -> MacAgentArtifactInput {
        MacAgentArtifactInput {
            artifact_id: "a1".to_owned(),
            family: "intuneMdmAgent".to_owned(),
            file_name: file_name.to_owned(),
            sanitized_source_path: None,
            capture_state: MacAgentCaptureState::Captured,
            content: Some(content.to_owned()),
            detail: None,
        }
    }

    const RECORD: &str =
        "2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 100 | AppInstaller | Reporting results";

    #[test]
    fn a_well_formed_record_is_framed_with_every_field() {
        let log = parse_agent_log(&input("IntuneMDMDaemon.log", RECORD));
        assert_eq!(log.records.len(), 1);
        let record = &log.records[0];
        assert_eq!(record.process, Some(MacAgentProcess::Daemon));
        assert_eq!(record.severity, Some(MacAgentSeverity::Info));
        assert_eq!(record.thread_id, Some(100));
        assert_eq!(record.component.as_deref(), Some("AppInstaller"));
        assert_eq!(record.message, "Reporting results");
        assert_eq!(record.parse_state, IntuneParseState::Parsed);
        assert_eq!(log.malformed_records, 0);
    }

    #[test]
    fn the_grammar_never_invents_a_timezone() {
        let log = parse_agent_log(&input("IntuneMDMDaemon.log", RECORD));
        let stamp = log.records[0].timestamp.as_ref().expect("timestamp framed");
        assert_eq!(stamp.kind, IntuneTimestampKind::Unspecified);
        assert_eq!(stamp.normalized_utc, None);
        assert_eq!(stamp.original_offset, None);
        assert_eq!(stamp.raw_text, "2026-07-29 09:10:11:888");
    }

    #[test]
    fn a_malformed_line_is_retained_rather_than_dropped() {
        let log = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            &format!("{RECORD}\nthis is not a record at all"),
        ));
        assert_eq!(log.records.len(), 2);
        assert_eq!(log.malformed_records, 1);
        assert_eq!(log.records[1].parse_state, IntuneParseState::Malformed);
        assert_eq!(log.records[1].raw_text, "this is not a record at all");
    }

    #[test]
    fn a_bom_is_stripped_and_reported() {
        let log = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            &format!("\u{feff}{RECORD}"),
        ));
        assert!(log.had_bom);
        assert_eq!(log.malformed_records, 0);
        assert_eq!(log.records.len(), 1);
    }

    #[test]
    fn the_file_name_selects_the_source_root_and_rotation() {
        assert_eq!(
            classify_file_name("IntuneMDMDaemon.log"),
            (MacAgentSourceRoot::System, MacAgentRotation::Current)
        );
        assert_eq!(
            classify_file_name("IntuneMDMAgent.log"),
            (MacAgentSourceRoot::User, MacAgentRotation::Current)
        );
        assert_eq!(
            classify_file_name("IntuneMDMDaemon 2026-07-29--09-10-11.log"),
            (
                MacAgentSourceRoot::System,
                MacAgentRotation::Rotated("2026-07-29--09-10-11".to_owned())
            )
        );
        assert_eq!(
            classify_file_name("SomethingElse.log").0,
            MacAgentSourceRoot::Unknown
        );
    }

    #[test]
    fn rotated_fragments_order_before_the_current_file() {
        // A transaction routinely straddles a rotation boundary; reversing this
        // makes the earlier half look like the later half.
        assert!(MacAgentRotation::Rotated("2026-07-29".to_owned()) < MacAgentRotation::Current);
    }

    #[test]
    fn a_pipe_delimited_line_without_an_agent_process_does_not_confirm_the_source() {
        let log = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            "2026-07-29 09:10:11:888 | SomeOtherTool | I | 1 | Thing | hello",
        ));
        assert!(!log.is_confirmed());
        assert!(ordered_records(&[log]).is_empty());
    }

    #[test]
    fn an_unknown_process_token_round_trips_verbatim() {
        let log = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            "2026-07-29 09:10:11:888 | IntuneMDM-Helper | I | 1 | Thing | hello",
        ));
        assert_eq!(
            log.records[0].process,
            Some(MacAgentProcess::Unknown("IntuneMDM-Helper".to_owned()))
        );
    }

    #[test]
    fn a_known_version_banner_is_recognized_and_an_unknown_one_is_not() {
        let known = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            "2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting",
        ));
        assert_eq!(known.grammar.declared_version.as_deref(), Some("2026.07.1"));
        assert!(known.grammar.recognized);

        let unknown = parse_agent_log(&input(
            "IntuneMDMDaemon.log",
            "2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2031.01.9 starting",
        ));
        assert!(!unknown.grammar.recognized);
        assert_eq!(
            unknown.grammar.declared_version.as_deref(),
            Some("2031.01.9")
        );
    }

    #[test]
    fn a_bundle_with_no_version_banner_is_treated_as_an_unknown_grammar() {
        let log = parse_agent_log(&input("IntuneMDMDaemon.log", RECORD));
        assert!(!bundle_grammar(&[log]).recognized);
    }

    #[test]
    fn absent_artifacts_yield_no_records_but_still_parse() {
        let mut absent = input("IntuneMDMDaemon.log", "");
        absent.capture_state = MacAgentCaptureState::Absent;
        absent.content = None;
        let log = parse_agent_log(&absent);
        assert!(log.records.is_empty());
        assert_eq!(
            log.capture_state.artifact_status(),
            crate::intune::evidence::IntuneArtifactStatus::Missing
        );
    }

    #[test]
    fn records_order_deterministically_across_rotations() {
        let rotated = MacAgentArtifactInput {
            artifact_id: "z-rotated".to_owned(),
            file_name: "IntuneMDMDaemon 2026-07-28--00-00-00.log".to_owned(),
            content: Some(
                "2026-07-28 08:00:00:000 | IntuneMDM-Daemon | I | 1 | AppInstaller | earlier"
                    .to_owned(),
            ),
            ..input("IntuneMDMDaemon.log", "")
        };
        let current = MacAgentArtifactInput {
            artifact_id: "a-current".to_owned(),
            file_name: "IntuneMDMDaemon.log".to_owned(),
            content: Some(
                "2026-07-29 09:10:11:888 | IntuneMDM-Daemon | I | 1 | AppInstaller | later"
                    .to_owned(),
            ),
            ..input("IntuneMDMDaemon.log", "")
        };

        // Supplied in both orders, the result must be identical.
        let forward = parse_bundle(&[rotated.clone(), current.clone()]);
        let backward = parse_bundle(&[current, rotated]);
        let forward_messages = ordered_records(&forward)
            .iter()
            .map(|r| r.message.clone())
            .collect::<Vec<_>>();
        let backward_messages = ordered_records(&backward)
            .iter()
            .map(|r| r.message.clone())
            .collect::<Vec<_>>();
        assert_eq!(forward_messages, vec!["earlier", "later"]);
        assert_eq!(forward_messages, backward_messages);
    }
}
