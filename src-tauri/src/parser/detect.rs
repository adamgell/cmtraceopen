//! Format auto-detection.
//!
//! Examines the first non-empty lines of file content to determine
//! whether it uses CCM, Simple, Timestamped, or Plain text format.
//!
//! Detection strategy (matches CMTrace binary behavior, extended):
//! - Check for `<![LOG[` marker → CCM format
//! - Check for `$$<` delimiter → Simple format
//! - Check for Panther path hints plus Panther setup log records → dedicated Panther parser
//! - Check for ReportingEvents path hints plus tab-delimited update history rows → dedicated ReportingEvents parser
//! - Check for ` type="` substring → CCM format (fallback indicator)
//! - Check for timestamp patterns (ISO, slash-date, syslog, time-only) → Timestamped
//! - Otherwise → Plain text

use super::{
    burn, cbs, dhcp, dism, intune_macos, msi, panther, psadt, reporting_events,
    timestamped::{self, DateOrder},
};
use crate::models::log_entry::{
    DateFieldOrder, LogFormat, ParseQuality, ParserImplementation, ParserKind,
    ParserProvenance, ParserSelectionInfo, ParserSpecialization, RecordFraming,
};

/// Backend-owned parser selection used for both initial parsing and tailing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedParser {
    pub parser: ParserKind,
    pub implementation: ParserImplementation,
    pub provenance: ParserProvenance,
    pub parse_quality: ParseQuality,
    pub record_framing: RecordFraming,
    pub date_order: DateOrder,
    pub specialization: Option<ParserSpecialization>,
}

impl ResolvedParser {
    pub fn new(
        parser: ParserKind,
        implementation: ParserImplementation,
        provenance: ParserProvenance,
        parse_quality: ParseQuality,
        record_framing: RecordFraming,
        date_order: DateOrder,
        specialization: Option<ParserSpecialization>,
    ) -> Self {
        Self {
            parser,
            implementation,
            provenance,
            parse_quality,
            record_framing,
            date_order,
            specialization,
        }
    }

    pub fn ccm() -> Self {
        Self::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn simple() -> Self {
        Self::new(
            ParserKind::Simple,
            ParserImplementation::Simple,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn ime() -> Self {
        Self::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            DateOrder::default(),
            Some(ParserSpecialization::Ime),
        )
    }

    pub fn generic_timestamped(date_order: DateOrder) -> Self {
        Self::new(
            ParserKind::Timestamped,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Heuristic,
            ParseQuality::SemiStructured,
            RecordFraming::PhysicalLine,
            date_order,
            None,
        )
    }

    pub fn panther() -> Self {
        Self::new(
            ParserKind::Panther,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::default(),
            None,
        )
    }

    pub fn cbs() -> Self {
        Self::new(
            ParserKind::Cbs,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::default(),
            None,
        )
    }

    pub fn dism() -> Self {
        Self::new(
            ParserKind::Dism,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::default(),
            None,
        )
    }

    pub fn plain_text() -> Self {
        Self::new(
            ParserKind::Plain,
            ParserImplementation::PlainText,
            ParserProvenance::Fallback,
            ParseQuality::TextFallback,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn reporting_events() -> Self {
        Self::new(
            ParserKind::ReportingEvents,
            ParserImplementation::ReportingEvents,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn msi() -> Self {
        Self::new(
            ParserKind::Msi,
            ParserImplementation::Msi,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::PhysicalLine,
            DateOrder::MonthFirst,
            None,
        )
    }

    pub fn burn() -> Self {
        Self::new(
            ParserKind::Burn,
            ParserImplementation::Burn,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn dhcp() -> Self {
        Self::new(
            ParserKind::Dhcp,
            ParserImplementation::Dhcp,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::MonthFirst,
            None,
        )
    }

    pub fn intune_macos() -> Self {
        Self::new(
            ParserKind::IntuneMacOs,
            ParserImplementation::IntuneMacOs,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn psadt_legacy() -> Self {
        Self::new(
            ParserKind::PsadtLegacy,
            ParserImplementation::PsadtLegacy,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::default(),
            None,
        )
    }

    pub fn compatibility_format(&self) -> LogFormat {
        match self.implementation {
            ParserImplementation::Ccm => LogFormat::Ccm,
            ParserImplementation::Simple => LogFormat::Simple,
            ParserImplementation::GenericTimestamped => LogFormat::Timestamped,
            ParserImplementation::ReportingEvents => LogFormat::Timestamped,
            ParserImplementation::Msi => LogFormat::Timestamped,
            ParserImplementation::PsadtLegacy => LogFormat::Timestamped,
            ParserImplementation::IntuneMacOs => LogFormat::Timestamped,
            ParserImplementation::Dhcp => LogFormat::Timestamped,
            ParserImplementation::Burn => LogFormat::Timestamped,
            ParserImplementation::PlainText => LogFormat::Plain,
        }
    }

    pub fn to_info(&self) -> ParserSelectionInfo {
        ParserSelectionInfo {
            parser: self.parser,
            implementation: self.implementation,
            provenance: self.provenance,
            parse_quality: self.parse_quality,
            record_framing: self.record_framing,
            date_order: match (self.parser, self.implementation) {
                (ParserKind::Timestamped, ParserImplementation::GenericTimestamped) => {
                    Some(match self.date_order {
                        DateOrder::MonthFirst => DateFieldOrder::MonthFirst,
                        DateOrder::DayFirst => DateFieldOrder::DayFirst,
                    })
                }
                _ => None,
            },
            specialization: self.specialization,
        }
    }
}

/// Detect the parser selection from file content.
/// Examines up to the first 20 non-empty lines.
pub fn detect_parser(path: &str, content: &str) -> ResolvedParser {
    let sample_lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(20)
        .collect();

    // Early detection: DHCP logs have a ~35-line header before any CSV data.
    // The first 20 non-empty lines are all header text, so content-based matching
    // won't find data rows. Detect via header signature or path hint + header.
    {
        let content_lower = content.to_ascii_lowercase();
        if content_lower.starts_with("\t\tmicrosoft dhcp")
            || content_lower.contains("microsoft dhcp service activity log")
            || content_lower.contains("microsoft dhcpv6 service activity log")
        {
            return ResolvedParser::dhcp();
        }
    }

    let path_lower = path.to_ascii_lowercase();
    let panther_path_hint = path_lower.contains("panther")
        || path_lower.ends_with("setupact.log")
        || path_lower.ends_with("setuperr.log");
    let cbs_path_hint = path_lower.ends_with("cbs.log")
        || path_lower.contains("/logs/cbs/")
        || path_lower.contains("\\logs\\cbs\\");
    let dism_path_hint = path_lower.ends_with("dism.log")
        || path_lower.contains("/logs/dism/")
        || path_lower.contains("\\logs\\dism\\");
    let reporting_events_path_hint = path_lower.ends_with("reportingevents.log")
        || path_lower.contains("/softwaredistribution/reportingevents.log")
        || path_lower.contains("\\softwaredistribution\\reportingevents.log");
    let ime_path_hint = matches!(
        path_lower.rsplit(['/', '\\']).next(),
        Some(
            "agentexecutor.log"
                | "appactionprocessor.log"
                | "appworkload.log"
                | "clienthealth.log"
                | "healthscripts.log"
                | "intunemanagementextension.log"
        )
    );

    let dhcp_path_hint = path_lower.contains("dhcpsrvlog")
        || path_lower.contains("dhcpv6srvlog")
        || path_lower.contains("dhcp_logs");

    let intune_macos_path_hint = path_lower.contains("intunemdmdaemon")
        || path_lower.contains("/logs/microsoft/intune/");

    let mut ccm_count = 0;
    let mut cbs_count = 0;
    let mut dism_count = 0;
    let mut reporting_events_count = 0;
    let mut simple_count = 0;
    let mut panther_count = 0;
    let mut msi_count = 0u32;
    let mut psadt_legacy_count = 0u32;
    let mut intune_macos_count = 0u32;
    let mut dhcp_count = 0u32;
    let mut burn_count = 0u32;
    let mut timestamp_count = 0;
    let mut has_day_first = false;

    for line in &sample_lines {
        if line.contains("<![LOG[") && line.contains("]LOG]!>") {
            ccm_count += 1;
        } else if line.contains(" type=\"") && line.contains("component=\"") {
            // Fallback CCM detection from the binary's ` type="` check
            ccm_count += 1;
        } else if line.contains("$$<") {
            simple_count += 1;
        } else if reporting_events::matches_reporting_events_record(line.trim()) {
            reporting_events_count += 1;
        } else if dism::matches_dism_record(line.trim()) {
            dism_count += 1;
            timestamp_count += 1;
        } else if cbs::matches_cbs_record(line.trim()) {
            cbs_count += 1;
            timestamp_count += 1;
        } else if panther::matches_panther_record(line.trim()) {
            panther_count += 1;
        } else if burn::matches_burn_record(line.trim()) {
            burn_count += 1;
            timestamp_count += 1;
        } else if dhcp::matches_dhcp_record(line.trim()) {
            dhcp_count += 1;
        } else if intune_macos::matches_intune_macos(line.trim()) {
            intune_macos_count += 1;
            timestamp_count += 1;
        } else {
            msi_count += msi::matches_msi_content(line.trim());
            psadt_legacy_count += psadt::matches_psadt_legacy_content(line.trim());
        }
        if timestamped::matches_any_timestamp(line.trim()) {
            timestamp_count += 1;
            // Check for EU-style dates (first field > 12 → must be day)
            if let Some(first_field) = timestamped::slash_date_first_field(line.trim()) {
                if first_field > 12 {
                    has_day_first = true;
                }
            }
        }
    }

    if ime_path_hint && ccm_count > 0 {
        ResolvedParser::ime()
    } else if ccm_count > 0 && ccm_count >= simple_count {
        ResolvedParser::ccm()
    } else if simple_count > 0 {
        ResolvedParser::simple()
    } else if reporting_events_path_hint && reporting_events_count >= 1 {
        ResolvedParser::reporting_events()
    } else if cbs_path_hint && cbs_count >= 1 {
        ResolvedParser::cbs()
    } else if dism_path_hint && dism_count >= 1 {
        ResolvedParser::dism()
    } else if panther_path_hint && panther_count >= 1 {
        ResolvedParser::panther()
    } else if reporting_events_count >= 2 {
        ResolvedParser::reporting_events()
    } else if dism_count >= 2 {
        ResolvedParser::dism()
    } else if burn_count >= 2 {
        ResolvedParser::burn()
    } else if (dhcp_path_hint && dhcp_count >= 1) || dhcp_count >= 3 {
        ResolvedParser::dhcp()
    } else if (intune_macos_path_hint && intune_macos_count >= 1) || intune_macos_count >= 2 {
        ResolvedParser::intune_macos()
    } else if msi_count >= 2 {
        ResolvedParser::msi()
    } else if psadt_legacy_count >= 2 {
        ResolvedParser::psadt_legacy()
    } else if timestamp_count >= 2 {
        // Require at least 2 timestamp matches to avoid false positives
        ResolvedParser::generic_timestamped(if has_day_first {
            DateOrder::DayFirst
        } else {
            DateOrder::MonthFirst
        })
    } else {
        ResolvedParser::plain_text()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ccm() {
        let content = r#"<![LOG[Test message]LOG]!><time="08:00:00.000+000" date="01-01-2024" component="Test" context="" type="1" thread="100" file="">
<![LOG[Another message]LOG]!><time="08:00:01.000+000" date="01-01-2024" component="Test" context="" type="1" thread="100" file="">"#;
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.parser, ParserKind::Ccm);
        assert_eq!(detected.compatibility_format(), LogFormat::Ccm);
        assert_eq!(detected.provenance, ParserProvenance::Dedicated);
        assert_eq!(detected.specialization, None);
    }

    #[test]
    fn test_detect_ime_family_from_known_path_hint() {
        let content = r#"<![LOG[Client Health evaluation starts.]LOG]!><time="23:00:10.6893636" date="11-12-2025" component="ClientHealth" context="" type="1" thread="1" file="">
<![LOG[OnStart, public cloud env.]LOG]!><time="23:00:11.4573058" date="11-12-2025" component="ClientHealth" context="" type="1" thread="1" file="">"#;

        let detected = detect_parser("C:/ProgramData/Microsoft/IntuneManagementExtension/Logs/ClientHealth.log", content);
        let info = detected.to_info();

        assert_eq!(detected.parser, ParserKind::Ccm);
        assert_eq!(detected.implementation, ParserImplementation::Ccm);
        assert_eq!(detected.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(detected.specialization, Some(ParserSpecialization::Ime));
        assert_eq!(info.specialization, Some(ParserSpecialization::Ime));
    }

    #[test]
    fn test_detect_known_ime_path_requires_ccm_content_before_specializing() {
        let content = "2026-03-12 11:16:37.309 ClientHealth check starts\n2026-03-12 11:16:38.000 ClientHealth check ends";

        let detected = detect_parser(
            "C:/ProgramData/Microsoft/IntuneManagementExtension/Logs/ClientHealth.log",
            content,
        );

        assert_eq!(detected.parser, ParserKind::Timestamped);
        assert_eq!(detected.implementation, ParserImplementation::GenericTimestamped);
        assert_eq!(detected.specialization, None);
    }

    #[test]
    fn test_detect_simple() {
        let content = r#"Message one $$<Comp1><01-01-2024 08:00:00.000+000><thread=100>
Message two $$<Comp2><01-01-2024 08:00:01.000+000><thread=200>"#;
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.parser, ParserKind::Simple);
        assert_eq!(detected.compatibility_format(), LogFormat::Simple);
    }

    #[test]
    fn test_detect_plain() {
        let content = "Just some plain text\nAnother line\nNothing special here";
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.parser, ParserKind::Plain);
        assert_eq!(detected.compatibility_format(), LogFormat::Plain);
        assert_eq!(detected.provenance, ParserProvenance::Fallback);
    }

    #[test]
    fn test_detect_timestamped_iso() {
        let content = "2024-01-15T08:00:00.000Z Starting application\n\
                        2024-01-15T08:00:01.000Z Loading config\n\
                        2024-01-15T08:00:02.000Z Ready";
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.parser, ParserKind::Timestamped);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(detected.parse_quality, ParseQuality::SemiStructured);
    }

    #[test]
    fn test_detect_timestamped_us_date() {
        let content = "01/15/2024 08:00:00 Starting application\n\
                        01/15/2024 08:00:01 Loading config";
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(detected.date_order, DateOrder::MonthFirst);
    }

    #[test]
    fn test_detect_timestamped_eu_date() {
        let content = "25/01/2024 08:00:00 Starting application\n\
                        15/01/2024 08:00:01 Loading config";
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(detected.date_order, DateOrder::DayFirst);
    }

    #[test]
    fn test_single_timestamp_line_stays_plain() {
        // Only 1 timestamped line should not trigger Timestamped format
        let content = "2024-01-15T08:00:00Z Starting\nRandom text\nMore text";
        let detected = detect_parser("sample.log", content);
        assert_eq!(detected.compatibility_format(), LogFormat::Plain);
    }

    #[test]
    fn test_detect_panther_from_path_and_content() {
        let content = "2024-01-15 08:00:00, Info SP Setup started\n\
                        2024-01-15 08:00:01, Warning MIG Retry required";

        let detected = detect_parser("C:/Windows/Panther/setupact.log", content);
        let info = detected.to_info();

        assert_eq!(detected.parser, ParserKind::Panther);
        assert_eq!(detected.provenance, ParserProvenance::Dedicated);
        assert_eq!(detected.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(info.parser, ParserKind::Panther);
        assert_eq!(info.date_order, None);
    }

    #[test]
    fn test_detect_cbs_from_path_and_content() {
        let content = "2024-01-15 08:00:00, Info                  CBS    Exec: Processing package\n\
                        2024-01-15 08:00:01, Warning               CSI    [SR] Repair retry scheduled";

        let detected = detect_parser("C:/Windows/Logs/CBS/CBS.log", content);
        let info = detected.to_info();

        assert_eq!(detected.parser, ParserKind::Cbs);
        assert_eq!(detected.implementation, ParserImplementation::GenericTimestamped);
        assert_eq!(detected.provenance, ParserProvenance::Dedicated);
        assert_eq!(detected.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(info.date_order, None);
    }

    #[test]
    fn test_detect_reporting_events_from_path_and_content() {
        let content = "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t1\t{22222222-2222-2222-2222-222222222222}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tInstallation Successful: KB5034123\n\
                        {33333333-3333-3333-3333-333333333333}\t2024-01-15 08:05:00:456\t2\tSoftware Update\t3\t{44444444-4444-4444-4444-444444444444}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034441";

        let detected = detect_parser("C:/Windows/SoftwareDistribution/ReportingEvents.log", content);
        let info = detected.to_info();

        assert_eq!(detected.parser, ParserKind::ReportingEvents);
        assert_eq!(detected.implementation, ParserImplementation::ReportingEvents);
        assert_eq!(detected.provenance, ParserProvenance::Dedicated);
        assert_eq!(detected.parse_quality, ParseQuality::Structured);
        assert_eq!(detected.record_framing, RecordFraming::PhysicalLine);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(info.parser, ParserKind::ReportingEvents);
        assert_eq!(info.implementation, ParserImplementation::ReportingEvents);
        assert_eq!(info.date_order, None);
    }

    #[test]
    fn test_detect_reporting_events_from_content_without_path_hint() {
        let content = "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t1\t{22222222-2222-2222-2222-222222222222}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tInstallation Successful: KB5034123\n\
                        {33333333-3333-3333-3333-333333333333}\t2024-01-15 08:05:00:456\t2\tSoftware Update\t3\t{44444444-4444-4444-4444-444444444444}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034441";

        let detected = detect_parser("C:/Temp/update-history.txt", content);

        assert_eq!(detected.parser, ParserKind::ReportingEvents);
        assert_eq!(detected.implementation, ParserImplementation::ReportingEvents);
        assert_eq!(detected.record_framing, RecordFraming::PhysicalLine);
    }

    #[test]
    fn test_detect_dism_from_path_and_content() {
        let content = "2024-01-15 08:00:00, Info                  DISM   DISM Provider Store: PID=100 TID=200 loaded provider\n\
                        2024-01-15 08:00:01, Error                 DISM   DISM Package Manager: Failed finalizing changes";

        let detected = detect_parser("C:/Windows/Logs/DISM/dism.log", content);
        let info = detected.to_info();

        assert_eq!(detected.parser, ParserKind::Dism);
        assert_eq!(detected.implementation, ParserImplementation::GenericTimestamped);
        assert_eq!(detected.provenance, ParserProvenance::Dedicated);
        assert_eq!(detected.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(info.date_order, None);
    }

    #[test]
    fn test_detect_panther_still_wins_for_panther_paths() {
        let content = "2024-01-15 08:00:00, Info SP Setup started\n\
                        2024-01-15 08:00:01, Warning MIG Retry required";

        let detected = detect_parser("C:/Windows/Panther/setupact.log", content);

        assert_eq!(detected.parser, ParserKind::Panther);
    }

    #[test]
    fn test_detect_dism_from_content_without_path_hint() {
        let content = "2024-01-15 08:00:00, Info                  DISM   DISM Provider Store: PID=100 TID=200 loaded provider\n\
                        2024-01-15 08:00:01, Warning               DISM   DISM Package Manager: Retry required";

        let detected = detect_parser("C:/Temp/servicing.txt", content);

        assert_eq!(detected.parser, ParserKind::Dism);
        assert_eq!(detected.compatibility_format(), LogFormat::Timestamped);
    }

    #[test]
    fn test_selection_info_can_distinguish_dedicated_parser_from_generic_fallback() {
        let selection = ResolvedParser::new(
            ParserKind::Panther,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );

        let info = selection.to_info();

        assert_eq!(info.parser, ParserKind::Panther);
        assert_eq!(info.implementation, ParserImplementation::GenericTimestamped);
        assert_eq!(info.provenance, ParserProvenance::Dedicated);
        assert_eq!(info.parse_quality, ParseQuality::SemiStructured);
        assert_eq!(info.record_framing, RecordFraming::LogicalRecord);
        assert_eq!(info.date_order, None);
        assert_eq!(info.specialization, None);
        assert_eq!(selection.compatibility_format(), LogFormat::Timestamped);
    }
}
