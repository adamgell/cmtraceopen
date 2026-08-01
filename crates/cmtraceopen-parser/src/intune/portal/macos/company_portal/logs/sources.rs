//! Artifact inputs, rotation identity, and byte decoding.
//!
//! This crate never opens a file. The native adapter walks
//! `~/Library/Logs/CompanyPortal/`, reads the bytes, and hands each artifact over
//! as a [`CompanyPortalLogSource`] together with what became of the collection
//! attempt. Keeping discovery on the native side is what lets the reduction be
//! tested from a fixture corpus with no device present, and is required by the
//! crate's wasm32 invariant.

use encoding_rs::{UTF_8, WINDOWS_1252};

use super::models::{CompanyPortalCaptureState, CompanyPortalRotation, CompanyPortalRotationKind};

/// File-name stems that identify a direct Company Portal application log.
///
/// Compared case-insensitively after the rotation suffix and extension are
/// stripped. A name match is a *candidate* signal only; content must confirm it.
pub const LOG_FILE_STEMS: &[&str] = &[
    "companyportal",
    "company portal",
    "companyportalagent",
    "companyportalappserviceextension",
];

/// Process tokens a direct Company Portal application log record may name.
pub const COMPANY_PORTAL_PROCESSES: &[&str] = &[
    "companyportal",
    "company portal",
    "companyportalagent",
    "companyportalappserviceextension",
    "com.microsoft.companyportal",
    "com.microsoft.companyportalmac",
];

/// Path fragments that suggest the Company Portal log directory.
///
/// A hint narrows the search; it never confirms one. Anything can be copied into
/// that directory, and the surrounding issue is explicit that a path is a
/// candidate signal rather than proof.
pub const PATH_HINTS: &[&str] = &[
    "/library/logs/companyportal",
    "/library/logs/company portal",
    "\\library\\logs\\companyportal",
];

/// One artifact the adapter attempted to collect.
///
/// `content` is `None` whenever the capture state produced no bytes, which keeps
/// "we read an empty file" distinguishable from "we never read the file".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyPortalLogSource {
    pub artifact_id: String,
    pub file_name: String,
    /// Path with the user's home directory already replaced by the adapter.
    pub sanitized_file_path: Option<String>,
    pub capture_state: CompanyPortalCaptureState,
    pub content: Option<String>,
    /// Encoding the adapter decoded the bytes with, from [`decode_log_bytes`].
    pub encoding: Option<String>,
    /// When the adapter collected the artifact, in UTC.
    ///
    /// Supplied rather than read from a clock: this crate has no clock on
    /// wasm32, and a capture time invented at reduction time would not be the
    /// capture time.
    pub captured_at_utc: String,
}

impl CompanyPortalLogSource {
    /// Minimal constructor for a fully captured artifact.
    pub fn captured(
        artifact_id: impl Into<String>,
        file_name: impl Into<String>,
        content: impl Into<String>,
        captured_at_utc: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            sanitized_file_path: None,
            capture_state: CompanyPortalCaptureState::Captured,
            content: Some(content.into()),
            encoding: Some(UTF_8.name().to_string()),
            captured_at_utc: captured_at_utc.into(),
        }
    }

    /// Does the sanitized path or file name point at the Company Portal log
    /// directory?
    pub fn has_path_hint(&self) -> bool {
        let haystack = self
            .sanitized_file_path
            .as_deref()
            .unwrap_or(&self.file_name)
            .to_ascii_lowercase()
            .replace('\\', "/");
        PATH_HINTS
            .iter()
            .any(|hint| haystack.contains(&hint.replace('\\', "/")))
            || file_name_is_candidate(&self.file_name)
    }

    /// Rotation identity derived from the file name.
    pub fn rotation(&self) -> CompanyPortalRotation {
        rotation_from_file_name(&self.file_name)
    }
}

/// Strip the extension and any rotation suffix, returning the stem.
fn strip_extension(file_name: &str) -> &str {
    let trimmed = file_name.trim();
    for extension in [".log", ".LOG", ".txt", ".TXT"] {
        if let Some(stem) = trimmed.strip_suffix(extension) {
            return stem;
        }
    }
    trimmed
}

/// Does this file name name a Company Portal application log?
pub fn file_name_is_candidate(file_name: &str) -> bool {
    let stem = strip_extension(file_name);
    let base = match stem.rsplit_once('-') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => stem,
    };
    let lowered = base.trim().to_ascii_lowercase();
    LOG_FILE_STEMS.iter().any(|candidate| *candidate == lowered)
}

/// Classify a file name into a rotation member.
///
/// `CompanyPortal.log` is the live file; `CompanyPortal-1.log` and higher are
/// progressively older; `CompanyPortal-20260312.log` is datestamped and gets no
/// ordinal, because a fabricated one would be indistinguishable from an explicit
/// one and would corrupt chronological ordering.
pub fn rotation_from_file_name(file_name: &str) -> CompanyPortalRotation {
    let stem = strip_extension(file_name);

    let Some((_, suffix)) = stem.rsplit_once('-') else {
        return CompanyPortalRotation {
            kind: CompanyPortalRotationKind::Current,
            ordinal: Some(0),
            datestamp: None,
        };
    };

    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return CompanyPortalRotation {
            kind: CompanyPortalRotationKind::Unknown,
            ordinal: None,
            datestamp: None,
        };
    }

    // Eight or more digits is a datestamp, not an ordinal. No log directory
    // holds ten million rotations, so the length test is unambiguous.
    if suffix.len() >= 8 {
        return CompanyPortalRotation {
            kind: CompanyPortalRotationKind::Datestamped,
            ordinal: None,
            datestamp: Some(suffix.to_string()),
        };
    }

    match suffix.parse::<u32>() {
        Ok(ordinal) => CompanyPortalRotation {
            kind: CompanyPortalRotationKind::Numbered,
            ordinal: Some(ordinal),
            datestamp: None,
        },
        Err(_) => CompanyPortalRotation {
            kind: CompanyPortalRotationKind::Unknown,
            ordinal: None,
            datestamp: None,
        },
    }
}

/// Decoded text plus the encoding that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLog {
    pub text: String,
    /// Encoding name as `encoding_rs` reports it, e.g. `UTF-8`.
    pub encoding: String,
    /// Was a byte-order mark present and stripped?
    pub had_bom: bool,
    /// Did the chosen encoding need replacement characters?
    pub had_replacements: bool,
}

/// Decode artifact bytes using the repository's UTF-8 then Windows-1252 rule.
///
/// A UTF-8, UTF-16LE, or UTF-16BE byte-order mark is honored and stripped. Bytes
/// that are not valid UTF-8 fall back to Windows-1252, which never fails, so an
/// artifact written by an older build is read rather than rejected. The chosen
/// encoding is reported so an export can say how the text was obtained instead of
/// implying the bytes were unambiguous.
pub fn decode_log_bytes(bytes: &[u8]) -> DecodedLog {
    if let Some((encoding, bom_length)) = encoding_rs::Encoding::for_bom(bytes) {
        let (text, _, had_replacements) = encoding.decode(&bytes[bom_length..]);
        return DecodedLog {
            text: text.into_owned(),
            encoding: encoding.name().to_string(),
            had_bom: true,
            had_replacements,
        };
    }

    match std::str::from_utf8(bytes) {
        Ok(text) => DecodedLog {
            text: text.to_string(),
            encoding: UTF_8.name().to_string(),
            had_bom: false,
            had_replacements: false,
        },
        Err(_) => {
            let (text, _, had_replacements) = WINDOWS_1252.decode(bytes);
            DecodedLog {
                text: text.into_owned(),
                encoding: WINDOWS_1252.name().to_string(),
                had_bom: false,
                had_replacements,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_live_file_is_rotation_zero() {
        let rotation = rotation_from_file_name("CompanyPortal.log");
        assert_eq!(rotation.kind, CompanyPortalRotationKind::Current);
        assert_eq!(rotation.ordinal, Some(0));
    }

    #[test]
    fn numbered_rotations_keep_their_ordinal() {
        let rotation = rotation_from_file_name("CompanyPortal-2.log");
        assert_eq!(rotation.kind, CompanyPortalRotationKind::Numbered);
        assert_eq!(rotation.ordinal, Some(2));
    }

    #[test]
    fn a_datestamped_rotation_gets_no_fabricated_ordinal() {
        let rotation = rotation_from_file_name("CompanyPortal-20260312.log");
        assert_eq!(rotation.kind, CompanyPortalRotationKind::Datestamped);
        assert_eq!(rotation.ordinal, None);
        assert_eq!(rotation.datestamp.as_deref(), Some("20260312"));
    }

    #[test]
    fn candidate_names_cover_the_rotation_forms() {
        assert!(file_name_is_candidate("CompanyPortal.log"));
        assert!(file_name_is_candidate("CompanyPortal-3.log"));
        assert!(file_name_is_candidate("Company Portal.log"));
        assert!(!file_name_is_candidate("IntuneMDMDaemon.log"));
        assert!(!file_name_is_candidate("CompanyPortalDiagnostics.zip"));
    }

    #[test]
    fn a_path_hint_is_recognized_without_confirming_anything() {
        let source = CompanyPortalLogSource {
            artifact_id: "a1".to_owned(),
            file_name: "unrelated.log".to_owned(),
            sanitized_file_path: Some(
                "SYNTHETIC://Library/Logs/CompanyPortal/unrelated.log".to_owned(),
            ),
            capture_state: CompanyPortalCaptureState::Captured,
            content: Some(String::new()),
            encoding: None,
            captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        };
        assert!(source.has_path_hint());
    }

    #[test]
    fn utf8_bytes_decode_without_a_bom() {
        let decoded = decode_log_bytes(b"plain ascii");
        assert_eq!(decoded.text, "plain ascii");
        assert_eq!(decoded.encoding, "UTF-8");
        assert!(!decoded.had_bom);
    }

    #[test]
    fn a_utf8_bom_is_stripped_and_reported() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice("record".as_bytes());
        let decoded = decode_log_bytes(&bytes);
        assert_eq!(decoded.text, "record");
        assert!(decoded.had_bom);
        assert_eq!(decoded.encoding, "UTF-8");
    }

    #[test]
    fn invalid_utf8_falls_back_to_windows_1252() {
        // 0xE9 is `é` in Windows-1252 and an invalid lone byte in UTF-8.
        let decoded = decode_log_bytes(b"caf\xE9 sync");
        assert_eq!(decoded.text, "café sync");
        assert_eq!(decoded.encoding, "windows-1252");
        assert!(!decoded.had_replacements);
    }

    #[test]
    fn a_utf16_bom_is_honored() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "ok".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_log_bytes(&bytes);
        assert_eq!(decoded.text, "ok");
        assert_eq!(decoded.encoding, "UTF-16LE");
        assert!(decoded.had_bom);
    }
}
