use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use thiserror::Error;

use super::models::{
    EspNormalizedStatus, EspOobeConfig, EspRawStatus, EspStatus, EspStatusDetail, EspTimestamp,
    EspTimestampKind,
};

pub const MAX_PERCENT_DECODE_INPUT_BYTES: usize = 4096;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum EspNormalizationError {
    #[error("percent-encoded input is {actual} bytes; maximum is {maximum}")]
    InputTooLong { actual: usize, maximum: usize },
    #[error("invalid percent escape at byte {index}")]
    InvalidPercentEscape { index: usize },
    #[error("percent-decoded value is not UTF-8")]
    InvalidUtf8,
}

pub fn normalize_office_detail_status(raw: EspRawStatus) -> EspStatus {
    let mapping = match raw_number(&raw) {
        Some(0) => Some((EspNormalizedStatus::NotStarted, "None")),
        Some(10) => Some((EspNormalizedStatus::Initialized, "Initialized")),
        Some(20) => Some((EspNormalizedStatus::Downloading, "Download In Progress")),
        Some(25) => Some((EspNormalizedStatus::Pending, "Pending Download Retry")),
        Some(30) => Some((EspNormalizedStatus::Failed, "Download Failed")),
        Some(40) => Some((EspNormalizedStatus::Downloaded, "Download Completed")),
        Some(48) => Some((EspNormalizedStatus::Pending, "Pending User Session")),
        Some(50) => Some((EspNormalizedStatus::Installing, "Enforcement In Progress")),
        Some(55) => Some((EspNormalizedStatus::Pending, "Pending Enforcement Retry")),
        Some(60) => Some((EspNormalizedStatus::Failed, "Enforcement Failed")),
        Some(70) => Some((
            EspNormalizedStatus::Succeeded,
            "Success / Enforcement Completed",
        )),
        _ => None,
    };
    mapped_status(raw, mapping)
}

pub fn normalize_classic_esp_status(raw: EspRawStatus) -> EspStatus {
    let mapping = match raw_number(&raw) {
        Some(1) => Some((EspNormalizedStatus::NotInstalled, "Not Installed")),
        Some(2) => Some((EspNormalizedStatus::InProgress, "Downloading / Installing")),
        Some(3) => Some((EspNormalizedStatus::Succeeded, "Success / Installed")),
        Some(4) => Some((EspNormalizedStatus::Failed, "Error / Failed")),
        _ => None,
    };
    mapped_status(raw, mapping)
}

pub fn normalize_policy_status(raw: EspRawStatus) -> EspStatus {
    let mapping = match raw_number(&raw) {
        Some(0) => Some((EspNormalizedStatus::NotStarted, "Not Processed")),
        Some(1) => Some((EspNormalizedStatus::Processed, "Processed")),
        _ => None,
    };
    mapped_status(raw, mapping)
}

pub fn normalize_v2_status(raw: EspRawStatus) -> EspStatus {
    let mapping = match &raw {
        EspRawStatus::Number(value) => v2_mapping_by_number(*value),
        EspRawStatus::Text(value) => value
            .trim()
            .parse::<i64>()
            .ok()
            .and_then(v2_mapping_by_number)
            .or_else(|| v2_mapping_by_name(value.trim())),
    };
    mapped_status(raw, mapping)
}

pub fn normalize_office_status(
    outer_raw: EspRawStatus,
    detailed_raw: Option<EspRawStatus>,
) -> EspStatus {
    let mut outer = normalize_policy_status(outer_raw);
    let Some(detailed_raw) = detailed_raw else {
        return outer;
    };
    let detailed = normalize_office_detail_status(detailed_raw);

    if !matches!(
        detailed.normalized,
        EspNormalizedStatus::Unknown | EspNormalizedStatus::NotStarted
    ) {
        outer.normalized = detailed.normalized.clone();
    }
    outer.display = format!("{} / {}", outer.display, detailed.display);
    outer.detail = Some(EspStatusDetail {
        raw: detailed.raw,
        normalized: detailed.normalized,
        display: detailed.display,
    });
    outer
}

pub fn percent_decode_bounded(input: &str) -> Result<String, EspNormalizationError> {
    if input.len() > MAX_PERCENT_DECODE_INPUT_BYTES {
        return Err(EspNormalizationError::InputTooLong {
            actual: input.len(),
            maximum: MAX_PERCENT_DECODE_INPUT_BYTES,
        });
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(EspNormalizationError::InvalidPercentEscape { index });
        }
        let Some(high) = hex_nibble(bytes[index + 1]) else {
            return Err(EspNormalizationError::InvalidPercentEscape { index });
        };
        let Some(low) = hex_nibble(bytes[index + 2]) else {
            return Err(EspNormalizationError::InvalidPercentEscape { index });
        };
        output.push((high << 4) | low);
        index += 3;
    }

    String::from_utf8(output).map_err(|_| EspNormalizationError::InvalidUtf8)
}

pub fn extract_guid(input: &str) -> Option<String> {
    let decoded = percent_decode_bounded(input).ok()?;
    let bytes = decoded.as_bytes();
    if bytes.len() < 36 {
        return None;
    }

    for window in bytes.windows(36) {
        if is_guid_window(window) {
            return Some(
                window
                    .iter()
                    .map(|byte| {
                        if *byte == b'_' {
                            '-'
                        } else {
                            char::from(byte.to_ascii_lowercase())
                        }
                    })
                    .collect(),
            );
        }
    }
    None
}

pub fn decode_oobe_config(raw_mask: u64) -> EspOobeConfig {
    EspOobeConfig {
        raw_mask,
        skip_keyboard: raw_mask & 1024 != 0,
        enable_patch_download: raw_mask & 512 != 0,
        skip_windows_upgrade_ux: raw_mask & 256 != 0,
        aad_tpm_required: raw_mask & 128 != 0,
        aad_device_authentication: raw_mask & 64 != 0,
        tpm_attestation: raw_mask & 32 != 0,
        skip_eula: raw_mask & 16 != 0,
        skip_oem_registration: raw_mask & 8 != 0,
        skip_express_settings: raw_mask & 4 != 0,
        disallow_admin: raw_mask & 2 != 0,
    }
}

pub fn normalize_timestamp(raw: &str, explicit_local_offset: Option<&str>) -> EspTimestamp {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        let is_utc_text = raw.ends_with('Z') || raw.ends_with('z');
        return EspTimestamp {
            raw_text: raw.to_string(),
            original_offset: Some(if is_utc_text {
                "Z".to_string()
            } else {
                parsed.offset().to_string()
            }),
            normalized_utc: Some(format_utc(parsed.with_timezone(&Utc))),
            kind: if is_utc_text {
                EspTimestampKind::Utc
            } else {
                EspTimestampKind::Offset
            },
        };
    }

    let Some(naive) = parse_naive_timestamp(raw) else {
        return unresolved_timestamp(raw, EspTimestampKind::Invalid, explicit_local_offset);
    };
    let Some(offset_text) = explicit_local_offset else {
        return unresolved_timestamp(raw, EspTimestampKind::Unspecified, None);
    };
    let Some(offset) = parse_fixed_offset(offset_text) else {
        return unresolved_timestamp(raw, EspTimestampKind::Invalid, Some(offset_text));
    };
    let Some(with_offset) = offset.from_local_datetime(&naive).single() else {
        return unresolved_timestamp(raw, EspTimestampKind::Invalid, Some(offset_text));
    };

    EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: Some(offset.to_string()),
        normalized_utc: Some(format_utc(with_offset.with_timezone(&Utc))),
        kind: EspTimestampKind::Local,
    }
}

fn mapped_status(
    raw: EspRawStatus,
    mapping: Option<(EspNormalizedStatus, &'static str)>,
) -> EspStatus {
    let fallback_display = raw_display(&raw);
    let (normalized, display) = mapping
        .map(|(normalized, display)| (normalized, display.to_string()))
        .unwrap_or((EspNormalizedStatus::Unknown, fallback_display));
    EspStatus {
        raw,
        normalized,
        display,
        detail: None,
    }
}

fn raw_number(raw: &EspRawStatus) -> Option<i64> {
    match raw {
        EspRawStatus::Number(value) => Some(*value),
        EspRawStatus::Text(value) => value.trim().parse().ok(),
    }
}

fn raw_display(raw: &EspRawStatus) -> String {
    match raw {
        EspRawStatus::Number(value) => value.to_string(),
        EspRawStatus::Text(value) => value.clone(),
    }
}

fn v2_mapping_by_number(value: i64) -> Option<(EspNormalizedStatus, &'static str)> {
    match value {
        0 => Some((EspNormalizedStatus::NotStarted, "NotStarted")),
        1 => Some((EspNormalizedStatus::Succeeded, "Completed")),
        2 => Some((EspNormalizedStatus::Skipped, "Skipped")),
        3 => Some((EspNormalizedStatus::Uninstalled, "Uninstalled")),
        4 => Some((EspNormalizedStatus::Failed, "Failed")),
        5 => Some((EspNormalizedStatus::InProgress, "InProgress")),
        6 => Some((EspNormalizedStatus::RebootRequired, "RebootRequired")),
        7 => Some((EspNormalizedStatus::Cancelled, "Cancelled")),
        _ => None,
    }
}

fn v2_mapping_by_name(value: &str) -> Option<(EspNormalizedStatus, &'static str)> {
    if value.eq_ignore_ascii_case("NotStarted") {
        Some((EspNormalizedStatus::NotStarted, "NotStarted"))
    } else if value.eq_ignore_ascii_case("Completed") {
        Some((EspNormalizedStatus::Succeeded, "Completed"))
    } else if value.eq_ignore_ascii_case("Skipped") {
        Some((EspNormalizedStatus::Skipped, "Skipped"))
    } else if value.eq_ignore_ascii_case("Uninstalled") {
        Some((EspNormalizedStatus::Uninstalled, "Uninstalled"))
    } else if value.eq_ignore_ascii_case("Failed") {
        Some((EspNormalizedStatus::Failed, "Failed"))
    } else if value.eq_ignore_ascii_case("InProgress") {
        Some((EspNormalizedStatus::InProgress, "InProgress"))
    } else if value.eq_ignore_ascii_case("RebootRequired") {
        Some((EspNormalizedStatus::RebootRequired, "RebootRequired"))
    } else if value.eq_ignore_ascii_case("Cancelled") {
        Some((EspNormalizedStatus::Cancelled, "Cancelled"))
    } else {
        None
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_guid_window(window: &[u8]) -> bool {
    window.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-' || *byte == b'_'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

fn parse_naive_timestamp(raw: &str) -> Option<NaiveDateTime> {
    [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S%.f",
    ]
    .iter()
    .find_map(|format| NaiveDateTime::parse_from_str(raw, format).ok())
}

fn parse_fixed_offset(raw: &str) -> Option<FixedOffset> {
    if raw == "Z" || raw == "z" {
        return FixedOffset::east_opt(0);
    }
    let bytes = raw.as_bytes();
    if bytes.len() != 6 || bytes[3] != b':' {
        return None;
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hours = decimal_pair(bytes[1], bytes[2])?;
    let minutes = decimal_pair(bytes[4], bytes[5])?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
}

fn decimal_pair(first: u8, second: u8) -> Option<i32> {
    if !first.is_ascii_digit() || !second.is_ascii_digit() {
        return None;
    }
    Some(i32::from(first - b'0') * 10 + i32::from(second - b'0'))
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn unresolved_timestamp(
    raw: &str,
    kind: EspTimestampKind,
    original_offset: Option<&str>,
) -> EspTimestamp {
    EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: original_offset.map(str::to_string),
        normalized_utc: None,
        kind,
    }
}
