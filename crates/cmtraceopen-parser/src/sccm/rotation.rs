use chrono::{NaiveDateTime, Timelike};

pub(super) fn is_canonical_rotation_number(value: u32) -> bool {
    value != 0
}

pub(super) fn parse_canonical_rotation_number(value: &str) -> Option<u32> {
    let first = value.as_bytes().first()?;
    if *first == b'0' || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    value
        .parse::<u32>()
        .ok()
        .filter(|value| is_canonical_rotation_number(*value))
}

/// Timestamped rotations use exactly `YYYYMMDD-HHMMSS`.
pub(super) fn is_canonical_rotation_timestamp(value: &str) -> bool {
    value.len() == "YYYYMMDD-HHMMSS".len()
        && NaiveDateTime::parse_from_str(value, "%Y%m%d-%H%M%S").is_ok_and(|timestamp| {
            timestamp.nanosecond() < 1_000_000_000
                && timestamp.format("%Y%m%d-%H%M%S").to_string() == value
        })
}
