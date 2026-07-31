//! Rotation-member identification and ordering.
//!
//! Company Portal keeps the live file as `CompanyPortal.log` and older members
//! as `CompanyPortal-<n>.log` or `CompanyPortal.log.<n>`, where a higher `<n>`
//! is older. Ordering is derived from the file name only; the crate never reads
//! the filesystem.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{PortalLogParse, PortalRotationMember};
use crate::models::log_entry::LogEntry;

fn rotation_suffix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)^CompanyPortal(?:[-_.](\d+)\.log|\.log\.(\d+)|\.log)$")
            .expect("Company Portal rotation pattern must compile")
    })
}

/// Extract the file name from a caller-supplied path (POSIX or Windows).
pub fn file_name_from_path(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
}

/// Classify a file name as a rotation member.
pub fn rotation_member_from_file_name(file_name: &str) -> PortalRotationMember {
    let Some(caps) = rotation_suffix_re().captures(file_name) else {
        return PortalRotationMember {
            file_name: Some(file_name.to_string()),
            rotation_index: None,
            is_current: false,
        };
    };

    // `is_current` comes from the *absence* of a digit group, not from the
    // parsed value. The digit group is unbounded, so `CompanyPortal-99999999999.log`
    // overflows `u32`; deriving currency from `index == 0` after an
    // `unwrap_or(0)` would mark that old member as the live file and sort it
    // newest. A digit group that will not parse still means "not the live file",
    // and an absurdly large index is definitionally very old, so it saturates to
    // `u32::MAX` and sorts oldest.
    let digits = caps.get(1).or_else(|| caps.get(2));
    let (rotation_index, is_current) = match digits {
        None => (0, true),
        Some(matched) => (matched.as_str().parse::<u32>().unwrap_or(u32::MAX), false),
    };

    PortalRotationMember {
        file_name: Some(file_name.to_string()),
        rotation_index: Some(rotation_index),
        is_current,
    }
}

/// Classify a rotation member from a full path.
pub fn rotation_member_from_path(path: &str) -> PortalRotationMember {
    match file_name_from_path(path) {
        Some(name) => rotation_member_from_file_name(name),
        None => PortalRotationMember {
            file_name: None,
            rotation_index: None,
            is_current: false,
        },
    }
}

/// Sort key placing the oldest rotation member first. Unrecognized members sort
/// last, with the file name as a deterministic tie-breaker.
fn oldest_first_key(member: &PortalRotationMember) -> (u8, i64, String) {
    match member.rotation_index {
        Some(index) => (
            0,
            -(index as i64),
            member.file_name.clone().unwrap_or_default(),
        ),
        None => (1, 0, member.file_name.clone().unwrap_or_default()),
    }
}

/// Order rotation members oldest first (highest rotation index first).
pub fn order_rotation_members_oldest_first(
    members: &[PortalRotationMember],
) -> Vec<PortalRotationMember> {
    let mut ordered = members.to_vec();
    ordered.sort_by_key(oldest_first_key);
    ordered
}

/// Merge parsed rotation members into one entry list, oldest member first.
///
/// The ordering is by rotation index only. This function never reads
/// `entry.timestamp`, so the result is **not** guaranteed to be chronological:
/// members whose file name is not a recognized rotation form sort last no matter
/// what their records say, and records already out of order inside a single file
/// stay out of order. Callers that need true chronological order must sort by
/// timestamp themselves. Entries keep their within-file order and `id` is
/// reassigned sequentially across the merged set.
pub fn merge_rotated_log_entries(parses: &[PortalLogParse]) -> Vec<LogEntry> {
    let mut ordered: Vec<&PortalLogParse> = parses.iter().collect();
    ordered.sort_by_key(|parse| oldest_first_key(&parse.rotation));

    let mut merged = Vec::new();
    for parse in ordered {
        merged.extend(super::parse::to_log_entries(parse));
    }
    for (index, entry) in merged.iter_mut().enumerate() {
        entry.id = index as u64;
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_rotation_members() {
        let current =
            rotation_member_from_path("/Users/x/Library/Logs/CompanyPortal/CompanyPortal.log");
        assert_eq!(current.rotation_index, Some(0));
        assert!(current.is_current);

        let older = rotation_member_from_file_name("CompanyPortal-2.log");
        assert_eq!(older.rotation_index, Some(2));
        assert!(!older.is_current);

        let alt = rotation_member_from_file_name("CompanyPortal.log.3");
        assert_eq!(alt.rotation_index, Some(3));

        let foreign = rotation_member_from_file_name("IntuneMdmAgent.log");
        assert_eq!(foreign.rotation_index, None);
        assert!(!foreign.is_current);
    }

    #[test]
    fn orders_oldest_first() {
        let members = vec![
            rotation_member_from_file_name("CompanyPortal.log"),
            rotation_member_from_file_name("CompanyPortal-2.log"),
            rotation_member_from_file_name("CompanyPortal-1.log"),
            rotation_member_from_file_name("stray.txt"),
        ];
        let ordered = order_rotation_members_oldest_first(&members);
        let names: Vec<&str> = ordered
            .iter()
            .map(|m| m.file_name.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(
            names,
            vec![
                "CompanyPortal-2.log",
                "CompanyPortal-1.log",
                "CompanyPortal.log",
                "stray.txt"
            ]
        );
    }
}
