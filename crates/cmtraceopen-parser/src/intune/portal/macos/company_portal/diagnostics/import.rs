//! Member-path hygiene, enforced again inside the pure parser.
//!
//! Path traversal, absolute members, symlink targets, encrypted entries, and
//! decompression bombs are the import boundary's job: it is the code that
//! actually writes bytes to a disk, so it is the only layer that can stop a
//! `../../../..` member from landing outside the extraction directory.
//!
//! This module re-checks the paths anyway. The parser is a public API that any
//! caller can drive, a rejected member has to become *visible coverage* rather
//! than a silent drop, and "the caller already validated it" is exactly the
//! assumption that turns one careless importer into a filesystem escape. A
//! second check here costs a string scan per member.

use std::collections::BTreeMap;

use super::models::MemberPathRejection;

/// Outcome of checking one member path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPathCheck {
    /// Normalized path when accepted, the raw path verbatim when rejected.
    ///
    /// The raw path is kept on rejection because it is the evidence: a reviewer
    /// needs to see the traversal that was attempted, not a sanitized stand-in.
    pub path: String,
    pub rejection: Option<MemberPathRejection>,
}

impl MemberPathCheck {
    pub fn is_rejected(&self) -> bool {
        self.rejection.is_some()
    }
}

/// Check one container member path in isolation.
///
/// Duplicate detection needs the whole member set and lives in
/// [`check_member_paths`].
pub fn check_member_path(raw: &str) -> MemberPathCheck {
    let reject = |rejection: MemberPathRejection| MemberPathCheck {
        path: raw.to_owned(),
        rejection: Some(rejection),
    };

    if raw.trim().is_empty() {
        return reject(MemberPathRejection::EmptyPath);
    }
    if raw.chars().any(|c| c.is_control()) {
        return reject(MemberPathRejection::ControlCharacter);
    }
    // A backslash in a zip member is either a Windows separator smuggled into a
    // POSIX archive or a literal filename character, and the two are
    // indistinguishable here. Guessing wrong picks the wrong extraction target,
    // so neither guess is made.
    if raw.contains('\\') {
        return reject(MemberPathRejection::BackslashSeparator);
    }
    if is_drive_qualified(raw) {
        return reject(MemberPathRejection::DriveQualifiedPath);
    }
    if raw.starts_with('/') {
        return reject(MemberPathRejection::AbsolutePath);
    }

    let mut segments = Vec::new();
    for segment in raw.split('/') {
        // Repeated separators are collapsed rather than rejected: `a//b` is
        // unambiguous and archivers produce it routinely.
        if segment.is_empty() {
            continue;
        }
        if segment == ".." {
            return reject(MemberPathRejection::ParentTraversal);
        }
        if segment == "." {
            return reject(MemberPathRejection::CurrentDirectorySegment);
        }
        segments.push(segment);
    }

    if segments.is_empty() {
        return reject(MemberPathRejection::EmptyPath);
    }

    MemberPathCheck {
        path: segments.join("/"),
        rejection: None,
    }
}

/// Check every member path and mark collisions.
///
/// Returned in the same order as `raw_paths`.
///
/// Collisions are compared case-insensitively. macOS ships case-insensitive
/// APFS by default, so two members differing only in case extract over each
/// other, and the surviving bytes depend on extraction order rather than on
/// anything in the report. Both sides are rejected: picking one would mean
/// asserting evidence whose provenance the container does not establish.
pub fn check_member_paths<'a, I>(raw_paths: I) -> Vec<MemberPathCheck>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut checks: Vec<MemberPathCheck> = raw_paths.into_iter().map(check_member_path).collect();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for check in &checks {
        if check.is_rejected() {
            continue;
        }
        *counts.entry(check.path.to_lowercase()).or_insert(0) += 1;
    }

    for check in &mut checks {
        if check.is_rejected() {
            continue;
        }
        if counts.get(&check.path.to_lowercase()).copied().unwrap_or(0) > 1 {
            check.rejection = Some(MemberPathRejection::DuplicatePath);
        }
    }

    checks
}

/// `C:/foo` or `C:foo`: a drive-qualified path smuggled through a POSIX member.
fn is_drive_qualified(raw: &str) -> bool {
    let mut chars = raw.chars();
    match (chars.next(), chars.next()) {
        (Some(letter), Some(':')) => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_relative_path_is_accepted_and_normalized() {
        let check = check_member_path("logs//current/portal.log");
        assert_eq!(check.rejection, None);
        assert_eq!(check.path, "logs/current/portal.log");
    }

    #[test]
    fn traversal_absolute_and_drive_paths_are_rejected() {
        for (raw, expected) in [
            ("../../etc/passwd", MemberPathRejection::ParentTraversal),
            ("/etc/passwd", MemberPathRejection::AbsolutePath),
            ("C:/Windows/system32", MemberPathRejection::DriveQualifiedPath),
            ("logs\\portal.log", MemberPathRejection::BackslashSeparator),
            ("./portal.log", MemberPathRejection::CurrentDirectorySegment),
            ("", MemberPathRejection::EmptyPath),
            ("logs/port\u{7}al.log", MemberPathRejection::ControlCharacter),
        ] {
            let check = check_member_path(raw);
            assert_eq!(
                check.rejection.as_ref(),
                Some(&expected),
                "path {raw:?} must be rejected as {expected:?}"
            );
            assert_eq!(check.path, raw, "a rejected path is preserved verbatim");
        }
    }

    #[test]
    fn a_rejected_path_is_never_normalized_into_something_safe_looking() {
        // Normalizing `a/../../b` to `b` would launder a traversal into a path
        // that looks fine in the output.
        let check = check_member_path("a/../../b");
        assert_eq!(check.rejection, Some(MemberPathRejection::ParentTraversal));
    }

    #[test]
    fn case_insensitive_duplicates_reject_every_side() {
        let checks = check_member_paths(["logs/Portal.log", "logs/portal.log", "other.txt"]);
        assert_eq!(
            checks[0].rejection,
            Some(MemberPathRejection::DuplicatePath)
        );
        assert_eq!(
            checks[1].rejection,
            Some(MemberPathRejection::DuplicatePath)
        );
        assert_eq!(checks[2].rejection, None);
    }

    #[test]
    fn an_already_rejected_path_keeps_its_original_reason() {
        let checks = check_member_paths(["../a", "../a"]);
        for check in &checks {
            assert_eq!(check.rejection, Some(MemberPathRejection::ParentTraversal));
        }
    }
}
