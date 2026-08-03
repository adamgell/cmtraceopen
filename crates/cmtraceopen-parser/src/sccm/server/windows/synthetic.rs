//! Closed grammar for the identifier vocabulary of the Windows server intake
//! contract.
//!
//! Manifest v1 admits two disjoint identifier disciplines on the fields that a
//! caller supplies verbatim and the assessment then projects:
//!
//! * A production capture (`syntheticFixture: false`) must supply opaque,
//!   domain-scoped SHA-256 handles. A 64-character digest cannot carry
//!   identity, so that discipline needs no vocabulary at all.
//! * A synthetic fixture (`syntheticFixture: true`) supplies human-readable
//!   labels, because the corpus asserts on them. Those labels are constrained
//!   by the grammar below instead.
//!
//! The grammar is closed. A label is a sequence of `-`-joined segments of
//! lowercase ASCII letters and digits, bounded in segment length, segment
//! count and total length, whose leading segment is a token the server contract
//! already declares (a catalog source-id token, a role slug, a coverage state,
//! a rotation kind, a configured-path state, or the reserved synthetic site
//! slug) and which contains at least one such token overall.
//!
//! Two properties follow, and together they are what the literal allowlists
//! this module replaced were protecting:
//!
//! 1. The character set alone excludes every Windows and Active Directory
//!    identifier shape. There is no `.` (FQDN, IPv4 address, file extension,
//!    product version), no `\`, `/` or `:` (local path, UNC share, URL), no `@`
//!    (user principal name), no `{`/`}` (braced GUID), no `$` (machine
//!    account), no `_`, no space and no uppercase letter (NetBIOS name, SAM
//!    account name, SID).
//! 2. The anchor requirement excludes free-form words. A label has to begin in
//!    the contract's own vocabulary, so a bare or hyphenated account name has
//!    nowhere to start.
//!
//! A grammar is used rather than a literal list so that the fixture corpus can
//! grow without a production-source edit (#409). The anchor vocabulary is
//! derived from the declared source catalog wherever it can be; the remaining
//! tokens mirror serde vocabularies that live in `crate::sccm::models`, and
//! `intake`'s unit tests assert that mirror stays exact.

use super::catalog::declared_server_source_catalog;

/// The reserved site code for synthetic fixtures.
///
/// This one stays a literal on purpose. A ConfigMgr site code is three
/// alphanumeric characters, so every value a grammar could admit is shaped
/// exactly like a real site code; only a reserved token is synthetic by
/// construction.
pub(super) const SYNTHETIC_SITE_CODE: &str = "LAB";

/// The reserved ConfigMgr source version for synthetic fixtures.
///
/// This is a reserved token for the same reason as the site code: a real
/// version is `5.00.<4-digit build>.<4-digit revision>`, so every value a
/// grammar could admit is shaped exactly like a shipped ConfigMgr build. The
/// reserved spelling is deliberately not one, which is what makes a synthetic
/// version impossible to confuse with a captured one.
pub(super) const SYNTHETIC_SOURCE_VERSION: &str = "5.00.TEST";

const MAX_LABEL_BYTES: usize = 64;
const MAX_SEGMENT_BYTES: usize = 16;
const MAX_LABEL_SEGMENTS: usize = 8;
const MIN_LABEL_SEGMENTS: usize = 2;

/// Anchor tokens the server contract declares outside the source catalog.
///
/// Every entry mirrors a serde vocabulary: the role path slugs, the coverage
/// states, the rotation kinds, the configured-path states, the open `unknown`
/// role and family tag, and the reserved synthetic site slug.
const CONTRACT_ANCHOR_TOKENS: &[&str] = &[
    // SccmRole
    "site",
    "server",
    "management",
    "point",
    "distribution",
    "software",
    "update",
    "wsus",
    "provider",
    "admin",
    "service",
    "client",
    "unknown",
    // SccmCoverageState
    "captured",
    "absent",
    "access",
    "denied",
    "capped",
    "skipped",
    "unsupported",
    "parse",
    "failed",
    // SccmRotation
    "current",
    "lo",
    "numbered",
    "timestamped",
    // SccmServerConfiguredPathState
    "configured",
    "default",
    "candidate",
    "not",
    "requested",
    "supplied",
    // Reserved synthetic site slug
    "lab",
];

/// Whether a single segment is a token the server contract declares.
pub(super) fn contract_anchor_token(segment: &str) -> bool {
    CONTRACT_ANCHOR_TOKENS.contains(&segment)
        || declared_server_source_catalog()
            .iter()
            .any(|spec| spec.source_id.split('-').any(|token| token == segment))
}

/// A single lowercase letter, used by fixtures that pin deterministic ordering.
///
/// One letter carries under five bits, which is not enough to name anything.
fn ordinal_segment(segment: &str) -> bool {
    segment.len() == 1 && segment.as_bytes()[0].is_ascii_lowercase()
}

/// The closed label grammar described in the module documentation.
pub(super) fn safe_contract_label(value: &str) -> bool {
    if value.len() > MAX_LABEL_BYTES {
        return false;
    }
    let segments = value.split('-').collect::<Vec<_>>();
    if !(MIN_LABEL_SEGMENTS..=MAX_LABEL_SEGMENTS).contains(&segments.len()) {
        return false;
    }
    if segments.iter().any(|segment| {
        segment.is_empty()
            || segment.len() > MAX_SEGMENT_BYTES
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return false;
    }
    let head = segments[0];
    (contract_anchor_token(head) || ordinal_segment(head))
        && segments
            .iter()
            .any(|segment| contract_anchor_token(segment))
}

/// A synthetic handle is a domain-scoped namespace over the label grammar, so
/// it cannot be confused with a production `cmtraceopen.<domain>.sha256.v1:`
/// handle or with a handle minted for a different domain.
pub(super) fn safe_synthetic_handle(value: &str, domain: &str) -> bool {
    value
        .strip_prefix(&format!("synthetic:{domain}:"))
        .is_some_and(safe_contract_label)
}

/// The public site handle a synthetic bundle projects.
pub(super) fn synthetic_site_handle() -> String {
    format!(
        "synthetic:site:{}",
        SYNTHETIC_SITE_CODE.to_ascii_lowercase()
    )
}

/// A synthetic capture host is the reserved synthetic site code, a short
/// uppercase role abbreviation and a two-digit ordinal, as in `LAB-CM01`.
///
/// The mandatory reserved prefix and the mandatory trailing ordinal are what
/// keep this from admitting a real NetBIOS computer name.
pub(super) fn safe_synthetic_capture_host(value: &str) -> bool {
    let Some(suffix) = value
        .strip_prefix(SYNTHETIC_SITE_CODE)
        .and_then(|rest| rest.strip_prefix('-'))
    else {
        return false;
    };
    let bytes = suffix.as_bytes();
    if !(4..=6).contains(&bytes.len()) {
        return false;
    }
    let (abbreviation, ordinal) = bytes.split_at(bytes.len() - 2);
    abbreviation.iter().all(u8::is_ascii_uppercase) && ordinal.iter().all(u8::is_ascii_digit)
}
