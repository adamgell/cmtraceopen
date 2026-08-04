use std::sync::OnceLock;

use regex::Regex;

use super::catalog::SccmArtifactFamily;
use super::findings::{has_at_most_chars, MAX_SCCM_CORRELATION_KEY_VALUE_CHARS};
use super::models::{
    SccmCorrelationKey, SccmCorrelationKeyKind, SccmEvidence, SccmExtractionGap,
    SccmExtractionGapKind, SccmExtractionProfile, SccmExtractionProfileMaturity, SccmKeyConfidence,
    SccmKeyExtractionResult,
};

pub const SCCM_EXPERIMENTAL_KEY_PROFILE_ID: &str = "sccm-keys-5.00.9128-experimental-v1";
/// Exact-key authority for the committed synthetic policy fixtures only.
/// `Stable` describes this closed test corpus shape; it does not validate a
/// production ConfigMgr release.
pub const SCCM_POLICY_KEY_PROFILE_ID: &str = "policy-client-5.00.test-v1";
pub const SCCM_HIERARCHY_KEY_PROFILE_ID: &str = "sccm-hierarchy-5.00.test-stable-v1";
const EXPERIMENTAL_VERSION_PREFIX: &str = "5.00.9128.";
const POLICY_TEST_VERSION: &str = "5.00.TEST.0000";
const HIERARCHY_SYNTHETIC_VERSION: &str = "5.00.TEST";

impl SccmExtractionProfile {
    pub fn for_version(configmgr_version: Option<&str>) -> Self {
        let selected_configmgr_version = configmgr_version
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(str::to_owned);

        match selected_configmgr_version {
            Some(version)
                if is_canonical_configmgr_version(&version)
                    && version.starts_with(EXPERIMENTAL_VERSION_PREFIX) =>
            {
                Self {
                    profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
                    configmgr_version_prefixes: vec![EXPERIMENTAL_VERSION_PREFIX.to_owned()],
                    validated_artifact_families: Vec::new(),
                    selected_configmgr_version: Some(version),
                    maturity: SccmExtractionProfileMaturity::Experimental,
                }
            }
            Some(version) => Self {
                profile_id: "sccm-keys-unvalidated-version-v1".to_owned(),
                configmgr_version_prefixes: Vec::new(),
                validated_artifact_families: Vec::new(),
                selected_configmgr_version: Some(version),
                maturity: SccmExtractionProfileMaturity::Unvalidated,
            },
            None => Self {
                profile_id: "sccm-keys-version-missing-v1".to_owned(),
                configmgr_version_prefixes: Vec::new(),
                validated_artifact_families: Vec::new(),
                selected_configmgr_version: None,
                maturity: SccmExtractionProfileMaturity::Unvalidated,
            },
        }
    }

    /// Selects the centrally defined built-in version profile and binds it to
    /// the catalog family that produced one admitted raw-CCM artifact.
    ///
    /// Family binding does not validate a new extractor family. `extract_keys`
    /// independently recognizes only the executable-fixture registry below;
    /// other families remain visible through `UnvalidatedProfile` gaps.
    pub(crate) fn for_artifact_family(
        configmgr_version: Option<&str>,
        family: &SccmArtifactFamily,
    ) -> Self {
        if family == &SccmArtifactFamily::Hierarchy
            && configmgr_version.map(str::trim) == Some(HIERARCHY_SYNTHETIC_VERSION)
        {
            return Self {
                profile_id: SCCM_HIERARCHY_KEY_PROFILE_ID.to_owned(),
                configmgr_version_prefixes: vec![HIERARCHY_SYNTHETIC_VERSION.to_owned()],
                validated_artifact_families: vec![SccmArtifactFamily::Hierarchy],
                selected_configmgr_version: Some(HIERARCHY_SYNTHETIC_VERSION.to_owned()),
                maturity: SccmExtractionProfileMaturity::Stable,
            };
        }
        if configmgr_version == Some(POLICY_TEST_VERSION)
            && matches!(family, SccmArtifactFamily::ClientPolicy)
        {
            return Self {
                profile_id: SCCM_POLICY_KEY_PROFILE_ID.to_owned(),
                configmgr_version_prefixes: vec![POLICY_TEST_VERSION.to_owned()],
                validated_artifact_families: vec![SccmArtifactFamily::ClientPolicy],
                selected_configmgr_version: Some(POLICY_TEST_VERSION.to_owned()),
                maturity: SccmExtractionProfileMaturity::Stable,
            };
        }
        let mut profile = Self::for_version(configmgr_version);
        profile.validated_artifact_families = vec![family.clone()];
        profile
    }
}

struct KeyPattern {
    kind: SccmCorrelationKeyKind,
    regex: Regex,
}

#[derive(Debug)]
struct KeyCandidate<'a> {
    kind: SccmCorrelationKeyKind,
    raw: &'a str,
    start: usize,
    end: usize,
}

fn key_patterns() -> &'static [KeyPattern] {
    static CELL: OnceLock<Vec<KeyPattern>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (
                SccmCorrelationKeyKind::AssignmentId,
                r"(?i:\bassignment[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::PolicyId,
                r"(?i:\bpolicy[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::ClientGuid,
                r"(?i:\bclient[ \t]*guid)[ \t]*=[ \t]*(?P<value>(?i:guid:)?\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::PackageId,
                r"(?i:\bpackage[ \t]*id)[ \t]*=[ \t]*(?P<value>[A-Za-z0-9]{8}[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::ContentId,
                r"(?i:\bcontent[ \t]*id)[ \t]*=[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::SiteCode,
                r"(?i:\bsite[ \t]*code)[ \t]*=[ \t]*(?P<value>[A-Za-z0-9]{3}[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::ServerHost,
                r"(?i:\bserver[ \t]*host)[ \t]*=[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]*)",
            ),
            (
                SccmCorrelationKeyKind::CiId,
                r"(?i:\b(?:ci|configuration[ \t]+item)[ \t]*id)[ \t]*=[ \t]*(?P<value>[0-9]+[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::UpdateId,
                r"(?i:\bupdate[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::KbId,
                r"(?i:\b(?:kb|knowledge[ \t]+base)(?:[ \t]*id)?)[ \t]*=[ \t]*(?P<value>(?i:kb)?[0-9]+[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::BitsJobId,
                r"(?i:\bbits[ \t]*job[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::TaskSequenceExecutionId,
                r"(?i:\btask[ \t]*sequence[ \t]*execution[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::RequestId,
                r"(?i:\brequest[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::TopicId,
                r"(?i:\btopic[ \t]*id)[ \t]*=[ \t]*(?P<value>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?[A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::StateMessageId,
                r"(?i:\bstate[ \t]*message[ \t]*id)[ \t]*=[ \t]*(?P<value>[0-9]+[A-Za-z0-9_.-]*)",
            ),
        ]
        .into_iter()
        .map(|(kind, pattern)| KeyPattern {
            kind,
            regex: Regex::new(pattern).expect("SCCM key regex must compile"),
        })
        .collect()
    })
}

fn hierarchy_key_patterns() -> &'static [KeyPattern] {
    static CELL: OnceLock<Vec<KeyPattern>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (
                SccmCorrelationKeyKind::HierarchyMessageId,
                r"(?i:\bmessage[ \t]*id)[ \t]*=[ \t]*(?P<value>msg-[A-Za-z0-9][A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::HierarchyLinkId,
                r"(?i:\blink[ \t]*id)[ \t]*=[ \t]*(?P<value>link-[A-Za-z0-9][A-Za-z0-9_.-]*)",
            ),
            (
                SccmCorrelationKeyKind::SiteCode,
                r"(?i:\b(?:origin|target)[ \t]*site)[ \t]*=[ \t]*(?P<value>[A-Z]{3})",
            ),
        ]
        .into_iter()
        .map(|(kind, pattern)| KeyPattern {
            kind,
            regex: Regex::new(pattern).expect("SCCM hierarchy key regex must compile"),
        })
        .collect()
    })
}

pub fn normalize_key(kind: SccmCorrelationKeyKind, raw: &str) -> SccmCorrelationKey {
    let (normalized, confidence) = normalize_value(&kind, raw);
    SccmCorrelationKey {
        kind,
        raw: raw.to_owned(),
        normalized,
        confidence,
        extraction_profile_id: None,
        evidence: None,
        start: None,
        end: None,
    }
}

pub fn extract_keys(
    evidence: &SccmEvidence,
    profile: &SccmExtractionProfile,
) -> SccmKeyExtractionResult {
    extract_keys_with_authority(evidence, profile, false)
}

pub(crate) fn extract_admitted_keys(
    evidence: &SccmEvidence,
    profile: &SccmExtractionProfile,
) -> SccmKeyExtractionResult {
    extract_keys_with_authority(evidence, profile, true)
}

fn extract_keys_with_authority(
    evidence: &SccmEvidence,
    profile: &SccmExtractionProfile,
    admitted_profile_authority: bool,
) -> SccmKeyExtractionResult {
    let candidates = find_candidates(&evidence.message, profile);
    let mut result = SccmKeyExtractionResult {
        profile_id: profile.profile_id.clone(),
        keys: Vec::new(),
        gaps: Vec::new(),
    };

    if let Some(kind) = profile_gap_kind(profile, admitted_profile_authority) {
        if candidates.is_empty() {
            result.gaps.push(gap_for(kind, profile, evidence, None));
        } else {
            result.gaps.extend(
                candidates
                    .iter()
                    .map(|candidate| gap_for(kind.clone(), profile, evidence, Some(candidate))),
            );
        }
        return result;
    }

    let stable_policy = admitted_profile_authority && is_builtin_stable_policy(profile);
    let stable_hierarchy = is_builtin_stable_hierarchy(profile);
    if !stable_policy && !stable_hierarchy {
        result.gaps.push(gap_for(
            SccmExtractionGapKind::ExperimentalProfile,
            profile,
            evidence,
            None,
        ));
    }

    for candidate in candidates {
        let mut key = normalize_key(candidate.kind.clone(), candidate.raw);
        // A candidate that normalizes cleanly but carries an out-of-bound value
        // is as unusable as one that fails to normalize: the crate's own
        // validator rejects it, so emitting it as a key would let the producer
        // hand out keys that no longer round trip. Both weigh the same way, and
        // both stay visible as a recorded gap.
        if key.confidence != SccmKeyConfidence::Exact || !is_bounded_key_value(&key) {
            result.gaps.push(gap_for(
                SccmExtractionGapKind::MalformedCandidate,
                profile,
                evidence,
                Some(&candidate),
            ));
            continue;
        }

        key.confidence = if stable_policy || stable_hierarchy {
            SccmKeyConfidence::Exact
        } else {
            SccmKeyConfidence::Low
        };
        key.extraction_profile_id = Some(profile.profile_id.clone());
        key.evidence = Some(evidence.reference.clone());
        key.start = Some(candidate.start);
        key.end = Some(candidate.end);
        result.keys.push(key);
    }

    result
}

// The normalized value can outgrow the raw one: normalize_kb_id prepends "KB",
// so a raw that fits the bound can still normalize past it. Both are on the
// wire, so both have to clear the bound the validator applies to both.
fn is_bounded_key_value(key: &SccmCorrelationKey) -> bool {
    has_at_most_chars(&key.raw, MAX_SCCM_CORRELATION_KEY_VALUE_CHARS)
        && has_at_most_chars(&key.normalized, MAX_SCCM_CORRELATION_KEY_VALUE_CHARS)
}

fn profile_gap_kind(
    profile: &SccmExtractionProfile,
    admitted_profile_authority: bool,
) -> Option<SccmExtractionGapKind> {
    if profile.selected_configmgr_version.is_none() {
        return Some(SccmExtractionGapKind::MissingVersion);
    }

    match profile.maturity {
        SccmExtractionProfileMaturity::Unvalidated => {
            Some(SccmExtractionGapKind::UnvalidatedVersion)
        }
        SccmExtractionProfileMaturity::Experimental if is_builtin_experimental(profile) => None,
        SccmExtractionProfileMaturity::Stable
            if admitted_profile_authority && is_builtin_stable_policy(profile) =>
        {
            None
        }
        SccmExtractionProfileMaturity::Stable if is_builtin_stable_hierarchy(profile) => None,
        SccmExtractionProfileMaturity::Experimental | SccmExtractionProfileMaturity::Stable => {
            Some(SccmExtractionGapKind::UnvalidatedProfile)
        }
    }
}

fn is_builtin_stable_hierarchy(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == SCCM_HIERARCHY_KEY_PROFILE_ID
        && profile.maturity == SccmExtractionProfileMaturity::Stable
        && profile.configmgr_version_prefixes == [HIERARCHY_SYNTHETIC_VERSION]
        && profile.validated_artifact_families == [SccmArtifactFamily::Hierarchy]
        && profile.selected_configmgr_version.as_deref() == Some(HIERARCHY_SYNTHETIC_VERSION)
}

fn is_builtin_stable_policy(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == SCCM_POLICY_KEY_PROFILE_ID
        && profile.maturity == SccmExtractionProfileMaturity::Stable
        && profile.configmgr_version_prefixes == [POLICY_TEST_VERSION]
        && profile.validated_artifact_families == [SccmArtifactFamily::ClientPolicy]
        && profile.selected_configmgr_version.as_deref() == Some(POLICY_TEST_VERSION)
}

fn is_builtin_experimental(profile: &SccmExtractionProfile) -> bool {
    is_builtin_experimental_core(profile)
        // Preserve the generic public `for_version` contract without treating
        // a caller-populated family list as admission authority.
        && profile.validated_artifact_families.is_empty()
}

fn is_builtin_experimental_core(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == SCCM_EXPERIMENTAL_KEY_PROFILE_ID
        && profile.maturity == SccmExtractionProfileMaturity::Experimental
        && profile.configmgr_version_prefixes == [EXPERIMENTAL_VERSION_PREFIX]
        && profile
            .selected_configmgr_version
            .as_deref()
            .is_some_and(|version| {
                is_canonical_configmgr_version(version)
                    && version.starts_with(EXPERIMENTAL_VERSION_PREFIX)
            })
}

fn is_canonical_configmgr_version(version: &str) -> bool {
    let mut component_count = 0;
    for component in version.split('.') {
        component_count += 1;
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    component_count == 4
}

fn find_candidates<'a>(message: &'a str, profile: &SccmExtractionProfile) -> Vec<KeyCandidate<'a>> {
    let patterns = if is_builtin_stable_hierarchy(profile) {
        hierarchy_key_patterns()
    } else {
        key_patterns()
    };
    let mut candidates = patterns
        .iter()
        .flat_map(|pattern| {
            pattern.regex.captures_iter(message).filter_map(|captures| {
                let matched = captures.get(0)?;
                if !is_key_label_start(message, matched.start()) {
                    return None;
                }
                let value = captures.name("value")?;
                let raw_end = candidate_token_end(message, value.end());
                let raw = &message[value.start()..raw_end];
                let start = message[..value.start()].encode_utf16().count();
                Some(KeyCandidate {
                    kind: pattern.kind.clone(),
                    raw,
                    start,
                    end: start + raw.encode_utf16().count(),
                })
            })
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|candidate| {
        (
            candidate.start,
            key_kind_order(&candidate.kind),
            candidate.end,
        )
    });
    candidates.dedup_by(|right, left| {
        right.kind == left.kind
            && right.raw == left.raw
            && right.start == left.start
            && right.end == left.end
    });
    candidates
}

fn is_key_label_start(message: &str, label_start: usize) -> bool {
    label_start == 0
        || message[..label_start]
            .chars()
            .next_back()
            .is_some_and(is_key_token_boundary)
}

fn candidate_token_end(message: &str, captured_end: usize) -> usize {
    message[captured_end..]
        .char_indices()
        .find_map(|(offset, character)| {
            is_key_token_boundary(character).then_some(captured_end + offset)
        })
        .unwrap_or(message.len())
}

fn is_key_token_boundary(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | ';' | '&')
}

fn gap_for(
    kind: SccmExtractionGapKind,
    profile: &SccmExtractionProfile,
    evidence: &SccmEvidence,
    candidate: Option<&KeyCandidate<'_>>,
) -> SccmExtractionGap {
    SccmExtractionGap {
        kind,
        profile_id: profile.profile_id.clone(),
        selected_configmgr_version: profile.selected_configmgr_version.clone(),
        candidate_kind: candidate.map(|candidate| candidate.kind.clone()),
        candidate_raw: candidate.map(|candidate| candidate.raw.to_owned()),
        evidence: evidence.reference.clone(),
    }
}

fn normalize_value(kind: &SccmCorrelationKeyKind, raw: &str) -> (String, SccmKeyConfidence) {
    let trimmed = raw.trim();
    let normalized = match kind {
        SccmCorrelationKeyKind::AssignmentId
        | SccmCorrelationKeyKind::PolicyId
        | SccmCorrelationKeyKind::ClientGuid
        | SccmCorrelationKeyKind::UpdateId
        | SccmCorrelationKeyKind::BitsJobId
        | SccmCorrelationKeyKind::TaskSequenceExecutionId
        | SccmCorrelationKeyKind::RequestId
        | SccmCorrelationKeyKind::TopicId => normalize_guid(trimmed),
        SccmCorrelationKeyKind::PackageId => {
            is_fixed_alphanumeric(trimmed, 8).then(|| trimmed.to_ascii_uppercase())
        }
        SccmCorrelationKeyKind::ContentId => {
            is_opaque_id(trimmed).then(|| trimmed.to_ascii_lowercase())
        }
        SccmCorrelationKeyKind::SiteCode => {
            is_fixed_alphanumeric(trimmed, 3).then(|| trimmed.to_ascii_uppercase())
        }
        SccmCorrelationKeyKind::ServerHost => normalize_server_host(trimmed),
        SccmCorrelationKeyKind::CiId | SccmCorrelationKeyKind::StateMessageId => {
            normalize_decimal(trimmed)
        }
        SccmCorrelationKeyKind::KbId => normalize_kb_id(trimmed),
        SccmCorrelationKeyKind::HierarchyMessageId => normalize_prefixed_opaque_id(trimmed, "msg-"),
        SccmCorrelationKeyKind::HierarchyLinkId => normalize_prefixed_opaque_id(trimmed, "link-"),
        SccmCorrelationKeyKind::InventoryCycleId
        | SccmCorrelationKeyKind::ReportId
        | SccmCorrelationKeyKind::ComplianceCiId
        | SccmCorrelationKeyKind::BaselineId
        | SccmCorrelationKeyKind::ComplianceStateId
        | SccmCorrelationKeyKind::MeteringCycleId
        | SccmCorrelationKeyKind::RuleId => is_opaque_id(trimmed).then(|| trimmed.to_owned()),
        SccmCorrelationKeyKind::ResourceHandle => normalize_resource_handle(trimmed),
    };

    normalized.map_or_else(
        || (trimmed.to_ascii_lowercase(), SccmKeyConfidence::Low),
        |normalized| (normalized, SccmKeyConfidence::Exact),
    )
}

fn normalize_prefixed_opaque_id(value: &str, prefix: &str) -> Option<String> {
    value.strip_prefix(prefix).and_then(|suffix| {
        (!suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        .then(|| value.to_owned())
    })
}

fn normalize_guid(raw: &str) -> Option<String> {
    let without_prefix = raw
        .get(..5)
        .filter(|prefix| prefix.eq_ignore_ascii_case("guid:"))
        .map_or(raw, |_| &raw[5..]);
    let without_braces = match (
        without_prefix.strip_prefix('{'),
        without_prefix.strip_suffix('}'),
    ) {
        (Some(_), None) | (None, Some(_)) => return None,
        (Some(_), Some(_)) => &without_prefix[1..without_prefix.len() - 1],
        (None, None) => without_prefix,
    };
    let bytes = without_braces.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    valid.then(|| without_braces.to_ascii_lowercase())
}

fn is_fixed_alphanumeric(value: &str, width: usize) -> bool {
    value.len() == width && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn is_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn normalize_server_host(value: &str) -> Option<String> {
    let host = value.strip_suffix('.').unwrap_or(value);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    valid.then(|| host.to_ascii_lowercase())
}

fn normalize_decimal(value: &str) -> Option<String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let normalized = value.trim_start_matches('0');
    Some(if normalized.is_empty() {
        "0".to_owned()
    } else {
        normalized.to_owned()
    })
}

fn normalize_kb_id(value: &str) -> Option<String> {
    let digits = value
        .get(..2)
        .filter(|prefix| prefix.eq_ignore_ascii_case("kb"))
        .map_or(value, |_| &value[2..]);
    normalize_decimal(digits).map(|digits| format!("KB{digits}"))
}

fn normalize_resource_handle(value: &str) -> Option<String> {
    let valid = value.len() <= 128
        && value.starts_with("safe:")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-'));
    valid.then(|| value.to_owned())
}

fn key_kind_order(kind: &SccmCorrelationKeyKind) -> u8 {
    match kind {
        SccmCorrelationKeyKind::AssignmentId => 0,
        SccmCorrelationKeyKind::PolicyId => 1,
        SccmCorrelationKeyKind::ClientGuid => 2,
        SccmCorrelationKeyKind::PackageId => 3,
        SccmCorrelationKeyKind::ContentId => 4,
        SccmCorrelationKeyKind::SiteCode => 5,
        SccmCorrelationKeyKind::ServerHost => 6,
        SccmCorrelationKeyKind::CiId => 7,
        SccmCorrelationKeyKind::UpdateId => 8,
        SccmCorrelationKeyKind::KbId => 9,
        SccmCorrelationKeyKind::BitsJobId => 10,
        SccmCorrelationKeyKind::TaskSequenceExecutionId => 11,
        SccmCorrelationKeyKind::RequestId => 12,
        SccmCorrelationKeyKind::TopicId => 13,
        SccmCorrelationKeyKind::StateMessageId => 14,
        SccmCorrelationKeyKind::HierarchyMessageId => 15,
        SccmCorrelationKeyKind::HierarchyLinkId => 16,
        SccmCorrelationKeyKind::InventoryCycleId => 17,
        SccmCorrelationKeyKind::ReportId => 18,
        SccmCorrelationKeyKind::ResourceHandle => 19,
        SccmCorrelationKeyKind::ComplianceCiId => 20,
        SccmCorrelationKeyKind::BaselineId => 21,
        SccmCorrelationKeyKind::ComplianceStateId => 22,
        SccmCorrelationKeyKind::MeteringCycleId => 23,
        SccmCorrelationKeyKind::RuleId => 24,
    }
}
