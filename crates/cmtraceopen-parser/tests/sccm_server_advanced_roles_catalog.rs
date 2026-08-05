use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

const CARD_SCHEMA_VERSION: &str = "1.0.0";
const SOURCE_CARDS: [&str; 6] = [
    "certificate-enrollment-pki.json",
    "client-notification-bgb.json",
    "cloud-service-connection.json",
    "osd-pxe.json",
    "reporting.json",
    "sql-database-export.json",
];
const CATALOG_FIXTURES: [&str; 4] = [
    "missing-required-field",
    "redaction-required",
    "unvalidated-source",
    "valid",
];
const REQUIRED_FIELDS: [&str; 20] = [
    "cardSchemaVersion",
    "cardId",
    "cardVersion",
    "family",
    "roleScope",
    "candidateBasenames",
    "pathClasses",
    "rawParserFamily",
    "sourceVersionScope",
    "capture",
    "privacy",
    "expectedHealthyEvidence",
    "terminalFailureEvidence",
    "correlationPolicy",
    "fixtureIds",
    "ownerIssue",
    "promotion",
    "semanticPolicy",
    "nextEvidence",
    "supersession",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceCard {
    card_schema_version: String,
    card_id: String,
    card_version: String,
    family: String,
    role_scope: Vec<String>,
    candidate_basenames: Vec<String>,
    path_classes: Vec<String>,
    raw_parser_family: RawParserFamily,
    source_version_scope: SourceVersionScope,
    capture: CapturePolicy,
    privacy: PrivacyPolicy,
    expected_healthy_evidence: String,
    terminal_failure_evidence: String,
    correlation_policy: CorrelationPolicy,
    fixture_ids: Vec<String>,
    owner_issue: String,
    promotion: Promotion,
    semantic_policy: SemanticPolicy,
    next_evidence: Vec<String>,
    supersession: Supersession,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawParserFamily {
    Ccm,
    Unsupported,
    Unknown(String),
}

impl<'de> Deserialize<'de> for RawParserFamily {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "ccm" => Self::Ccm,
            "unsupported" => Self::Unsupported,
            _ => Self::Unknown(value),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceVersionScope {
    state: SourceVersionState,
    allowed_prefixes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum SourceVersionState {
    Unknown,
    Scoped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapturePolicy {
    classification: CaptureClassification,
    max_bytes: u64,
    access_policy: AccessPolicy,
    rotation_policy: RotationPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum CaptureClassification {
    Mandatory,
    Optional,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum AccessPolicy {
    LeastPrivilegeNoEscalation,
    ExplicitOperatorExport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationPolicy {
    kinds: Vec<String>,
    max_files: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivacyPolicy {
    sensitivity: PrivacySensitivity,
    classes: Vec<String>,
    redaction_required: bool,
    public_projection: Vec<String>,
    raw_sensitive_field_projection: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
enum PrivacySensitivity {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CorrelationPolicy {
    key_state: KeyState,
    allowed_key_kinds: Vec<String>,
    time_only_eligible: bool,
    topology_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum KeyState {
    Unvalidated,
    Validated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PromotionState {
    Candidate,
    Observed,
    FixtureValidated,
    RuleValidated,
    Deferred,
    Unknown(String),
}

impl<'de> Deserialize<'de> for PromotionState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "candidate" => Self::Candidate,
            "observed" => Self::Observed,
            "fixtureValidated" => Self::FixtureValidated,
            "ruleValidated" => Self::RuleValidated,
            "deferred" => Self::Deferred,
            _ => Self::Unknown(value),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Promotion {
    state: PromotionState,
    observed_evidence_ids: Vec<String>,
    implementation_issue: Option<String>,
    production_reducer: Option<String>,
    deferred_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemanticPolicy {
    capture_guidance_only: bool,
    can_create_transactions: bool,
    can_create_failure_findings: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Supersession {
    state: SupersessionState,
    supersedes: Vec<String>,
    superseded_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum SupersessionState {
    Active,
    Deprecated,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedValidation {
    schema_version: String,
    valid: bool,
    admitted_to_semantic_catalog: bool,
    issues: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct Validation {
    valid: bool,
    admitted_to_semantic_catalog: bool,
    issues: Vec<String>,
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/advanced_roles")
}

fn read_json(path: &Path) -> Value {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn load_card(path: &Path) -> Result<SourceCard, String> {
    let value = read_json(path);
    let object = value
        .as_object()
        .ok_or_else(|| "schemaDeserializeFailed:rootMustBeObject".to_owned())?;
    let missing = REQUIRED_FIELDS
        .iter()
        .find(|field| !object.contains_key(**field));
    if let Some(field) = missing {
        return Err(format!("missingField:{field}"));
    }

    serde_json::from_value(value).map_err(|error| {
        let message = error.to_string();
        if let Some(field) = message
            .strip_prefix("unknown field `")
            .and_then(|value| value.split('`').next())
        {
            format!("unknownField:{field}")
        } else {
            format!("schemaDeserializeFailed:{message}")
        }
    })
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_card_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

fn is_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_issue(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn nonempty_sorted(values: &[String]) -> bool {
    !values.is_empty()
        && is_sorted_unique(values)
        && values.iter().all(|value| !value.trim().is_empty())
}

fn is_admitted(card: &SourceCard, issues: &[String]) -> bool {
    issues.is_empty()
        && matches!(card.promotion.state, PromotionState::RuleValidated)
        && card.supersession.state == SupersessionState::Active
}

fn validate_card(card: &SourceCard) -> Validation {
    let mut issues = Vec::new();

    if card.card_schema_version != CARD_SCHEMA_VERSION {
        issues.push("schemaVersionUnsupported".to_owned());
    }
    if !is_card_id(&card.card_id) {
        issues.push("invalidCardId".to_owned());
    }
    if !is_version(&card.card_version) {
        issues.push("invalidCardVersion".to_owned());
    }
    if card.family.trim().len() < 12 {
        issues.push("familyDescriptionTooShort".to_owned());
    }
    if !nonempty_sorted(&card.role_scope) {
        issues.push("roleScopeMustBeSortedUnique".to_owned());
    }
    if !nonempty_sorted(&card.candidate_basenames)
        || card.candidate_basenames.iter().any(|basename| {
            basename.contains(['/', '\\', '*'])
                || basename == "."
                || basename == ".."
                || basename.trim() != basename
        })
    {
        issues.push("candidateBasenamesInvalid".to_owned());
    }
    if !nonempty_sorted(&card.path_classes) {
        issues.push("pathClassesMustBeSortedUnique".to_owned());
    }
    if let RawParserFamily::Unknown(_) = &card.raw_parser_family {
        issues.push("unknownRawParserFamily".to_owned());
    }
    match card.source_version_scope.state {
        SourceVersionState::Unknown if !card.source_version_scope.allowed_prefixes.is_empty() => {
            issues.push("unknownVersionCannotDeclarePrefixes".to_owned());
        }
        SourceVersionState::Scoped
            if !nonempty_sorted(&card.source_version_scope.allowed_prefixes) =>
        {
            issues.push("scopedVersionRequiresSortedPrefixes".to_owned());
        }
        _ => {}
    }
    if card.capture.max_bytes == 0 || card.capture.max_bytes > 16 * 1024 * 1024 {
        issues.push("captureMaxBytesOutOfRange".to_owned());
    }
    let allowed_rotation_kinds = ["current", "lo_", "snapshot", "timestamped"];
    if !nonempty_sorted(&card.capture.rotation_policy.kinds)
        || card
            .capture
            .rotation_policy
            .kinds
            .iter()
            .any(|kind| !allowed_rotation_kinds.contains(&kind.as_str()))
        || card.capture.rotation_policy.max_files == 0
        || card.capture.rotation_policy.max_files > 4
    {
        issues.push("rotationPolicyInvalid".to_owned());
    }
    if !is_sorted_unique(&card.privacy.classes) || !nonempty_sorted(&card.privacy.public_projection)
    {
        issues.push("privacyClassesOrProjectionUnsorted".to_owned());
    }
    let allowed_public_projection = ["captureState", "cardId", "coverageState", "roleScope"];
    if card
        .privacy
        .public_projection
        .iter()
        .any(|field| !allowed_public_projection.contains(&field.as_str()))
    {
        issues.push("unsafePublicProjection".to_owned());
    }
    if (!card.privacy.classes.is_empty() || card.privacy.sensitivity >= PrivacySensitivity::Medium)
        && !card.privacy.redaction_required
    {
        issues.push("redactionRequired".to_owned());
    }
    if !card.privacy.raw_sensitive_field_projection.is_empty() {
        issues.push("rawSensitiveProjectionForbidden".to_owned());
    }
    let descriptions = [
        &card.expected_healthy_evidence,
        &card.terminal_failure_evidence,
    ];
    if descriptions.iter().any(|description| {
        description.trim().len() < 40
            || description
                .to_ascii_lowercase()
                .contains("parse log and identify errors")
    }) {
        issues.push("evidenceDescriptionNotSpecific".to_owned());
    }
    if card.correlation_policy.time_only_eligible {
        issues.push("timeOnlyCorrelationForbidden".to_owned());
    }
    if !card.correlation_policy.topology_required {
        issues.push("topologyRequirementMissing".to_owned());
    }
    if card.correlation_policy.key_state == KeyState::Unvalidated
        && !card.correlation_policy.allowed_key_kinds.is_empty()
    {
        issues.push("unvalidatedKeysCannotBeDeclared".to_owned());
    }
    if card.correlation_policy.key_state == KeyState::Validated
        && !nonempty_sorted(&card.correlation_policy.allowed_key_kinds)
    {
        issues.push("validatedKeysMustBeSorted".to_owned());
    }
    if !is_issue(&card.owner_issue) {
        issues.push("ownerIssueInvalid".to_owned());
    }
    if !is_sorted_unique(&card.fixture_ids) {
        issues.push("fixtureIdsMustBeSortedUnique".to_owned());
    }
    if !is_sorted_unique(&card.promotion.observed_evidence_ids) {
        issues.push("observedEvidenceIdsMustBeSortedUnique".to_owned());
    }
    if card.next_evidence.is_empty() || card.next_evidence.iter().any(|item| item.trim().len() < 30)
    {
        issues.push("nextEvidenceNotSpecific".to_owned());
    }
    if !is_sorted_unique(&card.supersession.supersedes) {
        issues.push("supersedesMustBeSortedUnique".to_owned());
    }
    match card.supersession.state {
        SupersessionState::Active if card.supersession.superseded_by.is_some() => {
            issues.push("activeCardCannotBeSuperseded".to_owned());
        }
        SupersessionState::Deprecated
            if card
                .supersession
                .superseded_by
                .as_deref()
                .is_none_or(str::is_empty) =>
        {
            issues.push("deprecatedCardRequiresSuccessor".to_owned());
        }
        SupersessionState::Deprecated
            if card
                .supersession
                .superseded_by
                .as_deref()
                .is_some_and(|successor| !is_card_id(successor) || successor == card.card_id) =>
        {
            issues.push("supersessionSuccessorInvalid".to_owned());
        }
        _ => {}
    }

    match &card.promotion.state {
        PromotionState::Candidate => {
            if !card.promotion.observed_evidence_ids.is_empty()
                || card.promotion.implementation_issue.is_some()
                || card.promotion.production_reducer.is_some()
                || card.promotion.deferred_reason.is_some()
            {
                issues.push("candidateMetadataInvalid".to_owned());
            }
        }
        PromotionState::Observed => {
            if card.promotion.observed_evidence_ids.is_empty()
                || card.promotion.implementation_issue.is_some()
                || card.promotion.production_reducer.is_some()
                || card.promotion.deferred_reason.is_some()
            {
                issues.push("observedMetadataInvalid".to_owned());
            }
        }
        PromotionState::FixtureValidated => {
            if card.promotion.observed_evidence_ids.is_empty()
                || card.fixture_ids.is_empty()
                || card.promotion.implementation_issue.is_some()
                || card.promotion.production_reducer.is_some()
                || card.promotion.deferred_reason.is_some()
            {
                issues.push("fixtureValidatedMetadataInvalid".to_owned());
            }
        }
        PromotionState::RuleValidated => {
            if card.promotion.observed_evidence_ids.is_empty()
                || card.fixture_ids.is_empty()
                || card
                    .promotion
                    .implementation_issue
                    .as_deref()
                    .is_none_or(|issue| !is_issue(issue))
                || card
                    .promotion
                    .production_reducer
                    .as_deref()
                    .is_none_or(str::is_empty)
                || card.promotion.deferred_reason.is_some()
                || card.raw_parser_family != RawParserFamily::Ccm
                || card.source_version_scope.state != SourceVersionState::Scoped
            {
                issues.push("ruleValidatedMetadataInvalid".to_owned());
            }
        }
        PromotionState::Deferred => {
            if card
                .promotion
                .deferred_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().len() < 30)
                || card.promotion.production_reducer.is_some()
                || card.promotion.implementation_issue.is_some()
            {
                issues.push("deferredMetadataInvalid".to_owned());
            }
        }
        PromotionState::Unknown(_) => issues.push("unknownPromotionState".to_owned()),
    }
    if matches!(card.promotion.state, PromotionState::RuleValidated)
        && (card.correlation_policy.key_state != KeyState::Validated
            || !nonempty_sorted(&card.correlation_policy.allowed_key_kinds))
    {
        issues.push("ruleValidatedKeyPolicyInvalid".to_owned());
    }

    let guidance_only = matches!(
        card.promotion.state,
        PromotionState::Candidate
            | PromotionState::Observed
            | PromotionState::FixtureValidated
            | PromotionState::Deferred
    );
    if guidance_only
        && (!card.semantic_policy.capture_guidance_only
            || card.semantic_policy.can_create_transactions
            || card.semantic_policy.can_create_failure_findings)
    {
        issues.push("unvalidatedSourceCannotDiagnose".to_owned());
    }
    if matches!(card.promotion.state, PromotionState::RuleValidated)
        && (card.semantic_policy.capture_guidance_only
            || !card.semantic_policy.can_create_transactions)
    {
        issues.push("ruleValidatedSemanticPolicyInvalid".to_owned());
    }

    issues.sort();
    issues.dedup();
    let admitted_to_semantic_catalog = is_admitted(card, &issues);
    Validation {
        valid: issues.is_empty(),
        admitted_to_semantic_catalog,
        issues,
    }
}

fn validate_card_with_inventory(card: &SourceCard, inventory: &BTreeSet<String>) -> Validation {
    let mut validation = validate_card(card);
    if card.supersession.state == SupersessionState::Deprecated
        && card
            .supersession
            .superseded_by
            .as_ref()
            .is_some_and(|successor| !inventory.contains(successor))
    {
        validation
            .issues
            .push("supersessionSuccessorMissing".to_owned());
    }
    if card
        .supersession
        .supersedes
        .iter()
        .any(|predecessor| !is_card_id(predecessor) || !inventory.contains(predecessor))
    {
        validation
            .issues
            .push("supersededPredecessorMissing".to_owned());
    }
    validation.issues.sort();
    validation.issues.dedup();
    validation.valid = validation.issues.is_empty();
    validation.admitted_to_semantic_catalog = is_admitted(card, &validation.issues);
    validation
}

fn validate_catalog(cards: &[SourceCard]) -> Vec<Validation> {
    let inventory = cards
        .iter()
        .map(|card| card.card_id.clone())
        .collect::<BTreeSet<_>>();
    let cycle_members = supersession_cycle_members(cards);
    cards
        .iter()
        .map(|card| {
            let mut validation = validate_card_with_inventory(card, &inventory);
            if cycle_members.contains(&card.card_id) {
                validation
                    .issues
                    .push("supersessionCycleDetected".to_owned());
                validation.issues.sort();
                validation.issues.dedup();
                validation.valid = false;
                validation.admitted_to_semantic_catalog = false;
            }
            validation
        })
        .collect()
}

fn supersession_cycle_members(cards: &[SourceCard]) -> BTreeSet<String> {
    let mut graph = cards
        .iter()
        .map(|card| (card.card_id.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();

    for card in cards {
        if let Some(successor) = &card.supersession.superseded_by {
            graph
                .entry(card.card_id.clone())
                .or_default()
                .push(successor.clone());
        }
        for predecessor in &card.supersession.supersedes {
            graph
                .entry(predecessor.clone())
                .or_default()
                .push(card.card_id.clone());
        }
    }

    cards
        .iter()
        .filter(|card| {
            supersession_cycle_reaches(&card.card_id, &card.card_id, &graph, &mut BTreeSet::new())
        })
        .map(|card| card.card_id.clone())
        .collect()
}

fn supersession_cycle_reaches(
    origin: &str,
    current: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
) -> bool {
    graph.get(current).is_some_and(|targets| {
        targets.iter().any(|target| {
            if target == origin {
                return true;
            }
            if !visited.insert(target.clone()) {
                return false;
            }
            let reaches_origin = supersession_cycle_reaches(origin, target, graph, visited);
            visited.remove(target);
            reaches_origin
        })
    })
}

fn validate_path(path: &Path) -> Validation {
    match load_card(path) {
        Ok(card) => validate_card(&card),
        Err(issue) => Validation {
            valid: false,
            admitted_to_semantic_catalog: false,
            issues: vec![issue],
        },
    }
}

#[test]
fn advanced_role_source_card_inventory_is_exact_and_sorted() {
    let root = corpus_root().join("source-cards");
    let actual = fs::read_dir(&root)
        .expect("advanced-role source-card root exists")
        .map(|entry| {
            entry
                .expect("source-card entry is readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<BTreeSet<_>>();
    let expected = SOURCE_CARDS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn candidate_catalog_is_typed_private_and_not_semantically_admitted() {
    let root = corpus_root().join("source-cards");
    let cards = SOURCE_CARDS
        .iter()
        .map(|filename| {
            load_card(&root.join(filename)).unwrap_or_else(|error| panic!("{filename}: {error}"))
        })
        .collect::<Vec<_>>();
    let inventory = cards
        .iter()
        .map(|card| card.card_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        inventory.len(),
        cards.len(),
        "source-card IDs must be unique"
    );
    let validations = validate_catalog(&cards);
    let mut card_ids = Vec::new();
    for ((filename, card), validation) in SOURCE_CARDS.into_iter().zip(cards).zip(validations) {
        assert!(
            validation.valid,
            "{filename}: {}",
            validation.issues.join(", ")
        );
        assert!(
            !validation.admitted_to_semantic_catalog,
            "{filename}: prep-only source cards cannot enter semantic analyzers"
        );
        assert!(
            matches!(
                card.promotion.state,
                PromotionState::Candidate | PromotionState::Deferred
            ),
            "{filename}: no lab-observed or rule-validated evidence exists"
        );
        assert!(card.semantic_policy.capture_guidance_only);
        assert!(!card.semantic_policy.can_create_transactions);
        assert!(!card.semantic_policy.can_create_failure_findings);
        card_ids.push(card.card_id);
    }
    assert!(
        is_sorted_unique(&card_ids),
        "source-card filenames must yield a deterministic card-id order"
    );
}

#[test]
fn catalog_fixture_matrix_has_exact_deterministic_admission_results() {
    let root = corpus_root().join("catalog-fixtures");
    let actual = fs::read_dir(&root)
        .expect("advanced-role catalog-fixture root exists")
        .map(|entry| {
            entry
                .expect("catalog-fixture entry is readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<BTreeSet<_>>();
    let expected_names = CATALOG_FIXTURES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected_names);

    for fixture in CATALOG_FIXTURES {
        let fixture_root = root.join(fixture);
        let actual = validate_path(&fixture_root.join("source-card.json"));
        let expected: ExpectedValidation =
            serde_json::from_value(read_json(&fixture_root.join("expected.json")))
                .unwrap_or_else(|error| panic!("{fixture}: expected result is typed: {error}"));
        assert_eq!(expected.schema_version, CARD_SCHEMA_VERSION);
        assert_eq!(
            actual,
            Validation {
                valid: expected.valid,
                admitted_to_semantic_catalog: expected.admitted_to_semantic_catalog,
                issues: expected.issues,
            },
            "{fixture}"
        );
    }
}

#[test]
fn unknown_parser_and_promotion_values_are_preserved_then_rejected() {
    let path = corpus_root()
        .join("catalog-fixtures/valid")
        .join("source-card.json");
    let mut value = read_json(&path);
    value["rawParserFamily"] = Value::String("future-binary-parser".to_owned());
    value["promotion"]["state"] = Value::String("futurePromotion".to_owned());
    let card: SourceCard =
        serde_json::from_value(value).expect("unknown values remain inspectable card data");
    assert_eq!(
        card.raw_parser_family,
        RawParserFamily::Unknown("future-binary-parser".to_owned())
    );
    assert_eq!(
        card.promotion.state,
        PromotionState::Unknown("futurePromotion".to_owned())
    );
    let validation = validate_card(&card);
    assert_eq!(
        validation.issues,
        ["unknownPromotionState", "unknownRawParserFamily"]
    );
    assert!(!validation.admitted_to_semantic_catalog);
}

#[test]
fn deprecation_requires_an_explicit_successor_and_never_panics() {
    let path = corpus_root()
        .join("catalog-fixtures/valid")
        .join("source-card.json");
    let mut card = load_card(&path).expect("valid fixture loads");
    card.supersession.state = SupersessionState::Deprecated;
    let invalid = validate_card(&card);
    assert!(invalid
        .issues
        .contains(&"deprecatedCardRequiresSuccessor".to_owned()));

    card.source_version_scope.state = SourceVersionState::Scoped;
    card.source_version_scope.allowed_prefixes = vec!["5.00.".to_owned()];
    card.correlation_policy.key_state = KeyState::Validated;
    card.correlation_policy.allowed_key_kinds = vec!["requestId".to_owned()];
    card.fixture_ids = vec!["advanced-role-rule-success".to_owned()];
    card.promotion.state = PromotionState::RuleValidated;
    card.promotion.observed_evidence_ids = vec!["sanitized-lab-role-path-version-001".to_owned()];
    card.promotion.implementation_issue = Some("#400".to_owned());
    card.promotion.production_reducer = Some("sccm.server.synthetic.reduce".to_owned());
    card.semantic_policy.capture_guidance_only = false;
    card.semantic_policy.can_create_transactions = true;
    card.semantic_policy.can_create_failure_findings = true;
    card.supersession.superseded_by = Some("missing-successor".to_owned());
    let inventory = [card.card_id.clone()].into_iter().collect();
    let dangling = validate_card_with_inventory(&card, &inventory);
    assert!(dangling
        .issues
        .contains(&"supersessionSuccessorMissing".to_owned()));
    assert!(!dangling.admitted_to_semantic_catalog);

    card.supersession.superseded_by = Some("advanced-role-successor".to_owned());
    let inventory = [card.card_id.clone(), "advanced-role-successor".to_owned()]
        .into_iter()
        .collect();
    let valid = validate_card_with_inventory(&card, &inventory);
    assert!(!valid
        .issues
        .contains(&"supersessionSuccessorMissing".to_owned()));
    assert!(valid.valid, "an existing successor keeps the card valid");
    assert!(
        !valid.admitted_to_semantic_catalog,
        "deprecation metadata cannot admit even a RuleValidated source"
    );

    card.supersession.supersedes = vec!["advanced-role-predecessor".to_owned()];
    let dangling_predecessor = validate_card_with_inventory(&card, &inventory);
    assert_eq!(
        dangling_predecessor.issues,
        ["supersededPredecessorMissing"],
        "a supersedes entry must resolve against the catalog inventory"
    );
    assert!(!dangling_predecessor.admitted_to_semantic_catalog);

    let inventory = [
        card.card_id.clone(),
        "advanced-role-predecessor".to_owned(),
        "advanced-role-successor".to_owned(),
    ]
    .into_iter()
    .collect();
    let resolved = validate_card_with_inventory(&card, &inventory);
    assert!(
        resolved.valid,
        "a supersedes entry present in the catalog keeps the card valid"
    );
}

#[test]
fn supersession_self_references_and_cycles_fail_closed() {
    let path = corpus_root()
        .join("catalog-fixtures/valid")
        .join("source-card.json");
    let mut self_referential = load_card(&path).expect("valid fixture loads");
    self_referential.supersession.supersedes = vec![self_referential.card_id.clone()];
    let self_validation = validate_catalog(&[self_referential]);
    assert_eq!(self_validation[0].issues, ["supersessionCycleDetected"]);
    assert!(!self_validation[0].admitted_to_semantic_catalog);

    let mut alpha = load_card(&path).expect("valid fixture loads");
    alpha.card_id = "alpha-card".to_owned();
    alpha.supersession.supersedes = vec!["bravo-card".to_owned()];
    let mut bravo = load_card(&path).expect("valid fixture loads");
    bravo.card_id = "bravo-card".to_owned();
    bravo.supersession.supersedes = vec!["charlie-card".to_owned()];
    let mut charlie = load_card(&path).expect("valid fixture loads");
    charlie.card_id = "charlie-card".to_owned();
    charlie.supersession.supersedes = vec!["alpha-card".to_owned()];

    let cycle_validations = validate_catalog(&[alpha, bravo, charlie]);
    assert!(cycle_validations.iter().all(|validation| {
        validation.issues == ["supersessionCycleDetected"]
            && !validation.admitted_to_semantic_catalog
    }));

    let mut predecessor = load_card(&path).expect("valid fixture loads");
    predecessor.card_id = "predecessor-card".to_owned();
    predecessor.supersession.state = SupersessionState::Deprecated;
    predecessor.supersession.superseded_by = Some("successor-card".to_owned());
    let mut successor = load_card(&path).expect("valid fixture loads");
    successor.card_id = "successor-card".to_owned();
    successor.supersession.supersedes = vec!["predecessor-card".to_owned()];

    let reciprocal_validations = validate_catalog(&[predecessor, successor]);
    assert!(reciprocal_validations
        .iter()
        .all(|validation| validation.valid));
}

#[test]
fn only_a_fully_linked_rule_validated_card_is_semantically_admitted() {
    let path = corpus_root()
        .join("catalog-fixtures/valid")
        .join("source-card.json");
    let mut card = load_card(&path).expect("valid fixture loads");
    card.source_version_scope.state = SourceVersionState::Scoped;
    card.source_version_scope.allowed_prefixes = vec!["5.00.".to_owned()];
    card.correlation_policy.key_state = KeyState::Validated;
    card.correlation_policy.allowed_key_kinds = vec!["requestId".to_owned()];
    card.fixture_ids = vec!["advanced-role-rule-success".to_owned()];
    card.promotion.state = PromotionState::RuleValidated;
    card.promotion.observed_evidence_ids = vec!["sanitized-lab-role-path-version-001".to_owned()];
    card.promotion.implementation_issue = Some("#400".to_owned());
    card.promotion.production_reducer = Some("sccm.server.synthetic.reduce".to_owned());
    card.semantic_policy.capture_guidance_only = false;
    card.semantic_policy.can_create_transactions = true;
    card.semantic_policy.can_create_failure_findings = true;

    let admitted = validate_card(&card);
    assert_eq!(
        admitted,
        Validation {
            valid: true,
            admitted_to_semantic_catalog: true,
            issues: Vec::new(),
        }
    );

    card.promotion.implementation_issue = None;
    let blocked = validate_card(&card);
    assert_eq!(blocked.issues, ["ruleValidatedMetadataInvalid"]);
    assert!(!blocked.admitted_to_semantic_catalog);

    card.promotion.implementation_issue = Some("#400".to_owned());
    card.correlation_policy.key_state = KeyState::Unvalidated;
    card.correlation_policy.allowed_key_kinds.clear();
    let unvalidated_key = validate_card(&card);
    assert_eq!(unvalidated_key.issues, ["ruleValidatedKeyPolicyInvalid"]);
    assert!(!unvalidated_key.admitted_to_semantic_catalog);
}
