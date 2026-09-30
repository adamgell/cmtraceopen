//! Deterministic privacy projection for the Autopilot snapshot.
//!
//! Autopilot evidence is unusually identity-dense: serial numbers, hardware
//! hashes, tenant domains, device names, and UPNs are the *subject* of the
//! analysis rather than incidental. A projection that simply dropped them would
//! destroy the diagnosis; one that dropped nothing would make the export
//! unshareable.
//!
//! So every masked value becomes a stable token derived only from the value
//! itself. Two records that named the same device still visibly name the same
//! device, and an explicit Autopilot-to-ESP correlation key still matches its
//! ESP counterpart after masking. Masking is idempotent: a token cannot itself
//! match a rule.
//!
//! # What survives, and why
//!
//! Tenant *object* identifiers survive in the clear: the Autopilot profile id,
//! the enrollment id, the correlation id, the activity id, and the ESP session
//! id. Those are the entire reason an export is shareable -- without them the
//! reader cannot line the export up against Intune or against the sibling ESP
//! analysis, and none of them describes a person or a machine.
//!
//! *Device and user* identity does not survive: serial number, hardware hash,
//! product key, ZTD id, Entra and managed device ids, tenant id and domain,
//! device name, user principal name, and the admin-authored profile name.
//! `entraDeviceId` is both device identity and a correlation key, which is
//! exactly why masking is deterministic rather than destructive.
//!
//! Every whole-value mask is computed over one canonical form of the value --
//! trimmed and case-folded, Unicode-aware -- under a single token kind, so the
//! same identifier masks identically no matter which field, which casing, or
//! which non-ASCII spelling it arrived in.
//!
//! Free narrative is not left out of that. A bare serial, a bare DNS domain,
//! and a bare host name carry no shape any pattern could recognize, so the
//! projection collects the literal values it is about to mask and scrubs them
//! out of every free-text field, leaving the very token the typed field
//! carries in their place. A value that *does* have a shape -- a UPN, a long
//! opaque blob -- is consumed by a shaped rule before the scrub ever runs, so
//! that rule resolves a value the export masks to that same typed token instead
//! of minting a second one. Two records naming one device therefore still read
//! as one device after the export.
//!
//! The hash is deliberately non-cryptographic and unsalted. It exists to make
//! equal values look equal across an export, not to resist an attacker who
//! already knows the serial number they are looking for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use crate::intune::apps::windows::common::{
    caseless_key, find_ignore_case, fold_with_offsets, FoldedChar,
};
use crate::intune::evidence::{IntuneFinding, IntuneNamedValue};

use super::models::*;

/// Named-data and report-value keys whose values are masked in an export.
///
/// Deliberately excludes `profileId`, `enrollmentId`, `correlationId`,
/// `activityId`, and `espSessionId`; see the module docs.
const SENSITIVE_VALUE_KEYS: [&str; 12] = [
    "serialNumber",
    "hardwareHash",
    "productKeyId",
    "ztdRegistrationId",
    "entraDeviceId",
    "managedDeviceId",
    "tenantId",
    "tenantDomain",
    "deviceName",
    "userPrincipalName",
    "upn",
    "profileName",
];

/// The single token kind used for every whole-value mask.
///
/// One kind rather than one per field is what makes a masked `serialNumber`
/// visibly equal to the same serial masked inside a record's named data. The
/// field name already says what the value was, so a per-field kind bought
/// nothing and cost cross-field equality.
const VALUE_KIND: &str = "redacted";

/// Shortest masked value that is scrubbed out of free text.
///
/// Firmware routinely reports junk serials ("0", "N/A", "None"). A value that
/// short cannot be told apart from an ordinary word or number once it sits
/// unlabelled in narrative, so scrubbing it would mangle readable evidence
/// without protecting anything. The floor stays below the seven characters of
/// a Dell service tag, so real serials are still covered.
const MIN_SCRUBBED_LITERAL_BYTES: usize = 6;

/// The floor for a value the field itself declares to be an identity.
///
/// A value read from an identity field is short because the identity is short,
/// not because it might be prose, so the prose floor does not describe it and
/// applying it there masked the typed field while leaving the same value in
/// narrative. #646 drew this line for the DsRegCmd leaf and #667 implemented it.
///
/// The trade is deliberate and it is paid in narrative: a four-byte device name
/// can also be an ordinary word, and scrubbing it mangles readable evidence
/// wherever that word appears. A display name keeps the prose floor for exactly
/// that reason.
const MIN_SCRUBBED_IDENTIFIER_BYTES: usize = 4;

/// FNV-1a, stable across runs, platforms, and process restarts, which
/// `DefaultHasher` explicitly is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{hash:016x}]")
}

/// Mask one whole value, normalizing case and surrounding space first so the
/// same identifier always produces the same token.
///
/// The canonical form is the grammar's [`caseless_key`], not `to_lowercase`: an
/// identity can carry a non-ASCII letter, and lowercasing alone does not fold
/// every pair the lane's own matching treats as one. `Σ` lowercases to `σ` while
/// final `ς` keeps its own shape, so a device spelled one way in a typed field
/// and the other way in a log line minted two tokens for one device. This is the
/// same key the literal table files a value under, so a typed value and every
/// caseless spelling of it cannot end up with two tokens.
fn mask_value(value: &str) -> String {
    if is_token(value) {
        return value.to_owned();
    }
    stable_token(VALUE_KIND, &caseless_key(value.trim()))
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("upn regex must compile")
    })
}

/// The profile segment of a user path, in either slash direction.
///
/// The leading `[` exclusion is what keeps the projection idempotent: an
/// already-masked `[user:…]` segment must not be masked a second time.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>[\\/]Users[\\/])(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)")
            .expect("user path regex must compile")
    })
}

/// A hardware hash or similar long opaque blob embedded in free text.
///
/// Bounded at 40 characters so a GUID (32 hex digits plus dashes, matched in
/// runs of at most 12) and an eight-digit HRESULT are both left readable; those
/// are diagnostic grammar, not identity.
///
/// No `\b` anchors. The Base64 alphabet includes `=`, `+`, and `/`, none of
/// which is a word character, so a trailing `\b` could not close a match on a
/// padded or punctuation-terminated hash and left its tail exposed. The match
/// is greedy and leftmost, so it consumes the whole contiguous Base64 run
/// wherever a >=40 run exists -- exactly the whole hash -- while the >=40 bound
/// still excludes the 36-char GUID (dashes break it into <=12-char runs) and
/// the short HRESULT. The `[blob:…]` token this produces contains `[`, `:`, and
/// `]`, which are outside the alphabet, so a token can never re-match: the
/// projection stays idempotent.
fn opaque_blob_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=]{40,}").expect("opaque blob regex must compile"))
}

/// Mask the sensitive spans inside a free-text value.
///
/// Shaped rules only, so this is also the entry point for a caller with no
/// snapshot to read masked literals from. Inside an export,
/// [`redact_export_text`] is the entry point that additionally scrubs those
/// literals -- and that hands this pass the table it needs to resolve a match
/// to the token its typed field carries.
pub fn redact_text(value: &str) -> String {
    redact_shaped_text(value, &MaskedLiterals::default())
}

/// The token for one shaped match.
///
/// A value that has a shape of its own is consumed here, before the literal
/// scrub runs, so this is where a value the export masks as a typed field must
/// resolve to that field's token. Leaving the rule's own kind in place instead
/// would give one identity two tokens -- `[upn:…]` in narrative and
/// `[redacted:…]` in the field -- and an export that named one user in two
/// records would read as two users.
fn shaped_token(literals: &MaskedLiterals, kind: &str, matched: &str) -> String {
    literals
        .masked_token(matched)
        .unwrap_or_else(|| stable_token(kind, matched))
}

fn redact_shaped_text(value: &str, literals: &MaskedLiterals) -> String {
    let masked = upn_re().replace_all(value, |captures: &regex::Captures<'_>| {
        shaped_token(literals, "upn", &captures[0])
    });
    let masked = user_path_re().replace_all(&masked, |captures: &regex::Captures<'_>| {
        format!(
            "{}{}",
            &captures["prefix"],
            shaped_token(literals, "user", &captures["user"])
        )
    });
    opaque_blob_re()
        .replace_all(&masked, |captures: &regex::Captures<'_>| {
            shaped_token(literals, "blob", &captures[0])
        })
        .into_owned()
}

fn redact_opt(value: &Option<String>) -> Option<String> {
    value.as_ref().map(|value| mask_value(value))
}

/// Whether a value is already a mask, which is what makes the projection
/// idempotent for whole-value fields.
fn is_token(value: &str) -> bool {
    // Only the exact format `[redacted:<16 lowercase hex chars>]` produced by
    // stable_token() is considered already-masked.  Arbitrary `[foo:bar]`
    // values (e.g. event-log setting tokens) must still go through redaction.
    let Some(inner) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    let Some(hex) = inner.strip_prefix("redacted:") else {
        return false;
    };
    hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether a named-data or report-value key holds a whole value the export
/// masks rather than free text it redacts.
///
/// One predicate, read by both the masking pass and the literal collector, so a
/// value cannot be masked as a typed field without its literal also being
/// scrubbed out of free text.
fn sensitive_value_key(name: &str) -> bool {
    SENSITIVE_VALUE_KEYS
        .iter()
        .any(|key| key.eq_ignore_ascii_case(name))
}

/// The values the export masks, each paired with the token it masks to.
///
/// A bare serial has no distinctive shape and a bare DNS domain has no label,
/// so no free-text rule can recognize one. What the projection does have is the
/// value itself, read from the field it is about to mask; scrubbing that exact
/// string out of every free-text field closes the gap by construction rather
/// than by pattern.
///
/// Every entry carries the mask token of its own value rather than a generic
/// marker, so a literal found in narrative is replaced by exactly what its
/// typed field shows: an export that names one device in two records still
/// reads as one device. The shaped rules consult the same table, so a value
/// that is both shaped and masked correlates as well.
#[derive(Default)]
struct MaskedLiterals {
    /// [`caseless_key`] of the literal to the needle the scrub matches with and
    /// the token its typed field carries.
    ///
    /// The key is the grammar's canonical form rather than `to_lowercase`, so the
    /// table holds one entry per identity the lane's own matching treats as one.
    /// Two keys would mean two tokens for one identity: the typed fields carry
    /// the token of their own spelling while a narrative mention matches both
    /// entries and is replaced by whichever the scan reaches first.
    ///
    /// The needle stays the folded spelling (`to_lowercase`) because
    /// [`find_ignore_case`] compares it one folded character at a time against
    /// the folded text. It is the first spelling classified, and any
    /// caseless-equal spelling matches it -- including the final sigma, which the
    /// comparison settles on the uppercase expansion.
    literals: BTreeMap<String, MaskedLiteral>,
}

/// One classified literal: what the scrub matches, and what it replaces with.
struct MaskedLiteral {
    needle: String,
    token: String,
}

impl MaskedLiterals {
    fn new(identifiers: BTreeSet<String>, display_names: BTreeSet<String>) -> Self {
        let mut literals = BTreeMap::new();
        // Identities first: a value that arrives as both is an identity, and the
        // identifier floor decides it whichever way round the sets are built.
        for (value, floor) in identifiers
            .into_iter()
            .map(|value| (value, MIN_SCRUBBED_IDENTIFIER_BYTES))
            .chain(
                display_names
                    .into_iter()
                    .map(|value| (value, MIN_SCRUBBED_LITERAL_BYTES)),
            )
        {
            let value = value.trim();
            // A mask is not identity, and skipping it is half of what keeps the
            // projection idempotent: on the second pass the typed fields
            // already hold tokens, so there is nothing left to scrub.
            if is_token(value) {
                continue;
            }
            // Firmware routinely reports junk serials ("0", "N/A", "None"). A
            // value that short cannot be told apart from an ordinary word once
            // it sits unlabelled in narrative, so scrubbing it would mangle
            // readable evidence without protecting anything. The floor stays
            // below the seven characters of a Dell service tag, so real serials
            // are still covered. A field that declares an identity holds to the
            // lower floor instead.
            if value.len() < floor {
                continue;
            }
            // The key is the form `mask_value` hashes, so the table and the
            // typed fields cannot disagree about the token: one identity folds to
            // one spelling, which mints one token.
            literals
                .entry(caseless_key(value))
                .or_insert(MaskedLiteral {
                    needle: value.to_lowercase(),
                    token: mask_value(value),
                });
        }
        Self { literals }
    }

    /// The token this value carries as a typed field, if the export masks it.
    ///
    /// Asked with the same key the table was built with, so a shaped rule does
    /// not depend on how the text happened to be cased either.
    fn masked_token(&self, value: &str) -> Option<String> {
        self.literals
            .get(&caseless_key(value.trim()))
            .map(|literal| literal.token.clone())
    }

    /// Replace every occurrence of a masked literal with that literal's token.
    ///
    /// Runs last in each free-text pipeline. The shaped rules go first so a
    /// tenant domain scrubbed on its own cannot break the mail-address match on
    /// a UPN that contains it, which would leak the local part.
    fn scrub(&self, value: &str) -> String {
        if self.literals.is_empty() {
            return value.to_owned();
        }

        // One folded view of the text, shared by every literal.
        let folded = fold_with_offsets(value);
        let mut scrubbed = String::with_capacity(value.len());
        let mut cursor = 0;

        while let Some((start, end, token)) = self.leftmost_longest_match(value, &folded, cursor) {
            scrubbed.push_str(&value[cursor..start]);
            scrubbed.push_str(token);
            cursor = end;
        }
        scrubbed.push_str(&value[cursor..]);
        scrubbed
    }

    /// Leftmost match, longest at that position, so a literal that sits inside
    /// a longer one can never cut the longer one in half.
    fn leftmost_longest_match<'a>(
        &'a self,
        haystack: &str,
        folded: &[FoldedChar],
        cursor: usize,
    ) -> Option<(usize, usize, &'a str)> {
        let mut best: Option<(usize, usize, &'a str)> = None;
        for literal in self.literals.values() {
            let Some((start, end)) = find_ignore_case(haystack, &literal.needle, folded, cursor)
            else {
                continue;
            };
            let replaces = best.is_none_or(|(best_start, best_end, _)| {
                start < best_start || (start == best_start && end > best_end)
            });
            if replaces {
                best = Some((start, end, literal.token.as_str()));
            }
        }
        best
    }
}

/// Mask the sensitive spans inside a free-text value, then scrub the literals
/// the export masks as typed fields out of it.
fn redact_export_text(value: &str, literals: &MaskedLiterals) -> String {
    literals.scrub(&redact_shaped_text(value, literals))
}

/// Visit every whole value the export masks in place.
///
/// One walk, read by both [`collect_masked_literals`] and
/// [`redacted_export_projection`], so a value cannot be masked as a typed field
/// without its literal also being scrubbed out of free text.
///
/// Named-data and conflict values are not on this walk because which of them is
/// masked is decided by a key rather than by the field they sit in;
/// [`sensitive_value_key`] and [`masked_conflict_literal`] are the shared
/// decisions for those two.
/** What a walked value is, which decides the floor its literal holds to. */
#[derive(Clone, Copy, PartialEq, Eq)]
enum MaskClass {
    /// A field that states an identity: device, tenant, correlation key.
    Identity,
    /// A field that labels something rather than naming it.
    DisplayName,
}

fn for_each_masked_value_mut(
    snapshot: &mut AutopilotSnapshot,
    mut visit: impl FnMut(&mut String, MaskClass),
) {
    let identity = &mut snapshot.identity;
    let fields = [
        &mut identity.serial_number,
        &mut identity.hardware_hash,
        &mut identity.product_key_id,
        &mut identity.ztd_registration_id,
        &mut identity.entra_device_id,
        &mut identity.managed_device_id,
        &mut identity.tenant_id,
        &mut identity.tenant_domain,
        &mut identity.device_name,
    ];
    for value in fields.into_iter().flatten() {
        visit(value, MaskClass::Identity);
    }

    // `profile_id` survives: it is a tenant object identifier and the only way
    // to line an export up against the Intune profile it describes. The
    // admin-authored display name does not survive.
    if let Some(name) = &mut snapshot.profile.profile_name {
        // The name labels the profile; `profile_id`, which identifies it, is the
        // identity above.
        visit(name, MaskClass::DisplayName);
    }

    for key in &mut snapshot.esp_linkage.matched_keys {
        visit(&mut key.value, MaskClass::Identity);
    }
}

/// Read the literal value out of every field the export masks.
///
/// Takes `&mut` only to share one walk with the masking pass in
/// [`for_each_masked_value_mut`]; it changes nothing.
/// A profile name labels a configuration rather than naming the device or the
/// tenant it belongs to, so it keeps the prose floor.
fn display_name_value_key(name: &str) -> bool {
    name.eq_ignore_ascii_case("profileName")
}

fn collect_masked_literals(snapshot: &mut AutopilotSnapshot) -> MaskedLiterals {
    let mut identifiers = BTreeSet::new();
    let mut display_names = BTreeSet::new();
    for_each_masked_value_mut(snapshot, |value, class| {
        match class {
            MaskClass::Identity => identifiers.insert(value.clone()),
            MaskClass::DisplayName => display_names.insert(value.clone()),
        };
    });
    for observation in &snapshot.observations {
        for named in &observation.named_data {
            if display_name_value_key(&named.name) {
                display_names.insert(named.value.clone());
            } else if sensitive_value_key(&named.name) {
                identifiers.insert(named.value.clone());
            }
        }
    }
    // A conflict is two identifiers disagreeing about the same device.
    for conflict in &snapshot.conflicts {
        for value in &conflict.values {
            identifiers.insert(masked_conflict_literal(value).to_owned());
        }
    }
    MaskedLiterals::new(identifiers, display_names)
}

/// Return a copy of `snapshot` safe to export by default.
///
/// Idempotent: `redacted_export_projection(&redacted_export_projection(&s))`
/// serializes identically to `redacted_export_projection(&s)`.
pub fn redacted_export_projection(snapshot: &AutopilotSnapshot) -> AutopilotSnapshot {
    let mut projected = snapshot.clone();
    // Read before anything is masked: once a typed field holds a token there is
    // no literal left to remember.
    let literals = collect_masked_literals(&mut projected);

    // `mask_value` everywhere a whole value is masked: it performs the
    // trim/lowercase normalization the module contract promises, so the same
    // identifier masks identically whatever field or casing it arrived in.
    for_each_masked_value_mut(&mut projected, |value, _class| *value = mask_value(value));

    for observation in &mut projected.observations {
        observation.message = observation
            .message
            .as_deref()
            .map(|message| redact_export_text(message, &literals));
        observation.context.provenance.file_path =
            redact_opt(&observation.context.provenance.file_path);
        redact_named_values(&mut observation.named_data, &literals);
    }

    for conflict in &mut projected.conflicts {
        conflict.detail = redact_export_text(&conflict.detail, &literals);
        conflict.values = conflict
            .values
            .iter()
            .map(|value| redact_conflict_value(value))
            .collect();
    }

    for entry in &mut projected.coverage {
        entry.detail = entry
            .detail
            .as_deref()
            .map(|detail| redact_export_text(detail, &literals));
    }

    projected.next_evidence_requests = projected
        .next_evidence_requests
        .iter()
        .map(|request| redact_export_text(request, &literals))
        .collect();

    for finding in &mut projected.findings {
        redact_finding(finding, &literals);
    }

    projected
}

fn redact_named_values(values: &mut [IntuneNamedValue], literals: &MaskedLiterals) {
    for value in values {
        if sensitive_value_key(&value.name) {
            value.value = mask_value(&value.value);
        } else {
            value.value = redact_export_text(&value.value, literals);
        }
    }
}

/// The portion of a conflict value the export masks as one whole value.
///
/// Conflict values are written as `name=value` by the reducer for report
/// sections and as bare values for named-key conflicts, so the masked portion
/// is a slice of the raw string. The masking pass and the literal collector
/// both read it here, so the two cannot disagree about what was masked.
fn masked_conflict_literal(value: &str) -> &str {
    match value.split_once('=') {
        Some((name, raw)) if sensitive_value_key(name) => raw,
        _ => value,
    }
}

fn redact_conflict_value(value: &str) -> String {
    let literal = masked_conflict_literal(value);
    // The masked portion is always a suffix, so what precedes it is the
    // `name=` prefix or nothing at all.
    let prefix = &value[..value.len() - literal.len()];
    format!("{prefix}{}", mask_value(literal))
}

fn redact_finding(finding: &mut IntuneFinding, literals: &MaskedLiterals) {
    finding.summary = redact_export_text(&finding.summary, literals);
    finding.recommended_checks = finding
        .recommended_checks
        .iter()
        .map(|check| redact_export_text(check, literals))
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_mask_to_equal_tokens_so_correlation_survives() {
        let left = stable_token(VALUE_KIND, "5CD1234ABC");
        let right = stable_token(VALUE_KIND, "5CD1234ABC");
        assert_eq!(left, right);
        assert_ne!(left, stable_token(VALUE_KIND, "5CD1234ABD"));
    }

    #[test]
    fn masking_free_text_is_idempotent() {
        let once = redact_text("signed in as synthetic.user@example.invalid");
        let twice = redact_text(&once);
        assert_eq!(once, twice);
        assert!(!once.contains('@'));
    }

    #[test]
    fn a_user_profile_segment_with_a_space_is_masked_in_full() {
        let masked = redact_text(r"D:\Users\Synthetic Person\provisioning.log");
        assert!(!masked.contains("Synthetic"), "got {masked}");
        assert!(!masked.contains("Person"), "got {masked}");
        assert!(masked.contains(r"\Users\"), "the shape must survive");
    }

    #[test]
    fn a_guid_and_an_hresult_survive_because_they_are_diagnostic_grammar() {
        let text = "profile 11111111-2222-3333-4444-555555555555 failed HRESULT=0x801C03EA";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn a_long_opaque_blob_is_masked() {
        let hash = "A".repeat(64);
        let masked = redact_text(&format!("hardware hash {hash}"));
        assert!(!masked.contains(&hash), "got {masked}");
    }

    /// A Base64 hardware hash may end in `=`, `==`, `+`, or `/` -- none of which
    /// is a word character, so a trailing `\b` cannot close the match at them.
    /// Every one of these must be masked in full, or raw identity material rides
    /// out in the padding after a partial match (ADR-004: restricted values are
    /// absent from export).
    #[test]
    fn a_base64_blob_ending_in_punctuation_is_masked_in_full() {
        // Each blob is a >=40 char Base64 run terminated by a non-word char.
        for blob in [
            format!("{}=", "A".repeat(43)),  // single pad
            format!("{}==", "A".repeat(42)), // double pad
            format!("{}+", "A".repeat(43)),  // plus terminal
            format!("{}/", "A".repeat(43)),  // slash terminal
        ] {
            let masked = redact_text(&format!("hardware hash {blob} was reported"));
            assert!(
                !masked.contains(&blob),
                "the whole blob must be masked, got {masked}"
            );
            // No fragment of the original run -- including the padding/punctuation
            // tail -- may survive between the surrounding words.
            assert!(
                !masked.contains("AA"),
                "no run of the blob may survive, got {masked}"
            );
            for tail in ['=', '+', '/'] {
                assert!(
                    !masked.contains(&format!("{tail} was")),
                    "a punctuation tail must not dangle after masking, got {masked}"
                );
            }
        }
    }

    #[test]
    fn an_already_masked_whole_value_is_left_alone() {
        let token = stable_token(VALUE_KIND, "abc");
        assert!(is_token(&token));
        assert_eq!(redact_conflict_value(&token), token);
        assert_eq!(
            redact_conflict_value(&format!("serialNumber={token}")),
            format!("serialNumber={token}")
        );
    }

    /// Every whole-value masking site must normalize case and surrounding
    /// space before hashing, or the same identifier arriving in two casings
    /// would mask to two different tokens and destroy the very correlation the
    /// projection exists to preserve.
    #[test]
    fn whole_value_masking_normalizes_case_and_space_at_every_site() {
        let canonical = mask_value("abcdabcd-1234-5678-9012-abcdabcdabcd");

        // Named-data values with a sensitive key.
        let mut values = vec![IntuneNamedValue {
            name: "entraDeviceId".to_owned(),
            value: "  ABCDABCD-1234-5678-9012-ABCDABCDABCD  ".to_owned(),
        }];
        redact_named_values(&mut values, &MaskedLiterals::default());
        assert_eq!(values[0].value, canonical);

        // Conflict values, both shapes.
        assert_eq!(
            redact_conflict_value("entraDeviceId= ABCDABCD-1234-5678-9012-ABCDABCDABCD "),
            format!("entraDeviceId={canonical}")
        );
        assert_eq!(
            redact_conflict_value(" ABCDABCD-1234-5678-9012-ABCDABCDABCD "),
            canonical
        );

        // The identity-field path already goes through mask_value; the token
        // must line up with all of the above.
        assert_eq!(
            redact_opt(&Some("Abcdabcd-1234-5678-9012-abcdabcdABCD".to_owned())),
            Some(canonical)
        );
    }

    #[test]
    fn a_non_sensitive_conflict_key_still_masks_its_value() {
        // Falling through to the bare-value branch is deliberate: a conflict
        // value the reducer could not attribute to a known key is more likely
        // to be identity than not.
        let masked = redact_conflict_value("someOtherKey=5CD1234ABC");
        assert!(!masked.contains("5CD1234ABC"), "got {masked}");
    }

    /// The literal search is cursor-driven and case-insensitive, so it has to
    /// hold at the tail of the text, across repeats, and for a value that is
    /// the whole text -- without re-finding what it already replaced.
    #[test]
    fn the_literal_search_replaces_every_occurrence_including_at_the_tail() {
        let literals =
            MaskedLiterals::new(BTreeSet::from(["PC-ÉLODIE".to_owned()]), BTreeSet::new());
        let token = mask_value("PC-ÉLODIE");

        assert_eq!(
            literals.scrub("device pc-élodie"),
            format!("device {token}")
        );
        assert_eq!(literals.scrub("PC-ÉLODIE"), token);
        assert_eq!(
            literals.scrub("pc-élodie met PC-ÉLODIE"),
            format!("{token} met {token}")
        );
        assert_eq!(literals.scrub("unrelated narrative"), "unrelated narrative");
    }

    /// One device spelled two ways in one export reaches one token.
    ///
    /// `Σ` and final `ς` are caseless-equal to the matcher -- the comparison
    /// settles them on the uppercase `Σ` -- but they are two different lowercase
    /// letters, so a table keyed by `to_lowercase` held two entries: the typed
    /// field carrying one spelling minted its own token, and a narrative mention
    /// of the other matched both entries and was replaced by one of the two.
    #[test]
    fn a_final_sigma_spelling_reaches_the_capital_sigma_token() {
        const CAPITAL: &str = "\u{3A3}\u{39F}\u{3A6}\u{39F}\u{3A5}\u{3A3}.Example";
        const NARRATIVE: &str = "\u{3C3}\u{3BF}\u{3C6}\u{3BF}\u{3C5}\u{3C2}.example";

        let literals = MaskedLiterals::new(
            BTreeSet::from([CAPITAL.to_owned(), NARRATIVE.to_owned()]),
            BTreeSet::new(),
        );
        let token = mask_value(CAPITAL);

        assert_eq!(literals.literals.len(), 1, "one identity, one entry");
        assert_eq!(mask_value(NARRATIVE), token, "one identity, one token");
        assert_eq!(literals.masked_token(NARRATIVE), Some(token.clone()));
        assert_eq!(
            literals.scrub(&format!("device {CAPITAL}")),
            format!("device {token}")
        );
        assert_eq!(
            literals.scrub(&format!("device {NARRATIVE}")),
            format!("device {token}")
        );
    }
}
