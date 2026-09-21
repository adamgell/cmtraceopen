//! The dsregcmd export projection (issue #556).
//!
//! `dsregcmd /status` is dense with the identifiers the Intune lanes mask:
//! the tenant id, the tenant and on-premises domains, the device id, the
//! device certificate thumbprint, the signed-in user's principal name and the
//! user's SID. This module is where that lane classifies them and produces the
//! form callers may publish.
//!
//! # Where the boundary is
//!
//! ADR-004 revision 1, Ruling 1: the contract binds at the crate/library export
//! boundary, and the published analysis value reaching callers is projected.
//! [`analyze_text`](super::analyze_text) and
//! [`analyze_text_with_evidence`](super::analyze_text_with_evidence) therefore
//! apply [`redacted_analysis`] before returning, and the unprojected analysis
//! stays crate-internal (`dsregcmd::analyze_text_preserving_local_values`), so
//! a consumer of this crate has no unprojected value in hand to copy to a
//! clipboard or a file, and a workspace that finds itself holding one has found
//! a defect here rather than something to fix at the clipboard call site.
//!
//! # What is shared and what is local
//!
//! Ruling 5: the masking *grammar* is shared and the *projection* is
//! workload-local. Masking runs through
//! [`redact_text`](crate::intune::apps::windows::common::redaction::redact_text)
//! for text and
//! [`redact_field_value`](crate::intune::apps::windows::common::redaction::redact_field_value)
//! for a value that is sensitive only because of the field it sits in; this
//! module owns only the classification — which of this lane's fields carry
//! identity. It writes no rule and mints no token of its own.
//!
//! # How the classification is expressed
//!
//! Ruling 7: every function on the projection path constructs its result with a
//! full struct literal, at every depth. There is no `clone()`-then-mutate and
//! no struct-update syntax anywhere in this file, so a field added to any model
//! on this path is a compile error here, in the change that adds it, rather
//! than a field that ships raw.
//!
//! # Two classes of field, and the free-text gap
//!
//! A string field is either an *identity field* — masked whole, from its
//! meaning — or *text*, masked for anything the shared grammar recognizes and
//! then scrubbed of every literal this projection classified as identity. The
//! second pass is what closes the gap a shaped rule cannot: `DeviceId` and
//! `Thumbprint` have no shape and no label once they are a struct field, and
//! the tenant id also appears inside `Endpoint URI` and the PRT authority URL
//! where nothing labels it.
//!
//! # Equality scope
//!
//! Masking here preserves equality within one analysis: equal values produce
//! equal tokens, and a value masked as a typed field and mentioned in narrative
//! text reaches the same token, so an export still shows that two records name
//! one tenant, one device, one user. Identity values are canonicalized (trimmed
//! and folded, Unicode-aware) before a token is minted, so two spellings of one
//! identity cannot reach two tokens.
//!
//! One case escapes that, and it belongs to the shared grammar rather than to
//! this lane: the grammar's own principal-name rule hashes the spelling it sees
//! (`stable_token("upn", &caps[0])`), so a narrative mention spelled in a
//! different case than the classified field keeps the grammar's token. Masking
//! runs after the grammar deliberately — the shaped rules must see the original
//! text — and changing that derivation would change every lane's tokens, so it
//! is the grammar owner's call rather than something to fork here.
//!
//! Two spellings are one identity when the shared caseless comparison says so:
//! equal after lowercasing, or after uppercasing (which is what bridges `Σ` and
//! Greek's final `ς`), or one side writes out the other's case mapping (`İ`
//! against `i` plus U+0307). What that deliberately does not reach is a pair
//! whose case mapping changes length (`ß` against `SS`, the `ﬀ`-style
//! ligatures), or a difference that is normalization rather than case (`é`
//! against `e` plus U+0301). Those need a folding or normalization table, which
//! this crate does not depend on; the limit is pinned by a test rather than
//! left to be assumed.
//!
//! Ruling 2 requires the derivation to be keyed per analysis and Ruling 4
//! forbids a scope the caller did not supply; neither is implemented for any
//! lane yet, and this lane adopts the one shared derivation rather than minting
//! a fifth (Ruling 5). A lane that forked the derivation would keep the unkeyed
//! one, and the fix would not reach it.

use crate::intune::apps::windows::common::{
    caseless_equal, find_ignore_case, fold_with_offsets, redact_field_value, redact_text,
    FoldedChar,
};
use crate::intune::models::{
    EventLogAnalysis, EventLogChannelSummary, EventLogCorrelationLink, EventLogEntry,
    EventLogLiveQueryChannelResult, EventLogLiveQueryMetadata, IntuneTimestampBounds,
};

use super::models::{
    DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdBundleEvidence,
    DsregcmdConnectivityResult, DsregcmdDerived, DsregcmdDeviceDetails, DsregcmdDiagnosticFields,
    DsregcmdDiagnosticInsight, DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdFacts,
    DsregcmdJoinState, DsregcmdManagementDetails, DsregcmdOsVersionEvidence,
    DsregcmdPolicyEvidenceValue, DsregcmdPostJoinDiagnostics, DsregcmdPreJoinTests,
    DsregcmdProxyEvidence, DsregcmdRegistrationState, DsregcmdScheduledTaskEvidence,
    DsregcmdScpQueryResult, DsregcmdServiceEndpoints, DsregcmdSsoState, DsregcmdTenantDetails,
    DsregcmdUserState, DsregcmdWhfbPolicyEvidence,
};

/// The field vocabulary this lane masks with. The shared grammar already emits
/// `tenant`, `upn` and `host` for values it recognizes from shape, so an
/// identity field that carries one of those keeps the token a narrative mention
/// of the same value would get.
const KIND_TENANT: &str = "tenant";
const KIND_DEVICE: &str = "device";
const KIND_THUMBPRINT: &str = "thumbprint";
const KIND_UPN: &str = "upn";
const KIND_HOST: &str = "host";

/// Shortest classified value scrubbed out of free text.
///
/// A tenant display name can be a short ordinary word, and a value that short
/// cannot be told apart from prose once it sits unlabelled in a sentence.
/// Scrubbing it would mangle readable evidence without protecting anything the
/// typed field does not already cover. The floor stays below the shortest real
/// domain, device id and thumbprint, so every shaped identifier is still
/// covered.
const MIN_SCRUBBED_LITERAL_BYTES: usize = 6;

/// Shortest value a **typed** sensitive field may contribute.
///
/// Below the ordinary floor, because a typed field is what makes the value an
/// identity: a four-character NetBIOS domain is real, and one was leaking from a
/// live capture's prose while its typed field was masked.
///
/// Not zero, because the reason for the ordinary floor does not vanish at two
/// characters: `ad` matches as a standalone word in any sentence, so a typed path
/// with no floor of its own mangled prose the lane had deliberately left alone —
/// which `a_short_value_does_not_scrub_unrelated_narrative` in this crate's
/// export-boundary test caught. Bounded matching is not enough on its own: a
/// short ordinary word is *often* a bounded token.
///
/// So the resulting policy is: a typed-sensitive value of four or five bytes may
/// be scrubbed, at boundaries only. Below four bytes it stays out of generic
/// narrative replacement because the observed false-positive risk is too high;
/// a field-specific treatment can be added if evidence ever supports one.
const MIN_TYPED_SENSITIVE_LITERAL_BYTES: usize = 4;

/// Every identity value this lane classified, paired with the token that
/// replaces it.
///
/// Built from the unprojected analysis and then applied to it, so a literal is
/// known before any free-text field is scrubbed. The table is the single source
/// of tokens: a typed field asks it for the token of the identity it holds rather
/// than minting a second one, and membership is decided by the shared
/// caseless comparison, so the table can never hold two entries that the
/// scrubber would treat as one identity — including spellings that differ by
/// case in a way only one of the two folds bridges (`Σ` against final `ς`) or
/// that write a case mapping out (`İ` against `i` plus U+0307).
#[derive(Default)]
struct IdentityLiterals {
    /// Classified literals, longest literal first.
    ///
    /// The scrub does not depend on that order —
    /// [`IdentityLiterals::leftmost_longest_match`] takes the longest match at
    /// the leftmost position itself, so a literal that sits inside a longer one
    /// still cannot cut the longer one in half — but the table is left in the
    /// order it has always held rather than reshuffled for no observable
    /// difference.
    values: Vec<ClassifiedLiteral>,
}

/// One classified identity, paired with the token that replaces it.
struct ClassifiedLiteral {
    /// The value as classified, canonicalized.
    literal: String,
    /// The value's byte length as it was found, before canonicalization.
    ///
    /// Lowercasing can change byte length — `İ` is two bytes and canonicalizes
    /// to three — so measuring the canonical form at match time would let a value
    /// clear one floor and be judged against a different length than the one the
    /// floor was applied to. Both decisions read this field so they cannot
    /// disagree, and it is the length the insertion floor was applied to.
    literal_bytes: usize,
    /// The token every spelling of this identity reaches.
    token: String,
    /// How the value was found, which is what authorizes replacing it and how it
    /// is matched. One property rather than a stored boundary flag, so the two
    /// cannot drift apart.
    origin: LiteralOrigin,
}

impl ClassifiedLiteral {
    /// Whether a match of this literal has to sit on a token boundary.
    fn requires_boundary(&self) -> bool {
        self.origin.requires_boundary(self.literal_bytes)
    }
}

/// Where a classified literal came from, which is what authorizes replacing it.
///
/// The ordinary six-byte floor exists because a short value in prose cannot be
/// told apart from the sentence around it: scrubbing one mangles readable
/// evidence without protecting anything a typed field does not already cover.
/// That reasoning does not reach a value the capture put in a **typed sensitive
/// field**, because the field is what makes it an identity and it is masked there
/// either way. Length alone therefore cannot be the whole test, and the typed
/// value gets its own insertion path rather than a lower floor.
///
/// The origin is passed in when a value is registered rather than inferred from
/// the `kind` at the match site: a `kind` names the token vocabulary — which token
/// a value reaches — and says nothing about how the value was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralOrigin {
    /// Read out of a typed field this lane masks, so it is an identity whatever
    /// its length.
    TypedSensitive,
    /// Derived from a typed value rather than observed on its own: the short
    /// hostname of a classified FQDN.
    DerivedFromTyped,
    /// A value with no field behind it, which is what the ordinary floor is for.
    ///
    /// No producer in this lane yet — every literal it classifies comes from a
    /// typed field — so this variant holds the policy's *other* insertion path
    /// open and pins the floor with a test, rather than leaving unstated the rule
    /// that a caller with no field must still clear it.
    #[allow(dead_code)]
    ObservedNarrative,
}

impl LiteralOrigin {
    /// The shortest value this origin may contribute.
    ///
    /// A typed field is a different authorization from length, not the absence of
    /// one: it lowers the bar far enough for a short real identifier to count, and
    /// keeps it above the length at which a value is indistinguishable from the
    /// text around it.
    fn floor(self) -> usize {
        match self {
            Self::TypedSensitive => MIN_TYPED_SENSITIVE_LITERAL_BYTES,
            Self::DerivedFromTyped | Self::ObservedNarrative => MIN_SCRUBBED_LITERAL_BYTES,
        }
    }

    /// Whether a value of this origin and length is replaced only where the
    /// characters around it could not continue an identifier.
    ///
    /// Two cases are bounded. A *short* value is, because it occurs as a fragment
    /// of something longer far more easily than a full identity does: `ACME` sits
    /// inside `ACMECORP`, `MYACME` and `ACME2`. A *derived* value is, because it is
    /// a fragment by construction: the short hostname sits inside
    /// `HELPDESK-LAPTOP011`. A value that cleared the floor and was named outright
    /// keeps the substring behaviour this lane has always had, which is what makes
    /// a domain lose inside `dc1.corp.contoso.com`.
    fn requires_boundary(self, literal_len: usize) -> bool {
        match self {
            Self::DerivedFromTyped => true,
            Self::TypedSensitive => literal_len < MIN_SCRUBBED_LITERAL_BYTES,
            Self::ObservedNarrative => false,
        }
    }

    /// The origin two registrations of one literal leave behind.
    ///
    /// A registration from a typed field wins over one that merely derived the
    /// value, so an identity never stays narrower than the lane's own evidence
    /// for it.
    fn widen(self, other: Self) -> Self {
        match (self, other) {
            (Self::TypedSensitive, _) | (_, Self::TypedSensitive) => Self::TypedSensitive,
            _ => self,
        }
    }
}

impl IdentityLiterals {
    /// Classify one identity value. Values too short to be told apart from
    /// prose are skipped rather than scrubbed out of narrative over-eagerly.
    fn push(&mut self, value: &str, kind: &str, origin: LiteralOrigin) {
        let Some(token) = self.push_literal(value, kind, origin) else {
            // Refused, so there is no token for a derived form to share either.
            return;
        };

        // A host is the one identity this lane classifies whose short form is a
        // *separate* literal in the capture: an event record names the machine by
        // FQDN while the messages around it name the same machine by its short
        // form. Classifying only the FQDN therefore masked the field it came from
        // and published the machine in every narrative mention — 190 occurrences
        // in a live capture. Both spellings reach one token, because they are one
        // machine.
        //
        // The short form passes the same floor below. That minimum is a shared
        // contract this lane does not change here (issue #646).
        if kind == KIND_HOST {
            if let Some((short, _)) = value.trim().split_once('.') {
                if !short.is_empty() {
                    self.push_alias(short, &token);
                }
            }
        }
    }

    /// Classify one literal and return the token it reaches.
    ///
    /// `None` when the value is below the scrub floor, so a caller that meant to
    /// share the token with a derived form knows there is none to share.
    fn push_literal(&mut self, value: &str, kind: &str, origin: LiteralOrigin) -> Option<String> {
        let literal = value.trim();
        if literal.is_empty() {
            return None;
        }

        // The floor is unchanged for a value with no field behind it. A typed
        // field is a different authorization: the field is what says the value is
        // an identity, so length settles less — but it still settles something,
        // which is why the typed path has its own floor rather than none.
        if literal.len() < origin.floor() {
            return None;
        }

        // The table is keyed by, holds, and mints from the canonical form, so a
        // second spelling of an identity already classified cannot reach a
        // second token.
        let canonical = canonical_identity(literal);
        if let Some(existing) = self
            .values
            .iter_mut()
            .find(|existing| caseless_equal(&existing.literal, &canonical))
        {
            // An entry first learned as a derived form widens when a typed field
            // holds the value outright, rather than staying narrower than the
            // lane's own evidence for it.
            existing.origin = existing.origin.widen(origin);
            return Some(existing.token.clone());
        }

        let token = identity_token(literal, kind);
        self.values.push(ClassifiedLiteral {
            literal: canonical,
            literal_bytes: literal.len(),
            token: token.clone(),
            origin,
        });
        self.sort_values();
        Some(token)
    }

    /// Classify a derived form that has to reach the token of an identity the
    /// capture already named, rather than minting a second one for one machine.
    fn push_alias(&mut self, value: &str, token: &str) {
        let literal = value.trim();
        if literal.len() < MIN_SCRUBBED_LITERAL_BYTES {
            return;
        }

        let canonical = canonical_identity(literal);
        if let Some(existing) = self
            .values
            .iter_mut()
            .find(|existing| caseless_equal(&existing.literal, &canonical))
        {
            // A derived form never narrows an identity the capture named outright.
            existing.origin = existing.origin.widen(LiteralOrigin::DerivedFromTyped);
            return;
        }

        self.values.push(ClassifiedLiteral {
            literal: canonical,
            literal_bytes: literal.len(),
            token: token.to_string(),
            origin: LiteralOrigin::DerivedFromTyped,
        });
        self.sort_values();
    }

    fn sort_values(&mut self) {
        self.values.sort_by(|left, right| {
            right
                .literal
                .len()
                .cmp(&left.literal.len())
                .then_with(|| left.literal.cmp(&right.literal))
        });
    }

    /// The token this identity already reached, when it is one of the classified
    /// ones. Caseless-equal spellings are one identity, so they all reach the
    /// token the table minted for the first of them.
    fn token_for(&self, value: &str) -> Option<&str> {
        let canonical = canonical_identity(value);
        self.values
            .iter()
            .find(|existing| caseless_equal(&existing.literal, &canonical))
            .map(|existing| existing.token.as_str())
    }

    /// Replace every occurrence of a classified literal, whatever its case.
    ///
    /// Runs after the shared grammar in every free-text pipeline: the shaped
    /// rules must see the original text, or scrubbing a tenant domain on its
    /// own would break the mail-address match on a principal name that contains
    /// it and leak the local part.
    fn scrub(&self, value: &str) -> String {
        if self.values.is_empty() {
            return value.to_string();
        }

        // One folded view of the text, shared by every literal. The fold is the
        // grammar's, not this lane's.
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

    /// The leftmost match, longest at that position, as `(start, end, token)`
    /// with byte offsets into `haystack` itself.
    ///
    /// Each literal asks the grammar's cursor search for its next occurrence at
    /// or after `cursor`; the leftmost of those answers wins, and a tie there
    /// goes to the longest match, so a literal that sits inside a longer one can
    /// never cut the longer one in half.
    fn leftmost_longest_match<'a>(
        &'a self,
        haystack: &str,
        folded: &[FoldedChar],
        cursor: usize,
    ) -> Option<(usize, usize, &'a str)> {
        let mut best: Option<(usize, usize, &'a str)> = None;
        for entry in &self.values {
            let Some((start, end)) = next_acceptable_match(entry, haystack, folded, cursor) else {
                continue;
            };
            let replaces = best.is_none_or(|(best_start, best_end, _)| {
                start < best_start || (start == best_start && end > best_end)
            });
            if replaces {
                best = Some((start, end, entry.token.as_str()));
            }
        }
        best
    }
}

/// Whether a character could continue an identifier, so a short or derived value
/// must not be replaced across it.
fn continues_identifier(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '-' | '_' | '.')
}

/// Whether `haystack[start..end]` sits on a token boundary.
fn on_token_boundary(haystack: &str, start: usize, end: usize) -> bool {
    let before = haystack[..start].chars().next_back();
    let after = haystack[end..].chars().next();
    !before.is_some_and(continues_identifier) && !after.is_some_and(continues_identifier)
}

/// The next match of `entry` at or after `cursor` that the entry's own boundary
/// rule accepts.
///
/// A bounded alias can still reach a later occurrence when the first one it
/// finds is a fragment of something longer, so the search steps past a rejected
/// match rather than giving up on the literal.
fn next_acceptable_match(
    entry: &ClassifiedLiteral,
    haystack: &str,
    folded: &[FoldedChar],
    cursor: usize,
) -> Option<(usize, usize)> {
    let mut from = cursor;

    while let Some((start, end)) = find_ignore_case(haystack, &entry.literal, folded, from) {
        if !entry.requires_boundary() || on_token_boundary(haystack, start, end) {
            return Some((start, end));
        }

        // `start` is a byte offset into `haystack` itself, so stepping one
        // character past it cannot desynchronize the folded view.
        let step = haystack[start..].chars().next().map_or(1, char::len_utf8);
        from = start + step;
    }

    None
}

/// The canonical form every classification keys on and mints from: trimmed and
/// case-folded.
///
/// Every identifier this lane masks is case-insensitive *as an identity*: a
/// tenant id and a device id are GUIDs, a certificate thumbprint is hex, a
/// tenant, on-premises and computer name is a DNS or NetBIOS name, a SID is
/// case-insensitive by definition, and a user principal name is matched
/// case-insensitively by Entra. None of them is case-significant, so folding
/// cannot conflate two distinct identities, and it is what keeps one identity
/// from reaching two tokens when two fields or a line of prose spell it
/// differently.
///
/// The fold is Unicode-aware (`to_lowercase`, not `to_ascii_lowercase`), because
/// a non-ASCII letter has to fold the same way here as it does in the scrub.
fn canonical_identity(value: &str) -> String {
    value.trim().to_lowercase()
}

/// The token an identity value reaches, wherever it is projected.
///
/// The value is canonicalized first, so a typed field and a narrative mention of
/// one identity reach one token. A canonical value the shared grammar recognizes
/// by shape keeps the grammar's token, which is already case-independent where
/// the grammar intends it to be (the SID rule hashes the uppercase form); a
/// value with no distinctive shape is minted through the shared minter.
fn identity_token(value: &str, kind: &str) -> String {
    let canonical = canonical_identity(value);
    let shaped = redact_text(&canonical);
    if shaped == canonical {
        redact_field_value(kind, &canonical)
    } else {
        shaped
    }
}

/// The projection: the classification above, applied to a whole analysis.
struct Projection {
    literals: IdentityLiterals,
}

impl Projection {
    /// A free-text field: the shared grammar first, then this lane's literal
    /// scrub.
    fn text(&self, value: &str) -> String {
        self.literals.scrub(&redact_text(value))
    }

    fn text_opt(&self, value: &Option<String>) -> Option<String> {
        value.as_deref().map(|value| self.text(value))
    }

    fn texts(&self, values: &[String]) -> Vec<String> {
        values.iter().map(|value| self.text(value)).collect()
    }

    /// An identity field: masked whole, because the field's meaning is what
    /// makes the value an identifier rather than anything in the value.
    ///
    /// The table is asked first. It decided this identity's token when the
    /// classification was collected, and the narrative scrub will use that same
    /// token, so minting a second one here would be the one way left for a field
    /// and a prose mention of one identity to disagree. A value the table does
    /// not hold is one below the scrub floor, and it mints its own.
    fn identity(&self, value: &Option<String>, kind: &str) -> Option<String> {
        value
            .as_deref()
            .map(|value| match self.literals.token_for(value) {
                Some(token) => token.to_string(),
                None => identity_token(value, kind),
            })
    }
}

/// Project a fully assembled analysis into the form callers may publish.
pub fn redacted_analysis(result: &DsregcmdAnalysisResult) -> DsregcmdAnalysisResult {
    let projection = Projection {
        literals: collect_identity_literals(result),
    };

    DsregcmdAnalysisResult {
        facts: projection.facts(&result.facts),
        derived: projection.derived(&result.derived),
        diagnostics: projection.diagnostics(&result.diagnostics),
        policy_evidence: projection.policy_evidence(&result.policy_evidence),
        os_version: result
            .os_version
            .as_ref()
            .map(|os_version| projection.os_version(os_version)),
        proxy_evidence: result
            .proxy_evidence
            .as_ref()
            .map(|proxy_evidence| projection.proxy_evidence(proxy_evidence)),
        enrollment_evidence: result
            .enrollment_evidence
            .as_ref()
            .map(|enrollment| projection.enrollment_evidence(enrollment)),
        active_evidence: result
            .active_evidence
            .as_ref()
            .map(|active| projection.active_evidence(active)),
        scheduled_task_evidence: result
            .scheduled_task_evidence
            .as_ref()
            .map(|scheduled| projection.scheduled_task_evidence(scheduled)),
        event_log_analysis: result
            .event_log_analysis
            .as_ref()
            .map(|events| projection.event_log_analysis(events)),
    }
}

/// Project raw `dsregcmd /status` text.
///
/// For callers that hold the capture itself rather than an analysis of it —
/// the workspace's "copy status text" path — this is the projection of the
/// input, and it is the same classification: the shared grammar over the whole
/// text, then the literals the parser read out of this same capture scrubbed
/// out of it. Text the parser does not recognize loses only what the grammar
/// recognizes by shape; nothing is invented for it.
///
/// This is the one form of the capture text that may be published. The capture
/// text itself stays a capture: it is the analyzer's input, and two analyzers
/// read it back from a bundle, so masking where it is *stored* would change what
/// they conclude rather than what they publish.
pub fn redacted_status_text(input: &str) -> String {
    Projection {
        literals: capture_literals(input),
    }
    .text(input)
}

/// One text artifact of a capture bundle: where it sits in the bundle, and what
/// it holds.
///
/// A projection input and output at once — the hand-off reads the bundle's
/// files into these, projects them, and writes them back out under the same
/// relative paths — which is why the path travels with the text rather than
/// being re-derived on the way out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsregcmdBundleArtifact {
    /// The artifact's path relative to the bundle root.
    pub relative_path: String,
    /// The artifact's contents, as the capture wrote them.
    pub text: String,
}

/// Project every text artifact of a capture bundle into the form that may leave
/// the machine.
///
/// The bundle itself stays raw and this is the hand-off instead. Masking the
/// files where they are *stored* would change what the analyzer concludes
/// rather than what anyone publishes: the captured command output is the
/// analyzer's input, the evidence files are read back by `load_bundle_evidence`,
/// and the same command output is read again by the ESP lane's bundle reader.
/// So the working copy keeps every value the rules read, and this projects the
/// same files on the way out (issue #628).
///
/// The classification is the *analysis* one rather than the capture-text one,
/// because the bundle carries identifiers the command output does not. The
/// enrollment UPN, the SCP tenant domain and directory id, and the computer an
/// event was logged on are read out of evidence files, and the shaped grammar
/// cannot mask a value it has no label for — a bare GUID in a registry key path
/// or a JSON field is deliberately left visible, since GUIDs are usually
/// correlation keys. A literal that never enters the table therefore cannot be
/// scrubbed, which is why the assembled analysis is built unprojected and its
/// classification is applied to every artifact's text.
///
/// A capture whose command output does not parse has no assembled analysis to
/// read a classification from, and falls back to the capture text's own: its
/// evidence then loses whatever the shared grammar recognizes by shape rather
/// than shipping raw.
///
/// The artifacts are taken and returned by value so this performs no I/O — the
/// caller owns the filesystem, exactly as it does for the analysis path — and
/// so the projected set is a new value rather than a mutation of the raw one.
pub fn redacted_bundle_artifacts(
    capture_text: &str,
    evidence: DsregcmdBundleEvidence,
    artifacts: Vec<DsregcmdBundleArtifact>,
) -> Vec<DsregcmdBundleArtifact> {
    let projection = Projection {
        literals: bundle_literals(capture_text, evidence),
    };

    artifacts
        .into_iter()
        .map(|artifact| DsregcmdBundleArtifact {
            relative_path: artifact.relative_path,
            text: project_artifact_text(&projection, &artifact.text),
        })
        .collect()
}

/// Project one artifact's text, a line at a time.
///
/// Line by line because the shared grammar refuses an oversized input rather
/// than masking it: it replaces any `text` longer than its own input bound with
/// a single marker. Fed a whole artifact, a real capture's half-megabyte event
/// log came back as that marker — the evidence was lost *and* the JSON was left
/// unparseable, so a bundle reopened from the hand-off silently reached
/// different verdicts (nine findings instead of ten on the machine this was
/// measured on).
///
/// Splitting is safe for these artifacts because they put one value per line —
/// a `dsregcmd /status` field, one registry value, one JSON value — and a
/// multi-line value is escaped rather than embedded. So masking per line reaches
/// every value the whole-file pass reached, while the grammar is never handed an
/// input it would refuse.
///
/// The bound that remains is stated rather than implied: a *single* line longer
/// than the grammar's input bound would still be replaced wholesale. None of
/// these artifacts produces one, and the alternative — chunking at an arbitrary
/// offset — could split an identifier across two chunks and leave it unmasked.
fn project_artifact_text(projection: &Projection, text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| projection.text(line))
        .collect()
}

impl Projection {
    fn facts(&self, facts: &DsregcmdFacts) -> DsregcmdFacts {
        DsregcmdFacts {
            join_state: DsregcmdJoinState {
                azure_ad_joined: facts.join_state.azure_ad_joined,
                domain_joined: facts.join_state.domain_joined,
                workplace_joined: facts.join_state.workplace_joined,
                enterprise_joined: facts.join_state.enterprise_joined,
            },
            device_details: DsregcmdDeviceDetails {
                device_id: self.identity(&facts.device_details.device_id, KIND_DEVICE),
                thumbprint: self.identity(&facts.device_details.thumbprint, KIND_THUMBPRINT),
                device_certificate_validity: self
                    .text_opt(&facts.device_details.device_certificate_validity),
                key_container_id: self.text_opt(&facts.device_details.key_container_id),
                key_provider: self.text_opt(&facts.device_details.key_provider),
                tpm_protected: facts.device_details.tpm_protected,
                device_auth_status: self.text_opt(&facts.device_details.device_auth_status),
            },
            tenant_details: self.tenant_details(&facts.tenant_details),
            management_details: DsregcmdManagementDetails {
                mdm_url: self.text_opt(&facts.management_details.mdm_url),
                mdm_compliance_url: self.text_opt(&facts.management_details.mdm_compliance_url),
                mdm_tou_url: self.text_opt(&facts.management_details.mdm_tou_url),
                settings_url: self.text_opt(&facts.management_details.settings_url),
                device_management_srv_ver: self
                    .text_opt(&facts.management_details.device_management_srv_ver),
                device_management_srv_url: self
                    .text_opt(&facts.management_details.device_management_srv_url),
                device_management_srv_id: self
                    .text_opt(&facts.management_details.device_management_srv_id),
            },
            service_endpoints: DsregcmdServiceEndpoints {
                auth_code_url: self.text_opt(&facts.service_endpoints.auth_code_url),
                access_token_url: self.text_opt(&facts.service_endpoints.access_token_url),
                join_srv_version: self.text_opt(&facts.service_endpoints.join_srv_version),
                join_srv_url: self.text_opt(&facts.service_endpoints.join_srv_url),
                join_srv_id: self.text_opt(&facts.service_endpoints.join_srv_id),
                key_srv_version: self.text_opt(&facts.service_endpoints.key_srv_version),
                key_srv_url: self.text_opt(&facts.service_endpoints.key_srv_url),
                key_srv_id: self.text_opt(&facts.service_endpoints.key_srv_id),
                web_authn_srv_version: self
                    .text_opt(&facts.service_endpoints.web_authn_srv_version),
                web_authn_srv_url: self.text_opt(&facts.service_endpoints.web_authn_srv_url),
                web_authn_srv_id: self.text_opt(&facts.service_endpoints.web_authn_srv_id),
            },
            user_state: DsregcmdUserState {
                ngc_set: facts.user_state.ngc_set,
                ngc_key_id: self.text_opt(&facts.user_state.ngc_key_id),
                can_reset: self.text_opt(&facts.user_state.can_reset),
                wam_default_set: facts.user_state.wam_default_set,
                wam_default_authority: self.text_opt(&facts.user_state.wam_default_authority),
                wam_default_id: self.text_opt(&facts.user_state.wam_default_id),
                wam_default_guid: self.text_opt(&facts.user_state.wam_default_guid),
                is_device_joined: facts.user_state.is_device_joined,
                is_user_azure_ad: facts.user_state.is_user_azure_ad,
                policy_enabled: facts.user_state.policy_enabled,
                post_logon_enabled: facts.user_state.post_logon_enabled,
                device_eligible: facts.user_state.device_eligible,
                session_is_not_remote: facts.user_state.session_is_not_remote,
            },
            sso_state: DsregcmdSsoState {
                azure_ad_prt: facts.sso_state.azure_ad_prt,
                // The PRT authority is tenant-scoped: for an Entra authority
                // its path is the tenant id, and for a hybrid authority its
                // host is the organization's STS. Scrubbing the classified
                // literals leaves the host readable and removes the identity
                // embedded in it.
                azure_ad_prt_authority: self.text_opt(&facts.sso_state.azure_ad_prt_authority),
                azure_ad_prt_update_time: self.text_opt(&facts.sso_state.azure_ad_prt_update_time),
                acquire_prt_diagnostics: self.text_opt(&facts.sso_state.acquire_prt_diagnostics),
                enterprise_prt: facts.sso_state.enterprise_prt,
                enterprise_prt_update_time: self
                    .text_opt(&facts.sso_state.enterprise_prt_update_time),
                enterprise_prt_expiry_time: self
                    .text_opt(&facts.sso_state.enterprise_prt_expiry_time),
                enterprise_prt_authority: self.text_opt(&facts.sso_state.enterprise_prt_authority),
                on_prem_tgt: facts.sso_state.on_prem_tgt,
                cloud_tgt: facts.sso_state.cloud_tgt,
                adfs_refresh_token: facts.sso_state.adfs_refresh_token,
                adfs_ra_is_ready: facts.sso_state.adfs_ra_is_ready,
                kerb_top_level_names: self.text_opt(&facts.sso_state.kerb_top_level_names),
            },
            diagnostics: DsregcmdDiagnosticFields {
                previous_prt_attempt: self.text_opt(&facts.diagnostics.previous_prt_attempt),
                attempt_status: self.text_opt(&facts.diagnostics.attempt_status),
                user_identity: self.identity(&facts.diagnostics.user_identity, KIND_UPN),
                credential_type: self.text_opt(&facts.diagnostics.credential_type),
                correlation_id: self.text_opt(&facts.diagnostics.correlation_id),
                endpoint_uri: self.text_opt(&facts.diagnostics.endpoint_uri),
                http_method: self.text_opt(&facts.diagnostics.http_method),
                http_error: self.text_opt(&facts.diagnostics.http_error),
                http_status: facts.diagnostics.http_status,
                request_id: self.text_opt(&facts.diagnostics.request_id),
                diagnostics_reference: self.text_opt(&facts.diagnostics.diagnostics_reference),
                user_context: self.text_opt(&facts.diagnostics.user_context),
                client_time: self.text_opt(&facts.diagnostics.client_time),
            },
            pre_join_tests: DsregcmdPreJoinTests {
                ad_connectivity_test: self.text_opt(&facts.pre_join_tests.ad_connectivity_test),
                ad_configuration_test: self.text_opt(&facts.pre_join_tests.ad_configuration_test),
                drs_discovery_test: self.text_opt(&facts.pre_join_tests.drs_discovery_test),
                drs_connectivity_test: self.text_opt(&facts.pre_join_tests.drs_connectivity_test),
                token_acquisition_test: self.text_opt(&facts.pre_join_tests.token_acquisition_test),
                fallback_to_sync_join: self.text_opt(&facts.pre_join_tests.fallback_to_sync_join),
            },
            registration: DsregcmdRegistrationState {
                previous_registration: self.text_opt(&facts.registration.previous_registration),
                error_phase: self.text_opt(&facts.registration.error_phase),
                cert_enrollment: self.text_opt(&facts.registration.cert_enrollment),
                logon_cert_template_ready: self
                    .text_opt(&facts.registration.logon_cert_template_ready),
                pre_req_result: self.text_opt(&facts.registration.pre_req_result),
                client_error_code: self.text_opt(&facts.registration.client_error_code),
                server_error_code: self.text_opt(&facts.registration.server_error_code),
                server_message: self.text_opt(&facts.registration.server_message),
                server_error_description: self
                    .text_opt(&facts.registration.server_error_description),
            },
            post_join_diagnostics: DsregcmdPostJoinDiagnostics {
                aad_recovery_enabled: facts.post_join_diagnostics.aad_recovery_enabled,
                key_sign_test: self.text_opt(&facts.post_join_diagnostics.key_sign_test),
            },
        }
    }

    fn tenant_details(&self, tenant: &DsregcmdTenantDetails) -> DsregcmdTenantDetails {
        DsregcmdTenantDetails {
            tenant_id: self.identity(&tenant.tenant_id, KIND_TENANT),
            tenant_name: self.identity(&tenant.tenant_name, KIND_TENANT),
            domain_name: self.identity(&tenant.domain_name, KIND_TENANT),
            idp: self.text_opt(&tenant.idp),
        }
    }

    fn derived(&self, derived: &DsregcmdDerived) -> DsregcmdDerived {
        DsregcmdDerived {
            join_type: derived.join_type,
            join_type_label: self.text(&derived.join_type_label),
            dominant_phase: derived.dominant_phase,
            phase_summary: self.text(&derived.phase_summary),
            capture_confidence: derived.capture_confidence,
            capture_confidence_reason: self.text(&derived.capture_confidence_reason),
            mdm_enrolled: derived.mdm_enrolled,
            missing_mdm: derived.missing_mdm,
            compliance_url_present: derived.compliance_url_present,
            missing_compliance_url: derived.missing_compliance_url,
            azure_ad_prt_present: derived.azure_ad_prt_present,
            stale_prt: derived.stale_prt,
            prt_last_update: derived.prt_last_update,
            prt_reference_time: derived.prt_reference_time,
            prt_age_hours: derived.prt_age_hours,
            tpm_protected: derived.tpm_protected,
            certificate_valid_from: derived.certificate_valid_from,
            certificate_valid_to: derived.certificate_valid_to,
            certificate_expiring_soon: derived.certificate_expiring_soon,
            certificate_days_remaining: derived.certificate_days_remaining,
            network_error_code: self.text_opt(&derived.network_error_code),
            has_network_error: derived.has_network_error,
            remote_session_system: derived.remote_session_system,
        }
    }

    fn diagnostics(
        &self,
        diagnostics: &[DsregcmdDiagnosticInsight],
    ) -> Vec<DsregcmdDiagnosticInsight> {
        diagnostics
            .iter()
            .map(|diagnostic| DsregcmdDiagnosticInsight {
                id: diagnostic.id.clone(),
                severity: diagnostic.severity.clone(),
                category: diagnostic.category.clone(),
                title: self.text(&diagnostic.title),
                summary: self.text(&diagnostic.summary),
                evidence: self.texts(&diagnostic.evidence),
                next_checks: self.texts(&diagnostic.next_checks),
                suggested_fixes: self.texts(&diagnostic.suggested_fixes),
            })
            .collect()
    }

    fn policy_evidence(&self, policy: &DsregcmdWhfbPolicyEvidence) -> DsregcmdWhfbPolicyEvidence {
        DsregcmdWhfbPolicyEvidence {
            policy_enabled: self.policy_value(&policy.policy_enabled),
            post_logon_enabled: self.policy_value(&policy.post_logon_enabled),
            pin_recovery_enabled: self.policy_value(&policy.pin_recovery_enabled),
            require_security_device: self.policy_value(&policy.require_security_device),
            use_certificate_for_on_prem_auth: self
                .policy_value(&policy.use_certificate_for_on_prem_auth),
            use_cloud_trust_for_on_prem_auth: self
                .policy_value(&policy.use_cloud_trust_for_on_prem_auth),
            artifact_paths: self.texts(&policy.artifact_paths),
        }
    }

    fn policy_value(&self, value: &DsregcmdPolicyEvidenceValue) -> DsregcmdPolicyEvidenceValue {
        DsregcmdPolicyEvidenceValue {
            display_value: value.display_value,
            current_value: value.current_value,
            provider_value: value.provider_value,
            source: value.source,
            note: self.text_opt(&value.note),
        }
    }

    fn os_version(&self, os: &DsregcmdOsVersionEvidence) -> DsregcmdOsVersionEvidence {
        DsregcmdOsVersionEvidence {
            current_build: self.text_opt(&os.current_build),
            display_version: self.text_opt(&os.display_version),
            product_name: self.text_opt(&os.product_name),
            ubr: os.ubr,
            edition_id: self.text_opt(&os.edition_id),
        }
    }

    fn proxy_evidence(&self, proxy: &DsregcmdProxyEvidence) -> DsregcmdProxyEvidence {
        DsregcmdProxyEvidence {
            proxy_enabled: proxy.proxy_enabled,
            proxy_server: self.text_opt(&proxy.proxy_server),
            proxy_override: self.text_opt(&proxy.proxy_override),
            auto_config_url: self.text_opt(&proxy.auto_config_url),
            wpad_detected: proxy.wpad_detected,
            winhttp_proxy: self.text_opt(&proxy.winhttp_proxy),
        }
    }

    fn enrollment_evidence(
        &self,
        enrollment: &DsregcmdEnrollmentEvidence,
    ) -> DsregcmdEnrollmentEvidence {
        DsregcmdEnrollmentEvidence {
            enrollment_count: enrollment.enrollment_count,
            enrollments: enrollment
                .enrollments
                .iter()
                .map(|entry| self.enrollment_entry(entry))
                .collect(),
        }
    }

    fn enrollment_entry(&self, entry: &DsregcmdEnrollmentEntry) -> DsregcmdEnrollmentEntry {
        DsregcmdEnrollmentEntry {
            // The enrollment GUID is an MDM correlation key, not an
            // organization identifier: it joins enrollment records inside one
            // export and the shared grammar documents correlation keys as
            // surviving.
            guid: self.text_opt(&entry.guid),
            upn: self.identity(&entry.upn, KIND_UPN),
            provider_id: self.text_opt(&entry.provider_id),
            enrollment_state: entry.enrollment_state,
        }
    }

    fn active_evidence(&self, active: &DsregcmdActiveEvidence) -> DsregcmdActiveEvidence {
        DsregcmdActiveEvidence {
            connectivity_tests: active
                .connectivity_tests
                .iter()
                .map(|test| self.connectivity_result(test))
                .collect(),
            scp_query: active.scp_query.as_ref().map(|scp| self.scp_query(scp)),
        }
    }

    fn connectivity_result(&self, test: &DsregcmdConnectivityResult) -> DsregcmdConnectivityResult {
        DsregcmdConnectivityResult {
            endpoint: self.text(&test.endpoint),
            reachable: test.reachable,
            status_code: test.status_code,
            latency_ms: test.latency_ms,
            error_message: self.text_opt(&test.error_message),
            timestamp: self.text(&test.timestamp),
        }
    }

    fn scp_query(&self, scp: &DsregcmdScpQueryResult) -> DsregcmdScpQueryResult {
        DsregcmdScpQueryResult {
            scp_found: scp.scp_found,
            tenant_domain: self.identity(&scp.tenant_domain, KIND_TENANT),
            azuread_id: self.identity(&scp.azuread_id, KIND_TENANT),
            keywords: self.texts(&scp.keywords),
            domain_controller: self.text_opt(&scp.domain_controller),
            error: self.text_opt(&scp.error),
        }
    }

    fn scheduled_task_evidence(
        &self,
        scheduled: &DsregcmdScheduledTaskEvidence,
    ) -> DsregcmdScheduledTaskEvidence {
        DsregcmdScheduledTaskEvidence {
            // EnterpriseMgmt task GUIDs are schedule identifiers; the shared
            // grammar documents GUIDs as correlation keys rather than
            // organization identifiers, and the event-log diagnostics match
            // enrollment records to them by value.
            enterprise_mgmt_guids: scheduled.enterprise_mgmt_guids.clone(),
        }
    }

    fn event_log_analysis(&self, analysis: &EventLogAnalysis) -> EventLogAnalysis {
        EventLogAnalysis {
            source_kind: analysis.source_kind,
            entries: analysis
                .entries
                .iter()
                .map(|entry| self.event_log_entry(entry))
                .collect(),
            channel_summaries: analysis
                .channel_summaries
                .iter()
                .map(|summary| self.event_log_channel_summary(summary))
                .collect(),
            correlation_links: analysis
                .correlation_links
                .iter()
                .map(|link| self.event_log_correlation_link(link))
                .collect(),
            parsed_file_count: analysis.parsed_file_count,
            total_entry_count: analysis.total_entry_count,
            error_entry_count: analysis.error_entry_count,
            warning_entry_count: analysis.warning_entry_count,
            timestamp_bounds: analysis
                .timestamp_bounds
                .as_ref()
                .map(|bounds| self.timestamp_bounds(bounds)),
            live_query: analysis
                .live_query
                .as_ref()
                .map(|live| self.event_log_live_query(live)),
        }
    }

    fn event_log_entry(&self, entry: &EventLogEntry) -> EventLogEntry {
        EventLogEntry {
            id: entry.id,
            channel: entry.channel.clone(),
            channel_display: self.text(&entry.channel_display),
            provider: self.text(&entry.provider),
            event_id: entry.event_id,
            severity: entry.severity,
            timestamp: self.text(&entry.timestamp),
            computer: self.identity(&entry.computer, KIND_HOST),
            message: self.text(&entry.message),
            // A correlation activity id is an event-log correlation key.
            correlation_activity_id: self.text_opt(&entry.correlation_activity_id),
            source_file: self.text(&entry.source_file),
        }
    }

    fn event_log_channel_summary(
        &self,
        summary: &EventLogChannelSummary,
    ) -> EventLogChannelSummary {
        EventLogChannelSummary {
            channel: summary.channel.clone(),
            channel_display: self.text(&summary.channel_display),
            entry_count: summary.entry_count,
            error_count: summary.error_count,
            warning_count: summary.warning_count,
            timestamp_bounds: summary
                .timestamp_bounds
                .as_ref()
                .map(|bounds| self.timestamp_bounds(bounds)),
            source_file: self.text(&summary.source_file),
        }
    }

    fn event_log_correlation_link(
        &self,
        link: &EventLogCorrelationLink,
    ) -> EventLogCorrelationLink {
        EventLogCorrelationLink {
            event_log_entry_id: link.event_log_entry_id,
            linked_intune_event_id: link.linked_intune_event_id,
            linked_diagnostic_id: link.linked_diagnostic_id.clone(),
            correlation_kind: link.correlation_kind,
            time_delta_secs: link.time_delta_secs,
        }
    }

    fn event_log_live_query(&self, live: &EventLogLiveQueryMetadata) -> EventLogLiveQueryMetadata {
        EventLogLiveQueryMetadata {
            attempted_channel_count: live.attempted_channel_count,
            successful_channel_count: live.successful_channel_count,
            channels_with_results_count: live.channels_with_results_count,
            failed_channel_count: live.failed_channel_count,
            per_channel_entry_limit: live.per_channel_entry_limit,
            channels: live
                .channels
                .iter()
                .map(|channel| self.event_log_live_query_channel(channel))
                .collect(),
        }
    }

    fn event_log_live_query_channel(
        &self,
        channel: &EventLogLiveQueryChannelResult,
    ) -> EventLogLiveQueryChannelResult {
        EventLogLiveQueryChannelResult {
            channel: channel.channel.clone(),
            channel_display: self.text(&channel.channel_display),
            channel_path: self.text(&channel.channel_path),
            source_file: self.text(&channel.source_file),
            status: channel.status,
            entry_count: channel.entry_count,
            error_message: self.text_opt(&channel.error_message),
        }
    }

    fn timestamp_bounds(&self, bounds: &IntuneTimestampBounds) -> IntuneTimestampBounds {
        IntuneTimestampBounds {
            first_timestamp: self.text_opt(&bounds.first_timestamp),
            last_timestamp: self.text_opt(&bounds.last_timestamp),
        }
    }
}

/// Read the identity values out of the fields this projection masks as typed
/// fields, so each literal is available for the free-text scrub.
///
/// One list, read twice: a value cannot be masked as a typed field without its
/// literal also being scrubbed out of narrative text.
fn collect_identity_literals(result: &DsregcmdAnalysisResult) -> IdentityLiterals {
    let mut literals = IdentityLiterals::default();
    collect_fact_literals(&result.facts, &mut literals);

    if let Some(enrollment) = &result.enrollment_evidence {
        for entry in &enrollment.enrollments {
            if let Some(upn) = entry.upn.as_deref() {
                literals.push(upn, KIND_UPN, LiteralOrigin::TypedSensitive);
            }
        }
    }

    if let Some(active) = &result.active_evidence {
        collect_active_evidence_into(active, &mut literals);
    }

    if let Some(events) = &result.event_log_analysis {
        collect_event_log_into(events, &mut literals);
    }

    literals
}

/// The identity literals one capture's command output contributes.
///
/// Output that does not parse is not an error here; the classification simply
/// has nothing to read.
fn capture_literals(capture_output: &str) -> IdentityLiterals {
    let mut literals = IdentityLiterals::default();
    if let Ok(facts) = super::parser::parse_dsregcmd(capture_output) {
        collect_fact_literals(&facts, &mut literals);
    }
    literals
}

/// The identity literals one whole capture contributes.
///
/// The assembled analysis already carries every class this lane classifies —
/// the command output's own facts, the enrollment UPNs, the SCP domain and
/// directory id, and the event-log computer names — so its classification is
/// read directly rather than rebuilt beside it. A second collector would be a
/// second list, and a class added to the analysis would then reach the typed
/// projection while quietly missing the hand-off.
///
/// Output the parser cannot read assembles no analysis to read from, and falls
/// back to the capture text's own classification.
fn bundle_literals(capture_text: &str, evidence: DsregcmdBundleEvidence) -> IdentityLiterals {
    match super::analyze_text_with_evidence_preserving_local_values(capture_text, evidence) {
        Ok(result) => collect_identity_literals(&result),
        Err(_) => capture_literals(capture_text),
    }
}

fn collect_fact_literals(facts: &DsregcmdFacts, literals: &mut IdentityLiterals) {
    for (value, kind) in [
        (facts.tenant_details.tenant_id.as_deref(), KIND_TENANT),
        (facts.tenant_details.tenant_name.as_deref(), KIND_TENANT),
        (facts.tenant_details.domain_name.as_deref(), KIND_TENANT),
        (facts.device_details.device_id.as_deref(), KIND_DEVICE),
        (facts.device_details.thumbprint.as_deref(), KIND_THUMBPRINT),
        (facts.diagnostics.user_identity.as_deref(), KIND_UPN),
    ] {
        if let Some(value) = value {
            literals.push(value, kind, LiteralOrigin::TypedSensitive);
        }
    }
}

fn collect_active_evidence_into(
    evidence: &DsregcmdActiveEvidence,
    literals: &mut IdentityLiterals,
) {
    if let Some(scp) = &evidence.scp_query {
        if let Some(domain) = scp.tenant_domain.as_deref() {
            literals.push(domain, KIND_TENANT, LiteralOrigin::TypedSensitive);
        }
        if let Some(azuread_id) = scp.azuread_id.as_deref() {
            literals.push(azuread_id, KIND_TENANT, LiteralOrigin::TypedSensitive);
        }
    }
}

fn collect_event_log_into(analysis: &EventLogAnalysis, literals: &mut IdentityLiterals) {
    for entry in &analysis.entries {
        if let Some(computer) = entry.computer.as_deref() {
            literals.push(computer, KIND_HOST, LiteralOrigin::TypedSensitive);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            analyze_text, analyze_text_preserving_local_values, analyze_text_with_evidence,
            models::{
                DsregcmdActiveEvidence, DsregcmdAnalysisResult, DsregcmdBundleEvidence,
                DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdScpQueryResult,
            },
        },
        redacted_bundle_artifacts, redacted_status_text, DsregcmdBundleArtifact, IdentityLiterals,
        LiteralOrigin, KIND_HOST, KIND_TENANT,
    };
    use crate::intune::models::{
        EventLogAnalysis, EventLogAnalysisSource, EventLogChannel, EventLogEntry, EventLogSeverity,
    };

    /// A capture carrying one identifier of every class this projection masks.
    const IDENTITY_CAPTURE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 TenantName : contoso.onmicrosoft.com
 DomainName : corp.contoso.com
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 Thumbprint : 8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D
 User Identity : adele.vance@contoso.onmicrosoft.com
 User Context : SYSTEM
"#;

    /// The same, with the identity shape the built-in-Administrator rule reads.
    const SID_CAPTURE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 User Identity : S-1-5-21-3623811015-3361044348-30300820-500
"#;

    const USER_SID: &str = "S-1-5-21-3623811015-3361044348-30300820-500";

    const PLANTED_IDENTIFIERS: &[(&str, &str)] = &[
        ("tenant id", "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90"),
        ("tenant domain", "contoso.onmicrosoft.com"),
        ("on-premises domain", "corp.contoso.com"),
        ("device id", "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b"),
        (
            "certificate thumbprint",
            "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D",
        ),
        ("user principal name", "adele.vance@contoso.onmicrosoft.com"),
    ];

    /// The canary: the unprojected analysis is crate-internal, so proving that
    /// each planted value really does reach the analysis as that identifier —
    /// rather than the export assertion passing because the fixture stopped
    /// carrying it — can only be asserted from inside.
    #[test]
    fn the_unprojected_analysis_carries_every_identity_the_projection_masks() {
        let local = json(&analyze_text_preserving_local_values(IDENTITY_CAPTURE).expect("parses"));
        let published = json(&analyze_text(IDENTITY_CAPTURE).expect("parses"));

        for (label, marker) in PLANTED_IDENTIFIERS {
            assert!(
                local.contains(marker),
                "the fixture no longer reaches the analysis as the {label}; the export check is vacuous"
            );
            assert!(
                !published.contains(marker),
                "the published analysis leaks the {label} ({marker})"
            );
        }
    }

    /// Rules that read an identifier's shape rather than its presence run on the
    /// unprojected values, so masking a value must not cost the diagnosis it
    /// produced. This is why the assembly lives here instead of in a caller.
    #[test]
    fn a_sid_user_identity_is_masked_without_losing_the_diagnosis_it_produced() {
        let local = analyze_text_preserving_local_values(SID_CAPTURE).expect("parses");
        let published = analyze_text(SID_CAPTURE).expect("parses");

        assert!(
            local
                .diagnostics
                .iter()
                .any(|issue| issue.id == "builtin-admin-cannot-join"),
            "the SID no longer reaches the built-in-Administrator rule"
        );
        assert!(
            !json(&published).contains(USER_SID),
            "the published analysis leaks the user SID ({USER_SID})"
        );
        assert!(
            published
                .diagnostics
                .iter()
                .any(|issue| issue.id == "builtin-admin-cannot-join"),
            "the diagnosis the raw SID produced was lost when the value was masked"
        );
    }

    #[test]
    fn projecting_does_not_drop_or_rename_a_diagnostic() {
        let local = analyze_text_preserving_local_values(IDENTITY_CAPTURE).expect("parses");
        let published = analyze_text(IDENTITY_CAPTURE).expect("parses");

        let local_ids = diagnostic_ids(&local);
        let published_ids = diagnostic_ids(&published);

        assert!(!local_ids.is_empty(), "the fixture produced no diagnostics");
        assert_eq!(local_ids, published_ids);
    }

    /// The capture text is the analyzer's input and keeps its values, so the
    /// projection of it is a separate entry point with the same classification.
    #[test]
    fn the_projected_status_text_keeps_the_capture_and_loses_the_identities() {
        let projected = redacted_status_text(IDENTITY_CAPTURE);

        for (label, marker) in PLANTED_IDENTIFIERS {
            assert!(
                !projected.contains(marker),
                "the projected status text leaks the {label} ({marker})"
            );
        }
        assert!(
            projected.contains("AzureAdJoined : YES")
                && projected.contains("User Context : SYSTEM"),
            "over-masking: the capture's own content was lost: {projected}"
        );
    }

    /// A classified literal whose letters are not all ASCII must still match the
    /// narrative spelling of it that differs only in case, or the export carries
    /// the identifier after all — the shared grammar masks only shapes it
    /// recognizes, and a bare display name is not one.
    #[test]
    fn a_non_ascii_identity_is_scrubbed_whatever_its_case_in_the_narrative() {
        let capture = " TenantName : Ünïcode.Example\n \
                       Server Message : discovery failed for ünïcode.example\n";
        let projected = redacted_status_text(capture);

        assert!(
            !projected.contains("Ünïcode") && !projected.contains("ünïcode"),
            "a differently-cased spelling of a non-ASCII identity survived: {projected:?}"
        );
        assert!(
            projected.matches("[tenant:").count() == 2,
            "expected both spellings at the typed token: {projected:?}"
        );
        assert!(
            projected.contains("discovery failed for"),
            "over-masking: the narrative around the identity was lost: {projected:?}"
        );
    }

    /// One canonical identity reaches exactly one token, whichever spelling the
    /// capture used and wherever it appears. Two typed fields that spell the same
    /// identity differently, plus a narrative mention, must all carry the same
    /// token — otherwise the export shows one tenant as two.
    #[test]
    fn one_identity_reaches_one_token_whatever_its_case() {
        let capture = " TenantName : ÉLODIE.Example\n \
                       DomainName : élodie.example\n \
                       Server Message : retry against ÉLODIE.Example failed\n";
        let published = json(&analyze_text(capture).expect("parses"));

        let tokens = tokens_of_kind(&published, "tenant");
        assert_eq!(
            tokens.len(),
            3,
            "expected both typed fields and the narrative to be masked: {published}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// A missing value is reported as missing, not as a masked identity.
    ///
    /// The evidence for the `missing-tenant` diagnostic is the analyzer's own
    /// render of an absent field. If the projection masks that render, the export
    /// contradicts itself — the rule says the capture held no `TenantId` while
    /// the evidence shows a tenant token — and it invents an identity the device
    /// never presented.
    #[test]
    fn a_missing_value_is_evidence_of_absence_not_a_masked_identity() {
        let published = analyze_text(" AzureAdJoined : NO\n DomainJoined : NO\n")
            .expect("a capture with no tenant or device id analyzes");

        let missing_tenant = published
            .diagnostics
            .iter()
            .find(|issue| issue.id == "missing-tenant")
            .expect("the missing tenant id is diagnosed");

        assert_eq!(missing_tenant.evidence, vec!["TenantId: (missing)"]);
        assert!(
            !json(&published).contains("[tenant:"),
            "the export claims a tenant identity the capture never held: {}",
            json(&published)
        );
    }

    /// One text reaches one token even when two fields classify it under two
    /// kinds.
    ///
    /// The kind is a property of the *field*; the token is a property of the
    /// *value*, and a narrative mention carries no field at all. Keying the table
    /// by kind would leave a mention of `contoso.example` in prose choosing
    /// between a `[tenant:…]` and a `[host:…]` token with no field to decide it,
    /// which is the one-identity-two-tokens failure this table exists to prevent.
    /// So the field that classifies a value first decides its token, and a later
    /// field holding the same value follows it rather than minting a second.
    /// A host value also derives its short form, which is a second entry on
    /// purpose — they are two different literals naming one machine. What must
    /// not happen is two entries for the *same* text.
    #[test]
    fn one_text_reaches_one_token_when_two_kinds_classify_it() {
        let mut literals = IdentityLiterals::default();
        literals.push(
            "contoso.example",
            KIND_TENANT,
            LiteralOrigin::TypedSensitive,
        );
        literals.push("contoso.example", KIND_HOST, LiteralOrigin::TypedSensitive);

        let token = literals
            .token_for("contoso.example")
            .expect("the domain was classified");
        assert_eq!(
            literals
                .values
                .iter()
                .filter(|entry| entry.literal == "contoso.example")
                .count(),
            1,
            "one text, one entry"
        );
        assert!(
            token.starts_with("[tenant:"),
            "the first classification names the token: {token}"
        );
        assert_eq!(
            literals.token_for("CONTOSO.Example"),
            Some(token),
            "another casing follows the same token"
        );
        assert_eq!(
            literals.token_for("contoso"),
            Some(token),
            "the short form derived from the host reaches the token of the value it came from, \
             rather than minting a second token for one machine"
        );
    }

    /// `ΣΟΦΟΥΣ.Example` in capitals: `Σ` U+03A3, `Ο` U+039F, `Φ` U+03A6,
    /// `Υ` U+03A5, and a final `Σ` U+03A3 that the narrative renders as `ς`.
    const CAPITAL_SIGMA_IDENTITY: &str = "\u{3A3}\u{39F}\u{3A6}\u{39F}\u{3A5}\u{3A3}.Example";

    /// The same name written in lower case with Greek's final sigma: it ends in
    /// `ς` U+03C2, which lowercasing `Σ` never produces.
    const FINAL_SIGMA_NARRATIVE: &str = "\u{3C3}\u{3BF}\u{3C6}\u{3BF}\u{3C5}\u{3C2}.example";

    /// `Σ` and final `ς` are caseless-equal, but they are two different
    /// lowercase letters, so a comparison that only folds down keeps them apart
    /// and the narrative spelling of the identity survives.
    #[test]
    fn a_final_sigma_narrative_reaches_the_capital_sigma_token() {
        let capture = format!(
            " TenantName : {CAPITAL_SIGMA_IDENTITY}\n \
               Server Message : discovery failed for {FINAL_SIGMA_NARRATIVE}\n"
        );
        let projected = redacted_status_text(&capture);

        assert!(
            !projected.contains(CAPITAL_SIGMA_IDENTITY)
                && !projected.contains(FINAL_SIGMA_NARRATIVE),
            "a sigma spelling of one identity survived: {projected:?}"
        );
        let tokens = tokens_of_kind(&projected, "tenant");
        assert_eq!(
            tokens.len(),
            2,
            "expected both spellings at the typed token: {projected:?}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// `İSTANBUL-PC` with the precomposed dotted capital I, which is U+0130.
    const DOTTED_CAPITAL_IDENTITY: &str = "\u{130}STANBUL-PC";

    /// The same name written with the capital I intact but lower case: `İ` then
    /// `stanbul-pc`. This is the spelling the identity's own lowercasing does not
    /// produce, so matching it needs the precomposed character understood as the
    /// sequence its case mapping stands for.
    const PRECOMPOSED_NARRATIVE: &str = "\u{130}stanbul-pc";

    /// The same name with that character's decomposition written out: `i`
    /// followed by U+0307, which is what lowercasing U+0130 produces.
    const DECOMPOSED_NARRATIVE: &str = "i\u{307}stanbul-pc";

    /// A character whose case mapping is a sequence must match the other side
    /// spelling that sequence out, in either direction, or the precomposed and
    /// decomposed spellings of one identity are two identities to this
    /// projection. A device name is where this lane meets a value like
    /// `İSTANBUL-PC`: the computer an event log record was written on, and the
    /// same name spelled inside the record's message.
    #[test]
    fn a_dotted_capital_i_reaches_one_token_whichever_way_it_is_spelled() {
        let events = EventLogAnalysis {
            source_kind: EventLogAnalysisSource::Live,
            entries: vec![EventLogEntry {
                id: 1,
                channel: EventLogChannel::AadOperational,
                channel_display: "AAD Operational".to_string(),
                provider: "Microsoft-Windows-AAD".to_string(),
                event_id: 1103,
                severity: EventLogSeverity::Error,
                timestamp: "2026-08-26T09:15:00Z".to_string(),
                computer: Some(DOTTED_CAPITAL_IDENTITY.to_string()),
                message: format!(
                    "registration failed on {PRECOMPOSED_NARRATIVE} and again on {DECOMPOSED_NARRATIVE}"
                ),
                correlation_activity_id: None,
                source_file: "AAD.evtx".to_string(),
            }],
            ..EventLogAnalysis::default()
        };
        let evidence = DsregcmdBundleEvidence {
            event_log_analysis: Some(events),
            ..DsregcmdBundleEvidence::default()
        };
        let published = {
            let analysis = analyze_text_with_evidence(IDENTITY_CAPTURE, evidence)
                .expect("the dsregcmd capture analyzes");
            serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
        };

        assert!(
            !published.contains(DOTTED_CAPITAL_IDENTITY)
                && !published.contains(PRECOMPOSED_NARRATIVE)
                && !published.contains(DECOMPOSED_NARRATIVE),
            "a dotted-I spelling of one identity survived: {published}"
        );
        let tokens = tokens_of_kind(&published, "host");
        assert_eq!(
            tokens.len(),
            3,
            "expected the typed host and both message spellings masked: {published}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one identity reached more than one token: {tokens:?}"
        );
    }

    /// The boundary of the rule above, asserted rather than assumed.
    ///
    /// A pair only bridges when the case mapping of one side spells the other
    /// out. `ß` (U+00DF) and `SS` do not: one character cannot be matched
    /// against two, and `ß`'s uppercase is `SS` while `S`'s is `S`, so neither
    /// the character comparison nor the mapping consumption reaches it. The
    /// same holds for the `ﬀ`-style ligatures and for text that differs by
    /// normalization rather than by case (`é` written as `e` plus U+0301).
    /// Closing those needs a case folding or normalization table — a dependency
    /// this crate does not have and should not acquire for this — so the
    /// limitation is pinned here instead of being implied.
    #[test]
    fn a_length_changing_case_pair_stays_out_of_reach() {
        let capture = " TenantName : Straße.Example\n \
                       Server Message : retry against strasse.example failed\n";
        let projected = redacted_status_text(capture);

        assert!(
            !projected.contains("Straße.Example"),
            "the typed field itself must still be masked: {projected:?}"
        );
        assert!(
            projected.contains("strasse.example"),
            "this pair is covered after all; the limitation note and this test need updating: {projected:?}"
        );
    }

    // -----------------------------------------------------------------------
    // The bundle hand-off (issue #628)
    // -----------------------------------------------------------------------

    const BUNDLE_TENANT_ID: &str = "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90";
    const BUNDLE_TENANT_DOMAIN: &str = "contoso.onmicrosoft.com";
    const BUNDLE_ON_PREMISES_DOMAIN: &str = "corp.contoso.com";
    const BUNDLE_DEVICE_ID: &str = "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b";
    const BUNDLE_THUMBPRINT: &str = "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D";
    const BUNDLE_ENROLLMENT_UPN: &str = "bruno.diaz@contoso.onmicrosoft.com";
    const BUNDLE_ENROLLMENT_GUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const BUNDLE_EVENT_COMPUTER: &str = "HELPDESK-LAPTOP01.corp.contoso.com";

    /// The tenant id sits in the bundle three times, and only one of them is a
    /// labelled field: `TenantId :` in the command output, the unlabelled
    /// registry key path under `JoinInfo`, and the SCP query's directory id.
    const BUNDLE_TENANT_ID_OCCURRENCES: usize = 3;

    /// Each identifier the hand-off is required to keep out of a shareable
    /// artefact, with the class it belongs to for the failure message.
    const BUNDLE_IDENTIFIERS: &[(&str, &str)] = &[
        ("tenant id", BUNDLE_TENANT_ID),
        ("tenant domain", BUNDLE_TENANT_DOMAIN),
        ("on-premises domain", BUNDLE_ON_PREMISES_DOMAIN),
        ("device id", BUNDLE_DEVICE_ID),
        ("certificate thumbprint", BUNDLE_THUMBPRINT),
        ("enrollment user principal name", BUNDLE_ENROLLMENT_UPN),
        ("event log computer name", BUNDLE_EVENT_COMPUTER),
        ("user SID", USER_SID),
    ];

    /// The bundle's command output, carrying one identifier of every class this
    /// projection masks and the SID spelling that makes the
    /// built-in-Administrator rule fire from the *raw* working copy.
    ///
    /// The join flags are the ones that rule is gated on — it reports only a
    /// device that did not reach Azure AD Join — so a SID reaching this fixture
    /// is observable as a verdict rather than as a field.
    fn bundle_capture() -> String {
        format!(
            "\n AzureAdJoined : NO\n \
             DomainJoined : YES\n \
             TenantId : {BUNDLE_TENANT_ID}\n \
             TenantName : {BUNDLE_TENANT_DOMAIN}\n \
             DomainName : {BUNDLE_ON_PREMISES_DOMAIN}\n \
             DeviceId : {BUNDLE_DEVICE_ID}\n \
             Thumbprint : {BUNDLE_THUMBPRINT}\n \
             User Identity : {USER_SID}\n \
             User Context : SYSTEM\n"
        )
    }

    /// A capture bundle as the hand-off sees it: the command output and every
    /// evidence file, each still carrying what the capture printed.
    ///
    /// The evidence files are where the command output does not reach — the
    /// enrollment UPN, the SCP tenant domain and directory id, and the computer
    /// an event was logged on — because the shaped grammar cannot mask a value
    /// it has no label for, and a bare GUID is deliberately left visible.
    fn unprojected_bundle_artifacts() -> Vec<DsregcmdBundleArtifact> {
        vec![
            DsregcmdBundleArtifact {
                relative_path: "manifest.json".to_string(),
                text: "{\n  \"manifestPath\": \"manifest.json\",\n  \"source\": \"live-dsregcmd-capture\"\n}\n"
                    .to_string(),
            },
            DsregcmdBundleArtifact {
                relative_path: "evidence/command-output/dsregcmd-status.txt".to_string(),
                text: bundle_capture(),
            },
            DsregcmdBundleArtifact {
                relative_path: "evidence/registry/cdj-joininfo.reg".to_string(),
                text: format!(
                    "Windows Registry Editor Version 5.00\n\n\
                     [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo\\{BUNDLE_TENANT_ID}]\n\
                     \"UserEmail\"=\"{BUNDLE_ENROLLMENT_UPN}\"\n\
                     \"IdpDomain\"=\"{BUNDLE_TENANT_DOMAIN}\"\n"
                ),
            },
            DsregcmdBundleArtifact {
                relative_path: "evidence/registry/enrollments.reg".to_string(),
                text: format!(
                    "Windows Registry Editor Version 5.00\n\n\
                     [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\{{{BUNDLE_ENROLLMENT_GUID}}}]\n\
                     \"UPN\"=\"{BUNDLE_ENROLLMENT_UPN}\"\n"
                ),
            },
            DsregcmdBundleArtifact {
                relative_path: "evidence/connectivity/scp-query.json".to_string(),
                text: format!(
                    "{{\n  \"scpFound\": true,\n  \"tenantDomain\": \"{BUNDLE_TENANT_DOMAIN}\",\n  \"azureadId\": \"{BUNDLE_TENANT_ID}\",\n  \"domainController\": \"dc1.{BUNDLE_ON_PREMISES_DOMAIN}\"\n}}\n"
                ),
            },
            DsregcmdBundleArtifact {
                relative_path: "evidence/event-logs/dsregcmd-events.json".to_string(),
                text: format!(
                    "{{\n  \"entries\": [\n    {{\n      \"computer\": \"{BUNDLE_EVENT_COMPUTER}\",\n      \"message\": \"registration failed for {BUNDLE_ENROLLMENT_UPN}\"\n    }}\n  ]\n}}\n"
                ),
            },
        ]
    }

    /// The typed evidence the same files deserialize into, as the application
    /// reads it back before analyzing.
    fn bundle_evidence() -> DsregcmdBundleEvidence {
        DsregcmdBundleEvidence {
            enrollment_evidence: Some(DsregcmdEnrollmentEvidence {
                enrollment_count: 1,
                enrollments: vec![DsregcmdEnrollmentEntry {
                    guid: Some(BUNDLE_ENROLLMENT_GUID.to_string()),
                    upn: Some(BUNDLE_ENROLLMENT_UPN.to_string()),
                    provider_id: Some("MS DM Server".to_string()),
                    enrollment_state: Some(1),
                }],
            }),
            active_evidence: Some(DsregcmdActiveEvidence {
                connectivity_tests: Vec::new(),
                scp_query: Some(DsregcmdScpQueryResult {
                    scp_found: true,
                    tenant_domain: Some(BUNDLE_TENANT_DOMAIN.to_string()),
                    azuread_id: Some(BUNDLE_TENANT_ID.to_string()),
                    keywords: Vec::new(),
                    domain_controller: Some(format!("dc1.{BUNDLE_ON_PREMISES_DOMAIN}")),
                    error: None,
                }),
            }),
            event_log_analysis: Some(EventLogAnalysis {
                source_kind: EventLogAnalysisSource::Live,
                entries: vec![EventLogEntry {
                    id: 1,
                    channel: EventLogChannel::AadOperational,
                    channel_display: "AAD Operational".to_string(),
                    provider: "Microsoft-Windows-AAD".to_string(),
                    event_id: 1103,
                    severity: EventLogSeverity::Error,
                    timestamp: "2026-08-26T09:15:00Z".to_string(),
                    computer: Some(BUNDLE_EVENT_COMPUTER.to_string()),
                    message: format!("registration failed for {BUNDLE_ENROLLMENT_UPN}"),
                    correlation_activity_id: None,
                    source_file: "AAD.evtx".to_string(),
                }],
                ..EventLogAnalysis::default()
            }),
            ..DsregcmdBundleEvidence::default()
        }
    }

    fn joined_artifact_text(artifacts: &[DsregcmdBundleArtifact]) -> String {
        artifacts
            .iter()
            .map(|artifact| artifact.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The canary: the fixture really does carry each identifier in cleartext
    /// before the projection, so the hand-off assertion below cannot pass
    /// vacuously because a value stopped being planted.
    #[test]
    fn the_unprojected_bundle_carries_every_identifier_the_hand_off_must_mask() {
        let raw = joined_artifact_text(&unprojected_bundle_artifacts());

        for (label, marker) in BUNDLE_IDENTIFIERS {
            assert!(
                raw.contains(marker),
                "the bundle fixture no longer carries the {label} ({marker}); the hand-off assertion is vacuous"
            );
        }
        assert_eq!(
            raw.matches(BUNDLE_TENANT_ID).count(),
            BUNDLE_TENANT_ID_OCCURRENCES,
            "the fixture no longer plants the tenant id in all three shapes the hand-off has to cover"
        );
    }

    /// The acceptance criteria's first half: the shareable artefact carries no
    /// cleartext tenant id, domain, device id, thumbprint, user principal name
    /// or SID — including the occurrences no shaped rule reaches.
    #[test]
    fn the_hand_off_keeps_every_identifier_out_of_the_shareable_bundle() {
        let projected = redacted_bundle_artifacts(
            &bundle_capture(),
            bundle_evidence(),
            unprojected_bundle_artifacts(),
        );
        let shareable = joined_artifact_text(&projected);

        for (label, marker) in BUNDLE_IDENTIFIERS {
            assert!(
                !shareable.contains(marker),
                "the shareable bundle leaks the {label} ({marker}): {shareable}"
            );
        }
    }

    /// The acceptance criteria's second half: the analyzer still reaches its
    /// existing verdicts, because the projection is built *from* the raw values
    /// at the hand-off rather than written back over the working copy.
    #[test]
    fn projecting_the_hand_off_leaves_the_raw_bundle_reaching_its_verdicts() {
        let analysis = analyze_text_with_evidence(&bundle_capture(), bundle_evidence())
            .expect("the bundle fixture analyzes");

        assert!(
            diagnostic_ids(&analysis).contains(&"builtin-admin-cannot-join"),
            "the SID in the raw capture no longer reaches the built-in-Administrator rule"
        );
        assert!(
            analysis.enrollment_evidence.is_some()
                && analysis.active_evidence.is_some()
                && analysis.event_log_analysis.is_some(),
            "the bundle evidence no longer reaches the analysis"
        );
        assert!(
            !json(&analysis).contains(BUNDLE_ENROLLMENT_UPN),
            "the published analysis leaks the enrollment user principal name"
        );
    }

    /// The hand-off stays usable: every artifact keeps its path, and the bundle
    /// classification agrees with the capture-text one, so a value classified
    /// from the command output reaches the token it always reached.
    #[test]
    fn the_hand_off_preserves_every_artifact_path_and_one_token_per_identity() {
        let artifacts = unprojected_bundle_artifacts();
        let expected_paths: Vec<String> = artifacts
            .iter()
            .map(|artifact| artifact.relative_path.clone())
            .collect();

        let projected = redacted_bundle_artifacts(&bundle_capture(), bundle_evidence(), artifacts);
        let actual_paths: Vec<String> = projected
            .iter()
            .map(|artifact| artifact.relative_path.clone())
            .collect();
        assert_eq!(
            actual_paths, expected_paths,
            "an artifact path was rewritten"
        );

        let shareable = joined_artifact_text(&projected);
        let from_capture_text = tokens_of_kind(&redacted_status_text(&bundle_capture()), "tenant");
        assert!(
            !from_capture_text.is_empty(),
            "the capture-text projection minted no tenant token; the comparison below is vacuous"
        );
        let from_bundle = tokens_of_kind(&shareable, "tenant");
        for token in &from_capture_text {
            assert!(
                from_bundle.contains(token),
                "the bundle projection disagreed with the capture-text one: {token} is missing from {from_bundle:?}"
            );
        }
    }

    /// The shared grammar refuses an oversized input rather than masking it, so
    /// projecting an artifact whole replaced the entire file with its marker. A
    /// capture's event-log export is routinely several hundred kilobytes, which
    /// is how this was found: on a live capture the hand-off wrote a 34-byte
    /// event log, the bundle lost that evidence, and the analysis of the
    /// reopened bundle reached nine findings instead of ten.
    #[test]
    fn the_hand_off_projects_a_large_artifact_instead_of_replacing_it() {
        let mut entries = String::new();
        for index in 0..6_000 {
            entries.push_str(&format!(
                "    {{\n      \"id\": {index},\n      \"channel\": \"AadOperational\",\n      \"message\": \"event detail line {index}\"\n    }},\n"
            ));
        }

        let artifact = vec![DsregcmdBundleArtifact {
            relative_path: "evidence/event-logs/dsregcmd-events.json".to_string(),
            text: format!(
                "{{\n  \"sourceKind\": \"Live\",\n  \"entries\": [\n{entries}    {{\n      \"id\": 6001,\n      \"computer\": \"{BUNDLE_EVENT_COMPUTER}\",\n      \"message\": \"registration failed for {BUNDLE_ENROLLMENT_UPN}\"\n    }}\n  ]\n}}\n"
            ),
        }];
        assert!(
            artifact[0].text.len() > 256 * 1024,
            "the fixture has to exceed the grammar's input bound to be a regression test"
        );

        let projected = redacted_bundle_artifacts(&bundle_capture(), bundle_evidence(), artifact);
        let text = &projected[0].text;

        assert!(
            !text.contains("oversized text omitted"),
            "the artifact was replaced wholesale instead of projected"
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(text).is_ok(),
            "the projected artifact is no longer parseable JSON"
        );
        assert!(
            !text.contains(BUNDLE_EVENT_COMPUTER) && !text.contains(BUNDLE_ENROLLMENT_UPN),
            "the oversized artifact kept an identifier in clear"
        );
    }

    /// A machine is named twice in a capture: the event record carries the FQDN,
    /// and the message body names the same machine by its short form. Only the
    /// FQDN was classified, so every narrative mention of the short form went out
    /// in clear — 190 of them in a live capture, in a bundle whose `computer`
    /// field was correctly masked.
    #[test]
    fn a_typed_host_scrubs_its_short_form_from_narrative_text() {
        let fqdn = "HELPDESK-LAPTOP01.corp.contoso.com";
        let short = "HELPDESK-LAPTOP01";

        let evidence = DsregcmdBundleEvidence {
            event_log_analysis: Some(EventLogAnalysis {
                source_kind: EventLogAnalysisSource::Live,
                entries: vec![EventLogEntry {
                    id: 1,
                    channel: EventLogChannel::AadOperational,
                    channel_display: "AAD Operational".to_string(),
                    provider: "Microsoft-Windows-AAD".to_string(),
                    event_id: 1103,
                    severity: EventLogSeverity::Error,
                    timestamp: "2026-08-26T09:15:00Z".to_string(),
                    computer: Some(fqdn.to_string()),
                    message: format!("{short} reported a failure for {USER_SID}"),
                    correlation_activity_id: None,
                    source_file: "AAD.evtx".to_string(),
                }],
                ..EventLogAnalysis::default()
            }),
            ..DsregcmdBundleEvidence::default()
        };

        let published = json(
            &analyze_text_with_evidence(IDENTITY_CAPTURE, evidence).expect("the capture analyzes"),
        );

        assert!(
            !published.contains(fqdn),
            "the typed host field kept the FQDN: {published}"
        );
        assert!(
            !published.contains(short),
            "the short form of a classified host survived in narrative text: {published}"
        );

        let tokens = tokens_of_kind(&published, "host");
        assert!(
            tokens.len() >= 2,
            "expected the typed host and its narrative mention both masked: {published}"
        );
        assert!(
            tokens.iter().all(|token| *token == tokens[0]),
            "one machine reached more than one token: {tokens:?}"
        );
    }

    /// A short form is far likelier than a full identity to occur as a fragment
    /// of ordinary text, so it matches only where the characters around it could
    /// not continue a hostname. `HELPDESK-LAPTOP011` is a different machine.
    #[test]
    fn a_short_host_alias_does_not_replace_a_longer_hostname() {
        let short = "HELPDESK-LAPTOP01";
        let neighbour = "HELPDESK-LAPTOP011";

        let evidence = DsregcmdBundleEvidence {
            event_log_analysis: Some(EventLogAnalysis {
                source_kind: EventLogAnalysisSource::Live,
                entries: vec![EventLogEntry {
                    id: 1,
                    channel: EventLogChannel::AadOperational,
                    channel_display: "AAD Operational".to_string(),
                    provider: "Microsoft-Windows-AAD".to_string(),
                    event_id: 1103,
                    severity: EventLogSeverity::Error,
                    timestamp: "2026-08-26T09:15:00Z".to_string(),
                    computer: Some(format!("{short}.corp.contoso.com")),
                    message: format!("{neighbour}.corp.contoso.com reported a failure"),
                    correlation_activity_id: None,
                    source_file: "AAD.evtx".to_string(),
                }],
                ..EventLogAnalysis::default()
            }),
            ..DsregcmdBundleEvidence::default()
        };

        let published = json(
            &analyze_text_with_evidence(IDENTITY_CAPTURE, evidence).expect("the capture analyzes"),
        );

        assert!(
            published.contains(neighbour),
            "the alias cut a different machine's name in half: {published}"
        );
    }

    // -----------------------------------------------------------------------
    // The typed short-literal policy (issue #646)
    // -----------------------------------------------------------------------

    /// A four-character on-premises domain: below the ordinary six-byte scrub
    /// floor, and the shape a live capture on a domain-joined machine has.
    const SHORT_DOMAIN: &str = "ACME";

    fn short_domain_capture(narrative: &str) -> String {
        format!(
            "\n AzureAdJoined : NO\n DomainJoined : YES\n \
             TenantId : {BUNDLE_TENANT_ID}\n DomainName : {SHORT_DOMAIN}\n \
             Server Message : {narrative}\n"
        )
    }

    fn projected_capture(capture: &str) -> serde_json::Value {
        let analysis = analyze_text_with_evidence(capture, DsregcmdBundleEvidence::default())
            .expect("the capture analyzes");
        serde_json::from_str(&json(&analysis)).expect("a dsregcmd analysis serializes")
    }

    /// A four-character value the capture put in a *typed* field is an identity,
    /// so it is masked in that field **and** in the narrative around it, and both
    /// reach one token — whatever their case, however often they occur.
    ///
    /// Covers the policy's requirements 1, 2, 3, 7 and 8.
    #[test]
    fn a_short_typed_domain_masks_its_field_and_its_narrative_mentions() {
        let value = projected_capture(&short_domain_capture(
            "sync to acme failed; retry ACME; then AcMe done",
        ));

        let domain_token = value["facts"]["tenantDetails"]["domainName"]
            .as_str()
            .expect("the domain field is present")
            .to_string();
        assert!(
            domain_token.starts_with("[tenant:"),
            "the typed field is masked: {domain_token}"
        );

        let message = value["facts"]["registration"]["serverMessage"]
            .as_str()
            .expect("the message field is present");
        assert!(
            !message.to_ascii_lowercase().contains("acme"),
            "narrative text kept the short domain: {message}"
        );
        assert_eq!(
            message.matches(domain_token.as_str()).count(),
            3,
            "every occurrence, whatever its case, reaches the typed field's token: {message}"
        );
    }

    /// The floor is unchanged for a value with no typed field behind it. The
    /// *classification* is what authorizes a short replacement, not the length.
    ///
    /// Covers requirement 4, and requirement 10 with the existing suite.
    #[test]
    fn an_ordinary_short_word_is_still_not_classified() {
        let mut observed = IdentityLiterals::default();
        observed.push(SHORT_DOMAIN, KIND_TENANT, LiteralOrigin::ObservedNarrative);
        assert!(
            observed.values.is_empty(),
            "a four-character value observed in prose still has to clear the floor"
        );

        let mut typed = IdentityLiterals::default();
        typed.push(SHORT_DOMAIN, KIND_TENANT, LiteralOrigin::TypedSensitive);
        assert_eq!(
            typed.values.len(),
            1,
            "the same four characters are an identity when a typed field holds them"
        );
    }

    /// The typed path has a smaller floor rather than none, and this pins the
    /// difference: two characters is prose, four is an identifier.
    #[test]
    fn a_two_character_typed_value_is_still_too_short_to_scrub() {
        let mut two = IdentityLiterals::default();
        two.push("ad", KIND_TENANT, LiteralOrigin::TypedSensitive);
        assert!(
            two.values.is_empty(),
            "a two-character typed value must not enter the table"
        );

        let mut four = IdentityLiterals::default();
        four.push(SHORT_DOMAIN, KIND_TENANT, LiteralOrigin::TypedSensitive);
        assert_eq!(
            four.values.len(),
            1,
            "a four-character typed value is the leak this policy exists for"
        );
    }

    /// One byte length decides both the insertion floor and the boundary
    /// requirement, so the two cannot disagree.
    ///
    /// Unicode lowercasing can change a value's byte length: `İ` (U+0130) is two
    /// bytes and canonicalizes to `i` plus a combining dot above, three bytes. A
    /// five-byte value therefore becomes six, which is exactly the length
    /// `requires_boundary` compares against. Measuring the *original* at insertion
    /// and the *canonical* form at match time let such a value clear the typed
    /// floor and then be replaced **inside** a longer identifier — the
    /// over-matching the boundary rule exists to prevent.
    #[test]
    fn a_value_whose_canonical_form_grows_is_still_bounded() {
        let value = "\u{130}abc";
        assert_eq!(value.len(), 5, "the fixture is five bytes as it was found");
        assert_eq!(
            value.to_lowercase().len(),
            6,
            "and six once canonicalized, which is the threshold that hid the gap"
        );

        let mut literals = IdentityLiterals::default();
        literals.push(value, KIND_TENANT, LiteralOrigin::TypedSensitive);
        assert_eq!(
            literals.values.len(),
            1,
            "the typed value clears the four-byte floor and is classified"
        );

        // Inside a longer identifier the value is a fragment of that identifier,
        // not the identifier itself, so a bounded literal must leave it alone.
        let inside = "x\u{130}abcy";
        assert_eq!(
            literals.scrub(inside),
            inside,
            "a short typed value must not be replaced inside a larger identifier"
        );
    }

    /// The typed floor is a policy boundary, not an accident of a comparison, so
    /// the lengths either side of it are pinned: two and three bytes stay out,
    /// four and five are admitted.
    #[test]
    fn the_typed_floor_admits_four_bytes_and_refuses_three() {
        for (value, admitted) in [
            ("ad", false),
            ("abc", false),
            ("abcd", true),
            ("abcde", true),
        ] {
            let mut literals = IdentityLiterals::default();
            literals.push(value, KIND_TENANT, LiteralOrigin::TypedSensitive);
            assert_eq!(
                !literals.values.is_empty(),
                admitted,
                "a {}-byte typed value admitted={} but the policy says {admitted}",
                value.len(),
                !literals.values.is_empty()
            );
        }
    }

    /// Four and five byte typed values are not merely admitted — they are scrubbed
    /// out of the narrative they appear in, at a boundary.
    #[test]
    fn a_four_or_five_byte_typed_value_is_scrubbed_from_narrative() {
        for domain in ["acme", "acmes"] {
            let capture = format!(
                "\n AzureAdJoined : NO\n DomainJoined : YES\n \
                 TenantId : {BUNDLE_TENANT_ID}\n DomainName : {domain}\n \
                 Server Message : sync to {domain} failed\n"
            );
            let value = projected_capture(&capture);
            let message = value["facts"]["registration"]["serverMessage"]
                .as_str()
                .expect("the message field is present");

            assert!(
                !message.to_ascii_lowercase().contains(domain),
                "a {}-byte typed domain survived in narrative text: {message}",
                domain.len()
            );
        }
    }

    /// A rejected occurrence must not end the search for that literal: the same
    /// value appearing later, on a boundary, still has to be found.
    #[test]
    fn a_bounded_occurrence_is_still_found_after_an_earlier_rejected_one() {
        let value = projected_capture(&short_domain_capture(
            "ACMECORP failed, then ACME failed too",
        ));
        let message = value["facts"]["registration"]["serverMessage"]
            .as_str()
            .expect("the message field is present");

        assert!(
            message.contains("ACMECORP"),
            "the fused occurrence was cut: {message}"
        );
        assert!(
            !message.contains("ACME failed"),
            "the bounded occurrence after the rejected one was missed: {message}"
        );
    }

    /// A short value is replaced only where the characters around it could not
    /// continue an identifier, so it cannot cut a longer one in half.
    ///
    /// Covers requirement 5.
    #[test]
    fn a_short_typed_domain_does_not_cut_a_longer_identifier() {
        let value = projected_capture(&short_domain_capture("ACMECORP MYACME ACME2 acme-corp"));
        let message = value["facts"]["registration"]["serverMessage"]
            .as_str()
            .expect("the message field is present");

        for untouched in ["ACMECORP", "MYACME", "ACME2", "acme-corp"] {
            assert!(
                message.contains(untouched),
                "the short domain cut '{untouched}' in half: {message}"
            );
        }
    }

    /// The account form is a boundary, so the domain loses while the account name
    /// it belongs to stays readable.
    ///
    /// Covers requirement 6.
    #[test]
    fn a_short_typed_domain_is_replaced_in_an_account_name() {
        let value = projected_capture(&short_domain_capture(r"sign-in failed for ACME\adam_admin"));
        let message = value["facts"]["registration"]["serverMessage"]
            .as_str()
            .expect("the message field is present");

        assert!(
            !message.to_ascii_lowercase().contains("acme"),
            "the domain survived in the account form: {message}"
        );
        assert!(
            message.contains("adam_admin"),
            "the account name went with the domain: {message}"
        );
    }

    /// Projecting what the projection produced changes nothing, which is what
    /// keeps a second egress pass from disagreeing with the first.
    ///
    /// Covers requirement 9.
    #[test]
    fn projecting_a_short_typed_domain_is_idempotent() {
        let capture = short_domain_capture("sync to ACME failed");
        let once = redacted_status_text(&capture);
        assert!(
            !once.to_ascii_lowercase().contains("acme"),
            "the first pass did not mask the short domain: {once}"
        );
        assert_eq!(
            redacted_status_text(&once),
            once,
            "a second pass changed the projected capture"
        );
    }

    /// Every `[kind:…]` token in a serialized analysis, in order.
    fn tokens_of_kind(published: &str, kind: &str) -> Vec<String> {
        let marker = format!("[{kind}:");
        published
            .split(marker.as_str())
            .skip(1)
            .filter_map(|rest| rest.split(']').next())
            .map(str::to_string)
            .collect()
    }

    fn diagnostic_ids(result: &DsregcmdAnalysisResult) -> Vec<&str> {
        result
            .diagnostics
            .iter()
            .map(|issue| issue.id.as_str())
            .collect()
    }

    fn json(result: &DsregcmdAnalysisResult) -> String {
        serde_json::to_string(result).expect("a dsregcmd analysis serializes")
    }
}
