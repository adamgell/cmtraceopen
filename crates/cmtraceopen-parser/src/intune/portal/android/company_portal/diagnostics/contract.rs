//! The Android Company Portal diagnostic artifact contract.
//!
//! # Status: source contract not yet verified
//!
//! Issue #371 requires that "no stable parser is exposed until an actual
//! sanitized artifact contract is documented". This module is where that
//! contract lives, and it currently records an honest negative result:
//!
//! **No sanitized Android Company Portal or Microsoft Intune app diagnostic
//! artifact has been obtained, so the container layout, member list, record
//! grammar, schema token, encoding, and timestamp format are unverified.**
//! [`VERIFIED_CONTRACTS`] is therefore empty, and every code path that would
//! claim a parsed record is unreachable by construction.
//!
//! # What *is* established
//!
//! The collection workflow is documented by Microsoft and is stable enough to
//! model. From the two Learn articles the issue cites:
//!
//! * Two distinct apps produce diagnostics: the **Intune Company Portal app for
//!   Android** and the **Microsoft Intune app**. Their menus and flows differ,
//!   so their artifacts are classified separately
//!   ([`AndroidDiagnosticApp`]).
//! * Company Portal offers `Help > Send logs`, which splits into **SEND LOGS,
//!   THEN EMAIL** and **SEND LOGS ONLY**. The Microsoft Intune app offers
//!   `Help > Get Support` and **UPLOAD LOGS**. Company Portal additionally
//!   offers `Settings > SAVE LOGS`, which writes a user-chosen local artifact.
//!   These are the values of [`AndroidCollectionFlow`].
//! * Every upload flow pre-populates an **incident ID** into the subject of a
//!   mail draft. The incident ID identifies a *submission attempt*. Microsoft's
//!   own wording ("your support person will reach out to Microsoft Support with
//!   your incident ID") never states that the upload succeeded, so this module
//!   refuses to treat an incident ID as proof of successful upload. That is the
//!   [`AndroidUploadOutcome`] axis, which is deliberately independent of
//!   whether an incident ID exists.
//! * Verbose logging is **on by default** and is turned off under
//!   `Settings > Troubleshooting > Verbose Logging`. A bundle collected with it
//!   off carries less detail, which is a coverage fact rather than a fault.
//! * On a work-profile device, Company Portal and the file-viewing app must
//!   both live **in the work profile**, so a saved artifact covers the work
//!   profile only. That limitation is preserved in provenance rather than
//!   silently generalized to the whole device.
//! * The send-logs option is unavailable in sovereign cloud environments, where
//!   users mail logs instead. That changes the flow, not the artifact.
//! * Microsoft states plainly that the logs sent to a support team **include
//!   the user's email address**. Identity is present by design, which is why
//!   redaction here is on by default rather than opt-in.
//!
//! None of that establishes the bytes. It establishes the *envelope*: who
//! collected it, with which app, under which management mode, through which
//! flow, and with what caveats. That envelope is supplied to this module by the
//! importer as [`crate::intune::evidence::IntuneSourceKind::SuppliedFact`], is
//! recorded verbatim with its provenance, and is never promoted to a
//! content-derived claim.
//!
//! # What a future contribution must record before adding a contract here
//!
//! Adding an entry to [`VERIFIED_CONTRACTS`] is the only way to make this
//! module claim a parsed record. Doing so requires a sanitized artifact plus,
//! per issue #371's source-contract phase, a written record of:
//!
//! 1. container type (and whether members are nested);
//! 2. schema or version marker, and where it appears;
//! 3. the full member list, including which members are optional;
//! 4. text encoding per member;
//! 5. timestamp format, timezone handling, and whether an offset is present;
//! 6. rollover/rotation naming;
//! 7. log-level vocabulary;
//! 8. app/process/component field names;
//! 9. incident and correlation identifier fields;
//! 10. which fields carry privacy-sensitive content.
//!
//! If the Company Portal and Microsoft Intune app artifacts differ
//! structurally, or if two app versions differ, they are separate entries. A
//! single entry covering "Android" would be the guess this module exists to
//! avoid.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::intune_raw_preserving_string_enum;

/// Schema version of every type this leaf serializes.
pub const ANDROID_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

/// Coverage family reported for every artifact this leaf enumerates.
pub const ANDROID_DIAGNOSTICS_FAMILY: &str = "androidCompanyPortalDiagnostics";

intune_raw_preserving_string_enum! {
    /// Which Android app produced the diagnostics.
    ///
    /// Kept separate because the two apps expose different menus and different
    /// submission flows, and nothing yet proves their artifacts share a layout.
    pub enum AndroidDiagnosticApp {
        CompanyPortal => "companyPortal",
        MicrosoftIntuneApp => "microsoftIntuneApp",
    }
}

intune_raw_preserving_string_enum! {
    /// The Android Enterprise management mode the device was in.
    ///
    /// Supplied by the importer. This module never infers a mode from content.
    pub enum AndroidManagementMode {
        WorkProfile => "workProfile",
        FullyManaged => "fullyManaged",
        DedicatedDevice => "dedicatedDevice",
        CorporateOwnedWorkProfile => "corporateOwnedWorkProfile",
        Unmanaged => "unmanaged",
    }
}

intune_raw_preserving_string_enum! {
    /// How the artifact left the device.
    ///
    /// * `SavedLogs`: Company Portal `Settings > SAVE LOGS`, written to a
    ///   user-chosen location.
    /// * `SendLogsThenEmail`: Company Portal `Help > Send logs`, then
    ///   `SEND LOGS, THEN EMAIL`.
    /// * `SendLogsOnly`: Company Portal `Help > Send logs`, then
    ///   `SEND LOGS ONLY`.
    /// * `UploadLogs`: Microsoft Intune app `Help > Get Support`, then
    ///   `UPLOAD LOGS`.
    /// * `AdminCenterDownload`: an administrator-initiated download from the
    ///   Intune admin center.
    pub enum AndroidCollectionFlow {
        SavedLogs => "savedLogs",
        SendLogsThenEmail => "sendLogsThenEmail",
        SendLogsOnly => "sendLogsOnly",
        UploadLogs => "uploadLogs",
        AdminCenterDownload => "adminCenterDownload",
    }
}

intune_raw_preserving_string_enum! {
    /// Whether verbose logging was on when the artifact was collected.
    ///
    /// Microsoft documents verbose logging as enabled by default, so `Off` is
    /// the notable state: it means the bundle contains less than it could have.
    pub enum AndroidVerboseLoggingState {
        On => "on",
        Off => "off",
        Unreported => "unreported",
    }
}

intune_raw_preserving_string_enum! {
    /// What the artifact reports about the upload itself.
    ///
    /// `Unreported` is the default and the honest answer for every artifact
    /// seen so far: an incident ID pre-populated into a mail draft says a
    /// submission was *started*, not that it was received.
    pub enum AndroidUploadOutcome {
        NotAttempted => "notAttempted",
        Attempted => "attempted",
        Confirmed => "confirmed",
        Failed => "failed",
        Unreported => "unreported",
    }
}

/// One verified artifact layout.
///
/// Constructing this type is a claim that a sanitized artifact was inspected
/// and the fields below were read off it, not inferred.
///
/// Serialize-only by design. The registry is a compile-time constant, so there
/// is no wire form to read one back from, and accepting one at runtime would
/// let a caller assert a contract nobody verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedArtifactContract {
    /// Stable identifier, e.g. `companyPortal/savedLogs/v1`.
    pub contract_id: &'static str,
    /// The app whose artifact this describes.
    pub app: &'static str,
    /// The schema or version token the artifact itself carries.
    pub schema_token: &'static str,
    /// Member entry names that must all be present for the contract to match.
    pub required_members: &'static [&'static str],
}

/// Every artifact layout this build has actually verified.
///
/// Deliberately empty. An empty registry is not an oversight; it is the
/// machine-readable form of "the source contract has not been established", and
/// it is what keeps [`crate::intune::portal::android::company_portal::diagnostics`]
/// from claiming a parse it cannot justify. See the module documentation above
/// for what must be recorded before an entry is added.
pub const VERIFIED_CONTRACTS: &[VerifiedArtifactContract] = &[];

/// How many artifact layouts this build can parse.
///
/// Exposed so a caller (and a test) can assert the honest answer rather than
/// discovering it by getting no records back.
pub fn verified_contract_count() -> usize {
    VERIFIED_CONTRACTS.len()
}

/// The verified contract matching a declared schema token and member list, if
/// any.
///
/// Both halves must agree: a token alone is a hint, and a member list alone is
/// a coincidence. With an empty registry this always returns `None`, which is
/// the point.
pub fn match_verified_contract(
    declared_schema_token: Option<&str>,
    member_entry_names: &[String],
) -> Option<&'static VerifiedArtifactContract> {
    let token = declared_schema_token?;
    VERIFIED_CONTRACTS.iter().find(|contract| {
        contract.schema_token == token
            && contract
                .required_members
                .iter()
                .all(|required| member_entry_names.iter().any(|name| name == required))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_artifact_contract_is_verified_in_this_build() {
        // If this ever fails, the module documentation above and the pull
        // request that adds the contract must both be updated: the parser is no
        // longer discovery-only.
        assert_eq!(verified_contract_count(), 0);
    }

    #[test]
    fn a_declared_schema_token_alone_never_matches_a_contract() {
        assert!(match_verified_contract(Some("anything"), &[]).is_none());
        assert!(match_verified_contract(None, &["a.log".to_string()]).is_none());
    }

    #[test]
    fn app_vocabulary_round_trips_unknown_values() {
        let decoded: AndroidDiagnosticApp = serde_json::from_str("\"someFutureApp\"").unwrap();
        assert_eq!(
            decoded,
            AndroidDiagnosticApp::Unknown("someFutureApp".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureApp\""
        );
    }

    #[test]
    fn management_mode_vocabulary_round_trips_unknown_values() {
        let decoded: AndroidManagementMode =
            serde_json::from_str("\"someFutureMode\"").unwrap();
        assert_eq!(
            decoded,
            AndroidManagementMode::Unknown("someFutureMode".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureMode\""
        );
    }
}
