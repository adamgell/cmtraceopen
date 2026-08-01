//! Windows Autopilot identity, profile, and OOBE evidence outside ESP.
//!
//! Owner: issue #362 of epic #356.
//!
//! # Where the boundary with ESP sits
//!
//! Autopilot and the Enrollment Status Page are **sibling contracts**, not one
//! contract under two names. This module owns device registration and identity,
//! profile discovery, retrieval and application, OOBE mode and deployment
//! profile facts, diagnostics-page/export evidence, and the handoff into
//! enrollment and ESP. `crate::esp` continues to own app and policy progress and
//! blocking status *after* that handoff, and nothing here re-derives it.
//!
//! The only thing crossing the boundary is an explicit key. An
//! [`AutopilotEspSessionFact`] supplied by the ESP side binds to this analysis
//! when it shares an enrollment, correlation, activity, or device identifier;
//! overlapping timestamps alone can only ever produce
//! [`AutopilotEspLinkState::TimeOnlyCandidate`] at low confidence, and are
//! refused outright when the collection's timezone is missing or unrecognizable.
//!
//! # What stays native
//!
//! EVTX decoding, registry reads, diagnostics-export generation, and live OOBE
//! interaction are all outside this crate; see the wasm32 invariant in the crate
//! root. What crosses the boundary is a set of versioned, self-declaring
//! documents plus the shared
//! [`NormalizedWindowsEvent`](crate::intune::normalized::NormalizedWindowsEvent)
//! type. Nothing here performs I/O.
//!
//! # Shape
//!
//! Deliberately the same shape as `crate::esp`, so the two read side by side:
//!
//! 1. [`sources`] declares the input contract and detects document schemas;
//! 2. [`normalize`] classifies records against Microsoft's documented event
//!    table, refusing to interpret anything outside it;
//! 3. [`reduce_autopilot_bundle`] folds observations into an immutable
//!    [`AutopilotSnapshot`];
//! 4. [`derive_findings`] turns that snapshot into
//!    [`IntuneFinding`](crate::intune::evidence::IntuneFinding)s, each citing
//!    evidence or a coverage gap and each naming the next smallest artifact;
//! 5. [`redacted_export_projection`] makes a snapshot safe to share.
//!
//! ```
//! use cmtraceopen_parser::intune::enrollment::windows::autopilot::{
//!     reduce_autopilot_bundle, AutopilotBundleInput, AutopilotCaptureMetadata,
//!     AutopilotCaptureState, AutopilotOutcome, AutopilotSourceInput,
//! };
//!
//! let events = r#"{
//!   "autopilotDocument": "autopilot.events",
//!   "documentVersion": 1,
//!   "events": [{
//!     "context": {
//!       "evidenceRef": { "evidenceId": "ap:0", "sourceArtifactId": "autopilot-channel" },
//!       "provenance": {
//!         "sourceKind": "eventLog", "sourceArtifactId": "autopilot-channel",
//!         "filePath": null, "lineNumber": null, "recordNumber": 1,
//!         "registry": null, "event": null
//!       },
//!       "sourceTimestamp": null,
//!       "observedAtUtc": "2026-07-31T09:00:00Z",
//!       "sensitivity": "public", "parseState": "parsed", "accessState": "available"
//!     },
//!     "channel": "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
//!     "provider": "Microsoft-Windows-ModernDeployment-Diagnostics-Provider",
//!     "eventId": 815,
//!     "level": "error",
//!     "task": null, "keywords": null, "recordId": 1, "activityId": null,
//!     "namedData": [],
//!     "message": "ZtdDeviceHasNoAssignedProfile - No profile assigned to the device."
//!   }]
//! }"#;
//!
//! let snapshot = reduce_autopilot_bundle(&AutopilotBundleInput {
//!     generated_at_utc: "2026-07-31T09:05:00Z".to_string(),
//!     capture: AutopilotCaptureMetadata {
//!         timezone: Some("UTC".to_string()),
//!         ..AutopilotCaptureMetadata::default()
//!     },
//!     sources: vec![AutopilotSourceInput {
//!         artifact_id: "autopilot-channel".to_string(),
//!         family: "autopilotEvents".to_string(),
//!         capture_state: AutopilotCaptureState::Captured,
//!         original_basename: Some("autopilot-events.json".to_string()),
//!         sanitized_source_path: None,
//!         content: Some(events.to_string()),
//!     }],
//!     events: Vec::new(),
//! });
//!
//! assert_eq!(snapshot.outcome, AutopilotOutcome::NoProfileCandidate);
//! assert!(snapshot.findings_are_evidence_backed());
//! ```

pub mod models;
pub mod normalize;
pub mod redaction;
pub mod reducer;
pub mod rules;
pub mod sources;

pub use models::*;
pub use normalize::{
    classify_event, error_code_from_token, extract_error_code, extract_oobe_setting,
    extract_policy_pair, extract_profile_state, is_autopilot_channel,
};
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::reduce_autopilot_bundle;
pub use rules::derive_findings;
pub use sources::{
    capture_is_validated, classify_timezone, detect_document, is_validated_schema_version,
    is_validated_windows_build, AutopilotBundleInput, AutopilotCaptureState,
    AutopilotDocumentDetection, AutopilotDocumentKind, AutopilotEspSessionDocument,
    AutopilotEventsDocument, AutopilotReportDocument, AutopilotReportSection, AutopilotSourceInput,
    AUTOPILOT_DOCUMENT_VERSION, AUTOPILOT_EVENT_CHANNEL, AUTOPILOT_EVENT_PROVIDER,
};
