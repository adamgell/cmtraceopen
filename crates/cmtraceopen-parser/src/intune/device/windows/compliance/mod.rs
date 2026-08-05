//! Intune Windows device compliance: local evaluation and reporting evidence.
//!
//! Owner: issue #364 of epic #356.
//!
//! # What this module refuses to do
//!
//! Four different signals are routinely described as "the device is
//! noncompliant", and conflating them is the single most common way a
//! compliance investigation goes wrong. This module keeps them in four separate
//! phases and never lets one become another:
//!
//! | Phase | Question it answers |
//! |---|---|
//! | [`ComplianceLocalPhase`] | what did the device evaluate, setting by setting? |
//! | [`ComplianceAggregatePhase`] | what device-wide result follows from that? |
//! | [`ComplianceReportingPhase`] | did the report submit, and how old is the service's copy? |
//! | [`ComplianceAccessPhase`] | what happened downstream at sign-in? |
//!
//! Concretely:
//!
//! - a **Conditional Access denial** never produces a local setting state. With
//!   no matching compliance record it is [`ComplianceAccessLinkage::NoMatchingComplianceEvidence`]
//!   and yields an `Info`/`Low` finding that says outright that no causal claim
//!   is being made. Even a fully correlated denial is capped at `Medium` and
//!   described as coincidence, because Conditional Access policy is out of scope
//!   here;
//! - a **stale service state** never produces a local setting state. It is
//!   reported as [`ComplianceServiceFreshness::Stale`] against the timestamp of
//!   the most recent local evaluation, and its finding states the local
//!   aggregate explicitly so the two cannot be confused;
//! - a **user-targeted policy with no user context** is
//!   [`ComplianceSettingState::NotEvaluated`], which is missing coverage, not a
//!   failure;
//! - a **custom-compliance script that crashed** is
//!   [`ComplianceCustomState::ScriptFailed`], never
//!   [`ComplianceCustomState::DiscoveryNoncompliant`]: a script that did not run
//!   produced no verdict to report;
//! - a report row whose outcome is `Failed` becomes
//!   [`ComplianceSettingState::EvaluationError`], not `Noncompliant`. "Could not
//!   evaluate" and "does not meet the requirement" are different claims.
//!
//! # I/O and platform
//!
//! None. The crate is `wasm32-unknown-unknown` clean, so the native adapter
//! reads EVTX, the live event log, and MDM diagnostic exports, then hands this
//! module the shared normalized shapes from [`crate::intune::normalized`] plus
//! the supplied facts defined here. Everything below is pure reduction.
//!
//! # Example
//!
//! ```
//! use cmtraceopen_parser::intune::device::windows::compliance::{
//!     analyze_compliance_bundle, ComplianceAggregateState, ComplianceSourceInput,
//! };
//! use cmtraceopen_parser::intune::evidence::IntuneArtifactStatus;
//!
//! let events = r#"{
//!   "complianceInputVersion": 1,
//!   "kind": "windowsEvents",
//!   "records": [{
//!     "context": {
//!       "evidenceRef": { "evidenceId": "evt-1", "sourceArtifactId": "mdm-events" },
//!       "provenance": {
//!         "sourceKind": "eventLog",
//!         "sourceArtifactId": "mdm-events",
//!         "filePath": null, "lineNumber": null, "recordNumber": 1,
//!         "registry": null, "event": null
//!       },
//!       "sourceTimestamp": {
//!         "rawText": "2026-07-31T10:00:00Z", "originalOffset": null,
//!         "normalizedUtc": "2026-07-31T10:00:00Z", "kind": "utc"
//!       },
//!       "observedAtUtc": "2026-07-31T12:00:00Z",
//!       "sensitivity": "public", "parseState": "parsed", "accessState": "available"
//!     },
//!     "channel": "DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
//!     "provider": "DeviceManagement-Enterprise-Diagnostics-Provider",
//!     "eventId": 813, "level": "information",
//!     "task": null, "keywords": null, "recordId": 1, "activityId": null,
//!     "namedData": [
//!       { "name": "SettingUri", "value": "./Device/Vendor/MSFT/Policy/Result/BitLocker" },
//!       { "name": "EvaluationResult", "value": "noncompliant" }
//!     ],
//!     "message": null
//!   }]
//! }"#;
//!
//! let snapshot = analyze_compliance_bundle(
//!     &[ComplianceSourceInput {
//!         artifact_id: "mdm-events".to_string(),
//!         family: "mdmEvents".to_string(),
//!         status: IntuneArtifactStatus::Available,
//!         captured_at_utc: "2026-07-31T12:00:00Z".to_string(),
//!         content: Some(events.to_string()),
//!     }],
//!     "2026-07-31T12:00:00Z",
//! );
//!
//! assert_eq!(snapshot.aggregate.state, ComplianceAggregateState::Noncompliant);
//! assert!(snapshot
//!     .findings
//!     .iter()
//!     .any(|finding| finding.finding_id == "compliance-local-setting-noncompliant"));
//! ```

mod models;
mod redaction;
mod reducer;
mod rules;
mod sources;

pub use models::{
    ComplianceAccessDecision, ComplianceAccessFact, ComplianceAccessLinkage,
    ComplianceAccessObservation, ComplianceAccessPhase, ComplianceAggregatePhase,
    ComplianceAggregateRationale, ComplianceAggregateState, ComplianceCustomEvaluation,
    ComplianceCustomFact, ComplianceCustomState, ComplianceDeviceContextFact,
    ComplianceDeviceContextView, ComplianceInput, ComplianceLocalPhase,
    CompliancePolicyObservation, CompliancePolicyState, CompliancePrerequisite,
    CompliancePrerequisiteState, ComplianceReportState, ComplianceReportingPhase, ComplianceScope,
    ComplianceServiceFact, ComplianceServiceFreshness, ComplianceServiceResult,
    ComplianceServiceState, ComplianceSettingEvaluation, ComplianceSettingKey,
    ComplianceSettingState, ComplianceSnapshot, ComplianceUserContext,
    INTUNE_COMPLIANCE_SCHEMA_VERSION,
};
pub use redaction::{redact_text, redacted_export_projection};
pub use reducer::{analyze_compliance, analyze_compliance_bundle};
pub use rules::derive_findings;
pub use sources::{decode_bundle, ComplianceSourceInput, COMPLIANCE_INPUT_ENVELOPE_VERSION};
