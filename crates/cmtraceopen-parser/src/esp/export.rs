//! The only shape an ESP session may leave this crate in.
//!
//! [`EspSessionCapture`] is the export boundary for the ESP lane. Its
//! `snapshot` field is private and its only constructor,
//! [`EspSessionCapture::from_snapshot`], runs
//! [`redacted_export_projection`](super::redacted_export_projection) first, so
//! no caller outside this crate can build a capture that still carries local
//! values. There is deliberately no `Deserialize` impl and no field-wise
//! constructor: either would hand back the ability to assemble a capture
//! around an unprojected snapshot.
//!
//! Egress paths (file save, clipboard, support attachment) serialize this
//! type. They never serialize an `EspDiagnosticsSnapshot` directly, which is
//! what issue #549 found them doing.
//!
//! This is the same arrangement as `SccmRawEvidenceSnapshot::export` in
//! `crate::sccm::evidence`: bind by construction at the library edge rather
//! than ask every egress point to remember.

use serde::{Deserialize, Serialize};

use super::models::EspDiagnosticsSnapshot;
use super::redaction::redacted_export_projection;

/// Envelope discriminator written into every exported file.
pub const ESP_SESSION_CAPTURE_KIND: &str = "esp-session-capture";
/// Envelope format version. Bump only on a breaking envelope change.
pub const ESP_SESSION_CAPTURE_VERSION: u32 = 1;

/// Caller-supplied provenance for an export. Carries no device data.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionCaptureMeta {
    /// When the export was taken, as an ISO-8601 UTC string.
    pub captured_at_utc: String,
    /// Version of the application that produced the export, when known.
    #[serde(default)]
    pub app_version: Option<String>,
    /// Commit the application was built from, when known.
    #[serde(default)]
    pub app_commit: Option<String>,
}

/// Application provenance as written into the envelope.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionCaptureApp {
    version: Option<String>,
    commit: Option<String>,
}

/// A portable, redacted record of one ESP diagnostics session.
///
/// Constructing one applies the export projection; there is no way to obtain
/// an instance holding the caller's original values.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionCapture {
    kind: &'static str,
    version: u32,
    captured_at_utc: String,
    app: EspSessionCaptureApp,
    /// Always `true`. An export that cannot say whether it was redacted is not
    /// auditable, so the flag is written rather than left to be inferred.
    redacted: bool,
    snapshot: EspDiagnosticsSnapshot,
}

impl EspSessionCapture {
    /// Project a session into its exportable form.
    ///
    /// The caller's snapshot is left untouched: the workspace keeps rendering
    /// local values while the exported copy carries none.
    pub fn from_snapshot(snapshot: &EspDiagnosticsSnapshot, meta: EspSessionCaptureMeta) -> Self {
        let EspSessionCaptureMeta {
            captured_at_utc,
            app_version,
            app_commit,
        } = meta;

        Self {
            kind: ESP_SESSION_CAPTURE_KIND,
            version: ESP_SESSION_CAPTURE_VERSION,
            captured_at_utc,
            app: EspSessionCaptureApp {
                version: app_version,
                commit: app_commit,
            },
            redacted: true,
            snapshot: redacted_export_projection(snapshot),
        }
    }

    /// The projected session. Safe to render, share, or attach.
    pub fn snapshot(&self) -> &EspDiagnosticsSnapshot {
        &self.snapshot
    }

    /// Serialize the capture as the JSON text an export writes.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::models::{
        EspClassifiedString, EspElevationState, EspIdentityEvidence, EspPhase, EspScenario,
        EspSensitivity, ESP_DIAGNOSTICS_SCHEMA_VERSION,
    };

    fn meta() -> EspSessionCaptureMeta {
        EspSessionCaptureMeta {
            captured_at_utc: "2026-08-11T09:15:00Z".to_string(),
            app_version: Some("1.5.1".to_string()),
            app_commit: None,
        }
    }

    fn snapshot_with_upn(upn: &str) -> EspDiagnosticsSnapshot {
        EspDiagnosticsSnapshot {
            schema_version: ESP_DIAGNOSTICS_SCHEMA_VERSION,
            scenario: EspScenario::AutopilotV1,
            phase: EspPhase::DeviceSetup,
            generated_at_utc: "2026-08-11T09:00:00Z".to_string(),
            elevation: EspElevationState {
                is_elevated: true,
                restart_supported: true,
                restricted_sources: vec![],
            },
            identity: EspIdentityEvidence {
                device_name: None,
                managed_device_id: None,
                entra_device_id: None,
                entdm_id: None,
                tenant_id: None,
                tenant_domain: None,
                user_principal_name: Some(EspClassifiedString {
                    value: upn.to_string(),
                    sensitivity: EspSensitivity::Restricted,
                }),
                serial_number: None,
                evidence: vec![],
            },
            profile: None,
            enrollments: vec![],
            sessions: vec![],
            workloads: vec![],
            installer_correlations: vec![],
            node_cache: vec![],
            registration_events: vec![],
            delivery_optimization: None,
            hardware: None,
            activity: vec![],
            findings: vec![],
            coverage: vec![],
            raw_evidence: vec![],
            graph: None,
        }
    }

    #[test]
    fn constructing_a_capture_projects_the_snapshot() {
        let snapshot = snapshot_with_upn("adele.vance@contoso.example");
        let capture = EspSessionCapture::from_snapshot(&snapshot, meta());
        let json = capture.to_json().expect("capture serializes");

        assert!(!json.contains("adele.vance@contoso.example"));
        assert!(capture.redacted);
        // The caller's own copy is untouched.
        assert_eq!(
            snapshot
                .identity
                .user_principal_name
                .as_ref()
                .map(|value| value.value.as_str()),
            Some("adele.vance@contoso.example")
        );
    }

    #[test]
    fn the_envelope_states_its_kind_version_and_redaction() {
        let capture = EspSessionCapture::from_snapshot(&snapshot_with_upn("a@b.example"), meta());
        let value: serde_json::Value =
            serde_json::from_str(&capture.to_json().unwrap()).expect("capture is JSON");

        assert_eq!(value["kind"], ESP_SESSION_CAPTURE_KIND);
        assert_eq!(value["version"], ESP_SESSION_CAPTURE_VERSION);
        assert_eq!(value["redacted"], true);
        assert_eq!(value["app"]["version"], "1.5.1");
        assert_eq!(value["capturedAtUtc"], "2026-08-11T09:15:00Z");
    }
}
