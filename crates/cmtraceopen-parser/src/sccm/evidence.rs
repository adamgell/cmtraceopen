use crate::parser::ccm::{CcmLogicalRecord, CcmTimestampParse, CcmTimestampParseState};

use super::models::{
    SccmArtifact, SccmEvidence, SccmEvidenceRef, SccmRole, SccmSensitiveHandle,
    SccmTimeOrderingState, SccmTimestamp,
};

const CONTEXT_HANDLE_SCHEME: &str = "sccm-context-fnv1a64-v1";
const FNV1A64_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV1A64_PRIME: u64 = 0x00000100000001b3;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SccmRawEvidenceSnapshot {
    evidence_id: String,
    reference: SccmEvidenceRef,
    role: SccmRole,
    component: Option<String>,
    ccm_source_file: Option<String>,
    message: String,
    timestamp: SccmTimestamp,
    raw_execution_context: Option<String>,
}

impl SccmRawEvidenceSnapshot {
    pub(crate) fn from_record(artifact: &SccmArtifact, record: CcmLogicalRecord) -> Self {
        let CcmLogicalRecord {
            entry,
            context,
            line_start,
            line_end,
            timestamp,
        } = record;
        let entry_id = format!("{}:{line_start}-{line_end}", artifact.artifact_id);

        Self {
            evidence_id: entry_id.clone(),
            reference: SccmEvidenceRef {
                artifact_id: artifact.artifact_id.clone(),
                entry_id,
                line_start: Some(line_start),
                line_end: Some(line_end),
            },
            role: artifact.role.clone(),
            component: entry.component,
            ccm_source_file: entry.source_file,
            message: entry.message,
            timestamp: timestamp.into(),
            raw_execution_context: context,
        }
    }

    pub(crate) fn export(&self) -> SccmEvidence {
        SccmEvidence {
            evidence_id: self.evidence_id.clone(),
            reference: self.reference.clone(),
            role: self.role.clone(),
            component: self.component.clone(),
            ccm_source_file: self.ccm_source_file.clone(),
            message: self.message.clone(),
            timestamp: self.timestamp.clone(),
            execution_context: self
                .raw_execution_context
                .as_deref()
                .filter(|context| !context.trim().is_empty())
                .map(sensitive_context_handle),
        }
    }
}

impl From<CcmTimestampParse> for SccmTimestamp {
    fn from(timestamp: CcmTimestampParse) -> Self {
        Self {
            original_display: timestamp.original_display,
            offset_minutes: timestamp.offset_minutes,
            utc_millis: timestamp.utc_millis,
            ordering_state: timestamp.ordering_state.into(),
        }
    }
}

impl From<CcmTimestampParseState> for SccmTimeOrderingState {
    fn from(state: CcmTimestampParseState) -> Self {
        match state {
            CcmTimestampParseState::NormalizedUtc => Self::NormalizedUtc,
            CcmTimestampParseState::OffsetMissing => Self::OffsetMissing,
            CcmTimestampParseState::OffsetInvalid => Self::OffsetInvalid,
            CcmTimestampParseState::TimestampMissing => Self::TimestampMissing,
        }
    }
}

fn sensitive_context_handle(context: &str) -> SccmSensitiveHandle {
    let mut hash = FNV1A64_OFFSET_BASIS;
    for byte in b"sccm-context-v1\0"
        .iter()
        .copied()
        .chain(context.as_bytes().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }

    SccmSensitiveHandle {
        scheme: CONTEXT_HANDLE_SCHEME.to_string(),
        value: format!("{hash:016x}"),
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::ccm::scan_logical_records;

    use super::*;
    use crate::sccm::models::{SccmCoverageState, SccmRole, SccmRotation};

    #[test]
    fn export_redaction_does_not_mutate_raw_context_snapshot() {
        let text = include_str!("../../tests/fixtures/sccm/spine/multiline-policy.log");
        let artifact = SccmArtifact {
            artifact_id: "client-policy-agent".into(),
            display_name: "PolicyAgent.log".into(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: None,
            collected_at_utc: None,
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".into()),
        };
        let record = scan_logical_records(text, &artifact.display_name)
            .into_iter()
            .next()
            .expect("fixture contains one CCM record");
        let snapshot = SccmRawEvidenceSnapshot::from_record(&artifact, record);
        let before = snapshot.clone();

        let exported = snapshot.export();

        assert_eq!(snapshot, before);
        assert_eq!(
            snapshot.raw_execution_context.as_deref(),
            Some(r"NT AUTHORITY\SYSTEM")
        );
        assert!(!serde_json::to_string(&exported)
            .unwrap()
            .contains(r"NT AUTHORITY\\SYSTEM"));
        assert!(exported.execution_context.is_some());
    }
}
