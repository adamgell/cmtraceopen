//! Which coverage kind a failed live channel query reports.
//!
//! The decision lives here, apart from the Windows calls that produce the error, so it runs and is
//! tested on every platform. Everything that reads a live channel is Windows-only, and a rule
//! written inside it is a rule only the Windows CI jobs ever compile.
//!
//! The kind matters because the operator acts on it. A channel the service refuses to an
//! unelevated process is read by running elevated; filed as a record or file failure, it reads as
//! a broken channel and the one fix that works is never offered.

use super::models::EvtxCoverageGapKind;

/// Windows `ERROR_ACCESS_DENIED`.
const ACCESS_DENIED: u32 = 5;

/// Windows `ERROR_PRIVILEGE_NOT_HELD`: the caller lacks a privilege the channel requires.
const PRIVILEGE_NOT_HELD: u32 = 1314;

/// The coverage kind for a live channel read that failed with Windows error `win32_code`.
///
/// Both access refusals are `AccessDenied`. Any other code keeps `otherwise`, the kind the failing
/// site reports for a failure that is not a refusal.
pub fn channel_failure_kind(
    win32_code: u32,
    otherwise: EvtxCoverageGapKind,
) -> EvtxCoverageGapKind {
    match win32_code {
        ACCESS_DENIED | PRIVILEGE_NOT_HELD => EvtxCoverageGapKind::AccessDenied,
        _ => otherwise,
    }
}

/// Why a live channel query produced no scan at all.
///
/// Keeps the Windows error code beside the message, because the message is localized text and
/// cannot be classified reliably once the code is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelQueryError {
    /// The Windows error code, when the failure came from the Event Log service.
    pub code: Option<u32>,
    /// Operator-facing explanation, including the service's own error text.
    pub message: String,
}

impl ChannelQueryError {
    /// A failure the Event Log service reported with Windows error `code`.
    pub fn win32(code: u32, message: String) -> Self {
        Self {
            code: Some(code),
            message,
        }
    }

    /// The coverage kind this failure reports for the channel. A channel that could not be queried
    /// at all is a file-level gap unless the service refused access to it.
    pub fn coverage_kind(&self) -> EvtxCoverageGapKind {
        self.code.map_or(EvtxCoverageGapKind::File, |code| {
            channel_failure_kind(code, EvtxCoverageGapKind::File)
        })
    }
}

/// A failure that carries no Windows error code, such as a filter that cannot be compiled.
impl From<String> for ChannelQueryError {
    fn from(message: String) -> Self {
        Self {
            code: None,
            message,
        }
    }
}

impl std::fmt::Display for ChannelQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_is_an_access_refusal() {
        assert_eq!(
            channel_failure_kind(5, EvtxCoverageGapKind::Record),
            EvtxCoverageGapKind::AccessDenied
        );
    }

    #[test]
    fn a_missing_privilege_is_an_access_refusal() {
        assert_eq!(
            channel_failure_kind(1314, EvtxCoverageGapKind::Record),
            EvtxCoverageGapKind::AccessDenied
        );
    }

    #[test]
    fn any_other_code_keeps_the_kind_the_site_reports() {
        // 15007 is ERROR_EVT_CHANNEL_NOT_FOUND, 1734 is RPC_S_INVALID_BOUND and 0 is success: none
        // of them is a refusal, and elevating would not change any of them.
        for code in [0, 2, 15007, 1734, 1326] {
            for otherwise in [EvtxCoverageGapKind::Record, EvtxCoverageGapKind::File] {
                assert_eq!(
                    channel_failure_kind(code, otherwise),
                    otherwise,
                    "code {code}"
                );
            }
        }
    }

    #[test]
    fn a_refused_query_reports_access_denied_and_keeps_its_text() {
        for code in [5, 1314] {
            let error =
                ChannelQueryError::win32(code, "EvtQuery(Security): Access is denied.".to_string());
            assert_eq!(
                error.coverage_kind(),
                EvtxCoverageGapKind::AccessDenied,
                "code {code}"
            );
            assert_eq!(error.to_string(), "EvtQuery(Security): Access is denied.");
        }
    }

    #[test]
    fn a_query_failure_that_is_not_a_refusal_stays_a_file_gap() {
        let error = ChannelQueryError::win32(
            15007,
            "EvtQuery(Missing): The specified channel could not be found.".to_string(),
        );
        assert_eq!(error.coverage_kind(), EvtxCoverageGapKind::File);
    }

    #[test]
    fn a_failure_without_a_code_stays_a_file_gap() {
        // Text alone is never classified: "denied" in a message is not a code from the service.
        let error =
            ChannelQueryError::from("cannot compile event query for Security: denied".to_string());
        assert_eq!(error.code, None);
        assert_eq!(error.coverage_kind(), EvtxCoverageGapKind::File);
    }
}
