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
}
