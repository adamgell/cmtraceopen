use super::models::{LogSession, LogSource, SecureBootScanState, SecureBootStage};

/// Determines the Secure Boot certificate opt-in stage from live scan data.
///
/// Checks are applied in priority order — the first matching condition wins:
/// 1. Secure Boot disabled → Stage0
/// 2. UEFI CA 2023 actively booting (capable == 2) → Stage5
/// 3. UEFI CA 2023 cert in DB but not booting (capable == 1) → Stage4
/// 4. Managed opt-in not set to 0x5944 → Stage1
/// 5. WU update bitmap present and non-zero (excluding 0x4000 sentinel) → Stage3
/// 6. Otherwise → Stage2 (configured, waiting for Windows Update)
pub fn determine_stage(state: &SecureBootScanState) -> SecureBootStage {
    // 1. Secure Boot must be enabled — if disabled (or explicitly false), nothing else matters.
    if state.secure_boot_enabled == Some(false) {
        return SecureBootStage::Stage0;
    }

    // 2. Already booting from the 2023 CA — fully compliant.
    if state.uefi_ca2023_capable == Some(2) {
        return SecureBootStage::Stage5;
    }

    // 3. Certificate is in the DB but device hasn't rebooted into it yet.
    if state.uefi_ca2023_capable == Some(1) {
        return SecureBootStage::Stage4;
    }

    // 4. Opt-in registry value must equal the magic 0x5944 ("YD") sentinel.
    if state.managed_opt_in != Some(0x5944) {
        return SecureBootStage::Stage1;
    }

    // 5. Windows Update is actively processing the cert deployment.
    //    available_updates == 0 or the 0x4000 "no applicable update" sentinel → not in progress.
    if let Some(val) = state.available_updates {
        if val > 0 && val != 0x4000 {
            return SecureBootStage::Stage3;
        }
    }

    // 6. Everything is configured; waiting for WU to deliver the update.
    SecureBootStage::Stage2
}

/// Determines the Secure Boot stage from imported log sessions only (no live scan).
///
/// Scans backwards through the session list for the last `Detect` session that
/// recorded a `result_stage`, and returns that stage. Falls back to `Stage0` if
/// no such session exists.
pub fn determine_stage_from_log(sessions: &[LogSession]) -> SecureBootStage {
    sessions
        .iter()
        .rev()
        .filter(|s| s.source == LogSource::Detect)
        .find_map(|s| s.result_stage)
        .unwrap_or(SecureBootStage::Stage0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secureboot::models::{LogSession, LogSource, SecureBootScanState, SecureBootStage};
    use chrono::Utc;

    fn base_enabled() -> SecureBootScanState {
        SecureBootScanState {
            secure_boot_enabled: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn stage0_when_secure_boot_disabled() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage0);
    }

    #[test]
    fn stage1_when_optin_missing() {
        // enabled=true, managed_opt_in=None → Stage1
        let state = base_enabled();
        assert_eq!(determine_stage(&state), SecureBootStage::Stage1);
    }

    #[test]
    fn stage2_when_optin_set_no_progress() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            available_updates: None,
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage2);
    }

    #[test]
    fn stage3_when_updates_in_progress() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            available_updates: Some(0x40),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage3);
    }

    #[test]
    fn stage4_when_cert_in_db() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            uefi_ca2023_capable: Some(1),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage4);
    }

    #[test]
    fn stage5_when_booting_2023() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            uefi_ca2023_capable: Some(2),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage5);
    }

    #[test]
    fn stage0_takes_precedence() {
        // Disabled check must fire before the uefi_ca2023_capable=2 check.
        let state = SecureBootScanState {
            secure_boot_enabled: Some(false),
            uefi_ca2023_capable: Some(2),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage0);
    }

    // --- determine_stage_from_log ---

    fn make_detect_session(result_stage: Option<SecureBootStage>) -> LogSession {
        LogSession {
            source: LogSource::Detect,
            started_at: Utc::now(),
            ended_at: None,
            result_stage,
            result_outcome: None,
            entries: vec![],
        }
    }

    #[test]
    fn log_stage_returns_last_detect_result() {
        let sessions = vec![
            make_detect_session(Some(SecureBootStage::Stage1)),
            make_detect_session(Some(SecureBootStage::Stage3)),
        ];
        assert_eq!(
            determine_stage_from_log(&sessions),
            SecureBootStage::Stage3
        );
    }

    #[test]
    fn log_stage_skips_sessions_with_no_result() {
        let sessions = vec![
            make_detect_session(Some(SecureBootStage::Stage2)),
            make_detect_session(None),
        ];
        assert_eq!(
            determine_stage_from_log(&sessions),
            SecureBootStage::Stage2
        );
    }

    #[test]
    fn log_stage_defaults_to_stage0_when_no_detect_sessions() {
        assert_eq!(determine_stage_from_log(&[]), SecureBootStage::Stage0);
    }

    #[test]
    fn log_stage_ignores_non_detect_sources() {
        let sessions = vec![LogSession {
            source: LogSource::Remediate,
            started_at: Utc::now(),
            ended_at: None,
            result_stage: Some(SecureBootStage::Stage5),
            result_outcome: None,
            entries: vec![],
        }];
        assert_eq!(determine_stage_from_log(&sessions), SecureBootStage::Stage0);
    }
}
