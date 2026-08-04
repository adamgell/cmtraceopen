#![cfg(feature = "macos-diag")]

use app_lib::jamf::detect::collect_environment_impl;

#[test]
fn collect_environment_does_not_panic() {
    let env = collect_environment_impl().expect("env collection should never fail");
    assert!(!env.summary.is_empty());
    // An installed binary does not guarantee `jamf version` succeeds (it can
    // fail or time out), so only the inverse is a real invariant.
    if !env.jamf_installed {
        assert!(env.jamf_version.is_none(), "version reported without a binary");
    }
}

#[test]
fn directory_status_matches_filesystem() {
    let env = collect_environment_impl().expect("ok");
    let real = std::path::Path::new("/var/log/jamf.log").is_file();
    assert_eq!(env.directories.jamf_log, real);
}

/// These three were hardcoded placeholders that the Overview tab rendered as
/// though they were probe results. They are now derived from the MDM profile
/// list and the TCC check, so assert they track the same sources the macOS
/// Diagnostics workspace uses rather than drifting back to constants.
#[cfg(target_os = "macos")]
#[test]
fn mdm_and_fda_fields_track_their_probes() {
    use app_lib::macos_diag::environment::detect_full_disk_access;
    use app_lib::macos_diag::profiles::list_profiles_impl;

    let env = collect_environment_impl().expect("ok");

    assert_eq!(
        format!("{:?}", env.fda_status),
        format!("{:?}", detect_full_disk_access()),
        "fda_status must come from the shared FDA probe"
    );

    let profiles = list_profiles_impl().expect("profile enumeration on macOS");
    let has_mdm_payload = profiles.profiles.iter().any(|p| {
        p.payloads.iter().any(|pl| {
            pl.payload_type == "com.apple.mdm" || pl.payload_identifier == "com.apple.mdm"
        })
    });
    let expected_present = has_mdm_payload || profiles.enrollment_status.enrolled;
    assert_eq!(env.mdm_profile_present, expected_present);

    if !expected_present {
        assert!(env.mdm_organization.is_none());
    }
}

/// Off macOS the probes are unavailable; the environment must still resolve
/// rather than erroring, and must not claim an MDM it cannot see.
#[cfg(not(target_os = "macos"))]
#[test]
fn mdm_and_fda_fields_degrade_off_macos() {
    let env = collect_environment_impl().expect("must not fail off macOS");
    assert!(!env.mdm_profile_present);
    assert!(env.mdm_organization.is_none());
}
