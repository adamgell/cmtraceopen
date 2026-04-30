use app_lib::jamf::detect::collect_environment_impl;

#[test]
fn collect_environment_does_not_panic() {
    let env = collect_environment_impl().expect("env collection should never fail");
    assert!(!env.summary.is_empty());
    if env.jamf_installed {
        assert!(env.jamf_version.is_some(), "jamf installed but version unknown");
    }
}

#[test]
fn directory_status_matches_filesystem() {
    let env = collect_environment_impl().expect("ok");
    let real = std::path::Path::new("/var/log/jamf.log").is_file();
    assert_eq!(env.directories.jamf_log, real);
}
