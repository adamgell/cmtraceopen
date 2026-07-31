// Pure pieces (types, embedded profile catalog, env-var expansion) live in
// cmtraceopen-parser::collector. Re-exported here so existing references like
// `crate::collector::types::CollectionProfile` and
// `crate::collector::profile::get_profile_by_id` keep resolving unchanged.
//
// Native modules (artifacts.rs: fs + glob, engine.rs: Tauri Emitter,
// manifest.rs: std::fs + AppError) stay in src-tauri because they touch the
// filesystem or the Tauri runtime — concerns that don't belong in the
// wasm-compatible parser crate.

pub use cmtraceopen_parser::collector::{env_expand, profile, types};

pub mod artifacts;
pub mod engine;
pub mod manifest;

// Windows-only proof that the native AppX adapter really emits the documented
// package-state schema. The pure crate can only assert the shape of the command
// string; running it needs a Windows host, so this is gated and exercised by the
// Windows CI job rather than on macOS or Linux.
#[cfg(all(test, target_os = "windows"))]
mod appx_adapter_windows_tests {
    use cmtraceopen_parser::intune::portal::windows::company_portal::package_state::{
        parse_package_state_capture, PackageCaptureCommandStatus, PackageCaptureSource,
        COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION,
    };

    use super::types::CollectionProfile;

    #[test]
    fn appx_adapter_emits_a_parseable_package_state_capture() {
        let profile = CollectionProfile::embedded();
        let item = profile
            .commands
            .iter()
            .find(|item| item.id == "appx-info")
            .expect("profile must contain the AppX package-state adapter");

        let output = std::process::Command::new(&item.command)
            .args(&item.arguments)
            .output()
            .expect("AppX adapter command must run");
        assert!(
            output.status.success(),
            "adapter exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let capture = parse_package_state_capture(stdout.trim())
            .expect("adapter output must parse as a package-state capture");

        assert_eq!(
            capture.schema_version,
            COMPANY_PORTAL_PACKAGE_STATE_SCHEMA_VERSION
        );
        assert_eq!(capture.capture.source, PackageCaptureSource::Json);
        assert!(!capture.capture.captured_at_utc.is_empty());
        assert!(!capture.capture.adapter_version.is_empty());
        assert!(
            !capture.capture.scope_coverage.is_empty(),
            "the adapter must always report scope coverage"
        );

        // An unelevated CI agent gets accessDenied; an elevated one gets
        // completed. Either is a correctly reported outcome, and neither may be
        // an empty success with no coverage.
        assert!(
            matches!(
                capture.capture.command_status,
                PackageCaptureCommandStatus::Completed
                    | PackageCaptureCommandStatus::AccessDenied
                    | PackageCaptureCommandStatus::Failed
            ),
            "unexpected command status: {:?}",
            capture.capture.command_status
        );
        if capture.capture.command_status != PackageCaptureCommandStatus::Completed {
            assert!(
                capture.capture.error.is_some(),
                "a non-completed capture must carry the failure detail"
            );
        }
    }
}
