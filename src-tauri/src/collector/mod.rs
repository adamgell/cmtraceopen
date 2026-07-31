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
    use cmtraceopen_parser::parser::{decode_bytes, detect_encoding};

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

        // PowerShell writes stdout in the active console code page, which is
        // Windows-1252 on many hosts, so a publisher string or install path can
        // carry non-UTF-8 bytes. from_utf8_lossy would turn those into U+FFFD
        // and fail the parse or corrupt the values.
        let stdout = decode_bytes(&output.stdout, detect_encoding(&output.stdout))
            .expect("adapter stdout must decode");

        // The exit code is deliberately not asserted first. The whole point of
        // the contract is that a denied or failed query is reported inside the
        // JSON, so a non-zero exit accompanied by a parseable capture is a
        // correctly reported outcome. Only an unparseable capture is a failure,
        // and then the exit code and stderr are the useful diagnostics.
        let capture = parse_package_state_capture(stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "adapter output must parse as a package-state capture \
                 (exit {:?}, error {error:?}): {}",
                output.status.code(),
                decode_bytes(&output.stderr, detect_encoding(&output.stderr))
                    .unwrap_or_else(|_| "<undecodable stderr>".to_string())
            )
        });

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
