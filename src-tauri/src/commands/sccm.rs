use std::fs;
use std::path::Path;

use tauri::Manager;

use crate::error::AppError;
use crate::sccm::collector::{
    capture_environment, discover_environment_with, NativeDiscoveryProvider, SccmCaptureResult,
    SccmCollectorError, SccmDiscoveryProvider, SccmEnvironmentDiscovery,
};

fn collector_error(error: SccmCollectorError) -> AppError {
    AppError::Analysis(error.code().to_owned())
}

pub(crate) fn discover_with_provider(
    provider: &dyn SccmDiscoveryProvider,
) -> Result<SccmEnvironmentDiscovery, AppError> {
    discover_environment_with(provider)
        .map_err(|_| AppError::Analysis("discoveryFailed".to_owned()))
}

pub(crate) fn capture_with_provider(
    provider: &dyn SccmDiscoveryProvider,
    cache_root: &Path,
) -> Result<SccmCaptureResult, AppError> {
    let collection_root = cache_root.join("sccm");
    fs::create_dir_all(&collection_root)
        .map_err(|_| collector_error(SccmCollectorError::DestinationUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&collection_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| collector_error(SccmCollectorError::DestinationUnavailable))?;
    }
    let bundle_root = collection_root.join(uuid::Uuid::new_v4().to_string());
    capture_environment(provider, &bundle_root).map_err(collector_error)
}

#[tauri::command]
pub fn discover_sccm_environment() -> Result<SccmEnvironmentDiscovery, AppError> {
    discover_with_provider(&NativeDiscoveryProvider)
}

#[tauri::command]
pub fn capture_sccm_diagnostics(app: tauri::AppHandle) -> Result<SccmCaptureResult, AppError> {
    let cache_root = app
        .path()
        .app_cache_dir()
        .map_err(|_| collector_error(SccmCollectorError::DestinationUnavailable))?;
    capture_with_provider(&NativeDiscoveryProvider, &cache_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccm::collector::{
        PrivateSccmEnvironment, SccmCaptureRoot, SccmDetectedRole, SccmDiscoveryBasis,
        SccmDiscoveryFailure,
    };
    use crate::sccm::SccmRole;

    struct FakeProvider {
        environment: PrivateSccmEnvironment,
    }

    impl SccmDiscoveryProvider for FakeProvider {
        fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
            Ok(self.environment.clone())
        }
    }

    #[test]
    fn discovery_does_not_write_to_the_working_directory() {
        let working = tempfile::tempdir().expect("temporary working directory");
        let provider = FakeProvider {
            environment: PrivateSccmEnvironment {
                supported: true,
                roles: vec![SccmDetectedRole {
                    role: SccmRole::Client,
                    basis: SccmDiscoveryBasis::Registry,
                }],
                ..PrivateSccmEnvironment::default()
            },
        };
        let before = fs::read_dir(working.path()).unwrap().count();
        let discovery = discover_with_provider(&provider).expect("discovery");
        assert!(discovery.supported);
        assert_eq!(fs::read_dir(working.path()).unwrap().count(), before);
    }

    #[test]
    fn capture_chooses_a_uuid_bundle_below_the_cache_root() {
        let cache = tempfile::tempdir().expect("temporary cache");
        let logs = tempfile::tempdir().expect("temporary logs");
        fs::write(logs.path().join("PolicyAgent.log"), b"policy").unwrap();
        let provider = FakeProvider {
            environment: PrivateSccmEnvironment {
                supported: true,
                roles: vec![SccmDetectedRole {
                    role: SccmRole::Client,
                    basis: SccmDiscoveryBasis::Registry,
                }],
                roots: vec![SccmCaptureRoot {
                    role: SccmRole::Client,
                    path: logs.path().to_owned(),
                }],
                ..PrivateSccmEnvironment::default()
            },
        };

        let result = capture_with_provider(&provider, cache.path()).expect("capture");
        let bundle = Path::new(&result.bundle_root);
        assert_eq!(bundle.parent(), Some(cache.path().join("sccm").as_path()));
        assert!(uuid::Uuid::parse_str(bundle.file_name().unwrap().to_str().unwrap()).is_ok());
        assert!(bundle.join("sccm-manifest.json").is_file());
    }

    #[test]
    fn command_errors_expose_only_generic_codes() {
        let cache = tempfile::tempdir().expect("temporary cache");
        let provider = FakeProvider {
            environment: PrivateSccmEnvironment {
                supported: true,
                roles: vec![SccmDetectedRole {
                    role: SccmRole::Client,
                    basis: SccmDiscoveryBasis::Registry,
                }],
                roots: vec![SccmCaptureRoot {
                    role: SccmRole::Client,
                    path: cache.path().join("private-sentinel"),
                }],
                ..PrivateSccmEnvironment::default()
            },
        };
        let file_cache = cache.path().join("not-a-directory");
        fs::write(&file_cache, b"occupied").unwrap();
        let error = capture_with_provider(&provider, &file_cache).unwrap_err();
        assert_eq!(error.to_string(), "Analysis failed: destinationUnavailable");
        assert!(!error.to_string().contains("private-sentinel"));
    }
}
