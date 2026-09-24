use std::fs;
use std::path::Path;
use std::time::Instant;

use tauri::{Manager, State};

use crate::error::AppError;
use crate::sccm::collector::{
    capture_advanced_authorized, capture_discovered_environment, discover_capture_environment,
    discover_environment_with, NativeDiscoveryProvider, SccmAdvancedCapabilityStore,
    SccmAdvancedCaptureAuthorizationRequest, SccmAdvancedCaptureCapability, SccmCaptureResult,
    SccmCollectorError, SccmDiscoveryProvider, SccmEnvironmentDiscovery,
};
use crate::state::app_state::AppState;

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
    let environment = discover_capture_environment(provider).map_err(collector_error)?;
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
    capture_discovered_environment(environment, &bundle_root).map_err(collector_error)
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

pub(crate) fn authorize_advanced_with_provider(
    provider: &dyn SccmDiscoveryProvider,
    store: &mut SccmAdvancedCapabilityStore,
    request: SccmAdvancedCaptureAuthorizationRequest,
    now: Instant,
) -> Result<SccmAdvancedCaptureCapability, AppError> {
    let environment = provider
        .discover()
        .map_err(|_| AppError::Analysis("discoveryFailed".to_owned()))?;
    store
        .authorize(&environment, request, now)
        .map_err(collector_error)
}

pub(crate) fn capture_advanced_with_store(
    store: &mut SccmAdvancedCapabilityStore,
    cache_root: &Path,
    capability_handle: &str,
    now: Instant,
) -> Result<SccmCaptureResult, AppError> {
    let authorization = store
        .consume(capability_handle, now)
        .map_err(collector_error)?;
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
    match capture_advanced_authorized(authorization, &bundle_root) {
        Ok(result) => Ok(result),
        Err(error) => {
            let _ = fs::remove_dir_all(&bundle_root);
            Err(collector_error(error))
        }
    }
}

#[tauri::command]
pub fn authorize_sccm_advanced_capture(
    state: State<'_, AppState>,
    request: SccmAdvancedCaptureAuthorizationRequest,
) -> Result<SccmAdvancedCaptureCapability, AppError> {
    let mut store = state
        .sccm_advanced_capabilities
        .lock()
        .map_err(|_| collector_error(SccmCollectorError::AdvancedAuthorizationRejected))?;
    authorize_advanced_with_provider(
        &NativeDiscoveryProvider,
        &mut store,
        request,
        Instant::now(),
    )
}

#[tauri::command]
pub fn capture_sccm_advanced_diagnostics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    capability_handle: String,
) -> Result<SccmCaptureResult, AppError> {
    let cache_root = app
        .path()
        .app_cache_dir()
        .map_err(|_| collector_error(SccmCollectorError::DestinationUnavailable))?;
    let mut store = state
        .sccm_advanced_capabilities
        .lock()
        .map_err(|_| collector_error(SccmCollectorError::AdvancedCapabilityUnavailable))?;
    capture_advanced_with_store(&mut store, &cache_root, &capability_handle, Instant::now())
}

#[tauri::command]
pub fn cancel_sccm_advanced_capture(
    state: State<'_, AppState>,
    capability_handle: String,
) -> Result<(), AppError> {
    let mut store = state
        .sccm_advanced_capabilities
        .lock()
        .map_err(|_| collector_error(SccmCollectorError::AdvancedCapabilityUnavailable))?;
    store.cancel(&capability_handle, Instant::now());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccm::collector::{
        PrivateSccmEnvironment, SccmCaptureRoot, SccmCaptureRootOrigin, SccmDetectedRole,
        SccmDiscoveryBasis, SccmDiscoveryFailure,
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
                    origin: SccmCaptureRootOrigin::ServiceExecutableDirectory,
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
                    origin: SccmCaptureRootOrigin::ServiceExecutableDirectory,
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

    #[test]
    fn capture_rejects_supported_environment_without_roles_before_writing() {
        let cache = tempfile::tempdir().expect("temporary cache");
        let provider = FakeProvider {
            environment: PrivateSccmEnvironment {
                supported: true,
                ..PrivateSccmEnvironment::default()
            },
        };

        let error = capture_with_provider(&provider, cache.path()).unwrap_err();
        assert_eq!(error.to_string(), "Analysis failed: noRolesDetected");
        assert!(!cache.path().join("sccm").exists());
        assert_eq!(fs::read_dir(cache.path()).unwrap().count(), 0);
    }

    #[test]
    fn capture_rejects_unsupported_environment_before_writing() {
        let cache = tempfile::tempdir().expect("temporary cache");
        let provider = FakeProvider {
            environment: PrivateSccmEnvironment {
                supported: false,
                ..PrivateSccmEnvironment::default()
            },
        };

        let error = capture_with_provider(&provider, cache.path()).unwrap_err();
        assert_eq!(error.to_string(), "Analysis failed: noRolesDetected");
        assert!(!cache.path().join("sccm").exists());
        assert_eq!(fs::read_dir(cache.path()).unwrap().count(), 0);
    }
}
