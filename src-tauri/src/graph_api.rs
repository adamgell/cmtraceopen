//! Microsoft Graph API integration.
//!
//! Portable models compile on every platform. The existing WAM token cache and
//! concrete HTTP implementation remain Windows-only and user-opt-in.

pub mod client;
#[cfg(feature = "esp-diagnostics")]
pub mod correlation;
#[cfg(feature = "esp-diagnostics")]
pub mod esp;
pub mod models;

pub use models::{
    normalize_graph_guid, project_graph_auth_status, GraphAppInfo, GraphAuthCapabilities,
    GraphAuthStatus, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
    GraphTransportResponse, GraphWamPermissionRequestContract, GraphWamRequestContract,
    GRAPH_DELEGATED_SCOPES, GRAPH_SCOPE_REQUEST, GRAPH_WAM_PERMISSION_REQUEST,
    GRAPH_WAM_PERMISSION_SCOPE_REQUEST, GRAPH_WAM_REQUEST,
};

#[cfg(any(target_os = "windows", test))]
fn is_wam_consent_denial(error_code: Option<u32>, error_message: Option<&str>) -> bool {
    const USER_DECLINED_CONSENT_CODE: u32 = 65_004;
    const DENIAL_IDENTIFIERS: [&str; 3] = ["AADSTS65004", "UserDeclinedConsent", "access_denied"];

    error_code == Some(USER_DECLINED_CONSENT_CODE)
        || error_message.is_some_and(|message| {
            message
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .any(|identifier| {
                    DENIAL_IDENTIFIERS
                        .iter()
                        .any(|expected| identifier.eq_ignore_ascii_case(expected))
                })
        })
}

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
struct VersionedGuidCache {
    generation: u64,
    apps: std::collections::HashMap<String, GraphAppInfo>,
}

#[cfg(any(target_os = "windows", test))]
impl VersionedGuidCache {
    fn get(&self, generation: u64, guid: &str) -> Option<GraphAppInfo> {
        (self.generation == generation)
            .then(|| self.apps.get(guid).cloned())
            .flatten()
    }

    fn insert_all(
        &mut self,
        generation: u64,
        apps: &std::collections::HashMap<String, GraphAppInfo>,
    ) {
        if self.generation != generation {
            return;
        }
        for (key, app) in apps {
            self.apps.insert(key.clone(), app.clone());
        }
    }

    fn replace_all(
        &mut self,
        generation: u64,
        apps: std::collections::HashMap<String, GraphAppInfo>,
    ) {
        if self.generation == generation {
            self.apps = apps;
        }
    }

    fn reset_to(&mut self, generation: u64) {
        if generation <= self.generation {
            return;
        }
        self.generation = generation;
        self.apps.clear();
    }
}

#[cfg(any(target_os = "windows", test))]
struct VersionedAuthSlot<T> {
    generation: u64,
    value: Option<T>,
}

#[cfg(any(target_os = "windows", test))]
impl<T> Default for VersionedAuthSlot<T> {
    fn default() -> Self {
        Self {
            generation: 0,
            value: None,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
impl<T> VersionedAuthSlot<T> {
    fn replace(&mut self, value: Option<T>) -> u64 {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("Graph auth generation exhausted");
        self.value = value;
        self.generation
    }

    fn replace_if_generation(&mut self, expected: u64, value: Option<T>) -> Option<u64> {
        if self.generation != expected {
            return None;
        }
        Some(self.replace(value))
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadlineReceiveError {
    Timeout,
    Disconnected,
}

#[cfg(any(target_os = "windows", test))]
fn receive_before_deadline<T>(
    receiver: &std::sync::mpsc::Receiver<T>,
    deadline: std::time::Instant,
) -> Result<T, DeadlineReceiveError> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(DeadlineReceiveError::Timeout);
    }
    match receiver.recv_timeout(remaining) {
        Ok(value) => Ok(value),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(DeadlineReceiveError::Timeout),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(DeadlineReceiveError::Disconnected)
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn invalid_graph_app_response(required_scope: &str) -> client::GraphClientError {
    client::GraphClientError::new(
        client::GraphClientErrorKind::InvalidResponse,
        required_scope,
    )
}

#[cfg(any(target_os = "windows", test))]
fn optional_graph_string(
    item: &serde_json::Value,
    key: &str,
    required_scope: &str,
) -> Result<Option<String>, client::GraphClientError> {
    match item.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_graph_app_response(required_scope)),
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_graph_app_json(
    item: &serde_json::Value,
    default_type: Option<&str>,
    expected_id: Option<&str>,
    required_scope: &str,
) -> Result<GraphAppInfo, client::GraphClientError> {
    let id = item
        .get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_graph_guid)
        .ok_or_else(|| invalid_graph_app_response(required_scope))?;
    if expected_id.is_some_and(|expected| id != expected) {
        return Err(invalid_graph_app_response(required_scope));
    }
    let display_name = item
        .get("displayName")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_graph_app_response(required_scope))?
        .to_string();
    let publisher = optional_graph_string(item, "publisher", required_scope)?;
    let odata_type = optional_graph_string(item, "@odata.type", required_scope)?
        .or_else(|| default_type.map(String::from));

    Ok(GraphAppInfo {
        id,
        display_name,
        publisher,
        odata_type,
    })
}

#[cfg(any(target_os = "windows", test))]
fn parse_graph_app_values(
    values: &[serde_json::Value],
    default_type: Option<&str>,
    required_scope: &str,
) -> Result<Vec<GraphAppInfo>, client::GraphClientError> {
    values
        .iter()
        .map(|item| parse_graph_app_json(item, default_type, None, required_scope))
        .collect()
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    use super::client::{
        resolve_app_chunk_with_fallback, GraphBatchItem, GraphCancellation, GraphClient,
        GraphClientError, GraphClientErrorKind, GraphTransport, GraphTransportFailure,
        MAX_GRAPH_RESPONSE_BYTES,
    };
    #[cfg(feature = "esp-diagnostics")]
    use super::esp::{
        EspGraphClientProvider, EspGraphEndpoint, EspGraphOperation, EspGraphOperationError,
        EspGraphOperationRegistry, EspGraphProvider, EspGraphRequest,
    };
    use super::models::{
        classify_graph_permission_candidate, GraphPermissionCandidateDecision,
        GraphPermissionUpgradeOutcome, GraphPermissionUpgradeResult,
    };
    use super::{
        normalize_graph_guid, parse_graph_app_json, parse_graph_app_values,
        project_graph_auth_status, receive_before_deadline, DeadlineReceiveError, GraphAppInfo,
        GraphAuthStatus, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
        GraphTransportResponse, VersionedAuthSlot, VersionedGuidCache,
        GRAPH_WAM_PERMISSION_REQUEST, GRAPH_WAM_REQUEST,
    };
    use crate::error::AppError;

    // ── Public types ────────────────────────────────────────────────────────────

    // ── Token cache ─────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct GraphAuthStateInner {
        access_token: Mutex<VersionedAuthSlot<CachedToken>>,
        guid_cache: Mutex<VersionedGuidCache>,
        #[cfg(feature = "esp-diagnostics")]
        esp_operations: EspGraphOperationRegistry,
        #[cfg(test)]
        dependent_generation_advances: std::sync::atomic::AtomicUsize,
    }

    #[derive(Clone, Default)]
    pub struct GraphAuthState {
        inner: Arc<GraphAuthStateInner>,
    }

    #[derive(Clone)]
    struct CachedToken {
        token: String,
        status: GraphAuthStatus,
    }

    enum WamAcquisitionFailure {
        Cancelled,
        Denied(AppError),
        Failed(AppError),
    }

    const WAM_USER_INTERACTION_REQUIRED_MESSAGE: &str =
        "Interactive authentication required. Please sign in to Windows with your Entra ID account first.";

    impl From<AppError> for WamAcquisitionFailure {
        fn from(error: AppError) -> Self {
            Self::Failed(error)
        }
    }

    impl WamAcquisitionFailure {
        fn into_initial_auth_error(self) -> AppError {
            match self {
                Self::Cancelled => {
                    AppError::Internal("Authentication was cancelled by user.".into())
                }
                Self::Denied(error) | Self::Failed(error) => error,
            }
        }
    }

    fn wam_provider_legacy_error(error_message: Option<String>) -> AppError {
        let error_message = error_message.unwrap_or_else(|| "Unknown WAM error".to_string());
        AppError::Internal(format!("WAM authentication failed: {error_message}"))
    }

    fn wam_provider_status_failure(
        error_code: Option<u32>,
        error_message: Option<String>,
    ) -> WamAcquisitionFailure {
        let denied = super::is_wam_consent_denial(error_code, error_message.as_deref());
        let legacy_error = wam_provider_legacy_error(error_message);
        if denied {
            WamAcquisitionFailure::Denied(legacy_error)
        } else {
            WamAcquisitionFailure::Failed(legacy_error)
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    impl GraphAuthState {
        pub fn new() -> Self {
            Self::default()
        }

        fn get_valid_token_snapshot(&self) -> (Option<CachedToken>, u64) {
            let mut guard = self.inner.access_token.lock().unwrap();
            let is_valid = guard
                .value
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if is_valid {
                return (guard.value.clone(), guard.generation);
            }

            if guard.value.is_none() {
                return (None, guard.generation);
            }

            let generation = guard.replace(None);
            self.advance_dependent_generation(generation);
            drop(guard);
            (None, generation)
        }

        fn get_valid_token(&self) -> Option<(CachedToken, u64)> {
            let (token, generation) = self.get_valid_token_snapshot();
            token.map(|token| (token, generation))
        }

        fn claim_authentication(&self) -> Result<CachedToken, u64> {
            let mut guard = self.inner.access_token.lock().unwrap();
            let is_valid = guard
                .value
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if is_valid {
                return Ok(guard
                    .value
                    .clone()
                    .expect("validated Graph token must remain present"));
            }

            let generation = guard.replace(None);
            self.advance_dependent_generation(generation);
            drop(guard);
            Err(generation)
        }

        fn set_token_if_generation(&self, expected: u64, token: CachedToken) -> bool {
            let mut guard = self.inner.access_token.lock().unwrap();
            let Some(generation) = guard.replace_if_generation(expected, Some(token)) else {
                return false;
            };
            self.advance_dependent_generation(generation);
            drop(guard);
            true
        }

        fn clear_token_if_generation(&self, expected: u64) -> bool {
            let mut guard = self.inner.access_token.lock().unwrap();
            let Some(generation) = guard.replace_if_generation(expected, None) else {
                return false;
            };
            self.advance_dependent_generation(generation);
            drop(guard);
            true
        }

        fn clear_token(&self) {
            let mut guard = self.inner.access_token.lock().unwrap();
            let generation = guard.replace(None);
            self.advance_dependent_generation(generation);
            drop(guard);
        }

        /// Advance dependent in-memory state while the auth slot remains
        /// locked. The global lock order is auth -> ESP registry -> GUID cache,
        /// so a new token generation cannot become observable before operation
        /// ownership is ready for that same generation.
        fn advance_dependent_generation(&self, generation: u64) {
            #[cfg(test)]
            self.inner
                .dependent_generation_advances
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            #[cfg(feature = "esp-diagnostics")]
            self.inner.esp_operations.advance_generation(generation);
            self.inner.guid_cache.lock().unwrap().reset_to(generation);
        }

        fn get_cached_app(&self, generation: u64, guid: &str) -> Option<GraphAppInfo> {
            self.inner.guid_cache.lock().unwrap().get(generation, guid)
        }

        fn cache_apps(&self, generation: u64, apps: &HashMap<String, GraphAppInfo>) {
            self.inner
                .guid_cache
                .lock()
                .unwrap()
                .insert_all(generation, apps);
        }

        fn replace_apps(&self, generation: u64, apps: HashMap<String, GraphAppInfo>) {
            self.inner
                .guid_cache
                .lock()
                .unwrap()
                .replace_all(generation, apps);
        }

        #[cfg(feature = "esp-diagnostics")]
        fn acquire_esp_operation(
            &self,
            request_id: &str,
        ) -> Result<Option<(CachedToken, u64, EspGraphOperation)>, EspGraphOperationError> {
            let mut guard = self.inner.access_token.lock().unwrap();
            let is_valid = guard
                .value
                .as_ref()
                .and_then(|token| token.status.expires_at)
                .is_some_and(|expires_at| expires_at > unix_now());
            if !is_valid && guard.value.is_some() {
                let generation = guard.replace(None);
                self.advance_dependent_generation(generation);
            }

            let generation = guard.generation;
            self.inner.esp_operations.advance_generation(generation);
            let operation = self.inner.esp_operations.begin(request_id, generation)?;
            let token = guard.value.clone();
            drop(guard);

            Ok(token.map(|token| (token, generation, operation)))
        }

        #[cfg(feature = "esp-diagnostics")]
        pub(crate) fn cancel_esp_operation(&self, request_id: &str) -> bool {
            self.inner.esp_operations.cancel(request_id)
        }
    }

    // ── WAM token acquisition (Windows only) ────────────────────────────────────

    /// Well-known Microsoft Graph PowerShell client ID (public client, no app reg needed).
    const GRAPH_POWERSHELL_CLIENT_ID: &str = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

    mod wam {
        use super::*;

        use windows::core::{factory, RuntimeType, HSTRING};
        use windows::Security::Authentication::Web::Core::{
            WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestPromptType,
            WebTokenRequestResult, WebTokenRequestStatus,
        };
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::WinRT::{
            IWebAuthenticationCoreManagerInterop, RoInitialize, RoUninitialize,
            RO_INIT_MULTITHREADED,
        };
        use windows_future::{AsyncOperationCompletedHandler, IAsyncOperation};

        const GRAPH_WAM_ACQUISITION_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(120);

        #[derive(Clone, Copy)]
        enum WamRequestMode {
            InitialConnect,
            PermissionConsent,
        }

        struct WinRtApartment;

        impl WinRtApartment {
            fn initialize() -> Result<Self, AppError> {
                unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|error| {
                    AppError::Internal(format!("WAM worker WinRT initialization failed: {error}"))
                })?;
                Ok(Self)
            }
        }

        impl Drop for WinRtApartment {
            fn drop(&mut self) {
                unsafe { RoUninitialize() };
            }
        }

        fn wait_for_operation<T>(
            operation: &IAsyncOperation<T>,
            deadline: std::time::Instant,
            stage: &str,
        ) -> Result<T, AppError>
        where
            T: RuntimeType + Send + 'static,
        {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            operation
                .SetCompleted(&AsyncOperationCompletedHandler::new(move |completed, _| {
                    let result = completed.ok().and_then(IAsyncOperation::GetResults);
                    let _ = sender.send(result);
                    Ok(())
                }))
                .map_err(|error| {
                    AppError::Internal(format!(
                        "WAM {stage} completion registration failed: {error}"
                    ))
                })?;

            match receive_before_deadline(&receiver, deadline) {
                Ok(result) => result
                    .map_err(|error| AppError::Internal(format!("WAM {stage} failed: {error}"))),
                Err(DeadlineReceiveError::Timeout) => {
                    let _ = operation.Cancel();
                    Err(AppError::Internal(format!(
                        "WAM authentication timed out during {stage} after {} seconds.",
                        GRAPH_WAM_ACQUISITION_TIMEOUT.as_secs()
                    )))
                }
                Err(DeadlineReceiveError::Disconnected) => Err(AppError::Internal(format!(
                    "WAM {stage} completion channel disconnected."
                ))),
            }
        }

        /// Acquire a token via WAM using the Win32 interop path.
        ///
        /// Desktop (Win32) apps don't have a CoreWindow, so we must use
        /// `IWebAuthenticationCoreManagerInterop::RequestTokenForWindowAsync`
        /// with an explicit HWND instead of the UWP `RequestTokenAsync`.
        pub fn acquire_permission_consent_token_on_initialized_worker(
            hwnd_raw: isize,
        ) -> Result<CachedToken, WamAcquisitionFailure> {
            let _apartment = WinRtApartment::initialize()?;
            acquire_token_with_request(hwnd_raw, WamRequestMode::PermissionConsent)
        }

        pub fn acquire_token(hwnd_raw: isize) -> Result<CachedToken, WamAcquisitionFailure> {
            acquire_token_with_request(hwnd_raw, WamRequestMode::InitialConnect)
        }

        fn acquire_token_with_request(
            hwnd_raw: isize,
            request_mode: WamRequestMode,
        ) -> Result<CachedToken, WamAcquisitionFailure> {
            let hwnd = HWND(hwnd_raw as *mut _);
            let deadline = std::time::Instant::now() + GRAPH_WAM_ACQUISITION_TIMEOUT;

            // Provider lookup doesn't need a window
            let authority = HSTRING::from("organizations");
            let provider_operation =
                WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
                    &HSTRING::from("https://login.microsoft.com"),
                    &authority,
                )
                .map_err(|e| AppError::Internal(format!("WAM provider lookup failed: {e}")))?;
            let provider = wait_for_operation(&provider_operation, deadline, "provider lookup")?;

            let client_id = HSTRING::from(GRAPH_POWERSHELL_CLIENT_ID);
            let request = match request_mode {
                WamRequestMode::PermissionConsent => {
                    let scope = HSTRING::from(GRAPH_WAM_PERMISSION_REQUEST.scope);
                    if GRAPH_WAM_PERMISSION_REQUEST.force_authentication {
                        WebTokenRequest::CreateWithPromptType(
                            &provider,
                            &scope,
                            &client_id,
                            WebTokenRequestPromptType::ForceAuthentication,
                        )
                    } else {
                        WebTokenRequest::Create(&provider, &scope, &client_id)
                    }
                }
                WamRequestMode::InitialConnect => {
                    let scope = HSTRING::from(GRAPH_WAM_REQUEST.scope);
                    WebTokenRequest::Create(&provider, &scope, &client_id)
                }
            }
            .map_err(|e| AppError::Internal(format!("WAM request creation failed: {e}")))?;

            let properties = request
                .Properties()
                .map_err(|e| AppError::Internal(format!("WAM properties failed: {e}")))?;
            match request_mode {
                WamRequestMode::PermissionConsent => {
                    // The explicit permission action mirrors MSAL's Entra WAM
                    // v2 consent shape. In particular, it must not attach the
                    // v1 `resource` property or WAM may reuse the cached token.
                    for &(name, value) in GRAPH_WAM_PERMISSION_REQUEST.properties {
                        properties
                            .Insert(&HSTRING::from(name), &HSTRING::from(value))
                            .map_err(|e| {
                                AppError::Internal(format!("WAM set consent property failed: {e}"))
                            })?;
                    }
                }
                WamRequestMode::InitialConnect => {
                    // Preserve the established initial-connect contract.
                    // Without this resource property the legacy/default request
                    // can report Success while returning an empty token.
                    properties
                        .Insert(
                            &HSTRING::from(GRAPH_WAM_REQUEST.resource_property),
                            &HSTRING::from(GRAPH_WAM_REQUEST.resource),
                        )
                        .map_err(|e| AppError::Internal(format!("WAM set resource failed: {e}")))?;
                }
            }

            // Use the COM interop interface to pass our HWND
            let interop: IWebAuthenticationCoreManagerInterop =
                factory::<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerInterop>()
                    .map_err(|e| AppError::Internal(format!("WAM interop factory failed: {e}")))?;

            let operation: IAsyncOperation<WebTokenRequestResult> =
                unsafe { interop.RequestTokenForWindowAsync(hwnd, &request) }
                    .map_err(|e| AppError::Internal(format!("WAM token request failed: {e}")))?;

            let result = wait_for_operation(&operation, deadline, "token request")?;

            let status = result
                .ResponseStatus()
                .map_err(|e| AppError::Internal(format!("WAM status check failed: {e}")))?;

            match status {
                WebTokenRequestStatus::Success => {
                    let responses = result
                        .ResponseData()
                        .map_err(|e| AppError::Internal(format!("WAM response data: {e}")))?;
                    let response = responses
                        .GetAt(0)
                        .map_err(|e| AppError::Internal(format!("WAM response index: {e}")))?;

                    let token = response
                        .Token()
                        .map_err(|e| AppError::Internal(format!("WAM token extract: {e}")))?
                        .to_string();

                    if token.is_empty() {
                        return Err(AppError::Internal(
                            "WAM returned Success but the access token is empty. \
                             The delegated scope request did not return usable credentials."
                                .into(),
                        )
                        .into());
                    }

                    let upn = response
                        .WebAccount()
                        .ok()
                        .and_then(|acct| acct.UserName().ok())
                        .map(|s| s.to_string());

                    let tenant = response
                        .Properties()
                        .ok()
                        .and_then(|props| props.Lookup(&HSTRING::from("TenantId")).ok())
                        .map(|s| s.to_string());

                    let status = project_graph_auth_status(
                        &token,
                        upn.as_deref(),
                        tenant.as_deref(),
                        unix_now(),
                    );
                    if !status.is_authenticated {
                        return Err(AppError::Internal(
                            status
                                .error
                                .clone()
                                .unwrap_or_else(|| "InvalidWamToken".to_string()),
                        )
                        .into());
                    }

                    Ok(CachedToken { token, status })
                }
                WebTokenRequestStatus::UserCancel => Err(WamAcquisitionFailure::Cancelled),
                WebTokenRequestStatus::UserInteractionRequired => {
                    Err(WamAcquisitionFailure::Denied(AppError::Internal(
                        WAM_USER_INTERACTION_REQUIRED_MESSAGE.into(),
                    )))
                }
                WebTokenRequestStatus::ProviderError => {
                    let provider_error = result.ResponseError().ok();
                    let error_code = provider_error
                        .as_ref()
                        .and_then(|error| error.ErrorCode().ok());
                    let error_message = provider_error
                        .and_then(|error| error.ErrorMessage().ok())
                        .map(|message| message.to_string());
                    Err(wam_provider_status_failure(error_code, error_message))
                }
                _ => {
                    let error_message = result
                        .ResponseError()
                        .ok()
                        .and_then(|error| error.ErrorMessage().ok())
                        .map(|message| message.to_string());
                    Err(WamAcquisitionFailure::Failed(wam_provider_legacy_error(
                        error_message,
                    )))
                }
            }
        }
    }

    // ── Graph API calls ─────────────────────────────────────────────────────────

    const GRAPH_BETA_BASE: &str = "https://graph.microsoft.com/beta";
    const MAX_GRAPH_RESOLUTION_IDS: usize = 5_000;

    struct UreqGraphTransport<'a> {
        access_token: &'a str,
        deadline: Option<std::time::Instant>,
    }

    impl GraphTransport for UreqGraphTransport<'_> {
        fn execute(
            &self,
            request: &GraphTransportRequest,
            timeout: std::time::Duration,
        ) -> Result<GraphTransportResponse, GraphTransportFailure> {
            let timeout = self
                .deadline
                .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or(timeout)
                .min(timeout);
            if timeout.is_zero() {
                return Err(GraphTransportFailure::Timeout);
            }
            let agent = ureq::Agent::config_builder()
                .https_only(true)
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(timeout))
                .timeout_connect(Some(timeout.min(std::time::Duration::from_secs(10))))
                .timeout_recv_response(Some(timeout))
                .timeout_recv_body(Some(timeout))
                .build()
                .new_agent();
            let authorization = format!("Bearer {}", self.access_token);

            let response = match request.method {
                GraphHttpMethod::Get => {
                    let mut builder = agent
                        .get(&request.url)
                        .header("Authorization", &authorization);
                    if let Some(consistency) = &request.consistency_level {
                        builder = builder.header("ConsistencyLevel", consistency);
                    }
                    builder.call()
                }
                GraphHttpMethod::Post => {
                    let mut builder = agent
                        .post(&request.url)
                        .header("Authorization", &authorization);
                    if let Some(consistency) = &request.consistency_level {
                        builder = builder.header("ConsistencyLevel", consistency);
                    }
                    if let Some(content_type) = &request.content_type {
                        builder = builder.header("Content-Type", content_type);
                    }
                    match &request.body {
                        Some(body) => builder.send(body.as_slice()),
                        None => builder.send_empty(),
                    }
                }
            }
            .map_err(map_ureq_transport_error)?;

            bounded_transport_response(response)
        }
    }

    struct NoGraphCancellation;

    impl GraphCancellation for NoGraphCancellation {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn wait_for_retry(&self, duration: std::time::Duration) -> bool {
            std::thread::sleep(duration);
            true
        }
    }

    #[cfg(feature = "esp-diagnostics")]
    struct WindowsEspGraphProvider {
        state: GraphAuthState,
        token: CachedToken,
        generation: u64,
        deadline: std::time::Instant,
    }

    #[cfg(feature = "esp-diagnostics")]
    impl WindowsEspGraphProvider {
        fn execute_endpoint(
            &self,
            endpoint: &EspGraphEndpoint,
            cancellation: &dyn GraphCancellation,
            collection: bool,
        ) -> Result<serde_json::Value, GraphClientError> {
            let transport = UreqGraphTransport {
                access_token: &self.token.token,
                deadline: Some(self.deadline),
            };
            let provider = EspGraphClientProvider::new(&transport);
            let result = if collection {
                provider.get_collection(endpoint, cancellation)
            } else {
                provider.get(endpoint, cancellation)
            };
            if let Err(error) = &result {
                if error.invalidates_auth() {
                    self.state.clear_token_if_generation(self.generation);
                }
            }
            result
        }
    }

    #[cfg(feature = "esp-diagnostics")]
    impl EspGraphProvider for WindowsEspGraphProvider {
        fn get(
            &self,
            endpoint: &EspGraphEndpoint,
            cancellation: &dyn GraphCancellation,
        ) -> Result<serde_json::Value, GraphClientError> {
            self.execute_endpoint(endpoint, cancellation, false)
        }

        fn get_collection(
            &self,
            endpoint: &EspGraphEndpoint,
            cancellation: &dyn GraphCancellation,
        ) -> Result<serde_json::Value, GraphClientError> {
            self.execute_endpoint(endpoint, cancellation, true)
        }
    }

    #[cfg(feature = "esp-diagnostics")]
    pub struct PreparedEspGraphRequest {
        provider: WindowsEspGraphProvider,
        request: EspGraphRequest,
        operation: EspGraphOperation,
    }

    #[cfg(feature = "esp-diagnostics")]
    impl PreparedEspGraphRequest {
        pub fn execute(self) -> cmtraceopen_parser::esp::EspGraphOverlay {
            let requested_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            super::esp::fetch_esp_graph_overlay(
                &self.provider,
                &self.request,
                &self.operation,
                &requested_at,
            )
        }
    }

    #[cfg(feature = "esp-diagnostics")]
    pub fn prepare_esp_diagnostics(
        state: &GraphAuthState,
        request: EspGraphRequest,
    ) -> Result<PreparedEspGraphRequest, AppError> {
        let (token, generation, operation) = state
            .acquire_esp_operation(&request.request_id)
            .map_err(|error| AppError::InvalidInput(error.to_string()))?
            .ok_or_else(|| AppError::Internal("GraphNotConnected".to_string()))?;
        let deadline = std::time::Instant::now() + operation.remaining();
        Ok(PreparedEspGraphRequest {
            provider: WindowsEspGraphProvider {
                state: state.clone(),
                token,
                generation,
                deadline,
            },
            request,
            operation,
        })
    }

    #[cfg(feature = "esp-diagnostics")]
    pub fn cancel_esp_diagnostics(state: &GraphAuthState, request_id: &str) -> bool {
        state.cancel_esp_operation(request_id)
    }

    fn map_ureq_transport_error(error: ureq::Error) -> GraphTransportFailure {
        match error {
            ureq::Error::Timeout(_) => GraphTransportFailure::Timeout,
            _ => GraphTransportFailure::Network,
        }
    }

    fn bounded_transport_response(
        response: ureq::http::Response<ureq::Body>,
    ) -> Result<GraphTransportResponse, GraphTransportFailure> {
        let (parts, body) = response.into_parts();
        let headers: BTreeMap<String, String> = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        let mut bytes = Vec::new();
        body.into_reader()
            .take((MAX_GRAPH_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    GraphTransportFailure::Timeout
                } else {
                    GraphTransportFailure::Network
                }
            })?;

        Ok(GraphTransportResponse {
            status: parts.status.as_u16(),
            headers,
            body: bytes,
        })
    }

    fn graph_request_error(
        state: &GraphAuthState,
        generation: u64,
        error: GraphClientError,
    ) -> AppError {
        if error.invalidates_auth() {
            state.clear_token_if_generation(generation);
        }
        AppError::Internal(error.to_string())
    }

    fn current_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
        state
            .get_valid_token()
            .map(|(cached, _)| cached.status)
            .unwrap_or_else(|| GraphAuthStatus::disconnected(None))
    }

    const GRAPH_PERMISSION_DENIED_MESSAGE: &str =
        "Consent was not granted. Your existing Graph permissions remain available. A tenant administrator may need to approve the missing permissions.";
    const GRAPH_PERMISSION_FAILED_MESSAGE: &str =
        "Windows could not complete the permission request. Your existing Graph permissions remain available.";
    const GRAPH_PERMISSION_STALE_MESSAGE: &str =
        "The permission request was superseded by a newer Graph connection change.";

    fn retained_permission_upgrade_result(
        state: &GraphAuthState,
        expected_generation: u64,
        outcome: GraphPermissionUpgradeOutcome,
        message: Option<&'static str>,
    ) -> GraphPermissionUpgradeResult {
        let (token, generation) = state.get_valid_token_snapshot();
        let status = token
            .map(|cached| cached.status)
            .unwrap_or_else(|| GraphAuthStatus::disconnected(None));
        if generation == expected_generation {
            GraphPermissionUpgradeResult {
                outcome,
                status,
                message: message.map(str::to_string),
            }
        } else {
            GraphPermissionUpgradeResult {
                outcome: GraphPermissionUpgradeOutcome::Stale,
                status,
                message: Some(GRAPH_PERMISSION_STALE_MESSAGE.to_string()),
            }
        }
    }

    fn request_missing_permissions_with<F>(
        state: &GraphAuthState,
        acquire: F,
    ) -> Result<GraphPermissionUpgradeResult, AppError>
    where
        F: FnOnce() -> Result<CachedToken, WamAcquisitionFailure>,
    {
        let (current, generation) = state.get_valid_token().ok_or_else(|| {
            AppError::InvalidInput("Microsoft Graph is not connected.".to_string())
        })?;
        if current.status.missing_scopes.is_empty() {
            return Err(AppError::InvalidInput(
                "No Microsoft Graph permissions are missing.".to_string(),
            ));
        }

        let candidate = match acquire() {
            Ok(candidate) => candidate,
            Err(WamAcquisitionFailure::Cancelled) => {
                return Ok(retained_permission_upgrade_result(
                    state,
                    generation,
                    GraphPermissionUpgradeOutcome::Cancelled,
                    None,
                ));
            }
            Err(WamAcquisitionFailure::Denied(_)) => {
                return Ok(retained_permission_upgrade_result(
                    state,
                    generation,
                    GraphPermissionUpgradeOutcome::Denied,
                    Some(GRAPH_PERMISSION_DENIED_MESSAGE),
                ));
            }
            Err(WamAcquisitionFailure::Failed(_)) => {
                return Ok(retained_permission_upgrade_result(
                    state,
                    generation,
                    GraphPermissionUpgradeOutcome::Failed,
                    Some(GRAPH_PERMISSION_FAILED_MESSAGE),
                ));
            }
        };

        match classify_graph_permission_candidate(&current.status, &candidate.status) {
            GraphPermissionCandidateDecision::Upgrade => {
                let status = candidate.status.clone();
                if state.set_token_if_generation(generation, candidate) {
                    Ok(GraphPermissionUpgradeResult {
                        outcome: GraphPermissionUpgradeOutcome::Upgraded,
                        status,
                        message: None,
                    })
                } else {
                    Ok(retained_permission_upgrade_result(
                        state,
                        generation,
                        GraphPermissionUpgradeOutcome::Stale,
                        Some(GRAPH_PERMISSION_STALE_MESSAGE),
                    ))
                }
            }
            GraphPermissionCandidateDecision::Unchanged => Ok(retained_permission_upgrade_result(
                state,
                generation,
                GraphPermissionUpgradeOutcome::Unchanged,
                None,
            )),
            GraphPermissionCandidateDecision::InvalidCandidate
            | GraphPermissionCandidateDecision::AccountMismatch
            | GraphPermissionCandidateDecision::TenantMismatch
            | GraphPermissionCandidateDecision::ScopeRegression => {
                Ok(retained_permission_upgrade_result(
                    state,
                    generation,
                    GraphPermissionUpgradeOutcome::Failed,
                    Some(GRAPH_PERMISSION_FAILED_MESSAGE),
                ))
            }
        }
    }

    /// Authenticate with Graph API via WAM. Returns current auth status.
    /// `hwnd_raw` is the native window handle for the WAM dialog.
    pub fn authenticate(
        state: &GraphAuthState,
        hwnd_raw: isize,
    ) -> Result<GraphAuthStatus, AppError> {
        let expected_generation = match state.claim_authentication() {
            Ok(cached) => return Ok(cached.status),
            Err(generation) => generation,
        };

        match wam::acquire_token(hwnd_raw) {
            Ok(token) => {
                let status = token.status.clone();
                if state.set_token_if_generation(expected_generation, token) {
                    Ok(status)
                } else {
                    Ok(current_auth_status(state))
                }
            }
            Err(failure) => {
                let error = failure.into_initial_auth_error();
                if state.clear_token_if_generation(expected_generation) {
                    Ok(GraphAuthStatus::disconnected(Some(error.to_string())))
                } else {
                    Ok(current_auth_status(state))
                }
            }
        }
    }

    pub fn request_missing_permissions_on_initialized_worker(
        state: &GraphAuthState,
        hwnd_raw: isize,
    ) -> Result<GraphPermissionUpgradeResult, AppError> {
        request_missing_permissions_with(state, || {
            wam::acquire_permission_consent_token_on_initialized_worker(hwnd_raw)
        })
    }

    /// Get current auth status without triggering a new auth flow.
    pub fn get_auth_status(state: &GraphAuthState) -> GraphAuthStatus {
        current_auth_status(state)
    }

    /// Sign out — clear cached token and GUID cache.
    pub fn sign_out(state: &GraphAuthState) {
        state.clear_token();
    }

    /// Resolve a batch of GUIDs to app display names via Graph API.
    pub fn resolve_guids(
        state: &GraphAuthState,
        guids: &[String],
    ) -> Result<GraphResolutionResult, AppError> {
        if guids.len() > MAX_GRAPH_RESOLUTION_IDS {
            return Err(AppError::Internal(format!(
                "Graph app resolution is limited to {MAX_GRAPH_RESOLUTION_IDS} identifiers."
            )));
        }
        let (token, generation) = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut resolved: HashMap<String, GraphAppInfo> = HashMap::new();
        let mut to_fetch: Vec<String> = Vec::new();
        let mut queued = HashSet::new();
        let mut invalid_identifiers = 0_usize;

        for guid in guids {
            let Some(normalized) = normalize_graph_guid(guid) else {
                invalid_identifiers += 1;
                continue;
            };
            if let Some(cached) = state.get_cached_app(generation, &normalized) {
                resolved.insert(normalized, cached);
            } else if queued.insert(normalized.clone()) {
                to_fetch.push(normalized);
            }
        }

        let mut errors = Vec::new();
        if invalid_identifiers > 0 {
            errors.push(format!(
                "Skipped {invalid_identifiers} invalid app identifier(s)."
            ));
        }

        if to_fetch.is_empty() {
            return Ok(GraphResolutionResult {
                resolved,
                not_found: vec![],
                errors,
            });
        }

        let mut not_found = Vec::new();

        // Graph $batch supports max 20 requests per batch
        for chunk in to_fetch.chunks(20) {
            let chunk_result = resolve_app_chunk_with_fallback(
                chunk,
                |guids| fetch_apps_batch(&token.token, guids),
                |guid| fetch_single_app(&token.token, guid),
            )
            .map_err(|error| graph_request_error(state, generation, error))?;

            for (guid, info) in chunk_result.resolved {
                resolved.insert(guid, info);
            }
            not_found.extend(chunk_result.not_found);
            errors.extend(chunk_result.errors);
        }

        state.cache_apps(generation, &resolved);

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors,
        })
    }

    /// Fetch all Intune apps, scripts, and remediations for pre-populating the cache.
    pub fn fetch_all_apps(state: &GraphAuthState) -> Result<Vec<GraphAppInfo>, AppError> {
        let (token, generation) = state
            .get_valid_token()
            .ok_or_else(|| AppError::Internal("Not authenticated. Please sign in first.".into()))?;

        let mut all: Vec<GraphAppInfo> = Vec::new();

        // Win32/LOB/Store apps
        all.extend(
            fetch_paginated(
                &token.token,
                &format!(
                    "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps?$select=id,displayName,publisher"
                ),
                None,
                "DeviceManagementApps.Read.All",
            )
            .map_err(|error| graph_request_error(state, generation, error))?,
        );

        // Proactive Remediations (Health Scripts)
        match fetch_paginated(
        &token.token,
        &format!("{GRAPH_BETA_BASE}/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher"),
        Some("#microsoft.graph.deviceHealthScript"),
        "DeviceManagementScripts.Read.All",
    ) {
        Ok(items) => all.extend(items),
        Err(error) if error.invalidates_auth() => {
            return Err(graph_request_error(state, generation, error));
        }
        Err(error) => log::warn!("event=graph_skip_health_scripts error=\"{error}\""),
    }

        // Platform scripts (PowerShell scripts deployed via Intune)
        match fetch_paginated(
            &token.token,
            &format!(
                "{GRAPH_BETA_BASE}/deviceManagement/deviceManagementScripts?$select=id,displayName"
            ),
            Some("#microsoft.graph.deviceManagementScript"),
            "DeviceManagementScripts.Read.All",
        ) {
            Ok(items) => all.extend(items),
            Err(error) if error.invalidates_auth() => {
                return Err(graph_request_error(state, generation, error));
            }
            Err(error) => {
                log::warn!("event=graph_skip_device_scripts error=\"{error}\"");
            }
        }

        // Shell scripts (macOS)
        match fetch_paginated(
            &token.token,
            &format!(
                "{GRAPH_BETA_BASE}/deviceManagement/deviceShellScripts?$select=id,displayName"
            ),
            Some("#microsoft.graph.deviceShellScript"),
            "DeviceManagementScripts.Read.All",
        ) {
            Ok(items) => all.extend(items),
            Err(error) if error.invalidates_auth() => {
                return Err(graph_request_error(state, generation, error));
            }
            Err(error) => log::warn!("event=graph_skip_shell_scripts error=\"{error}\""),
        }

        let cache_map: HashMap<String, GraphAppInfo> =
            all.iter().map(|a| (a.id.clone(), a.clone())).collect();
        state.replace_apps(generation, cache_map);

        Ok(all)
    }

    /// Fetch all items from a paginated Graph API endpoint.
    /// `default_type` is used when the response items don't include `@odata.type`.
    fn fetch_paginated(
        token: &str,
        initial_url: &str,
        default_type: Option<&str>,
        required_scope: &str,
    ) -> Result<Vec<GraphAppInfo>, GraphClientError> {
        let transport = UreqGraphTransport {
            access_token: token,
            deadline: None,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let values = client.get_paginated::<serde_json::Value>(initial_url, required_scope)?;
        parse_graph_app_values(&values, default_type, required_scope)
    }

    // ── Internal helpers ────────────────────────────────────────────────────────

    fn fetch_apps_batch(
        token: &str,
        guids: &[String],
    ) -> Result<GraphResolutionResult, GraphClientError> {
        let requests: Vec<serde_json::Value> = guids
        .iter()
        .enumerate()
        .map(|(i, guid)| {
            serde_json::json!({
                "id": i.to_string(),
                "method": "GET",
                "url": format!("/deviceAppManagement/mobileApps/{guid}?$select=id,displayName,publisher")
            })
        })
        .collect();

        let batch_body = serde_json::json!({ "requests": requests });
        let body_bytes = serde_json::to_vec(&batch_body).map_err(|_| {
            GraphClientError::new(
                GraphClientErrorKind::InvalidResponse,
                "DeviceManagementApps.Read.All",
            )
        })?;
        let transport = UreqGraphTransport {
            access_token: token,
            deadline: None,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let outcomes = client.request_batch_json::<serde_json::Value>(GraphTransportRequest {
            method: GraphHttpMethod::Post,
            url: format!("{GRAPH_BETA_BASE}/$batch"),
            consistency_level: None,
            content_type: Some("application/json".to_string()),
            body: Some(body_bytes),
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        })?;

        let mut resolved = HashMap::new();
        let mut not_found = Vec::new();

        for (guid, outcome) in guids.iter().zip(outcomes) {
            match outcome {
                GraphBatchItem::Success(body) => {
                    let app = parse_graph_app_json(
                        &body,
                        None,
                        Some(guid),
                        "DeviceManagementApps.Read.All",
                    )?;
                    resolved.insert(app.id.clone(), app);
                }
                GraphBatchItem::NotFound => not_found.push(guid.clone()),
            }
        }

        Ok(GraphResolutionResult {
            resolved,
            not_found,
            errors: Vec::new(),
        })
    }

    fn fetch_single_app(token: &str, guid: &str) -> Result<Option<GraphAppInfo>, GraphClientError> {
        let url = format!(
        "{GRAPH_BETA_BASE}/deviceAppManagement/mobileApps/{guid}?$select=id,displayName,publisher"
    );
        let transport = UreqGraphTransport {
            access_token: token,
            deadline: None,
        };
        let cancellation = NoGraphCancellation;
        let client = GraphClient::new("graph.microsoft.com", &transport, &cancellation);
        let request = GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url,
            consistency_level: None,
            content_type: None,
            body: None,
            required_scope: "DeviceManagementApps.Read.All".to_string(),
        };

        match client.request_json::<serde_json::Value>(request) {
            Ok(body) => {
                parse_graph_app_json(&body, None, Some(guid), "DeviceManagementApps.Read.All")
                    .map(Some)
            }
            Err(error) if error.kind == GraphClientErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    mod permission_upgrade_tests {
        use std::cell::Cell;

        use super::super::models::GraphPermissionUpgradeOutcome;
        use super::super::{GraphAuthCapabilities, GRAPH_DELEGATED_SCOPES};
        use super::*;

        const ORIGINAL_TOKEN: &str = "original-memory-only-token";
        const CANDIDATE_TOKEN: &str = "candidate-memory-only-token";
        const NEWER_TOKEN: &str = "newer-memory-only-token";

        fn status(
            is_authenticated: bool,
            upn: Option<&str>,
            tenant: Option<&str>,
            granted_scopes: &[&str],
        ) -> GraphAuthStatus {
            GraphAuthStatus {
                is_authenticated,
                user_principal_name: upn.map(str::to_string),
                // Same-account fixtures share one authoritative `oid`; the
                // account-mismatch cases below diverge on the UPN secondary
                // signal instead.
                object_id: Some("00000000-0000-0000-0000-0000000000a1".to_string()),
                tenant_id: tenant.map(str::to_string),
                granted_scopes: granted_scopes
                    .iter()
                    .map(|scope| (*scope).to_string())
                    .collect(),
                missing_scopes: GRAPH_DELEGATED_SCOPES
                    .iter()
                    .filter(|required| {
                        !granted_scopes
                            .iter()
                            .any(|scope| scope.eq_ignore_ascii_case(required))
                    })
                    .map(|scope| (*scope).to_string())
                    .collect(),
                expires_at: Some(unix_now() + 3_600),
                capabilities: GraphAuthCapabilities::default(),
                error: None,
            }
        }

        fn token(value: &str, upn: &str, tenant: &str, granted_scopes: &[&str]) -> CachedToken {
            CachedToken {
                token: value.to_string(),
                status: status(true, Some(upn), Some(tenant), granted_scopes),
            }
        }

        fn seed_partial_state() -> GraphAuthState {
            let state = GraphAuthState::new();
            assert!(state.set_token_if_generation(
                0,
                token(
                    ORIGINAL_TOKEN,
                    "user@contoso.example",
                    "tenant-a",
                    &[GRAPH_DELEGATED_SCOPES[0]],
                ),
            ));
            state
        }

        fn stored_token_and_generation(state: &GraphAuthState) -> (String, u64) {
            let guard = state.inner.access_token.lock().unwrap();
            let cached = guard.value.as_ref().expect("cached token");
            (cached.token.clone(), guard.generation)
        }

        fn assert_rejected_candidate_retains_current(candidate: CachedToken) {
            let state = seed_partial_state();
            let before = stored_token_and_generation(&state);

            let result = request_missing_permissions_with(&state, || Ok(candidate))
                .expect("candidate rejection is a structured outcome");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Failed);
            assert!(result.message.is_some());
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
            assert!(!format!("{result:?}").contains(CANDIDATE_TOKEN));
        }

        fn assert_acquisition_failure_retains_current(
            failure: WamAcquisitionFailure,
            expected_outcome: GraphPermissionUpgradeOutcome,
            expects_message: bool,
        ) {
            let state = seed_partial_state();
            let before = stored_token_and_generation(&state);

            let result = request_missing_permissions_with(&state, || Err(failure))
                .expect("acquisition failure is a structured outcome");

            assert_eq!(result.outcome, expected_outcome);
            assert_eq!(result.message.is_some(), expects_message);
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
        }

        #[test]
        fn graph_permission_upgrade_disconnected_precondition_does_not_invoke_wam() {
            let state = GraphAuthState::new();
            let calls = Cell::new(0);

            let result = request_missing_permissions_with(&state, || {
                calls.set(calls.get() + 1);
                unreachable!("disconnected precondition must stop before WAM")
            });

            assert!(result.is_err());
            assert_eq!(calls.get(), 0);
        }

        #[test]
        fn graph_permission_upgrade_complete_precondition_does_not_invoke_wam() {
            let state = GraphAuthState::new();
            assert!(state.set_token_if_generation(
                0,
                token(
                    ORIGINAL_TOKEN,
                    "user@contoso.example",
                    "tenant-a",
                    &GRAPH_DELEGATED_SCOPES,
                ),
            ));
            let calls = Cell::new(0);

            let result = request_missing_permissions_with(&state, || {
                calls.set(calls.get() + 1);
                unreachable!("complete precondition must stop before WAM")
            });

            assert!(result.is_err());
            assert_eq!(calls.get(), 0);
        }

        #[test]
        fn graph_permission_upgrade_strict_superset_replaces_token_and_advances_once() {
            let state = seed_partial_state();
            let (_, before_generation) = stored_token_and_generation(&state);
            let before_dependent_advances = state
                .inner
                .dependent_generation_advances
                .load(std::sync::atomic::Ordering::Relaxed);
            let candidate = token(
                CANDIDATE_TOKEN,
                "user@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
            );
            let expected_status = candidate.status.clone();
            let calls = Cell::new(0);

            let result = request_missing_permissions_with(&state, || {
                calls.set(calls.get() + 1);
                Ok(candidate)
            })
            .expect("strict superset upgrade");

            assert_eq!(calls.get(), 1);
            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Upgraded);
            assert_eq!(result.status, expected_status);
            assert!(result.message.is_none());
            assert_eq!(
                stored_token_and_generation(&state),
                (CANDIDATE_TOKEN.to_string(), before_generation + 1)
            );
            assert_eq!(
                state
                    .inner
                    .dependent_generation_advances
                    .load(std::sync::atomic::Ordering::Relaxed),
                before_dependent_advances + 1
            );
        }

        #[test]
        fn graph_permission_upgrade_equal_scopes_retain_original_token_and_generation() {
            let state = seed_partial_state();
            let before = stored_token_and_generation(&state);
            let candidate = token(
                CANDIDATE_TOKEN,
                "USER@CONTOSO.EXAMPLE",
                "TENANT-A",
                &[GRAPH_DELEGATED_SCOPES[0]],
            );

            let result = request_missing_permissions_with(&state, || Ok(candidate))
                .expect("equal scopes are unchanged");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Unchanged);
            assert!(result.message.is_none());
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
        }

        #[test]
        fn graph_permission_upgrade_scope_subset_retains_original_token() {
            let state = seed_partial_state();
            assert!(state.set_token_if_generation(
                1,
                token(
                    ORIGINAL_TOKEN,
                    "user@contoso.example",
                    "tenant-a",
                    &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
                ),
            ));
            let before = stored_token_and_generation(&state);
            let candidate = token(
                CANDIDATE_TOKEN,
                "user@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0]],
            );

            let result = request_missing_permissions_with(&state, || Ok(candidate))
                .expect("scope regression is a structured failure");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Failed);
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
        }

        #[test]
        fn graph_permission_upgrade_account_mismatch_retains_original_token() {
            assert_rejected_candidate_retains_current(token(
                CANDIDATE_TOKEN,
                "other@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
            ));
        }

        #[test]
        fn graph_permission_upgrade_tenant_mismatch_retains_original_token() {
            assert_rejected_candidate_retains_current(token(
                CANDIDATE_TOKEN,
                "user@contoso.example",
                "tenant-b",
                &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
            ));
        }

        #[test]
        fn graph_permission_upgrade_invalid_candidate_retains_original_token() {
            assert_rejected_candidate_retains_current(CachedToken {
                token: CANDIDATE_TOKEN.to_string(),
                status: status(
                    false,
                    Some("user@contoso.example"),
                    Some("tenant-a"),
                    &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
                ),
            });
        }

        #[test]
        fn graph_permission_upgrade_cancellation_retains_original_token() {
            assert_acquisition_failure_retains_current(
                WamAcquisitionFailure::Cancelled,
                GraphPermissionUpgradeOutcome::Cancelled,
                false,
            );
        }

        #[test]
        fn graph_permission_upgrade_denial_retains_original_token_and_sanitizes_provider_text() {
            let raw_provider_text = "AADSTS65004: UserDeclinedConsent access_denied";
            let state = seed_partial_state();
            let before = stored_token_and_generation(&state);

            let result = request_missing_permissions_with(&state, || {
                Err(WamAcquisitionFailure::Denied(AppError::Internal(
                    raw_provider_text.to_string(),
                )))
            })
            .expect("provider denial is a structured outcome");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Denied);
            assert!(result.message.is_some());
            assert!(!format!("{result:?}").contains(raw_provider_text));
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
        }

        #[test]
        fn graph_permission_upgrade_provider_failure_retains_original_token_and_sanitizes_message()
        {
            let raw_provider_text = "raw-provider-sensitive-text";
            let state = seed_partial_state();
            let before = stored_token_and_generation(&state);

            let result = request_missing_permissions_with(&state, || {
                Err(WamAcquisitionFailure::Failed(AppError::Internal(
                    raw_provider_text.to_string(),
                )))
            })
            .expect("provider failure is a structured outcome");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Failed);
            assert!(result.message.is_some());
            assert!(!format!("{result:?}").contains(raw_provider_text));
            assert_eq!(result.status, current_auth_status(&state));
            assert_eq!(stored_token_and_generation(&state), before);
        }

        #[test]
        fn graph_permission_upgrade_provider_status_failure_preserves_legacy_initial_auth_detail() {
            let raw_provider_text = "provider-specific failure";
            let error = wam_provider_status_failure(None, Some(raw_provider_text.to_string()))
                .into_initial_auth_error();
            assert_eq!(
                error.to_string(),
                format!("WAM authentication failed: {raw_provider_text}")
            );

            let fallback = wam_provider_status_failure(None, None).into_initial_auth_error();
            assert_eq!(
                fallback.to_string(),
                "WAM authentication failed: Unknown WAM error"
            );
        }

        #[test]
        fn graph_permission_upgrade_provider_denial_is_reachable_and_preserves_legacy_detail() {
            let raw_provider_text = "AADSTS65004: UserDeclinedConsent; OAuth error=access_denied";
            let failure =
                wam_provider_status_failure(Some(65_004), Some(raw_provider_text.to_string()));
            assert!(matches!(&failure, WamAcquisitionFailure::Denied(_)));

            let error = failure.into_initial_auth_error();
            assert_eq!(
                error.to_string(),
                format!("WAM authentication failed: {raw_provider_text}")
            );
        }

        #[test]
        fn graph_permission_upgrade_user_interaction_required_preserves_legacy_guidance() {
            let failure = WamAcquisitionFailure::Denied(AppError::Internal(
                WAM_USER_INTERACTION_REQUIRED_MESSAGE.into(),
            ));

            assert_eq!(
                failure.into_initial_auth_error().to_string(),
                "Interactive authentication required. Please sign in to Windows with your Entra ID account first."
            );
        }

        #[test]
        fn graph_permission_upgrade_unrelated_provider_failure_stays_failed() {
            let failure = wam_provider_status_failure(
                Some(65_005),
                Some("AADSTS65005: MisconfiguredApplication".to_string()),
            );
            assert!(matches!(failure, WamAcquisitionFailure::Failed(_)));
        }

        #[test]
        fn graph_permission_upgrade_newer_sign_out_prevents_stale_candidate_replacement() {
            let state = seed_partial_state();
            let candidate = token(
                CANDIDATE_TOKEN,
                "user@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
            );

            let result = request_missing_permissions_with(&state, || {
                state.clear_token();
                Ok(candidate)
            })
            .expect("stale candidate is a structured outcome");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Stale);
            assert!(!result.status.is_authenticated);
            assert!(result.message.is_some());
            let guard = state.inner.access_token.lock().unwrap();
            assert!(guard.value.is_none());
            assert_eq!(guard.generation, 2);
        }

        #[test]
        fn graph_permission_upgrade_newer_auth_prevents_stale_candidate_replacement() {
            let state = seed_partial_state();
            let candidate = token(
                CANDIDATE_TOKEN,
                "user@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
            );
            let newer = token(
                NEWER_TOKEN,
                "newer@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0]],
            );
            let newer_status = newer.status.clone();

            let result = request_missing_permissions_with(&state, || {
                assert!(state.set_token_if_generation(1, newer));
                Ok(candidate)
            })
            .expect("newer authentication wins");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Stale);
            assert_eq!(result.status, newer_status);
            assert_eq!(
                stored_token_and_generation(&state),
                (NEWER_TOKEN.to_string(), 2)
            );
        }

        #[test]
        fn graph_permission_upgrade_stale_failure_returns_current_authoritative_status() {
            let state = seed_partial_state();
            let newer = token(
                NEWER_TOKEN,
                "newer@contoso.example",
                "tenant-a",
                &[GRAPH_DELEGATED_SCOPES[0]],
            );
            let newer_status = newer.status.clone();

            let result = request_missing_permissions_with(&state, || {
                assert!(state.set_token_if_generation(1, newer));
                Err(WamAcquisitionFailure::Failed(AppError::Internal(
                    "raw-provider-sensitive-text".to_string(),
                )))
            })
            .expect("stale failure is a structured outcome");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Stale);
            assert_eq!(result.status, newer_status);
            assert!(!format!("{result:?}").contains("raw-provider-sensitive-text"));
        }

        #[cfg(feature = "esp-diagnostics")]
        #[test]
        fn graph_permission_upgrade_success_clears_guid_cache_and_cancels_older_esp_work() {
            let state = seed_partial_state();
            let (_, generation) = stored_token_and_generation(&state);
            state.cache_apps(
                generation,
                &HashMap::from([(
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
                    GraphAppInfo {
                        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
                        display_name: "Cached app".to_string(),
                        publisher: None,
                        odata_type: None,
                    },
                )]),
            );
            let operation = state
                .inner
                .esp_operations
                .begin("30000000-0000-4000-8000-000000000010", generation)
                .expect("ESP operation");
            assert!(!operation.is_cancelled());

            let result = request_missing_permissions_with(&state, || {
                Ok(token(
                    CANDIDATE_TOKEN,
                    "user@contoso.example",
                    "tenant-a",
                    &[GRAPH_DELEGATED_SCOPES[0], GRAPH_DELEGATED_SCOPES[1]],
                ))
            })
            .expect("strict superset upgrade");

            assert_eq!(result.outcome, GraphPermissionUpgradeOutcome::Upgraded);
            assert!(operation.is_cancelled());
            let cache = state.inner.guid_cache.lock().unwrap();
            assert_eq!(cache.generation, generation + 1);
            assert!(cache.apps.is_empty());
        }
    }

    #[cfg(all(test, feature = "esp-diagnostics"))]
    mod esp_tests {
        use super::*;
        use cmtraceopen_parser::esp::EspIdentityEvidence;

        fn request(request_id: &str) -> EspGraphRequest {
            EspGraphRequest {
                request_id: request_id.to_string(),
                identity: EspIdentityEvidence {
                    device_name: Some("DEVICE-01".to_string()),
                    managed_device_id: None,
                    entra_device_id: None,
                    entdm_id: None,
                    tenant_id: None,
                    tenant_domain: None,
                    user_principal_name: None,
                    serial_number: None,
                    evidence: Vec::new(),
                },
                workload_ids: Vec::new(),
                selected_managed_device_id: None,
                evidence_window_start_utc: None,
                evidence_window_end_utc: None,
                enrollment_configuration_ids: Vec::new(),
                app_ids: Vec::new(),
                policy_references: Vec::new(),
                script_references: Vec::new(),
            }
        }

        fn valid_token() -> CachedToken {
            CachedToken {
                token: "memory-only-test-token".to_string(),
                status: GraphAuthStatus {
                    is_authenticated: true,
                    user_principal_name: Some("user@contoso.example".to_string()),
                    object_id: Some("00000000-0000-0000-0000-0000000000a1".to_string()),
                    tenant_id: Some("tenant-a".to_string()),
                    granted_scopes: Vec::new(),
                    missing_scopes: Vec::new(),
                    expires_at: Some(unix_now() + 3_600),
                    capabilities: super::super::GraphAuthCapabilities::all(),
                    error: None,
                },
            }
        }

        #[test]
        fn disconnected_prepare_releases_request_id_ownership() {
            let state = GraphAuthState::new();

            for _ in 0..2 {
                let result = prepare_esp_diagnostics(
                    &state,
                    request("30000000-0000-4000-8000-000000000002"),
                );
                let error = match result {
                    Ok(_) => panic!("disconnected Graph state must not prepare a request"),
                    Err(error) => error,
                };
                assert_eq!(error.to_string(), "GraphNotConnected");
            }
        }

        #[test]
        fn matching_generation_invalidation_cancels_owned_operation_once() {
            let state = GraphAuthState::new();
            assert!(state.set_token_if_generation(0, valid_token()));
            let prepared =
                prepare_esp_diagnostics(&state, request("30000000-0000-4000-8000-000000000003"))
                    .expect("request ownership");
            assert!(!prepared.operation.is_cancelled());

            assert!(state.clear_token_if_generation(1));
            assert!(prepared.operation.is_cancelled());
            assert!(!state.clear_token_if_generation(1));
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::client::GraphClientErrorKind;
    use super::{
        parse_graph_app_json, parse_graph_app_values, GraphAppInfo, VersionedAuthSlot,
        VersionedGuidCache,
    };

    const APP_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const APP_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const APP_SCOPE: &str = "DeviceManagementApps.Read.All";

    #[test]
    fn graph_permission_upgrade_recognizes_documented_consent_denial_markers() {
        for (error_code, message) in [
            (Some(65_004), None),
            (None, Some("AADSTS65004: user declined consent")),
            (None, Some("provider=UserDeclinedConsent")),
            (None, Some("error=access_denied&error_subcode=cancel")),
            (None, Some("aadsts65004: USERDECLINEDCONSENT")),
            (None, Some("ERROR=ACCESS_DENIED")),
        ] {
            assert!(
                super::is_wam_consent_denial(error_code, message),
                "documented denial was not recognized: {error_code:?} {message:?}"
            );
        }
    }

    #[test]
    fn graph_permission_upgrade_rejects_denial_near_misses_and_unrelated_failures() {
        for (error_code, message) in [
            (None, None),
            (Some(65_005), Some("AADSTS65005: MisconfiguredApplication")),
            (None, Some("AADSTS650040")),
            (None, Some("NotUserDeclinedConsent")),
            (None, Some("access_denied_suffix")),
            (None, Some("prefixaccess_denied")),
        ] {
            assert!(
                !super::is_wam_consent_denial(error_code, message),
                "near miss was classified as a denial: {error_code:?} {message:?}"
            );
        }
    }

    #[test]
    fn deadline_receiver_distinguishes_ready_timeout_and_disconnect() {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        ready_sender.send(7_u8).expect("ready value");
        assert_eq!(
            super::receive_before_deadline(
                &ready_receiver,
                Instant::now() + Duration::from_secs(1)
            ),
            Ok(7)
        );

        let (_pending_sender, pending_receiver) = mpsc::sync_channel::<u8>(1);
        assert_eq!(
            super::receive_before_deadline(&pending_receiver, Instant::now()),
            Err(super::DeadlineReceiveError::Timeout)
        );

        let (disconnected_sender, disconnected_receiver) = mpsc::sync_channel::<u8>(1);
        drop(disconnected_sender);
        assert_eq!(
            super::receive_before_deadline(
                &disconnected_receiver,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(super::DeadlineReceiveError::Disconnected)
        );
    }

    fn app(id: &str, name: &str) -> GraphAppInfo {
        GraphAppInfo {
            id: id.to_string(),
            display_name: name.to_string(),
            publisher: None,
            odata_type: None,
        }
    }

    #[test]
    fn graph_guid_cache_rejects_stale_results_across_auth_generations() {
        let mut cache = VersionedGuidCache::default();
        cache.reset_to(7);
        cache.insert_all(
            7,
            &HashMap::from([("app-a".to_string(), app("app-a", "Tenant A"))]),
        );
        assert_eq!(
            cache.get(7, "app-a").map(|app| app.display_name),
            Some("Tenant A".to_string())
        );

        cache.reset_to(8);
        assert!(cache.get(8, "app-a").is_none());

        cache.insert_all(
            7,
            &HashMap::from([("app-stale".to_string(), app("app-stale", "Stale tenant"))]),
        );
        assert!(cache.get(8, "app-stale").is_none());

        cache.insert_all(
            8,
            &HashMap::from([("app-b".to_string(), app("app-b", "Tenant B"))]),
        );
        cache.reset_to(7);
        assert_eq!(
            cache.get(8, "app-b").map(|app| app.display_name),
            Some("Tenant B".to_string())
        );
    }

    #[test]
    fn graph_guid_cache_full_snapshot_replaces_same_generation_entries() {
        let mut cache = VersionedGuidCache::default();
        cache.reset_to(7);
        cache.insert_all(
            7,
            &HashMap::from([("app-stale".to_string(), app("app-stale", "Old name"))]),
        );

        cache.replace_all(
            7,
            HashMap::from([("app-current".to_string(), app("app-current", "Current"))]),
        );

        assert!(cache.get(7, "app-stale").is_none());
        assert_eq!(
            cache.get(7, "app-current").map(|app| app.display_name),
            Some("Current".to_string())
        );

        cache.replace_all(
            6,
            HashMap::from([("app-wrong".to_string(), app("app-wrong", "Wrong tenant"))]),
        );
        assert!(cache.get(7, "app-wrong").is_none());
        assert!(cache.get(7, "app-current").is_some());
    }

    #[test]
    fn graph_auth_slot_rejects_stale_token_set_and_clear_mutations() {
        let mut slot = VersionedAuthSlot::default();
        let first_attempt = slot.replace(None);
        let newer_attempt = slot.replace(None);
        assert_eq!(
            slot.replace_if_generation(first_attempt, Some("token-stale")),
            None
        );
        assert_eq!(
            slot.replace_if_generation(newer_attempt, Some("token-a")),
            Some(3)
        );

        let stale_request = newer_attempt;
        let newer_generation = slot.replace(Some("token-b"));
        assert_eq!(newer_generation, 4);
        assert_eq!(slot.replace_if_generation(stale_request, None), None);
        assert_eq!(slot.value, Some("token-b"));

        assert_eq!(slot.replace_if_generation(newer_generation, None), Some(5));
        assert_eq!(slot.value, None);
    }

    #[test]
    fn successful_graph_app_payloads_require_canonical_matching_guids() {
        let canonical = parse_graph_app_json(
            &serde_json::json!({
                "id": "{AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA}",
                "displayName": "App A",
                "publisher": "Contoso"
            }),
            Some("#microsoft.graph.win32LobApp"),
            Some(APP_A),
            APP_SCOPE,
        )
        .expect("canonical response");
        assert_eq!(canonical.id, APP_A);
        assert_eq!(
            canonical.odata_type.as_deref(),
            Some("#microsoft.graph.win32LobApp")
        );

        for payload in [
            serde_json::json!({"id": "not-a-guid", "displayName": "Bad"}),
            serde_json::json!({"id": APP_A}),
            serde_json::json!({"id": APP_A, "displayName": 42}),
            serde_json::json!({"id": APP_A, "displayName": "Bad", "publisher": 42}),
            serde_json::json!({"id": APP_B, "displayName": "Wrong app"}),
        ] {
            let error = parse_graph_app_json(&payload, None, Some(APP_A), APP_SCOPE)
                .expect_err("malformed or mismatched 2xx payload must fail");
            assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
        }
    }

    #[test]
    fn paginated_graph_app_payloads_fail_instead_of_dropping_malformed_items() {
        let values = vec![
            serde_json::json!({"id": APP_A, "displayName": "App A"}),
            serde_json::json!({"id": "bad", "displayName": "Discarded before fix"}),
        ];

        let error = parse_graph_app_values(&values, None, APP_SCOPE)
            .expect_err("one malformed successful item invalidates the page");
        assert_eq!(error.kind, GraphClientErrorKind::InvalidResponse);
    }
}
