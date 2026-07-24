//! Platform-neutral Microsoft Graph request and response contracts.
//!
//! These types intentionally contain no WAM, HWND, Tauri, `ureq`, or Windows
//! symbols so fake transports and orchestration can compile on every platform.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};

pub const GRAPH_DELEGATED_SCOPES: [&str; 5] = [
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementScripts.Read.All",
];

pub const GRAPH_SCOPE_REQUEST: &str = concat!(
    "DeviceManagementManagedDevices.Read.All ",
    "DeviceManagementServiceConfig.Read.All ",
    "DeviceManagementApps.Read.All ",
    "DeviceManagementConfiguration.Read.All ",
    "DeviceManagementScripts.Read.All"
);

/// Interactive Entra WAM v2 scope string. The five declared Intune data
/// permissions remain fixed; these three standard OpenID Connect scopes are
/// the identity/session scopes MSAL adds to interactive public-client calls.
pub const GRAPH_WAM_PERMISSION_SCOPE_REQUEST: &str = concat!(
    "DeviceManagementManagedDevices.Read.All ",
    "DeviceManagementServiceConfig.Read.All ",
    "DeviceManagementApps.Read.All ",
    "DeviceManagementConfiguration.Read.All ",
    "DeviceManagementScripts.Read.All ",
    "openid profile offline_access"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphWamRequestContract {
    pub scope: &'static str,
    pub resource_property: &'static str,
    pub resource: &'static str,
}

pub const GRAPH_WAM_REQUEST: GraphWamRequestContract = GraphWamRequestContract {
    scope: GRAPH_SCOPE_REQUEST,
    resource_property: "resource",
    resource: "https://graph.microsoft.com",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphWamPermissionRequestContract {
    pub scope: &'static str,
    pub force_authentication: bool,
    pub properties: &'static [(&'static str, &'static str)],
}

/// Provider contract for the explicit permission-upgrade action.
///
/// The Entra WAM provider's v2 compatibility mode interprets `scope` as a
/// dynamic delegated-permission request. `prompt=consent` requests an explicit
/// approval/denial surface instead of allowing the button to reuse the
/// established default/resource request that returned a cached partial token.
pub const GRAPH_WAM_PERMISSION_REQUEST: GraphWamPermissionRequestContract =
    GraphWamPermissionRequestContract {
        scope: GRAPH_WAM_PERMISSION_SCOPE_REQUEST,
        force_authentication: true,
        properties: &[
            ("wam_compat", "2.0"),
            ("prompt", "consent"),
            ("authority", "https://login.microsoftonline.com/common/"),
            ("validateAuthority", "yes"),
        ],
    };

const GRAPH_URL_AUDIENCE: &str = GRAPH_WAM_REQUEST.resource;
const GRAPH_APP_ID_AUDIENCE: &str = "00000003-0000-0000-c000-000000000000";
const MAX_ACCESS_TOKEN_BYTES: usize = 64 * 1024;

/// Normalize an Intune object identifier before it is interpolated into a
/// Microsoft Graph path. Rejecting every non-UUID form keeps log-derived or
/// IPC-supplied values from changing the endpoint path or query.
pub fn normalize_graph_guid(value: &str) -> Option<String> {
    uuid::Uuid::parse_str(value.trim())
        .ok()
        .map(|guid| guid.hyphenated().to_string().to_ascii_lowercase())
}

/// Delegated Intune read capabilities projected from the access token's
/// short-name `scp` claim. These flags are UX/cache hints; Graph 401/403
/// responses remain the authorization truth.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphAuthCapabilities {
    pub managed_devices: bool,
    pub service_config: bool,
    pub apps: bool,
    pub configuration: bool,
    pub scripts: bool,
}

impl GraphAuthCapabilities {
    pub const fn all() -> Self {
        Self {
            managed_devices: true,
            service_config: true,
            apps: true,
            configuration: true,
            scripts: true,
        }
    }

    fn from_granted_scopes(scopes: &[String]) -> Self {
        let has_scope = |required: &str| {
            scopes
                .iter()
                .any(|scope| scope.eq_ignore_ascii_case(required))
        };

        Self {
            managed_devices: has_scope(GRAPH_DELEGATED_SCOPES[0]),
            service_config: has_scope(GRAPH_DELEGATED_SCOPES[1]),
            apps: has_scope(GRAPH_DELEGATED_SCOPES[2]),
            configuration: has_scope(GRAPH_DELEGATED_SCOPES[3]),
            scripts: has_scope(GRAPH_DELEGATED_SCOPES[4]),
        }
    }
}

/// Status of the Graph API connection, returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphAuthStatus {
    pub is_authenticated: bool,
    pub user_principal_name: Option<String>,
    /// Authoritative account identity from the token's `oid` (object id) claim.
    /// Unlike the optional WAM `UserName`, this is always present in an
    /// authenticated Entra token and is the trusted key for same-account checks
    /// during a consent upgrade.
    pub object_id: Option<String>,
    pub tenant_id: Option<String>,
    pub granted_scopes: Vec<String>,
    pub missing_scopes: Vec<String>,
    pub expires_at: Option<u64>,
    pub capabilities: GraphAuthCapabilities,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphPermissionUpgradeOutcome {
    Upgraded,
    Unchanged,
    Cancelled,
    Denied,
    Failed,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphPermissionUpgradeResult {
    pub outcome: GraphPermissionUpgradeOutcome,
    pub status: GraphAuthStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphPermissionCandidateDecision {
    Upgrade,
    Unchanged,
    InvalidCandidate,
    AccountMismatch,
    TenantMismatch,
    ScopeRegression,
}

pub fn classify_graph_permission_candidate(
    current: &GraphAuthStatus,
    candidate: &GraphAuthStatus,
) -> GraphPermissionCandidateDecision {
    if !candidate.is_authenticated {
        return GraphPermissionCandidateDecision::InvalidCandidate;
    }

    let tenant_matches = match (current.tenant_id.as_deref(), candidate.tenant_id.as_deref()) {
        (Some(current), Some(candidate)) => current.eq_ignore_ascii_case(candidate),
        (None, None) => true,
        _ => false,
    };
    if !tenant_matches {
        return GraphPermissionCandidateDecision::TenantMismatch;
    }

    // Authoritative account check: bind identity to the token's `oid` claim,
    // which is always present in an authenticated token. Fail closed when the
    // object id is absent or unverifiable on either side so a same-tenant,
    // different-account token can never replace the connected token — even when
    // the optional WAM `UserName` (UPN) is missing for federated/guest accounts.
    let account_matches = match (
        current.object_id.as_deref(),
        candidate.object_id.as_deref(),
    ) {
        (Some(current_oid), Some(candidate_oid)) => current_oid.eq_ignore_ascii_case(candidate_oid),
        _ => false,
    };
    if !account_matches {
        return GraphPermissionCandidateDecision::AccountMismatch;
    }

    // Secondary signal: when both UPNs are known they must also agree.
    if let (Some(current), Some(candidate)) = (
        current.user_principal_name.as_deref(),
        candidate.user_principal_name.as_deref(),
    ) {
        if !current.eq_ignore_ascii_case(candidate) {
            return GraphPermissionCandidateDecision::AccountMismatch;
        }
    }

    let declared_scopes = |status: &GraphAuthStatus| {
        GRAPH_DELEGATED_SCOPES
            .iter()
            .copied()
            .filter(|required| {
                status
                    .granted_scopes
                    .iter()
                    .any(|scope| scope.eq_ignore_ascii_case(required))
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    let current_scopes = declared_scopes(current);
    let candidate_scopes = declared_scopes(candidate);

    if !candidate_scopes.is_superset(&current_scopes) {
        GraphPermissionCandidateDecision::ScopeRegression
    } else if candidate_scopes.len() > current_scopes.len() {
        GraphPermissionCandidateDecision::Upgrade
    } else {
        GraphPermissionCandidateDecision::Unchanged
    }
}

impl GraphAuthStatus {
    pub fn disconnected(error: Option<String>) -> Self {
        Self {
            is_authenticated: false,
            user_principal_name: None,
            object_id: None,
            tenant_id: None,
            granted_scopes: Vec::new(),
            missing_scopes: GRAPH_DELEGATED_SCOPES
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
            expires_at: None,
            capabilities: GraphAuthCapabilities::default(),
            error,
        }
    }
}

/// Decode the unsigned JWT claim payload for expiry/cache/capability UX.
///
/// This deliberately does not validate the signature or treat claims as an
/// authorization decision. The token comes directly from WAM, remains
/// memory-only, and Microsoft Graph 401/403 responses are authoritative.
pub fn project_graph_auth_status(
    access_token: &str,
    user_principal_name: Option<&str>,
    wam_tenant_id: Option<&str>,
    now_unix: u64,
) -> GraphAuthStatus {
    let reject = |code: &str| GraphAuthStatus::disconnected(Some(code.to_string()));

    if access_token.is_empty() || access_token.len() > MAX_ACCESS_TOKEN_BYTES {
        return reject("MalformedToken");
    }

    let mut segments = access_token.split('.');
    let Some(header) = segments.next() else {
        return reject("MalformedToken");
    };
    let Some(payload) = segments.next() else {
        return reject("MalformedToken");
    };
    let Some(signature) = segments.next() else {
        return reject("MalformedToken");
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() || segments.next().is_some()
    {
        return reject("MalformedToken");
    }

    let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return reject("MalformedToken");
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return reject("MalformedToken");
    };

    let Some(audience) = claims.get("aud").and_then(serde_json::Value::as_str) else {
        return reject("MissingAudience");
    };
    if audience.trim_end_matches('/') != GRAPH_URL_AUDIENCE
        && !audience.eq_ignore_ascii_case(GRAPH_APP_ID_AUDIENCE)
    {
        return reject("InvalidAudience");
    }

    let Some(expires_at) = claims.get("exp").and_then(serde_json::Value::as_u64) else {
        return reject("MissingExpiry");
    };
    if expires_at <= now_unix {
        return reject("ExpiredToken");
    }

    let Some(token_tenant_id) = claims
        .get("tid")
        .and_then(serde_json::Value::as_str)
        .filter(|tenant| !tenant.is_empty())
    else {
        return reject("MissingTenant");
    };
    if wam_tenant_id
        .filter(|tenant| !tenant.is_empty())
        .is_some_and(|tenant| !tenant.eq_ignore_ascii_case(token_tenant_id))
    {
        return reject("TenantMismatch");
    }

    // Authoritative account identity. Present in every authenticated Entra
    // token; parsed alongside `tid` and used to gate same-account consent
    // upgrades. Absence does not reject the token here (Graph 401/403 remain
    // authoritative) but does fail the upgrade check closed.
    let object_id = claims
        .get("oid")
        .and_then(serde_json::Value::as_str)
        .filter(|oid| !oid.is_empty())
        .map(str::to_string);

    let Some(scope_claim) = claims.get("scp").and_then(serde_json::Value::as_str) else {
        return reject("MissingScopeClaim");
    };
    let token_scopes: Vec<&str> = scope_claim.split_whitespace().collect();
    let granted_scopes: Vec<String> = GRAPH_DELEGATED_SCOPES
        .iter()
        .filter(|required| {
            token_scopes
                .iter()
                .any(|scope| scope.eq_ignore_ascii_case(required))
        })
        .map(|scope| (*scope).to_string())
        .collect();
    let missing_scopes: Vec<String> = GRAPH_DELEGATED_SCOPES
        .iter()
        .filter(|required| {
            !granted_scopes
                .iter()
                .any(|scope| scope.eq_ignore_ascii_case(required))
        })
        .map(|scope| (*scope).to_string())
        .collect();
    let capabilities = GraphAuthCapabilities::from_granted_scopes(&granted_scopes);

    GraphAuthStatus {
        is_authenticated: true,
        user_principal_name: user_principal_name.map(str::to_string),
        object_id,
        tenant_id: Some(token_tenant_id.to_string()),
        granted_scopes,
        missing_scopes,
        expires_at: Some(expires_at),
        capabilities,
        error: None,
    }
}

/// A resolved app from Graph API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphAppInfo {
    pub id: String,
    pub display_name: String,
    pub publisher: Option<String>,
    pub odata_type: Option<String>,
}

/// Batch resolution result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphResolutionResult {
    pub resolved: HashMap<String, GraphAppInfo>,
    pub not_found: Vec<String>,
    pub errors: Vec<String>,
}

/// Methods used by the bounded Graph client.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum GraphHttpMethod {
    Get,
    Post,
}

/// Token-free request passed from portable client logic to a concrete transport.
///
/// The Windows adapter attaches the in-memory bearer token separately. Keeping
/// authorization outside this serializable DTO prevents token-bearing fixtures,
/// debug output, or IPC payloads.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphTransportRequest {
    pub method: GraphHttpMethod,
    pub url: String,
    pub consistency_level: Option<String>,
    pub content_type: Option<String>,
    pub body: Option<Vec<u8>>,
    pub required_scope: String,
}

impl fmt::Debug for GraphTransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphTransportRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("consistency_level", &self.consistency_level)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .field("required_scope", &self.required_scope)
            .finish()
    }
}

/// Raw response returned by a concrete transport to the portable client.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphTransportResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for GraphTransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(String::as_str).collect();
        formatter
            .debug_struct("GraphTransportResponse")
            .field("status", &self.status)
            .field("header_names", &header_names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
