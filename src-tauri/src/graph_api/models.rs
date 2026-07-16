//! Platform-neutral Microsoft Graph request and response contracts.
//!
//! These types intentionally contain no WAM, HWND, Tauri, `ureq`, or Windows
//! symbols so fake transports and orchestration can compile on every platform.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Status of the Graph API connection, returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphAuthStatus {
    pub is_authenticated: bool,
    pub user_principal_name: Option<String>,
    pub tenant_id: Option<String>,
    pub error: Option<String>,
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
