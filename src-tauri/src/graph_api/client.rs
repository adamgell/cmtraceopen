//! Portable, bounded Microsoft Graph page client.
//!
//! The client owns request, retry, pagination, cancellation, and error-safety
//! policy. Concrete bearer-token attachment and HTTP I/O stay behind a
//! platform adapter implementing [`GraphTransport`].

use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::models::{GraphHttpMethod, GraphTransportRequest, GraphTransportResponse};

pub const MAX_GRAPH_ATTEMPTS: usize = 4;
pub const MAX_GRAPH_RETRY_DELAY: Duration = Duration::from_secs(30);
pub const MAX_GRAPH_PAGES: usize = 25;
pub const MAX_GRAPH_ITEMS: usize = 5_000;
pub const MAX_GRAPH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const GRAPH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphTransportFailure {
    Timeout,
    Network,
    Cancelled,
}

pub trait GraphTransport: Send + Sync {
    fn execute(
        &self,
        request: &GraphTransportRequest,
        timeout: Duration,
    ) -> Result<GraphTransportResponse, GraphTransportFailure>;
}

pub trait GraphCancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;

    /// Wait for a retry delay. Returns `false` when cancellation interrupted
    /// the wait and the request must stop.
    fn wait_for_retry(&self, duration: Duration) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphClientErrorKind {
    Cancelled,
    InvalidUrl,
    Unauthorized,
    PermissionDenied,
    NotFound,
    RetryExhausted,
    HttpStatus,
    ResponseTooLarge,
    PageLimitExceeded,
    ItemLimitExceeded,
    Timeout,
    Transport,
    InvalidResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphClientError {
    pub kind: GraphClientErrorKind,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    pub required_scope: String,
}

impl GraphClientError {
    fn new(kind: GraphClientErrorKind, required_scope: &str) -> Self {
        Self {
            kind,
            status: None,
            request_id: None,
            required_scope: sanitize_scope(required_scope),
        }
    }

    fn for_response(
        kind: GraphClientErrorKind,
        response: &GraphTransportResponse,
        required_scope: &str,
    ) -> Self {
        Self {
            kind,
            status: Some(response.status),
            request_id: graph_request_id(&response.headers),
            required_scope: sanitize_scope(required_scope),
        }
    }

    pub fn invalidates_auth(&self) -> bool {
        self.kind == GraphClientErrorKind::Unauthorized
    }
}

impl fmt::Display for GraphClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Graph request failed: {:?}", self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, " (HTTP {status})")?;
        }
        if let Some(request_id) = &self.request_id {
            write!(formatter, " request-id={request_id}")?;
        }
        write!(formatter, " required-scope={}", self.required_scope)
    }
}

impl std::error::Error for GraphClientError {}

#[derive(Debug, Deserialize)]
pub struct GraphPage<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

pub struct GraphClient<'a, T: GraphTransport, C: GraphCancellation> {
    graph_host: String,
    transport: &'a T,
    cancellation: &'a C,
}

impl<'a, T: GraphTransport, C: GraphCancellation> GraphClient<'a, T, C> {
    pub fn new(graph_host: &str, transport: &'a T, cancellation: &'a C) -> Self {
        Self {
            graph_host: graph_host.trim().trim_end_matches('.').to_ascii_lowercase(),
            transport,
            cancellation,
        }
    }

    pub fn get_paginated<Item: DeserializeOwned>(
        &self,
        initial_url: &str,
        required_scope: &str,
    ) -> Result<Vec<Item>, GraphClientError> {
        let mut url = initial_url.to_string();
        let mut items = Vec::new();

        for page_index in 0..MAX_GRAPH_PAGES {
            self.ensure_not_cancelled(required_scope)?;
            self.ensure_allowed_url(&url, required_scope)?;

            let response = self.execute_with_retry(&url, required_scope)?;
            let request_id = graph_request_id(&response.headers);
            let page: GraphPage<Item> = serde_json::from_slice(&response.body).map_err(|_| {
                let mut error =
                    GraphClientError::new(GraphClientErrorKind::InvalidResponse, required_scope);
                error.status = Some(response.status);
                error.request_id = request_id;
                error
            })?;

            if page.value.len() > MAX_GRAPH_ITEMS.saturating_sub(items.len()) {
                return Err(GraphClientError::for_response(
                    GraphClientErrorKind::ItemLimitExceeded,
                    &response,
                    required_scope,
                ));
            }
            items.extend(page.value);

            let Some(next_link) = page.next_link else {
                return Ok(items);
            };
            if page_index + 1 >= MAX_GRAPH_PAGES {
                return Err(GraphClientError::for_response(
                    GraphClientErrorKind::PageLimitExceeded,
                    &response,
                    required_scope,
                ));
            }

            self.ensure_not_cancelled(required_scope)?;
            self.ensure_allowed_url(&next_link, required_scope)?;
            url = next_link;
        }

        Err(GraphClientError::new(
            GraphClientErrorKind::PageLimitExceeded,
            required_scope,
        ))
    }

    fn execute_with_retry(
        &self,
        url: &str,
        required_scope: &str,
    ) -> Result<GraphTransportResponse, GraphClientError> {
        let request = GraphTransportRequest {
            method: GraphHttpMethod::Get,
            url: url.to_string(),
            consistency_level: Some("eventual".to_string()),
            content_type: None,
            body: None,
            required_scope: sanitize_scope(required_scope),
        };

        for attempt in 0..MAX_GRAPH_ATTEMPTS {
            self.ensure_not_cancelled(required_scope)?;
            let response = self
                .transport
                .execute(&request, GRAPH_REQUEST_TIMEOUT)
                .map_err(|failure| match failure {
                    GraphTransportFailure::Timeout => {
                        GraphClientError::new(GraphClientErrorKind::Timeout, required_scope)
                    }
                    GraphTransportFailure::Cancelled => {
                        GraphClientError::new(GraphClientErrorKind::Cancelled, required_scope)
                    }
                    GraphTransportFailure::Network => {
                        GraphClientError::new(GraphClientErrorKind::Transport, required_scope)
                    }
                })?;

            if response.body.len() > MAX_GRAPH_RESPONSE_BYTES {
                return Err(GraphClientError::for_response(
                    GraphClientErrorKind::ResponseTooLarge,
                    &response,
                    required_scope,
                ));
            }

            match response.status {
                200..=299 => return Ok(response),
                401 => {
                    return Err(GraphClientError::for_response(
                        GraphClientErrorKind::Unauthorized,
                        &response,
                        required_scope,
                    ));
                }
                403 => {
                    return Err(GraphClientError::for_response(
                        GraphClientErrorKind::PermissionDenied,
                        &response,
                        required_scope,
                    ));
                }
                404 => {
                    return Err(GraphClientError::for_response(
                        GraphClientErrorKind::NotFound,
                        &response,
                        required_scope,
                    ));
                }
                429 | 503 | 504 if attempt + 1 < MAX_GRAPH_ATTEMPTS => {
                    let delay = retry_delay(&response, attempt);
                    if !self.cancellation.wait_for_retry(delay) {
                        return Err(GraphClientError::new(
                            GraphClientErrorKind::Cancelled,
                            required_scope,
                        ));
                    }
                }
                429 | 503 | 504 => {
                    return Err(GraphClientError::for_response(
                        GraphClientErrorKind::RetryExhausted,
                        &response,
                        required_scope,
                    ));
                }
                _ => {
                    return Err(GraphClientError::for_response(
                        GraphClientErrorKind::HttpStatus,
                        &response,
                        required_scope,
                    ));
                }
            }
        }

        Err(GraphClientError::new(
            GraphClientErrorKind::RetryExhausted,
            required_scope,
        ))
    }

    fn ensure_not_cancelled(&self, required_scope: &str) -> Result<(), GraphClientError> {
        if self.cancellation.is_cancelled() {
            Err(GraphClientError::new(
                GraphClientErrorKind::Cancelled,
                required_scope,
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_allowed_url(&self, url: &str, required_scope: &str) -> Result<(), GraphClientError> {
        if is_allowed_graph_url(url, &self.graph_host) {
            Ok(())
        } else {
            Err(GraphClientError::new(
                GraphClientErrorKind::InvalidUrl,
                required_scope,
            ))
        }
    }
}

fn retry_delay(response: &GraphTransportResponse, attempt: usize) -> Duration {
    let retry_after = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    retry_after
        .unwrap_or_else(|| Duration::from_secs(1_u64 << attempt.min(5)))
        .min(MAX_GRAPH_RETRY_DELAY)
}

fn graph_request_id(headers: &std::collections::BTreeMap<String, String>) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("request-id"))
        .and_then(|(_, value)| sanitize_request_id(value))
}

fn sanitize_request_id(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn sanitize_scope(value: &str) -> String {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        "<invalid-scope>".to_string()
    } else {
        value.to_string()
    }
}

fn is_allowed_graph_url(url: &str, graph_host: &str) -> bool {
    if graph_host.is_empty()
        || url.len() > 16 * 1024
        || url.contains('#')
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\')
    {
        return false;
    }

    let Some(scheme) = url.get(..8) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https://") {
        return false;
    }
    let remainder = &url[8..];
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];

    !authority.is_empty()
        && !authority.contains('@')
        && !authority.contains(':')
        && authority.eq_ignore_ascii_case(graph_host)
}
