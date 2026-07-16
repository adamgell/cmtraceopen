//! Portable, bounded Microsoft Graph page client.
//!
//! The client owns request, retry, pagination, cancellation, and error-safety
//! policy. Concrete bearer-token attachment and HTTP I/O stay behind a
//! platform adapter implementing [`GraphTransport`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::models::{
    GraphAppInfo, GraphHttpMethod, GraphResolutionResult, GraphTransportRequest,
    GraphTransportResponse,
};

pub const MAX_GRAPH_ATTEMPTS: usize = 4;
pub const MAX_GRAPH_RETRY_DELAY: Duration = Duration::from_secs(30);
pub const MAX_GRAPH_PAGES: usize = 25;
pub const MAX_GRAPH_ITEMS: usize = 5_000;
pub const MAX_GRAPH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const GRAPH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GRAPH_BATCH_REQUESTS: usize = 20;

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
    pub(super) fn new(kind: GraphClientErrorKind, required_scope: &str) -> Self {
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
        Self::for_status(kind, response.status, &response.headers, required_scope)
    }

    fn for_status(
        kind: GraphClientErrorKind,
        status: u16,
        headers: &BTreeMap<String, String>,
        required_scope: &str,
    ) -> Self {
        Self {
            kind,
            status: Some(status),
            request_id: graph_request_id(headers),
            required_scope: sanitize_scope(required_scope),
        }
    }

    pub fn invalidates_auth(&self) -> bool {
        self.kind == GraphClientErrorKind::Unauthorized || self.status == Some(401)
    }

    /// Whether a failed `$batch` read may safely be retried as individual GETs.
    /// Auth, permission, throttle, cancellation, and connectivity failures must
    /// not fan out or restart an exhausted logical operation.
    pub fn allows_single_item_fallback(&self) -> bool {
        !matches!(self.status, Some(401 | 403 | 429 | 503 | 504))
            && matches!(
                self.kind,
                GraphClientErrorKind::NotFound
                    | GraphClientErrorKind::HttpStatus
                    | GraphClientErrorKind::ResponseTooLarge
                    | GraphClientErrorKind::InvalidResponse
            )
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

/// Resolve one Graph app chunk without restarting exhausted or retryable work.
///
/// The caller supplies the concrete batch and single-item reads so this policy
/// remains portable while Windows keeps ownership of WAM and HTTP I/O.
pub fn resolve_app_chunk_with_fallback<Batch, Single>(
    guids: &[String],
    fetch_batch: Batch,
    mut fetch_single: Single,
) -> Result<GraphResolutionResult, GraphClientError>
where
    Batch: FnOnce(&[String]) -> Result<GraphResolutionResult, GraphClientError>,
    Single: FnMut(&str) -> Result<Option<GraphAppInfo>, GraphClientError>,
{
    match fetch_batch(guids) {
        Ok(result) => Ok(result),
        Err(error) if error.invalidates_auth() => Err(error),
        Err(error) => {
            let allows_single_item_fallback = error.allows_single_item_fallback();
            let mut result = GraphResolutionResult {
                resolved: HashMap::new(),
                not_found: Vec::new(),
                errors: vec![format!("Batch request failed: {error}")],
            };

            if !allows_single_item_fallback {
                return Ok(result);
            }

            for guid in guids {
                match fetch_single(guid) {
                    Ok(Some(info)) => {
                        result.resolved.insert(guid.clone(), info);
                    }
                    Ok(None) => result.not_found.push(guid.clone()),
                    Err(error) if error.invalidates_auth() => return Err(error),
                    Err(error) => result.errors.push(format!("{guid}: {error}")),
                }
            }

            Ok(result)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GraphPage<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

#[derive(Clone, PartialEq)]
pub enum GraphBatchItem<T> {
    Success(T),
    NotFound,
}

impl<T> fmt::Debug for GraphBatchItem<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => formatter.write_str("GraphBatchItem::Success(<redacted>)"),
            Self::NotFound => formatter.write_str("GraphBatchItem::NotFound"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphBatchRequestEnvelope {
    requests: Vec<GraphBatchSubrequest>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphBatchSubrequest {
    id: String,
    method: String,
    url: String,
}

#[derive(Deserialize)]
struct GraphBatchResponseEnvelope {
    responses: Vec<GraphBatchSubresponse>,
}

#[derive(Deserialize)]
struct GraphBatchSubresponse {
    id: String,
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphStatusAction {
    Success,
    Retry,
    Error(GraphClientErrorKind),
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

            let request = GraphTransportRequest {
                method: GraphHttpMethod::Get,
                url: url.clone(),
                consistency_level: Some("eventual".to_string()),
                content_type: None,
                body: None,
                required_scope: sanitize_scope(required_scope),
            };
            let response = self.execute_with_retry(&request, required_scope)?;
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

    /// Execute one bounded Graph request and decode its JSON response.
    ///
    /// This accepts read-only GET requests. Validated `$batch` POSTs use
    /// [`Self::request_batch_json`] so callers cannot bypass batch policy.
    pub fn request_json<Response: DeserializeOwned>(
        &self,
        mut request: GraphTransportRequest,
    ) -> Result<Response, GraphClientError> {
        let required_scope = sanitize_scope(&request.required_scope);
        request.required_scope = required_scope.clone();
        if request.method != GraphHttpMethod::Get
            || request.content_type.is_some()
            || request.body.is_some()
        {
            return Err(GraphClientError::new(
                GraphClientErrorKind::InvalidResponse,
                &required_scope,
            ));
        }
        self.ensure_not_cancelled(&required_scope)?;
        self.ensure_allowed_url(&request.url, &required_scope)?;

        self.execute_json_with_retry(&request, &required_scope)
    }

    pub fn request_batch_json<Response: DeserializeOwned>(
        &self,
        mut request: GraphTransportRequest,
    ) -> Result<Vec<GraphBatchItem<Response>>, GraphClientError> {
        let required_scope = sanitize_scope(&request.required_scope);
        request.required_scope = required_scope.clone();
        if !is_allowed_graph_batch_url(&request.url, &self.graph_host) {
            return Err(GraphClientError::new(
                GraphClientErrorKind::InvalidUrl,
                &required_scope,
            ));
        }
        let batch = parse_batch_request(&request, &required_scope)?;
        let (outer_response, initial_attempts) =
            self.execute_with_retry_count(&request, &required_scope)?;
        let envelope: GraphBatchResponseEnvelope =
            decode_json_response(&outer_response, &required_scope)?;
        let mut responses =
            index_batch_responses(envelope.responses, &batch.requests, &required_scope)?;
        let mut items = Vec::with_capacity(batch.requests.len());

        for prioritized_kind in [
            GraphClientErrorKind::Unauthorized,
            GraphClientErrorKind::PermissionDenied,
        ] {
            for subrequest in &batch.requests {
                let response = responses
                    .get(&subrequest.id)
                    .ok_or_else(|| invalid_batch_response(&required_scope))?;
                if graph_status_action(response.status, initial_attempts - 1)
                    == GraphStatusAction::Error(prioritized_kind)
                {
                    return Err(GraphClientError::for_status(
                        prioritized_kind,
                        response.status,
                        &response.headers,
                        &required_scope,
                    ));
                }
            }
        }

        for subrequest in &batch.requests {
            let response = responses
                .get(&subrequest.id)
                .ok_or_else(|| invalid_batch_response(&required_scope))?;
            if let GraphStatusAction::Error(kind) =
                graph_status_action(response.status, initial_attempts - 1)
            {
                if kind != GraphClientErrorKind::NotFound {
                    return Err(GraphClientError::for_status(
                        kind,
                        response.status,
                        &response.headers,
                        &required_scope,
                    ));
                }
            }
        }

        for subrequest in &batch.requests {
            let response = responses
                .remove(&subrequest.id)
                .ok_or_else(|| invalid_batch_response(&required_scope))?;
            items.push(self.resolve_batch_item(
                &request,
                subrequest,
                response,
                initial_attempts,
                &required_scope,
            )?);
        }

        Ok(items)
    }

    fn resolve_batch_item<Response: DeserializeOwned>(
        &self,
        request_template: &GraphTransportRequest,
        subrequest: &GraphBatchSubrequest,
        mut response: GraphBatchSubresponse,
        mut attempts_used: usize,
        required_scope: &str,
    ) -> Result<GraphBatchItem<Response>, GraphClientError> {
        loop {
            let attempt = attempts_used - 1;
            match graph_status_action(response.status, attempt) {
                GraphStatusAction::Success => {
                    let body = response.body.take().ok_or_else(|| {
                        GraphClientError::for_status(
                            GraphClientErrorKind::InvalidResponse,
                            response.status,
                            &response.headers,
                            required_scope,
                        )
                    })?;
                    let item = serde_json::from_value(body).map_err(|_| {
                        GraphClientError::for_status(
                            GraphClientErrorKind::InvalidResponse,
                            response.status,
                            &response.headers,
                            required_scope,
                        )
                    })?;
                    return Ok(GraphBatchItem::Success(item));
                }
                GraphStatusAction::Error(GraphClientErrorKind::NotFound) => {
                    return Ok(GraphBatchItem::NotFound);
                }
                GraphStatusAction::Retry => {
                    self.wait_for_retry(&response.headers, attempt, required_scope)?;

                    let body = serde_json::to_vec(&GraphBatchRequestEnvelope {
                        requests: vec![subrequest.clone()],
                    })
                    .map_err(|_| invalid_batch_response(required_scope))?;
                    let mut retry_request = request_template.clone();
                    retry_request.body = Some(body);

                    loop {
                        let outer_response = self.execute_once(&retry_request, required_scope)?;
                        attempts_used += 1;
                        let attempt = attempts_used - 1;
                        match graph_status_action(outer_response.status, attempt) {
                            GraphStatusAction::Success => {
                                let envelope: GraphBatchResponseEnvelope =
                                    decode_json_response(&outer_response, required_scope)?;
                                let mut retry_responses = index_batch_responses(
                                    envelope.responses,
                                    std::slice::from_ref(subrequest),
                                    required_scope,
                                )?;
                                response = retry_responses
                                    .remove(&subrequest.id)
                                    .ok_or_else(|| invalid_batch_response(required_scope))?;
                                break;
                            }
                            GraphStatusAction::Retry => {
                                self.wait_for_retry(
                                    &outer_response.headers,
                                    attempt,
                                    required_scope,
                                )?;
                            }
                            GraphStatusAction::Error(kind) => {
                                return Err(GraphClientError::for_response(
                                    kind,
                                    &outer_response,
                                    required_scope,
                                ));
                            }
                        }
                    }
                }
                GraphStatusAction::Error(kind) => {
                    return Err(GraphClientError::for_status(
                        kind,
                        response.status,
                        &response.headers,
                        required_scope,
                    ));
                }
            }
        }
    }

    fn execute_with_retry(
        &self,
        request: &GraphTransportRequest,
        required_scope: &str,
    ) -> Result<GraphTransportResponse, GraphClientError> {
        self.execute_with_retry_count(request, required_scope)
            .map(|(response, _)| response)
    }

    fn execute_with_retry_count(
        &self,
        request: &GraphTransportRequest,
        required_scope: &str,
    ) -> Result<(GraphTransportResponse, usize), GraphClientError> {
        for attempt in 0..MAX_GRAPH_ATTEMPTS {
            let response = self.execute_once(request, required_scope)?;

            match graph_status_action(response.status, attempt) {
                GraphStatusAction::Success => return Ok((response, attempt + 1)),
                GraphStatusAction::Retry => {
                    self.wait_for_retry(&response.headers, attempt, required_scope)?;
                }
                GraphStatusAction::Error(kind) => {
                    return Err(GraphClientError::for_response(
                        kind,
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

    fn execute_once(
        &self,
        request: &GraphTransportRequest,
        required_scope: &str,
    ) -> Result<GraphTransportResponse, GraphClientError> {
        self.ensure_not_cancelled(required_scope)?;
        let response = self
            .transport
            .execute(request, GRAPH_REQUEST_TIMEOUT)
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

        Ok(response)
    }

    fn wait_for_retry(
        &self,
        headers: &BTreeMap<String, String>,
        attempt: usize,
        required_scope: &str,
    ) -> Result<(), GraphClientError> {
        let delay = retry_delay(headers, attempt);
        if self.cancellation.wait_for_retry(delay) {
            Ok(())
        } else {
            Err(GraphClientError::new(
                GraphClientErrorKind::Cancelled,
                required_scope,
            ))
        }
    }

    fn execute_json_with_retry<Response: DeserializeOwned>(
        &self,
        request: &GraphTransportRequest,
        required_scope: &str,
    ) -> Result<Response, GraphClientError> {
        let response = self.execute_with_retry(request, required_scope)?;
        decode_json_response(&response, required_scope)
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

fn decode_json_response<Response: DeserializeOwned>(
    response: &GraphTransportResponse,
    required_scope: &str,
) -> Result<Response, GraphClientError> {
    let request_id = graph_request_id(&response.headers);
    serde_json::from_slice(&response.body).map_err(|_| {
        let mut error =
            GraphClientError::new(GraphClientErrorKind::InvalidResponse, required_scope);
        error.status = Some(response.status);
        error.request_id = request_id;
        error
    })
}

fn parse_batch_request(
    request: &GraphTransportRequest,
    required_scope: &str,
) -> Result<GraphBatchRequestEnvelope, GraphClientError> {
    if request.method != GraphHttpMethod::Post
        || !request
            .content_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return Err(invalid_batch_response(required_scope));
    }

    let body = request
        .body
        .as_deref()
        .filter(|body| body.len() <= MAX_GRAPH_RESPONSE_BYTES)
        .ok_or_else(|| invalid_batch_response(required_scope))?;
    let batch: GraphBatchRequestEnvelope =
        serde_json::from_slice(body).map_err(|_| invalid_batch_response(required_scope))?;
    if batch.requests.is_empty() || batch.requests.len() > MAX_GRAPH_BATCH_REQUESTS {
        return Err(invalid_batch_response(required_scope));
    }

    let mut request_ids = HashSet::with_capacity(batch.requests.len());
    for subrequest in &batch.requests {
        if subrequest.method != "GET"
            || sanitize_request_id(&subrequest.id).as_deref() != Some(subrequest.id.as_str())
            || !request_ids.insert(subrequest.id.as_str())
            || !is_allowed_batch_relative_url(&subrequest.url)
        {
            return Err(invalid_batch_response(required_scope));
        }
    }

    Ok(batch)
}

fn index_batch_responses(
    responses: Vec<GraphBatchSubresponse>,
    expected_requests: &[GraphBatchSubrequest],
    required_scope: &str,
) -> Result<HashMap<String, GraphBatchSubresponse>, GraphClientError> {
    if responses.len() != expected_requests.len() {
        return Err(invalid_batch_response(required_scope));
    }

    let expected_ids: HashSet<&str> = expected_requests
        .iter()
        .map(|request| request.id.as_str())
        .collect();
    let mut indexed = HashMap::with_capacity(responses.len());
    for response in responses {
        let id = response.id.clone();
        if !expected_ids.contains(id.as_str()) || indexed.insert(id, response).is_some() {
            return Err(invalid_batch_response(required_scope));
        }
    }
    if indexed.len() != expected_ids.len() {
        return Err(invalid_batch_response(required_scope));
    }

    Ok(indexed)
}

fn invalid_batch_response(required_scope: &str) -> GraphClientError {
    GraphClientError::new(GraphClientErrorKind::InvalidResponse, required_scope)
}

fn graph_status_action(status: u16, attempt: usize) -> GraphStatusAction {
    match status {
        200..=299 => GraphStatusAction::Success,
        401 => GraphStatusAction::Error(GraphClientErrorKind::Unauthorized),
        403 => GraphStatusAction::Error(GraphClientErrorKind::PermissionDenied),
        404 => GraphStatusAction::Error(GraphClientErrorKind::NotFound),
        429 | 503 | 504 if attempt + 1 < MAX_GRAPH_ATTEMPTS => GraphStatusAction::Retry,
        429 | 503 | 504 => GraphStatusAction::Error(GraphClientErrorKind::RetryExhausted),
        _ => GraphStatusAction::Error(GraphClientErrorKind::HttpStatus),
    }
}

fn retry_delay(headers: &BTreeMap<String, String>, attempt: usize) -> Duration {
    let retry_after = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    retry_after
        .unwrap_or_else(|| Duration::from_secs(1_u64 << attempt.min(5)))
        .min(MAX_GRAPH_RETRY_DELAY)
}

fn graph_request_id(headers: &BTreeMap<String, String>) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("request-id"))
        .and_then(|(_, value)| sanitize_request_id(value))
}

fn is_allowed_batch_relative_url(url: &str) -> bool {
    url.starts_with('/')
        && !url.starts_with("//")
        && url.len() <= 16 * 1024
        && !url.contains('#')
        && !url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\')
        && !url
            .split('?')
            .next()
            .unwrap_or_default()
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
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

fn is_allowed_graph_batch_url(url: &str, graph_host: &str) -> bool {
    if !is_allowed_graph_url(url, graph_host) {
        return false;
    }

    let remainder = &url[8..];
    let Some(path_start) = remainder.find('/') else {
        return false;
    };
    let path = &remainder[path_start..];
    path.eq_ignore_ascii_case("/v1.0/$batch") || path.eq_ignore_ascii_case("/beta/$batch")
}
