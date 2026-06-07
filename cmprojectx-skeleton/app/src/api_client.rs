//! Thin HTTP client to the local .NET service (contract/openapi.yaml).
//! Replace with a generated client (progenitor) once codegen is wired.

use api_types::{AuditEvent, DriftRecord, SearchResult, SyncStatus};

pub struct ApiClient {
    base: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into(), http: reqwest::Client::new() }
    }

    pub async fn health(&self) -> reqwest::Result<SyncStatus> {
        self.http.get(format!("{}/health", self.base)).send().await?.json().await
    }

    pub async fn audit(&self, q: Option<&str>) -> reqwest::Result<Vec<AuditEvent>> {
        let mut req = self.http.get(format!("{}/audit", self.base));
        if let Some(q) = q {
            req = req.query(&[("q", q)]);
        }
        req.send().await?.json().await
    }

    pub async fn drift(&self, object_id: &str) -> reqwest::Result<DriftRecord> {
        self.http
            .get(format!("{}/drift", self.base))
            .query(&[("objectId", object_id)])
            .send()
            .await?
            .json()
            .await
    }

    pub async fn search(&self, q: &str) -> reqwest::Result<Vec<SearchResult>> {
        self.http
            .get(format!("{}/search", self.base))
            .query(&[("q", q)])
            .send()
            .await?
            .json()
            .await
    }
}
