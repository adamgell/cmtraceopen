use crate::intune::models::KnowledgeBaseLink;
use super::models::AnomalyKind;

/// Get Microsoft Learn links relevant to the given anomaly kind.
pub fn get_knowledge_base_links(kind: &AnomalyKind) -> Vec<KnowledgeBaseLink> {
    match kind {
        AnomalyKind::MissingStep => vec![
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Win32 app management".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/apps-win32-app-management".to_string(),
                relevance: "Win32 app lifecycle management".to_string(),
            },
        ],
        AnomalyKind::OutOfOrderStep => vec![
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "App dependencies and supersedence".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/apps-win32-supersedence".to_string(),
                relevance: "App dependency ordering".to_string(),
            },
        ],
        AnomalyKind::OrphanedStart => vec![
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Collect diagnostics from Windows device".to_string(),
                url: "https://learn.microsoft.com/mem/intune/remote-actions/collect-diagnostics".to_string(),
                relevance: "Diagnostic collection".to_string(),
            },
        ],
        AnomalyKind::UnexpectedLoop => vec![
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Win32 app management".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/apps-win32-app-management".to_string(),
                relevance: "Win32 app lifecycle management".to_string(),
            },
        ],
        AnomalyKind::DurationOutlier => vec![
            KnowledgeBaseLink {
                title: "Delivery Optimization for Intune".to_string(),
                url: "https://learn.microsoft.com/mem/intune/configuration/delivery-optimization-windows".to_string(),
                relevance: "Delivery Optimization setup".to_string(),
            },
        ],
        AnomalyKind::FrequencySpike => vec![
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
        ],
        AnomalyKind::FrequencyGap => vec![
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Collect diagnostics from Windows device".to_string(),
                url: "https://learn.microsoft.com/mem/intune/remote-actions/collect-diagnostics".to_string(),
                relevance: "Diagnostic collection".to_string(),
            },
        ],
        AnomalyKind::DownloadPerformance => vec![
            KnowledgeBaseLink {
                title: "Delivery Optimization for Intune".to_string(),
                url: "https://learn.microsoft.com/mem/intune/configuration/delivery-optimization-windows".to_string(),
                relevance: "Delivery Optimization setup".to_string(),
            },
            KnowledgeBaseLink {
                title: "Network endpoints for Intune".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/intune-endpoints".to_string(),
                relevance: "Network configuration".to_string(),
            },
        ],
        AnomalyKind::ErrorRateTrend => vec![
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
        ],
        AnomalyKind::SeverityEscalation => vec![
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
        ],
        AnomalyKind::CrossSourceCorrelation => vec![
            KnowledgeBaseLink {
                title: "Collect diagnostics from Windows device".to_string(),
                url: "https://learn.microsoft.com/mem/intune/remote-actions/collect-diagnostics".to_string(),
                relevance: "Diagnostic collection".to_string(),
            },
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
        ],
        AnomalyKind::RootCauseCandidate => vec![
            KnowledgeBaseLink {
                title: "Troubleshoot Win32 app installations".to_string(),
                url: "https://learn.microsoft.com/mem/intune/apps/troubleshoot-app-install".to_string(),
                relevance: "Win32 app troubleshooting".to_string(),
            },
            KnowledgeBaseLink {
                title: "Intune troubleshooting".to_string(),
                url: "https://learn.microsoft.com/mem/intune/fundamentals/help-desk-operators".to_string(),
                relevance: "General Intune troubleshooting".to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_kinds_have_links() {
        let all_kinds = [
            AnomalyKind::MissingStep,
            AnomalyKind::OutOfOrderStep,
            AnomalyKind::OrphanedStart,
            AnomalyKind::UnexpectedLoop,
            AnomalyKind::DurationOutlier,
            AnomalyKind::FrequencySpike,
            AnomalyKind::FrequencyGap,
            AnomalyKind::DownloadPerformance,
            AnomalyKind::ErrorRateTrend,
            AnomalyKind::SeverityEscalation,
            AnomalyKind::CrossSourceCorrelation,
            AnomalyKind::RootCauseCandidate,
        ];
        for kind in &all_kinds {
            let links = get_knowledge_base_links(kind);
            assert!(
                !links.is_empty(),
                "{:?} should have at least one knowledge base link",
                kind
            );
        }
    }

    #[test]
    fn test_links_have_valid_urls() {
        let all_kinds = [
            AnomalyKind::MissingStep,
            AnomalyKind::OutOfOrderStep,
            AnomalyKind::OrphanedStart,
            AnomalyKind::UnexpectedLoop,
            AnomalyKind::DurationOutlier,
            AnomalyKind::FrequencySpike,
            AnomalyKind::FrequencyGap,
            AnomalyKind::DownloadPerformance,
            AnomalyKind::ErrorRateTrend,
            AnomalyKind::SeverityEscalation,
            AnomalyKind::CrossSourceCorrelation,
            AnomalyKind::RootCauseCandidate,
        ];
        for kind in &all_kinds {
            for link in get_knowledge_base_links(kind) {
                assert!(
                    link.url.starts_with("https://"),
                    "URL for {:?} link '{}' should start with https://, got: {}",
                    kind,
                    link.title,
                    link.url
                );
            }
        }
    }

    #[test]
    fn test_download_performance_has_do_link() {
        let links = get_knowledge_base_links(&AnomalyKind::DownloadPerformance);
        let has_do = links.iter().any(|l| l.url.contains("delivery-optimization"));
        assert!(
            has_do,
            "DownloadPerformance should include a Delivery Optimization link"
        );
    }
}
