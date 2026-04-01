use crate::collector::types::CollectionProfile;

const EMBEDDED_PROFILE_JSON: &str = include_str!("profile_data.json");

impl CollectionProfile {
    /// Load the embedded collection profile compiled into the binary.
    pub fn embedded() -> CollectionProfile {
        serde_json::from_str(EMBEDDED_PROFILE_JSON)
            .expect("embedded collection profile JSON must be valid")
    }

    /// Total number of individual collection items across all categories.
    pub fn total_items(&self) -> usize {
        self.logs.len()
            + self.registry.len()
            + self.event_logs.len()
            + self.exports.len()
            + self.commands.len()
    }

    /// Filter all collection items to only those whose `family` is in the provided list.
    pub fn filter_by_families(&mut self, families: &[String]) {
        self.logs.retain(|item| families.contains(&item.family));
        self.registry.retain(|item| families.contains(&item.family));
        self.event_logs.retain(|item| families.contains(&item.family));
        self.exports.retain(|item| families.contains(&item.family));
        self.commands.retain(|item| families.contains(&item.family));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profile_deserializes() {
        let profile = CollectionProfile::embedded();
        assert_eq!(profile.profile_name, "cmtrace-full-diagnostics-v1");
        assert!(!profile.logs.is_empty());
        assert!(!profile.registry.is_empty());
        assert!(!profile.event_logs.is_empty());
        assert!(!profile.exports.is_empty());
        assert!(!profile.commands.is_empty());
    }

    #[test]
    fn total_items_sums_all_categories() {
        let profile = CollectionProfile::embedded();
        let expected = profile.logs.len()
            + profile.registry.len()
            + profile.event_logs.len()
            + profile.exports.len()
            + profile.commands.len();
        assert_eq!(profile.total_items(), expected);
        assert!(expected > 100, "full profile should have 100+ items");
    }

    #[test]
    fn filter_by_families_retains_only_matching() {
        let mut profile = CollectionProfile::embedded();
        let original_total = profile.total_items();

        profile.filter_by_families(&["general".to_string(), "networking".to_string()]);

        assert!(profile.total_items() > 0, "should have some items for general+networking");
        assert!(profile.total_items() < original_total, "should be fewer items than full profile");

        // Verify every remaining item belongs to an allowed family.
        for item in &profile.logs {
            assert!(item.family == "general" || item.family == "networking", "unexpected log family: {}", item.family);
        }
        for item in &profile.registry {
            assert!(item.family == "general" || item.family == "networking", "unexpected registry family: {}", item.family);
        }
        for item in &profile.commands {
            assert!(item.family == "general" || item.family == "networking", "unexpected command family: {}", item.family);
        }
    }

    #[test]
    fn filter_by_families_empty_list_yields_empty_profile() {
        let mut profile = CollectionProfile::embedded();
        profile.filter_by_families(&[]);
        assert_eq!(profile.total_items(), 0);
    }
}
