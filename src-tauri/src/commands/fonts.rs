use once_cell::sync::Lazy;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemFontList {
    pub families: Vec<String>,
}

static CACHED_FONTS: Lazy<SystemFontList> = Lazy::new(|| {
    let source = font_kit::source::SystemSource::new();
    let mut families = source.all_families().unwrap_or_default();
    families.sort_unstable_by_key(|a| a.to_ascii_lowercase());
    families.dedup();
    families.retain(|name| !name.starts_with('.') && !name.starts_with('#') && !name.is_empty());
    SystemFontList { families }
});

#[tauri::command]
pub fn list_system_fonts() -> SystemFontList {
    CACHED_FONTS.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_returns_non_empty() {
        let result = list_system_fonts();
        assert!(!result.families.is_empty());
    }

    #[test]
    fn test_list_is_sorted() {
        let result = list_system_fonts();
        let mut sorted = result.families.clone();
        sorted.sort_unstable_by(|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
        assert_eq!(result.families, sorted);
    }

    #[test]
    fn test_no_hidden_fonts() {
        let result = list_system_fonts();
        for family in &result.families {
            assert!(!family.starts_with('.'), "hidden font found: {}", family);
            assert!(!family.starts_with('#'), "hidden font found: {}", family);
            assert!(!family.is_empty(), "empty font name found");
        }
    }
}
