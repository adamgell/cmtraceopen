use crate::parser;

/// Parse a Windows Registry export (.reg) file and return its structured representation.
#[tauri::command]
pub fn parse_registry_file(
    path: String,
) -> Result<crate::parser::registry::RegistryParseResult, crate::error::AppError> {
    let content = parser::read_file_content(&path)?;
    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(crate::parser::registry::parse_registry_content(
        &content, &path, file_size,
    ))
}
