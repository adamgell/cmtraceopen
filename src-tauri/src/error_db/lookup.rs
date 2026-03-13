use super::codes::ERROR_CODES;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLookupResult {
    pub code_hex: String,
    pub code_decimal: String,
    pub description: String,
    pub found: bool,
}

/// Look up an error code by its hex or decimal value.
/// Accepts formats: "0x80070005", "80070005", "-2147024891", "2147942405"
pub fn lookup_error_code(input: &str) -> ErrorLookupResult {
    let input = input.trim();

    // Try to parse as hex (with or without 0x prefix)
    let code = if input.starts_with("0x") || input.starts_with("0X") {
        u32::from_str_radix(&input[2..], 16).ok()
    } else if input.starts_with('-') {
        // Negative decimal (signed representation of HRESULT)
        input.parse::<i32>().ok().map(|v| v as u32)
    } else if let Ok(hex_val) = u32::from_str_radix(input, 16) {
        // Try as raw hex without prefix (if it looks like hex)
        if input.len() >= 6 && input.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(hex_val)
        } else {
            // Try as decimal first
            input.parse::<u32>().ok().or(Some(hex_val))
        }
    } else {
        input.parse::<u32>().ok()
    };

    match code {
        Some(c) => {
            if let Some((_, desc)) = ERROR_CODES.iter().find(|(ec, _)| *ec == c) {
                ErrorLookupResult {
                    code_hex: format!("0x{:08X}", c),
                    code_decimal: format!("{}", c as i32),
                    description: desc.to_string(),
                    found: true,
                }
            } else {
                // Code not in database — still show the formatted values
                ErrorLookupResult {
                    code_hex: format!("0x{:08X}", c),
                    code_decimal: format!("{}", c as i32),
                    description: "Unknown error code".to_string(),
                    found: false,
                }
            }
        }
        None => ErrorLookupResult {
            code_hex: String::new(),
            code_decimal: String::new(),
            description: "Invalid error code format".to_string(),
            found: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_hex_prefix() {
        let result = lookup_error_code("0x80070005");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_hex_no_prefix() {
        let result = lookup_error_code("80070005");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_negative_decimal() {
        // 0x80070005 = -2147024891 as signed i32
        let result = lookup_error_code("-2147024891");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_success_code() {
        let result = lookup_error_code("0x00000000");
        assert!(result.found);
        assert!(result.description.contains("S_OK"));
    }

    #[test]
    fn test_lookup_unknown() {
        let result = lookup_error_code("0xDEADBEEF");
        assert!(!result.found);
        assert_eq!(result.code_hex, "0xDEADBEEF");
    }
}
