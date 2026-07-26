//! Windows Registry export file (.reg) parser.
//!
//! Parses files exported by `regedit.exe` (format version 5.00 and REGEDIT4).
//! Handles UTF-16LE encoded files via the shared `read_file_content` decoder.

use serde::{Deserialize, Serialize};

/// Registry value type tag, matching Windows registry value kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistryValueKind {
    String,
    Dword,
    Qword,
    Binary,
    ExpandString,
    MultiString,
    None,
    DeleteMarker,
}

/// A single registry value within a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryValue {
    pub name: String,
    pub kind: RegistryValueKind,
    pub data: String,
    pub line_number: u32,
}

/// A registry key with its path and values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryKey {
    pub path: String,
    pub values: Vec<RegistryValue>,
    pub line_number: u32,
    pub is_delete: bool,
}

/// Result of parsing a .reg file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryParseResult {
    pub keys: Vec<RegistryKey>,
    pub file_path: String,
    pub file_size: u64,
    pub total_keys: u32,
    pub total_values: u32,
    pub parse_errors: u32,
}

/// Parse a decoded .reg file content into structured registry data.
pub fn parse_registry_content(
    content: &str,
    file_path: &str,
    file_size: u64,
) -> RegistryParseResult {
    let lines: Vec<&str> = content.lines().collect();
    let mut keys: Vec<RegistryKey> = Vec::new();
    let mut current_key: Option<RegistryKey> = None;
    let mut parse_errors: u32 = 0;
    let mut total_values: u32 = 0;

    let mut i = 0;
    // Skip header line(s)
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("Windows Registry Editor Version")
            || trimmed.starts_with("REGEDIT4")
            || trimmed.is_empty()
        {
            i += 1;
        } else {
            break;
        }
    }

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Key line: [HKEY_...] or [-HKEY_...]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Flush previous key
            if let Some(key) = current_key.take() {
                keys.push(key);
            }

            let inner = &trimmed[1..trimmed.len() - 1];
            let (path, is_delete) = if let Some(stripped) = inner.strip_prefix('-') {
                (stripped.to_string(), true)
            } else {
                (inner.to_string(), false)
            };

            current_key = Some(RegistryKey {
                path,
                values: Vec::new(),
                line_number: (i + 1) as u32,
                is_delete,
            });
            i += 1;
            continue;
        }

        // Value line — only valid inside a key
        if let Some(ref mut key) = current_key {
            if let Some(value) = parse_value_line(trimmed, (i + 1) as u32, &lines, &mut i) {
                total_values += 1;
                key.values.push(value);
            } else {
                parse_errors += 1;
                i += 1;
            }
        } else {
            parse_errors += 1;
            i += 1;
        }
    }

    // Flush last key
    if let Some(key) = current_key.take() {
        keys.push(key);
    }

    let total_keys = keys.len() as u32;

    RegistryParseResult {
        keys,
        file_path: file_path.to_string(),
        file_size,
        total_keys,
        total_values,
        parse_errors,
    }
}

/// Parse a value line, consuming continuation lines for hex data.
/// Advances `line_idx` past any consumed continuation lines.
fn parse_value_line(
    first_line: &str,
    line_number: u32,
    all_lines: &[&str],
    line_idx: &mut usize,
) -> Option<RegistryValue> {
    // Default value: @=<data>
    let (name, data_str) = if let Some(stripped) = first_line.strip_prefix("@=") {
        ("(Default)".to_string(), stripped)
    } else if first_line.starts_with('"') {
        // "name"=<data> or "name"=-
        let closing_quote = find_closing_quote(first_line, 1)?;
        let name = unescape_reg_string(&first_line[1..closing_quote]);
        let after = first_line[closing_quote + 1..].trim_start();
        if !after.starts_with('=') {
            return None;
        }
        let data_str = after[1..].trim_start();
        (name, data_str)
    } else {
        return None;
    };

    // Collect full data string, joining continuation lines
    let mut full_data = data_str.to_string();
    *line_idx += 1;

    // Handle backslash continuation for hex values
    while full_data.ends_with('\\') {
        full_data.pop(); // remove trailing backslash
        if *line_idx < all_lines.len() {
            let cont = all_lines[*line_idx].trim();
            full_data.push_str(cont);
            *line_idx += 1;
        } else {
            break;
        }
    }

    let full_data = full_data.trim();

    // Delete marker
    if full_data == "-" {
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::DeleteMarker,
            data: "(value deleted)".to_string(),
            line_number,
        });
    }

    // String value: "..."
    if full_data.starts_with('"') && full_data.len() >= 2 {
        let inner = if let Some(close) = find_closing_quote(full_data, 1) {
            unescape_reg_string(&full_data[1..close])
        } else {
            full_data[1..].to_string()
        };
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::String,
            data: inner,
            line_number,
        });
    }

    // DWORD: dword:XXXXXXXX
    if let Some(hex_str) = full_data.strip_prefix("dword:") {
        let value = u32::from_str_radix(hex_str.trim(), 16).unwrap_or(0);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::Dword,
            data: format!("0x{:08x} ({})", value, value),
            line_number,
        });
    }

    // hex(b): QWORD
    if let Some(hex_bytes_str) = full_data.strip_prefix("hex(b):") {
        let bytes = parse_hex_bytes(hex_bytes_str);
        let value = bytes_to_qword(&bytes);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::Qword,
            data: format!("0x{:016x} ({})", value, value),
            line_number,
        });
    }

    // hex(2): REG_EXPAND_SZ (UTF-16LE encoded)
    if let Some(hex_bytes_str) = full_data.strip_prefix("hex(2):") {
        let bytes = parse_hex_bytes(hex_bytes_str);
        let decoded = decode_utf16le_bytes(&bytes);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::ExpandString,
            data: decoded,
            line_number,
        });
    }

    // hex(7): REG_MULTI_SZ (UTF-16LE encoded, null-separated)
    if let Some(hex_bytes_str) = full_data.strip_prefix("hex(7):") {
        let bytes = parse_hex_bytes(hex_bytes_str);
        let decoded = decode_utf16le_multi_string(&bytes);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::MultiString,
            data: decoded,
            line_number,
        });
    }

    // hex(0): REG_NONE
    if let Some(hex_bytes_str) = full_data.strip_prefix("hex(0):") {
        let bytes = parse_hex_bytes(hex_bytes_str);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::None,
            data: format_hex_display(&bytes),
            line_number,
        });
    }

    // hex: REG_BINARY
    if let Some(hex_bytes_str) = full_data.strip_prefix("hex:") {
        let bytes = parse_hex_bytes(hex_bytes_str);
        return Some(RegistryValue {
            name,
            kind: RegistryValueKind::Binary,
            data: format_hex_display(&bytes),
            line_number,
        });
    }

    // Other hex(N): types — treat as binary
    if full_data.starts_with("hex(") {
        if let Some(colon_pos) = full_data.find("):") {
            let hex_bytes_str = &full_data[colon_pos + 2..];
            let bytes = parse_hex_bytes(hex_bytes_str);
            return Some(RegistryValue {
                name,
                kind: RegistryValueKind::Binary,
                data: format_hex_display(&bytes),
                line_number,
            });
        }
    }

    // Unrecognized format
    Some(RegistryValue {
        name,
        kind: RegistryValueKind::String,
        data: full_data.to_string(),
        line_number,
    })
}

/// Find closing quote position, handling escaped quotes (\\").
fn find_closing_quote(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
        } else if bytes[i] == b'"' {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

/// Unescape a registry string value (handles \\, \").
fn unescape_reg_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    'n' => result.push('\n'),
                    _ => {
                        result.push('\\');
                        result.push(next);
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse comma-separated hex bytes like "01,00,04,80".
fn parse_hex_bytes(s: &str) -> Vec<u8> {
    s.split(',')
        .filter_map(|b| {
            let trimmed = b.trim();
            if trimmed.is_empty() {
                None
            } else {
                u8::from_str_radix(trimmed, 16).ok()
            }
        })
        .collect()
}

/// Convert up to 8 bytes (little-endian) to a u64.
fn bytes_to_qword(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        value |= (byte as u64) << (i * 8);
    }
    value
}

/// Decode UTF-16LE bytes to a String, stripping trailing null.
fn decode_utf16le_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }
    let u16_iter = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    let decoded: String = char::decode_utf16(u16_iter)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    decoded.trim_end_matches('\0').to_string()
}

/// Decode UTF-16LE multi-string (null-separated, double-null terminated).
fn decode_utf16le_multi_string(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }
    let u16_iter: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // Split on null characters, filter empties
    let strings: Vec<String> = u16_iter
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(|s| {
            char::decode_utf16(s.iter().copied())
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .collect()
        })
        .collect();

    strings.join(" | ")
}

/// Format bytes as hex display string, truncated if long.
fn format_hex_display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(zero-length binary value)".to_string();
    }
    let display_len = bytes.len().min(128);
    let hex: String = bytes[..display_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > 128 {
        format!("{} ... ({} bytes total)", hex, bytes.len())
    } else {
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_reg_file() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"StringValue"="Hello World"
"DwordValue"=dword:0000002a
@="Default Value"

[HKEY_LOCAL_MACHINE\SOFTWARE\Test\SubKey]
"AnotherValue"="Test"
"#;

        let result = parse_registry_content(content, "test.reg", 200);
        assert_eq!(result.total_keys, 2);
        assert_eq!(result.total_values, 4);
        assert_eq!(result.parse_errors, 0);

        let key0 = &result.keys[0];
        assert_eq!(key0.path, r"HKEY_LOCAL_MACHINE\SOFTWARE\Test");
        assert_eq!(key0.values.len(), 3);
        assert!(!key0.is_delete);

        assert_eq!(key0.values[0].name, "StringValue");
        assert_eq!(key0.values[0].kind, RegistryValueKind::String);
        assert_eq!(key0.values[0].data, "Hello World");

        assert_eq!(key0.values[1].name, "DwordValue");
        assert_eq!(key0.values[1].kind, RegistryValueKind::Dword);
        assert_eq!(key0.values[1].data, "0x0000002a (42)");

        assert_eq!(key0.values[2].name, "(Default)");
        assert_eq!(key0.values[2].data, "Default Value");
    }

    #[test]
    fn test_parse_hex_continuation() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"BinValue"=hex:01,02,03,\
  04,05,06
"#;

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(result.total_values, 1);
        assert_eq!(result.keys[0].values[0].kind, RegistryValueKind::Binary);
        assert_eq!(result.keys[0].values[0].data, "01 02 03 04 05 06");
    }

    #[test]
    fn test_parse_expand_string() {
        // "system32\drivers\HTTP.sys" encoded as UTF-16LE hex
        let content = "Windows Registry Editor Version 5.00\n\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n\
            \"Path\"=hex(2):73,00,79,00,73,00,00,00\n";

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(
            result.keys[0].values[0].kind,
            RegistryValueKind::ExpandString
        );
        assert_eq!(result.keys[0].values[0].data, "sys");
    }

    #[test]
    fn test_parse_delete_key_and_value() {
        let content = r#"Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\OldKey]

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"Removed"=-
"#;

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(result.total_keys, 2);
        assert!(result.keys[0].is_delete);
        assert_eq!(
            result.keys[1].values[0].kind,
            RegistryValueKind::DeleteMarker
        );
    }

    #[test]
    fn test_parse_qword() {
        let content = "Windows Registry Editor Version 5.00\n\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n\
            \"Big\"=hex(b):ff,ff,00,00,00,00,00,00\n";

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(result.keys[0].values[0].kind, RegistryValueKind::Qword);
        assert!(result.keys[0].values[0].data.contains("65535"));
    }

    #[test]
    fn test_parse_multi_string() {
        // "AB\0CD\0\0" encoded as UTF-16LE
        let content = "Windows Registry Editor Version 5.00\n\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n\
            \"Multi\"=hex(7):41,00,42,00,00,00,43,00,44,00,00,00,00,00\n";

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(
            result.keys[0].values[0].kind,
            RegistryValueKind::MultiString
        );
        assert_eq!(result.keys[0].values[0].data, "AB | CD");
    }

    #[test]
    fn test_escaped_string_value() {
        let content = "Windows Registry Editor Version 5.00\n\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n\
            \"Path\"=\"C:\\\\Windows\\\\System32\"\n";

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(result.keys[0].values[0].data, "C:\\Windows\\System32");
    }

    #[test]
    fn test_empty_key() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\EmptyKey]

[HKEY_LOCAL_MACHINE\SOFTWARE\NextKey]
"Value"="test"
"#;

        let result = parse_registry_content(content, "test.reg", 100);
        assert_eq!(result.total_keys, 2);
        assert_eq!(result.keys[0].values.len(), 0);
        assert_eq!(result.keys[1].values.len(), 1);
    }

    #[test]
    fn test_parse_empty_file() {
        let content = "Windows Registry Editor Version 5.00\n\n";
        let result = parse_registry_content(content, "empty.reg", 40);
        assert_eq!(result.total_keys, 0);
        assert_eq!(result.total_values, 0);
        assert_eq!(result.parse_errors, 0);
    }
}
