//! Parses "Get policies" JSON payloads from AppWorkload logs.
//!
//! These payloads contain per-app policy metadata including detection rules
//! with base64-encoded PowerShell scripts.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};

use super::ime_parser::ImeLine;
use super::models::{AppPolicyMetadata, DetectionRuleMetadata, ReturnCodeEntry};

const GET_POLICIES_PREFIX: &str = "Get policies = ";

/// Extract policy metadata from all "Get policies" lines in a set of parsed log lines.
pub fn extract_policy_metadata(lines: &[ImeLine]) -> HashMap<String, AppPolicyMetadata> {
    let mut result = HashMap::new();

    for line in lines {
        if !line.message.starts_with(GET_POLICIES_PREFIX) {
            continue;
        }

        let json_str = &line.message[GET_POLICIES_PREFIX.len()..];
        let sanitized = sanitize_json(json_str);

        let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&sanitized) else {
            log::warn!(
                "event=policy_parse_fail line={} reason=invalid_json",
                line.line_number
            );
            continue;
        };

        for obj in &arr {
            if let Some(policy) = parse_single_policy(obj) {
                result.insert(policy.id.clone(), policy);
            }
        }
    }

    log::debug!(
        "event=policy_extraction_complete count={}",
        result.len()
    );
    result
}

/// Sanitize JSON that may contain invalid escape sequences (e.g. Windows paths
/// with unescaped backslashes like `\Package` or `\norestart`).
fn sanitize_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                // Valid JSON escape chars: " \ / b f n r t u
                if matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u') {
                    out.push('\\');
                    out.push(next);
                    chars.next(); // consume the valid escape char
                } else {
                    // Invalid escape — double the backslash to make it literal
                    out.push_str("\\\\");
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_single_policy(obj: &serde_json::Value) -> Option<AppPolicyMetadata> {
    let id = obj.get("Id")?.as_str()?.to_string();
    let name = obj
        .get("Name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let intent = obj.get("Intent").and_then(|v| v.as_i64()).map(|v| v as i32);
    let target_type = obj
        .get("TargetType")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let install_command_line = obj
        .get("InstallCommandLine")
        .and_then(|v| v.as_str())
        .map(String::from);
    let uninstall_command_line = obj
        .get("UninstallCommandLine")
        .and_then(|v| v.as_str())
        .map(String::from);
    let install_behavior = obj
        .get("InstallBehavior")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let requirement_rules = obj
        .get("RequirementRules")
        .and_then(|v| v.as_str())
        .map(String::from);

    let detection_rules = parse_detection_rules(obj);
    let return_codes = parse_return_codes(obj);

    Some(AppPolicyMetadata {
        id,
        name,
        intent,
        target_type,
        install_command_line,
        uninstall_command_line,
        detection_rules,
        return_codes,
        requirement_rules,
        install_behavior,
    })
}

/// Parse the nested DetectionRule JSON string.
///
/// The field is a JSON-escaped string containing a JSON array:
/// ```json
/// "DetectionRule": "[{\"DetectionType\":3,\"DetectionText\":\"{...}\"}]"
/// ```
fn parse_detection_rules(obj: &serde_json::Value) -> Vec<DetectionRuleMetadata> {
    let Some(dr_str) = obj.get("DetectionRule").and_then(|v| v.as_str()) else {
        return Vec::new();
    };

    let Ok(rules) = serde_json::from_str::<Vec<serde_json::Value>>(dr_str) else {
        return Vec::new();
    };

    rules
        .iter()
        .filter_map(|rule| {
            let detection_type = rule.get("DetectionType")?.as_i64()? as i32;

            let (script_body, enforce_signature_check, run_as_32_bit) =
                if detection_type == 3 {
                    parse_script_detection_text(rule)
                } else {
                    (None, None, None)
                };

            Some(DetectionRuleMetadata {
                detection_type,
                script_body,
                enforce_signature_check,
                run_as_32_bit,
            })
        })
        .collect()
}

/// Parse DetectionText for script-type rules (DetectionType 3).
///
/// The DetectionText is itself a JSON-escaped string:
/// ```json
/// "{\"EnforceSignatureCheck\":0,\"RunAs32Bit\":0,\"ScriptBody\":\"<base64>\"}"
/// ```
fn parse_script_detection_text(
    rule: &serde_json::Value,
) -> (Option<String>, Option<bool>, Option<bool>) {
    let dt_str = match rule.get("DetectionText").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return (None, None, None),
    };

    let dt: serde_json::Value = match serde_json::from_str(dt_str) {
        Ok(v) => v,
        Err(_) => return (None, None, None),
    };

    let enforce_signature_check = dt
        .get("EnforceSignatureCheck")
        .and_then(|v| v.as_i64())
        .map(|v| v != 0);
    let run_as_32_bit = dt
        .get("RunAs32Bit")
        .and_then(|v| v.as_i64())
        .map(|v| v != 0);

    let script_body = dt
        .get("ScriptBody")
        .and_then(|v| v.as_str())
        .and_then(decode_script_body);

    (script_body, enforce_signature_check, run_as_32_bit)
}

/// Decode a base64-encoded PowerShell script body to UTF-8 text.
fn decode_script_body(encoded: &str) -> Option<String> {
    if encoded.is_empty() {
        return None;
    }
    let bytes = STANDARD.decode(encoded).ok()?;
    Some(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

/// Parse the ReturnCodes JSON string.
///
/// Format: `"[{\"ReturnCode\":0,\"Type\":1},...]"`
fn parse_return_codes(obj: &serde_json::Value) -> Vec<ReturnCodeEntry> {
    let Some(rc_str) = obj.get("ReturnCodes").and_then(|v| v.as_str()) else {
        return Vec::new();
    };

    let Ok(codes) = serde_json::from_str::<Vec<serde_json::Value>>(rc_str) else {
        return Vec::new();
    };

    codes
        .iter()
        .filter_map(|code| {
            let return_code = code.get("ReturnCode")?.as_i64()? as i32;
            let code_type = code.get("Type")?.as_i64()? as i32;
            Some(ReturnCodeEntry {
                return_code,
                code_type,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_line(msg: &str) -> ImeLine {
        ImeLine {
            line_number: 1,
            timestamp: None,
            timestamp_utc: None,
            message: msg.to_string(),
            component: Some("AppWorkload".to_string()),
        }
    }

    #[test]
    fn sanitize_json_fixes_invalid_escapes() {
        let input = r#"{"path":"C:\Program Files\Package Cache\foo"}"#;
        let sanitized = sanitize_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        let path = parsed["path"].as_str().unwrap();
        assert!(path.contains("Program Files"));
        assert!(path.contains("Package Cache"));
    }

    #[test]
    fn sanitize_json_preserves_valid_escapes() {
        let input = r#"{"msg":"line1\nline2","path":"C:\\Users"}"#;
        let sanitized = sanitize_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        assert_eq!(parsed["msg"].as_str().unwrap(), "line1\nline2");
        assert_eq!(parsed["path"].as_str().unwrap(), "C:\\Users");
    }

    #[test]
    fn parse_simple_policy() {
        let json = r#"Get policies = [{"Id":"abc-123","Name":"Test App","Version":1,"Intent":3,"TargetType":2,"DetectionRule":"[{\"DetectionType\":0}]","ReturnCodes":"[{\"ReturnCode\":0,\"Type\":1}]","InstallCommandLine":"setup.exe /s","UninstallCommandLine":"setup.exe /uninstall","InstallBehavior":0}]"#;
        let lines = vec![make_line(json)];
        let result = extract_policy_metadata(&lines);

        assert_eq!(result.len(), 1);
        let policy = result.get("abc-123").unwrap();
        assert_eq!(policy.name, "Test App");
        assert_eq!(policy.intent, Some(3));
        assert_eq!(policy.install_command_line.as_deref(), Some("setup.exe /s"));
        assert_eq!(policy.detection_rules.len(), 1);
        assert_eq!(policy.detection_rules[0].detection_type, 0);
        assert!(policy.detection_rules[0].script_body.is_none());
        assert_eq!(policy.return_codes.len(), 1);
        assert_eq!(policy.return_codes[0].return_code, 0);
        assert_eq!(policy.return_codes[0].code_type, 1);
    }

    #[test]
    fn parse_script_detection_rule() {
        // Base64 of "Write-Host 'Detected'"
        let b64 = STANDARD.encode("Write-Host 'Detected'");
        let json = format!(
            r#"Get policies = [{{"Id":"def-456","Name":"Script App","DetectionRule":"[{{\"DetectionType\":3,\"DetectionText\":\"{{\\\"EnforceSignatureCheck\\\":0,\\\"RunAs32Bit\\\":1,\\\"ScriptBody\\\":\\\"{b64}\\\"}}\"}}]","ReturnCodes":"[]"}}]"#
        );
        let lines = vec![make_line(&json)];
        let result = extract_policy_metadata(&lines);

        assert_eq!(result.len(), 1);
        let policy = result.get("def-456").unwrap();
        assert_eq!(policy.detection_rules.len(), 1);

        let rule = &policy.detection_rules[0];
        assert_eq!(rule.detection_type, 3);
        assert_eq!(
            rule.script_body.as_deref(),
            Some("Write-Host 'Detected'")
        );
        assert_eq!(rule.enforce_signature_check, Some(false));
        assert_eq!(rule.run_as_32_bit, Some(true));
    }

    #[test]
    fn skips_non_policy_lines() {
        let lines = vec![
            make_line("[Win32App] Some other message"),
            make_line("Not a policy line"),
        ];
        let result = extract_policy_metadata(&lines);
        assert!(result.is_empty());
    }

    #[test]
    fn handles_malformed_json_gracefully() {
        let lines = vec![make_line("Get policies = not valid json")];
        let result = extract_policy_metadata(&lines);
        assert!(result.is_empty());
    }

    #[test]
    fn handles_missing_detection_rule_fields() {
        let json = r#"Get policies = [{"Id":"ghi-789","Name":"Minimal App"}]"#;
        let lines = vec![make_line(json)];
        let result = extract_policy_metadata(&lines);

        assert_eq!(result.len(), 1);
        let policy = result.get("ghi-789").unwrap();
        assert!(policy.detection_rules.is_empty());
        assert!(policy.return_codes.is_empty());
    }
}
