use std::env;

/// Expand Windows-style `%VARNAME%` environment variable tokens in a path string.
///
/// Performs case-insensitive matching so `%systemroot%` and `%SystemRoot%` both
/// resolve correctly. Returns the path with all recognised tokens replaced by
/// their runtime values. Unknown or unset variables are left as-is.
pub fn expand_env_vars(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Collect the variable name up to the closing '%'.
            let mut var_name = String::new();
            let mut found_close = false;
            for next in chars.by_ref() {
                if next == '%' {
                    found_close = true;
                    break;
                }
                var_name.push(next);
            }

            if found_close && !var_name.is_empty() {
                if let Some(value) = resolve_env_var(&var_name) {
                    result.push_str(&value);
                } else {
                    // Unknown variable — keep the original token.
                    result.push('%');
                    result.push_str(&var_name);
                    result.push('%');
                }
            } else {
                // Unmatched '%' or empty — keep literal.
                result.push('%');
                result.push_str(&var_name);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Case-insensitive lookup of well-known Windows environment variables.
///
/// We try the exact name first, then the uppercase form, to handle variations
/// like `%systemroot%` vs `%SystemRoot%`.
fn resolve_env_var(name: &str) -> Option<String> {
    // Try exact case first.
    if let Ok(val) = env::var(name) {
        return Some(val);
    }
    // Try uppercase (handles %systemroot% → SYSTEMROOT on Windows).
    let upper = name.to_uppercase();
    if upper != name {
        if let Ok(val) = env::var(&upper) {
            return Some(val);
        }
    }
    // Common aliases: WINDIR and SystemRoot are interchangeable on Windows.
    match upper.as_str() {
        "SYSTEMROOT" => env::var("WINDIR").ok(),
        "WINDIR" => env::var("SystemRoot")
            .ok()
            .or_else(|| env::var("SYSTEMROOT").ok()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_when_no_tokens() {
        let input = "C:\\Windows\\System32\\cmd.exe";
        assert_eq!(expand_env_vars(input), input);
    }

    #[test]
    fn expands_known_variable() {
        // This test will work on any platform because we set the var ourselves.
        unsafe { env::set_var("CMTRACE_TEST_VAR", "hello") };
        let result = expand_env_vars("%CMTRACE_TEST_VAR%\\world");
        assert_eq!(result, "hello\\world");
        unsafe { env::remove_var("CMTRACE_TEST_VAR") };
    }

    #[test]
    fn preserves_unknown_variable() {
        let result = expand_env_vars("%VERY_UNLIKELY_VAR_NAME_XYZ%\\foo");
        assert_eq!(result, "%VERY_UNLIKELY_VAR_NAME_XYZ%\\foo");
    }

    #[test]
    fn handles_unmatched_percent() {
        let result = expand_env_vars("50% complete");
        // The "% complete" part has no closing %, so it stays literal.
        assert_eq!(result, "50% complete");
    }
}
