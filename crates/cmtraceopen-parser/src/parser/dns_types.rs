use crate::models::log_entry::Severity;

/// Map a numeric DNS QTYPE code to its canonical name.
pub fn qtype_name(code: u32) -> String {
    let name = match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        65281 => "WINS",
        65282 => "WINSR",
        _ => return format!("UNKNOWN({})", code),
    };
    name.to_string()
}

/// Map a numeric DNS RCODE to its canonical name.
pub fn rcode_name(code: u32) -> String {
    let name = match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return format!("RCODE({})", code),
    };
    name.to_string()
}

/// Map an RCODE name to a log severity.
pub fn rcode_to_severity(rcode: &str) -> Severity {
    match rcode {
        "NOERROR" => Severity::Info,
        "NXDOMAIN" => Severity::Warning,
        "SERVFAIL" | "REFUSED" | "FORMERR" => Severity::Error,
        _ => Severity::Warning,
    }
}

/// Decode a DNS query name from wire-format or dotted notation.
///
/// Formats handled:
/// - Wire-format labels: `(3)www(6)google(3)com(0)` → `www.google.com`
/// - Compression pointers: `[C00C](4)home(4)gell(3)one(0)` → `home.gell.one`
/// - Multiple pointers: `[C02B](4)dns3[C00C](4)home(4)gell(3)one(0)` → `dns3.home.gell.one`
/// - Root: `(0)` → `.`
/// - Dotted notation: `.ns1.example.com.` → `ns1.example.com`
/// - Empty: `""` → `""`
pub fn decode_query_name(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    // If the string contains wire-format labels like `(N)label`, decode them.
    if raw.contains('(') {
        return decode_wire_format(raw);
    }

    // Dotted notation: strip leading/trailing dots.
    let trimmed = raw.trim_matches('.');
    trimmed.to_string()
}

/// Decode wire-format DNS name, handling compression pointers `[XXXX]`.
///
/// Compression pointers are stripped; only the following labels are used.
fn decode_wire_format(raw: &str) -> String {
    let mut labels: Vec<String> = Vec::new();

    // We process the string left to right, consuming tokens.
    let mut remaining = raw;

    while !remaining.is_empty() {
        if remaining.starts_with('[') {
            // Compression pointer: skip to the closing `]`
            if let Some(end) = remaining.find(']') {
                remaining = &remaining[end + 1..];
                continue;
            } else {
                // Malformed — consume the rest.
                break;
            }
        }

        if remaining.starts_with('(') {
            // Wire-format label: `(N)label`
            if let Some(close_paren) = remaining.find(')') {
                let len_str = &remaining[1..close_paren];
                if let Ok(len) = len_str.parse::<usize>() {
                    let after_paren = &remaining[close_paren + 1..];
                    if len == 0 {
                        // Root label — signals end of name.
                        break;
                    }
                    // Extract exactly `len` bytes for the label.
                    let label_end = len.min(after_paren.len());
                    let label = &after_paren[..label_end];
                    if !label.is_empty() {
                        labels.push(label.to_string());
                    }
                    remaining = &after_paren[label_end..];
                    continue;
                }
            }
            // Malformed — stop.
            break;
        }

        // Unexpected character — advance by one to avoid an infinite loop.
        remaining = &remaining[1..];
    }

    if labels.is_empty() {
        // `(0)` alone is the root zone.
        if raw.trim() == "(0)" {
            return ".".to_string();
        }
        return String::new();
    }

    labels.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qtype_known() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(6), "SOA");
        assert_eq!(qtype_name(33), "SRV");
        assert_eq!(qtype_name(12), "PTR");
        assert_eq!(qtype_name(5), "CNAME");
        assert_eq!(qtype_name(15), "MX");
        assert_eq!(qtype_name(65281), "WINS");
        assert_eq!(qtype_name(65282), "WINSR");
    }

    #[test]
    fn test_qtype_unknown() {
        assert_eq!(qtype_name(9999), "UNKNOWN(9999)");
    }

    #[test]
    fn test_rcode_known() {
        assert_eq!(rcode_name(0), "NOERROR");
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(rcode_name(2), "SERVFAIL");
        assert_eq!(rcode_name(5), "REFUSED");
    }

    #[test]
    fn test_rcode_unknown() {
        assert_eq!(rcode_name(99), "RCODE(99)");
    }

    #[test]
    fn test_rcode_severity() {
        assert_eq!(rcode_to_severity("NOERROR"), Severity::Info);
        assert_eq!(rcode_to_severity("NXDOMAIN"), Severity::Warning);
        assert_eq!(rcode_to_severity("SERVFAIL"), Severity::Error);
        assert_eq!(rcode_to_severity("REFUSED"), Severity::Error);
        assert_eq!(rcode_to_severity("FORMERR"), Severity::Error);
        assert_eq!(rcode_to_severity("NOTAUTH"), Severity::Warning);
    }

    #[test]
    fn test_decode_wire_format() {
        assert_eq!(decode_query_name("(4)home(4)gell(3)one(0)"), "home.gell.one");
    }

    #[test]
    fn test_decode_wire_format_www() {
        assert_eq!(
            decode_query_name("(3)www(6)google(3)com(0)"),
            "www.google.com"
        );
    }

    #[test]
    fn test_decode_wire_format_root() {
        assert_eq!(decode_query_name("(0)"), ".");
    }

    #[test]
    fn test_decode_dotted() {
        assert_eq!(decode_query_name(".ns1.example.com."), "ns1.example.com");
    }

    #[test]
    fn test_decode_compression_pointer() {
        assert_eq!(
            decode_query_name("[C00C](4)home(4)gell(3)one(0)"),
            "home.gell.one"
        );
    }

    #[test]
    fn test_decode_multiple_compression_pointers() {
        assert_eq!(
            decode_query_name("[C02B](4)dns3[C00C](4)home(4)gell(3)one(0)"),
            "dns3.home.gell.one"
        );
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode_query_name(""), "");
    }
}
