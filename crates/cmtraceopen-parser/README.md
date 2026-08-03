# cmtraceopen-parser

[![Crates.io](https://img.shields.io/crates/v/cmtraceopen-parser.svg)](https://crates.io/crates/cmtraceopen-parser)
[![Docs.rs](https://docs.rs/cmtraceopen-parser/badge.svg)](https://docs.rs/cmtraceopen-parser)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/adamgell/cmtraceopen/blob/main/LICENSE)

Pure-Rust parsing for Windows management and deployment logs — ConfigMgr/SCCM, Intune, CBS, DISM, Panther, MSI, PSADT, and more — with format auto-detection, severity classification, and an embedded Windows error-code database.

This is the parsing engine behind [CMTrace Open](https://cmtraceopen.com), extracted as a standalone crate so it can be used without the desktop app.

## Why this crate

If you are writing anything that reads Windows deployment logs — a CI log summarizer, a custom triage tool, a bulk analyzer over collected diagnostics — the tedious part is not reading the file. It is knowing that ConfigMgr wraps entries in `<![LOG[...]LOG]!>`, that older SCCM logs use `$$<` delimiters, that PSADT and MSI logs each timestamp differently, and that a `0x80070005` in the message means "Access is denied."

This crate does that part.

## Design constraints

The crate is deliberately narrow, which is what makes it reusable:

- **No I/O.** Every entry point takes `&str` or `&[u8]`. You decide where bytes come from.
- **No async runtime**, no `tokio`.
- **No platform lock-in.** No `windows`/`winreg` crates, no Tauri, no `rayon`. Windows *log formats* are parsed anywhere — you can analyze ConfigMgr logs on Linux or macOS.
- **Compiles to `wasm32-unknown-unknown`** as well as native targets.

Dependencies are limited to `serde`, `serde_json`, `regex`, `chrono`, `encoding_rs`, `log`, `thiserror`, and `base64`.

## Install

```bash
cargo add cmtraceopen-parser
```

## Quick start

Parse a log and let the crate pick the format:

```rust
use cmtraceopen_parser::parser::parse_content;
use cmtraceopen_parser::models::log_entry::Severity;

let content = std::fs::read_to_string("CcmExec.log")?;
let (result, parser) = parse_content(&content, "CcmExec.log", content.len() as u64);

println!("format: {:?}", result.format_detected);
println!("{} entries across {} lines", result.entries.len(), result.total_lines);

for entry in result.entries.iter().filter(|e| e.severity == Severity::Error) {
    println!(
        "[{}] {} — {}",
        entry.timestamp_display.as_deref().unwrap_or("no timestamp"),
        entry.component.as_deref().unwrap_or("-"),
        entry.message
    );
}
```

`parse_content` returns a `ParseResult` (entries, detected format, total lines, parse-error count, byte offset for resuming a tail) plus the `ResolvedParser` that was selected.

### Decoding bytes yourself

Windows logs are frequently not UTF-8. The crate exposes the same encoding fallback the app uses:

```rust
use cmtraceopen_parser::parser::{decode_bytes, detect_encoding};

let bytes = std::fs::read("dism.log")?;
let encoding = detect_encoding(&bytes);       // BOM sniffing, UTF-8 → Windows-1252 fallback
let text = decode_bytes(&bytes, encoding)?;
```

### Error-code lookup

Over 700 Windows, Windows Update, BITS, ConfigMgr, Intune, Delivery Optimization, MSI, and PSADT codes are embedded — no network calls:

```rust
use cmtraceopen_parser::error_db::lookup::{detect_error_code_spans, lookup_error_code};

let hit = lookup_error_code("0x80070005");
assert!(hit.found);
println!("{} ({}) — {} [{}]", hit.code_hex, hit.code_decimal, hit.description, hit.category);

// Find codes inside a message, with byte offsets for highlighting:
for span in detect_error_code_spans("Install failed with 0x80070005 after retry") {
    println!("{:?}", span);
}
```

Hex (`0x80070005`), bare hex (`80070005`), unsigned decimal, and signed HRESULT (`-2147024891`) inputs are all accepted.

### Skipping detection

If you already know the format, resolve a parser once and reuse it across chunks:

```rust
use cmtraceopen_parser::parser::{detect, parse_content_with_selection};

let selection = detect::detect_parser("AppEnforce.log", &first_chunk);
let chunk = parse_content_with_selection(&next_chunk, "AppEnforce.log", &selection);
```

## Supported formats

Detection samples the start of the content and selects a parser automatically.

| Format | Typical source |
|--------|----------------|
| CCM | ConfigMgr / SCCM client logs (`<![LOG[...]LOG]!>`) |
| Simple | Older SCCM-style logs (`$$<` delimited) |
| ReportingEvents | Intune Management Extension `ReportingEvents.log` |
| CmtLog | CMTrace Open structured capture logs |
| CBS / DISM / Panther | `CBS.log`, `dism.log`, `setupact.log`, `setuperr.log` |
| MSI | Windows Installer verbose logs |
| PSADT (legacy) | PowerShell App Deployment Toolkit |
| Burn | WiX Burn bootstrapper logs |
| PatchMyPc detection | PatchMyPC detection-script output |
| IntuneMacOs | Intune agent logs on macOS |
| IntuneDeviceInventory | Microsoft Device Inventory Agent logs (`IntuneInventoryHarvesterLog.log`, `InventoryAdaptor.log`, `.log_` rotations) |
| IIS W3C | W3C extended-format web logs |
| DHCP | Windows DHCP Server logs |
| DNS debug | Windows DNS Server debug logs |
| Registry | Exported `.reg` content |
| SecureBootLog | Secure Boot certificate-rotation logs |
| Timestamped / Plain | Any log with, or without, a leading timestamp |

The `DnsAudit` parser *kind* exists in the shared models, but DNS audit logs arrive as binary `.evtx`. EVTX decoding is native-only and lives in the CMTrace Open app, not in this crate.

## Beyond the log viewer

The crate also carries the pure-analysis layers the app builds on top of parsing, each usable independently:

| Module | Contents |
|--------|----------|
| `parser` | Format detection, per-format parsers, encoding helpers |
| `models` | `LogEntry`, `ParseResult`, `Severity`, `FilterCriteria`, parser metadata |
| `error_db` | Embedded error-code database, lookup, in-message span detection |
| `intune` | IME event extraction and timeline reduction |
| `esp` | Autopilot Enrollment Status Page evidence normalization, reduction, and redaction |
| `dsregcmd` | `dsregcmd /status` output parsing and diagnostic rules |
| `collector` | Diagnostic-collection profile models and environment-variable expansion |

## Versioning

`0.x` — the public API may change in minor releases while it settles. Pin an exact version if you need stability.

## License

MIT. See [LICENSE](https://github.com/adamgell/cmtraceopen/blob/main/LICENSE).

## Disclaimer

CMTrace is a tool developed and distributed by Microsoft Corporation. CMTrace Open and this crate are an independent open-source project, **not** affiliated with, endorsed by, or connected with Microsoft Corporation.
