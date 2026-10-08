# Issue 814 synthetic parser investigation

These fixtures were authored from scratch for the explicitly authorized synthetic
investigation of [issue #814](https://github.com/adamgell/cmtraceopen/issues/814).
No private log was acquired, read, copied, sanitized, or transformed in this task.
Only a privacy-safe schema summary from the parent investigation informed the
Windows Firewall field names, header forms, and boundary-case categories.

Every traffic record, date, time, address, port, packet value, PID, request path,
and user agent is invented. IPv4 addresses use the documentation networks
192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24; IPv6 uses 2001:db8::/32.
The dates in 2042 are deliberately unrelated to any capture. These are format
examples, not captured traffic or a sanitized version of another file.

`firewall-local-18-fields.log` has a version 1.5 Windows Firewall header, a Local
time directive, and three independently invented TCP/UDP/ICMP records covering
ALLOW/DROP, IPv4/IPv6, ports, hyphens, SEND/RECEIVE, and PID values/missing markers.
Tests derive the 17-field variant by dropping the final field from this synthetic
file only, and generate CRLF and small boundary inputs in memory.

The additional cases are authored in the integration test: a numeric protocol
(`47`), a 17-field INFO-EVENTS-LOST row with an invented count (`23`) in `info`
and no trailing PID, a truly truncated ordinary row, repeated/reordered/missing
headers, and repeated Local wall-clock values shaped like a DST ambiguity. No
source timezone or future DST rule is asserted. NUL prefix lengths of 1 byte,
4 KiB, and 1 MiB are generated in memory; they do not reproduce a capture's byte
count. Tests distinguish a prefix attached to the first date from a separate
NUL-only line. No megabyte-scale fixture is checked in.

`iis-w3c-control.log` is also synthetic. Its genuine IIS W3C *format* is the
negative control: HTTP methods, paths, status codes, and client/server fields
must continue to work. It is not an IIS capture.

The acceptance integration test `issue_814_firewall.rs` uses the normal
`cmtraceopen_parser::parser::parse_content` entry point. `firewall_records.rs`
checks the pure record grammar; `firewall_model.rs` checks the optional wire model.
The implementation extends only these synthetic examples for schema, framing,
encoding and lifecycle boundary tests. Large padding and encoded variants are
generated in memory or temporary test files, never copied from a capture.

The original investigation at commit
`497a7a06a882eaad886ea25ba11ac8a301e16630` observed three firewall rows becoming
IIS messages (`- - → -`) with zero parse errors. Its 15 passing characterization
tests and separately failing prospective acceptance probe remain in task-private
evidence. Those defect-preserving assertions are replaced by desired acceptance
requirements as the approved implementation proceeds.

Pure parser and adapter tests are not native UI acceptance. Any Windows-native
acceptance report must name the exact code run there. No private capture is used.

The browser regression `e2e/firewall-log.spec.ts` uses invented TypeScript payloads
and the Tauri test shim. It exercises source loading, Local wall-clock display,
ordered fields/raw copy, coverage, idempotent full-row replacement, empty reset,
and timeline exclusion/changed-source notices. `CMTRACE_E2E_MOCK_ONLY=1` blocks
the optional native IPC bridge for the entire browser suite. Browser success is
not native Windows UI acceptance. NUL coverage counts decoded characters, not
raw UTF-16 bytes; undecoded suffix coverage counts actual retained bytes.
