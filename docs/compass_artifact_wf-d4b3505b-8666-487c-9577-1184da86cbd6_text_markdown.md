# Windows Server DNS logging: a complete Rust parser reference

Every DNS event Windows Server produces falls into one of four distinct log formats, each requiring a different parsing strategy. **No existing Rust crate handles the DNS debug text log format**, making a from-scratch parser necessary, but the ecosystem provides strong building blocks for EVTX (`evtx` crate v0.11.1), DNS wire format (`hickory-proto`), and real-time ETW capture (`ferrisetw`). This reference documents every field, format variation, event ID, and protocol constant needed to build a comprehensive Rust DNS log parser.

---

## 1. DNS debug log (dns.log) text format

The debug log is a locale-sensitive, whitespace-delimited text file produced by `dns.exe`. It starts with a ~30-line header (including a field key), followed by packet entries separated by blank lines.

### Line structure and fields

Each packet event produces a single summary line with 16 fields. The header printed in the log file itself defines them:

| Field # | Name | Format | Example |
|---------|------|--------|---------|
| 1 | Date | Locale-dependent (see below) | `4/15/2014`, `22/12/2021`, `20140816` |
| 2 | Time | 12h with AM/PM or 24h | `3:16:00 PM`, `21:46:04` |
| 3 | Thread ID | 3-4 hex chars | `0710`, `588` |
| 4 | Context | String literal | `PACKET` (always for DNS packets) |
| 5 | Internal packet ID | 8 hex (32-bit) or 16 hex (64-bit) | `0000000028FB94C0` |
| 6 | Protocol | `UDP` or `TCP` | `UDP` |
| 7 | Direction | `Snd` or `Rcv` | `Rcv` |
| 8 | Remote IP | IPv4 or IPv6 | `69.160.33.71`, `::1` |
| 9 | XID | 4 hex chars (transaction ID) | `8857` |
| 10 | Query/Response | `R` = response, space = query | `R` or ` ` |
| 11 | Opcode | `Q`=Query, `N`=Notify, `U`=Update, `?`=Unknown | `Q` |
| 12 | Flags (hex) | 4-digit hex inside `[` | `8081` |
| 13 | Flags (chars) | Up to 4 letters: A/T/D/R | `DR` |
| 14 | Response code | String name inside `]` | `NOERROR`, `NXDOMAIN` |
| 15 | Question type | String name | `A`, `AAAA`, `SRV` |
| 16 | Question name | Length-prefixed or dotted | `(3)www(6)google(3)com(0)` |

**Sample lines showing format variations:**

```
4/15/2014 3:16:00 PM 0710 PACKET  0000000028FB94C0 UDP Rcv 69.160.33.71    8857 R Q [0080       NOERROR] A      .ns1.example.com.
22/12/2021 21:46:04 0E1C PACKET  0000017DEDFE28D0 UDP Rcv 10.20.0.6       966f   Q [0001   D   NOERROR] A      (5)login(4)live(3)com(0)
20140816 16:08:57 588 PACKET  019B99F0 UDP Rcv 192.168.0.2 80fd   Q [0001   D   NOERROR] A     (3)www(6)google(3)com(0)
```

### The timestamp problem is the hardest parsing challenge

The date format follows the OS locale of the DNS service account, not a fixed format. Three known variants exist:

- **US locale:** `M/d/yyyy h:mm:ss tt` — e.g., `4/15/2014 3:16:00 PM` (no leading zeros, 12-hour with AM/PM)
- **EU locale:** `dd/MM/yyyy HH:mm:ss` — e.g., `22/12/2021 21:46:04` (leading zeros, 24-hour, no AM/PM)
- **ISO-style (older servers):** `yyyyMMdd HH:mm:ss` — e.g., `20140816 16:08:57`

**MM/DD and DD/MM are indistinguishable without context.** A robust parser should auto-detect or accept configuration.

### Comprehensive regex pattern for Rust

```regex
^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?|\d{8}\s+\d{2}:\d{2}:\d{2})\s+([0-9A-Fa-f]{3,4})\s+PACKET\s+([0-9A-Fa-f]{8,16})\s+(UDP|TCP)\s+(Snd|Rcv)\s+([0-9a-fA-F.:]+)\s+([0-9a-fA-F]{4})\s+([R ])\s*([QNU?])\s+\[([0-9A-Fa-f]{4})\s+([ATDR ]{1,4})\s+(\w+)\]\s+(\S+)\s+(.+)$
```

The flags section `[HHHH CCCC RCODE]` should be matched as a unit and parsed internally, since the character flags occupy variable positions with internal whitespace.

### Query name encoding

Two formats appear depending on Windows Server version:

**Wire-format style** (most common): `(3)www(6)google(3)com(0)` — each `(N)` gives the label length in decimal, terminated by `(0)`. Convert by replacing `(\d+)` captures with dots and stripping the leading dot.

**Dotted style** (older servers): `.ns1.example.com.` — standard FQDN with leading dot.

**Compression pointers** in detailed output: `[C00C](3)www(6)google(3)com(0)` — the `[C00C]` is a 2-byte DNS wire-format pointer to offset 0x0C.

### Multi-line detail format

When "Details" logging is enabled, each summary line is followed by a decoded packet dump including `Remote addr X.X.X.X, port NNNNN` (the **only** place port numbers appear), buffer/message lengths, and full DNS message decode with question, answer, authority, and additional sections. The detail section shows QTYPE as both name and number: `QTYPE A (1)`.

### Edge cases to handle

- **Blank lines** between entries must be skipped
- **Header** (~30 lines) at file start; detect via absence of `PACKET` keyword
- **Log file wrap** lines: `"Log file wrap at..."` appear when max size is reached
- **Windows line endings** (`\r\n`) throughout
- **Variable whitespace** between fields; use whitespace splitting, not fixed positions
- **The `R` vs space ambiguity**: the query/response field is a single character — `R Q` means "Response, Standard Query" while `  Q` (space-Q) means just "Standard Query"
- **IPv6 addresses** in the remote IP field (e.g., `::1`, `fe80::1`)
- **Non-PACKET context**: the context field can be `EVENT` for non-packet events

---

## 2. DNS analytical event log (Event IDs 256–280)

The analytical channel (`Microsoft-Windows-DNSServer/Analytical`) is ETW-based, stored as `.etl` files (not standard EVTX), and captures query-level DNS telemetry. **Event ID 256 is undocumented by Microsoft** but universally observed.

### Complete event ID registry

| ID | Name | Keyword Bit | Level | Direction |
|----|------|------------|-------|-----------|
| 256 | QUERY_RECEIVED | 0x01 | Info | Inbound query from client |
| 257 | RESPONSE_SUCCESS | 0x02 | Info | Successful response to client |
| 258 | RESPONSE_FAILURE | 0x04 | Error | Failed response to client |
| 259 | IGNORED_QUERY | 0x08 | Error | Query dropped/ignored |
| 260 | RECURSE_QUERY_OUT | 0x10 | Info | Recursive query to upstream |
| 261 | RECURSE_RESPONSE_IN | 0x20 | Info | Recursive response from upstream |
| 262 | RECURSE_QUERY_TIMEOUT | 0x40 | Error | Recursive query timed out |
| 263 | DYN_UPDATE_RECV | 0x80 | Info | Dynamic update received |
| 264 | DYN_UPDATE_RESPONSE | 0x100 | Info | Dynamic update response sent |
| 265 | IXFR_REQ_OUT | 0x200 | Info | IXFR request sent |
| 266 | IXFR_REQ_RECV | 0x400 | Info | IXFR request received |
| 267 | IXFR_RESP_OUT | 0x800 | Info | IXFR response sent |
| 268 | IXFR_RESP_RECV | 0x1000 | Info | IXFR response received |
| 269 | AXFR_REQ_OUT | 0x2000 | Info | AXFR request sent |
| 270 | AXFR_REQ_RECV | 0x4000 | Info | AXFR request received |
| 271 | AXFR_RESP_OUT | 0x8000 | Info | AXFR response sent |
| 272 | AXFR_RESP_RECV | 0x10000 | Info | AXFR response received |
| 273 | XFR_NOTIFY_RECV | 0x20000 | Info | Zone transfer notify received |
| 274 | XFR_NOTIFY_OUT | 0x40000 | Info | Zone transfer notify sent |
| 275 | XFR_NOTIFY_ACK_IN | 0x80000 | Info | Notify acknowledgment received |
| 276 | XFR_NOTIFY_ACK_OUT | 0x100000 | Info | Notify acknowledgment sent |
| 277 | DYN_UPDATE_FORWARD | 0x200000 | Info | Dynamic update forwarded |
| 278 | DYN_UPDATE_RESPONSE_IN | 0x400000 | Info | Dynamic update response received |
| 279 | INTERNAL_LOOKUP_CNAME | 0x800000 | Info | Internal CNAME chase lookup |
| 280 | INTERNAL_LOOKUP_ADDITIONAL | 0x1000000 | Info | Internal additional-section lookup |

### EventData fields per event ID

**Event 256 (QUERY_RECEIVED):**
`TCP`, `InterfaceIP`, `Source`, `RD`, `QNAME`, `QTYPE`, `XID`, `Port`, `Flags`, `BufferSize`, `PacketData`, `AdditionalInfo`

**Event 257 (RESPONSE_SUCCESS):**
`TCP`, `InterfaceIP`, `Destination`, `AA`, `AD`, `QNAME`, `QTYPE`, `XID`, `DNSSEC`, `RCODE`, `Port`, `Flags`, `Scope`, `Zone`, `PolicyName`, `PacketData`

**Event 258 (RESPONSE_FAILURE):**
`TCP`, `InterfaceIP`, `Reason`, `Destination`, `QNAME`, `QTYPE`, `XID`, `RCODE`, `Port`, `Flags`, `Zone`, `PolicyName`, `PacketData`

**Event 259 (IGNORED_QUERY):**
`TCP`, `InterfaceIP`, `Reason`, `QNAME`, `QTYPE`, `XID`, `Zone`, `PolicyName` — notably minimal, no IP/port/packet fields.

**Events 260 (RECURSE_QUERY_OUT):**
`TCP`, `Destination`, `InterfaceIP`, `RD`, `QNAME`, `QTYPE`, `XID`, `Port`, `Flags`, `ServerScope`, `CacheScope`, `PolicyName`, `PacketData`

**Event 261 (RECURSE_RESPONSE_IN):**
`TCP`, `Source`, `InterfaceIP`, `AA`, `AD`, `QNAME`, `QTYPE`, `XID`, `Port`, `Flags`, `ServerScope`, `CacheScope`, `PacketData`

**Event 262 (RECURSE_QUERY_TIMEOUT):**
`TCP`, `InterfaceIP`, `Destination`, `QNAME`, `QTYPE`, `XID`, `Port`, `Flags`, `ServerScope`, `CacheScope` — no `PacketData`.

**Events 263 (DYN_UPDATE_RECV):**
`TCP`, `InterfaceIP`, `Source`, `QNAME`, `XID`, `Port`, `Flags`, `SECURE`, `PacketData` — unique `SECURE` field indicates TSIG/GSS-TSIG. No `QTYPE`.

**Event 264 (DYN_UPDATE_RESPONSE):**
`TCP`, `InterfaceIP`, `Destination`, `QNAME`, `XID`, `ZoneScope`, `Zone`, `RCODE`, `PolicyName`, `PacketData`

**Events 265-268 (IXFR):**
`TCP`, `InterfaceIP`/`Source`, `QNAME`, `XID`, `ZoneScope`, `Zone`, `PacketData`. Response variants (267-268) add `Destination` and `RCODE`.

**Events 269-272 (AXFR):**
Same pattern as IXFR but **AXFR response events (271-272) lack `PacketData`**.

**Events 273-274 (XFR_NOTIFY):**
`Source`/`Destination`, `InterfaceIP`, `QNAME`, `ZoneScope`, `Zone`, `PacketData` — no `TCP` field.

**Events 275-276 (XFR_NOTIFY_ACK):**
Minimal — just `Source`/`Destination`, `InterfaceIP`, `PacketData` (276 adds `Zone`).

**Event 277 (DYN_UPDATE_FORWARD):**
`TCP`, `ForwardInterfaceIP` (unique field name), `Destination`, `QNAME`, `XID`, `ZoneScope`, `Zone`, `RCODE`, `PacketData`

**Events 279-280 (INTERNAL_LOOKUP):**
`TCP`, `InterfaceIP`, `Source`, `RD`, `QNAME`, `QTYPE`, `Port`, `Flags`, `XID`, `PacketData` — mirrors Event 256's structure.

### Key parsing notes for analytical events

All field values are strongly typed in the ETW schema: `TCP` is `UInt32` (0/1), `QTYPE` is `UInt32` (numeric code, not name), `RCODE` is `UInt32`, IP fields are `UnicodeString`, `PacketData` is hex-encoded binary (`0x...` prefix). The `PacketData` field contains the **raw DNS wire-format payload** identical to what appears after the UDP header in a packet capture.

The Keywords value in each event's System section combines the event keyword with `0x8000000000000000` (the analytical channel bit). For example, Event 256 shows `Keywords=0x8000000000000001`.

---

## 3. DNS audit event log (Event IDs 513–582)

The audit channel (`Microsoft-Windows-DNSServer/Audit`) is a standard EVTX event log, enabled by default with minimal performance impact.

### Complete audit event ID table

**Zone and record operations (513-521):**

| ID | Operation | Key EventData Fields |
|----|-----------|---------------------|
| 513 | Zone delete | `Zone` |
| 514 | Zone setting updated | `Zone`, `Setting`, `NewValue` |
| 515 | Record create | `Type`, `NAME`, `TTL`, `BufferSize`, `RDATA`, `Zone`, `ZoneScope`, `VirtualizationID` |
| 516 | Record delete | Same as 515 |
| 517 | RRSET delete | `Type`, `NAME`, `Zone`, `ZoneScope` |
| 518 | Node delete | `NodeName`, `Zone`, `ZoneScope` |
| 519 | Record create (dynamic update) | Same as 515 + `SourceIP` |
| 520 | Record delete (dynamic update) | Same as 515 + `SourceIP` |
| 521 | Record scavenge | Same as 515 |

The `Type` field is the DNS RR type number (1=A, 28=AAAA, etc.). The `RDATA` field contains hex-encoded binary data (e.g., `0x0A00020F` for IP 10.0.2.15).

**Zone scope and DNSSEC (522-537):**

| ID | Operation |
|----|-----------|
| 522-523 | Zone scope create/delete |
| 525-527 | Zone sign/unsign/re-sign |
| 528-531 | DNSSEC key rollover start/end/retire/triggered |
| 533 | Key poke rollover (Level=Warning) |
| 534-535 | DNSSEC export/import |
| 536 | Cache purge |
| 537 | Forwarder reset |

**Server configuration (540-560):**

| ID | Operation | Notable Fields |
|----|-----------|----------------|
| 540 | Root hints update | |
| 541 | Server setting change | `Setting`, `Scope`, `Value` — key for detecting `serverlevelplugindll` modifications |
| 542-543 | Server scope create/delete | |
| 544-546 | Trust anchor DNSKEY/DS add/remove | `TrustPoint`, `KeyProtocol`, `CryptoAlgorithm`, `Base64Data` |
| 547-550 | Trust point root/restart/clear debug/write zones | |
| 551-560 | Statistics, scavenging, demotion, listen address, pause/resume zone | |

**Extended operations (561-582):**

| ID | Operation |
|----|-----------|
| 561-568 | Reload/refresh/expire zone, update from DS, write and notify, force aging, scavenge servers, transfer key |
| 569-572 | SKD (Signing Key Descriptor) add/modify/delete/state change — extensive DNSSEC key fields |
| 573 | Add delegation |
| 574-576 | Client subnet record create/delete/update |
| 577-579 | Policy create (server-level/zone-level/forwarding) — fields include `ProcessingOrder`, `Criteria`, `Action`, `PolicyName`, `Scopes` |
| 580-582 | Policy delete (server-level/zone-level/forwarding) |

### Audit event XML structure

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DNSServer" 
              Guid="{EB79061A-A566-4698-9119-3ED2807060E7}" />
    <EventID>515</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>5</Task>
    <Keywords>0x4000000000000000</Keywords>
    <Channel>Microsoft-Windows-DNSServer/Audit</Channel>
  </System>
  <EventData>
    <Data Name="Type">1</Data>
    <Data Name="NAME">test.homelab.local</Data>
    <Data Name="TTL">3600</Data>
    <Data Name="BufferSize">4</Data>
    <Data Name="RDATA">0x01010101</Data>
    <Data Name="Zone">homelab.local</Data>
    <Data Name="ZoneScope">Default</Data>
    <Data Name="VirtualizationID">.</Data>
  </EventData>
</Event>
```

The `Keywords` value `0x4000000000000000` is the audit channel selector bit.

---

## 4. ETW provider and trace configuration

### Provider identity

- **Provider Name:** `Microsoft-Windows-DNSServer`
- **Provider GUID:** `{EB79061A-A566-4698-9119-3ED2807060E7}`
- **Binary:** `C:\Windows\System32\dns.exe` (manifest embedded in this binary)
- **Distinct from:** `Microsoft-Windows-DNS-Server-Service` (`{71A551F5-C893-4849-886B-B5EC8502641E}`) — a different, older provider

### Trace levels

| Value | Name | Use |
|-------|------|-----|
| 0 | None | Logging off |
| 1 | Critical | Process exit/termination only |
| 2 | Error | Severe failures |
| 3 | Warning | Recoverable errors |
| 4 | Informational | High-level operational events |
| 5 | Verbose | Complete event stream |

### Complete keyword bitmask reference

**Analytical keywords (bits 0-24):**

| Bit | Keyword | Events |
|-----|---------|--------|
| 0x0000000000000001 | QUERY_RECEIVED | 256 |
| 0x0000000000000002 | RESPONSE_SUCCESS | 257 |
| 0x0000000000000004 | RESPONSE_FAILURE | 258 |
| 0x0000000000000008 | IGNORED_QUERY | 259 |
| 0x0000000000000010 | RECURSE_QUERY_OUT | 260 |
| 0x0000000000000020 | RECURSE_RESPONSE_IN | 261 |
| 0x0000000000000040 | RECURSE_QUERY_DROP | 262 |
| 0x0000000000000080 | DYN_UPDATE_RECV | 263 |
| 0x0000000000000100 | DYN_UPDATE_RESPONSE | 264 |
| 0x0000000000000200 | IXFR_REQ_OUT | 265 |
| 0x0000000000000400 | IXFR_REQ_RECV | 266 |
| 0x0000000000000800 | IXFR_RESP_OUT | 267 |
| 0x0000000000001000 | IXFR_RESP_RECV | 268 |
| 0x0000000000002000 | AXFR_REQ_OUT | 269 |
| 0x0000000000004000 | AXFR_REQ_RECV | 270 |
| 0x0000000000008000 | AXFR_RESP_OUT | 271 |
| 0x0000000000010000 | AXFR_RESP_RECV | 272 |
| 0x0000000000020000 | XFR_NOTIFY_IN | 273 |
| 0x0000000000040000 | XFR_NOTIFY_OUT | 274 |
| 0x0000000000800000 | INTERNAL_LOOKUP_CNAME | 279 |
| 0x0000000001000000 | INTERNAL_LOOKUP_ADDITIONAL | 280 |

**Audit keywords (selected):**

| Bit | Keyword |
|-----|---------|
| 0x0000000000080000 | AUDIT_ZONES |
| 0x0000000000100000 | AUDIT_REC_ADMIN |
| 0x0000000000200000 | AUDIT_ZONESCOPE |
| 0x0000000000400000 | AUDIT_ZONE_SIGN |
| 0x0000000000800000 | AUDIT_ROLLOVER |
| 0x0000000002000000 | AUDIT_REC_DYN_UPDATE |
| 0x0000000008000000 | AUDIT_SERVER_CONFIG |
| 0x0000000020000000 | AUDIT_EXPORT_IMPORT |
| 0x0000000100000000 | AUDIT_TRUST_ANCHOR |
| 0x0000020000000000 | AUDIT_POLICY |
| 0x0000200000000000 | AUDIT_RRL |

**Channel selector bits:**

| Bit | Channel |
|-----|---------|
| 0x8000000000000000 | Analytical channel |
| 0x4000000000000000 | Audit channel |

**Common masks:** `0x7FFFF` captures all base analytical events (bits 0-18). `0xFFFFFFFFFFFFFFFF` captures everything. Note that `0xFFFFFFFF` (32-bit) misses extended keywords above bit 31.

### Capture commands

```bash
# logman (built-in)
logman create trace DnsTrace -p "Microsoft-Windows-DNSServer" 0xFFFFFFFF 5 -o C:\dns.etl
logman start DnsTrace

# tracelog.exe (WDK)
tracelog.exe -start Dns -guid #{EB79061A-A566-4698-9119-3ED2807060E7} -level 5 -matchanykw 0x7FFFF -f C:\analytical.etl
```

### Critical architecture detail

The analytical channel stores data as `.etl` (Event Trace Log), **not** `.evtx`. It cannot be read with standard Windows Event Log APIs in real-time. The audit channel is standard EVTX. Both originate from the same ETW provider — the channel keyword bits (62-63) route events to the appropriate channel.

---

## 5. QTYPE values: complete mapping

### Standard types (RFC 1035 and extensions)

| Code | Name | Description |
|------|------|-------------|
| 1 | A | IPv4 address |
| 2 | NS | Name server |
| 3 | MD | Mail destination (obsolete) |
| 4 | MF | Mail forwarder (obsolete) |
| 5 | CNAME | Canonical name/alias |
| 6 | SOA | Start of authority |
| 7 | MB | Mailbox (experimental) |
| 8 | MG | Mail group (experimental) |
| 9 | MR | Mail rename (experimental) |
| 10 | NULL | Null RR (experimental) |
| 11 | WKS | Well-known service |
| 12 | PTR | Pointer/reverse lookup |
| 13 | HINFO | Host information |
| 14 | MINFO | Mailbox info |
| 15 | MX | Mail exchange |
| 16 | TXT | Text strings |
| 17 | RP | Responsible person |
| 18 | AFSDB | AFS database |
| 24 | SIG | Security signature (legacy) |
| 25 | KEY | Security key (legacy) |
| 28 | AAAA | IPv6 address |
| 29 | LOC | Geographic location |
| 33 | SRV | Service locator |
| 35 | NAPTR | Naming authority pointer |
| 36 | KX | Key exchanger |
| 37 | CERT | Certificate |
| 39 | DNAME | Delegation name |
| 41 | OPT | EDNS pseudo-RR |
| 43 | DS | Delegation signer |
| 44 | SSHFP | SSH fingerprint |
| 45 | IPSECKEY | IPsec key |
| 46 | RRSIG | DNSSEC signature |
| 47 | NSEC | Next secure |
| 48 | DNSKEY | DNS key |
| 49 | DHCID | DHCP identifier |
| 50 | NSEC3 | Next secure v3 |
| 51 | NSEC3PARAM | NSEC3 parameters |
| 52 | TLSA | DANE certificate |
| 53 | SMIMEA | S/MIME certificate |
| 55 | HIP | Host identity protocol |
| 59 | CDS | Child DS |
| 60 | CDNSKEY | Child DNSKEY |
| 61 | OPENPGPKEY | OpenPGP key |
| 64 | SVCB | Service binding |
| 65 | HTTPS | HTTPS service binding |
| 99 | SPF | Sender policy framework |
| 249 | TKEY | Transaction key |
| 250 | TSIG | Transaction signature |
| 251 | IXFR | Incremental zone transfer |
| 252 | AXFR | Full zone transfer |
| 255 | ANY/\* | All records |
| 256 | URI | Uniform resource identifier |
| 257 | CAA | Certification authority authorization |

### Windows-specific types (private use range)

| Code | Name | Description |
|------|------|-------------|
| **65281** (0xFF01) | WINS | WINS forward lookup (Microsoft proprietary) |
| **65282** (0xFF02) | WINSR | WINS reverse lookup (Microsoft proprietary) |

**In the debug log, QTYPE appears as a name string** (`A`, `AAAA`, `SRV`). In the detail section, it shows both: `QTYPE A (1)`. **In analytical events, QTYPE is numeric** (`UInt32`).

---

## 6. RCODE values: complete mapping

| Code | Name | Description |
|------|------|-------------|
| 0 | NOERROR | Successful query |
| 1 | FORMERR | Format error |
| 2 | SERVFAIL | Server failure |
| 3 | NXDOMAIN | Domain does not exist |
| 4 | NOTIMP | Not implemented |
| 5 | REFUSED | Query refused |
| 6 | YXDOMAIN | Name exists when it should not |
| 7 | YXRRSET | RR set exists when it should not |
| 8 | NXRRSET | RR set does not exist when it should |
| 9 | NOTAUTH | Not authoritative / not authorized |
| 10 | NOTZONE | Name not in zone |
| 16 | BADVERS/BADSIG | Bad OPT version (EDNS) or TSIG signature failure |
| 17 | BADKEY | Key not recognized |
| 18 | BADTIME | Signature out of time window |
| 19 | BADMODE | Bad TKEY mode |
| 20 | BADNAME | Duplicate key name |
| 21 | BADALG | Algorithm not supported |
| 22 | BADTRUNC | Bad truncation |
| 23 | BADCOOKIE | Bad/missing server cookie |

**Code 16 has dual meaning**: BADVERS in EDNS OPT context, BADSIG in TSIG/TKEY context. In debug logs, RCODE appears as a **name string** (`NOERROR`, `NXDOMAIN`). In the Windows debug log, NOTIMP may appear as `NOTIMPL`. In analytical events, RCODE is a **UInt32** numeric code.

---

## 7. DNS wire format and hex packet data

### DNS message structure (RFC 1035)

```
Bytes 0-1:   ID        (16-bit transaction ID = XID in debug log)
Bytes 2-3:   Flags     (16-bit = hex flags in debug log)
Bytes 4-5:   QDCOUNT   (number of questions)
Bytes 6-7:   ANCOUNT   (number of answers)
Bytes 8-9:   NSCOUNT   (number of authority RRs)
Bytes 10-11: ARCOUNT   (number of additional RRs)
Byte 12+:    Question section, then Answer/Authority/Additional RRs
```

### Question section encoding

Each question is: `QNAME` (length-prefixed labels terminated by 0x00) + `QTYPE` (2 bytes big-endian) + `QCLASS` (2 bytes, 0x0001 = IN).

Example for `www.google.com`: `03 77 77 77 06 67 6F 6F 67 6C 65 03 63 6F 6D 00 00 01 00 01`

### Name compression pointers

When the two high bits of a label length byte are both 1 (byte ≥ 0xC0), the remaining 14 bits form an offset from the message start. **`0xC00C`** (pointer to offset 12) is the most common, pointing to the QNAME in the question section.

### PacketData in analytical events

The `PacketData` field in ETW analytical events (e.g., Event 256/257) contains the **raw DNS wire-format payload** prefixed with `0x`. It is byte-for-byte identical to the DNS payload captured in a packet trace. Parse it directly with any DNS wire-format library (`hickory-proto::op::Message::from_vec()`).

---

## 8. DNS header flags bitmap

```
Bit 15 (MSB): QR     — 0=Query, 1=Response
Bits 14-11:   Opcode — 0=QUERY, 4=NOTIFY, 5=UPDATE
Bit 10:       AA     — Authoritative Answer
Bit 9:        TC     — Truncation
Bit 8:        RD     — Recursion Desired
Bit 7:        RA     — Recursion Available
Bit 6:        Z      — Reserved (must be 0)
Bit 5:        AD     — Authentic Data (DNSSEC)
Bit 4:        CD     — Checking Disabled (DNSSEC)
Bits 3-0:     RCODE  — Response code (4-bit)
```

**Debug log hex flags decode examples:**
- `0x0001` → QR=0, RD=1 (query with recursion desired) → char flags: `D`
- `0x8081` → QR=1, RD=1, RA=1 (response, recursion available) → char flags: `DR`
- `0x8385` → QR=1, AA=1, RD=1, RA=1, RCODE=5 → char flags: `A DR`, RCODE=REFUSED
- `0x8180` → QR=1, RD=1, RA=1 (standard recursive response) → char flags: `DR`

The debug log char codes map: **A**=AA, **T**=TC, **D**=RD, **R**=RA. These appear between the hex flags and the RCODE name inside the square brackets.

---

## 9. Rust implementation strategy and available crates

### Recommended crate stack

| Component | Crate | Version | Purpose |
|-----------|-------|---------|---------|
| EVTX parsing | **`evtx`** (omerbenamram) | 0.11.1 | Parse offline EVTX audit logs; production-grade, used by Hayabusa and Chainsaw |
| DNS wire format | **`hickory-proto`** | 0.25.x | Decode `PacketData` hex fields from analytical events; `Message::from_vec()` |
| Lighter DNS alternative | **`simple-dns`** | 0.9.x | Smaller dependency; `Packet::parse(bytes)` |
| Real-time ETW | **`ferrisetw`** | 1.x (GitHub) | Subscribe to DNS Server ETW provider for live analytical events |
| ETW emission | **`tracelogging`** | 1.2.4 | Microsoft-maintained; for producing ETW events (optional) |
| Debug log parsing | **None exists** | — | Must build from scratch |

### No existing Rust crate parses dns.log

The debug text log format has **no Rust crate**. The only known Rust project is `u-siem/usiem-windns` on GitHub (MIT-licensed, part of the uSIEM framework) which could serve as a reference implementation.

### Reference parsers in other languages worth studying

- **NXLog `xm_msdns`** — the most complete commercial parser; hand-written in C without regex for performance; defines the canonical field list
- **PowerShell `Get-DNSDebugLog`** — multiple implementations on GitHub (winadm/posh, jschpp/DNSDebugLogHandler); provides tested regex patterns
- **Python `ScourDNS`** — DNS debug log analysis tool
- **`cybersecthreat/DFIR` PowerShell script** — analytical/ETW log parser using `wevtutil qe`

### Suggested parser architecture

A comprehensive Rust DNS parser should have three independent modules:

1. **Debug log parser** — custom line-by-line parser using `regex` crate or hand-rolled state machine (NXLog's experience suggests hand-written outperforms regex). Handle timestamp detection with fallback patterns. Emit structured records with typed fields.

2. **EVTX/audit parser** — use the `evtx` crate to read `.evtx` files, then dispatch on `EventID` to extract typed `EventData` fields. Map `Type`/`RDATA` fields from hex to structured records.

3. **ETW/analytical parser** — for offline `.etl` files, use `evtx` crate (which can read archived analytical logs). For real-time capture, use `ferrisetw` to subscribe to the DNS Server provider GUID. Extract `PacketData` fields and decode with `hickory-proto` for full DNS message parsing.

### Critical implementation note

The analytical channel produces `.etl` files, not `.evtx`. These cannot be consumed through standard Windows Event Log APIs. For real-time DNS query monitoring on Server 2012 R2+, ETW is the only path. The `evtx` crate can read archived `.etl` files converted to `.evtx` via `wevtutil`, but native `.etl` consumption requires an ETW consumer like `ferrisetw`.

---

## Conclusion

Building a Rust DNS log parser requires handling four fundamentally different formats from a single Windows Server service. The **debug text log** is the most challenging to parse due to locale-dependent timestamps, variable whitespace, and undocumented format quirks — but carries the richest legacy deployment base. The **analytical ETW channel** (Event IDs 256-280) is the modern replacement, offering structured fields with embedded DNS wire-format packets, though Event 256 remains officially undocumented despite being the most important event. The **audit EVTX channel** (Event IDs 513-582) covers administrative operations and is the only log enabled by default. The recommended Rust stack combines `evtx` for EVTX parsing, `hickory-proto` for DNS wire format decoding, and `ferrisetw` for live ETW consumption — with a new custom module needed exclusively for the legacy debug text log format.