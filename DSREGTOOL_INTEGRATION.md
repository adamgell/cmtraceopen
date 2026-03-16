# DSRegTool Diagnostic Capabilities Integration Plan

> Comprehensive analysis of [mzmaili/DSRegTool](https://github.com/mzmaili/DSRegTool) and how its diagnostic capabilities can enrich CMTrace Open's DSRegCMD workspace.

## Summary

After analyzing DSRegTool (a PowerShell-based device registration troubleshooting tool that performs 50+ diagnostic tests) against our existing DSRegCMD workspace, this document catalogs all identified gaps and provides a prioritized implementation plan.

---

## Current State: What CMTrace Open Already Does Well

Our DSRegCMD workspace is already a mature analysis engine:

- **Parses `dsregcmd /status` output** — 50+ fields extracted via regex-based parser (`src-tauri/src/dsregcmd/parser.rs`)
- **Join type detection** — Distinguishes `HybridEntraIdJoined`, `EntraIdJoined`, `NotJoined`, `Unknown`
- **Failure phase mapping** — Maps errors to `precheck` / `discover` / `auth` / `join` / `post_join` stages
- **PRT freshness analysis** — Calculates token age in hours, flags stale tokens (>4h since last update)
- **Certificate expiry checking** — Parses validity range `[YYYY-MM-DD -- YYYY-MM-DD]`, computes days remaining
- **Network error detection** — Recognizes `ERROR_WINHTTP_*` markers in diagnostic output
- **WHfB policy evidence** — Reads registry-backed Windows Hello for Business signals from evidence bundles (6 registry export files across PolicyManager, HKLM, HKCU sources)
- **Capture confidence scoring** — `high` / `medium` / `low` based on timestamp freshness and session type (remote vs. interactive)
- **20+ error rules, 10+ warning rules, 10+ info rules** — Comprehensive diagnostic insight generation in `rules.rs` (~2100 lines)
- **Live capture on Windows** — Executes `dsregcmd /status` with Microsoft signature verification, collects registry evidence into a structured bundle
- **5 input methods** — File, folder, clipboard, live capture, manual text
- **Export capabilities** — JSON and formatted summary text, copy to clipboard, save to file

---

## Gap Analysis: Features to Integrate

### 1. Endpoint Connectivity Testing (High Value)

**What DSRegTool does:**
- Actively tests HTTP/HTTPS reachability to critical Microsoft endpoints:
  - `login.microsoftonline.com/common/oauth2` — Authentication endpoint
  - `device.login.microsoftonline.com/common/oauth2` — Device authentication endpoint
  - `enterpriseregistration.windows.net` — Device Registration Service (DRS) discovery
- Reports HTTP status codes and connection errors for each endpoint
- Detects proxy interference and certificate validation failures

**What we currently do:**
- We detect `ERROR_WINHTTP_*` markers in dsregcmd output (passive detection)
- We parse service endpoint URLs from the output but don't test them

**Proposed implementation:**
- During live capture (`capture_dsregcmd` in `src-tauri/src/commands/dsregcmd.rs`), perform HTTPS connectivity tests to the three critical endpoints
- Store results in the evidence bundle (e.g., `evidence/connectivity/endpoint-tests.json`)
- Add new fields to `DsregcmdAnalysisResult` for connectivity test results
- Add diagnostic rules that correlate connectivity failures with specific registration errors
- For non-live inputs (file/clipboard), add rules that suggest running connectivity tests when network-related errors are detected

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Add connectivity test execution during capture
- `src-tauri/src/dsregcmd/models.rs` — Add connectivity result types
- `src-tauri/src/dsregcmd/rules.rs` — Add connectivity-aware diagnostic rules
- `src/types/dsregcmd.ts` — Mirror new types
- `src/components/dsregcmd/DsregcmdWorkspace.tsx` — Display connectivity results

---

### 2. Service Connection Point (SCP) Validation (High Value — Critical for Hybrid Join)

**What DSRegTool does:**
- Queries Active Directory for the SCP object at:
  `CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration,DC=...`
- Validates that the SCP contains correct tenant name and tenant ID
- Cross-references SCP tenant info with the device's actual tenant configuration
- Detects common SCP misconfigurations:
  - Missing SCP object entirely
  - SCP pointing to wrong tenant
  - SCP with stale/incorrect values after tenant migrations

**What we currently do:**
- We detect `HybridEntraIdJoined` join type and parse tenant details
- We have pre-join test fields (`drsDiscoveryTest`, etc.) but no SCP-specific rules
- No SCP data collection or validation

**Proposed implementation:**
- During live capture on domain-joined machines, query the SCP via LDAP or `nltest` / PowerShell
- Store SCP values in the evidence bundle
- Add diagnostic rules that:
  - Flag when `drsDiscoveryTest` fails and suggest SCP verification
  - Cross-reference parsed `tenantId` / `tenantName` with SCP values when available
  - Warn about common SCP misconfiguration patterns
- For non-live inputs, add heuristic rules based on existing parsed fields

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Add SCP query during capture
- `src-tauri/src/dsregcmd/models.rs` — Add SCP evidence types
- `src-tauri/src/dsregcmd/rules.rs` — Add SCP validation rules
- `src/types/dsregcmd.ts` — Mirror new types

---

### 3. Additional Registry Key Collection (Medium Value)

**What DSRegTool inspects that we don't currently collect:**

| Registry Path | Purpose | Value |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ` | Device registration root settings | Core CDJ configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD` | Tenant-specific AAD configuration | Tenant ID, tenant name, authority URL |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin` | Group Policy for workplace join | `autoWorkplaceJoin`, fallback-to-sync-join settings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com` | PRT storage location | Token presence, refresh status |
| `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions` | Product type (Server vs. Workstation) | Relevant for join eligibility |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion` | OS build information | Build number, UBR, edition |

**What we currently collect:**
- 6 registry files focused on WHfB policy evidence (PolicyManager, HKLM/HKCU policies)

**Proposed implementation:**
- Expand the `capture_dsregcmd` function to export these additional registry hives
- Add new evidence files to the bundle:
  - `evidence/registry/cdj-config.reg`
  - `evidence/registry/workplace-join-policy.reg`
  - `evidence/registry/prt-storage.reg`
  - `evidence/registry/os-version.reg`
- Extend `registry.rs` to parse these new sources
- Add new diagnostic rules that leverage this data

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Expand registry export list
- `src-tauri/src/dsregcmd/registry.rs` — Add parsers for new registry sources
- `src-tauri/src/dsregcmd/models.rs` — Add new evidence types
- `src-tauri/src/dsregcmd/rules.rs` — Add rules using new evidence

---

### 4. OS Version Validation (Easy Win)

**What DSRegTool does:**
- Validates that the OS is Windows 10 version 1511 or later (required for device registration)
- Checks build number and edition
- Warns about unsupported OS versions

**What we currently do:**
- No OS version checking at all

**Proposed implementation:**
- Parse OS version from the registry evidence bundle (`HKLM\Software\Microsoft\Windows NT\CurrentVersion`)
- Alternatively, during live capture, read OS version via `[System.Environment]::OSVersion` or WMI
- Add a diagnostic rule in `rules.rs`:
  - **Error** if OS build < 10586 (Windows 10 1511)
  - **Warning** if OS is a Server SKU (different join behavior)
  - **Info** displaying the detected OS version for context

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Collect OS version during capture
- `src-tauri/src/dsregcmd/models.rs` — Add OS version fields
- `src-tauri/src/dsregcmd/rules.rs` — Add validation rules

---

### 5. Built-in Administrator Account Detection (Easy Win)

**What DSRegTool does:**
- Detects when the built-in Administrator account (RID 500) is being used
- Warns that this account cannot perform Azure AD join operations
- This is a surprisingly common issue in enterprise environments

**What we currently do:**
- We parse `userIdentity` from diagnostic fields but don't check if it's the built-in admin

**Proposed implementation:**
- Add a diagnostic rule in `rules.rs` that checks the parsed `userIdentity` field
- If the identity matches common built-in admin patterns (e.g., SID ending in `-500`, or username `Administrator`), generate an **Error** insight:
  - Title: "Built-in Administrator account cannot Azure AD Join"
  - Evidence: The parsed `userIdentity` value
  - Suggested Fix: "Sign in with a standard user account or a non-built-in administrator account to perform Azure AD Join"
- This requires zero new data collection — purely a new rule on existing parsed data

**Files to modify:**
- `src-tauri/src/dsregcmd/rules.rs` — Add administrator detection rule (single rule, ~20 lines)

---

### 6. Proxy Configuration Evidence (Medium Value, High Impact)

**What DSRegTool does:**
- Checks WinHTTP proxy settings (`netsh winhttp show proxy`)
- Checks WinInet proxy settings (user-level, from registry `HKCU\...\Internet Settings`)
- Detects WPAD (Web Proxy Auto-Discovery) configuration
- Validates that proxy settings allow access to Microsoft device registration endpoints
- This is one of the most common root causes of registration failures in enterprise networks

**What we currently do:**
- We detect `ERROR_WINHTTP_*` markers in the dsregcmd output
- No proxy configuration data is collected or analyzed

**Proposed implementation:**
- During live capture, run `netsh winhttp show proxy` and store output in `evidence/network/winhttp-proxy.txt`
- Export WinInet proxy registry keys to `evidence/registry/wininet-proxy.reg`
- Add diagnostic rules that:
  - Correlate `ERROR_WINHTTP_*` errors with proxy configuration
  - Flag when proxy is configured but bypass list doesn't include Microsoft endpoints
  - Suggest proxy configuration changes when connectivity issues are detected
  - Differentiate between "no proxy" and "proxy misconfigured" scenarios

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Add proxy evidence collection
- `src-tauri/src/dsregcmd/models.rs` — Add proxy evidence types
- `src-tauri/src/dsregcmd/registry.rs` — Parse proxy registry data
- `src-tauri/src/dsregcmd/rules.rs` — Add proxy-aware diagnostic rules

---

### 7. Event Log Collection in Evidence Bundles (High Effort, High Impact)

**What DSRegTool collects:**
- **Web Authentication** events — Browser-based auth flows
- **LSA (Local Security Authority)** events — Security token operations
- **NTLM/CredSSP** authentication events — Credential delegation
- **Kerberos** authentication events — Ticket operations
- **Device Registration Configuration** events — Join/registration workflow
- **AAD Extension** events — Azure AD-specific operations
- **Netlogon, Netsetup, Lsass logs** — Domain authentication and setup

**What we currently do:**
- No event log collection whatsoever

**Proposed implementation:**
- During live capture (admin mode), export relevant Windows Event Log channels:
  - `Microsoft-Windows-AAD/Operational`
  - `Microsoft-Windows-User Device Registration/Admin`
  - `Microsoft-Windows-User Device Registration/Debug`
  - `Microsoft-Windows-Workplace Join/Admin`
- Store as EVTX or parsed JSON in `evidence/eventlogs/`
- Copy system logs (`netlogon.log`, `Netsetup.log`) to `evidence/logs/`
- Add an "Event Timeline" view to the workspace (similar to the Intune workspace's EventTimeline)
- Add diagnostic rules that correlate event log entries with dsregcmd output

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Add event log export
- `src-tauri/src/dsregcmd/models.rs` — Add event log types
- `src-tauri/src/dsregcmd/rules.rs` — Add event-log-aware rules
- New file: `src-tauri/src/dsregcmd/eventlogs.rs` — Event log parser
- `src/components/dsregcmd/DsregcmdWorkspace.tsx` — Add event timeline section

---

### 8. AD Computer Object Certificate Validation (High Effort, High Value for Hybrid Join)

**What DSRegTool does:**
- Queries the AD computer object's `userCertificate` attribute via LDAP
- Validates that a self-signed certificate exists and matches the device GUID
- Checks certificate validity dates
- This is the #1 troubleshooting step for Hybrid Join failures — if the certificate is missing or wrong, the device cannot complete Hybrid Join

**What we currently do:**
- We parse the `deviceCertificateValidity` field from dsregcmd output
- We check for certificate expiry
- No AD object querying capability

**Proposed implementation:**
- During live capture on domain-joined machines, query the local computer's AD object via LDAP (`[ADSI]"LDAP://..."` or `dsquery`/`certutil`)
- Extract the `userCertificate` attribute and validate it
- Store results in `evidence/ad/computer-certificate.json`
- Add diagnostic rules for:
  - Missing `userCertificate` attribute
  - Certificate GUID mismatch
  - Expired or not-yet-valid certificates
  - Multiple certificates (cleanup needed)

**Files to modify:**
- `src-tauri/src/commands/dsregcmd.rs` — Add AD certificate query
- `src-tauri/src/dsregcmd/models.rs` — Add AD certificate evidence types
- `src-tauri/src/dsregcmd/rules.rs` — Add certificate validation rules

---

### 9. Device Sync Status Checking (Medium Value)

**What DSRegTool does:**
- Checks whether the device has been synced from on-premises AD to Entra ID
- Validates the Microsoft Entra Connect synchronization scope
- Detects when devices are filtered out of the sync scope

**What we currently do:**
- We parse `fallbackToSyncJoin` from pre-join tests but don't validate sync status
- No sync-specific diagnostic rules

**Proposed implementation:**
- Add diagnostic rules that infer sync issues from existing parsed fields:
  - When `domainJoined = YES` but `azureAdJoined = NO` and pre-join tests pass, suggest checking Entra Connect sync scope
  - When `fallbackToSyncJoin` is set, explain its implications
- For live capture, could check `dsregcmd /status /debug` for additional sync details

**Files to modify:**
- `src-tauri/src/dsregcmd/rules.rs` — Add sync inference rules (low effort, just new rules)

---

## Implementation Priority Matrix

| Priority | Feature | Effort | Impact | Dependencies |
|:---:|---|:---:|:---:|---|
| **P0** | Built-in Administrator detection (#5) | Very Low | Medium | None — pure rule addition |
| **P0** | OS version validation (#4) | Low | Medium | Needs registry capture expansion (#3) or separate capture |
| **P0** | Device sync status inference (#9) | Low | Medium | None — pure rule addition |
| **P1** | Additional registry key collection (#3) | Low | Medium | None — extends existing capture |
| **P1** | New SCP-related diagnostic rules (#2 — rules only) | Low | High | None for heuristic rules; SCP query needs capture changes |
| **P2** | Proxy configuration evidence (#6) | Medium | High | None |
| **P2** | Endpoint connectivity testing (#1) | Medium | High | None |
| **P3** | Event log collection (#7) | High | High | Admin privileges required |
| **P3** | AD computer object cert validation (#8) | High | High | Domain access, LDAP queries |

---

## Suggested Phased Rollout

### Phase 1: Quick Wins (Rules Only — No New Data Collection)
- Built-in Administrator account detection
- Device sync status inference from existing fields
- Enhanced `fallbackToSyncJoin` interpretation
- SCP-related heuristic rules based on `drsDiscoveryTest` failures
- **Estimated scope:** ~100-150 lines added to `rules.rs`

### Phase 2: Expanded Evidence Collection
- Additional registry key capture (CDJ, WorkplaceJoin, OS version, PRT storage)
- Registry parsers for new sources
- OS version validation rule
- Proxy configuration capture and rules
- **Estimated scope:** Changes to `commands/dsregcmd.rs`, `registry.rs`, `rules.rs`, `models.rs`

### Phase 3: Active Diagnostics
- Endpoint connectivity testing during live capture
- SCP querying on domain-joined machines
- Results storage in evidence bundle
- Corresponding diagnostic rules
- **Estimated scope:** Significant additions to capture pipeline

### Phase 4: Deep Diagnostics
- Event log collection and parsing
- Event timeline UI component
- AD computer object certificate validation
- Comprehensive cross-correlation rules
- **Estimated scope:** New Rust module, major UI additions

---

## References

- [DSRegTool Repository](https://github.com/mzmaili/DSRegTool)
- [Microsoft: Troubleshoot devices by using the dsregcmd command](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd)
- [Microsoft: Troubleshoot hybrid Azure AD-joined devices](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current)
- Current CMTrace Open DSRegCMD implementation:
  - Backend: `src-tauri/src/dsregcmd/` (parser, rules, registry, models)
  - Frontend: `src/components/dsregcmd/DsregcmdWorkspace.tsx`
  - Commands: `src-tauri/src/commands/dsregcmd.rs`
