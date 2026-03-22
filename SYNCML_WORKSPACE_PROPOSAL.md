# Feature: SyncML Workspace — Port SyncMLViewer Functionality to Rust/Tauri

## Summary

Add a new **SyncML Workspace** to CMTraceOpen that replicates the core functionality of [okieselbach/SyncMLViewer](https://github.com/okieselbach/SyncMLViewer) — a real-time SyncML protocol viewer for Intune/MDM device management. This will be the 4th workspace alongside Log Viewer, Intune, and dsregcmd.

## Background: What is SyncMLViewer?

SyncMLViewer is a C#/WPF application by Oliver Kieselbach that captures and displays the SyncML (OMA-DM) XML messages exchanged between Windows devices and MDM servers like Microsoft Intune. It uses **ETW (Event Tracing for Windows)** to intercept these messages in real-time.

### Why port this to CMTraceOpen?

- SyncMLViewer is a standalone C#/WPF app — having this inside CMTraceOpen alongside the existing Intune workspace creates a unified troubleshooting tool
- CMTraceOpen already has the Rust/Tauri infrastructure, workspace system, and Intune analysis capabilities
- The SyncML messages are the raw protocol-level view of what Intune policies/apps are doing — complementing the higher-level IME log analysis already in CMTraceOpen

---

## Technical Reverse Engineering of SyncMLViewer

### ETW Provider Configuration

Two ETW providers capture MDM/OMA-DM traffic:

| Provider Name | GUID | Purpose |
|---|---|---|
| `Microsoft.Windows.DeviceManagement.OmaDmClient` | `{0EC685CD-64E4-4375-92AD-4086B6AF5F1D}` | Primary SyncML message capture |
| `Microsoft-WindowsPhone-OmaDm-Client-Provider` | `{3B9602FF-E09B-4C6C-BC19-1A3DFA8F2250}` | Secondary OMA-DM client events |

A third provider exists but is commented out in the original: `{3da494e4-0fe2-415C-b895-fb5265c5c83b}` (Enterprise Diagnostics Provider).

### ETW Event Types Captured

| Event Name | Purpose |
|---|---|
| `OmaDmClientExeStart` | Sync initiation marker |
| `OmaDmSyncmlVerboseTrace` | **Primary** — contains the actual SyncML XML body |
| `OmaDmSessionStart` | Session boundary start |
| `OmaDmSessionComplete` | Session boundary end |

Filtered/ignored events: `FunctionEntry`, `FunctionExit`, `GenericLogEvent`

### SyncML XML Extraction Pipeline

1. ETW event data → UTF-8 string conversion
2. Locate `<SyncML>` and `</SyncML>` tags (case-insensitive substring search)
3. Extract XML content between tags
4. Parse SessionID via regex: `<SessionID>([0-9a-zA-Z]+)</SessionID>`
5. Parse MsgID via regex: `<MsgID>([0-9]+)</MsgID>`
6. Format XML with indentation (XElement.Parse equivalent)
7. Handle truncation: ETW has a **64KB max buffer** — messages exceeding ~45KB may be truncated. Truncated messages get a synthetic closing tag appended: `<!-- ignore this line, closing SyncML tag added...--></SyncML>`

### Data Model

```
SyncMlSession
├── SessionId: String
├── DateTime: Timestamp
├── Comment: Option<String>
└── Messages: Vec<SyncMlMessage>
    ├── SessionId: String
    ├── MsgId: String
    ├── Xml: String (formatted SyncML XML)
    ├── DateTime: Timestamp
    └── Comment: Option<String>
```

### MDM Sync Triggering

SyncMLViewer can also **trigger** an MDM sync (not just observe). Two methods:

1. **Scheduled Task** (primary): `SCHTASKS.exe /Run /I /TN "Microsoft\Windows\EnterpriseMgmt\{AccountID}\Schedule #3..."`
2. **Windows Runtime**: `[Windows.Management.MdmSessionManager]::TryCreateSession()`

Enrollment Account IDs are read from: `HKLM\SOFTWARE\Microsoft\Enrollments`

### Registry Paths Referenced

| Path | Purpose |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Enrollments` | MDM enrollment info |
| `HKLM\SOFTWARE\Microsoft\PolicyManager` | Policy configuration |
| `HKLM\SOFTWARE\Microsoft\Provisioning` | Provisioning data |
| `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension` | IME presence check |
| `HKLM\SOFTWARE\Microsoft\DeclaredConfiguration` | DC host OS config |

### SyncML Extraction Regex

The original C# uses this regex to extract complete SyncML blocks from raw event data:

```regex
<SyncML[\s\S]*?</SyncML>
```

Both SessionID and MsgID regexes are case-insensitive.

### Local MDM API (`mdmlocalmanagement.dll`)

SyncMLViewer includes a separate **Executer** binary that interfaces with the undocumented `mdmlocalmanagement.dll` via P/Invoke to send local SyncML requests directly to the device's MDM stack — no MDM server needed.

**P/Invoke signatures:**
- `ApplyLocalManagementSyncML(string syncMLRequest, out IntPtr syncMLResult)` — sends a SyncML request locally and gets a response
- `RegisterDeviceWithLocalManagement(out bool alreadyRegistered)` — registers the device for local management (creates enrollment type 20, ProviderID `"Local_Management"`)
- `UnregisterDeviceWithLocalManagement()` — removes local management enrollment

**Prerequisites:** EmbeddedMode must be enabled — requires setting a SHA-256 hash of the SMBIOS UUID in registry at `HKLM\SYSTEM\CurrentControlSet\Services\EmbeddedMode\Parameters\Flags`.

The main application extracts the Executer binary from embedded resources at runtime, validates its **SHA-256 hash** before execution, and requires a **64-bit process** with **MTA threading model**.

### Declared Configuration / MMP-C Support

The newer Microsoft Managed Platform Cloud (MMP-C) uses a desired-state model but still transports over the same OMA-DM SyncML protocol. SyncMLViewer captures MMP-C traffic with the same ETW approach. There is also support for triggering MMP-C syncs separately from standard MDM syncs.

### Command-Line Arguments (Original Tool)

| Flag | Purpose |
|---|---|
| `/s` | Trigger MDM sync on startup |
| `/m` | Trigger MMP-C sync on startup |
| `/b` | Enable background logging to XML files |
| `/h` | Hide when minimized (system tray) |

### Views in Original Tool

1. **Stream View** — continuous raw XML log of all SyncML messages (searchable)
2. **Session View** — hierarchical: Sessions → Messages, with XML viewer (AvalonEdit) and code folding
3. **Status Code Reference** — built-in OMA SyncML response code documentation

Additional features: Base64/Hex decoding, Autopilot hardware hash decoding, NodeCache lookup, WiFi profile enumeration via `netsh`, VPN profile retrieval via PowerShell, MDM diagnostics report generation.

---

## Implementation Plan for CMTraceOpen

### Phase 1: Rust Backend (`src-tauri/src/syncml/`)

#### New Files
- `mod.rs` — module exports
- `etw.rs` — ETW trace session management (start/stop capture, session named `"CMTraceOpen-SyncML"`)
- `parser.rs` — SyncML XML extraction and formatting (regex: `<SyncML[\s\S]*?</SyncML>`)
- `models.rs` — `SyncMlSession`, `SyncMlMessage` data structures
- `trigger.rs` — MDM sync trigger via scheduled tasks and MMP-C sync
- `local_mdm.rs` — (future) Local MDM API via `mdmlocalmanagement.dll` FFI for sending SyncML requests without a server

#### ETW in Rust

Use the [`ferrisetw`](https://github.com/microsoft/ferrisetw) crate (Microsoft's official Rust ETW library) or the [`windows`](https://crates.io/crates/windows) crate with raw ETW APIs (`StartTrace`, `EnableTraceEx2`, `OpenTrace`, `ProcessTrace`).

The trace session needs admin privileges — handle gracefully with error messaging.

#### New Tauri Commands (`src-tauri/src/commands/syncml.rs`)
- `start_syncml_capture` — start ETW trace session
- `stop_syncml_capture` — stop ETW trace session
- `get_syncml_sessions` — return captured sessions/messages
- `trigger_mdm_sync` — kick off an MDM sync
- `export_syncml_log` — save captured messages to XML file
- `decode_base64_content` — decode base64 payloads in SyncML messages

### Phase 2: Frontend (`src/components/syncml/`)

#### New Files
- `SyncmlWorkspace.tsx` — main workspace component (add to AppShell workspace switcher)
- `SyncmlStream.tsx` — stream/raw view of all messages
- `SyncmlSessionList.tsx` — session tree with message list
- `SyncmlMessageViewer.tsx` — XML viewer with syntax highlighting and folding
- `SyncmlStatusCodes.tsx` — OMA-DM status code reference panel

#### New Store (`src/stores/syncml-store.ts`)
```typescript
interface SyncmlStore {
  sessions: SyncMlSession[]
  selectedSession: string | null
  selectedMessage: string | null
  isCapturing: boolean
  streamMessages: SyncMlMessage[] // flat list for stream view
  activeTab: 'stream' | 'sessions' | 'status-codes'
}
```

#### UI Store Update
- Add `"syncml"` to the `activeView` type union
- Add workspace switcher button/tab

### Phase 3: Integration

- Add SyncML workspace to the sidebar/toolbar navigation
- Add known source entry for SyncML capture
- Handle admin privilege requirements (detect + prompt)
- Add keyboard shortcuts for start/stop capture

---

## Crate Dependencies to Add

```toml
# In src-tauri/Cargo.toml - Windows-only ETW support
[target.'cfg(target_os = "windows")'.dependencies]
ferrisetw = "1"  # Microsoft's Rust ETW library
# OR
windows = { version = "0.58", features = ["Win32_System_Diagnostics_Etw"] }

# XML formatting
quick-xml = "0.36"
```

---

## Key Considerations

- **ETW is Windows-only**: The ETW capture and trigger commands are Windows-only and must be gated with `#[cfg(target_os = "windows")]`. The workspace UI itself can exist on all platforms with ETW-dependent actions disabled/hidden on non-Windows (consistent with the dsregcmd workspace, where only certain commands are Windows-gated).
- **Admin required**: ETW trace sessions require elevated privileges. Need clear UX for this
- **64KB ETW buffer limit**: Must handle truncated messages gracefully (the original tool appends synthetic closing tags)
- **Real-time streaming**: Messages arrive via ETW callbacks — needs async channel from Rust → frontend (similar pattern to the existing file tail watcher using Tauri events)
- **XML formatting**: Need a Rust XML pretty-printer (`quick-xml` crate for parsing/formatting)

---

## OMA-DM SyncML Status Codes Reference (for built-in panel)

| Code | Meaning |
|---|---|
| 200 | OK - Command completed successfully |
| 212 | Authentication accepted |
| 214 | Operation cancelled |
| 215 | Not executed (user interaction pending) |
| 216 | Atomic roll back OK |
| 400 | Bad request |
| 401 | Invalid credentials |
| 403 | Forbidden |
| 404 | Not found |
| 405 | Command not allowed |
| 406 | Optional feature not supported |
| 407 | Missing credentials |
| 408 | Request timeout |
| 409 | Conflict (already exists) |
| 410 | Gone (target deleted) |
| 412 | Incomplete command |
| 415 | Unsupported type |
| 416 | Atomic command failed |
| 418 | Already exists |
| 500 | Command failed |
| 507 | Atomic failed |
| 516 | Atomic roll back failed |

---

## References

- [SyncMLViewer GitHub](https://github.com/okieselbach/SyncMLViewer)
- [Oliver Kieselbach's blog post](https://oliverkieselbach.com/2019/10/11/windows-10-mdm-client-activity-monitoring-with-syncml-viewer/)
- [New SyncML Viewer version (2023)](https://oliverkieselbach.com/2023/12/12/new-syncml-viewer-version/)
- [MDM Local Management using SyncML Viewer](https://oliverkieselbach.com/2024/02/05/mdm-local-management-using-syncml-viewer/)
- [OMA-DM SyncML Protocol (Microsoft Docs)](https://learn.microsoft.com/en-us/windows/client-management/mdm/oma-dm-protocol-support)
- [ferrisetw - Rust ETW library by Microsoft](https://github.com/microsoft/ferrisetw)
- [ETW Providers GUID list](https://gist.github.com/guitarrapc/35a94b908bad677a7310)
- [Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider manifest](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider.xml)
- [SyncML Viewer Update with Autopilot hash decoding (2025)](https://oliverkieselbach.com/2025/01/27/syncml-viewer-update-with-autopilot-hash-decoding/)
- [MS-MDM SyncML Message Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/221ba29e-f0da-4b04-af9e-42f8631aea68)
- [Send MDM commands without an MDM service (Michael Niehaus)](https://oofhours.com/2022/08/26/send-mdm-commands-without-an-mdm-service-using-powershell/)
