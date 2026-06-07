# Unified Intune Platform — MVP Plan

> **Status:** Planning / pre-skeleton. No code yet.
> **Scope:** A new, Windows-forward commercial product combining **CMTrace Open**
> (Rust log/diagnostics engine) with the **Intune Commander** (.NET Graph engine),
> plus a new persistent, searchable **audit/drift "time-machine."**
> **Destination:** This doc lives in the `cmtraceopen` repo for now; it will be
> migrated into a new **private mono-repo** that the owner is creating.

---

## 1. Product thesis

Two existing apps sit on opposite sides of the same workflow:

- **CMTrace Open** — the *device / read* side. What **actually happened** on a
  machine: IME logs, app/workload/script deployment outcomes, error codes, GUIDs,
  dsregcmd, EVTX, timeline. (Rust backend + React/Fluent UI on Tauri.)
- **Intune Commander** — the *tenant / manage* side. What was **supposed to
  happen**: Graph API coverage for 30+ Intune object types, config export/import,
  drift detection, baseline comparison, multi-cloud (Commercial/GCC/GCC-High/DoD).
  (.NET 10 core + CLI + React UI.)

**The unique value of combining them is correlation across the gap between
*intended* and *actual* state, retained over time:**

> **who changed it** (audit event) → **what it became** (config drift snapshot) →
> **what broke** (device log outcome) — on one timeline, searchable, and retained
> longer than Microsoft keeps it.

Intune's native audit retention is limited (~1 year), so a persistent local index
meaningfully **extends the forensic/audit window** and enables longitudinal drift
analysis. No single existing tool does this.

---

## 2. Decisions locked in

| Decision | Choice | Notes |
|---|---|---|
| Platform priority | **Windows-forward** | macOS de-prioritized for this product. |
| New app UI stack | **WinUI 3 + Rust (Windows Reactor)** | "Rust forward." Native Fluent. |
| Intune/Graph engine | **Hard-fork the .NET IC core; keep it** | Do **not** rewrite Graph in Rust. |
| Topology | **Polyglot, API-first** | Rust/WinUI3 client ↔ HTTP API ↔ .NET service. |
| Repo | **Mono-repo** | Both stacks + the API contract in one place. |
| MVP slice | **Audit/drift time-machine** | Pure Intune data; no logs on critical path. |
| Data residency (MVP) | **Local desktop** | .NET service runs as a **local sidecar** on localhost. |
| System-of-record / index | **In the .NET service** | Shared store reachable by desktop now, webui/agents later. |
| Parser | **Stays native Rust, external OSS crate** | Keeps upstream contributions friction-free. |
| Transport | **REST + OpenAPI** (proposed) | Works for the Reactor client now and the webui later. |
| Commercial license | **TBD** (decide later) | Structure supports proprietary or source-available. |

### Why keep the .NET engine (correction from an earlier "all-Rust" idea)

- IC's **Core library is already UI-decoupled** and driven headlessly by its CLI,
  so exposing it via an API host is a **thin add, not a rewrite**.
- Avoids re-implementing 30+ Graph object types + multi-cloud auth in Rust
  (months of work + regression risk).
- Putting the **system-of-record + index in the .NET service** means the future
  **webui and agents share the same store** natively (solves the
  "desktop-local index can't be served" problem).
- Running it as a **local sidecar** keeps the MVP a single-machine desktop
  experience, while the *same* service hosts remotely later — no re-architecture.

---

## 3. Target architecture

```
  ┌──────────────────────────────────────────┐         ┌────────────────────────────────────┐
  │  NEW APP — WinUI 3 + Rust (Reactor)        │  HTTP   │  .NET IC core (hard-forked)          │
  │  • Reactor UI (Rust forward)               │ ◄─────► │  • 30+ Graph services (AS-IS)        │
  │  • CMTrace parser (native Rust, upstream)  │  REST/  │  • Multi-cloud Entra auth (AS-IS)    │
  │  • Local log index (Tantivy)               │ OpenAPI │  • Drift / export (AS-IS)            │
  │  • Log diagnostics + correlation UI        │         │  • NEW: audit+config store + index   │
  └──────────────────────────────────────────┘         │  • NEW: thin API host (the only add)  │
                                                         └──────────────┬───────────────────────┘
                                                            future: WebUI · Agents (MCP) — same API
```

**Data ownership**

- **.NET service:** Intune system-of-record — audit events + config snapshots
  (append-only) + full-text index (Lucene.NET) + drift. Shared by all clients.
- **Rust app:** log parsing + local log index (Tantivy) + UI. Logs are
  device-local anyway.
- **Correlation:** join across the two (a failing log line → the policy/app/script
  in the .NET store), via API.

**Two seams that keep future-you sane**

1. The **parser stays an external OSS crate** → improvements flow upstream to
   CMTrace Open.
2. The **`contract/` OpenAPI schema is the single source of truth** for DTOs →
   generates both C# and Rust types so the two-language split can't drift.

---

## 4. Mono-repo structure (proposed skeleton)

```
new-repo/
├─ service/            ← hard-forked .NET IC
│  ├─ Core/            (30+ Graph services, multi-cloud auth — AS-IS)
│  ├─ Store/           (NEW: append-only audit+config snapshots + Lucene.NET index)
│  ├─ Sync/            (NEW: Graph delta sync engine)
│  └─ Api/             (NEW: thin ASP.NET host — the main new code)
├─ app/                ← WinUI 3 + Rust (windows-reactor + windows-canvas)
├─ crates/parser/      ← OSS cmtraceopen-parser dependency (Phase 2; upstream seam)
├─ contract/           ← OpenAPI schema → generates C# + Rust types (shared component)
└─ docs/               ← this plan, ADRs
```

---

## 5. "Best of both" — what carries over

| Asset | From | Fate in new app |
|---|---|---|
| Rust parser engine (multi-format, auto-detect) | CMTrace | ✅ Direct crate reuse, no FFI (Phase 2). Crown jewel. |
| Watcher / live tail, error_db, IME/dsregcmd/sysmon/evtx analyzers | CMTrace | ✅ Reuse — already Rust (Phase 2). |
| React UI + Fluent components | both | ⚠️ Rewritten as Reactor components; design language carries 1:1. |
| 30+ Graph services / multi-cloud auth / drift / export | Intune Commander | ✅ Hard-fork, kept AS-IS behind the API. |
| LiteDB cache | Intune Commander | ✅ Keep as Graph accelerator behind the API. |
| Audit/drift durable store + index | — | 🆕 New, in the .NET service. |

---

## 6. Shared components (three senses)

1. **Open-core shared code (OSS ↔ commercial):** the `cmtraceopen-parser` crate
   (+ log models, error_db), consumed by both the OSS app and this product.
2. **Cross-service contract (Rust ↔ .NET):** the OpenAPI schema in `contract/`,
   generating types for both languages.
3. **In-app Reactor component library:** `LogGrid` (virtualized + live-tail),
   `DriftDiffView`, `FactGroupCard`, `StatusBanner`, `TimelineCanvas`
   (on `windows-canvas`/Direct2D), `SearchBar`/`ResultsList`, `NavShell`.

---

## 7. MVP plan (audit/drift time-machine)

The MVP is **pure Intune data** — no logs on the critical path — so the work
splits cleanly:

- **.NET service (most of the value, mostly existing code):** hard-fork core →
  add audit+config **append-only store + index** (Lucene.NET) → add **Graph delta
  sync** → expose **drift + timeline + search** over HTTP.
- **Rust/WinUI3 Reactor app (the new, Rust-forward client):** thin client
  rendering **timeline + drift-diff + search** from the API.

### Phasing

- **Phase 0 — Reactor risk-gate (small, throwaway).** Windows Reactor is brand new
  (landed in `microsoft/windows-rs`, May 2026). Build *just* `LogGrid` + live tail
  against the real parser crate. Green-light only if virtualized scrolling +
  streaming appends hold up on a large file. Days, not months.
- **Phase 1 — MVP.** Single tenant, **device-code Entra auth** → pull **audit
  events + a handful of config object types** via Graph (delta) → **append-only
  store + index** → UI: **audit timeline + drift-diff + unified search**.
- **Phase 2.** Bring in the **CMTrace parser + log viewer** (native Rust) and the
  **log↔policy correlation** workflow. Broaden Graph object-type coverage.
- **Phase 3.** Host the .NET service remotely → **WebUI** (React) + **app-only
  Entra auth** for unattended sync. Then **agents** (MCP server over the API).

---

## 8. Engineering realities to design around

- **Sync scale:** "pull in all logs and info" is a sync-scale problem. Rely on
  **Graph delta queries**, throttling/backoff, and a background sync engine — not
  naive full pulls.
- **Cache ≠ system of record:** IC's LiteDB cache (24h TTL) is a *read
  accelerator*. The time-machine needs a *separate, durable, append-only* store
  that never expires. Keep them distinct.
- **Reactor maturity:** first-party-*authored* (Kenny Kerr) but new and not
  declared production-ready. Hence the Phase 0 gate.
- **Packaging:** Windows-forward. Reactor app (~3 MB + Windows App SDK 2.0.1+
  runtime) + self-contained .NET service sidecar. MSIX is the blessed path.

---

## 9. Licensing posture (decide later)

- Both source apps are **MIT**, owner holds copyright → free to build a closed
  product on them.
- **MIT is irrevocable for already-public code** → the commercial moat is the
  **new** parts (audit/drift platform, webui, agents), not the already-open parts.
- Before taking money: **dependency license audit** (`cargo-deny`, `nuget-license`,
  `license-checker`); confirm the Intune Commander → `Micke-K/IntuneManagement`
  lineage copied no copyleft code (formats aren't copyrightable; clean reimpl is
  fine); add a **DCO/CLA** going forward.
- **Open-core split:** parser stays MIT/external; the app repo can go proprietary
  or source-available (BUSL / Elastic v2 / PolyForm worth considering for an
  audit tool, where source visibility is a selling point).
- *This is engineering guidance, not legal advice — get a short IP-attorney pass
  before commercial launch.*

---

## 10. Open decisions / TBD

- [ ] Repo name (`intune-forge` / `intune-time-machine` / `driftwatch` / …).
- [ ] Confirm transport = **REST + OpenAPI** (vs gRPC).
- [ ] How the parser is consumed early: **git dependency on a pinned commit**
  (proposed) vs submodule vs published crate.
- [ ] "Agents" meaning: **AI/LLM agents** querying the platform (MCP) vs
  **device-side log-collection agents**. Very different builds.
- [ ] Commercial license flavor (proprietary EULA vs source-available).

---

## Appendix — WinUI 3 + Rust foundation (research summary)

- **Windows Reactor** — a React-inspired, declarative UI framework for native
  **WinUI 3 in pure Rust**, by **Kenny Kerr** (creator of C++/WinRT and the
  `windows` crate), landed in `microsoft/windows-rs` (announced **May 2026**).
  Function components + typed props, hooks (`use_state`, `use_reducer`,
  `use_effect`, `use_context`, `use_memo`, `use_callback`, `use_resource`,
  `use_mutation`), 55+ widgets incl. virtualized `ListView`/`GridView`/`FlipView`,
  builder DSL + tuple children (no macros), runtime theming, accessibility.
  Companion `windows-canvas` (Direct2D). ~3 MB binary; needs Windows App SDK
  2.0.1+ runtime.
- **No XAML** on any Rust path — UI is built in code (the React/hooks model
  replaces XAML + x:Bind + MVVM). XAML/designer/MVVM exist only on the C# path.
- **Caveat:** new and not declared production-ready → Phase 0 risk-gate.

Sources:
- <https://github.com/microsoft/windows-rs>
- <https://github.com/microsoft/windows-rs/issues/4483> (Rust for Windows — May 2026)
- <https://github.com/microsoft/windows-rs/pull/4479> (Windows Reactor)
- <https://github.com/adamgell/IntuneCommander>
- <https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/downloads>
- <https://learn.microsoft.com/en-us/windows/apps/winui/winui3/>
