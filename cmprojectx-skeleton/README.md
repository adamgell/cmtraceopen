# cmProjectX

> Windows-forward unified Intune platform: a Rust/WinUI 3 client + a hard-forked
> .NET Intune (Graph) engine, with a persistent, searchable **audit/drift
> time-machine**. See [`docs/MVP-PLAN.md`](./docs/MVP-PLAN.md) for the full plan.

This is a **skeleton** — structure + seams + stubs, not a working app yet.

## Architecture

```
  ┌──────────────────────────────────────────┐         ┌────────────────────────────────────┐
  │  app/  — WinUI 3 + Rust (Windows Reactor)  │  HTTP   │  service/  — .NET Intune engine       │
  │  • Reactor UI (Rust forward)               │ ◄─────► │  • Core/  hard-forked IC (Graph)     │
  │  • api_client → service                    │  REST/  │  • Sync/  Graph delta sync           │
  │  • (Phase 2) CMTrace parser, log index     │ OpenAPI │  • Store/ append-only + search index │
  └──────────────────────────────────────────┘         │  • Api/   thin ASP.NET host          │
                                                         └──────────────┬───────────────────────┘
                                              contract/openapi.yaml ─────┘ (one schema → both sides)
                                                            future: WebUI · Agents (MCP) — same API
```

## Layout

| Path | Stack | Role |
|---|---|---|
| `contract/` | OpenAPI | **Single source of truth** for DTOs + endpoints → generates C# *and* Rust types |
| `service/Core/` | .NET 10 | **Drop the hard-forked Intune Commander core here** (Graph services + multi-cloud auth) |
| `service/Sync/` | .NET 10 | Graph **delta** sync engine (stub) |
| `service/Store/` | .NET 10 | Append-only audit+config snapshots + full-text index (stub) |
| `service/Api/` | .NET 10 | Thin ASP.NET minimal-API host (the main new code) |
| `app/` | Rust | WinUI 3 client (Windows Reactor) + API client |
| `crates/api-types/` | Rust | DTOs mirroring the contract (generatable) |
| `crates/parser/` | Rust | **External OSS dependency** on the CMTrace Open parser (upstream seam) |

## Getting started

```bash
# .NET service
cd service && dotnet build           # after you drop Core/ in and create the .sln

# Rust app
cargo build                          # builds app/ + crates/*
cargo run -p app                     # pings the service /health
```

## Status / next steps

- [ ] Create the .NET solution: `dotnet new sln && dotnet sln add service/**/**.csproj`
- [ ] Hard-fork IntuneCommander `Core` into `service/Core/`
- [ ] Phase 0: Windows Reactor risk-gate (LogGrid + live tail) — confirm the framework
- [ ] Phase 1 (MVP): device-code auth → delta sync → store/index → timeline/drift/search
- [ ] Wire OpenAPI codegen for both languages
- [ ] Decide: repo name, transport (REST vs gRPC), commercial license

> Generated as a starting skeleton. Pin/confirm crate & package versions before building.
