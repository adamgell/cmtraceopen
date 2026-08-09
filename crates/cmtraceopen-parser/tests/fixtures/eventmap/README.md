# EvtxECmd map fixtures

These are unmodified EvtxECmd maps from [EricZimmerman/evtx](https://github.com/EricZimmerman/evtx)
(MIT licensed), converted from YAML to JSON. Only the serialization format changed; the keys,
values, and structure are preserved exactly as upstream wrote them. The bytes necessarily differ,
since that is what the conversion does.

They are vendored so the map engine is tested against the real schema rather than invented
examples, per the repository rule that fixtures must anchor to real corpus.

| Fixture | Upstream file | Why it is here |
|---|---|---|
| `shell-core-9701.json` | `Microsoft-Windows-Shell-Core-Operational_Microsoft-Windows-Shell-Core_9701.map` | Simplest shape: one entry, bare `/Event/EventData/Data`. RunOnceEx during Autopilot OOBE. |
| `security-4624.json` | `Security_Microsoft-Windows-Security-Auditing_4624.map` | Multiple bindings per entry, multi-placeholder templates, `UserName` and `RemoteHost` targets. |
| `ntfs-146-lookups.json` | `Microsoft-Windows-Ntfs-Operational_Microsoft-Windows-Ntfs_146.map` | Exercises `Lookups` with a `Default` fallback. |
