# service/Core — hard-forked Intune Commander core

**Drop the hard-forked IntuneCommander `Core` library here.**

It already provides (per IntuneCommander docs):
- Graph API service coverage for **30+ Intune object types** (built & tested)
- Multi-cloud auth + endpoints (**Commercial / GCC / GCC-High / DoD**)
- Drift detection, export/import, baseline comparison
- LiteDB-backed encrypted cache (keep as a Graph *accelerator*)

It is already **UI-decoupled** (the IC CLI drives it headlessly), so `Api/`,
`Sync/`, and `Store/` just reference it as a project/package.

## Steps
1. Copy IntuneCommander's `Core` project into this folder.
2. `dotnet sln ../CmProjectX.sln add Core/Core.csproj`
3. Reference it from `Api`, `Sync`, `Store`.
4. Trim anything tied to the old desktop/WPF UI.

> Reuse, don't rewrite. The commercial value is the *new* time-machine layer
> (Sync + Store + Api), not re-implementing Graph.
