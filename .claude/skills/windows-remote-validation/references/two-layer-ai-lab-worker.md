# Two-layer AI lab worker reference

## Topology

- Windows client: `<client-host>` at `<client-address>`, interactive console session `1`, account `<lab-account>`.
- ConfigMgr server: `<cm-server-host>` at `<cm-server-address>`, account `<lab-account>`.
- Client app path observed: `C:\Program Files\CMTrace Open\cmtrace-open.exe`.
- Client-side evidence paths observed: `C:\Windows\CCM\Logs` and `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`.

## Deterministic worker contract

Lab-only PowerShell worker should emit one compact JSON result with:

- `schemaVersion`
- `mode`
- `status`: `PASS`, `REWORK`, or `NOT_APPLICABLE`
- `target`
- `findings`
- sanitized `errors`

Supported operations are discovery, security probes, provenance, and packaging. Discovery and disposable security probes were exercised successfully on the client. Provenance initially failed on Windows because recursive sanitization crossed complex Authenticode certificate/provider objects and hit call-depth overflow; the durable fix is to project those objects to flat scalar fields before sanitization.

## Interactive worker contract

Run only in the existing logged-on desktop session. Do not infer success from `cmtrace-open.exe` being present. The worker must:

1. launch or attach to the exact app artifact;
2. obtain the actual UI Automation tree;
3. write a screenshot, tree/diagnostic dump, and transcript before scenario actions;
4. apply bounded waits and exit even when a selector is missing;
5. emit structured results per scenario;
6. use source-derived selectors for in-app controls;
7. treat native picker and external consent labels as runtime observations;
8. never guess or click an unknown consent decision.

A scheduled task with `LogonType Interactive` can launch the GUI into session 1 from SSH. Normal SSH commands run in Session 0 and cannot validate native picker/consent/UI lifecycle.

## Transfer and retry pattern

Keep source scripts in a persistent worktree and copy from there. `/tmp` is acceptable for short-lived local construction, but not as the only source for background retries: a later process may report `scp: stat local ... No such file` because the temporary script disappeared. That is a local orchestration failure, not a Windows-target failure.

After deployment, run a small remote smoke command first (`whoami`, `hostname`, version/path check), then run the worker and retrieve evidence files separately. If the target becomes unreachable, classify it as a transport problem and do not reinterpret prior worker results.

## Acceptance boundary

- Deterministic discovery PASS is not product acceptance.
- A hardlink creation PASS is an environmental capability observation, not proof that product capture rejects hardlinks before bytes are read.
- UI process launch PASS is not UI/IPC acceptance.
- Only exact-artifact, scenario-specific evidence with returned JSON and artifacts can support the merge gate.
