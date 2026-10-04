---
name: windows-remote-validation
description: Use for SSH-based Windows lab validation and evidence.
---

# Windows Remote Validation

Use this class-level workflow when a Windows lab server must be inspected or validated remotely from macOS/Linux over OpenSSH. Prefer repeatable PowerShell script transfer and execution over complex inline commands.

## Workflow

1. Confirm the access contract before changing the server: SSH alias, target IP/FQDN, account, identity file, and administrator status.
2. Use a local PowerShell-capable shell for orchestration when available. On macOS, `pwsh` can construct or encode scripts, but the remote executable should normally be `powershell.exe` unless PowerShell 7 is explicitly installed on Windows.
3. Write complex validation logic to a local `.ps1` file. Do not embed multi-line PowerShell containing `$`, parentheses, nested quotes, script blocks, or backticks inside an SSH command; multiple shell parsers will corrupt it.
4. Transfer with `scp` to a temporary path owned by the target operator account:
   ```bash
   scp ./validation.ps1 <alias>:C:/Users/<user>/AppData/Local/Temp/validation.ps1
   ```
5. Execute explicitly with Windows PowerShell 5.1:
   ```bash
   ssh -o BatchMode=yes <alias> 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\<user>\AppData\Local\Temp\validation.ps1'
   ```
6. Keep probes read-only by default. Inspect adapter/device state, Registry, CIM/WMI, event logs, services, file metadata, and evidence paths before making any change. Do not repair a service or network device solely because it is stopped or unusual; classify it against the lab role and expected configuration first.
7. Verify the actual evidence surface, not only SSH login. For a ConfigMgr site server, check the site-server log root, ConfigMgr Registry keys, `SMS_*` services, recent Windows events, and whether the box is or is not a ConfigMgr client.
8. Record scope and provenance: hostname, account, address, collection time, exact script revision/hash if relevant, and whether each result is observed, operator-declared, unavailable, or not applicable. Sanitize raw logs, Registry values, paths, screenshots, and secrets before publishing evidence.
9. Clean up temporary scripts only when safe and after raw evidence is preserved. Never delete source evidence or alter lab services without explicit authorization.

## PowerShell compatibility

Windows PowerShell 5.1 has different cmdlet parameter surfaces from PowerShell 7 and newer documentation. Avoid assuming parameters such as `Get-NetAdapter -IfType`; query broadly and filter with `Where-Object` when necessary. Validate syntax locally where possible, then run remotely and treat actual output as authoritative.

## Two-layer AI lab worker

For application acceptance testing, split the worker into two explicit layers rather than trying to reach Tauri IPC over SSH:

1. **Deterministic layer:** SSH-driven PowerShell probes for Registry/CIM, event logs, services, file metadata, provenance, reparse/hardlink/final-path checks, budgets, redaction, and JSON evidence packaging.
2. **Interactive layer:** a lab-only UI Automation worker launched in the logged-on Windows session. It drives the real installed app so the normal frontend → Tauri IPC → native backend path is exercised. Use .NET UI Automation and guarded, source-derived selectors; unknown consent labels must produce `NOT_APPLICABLE`, never an unsafe click.

SSH controls the worker; it does not directly access the in-process Tauri IPC channel. Use an interactive scheduled task or equivalent session-1 launcher for GUI work—ordinary SSH Session 0 is not sufficient.

Before accepting UI evidence, require bounded waits, a transcript, a UI-tree/diagnostic artifact, and structured `PASS` / `REWORK` / `NOT_APPLICABLE` output. A launched process alone is not validation. Verify the exact artifact path/version/hash before using results as merge evidence.

Use persistent worktree paths or a durable remote lab directory for scripts. Do not rely on `/tmp` transfer scripts in background jobs: temporary files can disappear before a retry, yielding a local `scp: stat ... No such file` failure that says nothing about the target.

## Failure handling

- If DNS fails, verify the target IP and use the IP in the SSH host entry rather than blocking validation on unrelated DNS repair.
- If SSH succeeds but the probe fails, distinguish transport/authentication failure from PowerShell parsing, cmdlet availability, permissions, and target-state findings.
- After a failed script, fix it locally and resend it; do not repeatedly grow an inline command.
- If a remote Windows script returns call-depth overflow while serializing provider objects (for example Authenticode certificates), project provider objects to flat scalar fields before sanitization/JSON transport; add a regression test.
- If the client becomes unreachable, separate network/transport state from worker correctness. Check the route and target independently; do not classify the last worker run as PASS or FAIL without its evidence.
- Never report a system fix unless a change was actually made and verified. A healthy observed state should result in no change.

## Supporting material

- `references/lab-access-template.md` lists what to record about a lab host and what a ConfigMgr site server's evidence surface looks like. Keep real host names, addresses, accounts, and key paths in your local SSH config, never in the repository.
