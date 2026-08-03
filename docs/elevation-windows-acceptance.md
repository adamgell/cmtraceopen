# Windows Elevation and Restore Acceptance

This is the native Windows acceptance gate for application-wide **Restart as
administrator**. Unit tests on another operating system cannot prove UAC,
`ShellExecuteExW`, token identity, cross-account profile behavior, or Windows
ACL handling.

Run this only on a disposable Windows VM with synthetic logs. Do not capture or
publish real tenant, user, device, application, policy, token, ticket, or source
identifiers. Redact the opaque ticket value from screenshots and reports.

## Acceptance record

| Field | Recorded value |
| --- | --- |
| Source commit (40 characters) | `TBD` |
| Pull request | `384` |
| CI run and Windows artifact | `TBD` |
| Installer filename and SHA-256 | `TBD` |
| Installed executable SHA-256 | `TBD` |
| Windows edition and build | `TBD` |
| Same-account tester | `TBD` |
| Standard account and separate administrator used for OTS | `TBD` |
| VM snapshot | `TBD` |
| UTC start/end | `TBD` |
| Result | `NOT RUN` |

`OTS` below means over-the-shoulder elevation: a standard user enters the
credentials of a different administrator at the UAC prompt. Same-account UAC
keeps the launching profile, so the child can consume the one-time ticket from
that profile's LocalAppData. OTS runs the child under another profile, so the
ticket is intentionally unavailable. In that case only the closed,
non-sensitive workspace identifier is restored; no source path is placed on
the command line.

## Synthetic fixture

Before testing, snapshot the VM. As an administrator, create three clearly
named fixture roots containing only small synthetic CCM/plain-text and Intune
logs:

- **Same-account fixture (steps 6–9):** grant read access to Administrators and
  SYSTEM, remove inherited user access, and do not add an explicit deny ACE for
  the tester. The tester's unelevated split token must be refused while the same
  identity's elevated token is allowed.
- **OTS fixture (steps 10–11):** grant read access to the separate administrator
  and SYSTEM while leaving the standard account without access. The standard
  process must be refused and the different-account child must be permitted.
- **Readable control folder (step 7):** grant the same-account tester ordinary
  read, list, and traverse access. This control proves untyped directory
  classification independently of the ACL-denial recovery path.

Prove each ACL from both relevant tokens before testing the app. Record the
exact fixture paths and ACL output in the restricted test record, not in a
public issue. Never use customer logs.

## Sixteen-step gate

1. Verify the installed executable hash matches the exact-head Windows CI
   artifact, record both account identities, and confirm the VM snapshot can be
   reverted.
2. Start CMTrace Open normally as the same-account tester. Confirm the File menu
   offers **Restart as administrator**, the process is not elevated, and no UAC
   prompt appears before a separate confirmation click.
3. Confirm the menu action, cancel UAC, and verify the original process remains
   open and usable with its current workspace unchanged.
4. Repeat the menu action and approve same-account UAC. Verify one elevated
   child starts and the original process exits only after launch succeeds.
5. Inspect the elevated child's command line. Record only the redacted shape
   `--elevation-restore=<opaque-id> --elevation-workspace=<allowlisted-id>`.
   Fail if it contains a source path, token, filter, serialized session,
   inherited argument, or shell command.
6. From Log Explorer, open the same-account fixture's restricted synthetic
   file, accept the Access Denied recovery prompt, and approve same-account UAC.
   Verify exactly that typed file is retried once and no folder enumeration
   replaces it.
7. Open the readable control folder through the ordinary untyped path flow.
   Verify it is classified and opened as a folder without a false Access Denied
   prompt.
8. In Intune Diagnostics, open the same-account fixture's restricted synthetic
   Intune log file and approve same-account elevation. Verify the Intune
   workspace handler reruns analysis for that exact file; loading it only into
   hidden Log Explorer state is a failure.
9. Keep the elevated process open, force the same synthetic source to remain
   denied, and verify the restored retry reports the failure without offering a
   second elevation loop.
10. Sign in as the standard account, repeat the Intune source recovery against
    the OTS fixture, and enter the separate administrator's credentials at UAC.
    Verify the original process exits only after the OTS child launches.
11. Verify the OTS child opens the allowlisted Intune workspace but does not
    claim to have restored or analyzed the source. Confirm the bounded startup
    warning records the unavailable ticket without disclosing its value or the
    source path.
12. Inspect the OTS child's command line and confirm the same redacted two-flag
    shape as step 5. No ticket contents, source path, credential, token, or
    arbitrary workspace value may cross `argv`.
13. Exercise missing, malformed, expired, already-consumed, unknown, and
    traversal-like restore identifiers against missing, malformed, unknown,
    traversal-like, and valid `--elevation-workspace` values. Verify the full
    matrix: a consumable ticket restores its exact ticket workspace/source even
    when the fallback is absent or invalid; an unavailable but valid-shaped
    ticket may restore only a valid allowlisted fallback workspace; and a
    missing or malformed ticket cannot activate the fallback. Every case must
    start safely, must not interpret either option as a file path, and must not
    route a source through another workspace or execute a command.
14. Disable or make the ticket's requested workspace unavailable, then repeat a
    source restore. Verify the app stays on its normal available workspace and
    skips the source; it must not replay the source through a different
    workspace's handler.
15. From ESP Diagnostics, exercise its elevation banner once with UAC cancel and
    once with approval. The banner click itself is the confirmation; verify it
    uses the same coordinator/backend and single native `runas` implementation,
    returning to ESP without a source path on the command line.
16. Save sanitized screenshots/log excerpts, hashes, account-mode results, and
    every gap in the acceptance record. Revert the VM snapshot. Mark the gate
    passed only if both same-account and OTS paths were exercised; otherwise
    leave the result `NOT RUN` or `PARTIAL` with the precise missing steps.

## Required result wording

- Same-account success: **exact source restored from one-time per-user ticket**.
- OTS success: **allowlisted workspace restored; source restoration unavailable
  across account profiles**.
- A missing ticket, skipped source, unavailable workspace, cancellation, or
  second denial is a coverage/result state, never proof that the original
  operation succeeded.
- Until this checklist is exercised on Windows, report native acceptance as
  pending even when Rust, TypeScript, and hosted Windows build checks pass.
