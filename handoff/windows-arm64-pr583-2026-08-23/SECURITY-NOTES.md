# Security and privacy boundary

This handoff contains public instructions, PowerShell validation helpers, one small public Rust provider-capture helper, and public commit-verification material. It contains no application source checkout, Git history, application binary, customer data, credential, or private signing material.

## Trust boundary

The internal checksum inventory detects accidental or post-authentication mutation. It is self-contained and therefore not an authentication root. Authenticate the incoming handoff ZIP SHA-256 through a trusted out-of-band channel before extraction or execution. The adjacent checksum sidecar is only a transport convenience.

Apply the same rule in reverse to the validation return: the target operator sends the return ZIP's outer SHA-256 through a trusted out-of-band channel, and the receiver compares that trusted literal with both the received ZIP and its adjacent sidecar before extraction. An attacker who can replace both files can also recompute every internal hash, so neither the sidecar nor `SHA256SUMS.txt` is a transport trust root.

The public SSH key authenticates the sealed application source commit after the target performs its clean public clone. It does not sign the helper ZIP.

Bootstrap hashes and extracts through one read-only, write/delete-denying ZIP stream, so the path cannot be replaced between authentication and consumption. Documented artifact launches repeat source/Cargo/Rustup readback, then open the requested executable with the same denial, compute its expected length and SHA-256 from that guarded stream, and release it only after the owned wrapper confirms `Process.Start()` succeeded. This binds the recorded bytes to the Windows image creation without preventing later NSIS cleanup. The installed provider resources use separate expected-byte guards retained through the complete observation process.

The validation account/session is part of the trust boundary. It must be exclusive, clean, disposable, and free of unexpected same-account processes, scheduled tasks, startup items, injected tools, sync clients, and observed path mutations before trusted bytes are handled. Any such observation is a hard stop: execute no further package or source bytes, preserve only privacy-safe state, and revert only after the separate approval gate. The guarded ZIP and executable-launch bindings close ordinary namespace races; they do not claim to defend against hostile code already running with the validation account's token, which could terminate or inject into validation processes, alter source/toolchain state after readback, or read target-private evidence.

## Never transfer into the target

- A local worktree, `.git` directory, stash, reflog, untracked file, build cache, editor state, or existing evidence root.
- `.env*` other than the sealed tracked `.env.example`, any repository/user/global `.npmrc`, `HOME`/`PREFIX` path overrides, user-level or source/evidence-ancestor Cargo config, Cargo credential files, Git credential stores, GitHub CLI state, SSH/GPG private keys, SSH-agent state, certificates, PFX/P12, recovery codes, tokens, authenticated proxy settings, or URL-rewrite credentials. The sealed source's tracked `.cargo/config.toml` is part of the authenticated application tree; every other Cargo configuration discoverable from a validation working directory is rejected.
- Azure signing values, Tauri updater private key/password, production identities, customer data, tenant exports, Graph/WAM tokens, or private URLs.

The source initializer requires a normal isolated clone whose `.git` and common Git directories remain inside the validated source root; linked worktrees are rejected. It disables Git system/global configuration, prompts, credential helpers, hooks, templates, and push. Source readback rejects assume-unchanged, skip-worktree, sparse-checkout, active `.git/info` exclude/attribute rules, unsealed environment/toolchain controls, Cargo-home config/credentials, and external Cargo configuration; every automatic process gate repeats that readback and verifies the stable native ARM64 default Rustup toolchain before launch. Preflight rejects every environment variable outside an explicit ordinary-session allowlist (including `HOME` and bare `PREFIX` overrides), repository/user npmrc files, npmrc files under the Node installation and standard Windows locations, the global npmrc beneath npm's isolated-probe effective prefix, global Git credential controls, and user-level Cargo config or credential state. The prerequisite lane requires exactly canonical PSGallery, pins the exact Pester 5.7.1 package length/SHA-256, extracts it only into the reserved isolated tools root, verifies every extracted file against that package, and holds every pinned module file against write/delete until each importing child exits. Recovery EVTX files, structural ZIP fixtures, the private MDMDiag copy, sealed helper scripts, the unsigned Tauri validation configuration, and installed provider resources use the same expected-byte content guards for their complete consuming process; the documented recovery, structural-fixture, and MDMDiag Full UI launches explicitly retain applicable guards until Full exits. Structural junction metadata is revalidated immediately before the owned Full child starts under the required clean, exclusive account boundary. This avoids the clean-Windows inbox-Pester publisher conflict without `-SkipPublisherCheck`. Every automatic and documented private child process receives a smaller ordinary/toolchain allowlist plus only hardcoded per-gate overrides, and npm uses empty configuration. These controls reduce accidental credential use; they do not authorize running in a privileged or customer account.

## Never return from the target

- Raw `.evtx`, `.etl`, `.pml`, `.pcap`, `.pcapng`, `.cab`, `.zip`, `.db`, `.dmp`, `.mdmp`, registry data, raw exports, provider databases, or member manifests.
- EXE/MSI/NSIS artifacts, WebView2/application profiles, crash dumps, whole transcripts, screenshots, screen recordings, or target-local manual evidence files.
- Hostnames, usernames, domains, email addresses, SIDs, IP/MAC addresses, device/tenant IDs, serial numbers, event messages, source/member paths, credentials, private query strings, or remote endpoint names.

Tracked synthetic fixtures are fetched from the public repository at the sealed application commit. Target-generated structural-only ZIP fixtures are private test mechanics, not plausible event evidence.

## Target-local evidence layout

```text
evidence-root/
  raw-logs/             bounded automatic logs and privacy literals
  raw-artifacts/        private binaries, EVTX, provider DB, inventories, fixtures
    manual-evidence/    one unique regular <evidenceId>.proof file per exercised manual gate
    private-command-output/  captured stdout/stderr for native commands; never returned
  sanitized-logs/       exactly 33 bounded automatic logs; human-review before return
  summary.json          exact automatic contract and log hashes
  machine.json          bounded non-identity target and normalized toolchain facts
  artifacts.json        hashes, PE facts, and installed-file provenance only
  manual-results.json   enums, booleans, UTC times, counts, safe IDs, hashes only
```

The runner, EVTX helper, provider helper, and return exporter require disjoint fixed-local-NTFS paths outside known sync roots and reject existing reparse ancestors. Raw evidence remains on the validation target. Each exercised manual gate resolves its unique safe `evidenceId` only as `raw-artifacts/manual-evidence/<evidenceId>.proof`; the exporter hashes that target-local regular file and requires exact agreement with `evidenceSha256` without including the proof in the return.

## Returned evidence contract

The exporter allows exactly:

- `summary.json`
- `machine.json`
- `artifacts.json`
- `manual-results.json`
- one direct `sanitized-logs/<exact-automatic-gate-id>.log` for each of 33 gates
- the generated internal `SHA256SUMS.txt`

It rejects arbitrary `.txt`, extras, nested files, reparse points, renamed binary data, invalid UTF-8/control bytes, oversized logs, wrong JSON types/properties/coordinates/gate sets/statuses, partial artifacts, provenance/hash disagreement, and target-private literals. Common scanners redact/reject email, Windows SID, absolute Windows/UNC paths, IPv4/IPv6, GUID-like identifiers, common private DNS suffixes, arbitrary authorization headers, single-line secret assignments, multiline secret blocks, private-key/PAT/JWT patterns, long encoded payloads, and URL queries.

No regex can establish that arbitrary event or human text is private. The automatic lane never runs live ignored tests, the manual contract has no freeform returned field, and human review of every candidate remains mandatory.

The exporter takes the immutable `RepositoryPath` again, rechecks the live PR coordinate, exact detached source/tree/lockfiles/signature/remote, ordinary index visibility, sealed source controls, Cargo configuration boundary, and clean source status after manual work, then validates staged bytes, writes internal hashes, constructs the archive, reopens and checks its central-directory inventory, fresh-extracts it, and verifies every internal hash before publishing the outer checksum. The receiver must still authenticate that outer checksum out of band.

## Mutation classes

Automatic validation writes the new exact checkout's ignored dependency/build output (including `node_modules`, frontend output, and `src-tauri/target`), npm's account cache, Cargo registry/Git/advisory caches, the lab account's Playwright browser cache, and the new evidence root. `TEMP` and `TMP` must both remain exactly `C:\cmtraceopen-validation\temp`, disjoint from package, source, evidence, input, and return paths. The return exporter creates owned short-lived staging and fresh-extraction directories there plus an invocation-unique publication directory under the return parent. It validates the unpublished candidate completely, then publishes the deterministic return ZIP and sidecar with atomic fail-no-overwrite moves. Once a public return path exists, the exporter never deletes it by path; a late conflict or readback failure preserves the public namespace for operator inspection. Manual launches can create target-local CMTrace Open/WebView2 profile data; preserve the disposable VM until the privacy-bounded return is transported, verified, and accepted, then request separate approval before reverting its snapshot.

Approved prerequisite installation additionally mutates machine and account package state, Visual Studio/SDK/LLVM/Node/WebView2/Rust installations, Rustup toolchains, Cargo-installed binaries, PowerShell modules, installer caches, and package-manager caches. None of these writes are evidence of acceptance, and none are returnable.

Stop for human approval before:

- VM snapshot creation or revert;
- prerequisite installation or elevation;
- custom Event Log source/channel creation;
- installer launch, uninstall, file-association/default-app changes, or UAC/elevation;
- VSS snapshot creation/deletion;
- second-host access;
- clearing the owned canary channel;
- any signing, GitHub workflow dispatch, release upload, or publication.

No handoff instruction authorizes clearing a real log, touching a customer system, transferring a credential, signing locally, pushing code, or publishing evidence.
