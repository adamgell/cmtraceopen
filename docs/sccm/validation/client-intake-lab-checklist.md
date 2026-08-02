# SCCM client intake native validation checklist

Issue: #319
Manifest contract: `sccmManifestVersion: 1`
Source catalog: client source catalog v1
Acceptance state: **PENDING — no live Windows acceptance has been exercised**

Use this checklist only on an authorized development SCCM client. The
temporary-directory tests on macOS/Linux prove deterministic native contract
behavior; they do not prove Windows ACL, reparse-point, ConfigMgr path, or
concurrent-log behavior.

## 1. Authorization and read-only intake facts

- [ ] Confirm the host is a development/test machine, not a customer or
      production endpoint.
- [ ] Record the validation owner and approval reference:
      `________________________________`.
- [ ] Record a sanitized Windows version family: `________________________`.
- [ ] Record a sanitized ConfigMgr client version family:
      `________________________`.
- [ ] Record the three-character synthetic/test site code, or state why it is
      unavailable: `____________`.
- [ ] Observe the client installation/log root. Do not assume the default.
      Record only a privacy-safe label or handle: `________________________`.
- [ ] Observe any configured alternate/cached roots and record only
      privacy-safe labels or handles: `___________________________________`.
- [ ] Record the local time zone and UTC offset used during capture:
      `________________________`.
- [ ] Confirm no registry, WMI, network, database, service mutation, or Tauri
      frontend command is required for this validation.

A missing source under a default path is an `Absent` coverage observation. It
does not prove that the client, a role, or a workflow is missing or broken.

## 2. Privacy, limits, and retention gate

- [ ] Review the selected sources for credentials, enrollment tokens,
      certificates/private keys, live user context, customer identifiers, and
      secret-bearing command output. Exclude any source that cannot be made
      safe.
- [ ] Record `maxFilesPerSource`: `________` and its rationale:
      `____________________________________________________________`.
- [ ] Record `maxBytesPerSource`: `________` and its rationale:
      `____________________________________________________________`.
- [ ] Choose one safe synthetic policy, deployment, or update workflow, or
      choose discovery-only: `____________________________________________`.
- [ ] Record the temporary evidence location using a privacy-safe label, its
      retention period, and disposal owner:
      `____________________________________________________________`.
- [ ] Confirm fixtures will be synthetic/sanitized reductions only. Never add
      a wholesale lab log to the repository.

## 3. Discovery-only dry run

- [ ] Build/run the narrowly scoped native test harness with
      `sccm-diagnostics`; record its commit and exact command:

      ```text
      commit:
      command:
      ```

- [ ] Call `discover_client_sources` first, without calling
      `capture_client_bundle`.
- [ ] Confirm every requested source group and basename came from
      `authoritative_client_source_catalog`; no caller-invented catalog key or
      basename was accepted.
- [ ] Compare discovered current, `.lo_`, numbered, and timestamped candidates
      with the observed directory contents.
- [ ] Confirm duplicate/configured aliases of one canonical root do not create
      duplicate physical candidates.
- [ ] Confirm same-basename candidates from distinct roots retain distinct
      root handles, path fingerprints, and rotation lineages.
- [ ] Record every `Absent`, `AccessDenied`, `Skipped`, `Unsupported`,
      `UnsafePath`, `ParseFailed`, and capped prediction as coverage, not as a
      finding.
- [ ] Record unexplained path/rotation differences for follow-up; do not change
      the catalog from unsanitized live evidence.

## 4. One bounded synthetic capture

- [ ] Run `capture_client_bundle` only after the dry-run inventory is reviewed.
- [ ] Confirm `sccm-manifest.json` was created once and was not overwritten by
      a repeat attempt.
- [ ] Confirm deterministic artifact ordering by logical membership,
      privacy-safe source identity, rotation rank, basename, and artifact ID.
- [ ] For every physical artifact, verify:
  - [ ] role is `client`;
  - [ ] original basename and exact rotation are retained;
  - [ ] relative path stays under `evidence/sccm/client/`;
  - [ ] root/source/path/lineage values are opaque versioned handles;
  - [ ] `bytesCopied` equals the evidence file length;
  - [ ] capped evidence is the exact raw prefix, with no injected marker;
  - [ ] collection time, ConfigMgr version (when known), and encoding are
        present and valid;
  - [ ] `fragmentComplete` does not claim a CCM logical-record boundary the
        copier did not prove.
- [ ] Confirm distinct same-name files cannot overwrite one another.
- [ ] Exercise one deliberately unreadable synthetic path. Record
      `AccessDenied`, or explicitly label a test-provider simulation; never
      relabel it `Absent`.
- [ ] Exercise one safe test symlink/reparse path and confirm it is not
      followed. Record the resulting coverage state.
- [ ] If a source changes size during an uncapped copy, confirm only that
      source becomes `FailedUnknownDetail`, its partial destination is removed,
      and sibling sources remain represented.
- [ ] Confirm a legacy generic `collected` value is not promoted to native SCCM
      captured evidence and a generic failure remains unknown-detail coverage.

## 5. Sanitized fixture decision and disposal

- [ ] Scan the manifest and evidence recursively for raw hostname, user/profile
      paths, domain/email forms, SID/tenant/device identifiers, credentials,
      tokens, certificates, and customer text.
- [ ] Reduce any approved discrepancy to the smallest independently
      reproducible synthetic records while preserving only necessary
      line/rotation/timestamp relationships.
- [ ] Replace identities consistently and state in the fixture README that all
      values are synthetic.
- [ ] Run the focused parser/native tests and privacy checks before committing
      a fixture.
- [ ] Delete the temporary lab capture according to the recorded retention
      decision and record completion: `________________________`.

## 6. Issue #319 evidence record

Post a meaningful-state comment containing:

- sanitized Windows and ConfigMgr version families;
- source catalog and manifest schema versions;
- configured-root confirmation and rotations observed;
- file/byte limits and coverage states exercised;
- exact verification commands and results;
- redaction/privacy result;
- Windows CI result and authorized lab result as separate facts;
- any unvalidated ACL, reparse, alternate-path, rotation, or concurrent-growth
  behavior;
- commit/PR and review links.

Keep #319 open if Windows CI or the authorized client run is pending. A green
temp-directory suite, successful serialization, or successful compilation is
not live Windows acceptance.
