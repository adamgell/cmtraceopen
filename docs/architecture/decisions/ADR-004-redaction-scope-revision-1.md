# ADR-004 Revision 1: the redaction contract (scope and ownership)

- **Status:** PROPOSED. Not accepted. Six rulings are listed below and each is
  independently acceptable, amendable, or rejectable by the repository owner.
  `ADR-004-redaction-scope.md` remains authoritative until this document is
  ruled on.
- **Context:** ADR-004 accepted a redaction *boundary* and deferred the token
  algorithm, the caller-controlled key, the equality scope, and the
  cross-artifact behaviour as provisional. Thirteen redaction projections have
  since been written against that deferral. An inventory of them, verified
  against `origin/main` at `2678f1fb`, found that the boundary ADR-004 accepted
  binds at almost no real export surface, that ADR-004's own prohibition on
  stable correlation tokens is violated by most of the lanes that cite it, and
  that the one classification level meant to mean "never export this" is read by
  a single lane.
- **Decision:** deferred to the six rulings below.
- **Consequences:** deferred to the six rulings below.
- **Executable invariants:** deferred to the six rulings below. ADR-004's
  existing four invariants are re-examined under Ruling 5.

## How to read this document

This is a decision document, not a design and not a plan. It decides **what the
redaction contract promises and who owns each part of it**. It deliberately
decides nothing about *how*.

Three things are explicitly out of scope and are not decided here:

- **Token mechanics.** No cryptographic primitive, hash function, key length,
  key derivation, or encoding is named or implied. Ruling 2 states the security
  requirement as a *property*. Implementation research picks the algorithm after
  the contract is accepted. Naming one now would let an implementation detail
  masquerade as an architectural commitment, which is exactly how the current
  FNV-1a monoculture arrived: four lanes copied a hash function, and the hash
  function became the contract.
- **Migration.** No sequencing, no compatibility window, no deprecation path.
- **Code.** This branch changes no source file.

Every code reference below is repository-root relative with a line number and
was opened and read while writing this document. Where the inventory that
preceded this document was wrong, the correction is recorded in
[Corrections to the inventory](#corrections-to-the-inventory) rather than
quietly fixed.

## The contradiction this revision must resolve

`docs/architecture/decisions/ADR-004-redaction-scope.md:5` says new reducers
"must not introduce stable identifier tokens intended for cross-artifact,
cross-session, or cross-export correlation."

Five of the six Windows Intune lanes do exactly that, by design and with the
design stated in their own module docs:

- `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:9-12`
  states global stability as the goal: masking is "a pure function of the masked
  text, so the same input always produces the same token." The minter is
  `stable_token` at
  `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`,
  an unsalted FNV-1a over the value alone. Win32, Scripts, and Remediations all
  export through it.
- `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:33-35`
  is blunter still: "The hash is deliberately non-cryptographic and unsalted. It
  exists to make equal values look equal across an export, not to resist an
  attacker who already knows the serial number they are looking for."
- Microsoft Store and Compliance each carry a byte-identical private copy of the
  same unsalted minter:
  `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30`
  and
  `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:25-32`.

Exactly one lane scopes token equality to a single analysis. Configuration
derives a salt from a caller-supplied identity plus the generation instant at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-209`,
and every emitted token goes through the resulting scope at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:219-241`.
That module cites ADR-004 by name as its reason
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:22-32`)
and states plainly what it still cannot promise
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`):
"The token is not keyed. The salt is derived from material that travels with the
export, so it is no defense against an attacker who can enumerate candidate
values and confirm a match within a single export."

So the architecture currently says two incompatible things at once, and adapter
authors have been picking whichever one their neighbouring lane picked. A
document that resolves anything else and leaves this open has resolved nothing.

## What the code does today

Verified against `origin/main` at `2678f1fb`.

### Where a projection actually binds

Two places in the repository make redaction unavoidable by construction. Both
are inside the parser crate.

| Site | Mechanism |
|---|---|
| `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34` | `parse_log_document` *is* the projection: it wraps `parse_log_document_preserving_local_values`, so the default entry point cannot return an unprojected document. |
| `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` | `SccmRawEvidenceSnapshot::export` builds the public `SccmEvidence` with a struct literal in which every free-text field is projected, and drops `execution_context` entirely (`:341`). The only construction path calls it: `crates/cmtraceopen-parser/src/sccm/ingest.rs:9`. |

Everywhere else, the projection is a function a caller may or may not call. No
caller in the application calls one: `redacted_export_projection` has zero call
sites under `src-tauri/src/` or `src/`. Every reference lives inside the parser
crate, in its own re-exports and tests.

### The surfaces that carry data out today

| Surface | Site | Projected? |
|---|---|---|
| Crate/library API | `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34`; `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` | Yes, by construction, in those two lanes only |
| IPC command return | `src-tauri/src/commands/esp_diagnostics.rs:94-106` returns `EspDiagnosticsSnapshot` | No |
| Tauri `emit` stream | `src-tauri/src/commands/esp_diagnostics.rs:66-72` | No |
| Frontend file-save | `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx:328-353` calls `buildEspSessionCapture`, which embeds `snapshot` unmodified (`src/workspaces/esp-diagnostics/esp-session-capture.ts:34-45`, specifically `:43`), then writes it through `src-tauri/src/commands/file_ops.rs:481-487` | No. Filed as issue #549 |
| Frontend clipboard | `src/workspaces/dsregcmd/DsregcmdWorkspace.tsx:156-172` copies `JSON.stringify(result)`; `:174-190` copies the rendered summary | No |
| UI display masking | `src/workspaces/esp-diagnostics/esp-view-model.ts:114-124` and `:126-136` | Yes, but for display only |

The last row is the sharpest statement of the problem. The UI masks
`restricted` unconditionally and `sensitive` behind a reveal toggle
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119-122` and `:131-134`).
The operator therefore reads a masked screen and, one button away, writes
cleartext to a file of their choosing. The product currently makes a privacy
promise on screen that its export contradicts.

### Token equality scopes in force

| Lane | Minter | Equality scope in force |
|---|---|---|
| Win32, Scripts, Remediations | `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26` (Win32 re-exports it at `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:22`) | Global and permanent |
| Microsoft Store | `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30` | Global and permanent |
| Compliance | `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:25-32` | Global and permanent |
| Autopilot | `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:74-81` | Global and permanent |
| Configuration | `crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:219-241`, salted per `:196-209` | One analysis, when the caller supplies a scope; otherwise the generation instant |
| ESP | `crates/cmtraceopen-parser/src/esp/redaction.rs:858-864` | One export, ordinal, position-dependent |
| Company Portal package state | `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:36-48` | One export, ordinal, position-dependent |
| Company Portal macOS logs | `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/redaction.rs:270-317`, placeholders at `:315` | One export, ordinal per kind |
| SCCM | `crates/cmtraceopen-parser/src/sccm/evidence.rs:10` | None. Every masked span collapses to one constant marker |

Four incompatible answers are in production simultaneously: global,
per-analysis, per-export-ordinal, and none.

The ordinal schemes deserve a precise statement, because their instability is
subtler than "unstable within a snapshot". ESP and package state both build a
sorted set and number it (`crates/cmtraceopen-parser/src/esp/redaction.rs:858-864`;
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:36-48`).
Inside one export the numbering is self-consistent, and both modules go to real
trouble to keep it idempotent
(`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:28-35`
records the bug that motivated it). What they cannot do is survive a *second*
capture: adding one identifier that sorts early renumbers every identifier after
it, so the same user is `[redacted-user-3]` in Monday's export and
`[redacted-user-4]` in Tuesday's. Ordinal pseudonyms buy intra-export legibility
at the price of any longitudinal comparison.

### Sensitivity classification

`crates/cmtraceopen-parser/src/intune/evidence.rs:170-177` defines three levels
and documents the enum as "Privacy classification governing whether a value may
appear in an export."

`IntuneSensitivity::Restricted` is read at exactly one non-test site in the
entire crate:
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:464-467`,
where it forces whole-value tokenization ahead of the URI and diagnostic-name
exemptions. Two lanes collapse the vocabulary to a Public/not-Public binary
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:27-29`;
`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:88-90`).
Two never read sensitivity at all: neither
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:16-21`
nor
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:37-43`
imports `IntuneSensitivity`.

The frontend, by contrast, already implements a distinct `restricted` behaviour
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119-122`). The three-valued
vocabulary is honoured in the layer that cannot leak and ignored in the layer
that can.

### Structural construction

Five projections build their top-level result with an exhaustive struct literal,
so adding a field to the model is a compile error at the projection:
`crates/cmtraceopen-parser/src/intune/apps/windows/scripts/redaction.rs:45-61`,
`crates/cmtraceopen-parser/src/intune/apps/windows/remediations/redaction.rs:59-77`,
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:81-97`,
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:348-384`,
and `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/redaction.rs:270-317`
(which additionally returns a distinct output type).

Eight build theirs with `clone()` and mutation, or with struct-update syntax, so
a newly added field ships raw and silently:
`crates/cmtraceopen-parser/src/esp/redaction.rs:603-604`,
`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:107-108`,
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:126-127`,
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:176-177`,
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/redaction.rs:23-24`,
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:25-26`,
`crates/cmtraceopen-parser/src/intune/portal/ios_ipados/company_portal/diagnostics/redaction.rs:45-46`,
and `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/redaction.rs:439-442`.

Exhaustiveness is not inherited by nested helpers. Win32's top-level projection
is a struct literal, but the per-observation and per-transaction helpers beneath
it are `clone()` plus mutate
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:26-30`
and `:66-67`), so a new field on `Win32Observation` still ships raw. Compliance
has the same hole at
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:187`.
Configuration is the only lane exhaustive all the way down, and says so:
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:16-20`.

### Whether an export says it was projected

Three different mechanisms, each used by a different lane:

- A boolean field: `ConfigurationSnapshot.redacted`
  (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/models.rs:420`)
  and `CompanyPortalLogDocument.redacted`
  (`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/models.rs:238`).
- A distinct output type, which makes the question unaskable because an
  unprojected value has a different type: `PortalRedactedExport`
  (`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/models.rs:429-441`)
  and `SccmEvidence`, whose sensitive handle is typed away entirely
  (`crates/cmtraceopen-parser/src/sccm/models.rs:183`, set to `None` at
  `crates/cmtraceopen-parser/src/sccm/evidence.rs:341`).
- A field-level list of what was touched: `redacted_fields`
  (`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/models.rs:187`).

The remaining lanes say nothing at all.

### Cross-lane correlation

Correlation across lanes is not blocked by token vocabulary; it is blocked
upstream of it, because the lanes do not key on the same identity.

- Compliance keys the device on `device_key`
  (`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:130`).
- Autopilot keys on serial number and `entraDeviceId` among others
  (`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:180-188`).
- Win32 has no device identity field at all in
  `crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs`. The only
  device identity that ever reaches a Win32 export is a hostname scraped out of
  free text by the shared grammar's field and UNC rules
  (`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:142-155`
  and `:157-169`).

One shared hash applied to three different inputs yields three different tokens.
A shared token API would not make these exports joinable and would create the
appearance that it had.

---

## Ruling 1: where the contract binds

**Question.** The inventory found six surfaces that can carry analysis data out
of the process. Today the contract binds at none of them in the application, and
at the library API in only two lanes. Which are in scope?

**Option 1A. Bind at the crate/library API.** Every published analysis type is
constructible only in projected form, the way
`crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` and
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34`
already do. Preserving variants stay available under an explicitly named
local-only entry point. Downstream consumers of the published crate inherit the
guarantee.

**Option 1B. Bind at the IPC and emit boundary.** Leave the crate API dual and
require every Tauri command and every `emit` payload to carry the projected
form. Local rendering keeps cleartext only if a separate, explicitly named
command supplies it.

**Option 1C. Bind at each egress point.** Require the projection at file-save
and clipboard call sites in the frontend, leaving IPC and the crate API
unconstrained.

**Option 1D. Bind at all of them.** Defence in depth.

**Recommendation: 1A, with the IPC and emit boundary explicitly deferred and
the frontend egress points explicitly out of scope.**

The reasoning is that 1C is the arrangement that failed. Issue #549 is not a
missing call; it is the predictable outcome of making the safe form optional and
the unsafe form the default value in hand. `buildEspSessionCapture` embeds
`snapshot` unmodified at
`src/workspaces/esp-diagnostics/esp-session-capture.ts:43` because a snapshot is
what it was handed. Any contract that depends on a frontend author remembering
to call a function will be broken again by the next workspace, and the reviewer
will not see it, because the diff will look like an ordinary `save()`.

1A is the only option that is enforceable rather than remembered. It also
matches the two lanes that already got this right, so it is a generalization of
existing practice rather than a new invention.

The IPC and emit boundary is *deferred, not dismissed*. It cannot be ruled on
until [Open question 1](#open-questions) is answered, because it is not yet
known which analysis types are meant to cross it at all.

The frontend file-save and clipboard surfaces are **explicitly out of scope as
contract boundaries**. This is not a claim that they are safe. It is the claim
that they are the wrong place to put the guarantee: they are numerous, they are
added by every new workspace, and a per-lane hygiene rule at that layer is
precisely the arrangement that produced issue #549. Under 1A they need no rule,
because the value they receive is already projected. What they do need is a
*negative* rule: a frontend surface must never be handed an unprojected analysis
value in the first place.

The UI display-masking layer
(`src/workspaces/esp-diagnostics/esp-view-model.ts:114-136`) is a sixth surface
with its own guarantee, and it is **in scope as a constraint on the others**:
the export must never be less protective than the screen. Today it is strictly
less protective, which is the single most user-visible defect in this area.

## Ruling 2: equality scope

**Question.** Over what set must two masked values be equal, and across what
boundary must they not be?

This question matters because of a property the code states about itself. The
current derivation is unkeyed
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`;
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:33-35`),
and Configuration says the consequence out loud at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`.
Anyone holding an export and a list of candidate inputs can recompute the
derivation and recover the mapping. For the values these lanes mask, the
candidate lists are small and obtainable: serial numbers, UPNs in a known
tenant, SIDs on a known domain, hostnames from a naming convention. A globally
stable unkeyed token over a low-entropy input space is a public dictionary that
happens to be written in hex.

| Scope | Operator workflow | Re-identification risk |
|---|---|---|
| **Single artifact** | Two records in one log file show the same user. Nothing joins across files, so the commonest real question ("did the same account fail in both the app log and the enrollment log?") cannot be answered | Lowest. An attacker who enumerates learns only what one artifact contained |
| **Single analysis** | Every question the operator asks about one investigation is answerable. Two analyses of the same device are not joinable | Enumeration recovers the mapping *for that export only*. Correlating two exports requires re-enumerating each |
| **Single device** | Longitudinal comparison works: Monday's export and Tuesday's export line up. Requires a stable device identity that survives across analyses | An attacker who identifies the device once has identified it in every export of that device, past and future |
| **Single tenant** | Fleet-wide comparison works. Requires a tenant-scoped secret held somewhere | One recovered mapping compromises every export from that tenant |
| **Cross-analysis / global (today)** | Everything joins, including things the operator never intended to join: exports from different customers, different tenants, different years | Highest and permanent. One recovered mapping is universal, retroactive, and cannot be revoked. This is the current default for five lanes |

**Recommendation: single analysis, with the analysis identity supplied by the
caller.**

Rationale. Single artifact is too narrow to support the diagnosis: Compliance,
Autopilot, and ESP all reason across artifacts, and destroying that equality
would destroy the reduction, which ADR-004's third invariant already forbids.
Single device and single tenant require a durable identity or a durable secret
that the parser crate cannot mint; both are legitimate future scopes but neither
can be adopted before there is somewhere to keep the material. Global is the
status quo and is the risk row above.

Single analysis is the narrowest scope that keeps every diagnosis the lanes
currently produce, and it is the only one already implemented and tested in this
repository
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-241`,
with the inequality pinned by tests at `:638-671`). Adopting it is a
generalization of a working lane, not a new design.

The security requirement is stated as a **property, not an algorithm**:

> Token derivation must be keyed, domain-separated, and collision-resistant,
> with no feasible offline enumeration of candidate inputs without possession of
> the analysis secret.

Four consequences follow from that property and are part of this ruling:

1. **Keyed** means an unkeyed derivation does not satisfy the contract, however
   good the hash. Configuration's salt is derived from material that travels
   with the export
   (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`),
   so Configuration is *closer* to the contract than the other lanes but does
   not yet meet it.
2. **Domain-separated** means a token minted for a device identity and a token
   minted for a user identity cannot collide even if the underlying bytes are
   equal, and one lane's vocabulary cannot be confused with another's.
3. **Collision-resistant** is a property of the derivation, not a claim that
   collisions are impossible; the existing modules already qualify their
   equality guarantees this way and that qualification stands.
4. **No feasible offline enumeration without the analysis secret** is the whole
   point, and it is the clause the current design fails.

Which primitive delivers those four properties, how the secret is generated,
where it lives, and what happens when it is lost are **not decided here**.

## Ruling 3: ownership

**Question.** Who owns the grammar, who owns the projection, and who owns the
token derivation?

The grammar already has an assigned owner.
`docs/architecture/shared-vs-workload-invariants.md:27` names
`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs`
(`redact_text`), and divergence 7 at
`docs/architecture/shared-vs-workload-invariants.md:142-153` explains the split:
the grammar is shared, the projection is not, because "which Win32 fields are
classified sensitive is a property of this analyzer's contract."

That split is correct and this document endorses it. What is not correct is the
claim that the grammar has one owner in practice. Three of the six Windows lanes
carry a full private grammar rather than a private projection:
`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:55-75`,
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:64-76`,
and
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:135-151`
each define their own `redact_text`. Only Win32
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:22`),
Scripts, Remediations, and Configuration
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:94`)
use the shared one. The divergence-7 rule
is being cited as cover for forks it does not cover: a private *grammar* is not
a private *projection*.

**Option 3A. Grammar shared, projection per-lane, derivation per-lane.** The
status quo.

**Option 3B. Grammar shared, projection per-lane, derivation shared.** One
minter, one equality scope, one key. Each lane still decides which of its own
fields are sensitive.

**Option 3C. All three shared.** One module classifies every field of every
lane.

**Recommendation: 3B.**

3C is wrong for the reason divergence 7 already gives, and the reason is worth
restating because it is the strongest argument in the existing docs: what counts
as sensitive is a property of the evidence a lane reads, and a shared classifier
would have to be either the loosest or the strictest of the eight, and both are
defects. Configuration's `SENSITIVE_NAMES`
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:112-137`)
and its `DIAGNOSTIC_NAMES` carve-out (`:155-171`) are meaningful only against
CSP node semantics; imposing them on Win32 would mask return codes.

3A is wrong because the derivation is where every cross-cutting property lives.
Equality scope, keying, and domain separation are not per-lane facts; they are
statements about what an export as a whole promises, and a lane cannot make them
alone. Configuration proves this by being unable to: it scopes its own tokens
correctly and still has to write, at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:65-68`,
that defining the keyed API "is the Store pilot's decision under ADR-004, and
this module adopts it when it lands rather than inventing a local one."

**The test for what may stay per-lane**, which this ruling adopts in place of a
list:

> A decision may stay per-lane if changing it in one lane cannot change what any
> other lane's export promises. If a lane can weaken a guarantee another lane's
> reader relies on, that decision is shared.

Applying it: which fields a lane classifies as sensitive is per-lane, because
Compliance masking one more field cannot weaken a Win32 export. The token
derivation is shared, because one lane minting a globally stable token means an
attacker who recovers that lane's mapping can test the same candidate values
against every other lane's export that shares the vocabulary. The grammar is
shared, because a lane that forks it silently loses the fixes made in the
shared one, which has already happened once and is recorded at
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:9-15`.

## Ruling 4: `Restricted` versus `Sensitive`

**Question.** Define a behaviour for `Restricted` distinct from `Sensitive` and
require every lane to honour it, or remove the classification.

The current state is a false assurance. `crates/cmtraceopen-parser/src/intune/evidence.rs:170`
documents the enum as governing "whether a value may appear in an export," so an
adapter author who marks a field `Restricted` reasonably believes they have
prevented its export. In four of six lanes they have done nothing at all. And
ADR-004's fourth invariant, "restricted values are absent from export"
(`docs/architecture/decisions/ADR-004-redaction-scope.md:7`), is executable in
exactly one module.

**Option 4A. Remove `Restricted`.** Two levels, honestly enforced, beat three
levels unevenly enforced. Costs a schema-version bump: the enum has no
`#[serde(other)]` arm, so this is a breaking wire change
(`docs/architecture/shared-vs-workload-invariants.md:25`).

**Option 4B. Define `Restricted` as "no derived value either".** `Sensitive`
means the raw value is replaced by a token that preserves equality.
`Restricted` means no token is emitted: the field is absent, or carries a
constant marker that preserves nothing. The distinction is then real and
testable: after projection, a `Restricted` value contributes zero bits about its
input, not even equality.

**Option 4C. Keep the current three levels and require every lane to implement
Configuration's behaviour.** That behaviour, at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:464-467`,
is "tokenize unconditionally, ahead of every exemption."

**Recommendation: 4B.**

4C is the smallest change and it is the one to reject, because it does not make
the level mean what the enum's own doc comment says. Under 4C a `Restricted`
value still yields a token derived from it, so it is still present in the export
in the sense that matters for enumeration: an attacker with a candidate list can
still confirm a match. Calling that "absent from export" is the false assurance
in a new place.

4A is coherent and cheap and should be preferred over 4C if 4B is rejected. But
`Restricted` is not a hypothetical need. The frontend already implements exactly
the 4B distinction for display: `restricted` is never revealed, `sensitive` is
revealed behind a toggle
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119-122`). The vocabulary is
earning its keep in one layer already; the defect is that the export layer
ignores it.

4B also gives the level a property a test can assert without knowing anything
about the lane: **for a `Restricted` field, two inputs that differ must produce
identical output.** That single assertion is enough to catch every current lane,
and it is expressible as one shared test helper applied to every lane's corpus.

## Ruling 5: structural obligations

**Question 5a.** Should exhaustive construction be required, so a new field
cannot silently leak?

**Recommendation: yes, and the enforcement mechanism is the compiler, applied
recursively.**

The evidence is one-sided. Configuration adopted the struct literal
deliberately, and its module doc explains why in the past tense: it "closes the
previous gap where findings and coverage bypassed redaction entirely and
exported the un-scrubbed node path embedded in a finding summary"
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:16-20`).
That is not a hypothetical; that is a leak that shipped and was found.

The obligation must be stated recursively, because the top-level literal is not
where the risk lives. Win32's top level is exhaustive
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:81-97`)
while `redact_observation` beneath it is `clone()` plus mutate
(`:26-30`), so adding a field to `Win32Observation` still ships raw with no
compiler complaint. Compliance has the same shape at `:187`. An obligation
written as "the projection uses a struct literal" would pass both.

The correct wording is: **every function on a projection path constructs its
result exhaustively; no `clone()`-then-mutate, no struct-update syntax, no
`..Default::default()`.** Enforced by `rustc` at the point of the change, with
no test and no lint required. This is the mechanism's whole appeal: it fires in
the PR that adds the field, in the file the author is already looking at.

**Question 5b.** Should exports be self-describing about whether they were
projected?

**Recommendation: yes, and the mechanism is the type, not a boolean, wherever
the lane can express it.**

Three mechanisms are in use. A boolean
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/models.rs:420`;
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/models.rs:238`)
is honest but unenforced: nothing stops a value with `redacted: false` from
being written to a file, which is precisely what issue #549 describes. A
distinct output type
(`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/models.rs:429-441`;
`crates/cmtraceopen-parser/src/sccm/models.rs:183`) makes the question
unaskable, because the unprojected value will not typecheck at the boundary. A
field-level list
(`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/models.rs:187`)
is a useful addition to either but is not a substitute for either.

Where a lane cannot express a distinct type without an unreasonable duplication
of its model, a boolean is acceptable **provided it is a compile-time-enforced
literal in the exhaustive constructor**, as Configuration's is
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:383`).
A boolean that a `clone()` can carry over from the input is worse than nothing,
because it will read `true` on an unprojected value.

**On ADR-004's existing invariants.** Ruling 5 does not weaken the four
invariants at `docs/architecture/decisions/ADR-004-redaction-scope.md:7`. It
observes that only the third ("export/redaction does not alter non-sensitive
reducer conclusions") is currently executable across lanes, and that the fourth
becomes executable only under Ruling 4B.

## Ruling 6: cross-lane correlation

**Question.** Is correlating two lanes' exports in scope?

**Option 6A. In scope.** Requires a shared identity-resolution step upstream of
masking: something that decides that Compliance's `device_key`, Autopilot's
`entraDeviceId`, and whatever hostname Win32 scraped all denote one device, and
that hands the masking layer a single canonical identity to derive from. No lane
has this today.

**Option 6B. Out of scope.** Two lanes' exports are not correlatable by token,
and that is accepted and documented.

**Recommendation: 6B, stated plainly.**

Two lanes' exports are not correlatable by comparing masked values. This is
accepted, and it is a property of the evidence rather than of the redaction: the
lanes key on different identities, so they produce different tokens whatever
derivation is used. Compliance keys on `device_key`
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:130`),
Autopilot on serial and `entraDeviceId`
(`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:180-188`),
and Win32 has no device identity field in
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs` at all,
exporting only a hostname the shared grammar happened to scrape from free text
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:142-169`).

The important consequence is a prohibition, and it is the one thing in this
ruling that constrains future work: **a shared token derivation must not be
presented as delivering cross-lane correlation.** Adopting Ruling 3B gives every
lane one minter, and the natural next assumption is that tokens are now
comparable across lanes. They are not. Equal tokens across two lanes would mean
the two lanes derived from byte-equal inputs, which is a coincidence about
collection, not a statement that the exports describe one device.

Cross-lane correlation is a *shared-context* problem. If it is ever wanted, the
work is an identity-resolution step upstream of masking, with its own evidence
rules and its own correlation-strength reasoning under ADR-002, whose existing
ruling already covers it: explicit shared keys may be strong, stable secondary
identity is moderate, and display name alone is insufficient
(`docs/architecture/decisions/ADR-002-identity-correlation.md:5`). That is a
separate ADR, not a clause in this one.

---

## What this document does not decide

- **Any token algorithm.** Ruling 2 states a property. No primitive, no key
  length, no encoding, no library.
- **Where the analysis secret comes from, lives, or goes.** Configuration
  already records that the parser crate cannot mint one: it is pure,
  `wasm32-unknown-unknown`-clean, and has no clock, no entropy source, and no
  state surviving a restart
  (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:52-57`).
  Whatever supplies the secret is outside the crate, and deciding what that is
  requires answering Open question 2.
- **Migration.** No sequencing, no compatibility window, no deprecation path,
  no statement about existing exports.
- **Whether the IPC and `emit` boundary binds.** Deferred until Open question 1
  is answered.
- **Anything about the ESP session-capture replay format.** Issue #549 is cited
  as evidence of the defect class; how it is fixed, and whether replay needs an
  unprojected form, is not decided here.
- **Cross-lane identity resolution.** Ruled out of scope by Ruling 6; if it is
  ever wanted it needs its own ADR.

### What would have to be true to decide the deferred items later

- To rule on the IPC and `emit` boundary: a decision, or an observation, about
  which analysis types are meant to reach the UI at all (Open question 1).
- To specify the token derivation: acceptance of Ruling 2's property, plus an
  answer to Open question 2 about what identity a caller supplies as the
  analysis scope.
- To write a migration: acceptance of Rulings 1 through 5, since the shape of
  the migration is entirely determined by which of them are accepted.

## Open questions

Recorded rather than answered, because the inventory could not determine them
from the code.

1. **Are the Intune Windows lanes intended to reach the UI at all?** No Tauri
   command constructs a `Win32Analysis`, `StoreAnalysis`, `ComplianceSnapshot`,
   `AutopilotSnapshot`, `ConfigurationSnapshot`, or `ScriptAnalysis`: a search
   for their constructors across `src-tauri/src/` returns nothing. Every one of
   these lanes is currently exercised only by the parser crate's own tests. If
   they are library-only, Ruling 1A alone is sufficient and the IPC question
   never arises. If they are destined for a workspace, the IPC and `emit`
   boundary needs its own ruling before that workspace is written.

2. **What identity would a caller use as `analysis_scope`?** Configuration
   requires the caller to supply one and is explicit that supplying nothing buys
   no isolation
   (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:58-62`).
   Nothing in the repository establishes what a caller should pass. A case
   number, a collection run id, and a session id have different lifetimes and
   different blast radii, and the choice determines what "one analysis" means in
   Ruling 2.

3. **Are SCCM and DsRegCmd in scope?** They are in opposite states and neither
   was considered when ADR-004 was written.
   - SCCM already projects by construction at
     `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343`, with an equality
     scope of *none* (`:10`), and explicitly reserves the sensitive handle
     pending "a separately reviewed keyed scheme and explicit caller-provided
     key" (`:338-341`). That is the strongest existing implementation of the
     contract this document proposes, and it reached a different equality answer
     than Ruling 2 recommends. Whether SCCM adopts Ruling 2 or keeps its
     constant marker is a real question with a defensible answer either way.
   - DsRegCmd has no redaction anywhere: no projection exists in
     `crates/cmtraceopen-parser/src/dsregcmd/`, and the workspace copies the
     full analysis JSON to the clipboard at
     `src/workspaces/dsregcmd/DsregcmdWorkspace.tsx:156-172`. Device
     registration output is dense with tenant, device, and user identity.

4. **Does anything need cross-*export* equality within one device?** Ruling 2
   recommends per-analysis scope, which forbids it. The two ordinal schemes
   already forbid it in practice
   (`crates/cmtraceopen-parser/src/esp/redaction.rs:858-864`;
   `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:36-48`),
   and no test or issue in the repository asserts the capability. If an operator
   workflow genuinely needs Monday's export to line up with Tuesday's, Ruling 2
   should be amended to the single-device row before it is accepted, not after.

## Corrections to the inventory

The inventory that preceded this document carried citations for every claim.
Each was opened and read. Five claims were wrong or imprecise; the corrections
are recorded here rather than silently applied, because the corrections change
what some of the rulings must cover.

1. **"Exactly one place applies a redaction projection by construction" is
   wrong.** There are two. The second is
   `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343`, reachable only
   through `crates/cmtraceopen-parser/src/sccm/ingest.rs:9`. It is arguably the
   better of the two, because it also types the sensitive handle away
   (`:341`) rather than masking it. This materially strengthens Ruling 1A: the
   recommended binding is already implemented twice, in two unrelated families.

2. **"Five of eight projections use `clone()`+mutate" undercounts.** There are
   thirteen projections, not eight, and eight of them construct non-exhaustively,
   not five. The full census is in
   [Structural construction](#structural-construction). The direction of the
   claim holds and the situation is worse than reported.

3. **"ESP and `package_state` use ordinal pseudonyms that are unstable within a
   snapshot" is imprecise.** Within one export the numbering is stable and both
   modules take deliberate care to keep it idempotent
   (`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:28-35`).
   The instability is *across* exports: adding an identifier that sorts early
   renumbers everything after it. This matters because the intra-export
   guarantee the inventory denied is the one guarantee those lanes actually
   provide.

4. **"Only `ConfigurationSnapshot.redacted` and
   `CompanyPortalLogDocument.redacted` say whether a projection ran" is wrong as
   stated.** It is true only of the boolean form. Three further lanes say it by
   type or by field list:
   `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/models.rs:429-441`,
   `crates/cmtraceopen-parser/src/sccm/models.rs:183`, and
   `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/models.rs:187`.
   The type-level forms are stronger than the boolean, which is why Ruling 5b
   recommends them.

5. **The open question "whether SCCM and DsRegCmd are in scope (both export
   unprojected today)" is wrong about SCCM.** SCCM projects on export, by
   construction, at the crate boundary. Only DsRegCmd exports unprojected. The
   question of whether SCCM is in scope survives, but for the opposite reason:
   it has already answered Ruling 2 differently.

Two further findings that the inventory did not report:

6. **The shared-grammar claim at
   `docs/architecture/shared-vs-workload-invariants.md:27` and `:142-153` is
   true of three of the six Windows lanes.** Microsoft Store, Compliance, and
   Autopilot each carry a private `redact_text`
   (`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:55-75`,
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:64-76`,
   `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:135-151`).
   Divergence 7 licenses a private
   *projection*, not a private *grammar*, so these three forks are outside the
   protection that document offers them. Ruling 3 addresses this.

7. **The frontend already implements the `Restricted` behaviour that the Rust
   export lanes do not**
   (`src/workspaces/esp-diagnostics/esp-view-model.ts:119-122`). This is the
   strongest argument against removing the classification and is the reason
   Ruling 4 recommends 4B over 4A.
