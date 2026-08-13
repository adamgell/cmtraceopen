# ADR-004 Revision 1: the redaction contract (scope and ownership)

- **Status:** ACCEPTED. The eight rulings recorded below are decisions of the
  repository owner, not recommendations. They supersede the provisional parts of
  `ADR-004-redaction-scope.md`: the token equality scope is resolved to a single
  analysis, and the caller-owned opaque context is resolved. The token algorithm,
  the keying and derivation of that context, the encoding, the secret source, and
  the cross-artifact / cross-session / cross-export behaviour remain provisional.
  Where the two documents disagree, this one governs; every provision of ADR-004
  that these rulings do not touch stays in force.
- **Context:** ADR-004 accepted a redaction *boundary* and deferred the token
  algorithm, the caller-controlled key, the equality scope, and the
  cross-artifact behaviour. Thirteen redaction projections have since been
  written against that deferral. An inventory of them found that the boundary
  ADR-004 accepted binds at almost no real export surface, that ADR-004's own
  prohibition on stable correlation tokens is violated by every Windows Intune
  lane except Configuration, and that the one classification level meant to mean
  "never export this" is read by a single lane.
- **Decision:** the eight rulings below.
- **Consequences:** each ruling states what it obliges a lane author to do
  differently and where a violation is caught. Nothing in this document is
  implemented by this document; see [Scope limits](#scope-limits).
- **Executable invariants:** ADR-004's four invariants stand. Rulings 2, 4, 6
  and 7 make three of them executable that were not; see
  [What this does to ADR-004's invariants](#what-this-does-to-adr-004s-invariants).

## Scope limits

These limits are binding on this document and on anything that cites it.

- **Contract only.** This document decides what the redaction contract promises
  and who owns each part of it. It decides nothing about *how*.
- **No primitive is named.** No cryptographic primitive, hash function, key
  length, key derivation, or encoding is named or implied anywhere below. Ruling
  2 states the security requirement as a *property*. Implementation research
  selects the algorithm, and that work starts from this acceptance rather than
  being prejudged by it. Naming a primitive here would let an implementation
  detail masquerade as an architectural commitment, which is exactly how the
  current FNV-1a monoculture arrived: four modules copied a hash function
  (`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`,
  `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30`,
  `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:43-50`,
  `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:74-81`),
  and the hash function became the contract.
- **No token migration.** No sequencing, no compatibility window, no deprecation
  path, no statement about existing exports.
- **No production behaviour changes.** This branch changes no source file. Every
  code reference below is a citation, not a diff.

Every code reference is repository-root relative with a line number, was opened
and read while writing this document, and was verified against `origin/main` at
`f1740125`. Where the draft that preceded this document was wrong, or has been
overtaken by code that landed since, the correction is recorded in
[Corrections](#corrections) rather than quietly applied.

## The contradiction these rulings resolve

`docs/architecture/decisions/ADR-004-redaction-scope.md:14` says new reducers
"must not introduce stable identifier tokens intended for cross-artifact,
cross-session, or cross-export correlation."

Every Windows Intune lane except Configuration does exactly that, by design and
with the design stated in its own module docs:

- `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:9-12`
  states global stability as the goal: masking is "a pure function of the masked
  text, so the same input always produces the same token." The minter is
  `stable_token` at
  `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`,
  an unsalted hash over the value alone. Win32
  (`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:22`),
  Scripts (`crates/cmtraceopen-parser/src/intune/apps/windows/scripts/mod.rs:57`)
  and Compliance
  (`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:39`)
  all export through it.
- `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:33-35`
  is blunter still: "The hash is deliberately non-cryptographic and unsalted. It
  exists to make equal values look equal across an export, not to resist an
  attacker who already knows the serial number they are looking for."
- Microsoft Store and Compliance each carry a private copy of the same unsalted
  minter:
  `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30`
  and
  `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:43-50`.

Exactly one lane scopes token equality to a single analysis. Configuration
derives a salt from a caller-supplied value plus the generation instant at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-209`,
and every emitted token goes through the resulting scope at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:236-241`.
That module cites ADR-004 by name as its reason
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:22-32`)
and states plainly what it still cannot promise
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`):
"The token is not keyed. The salt is derived from material that travels with the
export, so it is no defense against an attacker who can enumerate candidate
values and confirm a match within a single export."

So the architecture has been saying two incompatible things at once, and adapter
authors have been picking whichever one their neighbouring lane picked. The
rulings below end that.

## What the code does today

Verified against `origin/main` at `f1740125`.

### Where a projection actually binds

Two places in the repository make redaction unavoidable by construction. Both
are inside the parser crate.

| Site | Mechanism |
|---|---|
| `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34` | `parse_log_document` *is* the projection: it wraps `parse_log_document_preserving_local_values`, so the default entry point cannot return an unprojected document. |
| `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` | `SccmRawEvidenceSnapshot::export` builds the public `SccmEvidence` with a struct literal in which every free-text field is projected, and drops `execution_context` entirely (`crates/cmtraceopen-parser/src/sccm/evidence.rs:341`). The only construction path calls it: `crates/cmtraceopen-parser/src/sccm/ingest.rs:9`. |

Everywhere else, the projection is a function a caller may or may not call. No
caller in the application calls one: `redacted_export_projection`,
`redacted_configuration_snapshot` and `redacted_package_state_export` have zero
call sites under `src-tauri/src/` or `src/`. Every reference lives inside the
parser crate, in its own re-exports and tests.

### The surfaces that carry data out today

| Surface | Site | Projected? |
|---|---|---|
| Crate/library API | `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34`; `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` | Yes, by construction, in those two lanes only |
| IPC command return | `src-tauri/src/commands/esp_diagnostics.rs:94-106` returns `EspDiagnosticsSnapshot` | No |
| Tauri `emit` stream | `src-tauri/src/commands/esp_diagnostics.rs:66-72` | No |
| Frontend file-save | `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx:328-345` calls `buildEspSessionCapture`, which embeds `snapshot` unmodified (`src/workspaces/esp-diagnostics/esp-session-capture.ts:34-45`, specifically `src/workspaces/esp-diagnostics/esp-session-capture.ts:43`), then writes it through `src-tauri/src/commands/file_ops.rs:481-487` | No. Tracked as issue #549 |
| Frontend clipboard | `src/workspaces/dsregcmd/DsregcmdWorkspace.tsx:156-172` copies `JSON.stringify(result)`; `src/workspaces/dsregcmd/DsregcmdWorkspace.tsx:174` begins the rendered-summary copy | No. Tracked as issue #556 |
| UI display masking | `src/workspaces/esp-diagnostics/esp-view-model.ts:114-124` and `src/workspaces/esp-diagnostics/esp-view-model.ts:126-136` | Yes, but for display only |

The last row is the sharpest statement of the problem. The UI masks
`restricted` unconditionally and `sensitive` behind a reveal toggle
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119` and `src/workspaces/esp-diagnostics/esp-view-model.ts:131`). The
operator therefore reads a masked screen and, one button away, writes cleartext
to a file of their choosing. The product currently makes a privacy promise on
screen that its export contradicts.

### Token equality scopes in force

| Lane | Minter | Equality scope in force |
|---|---|---|
| Win32, Scripts, Remediations | `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26` | Global and permanent |
| Microsoft Store | `crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30` | Global and permanent |
| Compliance | `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:43-50` | Global and permanent |
| Autopilot | `crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:74-81` | Global and permanent |
| Configuration | `crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:236-241`, salted per `crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-209` | One analysis when the caller supplies a scope; otherwise the generation instant, per the fallback at `crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:229` |
| ESP | `crates/cmtraceopen-parser/src/esp/redaction.rs:858-864` | One export, ordinal, position-dependent |
| Company Portal package state | `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:36-48` | One export, ordinal, position-dependent |
| Company Portal macOS logs | `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/redaction.rs:270-317`, placeholders at `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/redaction.rs:315` | One export, ordinal per kind |
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
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:36-39`
nor
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:41-43`
imports `IntuneSensitivity`.

The frontend, by contrast, already implements a distinct `restricted` behaviour
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119`). The three-valued
vocabulary is honoured in the layer that cannot leak and ignored in the layer
that can.

### Structural construction

Five projections build their top-level result with an exhaustive struct literal,
so adding a field to the model is a compile error at the projection:
`crates/cmtraceopen-parser/src/intune/apps/windows/scripts/redaction.rs:45-61`,
`crates/cmtraceopen-parser/src/intune/apps/windows/remediations/redaction.rs:59-77`,
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:81-97`,
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:348-385`,
and `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/redaction.rs:270-317`
(which additionally returns a distinct output type).

Eight build theirs with `clone()` and mutation, or with struct-update syntax, so
a newly added field ships raw and silently:
`crates/cmtraceopen-parser/src/esp/redaction.rs:603-604`,
`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:107-108`,
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:100-101`,
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:176-177`,
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/redaction.rs:23-25`,
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:25-26`,
`crates/cmtraceopen-parser/src/intune/portal/ios_ipados/company_portal/diagnostics/redaction.rs:45-46`,
and `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/redaction.rs:439-442`.

Exhaustiveness is not inherited by nested helpers, and the two lanes that show
this most clearly show it in opposite ways. Win32's top-level projection is a
struct literal
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:81-97`),
but the per-observation and per-transaction helpers beneath it are `clone()`
plus mutate
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:26-56`,
with the clones at `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:28` and
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:30`, and
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:66-74`,
with the clone at `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:67`), so a new field on `Win32Observation`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:209`) or
`Win32Transaction`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:369`) still
ships raw. Compliance is the inversion: its *nested* device-context view is an
exhaustive literal
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:103-113`)
while its top level is `clone()` plus mutate
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:100-101`)
and its findings map uses struct-update syntax
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:150-163`,
the spread at `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:161`). An obligation written as "the projection uses a struct
literal" would pass Win32 and would be ambiguous about Compliance, and neither
lane is safe.

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

The remaining lanes say nothing at all. This is the one structural question the
owner did not rule on; see
[What this ADR still does not decide](#what-this-adr-still-does-not-decide).

### Cross-lane correlation

Correlation across lanes is not blocked by token vocabulary; it is blocked
upstream of it, because the lanes do not key on the same identity.

- Compliance keys the device on `device_key`
  (`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:104`,
  and again per reported result and per access decision at `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:140` and
  `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:145`).
- Autopilot keys on serial number and `entraDeviceId` among others
  (`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:179-190`).
- Win32 has no device identity field at all: neither `Win32Observation`
  (`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:209`) nor
  `Win32Transaction`
  (`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:369`)
  declares one. The only device identity that ever reaches a Win32 export is a
  hostname scraped out of free text by the shared grammar's field and UNC rules
  (`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:142-155`
  and `crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:157-169`).

One shared derivation applied to three different inputs yields three different
tokens. A shared token API would not make these exports joinable and would
create the appearance that it had.

---

## The rulings

Eight rulings follow, one per section. Each records a decision, the reasoning
that supports it, what it
obliges a lane author to do differently, and where a violation is caught. Two of
them (Rulings 3 and 4) **refine** what the preceding draft recommended rather
than ratifying it; each says so explicitly and states what changed.

## Ruling 1: the contract binds at the crate/library export boundary

**Decision.** The redaction contract binds at the crate/library export boundary.
Every published analysis type is constructible only in projected form, the way
`crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343` and
`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/document.rs:30-34`
already do. Preserving variants stay available under an explicitly named
local-only entry point. Downstream consumers of the published crate inherit the
guarantee.

The IPC and `emit` boundary is **deferred, not dismissed**: it cannot be ruled on
until [Open question 1](#open-questions-that-survive) is answered, because it is
not yet known which analysis types are meant to cross it at all. The frontend
file-save and clipboard surfaces are **explicitly out of scope as contract
boundaries**.

**Why.** Binding at the frontend egress points is the arrangement that failed.
Issue #549 is not a missing call; it is the predictable outcome of making the
safe form optional and the unsafe form the default value in hand.
`buildEspSessionCapture` embeds `snapshot` unmodified at
`src/workspaces/esp-diagnostics/esp-session-capture.ts:43` because a snapshot is
what it was handed. Any contract that depends on a frontend author remembering to
call a function will be broken again by the next workspace, and the reviewer will
not see it, because the diff will look like an ordinary `save()`.

The crate boundary is the only place the guarantee is enforceable rather than
remembered, and it is already how two unrelated lanes work, so this generalizes
existing practice rather than inventing something.

Declaring the frontend surfaces out of scope is not a claim that they are safe.
It is the claim that they are the wrong place to put the guarantee: they are
numerous, they are added by every new workspace, and a per-lane hygiene rule at
that layer is what produced issue #549. Under this ruling they need no rule of
their own, because once the crate boundary of Ruling 1 is implemented the value
they receive is already projected. What they do need
is the *negative* rule stated below.

The UI display-masking layer
(`src/workspaces/esp-diagnostics/esp-view-model.ts:114-136`) is in scope **as a
constraint on the others**: the export must never be less protective than the
screen. Today it is strictly less protective, which is the single most
user-visible defect in this area.

**What it obliges.** A lane author publishing an analysis type must make the
projected form the only constructible public form, and must give the preserving
variant a name that says what it is. A frontend author must never be handed an
unprojected analysis value in the first place; a workspace that finds itself
holding one has found a defect in the lane, not in the workspace.

**Where a violation is caught.** The compiler, for the lane: an unprojected value
does not typecheck at the published boundary once the boundary is expressed that
way. Review, for the introduction of a new public constructor that reopens the
boundary, and for any new IPC command that takes an unprojected analysis type
across the process edge.

## Ruling 2: token equality is scoped to one analysis

**Decision.** Within **one analysis**, equal inputs produce equal tokens
(equality is preserved), and a token derived for one analysis is not comparable
with a token derived for another. Nothing joins two analyses. The security
requirement is stated as a property:

> Keyed, domain-separated, collision-resistant token derivation, with no feasible
> offline enumeration without the analysis secret.

**Why.** The current derivation is unkeyed
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`;
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:33-35`),
and Configuration says the consequence out loud at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`.
Anyone holding an export and a list of candidate inputs can recompute the
derivation and recover the mapping. For the values these lanes mask, the
candidate lists are small and obtainable: serial numbers, UPNs in a known tenant,
SIDs on a known domain, hostnames from a naming convention. A globally stable
unkeyed token over a low-entropy input space is a public dictionary that happens
to be written in hex.

| Scope | Operator workflow | Re-identification risk |
|---|---|---|
| **Single artifact** | Two records in one log file show the same user. Nothing joins across files, so the commonest real question ("did the same account fail in both the app log and the enrollment log?") cannot be answered | Lowest. An attacker who enumerates learns only what one artifact contained |
| **Single analysis (ruled)** | Every question the operator asks about one investigation is answerable. Two analyses of the same device are not joinable | Enumeration recovers the mapping *for that export only*. Correlating two exports requires re-enumerating each |
| **Single device** | Longitudinal comparison works: Monday's export and Tuesday's export line up. Requires a stable device identity that survives across analyses | An attacker who identifies the device once has identified it in every export of that device, past and future |
| **Single tenant** | Fleet-wide comparison works. Requires a tenant-scoped secret held somewhere | One recovered mapping compromises every export from that tenant |
| **Cross-analysis / global (today)** | Everything joins, including things the operator never intended to join: exports from different customers, different tenants, different years | Highest and permanent. One recovered mapping is universal, retroactive, and cannot be revoked. This is the current default for every Windows Intune lane except Configuration |

Single artifact is too narrow to support the diagnosis: Compliance, Autopilot and
ESP all reason across artifacts, and destroying that equality would destroy the
reduction, which ADR-004's third invariant already forbids. Single device and
single tenant require a durable identity or a durable secret that the parser
crate cannot mint; both are legitimate future scopes but neither can be adopted
before there is somewhere to keep the material. Global is the status quo and is
the risk row above.

Single analysis is the narrowest scope that keeps every diagnosis the lanes
currently produce, and it is the only one already implemented and tested here
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-241`,
with the inequality pinned by tests at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:638-671`).

Four consequences follow from the property and are part of this ruling:

1. **Keyed** means an unkeyed derivation does not satisfy the contract, however
   good the hash. Configuration's salt is derived from material that travels with
   the export
   (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`),
   so Configuration is *closer* to the contract than the other lanes but does not
   yet meet it.
2. **Domain-separated** means a token minted for a device identity and a token
   minted for a user identity cannot collide even if the underlying bytes are
   equal, and one lane's vocabulary cannot be confused with another's.
3. **Collision-resistant** is a property of the derivation, not a claim that
   collisions are impossible; the existing modules already qualify their equality
   guarantees this way and that qualification stands.
4. **No feasible offline enumeration without the analysis secret** is the whole
   point, and it is the clause the current design fails.

**What it obliges.** A lane author may no longer mint a token whose value depends
only on the masked input. Every emitted token must be scoped to the analysis, and
the lane must pin the inequality with a test, not merely the equality: two
analyses must not produce the same token for the same value.

**Where a violation is caught.** Test. Equality alone is not enough; the pinning
test is the *inequality* one, as
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:638-671`
already demonstrates. A globally stable minter passes an equality-only suite
perfectly, which is why the four lanes that ship one have green tests.

## Ruling 3: an opaque caller-owned `RedactionContext`, not a caller identity

**This ruling refines the draft.** The draft recommended that "the analysis
identity" be *supplied by the caller*, and then had to ask, as its own open
question 2, what identity a caller should supply. That framing is rejected. The
ruling is not that the caller names the analysis. It is that the caller **owns**
an opaque context value and hands it in.

**Decision.** The crate accepts a caller-owned `RedactionContext`. The value is
**opaque to the crate**. The crate does not interpret it, does not derive meaning
from it, does not validate it against any identity scheme, and does not require
it to name anything. Two exports belong to one analysis exactly when the caller
supplied the same context, because the caller said so, and for no other reason.

**Why.** The crate is in no position to know what an analysis is. It is pure,
`wasm32-unknown-unknown`-clean, and has no clock, no entropy source, and no state
surviving a restart, so Configuration already discovered the consequence and
wrote it down: the module "does not make uniqueness true; it only consumes it"
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:52-57`).
Once that is accepted, asking which identity the caller should use is asking the
crate's documentation to make a decision that belongs to the caller's
deployment. A case number, a collection run id and a session id have different
lifetimes and different blast radii, and the right answer differs per caller. An
opaque context lets each caller be right without the crate adjudicating.

The current field is the shape this ruling replaces:
`ConfigurationInput::analysis_scope` is an `Option<String>`
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/models.rs:65`)
described as an identity the caller picks, and the module already found itself
reasoning about the caller's *string semantics* rather than treating the value as
opaque bytes, when whitespace handling turned out to change which analyses were
the same one
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:200-204`).
That is exactly the kind of interpretation an opaque context forbids.

**What the opacity implies for the API shape.**

- The context is a value the crate accepts and consumes. It exposes no accessor,
  no parser, no comparison against a known vocabulary, and no validation beyond
  presence. There is nothing for the crate to read out of it.
- The crate must not echo the context into the export in a form the caller did
  not choose to publish. Configuration already got this right in substance: the
  export carries a digest, not the caller's value
  (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:185-195`,
  and `ConfigurationSnapshot::analysis_scope` at
  `crates/cmtraceopen-parser/src/intune/device/windows/configuration/models.rs:407`).
- Whether the context *is* the keying material of Ruling 2, is derived from it,
  or travels alongside it is a derivation question and is **not decided here**.

**What the opacity implies for testability.** Because the crate ascribes no
meaning to the value, every property worth testing is relational rather than
semantic: the same context yields equal tokens for equal inputs; different
contexts yield unequal tokens for the same input; an absent context yields no
value-derived token at all (Ruling 4). A test needs two distinct arbitrary
context values and nothing else. No test needs a real case number, a real tenant
id, or a real session id, and no fixture has to encode what an analysis is. This
is a strictly stronger testability position than a caller *identity*, which would
have made the tests depend on a convention the repository has never established.

**What it obliges.** A lane author takes the context as a parameter and passes it
through. They may not inspect it, normalize it, trim it, lowercase it, parse it,
or branch on its contents, and they may not put its raw value in the export.

**Where a violation is caught.** The compiler, for inspection: a context type
that exposes no accessor cannot be read, so code that tries does not compile.
Review, for the residual cases the type cannot prevent, chiefly a lane that
serializes the context into the export.

## Ruling 4: no global fallback and no timestamp-derived scope

**This ruling refines the draft, and it is pointed.** The draft recommended
per-analysis scope and treated Configuration as the model implementation. It did
not rule on what happens when no scope is supplied, and Configuration's answer to
that case is a defect this ruling now forbids.

**Decision.** There is no global fallback scope, and a timestamp may not stand in
for one. Absent a caller-supplied context there is **no scope**, and a lane may
not silently pick one.

**The specific behaviour this forbids.** Today,
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:196-209`
returns `None` when the caller supplies nothing, and
`RedactionScope::new` then substitutes the generation instant:

> `crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:229`
> reads `let material = scope_digest.unwrap_or(generated_at_utc);`

so the scope degrades to `generatedAtUtc` alone. The module documents the
degradation honestly at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:58-62`
("Omitting the scope buys no isolation") and, at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:34-38`,
records that an earlier revision made exactly this substitution its *primary*
scope and that the claim it rested on was false: a second-resolution UTC
timestamp is not a nonce, two independent analyses can legitimately carry the
same instant, and when they did they minted identical tokens for identical
values. Honest documentation of a hole is not a contract. Under this ruling the
degradation is forbidden outright, not merely disclosed.

**Why.** A fallback scope is indistinguishable, to a reader of the export, from a
real one. Both produce tokens; both look scoped. The reader cannot tell that this
export's tokens are joinable with an unrelated export's, and the whole value of
Ruling 2 is the reader's ability to rely on the boundary. A scope that a lane
invented rather than received is a boundary the caller never drew, and an
attacker enumerating candidates does not care that the substitute material was
well-intentioned. The specific substitute in force is the worst available: a
timestamp is low-entropy, predictable, present in the export, and collides across
unrelated analyses by construction.

**What a lane must do when no context is supplied.** It must not derive a token
from the value. Two responses satisfy this ruling and a lane must choose one
explicitly and say which in its module contract:

1. **Decline.** Refuse to produce a projected export at all, and say why.
2. **Emit with no equality.** Produce the export with masked values that preserve
   nothing: a constant marker, as SCCM already does
   (`crates/cmtraceopen-parser/src/sccm/evidence.rs:10`), so two different inputs
   are indistinguishable and no token vocabulary exists to be joined.

What a lane may **not** do is substitute any other material: not the generation
instant, not the file path, not the artifact id, not a build constant, not a
default context, and not anything else that travels with the export. The absence
of a context is a fact about the caller and must reach the export as an absence.

**What it obliges.** A lane author may not write a fallback. The derivation must
be unconstructible without a context, rather than constructible with a substitute.
Where a lane today reads a context and defaults it, that default is removed and
the no-context path becomes one of the two responses above.

**Where a violation is caught.** The compiler, primarily: if the derivation
cannot be constructed without a context, `unwrap_or`, `unwrap_or_default` and
`unwrap_or_else` have nothing to supply and the fallback is not expressible.
Test, for the residue: an export produced without a context must contain no
value-derived token, which is the same assertion Ruling 6 uses and can share its
helper. Review catches the third case, a lane that technically has a context
because the caller was made to invent one at the call site.

## Ruling 5: shared grammar where appropriate, shared derivation, workload-local projection

**Decision.** The masking **grammar** is shared. The token **derivation** is
shared: one minter, one equality scope, one key. The **projection** stays
workload-local: each lane decides which of its own fields are sensitive.
"Shared grammar where appropriate" is deliberate, not a hedge: a lane whose
evidence has a genuinely different vocabulary may own its own rules, but it must
say so and own the divergence, rather than forking the shared rules and
inheriting none of their fixes.

**Why.** `docs/architecture/shared-vs-workload-invariants.md:28` already names
`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs`
(`redact_text`) as the grammar's single owner, and divergence 7 at
`docs/architecture/shared-vs-workload-invariants.md:143-154` explains the split:
the grammar is shared, the projection is not, because which fields are classified
sensitive is a property of that analyzer's contract. That split is correct and
this ruling ratifies it.

Making the *classification* shared would be wrong for the reason divergence 7
gives: a shared classifier would have to be either the loosest or the strictest of
the lanes, and both are defects. Configuration's `SENSITIVE_NAMES`
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:112-137`)
and its `DIAGNOSTIC_NAMES` carve-out
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:155-171`)
are meaningful only against CSP node semantics; imposing them on Win32 would mask
return codes.

Leaving the *derivation* per-lane would be wrong because the derivation is where
every cross-cutting property lives. Equality scope, keying and domain separation
are not per-lane facts; they are statements about what an export as a whole
promises, and a lane cannot make them alone. Configuration proves this by being
unable to: it scopes its own tokens correctly and still had to write, at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:63-68`,
that defining the keyed API "is the Store pilot's decision under ADR-004, and this
module adopts it when it lands rather than inventing a local one."

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
shared, because a lane that forks it silently loses the fixes made in the shared
one, which has already happened twice and is recorded both at
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:8-15` and,
in nine separate leaking divergences, at
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:25-34`.

**What it obliges.** A lane author writes a projection and nothing else. They do
not write a `redact_text`, and they do not write a minter. The one exception is
the Decision's own: a lane whose evidence has a genuinely different vocabulary
may own its own grammar rules, but it must say so and own the divergence rather
than silently forking the shared rules. Two lanes still carry a private grammar
and must converge on the owner, or claim that exception: Microsoft Store
(`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:55-75`)
and Autopilot
(`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:135-151`).
Four modules carry a private minter and must converge on one derivation
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:19-26`,
`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:23-30`,
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:43-50`,
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:74-81`).
When and in what order that convergence happens is not decided here.

**Where a violation is caught.** Test, for drift: the parity assertion Compliance
now carries,
`crates/cmtraceopen-parser/tests/intune_windows_compliance.rs:1459`, pins the lane
byte-for-byte against the owner and is the pattern every lane should adopt.
Review, for a newly introduced private grammar or private minter, since nothing in
the type system stops a lane from writing its own.

## Ruling 6: `Restricted` emits no value-derived representation

**Decision.** `Sensitive` means the raw value is replaced by a token that
preserves equality. `Restricted` means **no representation derived from the value
is emitted at all**. Not a masked value; not a token; not a truncation, a length,
a prefix, a type tag inferred from the content, or a count. The field is absent,
or carries a constant marker that preserves nothing. Two different restricted
inputs must be indistinguishable in the export.

**Why.** The current state is a false assurance.
`crates/cmtraceopen-parser/src/intune/evidence.rs:170` documents the enum as
governing "whether a value may appear in an export," so an adapter author who
marks a field `Restricted` reasonably believes they have prevented its export. In
most lanes they have done nothing at all, and ADR-004's fourth invariant,
"restricted values are absent from export"
(`docs/architecture/decisions/ADR-004-redaction-scope.md:16`), is executable in
exactly one module.

The obvious smaller change, requiring every lane to copy Configuration's
behaviour at
`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:464-467`
("tokenize unconditionally, ahead of every exemption"), is rejected, because it
does not make the level mean what the enum's own doc comment says. Under it a
`Restricted` value still yields a token derived from it, so it is still present in
the export in the sense that matters for enumeration: an attacker with a candidate
list can still confirm a match, and two different restricted values are still
visibly different. That is the false assurance relocated, not removed. Note that
this makes the one lane that reads `Restricted` today non-conforming: being the
only lane to honour the level at all did not make its behaviour right.

Removing the level entirely would have been coherent and cheap, and would have
been preferable to the tokenizing reading. It is not chosen, because `Restricted`
is not a hypothetical need: the frontend already implements exactly this
distinction for display, where `restricted` is never revealed and `sensitive` is
revealed behind a toggle
(`src/workspaces/esp-diagnostics/esp-view-model.ts:119` and `src/workspaces/esp-diagnostics/esp-view-model.ts:131`). The
vocabulary is earning its keep in one layer already; the defect is that the export
layer ignores it.

**What it obliges.** A lane author must route `Restricted` before every other
branch, including before whatever exemptions the lane grants for URIs, diagnostic
names, or correlation keys, and must emit something that is a function of nothing
but the fact of restriction. A lane that does not read `IntuneSensitivity` at all
(Compliance,
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:36-39`;
Autopilot,
`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:41-43`)
must begin to.

**Where a violation is caught.** **Test**, and specifically one shared helper
applied to every lane's corpus, asserting the property that needs no knowledge of
the lane:

> For a `Restricted` field, two inputs that differ must produce identical output.

This cannot be a compiler check: sensitivity is a runtime value on a record, not a
type. The single assertion above is enough to catch every lane as it stands
today, including the one lane that currently reads the level, and it is the
mechanism this ruling relies on.

## Ruling 7: structural enforcement is recursive

**Decision.** Exhaustive construction is required **all the way down**, not only
at the top level. Every function on a projection path constructs its result
exhaustively: no `clone()`-then-mutate, no struct-update syntax, no
`..Default::default()`, at any depth.

**Why.** The evidence is one-sided. Configuration adopted the struct literal
deliberately, and its module doc explains why in the past tense: it "closes the
previous gap where findings and coverage bypassed redaction entirely and exported
the un-scrubbed node path embedded in a finding summary"
(`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:16-20`).
That is not a hypothetical; that is a leak that shipped and was found.

The obligation must be recursive because the top-level literal is not where the
risk lives, and the two lanes that prove it prove it in opposite directions.
**Win32** passes a top-level-only reading and leaks below it: the top level is an
exhaustive literal at
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:81-97`,
while `redact_observation`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:26-56`,
clones at `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:28` and
`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:30`) and `redact_transaction`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:66-74`,
clone at `crates/cmtraceopen-parser/src/intune/apps/windows/win32/redaction.rs:67`) are `clone()` plus mutate, so a new field on `Win32Observation`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:209`) or
`Win32Transaction`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:369`) ships
raw with no compiler complaint. **Compliance** fails even the top-level reading
while being exhaustive in one of its nested views: the projection opens with
`let mut projected = snapshot.clone();` at
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:100-101`,
builds `ComplianceDeviceContextView` exhaustively at
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:103-113`,
and then rebuilds each finding with struct-update syntax at
`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:150-163`
(the spread at `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:161`), so a new field on a finding ships raw. An obligation
written as "the projection uses a struct literal" would have passed Win32 and
been ambiguous about Compliance. Both lanes leak.

**What it obliges.** A lane author writes every constructor on the projection
path as a full struct literal, including the small per-record helpers that feel
too trivial to bother with, and accepts the verbosity. Where a nested type is
large enough that this is genuinely unreasonable, that is an argument for a
narrower projected type, not for a spread.

**Where a violation is caught.** Two mechanisms, and the division between them
matters:

- **The compiler**, for the case the obligation is designed to catch. Once a
  constructor is written exhaustively, adding a field to the model is a compile
  error at that constructor, in the PR that adds the field, in a file the author
  is already looking at. No test and no lint is involved.
- **Review**, for the introduction of a non-exhaustive constructor in the first
  place. `rustc` accepts `clone()`-then-mutate and `..spread` without complaint;
  that is precisely why the eight non-exhaustive projections listed in
  [Structural construction](#structural-construction) exist. The compiler enforces
  field coverage only once the construction style is right, so the construction
  style is a review obligation. A future lint could take this over, but no lint
  exists today and this ruling does not require one.

## Ruling 8: cross-lane correlation is explicitly out of scope

**Decision.** Correlating two lanes' exports is out of scope. Two lanes' exports
are not correlatable by comparing masked values, and that is accepted and
documented rather than treated as a gap.

**Why.** This is a property of the evidence rather than of the redaction: the
lanes key on different identities, so they produce different tokens whatever
derivation is used. Compliance keys on `device_key`
(`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:104`),
Autopilot on serial and `entraDeviceId`
(`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:179-190`),
and Win32 declares no device identity field at all on either
`Win32Observation`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:209`) or
`Win32Transaction`
(`crates/cmtraceopen-parser/src/intune/apps/windows/win32/models.rs:369`),
exporting only a hostname the shared grammar happened to scrape from free text
(`crates/cmtraceopen-parser/src/intune/apps/windows/common/redaction.rs:142-169`).

The important consequence is a prohibition, and it is the one thing in this ruling
that constrains future work: **a shared token derivation must not be presented as
delivering cross-lane correlation.** Ruling 5 gives every lane one minter, and the
natural next assumption is that tokens are now comparable across lanes. They are
not. Equal tokens across two lanes would mean the two lanes derived from
byte-equal inputs, which is a coincidence about collection, not a statement that
the exports describe one device.

**What it obliges.** A lane author must not document, test, or imply that a token
in their export means the same thing as an equal token in another lane's export.
Anyone wanting cross-lane joins must build an identity-resolution step upstream of
masking, under its own ADR, with its own evidence rules and its own
correlation-strength reasoning under ADR-002, whose existing ruling already covers
the ground: explicit shared keys may be strong, stable secondary identity is
moderate, and display name alone is insufficient
(`docs/architecture/decisions/ADR-002-identity-correlation.md:5`).

**Where a violation is caught.** Review. This is the one ruling with no mechanical
enforcement, because what it forbids is a claim rather than a behaviour: a test
asserting cross-lane token equality would be the violation, and the reviewer is
the only reader who can see that a doc comment or a fixture has started to promise
it.

---

## What this does to ADR-004's invariants

ADR-004's four invariants
(`docs/architecture/decisions/ADR-004-redaction-scope.md:16`) are unchanged in
wording and unweakened. Their status changes:

| Invariant | Before | After these rulings |
|---|---|---|
| Same-scope redaction preserves intended equality | Executable in Configuration only | Executable wherever a caller supplies a context: Ruling 2 gives every context-bearing analysis a scope and Ruling 3 gives every test a way to name two of them. The no-context paths Ruling 4 permits have no scope |
| Different scopes do not accidentally create equality | Not executable: most lanes have no scope | Executable under Rulings 2 and 4. Ruling 4 removes the fallback that made "different scope" silently mean "same timestamp"; the no-context constant-marker or decline path has no scope, so it cannot accidentally create equality |
| Export/redaction does not alter non-sensitive reducer conclusions | Executable across lanes | Unchanged |
| Restricted values are absent from export | Executable in one module, and that module's behaviour does not satisfy it | Executable everywhere under Ruling 6, via the shared differing-inputs assertion |

## What this ADR still does not decide

- **Any token algorithm.** Ruling 2 states a property. No primitive, no key
  length, no encoding, no library.
- **The derivation.** Ruling 3 fixes the context as opaque and caller-owned;
  whether the context is the keying material, is an input to it, or travels
  alongside it is not decided.
- **Where the analysis secret comes from, lives, or goes.** The parser crate
  cannot mint one: it is pure, `wasm32-unknown-unknown`-clean, and has no clock,
  no entropy source, and no state surviving a restart
  (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/redaction.rs:52-57`).
  Whatever supplies the secret is outside the crate.
- **Which of Ruling 4's two no-context responses a given lane takes.** The ruling
  requires the choice to be explicit and forbids the third option; it does not
  make the choice.
- **Whether an export should be self-describing about having been projected, and
  by what mechanism.** Three mechanisms are in use today: a boolean
  (`crates/cmtraceopen-parser/src/intune/device/windows/configuration/models.rs:420`;
  `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/logs/models.rs:238`),
  a distinct output type
  (`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/models.rs:429-441`;
  `crates/cmtraceopen-parser/src/sccm/models.rs:183`), and a field-level list
  (`crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/models.rs:187`).
  Ruling 1 makes the question partly moot at the crate boundary, since an
  unprojected value will not be constructible there, but it does not settle what a
  serialized export should carry. Not ruled on.
- **Migration.** No sequencing, no compatibility window, no deprecation path, no
  statement about existing exports, and no ordering for the convergence Ruling 5
  obliges.
- **Whether the IPC and `emit` boundary binds.** Deferred by Ruling 1 until open
  question 1 is answered.
- **Anything about the ESP session-capture replay format.** Issue #549 is cited as
  evidence of the defect class; how it is fixed, and whether replay needs an
  unprojected form, is not decided here.
- **Cross-lane identity resolution.** Ruled out of scope by Ruling 8; if it is
  ever wanted it needs its own ADR.

### What would have to be true to decide the deferred items later

- To rule on the IPC and `emit` boundary: an answer to open question 1 about
  which analysis types are meant to reach the UI at all.
- To specify the derivation: implementation research against Ruling 2's property,
  which is now unblocked.
- To write a migration: the rulings constrain its design but do not determine it.
  The token algorithm, derivation, secret source, encoding, existing-export
  behaviour, compatibility window, and convergence order remain unresolved. It
  was deliberately excluded from this document rather than blocked by it.

## Open questions that survive

Two of the draft's four open questions are resolved by these rulings and are
recorded here as resolved rather than dropped:

- *"What identity would a caller use as `analysis_scope`?"* is **dissolved by
  Ruling 3**. There is no required identity. The caller owns an opaque context and
  the crate does not interpret it, so the question has no answer the crate is
  entitled to give.
- *"Does anything need cross-export equality within one device?"* is **answered no
  for separate analyses by Ruling 2**, which scopes equality to one analysis and
  therefore forbids it across analyses. Exports that share one caller-supplied
  context belong to one analysis, per Ruling 3, and may still compare equal. The
  two ordinal schemes already forbid cross-export equality in practice
  (`crates/cmtraceopen-parser/src/esp/redaction.rs:858-864`;
  `crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:36-48`),
  and no test or issue in the repository asserts the capability.

Two survive, unanswered:

1. **Are the Intune Windows lanes intended to reach the UI at all?** No Tauri
   command constructs a `Win32Analysis`, `StoreAnalysis`, `ComplianceSnapshot`,
   `AutopilotSnapshot`, `ConfigurationSnapshot`, or `ScriptAnalysis`: a search for
   their constructors across `src-tauri/src/` and `src/` returns nothing. Every
   one of these lanes is currently exercised only by the parser crate's own tests.
   If they are library-only, Ruling 1 alone is sufficient and the IPC question
   never arises. If they are destined for a workspace, the IPC and `emit` boundary
   needs its own ruling before that workspace is written.

2. **Are SCCM and DsRegCmd in scope?** They are in opposite states and neither was
   considered when ADR-004 was written.
   - SCCM already projects by construction at the crate boundary
     (`crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343`), with an equality
     scope of *none* (`crates/cmtraceopen-parser/src/sccm/evidence.rs:10`), and
     explicitly reserves the sensitive handle pending "a separately reviewed keyed
     scheme and explicit caller-provided key"
     (`crates/cmtraceopen-parser/src/sccm/evidence.rs:338-341`). It is the
     strongest existing implementation of the contract these rulings state, and it
     reached a different equality answer than Ruling 2. Whether SCCM adopts Ruling
     2 or keeps its constant marker is a real question with a defensible answer
     either way; note that its constant marker is already one of the two responses
     Ruling 4 permits when no context is supplied.
   - DsRegCmd has no redaction anywhere: no projection exists under
     `crates/cmtraceopen-parser/src/dsregcmd/`, and the workspace copies the full
     analysis JSON to the clipboard at
     `src/workspaces/dsregcmd/DsregcmdWorkspace.tsx:156-172`. Device registration
     output is dense with tenant, device, and user identity. Tracked as issue #556.

The ESP session-capture leak referenced throughout is tracked as issue #549.

## Corrections

### Corrections to the inventory that preceded the draft

1. **"Exactly one place applies a redaction projection by construction" is
   wrong.** There are two. The second is
   `crates/cmtraceopen-parser/src/sccm/evidence.rs:329-343`, reachable only
   through `crates/cmtraceopen-parser/src/sccm/ingest.rs:9`. It is arguably the
   better of the two, because it also types the sensitive handle away
   (`crates/cmtraceopen-parser/src/sccm/evidence.rs:341`) rather than masking it.
   This materially strengthens Ruling 1: the ruled binding is already implemented
   twice, in two unrelated families.

2. **"Five of eight projections use `clone()`+mutate" undercounts.** There are
   thirteen public projections, not eight, and eight of them construct
   non-exhaustively, not five. The full census is in
   [Structural construction](#structural-construction).

3. **"ESP and `package_state` use ordinal pseudonyms that are unstable within a
   snapshot" is imprecise.** Within one export the numbering is stable and both
   modules take deliberate care to keep it idempotent
   (`crates/cmtraceopen-parser/src/intune/portal/windows/company_portal/package_state/redaction.rs:28-35`).
   The instability is *across* exports.

4. **"Only `ConfigurationSnapshot.redacted` and `CompanyPortalLogDocument.redacted`
   say whether a projection ran" is wrong as stated.** It is true only of the
   boolean form. Three further lanes say it by type or by field list:
   `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/logs/models.rs:429-441`,
   `crates/cmtraceopen-parser/src/sccm/models.rs:183`, and
   `crates/cmtraceopen-parser/src/intune/portal/macos/company_portal/unified_log/models.rs:187`.

5. **The open question "whether SCCM and DsRegCmd are in scope (both export
   unprojected today)" is wrong about SCCM.** SCCM projects on export, by
   construction, at the crate boundary. Only DsRegCmd exports unprojected.

### Corrections to the draft against current main

The draft was verified against `origin/main` at `2678f1fb`. Four PRs have landed
since (#543, #545, #546, #548) and this document is verified against `f1740125`.
Three of the draft's claims did not survive that move and are corrected above
rather than restated.

6. **The draft's claim that Compliance carries a private masking grammar is now
   false.** #546 deleted the fork. Compliance re-exports the shared owner at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:39`,
   documents the deference at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:16-23`,
   and pins byte-for-byte parity with it at
   `crates/cmtraceopen-parser/tests/intune_windows_compliance.rs:1459`. The fork's
   record is worth keeping because it is the strongest available evidence for
   Ruling 5: the copy had drifted in nine places, every one of them in the leaking
   direction, and the module now lists them at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:25-34`.
   The draft's count of "three of the six Windows lanes carry a full private
   grammar" is therefore now two: Microsoft Store
   (`crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/redaction.rs:55-75`)
   and Autopilot
   (`crates/cmtraceopen-parser/src/intune/enrollment/windows/autopilot/redaction.rs:135-151`).

7. **What did *not* change is Compliance's private minter.** It is still an
   unsalted copy at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:43-50`,
   and its equality scope is still global and permanent. Sharing the grammar did
   not share the derivation, which is exactly the distinction Ruling 5 draws and a
   useful demonstration that the two questions are independent.

8. **Compliance's structural citations all moved, and the shape of its defect is
   different from what the draft described.** The draft placed Compliance's
   non-exhaustive construction at lines 126 to 127 of that file, and a nested hole
   at line 187. Neither line holds what the draft said it held. On
   current main the top-level clone is at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:100-101`
   and the nested struct-update is at
   `crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:161`.
   More importantly, the draft implied Compliance was like Win32, exhaustive at the
   top and leaking below. It is the inverse: exhaustive in a nested view
   (`crates/cmtraceopen-parser/src/intune/device/windows/compliance/redaction.rs:103-113`)
   and non-exhaustive at the top. Ruling 7 is worded to catch both shapes.

9. **A documentation citation the draft used has moved.**
   `docs/architecture/shared-vs-workload-invariants.md:27` no longer names the
   grammar owner; #548 added the citation-verdict row there and the grammar-owner
   row is now `docs/architecture/shared-vs-workload-invariants.md:28`, with
   divergence 7 at `docs/architecture/shared-vs-workload-invariants.md:143-154`.
   The same PR moved `IntuneFinding::is_evidence_backed` to
   `crates/cmtraceopen-parser/src/intune/evidence.rs:355`.

### Two findings the inventory did not report

10. **Divergence 7 was being cited as cover for forks it does not cover.** It
    licenses a private *projection*, not a private *grammar*. The two remaining
    forks named in correction 6 are outside the protection that document offers
    them. Ruling 5 addresses this.

11. **The frontend already implements the `Restricted` behaviour that the Rust
    export lanes do not**
    (`src/workspaces/esp-diagnostics/esp-view-model.ts:119`). This is the strongest
    argument against removing the classification and is why Ruling 6 defines the
    level rather than deleting it.
