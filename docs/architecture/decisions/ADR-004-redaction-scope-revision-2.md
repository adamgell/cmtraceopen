# ADR-004 Revision 2: redaction mechanism and publication binding

- **Status:** ACCEPTED by the repository owner on 2026-08-30. This revision
  expressly revises Revision 1 Ruling 1's named public local-preserving entry
  point to a private lane-only intermediate; decides Revision 1's deferred
  per-lane no-context response as **decline** for every Intune lane; and decides
  the deferred IPC/emit binding, secret source and lifetime, primitive, domain
  framing, tag encoding/version, dependency ownership, ESP session-capture
  replay format, and migration order. All portions of Revision 1 not expressly
  revised or decided here remain in force.
- **Context:** ADR-004 Revision 1 selected a caller-owned opaque context and
  per-analysis keyed equality, but deliberately did not choose the mechanism or
  bind application publication surfaces. Issue #356 now needs native and import
  routes. Adding those routes before the deferred decisions are resolved would
  make raw analysis values callable or duplicate a provisional token scheme.
- **Decision:** the nine rulings below.
- **Implementation:** this ADR changes no production code. The approved issue
  #356 implementation plan will deliver the rulings as vertical slices.

## Ruling 1: one public context path, lower than every workload

The public API is
`cmtraceopen_parser::intune::redaction::RedactionContext`.

The type owns exactly 32 secret bytes in `Zeroizing<[u8; 32]>`. It has no
constructor from a raw array because `[u8; 32]` is `Copy` and would leave a
caller buffer behind. `RedactionContext::try_fill` allocates the zeroizing
storage internally and gives a caller-supplied closure one mutable borrow to
fill it in place. The type has no accessor, parser, serializer, `Debug`,
`Display`, semantic identity, or default. It is not `Clone` or `Copy`; its
storage clears on every success/error/drop path through the maintained
`zeroize` crate.

The context is opaque in the sense established by Revision 1: the parser does
not trim, parse, label, compare, persist, or infer an identity from it. Revision
2 decides that its bytes are the HMAC key; that cryptographic use does not give
the bytes application semantics.

Private shared implementation lives under `intune::redaction`:

- `derivation` owns token construction and framing;
- `management_text` owns a byte-for-byte relocation of the one masking grammar
  already proven shared by Win32, scripts, remediations, configuration, and
  compliance.

The current public app-owned
`intune::apps::windows::common::redaction` path is deleted. Windows workloads
in that exact five-lane family use the lower private grammar. Microsoft Store,
Autopilot, ESP, Company Portal, macOS, Android, and iOS retain their proven
workload grammar. #366 shares only the context and derivation with the first
consumer slice; it continues to use its existing ESP-derived text vocabulary.
Any later grammar convergence requires corpora collected from observed runs, byte-parity tests, and
an explicit ownership decision in that leaf. Workload-local projections
continue to own sensitivity classification.

## Ruling 2: public analysis is projected by construction

Each lane may expose public acquisition-input and admitted-evidence types needed
to call the pure parser. Those input types may implement `Serialize` and
`Deserialize` for the native-to-pure contract. They are inputs, not published
analysis.

The only publicly constructible analysis/export result is projected. A public
analysis function requires `&RedactionContext` and returns the projected type.
Local-preserving intermediate reduction types and constructors are private to
their lane, explicitly named `Local...`, and implement neither `Serialize`,
`Debug`, `Display`, nor `Error`. They cannot be used as Tauri response, emitted
event, save/export, clipboard, or frontend types.

Projected result fields are private. Projected types implement `Serialize` but
not `Deserialize`, `Default`, or public struct construction; they expose only
read-only getters needed by Rust callers. Sensitive-bearing fields use opaque
`ProjectedText` or `SensitiveToken` wrappers, and Restricted fields use an
opaque `RestrictedMarker`. Those wrappers have private fields, implement
`Serialize` but not `Deserialize`, and can be constructed only by the shared
grammar/derivation/restriction functions. A Tauri command therefore cannot
construct the approved DTO type and manually place a raw `String` in a
sensitive field. Fields classified non-sensitive remain ordinary typed values
and are covered by the workload's classification tests.

There is no public no-context overload. The no-context decision for every
Intune lane is Revision 1's **decline** option, enforced by the required
parameter. There is no global, timestamp, path, artifact, build, or default
fallback.

## Ruling 3: bind at every application publication surface

Tauri may hold raw acquisition bytes and input envelopes long enough to call the
pure analyzer. It may publish only the parser-created projected result.

The same rule binds:

- Tauri command responses;
- emitted events and progress payloads;
- saved files and exported captures;
- clipboard payloads;
- frontend stores and props;
- logs, error strings, and retained acceptance evidence.

Input-only types are forbidden in those positions. The compiler enforces the
analysis type boundary; focused Rust/TypeScript architecture tests enumerate
commands, events, save/clipboard adapters, and frontend decoders to enforce the
application boundary.

ESP session replay remains a supported workflow through one replacement wire,
not through the current dual reader. Export writes
`EspSessionCaptureV2`, a closed projected `Serialize`-only shape. Import is a
native operation: Tauri opens the selected file once, binds a stable file
identity and SHA-256 while enforcing the declared raw-byte and elapsed-time
caps, and deserializes it into the distinct input-only
`EspSessionCaptureImportV2`. That import shape is `Deserialize`-only, denies
unknown fields, and admits exactly schema version 2. It is never a command
response, event, saved export, clipboard payload, or frontend type.

The pure replay entry point requires a fresh operation-scoped
`&RedactionContext`. It validates the complete closed V2 structure and creates
projected frontend state without constructing a local-preserving
`EspDiagnosticsSnapshot`. Every imported Sensitive or projected-text string,
including text beginning with `cti1_`, is untrusted raw input and is projected
again under the fresh context. Restricted positions accept only the V2 schema's
constant marker or absence and never restore a prior value. A replay therefore
preserves validated conclusions and coverage but deliberately does not preserve
token equality with the exporting operation.

Replay cannot rely on the original workload grammar to rediscover a value that
the exporter already replaced. For each imported `ProjectedText`, it segments
left-to-right around every non-overlapping exact token span—literal `cti1_`
followed by exactly 43 URL-safe Base64 characters—at any byte position. Each
token span is reminted from the complete old-token bytes under the fresh
context and that field's semantic domain; each intervening segment runs through
the lane's normal text projection so injected raw values are still classified.
The newly minted output is not scanned again. A standalone imported
`SensitiveToken` follows the same remint rule. Token shape never authorizes a
bypass: only the closed V2 field position selects this replay transform, and it
always replaces rather than trusts the span.

The current frontend `parseEspSessionCapture` path, V1 envelope reader, bare
`EspDiagnosticsSnapshot` reader, permissive version check, TypeScript capture
DTO, guards, tests, and wires are deleted in the ESP slice. There is no V1
reader, bare-snapshot reader, migration, or dual-schema window. Invalid,
unknown-field, V1, bare, and future-version input yields only a typed
`unsupportedSchema` or `malformedCapture` public diagnostic and no partial
frontend state; no imported string is included in that diagnostic.

## Ruling 4: the native caller creates one operation-scoped secret

For a desktop analysis, import, or collection operation, `src-tauri` calls
`RedactionContext::try_fill` and runs its existing OS-backed `getrandom::fill`
directly against the context's borrowed internal buffer. No source array or
second desktop copy exists. Entropy failure returns a typed error and declines
analysis; it never substitutes zero bytes, a default, a timestamp, or any other
material. All projected outputs that belong to that one operation borrow the
same context. The context is dropped after the operation and is never written to
disk, IPC, logs, crash text, exports, or evidence.

A non-desktop library caller fills the borrowed buffer from its own secure source
and owns any external source material it chooses to use. Reusing the same
context deliberately defines one analysis; using a new context defines another.
The crate does not mint entropy and remains pure Rust and
`wasm32-unknown-unknown` compatible. Tests inject an entropy failure and prove
that no analysis or zero/default-key token is produced.

## Ruling 5: HMAC-SHA-256 with unambiguous domain framing

Token derivation uses HMAC-SHA-256 through the maintained `hmac` crate and the
existing `sha2` crate. The context bytes are the HMAC key.

The authenticated message is a binary frame, not string concatenation:

```text
ASCII "CMTRACEOPEN-INTUNE-REDACTION" || 0x00
u8 schema_version = 1
u16be lane_id_length || UTF-8 lane_id
u16be semantic_domain_length || UTF-8 semantic_domain
u64be canonical_value_length || canonical_value_bytes
```

`lane_id` and `semantic_domain` are compile-time constants owned by the
projection. The derivation layer accepts no caller-provided free-form domain.
It rejects an identifier that cannot fit its length field. It performs no value
normalization: a workload projection must explicitly decide whether equality is
byte-exact, case-folded, or otherwise canonicalized before calling it.

The full 32-byte HMAC tag is encoded as unpadded URL-safe Base64 with the literal
prefix `cti1_`. No tag truncation is allowed. A token therefore has one
self-identifying encoding version without exposing the context or a scope
digest.

## Ruling 6: Sensitive and Restricted stay different

`Sensitive` may emit the `cti1_` token and thereby preserve equality within one
context and semantic domain. The same canonical value under a different
context, lane, or semantic domain must produce a different token.

`Restricted` never calls the derivation. The field is absent where the schema
allows absence. Where a stable field shape is required, it contains the exact
constant `restricted`, independent of the original value, length, type, or
presence details. Two different restricted inputs are byte-identical in the
canonical export.

No token equality is documented as cross-lane identity correlation. Equal
tokens would establish only equal canonical bytes in the same domain and
context, not that two records describe one device or user.

## Ruling 7: safe diagnostics are typed

Published failures and logs use
`cmtraceopen_parser::intune::diagnostic::PublicDiagnostic`, a lower-layer type
owned beside the redaction boundary. Its fields are closed codes/enums, safe
source kinds, bounded numeric counts, and non-value-derived coverage state. It
accepts no path, member name, external error string, artifact text, record
value, account, tenant/device identifier, URL, token, or arbitrary metadata map.

Private errors may retain causes for local control flow but are mapped to a
`PublicDiagnostic` code before logging or crossing a publication boundary.
Intune parser and adapter modules do not call `log`, `println`, `eprintln`, or
`dbg` directly; a checked-in architecture test permits only the typed public
diagnostic sink.

## Ruling 8: migration is vertical and has no compatibility window

Canonical IME/ESP path and compatibility-wire deletion lands first so migration
targets the surviving API. The shared context, derivation, and publication
binding then land with the existing ESP route as the first complete consumer:
one context per analysis session, projected command responses and session events,
V2 export/native replay, and projected frontend consumption. Raw
`EspDiagnosticsSnapshot` and `EspSessionUpdate` publication wires, the
frontend V1/bare-snapshot replay parser, and all V1 capture types and tests are
deleted in that slice. #366 is the first child-issue consumer and shares
context/derivation while retaining its proven ESP-derived text grammar.

Every other lane migrates in its own child-owned vertical slice. Its private
minter/projection and all call sites are replaced atomically; old and new token
APIs, wire fields, or serializers never coexist as supported alternatives.
Scripts and remediations are separate slices because they are separate semantic
owners even though both may admit AgentExecutor evidence.

The order after the ESP foundation and #366 is:

1. existing application-wired leaves (#354, #367, #368, #370, and #372);
2. scripts and remediations (#359 and #360), separately;
3. existing pure analyzers as each native route lands (#357, #358, #362, #363,
   and #364);
4. new leaves (#361, #365, #369, and #371).

An implementation plan may reorder independent items within one numbered group
for lab availability, but it may not expose a new route before that lane has the
new publication boundary.

## Ruling 9: executable conformance

One shared helper runs against every Intune lane and proves:

- equal canonical inputs under one context/domain have equal tokens;
- the same input under different contexts, lanes, or semantic domains has
  unequal tokens;
- token strings match `cti1_` plus the full unpadded URL-safe Base64 tag;
- no context fallback API is constructible;
- two different Restricted inputs produce byte-identical output;
- projection does not change non-sensitive reducer conclusions;
- local-preserving types cannot serialize or appear in public command/event
  signatures;
- projected DTOs and wrappers cannot deserialize, default, expose mutable
  fields, or be constructed outside their projection owner;
- a unique sentinel injected into every sensitive/restricted field and nested
  unknown-value position is absent from the complete serialized output;
- a token-shaped raw Sensitive value is treated as raw input and receives a new
  token; no prefix or shape is accepted as proof that input was projected;
- an exported `EspSessionCaptureV2` replays only through the bounded native V2
  importer, produces projected frontend state under a fresh context, and
  reprojects every token-shaped Sensitive string and every exact token span in
  `ProjectedText` at the start, middle, and end of text;
- replay output contains none of the exact tokens present in its imported V2
  capture; repeated imported spans in one semantic domain produce equal new
  tokens, while every new token differs from the imported token;
- V1 envelopes, bare snapshots, unknown fields, malformed V2 input, and future
  versions produce no partial replay state and only closed public diagnostics;
- the same admitted input, schema/profile version, and context produces
  byte-identical canonical projected JSON;
- `cargo check --locked -p cmtraceopen-parser --target
  wasm32-unknown-unknown` passes.

Negative known-answer tests pin the exact HMAC frame and token encoding so a
separator, normalization, truncation, or prefix change cannot silently redefine
equality.

Projection is intentionally one-way by type and is not required to be
idempotent. The projected type is not accepted by the projection function.
Recursive exhaustive construction follows Revision 1's enforcement split: an
independent review records every projection/helper path and verifies full struct
literals with no clone-then-mutate, struct update, or default spread; once that
style exists, the compiler makes every later field addition fail until the
projection handles it. The runtime conformance helper does not claim to prove a
source-code construction style.

## Consequences

- A new direct dependency on `hmac` and `zeroize` is accepted; `sha2`, `base64`,
  and native `getrandom` are already project dependencies.
- Tokens intentionally change and existing token equality is not preserved.
  There is no reader, writer, or migration for old token shapes.
- ESP replay deliberately rekeys imported Sensitive text and supports only the
  replacement V2 capture. Existing V1 envelopes and bare snapshots are not
  migrated or accepted.
- The desktop cannot join separate analyses by token. This is intentional and
  is the accepted Revision 1 equality scope.
- Raw analysis remains possible only inside a workload implementation. Public
  consumers that need a new unprojected use case require a new ADR revision,
  not a convenience constructor.
- HMAC protects low-entropy values from offline enumeration only while the
  operation secret remains secret. It does not make a compromised process safe.

## Rejected alternatives

- **Value-only SHA/FNV tokens:** enumerable and globally joinable.
- **Timestamp, path, artifact ID, or build hash as a key:** predictable,
  exported, or collision-prone fallback material.
- **A parser-minted secret:** incompatible with the pure/wasm boundary and with
  caller ownership.
- **A persisted device or tenant key:** creates cross-analysis correlation that
  Revision 1 forbids.
- **A public local-preserving result plus frontend masking:** makes safety depend
  on every current and future UI/export caller remembering an optional step.
- **Truncated tags:** unnecessary space optimization that weakens the simplest
  collision contract.
- **Dual old/new token readers or schema fallbacks:** prohibited by current
  repository instructions.
